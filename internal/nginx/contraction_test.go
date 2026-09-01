package nginx

import (
	"context"
	"errors"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func contractionTestFixture(t *testing.T) (Paths, filetxn.Owner, Manifest, map[string]Entry) {
	t.Helper()
	paths, manifest := installTestGraph(t)
	owner := testOwner()
	entries := map[string]Entry{"app-one": manifest.Entries[0]}
	for index, id := range []string{"app-two", "app-three"} {
		entry := Entry{Kind: EntryApp, ResourceID: id, Relative: AppsDirectory + "/" + id + ".conf", Digest: testDigest("pending-" + id), Domains: []string{id + ".example.test"}, Generation: uint64(index + 2)}
		var err error
		manifest, _, err = InstallEntry(context.Background(), paths, owner, entry)
		if err != nil {
			t.Fatal(err)
		}
		for _, current := range manifest.Entries {
			if current.ResourceID == id {
				entries[id] = current
			}
		}
	}
	return paths, owner, manifest, entries
}

func TestContractionJournalRecoversEveryDeletionAndManifestBoundary(t *testing.T) {
	fault := errors.New("simulated contraction interruption")
	tests := []struct {
		name    string
		options func() contractionOptions
	}{
		{name: "before first entry deletion", options: func() contractionOptions {
			return contractionOptions{BeforeDelete: func(index int, _ Entry) error {
				if index == 0 {
					return fault
				}
				return nil
			}}
		}},
		{name: "before second entry deletion", options: func() contractionOptions {
			return contractionOptions{BeforeDelete: func(index int, _ Entry) error {
				if index == 1 {
					return fault
				}
				return nil
			}}
		}},
		{name: "before manifest commit", options: func() contractionOptions {
			return contractionOptions{BeforeManifestCommit: func() error { return fault }}
		}},
		{name: "after manifest commit", options: func() contractionOptions {
			return contractionOptions{AfterManifestCommit: func() error { return fault }}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths, owner, prior, entries := contractionTestFixture(t)
			expected := prior
			expected.Entries = []Entry{entries["app-three"]}
			if _, _, err := contract(context.Background(), paths, owner, []string{"app-one", "app-two"}, test.options()); !errors.Is(err, fault) {
				t.Fatalf("interrupted contraction error=%v", err)
			}
			journal, present, err := readContractionJournal(paths, owner)
			if err != nil || !present || journal.Phase == "" || len(journal.Entries) != 2 || !sameManifest(journal.Candidate, expected) {
				t.Fatalf("durable intent present=%t journal=%#v err=%v", present, journal, err)
			}
			pending, present, err := PendingContraction(paths, owner)
			if err != nil || !present || !sameManifest(pending, expected) {
				t.Fatalf("pending candidate present=%t manifest=%#v err=%v", present, pending, err)
			}
			contracted, modified, err := Contract(context.Background(), paths, owner, []string{"app-one", "app-two"})
			if err != nil || !sameManifest(contracted, expected) || len(modified) != 3 {
				t.Fatalf("recovered contraction=%#v modified=%v err=%v", contracted, modified, err)
			}
			for _, id := range []string{"app-one", "app-two"} {
				path := filepath.Join(paths.ConfigRoot, filepath.FromSlash(entries[id].Relative))
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("planned entry %s remains: %v", id, err)
				}
			}
			retainedPath := filepath.Join(paths.ConfigRoot, filepath.FromSlash(entries["app-three"].Relative))
			if _, err := os.Lstat(retainedPath); err != nil {
				t.Fatalf("unplanned retained entry was removed: %v", err)
			}
			if audited, err := Audit(paths, owner); err != nil || !sameManifest(audited, expected) {
				t.Fatalf("final audit=%#v err=%v", audited, err)
			}
			if err := AcknowledgeContraction(context.Background(), paths, owner, []string{"app-one", "app-two"}); err != nil {
				t.Fatal(err)
			}
			if _, present, err := PendingContraction(paths, owner); err != nil || present {
				t.Fatalf("completed contraction journal present=%t err=%v", present, err)
			}
		})
	}
}

func TestContractionRecoversFileTransactionCrashAtEachNamespaceMutation(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation int
		point     filetxn.Point
	}{{name: "first entry rename", operation: 1, point: filetxn.PointAfterRename}, {name: "second entry rename", operation: 2, point: filetxn.PointAfterRename}, {name: "manifest staged", operation: 0, point: filetxn.PointAfterCreate}, {name: "manifest before rename", operation: 3, point: filetxn.PointBeforeRename}, {name: "manifest rename", operation: 3, point: filetxn.PointAfterRename}} {
		t.Run(test.name, func(t *testing.T) {
			paths, owner, prior, entries := contractionTestFixture(t)
			expected := prior
			expected.Entries = []Entry{entries["app-three"]}
			fault := errors.New("simulated process death after namespace mutation")
			operation := 0
			options := contractionOptions{GraphFault: func(point filetxn.Point) error {
				if point == filetxn.PointBeforeRename {
					operation++
				}
				if point == test.point && (test.operation == 0 || operation == test.operation) {
					return fault
				}
				return nil
			}}
			if _, _, err := contract(context.Background(), paths, owner, []string{"app-one", "app-two"}, options); !errors.Is(err, fault) {
				t.Fatalf("namespace interruption operation=%d err=%v", operation, err)
			}
			if staged, err := os.ReadDir(paths.StagingPath()); err != nil || len(staged) != 1 {
				t.Fatalf("interrupted filetxn staging=%v err=%v", staged, err)
			}
			contracted, _, err := Contract(context.Background(), paths, owner, []string{"app-one", "app-two"})
			if err != nil || !sameManifest(contracted, expected) {
				t.Fatalf("namespace recovery=%#v err=%v", contracted, err)
			}
			if staged, err := os.ReadDir(paths.StagingPath()); err != nil || len(staged) != 0 {
				t.Fatalf("recovery left graph staging=%v err=%v", staged, err)
			}
		})
	}
}

func TestContractionRecoversJournalFileTransactionCrashBoundaries(t *testing.T) {
	for _, test := range []struct {
		name            string
		operation       int
		point           filetxn.Point
		expectedStaging int
	}{
		{name: "journal create staging", operation: 1, point: filetxn.PointAfterCreate, expectedStaging: 1},
		{name: "journal create rename", operation: 1, point: filetxn.PointAfterRename},
		{name: "manifest-pending journal rename", operation: 2, point: filetxn.PointAfterRename, expectedStaging: 1},
		{name: "manifest-committed journal rename", operation: 3, point: filetxn.PointAfterRename, expectedStaging: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, owner, prior, entries := contractionTestFixture(t)
			expected := prior
			expected.Entries = []Entry{entries["app-three"]}
			fault := errors.New("simulated journal namespace interruption")
			putOperation, namespaceOperation := 0, 0
			options := contractionOptions{JournalFault: func(point filetxn.Point) error {
				if point == filetxn.PointAfterCreate {
					putOperation++
				}
				if point == filetxn.PointBeforeRename {
					namespaceOperation++
				}
				operation := namespaceOperation
				if point == filetxn.PointAfterCreate {
					operation = putOperation
				}
				if point == test.point && operation == test.operation {
					return fault
				}
				return nil
			}}
			if _, _, err := contract(context.Background(), paths, owner, []string{"app-one", "app-two"}, options); !errors.Is(err, fault) {
				t.Fatalf("journal interruption operation=%d err=%v", namespaceOperation, err)
			}
			if staged, err := os.ReadDir(contractionStagingPath(paths)); err != nil || len(staged) != test.expectedStaging {
				t.Fatalf("interrupted journal staging=%v err=%v", staged, err)
			}
			contracted, modified, err := Contract(context.Background(), paths, owner, []string{"app-one", "app-two"})
			if err != nil || !sameManifest(contracted, expected) || len(modified) != 3 {
				t.Fatalf("journal recovery=%#v modified=%v err=%v", contracted, modified, err)
			}
			if staged, err := os.ReadDir(contractionStagingPath(paths)); err != nil || len(staged) != 0 {
				t.Fatalf("journal recovery left staging=%v err=%v", staged, err)
			}
			if err := AcknowledgeContraction(context.Background(), paths, owner, []string{"app-one", "app-two"}); err != nil {
				t.Fatal(err)
			}
			if _, present, err := PendingContraction(paths, owner); err != nil || present {
				t.Fatalf("journal recovery remained pending=%t err=%v", present, err)
			}
		})
	}
}

func TestContractionAcknowledgementRecoversRemovalBoundaries(t *testing.T) {
	for _, point := range []filetxn.Point{filetxn.PointAfterRename, filetxn.PointAfterCleanup} {
		t.Run(string(point), func(t *testing.T) {
			paths, owner, _, _ := contractionTestFixture(t)
			resourceIDs := []string{"app-missing", "app-one", "app-two"}
			_, modified, err := Contract(context.Background(), paths, owner, resourceIDs)
			if err != nil || len(modified) != 3 {
				t.Fatalf("terminal contraction modified=%v err=%v", modified, err)
			}
			fault := errors.New("simulated acknowledgement interruption")
			if err := acknowledgeContraction(context.Background(), paths, owner, resourceIDs, func(observed filetxn.Point) error {
				if observed == point {
					return fault
				}
				return nil
			}); !errors.Is(err, fault) {
				t.Fatalf("acknowledgement interruption err=%v", err)
			}
			if point == filetxn.PointAfterRename {
				if err := AcknowledgeContraction(context.Background(), paths, owner, []string{"app-one", "app-two"}); err == nil {
					t.Fatal("acknowledgement tombstone accepted an inexact resource scope")
				}
			}
			if err := AcknowledgeContraction(context.Background(), paths, owner, resourceIDs); err != nil {
				t.Fatalf("acknowledgement retry failed: %v", err)
			}
			if _, present, err := PendingContraction(paths, owner); err != nil || present {
				t.Fatalf("acknowledged contraction remained pending=%t err=%v", present, err)
			}
		})
	}
}

func TestContractionRejectsRequestOutsidePendingScope(t *testing.T) {
	for _, phase := range []string{"entries_pending", "terminal_receipt"} {
		t.Run(phase, func(t *testing.T) {
			paths, owner, _, entries := contractionTestFixture(t)
			if phase == "entries_pending" {
				fault := errors.New("hold pending scope")
				if _, _, err := contract(context.Background(), paths, owner, []string{"app-one"}, contractionOptions{BeforeDelete: func(int, Entry) error { return fault }}); !errors.Is(err, fault) {
					t.Fatal(err)
				}
			} else if _, _, err := Contract(context.Background(), paths, owner, []string{"app-one"}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Contract(context.Background(), paths, owner, []string{"app-two"}); err == nil {
				t.Fatal("unrelated contraction request consumed pending scope")
			}
			if _, err := os.Lstat(filepath.Join(paths.ConfigRoot, filepath.FromSlash(entries["app-two"].Relative))); err != nil {
				t.Fatalf("unrelated App entry changed: %v", err)
			}
			if _, _, err := Contract(context.Background(), paths, owner, []string{"app-one"}); err != nil {
				t.Fatal(err)
			}
			if err := AcknowledgeContraction(context.Background(), paths, owner, []string{"app-one"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTerminalContractionReceiptBlocksUnrelatedGraphMutationUntilAcknowledged(t *testing.T) {
	paths, owner, _, entries := contractionTestFixture(t)
	if _, _, err := Contract(context.Background(), paths, owner, []string{"app-one"}); err != nil {
		t.Fatal(err)
	}
	candidate := entries["app-two"]
	candidate.Generation++
	candidate.Digest = testDigest("replacement")
	if _, _, err := InstallEntry(context.Background(), paths, owner, candidate); err == nil {
		t.Fatal("graph mutation bypassed an unacknowledged terminal contraction receipt")
	}
	if err := AcknowledgeContraction(context.Background(), paths, owner, []string{"app-one"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InstallEntry(context.Background(), paths, owner, candidate); err != nil {
		t.Fatalf("acknowledged receipt continued to block graph mutation: %v", err)
	}
}

func TestContractionIntentIsDurableBeforeFirstEntryDeletion(t *testing.T) {
	paths, owner, prior, entries := contractionTestFixture(t)
	fault := errors.New("stop before first delete")
	checked := false
	_, _, err := contract(context.Background(), paths, owner, []string{"app-one", "app-two"}, contractionOptions{BeforeDelete: func(index int, entry Entry) error {
		if index != 0 {
			t.Fatalf("first deletion index=%d", index)
		}
		journal, present, readErr := readContractionJournal(paths, owner)
		if readErr != nil || !present || journal.Phase != contractionEntriesPending || len(journal.Entries) != 2 || !reflect.DeepEqual(journal.Entries[0], entries["app-one"]) {
			t.Fatalf("pre-delete intent present=%t journal=%#v err=%v", present, journal, readErr)
		}
		checked = true
		return fault
	}})
	if !errors.Is(err, fault) || !checked {
		t.Fatalf("pre-delete interruption checked=%t err=%v", checked, err)
	}
	for _, entry := range prior.Entries {
		if _, err := os.Lstat(filepath.Join(paths.ConfigRoot, filepath.FromSlash(entry.Relative))); err != nil {
			t.Fatalf("entry changed before first deletion: %v", err)
		}
	}
}

func TestContractionRecoveryWillNotDeleteChangedPlannedPath(t *testing.T) {
	paths, owner, _, entries := contractionTestFixture(t)
	fault := errors.New("stop before second delete")
	_, _, err := contract(context.Background(), paths, owner, []string{"app-one", "app-two"}, contractionOptions{BeforeDelete: func(index int, _ Entry) error {
		if index == 1 {
			return fault
		}
		return nil
	}})
	if !errors.Is(err, fault) {
		t.Fatal(err)
	}
	changed := entries["app-two"]
	changed.Generation++
	changed.Digest = testDigest("changed-placeholder")
	data, err := RenderClosedEntry(changed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(paths.ConfigRoot, filepath.FromSlash(changed.Relative))
	writeMode(t, path, data, 0o600)
	if _, _, err := Contract(context.Background(), paths, owner, []string{"app-one", "app-two"}); err == nil {
		t.Fatal("recovery deleted a path whose exact journaled identity changed")
	}
	observed, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(observed, data) {
		t.Fatalf("changed planned path was touched: %v", err)
	}
}
