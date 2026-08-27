//go:build linux

package activation

import (
	"bytes"
	"context"
	"errors"
	"lanpanel/internal/acme"
	"lanpanel/internal/challenge"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const challengeTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func challengeTransactionFixture(t *testing.T) (nginx.Paths, filetxn.Owner, challenge.Prepared, nginx.Entry) {
	t.Helper()
	root := t.TempDir()
	paths := nginx.Paths{ConfigRoot: filepath.Join(root, "config"), StateRoot: filepath.Join(root, "state"), AuditPath: filepath.Join(root, "audit"), CertificatePath: filepath.Join(root, "default.crt"), PrivateKeyPath: filepath.Join(root, "default.key"), PIDPath: filepath.Join(root, "nginx.pid")}
	for _, directory := range []string{paths.ConfigRoot, paths.StateRoot, paths.StagingPath(), filepath.Join(paths.ConfigRoot, nginx.AppsDirectory), filepath.Join(paths.ConfigRoot, nginx.ChallengesDirectory), filepath.Join(paths.ConfigRoot, nginx.ControlDirectory), filepath.Join(paths.ConfigRoot, nginx.TemporaryDirectory)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := nginx.GenerateDefaultCertificate("ins_challenge", bytes.NewReader(bytes.Repeat([]byte{9}, 256)), time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	writeChallengeTestFile(t, paths.CertificatePath, certificate.CertificatePEM, 0o644)
	writeChallengeTestFile(t, paths.PrivateKeyPath, certificate.PrivateKeyPEM, 0o600)
	writeChallengeTestFile(t, paths.AuditPath, []byte(nginx.AuditMarker), 0o600)
	baseline, err := nginx.RenderBaseline(paths, "ins_challenge", "gen_challenge", certificate.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range baseline.Files {
		writeChallengeTestFile(t, path, data, 0o600)
	}

	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: challengeTestDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}}
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: "res_challenge", PlanID: "plan_challenge", Generation: 2, ConfigDigest: challengeTestDigest, Domains: []string{"app.example.test"}, Binding: binding, CertificateIdentity: "cert_challenge", Webroot: "/var/lib/lanpanel/certificates/webroot/cert_challenge", BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}})
	if err != nil {
		t.Fatal(err)
	}
	prior := *prepared.Entry
	prior.Generation = 1
	prior.Challenge = &nginx.ChallengeSite{Hosts: append([]string(nil), prior.Domains...), Webroot: "/var/lib/lanpanel/certificates/webroot/cert_prior"}
	prior.Digest = "sha256:" + strings.Repeat("0", 64)
	prior.Digest, err = nginx.DigestEntry(prior)
	if err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if _, _, err := nginx.InstallEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	return paths, owner, prepared, prior
}

func writeChallengeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertChallengeSnapshotRestored(t *testing.T, paths nginx.Paths, owner filetxn.Owner, candidate nginx.Entry, snapshot nginx.ActivationSnapshot) {
	t.Helper()
	manifest, err := nginx.Audit(paths, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest, snapshot.Manifest) {
		t.Fatalf("restored manifest differs from snapshot: got=%#v want=%#v", manifest, snapshot.Manifest)
	}
	manifestBytes, err := os.ReadFile(paths.ManifestPath())
	if err != nil || !bytes.Equal(manifestBytes, snapshot.ManifestBytes) {
		t.Fatalf("manifest bytes were not restored exactly: %v", err)
	}
	entryBytes, err := os.ReadFile(filepath.Join(paths.ConfigRoot, filepath.FromSlash(candidate.Relative)))
	if err != nil || !bytes.Equal(entryBytes, snapshot.EntryBytes) {
		t.Fatalf("entry bytes were not restored exactly: %v", err)
	}
}

func TestChallengeExpansionGuardRejectsBeforeDiskMutation(t *testing.T) {
	paths, owner, prepared, _ := challengeTransactionFixture(t)
	before, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: prepared.Entry.ResourceID, GenerationSequence: prepared.Safety.Generation, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: challengeTestDigest, ChallengePending: &prepared.Safety}}
	authority := ChallengeReloadAuthority{Safety: state, Installation: domain.Installation{}, Ownership: map[string]string{prepared.Entry.ResourceID: "sha256:" + strings.Repeat("b", 64)}, ObservedAt: time.Now().UTC()}
	if _, _, err := PrepareChallengeExpansion(paths, owner, *prepared.Entry, authority); err == nil {
		t.Fatal("ownership-mismatched challenge expansion was allowed")
	}
	assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, before)
}

func TestChallengeInstallFaultsRestoreExactPriorGraph(t *testing.T) {
	testFault := errors.New("nginx test fault")
	reloadFault := errors.New("nginx reload fault")
	waitFault := errors.New("worker drain fault")
	for _, test := range []struct {
		name  string
		stage string
		fault error
	}{
		{name: "nginx test", stage: "test", fault: testFault},
		{name: "reload", stage: "reload", fault: reloadFault},
		{name: "worker drain", stage: "wait", fault: waitFault},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, owner, prepared, _ := challengeTransactionFixture(t)
			snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
			if err != nil {
				t.Fatal(err)
			}
			prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
			if err != nil {
				t.Fatal(err)
			}
			var calls []string
			runtime := ChallengeGraphRuntime{
				Activate: func(context.Context, nginx.Manifest) error {
					calls = append(calls, "test")
					if test.stage == "test" {
						return test.fault
					}
					calls = append(calls, "reload")
					if test.stage == "reload" {
						return test.fault
					}
					calls = append(calls, "wait")
					return test.fault
				},
				Observe: func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) {
					calls = append(calls, "observe")
					return []closure.ProcessIdentity{}, nil
				},
				Restore: func(_ context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity) error {
					calls = append(calls, "restore-runtime")
					if !reflect.DeepEqual(manifest, snapshot.Manifest) {
						t.Fatal("runtime restoration did not receive prior manifest")
					}
					return nil
				},
			}
			_, err = CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, func(ctx context.Context) (nginx.Manifest, []string, error) {
				return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
			}, runtime)
			var failure *Failure
			if !errors.As(err, &failure) || !failure.PriorRestored || !errors.Is(err, test.fault) {
				t.Fatalf("transaction error=%v", err)
			}
			if calls[len(calls)-1] != "restore-runtime" {
				t.Fatalf("runtime was not verified after graph restoration: %v", calls)
			}
			assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, snapshot)
		})
	}
}

func TestChallengeInstallReloadFaultRemovesNewEntry(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil || snapshot.EntryPresent {
		t.Fatalf("new challenge snapshot=%#v err=%v", snapshot, err)
	}
	prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	reloadFault := errors.New("new challenge reload fault")
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest) error { return reloadFault },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore: func(_ context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity) error {
			if !reflect.DeepEqual(manifest, snapshot.Manifest) {
				t.Fatal("new challenge rollback runtime did not receive prior manifest")
			}
			return nil
		},
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
	}, runtime)
	var failure *Failure
	if !errors.As(err, &failure) || !failure.PriorRestored || !errors.Is(err, reloadFault) {
		t.Fatalf("new challenge transaction error=%v", err)
	}
	manifest, auditErr := nginx.Audit(paths, owner)
	if auditErr != nil || !reflect.DeepEqual(manifest, snapshot.Manifest) {
		t.Fatalf("new challenge prior manifest was not restored: %#v %v", manifest, auditErr)
	}
	if _, statErr := os.Lstat(filepath.Join(paths.ConfigRoot, filepath.FromSlash(prepared.Entry.Relative))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed new challenge entry remains: %v", statErr)
	}
}

func TestChallengeRemovalReloadFaultRecreatesExactPriorEntry(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	expected := challenge.Prepared{Entry: &prior}
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	reloadFault := errors.New("removal reload fault")
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest) error { return reloadFault },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore: func(_ context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity) error {
			if !reflect.DeepEqual(manifest, snapshot.Manifest) {
				t.Fatal("removal rollback runtime did not receive prior manifest")
			}
			return nil
		},
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, *expected.Entry, snapshot, prospective, func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(ctx, paths, owner, *expected.Entry)
	}, runtime)
	var failure *Failure
	if !errors.As(err, &failure) || !failure.PriorRestored || !errors.Is(err, reloadFault) {
		t.Fatalf("removal transaction error=%v", err)
	}
	assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, snapshot)
}

func TestStoppedChallengeRemovalCommitsAndVerifiesStoppedRuntime(t *testing.T) {
	paths, owner, _, prior := challengeTransactionFixture(t)
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	observations := 0
	runtime := StoppedChallengeGraphRuntime(func(_ context.Context, manifest nginx.Manifest) (closure.RuntimeSnapshot, error) {
		observations++
		return closure.RuntimeSnapshot{ObservedAt: time.Now().UTC(), Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}, Complete: true, Generation: manifest.GenerationID}, nil
	})
	result, err := CommitChallengeGraph(context.Background(), paths, owner, prior, snapshot, prospective, func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(ctx, paths, owner, prior)
	}, runtime)
	if err != nil || observations != 1 || !reflect.DeepEqual(result.Manifest, prospective) {
		t.Fatalf("stopped removal result=%#v observations=%d err=%v", result, observations, err)
	}
	manifest, err := nginx.Audit(paths, owner)
	if err != nil || !reflect.DeepEqual(manifest, prospective) {
		t.Fatalf("stopped removal graph=%#v err=%v", manifest, err)
	}
}

func TestChallengeGraphTransactionSuccessKeepsProspectiveGraph(t *testing.T) {
	paths, owner, prepared, _ := challengeTransactionFixture(t)
	snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest) error {
			calls = append(calls, "test", "reload", "wait")
			return nil
		},
		Observe: func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) {
			t.Fatal("successful transaction attempted rollback observation")
			return nil, nil
		},
		Restore: func(context.Context, nginx.Manifest, []closure.ProcessIdentity) error {
			t.Fatal("successful transaction attempted rollback")
			return nil
		},
	}
	result, err := CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
	}, runtime)
	if err != nil || !reflect.DeepEqual(result.Manifest, prospective) || !reflect.DeepEqual(calls, []string{"test", "reload", "wait"}) {
		t.Fatalf("successful transaction result=%#v calls=%v err=%v", result, calls, err)
	}
	manifest, err := nginx.Audit(paths, owner)
	if err != nil || !reflect.DeepEqual(manifest, prospective) {
		t.Fatalf("prospective graph was not retained: %#v %v", manifest, err)
	}
}
