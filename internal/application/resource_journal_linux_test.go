//go:build linux

package application

import (
	"encoding/json"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestResourceJournalReadersRequireCanonicalSafeFiles(t *testing.T) {
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	resource := recoveryTailnetResource()
	jobID := "job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	create := ResourceCreateJournal{SchemaVersion: resourceCreateJournalSchema, JobID: jobID, ResourceID: resource.ID, Resource: resource, Phase: "prepared"}
	update := ResourceUpdateJournal{SchemaVersion: resourceUpdateJournalSchema, JobID: jobID, ResourceID: resource.ID, Prior: resource, Candidate: resource}
	createBytes, err := json.Marshal(create)
	if err != nil {
		t.Fatal(err)
	}
	updateBytes, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	newPath := func(data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), resource.ID+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("canonical", func(t *testing.T) {
		if _, err := readCreateJournal(newPath(createBytes), owner); err != nil {
			t.Fatalf("canonical create journal rejected: %v", err)
		}
		if _, err := readResourceUpdateJournal(newPath(updateBytes), owner); err != nil {
			t.Fatalf("canonical update journal rejected: %v", err)
		}
	})

	t.Run("strict_schema", func(t *testing.T) {
		createUnknown := append(append([]byte(nil), createBytes[:len(createBytes)-1]...), []byte(`,"unknown":true}`)...)
		if _, err := readCreateJournal(newPath(createUnknown), owner); err == nil {
			t.Fatal("create journal with an unknown field was accepted")
		}
		updateUnknown := append(append([]byte(nil), updateBytes[:len(updateBytes)-1]...), []byte(`,"unknown":true}`)...)
		if _, err := readResourceUpdateJournal(newPath(updateUnknown), owner); err == nil {
			t.Fatal("update journal with an unknown field was accepted")
		}
	})

	t.Run("config_identity", func(t *testing.T) {
		invalid := create
		invalid.Resource.CurrentConfigDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		data, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readCreateJournal(newPath(data), owner); err == nil {
			t.Fatal("resource journal with an inconsistent config digest was accepted")
		}
	})

	t.Run("mode", func(t *testing.T) {
		path := newPath(createBytes)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := readCreateJournal(path, owner); err == nil {
			t.Fatal("resource journal with unsafe mode was accepted")
		}
	})

	t.Run("owner_and_group", func(t *testing.T) {
		path := newPath(createBytes)
		wrong := filetxn.Owner{UID: owner.UID + 1, GID: owner.GID + 1}
		if _, err := readCreateJournal(path, wrong); err == nil {
			t.Fatal("resource journal with unexpected owner and group was accepted")
		}
	})

	t.Run("hard_link", func(t *testing.T) {
		source := newPath(createBytes)
		path := filepath.Join(t.TempDir(), resource.ID+".json")
		if err := os.Link(source, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readCreateJournal(path, owner); err == nil {
			t.Fatal("hard-linked resource journal was accepted")
		}
	})

	t.Run("symbolic_link", func(t *testing.T) {
		target := newPath(updateBytes)
		path := filepath.Join(t.TempDir(), resource.ID+".json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readResourceUpdateJournal(path, owner); err == nil {
			t.Fatal("symbolic-link resource journal was accepted")
		}
	})

	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), resource.ID+".json")
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCreateJournal(path, owner); err == nil {
			t.Fatal("FIFO resource journal was accepted")
		}
	})

	t.Run("resource_path_binding", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "res_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json")
		if err := os.WriteFile(path, createBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCreateJournal(path, owner); err == nil {
			t.Fatal("resource journal stored under another resource name was accepted")
		}
	})
}
