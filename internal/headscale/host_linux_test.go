//go:build linux

package headscale

import (
	"bytes"
	"context"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquisitionRetryRemovesOnlyExactOwnedPartialStaging(t *testing.T) {
	directory := t.TempDir()
	name := "job_00000000000000000000000000000001.archive"
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if err := reconcileAcquisitionStaging(directory, name, owner, 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("exact partial staging was not removed")
	}
	if err := os.Symlink("elsewhere", path); err != nil {
		t.Fatal(err)
	}
	if err := reconcileAcquisitionStaging(directory, name, owner, 1024); err == nil {
		t.Fatal("foreign staging symlink was removed")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("foreign staging evidence was not preserved")
	}
}

func TestInstallCommitsExactExecutableAndIdentityBeforeDatabase(t *testing.T) {
	root := t.TempDir()
	paths := fixturePaths(root)
	prepareDirectories(t, paths)
	installed, archive := fixtureRelease()
	candidate, _, snapshot, err := NewCandidate(CandidateRequest{InstallationID: "ins_00000000000000000000000000000001", ControlDomain: "control.example.com", MagicDNSNamespace: "tail.example.net", Release: installed, Random: bytes.NewReader(bytes.Repeat([]byte{3}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	request := InstallRequest{Paths: paths, Owner: owner, Release: installed, Candidate: candidate, SnapshotBytes: snapshot, ArchiveBytes: archive}
	if err := Install(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := Install(context.Background(), request); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}
	if data, err := os.ReadFile(paths.Executable); err != nil || string(data) != "headscale-fixture" {
		t.Fatalf("executable = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(paths.IdentityParent, paths.IdentityName, "snapshot.json")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.SQLite, paths.SQLite + "-wal", paths.SQLite + "-shm"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("database evidence created at %s", path)
		}
	}
}

func TestInstallRejectsForeignDatabaseAndArtifactBeforeIdentityCommit(t *testing.T) {
	for _, mutate := range []func(Paths, *InstallRequest){
		func(paths Paths, _ *InstallRequest) { _ = os.WriteFile(paths.SQLite+"-wal", []byte("foreign"), 0o600) },
		func(_ Paths, request *InstallRequest) {
			request.ArchiveBytes = append([]byte(nil), request.ArchiveBytes...)
			request.ArchiveBytes[0] ^= 1
		},
	} {
		root := t.TempDir()
		paths := fixturePaths(root)
		prepareDirectories(t, paths)
		installed, archive := fixtureRelease()
		candidate, _, snapshot, err := NewCandidate(CandidateRequest{InstallationID: "ins_00000000000000000000000000000001", ControlDomain: "control.example.com", MagicDNSNamespace: "tail.example.net", Release: installed, Random: bytes.NewReader(bytes.Repeat([]byte{4}, 32))})
		if err != nil {
			t.Fatal(err)
		}
		request := InstallRequest{Paths: paths, Owner: filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, Release: installed, Candidate: candidate, SnapshotBytes: snapshot, ArchiveBytes: archive}
		mutate(paths, &request)
		if err := Install(context.Background(), request); err == nil {
			t.Fatal("foreign evidence was accepted")
		}
		if _, err := os.Lstat(filepath.Join(paths.IdentityParent, paths.IdentityName)); !os.IsNotExist(err) {
			t.Fatal("identity committed after rejected evidence")
		}
	}
}

func fixturePaths(root string) Paths {
	return Paths{Root: root, Staging: filepath.Join(root, "var/lib/lanpanel/headscale/.filetxn"), Executable: filepath.Join(root, "usr/lib/lanpanel/dependencies/headscale"), IdentityParent: filepath.Join(root, "var/lib/lanpanel/headscale"), IdentityName: "identity", SQLite: filepath.Join(root, "var/lib/lanpanel/headscale-runtime/db.sqlite")}
}

func prepareDirectories(t *testing.T, paths Paths) {
	t.Helper()
	if err := os.Chmod(paths.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Staging, filepath.Dir(paths.Executable), paths.IdentityParent, filepath.Dir(paths.SQLite)} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if path == filepath.Dir(paths.Executable) {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
}
