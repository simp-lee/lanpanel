//go:build linux

package basic

import (
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedBasicFreshRootCreatesPrivateFileTransactionDirectory(t *testing.T) {
	root := t.TempDir()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	basicFD, err := ensureOwnedBasicDirectory(fd, "basic", stat.Uid, stat.Gid, 0o750)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(basicFD) }()
	txnFD, err := ensureOwnedBasicDirectory(basicFD, ".txn", stat.Uid, stat.Gid, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(txnFD) }()
	if err = unix.Fstat(txnFD, &stat); err != nil || stat.Mode&0o7777 != 0o700 {
		t.Fatalf("private staging metadata invalid: %#v %v", stat, err)
	}
	owner := filetxn.Owner{UID: stat.Uid, GID: stat.Gid}
	store, err := filetxn.Open(filetxn.Config{RootPath: filepath.Join(root, "basic"), Root: filetxn.Metadata{Owner: owner, Mode: 0o750}, StagingPath: filepath.Join(root, "basic", ".txn"), Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}}, filetxn.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedBasicExistingDirectoryDriftFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(root+"/basic", 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	if child, err := ensureOwnedBasicDirectory(fd, "basic", stat.Uid, stat.Gid, 0o750); err == nil {
		_ = unix.Close(child)
		t.Fatal("drifted directory was normalized")
	}
}

func TestGenerateUsesFixedCostBcrypt(t *testing.T) {
	generated, err := Generate("admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Password) != 43 || !strings.HasPrefix(string(generated.Record), "admin:$2y$12$") || strings.Contains(string(generated.Record), string(generated.Password)) {
		t.Fatalf("generation contract failed")
	}
}
