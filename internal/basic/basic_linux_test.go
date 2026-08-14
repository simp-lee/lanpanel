//go:build linux

package basic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"lanpanel/internal/child"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeRunner struct {
	input []byte
	inv   child.Invocation
}

func (f *fakeRunner) RunInvocation(_ context.Context, _ child.ProfileID, inv child.Invocation, input []byte) (child.Result, error) {
	f.input = append([]byte(nil), input...)
	f.inv = inv
	empty := sha256.Sum256(nil)
	return child.Result{ExitCode: 0, Stdout: []byte("admin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234\n"), StderrDigest: "sha256:" + hex.EncodeToString(empty[:])}, nil
}
func TestManagedBasicFreshRootCreatesPrivateFileTransactionDirectory(t *testing.T) {
	root := t.TempDir()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	basicFD, err := ensureOwnedBasicDirectory(fd, "basic", stat.Uid, stat.Gid, 0o750)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(basicFD)
	txnFD, err := ensureOwnedBasicDirectory(basicFD, ".txn", stat.Uid, stat.Gid, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(txnFD)
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
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	if child, err := ensureOwnedBasicDirectory(fd, "basic", stat.Uid, stat.Gid, 0o750); err == nil {
		unix.Close(child)
		t.Fatal("drifted directory was normalized")
	}
}

func TestGenerateKeepsPasswordOffInvocation(t *testing.T) {
	runner := &fakeRunner{}
	generated, err := Generate(context.Background(), runner, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Password) != 43 || string(runner.input) != string(generated.Password)+"\n" || runner.inv.HTPasswd == nil || runner.inv.HTPasswd.Username != "admin" {
		t.Fatalf("generation contract failed")
	}
	if strings.Contains(strings.Join([]string{runner.inv.HTPasswd.Username}, " "), string(generated.Password)) {
		t.Fatal("password entered invocation")
	}
}
