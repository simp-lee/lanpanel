//go:build linux

package download

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStagingRereadsExactOwnerModeSizeAndDigest(t *testing.T) {
	payload := []byte("verified staging bytes")
	file, err := os.CreateTemp(t.TempDir(), "stage-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	directoryFD, err := unix.Open(filepath.Dir(file.Name()), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	staging := &StagingFile{file: file, path: file.Name(), maximum: 1024, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()), directoryFD: directoryFD}
	if _, err := staging.Write(payload); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	if path, err := staging.CloseVerified(digest, int64(len(payload))); err != nil || path != file.Name() {
		t.Fatalf("path=%q error=%v", path, err)
	}
}

func TestCreateStagingRejectsUnsafeParentAndNames(t *testing.T) {
	unsafe := t.TempDir()
	if _, err := CreateStaging(unsafe, "artifact", uint32(os.Geteuid()), uint32(os.Getegid()), 1024); err == nil {
		t.Fatal("non-root-owned staging parent was accepted")
	}
	if _, err := CreateStaging(filepath.Clean("relative"), "../artifact", 0, 0, 1024); err == nil {
		t.Fatal("relative staging path or escaping name was accepted")
	}
}
