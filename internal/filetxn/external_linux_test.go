//go:build linux

package filetxn

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalArtifactRejectsUnsafeParentsLinksAndDigestMismatch(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "artifact")
	content := []byte("offline artifact")
	if err := os.WriteFile(artifact, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	if _, err := ValidateExternalArtifact(artifact, Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, 1024, digest); err == nil {
		t.Fatal("artifact below a non-root-owned or writable parent was accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(artifact, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateExternalArtifact(link, Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, 1024, digest); err == nil {
		t.Fatal("linked external artifact was accepted")
	}
}
