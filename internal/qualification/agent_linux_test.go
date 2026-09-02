//go:build linux

package qualification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretSentinelDetectsManagedResidue(t *testing.T) {
	root := t.TempDir()
	secret := []byte("qualification-sentinel-secret")
	path := filepath.Join(root, "managed.json")
	if err := os.WriteFile(path, []byte(`{"status":"clean"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSecretSentinelRoots([][]byte{secret}, []string{root}); err != nil {
		t.Fatalf("clean inventory rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"secret":"`+string(secret)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSecretSentinelRoots([][]byte{secret}, []string{root}); err == nil || !strings.Contains(err.Error(), "secret residue") {
		t.Fatalf("secret residue was not detected: %v", err)
	}
}
