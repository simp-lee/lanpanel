//go:build linux

package acme

import (
	"crypto/rand"
	"lanpanel/internal/acmeaccount"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountStageBindsExactManagedKeyFingerprint(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	root := protectedTestDir(t)
	key, err := acmeaccount.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "account.key")
	if err := os.WriteFile(source, key, 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := acmeaccount.Fingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	stageRoot := filepath.Join(root, "stage")
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := Stage{Root: stageRoot, UID: 2200000, GID: 2200000}
	if err := stage.copyProtectedTo(source, "/work/account.key", stage.UID, stage.GID, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := stage.copyProtectedTo(source, "/work/other.key", stage.UID, stage.GID, "sha256:"+"0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("account key changed from bound fingerprint was staged")
	}
}
