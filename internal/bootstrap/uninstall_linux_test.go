//go:build linux

package bootstrap

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestUninstallRequiresExactConfirmation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only uninstall confirmation")
	}
	var output bytes.Buffer
	err := RunPublicUninstall(nil, strings.NewReader("UNINSTALL\n"), &output)
	if err == nil || !strings.Contains(err.Error(), "exact confirmation") {
		t.Fatalf("wrong uninstall confirmation was accepted: %v", err)
	}
}

func TestUninstallNeverRemovesForeignFile(t *testing.T) {
	path := t.TempDir() + "/foreign"
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedPath(path, map[string]string{path: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("foreign file was accepted for deletion")
	}
}
