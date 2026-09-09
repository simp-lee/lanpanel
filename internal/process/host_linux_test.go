//go:build linux

package process

import (
	"lanpanel/internal/resource"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOwnedDirectoryUsesLinuxFileMetadata(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateOwnedDirectory(path, 0o700, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatalf("matching directory metadata rejected: %v", err)
	}
	if err := validateOwnedDirectory(path, 0o750, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("mismatched directory mode accepted")
	}
}

func TestExpectedRelayPolicyUsesDerivedBackendDirectory(t *testing.T) {
	resourceID := "res_00000000000000000000000000000001"
	paths, err := resource.DerivePaths(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := expectedRelayPolicy(resourceID, 1001, 1002)
	if err != nil {
		t.Fatal(err)
	}
	want := "BindReadOnlyPaths=" + filepath.Dir(paths.BackendSocket) + ":/backend"
	for _, directive := range policy.Directives {
		if directive == want {
			return
		}
	}
	t.Fatalf("relay policy does not bind the derived backend directory: %#v", policy.Directives)
}
