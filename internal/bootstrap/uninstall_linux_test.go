//go:build linux

package bootstrap

import (
	"bytes"
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUninstallRequiresExactConfirmation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only uninstall confirmation")
	}
	var output bytes.Buffer
	err := RunPublicUninstall(nil, strings.NewReader("UNINSTALL\n"), &output)
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("non-interactive uninstall was accepted: %v", err)
	}
}

func TestUninstallRejectsOpenAppIngress(t *testing.T) {
	installation := domain.Installation{Resources: []domain.AppResource{{ID: "res_" + strings.Repeat("01", 16), PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished}}}}
	if err := verifyLifecycleIngressClosed(installation); err == nil {
		t.Fatal("published App ingress was accepted")
	}
}

func TestUninstallAcceptsStoppedHistoricalProcess(t *testing.T) {
	installation := domain.Installation{Resources: []domain.AppResource{{ID: "res_" + strings.Repeat("02", 16), PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedStopped, Applied: &domain.ProcessBundle{}}}}}
	if err := verifyLifecycleIngressClosed(installation); err != nil {
		t.Fatalf("stopped historical process was rejected: %v", err)
	}
}

func TestUninstallRejectsUnsafeCurrentAdminToken(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned admin token validation")
	}
	for _, test := range []struct {
		name  string
		setup func(string) error
	}{
		{name: "malformed", setup: func(path string) error { return os.WriteFile(path, []byte("not-an-admin-token"), 0o600) }},
		{name: "writable", setup: func(path string) error { return os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0o644) }},
		{name: "symlink", setup: func(path string) error { return os.Symlink("target", path) }},
		{name: "fifo", setup: func(path string) error { return unix.Mkfifo(path, 0o600) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			installation := filepath.Join(root, "installation")
			if err := os.Mkdir(installation, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(installation, "admin-token")
			if err := test.setup(path); err != nil {
				t.Fatal(err)
			}
			if err := bindCurrentAdminTokenArtifact(Paths{InstallationRoot: installation}, &OwnershipInventory{}); err == nil {
				t.Fatal("unsafe admin token was accepted")
			}
		})
	}
}

func TestUninstallRejectsSymlinkedAdminTokenParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned admin token validation")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	installation := filepath.Join(root, "installation")
	if err := os.Symlink(target, installation); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "admin-token"), []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bindCurrentAdminTokenArtifact(Paths{InstallationRoot: installation}, &OwnershipInventory{}); err == nil {
		t.Fatal("symlinked admin token parent was accepted")
	}
}

func TestUninstallNeverRemovesForeignFile(t *testing.T) {
	path := t.TempDir() + "/foreign"
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedPath(path, map[string]string{path: strings.Repeat("0", 64)}, nil); err == nil {
		t.Fatal("foreign file was accepted for deletion")
	}
}

func TestUninstallRejectsSameContentForeignMetadata(t *testing.T) {
	path := t.TempDir() + "/binary"
	data := []byte("binary")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedFileMetadata(path, info); err == nil {
		t.Fatal("writable same-content file metadata was accepted")
	}
}
