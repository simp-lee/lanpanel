//go:build linux

package bootstrap

import (
	"bytes"
	"lanpanel/internal/domain"
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

func TestUninstallNeverRemovesForeignFile(t *testing.T) {
	path := t.TempDir() + "/foreign"
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedPath(path, map[string]string{path: strings.Repeat("0", 64)}, nil); err == nil {
		t.Fatal("foreign file was accepted for deletion")
	}
}
