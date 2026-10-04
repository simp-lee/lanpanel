//go:build linux

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyResumeInventoryAllowsInterruptedBootstrapResidue(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	transactionID := "txn_resume"
	journal := Journal{Phase: PhaseNginxMasked, Paths: paths, PackageTransactionID: transactionID, PlannedPaths: []string{
		paths.PersistentRoot,
		paths.PackageRoot,
		filepath.Join(paths.PackageRoot, "journals"),
		filepath.Join(paths.PackageRoot, "transactions"),
		filepath.Join(paths.PackageRoot, "staging"),
		paths.LockRoot,
		paths.RuntimeRoot,
	}}

	files := []string{
		filepath.Join(paths.LockRoot, "mutation-admission.lock"),
		filepath.Join(paths.LockRoot, "exposure.lock"),
		filepath.Join(paths.RuntimeRoot, "helper.sock"),
		testNginxPaths(paths).PIDPath,
		filepath.Join(paths.PackageRoot, "journals", transactionID+".json"),
		filepath.Join(paths.PackageRoot, "transactions", transactionID, "apt.conf"),
		filepath.Join(paths.PackageRoot, "transactions", transactionID, "archives", "partial", "download.part"),
		filepath.Join(paths.PackageRoot, "staging", transactionID, "package.deb"),
	}
	for _, path := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("interrupted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyResumeInventory(journal); err != nil {
		t.Fatalf("owned interrupted residue was rejected: %v", err)
	}
	prepared := journal
	prepared.Phase = PhasePrepared
	if err := verifyResumeInventory(prepared); err == nil {
		t.Fatal("package journal was accepted before package masking")
	}

	foreign := filepath.Join(paths.PackageRoot, "journals", "txn_foreign.json")
	if err := os.MkdirAll(filepath.Dir(foreign), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyResumeInventory(journal); err == nil {
		t.Fatal("foreign package journal residue was accepted")
	}
}
