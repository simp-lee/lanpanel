//go:build linux

package application

import (
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func recoveryFixture(operation string) (BasicJournal, domain.Credential) {
	journal := BasicJournal{Operation: operation, CredentialID: "cred_00000000000000000000000000000001", Username: "admin", Path: "/etc/lanpanel-public/basic/cred_00000000000000000000000000000001.htpasswd", PriorFingerprint: "sha256:prior", CandidateFingerprint: "sha256:candidate"}
	credential := domain.Credential{ID: journal.CredentialID, Username: journal.Username, ManagedPath: journal.Path, Fingerprint: journal.PriorFingerprint}
	return journal, credential
}

func TestManagedBasicRestartInventoryAcceptsExactFileTransactionDirectory(t *testing.T) {
	directory := t.TempDir()
	staging := filepath.Join(directory, ".filetxn")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(staging, &stat); err != nil {
		t.Fatal(err)
	}
	paths, err := managedBasicJournalInventory(directory, stat.Uid, stat.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("unexpected journals: %v", paths)
	}
}

func TestCommittedManagedBasicCreateResponseLossRetainsCredentialForRotateAgain(t *testing.T) {
	journal, credential := recoveryFixture("create")
	credential.Fingerprint = journal.CandidateFingerprint
	decision, err := decideManagedBasicRecovery(journal, true, credential, journal.CandidateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.LostDelivery || decision.DeleteFile || !decision.FileModified {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestUncommittedManagedBasicCreateResponseLossDeletesCandidate(t *testing.T) {
	journal, credential := recoveryFixture("create")
	decision, err := decideManagedBasicRecovery(journal, false, credential, journal.CandidateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if decision.LostDelivery || !decision.DeleteFile || !decision.FileModified {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestCommittedManagedBasicRotateResponseLossConvergesFingerprint(t *testing.T) {
	journal, credential := recoveryFixture("rotate")
	decision, err := decideManagedBasicRecovery(journal, true, credential, journal.CandidateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.CommitFingerprint || !decision.LostDelivery || decision.DeleteFile {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestManagedBasicRecoveryRejectsAmbiguousRotateState(t *testing.T) {
	journal, credential := recoveryFixture("rotate")
	credential.Fingerprint = "sha256:other"
	if _, err := decideManagedBasicRecovery(journal, true, credential, journal.CandidateFingerprint); err == nil {
		t.Fatal("ambiguous rotate accepted")
	}
}

func TestInterruptedManagedBasicDeleteConvergesMetadataAndFile(t *testing.T) {
	journal, credential := recoveryFixture("delete")
	decision, err := decideManagedBasicRecovery(journal, true, credential, journal.PriorFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.CommitDelete || !decision.DeleteFile || decision.LostDelivery {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}
