//go:build linux

package application

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/operations"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func recoveryFixture(operation string) (BasicJournal, domain.Credential) {
	journal := BasicJournal{Operation: operation, CredentialID: "cred_00000000000000000000000000000001", ResourceID: "res_00000000000000000000000000000001", Username: "admin", Path: "/etc/lanpanel-public/basic/cred_00000000000000000000000000000001.htpasswd", PriorFingerprint: "sha256:prior", CandidateFingerprint: "sha256:candidate"}
	credential := managedBasicJournalCredential(journal, journal.PriorFingerprint)
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

func TestManagedBasicRecoveryTerminalizesStaleRotateWithoutTouchingNewCredential(t *testing.T) {
	journal, credential := recoveryFixture("rotate")
	credential.Fingerprint = "sha256:other"
	decision, err := decideManagedBasicRecovery(journal, true, credential, journal.CandidateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.NoEffect || decision.CommitFingerprint || decision.DeleteFile || decision.FileModified {
		t.Fatalf("stale rotation decision=%#v", decision)
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

func TestOldManagedBasicDeletePlanCannotDeleteRotatedCredential(t *testing.T) {
	journal, credential := recoveryFixture("delete")
	credential.Fingerprint = "sha256:rotated"
	decision, err := decideManagedBasicRecovery(journal, true, credential, credential.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.NoEffect || decision.CommitDelete || decision.DeleteFile || decision.FileModified {
		t.Fatalf("old delete Plan decision=%#v", decision)
	}
}

func TestManagedBasicReservedRestartIsRejectedAndTerminalRecordsAreSkipped(t *testing.T) {
	intent := operations.Reservation{Operation: operations.ManagedBasicCreate, Phase: operations.PhaseReserved}
	if stage := classifyManagedBasicRecovery(intent); stage != managedBasicRecoveryReject {
		t.Fatalf("reserved stage=%v", stage)
	}
	for _, phase := range []operations.Phase{operations.PhaseRejected, operations.PhaseTerminal} {
		intent.Phase = phase
		if stage := classifyManagedBasicRecovery(intent); stage != managedBasicRecoverySkip {
			t.Fatalf("terminal phase %q stage=%v", phase, stage)
		}
	}
}
