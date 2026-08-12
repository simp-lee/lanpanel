//go:build linux

package bootstrap

import (
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalRecoveryUsesLastIntactSlot(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	journal := testJournal(root)
	store, err := createJournal(journal.Paths.Journal, uint32(os.Geteuid()), uint32(os.Getegid()), journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.Sequence = 2
	journal.Phase = PhaseBundleCommitted
	journal.ArtifactDigests["bundle"] = strings.Repeat("a", 64)
	if err := store.update(journal); err != nil {
		t.Fatal(err)
	}
	slot := store.slot
	_ = store.close()
	file, err := os.OpenFile(journal.Paths.Journal, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteAt([]byte("corrupt"), int64(slot*journalSlotBytes))
	_ = file.Close()
	opened, loaded, err := openJournal(journal.Paths.Journal, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	if loaded.Sequence != 1 {
		t.Fatalf("loaded sequence=%d", loaded.Sequence)
	}
}

func TestPartialAccountEvidenceIsNotACompleteInstallation(t *testing.T) {
	set, _ := identity.InstallationAccounts("ins_00000000000000000000000000000001")
	root := t.TempDir()
	passwd := filepath.Join(root, "passwd")
	group := filepath.Join(root, "group")
	shadow := filepath.Join(root, "shadow")
	spec := set.Specs[0]
	_ = os.WriteFile(passwd, []byte(spec.User+":x:3100:3200:"+spec.Comment+":"+spec.Home+":"+spec.Shell+"\n"), 0o600)
	_ = os.WriteFile(group, []byte(set.HelperClientGroup+":x:3200:\n"), 0o600)
	_ = os.WriteFile(shadow, []byte(spec.User+":!:1:0:99999:7:::\n"), 0o600)
	if _, _, err := identity.InspectAccountFiles(set, passwd, group, shadow); err == nil {
		t.Fatal("partial first-install identity was adopted as complete")
	}
}
