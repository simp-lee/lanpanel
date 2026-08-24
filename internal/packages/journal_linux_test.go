//go:build linux

package packages

import (
	"context"
	"lanpanel/internal/child"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyPackageJournalSchemaIsRejected(t *testing.T) {
	if ValidateJournal(Journal{SchemaVersion: "lanpanel.package.journal.v1"}) == nil {
		t.Fatal("legacy package journal schema accepted")
	}
}

func TestPackageJournalFileStorePersistsCanonicalCASPhases(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	transactions := filepath.Join(root, "transactions")
	for _, path := range []string{staging, transactions} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	files, err := filetxn.Open(filetxn.Config{
		RootPath: root, Root: filetxn.Metadata{Owner: owner, Mode: 0o700},
		StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700},
		StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700},
	}, filetxn.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(files.Close)
	store, err := NewFileJournalStore(files, transactions, owner)
	if err != nil {
		t.Fatal(err)
	}
	transactionID := "pkg_" + strings.Repeat("1", 64)
	prepared := Journal{SchemaVersion: PackageJournalSchemaVersion, TransactionID: transactionID, NormalJournalID: "package-" + transactionID, ChildID: "package-child-" + transactionID, JobID: "job_" + strings.Repeat("2", 64), PlanDigest: strings.Repeat("3", 64), AuthorityDigest: strings.Repeat("4", 64), PackageProfile: child.ProfileAPTTransaction, Prior: RuntimeSnapshot{Installed: []Package{}, Units: []UnitState{}, Listeners: []Listener{}}, Phase: JournalPrepared, Masks: []MaskIdentity{}}
	if err := store.Create(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	masked := prepared
	masked.Phase = JournalFilesPrepared
	if err := store.Advance(context.Background(), prepared, masked); err != nil {
		t.Fatal(err)
	}
	got, err := store.Read(context.Background(), prepared.TransactionID)
	if err != nil || got.Phase != JournalFilesPrepared {
		t.Fatalf("journal=%#v error=%v", got, err)
	}
	if err := store.Advance(context.Background(), prepared, masked); err == nil {
		t.Fatal("stale package journal phase was accepted")
	}
	pending, err := store.Pending(context.Background())
	if err != nil || len(pending) != 1 || pending[0].TransactionID != prepared.TransactionID {
		t.Fatalf("pending=%#v error=%v", pending, err)
	}
	cleaned := prepared
	cleaned.TransactionID = "pkg_" + strings.Repeat("5", 64)
	cleaned.NormalJournalID = "package-" + cleaned.TransactionID
	cleaned.ChildID = "package-child-" + cleaned.TransactionID
	cleaned.Phase = JournalCleaned
	cleaned.MasksComplete = true
	cleaned.ChildSucceeded = true
	cleaned.ChildResultDigest = strings.Repeat("6", 64)
	cleaned.PostconditionDigest = strings.Repeat("7", 64)
	data, err := encodeJournal(cleaned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.files.Put(context.Background(), store.request(cleaned.TransactionID, nil), data, filetxn.CreateOnly); err != nil {
		t.Fatal(err)
	}
	pending, err = store.Pending(context.Background())
	if err != nil || len(pending) != 1 || pending[0].TransactionID != prepared.TransactionID {
		t.Fatalf("cleaned journal entered pending inventory: %#v, %v", pending, err)
	}
	if _, err := store.Read(context.Background(), cleaned.TransactionID); err != nil {
		t.Fatalf("cleaned retry journal was not retained: %v", err)
	}
}
