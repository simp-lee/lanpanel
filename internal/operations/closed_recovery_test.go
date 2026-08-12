package operations

import (
	"bytes"
	"context"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/persist"
	"testing"
	"time"
)

func TestClosedRecoveryAcceptsEqualAlreadyUnpublishedGeneration(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	normal, manager, admission, mutationSet := newOperationStores(t)
	defer normal.Close()
	defer manager.Close()
	defer mutationSet.Close()
	if err := Register(normal); err != nil {
		t.Fatal(err)
	}
	installation := operationStateInstallation()
	raw, err := persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := normal.Update(context.Background(), admission, 1, func(transaction *persist.Transaction) error {
		return transaction.Create("installations/current", raw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}
	exposure, err := manager.Acquire(context.Background(), "exposure")
	if err != nil {
		t.Fatal(err)
	}
	defer exposure.Release()
	closureDigest := testDigest("closure")
	if err := RecoverClosedInstallation(context.Background(), normal, exposure, map[string]uint64{installation.Resources[0].ID: installation.Resources[0].PublicationRecord.UnpublishedGeneration}, closureDigest, testDigest("safety"), now, bytes.NewReader(bytes.Repeat([]byte{9}, 64))); err != nil {
		t.Fatal(err)
	}
	document, err := normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		t.Fatal(err)
	}
	publication := recovered.Resources[0].PublicationRecord
	if publication.State != domain.PublicationUnpublished || publication.UnpublishedGeneration != 2 || publication.ContractionIntent != nil || publication.LastOperationResult != domain.OperationSucceeded {
		t.Fatalf("recovered publication=%#v", publication)
	}
	found := false
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, key[len("intents/"):])
		if err != nil {
			t.Fatal(err)
		}
		if intent.Operation == StartupContraction {
			record, err := jobs.LoadEntries(document.Entries, intent.JobID)
			if err != nil || intent.Phase != PhaseTerminal || record.Result != jobs.ResultSucceeded {
				t.Fatalf("recovery intent=%#v job=%#v error=%v", intent, record, err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("startup recovery job was not persisted")
	}
}
