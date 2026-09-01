package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/persist"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPendingClosedRecoveryRejectsChangedConsumedAuthority(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	closure := testDigest("closure-a")
	safetyDigest := testDigest("safety")
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: "job_" + strings.Repeat("1", 64), AdmissionSource: AdmissionStartup, Operation: StartupContraction, Target: "installation", Phase: PhaseLocalIntent, SafetyDigest: safetyDigest, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionStartup, ConfirmationDigest: closure, ConfirmedAt: now, SafetyDigest: safetyDigest}}
	raw, err := persist.EncodeEntry(intent)
	if err != nil {
		t.Fatal(err)
	}
	document := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{"intents/" + intent.JobID: raw}}
	if _, _, err := pendingClosedRecovery(document, testDigest("different-closure"), safetyDigest); err == nil {
		t.Fatal("consumed startup recovery accepted a different closure digest")
	}
	if found, present, err := pendingClosedRecovery(document, closure, safetyDigest); err != nil || !present || found.JobID != intent.JobID {
		t.Fatalf("exact consumed startup authority was not reusable: found=%#v present=%t err=%v", found, present, err)
	}
}

func TestClosedRecoveryRejectsInexactGenerationInventoryBeforeWriting(t *testing.T) {
	base := operationStateInstallation()
	second := base.Resources[0]
	second.ID = "res_00000000000000000000000000000002"
	second.Name = "Second App"
	second.ManagedProcess = func() *domain.ManagedProcess {
		value := *second.ManagedProcess
		value.ID = "proc_00000000000000000000000000000002"
		return &value
	}()
	tests := []struct {
		name         string
		installation domain.Installation
		generations  map[string]uint64
	}{
		{name: "empty", installation: base, generations: map[string]uint64{}},
		{name: "missing", installation: func() domain.Installation {
			value := base
			value.Resources = append(append([]domain.AppResource(nil), base.Resources...), second)
			return value
		}(), generations: map[string]uint64{base.Resources[0].ID: 3}},
		{name: "extra", installation: base, generations: map[string]uint64{base.Resources[0].ID: 3, "res_00000000000000000000000000000002": 3}},
		{name: "invalid_identity", installation: base, generations: map[string]uint64{"invalid/id": 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0).UTC()
			normal, manager, admission, mutationSet := newOperationStores(t)
			defer func() { _ = normal.Close(); _ = manager.Close(); _ = mutationSet.Close() }()
			if err := Register(normal); err != nil {
				t.Fatal(err)
			}
			raw, err := persist.EncodeEntry(test.installation)
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
			defer func() { _ = exposure.Release() }()
			before, err := normal.Read()
			if err != nil {
				t.Fatal(err)
			}
			err = RecoverClosedInstallation(context.Background(), normal, exposure, test.generations, nil, testDigest("closure"), testDigest("safety"), now, bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
			if err == nil {
				t.Fatal("inexact closed-recovery generation inventory was accepted")
			}
			after, readErr := normal.Read()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if after.Revision != before.Revision || len(persist.EntryKeys(after, "intents")) != 0 || len(persist.EntryKeys(after, "jobs")) != 0 {
				t.Fatalf("closed recovery wrote before rejecting inventory: before=%d after=%d", before.Revision, after.Revision)
			}
		})
	}
}

func TestClosedRecoveryAcceptsEqualAlreadyUnpublishedGeneration(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	normal, manager, admission, mutationSet := newOperationStores(t)
	defer func(ignore func() error) { _ = ignore() }(normal.Close)
	defer func(ignore func() error) { _ = ignore() }(manager.Close)
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
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
	defer func(ignore func() error) { _ = ignore() }(exposure.Release)
	closureDigest := testDigest("closure")
	modifiedPaths := []string{"/etc/lanpanel/nginx/apps-enabled/recovered.conf"}
	if err := RecoverClosedInstallation(context.Background(), normal, exposure, map[string]uint64{installation.Resources[0].ID: installation.Resources[0].PublicationRecord.UnpublishedGeneration}, modifiedPaths, closureDigest, testDigest("safety"), now, bytes.NewReader(bytes.Repeat([]byte{9}, 64))); err != nil {
		t.Fatal(err)
	}
	document, err := normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	terminalRevision := document.Revision
	if err := RecoverClosedInstallation(context.Background(), normal, exposure, map[string]uint64{installation.Resources[0].ID: installation.Resources[0].PublicationRecord.UnpublishedGeneration}, modifiedPaths, closureDigest, testDigest("safety"), now.Add(time.Second), bytes.NewReader(bytes.Repeat([]byte{10}, 64))); err != nil {
		t.Fatalf("terminal closed recovery was not idempotent: %v", err)
	}
	document, err = normal.Read()
	if err != nil || document.Revision != terminalRevision {
		t.Fatalf("terminal closed recovery wrote duplicate evidence: revision=%d want=%d err=%v", document.Revision, terminalRevision, err)
	}
	if err := RecoverClosedInstallation(context.Background(), normal, exposure, map[string]uint64{installation.Resources[0].ID: installation.Resources[0].PublicationRecord.UnpublishedGeneration}, nil, closureDigest, testDigest("safety"), now.Add(2*time.Second), bytes.NewReader(bytes.Repeat([]byte{11}, 64))); err != nil {
		t.Fatalf("terminal closed recovery did not reuse persisted modified paths: %v", err)
	}
	afterEmptyRetry, err := normal.Read()
	if err != nil || afterEmptyRetry.Revision != terminalRevision {
		t.Fatalf("empty-path terminal retry wrote duplicate evidence: revision=%d want=%d err=%v", afterEmptyRetry.Revision, terminalRevision, err)
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
			if err != nil || intent.Phase != PhaseTerminal || record.Result != jobs.ResultSucceeded || !slices.Equal(record.ModifiedPaths, modifiedPaths) {
				t.Fatalf("recovery intent=%#v job=%#v error=%v", intent, record, err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("startup recovery job was not persisted")
	}
}
