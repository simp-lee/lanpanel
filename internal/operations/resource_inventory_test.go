package operations

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
	"reflect"
	"testing"
	"time"
)

func inventoryTestJournal(t *testing.T, id string, generation uint64, fingerprint string) (JournalRecord, jobs.Record, Reservation) {
	t.Helper()
	now := time.Now().UTC()
	resource := operationStateInstallation().Resources[0]
	job, err := jobs.NewReserved(jobs.Spec{Operation: string(CertificateRenew), Target: "resource/" + resource.ID, ActorIdentity: "timer/certificate-renewal"}, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job, err = jobs.Start(job)
	if err != nil {
		t.Fatal(err)
	}
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: job.ID, AdmissionSource: AdmissionTimer, Operation: CertificateRenew, Target: job.Target, Phase: PhaseLocalIntent, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{ResourceID: resource.ID}, CreatedAt: now, IntentGeneration: 1, Consumption: &ConsumptionSnapshot{Source: AdmissionTimer, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	bundle := certificates.BundleIdentity{Fingerprint: testDigest(fingerprint), SANIdentity: testDigest("san"), ChainIdentity: testDigest("chain"), IssuerIdentity: testDigest("issuer"), BindingIdentity: testDigest("binding"), DirectoryIdentity: testDigest("directory")}
	path, _ := certificates.BundlePath(id, generation)
	journal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + job.ID, JobID: job.ID, Kind: JournalCertificateActivation, Operation: CertificateRenew, InstallationID: operationStateInstallation().InstallationID, Target: job.Target, Generation: generation, Deadline: now.Add(time.Hour), ArtifactDigest: testDigest("artifact"), SafetyMarkerDigest: testDigest("safety"), ResourceIDs: []string{resource.ID}, ChildIDs: []string{"child-one"}, Phase: JournalPrepared, Certificate: &CertificateJournalIdentity{CertificateID: id, CandidateGeneration: generation, CandidatePointer: path, CandidateFingerprint: bundle.Fingerprint, CandidateBundleIdentity: bundle, Challenge: safety.ChallengePending{Generation: generation, PlanID: "plan-one", CertificateIdentity: id}, StageUID: 1200, StageGID: 1200}}
	return journal, job, intent
}

func TestResourceCertificateInventorySurvivesTerminalJournalPruning(t *testing.T) {
	normal, manager, admission, mutation := newOperationStores(t)
	defer func() { _ = admission.Release(); _ = normal.Close(); _ = mutation.Close(); _ = manager.Close() }()
	ctx := context.Background()
	installation := operationStateInstallation()
	raw, _ := persist.EncodeEntry(installation)
	if _, _, err := normal.Update(ctx, admission, 1, func(transaction *persist.Transaction) error { return transaction.Create("installations/current", raw) }); err != nil {
		t.Fatal(err)
	}
	// Exercise the retention/staging primitives here. Their transaction
	// provenance is checked separately below against the real validator.
	if err := normal.RegisterCanonicalDocumentTransitionValidator("operations.resource_transitions.v1", func(persist.Document, persist.Document) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var expected []certificates.Artifact
	for _, candidate := range []struct {
		id          string
		generation  uint64
		fingerprint string
	}{
		{"cert_00000000000000000000000000000001", 1, "first"},
		{"cert_00000000000000000000000000000001", 2, "failed"},
		{"cert_00000000000000000000000000000001", 2, "retry"},
		{"cert_00000000000000000000000000000002", 1, "republish"},
	} {
		journal, job, intent := inventoryTestJournal(t, candidate.id, candidate.generation, candidate.fingerprint)
		artifact, _ := journalResourceArtifact(journal)
		expected = certificates.AddArtifact(expected, artifact)
		terminal, err := jobs.Finish(job, jobs.Completion{Result: jobs.ResultFailed, ErrorCode: "certificate_setup_failed", Postconditions: []jobs.Postcondition{{Kind: "certificate_not_activated", Status: jobs.PostconditionVerified, Identity: artifact.CertificateID}}}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		intent.Phase = PhaseTerminal
		journal.Phase = JournalTerminal
		document, _ := normal.Read()
		_, _, err = normal.Update(ctx, admission, document.Revision, func(transaction *persist.Transaction) error {
			if err := retainResourceCertificateArtifact(transaction, journal); err != nil {
				return err
			}
			for key, value := range map[string]any{"journals/" + journal.ID: journal, "jobs/" + job.ID: terminal, "intents/" + job.ID: intent} {
				raw, _ := persist.EncodeEntry(value)
				if err := transaction.Create(key, raw); err != nil {
					return err
				}
			}
			return pruneTerminalGraphs(transaction, 0)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	document, err := normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(persist.EntryKeys(document, "journals")) != 0 {
		t.Fatal("terminal journals not pruned")
	}
	installation, err = domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(installation.Resources[0].PublicationRecord.CertificateInventory, expected) {
		t.Fatalf("lost historical certificate authority: %+v", installation.Resources[0].PublicationRecord.CertificateInventory)
	}
}

func TestCertificateInventoryCannotBeRewrittenWithoutStagingAuthority(t *testing.T) {
	journal, job, intent := inventoryTestJournal(t, "cert_00000000000000000000000000000001", 1, "first")
	prior := operationStateInstallation().Resources[0]
	artifact, _ := journalResourceArtifact(journal)
	candidate := prior
	candidate.PublicationRecord.CertificateInventory = certificates.AddArtifact(nil, artifact)
	encode := func(value any) json.RawMessage {
		raw, err := persist.EncodeEntry(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := persist.Document{Entries: map[string]json.RawMessage{}}
	after := persist.Document{Entries: map[string]json.RawMessage{"journals/" + journal.ID: encode(journal), "jobs/" + job.ID: encode(job), "intents/" + job.ID: encode(intent)}}
	if err := validateCertificateInventoryTransition(before, after, prior, candidate); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing_journal", "unchanged_journal", "foreign_resource", "rewrite_bytes", "unrelated_config", "deleting"} {
		t.Run(scenario, func(t *testing.T) {
			old, next := prior, candidate
			beforeDoc := persist.Document{Entries: map[string]json.RawMessage{}}
			afterDoc := persist.Document{Entries: map[string]json.RawMessage{}}
			for key, raw := range after.Entries {
				afterDoc.Entries[key] = bytes.Clone(raw)
			}
			switch scenario {
			case "missing_journal":
				delete(afterDoc.Entries, "journals/"+journal.ID)
			case "unchanged_journal":
				beforeDoc.Entries["journals/"+journal.ID] = afterDoc.Entries["journals/"+journal.ID]
			case "foreign_resource":
				next.ID = "res_00000000000000000000000000000002"
			case "rewrite_bytes":
				other := artifact
				other.Bundle.Fingerprint = testDigest("foreign")
				next.PublicationRecord.CertificateInventory = []certificates.Artifact{other}
			case "unrelated_config":
				next.Name = "changed"
			case "deleting":
				old.Lifecycle = domain.LifecycleDeleting
				next.Lifecycle = domain.LifecycleDeleting
			}
			if err := validateCertificateInventoryTransition(beforeDoc, afterDoc, old, next); err == nil {
				t.Fatal("unowned inventory update accepted")
			}
		})
	}
}
