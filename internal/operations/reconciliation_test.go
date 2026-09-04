package operations

import (
	"encoding/json"
	"lanpanel/internal/certificates"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
	"testing"
	"time"
)

func TestPendingJournalRecoveryRequiresTerminalJournals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	journal := JournalRecord{
		SchemaVersion:      "lanpanel.journal.v1",
		ID:                 "journal-one",
		JobID:              "job-one",
		Kind:               JournalAppContraction,
		Operation:          Publish,
		InstallationID:     testOperationInstallation().InstallationID,
		Target:             "resource/res_00000000000000000000000000000001",
		Generation:         7,
		Deadline:           now.Add(time.Hour),
		ArtifactDigest:     testDigest("artifact"),
		SafetyMarkerDigest: testDigest("marker"),
		ResourceIDs:        []string{"res_00000000000000000000000000000001"},
		ChildIDs:           []string{"child-one"},
		Phase:              JournalActive,
	}
	document := reconciliationDocument(t, journal, nil)
	if err := PendingJournalRecovery(document); err == nil {
		t.Fatal("nonterminal operation journal was accepted by the Nginx guard fence")
	}
	journal.Phase = JournalTerminal
	terminalAt := now.Add(time.Second)
	terminalChild := ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "child-one", JobID: journal.JobID, InstallationID: journal.InstallationID, Operation: journal.Operation, Target: journal.Target, IntentGeneration: journal.Generation, Profile: "fixed-profile", InputDigest: testDigest("input"), ArtifactDigest: journal.ArtifactDigest, Deadline: journal.Deadline, State: ChildTerminal, SubmittedAt: now, TerminalAt: &terminalAt, Outcome: ChildSucceeded, ResultDigest: testDigest("result")}
	runningChild := terminalChild
	runningChild.State = ChildRunning
	runningChild.TerminalAt = nil
	runningChild.Outcome = ""
	runningChild.ResultDigest = ""
	if err := PendingJournalRecovery(reconciliationDocument(t, journal, []ChildRecord{runningChild})); err == nil {
		t.Fatal("terminal operation journal with a running child was accepted")
	}
	if err := PendingJournalRecovery(reconciliationDocument(t, journal, nil)); err == nil {
		t.Fatal("non-certificate journal with a missing child was accepted")
	}
	if err := PendingJournalRecovery(reconciliationDocument(t, journal, []ChildRecord{terminalChild})); err != nil {
		t.Fatalf("terminal operation journal was rejected: %v", err)
	}
}

func TestPendingJournalRecoveryAllowsCertificatePublicationHandoff(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	resourceID := "res_00000000000000000000000000000001"
	jobID := "job-one"
	certificate := operationCertificateIdentity()
	certificatePath, err := certificates.BundlePath(certificate.Authority.CertificateID, certificate.Generation)
	if err != nil {
		t.Fatal(err)
	}
	challengeDigest := testDigest("challenge-safety")
	candidateBundleIdentity := certificates.BundleIdentity{Fingerprint: certificate.Fingerprint, SANIdentity: certificate.SANIdentity, ChainIdentity: certificate.ChainIdentity, IssuerIdentity: certificate.IssuerIdentity, BindingIdentity: certificate.BindingIdentity, DirectoryIdentity: certificate.DirectoryIdentity}
	appJournal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "activation-" + jobID, JobID: jobID, Kind: JournalAppActivation, Operation: Publish, InstallationID: testOperationInstallation().InstallationID, Target: "resource/" + resourceID, Generation: 7, Deadline: now.Add(time.Hour), ArtifactDigest: testDigest("publication"), SafetyMarkerDigest: testDigest("handoff-safety"), ResourceIDs: []string{resourceID}, ChildIDs: []string{}, Phase: JournalTerminal}
	certificateJournal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + jobID, JobID: jobID, Kind: JournalCertificateActivation, Operation: Publish, InstallationID: appJournal.InstallationID, Target: appJournal.Target, Generation: appJournal.Generation, Deadline: appJournal.Deadline, ArtifactDigest: testDigest("certificate"), SafetyMarkerDigest: challengeDigest, ResourceIDs: []string{resourceID}, ChildIDs: []string{"child-one"}, Phase: JournalTerminal, Certificate: &CertificateJournalIdentity{CertificateID: certificate.Authority.CertificateID, CandidateGeneration: certificate.Generation, CandidatePointer: certificatePath, CandidateFingerprint: certificate.Fingerprint, CandidateBundleIdentity: candidateBundleIdentity, Challenge: safety.ChallengePending{Generation: 1, PlanID: "plan-one", CertificateIdentity: certificate.Authority.CertificateID}, StageUID: 1200, StageGID: 1200}}
	intent := reconciliationIntent(appJournal, now)
	intent.OperationBinding = testDigest("acme")
	intent.SafetyBinding.ResourceID = resourceID
	intent.SafetyBinding.PlanID = intent.PlanID
	intent.SafetyBinding.IntentGeneration = appJournal.Generation
	intent.CertificateHandoff = &CertificatePublicationHandoff{PlanID: intent.PlanID, Generation: intent.IntentGeneration, SANIdentity: testDigest("san"), ACMEBinding: intent.OperationBinding, CertificateID: certificate.Authority.CertificateID, Fingerprint: certificate.Fingerprint, ChallengeSafetyDigest: challengeDigest}
	terminalAt := now.Add(time.Second)
	child := ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "child-one", JobID: jobID, InstallationID: appJournal.InstallationID, Operation: Publish, Target: appJournal.Target, IntentGeneration: appJournal.Generation, Profile: "lego", InputDigest: testDigest("input"), ArtifactDigest: certificateJournal.ArtifactDigest, Deadline: certificateJournal.Deadline, State: ChildTerminal, SubmittedAt: now, TerminalAt: &terminalAt, Outcome: ChildSucceeded, ResultDigest: testDigest("result")}
	entries := map[string]json.RawMessage{}
	put := func(key string, value any) {
		raw, encodeErr := persist.EncodeEntry(value)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		entries[key] = raw
	}
	put("installations/current", testOperationInstallation())
	put(reservationKey(jobID), intent)
	put("journals/"+appJournal.ID, appJournal)
	put("journals/"+certificateJournal.ID, certificateJournal)
	put("children/"+child.ID, child)
	document := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: entries}
	if err := PendingJournalRecovery(document); err != nil {
		t.Fatalf("valid certificate publication handoff was rejected: %v", err)
	}
	delete(entries, "journals/"+appJournal.ID)
	delete(entries, "journals/"+certificateJournal.ID)
	delete(entries, "children/"+child.ID)
	if err := PendingJournalRecovery(document); err == nil {
		t.Fatal("certificate publication handoff without its journal pair was accepted")
	}
}

func TestExactJournalReconciliationIsClosedAndFailClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	terminalAt := now.Add(time.Second)
	child := ChildRecord{
		SchemaVersion: "lanpanel.child.v1",
		ID:            "child-one",
		JobID:         "job-one",
		Profile:       "fixed-profile",
		State:         ChildTerminal,
		SubmittedAt:   now,
		TerminalAt:    &terminalAt,
		Outcome:       ChildSucceeded,
		ResultDigest:  testDigest("child-result"),
	}
	base := JournalRecord{
		SchemaVersion:      "lanpanel.journal.v1",
		ID:                 "journal-one",
		JobID:              "job-one",
		Kind:               JournalAppContraction,
		Operation:          Publish,
		InstallationID:     testOperationInstallation().InstallationID,
		Target:             "resource/res_00000000000000000000000000000001",
		Generation:         7,
		Deadline:           now.Add(time.Hour),
		ArtifactDigest:     testDigest("artifact"),
		SafetyMarkerDigest: testDigest("marker"),
		ResourceIDs:        []string{"res_00000000000000000000000000000001"},
		ChildIDs:           []string{"child-one"},
		Phase:              JournalActive,
	}
	observation := ExactReconciliationObservation{Deadline: base.Deadline, ArtifactDigest: base.ArtifactDigest, SafetyMarkerDigest: base.SafetyMarkerDigest}

	decision, err := decideExactReconciliation(reconciliationDocument(t, base, []ChildRecord{child}), base.ID, observation)
	if err != nil || decision.Action != ReconcileContractApp || decision.Target != base.Target {
		t.Fatalf("DecideExactReconciliation(App) = %#v, %v", decision, err)
	}

	t.Run("observed artifact mismatch", func(t *testing.T) {
		mismatch := observation
		mismatch.ArtifactDigest = testDigest("other")
		if decision, err := decideExactReconciliation(reconciliationDocument(t, base, []ChildRecord{child}), base.ID, mismatch); err == nil || decision.Action != "" {
			t.Fatalf("DecideExactReconciliation() = %#v, %v", decision, err)
		}
	})
	t.Run("authoritative nonterminal child", func(t *testing.T) {
		running := child
		running.State = ChildRunning
		running.TerminalAt = nil
		running.Outcome = ""
		running.ResultDigest = ""
		if decision, err := decideExactReconciliation(reconciliationDocument(t, base, []ChildRecord{running}), base.ID, observation); err == nil || decision.Action != "" {
			t.Fatalf("DecideExactReconciliation() = %#v, %v", decision, err)
		}
	})
	t.Run("unknown journal kind", func(t *testing.T) {
		unknown := base
		unknown.Kind = "provider_retry"
		if decision, err := decideExactReconciliation(reconciliationDocument(t, unknown, []ChildRecord{child}), unknown.ID, observation); err == nil || decision.Action != "" {
			t.Fatalf("DecideExactReconciliation() = %#v, %v", decision, err)
		}
	})
	t.Run("foreign installation", func(t *testing.T) {
		foreign := base
		foreign.InstallationID = "ins_00000000000000000000000000000002"
		if decision, err := decideExactReconciliation(reconciliationDocument(t, foreign, []ChildRecord{child}), foreign.ID, observation); err == nil || decision.Action != "" {
			t.Fatalf("DecideExactReconciliation() = %#v, %v", decision, err)
		}
	})
	t.Run("intent generation mismatch", func(t *testing.T) {
		document := reconciliationDocument(t, base, []ChildRecord{child})
		intent := reconciliationIntent(base, now)
		intent.IntentGeneration++
		raw, err := persist.EncodeEntry(intent)
		if err != nil {
			t.Fatal(err)
		}
		document.Entries[reservationKey(base.JobID)] = raw
		if decision, err := decideExactReconciliation(document, base.ID, observation); err == nil || decision.Action != "" {
			t.Fatalf("DecideExactReconciliation() = %#v, %v", decision, err)
		}
	})
}

func reconciliationDocument(t *testing.T, journal JournalRecord, children []ChildRecord) persist.Document {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	entries := map[string]json.RawMessage{}
	put := func(key string, value any) {
		raw, err := persist.EncodeEntry(value)
		if err != nil {
			t.Fatal(err)
		}
		entries[key] = raw
	}
	put("installations/current", testOperationInstallation())
	put(reservationKey(journal.JobID), reconciliationIntent(journal, now))
	put("journals/"+journal.ID, journal)
	for _, child := range children {
		child.InstallationID = journal.InstallationID
		child.Operation = journal.Operation
		child.Target = journal.Target
		child.IntentGeneration = journal.Generation
		child.InputDigest = testDigest("input")
		child.ArtifactDigest = journal.ArtifactDigest
		child.Deadline = journal.Deadline
		put("children/"+child.ID, child)
	}
	return persist.Document{SchemaVersion: "lanpanel.normal.v1", Revision: 1, Entries: entries}
}

func reconciliationIntent(journal JournalRecord, now time.Time) Reservation {
	return Reservation{
		SchemaVersion:       "lanpanel.operation.reservation.v1",
		JobID:               journal.JobID,
		PlanID:              "plan-one",
		AdmissionSource:     AdmissionPlan,
		Operation:           journal.Operation,
		Target:              journal.Target,
		Phase:               PhaseLocalIntent,
		SafetyDigest:        testDigest("safety"),
		JournalSafetyDigest: journal.SafetyMarkerDigest,
		CreatedAt:           now,
		IntentGeneration:    journal.Generation,
		Consumption: &ConsumptionSnapshot{
			Source:             AdmissionPlan,
			ConfirmationDigest: testDigest("confirmation"),
			ConfirmedAt:        now,
			SafetyDigest:       testDigest("safety"),
		},
	}
}
