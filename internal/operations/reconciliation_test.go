package operations

import (
	"encoding/json"
	"lanpanel/internal/persist"
	"testing"
	"time"
)

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
		Target:             "resource/app-one",
		Generation:         7,
		Deadline:           now.Add(time.Hour),
		ArtifactDigest:     testDigest("artifact"),
		SafetyMarkerDigest: testDigest("marker"),
		ChildIDs:           []string{"child-one"},
		Phase:              JournalActive,
	}
	observation := ExactReconciliationObservation{Deadline: base.Deadline, ArtifactDigest: base.ArtifactDigest, SafetyMarkerDigest: base.SafetyMarkerDigest}

	decision, err := decideExactReconciliation(reconciliationDocument(t, base, []ChildRecord{child}), base.ID, observation)
	if err != nil || decision.Action != ReconcileContractApp || decision.Target != base.Target {
		t.Fatalf("DecideExactReconciliation(App) = %#v, %v", decision, err)
	}

	local := base
	local.Kind = JournalNonIngressLocalCommit
	local.Operation = Maintenance
	local.Phase = JournalTerminal
	decision, err = decideExactReconciliation(reconciliationDocument(t, local, []ChildRecord{child}), local.ID, observation)
	if err != nil || decision.Action != ReconcileFinalizeNonIngressCommit || decision.Target != local.Target {
		t.Fatalf("DecideExactReconciliation(local commit) = %#v, %v", decision, err)
	}

	failedChild := child
	failedChild.Outcome = ChildFailed
	if decision, err := decideExactReconciliation(reconciliationDocument(t, local, []ChildRecord{failedChild}), local.ID, observation); err == nil || decision.Action != "" {
		t.Fatalf("DecideExactReconciliation(failed local child) = %#v, %v", decision, err)
	}
	emptyLocal := local
	emptyLocal.ChildIDs = nil
	if decision, err := decideExactReconciliation(reconciliationDocument(t, emptyLocal, nil), emptyLocal.ID, observation); err == nil || decision.Action != "" {
		t.Fatalf("DecideExactReconciliation(empty local child inventory) = %#v, %v", decision, err)
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
		put("children/"+child.ID, child)
	}
	return persist.Document{SchemaVersion: "lanpanel.normal.v1", Revision: 1, Entries: entries}
}

func reconciliationIntent(journal JournalRecord, now time.Time) Reservation {
	return Reservation{
		SchemaVersion:    "lanpanel.operation.reservation.v1",
		JobID:            journal.JobID,
		PlanID:           "plan-one",
		Operation:        journal.Operation,
		Target:           journal.Target,
		Phase:            PhaseLocalIntent,
		SafetyDigest:     testDigest("safety"),
		CreatedAt:        now,
		IntentGeneration: journal.Generation,
		Consumption: &ConsumptionSnapshot{
			ConfirmationDigest: testDigest("confirmation"),
			ConfirmedAt:        now,
			SafetyDigest:       testDigest("safety"),
		},
	}
}
