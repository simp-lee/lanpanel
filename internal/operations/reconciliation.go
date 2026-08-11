package operations

import (
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"time"
)

// ExactReconciliationAction is deliberately limited to a local non-ingress
// commit or contraction. It grants no authority to start a child, contact a
// provider, mutate an orphan record, start a stopped process, or open ingress.
type ExactReconciliationAction string

const (
	ReconcileFinalizeNonIngressCommit ExactReconciliationAction = "finalize_non_ingress_local_commit"
	ReconcileContractApp              ExactReconciliationAction = "contract_app"
)

type ExactReconciliationObservation struct {
	Deadline           time.Time
	ArtifactDigest     string
	SafetyMarkerDigest string
}

type ExactReconciliationDecision struct {
	Action             ExactReconciliationAction
	JournalID          string
	Operation          Type
	InstallationID     string
	Target             string
	Generation         uint64
	Deadline           time.Time
	ArtifactDigest     string
	SafetyMarkerDigest string
}

// DecideExactReconciliation reads the validated normal-state store while the
// shared exposure lock is held. The caller supplies only freshly observed host
// artifact/marker/deadline evidence.
func (admitter *Admitter) DecideExactReconciliation(exposure *locks.Lease, journalID string, observation ExactReconciliationObservation) (ExactReconciliationDecision, error) {
	if admitter == nil || exposure == nil || exposure.Authority() != admitter.normal.LockAuthority() || !exposure.Holds(locks.Exposure) {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation requires the authoritative store and exposure lock")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return ExactReconciliationDecision{}, err
	}
	return decideExactReconciliation(document, journalID, observation)
}

// decideExactReconciliation validates journal, installation, intent, and child
// identities from one already-validated normal-state document. A mismatch
// leaves the journal and any fence for diagnostics or same-version reinstall.
func decideExactReconciliation(document persist.Document, journalID string, observation ExactReconciliationObservation) (ExactReconciliationDecision, error) {
	if !validIdentityRef(journalID) {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation journal ID is invalid")
	}
	rawJournal, present := document.Entries["journals/"+journalID]
	if !present {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation journal is missing")
	}
	var journal JournalRecord
	if err := decodeStrict(rawJournal, &journal); err != nil {
		return ExactReconciliationDecision{}, err
	}
	if err := validateJournalRecord(journal); err != nil || journal.ID != journalID {
		if err != nil {
			return ExactReconciliationDecision{}, err
		}
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation journal key does not match identity")
	}
	rawInstallation, present := document.Entries["installations/current"]
	if !present {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(rawInstallation)
	if err != nil {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation installation authority: %w", err)
	}
	intent, err := loadReservationEntries(document.Entries, journal.JobID)
	if err != nil {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation intent authority: %w", err)
	}
	if journal.InstallationID != installation.InstallationID || journal.Operation != intent.Operation || journal.Target != intent.Target || journal.Generation != intent.IntentGeneration {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation journal does not match installation or intent authority")
	}
	if !observation.Deadline.Equal(journal.Deadline) || observation.ArtifactDigest != journal.ArtifactDigest || observation.SafetyMarkerDigest != journal.SafetyMarkerDigest {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation host evidence does not match journal")
	}

	children := map[string]ChildRecord{}
	for _, key := range persist.EntryKeys(document, "children") {
		var child ChildRecord
		if err := decodeStrict(document.Entries[key], &child); err != nil {
			return ExactReconciliationDecision{}, err
		}
		if child.JobID != journal.JobID {
			continue
		}
		if err := validateChildRecord(child); err != nil {
			return ExactReconciliationDecision{}, err
		}
		children[child.ID] = child
	}
	if len(children) != len(journal.ChildIDs) {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation child inventory does not match journal")
	}
	allSucceeded := true
	for _, childID := range journal.ChildIDs {
		child, present := children[childID]
		if !present || child.State != ChildTerminal {
			return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation requires every exact child result to be terminal")
		}
		allSucceeded = allSucceeded && child.Outcome == ChildSucceeded
	}
	decision := ExactReconciliationDecision{
		JournalID:          journal.ID,
		Operation:          journal.Operation,
		InstallationID:     journal.InstallationID,
		Target:             journal.Target,
		Generation:         journal.Generation,
		Deadline:           journal.Deadline,
		ArtifactDigest:     journal.ArtifactDigest,
		SafetyMarkerDigest: journal.SafetyMarkerDigest,
	}
	switch journal.Kind {
	case JournalNonIngressLocalCommit:
		if journal.Phase != JournalTerminal || len(journal.ChildIDs) == 0 || !allSucceeded {
			return ExactReconciliationDecision{}, fmt.Errorf("non-ingress local commit lacks a terminal successful child result")
		}
		decision.Action = ReconcileFinalizeNonIngressCommit
		return decision, nil
	case JournalAppContraction:
		decision.Action = ReconcileContractApp
		return decision, nil
	default:
		return ExactReconciliationDecision{}, fmt.Errorf("operation journal kind is not allowed")
	}
}
