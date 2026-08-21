package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/safety"
	"reflect"
	"slices"
	"sort"
	"time"
)

// ExactReconciliationAction is deliberately limited to local contraction. It
// grants no authority to start a child, contact a provider, mutate an orphan
// record, start a stopped process, or open ingress.
type ExactReconciliationAction string

const (
	ReconcileContractApp ExactReconciliationAction = "contract_app"
)

type ExactResourceClosure struct {
	ResourceID            string
	OwnershipDigest       string
	ContractionGeneration uint64
	RuntimeClosureDigest  string
	DiskClosureDigest     string
	ListenerClosureDigest string
}

type ExactReconciliationObservation struct {
	ReconciliationJobID string
	Deadline            time.Time
	ArtifactDigest      string
	SafetyMarkerDigest  string
	ObservedAt          time.Time
	GlobalGeneration    uint64
	StopFenceSequence   uint64
	Closures            []ExactResourceClosure
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
	ResourceIDs        []string
	ObservedAt         time.Time
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
	if err := validateReconciliationJob(document, observation.ReconciliationJobID, journalID); err != nil {
		return ExactReconciliationDecision{}, err
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return ExactReconciliationDecision{}, err
	}
	journal, err := loadJournalEntries(document.Entries, journalID)
	if err != nil {
		return ExactReconciliationDecision{}, err
	}
	originalIntent, err := loadReservationEntries(document.Entries, journal.JobID)
	if err != nil {
		return ExactReconciliationDecision{}, err
	}
	markerDigest, err := safetyBindingDigest(originalIntent.SafetyBinding)
	if err != nil {
		return ExactReconciliationDecision{}, err
	}
	if observation.SafetyMarkerDigest != markerDigest {
		return ExactReconciliationDecision{}, fmt.Errorf("observed safety marker does not match immutable journal authority")
	}
	decision, err := decideExactReconciliation(document, journalID, observation)
	if err != nil {
		return ExactReconciliationDecision{}, err
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return ExactReconciliationDecision{}, err
	}
	if observation.ObservedAt.IsZero() || observation.ObservedAt.After(observedNow) || observedNow.Sub(observation.ObservedAt) > time.Minute {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation closure observation is stale or invalid")
	}
	if state.GlobalClose.Phase != safety.GlobalCloseNone || state.StopFence != nil || observation.GlobalGeneration != state.GlobalClose.Generation || observation.StopFenceSequence != state.StopFenceSequence {
		return ExactReconciliationDecision{}, fmt.Errorf("exact reconciliation global or stop-fence authority has not converged")
	}
	if decision.Action == ReconcileContractApp {
		if err := validateExactClosedSafety(state, decision, observation); err != nil {
			return ExactReconciliationDecision{}, err
		}
	}
	decision.ObservedAt = observation.ObservedAt
	return decision, nil
}

// CompleteExactReconciliation atomically supersedes the interrupted original
// operation and terminalizes the reconciliation job. The original generation
// can never return to a completable phase after this commit.
func (admitter *Admitter) CompleteExactReconciliation(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, decision ExactReconciliationDecision, observation ExactReconciliationObservation, reconciliationJobID string) (jobs.Record, error) {
	if admitter == nil || !authoritativeOperationLeases(admitter.normal, mutation, exposure) || mutation.Target() != "journal/"+decision.JournalID {
		return jobs.Record{}, fmt.Errorf("exact reconciliation completion requires the bound journal mutation and exposure locks")
	}
	freshDecision, err := admitter.DecideExactReconciliation(exposure, decision.JournalID, observation)
	if err != nil {
		return jobs.Record{}, fmt.Errorf("exact reconciliation authority changed before terminal commit: %w", err)
	}
	terminalObservedAt := freshDecision.ObservedAt
	freshDecision.ObservedAt = decision.ObservedAt
	if !reflect.DeepEqual(freshDecision, decision) || !terminalObservedAt.After(decision.ObservedAt) {
		return jobs.Record{}, fmt.Errorf("exact reconciliation decision lacks a fresh terminal observation")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		if err := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-2); err != nil {
			return err
		}
		entries := map[string]json.RawMessage{}
		for _, namespace := range []string{"installations", "plans", "jobs", "intents", "children", "journals"} {
			for _, key := range transaction.Keys(namespace) {
				raw, _ := transaction.Get(key)
				entries[key] = raw
			}
		}
		document := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: expectedRevision, Entries: entries}
		if err := validateReconciliationJob(document, reconciliationJobID, decision.JournalID); err != nil {
			return err
		}
		rawJournal, present := transaction.Get("journals/" + decision.JournalID)
		if !present {
			return fmt.Errorf("exact reconciliation journal is missing")
		}
		var journal JournalRecord
		if err := decodeStrict(rawJournal, &journal); err != nil {
			return err
		}
		if journal.JobID == reconciliationJobID || journal.ID != decision.JournalID || journal.Operation != decision.Operation || journal.InstallationID != decision.InstallationID || journal.Target != decision.Target || journal.Generation != decision.Generation || !journal.Deadline.Equal(decision.Deadline) || journal.ArtifactDigest != decision.ArtifactDigest || journal.SafetyMarkerDigest != decision.SafetyMarkerDigest || !reflect.DeepEqual(journal.ResourceIDs, decision.ResourceIDs) {
			return fmt.Errorf("exact reconciliation decision no longer matches journal authority")
		}
		if decision.Action == ReconcileContractApp {
			rawInstallation, present := transaction.Get("installations/current")
			if !present {
				return fmt.Errorf("exact reconciliation installation authority is missing")
			}
			installation, err := domain.DecodeInstallation(rawInstallation)
			if err != nil {
				return err
			}
			affected := map[string]uint64{}
			for _, closure := range observation.Closures {
				affected[closure.ResourceID] = closure.ContractionGeneration
			}
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				stickyGeneration, present := affected[resource.ID]
				if !present {
					continue
				}
				currentGeneration := resource.PublicationRecord.UnpublishedGeneration
				if stickyGeneration < currentGeneration || stickyGeneration == currentGeneration && (resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.ActivationIntent != nil) {
					return fmt.Errorf("exact reconciliation sticky generation regressed or mismatches normal state")
				}
				if stickyGeneration > currentGeneration {
					resource.PublicationRecord.State = domain.PublicationUnpublished
					resource.PublicationRecord.UnpublishedGeneration = stickyGeneration
					resource.PublicationRecord.ActivationIntent = nil
					resource.PublicationRecord.LastOperation = domain.OperationUnpublish
					resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
					resource.PublicationRecord.LastJobID = reconciliationJobID
				}
				delete(affected, resource.ID)
			}
			if len(affected) != 0 {
				return fmt.Errorf("exact reconciliation affected resource disappeared")
			}
			rawInstallation, err = persist.EncodeEntry(installation)
			if err != nil {
				return err
			}
			if err := transaction.Replace("installations/current", rawInstallation); err != nil {
				return err
			}
		}
		originalIntent, err := loadReservation(transaction, journal.JobID)
		if err != nil {
			return err
		}
		if originalIntent.Phase != PhaseLocalIntent && originalIntent.Phase != PhaseRemoteWait && originalIntent.Phase != PhaseReentered {
			return fmt.Errorf("original operation is no longer supersedable")
		}
		for _, key := range transaction.Keys("children") {
			raw, _ := transaction.Get(key)
			var child ChildRecord
			if err := decodeStrict(raw, &child); err != nil {
				return err
			}
			if child.JobID == journal.JobID && child.State != ChildTerminal {
				return fmt.Errorf("exact reconciliation child remains nonterminal")
			}
		}
		originalJob, err := jobs.Load(transaction, journal.JobID)
		if err != nil {
			return err
		}
		originalJob, err = jobs.Finish(originalJob, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "superseded_by_exact_reconciliation", Status: jobs.PostconditionKnown, Identity: reconciliationJobID}}, ErrorCode: "exact_reconciliation_closed"}, observedNow)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, originalJob); err != nil {
			return err
		}
		originalIntent.Phase = PhaseTerminal
		raw, err := persist.EncodeEntry(originalIntent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(originalIntent.JobID), raw); err != nil {
			return err
		}
		if journal.Phase != JournalTerminal {
			journal.Phase = JournalTerminal
			raw, err = persist.EncodeEntry(journal)
			if err != nil {
				return err
			}
			if err := transaction.Replace("journals/"+journal.ID, raw); err != nil {
				return err
			}
		}
		reconciliationIntent, err := loadReservation(transaction, reconciliationJobID)
		if err != nil {
			return err
		}
		reconciliationJob, err := jobs.Load(transaction, reconciliationJobID)
		if err != nil {
			return err
		}
		reconciliationJob, err = jobs.Finish(reconciliationJob, jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{{Kind: "exact_closed_recovery", Status: jobs.PostconditionVerified, Identity: journal.ID}}}, observedNow)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, reconciliationJob); err != nil {
			return err
		}
		reconciliationIntent.Phase = PhaseTerminal
		raw, err = persist.EncodeEntry(reconciliationIntent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(reconciliationJobID), raw); err != nil {
			return err
		}
		completed = reconciliationJob
		return nil
	})
	return completed, err
}

func loadJournalEntries(entries map[string]json.RawMessage, journalID string) (JournalRecord, error) {
	raw, present := entries["journals/"+journalID]
	if !present {
		return JournalRecord{}, fmt.Errorf("exact reconciliation journal is missing")
	}
	var journal JournalRecord
	if err := decodeStrict(raw, &journal); err != nil {
		return JournalRecord{}, err
	}
	return journal, nil
}

func validateExactClosedSafety(state safety.State, decision ExactReconciliationDecision, observation ExactReconciliationObservation) error {
	resourceIDs := decision.ResourceIDs
	if len(resourceIDs) == 0 || len(observation.Closures) != len(resourceIDs) {
		return fmt.Errorf("exact App reconciliation closure inventory is incomplete")
	}
	resources := map[string]safety.ResourceSafety{}
	for _, resource := range state.Resources {
		resources[resource.ResourceID] = resource
	}
	if decision.Target == string(plans.TargetInstallation) && len(resources) != len(resourceIDs) {
		return fmt.Errorf("close-all reconciliation omits a safety or ownership identity")
	}
	for index, resourceID := range resourceIDs {
		closure := observation.Closures[index]
		if closure.ResourceID != resourceID || !exactDigest(closure.OwnershipDigest) || !exactDigest(closure.RuntimeClosureDigest) || !exactDigest(closure.DiskClosureDigest) || !exactDigest(closure.ListenerClosureDigest) || closure.ContractionGeneration == 0 {
			return fmt.Errorf("exact App reconciliation closure inventory is noncanonical")
		}
		resource, present := resources[resourceID]
		if !present || resource.Ownership != safety.OwnershipOwned || resource.OwnershipDigest != closure.OwnershipDigest || resource.ChallengePending != nil || resource.Reactivating != nil {
			return fmt.Errorf("exact App reconciliation safety authority is missing, one-sided, or expansion-capable")
		}
		if resource.StickyUnpublished == nil || resource.StickyUnpublished.Generation != closure.ContractionGeneration {
			return fmt.Errorf("exact App reconciliation has no matching sticky-unpublished generation for %q", resourceID)
		}
	}
	return nil
}

func validateReconciliationJob(document persist.Document, jobID, journalID string) error {
	if !validIdentityRef(jobID) {
		return fmt.Errorf("exact reconciliation requires a durable reconciliation job")
	}
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return fmt.Errorf("exact reconciliation job intent: %w", err)
	}
	if intent.Operation != AutomaticReconciliation || intent.AdmissionSource != AdmissionTimer && intent.AdmissionSource != AdmissionStartup || intent.Target != "journal/"+journalID || intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered || intent.Consumption == nil {
		return fmt.Errorf("exact reconciliation job does not match the closed startup/timer authority")
	}
	record, err := jobs.LoadEntries(document.Entries, jobID)
	if err != nil {
		return fmt.Errorf("exact reconciliation job: %w", err)
	}
	if record.Status != jobs.StatusRunning {
		return fmt.Errorf("exact reconciliation job is not running")
	}
	return nil
}

// decideExactReconciliation validates journal, installation, intent, and child
// identities from one already-validated normal-state document. A mismatch
// leaves the journal and any fence for diagnostics, export, and clean-host rebuild.
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
	if journal.Kind == JournalAppContraction || journal.Kind == JournalAppActivation || journal.Kind == JournalCertificateActivation {
		installed := make([]string, 0, len(installation.Resources))
		for _, resource := range installation.Resources {
			installed = append(installed, resource.ID)
		}
		sort.Strings(installed)
		if journal.Operation == CloseAll {
			if !reflect.DeepEqual(installed, journal.ResourceIDs) {
				return ExactReconciliationDecision{}, fmt.Errorf("close-all journal resource inventory is not exact")
			}
		} else if len(journal.ResourceIDs) != 1 || !slices.Contains(installed, journal.ResourceIDs[0]) {
			return ExactReconciliationDecision{}, fmt.Errorf("app journal resource is absent from installation authority")
		}
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
	handoffApp := intent.CertificateHandoff != nil && journal.Kind == JournalAppActivation && len(journal.ChildIDs) == 0
	if len(children) != len(journal.ChildIDs) && !handoffApp {
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
		ResourceIDs:        append([]string(nil), journal.ResourceIDs...),
	}
	switch journal.Kind {
	case JournalAppContraction, JournalAppActivation, JournalCertificateActivation:
		decision.Action = ReconcileContractApp
		return decision, nil
	default:
		return ExactReconciliationDecision{}, fmt.Errorf("operation journal kind is not allowed")
	}
}
