// Package operations implements durable admission, Plan consumption, phase
// intents, and exhaustive result contracts for normal mutations.
package operations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/safety"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type Type string

const (
	Publish                 Type = "publish"
	Unpublish               Type = "unpublish"
	CloseAll                Type = "close_all"
	EmergencyCloseAll       Type = "emergency_close_all"
	CertificateExpiry       Type = "certificate_expiry"
	EdgeOneExpiry           Type = "edgeone_expiry"
	Maintenance             Type = "maintenance"
	PackageTransaction      Type = "package_transaction"
	Upgrade                 Type = "upgrade"
	BackupEnter             Type = "backup_enter"
	AutomaticReconciliation Type = "automatic_exact_journal_reconciliation"
	StartupContraction      Type = "startup_activation_contraction"
)

const (
	maximumTerminalOperationGraphs = 256
	maximumActiveOperationGraphs   = 64
	maximumChildrenPerJob          = 32
	maximumJournalResources        = 256
)

type Phase string

const (
	PhaseReserved    Phase = "reserved"
	PhaseLocalIntent Phase = "local_intent"
	PhaseRemoteWait  Phase = "remote_wait"
	PhaseRejected    Phase = "rejected"
	PhaseReentered   Phase = "reentered"
	PhaseTerminal    Phase = "terminal"
)

type SafetyBinding struct {
	GlobalGeneration     uint64    `json:"global_generation,omitempty"`
	DependencyGeneration uint64    `json:"dependency_generation,omitempty"`
	ExpiryKind           string    `json:"expiry_kind,omitempty"`
	ExpiryGeneration     uint64    `json:"expiry_generation,omitempty"`
	ResourceID           string    `json:"resource_id,omitempty"`
	Deadline             time.Time `json:"deadline"`
	ProposedGeneration   uint64    `json:"proposed_generation,omitempty"`
	PlanID               string    `json:"plan_id,omitempty"`
	IntentGeneration     uint64    `json:"intent_generation,omitempty"`
	CandidateDigest      string    `json:"candidate_digest,omitempty"`
	CandidateBundle      string    `json:"candidate_bundle,omitempty"`
}
type AdmissionSource string

const (
	AdmissionPlan    AdmissionSource = "plan"
	AdmissionTimer   AdmissionSource = "timer"
	AdmissionStartup AdmissionSource = "startup"
)

type ConsumptionSnapshot struct {
	Source             AdmissionSource     `json:"source"`
	Config             plans.DigestBinding `json:"config"`
	Applied            plans.DigestBinding `json:"applied"`
	Evidence           []plans.Evidence    `json:"evidence"`
	ConfirmationDigest string              `json:"confirmation_digest"`
	ConfirmedAt        time.Time           `json:"confirmed_at"`
	SafetyDigest       string              `json:"safety_digest"`
}
type Reservation struct {
	SchemaVersion       string               `json:"schema_version"`
	JobID               string               `json:"job_id"`
	PlanID              string               `json:"plan_id,omitempty"`
	AdmissionSource     AdmissionSource      `json:"admission_source"`
	Operation           Type                 `json:"operation"`
	Target              string               `json:"target"`
	Phase               Phase                `json:"phase"`
	SafetyDigest        string               `json:"safety_digest"`
	JournalSafetyDigest string               `json:"journal_safety_digest,omitempty"`
	SafetyBinding       SafetyBinding        `json:"safety_binding"`
	CreatedAt           time.Time            `json:"created_at"`
	IntentGeneration    uint64               `json:"intent_generation,omitempty"`
	Consumption         *ConsumptionSnapshot `json:"consumption,omitempty"`
}
type ChildState string

type ChildOutcome string

const (
	ChildSubmitted ChildState = "submitted"
	ChildRunning   ChildState = "running"
	ChildTerminal  ChildState = "terminal"

	ChildSucceeded ChildOutcome = "succeeded"
	ChildFailed    ChildOutcome = "failed"
	ChildUnknown   ChildOutcome = "unknown"
)

type ChildRecord struct {
	SchemaVersion    string       `json:"schema_version"`
	ID               string       `json:"id"`
	JobID            string       `json:"job_id"`
	InstallationID   string       `json:"installation_id"`
	Operation        Type         `json:"operation"`
	Target           string       `json:"target"`
	IntentGeneration uint64       `json:"intent_generation"`
	Profile          string       `json:"profile"`
	InputDigest      string       `json:"input_digest"`
	ArtifactDigest   string       `json:"artifact_digest"`
	Deadline         time.Time    `json:"deadline"`
	State            ChildState   `json:"state"`
	SubmittedAt      time.Time    `json:"submitted_at"`
	TerminalAt       *time.Time   `json:"terminal_at,omitempty"`
	Outcome          ChildOutcome `json:"outcome,omitempty"`
	ResultDigest     string       `json:"result_digest,omitempty"`
}
type JournalKind string

type JournalPhase string

const (
	JournalNonIngressLocalCommit JournalKind = "non_ingress_local_commit"
	JournalPackageTransaction    JournalKind = "package_transaction"
	JournalAppContraction        JournalKind = "app_contraction"

	JournalPrepared JournalPhase = "prepared"
	JournalActive   JournalPhase = "active"
	JournalTerminal JournalPhase = "terminal"
)

type JournalRecord struct {
	SchemaVersion      string       `json:"schema_version"`
	ID                 string       `json:"id"`
	JobID              string       `json:"job_id"`
	Kind               JournalKind  `json:"kind"`
	Operation          Type         `json:"operation"`
	InstallationID     string       `json:"installation_id"`
	Target             string       `json:"target"`
	Generation         uint64       `json:"generation"`
	Deadline           time.Time    `json:"deadline"`
	ArtifactDigest     string       `json:"artifact_digest"`
	SafetyMarkerDigest string       `json:"safety_marker_digest"`
	ResourceIDs        []string     `json:"resource_ids,omitempty"`
	ChildIDs           []string     `json:"child_ids"`
	Phase              JournalPhase `json:"phase"`
}

type AdmitRequest struct {
	Operation        Type
	Target           string
	ActorIdentity    string
	PlanID           string
	Source           AdmissionSource
	SafetyBinding    SafetyBinding
	ExpectedRevision uint64
}
type ConsumeRequest struct {
	JobID             string
	ExpectedRevision  uint64
	IntentGeneration  uint64
	ConfirmationProof string
}
type SafetyReader interface {
	Read() (safety.State, error)
	LockAuthority() locks.Authority
}
type BindingReader interface {
	CurrentBinding(Type, string, time.Time) (plans.Binding, error)
}
type ConfirmationVerifier interface {
	VerifyConfirmation(plans.Plan, string, string, time.Time) (string, error)
}
type Options struct {
	Now                  func() time.Time
	Random               io.Reader
	Bindings             BindingReader
	Confirmation         ConfirmationVerifier
	Registry             *Registry
	StateIndependentOnly bool
}
type Admitter struct {
	normal               *persist.Store
	safety               SafetyReader
	now                  func() time.Time
	random               io.Reader
	bindings             BindingReader
	confirmation         ConfirmationVerifier
	registry             *Registry
	timeMu               sync.Mutex
	lastTrusted          time.Time
	stateIndependentOnly bool
}

func NewAdmitter(normal *persist.Store, safetyStore SafetyReader, options Options) (*Admitter, error) {
	if normal == nil || safetyStore == nil || safetyStore.LockAuthority() != normal.LockAuthority() || options.Bindings == nil || options.Confirmation == nil || options.Registry == nil {
		return nil, fmt.Errorf("operation admission requires normal and independent safety stores")
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	if !normal.SchemaSealed() {
		if err := plans.Register(normal); err != nil {
			return nil, err
		}
		if err := jobs.Register(normal); err != nil {
			return nil, err
		}
		if err := normal.RegisterCanonicalNamespace("intents", "operations.intents.v1", validateIntentEntry, validateIntentTransition); err != nil {
			return nil, err
		}
		if err := normal.RegisterCanonicalNamespace("children", "operations.children.v1", validateChildEntry, validateChildTransition); err != nil {
			return nil, err
		}
		if err := normal.RegisterCanonicalNamespace("journals", "operations.journals.v1", validateJournalEntry, validateJournalTransition); err != nil {
			return nil, err
		}
		if err := normal.RegisterCanonicalDocumentValidator("operations.links.v1", validateLinks); err != nil {
			return nil, err
		}
		if err := normal.RegisterCanonicalDocumentTransitionValidator("operations.resource_transitions.v1", validateOperationStateTransitions); err != nil {
			return nil, err
		}
		if err := normal.SealSchema(); err != nil {
			return nil, err
		}
	}
	admitter := &Admitter{normal: normal, safety: safetyStore, now: now, random: random, bindings: options.Bindings, confirmation: options.Confirmation, registry: options.Registry, stateIndependentOnly: options.StateIndependentOnly}
	observed := now().UTC()
	document, readErr := normal.Read()
	if readErr != nil && !options.StateIndependentOnly {
		return nil, fmt.Errorf("normal operation authority cannot read durable time: %w", readErr)
	}
	if readErr == nil {
		latest, err := latestDocumentTime(document)
		if err != nil {
			return nil, err
		}
		if observed.Before(latest) {
			return nil, fmt.Errorf("trusted wall clock regressed behind durable observation")
		}
		admitter.lastTrusted = latest
	}
	if admitter.lastTrusted.IsZero() || observed.After(admitter.lastTrusted) {
		admitter.lastTrusted = observed
	}
	return admitter, nil
}

func (admitter *Admitter) trustedNow() (time.Time, error) {
	admitter.timeMu.Lock()
	defer admitter.timeMu.Unlock()
	if admitter.stateIndependentOnly {
		return time.Time{}, fmt.Errorf("state-independent authority cannot perform normal operations")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return time.Time{}, fmt.Errorf("durable time observation failed: %w", err)
	}
	latest, err := latestDocumentTime(document)
	if err != nil {
		return time.Time{}, err
	}
	now := admitter.now().UTC()
	if now.Before(admitter.lastTrusted) || now.Before(latest) {
		return time.Time{}, fmt.Errorf("trusted wall clock regressed")
	}
	admitter.lastTrusted = now
	return now, nil
}
func (admitter *Admitter) independentNow() (time.Time, error) {
	admitter.timeMu.Lock()
	defer admitter.timeMu.Unlock()
	now := admitter.now().UTC()
	if now.Before(admitter.lastTrusted) {
		return time.Time{}, fmt.Errorf("trusted wall clock regressed")
	}
	admitter.lastTrusted = now
	return now, nil
}
func latestDocumentTime(document persist.Document) (time.Time, error) {
	latest := time.Time{}
	take := func(value time.Time) {
		if value.After(latest) {
			latest = value
		}
	}
	for _, key := range persist.EntryKeys(document, "plans") {
		plan, err := plans.LoadEntries(document.Entries, strings.TrimPrefix(key, "plans/"))
		if err != nil {
			return time.Time{}, err
		}
		take(plan.CreatedAt)
		if plan.ReservedAt != nil {
			take(*plan.ReservedAt)
		}
		if plan.ConsumedAt != nil {
			take(*plan.ConsumedAt)
		}
		if plan.RejectedAt != nil {
			take(*plan.RejectedAt)
		}
	}
	for _, key := range persist.EntryKeys(document, "jobs") {
		record, err := jobs.LoadEntries(document.Entries, strings.TrimPrefix(key, "jobs/"))
		if err != nil {
			return time.Time{}, err
		}
		take(record.StartedAt)
		if record.EndedAt != nil {
			take(*record.EndedAt)
		}
	}
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return time.Time{}, err
		}
		take(intent.CreatedAt)
		if intent.Consumption != nil {
			take(intent.Consumption.ConfirmedAt)
		}
	}
	return latest, nil
}

// Admit runs under the installation mutation-admission lock. It creates the
// redacted nonterminal job and reservation in one normal-state transaction.
func (admitter *Admitter) Admit(ctx context.Context, admission *locks.Lease, request AdmitRequest) (jobs.Record, error) {
	if admission == nil || !admission.Holds(locks.MutationAdmission) {
		return jobs.Record{}, fmt.Errorf("operation admission lock is required")
	}
	observedNow, timeErr := admitter.trustedNow()
	if timeErr != nil {
		return jobs.Record{}, timeErr
	}
	if _, registered := admitter.registry.Registration(request.Operation); !registered {
		return jobs.Record{}, fmt.Errorf("operation owner and result branches are not registered")
	}
	if err := validateAdmissionSource(request.Operation, request.Source, request.PlanID); err != nil {
		return jobs.Record{}, err
	}
	if err := validateSafetyTargetBinding(request); err != nil {
		return jobs.Record{}, err
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return jobs.Record{}, err
	}
	if err := authorize(request.Operation, state, request.SafetyBinding, false, observedNow); err != nil {
		return jobs.Record{}, err
	}
	digest, err := safetyDigest(state)
	if err != nil {
		return jobs.Record{}, err
	}
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(request.Operation), Target: request.Target, ActorIdentity: request.ActorIdentity}, observedNow, admitter.random)
	if err != nil {
		return jobs.Record{}, err
	}
	reservation := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, PlanID: request.PlanID, AdmissionSource: request.Source, Operation: request.Operation, Target: request.Target, Phase: PhaseReserved, SafetyDigest: digest, SafetyBinding: request.SafetyBinding, CreatedAt: observedNow}
	_, _, err = admitter.normal.Update(ctx, admission, request.ExpectedRevision, func(transaction *persist.Transaction) error {
		active, err := activeGraphCount(transaction)
		if err != nil {
			return err
		}
		if active >= maximumActiveOperationGraphs {
			return fmt.Errorf("active operation graph limit %d is reached", maximumActiveOperationGraphs)
		}
		if !isContraction(request.Operation) {
			for _, key := range transaction.Keys("intents") {
				raw, _ := transaction.Get(key)
				existing, err := decodeReservation(raw)
				if err != nil {
					return err
				}
				if existing.Target == request.Target && !isContraction(existing.Operation) && existing.Phase != PhaseTerminal && existing.Phase != PhaseRejected {
					return fmt.Errorf("target already has a nonterminal expansion authority")
				}
			}
		}
		if err := jobs.Put(transaction, record); err != nil {
			return err
		}
		if request.Source == AdmissionPlan {
			if _, err := plans.Reserve(transaction, request.PlanID, record.ID, string(request.Operation), request.Target, request.ActorIdentity, observedNow); err != nil {
				return err
			}
		}
		if _, exists := transaction.Get(reservationKey(record.ID)); exists {
			return fmt.Errorf("operation reservation collision")
		}
		raw, err := persist.EncodeEntry(reservation)
		if err != nil {
			return err
		}
		return transaction.Create(reservationKey(record.ID), raw)
	})
	if err != nil {
		return jobs.Record{}, err
	}
	fresh, readErr := admitter.safety.Read()
	if readErr != nil {
		if rejectErr := admitter.rejectReservation(ctx, admission, request.ExpectedRevision+1, record.ID, "safety_recheck_unavailable"); rejectErr != nil {
			return record, fmt.Errorf("reservation safety recheck failed (%v) and terminalization failed: %w", readErr, rejectErr)
		}
		return record, fmt.Errorf("reservation rejected because safety recheck failed: %w", readErr)
	}
	freshDigest, _ := safetyDigest(fresh)
	if freshDigest != digest {
		if rejectErr := admitter.rejectReservation(ctx, admission, request.ExpectedRevision+1, record.ID, "safety_authority_changed"); rejectErr != nil {
			return record, fmt.Errorf("reservation safety authority changed and terminalization failed: %w", rejectErr)
		}
		return record, fmt.Errorf("reservation rejected because independent safety authority changed")
	}
	return record, nil
}

func (admitter *Admitter) rejectReservation(ctx context.Context, admission *locks.Lease, expectedRevision uint64, jobID, code string) error {
	observedNow, timeErr := admitter.trustedNow()
	if timeErr != nil {
		return timeErr
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("reservation terminalization did not converge: %w", ctx.Err())
		default:
		}
		_, _, err := admitter.normal.Update(ctx, admission, expectedRevision, func(transaction *persist.Transaction) error {
			if err := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-1); err != nil {
				return err
			}
			record, err := jobs.Load(transaction, jobID)
			if err != nil {
				return err
			}
			record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultFailed, Postconditions: []jobs.Postcondition{{Kind: "mutation_not_started", Status: jobs.PostconditionVerified, Identity: jobID}}, ErrorCode: code}, observedNow)
			if err != nil {
				return err
			}
			if err := jobs.Replace(transaction, record); err != nil {
				return err
			}
			reservation, err := loadReservation(transaction, jobID)
			if err != nil {
				return err
			}
			if reservation.AdmissionSource == AdmissionPlan {
				if _, err := plans.Reject(transaction, reservation.PlanID, jobID, observedNow); err != nil {
					return err
				}
			}
			reservation.Phase = PhaseRejected
			raw, err := persist.EncodeEntry(reservation)
			if err != nil {
				return err
			}
			return transaction.Replace(reservationKey(jobID), raw)
		})
		if !errors.Is(err, persist.ErrRevision) {
			return err
		}
		document, readErr := admitter.normal.Read()
		if readErr != nil {
			return readErr
		}
		intent, loadErr := loadReservationEntries(document.Entries, jobID)
		if loadErr != nil {
			return loadErr
		}
		if intent.Phase != PhaseReserved {
			return fmt.Errorf("reservation changed while terminalizing")
		}
		expectedRevision = document.Revision
	}
}

// ConsumePlan must be called only after AcquireExposure has acquired the
// resource mutation lock and then the shared exposure lock. Plan consumption,
// running-job transition, and immutable local phase intent commit atomically.
func (admitter *Admitter) ConsumePlan(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, request ConsumeRequest) (Reservation, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return Reservation{}, fmt.Errorf("authoritative mutation then exposure locks are required")
	}
	observedNow, timeErr := admitter.trustedNow()
	if timeErr != nil {
		return Reservation{}, timeErr
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return Reservation{}, err
	}
	reservationView, err := loadReservationEntries(document.Entries, request.JobID)
	if err != nil {
		return Reservation{}, err
	}
	reject := func(code string, cause error) (Reservation, error) {
		rejectErr := admitter.rejectReservation(ctx, exposure, document.Revision, reservationView.JobID, code)
		if rejectErr != nil {
			return Reservation{}, fmt.Errorf("%v; terminalization failed: %w", cause, rejectErr)
		}
		return Reservation{}, cause
	}
	if document.Revision != request.ExpectedRevision {
		return reject("normal_revision_changed", persist.ErrRevision)
	}
	if reservationView.AdmissionSource != AdmissionPlan {
		return Reservation{}, fmt.Errorf("operation reservation is not Plan-bound")
	}
	plan, err := plans.LoadEntries(document.Entries, reservationView.PlanID)
	if err != nil {
		return Reservation{}, err
	}
	recordView, err := jobs.LoadEntries(document.Entries, reservationView.JobID)
	if err != nil {
		return Reservation{}, err
	}
	binding, err := admitter.bindings.CurrentBinding(reservationView.Operation, reservationView.Target, observedNow)
	if err != nil {
		return reject("binding_refresh_failed", err)
	}
	confirmationDigest, err := admitter.confirmation.VerifyConfirmation(plan, recordView.ActorIdentity, request.ConfirmationProof, observedNow)
	if err != nil {
		return reject("confirmation_rejected", err)
	}
	if !digest(confirmationDigest) {
		return reject("confirmation_invalid", fmt.Errorf("confirmation verifier returned invalid digest"))
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return reject("safety_refresh_failed", err)
	}
	digest, err := safetyDigest(state)
	if err != nil {
		return Reservation{}, err
	}
	var result Reservation
	_, _, err = admitter.normal.Update(ctx, exposure, request.ExpectedRevision, func(transaction *persist.Transaction) error {
		reservation, err := loadReservation(transaction, request.JobID)
		if err != nil {
			return err
		}
		if reservation.Phase != PhaseReserved || mutation.Target() != reservation.Target {
			return fmt.Errorf("operation reservation is already consumed")
		}
		if reservation.SafetyDigest != digest && reservation.Operation != Publish {
			return fmt.Errorf("independent safety authority changed after admission")
		}
		if err := authorize(reservation.Operation, state, reservation.SafetyBinding, true, observedNow); err != nil {
			return err
		}
		if request.IntentGeneration != request.ExpectedRevision+1 {
			return fmt.Errorf("phase intent generation must equal the fresh normal-state revision")
		}
		if string(reservation.Operation) != binding.Operation || reservation.Target != planTarget(binding.Target) {
			return fmt.Errorf("Plan does not match the reserved operation target")
		}
		if _, err := plans.Consume(transaction, reservation.PlanID, reservation.JobID, binding, observedNow); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, reservation.JobID)
		if err != nil {
			return err
		}
		record, err = jobs.Start(record)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		reservation.Phase = PhaseLocalIntent
		reservation.IntentGeneration = request.IntentGeneration
		reservation.Consumption = &ConsumptionSnapshot{Source: AdmissionPlan, Config: binding.Config, Applied: binding.Applied, Evidence: append([]plans.Evidence(nil), binding.Evidence...), ConfirmationDigest: confirmationDigest, ConfirmedAt: observedNow, SafetyDigest: digest}
		raw, err := persist.EncodeEntry(reservation)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(reservation.JobID), raw); err != nil {
			return err
		}
		result = reservation
		return nil
	})
	if err != nil && !errors.Is(err, persist.ErrRecoveryRequired) {
		return reject("plan_consumption_rejected", err)
	}
	return result, err
}

// BeginPlanless starts a previously admitted timer or startup operation only
// after mutation→exposure acquisition. It records the same immutable local
// intent boundary as Plan consumption without fabricating a UI Plan.
func (admitter *Admitter) BeginPlanless(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, request ConsumeRequest) (Reservation, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return Reservation{}, fmt.Errorf("authoritative mutation then exposure locks are required")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return Reservation{}, err
	}
	reject := func(code string, cause error) (Reservation, error) {
		if rejectErr := admitter.rejectReservation(ctx, exposure, request.ExpectedRevision, request.JobID, code); rejectErr != nil {
			return Reservation{}, fmt.Errorf("%v; terminalization failed: %w", cause, rejectErr)
		}
		return Reservation{}, cause
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return reject("safety_refresh_failed", err)
	}
	digest, err := safetyDigest(state)
	if err != nil {
		return Reservation{}, err
	}
	var result Reservation
	_, _, err = admitter.normal.Update(ctx, exposure, request.ExpectedRevision, func(transaction *persist.Transaction) error {
		reservation, err := loadReservation(transaction, request.JobID)
		if err != nil {
			return err
		}
		if reservation.AdmissionSource != AdmissionTimer && reservation.AdmissionSource != AdmissionStartup {
			return fmt.Errorf("operation reservation is not a timer or startup admission")
		}
		if reservation.Phase != PhaseReserved || mutation.Target() != reservation.Target {
			return fmt.Errorf("operation reservation is already consumed or target-mismatched")
		}
		if request.IntentGeneration != request.ExpectedRevision+1 {
			return fmt.Errorf("phase intent generation must equal the fresh normal-state revision")
		}
		if reservation.SafetyDigest != digest {
			return fmt.Errorf("independent safety authority changed after admission")
		}
		if err := authorize(reservation.Operation, state, reservation.SafetyBinding, true, observedNow); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, reservation.JobID)
		if err != nil {
			return err
		}
		record, err = jobs.Start(record)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		reservation.Phase = PhaseLocalIntent
		reservation.IntentGeneration = request.IntentGeneration
		reservation.Consumption = &ConsumptionSnapshot{Source: reservation.AdmissionSource, ConfirmationDigest: planlessAdmissionDigest(reservation, digest), ConfirmedAt: observedNow, SafetyDigest: digest}
		raw, err := persist.EncodeEntry(reservation)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(reservation.JobID), raw); err != nil {
			return err
		}
		result = reservation
		return nil
	})
	if err != nil && !errors.Is(err, persist.ErrRecoveryRequired) {
		return reject("planless_start_rejected", err)
	}
	return result, err
}

func (admitter *Admitter) markRemoteWait(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) (Reservation, error) {
	if admitter == nil || !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return Reservation{}, fmt.Errorf("authoritative mutation then exposure locks are required")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return Reservation{}, err
	}
	intentView, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return Reservation{}, err
	}
	if mutation.Target() != intentView.Target {
		return Reservation{}, fmt.Errorf("remote wait mutation target does not match immutable intent")
	}
	if err := admitter.validateFreshAuthority(document, intentView); err != nil {
		return Reservation{}, err
	}
	var result Reservation
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		reservation, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if reservation.Phase != PhaseLocalIntent || reservation.AdmissionSource != AdmissionPlan {
			return fmt.Errorf("remote wait requires a Plan-bound local phase intent")
		}
		reservation.Phase = PhaseRemoteWait
		raw, err := persist.EncodeEntry(reservation)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), raw); err != nil {
			return err
		}
		result = reservation
		return nil
	})
	return result, err
}

func (admitter *Admitter) EnterRemoteWait(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) (Reservation, error) {
	reservation, err := admitter.markRemoteWait(ctx, mutation, exposure, expectedRevision, jobID)
	releaseErr := ReleaseExposure(mutation, exposure)
	return reservation, errors.Join(err, releaseErr)
}

func (admitter *Admitter) Reenter(ctx context.Context, mutationSet *MutationSet, manager *locks.Manager, expectedRevision uint64, jobID string) (Reservation, *MutationLease, *locks.Lease, error) {
	observedNow, timeErr := admitter.trustedNow()
	if timeErr != nil {
		return Reservation{}, nil, nil, timeErr
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return Reservation{}, nil, nil, err
	}
	if document.Revision != expectedRevision {
		return Reservation{}, nil, nil, persist.ErrRevision
	}
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return Reservation{}, nil, nil, err
	}
	record, err := jobs.LoadEntries(document.Entries, jobID)
	if err != nil {
		return Reservation{}, nil, nil, err
	}
	if intent.Phase != PhaseRemoteWait || intent.Consumption == nil {
		return Reservation{}, nil, nil, fmt.Errorf("operation is not in remote wait")
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, manager)
	if err != nil {
		return Reservation{}, nil, nil, err
	}
	fail := func(err error) (Reservation, *MutationLease, *locks.Lease, error) {
		return Reservation{}, nil, nil, errors.Join(err, ReleaseExposure(mutation, exposure))
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return fail(err)
	}
	currentDigest, err := safetyDigest(state)
	if err != nil {
		return fail(err)
	}
	if intent.Consumption == nil || currentDigest != intent.Consumption.SafetyDigest {
		return fail(fmt.Errorf("contraction or safety transition preempted remote operation"))
	}
	if err := authorize(intent.Operation, state, intent.SafetyBinding, true, observedNow); err != nil {
		return fail(err)
	}
	binding, err := admitter.bindings.CurrentBinding(intent.Operation, intent.Target, observedNow)
	if err != nil {
		return fail(err)
	}
	if err := plans.ValidateBindingFreshness(binding, observedNow); err != nil {
		return fail(err)
	}
	if planTarget(binding.Target) != intent.Target || binding.ActorIdentity != record.ActorIdentity {
		return fail(fmt.Errorf("operation target or actor binding changed during remote wait"))
	}
	snapshot := plans.Binding{Operation: string(intent.Operation), Target: binding.Target, ActorIdentity: record.ActorIdentity, Config: intent.Consumption.Config, Applied: intent.Consumption.Applied, Evidence: intent.Consumption.Evidence}
	if !plans.SameBindingIdentity(binding, snapshot) {
		return fail(fmt.Errorf("Plan-derived binding changed during remote wait"))
	}
	var result Reservation
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		fresh, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if fresh.Phase != PhaseRemoteWait || !reflect.DeepEqual(fresh.Consumption, intent.Consumption) {
			return fmt.Errorf("remote intent changed")
		}
		fresh.Phase = PhaseReentered
		raw, err := persist.EncodeEntry(fresh)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), raw); err != nil {
			return err
		}
		result = fresh
		return nil
	})
	if err != nil {
		return fail(err)
	}
	return result, mutation, exposure, nil
}

// ReserveChild records a submitted child under the short-lived admission lock
// before any child may be launched. It intentionally does not accept mutation
// or exposure leases.
func (admitter *Admitter) ReserveChild(ctx context.Context, admission *locks.Lease, expectedRevision uint64, child ChildRecord) error {
	if admitter == nil || admission == nil || admission.Authority() != admitter.normal.LockAuthority() || !admission.Holds(locks.MutationAdmission) || child.State != ChildSubmitted {
		return fmt.Errorf("child reservation requires the authoritative mutation-admission lock")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return err
	}
	intentView, err := loadReservationEntries(document.Entries, child.JobID)
	if err != nil {
		return err
	}
	if err := admitter.validateFreshAuthority(document, intentView); err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, admission, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, child.JobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered {
			return fmt.Errorf("child reservation requires an active durable local intent")
		}
		if err := validateChildAgainstIntent(transaction, child, intent); err != nil {
			return err
		}
		linkedChildren := 0
		for _, key := range transaction.Keys("children") {
			raw, _ := transaction.Get(key)
			var existing ChildRecord
			if err := decodeStrict(raw, &existing); err != nil {
				return err
			}
			if existing.JobID == child.JobID {
				linkedChildren++
			}
		}
		if linkedChildren >= maximumChildrenPerJob {
			return fmt.Errorf("child reservation limit %d is reached", maximumChildrenPerJob)
		}
		raw, err := persist.EncodeEntry(child)
		if err != nil {
			return err
		}
		return transaction.Create("children/"+child.ID, raw)
	})
	return err
}
func (admitter *Admitter) TransitionChild(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, child ChildRecord) error {
	if admitter == nil || !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("child transition requires authoritative mutation then exposure locks")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return err
	}
	intentView, err := loadReservationEntries(document.Entries, child.JobID)
	if err != nil {
		return err
	}
	if mutation.Target() != intentView.Target {
		return fmt.Errorf("child transition mutation target does not match immutable intent")
	}
	if err := admitter.validateFreshAuthority(document, intentView); err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, child.JobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered {
			return fmt.Errorf("child transition requires an active locked local phase")
		}
		if err := validateChildAgainstIntent(transaction, child, intent); err != nil {
			return err
		}
		raw, err := persist.EncodeEntry(child)
		if err != nil {
			return err
		}
		return transaction.Replace("children/"+child.ID, raw)
	})
	return err
}

func validateChildAgainstIntent(transaction *persist.Transaction, child ChildRecord, intent Reservation) error {
	installation, err := loadInstallation(transaction)
	if err != nil {
		return err
	}
	if child.InstallationID != installation.InstallationID || child.Operation != intent.Operation || child.Target != intent.Target || child.IntentGeneration != intent.IntentGeneration || !child.Deadline.Equal(intent.SafetyBinding.Deadline) {
		return fmt.Errorf("child identity does not exactly match installation, operation, target, generation, and deadline authority")
	}
	return nil
}
func (admitter *Admitter) PutJournal(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, journal JournalRecord, create bool) error {
	if admitter == nil || !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("journal write requires authoritative mutation then exposure locks")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return err
	}
	intentView, err := loadReservationEntries(document.Entries, journal.JobID)
	if err != nil {
		return err
	}
	if mutation.Target() != intentView.Target {
		return fmt.Errorf("journal mutation target does not match immutable intent")
	}
	if err := admitter.validateFreshAuthority(document, intentView); err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, journal.JobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered {
			return fmt.Errorf("journal writes require an active local intent phase")
		}
		markerDigest, err := safetyBindingDigest(intent.SafetyBinding)
		if err != nil {
			return err
		}
		journal.SafetyMarkerDigest = markerDigest
		if intent.Consumption == nil || !journal.Deadline.Equal(intent.SafetyBinding.Deadline) {
			return fmt.Errorf("journal deadline does not match immutable intent authority")
		}
		if create {
			if intent.JournalSafetyDigest != "" {
				return fmt.Errorf("operation intent already binds a journal safety authority")
			}
			intent.JournalSafetyDigest = markerDigest
			intentRaw, err := persist.EncodeEntry(intent)
			if err != nil {
				return err
			}
			if err := transaction.Replace(reservationKey(intent.JobID), intentRaw); err != nil {
				return err
			}
		} else if intent.JournalSafetyDigest != markerDigest {
			return fmt.Errorf("journal safety authority changed")
		}
		if create {
			for _, key := range transaction.Keys("journals") {
				raw, _ := transaction.Get(key)
				var existing JournalRecord
				if err := decodeStrict(raw, &existing); err != nil {
					return err
				}
				if existing.JobID == journal.JobID {
					return fmt.Errorf("operation already has its single exact journal")
				}
			}
		}
		raw, err := persist.EncodeEntry(journal)
		if err != nil {
			return err
		}
		if create {
			return transaction.Create("journals/"+journal.ID, raw)
		}
		return transaction.Replace("journals/"+journal.ID, raw)
	})
	return err
}

func InventoryEmpty(document persist.Document, exceptJob string) (bool, error) {
	for _, key := range persist.EntryKeys(document, "jobs") {
		record, err := jobs.LoadEntries(document.Entries, strings.TrimPrefix(key, "jobs/"))
		if err != nil {
			return false, err
		}
		if record.ID != exceptJob && record.Status != jobs.StatusTerminal {
			return false, nil
		}
	}
	for _, key := range persist.EntryKeys(document, "children") {
		var child ChildRecord
		if err := decodeStrict(document.Entries[key], &child); err != nil {
			return false, err
		}
		if child.State != ChildTerminal {
			return false, nil
		}
	}
	for _, key := range persist.EntryKeys(document, "journals") {
		var journal JournalRecord
		if err := decodeStrict(document.Entries[key], &journal); err != nil {
			return false, err
		}
		if journal.Phase != JournalTerminal {
			return false, nil
		}
	}
	return true, nil
}

func activeGraphCount(transaction *persist.Transaction) (int, error) {
	active := 0
	for _, key := range transaction.Keys("intents") {
		raw, _ := transaction.Get(key)
		intent, err := decodeReservation(raw)
		if err != nil {
			return 0, err
		}
		if intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
			active++
		}
	}
	return active, nil
}

func pruneTerminalGraphs(transaction *persist.Transaction, keep int) error {
	if keep < 0 {
		return fmt.Errorf("terminal graph retention bound is invalid")
	}
	type terminalGraph struct {
		intent Reservation
		ended  time.Time
	}
	graphs := []terminalGraph{}
	for _, key := range transaction.Keys("intents") {
		raw, _ := transaction.Get(key)
		intent, err := decodeReservation(raw)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
			continue
		}
		record, err := jobs.Load(transaction, intent.JobID)
		if err != nil {
			return fmt.Errorf("terminal graph job authority: %w", err)
		}
		if record.EndedAt == nil {
			return fmt.Errorf("terminal graph job authority has no end time")
		}
		graphs = append(graphs, terminalGraph{intent: intent, ended: *record.EndedAt})
	}
	sort.Slice(graphs, func(i, j int) bool {
		if graphs[i].ended.Equal(graphs[j].ended) {
			return graphs[i].intent.JobID < graphs[j].intent.JobID
		}
		return graphs[i].ended.Before(graphs[j].ended)
	})
	remove := len(graphs) - keep
	for index := 0; index < remove; index++ {
		intent := graphs[index].intent
		for _, namespace := range []string{"children", "journals"} {
			for _, key := range transaction.Keys(namespace) {
				raw, _ := transaction.Get(key)
				linkedJob := ""
				if namespace == "children" {
					var child ChildRecord
					if err := decodeStrict(raw, &child); err != nil {
						return err
					}
					linkedJob = child.JobID
				} else {
					var journal JournalRecord
					if err := decodeStrict(raw, &journal); err != nil {
						return err
					}
					linkedJob = journal.JobID
				}
				if linkedJob == intent.JobID {
					if err := transaction.Delete(key); err != nil {
						return err
					}
				}
			}
		}
		if intent.PlanID != "" {
			if err := transaction.Delete("plans/" + intent.PlanID); err != nil {
				return err
			}
		}
		if err := transaction.Delete("jobs/" + intent.JobID); err != nil {
			return err
		}
		if err := transaction.Delete(reservationKey(intent.JobID)); err != nil {
			return err
		}
	}
	return nil
}

func linkedWorkTerminal(transaction *persist.Transaction, jobID string) (bool, error) {
	for _, key := range transaction.Keys("children") {
		raw, _ := transaction.Get(key)
		var child ChildRecord
		if err := decodeStrict(raw, &child); err != nil {
			return false, err
		}
		if child.JobID == jobID && child.State != ChildTerminal {
			return false, nil
		}
	}
	for _, key := range transaction.Keys("journals") {
		raw, _ := transaction.Get(key)
		var journal JournalRecord
		if err := decodeStrict(raw, &journal); err != nil {
			return false, err
		}
		if journal.JobID == jobID && journal.Phase != JournalTerminal {
			return false, nil
		}
	}
	return true, nil
}

func (admitter *Admitter) Complete(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, branchName string, paths []string, postconditions []jobs.Postcondition, errorCode string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("job completion requires authoritative mutation then exposure locks")
	}
	observedNow, timeErr := admitter.trustedNow()
	if timeErr != nil {
		return jobs.Record{}, timeErr
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return jobs.Record{}, err
	}
	if document.Revision != expectedRevision {
		return jobs.Record{}, persist.ErrRevision
	}
	intentView, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return jobs.Record{}, err
	}
	if mutation.Target() != intentView.Target {
		return jobs.Record{}, fmt.Errorf("completion mutation target does not match immutable intent")
	}
	recordView, err := jobs.LoadEntries(document.Entries, jobID)
	if err != nil {
		return jobs.Record{}, err
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return jobs.Record{}, err
	}
	currentSafetyDigest, err := safetyDigest(state)
	if err != nil {
		return jobs.Record{}, err
	}
	if intentView.Consumption == nil || intentView.Operation == Publish && currentSafetyDigest != intentView.Consumption.SafetyDigest {
		return jobs.Record{}, fmt.Errorf("operation safety authority changed before terminal commit")
	}
	if err := authorize(intentView.Operation, state, intentView.SafetyBinding, true, observedNow); err != nil {
		return jobs.Record{}, err
	}
	if intentView.AdmissionSource == AdmissionPlan {
		binding, err := admitter.bindings.CurrentBinding(intentView.Operation, intentView.Target, observedNow)
		if err != nil {
			return jobs.Record{}, err
		}
		if err := plans.ValidateBindingFreshness(binding, observedNow); err != nil {
			return jobs.Record{}, err
		}
		snapshot := plans.Binding{Operation: string(intentView.Operation), Target: binding.Target, ActorIdentity: recordView.ActorIdentity, Config: intentView.Consumption.Config, Applied: intentView.Consumption.Applied, Evidence: intentView.Consumption.Evidence}
		if planTarget(binding.Target) != intentView.Target || !plans.SameBindingIdentity(binding, snapshot) {
			return jobs.Record{}, fmt.Errorf("Plan-derived binding changed before terminal commit")
		}
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		if err := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-1); err != nil {
			return err
		}
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered {
			return fmt.Errorf("operation intent must complete from a validated local phase")
		}
		terminal, err := linkedWorkTerminal(transaction, jobID)
		if err != nil {
			return err
		}
		if !terminal {
			return fmt.Errorf("operation child or journal remains nonterminal")
		}
		registration, ok := admitter.registry.Registration(intent.Operation)
		if !ok {
			return fmt.Errorf("operation owner has no result branch registry")
		}
		branch, ok := registration.Results.Branch(branchName)
		if !ok {
			return fmt.Errorf("terminal result branch is not registered")
		}
		for _, condition := range postconditions {
			if condition.Status != branch.Postcondition {
				return fmt.Errorf("terminal postcondition does not match registered branch semantics")
			}
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: branch.Result, ModifiedPaths: paths, Postconditions: postconditions, ErrorCode: errorCode}, observedNow)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		intent.Phase = PhaseTerminal
		raw, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), raw); err != nil {
			return err
		}
		completed = record
		return nil
	})
	return completed, err
}

func (admitter *Admitter) validateFreshAuthority(document persist.Document, intent Reservation) error {
	if intent.Consumption == nil {
		return fmt.Errorf("operation has no consumed immutable authority")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return err
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return err
	}
	currentDigest, err := safetyDigest(state)
	if err != nil {
		return err
	}
	if !isContraction(intent.Operation) && currentDigest != intent.Consumption.SafetyDigest {
		return fmt.Errorf("contraction or safety transition preempted operation authority")
	}
	if err := authorize(intent.Operation, state, intent.SafetyBinding, true, observedNow); err != nil {
		return err
	}
	if intent.AdmissionSource != AdmissionPlan {
		return nil
	}
	record, err := jobs.LoadEntries(document.Entries, intent.JobID)
	if err != nil {
		return err
	}
	binding, err := admitter.bindings.CurrentBinding(intent.Operation, intent.Target, observedNow)
	if err != nil {
		return err
	}
	if err := plans.ValidateBindingFreshness(binding, observedNow); err != nil {
		return err
	}
	snapshot := plans.Binding{Operation: string(intent.Operation), Target: binding.Target, ActorIdentity: record.ActorIdentity, Config: intent.Consumption.Config, Applied: intent.Consumption.Applied, Evidence: intent.Consumption.Evidence}
	if planTarget(binding.Target) != intent.Target || !plans.SameBindingIdentity(binding, snapshot) {
		return fmt.Errorf("Plan-derived binding changed after intent commit")
	}
	return nil
}

func authorize(operation Type, state safety.State, binding SafetyBinding, consuming bool, now time.Time) error {
	if !validType(operation) || operation == EmergencyCloseAll {
		return fmt.Errorf("operation is unsupported for normal admission")
	}
	contraction := isContraction(operation)
	if operation == CertificateExpiry || operation == EdgeOneExpiry {
		if !validExpiryBinding(operation, state, binding) || binding.Deadline.IsZero() || binding.Deadline.After(now) {
			return fmt.Errorf("expiry contraction authority binding is stale, absent, or not due")
		}
	}
	if operation == StartupContraction && !validStartupBinding(state, binding) {
		return fmt.Errorf("startup contraction authority binding is stale or absent")
	}
	if state.MaintenancePending != nil || state.UpgradePending != nil || (state.BackupTransition != nil && state.BackupTransition.Phase != safety.BackupTransitionImported) || state.BackupQuiescence != nil || state.StopFence != nil {
		if !contraction {
			return fmt.Errorf("independent fence blocks expansion but not contraction")
		}
	}
	if state.DependencyTransitionPending != nil && !contraction {
		return fmt.Errorf("dependency transition blocks expansion admission")
	}
	if operation == Publish {
		if state.GlobalClose.Phase != safety.GlobalCloseNone {
			return fmt.Errorf("global close blocks expansion admission")
		}
		var resource *safety.ResourceSafety
		for index := range state.Resources {
			if state.Resources[index].ResourceID == binding.ResourceID {
				resource = &state.Resources[index]
				break
			}
		}
		if resource == nil {
			return fmt.Errorf("publish safety resource binding is missing")
		}
		if resource.Closing != nil || resource.State == safety.ResourceDeleting || resource.Ownership == safety.OwnershipOrphan || resource.ChallengePending != nil {
			return fmt.Errorf("resource lifecycle or challenge authority blocks publish")
		}
		if !resource.EdgeOne.Deadline.IsZero() && resource.EdgeOne.Deadline.Sub(now) < 5*time.Minute {
			return fmt.Errorf("EdgeOne safety deadline is too near for ordinary activation")
		}
		if resource.Reactivating != nil && (resource.Reactivating.CertificateUntil.Sub(now) < 5*time.Minute || resource.Reactivating.ACLUntil.Sub(now) < 5*time.Minute) {
			return fmt.Errorf("reactivation safety deadline is too near")
		}
		if !consuming {
			return nil
		}
		action := safety.ActionPublish
		input := safety.GuardInput{State: state, Action: action, ResourceID: binding.ResourceID, Now: now}
		if resource.Reactivating != nil {
			input.Action = safety.ActionReactivate
			input.PlanID = binding.PlanID
			input.Generation = binding.IntentGeneration
			input.CandidateDigest = binding.CandidateDigest
			input.CandidateBundle = binding.CandidateBundle
		}
		decision := safety.Check(input)
		if !decision.Allowed {
			return fmt.Errorf("mandatory safety guard rejected publish: %s", decision.Reason)
		}
	}
	return nil
}
func isContraction(operation Type) bool {
	switch operation {
	case Unpublish, CloseAll, CertificateExpiry, EdgeOneExpiry, AutomaticReconciliation, StartupContraction:
		return true
	default:
		return false
	}
}

func validStartupBinding(state safety.State, binding SafetyBinding) bool {
	if binding.IntentGeneration == 0 {
		return false
	}
	if binding.ResourceID == "headscale" {
		if state.Headscale.ChallengePending != nil {
			return state.Headscale.ChallengePending.Generation == binding.IntentGeneration && state.Headscale.ChallengePending.PlanID == binding.PlanID && state.Headscale.ChallengePending.BootstrapIdentity == binding.CandidateDigest && binding.CandidateBundle == ""
		}
		if state.Headscale.Reactivating != nil {
			return state.Headscale.Reactivating.Generation == binding.IntentGeneration && state.Headscale.Reactivating.PlanID == binding.PlanID && state.Headscale.Reactivating.CandidateDigest == binding.CandidateDigest && state.Headscale.Reactivating.CandidateBundle == binding.CandidateBundle
		}
		return false
	}
	for _, resource := range state.Resources {
		if resource.ResourceID != binding.ResourceID {
			continue
		}
		if resource.ChallengePending != nil {
			return resource.ChallengePending.Generation == binding.IntentGeneration && resource.ChallengePending.PlanID == binding.PlanID && resource.ChallengePending.BootstrapIdentity == binding.CandidateDigest && binding.CandidateBundle == ""
		}
		if resource.Reactivating != nil {
			return resource.Reactivating.Generation == binding.IntentGeneration && resource.Reactivating.PlanID == binding.PlanID && resource.Reactivating.CandidateDigest == binding.CandidateDigest && resource.Reactivating.CandidateBundle == binding.CandidateBundle
		}
	}
	return false
}

func validExpiryBinding(operation Type, state safety.State, binding SafetyBinding) bool {
	for _, resource := range state.Resources {
		if resource.ResourceID != binding.ResourceID {
			continue
		}
		if operation == CertificateExpiry && binding.ExpiryKind == "certificate_expiry" && resource.CertificateExpiry != nil {
			return resource.CertificateExpiry.Generation == binding.ExpiryGeneration && resource.CertificateExpiry.Deadline.Equal(binding.Deadline)
		}
		if operation == EdgeOneExpiry && binding.ExpiryKind == "edgeone_expiry" && resource.EdgeOne.Expiry != nil {
			return resource.EdgeOne.Expiry.Generation == binding.ExpiryGeneration && resource.EdgeOne.Expiry.Deadline.Equal(binding.Deadline)
		}
	}
	if operation == CertificateExpiry && binding.ResourceID == "headscale" && binding.ExpiryKind == "certificate_expiry" && state.Headscale.CertificateExpiry != nil {
		return state.Headscale.CertificateExpiry.Generation == binding.ExpiryGeneration && state.Headscale.CertificateExpiry.Deadline.Equal(binding.Deadline)
	}
	return false
}

// AuthorizeStateIndependentContraction is the closed no-normal-store exception.
// It grants no normal-state or job write authority.
func (admitter *Admitter) AuthorizeStateIndependentContraction(operation Type, binding SafetyBinding, unavailable persist.UnavailableProof, exposure *locks.Lease, commitAuthority func() error) error {
	if admitter == nil {
		return fmt.Errorf("state-independent authority is nil")
	}
	now, timeErr := admitter.independentNow()
	if timeErr != nil {
		return timeErr
	}
	if exposure == nil || exposure.Authority() != admitter.normal.LockAuthority() || !exposure.Holds(locks.Exposure) || commitAuthority == nil {
		return fmt.Errorf("state-independent contraction requires exposure-locked authority commit")
	}
	if !admitter.normal.ValidateUnavailable(unavailable) {
		return fmt.Errorf("state-independent contraction requires proven normal-store unavailability or a failed durable admission write")
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return fmt.Errorf("read independent safety authority: %w", err)
	}
	switch operation {
	case EmergencyCloseAll:
		if binding.GlobalGeneration != state.GlobalClose.Generation || binding.ProposedGeneration != state.GlobalClose.Generation+1 {
			return fmt.Errorf("emergency global generation binding is stale")
		}
	case CertificateExpiry, EdgeOneExpiry:
		if !validExpiryBinding(operation, state, binding) || binding.Deadline.IsZero() || binding.Deadline.After(now) {
			return fmt.Errorf("state-independent expiry binding is stale or not due")
		}
	case StartupContraction:
		if !validStartupBinding(state, binding) {
			return fmt.Errorf("state-independent startup contraction binding is stale")
		}
	default:
		return fmt.Errorf("operation is not a state-independent contraction exception")
	}
	return commitAuthority()
}

func authoritativeOperationLeases(normal *persist.Store, mutation *MutationLease, exposure *locks.Lease) bool {
	return normal != nil && mutation != nil && mutation.Active() && mutation.Authority() == normal.LockAuthority() && exposure != nil && exposure.Authority() == normal.LockAuthority() && exposure.Holds(locks.Exposure)
}

func loadInstallation(transaction *persist.Transaction) (domain.Installation, error) {
	raw, present := transaction.Get("installations/current")
	if !present {
		return domain.Installation{}, fmt.Errorf("installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return domain.Installation{}, fmt.Errorf("installation authority: %w", err)
	}
	return installation, nil
}

func loadReservation(transaction *persist.Transaction, jobID string) (Reservation, error) {
	raw, ok := transaction.Get(reservationKey(jobID))
	if !ok {
		return Reservation{}, fmt.Errorf("operation reservation is missing")
	}
	return decodeReservation(raw)
}
func loadReservationEntries(entries map[string]json.RawMessage, jobID string) (Reservation, error) {
	raw, ok := entries[reservationKey(jobID)]
	if !ok {
		return Reservation{}, fmt.Errorf("operation reservation is missing")
	}
	return decodeReservation(raw)
}
func validateIntentEntry(key string, raw json.RawMessage) error {
	value, err := decodeReservation(raw)
	if err != nil {
		return err
	}
	if key != reservationKey(value.JobID) {
		return fmt.Errorf("operation intent key does not match job")
	}
	return nil
}
func validateIntentTransition(_ string, before, after json.RawMessage) error {
	if len(before) == 0 {
		value, err := decodeReservation(after)
		if err != nil {
			return err
		}
		if value.Phase != PhaseReserved {
			return fmt.Errorf("new operation intent must start reserved")
		}
		return nil
	}
	oldValue, err := decodeReservation(before)
	if err != nil {
		return err
	}
	if len(after) == 0 {
		if oldValue.Phase != PhaseTerminal && oldValue.Phase != PhaseRejected {
			return fmt.Errorf("only a terminal operation intent may be pruned")
		}
		return nil
	}
	newValue, err := decodeReservation(after)
	if err != nil {
		return err
	}
	oldPhase, newPhase := oldValue.Phase, newValue.Phase
	oldValue.Phase = ""
	newValue.Phase = ""
	oldGeneration, newGeneration := oldValue.IntentGeneration, newValue.IntentGeneration
	oldConsumption, newConsumption := oldValue.Consumption, newValue.Consumption
	oldJournalSafety, newJournalSafety := oldValue.JournalSafetyDigest, newValue.JournalSafetyDigest
	oldValue.IntentGeneration = 0
	newValue.IntentGeneration = 0
	oldValue.Consumption = nil
	newValue.Consumption = nil
	oldValue.JournalSafetyDigest = ""
	newValue.JournalSafetyDigest = ""
	if !reflect.DeepEqual(oldValue, newValue) {
		return fmt.Errorf("immutable operation intent binding was rewritten")
	}
	journalBindingOnly := oldPhase == newPhase && oldJournalSafety == "" && newJournalSafety != ""
	valid := journalBindingOnly || oldPhase == PhaseReserved && (newPhase == PhaseLocalIntent || newPhase == PhaseRejected) || oldPhase == PhaseLocalIntent && (newPhase == PhaseRemoteWait || newPhase == PhaseTerminal) || oldPhase == PhaseRemoteWait && (newPhase == PhaseReentered || newPhase == PhaseTerminal) || oldPhase == PhaseReentered && (newPhase == PhaseRemoteWait || newPhase == PhaseTerminal)
	if !valid {
		return fmt.Errorf("operation intent phase transition is invalid")
	}
	if oldGeneration != 0 && newGeneration != oldGeneration {
		return fmt.Errorf("operation intent generation changed")
	}
	if oldConsumption == nil && newPhase != PhaseRejected && newConsumption == nil {
		return fmt.Errorf("consumption snapshot is missing")
	}
	if oldConsumption != nil && !reflect.DeepEqual(oldConsumption, newConsumption) {
		return fmt.Errorf("consumption snapshot was rewritten")
	}
	if oldJournalSafety != "" && newJournalSafety != oldJournalSafety || newJournalSafety != "" && !exactDigest(newJournalSafety) {
		return fmt.Errorf("journal safety binding was rewritten or is invalid")
	}
	return nil
}
func decodeReservation(raw json.RawMessage) (Reservation, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value Reservation
	if err := decoder.Decode(&value); err != nil {
		return Reservation{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Reservation{}, fmt.Errorf("operation intent has trailing data")
	}
	if err := validateReservation(value); err != nil {
		return Reservation{}, err
	}
	return value, nil
}
func validateChildEntry(key string, raw json.RawMessage) error {
	var value ChildRecord
	if err := decodeStrict(raw, &value); err != nil {
		return err
	}
	if key != "children/"+value.ID {
		return fmt.Errorf("child reservation key does not match ID")
	}
	return validateChildRecord(value)
}

func validateChildRecord(value ChildRecord) error {
	if value.SchemaVersion != "lanpanel.child.v1" || !validIdentityRef(value.ID) || !validIdentityRef(value.JobID) || !validIdentityRef(value.InstallationID) || !validType(value.Operation) || !validIdentityRef(value.Target) || value.IntentGeneration == 0 || !validIdentityRef(value.Profile) || !exactDigest(value.InputDigest) || !exactDigest(value.ArtifactDigest) || value.Deadline.IsZero() || value.SubmittedAt.IsZero() || value.Deadline.Before(value.SubmittedAt) {
		return fmt.Errorf("child reservation identity is invalid")
	}
	if value.State != ChildSubmitted && value.State != ChildRunning && value.State != ChildTerminal {
		return fmt.Errorf("child state is invalid")
	}
	terminal := value.State == ChildTerminal
	validOutcome := value.Outcome == ChildSucceeded || value.Outcome == ChildFailed || value.Outcome == ChildUnknown
	if terminal != (value.TerminalAt != nil) || terminal != validOutcome || terminal != exactDigest(value.ResultDigest) || terminal && value.TerminalAt.Before(value.SubmittedAt) {
		return fmt.Errorf("child terminal evidence is inconsistent")
	}
	return nil
}
func validateChildTransition(_ string, before, after json.RawMessage) error {
	if len(before) == 0 {
		var value ChildRecord
		if err := decodeStrict(after, &value); err != nil {
			return err
		}
		if value.State != ChildSubmitted {
			return fmt.Errorf("new child must start submitted")
		}
		return nil
	}
	var oldValue, newValue ChildRecord
	if err := decodeStrict(before, &oldValue); err != nil {
		return err
	}
	if len(after) == 0 {
		if oldValue.State != ChildTerminal {
			return fmt.Errorf("only a terminal child may be pruned")
		}
		return nil
	}
	if err := decodeStrict(after, &newValue); err != nil {
		return err
	}
	oldState, newState := oldValue.State, newValue.State
	oldValue.State = ""
	newValue.State = ""
	oldValue.TerminalAt = nil
	newValue.TerminalAt = nil
	oldValue.Outcome = ""
	newValue.Outcome = ""
	oldValue.ResultDigest = ""
	newValue.ResultDigest = ""
	if !reflect.DeepEqual(oldValue, newValue) {
		return fmt.Errorf("child identity was rewritten")
	}
	if oldState == ChildTerminal || oldState == ChildSubmitted && newState != ChildRunning && newState != ChildTerminal || oldState == ChildRunning && newState != ChildTerminal {
		return fmt.Errorf("child transition is invalid")
	}
	return nil
}
func validateJournalEntry(key string, raw json.RawMessage) error {
	var value JournalRecord
	if err := decodeStrict(raw, &value); err != nil {
		return err
	}
	if key != "journals/"+value.ID {
		return fmt.Errorf("operation journal key does not match ID")
	}
	return validateJournalRecord(value)
}

func validateJournalRecord(value JournalRecord) error {
	if value.SchemaVersion != "lanpanel.journal.v1" || !validIdentityRef(value.ID) || !validIdentityRef(value.JobID) || !validIdentityRef(value.InstallationID) || !validIdentityRef(value.Target) || value.Generation == 0 || value.Deadline.IsZero() || !exactDigest(value.ArtifactDigest) || !exactDigest(value.SafetyMarkerDigest) || (value.Phase != JournalPrepared && value.Phase != JournalActive && value.Phase != JournalTerminal) {
		return fmt.Errorf("operation journal identity is invalid")
	}
	if value.Kind == JournalNonIngressLocalCommit {
		if value.Operation != Maintenance && value.Operation != BackupEnter {
			return fmt.Errorf("non-ingress journal operation is not allowed")
		}
	} else if value.Kind == JournalPackageTransaction {
		if value.Operation != PackageTransaction || value.Target != string(plans.TargetInstallation) || len(value.ResourceIDs) != 0 {
			return fmt.Errorf("package journal operation or target is invalid")
		}
	} else if value.Kind == JournalAppContraction {
		switch value.Operation {
		case Publish, Unpublish, CloseAll, CertificateExpiry, EdgeOneExpiry, AutomaticReconciliation, StartupContraction:
		default:
			return fmt.Errorf("App contraction journal operation is not allowed")
		}
	} else {
		return fmt.Errorf("operation journal kind is not allowed")
	}
	if len(value.ResourceIDs) > maximumJournalResources || !sort.StringsAreSorted(value.ResourceIDs) {
		return fmt.Errorf("journal affected-resource inventory is unbounded or noncanonical")
	}
	for index, resourceID := range value.ResourceIDs {
		if !validIdentityRef(resourceID) || index != 0 && value.ResourceIDs[index-1] == resourceID {
			return fmt.Errorf("journal affected-resource inventory is invalid")
		}
	}
	if value.Kind == JournalAppContraction {
		exactApp := len(value.ResourceIDs) == 1 && value.Target == "resource/"+value.ResourceIDs[0]
		exactCloseAll := value.Operation == CloseAll && len(value.ResourceIDs) != 0 && value.Target == string(plans.TargetInstallation)
		if !exactApp && !exactCloseAll {
			return fmt.Errorf("App contraction journal does not exactly identify its affected resources")
		}
	} else if len(value.ResourceIDs) != 0 {
		return fmt.Errorf("non-ingress journal unexpectedly identifies App resources")
	}
	if len(value.ChildIDs) == 0 || len(value.ChildIDs) > maximumChildrenPerJob {
		return fmt.Errorf("journal child inventory is empty or unbounded")
	}
	for index, childID := range value.ChildIDs {
		if !validIdentityRef(childID) || index > 0 && value.ChildIDs[index-1] >= childID {
			return fmt.Errorf("operation journal child identities are not canonical")
		}
	}
	return nil
}
func validateJournalTransition(_ string, before, after json.RawMessage) error {
	if len(before) == 0 {
		var value JournalRecord
		if err := decodeStrict(after, &value); err != nil {
			return err
		}
		if value.Phase != JournalPrepared {
			return fmt.Errorf("new journal must start prepared")
		}
		return nil
	}
	var oldValue, newValue JournalRecord
	if err := decodeStrict(before, &oldValue); err != nil {
		return err
	}
	if len(after) == 0 {
		if oldValue.Phase != JournalTerminal {
			return fmt.Errorf("only a terminal journal may be pruned")
		}
		return nil
	}
	if err := decodeStrict(after, &newValue); err != nil {
		return err
	}
	oldPhase, newPhase := oldValue.Phase, newValue.Phase
	oldValue.Phase = ""
	newValue.Phase = ""
	if !reflect.DeepEqual(oldValue, newValue) {
		return fmt.Errorf("journal identity was rewritten")
	}
	if oldPhase == JournalTerminal || oldPhase == JournalPrepared && newPhase != JournalActive && newPhase != JournalTerminal || oldPhase == JournalActive && newPhase != JournalTerminal {
		return fmt.Errorf("journal transition is invalid")
	}
	return nil
}
func decodeStrict(raw json.RawMessage, value any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("normal entry has trailing data")
	}
	return nil
}

func validateLinks(document persist.Document) error {
	intents := map[string]Reservation{}
	terminalGraphs := 0
	for _, key := range persist.EntryKeys(document, "intents") {
		raw := document.Entries[key]
		intent, err := decodeReservation(raw)
		if err != nil {
			return err
		}
		intents[intent.JobID] = intent
		record, err := jobs.LoadEntries(document.Entries, intent.JobID)
		if err != nil {
			return fmt.Errorf("intent job link: %w", err)
		}
		var plan plans.Plan
		if intent.AdmissionSource == AdmissionPlan {
			plan, err = plans.LoadEntries(document.Entries, intent.PlanID)
			if err != nil {
				return fmt.Errorf("intent Plan link: %w", err)
			}
		}
		switch intent.Phase {
		case PhaseReserved:
			if record.Status != jobs.StatusReserved || intent.AdmissionSource == AdmissionPlan && (plan.ConsumedAt != nil || plan.ReservedByJob != record.ID) {
				return fmt.Errorf("reserved intent links inconsistent job or admission authority")
			}
		case PhaseLocalIntent, PhaseRemoteWait, PhaseReentered:
			if record.Status != jobs.StatusRunning || intent.AdmissionSource == AdmissionPlan && (plan.ConsumedAt == nil || plan.ConsumedByJob != record.ID) {
				return fmt.Errorf("active intent links inconsistent job or admission authority")
			}
		case PhaseRejected:
			if record.Status != jobs.StatusTerminal || intent.AdmissionSource == AdmissionPlan && (plan.RejectedAt == nil || plan.RejectedByJob != record.ID) {
				return fmt.Errorf("rejected intent links inconsistent job or admission authority")
			}
			terminalGraphs++
		case PhaseTerminal:
			if record.Status != jobs.StatusTerminal || intent.AdmissionSource == AdmissionPlan && plan.ConsumedAt == nil {
				return fmt.Errorf("terminal intent links inconsistent job or admission authority")
			}
			terminalGraphs++
		}
	}
	if terminalGraphs > maximumTerminalOperationGraphs {
		return fmt.Errorf("terminal operation graph retention exceeds %d", maximumTerminalOperationGraphs)
	}
	for _, key := range persist.EntryKeys(document, "jobs") {
		record, err := jobs.LoadEntries(document.Entries, strings.TrimPrefix(key, "jobs/"))
		if err != nil {
			return err
		}
		if _, ok := intents[record.ID]; !ok {
			return fmt.Errorf("job %q has no operation intent", record.ID)
		}
	}
	childKeys := persist.EntryKeys(document, "children")
	journalKeys := persist.EntryKeys(document, "journals")
	var installationID string
	if len(childKeys) != 0 || len(journalKeys) != 0 {
		raw, present := document.Entries["installations/current"]
		if !present {
			return fmt.Errorf("child or journal has no installation authority")
		}
		installation, err := domain.DecodeInstallation(raw)
		if err != nil {
			return fmt.Errorf("child or journal installation authority: %w", err)
		}
		installationID = installation.InstallationID
	}
	childrenByJob := map[string][]string{}
	children := map[string]ChildRecord{}
	for _, key := range childKeys {
		var child ChildRecord
		if err := decodeStrict(document.Entries[key], &child); err != nil {
			return err
		}
		intent, ok := intents[child.JobID]
		if !ok {
			return fmt.Errorf("child reservation has no matching operation intent")
		}
		if child.InstallationID != installationID || child.Operation != intent.Operation || child.Target != intent.Target || child.IntentGeneration != intent.IntentGeneration || !child.Deadline.Equal(intent.SafetyBinding.Deadline) {
			return fmt.Errorf("child does not exactly match installation and operation intent authority")
		}
		if (intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected) && child.State != ChildTerminal {
			return fmt.Errorf("terminal intent retains nonterminal child")
		}
		children[child.ID] = child
		childrenByJob[child.JobID] = append(childrenByJob[child.JobID], child.ID)
	}
	for jobID := range childrenByJob {
		sort.Strings(childrenByJob[jobID])
	}
	journalByJob := map[string]string{}
	for _, key := range journalKeys {
		var journal JournalRecord
		if err := decodeStrict(document.Entries[key], &journal); err != nil {
			return err
		}
		if err := validateJournalRecord(journal); err != nil {
			return err
		}
		intent, ok := intents[journal.JobID]
		if !ok {
			return fmt.Errorf("journal has no matching operation intent")
		}
		if _, duplicate := journalByJob[journal.JobID]; duplicate {
			return fmt.Errorf("operation intent has more than one journal authority")
		}
		journalByJob[journal.JobID] = journal.ID
		if journal.InstallationID != installationID || journal.Operation != intent.Operation || journal.Target != intent.Target || journal.Generation != intent.IntentGeneration || journal.SafetyMarkerDigest != intent.JournalSafetyDigest || !reflect.DeepEqual(journal.ChildIDs, childrenByJob[journal.JobID]) {
			return fmt.Errorf("journal installation, operation, target, generation, or child inventory does not match its authorities")
		}
		for _, childID := range journal.ChildIDs {
			child := children[childID]
			if child.ArtifactDigest != journal.ArtifactDigest || !child.Deadline.Equal(journal.Deadline) {
				return fmt.Errorf("journal artifact or deadline does not match exact child %q", childID)
			}
		}
		if (intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected) && journal.Phase != JournalTerminal {
			return fmt.Errorf("terminal intent retains nonterminal journal")
		}
	}
	for jobID, intent := range intents {
		if intent.JournalSafetyDigest != "" && journalByJob[jobID] == "" {
			return fmt.Errorf("operation intent binds missing journal authority")
		}
	}
	for _, key := range persist.EntryKeys(document, "plans") {
		plan, err := plans.LoadEntries(document.Entries, strings.TrimPrefix(key, "plans/"))
		if err != nil {
			return err
		}
		if plan.ReservedAt != nil {
			intent, ok := intents[plan.ReservedByJob]
			if !ok || intent.PlanID != plan.ID {
				return fmt.Errorf("reserved or consumed Plan has no matching operation intent")
			}
		}
	}
	return nil
}

func validateOperationStateTransitions(before, after persist.Document) error {
	if err := validateOperationRetentionTransition(before, after); err != nil {
		return err
	}
	beforeRaw, beforePresent := before.Entries["installations/current"]
	afterRaw, afterPresent := after.Entries["installations/current"]
	if !beforePresent || !afterPresent || string(beforeRaw) == string(afterRaw) {
		return nil
	}
	oldInstallation, err := domain.DecodeInstallation(beforeRaw)
	if err != nil {
		return err
	}
	newInstallation, err := domain.DecodeInstallation(afterRaw)
	if err != nil {
		return err
	}
	oldResources := map[string]domain.AppResource{}
	for _, resource := range oldInstallation.Resources {
		oldResources[resource.ID] = resource
	}
	for _, resource := range newInstallation.Resources {
		oldResource, existed := oldResources[resource.ID]
		if !existed || protectedResourceStateEqual(oldResource, resource) {
			delete(oldResources, resource.ID)
			continue
		}
		if resource.PublicationRecord.UnpublishedGeneration < oldResource.PublicationRecord.UnpublishedGeneration {
			return fmt.Errorf("resource %q unpublished generation regressed", resource.ID)
		}
		if resource.PublicationRecord.State == domain.PublicationUnpublished && oldResource.PublicationRecord.State != domain.PublicationUnpublished && resource.PublicationRecord.UnpublishedGeneration <= oldResource.PublicationRecord.UnpublishedGeneration {
			return fmt.Errorf("resource %q contraction did not allocate a fresh unpublished generation", resource.ID)
		}
		jobID := resource.PublicationRecord.LastJobID
		if jobID == "" {
			return fmt.Errorf("resource %q operation-owned state changed without a durable job binding", resource.ID)
		}
		beforeIntent, err := loadReservationEntries(before.Entries, jobID)
		if err != nil {
			return fmt.Errorf("resource %q has no active before-intent authority: %w", resource.ID, err)
		}
		intent, err := loadReservationEntries(after.Entries, jobID)
		if err != nil {
			return fmt.Errorf("resource %q state intent: %w", resource.ID, err)
		}
		targetMatches := intent.Target == "resource/"+resource.ID || intent.Operation == CloseAll && intent.Target == string(plans.TargetInstallation)
		if intent.Operation == AutomaticReconciliation && strings.HasPrefix(intent.Target, "journal/") {
			journal, err := loadJournalEntries(after.Entries, strings.TrimPrefix(intent.Target, "journal/"))
			if err == nil {
				targetMatches = slices.Contains(journal.ResourceIDs, resource.ID)
			}
		}
		if !targetMatches {
			return fmt.Errorf("resource %q state changed under a mismatched operation target", resource.ID)
		}
		if beforeIntent.Phase != PhaseLocalIntent && beforeIntent.Phase != PhaseReentered || intent.Phase != PhaseTerminal {
			return fmt.Errorf("resource %q state and job result must commit atomically from a locked local phase", resource.ID)
		}
		if !operationCodeMatchesIntent(resource.PublicationRecord.LastOperation, intent.Operation) {
			return fmt.Errorf("resource %q last operation does not match its immutable intent", resource.ID)
		}
		beforeRecord, err := jobs.LoadEntries(before.Entries, jobID)
		if err != nil {
			return err
		}
		record, err := jobs.LoadEntries(after.Entries, jobID)
		if err != nil {
			return err
		}
		if beforeRecord.Status != jobs.StatusRunning || record.Status != jobs.StatusTerminal || string(resource.PublicationRecord.LastOperationResult) != string(record.Result) {
			return fmt.Errorf("resource %q state does not match an atomic running-to-terminal job result", resource.ID)
		}
		if err := validateOperationResourceDelta(oldResource, resource, intent.Operation); err != nil {
			return fmt.Errorf("resource %q: %w", resource.ID, err)
		}
		delete(oldResources, resource.ID)
	}
	if len(oldResources) != 0 {
		return fmt.Errorf("resource state cannot disappear outside its typed deletion operation")
	}
	return nil
}

func validateOperationResourceDelta(before, after domain.AppResource, operation Type) error {
	if before.Lifecycle != after.Lifecycle || !reflect.DeepEqual(before.ManagedProcess, after.ManagedProcess) {
		return fmt.Errorf("operation %q does not own lifecycle or managed-process state", operation)
	}
	switch operation {
	case Publish:
		return nil
	case Unpublish, CloseAll, CertificateExpiry, EdgeOneExpiry, AutomaticReconciliation, StartupContraction, Maintenance:
		if after.PublicationRecord.State != domain.PublicationUnpublished || after.PublicationRecord.UnpublishedGeneration <= before.PublicationRecord.UnpublishedGeneration {
			return fmt.Errorf("contraction operation did not commit unpublished state with a fresh generation")
		}
		return nil
	default:
		return fmt.Errorf("operation %q has no resource-state delta authority", operation)
	}
}

func validateOperationRetentionTransition(before, after persist.Document) error {
	for _, namespace := range []string{"jobs", "children", "journals"} {
		for _, key := range persist.EntryKeys(before, namespace) {
			if _, retained := after.Entries[key]; retained {
				continue
			}
			jobID := strings.TrimPrefix(key, namespace+"/")
			if namespace == "children" {
				var child ChildRecord
				if err := decodeStrict(before.Entries[key], &child); err != nil {
					return err
				}
				jobID = child.JobID
			} else if namespace == "journals" {
				var journal JournalRecord
				if err := decodeStrict(before.Entries[key], &journal); err != nil {
					return err
				}
				jobID = journal.JobID
			}
			if _, intentRetained := after.Entries[reservationKey(jobID)]; intentRetained {
				return fmt.Errorf("operation retention cannot detach %s from its intent graph", namespace)
			}
		}
	}
	type graph struct {
		jobID   string
		endedAt time.Time
	}
	terminalBefore := []graph{}
	deleted := map[string]bool{}
	becomingTerminal := 0
	for _, key := range persist.EntryKeys(before, "intents") {
		jobID := strings.TrimPrefix(key, "intents/")
		intent, err := loadReservationEntries(before.Entries, jobID)
		if err != nil {
			return err
		}
		afterIntent, afterPresent, err := persist.DecodeEntry[Reservation](after, key)
		if err != nil {
			return err
		}
		terminal := intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected
		if terminal {
			record, err := jobs.LoadEntries(before.Entries, jobID)
			if err != nil {
				return err
			}
			if record.EndedAt == nil {
				return fmt.Errorf("terminal retention job authority has no end time")
			}
			terminalBefore = append(terminalBefore, graph{jobID: jobID, endedAt: *record.EndedAt})
			if !afterPresent {
				deleted[jobID] = true
			}
			continue
		}
		if afterPresent && (afterIntent.Phase == PhaseTerminal || afterIntent.Phase == PhaseRejected) {
			becomingTerminal++
		}
	}
	required := len(terminalBefore) + becomingTerminal - maximumTerminalOperationGraphs
	if required < 0 {
		required = 0
	}
	if len(deleted) != required {
		return fmt.Errorf("terminal graph retention deleted %d graphs; exact oldest overflow is %d", len(deleted), required)
	}
	sort.Slice(terminalBefore, func(left, right int) bool {
		if terminalBefore[left].endedAt.Equal(terminalBefore[right].endedAt) {
			return terminalBefore[left].jobID < terminalBefore[right].jobID
		}
		return terminalBefore[left].endedAt.Before(terminalBefore[right].endedAt)
	})
	for index := 0; index < required; index++ {
		if !deleted[terminalBefore[index].jobID] {
			return fmt.Errorf("terminal graph retention did not delete the oldest graph")
		}
	}
	return nil
}

func protectedResourceStateEqual(left, right domain.AppResource) bool {
	return left.Lifecycle == right.Lifecycle && reflect.DeepEqual(left.PublicationRecord, right.PublicationRecord) && reflect.DeepEqual(left.ManagedProcess, right.ManagedProcess)
}

func operationCodeMatchesIntent(code domain.OperationCode, operation Type) bool {
	switch operation {
	case Publish:
		return code == domain.OperationPublish
	case Unpublish, CertificateExpiry, EdgeOneExpiry, AutomaticReconciliation, StartupContraction:
		return code == domain.OperationUnpublish
	case CloseAll:
		return code == domain.OperationCloseAll
	case Maintenance:
		return code == domain.OperationMaintenance
	case BackupEnter:
		return code == domain.OperationBackupEnter
	default:
		return string(code) == string(operation)
	}
}

func validateReservation(value Reservation) error {
	if value.SchemaVersion != "lanpanel.operation.reservation.v1" || value.JobID == "" || !validType(value.Operation) || value.Target == "" || value.CreatedAt.IsZero() || !digest(value.SafetyDigest) || value.JournalSafetyDigest != "" && !exactDigest(value.JournalSafetyDigest) || validateAdmissionSource(value.Operation, value.AdmissionSource, value.PlanID) != nil {
		return fmt.Errorf("operation reservation is invalid")
	}
	if value.Phase != PhaseReserved && value.Phase != PhaseLocalIntent && value.Phase != PhaseRemoteWait && value.Phase != PhaseRejected && value.Phase != PhaseReentered && value.Phase != PhaseTerminal {
		return fmt.Errorf("operation phase is invalid")
	}
	if value.Phase != PhaseReserved && value.Phase != PhaseRejected && value.IntentGeneration == 0 {
		return fmt.Errorf("operation intent generation is missing")
	}
	if value.Phase == PhaseReserved || value.Phase == PhaseRejected {
		if value.Consumption != nil {
			return fmt.Errorf("unconsumed operation has consumption snapshot")
		}
	} else if value.Consumption == nil || value.Consumption.Source != value.AdmissionSource || !digest(value.Consumption.ConfirmationDigest) || !digest(value.Consumption.SafetyDigest) || value.Consumption.ConfirmedAt.IsZero() {
		return fmt.Errorf("operation consumption snapshot is incomplete")
	}
	return nil
}
func reservationKey(jobID string) string { return "intents/" + jobID }
func validType(value Type) bool {
	switch value {
	case Publish, Unpublish, CloseAll, EmergencyCloseAll, CertificateExpiry, EdgeOneExpiry, Maintenance, PackageTransaction, Upgrade, BackupEnter, AutomaticReconciliation, StartupContraction:
		return true
	}
	return false
}

func validateSafetyTargetBinding(request AdmitRequest) error {
	kind, identity, _ := strings.Cut(request.Target, "/")
	switch kind {
	case string(plans.TargetResource):
		if identity == "" || request.SafetyBinding.ResourceID != identity {
			return fmt.Errorf("operation target does not match resource safety authority")
		}
	case string(plans.TargetHeadscale):
		if identity == "" || request.SafetyBinding.ResourceID != "headscale" {
			return fmt.Errorf("Headscale target does not match safety authority")
		}
	case string(plans.TargetInstallation):
		if identity != "" || request.SafetyBinding.ResourceID != "" {
			return fmt.Errorf("installation target has unrelated resource safety authority")
		}
	default:
		if request.Operation != AutomaticReconciliation || kind != "journal" || identity == "" {
			return fmt.Errorf("operation target kind is invalid")
		}
	}
	binding := request.SafetyBinding
	activationBound := binding.PlanID != "" || binding.IntentGeneration != 0 || binding.CandidateDigest != "" || binding.CandidateBundle != ""
	if activationBound {
		planBound := request.Source == AdmissionPlan && binding.PlanID == request.PlanID && exactDigest(binding.CandidateBundle)
		startupBound := request.Operation == StartupContraction && request.Source == AdmissionStartup && (binding.CandidateBundle == "" || exactDigest(binding.CandidateBundle))
		exactCandidate := validIdentityRef(binding.PlanID) && binding.IntentGeneration != 0 && exactDigest(binding.CandidateDigest)
		if !exactCandidate || !planBound && !startupBound {
			return fmt.Errorf("activation safety identity does not match Plan or startup contraction authority")
		}
	}
	return nil
}

func validateAdmissionSource(operation Type, source AdmissionSource, planID string) error {
	switch source {
	case AdmissionPlan:
		if planID == "" {
			return fmt.Errorf("Plan admission requires a Plan identity")
		}
		switch operation {
		case Publish, Unpublish, CloseAll, Maintenance, PackageTransaction, BackupEnter:
		default:
			return fmt.Errorf("operation is not valid for Plan admission")
		}
	case AdmissionTimer:
		if planID != "" || operation != CertificateExpiry && operation != EdgeOneExpiry && operation != AutomaticReconciliation {
			return fmt.Errorf("timer admission is not authorized for operation")
		}
	case AdmissionStartup:
		if planID != "" || operation != AutomaticReconciliation && operation != StartupContraction {
			return fmt.Errorf("startup admission is not authorized for operation")
		}
	default:
		return fmt.Errorf("operation admission source is unsupported")
	}
	return nil
}
func safetyBindingDigest(binding SafetyBinding) (string, error) {
	data, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func planlessAdmissionDigest(reservation Reservation, safetyDigest string) string {
	value := strings.Join([]string{string(reservation.AdmissionSource), string(reservation.Operation), reservation.Target, reservation.JobID, safetyDigest}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func safetyDigest(state safety.State) (string, error) {
	copy := state
	copy.Checksum = ""
	data, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func digest(value string) bool { return len(value) == 71 && strings.HasPrefix(value, "sha256:") }
func exactDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil
}
func validIdentityRef(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}
func planTarget(target plans.Target) string {
	if target.ID == "" {
		return string(target.Kind)
	}
	return string(target.Kind) + "/" + target.ID
}

type HandoffVariant string

const (
	HandoffMaintenance HandoffVariant = "maintenance"
	HandoffUpgrade     HandoffVariant = "upgrade"
	HandoffBackupEnter HandoffVariant = "backup_enter"
)

// FencedHandoff is the sole admission-retaining path. It proves the inventory
// empty, then acquires resource mutation and exposure in order before the
// owning step commits its independent transition fence.
func (admitter *Admitter) FencedHandoff(ctx context.Context, admission *locks.Lease, mutationSet *MutationSet, manager *locks.Manager, variant HandoffVariant, target, exceptJob string, commitFence func(*MutationLease, *locks.Lease) error) error {
	if admission == nil || !admission.Holds(locks.MutationAdmission) || mutationSet == nil || manager == nil || admitter == nil || admitter.safety.LockAuthority() != manager.Authority() || admission.Authority() != manager.Authority() || admitter.normal.LockAuthority() != manager.Authority() || mutationSet.Authority() != manager.Authority() || commitFence == nil {
		return fmt.Errorf("fenced handoff authority is incomplete")
	}
	if variant != HandoffMaintenance && variant != HandoffUpgrade && variant != HandoffBackupEnter {
		return fmt.Errorf("admission-retaining handoff variant is unsupported")
	}
	normal := admitter.normal
	document, err := normal.Read()
	if err != nil {
		return err
	}
	if exceptJob != "" {
		intent, err := loadReservationEntries(document.Entries, exceptJob)
		if err != nil {
			return err
		}
		expected := map[HandoffVariant]Type{HandoffMaintenance: Maintenance, HandoffUpgrade: Upgrade, HandoffBackupEnter: BackupEnter}[variant]
		if intent.Operation != expected || intent.Target != target || intent.Phase != PhaseReserved {
			return fmt.Errorf("fenced handoff exemption does not match variant, target, and reserved intent")
		}
	}
	empty, err := InventoryEmpty(document, exceptJob)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("fenced handoff inventory is not empty")
	}
	mutation, exposure, err := mutationSet.acquireExposureForHandoff(ctx, target, manager)
	if err != nil {
		return err
	}
	document, err = normal.Read()
	if err == nil && exceptJob != "" {
		intent, loadErr := loadReservationEntries(document.Entries, exceptJob)
		expected := map[HandoffVariant]Type{HandoffMaintenance: Maintenance, HandoffUpgrade: Upgrade, HandoffBackupEnter: BackupEnter}[variant]
		if loadErr != nil {
			err = loadErr
		} else if intent.Operation != expected || intent.Target != target || intent.Phase != PhaseReserved {
			err = fmt.Errorf("fenced handoff exemption changed before fence")
		}
	}
	if err == nil {
		empty, err = InventoryEmpty(document, exceptJob)
	}
	if err != nil {
		return errors.Join(err, ReleaseExposure(mutation, exposure))
	}
	if !empty {
		return errors.Join(fmt.Errorf("fenced handoff inventory changed before fence"), ReleaseExposure(mutation, exposure))
	}
	commitErr := commitFence(mutation, exposure)
	return errors.Join(commitErr, ReleaseExposure(mutation, exposure))
}

// ResultBranch fixes one non-interchangeable terminal branch.
type ResultBranch struct {
	Name          string
	Result        jobs.Result
	Postcondition jobs.PostconditionStatus
}
type BranchTable struct{ branches map[string]ResultBranch }

func NewBranchTable(values []ResultBranch) (*BranchTable, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("result branch table is empty")
	}
	result := &BranchTable{branches: map[string]ResultBranch{}}
	seenResults := map[jobs.Result]bool{}
	for _, value := range values {
		if value.Name == "" {
			return nil, fmt.Errorf("result branch name is required")
		}
		if _, duplicate := result.branches[value.Name]; duplicate {
			return nil, fmt.Errorf("result branch name is duplicated")
		}
		if value.Result == jobs.ResultPartial && value.Postcondition != jobs.PostconditionKnown {
			return nil, fmt.Errorf("partial requires known residual postconditions")
		}
		if value.Result == jobs.ResultUnknown && value.Postcondition != jobs.PostconditionUnobserved {
			return nil, fmt.Errorf("unknown requires unobserved critical postconditions")
		}
		if value.Result != jobs.ResultPartial && value.Result != jobs.ResultUnknown && value.Postcondition == jobs.PostconditionUnobserved {
			return nil, fmt.Errorf("only unknown may own unobserved critical state")
		}
		result.branches[value.Name] = value
		seenResults[value.Result] = true
	}
	for _, required := range []jobs.Result{jobs.ResultSucceeded, jobs.ResultFailed, jobs.ResultPartial, jobs.ResultInterrupted, jobs.ResultUnknown} {
		if !seenResults[required] {
			return nil, fmt.Errorf("result branch table omits %q", required)
		}
	}
	return result, nil
}
func (table *BranchTable) Branch(name string) (ResultBranch, bool) {
	value, ok := table.branches[name]
	return value, ok
}

type Registration struct {
	Operation Type
	Owner     string
	Results   *BranchTable
}
type Registry struct{ registrations map[Type]Registration }

func NewRegistry(values []Registration) (*Registry, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("operation registry is empty")
	}
	registry := &Registry{registrations: map[Type]Registration{}}
	for _, value := range values {
		if !validType(value.Operation) || value.Operation == EmergencyCloseAll || value.Owner == "" || value.Results == nil {
			return nil, fmt.Errorf("operation registration is incomplete")
		}
		if _, exists := registry.registrations[value.Operation]; exists {
			return nil, fmt.Errorf("operation %q is registered twice", value.Operation)
		}
		registry.registrations[value.Operation] = value
	}
	return registry, nil
}
func (registry *Registry) Registration(operation Type) (Registration, bool) {
	value, ok := registry.registrations[operation]
	return value, ok
}

func (table *BranchTable) Names() []string {
	result := make([]string, 0, len(table.branches))
	for name := range table.branches {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
