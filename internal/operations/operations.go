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
	"sort"
	"strings"
	"sync"
	"time"
)

type Type string

const (
	Publish           Type = "publish"
	Unpublish         Type = "unpublish"
	CloseAll          Type = "close_all"
	EmergencyCloseAll Type = "emergency_close_all"
	CertificateExpiry Type = "certificate_expiry"
	EdgeOneExpiry     Type = "edgeone_expiry"
	Maintenance       Type = "maintenance"
	Upgrade           Type = "upgrade"
	BackupEnter       Type = "backup_enter"
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
type ConsumptionSnapshot struct {
	Config             plans.DigestBinding `json:"config"`
	Applied            plans.DigestBinding `json:"applied"`
	Evidence           []plans.Evidence    `json:"evidence"`
	ConfirmationDigest string              `json:"confirmation_digest"`
	ConfirmedAt        time.Time           `json:"confirmed_at"`
	SafetyDigest       string              `json:"safety_digest"`
}
type Reservation struct {
	SchemaVersion    string               `json:"schema_version"`
	JobID            string               `json:"job_id"`
	PlanID           string               `json:"plan_id"`
	Operation        Type                 `json:"operation"`
	Target           string               `json:"target"`
	Phase            Phase                `json:"phase"`
	SafetyDigest     string               `json:"safety_digest"`
	SafetyBinding    SafetyBinding        `json:"safety_binding"`
	CreatedAt        time.Time            `json:"created_at"`
	IntentGeneration uint64               `json:"intent_generation,omitempty"`
	Consumption      *ConsumptionSnapshot `json:"consumption,omitempty"`
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
	SchemaVersion string       `json:"schema_version"`
	ID            string       `json:"id"`
	JobID         string       `json:"job_id"`
	Profile       string       `json:"profile"`
	State         ChildState   `json:"state"`
	SubmittedAt   time.Time    `json:"submitted_at"`
	TerminalAt    *time.Time   `json:"terminal_at,omitempty"`
	Outcome       ChildOutcome `json:"outcome,omitempty"`
	ResultDigest  string       `json:"result_digest,omitempty"`
}
type JournalKind string

type JournalPhase string

const (
	JournalNonIngressLocalCommit JournalKind = "non_ingress_local_commit"
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
	ChildIDs           []string     `json:"child_ids"`
	Phase              JournalPhase `json:"phase"`
}

type AdmitRequest struct {
	Operation        Type
	Target           string
	ActorIdentity    string
	PlanID           string
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
		if err := normal.RegisterNamespace("intents", validateIntentEntry, validateIntentTransition); err != nil {
			return nil, err
		}
		if err := normal.RegisterNamespace("children", validateChildEntry, validateChildTransition); err != nil {
			return nil, err
		}
		if err := normal.RegisterNamespace("journals", validateJournalEntry, validateJournalTransition); err != nil {
			return nil, err
		}
		if err := normal.RegisterDocumentValidator(validateLinks); err != nil {
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
	reservation := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, PlanID: request.PlanID, Operation: request.Operation, Target: request.Target, Phase: PhaseReserved, SafetyDigest: digest, SafetyBinding: request.SafetyBinding, CreatedAt: observedNow}
	_, _, err = admitter.normal.Update(ctx, admission, request.ExpectedRevision, func(transaction *persist.Transaction) error {
		if err := jobs.Put(transaction, record); err != nil {
			return err
		}
		if _, err := plans.Reserve(transaction, request.PlanID, record.ID, string(request.Operation), request.Target, request.ActorIdentity, observedNow); err != nil {
			return err
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
			if _, err := plans.Reject(transaction, reservation.PlanID, jobID, observedNow); err != nil {
				return err
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
	if mutation == nil || !mutation.Active() || exposure == nil || !exposure.Holds(locks.Exposure) {
		return Reservation{}, fmt.Errorf("mutation then exposure locks are required")
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
		if request.IntentGeneration == 0 {
			return fmt.Errorf("phase intent generation is required")
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
		reservation.Consumption = &ConsumptionSnapshot{Config: binding.Config, Applied: binding.Applied, Evidence: append([]plans.Evidence(nil), binding.Evidence...), ConfirmationDigest: confirmationDigest, ConfirmedAt: observedNow, SafetyDigest: digest}
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

func markRemoteWait(ctx context.Context, normal *persist.Store, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) (Reservation, error) {
	if mutation == nil || !mutation.Active() || exposure == nil || !exposure.Holds(locks.Exposure) {
		return Reservation{}, fmt.Errorf("mutation then exposure locks are required")
	}
	var result Reservation
	_, _, err := normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		reservation, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if reservation.Phase != PhaseLocalIntent {
			return fmt.Errorf("remote wait requires a local phase intent")
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

func EnterRemoteWait(ctx context.Context, normal *persist.Store, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) (Reservation, error) {
	reservation, err := markRemoteWait(ctx, normal, mutation, exposure, expectedRevision, jobID)
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

func ReserveChild(ctx context.Context, normal *persist.Store, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, child ChildRecord) error {
	return writeChild(ctx, normal, mutation, exposure, expectedRevision, child, true)
}
func TransitionChild(ctx context.Context, normal *persist.Store, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, child ChildRecord) error {
	return writeChild(ctx, normal, mutation, exposure, expectedRevision, child, false)
}
func writeChild(ctx context.Context, normal *persist.Store, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, child ChildRecord, create bool) error {
	if mutation == nil || !mutation.Active() || exposure == nil || !exposure.Holds(locks.Exposure) {
		return fmt.Errorf("child write requires mutation then exposure locks")
	}
	_, _, err := normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, child.JobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered {
			return fmt.Errorf("child may be submitted only from a locked local phase")
		}
		raw, err := persist.EncodeEntry(child)
		if err != nil {
			return err
		}
		if create {
			return transaction.Create("children/"+child.ID, raw)
		}
		return transaction.Replace("children/"+child.ID, raw)
	})
	return err
}
func PutJournal(ctx context.Context, normal *persist.Store, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, journal JournalRecord, create bool) error {
	if mutation == nil || !mutation.Active() || exposure == nil || !exposure.Holds(locks.Exposure) {
		return fmt.Errorf("journal write requires mutation then exposure locks")
	}
	_, _, err := normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, journal.JobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered {
			return fmt.Errorf("journal writes require an active local intent phase")
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
	if mutation == nil || !mutation.Active() || exposure == nil || !exposure.Holds(locks.Exposure) {
		return jobs.Record{}, fmt.Errorf("job completion requires mutation then exposure locks")
	}
	observedNow, timeErr := admitter.trustedNow()
	if timeErr != nil {
		return jobs.Record{}, timeErr
	}
	var completed jobs.Record
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
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

func authorize(operation Type, state safety.State, binding SafetyBinding, consuming bool, now time.Time) error {
	if !validType(operation) || operation == EmergencyCloseAll {
		return fmt.Errorf("operation is unsupported for normal admission")
	}
	if state.MaintenancePending != nil || state.UpgradePending != nil || (state.BackupTransition != nil && state.BackupTransition.Phase != safety.BackupTransitionImported) || state.BackupQuiescence != nil {
		return fmt.Errorf("maintenance, upgrade, or backup marker admits no ordinary job")
	}
	if state.StopFence != nil {
		return fmt.Errorf("stop fence blocks operation admission")
	}
	if operation == CertificateExpiry || operation == EdgeOneExpiry {
		if !validExpiryBinding(operation, state, binding) {
			return fmt.Errorf("expiry contraction authority binding is stale or absent")
		}
	}
	if state.DependencyTransitionPending != nil {
		if (operation == CertificateExpiry || operation == EdgeOneExpiry) && binding.DependencyGeneration == state.DependencyTransitionPending.Generation {
			return nil
		}
		return fmt.Errorf("dependency transition blocks operation admission")
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
func (admitter *Admitter) AuthorizeStateIndependentContraction(operation Type, state safety.State, binding SafetyBinding, unavailable persist.UnavailableProof, exposure *locks.Lease, commitAuthority func() error) error {
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
		return fmt.Errorf("state-independent contraction requires proven normal-store unavailability")
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
	default:
		return fmt.Errorf("operation is not a state-independent contraction exception")
	}
	return commitAuthority()
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
	newValue, err := decodeReservation(after)
	if err != nil {
		return err
	}
	oldPhase, newPhase := oldValue.Phase, newValue.Phase
	oldValue.Phase = ""
	newValue.Phase = ""
	oldGeneration, newGeneration := oldValue.IntentGeneration, newValue.IntentGeneration
	oldConsumption, newConsumption := oldValue.Consumption, newValue.Consumption
	oldValue.IntentGeneration = 0
	newValue.IntentGeneration = 0
	oldValue.Consumption = nil
	newValue.Consumption = nil
	if !reflect.DeepEqual(oldValue, newValue) {
		return fmt.Errorf("immutable operation intent binding was rewritten")
	}
	valid := oldPhase == PhaseReserved && (newPhase == PhaseLocalIntent || newPhase == PhaseRejected) || oldPhase == PhaseLocalIntent && (newPhase == PhaseRemoteWait || newPhase == PhaseTerminal) || oldPhase == PhaseRemoteWait && (newPhase == PhaseReentered || newPhase == PhaseTerminal) || oldPhase == PhaseReentered && (newPhase == PhaseRemoteWait || newPhase == PhaseTerminal)
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
	if value.SchemaVersion != "lanpanel.child.v1" || !validIdentityRef(value.ID) || !validIdentityRef(value.JobID) || !validIdentityRef(value.Profile) || value.SubmittedAt.IsZero() {
		return fmt.Errorf("child reservation is invalid")
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
	} else if value.Kind == JournalAppContraction {
		switch value.Operation {
		case Publish, Unpublish, CloseAll, CertificateExpiry, EdgeOneExpiry:
		default:
			return fmt.Errorf("App contraction journal operation is not allowed")
		}
	} else {
		return fmt.Errorf("operation journal kind is not allowed")
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
		plan, err := plans.LoadEntries(document.Entries, intent.PlanID)
		if err != nil {
			return fmt.Errorf("intent Plan link: %w", err)
		}
		switch intent.Phase {
		case PhaseReserved:
			if record.Status != jobs.StatusReserved || plan.ConsumedAt != nil || plan.ReservedByJob != record.ID {
				return fmt.Errorf("reserved intent links inconsistent job or Plan")
			}
		case PhaseLocalIntent, PhaseRemoteWait, PhaseReentered:
			if record.Status != jobs.StatusRunning || plan.ConsumedAt == nil || plan.ConsumedByJob != record.ID {
				return fmt.Errorf("active intent links inconsistent job or Plan")
			}
		case PhaseRejected:
			if record.Status != jobs.StatusTerminal || plan.RejectedAt == nil || plan.RejectedByJob != record.ID {
				return fmt.Errorf("rejected intent links inconsistent job or Plan")
			}
		case PhaseTerminal:
			if record.Status != jobs.StatusTerminal || plan.ConsumedAt == nil {
				return fmt.Errorf("terminal intent links inconsistent job or Plan")
			}
		}
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
	childrenByJob := map[string][]string{}
	for _, key := range persist.EntryKeys(document, "children") {
		var child ChildRecord
		if err := decodeStrict(document.Entries[key], &child); err != nil {
			return err
		}
		intent, ok := intents[child.JobID]
		if !ok {
			return fmt.Errorf("child reservation has no matching operation intent")
		}
		if (intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected) && child.State != ChildTerminal {
			return fmt.Errorf("terminal intent retains nonterminal child")
		}
		childrenByJob[child.JobID] = append(childrenByJob[child.JobID], child.ID)
	}
	for jobID := range childrenByJob {
		sort.Strings(childrenByJob[jobID])
	}
	journalKeys := persist.EntryKeys(document, "journals")
	var installationID string
	if len(journalKeys) != 0 {
		raw, present := document.Entries["installations/current"]
		if !present {
			return fmt.Errorf("journal has no installation authority")
		}
		installation, err := domain.DecodeInstallation(raw)
		if err != nil {
			return fmt.Errorf("journal installation authority: %w", err)
		}
		installationID = installation.InstallationID
	}
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
		if journal.InstallationID != installationID || journal.Operation != intent.Operation || journal.Target != intent.Target || journal.Generation != intent.IntentGeneration || !reflect.DeepEqual(journal.ChildIDs, childrenByJob[journal.JobID]) {
			return fmt.Errorf("journal installation, operation, target, generation, or child inventory does not match its authorities")
		}
		if (intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected) && journal.Phase != JournalTerminal {
			return fmt.Errorf("terminal intent retains nonterminal journal")
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

func validateReservation(value Reservation) error {
	if value.SchemaVersion != "lanpanel.operation.reservation.v1" || value.JobID == "" || value.PlanID == "" || !validType(value.Operation) || value.Target == "" || value.CreatedAt.IsZero() || !digest(value.SafetyDigest) {
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
	} else if value.Consumption == nil || !digest(value.Consumption.ConfirmationDigest) || !digest(value.Consumption.SafetyDigest) || value.Consumption.ConfirmedAt.IsZero() {
		return fmt.Errorf("operation consumption snapshot is incomplete")
	}
	return nil
}
func reservationKey(jobID string) string { return "intents/" + jobID }
func validType(value Type) bool {
	switch value {
	case Publish, Unpublish, CloseAll, EmergencyCloseAll, CertificateExpiry, EdgeOneExpiry, Maintenance, Upgrade, BackupEnter:
		return true
	}
	return false
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
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, target, manager)
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
