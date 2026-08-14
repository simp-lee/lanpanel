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
	"lanpanel/internal/preflight"
	"lanpanel/internal/publication"
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
	Publish                  Type = "publish"
	Unpublish                Type = "unpublish"
	CloseAll                 Type = "close_all"
	EmergencyCloseAll        Type = "emergency_close_all"
	CertificateExpiry        Type = "certificate_expiry"
	CertificateRenew         Type = "certificate_renew"
	ManagedBasicCreate       Type = "managed_basic_create"
	ManagedBasicRotate       Type = "managed_basic_rotate"
	ManagedBasicDelete       Type = "managed_basic_delete"
	StaticRootRegister       Type = "static_root_register"
	ExternalHTPasswdRegister Type = "external_htpasswd_register"
	EdgeOneExpiry            Type = "edgeone_expiry"
	Maintenance              Type = "maintenance"
	PackageTransaction       Type = "package_transaction"
	AdminTokenRotate         Type = "admin_token_rotate"
	Upgrade                  Type = "upgrade"
	BackupEnter              Type = "backup_enter"
	AutomaticReconciliation  Type = "automatic_exact_journal_reconciliation"
	StartupContraction       Type = "startup_activation_contraction"
	ResourceCreate           Type = "resource_create"
	ResourceUpdate           Type = "resource_update"
	ProcessStart             Type = "process_start"
	ProcessStop              Type = "process_stop"
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
	ChallengeMethod      string    `json:"challenge_method,omitempty"`
	CertificateIdentity  string    `json:"certificate_identity,omitempty"`
}
type AdmissionSource string

const (
	AdmissionPlan    AdmissionSource = "plan"
	AdmissionTimer   AdmissionSource = "timer"
	AdmissionStartup AdmissionSource = "startup"
	AdmissionUI      AdmissionSource = "authenticated_ui"
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
type CertificatePublicationHandoff struct {
	PlanID                string `json:"plan_id"`
	Generation            uint64 `json:"generation"`
	SANIdentity           string `json:"san_identity"`
	ACMEBinding           string `json:"acme_binding"`
	CertificateID         string `json:"certificate_id"`
	Fingerprint           string `json:"fingerprint"`
	ChallengeSafetyDigest string `json:"challenge_safety_digest"`
}
type Reservation struct {
	SchemaVersion       string                         `json:"schema_version"`
	JobID               string                         `json:"job_id"`
	PlanID              string                         `json:"plan_id,omitempty"`
	OperationBinding    string                         `json:"operation_binding,omitempty"`
	CertificateHandoff  *CertificatePublicationHandoff `json:"certificate_handoff,omitempty"`
	AdmissionSource     AdmissionSource                `json:"admission_source"`
	Operation           Type                           `json:"operation"`
	Target              string                         `json:"target"`
	Phase               Phase                          `json:"phase"`
	SafetyDigest        string                         `json:"safety_digest"`
	JournalSafetyDigest string                         `json:"journal_safety_digest,omitempty"`
	ContractionDigest   string                         `json:"contraction_digest,omitempty"`
	SecretFingerprint   string                         `json:"secret_fingerprint,omitempty"`
	SecretCommitted     bool                           `json:"secret_committed,omitempty"`
	SafetyBinding       SafetyBinding                  `json:"safety_binding"`
	CreatedAt           time.Time                      `json:"created_at"`
	IntentGeneration    uint64                         `json:"intent_generation,omitempty"`
	Consumption         *ConsumptionSnapshot           `json:"consumption,omitempty"`
}

type ContractionCommit struct {
	ClosureAuthorityDigest string
	UnpublishedGenerations map[string]uint64
}

type ResourceCreateCommit struct {
	Resource domain.AppResource
}

type ProcessStateCommit struct {
	ResourceID  string
	Requested   domain.ProcessRequestedState
	Applied     *domain.ProcessBundle
	Observation domain.RuntimeObservation
}
type PublicationBeginCommit struct {
	ResourceID string
	Intent     domain.ActivationIntent
}
type PublicationTerminalCommit struct {
	ResourceID string
	Bundle     domain.PublicationBundle
	Runtime    domain.RuntimeObservation
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
	JournalAppActivation         JournalKind = "app_activation"
	JournalCertificateActivation JournalKind = "certificate_activation"

	JournalPrepared JournalPhase = "prepared"
	JournalActive   JournalPhase = "active"
	JournalTerminal JournalPhase = "terminal"
)

type CertificateJournalIdentity struct {
	CertificateID        string `json:"certificate_id"`
	PriorGeneration      uint64 `json:"prior_generation,omitempty"`
	CandidateGeneration  uint64 `json:"candidate_generation"`
	PriorPointer         string `json:"prior_pointer,omitempty"`
	CandidatePointer     string `json:"candidate_pointer"`
	PriorFingerprint     string `json:"prior_fingerprint,omitempty"`
	CandidateFingerprint string `json:"candidate_fingerprint,omitempty"`
	StageUID             uint32 `json:"stage_uid,omitempty"`
	StageGID             uint32 `json:"stage_gid,omitempty"`
}
type JournalRecord struct {
	SchemaVersion      string                      `json:"schema_version"`
	ID                 string                      `json:"id"`
	JobID              string                      `json:"job_id"`
	Kind               JournalKind                 `json:"kind"`
	Operation          Type                        `json:"operation"`
	InstallationID     string                      `json:"installation_id"`
	Target             string                      `json:"target"`
	Generation         uint64                      `json:"generation"`
	Deadline           time.Time                   `json:"deadline"`
	ArtifactDigest     string                      `json:"artifact_digest"`
	SafetyMarkerDigest string                      `json:"safety_marker_digest"`
	ResourceIDs        []string                    `json:"resource_ids,omitempty"`
	ChildIDs           []string                    `json:"child_ids"`
	Phase              JournalPhase                `json:"phase"`
	Certificate        *CertificateJournalIdentity `json:"certificate,omitempty"`
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
	JobID                string
	ExpectedRevision     uint64
	IntentGeneration     uint64
	ConfirmationProof    string
	ContractionRequest   *preflight.ContractionRequest
	ContractionPreflight *preflight.Result
}
type SafetyReader interface {
	Read() (safety.State, error)
	LockAuthority() locks.Authority
}
type DegradedContractionSafetyReader interface {
	ReadForContraction(*locks.Lease) (safety.State, error)
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
		if err := Register(normal); err != nil {
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

func Register(normal *persist.Store) error {
	if normal == nil {
		return fmt.Errorf("normal operation store is nil")
	}
	if err := plans.Register(normal); err != nil {
		return err
	}
	if err := jobs.Register(normal); err != nil {
		return err
	}
	if !normal.NamespaceRegistered("intents") {
		if err := normal.RegisterCanonicalNamespace("intents", "operations.intents.v1", validateIntentEntry, validateIntentTransition); err != nil {
			return err
		}
	}
	if !normal.NamespaceRegistered("children") {
		if err := normal.RegisterCanonicalNamespace("children", "operations.children.v1", validateChildEntry, validateChildTransition); err != nil {
			return err
		}
	}
	if !normal.NamespaceRegistered("journals") {
		if err := normal.RegisterCanonicalNamespace("journals", "operations.journals.v1", validateJournalEntry, validateJournalTransition); err != nil {
			return err
		}
	}
	if !normal.SchemaSealed() {
		if err := normal.RegisterCanonicalDocumentValidator("operations.links.v1", validateLinks); err != nil {
			return err
		}
		if err := normal.RegisterCanonicalDocumentTransitionValidator("operations.resource_transitions.v1", validateOperationStateTransitions); err != nil {
			return err
		}
		return normal.SealSchema()
	}
	return nil
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
				if (existing.Target == request.Target || existing.SafetyBinding.ResourceID != "" && existing.SafetyBinding.ResourceID == request.SafetyBinding.ResourceID) && !isContraction(existing.Operation) && existing.Phase != PhaseTerminal && existing.Phase != PhaseRejected {
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

func (admitter *Admitter) RejectReservation(ctx context.Context, admission *locks.Lease, expectedRevision uint64, jobID, code string) error {
	if admission == nil || !admission.Holds(locks.MutationAdmission) {
		return fmt.Errorf("reservation rejection requires the mutation-admission lock")
	}
	return admitter.rejectReservation(ctx, admission, expectedRevision, jobID, code)
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
	if err := requirePreflightEvidence(reservationView.Operation, reservationView.Target, binding.Evidence, observedNow); err != nil {
		return reject("preflight_rejected", err)
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
		if !planOperationMatches(reservation.Operation, binding.Operation) || reservation.Target != planTarget(binding.Target) {
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

// BeginUI starts a previously admitted authenticated non-Plan UI mutation.
// It is limited to S12 resource/process operations and commits the same durable
// local intent boundary before host or installation-state mutation.
func (admitter *Admitter) BeginUI(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, request ConsumeRequest) (Reservation, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return Reservation{}, fmt.Errorf("authoritative mutation then exposure locks are required")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return Reservation{}, err
	}
	state, err := admitter.safety.Read()
	if err != nil {
		return Reservation{}, err
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
		if reservation.AdmissionSource != AdmissionUI || reservation.Phase != PhaseReserved || mutation.Target() != reservation.Target {
			return fmt.Errorf("operation reservation is not authenticated-UI or target-matched")
		}
		if request.IntentGeneration != request.ExpectedRevision+1 || reservation.SafetyDigest != digest {
			return fmt.Errorf("authenticated UI phase generation or safety authority changed")
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
		reservation.Consumption = &ConsumptionSnapshot{Source: AdmissionUI, ConfirmationDigest: planlessAdmissionDigest(reservation, digest), ConfirmedAt: observedNow, SafetyDigest: digest}
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
	document, err := admitter.normal.Read()
	if err != nil {
		return Reservation{}, err
	}
	reservationView, err := loadReservationEntries(document.Entries, request.JobID)
	if err != nil {
		return Reservation{}, err
	}
	if requiresContractionPreflight(reservationView.Operation) {
		if request.ContractionRequest == nil || request.ContractionPreflight == nil || request.ContractionRequest.Kind != contractionKind(reservationView.Operation) || request.ContractionRequest.Target != reservationView.Target || request.ContractionRequest.Generation != contractionGeneration(reservationView) {
			return reject("preflight_rejected", fmt.Errorf("planless contraction requires exact typed closure preflight"))
		}
		if err := preflight.RequireContractionResultForRequest(*request.ContractionPreflight, *request.ContractionRequest, observedNow); err != nil {
			return reject("preflight_rejected", err)
		}
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
		if reservation.Phase != PhaseLocalIntent || (reservation.AdmissionSource != AdmissionPlan && (reservation.AdmissionSource != AdmissionTimer || reservation.Operation != CertificateRenew)) {
			return fmt.Errorf("remote wait requires Plan issuance or timer renewal authority")
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
	if intent.Consumption == nil || currentDigest != intent.Consumption.SafetyDigest && !exactCertificateChallenge(state, intent.SafetyBinding) && !exactCertificatePublicationAuthority(state, intent) {
		return fail(fmt.Errorf("contraction or safety transition preempted remote operation"))
	}
	if err := authorize(intent.Operation, state, intent.SafetyBinding, true, observedNow); err != nil && !exactCertificatePublicationAuthority(state, intent) {
		return fail(err)
	}
	if intent.AdmissionSource == AdmissionPlan {
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
		snapshot := plans.Binding{Operation: binding.Operation, Target: binding.Target, ActorIdentity: record.ActorIdentity, Config: intent.Consumption.Config, Applied: intent.Consumption.Applied, Evidence: intent.Consumption.Evidence}
		if !plans.SameBindingIdentity(binding, snapshot) {
			return fail(fmt.Errorf("Plan-derived binding changed during remote wait"))
		}
	} else if intent.AdmissionSource != AdmissionTimer || intent.Operation != CertificateRenew {
		return fail(fmt.Errorf("remote wait admission source invalid"))
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
func (admitter *Admitter) BindOperationIdentity(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, binding string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(binding) {
		return fmt.Errorf("operation identity binding requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent || intent.OperationBinding != "" {
			return fmt.Errorf("operation identity already bound or wrong phase")
		}
		intent.OperationBinding = binding
		raw, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		return transaction.Replace(reservationKey(jobID), raw)
	})
	return err
}

func (admitter *Admitter) BindSecretFingerprint(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, fingerprint string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(fingerprint) {
		return fmt.Errorf("secret fingerprint binding requires exact authority")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return err
	}
	intentView, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return err
	}
	if mutation.Target() != intentView.Target || intentView.Operation != AdminTokenRotate || intentView.Phase != PhaseLocalIntent || intentView.SecretFingerprint != "" {
		return fmt.Errorf("secret fingerprint intent is invalid")
	}
	if err := admitter.validateFreshAuthority(document, intentView); err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != AdminTokenRotate || intent.Phase != PhaseLocalIntent || intent.SecretFingerprint != "" {
			return fmt.Errorf("secret fingerprint is already bound or intent changed")
		}
		intent.SecretFingerprint = fingerprint
		raw, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		return transaction.Replace(reservationKey(jobID), raw)
	})
	return err
}

func (admitter *Admitter) MarkSecretCommitted(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, fingerprint string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(fingerprint) {
		return fmt.Errorf("secret commit marker requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != AdminTokenRotate || intent.Phase != PhaseLocalIntent || intent.SecretFingerprint != fingerprint || intent.SecretCommitted {
			return fmt.Errorf("secret commit marker does not match immutable intent")
		}
		intent.SecretCommitted = true
		raw, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		return transaction.Replace(reservationKey(jobID), raw)
	})
	return err
}

type PendingSecretIntent struct {
	JobID, PlanID, Target, Fingerprint string
	Phase                              Phase
	Committed                          bool
}

func FindPendingSecretIntent(document persist.Document, operation Type, target string) (PendingSecretIntent, bool, error) {
	var result PendingSecretIntent
	found := false
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return PendingSecretIntent{}, false, err
		}
		if intent.Operation != operation || intent.Target != target || intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected {
			continue
		}
		if found {
			return PendingSecretIntent{}, false, fmt.Errorf("multiple pending secret intents")
		}
		result = PendingSecretIntent{JobID: intent.JobID, PlanID: intent.PlanID, Target: intent.Target, Fingerprint: intent.SecretFingerprint, Phase: intent.Phase, Committed: intent.SecretCommitted}
		found = true
	}
	return result, found, nil
}

func certificateDeadlineAfter(candidate, prior string) bool {
	candidateTime, candidateErr := time.Parse(time.RFC3339, candidate)
	priorTime, priorErr := time.Parse(time.RFC3339, prior)
	return candidateErr == nil && priorErr == nil && candidateTime.After(priorTime)
}
func (admitter *Admitter) CommitManagedBasicCreate(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, credential domain.Credential) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || credential.Kind != "managed_basic" || !exactDigest(credential.Fingerprint) {
		return fmt.Errorf("managed Basic create requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ManagedBasicCreate || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+credential.OwnerResourceID || mutation.Target() != intent.Target || intent.SafetyBinding.ResourceID != credential.OwnerResourceID {
			return fmt.Errorf("managed Basic create intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		for _, current := range installation.Credentials {
			if current.ID == credential.ID {
				return fmt.Errorf("managed Basic credential ID collision")
			}
		}
		found := false
		for _, resource := range installation.Resources {
			if resource.ID == credential.OwnerResourceID {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("managed Basic owner resource missing")
		}
		installation.Credentials = append(installation.Credentials, credential)
		slices.SortFunc(installation.Credentials, func(a, b domain.Credential) int { return strings.Compare(a.ID, b.ID) })
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitManagedBasicFingerprint(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, credentialID, username, path, fingerprint string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(fingerprint) {
		return fmt.Errorf("managed Basic commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ManagedBasicRotate || intent.Phase != PhaseLocalIntent || intent.Target != "credential/"+credentialID || mutation.Target() != intent.Target {
			return fmt.Errorf("managed Basic intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Credentials {
			credential := &installation.Credentials[index]
			if credential.ID != credentialID {
				continue
			}
			if credential.Kind != "managed_basic" || credential.Username != username || credential.ManagedPath != path {
				return fmt.Errorf("managed Basic credential identity changed")
			}
			credential.Fingerprint = fingerprint
			found = true
		}
		if !found {
			return fmt.Errorf("managed Basic credential missing")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitManagedBasicDelete(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, credentialID string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("managed Basic delete requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ManagedBasicDelete || intent.Phase != PhaseLocalIntent || intent.Target != "credential/"+credentialID || mutation.Target() != intent.Target {
			return fmt.Errorf("managed Basic delete intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		for _, resource := range installation.Resources {
			if credentialReferenced(resource, credentialID) {
				return fmt.Errorf("active resource reference blocks credential delete")
			}
		}
		kept := installation.Credentials[:0]
		found := false
		for _, credential := range installation.Credentials {
			if credential.ID == credentialID {
				if credential.Kind != "managed_basic" {
					return fmt.Errorf("credential is not managed Basic")
				}
				found = true
				continue
			}
			kept = append(kept, credential)
		}
		if !found {
			return fmt.Errorf("managed Basic credential missing")
		}
		installation.Credentials = kept
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func operationNonPublicationCredentials(resource domain.AppResource) []string {
	values := append([]string(nil), resource.CredentialIDs...)
	if resource.Publication.DomainHTTPS != nil && resource.Publication.DomainHTTPS.CredentialID != "" {
		values = slices.DeleteFunc(values, func(value string) bool { return value == resource.Publication.DomainHTTPS.CredentialID })
	}
	return values
}
func credentialReferenced(resource domain.AppResource, credentialID string) bool {
	if slices.Contains(resource.CredentialIDs, credentialID) || resource.Publication.DomainHTTPS != nil && resource.Publication.DomainHTTPS.CredentialID == credentialID {
		return true
	}
	bundles := []*domain.PublicationBundle{resource.PublicationRecord.LastAppliedBundle}
	if intent := resource.PublicationRecord.ActivationIntent; intent != nil {
		bundles = append(bundles, &intent.Candidate, intent.Prior)
	}
	for _, bundle := range bundles {
		if bundle != nil && slices.Contains(bundle.CredentialIDs, credentialID) {
			return true
		}
	}
	return false
}

func (admitter *Admitter) CommitExternalHTPasswd(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, revision uint64, jobID, resourceID string, credential domain.Credential) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || credential.Kind != "external_htpasswd" || credential.OwnerResourceID != resourceID || !exactDigest(credential.Fingerprint) {
		return fmt.Errorf("external htpasswd commit authority invalid")
	}
	encoded, _ := json.Marshal(credential)
	sum := sha256.Sum256(encoded)
	binding := "sha256:" + hex.EncodeToString(sum[:])
	_, _, err := admitter.normal.Update(ctx, exposure, revision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ExternalHTPasswdRegister || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+resourceID || mutation.Target() != intent.Target || intent.SafetyBinding.ResourceID != resourceID || intent.SafetyBinding.CandidateDigest != credential.Fingerprint || intent.SafetyBinding.CandidateBundle != binding {
			return fmt.Errorf("external htpasswd intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		ownerFound := false
		for _, resource := range installation.Resources {
			ownerFound = ownerFound || resource.ID == resourceID
		}
		if !ownerFound {
			return fmt.Errorf("external htpasswd owner resource missing")
		}
		for _, current := range installation.Credentials {
			if current.ID == credential.ID || current.ExternalPath == credential.ExternalPath {
				return fmt.Errorf("external htpasswd identity conflicts")
			}
		}
		installation.Credentials = append(installation.Credentials, credential)
		slices.SortFunc(installation.Credentials, func(a, b domain.Credential) int { return strings.Compare(a.ID, b.ID) })
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitStaticRoot(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string, root domain.StaticContentRoot) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(root.Fingerprint) {
		return fmt.Errorf("static root commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		rootRaw, _ := json.Marshal(root)
		rootSum := sha256.Sum256(rootRaw)
		rootDigest := "sha256:" + hex.EncodeToString(rootSum[:])
		if intent.Operation != StaticRootRegister || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+resourceID || mutation.Target() != intent.Target || intent.SafetyBinding.ResourceID != resourceID || intent.SafetyBinding.CandidateDigest != root.Fingerprint || intent.SafetyBinding.CandidateBundle != rootDigest {
			return fmt.Errorf("static root intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		ownerFound := false
		for _, resource := range installation.Resources {
			ownerFound = ownerFound || resource.ID == resourceID
		}
		if !ownerFound {
			return fmt.Errorf("static root owner resource missing")
		}
		for _, current := range installation.StaticRoots {
			if current.ID == root.ID || current.Path == root.Path {
				return fmt.Errorf("static root identity conflicts")
			}
		}
		installation.StaticRoots = append(installation.StaticRoots, root)
		slices.SortFunc(installation.StaticRoots, func(a, b domain.StaticContentRoot) int { return strings.Compare(a.ID, b.ID) })
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) TerminalizeManagedBasicChildClosure(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, childID, closureDigest string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(closureDigest) {
		return fmt.Errorf("managed Basic child closure authority invalid")
	}
	terminal, err := admitter.trustedNow()
	if err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent || (intent.Operation != ManagedBasicCreate && intent.Operation != ManagedBasicRotate) || mutation.Target() != intent.Target {
			return fmt.Errorf("managed Basic child intent changed")
		}
		raw, present := transaction.Get("children/" + childID)
		if !present {
			return fmt.Errorf("managed Basic child missing")
		}
		var child ChildRecord
		if decodeStrict(raw, &child) != nil || child.JobID != jobID || child.Profile != "htpasswd" || child.State == ChildTerminal {
			return fmt.Errorf("managed Basic child closure identity changed")
		}
		child.State = ChildTerminal
		child.TerminalAt = &terminal
		child.Outcome = ChildUnknown
		child.ResultDigest = closureDigest
		raw, err = persist.EncodeEntry(child)
		if err != nil {
			return err
		}
		return transaction.Replace("children/"+childID, raw)
	})
	return err
}

func (admitter *Admitter) TerminalizeManagedBasicInterrupted(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, paths []string, condition jobs.Postcondition) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || condition.Status != jobs.PostconditionKnown {
		return jobs.Record{}, fmt.Errorf("managed Basic recovery terminal authority invalid")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent || (intent.Operation != ManagedBasicCreate && intent.Operation != ManagedBasicRotate && intent.Operation != ManagedBasicDelete) || mutation.Target() != intent.Target {
			return fmt.Errorf("managed Basic recovery intent changed")
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, ModifiedPaths: paths, Postconditions: []jobs.Postcondition{condition}, ErrorCode: "managed_basic_interrupted"}, observed)
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

func (admitter *Admitter) CommitCertificateRenewal(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string, prior, candidate domain.CertificateBundleIdentity) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("certificate renewal commit requires operation locks")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != CertificateRenew || intent.Target != "resource/"+resourceID || intent.Phase != PhaseReentered {
			return fmt.Errorf("certificate renewal intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != resourceID {
				continue
			}
			if resource.PublicationRecord.State != domain.PublicationPublished || resource.PublicationRecord.LastAppliedBundle == nil || resource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil || !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate, prior) {
				return fmt.Errorf("applied certificate changed before renewal commit")
			}
			if candidate.Generation != prior.Generation+1 || candidate.BindingIdentity != prior.BindingIdentity || candidate.SANIdentity != prior.SANIdentity || candidate.Authority == nil || prior.Authority == nil || !reflect.DeepEqual(candidate.Authority, prior.Authority) || !certificateDeadlineAfter(candidate.NotAfter, prior.NotAfter) {
				return fmt.Errorf("renewed certificate identity invalid")
			}
			resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate = candidate
			resource.PublicationRecord.LastJobID = jobID
			resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: time.Now().UTC().Format(time.RFC3339), Reason: "certificate_renewed_and_served"}
			found = true
		}
		if !found {
			return fmt.Errorf("certificate renewal resource missing")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}
func (admitter *Admitter) TerminalizeJournalLessCertificate(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, closureIdentity string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(closureIdentity) {
		return jobs.Record{}, fmt.Errorf("journal-less certificate recovery requires exact authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if (intent.Operation != Publish && intent.Operation != CertificateRenew) || intent.Phase != PhaseLocalIntent || intent.JournalSafetyDigest != "" || intent.SafetyBinding.CertificateIdentity == "" || intent.SafetyBinding.ChallengeMethod == "" {
			return fmt.Errorf("journal-less certificate intent mismatched")
		}
		for _, key := range transaction.Keys("journals") {
			raw, _ := transaction.Get(key)
			var journal JournalRecord
			if err := decodeStrict(raw, &journal); err != nil {
				return err
			}
			if journal.JobID == jobID {
				return fmt.Errorf("journal-less certificate unexpectedly has journal")
			}
		}
		for _, key := range transaction.Keys("children") {
			raw, _ := transaction.Get(key)
			var child ChildRecord
			if err := decodeStrict(raw, &child); err != nil {
				return err
			}
			if child.JobID == jobID {
				return fmt.Errorf("journal-less certificate unexpectedly has child")
			}
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil || record.Status != jobs.StatusRunning {
			return fmt.Errorf("journal-less certificate job mismatched")
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "certificate_child_never_started", Status: jobs.PostconditionKnown, Identity: closureIdentity}}, ErrorCode: "certificate_executor_interrupted"}, observed)
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

func (admitter *Admitter) TerminalizeContractedCertificate(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, pending safety.ChallengePending, closureIdentity string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(closureIdentity) {
		return jobs.Record{}, fmt.Errorf("certificate reconciliation requires exact closure authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		identityMatches := (intent.Operation == Publish || intent.Operation == CertificateRenew) && intent.Target == "resource/"+intent.SafetyBinding.ResourceID && intent.SafetyBinding.PlanID == pending.PlanID && intent.SafetyBinding.IntentGeneration == pending.Generation && intent.SafetyBinding.CandidateDigest == pending.SANIdentity && intent.SafetyBinding.CandidateBundle == pending.ACMEBinding
		if !identityMatches {
			return fmt.Errorf("certificate reconciliation intent mismatched")
		}
		if intent.Phase == PhaseTerminal {
			record, err := jobs.Load(transaction, jobID)
			if err != nil || record.Status != jobs.StatusTerminal || record.Result != jobs.ResultInterrupted {
				return fmt.Errorf("certificate reconciliation terminal result mismatched")
			}
			for _, key := range transaction.Keys("journals") {
				raw, _ := transaction.Get(key)
				var journal JournalRecord
				if decodeStrict(raw, &journal) != nil {
					return fmt.Errorf("certificate reconciliation journal invalid")
				}
				if journal.JobID == jobID && (journal.Kind != JournalCertificateActivation || journal.Phase != JournalTerminal) {
					return fmt.Errorf("certificate reconciliation terminal journal mismatched")
				}
			}
			for _, key := range transaction.Keys("children") {
				raw, _ := transaction.Get(key)
				var child ChildRecord
				if decodeStrict(raw, &child) != nil {
					return fmt.Errorf("certificate reconciliation child invalid")
				}
				if child.JobID == jobID && child.State != ChildTerminal {
					return fmt.Errorf("certificate reconciliation child nonterminal")
				}
			}
			completed = record
			return nil
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseRemoteWait && intent.Phase != PhaseReentered {
			return fmt.Errorf("certificate reconciliation phase mismatched")
		}
		for _, key := range transaction.Keys("children") {
			raw, _ := transaction.Get(key)
			var child ChildRecord
			if err := decodeStrict(raw, &child); err != nil {
				return err
			}
			if child.JobID != jobID || child.State == ChildTerminal {
				continue
			}
			child.State = ChildTerminal
			child.Outcome = ChildUnknown
			child.TerminalAt = &observed
			child.ResultDigest = closureIdentity
			encoded, err := persist.EncodeEntry(child)
			if err != nil {
				return err
			}
			if err := transaction.Replace(key, encoded); err != nil {
				return err
			}
		}
		journalFound := false
		for _, key := range transaction.Keys("journals") {
			raw, _ := transaction.Get(key)
			var journal JournalRecord
			if err := decodeStrict(raw, &journal); err != nil {
				return err
			}
			if journal.JobID != jobID {
				continue
			}
			if journal.Kind != JournalCertificateActivation {
				return fmt.Errorf("certificate reconciliation journal kind mismatched")
			}
			if journal.Phase != JournalTerminal {
				journal.Phase = JournalTerminal
				encoded, encodeErr := persist.EncodeEntry(journal)
				if encodeErr != nil {
					return encodeErr
				}
				if err := transaction.Replace(key, encoded); err != nil {
					return err
				}
			}
			journalFound = true
		}
		if !journalFound {
			return fmt.Errorf("certificate reconciliation journal missing")
		}
		intent.Phase = PhaseTerminal
		encodedIntent, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), encodedIntent); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "certificate_provider_result", Status: jobs.PostconditionUnobserved, Identity: closureIdentity}}, ErrorCode: "certificate_executor_interrupted"}, observed)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		completed = record
		return nil
	})
	return completed, err
}
func (admitter *Admitter) OperationIntent(jobID string) (Reservation, error) {
	if admitter == nil {
		return Reservation{}, fmt.Errorf("operation admitter missing")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return Reservation{}, err
	}
	return loadReservationEntries(document.Entries, jobID)
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

func HasPendingContraction(document persist.Document) (bool, error) {
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return false, err
		}
		if isContraction(intent.Operation) && (intent.Phase == PhaseLocalIntent || intent.Phase == PhaseReentered || intent.Phase == PhaseRemoteWait) {
			return true, nil
		}
	}
	return false, nil
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

// CommitContractionState atomically makes every affected App sticky-unpublished
// while leaving the job running. Runtime closure happens only after this
// durable boundary, so restart/reconciliation cannot infer or reopen prior
// ingress from normal state.
func (admitter *Admitter) CommitCertificatePublicationBegin(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit PublicationBeginCommit, journal JournalRecord) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.ResourceID == "" {
		return fmt.Errorf("certificate publication handoff requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != Publish || intent.Phase != PhaseReentered || intent.CertificateHandoff != nil || intent.OperationBinding == "" || intent.SafetyBinding.ResourceID != commit.ResourceID || mutation.Target() != intent.Target || commit.Intent.JobID != jobID || commit.Intent.PlanID != intent.PlanID || commit.Intent.Generation != intent.SafetyBinding.IntentGeneration || commit.Intent.Candidate.Generation != commit.Intent.Generation || commit.Intent.Candidate.ConfigDigest != intent.Consumption.Config.Digest {
			return fmt.Errorf("certificate publication handoff intent mismatched")
		}
		bundle := commit.Intent.Candidate
		if bundle.DomainHTTPS == nil || bundle.DomainHTTPS.Certificate.Authority == nil || bundle.DomainHTTPS.Certificate.Authority.CertificateID == "" || bundle.DomainHTTPS.Certificate.BindingIdentity != intent.SafetyBinding.CandidateBundle || bundle.DomainHTTPS.Certificate.SANIdentity != intent.SafetyBinding.CandidateDigest {
			return fmt.Errorf("certificate publication candidate mismatched challenge")
		}
		bundleDigest, err := publication.BundleDigest(bundle)
		if err != nil {
			return err
		}
		if journal.ID != "activation-"+jobID || journal.JobID != jobID || journal.Kind != JournalAppActivation || journal.Operation != Publish || journal.InstallationID == "" || journal.Target != intent.Target || journal.Generation != intent.IntentGeneration || journal.ArtifactDigest != bundleDigest || journal.SafetyMarkerDigest != "" || len(journal.ResourceIDs) != 1 || journal.ResourceIDs[0] != commit.ResourceID || len(journal.ChildIDs) != 0 || journal.Phase != JournalPrepared {
			return fmt.Errorf("certificate publication journal invalid")
		}
		certificateKey := ""
		var certificateJournal JournalRecord
		for _, key := range transaction.Keys("journals") {
			raw, _ := transaction.Get(key)
			var current JournalRecord
			if err := decodeStrict(raw, &current); err != nil {
				return err
			}
			if current.JobID == jobID && current.Kind == JournalCertificateActivation {
				if certificateKey != "" {
					return fmt.Errorf("certificate publication has multiple certificate journals")
				}
				certificateKey = key
				certificateJournal = current
			}
		}
		certificate := certificateJournal.Certificate
		if certificateKey == "" || certificateJournal.Phase != JournalActive || certificate == nil || certificate.CertificateID != bundle.DomainHTTPS.Certificate.Authority.CertificateID || certificate.CandidateFingerprint != bundle.DomainHTTPS.Certificate.Fingerprint {
			return fmt.Errorf("certificate publication staged identity missing")
		}
		original := intent.SafetyBinding
		intent.CertificateHandoff = &CertificatePublicationHandoff{PlanID: original.PlanID, Generation: original.IntentGeneration, SANIdentity: original.CandidateDigest, ACMEBinding: original.CandidateBundle, CertificateID: certificate.CertificateID, Fingerprint: certificate.CandidateFingerprint, ChallengeSafetyDigest: intent.JournalSafetyDigest}
		intent.SafetyBinding.CandidateDigest = bundle.ConfigDigest
		intent.SafetyBinding.CandidateBundle = bundleDigest
		nextSafetyDigest, err := safetyBindingDigest(intent.SafetyBinding)
		if err != nil {
			return err
		}
		intent.JournalSafetyDigest = nextSafetyDigest
		journal.SafetyMarkerDigest = nextSafetyDigest
		intent.Phase = PhaseLocalIntent
		encodedIntent, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), encodedIntent); err != nil {
			return err
		}
		certificateJournal.Phase = JournalTerminal
		encodedCertificate, err := persist.EncodeEntry(certificateJournal)
		if err != nil {
			return err
		}
		if err := transaction.Replace(certificateKey, encodedCertificate); err != nil {
			return err
		}
		encodedJournal, err := persist.EncodeEntry(journal)
		if err != nil {
			return err
		}
		if err := transaction.Create("journals/"+journal.ID, encodedJournal); err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != commit.ResourceID {
				continue
			}
			if resource.PublicationRecord.State != commit.Intent.PriorState || resource.PublicationRecord.ActivationIntent != nil || bundle.ConfigDigest != resource.CurrentConfigDigest {
				return fmt.Errorf("certificate publication prior or candidate changed")
			}
			resource.PublicationRecord.State = domain.PublicationActivating
			resource.PublicationRecord.ActivationIntent = &commit.Intent
			resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeUnknown, ObservedAt: intent.Consumption.ConfirmedAt.UTC().Format(time.RFC3339), Reason: "activating_may_be_live"}
			resource.PublicationRecord.LastJobID = jobID
			found = true
		}
		if !found {
			return fmt.Errorf("certificate publication resource disappeared")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitPublicationBegin(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit PublicationBeginCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.ResourceID == "" {
		return fmt.Errorf("publication begin requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != Publish || intent.Phase != PhaseLocalIntent || intent.SafetyBinding.ResourceID != commit.ResourceID || mutation.Target() != intent.Target || commit.Intent.JobID != jobID || commit.Intent.PlanID != intent.PlanID || commit.Intent.Generation != intent.SafetyBinding.IntentGeneration || commit.Intent.Candidate.Generation != commit.Intent.Generation || commit.Intent.Candidate.ConfigDigest != intent.SafetyBinding.CandidateDigest || publication.RequireBundleDigest(commit.Intent.Candidate, intent.SafetyBinding.CandidateBundle) != nil {
			return fmt.Errorf("publication begin intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != commit.ResourceID {
				continue
			}
			if resource.PublicationRecord.State != commit.Intent.PriorState || resource.PublicationRecord.ActivationIntent != nil || commit.Intent.Candidate.ConfigDigest != resource.CurrentConfigDigest {
				return fmt.Errorf("publication prior or candidate changed")
			}
			resource.PublicationRecord.State = domain.PublicationActivating
			resource.PublicationRecord.ActivationIntent = &commit.Intent
			resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeUnknown, ObservedAt: intent.Consumption.ConfirmedAt.UTC().Format(time.RFC3339), Reason: "activating_may_be_live"}
			resource.PublicationRecord.LastJobID = jobID
			found = true
		}
		if !found {
			return fmt.Errorf("publication resource disappeared")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitPublicationPublished(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit PublicationTerminalCommit, journalID, runtimeDigest string, paths []string, safetyCommit func() error) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(runtimeDigest) {
		return jobs.Record{}, fmt.Errorf("publication terminal commit requires exact authority")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	if safetyCommit == nil {
		return jobs.Record{}, fmt.Errorf("publication terminal safety convergence missing")
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != Publish || intent.Phase != PhaseLocalIntent || intent.SafetyBinding.ResourceID != commit.ResourceID || commit.Bundle.ConfigDigest != intent.SafetyBinding.CandidateDigest || publication.RequireBundleDigest(commit.Bundle, intent.SafetyBinding.CandidateBundle) != nil {
			return fmt.Errorf("publication terminal intent mismatched")
		}
		journalRaw, present := transaction.Get("journals/" + journalID)
		if !present {
			return fmt.Errorf("publication journal missing")
		}
		var journal JournalRecord
		if err := decodeStrict(journalRaw, &journal); err != nil {
			return err
		}
		if journal.JobID != jobID || journal.Kind != JournalAppActivation || journal.ArtifactDigest != intent.SafetyBinding.CandidateBundle || journal.Phase != JournalPrepared {
			return fmt.Errorf("publication journal authority changed")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != commit.ResourceID {
				continue
			}
			active := resource.PublicationRecord.ActivationIntent
			if resource.PublicationRecord.State != domain.PublicationActivating || active == nil || active.JobID != jobID || !reflect.DeepEqual(active.Candidate, commit.Bundle) {
				return fmt.Errorf("publication candidate authority changed")
			}
			digest := commit.Bundle.ConfigDigest
			resource.PublicationRecord.State = domain.PublicationPublished
			resource.PublicationRecord.LastAppliedDigest = &digest
			bundle := commit.Bundle
			resource.PublicationRecord.LastAppliedBundle = &bundle
			resource.PublicationRecord.ActivationIntent = nil
			resource.PublicationRecord.RuntimeObservation = &commit.Runtime
			resource.PublicationRecord.LastOperation = domain.OperationPublish
			resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
			resource.PublicationRecord.LastJobID = jobID
			found = true
		}
		if !found {
			return fmt.Errorf("publication resource disappeared")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", raw); err != nil {
			return err
		}
		journal.Phase = JournalTerminal
		journalRaw, err = persist.EncodeEntry(journal)
		if err != nil {
			return err
		}
		if err := transaction.Replace("journals/"+journal.ID, journalRaw); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, ModifiedPaths: paths, Postconditions: []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: runtimeDigest}}}, observedNow)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		intent.Phase = PhaseTerminal
		raw, err = persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), raw); err != nil {
			return err
		}
		completed = record
		return nil
	})
	if err != nil {
		return jobs.Record{}, err
	}
	return completed, safetyCommit()
}
func (admitter *Admitter) RejectPublication(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, code string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("publication rejection requires exact authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != Publish || intent.Phase != PhaseLocalIntent {
			return fmt.Errorf("publication intent is not rejectable")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID == intent.SafetyBinding.ResourceID && resource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.ActivationIntent.JobID == jobID {
				active := resource.PublicationRecord.ActivationIntent
				resource.PublicationRecord.State = active.PriorState
				resource.PublicationRecord.ActivationIntent = nil
				resource.PublicationRecord.LastOperation = domain.OperationPublish
				resource.PublicationRecord.LastOperationResult = domain.OperationFailed
				resource.PublicationRecord.LastJobID = jobID
				resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: observed.Format(time.RFC3339), Reason: "activation_restored_prior"}
			}
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", raw); err != nil {
			return err
		}
		for _, key := range transaction.Keys("journals") {
			journalRaw, _ := transaction.Get(key)
			var journal JournalRecord
			if err := decodeStrict(journalRaw, &journal); err != nil {
				return err
			}
			if journal.JobID == jobID && journal.Kind == JournalAppActivation {
				journal.Phase = JournalTerminal
				journalRaw, err = persist.EncodeEntry(journal)
				if err != nil {
					return err
				}
				if err := transaction.Replace(key, journalRaw); err != nil {
					return err
				}
			}
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultFailed, Postconditions: []jobs.Postcondition{{Kind: "prior_publication_restored", Status: jobs.PostconditionVerified, Identity: intent.SafetyBinding.CandidateBundle}}, ErrorCode: code}, observed)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		intent.Phase = PhaseTerminal
		raw, err = persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		return transaction.Replace(reservationKey(jobID), raw)
	})
	return err
}

func (admitter *Admitter) ConvergeCommittedPublicationContraction(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, resourceID string, generation uint64, runtimeDigest string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || generation == 0 || !exactDigest(runtimeDigest) {
		return fmt.Errorf("committed publication contraction authority invalid")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != resourceID {
				continue
			}
			if resource.PublicationRecord.State != domain.PublicationPublished || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.LastAppliedBundle == nil {
				return fmt.Errorf("committed publication recovery state changed")
			}
			intent, err := loadReservation(transaction, resource.PublicationRecord.LastJobID)
			if err != nil || intent.Operation != Publish || intent.Phase != PhaseTerminal {
				return fmt.Errorf("committed publication recovery intent changed")
			}
			record, err := jobs.Load(transaction, resource.PublicationRecord.LastJobID)
			if err != nil || record.Status != jobs.StatusTerminal || record.Result != jobs.ResultSucceeded {
				return fmt.Errorf("committed publication recovery job changed")
			}
			resource.PublicationRecord.State = domain.PublicationUnpublished
			resource.PublicationRecord.UnpublishedGeneration = generation
			resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: observed.Format(time.RFC3339), Reason: "committed_activation_recovery_contracted"}
			found = true
		}
		if !found {
			return fmt.Errorf("committed publication recovery resource missing")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) TerminalizeInterruptedPublication(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string, generation uint64, paths []string, runtimeDigest string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || generation == 0 || !exactDigest(runtimeDigest) {
		return jobs.Record{}, fmt.Errorf("publication recovery terminal authority invalid")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != Publish || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+resourceID || mutation.Target() != intent.Target {
			return fmt.Errorf("publication recovery intent changed")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != resourceID {
				continue
			}
			if resource.PublicationRecord.ActivationIntent == nil || resource.PublicationRecord.ActivationIntent.JobID != jobID {
				return fmt.Errorf("publication activation identity missing")
			}
			resource.PublicationRecord.State = domain.PublicationUnpublished
			resource.PublicationRecord.UnpublishedGeneration = generation
			resource.PublicationRecord.ActivationIntent = nil
			resource.PublicationRecord.LastOperation = domain.OperationPublish
			resource.PublicationRecord.LastOperationResult = domain.OperationInterrupted
			resource.PublicationRecord.LastJobID = jobID
			resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: observed.Format(time.RFC3339), Reason: "interrupted_activation_contracted"}
			found = true
		}
		if !found {
			return fmt.Errorf("publication recovery resource missing")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", raw); err != nil {
			return err
		}
		journalFound := false
		for _, key := range transaction.Keys("journals") {
			journalRaw, _ := transaction.Get(key)
			var journal JournalRecord
			if decodeStrict(journalRaw, &journal) != nil {
				return fmt.Errorf("publication recovery journal malformed")
			}
			if journal.JobID == jobID && journal.Kind == JournalAppActivation {
				if journalFound || journal.ArtifactDigest != intent.SafetyBinding.CandidateBundle || journal.Phase == JournalTerminal {
					return fmt.Errorf("publication recovery journal identity changed")
				}
				journalFound = true
				journal.Phase = JournalTerminal
				journalRaw, err = persist.EncodeEntry(journal)
				if err != nil {
					return err
				}
				if err := transaction.Replace(key, journalRaw); err != nil {
					return err
				}
			}
		}
		if !journalFound {
			return fmt.Errorf("publication recovery journal missing")
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, ModifiedPaths: paths, Postconditions: []jobs.Postcondition{{Kind: "interrupted_activation_contracted", Status: jobs.PostconditionKnown, Identity: runtimeDigest}}, ErrorCode: "activation_contracted"}, observed)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		intent.Phase = PhaseTerminal
		raw, err = persist.EncodeEntry(intent)
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

func (admitter *Admitter) CommitContractionState(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit ContractionCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(commit.ClosureAuthorityDigest) || len(commit.UnpublishedGenerations) > maximumJournalResources {
		return fmt.Errorf("contraction state commit requires exact bounded authority")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return err
	}
	intentView, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return err
	}
	if mutation.Target() != intentView.Target || intentView.Phase != PhaseLocalIntent && intentView.Phase != PhaseReentered || !isContraction(intentView.Operation) || intentView.ContractionDigest != "" {
		return fmt.Errorf("contraction state intent is not active or was already committed")
	}
	if err := admitter.validateFreshAuthority(document, intentView); err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered || intent.ContractionDigest != "" || !isContraction(intent.Operation) {
			return fmt.Errorf("contraction state intent changed")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		remaining := make(map[string]uint64, len(commit.UnpublishedGenerations))
		for id, generation := range commit.UnpublishedGenerations {
			if !validIdentityRef(id) || generation == 0 {
				return fmt.Errorf("contraction generation inventory is invalid")
			}
			remaining[id] = generation
		}
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			generation, affected := remaining[resource.ID]
			if !affected {
				continue
			}
			if generation <= resource.PublicationRecord.UnpublishedGeneration {
				return fmt.Errorf("resource %q contraction generation did not advance", resource.ID)
			}
			prior := resource.PublicationRecord.LastAppliedBundle
			var candidate *domain.PublicationBundle
			if resource.PublicationRecord.ActivationIntent != nil {
				value := resource.PublicationRecord.ActivationIntent.Candidate
				candidate = &value
				if resource.PublicationRecord.ActivationIntent.Prior != nil {
					prior = resource.PublicationRecord.ActivationIntent.Prior
				}
			}
			resource.PublicationRecord.State = domain.PublicationUnpublished
			resource.PublicationRecord.UnpublishedGeneration = generation
			resource.PublicationRecord.ActivationIntent = nil
			resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeUnknown, ObservedAt: intent.Consumption.ConfirmedAt.UTC().Format(time.RFC3339), Reason: "closing_may_be_live"}
			resource.PublicationRecord.ContractionIntent = &domain.ContractionIntent{JobID: intent.JobID, Operation: string(intent.Operation), Generation: generation, ClosureAuthorityDigest: commit.ClosureAuthorityDigest, Prior: cloneBundle(prior), Candidate: cloneBundle(candidate)}
			delete(remaining, resource.ID)
		}
		if len(remaining) != 0 {
			return fmt.Errorf("contraction affected resource is absent from installation")
		}
		rawInstallation, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", rawInstallation); err != nil {
			return err
		}
		intent.ContractionDigest = commit.ClosureAuthorityDigest
		rawIntent, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		return transaction.Replace(reservationKey(jobID), rawIntent)
	})
	return err
}

func (admitter *Admitter) ValidateActive(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, jobID string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("operation validation requires authoritative locks")
	}
	document, err := admitter.normal.Read()
	if err != nil {
		return err
	}
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return err
	}
	if mutation.Target() != intent.Target || intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered {
		return fmt.Errorf("operation intent is not active")
	}
	return admitter.validateFreshAuthority(document, intent)
}

func (admitter *Admitter) CommitResourceCreate(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit ResourceCreateCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.Resource.ID == "" {
		return fmt.Errorf("resource creation commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ResourceCreate || intent.AdmissionSource != AdmissionUI || intent.Phase != PhaseLocalIntent || intent.SafetyBinding.ResourceID != commit.Resource.ID || mutation.Target() != intent.Target {
			return fmt.Errorf("resource creation intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		installation.Resources = append(installation.Resources, commit.Resource)
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitResourceUpdate(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, candidate domain.AppResource) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || candidate.ID == "" {
		return fmt.Errorf("resource update commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ResourceUpdate || intent.Phase != PhaseLocalIntent || intent.SafetyBinding.ResourceID != candidate.ID || mutation.Target() != intent.Target {
			return fmt.Errorf("resource update intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			if installation.Resources[index].ID == candidate.ID {
				prior := installation.Resources[index]
				candidate.PublicationRecord = prior.PublicationRecord
				if candidate.ManagedProcess == nil || prior.ManagedProcess == nil {
					return fmt.Errorf("resource update managed process is absent")
				}
				candidate.ManagedProcess.Requested = prior.ManagedProcess.Requested
				candidate.ManagedProcess.Applied = cloneProcessBundle(prior.ManagedProcess.Applied)
				if prior.Name == candidate.Name && prior.Lifecycle == candidate.Lifecycle && reflect.DeepEqual(prior.Target, candidate.Target) && reflect.DeepEqual(prior.ManagedPaths, candidate.ManagedPaths) && reflect.DeepEqual(operationNonPublicationCredentials(prior), operationNonPublicationCredentials(candidate)) && reflect.DeepEqual(prior.ManagedProcess, candidate.ManagedProcess) && candidate.ManagedProcess.Applied != nil {
					candidate.ManagedProcess.Applied.ConfigDigest = candidate.CurrentConfigDigest
				}
				candidate.ManagedProcess.RuntimeObservation = prior.ManagedProcess.RuntimeObservation
				candidate.ManagedProcess.LastOperation = prior.ManagedProcess.LastOperation
				candidate.ManagedProcess.LastOperationResult = prior.ManagedProcess.LastOperationResult
				candidate.ManagedProcess.LastJobID = prior.ManagedProcess.LastJobID
				installation.Resources[index] = candidate
				found = true
			}
		}
		if !found {
			return fmt.Errorf("resource update target disappeared")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitProcessState(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit ProcessStateCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.ResourceID == "" || commit.Observation.ObservedAt == "" {
		return fmt.Errorf("process state commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if (intent.Operation != ProcessStart && intent.Operation != ProcessStop) || intent.Phase != PhaseLocalIntent || intent.SafetyBinding.ResourceID != commit.ResourceID || mutation.Target() != intent.Target {
			return fmt.Errorf("process state intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != commit.ResourceID {
				continue
			}
			if resource.ManagedProcess == nil {
				return fmt.Errorf("resource has no managed process")
			}
			resource.ManagedProcess.Requested = commit.Requested
			resource.ManagedProcess.Applied = cloneProcessBundle(commit.Applied)
			resource.ManagedProcess.RuntimeObservation = &commit.Observation
			resource.ManagedProcess.LastOperation = domain.OperationProcessStart
			if intent.Operation == ProcessStop {
				resource.ManagedProcess.LastOperation = domain.OperationProcessStop
			}
			resource.ManagedProcess.LastJobID = intent.JobID
			found = true
		}
		if !found {
			return fmt.Errorf("process resource disappeared")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func CompleteInterruptedLifecycle(transaction *persist.Transaction, jobID string, now time.Time) error {
	intent, err := loadReservation(transaction, jobID)
	if err != nil {
		return err
	}
	record, err := jobs.Load(transaction, jobID)
	if err != nil {
		return err
	}
	if record.Status != jobs.StatusRunning {
		return fmt.Errorf("interrupted lifecycle job not running")
	}
	record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "interrupted_lifecycle_contracted", Status: jobs.PostconditionKnown, Identity: jobID}}, ErrorCode: "interrupted_lifecycle_contracted"}, now)
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
	return transaction.Replace(reservationKey(jobID), raw)
}
func PendingResourceUpdates(document persist.Document) ([]Reservation, error) {
	result := []Reservation{}
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return nil, err
		}
		if intent.Operation == ResourceUpdate && (intent.Phase == PhaseReserved || intent.Phase == PhaseLocalIntent) {
			result = append(result, intent)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].JobID < result[j].JobID })
	return result, nil
}
func FindResourceUpdateAuthority(document persist.Document, jobID, resourceID string) (Reservation, error) {
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return Reservation{}, err
	}
	if intent.Operation != ResourceUpdate || intent.AdmissionSource != AdmissionUI || intent.Target != "resource/"+resourceID || intent.SafetyBinding.ResourceID != resourceID || (intent.Phase != PhaseReserved && intent.Phase != PhaseLocalIntent && intent.Phase != PhaseTerminal) {
		return Reservation{}, fmt.Errorf("resource update recovery authority mismatched")
	}
	return intent, nil
}

func PendingProcessLifecycles(document persist.Document) ([]Reservation, error) {
	result := []Reservation{}
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return nil, err
		}
		if (intent.Operation == ProcessStart || intent.Operation == ProcessStop) && (intent.Phase == PhaseReserved || intent.Phase == PhaseLocalIntent) {
			result = append(result, intent)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].JobID < result[j].JobID })
	return result, nil
}

func FindProcessLifecycleAuthority(document persist.Document, jobID, resourceID string) (Reservation, error) {
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return Reservation{}, err
	}
	if (intent.Operation != ProcessStart && intent.Operation != ProcessStop) || intent.AdmissionSource != AdmissionUI || intent.Target != "resource/"+resourceID || intent.SafetyBinding.ResourceID != resourceID || (intent.Phase != PhaseReserved && intent.Phase != PhaseLocalIntent) {
		return Reservation{}, fmt.Errorf("process lifecycle recovery authority mismatched")
	}
	return intent, nil
}

func PendingResourceCreates(document persist.Document) ([]Reservation, error) {
	result := []Reservation{}
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return nil, err
		}
		if intent.Operation == ResourceCreate && (intent.Phase == PhaseReserved || intent.Phase == PhaseLocalIntent) {
			result = append(result, intent)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].JobID < result[j].JobID })
	return result, nil
}

func FindResourceCreateAuthority(document persist.Document, jobID, resourceID string) (Reservation, error) {
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return Reservation{}, err
	}
	if intent.Operation != ResourceCreate || intent.AdmissionSource != AdmissionUI || intent.Target != string(plans.TargetInstallation) || intent.SafetyBinding.ResourceID != resourceID || intent.Phase != PhaseLocalIntent && intent.Phase != PhaseTerminal {
		return Reservation{}, fmt.Errorf("resource create recovery authority mismatched")
	}
	return intent, nil
}

func cloneProcessBundle(value *domain.ProcessBundle) *domain.ProcessBundle {
	if value == nil {
		return nil
	}
	copy := *value
	copy.WritePathIdentities = append([]string(nil), value.WritePathIdentities...)
	copy.EndpointSocketUnits = append([]string(nil), value.EndpointSocketUnits...)
	copy.ManagedPaths = append([]string(nil), value.ManagedPaths...)
	return &copy
}

func cloneBundle(value *domain.PublicationBundle) *domain.PublicationBundle {
	if value == nil {
		return nil
	}
	copy := *value
	copy.ManagedPaths = append([]string(nil), value.ManagedPaths...)
	copy.CredentialIDs = append([]string(nil), value.CredentialIDs...)
	copy.Listeners = append([]domain.BundleListenerIdentity(nil), value.Listeners...)
	if value.DomainHTTPS != nil {
		domainCopy := *value.DomainHTTPS
		domainCopy.ExactDomains = append([]string(nil), value.DomainHTTPS.ExactDomains...)
		domainCopy.Static.RouteIdentities = append([]string(nil), value.DomainHTTPS.Static.RouteIdentities...)
		copy.DomainHTTPS = &domainCopy
	}
	if value.TemporaryHTTP != nil {
		temporaryCopy := *value.TemporaryHTTP
		copy.TemporaryHTTP = &temporaryCopy
	}
	return &copy
}

func (admitter *Admitter) Complete(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, branchName string, paths []string, postconditions []jobs.Postcondition, errorCode string) (jobs.Record, error) {
	return admitter.CompleteWithSecret(ctx, mutation, exposure, expectedRevision, jobID, branchName, paths, postconditions, errorCode, nil)
}
func (admitter *Admitter) CompleteWithSecret(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, branchName string, paths []string, postconditions []jobs.Postcondition, errorCode string, secretResult *jobs.SecretResult) (jobs.Record, error) {
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
	if intentView.ContractionDigest == "" {
		if err := authorize(intentView.Operation, state, intentView.SafetyBinding, true, observedNow); err != nil {
			return jobs.Record{}, err
		}
	} else if err := validateCommittedContractionAuthority(document, state, intentView); err != nil {
		return jobs.Record{}, err
	}
	if intentView.AdmissionSource == AdmissionPlan && intentView.ContractionDigest == "" {
		binding, err := admitter.bindings.CurrentBinding(intentView.Operation, intentView.Target, observedNow)
		if err != nil {
			return jobs.Record{}, err
		}
		if err := plans.ValidateBindingFreshness(binding, observedNow); err != nil {
			return jobs.Record{}, err
		}
		snapshot := plans.Binding{Operation: binding.Operation, Target: binding.Target, ActorIdentity: recordView.ActorIdentity, Config: intentView.Consumption.Config, Applied: intentView.Consumption.Applied, Evidence: intentView.Consumption.Evidence}
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
		if intent.ContractionDigest != "" {
			rawInstallation, present := transaction.Get("installations/current")
			if !present {
				return fmt.Errorf("contraction installation authority is missing")
			}
			installation, err := domain.DecodeInstallation(rawInstallation)
			if err != nil {
				return err
			}
			affected := 0
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				contraction := resource.PublicationRecord.ContractionIntent
				if contraction == nil || contraction.JobID != intent.JobID {
					continue
				}
				if contraction.ClosureAuthorityDigest != intent.ContractionDigest || contraction.Generation != resource.PublicationRecord.UnpublishedGeneration || contraction.Operation != string(intent.Operation) {
					return fmt.Errorf("contraction terminalization identity changed")
				}
				resource.PublicationRecord.ContractionIntent = nil
				resource.PublicationRecord.LastOperation = contractionOperationCode(intent.Operation)
				resource.PublicationRecord.LastJobID = intent.JobID
				affected++
			}
			if affected == 0 && (intent.Operation != CloseAll || len(installation.Resources) != 0) {
				return fmt.Errorf("contraction terminalization has no affected resource")
			}
			rawInstallation, err = persist.EncodeEntry(installation)
			if err != nil {
				return err
			}
			if err := transaction.Replace("installations/current", rawInstallation); err != nil {
				return err
			}
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
		if intent.Operation == ResourceCreate && branch.Result == jobs.ResultSucceeded {
			rawInstallation, present := transaction.Get("installations/current")
			if !present {
				return fmt.Errorf("resource creation installation authority is missing")
			}
			installation, decodeErr := domain.DecodeInstallation(rawInstallation)
			if decodeErr != nil {
				return decodeErr
			}
			found := false
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				if resource.ID != intent.SafetyBinding.ResourceID {
					continue
				}
				resource.PublicationRecord.LastOperation = domain.OperationResourceCreate
				resource.PublicationRecord.LastOperationResult = domain.OperationResult(branch.Result)
				resource.PublicationRecord.LastJobID = intent.JobID
				found = true
			}
			if !found {
				return fmt.Errorf("created resource disappeared before terminal commit")
			}
			rawInstallation, encodeErr := persist.EncodeEntry(installation)
			if encodeErr != nil {
				return encodeErr
			}
			if err := transaction.Replace("installations/current", rawInstallation); err != nil {
				return err
			}
		}
		if intent.Operation == ResourceUpdate {
			rawInstallation, present := transaction.Get("installations/current")
			if !present {
				return fmt.Errorf("resource update installation authority missing")
			}
			installation, decodeErr := domain.DecodeInstallation(rawInstallation)
			if decodeErr != nil {
				return decodeErr
			}
			found := false
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				if resource.ID == intent.SafetyBinding.ResourceID {
					resource.PublicationRecord.LastOperation = domain.OperationResourceUpdate
					resource.PublicationRecord.LastOperationResult = domain.OperationResult(branch.Result)
					resource.PublicationRecord.LastJobID = intent.JobID
					found = true
				}
			}
			if !found {
				return fmt.Errorf("updated resource disappeared before terminal commit")
			}
			encoded, encodeErr := persist.EncodeEntry(installation)
			if encodeErr != nil {
				return encodeErr
			}
			if err := transaction.Replace("installations/current", encoded); err != nil {
				return err
			}
		}
		if intent.Operation == ProcessStart || intent.Operation == ProcessStop {
			rawInstallation, present := transaction.Get("installations/current")
			if !present {
				return fmt.Errorf("process installation authority is missing")
			}
			installation, decodeErr := domain.DecodeInstallation(rawInstallation)
			if decodeErr != nil {
				return decodeErr
			}
			found := false
			for index := range installation.Resources {
				process := installation.Resources[index].ManagedProcess
				if installation.Resources[index].ID != intent.SafetyBinding.ResourceID || process == nil {
					continue
				}
				process.LastOperation = domain.OperationProcessStart
				if intent.Operation == ProcessStop {
					process.LastOperation = domain.OperationProcessStop
				}
				process.LastJobID = intent.JobID
				process.LastOperationResult = domain.OperationResult(branch.Result)
				found = true
			}
			if !found {
				return fmt.Errorf("process resource disappeared before terminal commit")
			}
			rawInstallation, encodeErr := persist.EncodeEntry(installation)
			if encodeErr != nil {
				return encodeErr
			}
			if err := transaction.Replace("installations/current", rawInstallation); err != nil {
				return err
			}
		}
		if intent.ContractionDigest != "" {
			rawInstallation, _ := transaction.Get("installations/current")
			installation, decodeErr := domain.DecodeInstallation(rawInstallation)
			if decodeErr != nil {
				return decodeErr
			}
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				if resource.PublicationRecord.LastJobID == intent.JobID {
					resource.PublicationRecord.LastOperationResult = domain.OperationResult(branch.Result)
					if branch.Result == jobs.ResultSucceeded || branch.Result == jobs.ResultPartial {
						resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: observedNow.Format(time.RFC3339), Reason: "access_closed"}
					} else {
						resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeUnknown, ObservedAt: observedNow.Format(time.RFC3339), Reason: "access_may_remain"}
					}
				}
			}
			rawInstallation, encodeErr := persist.EncodeEntry(installation)
			if encodeErr != nil {
				return encodeErr
			}
			if err := transaction.Replace("installations/current", rawInstallation); err != nil {
				return err
			}
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: branch.Result, ModifiedPaths: paths, Postconditions: postconditions, ErrorCode: errorCode, SecretResult: secretResult}, observedNow)
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

func exactCertificatePublicationAuthority(state safety.State, intent Reservation) bool {
	handoff := intent.CertificateHandoff
	if handoff == nil || state.StopFence != nil || state.MaintenancePending != nil || state.DependencyTransitionPending != nil || state.UpgradePending != nil || state.BackupQuiescence != nil || state.BackupTransition != nil && state.BackupTransition.Phase != safety.BackupTransitionImported || state.GlobalClose.Phase != safety.GlobalCloseNone {
		return false
	}
	for _, resource := range state.Resources {
		if resource.ResourceID != intent.SafetyBinding.ResourceID {
			continue
		}
		if resource.Closing != nil || resource.State == safety.ResourceDeleting || resource.Ownership == safety.OwnershipOrphan {
			return false
		}
		if pending := resource.ChallengePending; pending != nil && pending.PlanID == handoff.PlanID && pending.Generation == handoff.Generation && pending.SANIdentity == handoff.SANIdentity && pending.ACMEBinding == handoff.ACMEBinding && pending.CertificateIdentity == handoff.CertificateID {
			return true
		}
		if active := resource.Reactivating; active != nil && active.PlanID == handoff.PlanID && active.Generation == handoff.Generation && active.CandidateDigest == intent.SafetyBinding.CandidateDigest && active.CandidateBundle == intent.SafetyBinding.CandidateBundle {
			return true
		}
	}
	return false
}
func exactCertificateChallenge(state safety.State, binding SafetyBinding) bool {
	for _, resource := range state.Resources {
		pending := resource.ChallengePending
		if resource.ResourceID == binding.ResourceID && pending != nil && pending.PlanID == binding.PlanID && pending.Generation == binding.IntentGeneration && pending.SANIdentity == binding.CandidateDigest && pending.ACMEBinding == binding.CandidateBundle {
			return true
		}
	}
	return false
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
		ownedChallenge := (intent.Operation == Publish || intent.Operation == CertificateRenew) && exactCertificateChallenge(state, intent.SafetyBinding)
		certificateHandoff := intent.Operation == Publish && exactCertificatePublicationAuthority(state, intent)
		if !ownedChallenge && !certificateHandoff {
			return fmt.Errorf("contraction or safety transition preempted operation authority")
		}
	}
	if err := authorize(intent.Operation, state, intent.SafetyBinding, true, observedNow); err != nil && !exactCertificatePublicationAuthority(state, intent) {
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
	snapshot := plans.Binding{Operation: binding.Operation, Target: binding.Target, ActorIdentity: record.ActorIdentity, Config: intent.Consumption.Config, Applied: intent.Consumption.Applied, Evidence: intent.Consumption.Evidence}
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
		valid := validExpiryBinding(operation, state, binding) || !consuming && validExpiryProposal(operation, state, binding, now)
		if !valid || binding.Deadline.IsZero() || binding.Deadline.After(now) {
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
	if operation == CloseAll {
		if state.GlobalClose.Phase != safety.GlobalCloseNone || binding.GlobalGeneration != state.GlobalClose.Generation || binding.ProposedGeneration != state.GlobalClose.Generation+1 {
			return fmt.Errorf("close-all global generation binding is stale or active")
		}
	}
	if operation == ResourceCreate {
		if binding.ResourceID == "" {
			return fmt.Errorf("resource creation requires a generated stable identity")
		}
		if state.GlobalClose.Phase != safety.GlobalCloseNone || state.MaintenancePending != nil || state.DependencyTransitionPending != nil || state.UpgradePending != nil || state.BackupQuiescence != nil || state.BackupTransition != nil || state.StopFence != nil {
			return fmt.Errorf("independent safety authority blocks resource creation")
		}
	}
	if operation == ManagedBasicCreate || operation == ManagedBasicRotate || operation == ManagedBasicDelete || operation == StaticRootRegister || operation == ExternalHTPasswdRegister {
		var resource *safety.ResourceSafety
		for index := range state.Resources {
			if state.Resources[index].ResourceID == binding.ResourceID {
				resource = &state.Resources[index]
			}
		}
		if resource == nil || resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || resource.Closing != nil || resource.ChallengePending != nil || resource.Reactivating != nil {
			return fmt.Errorf("resource safety blocks credential or static operation")
		}
	}
	if operation == ResourceUpdate || operation == ProcessStart || operation == ProcessStop {
		if state.GlobalClose.Phase != safety.GlobalCloseNone && operation != ProcessStop {
			return fmt.Errorf("global close blocks non-contraction resource operation")
		}
		var resource *safety.ResourceSafety
		for index := range state.Resources {
			if state.Resources[index].ResourceID == binding.ResourceID {
				resource = &state.Resources[index]
				break
			}
		}
		if resource == nil || resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || resource.Closing != nil || resource.ChallengePending != nil || resource.Reactivating != nil {
			return fmt.Errorf("resource lifecycle or expansion authority blocks process operation")
		}
	}
	if operation == CertificateRenew {
		var resource *safety.ResourceSafety
		for index := range state.Resources {
			if state.Resources[index].ResourceID == binding.ResourceID {
				resource = &state.Resources[index]
			}
		}
		if resource == nil || resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || resource.Closing != nil {
			return fmt.Errorf("certificate safety resource unavailable")
		}
		if operation == CertificateRenew && (state.GlobalClose.Phase != safety.GlobalCloseNone || resource.StickyUnpublished != nil || resource.Contraction != nil || resource.CertificateExpiry != nil || resource.EdgeOne.Expiry != nil || resource.ChallengePending != nil || resource.Reactivating != nil) {
			return fmt.Errorf("certificate renewal blocked by safety marker")
		}
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
		ownedChallenge := exactCertificateChallenge(state, binding)
		challengeStart := consuming && binding.CertificateIdentity != "" && (binding.ChallengeMethod == "http-01" || binding.ChallengeMethod == "dns-01")
		if resource.Closing != nil || resource.State == safety.ResourceDeleting || resource.Ownership == safety.OwnershipOrphan || resource.ChallengePending != nil && !ownedChallenge || ownedChallenge && resource.ChallengePending.Method == "http-01" && resource.EdgeOne.Expiry != nil || challengeStart && binding.ChallengeMethod == "http-01" && resource.EdgeOne.Expiry != nil {
			return fmt.Errorf("resource lifecycle or challenge authority blocks publish")
		}
		if !resource.EdgeOne.Deadline.IsZero() && resource.EdgeOne.Deadline.Sub(now) < 5*time.Minute {
			return fmt.Errorf("EdgeOne safety deadline is too near for ordinary activation")
		}
		if resource.Reactivating != nil && !resource.Reactivating.TemporaryHTTP && (resource.Reactivating.CertificateUntil.Sub(now) < 5*time.Minute || resource.Reactivating.ACLUntil.Sub(now) < 5*time.Minute) {
			return fmt.Errorf("reactivation safety deadline is too near")
		}
		if !consuming || ownedChallenge || challengeStart {
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
func contractionKind(operation Type) preflight.ContractionKind {
	switch operation {
	case CloseAll, EmergencyCloseAll:
		return preflight.ContractionCloseAll
	case CertificateExpiry, EdgeOneExpiry:
		return preflight.ContractionExpiry
	case StartupContraction:
		return preflight.ContractionStartup
	default:
		return preflight.ContractionUnpublish
	}
}

func contractionGeneration(reservation Reservation) uint64 {
	if reservation.Operation == EmergencyCloseAll || reservation.Operation == CloseAll {
		if reservation.SafetyBinding.ProposedGeneration != 0 {
			return reservation.SafetyBinding.ProposedGeneration
		}
		return reservation.SafetyBinding.GlobalGeneration
	}
	if reservation.SafetyBinding.ExpiryGeneration != 0 {
		return reservation.SafetyBinding.ExpiryGeneration
	}
	return reservation.SafetyBinding.IntentGeneration
}

func planOperationMatches(operation Type, binding string) bool { return binding == string(operation) }
func requirePreflightEvidence(operation Type, target string, evidence []plans.Evidence, now time.Time) error {
	switch operation {
	case Publish:
		return preflight.RequireExpansionPlanEvidence([]preflight.ExpansionScope{preflight.ExpansionDomainHTTPS, preflight.ExpansionTemporaryHTTP}, target, evidence, now)
	case PackageTransaction:
		return preflight.RequireExpansionPlanEvidence([]preflight.ExpansionScope{preflight.ExpansionBootstrap, preflight.ExpansionHeadscale}, target, evidence, now)
	case Unpublish:
		return preflight.RequireContractionPlanEvidence([]preflight.ContractionKind{preflight.ContractionUnpublish}, target, evidence, now)
	case CloseAll:
		return preflight.RequireContractionPlanEvidence([]preflight.ContractionKind{preflight.ContractionCloseAll}, target, evidence, now)
	default:
		return nil
	}
}

func requiresContractionPreflight(operation Type) bool {
	switch operation {
	case Unpublish, CloseAll, CertificateExpiry, EdgeOneExpiry, StartupContraction:
		return true
	default:
		return false
	}
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

func validExpiryProposal(operation Type, state safety.State, binding SafetyBinding, now time.Time) bool {
	for _, resource := range state.Resources {
		if resource.ResourceID != binding.ResourceID {
			continue
		}
		expectedKind := "certificate_expiry"
		if operation == EdgeOneExpiry {
			expectedKind = "edgeone_expiry"
		}
		if binding.ExpiryKind != expectedKind || binding.ExpiryGeneration != resource.GenerationSequence+1 {
			return false
		}
		if operation == CertificateExpiry {
			if resource.CertificateExpiry != nil || resource.ActiveCertificate == nil || binding.CandidateBundle != resource.ActiveCertificate.Binding {
				return false
			}
			deadline := resource.ActiveCertificate.NotAfter
			if now.Before(resource.ActiveCertificate.LastTrustedWall) {
				deadline = now
			}
			return binding.Deadline.Equal(deadline)
		}
		return resource.EdgeOne.Expiry == nil
	}
	return false
}
func validExpiryBinding(operation Type, state safety.State, binding SafetyBinding) bool {
	for _, resource := range state.Resources {
		if resource.ResourceID != binding.ResourceID {
			continue
		}
		if operation == CertificateExpiry && binding.ExpiryKind == "certificate_expiry" && resource.CertificateExpiry != nil {
			return resource.CertificateExpiry.Generation == binding.ExpiryGeneration && resource.CertificateExpiry.Deadline.Equal(binding.Deadline) && resource.CertificateExpiry.Binding == binding.CandidateBundle
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
func (admitter *Admitter) AuthorizeStateIndependentContraction(operation Type, binding SafetyBinding, contractionRequest preflight.ContractionRequest, preflightResult preflight.Result, unavailable persist.UnavailableProof, exposure *locks.Lease, commitAuthority func(fallbackStop bool) error) error {
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
	preflightKind := map[Type]preflight.ContractionKind{EmergencyCloseAll: preflight.ContractionEmergency, CertificateExpiry: preflight.ContractionExpiry, EdgeOneExpiry: preflight.ContractionExpiry, StartupContraction: preflight.ContractionStartup}[operation]
	expectedGeneration := binding.ExpiryGeneration
	if operation == EmergencyCloseAll {
		expectedGeneration = binding.ProposedGeneration
	} else if operation == StartupContraction {
		expectedGeneration = binding.IntentGeneration
	}
	if contractionRequest.Kind != preflightKind || contractionRequest.Target != stateIndependentTarget(operation, binding) || contractionRequest.Generation != expectedGeneration {
		return fmt.Errorf("state-independent contraction request does not match safety authority")
	}
	if err := preflight.RequireContractionResultForRequest(preflightResult, contractionRequest, now); err != nil {
		return fmt.Errorf("state-independent contraction preflight: %w", err)
	}
	state, err := admitter.safety.Read()
	if err != nil {
		degraded, ok := admitter.safety.(DegradedContractionSafetyReader)
		if !ok {
			return fmt.Errorf("read independent safety authority: %w", err)
		}
		state, err = degraded.ReadForContraction(exposure)
		if err != nil {
			return fmt.Errorf("read degraded contraction safety authority: %w", err)
		}
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
	return commitAuthority(contractionRequest.FallbackStop)
}

func stateIndependentTarget(operation Type, binding SafetyBinding) string {
	if operation == EmergencyCloseAll {
		return "installation"
	}
	return "resource/" + binding.ResourceID
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
func validCertificateHandoffTransition(oldValue, newValue Reservation) bool {
	handoff := newValue.CertificateHandoff
	if oldValue.Operation != Publish || oldValue.Phase != PhaseReentered || newValue.Phase != PhaseLocalIntent || oldValue.CertificateHandoff != nil || handoff == nil || handoff.PlanID != oldValue.SafetyBinding.PlanID || handoff.Generation != oldValue.SafetyBinding.IntentGeneration || handoff.SANIdentity != oldValue.SafetyBinding.CandidateDigest || handoff.ACMEBinding != oldValue.SafetyBinding.CandidateBundle || handoff.ACMEBinding != oldValue.OperationBinding || handoff.ChallengeSafetyDigest != oldValue.JournalSafetyDigest || !exactDigest(handoff.ChallengeSafetyDigest) || !exactDigest(handoff.SANIdentity) || !exactDigest(handoff.ACMEBinding) || !validIdentityRef(handoff.CertificateID) || !exactDigest(handoff.Fingerprint) || !exactDigest(newValue.SafetyBinding.CandidateDigest) || !exactDigest(newValue.SafetyBinding.CandidateBundle) {
		return false
	}
	candidateDigest, candidateBundle := newValue.SafetyBinding.CandidateDigest, newValue.SafetyBinding.CandidateBundle
	expectedSafetyDigest, err := safetyBindingDigest(newValue.SafetyBinding)
	if err != nil || newValue.JournalSafetyDigest != expectedSafetyDigest {
		return false
	}
	newValue.Phase = oldValue.Phase
	newValue.CertificateHandoff = nil
	newValue.SafetyBinding.CandidateDigest = oldValue.SafetyBinding.CandidateDigest
	newValue.SafetyBinding.CandidateBundle = oldValue.SafetyBinding.CandidateBundle
	newValue.JournalSafetyDigest = oldValue.JournalSafetyDigest
	if candidateDigest == oldValue.SafetyBinding.CandidateDigest || candidateBundle == oldValue.SafetyBinding.CandidateBundle {
		return false
	}
	return reflect.DeepEqual(oldValue, newValue)
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
	if validCertificateHandoffTransition(oldValue, newValue) {
		return nil
	}
	oldPhase, newPhase := oldValue.Phase, newValue.Phase
	oldValue.Phase = ""
	newValue.Phase = ""
	oldGeneration, newGeneration := oldValue.IntentGeneration, newValue.IntentGeneration
	oldConsumption, newConsumption := oldValue.Consumption, newValue.Consumption
	oldJournalSafety, newJournalSafety := oldValue.JournalSafetyDigest, newValue.JournalSafetyDigest
	oldContractionDigest, newContractionDigest := oldValue.ContractionDigest, newValue.ContractionDigest
	oldSecretFingerprint, newSecretFingerprint := oldValue.SecretFingerprint, newValue.SecretFingerprint
	oldSecretCommitted, newSecretCommitted := oldValue.SecretCommitted, newValue.SecretCommitted
	oldOperationBinding, newOperationBinding := oldValue.OperationBinding, newValue.OperationBinding
	oldValue.IntentGeneration = 0
	newValue.IntentGeneration = 0
	oldValue.Consumption = nil
	newValue.Consumption = nil
	oldValue.JournalSafetyDigest = ""
	newValue.JournalSafetyDigest = ""
	oldValue.ContractionDigest = ""
	newValue.ContractionDigest = ""
	oldValue.SecretFingerprint = ""
	newValue.SecretFingerprint = ""
	oldValue.SecretCommitted = false
	newValue.SecretCommitted = false
	oldValue.OperationBinding = ""
	newValue.OperationBinding = ""
	if !reflect.DeepEqual(oldValue, newValue) {
		return fmt.Errorf("immutable operation intent binding was rewritten")
	}
	journalBindingOnly := oldPhase == newPhase && oldJournalSafety == "" && newJournalSafety != "" && oldContractionDigest == newContractionDigest && oldSecretFingerprint == newSecretFingerprint && oldOperationBinding == newOperationBinding
	contractionBindingOnly := oldPhase == PhaseLocalIntent && newPhase == oldPhase && oldContractionDigest == "" && exactDigest(newContractionDigest) && oldJournalSafety == newJournalSafety && oldSecretFingerprint == newSecretFingerprint && oldOperationBinding == newOperationBinding
	secretBindingOnly := oldPhase == PhaseLocalIntent && newPhase == oldPhase && oldSecretFingerprint == "" && exactDigest(newSecretFingerprint) && !oldSecretCommitted && !newSecretCommitted && oldJournalSafety == newJournalSafety && oldContractionDigest == newContractionDigest && oldOperationBinding == newOperationBinding
	secretCommitOnly := oldPhase == PhaseLocalIntent && newPhase == oldPhase && oldSecretFingerprint == newSecretFingerprint && exactDigest(newSecretFingerprint) && !oldSecretCommitted && newSecretCommitted && oldJournalSafety == newJournalSafety && oldContractionDigest == newContractionDigest && oldOperationBinding == newOperationBinding
	operationBindingOnly := oldPhase == PhaseLocalIntent && newPhase == oldPhase && oldOperationBinding == "" && exactDigest(newOperationBinding) && oldJournalSafety == newJournalSafety && oldContractionDigest == newContractionDigest && oldSecretFingerprint == newSecretFingerprint
	valid := journalBindingOnly || contractionBindingOnly || secretBindingOnly || secretCommitOnly || operationBindingOnly || oldPhase == PhaseReserved && (newPhase == PhaseLocalIntent || newPhase == PhaseRejected) || oldPhase == PhaseLocalIntent && (newPhase == PhaseRemoteWait || newPhase == PhaseTerminal) || oldPhase == PhaseRemoteWait && (newPhase == PhaseReentered || newPhase == PhaseTerminal) || oldPhase == PhaseReentered && (newPhase == PhaseRemoteWait || newPhase == PhaseTerminal)
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
	if oldContractionDigest != "" && newContractionDigest != oldContractionDigest || newContractionDigest != "" && !exactDigest(newContractionDigest) {
		return fmt.Errorf("contraction authority binding was rewritten or is invalid")
	}
	if oldSecretFingerprint != "" && newSecretFingerprint != oldSecretFingerprint || newSecretFingerprint != "" && !exactDigest(newSecretFingerprint) || oldSecretCommitted && !newSecretCommitted || newSecretCommitted && newSecretFingerprint == "" {
		return fmt.Errorf("secret commit binding was rewritten or is invalid")
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

func validateCertificateJournalIdentity(value JournalRecord) error {
	identity := value.Certificate
	if identity == nil || !validIdentityRef(identity.CertificateID) || identity.CandidateGeneration == 0 || identity.StageUID == 0 || identity.StageGID == 0 {
		return fmt.Errorf("certificate journal pointer identity missing")
	}
	candidate := fmt.Sprintf("/var/lib/lanpanel/certificates/bundles/%s-%020d", identity.CertificateID, identity.CandidateGeneration)
	if identity.CandidatePointer != candidate {
		return fmt.Errorf("certificate journal candidate pointer invalid")
	}
	if identity.PriorGeneration == 0 {
		if identity.PriorPointer != "" || identity.PriorFingerprint != "" {
			return fmt.Errorf("certificate journal unexpected prior identity")
		}
	} else {
		prior := fmt.Sprintf("/var/lib/lanpanel/certificates/bundles/%s-%020d", identity.CertificateID, identity.PriorGeneration)
		if identity.PriorPointer != prior || !exactDigest(identity.PriorFingerprint) || identity.CandidateGeneration != identity.PriorGeneration+1 {
			return fmt.Errorf("certificate journal prior identity invalid")
		}
	}
	if identity.CandidateFingerprint != "" && !exactDigest(identity.CandidateFingerprint) {
		return fmt.Errorf("certificate journal candidate fingerprint invalid")
	}
	if value.Phase == JournalActive && identity.CandidateFingerprint == "" {
		return fmt.Errorf("active certificate journal lacks candidate fingerprint")
	}
	return nil
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
	} else if value.Kind == JournalCertificateActivation {
		if err := validateCertificateJournalIdentity(value); err != nil {
			return err
		}
		exactResource := len(value.ResourceIDs) == 1 && value.Target == "resource/"+value.ResourceIDs[0]
		exactHeadscale := len(value.ResourceIDs) == 0 && value.Target == "headscale"
		if value.Operation != Publish && value.Operation != CertificateRenew || !exactResource && !exactHeadscale {
			return fmt.Errorf("certificate activation journal identity is invalid")
		}
	} else if value.Kind == JournalAppActivation {
		if value.Operation != Publish || len(value.ResourceIDs) != 1 || value.Target != "resource/"+value.ResourceIDs[0] {
			return fmt.Errorf("App activation journal identity is invalid")
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
	if value.Kind != JournalCertificateActivation && value.Certificate != nil {
		return fmt.Errorf("non-certificate journal carried certificate identity")
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
	} else if value.Kind != JournalAppActivation && value.Kind != JournalCertificateActivation && len(value.ResourceIDs) != 0 {
		return fmt.Errorf("non-ingress journal unexpectedly identifies App resources")
	}
	if value.Kind != JournalAppActivation && len(value.ChildIDs) == 0 || len(value.ChildIDs) > maximumChildrenPerJob {
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
	oldCandidateFingerprint, newCandidateFingerprint := "", ""
	var oldUID, oldGID, newUID, newGID uint32
	if oldValue.Certificate != nil {
		oldCandidateFingerprint = oldValue.Certificate.CandidateFingerprint
		oldUID = oldValue.Certificate.StageUID
		oldGID = oldValue.Certificate.StageGID
		oldValue.Certificate.CandidateFingerprint = ""
		oldValue.Certificate.StageUID = 0
		oldValue.Certificate.StageGID = 0
	}
	if newValue.Certificate != nil {
		newCandidateFingerprint = newValue.Certificate.CandidateFingerprint
		newUID = newValue.Certificate.StageUID
		newGID = newValue.Certificate.StageGID
		newValue.Certificate.CandidateFingerprint = ""
		newValue.Certificate.StageUID = 0
		newValue.Certificate.StageGID = 0
	}
	oldValue.Phase = ""
	newValue.Phase = ""
	if !reflect.DeepEqual(oldValue, newValue) {
		return fmt.Errorf("journal identity was rewritten")
	}
	filledCandidate := oldCandidateFingerprint == "" && exactDigest(newCandidateFingerprint) && oldUID == newUID && oldGID == newGID && oldUID != 0 && oldPhase == JournalPrepared && newPhase == JournalActive
	sameCandidate := oldCandidateFingerprint == newCandidateFingerprint && oldUID == newUID && oldGID == newGID
	if !filledCandidate && !sameCandidate {
		return fmt.Errorf("journal candidate fingerprint was rewritten")
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
	journalByJob := map[string]bool{}
	journalsByJob := map[string][]JournalRecord{}
	certificateUID := map[uint32]string{}
	certificateGID := map[uint32]string{}
	for _, key := range journalKeys {
		var journal JournalRecord
		if err := decodeStrict(document.Entries[key], &journal); err != nil {
			return err
		}
		if err := validateJournalRecord(journal); err != nil {
			return err
		}
		if certificate := journal.Certificate; certificate != nil {
			if prior := certificateUID[certificate.StageUID]; prior != "" && prior != certificate.CertificateID {
				return fmt.Errorf("certificate journal stage UID collision")
			}
			if prior := certificateGID[certificate.StageGID]; prior != "" && prior != certificate.CertificateID {
				return fmt.Errorf("certificate journal stage GID collision")
			}
			certificateUID[certificate.StageUID] = certificate.CertificateID
			certificateGID[certificate.StageGID] = certificate.CertificateID
		}
		intent, ok := intents[journal.JobID]
		if !ok {
			return fmt.Errorf("journal has no matching operation intent")
		}
		priorJournals := journalsByJob[journal.JobID]
		if len(priorJournals) > 0 {
			prior := priorJournals[0]
			validPair := len(priorJournals) == 1 && intent.CertificateHandoff != nil && ((prior.Kind == JournalAppActivation && (prior.Phase == JournalPrepared || prior.Phase == JournalTerminal) && journal.Kind == JournalCertificateActivation && journal.Phase == JournalTerminal) || (journal.Kind == JournalAppActivation && (journal.Phase == JournalPrepared || journal.Phase == JournalTerminal) && prior.Kind == JournalCertificateActivation && prior.Phase == JournalTerminal))
			if !validPair {
				return fmt.Errorf("operation intent has incompatible journal authorities")
			}
		}
		journalsByJob[journal.JobID] = append(priorJournals, journal)
		journalByJob[journal.JobID] = true
		pendingCertificateReservation := journal.Kind == JournalCertificateActivation && journal.Phase == JournalPrepared && len(childrenByJob[journal.JobID]) < len(journal.ChildIDs) && slices.Equal(childrenByJob[journal.JobID], journal.ChildIDs[:len(childrenByJob[journal.JobID])])
		terminalNeverSubmitted := journal.Kind == JournalCertificateActivation && journal.Phase == JournalTerminal && intent.Phase == PhaseTerminal && len(childrenByJob[journal.JobID]) < len(journal.ChildIDs) && slices.Equal(childrenByJob[journal.JobID], journal.ChildIDs[:len(childrenByJob[journal.JobID])])
		handoffAppJournal := intent.CertificateHandoff != nil && journal.Kind == JournalAppActivation && (journal.Phase == JournalPrepared || journal.Phase == JournalTerminal) && len(journal.ChildIDs) == 0
		handoffCertificateJournal := intent.CertificateHandoff != nil && journal.Kind == JournalCertificateActivation && journal.Phase == JournalTerminal && journal.SafetyMarkerDigest == intent.CertificateHandoff.ChallengeSafetyDigest
		if journal.InstallationID != installationID || journal.Operation != intent.Operation || journal.Target != intent.Target || journal.Generation != intent.IntentGeneration || journal.SafetyMarkerDigest != intent.JournalSafetyDigest && !handoffCertificateJournal || !reflect.DeepEqual(journal.ChildIDs, childrenByJob[journal.JobID]) && !pendingCertificateReservation && !terminalNeverSubmitted && !handoffAppJournal {
			return fmt.Errorf("journal installation, operation, target, generation, or child inventory does not match its authorities")
		}
		for _, childID := range journal.ChildIDs {
			child, present := children[childID]
			if !present && (pendingCertificateReservation || terminalNeverSubmitted) {
				continue
			}
			if child.ArtifactDigest != journal.ArtifactDigest || !child.Deadline.Equal(journal.Deadline) {
				return fmt.Errorf("journal artifact or deadline does not match exact child %q", childID)
			}
		}
		if (intent.Phase == PhaseTerminal || intent.Phase == PhaseRejected) && journal.Phase != JournalTerminal {
			return fmt.Errorf("terminal intent retains nonterminal journal")
		}
	}
	for jobID, intent := range intents {
		if intent.JournalSafetyDigest != "" && !journalByJob[jobID] {
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
		if !existed {
			if err := validateNewResourceAuthority(after, resource); err != nil {
				return err
			}
			continue
		}
		if protectedResourceStateEqual(oldResource, resource) {
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
		if resource.ManagedProcess != nil && (resource.ManagedProcess.LastJobID != oldResource.ManagedProcess.LastJobID || resource.PublicationRecord == oldResource.PublicationRecord) {
			jobID = resource.ManagedProcess.LastJobID
		}
		if resource.PublicationRecord.ContractionIntent != nil {
			jobID = resource.PublicationRecord.ContractionIntent.JobID
		} else if oldResource.PublicationRecord.ContractionIntent != nil {
			jobID = oldResource.PublicationRecord.ContractionIntent.JobID
		}
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
		targetMatches := intent.Target == "resource/"+resource.ID || (intent.Operation == CloseAll || intent.Operation == StartupContraction || intent.Operation == ResourceCreate) && intent.Target == string(plans.TargetInstallation)
		if intent.Operation == AutomaticReconciliation && strings.HasPrefix(intent.Target, "journal/") {
			journal, err := loadJournalEntries(after.Entries, strings.TrimPrefix(intent.Target, "journal/"))
			if err == nil {
				targetMatches = slices.Contains(journal.ResourceIDs, resource.ID)
			}
		}
		if !targetMatches {
			return fmt.Errorf("resource %q state changed under a mismatched operation target", resource.ID)
		}
		beforeRecord, err := jobs.LoadEntries(before.Entries, jobID)
		if err != nil {
			return err
		}
		record, err := jobs.LoadEntries(after.Entries, jobID)
		if err != nil {
			return err
		}
		beginningActivation := oldResource.PublicationRecord.State != domain.PublicationActivating && resource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.ActivationIntent != nil && ((beforeIntent.Phase == intent.Phase && intent.Phase == PhaseLocalIntent) || (beforeIntent.Phase == PhaseReentered && intent.Phase == PhaseLocalIntent && intent.CertificateHandoff != nil)) && intent.Operation == Publish && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusRunning
		terminalActivation := oldResource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.State == domain.PublicationPublished && resource.PublicationRecord.ActivationIntent == nil && (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered) && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal
		committedRecoveryContraction := oldResource.PublicationRecord.State == domain.PublicationPublished && oldResource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.State == domain.PublicationUnpublished && resource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.UnpublishedGeneration > oldResource.PublicationRecord.UnpublishedGeneration && beforeIntent.Phase == PhaseTerminal && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusTerminal && record.Status == jobs.StatusTerminal && record.Result == jobs.ResultSucceeded
		interruptedActivation := oldResource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.State == domain.PublicationUnpublished && resource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.UnpublishedGeneration > oldResource.PublicationRecord.UnpublishedGeneration && beforeIntent.Phase == PhaseLocalIntent && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal && record.Result == jobs.ResultInterrupted
		failedActivation := oldResource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.State == oldResource.PublicationRecord.ActivationIntent.PriorState && resource.PublicationRecord.ActivationIntent == nil && beforeIntent.Phase == PhaseLocalIntent && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal && record.Result == jobs.ResultFailed
		beginningContraction := oldResource.PublicationRecord.ContractionIntent == nil && resource.PublicationRecord.ContractionIntent != nil && beforeIntent.Phase == intent.Phase && (intent.Phase == PhaseLocalIntent || intent.Phase == PhaseReentered) && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusRunning
		terminalContraction := oldResource.PublicationRecord.ContractionIntent != nil && resource.PublicationRecord.ContractionIntent == nil && (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered) && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal
		ordinaryLocal := oldResource.PublicationRecord.ContractionIntent == nil && resource.PublicationRecord.ContractionIntent == nil && beforeIntent.Phase == intent.Phase && intent.Phase == PhaseLocalIntent && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusRunning && (intent.Operation == ResourceUpdate || intent.Operation == ProcessStart || intent.Operation == ProcessStop)
		ordinaryTerminal := intent.Operation != Publish && oldResource.PublicationRecord.ContractionIntent == nil && resource.PublicationRecord.ContractionIntent == nil && (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered || beforeIntent.Phase == PhaseRemoteWait && intent.Operation == CertificateRenew) && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal
		switch {
		case beginningActivation:
			activation := resource.PublicationRecord.ActivationIntent
			if activation.JobID != intent.JobID || activation.PlanID != intent.PlanID || activation.Generation != intent.SafetyBinding.IntentGeneration || resource.PublicationRecord.LastJobID != intent.JobID {
				return fmt.Errorf("resource %q activation identity does not match durable intent", resource.ID)
			}
		case terminalActivation:
			activation := oldResource.PublicationRecord.ActivationIntent
			if activation.JobID != intent.JobID || resource.PublicationRecord.LastAppliedBundle == nil || !reflect.DeepEqual(*resource.PublicationRecord.LastAppliedBundle, activation.Candidate) || resource.PublicationRecord.LastOperation != domain.OperationPublish || string(resource.PublicationRecord.LastOperationResult) != string(record.Result) {
				return fmt.Errorf("resource %q publication result does not match durable activation", resource.ID)
			}
		case committedRecoveryContraction:
			if resource.PublicationRecord.LastAppliedDigest == nil || !reflect.DeepEqual(resource.PublicationRecord.LastAppliedDigest, oldResource.PublicationRecord.LastAppliedDigest) || !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle, oldResource.PublicationRecord.LastAppliedBundle) || resource.PublicationRecord.LastOperation != oldResource.PublicationRecord.LastOperation || resource.PublicationRecord.LastOperationResult != oldResource.PublicationRecord.LastOperationResult || resource.PublicationRecord.LastJobID != oldResource.PublicationRecord.LastJobID {
				return fmt.Errorf("resource %q committed publication recovery identity changed", resource.ID)
			}
		case interruptedActivation:
			if resource.PublicationRecord.LastAppliedDigest != oldResource.PublicationRecord.LastAppliedDigest || !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle, oldResource.PublicationRecord.LastAppliedBundle) || resource.PublicationRecord.LastOperation != domain.OperationPublish || resource.PublicationRecord.LastOperationResult != domain.OperationInterrupted {
				return fmt.Errorf("resource %q interrupted publication contraction identity changed", resource.ID)
			}
		case failedActivation:
			activation := oldResource.PublicationRecord.ActivationIntent
			if activation.JobID != intent.JobID || resource.PublicationRecord.LastAppliedDigest != oldResource.PublicationRecord.LastAppliedDigest || !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle, oldResource.PublicationRecord.LastAppliedBundle) || resource.PublicationRecord.LastOperation != domain.OperationPublish || resource.PublicationRecord.LastOperationResult != domain.OperationFailed {
				return fmt.Errorf("resource %q failed publication did not preserve exact prior", resource.ID)
			}
		case beginningContraction:
			contraction := resource.PublicationRecord.ContractionIntent
			if contraction.JobID != intent.JobID || contraction.Operation != string(intent.Operation) || contraction.Generation != resource.PublicationRecord.UnpublishedGeneration || contraction.ClosureAuthorityDigest != intent.ContractionDigest || resource.PublicationRecord.LastOperation != oldResource.PublicationRecord.LastOperation || resource.PublicationRecord.LastOperationResult != oldResource.PublicationRecord.LastOperationResult {
				return fmt.Errorf("resource %q running contraction identity does not match its durable intent", resource.ID)
			}
			if err := validateOperationResourceDelta(oldResource, resource, intent.Operation); err != nil {
				return fmt.Errorf("resource %q: %w", resource.ID, err)
			}
		case terminalContraction:
			if oldResource.PublicationRecord.ContractionIntent.JobID != intent.JobID || oldResource.PublicationRecord.ContractionIntent.ClosureAuthorityDigest != intent.ContractionDigest || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.UnpublishedGeneration != oldResource.PublicationRecord.UnpublishedGeneration || string(resource.PublicationRecord.LastOperationResult) != string(record.Result) || !operationCodeMatchesIntent(resource.PublicationRecord.LastOperation, intent.Operation) {
				return fmt.Errorf("resource %q contraction result does not match its running authority", resource.ID)
			}
		case ordinaryLocal:
			if err := validateOperationResourceDelta(oldResource, resource, intent.Operation); err != nil {
				return fmt.Errorf("resource %q: %w", resource.ID, err)
			}
		case ordinaryTerminal:
			if intent.Operation == ProcessStart || intent.Operation == ProcessStop {
				if resource.ManagedProcess == nil || !operationCodeMatchesIntent(resource.ManagedProcess.LastOperation, intent.Operation) || string(resource.ManagedProcess.LastOperationResult) != string(record.Result) {
					return fmt.Errorf("resource %q process state does not match atomic terminal job result", resource.ID)
				}
			} else if !operationCodeMatchesIntent(resource.PublicationRecord.LastOperation, intent.Operation) || string(resource.PublicationRecord.LastOperationResult) != string(record.Result) {
				return fmt.Errorf("resource %q state does not match an atomic terminal job result", resource.ID)
			}
			if err := validateOperationResourceDelta(oldResource, resource, intent.Operation); err != nil {
				return fmt.Errorf("resource %q: %w", resource.ID, err)
			}
		default:
			return fmt.Errorf("resource %q state changed outside an authorized operation phase", resource.ID)
		}
		delete(oldResources, resource.ID)
	}
	if len(oldResources) != 0 {
		return fmt.Errorf("resource state cannot disappear outside its typed deletion operation")
	}
	return nil
}

func validateNewResourceAuthority(document persist.Document, resource domain.AppResource) error {
	var match *Reservation
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return err
		}
		if intent.Operation == ResourceCreate && intent.SafetyBinding.ResourceID == resource.ID && intent.Phase == PhaseLocalIntent {
			if match != nil {
				return fmt.Errorf("new resource has multiple creation authorities")
			}
			copy := intent
			match = &copy
		}
	}
	if match == nil || match.Target != string(plans.TargetInstallation) || match.AdmissionSource != AdmissionUI || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.UnpublishedGeneration != 1 || resource.ManagedProcess == nil || resource.ManagedProcess.Requested != domain.ProcessRequestedStopped || resource.ManagedProcess.Applied != nil {
		return fmt.Errorf("new resource lacks exact authenticated durable creation authority")
	}
	record, err := jobs.LoadEntries(document.Entries, match.JobID)
	if err != nil || record.Status != jobs.StatusRunning {
		return fmt.Errorf("new resource creation job is not running")
	}
	return nil
}

func validateCommittedContractionAuthority(document persist.Document, state safety.State, intent Reservation) error {
	installation, err := loadInstallationEntries(document.Entries)
	if err != nil {
		return err
	}
	affected := 0
	for _, resource := range installation.Resources {
		contraction := resource.PublicationRecord.ContractionIntent
		if contraction == nil || contraction.JobID != intent.JobID {
			continue
		}
		if contraction.ClosureAuthorityDigest != intent.ContractionDigest || contraction.Operation != string(intent.Operation) || contraction.Generation != resource.PublicationRecord.UnpublishedGeneration {
			return fmt.Errorf("committed contraction identity changed before terminalization")
		}
		var safetyResource *safety.ResourceSafety
		for index := range state.Resources {
			if state.Resources[index].ResourceID == resource.ID {
				safetyResource = &state.Resources[index]
				break
			}
		}
		if safetyResource == nil || (safetyResource.Closing == nil || safetyResource.Closing.Generation != contraction.Generation) && (safetyResource.StickyUnpublished == nil || safetyResource.StickyUnpublished.Generation != contraction.Generation) && state.StopFence == nil {
			return fmt.Errorf("committed contraction safety generation is absent")
		}
		affected++
	}
	if affected == 0 && (intent.Operation != CloseAll || len(installation.Resources) != 0) {
		return fmt.Errorf("committed contraction has no affected App")
	}
	if intent.Operation == CloseAll && state.GlobalClose.Generation != intent.SafetyBinding.ProposedGeneration {
		return fmt.Errorf("committed close-all global generation changed")
	}
	return nil
}

func loadInstallationEntries(entries map[string]json.RawMessage) (domain.Installation, error) {
	raw, present := entries["installations/current"]
	if !present {
		return domain.Installation{}, fmt.Errorf("installation authority is missing")
	}
	return domain.DecodeInstallation(raw)
}

func validateOperationResourceDelta(before, after domain.AppResource, operation Type) error {
	if before.Lifecycle != after.Lifecycle {
		return fmt.Errorf("operation %q does not own lifecycle state", operation)
	}
	if operation != ResourceUpdate && operation != ProcessStart && operation != ProcessStop && !reflect.DeepEqual(before.ManagedProcess, after.ManagedProcess) {
		return fmt.Errorf("operation %q does not own managed-process state", operation)
	}
	switch operation {
	case ResourceCreate:
		beforeRecord, afterRecord := before.PublicationRecord, after.PublicationRecord
		beforeRecord.LastOperation = ""
		beforeRecord.LastOperationResult = ""
		beforeRecord.LastJobID = ""
		afterRecord.LastOperation = ""
		afterRecord.LastOperationResult = ""
		afterRecord.LastJobID = ""
		if !reflect.DeepEqual(beforeRecord, afterRecord) || after.PublicationRecord.LastOperation != domain.OperationResourceCreate || after.PublicationRecord.LastOperationResult != domain.OperationSucceeded || after.PublicationRecord.LastJobID == "" || before.ID != after.ID || before.Name != after.Name || before.CurrentConfigDigest != after.CurrentConfigDigest || !reflect.DeepEqual(before.Target, after.Target) || !reflect.DeepEqual(before.Publication, after.Publication) || !reflect.DeepEqual(before.CredentialIDs, after.CredentialIDs) || !reflect.DeepEqual(before.ManagedPaths, after.ManagedPaths) {
			return fmt.Errorf("resource create terminalization changed initial resource authority")
		}
		return nil
	case Publish:
		if after.PublicationRecord.State != domain.PublicationActivating && after.PublicationRecord.State != domain.PublicationPublished {
			return fmt.Errorf("publish did not preserve activating or commit published state")
		}
		return nil
	case StartupContraction:
		if after.PublicationRecord.State != domain.PublicationUnpublished || after.PublicationRecord.UnpublishedGeneration < before.PublicationRecord.UnpublishedGeneration || after.PublicationRecord.UnpublishedGeneration == before.PublicationRecord.UnpublishedGeneration && before.PublicationRecord.State != domain.PublicationUnpublished {
			return fmt.Errorf("startup contraction did not preserve or advance exact unpublished state")
		}
		return nil
	case Unpublish, CloseAll, CertificateExpiry, EdgeOneExpiry, AutomaticReconciliation, Maintenance:
		if after.PublicationRecord.State != domain.PublicationUnpublished || after.PublicationRecord.UnpublishedGeneration <= before.PublicationRecord.UnpublishedGeneration {
			return fmt.Errorf("contraction operation did not commit unpublished state with a fresh generation")
		}
		return nil
	case ResourceUpdate:
		beforePublication, afterPublication := before.PublicationRecord, after.PublicationRecord
		beforePublication.LastOperation = ""
		beforePublication.LastOperationResult = ""
		beforePublication.LastJobID = ""
		afterPublication.LastOperation = ""
		afterPublication.LastOperationResult = ""
		afterPublication.LastJobID = ""
		if before.Lifecycle != after.Lifecycle || !reflect.DeepEqual(beforePublication, afterPublication) || before.ManagedProcess == nil || after.ManagedProcess == nil || before.ManagedProcess.Requested != after.ManagedProcess.Requested || !reflect.DeepEqual(before.ManagedProcess.Applied, after.ManagedProcess.Applied) || !reflect.DeepEqual(before.ManagedProcess.RuntimeObservation, after.ManagedProcess.RuntimeObservation) {
			return fmt.Errorf("resource update changed applied lifecycle or process state")
		}
		return nil
	case ProcessStart:
		if exactProcessNoEffect(before, after) {
			return nil
		}
		interruptedClosed := after.ManagedProcess != nil && after.ManagedProcess.Requested == domain.ProcessRequestedStopped && after.ManagedProcess.LastOperationResult == domain.OperationInterrupted
		if after.ManagedProcess == nil || !interruptedClosed && (after.ManagedProcess.Requested != domain.ProcessRequestedRunning || after.ManagedProcess.Applied == nil) || before.Lifecycle != after.Lifecycle || !reflect.DeepEqual(before.PublicationRecord, after.PublicationRecord) {
			return fmt.Errorf("process start did not commit exact running bundle")
		}
		return nil
	case ProcessStop:
		if exactProcessNoEffect(before, after) {
			return nil
		}
		if after.ManagedProcess == nil || after.ManagedProcess.Requested != domain.ProcessRequestedStopped || before.Lifecycle != after.Lifecycle || !reflect.DeepEqual(before.PublicationRecord, after.PublicationRecord) {
			return fmt.Errorf("process stop did not commit stopped authority")
		}
		return nil
	default:
		return fmt.Errorf("operation %q has no resource-state delta authority", operation)
	}
}

func exactProcessNoEffect(before, after domain.AppResource) bool {
	if before.ManagedProcess == nil || after.ManagedProcess == nil || after.ManagedProcess.LastOperationResult != domain.OperationFailed || before.Lifecycle != after.Lifecycle || !reflect.DeepEqual(before.PublicationRecord, after.PublicationRecord) {
		return false
	}
	prior, current := *before.ManagedProcess, *after.ManagedProcess
	current.LastOperation = prior.LastOperation
	current.LastOperationResult = prior.LastOperationResult
	current.LastJobID = prior.LastJobID
	return reflect.DeepEqual(prior, current)
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

func contractionOperationCode(operation Type) domain.OperationCode {
	if operation == CloseAll {
		return domain.OperationCloseAll
	}
	return domain.OperationUnpublish
}

func operationCodeMatchesIntent(code domain.OperationCode, operation Type) bool {
	switch operation {
	case Publish:
		return code == domain.OperationPublish
	case ResourceCreate:
		return code == domain.OperationResourceCreate
	case ResourceUpdate:
		return code == domain.OperationResourceUpdate
	case ProcessStart:
		return code == domain.OperationProcessStart
	case ProcessStop:
		return code == domain.OperationProcessStop
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
	if (value.SafetyBinding.CertificateIdentity == "") != (value.SafetyBinding.ChallengeMethod == "") || (value.SafetyBinding.CertificateIdentity != "" && ((value.Operation != Publish && value.Operation != CertificateRenew) || !validIdentityRef(value.SafetyBinding.CertificateIdentity) || (value.SafetyBinding.ChallengeMethod != "http-01" && value.SafetyBinding.ChallengeMethod != "dns-01"))) {
		return fmt.Errorf("operation certificate challenge binding invalid")
	}
	if value.SchemaVersion != "lanpanel.operation.reservation.v1" || value.JobID == "" || !validType(value.Operation) || value.Target == "" || value.CreatedAt.IsZero() || !digest(value.SafetyDigest) || value.JournalSafetyDigest != "" && !exactDigest(value.JournalSafetyDigest) || value.ContractionDigest != "" && (!exactDigest(value.ContractionDigest) || !isContraction(value.Operation)) || value.SecretFingerprint != "" && (!exactDigest(value.SecretFingerprint) || value.Operation != AdminTokenRotate) || value.OperationBinding != "" && !exactDigest(value.OperationBinding) || validateAdmissionSource(value.Operation, value.AdmissionSource, value.PlanID) != nil {
		return fmt.Errorf("operation reservation is invalid")
	}
	if handoff := value.CertificateHandoff; handoff != nil {
		if value.Operation != Publish || (value.Phase != PhaseLocalIntent && value.Phase != PhaseTerminal) || handoff.PlanID != value.PlanID || handoff.Generation != value.SafetyBinding.IntentGeneration || handoff.ACMEBinding != value.OperationBinding || !exactDigest(handoff.SANIdentity) || !exactDigest(handoff.ACMEBinding) || !validIdentityRef(handoff.CertificateID) || !exactDigest(handoff.Fingerprint) || !exactDigest(handoff.ChallengeSafetyDigest) {
			return fmt.Errorf("certificate publication handoff invalid")
		}
	}
	if value.Phase != PhaseReserved && value.Phase != PhaseLocalIntent && value.Phase != PhaseRemoteWait && value.Phase != PhaseRejected && value.Phase != PhaseReentered && value.Phase != PhaseTerminal {
		return fmt.Errorf("operation phase is invalid")
	}
	if value.Phase != PhaseReserved && value.Phase != PhaseRejected && value.IntentGeneration == 0 {
		return fmt.Errorf("operation intent generation is missing")
	}
	if value.SecretFingerprint != "" && (value.Phase == PhaseReserved || value.Phase == PhaseRejected || value.Consumption == nil) || value.SecretCommitted && value.SecretFingerprint == "" {
		return fmt.Errorf("secret commit authority precedes durable local intent")
	}
	if value.Phase == PhaseReserved || value.Phase == PhaseRejected {
		if value.Consumption != nil {
			return fmt.Errorf("unconsumed operation has consumption snapshot")
		}
	} else if value.Consumption == nil || value.Consumption.Source != value.AdmissionSource || !digest(value.Consumption.ConfirmationDigest) || !digest(value.Consumption.SafetyDigest) || value.Consumption.ConfirmedAt.IsZero() {
		return fmt.Errorf("operation consumption snapshot is incomplete")
	}
	if value.AdmissionSource == AdmissionUI && value.Consumption != nil && (value.Consumption.Config.Applicable || value.Consumption.Applied.Applicable || len(value.Consumption.Evidence) != 0) {
		return fmt.Errorf("authenticated UI consumption snapshot is invalid")
	}
	return nil
}
func reservationKey(jobID string) string { return "intents/" + jobID }
func validType(value Type) bool {
	switch value {
	case Publish, Unpublish, CloseAll, EmergencyCloseAll, CertificateExpiry, CertificateRenew, ManagedBasicCreate, ManagedBasicRotate, ManagedBasicDelete, StaticRootRegister, ExternalHTPasswdRegister, EdgeOneExpiry, Maintenance, PackageTransaction, AdminTokenRotate, Upgrade, BackupEnter, AutomaticReconciliation, StartupContraction, ResourceCreate, ResourceUpdate, ProcessStart, ProcessStop:
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
		resourceCreate := request.Operation == ResourceCreate && identity == "" && request.SafetyBinding.ResourceID != ""
		if !resourceCreate && (identity != "" || request.SafetyBinding.ResourceID != "") {
			return fmt.Errorf("installation target has unrelated resource safety authority")
		}
	case "credential":
		if (request.Operation != ManagedBasicRotate && request.Operation != ManagedBasicDelete) || identity == "" || !validIdentityRef(request.SafetyBinding.ResourceID) {
			return fmt.Errorf("credential target authority invalid")
		}
	default:
		if request.Operation != AutomaticReconciliation || kind != "journal" || identity == "" {
			return fmt.Errorf("operation target kind is invalid")
		}
	}
	binding := request.SafetyBinding
	if request.Operation == ResourceUpdate && request.Source == AdmissionUI {
		if request.PlanID != "" || binding.PlanID != "" || binding.IntentGeneration != 0 || !exactDigest(binding.CandidateDigest) || !exactDigest(binding.CandidateBundle) {
			return fmt.Errorf("authenticated resource update requires exact prior and candidate digests")
		}
		return nil
	}
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
		case Publish, Unpublish, CloseAll, Maintenance, PackageTransaction, AdminTokenRotate, ManagedBasicDelete, BackupEnter:
		default:
			return fmt.Errorf("operation is not valid for Plan admission")
		}
	case AdmissionTimer:
		if planID != "" || operation != CertificateExpiry && operation != CertificateRenew && operation != EdgeOneExpiry && operation != AutomaticReconciliation {
			return fmt.Errorf("timer admission is not authorized for operation")
		}
	case AdmissionStartup:
		if planID != "" || operation != AutomaticReconciliation && operation != StartupContraction {
			return fmt.Errorf("startup admission is not authorized for operation")
		}
	case AdmissionUI:
		if planID != "" || operation != ResourceCreate && operation != ResourceUpdate && operation != ProcessStart && operation != ProcessStop && operation != ManagedBasicCreate && operation != ManagedBasicRotate && operation != StaticRootRegister && operation != ExternalHTPasswdRegister {
			return fmt.Errorf("authenticated UI admission is not authorized for operation")
		}
	default:
		return fmt.Errorf("operation admission source is unsupported")
	}
	return nil
}
func SafetyBindingDigest(binding SafetyBinding) (string, error) { return safetyBindingDigest(binding) }
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
