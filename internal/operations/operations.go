// Package operations implements durable admission, Plan consumption, phase
// intents, and exhaustive result contracts for normal mutations.
package operations

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/certificates"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/publication"
	appresource "lanpanel/internal/resource"
	"lanpanel/internal/safety"
	"lanpanel/internal/storeauthority"
	"reflect"
	"slices"
	"sort"
	"strconv"
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
	AdminTokenRotate         Type = "admin_token_rotate"
	AutomaticReconciliation  Type = "automatic_exact_journal_reconciliation"
	StartupContraction       Type = "startup_activation_contraction"
	GoAccessRetirement       Type = "goaccess_retirement_reconciliation"
	HeadscaleInitialize      Type = "headscale_initialize"
	HeadscaleDeploy          Type = "headscale_control_deploy"
	HeadscaleUserCreate      Type = "headscale_user_create"
	PreauthKeyCreate         Type = "preauth_key_create"
	PreauthKeyRevoke         Type = "preauth_key_revoke"
	DeviceExpire             Type = "device_expire"
	ConnectorBindingSet      Type = "connector_binding_set"
	ConnectorLogin           Type = "connector_login"
	ResourceCreate           Type = "resource_create"
	ResourceUpdate           Type = "resource_update"
	ResourceDelete           Type = "resource_delete"
	ProcessStart             Type = "process_start"
	ProcessStop              Type = "process_stop"
)

const (
	maximumTerminalOperationGraphs = 512
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
	GlobalGeneration        uint64                              `json:"global_generation,omitempty"`
	ExpiryGeneration        uint64                              `json:"expiry_generation,omitempty"`
	ResourceID              string                              `json:"resource_id,omitempty"`
	Deadline                time.Time                           `json:"deadline"`
	ProposedGeneration      uint64                              `json:"proposed_generation,omitempty"`
	PlanID                  string                              `json:"plan_id,omitempty"`
	IntentGeneration        uint64                              `json:"intent_generation,omitempty"`
	CandidateDigest         string                              `json:"candidate_digest,omitempty"`
	CandidateBundle         string                              `json:"candidate_bundle,omitempty"`
	PriorFingerprint        string                              `json:"prior_fingerprint,omitempty"`
	ChallengeMethod         string                              `json:"challenge_method,omitempty"`
	CertificateIdentity     string                              `json:"certificate_identity,omitempty"`
	ACMEBinding             string                              `json:"acme_binding,omitempty"`
	InstallationID          string                              `json:"installation_id,omitempty"`
	GoAccessSource          string                              `json:"goaccess_source,omitempty"`
	GoAccessSourceJobID     string                              `json:"goaccess_source_job_id,omitempty"`
	GoAccessSourceJournalID string                              `json:"goaccess_source_journal_id,omitempty"`
	GoAccessAuthorityDigest string                              `json:"goaccess_authority_digest,omitempty"`
	GoAccessRetirements     []domain.GoAccessRetirementIdentity `json:"goaccess_retirements,omitempty"`
}
type AdmissionSource string

const (
	AdmissionPlan         AdmissionSource = "plan"
	AdmissionTimer        AdmissionSource = "timer"
	AdmissionStartup      AdmissionSource = "startup"
	AdmissionRuntimeGuard AdmissionSource = "runtime_guard"
	AdmissionUI           AdmissionSource = "authenticated_ui"
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
type HeadscaleInitializationBinding struct {
	Candidate        domain.HeadscaleDomain     `json:"candidate"`
	Snapshot         json.RawMessage            `json:"snapshot"`
	PreflightRequest preflight.ExpansionRequest `json:"preflight_request"`
	PreflightResult  preflight.Result           `json:"preflight_result"`
}
type HeadscaleDeployBinding struct {
	Candidate        control.Candidate          `json:"candidate"`
	PreflightRequest preflight.ExpansionRequest `json:"preflight_request"`
	PreflightResult  preflight.Result           `json:"preflight_result"`
}

// ResourceDeleteBinding survives normal/safety removal so a resumed delete
// can freshly verify the same endpoints and finish only its frozen inventory.
type ResourceDeleteBinding struct {
	InstallationID string             `json:"installation_id"`
	Resource       domain.AppResource `json:"resource"`
	Ownership      ownership.Record   `json:"ownership"`
}

type ExpiryGenerationRecord struct {
	SchemaVersion    string    `json:"schema_version"`
	ResourceID       string    `json:"resource_id"`
	Target           string    `json:"target"`
	ExpiryGeneration uint64    `json:"expiry_generation"`
	JobID            string    `json:"job_id"`
	CreatedAt        time.Time `json:"created_at"`
}

type Reservation struct {
	SchemaVersion       string                          `json:"schema_version"`
	JobID               string                          `json:"job_id"`
	PlanID              string                          `json:"plan_id,omitempty"`
	OperationBinding    string                          `json:"operation_binding,omitempty"`
	CertificateHandoff  *CertificatePublicationHandoff  `json:"certificate_handoff,omitempty"`
	HeadscaleBinding    *HeadscaleInitializationBinding `json:"headscale_initialization,omitempty"`
	HeadscaleDeploy     *HeadscaleDeployBinding         `json:"headscale_deploy,omitempty"`
	ResourceDelete      *ResourceDeleteBinding          `json:"resource_delete,omitempty"`
	AdmissionSource     AdmissionSource                 `json:"admission_source"`
	Operation           Type                            `json:"operation"`
	Target              string                          `json:"target"`
	Phase               Phase                           `json:"phase"`
	SafetyDigest        string                          `json:"safety_digest"`
	JournalSafetyDigest string                          `json:"journal_safety_digest,omitempty"`
	ContractionDigest   string                          `json:"contraction_digest,omitempty"`
	SecretFingerprint   string                          `json:"secret_fingerprint,omitempty"`
	SecretCommitted     bool                            `json:"secret_committed,omitempty"`
	SafetyBinding       SafetyBinding                   `json:"safety_binding"`
	CreatedAt           time.Time                       `json:"created_at"`
	IntentGeneration    uint64                          `json:"intent_generation,omitempty"`
	Consumption         *ConsumptionSnapshot            `json:"consumption,omitempty"`
}

type ContractionCommit struct {
	ClosureAuthorityDigest string
	UnpublishedGenerations map[string]uint64
}

type HeadscaleInitializeCommit struct {
	Headscale domain.HeadscaleDomain
}
type HeadscaleDeployBeginCommit struct {
	HeadscaleID string
	Intent      domain.HeadscaleDeployIntent
}
type HeadscaleDeployStagedCommit struct {
	HeadscaleID       string
	InitializedDigest string
}
type HeadscaleCertificateStagedCommit struct {
	HeadscaleID string
	Fingerprint string
}
type HeadscaleActivationIntentCommit struct {
	HeadscaleID      string
	ActivationDigest string
}
type HeadscaleActivatedCommit struct {
	HeadscaleID   string
	RuntimeDigest string
	Applied       domain.HeadscaleAppliedIdentity
}
type HeadscaleDeployCompleteCommit struct {
	HeadscaleID   string
	Certificate   domain.CertificateBundleIdentity
	RuntimeDigest string
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
	ResourceID                string
	Bundle                    domain.PublicationBundle
	Runtime                   domain.RuntimeObservation
	GoAccessRetirementPending bool
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
	JournalAppContraction        JournalKind = "app_contraction"
	JournalAppActivation         JournalKind = "app_activation"
	JournalCertificateActivation JournalKind = "certificate_activation"

	JournalPrepared JournalPhase = "prepared"
	JournalActive   JournalPhase = "active"
	JournalTerminal JournalPhase = "terminal"
)

type CertificateJournalIdentity struct {
	CertificateID           string                      `json:"certificate_id"`
	PriorGeneration         uint64                      `json:"prior_generation,omitempty"`
	CandidateGeneration     uint64                      `json:"candidate_generation"`
	PriorPointer            string                      `json:"prior_pointer,omitempty"`
	CandidatePointer        string                      `json:"candidate_pointer"`
	PriorFingerprint        string                      `json:"prior_fingerprint,omitempty"`
	CandidateFingerprint    string                      `json:"candidate_fingerprint,omitempty"`
	PriorBundleIdentity     certificates.BundleIdentity `json:"prior_bundle_identity"`
	CandidateBundleIdentity certificates.BundleIdentity `json:"candidate_bundle_identity"`
	Challenge               safety.ChallengePending     `json:"challenge"`
	StageUID                uint32                      `json:"stage_uid,omitempty"`
	StageGID                uint32                      `json:"stage_gid,omitempty"`
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
	RuntimeDigest      string                      `json:"runtime_digest,omitempty"`
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
	HeadscaleBinding *HeadscaleInitializationBinding
	HeadscaleDeploy  *HeadscaleDeployBinding
	ResourceDelete   *ResourceDeleteBinding
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
	if !normal.NamespaceRegistered("expiry_generations") {
		if err := normal.RegisterCanonicalNamespace("expiry_generations", "operations.expiry.generations.v1", validateExpiryGenerationEntry, validateExpiryGenerationTransition); err != nil {
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

func (admitter *Admitter) TrustedNow() (time.Time, error) { return admitter.trustedNow() }
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
	for _, key := range persist.EntryKeys(document, "expiry_generations") {
		highWater, err := decodeExpiryGenerationRecord(document.Entries[key])
		if err != nil {
			return time.Time{}, err
		}
		take(highWater.CreatedAt)
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
	if err := validateHeadscaleInitializationBinding(request.Operation, request.SafetyBinding, request.HeadscaleBinding); err != nil {
		return jobs.Record{}, err
	}
	if err := validateHeadscaleDeployBinding(request.Operation, request.SafetyBinding, request.HeadscaleDeploy); err != nil {
		return jobs.Record{}, err
	}
	if err := validateResourceDeleteBinding(request.Operation, request.SafetyBinding, request.ResourceDelete); err != nil {
		return jobs.Record{}, err
	}
	if request.Operation == HeadscaleInitialize {
		if err := preflight.RequireExpansionResultForRequest(request.HeadscaleBinding.PreflightResult, request.HeadscaleBinding.PreflightRequest, observedNow); err != nil {
			return jobs.Record{}, err
		}
	}
	if request.Operation == HeadscaleDeploy {
		if err := preflight.RequireExpansionResultForRequest(request.HeadscaleDeploy.PreflightResult, request.HeadscaleDeploy.PreflightRequest, observedNow); err != nil {
			return jobs.Record{}, err
		}
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
	reservation := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, PlanID: request.PlanID, AdmissionSource: request.Source, Operation: request.Operation, Target: request.Target, Phase: PhaseReserved, SafetyDigest: digest, SafetyBinding: request.SafetyBinding, HeadscaleBinding: request.HeadscaleBinding, HeadscaleDeploy: request.HeadscaleDeploy, ResourceDelete: request.ResourceDelete, CreatedAt: observedNow}
	_, _, err = admitter.normal.Update(ctx, admission, request.ExpectedRevision, func(transaction *persist.Transaction) error {
		switch request.Operation {
		case ResourceCreate, ResourceUpdate, Publish, ProcessStart, HeadscaleInitialize, HeadscaleDeploy:
			if err := requireCompletedRemovedResourceDeletes(transaction); err != nil {
				return err
			}
		}
		if request.Operation == ResourceDelete {
			installation, err := loadInstallation(transaction)
			if err != nil {
				return err
			}
			if err := matchResourceDeleteAdmission(installation, request.ResourceDelete); err != nil {
				return err
			}
		}
		if request.Operation == Publish {
			installation, err := loadInstallation(transaction)
			if err != nil {
				return err
			}
			if err := validatePublicationInventory(installation, state); err != nil {
				return err
			}
		}
		active, err := activeGraphCount(transaction)
		if err != nil {
			return err
		}
		if active >= maximumActiveOperationGraphs {
			return fmt.Errorf("active operation graph limit %d is reached", maximumActiveOperationGraphs)
		}
		if !isContraction(request.Operation) && request.SafetyBinding.ResourceID != "" && request.SafetyBinding.ResourceID != "headscale" {
			if raw, present := transaction.Get(expiryGenerationKey(request.SafetyBinding.ResourceID)); present {
				highWater, err := decodeExpiryGenerationRecord(raw)
				if err != nil {
					return err
				}
				for _, resource := range state.Resources {
					if resource.ResourceID == request.SafetyBinding.ResourceID && resource.CertificateExpiry == nil && highWater.ExpiryGeneration == resource.GenerationSequence+1 {
						return fmt.Errorf("target has a recorded certificate expiry contraction")
					}
				}
			}
		}
		if request.Operation == CertificateExpiry && request.SafetyBinding.ResourceID != "headscale" {
			if raw, present := transaction.Get(expiryGenerationKey(request.SafetyBinding.ResourceID)); present {
				highWater, err := decodeExpiryGenerationRecord(raw)
				if err != nil {
					return err
				}
				if request.SafetyBinding.ExpiryGeneration <= highWater.ExpiryGeneration {
					return fmt.Errorf("certificate expiry generation already has an operation graph")
				}
			}
			for _, key := range transaction.Keys("intents") {
				raw, _ := transaction.Get(key)
				existing, err := decodeReservation(raw)
				if err != nil {
					return err
				}
				if existing.Operation == CertificateExpiry && existing.SafetyBinding.ResourceID == request.SafetyBinding.ResourceID && existing.SafetyBinding.ExpiryGeneration == request.SafetyBinding.ExpiryGeneration {
					return fmt.Errorf("certificate expiry generation already has an operation graph")
				}
				if existing.Operation == ResourceDelete && existing.SafetyBinding.ResourceID == request.SafetyBinding.ResourceID && existing.Phase != PhaseTerminal && existing.Phase != PhaseRejected {
					return fmt.Errorf("certificate expiry is blocked by nonterminal resource deletion")
				}
			}
		}
		if !isContraction(request.Operation) {
			for _, key := range transaction.Keys("intents") {
				raw, _ := transaction.Get(key)
				existing, err := decodeReservation(raw)
				if err != nil {
					return err
				}
				sameResource := existing.Target == request.Target || existing.SafetyBinding.ResourceID != "" && existing.SafetyBinding.ResourceID == request.SafetyBinding.ResourceID
				if sameResource && existing.Operation == CertificateExpiry && existing.Phase != PhaseTerminal && existing.Phase != PhaseRejected {
					return fmt.Errorf("target has a nonterminal certificate expiry contraction")
				}
				if sameResource && existing.Operation == AutomaticReconciliation && existing.SafetyBinding.ResourceID == "headscale" && strings.HasPrefix(existing.Target, "journal/headscale-certificate-expiry-") && existing.Phase != PhaseTerminal && existing.Phase != PhaseRejected {
					return fmt.Errorf("headscale certificate action is blocked by expiry reconciliation")
				}
				if sameResource && !isContraction(existing.Operation) && existing.Phase != PhaseTerminal && existing.Phase != PhaseRejected {
					return fmt.Errorf("target already has a nonterminal expansion authority")
				}
			}
		}
		if request.Operation == CertificateExpiry && request.SafetyBinding.ResourceID != "headscale" {
			highWater := ExpiryGenerationRecord{SchemaVersion: "lanpanel.operation.expiry-generation.v1", ResourceID: request.SafetyBinding.ResourceID, Target: request.Target, ExpiryGeneration: request.SafetyBinding.ExpiryGeneration, JobID: record.ID, CreatedAt: observedNow}
			raw, encodeErr := persist.EncodeEntry(highWater)
			if encodeErr != nil {
				return encodeErr
			}
			key := expiryGenerationKey(highWater.ResourceID)
			if _, present := transaction.Get(key); present {
				if err := transaction.Replace(key, raw); err != nil {
					return err
				}
			} else if err := transaction.Create(key, raw); err != nil {
				return err
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
			reservation, err := loadReservation(transaction, jobID)
			if err != nil {
				return err
			}
			record, err := jobs.Load(transaction, jobID)
			if err != nil {
				return err
			}
			if reservation.Phase != PhaseReserved || record.Status != jobs.StatusReserved {
				return fmt.Errorf("reservation is no longer reserved")
			}
			record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultFailed, Postconditions: []jobs.Postcondition{{Kind: "mutation_not_started", Status: jobs.PostconditionVerified, Identity: jobID}}, ErrorCode: code}, observedNow)
			if err != nil {
				return err
			}
			if err := jobs.Replace(transaction, record); err != nil {
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
		if reservation.Operation == Publish {
			installation, err := loadInstallation(transaction)
			if err != nil {
				return err
			}
			if err := validatePublicationInventory(installation, state); err != nil {
				return err
			}
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
			return fmt.Errorf("plan does not match the reserved operation target")
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

// BeginPlanless starts a previously admitted timer, startup, or runtime-guard
// operation only after mutation→exposure acquisition. It records the same
// immutable local intent boundary as Plan consumption without fabricating a UI
// Plan.
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
		if reservation.AdmissionSource != AdmissionTimer && reservation.AdmissionSource != AdmissionStartup && reservation.AdmissionSource != AdmissionRuntimeGuard {
			return fmt.Errorf("operation reservation is not a timer, startup, or runtime-guard admission")
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
		if (reservation.Phase != PhaseLocalIntent && reservation.Phase != PhaseReentered) || (reservation.AdmissionSource != AdmissionPlan && (reservation.AdmissionSource != AdmissionTimer || reservation.Operation != CertificateRenew) && (reservation.AdmissionSource != AdmissionUI || reservation.Operation != HeadscaleInitialize && reservation.Operation != HeadscaleUserCreate)) {
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

func (admitter *Admitter) ReenterHeadscaleChallengeContraction(ctx context.Context, mutationSet *MutationSet, manager *locks.Manager, expectedRevision uint64, jobID, childID, closureDigest string) (Reservation, ChildRecord, *MutationLease, *locks.Lease, error) {
	if admitter == nil || mutationSet == nil || manager == nil || !exactDigest(closureDigest) {
		return Reservation{}, ChildRecord{}, nil, nil, fmt.Errorf("headscale challenge contraction authority is invalid")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return Reservation{}, ChildRecord{}, nil, nil, err
	}
	document, err := admitter.normal.Read()
	if err != nil || document.Revision != expectedRevision {
		return Reservation{}, ChildRecord{}, nil, nil, errors.Join(err, persist.ErrRevision)
	}
	intent, err := loadReservationEntries(document.Entries, jobID)
	recoverable := intent.Operation == HeadscaleDeploy && intent.HeadscaleDeploy != nil || intent.Operation == CertificateRenew && strings.HasPrefix(intent.Target, "headscale/")
	if err != nil || !recoverable || intent.Consumption == nil || (intent.Phase != PhaseLocalIntent && intent.Phase != PhaseRemoteWait && intent.Phase != PhaseReentered && intent.Phase != PhaseTerminal) {
		return Reservation{}, ChildRecord{}, nil, nil, fmt.Errorf("headscale challenge is not contraction-recoverable")
	}
	state, err := admitter.safety.Read()
	if err != nil || !exactCertificateChallenge(state, intent.Operation, intent.SafetyBinding) {
		return Reservation{}, ChildRecord{}, nil, nil, fmt.Errorf("headscale challenge contraction safety authority changed")
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, manager)
	if err != nil {
		return Reservation{}, ChildRecord{}, nil, nil, err
	}
	fail := func(cause error) (Reservation, ChildRecord, *MutationLease, *locks.Lease, error) {
		return Reservation{}, ChildRecord{}, nil, nil, errors.Join(cause, ReleaseExposure(mutation, exposure))
	}
	if intent.Phase == PhaseTerminal {
		rawChild, present := document.Entries["children/"+childID]
		var current ChildRecord
		if !present || decodeStrict(rawChild, &current) != nil || current.ID != childID || current.JobID != jobID || current.State != ChildTerminal {
			return fail(fmt.Errorf("terminal Headscale contraction child authority changed"))
		}
		return intent, current, mutation, exposure, nil
	}
	var result Reservation
	var childResult ChildRecord
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		fresh, err := loadReservation(transaction, jobID)
		if err != nil || !reflect.DeepEqual(fresh, intent) {
			return errors.Join(err, fmt.Errorf("headscale contraction intent changed"))
		}
		rawChild, present := transaction.Get("children/" + childID)
		if !present {
			return fmt.Errorf("headscale contraction child is missing")
		}
		var current ChildRecord
		if err := decodeStrict(rawChild, &current); err != nil || current.ID != childID || current.JobID != jobID || current.Operation != fresh.Operation || current.Target != fresh.Target || current.IntentGeneration != fresh.IntentGeneration {
			return fmt.Errorf("headscale contraction child authority changed")
		}
		if current.State != ChildTerminal {
			current.State = ChildTerminal
			current.TerminalAt = &observedNow
			current.Outcome = ChildUnknown
			current.ResultDigest = closureDigest
			encodedChild, err := persist.EncodeEntry(current)
			if err != nil {
				return err
			}
			if err := transaction.Replace("children/"+childID, encodedChild); err != nil {
				return err
			}
		}
		if fresh.Phase == PhaseRemoteWait {
			fresh.Phase = PhaseReentered
		}
		encodedIntent, err := persist.EncodeEntry(fresh)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), encodedIntent); err != nil {
			return err
		}
		result, childResult = fresh, current
		return nil
	})
	if err != nil {
		return fail(err)
	}
	return result, childResult, mutation, exposure, nil
}

func (admitter *Admitter) ContractHeadscaleDeployChallenge(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, journalID string) error {
	if admitter == nil || !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("headscale challenge terminal contraction requires exact locks")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return err
	}
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil || intent.Operation != HeadscaleDeploy || intent.HeadscaleDeploy == nil || mutation.Target() != intent.Target {
			return fmt.Errorf("headscale challenge contraction intent changed")
		}
		installation, err := loadInstallation(transaction)
		if err != nil || installation.Headscale == nil || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.JobID != jobID {
			return fmt.Errorf("headscale challenge contraction domain authority changed")
		}
		journalRaw, present := transaction.Get("journals/" + journalID)
		var journal JournalRecord
		if !present || decodeStrict(journalRaw, &journal) != nil || journal.ID != journalID || journal.JobID != jobID || journal.Kind != JournalCertificateActivation || (journal.Phase != JournalPrepared && journal.Phase != JournalActive && journal.Phase != JournalTerminal) {
			return fmt.Errorf("headscale challenge contraction journal changed")
		}
		if intent.Phase == PhaseTerminal {
			record, recordErr := jobs.Load(transaction, jobID)
			if recordErr != nil || record.Status != jobs.StatusTerminal || installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployContracted || journal.Phase != JournalTerminal {
				return fmt.Errorf("headscale challenge terminal authority is incomplete")
			}
			return nil
		}
		if (intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered) || (installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployCertificatePending && installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployCertificateStaged && installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployActivating && installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployActivated) {
			return fmt.Errorf("headscale challenge is not terminal-contractible")
		}
		for _, childID := range journal.ChildIDs {
			rawChild, present := transaction.Get("children/" + childID)
			var child ChildRecord
			if !present || decodeStrict(rawChild, &child) != nil || child.JobID != jobID || child.State != ChildTerminal {
				return fmt.Errorf("headscale challenge child closure is incomplete")
			}
		}
		journal.Phase = JournalTerminal
		encodedJournal, err := persist.EncodeEntry(journal)
		if err != nil {
			return err
		}
		if err := transaction.Replace("journals/"+journalID, encodedJournal); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "headscale_candidate_contracted", Status: jobs.PostconditionVerified, Identity: jobID}}, ErrorCode: "certificate_executor_interrupted"}, observedNow)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		intent.Phase = PhaseTerminal
		encodedIntent, err := persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), encodedIntent); err != nil {
			return err
		}
		headscale := *installation.Headscale
		deploy := *headscale.DeployIntent
		deploy.Phase = domain.HeadscaleDeployContracted
		deploy.RuntimeDigest = ""
		if deploy.Prior == nil {
			headscale.Applied = nil
			headscale.Enabled = false
		} else {
			prior := *deploy.Prior
			headscale.Applied = &prior
			headscale.Enabled = true
		}
		headscale.DeployIntent = &deploy
		installation.Headscale = &headscale
		encodedInstallation, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", encodedInstallation)
	})
	return err
}

func (admitter *Admitter) EnterRemoteWait(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) (Reservation, error) {
	reservation, err := admitter.markRemoteWait(ctx, mutation, exposure, expectedRevision, jobID)
	releaseErr := ReleaseExposure(mutation, exposure)
	return reservation, errors.Join(err, releaseErr)
}

func (admitter *Admitter) ReenterHeadscaleActivationContraction(ctx context.Context, mutationSet *MutationSet, manager *locks.Manager, expectedRevision uint64, jobID string) (Reservation, *MutationLease, *locks.Lease, error) {
	if admitter == nil || mutationSet == nil || manager == nil {
		return Reservation{}, nil, nil, fmt.Errorf("headscale activation contraction authority invalid")
	}
	document, err := admitter.normal.Read()
	if err != nil || document.Revision != expectedRevision {
		return Reservation{}, nil, nil, errors.Join(err, persist.ErrRevision)
	}
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil || intent.Operation != HeadscaleDeploy || intent.HeadscaleDeploy == nil || intent.Consumption == nil || (intent.Phase != PhaseReentered && intent.Phase != PhaseTerminal) {
		return Reservation{}, nil, nil, fmt.Errorf("headscale activation is not contraction-recoverable")
	}
	installationRaw, present := document.Entries["installations/current"]
	installation, decodeErr := domain.DecodeInstallation(installationRaw)
	if !present || decodeErr != nil || installation.Headscale == nil || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.JobID != jobID {
		return Reservation{}, nil, nil, fmt.Errorf("headscale activation contraction domain authority changed")
	}
	phase := installation.Headscale.DeployIntent.Phase
	if phase != domain.HeadscaleDeployCertificateStaged && phase != domain.HeadscaleDeployActivating && phase != domain.HeadscaleDeployActivated && phase != domain.HeadscaleDeployContracted || intent.Phase == PhaseTerminal && phase != domain.HeadscaleDeployContracted {
		return Reservation{}, nil, nil, fmt.Errorf("headscale activation domain phase is not recoverable")
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, manager)
	if err != nil {
		return Reservation{}, nil, nil, err
	}
	fail := func(cause error) (Reservation, *MutationLease, *locks.Lease, error) {
		return Reservation{}, nil, nil, errors.Join(cause, ReleaseExposure(mutation, exposure))
	}
	fresh, err := admitter.normal.Read()
	if err != nil || fresh.Revision != expectedRevision {
		return fail(errors.Join(err, persist.ErrRevision))
	}
	state, err := admitter.safety.Read()
	if err != nil || !validStartupBinding(state, intent.SafetyBinding) {
		return fail(fmt.Errorf("headscale activation contraction safety authority changed: %w", err))
	}
	return intent, mutation, exposure, nil
}

// ReenterHTTP01Contraction reacquires an operation solely to remove its exact
// durable HTTP-01 presentation. Unlike expansion reentry, contraction remains
// available after Plan evidence expires.
func (admitter *Admitter) ReenterHTTP01Contraction(ctx context.Context, mutationSet *MutationSet, manager *locks.Manager, expectedRevision uint64, jobID string) (Reservation, *MutationLease, *locks.Lease, error) {
	if admitter == nil || mutationSet == nil || manager == nil {
		return Reservation{}, nil, nil, fmt.Errorf("HTTP-01 contraction authority is invalid")
	}
	document, err := admitter.normal.Read()
	if err != nil || document.Revision != expectedRevision {
		return Reservation{}, nil, nil, errors.Join(err, persist.ErrRevision)
	}
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil || intent.Phase != PhaseRemoteWait && intent.Phase != PhaseReentered || intent.Consumption == nil || intent.Operation != Publish && intent.Operation != CertificateRenew && intent.Operation != HeadscaleDeploy {
		return Reservation{}, nil, nil, fmt.Errorf("operation is not in HTTP-01 remote wait or reentry")
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, manager)
	if err != nil {
		return Reservation{}, nil, nil, err
	}
	fail := func(cause error) (Reservation, *MutationLease, *locks.Lease, error) {
		return Reservation{}, nil, nil, errors.Join(cause, ReleaseExposure(mutation, exposure))
	}
	state, err := admitter.safety.Read()
	if err != nil || !exactHTTP01Challenge(state, intent.Operation, intent.SafetyBinding) {
		return fail(errors.Join(err, fmt.Errorf("HTTP-01 contraction safety authority changed")))
	}
	var result Reservation
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		fresh, err := loadReservation(transaction, jobID)
		if err != nil || !reflect.DeepEqual(fresh, intent) {
			return errors.Join(err, fmt.Errorf("HTTP-01 contraction intent changed"))
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
	if intent.Operation == Publish {
		installation, err := loadInstallationEntries(document.Entries)
		if err != nil {
			return fail(err)
		}
		if err := validatePublicationInventory(installation, state); err != nil {
			return fail(err)
		}
	}
	currentDigest, err := safetyDigest(state)
	if err != nil {
		return fail(err)
	}
	if intent.Consumption == nil || currentDigest != intent.Consumption.SafetyDigest && !exactCertificateChallenge(state, intent.Operation, intent.SafetyBinding) && !exactCertificatePublicationAuthority(state, intent) {
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
			return fail(fmt.Errorf("plan-derived binding changed during remote wait"))
		}
	} else if (intent.AdmissionSource != AdmissionTimer || intent.Operation != CertificateRenew) && (intent.AdmissionSource != AdmissionUI || intent.Operation != HeadscaleInitialize && intent.Operation != HeadscaleUserCreate) {
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

func requireManagedBasicCandidateChild(transaction *persist.Transaction, jobID, fingerprint string) error {
	matches := 0
	for _, key := range transaction.Keys("children") {
		raw, _ := transaction.Get(key)
		var child ChildRecord
		if err := decodeStrict(raw, &child); err != nil {
			return err
		}
		if child.JobID != jobID {
			continue
		}
		matches++
		if child.Profile != "htpasswd" || child.State != ChildTerminal || child.Outcome != ChildSucceeded || child.ResultDigest != fingerprint {
			return fmt.Errorf("managed Basic candidate child result changed")
		}
	}
	if matches != 1 {
		return fmt.Errorf("managed Basic candidate requires one exact terminal child")
	}
	return nil
}

func requireManagedBasicCandidateChildEntries(entries map[string]json.RawMessage, jobID, fingerprint string) error {
	matches := 0
	for key, raw := range entries {
		if !strings.HasPrefix(key, "children/") {
			continue
		}
		var child ChildRecord
		if err := decodeStrict(raw, &child); err != nil {
			return err
		}
		if child.JobID != jobID {
			continue
		}
		matches++
		if child.Profile != "htpasswd" || child.State != ChildTerminal || child.Outcome != ChildSucceeded || child.ResultDigest != fingerprint {
			return fmt.Errorf("managed Basic candidate child result changed")
		}
	}
	if matches != 1 {
		return fmt.Errorf("managed Basic candidate requires one exact terminal child")
	}
	return nil
}

func (admitter *Admitter) CommitManagedBasicCreate(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, credential domain.Credential) error {
	binding, bindingErr := canonicalValueDigest(credential)
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || credential.Kind != "managed_basic" || !exactDigest(credential.Fingerprint) || bindingErr != nil {
		return fmt.Errorf("managed Basic create requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ManagedBasicCreate || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+credential.OwnerResourceID || mutation.Target() != intent.Target || intent.SafetyBinding.ResourceID != credential.OwnerResourceID || intent.OperationBinding != binding {
			return fmt.Errorf("managed Basic create intent mismatched")
		}
		if err := requireManagedBasicCandidateChild(transaction, jobID, credential.Fingerprint); err != nil {
			return err
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

func (admitter *Admitter) CommitManagedBasicFingerprint(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, prior domain.Credential, fingerprint string) error {
	candidate := prior
	candidate.Fingerprint = fingerprint
	binding, bindingErr := canonicalValueDigest(candidate)
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || prior.Kind != "managed_basic" || !exactDigest(prior.Fingerprint) || !exactDigest(fingerprint) || bindingErr != nil {
		return fmt.Errorf("managed Basic commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ManagedBasicRotate || intent.Phase != PhaseLocalIntent || intent.Target != "credential/"+prior.ID || mutation.Target() != intent.Target || intent.SafetyBinding.ResourceID != prior.OwnerResourceID || intent.SafetyBinding.PriorFingerprint != prior.Fingerprint || intent.OperationBinding != binding {
			return fmt.Errorf("managed Basic intent mismatched")
		}
		if err := requireManagedBasicCandidateChild(transaction, jobID, fingerprint); err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Credentials {
			credential := &installation.Credentials[index]
			if credential.ID != prior.ID {
				continue
			}
			if *credential != prior {
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

func (admitter *Admitter) CommitManagedBasicDelete(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, prior domain.Credential) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || prior.Kind != "managed_basic" || !exactDigest(prior.Fingerprint) {
		return fmt.Errorf("managed Basic delete requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ManagedBasicDelete || intent.Phase != PhaseLocalIntent || intent.Target != "credential/"+prior.ID || mutation.Target() != intent.Target || intent.SafetyBinding.ResourceID != prior.OwnerResourceID || intent.SafetyBinding.PriorFingerprint != prior.Fingerprint {
			return fmt.Errorf("managed Basic delete intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		for _, resource := range installation.Resources {
			if credentialReferenced(resource, prior.ID) {
				return fmt.Errorf("active resource reference blocks credential delete")
			}
		}
		kept := installation.Credentials[:0]
		found := false
		for _, credential := range installation.Credentials {
			if credential.ID == prior.ID {
				if credential != prior {
					return fmt.Errorf("managed Basic credential identity changed")
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
			if len(resource.PublicationRecord.PendingGoAccessRetirements) != 0 {
				return fmt.Errorf("certificate renewal commit found pending GoAccess retirement")
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
		identityMatches := ((intent.Operation == Publish || intent.Operation == CertificateRenew) && intent.Target == "resource/"+intent.SafetyBinding.ResourceID || intent.Operation == CertificateRenew && strings.HasPrefix(intent.Target, "headscale/") && intent.SafetyBinding.ResourceID == "headscale") && intent.SafetyBinding.PlanID == pending.PlanID && intent.SafetyBinding.IntentGeneration == pending.Generation && intent.SafetyBinding.CandidateDigest == pending.SANIdentity && intent.SafetyBinding.CandidateBundle == pending.ACMEBinding
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
		if err := retainResourceCertificateArtifact(transaction, journal); err != nil {
			return err
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

// PendingCertificateRecovery reports certificate work that has not reached a
// terminal operation phase. The guard uses the document it already read so a
// certificate journal cannot be checked against a different normal-state
// snapshot.
func PendingCertificateRecovery(document persist.Document) error {
	certificateJobs := map[string]bool{}
	for _, key := range persist.EntryKeys(document, "journals") {
		var journal JournalRecord
		if err := decodeStrict(document.Entries[key], &journal); err != nil {
			return fmt.Errorf("certificate journal authority is invalid: %w", err)
		}
		if journal.Kind == JournalCertificateActivation && journal.Phase != JournalTerminal {
			certificateJobs[journal.JobID] = true
		}
	}
	ids := []string{}
	for _, key := range persist.EntryKeys(document, "intents") {
		var intent Reservation
		if err := decodeStrict(document.Entries[key], &intent); err != nil {
			return fmt.Errorf("certificate intent authority is invalid: %w", err)
		}
		if certificateJobs[intent.JobID] && intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
			ids = append(ids, intent.JobID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return fmt.Errorf("interrupted certificate operation requires contraction: %s", strings.Join(ids, ","))
}

// PendingPublicationRecovery reports publication work that must be recovered
// or contracted before Nginx is allowed to start or reload. It deliberately
// checks both normal operation intent and independent safety reactivation
// state; either side alone is enough to block the data plane.
func PendingPublicationRecovery(document persist.Document, state safety.State) error {
	pending := map[string]bool{}
	for _, key := range persist.EntryKeys(document, "intents") {
		var intent Reservation
		if err := decodeStrict(document.Entries[key], &intent); err != nil {
			return fmt.Errorf("publication intent authority is invalid: %w", err)
		}
		if intent.Operation == Publish && intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
			pending[intent.SafetyBinding.ResourceID] = true
		}
	}
	for _, resource := range state.Resources {
		if resource.Reactivating != nil {
			pending[resource.ResourceID] = true
		}
	}
	if len(pending) == 0 {
		return nil
	}
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return fmt.Errorf("interrupted publication requires contraction: %s", strings.Join(ids, ","))
}

// PendingJournalRecovery is the final journal-side fence for the Nginx data
// plane. A graph may look valid while a prior operation still owns an
// in-flight physical transition, so every registered journal must be terminal
// before startup or reload. Validation is repeated here intentionally: this is
// the guard's independent decision boundary, not merely an incidental store
// read side effect.
func PendingJournalRecovery(document persist.Document) error {
	type journalEntry struct {
		key     string
		journal JournalRecord
	}
	entries := []journalEntry{}
	journalsByJob := map[string][]JournalRecord{}
	for _, key := range persist.EntryKeys(document, "journals") {
		raw := document.Entries[key]
		if err := validateJournalEntry(key, raw); err != nil {
			return fmt.Errorf("nginx guard journal authority is invalid: %w", err)
		}
		var journal JournalRecord
		if err := decodeStrict(raw, &journal); err != nil {
			return fmt.Errorf("nginx guard journal authority is invalid: %w", err)
		}
		entries = append(entries, journalEntry{key: key, journal: journal})
		journalsByJob[journal.JobID] = append(journalsByJob[journal.JobID], journal)
	}
	for _, entry := range entries {
		key, journal := entry.key, entry.journal
		if journal.Phase != JournalTerminal {
			return fmt.Errorf("nginx guard requires terminal operation journal: %s", key)
		}
		intent, err := loadReservationEntries(document.Entries, journal.JobID)
		if err != nil {
			return fmt.Errorf("nginx guard journal intent authority is invalid: %w", err)
		}
		children := map[string]ChildRecord{}
		childIDs := []string{}
		for _, childKey := range persist.EntryKeys(document, "children") {
			childRaw := document.Entries[childKey]
			if err := validateChildEntry(childKey, childRaw); err != nil {
				return fmt.Errorf("nginx guard child authority is invalid: %w", err)
			}
			var child ChildRecord
			if err := decodeStrict(childRaw, &child); err != nil {
				return fmt.Errorf("nginx guard child authority is invalid: %w", err)
			}
			if child.JobID == journal.JobID {
				children[child.ID] = child
				childIDs = append(childIDs, child.ID)
			}
		}
		sort.Strings(childIDs)
		if len(journalsByJob[journal.JobID]) > 1 && intent.CertificateHandoff == nil {
			return fmt.Errorf("nginx guard operation has incompatible journal authorities: %s", key)
		}
		handoff := exactCertificatePublicationHandoff(intent, journalsByJob[journal.JobID], childIDs)
		if intent.CertificateHandoff != nil && !handoff {
			return fmt.Errorf("nginx guard certificate publication handoff is incomplete: %s", key)
		}
		if !slices.Equal(childIDs, journal.ChildIDs) {
			terminalNeverSubmitted := intent.CertificateHandoff == nil && journal.Kind == JournalCertificateActivation && intent.Phase == PhaseTerminal && len(childIDs) < len(journal.ChildIDs) && slices.Equal(childIDs, journal.ChildIDs[:len(childIDs)])
			if !terminalNeverSubmitted && !handoff {
				return fmt.Errorf("nginx guard journal child inventory is incomplete or mismatched: %s", key)
			}
		}
		for _, child := range children {
			if child.State != ChildTerminal {
				return fmt.Errorf("nginx guard requires terminal journal child: %s", child.ID)
			}
		}
	}
	for _, intentKey := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(intentKey, "intents/"))
		if err != nil {
			return fmt.Errorf("nginx guard operation intent authority is invalid: %w", err)
		}
		if intent.CertificateHandoff != nil && len(journalsByJob[intent.JobID]) != 2 {
			return fmt.Errorf("nginx guard certificate publication handoff lacks its exact journal pair: %s", intentKey)
		}
	}
	return nil
}

func exactCertificatePublicationHandoff(intent Reservation, journals []JournalRecord, childIDs []string) bool {
	if intent.CertificateHandoff == nil || len(journals) != 2 {
		return false
	}
	var appJournal, certificateJournal *JournalRecord
	for index := range journals {
		journal := &journals[index]
		switch journal.Kind {
		case JournalAppActivation:
			if appJournal != nil {
				return false
			}
			appJournal = journal
		case JournalCertificateActivation:
			if certificateJournal != nil {
				return false
			}
			certificateJournal = journal
		default:
			return false
		}
	}
	if appJournal == nil || certificateJournal == nil || appJournal.Phase != JournalTerminal || appJournal.SafetyMarkerDigest != intent.JournalSafetyDigest || len(appJournal.ChildIDs) != 0 || certificateJournal.Phase != JournalTerminal || certificateJournal.SafetyMarkerDigest != intent.CertificateHandoff.ChallengeSafetyDigest || !slices.Equal(childIDs, certificateJournal.ChildIDs) {
		return false
	}
	certificate := certificateJournal.Certificate
	return certificate != nil && certificate.CertificateID == intent.CertificateHandoff.CertificateID && certificate.CandidateFingerprint == intent.CertificateHandoff.Fingerprint
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
	return pruneTerminalGraphsExcept(transaction, keep, "")
}

func pruneTerminalGraphsExcept(transaction *persist.Transaction, keep int, exemptPin string) error {
	if keep < 0 {
		return fmt.Errorf("terminal graph retention bound is invalid")
	}
	type terminalGraph struct {
		intent Reservation
		ended  time.Time
	}
	pinned := map[string]bool{}
	pinReferences := map[string]int{}
	if raw, present := transaction.Get("installations/current"); present {
		installation, err := domain.DecodeInstallation(raw)
		if err != nil {
			return err
		}
		for _, resource := range installation.Resources {
			if len(resource.PublicationRecord.PendingGoAccessRetirements) > 0 {
				if resource.PublicationRecord.GoAccessRetirementSourceJobID == "" {
					return fmt.Errorf("pending GoAccess retirement source missing")
				}
				pinReferences[resource.PublicationRecord.GoAccessRetirementSourceJobID]++
			}
		}
		for source, references := range pinReferences {
			if source != exemptPin || references > 1 {
				pinned[source] = true
			}
		}
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
	if remove <= 0 {
		return nil
	}
	removable := make([]terminalGraph, 0, remove)
	for _, graph := range graphs {
		if !pinned[graph.intent.JobID] {
			removable = append(removable, graph)
		}
	}
	if len(removable) < remove {
		return fmt.Errorf("terminal graph retention is pinned by pending GoAccess retirement")
	}
	for index := 0; index < remove; index++ {
		intent := removable[index].intent
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
		expectedCertificateIdentity := certificates.BundleIdentity{Fingerprint: bundle.DomainHTTPS.Certificate.Fingerprint, SANIdentity: bundle.DomainHTTPS.Certificate.SANIdentity, ChainIdentity: bundle.DomainHTTPS.Certificate.ChainIdentity, IssuerIdentity: bundle.DomainHTTPS.Certificate.IssuerIdentity, BindingIdentity: bundle.DomainHTTPS.Certificate.BindingIdentity, DirectoryIdentity: bundle.DomainHTTPS.Certificate.DirectoryIdentity}
		if certificateKey == "" || certificateJournal.Phase != JournalActive || certificate == nil || certificate.CertificateID != bundle.DomainHTTPS.Certificate.Authority.CertificateID || certificate.CandidateGeneration != bundle.DomainHTTPS.Certificate.Generation || certificate.CandidateFingerprint != bundle.DomainHTTPS.Certificate.Fingerprint || certificate.CandidateBundleIdentity != expectedCertificateIdentity {
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
		expectedRetirement := commit.Bundle.DomainHTTPS != nil && commit.Bundle.DomainHTTPS.GoAccess.RetiredGeneration != 0
		if commit.GoAccessRetirementPending != expectedRetirement {
			return fmt.Errorf("publication retirement authority mismatched")
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
			if commit.GoAccessRetirementPending {
				identity := commit.Bundle.DomainHTTPS.GoAccess
				resource.PublicationRecord.LastOperationResult = domain.OperationPartial
				resource.PublicationRecord.PendingGoAccessRetirements = []domain.GoAccessRetirementIdentity{{Generation: identity.RetiredGeneration, StateGeneration: identity.RetiredStateGeneration, ServiceIdentity: identity.RetiredServiceIdentity, RemoveState: identity.RemovesRetiredState(), UnitIdentities: append([]string(nil), identity.RetiredUnitIdentities...)}}
				retirementDigest, digestErr := GoAccessRetirementInventoryDigest(resource.PublicationRecord.PendingGoAccessRetirements)
				if digestErr != nil {
					return digestErr
				}
				resource.PublicationRecord.GoAccessRetirementSourceJobID = jobID
				resource.PublicationRecord.GoAccessRetirementSourceJournalID = journalID
				resource.PublicationRecord.GoAccessRetirementAuthorityDigest = retirementDigest
			} else {
				resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
				resource.PublicationRecord.PendingGoAccessRetirements = nil
				resource.PublicationRecord.GoAccessRetirementSourceJobID = ""
				resource.PublicationRecord.GoAccessRetirementSourceJournalID = ""
				resource.PublicationRecord.GoAccessRetirementAuthorityDigest = ""
			}
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
		if commit.GoAccessRetirementPending {
			journal.Phase = JournalActive
		} else {
			journal.Phase = JournalTerminal
		}
		journalRaw, err = persist.EncodeEntry(journal)
		if err != nil {
			return err
		}
		if err = transaction.Replace("journals/"+journal.ID, journalRaw); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		if commit.GoAccessRetirementPending {
			completed = record
		} else {
			publicationPaths := append(append([]string(nil), paths...), commit.Bundle.ManagedPaths...)
			completion := jobs.Completion{Result: jobs.ResultSucceeded, ModifiedPaths: publicationPaths, Postconditions: []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: runtimeDigest}}}
			record, err = jobs.Finish(record, completion, observedNow)
			if err != nil {
				return err
			}
			if err = jobs.Replace(transaction, record); err != nil {
				return err
			}
			intent.Phase = PhaseTerminal
			raw, err = persist.EncodeEntry(intent)
			if err != nil {
				return err
			}
			if err = transaction.Replace(reservationKey(jobID), raw); err != nil {
				return err
			}
			completed = record
		}
		return nil
	})
	if err != nil {
		return jobs.Record{}, err
	}
	return completed, safetyCommit()
}

func (admitter *Admitter) InterruptPublicationGoAccessRetirement(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("GoAccess retirement interruption requires exact authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var interrupted jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		if pruneErr := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-1); pruneErr != nil {
			return pruneErr
		}
		record, loadErr := jobs.Load(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		if record.Status != jobs.StatusRunning || record.Operation != string(Publish) {
			return fmt.Errorf("GoAccess retirement running job changed")
		}
		installation, loadErr := loadInstallation(transaction)
		if loadErr != nil {
			return loadErr
		}
		retirementIdentity, siteIdentity := "", ""
		modifiedPaths := []string{}
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID == resourceID && resource.PublicationRecord.LastJobID == jobID && resource.PublicationRecord.State == domain.PublicationPublished && resource.PublicationRecord.LastAppliedBundle != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS != nil {
				goaccess := resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.GoAccess
				if goaccess.RetiredGeneration != 0 {
					paths, pathErr := publicationGoAccessModifiedPaths(resourceID, resource.PublicationRecord.LastAppliedBundle)
					if pathErr != nil {
						return pathErr
					}
					retirementIdentity = fmt.Sprintf("%d:%s", goaccess.RetiredGeneration, goaccess.RetiredServiceIdentity)
					siteIdentity = resource.PublicationRecord.LastAppliedBundle.SiteIdentity
					modifiedPaths = paths
					resource.PublicationRecord.LastOperationResult = domain.OperationInterrupted
				}
			}
		}
		if retirementIdentity == "" {
			return fmt.Errorf("GoAccess retirement interruption authority missing")
		}
		record, loadErr = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, ModifiedPaths: modifiedPaths, Postconditions: []jobs.Postcondition{{Kind: "published_committed", Status: jobs.PostconditionKnown, Identity: siteIdentity}, {Kind: "goaccess_prior_retirement", Status: jobs.PostconditionKnown, Identity: retirementIdentity}}, ErrorCode: "goaccess_retirement_recovery"}, observed)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = jobs.Replace(transaction, record); loadErr != nil {
			return loadErr
		}
		journalRaw, present := transaction.Get("journals/activation-" + jobID)
		if !present {
			return fmt.Errorf("GoAccess retirement journal missing")
		}
		var journal JournalRecord
		if loadErr = decodeStrict(journalRaw, &journal); loadErr != nil {
			return loadErr
		}
		if journal.JobID != jobID || journal.Phase != JournalActive {
			return fmt.Errorf("GoAccess retirement journal changed")
		}
		journal.Phase = JournalTerminal
		journalRaw, loadErr = persist.EncodeEntry(journal)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("journals/"+journal.ID, journalRaw); loadErr != nil {
			return loadErr
		}
		intent, loadErr := loadReservation(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		intent.Phase = PhaseTerminal
		raw, loadErr := persist.EncodeEntry(intent)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace(reservationKey(jobID), raw); loadErr != nil {
			return loadErr
		}
		raw, loadErr = persist.EncodeEntry(installation)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("installations/current", raw); loadErr != nil {
			return loadErr
		}
		interrupted = record
		return nil
	})
	return interrupted, err
}

func (admitter *Admitter) FailPublicationGoAccessRetirement(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("GoAccess retirement failure requires exact authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var failed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		if pruneErr := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-1); pruneErr != nil {
			return pruneErr
		}
		record, loadErr := jobs.Load(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		if record.Status != jobs.StatusRunning || record.Operation != string(Publish) {
			return fmt.Errorf("GoAccess retirement running job changed")
		}
		installation, loadErr := loadInstallation(transaction)
		if loadErr != nil {
			return loadErr
		}
		retirementIdentity := ""
		siteIdentity := ""
		modifiedPaths := []string{}
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID == resourceID && resource.PublicationRecord.LastJobID == jobID && resource.PublicationRecord.LastAppliedBundle != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS != nil {
				goaccess := resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.GoAccess
				if goaccess.RetiredGeneration != 0 {
					paths, pathErr := publicationGoAccessModifiedPaths(resourceID, resource.PublicationRecord.LastAppliedBundle)
					if pathErr != nil {
						return pathErr
					}
					retirementIdentity = fmt.Sprintf("%d:%s", goaccess.RetiredGeneration, goaccess.RetiredServiceIdentity)
					siteIdentity = resource.PublicationRecord.LastAppliedBundle.SiteIdentity
					modifiedPaths = paths
					resource.PublicationRecord.LastOperationResult = domain.OperationPartial
				}
			}
		}
		if retirementIdentity == "" {
			return fmt.Errorf("GoAccess retirement failure authority missing")
		}
		record, loadErr = jobs.Finish(record, jobs.Completion{Result: jobs.ResultPartial, ModifiedPaths: modifiedPaths, Postconditions: []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: siteIdentity}, {Kind: "goaccess_prior_retirement", Status: jobs.PostconditionKnown, Identity: retirementIdentity}}, ErrorCode: "goaccess_stop_failed"}, observed)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = jobs.Replace(transaction, record); loadErr != nil {
			return loadErr
		}
		journalRaw, present := transaction.Get("journals/activation-" + jobID)
		if !present {
			return fmt.Errorf("GoAccess retirement journal missing")
		}
		var journal JournalRecord
		if loadErr = decodeStrict(journalRaw, &journal); loadErr != nil {
			return loadErr
		}
		if journal.JobID != jobID || journal.Phase != JournalActive {
			return fmt.Errorf("GoAccess retirement journal changed")
		}
		journal.Phase = JournalTerminal
		journalRaw, loadErr = persist.EncodeEntry(journal)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("journals/"+journal.ID, journalRaw); loadErr != nil {
			return loadErr
		}
		intent, loadErr := loadReservation(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		intent.Phase = PhaseTerminal
		raw, loadErr := persist.EncodeEntry(intent)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace(reservationKey(jobID), raw); loadErr != nil {
			return loadErr
		}
		raw, loadErr = persist.EncodeEntry(installation)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("installations/current", raw); loadErr != nil {
			return loadErr
		}
		failed = record
		return nil
	})
	return failed, err
}

func (admitter *Admitter) CompletePublicationGoAccessRetirement(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("GoAccess retirement completion requires exact authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		if pruneErr := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-1); pruneErr != nil {
			return pruneErr
		}
		record, loadErr := jobs.Load(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		if record.Status != jobs.StatusRunning || record.Operation != string(Publish) {
			return fmt.Errorf("GoAccess retirement job authority changed")
		}
		intent, loadErr := loadReservation(transaction, jobID)
		if loadErr != nil || intent.Operation != Publish || intent.Phase != PhaseLocalIntent {
			return fmt.Errorf("GoAccess retirement reservation authority changed")
		}
		journalRaw, present := transaction.Get("journals/activation-" + jobID)
		if !present {
			return fmt.Errorf("GoAccess retirement journal missing")
		}
		var journal JournalRecord
		if loadErr = decodeStrict(journalRaw, &journal); loadErr != nil {
			return loadErr
		}
		if journal.JobID != jobID || journal.Kind != JournalAppActivation || journal.Phase != JournalActive {
			return fmt.Errorf("GoAccess retirement journal authority changed")
		}
		installation, loadErr := loadInstallation(transaction)
		if loadErr != nil {
			return loadErr
		}
		var bundle *domain.PublicationBundle
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID == resourceID && resource.PublicationRecord.LastJobID == jobID && resource.PublicationRecord.LastAppliedBundle != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.GoAccess.RetiredGeneration != 0 {
				resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
				clearGoAccessRetirementAuthority(&resource.PublicationRecord)
				bundle = resource.PublicationRecord.LastAppliedBundle
			}
		}
		if bundle == nil {
			return fmt.Errorf("GoAccess retirement resource authority changed")
		}
		if journal.ArtifactDigest == "" || publication.RequireBundleDigest(*bundle, journal.ArtifactDigest) != nil {
			return fmt.Errorf("GoAccess retirement bundle authority changed")
		}
		goaccess := bundle.DomainHTTPS.GoAccess
		modifiedPaths, pathErr := publicationGoAccessModifiedPaths(resourceID, bundle)
		if pathErr != nil {
			return pathErr
		}
		retirementIdentity := fmt.Sprintf("%d:%s", goaccess.RetiredGeneration, goaccess.RetiredServiceIdentity)
		record, loadErr = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, ModifiedPaths: modifiedPaths, Postconditions: []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: bundle.SiteIdentity}, {Kind: "goaccess_prior_retirement", Status: jobs.PostconditionVerified, Identity: retirementIdentity}}}, observed)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = jobs.Replace(transaction, record); loadErr != nil {
			return loadErr
		}
		journal.Phase = JournalTerminal
		journalRaw, loadErr = persist.EncodeEntry(journal)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("journals/"+journal.ID, journalRaw); loadErr != nil {
			return loadErr
		}
		intent.Phase = PhaseTerminal
		raw, loadErr := persist.EncodeEntry(intent)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace(reservationKey(jobID), raw); loadErr != nil {
			return loadErr
		}
		raw, loadErr = persist.EncodeEntry(installation)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("installations/current", raw); loadErr != nil {
			return loadErr
		}
		completed = record
		return nil
	})
	return completed, err
}

func (admitter *Admitter) CompleteGoAccessRetirementReconciliation(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string, generation uint64, serviceIdentity string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("GoAccess reconciliation completion requires exact authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		record, loadErr := jobs.Load(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		intent, loadErr := loadReservation(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		if record.Status != jobs.StatusRunning || record.Operation != string(GoAccessRetirement) || intent.Operation != GoAccessRetirement || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+resourceID {
			return fmt.Errorf("GoAccess reconciliation job authority changed")
		}
		installation, loadErr := loadInstallation(transaction)
		if loadErr != nil {
			return loadErr
		}
		oldJobID := ""
		sourceJournalID := ""
		siteIdentity := ""
		modifiedPaths := []string{}
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID == resourceID && resource.PublicationRecord.LastAppliedBundle != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS != nil {
				goaccess := resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.GoAccess
				if goaccess.RetiredGeneration == generation && goaccess.RetiredServiceIdentity == serviceIdentity {
					retirement := domain.GoAccessRetirementIdentity{Generation: goaccess.RetiredGeneration, StateGeneration: goaccess.RetiredStateGeneration, ServiceIdentity: goaccess.RetiredServiceIdentity, RemoveState: goaccess.RemovesRetiredState(), UnitIdentities: append([]string(nil), goaccess.RetiredUnitIdentities...)}
					retirementPaths, pathErr := GoAccessRetirementModifiedPaths(resourceID, retirement)
					if pathErr != nil {
						return pathErr
					}
					oldJobID = resource.PublicationRecord.GoAccessRetirementSourceJobID
					sourceJournalID = resource.PublicationRecord.GoAccessRetirementSourceJournalID
					siteIdentity = resource.PublicationRecord.LastAppliedBundle.SiteIdentity
					modifiedPaths = append(modifiedPaths, retirementPaths...)
					resource.PublicationRecord.LastJobID = jobID
					resource.PublicationRecord.LastOperation = domain.OperationPublish
					resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
					clearGoAccessRetirementAuthority(&resource.PublicationRecord)
				}
			}
		}
		if oldJobID == "" {
			return fmt.Errorf("GoAccess reconciliation resource authority changed")
		}
		oldRecord, loadErr := jobs.Load(transaction, oldJobID)
		priorTerminal := oldRecord.Result == jobs.ResultPartial && oldRecord.ErrorCode == "goaccess_stop_failed" || oldRecord.Result == jobs.ResultInterrupted && oldRecord.ErrorCode == "goaccess_retirement_recovery"
		if loadErr != nil || oldRecord.Status != jobs.StatusTerminal || !priorTerminal {
			return fmt.Errorf("GoAccess prior retirement result changed")
		}
		journalRaw, present := transaction.Get("journals/" + sourceJournalID)
		if !present {
			return fmt.Errorf("GoAccess retirement journal missing")
		}
		var journal JournalRecord
		if loadErr = decodeStrict(journalRaw, &journal); loadErr != nil {
			return loadErr
		}
		if journal.Phase != JournalTerminal || journal.JobID != oldJobID {
			return fmt.Errorf("GoAccess retirement journal changed")
		}
		if pruneErr := pruneTerminalGraphsExcept(transaction, maximumTerminalOperationGraphs-1, oldJobID); pruneErr != nil {
			return pruneErr
		}
		retirementIdentity := fmt.Sprintf("%d:%s", generation, serviceIdentity)
		record, loadErr = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, ModifiedPaths: modifiedPaths, Postconditions: []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: siteIdentity}, {Kind: "goaccess_prior_retirement", Status: jobs.PostconditionVerified, Identity: retirementIdentity}}}, observed)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = jobs.Replace(transaction, record); loadErr != nil {
			return loadErr
		}
		intent.Phase = PhaseTerminal
		raw, loadErr := persist.EncodeEntry(intent)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace(reservationKey(jobID), raw); loadErr != nil {
			return loadErr
		}
		raw, loadErr = persist.EncodeEntry(installation)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("installations/current", raw); loadErr != nil {
			return loadErr
		}
		completed = record
		return nil
	})
	return completed, err
}

func (admitter *Admitter) CompleteGoAccessContractionReconciliation(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string, retirements []domain.GoAccessRetirementIdentity) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("GoAccess contraction reconciliation requires exact authority")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		record, loadErr := jobs.Load(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		intent, loadErr := loadReservation(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		if record.Status != jobs.StatusRunning || record.Operation != string(GoAccessRetirement) || intent.Operation != GoAccessRetirement || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+resourceID {
			return fmt.Errorf("GoAccess contraction reconciliation job changed")
		}
		installation, loadErr := loadInstallation(transaction)
		if loadErr != nil {
			return loadErr
		}
		oldJobID := ""
		operation := domain.OperationCode("")
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID == resourceID && reflect.DeepEqual(resource.PublicationRecord.PendingGoAccessRetirements, retirements) {
				oldJobID = resource.PublicationRecord.GoAccessRetirementSourceJobID
				operation = resource.PublicationRecord.LastOperation
				clearGoAccessRetirementAuthority(&resource.PublicationRecord)
				resource.PublicationRecord.LastJobID = jobID
				resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
			}
		}
		if oldJobID == "" || (operation != domain.OperationUnpublish && operation != domain.OperationCloseAll) {
			return fmt.Errorf("GoAccess contraction reconciliation authority changed")
		}
		oldRecord, loadErr := jobs.Load(transaction, oldJobID)
		if loadErr != nil || oldRecord.Status != jobs.StatusTerminal || oldRecord.Result != jobs.ResultPartial || oldRecord.ErrorCode != "goaccess_stop_failed" {
			return fmt.Errorf("GoAccess contraction partial result changed")
		}
		if pruneErr := pruneTerminalGraphsExcept(transaction, maximumTerminalOperationGraphs-1, oldJobID); pruneErr != nil {
			return pruneErr
		}
		identities := make([]string, 0, len(retirements))
		modifiedPaths := []string{}
		for _, item := range retirements {
			identities = append(identities, fmt.Sprintf("%d:%s", item.Generation, item.ServiceIdentity))
			paths, pathErr := GoAccessRetirementModifiedPaths(resourceID, item)
			if pathErr != nil {
				return pathErr
			}
			modifiedPaths = append(modifiedPaths, paths...)
		}
		record, loadErr = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, ModifiedPaths: modifiedPaths, Postconditions: []jobs.Postcondition{{Kind: "goaccess_contraction_retirement", Status: jobs.PostconditionVerified, Identity: strings.Join(identities, ",")}}}, observed)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = jobs.Replace(transaction, record); loadErr != nil {
			return loadErr
		}
		intent.Phase = PhaseTerminal
		raw, loadErr := persist.EncodeEntry(intent)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace(reservationKey(jobID), raw); loadErr != nil {
			return loadErr
		}
		raw, loadErr = persist.EncodeEntry(installation)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.Replace("installations/current", raw); loadErr != nil {
			return loadErr
		}
		completed = record
		return nil
	})
	return completed, err
}

func (admitter *Admitter) TerminalizeTemporaryPublicationNoEffect(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, expected SafetyBinding, code string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || expected.ResourceID == "" || expected.PlanID == "" || expected.IntentGeneration == 0 || !exactDigest(expected.CandidateDigest) || !exactDigest(expected.CandidateBundle) {
		return jobs.Record{}, fmt.Errorf("temporary publication no-effect authority invalid")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
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
		if intent.Operation != Publish || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+expected.ResourceID || mutation.Target() != intent.Target || !reflect.DeepEqual(intent.SafetyBinding, expected) || intent.PlanID != expected.PlanID {
			return fmt.Errorf("temporary publication no-effect intent changed")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != expected.ResourceID {
				continue
			}
			if resource.Publication.Kind != domain.PublicationTemporaryHTTP || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.State == domain.PublicationActivating {
				return fmt.Errorf("temporary publication already has activation effect")
			}
			found = true
		}
		if !found {
			return fmt.Errorf("temporary publication no-effect resource missing")
		}
		for _, key := range transaction.Keys("journals") {
			raw, _ := transaction.Get(key)
			var journal JournalRecord
			if err := decodeStrict(raw, &journal); err != nil {
				return err
			}
			if journal.JobID == jobID {
				return fmt.Errorf("temporary publication no-effect retains journal authority")
			}
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil || record.Status != jobs.StatusRunning {
			return fmt.Errorf("temporary publication no-effect job changed: %w", err)
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultFailed, Postconditions: []jobs.Postcondition{{Kind: "temporary_http_not_activated", Status: jobs.PostconditionVerified, Identity: expected.CandidateBundle}}, ErrorCode: code}, observed)
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
			acceptedTerminal := record.Result == jobs.ResultSucceeded || record.Result == jobs.ResultInterrupted && record.ErrorCode == "goaccess_retirement_recovery"
			if err != nil || record.Status != jobs.StatusTerminal || !acceptedTerminal {
				return fmt.Errorf("committed publication recovery job changed")
			}
			if len(resource.PublicationRecord.PendingGoAccessRetirements) > 0 {
				if resource.PublicationRecord.GoAccessRetirementSourceJournalID == "" {
					return fmt.Errorf("committed publication contraction found nonpublication retirement source")
				}
				clearGoAccessRetirementAuthority(&resource.PublicationRecord)
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

func (admitter *Admitter) TerminalizeInterruptedTemporaryPublication(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, expected SafetyBinding, generation uint64, paths []string, runtimeDigest string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || expected.ResourceID == "" || expected.PlanID == "" || generation == 0 || !exactDigest(expected.CandidateDigest) || !exactDigest(expected.CandidateBundle) || !exactDigest(runtimeDigest) {
		return jobs.Record{}, fmt.Errorf("temporary publication contraction authority invalid")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
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
		if intent.Operation != Publish || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+expected.ResourceID || mutation.Target() != intent.Target || intent.PlanID != expected.PlanID || !reflect.DeepEqual(intent.SafetyBinding, expected) {
			return fmt.Errorf("temporary publication contraction intent changed")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		found := false
		for index := range installation.Resources {
			resource := &installation.Resources[index]
			if resource.ID != expected.ResourceID {
				continue
			}
			active := resource.PublicationRecord.ActivationIntent
			if resource.Publication.Kind != domain.PublicationTemporaryHTTP || resource.PublicationRecord.State != domain.PublicationActivating || active == nil || active.JobID != jobID || active.PlanID != expected.PlanID || active.Generation != expected.IntentGeneration || active.Candidate.TemporaryHTTP == nil || active.Candidate.ConfigDigest != expected.CandidateDigest || publication.RequireBundleDigest(active.Candidate, expected.CandidateBundle) != nil {
				return fmt.Errorf("temporary publication activation authority changed")
			}
			resource.PublicationRecord.State = domain.PublicationUnpublished
			resource.PublicationRecord.UnpublishedGeneration = generation
			resource.PublicationRecord.ActivationIntent = nil
			resource.PublicationRecord.LastOperation = domain.OperationPublish
			resource.PublicationRecord.LastOperationResult = domain.OperationInterrupted
			resource.PublicationRecord.LastJobID = jobID
			resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: observed.Format(time.RFC3339), Reason: "temporary_http_activation_contracted"}
			found = true
		}
		if !found {
			return fmt.Errorf("temporary publication contraction resource missing")
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
			if err := decodeStrict(journalRaw, &journal); err != nil {
				return err
			}
			if journal.JobID != jobID {
				continue
			}
			if journalFound || journal.ID != "activation-"+jobID || journal.Kind != JournalAppActivation || journal.Operation != Publish || journal.Target != intent.Target || journal.Generation != intent.IntentGeneration || journal.ArtifactDigest != expected.CandidateBundle || journal.Phase != JournalPrepared {
				return fmt.Errorf("temporary publication contraction journal changed")
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
		record, err := jobs.Load(transaction, jobID)
		if err != nil || record.Status != jobs.StatusRunning {
			return fmt.Errorf("temporary publication contraction job changed: %w", err)
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, ModifiedPaths: paths, Postconditions: []jobs.Postcondition{{Kind: "temporary_http_activation_contracted", Status: jobs.PostconditionVerified, Identity: runtimeDigest}}, ErrorCode: "temporary_http_activation_recovery"}, observed)
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
			retirements, retirementErr := goAccessRetirements(prior, candidate)
			if retirementErr != nil {
				return retirementErr
			}
			retirements, retirementErr = transferPendingGoAccessRetirements(&resource.PublicationRecord, retirements)
			if retirementErr != nil {
				return retirementErr
			}
			resource.PublicationRecord.ContractionIntent = &domain.ContractionIntent{JobID: intent.JobID, Operation: string(intent.Operation), Generation: generation, ClosureAuthorityDigest: commit.ClosureAuthorityDigest, Prior: cloneBundle(prior), Candidate: cloneBundle(candidate), GoAccessRetirements: retirements}
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

func (admitter *Admitter) CommitResourceDeleteBegin(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("resource delete begin requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil || intent.Operation != ResourceDelete || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+resourceID || mutation.Target() != intent.Target {
			return fmt.Errorf("resource delete intent mismatched")
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
			if resource.Lifecycle != domain.LifecycleActive || resource.PublicationRecord.State != domain.PublicationUnpublished || intent.ResourceDelete == nil || intent.ResourceDelete.InstallationID != installation.InstallationID || !reflect.DeepEqual(*resource, intent.ResourceDelete.Resource) {
				return fmt.Errorf("resource delete requires exact frozen unpublished resource")
			}
			resource.Lifecycle = domain.LifecycleDeleting
			resource.PublicationRecord.LastOperation = domain.OperationResourceDelete
			resource.PublicationRecord.LastOperationResult = ""
			resource.PublicationRecord.LastJobID = jobID
			found = true
		}
		if !found {
			return fmt.Errorf("resource delete target missing")
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitResourceDeleteRemoval(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("resource delete removal requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil || intent.Operation != ResourceDelete || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+resourceID {
			return fmt.Errorf("resource delete removal intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		kept := installation.Resources[:0]
		deletedStaticRoots := map[string]bool{}
		for _, root := range installation.StaticRoots {
			if root.OwnerResourceID == resourceID {
				deletedStaticRoots[root.ID] = true
			}
		}
		found := false
		for _, resource := range installation.Resources {
			if resource.ID == resourceID {
				if resource.Lifecycle != domain.LifecycleDeleting || resource.PublicationRecord.LastJobID != jobID {
					return fmt.Errorf("resource deleting tombstone changed")
				}
				if publication := resource.Publication.DomainHTTPS; publication != nil && publication.StaticRootID != "" {
					deletedStaticRoots[publication.StaticRootID] = true
				}
				if applied := resource.PublicationRecord.LastAppliedBundle; applied != nil && applied.DomainHTTPS != nil && applied.DomainHTTPS.Static.RootID != "" {
					deletedStaticRoots[applied.DomainHTTPS.Static.RootID] = true
				}
				found = true
				continue
			}
			kept = append(kept, resource)
		}
		if !found {
			return fmt.Errorf("resource delete target missing")
		}
		installation.Resources = kept
		credentials := installation.Credentials[:0]
		for _, credential := range installation.Credentials {
			if credential.OwnerResourceID != resourceID {
				credentials = append(credentials, credential)
			}
		}
		installation.Credentials = credentials
		for _, resource := range kept {
			if publication := resource.Publication.DomainHTTPS; publication != nil {
				delete(deletedStaticRoots, publication.StaticRootID)
			}
			if applied := resource.PublicationRecord.LastAppliedBundle; applied != nil && applied.DomainHTTPS != nil {
				delete(deletedStaticRoots, applied.DomainHTTPS.Static.RootID)
			}
		}
		staticRoots := installation.StaticRoots[:0]
		for _, root := range installation.StaticRoots {
			if !deletedStaticRoots[root.ID] {
				staticRoots = append(staticRoots, root)
			}
		}
		installation.StaticRoots = staticRoots
		for _, key := range transaction.Keys("intents") {
			rawIntent, _ := transaction.Get(key)
			expiryIntent, decodeErr := decodeReservation(rawIntent)
			if decodeErr != nil {
				return decodeErr
			}
			if expiryIntent.Operation == CertificateExpiry && expiryIntent.SafetyBinding.ResourceID == resourceID && expiryIntent.Phase != PhaseTerminal && expiryIntent.Phase != PhaseRejected {
				return fmt.Errorf("resource delete is blocked by nonterminal certificate expiry")
			}
		}
		if _, present := transaction.Get(expiryGenerationKey(resourceID)); present {
			if err := transaction.Delete(expiryGenerationKey(resourceID)); err != nil {
				return err
			}
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitConnectorBinding(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, connector domain.TailnetConnector) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || connector.LastOperation != domain.OperationConnectorBindingSet || connector.LastJobID != jobID {
		return fmt.Errorf("connector binding commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil || intent.Operation != ConnectorBindingSet || intent.Phase != PhaseLocalIntent || intent.Target != "connector" || mutation.Target() != intent.Target {
			return fmt.Errorf("connector binding intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if installation.Connector != nil {
			return fmt.Errorf("connector binding is already committed")
		}
		installation.Connector = &connector
		if err := domain.ValidateInstallation(installation); err != nil {
			return err
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitConnectorLogin(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("connector login commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil || intent.Operation != ConnectorLogin || intent.Phase != PhaseReentered || intent.Target != "connector" || mutation.Target() != intent.Target {
			return fmt.Errorf("connector login intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if installation.Connector == nil {
			return fmt.Errorf("connector binding missing")
		}
		connector := *installation.Connector
		connector.LastOperation, connector.LastJobID = domain.OperationConnectorLogin, jobID
		installation.Connector = &connector
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleInitialize(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleInitializeCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.Headscale.ID == "" || commit.Headscale.LastJobID != jobID || commit.Headscale.LastOperation != domain.OperationHeadscaleInitialize {
		return fmt.Errorf("headscale initialization commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != HeadscaleInitialize || intent.AdmissionSource != AdmissionUI || (intent.Phase != PhaseLocalIntent && intent.Phase != PhaseReentered) || mutation.Target() != intent.Target || intent.Target != string(plans.TargetInstallation) {
			return fmt.Errorf("headscale initialization intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if installation.Headscale != nil {
			return fmt.Errorf("headscale trust domain is already initialized")
		}
		installation.Headscale = &commit.Headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleDeployBegin(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleDeployBeginCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.HeadscaleID == "" || commit.Intent.JobID != jobID || commit.Intent.Phase != domain.HeadscaleDeployPrepared {
		return fmt.Errorf("headscale deploy begin requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != HeadscaleDeploy || intent.AdmissionSource != AdmissionPlan || intent.Phase != PhaseLocalIntent || intent.HeadscaleDeploy == nil || mutation.Target() != intent.Target || intent.Target != string(plans.TargetHeadscale)+"/"+commit.HeadscaleID || commit.Intent.PlanID != intent.PlanID || commit.Intent.Generation != intent.HeadscaleDeploy.Candidate.Generation || commit.Intent.PreflightDigest != intent.HeadscaleDeploy.PreflightResult.RequestDigest || commit.Intent.CertificateBinding != intent.HeadscaleDeploy.Candidate.CertificateBinding {
			return fmt.Errorf("headscale deploy begin intent mismatched")
		}
		applied, err := control.AppliedIdentity(intent.HeadscaleDeploy.Candidate)
		if err != nil || !reflect.DeepEqual(applied, commit.Intent.Candidate) {
			return fmt.Errorf("headscale deploy candidate changed")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if installation.Headscale == nil || installation.Headscale.ID != commit.HeadscaleID || installation.Headscale.Database.Phase != domain.HeadscaleIdentityCommitted || installation.Headscale.DeployIntent != nil || installation.Headscale.Applied != nil || installation.Headscale.Enabled {
			return fmt.Errorf("headscale deploy prior authority changed")
		}
		headscale := *installation.Headscale
		headscale.DeployIntent = &commit.Intent
		headscale.LastOperation = domain.OperationHeadscaleControlDeploy
		headscale.LastJobID = jobID
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) FailPreparedHeadscaleDeploy(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("prepared Headscale deploy failure requires exact authority")
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
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if intent.Operation != HeadscaleDeploy || intent.Phase != PhaseLocalIntent || intent.HeadscaleDeploy == nil || mutation.Target() != intent.Target || installation.Headscale == nil || installation.Headscale.LastOperation != domain.OperationHeadscaleControlDeploy || installation.Headscale.LastJobID != jobID || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.JobID != jobID || installation.Headscale.DeployIntent.PlanID != intent.PlanID || installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployPrepared {
			return fmt.Errorf("prepared Headscale deploy failure authority changed")
		}
		deploy := installation.Headscale.DeployIntent
		applied, appliedErr := control.AppliedIdentity(intent.HeadscaleDeploy.Candidate)
		if appliedErr != nil || !reflect.DeepEqual(applied, deploy.Candidate) || deploy.Generation != intent.HeadscaleDeploy.Candidate.Generation || deploy.CertificateBinding != intent.HeadscaleDeploy.Candidate.CertificateBinding || deploy.PreflightDigest != intent.HeadscaleDeploy.PreflightResult.RequestDigest {
			return fmt.Errorf("prepared Headscale deploy failure candidate changed")
		}
		for _, key := range transaction.Keys("children") {
			raw, _ := transaction.Get(key)
			var child ChildRecord
			if decodeStrict(raw, &child) == nil && child.JobID == jobID {
				return fmt.Errorf("prepared Headscale deploy already has durable local work")
			}
		}
		for _, key := range transaction.Keys("journals") {
			raw, _ := transaction.Get(key)
			var journal JournalRecord
			if decodeStrict(raw, &journal) == nil && journal.JobID == jobID {
				return fmt.Errorf("prepared Headscale deploy already has durable local work")
			}
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil || record.Status != jobs.StatusRunning {
			return fmt.Errorf("prepared Headscale deploy job changed: %w", err)
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultFailed, Postconditions: []jobs.Postcondition{{Kind: "headscale_deploy_not_started", Status: jobs.PostconditionVerified, Identity: jobID}}, ErrorCode: "headscale_deploy_revalidation_failed"}, observed)
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
		headscale := *installation.Headscale
		headscale.DeployIntent = nil
		installation.Headscale = &headscale
		raw, err = persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", raw); err != nil {
			return err
		}
		completed = record
		return nil
	})
	return completed, err
}

func (admitter *Admitter) CommitHeadscaleDeployStaged(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleDeployStagedCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.HeadscaleID == "" || !exactDigest(commit.InitializedDigest) {
		return fmt.Errorf("headscale staged commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != HeadscaleDeploy || intent.Phase != PhaseLocalIntent || intent.HeadscaleDeploy == nil || mutation.Target() != intent.Target {
			return fmt.Errorf("headscale staged operation intent mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if installation.Headscale == nil || installation.Headscale.ID != commit.HeadscaleID || installation.Headscale.LastJobID != jobID || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployPrepared {
			return fmt.Errorf("headscale staged domain intent mismatched")
		}
		headscale := *installation.Headscale
		nextIntent := *headscale.DeployIntent
		nextIntent.Phase = domain.HeadscaleDeployCertificatePending
		headscale.DeployIntent = &nextIntent
		headscale.Database.Phase = domain.HeadscaleInitialized
		headscale.Database.InitializedDigest = commit.InitializedDigest
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleCertificateStaged(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleCertificateStagedCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.HeadscaleID == "" || !exactDigest(commit.Fingerprint) {
		return fmt.Errorf("headscale certificate staged commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != HeadscaleDeploy || intent.Phase != PhaseReentered || intent.HeadscaleDeploy == nil || mutation.Target() != intent.Target {
			return fmt.Errorf("headscale certificate reentry mismatched")
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if installation.Headscale == nil || installation.Headscale.ID != commit.HeadscaleID || installation.Headscale.LastJobID != jobID || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployCertificatePending || installation.Headscale.DeployIntent.Candidate.CertificateID != intent.HeadscaleDeploy.Candidate.CertificateID {
			return fmt.Errorf("headscale certificate domain intent mismatched")
		}
		headscale := *installation.Headscale
		nextIntent := *headscale.DeployIntent
		nextIntent.Phase = domain.HeadscaleDeployCertificateStaged
		nextIntent.CertificateFingerprint = commit.Fingerprint
		headscale.DeployIntent = &nextIntent
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleReissueActivationIntent(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, candidate domain.CertificateBundleIdentity, activationDigest string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(activationDigest) || candidate.Authority == nil {
		return fmt.Errorf("headscale reissue activation authority invalid")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if intent.Operation != CertificateRenew || intent.AdmissionSource != AdmissionPlan || !strings.HasPrefix(intent.Target, "headscale/") || intent.Phase != PhaseReentered || mutation.Target() != intent.Target || installation.Headscale == nil || installation.Headscale.Applied == nil || installation.Headscale.Certificate == nil || installation.Headscale.DeployIntent != nil || candidate.Generation != installation.Headscale.Certificate.Generation+1 || candidate.Authority.CertificateID != installation.Headscale.Certificate.Authority.CertificateID {
			return fmt.Errorf("headscale reissue activation identity changed")
		}
		headscale := *installation.Headscale
		prior := *headscale.Applied
		headscale.LastOperation = domain.OperationHeadscaleReissue
		headscale.LastJobID = jobID
		headscale.DeployIntent = &domain.HeadscaleDeployIntent{Generation: prior.Generation, PlanID: intent.PlanID, JobID: jobID, Phase: domain.HeadscaleDeployActivating, PreflightDigest: intent.SafetyBinding.CandidateBundle, CertificateBinding: candidate.BindingIdentity, CertificateFingerprint: candidate.Fingerprint, ActivationDigest: activationDigest, Candidate: prior, Prior: &prior}
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) ContractHeadscaleReissueActivation(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("headscale reissue contraction locks invalid")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if intent.Operation != CertificateRenew || intent.AdmissionSource != AdmissionPlan || !strings.HasPrefix(intent.Target, "headscale/") || installation.Headscale == nil || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.JobID != jobID {
			return fmt.Errorf("headscale reissue contraction authority changed")
		}
		headscale := *installation.Headscale
		headscale.DeployIntent = nil
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) RestoreHeadscaleCertificateRenewal(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, candidate, prior domain.CertificateBundleIdentity) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return fmt.Errorf("headscale certificate restoration locks invalid")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if intent.Operation != CertificateRenew || !strings.HasPrefix(intent.Target, "headscale/") || installation.Headscale == nil || installation.Headscale.Certificate == nil || !reflect.DeepEqual(*installation.Headscale.Certificate, candidate) {
			return fmt.Errorf("headscale certificate restoration authority changed")
		}
		headscale := *installation.Headscale
		copy := prior
		headscale.Certificate = &copy
		headscale.DeployIntent = nil
		headscale.LastOperation = domain.OperationHeadscaleReissue
		headscale.LastJobID = jobID
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleCertificateRenewal(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, prior, candidate domain.CertificateBundleIdentity) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || candidate.Generation != prior.Generation+1 || candidate.Authority == nil || prior.Authority == nil || candidate.Authority.CertificateID != prior.Authority.CertificateID {
		return fmt.Errorf("headscale renewal commit authority invalid")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if intent.Operation != CertificateRenew || !strings.HasPrefix(intent.Target, "headscale/") || intent.Phase != PhaseReentered || mutation.Target() != intent.Target || installation.Headscale == nil || installation.Headscale.Certificate == nil || !reflect.DeepEqual(*installation.Headscale.Certificate, prior) {
			return fmt.Errorf("headscale renewal identity changed")
		}
		headscale := *installation.Headscale
		next := candidate
		headscale.Certificate = &next
		if headscale.DeployIntent != nil {
			deploy := headscale.DeployIntent
			if intent.AdmissionSource != AdmissionPlan || deploy.JobID != jobID || deploy.PlanID != intent.PlanID || deploy.Phase != domain.HeadscaleDeployActivating || deploy.CertificateBinding != candidate.BindingIdentity || deploy.CertificateFingerprint != candidate.Fingerprint {
				return fmt.Errorf("headscale reissue activation intent changed")
			}
			headscale.DeployIntent = nil
		}
		headscale.LastOperation = domain.OperationHeadscaleReissue
		headscale.LastJobID = jobID
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleActivationIntent(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleActivationIntentCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.HeadscaleID == "" || !exactDigest(commit.ActivationDigest) {
		return fmt.Errorf("headscale activation intent requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		reservation, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if reservation.Operation != HeadscaleDeploy || reservation.Phase != PhaseReentered || reservation.HeadscaleDeploy == nil || mutation.Target() != reservation.Target || installation.Headscale == nil || installation.Headscale.ID != commit.HeadscaleID || installation.Headscale.LastJobID != jobID || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployCertificateStaged {
			return fmt.Errorf("headscale activation intent identity mismatched")
		}
		headscale := *installation.Headscale
		next := *headscale.DeployIntent
		next.Phase = domain.HeadscaleDeployActivating
		next.ActivationDigest = commit.ActivationDigest
		headscale.DeployIntent = &next
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleActivated(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleActivatedCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.HeadscaleID == "" || !exactDigest(commit.RuntimeDigest) || domain.ValidateHeadscaleApplied(commit.Applied) != nil {
		return fmt.Errorf("headscale activated commit requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		reservation, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if reservation.Operation != HeadscaleDeploy || reservation.Phase != PhaseReentered || mutation.Target() != reservation.Target || installation.Headscale == nil || installation.Headscale.ID != commit.HeadscaleID || installation.Headscale.LastJobID != jobID || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployActivating || !reflect.DeepEqual(installation.Headscale.DeployIntent.Candidate, commit.Applied) {
			return fmt.Errorf("headscale activated identity mismatched")
		}
		headscale := *installation.Headscale
		next := *headscale.DeployIntent
		next.Phase = domain.HeadscaleDeployActivated
		next.RuntimeDigest = commit.RuntimeDigest
		headscale.DeployIntent = &next
		applied := commit.Applied
		headscale.Applied = &applied
		headscale.Enabled = true
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err
}

func (admitter *Admitter) CommitHeadscaleDeployLifecycle(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleDeployCompleteCommit) error {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || commit.HeadscaleID == "" || !exactDigest(commit.RuntimeDigest) || commit.Certificate.Authority == nil {
		return fmt.Errorf("headscale deploy completion requires exact authority")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		reservation, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		if reservation.Operation != HeadscaleDeploy || reservation.Phase != PhaseReentered || mutation.Target() != reservation.Target || installation.Headscale == nil || installation.Headscale.ID != commit.HeadscaleID || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployActivated || installation.Headscale.DeployIntent.RuntimeDigest != commit.RuntimeDigest || installation.Headscale.Applied == nil || installation.Headscale.Applied.CertificateID != commit.Certificate.Authority.CertificateID {
			return fmt.Errorf("headscale deploy completion identity mismatched")
		}
		headscale := *installation.Headscale
		headscale.DeployIntent = nil
		certificate := commit.Certificate
		headscale.Certificate = &certificate
		installation.Headscale = &headscale
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", raw); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (admitter *Admitter) CompleteHeadscaleDeploy(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID string, commit HeadscaleDeployCompleteCommit) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) {
		return jobs.Record{}, fmt.Errorf("headscale deploy completion locks invalid")
	}
	document, readErr := admitter.normal.Read()
	if readErr != nil {
		return jobs.Record{}, readErr
	}
	existing, existingErr := loadReservationEntries(document.Entries, jobID)
	if existingErr == nil && existing.Phase == PhaseTerminal {
		record, recordErr := jobs.LoadEntries(document.Entries, jobID)
		raw, present := document.Entries["journals/certificate-"+jobID]
		var journal JournalRecord
		if recordErr == nil && record.Status == jobs.StatusTerminal && record.Result == jobs.ResultSucceeded && present && decodeStrict(raw, &journal) == nil && journal.Phase == JournalTerminal {
			return record, nil
		}
		return jobs.Record{}, fmt.Errorf("terminal Headscale lifecycle authority incomplete")
	}
	observed, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
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
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		state, err := admitter.safety.Read()
		if err != nil {
			return err
		}
		if intent.Operation != HeadscaleDeploy || intent.Phase != PhaseReentered || mutation.Target() != intent.Target || commit.Certificate.Authority == nil || installation.Headscale == nil || installation.Headscale.DeployIntent != nil || installation.Headscale.Certificate == nil || !reflect.DeepEqual(*installation.Headscale.Certificate, commit.Certificate) || state.Headscale.Reactivating != nil {
			return fmt.Errorf("headscale lifecycle completion authority incomplete")
		}
		journalKey := "journals/certificate-" + jobID
		raw, present := transaction.Get(journalKey)
		var journal JournalRecord
		expectedBundleIdentity := certificates.BundleIdentity{Fingerprint: commit.Certificate.Fingerprint, SANIdentity: commit.Certificate.SANIdentity, ChainIdentity: commit.Certificate.ChainIdentity, IssuerIdentity: commit.Certificate.IssuerIdentity, BindingIdentity: commit.Certificate.BindingIdentity, DirectoryIdentity: commit.Certificate.DirectoryIdentity}
		if !present || decodeStrict(raw, &journal) != nil || journal.Phase != JournalActive || journal.Certificate == nil || journal.Certificate.CertificateID != commit.Certificate.Authority.CertificateID || journal.Certificate.CandidateGeneration != commit.Certificate.Generation || journal.Certificate.CandidateBundleIdentity != expectedBundleIdentity {
			return fmt.Errorf("headscale lifecycle journal changed")
		}
		notAfter, notAfterErr := time.Parse(time.RFC3339, commit.Certificate.NotAfter)
		lastTrustedWall, lastTrustedWallErr := time.Parse(time.RFC3339, commit.Certificate.LastTrustedWall)
		active := state.Headscale.ActiveCertificate
		if notAfterErr != nil || lastTrustedWallErr != nil || active == nil || active.Generation != commit.Certificate.Generation || active.Fingerprint != commit.Certificate.Fingerprint || active.Binding != commit.Certificate.BindingIdentity || !active.NotAfter.Equal(notAfter) || active.LastTrustedWall.Before(lastTrustedWall) {
			return fmt.Errorf("headscale lifecycle active certificate authority changed")
		}
		journal.Phase = JournalTerminal
		encoded, err := persist.EncodeEntry(journal)
		if err != nil {
			return err
		}
		if err := transaction.Replace(journalKey, encoded); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{{Kind: "headscale_control_committed", Status: jobs.PostconditionVerified, Identity: commit.RuntimeDigest}}}, observed)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		intent.Phase = PhaseTerminal
		encoded, err = persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		if err := transaction.Replace(reservationKey(jobID), encoded); err != nil {
			return err
		}
		completed = record
		return nil
	})
	return completed, err
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
	candidateDigest, digestErr := appresource.ConfigDigest(candidate)
	if digestErr != nil {
		return fmt.Errorf("resource update candidate config identity: %w", digestErr)
	}
	if candidate.CurrentConfigDigest != candidateDigest {
		return fmt.Errorf("resource update candidate config identity changed")
	}
	_, _, err := admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		intent, err := loadReservation(transaction, jobID)
		if err != nil {
			return err
		}
		if intent.Operation != ResourceUpdate || intent.AdmissionSource != AdmissionUI || intent.Phase != PhaseLocalIntent || intent.Target != "resource/"+candidate.ID || intent.SafetyBinding.ResourceID != candidate.ID || intent.SafetyBinding.CandidateDigest != candidateDigest || mutation.Target() != intent.Target {
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
				if intent.SafetyBinding.CandidateBundle != prior.CurrentConfigDigest {
					return fmt.Errorf("resource update prior config identity changed")
				}
				candidate.PublicationRecord = prior.PublicationRecord
				if prior.Lifecycle != candidate.Lifecycle || prior.Target.Kind != candidate.Target.Kind {
					return fmt.Errorf("resource update lifecycle or target kind changed")
				}
				if err := validateResourceManagedProcessPresence(prior); err != nil {
					return fmt.Errorf("prior resource update authority: %w", err)
				}
				if err := validateResourceManagedProcessPresence(candidate); err != nil {
					return fmt.Errorf("candidate resource update authority: %w", err)
				}
				switch candidate.Target.Kind {
				case domain.AppTargetLocalHTTP:
					if candidate.ManagedProcess.ID != prior.ManagedProcess.ID {
						return fmt.Errorf("resource update managed process identity changed")
					}
					candidate.ManagedProcess.Requested = prior.ManagedProcess.Requested
					candidate.ManagedProcess.Applied = cloneProcessBundle(prior.ManagedProcess.Applied)
					candidate.ManagedProcess.RuntimeObservation = prior.ManagedProcess.RuntimeObservation
					candidate.ManagedProcess.LastOperation = prior.ManagedProcess.LastOperation
					candidate.ManagedProcess.LastOperationResult = prior.ManagedProcess.LastOperationResult
					candidate.ManagedProcess.LastJobID = prior.ManagedProcess.LastJobID
				case domain.AppTargetTailnetHTTP:
					// Tailnet resources have no local process authority to preserve.
				default:
					return fmt.Errorf("resource update target kind is unsupported")
				}
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

func FindRunningHeadscaleInitialization(document persist.Document) (Reservation, jobs.Record, bool, error) {
	var found Reservation
	var record jobs.Record
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return Reservation{}, jobs.Record{}, false, err
		}
		if intent.Operation != HeadscaleInitialize || intent.Phase == PhaseRejected || intent.Phase == PhaseTerminal {
			continue
		}
		candidate, err := jobs.LoadEntries(document.Entries, intent.JobID)
		if err != nil || candidate.Status != jobs.StatusRunning || found.JobID != "" {
			return Reservation{}, jobs.Record{}, false, fmt.Errorf("running Headscale initialization authority is invalid or duplicated")
		}
		found, record = intent, candidate
	}
	return found, record, found.JobID != "", nil
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
	sourceAllowed := intent.AdmissionSource == AdmissionUI || intent.AdmissionSource == AdmissionRuntimeGuard && intent.Operation == ProcessStop
	if (intent.Operation != ProcessStart && intent.Operation != ProcessStop) || !sourceAllowed || intent.Target != "resource/"+resourceID || intent.SafetyBinding.ResourceID != resourceID || (intent.Phase != PhaseReserved && intent.Phase != PhaseLocalIntent) {
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

func clearGoAccessRetirementAuthority(record *domain.PublicationRecord) {
	record.PendingGoAccessRetirements = nil
	record.GoAccessRetirementSourceJobID = ""
	record.GoAccessRetirementSourceJournalID = ""
	record.GoAccessRetirementAuthorityDigest = ""
}

func publicationGoAccessModifiedPaths(resourceID string, bundle *domain.PublicationBundle) ([]string, error) {
	if bundle == nil || bundle.DomainHTTPS == nil || bundle.DomainHTTPS.GoAccess.RetiredGeneration == 0 {
		return nil, fmt.Errorf("publication GoAccess modified-path authority invalid")
	}
	goaccess := bundle.DomainHTTPS.GoAccess
	retirement := domain.GoAccessRetirementIdentity{Generation: goaccess.RetiredGeneration, StateGeneration: goaccess.RetiredStateGeneration, ServiceIdentity: goaccess.RetiredServiceIdentity, RemoveState: goaccess.RemovesRetiredState(), UnitIdentities: append([]string(nil), goaccess.RetiredUnitIdentities...)}
	retirementPaths, err := GoAccessRetirementModifiedPaths(resourceID, retirement)
	if err != nil {
		return nil, err
	}
	paths := append(append([]string(nil), bundle.ManagedPaths...), nginx.FixedPaths().ManifestPath())
	paths = append(paths, retirementPaths...)
	return paths, nil
}

func GoAccessStopModifiedPaths(resourceID string, generation uint64) ([]string, error) {
	if !validIdentityRef(resourceID) || !strings.HasPrefix(resourceID, "res_") || generation == 0 {
		return nil, fmt.Errorf("GoAccess stop modified-path authority invalid")
	}
	unitID := resourceID + "-" + strconv.FormatUint(generation, 10)
	paths := []string{
		"/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-" + unitID + ".service",
		"/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-relay-" + unitID + ".service",
		"/etc/systemd/system/sockets.target.wants/lanpanel-goaccess-" + unitID + ".socket",
		"/etc/systemd/system/timers.target.wants/lanpanel-goaccess-retention-" + unitID + ".timer",
		"/run/lanpanel-goaccess/" + unitID + ".sock",
		"/var/log/lanpanel/goaccess/" + resourceID,
	}
	slices.Sort(paths)
	return paths, nil
}

func GoAccessRetirementModifiedPaths(resourceID string, retirement domain.GoAccessRetirementIdentity) ([]string, error) {
	if !validIdentityRef(resourceID) || !strings.HasPrefix(resourceID, "res_") || retirement.Generation == 0 || retirement.StateGeneration == 0 || retirement.StateGeneration > retirement.Generation || len(retirement.UnitIdentities) != 5 {
		return nil, fmt.Errorf("GoAccess retirement modified-path authority invalid")
	}
	unitID := resourceID + "-" + strconv.FormatUint(retirement.Generation, 10)
	paths := []string{
		"/etc/systemd/system/lanpanel-goaccess-" + unitID + ".service",
		"/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-" + unitID + ".service",
		"/etc/systemd/system/lanpanel-goaccess-relay-" + unitID + ".service",
		"/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-relay-" + unitID + ".service",
		"/etc/systemd/system/lanpanel-goaccess-" + unitID + ".socket",
		"/etc/systemd/system/sockets.target.wants/lanpanel-goaccess-" + unitID + ".socket",
		"/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".service",
		"/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".timer",
		"/etc/systemd/system/timers.target.wants/lanpanel-goaccess-retention-" + unitID + ".timer",
		"/run/lanpanel-goaccess/" + unitID + ".sock",
		"/var/log/lanpanel/goaccess/" + resourceID,
	}
	if retirement.RemoveState {
		paths = append(paths, "/var/lib/lanpanel/goaccess/"+resourceID+"/generations/"+strconv.FormatUint(retirement.StateGeneration, 10))
	}
	if retirement.RemoveShared {
		paths = append(paths, "/var/lib/lanpanel/goaccess/"+resourceID, "/etc/sysusers.d/lanpanel-goaccess-"+resourceID+".conf", "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow")
	}
	slices.Sort(paths)
	return paths, nil
}

func GoAccessRetirementInventoryDigest(retirements []domain.GoAccessRetirementIdentity) (string, error) {
	data, err := json.Marshal(retirements)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func GoAccessRetirementBinding(installationID, resourceID, source, sourceJobID, sourceJournalID, authorityDigest string, retirements []domain.GoAccessRetirementIdentity) (SafetyBinding, error) {
	binding := SafetyBinding{ResourceID: resourceID, InstallationID: installationID, GoAccessSource: source, GoAccessSourceJobID: sourceJobID, GoAccessSourceJournalID: sourceJournalID, GoAccessAuthorityDigest: authorityDigest, GoAccessRetirements: append([]domain.GoAccessRetirementIdentity(nil), retirements...)}
	if err := validateGoAccessRetirementBinding(binding); err != nil {
		return SafetyBinding{}, err
	}
	return binding, nil
}

func validateGoAccessRetirementBinding(binding SafetyBinding) error {
	if !validIdentityRef(binding.InstallationID) || !strings.HasPrefix(binding.InstallationID, "ins_") || !validIdentityRef(binding.ResourceID) || !validIdentityRef(binding.GoAccessSourceJobID) || !exactDigest(binding.GoAccessAuthorityDigest) || len(binding.GoAccessRetirements) == 0 {
		return fmt.Errorf("GoAccess retirement binding incomplete")
	}
	prior := uint64(0)
	for _, item := range binding.GoAccessRetirements {
		if item.Generation <= prior || item.StateGeneration == 0 || item.StateGeneration > item.Generation || !exactDigest(item.ServiceIdentity) {
			return fmt.Errorf("GoAccess retirement binding inventory invalid")
		}
		prior = item.Generation
	}
	switch binding.GoAccessSource {
	case "publication":
		if binding.GoAccessSourceJournalID != "activation-"+binding.GoAccessSourceJobID || len(binding.GoAccessRetirements) != 1 {
			return fmt.Errorf("GoAccess publication retirement binding invalid")
		}
	case "contraction":
		if binding.GoAccessSourceJournalID != "" {
			return fmt.Errorf("GoAccess contraction retirement binding invalid")
		}
	default:
		return fmt.Errorf("GoAccess retirement binding source invalid")
	}
	return nil
}

func ValidateGoAccessRetirementAuthority(document persist.Document, binding SafetyBinding) error {
	if err := validateGoAccessRetirementBinding(binding); err != nil {
		return err
	}
	rawInstallation, present := document.Entries["installations/current"]
	if !present {
		return fmt.Errorf("GoAccess retirement installation missing")
	}
	installation, err := domain.DecodeInstallation(rawInstallation)
	if err != nil {
		return err
	}
	if installation.InstallationID != binding.InstallationID {
		return fmt.Errorf("GoAccess retirement installation changed")
	}
	sourceRecord, err := jobs.LoadEntries(document.Entries, binding.GoAccessSourceJobID)
	if err != nil {
		return err
	}
	for _, resource := range installation.Resources {
		if resource.ID != binding.ResourceID {
			continue
		}
		pendingDigest, digestErr := GoAccessRetirementInventoryDigest(resource.PublicationRecord.PendingGoAccessRetirements)
		if digestErr != nil {
			return digestErr
		}
		if resource.PublicationRecord.GoAccessRetirementSourceJobID != binding.GoAccessSourceJobID || resource.PublicationRecord.GoAccessRetirementSourceJournalID != binding.GoAccessSourceJournalID || resource.PublicationRecord.GoAccessRetirementAuthorityDigest != binding.GoAccessAuthorityDigest || pendingDigest != binding.GoAccessAuthorityDigest || !reflect.DeepEqual(resource.PublicationRecord.PendingGoAccessRetirements, binding.GoAccessRetirements) {
			return fmt.Errorf("GoAccess retirement source authority changed")
		}
		switch binding.GoAccessSource {
		case "publication":
			journalRaw, present := document.Entries["journals/"+binding.GoAccessSourceJournalID]
			if !present {
				return fmt.Errorf("GoAccess retirement journal missing")
			}
			var journal JournalRecord
			if err := decodeStrict(journalRaw, &journal); err != nil {
				return err
			}
			sourceTerminal := sourceRecord.Result == jobs.ResultPartial && sourceRecord.ErrorCode == "goaccess_stop_failed" || sourceRecord.Result == jobs.ResultInterrupted && sourceRecord.ErrorCode == "goaccess_retirement_recovery"
			if journal.JobID != binding.GoAccessSourceJobID || journal.Phase != JournalTerminal || sourceRecord.Status != jobs.StatusTerminal || !sourceTerminal {
				return fmt.Errorf("GoAccess publication retirement source changed")
			}
		case "contraction":
			if sourceRecord.Status != jobs.StatusTerminal || sourceRecord.Result != jobs.ResultPartial || sourceRecord.ErrorCode != "goaccess_stop_failed" {
				return fmt.Errorf("GoAccess contraction retirement source changed")
			}
		default:
			return fmt.Errorf("GoAccess retirement source invalid")
		}
		return nil
	}
	return fmt.Errorf("GoAccess retirement resource missing")
}

func FindRunningGoAccessRetirement(document persist.Document, target string) (Reservation, jobs.Record, bool, error) {
	var found Reservation
	var record jobs.Record
	present := false
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		intent, err := decodeReservation(raw)
		if err != nil {
			return Reservation{}, jobs.Record{}, false, err
		}
		if intent.Operation != GoAccessRetirement || intent.Target != target || intent.Phase != PhaseReserved && intent.Phase != PhaseLocalIntent {
			continue
		}
		if err := validateGoAccessRetirementBinding(intent.SafetyBinding); err != nil {
			return Reservation{}, jobs.Record{}, false, err
		}
		if present {
			return Reservation{}, jobs.Record{}, false, fmt.Errorf("multiple GoAccess retirement authorities")
		}
		record, err = jobs.LoadEntries(document.Entries, intent.JobID)
		if err != nil || intent.Phase == PhaseReserved && record.Status != jobs.StatusReserved || intent.Phase == PhaseLocalIntent && record.Status != jobs.StatusRunning {
			return Reservation{}, jobs.Record{}, false, fmt.Errorf("GoAccess retirement authority phase changed")
		}
		found = intent
		present = true
	}
	return found, record, present, nil
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

func transferPendingGoAccessRetirements(record *domain.PublicationRecord, retirements []domain.GoAccessRetirementIdentity) ([]domain.GoAccessRetirementIdentity, error) {
	for _, pending := range record.PendingGoAccessRetirements {
		matched := false
		for index := range retirements {
			if retirements[index].Generation == pending.Generation {
				if retirements[index].ServiceIdentity != pending.ServiceIdentity || !slices.Equal(retirements[index].UnitIdentities, pending.UnitIdentities) {
					return nil, fmt.Errorf("pending GoAccess retirement identity conflicts")
				}
				retirements[index].RemoveState = retirements[index].RemoveState || pending.RemoveState
				retirements[index].RemoveShared = retirements[index].RemoveShared || pending.RemoveShared
				matched = true
			}
		}
		if !matched {
			retirements = append(retirements, pending)
		}
	}
	slices.SortFunc(retirements, func(a, b domain.GoAccessRetirementIdentity) int { return cmp.Compare(a.Generation, b.Generation) })
	record.PendingGoAccessRetirements = nil
	record.GoAccessRetirementSourceJobID = ""
	record.GoAccessRetirementSourceJournalID = ""
	record.GoAccessRetirementAuthorityDigest = ""
	return retirements, nil
}

func goAccessRetirements(bundles ...*domain.PublicationBundle) ([]domain.GoAccessRetirementIdentity, error) {
	byGeneration := map[uint64]domain.GoAccessRetirementIdentity{}
	priorShared := false
	if len(bundles) > 0 && bundles[0] != nil && bundles[0].DomainHTTPS != nil {
		identity := bundles[0].DomainHTTPS.GoAccess
		priorShared = identity.Enabled || identity.RetiredGeneration != 0
	}
	for bundleIndex, bundle := range bundles {
		if bundle == nil || bundle.DomainHTTPS == nil {
			continue
		}
		identity := bundle.DomainHTTPS.GoAccess
		values := []domain.GoAccessRetirementIdentity{}
		if identity.Enabled {
			values = append(values, domain.GoAccessRetirementIdentity{Generation: identity.Generation, StateGeneration: identity.StateGeneration, ServiceIdentity: identity.ServiceIdentity, RemoveState: bundleIndex > 0 && identity.StateGeneration == identity.Generation, RemoveShared: bundleIndex > 0 && !priorShared, UnitIdentities: append([]string(nil), identity.UnitIdentities...)})
		}
		if identity.RetiredGeneration != 0 {
			values = append(values, domain.GoAccessRetirementIdentity{Generation: identity.RetiredGeneration, StateGeneration: identity.RetiredStateGeneration, ServiceIdentity: identity.RetiredServiceIdentity, RemoveState: bundleIndex > 0 && identity.RemovesRetiredState(), UnitIdentities: append([]string(nil), identity.RetiredUnitIdentities...)})
		}
		for _, value := range values {
			if prior, present := byGeneration[value.Generation]; present {
				if prior.StateGeneration != value.StateGeneration || prior.ServiceIdentity != value.ServiceIdentity || !slices.Equal(prior.UnitIdentities, value.UnitIdentities) {
					return nil, fmt.Errorf("GoAccess contraction generation identity conflicts")
				}
				value.RemoveState = value.RemoveState && prior.RemoveState
				value.RemoveShared = value.RemoveShared && prior.RemoveShared
			}
			byGeneration[value.Generation] = value
		}
	}
	generations := make([]uint64, 0, len(byGeneration))
	for generation := range byGeneration {
		generations = append(generations, generation)
	}
	slices.Sort(generations)
	result := make([]domain.GoAccessRetirementIdentity, 0, len(generations))
	for _, generation := range generations {
		result = append(result, byGeneration[generation])
	}
	return result, nil
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

// CompleteInterruptedEntity is a startup-only terminalizer for non-retryable
// Headscale entity and connector mutations. It relies on independently
// observed old-helper child closure and the already-consumed intent snapshot;
// it deliberately does not refresh or re-authorize an expired Plan. Connector
// login also requires the result of fresh read-only verification after secret
// cleanup; this observation does not establish the old remote mutation's result.
func (admitter *Admitter) CompleteInterruptedEntity(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, childClosureDigest, errorCode string, connectorVerification *jobs.Postcondition) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || !exactDigest(childClosureDigest) {
		return jobs.Record{}, fmt.Errorf("interrupted entity completion lacks authoritative closure locks")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		if err := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-1); err != nil {
			return err
		}
		intent, loadErr := loadReservation(transaction, jobID)
		if loadErr != nil {
			return loadErr
		}
		allowed := intent.Operation == HeadscaleUserCreate || intent.Operation == PreauthKeyCreate || intent.Operation == PreauthKeyRevoke || intent.Operation == DeviceExpire || intent.Operation == ConnectorBindingSet || intent.Operation == ConnectorLogin
		if !allowed || mutation.Target() != intent.Target || intent.Consumption == nil || (intent.Phase != PhaseLocalIntent && intent.Phase != PhaseRemoteWait && intent.Phase != PhaseReentered) {
			return fmt.Errorf("interrupted entity intent is not terminalizable")
		}
		wantCode := "headscale_lifecycle_interrupted"
		if intent.Operation == ConnectorBindingSet || intent.Operation == ConnectorLogin {
			wantCode = "connector_mutation_interrupted"
		}
		if errorCode != wantCode {
			return fmt.Errorf("interrupted entity error code does not match operation")
		}
		registration, present := admitter.registry.Registration(intent.Operation)
		if !present {
			return fmt.Errorf("interrupted entity operation owner is missing")
		}
		branch, present := registration.Results.Branch("source_unknown")
		if !present || branch.Postcondition != jobs.PostconditionUnobserved {
			return fmt.Errorf("interrupted entity result branch is invalid")
		}
		record, loadErr := jobs.Load(transaction, jobID)
		if loadErr != nil || record.Status != jobs.StatusRunning {
			return fmt.Errorf("interrupted entity job is not running")
		}
		conditions := []jobs.Postcondition{{Kind: "interrupted_remote_mutation", Status: jobs.PostconditionUnobserved, Identity: childClosureDigest}}
		if intent.Operation == ConnectorLogin {
			if connectorVerification == nil || connectorVerification.Kind != "connector_recovery_verification" ||
				(connectorVerification.Status != jobs.PostconditionVerified || !exactDigest(connectorVerification.Identity)) &&
					(connectorVerification.Status != jobs.PostconditionUnobserved || connectorVerification.Identity != jobID) {
				return fmt.Errorf("interrupted connector login lacks fresh verification result")
			}
			conditions = append(conditions, *connectorVerification)
		} else if connectorVerification != nil {
			return fmt.Errorf("interrupted entity has unrelated connector verification")
		}
		record, loadErr = jobs.Finish(record, jobs.Completion{Result: branch.Result, Postconditions: conditions, ErrorCode: errorCode}, observedNow)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = jobs.Replace(transaction, record); loadErr != nil {
			return loadErr
		}
		intent.Phase = PhaseTerminal
		raw, encodeErr := persist.EncodeEntry(intent)
		if encodeErr != nil {
			return encodeErr
		}
		if encodeErr = transaction.Replace(reservationKey(jobID), raw); encodeErr != nil {
			return encodeErr
		}
		completed = record
		return nil
	})
	return completed, err
}

func (admitter *Admitter) CompleteRecoveredResourceDelete(ctx context.Context, mutation *MutationLease, exposure *locks.Lease, expectedRevision uint64, jobID, resourceID, closureDigest string, succeeded bool) (jobs.Record, error) {
	if !authoritativeOperationLeases(admitter.normal, mutation, exposure) || mutation.Target() != "resource/"+resourceID || !exactDigest(closureDigest) {
		return jobs.Record{}, fmt.Errorf("resource delete recovery lacks exact authority")
	}
	observedNow, err := admitter.trustedNow()
	if err != nil {
		return jobs.Record{}, err
	}
	var completed jobs.Record
	_, _, err = admitter.normal.Update(ctx, exposure, expectedRevision, func(transaction *persist.Transaction) error {
		if err := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-1); err != nil {
			return err
		}
		intent, loadErr := loadReservation(transaction, jobID)
		if loadErr != nil || intent.Operation != ResourceDelete || intent.Target != "resource/"+resourceID || intent.Phase != PhaseLocalIntent || intent.Consumption == nil {
			return fmt.Errorf("resource delete recovery intent changed")
		}
		installation, loadErr := loadInstallation(transaction)
		if loadErr != nil {
			return loadErr
		}
		present := false
		active := false
		for _, resource := range installation.Resources {
			if resource.ID == resourceID {
				present = true
				active = resource.Lifecycle == domain.LifecycleActive && resource.PublicationRecord.State == domain.PublicationUnpublished
			}
		}
		condition := jobs.Postcondition{Kind: "resource_delete_not_started", Status: jobs.PostconditionKnown, Identity: closureDigest}
		completion := jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{condition}, ErrorCode: "resource_delete_not_started"}
		if succeeded {
			if present {
				return fmt.Errorf("recovered resource delete target still exists")
			}
			condition = jobs.Postcondition{Kind: "resource_managed_inventory_deleted", Status: jobs.PostconditionVerified, Identity: closureDigest}
			completion = jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{condition}}
		} else if !active {
			return fmt.Errorf("resource delete cannot abort after deletion began")
		}
		record, loadErr := jobs.Load(transaction, jobID)
		if loadErr != nil || record.Status != jobs.StatusRunning {
			return fmt.Errorf("resource delete recovery job is not running")
		}
		record, loadErr = jobs.Finish(record, completion, observedNow)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = jobs.Replace(transaction, record); loadErr != nil {
			return loadErr
		}
		intent.Phase = PhaseTerminal
		raw, encodeErr := persist.EncodeEntry(intent)
		if encodeErr != nil {
			return encodeErr
		}
		if encodeErr = transaction.Replace(reservationKey(jobID), raw); encodeErr != nil {
			return encodeErr
		}
		completed = record
		return nil
	})
	return completed, err
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
	if intentView.Operation == Publish {
		installation, err := loadInstallationEntries(document.Entries)
		if err != nil {
			return jobs.Record{}, err
		}
		if err := validatePublicationInventory(installation, state); err != nil {
			return jobs.Record{}, err
		}
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
			return jobs.Record{}, fmt.Errorf("plan-derived binding changed before terminal commit")
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
				if errorCode == "goaccess_stop_failed" && len(contraction.GoAccessRetirements) > 0 {
					retirementDigest, digestErr := GoAccessRetirementInventoryDigest(contraction.GoAccessRetirements)
					if digestErr != nil {
						return digestErr
					}
					resource.PublicationRecord.PendingGoAccessRetirements = append([]domain.GoAccessRetirementIdentity(nil), contraction.GoAccessRetirements...)
					resource.PublicationRecord.GoAccessRetirementSourceJobID = intent.JobID
					resource.PublicationRecord.GoAccessRetirementSourceJournalID = ""
					resource.PublicationRecord.GoAccessRetirementAuthorityDigest = retirementDigest
					resource.PublicationRecord.LastOperationResult = domain.OperationPartial
				} else {
					clearGoAccessRetirementAuthority(&resource.PublicationRecord)
					if errorCode == "" {
						resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
					} else {
						resource.PublicationRecord.LastOperationResult = domain.OperationPartial
					}
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
	if handoff == nil || state.StopFence != nil || state.GlobalClose.Phase != safety.GlobalCloseNone {
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

func exactHTTP01Challenge(state safety.State, operation Type, binding SafetyBinding) bool {
	if !exactCertificateChallenge(state, operation, binding) {
		return false
	}
	if binding.ResourceID == "headscale" {
		return state.Headscale.ChallengePending != nil && state.Headscale.ChallengePending.Method == "http-01"
	}
	for _, resource := range state.Resources {
		if resource.ResourceID == binding.ResourceID {
			return resource.ChallengePending != nil && resource.ChallengePending.Method == "http-01"
		}
	}
	return false
}

func exactCertificateChallenge(state safety.State, operation Type, binding SafetyBinding) bool {
	if binding.ResourceID == "headscale" {
		pending := state.Headscale.ChallengePending
		if pending == nil || pending.PlanID != binding.PlanID || pending.Generation != binding.IntentGeneration || pending.CertificateIdentity != binding.CertificateIdentity {
			return false
		}
		if operation == HeadscaleDeploy {
			return pending.ConfigDigest == binding.CandidateDigest && pending.ACMEBinding == binding.ACMEBinding
		}
		return operation == CertificateRenew && pending.SANIdentity == binding.CandidateDigest && pending.ACMEBinding == binding.CandidateBundle
	}
	if operation != Publish && operation != CertificateRenew {
		return false
	}
	for _, resource := range state.Resources {
		pending := resource.ChallengePending
		if resource.ResourceID == binding.ResourceID && pending != nil && pending.PlanID == binding.PlanID && pending.Generation == binding.IntentGeneration && pending.SANIdentity == binding.CandidateDigest && pending.ACMEBinding == binding.CandidateBundle && pending.CertificateIdentity == binding.CertificateIdentity {
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
	if intent.Operation == Publish {
		installation, err := loadInstallationEntries(document.Entries)
		if err != nil {
			return err
		}
		if err := validatePublicationInventory(installation, state); err != nil {
			return err
		}
	}
	currentDigest, err := safetyDigest(state)
	if err != nil {
		return err
	}
	if !isContraction(intent.Operation) && currentDigest != intent.Consumption.SafetyDigest {
		ownedChallenge := (intent.Operation == Publish || intent.Operation == CertificateRenew || intent.Operation == HeadscaleDeploy) && exactCertificateChallenge(state, intent.Operation, intent.SafetyBinding)
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
		return fmt.Errorf("plan-derived binding changed after intent commit")
	}
	return nil
}

func authorize(operation Type, state safety.State, binding SafetyBinding, consuming bool, now time.Time) error {
	if !validType(operation) || operation == EmergencyCloseAll {
		return fmt.Errorf("operation is unsupported for normal admission")
	}
	if operation == Publish {
		for _, resource := range state.Resources {
			if resource.Ownership == safety.OwnershipOrphan {
				return fmt.Errorf("resource %q is an ownership orphan and blocks publication; keep ingress closed; do not adopt or delete it; use configuration export and clean-host rebuild", resource.ResourceID)
			}
		}
	}
	contraction := isContraction(operation)
	if operation == CertificateExpiry {
		if binding.ResourceID == "headscale" && state.GlobalClose.Phase != safety.GlobalCloseNone {
			return fmt.Errorf("global close blocks Headscale certificate expiry")
		}
		existing := validExpiryBinding(operation, state, binding)
		proposal := validExpiryProposal(operation, state, binding, now)
		if binding.Deadline.IsZero() || !existing && (!proposal || binding.Deadline.After(now)) {
			return fmt.Errorf("expiry contraction authority binding is stale, absent, or not due")
		}
	}
	if operation == AutomaticReconciliation && binding.ResourceID == "headscale" {
		if state.GlobalClose.Phase != safety.GlobalCloseNone || !validExpiryBinding(CertificateExpiry, state, binding) {
			return fmt.Errorf("headscale expiry reconciliation authority is stale or globally blocked")
		}
	}
	if operation == StartupContraction && !validStartupBinding(state, binding) {
		return fmt.Errorf("startup contraction authority binding is stale or absent")
	}
	if state.StopFence != nil && !contraction {
		return fmt.Errorf("independent stop fence blocks expansion but not contraction")
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
		if state.GlobalClose.Phase != safety.GlobalCloseNone || state.StopFence != nil {
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
	if operation == HeadscaleDeploy {
		if state.StopFence != nil {
			return fmt.Errorf("global safety authority blocks Headscale deploy")
		}
		ownedChallenge := exactCertificateChallenge(state, operation, binding)
		if state.Headscale.CertificateExpiry != nil || state.Headscale.Reactivating != nil || state.Headscale.ChallengePending != nil && !ownedChallenge {
			return fmt.Errorf("headscale marker authority blocks deploy")
		}
	}
	if operation == CertificateRenew && binding.ResourceID == "headscale" {
		if state.StopFence != nil || state.GlobalClose.Phase != safety.GlobalCloseNone {
			return fmt.Errorf("headscale renewal blocked by shared safety marker")
		}
		ownedChallenge := exactCertificateChallenge(state, operation, binding)
		expiryChallenge := state.Headscale.CertificateExpiry != nil && binding.ExpiryGeneration == state.Headscale.CertificateExpiry.Generation && (binding.ChallengeMethod == "http-01" || binding.ChallengeMethod == "dns-01")
		if state.Headscale.CertificateExpiry != nil && !expiryChallenge || state.Headscale.Reactivating != nil || state.Headscale.ChallengePending != nil && !ownedChallenge {
			return fmt.Errorf("headscale renewal blocked by safety marker")
		}
	}
	if operation == CertificateRenew && binding.ResourceID != "headscale" {
		var resource *safety.ResourceSafety
		for index := range state.Resources {
			if state.Resources[index].ResourceID == binding.ResourceID {
				resource = &state.Resources[index]
			}
		}
		if resource == nil || resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || resource.Closing != nil {
			return fmt.Errorf("certificate safety resource unavailable")
		}
		ownedChallenge := exactCertificateChallenge(state, operation, binding)
		if state.GlobalClose.Phase != safety.GlobalCloseNone || resource.StickyUnpublished != nil || resource.Contraction != nil || resource.CertificateExpiry != nil || resource.ChallengePending != nil && !ownedChallenge || resource.Reactivating != nil {
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
		ownedChallenge := exactCertificateChallenge(state, operation, binding)
		challengeStart := consuming && binding.CertificateIdentity != "" && (binding.ChallengeMethod == "http-01" || binding.ChallengeMethod == "dns-01")
		if resource.Closing != nil || resource.State == safety.ResourceDeleting || resource.Ownership == safety.OwnershipOrphan || resource.ChallengePending != nil && !ownedChallenge {
			return fmt.Errorf("resource lifecycle or challenge authority blocks publish")
		}
		if resource.Reactivating != nil && !resource.Reactivating.TemporaryHTTP && (resource.Reactivating.CertificateUntil.Sub(now) < 5*time.Minute) {
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
	case CertificateExpiry:
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
	case HeadscaleDeploy:
		return preflight.RequireExpansionPlanEvidence([]preflight.ExpansionScope{preflight.ExpansionHeadscale}, "headscale", evidence, now)
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
	case Unpublish, CloseAll, CertificateExpiry, StartupContraction:
		return true
	default:
		return false
	}
}

func isContraction(operation Type) bool {
	switch operation {
	case Unpublish, CloseAll, CertificateExpiry, AutomaticReconciliation, StartupContraction, GoAccessRetirement:
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
	if operation != CertificateExpiry {
		return false
	}
	if binding.ResourceID == "headscale" {
		active := state.Headscale.ActiveCertificate
		if state.Headscale.CertificateExpiry != nil || active == nil || binding.ExpiryGeneration != state.Headscale.GenerationSequence+1 || binding.CandidateBundle != active.Binding {
			return false
		}
		deadline := active.NotAfter
		if now.Before(active.LastTrustedWall) {
			deadline = now
		}
		return binding.Deadline.Equal(deadline)
	}
	for _, resource := range state.Resources {
		if resource.ResourceID != binding.ResourceID || resource.State != safety.ResourceActive || resource.Ownership != safety.OwnershipOwned || binding.ExpiryGeneration != resource.GenerationSequence+1 || resource.CertificateExpiry != nil || resource.ActiveCertificate == nil || binding.CandidateBundle != resource.ActiveCertificate.Binding {
			continue
		}
		deadline := resource.ActiveCertificate.NotAfter
		if now.Before(resource.ActiveCertificate.LastTrustedWall) {
			deadline = now
		}
		return binding.Deadline.Equal(deadline)
	}
	return false
}

func validExpiryBinding(operation Type, state safety.State, binding SafetyBinding) bool {
	if operation != CertificateExpiry {
		return false
	}
	for _, resource := range state.Resources {
		if resource.ResourceID == binding.ResourceID && resource.CertificateExpiry != nil {
			return resource.CertificateExpiry.Generation == binding.ExpiryGeneration && resource.CertificateExpiry.Deadline.Equal(binding.Deadline) && resource.CertificateExpiry.Binding == binding.CandidateBundle
		}
	}
	if binding.ResourceID == "headscale" && state.Headscale.CertificateExpiry != nil {
		return state.Headscale.CertificateExpiry.Generation == binding.ExpiryGeneration && state.Headscale.CertificateExpiry.Deadline.Equal(binding.Deadline) && state.Headscale.CertificateExpiry.Binding == binding.CandidateBundle
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
	preflightKind := map[Type]preflight.ContractionKind{EmergencyCloseAll: preflight.ContractionEmergency, CertificateExpiry: preflight.ContractionExpiry, StartupContraction: preflight.ContractionStartup}[operation]
	expectedGeneration := binding.ExpiryGeneration
	switch operation {
	case EmergencyCloseAll:
		expectedGeneration = binding.ProposedGeneration
	case StartupContraction:
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
	case CertificateExpiry:
		if binding.ResourceID == "headscale" && state.GlobalClose.Phase != safety.GlobalCloseNone {
			return fmt.Errorf("global close blocks state-independent Headscale certificate expiry")
		}
		if !validExpiryBinding(operation, state, binding) || binding.Deadline.IsZero() {
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

func validatePublicationInventory(installation domain.Installation, state safety.State) error {
	if err := storeauthority.ValidateNormalSafety(&installation, state); err != nil {
		return fmt.Errorf("publish cross-store authority mismatch: %w", err)
	}
	return nil
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

func expiryGenerationKey(resourceID string) string { return "expiry_generations/" + resourceID }

func decodeExpiryGenerationRecord(raw json.RawMessage) (ExpiryGenerationRecord, error) {
	var value ExpiryGenerationRecord
	if err := decodeStrict(raw, &value); err != nil {
		return ExpiryGenerationRecord{}, err
	}
	kind, identity, separated := strings.Cut(value.Target, "/")
	exactTarget := separated && value.ResourceID != "headscale" && kind == "resource" && identity == value.ResourceID
	if value.SchemaVersion != "lanpanel.operation.expiry-generation.v1" || !validIdentityRef(value.ResourceID) || !validIdentityRef(value.Target) || !exactTarget || value.ExpiryGeneration == 0 || !validIdentityRef(value.JobID) || value.CreatedAt.IsZero() {
		return ExpiryGenerationRecord{}, fmt.Errorf("certificate expiry generation high-water is invalid")
	}
	return value, nil
}

func RequireNoActiveCertificateExpiry(document persist.Document, resourceID string) error {
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, strings.TrimPrefix(key, "intents/"))
		if err != nil {
			return err
		}
		if intent.Operation == CertificateExpiry && intent.SafetyBinding.ResourceID == resourceID && intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
			return fmt.Errorf("resource is blocked by nonterminal certificate expiry")
		}
	}
	return nil
}

func ExpiryGenerationHighWater(document persist.Document, resourceID string) (ExpiryGenerationRecord, bool, error) {
	raw, present := document.Entries[expiryGenerationKey(resourceID)]
	if !present {
		return ExpiryGenerationRecord{}, false, nil
	}
	value, err := decodeExpiryGenerationRecord(raw)
	return value, err == nil, err
}

func validateExpiryGenerationEntry(key string, raw json.RawMessage) error {
	value, err := decodeExpiryGenerationRecord(raw)
	if err != nil {
		return err
	}
	if key != expiryGenerationKey(value.ResourceID) {
		return fmt.Errorf("certificate expiry generation high-water key is invalid")
	}
	return nil
}

func validateExpiryGenerationTransition(_ string, before, after json.RawMessage) error {
	if len(after) == 0 {
		_, err := decodeExpiryGenerationRecord(before)
		return err
	}
	next, err := decodeExpiryGenerationRecord(after)
	if err != nil || len(before) == 0 {
		return err
	}
	current, err := decodeExpiryGenerationRecord(before)
	if err != nil {
		return err
	}
	if next.ResourceID != current.ResourceID || next.Target != current.Target || next.ExpiryGeneration <= current.ExpiryGeneration || next.JobID == current.JobID || next.CreatedAt.Before(current.CreatedAt) {
		return fmt.Errorf("certificate expiry generation high-water did not advance exactly")
	}
	return nil
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
	if identity == nil || !validIdentityRef(identity.CertificateID) || identity.CandidateGeneration == 0 || identity.StageUID == 0 || identity.StageGID == 0 || identity.Challenge.Generation == 0 || identity.Challenge.PlanID == "" || identity.Challenge.CertificateIdentity != identity.CertificateID {
		return fmt.Errorf("certificate journal pointer identity missing")
	}
	candidate := fmt.Sprintf("/var/lib/lanpanel/certificates/bundles/%s-%020d", identity.CertificateID, identity.CandidateGeneration)
	if identity.CandidatePointer != candidate {
		return fmt.Errorf("certificate journal candidate pointer invalid")
	}
	zeroBundleIdentity := certificates.BundleIdentity{}
	if identity.PriorGeneration == 0 {
		if identity.PriorPointer != "" || identity.PriorFingerprint != "" || identity.PriorBundleIdentity != zeroBundleIdentity {
			return fmt.Errorf("certificate journal unexpected prior identity")
		}
	} else {
		prior := fmt.Sprintf("/var/lib/lanpanel/certificates/bundles/%s-%020d", identity.CertificateID, identity.PriorGeneration)
		if identity.PriorPointer != prior || !exactDigest(identity.PriorFingerprint) || identity.CandidateGeneration != identity.PriorGeneration+1 || certificates.ValidateBundleIdentity(identity.PriorBundleIdentity) != nil || identity.PriorBundleIdentity.Fingerprint != identity.PriorFingerprint {
			return fmt.Errorf("certificate journal prior identity invalid")
		}
	}
	if identity.CandidateFingerprint == "" {
		if identity.CandidateBundleIdentity != zeroBundleIdentity {
			return fmt.Errorf("certificate journal unexpected candidate identity")
		}
	} else if !exactDigest(identity.CandidateFingerprint) || certificates.ValidateBundleIdentity(identity.CandidateBundleIdentity) != nil || identity.CandidateBundleIdentity.Fingerprint != identity.CandidateFingerprint {
		return fmt.Errorf("certificate journal candidate identity invalid")
	}
	if value.Phase == JournalActive && identity.CandidateFingerprint == "" {
		return fmt.Errorf("active certificate journal lacks candidate identity")
	}
	return nil
}

func validateJournalRecord(value JournalRecord) error {
	if value.SchemaVersion != "lanpanel.journal.v1" || !validIdentityRef(value.ID) || !validIdentityRef(value.JobID) || !validIdentityRef(value.InstallationID) || !validIdentityRef(value.Target) || value.Generation == 0 || value.Deadline.IsZero() || !exactDigest(value.ArtifactDigest) || !exactDigest(value.SafetyMarkerDigest) || value.RuntimeDigest != "" && !exactDigest(value.RuntimeDigest) || (value.Phase != JournalPrepared && value.Phase != JournalActive && value.Phase != JournalTerminal) {
		return fmt.Errorf("operation journal identity is invalid")
	}
	switch value.Kind {
	case JournalCertificateActivation:
		if err := validateCertificateJournalIdentity(value); err != nil {
			return err
		}
		exactResource := len(value.ResourceIDs) == 1 && value.Target == "resource/"+value.ResourceIDs[0]
		exactHeadscale := len(value.ResourceIDs) == 0 && (value.Target == "headscale" || strings.HasPrefix(value.Target, "headscale/"))
		if value.Operation != Publish && value.Operation != CertificateRenew && value.Operation != HeadscaleDeploy || !exactResource && !exactHeadscale {
			return fmt.Errorf("certificate activation journal identity is invalid")
		}
		if value.RuntimeDigest != "" && (!exactHeadscale || value.Operation != CertificateRenew || value.Phase != JournalTerminal) {
			return fmt.Errorf("certificate runtime evidence scope invalid")
		}
	case JournalAppActivation:
		if value.Operation != Publish || len(value.ResourceIDs) != 1 || value.Target != "resource/"+value.ResourceIDs[0] {
			return fmt.Errorf("app activation journal identity is invalid")
		}
	case JournalAppContraction:
		switch value.Operation {
		case Publish, Unpublish, CloseAll, CertificateExpiry, AutomaticReconciliation, StartupContraction:
		default:
			return fmt.Errorf("app contraction journal operation is not allowed")
		}
	default:
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
			return fmt.Errorf("app contraction journal does not exactly identify its affected resources")
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
	oldRuntime, newRuntime := oldValue.RuntimeDigest, newValue.RuntimeDigest
	oldValue.RuntimeDigest = ""
	newValue.RuntimeDigest = ""
	oldCandidateFingerprint, newCandidateFingerprint := "", ""
	oldCandidateIdentity, newCandidateIdentity := certificates.BundleIdentity{}, certificates.BundleIdentity{}
	var oldUID, oldGID, newUID, newGID uint32
	if oldValue.Certificate != nil {
		oldCandidateFingerprint = oldValue.Certificate.CandidateFingerprint
		oldCandidateIdentity = oldValue.Certificate.CandidateBundleIdentity
		oldUID = oldValue.Certificate.StageUID
		oldGID = oldValue.Certificate.StageGID
		oldValue.Certificate.CandidateFingerprint = ""
		oldValue.Certificate.CandidateBundleIdentity = certificates.BundleIdentity{}
		oldValue.Certificate.StageUID = 0
		oldValue.Certificate.StageGID = 0
	}
	if newValue.Certificate != nil {
		newCandidateFingerprint = newValue.Certificate.CandidateFingerprint
		newCandidateIdentity = newValue.Certificate.CandidateBundleIdentity
		newUID = newValue.Certificate.StageUID
		newGID = newValue.Certificate.StageGID
		newValue.Certificate.CandidateFingerprint = ""
		newValue.Certificate.CandidateBundleIdentity = certificates.BundleIdentity{}
		newValue.Certificate.StageUID = 0
		newValue.Certificate.StageGID = 0
	}
	oldValue.Phase = ""
	newValue.Phase = ""
	if !reflect.DeepEqual(oldValue, newValue) {
		return fmt.Errorf("journal identity was rewritten")
	}
	filledCandidate := oldCandidateFingerprint == "" && oldCandidateIdentity == (certificates.BundleIdentity{}) && exactDigest(newCandidateFingerprint) && certificates.ValidateBundleIdentity(newCandidateIdentity) == nil && newCandidateIdentity.Fingerprint == newCandidateFingerprint && oldUID == newUID && oldGID == newGID && oldUID != 0 && oldPhase == JournalPrepared && (newPhase == JournalPrepared || newPhase == JournalActive)
	sameCandidate := oldCandidateFingerprint == newCandidateFingerprint && oldCandidateIdentity == newCandidateIdentity && oldUID == newUID && oldGID == newGID
	if !filledCandidate && !sameCandidate {
		return fmt.Errorf("journal candidate bundle identity was rewritten")
	}
	runtimeFilled := oldRuntime == "" && exactDigest(newRuntime) && oldPhase == JournalActive && newPhase == JournalTerminal
	if oldRuntime != newRuntime && !runtimeFilled {
		return fmt.Errorf("journal runtime evidence was rewritten")
	}
	preparedAuthorization := oldPhase == JournalPrepared && newPhase == JournalPrepared && filledCandidate
	if oldPhase == JournalTerminal || oldPhase == JournalPrepared && newPhase != JournalActive && newPhase != JournalTerminal && !preparedAuthorization || oldPhase == JournalActive && newPhase != JournalTerminal {
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
	if raw, present := document.Entries["installations/current"]; present {
		installation, err := domain.DecodeInstallation(raw)
		if err != nil {
			return err
		}
		if installation.Headscale != nil && installation.Headscale.DeployIntent != nil {
			deploy := installation.Headscale.DeployIntent
			intent, ok := intents[deploy.JobID]
			if !ok || intent.Operation != HeadscaleDeploy || intent.PlanID != deploy.PlanID || intent.HeadscaleDeploy == nil || intent.HeadscaleDeploy.Candidate.HeadscaleID != installation.Headscale.ID || intent.HeadscaleDeploy.Candidate.CertificateBinding != deploy.CertificateBinding || intent.HeadscaleDeploy.PreflightResult.RequestDigest != deploy.PreflightDigest {
				return fmt.Errorf("headscale deploy domain intent has no exact operation authority")
			}
			applied, err := control.AppliedIdentity(intent.HeadscaleDeploy.Candidate)
			if err != nil || !reflect.DeepEqual(applied, deploy.Candidate) {
				return fmt.Errorf("headscale deploy candidate authority changed")
			}
			switch deploy.Phase {
			case domain.HeadscaleDeployPrepared:
				if intent.Phase != PhaseLocalIntent {
					return fmt.Errorf("prepared Headscale deploy is outside local intent")
				}
			case domain.HeadscaleDeployCertificatePending:
				if intent.Phase != PhaseLocalIntent && intent.Phase != PhaseRemoteWait && intent.Phase != PhaseReentered {
					return fmt.Errorf("pending Headscale certificate is outside remote authority")
				}
			case domain.HeadscaleDeployContracted:
				if intent.Phase != PhaseTerminal {
					return fmt.Errorf("contracted Headscale deploy is not terminal")
				}
				rawJournal, present := document.Entries["journals/certificate-"+deploy.JobID]
				if !present {
					return fmt.Errorf("contracted Headscale certificate journal is missing")
				}
				var journal JournalRecord
				if err := decodeStrict(rawJournal, &journal); err != nil || journal.Phase != JournalTerminal {
					return fmt.Errorf("contracted Headscale certificate journal is not terminal")
				}
			case domain.HeadscaleDeployCertificateStaged, domain.HeadscaleDeployActivating, domain.HeadscaleDeployActivated:
				if intent.Phase != PhaseReentered {
					return fmt.Errorf("staged or activating Headscale certificate is outside reentry authority")
				}
				rawJournal, present := document.Entries["journals/certificate-"+deploy.JobID]
				if !present {
					return fmt.Errorf("staged Headscale certificate journal is missing")
				}
				var journal JournalRecord
				if err := decodeStrict(rawJournal, &journal); err != nil || journal.Certificate == nil || journal.Certificate.CertificateID != deploy.Candidate.CertificateID || journal.Certificate.CandidateGeneration != 1 || journal.Certificate.CandidateFingerprint != deploy.CertificateFingerprint || journal.Certificate.CandidateBundleIdentity.BindingIdentity != deploy.CertificateBinding {
					return fmt.Errorf("staged Headscale certificate identity changed")
				}
			default:
				return fmt.Errorf("headscale deploy domain phase is invalid")
			}
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
			validPair := len(priorJournals) == 1 && intent.CertificateHandoff != nil && ((prior.Kind == JournalAppActivation && (prior.Phase == JournalPrepared || prior.Phase == JournalActive || prior.Phase == JournalTerminal) && journal.Kind == JournalCertificateActivation && journal.Phase == JournalTerminal) || (journal.Kind == JournalAppActivation && (journal.Phase == JournalPrepared || journal.Phase == JournalActive || journal.Phase == JournalTerminal) && prior.Kind == JournalCertificateActivation && prior.Phase == JournalTerminal))
			if !validPair {
				return fmt.Errorf("operation intent has incompatible journal authorities")
			}
		}
		journalsByJob[journal.JobID] = append(priorJournals, journal)
		journalByJob[journal.JobID] = true
		pendingCertificateReservation := journal.Kind == JournalCertificateActivation && journal.Phase == JournalPrepared && len(childrenByJob[journal.JobID]) < len(journal.ChildIDs) && slices.Equal(childrenByJob[journal.JobID], journal.ChildIDs[:len(childrenByJob[journal.JobID])])
		terminalNeverSubmitted := journal.Kind == JournalCertificateActivation && journal.Phase == JournalTerminal && intent.Phase == PhaseTerminal && len(childrenByJob[journal.JobID]) < len(journal.ChildIDs) && slices.Equal(childrenByJob[journal.JobID], journal.ChildIDs[:len(childrenByJob[journal.JobID])])
		handoffAppJournal := intent.CertificateHandoff != nil && journal.Kind == JournalAppActivation && (journal.Phase == JournalPrepared || journal.Phase == JournalActive || journal.Phase == JournalTerminal) && len(journal.ChildIDs) == 0
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

func validateExpiryGenerationProvenance(before, after persist.Document) error {
	for _, key := range persist.EntryKeys(after, "expiry_generations") {
		if raw, present := before.Entries[key]; present && string(raw) == string(after.Entries[key]) {
			continue
		}
		record, err := decodeExpiryGenerationRecord(after.Entries[key])
		if err != nil {
			return err
		}
		if _, existed := before.Entries[reservationKey(record.JobID)]; existed {
			return fmt.Errorf("certificate expiry generation high-water intent predates its transition")
		}
		if _, existed := before.Entries["jobs/"+record.JobID]; existed {
			return fmt.Errorf("certificate expiry generation high-water job predates its transition")
		}
		intent, err := loadReservationEntries(after.Entries, record.JobID)
		if err != nil {
			return fmt.Errorf("certificate expiry generation high-water lacks exact intent provenance: %w", err)
		}
		if intent.Operation != CertificateExpiry || intent.Target != record.Target || intent.SafetyBinding.ResourceID != record.ResourceID || intent.SafetyBinding.ExpiryGeneration != record.ExpiryGeneration || !intent.CreatedAt.Equal(record.CreatedAt) {
			return fmt.Errorf("certificate expiry generation high-water lacks exact intent provenance")
		}
		job, err := jobs.LoadEntries(after.Entries, record.JobID)
		if err != nil {
			return fmt.Errorf("certificate expiry generation high-water lacks exact job provenance: %w", err)
		}
		if job.Operation != string(CertificateExpiry) || job.Target != record.Target || !job.StartedAt.Equal(record.CreatedAt) {
			return fmt.Errorf("certificate expiry generation high-water lacks exact job provenance")
		}
	}
	return nil
}

func validateExpiryGenerationRemoval(before, after persist.Document) error {
	for _, key := range persist.EntryKeys(before, "expiry_generations") {
		if _, present := after.Entries[key]; present {
			continue
		}
		record, err := decodeExpiryGenerationRecord(before.Entries[key])
		if err != nil {
			return err
		}
		oldInstallation, err := loadInstallationEntries(before.Entries)
		if err != nil {
			return err
		}
		newInstallation, err := loadInstallationEntries(after.Entries)
		if err != nil {
			return err
		}
		oldPresent, newPresent := false, false
		for _, resource := range oldInstallation.Resources {
			oldPresent = oldPresent || resource.ID == record.ResourceID
		}
		for _, resource := range newInstallation.Resources {
			newPresent = newPresent || resource.ID == record.ResourceID
		}
		if !oldPresent || newPresent {
			return fmt.Errorf("certificate expiry generation high-water deletion lacks resource removal")
		}
		matchedDelete := false
		for _, intentKey := range persist.EntryKeys(after, "intents") {
			intent, loadErr := loadReservationEntries(after.Entries, strings.TrimPrefix(intentKey, "intents/"))
			if loadErr != nil {
				return loadErr
			}
			if intent.Operation == ResourceDelete && intent.Target == "resource/"+record.ResourceID && intent.Phase == PhaseLocalIntent {
				matchedDelete = true
			}
			if intent.Operation == CertificateExpiry && intent.SafetyBinding.ResourceID == record.ResourceID && intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
				return fmt.Errorf("certificate expiry generation high-water deletion has active expiry")
			}
		}
		if !matchedDelete {
			return fmt.Errorf("certificate expiry generation high-water deletion lacks resource-delete intent")
		}
	}
	return nil
}

func temporaryPublicationRestoredUnpublished(oldResource, resource domain.AppResource) bool {
	activation := oldResource.PublicationRecord.ActivationIntent
	return oldResource.Publication.Kind == domain.PublicationTemporaryHTTP && oldResource.Publication.TemporaryHTTP != nil && oldResource.PublicationRecord.State == domain.PublicationActivating && activation != nil && activation.Candidate.Kind == domain.PublicationTemporaryHTTP && activation.Candidate.TemporaryHTTP != nil && activation.PriorState == domain.PublicationUnpublished && resource.PublicationRecord.UnpublishedGeneration == oldResource.PublicationRecord.UnpublishedGeneration
}

func canonicalValueDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func exactRunningInstallationAuthority(before, after persist.Document, predicate func(Reservation) bool) error {
	matches := 0
	for _, key := range persist.EntryKeys(after, "intents") {
		jobID := strings.TrimPrefix(key, "intents/")
		afterIntent, err := loadReservationEntries(after.Entries, jobID)
		if err != nil {
			return err
		}
		afterRecord, err := jobs.LoadEntries(after.Entries, jobID)
		if err != nil {
			return fmt.Errorf("installation collection transition lacks current job: %w", err)
		}
		if afterIntent.Phase != PhaseLocalIntent || afterRecord.Status != jobs.StatusRunning {
			continue
		}
		beforeIntent, err := loadReservationEntries(before.Entries, jobID)
		if err != nil {
			return fmt.Errorf("installation collection transition lacks prior intent: %w", err)
		}
		beforeRecord, err := jobs.LoadEntries(before.Entries, jobID)
		if err != nil {
			return fmt.Errorf("installation collection transition lacks prior job: %w", err)
		}
		if !reflect.DeepEqual(beforeIntent, afterIntent) || beforeRecord.Status != jobs.StatusRunning || !reflect.DeepEqual(beforeRecord, afterRecord) {
			return fmt.Errorf("installation collection transition changed outside one running local intent")
		}
		if predicate(afterIntent) {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("installation collection transition has %d exact running authorities", matches)
	}
	return nil
}

func resourceDeleteCollectionAuthority(oldInstallation, newInstallation domain.Installation, intent Reservation, resourceID string) bool {
	if intent.Operation != ResourceDelete || intent.Target != "resource/"+resourceID || intent.SafetyBinding.ResourceID != resourceID {
		return false
	}
	foundOld := false
	for _, resource := range oldInstallation.Resources {
		if resource.ID == resourceID && resource.Lifecycle == domain.LifecycleDeleting && resource.PublicationRecord.LastOperation == domain.OperationResourceDelete && resource.PublicationRecord.LastJobID == intent.JobID {
			foundOld = true
		}
	}
	for _, resource := range newInstallation.Resources {
		if resource.ID == resourceID {
			return false
		}
	}
	return foundOld
}

func validateCredentialTransition(before, after persist.Document, oldInstallation, newInstallation domain.Installation) error {
	if reflect.DeepEqual(oldInstallation.Credentials, newInstallation.Credentials) {
		return nil
	}
	oldByID := make(map[string]domain.Credential, len(oldInstallation.Credentials))
	newByID := make(map[string]domain.Credential, len(newInstallation.Credentials))
	for _, credential := range oldInstallation.Credentials {
		oldByID[credential.ID] = credential
	}
	for _, credential := range newInstallation.Credentials {
		newByID[credential.ID] = credential
	}
	added := []domain.Credential{}
	removed := []domain.Credential{}
	changedOld := []domain.Credential{}
	changedNew := []domain.Credential{}
	for id, credential := range newByID {
		prior, present := oldByID[id]
		if !present {
			added = append(added, credential)
		} else if prior != credential {
			changedOld = append(changedOld, prior)
			changedNew = append(changedNew, credential)
		}
	}
	for id, credential := range oldByID {
		if _, present := newByID[id]; !present {
			removed = append(removed, credential)
		}
	}
	switch {
	case len(added) == 1 && len(removed) == 0 && len(changedOld) == 0:
		candidate := added[0]
		expected := append(append([]domain.Credential(nil), oldInstallation.Credentials...), candidate)
		slices.SortFunc(expected, func(a, b domain.Credential) int { return strings.Compare(a.ID, b.ID) })
		if !slices.Equal(expected, newInstallation.Credentials) {
			return fmt.Errorf("credential addition reordered unrelated authority")
		}
		switch candidate.Kind {
		case "managed_basic":
			binding, err := canonicalValueDigest(candidate)
			if err != nil {
				return err
			}
			jobID := ""
			if err := exactRunningInstallationAuthority(before, after, func(intent Reservation) bool {
				matches := intent.Operation == ManagedBasicCreate && intent.Target == "resource/"+candidate.OwnerResourceID && intent.SafetyBinding.ResourceID == candidate.OwnerResourceID && intent.OperationBinding == binding
				if matches {
					jobID = intent.JobID
				}
				return matches
			}); err != nil {
				return err
			}
			return requireManagedBasicCandidateChildEntries(after.Entries, jobID, candidate.Fingerprint)
		case "external_htpasswd":
			binding, err := canonicalValueDigest(candidate)
			if err != nil {
				return err
			}
			return exactRunningInstallationAuthority(before, after, func(intent Reservation) bool {
				return intent.Operation == ExternalHTPasswdRegister && intent.Target == "resource/"+candidate.OwnerResourceID && intent.SafetyBinding.ResourceID == candidate.OwnerResourceID && intent.SafetyBinding.CandidateDigest == candidate.Fingerprint && intent.SafetyBinding.CandidateBundle == binding
			})
		default:
			return fmt.Errorf("credential addition has no typed operation")
		}
	case len(added) == 0 && len(removed) == 0 && len(changedOld) == 1:
		prior, candidate := changedOld[0], changedNew[0]
		expectedCredential := prior
		expectedCredential.Fingerprint = candidate.Fingerprint
		expectedCollection := append([]domain.Credential(nil), oldInstallation.Credentials...)
		for index := range expectedCollection {
			if expectedCollection[index].ID == candidate.ID {
				expectedCollection[index] = candidate
			}
		}
		if prior.Kind != "managed_basic" || candidate.Fingerprint == prior.Fingerprint || candidate != expectedCredential || !slices.Equal(expectedCollection, newInstallation.Credentials) {
			return fmt.Errorf("credential update changed fields outside managed Basic fingerprint")
		}
		binding, err := canonicalValueDigest(candidate)
		if err != nil {
			return err
		}
		jobID := ""
		if err := exactRunningInstallationAuthority(before, after, func(intent Reservation) bool {
			matches := intent.Operation == ManagedBasicRotate && intent.Target == "credential/"+prior.ID && intent.SafetyBinding.ResourceID == prior.OwnerResourceID && intent.SafetyBinding.PriorFingerprint == prior.Fingerprint && intent.OperationBinding == binding
			if matches {
				jobID = intent.JobID
			}
			return matches
		}); err != nil {
			return err
		}
		return requireManagedBasicCandidateChildEntries(after.Entries, jobID, candidate.Fingerprint)
	case len(added) == 0 && len(changedOld) == 0 && len(removed) > 0:
		removedIDs := make(map[string]struct{}, len(removed))
		for _, credential := range removed {
			removedIDs[credential.ID] = struct{}{}
		}
		expected := make([]domain.Credential, 0, len(oldInstallation.Credentials)-len(removed))
		for _, credential := range oldInstallation.Credentials {
			if _, remove := removedIDs[credential.ID]; !remove {
				expected = append(expected, credential)
			}
		}
		if !slices.Equal(expected, newInstallation.Credentials) {
			return fmt.Errorf("credential deletion reordered unrelated authority")
		}
		return exactRunningInstallationAuthority(before, after, func(intent Reservation) bool {
			if len(removed) == 1 {
				prior := removed[0]
				if prior.Kind == "managed_basic" && intent.Operation == ManagedBasicDelete && intent.Target == "credential/"+prior.ID && intent.SafetyBinding.ResourceID == prior.OwnerResourceID && intent.SafetyBinding.PriorFingerprint == prior.Fingerprint {
					return true
				}
			}
			resourceID := removed[0].OwnerResourceID
			for _, credential := range removed {
				if credential.OwnerResourceID != resourceID {
					return false
				}
			}
			for _, credential := range oldInstallation.Credentials {
				if credential.OwnerResourceID == resourceID {
					if _, retained := newByID[credential.ID]; retained {
						return false
					}
				}
			}
			return resourceDeleteCollectionAuthority(oldInstallation, newInstallation, intent, resourceID)
		})
	default:
		return fmt.Errorf("credential collection changed more than one typed operation permits")
	}
}

func validateStaticRootTransition(before, after persist.Document, oldInstallation, newInstallation domain.Installation) error {
	if reflect.DeepEqual(oldInstallation.StaticRoots, newInstallation.StaticRoots) {
		return nil
	}
	oldByID := make(map[string]domain.StaticContentRoot, len(oldInstallation.StaticRoots))
	newByID := make(map[string]domain.StaticContentRoot, len(newInstallation.StaticRoots))
	for _, root := range oldInstallation.StaticRoots {
		oldByID[root.ID] = root
	}
	for _, root := range newInstallation.StaticRoots {
		newByID[root.ID] = root
	}
	added := []domain.StaticContentRoot{}
	removed := []domain.StaticContentRoot{}
	changed := false
	for id, root := range newByID {
		prior, present := oldByID[id]
		if !present {
			added = append(added, root)
		} else if prior != root {
			changed = true
		}
	}
	for id, root := range oldByID {
		if _, present := newByID[id]; !present {
			removed = append(removed, root)
		}
	}
	switch {
	case len(added) == 1 && len(removed) == 0 && !changed:
		candidate := added[0]
		expected := append(append([]domain.StaticContentRoot(nil), oldInstallation.StaticRoots...), candidate)
		slices.SortFunc(expected, func(a, b domain.StaticContentRoot) int { return strings.Compare(a.ID, b.ID) })
		if !slices.Equal(expected, newInstallation.StaticRoots) {
			return fmt.Errorf("static root addition reordered unrelated authority")
		}
		binding, err := canonicalValueDigest(candidate)
		if err != nil {
			return err
		}
		return exactRunningInstallationAuthority(before, after, func(intent Reservation) bool {
			return intent.Operation == StaticRootRegister && intent.Target == "resource/"+candidate.OwnerResourceID && intent.SafetyBinding.ResourceID == candidate.OwnerResourceID && intent.SafetyBinding.CandidateDigest == candidate.Fingerprint && intent.SafetyBinding.CandidateBundle == binding
		})
	case len(added) == 0 && len(removed) > 0 && !changed:
		removedIDs := make(map[string]struct{}, len(removed))
		for _, root := range removed {
			removedIDs[root.ID] = struct{}{}
		}
		expected := make([]domain.StaticContentRoot, 0, len(oldInstallation.StaticRoots)-len(removed))
		for _, root := range oldInstallation.StaticRoots {
			if _, remove := removedIDs[root.ID]; !remove {
				expected = append(expected, root)
			}
		}
		if !slices.Equal(expected, newInstallation.StaticRoots) {
			return fmt.Errorf("static root deletion reordered unrelated authority")
		}
		resourceID := removed[0].OwnerResourceID
		for _, root := range removed {
			if root.OwnerResourceID != resourceID {
				return fmt.Errorf("static roots from multiple owners changed together")
			}
		}
		for _, root := range oldInstallation.StaticRoots {
			if root.OwnerResourceID == resourceID {
				if _, retained := newByID[root.ID]; retained {
					return fmt.Errorf("resource deletion retained an owned static root")
				}
			}
		}
		return exactRunningInstallationAuthority(before, after, func(intent Reservation) bool {
			return resourceDeleteCollectionAuthority(oldInstallation, newInstallation, intent, resourceID)
		})
	default:
		return fmt.Errorf("static root collection changed more than one typed operation permits")
	}
}

func validateOperationStateTransitions(before, after persist.Document) error {
	if err := validateOperationRetentionTransition(before, after); err != nil {
		return err
	}
	if err := validateExpiryGenerationProvenance(before, after); err != nil {
		return err
	}
	if err := validateExpiryGenerationRemoval(before, after); err != nil {
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
	if err := validateCredentialTransition(before, after, oldInstallation, newInstallation); err != nil {
		return err
	}
	if err := validateStaticRootTransition(before, after, oldInstallation, newInstallation); err != nil {
		return err
	}
	oldBase, newBase := oldInstallation, newInstallation
	oldBase.Headscale, newBase.Headscale = nil, nil
	oldBase.Connector, newBase.Connector = nil, nil
	oldBase.Credentials, newBase.Credentials = nil, nil
	oldBase.StaticRoots, newBase.StaticRoots = nil, nil
	oldBase.Resources, newBase.Resources = nil, nil
	if !reflect.DeepEqual(oldBase, newBase) {
		return fmt.Errorf("installation authority outside typed Headscale, connector, credential, static-root, or resource transitions changed")
	}
	if !reflect.DeepEqual(oldInstallation.Connector, newInstallation.Connector) {
		if newInstallation.Connector == nil || newInstallation.Connector.LastJobID == "" || (newInstallation.Connector.LastOperation != domain.OperationConnectorBindingSet && newInstallation.Connector.LastOperation != domain.OperationConnectorLogin) {
			return fmt.Errorf("connector transition lacks durable job identity")
		}
		intent, err := loadReservationEntries(after.Entries, newInstallation.Connector.LastJobID)
		if err != nil || (intent.Operation != ConnectorBindingSet && intent.Operation != ConnectorLogin) || intent.Target != "connector" || intent.Operation == ConnectorBindingSet && intent.Phase != PhaseLocalIntent || intent.Operation == ConnectorLogin && intent.Phase != PhaseReentered {
			return fmt.Errorf("connector transition lacks exact local intent")
		}
		if oldInstallation.Connector != nil && (intent.Operation != ConnectorLogin || oldInstallation.Connector.ID != newInstallation.Connector.ID || oldInstallation.Connector.ControlURL != newInstallation.Connector.ControlURL || !slices.Equal(oldInstallation.Connector.ManagedPaths, newInstallation.Connector.ManagedPaths)) {
			return fmt.Errorf("connector binding is immutable")
		}
	}
	if !reflect.DeepEqual(oldInstallation.Headscale, newInstallation.Headscale) {
		if oldInstallation.Headscale == nil {
			if newInstallation.Headscale == nil {
				return fmt.Errorf("headscale initialization candidate disappeared")
			}
			headscale := newInstallation.Headscale
			if headscale.LastJobID == "" || headscale.LastOperation != domain.OperationHeadscaleInitialize {
				return fmt.Errorf("headscale initialization lacks durable job identity")
			}
			beforeIntent, err := loadReservationEntries(before.Entries, headscale.LastJobID)
			if err != nil {
				return err
			}
			afterIntent, err := loadReservationEntries(after.Entries, headscale.LastJobID)
			if err != nil {
				return err
			}
			beforeRecord, err := jobs.LoadEntries(before.Entries, headscale.LastJobID)
			if err != nil {
				return err
			}
			afterRecord, err := jobs.LoadEntries(after.Entries, headscale.LastJobID)
			if err != nil {
				return err
			}
			if beforeIntent.Operation != HeadscaleInitialize || afterIntent.Operation != HeadscaleInitialize || beforeIntent.Target != string(plans.TargetInstallation) || afterIntent.Target != string(plans.TargetInstallation) || beforeIntent.Phase != PhaseReentered || afterIntent.Phase != PhaseReentered || beforeRecord.Status != jobs.StatusRunning || afterRecord.Status != jobs.StatusRunning {
				return fmt.Errorf("headscale initialization changed outside its running local intent")
			}
		} else {
			if newInstallation.Headscale == nil || domain.ValidateHeadscaleTransition(*oldInstallation.Headscale, *newInstallation.Headscale) != nil {
				return fmt.Errorf("headscale identity cannot be removed or changed by deploy")
			}
			oldHeadscale, newHeadscale := oldInstallation.Headscale, newInstallation.Headscale
			completing := oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivated && newHeadscale.DeployIntent == nil
			failingPrepared := oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployPrepared && newHeadscale.DeployIntent == nil
			renewing := oldHeadscale.DeployIntent == nil && newHeadscale.DeployIntent == nil && newHeadscale.LastOperation == domain.OperationHeadscaleReissue
			reissueActivating := oldHeadscale.DeployIntent == nil && newHeadscale.DeployIntent != nil && newHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivating && newHeadscale.LastOperation == domain.OperationHeadscaleReissue
			reissueCompleting := oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivating && newHeadscale.DeployIntent == nil && newHeadscale.LastOperation == domain.OperationHeadscaleReissue
			if (!completing && !failingPrepared && !renewing && !reissueActivating && !reissueCompleting && newHeadscale.DeployIntent == nil) || newHeadscale.LastJobID == "" || (!renewing && !reissueActivating && !reissueCompleting && newHeadscale.LastOperation != domain.OperationHeadscaleControlDeploy) {
				return fmt.Errorf("headscale deploy lacks durable intent")
			}
			expected := *oldHeadscale
			beforePhase, afterPhase := PhaseLocalIntent, PhaseLocalIntent
			beforeStatus, afterStatus := jobs.StatusRunning, jobs.StatusRunning
			contracting := false
			expectedOperation := HeadscaleDeploy
			expectedTarget := string(plans.TargetHeadscale) + "/" + newHeadscale.ID
			switch {
			case failingPrepared:
				expected.DeployIntent = nil
				beforePhase, afterPhase = PhaseLocalIntent, PhaseTerminal
				beforeStatus, afterStatus = jobs.StatusRunning, jobs.StatusTerminal
			case reissueActivating:
				expected.DeployIntent = newHeadscale.DeployIntent
				expected.LastOperation = newHeadscale.LastOperation
				expected.LastJobID = newHeadscale.LastJobID
				beforePhase, afterPhase = PhaseReentered, PhaseReentered
				expectedOperation = CertificateRenew
			case reissueCompleting:
				expected.DeployIntent = nil
				expected.Certificate = newHeadscale.Certificate
				expected.LastOperation = newHeadscale.LastOperation
				expected.LastJobID = newHeadscale.LastJobID
				beforePhase, afterPhase = PhaseReentered, PhaseReentered
				expectedOperation = CertificateRenew
			case renewing:
				expected.Certificate = newHeadscale.Certificate
				expected.LastOperation = newHeadscale.LastOperation
				expected.LastJobID = newHeadscale.LastJobID
				beforePhase, afterPhase = PhaseReentered, PhaseReentered
				expectedOperation = CertificateRenew
				expectedTarget = string(plans.TargetHeadscale) + "/" + newHeadscale.ID
			case oldHeadscale.DeployIntent == nil && newHeadscale.DeployIntent.Phase == domain.HeadscaleDeployPrepared:
				expected.DeployIntent = newHeadscale.DeployIntent
				expected.LastJobID = newHeadscale.LastJobID
				expected.LastOperation = domain.OperationHeadscaleControlDeploy
			case oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployPrepared && newHeadscale.DeployIntent.Phase == domain.HeadscaleDeployCertificatePending:
				expected.DeployIntent = newHeadscale.DeployIntent
				expected.Database.Phase = domain.HeadscaleInitialized
				expected.Database.InitializedDigest = newHeadscale.Database.InitializedDigest
			case oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployCertificatePending && newHeadscale.DeployIntent.Phase == domain.HeadscaleDeployCertificateStaged:
				expected.DeployIntent = newHeadscale.DeployIntent
				beforePhase, afterPhase = PhaseReentered, PhaseReentered
			case oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployCertificateStaged && newHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivating:
				expected.DeployIntent = newHeadscale.DeployIntent
				beforePhase, afterPhase = PhaseReentered, PhaseReentered
			case oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivating && newHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivated:
				expected.DeployIntent = newHeadscale.DeployIntent
				expected.Applied, expected.Enabled = newHeadscale.Applied, newHeadscale.Enabled
				beforePhase, afterPhase = PhaseReentered, PhaseReentered
			case oldHeadscale.DeployIntent != nil && oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivated && newHeadscale.DeployIntent == nil:
				expected.DeployIntent = nil
				expected.Certificate = newHeadscale.Certificate
				beforePhase, afterPhase = PhaseReentered, PhaseReentered
				beforeStatus, afterStatus = jobs.StatusRunning, jobs.StatusRunning
			case oldHeadscale.DeployIntent != nil && (oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployCertificatePending || oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployCertificateStaged || oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivating || oldHeadscale.DeployIntent.Phase == domain.HeadscaleDeployActivated) && newHeadscale.DeployIntent.Phase == domain.HeadscaleDeployContracted:
				expected.DeployIntent = newHeadscale.DeployIntent
				expected.Applied, expected.Enabled = newHeadscale.Applied, newHeadscale.Enabled
				beforePhase, afterPhase = PhaseReentered, PhaseTerminal
				beforeStatus, afterStatus = jobs.StatusRunning, jobs.StatusTerminal
				contracting = true
			default:
				return fmt.Errorf("headscale deploy state transition is not owned")
			}
			if !reflect.DeepEqual(expected, *newHeadscale) {
				return fmt.Errorf("headscale deploy changed unrelated authority")
			}
			beforeIntent, err := loadReservationEntries(before.Entries, newHeadscale.LastJobID)
			if err != nil {
				return err
			}
			afterIntent, err := loadReservationEntries(after.Entries, newHeadscale.LastJobID)
			if err != nil {
				return err
			}
			beforeRecord, err := jobs.LoadEntries(before.Entries, newHeadscale.LastJobID)
			if err != nil {
				return err
			}
			afterRecord, err := jobs.LoadEntries(after.Entries, newHeadscale.LastJobID)
			if err != nil {
				return err
			}
			phaseValid := beforeIntent.Phase == beforePhase && afterIntent.Phase == afterPhase
			if contracting {
				phaseValid = (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered) && afterIntent.Phase == PhaseTerminal
			}
			if beforeIntent.Operation != expectedOperation || afterIntent.Operation != expectedOperation || beforeIntent.Target != expectedTarget || afterIntent.Target != expectedTarget || !phaseValid || beforeRecord.Status != beforeStatus || afterRecord.Status != afterStatus {
				return fmt.Errorf("headscale deploy changed outside its running exact intent")
			}
		}
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
		if !slices.Equal(oldResource.PublicationRecord.CertificateInventory, resource.PublicationRecord.CertificateInventory) {
			if err := validateCertificateInventoryTransition(before, after, oldResource, resource); err != nil {
				return err
			}
			delete(oldResources, resource.ID)
			continue
		}
		if !resourceConfigurationEqual(oldResource, resource) {
			if err := validateResourceUpdateConfigurationTransition(before, after, oldResource, resource); err != nil {
				return fmt.Errorf("resource %q: %w", resource.ID, err)
			}
			delete(oldResources, resource.ID)
			continue
		}
		if oldResource.Target.Kind != resource.Target.Kind {
			return fmt.Errorf("resource %q target kind changed", resource.ID)
		}
		if err := validateResourceManagedProcessPresence(oldResource); err != nil {
			return fmt.Errorf("resource %q prior authority: %w", resource.ID, err)
		}
		if err := validateResourceManagedProcessPresence(resource); err != nil {
			return fmt.Errorf("resource %q candidate authority: %w", resource.ID, err)
		}
		if protectedResourceStateEqual(oldResource, resource) {
			delete(oldResources, resource.ID)
			continue
		}
		if resource.PublicationRecord.UnpublishedGeneration < oldResource.PublicationRecord.UnpublishedGeneration {
			return fmt.Errorf("resource %q unpublished generation regressed", resource.ID)
		}
		if resource.PublicationRecord.State == domain.PublicationUnpublished && oldResource.PublicationRecord.State != domain.PublicationUnpublished && resource.PublicationRecord.UnpublishedGeneration <= oldResource.PublicationRecord.UnpublishedGeneration {
			if !temporaryPublicationRestoredUnpublished(oldResource, resource) {
				return fmt.Errorf("resource %q contraction did not allocate a fresh unpublished generation", resource.ID)
			}
		}
		jobID := resource.PublicationRecord.LastJobID
		if resource.Target.Kind == domain.AppTargetLocalHTTP && (resource.ManagedProcess.LastJobID != oldResource.ManagedProcess.LastJobID || reflect.DeepEqual(resource.PublicationRecord, oldResource.PublicationRecord)) {
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
		pendingRetirementActivation := oldResource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.State == domain.PublicationPublished && resource.PublicationRecord.ActivationIntent == nil && (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered) && intent.Phase == PhaseLocalIntent && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusRunning && resource.PublicationRecord.LastAppliedBundle != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS != nil && resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.GoAccess.RetiredGeneration != 0
		retirementTerminalBase := oldResource.PublicationRecord.State == domain.PublicationPublished && oldResource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.State == domain.PublicationPublished && resource.PublicationRecord.ActivationIntent == nil && beforeIntent.Phase == PhaseLocalIntent && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal && intent.Operation == Publish
		terminalRetirement := retirementTerminalBase && record.Result == jobs.ResultSucceeded
		failedRetirement := retirementTerminalBase && record.Result == jobs.ResultPartial
		interruptedRetirement := retirementTerminalBase && record.Result == jobs.ResultInterrupted
		terminalActivation := oldResource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.State == domain.PublicationPublished && resource.PublicationRecord.ActivationIntent == nil && (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered) && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal
		committedRecoveryContraction := oldResource.PublicationRecord.State == domain.PublicationPublished && oldResource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.State == domain.PublicationUnpublished && resource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.UnpublishedGeneration > oldResource.PublicationRecord.UnpublishedGeneration && beforeIntent.Phase == PhaseTerminal && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusTerminal && record.Status == jobs.StatusTerminal && (record.Result == jobs.ResultSucceeded || record.Result == jobs.ResultInterrupted && record.ErrorCode == "goaccess_retirement_recovery")
		interruptedActivation := oldResource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.State == domain.PublicationUnpublished && resource.PublicationRecord.ActivationIntent == nil && resource.PublicationRecord.UnpublishedGeneration > oldResource.PublicationRecord.UnpublishedGeneration && beforeIntent.Phase == PhaseLocalIntent && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal && (record.Result == jobs.ResultInterrupted || record.Result == jobs.ResultPartial && record.ErrorCode == "goaccess_stop_failed")
		failedActivation := oldResource.PublicationRecord.State == domain.PublicationActivating && oldResource.PublicationRecord.ActivationIntent != nil && resource.PublicationRecord.State == oldResource.PublicationRecord.ActivationIntent.PriorState && resource.PublicationRecord.ActivationIntent == nil && beforeIntent.Phase == PhaseLocalIntent && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal && record.Result == jobs.ResultFailed
		beginningContraction := oldResource.PublicationRecord.ContractionIntent == nil && resource.PublicationRecord.ContractionIntent != nil && beforeIntent.Phase == intent.Phase && (intent.Phase == PhaseLocalIntent || intent.Phase == PhaseReentered) && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusRunning
		terminalContraction := oldResource.PublicationRecord.ContractionIntent != nil && resource.PublicationRecord.ContractionIntent == nil && (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered) && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal
		terminalGoAccessContractionReconciliation := oldResource.PublicationRecord.State == domain.PublicationUnpublished && resource.PublicationRecord.State == domain.PublicationUnpublished && len(oldResource.PublicationRecord.PendingGoAccessRetirements) > 0 && len(resource.PublicationRecord.PendingGoAccessRetirements) == 0 && intent.Operation == GoAccessRetirement && beforeIntent.Phase == PhaseLocalIntent && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal && record.Result == jobs.ResultSucceeded
		terminalGoAccessReconciliation := oldResource.PublicationRecord.State == domain.PublicationPublished && resource.PublicationRecord.State == domain.PublicationPublished && reflect.DeepEqual(oldResource.PublicationRecord.LastAppliedBundle, resource.PublicationRecord.LastAppliedBundle) && intent.Operation == GoAccessRetirement && beforeIntent.Phase == PhaseLocalIntent && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal && record.Result == jobs.ResultSucceeded
		ordinaryLocal := oldResource.PublicationRecord.ContractionIntent == nil && resource.PublicationRecord.ContractionIntent == nil && beforeIntent.Phase == intent.Phase && intent.Phase == PhaseLocalIntent && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusRunning && (intent.Operation == ResourceUpdate || intent.Operation == ResourceDelete || intent.Operation == ProcessStart || intent.Operation == ProcessStop)
		ordinaryTerminal := intent.Operation != Publish && oldResource.PublicationRecord.ContractionIntent == nil && resource.PublicationRecord.ContractionIntent == nil && (beforeIntent.Phase == PhaseLocalIntent || beforeIntent.Phase == PhaseReentered || beforeIntent.Phase == PhaseRemoteWait && intent.Operation == CertificateRenew) && intent.Phase == PhaseTerminal && beforeRecord.Status == jobs.StatusRunning && record.Status == jobs.StatusTerminal
		switch {
		case beginningActivation:
			activation := resource.PublicationRecord.ActivationIntent
			if activation.JobID != intent.JobID || activation.PlanID != intent.PlanID || activation.Generation != intent.SafetyBinding.IntentGeneration || resource.PublicationRecord.LastJobID != intent.JobID {
				return fmt.Errorf("resource %q activation identity does not match durable intent", resource.ID)
			}
		case pendingRetirementActivation:
			activation := oldResource.PublicationRecord.ActivationIntent
			if activation.JobID != intent.JobID || resource.PublicationRecord.LastAppliedBundle == nil || !reflect.DeepEqual(*resource.PublicationRecord.LastAppliedBundle, activation.Candidate) || resource.PublicationRecord.LastOperation != domain.OperationPublish || resource.PublicationRecord.LastOperationResult != domain.OperationPartial {
				return fmt.Errorf("resource %q pending GoAccess retirement authority changed", resource.ID)
			}
		case terminalRetirement:
			if !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle, oldResource.PublicationRecord.LastAppliedBundle) || resource.PublicationRecord.LastOperation != domain.OperationPublish || resource.PublicationRecord.LastOperationResult != domain.OperationSucceeded {
				return fmt.Errorf("resource %q GoAccess retirement terminal result changed", resource.ID)
			}
		case failedRetirement:
			if !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle, oldResource.PublicationRecord.LastAppliedBundle) || resource.PublicationRecord.LastOperation != domain.OperationPublish || resource.PublicationRecord.LastOperationResult != domain.OperationPartial || record.ErrorCode != "goaccess_stop_failed" {
				return fmt.Errorf("resource %q GoAccess retirement partial result changed", resource.ID)
			}
		case interruptedRetirement:
			if !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle, oldResource.PublicationRecord.LastAppliedBundle) || resource.PublicationRecord.LastOperation != domain.OperationPublish || resource.PublicationRecord.LastOperationResult != domain.OperationInterrupted || record.ErrorCode != "goaccess_retirement_recovery" {
				return fmt.Errorf("resource %q GoAccess retirement interruption changed", resource.ID)
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
			if resource.PublicationRecord.LastAppliedDigest != oldResource.PublicationRecord.LastAppliedDigest || !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle, oldResource.PublicationRecord.LastAppliedBundle) || resource.PublicationRecord.LastOperation != domain.OperationPublish || string(resource.PublicationRecord.LastOperationResult) != string(record.Result) {
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
		case terminalGoAccessContractionReconciliation:
			if resource.PublicationRecord.LastJobID != intent.JobID || resource.PublicationRecord.LastOperation != oldResource.PublicationRecord.LastOperation || resource.PublicationRecord.LastOperationResult != domain.OperationSucceeded {
				return fmt.Errorf("resource %q GoAccess contraction reconciliation changed", resource.ID)
			}
		case terminalGoAccessReconciliation:
			if resource.PublicationRecord.LastJobID != intent.JobID || resource.PublicationRecord.LastOperation != domain.OperationPublish || resource.PublicationRecord.LastOperationResult != domain.OperationSucceeded {
				return fmt.Errorf("resource %q GoAccess reconciliation result changed", resource.ID)
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
	for resourceID, resource := range oldResources {
		matched := false
		for _, key := range persist.EntryKeys(after, "intents") {
			intent, err := loadReservationEntries(after.Entries, strings.TrimPrefix(key, "intents/"))
			if err == nil && intent.Operation == ResourceDelete && intent.Target == "resource/"+resourceID && intent.Phase == PhaseLocalIntent {
				record, recordErr := jobs.LoadEntries(after.Entries, intent.JobID)
				matched = recordErr == nil && record.Status == jobs.StatusRunning && resource.Lifecycle == domain.LifecycleDeleting && resource.PublicationRecord.LastJobID == intent.JobID
				break
			}
		}
		if !matched {
			return fmt.Errorf("resource state cannot disappear outside its typed deletion operation")
		}
	}

	return nil
}

func validateResourceManagedProcessPresence(resource domain.AppResource) error {
	switch resource.Target.Kind {
	case domain.AppTargetLocalHTTP:
		if resource.ManagedProcess == nil {
			return fmt.Errorf("local_http resource requires managed process authority")
		}
	case domain.AppTargetTailnetHTTP:
		if resource.ManagedProcess != nil {
			return fmt.Errorf("tailnet_http resource must not carry managed process authority")
		}
	default:
		return fmt.Errorf("resource target kind %q is unsupported", resource.Target.Kind)
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
	if len(resource.PublicationRecord.CertificateInventory) != 0 {
		return fmt.Errorf("new resource cannot supply certificate inventory")
	}
	if match == nil || match.Target != string(plans.TargetInstallation) || match.AdmissionSource != AdmissionUI || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.UnpublishedGeneration != 1 {
		return fmt.Errorf("new resource lacks exact authenticated durable creation authority")
	}
	if err := validateResourceManagedProcessPresence(resource); err != nil {
		return fmt.Errorf("new resource lacks exact authenticated durable creation authority: %w", err)
	}
	if resource.Target.Kind == domain.AppTargetLocalHTTP && (resource.ManagedProcess.Requested != domain.ProcessRequestedStopped || resource.ManagedProcess.Applied != nil) {
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
	if operation == ResourceDelete {
		beforeCopy, afterCopy := before, after
		beforeCopy.Lifecycle, afterCopy.Lifecycle = "", ""
		beforeCopy.PublicationRecord.LastOperation, afterCopy.PublicationRecord.LastOperation = "", ""
		beforeCopy.PublicationRecord.LastOperationResult, afterCopy.PublicationRecord.LastOperationResult = "", ""
		beforeCopy.PublicationRecord.LastJobID, afterCopy.PublicationRecord.LastJobID = "", ""
		if before.Lifecycle != domain.LifecycleActive || after.Lifecycle != domain.LifecycleDeleting || after.PublicationRecord.LastOperation != domain.OperationResourceDelete || after.PublicationRecord.LastOperationResult != "" || after.PublicationRecord.LastJobID == "" || !reflect.DeepEqual(beforeCopy, afterCopy) {
			return fmt.Errorf("resource delete begin changed unrelated authority")
		}
		return nil
	}
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
	case Unpublish, CloseAll, CertificateExpiry, AutomaticReconciliation:
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
		if before.Lifecycle != after.Lifecycle || !reflect.DeepEqual(beforePublication, afterPublication) || before.Target.Kind != after.Target.Kind {
			return fmt.Errorf("resource update changed applied lifecycle, publication, or target kind")
		}
		if err := validateResourceManagedProcessPresence(before); err != nil {
			return fmt.Errorf("resource update prior authority: %w", err)
		}
		if err := validateResourceManagedProcessPresence(after); err != nil {
			return fmt.Errorf("resource update candidate authority: %w", err)
		}
		if before.Target.Kind == domain.AppTargetLocalHTTP && (before.ManagedProcess.ID != after.ManagedProcess.ID || before.ManagedProcess.Requested != after.ManagedProcess.Requested || !reflect.DeepEqual(before.ManagedProcess.Applied, after.ManagedProcess.Applied) || !reflect.DeepEqual(before.ManagedProcess.RuntimeObservation, after.ManagedProcess.RuntimeObservation) || before.ManagedProcess.LastOperation != after.ManagedProcess.LastOperation || before.ManagedProcess.LastOperationResult != after.ManagedProcess.LastOperationResult || before.ManagedProcess.LastJobID != after.ManagedProcess.LastJobID) {
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
			switch namespace {
			case "children":
				var child ChildRecord
				if err := decodeStrict(before.Entries[key], &child); err != nil {
					return err
				}
				jobID = child.JobID
			case "journals":
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
	pinned := map[string]bool{}
	if raw, present := before.Entries["installations/current"]; present {
		installation, err := domain.DecodeInstallation(raw)
		if err != nil {
			return err
		}
		for _, resource := range installation.Resources {
			if len(resource.PublicationRecord.PendingGoAccessRetirements) > 0 {
				pinned[resource.PublicationRecord.GoAccessRetirementSourceJobID] = true
			}
		}
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
	for jobID := range deleted {
		if pinned[jobID] {
			return fmt.Errorf("terminal graph retention deleted pending GoAccess source")
		}
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
	removable := make([]graph, 0, len(terminalBefore))
	for _, graph := range terminalBefore {
		if !pinned[graph.jobID] {
			removable = append(removable, graph)
		}
	}
	if len(removable) < required {
		return fmt.Errorf("terminal graph retention lacks unpinned capacity")
	}
	for index := 0; index < required; index++ {
		if !deleted[removable[index].jobID] {
			return fmt.Errorf("terminal graph retention did not delete the oldest unpinned graph")
		}
	}
	return nil
}

func resourceConfigurationEqual(left, right domain.AppResource) bool {
	leftConfig, rightConfig := left, right
	leftConfig.Lifecycle, rightConfig.Lifecycle = "", ""
	leftConfig.PublicationRecord, rightConfig.PublicationRecord = domain.PublicationRecord{}, domain.PublicationRecord{}
	if leftConfig.ManagedProcess != nil {
		process := *leftConfig.ManagedProcess
		process.Requested = ""
		process.Applied = nil
		process.RuntimeObservation = nil
		process.LastOperation = ""
		process.LastOperationResult = ""
		process.LastJobID = ""
		leftConfig.ManagedProcess = &process
	}
	if rightConfig.ManagedProcess != nil {
		process := *rightConfig.ManagedProcess
		process.Requested = ""
		process.Applied = nil
		process.RuntimeObservation = nil
		process.LastOperation = ""
		process.LastOperationResult = ""
		process.LastJobID = ""
		rightConfig.ManagedProcess = &process
	}
	return reflect.DeepEqual(leftConfig, rightConfig)
}

func validateResourceUpdateConfigurationTransition(before, after persist.Document, prior, candidate domain.AppResource) error {
	if prior.ID != candidate.ID || prior.Name != candidate.Name {
		return fmt.Errorf("resource update immutable identity changed")
	}
	if prior.Lifecycle != candidate.Lifecycle || prior.Target.Kind != candidate.Target.Kind || !reflect.DeepEqual(prior.PublicationRecord, candidate.PublicationRecord) || !protectedManagedProcessStateEqual(prior.ManagedProcess, candidate.ManagedProcess) {
		return fmt.Errorf("resource update combined configuration with applied-state changes")
	}
	candidateDigest, err := appresource.ConfigDigest(candidate)
	if err != nil || candidate.CurrentConfigDigest != candidateDigest {
		return fmt.Errorf("resource update candidate config identity is not canonical")
	}
	return exactRunningInstallationAuthority(before, after, func(intent Reservation) bool {
		return intent.Operation == ResourceUpdate && intent.AdmissionSource == AdmissionUI && intent.Target == "resource/"+candidate.ID && intent.SafetyBinding.ResourceID == candidate.ID && intent.SafetyBinding.CandidateDigest == candidateDigest && intent.SafetyBinding.CandidateBundle == prior.CurrentConfigDigest
	})
}

func protectedResourceStateEqual(left, right domain.AppResource) bool {
	return reflect.DeepEqual(left, right)
}

func protectedManagedProcessStateEqual(left, right *domain.ManagedProcess) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftState, rightState := *left, *right
	leftState.Service, rightState.Service = domain.ManagedService{}, domain.ManagedService{}
	leftState.ReferenceBinding, rightState.ReferenceBinding = nil, nil
	return reflect.DeepEqual(leftState, rightState)
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
	case ResourceDelete:
		return code == domain.OperationResourceDelete
	case ProcessStart:
		return code == domain.OperationProcessStart
	case ProcessStop:
		return code == domain.OperationProcessStop
	case Unpublish, CertificateExpiry, AutomaticReconciliation, StartupContraction:
		return code == domain.OperationUnpublish
	case CloseAll:
		return code == domain.OperationCloseAll
	default:
		return string(code) == string(operation)
	}
}

func validateHeadscaleInitializationBinding(operation Type, safetyBinding SafetyBinding, binding *HeadscaleInitializationBinding) error {
	if operation != HeadscaleInitialize {
		if binding != nil {
			return fmt.Errorf("unrelated operation carried Headscale initialization authority")
		}
		return nil
	}
	if binding == nil || binding.Candidate.LastJobID != "" || binding.Candidate.LastOperation != "" || binding.Candidate.DesiredDigest != safetyBinding.CandidateDigest || binding.Candidate.Artifact.ArchiveDigest != safetyBinding.CandidateBundle || managedheadscale.VerifySnapshot(binding.Candidate, binding.Snapshot) != nil {
		return fmt.Errorf("headscale initialization authority is invalid")
	}
	preflightDigest, err := preflight.ExpansionRequestDigest(binding.PreflightRequest)
	if err != nil || binding.PreflightRequest.Scope != preflight.ExpansionHeadscale || binding.PreflightRequest.Target != "headscale" || binding.PreflightRequest.Generation != binding.Candidate.Database.Generation || binding.PreflightResult.SchemaVersion == "" || binding.PreflightResult.Scope != string(preflight.ExpansionHeadscale) || binding.PreflightResult.Target != "headscale" || binding.PreflightResult.Generation != binding.PreflightRequest.Generation || binding.PreflightResult.RequestDigest != preflightDigest || !binding.PreflightResult.Allowed || binding.PreflightResult.ObservedAt.IsZero() || !binding.PreflightResult.ValidUntil.After(binding.PreflightResult.ObservedAt) {
		return fmt.Errorf("headscale initialization authority is invalid")
	}
	if err := preflight.RequireExpansionResultForRequest(binding.PreflightResult, binding.PreflightRequest, binding.PreflightResult.ObservedAt); err != nil {
		return fmt.Errorf("headscale initialization preflight authority is invalid")
	}
	return nil
}

func validateHeadscaleDeployBinding(operation Type, safetyBinding SafetyBinding, binding *HeadscaleDeployBinding) error {
	if operation != HeadscaleDeploy {
		if binding != nil || safetyBinding.ACMEBinding != "" {
			return fmt.Errorf("unrelated operation carried Headscale deploy authority")
		}
		return nil
	}
	if binding == nil || control.Validate(binding.Candidate) != nil || binding.Candidate.ConfigDigest != safetyBinding.CandidateDigest || binding.Candidate.CertificateBinding != safetyBinding.ACMEBinding || binding.Candidate.CertificateID != safetyBinding.CertificateIdentity {
		return fmt.Errorf("headscale deploy authority is invalid")
	}
	candidateDigest, err := control.Digest(binding.Candidate)
	if err != nil || candidateDigest != safetyBinding.CandidateBundle || binding.PreflightRequest.Scope != preflight.ExpansionHeadscale || binding.PreflightRequest.Target != "headscale" || binding.PreflightRequest.Generation != binding.Candidate.DatabaseGeneration {
		return fmt.Errorf("headscale deploy authority is invalid")
	}
	if err := preflight.RequireExpansionResultForRequest(binding.PreflightResult, binding.PreflightRequest, binding.PreflightResult.ObservedAt); err != nil {
		return fmt.Errorf("headscale deploy preflight authority is invalid")
	}
	return nil
}

func validateReservation(value Reservation) error {
	if (value.SafetyBinding.CertificateIdentity == "") != (value.SafetyBinding.ChallengeMethod == "") || value.SafetyBinding.ACMEBinding != "" && !exactDigest(value.SafetyBinding.ACMEBinding) || (value.SafetyBinding.CertificateIdentity != "" && ((value.Operation != Publish && value.Operation != CertificateRenew && value.Operation != HeadscaleDeploy) || !validIdentityRef(value.SafetyBinding.CertificateIdentity) || (value.SafetyBinding.ChallengeMethod != "http-01" && value.SafetyBinding.ChallengeMethod != "dns-01"))) {
		return fmt.Errorf("operation certificate challenge binding invalid")
	}
	if (value.Operation == ManagedBasicRotate || value.Operation == ManagedBasicDelete) != (value.SafetyBinding.PriorFingerprint != "") || value.SafetyBinding.PriorFingerprint != "" && !exactDigest(value.SafetyBinding.PriorFingerprint) {
		return fmt.Errorf("managed Basic prior fingerprint binding invalid")
	}
	if err := validateHeadscaleInitializationBinding(value.Operation, value.SafetyBinding, value.HeadscaleBinding); err != nil {
		return err
	}
	if err := validateHeadscaleDeployBinding(value.Operation, value.SafetyBinding, value.HeadscaleDeploy); err != nil {
		return err
	}
	if err := validateResourceDeleteBinding(value.Operation, value.SafetyBinding, value.ResourceDelete); err != nil {
		return err
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
	case Publish, Unpublish, CloseAll, EmergencyCloseAll, CertificateExpiry, CertificateRenew, ManagedBasicCreate, ManagedBasicRotate, ManagedBasicDelete, StaticRootRegister, ExternalHTPasswdRegister, AdminTokenRotate, AutomaticReconciliation, StartupContraction, GoAccessRetirement, HeadscaleInitialize, HeadscaleDeploy, HeadscaleUserCreate, PreauthKeyCreate, PreauthKeyRevoke, DeviceExpire, ConnectorBindingSet, ConnectorLogin, ResourceCreate, ResourceUpdate, ResourceDelete, ProcessStart, ProcessStop:
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
			return fmt.Errorf("headscale target does not match safety authority")
		}
	case "connector":
		if identity != "" || request.SafetyBinding.ResourceID != "" || (request.Operation != ConnectorBindingSet && request.Operation != ConnectorLogin) {
			return fmt.Errorf("connector target authority is invalid")
		}
	case "headscale_user", "preauth_key", "device":
		if identity == "" || request.SafetyBinding.ResourceID != "headscale" || (request.Operation != PreauthKeyCreate && request.Operation != PreauthKeyRevoke && request.Operation != DeviceExpire) {
			return fmt.Errorf("headscale lifecycle target does not match immutable safety authority")
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
	if request.Operation == ManagedBasicRotate || request.Operation == ManagedBasicDelete {
		expected := SafetyBinding{ResourceID: binding.ResourceID, Deadline: binding.Deadline, PriorFingerprint: binding.PriorFingerprint}
		if !exactDigest(binding.PriorFingerprint) || !reflect.DeepEqual(binding, expected) {
			return fmt.Errorf("managed Basic mutation requires an exact prior fingerprint")
		}
	} else if binding.PriorFingerprint != "" {
		return fmt.Errorf("unrelated operation carried managed Basic prior authority")
	}
	if request.Operation == GoAccessRetirement {
		if request.Source != AdmissionStartup {
			return fmt.Errorf("GoAccess retirement must be startup-bound")
		}
		return validateGoAccessRetirementBinding(binding)
	}
	if request.Operation == AutomaticReconciliation && strings.HasPrefix(request.Target, "journal/headscale-certificate-expiry-") {
		expected := SafetyBinding{ExpiryGeneration: binding.ExpiryGeneration, ResourceID: "headscale", Deadline: binding.Deadline, CandidateBundle: binding.CandidateBundle}
		if request.Source != AdmissionTimer || binding.ExpiryGeneration == 0 || binding.Deadline.IsZero() || binding.CandidateBundle == "" || !reflect.DeepEqual(binding, expected) {
			return fmt.Errorf("headscale expiry reconciliation requires exact timer authority")
		}
		return nil
	}
	if request.Operation == CertificateExpiry {
		expected := SafetyBinding{ExpiryGeneration: binding.ExpiryGeneration, ResourceID: binding.ResourceID, Deadline: binding.Deadline, CandidateBundle: binding.CandidateBundle}
		if request.Source != AdmissionTimer || binding.ExpiryGeneration == 0 || binding.Deadline.IsZero() || binding.CandidateBundle == "" || !reflect.DeepEqual(binding, expected) {
			return fmt.Errorf("certificate expiry requires exact timer deadline authority")
		}
		return nil
	}
	if request.Operation == HeadscaleInitialize && request.Source == AdmissionUI {
		if request.PlanID != "" || binding.PlanID != "" || binding.IntentGeneration != 0 || !exactDigest(binding.CandidateDigest) || !exactDigest(binding.CandidateBundle) {
			return fmt.Errorf("authenticated Headscale initialization requires exact config and release authority")
		}
		return nil
	}
	if (request.Operation == ResourceUpdate || request.Operation == HeadscaleUserCreate || request.Operation == ConnectorBindingSet) && request.Source == AdmissionUI {
		if request.PlanID != "" || binding.PlanID != "" || binding.IntentGeneration != 0 || !exactDigest(binding.CandidateDigest) || !exactDigest(binding.CandidateBundle) {
			return fmt.Errorf("authenticated direct mutation requires exact prior and candidate digests")
		}
		return nil
	}
	planMutationWithoutGeneration := request.Operation == PreauthKeyCreate || request.Operation == PreauthKeyRevoke || request.Operation == DeviceExpire || request.Operation == ConnectorLogin || request.Operation == ResourceDelete
	if planMutationWithoutGeneration {
		if request.Source != AdmissionPlan || binding.PlanID != request.PlanID || binding.IntentGeneration != 0 || !exactDigest(binding.CandidateDigest) || !exactDigest(binding.CandidateBundle) {
			return fmt.Errorf("plan mutation safety identity is invalid")
		}
		return nil
	}
	activationBound := binding.PlanID != "" || binding.IntentGeneration != 0 || binding.CandidateDigest != "" || binding.CandidateBundle != ""
	if activationBound {
		planBound := request.Source == AdmissionPlan && binding.PlanID == request.PlanID && exactDigest(binding.CandidateBundle)
		timerBound := request.Source == AdmissionTimer && request.Operation == CertificateRenew && validIdentityRef(binding.PlanID) && exactDigest(binding.CandidateBundle)
		startupBound := request.Operation == StartupContraction && request.Source == AdmissionStartup && (binding.CandidateBundle == "" || exactDigest(binding.CandidateBundle))
		exactCandidate := validIdentityRef(binding.PlanID) && binding.IntentGeneration != 0 && exactDigest(binding.CandidateDigest)
		if !exactCandidate || !planBound && !timerBound && !startupBound {
			return fmt.Errorf("activation safety identity does not match Plan or startup contraction authority")
		}
	}
	return nil
}

func validateAdmissionSource(operation Type, source AdmissionSource, planID string) error {
	switch source {
	case AdmissionPlan:
		if planID == "" {
			return fmt.Errorf("plan admission requires a Plan identity")
		}
		switch operation {
		case Publish, Unpublish, CloseAll, AdminTokenRotate, ManagedBasicRotate, ManagedBasicDelete, HeadscaleDeploy, ResourceDelete, CertificateRenew, PreauthKeyCreate, PreauthKeyRevoke, DeviceExpire, ConnectorLogin:
		default:
			return fmt.Errorf("operation is not valid for Plan admission")
		}
	case AdmissionTimer:
		if planID != "" || operation != CertificateExpiry && operation != CertificateRenew && operation != AutomaticReconciliation {
			return fmt.Errorf("timer admission is not authorized for operation")
		}
	case AdmissionStartup:
		if planID != "" || operation != AutomaticReconciliation && operation != StartupContraction && operation != GoAccessRetirement {
			return fmt.Errorf("startup admission is not authorized for operation")
		}
	case AdmissionRuntimeGuard:
		if planID != "" || operation != ProcessStop {
			return fmt.Errorf("runtime-guard admission is not authorized for operation")
		}
	case AdmissionUI:
		if planID != "" || operation != HeadscaleInitialize && operation != HeadscaleUserCreate && operation != ConnectorBindingSet && operation != ResourceCreate && operation != ResourceUpdate && operation != ProcessStart && operation != ProcessStop && operation != ManagedBasicCreate && operation != StaticRootRegister && operation != ExternalHTPasswdRegister {
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
