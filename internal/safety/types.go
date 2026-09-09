package safety

import "time"

const SchemaVersion = "lanpanel.safety.v1"

type GlobalClosePhase string

const (
	GlobalCloseNone      GlobalClosePhase = "none"
	GlobalCloseClosing   GlobalClosePhase = "closing"
	GlobalCloseEmergency GlobalClosePhase = "emergency"
)

type GlobalClose struct {
	Phase      GlobalClosePhase `json:"phase"`
	Generation uint64           `json:"generation"`
}

type MarkerKind string

const (
	MarkerStickyUnpublished MarkerKind = "sticky_unpublished"
	MarkerClosing           MarkerKind = "closing"
	MarkerContraction       MarkerKind = "contraction"
	MarkerCertificateExpiry MarkerKind = "certificate_expiry"
	MarkerDeleting          MarkerKind = "deleting"
)

type GenerationMarker struct {
	Kind       MarkerKind `json:"kind"`
	Generation uint64     `json:"generation"`
	Reason     string     `json:"reason"`
}

type DeadlineMarker struct {
	Generation uint64    `json:"generation"`
	Deadline   time.Time `json:"deadline"`
	Binding    string    `json:"binding"`
}

type MarkerSnapshotState string

const (
	SnapshotAbsent  MarkerSnapshotState = "absent"
	SnapshotPresent MarkerSnapshotState = "present"
)

type MarkerSnapshot struct {
	Kind       MarkerKind          `json:"kind"`
	State      MarkerSnapshotState `json:"state"`
	Generation uint64              `json:"generation,omitempty"`
}

type ChallengePending struct {
	Generation             uint64           `json:"generation"`
	PlanID                 string           `json:"plan_id"`
	Method                 string           `json:"method,omitempty"`
	ConfigDigest           string           `json:"config_digest,omitempty"`
	SANIdentity            string           `json:"san_identity,omitempty"`
	ACMEBinding            string           `json:"acme_binding,omitempty"`
	CertificateIdentity    string           `json:"certificate_identity,omitempty"`
	OwnerLock              string           `json:"owner_lock,omitempty"`
	Provider               string           `json:"provider,omitempty"`
	Zone                   string           `json:"zone,omitempty"`
	Owners                 []string         `json:"owners,omitempty"`
	Host                   string           `json:"host,omitempty"`
	Hosts                  []string         `json:"hosts,omitempty"`
	Token                  string           `json:"token,omitempty"`
	TokenPath              string           `json:"token_path,omitempty"`
	KeyAuthorizationDigest string           `json:"key_authorization_digest,omitempty"`
	Webroot                string           `json:"webroot"`
	BootstrapIdentity      string           `json:"bootstrap_identity"`
	BaseMarkers            []MarkerSnapshot `json:"base_markers"`
}

type Reactivating struct {
	Generation       uint64           `json:"generation"`
	PriorGeneration  uint64           `json:"prior_generation"`
	PlanID           string           `json:"plan_id"`
	CandidateDigest  string           `json:"candidate_digest"`
	CandidateBundle  string           `json:"candidate_bundle"`
	BaseMarkers      []MarkerSnapshot `json:"base_markers"`
	ProbePending     bool             `json:"probe_pending"`
	ProbeCorrelation string           `json:"probe_correlation,omitempty"`
	CertificateUntil time.Time        `json:"certificate_until,omitzero"`
	TemporaryHTTP    bool             `json:"temporary_http,omitempty"`
}

type HeadscaleReactivating struct {
	Generation                 uint64           `json:"generation"`
	PriorGeneration            uint64           `json:"prior_generation"`
	PlanID                     string           `json:"plan_id"`
	ControlGeneration          uint64           `json:"control_generation"`
	CertificateGeneration      uint64           `json:"certificate_generation"`
	CertificateFingerprint     string           `json:"certificate_fingerprint"`
	CandidateDigest            string           `json:"candidate_digest"`
	CandidateBundle            string           `json:"candidate_bundle"`
	ActivationDigest           string           `json:"activation_digest,omitempty"`
	ControlEntryDigest         string           `json:"control_entry_digest,omitempty"`
	BaseMarkers                []MarkerSnapshot `json:"base_markers"`
	ProbePending               bool             `json:"probe_pending"`
	ProbeCorrelation           string           `json:"probe_correlation,omitempty"`
	CertificateUntil           time.Time        `json:"certificate_until"`
	CertificateLastTrustedWall time.Time        `json:"certificate_last_trusted_wall"`
}

type ResourceState string

const (
	ResourceActive   ResourceState = "active"
	ResourceDeleting ResourceState = "deleting"
)

type OwnershipState string

const (
	OwnershipOwned  OwnershipState = "owned"
	OwnershipOrphan OwnershipState = "ownership_orphan"
)

type ActiveCertificateAuthority struct {
	Generation      uint64    `json:"generation"`
	Fingerprint     string    `json:"fingerprint"`
	Binding         string    `json:"binding"`
	NotAfter        time.Time `json:"not_after"`
	LastTrustedWall time.Time `json:"last_trusted_wall"`
}
type ResourceSafety struct {
	ResourceID         string                      `json:"resource_id"`
	GenerationSequence uint64                      `json:"generation_sequence"`
	State              ResourceState               `json:"state"`
	Ownership          OwnershipState              `json:"ownership"`
	OwnershipDigest    string                      `json:"ownership_digest"`
	StickyUnpublished  *GenerationMarker           `json:"sticky_unpublished,omitempty"`
	Closing            *GenerationMarker           `json:"closing,omitempty"`
	Contraction        *GenerationMarker           `json:"contraction,omitempty"`
	ActiveCertificate  *ActiveCertificateAuthority `json:"active_certificate,omitempty"`
	CertificateExpiry  *DeadlineMarker             `json:"certificate_expiry,omitempty"`
	ChallengePending   *ChallengePending           `json:"challenge_pending,omitempty"`
	Reactivating       *Reactivating               `json:"reactivating,omitempty"`
	DeletionTombstone  string                      `json:"deletion_tombstone,omitempty"`
}

type HeadscaleSafety struct {
	GenerationSequence uint64                      `json:"generation_sequence,omitempty"`
	ActiveCertificate  *ActiveCertificateAuthority `json:"active_certificate,omitempty"`
	ControlEntryDigest string                      `json:"control_entry_digest,omitempty"`
	CertificateExpiry  *DeadlineMarker             `json:"certificate_expiry,omitempty"`
	ChallengePending   *ChallengePending           `json:"challenge_pending,omitempty"`
	Reactivating       *HeadscaleReactivating      `json:"reactivating,omitempty"`
}

type StopFenceKind string

const (
	StopFenceContraction           StopFenceKind = "contraction"
	StopFenceIngressActivation     StopFenceKind = "ingress_activation"
	StopFenceCertificateActivation StopFenceKind = "certificate_activation"
)

type FenceScope struct {
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id,omitempty"`
}

type MarkerGeneration struct {
	Kind       string `json:"kind"`
	Generation uint64 `json:"generation"`
}

type StopObservation struct {
	MasterStopped    bool      `json:"master_stopped"`
	WorkersStopped   bool      `json:"workers_stopped"`
	ListenersStopped bool      `json:"listeners_stopped"`
	ObservedAt       time.Time `json:"observed_at"`
}

type ContractionFence struct {
	Authorities            []MarkerGeneration `json:"authorities"`
	OwnershipDigest        string             `json:"ownership_digest"`
	OperationRef           string             `json:"operation_ref,omitempty"`
	SafetyIntentID         string             `json:"safety_intent_id,omitempty"`
	SafetyIntentGeneration uint64             `json:"safety_intent_generation,omitempty"`
}

type IngressActivationFence struct {
	IntentRef           string `json:"intent_ref"`
	CandidateGeneration uint64 `json:"candidate_generation"`
	PriorGeneration     uint64 `json:"prior_generation"`
}

type CertificateActivationFence struct {
	JournalRef         string `json:"journal_ref"`
	ResourceGeneration uint64 `json:"resource_generation"`
	PriorPointer       string `json:"prior_pointer"`
	CandidatePointer   string `json:"candidate_pointer"`
	ExpiryGeneration   uint64 `json:"expiry_generation"`
}

type StopFence struct {
	Kind                  StopFenceKind               `json:"kind"`
	OriginOperation       string                      `json:"origin_operation"`
	Scope                 FenceScope                  `json:"scope"`
	FenceGeneration       uint64                      `json:"fence_generation"`
	CreatedAt             time.Time                   `json:"created_at"`
	SafetyGenerations     []MarkerGeneration          `json:"safety_generations"`
	OwnedGraphDigest      string                      `json:"owned_graph_digest"`
	InventoryDigest       string                      `json:"inventory_digest"`
	Observation           StopObservation             `json:"observation"`
	AccessMayRemain       bool                        `json:"access_may_remain"`
	Contraction           *ContractionFence           `json:"contraction,omitempty"`
	IngressActivation     *IngressActivationFence     `json:"ingress_activation,omitempty"`
	CertificateActivation *CertificateActivationFence `json:"certificate_activation,omitempty"`
}

type State struct {
	SchemaVersion     string           `json:"schema_version"`
	Revision          uint64           `json:"revision"`
	AuthoritySequence uint64           `json:"authority_sequence"`
	Checksum          string           `json:"checksum,omitempty"`
	GlobalClose       GlobalClose      `json:"global_close"`
	StopFenceSequence uint64           `json:"stop_fence_sequence"`
	StopFence         *StopFence       `json:"stop_fence,omitempty"`
	Headscale         HeadscaleSafety  `json:"headscale"`
	Resources         []ResourceSafety `json:"resources"`
}

func EmptyState() State {
	return State{SchemaVersion: SchemaVersion, Revision: 1, AuthoritySequence: 1, GlobalClose: GlobalClose{Phase: GlobalCloseNone}}
}
