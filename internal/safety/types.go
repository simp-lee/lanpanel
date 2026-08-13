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
	MarkerEdgeOneExpiry     MarkerKind = "edgeone_expiry"
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
	Generation        uint64           `json:"generation"`
	PlanID            string           `json:"plan_id"`
	Host              string           `json:"host"`
	TokenPath         string           `json:"token_path"`
	Webroot           string           `json:"webroot"`
	BootstrapIdentity string           `json:"bootstrap_identity"`
	BaseMarkers       []MarkerSnapshot `json:"base_markers"`
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
	ACLUntil         time.Time        `json:"acl_until,omitzero"`
	TemporaryHTTP    bool             `json:"temporary_http,omitempty"`
}

type HeadscaleReactivating struct {
	Generation            uint64           `json:"generation"`
	PriorGeneration       uint64           `json:"prior_generation"`
	PlanID                string           `json:"plan_id"`
	ControlGeneration     uint64           `json:"control_generation"`
	CertificateGeneration uint64           `json:"certificate_generation"`
	CandidateDigest       string           `json:"candidate_digest"`
	CandidateBundle       string           `json:"candidate_bundle"`
	BaseMarkers           []MarkerSnapshot `json:"base_markers"`
	ProbePending          bool             `json:"probe_pending"`
	ProbeCorrelation      string           `json:"probe_correlation,omitempty"`
	CertificateUntil      time.Time        `json:"certificate_until"`
}

type EdgeOneSafety struct {
	RefreshJournal string          `json:"refresh_journal,omitempty"`
	Deadline       time.Time       `json:"deadline"`
	Expiry         *DeadlineMarker `json:"expiry,omitempty"`
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

type ResourceSafety struct {
	ResourceID         string            `json:"resource_id"`
	GenerationSequence uint64            `json:"generation_sequence"`
	State              ResourceState     `json:"state"`
	Ownership          OwnershipState    `json:"ownership"`
	OwnershipDigest    string            `json:"ownership_digest"`
	StickyUnpublished  *GenerationMarker `json:"sticky_unpublished,omitempty"`
	Closing            *GenerationMarker `json:"closing,omitempty"`
	Contraction        *GenerationMarker `json:"contraction,omitempty"`
	CertificateExpiry  *DeadlineMarker   `json:"certificate_expiry,omitempty"`
	EdgeOne            EdgeOneSafety     `json:"edgeone"`
	ChallengePending   *ChallengePending `json:"challenge_pending,omitempty"`
	Reactivating       *Reactivating     `json:"reactivating,omitempty"`
	DeletionTombstone  string            `json:"deletion_tombstone,omitempty"`
}

type HeadscaleSafety struct {
	GenerationSequence uint64                 `json:"generation_sequence,omitempty"`
	CertificateExpiry  *DeadlineMarker        `json:"certificate_expiry,omitempty"`
	ChallengePending   *ChallengePending      `json:"challenge_pending,omitempty"`
	Reactivating       *HeadscaleReactivating `json:"reactivating,omitempty"`
}

type TransitionMarker struct {
	Generation      uint64    `json:"generation"`
	JournalRef      string    `json:"journal_ref"`
	CurrentEnvelope string    `json:"current_envelope"`
	TargetEnvelope  string    `json:"target_envelope"`
	Deadline        time.Time `json:"deadline"`
}

type BackupQuiescencePhase string

const (
	BackupPreparing BackupQuiescencePhase = "preparing"
	BackupSealed    BackupQuiescencePhase = "sealed"
)

type BackupQuiescence struct {
	Generation     uint64                `json:"generation"`
	Phase          BackupQuiescencePhase `json:"phase"`
	ManifestDigest string                `json:"manifest_digest,omitempty"`
	PayloadDigest  string                `json:"payload_digest,omitempty"`
}

type BackupTransitionPhase string

const (
	BackupTransitionPrepared  BackupTransitionPhase = "prepared"
	BackupTransitionCommitted BackupTransitionPhase = "committed"
	BackupTransitionImported  BackupTransitionPhase = "imported"
)

type BackupTransition struct {
	Generation uint64                `json:"generation"`
	Phase      BackupTransitionPhase `json:"phase"`
	JournalRef string                `json:"journal_ref"`
}

type StopFenceKind string

const (
	StopFenceContraction           StopFenceKind = "contraction"
	StopFenceIngressActivation     StopFenceKind = "ingress_activation"
	StopFenceCertificateActivation StopFenceKind = "certificate_activation"
	StopFenceEdgeOneRefresh        StopFenceKind = "edgeone_refresh"
	StopFenceMaintenanceTransition StopFenceKind = "maintenance_transition"
	StopFenceGenerationUpgrade     StopFenceKind = "generation_upgrade"
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
	Authorities     []MarkerGeneration `json:"authorities"`
	OwnershipDigest string             `json:"ownership_digest"`
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

type EdgeOneRefreshFence struct {
	JournalRef         string    `json:"journal_ref"`
	ResourceGeneration uint64    `json:"resource_generation"`
	PriorACL           string    `json:"prior_acl"`
	CandidateACL       string    `json:"candidate_acl"`
	PriorDeadline      time.Time `json:"prior_deadline"`
	CandidateDeadline  time.Time `json:"candidate_deadline"`
}

type TransitionFence struct {
	JournalRef              string `json:"journal_ref"`
	CurrentEnvelope         string `json:"current_envelope"`
	TargetEnvelope          string `json:"target_envelope"`
	RuntimeClosureDigest    string `json:"runtime_closure_digest"`
	GenerationClosureDigest string `json:"generation_closure_digest"`
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
	EdgeOneRefresh        *EdgeOneRefreshFence        `json:"edgeone_refresh,omitempty"`
	Transition            *TransitionFence            `json:"transition,omitempty"`
}

type State struct {
	SchemaVersion               string            `json:"schema_version"`
	Revision                    uint64            `json:"revision"`
	AuthoritySequence           uint64            `json:"authority_sequence"`
	Checksum                    string            `json:"checksum,omitempty"`
	GlobalClose                 GlobalClose       `json:"global_close"`
	MaintenancePending          *TransitionMarker `json:"maintenance_pending,omitempty"`
	DependencyTransitionPending *TransitionMarker `json:"dependency_transition_pending,omitempty"`
	UpgradePending              *TransitionMarker `json:"upgrade_pending,omitempty"`
	BackupQuiescence            *BackupQuiescence `json:"backup_quiescence,omitempty"`
	BackupTransition            *BackupTransition `json:"backup_transition,omitempty"`
	StopFenceSequence           uint64            `json:"stop_fence_sequence"`
	StopFence                   *StopFence        `json:"stop_fence,omitempty"`
	Headscale                   HeadscaleSafety   `json:"headscale"`
	Resources                   []ResourceSafety  `json:"resources"`
}

func EmptyState() State {
	return State{SchemaVersion: SchemaVersion, Revision: 1, AuthoritySequence: 1, GlobalClose: GlobalClose{Phase: GlobalCloseNone}}
}
