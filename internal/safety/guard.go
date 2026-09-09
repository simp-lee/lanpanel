package safety

import (
	"fmt"
	"slices"
	"time"
)

type Action string

const (
	ActionPublish             Action = "publish"
	ActionAppChallenge        Action = "app_challenge"
	ActionHeadscaleChallenge  Action = "headscale_challenge"
	ActionHeadscaleReactivate Action = "headscale_reactivate"
	ActionReactivate          Action = "reactivate"
	ActionContraction         Action = "contraction"
	ActionReadOnly            Action = "read_only"
)

type EffectivePriority string

const (
	PriorityStopFence        EffectivePriority = "stop_fence"
	PriorityGlobalClose      EffectivePriority = "global_close"
	PriorityClosing          EffectivePriority = "closing"
	PriorityDeletingOrOrphan EffectivePriority = "deleting_or_ownership_orphan"
	PriorityChallenge        EffectivePriority = "challenge_pending"
	PriorityReactivating     EffectivePriority = "reactivating"
	PriorityBaseContraction  EffectivePriority = "base_contraction"
	PriorityPublished        EffectivePriority = "published"
)

type GuardInput struct {
	State                  State
	Action                 Action
	ResourceID             string
	CandidateDigest        string
	CandidateBundle        string
	PlanID                 string
	Generation             uint64
	ControlGeneration      uint64
	CertificateGeneration  uint64
	CertificateFingerprint string
	Now                    time.Time
}

type Decision struct {
	Allowed  bool
	Priority EffectivePriority
	Reason   string
}

func Check(input GuardInput) Decision {
	if err := Validate(input.State); err != nil {
		return Decision{Priority: PriorityStopFence, Reason: "invalid independent safety state: " + err.Error()}
	}
	if input.Action == ActionContraction {
		return Decision{Allowed: true, Priority: effectivePriority(input.State, input.ResourceID, input.Now), Reason: "contraction-safe action"}
	}
	if input.Now.IsZero() {
		return Decision{Priority: PriorityStopFence, Reason: "guard observation time is required"}
	}
	if input.Action == ActionReadOnly {
		return Decision{Allowed: true, Priority: effectivePriority(input.State, input.ResourceID, input.Now), Reason: "read-only action"}
	}
	if input.Action == ActionPublish || input.Action == ActionAppChallenge || input.Action == ActionReactivate {
		for _, candidate := range input.State.Resources {
			if candidate.Ownership == OwnershipOrphan {
				return Decision{Priority: PriorityDeletingOrOrphan, Reason: fmt.Sprintf("resource %q is an ownership orphan; keep ingress closed; do not adopt or delete it; use configuration export and clean-host rebuild", candidate.ResourceID)}
			}
		}
	}
	resource := findResource(input.State, input.ResourceID)
	priority := effectivePriority(input.State, input.ResourceID, input.Now)
	if input.State.StopFence != nil {
		return Decision{Priority: priority, Reason: "stop fence blocks expansion"}
	}
	if input.Action == ActionHeadscaleChallenge {
		return checkHeadscaleChallenge(input)
	}
	if input.Action == ActionHeadscaleReactivate {
		return checkHeadscaleReactivate(input)
	}
	if resource == nil {
		return Decision{Priority: PriorityDeletingOrOrphan, Reason: "resource safety identity is missing"}
	}
	if input.State.GlobalClose.Phase != GlobalCloseNone {
		return Decision{Priority: PriorityGlobalClose, Reason: "global close blocks App expansion"}
	}
	if resource.Closing != nil {
		return Decision{Priority: PriorityClosing, Reason: "resource closing marker blocks expansion"}
	}
	if resource.State == ResourceDeleting || resource.Ownership == OwnershipOrphan {
		return Decision{Priority: PriorityDeletingOrOrphan, Reason: "deleting or orphan ownership blocks expansion"}
	}
	switch input.Action {
	case ActionAppChallenge:
		if resource.ChallengePending == nil || resource.ChallengePending.Method != "http-01" || resource.ChallengePending.PlanID != input.PlanID || resource.ChallengePending.Generation != input.Generation || resource.ChallengePending.BootstrapIdentity != input.CandidateDigest {
			return Decision{Priority: priority, Reason: "matching challenge identity is missing"}
		}
		if !snapshotMatches(resource.ChallengePending.BaseMarkers, resource) {
			return Decision{Priority: PriorityBaseContraction, Reason: "challenge base marker snapshot is stale"}
		}
		return Decision{Allowed: true, Priority: PriorityChallenge, Reason: "exact challenge-only route is allowed"}
	case ActionReactivate:
		if resource.Reactivating == nil || resource.ChallengePending != nil || resource.Reactivating.PlanID != input.PlanID || resource.Reactivating.Generation != input.Generation || resource.Reactivating.CandidateDigest != input.CandidateDigest || resource.Reactivating.CandidateBundle != input.CandidateBundle || !snapshotMatches(resource.Reactivating.BaseMarkers, resource) {
			return Decision{Priority: priority, Reason: "matching reactivation identity is missing or stale"}
		}
		if !resource.Reactivating.TemporaryHTTP && !future(resource.Reactivating.CertificateUntil, input.Now) {
			return Decision{Priority: PriorityBaseContraction, Reason: "reactivation safety deadline is not future"}
		}
		return Decision{Allowed: true, Priority: PriorityReactivating, Reason: "exact complete reactivation candidate is allowed"}
	case ActionPublish:
		if resource.ChallengePending != nil || resource.Reactivating != nil {
			return Decision{Priority: priority, Reason: "ordinary publish cannot bypass a challenge or reactivation intent"}
		}
		if hasBaseMarker(resource) {
			return Decision{Priority: PriorityBaseContraction, Reason: "base contraction requires matching reactivation"}
		}
		return Decision{Allowed: true, Priority: PriorityPublished, Reason: "no independent expansion blocker"}
	default:
		return Decision{Priority: priority, Reason: fmt.Sprintf("action %q is not registered", input.Action)}
	}
}

func checkHeadscaleChallenge(input GuardInput) Decision {
	challenge := input.State.Headscale.ChallengePending
	if challenge == nil || challenge.Method != "http-01" || challenge.PlanID != input.PlanID || challenge.Generation != input.Generation || challenge.BootstrapIdentity != input.CandidateDigest {
		return Decision{Priority: PriorityBaseContraction, Reason: "matching Headscale challenge identity is missing"}
	}
	if !headscaleSnapshotMatches(challenge.BaseMarkers, input.State.Headscale) {
		return Decision{Priority: PriorityBaseContraction, Reason: "Headscale challenge marker snapshot is stale"}
	}
	return Decision{Allowed: true, Priority: PriorityChallenge, Reason: "exact Headscale challenge-only route is allowed"}
}

func checkHeadscaleReactivate(input GuardInput) Decision {
	intent := input.State.Headscale.Reactivating
	if intent == nil || input.State.Headscale.ChallengePending != nil || intent.Generation != input.Generation || intent.CandidateDigest != input.CandidateDigest || intent.CandidateBundle != input.CandidateBundle || intent.PlanID != input.PlanID || intent.ControlGeneration != input.ControlGeneration || intent.CertificateGeneration != input.CertificateGeneration || intent.CertificateFingerprint != input.CertificateFingerprint || !headscaleSnapshotMatches(intent.BaseMarkers, input.State.Headscale) {
		return Decision{Priority: PriorityBaseContraction, Reason: "matching Headscale reactivation identity is missing or stale"}
	}
	if !future(intent.CertificateUntil, input.Now) {
		return Decision{Priority: PriorityBaseContraction, Reason: "Headscale certificate deadline is not future"}
	}
	return Decision{Allowed: true, Priority: PriorityReactivating, Reason: "exact Headscale control and certificate reactivation candidate is allowed"}
}

func effectivePriority(state State, resourceID string, now time.Time) EffectivePriority {
	if state.StopFence != nil {
		return PriorityStopFence
	}
	if state.GlobalClose.Phase != GlobalCloseNone {
		return PriorityGlobalClose
	}
	resource := findResource(state, resourceID)
	if resource == nil {
		return PriorityDeletingOrOrphan
	}
	if resource.Closing != nil {
		return PriorityClosing
	}
	if resource.State == ResourceDeleting || resource.Ownership == OwnershipOrphan {
		return PriorityDeletingOrOrphan
	}
	if resource.ChallengePending != nil && snapshotMatches(resource.ChallengePending.BaseMarkers, resource) {
		return PriorityChallenge
	}
	if resource.Reactivating != nil && snapshotMatches(resource.Reactivating.BaseMarkers, resource) && (resource.Reactivating.TemporaryHTTP || future(resource.Reactivating.CertificateUntil, now)) {
		return PriorityReactivating
	}
	if hasBaseMarker(resource) || resource.ChallengePending != nil || resource.Reactivating != nil {
		return PriorityBaseContraction
	}
	return PriorityPublished
}

func findResource(state State, resourceID string) *ResourceSafety {
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resourceID {
			return &state.Resources[index]
		}
	}
	return nil
}

func hasBaseMarker(resource *ResourceSafety) bool {
	return resource.StickyUnpublished != nil || resource.Contraction != nil || resource.CertificateExpiry != nil
}

func snapshotMatches(snapshot []MarkerSnapshot, resource *ResourceSafety) bool {
	current := map[MarkerKind]uint64{}
	if resource.StickyUnpublished != nil {
		current[MarkerStickyUnpublished] = resource.StickyUnpublished.Generation
	}
	if resource.Contraction != nil {
		current[MarkerContraction] = resource.Contraction.Generation
	}
	if resource.CertificateExpiry != nil {
		current[MarkerCertificateExpiry] = resource.CertificateExpiry.Generation
	}
	return snapshotsEqual(snapshot, current)
}

func headscaleSnapshotMatches(snapshot []MarkerSnapshot, headscale HeadscaleSafety) bool {
	current := map[MarkerKind]uint64{}
	if headscale.CertificateExpiry != nil {
		current[MarkerCertificateExpiry] = headscale.CertificateExpiry.Generation
	}
	return snapshotsEqual(snapshot, current)
}

func snapshotsEqual(snapshot []MarkerSnapshot, current map[MarkerKind]uint64) bool {
	for _, marker := range snapshot {
		generation, present := current[marker.Kind]
		if marker.State == SnapshotPresent {
			if !present || generation != marker.Generation {
				return false
			}
		} else if present {
			return false
		}
	}
	return true
}

type Operation string

type Registration struct {
	Operation Operation
	Action    Action
	Owner     string
}

type Registry struct{ registrations map[Operation]Registration }

func NewRegistry(registrations []Registration) (*Registry, error) {
	if len(registrations) == 0 {
		return nil, fmt.Errorf("guard registry requires at least one operation")
	}
	result := &Registry{registrations: map[Operation]Registration{}}
	for _, registration := range registrations {
		if !validRef(string(registration.Operation)) || !validRef(registration.Owner) || !validAction(registration.Action) {
			return nil, fmt.Errorf("guard registration is invalid")
		}
		if _, duplicate := result.registrations[registration.Operation]; duplicate {
			return nil, fmt.Errorf("guard operation %q is duplicated", registration.Operation)
		}
		result.registrations[registration.Operation] = registration
	}
	return result, nil
}

func (registry *Registry) Check(operation Operation, input GuardInput) (Decision, error) {
	registration, ok := registry.registrations[operation]
	if !ok {
		return Decision{Priority: PriorityStopFence, Reason: "operation is not registered"}, fmt.Errorf("operation %q has no mandatory safety guard registration", operation)
	}
	input.Action = registration.Action
	return Check(input), nil
}

func (registry *Registry) Operations() []Operation {
	result := make([]Operation, 0, len(registry.registrations))
	for operation := range registry.registrations {
		result = append(result, operation)
	}
	slices.Sort(result)
	return result
}

func validAction(action Action) bool {
	switch action {
	case ActionPublish, ActionAppChallenge, ActionHeadscaleChallenge, ActionHeadscaleReactivate, ActionReactivate, ActionContraction, ActionReadOnly:
		return true
	default:
		return false
	}
}

type ClearRole string

const (
	RoleGlobalCloseConvergence ClearRole = "global_close_convergence"
	RoleJournalConvergence     ClearRole = "journal_convergence"
	RoleOwnershipContraction   ClearRole = "ownership_contraction"
	RoleOwnershipActivation    ClearRole = "ownership_activation"
	RoleOwnershipRetirement    ClearRole = "ownership_retirement"
	RolePublish                ClearRole = "publish"
	RoleDelete                 ClearRole = "delete"
	RoleChallenge              ClearRole = "challenge"
	RoleCertificateHandoff     ClearRole = "certificate_handoff"
	RoleContraction            ClearRole = "contraction"
	RoleIngressActivation      ClearRole = "ingress_activation"
	RoleCertificateActivation  ClearRole = "certificate_activation"
	RoleCertificateObservation ClearRole = "certificate_observation"
	RoleBootstrap              ClearRole = "bootstrap"
	RoleResourceCreate         ClearRole = "resource_create"
)

type ClearTarget string

const (
	ClearGlobalClose       ClearTarget = "global_close"
	ClearStopFence         ClearTarget = "stop_fence"
	ClearBaseContraction   ClearTarget = "base_contraction"
	ClearClosing           ClearTarget = "closing"
	ClearDeletionTombstone ClearTarget = "deletion_tombstone"
	ClearChallenge         ClearTarget = "challenge"
)

func AuthorizeClear(role ClearRole, target ClearTarget, fenceKind StopFenceKind) error {
	allowed := false
	switch target {
	case ClearGlobalClose:
		allowed = role == RoleGlobalCloseConvergence
	case ClearStopFence:
		allowed = role == RoleJournalConvergence
	case ClearBaseContraction:
		allowed = role == RolePublish || role == RoleDelete
	case ClearClosing:
		allowed = role == RoleContraction
	case ClearDeletionTombstone:
		allowed = role == RoleDelete
	case ClearChallenge:
		allowed = role == RoleChallenge
	default:
		return fmt.Errorf("clear target %q is unsupported", target)
	}
	if !allowed {
		return fmt.Errorf("role %q is not the unique clearer for %q", role, target)
	}
	return nil
}
