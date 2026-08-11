package safety

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func Validate(state State) error {
	if state.SchemaVersion != SchemaVersion || state.Revision == 0 || state.AuthoritySequence == 0 {
		return fmt.Errorf("safety schema version, revision, and authority sequence are required")
	}
	if err := validateGlobalClose(state.GlobalClose); err != nil {
		return err
	}
	for name, marker := range map[string]*TransitionMarker{
		"maintenance_pending":           state.MaintenancePending,
		"dependency_transition_pending": state.DependencyTransitionPending,
		"upgrade_pending":               state.UpgradePending,
	} {
		if marker != nil {
			if err := validateTransitionMarker(*marker); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if state.BackupQuiescence != nil {
		if err := validateBackupQuiescence(*state.BackupQuiescence); err != nil {
			return err
		}
	}
	if state.BackupTransition != nil {
		if err := validateBackupTransition(*state.BackupTransition); err != nil {
			return err
		}
	}
	if err := validateHeadscale(state.Headscale); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for index, resource := range state.Resources {
		if _, duplicate := seen[resource.ResourceID]; duplicate {
			return fmt.Errorf("duplicate resource safety identity %q", resource.ResourceID)
		}
		seen[resource.ResourceID] = struct{}{}
		if err := validateResource(resource); err != nil {
			return fmt.Errorf("resources[%d]: %w", index, err)
		}
	}
	if state.StopFence != nil {
		if state.StopFence.FenceGeneration != state.StopFenceSequence {
			return fmt.Errorf("active stop fence does not match retained generation sequence")
		}
		if err := validateStopFence(*state.StopFence, state); err != nil {
			return err
		}
	}
	return nil
}

func validateGlobalClose(marker GlobalClose) error {
	switch marker.Phase {
	case GlobalCloseNone:
		return nil
	case GlobalCloseClosing, GlobalCloseEmergency:
		if marker.Generation == 0 {
			return fmt.Errorf("active global close requires a nonzero generation")
		}
		return nil
	default:
		return fmt.Errorf("global close phase %q is unsupported", marker.Phase)
	}
}

func validateTransitionMarker(marker TransitionMarker) error {
	if marker.Generation == 0 || !validRef(marker.JournalRef) || !isDigest(marker.CurrentEnvelope) || !isDigest(marker.TargetEnvelope) || marker.Deadline.IsZero() {
		return fmt.Errorf("transition marker requires generation, journal, envelopes, and deadline")
	}
	return nil
}

func validateBackupQuiescence(marker BackupQuiescence) error {
	if marker.Generation == 0 {
		return fmt.Errorf("backup quiescence generation is required")
	}
	switch marker.Phase {
	case BackupPreparing:
		if marker.ManifestDigest != "" || marker.PayloadDigest != "" {
			return fmt.Errorf("preparing backup must not contain sealed digests")
		}
	case BackupSealed:
		if !isDigest(marker.ManifestDigest) || !isDigest(marker.PayloadDigest) {
			return fmt.Errorf("sealed backup requires manifest and payload digests")
		}
	default:
		return fmt.Errorf("backup quiescence phase %q is unsupported", marker.Phase)
	}
	return nil
}

func validateBackupTransition(marker BackupTransition) error {
	if marker.Generation == 0 || !validRef(marker.JournalRef) {
		return fmt.Errorf("backup transition generation and journal are required")
	}
	switch marker.Phase {
	case BackupTransitionPrepared, BackupTransitionCommitted, BackupTransitionImported:
		return nil
	default:
		return fmt.Errorf("backup transition phase %q is unsupported", marker.Phase)
	}
}

func validateHeadscale(headscale HeadscaleSafety) error {
	if maximumGeneration(headscaleGenerations(headscale)) > headscale.GenerationSequence {
		return fmt.Errorf("Headscale generation exceeds its monotonic sequence")
	}
	if headscale.CertificateExpiry != nil {
		if err := validateDeadlineMarker(*headscale.CertificateExpiry); err != nil {
			return fmt.Errorf("headscale certificate expiry: %w", err)
		}
	}
	if headscale.ChallengePending != nil {
		if err := validateChallenge(*headscale.ChallengePending); err != nil {
			return fmt.Errorf("headscale challenge: %w", err)
		}
	}
	if headscale.Reactivating != nil {
		if err := validateHeadscaleReactivating(*headscale.Reactivating); err != nil {
			return fmt.Errorf("headscale reactivating: %w", err)
		}
	}
	if headscale.ChallengePending != nil && headscale.Reactivating != nil {
		return fmt.Errorf("Headscale challenge and reactivation identities are mutually exclusive")
	}
	return nil
}

func validateResource(resource ResourceSafety) error {
	if !validRef(resource.ResourceID) || !isDigest(resource.OwnershipDigest) {
		return fmt.Errorf("resource ID and ownership digest are required")
	}
	if maximumGeneration(resourceGenerations(resource)) > resource.GenerationSequence {
		return fmt.Errorf("resource generation exceeds its monotonic sequence")
	}
	if resource.State != ResourceActive && resource.State != ResourceDeleting {
		return fmt.Errorf("resource state %q is unsupported", resource.State)
	}
	if resource.Ownership != OwnershipOwned && resource.Ownership != OwnershipOrphan {
		return fmt.Errorf("ownership state %q is unsupported", resource.Ownership)
	}
	for name, marker := range map[string]*GenerationMarker{
		"sticky_unpublished": resource.StickyUnpublished,
		"closing":            resource.Closing,
		"contraction":        resource.Contraction,
	} {
		if marker != nil {
			if err := validateGenerationMarker(*marker); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if resource.StickyUnpublished != nil && resource.StickyUnpublished.Kind != MarkerStickyUnpublished {
		return fmt.Errorf("sticky unpublished marker kind mismatch")
	}
	if resource.Closing != nil && resource.Closing.Kind != MarkerClosing {
		return fmt.Errorf("closing marker kind mismatch")
	}
	if resource.Contraction != nil && resource.Contraction.Kind != MarkerContraction {
		return fmt.Errorf("contraction marker kind mismatch")
	}
	if resource.CertificateExpiry != nil {
		if err := validateDeadlineMarker(*resource.CertificateExpiry); err != nil {
			return fmt.Errorf("certificate expiry: %w", err)
		}
	}
	if resource.EdgeOne.Expiry != nil {
		if err := validateDeadlineMarker(*resource.EdgeOne.Expiry); err != nil {
			return fmt.Errorf("EdgeOne expiry: %w", err)
		}
	}
	if resource.EdgeOne.Deadline.IsZero() != (resource.EdgeOne.RefreshJournal == "") {
		return fmt.Errorf("EdgeOne refresh journal and deadline must be committed as one pair")
	}
	if resource.ChallengePending != nil {
		if err := validateChallenge(*resource.ChallengePending); err != nil {
			return err
		}
	}
	if resource.Reactivating != nil {
		if err := validateReactivating(*resource.Reactivating); err != nil {
			return err
		}
	}
	if resource.ChallengePending != nil && resource.Reactivating != nil {
		return fmt.Errorf("App challenge and reactivation identities are mutually exclusive")
	}
	if resource.State == ResourceDeleting && !validRef(resource.DeletionTombstone) {
		return fmt.Errorf("deleting resource requires tombstone reference")
	}
	if resource.Ownership == OwnershipOrphan && (resource.ChallengePending != nil || resource.Reactivating != nil) {
		return fmt.Errorf("ownership orphan cannot carry expansion intent")
	}
	return nil
}

func validateGenerationMarker(marker GenerationMarker) error {
	if marker.Generation == 0 || !validMarkerKind(marker.Kind) || !validRef(marker.Reason) {
		return fmt.Errorf("generation marker kind, generation, and reason are required")
	}
	return nil
}

func validateDeadlineMarker(marker DeadlineMarker) error {
	if marker.Generation == 0 || marker.Deadline.IsZero() || !validRef(marker.Binding) {
		return fmt.Errorf("deadline marker generation, deadline, and binding are required")
	}
	return nil
}

func validateChallenge(challenge ChallengePending) error {
	if challenge.Generation == 0 || !validRef(challenge.PlanID) || !validHost(challenge.Host) || !cleanAbsolute(challenge.TokenPath) || !cleanAbsolute(challenge.Webroot) || !isDigest(challenge.BootstrapIdentity) {
		return fmt.Errorf("challenge identity is incomplete")
	}
	if err := validateBaseSnapshot(challenge.BaseMarkers); err != nil {
		return err
	}
	return nil
}

func validateReactivating(reactivating Reactivating) error {
	if reactivating.Generation == 0 || reactivating.PriorGeneration+1 != reactivating.Generation || !validRef(reactivating.PlanID) || !isDigest(reactivating.CandidateDigest) || !isDigest(reactivating.CandidateBundle) || reactivating.CertificateUntil.IsZero() || reactivating.ACLUntil.IsZero() {
		return fmt.Errorf("reactivating identity is incomplete")
	}
	if reactivating.ProbePending && !validRef(reactivating.ProbeCorrelation) {
		return fmt.Errorf("probe-pending reactivation requires correlation")
	}
	return validateBaseSnapshot(reactivating.BaseMarkers)
}

func validateHeadscaleReactivating(reactivating HeadscaleReactivating) error {
	if reactivating.Generation == 0 || reactivating.PriorGeneration+1 != reactivating.Generation || !validRef(reactivating.PlanID) || reactivating.ControlGeneration == 0 || reactivating.CertificateGeneration == 0 || !isDigest(reactivating.CandidateDigest) || !isDigest(reactivating.CandidateBundle) || reactivating.CertificateUntil.IsZero() {
		return fmt.Errorf("Headscale reactivating identity is incomplete")
	}
	if reactivating.ProbePending && !validRef(reactivating.ProbeCorrelation) {
		return fmt.Errorf("probe-pending Headscale reactivation requires correlation")
	}
	return validateBaseSnapshot(reactivating.BaseMarkers)
}

func validateBaseSnapshot(snapshot []MarkerSnapshot) error {
	required := []MarkerKind{MarkerStickyUnpublished, MarkerContraction, MarkerCertificateExpiry, MarkerEdgeOneExpiry}
	if len(snapshot) != len(required) {
		return fmt.Errorf("base marker snapshot must contain the exact closed marker set")
	}
	seen := map[MarkerKind]bool{}
	for _, marker := range snapshot {
		if seen[marker.Kind] {
			return fmt.Errorf("duplicate base marker snapshot %q", marker.Kind)
		}
		seen[marker.Kind] = true
		switch marker.State {
		case SnapshotAbsent:
			if marker.Generation != 0 {
				return fmt.Errorf("absent marker %q has generation", marker.Kind)
			}
		case SnapshotPresent:
			if marker.Generation == 0 {
				return fmt.Errorf("present marker %q lacks generation", marker.Kind)
			}
		default:
			return fmt.Errorf("snapshot state %q is unsupported", marker.State)
		}
	}
	for _, kind := range required {
		if !seen[kind] {
			return fmt.Errorf("base marker snapshot omits %q", kind)
		}
	}
	return nil
}

func validateStopFence(fence StopFence, state State) error {
	if !validRef(fence.OriginOperation) || fence.FenceGeneration == 0 || fence.CreatedAt.IsZero() || !isDigest(fence.OwnedGraphDigest) || !isDigest(fence.InventoryDigest) || fence.Observation.ObservedAt.IsZero() {
		return fmt.Errorf("stop fence common identity is incomplete")
	}
	if fence.Scope.Kind != "installation" && fence.Scope.Kind != "app" && fence.Scope.Kind != "headscale" {
		return fmt.Errorf("stop fence scope kind is unsupported")
	}
	if fence.Scope.Kind == "app" && !validRef(fence.Scope.ResourceID) {
		return fmt.Errorf("App stop fence requires resource ID")
	}
	if !fence.AccessMayRemain && (!fence.Observation.MasterStopped || !fence.Observation.WorkersStopped || !fence.Observation.ListenersStopped) {
		return fmt.Errorf("stop fence can clear access_may_remain only with complete stop observation")
	}
	if len(fence.SafetyGenerations) == 0 {
		return fmt.Errorf("stop fence requires applicable safety generations")
	}
	if err := validateMarkerGenerations(fence.SafetyGenerations); err != nil {
		return err
	}
	if err := bindMarkerGenerations(fence.SafetyGenerations, fence.Scope, state); err != nil {
		return err
	}
	listed := map[string]uint64{}
	for _, marker := range fence.SafetyGenerations {
		listed[marker.Kind] = marker.Generation
	}
	applicable := applicableMarkerGenerations(fence.Scope, state)
	if len(listed) != len(applicable) {
		return fmt.Errorf("stop fence safety generation set is not exact")
	}
	for kind, generation := range applicable {
		if listed[kind] != generation {
			return fmt.Errorf("stop fence omits applicable marker %q generation", kind)
		}
	}
	payloads := 0
	for _, present := range []bool{fence.Contraction != nil, fence.IngressActivation != nil, fence.CertificateActivation != nil, fence.EdgeOneRefresh != nil, fence.Transition != nil} {
		if present {
			payloads++
		}
	}
	if payloads != 1 {
		return fmt.Errorf("stop fence requires exactly one kind payload")
	}
	switch fence.Kind {
	case StopFenceContraction:
		if fence.Contraction == nil || len(fence.Contraction.Authorities) == 0 || !isDigest(fence.Contraction.OwnershipDigest) {
			return fmt.Errorf("contraction stop fence payload is incomplete")
		}
		if err := validateMarkerGenerations(fence.Contraction.Authorities); err != nil {
			return err
		}
		if fence.Scope.Kind == "app" {
			resource := findResource(state, fence.Scope.ResourceID)
			if resource == nil || resource.OwnershipDigest != fence.Contraction.OwnershipDigest {
				return fmt.Errorf("contraction stop fence does not match App ownership authority")
			}
		}
		return bindMarkerGenerations(fence.Contraction.Authorities, fence.Scope, state)
	case StopFenceIngressActivation:
		p := fence.IngressActivation
		if fence.Scope.Kind != "app" && fence.Scope.Kind != "headscale" {
			return fmt.Errorf("ingress activation stop fence requires App or Headscale scope")
		}
		if p == nil || !validRef(p.IntentRef) || p.CandidateGeneration == 0 || p.PriorGeneration == 0 || p.PriorGeneration+1 != p.CandidateGeneration {
			return fmt.Errorf("ingress activation stop fence payload is incomplete or generation-invalid")
		}
		if fence.Scope.Kind == "app" {
			resource := findResource(state, fence.Scope.ResourceID)
			if resource == nil || resource.Reactivating == nil || resource.Reactivating.Generation != p.CandidateGeneration || resource.Reactivating.PriorGeneration != p.PriorGeneration || resource.Reactivating.PlanID != p.IntentRef {
				return fmt.Errorf("ingress activation stop fence does not match App reactivation authority")
			}
		} else if fence.Scope.Kind == "headscale" && (state.Headscale.Reactivating == nil || state.Headscale.Reactivating.Generation != p.CandidateGeneration || state.Headscale.Reactivating.PriorGeneration != p.PriorGeneration || state.Headscale.Reactivating.PlanID != p.IntentRef) {
			return fmt.Errorf("ingress activation stop fence does not match Headscale reactivation authority")
		}
	case StopFenceCertificateActivation:
		p := fence.CertificateActivation
		if fence.Scope.Kind != "app" && fence.Scope.Kind != "headscale" {
			return fmt.Errorf("certificate activation stop fence requires App or Headscale scope")
		}
		if p == nil || !validRef(p.JournalRef) || p.ResourceGeneration == 0 || !isDigest(p.PriorPointer) || !isDigest(p.CandidatePointer) || p.ExpiryGeneration == 0 {
			return fmt.Errorf("certificate activation stop fence payload is incomplete")
		}
		if fence.Scope.Kind == "app" {
			resource := findResource(state, fence.Scope.ResourceID)
			if resource == nil || resource.GenerationSequence != p.ResourceGeneration || resource.CertificateExpiry == nil || resource.CertificateExpiry.Generation != p.ExpiryGeneration {
				return fmt.Errorf("certificate activation stop fence does not match App generation and expiry authority")
			}
		} else if fence.Scope.Kind == "headscale" && (state.Headscale.GenerationSequence != p.ResourceGeneration || state.Headscale.CertificateExpiry == nil || state.Headscale.CertificateExpiry.Generation != p.ExpiryGeneration) {
			return fmt.Errorf("certificate activation stop fence does not match Headscale generation and expiry authority")
		}
	case StopFenceEdgeOneRefresh:
		p := fence.EdgeOneRefresh
		if p == nil || !validRef(p.JournalRef) || p.ResourceGeneration == 0 || !isDigest(p.PriorACL) || !isDigest(p.CandidateACL) || p.PriorDeadline.IsZero() || p.CandidateDeadline.IsZero() {
			return fmt.Errorf("EdgeOne refresh stop fence payload is incomplete")
		}
		resource := findResource(state, fence.Scope.ResourceID)
		if fence.Scope.Kind != "app" || resource == nil || resource.GenerationSequence != p.ResourceGeneration || resource.EdgeOne.RefreshJournal != p.JournalRef || !resource.EdgeOne.Deadline.Equal(p.PriorDeadline) && !resource.EdgeOne.Deadline.Equal(p.CandidateDeadline) {
			return fmt.Errorf("EdgeOne refresh stop fence does not match journal, generation, and deadline authority")
		}
	case StopFenceMaintenanceTransition, StopFenceGenerationUpgrade:
		p := fence.Transition
		if fence.Scope.Kind != "installation" {
			return fmt.Errorf("transition stop fence requires installation scope")
		}
		if p == nil || !validRef(p.JournalRef) || !isDigest(p.CurrentEnvelope) || !isDigest(p.TargetEnvelope) || !isDigest(p.RuntimeClosureDigest) || !isDigest(p.GenerationClosureDigest) {
			return fmt.Errorf("transition stop fence payload is incomplete")
		}
		marker := state.MaintenancePending
		if fence.Kind == StopFenceGenerationUpgrade {
			marker = state.UpgradePending
		}
		if marker == nil || marker.JournalRef != p.JournalRef || marker.CurrentEnvelope != p.CurrentEnvelope || marker.TargetEnvelope != p.TargetEnvelope {
			return fmt.Errorf("transition stop fence does not match its journal marker")
		}
	default:
		return fmt.Errorf("stop fence kind %q is unsupported", fence.Kind)
	}
	return nil
}

func validateMarkerGenerations(values []MarkerGeneration) error {
	seen := map[string]bool{}
	for _, value := range values {
		if !validRef(value.Kind) || value.Generation == 0 || seen[value.Kind] {
			return fmt.Errorf("marker generation list is invalid")
		}
		seen[value.Kind] = true
	}
	return nil
}

func applicableMarkerGenerations(scope FenceScope, state State) map[string]uint64 {
	result := map[string]uint64{}
	if state.GlobalClose.Phase != GlobalCloseNone {
		result["global_close"] = state.GlobalClose.Generation
	}
	if state.MaintenancePending != nil {
		result["maintenance_pending"] = state.MaintenancePending.Generation
	}
	if state.DependencyTransitionPending != nil {
		result["dependency_transition_pending"] = state.DependencyTransitionPending.Generation
	}
	if state.UpgradePending != nil {
		result["upgrade_pending"] = state.UpgradePending.Generation
	}
	if state.BackupQuiescence != nil {
		result["backup_quiescence"] = state.BackupQuiescence.Generation
	}
	if state.BackupTransition != nil && state.BackupTransition.Phase != BackupTransitionImported {
		result["backup_transition"] = state.BackupTransition.Generation
	}
	switch scope.Kind {
	case "app":
		if resource := findResource(state, scope.ResourceID); resource != nil {
			if resource.StickyUnpublished != nil {
				result["sticky_unpublished"] = resource.StickyUnpublished.Generation
			}
			if resource.Closing != nil {
				result["closing"] = resource.Closing.Generation
			}
			if resource.Contraction != nil {
				result["contraction"] = resource.Contraction.Generation
			}
			if resource.CertificateExpiry != nil {
				result["certificate_expiry"] = resource.CertificateExpiry.Generation
			}
			if resource.EdgeOne.Expiry != nil {
				result["edgeone_expiry"] = resource.EdgeOne.Expiry.Generation
			}
			if resource.ChallengePending != nil {
				result["challenge_pending"] = resource.ChallengePending.Generation
			}
			if resource.Reactivating != nil {
				result["reactivating"] = resource.Reactivating.Generation
			}
		}
	case "headscale":
		if state.Headscale.CertificateExpiry != nil {
			result["certificate_expiry"] = state.Headscale.CertificateExpiry.Generation
		}
		if state.Headscale.ChallengePending != nil {
			result["challenge_pending"] = state.Headscale.ChallengePending.Generation
		}
		if state.Headscale.Reactivating != nil {
			result["reactivating"] = state.Headscale.Reactivating.Generation
		}
	}
	return result
}

func bindMarkerGenerations(values []MarkerGeneration, scope FenceScope, state State) error {
	var resource *ResourceSafety
	if scope.Kind == "app" {
		resource = findResource(state, scope.ResourceID)
		if resource == nil {
			return fmt.Errorf("stop fence App scope is absent from safety state")
		}
	}
	for _, value := range values {
		var generation uint64
		switch value.Kind {
		case "global_close":
			if state.GlobalClose.Phase != GlobalCloseNone {
				generation = state.GlobalClose.Generation
			}
		case "maintenance_pending":
			if state.MaintenancePending != nil {
				generation = state.MaintenancePending.Generation
			}
		case "dependency_transition_pending":
			if state.DependencyTransitionPending != nil {
				generation = state.DependencyTransitionPending.Generation
			}
		case "upgrade_pending":
			if state.UpgradePending != nil {
				generation = state.UpgradePending.Generation
			}
		case "backup_quiescence":
			if state.BackupQuiescence != nil {
				generation = state.BackupQuiescence.Generation
			}
		case "backup_transition":
			if state.BackupTransition != nil {
				generation = state.BackupTransition.Generation
			}
		case "sticky_unpublished":
			if resource != nil && resource.StickyUnpublished != nil {
				generation = resource.StickyUnpublished.Generation
			}
		case "closing":
			if resource != nil && resource.Closing != nil {
				generation = resource.Closing.Generation
			}
		case "contraction":
			if resource != nil && resource.Contraction != nil {
				generation = resource.Contraction.Generation
			}
		case "certificate_expiry":
			if resource != nil && resource.CertificateExpiry != nil {
				generation = resource.CertificateExpiry.Generation
			} else if scope.Kind == "headscale" && state.Headscale.CertificateExpiry != nil {
				generation = state.Headscale.CertificateExpiry.Generation
			}
		case "edgeone_expiry":
			if resource != nil && resource.EdgeOne.Expiry != nil {
				generation = resource.EdgeOne.Expiry.Generation
			}
		case "challenge_pending":
			if resource != nil && resource.ChallengePending != nil {
				generation = resource.ChallengePending.Generation
			} else if scope.Kind == "headscale" && state.Headscale.ChallengePending != nil {
				generation = state.Headscale.ChallengePending.Generation
			}
		case "reactivating":
			if resource != nil && resource.Reactivating != nil {
				generation = resource.Reactivating.Generation
			} else if scope.Kind == "headscale" && state.Headscale.Reactivating != nil {
				generation = state.Headscale.Reactivating.Generation
			}
		default:
			return fmt.Errorf("stop fence marker kind %q is unsupported", value.Kind)
		}
		if generation == 0 || generation != value.Generation {
			return fmt.Errorf("stop fence marker %q does not match current safety generation", value.Kind)
		}
	}
	return nil
}

func resourceGenerations(resource ResourceSafety) map[string]uint64 {
	values := map[string]uint64{}
	if resource.StickyUnpublished != nil {
		values["sticky_unpublished"] = resource.StickyUnpublished.Generation
	}
	if resource.Closing != nil {
		values["closing"] = resource.Closing.Generation
	}
	if resource.Contraction != nil {
		values["contraction"] = resource.Contraction.Generation
	}
	if resource.CertificateExpiry != nil {
		values["certificate_expiry"] = resource.CertificateExpiry.Generation
	}
	if resource.EdgeOne.Expiry != nil {
		values["edgeone_expiry"] = resource.EdgeOne.Expiry.Generation
	}
	if resource.ChallengePending != nil {
		values["challenge_pending"] = resource.ChallengePending.Generation
	}
	if resource.Reactivating != nil {
		values["reactivating"] = resource.Reactivating.Generation
	}
	return values
}

func headscaleGenerations(headscale HeadscaleSafety) map[string]uint64 {
	values := map[string]uint64{}
	if headscale.CertificateExpiry != nil {
		values["certificate_expiry"] = headscale.CertificateExpiry.Generation
	}
	if headscale.ChallengePending != nil {
		values["challenge_pending"] = headscale.ChallengePending.Generation
	}
	if headscale.Reactivating != nil {
		values["reactivating"] = headscale.Reactivating.Generation
	}
	return values
}

func maximumGeneration(values map[string]uint64) uint64 {
	var maximum uint64
	for _, generation := range values {
		if generation > maximum {
			maximum = generation
		}
	}
	return maximum
}

func validMarkerKind(kind MarkerKind) bool {
	switch kind {
	case MarkerStickyUnpublished, MarkerClosing, MarkerContraction, MarkerCertificateExpiry, MarkerEdgeOneExpiry, MarkerDeleting:
		return true
	default:
		return false
	}
}

func validRef(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n")
}

func isDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func cleanAbsolute(path string) bool {
	return path != "" && path == strings.TrimSpace(path) && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validHost(host string) bool {
	return validRef(host) && strings.ToLower(host) == host && !strings.ContainsAny(host, "/: ")
}

func canonicalResources(resources []ResourceSafety) []ResourceSafety {
	copy := append([]ResourceSafety(nil), resources...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].ResourceID < copy[j].ResourceID })
	return copy
}

func future(value time.Time, now time.Time) bool { return !value.IsZero() && value.After(now) }
