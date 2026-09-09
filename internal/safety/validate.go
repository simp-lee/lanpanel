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

func validateHeadscale(headscale HeadscaleSafety) error {
	if maximumGeneration(headscaleGenerations(headscale)) > headscale.GenerationSequence {
		return fmt.Errorf("headscale generation exceeds its monotonic sequence")
	}
	if (headscale.ActiveCertificate == nil) != (headscale.ControlEntryDigest == "") || headscale.ControlEntryDigest != "" && !isDigest(headscale.ControlEntryDigest) {
		return fmt.Errorf("headscale control entry authority invalid")
	}
	if headscale.ActiveCertificate != nil {
		active := headscale.ActiveCertificate
		if active.Generation == 0 || !isDigest(active.Fingerprint) || !validRef(active.Binding) || active.NotAfter.IsZero() || active.LastTrustedWall.IsZero() || !active.NotAfter.After(active.LastTrustedWall) {
			return fmt.Errorf("headscale active certificate authority invalid")
		}
	}
	if headscale.CertificateExpiry != nil {
		if err := validateDeadlineMarker(*headscale.CertificateExpiry); err != nil {
			return fmt.Errorf("headscale certificate expiry: %w", err)
		}
		if headscale.ActiveCertificate == nil || headscale.CertificateExpiry.Binding != headscale.ActiveCertificate.Binding {
			return fmt.Errorf("headscale certificate expiry lacks active authority")
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
		return fmt.Errorf("headscale challenge and reactivation identities are mutually exclusive")
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
	if resource.ActiveCertificate != nil {
		active := resource.ActiveCertificate
		if active.Generation == 0 || !isDigest(active.Fingerprint) || !validRef(active.Binding) || active.NotAfter.IsZero() || active.LastTrustedWall.IsZero() || !active.NotAfter.After(active.LastTrustedWall) {
			return fmt.Errorf("active certificate authority invalid")
		}
	}
	if resource.CertificateExpiry != nil {
		if err := validateDeadlineMarker(*resource.CertificateExpiry); err != nil {
			return fmt.Errorf("certificate expiry: %w", err)
		}
		if resource.ActiveCertificate == nil || resource.CertificateExpiry.Binding != resource.ActiveCertificate.Binding {
			return fmt.Errorf("certificate expiry lacks matching active authority")
		}
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
		return fmt.Errorf("app challenge and reactivation identities are mutually exclusive")
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
	if challenge.Generation == 0 || !validRef(challenge.PlanID) || !validHost(challenge.Host) || len(challenge.Hosts) == 0 || !isDigest(challenge.ConfigDigest) || !isDigest(challenge.SANIdentity) || !isDigest(challenge.ACMEBinding) || !validRef(challenge.CertificateIdentity) || !isDigest(challenge.BootstrapIdentity) {
		return fmt.Errorf("challenge complete ACME identity is incomplete")
	}
	hostPresent := false
	for index, host := range challenge.Hosts {
		if !validHost(host) || index > 0 && challenge.Hosts[index-1] >= host {
			return fmt.Errorf("challenge Host inventory invalid")
		}
		hostPresent = hostPresent || challenge.Host == host
	}
	switch challenge.Method {
	case "http-01":
		inactive := challenge.Host == challenge.Hosts[0] && challenge.Token == "" && challenge.TokenPath == "" && challenge.KeyAuthorizationDigest == ""
		active := hostPresent && validHTTP01Token(challenge.Token) && challenge.TokenPath == "/.well-known/acme-challenge/"+challenge.Token && isDigest(challenge.KeyAuthorizationDigest)
		expectedWebroot := filepath.Join("/var/lib/lanpanel/certificates/webroot", challenge.CertificateIdentity)
		if challenge.OwnerLock != "" || challenge.Provider != "" || challenge.Zone != "" || len(challenge.Owners) != 0 || challenge.Webroot != expectedWebroot || !inactive && !active {
			return fmt.Errorf("HTTP-01 route authority invalid")
		}
	case "dns-01":
		if challenge.Token != "" || challenge.KeyAuthorizationDigest != "" || !isDigest(challenge.OwnerLock) || (challenge.Provider != "cloudflare" && challenge.Provider != "route53" && challenge.Provider != "digitalocean" && challenge.Provider != "gcloud" && challenge.Provider != "tencentcloud") || !validHost(challenge.Zone) || len(challenge.Owners) != len(challenge.Hosts) || challenge.TokenPath != "/dns-01" || challenge.Webroot != "/var/lib/lanpanel/certificates/dns-only" {
			return fmt.Errorf("DNS-01 owner authority invalid")
		}
		for index, owner := range challenge.Owners {
			if owner != "_acme-challenge."+challenge.Hosts[index] || (owner != challenge.Zone && !strings.HasSuffix(owner, "."+challenge.Zone)) {
				return fmt.Errorf("DNS-01 owner inventory invalid")
			}
		}
	default:
		return fmt.Errorf("challenge method invalid")
	}
	if challenge.TokenPath != "" && (!strings.HasPrefix(challenge.TokenPath, "/") || filepath.Clean(challenge.TokenPath) != challenge.TokenPath) || !cleanAbsolute(challenge.Webroot) {
		return fmt.Errorf("challenge path authority invalid")
	}
	if err := validateBaseSnapshot(challenge.BaseMarkers); err != nil {
		return err
	}
	return nil
}

func validHTTP01Token(value string) bool {
	if len(value) < 20 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		letter := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validateReactivating(reactivating Reactivating) error {
	if reactivating.Generation == 0 || reactivating.PriorGeneration+1 != reactivating.Generation || !validRef(reactivating.PlanID) || !isDigest(reactivating.CandidateDigest) || !isDigest(reactivating.CandidateBundle) || (!reactivating.TemporaryHTTP && reactivating.CertificateUntil.IsZero()) || (reactivating.TemporaryHTTP && !reactivating.CertificateUntil.IsZero()) {
		return fmt.Errorf("reactivating identity is incomplete")
	}
	if reactivating.ProbePending && !validRef(reactivating.ProbeCorrelation) {
		return fmt.Errorf("probe-pending reactivation requires correlation")
	}
	return validateBaseSnapshot(reactivating.BaseMarkers)
}

func validateHeadscaleReactivating(reactivating HeadscaleReactivating) error {
	activationPairValid := reactivating.ActivationDigest == "" && reactivating.ControlEntryDigest == "" || isDigest(reactivating.ActivationDigest) && isDigest(reactivating.ControlEntryDigest)
	if reactivating.Generation == 0 || reactivating.PriorGeneration+1 != reactivating.Generation || !validRef(reactivating.PlanID) || reactivating.ControlGeneration == 0 || reactivating.CertificateGeneration == 0 || !isDigest(reactivating.CertificateFingerprint) || !isDigest(reactivating.CandidateDigest) || !isDigest(reactivating.CandidateBundle) || !activationPairValid || reactivating.CertificateUntil.IsZero() || reactivating.CertificateLastTrustedWall.IsZero() || !reactivating.CertificateUntil.After(reactivating.CertificateLastTrustedWall) {
		return fmt.Errorf("headscale reactivating identity is incomplete")
	}
	if reactivating.ProbePending && !validRef(reactivating.ProbeCorrelation) {
		return fmt.Errorf("probe-pending Headscale reactivation requires correlation")
	}
	return validateBaseSnapshot(reactivating.BaseMarkers)
}

func validateBaseSnapshot(snapshot []MarkerSnapshot) error {
	required := []MarkerKind{MarkerStickyUnpublished, MarkerContraction, MarkerCertificateExpiry}
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
		return fmt.Errorf("app stop fence requires resource ID")
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
	for _, present := range []bool{fence.Contraction != nil, fence.IngressActivation != nil, fence.CertificateActivation != nil} {
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
		normalOperation := validRef(fence.Contraction.OperationRef) && fence.Contraction.SafetyIntentID == "" && fence.Contraction.SafetyIntentGeneration == 0
		stateIndependent := fence.Contraction.OperationRef == "" && validRef(fence.Contraction.SafetyIntentID) && fence.Contraction.SafetyIntentGeneration != 0
		if !normalOperation && !stateIndependent {
			return fmt.Errorf("contraction stop fence lacks exact operation or safety-intent identity")
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
		if p == nil || !validRef(p.IntentRef) || p.CandidateGeneration == 0 || p.PriorGeneration+1 != p.CandidateGeneration || fence.Scope.Kind == "app" && p.PriorGeneration == 0 {
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
	case MarkerStickyUnpublished, MarkerClosing, MarkerContraction, MarkerCertificateExpiry, MarkerDeleting:
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
