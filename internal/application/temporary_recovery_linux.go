//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/publication"
	"lanpanel/internal/safety"
	"reflect"
	"slices"
	"time"
)

const (
	temporaryInterruptedClosingReason = "interrupted_temporary_http_activation"
	temporaryCommittedClosingReason   = "committed_temporary_http_recovery"
)

type temporaryPublicationRecoveryStage uint8

const (
	temporaryRecoveryReserved temporaryPublicationRecoveryStage = iota + 1
	temporaryRecoveryConsumedNoEffect
	temporaryRecoveryActivationDurable
	temporaryRecoveryTerminalNoEffect
	temporaryRecoveryCommitted
)

type temporaryPublicationRecovery struct {
	Resource domain.AppResource
	Intent   operations.Reservation
	Job      jobs.Record
	Journal  *operations.JournalRecord
	Marker   safety.Reactivating
}

type temporaryPublicationRecoveryHost interface {
	VerifyTemporary(context.Context, publication.Candidate, domain.AppTarget) (string, error)
	AuditManifest(context.Context) (nginx.Manifest, error)
	ContractResource(context.Context, string) (activation.Result, error)
	ProbeTemporaryClosure(context.Context, closure.Inventory) (string, error)
	StopAndVerify(context.Context) (closure.RuntimeSnapshot, error)
}

func temporaryClosingReason(reason string) bool {
	return reason == temporaryInterruptedClosingReason || reason == temporaryCommittedClosingReason
}

func loadTemporaryPublicationRecovery(document persist.Document, resourceID string, marker safety.Reactivating) (temporaryPublicationRecovery, error) {
	installation, err := installationFromDocument(document)
	if err != nil {
		return temporaryPublicationRecovery{}, err
	}
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == resourceID {
			copy := installation.Resources[index]
			resource = &copy
			break
		}
	}
	if resource == nil || resource.Publication.Kind != domain.PublicationTemporaryHTTP || resource.Publication.TemporaryHTTP == nil || !marker.TemporaryHTTP {
		return temporaryPublicationRecovery{}, fmt.Errorf("temporary publication recovery resource changed")
	}
	var intent *operations.Reservation
	for _, key := range persist.EntryKeys(document, "intents") {
		var candidate operations.Reservation
		if err := json.Unmarshal(document.Entries[key], &candidate); err != nil {
			return temporaryPublicationRecovery{}, err
		}
		if candidate.Operation != operations.Publish || candidate.PlanID != marker.PlanID {
			continue
		}
		if intent != nil {
			return temporaryPublicationRecovery{}, fmt.Errorf("temporary publication has multiple Plan intents")
		}
		copy := candidate
		intent = &copy
	}
	if intent == nil || intent.Target != "resource/"+resourceID || intent.SafetyBinding.ResourceID != resourceID || intent.SafetyBinding.PlanID != marker.PlanID || intent.SafetyBinding.IntentGeneration != marker.Generation || intent.SafetyBinding.CandidateDigest != marker.CandidateDigest || intent.SafetyBinding.CandidateBundle != marker.CandidateBundle {
		return temporaryPublicationRecovery{}, fmt.Errorf("temporary publication lacks exact normal intent authority")
	}
	record, err := jobs.LoadEntries(document.Entries, intent.JobID)
	if err != nil {
		return temporaryPublicationRecovery{}, err
	}
	var journal *operations.JournalRecord
	for _, key := range persist.EntryKeys(document, "journals") {
		var candidate operations.JournalRecord
		if err := json.Unmarshal(document.Entries[key], &candidate); err != nil {
			return temporaryPublicationRecovery{}, err
		}
		if candidate.JobID != intent.JobID {
			continue
		}
		if journal != nil {
			return temporaryPublicationRecovery{}, fmt.Errorf("temporary publication has multiple journals")
		}
		copy := candidate
		journal = &copy
	}
	return temporaryPublicationRecovery{Resource: *resource, Intent: *intent, Job: record, Journal: journal, Marker: marker}, nil
}

func classifyTemporaryPublicationRecovery(value temporaryPublicationRecovery) (temporaryPublicationRecoveryStage, error) {
	active := value.Resource.PublicationRecord.ActivationIntent
	switch value.Intent.Phase {
	case operations.PhaseReserved:
		if value.Job.Status != jobs.StatusReserved || active != nil || value.Resource.PublicationRecord.State == domain.PublicationActivating || value.Journal != nil {
			return 0, fmt.Errorf("reserved temporary publication already has durable effect")
		}
		return temporaryRecoveryReserved, nil
	case operations.PhaseRejected:
		if value.Job.Status != jobs.StatusTerminal || value.Job.Result != jobs.ResultFailed || active != nil || value.Resource.PublicationRecord.State == domain.PublicationActivating || value.Journal != nil {
			return 0, fmt.Errorf("rejected temporary publication retains durable effect")
		}
		return temporaryRecoveryTerminalNoEffect, nil
	case operations.PhaseLocalIntent:
		if value.Job.Status != jobs.StatusRunning {
			return 0, fmt.Errorf("temporary publication local intent job is not running")
		}
		if active == nil {
			if value.Resource.PublicationRecord.State == domain.PublicationActivating || value.Journal != nil {
				return 0, fmt.Errorf("temporary publication no-effect boundary is inconsistent")
			}
			return temporaryRecoveryConsumedNoEffect, nil
		}
		if err := validateTemporaryActivationAuthority(value); err != nil {
			return 0, err
		}
		return temporaryRecoveryActivationDurable, nil
	case operations.PhaseTerminal:
		if value.Job.Status != jobs.StatusTerminal || active != nil {
			return 0, fmt.Errorf("terminal temporary publication authority is inconsistent")
		}
		if value.Resource.PublicationRecord.State == domain.PublicationPublished && value.Resource.PublicationRecord.LastAppliedBundle != nil && value.Resource.PublicationRecord.LastAppliedBundle.TemporaryHTTP != nil && value.Job.Result == jobs.ResultSucceeded {
			return temporaryRecoveryCommitted, nil
		}
		if value.Resource.PublicationRecord.State != domain.PublicationActivating && value.Job.Result == jobs.ResultFailed {
			if value.Journal != nil {
				journal := value.Journal
				if journal.ID != "activation-"+value.Intent.JobID || journal.Kind != operations.JournalAppActivation || journal.Operation != operations.Publish || journal.Target != value.Intent.Target || journal.Generation != value.Intent.IntentGeneration || journal.ArtifactDigest != value.Marker.CandidateBundle || journal.Phase != operations.JournalTerminal {
					return 0, fmt.Errorf("failed temporary publication journal authority changed")
				}
			}
			return temporaryRecoveryTerminalNoEffect, nil
		}
		return 0, fmt.Errorf("terminal temporary publication lacks exact completion or no-effect evidence")
	default:
		return 0, fmt.Errorf("temporary publication recovery phase is unsupported")
	}
}

func validateTemporaryActivationAuthority(value temporaryPublicationRecovery) error {
	active := value.Resource.PublicationRecord.ActivationIntent
	if active == nil || value.Resource.PublicationRecord.State != domain.PublicationActivating || active.JobID != value.Intent.JobID || active.PlanID != value.Marker.PlanID || active.Generation != value.Marker.Generation || active.Candidate.TemporaryHTTP == nil || active.Candidate.ConfigDigest != value.Marker.CandidateDigest || publication.RequireBundleDigest(active.Candidate, value.Marker.CandidateBundle) != nil {
		return fmt.Errorf("temporary publication activation intent changed")
	}
	if value.Journal != nil {
		journal := value.Journal
		if journal.ID != "activation-"+value.Intent.JobID || journal.Kind != operations.JournalAppActivation || journal.Operation != operations.Publish || journal.Target != value.Intent.Target || journal.Generation != value.Intent.IntentGeneration || journal.ArtifactDigest != value.Marker.CandidateBundle || journal.Phase != operations.JournalPrepared {
			return fmt.Errorf("temporary publication journal authority changed")
		}
	}
	return nil
}

func exactTemporaryMarkerPresent(service *FixedService, exposure *locks.Lease, resourceID string, marker safety.Reactivating) (bool, error) {
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return false, err
	}
	for _, item := range state.Resources {
		if item.ResourceID != resourceID {
			continue
		}
		if item.Reactivating == nil {
			return false, nil
		}
		if !reflect.DeepEqual(*item.Reactivating, marker) {
			return false, fmt.Errorf("temporary publication marker changed")
		}
		return true, nil
	}
	return false, fmt.Errorf("temporary publication safety resource missing")
}

func restoreExactTemporaryMarker(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID string, marker safety.Reactivating) error {
	return service.RestorePublicationSafety(ctx, exposure, resourceID, marker)
}

func convergeTemporaryPublicationOwnership(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID string, marker safety.Reactivating) (ownership.Record, error) {
	owned, err := service.ownership.Read(resourceID)
	if err != nil {
		return ownership.Record{}, err
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return ownership.Record{}, err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	for index := range next.Resources {
		item := &next.Resources[index]
		if item.ResourceID != resourceID {
			continue
		}
		if item.Reactivating == nil || !reflect.DeepEqual(*item.Reactivating, marker) {
			return ownership.Record{}, fmt.Errorf("temporary publication ownership marker changed")
		}
		if item.OwnershipDigest == owned.Checksum {
			return owned, nil
		}
		before := item.OwnershipDigest
		item.OwnershipDigest = owned.Checksum
		proof := &safety.OwnershipConvergenceProof{ResourceID: resourceID, IntentRef: marker.PlanID, Generation: marker.Generation, BeforeDigest: before, AfterDigest: owned.Checksum}
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleOwnershipActivation, state.Revision, next, safety.TransitionProof{Ownership: proof}); err != nil {
			return ownership.Record{}, err
		}
		return owned, nil
	}
	return ownership.Record{}, fmt.Errorf("temporary publication ownership safety resource missing")
}

func temporaryCandidateOwned(owned ownership.Record, candidate publication.Candidate) bool {
	paths := candidate.OwnershipPaths
	if len(paths) == 0 {
		paths = []ownership.OwnedPath{candidate.OwnershipPath}
	}
	listeners := candidate.OwnershipListeners
	if len(listeners) == 0 {
		listeners = []ownership.OwnedListener{candidate.OwnershipListener}
	}
	for _, expected := range paths {
		if !slices.Contains(owned.Paths, expected) {
			return false
		}
	}
	for _, expected := range listeners {
		if !slices.Contains(owned.Listeners, expected) {
			return false
		}
	}
	return true
}

func convergeCommittedTemporaryPublication(ctx context.Context, service *FixedService, exposure *locks.Lease, resource domain.AppResource, marker safety.Reactivating, candidate publication.Candidate, runtimeDigest string) error {
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	proof := &safety.ReactivationConvergenceProof{ResourceID: resource.ID, PlanID: marker.PlanID, Generation: marker.Generation, CandidateDigest: marker.CandidateDigest, CandidateBundle: marker.CandidateBundle, RuntimeClosureDigest: runtimeDigest}
	found := false
	for index := range next.Resources {
		item := &next.Resources[index]
		if item.ResourceID != resource.ID {
			continue
		}
		if item.Reactivating == nil || !reflect.DeepEqual(*item.Reactivating, marker) || candidate.Bundle.ConfigDigest != marker.CandidateDigest || candidate.BundleDigest != marker.CandidateBundle {
			return fmt.Errorf("committed temporary publication marker changed")
		}
		item.StickyUnpublished = nil
		item.Contraction = nil
		item.CertificateExpiry = nil
		item.Reactivating = nil
		found = true
	}
	if !found {
		return fmt.Errorf("committed temporary publication safety resource missing")
	}
	_, err = service.safety.Commit(ctx, exposure, safety.RolePublish, state.Revision, next, safety.TransitionProof{Reactivation: proof})
	return err
}

func beginTemporaryPublicationContraction(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID string, marker safety.Reactivating, reason string) (uint64, error) {
	if !temporaryClosingReason(reason) {
		return 0, fmt.Errorf("temporary publication closing reason invalid")
	}
	if _, err := convergeTemporaryPublicationOwnership(ctx, service, exposure, resourceID, marker); err != nil {
		return 0, err
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return 0, err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	generation := uint64(0)
	for index := range next.Resources {
		item := &next.Resources[index]
		if item.ResourceID != resourceID {
			continue
		}
		if item.Reactivating == nil || !reflect.DeepEqual(*item.Reactivating, marker) {
			return 0, fmt.Errorf("temporary publication contraction marker changed")
		}
		generation = item.GenerationSequence + 1
		item.GenerationSequence = generation
		item.Closing = &safety.GenerationMarker{Kind: safety.MarkerClosing, Generation: generation, Reason: reason}
		item.Reactivating = nil
	}
	if generation == 0 {
		return 0, fmt.Errorf("temporary publication contraction safety resource missing")
	}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, state.Revision, next, safety.TransitionProof{}); err != nil {
		return 0, err
	}
	return generation, nil
}

func buildTemporaryClosureInventory(service *FixedService, exposure *locks.Lease, resourceID, planID string, candidateGeneration uint64, manifest nginx.Manifest) (closure.Inventory, error) {
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return closure.Inventory{}, err
	}
	document, err := service.normal.Read()
	if err != nil {
		return closure.Inventory{}, err
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		return closure.Inventory{}, err
	}
	var intent *operations.Reservation
	for _, key := range persist.EntryKeys(document, "intents") {
		var current operations.Reservation
		if err := json.Unmarshal(document.Entries[key], &current); err != nil {
			return closure.Inventory{}, err
		}
		if current.Operation != operations.Publish || current.PlanID != planID {
			continue
		}
		if intent != nil {
			return closure.Inventory{}, fmt.Errorf("temporary closure has multiple Plan intents")
		}
		copy := current
		intent = &copy
	}
	if intent == nil || intent.Target != "resource/"+resourceID || intent.SafetyBinding.ResourceID != resourceID || intent.SafetyBinding.PlanID != planID || intent.SafetyBinding.IntentGeneration != candidateGeneration || intent.Phase == operations.PhaseReserved || intent.Phase == operations.PhaseRejected {
		return closure.Inventory{}, fmt.Errorf("temporary closure intent authority changed")
	}
	installation.Resources = append([]domain.AppResource(nil), installation.Resources...)
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == resourceID {
			resource = &installation.Resources[index]
		}
	}
	if resource == nil || resource.Publication.Kind != domain.PublicationTemporaryHTTP || resource.Publication.TemporaryHTTP == nil {
		return closure.Inventory{}, fmt.Errorf("temporary closure resource authority changed")
	}
	candidate, err := publication.PrepareTemporary(*resource, candidateGeneration)
	if err != nil || candidate.Bundle.ConfigDigest != intent.SafetyBinding.CandidateDigest || candidate.BundleDigest != intent.SafetyBinding.CandidateBundle {
		return closure.Inventory{}, fmt.Errorf("temporary closure candidate authority changed: %w", err)
	}
	active := resource.PublicationRecord.ActivationIntent
	candidatePresent := resource.PublicationRecord.LastAppliedBundle != nil && reflect.DeepEqual(*resource.PublicationRecord.LastAppliedBundle, candidate.Bundle)
	if active != nil {
		if active.Generation != candidateGeneration || !reflect.DeepEqual(active.Candidate, candidate.Bundle) {
			return closure.Inventory{}, fmt.Errorf("temporary closure activation candidate changed")
		}
		candidatePresent = true
	}
	if !candidatePresent {
		resource.PublicationRecord.ActivationIntent = &domain.ActivationIntent{ID: "closure-" + intent.JobID, JobID: intent.JobID, PlanID: planID, Generation: candidateGeneration, Candidate: candidate.Bundle, Prior: resource.PublicationRecord.LastAppliedBundle, PriorState: resource.PublicationRecord.State}
	}
	candidateEntryPresent := false
	for _, entry := range manifest.Entries {
		if reflect.DeepEqual(entry, candidate.Entry) {
			candidateEntryPresent = true
		}
	}
	if !candidateEntryPresent {
		manifest.Entries = append(append([]nginx.Entry(nil), manifest.Entries...), candidate.Entry)
	}
	owned, err := service.ownership.Inventory()
	if err != nil || !owned.Complete {
		return closure.Inventory{}, fmt.Errorf("temporary closure ownership authority incomplete: %w", err)
	}
	inventory, err := closure.BuildInventory(closure.Inputs{Installation: installation, Safety: &state, Ownership: owned, Graph: &manifest, ResourceIDs: []string{resourceID}})
	if err != nil || !inventory.Complete {
		return closure.Inventory{}, fmt.Errorf("temporary closure inventory is incomplete: %w", err)
	}
	authority := findSafetyResource(state, resourceID)
	if authority == nil || inventory.ResourceOwnership[resourceID] != authority.OwnershipDigest {
		return closure.Inventory{}, fmt.Errorf("temporary closure ownership identity changed")
	}
	expectedListeners := make(map[string]bool, len(candidate.Entry.Listeners))
	for _, listener := range candidate.Entry.Listeners {
		expectedListeners[listener] = false
	}
	for _, identity := range inventory.Identities {
		if identity.ResourceID == resourceID && identity.Kind == closure.IdentityTemporaryListener {
			if _, present := expectedListeners[identity.Value]; present {
				expectedListeners[identity.Value] = true
			}
		}
	}
	for _, present := range expectedListeners {
		if !present {
			return closure.Inventory{}, fmt.Errorf("temporary closure candidate listener is missing")
		}
	}
	return inventory, nil
}

func persistTemporaryContractionFence(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID, planID string, generation uint64) error {
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil || state.GlobalClose.Phase != safety.GlobalCloseNone {
		return fmt.Errorf("temporary contraction fence safety authority changed: %w", err)
	}
	var resource *safety.ResourceSafety
	for index := range state.Resources {
		item := &state.Resources[index]
		if item.ResourceID == resourceID && item.Closing != nil && item.Closing.Generation == generation && temporaryClosingReason(item.Closing.Reason) {
			resource = item
			break
		}
	}
	if resource == nil {
		return fmt.Errorf("temporary contraction fence closing authority missing")
	}
	manifest, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return err
	}
	if generation == 0 {
		return fmt.Errorf("temporary contraction candidate generation is missing")
	}
	inventory, err := buildTemporaryClosureInventory(service, exposure, resourceID, planID, generation-1, manifest)
	if err != nil || inventory.ResourceOwnership[resourceID] != resource.OwnershipDigest {
		return fmt.Errorf("temporary contraction closure inventory is incomplete or changed: %w", err)
	}
	return commitTemporaryContractionFence(ctx, service, exposure, resourceID, planID, generation, resource.OwnershipDigest, inventory.Digest, inventory.FullOwnershipDigest)
}

func temporaryContractionFenceIdentityMatches(normal *safety.StopFence, emergency safety.EmergencyStopFence) bool {
	if normal == nil || normal.Kind != safety.StopFenceContraction || normal.Contraction == nil || normal.OriginOperation != emergency.OriginOperation || normal.Scope.Kind != emergency.ScopeKind || normal.Scope.ResourceID != emergency.ResourceID || normal.FenceGeneration != emergency.Generation || normal.OwnedGraphDigest != emergency.OwnedGraphDigest || normal.InventoryDigest != emergency.InventoryDigest || normal.Contraction.OwnershipDigest != emergency.OwnershipDigest || normal.Contraction.OperationRef != emergency.OperationRef || len(normal.Contraction.Authorities) != 1 {
		return false
	}
	authority := normal.Contraction.Authorities[0]
	return authority.Kind == "closing" && authority.Generation == emergency.ClosingGeneration
}

func commitTemporaryContractionFence(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID, planID string, generation uint64, ownershipDigest, graphDigest, inventoryDigest string) error {
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil || state.GlobalClose.Phase != safety.GlobalCloseNone || ownershipDigest == "" || graphDigest == "" || inventoryDigest == "" {
		return fmt.Errorf("temporary contraction fence commit authority changed: %w", err)
	}
	found := false
	for _, resource := range state.Resources {
		if resource.ResourceID == resourceID && resource.OwnershipDigest == ownershipDigest && resource.Closing != nil && resource.Closing.Generation == generation && temporaryClosingReason(resource.Closing.Reason) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("temporary contraction fence exact closing authority missing")
	}
	authority, err := service.emergency.Authority()
	if err != nil || authority.GlobalClose != state.GlobalClose {
		return fmt.Errorf("temporary contraction emergency authority changed: %w", err)
	}
	var emergencyFence safety.EmergencyStopFence
	if authority.StopFence == nil {
		if state.StopFence != nil || authority.StopFenceSequence != state.StopFenceSequence {
			return fmt.Errorf("temporary contraction fence high-water changed")
		}
		observedAt := time.Now().UTC()
		emergencyFence = safety.EmergencyStopFence{Kind: safety.StopFenceContraction, OriginOperation: string(operations.Publish), ScopeKind: "app", ResourceID: resourceID, Generation: authority.StopFenceSequence + 1, ClosingGeneration: generation, OperationRef: planID, OwnershipDigest: ownershipDigest, OwnedGraphDigest: graphDigest, InventoryDigest: inventoryDigest, ObservedUnix: observedAt.Unix(), AccessMayRemain: true}
		emergencyNext := authority
		emergencyNext.Sequence++
		emergencyNext.StopFenceSequence++
		emergencyNext.ReservedStopFenceKind = safety.StopFenceContraction
		emergencyNext.StopFence = &emergencyFence
		if err := service.emergency.Commit(exposure, safety.RoleContraction, authority.Sequence, emergencyNext); err != nil {
			return err
		}
		authority = emergencyNext
	} else {
		emergencyFence = *authority.StopFence
		if emergencyFence.Kind != safety.StopFenceContraction || emergencyFence.OriginOperation != string(operations.Publish) || emergencyFence.ScopeKind != "app" || emergencyFence.ResourceID != resourceID || emergencyFence.ClosingGeneration != generation || emergencyFence.OperationRef != planID || emergencyFence.OwnershipDigest != ownershipDigest || authority.StopFenceSequence != emergencyFence.Generation || state.StopFence == nil && authority.StopFenceSequence != state.StopFenceSequence+1 || state.StopFence != nil && (authority.StopFenceSequence != state.StopFenceSequence || !temporaryContractionFenceIdentityMatches(state.StopFence, emergencyFence)) {
			return fmt.Errorf("one-sided temporary contraction fence identity changed")
		}
		if state.StopFence != nil && safety.FenceMatchesEmergency(state.StopFence, emergencyFence) && state.AuthoritySequence == authority.Sequence {
			return nil
		}
	}
	createdAt := time.Unix(emergencyFence.ObservedUnix, 0).UTC()
	if state.StopFence != nil {
		createdAt = state.StopFence.CreatedAt
	}
	next := state
	next.Revision++
	next.AuthoritySequence = authority.Sequence
	next.StopFenceSequence = authority.StopFenceSequence
	next.StopFence = &safety.StopFence{Kind: safety.StopFenceContraction, OriginOperation: emergencyFence.OriginOperation, Scope: safety.FenceScope{Kind: "app", ResourceID: resourceID}, FenceGeneration: emergencyFence.Generation, CreatedAt: createdAt, SafetyGenerations: applicablePublicationMarkers(state, resourceID), OwnedGraphDigest: emergencyFence.OwnedGraphDigest, InventoryDigest: emergencyFence.InventoryDigest, Observation: safety.StopObservation{MasterStopped: emergencyFence.MasterStopped, WorkersStopped: emergencyFence.WorkersStopped, ListenersStopped: emergencyFence.ListenersStopped, ObservedAt: time.Unix(emergencyFence.ObservedUnix, 0).UTC()}, AccessMayRemain: emergencyFence.AccessMayRemain, Contraction: &safety.ContractionFence{Authorities: []safety.MarkerGeneration{{Kind: "closing", Generation: generation}}, OwnershipDigest: ownershipDigest, OperationRef: planID}}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, state.Revision, next, safety.TransitionProof{}); err != nil {
		return fmt.Errorf("temporary emergency contraction fence committed but normal projection failed: %w", err)
	}
	return nil
}

func updateTemporaryContractionFence(ctx context.Context, service *FixedService, exposure *locks.Lease, observation safety.StopObservation, accessMayRemain bool) error {
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil || state.StopFence == nil || state.StopFence.Kind != safety.StopFenceContraction || state.StopFence.Scope.Kind != "app" || state.StopFence.Contraction == nil {
		return fmt.Errorf("temporary contraction normal fence changed: %w", err)
	}
	authority, err := service.emergency.Authority()
	if err != nil || authority.StopFence == nil {
		return fmt.Errorf("temporary contraction emergency fence changed: %w", err)
	}
	if !safety.FenceMatchesEmergency(state.StopFence, *authority.StopFence) {
		if !temporaryContractionFenceIdentityMatches(state.StopFence, *authority.StopFence) {
			return fmt.Errorf("temporary contraction emergency fence identity changed")
		}
		emergencyFence := authority.StopFence
		if err := commitTemporaryContractionFence(ctx, service, exposure, emergencyFence.ResourceID, emergencyFence.OperationRef, emergencyFence.ClosingGeneration, emergencyFence.OwnershipDigest, emergencyFence.OwnedGraphDigest, emergencyFence.InventoryDigest); err != nil {
			return err
		}
		state, err = service.safety.ReadForRecovery(exposure)
		if err != nil {
			return err
		}
		authority, err = service.emergency.Authority()
		if err != nil || authority.StopFence == nil || !safety.FenceMatchesEmergency(state.StopFence, *authority.StopFence) {
			return fmt.Errorf("temporary contraction emergency fence projection failed: %w", err)
		}
	}
	if state.StopFence.Observation == observation && state.StopFence.AccessMayRemain == accessMayRemain {
		return nil
	}
	emergencyFence := *authority.StopFence
	emergencyFence.MasterStopped = observation.MasterStopped
	emergencyFence.WorkersStopped = observation.WorkersStopped
	emergencyFence.ListenersStopped = observation.ListenersStopped
	emergencyFence.ObservedUnix = observation.ObservedAt.Unix()
	emergencyFence.AccessMayRemain = accessMayRemain
	emergencyNext := authority
	emergencyNext.Sequence++
	emergencyNext.StopFence = &emergencyFence
	if err := service.emergency.Commit(exposure, safety.RoleContraction, authority.Sequence, emergencyNext); err != nil {
		return err
	}
	next := state
	next.Revision++
	next.AuthoritySequence = emergencyNext.Sequence
	fence := *state.StopFence
	fence.Observation = observation
	fence.AccessMayRemain = accessMayRemain
	next.StopFence = &fence
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, state.Revision, next, safety.TransitionProof{}); err != nil {
		return fmt.Errorf("temporary emergency stop observation committed but normal projection failed: %w", err)
	}
	return nil
}

func failTemporaryPublicationContraction(ctx context.Context, service *FixedService, exposure *locks.Lease, host temporaryPublicationRecoveryHost, resourceID, planID string, generation uint64, cause error) error {
	fenceCtx, cancelFence := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	fenceErr := persistTemporaryContractionFence(fenceCtx, service, exposure, resourceID, planID, generation)
	cancelFence()
	stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	snapshot, stopErr := host.StopAndVerify(stopCtx)
	cancelStop()
	observedAt := snapshot.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: observedAt}
	var updateErr error
	if fenceErr == nil {
		updateCtx, cancelUpdate := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		updateErr = updateTemporaryContractionFence(updateCtx, service, exposure, observed, stopErr != nil)
		cancelUpdate()
	}
	return errors.Join(cause, fenceErr, stopErr, updateErr)
}

func temporaryTerminalContractionEvidence(document persist.Document, resource domain.AppResource, closing safety.GenerationMarker) error {
	if resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.UnpublishedGeneration != closing.Generation {
		return fmt.Errorf("temporary publication terminal contraction generation changed")
	}
	record, err := jobs.LoadEntries(document.Entries, resource.PublicationRecord.LastJobID)
	if err != nil || record.Status != jobs.StatusTerminal {
		return fmt.Errorf("temporary publication terminal contraction job changed: %w", err)
	}
	switch closing.Reason {
	case temporaryInterruptedClosingReason:
		if record.Result != jobs.ResultInterrupted || record.ErrorCode != "temporary_http_activation_recovery" {
			return fmt.Errorf("interrupted temporary publication terminal evidence changed")
		}
	case temporaryCommittedClosingReason:
		bundle := resource.PublicationRecord.LastAppliedBundle
		if record.Result != jobs.ResultSucceeded || bundle == nil || bundle.TemporaryHTTP == nil || bundle.Generation+1 != closing.Generation {
			return fmt.Errorf("committed temporary publication terminal evidence changed")
		}
	default:
		return fmt.Errorf("temporary publication closing reason changed")
	}
	return nil
}

func contractTemporaryPublicationLocked(ctx context.Context, service *FixedService, admitter *operations.Admitter, mutation *operations.MutationLease, exposure *locks.Lease, recovery temporaryPublicationRecovery, host temporaryPublicationRecoveryHost, reason string) error {
	manifest, manifestErr := host.AuditManifest(ctx)
	inventory, inventoryErr := buildTemporaryClosureInventory(service, exposure, recovery.Resource.ID, recovery.Marker.PlanID, recovery.Marker.Generation, manifest)
	generation, err := beginTemporaryPublicationContraction(ctx, service, exposure, recovery.Resource.ID, recovery.Marker, reason)
	if err != nil {
		return err
	}
	if inventoryErr != nil || manifestErr != nil {
		return failTemporaryPublicationContraction(ctx, service, exposure, host, recovery.Resource.ID, recovery.Marker.PlanID, generation, errors.Join(manifestErr, inventoryErr))
	}
	result, contractErr := host.ContractResource(ctx, recovery.Resource.ID)
	if contractErr == nil {
		result.RuntimeDigest, contractErr = host.ProbeTemporaryClosure(ctx, inventory)
	}
	if contractErr != nil {
		return failTemporaryPublicationContraction(ctx, service, exposure, host, recovery.Resource.ID, recovery.Marker.PlanID, generation, contractErr)
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		return err
	}
	var current *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == recovery.Resource.ID {
			current = &installation.Resources[index]
			break
		}
	}
	if current == nil {
		return fmt.Errorf("temporary publication contraction normal resource missing")
	}
	switch current.PublicationRecord.State {
	case domain.PublicationActivating:
		if reason != temporaryInterruptedClosingReason {
			return fmt.Errorf("committed temporary publication returned to activating")
		}
		if _, err := admitter.TerminalizeInterruptedTemporaryPublication(ctx, mutation, exposure, document.Revision, recovery.Intent.JobID, recovery.Intent.SafetyBinding, generation, result.ModifiedPaths, result.RuntimeDigest); err != nil {
			return err
		}
	case domain.PublicationPublished:
		if reason != temporaryCommittedClosingReason {
			return fmt.Errorf("interrupted temporary publication advanced to published")
		}
		if err := admitter.ConvergeCommittedPublicationContraction(ctx, mutation, exposure, document.Revision, current.ID, generation, result.RuntimeDigest); err != nil {
			return err
		}
	case domain.PublicationUnpublished:
		if err := temporaryTerminalContractionEvidence(document, *current, safety.GenerationMarker{Kind: safety.MarkerClosing, Generation: generation, Reason: reason}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("temporary publication contraction normal state changed")
	}
	return convergeInterruptedDomainClosing(ctx, service, exposure, recovery.Resource.ID, generation, result.RuntimeDigest, reason)
}

func completeTemporaryPublicationLocked(ctx context.Context, service *FixedService, admitter *operations.Admitter, mutation *operations.MutationLease, exposure *locks.Lease, recovery temporaryPublicationRecovery, host temporaryPublicationRecoveryHost) (bool, error) {
	candidate, err := publication.PrepareTemporary(recovery.Resource, recovery.Marker.Generation)
	if err != nil || candidate.BundleDigest != recovery.Marker.CandidateBundle || candidate.Bundle.ConfigDigest != recovery.Marker.CandidateDigest {
		return false, nil
	}
	owned, err := convergeTemporaryPublicationOwnership(ctx, service, exposure, recovery.Resource.ID, recovery.Marker)
	if err != nil || !temporaryCandidateOwned(owned, candidate) {
		return false, err
	}
	runtimeDigest, err := host.VerifyTemporary(ctx, candidate, recovery.Resource.Target)
	if err != nil {
		return false, nil
	}
	if recovery.Resource.PublicationRecord.State == domain.PublicationPublished {
		applied := recovery.Resource.PublicationRecord.LastAppliedBundle
		if applied == nil || !reflect.DeepEqual(*applied, candidate.Bundle) || recovery.Journal == nil || recovery.Journal.Phase != operations.JournalTerminal || recovery.Job.Result != jobs.ResultSucceeded {
			return false, nil
		}
		return true, convergeCommittedTemporaryPublication(ctx, service, exposure, recovery.Resource, recovery.Marker, candidate, runtimeDigest)
	}
	if recovery.Resource.PublicationRecord.State != domain.PublicationActivating || recovery.Journal == nil || recovery.Journal.Phase != operations.JournalPrepared || !reflect.DeepEqual(recovery.Resource.PublicationRecord.ActivationIntent.Candidate, candidate.Bundle) {
		return false, nil
	}
	document, err := service.normal.Read()
	if err != nil {
		return false, err
	}
	observation := domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: time.Now().UTC().Format(time.RFC3339), Reason: "published_recovered"}
	safetyCommit := func() error {
		return convergeCommittedTemporaryPublication(ctx, service, exposure, recovery.Resource, recovery.Marker, candidate, runtimeDigest)
	}
	job, commitErr := admitter.CommitPublicationPublished(ctx, mutation, exposure, document.Revision, recovery.Intent.JobID, operations.PublicationTerminalCommit{ResourceID: recovery.Resource.ID, Bundle: candidate.Bundle, Runtime: observation}, "activation-"+recovery.Intent.JobID, runtimeDigest, nil, safetyCommit)
	if commitErr != nil && job.ID != "" {
		commitErr = convergeCommittedTemporaryPublication(ctx, service, exposure, recovery.Resource, recovery.Marker, candidate, runtimeDigest)
	}
	return true, commitErr
}

func recoverTemporaryPublicationLocked(ctx context.Context, service *FixedService, admitter *operations.Admitter, mutation *operations.MutationLease, exposure *locks.Lease, resourceID, jobID string, marker safety.Reactivating, host temporaryPublicationRecoveryHost, noEffectCode string) (bool, error) {
	document, err := service.normal.Read()
	if err != nil {
		return false, err
	}
	recovery, err := loadTemporaryPublicationRecovery(document, resourceID, marker)
	if err != nil {
		return false, err
	}
	if recovery.Intent.JobID != jobID {
		return false, fmt.Errorf("temporary publication recovery job changed")
	}
	stage, err := classifyTemporaryPublicationRecovery(recovery)
	if err != nil {
		return false, err
	}
	switch stage {
	case temporaryRecoveryReserved:
		if err := restoreExactTemporaryMarker(ctx, service, exposure, recovery.Resource.ID, marker); err != nil {
			return false, err
		}
		return true, nil
	case temporaryRecoveryConsumedNoEffect:
		if _, err := admitter.TerminalizeTemporaryPublicationNoEffect(ctx, mutation, exposure, document.Revision, jobID, recovery.Intent.SafetyBinding, noEffectCode); err != nil {
			return false, err
		}
		return false, restoreExactTemporaryMarker(ctx, service, exposure, recovery.Resource.ID, marker)
	case temporaryRecoveryTerminalNoEffect:
		return false, restoreExactTemporaryMarker(ctx, service, exposure, recovery.Resource.ID, marker)
	case temporaryRecoveryActivationDurable, temporaryRecoveryCommitted:
		completed, completeErr := completeTemporaryPublicationLocked(ctx, service, admitter, mutation, exposure, recovery, host)
		if completeErr != nil || completed {
			return false, completeErr
		}
		reason := temporaryInterruptedClosingReason
		if stage == temporaryRecoveryCommitted {
			reason = temporaryCommittedClosingReason
		}
		return false, contractTemporaryPublicationLocked(ctx, service, admitter, mutation, exposure, recovery, host, reason)
	default:
		return false, fmt.Errorf("temporary publication recovery stage invalid")
	}
}

func rejectExactTemporaryReservation(ctx context.Context, service *FixedService, admitter *operations.Admitter, admission *locks.Lease, jobID string, expected operations.SafetyBinding, code string) error {
	if admission == nil || !admission.Holds(locks.MutationAdmission) {
		return fmt.Errorf("temporary publication reservation rejection lacks admission authority")
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	raw, present := document.Entries["intents/"+jobID]
	if !present {
		return fmt.Errorf("temporary publication reservation is missing")
	}
	var intent operations.Reservation
	if err := json.Unmarshal(raw, &intent); err != nil {
		return err
	}
	if intent.JobID != jobID || intent.Operation != operations.Publish || intent.AdmissionSource != operations.AdmissionPlan || intent.Target != "resource/"+expected.ResourceID || intent.PlanID != expected.PlanID || !reflect.DeepEqual(intent.SafetyBinding, expected) {
		return fmt.Errorf("temporary publication reservation identity changed")
	}
	record, err := jobs.LoadEntries(document.Entries, jobID)
	if err != nil {
		return err
	}
	switch intent.Phase {
	case operations.PhaseReserved:
		if record.Status != jobs.StatusReserved {
			return fmt.Errorf("temporary publication reserved job changed")
		}
		return admitter.RejectReservation(ctx, admission, document.Revision, jobID, code)
	case operations.PhaseRejected:
		if record.Status != jobs.StatusTerminal {
			return fmt.Errorf("temporary publication rejected job changed")
		}
		return nil
	default:
		return fmt.Errorf("temporary publication reservation advanced during rejection")
	}
}

func rejectReservedTemporaryPublication(ctx context.Context, service *FixedService, admitter *operations.Admitter, jobID string, expected operations.SafetyBinding, code string) error {
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return err
	}
	rejectErr := rejectExactTemporaryReservation(ctx, service, admitter, admission, jobID, expected, code)
	return errors.Join(rejectErr, admission.Release())
}

func markerlessTemporaryReservations(document persist.Document, state safety.State) ([]operations.Reservation, error) {
	installation, err := installationFromDocument(document)
	if err != nil {
		return nil, err
	}
	resources := make(map[string]domain.AppResource, len(installation.Resources))
	for _, resource := range installation.Resources {
		resources[resource.ID] = resource
	}
	safetyResources := make(map[string]safety.ResourceSafety, len(state.Resources))
	for _, resource := range state.Resources {
		safetyResources[resource.ResourceID] = resource
	}
	journals := map[string]bool{}
	for _, key := range persist.EntryKeys(document, "journals") {
		var journal operations.JournalRecord
		if err := json.Unmarshal(document.Entries[key], &journal); err != nil {
			return nil, err
		}
		journals[journal.JobID] = true
	}
	reservations := []operations.Reservation{}
	for _, key := range persist.EntryKeys(document, "intents") {
		var intent operations.Reservation
		if err := json.Unmarshal(document.Entries[key], &intent); err != nil {
			return nil, err
		}
		if intent.Operation != operations.Publish || intent.AdmissionSource != operations.AdmissionPlan || intent.Phase != operations.PhaseReserved || intent.PlanID == "" || intent.Target != "resource/"+intent.SafetyBinding.ResourceID || intent.SafetyBinding.PlanID != intent.PlanID || journals[intent.JobID] {
			continue
		}
		resource, present := resources[intent.SafetyBinding.ResourceID]
		authority := safetyResources[intent.SafetyBinding.ResourceID]
		if !present || resource.Publication.Kind != domain.PublicationTemporaryHTTP || resource.Publication.TemporaryHTTP == nil || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.State == domain.PublicationActivating || authority.Reactivating != nil || authority.Closing != nil {
			continue
		}
		candidate, prepareErr := publication.PrepareTemporary(resource, intent.SafetyBinding.IntentGeneration)
		if prepareErr != nil || candidate.Bundle.ConfigDigest != intent.SafetyBinding.CandidateDigest || candidate.BundleDigest != intent.SafetyBinding.CandidateBundle {
			continue
		}
		record, loadErr := jobs.LoadEntries(document.Entries, intent.JobID)
		if loadErr != nil {
			return nil, loadErr
		}
		if record.Status != jobs.StatusReserved {
			return nil, fmt.Errorf("markerless temporary reservation job changed")
		}
		reservations = append(reservations, intent)
	}
	slices.SortFunc(reservations, func(left, right operations.Reservation) int { return compare(left.JobID, right.JobID) })
	return reservations, nil
}

func reconcileMarkerlessTemporaryReservations(ctx context.Context, service *FixedService, state safety.State) error {
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	reservations, err := markerlessTemporaryReservations(document, state)
	if err != nil {
		return err
	}
	if len(reservations) == 0 {
		return nil
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	for _, reservation := range reservations {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		err = rejectReservedTemporaryPublication(cleanupCtx, service, admitter, reservation.JobID, reservation.SafetyBinding, "publication_revalidation_failed")
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func reconcileInterruptedTemporaryPublication(ctx context.Context, service *FixedService, authority safety.ResourceSafety, lockRoot string, owner, group uint32, host temporaryPublicationRecoveryHost) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if authority.Reactivating == nil || !authority.Reactivating.TemporaryHTTP {
		if authority.Closing != nil && temporaryClosingReason(authority.Closing.Reason) {
			if host == nil {
				fixedHost, err := activation.NewFixedHost()
				if err != nil {
					return err
				}
				host = fixedHost
			}
			return resumeTemporaryPublicationContraction(cleanupCtx, service, authority.ResourceID, *authority.Closing, lockRoot, owner, group, host)
		}
		return fmt.Errorf("temporary publication recovery authority missing")
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	recovery, err := loadTemporaryPublicationRecovery(document, authority.ResourceID, *authority.Reactivating)
	if err != nil {
		return err
	}
	recoveryStage, err := classifyTemporaryPublicationRecovery(recovery)
	if err != nil {
		return err
	}
	if host == nil && (recoveryStage == temporaryRecoveryActivationDurable || recoveryStage == temporaryRecoveryCommitted) {
		fixedHost, err := activation.NewFixedHost()
		if err != nil {
			return err
		}
		host = fixedHost
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: lockRoot, Owner: owner, Group: group, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(cleanupCtx, "resource/"+authority.ResourceID, service.manager)
	if err != nil {
		_ = mutationSet.Close()
		return err
	}
	reject, recoveryErr := recoverTemporaryPublicationLocked(cleanupCtx, service, admitter, mutation, exposure, authority.ResourceID, recovery.Intent.JobID, *authority.Reactivating, host, "temporary_http_no_effect")
	releaseErr := operations.ReleaseExposure(mutation, exposure)
	closeErr := mutationSet.Close()
	if err := errors.Join(recoveryErr, releaseErr, closeErr); err != nil {
		return err
	}
	if reject {
		return rejectReservedTemporaryPublication(cleanupCtx, service, admitter, recovery.Intent.JobID, recovery.Intent.SafetyBinding, "publication_revalidation_failed")
	}
	return nil
}

func resumeTemporaryPublicationContraction(ctx context.Context, service *FixedService, resourceID string, closing safety.GenerationMarker, lockRoot string, owner, group uint32, host temporaryPublicationRecoveryHost) (resultErr error) {
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: lockRoot, Owner: owner, Group: group, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resourceID, service.manager)
	if err != nil {
		return errors.Join(err, mutationSet.Close())
	}
	defer func() {
		resultErr = errors.Join(resultErr, operations.ReleaseExposure(mutation, exposure), mutationSet.Close())
	}()
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	found := false
	for _, item := range state.Resources {
		if item.ResourceID == resourceID && item.Closing != nil && reflect.DeepEqual(*item.Closing, closing) && temporaryClosingReason(item.Closing.Reason) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("temporary publication closing authority changed")
	}
	authority, authorityErr := service.emergency.Authority()
	if authorityErr != nil {
		return authorityErr
	}
	if state.StopFence != nil && (state.StopFence.Kind != safety.StopFenceContraction || state.StopFence.Scope.Kind != "app" || state.StopFence.Scope.ResourceID != resourceID || state.StopFence.Contraction == nil) {
		return fmt.Errorf("temporary publication closing has unrelated stop fence")
	}
	if authority.StopFence != nil {
		emergencyFence := authority.StopFence
		return commitTemporaryContractionFence(ctx, service, exposure, emergencyFence.ResourceID, emergencyFence.OperationRef, emergencyFence.ClosingGeneration, emergencyFence.OwnershipDigest, emergencyFence.OwnedGraphDigest, emergencyFence.InventoryDigest)
	}
	if state.StopFence != nil {
		proof := authority.ClearProof
		if proof == nil || proof.StopFenceGeneration != state.StopFence.FenceGeneration || proof.InventoryDigest != state.StopFence.InventoryDigest || proof.OwnedGraphDigest != state.StopFence.OwnedGraphDigest || !proof.NginxTestPassed || !proof.RuntimeClosed {
			return fmt.Errorf("temporary publication closing emergency clear proof changed")
		}
		return nil
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		return err
	}
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == resourceID {
			resource = &installation.Resources[index]
			break
		}
	}
	if resource == nil || resource.Publication.Kind != domain.PublicationTemporaryHTTP {
		return fmt.Errorf("temporary publication closing resource changed")
	}
	jobID := resource.PublicationRecord.LastJobID
	if active := resource.PublicationRecord.ActivationIntent; active != nil {
		jobID = active.JobID
	}
	planID := ""
	intent, intentErr := admitter.OperationIntent(jobID)
	if intentErr == nil {
		planID = intent.PlanID
	}
	manifest, manifestErr := host.AuditManifest(ctx)
	if closing.Generation == 0 {
		return fmt.Errorf("temporary publication closing generation is missing")
	}
	inventory, inventoryErr := buildTemporaryClosureInventory(service, exposure, resourceID, planID, closing.Generation-1, manifest)
	if manifestErr != nil || inventoryErr != nil {
		return failTemporaryPublicationContraction(ctx, service, exposure, host, resourceID, planID, closing.Generation, errors.Join(manifestErr, inventoryErr, intentErr))
	}
	result, contractErr := host.ContractResource(ctx, resourceID)
	if contractErr == nil {
		result.RuntimeDigest, contractErr = host.ProbeTemporaryClosure(ctx, inventory)
	}
	if contractErr != nil {
		return failTemporaryPublicationContraction(ctx, service, exposure, host, resourceID, planID, closing.Generation, errors.Join(contractErr, intentErr))
	}
	switch resource.PublicationRecord.State {
	case domain.PublicationActivating:
		active := resource.PublicationRecord.ActivationIntent
		if closing.Reason != temporaryInterruptedClosingReason || active == nil || active.Generation+1 != closing.Generation || intentErr != nil {
			return fmt.Errorf("temporary publication closing activation authority changed: %w", intentErr)
		}
		if _, err := admitter.TerminalizeInterruptedTemporaryPublication(ctx, mutation, exposure, document.Revision, active.JobID, intent.SafetyBinding, closing.Generation, result.ModifiedPaths, result.RuntimeDigest); err != nil {
			return err
		}
	case domain.PublicationPublished:
		bundle := resource.PublicationRecord.LastAppliedBundle
		if closing.Reason != temporaryCommittedClosingReason || bundle == nil || bundle.TemporaryHTTP == nil || bundle.Generation+1 != closing.Generation {
			return fmt.Errorf("committed temporary publication closing authority changed")
		}
		if err := admitter.ConvergeCommittedPublicationContraction(ctx, mutation, exposure, document.Revision, resourceID, closing.Generation, result.RuntimeDigest); err != nil {
			return err
		}
	case domain.PublicationUnpublished:
		if err := temporaryTerminalContractionEvidence(document, *resource, closing); err != nil {
			return err
		}
	default:
		return fmt.Errorf("temporary publication closing normal state changed")
	}
	return convergeInterruptedDomainClosing(ctx, service, exposure, resourceID, closing.Generation, result.RuntimeDigest, closing.Reason)
}
