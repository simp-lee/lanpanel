package contraction

import (
	"context"
	"fmt"
	"lanpanel/internal/closure"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/safety"
	"time"
)

// NormalAuthority adapts one already-admitted contraction job. Callers retain
// mutation then exposure locks for each bounded local phase.
type NormalAuthority struct {
	Safety          *safety.Store
	Emergency       *safety.EmergencyStore
	Admitter        *operations.Admitter
	Mutation        *operations.MutationLease
	Exposure        *locks.Lease
	JobID           string
	PlanID          string
	Operation       operations.Type
	Revision        uint64
	SafetyState     safety.State
	Generations     map[string]uint64
	Global          bool
	InventoryDigest string
}

func (authority *NormalAuthority) PersistClosing(ctx context.Context, inventory closure.Inventory) error {
	if authority == nil || authority.Safety == nil || authority.Emergency == nil || authority.Exposure == nil || len(authority.Generations) == 0 && !authority.Global || inventory.Digest == "" {
		return fmt.Errorf("normal contraction authority is incomplete")
	}
	authority.InventoryDigest = inventory.Digest
	if !authority.Global && len(authority.Generations) != 0 {
		persisted := 0
		for _, resource := range authority.SafetyState.Resources {
			generation, selected := authority.Generations[resource.ResourceID]
			if !selected {
				continue
			}
			if resource.Closing != nil {
				if resource.Closing.Generation != generation {
					return fmt.Errorf("persisted closing generation changed")
				}
				persisted++
				continue
			}
			if resource.StickyUnpublished != nil {
				if resource.StickyUnpublished.Generation > generation {
					return fmt.Errorf("persisted closed generation changed")
				}
				if resource.StickyUnpublished.Generation == generation {
					persisted++
				}
			}
		}
		if persisted == len(authority.Generations) {
			return nil
		}
		if persisted != 0 {
			return fmt.Errorf("persisted contraction generation inventory is incomplete")
		}
	}
	next := authority.SafetyState
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), authority.SafetyState.Resources...)
	if authority.Global {
		if next.GlobalClose.Phase != safety.GlobalCloseNone {
			return fmt.Errorf("global close authority is already active")
		}
		emergency, err := authority.Emergency.Authority()
		if err != nil || emergency.GlobalClose != authority.SafetyState.GlobalClose {
			return fmt.Errorf("global close high-water is one-sided: %w", err)
		}
		emergencyNext := emergency
		emergencyNext.Sequence++
		emergencyNext.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseClosing, Generation: emergency.GlobalClose.Generation + 1}
		if err := authority.Emergency.Commit(authority.Exposure, safety.RoleContraction, emergency.Sequence, emergencyNext); err != nil {
			return err
		}
		next.AuthoritySequence = emergencyNext.Sequence
		next.GlobalClose = emergencyNext.GlobalClose
	}
	if len(authority.Generations) == 0 && authority.Global {
		if _, err := authority.Safety.Commit(ctx, authority.Exposure, safety.RoleContraction, authority.SafetyState.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
		authority.SafetyState = next
		return nil
	}
	remaining := make(map[string]uint64, len(authority.Generations))
	for id, generation := range authority.Generations {
		remaining[id] = generation
	}
	for index := range next.Resources {
		resource := &next.Resources[index]
		generation, ok := remaining[resource.ResourceID]
		if !ok {
			continue
		}
		if generation <= resource.GenerationSequence {
			return fmt.Errorf("closing generation did not advance")
		}
		resource.GenerationSequence = generation
		resource.Closing = &safety.GenerationMarker{Kind: safety.MarkerClosing, Generation: generation, Reason: "contraction"}
		resource.Reactivating = nil
		delete(remaining, resource.ResourceID)
	}
	if len(remaining) != 0 {
		return fmt.Errorf("closing resource safety identity is missing")
	}
	if _, err := authority.Safety.Commit(ctx, authority.Exposure, safety.RoleContraction, authority.SafetyState.Revision, next, safety.TransitionProof{}); err != nil {
		if authority.Global {
			return authorityCommittedError{err: fmt.Errorf("global close authority committed but normal projection failed: %w", err)}
		}
		return err
	}
	authority.SafetyState = next
	return nil
}

func (authority *NormalAuthority) CommitUnpublished(ctx context.Context, inventory closure.Inventory) error {
	if authority.InventoryDigest != inventory.Digest {
		return fmt.Errorf("normal contraction inventory changed")
	}
	intent, err := authority.Admitter.OperationIntent(authority.JobID)
	if err != nil {
		return err
	}
	if intent.ContractionDigest != "" {
		if intent.ContractionDigest != inventory.Digest {
			return fmt.Errorf("persisted normal contraction inventory changed")
		}
		return nil
	}
	if err := authority.Admitter.CommitContractionState(ctx, authority.Mutation, authority.Exposure, authority.Revision, authority.JobID, operations.ContractionCommit{ClosureAuthorityDigest: inventory.Digest, UnpublishedGenerations: authority.Generations}); err != nil {
		return err
	}
	authority.Revision++
	return nil
}

func appContractionMarkerGenerations(resource safety.ResourceSafety) []safety.MarkerGeneration {
	result := []safety.MarkerGeneration{}
	if resource.StickyUnpublished != nil {
		result = append(result, safety.MarkerGeneration{Kind: "sticky_unpublished", Generation: resource.StickyUnpublished.Generation})
	}
	if resource.Closing != nil {
		result = append(result, safety.MarkerGeneration{Kind: "closing", Generation: resource.Closing.Generation})
	}
	if resource.Contraction != nil {
		result = append(result, safety.MarkerGeneration{Kind: "contraction", Generation: resource.Contraction.Generation})
	}
	if resource.CertificateExpiry != nil {
		result = append(result, safety.MarkerGeneration{Kind: "certificate_expiry", Generation: resource.CertificateExpiry.Generation})
	}
	if resource.ChallengePending != nil {
		result = append(result, safety.MarkerGeneration{Kind: "challenge_pending", Generation: resource.ChallengePending.Generation})
	}
	if resource.Reactivating != nil {
		result = append(result, safety.MarkerGeneration{Kind: "reactivating", Generation: resource.Reactivating.Generation})
	}
	return result
}

func appContractionFenceBindings(resource safety.ResourceSafety, closingGeneration uint64) ([]safety.MarkerGeneration, []safety.MarkerGeneration, uint64, error) {
	if resource.Closing == nil || resource.Closing.Generation != closingGeneration {
		return nil, nil, 0, fmt.Errorf("app stop fence closing authority is unavailable")
	}
	safetyGenerations := appContractionMarkerGenerations(resource)
	authorities := []safety.MarkerGeneration{{Kind: "closing", Generation: closingGeneration}}
	certificateGeneration := uint64(0)
	if resource.CertificateExpiry != nil {
		certificateGeneration = resource.CertificateExpiry.Generation
		authorities = append(authorities, safety.MarkerGeneration{Kind: "certificate_expiry", Generation: certificateGeneration})
	}
	return safetyGenerations, authorities, certificateGeneration, nil
}

func (authority *NormalAuthority) PersistStopFence(ctx context.Context, inventory closure.Inventory) error {
	if inventory.Digest != authority.InventoryDigest || authority.SafetyState.StopFence != nil || authority.Operation == "" {
		return fmt.Errorf("normal stop-fence authority changed")
	}
	emergency, err := authority.Emergency.Authority()
	if err != nil || emergency.StopFence != nil {
		return fmt.Errorf("emergency stop-fence high-water is unavailable: %w", err)
	}
	globalGeneration, closingGeneration, certificateGeneration := uint64(0), uint64(0), uint64(0)
	scopeKind, resourceID := "installation", ""
	authorities := []safety.MarkerGeneration{}
	safetyGenerations := []safety.MarkerGeneration{}
	if emergency.GlobalClose.Phase != safety.GlobalCloseNone {
		globalGeneration = emergency.GlobalClose.Generation
		authorities = append(authorities, safety.MarkerGeneration{Kind: "global_close", Generation: globalGeneration})
		safetyGenerations = append(safetyGenerations, authorities...)
	} else if len(authority.Generations) == 1 {
		scopeKind = "app"
		for id, generation := range authority.Generations {
			resourceID, closingGeneration = id, generation
		}
	} else {
		return fmt.Errorf("stop fence lacks global or exact App contraction authority")
	}
	observed := time.Now().UTC()
	ownershipDigest := inventory.FullOwnershipDigest
	if scopeKind == "app" {
		var resourceAuthority *safety.ResourceSafety
		for index := range authority.SafetyState.Resources {
			resource := &authority.SafetyState.Resources[index]
			if resource.ResourceID == resourceID && resource.Closing != nil && resource.Closing.Generation == closingGeneration {
				resourceAuthority = resource
				break
			}
		}
		if resourceAuthority == nil {
			return fmt.Errorf("app stop fence closing authority is unavailable")
		}
		var bindingErr error
		safetyGenerations, authorities, certificateGeneration, bindingErr = appContractionFenceBindings(*resourceAuthority, closingGeneration)
		if bindingErr != nil {
			return bindingErr
		}
		ownershipDigest = inventory.ResourceOwnership[resourceID]
		if ownershipDigest == "" {
			return fmt.Errorf("app stop fence ownership digest is unavailable")
		}
	}
	emergencyFence := safety.EmergencyStopFence{Kind: safety.StopFenceContraction, OriginOperation: string(authority.Operation), ScopeKind: scopeKind, ResourceID: resourceID, Generation: emergency.StopFenceSequence + 1, GlobalGeneration: globalGeneration, ClosingGeneration: closingGeneration, CertificateGeneration: certificateGeneration, OwnershipDigest: ownershipDigest, OwnedGraphDigest: inventory.Digest, InventoryDigest: inventory.FullOwnershipDigest, ObservedUnix: observed.Unix(), OperationRef: func() string {
		if authority.PlanID != "" {
			return authority.PlanID
		}
		return "intent/" + authority.JobID
	}(), AccessMayRemain: true}
	emergencyNext := emergency
	emergencyNext.Sequence++
	emergencyNext.StopFenceSequence++
	emergencyNext.ReservedStopFenceKind = safety.StopFenceContraction
	emergencyNext.StopFence = &emergencyFence
	if err := authority.Emergency.Commit(authority.Exposure, safety.RoleContraction, emergency.Sequence, emergencyNext); err != nil {
		return err
	}
	normalFence := safety.StopFence{Kind: safety.StopFenceContraction, OriginOperation: string(authority.Operation), Scope: safety.FenceScope{Kind: scopeKind, ResourceID: resourceID}, FenceGeneration: emergencyNext.StopFenceSequence, CreatedAt: observed, SafetyGenerations: append([]safety.MarkerGeneration(nil), safetyGenerations...), OwnedGraphDigest: inventory.Digest, InventoryDigest: inventory.FullOwnershipDigest, Observation: safety.StopObservation{ObservedAt: observed}, AccessMayRemain: true, Contraction: &safety.ContractionFence{Authorities: append([]safety.MarkerGeneration(nil), authorities...), OwnershipDigest: ownershipDigest, OperationRef: emergencyFence.OperationRef}}
	next := authority.SafetyState
	next.Revision++
	next.AuthoritySequence = emergencyNext.Sequence
	next.GlobalClose = emergencyNext.GlobalClose
	next.StopFenceSequence = emergencyNext.StopFenceSequence
	next.StopFence = &normalFence
	if _, err := authority.Safety.Commit(ctx, authority.Exposure, safety.RoleContraction, authority.SafetyState.Revision, next, safety.TransitionProof{}); err != nil {
		return fmt.Errorf("emergency stop fence committed but normal projection failed: %w", err)
	}
	authority.SafetyState = next
	return nil
}

func (authority *NormalAuthority) UpdateStopObservation(ctx context.Context, snapshot closure.RuntimeSnapshot, verified bool) error {
	if authority.SafetyState.StopFence == nil {
		return fmt.Errorf("normal stop fence is missing")
	}
	emergency, err := authority.Emergency.Authority()
	if err != nil || emergency.StopFence == nil {
		return fmt.Errorf("emergency stop fence is missing: %w", err)
	}
	emergencyFence := *emergency.StopFence
	emergencyFence.MasterStopped = snapshot.Master == nil
	emergencyFence.WorkersStopped = len(snapshot.Workers) == 0
	emergencyFence.ListenersStopped = len(snapshot.Listeners) == 0
	emergencyFence.ObservedUnix = snapshot.ObservedAt.Unix()
	emergencyFence.AccessMayRemain = !verified
	emergencyNext := emergency
	emergencyNext.Sequence++
	emergencyNext.StopFence = &emergencyFence
	if err := authority.Emergency.Commit(authority.Exposure, safety.RoleContraction, emergency.Sequence, emergencyNext); err != nil {
		return err
	}
	next := authority.SafetyState
	next.Revision++
	next.AuthoritySequence = emergencyNext.Sequence
	fence := *next.StopFence
	fence.Observation = safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: snapshot.ObservedAt}
	fence.AccessMayRemain = !verified
	next.StopFence = &fence
	if _, err := authority.Safety.Commit(ctx, authority.Exposure, safety.RoleContraction, authority.SafetyState.Revision, next, safety.TransitionProof{}); err != nil {
		return fmt.Errorf("emergency stop observation committed but normal projection failed: %w", err)
	}
	authority.SafetyState = next
	return nil
}

func (authority *NormalAuthority) FinalizeClosure(ctx context.Context, inventory closure.Inventory, closureDigest string) error {
	if inventory.Digest != authority.InventoryDigest {
		return fmt.Errorf("normal closure inventory changed")
	}
	if authority.SafetyState.StopFence != nil {
		return nil
	}
	persisted := 0
	for _, resource := range authority.SafetyState.Resources {
		generation, selected := authority.Generations[resource.ResourceID]
		if !selected || resource.Closing != nil || resource.StickyUnpublished == nil {
			continue
		}
		if resource.StickyUnpublished.Generation != generation {
			return fmt.Errorf("persisted closure generation changed")
		}
		persisted++
	}
	if !authority.Global && persisted == len(authority.Generations) && persisted != 0 {
		return nil
	}
	if !authority.Global && persisted != 0 {
		return fmt.Errorf("persisted closure generation inventory is incomplete")
	}
	next := authority.SafetyState
	next.Resources = append([]safety.ResourceSafety(nil), authority.SafetyState.Resources...)
	proofs := map[string]safety.ClosingConvergenceProof{}
	for index := range next.Resources {
		resource := &next.Resources[index]
		generation, ok := authority.Generations[resource.ResourceID]
		if !ok {
			continue
		}
		if resource.Closing == nil {
			if resource.StickyUnpublished == nil || resource.StickyUnpublished.Generation != generation {
				return fmt.Errorf("closing safety identity changed before finalization")
			}
			continue
		}
		if resource.Closing.Generation != generation {
			return fmt.Errorf("closing safety identity changed before finalization")
		}
		resource.Closing = nil
		resource.StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: generation, Reason: "closed"}
		proofs[resource.ResourceID] = safety.ClosingConvergenceProof{ResourceID: resource.ResourceID, ClosingGeneration: generation, UnpublishedGeneration: generation, OwnershipDigest: resource.OwnershipDigest, RuntimeClosureDigest: closureDigest}
	}
	if len(proofs) != 0 {
		next.Revision++
		if _, err := authority.Safety.Commit(ctx, authority.Exposure, safety.RoleContraction, authority.SafetyState.Revision, next, safety.TransitionProof{Closings: proofs}); err != nil {
			return err
		}
		authority.SafetyState = next
	}
	if !authority.Global {
		return nil
	}
	unpublished := make(map[string]uint64, len(next.Resources))
	ownership := make(map[string]string, len(next.Resources))
	for _, resource := range next.Resources {
		if resource.StickyUnpublished == nil {
			return fmt.Errorf("global close cannot converge while an App is not sticky-unpublished")
		}
		unpublished[resource.ResourceID] = resource.StickyUnpublished.Generation
		ownership[resource.ResourceID] = resource.OwnershipDigest
	}
	globalProof := &safety.GlobalConvergenceProof{Generation: next.GlobalClose.Generation, InventoryDigest: safety.OwnershipInventoryDigest(ownership), OwnedGraphDigest: inventory.Digest, RuntimeClosureDigest: closureDigest, UnpublishedGenerations: unpublished, NginxTestPassed: true, RuntimeClosed: true}
	emergency, err := authority.Emergency.Authority()
	if err != nil || emergency.GlobalClose != next.GlobalClose || emergency.StopFence != nil {
		return fmt.Errorf("global close high-water changed before convergence: %w", err)
	}
	emergencyNext := emergency
	emergencyNext.Sequence++
	emergencyNext.GlobalClose.Phase = safety.GlobalCloseNone
	emergencyNext.ClearProof = &safety.EmergencyClearProof{Generation: globalProof.Generation, InventoryDigest: globalProof.InventoryDigest, OwnedGraphDigest: globalProof.OwnedGraphDigest, RuntimeClosureDigest: globalProof.RuntimeClosureDigest, NginxTestPassed: true, RuntimeClosed: true}
	if err := authority.Emergency.Commit(authority.Exposure, safety.RoleGlobalCloseConvergence, emergency.Sequence, emergencyNext); err != nil {
		return err
	}
	globalNext := next
	globalNext.Revision++
	globalNext.AuthoritySequence = emergencyNext.Sequence
	globalNext.GlobalClose = emergencyNext.GlobalClose
	if _, err := authority.Safety.Commit(ctx, authority.Exposure, safety.RoleGlobalCloseConvergence, next.Revision, globalNext, safety.TransitionProof{GlobalClose: globalProof}); err != nil {
		return authorityCommittedError{err: fmt.Errorf("emergency global clear committed but normal projection failed: %w", err)}
	}
	authority.SafetyState = globalNext
	return nil
}

func CompleteNormal(ctx context.Context, authority *NormalAuthority, result Result) (jobs.Record, error) {
	branch, status, kind, code := "complete", jobs.PostconditionVerified, "access_closed", ""
	identity := result.ClosureDigest
	if identity == "" {
		identity = authority.InventoryDigest
	}
	switch result.Outcome {
	case OutcomeSucceeded:
	case OutcomePartial:
		branch, status, kind, code = "known_residual", jobs.PostconditionKnown, "shared_ingress_down", "activation_contracted"
		if result.ErrorCode == "goaccess_stop_failed" {
			code = result.ErrorCode
			kind = "goaccess_retirement_pending"
		}
	case OutcomeInterrupted:
		branch, status, kind, code = "executor_died", jobs.PostconditionKnown, "contraction_interrupted", "activation_contracted"
	case OutcomeUnknown:
		branch, status, kind, code = "source_unknown", jobs.PostconditionUnobserved, "access_may_remain", "activation_contracted"
	case OutcomeFailed:
		branch, status, kind, code = "no_effect", jobs.PostconditionVerified, "mutation_not_started", "contraction_authority_failed"
	default:
		return jobs.Record{}, fmt.Errorf("normal contraction result is invalid")
	}
	return authority.Admitter.Complete(ctx, authority.Mutation, authority.Exposure, authority.Revision, authority.JobID, branch, result.ModifiedPaths, []jobs.Postcondition{{Kind: kind, Status: status, Identity: identity}}, code)
}
