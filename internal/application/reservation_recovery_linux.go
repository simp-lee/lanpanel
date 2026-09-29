//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/closure"
	"lanpanel/internal/contraction"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/safety"
	"time"
)

const staleReservationRetirementJournal = "emergency-reservation-retirement"

// reconcileStaleEmergencyStopFenceReservation retires only a reservation
// whose normal fence was never persisted and whose interrupted domain
// activation already has terminal, contracted job evidence. It never infers
// a fence from the reservation digest; the digest is matched exactly by the
// safety store while the current graph and runtime are proved closed here.
func reconcileStaleEmergencyStopFenceReservation(ctx context.Context, service *FixedService, state safety.State) error {
	if service == nil {
		return fmt.Errorf("stale reservation recovery service is nil")
	}
	authority, err := service.emergency.Authority()
	if err != nil {
		return err
	}
	if state.StopFence != nil || authority.StopFence != nil || authority.GlobalClose != state.GlobalClose || authority.StopFenceSequence != state.StopFenceSequence || authority.ReservedStopFenceKind == "" || authority.ReservedStopFenceKind == safety.StopFenceContraction || authority.ClearProof != nil && authority.ClearProof.StopFenceGeneration == authority.StopFenceSequence {
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
	candidates := []struct {
		resource domain.AppResource
		runtime  string
	}{}
	for _, independent := range state.Resources {
		if independent.Ownership == safety.OwnershipOrphan || independent.StickyUnpublished == nil || independent.Closing != nil || independent.Reactivating != nil || independent.ChallengePending != nil {
			continue
		}
		for _, resource := range installation.Resources {
			if resource.ID != independent.ResourceID || resource.Publication.Kind != domain.PublicationDomainHTTPS || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.LastJobID == "" {
				continue
			}
			record, loadErr := jobs.LoadEntries(document.Entries, resource.PublicationRecord.LastJobID)
			if loadErr != nil {
				return loadErr
			}
			if record.Status != jobs.StatusTerminal || record.Result != jobs.ResultInterrupted || record.ErrorCode != "activation_contracted" {
				continue
			}
			runtime := ""
			for _, postcondition := range record.Postconditions {
				if postcondition.Kind == "interrupted_activation_contracted" && postcondition.Status == jobs.PostconditionKnown {
					runtime = postcondition.Identity
				}
			}
			if runtime == "" {
				return fmt.Errorf("stale emergency reservation lacks contracted activation evidence")
			}
			candidates = append(candidates, struct {
				resource domain.AppResource
				runtime  string
			}{resource: resource, runtime: runtime})
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("stale emergency reservation lacks a terminal interrupted domain activation")
	}
	if len(candidates) != 1 {
		return fmt.Errorf("stale emergency reservation has ambiguous terminal activation evidence")
	}

	resource := candidates[0].resource
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func() { _ = mutationSet.Close() }()
	mutation, exposure, err := mutationSet.AcquireExposure(cleanupCtx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()

	fresh, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	freshAuthority, err := service.emergency.Authority()
	if err != nil {
		return err
	}
	if fresh.StopFence != nil || freshAuthority.StopFence != nil || freshAuthority.ReservedStopFenceKind != authority.ReservedStopFenceKind || freshAuthority.ReservedStopFenceDigest != authority.ReservedStopFenceDigest || freshAuthority.StopFenceSequence != fresh.StopFenceSequence || freshAuthority.Sequence != fresh.AuthoritySequence || freshAuthority.ClearProof != nil && freshAuthority.ClearProof.StopFenceGeneration == freshAuthority.StopFenceSequence {
		return fmt.Errorf("stale emergency reservation changed before runtime reconciliation")
	}

	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	result, err := host.ContractResource(cleanupCtx, resource.ID)
	if err != nil {
		return err
	}
	if result.RuntimeDigest != candidates[0].runtime {
		return fmt.Errorf("stale emergency reservation contracted runtime evidence changed")
	}
	if err := stopRecoveredGoAccessBounded(service, exposure, resource); err != nil {
		return err
	}
	if err := host.AcknowledgeContraction(context.WithoutCancel(cleanupCtx), resource.ID); err != nil {
		return err
	}

	fresh, err = service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	freshAuthority, err = service.emergency.Authority()
	if err != nil {
		return err
	}
	if fresh.StopFence != nil || freshAuthority.StopFence != nil || freshAuthority.ReservedStopFenceKind != authority.ReservedStopFenceKind || freshAuthority.ReservedStopFenceDigest != authority.ReservedStopFenceDigest || freshAuthority.StopFenceSequence != fresh.StopFenceSequence || freshAuthority.Sequence != fresh.AuthoritySequence {
		return fmt.Errorf("stale emergency reservation changed before closure proof")
	}
	owned, err := service.ownership.Inventory()
	if err != nil || !owned.Complete {
		return fmt.Errorf("stale emergency reservation ownership authority incomplete: %w", err)
	}
	manifest := result.Manifest
	inventory, err := closure.BuildInventory(closure.Inputs{Installation: installation, Safety: &fresh, Ownership: owned, Graph: &manifest})
	if err != nil || !inventory.Complete {
		return fmt.Errorf("stale emergency reservation closure inventory incomplete: %w", err)
	}
	closedHost, err := contraction.FixedHost(inventory)
	if err != nil {
		return err
	}
	if err := closedHost.TestClosedGraph(cleanupCtx); err != nil {
		return err
	}
	snapshot, err := closedHost.Observer.Observe(cleanupCtx)
	if err != nil {
		return err
	}
	if err := closure.VerifyStopped(snapshot); err != nil {
		return err
	}
	closureDigest, err := closedHost.Probe.Run(cleanupCtx, inventory)
	if err != nil {
		return err
	}
	graph, err := nginx.EncodeManifest(manifest)
	if err != nil {
		return err
	}
	unpublished := make(map[string]uint64, len(fresh.Resources))
	for _, item := range fresh.Resources {
		if item.Ownership == safety.OwnershipOrphan || item.StickyUnpublished == nil || item.Closing != nil || item.ChallengePending != nil || item.Reactivating != nil {
			return fmt.Errorf("stale emergency reservation safety coverage is incomplete")
		}
		unpublished[item.ResourceID] = item.StickyUnpublished.Generation
	}
	inventoryDigest, err := service.safety.OwnershipInventoryDigest()
	if err != nil {
		return err
	}
	proof := &safety.StopFenceConvergenceProof{Kind: freshAuthority.ReservedStopFenceKind, FenceGeneration: freshAuthority.StopFenceSequence, FenceDigest: freshAuthority.ReservedStopFenceDigest, JournalRef: staleReservationRetirementJournal, InventoryDigest: inventoryDigest, OwnedGraphDigest: shaDigest(graph), RuntimeClosureDigest: closureDigest, AllChildrenExited: true, AllAppsUnpublished: true, NoAppDisk: true, WorkersDrained: true, ListenersClosed: true, RuntimeClosed: true, NginxTestPassed: true, UnpublishedGenerations: unpublished}
	next := fresh
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
	if _, err := service.safety.Commit(cleanupCtx, exposure, safety.RoleJournalConvergence, fresh.Revision, next, safety.TransitionProof{StopFence: proof}); err != nil {
		return err
	}
	return nil
}
