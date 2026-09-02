//go:build linux

package contraction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	goaccessruntime "lanpanel/internal/goaccess"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/safety"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type EmergencySnapshot struct {
	Inventory        closure.Inventory
	GlobalGeneration uint64
}

type EmergencyService struct {
	manager           *locks.Manager
	exposure          *locks.Lease
	ownership         *ownership.Store
	emergency         *safety.EmergencyStore
	safetyStore       *safety.Store
	safetyState       *safety.State
	installation      domain.Installation
	normalUnavailable bool
	graph             *nginx.Manifest
	inventory         ownership.Inventory
	normal            *persist.Store
	launcher          *child.Launcher
	paths             nginx.Paths
	closed            bool
	globalCommitted   bool
}

func OpenEmergency(ctx context.Context) (*EmergencyService, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, fmt.Errorf("emergency contraction requires root helper")
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	manager, err := locks.Open(locks.Config{RootPath: "/var/lib/lanpanel/locks", Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*EmergencyService, error) { _ = manager.Close(); return nil, err }
	exposure, err := manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		return fail(err)
	}
	service := &EmergencyService{manager: manager, exposure: exposure, paths: nginx.FixedPaths()}
	closeFail := func(err error) (*EmergencyService, error) { _ = service.Close(); return nil, err }
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: "/var/lib/lanpanel/ownership", StagingPath: "/var/lib/lanpanel/ownership/.filetxn", RecordsPath: "/var/lib/lanpanel/ownership/records", Owner: owner, Policy: ownership.FixedPolicy(), LockAuthority: manager.Authority()})
	if err == nil {
		service.ownership = ownershipStore
		service.inventory, err = ownershipStore.Inventory()
	}
	if err != nil {
		service.inventory = ownership.Inventory{Complete: false, Issues: []ownership.Issue{{Name: "ownership_tree", Error: "unavailable"}}}
	}
	emergency, err := safety.OpenEmergency("/var/lib/lanpanel/safety/emergency", owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		return closeFail(err)
	}
	service.emergency = emergency
	if service.ownership != nil {
		store, openErr := safety.OpenStore(safety.StoreConfig{RootPath: "/var/lib/lanpanel/safety", StagingPath: "/var/lib/lanpanel/safety/.filetxn", StatePath: "/var/lib/lanpanel/safety/state.json", Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
		if openErr == nil {
			service.safetyStore = store
			if state, readErr := store.ReadForContraction(exposure); readErr == nil {
				service.safetyState = &state
			} else if state, recoveryErr := store.ReadForRecovery(exposure); recoveryErr == nil {
				service.safetyState = &state
			}
		}
	}
	service.normalUnavailable = true
	if normal, openErr := persist.Open(persist.Config{RootPath: "/var/lib/lanpanel/state", StagingPath: "/var/lib/lanpanel/state/.filetxn", StatePath: "/var/lib/lanpanel/state/normal.json", Owner: owner, LockAuthority: manager.Authority()}); openErr == nil {
		if registerErr := operations.Register(normal); registerErr == nil {
			service.normal = normal
		}
		if document, readErr := normal.Read(); readErr == nil {
			if raw, present := document.Entries["installations/current"]; present {
				if installation, decodeErr := domain.DecodeInstallation(raw); decodeErr == nil {
					service.installation = installation
					service.normalUnavailable = false
				}
			}
		}
		if service.normal == nil {
			_ = normal.Close()
		}
	}
	if manifest, auditErr := nginx.Audit(service.paths, owner); auditErr == nil {
		service.graph = &manifest
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return closeFail(err)
	}
	service.launcher = launcher
	return service, nil
}

func (service *EmergencyService) Snapshot() (EmergencySnapshot, error) {
	if service == nil || service.closed {
		return EmergencySnapshot{}, fmt.Errorf("emergency contraction service is closed")
	}
	inputs := closure.Inputs{Installation: service.installation, NormalUnavailable: service.normalUnavailable, Safety: service.safetyState, Ownership: service.inventory, Graph: service.graph}
	inventory, err := closure.BuildInventory(inputs)
	if err != nil {
		inventory = closure.BuildFallbackInventory(inputs, err)
	}
	authority, err := service.emergency.Authority()
	if err != nil {
		return EmergencySnapshot{}, err
	}
	return EmergencySnapshot{Inventory: inventory, GlobalGeneration: authority.GlobalClose.Generation}, nil
}

func projectedFenceSafetyGenerations(scope safety.FenceScope, state safety.State) []safety.MarkerGeneration {
	result := []safety.MarkerGeneration{}
	if state.GlobalClose.Phase != safety.GlobalCloseNone {
		result = append(result, safety.MarkerGeneration{Kind: "global_close", Generation: state.GlobalClose.Generation})
	}
	switch scope.Kind {
	case "app":
		for _, resource := range state.Resources {
			if resource.ResourceID == scope.ResourceID {
				result = append(result, appContractionMarkerGenerations(resource)...)
				break
			}
		}
	case "headscale":
		if state.Headscale.CertificateExpiry != nil {
			result = append(result, safety.MarkerGeneration{Kind: "certificate_expiry", Generation: state.Headscale.CertificateExpiry.Generation})
		}
		if state.Headscale.ChallengePending != nil {
			result = append(result, safety.MarkerGeneration{Kind: "challenge_pending", Generation: state.Headscale.ChallengePending.Generation})
		}
		if state.Headscale.Reactivating != nil {
			result = append(result, safety.MarkerGeneration{Kind: "reactivating", Generation: state.Headscale.Reactivating.Generation})
		}
	}
	return result
}

func (service *EmergencyService) recoverPendingNginxContraction(ctx context.Context, snapshot EmergencySnapshot) error {
	scope, present, err := nginx.ContractionScope(service.paths, filetxn.Owner{UID: 0, GID: 0})
	if err != nil || !present {
		return err
	}
	_, modifiedPaths, recovered, err := nginx.RecoverContraction(ctx, service.paths, filetxn.Owner{UID: 0, GID: 0})
	if err != nil || !recovered {
		return errors.Join(err, fmt.Errorf("pending nginx contraction was not recovered"))
	}
	if service.normal == nil {
		return fmt.Errorf("pending nginx contraction normal store is unavailable")
	}
	if err := operations.TerminalizeContractionReceipt(ctx, service.normal, service.exposure, scope, modifiedPaths, snapshot.Inventory.Digest, time.Now().UTC()); err != nil {
		fullScope := appResourceIDs(snapshot.Inventory)
		slices.Sort(fullScope)
		if errors.Is(err, operations.ErrContractionReceiptUnbound) && slices.Equal(scope, fullScope) {
			return nil
		}
		return err
	}
	return nginx.AcknowledgeContraction(context.WithoutCancel(ctx), service.paths, filetxn.Owner{UID: 0, GID: 0}, scope)
}

func (service *EmergencyService) recoverFenceClearedGlobal(ctx context.Context, snapshot EmergencySnapshot, authority safety.EmergencyState, state safety.State) error {
	if err := service.recoverPendingNginxContraction(ctx, snapshot); err != nil {
		return err
	}
	if state.GlobalClose.Phase == safety.GlobalCloseNone || authority.GlobalClose.Generation != state.GlobalClose.Generation || service.normal == nil {
		return fmt.Errorf("fence-cleared global recovery authority is incomplete")
	}
	host, err := FixedHost(snapshot.Inventory)
	if err != nil {
		return err
	}
	modifiedPaths, err := host.ContractDisk(ctx, snapshot.Inventory)
	if err != nil {
		return err
	}
	if err := host.TestClosedGraph(ctx); err != nil {
		return err
	}
	runtime, observeErr := host.Observe(ctx)
	stoppedErr := closure.VerifyStopped(runtime)
	if observeErr != nil || stoppedErr != nil {
		return fmt.Errorf("fence-cleared global recovery runtime is not stopped: %w", errors.Join(observeErr, stoppedErr))
	}
	unpublished := make(map[string]uint64, len(state.Resources))
	ownership := make(map[string]string, len(state.Resources))
	for _, resource := range state.Resources {
		if resource.StickyUnpublished == nil || resource.Closing != nil {
			return fmt.Errorf("fence-cleared global recovery resource is not converged")
		}
		unpublished[resource.ResourceID] = resource.StickyUnpublished.Generation
		ownership[resource.ResourceID] = resource.OwnershipDigest
	}
	closureDigest := snapshot.Inventory.Digest
	globalProof := &safety.GlobalConvergenceProof{Generation: state.GlobalClose.Generation, InventoryDigest: safety.OwnershipInventoryDigest(ownership), OwnedGraphDigest: snapshot.Inventory.Digest, RuntimeClosureDigest: closureDigest, UnpublishedGenerations: unpublished, NginxTestPassed: true, RuntimeClosed: true}
	current := authority
	if authority.GlobalClose.Phase == safety.GlobalCloseNone {
		proof := authority.ClearProof
		if proof == nil || proof.Generation != globalProof.Generation || proof.InventoryDigest != globalProof.InventoryDigest || proof.OwnedGraphDigest != snapshot.Inventory.Digest || proof.RuntimeClosureDigest != snapshot.Inventory.Digest || !proof.NginxTestPassed || !proof.RuntimeClosed {
			return fmt.Errorf("fence-cleared emergency global proof changed")
		}
		globalProof.OwnedGraphDigest = proof.OwnedGraphDigest
		globalProof.RuntimeClosureDigest = proof.RuntimeClosureDigest
		closureDigest = proof.RuntimeClosureDigest
	}
	if err := operations.RecoverClosedInstallation(ctx, service.normal, service.exposure, unpublished, modifiedPaths, closureDigest, state.Checksum, time.Now().UTC(), nil); err != nil {
		return err
	}
	if err := host.AcknowledgeDiskContraction(context.WithoutCancel(ctx), snapshot.Inventory); err != nil {
		return err
	}
	if authority.GlobalClose.Phase != safety.GlobalCloseNone {
		cleared := authority
		cleared.Sequence++
		cleared.GlobalClose.Phase = safety.GlobalCloseNone
		cleared.ClearProof = &safety.EmergencyClearProof{Generation: globalProof.Generation, InventoryDigest: globalProof.InventoryDigest, OwnedGraphDigest: globalProof.OwnedGraphDigest, RuntimeClosureDigest: globalProof.RuntimeClosureDigest, NginxTestPassed: true, RuntimeClosed: true}
		if err := service.emergency.Commit(service.exposure, safety.RoleGlobalCloseConvergence, authority.Sequence, cleared); err != nil {
			return err
		}
		current = cleared
	}
	next := state
	next.Revision++
	next.AuthoritySequence = current.Sequence
	next.GlobalClose = current.GlobalClose
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleGlobalCloseConvergence, state.Revision, next, safety.TransitionProof{GlobalClose: globalProof}); err != nil {
		return err
	}
	service.safetyState = &next
	return nil
}

func emergencyClearMatchesNormalFence(authority safety.EmergencyState, fence *safety.StopFence) bool {
	if authority.StopFence != nil || fence == nil || authority.ClearProof == nil || authority.ClearProof.StopFenceGeneration != authority.StopFenceSequence || !authority.ClearProof.NginxTestPassed || !authority.ClearProof.RuntimeClosed {
		return false
	}
	if fence.Kind != safety.StopFenceContraction {
		return true
	}
	return authority.ClearProof.InventoryDigest == fence.InventoryDigest && authority.ClearProof.OwnedGraphDigest == fence.OwnedGraphDigest && authority.ClearProof.StopFenceGeneration == fence.FenceGeneration
}

func (service *EmergencyService) RecoverClosed(ctx context.Context, expectedGlobal uint64, expectedInventory string) error {
	snapshot, err := service.Snapshot()
	if err != nil || snapshot.GlobalGeneration != expectedGlobal || snapshot.Inventory.Digest != expectedInventory || !snapshot.Inventory.Complete || service.safetyStore == nil || service.safetyState == nil {
		return fmt.Errorf("exact closed recovery authority is incomplete: %w", err)
	}
	authority, err := service.emergency.Authority()
	if err != nil {
		return fmt.Errorf("verified stopped emergency fence is unavailable: %w", err)
	}
	state := *service.safetyState
	if authority.StopFence == nil && state.StopFence == nil {
		return service.recoverFenceClearedGlobal(ctx, snapshot, authority, state)
	}
	emergencyFenceActive := authority.StopFence != nil && !authority.StopFence.AccessMayRemain && authority.StopFence.MasterStopped && authority.StopFence.WorkersStopped && authority.StopFence.ListenersStopped
	emergencyFenceCleared := emergencyClearMatchesNormalFence(authority, state.StopFence)
	if !emergencyFenceActive && !emergencyFenceCleared {
		return fmt.Errorf("verified stopped emergency fence is unavailable")
	}
	if state.StopFence != nil {
		if err := service.validateStopFenceOrigin(*state.StopFence); err != nil {
			return err
		}
	}
	// An emergency contraction may supersede an activation fence when the
	// activation writer was unavailable while the emergency authority was
	// being established. Keep the activation fence intact: its payload is the
	// exact origin identity required to clear it. Only a contraction fence may
	// be projected from the fixed-format emergency authority.
	if emergencyFenceActive && (state.StopFence == nil || state.StopFence.Kind == safety.StopFenceContraction) && !safety.FenceMatchesEmergency(state.StopFence, *authority.StopFence) {
		emergencyFence := authority.StopFence
		authorities := []safety.MarkerGeneration{}
		if emergencyFence.GlobalGeneration != 0 {
			authorities = append(authorities, safety.MarkerGeneration{Kind: "global_close", Generation: emergencyFence.GlobalGeneration})
		}
		if emergencyFence.ClosingGeneration != 0 {
			authorities = append(authorities, safety.MarkerGeneration{Kind: "closing", Generation: emergencyFence.ClosingGeneration})
		}
		if emergencyFence.CertificateGeneration != 0 {
			authorities = append(authorities, safety.MarkerGeneration{Kind: "certificate_expiry", Generation: emergencyFence.CertificateGeneration})
		}
		projectedState := state
		projectedState.Revision++
		projectedState.AuthoritySequence = authority.Sequence
		projectedState.GlobalClose = authority.GlobalClose
		projectedState.StopFenceSequence = authority.StopFenceSequence
		scope := safety.FenceScope{Kind: emergencyFence.ScopeKind, ResourceID: emergencyFence.ResourceID}
		projected := safety.StopFence{Kind: safety.StopFenceContraction, OriginOperation: emergencyFence.OriginOperation, Scope: scope, FenceGeneration: emergencyFence.Generation, CreatedAt: time.Unix(emergencyFence.ObservedUnix, 0).UTC(), SafetyGenerations: projectedFenceSafetyGenerations(scope, projectedState), OwnedGraphDigest: emergencyFence.OwnedGraphDigest, InventoryDigest: emergencyFence.InventoryDigest, Observation: safety.StopObservation{MasterStopped: emergencyFence.MasterStopped, WorkersStopped: emergencyFence.WorkersStopped, ListenersStopped: emergencyFence.ListenersStopped, ObservedAt: time.Unix(emergencyFence.ObservedUnix, 0).UTC()}, AccessMayRemain: emergencyFence.AccessMayRemain, Contraction: &safety.ContractionFence{Authorities: append([]safety.MarkerGeneration(nil), authorities...), OwnershipDigest: emergencyFence.OwnershipDigest, OperationRef: emergencyFence.OperationRef, SafetyIntentID: emergencyFence.SafetyIntentID, SafetyIntentGeneration: emergencyFence.SafetyIntentGeneration}}
		projectedState.StopFence = &projected
		if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleContraction, state.Revision, projectedState, safety.TransitionProof{}); err != nil {
			return fmt.Errorf("project emergency fence into normal safety: %w", err)
		}
		state = projectedState
		service.safetyState = &state
	}
	if err := service.recoverPendingNginxContraction(ctx, snapshot); err != nil {
		return err
	}
	host, err := FixedHost(snapshot.Inventory)
	if err != nil {
		return err
	}
	paths, contractErr := host.ContractDisk(ctx, snapshot.Inventory)
	_ = paths
	if contractErr != nil {
		return contractErr
	}
	if err := host.TestClosedGraph(ctx); err != nil {
		return err
	}
	runtime, err := host.Observe(ctx)
	if err != nil || closure.VerifyStopped(runtime) != nil {
		return fmt.Errorf("closed recovery runtime is not exactly stopped: %w", err)
	}
	generations := make(map[string]uint64, len(state.Resources))
	for _, resource := range state.Resources {
		generation := resource.GenerationSequence + 1
		if resource.Closing != nil {
			generation = resource.Closing.Generation
		}
		generations[resource.ResourceID] = generation
	}
	if service.normal == nil {
		return fmt.Errorf("normal recovery store is unavailable")
	}
	if err := operations.RecoverClosedInstallation(ctx, service.normal, service.exposure, generations, paths, snapshot.Inventory.Digest, state.Checksum, time.Now().UTC(), nil); err != nil {
		return err
	}
	if err := host.AcknowledgeDiskContraction(context.WithoutCancel(ctx), snapshot.Inventory); err != nil {
		return err
	}
	unpublished := make(map[string]uint64, len(generations))
	for resourceID, generation := range generations {
		unpublished[resourceID] = generation
	}
	closureDigest := snapshot.Inventory.Digest
	if state.StopFence == nil {
		return fmt.Errorf("normal stop fence is unavailable for exact recovery")
	}
	if err := service.validateStopFenceOrigin(*state.StopFence); err != nil {
		return err
	}
	withoutFence := authority
	if emergencyFenceActive {
		clearProof := &safety.EmergencyClearProof{Generation: authority.GlobalClose.Generation, StopFenceGeneration: authority.StopFence.Generation, StopFenceDigest: safety.EmergencyFenceDigest(*authority.StopFence), InventoryDigest: authority.StopFence.InventoryDigest, OwnedGraphDigest: authority.StopFence.OwnedGraphDigest, RuntimeClosureDigest: closureDigest, NginxTestPassed: true, RuntimeClosed: true}
		withoutFence.Sequence++
		withoutFence.StopFence = nil
		withoutFence.ClearProof = clearProof
		if err := service.emergency.Commit(service.exposure, safety.RoleJournalConvergence, authority.Sequence, withoutFence); err != nil {
			return err
		}
	}
	nextState := state
	nextState.Revision++
	nextState.AuthoritySequence = withoutFence.Sequence
	nextState.GlobalClose = withoutFence.GlobalClose
	nextState.StopFenceSequence = withoutFence.StopFenceSequence
	nextState.StopFence = nil
	nextState.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	closingProofs := map[string]safety.ClosingConvergenceProof{}
	for index := range nextState.Resources {
		resource := &nextState.Resources[index]
		generation := generations[resource.ResourceID]
		if resource.Closing != nil {
			generation = resource.Closing.Generation
			closingProofs[resource.ResourceID] = safety.ClosingConvergenceProof{ResourceID: resource.ResourceID, ClosingGeneration: generation, UnpublishedGeneration: generation, OwnershipDigest: resource.OwnershipDigest, RuntimeClosureDigest: snapshot.Inventory.Digest}
		}
		resource.GenerationSequence = generation
		resource.StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: generation, Reason: "recovered_closed"}
		resource.Closing, resource.ChallengePending, resource.Reactivating = nil, nil, nil
		generations[resource.ResourceID] = generation
		unpublished[resource.ResourceID] = generation
	}
	stopProof := &safety.StopFenceConvergenceProof{Kind: state.StopFence.Kind, FenceGeneration: state.StopFence.FenceGeneration, FenceDigest: safety.StopFenceDigest(*state.StopFence), InventoryDigest: state.StopFence.InventoryDigest, OwnedGraphDigest: state.StopFence.OwnedGraphDigest, RuntimeClosureDigest: closureDigest, AllChildrenExited: true, AllAppsUnpublished: true, NoAppDisk: true, WorkersDrained: true, ListenersClosed: true, RuntimeClosed: true, NginxTestPassed: true, UnpublishedGenerations: unpublished}
	if state.StopFence.Contraction != nil {
		stopProof.JournalRef = state.StopFence.Contraction.OperationRef
		stopProof.SafetyIntentID = state.StopFence.Contraction.SafetyIntentID
		stopProof.SafetyIntentGeneration = state.StopFence.Contraction.SafetyIntentGeneration
	} else if state.StopFence.IngressActivation != nil {
		stopProof.JournalRef = state.StopFence.IngressActivation.IntentRef
	} else if state.StopFence.CertificateActivation != nil {
		stopProof.JournalRef = state.StopFence.CertificateActivation.JournalRef
	}
	transitionProof := safety.TransitionProof{StopFence: stopProof, Closings: closingProofs}
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleJournalConvergence, state.Revision, nextState, transitionProof); err != nil {
		return err
	}
	state = nextState
	service.safetyState = &state
	if withoutFence.GlobalClose.Phase == safety.GlobalCloseNone {
		return nil
	}

	globalProof := &safety.GlobalConvergenceProof{Generation: withoutFence.GlobalClose.Generation, InventoryDigest: snapshot.Inventory.FullOwnershipDigest, OwnedGraphDigest: snapshot.Inventory.Digest, RuntimeClosureDigest: closureDigest, UnpublishedGenerations: unpublished, NginxTestPassed: true, RuntimeClosed: true}
	cleared := withoutFence
	cleared.Sequence++
	cleared.GlobalClose.Phase = safety.GlobalCloseNone
	cleared.ClearProof = &safety.EmergencyClearProof{Generation: globalProof.Generation, InventoryDigest: globalProof.InventoryDigest, OwnedGraphDigest: globalProof.OwnedGraphDigest, RuntimeClosureDigest: globalProof.RuntimeClosureDigest, NginxTestPassed: true, RuntimeClosed: true}
	if err := service.emergency.Commit(service.exposure, safety.RoleGlobalCloseConvergence, withoutFence.Sequence, cleared); err != nil {
		return err
	}
	normalCleared := state
	normalCleared.Revision++
	normalCleared.AuthoritySequence = cleared.Sequence
	normalCleared.GlobalClose = cleared.GlobalClose
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleGlobalCloseConvergence, state.Revision, normalCleared, safety.TransitionProof{GlobalClose: globalProof}); err != nil {
		return err
	}
	service.safetyState = &normalCleared
	return nil
}

func (service *EmergencyService) Run(ctx context.Context, expectedGlobal uint64, expectedInventory string) (Result, error) {
	return service.run(ctx, expectedGlobal, expectedInventory, child.ProfileSystemctlNginxStop, 0)
}

func (service *EmergencyService) RunGuardFailure(ctx context.Context, expectedGlobal uint64, expectedInventory string, guardPID int) (Result, error) {
	if guardPID <= 1 {
		return Result{}, fmt.Errorf("guard fallback PID authority is invalid")
	}
	return service.run(ctx, expectedGlobal, expectedInventory, child.ProfileNginxQuitSignal, guardPID)
}

func (service *EmergencyService) run(ctx context.Context, expectedGlobal uint64, expectedInventory string, stopProfile child.ProfileID, controlPID int) (Result, error) {
	snapshot, err := service.Snapshot()
	if err != nil {
		return Result{}, err
	}
	if snapshot.GlobalGeneration != expectedGlobal || snapshot.Inventory.Digest != expectedInventory {
		return Result{}, fmt.Errorf("emergency Plan authority changed")
	}
	if stopProfile == child.ProfileNginxQuitSignal {
		forced, err := closure.ForceUncertain(snapshot.Inventory, "guard_failure", "shared_ingress_stop_required")
		if err != nil {
			return Result{}, err
		}
		snapshot.Inventory = forced
	}
	generation := "unknown"
	if service.graph != nil {
		generation = service.graph.GenerationID
	}
	observer := closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: service.paths.PIDPath, ControlPID: controlPID, Generation: generation, OwnedListeners: inventoryListeners(snapshot.Inventory)}
	certificateFingerprint := "sha256:" + strings.Repeat("0", 64)
	if service.graph != nil {
		certificateFingerprint = service.graph.DefaultCertFingerprint
	}
	host := Host{Launcher: service.launcher, Paths: service.paths, Owner: filetxn.Owner{UID: 0, GID: 0}, Observer: observer, Probe: closure.NegativeProbe{TLSAddress: "127.0.0.1:443", DefaultCertFingerprint: certificateFingerprint, AuditPath: service.paths.AuditPath}, StopProfile: stopProfile}
	return (Engine{Authority: service, Runtime: host}).Run(ctx, snapshot.Inventory)
}

func (service *EmergencyService) PersistClosing(_ context.Context, inventory closure.Inventory) error {
	current, err := service.emergency.Authority()
	if err != nil {
		return err
	}
	if current.GlobalClose.Phase != safety.GlobalCloseNone {
		service.globalCommitted = true
		return nil
	}
	reservationOutstanding := current.StopFence == nil && current.ReservedStopFenceKind != "" && service.safetyState != nil && current.StopFenceSequence > service.safetyState.StopFenceSequence
	if current.StopFence != nil || reservationOutstanding || service.safetyState != nil && service.safetyState.StopFence != nil {
		return fmt.Errorf("existing stop fence must converge before global close")
	}
	next := current
	next.Sequence++
	next.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseEmergency, Generation: current.GlobalClose.Generation + 1}
	if err := service.emergency.Commit(service.exposure, safety.RoleContraction, current.Sequence, next); err != nil {
		return err
	}
	service.globalCommitted = true
	if service.safetyStore == nil || service.safetyState == nil || !inventory.Complete {
		return nil
	}
	normalNext := *service.safetyState
	normalNext.Revision++
	normalNext.AuthoritySequence = next.Sequence
	normalNext.GlobalClose = next.GlobalClose
	if _, err := service.safetyStore.Commit(context.Background(), service.exposure, safety.RoleContraction, service.safetyState.Revision, normalNext, safety.TransitionProof{}); err != nil {
		return authorityCommittedError{err: fmt.Errorf("emergency authority committed but normal projection failed: %w", err)}
	}
	service.safetyState = &normalNext
	return nil
}

func supportedContractionFenceOrigin(operation operations.Type, scope safety.FenceScope) bool {
	if operation == operations.Publish {
		return scope.Kind == "app" && scope.ResourceID != ""
	}
	return operation == operations.CloseAll || operation == operations.Unpublish || operation == operations.CertificateExpiry
}

func (service *EmergencyService) validateStopFenceOrigin(fence safety.StopFence) error {
	if fence.IngressActivation != nil {
		expected := operations.Publish
		if fence.OriginOperation == "headscale_deploy" && fence.Scope.Kind == "headscale" {
			expected = operations.HeadscaleDeploy
		} else if fence.OriginOperation != "publish" || fence.Scope.Kind != "app" {
			return fmt.Errorf("ingress activation fence operation is unsupported")
		}
		return service.validateIntentFenceOrigin(fence.IngressActivation.IntentRef, fence.Scope, "ingress activation", expected)
	}
	if fence.CertificateActivation != nil {
		if service.normal == nil {
			return fmt.Errorf("certificate activation journal authority is unavailable")
		}
		document, err := service.normal.Read()
		if err != nil {
			return err
		}
		journalKey := fence.CertificateActivation.JournalRef
		if !strings.HasPrefix(journalKey, "journals/") {
			journalKey = "journals/" + journalKey
		}
		raw, present := document.Entries[journalKey]
		var journal operations.JournalRecord
		pointerDigest := func(value string) string {
			sum := sha256.Sum256([]byte(value))
			return "sha256:" + hex.EncodeToString(sum[:])
		}
		if !present || json.Unmarshal(raw, &journal) != nil || journal.ID == "" || "journals/"+journal.ID != journalKey || journal.Certificate == nil || journal.Kind != operations.JournalCertificateActivation || journal.Phase != operations.JournalActive && journal.Phase != operations.JournalTerminal || journal.Certificate.PriorGeneration != 0 && pointerDigest(journal.Certificate.PriorPointer) != fence.CertificateActivation.PriorPointer || pointerDigest(journal.Certificate.CandidatePointer) != fence.CertificateActivation.CandidatePointer {
			return fmt.Errorf("certificate activation fence journal reference is stale or invalid")
		}
		if fence.Scope.Kind == "app" && (journal.Target != "resource/"+fence.Scope.ResourceID || journal.Operation != operations.Publish && journal.Operation != operations.CertificateRenew) || fence.Scope.Kind == "headscale" && (!strings.HasPrefix(journal.Target, "headscale/") || journal.Operation != operations.CertificateRenew) {
			return fmt.Errorf("certificate activation fence journal target changed")
		}
		return nil
	}
	if fence.Contraction == nil {
		return fmt.Errorf("stop fence origin payload is missing")
	}
	origin := fence.Contraction
	if origin.OperationRef != "" {
		expected := operations.Type(fence.OriginOperation)
		if !supportedContractionFenceOrigin(expected, fence.Scope) {
			return fmt.Errorf("contraction fence operation is unsupported")
		}
		return service.validateIntentFenceOrigin(origin.OperationRef, fence.Scope, "contraction", expected)
	}
	if origin.SafetyIntentID == "emergency_close_all" && origin.SafetyIntentGeneration == service.safetyState.GlobalClose.Generation {
		return nil
	}
	if origin.SafetyIntentID == "headscale_certificate_expiry" && service.safetyState.Headscale.CertificateExpiry != nil && origin.SafetyIntentGeneration == service.safetyState.Headscale.CertificateExpiry.Generation {
		return nil
	}
	return fmt.Errorf("contraction fence safety-intent reference is stale or invalid")
}

func (service *EmergencyService) validateIntentFenceOrigin(reference string, scope safety.FenceScope, kind string, expected ...operations.Type) error {
	if service.normal == nil {
		return fmt.Errorf("%s operation reference is unavailable", kind)
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	jobID, ok := strings.CutPrefix(reference, "intent/")
	if !ok {
		planID, planRef := strings.CutPrefix(reference, "plan_")
		if !planRef || planID == "" {
			return fmt.Errorf("%s fence operation reference is invalid", kind)
		}
		rawPlan, present := document.Entries["plans/"+reference]
		var plan plans.Plan
		if !present || json.Unmarshal(rawPlan, &plan) != nil || plan.ID != reference || plan.ConsumedByJob == "" {
			return fmt.Errorf("%s fence Plan reference is stale or invalid", kind)
		}
		jobID = plan.ConsumedByJob
	}
	raw, present := document.Entries["intents/"+jobID]
	var intent operations.Reservation
	if !present || json.Unmarshal(raw, &intent) != nil || intent.JobID != jobID || intent.Phase == operations.PhaseReserved {
		return fmt.Errorf("%s fence operation reference is stale or invalid", kind)
	}
	if len(expected) != 0 && intent.Operation != expected[0] {
		return fmt.Errorf("%s fence operation changed", kind)
	}
	if scope.Kind == "app" && intent.Target != "resource/"+scope.ResourceID || scope.Kind == "headscale" && !strings.HasPrefix(intent.Target, "headscale/") {
		return fmt.Errorf("%s fence operation target changed", kind)
	}
	return nil
}

func (service *EmergencyService) CommitUnpublished(context.Context, closure.Inventory) error {
	// State-independent emergency contraction must not fabricate normal jobs or
	// state. Exact recovery later projects the emergency generation.
	return nil
}

func (service *EmergencyService) PersistStopFence(_ context.Context, inventory closure.Inventory) error {
	current, err := service.emergency.Authority()
	if err != nil {
		return err
	}
	if current.StopFence != nil {
		return nil
	}
	if service.safetyState != nil && service.safetyState.StopFence != nil {
		return fmt.Errorf("normal stop fence must converge before emergency fence allocation")
	}
	if current.GlobalClose.Phase == safety.GlobalCloseNone {
		return fmt.Errorf("stop fence requires prior global close authority")
	}
	fence := safety.EmergencyStopFence{Kind: safety.StopFenceContraction, OriginOperation: "emergency_close_all", ScopeKind: "installation", Generation: current.StopFenceSequence + 1, GlobalGeneration: current.GlobalClose.Generation, OwnershipDigest: inventory.FullOwnershipDigest, OwnedGraphDigest: inventory.Digest, InventoryDigest: inventory.FullOwnershipDigest, ObservedUnix: time.Now().Unix(), SafetyIntentID: "emergency_close_all", SafetyIntentGeneration: current.GlobalClose.Generation, AccessMayRemain: true}
	next := current
	next.Sequence++
	next.StopFenceSequence++
	next.ReservedStopFenceKind = safety.StopFenceContraction
	next.ReservedStopFenceDigest = ""
	next.StopFence = &fence
	return service.emergency.Commit(service.exposure, safety.RoleContraction, current.Sequence, next)
}

func (service *EmergencyService) stopGoAccess(ctx context.Context, inventory closure.Inventory) error {
	host, err := goaccessruntime.NewFixedHost()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, identity := range inventory.Identities {
		if identity.Kind != closure.IdentityOwnershipPath {
			continue
		}
		prefix := "service:/etc/systemd/system/lanpanel-goaccess-" + identity.ResourceID + "-"
		if !strings.HasPrefix(identity.Value, prefix) || !strings.HasSuffix(identity.Value, ".service") {
			continue
		}
		generationText := strings.TrimSuffix(strings.TrimPrefix(identity.Value, prefix), ".service")
		generation, parseErr := strconv.ParseUint(generationText, 10, 64)
		if parseErr != nil || generation == 0 {
			return fmt.Errorf("emergency GoAccess generation identity invalid")
		}
		key := fmt.Sprintf("%s:%d", identity.ResourceID, generation)
		if seen[key] {
			continue
		}
		seen[key] = true
		if stopErr := host.EnsureStopped(ctx, identity.ResourceID, generation); stopErr != nil {
			err = errors.Join(err, stopErr)
		}
	}
	discovered, discoverErr := goaccessruntime.DiscoverServiceGenerations(ctx)
	if discoverErr != nil {
		return errors.Join(err, discoverErr)
	}
	for _, item := range discovered {
		key := fmt.Sprintf("%s:%d", item.ResourceID, item.Generation)
		if !seen[key] {
			err = errors.Join(err, fmt.Errorf("unowned GoAccess service generation discovered: %s", key))
		}
	}
	return err
}

func (service *EmergencyService) FinalizeClosure(ctx context.Context, inventory closure.Inventory, closureDigest string, modifiedPaths []string) error {
	if err := service.stopGoAccess(ctx, inventory); err != nil {
		return err
	}
	current, err := service.emergency.Authority()
	if err != nil {
		return err
	}
	if current.StopFence != nil {
		return fmt.Errorf("durable emergency stop fence still requires exact recovery")
	}
	if current.GlobalClose.Phase == safety.GlobalCloseNone || service.normal == nil || service.safetyStore == nil || service.safetyState == nil || !inventory.Complete {
		return fmt.Errorf("emergency closure cannot finalize incomplete normal projection")
	}
	state := *service.safetyState
	generations := make(map[string]uint64, len(state.Resources))
	for _, resource := range state.Resources {
		generations[resource.ResourceID] = resource.GenerationSequence + 1
	}
	if err := operations.RecoverClosedInstallation(ctx, service.normal, service.exposure, generations, modifiedPaths, closureDigest, state.Checksum, time.Now().UTC(), nil); err != nil {
		return err
	}
	host := Host{Paths: service.paths, Owner: filetxn.Owner{UID: 0, GID: 0}}
	if err := host.AcknowledgeDiskContraction(context.WithoutCancel(ctx), inventory); err != nil {
		return err
	}
	state.Revision++
	state.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	proofs := map[string]safety.ClosingConvergenceProof{}
	for index := range state.Resources {
		resource := &state.Resources[index]
		generation := generations[resource.ResourceID]
		if resource.Closing != nil {
			proofs[resource.ResourceID] = safety.ClosingConvergenceProof{ResourceID: resource.ResourceID, ClosingGeneration: resource.Closing.Generation, UnpublishedGeneration: resource.Closing.Generation, OwnershipDigest: resource.OwnershipDigest, RuntimeClosureDigest: closureDigest}
			generation = resource.Closing.Generation
		}
		resource.GenerationSequence = generation
		resource.Closing = nil
		resource.StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: generation, Reason: "closed"}
		generations[resource.ResourceID] = generation
	}
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleContraction, service.safetyState.Revision, state, safety.TransitionProof{Closings: proofs}); err != nil {
		return err
	}
	ownership := map[string]string{}
	for _, resource := range state.Resources {
		ownership[resource.ResourceID] = resource.OwnershipDigest
	}
	globalProof := &safety.GlobalConvergenceProof{Generation: current.GlobalClose.Generation, InventoryDigest: safety.OwnershipInventoryDigest(ownership), OwnedGraphDigest: inventory.Digest, RuntimeClosureDigest: closureDigest, UnpublishedGenerations: generations, NginxTestPassed: true, RuntimeClosed: true}
	next := current
	next.Sequence++
	next.GlobalClose.Phase = safety.GlobalCloseNone
	next.ClearProof = &safety.EmergencyClearProof{Generation: globalProof.Generation, InventoryDigest: globalProof.InventoryDigest, OwnedGraphDigest: globalProof.OwnedGraphDigest, RuntimeClosureDigest: closureDigest, NginxTestPassed: true, RuntimeClosed: true}
	if err := service.emergency.Commit(service.exposure, safety.RoleGlobalCloseConvergence, current.Sequence, next); err != nil {
		return err
	}
	normalNext := state
	normalNext.Revision++
	normalNext.AuthoritySequence = next.Sequence
	normalNext.GlobalClose = next.GlobalClose
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleGlobalCloseConvergence, state.Revision, normalNext, safety.TransitionProof{GlobalClose: globalProof}); err != nil {
		return authorityCommittedError{err: err}
	}
	service.safetyState = &normalNext
	return nil
}

func (service *EmergencyService) UpdateStopObservation(_ context.Context, snapshot closure.RuntimeSnapshot, verified bool) error {
	current, err := service.emergency.Authority()
	if err != nil || current.StopFence == nil {
		return errors.Join(err, fmt.Errorf("emergency stop fence is missing"))
	}
	fence := *current.StopFence
	fence.MasterStopped = snapshot.Master == nil
	fence.WorkersStopped = len(snapshot.Workers) == 0
	fence.ListenersStopped = len(snapshot.Listeners) == 0
	fence.ObservedUnix = snapshot.ObservedAt.Unix()
	fence.AccessMayRemain = !verified
	next := current
	next.Sequence++
	next.StopFence = &fence
	return service.emergency.Commit(service.exposure, safety.RoleContraction, current.Sequence, next)
}

func (service *EmergencyService) Close() error {
	if service == nil || service.closed {
		return nil
	}
	service.closed = true
	var errs []error
	if service.normal != nil {
		errs = append(errs, service.normal.Close())
	}
	if service.safetyStore != nil {
		errs = append(errs, service.safetyStore.Close())
	}
	if service.emergency != nil {
		errs = append(errs, service.emergency.Close())
	}
	if service.ownership != nil {
		errs = append(errs, service.ownership.Close())
	}
	if service.exposure != nil {
		errs = append(errs, service.exposure.Release())
	}
	if service.manager != nil {
		errs = append(errs, service.manager.Close())
	}
	return errors.Join(errs...)
}

func inventoryListeners(inventory closure.Inventory) []string {
	result := append([]string(nil), inventory.FallbackListeners...)
	for _, identity := range inventory.Identities {
		if identity.Kind == closure.IdentityListener || identity.Kind == closure.IdentityOwnershipListener {
			result = append(result, identity.Value)
		}
	}
	return result
}
