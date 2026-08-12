//go:build linux

package contraction

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
	"os"
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
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: "/var/lib/lanpanel/ownership", StagingPath: "/var/lib/lanpanel/ownership/.filetxn", RecordsPath: "/var/lib/lanpanel/ownership/records", Owner: owner, Policy: ownership.Policy{ManagedRoots: []string{"/etc/lanpanel", "/var/lib/lanpanel"}}, LockAuthority: manager.Authority()})
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

func (service *EmergencyService) RecoverClosed(ctx context.Context, expectedGlobal uint64, expectedInventory string) error {
	snapshot, err := service.Snapshot()
	if err != nil || snapshot.GlobalGeneration != expectedGlobal || snapshot.Inventory.Digest != expectedInventory || !snapshot.Inventory.Complete || service.safetyStore == nil || service.safetyState == nil {
		return fmt.Errorf("exact closed recovery authority is incomplete: %w", err)
	}
	authority, err := service.emergency.Authority()
	if err != nil || authority.GlobalClose.Phase == safety.GlobalCloseNone || authority.StopFence == nil || authority.StopFence.AccessMayRemain || !authority.StopFence.MasterStopped || !authority.StopFence.WorkersStopped || !authority.StopFence.ListenersStopped {
		return fmt.Errorf("verified stopped emergency fence is unavailable: %w", err)
	}
	state := *service.safetyState
	if !safety.FenceMatchesEmergency(state.StopFence, *authority.StopFence) {
		emergencyFence := authority.StopFence
		authorities := []safety.MarkerGeneration{}
		if emergencyFence.GlobalGeneration != 0 {
			authorities = append(authorities, safety.MarkerGeneration{Kind: "global_close", Generation: emergencyFence.GlobalGeneration})
		}
		if emergencyFence.ClosingGeneration != 0 {
			authorities = append(authorities, safety.MarkerGeneration{Kind: "closing", Generation: emergencyFence.ClosingGeneration})
		}
		projected := safety.StopFence{Kind: safety.StopFenceContraction, OriginOperation: emergencyFence.OriginOperation, Scope: safety.FenceScope{Kind: emergencyFence.ScopeKind, ResourceID: emergencyFence.ResourceID}, FenceGeneration: emergencyFence.Generation, CreatedAt: time.Unix(emergencyFence.ObservedUnix, 0).UTC(), SafetyGenerations: append([]safety.MarkerGeneration(nil), authorities...), OwnedGraphDigest: emergencyFence.OwnedGraphDigest, InventoryDigest: emergencyFence.InventoryDigest, Observation: safety.StopObservation{MasterStopped: emergencyFence.MasterStopped, WorkersStopped: emergencyFence.WorkersStopped, ListenersStopped: emergencyFence.ListenersStopped, ObservedAt: time.Unix(emergencyFence.ObservedUnix, 0).UTC()}, AccessMayRemain: emergencyFence.AccessMayRemain, Contraction: &safety.ContractionFence{Authorities: append([]safety.MarkerGeneration(nil), authorities...), OwnershipDigest: emergencyFence.OwnershipDigest}}
		projectedState := state
		projectedState.Revision++
		projectedState.AuthoritySequence = authority.Sequence
		projectedState.GlobalClose = authority.GlobalClose
		projectedState.StopFenceSequence = authority.StopFenceSequence
		projectedState.StopFence = &projected
		if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleContraction, state.Revision, projectedState, safety.TransitionProof{}); err != nil {
			return fmt.Errorf("project emergency fence into normal safety: %w", err)
		}
		state = projectedState
		service.safetyState = &state
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
	if err := operations.RecoverClosedInstallation(ctx, service.normal, service.exposure, generations, snapshot.Inventory.Digest, state.Checksum, time.Now().UTC(), nil); err != nil {
		return err
	}
	state.Revision++
	state.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	unpublished := map[string]uint64{}
	for index := range state.Resources {
		resource := &state.Resources[index]
		generation := generations[resource.ResourceID]
		if resource.Closing != nil {
			generation = resource.Closing.Generation
		}
		resource.GenerationSequence = generation
		resource.StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: generation, Reason: "recovered_closed"}
		resource.Closing, resource.ChallengePending, resource.Reactivating = nil, nil, nil
		generations[resource.ResourceID] = generation
		unpublished[resource.ResourceID] = generation
	}
	closingProofs := map[string]safety.ClosingConvergenceProof{}
	for _, before := range service.safetyState.Resources {
		if before.Closing != nil {
			closingProofs[before.ResourceID] = safety.ClosingConvergenceProof{ResourceID: before.ResourceID, ClosingGeneration: before.Closing.Generation, UnpublishedGeneration: before.Closing.Generation, OwnershipDigest: before.OwnershipDigest, RuntimeClosureDigest: snapshot.Inventory.Digest}
		}
	}
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleContraction, service.safetyState.Revision, state, safety.TransitionProof{Closings: closingProofs}); err != nil {
		return err
	}
	service.safetyState = &state
	closureDigest := snapshot.Inventory.Digest
	if state.StopFence == nil {
		return fmt.Errorf("normal stop fence is unavailable for exact recovery")
	}
	clearProof := &safety.EmergencyClearProof{Generation: authority.GlobalClose.Generation, StopFenceGeneration: authority.StopFence.Generation, StopFenceDigest: safety.EmergencyFenceDigest(*authority.StopFence), InventoryDigest: snapshot.Inventory.FullOwnershipDigest, OwnedGraphDigest: snapshot.Inventory.Digest, RuntimeClosureDigest: closureDigest, NginxTestPassed: true, RuntimeClosed: true}
	withoutFence := authority
	withoutFence.Sequence++
	withoutFence.StopFence = nil
	withoutFence.ClearProof = clearProof
	if err := service.emergency.Commit(service.exposure, safety.RoleJournalConvergence, authority.Sequence, withoutFence); err != nil {
		return err
	}
	normalWithoutFence := state
	normalWithoutFence.Revision++
	normalWithoutFence.AuthoritySequence = withoutFence.Sequence
	normalWithoutFence.StopFence = nil
	stopProof := &safety.StopFenceConvergenceProof{Kind: state.StopFence.Kind, FenceGeneration: state.StopFence.FenceGeneration, FenceDigest: safety.StopFenceDigest(*state.StopFence), InventoryDigest: state.StopFence.InventoryDigest, OwnedGraphDigest: state.StopFence.OwnedGraphDigest, RuntimeClosureDigest: closureDigest, AllChildrenExited: true, AllAppsUnpublished: true, NoAppDisk: true, WorkersDrained: true, ListenersClosed: true, RuntimeClosed: true, NginxTestPassed: true, UnpublishedGenerations: unpublished}
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleJournalConvergence, state.Revision, normalWithoutFence, safety.TransitionProof{StopFence: stopProof}); err != nil {
		return err
	}
	globalProof := &safety.GlobalConvergenceProof{Generation: withoutFence.GlobalClose.Generation, InventoryDigest: snapshot.Inventory.FullOwnershipDigest, OwnedGraphDigest: snapshot.Inventory.Digest, RuntimeClosureDigest: closureDigest, UnpublishedGenerations: unpublished, NginxTestPassed: true, RuntimeClosed: true}
	cleared := withoutFence
	cleared.Sequence++
	cleared.GlobalClose.Phase = safety.GlobalCloseNone
	if err := service.emergency.Commit(service.exposure, safety.RoleGlobalCloseConvergence, withoutFence.Sequence, cleared); err != nil {
		return err
	}
	normalCleared := normalWithoutFence
	normalCleared.Revision++
	normalCleared.AuthoritySequence = cleared.Sequence
	normalCleared.GlobalClose = cleared.GlobalClose
	if _, err := service.safetyStore.Commit(ctx, service.exposure, safety.RoleGlobalCloseConvergence, normalWithoutFence.Revision, normalCleared, safety.TransitionProof{GlobalClose: globalProof}); err != nil {
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
	if current.GlobalClose.Phase == safety.GlobalCloseNone {
		return fmt.Errorf("stop fence requires prior global close authority")
	}
	fence := safety.EmergencyStopFence{Kind: safety.StopFenceContraction, OriginOperation: "emergency_close_all", ScopeKind: "installation", Generation: current.StopFenceSequence + 1, GlobalGeneration: current.GlobalClose.Generation, OwnershipDigest: inventory.FullOwnershipDigest, OwnedGraphDigest: inventory.Digest, InventoryDigest: inventory.FullOwnershipDigest, ObservedUnix: time.Now().Unix(), AccessMayRemain: true}
	next := current
	next.Sequence++
	next.StopFenceSequence++
	next.ReservedStopFenceKind = safety.StopFenceContraction
	next.ReservedStopFenceDigest = ""
	next.StopFence = &fence
	return service.emergency.Commit(service.exposure, safety.RoleContraction, current.Sequence, next)
}
func (service *EmergencyService) FinalizeClosure(ctx context.Context, inventory closure.Inventory, closureDigest string) error {
	current, err := service.emergency.Authority()
	if err != nil || current.GlobalClose.Phase == safety.GlobalCloseNone || current.StopFence != nil || service.normal == nil || service.safetyStore == nil || service.safetyState == nil || !inventory.Complete {
		return nil
	}
	state := *service.safetyState
	generations := make(map[string]uint64, len(state.Resources))
	for _, resource := range state.Resources {
		generations[resource.ResourceID] = resource.GenerationSequence + 1
	}
	if err := operations.RecoverClosedInstallation(ctx, service.normal, service.exposure, generations, closureDigest, state.Checksum, time.Now().UTC(), nil); err != nil {
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
