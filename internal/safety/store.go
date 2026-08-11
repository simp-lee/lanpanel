package safety

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

const maxStateBytes = 2 << 20

var ErrSafetyStateMissing = errors.New("independent safety state is missing")

type StoreConfig struct {
	RootPath    string
	StagingPath string
	StatePath   string
	Owner       filetxn.Owner
	Emergency   *EmergencyStore
}

type ReactivationConvergenceProof struct {
	ResourceID           string
	PlanID               string
	Generation           uint64
	CandidateDigest      string
	CandidateBundle      string
	RuntimeClosureDigest string
}

type ClosingConvergenceProof struct {
	ResourceID            string
	ClosingGeneration     uint64
	UnpublishedGeneration uint64
	OwnershipDigest       string
	RuntimeClosureDigest  string
}

type HeadscaleConvergenceProof struct {
	PlanID                string
	Generation            uint64
	ControlGeneration     uint64
	CertificateGeneration uint64
	CandidateDigest       string
	CandidateBundle       string
	RuntimeClosureDigest  string
}

type DeleteConvergenceProof struct {
	ResourceID           string
	TombstoneRef         string
	OwnershipDigest      string
	RuntimeClosureDigest string
}

type GlobalConvergenceProof struct {
	Generation             uint64
	InventoryDigest        string
	OwnedGraphDigest       string
	RuntimeClosureDigest   string
	UnpublishedGenerations map[string]uint64
	NginxTestPassed        bool
	RuntimeClosed          bool
}

type StopFenceConvergenceProof struct {
	Kind                   StopFenceKind
	FenceGeneration        uint64
	JournalRef             string
	InventoryDigest        string
	OwnedGraphDigest       string
	RuntimeClosureDigest   string
	AllChildrenExited      bool
	AllAppsUnpublished     bool
	NginxTestPassed        bool
	UnpublishedGenerations map[string]uint64
}

type TransitionProof struct {
	Reactivation *ReactivationConvergenceProof
	Headscale    *HeadscaleConvergenceProof
	Closing      *ClosingConvergenceProof
	Delete       *DeleteConvergenceProof
	GlobalClose  *GlobalConvergenceProof
	StopFence    *StopFenceConvergenceProof
}

type Store struct {
	config   StoreConfig
	txn      *filetxn.Store
	rootFD   int
	rootStat unix.Stat_t
}

func OpenStore(config StoreConfig) (*Store, error) {
	if err := validateStoreConfig(config); err != nil {
		return nil, err
	}
	directories := filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{config.Owner}, AllowedMode: 0o700}
	rootFD, rootStat, err := openSafetyRoot(config)
	if err != nil {
		return nil, err
	}
	txn, err := filetxn.Open(filetxn.Config{
		RootPath: config.RootPath, Root: filetxn.Metadata{Owner: config.Owner, Mode: 0o700},
		StagingPath: config.StagingPath, Staging: filetxn.Metadata{Owner: config.Owner, Mode: 0o700}, StagingParents: directories,
	}, filetxn.Options{})
	if err != nil {
		_ = unix.Close(rootFD)
		return nil, err
	}
	return &Store{config: config, txn: txn, rootFD: rootFD, rootStat: rootStat}, nil
}

func (store *Store) Close() error { return errors.Join(store.txn.Close(), unix.Close(store.rootFD)) }

func (store *Store) Read() (State, error) { return store.read(true) }

func (store *Store) read(requireAuthority bool) (State, error) {
	if err := store.revalidateRoot(); err != nil {
		return State{}, err
	}
	fd, err := unix.Openat2(store.rootFD, filepath.Base(store.config.StatePath), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if errors.Is(err, unix.ENOENT) {
		return State{}, ErrSafetyStateMissing
	}
	if err != nil {
		return State{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return State{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != store.config.Owner.UID || stat.Gid != store.config.Owner.GID || stat.Nlink != 1 || stat.Size > maxStateBytes {
		_ = unix.Close(fd)
		return State{}, fmt.Errorf("independent safety state has unsafe type, owner, mode, links, or size")
	}
	file := os.NewFile(uintptr(fd), filepath.Base(store.config.StatePath))
	if file == nil {
		_ = unix.Close(fd)
		return State{}, fmt.Errorf("wrap independent safety state descriptor")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes+1))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode independent safety state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, fmt.Errorf("independent safety state contains trailing data")
	}
	if err := Validate(state); err != nil {
		return State{}, err
	}
	checksum := state.Checksum
	state.Checksum = ""
	expected, err := stateChecksum(state)
	if err != nil {
		return State{}, err
	}
	if checksum != expected {
		return State{}, fmt.Errorf("independent safety state checksum mismatch")
	}
	state.Checksum = checksum
	if requireAuthority {
		authority, err := store.config.Emergency.Authority()
		if err != nil {
			return State{}, err
		}
		if err := matchAuthority(state, authority); err != nil {
			return State{}, err
		}
	}
	return state, nil
}

func (store *Store) Initialize(ctx context.Context, lease *locks.Lease) (filetxn.Result, error) {
	if lease == nil || lease.Kind() != locks.Exposure || lease.Validate() != nil {
		return filetxn.Result{}, fmt.Errorf("safety initialization requires the shared exposure lock")
	}
	authority, err := store.config.Emergency.Authority()
	if err != nil {
		return filetxn.Result{}, err
	}
	if authority.NormalInitialized {
		return filetxn.Result{}, fmt.Errorf("normal safety state was already initialized; missing state requires recovery")
	}
	if authority.StopFence != nil || authority.GlobalClose.Phase != GlobalCloseNone {
		return filetxn.Result{}, fmt.Errorf("cannot initialize normal safety state while emergency authority is active")
	}
	nextAuthority := authority
	nextAuthority.Sequence++
	nextAuthority.NormalInitialized = true
	if err := store.config.Emergency.Commit(lease, RoleBootstrap, authority.Sequence, nextAuthority); err != nil {
		return filetxn.Result{}, err
	}
	state := EmptyState()
	state.AuthoritySequence = nextAuthority.Sequence
	state.GlobalClose = nextAuthority.GlobalClose
	return store.persist(ctx, state, filetxn.CreateOnly)
}

func (store *Store) Commit(ctx context.Context, lease *locks.Lease, role ClearRole, expectedRevision uint64, next State, proof TransitionProof) (filetxn.Result, error) {
	if lease == nil || lease.Kind() != locks.Exposure || lease.Validate() != nil {
		return filetxn.Result{}, fmt.Errorf("safety commit requires the shared exposure lock")
	}
	if !validRole(role) {
		return filetxn.Result{}, fmt.Errorf("safety writer role %q is unauthorized", role)
	}
	current, err := store.read(false)
	if err != nil {
		return filetxn.Result{}, err
	}
	if current.Revision != expectedRevision || next.Revision != expectedRevision+1 {
		return filetxn.Result{}, fmt.Errorf("safety revision changed: current=%d expected=%d next=%d", current.Revision, expectedRevision, next.Revision)
	}
	authority, err := store.config.Emergency.Authority()
	if err != nil {
		return filetxn.Result{}, err
	}
	if next.AuthoritySequence != authority.Sequence || next.GlobalClose != authority.GlobalClose {
		return filetxn.Result{}, fmt.Errorf("normal safety state does not bind the current emergency generation authority")
	}
	if authority.StopFence != nil && !normalFenceMatchesEmergency(next.StopFence, *authority.StopFence) {
		return filetxn.Result{}, fmt.Errorf("normal safety state omits or mismatches the current emergency stop authority")
	}
	if current.GlobalClose.Phase != GlobalCloseNone && next.GlobalClose.Phase == GlobalCloseNone && !globalProofMatchesEmergency(proof.GlobalClose, authority.ClearProof) {
		return filetxn.Result{}, fmt.Errorf("normal global clear proof does not match emergency authority")
	}
	next.SchemaVersion = SchemaVersion
	next.Resources = canonicalResources(next.Resources)
	next.Checksum = ""
	if err := Validate(next); err != nil {
		return filetxn.Result{}, err
	}
	if err := validateTransition(role, current, next, proof); err != nil {
		return filetxn.Result{}, err
	}
	return store.persist(ctx, next, filetxn.ReplaceOnly)
}

func (store *Store) persist(ctx context.Context, state State, disposition filetxn.Disposition) (filetxn.Result, error) {
	checksum, err := stateChecksum(state)
	if err != nil {
		return filetxn.Result{}, err
	}
	state.Checksum = checksum
	data, err := json.Marshal(state)
	if err != nil {
		return filetxn.Result{}, err
	}
	data = append(data, '\n')
	metadata := filetxn.Metadata{Owner: store.config.Owner, Mode: 0o600}
	return store.txn.Put(ctx, filetxn.Request{Path: store.config.StatePath, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{store.config.Owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: maxStateBytes}, data, disposition)
}

func matchAuthority(state State, authority EmergencyState) error {
	if state.AuthoritySequence != authority.Sequence || state.GlobalClose != authority.GlobalClose {
		return fmt.Errorf("normal and emergency safety authority are one-sided")
	}
	if authority.StopFence != nil && !normalFenceMatchesEmergency(state.StopFence, *authority.StopFence) {
		return fmt.Errorf("normal safety state omits or mismatches emergency stop authority")
	}
	return nil
}

func globalProofMatchesEmergency(normal *GlobalConvergenceProof, emergency *EmergencyClearProof) bool {
	return normal != nil && emergency != nil && normal.Generation == emergency.Generation && normal.InventoryDigest == emergency.InventoryDigest && normal.OwnedGraphDigest == emergency.OwnedGraphDigest && normal.RuntimeClosureDigest == emergency.RuntimeClosureDigest && normal.NginxTestPassed == emergency.NginxTestPassed && normal.RuntimeClosed == emergency.RuntimeClosed
}

func normalFenceMatchesEmergency(normal *StopFence, emergency EmergencyStopFence) bool {
	if normal == nil || normal.Kind != StopFenceContraction || normal.Contraction == nil {
		return false
	}
	if normal.OriginOperation != emergency.OriginOperation || normal.Scope.Kind != emergency.ScopeKind || normal.Scope.ResourceID != emergency.ResourceID || normal.FenceGeneration != emergency.Generation || normal.OwnedGraphDigest != emergency.OwnedGraphDigest || normal.InventoryDigest != emergency.InventoryDigest || normal.Contraction.OwnershipDigest != emergency.OwnershipDigest || normal.AccessMayRemain != emergency.AccessMayRemain || normal.Observation.MasterStopped != emergency.MasterStopped || normal.Observation.WorkersStopped != emergency.WorkersStopped || normal.Observation.ListenersStopped != emergency.ListenersStopped || normal.Observation.ObservedAt.Unix() != emergency.ObservedUnix {
		return false
	}
	want := map[string]uint64{}
	if emergency.GlobalGeneration != 0 {
		want["global_close"] = emergency.GlobalGeneration
	}
	if emergency.ClosingGeneration != 0 {
		want["closing"] = emergency.ClosingGeneration
	}
	if emergency.CertificateGeneration != 0 {
		want["certificate_expiry"] = emergency.CertificateGeneration
	}
	if emergency.EdgeOneGeneration != 0 {
		want["edgeone_expiry"] = emergency.EdgeOneGeneration
	}
	if len(normal.Contraction.Authorities) != len(want) {
		return false
	}
	for _, authority := range normal.Contraction.Authorities {
		if want[authority.Kind] != authority.Generation {
			return false
		}
	}
	safety := map[string]uint64{}
	for _, marker := range normal.SafetyGenerations {
		safety[marker.Kind] = marker.Generation
	}
	for kind, generation := range want {
		if safety[kind] != generation {
			return false
		}
	}
	return true
}

func validateTransition(role ClearRole, current, next State, proof TransitionProof) error {
	if current.GlobalClose != next.GlobalClose {
		if next.GlobalClose.Phase == GlobalCloseNone {
			if err := AuthorizeClear(role, ClearGlobalClose, ""); err != nil {
				return err
			}
			if !validGlobalClearProof(current, proof.GlobalClose) {
				return fmt.Errorf("global close clear lacks exact convergence proof")
			}
		} else if role != RoleContraction && role != RoleMaintenanceBegin {
			return fmt.Errorf("only contraction or maintenance-begin owns global close creation")
		}
	}
	if err := validateStopFenceTransition(role, current.StopFence, next.StopFence, proof.StopFence, next); err != nil {
		return err
	}
	for _, transition := range []struct {
		name          string
		before, after any
		owner         ClearRole
	}{
		{"maintenance_pending", current.MaintenancePending, next.MaintenancePending, RoleMaintenance},
		{"dependency_transition_pending", current.DependencyTransitionPending, next.DependencyTransitionPending, RoleUpgrade},
		{"upgrade_pending", current.UpgradePending, next.UpgradePending, RoleUpgrade},
		{"backup_quiescence", current.BackupQuiescence, next.BackupQuiescence, RoleBackup},
		{"backup_transition", current.BackupTransition, next.BackupTransition, RoleBackup},
	} {
		if transition.name == "maintenance_pending" && transition.before == nil && transition.after != nil && role != RoleMaintenanceBegin {
			return fmt.Errorf("maintenance creation requires atomic maintenance-begin authority")
		}
		if !reflect.DeepEqual(transition.before, transition.after) && role != transition.owner {
			compound := transition.name == "maintenance_pending" && (role == RoleMaintenanceBegin || role == RoleMaintenanceToDependency) || transition.name == "dependency_transition_pending" && role == RoleMaintenanceToDependency
			if !compound {
				return fmt.Errorf("role %q does not own %s transition", role, transition.name)
			}
		}
	}
	for name, generations := range map[string][2]uint64{
		"maintenance_pending":           {transitionGeneration(current.MaintenancePending), transitionGeneration(next.MaintenancePending)},
		"dependency_transition_pending": {transitionGeneration(current.DependencyTransitionPending), transitionGeneration(next.DependencyTransitionPending)},
		"upgrade_pending":               {transitionGeneration(current.UpgradePending), transitionGeneration(next.UpgradePending)},
		"backup_quiescence":             {backupQuiescenceGeneration(current.BackupQuiescence), backupQuiescenceGeneration(next.BackupQuiescence)},
		"backup_transition":             {backupTransitionGeneration(current.BackupTransition), backupTransitionGeneration(next.BackupTransition)},
	} {
		if generations[0] != 0 && generations[1] != 0 && generations[1] < generations[0] {
			return fmt.Errorf("%s generation regressed", name)
		}
	}
	if err := validateMaintenanceCompound(role, current, next); err != nil {
		return err
	}
	if err := validateHeadscaleTransition(role, current.Headscale, next.Headscale, proof.Headscale); err != nil {
		return err
	}
	beforeResources := map[string]ResourceSafety{}
	afterResources := map[string]ResourceSafety{}
	for _, resource := range current.Resources {
		beforeResources[resource.ResourceID] = resource
	}
	for _, resource := range next.Resources {
		afterResources[resource.ResourceID] = resource
	}
	for id, after := range afterResources {
		before, present := beforeResources[id]
		if !present {
			if role != RoleContraction || !hasBaseMarker(&after) || after.ChallengePending != nil || after.Reactivating != nil {
				return fmt.Errorf("new resource safety identity must start contracted")
			}
			continue
		}
		if err := validateResourceTransition(role, before, after, proof); err != nil {
			return fmt.Errorf("resource %s: %w", id, err)
		}
	}
	for id := range beforeResources {
		if _, present := afterResources[id]; !present && (role != RoleDelete || !validDeleteProof(beforeResources[id], proof.Delete)) {
			return fmt.Errorf("only delete may remove resource safety identity %s", id)
		}
	}
	return nil
}

func validateMaintenanceCompound(role ClearRole, current, next State) error {
	switch role {
	case RoleMaintenanceBegin:
		if current.MaintenancePending != nil || next.MaintenancePending == nil || current.GlobalClose.Phase != GlobalCloseNone || next.GlobalClose.Phase == GlobalCloseNone {
			return fmt.Errorf("maintenance-begin requires one atomic new maintenance and global-close authority")
		}
		if len(current.Resources) != len(next.Resources) {
			return fmt.Errorf("maintenance-begin cannot change resource identity inventory")
		}
		for index := range next.Resources {
			if next.Resources[index].StickyUnpublished == nil {
				return fmt.Errorf("maintenance-begin requires every App to become sticky-unpublished atomically")
			}
		}
	case RoleMaintenanceToDependency:
		if current.MaintenancePending == nil || next.MaintenancePending != nil || current.DependencyTransitionPending != nil || next.DependencyTransitionPending == nil {
			return fmt.Errorf("maintenance-to-dependency requires one exact marker replacement")
		}
		if next.DependencyTransitionPending.CurrentEnvelope != current.MaintenancePending.TargetEnvelope || next.DependencyTransitionPending.JournalRef != current.MaintenancePending.JournalRef {
			return fmt.Errorf("maintenance-to-dependency identity does not bind the completed maintenance target")
		}
	}
	return nil
}

func validateStopFenceTransition(role ClearRole, before, after *StopFence, proof *StopFenceConvergenceProof, next State) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if before == nil {
		if after == nil || role != stopFenceOwner(after.Kind) {
			return fmt.Errorf("wrong stop fence writer")
		}
		return nil
	}
	if after == nil {
		if err := AuthorizeClear(role, ClearStopFence, before.Kind); err != nil {
			return err
		}
		if !validStopClearProof(*before, next, proof) {
			return fmt.Errorf("stop fence clear lacks exact convergence proof")
		}
		return nil
	}
	if before.Kind != after.Kind || !sameStopFenceBinding(*before, *after) {
		return fmt.Errorf("stop fence kind and binding are immutable")
	}
	if role != stopFenceOwner(before.Kind) {
		return fmt.Errorf("wrong stop fence update writer")
	}
	return nil
}

func stopFenceOwner(kind StopFenceKind) ClearRole {
	switch kind {
	case StopFenceContraction:
		return RoleContraction
	case StopFenceIngressActivation:
		return RoleIngressActivation
	case StopFenceCertificateActivation:
		return RoleCertificateActivation
	case StopFenceEdgeOneRefresh:
		return RoleEdgeOneRefresh
	case StopFenceMaintenanceTransition:
		return RoleMaintenance
	case StopFenceGenerationUpgrade:
		return RoleUpgradeRecovery
	default:
		return ""
	}
}

func sameStopFenceBinding(left, right StopFence) bool {
	left.Observation = StopObservation{}
	right.Observation = StopObservation{}
	left.AccessMayRemain = false
	right.AccessMayRemain = false
	return reflect.DeepEqual(left, right)
}

func validateHeadscaleTransition(role ClearRole, before, after HeadscaleSafety, proof *HeadscaleConvergenceProof) error {
	if !reflect.DeepEqual(before.CertificateExpiry, after.CertificateExpiry) {
		if after.CertificateExpiry == nil {
			if role != RolePublish {
				return fmt.Errorf("wrong Headscale certificate-expiry clearer")
			}
		} else if role != RoleContraction {
			return fmt.Errorf("wrong Headscale certificate-expiry writer")
		}
		if before.CertificateExpiry != nil && after.CertificateExpiry != nil && after.CertificateExpiry.Generation <= before.CertificateExpiry.Generation {
			return fmt.Errorf("Headscale certificate-expiry replacement requires fresh generation")
		}
	}
	if err := challengeTransition(role, before.ChallengePending, after.ChallengePending); err != nil {
		return fmt.Errorf("Headscale: %w", err)
	}
	if !reflect.DeepEqual(before.Reactivating, after.Reactivating) {
		if role != RolePublish {
			return fmt.Errorf("wrong Headscale reactivation writer")
		}
		if before.Reactivating != nil && after.Reactivating != nil && after.Reactivating.Generation <= before.Reactivating.Generation {
			return fmt.Errorf("Headscale reactivation replacement requires fresh generation")
		}
	}
	if (before.CertificateExpiry != nil && after.CertificateExpiry == nil || before.Reactivating != nil && after.Reactivating == nil) && !validHeadscaleProof(before, after, proof) {
		return fmt.Errorf("Headscale expiry or reactivation clear lacks matching convergence proof")
	}
	return nil
}

func validateResourceTransition(role ClearRole, before, after ResourceSafety, proof TransitionProof) error {
	if before.State != after.State || before.DeletionTombstone != after.DeletionTombstone {
		if role != RoleDelete {
			return fmt.Errorf("wrong deletion writer")
		}
	}
	if before.Ownership != after.Ownership || before.OwnershipDigest != after.OwnershipDigest {
		if role != RoleRepair {
			return fmt.Errorf("wrong ownership writer")
		}
	}
	if err := markerTransition(role, before.StickyUnpublished, after.StickyUnpublished, RoleContraction, ClearBaseContraction, RoleMaintenanceBegin); err != nil {
		return err
	}
	if err := markerTransition(role, before.Closing, after.Closing, RoleContraction, ClearClosing); err != nil {
		return err
	}
	if before.Closing != nil && after.Closing == nil && !validClosingProof(before, after, proof.Closing) {
		return fmt.Errorf("closing normalization lacks exact unpublished convergence proof")
	}
	if err := markerTransition(role, before.Contraction, after.Contraction, RoleContraction, ClearBaseContraction); err != nil {
		return err
	}
	if err := deadlineTransition(role, before.CertificateExpiry, after.CertificateExpiry, RoleContraction, ClearBaseContraction); err != nil {
		return err
	}
	if err := deadlineTransition(role, before.EdgeOne.Expiry, after.EdgeOne.Expiry, RoleContraction, ClearBaseContraction); err != nil {
		return err
	}
	beforeEdge, afterEdge := before.EdgeOne, after.EdgeOne
	beforeEdge.Expiry = nil
	afterEdge.Expiry = nil
	if !reflect.DeepEqual(beforeEdge, afterEdge) && role != RoleEdgeOneRefresh {
		return fmt.Errorf("wrong EdgeOne journal writer")
	}
	if err := challengeTransition(role, before.ChallengePending, after.ChallengePending); err != nil {
		return err
	}
	if err := reactivationTransition(role, before.Reactivating, after.Reactivating); err != nil {
		return err
	}
	if before.Reactivating != nil && after.Reactivating == nil && role == RolePublish && !validReactivationProof(before, after, proof.Reactivation) {
		return fmt.Errorf("reactivation clear lacks exact convergence proof")
	}
	if baseMarkersRemoved(before, after) {
		if role == RolePublish && !validReactivationProof(before, after, proof.Reactivation) {
			return fmt.Errorf("base marker clear lacks matching reactivation convergence proof")
		}
		if role == RoleDelete && !validDeleteProof(before, proof.Delete) {
			return fmt.Errorf("base marker delete clear lacks deletion convergence proof")
		}
	}
	return nil
}

func markerTransition(role ClearRole, before, after *GenerationMarker, owner ClearRole, clear ClearTarget, additionalOwners ...ClearRole) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if after == nil {
		return AuthorizeClear(role, clear, "")
	}
	if role != owner {
		allowed := false
		for _, additional := range additionalOwners {
			if role == additional {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("wrong marker writer")
		}
	}
	if before != nil && after.Generation <= before.Generation {
		return fmt.Errorf("marker replacement requires a fresh generation")
	}
	return nil
}
func deadlineTransition(role ClearRole, before, after *DeadlineMarker, owner ClearRole, clear ClearTarget) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if after == nil {
		return AuthorizeClear(role, clear, "")
	}
	if role != owner {
		return fmt.Errorf("wrong deadline marker writer")
	}
	if before != nil && after.Generation <= before.Generation {
		return fmt.Errorf("deadline replacement requires a fresh generation")
	}
	return nil
}
func challengeTransition(role ClearRole, before, after *ChallengePending) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if role != RoleChallenge {
		return fmt.Errorf("wrong challenge writer")
	}
	if before != nil && after != nil && after.Generation <= before.Generation {
		return fmt.Errorf("challenge replacement requires a fresh generation")
	}
	return nil
}
func reactivationTransition(role ClearRole, before, after *Reactivating) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if role != RolePublish {
		return fmt.Errorf("wrong reactivation writer")
	}
	if before != nil && after != nil && after.Generation <= before.Generation {
		return fmt.Errorf("reactivation replacement requires a fresh generation")
	}
	return nil
}

func baseMarkersRemoved(before, after ResourceSafety) bool {
	return before.StickyUnpublished != nil && after.StickyUnpublished == nil || before.Contraction != nil && after.Contraction == nil || before.CertificateExpiry != nil && after.CertificateExpiry == nil || before.EdgeOne.Expiry != nil && after.EdgeOne.Expiry == nil
}

func validReactivationProof(before, after ResourceSafety, proof *ReactivationConvergenceProof) bool {
	intent := before.Reactivating
	return proof != nil && intent != nil && after.Reactivating == nil && proof.ResourceID == before.ResourceID && proof.PlanID == intent.PlanID && proof.Generation == intent.Generation && proof.CandidateDigest == intent.CandidateDigest && proof.CandidateBundle == intent.CandidateBundle && isDigest(proof.RuntimeClosureDigest) && snapshotMatches(intent.BaseMarkers, &before)
}

func validClosingProof(before, after ResourceSafety, proof *ClosingConvergenceProof) bool {
	return proof != nil && before.Closing != nil && after.StickyUnpublished != nil && proof.ResourceID == before.ResourceID && proof.ClosingGeneration == before.Closing.Generation && proof.UnpublishedGeneration == after.StickyUnpublished.Generation && proof.OwnershipDigest == before.OwnershipDigest && isDigest(proof.RuntimeClosureDigest)
}

func validHeadscaleProof(before, after HeadscaleSafety, proof *HeadscaleConvergenceProof) bool {
	intent := before.Reactivating
	return proof != nil && intent != nil && after.Reactivating == nil && proof.PlanID == intent.PlanID && proof.Generation == intent.Generation && proof.ControlGeneration == intent.ControlGeneration && proof.CertificateGeneration == intent.CertificateGeneration && proof.CandidateDigest == intent.CandidateDigest && proof.CandidateBundle == intent.CandidateBundle && isDigest(proof.RuntimeClosureDigest) && headscaleSnapshotMatches(intent.BaseMarkers, before)
}

func validDeleteProof(before ResourceSafety, proof *DeleteConvergenceProof) bool {
	return proof != nil && proof.ResourceID == before.ResourceID && proof.TombstoneRef == before.DeletionTombstone && proof.OwnershipDigest == before.OwnershipDigest && isDigest(proof.RuntimeClosureDigest)
}

func validGlobalClearProof(current State, proof *GlobalConvergenceProof) bool {
	if proof == nil || proof.Generation != current.GlobalClose.Generation || !isDigest(proof.InventoryDigest) || !isDigest(proof.OwnedGraphDigest) || !isDigest(proof.RuntimeClosureDigest) || !proof.NginxTestPassed || !proof.RuntimeClosed || len(proof.UnpublishedGenerations) != len(current.Resources) {
		return false
	}
	for _, resource := range current.Resources {
		if resource.StickyUnpublished == nil || proof.UnpublishedGenerations[resource.ResourceID] != resource.StickyUnpublished.Generation {
			return false
		}
	}
	return true
}

func validStopClearProof(fence StopFence, next State, proof *StopFenceConvergenceProof) bool {
	if proof == nil || proof.Kind != fence.Kind || proof.FenceGeneration != fence.FenceGeneration || proof.InventoryDigest != fence.InventoryDigest || proof.OwnedGraphDigest != fence.OwnedGraphDigest || !isDigest(proof.RuntimeClosureDigest) || !proof.AllChildrenExited || !proof.AllAppsUnpublished || !proof.NginxTestPassed || len(proof.UnpublishedGenerations) != len(next.Resources) {
		return false
	}
	for _, resource := range next.Resources {
		if resource.StickyUnpublished == nil || resource.ChallengePending != nil || resource.Reactivating != nil || proof.UnpublishedGenerations[resource.ResourceID] != resource.StickyUnpublished.Generation {
			return false
		}
	}
	journal := ""
	if fence.IngressActivation != nil {
		journal = fence.IngressActivation.IntentRef
	}
	if fence.CertificateActivation != nil {
		journal = fence.CertificateActivation.JournalRef
	}
	if fence.EdgeOneRefresh != nil {
		journal = fence.EdgeOneRefresh.JournalRef
	}
	if fence.Transition != nil {
		journal = fence.Transition.JournalRef
	}
	return proof.JournalRef == journal
}

func transitionGeneration(marker *TransitionMarker) uint64 {
	if marker == nil {
		return 0
	}
	return marker.Generation
}
func backupQuiescenceGeneration(marker *BackupQuiescence) uint64 {
	if marker == nil {
		return 0
	}
	return marker.Generation
}
func backupTransitionGeneration(marker *BackupTransition) uint64 {
	if marker == nil {
		return 0
	}
	return marker.Generation
}

func validRole(role ClearRole) bool {
	switch role {
	case RoleGlobalCloseRepair, RoleRepair, RoleUpgradeRecovery, RoleMaintenance, RoleMaintenanceBegin, RoleMaintenanceToDependency, RoleUpgrade, RoleBackup, RolePublish, RoleDelete, RoleChallenge, RoleContraction, RoleIngressActivation, RoleCertificateActivation, RoleEdgeOneRefresh:
		return true
	default:
		return false
	}
}

func stateChecksum(state State) (string, error) {
	state.Checksum = ""
	state.Resources = canonicalResources(state.Resources)
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateStoreConfig(config StoreConfig) error {
	if config.Emergency == nil {
		return fmt.Errorf("normal safety store requires the shared emergency generation authority")
	}
	if config.Owner.UID != uint32(os.Geteuid()) || config.Owner.GID != uint32(os.Getegid()) {
		return fmt.Errorf("independent safety store must be helper-owned")
	}
	for label, path := range map[string]string{"root": config.RootPath, "staging": config.StagingPath, "state": config.StatePath} {
		if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("safety %s path must be clean and absolute", label)
		}
		if label != "root" && filepath.Dir(path) != config.RootPath {
			return fmt.Errorf("safety %s path must be a direct root child", label)
		}
	}
	return nil
}

func openSafetyRoot(config StoreConfig) (int, unix.Stat_t, error) {
	fd, err := unix.Open(config.RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	if err := validateSafetyRootStat(stat, config.Owner); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	return fd, stat, nil
}

func (store *Store) revalidateRoot() error {
	var opened unix.Stat_t
	if err := unix.Fstat(store.rootFD, &opened); err != nil {
		return err
	}
	if err := validateSafetyRootStat(opened, store.config.Owner); err != nil || !sameSafetyDirectory(opened, store.rootStat) {
		return fmt.Errorf("open safety root changed: %w", err)
	}
	var fresh unix.Stat_t
	if err := unix.Lstat(store.config.RootPath, &fresh); err != nil {
		return err
	}
	if err := validateSafetyRootStat(fresh, store.config.Owner); err != nil || !sameSafetyDirectory(fresh, store.rootStat) {
		return fmt.Errorf("configured safety root changed: %w", err)
	}
	return nil
}

func validateSafetyRootStat(stat unix.Stat_t, owner filetxn.Owner) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != owner.UID || stat.Gid != owner.GID {
		return fmt.Errorf("safety root must be helper-owned mode 0700")
	}
	return nil
}

func sameSafetyDirectory(actual, expected unix.Stat_t) bool {
	return actual.Dev == expected.Dev && actual.Ino == expected.Ino && actual.Mode == expected.Mode && actual.Uid == expected.Uid && actual.Gid == expected.Gid
}
