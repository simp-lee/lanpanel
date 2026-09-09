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
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxStateBytes = 2 << 20

var ErrSafetyStateMissing = errors.New("independent safety state is missing")

type OwnershipAuthority interface {
	InventoryAuthority() (map[string]string, bool, error)
}

type StoreConfig struct {
	RootPath      string
	StagingPath   string
	StatePath     string
	Owner         filetxn.Owner
	Emergency     *EmergencyStore
	LockAuthority locks.Authority
	Ownership     OwnershipAuthority
}

type OwnershipConvergenceProof struct {
	ResourceID   string
	IntentRef    string
	Generation   uint64
	BeforeDigest string
	AfterDigest  string
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
	PlanID                 string
	Generation             uint64
	ControlGeneration      uint64
	CertificateGeneration  uint64
	CertificateFingerprint string
	CandidateDigest        string
	CandidateBundle        string
	RuntimeClosureDigest   string
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
	FenceDigest            string
	JournalRef             string
	SafetyIntentID         string
	SafetyIntentGeneration uint64
	InventoryDigest        string
	OwnedGraphDigest       string
	RuntimeClosureDigest   string
	AllChildrenExited      bool
	AllAppsUnpublished     bool
	NoAppDisk              bool
	WorkersDrained         bool
	ListenersClosed        bool
	RuntimeClosed          bool
	NginxTestPassed        bool
	UnpublishedGenerations map[string]uint64
}

type TransitionProof struct {
	Ownership    *OwnershipConvergenceProof
	Reactivation *ReactivationConvergenceProof
	Headscale    *HeadscaleConvergenceProof
	Closing      *ClosingConvergenceProof
	Closings     map[string]ClosingConvergenceProof
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

// ReserveEmergencyStopFenceGeneration durably allocates the next emergency
// generation before a non-contraction normal stop fence may be committed.
func ReserveEmergencyStopFenceGeneration(lease *locks.Lease, emergency *EmergencyStore, role ClearRole, kind StopFenceKind, reservationDigest string, expectedNormalSequence uint64) (EmergencyState, error) {
	if lease == nil || emergency == nil || kind == StopFenceContraction || role != stopFenceWriter(kind) || !isDigest(reservationDigest) {
		return EmergencyState{}, fmt.Errorf("emergency stop-fence reservation authority is invalid")
	}
	current, err := emergency.Authority()
	if err != nil {
		return EmergencyState{}, err
	}
	if current.StopFence != nil {
		return EmergencyState{}, fmt.Errorf("emergency stop fence is already active")
	}
	if current.StopFenceSequence == expectedNormalSequence+1 && current.ReservedStopFenceKind == kind && current.ReservedStopFenceDigest == reservationDigest {
		return current, nil
	}
	if current.StopFenceSequence != expectedNormalSequence {
		return EmergencyState{}, fmt.Errorf("emergency stop-fence reservation does not match expected normal high-water")
	}
	next := current
	next.Sequence++
	next.StopFenceSequence++
	next.ReservedStopFenceKind = kind
	next.ReservedStopFenceDigest = reservationDigest
	if err := emergency.Commit(lease, role, current.Sequence, next); err != nil {
		return EmergencyState{}, err
	}
	return next, nil
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

func (store *Store) LockAuthority() locks.Authority {
	if store == nil {
		return locks.Authority{}
	}
	return store.config.LockAuthority
}
func (store *Store) Close() error { return errors.Join(store.txn.Close(), unix.Close(store.rootFD)) }

func (store *Store) Read() (State, error) { return store.read(true) }

// ReadForContraction retains checksum and emergency high-water validation but
// deliberately does not treat a damaged ownership tree as authority to narrow
// ingress. The caller must force fallback stop when ownership is incomplete.
func (store *Store) ReadForRecovery(exposure *locks.Lease) (State, error) {
	if exposure == nil || exposure.Authority() != store.config.LockAuthority || !exposure.Holds(locks.Exposure) {
		return State{}, fmt.Errorf("recovery safety read requires exposure lock")
	}
	state, err := store.read(false)
	if err != nil {
		return State{}, err
	}
	return state, nil
}

// ReadForDeleteRecovery accepts either exact safety/ownership authority or the
// one ownership record retained after its proven safety tombstone converged.
func (store *Store) ReadForDeleteRecovery(exposure *locks.Lease, resourceID, ownershipDigest string) (State, error) {
	if !validRef(resourceID) || !isDigest(ownershipDigest) {
		return State{}, fmt.Errorf("delete recovery ownership identity is invalid")
	}
	state, err := store.ReadForRecovery(exposure)
	if err != nil {
		return State{}, err
	}
	if err := validateOwnershipAuthority(state, store.config.Ownership); err == nil {
		return state, nil
	}
	overhang := map[string]string{resourceID: ownershipDigest}
	if err := validateOwnershipAuthorityWithOverhang(state, store.config.Ownership, overhang); err != nil {
		return State{}, fmt.Errorf("delete recovery ownership authority invalid: %w", err)
	}
	return state, nil
}

func (store *Store) ReadForContraction(exposure *locks.Lease) (State, error) {
	if exposure == nil || exposure.Authority() != store.config.LockAuthority || !exposure.Holds(locks.Exposure) {
		return State{}, fmt.Errorf("degraded safety read requires the shared exposure lock")
	}
	state, err := store.read(false)
	if err != nil {
		return State{}, err
	}
	authority, err := store.config.Emergency.Authority()
	if err != nil {
		return State{}, err
	}
	if err := matchAuthority(state, authority); err != nil {
		return State{}, err
	}
	return state, nil
}

func (store *Store) EmergencyAuthority() (EmergencyState, error) {
	if store == nil || store.config.Emergency == nil {
		return EmergencyState{}, fmt.Errorf("emergency authority is unavailable")
	}
	return store.config.Emergency.Authority()
}

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
	defer func(ignore func() error) { _ = ignore() }(file.Close)
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
		if err := validateOwnershipAuthority(state, store.config.Ownership); err != nil {
			return State{}, err
		}
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
	if lease == nil || lease.Authority() != store.config.LockAuthority || lease.Kind() != locks.Exposure || lease.Validate() != nil {
		return filetxn.Result{}, fmt.Errorf("safety initialization requires the shared exposure lock")
	}
	authority, err := store.config.Emergency.Authority()
	if err != nil {
		return filetxn.Result{}, err
	}
	if authority.NormalInitialized {
		return filetxn.Result{}, fmt.Errorf("normal safety state was already initialized; missing state requires recovery")
	}
	if authority.StopFence != nil || authority.StopFenceSequence != 0 || authority.ReservedStopFenceKind != "" || authority.GlobalClose.Phase != GlobalCloseNone {
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
	state.StopFenceSequence = nextAuthority.StopFenceSequence
	if err := validateOwnershipAuthority(state, store.config.Ownership); err != nil {
		return filetxn.Result{}, fmt.Errorf("initialize safety ownership authority: %w", err)
	}
	return store.persist(ctx, state, filetxn.CreateOnly)
}

func (store *Store) Commit(ctx context.Context, lease *locks.Lease, role ClearRole, expectedRevision uint64, next State, proof TransitionProof) (filetxn.Result, error) {
	if lease == nil || lease.Authority() != store.config.LockAuthority || lease.Kind() != locks.Exposure || lease.Validate() != nil {
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
	if next.AuthoritySequence != authority.Sequence || next.GlobalClose != authority.GlobalClose || next.StopFenceSequence != authority.StopFenceSequence {
		return filetxn.Result{}, fmt.Errorf("normal safety state does not bind the current emergency generation authority")
	}
	if next.StopFence != nil {
		projected := authority.StopFence != nil && normalFenceMatchesEmergency(next.StopFence, *authority.StopFence)
		reserved := authority.StopFence == nil && authority.ReservedStopFenceKind == next.StopFence.Kind && authority.ReservedStopFenceDigest == StopFenceDigest(*next.StopFence) && authority.StopFenceSequence == next.StopFence.FenceGeneration
		if !projected && !reserved {
			return filetxn.Result{}, fmt.Errorf("normal safety fence does not match current emergency reservation")
		}
	} else if authority.StopFence != nil {
		return filetxn.Result{}, fmt.Errorf("normal safety state omits current emergency stop authority")
	}
	if current.StopFence != nil && next.StopFence == nil && next.StopFenceSequence != current.StopFenceSequence {
		// A fallback emergency contraction can advance the emergency high-water
		// while an ingress/certificate fence remains in normal safety. That
		// original fence may still be cleared, but only with its exact
		// reconciliation proof and the matching emergency clear proof.
		if current.StopFence.Kind == StopFenceContraction || next.StopFenceSequence != current.StopFenceSequence+1 || authority.StopFence != nil || authority.ClearProof == nil || authority.ClearProof.StopFenceGeneration != next.StopFenceSequence {
			return filetxn.Result{}, fmt.Errorf("stop fence clear cannot consume an unrelated emergency generation")
		}
	}
	if current.GlobalClose.Phase == GlobalCloseNone && next.GlobalClose.Phase != GlobalCloseNone && current.StopFence != nil && next.StopFence == nil && current.StopFence.Kind != StopFenceContraction && (authority.ClearProof == nil || authority.ClearProof.StopFenceGeneration != next.StopFenceSequence) {
		return filetxn.Result{}, fmt.Errorf("activation fence clear cannot project global close without emergency convergence")
	}
	if current.GlobalClose.Phase != GlobalCloseNone && next.GlobalClose.Phase == GlobalCloseNone {
		inventoryDigest, err := readOwnershipInventoryDigest(store.config.Ownership)
		if err != nil {
			return filetxn.Result{}, err
		}
		if proof.GlobalClose == nil || proof.GlobalClose.InventoryDigest != inventoryDigest || !globalProofMatchesEmergency(proof.GlobalClose, authority.ClearProof) {
			return filetxn.Result{}, fmt.Errorf("normal global clear proof does not match emergency and ownership authority")
		}
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
	deleteOverhang := map[string]string(nil)
	if role == RoleDelete && proof.Delete != nil {
		deleteOverhang = map[string]string{proof.Delete.ResourceID: proof.Delete.OwnershipDigest}
	}
	if err := validateOwnershipAuthorityWithOverhang(next, store.config.Ownership, deleteOverhang); err != nil {
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

// OwnershipInventoryDigest returns the exact complete ownership inventory
// bound to this independent safety store.
func (store *Store) OwnershipInventoryDigest() (string, error) {
	if store == nil {
		return "", fmt.Errorf("independent safety store is nil")
	}
	return readOwnershipInventoryDigest(store.config.Ownership)
}

func readOwnershipInventoryDigest(authority OwnershipAuthority) (string, error) {
	if authority == nil {
		return "", fmt.Errorf("independent ownership authority is missing")
	}
	records, complete, err := authority.InventoryAuthority()
	if err != nil {
		return "", fmt.Errorf("read ownership authority: %w", err)
	}
	if !complete {
		return "", fmt.Errorf("ownership authority inventory is incomplete")
	}
	return OwnershipInventoryDigest(records), nil
}

func validateOwnershipAuthority(state State, authority OwnershipAuthority) error {
	return validateOwnershipAuthorityWithOverhang(state, authority, nil)
}

func validateOwnershipAuthorityWithOverhang(state State, authority OwnershipAuthority, overhang map[string]string) error {
	if authority == nil {
		return fmt.Errorf("independent ownership authority is missing")
	}
	records, complete, err := authority.InventoryAuthority()
	if err != nil {
		return fmt.Errorf("read ownership authority: %w", err)
	}
	if !complete {
		return fmt.Errorf("ownership authority inventory is incomplete")
	}
	inventoryDigest := OwnershipInventoryDigest(records)
	if state.StopFence != nil && state.StopFence.InventoryDigest != inventoryDigest {
		return fmt.Errorf("stop fence inventory digest does not match exact ownership authority")
	}
	for _, resource := range state.Resources {
		digest, present := records[resource.ResourceID]
		if present {
			if digest != resource.OwnershipDigest {
				return fmt.Errorf("resource %q safety and ownership digests are one-sided", resource.ResourceID)
			}
			delete(records, resource.ResourceID)
			continue
		}
		return fmt.Errorf("resource %q has no complete ownership record", resource.ResourceID)
	}
	for resourceID, digest := range overhang {
		current, present := records[resourceID]
		if !present || current != digest {
			return fmt.Errorf("resource %q deletion ownership overhang changed", resourceID)
		}
		delete(records, resourceID)
	}
	if len(records) != 0 {
		return fmt.Errorf("ownership record inventory has no matching closed safety identity")
	}
	return nil
}

// OwnershipInventoryDigest canonically binds the complete ownership identity inventory.
func OwnershipInventoryDigest(records map[string]string) string {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		hash.Write([]byte(key))
		hash.Write([]byte{0})
		hash.Write([]byte(records[key]))
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func matchAuthority(state State, authority EmergencyState) error {
	if state.AuthoritySequence != authority.Sequence || state.GlobalClose != authority.GlobalClose || state.StopFenceSequence != authority.StopFenceSequence {
		return fmt.Errorf("normal and emergency safety authority are one-sided")
	}
	if state.StopFence != nil {
		projected := authority.StopFence != nil && normalFenceMatchesEmergency(state.StopFence, *authority.StopFence)
		reserved := authority.StopFence == nil && authority.ReservedStopFenceKind == state.StopFence.Kind && authority.ReservedStopFenceDigest == StopFenceDigest(*state.StopFence) && authority.StopFenceSequence == state.StopFence.FenceGeneration
		if !projected && !reserved {
			return fmt.Errorf("normal safety fence mismatches emergency reservation")
		}
	} else if authority.StopFence != nil {
		return fmt.Errorf("normal safety state omits emergency stop authority")
	}
	return nil
}

func globalProofMatchesEmergency(normal *GlobalConvergenceProof, emergency *EmergencyClearProof) bool {
	return normal != nil && emergency != nil && normal.Generation == emergency.Generation && normal.InventoryDigest == emergency.InventoryDigest && normal.OwnedGraphDigest == emergency.OwnedGraphDigest && normal.RuntimeClosureDigest == emergency.RuntimeClosureDigest && normal.NginxTestPassed == emergency.NginxTestPassed && normal.RuntimeClosed == emergency.RuntimeClosed
}

func FenceMatchesEmergency(normal *StopFence, emergency EmergencyStopFence) bool {
	return normalFenceMatchesEmergency(normal, emergency)
}

func normalFenceMatchesEmergency(normal *StopFence, emergency EmergencyStopFence) bool {
	if normal == nil || normal.Kind != StopFenceContraction || normal.Contraction == nil {
		return false
	}
	if normal.OriginOperation != emergency.OriginOperation || normal.Scope.Kind != emergency.ScopeKind || normal.Scope.ResourceID != emergency.ResourceID || normal.FenceGeneration != emergency.Generation || normal.OwnedGraphDigest != emergency.OwnedGraphDigest || normal.InventoryDigest != emergency.InventoryDigest || normal.Contraction.OwnershipDigest != emergency.OwnershipDigest || normal.Contraction.OperationRef != emergency.OperationRef || normal.Contraction.SafetyIntentID != emergency.SafetyIntentID || normal.Contraction.SafetyIntentGeneration != emergency.SafetyIntentGeneration || normal.AccessMayRemain != emergency.AccessMayRemain || normal.Observation.MasterStopped != emergency.MasterStopped || normal.Observation.WorkersStopped != emergency.WorkersStopped || normal.Observation.ListenersStopped != emergency.ListenersStopped || normal.Observation.ObservedAt.Unix() != emergency.ObservedUnix {
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
		} else if role != RoleContraction {
			// Recovery may atomically project an emergency global close while
			// clearing a superseded activation fence. The activation fence still
			// has to be cleared with its exact origin proof; no other journal
			// transition may create global close authority.
			activationProjection := role == RoleJournalConvergence && current.StopFence != nil && next.StopFence == nil && current.StopFence.Kind != StopFenceContraction && validStopClearProof(*current.StopFence, next, proof.StopFence)
			if !activationProjection {
				return fmt.Errorf("only contraction owns global close creation")
			}
		}
	}
	if err := validateStopFenceTransition(role, current, next, proof.StopFence); err != nil {
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
	stopFenceConvergence := current.StopFence != nil && next.StopFence == nil
	for id, after := range afterResources {
		before, present := beforeResources[id]
		if !present {
			if role != RoleResourceCreate || after.State != ResourceActive || after.Ownership != OwnershipOwned || after.GenerationSequence != 1 || after.StickyUnpublished == nil || after.StickyUnpublished.Generation != 1 || after.StickyUnpublished.Kind != MarkerStickyUnpublished || after.Closing != nil || after.Contraction != nil || after.CertificateExpiry != nil || after.ChallengePending != nil || after.Reactivating != nil || after.DeletionTombstone != "" {
				return fmt.Errorf("new resource safety identity must start as exact owned sticky-unpublished generation 1")
			}
			continue
		}
		if err := validateResourceTransition(role, before, after, proof, stopFenceConvergence); err != nil {
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

func validateStopFenceTransition(role ClearRole, current, next State, proof *StopFenceConvergenceProof) error {
	before, after := current.StopFence, next.StopFence
	if next.StopFenceSequence < current.StopFenceSequence {
		return fmt.Errorf("stop fence generation sequence regressed")
	}
	if reflect.DeepEqual(before, after) {
		if next.StopFenceSequence != current.StopFenceSequence {
			return fmt.Errorf("stop fence generation sequence changed without a new fence")
		}
		return nil
	}
	if before == nil {
		if after == nil || role != stopFenceWriter(after.Kind) || next.StopFenceSequence != current.StopFenceSequence+1 || after.FenceGeneration != next.StopFenceSequence {
			return fmt.Errorf("wrong or replayed stop fence writer generation")
		}
		return nil
	}
	if after == nil {
		if next.StopFenceSequence != current.StopFenceSequence && (before.Kind == StopFenceContraction || next.StopFenceSequence != current.StopFenceSequence+1) {
			return fmt.Errorf("stop fence clear rewrote its retained generation sequence")
		}
		if err := AuthorizeClear(role, ClearStopFence, before.Kind); err != nil {
			return err
		}
		if !validStopClearProof(*before, next, proof) {
			return fmt.Errorf("stop fence clear lacks exact convergence proof")
		}
		return nil
	}
	if next.StopFenceSequence != current.StopFenceSequence || before.Kind != after.Kind || !sameStopFenceBinding(*before, *after) {
		return fmt.Errorf("stop fence kind, generation, and binding are immutable")
	}
	if role != stopFenceWriter(before.Kind) {
		return fmt.Errorf("wrong stop fence update writer")
	}
	return nil
}

func stopFenceWriter(kind StopFenceKind) ClearRole {
	switch kind {
	case StopFenceContraction:
		return RoleContraction
	case StopFenceIngressActivation:
		return RoleIngressActivation
	case StopFenceCertificateActivation:
		return RoleCertificateActivation
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
	if role == RoleCertificateHandoff && !reflect.DeepEqual(before, after) {
		pending, active := before.ChallengePending, after.Reactivating
		if pending == nil || before.Reactivating != nil || after.ChallengePending != nil || active == nil || active.PlanID != pending.PlanID || active.Generation != pending.Generation || active.PriorGeneration+1 != pending.Generation || active.CandidateDigest != pending.ConfigDigest || !reflect.DeepEqual(active.BaseMarkers, pending.BaseMarkers) || !isDigest(active.CandidateBundle) || active.ControlGeneration == 0 || active.CertificateGeneration == 0 || !isDigest(active.CertificateFingerprint) || active.CertificateUntil.IsZero() {
			return fmt.Errorf("headscale certificate handoff does not exactly replace challenge authority")
		}
	}
	if before.ControlEntryDigest != after.ControlEntryDigest {
		if role != RolePublish || before.ControlEntryDigest != "" || !isDigest(after.ControlEntryDigest) || before.Reactivating == nil {
			return fmt.Errorf("wrong Headscale control-entry writer")
		}
	}
	if !reflect.DeepEqual(before.ActiveCertificate, after.ActiveCertificate) {
		observation := role == RoleCertificateObservation && before.ActiveCertificate != nil && after.ActiveCertificate != nil && before.ActiveCertificate.Generation == after.ActiveCertificate.Generation && before.ActiveCertificate.Fingerprint == after.ActiveCertificate.Fingerprint && before.ActiveCertificate.Binding == after.ActiveCertificate.Binding && before.ActiveCertificate.NotAfter.Equal(after.ActiveCertificate.NotAfter) && after.ActiveCertificate.LastTrustedWall.After(before.ActiveCertificate.LastTrustedWall) && after.ActiveCertificate.LastTrustedWall.Before(after.ActiveCertificate.NotAfter)
		if !observation && role != RolePublish && role != RoleCertificateActivation {
			return fmt.Errorf("wrong Headscale active-certificate writer")
		}
		if after.ActiveCertificate == nil {
			return fmt.Errorf("headscale active certificate cannot be cleared by activation")
		}
		if !observation && role == RolePublish {
			active := before.Reactivating
			if active == nil || after.ActiveCertificate.Generation != active.CertificateGeneration || after.ActiveCertificate.Fingerprint != active.CertificateFingerprint || !after.ActiveCertificate.NotAfter.Equal(active.CertificateUntil) || !after.ActiveCertificate.LastTrustedWall.Equal(active.CertificateLastTrustedWall) {
				return fmt.Errorf("headscale active certificate does not match reactivation")
			}
		}
		if !observation && role == RoleCertificateActivation {
			pending := before.ChallengePending
			if before.ActiveCertificate == nil || pending == nil || after.ChallengePending != nil || after.ActiveCertificate.Generation != before.ActiveCertificate.Generation+1 || after.ActiveCertificate.Fingerprint == before.ActiveCertificate.Fingerprint || !after.ActiveCertificate.NotAfter.After(after.ActiveCertificate.LastTrustedWall) {
				return fmt.Errorf("headscale renewal certificate does not replace exact challenge authority")
			}
		}
	}
	beforeGenerations := headscaleGenerations(before)
	if role == RoleCertificateHandoff && before.ChallengePending != nil && after.Reactivating != nil {
		delete(beforeGenerations, "challenge_pending")
		beforeGenerations["reactivating"] = before.ChallengePending.Generation
	}
	if err := validateMonotonicGenerationSequence(before.GenerationSequence, after.GenerationSequence, beforeGenerations, headscaleGenerations(after)); err != nil {
		return fmt.Errorf("headscale: %w", err)
	}
	if !reflect.DeepEqual(before.CertificateExpiry, after.CertificateExpiry) {
		if after.CertificateExpiry == nil {
			if role != RolePublish {
				return fmt.Errorf("wrong Headscale certificate-expiry clearer")
			}
		} else if role != RoleCertificateActivation {
			return fmt.Errorf("wrong Headscale certificate-expiry writer")
		}
		if before.CertificateExpiry != nil && after.CertificateExpiry != nil && after.CertificateExpiry.Generation <= before.CertificateExpiry.Generation {
			return fmt.Errorf("headscale certificate-expiry replacement requires fresh generation")
		}
	}
	if err := challengeTransition(role, before.ChallengePending, after.ChallengePending); err != nil {
		return fmt.Errorf("headscale: %w", err)
	}
	if !reflect.DeepEqual(before.Reactivating, after.Reactivating) {
		bindingOnly := false
		if role == RoleIngressActivation && before.Reactivating != nil && after.Reactivating != nil && before.Reactivating.ActivationDigest == "" && before.Reactivating.ControlEntryDigest == "" && isDigest(after.Reactivating.ActivationDigest) && isDigest(after.Reactivating.ControlEntryDigest) {
			left, right := *before.Reactivating, *after.Reactivating
			left.ActivationDigest, left.ControlEntryDigest = "", ""
			right.ActivationDigest, right.ControlEntryDigest = "", ""
			bindingOnly = reflect.DeepEqual(left, right)
		}
		if !bindingOnly && role != RolePublish && role != RoleCertificateHandoff {
			return fmt.Errorf("wrong Headscale reactivation writer")
		}
		if !bindingOnly && role != RoleCertificateHandoff && after.Reactivating != nil && (after.Reactivating.PriorGeneration != before.GenerationSequence || after.Reactivating.Generation != before.GenerationSequence+1) {
			return fmt.Errorf("headscale reactivation does not bind the exact prior generation")
		}
	}
	if (before.CertificateExpiry != nil && after.CertificateExpiry == nil || before.Reactivating != nil && after.Reactivating == nil) && !validHeadscaleProof(before, after, proof) {
		return fmt.Errorf("headscale expiry or reactivation clear lacks matching convergence proof")
	}
	return nil
}

func validateResourceTransition(role ClearRole, before, after ResourceSafety, proof TransitionProof, stopFenceConvergence bool) error {
	if role == RoleCertificateHandoff {
		pending, active := before.ChallengePending, after.Reactivating
		if pending == nil || before.Reactivating != nil || after.ChallengePending != nil || active == nil || active.PlanID != pending.PlanID || active.Generation != pending.Generation || active.PriorGeneration+1 != pending.Generation || active.CandidateDigest != pending.ConfigDigest || !reflect.DeepEqual(active.BaseMarkers, pending.BaseMarkers) || !isDigest(active.CandidateBundle) {
			return fmt.Errorf("certificate handoff does not exactly replace challenge authority")
		}
		before.ChallengePending = nil
		after.Reactivating = nil
		if !reflect.DeepEqual(before, after) {
			return fmt.Errorf("certificate handoff changed unrelated safety authority")
		}
	}
	beforeGenerations := resourceGenerations(before)
	if before.Closing != nil && after.Closing == nil && after.StickyUnpublished != nil && after.StickyUnpublished.Generation == before.Closing.Generation {
		delete(beforeGenerations, "closing")
		beforeGenerations["sticky_unpublished"] = before.Closing.Generation
	}
	if err := validateMonotonicGenerationSequence(before.GenerationSequence, after.GenerationSequence, beforeGenerations, resourceGenerations(after)); err != nil {
		return err
	}
	if before.State != after.State || before.DeletionTombstone != after.DeletionTombstone {
		if role != RoleDelete {
			return fmt.Errorf("wrong deletion writer")
		}
	}
	if before.Ownership != after.Ownership || before.OwnershipDigest != after.OwnershipDigest {
		orphanContraction := role == RoleOwnershipContraction && before.Ownership == OwnershipOwned && after.Ownership == OwnershipOrphan && before.OwnershipDigest == after.OwnershipDigest
		publicationContraction := role == RoleOwnershipContraction && before.Ownership == OwnershipOwned && after.Ownership == OwnershipOwned && validOwnershipContractionProof(before, after, proof.Ownership)
		activationRebind := role == RoleOwnershipActivation && before.Ownership == OwnershipOwned && after.Ownership == OwnershipOwned && validOwnershipConvergenceProof(before, after, proof.Ownership)
		retirementRebind := role == RoleOwnershipRetirement && before.Ownership == OwnershipOwned && after.Ownership == OwnershipOwned && validOwnershipRetirementProof(before, after, proof.Ownership)
		if !orphanContraction && !publicationContraction && !activationRebind && !retirementRebind {
			return fmt.Errorf("ownership authority transition lacks exact contraction or activation proof")
		}
	}
	additionalMarkerOwners := []ClearRole{}
	journalConvergence := role == RoleJournalConvergence && stopFenceConvergence && proof.StopFence != nil
	if journalConvergence {
		additionalMarkerOwners = append(additionalMarkerOwners, RoleJournalConvergence)
	}
	if err := markerTransition(role, before.StickyUnpublished, after.StickyUnpublished, RoleContraction, ClearBaseContraction, additionalMarkerOwners...); err != nil {
		return err
	}
	if err := markerTransition(role, before.Closing, after.Closing, RoleContraction, ClearClosing, additionalMarkerOwners...); err != nil {
		return err
	}
	if before.Closing != nil && after.Closing == nil {
		closingProof := proof.Closing
		if value, ok := proof.Closings[before.ResourceID]; ok {
			copy := value
			closingProof = &copy
		}
		if !validClosingProof(before, after, closingProof) {
			return fmt.Errorf("closing normalization lacks exact unpublished convergence proof")
		}
	}
	if err := markerTransition(role, before.Contraction, after.Contraction, RoleContraction, ClearBaseContraction); err != nil {
		return err
	}
	if !reflect.DeepEqual(before.ActiveCertificate, after.ActiveCertificate) {
		observation := false
		if role == RoleCertificateObservation && before.ActiveCertificate != nil && after.ActiveCertificate != nil {
			prior, next := *before.ActiveCertificate, *after.ActiveCertificate
			priorWall, nextWall := prior.LastTrustedWall, next.LastTrustedWall
			prior.LastTrustedWall = time.Time{}
			next.LastTrustedWall = time.Time{}
			observation = reflect.DeepEqual(prior, next) && !nextWall.Before(priorWall) && next.NotAfter.After(nextWall)
		}
		allowed := role == RolePublish || role == RoleCertificateActivation || role == RoleDelete || observation
		if !allowed {
			return fmt.Errorf("wrong active certificate authority writer")
		}
		if !observation && after.ActiveCertificate != nil && before.ActiveCertificate != nil && after.ActiveCertificate.Generation <= before.ActiveCertificate.Generation {
			return fmt.Errorf("active certificate generation did not advance")
		}
	}
	if err := deadlineTransition(role, before.CertificateExpiry, after.CertificateExpiry, RoleCertificateActivation, ClearBaseContraction); err != nil {
		return err
	}
	if !journalConvergence || before.ChallengePending == nil || after.ChallengePending != nil {
		if err := challengeTransition(role, before.ChallengePending, after.ChallengePending); err != nil {
			return err
		}
	}
	if !journalConvergence || before.Reactivating == nil || after.Reactivating != nil {
		if err := reactivationTransition(role, before.GenerationSequence, before.Reactivating, after.Reactivating); err != nil {
			return err
		}
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

func validateMonotonicGenerationSequence(beforeSequence, afterSequence uint64, before, after map[string]uint64) error {
	maximum := beforeSequence
	seenFresh := map[uint64]bool{}
	for kind, generation := range after {
		if generation == before[kind] {
			continue
		}
		if generation <= beforeSequence {
			return fmt.Errorf("%s generation %d does not exceed retained sequence %d", kind, generation, beforeSequence)
		}
		if seenFresh[generation] {
			return fmt.Errorf("fresh generation %d is reused in one transition", generation)
		}
		seenFresh[generation] = true
		if generation > maximum {
			maximum = generation
		}
	}
	if afterSequence != maximum {
		return fmt.Errorf("generation sequence is %d, want exact high-water %d", afterSequence, maximum)
	}
	return nil
}

func markerTransition(role ClearRole, before, after *GenerationMarker, owner ClearRole, clear ClearTarget, additionalOwners ...ClearRole) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if after == nil {
		for _, additional := range additionalOwners {
			if role == additional {
				return nil
			}
		}
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
	if (role == RoleContraction || role == RoleCertificateHandoff || role == RoleCertificateActivation) && before != nil && after == nil {
		return nil
	}
	if role != RoleChallenge {
		return fmt.Errorf("wrong challenge writer")
	}
	if before != nil && after != nil && sameHTTPChallengeOperation(*before, *after) {
		beforeActive := before.Token != ""
		afterActive := after.Token != ""
		if beforeActive != afterActive {
			return nil
		}
	}
	if before != nil && after != nil && after.Generation <= before.Generation {
		return fmt.Errorf("challenge replacement requires a fresh generation")
	}
	return nil
}

func sameHTTPChallengeOperation(left, right ChallengePending) bool {
	if left.Method != "http-01" || right.Method != "http-01" || len(left.Hosts) == 0 || len(right.Hosts) == 0 {
		return false
	}
	left.Host, right.Host = left.Hosts[0], right.Hosts[0]
	left.Token, right.Token = "", ""
	left.TokenPath, right.TokenPath = "", ""
	left.KeyAuthorizationDigest, right.KeyAuthorizationDigest = "", ""
	return reflect.DeepEqual(left, right)
}

func reactivationTransition(role ClearRole, priorGeneration uint64, before, after *Reactivating) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if role == RoleContraction && before != nil && after == nil {
		return nil
	}
	if role != RolePublish && role != RoleCertificateHandoff {
		return fmt.Errorf("wrong reactivation writer")
	}
	if role == RoleCertificateHandoff {
		return nil
	}
	if after != nil && (after.PriorGeneration != priorGeneration || after.Generation != priorGeneration+1) {
		return fmt.Errorf("reactivation does not bind the exact prior generation")
	}
	return nil
}

func baseMarkersRemoved(before, after ResourceSafety) bool {
	return before.StickyUnpublished != nil && after.StickyUnpublished == nil || before.Contraction != nil && after.Contraction == nil || before.CertificateExpiry != nil && after.CertificateExpiry == nil
}

func validOwnershipContractionProof(before, after ResourceSafety, proof *OwnershipConvergenceProof) bool {
	generation := uint64(0)
	if before.Closing != nil {
		generation = before.Closing.Generation
	} else if before.StickyUnpublished != nil {
		generation = before.StickyUnpublished.Generation
	}
	return proof != nil && before.ResourceID == after.ResourceID && proof.ResourceID == before.ResourceID && validRef(proof.IntentRef) && proof.Generation == generation && generation != 0 && proof.BeforeDigest == before.OwnershipDigest && proof.AfterDigest == after.OwnershipDigest && isDigest(proof.BeforeDigest) && isDigest(proof.AfterDigest)
}

func validOwnershipRetirementProof(before, after ResourceSafety, proof *OwnershipConvergenceProof) bool {
	return proof != nil && proof.ResourceID == before.ResourceID && validRef(proof.IntentRef) && proof.Generation != 0 && proof.BeforeDigest == before.OwnershipDigest && proof.AfterDigest == after.OwnershipDigest && isDigest(proof.BeforeDigest) && isDigest(proof.AfterDigest)
}

func validOwnershipConvergenceProof(before, after ResourceSafety, proof *OwnershipConvergenceProof) bool {
	return proof != nil && after.Reactivating != nil && proof.ResourceID == before.ResourceID && proof.IntentRef == after.Reactivating.PlanID && proof.Generation == after.Reactivating.Generation && proof.BeforeDigest == before.OwnershipDigest && proof.AfterDigest == after.OwnershipDigest && isDigest(proof.BeforeDigest) && isDigest(proof.AfterDigest)
}

func validReactivationProof(before, after ResourceSafety, proof *ReactivationConvergenceProof) bool {
	intent := before.Reactivating
	return proof != nil && intent != nil && after.Reactivating == nil && proof.ResourceID == before.ResourceID && proof.PlanID == intent.PlanID && proof.Generation == intent.Generation && proof.CandidateDigest == intent.CandidateDigest && proof.CandidateBundle == intent.CandidateBundle && isDigest(proof.RuntimeClosureDigest) && snapshotMatches(intent.BaseMarkers, &before)
}

func validClosingProof(before, after ResourceSafety, proof *ClosingConvergenceProof) bool {
	return proof != nil && before.Closing != nil && after.Closing == nil && after.StickyUnpublished != nil && after.StickyUnpublished.Generation == before.Closing.Generation && proof.ResourceID == before.ResourceID && proof.ClosingGeneration == before.Closing.Generation && proof.UnpublishedGeneration == after.StickyUnpublished.Generation && proof.OwnershipDigest == before.OwnershipDigest && isDigest(proof.RuntimeClosureDigest)
}

func validHeadscaleProof(before, after HeadscaleSafety, proof *HeadscaleConvergenceProof) bool {
	intent := before.Reactivating
	return proof != nil && intent != nil && after.Reactivating == nil && proof.PlanID == intent.PlanID && proof.Generation == intent.Generation && proof.ControlGeneration == intent.ControlGeneration && proof.CertificateGeneration == intent.CertificateGeneration && proof.CertificateFingerprint == intent.CertificateFingerprint && isDigest(proof.CertificateFingerprint) && proof.CandidateDigest == intent.CandidateDigest && proof.CandidateBundle == intent.CandidateBundle && isDigest(proof.RuntimeClosureDigest) && headscaleSnapshotMatches(intent.BaseMarkers, before)
}

func validDeleteProof(before ResourceSafety, proof *DeleteConvergenceProof) bool {
	return proof != nil && before.State == ResourceDeleting && before.Ownership == OwnershipOwned && validRef(before.DeletionTombstone) && proof.ResourceID == before.ResourceID && proof.TombstoneRef == before.DeletionTombstone && proof.OwnershipDigest == before.OwnershipDigest && isDigest(proof.RuntimeClosureDigest)
}

func validGlobalClearProof(current State, proof *GlobalConvergenceProof) bool {
	if proof == nil || proof.Generation != current.GlobalClose.Generation || !isDigest(proof.InventoryDigest) || !isDigest(proof.OwnedGraphDigest) || !isDigest(proof.RuntimeClosureDigest) || !proof.NginxTestPassed || !proof.RuntimeClosed || len(proof.UnpublishedGenerations) != len(current.Resources) {
		return false
	}
	for _, resource := range current.Resources {
		if resource.Ownership == OwnershipOrphan || resource.StickyUnpublished == nil || proof.UnpublishedGenerations[resource.ResourceID] != resource.StickyUnpublished.Generation {
			return false
		}
	}
	return true
}

func validStopClearProof(fence StopFence, next State, proof *StopFenceConvergenceProof) bool {
	if proof == nil || proof.Kind != fence.Kind || proof.FenceGeneration != fence.FenceGeneration || proof.FenceDigest != StopFenceDigest(fence) || proof.InventoryDigest != fence.InventoryDigest || proof.OwnedGraphDigest != fence.OwnedGraphDigest || !isDigest(proof.RuntimeClosureDigest) || !proof.AllChildrenExited || !proof.AllAppsUnpublished || !proof.NoAppDisk || !proof.WorkersDrained || !proof.ListenersClosed || !proof.RuntimeClosed || !proof.NginxTestPassed || len(proof.UnpublishedGenerations) != len(next.Resources) {
		return false
	}
	for _, resource := range next.Resources {
		if resource.Ownership == OwnershipOrphan || resource.StickyUnpublished == nil || resource.ChallengePending != nil || resource.Reactivating != nil || proof.UnpublishedGenerations[resource.ResourceID] != resource.StickyUnpublished.Generation {
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
	if fence.Contraction != nil {
		journal = fence.Contraction.OperationRef
		if proof.SafetyIntentID != fence.Contraction.SafetyIntentID || proof.SafetyIntentGeneration != fence.Contraction.SafetyIntentGeneration {
			return false
		}
	}
	return proof.JournalRef == journal
}

// StopFenceDigest binds every immutable fence identity and observation field.
func StopFenceDigest(fence StopFence) string {
	data, err := json.Marshal(fence)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validRole(role ClearRole) bool {
	switch role {
	case RoleGlobalCloseConvergence, RoleJournalConvergence, RoleOwnershipContraction, RoleOwnershipActivation, RoleOwnershipRetirement, RolePublish, RoleDelete, RoleChallenge, RoleCertificateHandoff, RoleContraction, RoleIngressActivation, RoleCertificateActivation, RoleCertificateObservation, RoleResourceCreate:
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
	if config.Emergency == nil || config.Ownership == nil || !config.LockAuthority.Valid() || config.Emergency.LockAuthority() != config.LockAuthority {
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
