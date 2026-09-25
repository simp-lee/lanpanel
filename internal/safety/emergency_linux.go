//go:build linux

package safety

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	emergencySlotSize = 4096
	emergencyFileSize = emergencySlotSize * 2
)

var (
	ErrEmergencySequence  = errors.New("emergency backing sequence mismatch")
	ErrEmergencyState     = errors.New("invalid emergency backing state")
	ErrEmergencyAmbiguous = errors.New("emergency backing requires reopen reconciliation")
)

type EmergencyStopFence struct {
	Kind                   StopFenceKind
	OriginOperation        string
	ScopeKind              string
	ResourceID             string
	Generation             uint64
	GlobalGeneration       uint64
	ClosingGeneration      uint64
	CertificateGeneration  uint64
	SafetyIntentGeneration uint64
	OperationRef           string
	SafetyIntentID         string
	OwnershipDigest        string
	OwnedGraphDigest       string
	InventoryDigest        string
	MasterStopped          bool
	WorkersStopped         bool
	ListenersStopped       bool
	ObservedUnix           int64
	AccessMayRemain        bool
}

type EmergencyClearProof struct {
	Generation           uint64
	StopFenceGeneration  uint64
	StopFenceDigest      string
	InventoryDigest      string
	OwnedGraphDigest     string
	RuntimeClosureDigest string
	NginxTestPassed      bool
	RuntimeClosed        bool
}

type EmergencyState struct {
	Sequence                uint64
	StopFenceSequence       uint64
	ReservedStopFenceKind   StopFenceKind
	ReservedStopFenceDigest string
	NormalInitialized       bool
	GlobalClose             GlobalClose
	StopFence               *EmergencyStopFence
	ClearProof              *EmergencyClearProof
}

type EmergencyPoint string

const (
	EmergencyAfterSlotWrite EmergencyPoint = "after_slot_write"
	EmergencyAfterSlotSync  EmergencyPoint = "after_slot_sync"
)

type EmergencyOptions struct {
	Fault         func(EmergencyPoint) error
	LockAuthority locks.Authority
}

type EmergencyCommitter struct {
	store            *EmergencyStore
	lease            *locks.Lease
	preparedSequence uint64
	used             bool
}

type EmergencyStore struct {
	mu            sync.Mutex
	fd            int
	dirFD         int
	fileStat      unix.Stat_t
	dirStat       unix.Stat_t
	path          string
	pathCString   []byte
	dirCString    []byte
	owner         filetxn.Owner
	lockAuthority locks.Authority
	current       EmergencyState
	currentFence  EmergencyStopFence
	currentClear  EmergencyClearProof
	slot          [emergencySlotSize]byte
	readSlots     [2][emergencySlotSize]byte
	fault         func(EmergencyPoint) error
	poisoned      bool
	closed        bool
}

func CreateEmergency(path string, owner filetxn.Owner, options EmergencyOptions) (*EmergencyStore, error) {
	return openEmergency(path, owner, options, true)
}

func OpenEmergency(path string, owner filetxn.Owner, options EmergencyOptions) (*EmergencyStore, error) {
	return openEmergency(path, owner, options, false)
}

func openEmergency(path string, owner filetxn.Owner, options EmergencyOptions, create bool) (*EmergencyStore, error) {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("emergency backing path must be clean and absolute")
	}
	if owner.UID != uint32(os.Geteuid()) || owner.GID != uint32(os.Getegid()) || !options.LockAuthority.Valid() {
		return nil, fmt.Errorf("emergency backing must be helper-owned")
	}
	directory := filepath.Dir(path)
	var stat unix.Stat_t
	if err := unix.Lstat(directory, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != owner.UID || stat.Gid != owner.GID {
		return nil, fmt.Errorf("emergency backing directory must be helper-owned mode 0700")
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(dirFD, filepath.Base(path), flags, 0o600)
	if err != nil {
		_ = unix.Close(dirFD)
		return nil, err
	}
	store := &EmergencyStore{fd: fd, dirFD: dirFD, dirStat: stat, path: path, pathCString: append([]byte(path), 0), dirCString: append([]byte(filepath.Dir(path)), 0), owner: owner, lockAuthority: options.LockAuthority, fault: options.Fault}
	if err := store.validateFile(); err != nil {
		_ = store.closeDescriptors()
		return nil, err
	}
	var fileStat unix.Stat_t
	if err := unix.Fstat(fd, &fileStat); err != nil {
		_ = store.closeDescriptors()
		return nil, err
	}
	store.fileStat = fileStat
	if create {
		if err := unix.Ftruncate(fd, emergencyFileSize); err != nil {
			_ = store.closeDescriptors()
			return nil, err
		}
		if err := unix.Fallocate(fd, 0, 0, emergencyFileSize); err != nil {
			_ = store.closeDescriptors()
			return nil, fmt.Errorf("preallocate emergency backing: %w", err)
		}
		baseline := EmergencyState{Sequence: 1, GlobalClose: GlobalClose{Phase: GlobalCloseNone}}
		var slot [emergencySlotSize]byte
		encodeEmergency(slot[:], baseline)
		for index := range 2 {
			if n, err := unix.Pwrite(fd, slot[:], int64(index*emergencySlotSize)); err != nil || n != len(slot) {
				_ = store.closeDescriptors()
				return nil, fmt.Errorf("initialize emergency slot %d: wrote %d: %w", index, n, err)
			}
		}
		if err := unix.Fsync(fd); err != nil {
			_ = store.closeDescriptors()
			return nil, err
		}
		if err := unix.Fsync(dirFD); err != nil {
			_ = store.closeDescriptors()
			return nil, err
		}
	} else if fileStat.Size != emergencyFileSize {
		_ = store.closeDescriptors()
		return nil, fmt.Errorf("emergency backing size is %d, want %d", fileStat.Size, emergencyFileSize)
	}
	current, validSlots, err := store.loadLatest()
	if err != nil {
		_ = store.closeDescriptors()
		return nil, err
	}
	if validSlots == 0 || validSlots == 1 && current.GlobalClose.Phase == GlobalCloseNone && current.StopFence == nil && current.ReservedStopFenceKind == "" {
		_ = store.closeDescriptors()
		return nil, fmt.Errorf("emergency backing does not have unambiguous fail-closed authority")
	}
	store.setCurrent(current)
	return store, nil
}

func (store *EmergencyStore) Current() EmergencyState {
	state, _ := store.Authority()
	return state
}

func (store *EmergencyStore) LockAuthority() locks.Authority {
	if store == nil {
		return locks.Authority{}
	}
	return store.lockAuthority
}

func (store *EmergencyStore) Authority() (EmergencyState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.poisoned {
		return EmergencyState{}, ErrEmergencyAmbiguous
	}
	if err := store.revalidateBacking(); err != nil {
		return EmergencyState{}, err
	}
	latest, validSlots, err := store.loadLatest()
	if err != nil {
		return EmergencyState{}, err
	}
	if validSlots == 0 || validSlots == 1 && latest.GlobalClose.Phase == GlobalCloseNone && latest.StopFence == nil && latest.ReservedStopFenceKind == "" {
		return EmergencyState{}, ErrEmergencyAmbiguous
	}
	store.setCurrent(latest)
	return cloneEmergency(store.current), nil
}

func (store *EmergencyStore) PrepareCommit(lease *locks.Lease) (*EmergencyCommitter, error) {
	if lease == nil || lease.Authority() != store.lockAuthority || lease.Kind() != locks.Exposure || lease.Validate() != nil {
		return nil, ErrEmergencyState
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.poisoned {
		return nil, ErrEmergencyAmbiguous
	}
	if err := store.revalidateBacking(); err != nil {
		return nil, err
	}
	latest, validSlots, err := store.loadLatest()
	if err != nil {
		return nil, err
	}
	if validSlots == 0 || validSlots == 1 && latest.GlobalClose.Phase == GlobalCloseNone && latest.StopFence == nil && latest.ReservedStopFenceKind == "" {
		return nil, ErrEmergencyAmbiguous
	}
	store.setCurrent(latest)
	return &EmergencyCommitter{store: store, lease: lease, preparedSequence: latest.Sequence}, nil
}

func (store *EmergencyStore) Commit(lease *locks.Lease, role ClearRole, expectedSequence uint64, next EmergencyState) error {
	committer, err := store.PrepareCommit(lease)
	if err != nil {
		return err
	}
	return committer.Commit(role, expectedSequence, next)
}

func (store *EmergencyStore) commitReservedStopFenceClearProof(lease *locks.Lease, expectedSequence uint64, next EmergencyState) error {
	committer, err := store.PrepareCommit(lease)
	if err != nil {
		return err
	}
	return committer.commit(RoleJournalConvergence, expectedSequence, next, true)
}

func (committer *EmergencyCommitter) Commit(role ClearRole, expectedSequence uint64, next EmergencyState) error {
	return committer.commit(role, expectedSequence, next, false)
}

func (committer *EmergencyCommitter) commit(role ClearRole, expectedSequence uint64, next EmergencyState, allowReservedStopFenceClear bool) error {
	if committer == nil || committer.used || committer.store == nil || !committer.lease.Active(locks.Exposure) {
		return ErrEmergencyState
	}
	committer.used = true
	store := committer.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.poisoned {
		return ErrEmergencyAmbiguous
	}
	if err := store.revalidateBacking(); err != nil {
		return err
	}
	latestSequence, validSlots, inactive, err := store.scanLatestSequence()
	if err != nil {
		return err
	}
	if validSlots == 0 || validSlots == 1 && inactive || latestSequence != committer.preparedSequence {
		return ErrEmergencyAmbiguous
	}
	if store.closed || store.current.Sequence != expectedSequence || next.Sequence != expectedSequence+1 {
		return ErrEmergencySequence
	}
	if !validEmergencyTransition(role, store.current, next) && (!allowReservedStopFenceClear || !validReservedStopFenceClearTransition(store.current, next)) {
		return ErrEmergencyState
	}
	clear(store.slot[:])
	encodeEmergency(store.slot[:], next)
	offset := int64(next.Sequence%2) * emergencySlotSize
	store.poisoned = true
	written := 0
	for written < len(store.slot) {
		n, err := unix.Pwrite(store.fd, store.slot[written:], offset+int64(written))
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short emergency slot write")
		}
		written += n
	}
	if store.fault != nil {
		if err := store.fault(EmergencyAfterSlotWrite); err != nil {
			return err
		}
	}
	if err := unix.Fsync(store.fd); err != nil {
		return err
	}
	if store.fault != nil {
		if err := store.fault(EmergencyAfterSlotSync); err != nil {
			return err
		}
	}
	store.setCurrent(next)
	store.poisoned = false
	return nil
}

func (store *EmergencyStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return store.closeDescriptors()
}

func (store *EmergencyStore) closeDescriptors() error {
	return errors.Join(unix.Close(store.fd), unix.Close(store.dirFD))
}

func (store *EmergencyStore) validateFile() error {
	var stat unix.Stat_t
	if err := unix.Fstat(store.fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != store.owner.UID || stat.Gid != store.owner.GID || stat.Nlink != 1 {
		return fmt.Errorf("emergency backing must be a singly linked helper-owned regular file mode 0600")
	}
	return nil
}

func (store *EmergencyStore) revalidateBacking() error {
	var opened unix.Stat_t
	if err := unix.Fstat(store.fd, &opened); err != nil {
		return err
	}
	if err := store.validateFile(); err != nil || !sameEmergencyObject(opened, store.fileStat) || opened.Size != emergencyFileSize {
		return fmt.Errorf("open emergency backing changed: %w", err)
	}
	var fresh unix.Stat_t
	if err := rawLstat(store.pathCString, &fresh); err != nil {
		return err
	}
	if !sameEmergencyObject(fresh, store.fileStat) || fresh.Size != emergencyFileSize {
		return fmt.Errorf("configured emergency backing identity changed")
	}
	var directory unix.Stat_t
	if err := unix.Fstat(store.dirFD, &directory); err != nil {
		return err
	}
	if !sameEmergencyDirectory(directory, store.dirStat) {
		return fmt.Errorf("emergency backing directory identity changed")
	}
	if err := rawLstat(store.dirCString, &directory); err != nil {
		return err
	}
	if !sameEmergencyDirectory(directory, store.dirStat) {
		return fmt.Errorf("emergency backing directory identity changed")
	}
	return nil
}

func rawLstat(path []byte, stat *unix.Stat_t) error {
	dirfd := unix.AT_FDCWD
	_, _, errno := unix.Syscall6(unix.SYS_NEWFSTATAT, uintptr(dirfd), uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(stat)), uintptr(unix.AT_SYMLINK_NOFOLLOW), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func sameEmergencyObject(actual, expected unix.Stat_t) bool {
	return sameEmergencyDirectory(actual, expected) && actual.Nlink == expected.Nlink
}

func sameEmergencyDirectory(actual, expected unix.Stat_t) bool {
	return actual.Dev == expected.Dev && actual.Ino == expected.Ino && actual.Mode == expected.Mode && actual.Uid == expected.Uid && actual.Gid == expected.Gid
}

func validReservedStopFenceClearTransition(current, next EmergencyState) bool {
	return current.StopFence == nil && next.StopFence == nil && current.StopFenceSequence != 0 && current.ReservedStopFenceKind != StopFenceContraction && next.StopFenceSequence == current.StopFenceSequence && next.ReservedStopFenceKind == current.ReservedStopFenceKind && next.ReservedStopFenceDigest == current.ReservedStopFenceDigest && (current.ClearProof == nil || current.ClearProof.StopFenceGeneration == 0) && next.ClearProof != nil && next.ClearProof.StopFenceGeneration == current.StopFenceSequence && validEmergencyClearProof(next.ClearProof, current)
}

func validEmergencyTransition(role ClearRole, current, next EmergencyState) bool {
	if next.Sequence == 0 || next.GlobalClose.Generation < current.GlobalClose.Generation || validateGlobalClose(next.GlobalClose) != nil {
		return false
	}
	if current.GlobalClose.Phase == GlobalCloseNone && next.GlobalClose.Phase == GlobalCloseNone && next.GlobalClose.Generation != current.GlobalClose.Generation {
		return false
	}
	if current.GlobalClose.Phase == GlobalCloseNone && next.GlobalClose.Phase != GlobalCloseNone && (role != RoleContraction || next.GlobalClose.Generation <= current.GlobalClose.Generation || !sameEmergencyClearProof(current.ClearProof, next.ClearProof)) {
		return false
	}
	if current.GlobalClose.Phase != GlobalCloseNone && next.GlobalClose.Phase != GlobalCloseNone && current.GlobalClose != next.GlobalClose && (role != RoleContraction || next.GlobalClose.Generation != current.GlobalClose.Generation) {
		return false
	}
	if current.GlobalClose.Phase != GlobalCloseNone && next.GlobalClose.Phase == GlobalCloseNone && (role != RoleGlobalCloseConvergence || next.GlobalClose.Generation != current.GlobalClose.Generation || !validEmergencyClearProof(next.ClearProof, current)) {
		return false
	}
	stopFenceClear := current.StopFence != nil && next.StopFence == nil
	if current.GlobalClose.Phase == GlobalCloseNone && next.GlobalClose.Phase == GlobalCloseNone && !sameEmergencyClearProof(current.ClearProof, next.ClearProof) && !stopFenceClear {
		return false
	}
	if current.NormalInitialized && !next.NormalInitialized {
		return false
	}
	if !current.NormalInitialized && next.NormalInitialized && (role != RoleBootstrap || next.GlobalClose.Phase != GlobalCloseNone || next.StopFence != nil) {
		return false
	}
	if !current.NormalInitialized && !next.NormalInitialized && role == RoleBootstrap {
		return false
	}
	if next.StopFence != nil && !validEmergencyFence(*next.StopFence, next.GlobalClose) {
		return false
	}
	if next.StopFenceSequence < current.StopFenceSequence || next.StopFenceSequence != 0 && !validStopFenceKind(next.ReservedStopFenceKind) || next.StopFenceSequence == 0 && next.ReservedStopFenceKind != "" || next.StopFenceSequence != 0 && next.ReservedStopFenceKind != StopFenceContraction && !isDigest(next.ReservedStopFenceDigest) {
		return false
	}
	if current.StopFence == nil && next.StopFence == nil {
		unchanged := next.StopFenceSequence == current.StopFenceSequence && next.ReservedStopFenceKind == current.ReservedStopFenceKind && next.ReservedStopFenceDigest == current.ReservedStopFenceDigest
		reserved := next.ReservedStopFenceKind != StopFenceContraction && next.StopFenceSequence == current.StopFenceSequence+1 && role == stopFenceWriter(next.ReservedStopFenceKind)
		if !unchanged && !reserved {
			return false
		}
	}
	if current.StopFence == nil && next.StopFence != nil {
		if role != RoleContraction || next.ReservedStopFenceKind != StopFenceContraction || next.StopFenceSequence != current.StopFenceSequence+1 || next.StopFence.Generation != next.StopFenceSequence {
			return false
		}
	}
	if current.StopFence != nil && next.StopFence == nil {
		if next.StopFenceSequence != current.StopFenceSequence || next.ReservedStopFenceKind != current.ReservedStopFenceKind || next.ReservedStopFenceDigest != current.ReservedStopFenceDigest {
			return false
		}
		expectedRole := RoleJournalConvergence
		if role != expectedRole || !validEmergencyClearProof(next.ClearProof, current) {
			return false
		}
	}
	if current.StopFence != nil && next.StopFence != nil && (next.StopFenceSequence != current.StopFenceSequence || next.ReservedStopFenceKind != current.ReservedStopFenceKind || next.ReservedStopFenceDigest != current.ReservedStopFenceDigest || *current.StopFence != *next.StopFence && (role != RoleContraction || !sameEmergencyFenceBinding(*current.StopFence, *next.StopFence))) {
		return false
	}
	return true
}

func validEmergencyClearProof(proof *EmergencyClearProof, current EmergencyState) bool {
	if proof == nil || !isDigest(proof.InventoryDigest) || !isDigest(proof.OwnedGraphDigest) || !isDigest(proof.RuntimeClosureDigest) || !proof.NginxTestPassed || !proof.RuntimeClosed {
		return false
	}
	if current.GlobalClose.Phase != GlobalCloseNone && proof.Generation != current.GlobalClose.Generation {
		return false
	}
	if current.StopFence != nil && (proof.StopFenceGeneration != current.StopFence.Generation || proof.StopFenceDigest != EmergencyFenceDigest(*current.StopFence)) {
		return false
	}
	return true
}

func sameEmergencyClearProof(left, right *EmergencyClearProof) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func validEmergencyFence(fence EmergencyStopFence, global GlobalClose) bool {
	if fence.Kind != StopFenceContraction || fence.Generation == 0 || !validRef(fence.OriginOperation) || len(fence.OriginOperation) > 64 || fence.ObservedUnix <= 0 || !isDigest(fence.OwnershipDigest) || !isDigest(fence.OwnedGraphDigest) || !isDigest(fence.InventoryDigest) {
		return false
	}
	if fence.ScopeKind != "installation" && fence.ScopeKind != "app" && fence.ScopeKind != "headscale" {
		return false
	}
	if fence.ScopeKind == "app" && (!validRef(fence.ResourceID) || len(fence.ResourceID) > 128) {
		return false
	}
	if fence.GlobalGeneration+fence.ClosingGeneration+fence.CertificateGeneration == 0 {
		return false
	}
	normalOperation := validRef(fence.OperationRef) && fence.SafetyIntentID == "" && fence.SafetyIntentGeneration == 0
	stateIndependent := fence.OperationRef == "" && validRef(fence.SafetyIntentID) && fence.SafetyIntentGeneration != 0
	if !normalOperation && !stateIndependent {
		return false
	}
	if fence.GlobalGeneration != 0 && fence.GlobalGeneration != global.Generation {
		return false
	}
	if !fence.AccessMayRemain && (!fence.MasterStopped || !fence.WorkersStopped || !fence.ListenersStopped) {
		return false
	}
	return true
}

// EmergencyFenceDigest binds the complete fixed-format emergency fence identity.
func EmergencyFenceDigest(fence EmergencyStopFence) string {
	data, err := json.Marshal(fence)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sameEmergencyFenceBinding(left, right EmergencyStopFence) bool {
	return left.Kind == right.Kind && left.OriginOperation == right.OriginOperation && left.ScopeKind == right.ScopeKind && left.ResourceID == right.ResourceID && left.Generation == right.Generation && left.GlobalGeneration == right.GlobalGeneration && left.ClosingGeneration == right.ClosingGeneration && left.CertificateGeneration == right.CertificateGeneration && left.OperationRef == right.OperationRef && left.SafetyIntentID == right.SafetyIntentID && left.SafetyIntentGeneration == right.SafetyIntentGeneration && left.OwnershipDigest == right.OwnershipDigest && left.OwnedGraphDigest == right.OwnedGraphDigest && left.InventoryDigest == right.InventoryDigest
}

func validStopFenceKind(kind StopFenceKind) bool {
	switch kind {
	case StopFenceContraction, StopFenceIngressActivation, StopFenceCertificateActivation:
		return true
	default:
		return false
	}
}

func encodeEmergency(slot []byte, state EmergencyState) {
	copy(slot[0:8], "LPSAFE04")
	binary.LittleEndian.PutUint64(slot[8:16], state.Sequence)
	binary.LittleEndian.PutUint64(slot[16:24], state.GlobalClose.Generation)
	slot[24] = phaseCode(state.GlobalClose.Phase)
	if state.NormalInitialized {
		slot[28] = 1
	}
	if state.ClearProof != nil {
		proof := state.ClearProof
		slot[29] = 1
		binary.LittleEndian.PutUint64(slot[376:384], proof.Generation)
		binary.LittleEndian.PutUint64(slot[384:392], proof.StopFenceGeneration)
		putDigest(slot[504:536], proof.StopFenceDigest)
		if proof.NginxTestPassed {
			slot[392] |= 1
		}
		if proof.RuntimeClosed {
			slot[392] |= 2
		}
		putDigest(slot[400:432], proof.InventoryDigest)
		putDigest(slot[432:464], proof.OwnedGraphDigest)
		putDigest(slot[464:496], proof.RuntimeClosureDigest)
	}
	binary.LittleEndian.PutUint64(slot[496:504], state.StopFenceSequence)
	slot[536] = fenceCode(state.ReservedStopFenceKind)
	putDigest(slot[544:576], state.ReservedStopFenceDigest)
	if state.StopFence != nil {
		fence := state.StopFence
		slot[25] = 1
		if fence.AccessMayRemain {
			slot[26] |= 1
		}
		if fence.MasterStopped {
			slot[26] |= 2
		}
		if fence.WorkersStopped {
			slot[26] |= 4
		}
		if fence.ListenersStopped {
			slot[26] |= 8
		}
		slot[27] = scopeCode(fence.ScopeKind)
		binary.LittleEndian.PutUint64(slot[32:40], fence.Generation)
		binary.LittleEndian.PutUint64(slot[40:48], fence.GlobalGeneration)
		binary.LittleEndian.PutUint64(slot[48:56], fence.ClosingGeneration)
		binary.LittleEndian.PutUint64(slot[56:64], fence.CertificateGeneration)
		binary.LittleEndian.PutUint64(slot[64:72], fence.SafetyIntentGeneration)
		binary.LittleEndian.PutUint64(slot[72:80], uint64(fence.ObservedUnix))
		putFixedString(slot[80:145], fence.OriginOperation)
		putFixedString(slot[145:274], fence.ResourceID)
		putDigest(slot[274:306], fence.OwnershipDigest)
		putDigest(slot[306:338], fence.OwnedGraphDigest)
		putDigest(slot[338:370], fence.InventoryDigest)
		putFixedString(slot[576:834], fence.OperationRef)
		putFixedString(slot[834:1092], fence.SafetyIntentID)
	}
	checksum := crc32.ChecksumIEEE(slot[:emergencySlotSize-4])
	binary.LittleEndian.PutUint32(slot[emergencySlotSize-4:], checksum)
}

func decodeEmergency(slot []byte) (EmergencyState, bool) {
	if string(slot[0:8]) != "LPSAFE04" {
		return EmergencyState{}, false
	}
	want := binary.LittleEndian.Uint32(slot[emergencySlotSize-4:])
	if crc32.ChecksumIEEE(slot[:emergencySlotSize-4]) != want {
		return EmergencyState{}, false
	}
	state := EmergencyState{Sequence: binary.LittleEndian.Uint64(slot[8:16]), StopFenceSequence: binary.LittleEndian.Uint64(slot[496:504]), ReservedStopFenceKind: fenceFromCode(slot[536]), NormalInitialized: slot[28] == 1, GlobalClose: GlobalClose{Phase: phaseFromCode(slot[24]), Generation: binary.LittleEndian.Uint64(slot[16:24])}}
	if state.StopFenceSequence != 0 && state.ReservedStopFenceKind != StopFenceContraction {
		state.ReservedStopFenceDigest = getDigest(slot[544:576])
	}
	if state.Sequence == 0 || validateGlobalClose(state.GlobalClose) != nil || state.StopFenceSequence == 0 && state.ReservedStopFenceKind != "" || state.StopFenceSequence != 0 && !validStopFenceKind(state.ReservedStopFenceKind) || state.StopFenceSequence != 0 && state.ReservedStopFenceKind != StopFenceContraction && !isDigest(state.ReservedStopFenceDigest) {
		return EmergencyState{}, false
	}
	if slot[29] != 0 {
		proof := EmergencyClearProof{Generation: binary.LittleEndian.Uint64(slot[376:384]), StopFenceGeneration: binary.LittleEndian.Uint64(slot[384:392]), StopFenceDigest: getDigest(slot[504:536]), NginxTestPassed: slot[392]&1 != 0, RuntimeClosed: slot[392]&2 != 0, InventoryDigest: getDigest(slot[400:432]), OwnedGraphDigest: getDigest(slot[432:464]), RuntimeClosureDigest: getDigest(slot[464:496])}
		if !isDigest(proof.InventoryDigest) || !isDigest(proof.OwnedGraphDigest) || !isDigest(proof.RuntimeClosureDigest) {
			return EmergencyState{}, false
		}
		state.ClearProof = &proof
	}
	if slot[25] != 0 {
		fence := EmergencyStopFence{Kind: StopFenceContraction, ScopeKind: scopeFromCode(slot[27]), Generation: binary.LittleEndian.Uint64(slot[32:40]), GlobalGeneration: binary.LittleEndian.Uint64(slot[40:48]), ClosingGeneration: binary.LittleEndian.Uint64(slot[48:56]), CertificateGeneration: binary.LittleEndian.Uint64(slot[56:64]), SafetyIntentGeneration: binary.LittleEndian.Uint64(slot[64:72]), ObservedUnix: int64(binary.LittleEndian.Uint64(slot[72:80])), OriginOperation: getFixedString(slot[80:145]), ResourceID: getFixedString(slot[145:274]), OwnershipDigest: getDigest(slot[274:306]), OwnedGraphDigest: getDigest(slot[306:338]), InventoryDigest: getDigest(slot[338:370]), OperationRef: getFixedString(slot[576:834]), SafetyIntentID: getFixedString(slot[834:1092]), AccessMayRemain: slot[26]&1 != 0, MasterStopped: slot[26]&2 != 0, WorkersStopped: slot[26]&4 != 0, ListenersStopped: slot[26]&8 != 0}
		if !validEmergencyFence(fence, state.GlobalClose) || fence.Generation != state.StopFenceSequence {
			return EmergencyState{}, false
		}
		state.StopFence = &fence
	}
	return state, true
}

func (store *EmergencyStore) loadLatest() (EmergencyState, int, error) {
	best := EmergencyState{GlobalClose: GlobalClose{Phase: GlobalCloseNone}}
	valid := 0
	for index := range 2 {
		slot := store.readSlots[index][:]
		n, err := unix.Pread(store.fd, slot, int64(index*emergencySlotSize))
		if err != nil {
			return EmergencyState{}, 0, err
		}
		if n != len(slot) {
			return EmergencyState{}, 0, errors.New("short emergency slot read")
		}
		state, ok := decodeEmergency(slot)
		if ok {
			valid++
			if state.Sequence > best.Sequence {
				best = state
			}
		}
	}
	return best, valid, nil
}

func putFixedString(target []byte, value string) {
	if len(value) > len(target)-1 {
		return
	}
	target[0] = byte(len(value))
	copy(target[1:], value)
}

func getFixedString(source []byte) string {
	length := int(source[0])
	if length > len(source)-1 {
		return ""
	}
	return string(source[1 : 1+length])
}

func putDigest(target []byte, value string) {
	if len(value) != 71 {
		return
	}
	for index := range len(target) {
		high, okHigh := hexNibble(value[7+index*2])
		low, okLow := hexNibble(value[8+index*2])
		if !okHigh || !okLow {
			clear(target)
			return
		}
		target[index] = high<<4 | low
	}
}

func getDigest(source []byte) string { return "sha256:" + hex.EncodeToString(source) }

func hexNibble(value byte) (byte, bool) {
	if value >= '0' && value <= '9' {
		return value - '0', true
	}
	if value >= 'a' && value <= 'f' {
		return value - 'a' + 10, true
	}
	return 0, false
}

func scopeCode(scope string) byte {
	switch scope {
	case "installation":
		return 1
	case "app":
		return 2
	case "headscale":
		return 3
	}
	return 0
}

func scopeFromCode(code byte) string {
	switch code {
	case 1:
		return "installation"
	case 2:
		return "app"
	case 3:
		return "headscale"
	}
	return ""
}

func (store *EmergencyStore) scanLatestSequence() (uint64, int, bool, error) {
	var best uint64
	valid := 0
	inactive := false
	for index := range 2 {
		slot := store.readSlots[index][:]
		n, err := unix.Pread(store.fd, slot, int64(index*emergencySlotSize))
		if err != nil {
			return 0, 0, false, err
		}
		if n != len(slot) {
			return 0, 0, false, errors.New("short emergency slot read")
		}
		if string(slot[0:8]) != "LPSAFE04" || crc32.ChecksumIEEE(slot[:emergencySlotSize-4]) != binary.LittleEndian.Uint32(slot[emergencySlotSize-4:]) {
			continue
		}
		sequence := binary.LittleEndian.Uint64(slot[8:16])
		if sequence == 0 {
			continue
		}
		valid++
		if sequence > best {
			best = sequence
			inactive = phaseFromCode(slot[24]) == GlobalCloseNone && slot[25] == 0 && fenceFromCode(slot[536]) == ""
		}
	}
	return best, valid, inactive, nil
}

func phaseCode(phase GlobalClosePhase) byte {
	switch phase {
	case GlobalCloseNone:
		return 1
	case GlobalCloseClosing:
		return 2
	case GlobalCloseEmergency:
		return 3
	}
	return 0
}

func phaseFromCode(code byte) GlobalClosePhase {
	switch code {
	case 1:
		return GlobalCloseNone
	case 2:
		return GlobalCloseClosing
	case 3:
		return GlobalCloseEmergency
	}
	return ""
}

func fenceCode(kind StopFenceKind) byte {
	switch kind {
	case StopFenceContraction:
		return 1
	case StopFenceIngressActivation:
		return 2
	case StopFenceCertificateActivation:
		return 3
	}
	return 0
}

func fenceFromCode(code byte) StopFenceKind {
	switch code {
	case 1:
		return StopFenceContraction
	case 2:
		return StopFenceIngressActivation
	case 3:
		return StopFenceCertificateActivation
	}
	return ""
}

func (store *EmergencyStore) setCurrent(state EmergencyState) {
	store.current = state
	if state.StopFence == nil {
		store.current.StopFence = nil
	} else {
		store.currentFence = *state.StopFence
		store.current.StopFence = &store.currentFence
	}
	if state.ClearProof == nil {
		store.current.ClearProof = nil
	} else {
		store.currentClear = *state.ClearProof
		store.current.ClearProof = &store.currentClear
	}
}

func cloneEmergency(state EmergencyState) EmergencyState {
	copy := state
	if state.StopFence != nil {
		fence := *state.StopFence
		copy.StopFence = &fence
	}
	if state.ClearProof != nil {
		proof := *state.ClearProof
		copy.ClearProof = &proof
	}
	return copy
}
