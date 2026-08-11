//go:build linux

package locks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type Kind string

const (
	MutationAdmission Kind = "mutation_admission"
	Exposure          Kind = "exposure"
)

const NormalActivationTimeout = 60 * time.Second

var (
	ErrClosed    = errors.New("independent lock manager is closed")
	ErrHeld      = errors.New("independent lock is already held or being acquired")
	ErrLockOrder = errors.New("independent lock order violation")
	processOrder = struct {
		sync.Mutex
		heldExposure      int
		acquiringExposure int
	}{}
)

type Config struct {
	RootPath string
	Owner    uint32
	Group    uint32
	Mode     fs.FileMode
}

type lockFile struct {
	name string
	fd   int
	stat unix.Stat_t
}

type Manager struct {
	mu        sync.Mutex
	rootPath  string
	rootFD    int
	rootStat  unix.Stat_t
	owner     uint32
	group     uint32
	mode      fs.FileMode
	files     map[Kind]lockFile
	held      map[Kind]*Lease
	acquiring map[Kind]bool
	closed    bool
}

type Lease struct {
	manager  *Manager
	kind     Kind
	released atomic.Bool
}

func Open(config Config) (*Manager, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	rootFD, rootStat, err := openAbsoluteDirectory(config.RootPath)
	if err != nil {
		return nil, fmt.Errorf("open independent lock root: %w", err)
	}
	if err := validateDirectory(rootStat, config.Owner, config.Group, config.Mode); err != nil {
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("independent lock root: %w", err)
	}
	manager := &Manager{
		rootPath: config.RootPath, rootFD: rootFD, rootStat: rootStat,
		owner: config.Owner, group: config.Group, mode: config.Mode.Perm(),
		files: map[Kind]lockFile{}, held: map[Kind]*Lease{}, acquiring: map[Kind]bool{},
	}
	for _, kind := range []Kind{MutationAdmission, Exposure} {
		file, openErr := openLockFile(rootFD, lockName(kind), config.Owner, config.Group)
		if openErr != nil {
			_ = manager.closeFiles()
			return nil, openErr
		}
		manager.files[kind] = file
	}
	if err := unix.Fsync(rootFD); err != nil {
		_ = manager.closeFiles()
		return nil, fmt.Errorf("sync independent lock root: %w", err)
	}
	return manager, nil
}

func (manager *Manager) Acquire(ctx context.Context, kind Kind) (*Lease, error) {
	if !validKind(kind) {
		return nil, fmt.Errorf("unsupported independent lock kind %q", kind)
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return nil, ErrClosed
	}
	if manager.acquiring[kind] || manager.held[kind] != nil {
		manager.mu.Unlock()
		return nil, ErrHeld
	}
	if kind == MutationAdmission && manager.held[Exposure] != nil {
		manager.mu.Unlock()
		return nil, ErrLockOrder
	}
	processOrder.Lock()
	if kind == MutationAdmission && processOrder.heldExposure+processOrder.acquiringExposure != 0 {
		processOrder.Unlock()
		manager.mu.Unlock()
		return nil, ErrLockOrder
	}
	if kind == Exposure {
		processOrder.acquiringExposure++
	}
	processOrder.Unlock()
	manager.acquiring[kind] = true
	file := manager.files[kind]
	manager.mu.Unlock()

	if err := manager.revalidate(kind); err != nil {
		manager.finishAcquire(kind, nil)
		return nil, err
	}
	for {
		err := unix.Flock(file.fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			if validateErr := manager.revalidate(kind); validateErr != nil {
				_ = unix.Flock(file.fd, unix.LOCK_UN)
				manager.finishAcquire(kind, nil)
				return nil, validateErr
			}
			lease := &Lease{manager: manager, kind: kind}
			manager.finishAcquire(kind, lease)
			return lease, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			manager.finishAcquire(kind, nil)
			return nil, fmt.Errorf("acquire %s lock: %w", kind, err)
		}
		select {
		case <-ctx.Done():
			manager.finishAcquire(kind, nil)
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (manager *Manager) finishAcquire(kind Kind, lease *Lease) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	delete(manager.acquiring, kind)
	if kind == Exposure {
		processOrder.Lock()
		processOrder.acquiringExposure--
		if lease != nil {
			processOrder.heldExposure++
		}
		processOrder.Unlock()
	}
	if lease != nil {
		manager.held[kind] = lease
	}
}

func (lease *Lease) Kind() Kind {
	if lease == nil {
		return ""
	}
	return lease.kind
}

func (lease *Lease) Holds(kind Kind) bool {
	return lease != nil && lease.kind == kind && lease.Validate() == nil
}

func (lease *Lease) Active(kind Kind) bool {
	if lease == nil || lease.released.Load() || lease.manager == nil || lease.kind != kind {
		return false
	}
	lease.manager.mu.Lock()
	defer lease.manager.mu.Unlock()
	return !lease.manager.closed && lease.manager.held[kind] == lease
}

func (lease *Lease) Validate() error {
	if lease == nil || lease.released.Load() || lease.manager == nil {
		return fmt.Errorf("independent lock lease is not active")
	}
	lease.manager.mu.Lock()
	active := !lease.manager.closed && lease.manager.held[lease.kind] == lease
	lease.manager.mu.Unlock()
	if !active {
		return fmt.Errorf("independent %s lock lease is not current", lease.kind)
	}
	if err := lease.manager.revalidate(lease.kind); err != nil {
		return fmt.Errorf("independent %s lock lease path changed: %w", lease.kind, err)
	}
	return nil
}

func (lease *Lease) Release() error {
	if lease == nil || lease.manager == nil {
		return fmt.Errorf("independent lock lease is nil")
	}
	if !lease.released.CompareAndSwap(false, true) {
		return fmt.Errorf("independent %s lock lease is already released", lease.kind)
	}
	manager := lease.manager
	manager.mu.Lock()
	if manager.held[lease.kind] != lease {
		manager.mu.Unlock()
		return fmt.Errorf("independent %s lock lease is not current", lease.kind)
	}
	file := manager.files[lease.kind]
	if err := unix.Flock(file.fd, unix.LOCK_UN); err != nil {
		manager.mu.Unlock()
		return fmt.Errorf("release %s lock: %w", lease.kind, err)
	}
	delete(manager.held, lease.kind)
	if lease.kind == Exposure {
		processOrder.Lock()
		processOrder.heldExposure--
		processOrder.Unlock()
	}
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) Close() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return nil
	}
	if len(manager.held) != 0 || len(manager.acquiring) != 0 {
		return fmt.Errorf("cannot close independent lock manager while locks are active")
	}
	manager.closed = true
	return manager.closeFiles()
}

func (manager *Manager) closeFiles() error {
	var result error
	for kind, file := range manager.files {
		if err := unix.Close(file.fd); err != nil {
			result = errors.Join(result, fmt.Errorf("close %s lock: %w", kind, err))
		}
	}
	if manager.rootFD >= 0 {
		if err := unix.Close(manager.rootFD); err != nil {
			result = errors.Join(result, fmt.Errorf("close lock root: %w", err))
		}
		manager.rootFD = -1
	}
	return result
}

func (manager *Manager) revalidate(kind Kind) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return ErrClosed
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(manager.rootFD, &rootStat); err != nil {
		return err
	}
	if err := validateDirectory(rootStat, manager.owner, manager.group, manager.mode); err != nil || !sameDirectory(rootStat, manager.rootStat) {
		return fmt.Errorf("open independent lock root changed: %w", err)
	}
	freshRootFD, freshRoot, err := openAbsoluteDirectory(manager.rootPath)
	if err != nil {
		return err
	}
	defer unix.Close(freshRootFD)
	if err := validateDirectory(freshRoot, manager.owner, manager.group, manager.mode); err != nil || !sameDirectory(freshRoot, manager.rootStat) {
		return fmt.Errorf("configured independent lock root changed: %w", err)
	}
	file := manager.files[kind]
	var openStat unix.Stat_t
	if err := unix.Fstat(file.fd, &openStat); err != nil {
		return err
	}
	if err := validateLockStat(openStat, manager.owner, manager.group); err != nil || !sameFile(openStat, file.stat) {
		return fmt.Errorf("open %s lock changed: %w", kind, err)
	}
	freshFD, err := unix.Openat2(freshRootFD, file.name, &unix.OpenHow{
		Flags:   unix.O_RDWR | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return err
	}
	defer unix.Close(freshFD)
	var freshStat unix.Stat_t
	if err := unix.Fstat(freshFD, &freshStat); err != nil {
		return err
	}
	if err := validateLockStat(freshStat, manager.owner, manager.group); err != nil || !sameFile(freshStat, file.stat) {
		return fmt.Errorf("configured %s lock changed: %w", kind, err)
	}
	return nil
}

func WithNormalActivationTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, NormalActivationTimeout)
}

func validKind(kind Kind) bool { return kind == MutationAdmission || kind == Exposure }

func lockName(kind Kind) string {
	if kind == MutationAdmission {
		return "mutation-admission.lock"
	}
	return "exposure.lock"
}

func validateConfig(config Config) error {
	if config.RootPath == "" || config.RootPath != strings.TrimSpace(config.RootPath) || !filepath.IsAbs(config.RootPath) || filepath.Clean(config.RootPath) != config.RootPath {
		return fmt.Errorf("independent lock root must be a clean absolute path")
	}
	if config.Owner != uint32(unix.Geteuid()) || config.Group != uint32(unix.Getegid()) {
		return fmt.Errorf("independent locks must be owned by the helper identity")
	}
	if config.Mode.Perm() != 0o700 || config.Mode&^fs.FileMode(0o777) != 0 {
		return fmt.Errorf("independent lock root mode must be 0700")
	}
	return nil
}

func openLockFile(rootFD int, name string, owner, group uint32) (lockFile, error) {
	fd, err := unix.Openat(rootFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return lockFile{}, fmt.Errorf("open %s: %w", name, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return lockFile{}, err
	}
	if err := validateLockStat(stat, owner, group); err != nil {
		_ = unix.Close(fd)
		return lockFile{}, fmt.Errorf("lock %s: %w", name, err)
	}
	return lockFile{name: name, fd: fd, stat: stat}, nil
}

func validateDirectory(stat unix.Stat_t, owner, group uint32, mode fs.FileMode) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != uint32(mode.Perm()) || stat.Uid != owner || stat.Gid != group {
		return fmt.Errorf("directory type, owner, group, or mode mismatch")
	}
	return nil
}

func validateLockStat(stat unix.Stat_t, owner, group uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != owner || stat.Gid != group || stat.Nlink != 1 {
		return fmt.Errorf("lock must be a singly linked helper-owned regular file with mode 0600")
	}
	return nil
}

func sameDirectory(actual, expected unix.Stat_t) bool {
	return actual.Dev == expected.Dev && actual.Ino == expected.Ino && actual.Mode == expected.Mode && actual.Uid == expected.Uid && actual.Gid == expected.Gid
}

func sameFile(actual, expected unix.Stat_t) bool {
	return sameDirectory(actual, expected) && actual.Nlink == expected.Nlink
}

func openAbsoluteDirectory(path string) (int, unix.Stat_t, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	if path != "/" {
		for component := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
			next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			_ = unix.Close(fd)
			if openErr != nil {
				return -1, unix.Stat_t{}, openErr
			}
			fd = next
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	return fd, stat, nil
}
