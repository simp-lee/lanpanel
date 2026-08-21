//go:build linux

package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type MutationConfig struct {
	RootPath     string
	Owner, Group uint32
	Mode         fs.FileMode
	Authority    locks.Authority
}
type MutationSet struct {
	config   MutationConfig
	rootFD   int
	rootStat unix.Stat_t
	closed   atomic.Bool
}
type MutationLease struct {
	fd        int
	target    string
	authority locks.Authority
	released  atomic.Bool
}

func OpenMutationSet(config MutationConfig) (*MutationSet, error) {
	if config.RootPath == "" || !filepath.IsAbs(config.RootPath) || filepath.Clean(config.RootPath) != config.RootPath || config.Owner != uint32(os.Geteuid()) || config.Group != uint32(os.Getegid()) || config.Mode.Perm() != 0o700 || !config.Authority.Valid() {
		return nil, fmt.Errorf("mutation lock root configuration is invalid")
	}
	fd, err := unix.Open(config.RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := validateMutationRoot(stat, config); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &MutationSet{config: config, rootFD: fd, rootStat: stat}, nil
}

func (set *MutationSet) Authority() locks.Authority {
	if set == nil {
		return locks.Authority{}
	}
	return set.config.Authority
}

func (set *MutationSet) Close() error {
	if set.closed.Swap(true) {
		return nil
	}
	return unix.Close(set.rootFD)
}

// AcquireExposure fixes the only normal-operation order: resource mutation
// first, then the installation exposure lock. Ordinary operations must have
// released the short-lived admission lock before entering this phase.
func (set *MutationSet) AcquireExposure(ctx context.Context, target string, manager *locks.Manager) (*MutationLease, *locks.Lease, error) {
	if set == nil || set.closed.Load() || manager == nil || manager.Authority() != set.config.Authority || manager.Held(locks.Exposure) || manager.Held(locks.MutationAdmission) || target == "" || target != strings.TrimSpace(target) {
		return nil, nil, fmt.Errorf("mutation lock request is invalid")
	}
	if err := set.revalidate(); err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256([]byte(target))
	name := "mutation-" + hex.EncodeToString(sum[:]) + ".lock"
	fd, err := unix.Openat(set.rootFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != set.config.Owner || stat.Gid != set.config.Group || stat.Nlink != 1 {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("mutation lock file metadata is unsafe")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = unix.Close(fd)
			return nil, nil, err
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(fd)
			return nil, nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	mutation := &MutationLease{fd: fd, target: target, authority: set.config.Authority}
	exposure, err := manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		_ = mutation.Release()
		return nil, nil, err
	}
	return mutation, exposure, nil
}

func (lease *MutationLease) Active() bool {
	return lease != nil && !lease.released.Load() && lease.fd >= 0
}

func (lease *MutationLease) Target() string {
	if lease == nil {
		return ""
	}
	return lease.target
}

func (lease *MutationLease) Authority() locks.Authority {
	if lease == nil || !lease.Active() {
		return locks.Authority{}
	}
	return lease.authority
}

func (lease *MutationLease) Release() error {
	if lease == nil || !lease.released.CompareAndSwap(false, true) {
		return fmt.Errorf("mutation lease is not active")
	}
	return errors.Join(unix.Flock(lease.fd, unix.LOCK_UN), unix.Close(lease.fd))
}

func ReleaseExposure(mutation *MutationLease, exposure *locks.Lease) error {
	var result error
	if exposure != nil {
		result = errors.Join(result, exposure.Release())
	}
	if mutation != nil {
		result = errors.Join(result, mutation.Release())
	}
	return result
}

func (set *MutationSet) revalidate() error {
	var opened unix.Stat_t
	if err := unix.Fstat(set.rootFD, &opened); err != nil {
		return err
	}
	if err := validateMutationRoot(opened, set.config); err != nil || !sameMutationRoot(opened, set.rootStat) {
		return fmt.Errorf("open mutation lock root changed: %w", err)
	}
	var fresh unix.Stat_t
	if err := unix.Lstat(set.config.RootPath, &fresh); err != nil {
		return err
	}
	if err := validateMutationRoot(fresh, set.config); err != nil || !sameMutationRoot(fresh, set.rootStat) {
		return fmt.Errorf("configured mutation lock root changed: %w", err)
	}
	return nil
}

func validateMutationRoot(stat unix.Stat_t, config MutationConfig) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != uint32(config.Mode.Perm()) || stat.Uid != config.Owner || stat.Gid != config.Group {
		return fmt.Errorf("mutation lock root must be helper-owned mode 0700")
	}
	return nil
}

func sameMutationRoot(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}
