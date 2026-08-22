//go:build linux

package qualification

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type runLock struct{ fd int }

func acquireRunLock(path string) (*runLock, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("qualification run lock path is invalid")
	}
	parentFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	var parent unix.Stat_t
	if unix.Fstat(parentFD, &parent) != nil || parent.Uid != uint32(os.Geteuid()) || parent.Mode&0o077 != 0 {
		return nil, fmt.Errorf("qualification run lock parent is unsafe")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("qualification run lock authority is unsafe")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("qualification run is already active: %w", err)
	}
	return &runLock{fd: fd}, nil
}

func (lock *runLock) Close() error {
	if lock == nil || lock.fd < 0 {
		return nil
	}
	unlockErr := unix.Flock(lock.fd, unix.LOCK_UN)
	closeErr := unix.Close(lock.fd)
	lock.fd = -1
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
