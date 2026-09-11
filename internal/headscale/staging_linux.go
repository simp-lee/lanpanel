//go:build linux

package headscale

import (
	"fmt"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// reconcileAcquisitionStaging rejects foreign residue left by an interrupted
// transaction. It is retained as a narrow recovery primitive; public lifecycle
// never acquires a new Headscale source.
func reconcileAcquisitionStaging(directory, name string, owner filetxn.Owner, maximum int64) error {
	parent, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	closeErr := unix.Close(fd)
	if statErr != nil || closeErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != 0o600 || stat.Size < 0 || stat.Size > maximum {
		return fmt.Errorf("headscale acquisition staging evidence is foreign")
	}
	if err := unix.Unlinkat(parent, filepath.Base(name), 0); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

var _ = os.ErrNotExist
