//go:build linux

package filetxn

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// CleanPrivateStaging removes inert Put artifacts from a dedicated 0700
// staging directory. Callers must serialize this with writers using the same
// directory.
func CleanPrivateStaging(path string, owner Owner, maximumBytes int64) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximumBytes <= 0 || maximumBytes > MaximumContentBytes {
		return fmt.Errorf("private staging cleanup request is invalid")
	}
	fd, stat, err := openAbsoluteDirectory(path)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("private staging descriptor is invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	metadata := Metadata{Owner: owner, Mode: 0o700}
	if err := validateDirectoryMetadata(stat, metadata); err != nil {
		return fmt.Errorf("private staging directory metadata is unsafe: %w", err)
	}
	parentFD, parentStat, err := openAbsoluteDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if err := validateDirectoryMetadata(parentStat, metadata); err != nil {
		return fmt.Errorf("private staging parent metadata is unsafe: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync private staging destination: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync private staging source: %w", err)
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
		return err
	}
	identities := make(map[string]unix.Stat_t, len(entries))
	for _, entry := range entries {
		if !privateStagingName(entry.Name()) {
			return fmt.Errorf("private staging entry name is unsafe")
		}
		child, err := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("open private staging entry no-follow: %w", err)
		}
		var childStat unix.Stat_t
		statErr := unix.Fstat(child, &childStat)
		closeErr := unix.Close(child)
		if statErr != nil || closeErr != nil || childStat.Mode&unix.S_IFMT != unix.S_IFREG || childStat.Mode&0o7777 != 0o600 || childStat.Uid != owner.UID || childStat.Gid != owner.GID || childStat.Nlink != 1 || childStat.Size < 0 || childStat.Size > maximumBytes {
			return fmt.Errorf("private staging entry metadata is unsafe")
		}
		identities[entry.Name()] = childStat
	}
	for _, entry := range entries {
		before := identities[entry.Name()]
		var fresh unix.Stat_t
		if err := unix.Fstatat(fd, entry.Name(), &fresh, unix.AT_SYMLINK_NOFOLLOW); err != nil || compareIdentity(fresh, before) != nil || fresh.Size != before.Size || fresh.Mtim != before.Mtim || fresh.Ctim != before.Ctim {
			return fmt.Errorf("private staging entry changed before cleanup")
		}
		if err := unix.Unlinkat(fd, entry.Name(), 0); err != nil {
			return err
		}
	}
	if len(entries) != 0 {
		return unix.Fsync(fd)
	}
	return nil
}

func privateStagingName(name string) bool {
	const prefix = ".lanpanel-txn."
	if !strings.HasPrefix(name, prefix) || strings.ToLower(name) != name {
		return false
	}
	identity := strings.TrimPrefix(name, prefix)
	if len(identity) != 16+1+24 || identity[16] != '.' {
		return false
	}
	_, firstErr := hex.DecodeString(identity[:16])
	_, secondErr := hex.DecodeString(identity[17:])
	return firstErr == nil && secondErr == nil
}
