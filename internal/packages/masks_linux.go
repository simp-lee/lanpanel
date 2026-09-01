//go:build linux

package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const FixedSystemdMaskDirectory = "/etc/systemd/system"

type MaskPoint string

const (
	MaskPointAfterCreate         MaskPoint = "after_create"
	MaskPointBeforeDirectorySync MaskPoint = "before_directory_sync"
	MaskPointAfterDirectorySync  MaskPoint = "after_directory_sync"
)

type maskFaultFunc func(MaskPoint, string) error

type UnitMasks struct {
	directory string
	strict    bool
	fault     maskFaultFunc
}

func NewUnitMasks(directory string) (*UnitMasks, error) {
	if directory != FixedSystemdMaskDirectory {
		return nil, fmt.Errorf("package masks require the fixed systemd authority")
	}
	if err := validateMaskParentChain(directory); err != nil {
		return nil, err
	}
	return &UnitMasks{directory: directory, strict: true}, nil
}

func newTestUnitMasks(directory string) *UnitMasks { return &UnitMasks{directory: directory} }

func newTestUnitMasksWithFault(directory string, fault maskFaultFunc) *UnitMasks {
	return &UnitMasks{directory: directory, fault: fault}
}

func (masks *UnitMasks) Mask(ctx context.Context, units []string, pendingIntent string, persistIntent func(string) error, persistIdentity func(MaskIdentity) error) (MaskResult, error) {
	if masks == nil || !sortedUniqueUnits(units) || persistIntent == nil || persistIdentity == nil || pendingIntent != "" && (len(units) == 0 || pendingIntent != units[0]) {
		return MaskResult{}, fmt.Errorf("package unit mask request is invalid")
	}
	directory, err := openMaskDirectory(masks.directory, masks.strict)
	if err != nil {
		return MaskResult{}, err
	}
	defer func() { _ = unix.Close(directory) }()
	result := MaskResult{Masks: []MaskIdentity{}}
	for _, unit := range units {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		var stat unix.Stat_t
		statErr := unix.Fstatat(directory, unit, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if pendingIntent != "" && statErr == nil {
			return result, fmt.Errorf("package mask intent lacks an exact created-inode identity")
		}
		if pendingIntent == "" && statErr == nil {
			if err := verifyMaskStat(directory, unit, stat); err != nil {
				return result, err
			}
			identity := maskIdentity(unit, true, stat)
			if err := persistIdentity(identity); err != nil {
				return result, fmt.Errorf("persist preexisting package mask identity: %w", err)
			}
			result.Masks = append(result.Masks, identity)
			continue
		}
		if pendingIntent == "" {
			if !errors.Is(statErr, unix.ENOENT) {
				return result, fmt.Errorf("inspect package no-autostart mask: %w", statErr)
			}
			if err := persistIntent(unit); err != nil {
				return result, fmt.Errorf("persist package mask intent: %w", err)
			}
		} else if pendingIntent != unit {
			return result, fmt.Errorf("package mask intent does not name the exact next unit")
		}

		if errors.Is(statErr, unix.ENOENT) {
			if err := unix.Symlinkat("/dev/null", directory, unit); err != nil {
				return result, fmt.Errorf("create package no-autostart mask: %w", err)
			}
			if err := masks.check(MaskPointAfterCreate, unit); err != nil {
				return result, err
			}
		} else if statErr != nil {
			return result, fmt.Errorf("inspect intended package no-autostart mask: %w", statErr)
		}
		if err := unix.Fstatat(directory, unit, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return result, fmt.Errorf("observe intended package no-autostart mask: %w", err)
		}
		if err := verifyMaskStat(directory, unit, stat); err != nil {
			return result, err
		}
		if err := masks.check(MaskPointBeforeDirectorySync, unit); err != nil {
			return result, err
		}
		if err := unix.Fsync(directory); err != nil {
			return result, fmt.Errorf("sync package no-autostart mask %q: %w", unit, err)
		}
		if err := masks.check(MaskPointAfterDirectorySync, unit); err != nil {
			return result, err
		}
		identity := maskIdentity(unit, false, stat)
		if err := persistIdentity(identity); err != nil {
			return result, fmt.Errorf("persist durable created package mask identity: %w", err)
		}
		result.Masks = append(result.Masks, identity)
		pendingIntent = ""
	}
	return result, nil
}

func (masks *UnitMasks) check(point MaskPoint, unit string) error {
	if masks.fault == nil {
		return nil
	}
	if err := masks.fault(point, unit); err != nil {
		return fmt.Errorf("package mask fault at %s for %q: %w", point, unit, err)
	}
	return nil
}

func verifyMaskStat(directory int, unit string, stat unix.Stat_t) error {
	target, err := readlinkAt(directory, unit)
	if stat.Mode&unix.S_IFMT != unix.S_IFLNK || err != nil || target != "/dev/null" {
		return fmt.Errorf("package unit mask collides with a non-mask systemd override")
	}
	return nil
}

func maskIdentity(unit string, preexisting bool, stat unix.Stat_t) MaskIdentity {
	return MaskIdentity{Unit: unit, Preexisting: preexisting, Device: uint64(stat.Dev), Inode: stat.Ino, CTimeSec: stat.Ctim.Sec, CTimeNsec: stat.Ctim.Nsec}
}

func (masks *UnitMasks) Verify(ctx context.Context, identities []MaskIdentity) error {
	if masks == nil || !validMaskIdentities(identities) {
		return fmt.Errorf("package unit mask verification request is invalid")
	}
	directory, err := openMaskDirectory(masks.directory, masks.strict)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(directory) }()
	for _, identity := range identities {
		if err := ctx.Err(); err != nil {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directory, identity.Unit, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFLNK || uint64(stat.Dev) != identity.Device || stat.Ino != identity.Inode || stat.Ctim.Sec != identity.CTimeSec || stat.Ctim.Nsec != identity.CTimeNsec {
			return fmt.Errorf("package unit mask %q is missing, replaced, or changed", identity.Unit)
		}
		target, err := readlinkAt(directory, identity.Unit)
		if err != nil || target != "/dev/null" {
			return fmt.Errorf("package unit mask %q target changed", identity.Unit)
		}
	}
	return nil
}

func (masks *UnitMasks) Unmask(ctx context.Context, identities []MaskIdentity) error {
	if masks == nil || !validMaskIdentities(identities) {
		return fmt.Errorf("package unit unmask request is invalid")
	}
	directory, err := openMaskDirectory(masks.directory, masks.strict)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(directory) }()
	for _, identity := range identities {
		if identity.Preexisting {
			return fmt.Errorf("package transaction cannot remove a preexisting mask")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var stat unix.Stat_t
		statErr := unix.Fstatat(directory, identity.Unit, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(statErr, unix.ENOENT) {
			continue
		}
		if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFLNK || uint64(stat.Dev) != identity.Device || stat.Ino != identity.Inode || stat.Ctim.Sec != identity.CTimeSec || stat.Ctim.Nsec != identity.CTimeNsec {
			return fmt.Errorf("transaction-created package mask is replaced or changed")
		}
		target, err := readlinkAt(directory, identity.Unit)
		if err != nil || target != "/dev/null" {
			return fmt.Errorf("transaction-created package mask target changed")
		}
		if err := unix.Unlinkat(directory, identity.Unit, 0); err != nil {
			return fmt.Errorf("remove transaction-created package mask: %w", err)
		}
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("sync package mask removal: %w", err)
	}
	return nil
}

func openMaskDirectory(path string, strict bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("systemd mask directory is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open fixed systemd mask directory: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || strict && stat.Uid != 0 || !strict && stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("systemd mask directory owner, mode, or type is unsafe")
	}
	return fd, nil
}

func validateMaskParentChain(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		var stat unix.Stat_t
		if err := unix.Lstat(current, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return fmt.Errorf("systemd mask parent is linked, non-directory, non-root-owned, or writable")
		}
		if current == "/" {
			return nil
		}
	}
}

func readlinkAt(directory int, name string) (string, error) {
	buffer := make([]byte, 256)
	length, err := unix.Readlinkat(directory, name, buffer)
	if err != nil || length <= 0 || length == len(buffer) {
		return "", fmt.Errorf("read package unit mask target")
	}
	return string(buffer[:length]), nil
}
