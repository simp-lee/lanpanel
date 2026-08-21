//go:build linux

package goaccess

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const maximumAccessLogBytes int64 = 10 << 20

func RunRetention(args []string) error {
	installationID, resourceID := os.Getenv("LANPANEL_INSTALLATION_ID"), os.Getenv("LANPANEL_RESOURCE_ID")
	if len(args) != 0 || !validInstallationID(installationID) || !validResourceID(resourceID) {
		return fmt.Errorf("GoAccess retention requires fixed root timer invocation")
	}
	paths, err := DerivePaths(resourceID, 1)
	if err != nil {
		return err
	}
	uid, gid, _, _ := numeric(installationID, resourceID)
	if uint32(os.Geteuid()) != uid || uint32(os.Getegid()) != gid {
		return fmt.Errorf("GoAccess retention identity differs")
	}
	return rotateAccessLog(paths.AccessLog, paths.RetentionLock, uid, gid)
}

func rotateAccessLog(path, lockPath string, expectedUID, expectedGID uint32) error {
	lock, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(lock) }()
	var lockStat unix.Stat_t
	if err = unix.Fstat(lock, &lockStat); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Uid != expectedUID || lockStat.Gid != expectedGID || lockStat.Mode&0o7777 != 0o600 {
		return fmt.Errorf("GoAccess retention lock identity unsafe")
	}
	if err = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("GoAccess retention already running: %w", err)
	}
	defer func() { _ = unix.Flock(lock, unix.LOCK_UN) }()

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != expectedUID || stat.Gid != expectedGID || info.Mode().Perm() != 0o640 {
		return fmt.Errorf("GoAccess log identity unsafe")
	}
	if info.Size() <= maximumAccessLogBytes {
		return nil
	}
	source, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(source.Close)
	opened, err := source.Stat()
	if err != nil {
		return err
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return fmt.Errorf("GoAccess log changed during retention")
	}
	buffer := make([]byte, maximumAccessLogBytes)
	n, readErr := source.ReadAt(buffer, info.Size()-maximumAccessLogBytes)
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	validate := func(candidate string, temporary bool) error {
		entry, observeErr := os.Lstat(candidate)
		if observeErr != nil {
			return observeErr
		}
		value, valid := entry.Sys().(*syscall.Stat_t)
		mode := entry.Mode().Perm()
		modeOK := mode == 0o640 || temporary && mode == 0o600
		if !valid || !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 || value.Nlink != 1 || value.Uid != expectedUID || value.Gid != expectedGID || !modeOK {
			return fmt.Errorf("GoAccess retained log identity unsafe")
		}
		return nil
	}
	snapshot := path + ".1"
	if _, err = os.Lstat(snapshot); err == nil {
		if err = validate(snapshot, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp := snapshot + ".lanpanel"
	if _, err = os.Lstat(temp); err == nil {
		if err = validate(temp, true); err != nil {
			return err
		}
		if err = os.Remove(temp); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := out.Write(buffer[:n])
	syncErr := out.Sync()
	closeErr := out.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err = os.Chmod(temp, 0o640); err != nil {
		return err
	}
	if err = validate(temp, false); err != nil {
		return err
	}
	if err = os.Rename(temp, snapshot); err != nil {
		return err
	}
	if err = source.Truncate(0); err != nil {
		return err
	}
	if err = source.Sync(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(parent.Close)
	return parent.Sync()
}
