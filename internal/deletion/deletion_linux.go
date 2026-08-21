//go:build linux

package deletion

import (
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	managedresource "lanpanel/internal/resource"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func Cleanup(resource domain.AppResource, allowedUIDs []uint32) ([]string, error) {
	if resource.Lifecycle != domain.LifecycleDeleting || resource.PublicationRecord.State != domain.PublicationUnpublished {
		return nil, fmt.Errorf("resource cleanup requires deleting unpublished authority")
	}
	if resource.ManagedProcess != nil && resource.ManagedProcess.Requested != domain.ProcessRequestedStopped {
		return nil, fmt.Errorf("resource cleanup requires requested stopped")
	}
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		if len(resource.ManagedPaths) != 0 {
			return nil, fmt.Errorf("tailnet resource carries local managed inventory")
		}
		return []string{}, nil
	}
	paths, err := managedresource.DerivePaths(resource.ID)
	if err != nil {
		return nil, err
	}
	expected := paths.ManagedPaths()
	if !slices.Equal(resource.ManagedPaths, expected) {
		return nil, fmt.Errorf("resource managed inventory changed")
	}
	allowed := map[uint32]bool{0: true}
	for _, uid := range allowedUIDs {
		allowed[uid] = true
	}
	removed := []string{}
	for index := len(expected) - 1; index >= 0; index-- {
		path := expected[index]
		if path == paths.ResourceRoot {
			continue
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			if syncErr := syncDeletionParent(path); syncErr != nil {
				return removed, syncErr
			}
			continue
		}
		if err != nil {
			return removed, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !allowed[stat.Uid] || info.Mode()&os.ModeSymlink != 0 {
			return removed, fmt.Errorf("managed path %q is foreign", path)
		}
		if info.IsDir() || info.Mode().IsRegular() {
			if err := removeDurably(path); err != nil {
				return removed, err
			}
		} else {
			return removed, fmt.Errorf("managed path %q still has non-regular runtime type", path)
		}
		removed = append(removed, path)
	}
	if _, err := os.Lstat(paths.ResourceRoot); err == nil {
		values, walkErr := walkOwnedTree(paths.ResourceRoot, allowed)
		if walkErr != nil {
			return removed, walkErr
		}
		for index := len(values) - 1; index >= 0; index-- {
			if err := removeDurably(values[index]); err != nil {
				return removed, err
			}
			removed = append(removed, values[index])
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if syncErr := syncDeletionParent(paths.ResourceRoot); syncErr != nil {
			return removed, syncErr
		}
	} else {
		return removed, err
	}
	slices.Sort(removed)
	return removed, nil
}

func removeDurably(path string) error {
	parent, name := filepath.Dir(path), filepath.Base(path)
	fd, err := openDeletionParent(parent)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	flag := 0
	if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		flag = unix.AT_REMOVEDIR
	} else if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("managed deletion target type changed")
	}
	if err := unix.Unlinkat(fd, name, flag); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func openDeletionParent(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("managed deletion parent authority changed")
	}
	return fd, nil
}

func syncDeletionParent(path string) error {
	parent := filepath.Dir(path)
	for {
		fd, err := openDeletionParent(parent)
		if err == nil {
			syncErr := unix.Fsync(fd)
			closeErr := unix.Close(fd)
			return errors.Join(syncErr, closeErr)
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return err
		}
		parent = next
	}
}

func walkOwnedTree(root string, allowed map[uint32]bool) ([]string, error) {
	clean := filepath.Clean(root)
	if !strings.HasPrefix(clean, "/var/lib/lanpanel/resources/res_") {
		return nil, fmt.Errorf("resource root is outside fixed inventory")
	}
	var rootDevice uint64
	result := []string{}
	err := filepath.WalkDir(clean, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !allowed[stat.Uid] || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("resource tree contains foreign path %q", path)
		}
		if path == clean {
			rootDevice = uint64(stat.Dev)
		} else if uint64(stat.Dev) != rootDevice {
			return fmt.Errorf("resource tree contains nested mount")
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("resource tree contains active or unsupported file type")
		}
		result = append(result, path)
		if len(result) > 4096 {
			return fmt.Errorf("resource tree inventory is unbounded")
		}
		return nil
	})
	return result, err
}
