//go:build linux

package bootstrap

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func plannedBootstrapPaths(paths Paths) ([]string, error) {
	values := []string{paths.Journal, paths.StartupAuthority, paths.CommitPath, paths.PersistentRoot, paths.InstallationRoot, paths.StateRoot, paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, paths.SysusersPath, paths.BinaryPath, filepath.Dir(paths.BinaryPath), filepath.Join(paths.PersistentRoot, ".bootstrap-filetxn")}
	for _, name := range []string{"lanpanel-management.socket", "lanpanel-ui.service", "lanpanel-helper.service", "lanpanel-timer.service", "lanpanel-timer.timer", "lanpanel-recovery.service"} {
		values = append(values, filepath.Join(paths.SystemdRoot, name))
	}
	slices.Sort(values)
	values = slices.Compact(values)
	for _, path := range values {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("bootstrap planned path is invalid")
		}
	}
	return values, nil
}

func verifyResumeInventory(journal Journal) error {
	for _, root := range []string{journal.Paths.PersistentRoot, journal.Paths.RuntimeRoot} {
		if _, err := walkBounded(root, 512); err != nil {
			return err
		}
	}
	for _, path := range journal.PlannedPaths {
		if path == journal.Paths.SystemdRoot || path == journal.Paths.PersistentRoot || path == journal.Paths.RuntimeRoot {
			continue
		}
		if _, err := os.Lstat(path); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func walkBounded(root string, maximum int) ([]string, error) {
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	result := []string{root}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		result = append(result, path)
		if len(result) > maximum {
			return fmt.Errorf("bootstrap inventory exceeds its fixed bound")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("bootstrap inventory contains a symlink")
		}
		return nil
	})
	return result, err
}
