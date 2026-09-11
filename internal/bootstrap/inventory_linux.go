//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/nginx"
	"os"
	"path/filepath"
	"slices"
)

func plannedBootstrapPaths(paths Paths) ([]string, error) {
	nginxPaths := nginx.FixedPaths()
	if paths != FixedPaths() {
		nginxPaths = testNginxPaths(paths)
	}
	values := []string{paths.Journal, paths.StartupAuthority, paths.CommitPath, paths.PersistentRoot, paths.InstallationRoot, paths.ACMEAccountKey, filepath.Join(paths.InstallationRoot, "acme-account.contact"), paths.StateRoot, paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, paths.SysusersPath, paths.BinaryPath, publicCommandPath(paths), filepath.Dir(paths.BinaryPath), "/usr/sbin/policy-rc.d", "/usr/lib/lanpanel/dependencies", "/usr/lib/lanpanel/dependencies/lego", "/usr/lib/lanpanel/dependencies/tailscale", "/usr/lib/lanpanel/dependencies/headscale", "/usr/lib/lanpanel/dependencies/headscale.tar.gz", "/etc/sysusers.d/lanpanel-headscale.conf", filepath.Join(paths.OwnershipRoot, "installation.json"), filepath.Join(paths.OwnershipRoot, "installation.json"), filepath.Join(paths.PersistentRoot, ".bootstrap-filetxn"), filepath.Join(paths.PersistentRoot, "certificates"), filepath.Join(paths.PersistentRoot, "certificates", "chroot"), filepath.Join(paths.PersistentRoot, "certificates", "staging"), filepath.Join(paths.PersistentRoot, "certificates", "webroot"), filepath.Join(paths.PersistentRoot, "certificates", "bundles"), filepath.Join(paths.PersistentRoot, "certificates", "active"), filepath.Join(paths.PersistentRoot, "certificates", "bootstrap"), "/etc/lanpanel-public", "/etc/lanpanel-public/basic", "/var/log/lanpanel/goaccess", "/run/lanpanel-goaccess", "/etc/lanpanel-public/basic/.txn", nginxPaths.ConfigRoot, nginxPaths.StateRoot, nginxPaths.AuditPath, filepath.Dir(nginxPaths.AuditPath)}
	for _, name := range []string{"lanpanel-management.socket", "lanpanel-ui.service", "lanpanel-runtime.service", "lanpanel-process-guard.service", "lanpanel-helper.service", "lanpanel-timer.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"} {
		values = append(values, filepath.Join(paths.SystemdRoot, name))
	}
	values = append(values, filepath.Join(paths.SystemdRoot, "nginx.service"))
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
