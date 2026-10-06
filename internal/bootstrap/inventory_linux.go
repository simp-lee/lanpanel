//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/helper"
	"lanpanel/internal/nginx"
	"lanpanel/internal/packages"
	managedprocess "lanpanel/internal/process"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func plannedBootstrapPaths(paths Paths) ([]string, error) {
	nginxPaths := nginx.FixedPaths()
	if paths != FixedPaths() {
		nginxPaths = testNginxPaths(paths)
	}
	values := []string{paths.Journal, paths.StartupAuthority, paths.CommitPath, paths.PersistentRoot, paths.InstallationRoot, paths.ACMEAccountKey, filepath.Join(paths.InstallationRoot, "acme-account.contact"), paths.StateRoot, paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, paths.SysusersPath, paths.BinaryPath, publicCommandPath(paths), filepath.Dir(paths.BinaryPath), filepath.Join(filepath.Dir(paths.BinaryPath), ".lanpanel-filetxn"), filepath.Join(filepath.Dir(publicCommandPath(paths)), ".lanpanel-filetxn"), "/usr/sbin/policy-rc.d", "/usr/sbin/.lanpanel-filetxn", "/usr/lib/lanpanel/dependencies", "/usr/lib/lanpanel/dependencies/.lanpanel-filetxn", "/usr/lib/lanpanel/dependencies/lego", "/usr/lib/lanpanel/dependencies/tailscale", "/usr/lib/lanpanel/dependencies/goaccess", "/usr/lib/lanpanel/dependencies/headscale", "/usr/lib/lanpanel/dependencies/headscale.tar.gz", "/etc/sysusers.d/lanpanel-headscale.conf", "/etc/sysusers.d/.lanpanel-filetxn", filepath.Join(filepath.Dir(paths.StartupAuthority), ".lanpanel-filetxn"), filepath.Join(paths.PersistentRoot, "sbin", ".lanpanel-filetxn"), helper.FixedIdentityConfigPath, filepath.Join(paths.OwnershipRoot, "installation.json"), filepath.Join(paths.OwnershipRoot, "installation.json"), filepath.Join(paths.PersistentRoot, ".bootstrap-filetxn"), filepath.Join(paths.StateRoot, ".filetxn"), filepath.Join(paths.SafetyRoot, ".filetxn"), filepath.Join(paths.OwnershipRoot, ".lanpanel-filetxn"), filepath.Join(paths.PersistentRoot, "certificates"), filepath.Join(paths.PersistentRoot, "certificates", "chroot"), filepath.Join(paths.PersistentRoot, "certificates", "staging"), filepath.Join(paths.PersistentRoot, "certificates", "webroot"), filepath.Join(paths.PersistentRoot, "certificates", "bundles"), filepath.Join(paths.PersistentRoot, "certificates", "active"), filepath.Join(paths.PersistentRoot, "certificates", "bootstrap"), "/etc/lanpanel-public", "/etc/lanpanel-public/basic", "/var/log/lanpanel/goaccess", "/var/log/lanpanel/goaccess/.retention-reopen.lock", "/run/lanpanel-goaccess", "/etc/lanpanel-public/basic/.txn", nginxPaths.ConfigRoot, nginxPaths.StagingPath(), filepath.Join(nginxPaths.ConfigRoot, nginx.AppsDirectory), filepath.Join(nginxPaths.ConfigRoot, nginx.ChallengesDirectory), filepath.Join(nginxPaths.ConfigRoot, nginx.ControlDirectory), filepath.Join(nginxPaths.ConfigRoot, nginx.ManagementDirectory), filepath.Join(nginxPaths.ConfigRoot, nginx.TemporaryDirectory), nginxPaths.StateRoot, nginxPaths.AuditPath, filepath.Dir(nginxPaths.AuditPath)}
	values = append(values, filepath.Join(paths.LockRoot, "mutation-admission.lock"), filepath.Join(paths.LockRoot, "exposure.lock"), filepath.Join(paths.RuntimeRoot, filepath.Base(helper.FixedSocketPath)), nginxPaths.PIDPath)
	if paths == FixedPaths() {
		values = append(values, managedprocess.ProcessBootReadyPath())
	}
	for _, name := range []string{"lanpanel-management.socket", "lanpanel-ui.service", "lanpanel-runtime.service", "lanpanel-process-guard.service", "lanpanel-helper.service", "lanpanel-timer.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"} {
		values = append(values, filepath.Join(paths.SystemdRoot, name))
	}
	values = append(values, filepath.Join(paths.SystemdRoot, "nginx.service"), filepath.Join(paths.SystemdRoot, ".lanpanel-filetxn"))
	values = append(values,
		nginxPaths.MainPath(), nginxPaths.SanitizerPath(), nginxPaths.ManifestPath(), nginxPaths.AuditPath, nginxPaths.StateRoot, filepath.Join(nginxPaths.StateRoot, ".lanpanel-contraction-filetxn"),
		filepath.Join(paths.PersistentRoot, ".lanpanel-filetxn"), filepath.Join(paths.PersistentRoot, ".bootstrap-filetxn"),
		filepath.Join(paths.InstallationRoot, ".lanpanel-filetxn"), filepath.Join(paths.InstallationRoot, "acme-account.key"), filepath.Join(paths.InstallationRoot, "admin-token"), filepath.Join(paths.InstallationRoot, "bundle.json"), filepath.Join(paths.InstallationRoot, "default-rejection.crt"), filepath.Join(paths.InstallationRoot, "default-rejection.key"), filepath.Join(paths.InstallationRoot, "helper-identities.json"), filepath.Join(paths.InstallationRoot, "host-fingerprint"), filepath.Join(paths.InstallationRoot, "managed-confinement.json"), filepath.Join(paths.InstallationRoot, "os-profile.digest"), filepath.Join(paths.InstallationRoot, "release-authority.digest"),
		filepath.Join(paths.StateRoot, ".filetxn"), filepath.Join(paths.StateRoot, "normal.json"), filepath.Join(paths.SafetyRoot, ".filetxn"), filepath.Join(paths.SafetyRoot, "emergency"), filepath.Join(paths.SafetyRoot, "state.json"), filepath.Join(paths.OwnershipRoot, ".filetxn"), filepath.Join(paths.OwnershipRoot, "records"), filepath.Join(paths.OwnershipRoot, "installation.json"),
		filepath.Join(paths.PackageRoot, ".filetxn"), filepath.Join(paths.PackageRoot, "journals"), filepath.Join(paths.PackageRoot, "plans"), filepath.Join(paths.PackageRoot, "transactions"), filepath.Join(paths.PackageRoot, "staging"),
		filepath.Join(filepath.Dir(paths.StartupAuthority), ".lanpanel-filetxn"), "/var/log/lanpanel", "/var/log/lanpanel/install.log", "/var/log/lanpanel/.lanpanel-filetxn", "/usr/lib/lanpanel/.lanpanel-filetxn")
	for _, name := range []string{"lanpanel-runtime.service", "lanpanel-helper.service", "lanpanel-ui.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"} {
		values = append(values, filepath.Join(paths.SystemdRoot, "multi-user.target.wants", name))
	}
	values = append(values, filepath.Join(paths.SystemdRoot, "sockets.target.wants", "lanpanel-management.socket"), filepath.Join(paths.SystemdRoot, "timers.target.wants", "lanpanel-timer.timer"))
	if paths == FixedPaths() {
		values = append(values, domain.HeadscaleManagedPaths()...)
		controlPaths := control.FixedPaths()
		values = append(values, controlPaths.ConfigRoot, filepath.Join(controlPaths.ConfigRoot, ".lanpanel-filetxn"), controlPaths.Config, controlPaths.Policy, controlPaths.Unit, controlPaths.RuntimeRoot, controlPaths.JournalRoot, controlPaths.Database, controlPaths.NoiseKey, controlPaths.DERPKey, controlPaths.Journal, controlPaths.JournalStaging, controlPaths.ControlSocket, controlPaths.AdminSocket, controlPaths.MetricsSocket, "/var/lib/lanpanel/headscale/identity", "/var/lib/lanpanel/headscale/identity/database-uuid", "/var/lib/lanpanel/headscale/identity/snapshot.json", "/var/lib/lanpanel/headscale/identity/.identity.lanpanel-staging")
		activationPaths := control.FixedActivationPaths()
		values = append(values, activationPaths.ControlRuntime, filepath.Join(controlPaths.ConfigRoot, ".lanpanel-filetxn"), "/etc/systemd/system/.lanpanel-headscale-filetxn", filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale.service"), filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale-control-relay.service"), filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale-stun-relay.service"), filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale-private-probe.service"), filepath.Join(paths.SystemdRoot, "sockets.target.wants", "lanpanel-headscale-control.socket"), filepath.Join(paths.SystemdRoot, "sockets.target.wants", "lanpanel-headscale-stun.socket"), activationPaths.ControlSocketUnit, activationPaths.ControlRelayUnit, activationPaths.STUNSocketUnit, activationPaths.STUNRelayUnit, activationPaths.PrivateProbeUnit)
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

func plannedBootstrapPathsForPlan(paths Paths, plan packages.Plan) ([]string, error) {
	if err := packages.ValidatePlan(plan); err != nil {
		return nil, err
	}
	values, err := plannedBootstrapPaths(paths)
	if err != nil {
		return nil, err
	}
	for _, root := range []string{"transactions", "staging"} {
		values = append(values, filepath.Join(paths.PackageRoot, root, plan.TransactionID))
	}
	if plan.ExternalNginx && len(plan.Packages) == 0 {
		// A read-only reuse must not claim a host's policy-rc.d or its directory.
		values = slices.DeleteFunc(values, func(path string) bool {
			return path == "/usr/sbin/policy-rc.d" || path == "/usr/sbin/.lanpanel-filetxn"
		})
	}
	slices.Sort(values)
	values = slices.Compact(values)
	return values, nil
}

func verifyResumeInventory(journal Journal) error {
	allowed := make(map[string]struct{}, len(journal.PlannedPaths)+len(journal.ArtifactDigests))
	for _, path := range journal.PlannedPaths {
		allowed[path] = struct{}{}
	}
	for path := range journal.ArtifactDigests {
		if filepath.IsAbs(path) {
			allowed[path] = struct{}{}
		}
	}
	for _, root := range []string{journal.Paths.PersistentRoot, journal.Paths.RuntimeRoot} {
		entries, err := walkBounded(root, 512)
		if err != nil {
			return err
		}
		for _, path := range entries {
			if path == root {
				continue
			}
			if _, ok := allowed[path]; ok || resumeInventoryPathAllowed(journal, path) {
				continue
			}
			return fmt.Errorf("bootstrap resume found foreign residue at %q", path)
		}
	}
	return nil
}

func resumeInventoryPathAllowed(journal Journal, path string) bool {
	if journal.Phase != PhasePrepared && path == filepath.Join(journal.Paths.PackageRoot, "journals", journal.PackageTransactionID+".json") {
		return true
	}
	nginxPaths := nginx.FixedPaths()
	if journal.Paths != FixedPaths() {
		nginxPaths = testNginxPaths(journal.Paths)
	}
	exactPaths := []string{
		filepath.Join(journal.Paths.LockRoot, "mutation-admission.lock"),
		filepath.Join(journal.Paths.LockRoot, "exposure.lock"),
		filepath.Join(journal.Paths.RuntimeRoot, filepath.Base(helper.FixedSocketPath)),
		nginxPaths.PIDPath,
	}
	if journal.Paths == FixedPaths() {
		exactPaths = append(exactPaths, managedprocess.ProcessBootReadyPath())
	}
	for _, exact := range exactPaths {
		if path == exact {
			return true
		}
	}
	if journal.Phase != PhasePrepared && journal.Phase != PhaseNginxMasked {
		return false
	}
	for _, root := range []string{
		filepath.Join(journal.Paths.PackageRoot, "transactions", journal.PackageTransactionID),
		filepath.Join(journal.Paths.PackageRoot, "staging", journal.PackageTransactionID),
	} {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
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
