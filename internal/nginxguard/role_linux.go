//go:build linux

package nginxguard

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/contraction"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
	"os"
	"time"
)

func RunStartupGuard(args []string) error { return runGuardRole(args, nginx.GuardStart) }
func RunReloadGuard(args []string) error  { return runGuardRole(args, nginx.GuardReload) }

func runGuardRole(args []string, action nginx.GuardAction) (returnErr error) {
	stop := len(args) == 1 && args[0] == "stop" && action == nginx.GuardReload
	if len(args) != 0 && !stop || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("Nginx guard requires its fixed root unit invocation")
	}
	defer func() {
		if returnErr != nil && !stop {
			returnErr = errors.Join(returnErr, fencedGuardFailure())
		}
	}()
	if err := bootstrap.RequireCommitted(bootstrap.FixedPaths()); err != nil {
		return err
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return err
	}
	if stop {
		return runProfile(context.Background(), launcher, child.ProfileNginxQuitSignal)
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	paths := nginx.FixedPaths()
	if err := auditFixedUnitGraph(); err != nil {
		return err
	}
	manager, err := locks.Open(locks.Config{RootPath: "/var/lib/lanpanel/locks", Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return err
	}
	defer manager.Close()
	exposure, err := manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		return err
	}
	defer exposure.Release()
	manifest, err := nginx.Audit(paths, owner)
	if err != nil {
		return err
	}
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: "/var/lib/lanpanel/ownership", StagingPath: "/var/lib/lanpanel/ownership/.filetxn", RecordsPath: "/var/lib/lanpanel/ownership/records", Owner: owner, Policy: ownership.FixedPolicy(), LockAuthority: manager.Authority()})
	if err != nil {
		return err
	}
	defer ownershipStore.Close()
	emergency, err := safety.OpenEmergency("/var/lib/lanpanel/safety/emergency", owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		return err
	}
	defer emergency.Close()
	store, err := safety.OpenStore(safety.StoreConfig{RootPath: "/var/lib/lanpanel/safety", StagingPath: "/var/lib/lanpanel/safety/.filetxn", StatePath: "/var/lib/lanpanel/safety/state.json", Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		return err
	}
	defer store.Close()
	state, err := store.Read()
	if err != nil {
		return err
	}
	var installation *domain.Installation
	normal, normalErr := persist.Open(persist.Config{RootPath: "/var/lib/lanpanel/state", StagingPath: "/var/lib/lanpanel/state/.filetxn", StatePath: "/var/lib/lanpanel/state/normal.json", Owner: owner, LockAuthority: manager.Authority()})
	if normalErr == nil {
		if registerErr := operations.Register(normal); registerErr != nil {
			normalErr = registerErr
		}
		document, readErr := normal.Read()
		pending, pendingErr := operations.HasPendingContraction(document)
		if readErr == nil && pendingErr == nil && !pending {
			if raw, present := document.Entries["installations/current"]; present {
				value, decodeErr := domain.DecodeInstallation(raw)
				if decodeErr == nil {
					installation = &value
				}
			}
		}
		_ = normal.Close()
	}
	if normalErr != nil || installation == nil {
		return fmt.Errorf("normal operation authority is unavailable to Nginx guard: %w", normalErr)
	}
	decision := nginx.Guard(nginx.GuardInput{Action: action, Manifest: manifest, Safety: state, Installation: installation, Now: time.Now().UTC()})
	if !decision.Allowed {
		return fmt.Errorf("Nginx guard rejected: %s", decision.Reason)
	}
	if err := runProfile(context.Background(), launcher, child.ProfileNginxTest); err != nil {
		return err
	}
	if action == nginx.GuardReload {
		listeners := []string{"tcp:0.0.0.0:80", "tcp:0.0.0.0:443", "tcp::::80", "tcp::::443"}
		for _, entry := range manifest.Entries {
			listeners = append(listeners, entry.Listeners...)
		}
		observer := closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: paths.PIDPath, ControlPID: os.Getpid(), Generation: manifest.GenerationID, OwnedListeners: listeners}
		prior, observeErr := observer.Observe(context.Background())
		if observeErr != nil || prior.Master == nil {
			return fmt.Errorf("observe guarded reload prior runtime: %w", observeErr)
		}
		if err := runProfile(context.Background(), launcher, child.ProfileNginxReloadSignal); err != nil {
			return err
		}
		if _, err := closure.WaitPriorWorkers(context.Background(), observer, prior.Workers, nginx.DefaultWorkerTimeout); err != nil {
			return err
		}
		return nil
	}
	return child.ExecutePersistentProfile(child.ProfileNginxStart)
}

func fencedGuardFailure() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	service, err := contraction.OpenEmergency(ctx)
	if err != nil {
		return err
	}
	defer service.Close()
	snapshot, err := service.Snapshot()
	if err != nil {
		return err
	}
	result, runErr := service.RunGuardFailure(ctx, snapshot.GlobalGeneration, snapshot.Inventory.Digest, os.Getpid())
	if result.Outcome != contraction.OutcomePartial && result.Outcome != contraction.OutcomeUnknown {
		return errors.Join(runErr, fmt.Errorf("guard fallback stop did not reach a closed classification"))
	}
	return runErr
}

func auditFixedUnitGraph() error {
	unit := "/etc/systemd/system/lanpanel-nginx.service"
	stat, err := os.Lstat(unit)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o644 {
		return fmt.Errorf("LanPanel Nginx unit identity is unsafe")
	}
	for _, path := range []string{unit + ".d", "/run/systemd/system.control/lanpanel-nginx.service", "/run/systemd/system.control/lanpanel-nginx.service.d", "/run/systemd/transient/lanpanel-nginx.service", "/run/systemd/transient/lanpanel-nginx.service.d", "/run/systemd/system.attached/lanpanel-nginx.service", "/run/systemd/system.attached/lanpanel-nginx.service.d", "/run/systemd/generator.early/lanpanel-nginx.service", "/run/systemd/generator.early/lanpanel-nginx.service.d", "/run/systemd/system/lanpanel-nginx.service", "/run/systemd/system/lanpanel-nginx.service.d", "/run/systemd/generator/lanpanel-nginx.service", "/run/systemd/generator/lanpanel-nginx.service.d", "/usr/local/lib/systemd/system/lanpanel-nginx.service", "/usr/local/lib/systemd/system/lanpanel-nginx.service.d", "/usr/lib/systemd/system/lanpanel-nginx.service", "/usr/lib/systemd/system/lanpanel-nginx.service.d", "/lib/systemd/system/lanpanel-nginx.service", "/lib/systemd/system/lanpanel-nginx.service.d", "/run/systemd/generator.late/lanpanel-nginx.service", "/run/systemd/generator.late/lanpanel-nginx.service.d"} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("LanPanel Nginx unit has a foreign shadow or drop-in")
		}
	}
	return nil
}

func runProfile(ctx context.Context, launcher *child.Launcher, profile child.ProfileID) error {
	result, err := launcher.Run(ctx, profile, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return errors.Join(err, fmt.Errorf("fixed Nginx guard profile %q failed", profile))
	}
	return nil
}
