//go:build linux

package contraction

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"os"
	"time"
)

func FixedFallbackHost(inventory closure.Inventory) (Host, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return Host{}, err
	}
	paths := nginx.FixedPaths()
	observer := closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: paths.PIDPath, Generation: "fallback", OwnedListeners: inventoryListeners(inventory)}
	return Host{Launcher: launcher, Paths: paths, Owner: filetxn.Owner{UID: 0, GID: 0}, Observer: observer}, nil
}

func FixedHost(inventory closure.Inventory) (Host, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return Host{}, err
	}
	paths := nginx.FixedPaths()
	owner := filetxn.Owner{UID: 0, GID: 0}
	manifest, err := nginx.Audit(paths, owner)
	if err != nil {
		auditErr := err
		var pending bool
		manifest, pending, err = nginx.PendingContraction(paths, owner)
		if err != nil || !pending {
			return Host{}, errors.Join(auditErr, err)
		}
	}
	observer := closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: paths.PIDPath, Generation: manifest.GenerationID, OwnedListeners: inventoryListeners(inventory)}
	return Host{Launcher: launcher, Paths: paths, Owner: filetxn.Owner{UID: 0, GID: 0}, Observer: observer, Probe: closure.NegativeProbe{TLSAddress: "127.0.0.1:443", DefaultCertFingerprint: manifest.DefaultCertFingerprint, AuditPath: paths.AuditPath, TargetObserved: targetClosureObserver(paths, owner)}}, nil
}

// targetClosureObserver conservatively treats any remaining App graph entry
// for the probed domain as possible target access. The fixed rejection
// response is only sufficient after the fresh graph audit also shows that no
// release-owned App route can forward the correlation request.
func targetClosureObserver(paths nginx.Paths, owner filetxn.Owner) func(context.Context, closure.Inventory, string, string) (bool, error) {
	return func(_ context.Context, _ closure.Inventory, domainName, _ string) (bool, error) {
		manifest, err := nginx.Audit(paths, owner)
		if err != nil {
			return false, err
		}
		for _, entry := range manifest.Entries {
			if entry.Kind != nginx.EntryApp {
				continue
			}
			for _, value := range entry.Domains {
				if value == domainName {
					return true, nil
				}
			}
		}
		return false, nil
	}
}

type Host struct {
	Launcher    *child.Launcher
	Paths       nginx.Paths
	Owner       filetxn.Owner
	Observer    closure.RuntimeObserver
	Probe       closure.NegativeProbe
	StopProfile child.ProfileID
	Guard       func(nginx.Manifest) error
}

func appResourceIDs(inventory closure.Inventory) []string {
	resourceIDs := []string{}
	seen := map[string]bool{}
	for _, identity := range inventory.Identities {
		if identity.ResourceID == "headscale" || seen[identity.ResourceID] {
			continue
		}
		seen[identity.ResourceID] = true
		resourceIDs = append(resourceIDs, identity.ResourceID)
	}
	return resourceIDs
}

func (host Host) ContractDisk(ctx context.Context, inventory closure.Inventory) ([]string, error) {
	resourceIDs := appResourceIDs(inventory)
	manifest, paths, err := nginx.Contract(ctx, host.Paths, host.Owner, resourceIDs)
	if err == nil && host.Guard != nil {
		err = host.Guard(manifest)
	}
	return paths, err
}

func (host Host) AcknowledgeDiskContraction(ctx context.Context, inventory closure.Inventory) error {
	resourceIDs := appResourceIDs(inventory)
	if len(resourceIDs) == 0 {
		return nil
	}
	return nginx.AcknowledgeContraction(ctx, host.Paths, host.Owner, resourceIDs)
}

func (host Host) TestClosedGraph(ctx context.Context) error {
	if _, err := nginx.Audit(host.Paths, host.Owner); err != nil {
		return err
	}
	if err := host.run(ctx, child.ProfileNginxDump); err != nil {
		return err
	}
	testErr := host.run(ctx, child.ProfileNginxTest)
	if cleanupErr := removeEmptyNginxTestPID(host.Paths.PIDPath); testErr != nil || cleanupErr != nil {
		return errors.Join(testErr, cleanupErr)
	}
	return nil
}

func removeEmptyNginxTestPID(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return err
	}
	return os.Remove(path)
}

func (host Host) ReloadAndDrain(ctx context.Context) error {
	if host.Observer == nil {
		return fmt.Errorf("nginx runtime observer is missing")
	}
	prior, err := host.Observer.Observe(ctx)
	if err != nil {
		return err
	}
	priorProcesses := append([]closure.ProcessIdentity(nil), prior.Workers...)
	if prior.Master == nil {
		if err := closure.VerifyStopped(prior); err != nil {
			return err
		}
		return nil
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal); err != nil {
		return err
	}
	current, err := closure.WaitPriorWorkers(ctx, host.Observer, priorProcesses, nginx.DefaultWorkerTimeout)
	if err != nil {
		return err
	}
	if !current.Complete || current.Master == nil || current.Generation == "" {
		return fmt.Errorf("reloaded Nginx runtime generation is incomplete")
	}
	return nil
}

func (host Host) ProbeSelectiveClosure(ctx context.Context, inventory closure.Inventory) (string, error) {
	snapshot, err := host.Observe(ctx)
	if err == nil && closure.VerifyStopped(snapshot) == nil {
		return inventory.Digest, nil
	}
	return host.Probe.Run(ctx, inventory)
}

func (host Host) Stop(ctx context.Context) error {
	if snapshot, err := host.Observe(ctx); err == nil && closure.VerifyStopped(snapshot) == nil {
		return nil
	}
	profile := host.StopProfile
	if profile == "" {
		profile = child.ProfileSystemctlNginxStop
	}
	if err := host.run(ctx, profile); err != nil {
		return err
	}
	if profile != child.ProfileNginxQuitSignal {
		return nil
	}
	deadline := time.Now().Add(nginx.DefaultWorkerTimeout)
	for {
		snapshot, err := host.Observe(ctx)
		if err == nil && closure.VerifyStopped(snapshot) == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("guarded Nginx quit did not reach exact stopped state: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (host Host) Observe(ctx context.Context) (closure.RuntimeSnapshot, error) {
	if host.Observer == nil {
		return closure.RuntimeSnapshot{}, fmt.Errorf("nginx runtime observer is missing")
	}
	return host.Observer.Observe(ctx)
}

func (host Host) run(ctx context.Context, profile child.ProfileID) error {
	if host.Launcher == nil {
		return fmt.Errorf("nginx fixed child launcher is missing")
	}
	result, err := host.Launcher.Run(ctx, profile, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("fixed Nginx operation %q failed: %w", profile, err)
	}
	return nil
}
