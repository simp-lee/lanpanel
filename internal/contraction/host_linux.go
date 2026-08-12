//go:build linux

package contraction

import (
	"context"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
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
	manifest, err := nginx.Audit(paths, filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return Host{}, err
	}
	observer := closure.ProcObserver{UnitCgroup: "/system.slice/lanpanel-nginx.service", Executable: "/usr/sbin/nginx", ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;", PIDPath: paths.PIDPath, Generation: manifest.GenerationID, OwnedListeners: inventoryListeners(inventory)}
	return Host{Launcher: launcher, Paths: paths, Owner: filetxn.Owner{UID: 0, GID: 0}, Observer: observer, Probe: closure.NegativeProbe{TLSAddress: "127.0.0.1:443", DefaultCertFingerprint: manifest.DefaultCertFingerprint, AuditPath: paths.AuditPath}}, nil
}

type Host struct {
	Launcher    *child.Launcher
	Paths       nginx.Paths
	Owner       filetxn.Owner
	Observer    closure.RuntimeObserver
	Probe       closure.NegativeProbe
	StopProfile child.ProfileID
}

func (host Host) ContractDisk(ctx context.Context, inventory closure.Inventory) ([]string, error) {
	resourceIDs := []string{}
	seen := map[string]bool{}
	for _, identity := range inventory.Identities {
		if !seen[identity.ResourceID] {
			seen[identity.ResourceID] = true
			resourceIDs = append(resourceIDs, identity.ResourceID)
		}
	}
	_, paths, err := nginx.Contract(ctx, host.Paths, host.Owner, resourceIDs)
	return paths, err
}
func (host Host) TestClosedGraph(ctx context.Context) error {
	if _, err := nginx.Audit(host.Paths, host.Owner); err != nil {
		return err
	}
	if err := host.run(ctx, child.ProfileNginxDump); err != nil {
		return err
	}
	return host.run(ctx, child.ProfileNginxTest)
}
func (host Host) ReloadAndDrain(ctx context.Context) error {
	if host.Observer == nil {
		return fmt.Errorf("Nginx runtime observer is missing")
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
		return closure.RuntimeSnapshot{}, fmt.Errorf("Nginx runtime observer is missing")
	}
	return host.Observer.Observe(ctx)
}
func (host Host) run(ctx context.Context, profile child.ProfileID) error {
	if host.Launcher == nil {
		return fmt.Errorf("Nginx fixed child launcher is missing")
	}
	result, err := host.Launcher.Run(ctx, profile, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("fixed Nginx operation %q failed: %w", profile, err)
	}
	return nil
}
