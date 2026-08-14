//go:build linux

package activation

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/challenge"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/nginx"
)

func (host Host) ActivateChallenge(ctx context.Context, candidate challenge.Prepared) (result Result, resultErr error) {
	if candidate.Entry == nil || candidate.Entry.Kind != nginx.EntryChallenge || host.Launcher == nil {
		return Result{}, fmt.Errorf("challenge activation authority incomplete")
	}
	priorManifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return Result{}, err
	}
	prior, err := host.observer(priorManifest).Observe(ctx)
	if err != nil || prior.Master == nil {
		return Result{}, fmt.Errorf("Nginx unavailable for challenge activation")
	}
	snapshot, err := nginx.SnapshotActivation(host.Paths, host.Owner, *candidate.Entry)
	if err != nil {
		return Result{}, err
	}
	mutated := true
	defer func() {
		if resultErr == nil || !mutated {
			return
		}
		recoveryCtx := context.WithoutCancel(ctx)
		current, observeErr := host.observer(priorManifest).Observe(recoveryCtx)
		_, restoreErr := nginx.RestoreActivation(recoveryCtx, host.Paths, host.Owner, *candidate.Entry, snapshot)
		restoreErr = errors.Join(observeErr, restoreErr)
		if restoreErr == nil {
			restoreErr = host.Reload(recoveryCtx)
		}
		if restoreErr == nil {
			converged, waitErr := closure.WaitPriorWorkers(recoveryCtx, host.observer(priorManifest), current.Workers, nginx.DefaultWorkerTimeout)
			if waitErr != nil || converged.Master == nil {
				restoreErr = errors.Join(waitErr, fmt.Errorf("challenge rollback workers did not converge"))
			}
		}
		resultErr = &Failure{Cause: errors.Join(resultErr, restoreErr), PriorRestored: restoreErr == nil}
	}()
	manifest, paths, err := nginx.InstallEntry(ctx, host.Paths, host.Owner, *candidate.Entry)
	if err != nil {
		return Result{}, err
	}
	if err := host.run(ctx, child.ProfileNginxDump); err != nil {
		return Result{}, err
	}
	if err := host.run(ctx, child.ProfileNginxTest); err != nil {
		return Result{}, err
	}
	if err := host.run(ctx, child.ProfileNginxReloadSignal); err != nil {
		return Result{}, err
	}
	runtime, err := closure.WaitPriorWorkers(ctx, host.observer(manifest), prior.Workers, nginx.DefaultWorkerTimeout)
	if err != nil || runtime.Master == nil {
		return Result{}, fmt.Errorf("challenge runtime activation unavailable")
	}
	return Result{Manifest: manifest, ModifiedPaths: paths, RuntimeDigest: candidate.Entry.Digest}, nil
}
func (host Host) RemoveChallenge(ctx context.Context, candidate challenge.Prepared) (Result, error) {
	if candidate.Entry == nil {
		return Result{}, nil
	}
	priorManifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return Result{}, err
	}
	prior, err := host.observer(priorManifest).Observe(ctx)
	if err != nil {
		return Result{}, err
	}
	running := prior.Master != nil
	if !running && (len(prior.Workers) != 0 || len(prior.Listeners) != 0) {
		return Result{}, fmt.Errorf("stopped Nginx challenge runtime is inconsistent")
	}
	manifest, paths, err := nginx.RemoveEntry(ctx, host.Paths, host.Owner, *candidate.Entry)
	if err != nil {
		return Result{}, err
	}
	if !running {
		return Result{Manifest: manifest, ModifiedPaths: paths, RuntimeDigest: candidate.Entry.Digest}, nil
	}
	if err := host.Reload(ctx); err != nil {
		return Result{}, err
	}
	runtime, err := closure.WaitPriorWorkers(ctx, host.observer(manifest), prior.Workers, nginx.DefaultWorkerTimeout)
	if err != nil || runtime.Master == nil {
		return Result{}, fmt.Errorf("challenge contraction prior workers remain")
	}
	return Result{Manifest: manifest, ModifiedPaths: paths, RuntimeDigest: candidate.Entry.Digest}, nil
}
