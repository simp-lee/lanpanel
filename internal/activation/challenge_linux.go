//go:build linux

package activation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/challenge"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"time"
)

type ChallengeReloadAuthority struct {
	Safety       safety.State
	Installation domain.Installation
	Ownership    map[string]string
	ObservedAt   time.Time
}

type ChallengeGraphRuntime struct {
	Activate func(context.Context, nginx.Manifest) error
	Observe  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error)
	Restore  func(context.Context, nginx.Manifest, []closure.ProcessIdentity) error
}

func StoppedChallengeGraphRuntime(observe func(context.Context, nginx.Manifest) (closure.RuntimeSnapshot, error)) ChallengeGraphRuntime {
	verify := func(ctx context.Context, manifest nginx.Manifest) ([]closure.ProcessIdentity, error) {
		current, observeErr := observe(ctx, manifest)
		return current.Workers, errors.Join(observeErr, closure.VerifyStopped(current))
	}
	return ChallengeGraphRuntime{
		Activate: func(ctx context.Context, manifest nginx.Manifest) error {
			_, err := verify(ctx, manifest)
			return err
		},
		Observe: verify,
		Restore: func(ctx context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity) error {
			_, err := verify(ctx, manifest)
			return err
		},
	}
}

func PrepareChallengeExpansion(paths nginx.Paths, owner filetxn.Owner, entry nginx.Entry, authority ChallengeReloadAuthority) (nginx.ActivationSnapshot, nginx.Manifest, error) {
	snapshot, err := nginx.SnapshotActivation(paths, owner, entry)
	if err != nil {
		return nginx.ActivationSnapshot{}, nginx.Manifest{}, err
	}
	prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, entry)
	if err != nil {
		return nginx.ActivationSnapshot{}, nginx.Manifest{}, err
	}
	decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: prospective, Safety: authority.Safety, Installation: &authority.Installation, Ownership: authority.Ownership, Now: authority.ObservedAt})
	if !decision.Allowed {
		return nginx.ActivationSnapshot{}, nginx.Manifest{}, fmt.Errorf("challenge expansion rejected: %s", decision.Reason)
	}
	return snapshot, prospective, nil
}

func CommitChallengeGraph(ctx context.Context, paths nginx.Paths, owner filetxn.Owner, candidate nginx.Entry, snapshot nginx.ActivationSnapshot, attempted nginx.Manifest, change func(context.Context) (nginx.Manifest, []string, error), runtime ChallengeGraphRuntime) (Result, error) {
	if change == nil || runtime.Activate == nil || runtime.Observe == nil || runtime.Restore == nil || nginx.ValidateManifest(snapshot.Manifest) != nil || nginx.ValidateManifest(attempted) != nil {
		return Result{}, fmt.Errorf("challenge graph transaction authority is invalid")
	}
	manifest, modified, changeErr := change(ctx)
	if changeErr == nil {
		actualBytes, actualErr := nginx.EncodeManifest(manifest)
		attemptedBytes, attemptedErr := nginx.EncodeManifest(attempted)
		if actualErr != nil || attemptedErr != nil || !bytes.Equal(actualBytes, attemptedBytes) {
			changeErr = errors.Join(actualErr, attemptedErr, fmt.Errorf("challenge graph mutation differs from prospective manifest"))
		}
	}
	if changeErr == nil {
		changeErr = runtime.Activate(ctx, manifest)
	}
	if changeErr == nil {
		return Result{Manifest: manifest, ModifiedPaths: modified, RuntimeDigest: candidate.Digest}, nil
	}

	recoveryCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	workers, observeErr := runtime.Observe(recoveryCtx, attempted)
	_, restoreDiskErr := nginx.RestoreActivation(recoveryCtx, paths, owner, candidate, snapshot)
	var restoreRuntimeErr error
	if restoreDiskErr == nil {
		restoreRuntimeErr = runtime.Restore(recoveryCtx, snapshot.Manifest, workers)
	}
	restoreErr := errors.Join(observeErr, restoreDiskErr, restoreRuntimeErr)
	return Result{}, &Failure{Cause: errors.Join(changeErr, restoreErr), PriorRestored: restoreErr == nil}
}

func (host Host) ActivateChallenge(ctx context.Context, candidate challenge.Prepared, authority ChallengeReloadAuthority) (Result, error) {
	if candidate.Entry == nil || candidate.Entry.Kind != nginx.EntryChallenge || host.Launcher == nil {
		return Result{}, fmt.Errorf("challenge activation authority incomplete")
	}
	snapshot, prospective, err := PrepareChallengeExpansion(host.Paths, host.Owner, *candidate.Entry, authority)
	if err != nil {
		return Result{}, err
	}
	prior, err := host.observer(snapshot.Manifest).Observe(ctx)
	if err != nil || prior.Master == nil {
		return Result{}, fmt.Errorf("nginx unavailable for challenge activation: %w", err)
	}
	runtime := ChallengeGraphRuntime{
		Activate: func(runCtx context.Context, manifest nginx.Manifest) error {
			if err := host.run(runCtx, child.ProfileNginxDump); err != nil {
				return err
			}
			if err := host.run(runCtx, child.ProfileNginxTest); err != nil {
				return err
			}
			if err := host.run(runCtx, child.ProfileNginxReloadSignal); err != nil {
				return err
			}
			if _, err := host.WaitForPriorWorkers(runCtx, manifest, prior.Workers); err != nil {
				return fmt.Errorf("challenge runtime activation unavailable: %w", err)
			}
			return nil
		},
		Observe: func(observeCtx context.Context, manifest nginx.Manifest) ([]closure.ProcessIdentity, error) {
			current, observeErr := host.observer(manifest).Observe(observeCtx)
			return current.Workers, observeErr
		},
		Restore: func(restoreCtx context.Context, manifest nginx.Manifest, workers []closure.ProcessIdentity) error {
			if err := host.Reload(restoreCtx); err != nil {
				return err
			}
			_, err := host.WaitForPriorWorkers(restoreCtx, manifest, workers)
			return err
		},
	}
	return CommitChallengeGraph(ctx, host.Paths, host.Owner, *candidate.Entry, snapshot, prospective, func(changeCtx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(changeCtx, host.Paths, host.Owner, *candidate.Entry)
	}, runtime)
}

func (host Host) RemoveChallenge(ctx context.Context, candidate challenge.Prepared) (Result, error) {
	if candidate.Entry == nil {
		return Result{}, nil
	}
	snapshot, err := nginx.SnapshotActivation(host.Paths, host.Owner, *candidate.Entry)
	if err != nil {
		return Result{}, err
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, *candidate.Entry)
	if err != nil {
		return Result{}, err
	}
	prior, err := host.observer(snapshot.Manifest).Observe(ctx)
	if err != nil {
		return Result{}, err
	}
	running := prior.Master != nil
	if !running && (len(prior.Workers) != 0 || len(prior.Listeners) != 0) {
		return Result{}, fmt.Errorf("stopped Nginx challenge runtime is inconsistent")
	}
	runtime := StoppedChallengeGraphRuntime(func(observeCtx context.Context, manifest nginx.Manifest) (closure.RuntimeSnapshot, error) {
		return host.observer(manifest).Observe(observeCtx)
	})
	if running {
		runtime = ChallengeGraphRuntime{
			Activate: func(runCtx context.Context, manifest nginx.Manifest) error {
				if err := host.Reload(runCtx); err != nil {
					return err
				}
				if _, err := host.WaitForPriorWorkers(runCtx, manifest, prior.Workers); err != nil {
					return fmt.Errorf("challenge contraction prior workers remain: %w", err)
				}
				return nil
			},
			Observe: func(observeCtx context.Context, manifest nginx.Manifest) ([]closure.ProcessIdentity, error) {
				current, observeErr := host.observer(manifest).Observe(observeCtx)
				return current.Workers, observeErr
			},
			Restore: func(restoreCtx context.Context, manifest nginx.Manifest, workers []closure.ProcessIdentity) error {
				if err := host.Reload(restoreCtx); err != nil {
					return err
				}
				_, err := host.WaitForPriorWorkers(restoreCtx, manifest, workers)
				return err
			},
		}
	}
	return CommitChallengeGraph(ctx, host.Paths, host.Owner, *candidate.Entry, snapshot, prospective, func(changeCtx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(changeCtx, host.Paths, host.Owner, *candidate.Entry)
	}, runtime)
}
