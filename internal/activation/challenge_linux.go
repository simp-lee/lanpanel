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

type ReloadAuthoritySnapshot struct {
	Safety       safety.State
	Installation domain.Installation
	Ownership    map[string]string
	ObservedAt   time.Time
}

type ReloadAuthority struct {
	refresh func() (ReloadAuthoritySnapshot, error)
}

type ChallengeReloadAuthority = ReloadAuthority

func NewReloadAuthority(refresh func() (ReloadAuthoritySnapshot, error)) (ReloadAuthority, error) {
	if refresh == nil {
		return ReloadAuthority{}, fmt.Errorf("nginx reload authority refresh is unavailable")
	}
	snapshot, err := refresh()
	if err != nil {
		return ReloadAuthority{}, err
	}
	if snapshot.ObservedAt.IsZero() {
		return ReloadAuthority{}, fmt.Errorf("nginx reload authority time is unavailable")
	}
	return ReloadAuthority{refresh: refresh}, nil
}

func (authority ReloadAuthority) Current() (ReloadAuthoritySnapshot, error) {
	if authority.refresh == nil {
		return ReloadAuthoritySnapshot{}, fmt.Errorf("nginx reload authority refresh is unavailable")
	}
	current, err := authority.refresh()
	if err != nil {
		return ReloadAuthoritySnapshot{}, err
	}
	current.ObservedAt = current.ObservedAt.UTC()
	if current.ObservedAt.IsZero() {
		return ReloadAuthoritySnapshot{}, fmt.Errorf("nginx reload authority time is unavailable")
	}
	return current, nil
}

func (authority ReloadAuthority) Guard(manifest nginx.Manifest) error {
	current, err := authority.Current()
	if err != nil {
		return err
	}
	if current.Installation.InstallationID == "" || manifest.InstallationID != current.Installation.InstallationID {
		return fmt.Errorf("nginx reload installation authority changed")
	}
	decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: current.Safety, Installation: &current.Installation, Ownership: current.Ownership, Now: current.ObservedAt})
	if !decision.Allowed {
		return fmt.Errorf("%s", decision.Reason)
	}
	return nil
}

func guardReload(manifest nginx.Manifest, authority ReloadAuthority) error {
	return authority.Guard(manifest)
}

func guardAuditedReload(paths nginx.Paths, owner filetxn.Owner, expected nginx.Manifest, authority ReloadAuthority) error {
	if _, err := authority.Current(); err != nil {
		return err
	}
	current, err := nginx.Audit(paths, owner)
	if err != nil {
		return err
	}
	currentBytes, currentErr := nginx.EncodeManifest(current)
	expectedBytes, expectedErr := nginx.EncodeManifest(expected)
	if currentErr != nil || expectedErr != nil || !bytes.Equal(currentBytes, expectedBytes) {
		return errors.Join(currentErr, expectedErr, fmt.Errorf("nginx reload manifest changed after transaction"))
	}
	return authority.Guard(current)
}

type ChallengeGraphRuntime struct {
	Activate func(context.Context, nginx.Manifest, func() error) error
	Observe  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error)
	Restore  func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error
}

func StoppedChallengeGraphRuntime(observe func(context.Context, nginx.Manifest) (closure.RuntimeSnapshot, error)) ChallengeGraphRuntime {
	verify := func(ctx context.Context, manifest nginx.Manifest) ([]closure.ProcessIdentity, error) {
		current, observeErr := observe(ctx, manifest)
		return current.Workers, errors.Join(observeErr, closure.VerifyStopped(current))
	}
	return ChallengeGraphRuntime{
		Activate: func(ctx context.Context, manifest nginx.Manifest, _ func() error) error {
			_, err := verify(ctx, manifest)
			return err
		},
		Observe: verify,
		Restore: func(ctx context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity, _ func() error) error {
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
	if err := guardReload(prospective, authority); err != nil {
		return nginx.ActivationSnapshot{}, nginx.Manifest{}, fmt.Errorf("challenge expansion rejected: %w", err)
	}
	return snapshot, prospective, nil
}

func CommitChallengeGraph(ctx context.Context, paths nginx.Paths, owner filetxn.Owner, candidate nginx.Entry, snapshot nginx.ActivationSnapshot, attempted nginx.Manifest, authority ChallengeReloadAuthority, change func(context.Context) (nginx.Manifest, []string, error), runtime ChallengeGraphRuntime) (Result, error) {
	if change == nil || runtime.Activate == nil || runtime.Observe == nil || runtime.Restore == nil || nginx.ValidateManifest(snapshot.Manifest) != nil || nginx.ValidateManifest(attempted) != nil {
		return Result{}, fmt.Errorf("challenge graph transaction authority is invalid")
	}
	if err := guardReload(attempted, authority); err != nil {
		return Result{}, fmt.Errorf("challenge graph reload rejected before mutation: %w", err)
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
		changeErr = runtime.Activate(ctx, manifest, func() error {
			if guardErr := guardAuditedReload(paths, owner, manifest, authority); guardErr != nil {
				return fmt.Errorf("challenge graph reload rejected at signal: %w", guardErr)
			}
			return nil
		})
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
		restoreRuntimeErr = runtime.Restore(recoveryCtx, snapshot.Manifest, workers, func() error {
			if guardErr := guardAuditedReload(paths, owner, snapshot.Manifest, authority); guardErr != nil {
				return fmt.Errorf("challenge graph rollback reload rejected: %w", guardErr)
			}
			return nil
		})
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
		Activate: func(runCtx context.Context, manifest nginx.Manifest, authorize func() error) error {
			if err := host.run(runCtx, child.ProfileNginxDump); err != nil {
				return err
			}
			if err := host.run(runCtx, child.ProfileNginxTest); err != nil {
				return err
			}
			if err := authorize(); err != nil {
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
		Restore: func(restoreCtx context.Context, manifest nginx.Manifest, workers []closure.ProcessIdentity, authorize func() error) error {
			if err := host.run(restoreCtx, child.ProfileNginxTest); err != nil {
				return err
			}
			if err := authorize(); err != nil {
				return err
			}
			if err := host.run(restoreCtx, child.ProfileNginxReloadSignal); err != nil {
				return err
			}
			_, err := host.WaitForPriorWorkers(restoreCtx, manifest, workers)
			return err
		},
	}
	return CommitChallengeGraph(ctx, host.Paths, host.Owner, *candidate.Entry, snapshot, prospective, authority, func(changeCtx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(changeCtx, host.Paths, host.Owner, *candidate.Entry)
	}, runtime)
}

func (host Host) RemoveChallenge(ctx context.Context, candidate challenge.Prepared, authority ChallengeReloadAuthority) (Result, error) {
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
			Activate: func(runCtx context.Context, manifest nginx.Manifest, authorize func() error) error {
				if err := host.run(runCtx, child.ProfileNginxTest); err != nil {
					return err
				}
				if err := authorize(); err != nil {
					return err
				}
				if err := host.run(runCtx, child.ProfileNginxReloadSignal); err != nil {
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
			Restore: func(restoreCtx context.Context, manifest nginx.Manifest, workers []closure.ProcessIdentity, authorize func() error) error {
				if err := host.run(restoreCtx, child.ProfileNginxTest); err != nil {
					return err
				}
				if err := authorize(); err != nil {
					return err
				}
				if err := host.run(restoreCtx, child.ProfileNginxReloadSignal); err != nil {
					return err
				}
				_, err := host.WaitForPriorWorkers(restoreCtx, manifest, workers)
				return err
			},
		}
	}
	return CommitChallengeGraph(ctx, host.Paths, host.Owner, *candidate.Entry, snapshot, prospective, authority, func(changeCtx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(changeCtx, host.Paths, host.Owner, *candidate.Entry)
	}, runtime)
}
