// Package contraction coordinates durable fail-closed Nginx contraction.
package contraction

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/closure"
	"time"
)

type Outcome string

const (
	OutcomeSucceeded   Outcome = "succeeded"
	OutcomeFailed      Outcome = "failed"
	OutcomePartial     Outcome = "partial"
	OutcomeInterrupted Outcome = "interrupted"
	OutcomeUnknown     Outcome = "unknown"
)

type Result struct {
	Outcome           Outcome
	AccessClosed      bool
	SharedIngressDown bool
	AccessMayRemain   bool
	ModifiedPaths     []string
	ClosureDigest     string
	ErrorCode         string
}

type Authority interface {
	PersistClosing(context.Context, closure.Inventory) error
	CommitUnpublished(context.Context, closure.Inventory) error
	PersistStopFence(context.Context, closure.Inventory) error
	UpdateStopObservation(context.Context, closure.RuntimeSnapshot, bool) error
	FinalizeClosure(context.Context, closure.Inventory, string, []string) error
}

type Runtime interface {
	ContractDisk(context.Context, closure.Inventory) ([]string, error)
	TestClosedGraph(context.Context) error
	ReloadAndDrain(context.Context) error
	ProbeSelectiveClosure(context.Context, closure.Inventory) (string, error)
	Stop(context.Context) error
	Observe(context.Context) (closure.RuntimeSnapshot, error)
}

type Engine struct {
	Authority Authority
	Runtime   Runtime
}

func (engine Engine) Run(ctx context.Context, inventory closure.Inventory) (Result, error) {
	if engine.Authority == nil || engine.Runtime == nil || inventory.Digest == "" {
		return Result{}, fmt.Errorf("contraction engine authority is incomplete")
	}
	if err := engine.Authority.PersistClosing(ctx, inventory); err != nil {
		result, fallbackErr := engine.fallback(ctx, inventory, "contraction_authority_failed", nil)
		return result, errors.Join(err, fallbackErr)
	}
	if err := engine.Authority.CommitUnpublished(ctx, inventory); err != nil {
		result, fallbackErr := engine.fallback(ctx, inventory, "unpublished_commit_failed", nil)
		return result, errors.Join(err, fallbackErr)
	}
	if !inventory.Complete {
		return engine.fallback(ctx, inventory, "closure_inventory_incomplete", nil)
	}
	paths, err := engine.Runtime.ContractDisk(ctx, inventory)
	if err != nil {
		result, fallbackErr := engine.fallback(ctx, inventory, "disk_contraction_failed", paths)
		return result, errors.Join(err, fallbackErr)
	}
	if err := engine.Runtime.TestClosedGraph(ctx); err != nil {
		result, fallbackErr := engine.fallback(ctx, inventory, "nginx_test_failed", paths)
		result.ModifiedPaths = paths
		return result, errors.Join(err, fallbackErr)
	}
	if err := engine.Runtime.ReloadAndDrain(ctx); err != nil {
		result, fallbackErr := engine.fallback(ctx, inventory, "worker_drain_failed", paths)
		result.ModifiedPaths = paths
		return result, errors.Join(err, fallbackErr)
	}
	closureDigest, err := engine.Runtime.ProbeSelectiveClosure(ctx, inventory)
	if err != nil {
		result, fallbackErr := engine.fallback(ctx, inventory, "runtime_probe_failed", paths)
		result.ModifiedPaths = paths
		return result, errors.Join(err, fallbackErr)
	}
	if err := engine.Authority.FinalizeClosure(ctx, inventory, closureDigest, paths); err != nil {
		result, fallbackErr := engine.fallback(ctx, inventory, "closure_commit_failed", paths)
		result.ModifiedPaths = paths
		return result, errors.Join(err, fallbackErr)
	}
	return Result{Outcome: OutcomeSucceeded, AccessClosed: true, ModifiedPaths: paths, ClosureDigest: closureDigest}, nil
}

type authorityCommittedError struct{ err error }

func (err authorityCommittedError) Error() string { return err.err.Error() }
func (err authorityCommittedError) Unwrap() error { return err.err }
func (engine Engine) fallback(_ context.Context, inventory closure.Inventory, code string, modifiedPaths []string) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	result := Result{Outcome: OutcomeUnknown, AccessMayRemain: true, ErrorCode: code}
	fenceErr := engine.Authority.PersistStopFence(ctx, inventory)
	stopErr := engine.Runtime.Stop(ctx)
	snapshot, observeErr := engine.Runtime.Observe(ctx)
	closedErr := closure.VerifyStopped(snapshot)
	verified := stopErr == nil && observeErr == nil && closedErr == nil
	var updateErr error
	if fenceErr == nil {
		updateErr = engine.Authority.UpdateStopObservation(ctx, snapshot, verified)
	}
	if verified && fenceErr == nil && updateErr == nil {
		closureDigest := inventory.Digest
		if finalizeErr := engine.Authority.FinalizeClosure(ctx, inventory, closureDigest, modifiedPaths); finalizeErr != nil {
			return result, finalizeErr
		}
		result.Outcome = OutcomePartial
		result.ModifiedPaths = append([]string(nil), modifiedPaths...)
		result.ClosureDigest = closureDigest
		result.AccessClosed = true
		result.SharedIngressDown = true
		result.AccessMayRemain = false
		return result, nil
	}
	return result, errors.Join(fenceErr, stopErr, observeErr, closedErr, updateErr)
}
