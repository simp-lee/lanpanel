//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
)

// ReconcileInterruptedEntityMutations terminalizes non-retryable Headscale and
// connector mutations only after startup has independently proved that the old
// helper cgroup has no surviving child. It never repeats a remote mutation.
func ReconcileInterruptedEntityMutations(ctx context.Context, childClosureDigest string) error {
	if childClosureDigest == "" {
		return fmt.Errorf("interrupted entity reconciliation requires child closure evidence")
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	type pending struct {
		intent operations.Reservation
		code   string
	}
	pendingValues := []pending{}
	for key, raw := range document.Entries {
		if len(key) < len("intents/") || key[:len("intents/")] != "intents/" {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) != nil || intent.Phase == operations.PhaseTerminal || intent.Phase == operations.PhaseRejected {
			continue
		}
		code := ""
		switch intent.Operation {
		case operations.HeadscaleUserCreate, operations.PreauthKeyCreate, operations.PreauthKeyRevoke, operations.DeviceExpire:
			code = "headscale_lifecycle_interrupted"
		case operations.ConnectorBindingSet, operations.ConnectorLogin:
			code = "connector_mutation_interrupted"
		default:
			continue
		}
		pendingValues = append(pendingValues, pending{intent: intent, code: code})
	}
	if len(pendingValues) == 0 {
		return nil
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return err
	}
	set, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(set.Close)
	var result error
	for _, value := range pendingValues {
		intent := value.intent
		switch intent.Phase {
		case operations.PhaseReserved:
			lease, acquireErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if acquireErr != nil {
				result = errors.Join(result, acquireErr)
				continue
			}
			fresh, readErr := service.normal.Read()
			if readErr == nil {
				readErr = admitter.RejectReservation(ctx, lease, fresh.Revision, intent.JobID, "plan_consumption_rejected")
			}
			result = errors.Join(result, readErr, lease.Release())
		case operations.PhaseLocalIntent, operations.PhaseRemoteWait, operations.PhaseReentered:
			mutation, exposure, acquireErr := set.AcquireExposure(ctx, intent.Target, service.manager)
			if acquireErr != nil {
				result = errors.Join(result, acquireErr)
				continue
			}
			fresh, readErr := service.normal.Read()
			if readErr == nil {
				_, readErr = admitter.CompleteInterruptedEntity(ctx, mutation, exposure, fresh.Revision, intent.JobID, childClosureDigest, value.code)
			}
			result = errors.Join(result, readErr, operations.ReleaseExposure(mutation, exposure))
		default:
			result = errors.Join(result, fmt.Errorf("interrupted entity mutation has unsupported phase %q", intent.Phase))
		}
	}
	return result
}
