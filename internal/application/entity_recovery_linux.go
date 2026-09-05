//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
)

// ReconcileInterruptedEntityMutations terminalizes non-retryable Headscale and
// connector mutations only after startup has independently proved that the old
// helper cgroup has no surviving child. The helper's exact auth-key cleanup must
// succeed before fresh connector verification or terminalization. Recovery never
// repeats a remote mutation, even if verification fails.
func ReconcileInterruptedEntityMutations(ctx context.Context, childClosureDigest string, connectorCleanupErr error) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	return reconcileInterruptedEntityMutations(ctx, service, childClosureDigest, operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()}, connectorCleanupErr, func(ctx context.Context) (ConnectorVerifyResult, error) {
		return VerifyConnector(ctx, nil, nil)
	})
}

func reconcileInterruptedEntityMutations(ctx context.Context, service *FixedService, childClosureDigest string, lockConfig operations.MutationConfig, connectorCleanupErr error, verifyConnector func(context.Context) (ConnectorVerifyResult, error)) error {
	if childClosureDigest == "" {
		return fmt.Errorf("interrupted entity reconciliation requires child closure evidence")
	}
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
	set, err := operations.OpenMutationSet(lockConfig)
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
			var connectorVerification *jobs.Postcondition
			if intent.Operation == operations.ConnectorLogin {
				if connectorCleanupErr != nil {
					// The exact key was not proved deleted. Leave this login
					// unresolved, but do not block unrelated entity recovery.
					result = errors.Join(result, connectorCleanupErr)
					continue
				}
				// Observe without an exposure lock. This is historical job evidence,
				// not a cached authorization or proof that the old login succeeded.
				connectorVerification = &jobs.Postcondition{Kind: "connector_recovery_verification", Status: jobs.PostconditionUnobserved, Identity: intent.JobID}
				if verified, verifyErr := verifyConnector(ctx); verifyErr == nil {
					connectorVerification.Status = jobs.PostconditionVerified
					connectorVerification.Identity = digestLifecycle(verified.Observation)
				}
				// Failed verification is recorded as unobserved, not a global
				// recovery failure that would prevent a fresh explicit login.
			}
			mutation, exposure, acquireErr := set.AcquireExposure(ctx, intent.Target, service.manager)
			if acquireErr != nil {
				result = errors.Join(result, acquireErr)
				continue
			}
			fresh, readErr := service.normal.Read()
			if readErr == nil {
				_, readErr = admitter.CompleteInterruptedEntity(ctx, mutation, exposure, fresh.Revision, intent.JobID, childClosureDigest, value.code, connectorVerification)
			}
			result = errors.Join(result, readErr, operations.ReleaseExposure(mutation, exposure))
		default:
			result = errors.Join(result, fmt.Errorf("interrupted entity mutation has unsupported phase %q", intent.Phase))
		}
	}
	return result
}
