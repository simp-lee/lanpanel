//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"lanpanel/internal/secrets"
	"sync"
	"time"
)

type Rotation struct {
	Service     *FixedService
	Admitter    *operations.Admitter
	MutationSet *operations.MutationSet
	Plan        plans.Plan
	Job         jobs.Record
	Mutation    *operations.MutationLease
	Exposure    *locks.Lease
	Revision    uint64
	closeOnce   sync.Once
	closeErr    error
}

func BeginAdminTokenRotation(ctx context.Context, actor Actor, payload ConfirmationPayload) (*Rotation, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Rotation, error) { _ = service.Close(); return nil, err }
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	plan, err := service.ReadPlan(payload.PlanID)
	if err != nil {
		return fail(err)
	}
	if plan.Operation != "admin_token_rotate" || plan.ActorIdentity != authority || payload.Confirmation != "rotate" {
		return fail(fmt.Errorf("rotation confirmation invalid"))
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return fail(err)
	}
	document, err := service.Normal().Read()
	if err != nil {
		return fail(err)
	}
	admission, err := service.Manager().Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.AdminTokenRotate, Target: "installation", ActorIdentity: authority, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil {
		return fail(err)
	}
	if releaseErr != nil {
		return fail(releaseErr)
	}
	reservedRevision := document.Revision + 1
	rejectReserved := func(cause error) (*Rotation, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		lease, acquireErr := service.Manager().Acquire(cleanupCtx, locks.MutationAdmission)
		if acquireErr != nil {
			return fail(fmt.Errorf("%v; reserved rotation terminalization lock failed: %w", cause, acquireErr))
		}
		rejectErr := admitter.RejectReservation(cleanupCtx, lease, reservedRevision, job.ID, "admin_token_rotation_interrupted")
		releaseErr := lease.Release()
		if terminalErr := errors.Join(rejectErr, releaseErr); terminalErr != nil {
			return fail(fmt.Errorf("%v; reserved rotation terminalization failed: %w", cause, terminalErr))
		}
		return fail(cause)
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: "/var/lib/lanpanel/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return rejectReserved(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "installation", service.Manager())
	if err != nil {
		_ = mutationSet.Close()
		return rejectReserved(err)
	}
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: reservedRevision, IntentGeneration: reservedRevision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(err)
	}
	return &Rotation{Service: service, Admitter: admitter, MutationSet: mutationSet, Plan: plan, Job: job, Mutation: mutation, Exposure: exposure, Revision: intent.IntentGeneration}, nil
}

func (value *Rotation) PriorFingerprint() string {
	if value == nil || !value.Plan.Applied.Applicable {
		return ""
	}
	return value.Plan.Applied.Digest
}

func (value *Rotation) BindFingerprint(ctx context.Context, fingerprint string) error {
	if value == nil || value.Mutation == nil {
		return fmt.Errorf("rotation is not active")
	}
	if err := value.Admitter.BindSecretFingerprint(ctx, value.Mutation, value.Exposure, value.Revision, value.Job.ID, fingerprint); err != nil {
		return err
	}
	value.Revision++
	return nil
}

func (value *Rotation) MarkCommitted(ctx context.Context, fingerprint string) error {
	if value == nil || value.Mutation == nil {
		return fmt.Errorf("rotation is not active")
	}
	if err := value.Admitter.MarkSecretCommitted(ctx, value.Mutation, value.Exposure, value.Revision, value.Job.ID, fingerprint); err != nil {
		return err
	}
	value.Revision++
	return nil
}

func (value *Rotation) Fail(ctx context.Context, committed bool, fingerprint string) (jobs.Record, error) {
	if value == nil || value.Mutation == nil {
		return jobs.Record{}, fmt.Errorf("rotation is not active")
	}
	branch, status, kind, identity, code, paths := "no_effect", jobs.PostconditionVerified, "mutation_not_started", value.Job.ID, "admin_token_rotation_failed", []string(nil)
	if committed {
		branch, status, kind, identity, code, paths = "known_residual", jobs.PostconditionKnown, "admin_token_source", fingerprint, "admin_token_delivery_failed", []string{"/var/lib/lanpanel/installation/admin-token"}
	} else if fingerprint != "" {
		branch, status, kind, identity, code = "source_unknown", jobs.PostconditionUnobserved, "admin_token_source", fingerprint, "admin_token_source_unknown"
	}
	record, err := value.Admitter.Complete(ctx, value.Mutation, value.Exposure, value.Revision, value.Job.ID, branch, paths, []jobs.Postcondition{{Kind: kind, Status: status, Identity: identity}}, code)
	if err == nil {
		err = errors.Join(err, value.Close())
	}
	return record, err
}

func (value *Rotation) Finish(ctx context.Context, fingerprint string) (jobs.Record, error) {
	if value == nil || value.Mutation == nil {
		return jobs.Record{}, fmt.Errorf("rotation is not active")
	}
	result, err := value.Admitter.CompleteWithSecret(ctx, value.Mutation, value.Exposure, value.Revision, value.Job.ID, "complete", []string{"/var/lib/lanpanel/installation/admin-token"}, []jobs.Postcondition{{Kind: "admin_token_source", Status: jobs.PostconditionVerified, Identity: fingerprint}}, "", &jobs.SecretResult{Kind: "admin_token", ObjectID: "installation", Fingerprint: fingerprint, DeliveryAttempted: true, Remedy: "read_protected_source"})
	if err == nil {
		err = errors.Join(err, value.Close())
	}
	return result, err
}

func ReconcileAdminTokenRotation(ctx context.Context, fingerprint string) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.Normal().Read()
	if err != nil {
		return err
	}
	pending, found, err := operations.FindPendingSecretIntent(document, operations.AdminTokenRotate, "installation")
	if err != nil {
		return err
	}
	if !found {
		return secrets.RequireNoAdminTokenCandidate()
	}
	plan, err := service.ReadPlan(pending.PlanID)
	if err != nil {
		return err
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return err
	}
	if pending.Fingerprint != "" {
		if err := secrets.ReconcileAdminTokenCandidate(plan.Applied.Digest, pending.Fingerprint, fingerprint, pending.Committed); err != nil {
			return err
		}
		fingerprint, err = secrets.CurrentAdminTokenFingerprint()
		if err != nil {
			return err
		}
	}
	if pending.Phase == operations.PhaseReserved {
		admission, acquireErr := service.Manager().Acquire(ctx, locks.MutationAdmission)
		if acquireErr != nil {
			return acquireErr
		}
		rejectErr := admitter.RejectReservation(ctx, admission, document.Revision, pending.JobID, "admin_token_rotation_interrupted")
		releaseErr := admission.Release()
		return errors.Join(rejectErr, releaseErr)
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: "/var/lib/lanpanel/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "installation", service.Manager())
	if err != nil {
		return err
	}
	rotation := &Rotation{Service: service, Admitter: admitter, MutationSet: mutationSet, Plan: plan, Job: jobs.Record{ID: pending.JobID}, Mutation: mutation, Exposure: exposure, Revision: document.Revision}
	defer func() { _ = rotation.Close() }()
	if pending.Committed && pending.Fingerprint != "" && fingerprint == pending.Fingerprint {
		result, finishErr := rotation.Finish(ctx, pending.Fingerprint)
		_ = result
		return finishErr
	}
	if plan.Applied.Applicable && fingerprint == plan.Applied.Digest {
		_, err = rotation.Fail(ctx, false, "")
		return err
	}
	_, err = rotation.Fail(ctx, false, pending.Fingerprint)
	return err
}

func (value *Rotation) Close() error {
	if value == nil {
		return nil
	}
	value.closeOnce.Do(func() {
		value.closeErr = errors.Join(operations.ReleaseExposure(value.Mutation, value.Exposure), value.MutationSet.Close(), value.Service.Close())
		value.Mutation = nil
		value.Exposure = nil
	})
	return value.closeErr
}
