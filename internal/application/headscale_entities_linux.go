//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"strconv"
	"time"
)

type HeadscaleUserPayload struct {
	Name string `json:"name"`
}

type HeadscaleLifecyclePayload struct {
	PlanID            string `json:"plan_id,omitempty"`
	Confirmation      string `json:"confirmation,omitempty"`
	ExpirationSeconds uint32 `json:"expiration_seconds,omitempty"`
}

type HeadscaleUsersResult struct {
	Users []managedheadscale.User `json:"users"`
}
type HeadscaleKeysResult struct {
	Keys []managedheadscale.PreauthKey `json:"keys"`
}
type HeadscaleDevicesResult struct {
	Devices []managedheadscale.Device `json:"devices"`
}
type HeadscaleUserResult struct {
	JobID string                `json:"job_id"`
	User  managedheadscale.User `json:"user"`
}
type HeadscaleKeyResult struct {
	JobID  string                      `json:"job_id"`
	Key    managedheadscale.PreauthKey `json:"key"`
	Secret []byte                      `json:"secret,omitempty"`
}
type HeadscaleDeviceResult struct {
	JobID  string                  `json:"job_id"`
	Device managedheadscale.Device `json:"device"`
}

type headscaleLifecycleAuthority struct {
	service      *FixedService
	documentRev  uint64
	installation domain.Installation
	runner       managedheadscale.AdminRunner
}

func openHeadscaleLifecycle(runner managedheadscale.AdminRunner) (*headscaleLifecycleAuthority, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*headscaleLifecycleAuthority, error) { _ = service.Close(); return nil, err }
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil || installation.Headscale == nil || !installation.Headscale.Enabled || installation.Headscale.Applied == nil || installation.Headscale.Artifact.Version == "" {
		return fail(errors.Join(err, fmt.Errorf("headscale active lifecycle authority is unavailable")))
	}
	if runner == nil {
		runner, err = managedheadscale.NewFixedAdminRunner(installation.InstallationID, installation.Headscale.ID)
		if err != nil {
			return fail(err)
		}
	}
	return &headscaleLifecycleAuthority{service: service, documentRev: document.Revision, installation: installation, runner: runner}, nil
}

func ListHeadscaleUsers(ctx context.Context, runner managedheadscale.AdminRunner) (HeadscaleUsersResult, error) {
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return HeadscaleUsersResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	users, err := managedheadscale.ListUsers(ctx, authority.runner, authority.installation.Headscale.ID)
	return HeadscaleUsersResult{Users: users}, err
}

func ListHeadscalePreauthKeys(ctx context.Context, runner managedheadscale.AdminRunner) (HeadscaleKeysResult, error) {
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return HeadscaleKeysResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	keys, err := managedheadscale.ListPreauthKeys(ctx, authority.runner, authority.installation.Headscale.ID)
	return HeadscaleKeysResult{Keys: keys}, err
}

func ListHeadscaleDevices(ctx context.Context, runner managedheadscale.AdminRunner) (HeadscaleDevicesResult, error) {
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return HeadscaleDevicesResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	devices, err := managedheadscale.ListDevices(ctx, authority.runner, authority.installation.Headscale.ID)
	return HeadscaleDevicesResult{Devices: devices}, err
}

func CreateHeadscaleUser(ctx context.Context, actor Actor, payload HeadscaleUserPayload, runner managedheadscale.AdminRunner) (HeadscaleUserResult, error) {
	if payload.Name == "" {
		return HeadscaleUserResult{}, fmt.Errorf("headscale user name is required")
	}
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return HeadscaleUserResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	configDigest := digestLifecycle(payload)
	execution, err := beginHeadscaleEntityMutation(ctx, authority, actor, operations.HeadscaleUserCreate, "headscale/"+authority.installation.Headscale.ID, "", configDigest)
	if err != nil {
		return HeadscaleUserResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(execution.close)
	user, runErr := managedheadscale.CreateUser(ctx, authority.runner, authority.installation.Headscale.ID, payload.Name)
	if runErr != nil {
		return HeadscaleUserResult{}, errors.Join(runErr, execution.fail(ctx, "headscale_user_create_failed"))
	}
	if err := execution.complete(ctx, []jobs.Postcondition{{Kind: "headscale_user_created", Status: jobs.PostconditionVerified, Identity: strconv.FormatUint(user.ID, 10)}}, nil); err != nil {
		return HeadscaleUserResult{}, err
	}
	return HeadscaleUserResult{JobID: execution.jobID, User: user}, nil
}

func CreateHeadscaleLifecyclePlan(ctx context.Context, actor Actor, operation domain.OperationCode, target domain.OperationTarget, payload HeadscaleLifecyclePayload, runner managedheadscale.AdminRunner) (plans.Plan, error) {
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	actorID, err := actorAuthority(actor)
	if err != nil {
		return plans.Plan{}, err
	}
	if err := domain.ValidateOperationTarget(operation, target); err != nil {
		return plans.Plan{}, err
	}
	configDigest, summary, err := observeHeadscaleLifecyclePlan(ctx, authority, operation, target, payload)
	if err != nil {
		return plans.Plan{}, err
	}
	admission, err := authority.service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(admission.Release)
	spec := plans.Spec{Operation: string(operation), Target: plans.Target{Kind: plans.TargetKind(target.Kind), ID: target.ID}, ActorIdentity: actorID, Config: plans.DigestBinding{Applicable: true, Digest: configDigest}, ExposureSummary: summary, Prerequisites: "fresh immutable Headscale ID and exact active control authority", Lifetime: 10 * time.Minute}
	return authority.service.plans.Create(ctx, admission, authority.documentRev, spec)
}

func CreateHeadscalePreauthKey(ctx context.Context, actor Actor, target domain.OperationTarget, payload HeadscaleLifecyclePayload, runner managedheadscale.AdminRunner) (HeadscaleKeyResult, error) {
	if payload.PlanID == "" || payload.Confirmation != "create" || payload.ExpirationSeconds == 0 || payload.ExpirationSeconds > 24*60*60 {
		return HeadscaleKeyResult{}, fmt.Errorf("preauth key confirmation or expiration is invalid")
	}
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return HeadscaleKeyResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	configDigest, _, err := observeHeadscaleLifecyclePlan(ctx, authority, domain.OperationPreauthKeyCreate, target, payload)
	if err != nil {
		return HeadscaleKeyResult{}, err
	}
	execution, err := beginHeadscaleEntityMutation(ctx, authority, actor, operations.PreauthKeyCreate, "headscale_user/"+target.ID, payload.PlanID, configDigest)
	if err != nil {
		return HeadscaleKeyResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(execution.close)
	userID, _ := strconv.ParseUint(target.ID, 10, 64)
	key, secret, runErr := managedheadscale.CreatePreauthKey(ctx, authority.runner, authority.installation.Headscale.ID, userID, time.Duration(payload.ExpirationSeconds)*time.Second)
	if runErr != nil {
		return HeadscaleKeyResult{}, errors.Join(runErr, execution.fail(ctx, "preauth_key_create_failed"))
	}
	fingerprint := digestSecret(secret)
	if err := execution.complete(ctx, []jobs.Postcondition{{Kind: "preauth_key_created", Status: jobs.PostconditionVerified, Identity: strconv.FormatUint(key.ID, 10)}}, &jobs.SecretResult{Kind: "preauth_key", ObjectID: strconv.FormatUint(key.ID, 10), Fingerprint: fingerprint, DeliveryAttempted: true, Remedy: "revoke_and_create"}); err != nil {
		clear(secret)
		return HeadscaleKeyResult{}, err
	}
	return HeadscaleKeyResult{JobID: execution.jobID, Key: key, Secret: secret}, nil
}

func RevokeHeadscalePreauthKey(ctx context.Context, actor Actor, target domain.OperationTarget, payload HeadscaleLifecyclePayload, runner managedheadscale.AdminRunner) (HeadscaleKeyResult, error) {
	if payload.PlanID == "" || payload.Confirmation != "revoke" {
		return HeadscaleKeyResult{}, fmt.Errorf("preauth key revoke confirmation is invalid")
	}
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return HeadscaleKeyResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	configDigest, _, err := observeHeadscaleLifecyclePlan(ctx, authority, domain.OperationPreauthKeyRevoke, target, payload)
	if err != nil {
		return HeadscaleKeyResult{}, err
	}
	execution, err := beginHeadscaleEntityMutation(ctx, authority, actor, operations.PreauthKeyRevoke, "preauth_key/"+target.ID, payload.PlanID, configDigest)
	if err != nil {
		return HeadscaleKeyResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(execution.close)
	id, _ := strconv.ParseUint(target.ID, 10, 64)
	key, runErr := managedheadscale.RevokePreauthKey(ctx, authority.runner, authority.installation.Headscale.ID, id)
	if runErr != nil {
		return HeadscaleKeyResult{}, errors.Join(runErr, execution.fail(ctx, "preauth_key_revoke_failed"))
	}
	if err := execution.complete(ctx, []jobs.Postcondition{{Kind: "preauth_key_revoked", Status: jobs.PostconditionVerified, Identity: target.ID}}, nil); err != nil {
		return HeadscaleKeyResult{}, err
	}
	return HeadscaleKeyResult{JobID: execution.jobID, Key: key}, nil
}

func ExpireHeadscaleDevice(ctx context.Context, actor Actor, target domain.OperationTarget, payload HeadscaleLifecyclePayload, runner managedheadscale.AdminRunner) (HeadscaleDeviceResult, error) {
	if payload.PlanID == "" || payload.Confirmation != "expire" {
		return HeadscaleDeviceResult{}, fmt.Errorf("device expiry confirmation is invalid")
	}
	authority, err := openHeadscaleLifecycle(runner)
	if err != nil {
		return HeadscaleDeviceResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(authority.service.Close)
	configDigest, _, err := observeHeadscaleLifecyclePlan(ctx, authority, domain.OperationDeviceExpire, target, payload)
	if err != nil {
		return HeadscaleDeviceResult{}, err
	}
	execution, err := beginHeadscaleEntityMutation(ctx, authority, actor, operations.DeviceExpire, "device/"+target.ID, payload.PlanID, configDigest)
	if err != nil {
		return HeadscaleDeviceResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(execution.close)
	id, _ := strconv.ParseUint(target.ID, 10, 64)
	device, runErr := managedheadscale.ExpireDevice(ctx, authority.runner, authority.installation.Headscale.ID, id)
	if runErr != nil {
		return HeadscaleDeviceResult{}, errors.Join(runErr, execution.fail(ctx, "device_expire_failed"))
	}
	if err := execution.complete(ctx, []jobs.Postcondition{{Kind: "device_expired", Status: jobs.PostconditionVerified, Identity: target.ID}}, nil); err != nil {
		return HeadscaleDeviceResult{}, err
	}
	return HeadscaleDeviceResult{JobID: execution.jobID, Device: device}, nil
}

func observeHeadscaleLifecyclePlan(ctx context.Context, authority *headscaleLifecycleAuthority, operation domain.OperationCode, target domain.OperationTarget, payload HeadscaleLifecyclePayload) (string, string, error) {
	switch operation {
	case domain.OperationPreauthKeyCreate:
		if payload.ExpirationSeconds == 0 {
			payload.ExpirationSeconds = 3600
		}
		if payload.ExpirationSeconds > 24*60*60 {
			return "", "", fmt.Errorf("preauth key expiration exceeds 24 hours")
		}
		users, err := managedheadscale.ListUsers(ctx, authority.runner, authority.installation.Headscale.ID)
		if err != nil {
			return "", "", err
		}
		found := false
		for _, user := range users {
			found = found || strconv.FormatUint(user.ID, 10) == target.ID
		}
		if !found {
			return "", "", fmt.Errorf("immutable Headscale user ID is absent")
		}
		return digestLifecycle(struct {
			Operation, ID string
			Expiration    uint32
		}{string(operation), target.ID, payload.ExpirationSeconds}), "creates one-use untagged preauth key for user " + target.ID, nil
	case domain.OperationPreauthKeyRevoke:
		keys, err := managedheadscale.ListPreauthKeys(ctx, authority.runner, authority.installation.Headscale.ID)
		if err != nil {
			return "", "", err
		}
		for _, key := range keys {
			if strconv.FormatUint(key.ID, 10) == target.ID {
				return digestLifecycle(key), "revokes preauth key " + target.ID + "; registered devices are unchanged", nil
			}
		}
		return "", "", fmt.Errorf("immutable preauth key ID is absent")
	case domain.OperationDeviceExpire:
		devices, err := managedheadscale.ListDevices(ctx, authority.runner, authority.installation.Headscale.ID)
		if err != nil {
			return "", "", err
		}
		for _, device := range devices {
			if strconv.FormatUint(device.ID, 10) == target.ID {
				return digestLifecycle(device), "expires device " + target.ID + "; existing flows may continue", nil
			}
		}
		return "", "", fmt.Errorf("immutable device ID is absent")
	default:
		return "", "", fmt.Errorf("headscale lifecycle Plan operation is unavailable")
	}
}

type headscaleEntityExecution struct {
	service  *FixedService
	admitter *operations.Admitter
	set      *operations.MutationSet
	mutation *operations.MutationLease
	exposure *locks.Lease
	jobID    string
}

func beginHeadscaleEntityMutation(ctx context.Context, authority *headscaleLifecycleAuthority, actor Actor, operation operations.Type, target, planID, configDigest string) (*headscaleEntityExecution, error) {
	actorID, err := actorAuthority(actor)
	if err != nil {
		return nil, err
	}
	var admitter *operations.Admitter
	var source operations.AdmissionSource
	var plan plans.Plan
	if planID == "" {
		admitter, err = authority.service.resourceAdmitter()
		source = operations.AdmissionUI
	} else {
		plan, err = authority.service.ReadPlan(planID)
		if err == nil && (plan.Operation != string(operation) || plan.ActorIdentity != actorID || plan.Config.Digest != configDigest || target != string(plan.Target.Kind)+"/"+plan.Target.ID) {
			err = fmt.Errorf("headscale lifecycle Plan authority changed")
		}
		if err == nil {
			admitter, err = authority.service.Admitter(plan)
		}
		source = operations.AdmissionPlan
	}
	if err != nil {
		return nil, err
	}
	admission, err := authority.service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return nil, err
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operation, Target: target, ActorIdentity: actorID, PlanID: planID, Source: source, SafetyBinding: operations.SafetyBinding{ResourceID: "headscale", CandidateDigest: configDigest, CandidateBundle: configDigest, PlanID: planID}, ExpectedRevision: authority.documentRev})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		return nil, errors.Join(admitErr, releaseErr)
	}
	reject := func(cause error) error {
		lease, acquireErr := authority.service.manager.Acquire(context.WithoutCancel(ctx), locks.MutationAdmission)
		if acquireErr != nil {
			return errors.Join(cause, acquireErr)
		}
		defer func(ignore func() error) { _ = ignore() }(lease.Release)
		current, readErr := authority.service.normal.Read()
		if readErr != nil {
			return errors.Join(cause, readErr)
		}
		return errors.Join(cause, admitter.RejectReservation(context.WithoutCancel(ctx), lease, current.Revision, job.ID, "plan_consumption_rejected"))
	}
	set, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: authority.service.manager.Authority()})
	if err != nil {
		return nil, reject(err)
	}
	mutation, exposure, err := set.AcquireExposure(ctx, target, authority.service.manager)
	if err != nil {
		_ = set.Close()
		return nil, reject(err)
	}
	fresh, err := authority.service.normal.Read()
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = set.Close()
		return nil, reject(err)
	}
	var intent operations.Reservation
	if planID == "" {
		intent, err = admitter.BeginUI(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	} else {
		intent, err = admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest})
	}
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = set.Close()
		return nil, reject(err)
	}
	if _, err = admitter.EnterRemoteWait(ctx, mutation, exposure, intent.IntentGeneration, job.ID); err != nil {
		_ = set.Close()
		return nil, err
	}
	return &headscaleEntityExecution{service: authority.service, admitter: admitter, set: set, jobID: job.ID}, nil
}

func (execution *headscaleEntityExecution) reenter(ctx context.Context) (uint64, error) {
	document, err := execution.service.normal.Read()
	if err != nil {
		return 0, err
	}
	intent, mutation, exposure, err := execution.admitter.Reenter(context.WithoutCancel(ctx), execution.set, execution.service.manager, document.Revision, execution.jobID)
	if err != nil {
		return 0, err
	}
	execution.mutation, execution.exposure = mutation, exposure
	return intent.IntentGeneration, nil
}

func (execution *headscaleEntityExecution) complete(ctx context.Context, postconditions []jobs.Postcondition, secret *jobs.SecretResult) error {
	revision, err := execution.reenter(ctx)
	if err != nil {
		return err
	}
	if secret != nil {
		_, err = execution.admitter.CompleteWithSecret(ctx, execution.mutation, execution.exposure, revision, execution.jobID, "complete", nil, postconditions, "", secret)
	} else {
		_, err = execution.admitter.Complete(ctx, execution.mutation, execution.exposure, revision, execution.jobID, "complete", nil, postconditions, "")
	}
	return err
}

func (execution *headscaleEntityExecution) fail(ctx context.Context, code string) error {
	revision, err := execution.reenter(ctx)
	if err != nil {
		return err
	}
	_, err = execution.admitter.Complete(context.WithoutCancel(ctx), execution.mutation, execution.exposure, revision, execution.jobID, "source_unknown", nil, []jobs.Postcondition{{Kind: "headscale_lifecycle_observation", Status: jobs.PostconditionUnobserved, Identity: execution.jobID}}, code)
	return err
}

func (execution *headscaleEntityExecution) close() error {
	return errors.Join(operations.ReleaseExposure(execution.mutation, execution.exposure), execution.set.Close())
}

func digestLifecycle(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestSecret(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
