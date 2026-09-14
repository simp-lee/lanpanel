//go:build linux

package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/basic"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"strings"
	"time"
)

type ManagedBasicResult struct {
	Job          jobs.Record
	CredentialID string
	Fingerprint  string
	Password     []byte
}
type basicExecution struct {
	service     *FixedService
	admitter    *operations.Admitter
	mutationSet *operations.MutationSet
	mutation    *operations.MutationLease
	exposure    *locks.Lease
	intent      operations.Reservation
	job         jobs.Record
	revision    uint64
	child       *operations.ChildRecord
}

func (value *basicExecution) Close() error {
	if value == nil {
		return nil
	}
	err := operations.ReleaseExposure(value.mutation, value.exposure)
	if value.mutationSet != nil {
		err = errors.Join(err, value.mutationSet.Close())
	}
	if value.service != nil {
		err = errors.Join(err, value.service.Close())
	}
	return err
}

func finalizeManagedBasic(resultErr *error, password []byte, closeExecution func() error) {
	*resultErr = errors.Join(*resultErr, closeExecution())
	if *resultErr != nil {
		clear(password)
	}
}

func (value *basicExecution) completeNoEffect(ctx context.Context, condition jobs.Postcondition, code string, cause error) (jobs.Record, error) {
	if value == nil || value.service == nil || value.admitter == nil || value.mutation == nil || value.exposure == nil {
		return jobs.Record{}, errors.Join(cause, fmt.Errorf("managed Basic no-effect completion authority is unavailable"))
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	document, readErr := value.service.normal.Read()
	if readErr != nil {
		return jobs.Record{}, errors.Join(cause, readErr)
	}
	completed, completeErr := value.admitter.Complete(cleanupCtx, value.mutation, value.exposure, document.Revision, value.job.ID, "no_effect", nil, []jobs.Postcondition{condition}, code)
	if completeErr == nil {
		value.revision = document.Revision + 1
	}
	return completed, errors.Join(cause, completeErr)
}

func basicReservationRejectionCode(operation operations.Type) string {
	switch operation {
	case operations.StaticRootRegister:
		return "static_root_registration_interrupted"
	case operations.ExternalHTPasswdRegister:
		return "external_htpasswd_registration_interrupted"
	default:
		return "managed_basic_interrupted"
	}
}

func beginBasic(ctx context.Context, operation operations.Type, target, actor string, binding operations.SafetyBinding, planID string) (*basicExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*basicExecution, error) { _ = service.Close(); return nil, cause }
	if operation == operations.ManagedBasicRotate && planID == "" {
		return fail(fmt.Errorf("managed Basic rotation requires a Plan"))
	}
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return fail(err)
	}
	source := operations.AdmissionUI
	var confirmationProof string
	if planID != "" {
		plan, planErr := service.ReadPlan(planID)
		if planErr != nil || plan.Operation != string(operation) || plan.Target.Kind != "credential" || plan.Target.ID != strings.TrimPrefix(target, "credential/") || plan.ActorIdentity != actor || !plan.Config.Applicable || plan.Config.Digest != binding.PriorFingerprint {
			return fail(fmt.Errorf("managed Basic Plan changed"))
		}
		admitter, err = service.Admitter(plan)
		if err != nil {
			return fail(err)
		}
		binding.Deadline = plan.ExpiresAt
		source = operations.AdmissionPlan
		confirmationProof = plan.NonceDigest
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operation, Target: target, ActorIdentity: actor, PlanID: planID, Source: source, SafetyBinding: binding, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	rejectReserved := func(cause error) (*basicExecution, error) {
		rejectErr := rejectReservedBasicOperation(context.WithoutCancel(ctx), service, admitter, job.ID, basicReservationRejectionCode(operation))
		return fail(errors.Join(cause, rejectErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return rejectReserved(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, target, service.manager)
	if err != nil {
		closeErr := mutationSet.Close()
		return rejectReserved(errors.Join(err, closeErr))
	}
	cleanupReserved := func(cause error) (*basicExecution, error) {
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		return rejectReserved(errors.Join(cause, releaseErr, closeErr))
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return cleanupReserved(err)
	}
	var intent operations.Reservation
	if source == operations.AdmissionPlan {
		intent, err = admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: confirmationProof})
	} else {
		intent, err = admitter.BeginUI(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	}
	if err != nil {
		return cleanupReserved(err)
	}
	return &basicExecution{service: service, admitter: admitter, mutationSet: mutationSet, mutation: mutation, exposure: exposure, intent: intent, job: job, revision: intent.IntentGeneration}, nil
}

func (value *basicExecution) reserveBasicHash(ctx context.Context, username string, password []byte) error {
	if value.mutation == nil || value.exposure == nil {
		return fmt.Errorf("managed Basic operation locks missing")
	}
	if err := operations.ReleaseExposure(value.mutation, value.exposure); err != nil {
		return err
	}
	value.mutation = nil
	value.exposure = nil
	if err := value.mutationSet.Close(); err != nil {
		return err
	}
	value.mutationSet = nil
	document, err := value.service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return err
	}
	childRecord := operations.ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "htpasswd-" + value.job.ID, JobID: value.job.ID, InstallationID: installation.InstallationID, Operation: value.intent.Operation, Target: value.intent.Target, IntentGeneration: value.intent.IntentGeneration, Profile: "htpasswd", InputDigest: shaDigest(password), ArtifactDigest: shaDigest([]byte(username + "\x00cost=12")), Deadline: value.intent.SafetyBinding.Deadline, State: operations.ChildSubmitted, SubmittedAt: time.Now().UTC()}
	admission, err := value.service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return err
	}
	err = value.admitter.ReserveChild(ctx, admission, document.Revision, childRecord)
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return errors.Join(err, releaseErr)
	}
	value.revision = document.Revision + 1
	value.mutationSet, err = operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: value.service.manager.Authority()})
	if err != nil {
		return err
	}
	value.mutation, value.exposure, err = value.mutationSet.AcquireExposure(ctx, value.intent.Target, value.service.manager)
	if err != nil {
		return err
	}
	childRecord.State = operations.ChildRunning
	if err := value.admitter.TransitionChild(ctx, value.mutation, value.exposure, value.revision, childRecord); err != nil {
		return err
	}
	value.revision++
	value.child = &childRecord
	return nil
}

func (value *basicExecution) terminalBasicHash(ctx context.Context, outcome operations.ChildOutcome, resultDigest string) error {
	if value.child == nil {
		return fmt.Errorf("managed Basic child missing")
	}
	terminal := time.Now().UTC()
	childRecord := *value.child
	childRecord.State = operations.ChildTerminal
	childRecord.Outcome = outcome
	childRecord.ResultDigest = resultDigest
	childRecord.TerminalAt = &terminal
	if err := value.admitter.TransitionChild(ctx, value.mutation, value.exposure, value.revision, childRecord); err != nil {
		return err
	}
	value.revision++
	value.child = &childRecord
	return nil
}

func hashBasic(_ context.Context, _ string, username string, password []byte) (basic.Generated, error) {
	return basic.Hash(username, password)
}

func newCredentialID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "cred_" + hex.EncodeToString(raw), nil
}

func managedBasicCredentialBinding(credential domain.Credential) (string, error) {
	raw, err := json.Marshal(credential)
	if err != nil {
		return "", err
	}
	return shaDigest(raw), nil
}

func basicCredential(installation domain.Installation, credentialID string) (domain.Credential, error) {
	for _, credential := range installation.Credentials {
		if credential.ID == credentialID && credential.Kind == "managed_basic" {
			return credential, nil
		}
	}
	return domain.Credential{}, fmt.Errorf("managed Basic credential missing")
}

func loadBasicInstallation(service *FixedService) (domain.Installation, error) {
	document, err := service.normal.Read()
	if err != nil {
		return domain.Installation{}, err
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return domain.Installation{}, fmt.Errorf("installation authority missing")
	}
	return domain.DecodeInstallation(raw)
}

func CreateManagedBasic(ctx context.Context, resourceID, username, actor string) (result ManagedBasicResult, resultErr error) {
	if err := requireNoDegradedAppliedSource(resourceID); err != nil {
		return result, err
	}
	credentialID, err := newCredentialID()
	if err != nil {
		return result, err
	}
	execution, err := beginBasic(ctx, operations.ManagedBasicCreate, "resource/"+resourceID, actor, operations.SafetyBinding{ResourceID: resourceID, Deadline: time.Now().UTC().Add(time.Minute)}, "")
	if err != nil {
		return result, err
	}
	var password []byte
	defer func() { finalizeManagedBasic(&resultErr, password, execution.Close) }()
	password, err = basic.NewPassword()
	if err != nil {
		completed, terminalErr := execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "managed_basic_not_created", Status: jobs.PostconditionVerified, Identity: credentialID}, "managed_basic_generation_failed", err)
		result.Job = completed
		return result, terminalErr
	}
	if err := execution.reserveBasicHash(ctx, username, password); err != nil {
		return result, err
	}
	generated, hashErr := hashBasic(ctx, credentialID, username, password)
	resultDigest := shaDigest([]byte("bcrypt_failed"))
	outcome := operations.ChildFailed
	if hashErr == nil {
		resultDigest = generated.Fingerprint
		outcome = operations.ChildSucceeded
	}
	if err := execution.terminalBasicHash(ctx, outcome, resultDigest); err != nil {
		return result, err
	}
	if hashErr != nil {
		_, completeErr := execution.admitter.Complete(ctx, execution.mutation, execution.exposure, execution.revision, execution.job.ID, "no_effect", nil, []jobs.Postcondition{{Kind: "managed_basic_not_created", Status: jobs.PostconditionVerified, Identity: credentialID}}, "managed_basic_hash_failed")
		return result, errors.Join(hashErr, completeErr)
	}
	defer clear(generated.Record)
	path := basic.Path(credentialID)
	credential := domain.Credential{ID: credentialID, Kind: "managed_basic", OwnerResourceID: resourceID, Username: username, ManagedPath: path, Fingerprint: generated.Fingerprint}
	candidateBinding, err := managedBasicCredentialBinding(credential)
	if err != nil {
		return result, err
	}
	if err := execution.admitter.BindOperationIdentity(ctx, execution.mutation, execution.exposure, execution.revision, execution.job.ID, candidateBinding); err != nil {
		return result, err
	}
	execution.revision++
	journal := BasicJournal{SchemaVersion: basicJournalSchema, JobID: execution.job.ID, Operation: "create", CredentialID: credentialID, ResourceID: resourceID, Username: username, Path: path, CandidateFingerprint: generated.Fingerprint}
	if err := writeBasicJournal(ctx, journal); err != nil {
		return result, err
	}
	gid, err := nginxGroupGID()
	if err != nil {
		return result, err
	}
	stored, err := basic.Store(ctx, credentialID, generated.Record, gid)
	if err != nil || stored != path {
		return result, fmt.Errorf("managed Basic path changed: %w", err)
	}
	if err := execution.admitter.CommitManagedBasicCreate(ctx, execution.mutation, execution.exposure, execution.revision, execution.job.ID, credential); err != nil {
		return result, err
	}
	completed, err := execution.admitter.CompleteWithSecret(ctx, execution.mutation, execution.exposure, execution.revision+1, execution.job.ID, "complete", []string{path}, []jobs.Postcondition{{Kind: "managed_basic_created", Status: jobs.PostconditionVerified, Identity: generated.Fingerprint}}, "", &jobs.SecretResult{Kind: "managed_basic", ObjectID: credentialID, Fingerprint: generated.Fingerprint, DeliveryAttempted: true, Remedy: "rotate_again"})
	if err != nil {
		return result, err
	}
	if err := removeBasicJournal(basicJournalPath(credentialID)); err != nil {
		return result, err
	}
	return ManagedBasicResult{Job: completed, CredentialID: credentialID, Fingerprint: generated.Fingerprint, Password: password}, nil
}

func RotateManagedBasic(ctx context.Context, credentialID, actor, planID string) (result ManagedBasicResult, resultErr error) {
	service, err := OpenFixed()
	if err != nil {
		return result, err
	}
	installation, err := loadBasicInstallation(service)
	_ = service.Close()
	if err != nil {
		return result, err
	}
	credential, err := basicCredential(installation, credentialID)
	if err != nil {
		return result, err
	}
	if err := requireNoDegradedAppliedSource(credential.OwnerResourceID); err != nil {
		return result, err
	}
	execution, err := beginBasic(ctx, operations.ManagedBasicRotate, "credential/"+credentialID, actor, operations.SafetyBinding{ResourceID: credential.OwnerResourceID, PriorFingerprint: credential.Fingerprint, Deadline: time.Now().UTC().Add(time.Minute)}, planID)
	if err != nil {
		return result, err
	}
	var password []byte
	defer func() { finalizeManagedBasic(&resultErr, password, execution.Close) }()
	lockedInstallation, err := loadBasicInstallation(execution.service)
	if err != nil {
		completed, terminalErr := execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "managed_basic_not_rotated", Status: jobs.PostconditionVerified, Identity: credential.Fingerprint}, "managed_basic_revalidation_failed", err)
		result = ManagedBasicResult{Job: completed, CredentialID: credentialID, Fingerprint: credential.Fingerprint}
		return result, terminalErr
	}
	lockedCredential, err := basicCredential(lockedInstallation, credentialID)
	if err != nil || lockedCredential != credential {
		completed, terminalErr := execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "managed_basic_prior_changed", Status: jobs.PostconditionVerified, Identity: credential.Fingerprint}, "plan_consumption_rejected", errors.Join(fmt.Errorf("managed Basic credential changed before locked mutation"), err))
		result = ManagedBasicResult{Job: completed, CredentialID: credentialID, Fingerprint: lockedCredential.Fingerprint}
		return result, terminalErr
	}
	credential = lockedCredential
	password, err = basic.NewPassword()
	if err != nil {
		completed, terminalErr := execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "managed_basic_not_rotated", Status: jobs.PostconditionVerified, Identity: credential.Fingerprint}, "managed_basic_generation_failed", err)
		result = ManagedBasicResult{Job: completed, CredentialID: credentialID, Fingerprint: credential.Fingerprint}
		return result, terminalErr
	}
	if err := execution.reserveBasicHash(ctx, credential.Username, password); err != nil {
		return result, err
	}
	generated, hashErr := hashBasic(ctx, credentialID, credential.Username, password)
	resultDigest := shaDigest([]byte("bcrypt_failed"))
	outcome := operations.ChildFailed
	if hashErr == nil {
		resultDigest = generated.Fingerprint
		outcome = operations.ChildSucceeded
	}
	if err := execution.terminalBasicHash(ctx, outcome, resultDigest); err != nil {
		return result, err
	}
	if hashErr != nil {
		_, completeErr := execution.admitter.Complete(ctx, execution.mutation, execution.exposure, execution.revision, execution.job.ID, "no_effect", nil, []jobs.Postcondition{{Kind: "managed_basic_not_rotated", Status: jobs.PostconditionVerified, Identity: credentialID}}, "managed_basic_hash_failed")
		return result, errors.Join(hashErr, completeErr)
	}
	defer clear(generated.Record)
	candidateCredential := credential
	candidateCredential.Fingerprint = generated.Fingerprint
	candidateBinding, err := managedBasicCredentialBinding(candidateCredential)
	if err != nil {
		return result, err
	}
	if err := execution.admitter.BindOperationIdentity(ctx, execution.mutation, execution.exposure, execution.revision, execution.job.ID, candidateBinding); err != nil {
		return result, err
	}
	execution.revision++
	journal := BasicJournal{SchemaVersion: basicJournalSchema, JobID: execution.job.ID, Operation: "rotate", CredentialID: credentialID, ResourceID: credential.OwnerResourceID, Username: credential.Username, Path: credential.ManagedPath, PriorFingerprint: credential.Fingerprint, CandidateFingerprint: generated.Fingerprint}
	if err := writeBasicJournal(ctx, journal); err != nil {
		return result, err
	}
	gid, err := nginxGroupGID()
	if err != nil {
		return result, err
	}
	stored, err := basic.Store(ctx, credentialID, generated.Record, gid)
	if err != nil || stored != credential.ManagedPath {
		return result, fmt.Errorf("managed Basic path changed: %w", err)
	}
	if err := execution.admitter.CommitManagedBasicFingerprint(ctx, execution.mutation, execution.exposure, execution.revision, execution.job.ID, credential, generated.Fingerprint); err != nil {
		return result, err
	}
	completed, err := execution.admitter.CompleteWithSecret(ctx, execution.mutation, execution.exposure, execution.revision+1, execution.job.ID, "complete", []string{credential.ManagedPath}, []jobs.Postcondition{{Kind: "managed_basic_rotated", Status: jobs.PostconditionVerified, Identity: generated.Fingerprint}}, "", &jobs.SecretResult{Kind: "managed_basic", ObjectID: credentialID, Fingerprint: generated.Fingerprint, DeliveryAttempted: true, Remedy: "rotate_again"})
	if err != nil {
		return result, err
	}
	if err := removeBasicJournal(basicJournalPath(credentialID)); err != nil {
		return result, err
	}
	return ManagedBasicResult{Job: completed, CredentialID: credentialID, Fingerprint: generated.Fingerprint, Password: password}, nil
}

func beginBasicDelete(ctx context.Context, credential domain.Credential, actor, planID string) (*basicExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*basicExecution, error) { _ = service.Close(); return nil, cause }
	plan, err := service.ReadPlan(planID)
	if err != nil || plan.Operation != string(domain.OperationManagedBasicDelete) || plan.Target.Kind != "credential" || plan.Target.ID != credential.ID || plan.ActorIdentity != actor || !plan.Config.Applicable || plan.Config.Digest != credential.Fingerprint {
		return fail(fmt.Errorf("managed Basic delete Plan changed"))
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return fail(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ManagedBasicDelete, Target: "credential/" + credential.ID, ActorIdentity: actor, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{ResourceID: credential.OwnerResourceID, PriorFingerprint: credential.Fingerprint, Deadline: plan.ExpiresAt}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	rejectReserved := func(cause error) (*basicExecution, error) {
		rejectErr := rejectReservedBasicOperation(context.WithoutCancel(ctx), service, admitter, job.ID, "managed_basic_interrupted")
		return fail(errors.Join(cause, rejectErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return rejectReserved(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "credential/"+credential.ID, service.manager)
	if err != nil {
		closeErr := mutationSet.Close()
		return rejectReserved(errors.Join(err, closeErr))
	}
	cleanupReserved := func(cause error) (*basicExecution, error) {
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		return rejectReserved(errors.Join(cause, releaseErr, closeErr))
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return cleanupReserved(err)
	}
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		return cleanupReserved(err)
	}
	return &basicExecution{service: service, admitter: admitter, mutationSet: mutationSet, mutation: mutation, exposure: exposure, intent: intent, job: job, revision: intent.IntentGeneration}, nil
}

func DeleteManagedBasic(ctx context.Context, credentialID, actor, planID string) (record jobs.Record, resultErr error) {
	service, err := OpenFixed()
	if err != nil {
		return record, err
	}
	installation, err := loadBasicInstallation(service)
	_ = service.Close()
	if err != nil {
		return record, err
	}
	credential, err := basicCredential(installation, credentialID)
	if err != nil {
		return record, err
	}
	if err := requireNoDegradedAppliedSource(credential.OwnerResourceID); err != nil {
		return record, err
	}
	execution, err := beginBasicDelete(ctx, credential, actor, planID)
	if err != nil {
		return record, err
	}
	defer func() { resultErr = errors.Join(resultErr, execution.Close()) }()
	freshInstallation, err := loadBasicInstallation(execution.service)
	if err != nil {
		return execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "managed_basic_not_deleted", Status: jobs.PostconditionVerified, Identity: credential.Fingerprint}, "plan_consumption_rejected", err)
	}
	lockedCredential, err := basicCredential(freshInstallation, credentialID)
	if err != nil || lockedCredential != credential {
		return execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "managed_basic_prior_changed", Status: jobs.PostconditionVerified, Identity: credential.Fingerprint}, "plan_consumption_rejected", errors.Join(fmt.Errorf("managed Basic credential changed before locked delete"), err))
	}
	credential = lockedCredential
	for _, resource := range freshInstallation.Resources {
		if applicationCredentialReferenced(resource, credentialID) {
			return execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "managed_basic_delete_blocked", Status: jobs.PostconditionVerified, Identity: credentialID}, "plan_consumption_rejected", fmt.Errorf("active resource reference blocks credential delete"))
		}
	}
	journal := BasicJournal{SchemaVersion: basicJournalSchema, JobID: execution.job.ID, Operation: "delete", CredentialID: credentialID, ResourceID: credential.OwnerResourceID, Username: credential.Username, Path: credential.ManagedPath, PriorFingerprint: credential.Fingerprint}
	if err := writeBasicJournal(ctx, journal); err != nil {
		return record, err
	}
	if err := execution.admitter.CommitManagedBasicDelete(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration, execution.job.ID, credential); err != nil {
		return record, err
	}
	gid, err := nginxGroupGID()
	if err != nil {
		return record, err
	}
	if err := basic.Delete(ctx, credentialID, gid); err != nil {
		return record, err
	}
	completed, err := execution.admitter.Complete(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration+1, execution.job.ID, "complete", []string{credential.ManagedPath}, []jobs.Postcondition{{Kind: "managed_basic_deleted", Status: jobs.PostconditionVerified, Identity: credentialID}}, "")
	if err != nil {
		return record, err
	}
	if err := removeBasicJournal(basicJournalPath(credentialID)); err != nil {
		return record, err
	}
	return completed, nil
}
