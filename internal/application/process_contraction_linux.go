//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/contraction"
	"lanpanel/internal/domain"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	managedprocess "lanpanel/internal/process"
	"reflect"
	"time"
)

type processRuntimeViolation struct {
	ResourceID    string
	PolicyDigest  string
	Cgroup        string
	RelayRequired bool
	Bundle        domain.ProcessBundle
	Kind          managedprocess.RuntimeViolationKind
	cause         error
}

func (violation *processRuntimeViolation) Error() string {
	if violation == nil || violation.cause == nil {
		return "managed process runtime violation requires contraction"
	}
	return violation.cause.Error()
}

func (violation *processRuntimeViolation) Unwrap() error {
	if violation == nil {
		return nil
	}
	return violation.cause
}

func bindProcessRuntimeViolation(resource domain.AppResource, cause error) error {
	var runtimeViolation *managedprocess.RuntimeViolation
	if !errors.As(cause, &runtimeViolation) {
		return cause
	}
	if resource.ManagedProcess == nil || resource.ManagedProcess.Applied == nil {
		return cause
	}
	bundle := *resource.ManagedProcess.Applied
	return &processRuntimeViolation{
		ResourceID:    resource.ID,
		PolicyDigest:  bundle.PolicyDigest,
		Cgroup:        bundle.Cgroup,
		RelayRequired: bundle.RelayRequired,
		Bundle:        bundle,
		Kind:          runtimeViolation.Kind,
		cause:         cause,
	}
}

func IsProcessRuntimeViolation(err error) bool {
	var violation *processRuntimeViolation
	return errors.As(err, &violation)
}

var (
	errProcessAlreadyContracted = errors.New("managed process is already durably stopped")
	errProcessViolationObsolete = errors.New("managed process violation no longer matches the applied bundle")
)

func obsoleteProcessViolation(err error) bool {
	return errors.Is(err, errProcessAlreadyContracted) || errors.Is(err, errProcessViolationObsolete)
}

// ContractProcessRuntimeViolation consumes only a typed violation returned by a
// publication target probe. If ingress might already be live, it is contracted
// before the violating process is disabled and its complete cgroup closure is
// observed. The process-stop intent and host transition are journaled so an
// interrupted helper restart resumes the same contraction.
func ContractProcessRuntimeViolation(ctx context.Context, cause error) error {
	var violation *processRuntimeViolation
	if !errors.As(cause, &violation) {
		return fmt.Errorf("process contraction requires a typed runtime violation")
	}
	if _, err := managedprocess.RuntimeViolationReason(violation.Kind); err != nil {
		return err
	}

	publicationErr := contractPublishedIngressBeforeProcess(ctx, *violation)
	if obsoleteProcessViolation(publicationErr) {
		return nil
	}
	if publicationErr != nil {
		return publicationErr
	}
	execution, err := beginProcessRuntimeContraction(ctx, *violation)
	if obsoleteProcessViolation(err) {
		return nil
	}
	if err != nil {
		// Admission/revision conflicts can occur after the first bundle check.
		// Recheck under exposure before treating an obsolete probe as a fatal
		// contraction failure (which would terminate the shared helper).
		freshErr := recheckProcessRuntimeViolation(ctx, *violation)
		if obsoleteProcessViolation(freshErr) {
			return nil
		}
		// No stop-by-ID fallback is safe without a matching locked execution.
		return errors.Join(err, freshErr)
	}
	closed := false
	defer func() {
		if !closed {
			_ = execution.Close()
		}
	}()

	bundle := execution.Resource.ManagedProcess.Applied
	if bundle == nil {
		return errors.Join(publicationErr, fmt.Errorf("process contraction lost applied bundle authority"))
	}
	journal := managedprocess.Journal{
		SchemaVersion:   "lanpanel.process.lifecycle.v1",
		JobID:           execution.JobID,
		ResourceID:      violation.ResourceID,
		Operation:       string(operations.ProcessStop),
		Phase:           "prepared",
		BundleDigest:    bundle.PolicyDigest,
		RelayRequired:   bundle.RelayRequired,
		ContractionKind: violation.Kind,
		Applied:         cloneBundleForProcess(bundle),
		ApplicationUID:  bundle.ApplicationUID,
		ApplicationGID:  bundle.ApplicationGID,
		RelayUID:        bundle.RelayUID,
		RelayGID:        bundle.RelayGID,
	}
	recoverFailure := func(cause error) error {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		host, hostErr := managedprocess.NewFixedHost()
		var stopErr, commitErr, verifyErr, closeErr, removeErr error
		if hostErr == nil {
			stopErr = host.Stop(recoveryCtx, violation.ResourceID, bundle.RelayRequired)
		}
		if hostErr == nil && stopErr == nil {
			commitErr = execution.CommitInterrupted(recoveryCtx, bundle)
		}
		if hostErr == nil && stopErr == nil && commitErr == nil {
			verifyErr = host.VerifyCommittedJournal(recoveryCtx, journal, false)
		}
		if hostErr == nil && stopErr == nil && commitErr == nil && verifyErr == nil {
			closeErr = execution.Close()
		}
		if hostErr == nil && stopErr == nil && commitErr == nil && verifyErr == nil && closeErr == nil {
			closed = true
			removeErr = managedprocess.RemoveJournal(violation.ResourceID)
		}
		return errors.Join(publicationErr, cause, hostErr, stopErr, commitErr, verifyErr, closeErr, removeErr)
	}
	if err := managedprocess.WriteJournal(ctx, journal); err != nil {
		return recoverFailure(err)
	}
	host, err := managedprocess.NewFixedHost()
	if err != nil {
		return recoverFailure(err)
	}
	if err := host.Stop(ctx, violation.ResourceID, bundle.RelayRequired); err != nil {
		return recoverFailure(err)
	}
	journal.Phase = "host_mutated"
	if err := managedprocess.WriteJournal(ctx, journal); err != nil {
		return recoverFailure(err)
	}
	observation, err := managedprocess.ObserveStopped(ctx, "/sys/fs/cgroup", *bundle)
	if err == nil {
		err = managedprocess.VerifyStopped(observation)
	}
	if err != nil {
		return recoverFailure(err)
	}
	if _, err := execution.Commit(ctx, bundle, observation); err != nil {
		return recoverFailure(err)
	}
	if err := host.VerifyCommittedJournal(ctx, journal, false); err != nil {
		return recoverFailure(err)
	}
	if err := execution.Close(); err != nil {
		return errors.Join(publicationErr, err)
	}
	closed = true
	if err := managedprocess.RemoveJournal(violation.ResourceID); err != nil {
		return errors.Join(publicationErr, err)
	}
	return publicationErr
}

func beginProcessRuntimeContraction(ctx context.Context, violation processRuntimeViolation) (*ProcessExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*ProcessExecution, error) {
		_ = service.Close()
		return nil, cause
	}
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	if _, err := exactProcessViolationResource(document, violation); err != nil {
		return fail(err)
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{
		Operation:        operations.ProcessStop,
		Target:           "resource/" + violation.ResourceID,
		ActorIdentity:    "runtime-policy-guard/" + string(violation.Kind),
		Source:           operations.AdmissionRuntimeGuard,
		SafetyBinding:    operations.SafetyBinding{ResourceID: violation.ResourceID},
		ExpectedRevision: document.Revision,
	})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		return fail(errors.Join(admitErr, releaseErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+violation.ResourceID, service.manager)
	if err != nil {
		_ = mutationSet.Close()
		return fail(err)
	}
	fresh, err := service.normal.Read()
	if err != nil || fresh.Revision != document.Revision+1 {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(errors.Join(err, fmt.Errorf("process contraction authority changed")))
	}
	resource, err := exactProcessViolationResource(fresh, violation)
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(err)
	}
	intent, err := admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(err)
	}
	return &ProcessExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: intent.IntentGeneration, Resource: resource, Operation: operations.ProcessStop, ContractionKind: violation.Kind}, nil
}

func recheckProcessRuntimeViolation(ctx context.Context, violation processRuntimeViolation) (returnErr error) {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	exposure, err := service.manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, exposure.Release()) }()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	_, err = boundProcessViolationResource(document, violation)
	return err
}

func exactProcessViolationResource(document persist.Document, violation processRuntimeViolation) (domain.AppResource, error) {
	resource, err := boundProcessViolationResource(document, violation)
	if err != nil {
		return domain.AppResource{}, err
	}
	if resource.PublicationRecord.State != domain.PublicationUnpublished {
		return domain.AppResource{}, fmt.Errorf("process contraction requires publication closure first")
	}
	return resource, nil
}

func boundProcessViolationResource(document persist.Document, violation processRuntimeViolation) (domain.AppResource, error) {
	raw, present := document.Entries["installations/current"]
	if !present {
		return domain.AppResource{}, fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return domain.AppResource{}, err
	}
	for _, resource := range installation.Resources {
		if resource.ID != violation.ResourceID {
			continue
		}
		managed := resource.ManagedProcess
		if managed == nil || managed.Applied == nil || !reflect.DeepEqual(*managed.Applied, violation.Bundle) {
			return domain.AppResource{}, errProcessViolationObsolete
		}
		if managed.Requested == domain.ProcessRequestedStopped {
			return domain.AppResource{}, errProcessAlreadyContracted
		}
		return resource, nil
	}
	return domain.AppResource{}, errProcessViolationObsolete
}

func contractPublishedIngressBeforeProcess(ctx context.Context, violation processRuntimeViolation) (returnErr error) {
	contractCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	emergency, err := contraction.OpenEmergency(contractCtx)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, emergency.Close()) }()
	// OpenEmergency holds the installation exposure lock. Compare the probe's
	// bundle before any ingress mutation, not against an unlocked snapshot.
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	document, readErr := service.normal.Read()
	live := false
	if readErr == nil {
		var resource domain.AppResource
		resource, readErr = boundProcessViolationResource(document, violation)
		live = readErr == nil && resource.PublicationRecord.State != domain.PublicationUnpublished
	}
	closeErr := service.Close()
	if readErr != nil || closeErr != nil || !live {
		return errors.Join(readErr, closeErr)
	}

	snapshot, err := emergency.Snapshot()
	if err != nil {
		return errors.Join(err, emergency.Close())
	}
	result, runErr := emergency.Run(contractCtx, snapshot.GlobalGeneration, snapshot.Inventory.Digest)
	closeEmergencyErr := emergency.Close()
	if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
		runErr = errors.Join(runErr, fmt.Errorf("publication contraction did not converge: %s", result.Outcome))
	}
	if runErr != nil || closeEmergencyErr != nil {
		return errors.Join(runErr, closeEmergencyErr)
	}
	return ReconcileTerminalNginxContraction(contractCtx)
}
