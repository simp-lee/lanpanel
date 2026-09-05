//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"lanpanel/internal/process"
	"reflect"
	"time"
)

type ProcessExecution struct {
	Service     *FixedService
	Admitter    *operations.Admitter
	MutationSet *operations.MutationSet
	Mutation    *operations.MutationLease
	Exposure    *locks.Lease
	JobID       string
	Revision    uint64
	Resource    domain.AppResource
	Operation   operations.Type
}

func BeginProcess(ctx context.Context, actor Actor, resourceID string, start bool) (*ProcessExecution, error) {
	if err := requireNoDegradedAppliedSource(resourceID); err != nil {
		return nil, err
	}
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*ProcessExecution, error) { _ = service.Close(); return nil, cause }
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	document, err := service.Normal().Read()
	if err != nil {
		return fail(err)
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fail(fmt.Errorf("installation authority missing"))
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return fail(err)
	}
	var candidate *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == resourceID {
			copy := installation.Resources[index]
			candidate = &copy
			break
		}
	}
	if candidate == nil || candidate.ManagedProcess == nil || candidate.Lifecycle != domain.LifecycleActive {
		return fail(fmt.Errorf("managed process resource is absent"))
	}
	operation := operations.ProcessStop
	if start {
		if candidate.ManagedProcess.Requested != domain.ProcessRequestedStopped {
			return fail(fmt.Errorf("managed process is already requested running"))
		}
		operation = operations.ProcessStart
	} else if candidate.ManagedProcess.Requested != domain.ProcessRequestedRunning {
		return fail(fmt.Errorf("managed process is already requested stopped"))
	} else if candidate.PublicationRecord.State != domain.PublicationUnpublished || candidate.PublicationRecord.ActivationIntent != nil || candidate.PublicationRecord.ContractionIntent != nil {
		return fail(fmt.Errorf("published or transitional resource rejects standalone stop"))
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return fail(err)
	}
	admission, err := service.Manager().Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operation, Target: "resource/" + resourceID, ActorIdentity: authority, Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{ResourceID: resourceID}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resourceID, service.Manager())
	if err != nil {
		_ = mutationSet.Close()
		return fail(err)
	}
	fresh, err := service.Normal().Read()
	if err != nil || fresh.Revision != document.Revision+1 {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(fmt.Errorf("process authority changed"))
	}
	intent, err := admitter.BeginUI(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(err)
	}
	return &ProcessExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: intent.IntentGeneration, Resource: *candidate, Operation: operation}, nil
}

func (execution *ProcessExecution) Commit(ctx context.Context, bundle *domain.ProcessBundle, observation process.RuntimeObservation) (jobs.Record, error) {
	if execution == nil {
		return jobs.Record{}, fmt.Errorf("process execution is inactive")
	}
	requested := domain.ProcessRequestedStopped
	status := domain.RuntimeDegraded
	reason := "stopped"
	if execution.Operation == operations.ProcessStart {
		requested = domain.ProcessRequestedRunning
		status = domain.RuntimeHealthy
		reason = "running"
		if bundle == nil || bundle.ConfigDigest != execution.Resource.CurrentConfigDigest {
			return jobs.Record{}, fmt.Errorf("process start requires exact applied config bundle")
		}
		if err := process.VerifyRunning(observation); err != nil {
			return jobs.Record{}, err
		}
	} else {
		if err := process.VerifyStopped(observation); err != nil {
			return jobs.Record{}, err
		}
	}
	runtimeObservation := domain.RuntimeObservation{Status: status, ObservedAt: observation.ObservedAt.UTC().Format(time.RFC3339), Reason: reason}
	if err := execution.Admitter.CommitProcessState(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.ProcessStateCommit{ResourceID: execution.Resource.ID, Requested: requested, Applied: bundle, Observation: runtimeObservation}); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	identity := observation.Digest
	if bundle != nil {
		identity = bundle.PolicyDigest
	}
	return execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "complete", nil, []jobs.Postcondition{{Kind: "managed_process_" + reason, Status: jobs.PostconditionVerified, Identity: identity}}, "")
}

func (execution *ProcessExecution) CommitNoEffect(ctx context.Context) error {
	if execution == nil {
		return fmt.Errorf("process execution is inactive")
	}
	_, err := execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "no_effect", nil, []jobs.Postcondition{{Kind: "managed_process_not_started", Status: jobs.PostconditionVerified, Identity: execution.Resource.ID}}, "process_lifecycle_not_started")
	if err == nil {
		execution.Revision++
	}
	return err
}

func (execution *ProcessExecution) CommitInterrupted(ctx context.Context, bundle *domain.ProcessBundle) error {
	if execution == nil || execution.Service == nil {
		return fmt.Errorf("process execution is inactive")
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return err
	}
	if document.Revision != execution.Revision {
		return persist.ErrRevision
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return err
	}
	found := false
	for index := range installation.Resources {
		item := &installation.Resources[index]
		if item.ID != execution.Resource.ID || item.ManagedProcess == nil {
			continue
		}
		item.ManagedProcess.Requested = domain.ProcessRequestedStopped
		item.ManagedProcess.Applied = cloneBundleForProcess(bundle)
		item.ManagedProcess.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: time.Now().UTC().Format(time.RFC3339), Reason: "interrupted_lifecycle_contracted"}
		item.ManagedProcess.LastOperation = domain.OperationProcessStart
		if execution.Operation == operations.ProcessStop {
			item.ManagedProcess.LastOperation = domain.OperationProcessStop
		}
		item.ManagedProcess.LastOperationResult = domain.OperationInterrupted
		item.ManagedProcess.LastJobID = execution.JobID
		found = true
	}
	if !found {
		return fmt.Errorf("process interruption target missing")
	}
	_, _, err = execution.Service.normal.Update(ctx, execution.Exposure, execution.Revision, func(transaction *persist.Transaction) error {
		encoded, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", encoded); err != nil {
			return err
		}
		return operations.CompleteInterruptedLifecycle(transaction, execution.JobID, time.Now().UTC())
	})
	if err == nil {
		execution.Revision++
	}
	return err
}

func cloneBundleForProcess(value *domain.ProcessBundle) *domain.ProcessBundle {
	if value == nil {
		return nil
	}
	copy := *value
	copy.WritePathIdentities = append([]string(nil), value.WritePathIdentities...)
	copy.EndpointSocketUnits = append([]string(nil), value.EndpointSocketUnits...)
	copy.ManagedPaths = append([]string(nil), value.ManagedPaths...)
	return &copy
}

func ReconcileJournalLessProcesses(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	document, err := service.normal.Read()
	if err != nil {
		_ = service.Close()
		return err
	}
	intents, err := operations.PendingProcessLifecycles(document)
	_ = service.Close()
	if err != nil {
		return err
	}
	for _, intent := range intents {
		present, err := process.JournalPresent(intent.SafetyBinding.ResourceID)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		service, err := OpenFixed()
		if err != nil {
			return err
		}
		document, err := service.normal.Read()
		if err != nil {
			_ = service.Close()
			return err
		}
		fresh, err := operations.FindProcessLifecycleAuthority(document, intent.JobID, intent.SafetyBinding.ResourceID)
		if err != nil {
			_ = service.Close()
			return err
		}
		admitter, err := service.resourceAdmitter()
		if err != nil {
			_ = service.Close()
			return err
		}
		if fresh.Phase == operations.PhaseReserved {
			admission, lockErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if lockErr != nil {
				_ = service.Close()
				return lockErr
			}
			err = admitter.RejectReservation(ctx, admission, document.Revision, fresh.JobID, "process_lifecycle_not_started")
			releaseErr := admission.Release()
			_ = service.Close()
			if err != nil || releaseErr != nil {
				return errors.Join(err, releaseErr)
			}
			continue
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			_ = service.Close()
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+fresh.SafetyBinding.ResourceID, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			_ = service.Close()
			return err
		}
		present, err = process.JournalPresent(fresh.SafetyBinding.ResourceID)
		if err == nil && present {
			err = fmt.Errorf("process journal appeared during no-effect recovery")
		}
		if err == nil {
			document, err = service.normal.Read()
		}
		if err == nil {
			fresh, err = operations.FindProcessLifecycleAuthority(document, fresh.JobID, fresh.SafetyBinding.ResourceID)
		}
		if err == nil && fresh.Phase != operations.PhaseLocalIntent {
			err = fmt.Errorf("process lifecycle no-effect phase changed")
		}
		if err == nil {
			raw := document.Entries["installations/current"]
			var installation domain.Installation
			installation, err = domain.DecodeInstallation(raw)
			if err == nil {
				found := false
				for _, item := range installation.Resources {
					if item.ID == fresh.SafetyBinding.ResourceID && item.ManagedProcess != nil {
						found = true
						if fresh.Operation == operations.ProcessStart && item.ManagedProcess.Requested != domain.ProcessRequestedStopped {
							err = fmt.Errorf("journal-less start changed requested state")
						}
						if fresh.Operation == operations.ProcessStop && (item.ManagedProcess.Requested != domain.ProcessRequestedRunning || item.PublicationRecord.State != domain.PublicationUnpublished) {
							err = fmt.Errorf("journal-less stop changed lifecycle state")
						}
					}
				}
				if !found && err == nil {
					err = fmt.Errorf("journal-less process target missing")
				}
			}
		}
		if err == nil {
			_, err = admitter.Complete(ctx, mutation, exposure, document.Revision, fresh.JobID, "no_effect", nil, []jobs.Postcondition{{Kind: "managed_process_not_started", Status: jobs.PostconditionVerified, Identity: fresh.SafetyBinding.ResourceID}}, "process_lifecycle_not_started")
		}
		err = errors.Join(err, operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

func ReconcileInterruptedProcess(ctx context.Context, journal process.Journal, contracted bool) (terminal bool, running bool, result error) {
	service, err := OpenFixed()
	if err != nil {
		return false, false, err
	}
	defer func() { result = errors.Join(result, service.Close()) }()
	document, err := service.normal.Read()
	if err != nil {
		return false, false, err
	}
	terminal, running, err = classifyCommittedProcess(document, journal)
	if err != nil || terminal {
		return terminal, running, err
	}
	if err := validatePendingProcessRecovery(document, journal); err != nil {
		return false, false, err
	}
	if !contracted {
		return false, false, nil
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return false, false, fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return false, false, err
	}
	found := false
	for index := range installation.Resources {
		managed := installation.Resources[index].ManagedProcess
		if installation.Resources[index].ID == journal.ResourceID && managed != nil {
			managed.Requested = domain.ProcessRequestedStopped
			if journal.Applied != nil {
				copy := *journal.Applied
				managed.Applied = &copy
			}
			managed.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: time.Now().UTC().Format(time.RFC3339), Reason: "interrupted_lifecycle_contracted"}
			managed.LastOperation = domain.OperationProcessStart
			if journal.Operation == "process_stop" {
				managed.LastOperation = domain.OperationProcessStop
			}
			managed.LastJobID = journal.JobID
			managed.LastOperationResult = domain.OperationInterrupted
			found = true
		}
	}
	if !found {
		return false, false, fmt.Errorf("process recovery target missing")
	}
	manager := service.manager
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: manager.Authority()})
	if err != nil {
		return false, false, err
	}
	defer func() { result = errors.Join(result, mutationSet.Close()) }()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+journal.ResourceID, manager)
	if err != nil {
		return false, false, err
	}
	defer func() { result = errors.Join(result, operations.ReleaseExposure(mutation, exposure)) }()
	_, _, err = service.normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
		encoded, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		if err := transaction.Replace("installations/current", encoded); err != nil {
			return err
		}
		return operations.CompleteInterruptedLifecycle(transaction, journal.JobID, time.Now().UTC())
	})
	return err == nil, false, err
}

func validatePendingProcessRecovery(document persist.Document, journal process.Journal) error {
	intent, err := operations.FindProcessLifecycleAuthority(document, journal.JobID, journal.ResourceID)
	if err != nil || intent.Phase != operations.PhaseLocalIntent || string(intent.Operation) != journal.Operation {
		return fmt.Errorf("pending process recovery authority differs from journal")
	}
	record, err := jobs.LoadEntries(document.Entries, journal.JobID)
	if err != nil || record.Status != jobs.StatusRunning || record.Operation != journal.Operation || record.Target != "resource/"+journal.ResourceID {
		return fmt.Errorf("pending process recovery job differs from journal")
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return err
	}
	for _, item := range installation.Resources {
		if item.ID != journal.ResourceID || item.ManagedProcess == nil || item.Lifecycle != domain.LifecycleActive || item.Target.LocalHTTP == nil {
			continue
		}
		managed := item.ManagedProcess
		if journal.Operation == "process_stop" {
			preCommit := managed.Requested == domain.ProcessRequestedRunning && item.PublicationRecord.State == domain.PublicationUnpublished && reflect.DeepEqual(journal.Applied, managed.Applied)
			postCommit := journal.Phase == "host_mutated" && managed.Requested == domain.ProcessRequestedStopped && item.PublicationRecord.State == domain.PublicationUnpublished && reflect.DeepEqual(journal.Applied, managed.Applied) && managed.RuntimeObservation != nil && managed.RuntimeObservation.Status == domain.RuntimeDegraded && managed.RuntimeObservation.Reason == "stopped" && managed.LastOperation == domain.OperationProcessStop && managed.LastJobID == journal.JobID
			if !preCommit && !postCommit {
				return fmt.Errorf("pending process stop authority differs from journal")
			}
			return nil
		}
		relayRequired := item.Target.LocalHTTP.EndpointKind == domain.LocalEndpointRelayUnix
		if journal.RelayRequired != relayRequired {
			return fmt.Errorf("pending process start relay authority differs from journal")
		}
		preCommit := managed.Requested == domain.ProcessRequestedStopped && (journal.Phase != "prepared" || reflect.DeepEqual(journal.Applied, managed.Applied))
		postCommit := journal.Phase == "host_mutated" && managed.Requested == domain.ProcessRequestedRunning && journal.Applied != nil && reflect.DeepEqual(journal.Applied, managed.Applied) && managed.RuntimeObservation != nil && managed.RuntimeObservation.Status == domain.RuntimeHealthy && managed.RuntimeObservation.Reason == "running" && managed.LastOperation == domain.OperationProcessStart && managed.LastJobID == journal.JobID
		if !preCommit && !postCommit {
			return fmt.Errorf("pending process start authority differs from journal")
		}
		if journal.Phase != "prepared" && (journal.Applied == nil || journal.Applied.ConfigDigest != item.CurrentConfigDigest) {
			return fmt.Errorf("pending process start candidate bundle differs from resource")
		}
		return nil
	}
	return fmt.Errorf("pending process recovery target missing")
}

func (execution *ProcessExecution) CommitSucceeded(journal process.Journal) (bool, error) {
	if execution == nil || execution.Service == nil {
		return false, fmt.Errorf("process execution is inactive")
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return false, err
	}
	terminal, _, err := classifyCommittedProcess(document, journal)
	return terminal, err
}

func classifyCommittedProcess(document persist.Document, journal process.Journal) (terminal bool, running bool, err error) {
	record, err := jobs.LoadEntries(document.Entries, journal.JobID)
	if err != nil {
		return false, false, err
	}
	if !jobs.IsComplete(record) {
		return false, false, nil
	}
	if record.Operation != journal.Operation || record.Target != "resource/"+journal.ResourceID || len(record.Postconditions) != 1 || journal.Applied == nil && journal.BundleDigest != "" || journal.Applied != nil && journal.BundleDigest != journal.Applied.PolicyDigest {
		return false, false, fmt.Errorf("terminal process journal authority is inconsistent")
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return false, false, fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return false, false, err
	}
	for _, item := range installation.Resources {
		if item.ID != journal.ResourceID || item.ManagedProcess == nil {
			continue
		}
		managed := item.ManagedProcess
		wantOperation := domain.OperationProcessStart
		if journal.Operation == "process_stop" {
			wantOperation = domain.OperationProcessStop
		}
		condition := record.Postconditions[0]
		if record.Result == jobs.ResultInterrupted {
			if managed.Requested != domain.ProcessRequestedStopped || managed.RuntimeObservation == nil || managed.RuntimeObservation.Status != domain.RuntimeDegraded || managed.RuntimeObservation.Reason != "interrupted_lifecycle_contracted" || managed.LastOperation != wantOperation || managed.LastOperationResult != domain.OperationInterrupted || managed.LastJobID != journal.JobID || !reflect.DeepEqual(managed.Applied, journal.Applied) || record.ErrorCode != "interrupted_lifecycle_contracted" || condition != (jobs.Postcondition{Kind: "interrupted_lifecycle_contracted", Status: jobs.PostconditionKnown, Identity: journal.JobID}) {
				return false, false, fmt.Errorf("interrupted process state differs from recovery journal")
			}
			return true, false, nil
		}
		if record.Result != jobs.ResultSucceeded || journal.Phase != "host_mutated" || journal.Applied == nil {
			return false, false, fmt.Errorf("terminal process result is unsupported")
		}
		wantRequested, wantStatus, wantKind := domain.ProcessRequestedRunning, domain.RuntimeHealthy, "managed_process_running"
		running = true
		if journal.Operation == "process_stop" {
			wantRequested = domain.ProcessRequestedStopped
			wantStatus = domain.RuntimeDegraded
			wantKind = "managed_process_stopped"
			running = false
		}
		if managed.Requested != wantRequested || managed.RuntimeObservation == nil || managed.RuntimeObservation.Status != wantStatus || managed.LastOperation != wantOperation || managed.LastOperationResult != domain.OperationSucceeded || managed.LastJobID != journal.JobID || !reflect.DeepEqual(managed.Applied, journal.Applied) || condition != (jobs.Postcondition{Kind: wantKind, Status: jobs.PostconditionVerified, Identity: journal.BundleDigest}) {
			return false, false, fmt.Errorf("terminal process state differs from lifecycle journal")
		}
		return true, running, nil
	}
	return false, false, fmt.Errorf("terminal process recovery target missing")
}

func (execution *ProcessExecution) Close() error {
	if execution == nil {
		return nil
	}
	err := operations.ReleaseExposure(execution.Mutation, execution.Exposure)
	if execution.MutationSet != nil {
		err = errors.Join(err, execution.MutationSet.Close())
	}
	if execution.Service != nil {
		err = errors.Join(err, execution.Service.Close())
	}
	execution.Mutation = nil
	execution.Exposure = nil
	return err
}
