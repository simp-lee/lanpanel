//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	goaccessruntime "lanpanel/internal/goaccess"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/publication"
	"lanpanel/internal/safety"
	"reflect"
	"time"
)

func readPublicationRecoverySafety(ctx context.Context, service *FixedService) (safety.State, error) {
	exposure, err := service.manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		return safety.State{}, err
	}
	state, readErr := service.safety.ReadForRecovery(exposure)
	return state, errors.Join(readErr, exposure.Release())
}

func ReconcileInterruptedDomainPublications(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	state, err := readPublicationRecoverySafety(ctx, service)
	if err != nil {
		return err
	}
	if err := reconcileMarkerlessTemporaryReservations(ctx, service, state); err != nil {
		return err
	}
	state, err = readPublicationRecoverySafety(ctx, service)
	if err != nil {
		return err
	}
	for _, authority := range state.Resources {
		temporaryRecovery := authority.Reactivating != nil && authority.Reactivating.TemporaryHTTP || authority.Reactivating == nil && authority.Closing != nil && temporaryClosingReason(authority.Closing.Reason)
		if temporaryRecovery {
			if err := reconcileInterruptedTemporaryPublication(ctx, service, authority, fixedRoot+"/locks", 0, 0, nil); err != nil {
				return err
			}
			state, err = readPublicationRecoverySafety(ctx, service)
			if err != nil {
				return err
			}
			continue
		}
		if authority.Reactivating == nil && (authority.Closing == nil || authority.Closing.Reason != "interrupted_domain_activation" && authority.Closing.Reason != "committed_domain_recovery") {
			continue
		}
		document, err := service.normal.Read()
		if err != nil {
			return err
		}
		_, resource, err := loadCertificateResource(document.Entries, authority.ResourceID)
		if err != nil {
			return err
		}
		activationIntent := resource.PublicationRecord.ActivationIntent
		if authority.Reactivating == nil && authority.Closing != nil && authority.Closing.Reason == "committed_domain_recovery" {
			if err := resumeCommittedDomainContraction(ctx, service, resource, *authority.Closing); err != nil {
				return err
			}
			state, err = readPublicationRecoverySafety(ctx, service)
			if err != nil {
				return err
			}
			continue
		}
		if authority.Reactivating != nil && resource.PublicationRecord.State == domain.PublicationPublished && activationIntent == nil {
			if err := convergeCommittedDomainPublication(ctx, service, resource, *authority.Reactivating); err != nil {
				return err
			}
			state, err = readPublicationRecoverySafety(ctx, service)
			if err != nil {
				return err
			}
			continue
		}
		if authority.Reactivating == nil && authority.Closing != nil && resource.PublicationRecord.State == domain.PublicationUnpublished && activationIntent == nil {
			record, err := jobs.LoadEntries(document.Entries, resource.PublicationRecord.LastJobID)
			if err != nil || record.Result != jobs.ResultInterrupted || len(record.Postconditions) != 1 || record.Postconditions[0].Kind != "interrupted_activation_contracted" {
				return fmt.Errorf("terminal interrupted publication evidence changed")
			}
			mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
			if err != nil {
				return err
			}
			mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
			if err == nil {
				err = convergeInterruptedDomainClosing(ctx, service, exposure, resource.ID, authority.Closing.Generation, record.Postconditions[0].Identity, "interrupted_domain_activation")
			}
			releaseErr := operations.ReleaseExposure(mutation, exposure)
			closeErr := mutationSet.Close()
			if err := errors.Join(err, releaseErr, closeErr); err != nil {
				return err
			}
			state, err = readPublicationRecoverySafety(ctx, service)
			if err != nil {
				return err
			}
			continue
		}
		if resource.PublicationRecord.State != domain.PublicationActivating || activationIntent == nil || activationIntent.Candidate.DomainHTTPS == nil || activationIntent.JobID == "" {
			return fmt.Errorf("reactivating domain publication lacks normal activation authority")
		}
		admitter, err := service.TimerAdmitter()
		if err != nil {
			return err
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		fresh, err := service.safety.ReadForRecovery(exposure)
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		owned, ownerErr := service.ownership.Read(resource.ID)
		if ownerErr != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return ownerErr
		}
		for _, item := range fresh.Resources {
			if item.ResourceID == resource.ID && item.Reactivating != nil && item.OwnershipDigest != owned.Checksum {
				ownershipNext := fresh
				ownershipNext.Revision++
				ownershipNext.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
				for index := range ownershipNext.Resources {
					if ownershipNext.Resources[index].ResourceID == resource.ID {
						before := ownershipNext.Resources[index].OwnershipDigest
						ownershipNext.Resources[index].OwnershipDigest = owned.Checksum
						proof := &safety.OwnershipConvergenceProof{ResourceID: resource.ID, IntentRef: item.Reactivating.PlanID, Generation: item.Reactivating.Generation, BeforeDigest: before, AfterDigest: owned.Checksum}
						if _, err := service.safety.Commit(ctx, exposure, safety.RoleOwnershipActivation, fresh.Revision, ownershipNext, safety.TransitionProof{Ownership: proof}); err != nil {
							_ = operations.ReleaseExposure(mutation, exposure)
							_ = mutationSet.Close()
							return err
						}
					}
				}
				fresh, err = service.safety.ReadForRecovery(exposure)
				if err != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return err
				}
				break
			}
		}
		next := fresh
		next.Revision++
		next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
		generation := uint64(0)
		safetyChanged := false
		for index := range next.Resources {
			if next.Resources[index].ResourceID != resource.ID {
				continue
			}
			updated, currentGeneration, changed, transitionErr := interruptDomainSafety(next.Resources[index], *activationIntent)
			if transitionErr != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return transitionErr
			}
			next.Resources[index] = updated
			generation = currentGeneration
			safetyChanged = changed
		}
		if generation == 0 {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("reactivating publication safety resource missing")
		}
		if safetyChanged {
			if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, fresh.Revision, next, safety.TransitionProof{}); err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
		}
		host, err := activation.NewFixedHost()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		result, contractErr := host.ContractResource(ctx, resource.ID)
		if contractErr == nil {
			contractErr = stopRecoveredGoAccessBounded(service, exposure, resource)
		}
		if contractErr != nil {
			snapshot, stopErr := stopRecoveredNginxBounded(host)
			goaccessErr := stopRecoveredGoAccessBounded(service, exposure, resource)
			observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
			fenceCtx, cancelFence := context.WithTimeout(context.Background(), 15*time.Second)
			fenceErr := service.WriteIngressActivationFence(fenceCtx, exposure, resource.ID, activationIntent.PlanID, generation, generation-1, observed, stopErr != nil || goaccessErr != nil)
			cancelFence()
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return errors.Join(contractErr, stopErr, goaccessErr, fenceErr)
		}
		pointerErr := restoreInterruptedDomainPointer(ctx, *activationIntent)
		freshDocument, err := service.normal.Read()
		if err == nil && pointerErr == nil {
			_, err = admitter.TerminalizeInterruptedPublication(ctx, mutation, exposure, freshDocument.Revision, activationIntent.JobID, resource.ID, generation, result.ModifiedPaths, result.RuntimeDigest)
		}
		if err == nil && pointerErr == nil {
			err = convergeInterruptedDomainClosing(ctx, service, exposure, resource.ID, generation, result.RuntimeDigest, "interrupted_domain_activation")
		}
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err := errors.Join(err, pointerErr, releaseErr, closeErr); err != nil {
			return err
		}
		state, err = readPublicationRecoverySafety(ctx, service)
		if err != nil {
			return err
		}
	}
	if err := reconcileRetiredGoAccess(ctx, service); err != nil {
		return err
	}
	return reconcilePendingContractionGoAccess(ctx, service)
}

func reconcilePendingContractionGoAccess(ctx context.Context, service *FixedService) error {
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		return err
	}
	host, err := goaccessruntime.NewFixedHost()
	if err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	for _, resource := range installation.Resources {
		retirements := append([]domain.GoAccessRetirementIdentity(nil), resource.PublicationRecord.PendingGoAccessRetirements...)
		if len(retirements) == 0 {
			continue
		}
		authorityDigest, digestErr := operations.GoAccessRetirementInventoryDigest(retirements)
		if digestErr != nil {
			return digestErr
		}
		if resource.PublicationRecord.GoAccessRetirementAuthorityDigest != authorityDigest || resource.PublicationRecord.GoAccessRetirementSourceJournalID != "" {
			return fmt.Errorf("pending GoAccess contraction source changed")
		}
		sourceJobID := resource.PublicationRecord.GoAccessRetirementSourceJobID
		expectedBinding, bindingErr := operations.GoAccessRetirementBinding(installation.InstallationID, resource.ID, "contraction", sourceJobID, "", authorityDigest, retirements)
		if bindingErr != nil {
			return bindingErr
		}
		oldRecord, loadErr := jobs.LoadEntries(document.Entries, sourceJobID)
		if loadErr != nil || oldRecord.Status != jobs.StatusTerminal || oldRecord.Result != jobs.ResultPartial || oldRecord.ErrorCode != "goaccess_stop_failed" {
			return fmt.Errorf("pending GoAccess contraction job authority changed")
		}
		retirementIntent, runningRetirement, resume, authorityErr := operations.FindRunningGoAccessRetirement(document, "resource/"+resource.ID)
		if authorityErr != nil {
			return authorityErr
		}
		if resume && !reflect.DeepEqual(retirementIntent.SafetyBinding, expectedBinding) {
			return fmt.Errorf("pending GoAccess contraction immutable authority changed")
		}
		jobID := runningRetirement.ID
		needsBegin := resume && runningRetirement.Status == jobs.StatusReserved
		if !resume {
			admission, acquireErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if acquireErr != nil {
				return acquireErr
			}
			fresh, readErr := service.normal.Read()
			if readErr == nil {
				job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.GoAccessRetirement, Target: "resource/" + resource.ID, ActorIdentity: "startup-recovery", Source: operations.AdmissionStartup, SafetyBinding: expectedBinding, ExpectedRevision: fresh.Revision})
				readErr = admitErr
				jobID = job.ID
				needsBegin = admitErr == nil
			}
			releaseErr := admission.Release()
			if err := errors.Join(readErr, releaseErr); err != nil {
				return err
			}
			document, err = service.normal.Read()
			if err != nil {
				return err
			}
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), time.Minute)
		mutation, exposure, err := mutationSet.AcquireExposure(cleanupCtx, "resource/"+resource.ID, service.manager)
		if err != nil {
			cancelCleanup()
			_ = mutationSet.Close()
			return err
		}
		if needsBegin {
			_, err = admitter.BeginPlanless(cleanupCtx, mutation, exposure, operations.ConsumeRequest{JobID: jobID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1})
			if err == nil {
				document, err = service.normal.Read()
			}
		}
		if err == nil {
			freshInstallation, decodeErr := installationFromDocument(document)
			err = decodeErr
			if decodeErr == nil {
				err = fmt.Errorf("pending GoAccess contraction authority changed")
				for _, candidate := range freshInstallation.Resources {
					if candidate.ID == resource.ID && reflect.DeepEqual(candidate.PublicationRecord.PendingGoAccessRetirements, retirements) {
						err = nil
						break
					}
				}
			}
		}
		if err == nil {
			err = operations.ValidateGoAccessRetirementAuthority(document, expectedBinding)
		}
		if err == nil {
			for _, item := range retirements {
				stopErr := host.Retire(cleanupCtx, resource.ID, item.Generation, item.ServiceIdentity, item.UnitIdentities)
				if stopErr == nil && item.RemoveState {
					stopErr = host.RemoveGenerationState(cleanupCtx, resource.ID, item.StateGeneration)
				}
				if stopErr == nil && item.RemoveShared {
					stopErr = host.CleanupUncommittedShared(cleanupCtx, installation.InstallationID, resource.ID)
				}
				if stopErr != nil {
					err = errors.Join(err, stopErr)
				}
			}
		}
		if err == nil {
			for _, item := range retirements {
				if pruneErr := pruneRetiredGoAccessOwnership(cleanupCtx, service, exposure, resource.ID, sourceJobID, item.Generation, item.StateGeneration, item.RemoveState, item.RemoveShared); pruneErr != nil {
					err = errors.Join(err, pruneErr)
				}
			}
		}
		if err == nil {
			_, err = admitter.CompleteGoAccessContractionReconciliation(cleanupCtx, mutation, exposure, document.Revision, jobID, resource.ID, retirements)
		}
		cancelCleanup()
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err := errors.Join(err, releaseErr, closeErr); err != nil {
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
	}
	return nil
}

func reconcileRetiredGoAccess(ctx context.Context, service *FixedService) error {
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		return err
	}
	host, err := goaccessruntime.NewFixedHost()
	if err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	for _, resource := range installation.Resources {
		if resource.PublicationRecord.State != domain.PublicationPublished {
			continue
		}
		bundle := resource.PublicationRecord.LastAppliedBundle
		if bundle == nil || bundle.DomainHTTPS == nil || bundle.DomainHTTPS.GoAccess.RetiredGeneration == 0 {
			continue
		}
		goaccess := bundle.DomainHTTPS.GoAccess
		retirements := append([]domain.GoAccessRetirementIdentity(nil), resource.PublicationRecord.PendingGoAccessRetirements...)
		if len(retirements) == 0 {
			removeRetiredState := goaccess.RemovesRetiredState()
			complete, completeErr := host.RetirementComplete(ctx, resource.ID, goaccess.RetiredGeneration, goaccess.RetiredStateGeneration, removeRetiredState)
			if completeErr != nil {
				return completeErr
			}
			if !complete {
				return fmt.Errorf("completed GoAccess retirement authority invalid")
			}
			if ownershipErr := requireRetiredGoAccessOwnershipComplete(service, resource.ID, goaccess.RetiredGeneration, goaccess.RetiredStateGeneration, removeRetiredState); ownershipErr != nil {
				return ownershipErr
			}
			continue
		}
		if len(retirements) != 1 || !reflect.DeepEqual(retirements[0], domain.GoAccessRetirementIdentity{Generation: goaccess.RetiredGeneration, StateGeneration: goaccess.RetiredStateGeneration, ServiceIdentity: goaccess.RetiredServiceIdentity, RemoveState: goaccess.RemovesRetiredState(), UnitIdentities: goaccess.RetiredUnitIdentities}) {
			return fmt.Errorf("pending GoAccess publication retirement changed")
		}
		retirementDigest, digestErr := operations.GoAccessRetirementInventoryDigest(retirements)
		if digestErr != nil {
			return digestErr
		}
		if resource.PublicationRecord.GoAccessRetirementAuthorityDigest != retirementDigest {
			return fmt.Errorf("pending GoAccess publication digest changed")
		}
		sourceJobID, sourceJournalID := resource.PublicationRecord.GoAccessRetirementSourceJobID, resource.PublicationRecord.GoAccessRetirementSourceJournalID
		expectedBinding, bindingErr := operations.GoAccessRetirementBinding(installation.InstallationID, resource.ID, "publication", sourceJobID, sourceJournalID, retirementDigest, retirements)
		if bindingErr != nil {
			return bindingErr
		}
		record, recordErr := jobs.LoadEntries(document.Entries, sourceJobID)
		if recordErr != nil {
			return recordErr
		}
		if record.Status == jobs.StatusRunning {
			mutationSet, openErr := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
			if openErr != nil {
				return openErr
			}
			mutation, exposure, acquireErr := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
			if acquireErr != nil {
				_ = mutationSet.Close()
				return acquireErr
			}
			interruptCtx, cancelInterrupt := context.WithTimeout(context.Background(), 15*time.Second)
			record, recordErr = admitter.InterruptPublicationGoAccessRetirement(interruptCtx, mutation, exposure, document.Revision, record.ID, resource.ID)
			cancelInterrupt()
			releaseErr := operations.ReleaseExposure(mutation, exposure)
			closeErr := mutationSet.Close()
			if err := errors.Join(recordErr, releaseErr, closeErr); err != nil {
				return err
			}
			document, err = service.normal.Read()
			if err != nil {
				return err
			}
		}
		complete, completeErr := host.RetirementComplete(ctx, resource.ID, goaccess.RetiredGeneration, goaccess.RetiredStateGeneration, goaccess.RemovesRetiredState())
		if completeErr != nil {
			return completeErr
		}
		if record.Status == jobs.StatusTerminal && record.Result == jobs.ResultSucceeded {
			if !complete {
				return fmt.Errorf("succeeded publication retains incomplete GoAccess retirement")
			}
			continue
		}
		reconciliation := record.Status == jobs.StatusTerminal && ((record.Result == jobs.ResultPartial && record.ErrorCode == "goaccess_stop_failed") || (record.Result == jobs.ResultInterrupted && record.ErrorCode == "goaccess_retirement_recovery"))
		if record.Status != jobs.StatusRunning && !reconciliation {
			return fmt.Errorf("GoAccess retirement durable job authority changed")
		}
		jobID := sourceJobID
		retirementIntent, runningRetirement, resumeReconciliation, authorityErr := operations.FindRunningGoAccessRetirement(document, "resource/"+resource.ID)
		if authorityErr != nil {
			return authorityErr
		}
		if resumeReconciliation && !reflect.DeepEqual(retirementIntent.SafetyBinding, expectedBinding) {
			return fmt.Errorf("pending GoAccess publication immutable authority changed")
		}
		needsBegin := resumeReconciliation && runningRetirement.Status == jobs.StatusReserved
		if resumeReconciliation {
			reconciliation = true
			jobID = runningRetirement.ID
		}
		if reconciliation && !resumeReconciliation {
			admission, admissionErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if admissionErr != nil {
				return admissionErr
			}
			fresh, readErr := service.normal.Read()
			if readErr == nil {
				newJob, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.GoAccessRetirement, Target: "resource/" + resource.ID, ActorIdentity: "startup-recovery", Source: operations.AdmissionStartup, SafetyBinding: expectedBinding, ExpectedRevision: fresh.Revision})
				readErr = admitErr
				if admitErr == nil {
					jobID = newJob.ID
					needsBegin = true
				}
			}
			releaseErr := admission.Release()
			if err := errors.Join(readErr, releaseErr); err != nil {
				return err
			}
			document, err = service.normal.Read()
			if err != nil {
				return err
			}
		}
		mutationSet, openErr := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if openErr != nil {
			return openErr
		}
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), time.Minute)
		mutation, exposure, acquireErr := mutationSet.AcquireExposure(cleanupCtx, "resource/"+resource.ID, service.manager)
		if acquireErr != nil {
			cancelCleanup()
			_ = mutationSet.Close()
			return acquireErr
		}
		if reconciliation && needsBegin {
			_, beginErr := admitter.BeginPlanless(cleanupCtx, mutation, exposure, operations.ConsumeRequest{JobID: jobID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1})
			if beginErr != nil {
				cancelCleanup()
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return beginErr
			}
			document, err = service.normal.Read()
			if err != nil {
				cancelCleanup()
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
		}
		freshDocument, freshErr := service.normal.Read()
		if freshErr == nil && reconciliation {
			freshErr = operations.ValidateGoAccessRetirementAuthority(freshDocument, expectedBinding)
		}
		if freshErr == nil && !complete {
			freshErr = host.Retire(cleanupCtx, resource.ID, goaccess.RetiredGeneration, goaccess.RetiredServiceIdentity, goaccess.RetiredUnitIdentities)
		}
		removeRetiredState := goaccess.RemovesRetiredState()
		if freshErr == nil && !complete && removeRetiredState {
			freshErr = host.RemoveGenerationState(cleanupCtx, resource.ID, goaccess.RetiredStateGeneration)
		}
		if freshErr == nil {
			freshErr = pruneRetiredGoAccessOwnership(cleanupCtx, service, exposure, resource.ID, sourceJobID, goaccess.RetiredGeneration, goaccess.RetiredStateGeneration, removeRetiredState, false)
		}
		if freshErr == nil {
			if reconciliation {
				_, freshErr = admitter.CompleteGoAccessRetirementReconciliation(cleanupCtx, mutation, exposure, freshDocument.Revision, jobID, resource.ID, goaccess.RetiredGeneration, goaccess.RetiredServiceIdentity)
			} else {
				_, freshErr = admitter.CompletePublicationGoAccessRetirement(cleanupCtx, mutation, exposure, freshDocument.Revision, jobID, resource.ID)
			}
		}
		cancelCleanup()
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err := errors.Join(freshErr, releaseErr, closeErr); err != nil {
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
	}
	return nil
}

func interruptDomainSafety(item safety.ResourceSafety, intent domain.ActivationIntent) (safety.ResourceSafety, uint64, bool, error) {
	if item.Reactivating != nil {
		if item.Reactivating.PlanID != intent.PlanID || item.Reactivating.Generation != intent.Generation {
			return item, 0, false, fmt.Errorf("reactivating publication safety changed")
		}
		generation := item.GenerationSequence + 1
		item.GenerationSequence = generation
		item.Closing = &safety.GenerationMarker{Kind: safety.MarkerClosing, Generation: generation, Reason: "interrupted_domain_activation"}
		item.Reactivating = nil
		return item, generation, true, nil
	}
	if item.Closing != nil && item.Closing.Reason == "interrupted_domain_activation" {
		return item, item.Closing.Generation, false, nil
	}
	return item, 0, false, fmt.Errorf("reactivating publication safety missing")
}

func stopRecoveredNginxBounded(host activation.Host) (closure.RuntimeSnapshot, error) {
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return host.StopAndVerify(stopCtx)
}

func stopRecoveredGoAccessBounded(service *FixedService, exposure *locks.Lease, resource domain.AppResource) error {
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return stopRecoveredGoAccess(stopCtx, service, exposure, resource)
}

func stopRecoveredGoAccess(ctx context.Context, service *FixedService, exposure *locks.Lease, resource domain.AppResource) error {
	type generationAction struct {
		identity        string
		unitIdentities  []string
		stateGeneration uint64
		removeState     bool
		removeShared    bool
		candidate       bool
	}
	document, documentErr := service.normal.Read()
	if documentErr != nil {
		return documentErr
	}
	installation, installationErr := installationFromDocument(document)
	if installationErr != nil {
		return installationErr
	}
	priorShared := goAccessSharedRetained(resource)
	generations := map[uint64]generationAction{}
	add := func(bundle *domain.PublicationBundle, candidate bool) {
		if bundle == nil || bundle.DomainHTTPS == nil {
			return
		}
		goaccess := bundle.DomainHTTPS.GoAccess
		if goaccess.Enabled {
			action := generationAction{}
			if candidate {
				action = generationAction{identity: goaccess.ServiceIdentity, unitIdentities: append([]string(nil), goaccess.UnitIdentities...), stateGeneration: goaccess.StateGeneration, removeState: goaccess.StateGeneration == goaccess.Generation, removeShared: !priorShared, candidate: true}
			}
			generations[goaccess.Generation] = action
		}
		if goaccess.RetiredGeneration != 0 {
			generations[goaccess.RetiredGeneration] = generationAction{identity: goaccess.RetiredServiceIdentity, unitIdentities: append([]string(nil), goaccess.RetiredUnitIdentities...), stateGeneration: goaccess.RetiredStateGeneration}
		}
	}
	add(resource.PublicationRecord.LastAppliedBundle, false)
	if intent := resource.PublicationRecord.ActivationIntent; intent != nil {
		add(&intent.Candidate, true)
		add(intent.Prior, false)
	}
	if len(generations) == 0 {
		return nil
	}
	host, err := goaccessruntime.NewFixedHost()
	if err != nil {
		return err
	}
	for generation, action := range generations {
		if action.identity == "" {
			err = errors.Join(err, host.Stop(ctx, resource.ID, generation))
		} else {
			currentErr := error(nil)
			if action.candidate {
				gid, gidErr := nginxGroupGID()
				candidate, renderErr := goaccessruntime.Render(installation.InstallationID, resource, gid, generation)
				currentErr = errors.Join(gidErr, renderErr)
				if currentErr == nil {
					currentErr = host.CleanupCandidate(ctx, candidate)
				}
			} else {
				currentErr = host.Retire(ctx, resource.ID, generation, action.identity, action.unitIdentities)
				if currentErr == nil && action.removeState {
					currentErr = host.RemoveGenerationState(ctx, resource.ID, action.stateGeneration)
				}
				if currentErr == nil && action.removeShared {
					currentErr = host.CleanupUncommittedShared(ctx, installation.InstallationID, resource.ID)
				}
			}
			if currentErr == nil {
				sourceJobID := resource.PublicationRecord.LastJobID
				if intent := resource.PublicationRecord.ActivationIntent; intent != nil {
					sourceJobID = intent.JobID
				}
				currentErr = pruneRetiredGoAccessOwnership(ctx, service, exposure, resource.ID, sourceJobID, generation, action.stateGeneration, action.removeState, action.removeShared)
			}
			err = errors.Join(err, currentErr)
		}
	}
	return err
}

func convergeInterruptedDomainClosing(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID string, generation uint64, runtimeDigest, reason string) error {
	fresh, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := fresh
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
	var proof *safety.ClosingConvergenceProof
	for index := range next.Resources {
		item := &next.Resources[index]
		if item.ResourceID != resourceID {
			continue
		}
		if item.Closing == nil || item.Closing.Generation != generation || item.Closing.Reason != reason {
			return fmt.Errorf("interrupted closing authority changed")
		}
		proof = &safety.ClosingConvergenceProof{ResourceID: resourceID, ClosingGeneration: generation, UnpublishedGeneration: generation, OwnershipDigest: item.OwnershipDigest, RuntimeClosureDigest: runtimeDigest}
		item.Closing = nil
		item.StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: generation, Reason: reason}
	}
	if proof == nil {
		return fmt.Errorf("interrupted closing resource missing")
	}
	_, err = service.safety.Commit(ctx, exposure, safety.RoleContraction, fresh.Revision, next, safety.TransitionProof{Closing: proof})
	return err
}

func convergeCommittedDomainPublication(ctx context.Context, service *FixedService, resource domain.AppResource, marker safety.Reactivating) error {
	applied := resource.PublicationRecord.LastAppliedBundle
	if applied == nil || applied.DomainHTTPS == nil || marker.Generation != applied.Generation {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
	}
	if applied.DomainHTTPS.GoAccess.RetiredGeneration != 0 {
		document, readErr := service.normal.Read()
		if readErr != nil {
			return readErr
		}
		record, loadErr := jobs.LoadEntries(document.Entries, resource.PublicationRecord.LastJobID)
		if loadErr != nil {
			return loadErr
		}
		if record.Status == jobs.StatusRunning {
			admitter, admitErr := service.TimerAdmitter()
			if admitErr != nil {
				return admitErr
			}
			mutationSet, openErr := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
			if openErr != nil {
				return openErr
			}
			mutation, exposure, acquireErr := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
			if acquireErr != nil {
				_ = mutationSet.Close()
				return acquireErr
			}
			interruptCtx, cancelInterrupt := context.WithTimeout(context.Background(), 15*time.Second)
			_, interruptErr := admitter.InterruptPublicationGoAccessRetirement(interruptCtx, mutation, exposure, document.Revision, record.ID, resource.ID)
			cancelInterrupt()
			releaseErr := operations.ReleaseExposure(mutation, exposure)
			closeErr := mutationSet.Close()
			if err := errors.Join(interruptErr, releaseErr, closeErr); err != nil {
				return err
			}
		}
	}
	candidate, err := prepareDomainCandidate(service, resource, marker.Generation, applied.DomainHTTPS.Certificate)
	if err == nil && candidate.Bundle.DomainHTTPS != nil {
		candidate.Bundle.DomainHTTPS.GoAccess = applied.DomainHTTPS.GoAccess
		candidate.BundleDigest, err = publication.BundleDigest(candidate.Bundle)
	}
	if err != nil {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
	}
	if !reflect.DeepEqual(candidate.Bundle, *applied) {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
	}
	if applied.DomainHTTPS.GoAccess.Enabled {
		gid, gidErr := nginxGroupGID()
		recoveryDocument, documentErr := service.normal.Read()
		recoveryInstallation, installationErr := installationFromDocument(recoveryDocument)
		runtimeCandidate, renderErr := goaccessruntime.Render(recoveryInstallation.InstallationID, resource, gid, applied.DomainHTTPS.GoAccess.Generation)
		verifyErr := errors.Join(gidErr, documentErr, installationErr, renderErr)
		goaccessHost, hostErr := goaccessruntime.NewFixedHost()
		verifyErr = errors.Join(verifyErr, hostErr)
		if verifyErr == nil {
			verifyErr = goaccessHost.Verify(ctx, runtimeCandidate)
		}
		if verifyErr != nil {
			return contractCommittedDomainPublication(ctx, service, resource, marker)
		}
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	runtimeDigest, err := host.VerifyDomain(ctx, candidate, resource.Target)
	if err != nil {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	record, err := jobs.LoadEntries(document.Entries, resource.PublicationRecord.LastJobID)
	validSucceeded := err == nil && record.Result == jobs.ResultSucceeded && len(record.Postconditions) == 1 && record.Postconditions[0].Kind == "published" && record.Postconditions[0].Identity == runtimeDigest
	validInterrupted := err == nil && record.Result == jobs.ResultInterrupted && record.ErrorCode == "goaccess_retirement_recovery" && len(record.Postconditions) == 2 && record.Postconditions[0].Kind == "published_committed" && record.Postconditions[0].Identity == applied.SiteIdentity
	if !validSucceeded && !validInterrupted {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	proof := &safety.ReactivationConvergenceProof{ResourceID: resource.ID, PlanID: marker.PlanID, Generation: marker.Generation, CandidateDigest: candidate.Bundle.ConfigDigest, CandidateBundle: candidate.BundleDigest, RuntimeClosureDigest: runtimeDigest}
	found := false
	for index := range next.Resources {
		item := &next.Resources[index]
		if item.ResourceID == resource.ID {
			if item.Reactivating == nil || !reflect.DeepEqual(*item.Reactivating, marker) {
				return fmt.Errorf("committed domain marker changed")
			}
			item.StickyUnpublished = nil
			item.Contraction = nil
			item.CertificateExpiry = nil
			authority, authorityErr := activeCertificateAuthority(candidate.Bundle.DomainHTTPS.Certificate)
			if authorityErr != nil {
				return authorityErr
			}
			item.ActiveCertificate = authority
			item.Reactivating = nil
			found = true
		}
	}
	if !found {
		return fmt.Errorf("committed domain safety resource missing")
	}
	_, err = service.safety.Commit(ctx, exposure, safety.RolePublish, state.Revision, next, safety.TransitionProof{Reactivation: proof})
	return err
}

func contractCommittedDomainPublication(ctx context.Context, service *FixedService, resource domain.AppResource, marker safety.Reactivating) error {
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	generation := uint64(0)
	for index := range next.Resources {
		item := &next.Resources[index]
		if item.ResourceID == resource.ID {
			if item.Reactivating == nil || !reflect.DeepEqual(*item.Reactivating, marker) {
				return fmt.Errorf("committed domain contraction marker changed")
			}
			generation = item.GenerationSequence + 1
			item.GenerationSequence = generation
			item.Closing = &safety.GenerationMarker{Kind: safety.MarkerClosing, Generation: generation, Reason: "committed_domain_recovery"}
			item.Reactivating = nil
		}
	}
	if generation == 0 {
		return fmt.Errorf("committed domain contraction safety missing")
	}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, state.Revision, next, safety.TransitionProof{}); err != nil {
		return err
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	result, contractErr := host.ContractResource(ctx, resource.ID)
	if contractErr == nil {
		contractErr = stopRecoveredGoAccessBounded(service, exposure, resource)
	}
	if contractErr != nil {
		snapshot, stopErr := stopRecoveredNginxBounded(host)
		goaccessErr := stopRecoveredGoAccessBounded(service, exposure, resource)
		observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
		fenceCtx, cancelFence := context.WithTimeout(context.Background(), 15*time.Second)
		fenceErr := service.WriteIngressActivationFence(fenceCtx, exposure, resource.ID, marker.PlanID, generation, generation-1, observed, stopErr != nil || goaccessErr != nil)
		cancelFence()
		return errors.Join(contractErr, stopErr, goaccessErr, fenceErr)
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	if err := admitter.ConvergeCommittedPublicationContraction(ctx, mutation, exposure, document.Revision, resource.ID, generation, result.RuntimeDigest); err != nil {
		return err
	}
	return convergeInterruptedDomainClosing(ctx, service, exposure, resource.ID, generation, result.RuntimeDigest, "committed_domain_recovery")
}

func resumeCommittedDomainContraction(ctx context.Context, service *FixedService, resource domain.AppResource, closing safety.GenerationMarker) error {
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	found := false
	for _, item := range state.Resources {
		found = found || item.ResourceID == resource.ID && item.Closing != nil && reflect.DeepEqual(*item.Closing, closing)
	}
	if !found {
		return fmt.Errorf("committed domain closing changed")
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	result, contractErr := host.ContractResource(ctx, resource.ID)
	if contractErr == nil {
		contractErr = stopRecoveredGoAccessBounded(service, exposure, resource)
	}
	if contractErr != nil {
		snapshot, stopErr := stopRecoveredNginxBounded(host)
		goaccessErr := stopRecoveredGoAccessBounded(service, exposure, resource)
		observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
		planID := ""
		if admitter, openErr := service.TimerAdmitter(); openErr == nil {
			if intent, intentErr := admitter.OperationIntent(resource.PublicationRecord.LastJobID); intentErr == nil {
				planID = intent.PlanID
			}
		}
		fenceCtx, cancelFence := context.WithTimeout(context.Background(), 15*time.Second)
		fenceErr := service.WriteIngressActivationFence(fenceCtx, exposure, resource.ID, planID, closing.Generation, closing.Generation-1, observed, stopErr != nil || goaccessErr != nil)
		cancelFence()
		return errors.Join(contractErr, stopErr, goaccessErr, fenceErr)
	}
	if resource.PublicationRecord.State == domain.PublicationPublished {
		document, err := service.normal.Read()
		if err != nil {
			return err
		}
		admitter, err := service.TimerAdmitter()
		if err != nil {
			return err
		}
		if err := admitter.ConvergeCommittedPublicationContraction(ctx, mutation, exposure, document.Revision, resource.ID, closing.Generation, result.RuntimeDigest); err != nil {
			return err
		}
	} else if resource.PublicationRecord.State != domain.PublicationUnpublished {
		return fmt.Errorf("committed domain normal recovery changed")
	}
	return convergeInterruptedDomainClosing(ctx, service, exposure, resource.ID, closing.Generation, result.RuntimeDigest, "committed_domain_recovery")
}

func restoreInterruptedDomainPointer(ctx context.Context, intent domain.ActivationIntent) error {
	candidate := intent.Candidate.DomainHTTPS
	if candidate == nil || candidate.Certificate.Authority == nil {
		return fmt.Errorf("interrupted certificate pointer authority missing")
	}
	priorGeneration := uint64(0)
	priorIdentity := certificates.BundleIdentity{}
	if intent.Prior != nil && intent.Prior.DomainHTTPS != nil && intent.Prior.DomainHTTPS.Certificate.Authority != nil && intent.Prior.DomainHTTPS.Certificate.Authority.CertificateID == candidate.Certificate.Authority.CertificateID {
		priorGeneration = intent.Prior.DomainHTTPS.Certificate.Generation
		priorIdentity = certificateBundleIdentity(intent.Prior.DomainHTTPS.Certificate)
	}
	pointer := certificates.Pointer{CertificateID: candidate.Certificate.Authority.CertificateID, CandidateGeneration: candidate.Certificate.Generation, CandidateIdentity: certificateBundleIdentity(candidate.Certificate), ExpectedPriorGeneration: priorGeneration, ExpectedPriorIdentity: priorIdentity}
	candidatePath, err := certificates.BundlePath(pointer.CertificateID, pointer.CandidateGeneration)
	if err != nil {
		return err
	}
	observed, err := certificates.ObservePointer(pointer.CertificateID)
	if err != nil {
		return err
	}
	if observed == candidatePath {
		if priorGeneration == 0 {
			return certificates.RemovePointer(ctx, pointer, candidatePath)
		}
		return certificates.RestorePointer(ctx, pointer, candidatePath)
	}
	priorPath := ""
	if priorGeneration != 0 {
		priorPath, err = certificates.BundlePath(pointer.CertificateID, priorGeneration)
		if err != nil {
			return err
		}
	}
	if observed != priorPath {
		return fmt.Errorf("interrupted certificate pointer identity changed")
	}
	if priorGeneration != 0 {
		return certificates.VerifyBundleIdentity(pointer.CertificateID, priorGeneration, priorIdentity)
	}
	return nil
}
