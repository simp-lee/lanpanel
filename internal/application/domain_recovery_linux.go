//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/safety"
	"reflect"
	"time"
)

func ReconcileInterruptedDomainPublications(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer service.Close()
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	for _, authority := range state.Resources {
		if authority.Reactivating == nil && (authority.Closing == nil || authority.Closing.Reason != "interrupted_domain_activation" && authority.Closing.Reason != "committed_domain_recovery") {
			continue
		}
		if authority.Reactivating != nil && authority.Reactivating.TemporaryHTTP {
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
			state, err = service.safety.Read()
			if err != nil {
				return err
			}
			continue
		}
		if authority.Reactivating != nil && resource.PublicationRecord.State == domain.PublicationPublished && activationIntent == nil {
			if err := convergeCommittedDomainPublication(ctx, service, resource, *authority.Reactivating); err != nil {
				return err
			}
			state, err = service.safety.Read()
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
			state, err = service.safety.Read()
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
			mutationSet.Close()
			return err
		}
		fresh, err := service.safety.ReadForRecovery(exposure)
		if err != nil {
			operations.ReleaseExposure(mutation, exposure)
			mutationSet.Close()
			return err
		}
		owned, ownerErr := service.ownership.Read(resource.ID)
		if ownerErr != nil {
			operations.ReleaseExposure(mutation, exposure)
			mutationSet.Close()
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
							operations.ReleaseExposure(mutation, exposure)
							mutationSet.Close()
							return err
						}
					}
				}
				fresh, err = service.safety.ReadForRecovery(exposure)
				if err != nil {
					operations.ReleaseExposure(mutation, exposure)
					mutationSet.Close()
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
				operations.ReleaseExposure(mutation, exposure)
				mutationSet.Close()
				return transitionErr
			}
			next.Resources[index] = updated
			generation = currentGeneration
			safetyChanged = changed
		}
		if generation == 0 {
			operations.ReleaseExposure(mutation, exposure)
			mutationSet.Close()
			return fmt.Errorf("reactivating publication safety resource missing")
		}
		if safetyChanged {
			if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, fresh.Revision, next, safety.TransitionProof{}); err != nil {
				operations.ReleaseExposure(mutation, exposure)
				mutationSet.Close()
				return err
			}
		}
		host, err := activation.NewFixedHost()
		if err != nil {
			operations.ReleaseExposure(mutation, exposure)
			mutationSet.Close()
			return err
		}
		result, contractErr := host.ContractResource(ctx, resource.ID)
		if contractErr != nil {
			snapshot, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
			observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
			fenceErr := service.WriteIngressActivationFence(context.WithoutCancel(ctx), exposure, resource.ID, activationIntent.PlanID, generation, generation-1, observed, stopErr != nil)
			operations.ReleaseExposure(mutation, exposure)
			mutationSet.Close()
			return errors.Join(contractErr, stopErr, fenceErr)
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
		state, err = service.safety.Read()
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
		if item.Closing == nil || item.Closing.Generation != generation {
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
	candidate, err := prepareDomainCandidate(service, resource, marker.Generation, applied.DomainHTTPS.Certificate)
	if err != nil {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
	}
	if !reflect.DeepEqual(candidate.Bundle, *applied) {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
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
	if err != nil || record.Result != jobs.ResultSucceeded || len(record.Postconditions) != 1 || record.Postconditions[0].Kind != "published" || record.Postconditions[0].Identity != runtimeDigest {
		return contractCommittedDomainPublication(ctx, service, resource, marker)
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer mutationSet.Close()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return err
	}
	defer operations.ReleaseExposure(mutation, exposure)
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
			item.EdgeOne.Expiry = nil
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
	defer mutationSet.Close()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return err
	}
	defer operations.ReleaseExposure(mutation, exposure)
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
	if contractErr != nil {
		snapshot, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
		fenceErr := service.WriteIngressActivationFence(context.WithoutCancel(ctx), exposure, resource.ID, marker.PlanID, generation, generation-1, observed, stopErr != nil)
		return errors.Join(contractErr, stopErr, fenceErr)
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
	defer mutationSet.Close()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return err
	}
	defer operations.ReleaseExposure(mutation, exposure)
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
	if contractErr != nil {
		snapshot, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
		planID := ""
		if admitter, openErr := service.TimerAdmitter(); openErr == nil {
			if intent, intentErr := admitter.OperationIntent(resource.PublicationRecord.LastJobID); intentErr == nil {
				planID = intent.PlanID
			}
		}
		fenceErr := service.WriteIngressActivationFence(context.WithoutCancel(ctx), exposure, resource.ID, planID, closing.Generation, closing.Generation-1, observed, stopErr != nil)
		return errors.Join(contractErr, stopErr, fenceErr)
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
	if intent.Prior != nil && intent.Prior.DomainHTTPS != nil && intent.Prior.DomainHTTPS.Certificate.Authority != nil && intent.Prior.DomainHTTPS.Certificate.Authority.CertificateID == candidate.Certificate.Authority.CertificateID {
		priorGeneration = intent.Prior.DomainHTTPS.Certificate.Generation
	}
	pointer := certificates.Pointer{CertificateID: candidate.Certificate.Authority.CertificateID, CandidateGeneration: candidate.Certificate.Generation, ExpectedPriorGeneration: priorGeneration}
	candidatePath, err := certificates.BundlePath(pointer.CertificateID, pointer.CandidateGeneration)
	if err != nil {
		return err
	}
	observed, err := certificates.ObservePointer(pointer.CertificateID)
	if err != nil {
		return err
	}
	if observed == candidatePath {
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
	return nil
}
