//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/certificates"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"os"
	"strings"
	"time"
)

func headscaleCertificateBundle(value certificates.Identity, binding acme.Binding) (domain.CertificateBundleIdentity, error) {
	if certificates.ValidateIdentity(value) != nil {
		return domain.CertificateBundleIdentity{}, fmt.Errorf("headscale certificate identity invalid")
	}
	pointer, err := certificates.ActivePointerPath(value.ID)
	if err != nil {
		return domain.CertificateBundleIdentity{}, err
	}
	credentials := make([]domain.CertificateCredentialIdentity, len(binding.CredentialFiles))
	for index, file := range binding.CredentialFiles {
		credentials[index] = domain.CertificateCredentialIdentity{Key: file.Key, Path: file.Path, Fingerprint: file.Fingerprint}
	}
	authority := &domain.CertificateAuthorityIdentity{CertificateID: value.ID, DirectoryURL: binding.DirectoryURL, AccountKeyPath: binding.AccountKeyPath, AccountKeyFingerprint: binding.AccountKeyFingerprint, AccountEmail: binding.AccountEmail, TermsAccepted: binding.TermsAccepted, Method: string(binding.Method), Provider: string(binding.Provider), ProfilePath: binding.ProfilePath, ProfileFingerprint: binding.ProfileFingerprint, CredentialFiles: credentials, Zone: binding.Zone, Principal: binding.Principal}
	return domain.CertificateBundleIdentity{PointerIdentity: pointer, BindingIdentity: value.BindingIdentity, Generation: value.Generation, Fingerprint: value.Fingerprint, SANIdentity: value.SANIdentity, NotAfter: value.NotAfter.Format("2006-01-02T15:04:05Z07:00"), LastTrustedWall: value.LastTrustedWall.Format("2006-01-02T15:04:05Z07:00"), ChainIdentity: value.ChainIdentity, IssuerIdentity: value.IssuerIdentity, Authority: authority}, nil
}

// CompleteHeadscaleLifecycle installs the durable certificate/start authority
// before S17C exposes the typed deploy/reissue actions.
func headscaleLifecycleNormalCommitted(service *FixedService, journal control.Journal) (bool, error) {
	document, err := service.normal.Read()
	if err != nil {
		return false, err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return false, err
	}
	headscale := installation.Headscale
	if headscale == nil || headscale.DeployIntent != nil || !headscale.Enabled || headscale.Applied == nil || headscale.Certificate == nil {
		return false, nil
	}
	return headscale.Certificate.Fingerprint == journal.Certificate.Fingerprint && headscale.Certificate.BindingIdentity == journal.Certificate.BindingIdentity && headscale.Applied.CertificateID == journal.Certificate.ID, nil
}

func verifyCommittedHeadscaleLifecycle(service *FixedService, journal control.Journal, state safety.State) error {
	committed, err := headscaleLifecycleNormalCommitted(service, journal)
	if err != nil || !committed || journal.Certificate == nil || state.Headscale.Reactivating != nil || state.Headscale.ActiveCertificate == nil || state.Headscale.ActiveCertificate.Fingerprint != journal.Certificate.Fingerprint || state.Headscale.ActiveCertificate.Binding != journal.Certificate.BindingIdentity {
		return fmt.Errorf("committed Headscale lifecycle authority incomplete: %w", err)
	}
	return nil
}

func finalizeInterruptedHeadscaleLifecycle(ctx context.Context, service *FixedService, journal control.Journal, _ safety.State) (returnErr error) {
	if journal.Certificate == nil {
		return fmt.Errorf("headscale lifecycle certificate missing")
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "headscale/"+journal.Candidate.HeadscaleID, service.manager)
	if err != nil {
		return errors.Join(err, mutationSet.Close())
	}
	defer func() {
		returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure), mutationSet.Close())
	}()
	fresh, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	if fresh.Headscale.Reactivating != nil {
		active := fresh.Headscale.Reactivating
		if active.PlanID != journal.PlanID || active.CertificateFingerprint != journal.Certificate.Fingerprint {
			return fmt.Errorf("headscale lifecycle reactivation changed")
		}
		next := fresh
		next.Revision++
		bundle, bundleErr := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
		if bundleErr != nil {
			return bundleErr
		}
		next.Headscale.ControlEntryDigest = bundle.Entry.Digest
		next.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: journal.Certificate.Generation, Fingerprint: journal.Certificate.Fingerprint, Binding: journal.Certificate.BindingIdentity, NotAfter: journal.Certificate.NotAfter, LastTrustedWall: journal.Certificate.LastTrustedWall}
		next.Headscale.Reactivating = nil
		if _, err := service.safety.Commit(ctx, exposure, safety.RolePublish, fresh.Revision, next, safety.TransitionProof{Headscale: headscaleConvergenceProof(*active, journal.RuntimeDigest)}); err != nil {
			return err
		}
		fresh = next
	}
	if fresh.Headscale.ActiveCertificate == nil || fresh.Headscale.ActiveCertificate.Fingerprint != journal.Certificate.Fingerprint {
		return fmt.Errorf("headscale lifecycle active certificate missing")
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	current, err := store.Read()
	if err != nil {
		return err
	}
	if current.Phase != control.PhaseCommitted {
		committed := current
		committed.Phase = control.PhaseCommitted
		if err := store.Replace(ctx, current, committed); err != nil {
			return err
		}
		current = committed
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || installation.Headscale.Certificate == nil {
		return fmt.Errorf("committed Headscale lifecycle normal authority missing")
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	_, err = admitter.CompleteHeadscaleDeploy(ctx, mutation, exposure, document.Revision, current.JobID, operations.HeadscaleDeployCompleteCommit{HeadscaleID: current.Candidate.HeadscaleID, Certificate: *installation.Headscale.Certificate, RuntimeDigest: current.RuntimeDigest})
	return err
}

func recordObservedHeadscaleExpiry(ctx context.Context, service *FixedService, document persist.Document, headscale *domain.HeadscaleDomain, generation uint64, deadline time.Time, journal control.Journal) (returnErr error) {
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return err
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.CertificateExpiry, Target: "headscale/" + headscale.ID, ActorIdentity: "recovery/headscale-certificate-expiry", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ResourceID: "headscale", ExpiryGeneration: generation, Deadline: deadline, CandidateBundle: headscale.Certificate.BindingIdentity}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		return errors.Join(admitErr, releaseErr)
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, mutationSet.Close()) }()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "headscale/"+headscale.ID, service.manager)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure)) }()
	inventory := safety.OwnershipInventoryDigest(map[string]string{})
	request := preflight.ContractionRequest{Kind: preflight.ContractionExpiry, Target: "headscale/" + headscale.ID, Generation: generation, OwnershipInventoryDigest: inventory, ClosureAuthorityDigest: headscale.Certificate.Fingerprint}
	result, err := preflight.EvaluateContraction(request, preflight.ContractionObservations{ExecutorUID: uint32(os.Geteuid()), InventoryComplete: true, OwnershipInventoryDigest: inventory, ClosureAuthorityDigest: headscale.Certificate.Fingerprint, ObservedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return err
	}
	intent, err := admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ContractionRequest: &request, ContractionPreflight: &result})
	if err != nil {
		return err
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	_, err = admitter.Complete(ctx, mutation, exposure, intent.IntentGeneration, job.ID, "complete", nil, []jobs.Postcondition{{Kind: "headscale_control_expired_closed", Status: jobs.PostconditionVerified, Identity: bundle.Digest}}, "")
	return err
}

func resumeExpiredHeadscaleCertificate(ctx context.Context, service *FixedService, document persist.Document, headscale *domain.HeadscaleDomain, journal control.Journal, intent operations.Reservation) (returnErr error) {
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, mutationSet.Close()) }()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, service.manager)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure)) }()
	if intent.Phase == operations.PhaseReserved {
		inventory := safety.OwnershipInventoryDigest(map[string]string{})
		request := preflight.ContractionRequest{Kind: preflight.ContractionExpiry, Target: intent.Target, Generation: intent.SafetyBinding.ExpiryGeneration, OwnershipInventoryDigest: inventory, ClosureAuthorityDigest: headscale.Certificate.Fingerprint}
		result, evaluateErr := preflight.EvaluateContraction(request, preflight.ContractionObservations{ExecutorUID: uint32(os.Geteuid()), InventoryComplete: true, OwnershipInventoryDigest: inventory, ClosureAuthorityDigest: headscale.Certificate.Fingerprint, ObservedAt: time.Now().UTC()})
		if evaluateErr != nil {
			return evaluateErr
		}
		fresh, readErr := service.normal.Read()
		if readErr != nil {
			return readErr
		}
		intent, err = admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: intent.JobID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ContractionRequest: &request, ContractionPreflight: &result})
		if err != nil {
			return err
		}
	}
	freshState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	if freshState.Headscale.CertificateExpiry == nil {
		generation := intent.SafetyBinding.ExpiryGeneration
		if freshState.Headscale.GenerationSequence+1 != generation {
			return fmt.Errorf("resumed Headscale expiry generation changed")
		}
		next := freshState
		next.Revision++
		next.Headscale.GenerationSequence = generation
		next.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: generation, Deadline: intent.SafetyBinding.Deadline, Binding: intent.SafetyBinding.CandidateBundle}
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, freshState.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	host, err := control.NewActivationHost()
	if err != nil {
		return err
	}
	closureErr := host.CloseControl(ctx, bundle)
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if closureErr == nil {
		expired := journal
		expired.Phase = control.PhaseExpired
		closureErr = store.Replace(ctx, journal, expired)
	}
	branch := "complete"
	post := jobs.PostconditionVerified
	code := ""
	if closureErr != nil {
		fenceErr := service.WriteHeadscaleCertificateContractionFence(context.WithoutCancel(ctx), exposure, bundle.Digest, safety.StopObservation{ObservedAt: time.Now().UTC()}, true)
		if fenceErr != nil {
			return errors.Join(closureErr, fenceErr)
		}
		observed, fallbackErr := host.FallbackStop(context.WithoutCancel(ctx), bundle)
		updateErr := service.UpdateHeadscaleCertificateContractionFence(context.WithoutCancel(ctx), exposure, observed, fallbackErr != nil)
		closureErr = errors.Join(closureErr, fallbackErr, updateErr)
		branch = "known_residual"
		post = jobs.PostconditionKnown
		code = "headscale_control_stop_fenced"
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return errors.Join(closureErr, err)
	}
	_, completeErr := admitter.Complete(context.WithoutCancel(ctx), mutation, exposure, fresh.Revision, intent.JobID, branch, nil, []jobs.Postcondition{{Kind: "headscale_control_expired_closed", Status: post, Identity: bundle.Digest}}, code)
	return errors.Join(closureErr, completeErr)
}

func ContractExpiredHeadscaleCertificate(ctx context.Context, now time.Time) (returnErr error) {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return err
	}
	headscale := installation.Headscale
	if headscale == nil || !headscale.Enabled || headscale.Certificate == nil {
		return nil
	}
	deadline, deadlineErr := time.Parse(time.RFC3339, headscale.Certificate.NotAfter)
	wall, wallErr := time.Parse(time.RFC3339, headscale.Certificate.LastTrustedWall)
	if deadlineErr != nil || wallErr != nil {
		return fmt.Errorf("headscale certificate deadline invalid")
	}
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	active := state.Headscale.ActiveCertificate
	if active == nil || active.Fingerprint != headscale.Certificate.Fingerprint || active.Binding != headscale.Certificate.BindingIdentity {
		return fmt.Errorf("headscale expiry active authority changed")
	}
	effective := deadline
	if now.Before(active.LastTrustedWall) || active.LastTrustedWall.Before(wall) || !active.NotAfter.Equal(deadline) {
		effective = now
	}
	if effective.After(now) {
		return nil
	}
	generation := state.Headscale.GenerationSequence + 1
	if state.Headscale.CertificateExpiry != nil {
		generation = state.Headscale.CertificateExpiry.Generation
		effective = state.Headscale.CertificateExpiry.Deadline
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	journal, err := store.Read()
	if err != nil || journal.Certificate == nil {
		return fmt.Errorf("headscale expiry lifecycle journal changed: %w", err)
	}
	if journal.Phase == control.PhaseCommitted {
		var running operations.Reservation
		for key, raw := range document.Entries {
			if !strings.HasPrefix(key, "intents/") {
				continue
			}
			var candidate operations.Reservation
			if json.Unmarshal(raw, &candidate) == nil && candidate.Operation == operations.CertificateExpiry && candidate.Target == "headscale/"+headscale.ID && candidate.SafetyBinding.ExpiryGeneration == generation && candidate.Phase != operations.PhaseTerminal && candidate.Phase != operations.PhaseRejected {
				if running.JobID != "" {
					return fmt.Errorf("multiple Headscale expiry intents")
				}
				running = candidate
			}
		}
		if running.JobID != "" {
			return resumeExpiredHeadscaleCertificate(ctx, service, document, headscale, journal, running)
		}
	}
	if journal.Phase == control.PhaseExpired {
		var existing operations.Reservation
		for key, raw := range document.Entries {
			if !strings.HasPrefix(key, "intents/") {
				continue
			}
			var candidate operations.Reservation
			if json.Unmarshal(raw, &candidate) == nil && candidate.Operation == operations.CertificateExpiry && candidate.Target == "headscale/"+headscale.ID && candidate.SafetyBinding.ExpiryGeneration == generation {
				if existing.JobID != "" {
					return fmt.Errorf("multiple Headscale expiry intents")
				}
				existing = candidate
			}
		}
		if existing.JobID == "" {
			return recordObservedHeadscaleExpiry(ctx, service, document, headscale, generation, effective, journal)
		}
		if existing.Phase == operations.PhaseTerminal {
			return nil
		}
		admitter, err := service.TimerAdmitter()
		if err != nil {
			return err
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, existing.Target, service.manager)
		if err != nil {
			return err
		}
		defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
		fresh, err := service.normal.Read()
		if err != nil {
			return err
		}
		bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
		if err != nil {
			return err
		}
		_, err = admitter.Complete(ctx, mutation, exposure, fresh.Revision, existing.JobID, "complete", nil, []jobs.Postcondition{{Kind: "headscale_control_expired_closed", Status: jobs.PostconditionVerified, Identity: bundle.Digest}}, "")
		return err
	}
	if journal.Phase != control.PhaseCommitted {
		return fmt.Errorf("headscale expiry lifecycle phase changed")
	}
	if state.Headscale.CertificateExpiry != nil {
		var existing operations.Reservation
		for key, raw := range document.Entries {
			if !strings.HasPrefix(key, "intents/") {
				continue
			}
			var candidate operations.Reservation
			if json.Unmarshal(raw, &candidate) == nil && candidate.Operation == operations.CertificateExpiry && candidate.Target == "headscale/"+headscale.ID && candidate.SafetyBinding.ExpiryGeneration == generation {
				if existing.JobID != "" {
					return fmt.Errorf("multiple Headscale expiry intents")
				}
				existing = candidate
			}
		}
		if existing.JobID != "" {
			if existing.Phase == operations.PhaseTerminal {
				return nil
			}
			return resumeExpiredHeadscaleCertificate(ctx, service, document, headscale, journal, existing)
		}
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return err
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.CertificateExpiry, Target: "headscale/" + headscale.ID, ActorIdentity: "timer/headscale-certificate-expiry", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ResourceID: "headscale", ExpiryGeneration: generation, Deadline: effective, CandidateBundle: headscale.Certificate.BindingIdentity}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		return errors.Join(admitErr, releaseErr)
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, mutationSet.Close()) }()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "headscale/"+headscale.ID, service.manager)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure)) }()
	inventoryDigest := safety.OwnershipInventoryDigest(map[string]string{})
	closureDigest := headscale.Certificate.Fingerprint
	request := preflight.ContractionRequest{Kind: preflight.ContractionExpiry, Target: "headscale/" + headscale.ID, Generation: generation, OwnershipInventoryDigest: inventoryDigest, ClosureAuthorityDigest: closureDigest}
	result, err := preflight.EvaluateContraction(request, preflight.ContractionObservations{ExecutorUID: uint32(os.Geteuid()), InventoryComplete: true, OwnershipInventoryDigest: inventoryDigest, ClosureAuthorityDigest: closureDigest, ObservedAt: now})
	if err != nil {
		return err
	}
	freshDocument, err := service.normal.Read()
	if err != nil {
		return err
	}
	intent, err := admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: freshDocument.Revision, IntentGeneration: freshDocument.Revision + 1, ContractionRequest: &request, ContractionPreflight: &result})
	if err != nil {
		return err
	}
	freshState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	if freshState.Headscale.CertificateExpiry == nil {
		if freshState.Headscale.GenerationSequence+1 != generation {
			return fmt.Errorf("headscale expiry generation changed")
		}
		next := freshState
		next.Revision++
		next.Headscale.GenerationSequence = generation
		next.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: generation, Deadline: effective, Binding: headscale.Certificate.BindingIdentity}
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, freshState.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	host, err := control.NewActivationHost()
	if err != nil {
		return err
	}
	closureErr := host.CloseControl(ctx, bundle)
	if closureErr == nil {
		expired := journal
		expired.Phase = control.PhaseExpired
		closureErr = store.Replace(ctx, journal, expired)
	}
	branch := "complete"
	post := jobs.PostconditionVerified
	code := ""
	if closureErr != nil {
		fenceErr := service.WriteHeadscaleCertificateContractionFence(context.WithoutCancel(ctx), exposure, bundle.Digest, safety.StopObservation{ObservedAt: time.Now().UTC()}, true)
		if fenceErr != nil {
			return errors.Join(closureErr, fenceErr)
		}
		observed, fallbackErr := host.FallbackStop(context.WithoutCancel(ctx), bundle)
		updateErr := service.UpdateHeadscaleCertificateContractionFence(context.WithoutCancel(ctx), exposure, observed, fallbackErr != nil)
		closureErr = errors.Join(closureErr, fallbackErr, updateErr)
		branch = "known_residual"
		post = jobs.PostconditionKnown
		code = "headscale_control_stop_fenced"
	}
	_, completeErr := admitter.Complete(context.WithoutCancel(ctx), mutation, exposure, intent.IntentGeneration, job.ID, branch, nil, []jobs.Postcondition{{Kind: "headscale_control_expired_closed", Status: post, Identity: bundle.Digest}}, code)
	return errors.Join(closureErr, completeErr)
}

func ExecuteHeadscaleDeploy(ctx context.Context, actor Actor, payload HeadscaleDeployPayload) (record jobs.Record, returnErr error) {
	execution, err := BeginHeadscaleDeploy(ctx, actor, payload)
	if err != nil {
		return jobs.Record{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, execution.Close()) }()
	account, err := managedheadscale.ValidateAccount(execution.Installation.InstallationID, execution.Installation.Headscale.ID)
	if err != nil {
		return jobs.Record{}, err
	}
	runtime, err := control.NewSystemdRuntime()
	if err != nil {
		return jobs.Record{}, err
	}
	candidateHost, err := control.NewLinuxCandidateHost(account, runtime)
	if err != nil {
		return jobs.Record{}, err
	}
	if _, err := execution.PrepareLocalCandidate(ctx, candidateHost); err != nil {
		return jobs.Record{}, err
	}
	if _, err := execution.RunFirstCertificate(ctx, candidateHost); err != nil {
		return jobs.Record{}, err
	}
	activationHost, err := control.NewActivationHost()
	if err != nil {
		return jobs.Record{}, err
	}
	if err := execution.ActivateControl(ctx, activationHost); err != nil {
		return jobs.Record{}, err
	}
	return execution.CompleteHeadscaleLifecycle(ctx)
}

func (execution *HeadscaleDeployExecution) CompleteHeadscaleLifecycle(ctx context.Context) (jobs.Record, error) {
	if execution == nil || execution.Mutation == nil || execution.Exposure == nil || execution.Installation.Headscale == nil || execution.Installation.Headscale.DeployIntent == nil || execution.Installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployActivated {
		return jobs.Record{}, fmt.Errorf("headscale lifecycle completion phase invalid")
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	journal, err := store.Read()
	if err != nil || journal.Phase != control.PhaseActivated || journal.JobID != execution.JobID || journal.Certificate == nil {
		return jobs.Record{}, fmt.Errorf("headscale activated lifecycle journal changed: %w", err)
	}
	certificate, err := headscaleCertificateBundle(*journal.Certificate, execution.Authority.Binding)
	if err != nil {
		return jobs.Record{}, err
	}
	commit := operations.HeadscaleDeployCompleteCommit{HeadscaleID: execution.Installation.Headscale.ID, Certificate: certificate, RuntimeDigest: journal.RuntimeDigest}
	if err := execution.Admitter.CommitHeadscaleDeployLifecycle(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, commit); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil || state.Headscale.Reactivating == nil || state.Headscale.Reactivating.PlanID != journal.PlanID {
		return jobs.Record{}, fmt.Errorf("headscale lifecycle safety authority changed: %w", err)
	}
	active := state.Headscale.Reactivating
	next := state
	next.Revision++
	bundle, bundleErr := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if bundleErr != nil {
		return jobs.Record{}, bundleErr
	}
	next.Headscale.ControlEntryDigest = bundle.Entry.Digest
	next.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: certificate.Generation, Fingerprint: certificate.Fingerprint, Binding: certificate.BindingIdentity, NotAfter: journal.Certificate.NotAfter, LastTrustedWall: journal.Certificate.LastTrustedWall}
	next.Headscale.Reactivating = nil
	proof := safety.TransitionProof{Headscale: headscaleConvergenceProof(*active, journal.RuntimeDigest)}
	if _, err = execution.Service.safety.Commit(ctx, execution.Exposure, safety.RolePublish, state.Revision, next, proof); err != nil {
		return jobs.Record{}, err
	}
	committed := journal
	committed.Phase = control.PhaseCommitted
	if err := store.Replace(ctx, journal, committed); err != nil {
		return jobs.Record{}, err
	}
	record, err := execution.Admitter.CompleteHeadscaleDeploy(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, commit)
	if err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	execution.Installation.Headscale.DeployIntent = nil
	execution.Installation.Headscale.Certificate = &certificate
	return record, nil
}
