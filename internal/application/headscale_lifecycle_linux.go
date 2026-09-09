//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func verifyLiveHeadscaleCertificate(ctx context.Context, installationID string, candidate control.Candidate, certificate certificates.Identity) error {
	bundle, err := control.BuildActivation(installationID, candidate, certificate)
	if err != nil {
		return err
	}
	manifest, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return err
	}
	matched := false
	for _, entry := range manifest.Entries {
		matched = matched || reflect.DeepEqual(entry, bundle.Entry)
	}
	if !matched {
		return fmt.Errorf("headscale live control entry differs from certificate authority")
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	runtime, err := host.ObserveRuntime(ctx, manifest)
	if err != nil || runtime.Master == nil {
		return fmt.Errorf("headscale live runtime unavailable: %w", err)
	}
	return host.VerifyServedCertificate(ctx, candidate.ControlDomain, certificate.Fingerprint)
}

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
	return domain.CertificateBundleIdentity{PointerIdentity: pointer, BindingIdentity: value.BindingIdentity, Generation: value.Generation, Fingerprint: value.Fingerprint, SANIdentity: value.SANIdentity, NotAfter: value.NotAfter.Format("2006-01-02T15:04:05Z07:00"), LastTrustedWall: value.LastTrustedWall.Format("2006-01-02T15:04:05Z07:00"), ChainIdentity: value.ChainIdentity, IssuerIdentity: value.IssuerIdentity, DirectoryIdentity: value.DirectoryIdentity, Authority: authority}, nil
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
	if !headscaleControlCandidateMatchesNormal(installation, journal) || headscale.DeployIntent != nil || !headscale.Enabled || headscale.Certificate == nil || headscale.Certificate.Authority == nil || journal.Certificate == nil {
		return false, nil
	}
	return headscale.Certificate.Authority.CertificateID == journal.Certificate.ID && headscale.Certificate.Generation == journal.Certificate.Generation && certificateBundleIdentity(*headscale.Certificate) == certificates.BundleIdentityFor(*journal.Certificate), nil
}

func verifyCommittedHeadscaleLifecycle(service *FixedService, journal control.Journal, state safety.State) error {
	committed, err := headscaleLifecycleNormalCommitted(service, journal)
	if err != nil || !committed || journal.Certificate == nil || state.Headscale.Reactivating != nil {
		return fmt.Errorf("committed Headscale lifecycle authority incomplete: %w", err)
	}
	expectedActive := &safety.ActiveCertificateAuthority{Generation: journal.Certificate.Generation, Fingerprint: journal.Certificate.Fingerprint, Binding: journal.Certificate.BindingIdentity, NotAfter: journal.Certificate.NotAfter, LastTrustedWall: journal.Certificate.LastTrustedWall}
	if !activeCertificateMatchesExpected(state.Headscale.ActiveCertificate, expectedActive) {
		return fmt.Errorf("committed Headscale lifecycle active certificate authority changed")
	}
	return nil
}

func finalizeInterruptedHeadscaleLifecycle(ctx context.Context, service *FixedService, journal control.Journal, _ safety.State) (returnErr error) {
	if journal.Certificate == nil || (journal.Phase != control.PhaseActivated && journal.Phase != control.PhaseCommitted) {
		return fmt.Errorf("headscale lifecycle certificate or phase missing")
	}
	target, err := certificates.BundlePath(journal.Certificate.ID, journal.Certificate.Generation)
	if err != nil {
		return err
	}
	activePointer, err := certificates.ObservePointer(journal.Certificate.ID)
	if err != nil || activePointer != target {
		return fmt.Errorf("headscale lifecycle active pointer changed: %w", err)
	}
	if err := certificates.VerifyBundleIdentity(journal.Certificate.ID, journal.Certificate.Generation, certificates.BundleIdentityFor(*journal.Certificate)); err != nil {
		return err
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if err != nil {
		return err
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
		candidateDigest, candidateDigestErr := control.Digest(journal.Candidate)
		if candidateDigestErr != nil {
			return candidateDigestErr
		}
		if active.PlanID != journal.PlanID || active.Generation != journal.IntentGeneration || active.PriorGeneration+1 != active.Generation || active.ControlGeneration != journal.Candidate.Generation || active.CertificateGeneration != journal.Certificate.Generation || active.CertificateFingerprint != journal.Certificate.Fingerprint || active.CandidateDigest != journal.Candidate.ConfigDigest || active.CandidateBundle != candidateDigest || active.ActivationDigest != bundle.Digest || active.ControlEntryDigest != bundle.Entry.Digest || !active.CertificateUntil.Equal(journal.Certificate.NotAfter) || !active.CertificateLastTrustedWall.Equal(journal.Certificate.LastTrustedWall) {
			return fmt.Errorf("headscale lifecycle reactivation changed")
		}
		next := fresh
		next.Revision++
		next.Headscale.ControlEntryDigest = bundle.Entry.Digest
		next.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: journal.Certificate.Generation, Fingerprint: journal.Certificate.Fingerprint, Binding: journal.Certificate.BindingIdentity, NotAfter: journal.Certificate.NotAfter, LastTrustedWall: journal.Certificate.LastTrustedWall}
		next.Headscale.Reactivating = nil
		if _, err := service.safety.Commit(ctx, exposure, safety.RolePublish, fresh.Revision, next, safety.TransitionProof{Headscale: headscaleConvergenceProof(*active, journal.RuntimeDigest)}); err != nil {
			return err
		}
		fresh = next
	}
	expectedActive := &safety.ActiveCertificateAuthority{Generation: journal.Certificate.Generation, Fingerprint: journal.Certificate.Fingerprint, Binding: journal.Certificate.BindingIdentity, NotAfter: journal.Certificate.NotAfter, LastTrustedWall: journal.Certificate.LastTrustedWall}
	if !activeCertificateMatchesExpected(fresh.Headscale.ActiveCertificate, expectedActive) {
		return fmt.Errorf("headscale lifecycle active certificate missing")
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	current, err := store.Read()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, journal) {
		return fmt.Errorf("headscale lifecycle control journal lineage changed")
	}
	if current.Phase == control.PhaseActivated {
		committed := current
		committed.Phase = control.PhaseCommitted
		if err := store.Replace(ctx, current, committed); err != nil {
			return err
		}
		current = committed
	} else if current.Phase != control.PhaseCommitted {
		return fmt.Errorf("headscale lifecycle control phase changed")
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || installation.Headscale.Certificate == nil || installation.Headscale.Certificate.Authority == nil || installation.Headscale.Certificate.Authority.CertificateID != journal.Certificate.ID || installation.Headscale.Certificate.Generation != journal.Certificate.Generation || certificateBundleIdentity(*installation.Headscale.Certificate) != certificates.BundleIdentityFor(*journal.Certificate) {
		return fmt.Errorf("committed Headscale lifecycle normal authority missing")
	}
	rendered, err := readHeadscaleRendered(journal.Candidate)
	if err != nil {
		return err
	}
	activationHost, err := control.NewActivationHost()
	if err != nil {
		return err
	}
	reloadAuthority, err := challengeReloadAuthorityForExposure(service, exposure)
	if err != nil {
		return err
	}
	rawIntent, present := document.Entries["intents/"+current.JobID]
	var intent operations.Reservation
	if !present || json.Unmarshal(rawIntent, &intent) != nil || intent.JobID != current.JobID || intent.Operation != operations.HeadscaleDeploy || intent.Target != "headscale/"+current.Candidate.HeadscaleID || intent.Phase != operations.PhaseReentered && intent.Phase != operations.PhaseTerminal {
		return fmt.Errorf("committed Headscale lifecycle operation authority missing")
	}
	if intent.Phase == operations.PhaseTerminal {
		err = activationHost.ObserveBootActivation(ctx, bundle, rendered, reloadAuthority)
	} else {
		err = activationHost.ReconcileBootActivation(ctx, bundle, rendered, reloadAuthority)
	}
	if err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	_, err = admitter.CompleteHeadscaleDeploy(ctx, mutation, exposure, document.Revision, current.JobID, operations.HeadscaleDeployCompleteCommit{HeadscaleID: current.Candidate.HeadscaleID, Certificate: *installation.Headscale.Certificate, RuntimeDigest: current.RuntimeDigest})
	return err
}

func readHeadscaleRendered(candidate control.Candidate) (control.Rendered, error) {
	config, configErr := os.ReadFile(candidate.Paths.Config)
	policy, policyErr := os.ReadFile(candidate.Paths.Policy)
	unit, unitErr := os.ReadFile(candidate.Paths.Unit)
	if err := errors.Join(configErr, policyErr, unitErr); err != nil {
		return control.Rendered{}, err
	}
	rendered := control.Rendered{Candidate: candidate, Config: config, Policy: policy, Unit: unit}
	if err := control.VerifyRendered(rendered); err != nil {
		return control.Rendered{}, err
	}
	return rendered, nil
}

func headscaleControlCandidateMatchesNormal(installation domain.Installation, journal control.Journal) bool {
	headscale := installation.Headscale
	if headscale == nil || headscale.Applied == nil || journal.InstallationID != installation.InstallationID {
		return false
	}
	applied, err := control.AppliedIdentity(journal.Candidate)
	return err == nil && reflect.DeepEqual(applied, *headscale.Applied) && journal.Candidate.HeadscaleID == headscale.ID && journal.Candidate.DatabaseUUID == headscale.Database.UUID && journal.Candidate.DatabaseGeneration == headscale.Database.Generation && journal.Candidate.ControlDomain == headscale.ControlDomain && journal.Candidate.MagicDNSNamespace == headscale.MagicDNSNamespace && reflect.DeepEqual(journal.Candidate.Artifact, headscale.Artifact)
}

func headscaleExpiryJournalMatchesNormal(installation domain.Installation, journal control.Journal) bool {
	headscale := installation.Headscale
	identity := journal.Certificate
	if !headscaleControlCandidateMatchesNormal(installation, journal) || headscale.Certificate == nil || identity == nil || headscale.Certificate.Authority == nil {
		return false
	}
	certificate := headscale.Certificate
	notAfter, notAfterErr := time.Parse(time.RFC3339, certificate.NotAfter)
	lastWall, lastWallErr := time.Parse(time.RFC3339, certificate.LastTrustedWall)
	return notAfterErr == nil && lastWallErr == nil && journal.Candidate.CertificateID == identity.ID &&
		headscale.Applied.CertificateID == identity.ID && certificate.Authority.CertificateID == identity.ID &&
		certificate.Generation == identity.Generation && certificate.Fingerprint == identity.Fingerprint && certificate.BindingIdentity == identity.BindingIdentity && certificate.SANIdentity == identity.SANIdentity && certificate.ChainIdentity == identity.ChainIdentity && certificate.IssuerIdentity == identity.IssuerIdentity && certificate.DirectoryIdentity == identity.DirectoryIdentity &&
		notAfter.Equal(identity.NotAfter.Truncate(time.Second)) && lastWall.Equal(identity.LastTrustedWall.Truncate(time.Second))
}

func readLockedHeadscaleExpiryAuthority(service *FixedService, headscale *domain.HeadscaleDomain, expectedJournal control.Journal) (persist.Document, control.Journal, error) {
	document, err := service.normal.Read()
	if err != nil {
		return persist.Document{}, control.Journal{}, err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return persist.Document{}, control.Journal{}, err
	}
	if installation.Headscale == nil || installation.Headscale.ID != headscale.ID || !reflect.DeepEqual(installation.Headscale.Certificate, headscale.Certificate) {
		return persist.Document{}, control.Journal{}, fmt.Errorf("headscale expiry normal authority changed under lock")
	}
	journal, err := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}).Read()
	if err != nil {
		return persist.Document{}, control.Journal{}, err
	}
	if !reflect.DeepEqual(journal, expectedJournal) || !headscaleExpiryJournalMatchesNormal(installation, journal) {
		return persist.Document{}, control.Journal{}, fmt.Errorf("headscale expiry control journal changed under lock")
	}
	return document, journal, nil
}

func requireHeadscaleExpirySafety(state safety.State, headscale *domain.HeadscaleDomain, intent operations.Reservation) error {
	active := state.Headscale.ActiveCertificate
	marker := state.Headscale.CertificateExpiry
	certificate := headscale.Certificate
	if state.GlobalClose.Phase != safety.GlobalCloseNone || certificate == nil || active == nil || active.Generation != certificate.Generation || active.Fingerprint != certificate.Fingerprint || active.Binding != certificate.BindingIdentity || marker == nil || marker.Generation != intent.SafetyBinding.ExpiryGeneration || !marker.Deadline.Equal(intent.SafetyBinding.Deadline) || marker.Binding != intent.SafetyBinding.CandidateBundle {
		return fmt.Errorf("headscale expiry safety authority changed under lock")
	}
	return nil
}

func requireHeadscaleExpiryBundle(state safety.State, bundle control.ActivationBundle) error {
	if state.Headscale.ControlEntryDigest == "" || bundle.Entry.Digest != state.Headscale.ControlEntryDigest {
		return fmt.Errorf("headscale expiry control graph authority changed under lock")
	}
	return nil
}

func resumeExpiredHeadscaleCertificate(ctx context.Context, service *FixedService, _ persist.Document, headscale *domain.HeadscaleDomain, journal control.Journal, intent operations.Reservation) (returnErr error) {
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
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	lockedJournal, err := store.Read()
	if err != nil {
		return err
	}
	expectedJournal := journal
	expectedJournal.Phase = lockedJournal.Phase
	if lockedJournal.Phase != control.PhaseCommitted && lockedJournal.Phase != control.PhaseExpired {
		return fmt.Errorf("headscale expiry control journal changed under lock")
	}
	lockedDocument, lockedJournal, err := readLockedHeadscaleExpiryAuthority(service, headscale, expectedJournal)
	if err != nil {
		return err
	}
	lockedIntent, err := admitter.OperationIntent(intent.JobID)
	if err != nil {
		return fmt.Errorf("headscale expiry intent changed under lock: %w", err)
	}
	if lockedIntent.JobID != intent.JobID || lockedIntent.Operation != operations.CertificateExpiry || lockedIntent.Target != intent.Target || lockedIntent.SafetyBinding.ExpiryGeneration != intent.SafetyBinding.ExpiryGeneration {
		return fmt.Errorf("headscale expiry intent changed under lock")
	}
	intent = lockedIntent
	journal = lockedJournal
	if intent.Phase == operations.PhaseTerminal {
		if journal.Phase == control.PhaseExpired {
			return nil
		}
		return fmt.Errorf("terminal Headscale expiry left committed control")
	}
	if intent.Phase != operations.PhaseReserved && intent.Phase != operations.PhaseLocalIntent {
		return fmt.Errorf("headscale expiry intent has unsupported phase %q", intent.Phase)
	}
	if intent.Phase == operations.PhaseReserved {
		inventory := safety.OwnershipInventoryDigest(map[string]string{})
		request := preflight.ContractionRequest{Kind: preflight.ContractionExpiry, Target: intent.Target, Generation: intent.SafetyBinding.ExpiryGeneration, OwnershipInventoryDigest: inventory, ClosureAuthorityDigest: headscale.Certificate.Fingerprint}
		result, evaluateErr := preflight.EvaluateContraction(request, preflight.ContractionObservations{ExecutorUID: uint32(os.Geteuid()), InventoryComplete: true, OwnershipInventoryDigest: inventory, ClosureAuthorityDigest: headscale.Certificate.Fingerprint, ObservedAt: time.Now().UTC()})
		if evaluateErr != nil {
			return evaluateErr
		}
		intent, err = admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: intent.JobID, ExpectedRevision: lockedDocument.Revision, IntentGeneration: lockedDocument.Revision + 1, ContractionRequest: &request, ContractionPreflight: &result})
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
		freshState = next
	}
	if err := requireHeadscaleExpirySafety(freshState, headscale, intent); err != nil {
		return err
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	if err := requireHeadscaleExpiryBundle(freshState, bundle); err != nil {
		return err
	}
	if journal.Phase == control.PhaseExpired {
		fresh, err := service.normal.Read()
		if err != nil {
			return err
		}
		_, completeErr := admitter.Complete(context.WithoutCancel(ctx), mutation, exposure, fresh.Revision, intent.JobID, "complete", nil, []jobs.Postcondition{{Kind: "headscale_control_expired_closed", Status: jobs.PostconditionVerified, Identity: bundle.Digest}}, "")
		return completeErr
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
	fresh, err := service.normal.Read()
	if err != nil {
		return errors.Join(closureErr, err)
	}
	_, completeErr := admitter.Complete(context.WithoutCancel(ctx), mutation, exposure, fresh.Revision, intent.JobID, branch, nil, []jobs.Postcondition{{Kind: "headscale_control_expired_closed", Status: post, Identity: bundle.Digest}}, code)
	return errors.Join(closureErr, completeErr)
}

func commitDiscrepantHeadscaleExpiryMarker(ctx context.Context, service *FixedService, headscale *domain.HeadscaleDomain, journal control.Journal, generation uint64, deadline time.Time) (returnErr error) {
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	cleanup := &certificateContractionCleanup{mutationSet: mutationSet}
	defer func() { returnErr = errors.Join(returnErr, cleanup.Close()) }()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "headscale/"+headscale.ID, service.manager)
	if err != nil {
		return err
	}
	cleanup.mutation = mutation
	cleanup.exposure = exposure
	if _, _, err := readLockedHeadscaleExpiryAuthority(service, headscale, journal); err != nil {
		return err
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	if state.GlobalClose.Phase != safety.GlobalCloseNone {
		return fmt.Errorf("global close blocks discrepant Headscale expiry marker")
	}
	if state.Headscale.CertificateExpiry != nil {
		if state.Headscale.CertificateExpiry.Generation == generation && state.Headscale.CertificateExpiry.Deadline.Equal(deadline) && state.Headscale.CertificateExpiry.Binding == headscale.Certificate.BindingIdentity {
			return nil
		}
		return fmt.Errorf("discrepant Headscale expiry marker changed")
	}
	active := state.Headscale.ActiveCertificate
	if active == nil || active.Generation != headscale.Certificate.Generation || active.Fingerprint != headscale.Certificate.Fingerprint || active.Binding != headscale.Certificate.BindingIdentity || state.Headscale.GenerationSequence+1 != generation {
		return fmt.Errorf("discrepant Headscale expiry safety authority changed")
	}
	next := state
	next.Revision++
	next.Headscale.GenerationSequence = generation
	next.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: generation, Deadline: deadline, Binding: headscale.Certificate.BindingIdentity}
	_, err = service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
	return err
}

func requireExpiredHeadscaleClosureLocked(service *FixedService, exposure *locks.Lease, headscale *domain.HeadscaleDomain, journal control.Journal, binding operations.SafetyBinding) (persist.Document, string, error) {
	document, lockedJournal, err := readLockedHeadscaleExpiryAuthority(service, headscale, journal)
	if err != nil {
		return persist.Document{}, "", fmt.Errorf("expired Headscale closure authority changed under lock: %w", err)
	}
	if lockedJournal.Phase != control.PhaseExpired {
		return persist.Document{}, "", fmt.Errorf("expired Headscale closure authority changed under lock")
	}
	lockedState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return persist.Document{}, "", err
	}
	if err := requireHeadscaleExpirySafety(lockedState, headscale, operations.Reservation{SafetyBinding: binding}); err != nil {
		return persist.Document{}, "", err
	}
	bundle, err := control.BuildActivation(lockedJournal.InstallationID, lockedJournal.Candidate, *lockedJournal.Certificate)
	if err != nil {
		return persist.Document{}, "", err
	}
	if err := requireHeadscaleExpiryBundle(lockedState, bundle); err != nil {
		return persist.Document{}, "", err
	}
	return document, bundle.Digest, nil
}

func validateExpiredHeadscaleClosure(ctx context.Context, service *FixedService, headscale *domain.HeadscaleDomain, journal control.Journal, intent *operations.Reservation, generation uint64, deadline time.Time) (returnErr error) {
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, mutationSet.Close()) }()
	target := "headscale/" + headscale.ID
	if intent != nil {
		target = intent.Target
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, target, service.manager)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure)) }()
	binding := operations.SafetyBinding{ResourceID: "headscale", ExpiryGeneration: generation, Deadline: deadline, CandidateBundle: headscale.Certificate.BindingIdentity}
	if intent != nil {
		binding = intent.SafetyBinding
	}
	_, _, err = requireExpiredHeadscaleClosureLocked(service, exposure, headscale, journal, binding)
	return err
}

func recordHeadscaleExpiryReconciliation(ctx context.Context, service *FixedService, headscale *domain.HeadscaleDomain, journal control.Journal, generation uint64, deadline time.Time) (returnErr error) {
	target := "journal/headscale-certificate-expiry-" + strconv.FormatUint(generation, 10)
	binding := operations.SafetyBinding{ResourceID: "headscale", ExpiryGeneration: generation, Deadline: deadline, CandidateBundle: headscale.Certificate.BindingIdentity}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	var intent operations.Reservation
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var candidate operations.Reservation
		if json.Unmarshal(raw, &candidate) == nil && candidate.Operation == operations.AutomaticReconciliation && candidate.Target == target && candidate.Phase != operations.PhaseRejected {
			if intent.JobID != "" {
				return fmt.Errorf("multiple Headscale expiry reconciliation intents")
			}
			intent = candidate
		}
	}
	if intent.Phase == operations.PhaseTerminal {
		return validateExpiredHeadscaleClosure(ctx, service, headscale, journal, nil, generation, deadline)
	}
	if intent.JobID == "" {
		admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
		if err != nil {
			return err
		}
		job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.AutomaticReconciliation, Target: target, ActorIdentity: "recovery/headscale-certificate-expiry", Source: operations.AdmissionTimer, SafetyBinding: binding, ExpectedRevision: document.Revision})
		releaseErr := admission.Release()
		if admitErr != nil || releaseErr != nil {
			return errors.Join(admitErr, releaseErr)
		}
		intent, err = admitter.OperationIntent(job.ID)
		if err != nil {
			return err
		}
	}
	planlessStarted := intent.Phase != operations.PhaseReserved
	defer func() {
		if !planlessStarted {
			returnErr = errors.Join(returnErr, rejectReservedCertificateExpiry(ctx, service, admitter, intent.JobID, "certificate_setup_failed"))
		}
	}()
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, mutationSet.Close()) }()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, target, service.manager)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure)) }()
	lockedDocument, closureDigest, err := requireExpiredHeadscaleClosureLocked(service, exposure, headscale, journal, binding)
	if err != nil {
		return err
	}
	intent, err = admitter.OperationIntent(intent.JobID)
	if err != nil {
		return fmt.Errorf("headscale expiry reconciliation intent changed: %w", err)
	}
	if intent.Operation != operations.AutomaticReconciliation || intent.Target != target {
		return fmt.Errorf("headscale expiry reconciliation intent changed")
	}
	if intent.Phase == operations.PhaseReserved {
		intent, err = admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: intent.JobID, ExpectedRevision: lockedDocument.Revision, IntentGeneration: lockedDocument.Revision + 1})
		if err != nil {
			return err
		}
		planlessStarted = true
	} else if intent.Phase != operations.PhaseLocalIntent {
		return fmt.Errorf("headscale expiry reconciliation phase changed")
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return err
	}
	_, err = admitter.Complete(ctx, mutation, exposure, fresh.Revision, intent.JobID, "complete", nil, []jobs.Postcondition{{Kind: "headscale_control_expired_closed", Status: jobs.PostconditionVerified, Identity: closureDigest}}, "")
	return err
}

func findHeadscaleExpiryIntent(document persist.Document, target string, generation uint64) (operations.Reservation, bool, error) {
	var result operations.Reservation
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if err := json.Unmarshal(raw, &intent); err != nil {
			return operations.Reservation{}, false, err
		}
		if intent.Operation == operations.CertificateExpiry && intent.Target == target && intent.SafetyBinding.ExpiryGeneration == generation {
			if result.JobID != "" {
				return operations.Reservation{}, false, fmt.Errorf("multiple Headscale expiry intents")
			}
			result = intent
		}
	}
	return result, result.JobID != "", nil
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
	if state.GlobalClose.Phase != safety.GlobalCloseNone {
		return nil
	}
	active := state.Headscale.ActiveCertificate
	if active == nil || active.Fingerprint != headscale.Certificate.Fingerprint || active.Binding != headscale.Certificate.BindingIdentity {
		return fmt.Errorf("headscale expiry active authority changed")
	}
	effective := deadline
	if now.Before(active.LastTrustedWall) || active.LastTrustedWall.Before(wall) || !active.NotAfter.Equal(deadline) {
		effective = now
	}
	generation := state.Headscale.GenerationSequence + 1
	markerNeeded := state.Headscale.CertificateExpiry == nil
	if state.Headscale.CertificateExpiry != nil {
		generation = state.Headscale.CertificateExpiry.Generation
		effective = state.Headscale.CertificateExpiry.Deadline
	}
	existingExpiryIntent, foundExpiryIntent, err := findHeadscaleExpiryIntent(document, "headscale/"+headscale.ID, generation)
	if err != nil {
		return err
	}
	if foundExpiryIntent && markerNeeded {
		effective = existingExpiryIntent.SafetyBinding.Deadline
	}
	if markerNeeded && effective.After(now) && !foundExpiryIntent {
		return nil
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	journal, err := store.Read()
	if err != nil {
		return fmt.Errorf("headscale expiry lifecycle journal changed: %w", err)
	}
	if journal.Certificate == nil || !headscaleExpiryJournalMatchesNormal(installation, journal) {
		return fmt.Errorf("headscale expiry lifecycle journal changed")
	}
	if markerNeeded && !foundExpiryIntent && !effective.Equal(active.NotAfter) {
		if err := commitDiscrepantHeadscaleExpiryMarker(ctx, service, headscale, journal, generation, effective); err != nil {
			return err
		}
	}
	if journal.Phase == control.PhaseCommitted {
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
			switch existing.Phase {
			case operations.PhaseReserved, operations.PhaseLocalIntent:
				return resumeExpiredHeadscaleCertificate(ctx, service, document, headscale, journal, existing)
			case operations.PhaseTerminal, operations.PhaseRejected:
				return fmt.Errorf("terminal Headscale expiry with committed control requires independent contraction")
			default:
				return fmt.Errorf("headscale expiry intent has unsupported phase %q", existing.Phase)
			}
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
		if existing.Phase == operations.PhaseTerminal {
			return validateExpiredHeadscaleClosure(ctx, service, headscale, journal, &existing, generation, effective)
		}
		if existing.JobID == "" || existing.Phase == operations.PhaseRejected {
			return recordHeadscaleExpiryReconciliation(ctx, service, headscale, journal, generation, effective)
		}
		if existing.Phase != operations.PhaseReserved && existing.Phase != operations.PhaseLocalIntent {
			return fmt.Errorf("expired Headscale intent has unsupported phase %q", existing.Phase)
		}
		return resumeExpiredHeadscaleCertificate(ctx, service, document, headscale, journal, existing)
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
			switch existing.Phase {
			case operations.PhaseReserved, operations.PhaseLocalIntent:
				return resumeExpiredHeadscaleCertificate(ctx, service, document, headscale, journal, existing)
			case operations.PhaseTerminal, operations.PhaseRejected:
				return fmt.Errorf("terminal Headscale expiry with committed control requires independent contraction")
			default:
				return fmt.Errorf("headscale expiry intent has unsupported phase %q", existing.Phase)
			}
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
	lockedDocument, lockedJournal, err := readLockedHeadscaleExpiryAuthority(service, headscale, journal)
	if err != nil {
		return err
	}
	journal = lockedJournal
	inventoryDigest := safety.OwnershipInventoryDigest(map[string]string{})
	closureDigest := headscale.Certificate.Fingerprint
	request := preflight.ContractionRequest{Kind: preflight.ContractionExpiry, Target: "headscale/" + headscale.ID, Generation: generation, OwnershipInventoryDigest: inventoryDigest, ClosureAuthorityDigest: closureDigest}
	result, err := preflight.EvaluateContraction(request, preflight.ContractionObservations{ExecutorUID: uint32(os.Geteuid()), InventoryComplete: true, OwnershipInventoryDigest: inventoryDigest, ClosureAuthorityDigest: closureDigest, ObservedAt: now})
	if err != nil {
		return err
	}
	intent, err := admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: lockedDocument.Revision, IntentGeneration: lockedDocument.Revision + 1, ContractionRequest: &request, ContractionPreflight: &result})
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
		freshState = next
	}
	if err := requireHeadscaleExpirySafety(freshState, headscale, intent); err != nil {
		return err
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	if err := requireHeadscaleExpiryBundle(freshState, bundle); err != nil {
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
	if execution == nil || execution.Mutation == nil || execution.Exposure == nil || execution.ActivationHost == nil || execution.Installation.Headscale == nil || execution.Installation.Headscale.DeployIntent == nil || execution.Installation.Headscale.DeployIntent.Phase != domain.HeadscaleDeployActivated {
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
	reloadAuthority, err := challengeReloadAuthorityForExposure(execution.Service, execution.Exposure)
	if err != nil {
		return jobs.Record{}, err
	}
	if err := execution.ActivationHost.CommitBootActivation(ctx, bundle, execution.Authority.Rendered, reloadAuthority); err != nil {
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
