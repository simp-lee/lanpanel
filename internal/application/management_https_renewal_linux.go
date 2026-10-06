//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/child"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/renewal"
	"lanpanel/internal/safety"
	"reflect"
	"time"
)

func managementHTTPSBaseSnapshot(value safety.ManagementHTTPSSafety) []safety.MarkerSnapshot {
	expiry := safety.MarkerSnapshot{Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}
	if value.CertificateExpiry != nil {
		expiry = safety.MarkerSnapshot{Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotPresent, Generation: value.CertificateExpiry.Generation}
	}
	return []safety.MarkerSnapshot{
		{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent},
		{Kind: safety.MarkerContraction, State: safety.SnapshotAbsent},
		expiry,
	}
}

// BeginManagementHTTPSRenew starts the durable local part of a Management
// HTTPS renewal. Remote ACME work is still performed only by the existing
// child/stage boundary in CertificateExecution.
func BeginManagementHTTPSRenew(ctx context.Context) (*CertificateExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*CertificateExecution, error) {
		return nil, errors.Join(cause, service.Close())
	}
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return fail(err)
	}
	config := installation.ManagementHTTPS
	if config == nil || config.Phase != domain.ManagementHTTPSActive || config.CertificateBundle == nil || config.CertificateBundle.Authority == nil {
		return fail(fmt.Errorf("management HTTPS renewal requires an active certificate authority"))
	}
	prior := *config.CertificateBundle
	binding, err := loadManagementHTTPSBinding(config.Certificate)
	if err != nil {
		return fail(err)
	}
	bindingDigest, err := acme.BindingDigest(binding)
	if err != nil || bindingDigest != config.ACMEBinding || bindingDigest != prior.BindingIdentity {
		return fail(fmt.Errorf("management HTTPS renewal binding changed"))
	}
	state, err := service.safety.Read()
	if err != nil {
		return fail(err)
	}
	decision, err := renewal.EvaluateManagementHTTPS(time.Now().UTC(), 30*24*time.Hour, config, state)
	if err != nil || decision != renewal.DecisionRenew {
		return fail(fmt.Errorf("management HTTPS certificate renewal is not due: %w", err))
	}
	generation := state.ManagementHTTPS.GenerationSequence + 1
	if generation == 0 {
		return fail(fmt.Errorf("management HTTPS renewal generation overflow"))
	}
	configDigest, err := managementHTTPSCandidateDigest(*config)
	if err != nil {
		return fail(err)
	}
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: "management_https", PlanID: prior.Authority.CertificateID, Generation: generation, ConfigDigest: configDigest, Domains: []string{config.Domain}, Binding: binding, CertificateIdentity: prior.Authority.CertificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + prior.Authority.CertificateID, BaseMarkers: managementHTTPSBaseSnapshot(state.ManagementHTTPS)})
	if err != nil {
		return fail(err)
	}
	deadline, err := time.Parse(time.RFC3339, prior.NotAfter)
	if err != nil {
		return fail(err)
	}
	now := time.Now().UTC()
	operationDeadline := now.Add(10 * time.Minute)
	if latest := deadline.Add(-5 * time.Minute); latest.Before(operationDeadline) {
		operationDeadline = latest
	}
	if !operationDeadline.After(now.Add(time.Minute)) {
		return fail(fmt.Errorf("management HTTPS renewal deadline insufficient"))
	}
	stageIdentity, err := identity.CertificateStageIdentityFor(prior.Authority.CertificateID)
	if err != nil {
		return fail(err)
	}
	legoDigest, err := loadCertificateLegoDigest()
	if err != nil {
		return fail(err)
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.CertificateRenew, Target: "management_https", ActorIdentity: "timer/management-https-renewal", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ResourceID: "management_https", PlanID: prior.Authority.CertificateID, IntentGeneration: generation, CandidateDigest: prepared.Safety.SANIdentity, CandidateBundle: bindingDigest, ChallengeMethod: string(binding.Method), CertificateIdentity: prior.Authority.CertificateID, Deadline: operationDeadline}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: service.managementHTTPSRoot() + "/locks", Owner: service.managementHTTPSOwner().UID, Group: service.managementHTTPSOwner().GID, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return fail(err)
	}
	var mutation *operations.MutationLease
	var exposure *locks.Lease
	cleanup := func(cause error) (*CertificateExecution, error) {
		return nil, errors.Join(cause, operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close())
	}
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "management_https", service.manager)
	if err != nil {
		return cleanup(err)
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return cleanup(err)
	}
	freshInstallation, err := domain.DecodeInstallation(fresh.Entries["installations/current"])
	if err != nil || freshInstallation.ManagementHTTPS == nil || freshInstallation.ManagementHTTPS.Phase != domain.ManagementHTTPSActive || freshInstallation.ManagementHTTPS.CertificateBundle == nil || !reflect.DeepEqual(*freshInstallation.ManagementHTTPS.CertificateBundle, prior) {
		return cleanup(fmt.Errorf("management HTTPS renewal authority changed under lock"))
	}
	priorPath, err := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation)
	if err != nil {
		return cleanup(err)
	}
	activeTarget, err := certificates.ObservePointer(prior.Authority.CertificateID)
	if err != nil || activeTarget != priorPath || certificates.VerifyBundleIdentity(prior.Authority.CertificateID, prior.Generation, certificateBundleIdentity(prior)) != nil {
		return cleanup(fmt.Errorf("management HTTPS prior certificate lineage changed under lock"))
	}
	intent, err := admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		return cleanup(err)
	}
	childRecord := operations.ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "lego-" + job.ID, JobID: job.ID, InstallationID: installation.InstallationID, Operation: operations.CertificateRenew, Target: "management_https", IntentGeneration: intent.IntentGeneration, Profile: string(child.ProfileLego), InputDigest: bindingDigest, ArtifactDigest: bindingDigest, Deadline: operationDeadline, State: operations.ChildSubmitted, SubmittedAt: now}
	if err := admitter.BindOperationIdentity(ctx, mutation, exposure, intent.IntentGeneration, job.ID, bindingDigest); err != nil {
		return cleanup(err)
	}
	candidatePath, err := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation+1)
	if err != nil {
		return cleanup(err)
	}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + job.ID, JobID: job.ID, Kind: operations.JournalCertificateActivation, Operation: operations.CertificateRenew, InstallationID: installation.InstallationID, Target: "management_https", Generation: intent.IntentGeneration, Deadline: operationDeadline, ArtifactDigest: bindingDigest, ChildIDs: []string{childRecord.ID}, Phase: operations.JournalPrepared, Certificate: &operations.CertificateJournalIdentity{CertificateID: prior.Authority.CertificateID, PriorGeneration: prior.Generation, CandidateGeneration: prior.Generation + 1, PriorPointer: priorPath, CandidatePointer: candidatePath, PriorFingerprint: prior.Fingerprint, PriorBundleIdentity: certificateBundleIdentity(prior), Challenge: prepared.Safety, StageUID: stageIdentity.UID, StageGID: stageIdentity.GID}}
	current, err := service.normal.Read()
	if err != nil {
		return cleanup(err)
	}
	if err := admitter.PutJournal(ctx, mutation, exposure, current.Revision, journal, true); err != nil {
		return cleanup(err)
	}
	if err := operations.ReleaseExposure(mutation, exposure); err != nil {
		return cleanup(err)
	}
	mutation, exposure = nil, nil
	admission, err = service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return cleanup(err)
	}
	reserveErr := admitter.ReserveChild(ctx, admission, intent.IntentGeneration+2, childRecord)
	releaseErr = admission.Release()
	if reserveErr != nil || releaseErr != nil {
		return cleanup(errors.Join(reserveErr, releaseErr))
	}
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "management_https", service.manager)
	if err != nil {
		return cleanup(err)
	}
	freshState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return cleanup(err)
	}
	if freshState.ManagementHTTPS.GenerationSequence+1 != generation || !reflect.DeepEqual(managementHTTPSBaseSnapshot(freshState.ManagementHTTPS), prepared.Safety.BaseMarkers) {
		return cleanup(fmt.Errorf("management HTTPS renewal safety changed"))
	}
	next := freshState
	next.Revision++
	next.ManagementHTTPS.GenerationSequence = generation
	next.ManagementHTTPS.ChallengePending = &prepared.Safety
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleChallenge, freshState.Revision, next, safety.TransitionProof{}); err != nil {
		return cleanup(err)
	}
	priorCopy := prior
	return &CertificateExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Operation: operations.CertificateRenew, Revision: intent.IntentGeneration + 3, Binding: binding, Challenge: prepared, InstallationID: installation.InstallationID, Deadline: operationDeadline, BundleGeneration: prior.Generation + 1, PriorCertificate: &priorCopy, Child: childRecord, StageUID: stageIdentity.UID, StageGID: stageIdentity.GID, LegoDigest: legoDigest, ManagementHTTPS: true}, nil
}
