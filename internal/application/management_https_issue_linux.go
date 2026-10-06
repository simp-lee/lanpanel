//go:build linux

package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"lanpanel/internal/safety"
	"reflect"
	"time"
)

func newManagementCertificateID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "cert_" + hex.EncodeToString(value), nil
}

// BeginManagementHTTPSIssue starts the first Management HTTPS certificate
// transaction from a pending typed configuration.
func BeginManagementHTTPSIssue(ctx context.Context) (*CertificateExecution, error) {
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
	if config == nil || config.Phase != domain.ManagementHTTPSPending || config.CertificateBundle != nil || config.ACMEBinding == "" {
		return fail(fmt.Errorf("management HTTPS issuance requires a pending configuration"))
	}
	if owner := managementHTTPSDomainOwner(installation, config.Domain); owner != "" {
		return fail(fmt.Errorf("management HTTPS domain conflicts with application resource %s", owner))
	}
	binding, err := loadManagementHTTPSBinding(config.Certificate)
	if err != nil {
		return fail(err)
	}
	bindingDigest, err := acme.BindingDigest(binding)
	if err != nil || bindingDigest != config.ACMEBinding {
		return fail(fmt.Errorf("management HTTPS issuance binding changed"))
	}
	state, err := service.safety.Read()
	if err != nil {
		return fail(err)
	}
	if state.ManagementHTTPS.ChallengePending != nil || state.ManagementHTTPS.ActiveCertificate != nil && (state.ManagementHTTPS.EntryDigest != "" || state.ManagementHTTPS.CertificateExpiry == nil) {
		return fail(fmt.Errorf("management HTTPS issuance safety authority is already occupied"))
	}
	if state.StopFence != nil || state.GlobalClose.Phase != safety.GlobalCloseNone {
		return fail(fmt.Errorf("management HTTPS issuance is blocked by safety authority"))
	}
	certificateID, err := newManagementCertificateID()
	if err != nil {
		return fail(err)
	}
	generation := state.ManagementHTTPS.GenerationSequence + 1
	if generation == 0 {
		return fail(fmt.Errorf("management HTTPS issuance generation overflow"))
	}
	bundleGeneration := uint64(1)
	if active := state.ManagementHTTPS.ActiveCertificate; active != nil {
		if state.ManagementHTTPS.EntryDigest != "" || state.ManagementHTTPS.CertificateExpiry == nil || active.Generation == ^uint64(0) {
			return fail(fmt.Errorf("management HTTPS issuance safety replacement authority is invalid"))
		}
		bundleGeneration = active.Generation + 1
	}
	configDigest, err := managementHTTPSCandidateDigest(*config)
	if err != nil {
		return fail(err)
	}
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: "management_https", PlanID: certificateID, Generation: generation, ConfigDigest: configDigest, Domains: []string{config.Domain}, Binding: binding, CertificateIdentity: certificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + certificateID, BaseMarkers: managementHTTPSBaseSnapshot(state.ManagementHTTPS)})
	if err != nil {
		return fail(err)
	}
	now := time.Now().UTC()
	operationDeadline := now.Add(10 * time.Minute)
	stageIdentity, err := identity.CertificateStageIdentityFor(certificateID)
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
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.AutomaticReconciliation, Target: "management_https", ActorIdentity: "timer/management-https-issue", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ResourceID: "management_https", PlanID: certificateID, IntentGeneration: generation, CandidateDigest: configDigest, CandidateBundle: bindingDigest, ChallengeMethod: string(binding.Method), CertificateIdentity: certificateID, Deadline: operationDeadline}, ExpectedRevision: document.Revision})
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
	if err != nil || freshInstallation.ManagementHTTPS == nil || freshInstallation.ManagementHTTPS.Phase != domain.ManagementHTTPSPending || freshInstallation.ManagementHTTPS.CertificateBundle != nil || freshInstallation.ManagementHTTPS.ACMEBinding != config.ACMEBinding {
		return cleanup(fmt.Errorf("management HTTPS pending authority changed under lock"))
	}
	intent, err := admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		return cleanup(err)
	}
	childRecord := operations.ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "lego-" + job.ID, JobID: job.ID, InstallationID: installation.InstallationID, Operation: operations.AutomaticReconciliation, Target: "management_https", IntentGeneration: intent.IntentGeneration, Profile: string(child.ProfileLego), InputDigest: bindingDigest, ArtifactDigest: bindingDigest, Deadline: operationDeadline, State: operations.ChildSubmitted, SubmittedAt: now}
	if err := admitter.BindOperationIdentity(ctx, mutation, exposure, intent.IntentGeneration, job.ID, bindingDigest); err != nil {
		return cleanup(err)
	}
	candidatePath, err := certificates.BundlePath(certificateID, bundleGeneration)
	if err != nil {
		return cleanup(err)
	}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + job.ID, JobID: job.ID, Kind: operations.JournalCertificateActivation, Operation: operations.AutomaticReconciliation, InstallationID: installation.InstallationID, Target: "management_https", Generation: intent.IntentGeneration, Deadline: operationDeadline, ArtifactDigest: bindingDigest, ChildIDs: []string{childRecord.ID}, Phase: operations.JournalPrepared, Certificate: &operations.CertificateJournalIdentity{CertificateID: certificateID, CandidateGeneration: bundleGeneration, CandidatePointer: candidatePath, PriorGeneration: 0, Challenge: prepared.Safety, StageUID: stageIdentity.UID, StageGID: stageIdentity.GID}}
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
		return cleanup(fmt.Errorf("management HTTPS issuance safety changed"))
	}
	freshBundleGeneration := uint64(1)
	if active := freshState.ManagementHTTPS.ActiveCertificate; active != nil {
		if freshState.ManagementHTTPS.EntryDigest != "" || freshState.ManagementHTTPS.CertificateExpiry == nil || active.Generation == ^uint64(0) {
			return cleanup(fmt.Errorf("management HTTPS issuance safety replacement authority is invalid"))
		}
		freshBundleGeneration = active.Generation + 1
	}
	if freshBundleGeneration != bundleGeneration {
		return cleanup(fmt.Errorf("management HTTPS issuance bundle generation changed"))
	}
	next := freshState
	next.Revision++
	next.ManagementHTTPS.GenerationSequence = generation
	next.ManagementHTTPS.ChallengePending = &prepared.Safety
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleChallenge, freshState.Revision, next, safety.TransitionProof{}); err != nil {
		return cleanup(err)
	}
	return &CertificateExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Operation: operations.AutomaticReconciliation, Revision: intent.IntentGeneration + 3, Binding: binding, Challenge: prepared, InstallationID: installation.InstallationID, Deadline: operationDeadline, BundleGeneration: bundleGeneration, Child: childRecord, StageUID: stageIdentity.UID, StageGID: stageIdentity.GID, LegoDigest: legoDigest, ManagementHTTPS: true}, nil
}

func ManagementHTTPSIssueDue(config *domain.ManagementHTTPSConfig, state safety.State) bool {
	return config != nil && config.Phase == domain.ManagementHTTPSPending && config.CertificateBundle == nil && config.ACMEBinding != "" && state.StopFence == nil && state.GlobalClose.Phase == safety.GlobalCloseNone && (state.ManagementHTTPS.ActiveCertificate == nil || state.ManagementHTTPS.EntryDigest == "" && state.ManagementHTTPS.CertificateExpiry != nil) && state.ManagementHTTPS.ChallengePending == nil
}
