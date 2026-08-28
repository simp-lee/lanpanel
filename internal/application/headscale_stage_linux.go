//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/child"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type HeadscaleDeployExecution struct {
	Service             *FixedService
	Admitter            *operations.Admitter
	MutationSet         *operations.MutationSet
	Mutation            *operations.MutationLease
	Exposure            *locks.Lease
	JobID               string
	Revision            uint64
	Plan                plans.Plan
	Installation        domain.Installation
	Authority           HeadscaleDeployAuthority
	Local               *control.Execution
	Host                control.CandidateHost
	CertificateStaged   bool
	CertificateIdentity certificates.BundleIdentity
	ClosureUncertain    bool
	Challenge           challenge.Prepared
	Child               operations.ChildRecord
	StageUID            uint32
	StageGID            uint32
	LegoDigest          string
	DNSLocks            *acme.OwnerLocks
	DNSPreflight        *acme.DNSPreflight
}

// BeginHeadscaleDeploy is an internal application boundary. S17C registers the
// helper/UI route only after expiry/startup contraction owners are available.
func BeginHeadscaleDeploy(ctx context.Context, actor Actor, payload HeadscaleDeployPayload) (*HeadscaleDeployExecution, error) {
	if payload.PlanID == "" || payload.Confirmation != "deploy" {
		return nil, fmt.Errorf("headscale deploy confirmation is invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*HeadscaleDeployExecution, error) { _ = service.Close(); return nil, cause }
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	plan, err := service.ReadPlan(payload.PlanID)
	if err != nil || plan.Operation != string(domain.OperationHeadscaleControlDeploy) || plan.Target.Kind != plans.TargetHeadscale || plan.Target.ID == "" || plan.ActorIdentity != authority {
		return fail(fmt.Errorf("headscale deploy Plan authority is invalid"))
	}
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return fail(err)
	}
	binding, err := loadHeadscaleCertificateBinding(payload.Certificate)
	if err != nil {
		return fail(err)
	}
	certificateID, plannedDigest, err := headscalePlanCandidateEvidence(plan)
	if err != nil {
		return fail(err)
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return fail(err)
	}
	preflightRequest, preflightResult, err := evaluateHeadscaleDeployPreflight(ctx, installed, installation.InstallationID, installation.Headscale.ID, installation.Headscale.ControlDomain, installation.Headscale.Database.Generation)
	if err != nil {
		return fail(err)
	}
	plannedSafety, err := service.safety.Read()
	if err != nil {
		return fail(err)
	}
	candidateAuthority, err := buildHeadscaleDeployAuthority(installation, binding, certificateID, authority, preflightRequest, preflightResult, plannedSafety, preflightResult.ObservedAt)
	if err != nil {
		return fail(err)
	}
	candidateDigest, err := control.Digest(candidateAuthority.Rendered.Candidate)
	if err != nil || candidateDigest != plannedDigest || !headscaleDeployPlanMatches(plan, candidateAuthority) {
		return fail(fmt.Errorf("headscale deploy candidate changed after Plan"))
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	safetyBinding := operations.SafetyBinding{ResourceID: "headscale", PlanID: plan.ID, IntentGeneration: candidateAuthority.Rendered.Candidate.Generation, CandidateDigest: candidateAuthority.Rendered.Candidate.ConfigDigest, CandidateBundle: candidateDigest, ChallengeMethod: string(binding.Method), CertificateIdentity: certificateID, ACMEBinding: candidateAuthority.Rendered.Candidate.CertificateBinding, Deadline: plan.ExpiresAt}
	target := string(plans.TargetHeadscale) + "/" + freshInstallationID(installation)
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.HeadscaleDeploy, Target: target, ActorIdentity: authority, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: safetyBinding, HeadscaleDeploy: &operations.HeadscaleDeployBinding{Candidate: candidateAuthority.Rendered.Candidate, PreflightRequest: preflightRequest, PreflightResult: preflightResult}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	rejectReserved := func(cause error) (*HeadscaleDeployExecution, error) {
		lease, acquireErr := service.manager.Acquire(context.WithoutCancel(ctx), locks.MutationAdmission)
		var document persist.Document
		var readErr, rejectErr, releaseErr error
		if acquireErr == nil {
			document, readErr = service.normal.Read()
		}
		if acquireErr == nil && readErr == nil {
			rejectErr = admitter.RejectReservation(context.WithoutCancel(ctx), lease, document.Revision, job.ID, "headscale_deploy_revalidation_failed")
		}
		if lease != nil {
			releaseErr = lease.Release()
		}
		return fail(errors.Join(cause, readErr, acquireErr, rejectErr, releaseErr))
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
	consumed := false
	cleanup := func(cause error) (*HeadscaleDeployExecution, error) {
		release := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		cause = errors.Join(cause, release, closeErr)
		if !consumed {
			return rejectReserved(cause)
		}
		return fail(cause)
	}
	fresh, err := service.normal.Read()
	if err != nil || fresh.Revision != document.Revision+1 {
		return cleanup(fmt.Errorf("headscale deploy authority changed after admission"))
	}
	freshInstallation, err := loadHeadscaleInstallation(fresh)
	if err != nil || !reflect.DeepEqual(freshInstallation.Headscale, installation.Headscale) {
		return cleanup(fmt.Errorf("headscale identity changed after admission"))
	}
	freshRequest, freshResult, err := evaluateHeadscaleDeployPreflight(ctx, installed, freshInstallation.InstallationID, freshInstallation.Headscale.ID, freshInstallation.Headscale.ControlDomain, freshInstallation.Headscale.Database.Generation)
	if err != nil || !reflect.DeepEqual(freshRequest, preflightRequest) {
		return cleanup(fmt.Errorf("headscale deploy preflight policy changed"))
	}
	if err := preflight.RequireExpansionResultForRequest(freshResult, freshRequest, freshResult.ObservedAt); err != nil {
		return cleanup(err)
	}
	freshBinding, err := loadHeadscaleCertificateBinding(payload.Certificate)
	if err != nil || !reflect.DeepEqual(freshBinding, binding) {
		return cleanup(fmt.Errorf("headscale ACME authority changed after Plan"))
	}
	binding = freshBinding
	freshSafety, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return cleanup(err)
	}
	freshAuthority, err := buildHeadscaleDeployAuthority(freshInstallation, binding, certificateID, authority, freshRequest, freshResult, freshSafety, freshResult.ObservedAt)
	if err != nil || !headscaleDeployPlanMatches(plan, freshAuthority) {
		return cleanup(fmt.Errorf("headscale deploy prerequisites changed after Plan"))
	}
	candidateAuthority = freshAuthority
	if err := managedheadscale.ValidateCommittedInitialization(freshInstallation.InstallationID, *freshInstallation.Headscale, installed, managedheadscale.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}); err != nil {
		return cleanup(err)
	}
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		return cleanup(err)
	}
	consumed = true
	applied, err := control.AppliedIdentity(candidateAuthority.Rendered.Candidate)
	if err != nil {
		return cleanup(err)
	}
	domainIntent := domain.HeadscaleDeployIntent{Generation: applied.Generation, PlanID: plan.ID, JobID: job.ID, Phase: domain.HeadscaleDeployPrepared, PreflightDigest: freshResult.RequestDigest, CertificateBinding: candidateAuthority.Rendered.Candidate.CertificateBinding, Candidate: applied}
	if freshInstallation.Headscale.Applied != nil {
		prior := *freshInstallation.Headscale.Applied
		domainIntent.Prior = &prior
	}
	if err := admitter.CommitHeadscaleDeployBegin(ctx, mutation, exposure, intent.IntentGeneration, job.ID, operations.HeadscaleDeployBeginCommit{HeadscaleID: freshInstallation.Headscale.ID, Intent: domainIntent}); err != nil {
		return cleanup(err)
	}
	return &HeadscaleDeployExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: intent.IntentGeneration + 1, Plan: plan, Installation: freshInstallation, Authority: candidateAuthority}, nil
}

// PrepareLocalCandidate journals and probes the database/private service while
// the exposure lock prevents competing graph changes, then releases all local
// locks before the remote ACME wait.
func headscaleDeployPlanMatches(plan plans.Plan, authority HeadscaleDeployAuthority) bool {
	expected := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: append([]plans.Evidence(nil), plan.Evidence...)}
	actual := plans.Binding{Operation: authority.Spec.Operation, Target: authority.Spec.Target, ActorIdentity: authority.Spec.ActorIdentity, Config: authority.Spec.Config, Applied: authority.Spec.Applied, Evidence: append([]plans.Evidence(nil), authority.Spec.Evidence...)}
	for index := range actual.Evidence {
		if !strings.HasPrefix(actual.Evidence[index].Kind, preflight.ExpansionEvidencePrefix) {
			continue
		}
		for _, planned := range expected.Evidence {
			if planned.Kind == actual.Evidence[index].Kind && planned.Identity == actual.Evidence[index].Identity && planned.Generation == actual.Evidence[index].Generation {
				actual.Evidence[index].Digest = planned.Digest
			}
		}
	}
	return plans.SameBindingIdentity(expected, actual)
}

func freshInstallationID(installation domain.Installation) string {
	if installation.Headscale == nil {
		return ""
	}
	return installation.Headscale.ID
}

func (execution *HeadscaleDeployExecution) PrepareLocalCandidate(ctx context.Context, host control.CandidateHost) (issued control.IssueRequest, returnErr error) {
	if execution == nil || execution.Mutation == nil || execution.Exposure == nil {
		return control.IssueRequest{}, fmt.Errorf("headscale deploy local authority is unavailable")
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	local, err := control.Prepare(ctx, store, host, control.StageRequest{InstallationID: execution.Installation.InstallationID, JobID: execution.JobID, PlanID: execution.Plan.ID, IntentGeneration: execution.Revision - 1, Rendered: execution.Authority.Rendered, Preflight: execution.Authority.Preflight, PreflightResult: execution.Authority.Result})
	if err != nil {
		return control.IssueRequest{}, err
	}
	execution.Local = local
	execution.Host = host
	cleanup := true
	defer func() {
		if cleanup && returnErr != nil {
			returnErr = errors.Join(returnErr, execution.removeFailedChallenge(context.WithoutCancel(ctx), host))
		}
	}()
	journal := local.Journal()
	if journal.Database == nil || journal.Phase != control.PhaseCertificatePending {
		return control.IssueRequest{}, fmt.Errorf("headscale local candidate did not reach certificate wait")
	}
	if err := execution.Admitter.CommitHeadscaleDeployStaged(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.HeadscaleDeployStagedCommit{HeadscaleID: execution.Installation.Headscale.ID, InitializedDigest: journal.Database.InitializedDigest}); err != nil {
		return control.IssueRequest{}, err
	}
	execution.Revision++
	bindingDigest, err := acme.BindingDigest(execution.Authority.Binding)
	if err != nil || bindingDigest != execution.Authority.Rendered.Candidate.CertificateBinding {
		return control.IssueRequest{}, fmt.Errorf("headscale ACME binding changed before challenge")
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil || state.Headscale.GenerationSequence+1 != execution.Authority.Rendered.Candidate.Generation || state.Headscale.ChallengePending != nil || state.Headscale.Reactivating != nil {
		return control.IssueRequest{}, fmt.Errorf("headscale challenge safety generation changed")
	}
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: "headscale", PlanID: execution.Plan.ID, Generation: execution.Authority.Rendered.Candidate.Generation, ConfigDigest: execution.Authority.Rendered.Candidate.ConfigDigest, Domains: []string{execution.Installation.Headscale.ControlDomain}, Binding: execution.Authority.Binding, CertificateIdentity: execution.Authority.Rendered.Candidate.CertificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + execution.Authority.Rendered.Candidate.CertificateID, BaseMarkers: headscaleBaseSnapshot(state.Headscale)})
	if err != nil {
		return control.IssueRequest{}, err
	}
	execution.Challenge = prepared
	stageIdentity, err := identity.CertificateStageIdentityFor(execution.Authority.Rendered.Candidate.CertificateID)
	if err != nil {
		return control.IssueRequest{}, err
	}
	execution.StageUID, execution.StageGID = stageIdentity.UID, stageIdentity.GID
	identityDocument, err := execution.Service.normal.Read()
	if err != nil || identityDocument.Revision != execution.Revision || validateCertificateStageIdentity(identityDocument, stageIdentity) != nil {
		return control.IssueRequest{}, fmt.Errorf("headscale certificate stage identity is unavailable")
	}
	if err := execution.Admitter.BindOperationIdentity(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, bindingDigest); err != nil {
		return control.IssueRequest{}, err
	}
	execution.Revision++
	childID := "lego-" + execution.JobID
	childRecord := operations.ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: childID, JobID: execution.JobID, InstallationID: execution.Installation.InstallationID, Operation: operations.HeadscaleDeploy, Target: "headscale/" + execution.Installation.Headscale.ID, IntentGeneration: execution.Revision - 3, Profile: string(child.ProfileLego), InputDigest: bindingDigest, ArtifactDigest: bindingDigest, Deadline: execution.Plan.ExpiresAt, State: operations.ChildSubmitted, SubmittedAt: time.Now().UTC()}
	execution.Child = childRecord
	candidatePath, err := certificates.BundlePath(execution.Authority.Rendered.Candidate.CertificateID, 1)
	if err != nil {
		return control.IssueRequest{}, err
	}
	certificateJournal := &operations.CertificateJournalIdentity{CertificateID: execution.Authority.Rendered.Candidate.CertificateID, CandidateGeneration: 1, CandidatePointer: candidatePath, Challenge: execution.Challenge.Safety, StageUID: stageIdentity.UID, StageGID: stageIdentity.GID}
	operationJournal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + execution.JobID, JobID: execution.JobID, Kind: operations.JournalCertificateActivation, Operation: operations.HeadscaleDeploy, InstallationID: execution.Installation.InstallationID, Target: childRecord.Target, Generation: childRecord.IntentGeneration, Deadline: execution.Plan.ExpiresAt, ArtifactDigest: bindingDigest, ChildIDs: []string{childID}, Phase: operations.JournalPrepared, Certificate: certificateJournal}
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, operationJournal, true); err != nil {
		return control.IssueRequest{}, err
	}
	execution.Revision++
	if err := operations.ReleaseExposure(execution.Mutation, execution.Exposure); err != nil {
		return control.IssueRequest{}, err
	}
	execution.Mutation, execution.Exposure = nil, nil
	admission, err := execution.Service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return control.IssueRequest{}, err
	}
	reserveErr := execution.Admitter.ReserveChild(ctx, admission, execution.Revision, childRecord)
	releaseErr := admission.Release()
	if reserveErr != nil || releaseErr != nil {
		return control.IssueRequest{}, errors.Join(reserveErr, releaseErr)
	}
	execution.Revision++
	mutation, exposure, err := execution.MutationSet.AcquireExposure(ctx, childRecord.Target, execution.Service.manager)
	if err != nil {
		return control.IssueRequest{}, err
	}
	execution.Mutation, execution.Exposure = mutation, exposure
	freshState, err := execution.Service.safety.ReadForRecovery(exposure)
	if err != nil || freshState.Headscale.GenerationSequence+1 != prepared.Safety.Generation || freshState.Headscale.ChallengePending != nil || freshState.Headscale.Reactivating != nil {
		return control.IssueRequest{}, fmt.Errorf("headscale challenge safety authority changed")
	}
	next := freshState
	next.Revision++
	next.Headscale.GenerationSequence = prepared.Safety.Generation
	next.Headscale.ChallengePending = &prepared.Safety
	if _, err := execution.Service.safety.Commit(ctx, exposure, safety.RoleChallenge, freshState.Revision, next, safety.TransitionProof{}); err != nil {
		return control.IssueRequest{}, err
	}
	if execution.Authority.Binding.Method == acme.ChallengeHTTP01 {
		ownershipAuthority, ownershipErr := fixedOwnershipAuthority(execution.Service.ownership)
		if ownershipErr != nil {
			return control.IssueRequest{}, ownershipErr
		}
		host, err := activation.NewFixedHost()
		if err != nil {
			return control.IssueRequest{}, err
		}
		authority := activation.ChallengeReloadAuthority{Safety: next, Installation: execution.Installation, Ownership: ownershipAuthority, ObservedAt: time.Now().UTC()}
		if _, err := host.ActivateChallenge(ctx, prepared, authority); err != nil {
			return control.IssueRequest{}, err
		}
	}
	_, remoteErr := execution.Admitter.EnterRemoteWait(ctx, mutation, exposure, execution.Revision, execution.JobID)
	execution.Mutation, execution.Exposure = nil, nil
	if remoteErr != nil {
		return control.IssueRequest{}, remoteErr
	}
	execution.Revision++
	if execution.Authority.Binding.Method == acme.ChallengeDNS01 {
		ownerLocks, err := acme.AcquireOwnerLocks(ctx, fixedRoot+"/locks", execution.Authority.Binding.Provider, execution.Authority.Binding.Zone, prepared.Owners, prepared.Safety.OwnerLock)
		if err != nil {
			return control.IssueRequest{}, err
		}
		dnsPreflight, err := acme.PreflightDNS01(ctx, acme.NetDNSObserver{}, execution.Authority.Binding.Zone, prepared.Owners)
		if err != nil {
			_ = ownerLocks.Close()
			return control.IssueRequest{}, err
		}
		execution.DNSLocks, execution.DNSPreflight = ownerLocks, &dnsPreflight
	}
	execution.LegoDigest, err = loadCertificateLegoDigest()
	if err != nil {
		return control.IssueRequest{}, err
	}
	issued, err = local.IssueRequest()
	if err != nil {
		return control.IssueRequest{}, err
	}
	cleanup = false
	return issued, nil
}

// RunFirstCertificate performs the one bounded remote wait for the initiating
// authenticated request. Startup recovery has no path to this method.
func (execution *HeadscaleDeployExecution) RunFirstCertificate(ctx context.Context, host control.CandidateHost) (issuedIdentity certificates.Identity, returnErr error) {
	if execution == nil || execution.Local == nil || execution.Mutation != nil || execution.Exposure != nil || execution.Child.ID == "" {
		return certificates.Identity{}, fmt.Errorf("headscale first certificate remote authority is unavailable")
	}
	cleanup := true
	defer func() {
		if cleanup && returnErr != nil {
			returnErr = errors.Join(returnErr, execution.removeFailedChallenge(context.WithoutCancel(ctx), host))
		}
	}()
	issueRequest, err := execution.Local.IssueRequest()
	if err != nil {
		return certificates.Identity{}, err
	}
	stage, err := acme.PrepareStage(ctx, issueRequest.CertificateID, execution.Authority.Binding, execution.StageUID, execution.StageGID)
	if err != nil {
		return certificates.Identity{}, err
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{CertificateStage: child.Identity{UID: execution.StageUID, GID: execution.StageGID, Chroot: stage.Root}})
	if err != nil {
		return certificates.Identity{}, errors.Join(err, stage.Close())
	}
	remoteCtx, cancel := context.WithDeadline(ctx, execution.Plan.ExpiresAt)
	result, runErr := acme.RunLego(remoteCtx, launcher, acme.IssueRequest{CertificateID: issueRequest.CertificateID, Domains: []string{issueRequest.Domain}, Binding: execution.Authority.Binding, UID: execution.StageUID, GID: execution.StageGID, Chroot: stage.Root, ExecutableDigest: execution.LegoDigest})
	cancel()
	runErr = errors.Join(runErr, verifyManagedACMEBinding(execution.Authority.Binding))
	if child.CgroupClosureUnproved(runErr) {
		execution.ClosureUncertain = true
		cleanup = false
		return certificates.Identity{}, runErr
	}
	runErr = errors.Join(runErr, stage.Close())
	if execution.DNSPreflight != nil {
		cleanupErr := acme.VerifyDNS01Cleanup(ctx, acme.NetDNSObserver{}, *execution.DNSPreflight)
		runErr = errors.Join(runErr, cleanupErr)
		if cleanupErr == nil {
			execution.DNSPreflight = nil
			if execution.DNSLocks != nil {
				runErr = errors.Join(runErr, execution.DNSLocks.Close())
				execution.DNSLocks = nil
			}
		}
	}
	if runErr != nil {
		return certificates.Identity{}, runErr
	}
	material, err := loadHeadscaleIssuedMaterial(issueRequest, execution.StageUID, execution.StageGID, execution.Authority.Binding.DirectoryURL, time.Now().UTC())
	if err != nil {
		return certificates.Identity{}, err
	}
	identity, err := certificates.StageIssued(ctx, certificates.FixedBundlesRoot, issueRequest.CertificateID, 1, issueRequest.BindingDigest, material, filetxn.Owner{UID: execution.StageUID, GID: execution.StageGID}, time.Now().UTC(), func(identity certificates.Identity) error { return execution.authorizeStagedCertificate(ctx, identity) })
	if err != nil {
		return certificates.Identity{}, err
	}
	cleanup = false
	if err := execution.StageIssuedCertificate(ctx, issueRequest, identity, host, result); err != nil {
		return certificates.Identity{}, err
	}
	return identity, nil
}

func (execution *HeadscaleDeployExecution) authorizeStagedCertificate(ctx context.Context, identity certificates.Identity) error {
	if execution == nil || certificates.ValidateIdentity(identity) != nil || identity.ID != execution.Authority.Rendered.Candidate.CertificateID || identity.Generation != 1 || identity.BindingIdentity != execution.Authority.Rendered.Candidate.CertificateBinding {
		return fmt.Errorf("headscale staged certificate authorization identity invalid")
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return err
	}
	if execution.Mutation == nil && execution.Exposure == nil {
		_, execution.Mutation, execution.Exposure, err = execution.Admitter.Reenter(ctx, execution.MutationSet, execution.Service.manager, document.Revision, execution.JobID)
		if err != nil {
			return err
		}
		execution.Revision = document.Revision + 1
		document, err = execution.Service.normal.Read()
	}
	if err != nil || document.Revision != execution.Revision {
		return fmt.Errorf("headscale staged certificate authorization revision changed: %w", err)
	}
	raw, present := document.Entries["journals/certificate-"+execution.JobID]
	var journal operations.JournalRecord
	if !present || json.Unmarshal(raw, &journal) != nil || journal.Phase != operations.JournalPrepared || journal.Certificate == nil || journal.Certificate.CandidateFingerprint != "" || journal.Certificate.CandidateBundleIdentity != (certificates.BundleIdentity{}) || !reflect.DeepEqual(journal.Certificate.Challenge, execution.Challenge.Safety) {
		return fmt.Errorf("headscale staged certificate journal authority changed")
	}
	journal.Certificate.CandidateFingerprint = identity.Fingerprint
	journal.Certificate.CandidateBundleIdentity = certificates.BundleIdentityFor(identity)
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return err
	}
	execution.Revision++
	execution.CertificateIdentity = certificates.BundleIdentityFor(identity)
	return nil
}

// StageIssuedCertificate accepts only the same request's verified terminal
// result. It advances to a complete non-applied reactivation candidate but does
// not load the control site, activate the certificate pointer, or expose STUN.
func (execution *HeadscaleDeployExecution) StageIssuedCertificate(ctx context.Context, request control.IssueRequest, identity certificates.Identity, host control.CandidateHost, remote ...acme.IssueResult) (returnErr error) {
	if execution == nil || (execution.Mutation == nil) != (execution.Exposure == nil) {
		return fmt.Errorf("headscale remote result phase is invalid")
	}
	if err := verifyManagedACMEBinding(execution.Authority.Binding); err != nil {
		return err
	}
	if certificates.ValidateIdentity(identity) == nil && identity.ID == execution.Authority.Rendered.Candidate.CertificateID && identity.Generation == 1 {
		execution.CertificateIdentity = certificates.BundleIdentityFor(identity)
	}
	cleanup := true
	defer func() {
		if cleanup && returnErr != nil {
			returnErr = errors.Join(returnErr, execution.removeFailedChallenge(context.WithoutCancel(ctx), host))
		}
	}()
	document, err := execution.Service.normal.Read()
	if err != nil {
		return err
	}
	mutation, exposure := execution.Mutation, execution.Exposure
	if mutation == nil {
		_, mutation, exposure, err = execution.Admitter.Reenter(ctx, execution.MutationSet, execution.Service.manager, document.Revision, execution.JobID)
		if err != nil {
			return err
		}
		execution.Mutation, execution.Exposure = mutation, exposure
		execution.Revision = document.Revision + 1
	} else if document.Revision != execution.Revision {
		return fmt.Errorf("headscale staged certificate revision changed")
	}
	if execution.Child.ID == "" {
		return fmt.Errorf("headscale issuer child authority is missing")
	}
	terminalChild := execution.Child
	now := time.Now().UTC()
	terminalChild.State = operations.ChildTerminal
	terminalChild.TerminalAt = &now
	terminalChild.Outcome = operations.ChildSucceeded
	resultIdentity := identity.Fingerprint
	if len(remote) == 1 {
		resultIdentity = remote[0].StdoutDigest + "\x00" + remote[0].StderrDigest
	} else if len(remote) != 0 {
		return fmt.Errorf("headscale issuer result is ambiguous")
	}
	resultSum := sha256.Sum256([]byte(resultIdentity))
	terminalChild.ResultDigest = "sha256:" + hex.EncodeToString(resultSum[:])
	if err := execution.Admitter.TransitionChild(ctx, mutation, exposure, execution.Revision, terminalChild); err != nil {
		return err
	}
	execution.Revision++
	candidatePath, err := certificates.BundlePath(identity.ID, identity.Generation)
	if err != nil {
		return err
	}
	operationJournal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + execution.JobID, JobID: execution.JobID, Kind: operations.JournalCertificateActivation, Operation: operations.HeadscaleDeploy, InstallationID: execution.Installation.InstallationID, Target: terminalChild.Target, Generation: terminalChild.IntentGeneration, Deadline: execution.Plan.ExpiresAt, ArtifactDigest: request.BindingDigest, ChildIDs: []string{terminalChild.ID}, Phase: operations.JournalActive, Certificate: &operations.CertificateJournalIdentity{CertificateID: identity.ID, CandidateGeneration: identity.Generation, CandidatePointer: candidatePath, CandidateFingerprint: identity.Fingerprint, CandidateBundleIdentity: certificates.BundleIdentityFor(identity), Challenge: execution.Challenge.Safety, StageUID: execution.StageUID, StageGID: execution.StageGID}}
	if err := execution.Admitter.PutJournal(ctx, mutation, exposure, execution.Revision, operationJournal, false); err != nil {
		return err
	}
	execution.Revision++
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	local, err := control.ResumeLocal(ctx, store, host, execution.Authority.Rendered)
	if err != nil {
		return err
	}
	if err := local.StageCertificate(ctx, request, identity); err != nil {
		return err
	}
	if execution.Authority.Binding.Method == acme.ChallengeHTTP01 {
		nginxHost, err := activation.NewFixedHost()
		if err != nil {
			return err
		}
		if _, err := nginxHost.RemoveChallenge(ctx, execution.Challenge); err != nil {
			return err
		}
		if err := acme.VerifyWebrootEmpty(identity.ID, execution.StageUID, execution.StageGID); err != nil {
			return err
		}
	}
	if err := errors.Join(acme.RemoveStage(identity.ID, execution.StageUID, execution.StageGID), acme.RemoveWebroot(identity.ID, execution.StageUID, execution.StageGID)); err != nil {
		return err
	}
	freshSafety, err := execution.Service.safety.ReadForRecovery(exposure)
	if err != nil || freshSafety.Headscale.ChallengePending == nil || !challenge.Matches(*freshSafety.Headscale.ChallengePending, execution.Challenge) || freshSafety.Headscale.Reactivating != nil || freshSafety.StopFence != nil {
		return fmt.Errorf("headscale challenge authority changed before certificate handoff")
	}
	candidateDigest, err := control.Digest(execution.Authority.Rendered.Candidate)
	if err != nil {
		return err
	}
	next := freshSafety
	next.Revision++
	next.Headscale.ChallengePending = nil
	next.Headscale.Reactivating = &safety.HeadscaleReactivating{Generation: execution.Challenge.Safety.Generation, PriorGeneration: execution.Challenge.Safety.Generation - 1, PlanID: execution.Plan.ID, ControlGeneration: execution.Authority.Rendered.Candidate.Generation, CertificateGeneration: identity.Generation, CertificateFingerprint: identity.Fingerprint, CandidateDigest: execution.Authority.Rendered.Candidate.ConfigDigest, CandidateBundle: candidateDigest, BaseMarkers: append([]safety.MarkerSnapshot(nil), execution.Challenge.Safety.BaseMarkers...), CertificateUntil: identity.NotAfter, CertificateLastTrustedWall: identity.LastTrustedWall}
	if _, err := execution.Service.safety.Commit(ctx, exposure, safety.RoleCertificateHandoff, freshSafety.Revision, next, safety.TransitionProof{}); err != nil {
		return err
	}
	if err := execution.Admitter.CommitHeadscaleCertificateStaged(ctx, mutation, exposure, execution.Revision, execution.JobID, operations.HeadscaleCertificateStagedCommit{HeadscaleID: execution.Installation.Headscale.ID, Fingerprint: identity.Fingerprint}); err != nil {
		return err
	}
	execution.Revision++
	execution.Child = terminalChild
	execution.Local = local
	execution.CertificateStaged = true
	cleanup = false
	return nil
}

func loadHeadscaleIssuedMaterial(request control.IssueRequest, uid, gid uint32, directoryURL string, now time.Time) (certificates.IssuedMaterial, error) {
	base := filepath.Join("/var/lib/lanpanel/certificates/chroot", request.CertificateID, "work", "certificates")
	certificate, err := readHeadscaleStageFile(filepath.Join(base, request.Domain+".crt"), uid, gid, 0o644)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	issuer, err := readHeadscaleStageFile(filepath.Join(base, request.Domain+".issuer.crt"), uid, gid, 0o644)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	key, err := readHeadscaleStageFile(filepath.Join(base, request.Domain+".key"), uid, gid, 0o600)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	chain, err := certificates.JoinLegoChain(certificate, issuer)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	return certificates.ValidateIssued(chain, key, []string{request.Domain}, now, directoryURL)
}

func readHeadscaleStageFile(path string, uid, gid uint32, maximumMode uint32) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("headscale certificate stage descriptor unavailable")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777&^maximumMode != 0 || stat.Size <= 0 || stat.Size > 1<<20 {
		return nil, fmt.Errorf("headscale certificate stage metadata is unsafe")
	}
	data := make([]byte, stat.Size)
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || stat.Dev != after.Dev || stat.Ino != after.Ino || stat.Size != after.Size || stat.Mtim != after.Mtim {
		return nil, fmt.Errorf("headscale certificate stage changed during read")
	}
	return data, nil
}

func (execution *HeadscaleDeployExecution) removeFailedChallenge(ctx context.Context, host control.CandidateHost) error {
	if execution == nil {
		return fmt.Errorf("headscale failed challenge authority unavailable")
	}
	var errs []error
	if execution.DNSPreflight != nil {
		cleanupErr := acme.VerifyDNS01Cleanup(ctx, acme.NetDNSObserver{}, *execution.DNSPreflight)
		if cleanupErr != nil {
			errs = append(errs, cleanupErr)
		} else {
			execution.DNSPreflight = nil
			if execution.DNSLocks != nil {
				if err := execution.DNSLocks.Close(); err != nil {
					errs = append(errs, err)
				} else {
					execution.DNSLocks = nil
				}
			}
		}
	}
	if execution.Mutation == nil && execution.Exposure == nil {
		document, err := execution.Service.normal.Read()
		if err == nil {
			_, execution.Mutation, execution.Exposure, err = execution.Admitter.Reenter(ctx, execution.MutationSet, execution.Service.manager, document.Revision, execution.JobID)
			execution.Revision = document.Revision + 1
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if execution.Mutation != nil && execution.Exposure != nil {
		if execution.Child.ID != "" && execution.Child.State != operations.ChildTerminal {
			terminal := execution.Child
			now := time.Now().UTC()
			terminal.State, terminal.TerminalAt, terminal.Outcome = operations.ChildTerminal, &now, operations.ChildUnknown
			terminal.ResultDigest = headscaleFailureDigest("headscale-first-certificate-unknown")
			if err := execution.Admitter.TransitionChild(ctx, execution.Mutation, execution.Exposure, execution.Revision, terminal); err != nil {
				errs = append(errs, err)
			} else {
				execution.Revision++
				execution.Child = terminal
			}
		}
		if execution.Authority.Binding.Method == acme.ChallengeHTTP01 && execution.Challenge.Entry != nil {
			nginxHost, err := activation.NewFixedHost()
			if err == nil {
				_, err = nginxHost.RemoveChallenge(ctx, execution.Challenge)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	if host != nil {
		if err := host.StopPrivateService(ctx, execution.Authority.Rendered.Candidate); err != nil {
			errs = append(errs, err)
		}
	}
	if err := acme.RemoveStage(execution.Authority.Rendered.Candidate.CertificateID, execution.StageUID, execution.StageGID); err != nil {
		errs = append(errs, err)
	}
	if err := acme.RemoveWebroot(execution.Authority.Rendered.Candidate.CertificateID, execution.StageUID, execution.StageGID); err != nil {
		errs = append(errs, err)
	}
	if execution.StageUID != 0 && execution.StageGID != 0 {
		if err := certificates.RemoveInactiveBundle(execution.Authority.Rendered.Candidate.CertificateID, 1, execution.CertificateIdentity, execution.StageUID, execution.StageGID); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 && execution.Exposure != nil {
		state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
		changed := false
		if err == nil && state.Headscale.ChallengePending != nil {
			if !challenge.Matches(*state.Headscale.ChallengePending, execution.Challenge) {
				err = fmt.Errorf("headscale challenge owner changed during cleanup")
			} else {
				changed = true
			}
		}
		if err == nil && state.Headscale.Reactivating != nil {
			if state.Headscale.Reactivating.PlanID != execution.Plan.ID || state.Headscale.Reactivating.Generation != execution.Challenge.Safety.Generation {
				err = fmt.Errorf("headscale reactivation owner changed during cleanup")
			} else {
				changed = true
			}
		}
		if err == nil && changed {
			store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
			journal, contractErr := store.Read()
			if contractErr == nil {
				_, contractErr = store.Contract(ctx, journal)
			}
			if contractErr == nil {
				document, readErr := execution.Service.normal.Read()
				contractErr = readErr
				if readErr == nil {
					contractErr = execution.Admitter.ContractHeadscaleDeployChallenge(ctx, execution.Mutation, execution.Exposure, document.Revision, execution.JobID, "certificate-"+execution.JobID)
				}
			}
			if contractErr == nil {
				state, contractErr = execution.Service.safety.ReadForRecovery(execution.Exposure)
			}
			if contractErr == nil {
				next := state
				next.Revision++
				next.Headscale.ChallengePending = nil
				next.Headscale.Reactivating = nil
				proof := safety.TransitionProof{}
				if active := state.Headscale.Reactivating; active != nil {
					proof.Headscale = headscaleConvergenceProof(*active, headscaleFailureDigest("headscale-candidate-closed"))
				}
				_, contractErr = execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleContraction, state.Revision, next, proof)
			}
			err = contractErr
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func headscaleFailureDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func headscaleBaseSnapshot(value safety.HeadscaleSafety) []safety.MarkerSnapshot {
	certificate := safety.MarkerSnapshot{Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}
	if value.CertificateExpiry != nil {
		certificate = safety.MarkerSnapshot{Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotPresent, Generation: value.CertificateExpiry.Generation}
	}
	return []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, certificate}
}

func reconcileInterruptedHeadscaleLocalCandidate(ctx context.Context, service *FixedService) error {
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	journal, err := store.Read()
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	if state.Headscale.ChallengePending != nil {
		return nil
	}
	if journal.Phase == control.PhaseExpired {
		if state.Headscale.CertificateExpiry == nil {
			return fmt.Errorf("expired Headscale journal lacks marker")
		}
		manifest, auditErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
		if auditErr != nil {
			return auditErr
		}
		for _, entry := range manifest.Entries {
			if entry.Kind == nginx.EntryControl {
				return fmt.Errorf("expired Headscale control graph remained")
			}
		}
		return nil
	}
	if journal.Phase == control.PhaseCommitted {
		if err := verifyCommittedHeadscaleLifecycle(service, journal, state); err != nil {
			return err
		}
		return finalizeInterruptedHeadscaleLifecycle(ctx, service, journal, state)
	}
	if journal.Phase == control.PhaseActivated {
		if committed, checkErr := headscaleLifecycleNormalCommitted(service, journal); checkErr != nil {
			return checkErr
		} else if committed {
			return finalizeInterruptedHeadscaleLifecycle(ctx, service, journal, state)
		}
	}
	if journal.Phase == control.PhaseContracted {
		document, readErr := service.normal.Read()
		if readErr != nil {
			return readErr
		}
		installation, readErr := loadHeadscaleInstallation(document)
		if readErr == nil && installation.Headscale.DeployIntent != nil && installation.Headscale.DeployIntent.JobID == journal.JobID && installation.Headscale.DeployIntent.Phase == domain.HeadscaleDeployContracted && state.Headscale.Reactivating == nil {
			return nil
		}
		if state.Headscale.Reactivating != nil {
			return reconcileInterruptedHeadscaleActivation(ctx, service, journal, state)
		}
		return fmt.Errorf("contracted Headscale local journal lacks terminal authority")
	}
	if journal.Phase == control.PhaseActivationIntent || journal.Phase == control.PhaseActivated || journal.Phase == control.PhaseCertificateStaged && state.Headscale.Reactivating != nil && state.Headscale.Reactivating.ActivationDigest != "" {
		return reconcileInterruptedHeadscaleActivation(ctx, service, journal, state)
	}
	if journal.Phase == control.PhaseCertificateStaged {
		active := state.Headscale.Reactivating
		if active == nil || journal.Certificate == nil || active.PlanID != journal.PlanID || active.Generation != journal.Candidate.Generation || active.CertificateFingerprint != journal.Certificate.Fingerprint {
			return fmt.Errorf("staged Headscale certificate lost exact safety authority")
		}
		return nil
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.JobID != journal.JobID || installation.Headscale.DeployIntent.PlanID != journal.PlanID {
		return fmt.Errorf("interrupted Headscale local journal lacks domain authority")
	}
	rawIntent, present := document.Entries["intents/"+journal.JobID]
	var intent operations.Reservation
	if !present || json.Unmarshal(rawIntent, &intent) != nil || intent.Operation != operations.HeadscaleDeploy || intent.HeadscaleDeploy == nil || intent.HeadscaleDeploy.Candidate != journal.Candidate {
		return fmt.Errorf("interrupted Headscale local journal lacks operation authority")
	}
	account, err := managedheadscale.ValidateAccount(journal.InstallationID, journal.Candidate.HeadscaleID)
	if err != nil {
		return err
	}
	runtime, err := control.NewSystemdRuntime()
	if err != nil {
		return err
	}
	host, err := control.NewLinuxCandidateHost(account, runtime)
	if err != nil {
		return err
	}
	stageIdentity, stageErr := identity.CertificateStageIdentityFor(journal.Candidate.CertificateID)
	stopErr := host.StopPrivateService(context.WithoutCancel(ctx), journal.Candidate)
	var cleanupErr error
	if stageErr == nil {
		cleanupErr = errors.Join(acme.RemoveStage(journal.Candidate.CertificateID, stageIdentity.UID, stageIdentity.GID), acme.RemoveWebroot(journal.Candidate.CertificateID, stageIdentity.UID, stageIdentity.GID))
	}
	return errors.Join(stageErr, stopErr, cleanupErr)
}

func contractInterruptedHeadscaleRenewal(ctx context.Context, service *FixedService, document persist.Document, intent operations.Reservation, pending safety.ChallengePending, childClosure string) (returnErr error) {
	raw, present := document.Entries["journals/certificate-"+intent.JobID]
	var journal operations.JournalRecord
	if !present || json.Unmarshal(raw, &journal) != nil || journal.JobID != intent.JobID || journal.Operation != operations.CertificateRenew || !strings.HasPrefix(journal.Target, "headscale/") || journal.Certificate == nil || len(journal.ChildIDs) != 1 {
		return fmt.Errorf("interrupted Headscale renewal journal invalid")
	}
	var childRecord operations.ChildRecord
	childRaw, present := document.Entries["children/"+journal.ChildIDs[0]]
	if !present || json.Unmarshal(childRaw, &childRecord) != nil || childRecord.JobID != intent.JobID {
		return fmt.Errorf("interrupted Headscale renewal child invalid")
	}
	if pending.Method == "dns-01" {
		ownerLocks, err := acme.AcquireOwnerLocks(ctx, fixedRoot+"/locks", acme.DNSProvider(pending.Provider), pending.Zone, pending.Owners, pending.OwnerLock)
		if err != nil {
			return err
		}
		_, preflightErr := acme.PreflightDNS01(ctx, acme.NetDNSObserver{}, pending.Zone, pending.Owners)
		if err := errors.Join(preflightErr, ownerLocks.Close()); err != nil {
			return fmt.Errorf("interrupted Headscale renewal DNS cleanup unproved: %w", err)
		}
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	controlJournal, err := store.Read()
	if err != nil || (controlJournal.Phase != control.PhaseCommitted && controlJournal.Phase != control.PhaseExpired) || controlJournal.Certificate == nil {
		return fmt.Errorf("interrupted Headscale renewal control authority changed: %w", err)
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	_, _, mutation, exposure, err := admitter.ReenterHeadscaleChallengeContraction(ctx, mutationSet, service.manager, document.Revision, intent.JobID, childRecord.ID, childClosure)
	if err != nil {
		_ = mutationSet.Close()
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure), mutationSet.Close())
	}()
	if pending.Method == "http-01" {
		prepared, prepareErr := challenge.PreparedHTTP("headscale", pending)
		if prepareErr != nil {
			return prepareErr
		}
		if controlJournal.Phase == control.PhaseExpired {
			host, hostErr := activation.NewFixedHost()
			if hostErr != nil {
				return hostErr
			}
			if _, removeErr := host.RemoveChallenge(ctx, prepared); removeErr != nil {
				return removeErr
			}
		} else {
			bundle, bundleErr := control.BuildActivation(controlJournal.InstallationID, controlJournal.Candidate, *controlJournal.Certificate)
			if bundleErr != nil {
				return bundleErr
			}
			host, hostErr := control.NewActivationHost()
			if hostErr != nil {
				return hostErr
			}
			if removeErr := host.RemoveCertificateChallenge(ctx, bundle, prepared); removeErr != nil {
				return removeErr
			}
		}
	}
	certificate := journal.Certificate
	if err := certificates.RemoveInactiveBundle(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity, certificate.StageUID, certificate.StageGID); err != nil {
		return err
	}
	if err := errors.Join(acme.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), acme.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
		return err
	}
	freshDocument, err := service.normal.Read()
	if err != nil {
		return err
	}
	freshInstallation, loadErr := loadHeadscaleInstallation(freshDocument)
	if loadErr != nil {
		return loadErr
	}
	if freshInstallation.Headscale.DeployIntent != nil {
		if err := admitter.ContractHeadscaleReissueActivation(ctx, mutation, exposure, freshDocument.Revision, intent.JobID); err != nil {
			return err
		}
		freshDocument, err = service.normal.Read()
		if err != nil {
			return err
		}
	}
	closureRaw, _ := json.Marshal(struct {
		Job        string `json:"job"`
		Generation uint64 `json:"generation"`
		Binding    string `json:"binding"`
	}{intent.JobID, pending.Generation, pending.ACMEBinding})
	closure := shaDigest(append(closureRaw, []byte("\x00"+childClosure)...))
	if _, err := admitter.TerminalizeContractedCertificate(ctx, mutation, exposure, freshDocument.Revision, intent.JobID, pending, closure); err != nil {
		return err
	}
	fresh, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	if fresh.Headscale.ChallengePending == nil || !reflect.DeepEqual(*fresh.Headscale.ChallengePending, pending) {
		return fmt.Errorf("interrupted Headscale renewal safety changed")
	}
	next := fresh
	next.Revision++
	next.Headscale.ChallengePending = nil
	_, err = service.safety.Commit(ctx, exposure, safety.RoleContraction, fresh.Revision, next, safety.TransitionProof{})
	return err
}

func interruptedHeadscaleChallengeIntentMatches(candidate operations.Reservation, pending safety.ChallengePending, headscale domain.HeadscaleDomain) bool {
	if candidate.SafetyBinding.PlanID != pending.PlanID || candidate.SafetyBinding.IntentGeneration != pending.Generation || candidate.SafetyBinding.CertificateIdentity != pending.CertificateIdentity || candidate.SafetyBinding.ChallengeMethod != pending.Method || candidate.Target != "headscale/"+headscale.ID {
		return false
	}
	switch candidate.Operation {
	case operations.HeadscaleDeploy:
		return candidate.HeadscaleDeploy != nil && candidate.HeadscaleDeploy.Candidate.HeadscaleID == headscale.ID && candidate.SafetyBinding.CandidateDigest == pending.ConfigDigest && candidate.SafetyBinding.ACMEBinding == pending.ACMEBinding
	case operations.CertificateRenew:
		return headscale.Applied != nil && headscale.Applied.ConfigDigest == pending.ConfigDigest && candidate.SafetyBinding.CandidateDigest == pending.SANIdentity && candidate.SafetyBinding.CandidateBundle == pending.ACMEBinding
	default:
		return false
	}
}

func reconcileInterruptedHeadscaleChallenge(ctx context.Context, service *FixedService, childClosure string) error {
	state, err := service.safety.Read()
	if err != nil || state.Headscale.ChallengePending == nil {
		return err
	}
	pending := *state.Headscale.ChallengePending
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || installation.Headscale == nil {
		return errors.Join(err, fmt.Errorf("interrupted Headscale challenge installation authority missing"))
	}
	var intent operations.Reservation
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var candidate operations.Reservation
		if json.Unmarshal(raw, &candidate) != nil || !interruptedHeadscaleChallengeIntentMatches(candidate, pending, *installation.Headscale) {
			continue
		}
		if intent.JobID != "" {
			return fmt.Errorf("multiple Headscale operation intents match interrupted challenge")
		}
		intent = candidate
	}
	if intent.JobID == "" {
		return fmt.Errorf("interrupted Headscale challenge lacks exact operation authority")
	}
	if intent.Operation == operations.CertificateRenew {
		return contractInterruptedHeadscaleRenewal(ctx, service, document, intent, pending, childClosure)
	}
	var operationJournal operations.JournalRecord
	rawOperationJournal, present := document.Entries["journals/certificate-"+intent.JobID]
	if !present || json.Unmarshal(rawOperationJournal, &operationJournal) != nil || operationJournal.JobID != intent.JobID || len(operationJournal.ChildIDs) != 1 {
		return fmt.Errorf("interrupted Headscale challenge journal authority is invalid")
	}
	var childRecord operations.ChildRecord
	if raw, present := document.Entries["children/"+operationJournal.ChildIDs[0]]; !present || json.Unmarshal(raw, &childRecord) != nil || childRecord.ID != operationJournal.ChildIDs[0] || childRecord.JobID != intent.JobID {
		return fmt.Errorf("interrupted Headscale issuer child authority is invalid")
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	journal, err := store.Read()
	if err != nil || journal.JobID != intent.JobID || journal.PlanID != intent.PlanID || (journal.Phase != control.PhaseCertificatePending && journal.Phase != control.PhaseCertificateStaged && journal.Phase != control.PhaseContracted) || journal.Candidate != intent.HeadscaleDeploy.Candidate {
		return fmt.Errorf("interrupted Headscale local journal authority changed")
	}
	account, err := managedheadscale.ValidateAccount(journal.InstallationID, journal.Candidate.HeadscaleID)
	if err != nil {
		return err
	}
	runtime, err := control.NewSystemdRuntime()
	if err != nil {
		return err
	}
	host, err := control.NewLinuxCandidateHost(account, runtime)
	if err != nil {
		return err
	}
	if pending.Method == "dns-01" {
		ownerLocks, lockErr := acme.AcquireOwnerLocks(ctx, fixedRoot+"/locks", acme.DNSProvider(pending.Provider), pending.Zone, pending.Owners, pending.OwnerLock)
		if lockErr != nil {
			return lockErr
		}
		_, preflightErr := acme.PreflightDNS01(ctx, acme.NetDNSObserver{}, pending.Zone, pending.Owners)
		closeErr := ownerLocks.Close()
		if err := errors.Join(preflightErr, closeErr); err != nil {
			return fmt.Errorf("interrupted Headscale DNS challenge cleanup unproved: %w", err)
		}
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	_, childRecord, mutation, exposure, err := admitter.ReenterHeadscaleChallengeContraction(ctx, mutationSet, service.manager, document.Revision, intent.JobID, childRecord.ID, childClosure)
	if err != nil {
		_ = mutationSet.Close()
		return err
	}
	var closureErr error
	if pending.Method == "http-01" {
		prepared, prepareErr := challenge.PreparedHTTP("headscale", pending)
		if prepareErr == nil {
			var nginxHost activation.Host
			nginxHost, prepareErr = activation.NewFixedHost()
			if prepareErr == nil {
				_, prepareErr = nginxHost.RemoveChallenge(ctx, prepared)
			}
		}
		closureErr = errors.Join(closureErr, prepareErr)
	}
	stageIdentity, stageErr := identity.CertificateStageIdentityFor(journal.Candidate.CertificateID)
	closureErr = errors.Join(closureErr, stageErr, host.StopPrivateService(context.WithoutCancel(ctx), journal.Candidate))
	if stageErr == nil {
		cleanupIdentity := certificates.BundleIdentity{}
		if operationJournal.Certificate != nil {
			cleanupIdentity = operationJournal.Certificate.CandidateBundleIdentity
		}
		closureErr = errors.Join(closureErr, acme.RemoveStage(journal.Candidate.CertificateID, stageIdentity.UID, stageIdentity.GID), acme.RemoveWebroot(journal.Candidate.CertificateID, stageIdentity.UID, stageIdentity.GID), certificates.RemoveInactiveBundle(journal.Candidate.CertificateID, 1, cleanupIdentity, stageIdentity.UID, stageIdentity.GID))
	}
	if closureErr == nil {
		journal, closureErr = store.Contract(ctx, journal)
	}
	if closureErr == nil {
		freshDocument, readErr := service.normal.Read()
		if readErr == nil {
			readErr = admitter.ContractHeadscaleDeployChallenge(ctx, mutation, exposure, freshDocument.Revision, intent.JobID, operationJournal.ID)
		}
		closureErr = errors.Join(closureErr, readErr)
	}
	if closureErr == nil {
		freshSafety, readErr := service.safety.ReadForRecovery(exposure)
		if readErr == nil && freshSafety.Headscale.ChallengePending != nil && reflect.DeepEqual(*freshSafety.Headscale.ChallengePending, pending) {
			next := freshSafety
			next.Revision++
			next.Headscale.ChallengePending = nil
			_, readErr = service.safety.Commit(ctx, exposure, safety.RoleContraction, freshSafety.Revision, next, safety.TransitionProof{})
		}
		closureErr = errors.Join(closureErr, readErr)
	}
	releaseErr := operations.ReleaseExposure(mutation, exposure)
	closeErr := mutationSet.Close()
	return errors.Join(closureErr, releaseErr, closeErr)
}

func (execution *HeadscaleDeployExecution) Job() jobs.Record {
	if execution == nil {
		return jobs.Record{}
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return jobs.Record{ID: execution.JobID}
	}
	record, err := jobs.LoadEntries(document.Entries, execution.JobID)
	if err != nil {
		return jobs.Record{ID: execution.JobID}
	}
	return record
}

func (execution *HeadscaleDeployExecution) Close() error {
	if execution == nil {
		return nil
	}
	var err error
	if execution.Local != nil && !execution.CertificateStaged && !execution.ClosureUncertain {
		err = execution.removeFailedChallenge(context.Background(), execution.Host)
	}
	if execution.Mutation != nil || execution.Exposure != nil {
		err = operations.ReleaseExposure(execution.Mutation, execution.Exposure)
		execution.Mutation, execution.Exposure = nil, nil
	}
	if execution.MutationSet != nil {
		err = errors.Join(err, execution.MutationSet.Close())
	}
	if execution.Service != nil {
		err = errors.Join(err, execution.Service.Close())
	}
	return err
}
