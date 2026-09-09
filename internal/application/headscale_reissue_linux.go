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
	"lanpanel/internal/closure"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"lanpanel/internal/renewal"
	"lanpanel/internal/safety"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"
)

func expectedHeadscaleReissueMarker(expected safety.ChallengePending, bundle control.ActivationBundle, candidate certificates.Identity) safety.HeadscaleReactivating {
	return safety.HeadscaleReactivating{Generation: expected.Generation, PriorGeneration: expected.Generation - 1, PlanID: expected.PlanID, ControlGeneration: bundle.Entry.Generation, CertificateGeneration: candidate.Generation, CertificateFingerprint: candidate.Fingerprint, CandidateDigest: expected.ConfigDigest, CandidateBundle: bundle.Digest, ActivationDigest: bundle.Digest, ControlEntryDigest: bundle.Entry.Digest, BaseMarkers: append([]safety.MarkerSnapshot(nil), expected.BaseMarkers...), CertificateUntil: candidate.NotAfter, CertificateLastTrustedWall: candidate.LastTrustedWall}
}

func headscaleReissueMarkerMatches(active *safety.HeadscaleReactivating, expected safety.ChallengePending, bundle control.ActivationBundle, candidate certificates.Identity) bool {
	return active != nil && reflect.DeepEqual(*active, expectedHeadscaleReissueMarker(expected, bundle, candidate))
}

func headscaleChallengeMatchesExpected(pending *safety.ChallengePending, expected safety.ChallengePending) bool {
	return pending != nil && reflect.DeepEqual(*pending, expected)
}

func (execution *CertificateExecution) headscaleActivationBundle() (control.ActivationBundle, error) {
	if execution == nil || !execution.Headscale {
		return control.ActivationBundle{}, fmt.Errorf("headscale certificate execution missing")
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	journal, err := store.Read()
	if err != nil || journal.Phase != control.PhaseCommitted || journal.Certificate == nil {
		return control.ActivationBundle{}, fmt.Errorf("headscale committed control journal changed: %w", err)
	}
	return control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
}

func headscaleReissueSafetyEvidence(state safety.State, headscaleID string, now time.Time) (plans.Evidence, error) {
	value := struct {
		Sequence uint64                  `json:"sequence"`
		Base     []safety.MarkerSnapshot `json:"base"`
		Control  string                  `json:"control"`
	}{state.Headscale.GenerationSequence, headscaleBaseSnapshot(state.Headscale), state.Headscale.ControlEntryDigest}
	raw, err := json.Marshal(value)
	if err != nil {
		return plans.Evidence{}, err
	}
	sum := sha256.Sum256(raw)
	return plans.Evidence{Kind: "headscale_reissue_safety", Identity: headscaleID, Generation: state.Headscale.GenerationSequence, Digest: "sha256:" + hex.EncodeToString(sum[:]), ObservedAt: now.UTC()}, nil
}

func requireHeadscaleReissueSafetyEvidence(plan plans.Plan, state safety.State, headscaleID string, now time.Time) error {
	expected, err := headscaleReissueSafetyEvidence(state, headscaleID, now)
	if err != nil {
		return err
	}
	for _, evidence := range plan.Evidence {
		if evidence.Kind == expected.Kind && evidence.Identity == expected.Identity && evidence.Generation == expected.Generation && evidence.Digest == expected.Digest {
			return nil
		}
	}
	return fmt.Errorf("headscale reissue safety Plan changed")
}

func (s *FixedService) CreateHeadscaleReissuePlan(ctx context.Context, actor Actor, config HeadscaleCertificateConfig) (plans.Plan, error) {
	authority, err := actorAuthority(actor)
	if err != nil {
		return plans.Plan{}, err
	}
	document, err := s.normal.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || !installation.Headscale.Enabled || installation.Headscale.Certificate == nil {
		return plans.Plan{}, fmt.Errorf("headscale reissue requires committed control")
	}
	binding, err := loadHeadscaleCertificateBinding(config)
	if err != nil {
		return plans.Plan{}, err
	}
	bindingDigest, err := acme.BindingDigest(binding)
	if err != nil {
		return plans.Plan{}, err
	}
	state, err := s.safety.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	if state.StopFence != nil || state.GlobalClose.Phase != safety.GlobalCloseNone || state.Headscale.ChallengePending != nil || state.Headscale.Reactivating != nil {
		return plans.Plan{}, fmt.Errorf("headscale reissue safety authority unavailable")
	}
	if state.Headscale.CertificateExpiry != nil {
		journal, readErr := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}).Read()
		if readErr != nil || journal.Phase != control.PhaseExpired || journal.Certificate == nil || journal.Certificate.Fingerprint != installation.Headscale.Certificate.Fingerprint {
			return plans.Plan{}, fmt.Errorf("headscale expiry reissue closure authority changed: %w", readErr)
		}
	}
	now := time.Now().UTC()
	safetyEvidence, evidenceErr := headscaleReissueSafetyEvidence(state, installation.Headscale.ID, now)
	if evidenceErr != nil {
		return plans.Plan{}, evidenceErr
	}
	spec := plans.Spec{Operation: string(operations.CertificateRenew), Target: plans.Target{Kind: plans.TargetHeadscale, ID: installation.Headscale.ID}, ActorIdentity: authority, Config: plans.DigestBinding{Applicable: true, Digest: bindingDigest}, Applied: plans.DigestBinding{Applicable: true, Digest: installation.Headscale.Certificate.Fingerprint}, Evidence: []plans.Evidence{{Kind: "headscale_certificate", Identity: installation.Headscale.Certificate.Authority.CertificateID, Generation: installation.Headscale.Certificate.Generation, Digest: installation.Headscale.Certificate.Fingerprint, ObservedAt: now}, safetyEvidence}, ExposureSummary: "Reissue the Headscale control certificate without changing control identity.", Prerequisites: "The exact applied ACME binding, control graph, and prior certificate remain valid until atomic cutover.", Lifetime: 10 * time.Minute}
	admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(admission.Release)
	return s.plans.Create(ctx, admission, document.Revision, spec)
}

func BeginHeadscaleCertificateReissue(ctx context.Context, actor Actor, payload HeadscaleReissuePayload) (*CertificateExecution, error) {
	authority, err := actorAuthority(actor)
	if err != nil {
		return nil, err
	}
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	plan, err := service.ReadPlan(payload.PlanID)
	closeErr := service.Close()
	if err != nil || closeErr != nil || plan.Operation != string(operations.CertificateRenew) || plan.ActorIdentity != authority || plan.Target.Kind != plans.TargetHeadscale || payload.Confirmation != "reissue" {
		return nil, errors.Join(err, closeErr, fmt.Errorf("headscale reissue Plan invalid"))
	}
	binding, bindErr := loadHeadscaleCertificateBinding(payload.Certificate)
	bindingDigest, digestErr := acme.BindingDigest(binding)
	if bindErr != nil || digestErr != nil || bindingDigest != plan.Config.Digest {
		return nil, errors.Join(bindErr, digestErr, fmt.Errorf("headscale reissue binding changed"))
	}
	return beginHeadscaleCertificateRenew(ctx, &plan, authority, binding)
}

func BeginHeadscaleCertificateRenew(ctx context.Context) (*CertificateExecution, error) {
	return beginHeadscaleCertificateRenew(ctx, nil, "", acme.Binding{})
}

func beginHeadscaleCertificateRenew(ctx context.Context, plan *plans.Plan, actor string, requested acme.Binding) (execution *CertificateExecution, returnErr error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*CertificateExecution, error) { return nil, errors.Join(cause, service.Close()) }
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return fail(err)
	}
	headscale := installation.Headscale
	if !headscale.Enabled || headscale.Certificate == nil || headscale.Certificate.Authority == nil {
		return fail(fmt.Errorf("headscale renewal requires committed certificate authority"))
	}
	prior := *headscale.Certificate
	controlJournal, err := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}).Read()
	if err != nil || (controlJournal.Phase != control.PhaseCommitted && controlJournal.Phase != control.PhaseExpired) || !headscaleExpiryJournalMatchesNormal(installation, controlJournal) {
		return fail(fmt.Errorf("headscale renewal prior control certificate authority changed: %w", err))
	}
	binding := requested
	if plan == nil {
		binding, err = bindingFromCertificateAuthority(prior.Authority)
	}
	if err != nil {
		return fail(err)
	}
	bindingDigest, err := acme.BindingDigest(binding)
	if err != nil || plan == nil && bindingDigest != prior.BindingIdentity || plan != nil && (plan.Config.Digest != bindingDigest || plan.Applied.Digest != prior.Fingerprint) {
		return fail(fmt.Errorf("headscale renewal binding changed"))
	}
	state, err := service.safety.Read()
	if err != nil {
		return fail(err)
	}
	if state.GlobalClose.Phase != safety.GlobalCloseNone {
		return fail(fmt.Errorf("global close blocks Headscale certificate action"))
	}
	if plan != nil {
		if err := requireHeadscaleReissueSafetyEvidence(*plan, state, headscale.ID, time.Now().UTC()); err != nil {
			return fail(err)
		}
	}
	decision, err := renewal.EvaluateHeadscale(time.Now().UTC(), 30*24*time.Hour, headscale, state)
	if err != nil || plan == nil && decision != renewal.DecisionRenew {
		return fail(fmt.Errorf("headscale certificate renewal is not due: %w", err))
	}
	if plan != nil && decision == renewal.DecisionContract && state.Headscale.CertificateExpiry == nil {
		return fail(fmt.Errorf("headscale reissue contraction authority missing"))
	}
	generation := state.Headscale.GenerationSequence + 1
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: "headscale", PlanID: func() string {
		if plan != nil {
			return plan.ID
		}
		return prior.Authority.CertificateID
	}(), Generation: generation, ConfigDigest: headscale.Applied.ConfigDigest, Domains: []string{headscale.ControlDomain}, Binding: binding, CertificateIdentity: prior.Authority.CertificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + prior.Authority.CertificateID, BaseMarkers: headscaleBaseSnapshot(state.Headscale)})
	if err != nil {
		return fail(err)
	}
	deadline, _ := time.Parse(time.RFC3339, prior.NotAfter)
	now := time.Now().UTC()
	operationDeadline := now.Add(10 * time.Minute)
	if state.Headscale.CertificateExpiry == nil {
		if latest := deadline.Add(-5 * time.Minute); latest.Before(operationDeadline) {
			operationDeadline = latest
		}
	}
	if !operationDeadline.After(now.Add(time.Minute)) {
		return fail(fmt.Errorf("headscale renewal deadline insufficient"))
	}
	stageIdentity, err := identity.CertificateStageIdentityFor(prior.Authority.CertificateID)
	if err != nil {
		return fail(err)
	}
	legoDigest, err := loadCertificateLegoDigest()
	if err != nil {
		return fail(err)
	}
	var admitter *operations.Admitter
	if plan == nil {
		admitter, err = service.TimerAdmitter()
	} else {
		admitter, err = service.Admitter(*plan)
	}
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.CertificateRenew, Target: "headscale/" + headscale.ID, ActorIdentity: func() string {
		if plan != nil {
			return actor
		}
		return "timer/headscale-certificate-renewal"
	}(), Source: func() operations.AdmissionSource {
		if plan != nil {
			return operations.AdmissionPlan
		}
		return operations.AdmissionTimer
	}(), PlanID: func() string {
		if plan != nil {
			return plan.ID
		}
		return ""
	}(), SafetyBinding: operations.SafetyBinding{ResourceID: "headscale", PlanID: func() string {
		if plan != nil {
			return plan.ID
		}
		return prior.Authority.CertificateID
	}(), IntentGeneration: generation, CandidateDigest: prepared.Safety.SANIdentity, CandidateBundle: bindingDigest, ChallengeMethod: string(binding.Method), CertificateIdentity: prior.Authority.CertificateID, ExpiryGeneration: func() uint64 {
		if state.Headscale.CertificateExpiry != nil {
			return state.Headscale.CertificateExpiry.Generation
		}
		return 0
	}(), Deadline: operationDeadline}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		return fail(errors.Join(admitErr, releaseErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return fail(err)
	}
	cleanup := func(cause error) (*CertificateExecution, error) {
		return nil, errors.Join(cause, mutationSet.Close(), service.Close())
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "headscale/"+headscale.ID, service.manager)
	if err != nil {
		return cleanup(err)
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return cleanup(errors.Join(err, operations.ReleaseExposure(mutation, exposure)))
	}
	freshInstallation, err := loadHeadscaleInstallation(fresh)
	if err != nil || freshInstallation.Headscale.Certificate == nil || !reflect.DeepEqual(*freshInstallation.Headscale.Certificate, prior) {
		return cleanup(errors.Join(fmt.Errorf("headscale applied certificate changed"), operations.ReleaseExposure(mutation, exposure)))
	}
	lockedControlJournal, controlErr := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}).Read()
	priorTarget, targetErr := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation)
	activeTarget, pointerErr := certificates.ObservePointer(prior.Authority.CertificateID)
	bundleErr := certificates.VerifyBundleIdentity(prior.Authority.CertificateID, prior.Generation, certificateBundleIdentity(prior))
	if controlErr != nil || !reflect.DeepEqual(lockedControlJournal, controlJournal) || !headscaleExpiryJournalMatchesNormal(freshInstallation, lockedControlJournal) || targetErr != nil || pointerErr != nil || activeTarget != priorTarget || bundleErr != nil {
		return cleanup(errors.Join(fmt.Errorf("headscale prior certificate lineage changed under lock"), controlErr, targetErr, pointerErr, bundleErr, operations.ReleaseExposure(mutation, exposure)))
	}
	var intent operations.Reservation
	if plan == nil {
		intent, err = admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	} else {
		intent, err = admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest})
	}
	if err != nil {
		return cleanup(errors.Join(err, operations.ReleaseExposure(mutation, exposure)))
	}
	childRecord := operations.ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "lego-" + job.ID, JobID: job.ID, InstallationID: installation.InstallationID, Operation: operations.CertificateRenew, Target: "headscale/" + headscale.ID, IntentGeneration: intent.IntentGeneration, Profile: string(child.ProfileLego), InputDigest: bindingDigest, ArtifactDigest: bindingDigest, Deadline: operationDeadline, State: operations.ChildSubmitted, SubmittedAt: now}
	if err := admitter.BindOperationIdentity(ctx, mutation, exposure, intent.IntentGeneration, job.ID, bindingDigest); err != nil {
		return cleanup(errors.Join(err, operations.ReleaseExposure(mutation, exposure)))
	}
	priorPath, _ := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation)
	candidatePath, _ := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation+1)
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + job.ID, JobID: job.ID, Kind: operations.JournalCertificateActivation, Operation: operations.CertificateRenew, InstallationID: installation.InstallationID, Target: "headscale/" + headscale.ID, Generation: intent.IntentGeneration, Deadline: operationDeadline, ArtifactDigest: bindingDigest, ChildIDs: []string{childRecord.ID}, Phase: operations.JournalPrepared, Certificate: &operations.CertificateJournalIdentity{CertificateID: prior.Authority.CertificateID, PriorGeneration: prior.Generation, CandidateGeneration: prior.Generation + 1, PriorPointer: priorPath, CandidatePointer: candidatePath, PriorFingerprint: prior.Fingerprint, PriorBundleIdentity: certificateBundleIdentity(prior), Challenge: prepared.Safety, StageUID: stageIdentity.UID, StageGID: stageIdentity.GID}}
	current, err := service.normal.Read()
	if err != nil {
		return cleanup(errors.Join(err, operations.ReleaseExposure(mutation, exposure)))
	}
	if err := admitter.PutJournal(ctx, mutation, exposure, current.Revision, journal, true); err != nil {
		return cleanup(errors.Join(err, operations.ReleaseExposure(mutation, exposure)))
	}
	if err := operations.ReleaseExposure(mutation, exposure); err != nil {
		return cleanup(err)
	}
	admission, err = service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return cleanup(err)
	}
	reserveErr := admitter.ReserveChild(ctx, admission, intent.IntentGeneration+2, childRecord)
	releaseErr = admission.Release()
	if reserveErr != nil || releaseErr != nil {
		return cleanup(errors.Join(reserveErr, releaseErr))
	}
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "headscale/"+headscale.ID, service.manager)
	if err != nil {
		return cleanup(err)
	}
	freshState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return cleanup(errors.Join(err, operations.ReleaseExposure(mutation, exposure)))
	}
	if freshState.Headscale.GenerationSequence+1 != generation || !reflect.DeepEqual(headscaleBaseSnapshot(freshState.Headscale), prepared.Safety.BaseMarkers) {
		return cleanup(errors.Join(fmt.Errorf("headscale renewal safety changed"), operations.ReleaseExposure(mutation, exposure)))
	}
	next := freshState
	next.Revision++
	next.Headscale.GenerationSequence = generation
	next.Headscale.ChallengePending = &prepared.Safety
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleChallenge, freshState.Revision, next, safety.TransitionProof{}); err != nil {
		return cleanup(errors.Join(err, operations.ReleaseExposure(mutation, exposure)))
	}
	priorCopy := prior
	return &CertificateExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Operation: operations.CertificateRenew, Revision: intent.IntentGeneration + 3, Binding: binding, Challenge: prepared, InstallationID: installation.InstallationID, Deadline: operationDeadline, BundleGeneration: prior.Generation + 1, PriorCertificate: &priorCopy, Child: childRecord, StageUID: stageIdentity.UID, StageGID: stageIdentity.GID, LegoDigest: legoDigest, Headscale: true, HeadscaleID: headscale.ID, HeadscalePrior: &priorCopy}, nil
}

// A candidate partially deleted after rollback is cleanup material, never a
// candidate for reactivation. The remaining suffix must still match the exact
// journal, and both activation intents must already have been contracted.
func headscaleRollbackCandidate(candidate certificates.Identity, observeErr error, expected certificates.BundleIdentity, cleanupOnly bool, verifyCleanup func() error) (certificates.Identity, bool, error) {
	if observeErr == nil {
		if certificates.BundleIdentityFor(candidate) != expected {
			return certificates.Identity{}, false, fmt.Errorf("headscale rollback candidate identity changed")
		}
		return candidate, true, nil
	}
	if errors.Is(observeErr, os.ErrNotExist) {
		return certificates.Identity{}, false, nil
	}
	if cleanupOnly {
		if err := verifyCleanup(); err == nil {
			return certificates.Identity{}, false, nil
		} else {
			return certificates.Identity{}, false, errors.Join(observeErr, err)
		}
	}
	return certificates.Identity{}, false, observeErr
}

func reconcileCompletedHeadscaleRenewal(ctx context.Context, journalID string) (returnErr error) {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	raw, present := document.Entries["journals/"+journalID]
	var journal operations.JournalRecord
	if !present || json.Unmarshal(raw, &journal) != nil || journal.Certificate == nil || !strings.HasPrefix(journal.Target, "headscale/") || journal.Operation != operations.CertificateRenew {
		return fmt.Errorf("completed Headscale renewal journal invalid")
	}
	certificate := *journal.Certificate
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, journal.Target, service.manager)
	if err != nil {
		return errors.Join(err, mutationSet.Close())
	}
	defer func() {
		returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure), mutationSet.Close())
	}()
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	intent, err := admitter.OperationIntent(journal.JobID)
	if err != nil || intent.Operation != operations.CertificateRenew || !strings.HasPrefix(intent.Target, "headscale/") || (intent.Phase != operations.PhaseReentered && intent.Phase != operations.PhaseLocalIntent && intent.Phase != operations.PhaseRemoteWait) {
		return fmt.Errorf("completed Headscale renewal intent changed")
	}
	if !slices.Equal(journal.ChildIDs, []string{"lego-" + journal.JobID}) {
		return fmt.Errorf("completed Headscale renewal child identity changed")
	}
	var childRecord operations.ChildRecord
	childRaw, present := document.Entries["children/"+journal.ChildIDs[0]]
	if !present || json.Unmarshal(childRaw, &childRecord) != nil || childRecord.State != operations.ChildTerminal || childRecord.Outcome != operations.ChildSucceeded {
		return fmt.Errorf("completed Headscale renewal child result changed")
	}
	pointer, err := certificates.ObservePointer(certificate.CertificateID)
	if err != nil {
		return err
	}
	fenceRollback := func(cause error) error {
		execution := &CertificateExecution{Service: service, Exposure: exposure, JobID: journal.JobID}
		prior := domain.CertificateBundleIdentity{Generation: certificate.PriorGeneration, Fingerprint: certificate.PriorFingerprint, BindingIdentity: certificate.PriorBundleIdentity.BindingIdentity}
		candidate := certificates.Identity{ID: certificate.CertificateID, Generation: certificate.CandidateGeneration}
		return execution.fencePlannedHeadscaleReissue(ctx, prior, candidate, cause)
	}
	if pointer == certificate.PriorPointer {
		installation, loadErr := loadHeadscaleInstallation(document)
		priorMatches := loadErr == nil && installation.Headscale.Certificate != nil && certificateBundleMatches(*installation.Headscale.Certificate, certificate.CertificateID, certificate.PriorGeneration, certificate.PriorBundleIdentity)
		if !priorMatches {
			return fenceRollback(errors.Join(loadErr, fmt.Errorf("headscale rollback normal certificate does not match prior authority")))
		}
		if err := certificates.VerifyBundleIdentity(certificate.CertificateID, certificate.PriorGeneration, certificate.PriorBundleIdentity); err != nil {
			return fenceRollback(err)
		}
		controlJournal, controlErr := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}).Read()
		if controlErr != nil || controlJournal.Certificate == nil || controlJournal.Certificate.ID != certificate.CertificateID || controlJournal.Certificate.Generation != certificate.PriorGeneration || certificates.BundleIdentityFor(*controlJournal.Certificate) != certificate.PriorBundleIdentity || (controlJournal.Phase != control.PhaseCommitted && controlJournal.Phase != control.PhaseExpired) || installation.Headscale.Applied == nil {
			return fenceRollback(errors.Join(controlErr, fmt.Errorf("headscale rollback control certificate authority changed")))
		}
		rollbackState, stateErr := service.safety.ReadForRecovery(exposure)
		if stateErr != nil {
			return fenceRollback(stateErr)
		}
		candidateIdentity, candidateErr := certificates.ObserveIdentity(certificates.FixedBundlesRoot, certificate.CertificateID, certificate.CandidateGeneration, filetxn.Owner{UID: certificate.StageUID, GID: certificate.StageGID})
		candidateIdentity, candidatePresent, candidateErr := headscaleRollbackCandidate(candidateIdentity, candidateErr, certificate.CandidateBundleIdentity, installation.Headscale.DeployIntent == nil && rollbackState.Headscale.Reactivating == nil, func() error {
			return certificates.VerifyBundleCleanupIdentity(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity)
		})
		if candidateErr != nil {
			return fenceRollback(candidateErr)
		}
		priorActivation, priorActivationErr := control.BuildActivation(controlJournal.InstallationID, controlJournal.Candidate, *controlJournal.Certificate)
		if priorActivationErr != nil {
			return fenceRollback(priorActivationErr)
		}
		var reactivationBundle control.ActivationBundle
		if candidatePresent {
			var bundleErr error
			reactivationBundle, bundleErr = control.BuildReactivation(installation.InstallationID, controlJournal.Candidate, candidateIdentity, *controlJournal.Certificate, *installation.Headscale.Applied)
			if bundleErr != nil {
				return fenceRollback(bundleErr)
			}
		}
		manifest, auditErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
		if auditErr != nil {
			return fenceRollback(auditErr)
		}
		if controlJournal.Phase == control.PhaseExpired {
			for _, entry := range manifest.Entries {
				if entry.Kind == nginx.EntryControl {
					return fenceRollback(fmt.Errorf("expired Headscale control entry remained after rollback"))
				}
			}
			host, hostErr := activation.NewFixedHost()
			runtime, runtimeErr := host.ObserveRuntime(ctx, manifest)
			if hostErr != nil || runtimeErr != nil {
				return fenceRollback(errors.Join(hostErr, runtimeErr))
			}
			if runtime.Master == nil {
				if len(runtime.Workers) != 0 || len(runtime.Listeners) != 0 {
					return fenceRollback(fmt.Errorf("expired Headscale runtime closure is inconsistent"))
				}
			} else {
				reloadAuthority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
				if authorityErr != nil {
					return fenceRollback(authorityErr)
				}
				if _, err := host.ReloadCertificate(ctx, reloadAuthority); err != nil {
					return fenceRollback(err)
				}
				inventory := closure.Inventory{Complete: true, Digest: priorActivation.Digest, Identities: []closure.Identity{{ResourceID: "headscale", Kind: closure.IdentityDomain, Value: controlJournal.Candidate.ControlDomain, Digest: priorActivation.Entry.Digest}}}
				probe := closure.NegativeProbe{TLSAddress: "127.0.0.1:443", DefaultCertFingerprint: manifest.DefaultCertFingerprint, AuditPath: nginx.FixedPaths().AuditPath, TargetObserved: func(context.Context, closure.Inventory, string, string) (bool, error) { return false, nil }}
				if _, err := probe.Run(ctx, inventory); err != nil {
					return fenceRollback(err)
				}
			}
		} else {
			entryMatched := false
			for _, entry := range manifest.Entries {
				entryMatched = entryMatched || reflect.DeepEqual(entry, priorActivation.Entry)
			}
			if !entryMatched {
				return fenceRollback(fmt.Errorf("headscale prior control entry changed"))
			}
			host, hostErr := activation.NewFixedHost()
			priorRuntime, runtimeErr := host.ObserveRuntime(ctx, manifest)
			if hostErr != nil || runtimeErr != nil || priorRuntime.Master == nil {
				return fenceRollback(errors.Join(hostErr, runtimeErr, fmt.Errorf("headscale prior runtime unavailable")))
			}
			reloadAuthority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
			if authorityErr != nil {
				return fenceRollback(authorityErr)
			}
			expectedReactivating := expectedHeadscaleReissueMarker(certificate.Challenge, reactivationBundle, candidateIdentity)
			reloadAuthority, authorityErr = headscalePriorCertificateReloadAuthority(reloadAuthority, *installation.Headscale.Certificate, expectedReactivating)
			if authorityErr != nil {
				return fenceRollback(authorityErr)
			}
			if _, err := host.ReloadCertificate(ctx, reloadAuthority); err != nil {
				return fenceRollback(err)
			}
			if err := host.VerifyServedCertificate(ctx, installation.Headscale.ControlDomain, certificate.PriorFingerprint); err != nil {
				return fenceRollback(err)
			}
		}
		freshDocument, readErr := service.normal.Read()
		if readErr != nil {
			return readErr
		}
		freshInstallation, loadErr := loadHeadscaleInstallation(freshDocument)
		if loadErr != nil {
			return loadErr
		}
		if freshInstallation.Headscale.DeployIntent != nil {
			if err := admitter.ContractHeadscaleReissueActivation(ctx, mutation, exposure, freshDocument.Revision, journal.JobID); err != nil {
				return err
			}
			freshDocument, readErr = service.normal.Read()
			if readErr != nil {
				return readErr
			}
		}
		freshSafety, safetyErr := service.safety.ReadForRecovery(exposure)
		if safetyErr != nil {
			return fenceRollback(safetyErr)
		}
		if !activeCertificateMatchesIdentity(freshSafety.Headscale.ActiveCertificate, *controlJournal.Certificate) {
			return fenceRollback(fmt.Errorf("headscale rollback safety certificate does not match prior authority"))
		}
		if freshSafety.Headscale.Reactivating != nil {
			active := *freshSafety.Headscale.Reactivating
			if !headscaleReissueMarkerMatches(&active, certificate.Challenge, reactivationBundle, candidateIdentity) {
				return fenceRollback(fmt.Errorf("headscale rollback reactivation marker changed"))
			}
			contracted := freshSafety
			contracted.Revision++
			contracted.Headscale.Reactivating = nil
			if _, err := service.safety.Commit(ctx, exposure, safety.RolePublish, freshSafety.Revision, contracted, safety.TransitionProof{Headscale: headscaleConvergenceProof(active, headscaleFailureDigest("interrupted-renewal\x00"+journal.JobID))}); err != nil {
				return fenceRollback(err)
			}
		}
		if err := certificates.RemoveInactiveBundle(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity, certificate.StageUID, certificate.StageGID); err != nil {
			return err
		}
		if err := errors.Join(acme.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), acme.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
			return err
		}
		pending := safety.ChallengePending{PlanID: intent.SafetyBinding.PlanID, Generation: intent.SafetyBinding.IntentGeneration, SANIdentity: intent.SafetyBinding.CandidateDigest, ACMEBinding: intent.SafetyBinding.CandidateBundle}
		_, err = admitter.TerminalizeContractedCertificate(ctx, mutation, exposure, freshDocument.Revision, journal.JobID, pending, headscaleFailureDigest("interrupted-renewal\x00"+journal.JobID))
		return err
	}
	if pointer != certificate.CandidatePointer {
		return fmt.Errorf("completed Headscale renewal pointer changed")
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || installation.Headscale.Certificate == nil {
		return fmt.Errorf("completed Headscale renewal normal authority missing")
	}
	stageIdentity, err := identity.CertificateStageIdentityFor(certificate.CertificateID)
	if err != nil || stageIdentity.UID != certificate.StageUID || stageIdentity.GID != certificate.StageGID {
		return fmt.Errorf("completed Headscale renewal stage identity changed")
	}
	candidateIdentity, err := certificates.ObserveIdentity(certificates.FixedBundlesRoot, certificate.CertificateID, certificate.CandidateGeneration, filetxn.Owner{UID: certificate.StageUID, GID: certificate.StageGID})
	if err != nil {
		return err
	}
	if certificates.BundleIdentityFor(candidateIdentity) != certificate.CandidateBundleIdentity {
		return fmt.Errorf("completed Headscale renewal candidate bundle identity changed")
	}
	normalCandidate := certificateBundleMatches(*installation.Headscale.Certificate, certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity)
	normalPrior := certificate.PriorGeneration > 0 && certificateBundleMatches(*installation.Headscale.Certificate, certificate.CertificateID, certificate.PriorGeneration, certificate.PriorBundleIdentity)
	if !normalCandidate && !normalPrior {
		return fmt.Errorf("completed Headscale renewal normal certificate differs from candidate and prior authority")
	}
	if normalCandidate && journal.RuntimeDigest == "" {
		return fmt.Errorf("completed Headscale renewal lacks durable runtime evidence")
	}
	if normalPrior && (journal.RuntimeDigest == "" || installation.Headscale.Certificate.BindingIdentity != candidateIdentity.BindingIdentity) {
		pointerAuthority := certificatePointerFromJournal(certificate)
		controlJournal, controlErr := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}).Read()
		if controlErr != nil || controlJournal.Certificate == nil || controlJournal.Certificate.ID != certificate.CertificateID || controlJournal.Certificate.Generation != certificate.PriorGeneration || certificates.BundleIdentityFor(*controlJournal.Certificate) != certificate.PriorBundleIdentity || (controlJournal.Phase != control.PhaseCommitted && controlJournal.Phase != control.PhaseExpired) || installation.Headscale.Applied == nil {
			return errors.Join(controlErr, fmt.Errorf("headscale rollback control certificate authority changed"))
		}
		reactivationBundle, bundleErr := control.BuildReactivation(installation.InstallationID, controlJournal.Candidate, candidateIdentity, *controlJournal.Certificate, *installation.Headscale.Applied)
		if bundleErr != nil {
			return bundleErr
		}
		runtimeHost, runtimeHostErr := activation.NewFixedHost()
		if runtimeHostErr != nil {
			return runtimeHostErr
		}
		manifest, auditErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
		if auditErr != nil {
			return auditErr
		}
		runtime, runtimeErr := runtimeHost.ObserveRuntime(ctx, manifest)
		if runtimeErr != nil {
			return runtimeErr
		}
		stopped := runtime.Master == nil && len(runtime.Workers) == 0 && len(runtime.Listeners) == 0
		if controlJournal.Phase == control.PhaseExpired {
			if restoreErr := certificates.RestorePointer(ctx, pointerAuthority, certificate.CandidatePointer); restoreErr != nil {
				return fenceRollback(restoreErr)
			}
			if stopped {
				if _, _, removeErr := nginx.RemoveEntry(ctx, nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}, reactivationBundle.Entry); removeErr != nil {
					return fenceRollback(removeErr)
				}
			} else {
				controlHost, hostErr := control.NewActivationHost()
				if hostErr != nil {
					return fenceRollback(hostErr)
				}
				reloadAuthority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
				if authorityErr != nil {
					return fenceRollback(authorityErr)
				}
				if closeErr := controlHost.CloseControlCertificateRecovery(ctx, reactivationBundle, reloadAuthority); closeErr != nil {
					return fenceRollback(closeErr)
				}
			}
		} else {
			if stopped {
				if restoreErr := certificates.RestorePointer(ctx, pointerAuthority, certificate.CandidatePointer); restoreErr != nil {
					return restoreErr
				}
			} else {
				reloadAuthority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
				if authorityErr != nil {
					return fenceRollback(authorityErr)
				}
				expectedReactivating := expectedHeadscaleReissueMarker(certificate.Challenge, reactivationBundle, candidateIdentity)
				reloadAuthority, authorityErr = headscalePriorCertificateReloadAuthority(reloadAuthority, *installation.Headscale.Certificate, expectedReactivating)
				if authorityErr != nil {
					return fenceRollback(authorityErr)
				}
				if restoreErr := runtimeHost.RestoreCertificate(ctx, pointerAuthority, certificate.CandidatePointer, installation.Headscale.ControlDomain, certificate.PriorFingerprint, reloadAuthority); restoreErr != nil {
					return fenceRollback(restoreErr)
				}
			}
		}
		freshDocument, readErr := service.normal.Read()
		if readErr != nil {
			return readErr
		}
		freshInstallation, loadErr := loadHeadscaleInstallation(freshDocument)
		if loadErr != nil {
			return loadErr
		}
		if freshInstallation.Headscale.DeployIntent != nil {
			if err := admitter.ContractHeadscaleReissueActivation(ctx, mutation, exposure, freshDocument.Revision, journal.JobID); err != nil {
				return err
			}
			freshDocument, readErr = service.normal.Read()
			if readErr != nil {
				return readErr
			}
		}
		freshSafety, safetyErr := service.safety.ReadForRecovery(exposure)
		if safetyErr != nil {
			return fenceRollback(safetyErr)
		}
		if !activeCertificateMatchesIdentity(freshSafety.Headscale.ActiveCertificate, *controlJournal.Certificate) {
			return fenceRollback(fmt.Errorf("headscale rollback safety certificate does not match prior authority"))
		}
		if freshSafety.Headscale.Reactivating != nil {
			active := *freshSafety.Headscale.Reactivating
			if !headscaleReissueMarkerMatches(&active, certificate.Challenge, reactivationBundle, candidateIdentity) {
				return fenceRollback(fmt.Errorf("headscale rollback reactivation marker changed"))
			}
			contracted := freshSafety
			contracted.Revision++
			contracted.Headscale.Reactivating = nil
			if _, err := service.safety.Commit(ctx, exposure, safety.RolePublish, freshSafety.Revision, contracted, safety.TransitionProof{Headscale: headscaleConvergenceProof(active, headscaleFailureDigest("interrupted-binding-change\x00"+journal.JobID))}); err != nil {
				return fenceRollback(err)
			}
		}
		if err := certificates.RemoveInactiveBundle(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity, certificate.StageUID, certificate.StageGID); err != nil {
			return err
		}
		if err := errors.Join(acme.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), acme.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
			return err
		}
		pending := safety.ChallengePending{PlanID: intent.SafetyBinding.PlanID, Generation: intent.SafetyBinding.IntentGeneration, SANIdentity: intent.SafetyBinding.CandidateDigest, ACMEBinding: intent.SafetyBinding.CandidateBundle}
		_, err = admitter.TerminalizeContractedCertificate(ctx, mutation, exposure, freshDocument.Revision, journal.JobID, pending, headscaleFailureDigest("interrupted-binding-change\x00"+journal.JobID))
		return err
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	controlJournal, err := store.Read()
	if err != nil || controlJournal.Certificate == nil {
		return fmt.Errorf("completed Headscale renewal control certificate authority missing: %w", err)
	}
	controlCandidate := controlJournal.Phase == control.PhaseCommitted && reflect.DeepEqual(*controlJournal.Certificate, candidateIdentity)
	controlPrior := (controlJournal.Phase == control.PhaseCommitted || controlJournal.Phase == control.PhaseExpired) && controlJournal.Certificate.ID == certificate.CertificateID && controlJournal.Certificate.Generation == certificate.PriorGeneration && certificates.BundleIdentityFor(*controlJournal.Certificate) == certificate.PriorBundleIdentity
	if (!controlCandidate && !controlPrior) || !headscaleControlCandidateMatchesNormal(installation, controlJournal) {
		return fmt.Errorf("completed Headscale renewal control journal lineage changed")
	}
	if err := verifyLiveHeadscaleCertificate(ctx, installation.InstallationID, controlJournal.Candidate, candidateIdentity); err != nil {
		return err
	}
	binding, err := bindingFromCertificateAuthority(installation.Headscale.Certificate.Authority)
	if err != nil {
		return err
	}
	candidate, err := headscaleCertificateBundle(candidateIdentity, binding)
	if err != nil || candidate.Generation != certificate.CandidateGeneration || candidate.Authority == nil || candidate.Authority.CertificateID != certificate.CertificateID || certificateBundleIdentity(candidate) != certificate.CandidateBundleIdentity {
		return fmt.Errorf("completed Headscale renewal candidate changed: %w", err)
	}
	revision := document.Revision
	if !reflect.DeepEqual(*installation.Headscale.Certificate, candidate) {
		prior := *installation.Headscale.Certificate
		if prior.Generation != certificate.PriorGeneration || prior.Authority == nil || prior.Authority.CertificateID != certificate.CertificateID || certificateBundleIdentity(prior) != certificate.PriorBundleIdentity {
			return fmt.Errorf("completed Headscale renewal prior changed")
		}
		if err := admitter.CommitHeadscaleCertificateRenewal(ctx, mutation, exposure, revision, journal.JobID, prior, candidate); err != nil {
			return err
		}
		revision++
	}
	if journal.Phase == operations.JournalActive {
		journal.Phase = operations.JournalTerminal
		if err := admitter.PutJournal(ctx, mutation, exposure, revision, journal, false); err != nil {
			return err
		}
		revision++
	} else if journal.Phase != operations.JournalTerminal {
		return fmt.Errorf("completed Headscale renewal phase changed")
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	expectedActiveCertificate := &safety.ActiveCertificateAuthority{Generation: candidate.Generation, Fingerprint: candidate.Fingerprint, Binding: candidate.BindingIdentity, NotAfter: candidateIdentity.NotAfter, LastTrustedWall: candidateIdentity.LastTrustedWall}
	candidateActive := activeCertificateMatchesExpected(state.Headscale.ActiveCertificate, expectedActiveCertificate)
	if controlCandidate {
		if !candidateActive || state.Headscale.ChallengePending != nil || state.Headscale.Reactivating != nil {
			return fmt.Errorf("completed Headscale renewal committed control safety changed")
		}
	} else if state.Headscale.ChallengePending != nil {
		if !headscaleChallengeMatchesExpected(state.Headscale.ChallengePending, certificate.Challenge) {
			return fmt.Errorf("completed Headscale renewal challenge marker changed")
		}
		next := state
		next.Revision++
		next.Headscale.ActiveCertificate = expectedActiveCertificate
		next.Headscale.ChallengePending = nil
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
	} else if state.Headscale.Reactivating != nil {
		if len(journal.RuntimeDigest) != 71 || !strings.HasPrefix(journal.RuntimeDigest, "sha256:") || installation.Headscale.Applied == nil {
			return fmt.Errorf("completed Headscale renewal runtime authority missing")
		}
		reactivationBundle, bundleErr := control.BuildReactivation(installation.InstallationID, controlJournal.Candidate, candidateIdentity, *controlJournal.Certificate, *installation.Headscale.Applied)
		if bundleErr != nil || !headscaleReissueMarkerMatches(state.Headscale.Reactivating, certificate.Challenge, reactivationBundle, candidateIdentity) {
			return fmt.Errorf("completed Headscale renewal reactivation marker changed: %w", bundleErr)
		}
		active := *state.Headscale.Reactivating
		next := state
		next.Revision++
		next.Headscale.ActiveCertificate = expectedActiveCertificate
		next.Headscale.Reactivating = nil
		next.Headscale.CertificateExpiry = nil
		next.Headscale.ControlEntryDigest = active.ControlEntryDigest
		if _, err := service.safety.Commit(ctx, exposure, safety.RolePublish, state.Revision, next, safety.TransitionProof{Headscale: headscaleConvergenceProof(active, journal.RuntimeDigest)}); err != nil {
			return err
		}
	} else if !candidateActive {
		return fmt.Errorf("completed Headscale renewal safety differs from candidate authority")
	}
	state, err = service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	currentControlJournal, err := store.Read()
	if err != nil || !reflect.DeepEqual(currentControlJournal, controlJournal) {
		return fmt.Errorf("completed Headscale renewal control journal changed during convergence: %w", err)
	}
	controlJournal = currentControlJournal
	if controlJournal.Certificate == nil {
		return fmt.Errorf("completed Headscale renewal control certificate authority missing")
	}
	if !reflect.DeepEqual(*controlJournal.Certificate, candidateIdentity) {
		if controlJournal.Certificate.ID != certificate.CertificateID || controlJournal.Certificate.Generation != certificate.PriorGeneration || certificates.BundleIdentityFor(*controlJournal.Certificate) != certificate.PriorBundleIdentity {
			return fmt.Errorf("completed Headscale renewal control certificate authority changed")
		}
		if _, err := store.CommitRenewal(ctx, controlJournal, certificate.PriorBundleIdentity, candidateIdentity, func() string {
			if len(journal.RuntimeDigest) == 71 && strings.HasPrefix(journal.RuntimeDigest, "sha256:") {
				return journal.RuntimeDigest
			}
			return headscaleFailureDigest(certificate.CandidatePointer + "\x00" + candidate.Fingerprint)
		}()); err != nil {
			return err
		}
	}
	if err := errors.Join(acme.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), acme.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
		return err
	}
	_, err = admitter.Complete(ctx, mutation, exposure, revision, journal.JobID, "complete", []string{certificate.CandidatePointer}, []jobs.Postcondition{{Kind: "certificate_renewed_and_served", Status: jobs.PostconditionVerified, Identity: candidate.Fingerprint}}, "")
	return err
}

func stopUnfencedHeadscaleReissue(ctx context.Context, cause error) error {
	host, err := activation.NewFixedHost()
	if err != nil {
		return errors.Join(cause, err)
	}
	_, stopErr := host.StopAndVerify(ctx)
	return errors.Join(cause, stopErr)
}

func (execution *CertificateExecution) fencePlannedHeadscaleReissue(ctx context.Context, prior domain.CertificateBundleIdentity, identity certificates.Identity, cause error) error {
	now := time.Now().UTC()
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return stopUnfencedHeadscaleReissue(ctx, errors.Join(cause, err))
	}
	if state.Headscale.CertificateExpiry == nil {
		if err := execution.Service.MarkHeadscaleCertificateActivationUncertain(ctx, execution.Exposure, prior.BindingIdentity, now); err != nil {
			return stopUnfencedHeadscaleReissue(ctx, errors.Join(cause, err))
		}
	}
	priorPath, _ := certificates.BundlePath(identity.ID, prior.Generation)
	candidatePath, _ := certificates.BundlePath(identity.ID, identity.Generation)
	priorSum := sha256.Sum256([]byte(priorPath))
	candidateSum := sha256.Sum256([]byte(candidatePath))
	if err := execution.Service.WriteHeadscaleCertificateActivationFence(ctx, execution.Exposure, "certificate-"+execution.JobID, "sha256:"+hex.EncodeToString(priorSum[:]), "sha256:"+hex.EncodeToString(candidateSum[:]), safety.StopObservation{ObservedAt: now}, true); err != nil {
		return stopUnfencedHeadscaleReissue(ctx, errors.Join(cause, err))
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return errors.Join(cause, err)
	}
	snapshot, stopErr := host.StopAndVerify(ctx)
	observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
	updateErr := execution.Service.UpdateCertificateActivationFence(ctx, execution.Exposure, observed, stopErr != nil)
	execution.ClosureUncertain = true
	return errors.Join(cause, stopErr, updateErr)
}

func (execution *CertificateExecution) restorePlannedHeadscaleReissue(ctx context.Context, controlJournal control.Journal, bundle control.ActivationBundle, prior, candidate domain.CertificateBundleIdentity, identity certificates.Identity, reactivating safety.HeadscaleReactivating, cause error) error {
	pointer := certificates.Pointer{CertificateID: identity.ID, CandidateGeneration: identity.Generation, CandidateIdentity: certificates.BundleIdentityFor(identity), ExpectedPriorGeneration: prior.Generation, ExpectedPriorIdentity: certificateBundleIdentity(prior)}
	var physicalErr error
	if controlJournal.Phase == control.PhaseExpired {
		candidatePath, _ := certificates.BundlePath(identity.ID, identity.Generation)
		physicalErr = certificates.RestorePointer(ctx, pointer, candidatePath)
		if physicalErr == nil {
			host, err := control.NewActivationHost()
			if err == nil {
				reloadAuthority, authorityErr := execution.challengeReloadAuthority()
				if authorityErr != nil {
					physicalErr = authorityErr
				} else {
					physicalErr = host.CloseControlCertificateRecovery(ctx, bundle, reloadAuthority)
				}
			} else {
				physicalErr = err
			}
		}
	} else {
		candidatePath, pathErr := certificates.BundlePath(identity.ID, identity.Generation)
		if pathErr != nil {
			physicalErr = pathErr
		} else {
			physicalErr = certificates.RestorePointer(ctx, pointer, candidatePath)
		}
	}
	if physicalErr != nil {
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, physicalErr))
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, err))
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, err))
	}
	switch {
	case installation.Headscale.Certificate != nil && reflect.DeepEqual(*installation.Headscale.Certificate, candidate):
		err = execution.Admitter.RestoreHeadscaleCertificateRenewal(ctx, execution.Mutation, execution.Exposure, document.Revision, execution.JobID, candidate, prior)
	case installation.Headscale.Certificate != nil && reflect.DeepEqual(*installation.Headscale.Certificate, prior):
		if installation.Headscale.DeployIntent != nil {
			err = execution.Admitter.ContractHeadscaleReissueActivation(ctx, execution.Mutation, execution.Exposure, document.Revision, execution.JobID)
		}
	default:
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, fmt.Errorf("headscale rollback normal certificate differs from candidate and prior authority")))
	}
	if err != nil {
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, err))
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, err))
	}
	if !activeCertificateMatchesBundle(state.Headscale.ActiveCertificate, prior) {
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, fmt.Errorf("headscale rollback safety certificate does not match prior authority")))
	}
	if state.Headscale.Reactivating != nil {
		if !reflect.DeepEqual(*state.Headscale.Reactivating, reactivating) {
			return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, fmt.Errorf("headscale rollback reactivation marker changed")))
		}
		next := state
		next.Revision++
		next.Headscale.Reactivating = nil
		_, err = execution.Service.safety.Commit(ctx, execution.Exposure, safety.RolePublish, state.Revision, next, safety.TransitionProof{Headscale: headscaleConvergenceProof(reactivating, headscaleFailureDigest("reissue-prior-restored\x00"+execution.JobID))})
	}
	if err != nil {
		return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, err))
	}
	if controlJournal.Phase != control.PhaseExpired {
		host, hostErr := activation.NewFixedHost()
		if hostErr != nil {
			return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, hostErr))
		}
		reloadAuthority, authorityErr := execution.challengeReloadAuthority()
		if authorityErr == nil {
			reloadAuthority, authorityErr = headscalePriorCertificateReloadAuthority(reloadAuthority, prior, reactivating)
		}
		if authorityErr != nil {
			return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, authorityErr))
		}
		if _, reloadErr := host.ReloadCertificate(ctx, reloadAuthority); reloadErr != nil {
			return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, reloadErr))
		}
		if probeErr := host.VerifyServedCertificate(ctx, execution.Challenge.Safety.Hosts[0], prior.Fingerprint); probeErr != nil {
			return execution.fencePlannedHeadscaleReissue(ctx, prior, identity, errors.Join(cause, probeErr))
		}
	}
	return cause
}

func (execution *CertificateExecution) CompletePlannedHeadscaleReissue(ctx context.Context, identity certificates.Identity) (record jobs.Record, returnErr error) {
	if execution == nil || !execution.Headscale || execution.PriorCertificate == nil {
		return jobs.Record{}, fmt.Errorf("expired Headscale reissue authority missing")
	}
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return jobs.Record{}, err
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return jobs.Record{}, err
	}
	if err := execution.removeActiveChallenge(ctx, host); err != nil {
		return jobs.Record{}, err
	}
	if execution.Binding.Method == acme.ChallengeHTTP01 {
		if err := acme.VerifyWebrootEmpty(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID); err != nil {
			return jobs.Record{}, err
		}
	}
	if err := errors.Join(acme.RemoveStage(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID), acme.RemoveWebroot(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID)); err != nil {
		return jobs.Record{}, err
	}
	prior := *execution.PriorCertificate
	candidate, err := headscaleCertificateBundle(identity, execution.Binding)
	if err != nil {
		return jobs.Record{}, err
	}
	controlStore := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	controlJournal, err := controlStore.Read()
	if err != nil || (controlJournal.Phase != control.PhaseExpired && controlJournal.Phase != control.PhaseCommitted) || controlJournal.Certificate == nil {
		return jobs.Record{}, fmt.Errorf("expired Headscale control journal changed: %w", err)
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return jobs.Record{}, err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || prior.Authority == nil || installation.Headscale.Applied == nil || installation.Headscale.Certificate == nil || !reflect.DeepEqual(*installation.Headscale.Certificate, prior) {
		return jobs.Record{}, fmt.Errorf("expired Headscale installation changed")
	}
	if controlJournal.Certificate.ID != prior.Authority.CertificateID || controlJournal.Certificate.Generation != prior.Generation || certificates.BundleIdentityFor(*controlJournal.Certificate) != certificateBundleIdentity(prior) {
		return jobs.Record{}, fmt.Errorf("expired Headscale prior control certificate authority changed")
	}
	bundle, err := control.BuildReactivation(installation.InstallationID, controlJournal.Candidate, identity, *controlJournal.Certificate, *installation.Headscale.Applied)
	if err != nil {
		return jobs.Record{}, err
	}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + execution.JobID, JobID: execution.JobID, Kind: operations.JournalCertificateActivation, Operation: operations.CertificateRenew, InstallationID: execution.InstallationID, Target: "headscale/" + execution.HeadscaleID, Generation: execution.Child.IntentGeneration, Deadline: execution.Deadline, ArtifactDigest: execution.Child.InputDigest, ChildIDs: []string{execution.Child.ID}, Phase: operations.JournalActive, Certificate: &operations.CertificateJournalIdentity{CertificateID: identity.ID, PriorGeneration: prior.Generation, CandidateGeneration: identity.Generation, PriorPointer: func() string { value, _ := certificates.BundlePath(identity.ID, prior.Generation); return value }(), CandidatePointer: func() string { value, _ := certificates.BundlePath(identity.ID, identity.Generation); return value }(), PriorFingerprint: prior.Fingerprint, CandidateFingerprint: identity.Fingerprint, PriorBundleIdentity: certificateBundleIdentity(prior), CandidateBundleIdentity: certificates.BundleIdentityFor(identity), Challenge: execution.Challenge.Safety, StageUID: execution.StageUID, StageGID: execution.StageGID}}
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	if err := execution.Admitter.CommitHeadscaleReissueActivationIntent(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, candidate, bundle.Digest); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil || (controlJournal.Phase == control.PhaseExpired) != (state.Headscale.CertificateExpiry != nil) || state.Headscale.ChallengePending == nil || !challenge.Matches(*state.Headscale.ChallengePending, execution.Challenge) {
		return jobs.Record{}, fmt.Errorf("expired Headscale reissue safety changed: %w", err)
	}
	pending := state.Headscale.ChallengePending
	reactivationMarker := expectedHeadscaleReissueMarker(*pending, bundle, identity)
	reactivating := &reactivationMarker
	next := state
	next.Revision++
	next.Headscale.ChallengePending = nil
	next.Headscale.Reactivating = reactivating
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleCertificateHandoff, state.Revision, next, safety.TransitionProof{}); err != nil {
		return jobs.Record{}, err
	}
	document, err = execution.Service.normal.Read()
	if err != nil {
		return jobs.Record{}, err
	}
	installation, err = loadHeadscaleInstallation(document)
	if err != nil {
		return jobs.Record{}, err
	}
	runtimeDigest := ""
	priorRestored := false
	var activateErr error
	ownershipAuthority, ownershipErr := fixedOwnershipAuthority(execution.Service.ownership)
	if ownershipErr != nil {
		return jobs.Record{}, ownershipErr
	}
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return jobs.Record{}, err
	}
	if controlJournal.Phase == control.PhaseExpired {
		activationHost, hostErr := control.NewActivationHost()
		if hostErr != nil {
			return jobs.Record{}, hostErr
		}
		reloadAuthority, authorityErr := execution.challengeReloadAuthority()
		if authorityErr != nil {
			return jobs.Record{}, authorityErr
		}
		activationResult, resultErr := activationHost.Activate(ctx, bundle, control.ActivationAuthority{Safety: next, Installation: installation, Ownership: ownershipAuthority, ObservedAt: time.Now().UTC()}, reloadAuthority)
		activateErr = resultErr
		priorRestored = activationResult.PriorRestored
		runtimeDigest = activationResult.RuntimeDigest
	} else {
		manifest, auditErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
		if auditErr != nil {
			return jobs.Record{}, auditErr
		}
		if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: next, Installation: &installation, Ownership: ownershipAuthority, Now: time.Now().UTC()}); !decision.Allowed {
			return jobs.Record{}, fmt.Errorf("headscale reissue reload rejected: %s", decision.Reason)
		}
		pointer := certificates.Pointer{CertificateID: identity.ID, CandidateGeneration: identity.Generation, CandidateIdentity: certificates.BundleIdentityFor(identity), ExpectedPriorGeneration: prior.Generation, ExpectedPriorIdentity: certificateBundleIdentity(prior)}
		reloadAuthority, authorityErr := execution.challengeReloadAuthority()
		if authorityErr != nil {
			return jobs.Record{}, authorityErr
		}
		restoreAuthority, authorityErr := headscalePriorCertificateReloadAuthority(reloadAuthority, prior, *reactivating)
		if authorityErr != nil {
			return jobs.Record{}, authorityErr
		}
		activationResult, resultErr := host.ActivateCertificate(ctx, pointer, execution.Challenge.Safety.Hosts[0], identity.Fingerprint, prior.Fingerprint, reloadAuthority, restoreAuthority)
		activateErr = resultErr
		var failure *activation.Failure
		if errors.As(resultErr, &failure) {
			priorRestored = failure.PriorRestored
		}
		runtimeDigest = headscaleFailureDigest(activationResult.Runtime.Generation + "\x00" + identity.Fingerprint)
	}
	if activateErr != nil {
		if !priorRestored {
			return jobs.Record{}, execution.fencePlannedHeadscaleReissue(context.WithoutCancel(ctx), prior, identity, activateErr)
		}
		fresh, readErr := execution.Service.normal.Read()
		contractErr := error(nil)
		if readErr == nil {
			contractErr = execution.Admitter.ContractHeadscaleReissueActivation(context.WithoutCancel(ctx), execution.Mutation, execution.Exposure, fresh.Revision, execution.JobID)
		}
		safetyState, safetyErr := execution.Service.safety.ReadForRecovery(execution.Exposure)
		if safetyErr == nil && safetyState.Headscale.Reactivating != nil {
			contracted := safetyState
			contracted.Revision++
			contracted.Headscale.Reactivating = nil
			_, safetyErr = execution.Service.safety.Commit(context.WithoutCancel(ctx), execution.Exposure, safety.RolePublish, safetyState.Revision, contracted, safety.TransitionProof{Headscale: headscaleConvergenceProof(*reactivating, headscaleFailureDigest("expired-reissue-restored\x00"+execution.JobID))})
		}
		return jobs.Record{}, errors.Join(activateErr, readErr, contractErr, safetyErr)
	}
	journal.RuntimeDigest = runtimeDigest
	journal.Phase = operations.JournalTerminal
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return jobs.Record{}, execution.restorePlannedHeadscaleReissue(context.WithoutCancel(ctx), controlJournal, bundle, prior, candidate, identity, *reactivating, err)
	}
	execution.Revision++
	if err := execution.Admitter.CommitHeadscaleCertificateRenewal(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, prior, candidate); err != nil {
		return jobs.Record{}, execution.restorePlannedHeadscaleReissue(context.WithoutCancel(ctx), controlJournal, bundle, prior, candidate, identity, *reactivating, err)
	}
	execution.Revision++
	state, err = execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil || state.Headscale.Reactivating == nil {
		return jobs.Record{}, fmt.Errorf("expired Headscale reissue convergence changed: %w", err)
	}
	next = state
	next.Revision++
	next.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: candidate.Generation, Fingerprint: candidate.Fingerprint, Binding: candidate.BindingIdentity, NotAfter: identity.NotAfter, LastTrustedWall: identity.LastTrustedWall}
	next.Headscale.ControlEntryDigest = bundle.Entry.Digest
	next.Headscale.CertificateExpiry = nil
	next.Headscale.Reactivating = nil
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RolePublish, state.Revision, next, safety.TransitionProof{Headscale: headscaleConvergenceProof(*reactivating, runtimeDigest)}); err != nil {
		return jobs.Record{}, execution.restorePlannedHeadscaleReissue(context.WithoutCancel(ctx), controlJournal, bundle, prior, candidate, identity, *reactivating, err)
	}
	if _, err := controlStore.CommitRenewal(ctx, controlJournal, certificateBundleIdentity(prior), identity, runtimeDigest); err != nil {
		return jobs.Record{}, execution.fencePlannedHeadscaleReissue(context.WithoutCancel(ctx), prior, identity, err)
	}
	record, completeErr := execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "complete", []string{identity.CertificatePath, identity.PrivateKeyPath, journal.Certificate.CandidatePointer}, []jobs.Postcondition{{Kind: "headscale_control_reissued_and_served", Status: jobs.PostconditionVerified, Identity: identity.Fingerprint}}, "")
	if completeErr != nil {
		execution.RecoveryPending = true
	}
	return record, completeErr
}

func ExecuteHeadscaleCertificateRenewal(ctx context.Context) (string, error) {
	execution, err := BeginHeadscaleCertificateRenew(ctx)
	if err != nil {
		return "", err
	}
	defer func(ignore func() error) { _ = ignore() }(execution.Close)
	abort := func(cause error) error { return execution.Abort(context.WithoutCancel(ctx), cause) }
	if err := execution.ActivateChallenge(ctx); err != nil {
		return "", abort(err)
	}
	result, runErr := execution.RunRemote(ctx, execution.StageUID, execution.StageGID)
	if err := execution.TerminalizeChild(ctx, result, runErr); err != nil {
		return "", abort(err)
	}
	if runErr != nil {
		return "", abort(runErr)
	}
	material, err := execution.LoadIssued(time.Now().UTC())
	if err != nil {
		return "", abort(err)
	}
	bundle, err := certificates.StageIssued(ctx, certificates.FixedBundlesRoot, execution.Challenge.Safety.CertificateIdentity, execution.BundleGeneration, execution.Child.InputDigest, material, filetxn.Owner{UID: execution.StageUID, GID: execution.StageGID}, time.Now().UTC(), func(identity certificates.Identity) error { return execution.AuthorizeStagedCertificate(ctx, identity) })
	if err != nil {
		return "", abort(err)
	}
	if _, err := execution.CompleteRenewal(ctx, bundle); err != nil {
		return "", abort(err)
	}
	return bundle.Fingerprint, nil
}

func ExecuteHeadscaleCertificateReissue(ctx context.Context, actor Actor, payload HeadscaleReissuePayload) (record jobs.Record, returnErr error) {
	execution, err := BeginHeadscaleCertificateReissue(ctx, actor, payload)
	if err != nil {
		return jobs.Record{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, execution.Close()) }()
	abort := func(cause error) (jobs.Record, error) {
		return jobs.Record{}, execution.Abort(context.WithoutCancel(ctx), cause)
	}
	if err := execution.ActivateChallenge(ctx); err != nil {
		return abort(err)
	}
	result, runErr := execution.RunRemote(ctx, execution.StageUID, execution.StageGID)
	if err := execution.TerminalizeChild(ctx, result, runErr); err != nil {
		return abort(err)
	}
	if runErr != nil {
		return abort(runErr)
	}
	material, err := execution.LoadIssued(time.Now().UTC())
	if err != nil {
		return abort(err)
	}
	bundle, err := certificates.StageIssued(ctx, certificates.FixedBundlesRoot, execution.Challenge.Safety.CertificateIdentity, execution.BundleGeneration, execution.Child.InputDigest, material, filetxn.Owner{UID: execution.StageUID, GID: execution.StageGID}, time.Now().UTC(), func(identity certificates.Identity) error { return execution.AuthorizeStagedCertificate(ctx, identity) })
	if err != nil {
		return abort(err)
	}
	record, err = execution.CompletePlannedHeadscaleReissue(ctx, bundle)
	if err != nil {
		if execution.ClosureUncertain || execution.RecoveryPending {
			return jobs.Record{}, err
		}
		return abort(err)
	}
	return record, nil
}
