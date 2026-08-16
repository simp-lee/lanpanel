//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/certificates"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/identity"
	"lanpanel/internal/operations"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"reflect"
	"time"
)

type headscaleActivationHost interface {
	Stage(context.Context, control.ActivationBundle) error
	Activate(context.Context, control.ActivationBundle, control.ActivationAuthority) (control.ActivationResult, error)
	Contract(context.Context, control.ActivationBundle) error
}

// ActivateControl performs only S17B's mutation-to-exposure transition. The
// durable deploy remains owned by the reactivation marker for S17C to install
// expiry/renewal authority and terminalize the job.
func (execution *HeadscaleDeployExecution) ActivateControl(ctx context.Context, host headscaleActivationHost) (returnErr error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if execution == nil || execution.Mutation == nil || execution.Exposure == nil || !execution.CertificateStaged || execution.Local == nil || execution.Host == nil || host == nil {
		return fmt.Errorf("Headscale control activation phase is invalid")
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	journal, err := store.Read()
	if err != nil || journal.JobID != execution.JobID || journal.PlanID != execution.Plan.ID || journal.IntentGeneration != execution.Child.IntentGeneration || journal.Phase != control.PhaseCertificateStaged || journal.Certificate == nil {
		return fmt.Errorf("Headscale staged certificate authority changed: %w", err)
	}
	bundle, err := control.BuildActivation(execution.Installation.InstallationID, execution.Authority.Rendered.Candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return err
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return err
	}
	if err := managedheadscale.ValidateCommittedInitialization(installation.InstallationID, *installation.Headscale, installed, managedheadscale.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}); err != nil {
		return err
	}
	freshRequest, freshResult, err := evaluateHeadscaleDeployPreflight(ctx, installed, installation.InstallationID, installation.Headscale.ID, installation.Headscale.ControlDomain, installation.Headscale.Database.Generation)
	if err != nil || !reflect.DeepEqual(freshRequest, execution.Authority.Preflight) {
		return fmt.Errorf("Headscale activation preflight policy changed: %w", err)
	}
	if err := preflight.RequireExpansionResultForRequest(freshResult, freshRequest, freshResult.ObservedAt); err != nil {
		return err
	}
	if !freshResult.ObservedAt.Before(execution.Plan.ExpiresAt) {
		return fmt.Errorf("Headscale activation Plan deadline elapsed")
	}
	if err := execution.Local.VerifyPrivateCandidate(ctx); err != nil {
		return fmt.Errorf("Headscale private candidate changed before activation: %w", err)
	}
	if err := host.Stage(ctx, bundle); err != nil {
		return err
	}
	if err := execution.Service.BindHeadscaleIngressActivation(ctx, execution.Exposure, execution.Plan.ID, bundle.Digest, bundle.Entry.Digest); err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	activationIntent := journal
	activationIntent.Phase = control.PhaseActivationIntent
	activationIntent.ActivationDigest = bundle.Digest
	if err := store.Replace(ctx, journal, activationIntent); err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	if err := execution.Admitter.CommitHeadscaleActivationIntent(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.HeadscaleActivationIntentCommit{HeadscaleID: execution.Installation.Headscale.ID, ActivationDigest: bundle.Digest}); err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	execution.Revision++
	activationDocument, err := execution.Service.normal.Read()
	if err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	activationInstallation, err := loadHeadscaleInstallation(activationDocument)
	if err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	activationSafety, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	trustedNow, timeErr := execution.Admitter.TrustedNow()
	if timeErr != nil || !trustedNow.Before(execution.Plan.ExpiresAt) {
		return errors.Join(fmt.Errorf("Headscale activation deadline changed: %w", timeErr), execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	runtimeAuthority := control.ActivationAuthority{Safety: activationSafety, Installation: activationInstallation, ObservedAt: trustedNow}
	result, err := host.Activate(ctx, bundle, runtimeAuthority)
	if err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	activated := activationIntent
	activated.Phase = control.PhaseActivated
	activated.RuntimeDigest = result.RuntimeDigest
	if err := store.Replace(ctx, activationIntent, activated); err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	applied := control.AppliedFromActivation(bundle)
	if err := execution.Admitter.CommitHeadscaleActivated(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.HeadscaleActivatedCommit{HeadscaleID: execution.Installation.Headscale.ID, RuntimeDigest: result.RuntimeDigest, Applied: applied}); err != nil {
		return errors.Join(err, execution.contractActivationFailure(context.WithoutCancel(ctx), host, bundle))
	}
	execution.Revision++
	execution.Installation = activationInstallation
	execution.Installation.Headscale.Applied = &applied
	execution.Installation.Headscale.Enabled = true
	intent := *execution.Installation.Headscale.DeployIntent
	intent.Phase, intent.ActivationDigest, intent.RuntimeDigest = domain.HeadscaleDeployActivated, bundle.Digest, result.RuntimeDigest
	execution.Installation.Headscale.DeployIntent = &intent
	return nil
}

func reconcileInterruptedHeadscaleActivation(ctx context.Context, service *FixedService, journal control.Journal, state safety.State) (returnErr error) {
	active := state.Headscale.Reactivating
	if active == nil || journal.Certificate == nil || active.PlanID != journal.PlanID || active.Generation != journal.IntentGeneration || active.ControlGeneration != journal.Candidate.Generation || active.CertificateGeneration != journal.Certificate.Generation || active.CertificateFingerprint != journal.Certificate.Fingerprint {
		return fmt.Errorf("interrupted Headscale activation lost exact safety authority")
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil || installation.Headscale.DeployIntent == nil || installation.Headscale.DeployIntent.JobID != journal.JobID {
		return fmt.Errorf("interrupted Headscale activation lost domain authority: %w", err)
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
	if err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	_, mutation, exposure, err := admitter.ReenterHeadscaleActivationContraction(ctx, mutationSet, service.manager, document.Revision, journal.JobID)
	if err != nil {
		return errors.Join(err, mutationSet.Close())
	}
	defer func() {
		returnErr = errors.Join(returnErr, operations.ReleaseExposure(mutation, exposure), mutationSet.Close())
	}()
	activationHost, err := control.NewActivationHost()
	if err != nil {
		return err
	}
	account, err := managedheadscale.ValidateAccount(journal.InstallationID, journal.Candidate.HeadscaleID)
	if err != nil {
		return err
	}
	runtime, err := control.NewSystemdRuntime()
	if err != nil {
		return err
	}
	candidateHost, err := control.NewLinuxCandidateHost(account, runtime)
	if err != nil {
		return err
	}
	physicalErr := errors.Join(activationHost.Contract(context.WithoutCancel(ctx), bundle), candidateHost.StopPrivateService(context.WithoutCancel(ctx), journal.Candidate))
	stage, stageErr := identity.CertificateStageIdentityFor(journal.Candidate.CertificateID)
	physicalErr = errors.Join(physicalErr, stageErr)
	if stageErr == nil {
		physicalErr = errors.Join(physicalErr, acme.RemoveStage(journal.Candidate.CertificateID, stage.UID, stage.GID), acme.RemoveWebroot(journal.Candidate.CertificateID, stage.UID, stage.GID), certificates.RemoveInactiveBundle(journal.Candidate.CertificateID, journal.Certificate.Generation, stage.UID, stage.GID))
	}
	if physicalErr != nil {
		observed, fallbackErr := activationHost.FallbackStop(context.WithoutCancel(ctx), bundle)
		accessMayRemain := fallbackErr != nil
		fenceErr := service.WriteHeadscaleIngressActivationFence(context.WithoutCancel(ctx), exposure, journal.PlanID, bundle.Digest, active.Generation, active.PriorGeneration, observed, accessMayRemain)
		physicalErr = errors.Join(physicalErr, fallbackErr)
		return errors.Join(fmt.Errorf("interrupted Headscale activation closure uncertain: %w", physicalErr), fenceErr)
	}
	store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if _, err = store.Contract(context.WithoutCancel(ctx), journal); err != nil {
		return err
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return err
	}
	if err = admitter.ContractHeadscaleDeployChallenge(context.WithoutCancel(ctx), mutation, exposure, fresh.Revision, journal.JobID, "certificate-"+journal.JobID); err != nil {
		return err
	}
	freshSafety, err := service.safety.ReadForRecovery(exposure)
	if err != nil || freshSafety.Headscale.Reactivating == nil || freshSafety.Headscale.Reactivating.PlanID != journal.PlanID {
		return fmt.Errorf("Headscale activation contraction safety changed: %w", err)
	}
	next := freshSafety
	next.Revision++
	activeAuthority := *freshSafety.Headscale.Reactivating
	next.Headscale.Reactivating = nil
	_, err = service.safety.Commit(context.WithoutCancel(ctx), exposure, safety.RoleContraction, freshSafety.Revision, next, safety.TransitionProof{Headscale: headscaleConvergenceProof(activeAuthority, bundle.Digest)})
	return err
}

func headscaleConvergenceProof(active safety.HeadscaleReactivating, closureDigest string) *safety.HeadscaleConvergenceProof {
	return &safety.HeadscaleConvergenceProof{PlanID: active.PlanID, Generation: active.Generation, ControlGeneration: active.ControlGeneration, CertificateGeneration: active.CertificateGeneration, CertificateFingerprint: active.CertificateFingerprint, CandidateDigest: active.CandidateDigest, CandidateBundle: active.CandidateBundle, RuntimeClosureDigest: closureDigest}
}

func (execution *HeadscaleDeployExecution) contractActivationFailure(ctx context.Context, host headscaleActivationHost, bundle control.ActivationBundle) error {
	physicalErr := host.Contract(ctx, bundle)
	if physicalErr != nil {
		observed := safety.StopObservation{ObservedAt: time.Now().UTC()}
		accessMayRemain := true
		var fallbackErr error
		if fallback, ok := host.(interface {
			FallbackStop(context.Context, control.ActivationBundle) (safety.StopObservation, error)
		}); ok {
			observed, fallbackErr = fallback.FallbackStop(ctx, bundle)
			accessMayRemain = fallbackErr != nil
		}
		fenceErr := execution.Service.WriteHeadscaleIngressActivationFence(ctx, execution.Exposure, execution.Plan.ID, bundle.Digest, execution.Challenge.Safety.Generation, execution.Challenge.Safety.Generation-1, observed, accessMayRemain)
		execution.ClosureUncertain = true
		return errors.Join(fmt.Errorf("Headscale ingress activation closure uncertain: %w", physicalErr), fallbackErr, fenceErr)
	}
	return execution.removeFailedChallenge(ctx, execution.Host)
}
