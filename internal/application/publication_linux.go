//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	goaccessruntime "lanpanel/internal/goaccess"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/publication"
	"lanpanel/internal/reservations"
	"lanpanel/internal/safety"
	"lanpanel/internal/target"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

type temporaryPublicationBeginStage uint8

const (
	temporaryPublicationReserved temporaryPublicationBeginStage = iota + 1
	temporaryPublicationSafetyCommitted
	temporaryPublicationPlanConsumed
	temporaryPublicationIntentCommitted
	temporaryPublicationJournalCommitted
	temporaryPublicationOwnershipCommitted
	temporaryPublicationOwnershipConverged
)

func temporaryPublicationBeginFailureCode(stage temporaryPublicationBeginStage) string {
	if stage >= temporaryPublicationPlanConsumed {
		return "temporary_http_no_effect"
	}
	return "publication_revalidation_failed"
}

type PublicationExecution struct {
	Service            *FixedService
	Admitter           *operations.Admitter
	MutationSet        *operations.MutationSet
	Mutation           *operations.MutationLease
	Exposure           *locks.Lease
	JobID              string
	Revision           uint64
	Resource           domain.AppResource
	Candidate          publication.Candidate
	SafetyState        safety.State
	Reactivating       safety.Reactivating
	Ownership          ownership.Record
	PlanID             string
	InstallationID     string
	ActivationDeadline time.Time
	StagedGoAccess     *goaccessruntime.Candidate
}

func BeginPublication(ctx context.Context, actor Actor, envelopeTarget string, payload ConfirmationPayload) (*PublicationExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*PublicationExecution, error) { _ = service.Close(); return nil, cause }
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	plan, err := service.ReadPlan(payload.PlanID)
	if err != nil || plan.Operation != string(domain.OperationPublish) || plan.ActorIdentity != authority || plan.Target.Kind != plans.TargetResource || envelopeTarget != "resource/"+plan.Target.ID || payload.Confirmation != "publish" || time.Now().UTC().Before(plan.CreatedAt) || !time.Now().UTC().Before(plan.ExpiresAt) || plan.ReservedAt != nil || plan.ConsumedAt != nil || plan.RejectedAt != nil {
		return fail(fmt.Errorf("publication confirmation invalid"))
	}
	document, err := service.normal.Read()
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
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == plan.Target.ID {
			copy := installation.Resources[index]
			resource = &copy
			break
		}
	}
	if resource == nil {
		return fail(fmt.Errorf("publication resource missing"))
	}
	if _, err := reservations.BuildClaims(installation); err != nil {
		return fail(err)
	}
	state, err := service.safety.Read()
	if err != nil {
		return fail(err)
	}
	safetyResource := findSafetyResource(state, resource.ID)
	if safetyResource == nil {
		return fail(fmt.Errorf("publication safety resource missing"))
	}
	generation := safetyResource.GenerationSequence + 1
	candidate, err := publication.PrepareTemporary(*resource, generation)
	if err != nil {
		return fail(err)
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	binding := operations.SafetyBinding{ResourceID: resource.ID, PlanID: plan.ID, IntentGeneration: generation, CandidateDigest: candidate.Bundle.ConfigDigest, CandidateBundle: candidate.BundleDigest, Deadline: plan.ExpiresAt}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.Publish, Target: "resource/" + resource.ID, ActorIdentity: authority, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: binding, ExpectedRevision: document.Revision})
	var admissionCleanupErr error
	if admitErr != nil && job.ID != "" {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		admissionCleanupErr = rejectExactTemporaryReservation(cleanupCtx, service, admitter, admission, job.ID, binding, "publication_revalidation_failed")
		cancelCleanup()
	}
	releaseErr := admission.Release()
	if releaseErr != nil && admitErr == nil && job.ID != "" {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		admissionCleanupErr = rejectReservedTemporaryPublication(cleanupCtx, service, admitter, job.ID, binding, "publication_revalidation_failed")
		cancelCleanup()
	}
	if admitErr != nil || releaseErr != nil || admissionCleanupErr != nil {
		return fail(errors.Join(admitErr, releaseErr, admissionCleanupErr))
	}
	rejectAdmitted := func(cause error) (*PublicationExecution, error) {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancelCleanup()
		rejectErr := rejectReservedTemporaryPublication(cleanupCtx, service, admitter, job.ID, binding, "publication_revalidation_failed")
		return fail(errors.Join(cause, rejectErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return rejectAdmitted(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	activationDeadline := time.Now().UTC().Add(time.Minute)
	if err != nil {
		return rejectAdmitted(errors.Join(err, mutationSet.Close()))
	}
	stage := temporaryPublicationReserved
	var reactivating safety.Reactivating
	cleanup := func(cause error) (*PublicationExecution, error) {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancelCleanup()
		rejectReserved := false
		markerPresent := false
		var recoveryErr error
		if reactivating.Generation != 0 {
			markerPresent, recoveryErr = exactTemporaryMarkerPresent(service, exposure, resource.ID, reactivating)
			if recoveryErr == nil && markerPresent {
				var host temporaryPublicationRecoveryHost
				document, readErr := service.normal.Read()
				if readErr == nil {
					var recovery temporaryPublicationRecovery
					recovery, readErr = loadTemporaryPublicationRecovery(document, resource.ID, reactivating)
					if readErr == nil {
						var recoveryStage temporaryPublicationRecoveryStage
						recoveryStage, readErr = classifyTemporaryPublicationRecovery(recovery)
						if readErr == nil && (recoveryStage == temporaryRecoveryActivationDurable || recoveryStage == temporaryRecoveryCommitted) {
							var fixedHost activation.Host
							fixedHost, readErr = activation.NewFixedHost()
							host = fixedHost
						}
					}
				}
				if readErr == nil {
					rejectReserved, recoveryErr = recoverTemporaryPublicationLocked(cleanupCtx, service, admitter, mutation, exposure, resource.ID, job.ID, reactivating, host, temporaryPublicationBeginFailureCode(stage))
				} else {
					recoveryErr = readErr
				}
			}
		}
		if recoveryErr == nil && !markerPresent {
			if stage == temporaryPublicationReserved {
				rejectReserved = true
			} else {
				recoveryErr = fmt.Errorf("temporary publication marker disappeared after stage %d", stage)
			}
		}
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if recoveryErr == nil && rejectReserved {
			recoveryErr = rejectReservedTemporaryPublication(cleanupCtx, service, admitter, job.ID, binding, temporaryPublicationBeginFailureCode(stage))
		}
		return fail(errors.Join(cause, recoveryErr, releaseErr, closeErr))
	}
	fresh, err := service.normal.Read()
	if err != nil || fresh.Revision != document.Revision+1 {
		return cleanup(fmt.Errorf("publication normal authority changed"))
	}
	freshState, err := service.safety.Read()
	if err != nil {
		return cleanup(err)
	}
	freshRaw := fresh.Entries["installations/current"]
	freshInstallation, err := domain.DecodeInstallation(freshRaw)
	if err != nil {
		return cleanup(err)
	}
	if _, err := reservations.BuildClaims(freshInstallation); err != nil {
		return cleanup(err)
	}
	var freshResource *domain.AppResource
	for index := range freshInstallation.Resources {
		if freshInstallation.Resources[index].ID == resource.ID {
			freshResource = &freshInstallation.Resources[index]
		}
	}
	if freshResource == nil || freshResource.CurrentConfigDigest != resource.CurrentConfigDigest {
		return cleanup(fmt.Errorf("publication config changed"))
	}
	var preflightOwned *ownership.Record
	if freshResource.PublicationRecord.State == domain.PublicationPublished {
		record, readErr := service.ownership.Read(resource.ID)
		if readErr != nil {
			return cleanup(readErr)
		}
		preflightOwned = &record
	}
	request, result, err := evaluateTemporaryPreflight(ctx, freshInstallation, *freshResource, freshState, preflightOwned)
	if err != nil {
		return cleanup(err)
	}
	ready, err := probeResourceTarget(ctx, *freshResource)
	if err != nil {
		return cleanup(err)
	}
	if !publicationPlanBindingMatches(plan, *freshResource, result, ready) {
		return cleanup(fmt.Errorf("publication Plan binding changed"))
	}
	if request.Generation != freshResource.PublicationRecord.UnpublishedGeneration {
		return cleanup(fmt.Errorf("publication preflight generation changed"))
	}
	next := freshState
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), freshState.Resources...)
	var nextResource *safety.ResourceSafety
	for index := range next.Resources {
		if next.Resources[index].ResourceID == resource.ID {
			nextResource = &next.Resources[index]
		}
	}
	if nextResource == nil || nextResource.GenerationSequence+1 != generation {
		return cleanup(fmt.Errorf("publication safety generation changed"))
	}
	snapshots := baseSnapshot(*nextResource)
	nextResource.GenerationSequence = generation
	reactivating = safety.Reactivating{Generation: generation, PriorGeneration: generation - 1, PlanID: plan.ID, CandidateDigest: candidate.Bundle.ConfigDigest, CandidateBundle: candidate.BundleDigest, BaseMarkers: snapshots, TemporaryHTTP: true}
	nextResource.Reactivating = &reactivating
	if _, err := service.safety.Commit(ctx, exposure, safety.RolePublish, freshState.Revision, next, safety.TransitionProof{}); err != nil {
		return cleanup(err)
	}
	stage = temporaryPublicationSafetyCommitted
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		return cleanup(err)
	}
	stage = temporaryPublicationPlanConsumed
	activationIntent := domain.ActivationIntent{ID: "activation-" + job.ID, JobID: job.ID, PlanID: plan.ID, Generation: generation, Candidate: candidate.Bundle, PriorState: freshResource.PublicationRecord.State}
	if freshResource.PublicationRecord.State == domain.PublicationPublished {
		activationIntent.Prior = freshResource.PublicationRecord.LastAppliedBundle
	}
	if err := admitter.CommitPublicationBegin(ctx, mutation, exposure, intent.IntentGeneration, job.ID, operations.PublicationBeginCommit{ResourceID: resource.ID, Intent: activationIntent}); err != nil {
		return cleanup(err)
	}
	stage = temporaryPublicationIntentCommitted
	revision := intent.IntentGeneration + 1
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "activation-" + job.ID, JobID: job.ID, Kind: operations.JournalAppActivation, Operation: operations.Publish, InstallationID: freshInstallation.InstallationID, Target: "resource/" + resource.ID, Generation: intent.IntentGeneration, Deadline: plan.ExpiresAt, ArtifactDigest: candidate.BundleDigest, ResourceIDs: []string{resource.ID}, ChildIDs: nil, Phase: operations.JournalPrepared}
	if err := admitter.PutJournal(ctx, mutation, exposure, revision, journal, true); err != nil {
		return cleanup(err)
	}
	stage = temporaryPublicationJournalCommitted
	revision++
	owned, err := service.ownership.Read(resource.ID)
	if err != nil {
		return cleanup(err)
	}
	owned.Revision++
	paths := candidate.OwnershipPaths
	if len(paths) == 0 {
		paths = []ownership.OwnedPath{candidate.OwnershipPath}
	}
	for _, path := range paths {
		owned.Paths = upsertOwnedPath(owned.Paths, path)
	}
	listeners := candidate.OwnershipListeners
	if len(listeners) == 0 {
		listeners = []ownership.OwnedListener{candidate.OwnershipListener}
	}
	for _, listener := range listeners {
		owned.Listeners = upsertOwnedListener(owned.Listeners, listener)
	}
	slices.SortFunc(owned.Paths, func(a, b ownership.OwnedPath) int { return compare(a.Path, b.Path) })
	slices.SortFunc(owned.Listeners, func(a, b ownership.OwnedListener) int {
		return compare(fmt.Sprintf("%s:%s:%d", a.Protocol, a.Address, a.Port), fmt.Sprintf("%s:%s:%d", b.Protocol, b.Address, b.Port))
	})
	persisted, err := service.OwnershipWrite(ctx, exposure, owned.Revision-1, owned)
	if err != nil {
		return cleanup(err)
	}
	stage = temporaryPublicationOwnershipCommitted
	safetyAfterOwnership, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return cleanup(err)
	}
	ownershipNext := safetyAfterOwnership
	ownershipNext.Revision++
	ownershipNext.Resources = append([]safety.ResourceSafety(nil), safetyAfterOwnership.Resources...)
	for index := range ownershipNext.Resources {
		if ownershipNext.Resources[index].ResourceID == resource.ID {
			before := ownershipNext.Resources[index].OwnershipDigest
			ownershipNext.Resources[index].OwnershipDigest = persisted.Checksum
			proof := &safety.OwnershipConvergenceProof{ResourceID: resource.ID, IntentRef: plan.ID, Generation: generation, BeforeDigest: before, AfterDigest: persisted.Checksum}
			if _, err := service.safety.Commit(ctx, exposure, safety.RoleOwnershipActivation, safetyAfterOwnership.Revision, ownershipNext, safety.TransitionProof{Ownership: proof}); err != nil {
				return cleanup(err)
			}
		}
	}
	stage = temporaryPublicationOwnershipConverged
	return &PublicationExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: revision, Resource: *freshResource, Candidate: candidate, SafetyState: ownershipNext, Reactivating: reactivating, Ownership: persisted, PlanID: plan.ID, InstallationID: installation.InstallationID, ActivationDeadline: activationDeadline}, nil
}

func emergencyStopFenceOutstanding(state safety.State, emergency safety.EmergencyState) bool {
	return state.StopFence != nil || emergency.StopFence != nil || emergency.StopFenceSequence > state.StopFenceSequence
}

func contractClosedPublicationOwnership(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID, sourceJobID string, generation uint64) (safety.State, error) {
	if service == nil || service.emergency == nil || exposure == nil || resourceID == "" || sourceJobID == "" || generation == 0 {
		return safety.State{}, fmt.Errorf("publication ownership contraction authority is incomplete")
	}
	owned, err := service.ownership.Read(resourceID)
	if err != nil {
		return safety.State{}, err
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return safety.State{}, err
	}
	emergency, err := service.emergency.Authority()
	if err != nil {
		return safety.State{}, err
	}
	if emergencyStopFenceOutstanding(state, emergency) {
		return state, nil
	}
	var safetyResource *safety.ResourceSafety
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resourceID {
			safetyResource = &state.Resources[index]
			break
		}
	}
	if safetyResource == nil {
		return safety.State{}, fmt.Errorf("publication ownership contraction safety resource missing")
	}
	markerGeneration := uint64(0)
	if safetyResource.Closing != nil {
		markerGeneration = safetyResource.Closing.Generation
	} else if safetyResource.StickyUnpublished != nil {
		markerGeneration = safetyResource.StickyUnpublished.Generation
	}
	if markerGeneration != generation {
		return safety.State{}, fmt.Errorf("publication ownership contraction generation changed")
	}
	next := owned
	next.Paths = append([]ownership.OwnedPath(nil), owned.Paths...)
	next.Paths = slices.DeleteFunc(next.Paths, func(path ownership.OwnedPath) bool {
		return path.Kind == ownership.PathSite || path.Kind == ownership.PathListener
	})
	next.Listeners = nil
	changed := len(next.Paths) != len(owned.Paths) || len(owned.Listeners) != 0
	if changed {
		if safetyResource.OwnershipDigest != owned.Checksum {
			return safety.State{}, fmt.Errorf("publication ownership contraction authority changed")
		}
		next.Revision = owned.Revision + 1
		owned, err = service.OwnershipContractPublication(ctx, exposure, owned.Revision, next)
		if err != nil {
			return safety.State{}, err
		}
	}
	if safetyResource.OwnershipDigest == owned.Checksum {
		return state, nil
	}
	nextState := state
	nextState.Revision++
	nextState.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	found := false
	for index := range nextState.Resources {
		item := &nextState.Resources[index]
		if item.ResourceID != resourceID {
			continue
		}
		if item.Closing == nil && item.StickyUnpublished == nil || item.Closing != nil && item.Closing.Generation != generation || item.Closing == nil && item.StickyUnpublished.Generation != generation {
			return safety.State{}, fmt.Errorf("publication ownership contraction marker changed")
		}
		beforeDigest := item.OwnershipDigest
		item.OwnershipDigest = owned.Checksum
		proof := &safety.OwnershipConvergenceProof{ResourceID: resourceID, IntentRef: sourceJobID, Generation: generation, BeforeDigest: beforeDigest, AfterDigest: owned.Checksum}
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleOwnershipContraction, state.Revision, nextState, safety.TransitionProof{Ownership: proof}); err != nil {
			return safety.State{}, err
		}
		found = true
	}
	if !found {
		return safety.State{}, fmt.Errorf("publication ownership contraction safety resource missing")
	}
	return service.safety.ReadForRecovery(exposure)
}

func goAccessSharedRetained(resource domain.AppResource) bool {
	if bundle := resource.PublicationRecord.LastAppliedBundle; bundle != nil && bundle.DomainHTTPS != nil {
		return bundle.DomainHTTPS.GoAccess.Enabled || bundle.DomainHTTPS.GoAccess.RetiredGeneration != 0
	}
	return false
}

func (execution *PublicationExecution) restoreTemporaryPrior(ctx context.Context) error {
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancelCleanup()
	if err := execution.Admitter.RejectPublication(cleanupCtx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "activation_restored_prior"); err != nil {
		return err
	}
	return execution.Service.RestorePublicationSafety(cleanupCtx, execution.Exposure, execution.Resource.ID, execution.Reactivating)
}

func (execution *PublicationExecution) Run(ctx context.Context) (jobs.Record, error) {
	activationCtx, cancelActivation := context.WithDeadline(ctx, execution.ActivationDeadline)
	defer cancelActivation()
	candidateGoAccess := execution.Candidate.Bundle.DomainHTTPS != nil && execution.Candidate.Bundle.DomainHTTPS.GoAccess.Enabled
	var goaccessHost goaccessruntime.Host
	var stagedGoAccess *goaccessruntime.Candidate
	if candidateGoAccess {
		gid, gidErr := nginxGroupGID()
		if gidErr != nil {
			pruneErr := execution.rollbackUnstagedGoAccessOwnership(activationCtx)
			return jobs.Record{}, execution.failClosed(ctx, errors.Join(gidErr, pruneErr))
		}
		candidate, renderErr := goaccessruntime.Render(execution.InstallationID, execution.Resource, gid, execution.Candidate.Generation)
		if renderErr != nil {
			pruneErr := execution.rollbackUnstagedGoAccessOwnership(activationCtx)
			return jobs.Record{}, execution.failClosed(ctx, errors.Join(renderErr, pruneErr))
		}
		if !candidate.ReuseApplied {
			stagedGoAccess = &candidate
			execution.StagedGoAccess = &candidate
		}
		goaccessHost, renderErr = goaccessruntime.NewFixedHost()
		if renderErr == nil {
			renderErr = goaccessHost.Stage(activationCtx, execution.Resource.ID, candidate)
		}
		if renderErr != nil {
			if !candidate.ReuseApplied {
				cleanupErr := goaccessHost.CleanupCandidate(activationCtx, candidate)
				if cleanupErr != nil {
					return jobs.Record{}, execution.failClosed(ctx, errors.Join(renderErr, cleanupErr))
				}
				if pruneErr := pruneRetiredGoAccessOwnership(activationCtx, execution.Service, execution.Exposure, execution.Resource.ID, execution.JobID, candidate.Generation, candidate.StateGeneration, !candidate.RetainState, !candidate.RetainShared); pruneErr != nil {
					return jobs.Record{}, execution.failClosed(ctx, errors.Join(renderErr, pruneErr))
				}
			}
			if activationCtx.Err() != nil {
				return jobs.Record{}, execution.failClosed(ctx, errors.Join(renderErr, activationCtx.Err()))
			}
			return jobs.Record{}, execution.restorePriorAfterStaging(activationCtx, renderErr)
		}
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return jobs.Record{}, execution.failClosed(ctx, err)
	}
	if execution.Candidate.Bundle.DomainHTTPS != nil {
		if _, bindingErr := bindingFromCertificateAuthority(execution.Candidate.Bundle.DomainHTTPS.Certificate.Authority); bindingErr != nil {
			if stagedGoAccess != nil {
				bindingErr = errors.Join(bindingErr, goaccessHost.CleanupCandidate(activationCtx, *stagedGoAccess), pruneRetiredGoAccessOwnership(activationCtx, execution.Service, execution.Exposure, execution.Resource.ID, execution.JobID, stagedGoAccess.Generation, stagedGoAccess.StateGeneration, !stagedGoAccess.RetainState, !stagedGoAccess.RetainShared))
			}
			return jobs.Record{}, execution.failClosed(ctx, bindingErr)
		}
	}
	reloadAuthority, err := challengeReloadAuthorityForExposure(execution.Service, execution.Exposure)
	result := activation.Result{}
	if err == nil {
		result, err = host.Activate(activationCtx, execution.Candidate, execution.Resource.Target, reloadAuthority)
	}
	if err != nil {
		if stagedGoAccess != nil {
			if cleanupErr := goaccessHost.CleanupCandidate(activationCtx, *stagedGoAccess); cleanupErr != nil {
				return jobs.Record{}, execution.failClosed(ctx, errors.Join(err, cleanupErr))
			}
			if pruneErr := pruneRetiredGoAccessOwnership(activationCtx, execution.Service, execution.Exposure, execution.Resource.ID, execution.JobID, stagedGoAccess.Generation, stagedGoAccess.StateGeneration, !stagedGoAccess.RetainState, !stagedGoAccess.RetainShared); pruneErr != nil {
				return jobs.Record{}, execution.failClosed(ctx, errors.Join(err, pruneErr))
			}
		}
		var failure *activation.Failure
		priorRestored := errors.As(err, &failure) && failure.PriorRestored
		if execution.Candidate.Bundle.TemporaryHTTP != nil && priorRestored {
			if restoreErr := execution.restoreTemporaryPrior(ctx); restoreErr == nil {
				return jobs.Record{}, err
			} else {
				return jobs.Record{}, execution.failClosed(ctx, errors.Join(err, restoreErr))
			}
		}
		if activationCtx.Err() != nil {
			return jobs.Record{}, execution.failClosed(ctx, errors.Join(err, activationCtx.Err()))
		}
		if !priorRestored {
			return jobs.Record{}, execution.failClosed(ctx, err)
		}
		if restoreErr := execution.Service.RestorePublicationSafety(activationCtx, execution.Exposure, execution.Resource.ID, execution.Reactivating); restoreErr == nil {
			if rejectErr := execution.Admitter.RejectPublication(activationCtx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "activation_restored_prior"); rejectErr == nil {
				return jobs.Record{}, err
			} else {
				err = errors.Join(err, rejectErr)
			}
		} else {
			err = errors.Join(err, restoreErr)
		}
		return jobs.Record{}, execution.failClosed(ctx, err)
	}
	observation := domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: time.Now().UTC().Format(time.RFC3339), Reason: "published"}
	safetyCommit := func() error {
		state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
		if err != nil {
			return err
		}
		next := state
		next.Revision++
		next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
		proof := &safety.ReactivationConvergenceProof{ResourceID: execution.Resource.ID, PlanID: execution.Reactivating.PlanID, Generation: execution.Candidate.Generation, CandidateDigest: execution.Candidate.Bundle.ConfigDigest, CandidateBundle: execution.Candidate.BundleDigest, RuntimeClosureDigest: result.RuntimeDigest}
		found := false
		for index := range next.Resources {
			resource := &next.Resources[index]
			if resource.ResourceID == execution.Resource.ID {
				if resource.Reactivating == nil || !reflect.DeepEqual(*resource.Reactivating, execution.Reactivating) {
					return fmt.Errorf("publication reactivation authority changed")
				}
				resource.StickyUnpublished = nil
				resource.Contraction = nil
				resource.CertificateExpiry = nil
				if execution.Candidate.Bundle.DomainHTTPS != nil {
					authority, authorityErr := activeCertificateAuthority(execution.Candidate.Bundle.DomainHTTPS.Certificate)
					if authorityErr != nil {
						return authorityErr
					}
					resource.ActiveCertificate = authority
				}
				resource.Reactivating = nil
				found = true
			}
		}
		if !found {
			return fmt.Errorf("publication safety resource disappeared")
		}
		_, err = execution.Service.safety.Commit(activationCtx, execution.Exposure, safety.RolePublish, state.Revision, next, safety.TransitionProof{Reactivation: proof})
		return err
	}
	if stagedGoAccess != nil && !stagedGoAccess.RetainShared {
		result.ModifiedPaths = append(result.ModifiedPaths, "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow")
	}
	retirementPending := execution.Candidate.Bundle.DomainHTTPS != nil && execution.Candidate.Bundle.DomainHTTPS.GoAccess.RetiredGeneration != 0
	job, err := execution.Admitter.CommitPublicationPublished(activationCtx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.PublicationTerminalCommit{ResourceID: execution.Resource.ID, Bundle: execution.Candidate.Bundle, Runtime: observation, GoAccessRetirementPending: retirementPending}, "activation-"+execution.JobID, result.RuntimeDigest, result.ModifiedPaths, safetyCommit)
	if err != nil {
		if job.ID != "" {
			return job, err
		}
		return jobs.Record{}, execution.failClosed(ctx, err)
	}
	execution.Revision++
	retirement := domain.GoAccessBundleIdentity{}
	if execution.Candidate.Bundle.DomainHTTPS != nil {
		retirement = execution.Candidate.Bundle.DomainHTTPS.GoAccess
	}
	if retirement.RetiredGeneration != 0 {
		retirementCtx, cancelRetirement := context.WithDeadline(context.Background(), execution.ActivationDeadline)
		goaccessHost, retireErr := goaccessruntime.NewFixedHost()
		if retireErr == nil {
			retireErr = goaccessHost.Retire(retirementCtx, execution.Resource.ID, retirement.RetiredGeneration, retirement.RetiredServiceIdentity, retirement.RetiredUnitIdentities)
		}
		removeRetiredState := retirement.RemovesRetiredState()
		if retireErr == nil && removeRetiredState {
			retireErr = goaccessHost.RemoveGenerationState(retirementCtx, execution.Resource.ID, retirement.RetiredStateGeneration)
		}
		if retireErr == nil {
			retireErr = pruneRetiredGoAccessOwnership(retirementCtx, execution.Service, execution.Exposure, execution.Resource.ID, execution.JobID, retirement.RetiredGeneration, retirement.RetiredStateGeneration, removeRetiredState, false)
		}
		cancelRetirement()
		terminalCtx, cancelTerminal := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelTerminal()
		if retireErr != nil {
			partial, recordErr := execution.Admitter.FailPublicationGoAccessRetirement(terminalCtx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, execution.Resource.ID)
			if recordErr == nil {
				job = partial
				execution.Revision++
			}
			return job, errors.Join(fmt.Errorf("GoAccess prior generation retirement failed: %w", retireErr), recordErr)
		}
		completed, completeErr := execution.Admitter.CompletePublicationGoAccessRetirement(terminalCtx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, execution.Resource.ID)
		if completeErr != nil {
			return job, completeErr
		}
		job = completed
		execution.Revision++
	}
	return job, nil
}

func requireRetiredGoAccessOwnershipComplete(service *FixedService, resourceID string, generation, stateGeneration uint64, removeState bool) error {
	paths, err := goaccessruntime.DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	forbidden := map[string]bool{paths.ServiceUnit: true, paths.ServiceEnablement: true, paths.RelayUnit: true, paths.RelayEnablement: true, paths.SocketUnit: true, paths.SocketEnablement: true, paths.RetentionUnit: true, paths.RetentionTimer: true, paths.RetentionEnablement: true, paths.Endpoint: true}
	if removeState {
		statePaths, stateErr := goaccessruntime.DerivePaths(resourceID, stateGeneration)
		if stateErr != nil {
			return stateErr
		}
		forbidden[statePaths.StateRoot] = true
	}
	record, err := service.ownership.Read(resourceID)
	if err != nil {
		return err
	}
	for _, path := range record.Paths {
		if forbidden[path.Path] {
			return fmt.Errorf("retired GoAccess ownership remains")
		}
	}
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	for _, item := range state.Resources {
		if item.ResourceID == resourceID {
			if item.OwnershipDigest != record.Checksum {
				return fmt.Errorf("retired GoAccess safety ownership differs")
			}
			return nil
		}
	}
	return fmt.Errorf("retired GoAccess safety resource missing")
}

func pruneRetiredGoAccessOwnership(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID, sourceJobID string, generation, stateGeneration uint64, removeState, removeShared bool) error {
	paths, err := goaccessruntime.DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	remove := map[string]bool{paths.ServiceUnit: true, paths.ServiceEnablement: true, paths.RelayUnit: true, paths.RelayEnablement: true, paths.SocketUnit: true, paths.SocketEnablement: true, paths.RetentionUnit: true, paths.RetentionTimer: true, paths.RetentionEnablement: true, paths.Endpoint: true}
	if removeState {
		statePaths, stateErr := goaccessruntime.DerivePaths(resourceID, stateGeneration)
		if stateErr != nil {
			return stateErr
		}
		remove[statePaths.StateRoot] = true
	}
	if removeShared {
		remove[paths.Sysusers] = true
		remove[filepath.Dir(paths.AccessLog)] = true
		remove[paths.RetentionLock] = true
	}
	record, err := service.ownership.Read(resourceID)
	if err != nil {
		return err
	}
	kept := make([]ownership.OwnedPath, 0, len(record.Paths))
	changed := false
	for _, path := range record.Paths {
		if remove[path.Path] {
			changed = true
			continue
		}
		kept = append(kept, path)
	}
	persisted := record
	if changed {
		record.Revision++
		record.Paths = kept
		persisted, err = service.OwnershipRetireGoAccess(ctx, exposure, record.Revision-1, record, removeShared)
		if err != nil {
			return err
		}
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	found := false
	var proof *safety.OwnershipConvergenceProof
	for index := range next.Resources {
		item := &next.Resources[index]
		if item.ResourceID != resourceID {
			continue
		}
		if item.OwnershipDigest == persisted.Checksum {
			return nil
		}
		proof = &safety.OwnershipConvergenceProof{ResourceID: resourceID, IntentRef: sourceJobID, Generation: generation, BeforeDigest: item.OwnershipDigest, AfterDigest: persisted.Checksum}
		item.OwnershipDigest = persisted.Checksum
		found = true
	}
	if !found || proof == nil {
		return fmt.Errorf("GoAccess ownership retirement safety resource missing")
	}
	_, err = service.safety.Commit(ctx, exposure, safety.RoleOwnershipRetirement, state.Revision, next, safety.TransitionProof{Ownership: proof})
	return err
}

func (execution *PublicationExecution) rollbackUnstagedGoAccessOwnership(ctx context.Context) error {
	goaccess := execution.Candidate.Bundle.DomainHTTPS.GoAccess
	if goaccess.Generation != execution.Candidate.Generation {
		return nil
	}
	return pruneRetiredGoAccessOwnership(ctx, execution.Service, execution.Exposure, execution.Resource.ID, execution.JobID, goaccess.Generation, goaccess.StateGeneration, goaccess.StateGeneration == goaccess.Generation, !goAccessSharedRetained(execution.Resource))
}

func (execution *PublicationExecution) restorePriorAfterStaging(ctx context.Context, cause error) error {
	restoreErr := execution.Service.RestorePublicationSafety(ctx, execution.Exposure, execution.Resource.ID, execution.Reactivating)
	if restoreErr == nil {
		restoreErr = execution.Admitter.RejectPublication(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "goaccess_staging_restored_prior")
	}
	if restoreErr == nil {
		return cause
	}
	return execution.failClosed(ctx, errors.Join(cause, restoreErr))
}

type publicationFailureHost interface {
	Reload(context.Context) error
	StopAndVerify(context.Context) (closure.RuntimeSnapshot, error)
}

func shutdownFailedPublicationRuntime(host publicationFailureHost, contractionErr error, reloadTimeout, stopTimeout time.Duration) (closure.RuntimeSnapshot, error, error) {
	reloadErr := error(nil)
	if contractionErr == nil {
		reloadCtx, cancelReload := context.WithTimeout(context.Background(), reloadTimeout)
		reloadErr = host.Reload(reloadCtx)
		cancelReload()
	}
	stopCtx, cancelStop := context.WithTimeout(context.Background(), stopTimeout)
	snapshot, stopErr := host.StopAndVerify(stopCtx)
	cancelStop()
	return snapshot, reloadErr, stopErr
}

func (execution *PublicationExecution) failClosed(_ context.Context, cause error) error {
	contractCtx, cancelContract := context.WithTimeout(context.Background(), time.Minute)
	defer cancelContract()
	paths := nginx.FixedPaths()
	_, _, auditErr := nginx.Contract(contractCtx, paths, filetxn.Owner{UID: 0, GID: 0}, []string{execution.Resource.ID})
	host, hostErr := activation.NewFixedHost()
	snapshot := closure.RuntimeSnapshot{}
	reloadErr, stopErr := error(nil), hostErr
	if hostErr == nil {
		snapshot, reloadErr, stopErr = shutdownFailedPublicationRuntime(host, auditErr, 15*time.Second, time.Minute)
	}
	observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
	planID := execution.PlanID
	if planID == "" {
		if resource := findSafetyResource(execution.SafetyState, execution.Resource.ID); resource != nil && resource.Reactivating != nil {
			planID = resource.Reactivating.PlanID
		}
	}
	var cleanupErr error
	if execution.StagedGoAccess != nil {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), time.Minute)
		goaccessHost, newErr := goaccessruntime.NewFixedHost()
		cleanupErr = newErr
		if newErr == nil {
			cleanupErr = goaccessHost.CleanupCandidate(cleanupCtx, *execution.StagedGoAccess)
		}
		if cleanupErr == nil {
			cleanupErr = pruneRetiredGoAccessOwnership(cleanupCtx, execution.Service, execution.Exposure, execution.Resource.ID, execution.JobID, execution.StagedGoAccess.Generation, execution.StagedGoAccess.StateGeneration, !execution.StagedGoAccess.RetainState, !execution.StagedGoAccess.RetainShared)
		}
		cancelCleanup()
	}
	fenceCtx, cancelFence := context.WithTimeout(context.Background(), 15*time.Second)
	fenceErr := execution.Service.WriteIngressActivationFence(fenceCtx, execution.Exposure, execution.Resource.ID, planID, execution.Candidate.Generation, execution.Candidate.Generation-1, observed, stopErr != nil || cleanupErr != nil)
	cancelFence()
	return errors.Join(cause, auditErr, hostErr, reloadErr, stopErr, cleanupErr, fenceErr)
}

func (execution *PublicationExecution) Close() error {
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

func publicationPlanBindingMatches(plan plans.Plan, resource domain.AppResource, result preflight.Result, ready target.Evidence) bool {
	if err := preflight.ValidateFreshResult(result, time.Now().UTC()); err != nil {
		return false
	}
	preflightEvidence, err := result.PlanEvidence()
	if err != nil {
		return false
	}
	matchedPreflight, matchedReadiness := false, false
	for index := range plan.Evidence {
		if plan.Evidence[index].Kind == preflightEvidence.Kind && plan.Evidence[index].Identity == preflightEvidence.Identity && plan.Evidence[index].Generation == preflightEvidence.Generation && plan.Evidence[index].Digest == preflightEvidence.Digest {
			matchedPreflight = true
		}
		if plan.Evidence[index].Kind == "target_readiness" && plan.Evidence[index].Identity == "resource/"+resource.ID && plan.Evidence[index].Generation == targetEvidenceGeneration(resource) && plan.Evidence[index].Digest == ready.Digest {
			matchedReadiness = true
		}
	}
	if !matchedPreflight || !matchedReadiness {
		return false
	}
	binding := plans.Binding{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: plan.ActorIdentity, Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Evidence: []plans.Evidence{preflightEvidence, {Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: targetEvidenceGeneration(resource), Digest: ready.Digest, ObservedAt: ready.ObservedAt}}}
	if resource.PublicationRecord.LastAppliedDigest != nil {
		binding.Applied = plans.DigestBinding{Applicable: true, Digest: *resource.PublicationRecord.LastAppliedDigest}
	}
	expected := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
	return plans.SameBindingIdentity(expected, binding)
}

func baseSnapshot(resource safety.ResourceSafety) []safety.MarkerSnapshot {
	values := []struct {
		kind       safety.MarkerKind
		generation uint64
	}{{safety.MarkerStickyUnpublished, generation(resource.StickyUnpublished)}, {safety.MarkerContraction, generation(resource.Contraction)}, {safety.MarkerCertificateExpiry, deadlineGeneration(resource.CertificateExpiry)}}
	result := make([]safety.MarkerSnapshot, len(values))
	for i, value := range values {
		result[i] = safety.MarkerSnapshot{Kind: value.kind, State: safety.SnapshotAbsent}
		if value.generation != 0 {
			result[i].State = safety.SnapshotPresent
			result[i].Generation = value.generation
		}
	}
	return result
}

func generation(marker *safety.GenerationMarker) uint64 {
	if marker == nil {
		return 0
	}
	return marker.Generation
}

func deadlineGeneration(marker *safety.DeadlineMarker) uint64 {
	if marker == nil {
		return 0
	}
	return marker.Generation
}

func upsertOwnedPath(values []ownership.OwnedPath, candidate ownership.OwnedPath) []ownership.OwnedPath {
	result := make([]ownership.OwnedPath, 0, len(values)+1)
	for _, value := range values {
		if value.Kind == candidate.Kind && value.Path == candidate.Path {
			continue
		}
		result = append(result, value)
	}
	return append(result, candidate)
}

func upsertOwnedListener(values []ownership.OwnedListener, candidate ownership.OwnedListener) []ownership.OwnedListener {
	result := make([]ownership.OwnedListener, 0, len(values)+1)
	for _, value := range values {
		if value.Protocol == candidate.Protocol && value.Address == candidate.Address && value.Port == candidate.Port {
			continue
		}
		result = append(result, value)
	}
	return append(result, candidate)
}

func compare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
