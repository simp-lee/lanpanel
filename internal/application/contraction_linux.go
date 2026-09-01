//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/closure"
	"lanpanel/internal/contraction"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	goaccessruntime "lanpanel/internal/goaccess"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"lanpanel/internal/safety"
	"slices"
	"time"
)

type goaccessGeneration struct {
	generation      uint64
	stateGeneration uint64
	retiredIdentity string
	removeState     bool
	removeShared    bool
	installationID  string
	unitIdentities  []string
}
type CloseAllExecution struct {
	Service             *FixedService
	Admitter            *operations.Admitter
	MutationSet         *operations.MutationSet
	Mutation            *operations.MutationLease
	Exposure            *locks.Lease
	Authority           *contraction.NormalAuthority
	Inventory           closure.Inventory
	Installation        domain.Installation
	SafetyState         safety.State
	OwnershipAuthority  map[string]string
	GoAccessGenerations map[string][]goaccessGeneration
}

func BeginCloseAll(ctx context.Context, actor Actor, payload ConfirmationPayload) (*CloseAllExecution, error) {
	return beginContraction(ctx, actor, domain.OperationCloseAll, domain.OperationTarget{Kind: domain.OperationTargetInstallation}, payload)
}

func BeginUnpublish(ctx context.Context, actor Actor, target domain.OperationTarget, payload ConfirmationPayload) (*CloseAllExecution, error) {
	return beginContraction(ctx, actor, domain.OperationUnpublish, target, payload)
}

func beginContraction(ctx context.Context, actor Actor, operation domain.OperationCode, target domain.OperationTarget, payload ConfirmationPayload) (*CloseAllExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*CloseAllExecution, error) { _ = service.Close(); return nil, cause }
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	plan, err := service.ReadPlan(payload.PlanID)
	confirmation := "close"
	if operation == domain.OperationUnpublish {
		confirmation = "unpublish"
	}
	if err != nil || plan.Operation != string(operation) || plan.ActorIdentity != authority || plan.Target.Kind != plans.TargetKind(target.Kind) || plan.Target.ID != target.ID || payload.Confirmation != confirmation {
		return fail(fmt.Errorf("contraction confirmation is invalid"))
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return fail(err)
	}
	document, err := service.Normal().Read()
	if err != nil {
		return fail(err)
	}
	state, err := service.SafetyState()
	if err != nil || plan.Config.Digest != state.Checksum {
		return fail(fmt.Errorf("close-all safety binding changed"))
	}
	admission, err := service.Manager().Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	operationType := operations.CloseAll
	operationTarget := "installation"
	binding := operations.SafetyBinding{GlobalGeneration: state.GlobalClose.Generation, ProposedGeneration: state.GlobalClose.Generation + 1}
	resourceIDs := []string{}
	global := true
	if operation == domain.OperationUnpublish {
		operationType = operations.Unpublish
		operationTarget = "resource/" + target.ID
		binding = operations.SafetyBinding{ResourceID: target.ID}
		resourceIDs = []string{target.ID}
		global = false
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operationType, Target: operationTarget, ActorIdentity: authority, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: binding, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil {
		return fail(err)
	}
	if releaseErr != nil {
		return fail(releaseErr)
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: "/var/lib/lanpanel/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, operationTarget, service.Manager())
	if err != nil {
		_ = mutationSet.Close()
		return fail(err)
	}
	freshDocument, normalErr := service.Normal().Read()
	freshState, safetyErr := service.SafetyState()
	freshOwnership, ownershipErr := service.OwnershipInventory()
	freshManifest, graphErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	lockedErr := errors.Join(normalErr, safetyErr, ownershipErr, graphErr)
	if freshDocument.Revision != document.Revision+1 || freshState.Checksum != plan.Config.Digest {
		lockedErr = errors.Join(lockedErr, fmt.Errorf("contraction authority changed after lock acquisition"))
	}
	freshRaw, present := freshDocument.Entries["installations/current"]
	if !present {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(fmt.Errorf("normal installation authority disappeared"))
	}
	freshInstallation, decodeErr := domain.DecodeInstallation(freshRaw)
	inventoryInputs := closure.Inputs{Installation: freshInstallation, Safety: &freshState, Ownership: freshOwnership, Graph: &freshManifest, ResourceIDs: resourceIDs}
	inventory, inventoryErr := closure.BuildInventory(inventoryInputs)
	if inventoryErr != nil {
		inventory = closure.BuildFallbackInventory(inventoryInputs, inventoryErr)
	}
	generations, generationErr := contractionGenerations(freshInstallation, freshState, resourceIDs)
	lockedErr = errors.Join(lockedErr, decodeErr, inventoryErr, generationErr)
	if generationErr != nil {
		global = true
	}
	if lockedErr != nil || !inventory.Complete {
		var forceErr error
		inventory, forceErr = closure.ForceUncertain(inventory, "locked_authority_changed", "confirmed_contraction")
		if forceErr != nil {
			inventory = closure.BuildFallbackInventory(inventoryInputs, forceErr)
		}
	}
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: freshDocument.Revision, IntentGeneration: freshDocument.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(err)
	}
	goaccessIDs := goAccessContractionInventory(freshInstallation, resourceIDs)
	ownershipAuthority := map[string]string{}
	if freshOwnership.Complete {
		for _, record := range freshOwnership.Records {
			ownershipAuthority[record.ResourceID] = record.Checksum
		}
	}
	return &CloseAllExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, Inventory: inventory, Installation: freshInstallation, SafetyState: freshState, OwnershipAuthority: ownershipAuthority, GoAccessGenerations: goaccessIDs, Authority: &contraction.NormalAuthority{Safety: service.SafetyStore(), Emergency: service.EmergencyStore(), Admitter: admitter, Mutation: mutation, Exposure: exposure, JobID: job.ID, PlanID: plan.ID, Operation: operations.Type(operation), Revision: intent.IntentGeneration, SafetyState: freshState, Generations: generations, Global: global}}, nil
}

func contractionGenerations(installation domain.Installation, state safety.State, selectedIDs []string) (map[string]uint64, error) {
	normal := make(map[string]uint64, len(installation.Resources))
	for _, resource := range installation.Resources {
		normal[resource.ID] = resource.PublicationRecord.UnpublishedGeneration
	}
	selected := func(id string) bool { return len(selectedIDs) == 0 || id == selectedIDs[0] }
	result := make(map[string]uint64, len(state.Resources))
	var mismatch error
	for _, resource := range state.Resources {
		if !selected(resource.ResourceID) {
			delete(normal, resource.ResourceID)
			continue
		}
		high, present := normal[resource.ResourceID]
		if !present {
			mismatch = errors.Join(mismatch, fmt.Errorf("safety App lacks normal resource identity"))
			high = resource.GenerationSequence
		}
		if resource.GenerationSequence > high {
			high = resource.GenerationSequence
		}
		result[resource.ResourceID] = high + 1
		delete(normal, resource.ResourceID)
	}
	if len(normal) != 0 || len(result) == 0 && len(selectedIDs) != 0 {
		mismatch = errors.Join(mismatch, fmt.Errorf("normal and safety App identities are not one-to-one"))
	}
	return result, mismatch
}

func (execution *CloseAllExecution) Run(ctx context.Context) (contraction.Result, error) {
	if execution == nil || execution.Authority == nil {
		return contraction.Result{}, fmt.Errorf("close-all execution is inactive")
	}
	host, err := contraction.FixedHost(execution.Inventory)
	if err != nil {
		fallback, fallbackErr := contraction.FixedFallbackHost(execution.Inventory)
		if fallbackErr != nil {
			return contraction.Result{}, errors.Join(err, fallbackErr, execution.Close())
		}
		uncertain, uncertaintyErr := closure.ForceUncertain(execution.Inventory, "runtime_authority_unavailable", "fixed_host")
		if uncertaintyErr != nil {
			return contraction.Result{}, errors.Join(err, uncertaintyErr, execution.Close())
		}
		execution.Inventory = uncertain
		result, runErr := (contraction.Engine{Authority: execution.Authority, Runtime: fallback}).Run(ctx, uncertain)
		result, runErr, cleanupComplete := execution.stopGoAccessAfterClosure(ctx, result, runErr)
		if !cleanupComplete && !result.AccessClosed {
			return result, errors.Join(runErr, execution.Close())
		}
		recoveryCtx, cancelRecovery := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		recoveredPaths, recoveryErr := fallback.ContractDisk(recoveryCtx, uncertain)
		cancelRecovery()
		if recoveryErr != nil {
			return result, errors.Join(runErr, recoveryErr, execution.Close())
		}
		result.ModifiedPaths = append(result.ModifiedPaths, recoveredPaths...)
		_, completeErr := contraction.CompleteNormal(ctx, execution.Authority, result)
		var acknowledgeErr, convergeErr error
		if completeErr == nil {
			acknowledgeErr = fallback.AcknowledgeDiskContraction(context.WithoutCancel(ctx), uncertain)
		}
		if completeErr == nil && acknowledgeErr == nil {
			convergeErr = execution.Authority.ConvergeClosure(context.WithoutCancel(ctx), uncertain, result.ClosureDigest)
		}
		closeErr := execution.Close()
		if completeErr == nil && acknowledgeErr == nil && convergeErr == nil && closeErr == nil && (result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown) {
			return result, nil
		}
		return result, errors.Join(err, runErr, completeErr, acknowledgeErr, convergeErr, closeErr)
	}
	host.Guard = func(manifest nginx.Manifest) error {
		decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: execution.SafetyState, Installation: &execution.Installation, Ownership: execution.OwnershipAuthority, Now: time.Now().UTC()})
		if !decision.Allowed {
			return fmt.Errorf("selective closure preserved control is unsafe: %s", decision.Reason)
		}
		return nil
	}
	result, runErr := (contraction.Engine{Authority: execution.Authority, Runtime: host}).Run(ctx, execution.Inventory)
	result, runErr, cleanupComplete := execution.stopGoAccessAfterClosure(ctx, result, runErr)
	if !cleanupComplete && !result.AccessClosed {
		return result, errors.Join(runErr, execution.Close())
	}
	recoveryCtx, cancelRecovery := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	recoveredPaths, recoveryErr := host.ContractDisk(recoveryCtx, execution.Inventory)
	cancelRecovery()
	if recoveryErr != nil {
		return result, errors.Join(runErr, recoveryErr, execution.Close())
	}
	result.ModifiedPaths = append(result.ModifiedPaths, recoveredPaths...)
	_, completeErr := contraction.CompleteNormal(ctx, execution.Authority, result)
	var acknowledgeErr, convergeErr error
	if completeErr == nil {
		acknowledgeErr = host.AcknowledgeDiskContraction(context.WithoutCancel(ctx), execution.Inventory)
	}
	if completeErr == nil && acknowledgeErr == nil {
		convergeErr = execution.Authority.ConvergeClosure(context.WithoutCancel(ctx), execution.Inventory, result.ClosureDigest)
	}
	closeErr := execution.Close()
	if completeErr != nil || acknowledgeErr != nil || convergeErr != nil || closeErr != nil {
		return result, errors.Join(runErr, completeErr, acknowledgeErr, convergeErr, closeErr)
	}
	if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
		return result, nil
	}
	return result, runErr
}

func goAccessContractionInventory(installation domain.Installation, resourceIDs []string) map[string][]goaccessGeneration {
	result := map[string][]goaccessGeneration{}
	selected := func(id string) bool {
		if len(resourceIDs) == 0 {
			return true
		}
		return slices.Contains(resourceIDs, id)
	}
	for _, resource := range installation.Resources {
		if !selected(resource.ID) {
			continue
		}
		add := func(identity domain.GoAccessBundleIdentity, candidate bool) {
			values := []goaccessGeneration{}
			if identity.Enabled {
				value := goaccessGeneration{generation: identity.Generation, stateGeneration: identity.StateGeneration, installationID: installation.InstallationID, unitIdentities: append([]string(nil), identity.UnitIdentities...)}
				if candidate {
					value.retiredIdentity = identity.ServiceIdentity
					value.removeState = identity.StateGeneration == identity.Generation
					value.removeShared = !goAccessSharedRetained(resource)
				}
				values = append(values, value)
			}
			if identity.RetiredGeneration != 0 {
				values = append(values, goaccessGeneration{generation: identity.RetiredGeneration, stateGeneration: identity.RetiredStateGeneration, retiredIdentity: identity.RetiredServiceIdentity, installationID: installation.InstallationID, unitIdentities: append([]string(nil), identity.RetiredUnitIdentities...)})
			}
			for _, value := range values {
				duplicate := false
				for _, prior := range result[resource.ID] {
					if prior.generation == value.generation {
						duplicate = true
					}
				}
				if !duplicate {
					result[resource.ID] = append(result[resource.ID], value)
				}
			}
		}
		if applied := resource.PublicationRecord.LastAppliedBundle; applied != nil && applied.DomainHTTPS != nil {
			add(applied.DomainHTTPS.GoAccess, false)
		}
		if activation := resource.PublicationRecord.ActivationIntent; activation != nil && activation.Candidate.DomainHTTPS != nil {
			add(activation.Candidate.DomainHTTPS.GoAccess, true)
		}
		for _, pending := range resource.PublicationRecord.PendingGoAccessRetirements {
			matched := false
			for index := range result[resource.ID] {
				item := &result[resource.ID][index]
				if item.generation == pending.Generation {
					item.stateGeneration = pending.StateGeneration
					item.retiredIdentity = pending.ServiceIdentity
					item.unitIdentities = append([]string(nil), pending.UnitIdentities...)
					item.removeState = item.removeState || pending.RemoveState
					item.removeShared = item.removeShared || pending.RemoveShared
					matched = true
				}
			}
			if !matched {
				result[resource.ID] = append(result[resource.ID], goaccessGeneration{generation: pending.Generation, stateGeneration: pending.StateGeneration, retiredIdentity: pending.ServiceIdentity, removeState: pending.RemoveState, removeShared: pending.RemoveShared, installationID: installation.InstallationID, unitIdentities: append([]string(nil), pending.UnitIdentities...)})
			}
		}
	}
	return result
}

const goAccessContractionCleanupTimeout = time.Minute

type goAccessContractionHost interface {
	Stop(context.Context, string, uint64) error
	Retire(context.Context, string, uint64, string, []string) error
	RemoveGenerationState(context.Context, string, uint64) error
	CleanupUncommittedShared(context.Context, string, string) error
}

func stopGoAccessAfterClosure(_ context.Context, generations map[string][]goaccessGeneration, result contraction.Result, runErr error) (contraction.Result, error, bool) {
	generationCount := 0
	for _, items := range generations {
		generationCount += len(items)
	}
	if generationCount == 0 {
		return result, runErr, true
	}
	overallTimeout, budgetErr := goAccessContractionTimeout(generationCount)
	if budgetErr != nil {
		return finishGoAccessClosureFailure(result, runErr, budgetErr)
	}
	stopCtx, cancelStop := context.WithTimeout(context.Background(), overallTimeout)
	defer cancelStop()
	host, stopErr := goaccessruntime.NewFixedHost()
	if stopErr == nil {
		result, stopErr = stopGoAccessGenerations(stopCtx, host, goaccessruntime.GenerationRetirementTimeout, goAccessContractionCleanupTimeout, generations, result)
	}
	if stopErr != nil {
		return finishGoAccessClosureFailure(result, runErr, stopErr)
	}
	return result, runErr, true
}

func goAccessContractionTimeout(generationCount int) (time.Duration, error) {
	generationTimeout := goaccessruntime.GenerationRetirementTimeout + goAccessContractionCleanupTimeout
	if generationCount <= 0 || generationCount > int(time.Duration(1<<63-1)/generationTimeout) {
		return 0, fmt.Errorf("GoAccess contraction generation budget is invalid or overflowed")
	}
	return time.Duration(generationCount) * generationTimeout, nil
}

func stopGoAccessGenerations(ctx context.Context, host goAccessContractionHost, retirementTimeout, cleanupTimeout time.Duration, generations map[string][]goaccessGeneration, result contraction.Result) (contraction.Result, error) {
	if ctx == nil || host == nil || retirementTimeout <= 0 || cleanupTimeout <= 0 {
		return result, fmt.Errorf("GoAccess contraction cleanup budget is invalid")
	}
	var stopErr error
	for resourceID, items := range generations {
		for _, generation := range items {
			retirementCtx, cancelRetirement := context.WithTimeout(ctx, retirementTimeout)
			if generation.retiredIdentity == "" {
				paths, pathErr := operations.GoAccessStopModifiedPaths(resourceID, generation.generation)
				result.ModifiedPaths = append(result.ModifiedPaths, paths...)
				stopErr = errors.Join(stopErr, pathErr, host.Stop(retirementCtx, resourceID, generation.generation))
				cancelRetirement()
				continue
			}
			currentErr := host.Retire(retirementCtx, resourceID, generation.generation, generation.retiredIdentity, generation.unitIdentities)
			cancelRetirement()
			if currentErr == nil && (generation.removeState || generation.removeShared) {
				cleanupCtx, cancelCleanup := context.WithTimeout(ctx, cleanupTimeout)
				if generation.removeState {
					currentErr = host.RemoveGenerationState(cleanupCtx, resourceID, generation.stateGeneration)
				}
				if currentErr == nil && generation.removeShared {
					currentErr = host.CleanupUncommittedShared(cleanupCtx, generation.installationID, resourceID)
				}
				cancelCleanup()
			}
			if currentErr == nil {
				paths, pathErr := operations.GoAccessRetirementModifiedPaths(resourceID, domain.GoAccessRetirementIdentity{Generation: generation.generation, StateGeneration: generation.stateGeneration, ServiceIdentity: generation.retiredIdentity, RemoveState: generation.removeState, RemoveShared: generation.removeShared, UnitIdentities: append([]string(nil), generation.unitIdentities...)})
				currentErr = pathErr
				result.ModifiedPaths = append(result.ModifiedPaths, paths...)
			}
			stopErr = errors.Join(stopErr, currentErr)
		}
	}
	return result, stopErr
}

func finishGoAccessClosureFailure(result contraction.Result, runErr, stopErr error) (contraction.Result, error, bool) {
	if result.AccessClosed {
		result.Outcome = contraction.OutcomePartial
		result.ErrorCode = "goaccess_stop_failed"
	}
	return result, errors.Join(runErr, stopErr), false
}

func pruneGoAccessContractionOwnership(_ context.Context, service *FixedService, exposure *locks.Lease, sourceJobID string, generations map[string][]goaccessGeneration) error {
	pruneCtx, cancelPrune := context.WithTimeout(context.Background(), time.Minute)
	defer cancelPrune()
	var result error
	for resourceID, items := range generations {
		for _, item := range items {
			if item.retiredIdentity != "" {
				result = errors.Join(result, pruneRetiredGoAccessOwnership(pruneCtx, service, exposure, resourceID, sourceJobID, item.generation, item.stateGeneration, item.removeState, item.removeShared))
			}
		}
	}
	return result
}

func (execution *CloseAllExecution) stopGoAccessAfterClosure(ctx context.Context, result contraction.Result, runErr error) (contraction.Result, error, bool) {
	var cleanupComplete bool
	result, runErr, cleanupComplete = stopGoAccessAfterClosure(ctx, execution.GoAccessGenerations, result, runErr)
	if cleanupComplete {
		if pruneErr := pruneGoAccessContractionOwnership(ctx, execution.Service, execution.Exposure, execution.Authority.JobID, execution.GoAccessGenerations); pruneErr != nil {
			cleanupComplete = false
			if result.AccessClosed {
				result.Outcome = contraction.OutcomePartial
				result.ErrorCode = "goaccess_stop_failed"
			}
			runErr = errors.Join(runErr, pruneErr)
		}
	}
	return result, runErr, cleanupComplete
}

func (execution *CloseAllExecution) Close() error {
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
	execution.Mutation, execution.Exposure = nil, nil
	return err
}
