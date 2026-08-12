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
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"lanpanel/internal/safety"
)

type CloseAllExecution struct {
	Service     *FixedService
	Admitter    *operations.Admitter
	MutationSet *operations.MutationSet
	Mutation    *operations.MutationLease
	Exposure    *locks.Lease
	Authority   *contraction.NormalAuthority
	Inventory   closure.Inventory
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
	return &CloseAllExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, Inventory: inventory, Authority: &contraction.NormalAuthority{Safety: service.SafetyStore(), Emergency: service.EmergencyStore(), Admitter: admitter, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: intent.IntentGeneration, SafetyState: freshState, Generations: generations, Global: global}}, nil
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
		_, completeErr := contraction.CompleteNormal(ctx, execution.Authority, result)
		closeErr := execution.Close()
		if completeErr == nil && closeErr == nil && (result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown) {
			return result, nil
		}
		return result, errors.Join(err, runErr, completeErr, closeErr)
	}
	result, runErr := (contraction.Engine{Authority: execution.Authority, Runtime: host}).Run(ctx, execution.Inventory)
	_, completeErr := contraction.CompleteNormal(ctx, execution.Authority, result)
	closeErr := execution.Close()
	if completeErr != nil || closeErr != nil {
		return result, errors.Join(runErr, completeErr, closeErr)
	}
	if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
		return result, nil
	}
	return result, runErr
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
