//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	manageddeletion "lanpanel/internal/deletion"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/plans"
	managedprocess "lanpanel/internal/process"
	managedresource "lanpanel/internal/resource"
	"lanpanel/internal/safety"
	"os"
)

type ResourceDeleteResult struct {
	JobID string `json:"job_id"`
}

const (
	deletePasswdPath = "/etc/passwd"
	deleteGroupPath  = "/etc/group"
	deleteShadowPath = "/etc/shadow"
)

func exactDeleteOwnership(resource domain.AppResource, record ownership.Record) bool {
	return exactDeleteOwnershipID(resource.ID, record)
}

func exactDeleteOwnershipID(resourceID string, record ownership.Record) bool {
	paths, err := managedresource.DerivePaths(resourceID)
	return err == nil && len(record.Listeners) == 0 && len(record.Paths) == 1 && record.Paths[0].Kind == ownership.PathService && record.Paths[0].Path == paths.ResourceRoot && record.Paths[0].IdentityDigest == ownership.PathIdentity(resourceID, ownership.PathService, paths.ResourceRoot)
}

func DeleteResource(ctx context.Context, actor Actor, target domain.OperationTarget, payload ConfirmationPayload) (ResourceDeleteResult, error) {
	if target.Kind != domain.OperationTargetResource || payload.PlanID == "" || payload.Confirmation != "delete" {
		return ResourceDeleteResult{}, fmt.Errorf("resource delete confirmation invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	actorID, err := actorAuthority(actor)
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	plan, err := service.ReadPlan(payload.PlanID)
	if err != nil || plan.Operation != string(domain.OperationResourceDelete) || plan.Target.Kind != plans.TargetResource || plan.Target.ID != target.ID || plan.ActorIdentity != actorID {
		return ResourceDeleteResult{}, fmt.Errorf("resource delete Plan authority invalid")
	}
	document, err := service.normal.Read()
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == target.ID {
			copy := installation.Resources[index]
			resource = &copy
		}
	}
	if resource == nil || resource.Lifecycle != domain.LifecycleActive || resource.PublicationRecord.State != domain.PublicationUnpublished || plan.Config.Digest != resource.CurrentConfigDigest || resource.ManagedProcess != nil && resource.ManagedProcess.Requested != domain.ProcessRequestedStopped || resourceHasManagedCredential(installation, target.ID) {
		return ResourceDeleteResult{}, fmt.Errorf("resource delete closure changed")
	}
	owned, err := service.ownership.Read(target.ID)
	if err != nil || owned.State != ownership.Owned || owned.Checksum != plan.Applied.Digest || !exactDeleteOwnership(*resource, owned) {
		return ResourceDeleteResult{}, fmt.Errorf("resource delete ownership is not freshly closed: %w", err)
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ResourceDelete, Target: "resource/" + target.ID, ActorIdentity: actorID, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{ResourceID: target.ID, CandidateDigest: resource.CurrentConfigDigest, CandidateBundle: owned.Checksum, PlanID: plan.ID}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		return ResourceDeleteResult{}, errors.Join(admitErr, releaseErr)
	}
	set, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return ResourceDeleteResult{}, rejectReservedResourceDelete(ctx, service, admitter, job.ID, err)
	}
	defer func(ignore func() error) { _ = ignore() }(set.Close)
	mutation, exposure, err := set.AcquireExposure(ctx, "resource/"+target.ID, service.manager)
	if err != nil {
		return ResourceDeleteResult{}, rejectReservedResourceDelete(ctx, service, admitter, job.ID, err)
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	fresh, err := service.normal.Read()
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		return ResourceDeleteResult{}, rejectReservedResourceDelete(ctx, service, admitter, job.ID, err)
	}
	if _, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest}); err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		return ResourceDeleteResult{}, rejectReservedResourceDelete(ctx, service, admitter, job.ID, err)
	}
	fresh, err = service.normal.Read()
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	freshInstallation, decodeErr := domain.DecodeInstallation(fresh.Entries["installations/current"])
	if decodeErr != nil {
		return ResourceDeleteResult{}, decodeErr
	}
	var freshResource *domain.AppResource
	for index := range freshInstallation.Resources {
		if freshInstallation.Resources[index].ID == target.ID {
			copy := freshInstallation.Resources[index]
			freshResource = &copy
		}
	}
	freshOwned, ownershipErr := service.ownership.Read(target.ID)
	deleteClosureDigest := digestLifecycle(struct{ ResourceID, ConfigDigest string }{target.ID, resource.CurrentConfigDigest})
	closedErr := error(nil)
	if freshResource == nil || freshResource.Lifecycle != domain.LifecycleActive || freshResource.PublicationRecord.State != domain.PublicationUnpublished || freshResource.CurrentConfigDigest != resource.CurrentConfigDigest || resourceHasManagedCredential(freshInstallation, target.ID) || ownershipErr != nil || freshOwned.Checksum != owned.Checksum || freshResource != nil && !exactDeleteOwnership(*freshResource, freshOwned) {
		closedErr = fmt.Errorf("resource delete authority changed under lock: %w", ownershipErr)
	} else {
		closedErr = verifyDeleteRuntimeClosed(ctx, *freshResource)
	}
	if closedErr != nil {
		_, terminalErr := admitter.CompleteRecoveredResourceDelete(context.WithoutCancel(ctx), mutation, exposure, fresh.Revision, job.ID, target.ID, deleteClosureDigest, false)
		return ResourceDeleteResult{}, errors.Join(closedErr, terminalErr)
	}
	resource = freshResource
	installation = freshInstallation
	owned = freshOwned
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	found := false
	tombstone := "delete/" + job.ID
	for index := range next.Resources {
		if next.Resources[index].ResourceID == target.ID {
			if next.Resources[index].StickyUnpublished == nil || next.Resources[index].Ownership != safety.OwnershipOwned {
				return ResourceDeleteResult{}, fmt.Errorf("resource delete safety closure changed")
			}
			next.Resources[index].State = safety.ResourceDeleting
			next.Resources[index].DeletionTombstone = tombstone
			found = true
		}
	}
	if !found {
		return ResourceDeleteResult{}, fmt.Errorf("resource delete safety identity missing")
	}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleDelete, state.Revision, next, safety.TransitionProof{}); err != nil {
		return ResourceDeleteResult{}, err
	}
	fresh, _ = service.normal.Read()
	if err := admitter.CommitResourceDeleteBegin(ctx, mutation, exposure, fresh.Revision, job.ID, target.ID); err != nil {
		return ResourceDeleteResult{}, err
	}
	resource.Lifecycle = domain.LifecycleDeleting
	resource.PublicationRecord.LastJobID = job.ID
	if resource.ManagedProcess != nil && resource.ManagedProcess.Applied != nil {
		observation, observeErr := managedprocess.Observe(ctx, "/sys/fs/cgroup", *resource.ManagedProcess.Applied, resource.Target.LocalHTTP.EndpointKind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
		if observeErr != nil || managedprocess.VerifyStopped(observation) != nil {
			return ResourceDeleteResult{}, errors.Join(observeErr, fmt.Errorf("resource cgroup or listener is not stopped"))
		}
	}
	removed, err := cleanupDeleteInventory(*resource, installation)
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	closureDigest := digestLifecycle(struct{ ResourceID, ConfigDigest string }{resource.ID, resource.CurrentConfigDigest})
	current, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return ResourceDeleteResult{}, err
	}
	after := current
	after.Revision++
	after.Resources = []safety.ResourceSafety{}
	for _, item := range current.Resources {
		if item.ResourceID != target.ID {
			after.Resources = append(after.Resources, item)
		}
	}
	proof := &safety.DeleteConvergenceProof{ResourceID: target.ID, TombstoneRef: tombstone, OwnershipDigest: owned.Checksum, RuntimeClosureDigest: closureDigest}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleDelete, current.Revision, after, safety.TransitionProof{Delete: proof}); err != nil {
		return ResourceDeleteResult{}, err
	}
	if err := service.ownership.Delete(ctx, exposure, owned); err != nil {
		return ResourceDeleteResult{}, err
	}
	fresh, _ = service.normal.Read()
	if err := admitter.CommitResourceDeleteRemoval(ctx, mutation, exposure, fresh.Revision, job.ID, target.ID); err != nil {
		return ResourceDeleteResult{}, err
	}
	fresh, _ = service.normal.Read()
	if _, err := admitter.Complete(ctx, mutation, exposure, fresh.Revision, job.ID, "complete", removed, []jobs.Postcondition{{Kind: "resource_managed_inventory_deleted", Status: jobs.PostconditionVerified, Identity: closureDigest}}, ""); err != nil {
		return ResourceDeleteResult{}, err
	}
	return ResourceDeleteResult{JobID: job.ID}, nil
}

// ReconcileResourceDeletes resumes only a durable consumed delete intent. It
// never recreates a resource or repeats a remote action.
func ReconcileResourceDeletes(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	pending := []operations.Reservation{}
	for key, raw := range document.Entries {
		if len(key) < 8 || key[:8] != "intents/" {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) == nil && intent.Operation == operations.ResourceDelete && (intent.Phase == operations.PhaseReserved || intent.Phase == operations.PhaseLocalIntent) {
			pending = append(pending, intent)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return err
	}
	set, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(set.Close)
	var result error
	for _, intent := range pending {
		if intent.Phase == operations.PhaseReserved {
			lease, acquireErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if acquireErr != nil {
				result = errors.Join(result, acquireErr)
				continue
			}
			fresh, readErr := service.normal.Read()
			if readErr == nil {
				readErr = admitter.RejectReservation(ctx, lease, fresh.Revision, intent.JobID, "plan_consumption_rejected")
			}
			result = errors.Join(result, readErr, lease.Release())
			continue
		}
		resourceID := intent.SafetyBinding.ResourceID
		mutation, exposure, acquireErr := set.AcquireExposure(ctx, "resource/"+resourceID, service.manager)
		if acquireErr != nil {
			result = errors.Join(result, acquireErr)
			continue
		}
		reconcileErr := reconcileResourceDelete(ctx, service, admitter, mutation, exposure, intent)
		result = errors.Join(result, reconcileErr, operations.ReleaseExposure(mutation, exposure))
	}
	return result
}

func reconcileResourceDelete(ctx context.Context, service *FixedService, admitter *operations.Admitter, mutation *operations.MutationLease, exposure *locks.Lease, intent operations.Reservation) error {
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return err
	}
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == intent.SafetyBinding.ResourceID {
			copy := installation.Resources[index]
			resource = &copy
		}
	}
	closureDigest := digestLifecycle(struct{ ResourceID, ConfigDigest string }{intent.SafetyBinding.ResourceID, intent.SafetyBinding.CandidateDigest})
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	var safetyResource *safety.ResourceSafety
	for index := range state.Resources {
		if state.Resources[index].ResourceID == intent.SafetyBinding.ResourceID {
			safetyResource = &state.Resources[index]
		}
	}
	if safetyResource != nil && safetyResource.State != safety.ResourceDeleting {
		return completeRecoveredDelete(ctx, service, admitter, mutation, exposure, intent, closureDigest, false)
	}
	owned, ownershipErr := service.ownership.Read(intent.SafetyBinding.ResourceID)
	ownershipPresent := ownershipErr == nil
	if ownershipErr != nil && !errors.Is(ownershipErr, os.ErrNotExist) {
		return ownershipErr
	}
	if ownershipPresent && (owned.Checksum != intent.SafetyBinding.CandidateBundle || !exactDeleteOwnershipID(intent.SafetyBinding.ResourceID, owned)) {
		return fmt.Errorf("recovered resource delete ownership changed")
	}
	if safetyResource != nil {
		if safetyResource.DeletionTombstone != "delete/"+intent.JobID || !ownershipPresent {
			return fmt.Errorf("recovered resource delete tombstone or ownership changed")
		}
		if resource == nil {
			return fmt.Errorf("recovered resource delete lost normal resource before safety convergence")
		}
		if resource.Lifecycle == domain.LifecycleActive {
			if err := admitter.CommitResourceDeleteBegin(ctx, mutation, exposure, document.Revision, intent.JobID, resource.ID); err != nil {
				return err
			}
			resource.Lifecycle = domain.LifecycleDeleting
			resource.PublicationRecord.LastOperation = domain.OperationResourceDelete
			resource.PublicationRecord.LastJobID = intent.JobID
		} else if resource.Lifecycle != domain.LifecycleDeleting {
			return fmt.Errorf("recovered resource delete lifecycle changed")
		}
		if err := verifyDeleteRuntimeClosed(ctx, *resource); err != nil {
			return err
		}
		if _, err := cleanupDeleteInventory(*resource, installation); err != nil {
			return err
		}
		after := state
		after.Revision++
		after.Resources = []safety.ResourceSafety{}
		for _, item := range state.Resources {
			if item.ResourceID != resource.ID {
				after.Resources = append(after.Resources, item)
			}
		}
		proof := &safety.DeleteConvergenceProof{ResourceID: resource.ID, TombstoneRef: "delete/" + intent.JobID, OwnershipDigest: owned.Checksum, RuntimeClosureDigest: closureDigest}
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleDelete, state.Revision, after, safety.TransitionProof{Delete: proof}); err != nil {
			return err
		}
	}
	if safetyResource == nil && resource != nil {
		if resource.Lifecycle != domain.LifecycleDeleting {
			return fmt.Errorf("recovered resource delete is not deleting")
		}
		if err := verifyDeleteRuntimeClosed(ctx, *resource); err != nil {
			return err
		}
		if _, err := cleanupDeleteInventory(*resource, installation); err != nil {
			return err
		}
	}
	if ownershipPresent {
		if err := service.ownership.Delete(ctx, exposure, owned); err != nil {
			return err
		}
	}
	document, err = service.normal.Read()
	if err != nil {
		return err
	}
	installation, err = domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return err
	}
	present := false
	for _, item := range installation.Resources {
		if item.ID == intent.SafetyBinding.ResourceID {
			present = true
			resource = &item
		}
	}
	if present {
		if resource.Lifecycle != domain.LifecycleDeleting {
			return fmt.Errorf("recovered resource delete is not deleting")
		}
		if err := verifyDeleteRuntimeClosed(ctx, *resource); err != nil {
			return err
		}
		if _, err := cleanupDeleteInventory(*resource, installation); err != nil {
			return err
		}
		if err := admitter.CommitResourceDeleteRemoval(ctx, mutation, exposure, document.Revision, intent.JobID, resource.ID); err != nil {
			return err
		}
	}
	return completeRecoveredDelete(ctx, service, admitter, mutation, exposure, intent, closureDigest, true)
}

func resourceHasManagedCredential(installation domain.Installation, resourceID string) bool {
	for _, credential := range installation.Credentials {
		if credential.OwnerResourceID == resourceID && credential.Kind == "managed_basic" {
			return true
		}
	}
	return false
}

func rejectReservedResourceDelete(ctx context.Context, service *FixedService, admitter *operations.Admitter, jobID string, cause error) error {
	lease, err := service.manager.Acquire(context.WithoutCancel(ctx), locks.MutationAdmission)
	if err != nil {
		return errors.Join(cause, err)
	}
	defer func() { _ = lease.Release() }()
	document, err := service.normal.Read()
	if err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, admitter.RejectReservation(context.WithoutCancel(ctx), lease, document.Revision, jobID, "plan_consumption_rejected"))
}

func verifyDeleteRuntimeClosed(ctx context.Context, resource domain.AppResource) error {
	if resource.ManagedProcess == nil {
		return nil
	}
	if resource.ManagedProcess.Requested != domain.ProcessRequestedStopped {
		return fmt.Errorf("resource process is not requested stopped")
	}
	if resource.ManagedProcess.Applied == nil {
		return nil
	}
	observation, err := managedprocess.Observe(ctx, "/sys/fs/cgroup", *resource.ManagedProcess.Applied, resource.Target.LocalHTTP.EndpointKind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
	if err != nil {
		return err
	}
	return managedprocess.VerifyStopped(observation)
}

func cleanupDeleteInventory(resource domain.AppResource, installation domain.Installation) ([]string, error) {
	return cleanupDeleteInventoryWithCleanup(resource, installation, deletePasswdPath, deleteGroupPath, deleteShadowPath, manageddeletion.Cleanup)
}

func cleanupDeleteInventoryWithCleanup(resource domain.AppResource, installation domain.Installation, passwdPath, groupPath, shadowPath string, cleanup func(domain.AppResource, []uint32) ([]string, error)) ([]string, error) {
	if cleanup == nil {
		return nil, fmt.Errorf("resource deletion cleanup is unavailable")
	}
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		return cleanup(resource, nil)
	}
	accountSet, err := identity.ResourceAccounts(installation.InstallationID, resource.ID, resource.Target.LocalHTTP != nil && resource.Target.LocalHTTP.EndpointKind == domain.LocalEndpointRelayUnix)
	if err != nil {
		return nil, fmt.Errorf("construct resource deletion accounts: %w", err)
	}
	_, accounts, err := identity.InspectResourceAccountFiles(accountSet, passwdPath, groupPath, shadowPath)
	if err != nil {
		return nil, fmt.Errorf("inspect resource deletion accounts: %w", err)
	}
	uids := make([]uint32, 0, len(accounts))
	for _, account := range accounts {
		uids = append(uids, account.UID)
	}
	return cleanup(resource, uids)
}

func completeRecoveredDelete(ctx context.Context, service *FixedService, admitter *operations.Admitter, mutation *operations.MutationLease, exposure *locks.Lease, intent operations.Reservation, closureDigest string, succeeded bool) error {
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	_, err = admitter.CompleteRecoveredResourceDelete(ctx, mutation, exposure, document.Revision, intent.JobID, intent.SafetyBinding.ResourceID, closureDigest, succeeded)
	return err
}
