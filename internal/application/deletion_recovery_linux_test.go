//go:build linux

package application

import (
	"context"
	"errors"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"lanpanel/internal/safety"
	"reflect"
	"testing"
)

func newDeleteRecoveryFixture(t *testing.T) (resourceRecoveryFixture, operations.Reservation) {
	t.Helper()
	ctx := context.Background()
	resource := recoveryTailnetResource()
	resource.PublicationRecord.CertificateInventory = []certificates.Artifact{{CertificateID: "cert_00000000000000000000000000000001", Generation: 1, Bundle: certificates.BundleIdentity{Fingerprint: recoveryDigest("cert"), SANIdentity: recoveryDigest("san"), ChainIdentity: recoveryDigest("chain"), IssuerIdentity: recoveryDigest("issuer"), BindingIdentity: recoveryDigest("binding"), DirectoryIdentity: recoveryDigest("directory")}}}
	installation := recoveryResourceInstallation(&resource)
	fixture := newResourceRecoveryFixture(t, installation)
	service := fixture.open(t)
	defer func() { _ = service.Close() }()
	set, mutation, exposure := fixture.acquire(t, service, "resource/"+resource.ID)
	owned := writeRecoveryOwnershipAndSafety(t, service, exposure, resource.ID)
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()); err != nil {
		t.Fatal(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	store, err := plans.NewStore(service.normal, plans.Options{})
	if err != nil {
		t.Fatal(err)
	}
	document, _ := service.normal.Read()
	plan, err := store.Create(ctx, admission, document.Revision, plans.Spec{Operation: string(domain.OperationResourceDelete), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: "ui/test/generation/1", Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Applied: plans.DigestBinding{Applicable: true, Digest: owned.Checksum}, ExposureSummary: "delete_resource", Prerequisites: "fresh_closure"})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		t.Fatal(err)
	}
	document, _ = service.normal.Read()
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ResourceDelete, Target: "resource/" + resource.ID, ActorIdentity: plan.ActorIdentity, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{ResourceID: resource.ID, CandidateDigest: resource.CurrentConfigDigest, CandidateBundle: owned.Checksum, PlanID: plan.ID}, ResourceDelete: &operations.ResourceDeleteBinding{InstallationID: installation.InstallationID, Resource: resource, Ownership: owned}, ExpectedRevision: document.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}
	set, mutation, exposure = fixture.acquire(t, service, "resource/"+resource.ID)
	defer func() { _ = errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()) }()
	document, _ = service.normal.Read()
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, intent
}

func TestDeleteRecoveryRetainsFrozenInventoryAndReobservesEveryCrashBoundary(t *testing.T) {
	ctx := context.Background()
	for _, phase := range []string{"consumed", "tombstone", "deleting", "safety_removed", "normal_removed", "ownership_removed"} {
		t.Run(phase, func(t *testing.T) {
			fixture, intent := newDeleteRecoveryFixture(t)
			binding := *intent.ResourceDelete
			resourceID := binding.Resource.ID
			service := fixture.open(t)
			admitter, err := service.resourceAdmitter()
			if err != nil {
				t.Fatal(err)
			}
			set, mutation, exposure := fixture.acquire(t, service, intent.Target)
			initialService := service
			t.Cleanup(func() {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = set.Close()
				_ = initialService.Close()
			})
			state, err := service.safety.ReadForRecovery(exposure)
			if err != nil {
				t.Fatal(err)
			}
			if phase != "consumed" {
				next := state
				next.Revision++
				next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
				next.Resources[0].State = safety.ResourceDeleting
				next.Resources[0].DeletionTombstone = "delete/" + intent.JobID
				if _, err := service.safety.Commit(ctx, exposure, safety.RoleDelete, state.Revision, next, safety.TransitionProof{}); err != nil {
					t.Fatal(err)
				}
			}
			if phase != "consumed" && phase != "tombstone" {
				document, _ := service.normal.Read()
				if err := admitter.CommitResourceDeleteBegin(ctx, mutation, exposure, document.Revision, intent.JobID, resourceID); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "safety_removed" || phase == "normal_removed" || phase == "ownership_removed" {
				state, _ = service.safety.ReadForRecovery(exposure)
				next := state
				next.Revision++
				next.Resources = nil
				proof := &safety.DeleteConvergenceProof{ResourceID: resourceID, TombstoneRef: "delete/" + intent.JobID, OwnershipDigest: binding.Ownership.Checksum, RuntimeClosureDigest: recoveryDigest("prior-live-closure")}
				if _, err := service.safety.Commit(ctx, exposure, safety.RoleDelete, state.Revision, next, safety.TransitionProof{Delete: proof}); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "normal_removed" || phase == "ownership_removed" {
				document, _ := service.normal.Read()
				if err := admitter.CommitResourceDeleteRemoval(ctx, mutation, exposure, document.Revision, intent.JobID, resourceID); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "ownership_removed" {
				if err := service.ownership.Delete(ctx, exposure, binding.Ownership); err != nil {
					t.Fatal(err)
				}
			}
			if err := errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close(), service.Close()); err != nil {
				t.Fatal(err)
			}
			closureCalls, cleanupCalls := 0, 0
			failure := errors.New("fresh runtime closure unavailable")
			runtime := resourceDeleteRuntime{closed: func(_ context.Context, observed operations.ResourceDeleteBinding, _ safety.State) (string, error) {
				closureCalls++
				if !reflect.DeepEqual(observed, binding) {
					t.Fatal("reconstructed or changed frozen deletion authority")
				}
				if closureCalls == 1 {
					return "", failure
				}
				return recoveryDigest("fresh-closure"), nil
			}, cleanup: func(_ context.Context, resource domain.AppResource, installation domain.Installation) ([]string, error) {
				cleanupCalls++
				if resource.Lifecycle != domain.LifecycleDeleting || !reflect.DeepEqual(resource.PublicationRecord.CertificateInventory, binding.Resource.PublicationRecord.CertificateInventory) {
					t.Fatal("lost certificate inventory after normal removal")
				}
				return []string{}, nil
			}}
			run := func() error {
				service := fixture.open(t)
				defer func() { _ = service.Close() }()
				admitter, err := service.resourceAdmitter()
				if err != nil {
					return err
				}
				set, mutation, exposure := fixture.acquire(t, service, intent.Target)
				defer func() { _ = errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()) }()
				return reconcileResourceDeleteWithRuntime(ctx, service, admitter, mutation, exposure, intent, runtime)
			}
			if phase == "consumed" {
				if err := run(); err != nil {
					t.Fatal(err)
				}
				if closureCalls != 0 || cleanupCalls != 0 {
					t.Fatal("startup began an uncommitted deletion")
				}
				return
			}
			if err := run(); !errors.Is(err, failure) {
				t.Fatalf("failed closure was accepted: %v", err)
			}
			if cleanupCalls != 0 {
				t.Fatal("cleanup ran without fresh closure")
			}
			service = fixture.open(t)
			document, _ := service.normal.Read()
			job, err := jobs.LoadEntries(document.Entries, intent.JobID)
			if err != nil || job.Status == jobs.StatusTerminal {
				t.Fatalf("failed proof terminalized deletion: %+v %v", job, err)
			}
			_ = service.Close()
			if err := run(); err != nil {
				t.Fatalf("same frozen delete could not resume: %v", err)
			}
			if cleanupCalls != 1 || closureCalls != 3 {
				t.Fatalf("cleanup=%d fresh_observations=%d", cleanupCalls, closureCalls)
			}
			service = fixture.open(t)
			defer func() { _ = service.Close() }()
			document, _ = service.normal.Read()
			job, err = jobs.LoadEntries(document.Entries, intent.JobID)
			if err != nil || job.Status != jobs.StatusTerminal || job.Result != jobs.ResultSucceeded {
				t.Fatalf("delete not complete: %+v %v", job, err)
			}
			installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
			if err != nil || len(installation.Resources) != 0 {
				t.Fatalf("resource remains: %v", err)
			}
			if _, err := service.ownership.Read(resourceID); err == nil {
				t.Fatal("ownership remains after normal removal")
			}
		})
	}
}
