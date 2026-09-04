//go:build linux

package application

import (
	"context"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	managedresource "lanpanel/internal/resource"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveredDeleteKeepsOwnershipUntilNormalRemovalCommits(t *testing.T) {
	ctx := context.Background()
	resource := recoveryTailnetResource()
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(&resource))
	service := fixture.open(t)
	defer func() { _ = service.Close() }()

	setupSet, setupMutation, setupExposure := fixture.acquire(t, service, "resource/"+resource.ID)
	owned := writeRecoveryOwnershipAndSafety(t, service, setupExposure, resource.ID)
	if err := operations.ReleaseExposure(setupMutation, setupExposure); err != nil {
		t.Fatal(err)
	}
	if err := setupSet.Close(); err != nil {
		t.Fatal(err)
	}

	planStore, err := plans.NewStore(service.normal, plans.Options{})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	actor := "ui/session/generation/1"
	plan, err := planStore.Create(ctx, admission, document.Revision, plans.Spec{Operation: string(domain.OperationResourceDelete), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: actor, Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Applied: plans.DigestBinding{Applicable: true, Digest: owned.Checksum}, ExposureSummary: "delete_managed_resource_inventory", Prerequisites: "resource_unpublished_and_stopped"})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	binding := operations.SafetyBinding{ResourceID: resource.ID, CandidateDigest: resource.CurrentConfigDigest, CandidateBundle: owned.Checksum, PlanID: plan.ID}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ResourceDelete, Target: "resource/" + resource.ID, ActorIdentity: actor, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: binding, ExpectedRevision: document.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}

	set, mutation, exposure := fixture.acquire(t, service, "resource/"+resource.ID)
	mutationReleased := false
	defer func() {
		_ = exposure.Release()
		if !mutationReleased {
			_ = mutation.Release()
		}
		_ = set.Close()
	}()
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		t.Fatal(err)
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	for index := range next.Resources {
		if next.Resources[index].ResourceID == resource.ID {
			next.Resources[index].State = safety.ResourceDeleting
			next.Resources[index].DeletionTombstone = "delete/" + job.ID
		}
	}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleDelete, state.Revision, next, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := admitter.CommitResourceDeleteBegin(ctx, mutation, exposure, document.Revision, job.ID, resource.ID); err != nil {
		t.Fatal(err)
	}
	state, err = service.safety.ReadForRecovery(exposure)
	if err != nil {
		t.Fatal(err)
	}
	next = state
	next.Revision++
	next.Resources = nil
	closureDigest := digestLifecycle(struct{ ResourceID, ConfigDigest string }{resource.ID, resource.CurrentConfigDigest})
	proof := &safety.DeleteConvergenceProof{ResourceID: resource.ID, TombstoneRef: "delete/" + job.ID, OwnershipDigest: owned.Checksum, RuntimeClosureDigest: closureDigest}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleDelete, state.Revision, next, safety.TransitionProof{Delete: proof}); err != nil {
		t.Fatal(err)
	}

	if err := mutation.Release(); err != nil {
		t.Fatal(err)
	}
	mutationReleased = true
	if err := reconcileResourceDelete(ctx, service, admitter, mutation, exposure, intent); err == nil {
		t.Fatal("recovery unexpectedly committed without its mutation authority")
	}
	persisted, err := service.ownership.Read(resource.ID)
	if err != nil || persisted.Checksum != owned.Checksum {
		t.Fatalf("ownership was removed before normal deletion committed: ownership=%#v err=%v", persisted, err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		t.Fatal(err)
	}
	remaining := findNormalResource(installation, resource.ID)
	if remaining == nil || remaining.Lifecycle != domain.LifecycleDeleting {
		t.Fatalf("normal deletion unexpectedly committed: resource=%#v", remaining)
	}
}

func TestCleanupDeleteInventoryAccountErrorsFailBeforeMutation(t *testing.T) {
	installation := domain.Installation{InstallationID: "ins_00000000000000000000000000000001"}
	resource := deletionTestLocalResource(t)
	set, err := identity.ResourceAccounts(installation.InstallationID, resource.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	data := deletionAccountDatabase(set)
	tests := []string{
		"unreadable passwd",
		"unreadable group",
		"unreadable shadow",
		"malformed passwd",
		"malformed group",
		"malformed shadow",
		"partial account",
		"invalid account authority",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			currentInstallation := installation
			paths := writeDeletionAccountDatabase(t, data)
			switch name {
			case "unreadable passwd":
				paths.passwd = filepath.Join(t.TempDir(), "missing-passwd")
			case "unreadable group":
				paths.group = filepath.Join(t.TempDir(), "missing-group")
			case "unreadable shadow":
				paths.shadow = filepath.Join(t.TempDir(), "missing-shadow")
			case "malformed passwd":
				writeDeletionAccountFile(t, paths.passwd, "malformed\n")
			case "malformed group":
				writeDeletionAccountFile(t, paths.group, "malformed\n")
			case "malformed shadow":
				writeDeletionAccountFile(t, paths.shadow, "malformed\n")
			case "partial account":
				writeDeletionAccountFile(t, paths.group, "root:x:0:\n")
				writeDeletionAccountFile(t, paths.shadow, "root:*:1:0:99999:7:::\n")
			case "invalid account authority":
				currentInstallation.InstallationID = "invalid"
			}
			sentinel := filepath.Join(t.TempDir(), "sentinel")
			writeDeletionAccountFile(t, sentinel, "must remain")
			cleanupCalls := 0
			removed, err := cleanupDeleteInventoryWithCleanup(resource, currentInstallation, paths.passwd, paths.group, paths.shadow, func(domain.AppResource, []uint32) ([]string, error) {
				cleanupCalls++
				return []string{"unexpected"}, nil
			})
			if err == nil || len(removed) != 0 || cleanupCalls != 0 {
				t.Fatalf("removed=%v cleanupCalls=%d err=%v", removed, cleanupCalls, err)
			}
			if content, err := os.ReadFile(sentinel); err != nil || string(content) != "must remain" {
				t.Fatalf("account failure mutated files: content=%q err=%v", content, err)
			}
		})
	}
}

func TestCleanupDeleteInventoryNormalAndRecoveryUseKnownAccounts(t *testing.T) {
	installation := domain.Installation{InstallationID: "ins_00000000000000000000000000000001"}
	resource := deletionTestLocalResource(t)
	set, err := identity.ResourceAccounts(installation.InstallationID, resource.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	paths := writeDeletionAccountDatabase(t, deletionAccountDatabase(set))
	calls := 0
	cleanup := func(observed domain.AppResource, uids []uint32) ([]string, error) {
		calls++
		if observed.ID != resource.ID || len(uids) != 1 || uids[0] != 4100 {
			t.Fatalf("cleanup resource=%q uids=%v", observed.ID, uids)
		}
		return []string{"removed"}, nil
	}
	for _, path := range []string{"normal", "recovery"} {
		t.Run(path, func(t *testing.T) {
			removed, err := cleanupDeleteInventoryWithCleanup(resource, installation, paths.passwd, paths.group, paths.shadow, cleanup)
			if err != nil || len(removed) != 1 || removed[0] != "removed" {
				t.Fatalf("removed=%v err=%v", removed, err)
			}
		})
	}
	if calls != 2 {
		t.Fatalf("cleanup calls=%d", calls)
	}
}

func TestCleanupDeleteInventoryTailnetSkipsLocalAccounts(t *testing.T) {
	resource := domain.AppResource{
		ID:        "res_00000000000000000000000000000002",
		Lifecycle: domain.LifecycleDeleting,
		Target: domain.AppTarget{
			Kind:        domain.AppTargetTailnetHTTP,
			TailnetHTTP: &domain.TailnetHTTPTarget{IP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080},
		},
		PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished},
		ManagedPaths:      []string{},
	}
	removed, err := cleanupDeleteInventory(resource, domain.Installation{InstallationID: "invalid"})
	if err != nil || len(removed) != 0 {
		t.Fatalf("tailnet removed=%v err=%v", removed, err)
	}
}

func deletionTestLocalResource(t *testing.T) domain.AppResource {
	t.Helper()
	resourceID := "res_00000000000000000000000000000001"
	paths, err := managedresource.DerivePaths(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	return domain.AppResource{
		ID:        resourceID,
		Lifecycle: domain.LifecycleDeleting,
		Target: domain.AppTarget{
			Kind:      domain.AppTargetLocalHTTP,
			LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation},
		},
		PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished},
		ManagedProcess:    &domain.ManagedProcess{Requested: domain.ProcessRequestedStopped},
		ManagedPaths:      paths.ManagedPaths(),
	}
}

type deletionAccountPaths struct {
	passwd string
	group  string
	shadow string
}

type deletionAccountData struct {
	passwd string
	group  string
	shadow string
}

func deletionAccountDatabase(set identity.ResourceAccountSet) deletionAccountData {
	spec := set.Application
	return deletionAccountData{
		passwd: "root:x:0:0:root:/root:/bin/sh\n" + spec.User + ":x:4100:4200:" + spec.Comment + ":" + spec.Home + ":" + spec.Shell + "\n",
		group:  "root:x:0:\n" + spec.Group + ":x:4200:\n",
		shadow: "root:*:1:0:99999:7:::\n" + spec.User + ":!:1:0:99999:7:::\n",
	}
}

func writeDeletionAccountDatabase(t *testing.T, data deletionAccountData) deletionAccountPaths {
	t.Helper()
	root := t.TempDir()
	paths := deletionAccountPaths{passwd: filepath.Join(root, "passwd"), group: filepath.Join(root, "group"), shadow: filepath.Join(root, "shadow")}
	writeDeletionAccountFile(t, paths.passwd, data.passwd)
	writeDeletionAccountFile(t, paths.group, data.group)
	writeDeletionAccountFile(t, paths.shadow, data.shadow)
	return paths
}

func writeDeletionAccountFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
