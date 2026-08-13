//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"lanpanel/internal/secrets"
	"os"
	"sort"
	"sync"
	"time"
)

const fixedRoot = "/var/lib/lanpanel"

type planBinding struct{ binding plans.Binding }

func (value planBinding) CurrentBinding(_ operations.Type, _ string, _ time.Time) (plans.Binding, error) {
	return value.binding, nil
}

type confirmation struct{}

func actorAuthority(actor Actor) (string, error) {
	if actor.Kind != ActorUI || actor.Identity == "" || actor.Generation == 0 {
		return "", fmt.Errorf("Plan actor invalid")
	}
	return fmt.Sprintf("ui/%s/generation/%d", actor.Identity, actor.Generation), nil
}

func (confirmation) VerifyConfirmation(plan plans.Plan, actor, proof string, _ time.Time) (string, error) {
	if actor != plan.ActorIdentity || proof != plan.NonceDigest {
		return "", fmt.Errorf("confirmation rejected")
	}
	return plan.NonceDigest, nil
}
func operationRegistry() (*operations.Registry, error) {
	table, err := operations.NewBranchTable([]operations.ResultBranch{{Name: "complete", Result: jobs.ResultSucceeded, Postcondition: jobs.PostconditionVerified}, {Name: "no_effect", Result: jobs.ResultFailed, Postcondition: jobs.PostconditionVerified}, {Name: "known_residual", Result: jobs.ResultPartial, Postcondition: jobs.PostconditionKnown}, {Name: "executor_died", Result: jobs.ResultInterrupted, Postcondition: jobs.PostconditionKnown}, {Name: "source_unknown", Result: jobs.ResultUnknown, Postcondition: jobs.PostconditionUnobserved}})
	if err != nil {
		return nil, err
	}
	return operations.NewRegistry([]operations.Registration{{Operation: operations.AdminTokenRotate, Owner: "application.admin-token", Results: table}, {Operation: operations.CloseAll, Owner: "application.contraction", Results: table}, {Operation: operations.Unpublish, Owner: "application.contraction", Results: table}, {Operation: operations.StartupContraction, Owner: "application.contraction", Results: table}})
}

type FixedService struct {
	normal    *persist.Store
	manager   *locks.Manager
	safety    *safety.Store
	emergency *safety.EmergencyStore
	ownership *ownership.Store
	plans     *plans.Store
	closeOnce sync.Once
	closeErr  error
}

func OpenFixed() (*FixedService, error) {
	owner := filetxn.Owner{UID: 0, GID: 0}
	manager, err := locks.Open(locks.Config{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*FixedService, error) { manager.Close(); return nil, err }
	normal, err := persist.Open(persist.Config{RootPath: fixedRoot + "/state", StagingPath: fixedRoot + "/state/.filetxn", StatePath: fixedRoot + "/state/normal.json", Owner: owner, LockAuthority: manager.Authority()})
	if err != nil {
		return fail(err)
	}
	if err := operations.Register(normal); err != nil {
		normal.Close()
		return fail(err)
	}
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: fixedRoot + "/ownership", StagingPath: fixedRoot + "/ownership/.filetxn", RecordsPath: fixedRoot + "/ownership/records", Owner: owner, Policy: ownership.Policy{ManagedRoots: []string{"/etc/lanpanel", fixedRoot}}, LockAuthority: manager.Authority()})
	if err != nil {
		normal.Close()
		return fail(err)
	}
	emergency, err := safety.OpenEmergency(fixedRoot+"/safety/emergency", owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		ownershipStore.Close()
		normal.Close()
		return fail(err)
	}
	safetyStore, err := safety.OpenStore(safety.StoreConfig{RootPath: fixedRoot + "/safety", StagingPath: fixedRoot + "/safety/.filetxn", StatePath: fixedRoot + "/safety/state.json", Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		emergency.Close()
		ownershipStore.Close()
		normal.Close()
		return fail(err)
	}
	planStore, err := plans.NewStore(normal, plans.Options{})
	if err != nil {
		safetyStore.Close()
		emergency.Close()
		ownershipStore.Close()
		normal.Close()
		return fail(err)
	}
	return &FixedService{normal: normal, manager: manager, safety: safetyStore, emergency: emergency, ownership: ownershipStore, plans: planStore}, nil
}
func (s *FixedService) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.safety.Close(), s.emergency.Close(), s.ownership.Close(), s.normal.Close(), s.manager.Close())
	})
	return s.closeErr
}
func (s *FixedService) ReadPlan(id string) (plans.Plan, error) { return s.plans.Read(id) }
func (s *FixedService) Admitter(plan plans.Plan) (*operations.Admitter, error) {
	registry, err := operationRegistry()
	if err != nil {
		return nil, err
	}
	binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
	return operations.NewAdmitter(s.normal, s.safety, operations.Options{Bindings: planBinding{binding}, Confirmation: confirmation{}, Registry: registry})
}
func (s *FixedService) Manager() *locks.Manager { return s.manager }
func (s *FixedService) Normal() *persist.Store  { return s.normal }
func (s *FixedService) NormalInstallationID() string {
	if s == nil || s.normal == nil {
		return ""
	}
	document, err := s.normal.Read()
	if err != nil {
		return ""
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return ""
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return ""
	}
	return installation.InstallationID
}
func (s *FixedService) SafetyState() (safety.State, error)     { return s.safety.Read() }
func (s *FixedService) SafetyStore() *safety.Store             { return s.safety }
func (s *FixedService) EmergencyStore() *safety.EmergencyStore { return s.emergency }
func (s *FixedService) OwnershipInventory() (ownership.Inventory, error) {
	return s.ownership.Inventory()
}
func (s *FixedService) NginxStartAllowed(now time.Time) (bool, error) {
	state, err := s.safety.Read()
	if err != nil {
		return false, err
	}
	document, err := s.normal.Read()
	if err != nil {
		return false, err
	}
	pending, err := operations.HasPendingContraction(document)
	if err != nil || pending {
		return false, err
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return false, fmt.Errorf("normal installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return false, err
	}
	manifest, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return false, err
	}
	return nginx.Guard(nginx.GuardInput{Action: nginx.GuardStart, Manifest: manifest, Safety: state, Installation: &installation, Now: now}).Allowed, nil
}
func (s *FixedService) CreatePlan(ctx context.Context, actor Actor, payload PlanPayload) (plans.Plan, error) {
	authority, err := actorAuthority(actor)
	if err != nil {
		return plans.Plan{}, err
	}
	if err := domain.ValidateOperationTarget(payload.Operation, payload.Target); err != nil {
		return plans.Plan{}, err
	}
	if payload.Operation != domain.OperationAdminTokenRotate && payload.Operation != domain.OperationCloseAll && payload.Operation != domain.OperationUnpublish {
		return plans.Plan{}, ErrUnavailable
	}
	document, err := s.normal.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	fingerprint, err := secrets.CurrentAdminTokenFingerprint()
	if err != nil {
		return plans.Plan{}, err
	}
	admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer admission.Release()
	spec := plans.Spec{Operation: string(payload.Operation), Target: plans.Target{Kind: plans.TargetInstallation}, ActorIdentity: authority, Config: plans.DigestBinding{}, Applied: plans.DigestBinding{Applicable: true, Digest: fingerprint}, Evidence: []plans.Evidence{}, ExposureSummary: "admin_token_rotation", Prerequisites: "authenticated_destructive_confirmation", Lifetime: 10 * time.Minute}
	if payload.Operation == domain.OperationCloseAll || payload.Operation == domain.OperationUnpublish {
		state, err := s.safety.Read()
		if err != nil || state.GlobalClose.Phase != safety.GlobalCloseNone || state.StopFence != nil {
			return plans.Plan{}, fmt.Errorf("normal close-all authority is unavailable")
		}
		evidence, err := s.contractionEvidence(document, state, payload.Target)
		if err != nil {
			return plans.Plan{}, err
		}
		spec.Target = plans.Target{Kind: plans.TargetKind(payload.Target.Kind), ID: payload.Target.ID}
		spec.Config = plans.DigestBinding{Applicable: true, Digest: state.Checksum}
		spec.Applied = plans.DigestBinding{}
		spec.Evidence = []plans.Evidence{evidence}
		spec.ExposureSummary = "closes_all_app_origin_ingress"
		if payload.Operation == domain.OperationUnpublish {
			spec.ExposureSummary = "closes_selected_app_origin_ingress"
		}
	}
	return s.plans.Create(ctx, admission, document.Revision, spec)
}

func (s *FixedService) contractionEvidence(document persist.Document, state safety.State, target domain.OperationTarget) (plans.Evidence, error) {
	if os.Geteuid() != 0 {
		return plans.Evidence{}, fmt.Errorf("normal contraction preflight requires root helper")
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return plans.Evidence{}, fmt.Errorf("normal installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return plans.Evidence{}, err
	}
	owned, err := s.ownership.Inventory()
	if err != nil {
		return plans.Evidence{}, err
	}
	manifest, graphErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	resourceIDs := []string{}
	kind := preflight.ContractionCloseAll
	preflightTarget := "installation"
	if target.Kind == domain.OperationTargetResource {
		resourceIDs = []string{target.ID}
		kind = preflight.ContractionUnpublish
		preflightTarget = "resource/" + target.ID
	}
	var graph *nginx.Manifest
	if graphErr == nil {
		graph = &manifest
	}
	inventory, err := closure.BuildInventory(closure.Inputs{Installation: installation, Safety: &state, Ownership: owned, Graph: graph, ResourceIDs: resourceIDs})
	if err != nil {
		return plans.Evidence{}, err
	}
	authorities := make([]preflight.OwnedIngressAuthority, 0, len(owned.Records))
	checksums := make(map[string]string, len(owned.Records))
	selected := func(id string) bool { return len(resourceIDs) == 0 || id == resourceIDs[0] }
	for _, record := range owned.Records {
		if !selected(record.ResourceID) {
			continue
		}
		checksums[record.ResourceID] = record.Checksum
		authorities = append(authorities, preflight.OwnedIngressAuthority{ResourceID: record.ResourceID, RuntimeIdentity: inventory.Digest, OwnershipDigest: record.Checksum})
	}
	sort.Slice(authorities, func(left, right int) bool { return authorities[left].ResourceID < authorities[right].ResourceID })
	generation := state.GlobalClose.Generation + 1
	if len(resourceIDs) == 1 {
		for _, resource := range state.Resources {
			if resource.ResourceID == resourceIDs[0] {
				generation = resource.GenerationSequence + 1
			}
		}
	}
	fallbackStop := graphErr != nil || !inventory.Complete
	request := preflight.ContractionRequest{Kind: kind, Target: preflightTarget, Generation: generation, OwnershipInventoryDigest: safety.OwnershipInventoryDigest(checksums), ClosureAuthorityDigest: inventory.Digest, OwnedIngress: authorities, FallbackStop: fallbackStop}
	now := time.Now().UTC()
	result, err := preflight.EvaluateContraction(request, preflight.ContractionObservations{ExecutorUID: uint32(os.Geteuid()), InventoryComplete: owned.Complete, OwnershipInventoryDigest: request.OwnershipInventoryDigest, ClosureAuthorityDigest: inventory.Digest, OwnedIngress: authorities, ObservedAt: now, Diagnostics: []preflight.Diagnostic{}})
	if err != nil {
		return plans.Evidence{}, err
	}
	return result.PlanEvidence()
}
