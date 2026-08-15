//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"lanpanel/internal/publication"
	"lanpanel/internal/reservations"
	"lanpanel/internal/safety"
	"lanpanel/internal/secrets"
	"os"
	"slices"
	"sort"
	"strings"
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
	return operations.NewRegistry([]operations.Registration{{Operation: operations.AdminTokenRotate, Owner: "application.admin-token", Results: table}, {Operation: operations.Publish, Owner: "application.publication", Results: table}, {Operation: operations.CertificateRenew, Owner: "application.certificate", Results: table}, {Operation: operations.ManagedBasicCreate, Owner: "application.basic", Results: table}, {Operation: operations.ManagedBasicRotate, Owner: "application.basic", Results: table}, {Operation: operations.ManagedBasicDelete, Owner: "application.basic", Results: table}, {Operation: operations.StaticRootRegister, Owner: "application.static", Results: table}, {Operation: operations.ExternalHTPasswdRegister, Owner: "application.external-htpasswd", Results: table}, {Operation: operations.CloseAll, Owner: "application.contraction", Results: table}, {Operation: operations.Unpublish, Owner: "application.contraction", Results: table}, {Operation: operations.StartupContraction, Owner: "application.contraction", Results: table}, {Operation: operations.GoAccessRetirement, Owner: "application.goaccess", Results: table}})
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
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: fixedRoot + "/ownership", StagingPath: fixedRoot + "/ownership/.filetxn", RecordsPath: fixedRoot + "/ownership/records", Owner: owner, Policy: ownership.FixedPolicy(), LockAuthority: manager.Authority()})
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
func (s *FixedService) TimerAdmitter() (*operations.Admitter, error) {
	registry, err := operationRegistry()
	if err != nil {
		return nil, err
	}
	return operations.NewAdmitter(s.normal, s.safety, operations.Options{Bindings: planBinding{}, Confirmation: confirmation{}, Registry: registry})
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
func (s *FixedService) RestorePublicationSafety(ctx context.Context, lease *locks.Lease, resourceID string) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	for index := range next.Resources {
		if next.Resources[index].ResourceID == resourceID {
			next.Resources[index].Reactivating = nil
		}
	}
	_, err = s.safety.Commit(ctx, lease, safety.RoleContraction, state.Revision, next, safety.TransitionProof{})
	return err
}
func (s *FixedService) WriteIngressActivationFence(ctx context.Context, lease *locks.Lease, resourceID, intentRef string, candidate, prior uint64, observed safety.StopObservation, accessMayRemain bool) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	inventory, err := s.ownership.Inventory()
	if err != nil {
		return err
	}
	checksums := map[string]string{}
	for _, record := range inventory.Records {
		checksums[record.ResourceID] = record.Checksum
	}
	ownershipDigest := safety.OwnershipInventoryDigest(checksums)
	graph, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return err
	}
	data, err := nginx.EncodeManifest(graph)
	if err != nil {
		return err
	}
	graphDigest := shaDigest(data)
	fence := &safety.StopFence{Kind: safety.StopFenceIngressActivation, OriginOperation: "publish", Scope: safety.FenceScope{Kind: "app", ResourceID: resourceID}, FenceGeneration: state.StopFenceSequence + 1, CreatedAt: time.Now().UTC(), SafetyGenerations: applicablePublicationMarkers(state, resourceID), OwnedGraphDigest: graphDigest, InventoryDigest: ownershipDigest, Observation: observed, AccessMayRemain: accessMayRemain, IngressActivation: &safety.IngressActivationFence{IntentRef: intentRef, CandidateGeneration: candidate, PriorGeneration: prior}}
	authority, err := safety.ReserveEmergencyStopFenceGeneration(lease, s.emergency, safety.RoleIngressActivation, safety.StopFenceIngressActivation, safety.StopFenceDigest(*fence), state.StopFenceSequence)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.AuthoritySequence = authority.Sequence
	next.StopFenceSequence = authority.StopFenceSequence
	next.StopFence = fence
	_, err = s.safety.Commit(ctx, lease, safety.RoleIngressActivation, state.Revision, next, safety.TransitionProof{})
	return err
}
func activeCertificateAuthority(certificate domain.CertificateBundleIdentity) (*safety.ActiveCertificateAuthority, error) {
	notAfter, deadlineErr := time.Parse(time.RFC3339, certificate.NotAfter)
	lastWall, wallErr := time.Parse(time.RFC3339, certificate.LastTrustedWall)
	if deadlineErr != nil || wallErr != nil || certificate.Generation == 0 || certificate.Fingerprint == "" || certificate.BindingIdentity == "" {
		return nil, fmt.Errorf("active certificate deadline identity invalid")
	}
	return &safety.ActiveCertificateAuthority{Generation: certificate.Generation, Fingerprint: certificate.Fingerprint, Binding: certificate.BindingIdentity, NotAfter: notAfter, LastTrustedWall: lastWall}, nil
}
func (s *FixedService) CommitRenewedCertificateAuthority(ctx context.Context, lease *locks.Lease, resourceID string, certificate domain.CertificateBundleIdentity) error {
	authority, err := activeCertificateAuthority(certificate)
	if err != nil {
		return err
	}
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	found := false
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	for index := range next.Resources {
		resource := &next.Resources[index]
		if resource.ResourceID == resourceID {
			if resource.ActiveCertificate == nil || authority.Generation != resource.ActiveCertificate.Generation+1 || authority.Binding != resource.ActiveCertificate.Binding {
				return fmt.Errorf("renewed certificate safety authority mismatched")
			}
			resource.ActiveCertificate = authority
			found = true
		}
	}
	if !found {
		return fmt.Errorf("renewed certificate safety resource missing")
	}
	_, err = s.safety.Commit(ctx, lease, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
	return err
}
func (s *FixedService) MarkCertificateActivationUncertain(ctx context.Context, lease *locks.Lease, resourceID, binding string, now time.Time) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	found := false
	for index := range next.Resources {
		resource := &next.Resources[index]
		if resource.ResourceID == resourceID {
			resource.GenerationSequence++
			resource.CertificateExpiry = &safety.DeadlineMarker{Generation: resource.GenerationSequence, Deadline: now.UTC(), Binding: binding}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("certificate uncertainty resource missing")
	}
	_, err = s.safety.Commit(ctx, lease, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
	return err
}
func (s *FixedService) WriteCertificateActivationFence(ctx context.Context, lease *locks.Lease, resourceID, journalRef, priorPointer, candidatePointer string, observed safety.StopObservation, accessMayRemain bool) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	var resource *safety.ResourceSafety
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resourceID {
			resource = &state.Resources[index]
		}
	}
	if resource == nil || resource.CertificateExpiry == nil {
		return fmt.Errorf("certificate fence requires expiry authority")
	}
	inventory, err := s.ownership.Inventory()
	if err != nil {
		return err
	}
	checksums := map[string]string{}
	for _, record := range inventory.Records {
		checksums[record.ResourceID] = record.Checksum
	}
	graph, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return err
	}
	data, err := nginx.EncodeManifest(graph)
	if err != nil {
		return err
	}
	fence := &safety.StopFence{Kind: safety.StopFenceCertificateActivation, OriginOperation: "certificate_activation", Scope: safety.FenceScope{Kind: "app", ResourceID: resourceID}, FenceGeneration: state.StopFenceSequence + 1, CreatedAt: time.Now().UTC(), SafetyGenerations: applicablePublicationMarkers(state, resourceID), OwnedGraphDigest: shaDigest(data), InventoryDigest: safety.OwnershipInventoryDigest(checksums), Observation: observed, AccessMayRemain: accessMayRemain, CertificateActivation: &safety.CertificateActivationFence{JournalRef: journalRef, ResourceGeneration: resource.GenerationSequence, PriorPointer: priorPointer, CandidatePointer: candidatePointer, ExpiryGeneration: resource.CertificateExpiry.Generation}}
	authority, err := safety.ReserveEmergencyStopFenceGeneration(lease, s.emergency, safety.RoleCertificateActivation, safety.StopFenceCertificateActivation, safety.StopFenceDigest(*fence), state.StopFenceSequence)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.AuthoritySequence = authority.Sequence
	next.StopFenceSequence = authority.StopFenceSequence
	next.StopFence = fence
	_, err = s.safety.Commit(ctx, lease, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
	return err
}
func (s *FixedService) UpdateCertificateActivationFence(ctx context.Context, lease *locks.Lease, observation safety.StopObservation, accessMayRemain bool) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	if state.StopFence == nil || state.StopFence.Kind != safety.StopFenceCertificateActivation {
		return fmt.Errorf("certificate activation stop fence missing")
	}
	next := state
	next.Revision++
	copy := *state.StopFence
	copy.Observation = observation
	copy.AccessMayRemain = accessMayRemain
	next.StopFence = &copy
	_, err = s.safety.Commit(ctx, lease, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
	return err
}
func applicablePublicationMarkers(state safety.State, resourceID string) []safety.MarkerGeneration {
	result := []safety.MarkerGeneration{}
	if state.GlobalClose.Phase != safety.GlobalCloseNone {
		result = append(result, safety.MarkerGeneration{Kind: "global_close", Generation: state.GlobalClose.Generation})
	}
	for _, value := range []struct {
		kind   string
		marker *safety.TransitionMarker
	}{{"maintenance_pending", state.MaintenancePending}, {"dependency_transition_pending", state.DependencyTransitionPending}, {"upgrade_pending", state.UpgradePending}} {
		if value.marker != nil {
			result = append(result, safety.MarkerGeneration{Kind: value.kind, Generation: value.marker.Generation})
		}
	}
	if state.BackupQuiescence != nil {
		result = append(result, safety.MarkerGeneration{Kind: "backup_quiescence", Generation: state.BackupQuiescence.Generation})
	}
	if state.BackupTransition != nil && state.BackupTransition.Phase != safety.BackupTransitionImported {
		result = append(result, safety.MarkerGeneration{Kind: "backup_transition", Generation: state.BackupTransition.Generation})
	}
	for _, resource := range state.Resources {
		if resource.ResourceID == resourceID {
			for _, value := range []struct {
				kind       string
				generation uint64
			}{{"sticky_unpublished", generation(resource.StickyUnpublished)}, {"closing", generation(resource.Closing)}, {"contraction", generation(resource.Contraction)}, {"certificate_expiry", deadlineGeneration(resource.CertificateExpiry)}, {"edgeone_expiry", deadlineGeneration(resource.EdgeOne.Expiry)}, {"challenge_pending", challengeGeneration(resource.ChallengePending)}, {"reactivating", reactivationGeneration(resource.Reactivating)}} {
				if value.generation != 0 {
					result = append(result, safety.MarkerGeneration{Kind: value.kind, Generation: value.generation})
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Kind < result[j].Kind })
	return result
}
func challengeGeneration(marker *safety.ChallengePending) uint64 {
	if marker == nil {
		return 0
	}
	return marker.Generation
}
func reactivationGeneration(marker *safety.Reactivating) uint64 {
	if marker == nil {
		return 0
	}
	return marker.Generation
}
func shaDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (s *FixedService) OwnershipInventory() (ownership.Inventory, error) {
	return s.ownership.Inventory()
}
func (s *FixedService) PendingCertificateRecovery() error {
	document, err := s.normal.Read()
	if err != nil {
		return err
	}
	certificateJobs := map[string]bool{}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "journals/") {
			continue
		}
		var journal operations.JournalRecord
		if json.Unmarshal(raw, &journal) == nil && journal.Kind == operations.JournalCertificateActivation && journal.Phase != operations.JournalTerminal {
			certificateJobs[journal.JobID] = true
		}
	}
	ids := []string{}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) == nil && certificateJobs[intent.JobID] && intent.Phase != operations.PhaseTerminal && intent.Phase != operations.PhaseRejected {
			ids = append(ids, intent.JobID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	return fmt.Errorf("interrupted certificate operation requires contraction: %s", strings.Join(ids, ","))
}
func (s *FixedService) PendingPublicationRecovery() error {
	document, err := s.normal.Read()
	if err != nil {
		return err
	}
	state, err := s.safety.Read()
	if err != nil {
		return err
	}
	pending := map[string]bool{}
	for _, key := range persist.EntryKeys(document, "intents") {
		var intent operations.Reservation
		if err := json.Unmarshal(document.Entries[key], &intent); err != nil {
			return err
		}
		if intent.Operation == operations.Publish && intent.Phase != operations.PhaseTerminal && intent.Phase != operations.PhaseRejected {
			pending[intent.SafetyBinding.ResourceID] = true
		}
	}
	for _, resource := range state.Resources {
		if resource.Reactivating != nil {
			pending[resource.ResourceID] = true
		}
	}
	if len(pending) == 0 {
		return nil
	}
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return fmt.Errorf("interrupted publication requires contraction: %s", strings.Join(ids, ","))
}
func (s *FixedService) OwnershipRead(resourceID string) (ownership.Record, error) {
	return s.ownership.Read(resourceID)
}
func (s *FixedService) OwnershipWrite(ctx context.Context, lease *locks.Lease, expected uint64, record ownership.Record) (ownership.Record, error) {
	if _, err := s.ownership.Write(ctx, lease, ownership.ActivationWriter, expected, record); err != nil {
		return ownership.Record{}, err
	}
	return s.ownership.Read(record.ResourceID)
}
func (s *FixedService) OwnershipRetireGoAccess(ctx context.Context, lease *locks.Lease, expected uint64, record ownership.Record, removeShared bool) (ownership.Record, error) {
	role := ownership.GoAccessRetirementWriter
	if removeShared {
		role = ownership.GoAccessCandidateRollbackWriter
	}
	if _, err := s.ownership.Write(ctx, lease, role, expected, record); err != nil {
		return ownership.Record{}, err
	}
	return s.ownership.Read(record.ResourceID)
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
	if err := s.PendingPublicationRecovery(); err != nil {
		return false, err
	}
	if err := s.PendingCertificateRecovery(); err != nil {
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
	if payload.Operation != domain.OperationAdminTokenRotate && payload.Operation != domain.OperationCloseAll && payload.Operation != domain.OperationUnpublish && payload.Operation != domain.OperationPublish && payload.Operation != domain.OperationManagedBasicDelete {
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
	if payload.Operation == domain.OperationPublish {
		return s.createPublishPlan(ctx, authority, document, payload.Target)
	}
	if payload.Operation == domain.OperationManagedBasicDelete {
		installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
		if err != nil {
			return plans.Plan{}, err
		}
		var credential *domain.Credential
		for index := range installation.Credentials {
			if installation.Credentials[index].ID == payload.Target.ID {
				credential = &installation.Credentials[index]
			}
		}
		if credential == nil || credential.Kind != "managed_basic" {
			return plans.Plan{}, fmt.Errorf("managed Basic credential missing")
		}
		if err := requireNoDegradedAppliedSource(credential.OwnerResourceID); err != nil {
			return plans.Plan{}, err
		}
		for _, resource := range installation.Resources {
			if applicationCredentialReferenced(resource, credential.ID) {
				return plans.Plan{}, fmt.Errorf("active resource reference blocks credential delete")
			}
		}
		admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
		if err != nil {
			return plans.Plan{}, err
		}
		defer admission.Release()
		spec := plans.Spec{Operation: string(payload.Operation), Target: plans.Target{Kind: plans.TargetCredential, ID: credential.ID}, ActorIdentity: authority, Config: plans.DigestBinding{Applicable: true, Digest: credential.Fingerprint}, ExposureSummary: "deletes_managed_basic_credential_" + credential.ID, Prerequisites: "credential_has_no_current_applied_or_activating_reference", Lifetime: 10 * time.Minute}
		return s.plans.Create(ctx, admission, document.Revision, spec)
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

func applicationCredentialReferenced(resource domain.AppResource, id string) bool {
	if slices.Contains(resource.CredentialIDs, id) || resource.Publication.DomainHTTPS != nil && resource.Publication.DomainHTTPS.CredentialID == id {
		return true
	}
	if bundle := resource.PublicationRecord.LastAppliedBundle; bundle != nil && slices.Contains(bundle.CredentialIDs, id) {
		return true
	}
	if intent := resource.PublicationRecord.ActivationIntent; intent != nil && (slices.Contains(intent.Candidate.CredentialIDs, id) || intent.Prior != nil && slices.Contains(intent.Prior.CredentialIDs, id)) {
		return true
	}
	return false
}

func (s *FixedService) createPublishPlan(ctx context.Context, authority string, document persist.Document, target domain.OperationTarget) (plans.Plan, error) {
	if target.Kind != domain.OperationTargetResource {
		return plans.Plan{}, fmt.Errorf("publish target must be a resource")
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return plans.Plan{}, fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return plans.Plan{}, err
	}
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == target.ID {
			resource = &installation.Resources[index]
			break
		}
	}
	if resource == nil {
		return plans.Plan{}, fmt.Errorf("publish resource missing")
	}
	if resource.Publication.Kind == domain.PublicationDomainHTTPS {
		return s.createDomainPublishPlan(ctx, authority, document, installation, *resource)
	}
	if resource.Publication.Kind != domain.PublicationTemporaryHTTP {
		return plans.Plan{}, fmt.Errorf("publication type unsupported")
	}
	if resource.Target.Kind != domain.AppTargetLocalHTTP || resource.Target.WebSocket.Enabled || resource.ManagedProcess == nil || resource.ManagedProcess.Requested != domain.ProcessRequestedRunning || resource.ManagedProcess.Applied == nil || resource.ManagedProcess.Applied.ConfigDigest != resource.CurrentConfigDigest {
		return plans.Plan{}, fmt.Errorf("temporary publication requires exact running local target without WebSocket")
	}
	if _, err := reservations.BuildClaims(installation); err != nil {
		return plans.Plan{}, err
	}
	state, err := s.safety.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	safetyResource := findSafetyResource(state, resource.ID)
	if safetyResource == nil || safetyResource.StickyUnpublished == nil && resource.PublicationRecord.State != domain.PublicationPublished {
		return plans.Plan{}, fmt.Errorf("publish requires exact published or sticky unpublished authority")
	}
	var owned *ownership.Record
	if resource.PublicationRecord.State == domain.PublicationPublished {
		record, readErr := s.ownership.Read(resource.ID)
		if readErr != nil {
			return plans.Plan{}, readErr
		}
		owned = &record
	}
	request, preflightResult, err := evaluateTemporaryPreflight(ctx, installation, *resource, state, owned)
	if err != nil {
		return plans.Plan{}, err
	}
	preflightEvidence, err := preflightResult.PlanEvidence()
	if err != nil {
		return plans.Plan{}, err
	}
	readiness, err := probeResourceTarget(ctx, *resource)
	if err != nil {
		return plans.Plan{}, err
	}
	readinessEvidence := plans.Evidence{Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: resource.ManagedProcess.Applied.Generation, Digest: readiness.Digest, ObservedAt: readiness.ObservedAt}
	applied := plans.DigestBinding{}
	if resource.PublicationRecord.LastAppliedDigest != nil {
		applied = plans.DigestBinding{Applicable: true, Digest: *resource.PublicationRecord.LastAppliedDigest}
	}
	temporary := resource.Publication.TemporaryHTTP
	spec := plans.Spec{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: authority, Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Applied: applied, Evidence: []plans.Evidence{preflightEvidence, readinessEvidence}, ExposureSummary: fmt.Sprintf("url=http://%s:%d/ listener=0.0.0.0:%d target=resource/%s", temporary.PublicIPv4, temporary.Port, temporary.Port, resource.ID), Prerequisites: publication.PlaintextWarning, Lifetime: 10 * time.Minute}
	_ = request
	admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer admission.Release()
	return s.plans.Create(ctx, admission, document.Revision, spec)
}

func (s *FixedService) createDomainPublishPlan(ctx context.Context, authority string, document persist.Document, installation domain.Installation, resource domain.AppResource) (plans.Plan, error) {
	if err := requireGoAccessRetirementComplete(ctx, s, resource); err != nil {
		return plans.Plan{}, err
	}
	if err := requireGoAccessServiceTransition(resource); err != nil {
		return plans.Plan{}, err
	}
	if err := requireAppliedDomainSourcesHealthy(resource); err != nil {
		return plans.Plan{}, err
	}
	if resource.Target.Kind != domain.AppTargetLocalHTTP || resource.ManagedProcess == nil || resource.ManagedProcess.Requested != domain.ProcessRequestedRunning || resource.ManagedProcess.Applied == nil || resource.ManagedProcess.Applied.ConfigDigest != resource.CurrentConfigDigest {
		return plans.Plan{}, fmt.Errorf("domain publication requires exact running target")
	}
	if _, err := reservations.BuildClaims(installation); err != nil {
		return plans.Plan{}, err
	}
	state, err := s.safety.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	safetyResource := findSafetyResource(state, resource.ID)
	if safetyResource == nil || safetyResource.StickyUnpublished == nil && resource.PublicationRecord.State != domain.PublicationPublished {
		return plans.Plan{}, fmt.Errorf("domain publish authority unavailable")
	}
	request, preflightResult, err := evaluateDomainPreflight(ctx, installation, resource, state)
	if err != nil {
		return plans.Plan{}, err
	}
	preflightEvidence, err := preflightResult.PlanEvidence()
	if err != nil {
		return plans.Plan{}, err
	}
	readiness, err := probeResourceTarget(ctx, resource)
	if err != nil {
		return plans.Plan{}, err
	}
	_, bindingDigest, err := candidateACMEBinding(resource)
	if err != nil {
		return plans.Plan{}, err
	}
	sourceEvidence, err := observeDomainSources(s, resource)
	if err != nil {
		return plans.Plan{}, err
	}
	readinessEvidence := plans.Evidence{Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: resource.ManagedProcess.Applied.Generation, Digest: readiness.Digest, ObservedAt: readiness.ObservedAt}
	acmeEvidence := plans.Evidence{Kind: "acme_binding", Identity: "resource/" + resource.ID, Generation: safetyResource.GenerationSequence + 1, Digest: bindingDigest, ObservedAt: time.Now().UTC()}
	applied := plans.DigestBinding{}
	if resource.PublicationRecord.LastAppliedDigest != nil {
		applied = plans.DigestBinding{Applicable: true, Digest: *resource.PublicationRecord.LastAppliedDigest}
	}
	publication := resource.Publication.DomainHTTPS
	domains := append([]string{publication.CanonicalDomain}, publication.Aliases...)
	sort.Strings(domains)
	anonymousStatic := publication.AccessMode == domain.AppAccessApplicationManaged && len(publication.StaticMappings) > 0
	staticValues := make([]string, len(publication.StaticMappings))
	for index, mapping := range publication.StaticMappings {
		staticValues[index] = mapping.URLPath + ":" + mapping.RelativePath
	}
	certificate := publication.Certificate
	summary := fmt.Sprintf("url=https://%s/ listeners=80,443 domains=%s auth=%s credential=%s cidrs=%s static_root=%s static=%s static_anonymous_confirmed=%t goaccess=%t goaccess_credential=%s goaccess_cidrs=%s goaccess_dashboard=%s goaccess_websocket=%s certificate=%s:%s:%s target=resource/%s", publication.CanonicalDomain, strings.Join(domains, ","), publication.AccessMode, publication.CredentialID, strings.Join(publication.CIDRs, ","), publication.StaticRootID, strings.Join(staticValues, ","), anonymousStatic, publication.GoAccess.Enabled, publication.GoAccess.CredentialID, strings.Join(publication.GoAccess.CIDRs, ","), publication.GoAccess.DashboardPath, publication.GoAccess.WebSocketPath, certificate.ChallengeMethod, certificate.DNSProvider, certificate.DirectoryURL, resource.ID)
	spec := plans.Spec{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: authority, Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Applied: applied, Evidence: []plans.Evidence{preflightEvidence, readinessEvidence, acmeEvidence, sourceEvidence}, ExposureSummary: summary, Prerequisites: "Exact certificate, auth, CIDR, static, isolated GoAccess staging, target, and Host/SNI validation required before activation.", Lifetime: 10 * time.Minute}
	_ = request
	admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer admission.Release()
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
