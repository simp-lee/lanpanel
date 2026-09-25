//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"reflect"
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
		return "", fmt.Errorf("plan actor invalid")
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
	return operations.NewRegistry([]operations.Registration{{Operation: operations.AdminTokenRotate, Owner: "application.admin-token", Results: table}, {Operation: operations.HeadscaleDeploy, Owner: "application.headscale-control", Results: table}, {Operation: operations.PreauthKeyCreate, Owner: "application.headscale-preauth", Results: table}, {Operation: operations.PreauthKeyRevoke, Owner: "application.headscale-preauth", Results: table}, {Operation: operations.DeviceExpire, Owner: "application.headscale-device", Results: table}, {Operation: operations.ConnectorLogin, Owner: "application.connector-login", Results: table}, {Operation: operations.ResourceDelete, Owner: "application.resource-delete", Results: table}, {Operation: operations.Publish, Owner: "application.publication", Results: table}, {Operation: operations.CertificateRenew, Owner: "application.certificate", Results: table}, {Operation: operations.CertificateExpiry, Owner: "application.certificate", Results: table}, {Operation: operations.ManagedBasicCreate, Owner: "application.basic", Results: table}, {Operation: operations.ManagedBasicRotate, Owner: "application.basic", Results: table}, {Operation: operations.ManagedBasicDelete, Owner: "application.basic", Results: table}, {Operation: operations.StaticRootRegister, Owner: "application.static", Results: table}, {Operation: operations.ExternalHTPasswdRegister, Owner: "application.external-htpasswd", Results: table}, {Operation: operations.CloseAll, Owner: "application.contraction", Results: table}, {Operation: operations.Unpublish, Owner: "application.contraction", Results: table}, {Operation: operations.AutomaticReconciliation, Owner: "application.reconciliation", Results: table}, {Operation: operations.StartupContraction, Owner: "application.contraction", Results: table}, {Operation: operations.GoAccessRetirement, Owner: "application.goaccess", Results: table}})
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
	fail := func(err error) (*FixedService, error) { _ = manager.Close(); return nil, err }
	normal, err := persist.Open(persist.Config{RootPath: fixedRoot + "/state", StagingPath: fixedRoot + "/state/.filetxn", StatePath: fixedRoot + "/state/normal.json", Owner: owner, LockAuthority: manager.Authority()})
	if err != nil {
		return fail(err)
	}
	if err := operations.Register(normal); err != nil {
		_ = normal.Close()
		return fail(err)
	}
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: fixedRoot + "/ownership", StagingPath: fixedRoot + "/ownership/.filetxn", RecordsPath: fixedRoot + "/ownership/records", Owner: owner, Policy: ownership.FixedPolicy(), LockAuthority: manager.Authority()})
	if err != nil {
		_ = normal.Close()
		return fail(err)
	}
	emergency, err := safety.OpenEmergency(fixedRoot+"/safety/emergency", owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		_ = ownershipStore.Close()
		_ = normal.Close()
		return fail(err)
	}
	safetyStore, err := safety.OpenStore(safety.StoreConfig{RootPath: fixedRoot + "/safety", StagingPath: fixedRoot + "/safety/.filetxn", StatePath: fixedRoot + "/safety/state.json", Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		_ = emergency.Close()
		_ = ownershipStore.Close()
		_ = normal.Close()
		return fail(err)
	}
	planStore, err := plans.NewStore(normal, plans.Options{})
	if err != nil {
		_ = safetyStore.Close()
		_ = emergency.Close()
		_ = ownershipStore.Close()
		_ = normal.Close()
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
func (s *FixedService) RestorePublicationSafety(ctx context.Context, lease *locks.Lease, resourceID string, expected safety.Reactivating) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	found := false
	for index := range next.Resources {
		if next.Resources[index].ResourceID != resourceID {
			continue
		}
		if next.Resources[index].Reactivating == nil || !reflect.DeepEqual(*next.Resources[index].Reactivating, expected) || expected.PlanID == "" || expected.Generation == 0 || expected.CandidateDigest == "" || expected.CandidateBundle == "" {
			return fmt.Errorf("publication reactivation authority changed")
		}
		next.Resources[index].Reactivating = nil
		found = true
	}
	if !found {
		return fmt.Errorf("publication safety resource missing")
	}
	_, err = s.safety.Commit(ctx, lease, safety.RoleContraction, state.Revision, next, safety.TransitionProof{})
	return err
}

func (s *FixedService) WriteIngressActivationFence(ctx context.Context, lease *locks.Lease, resourceID, intentRef string, candidate, prior uint64, observed safety.StopObservation, accessMayRemain bool) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	if state.StopFence != nil {
		return fmt.Errorf("ingress activation fence is already active")
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

func (s *FixedService) BindHeadscaleIngressActivation(ctx context.Context, lease *locks.Lease, planID, activationDigest, entryDigest string) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil || state.StopFence != nil || state.Headscale.Reactivating == nil || state.Headscale.Reactivating.PlanID != planID || state.Headscale.Reactivating.ActivationDigest != "" || state.Headscale.Reactivating.ControlEntryDigest != "" {
		return fmt.Errorf("headscale ingress activation safety authority changed: %w", err)
	}
	next := state
	next.Revision++
	active := *next.Headscale.Reactivating
	active.ActivationDigest = activationDigest
	active.ControlEntryDigest = entryDigest
	next.Headscale.Reactivating = &active
	_, err = s.safety.Commit(ctx, lease, safety.RoleIngressActivation, state.Revision, next, safety.TransitionProof{})
	return err
}

func (s *FixedService) WriteHeadscaleIngressActivationFence(ctx context.Context, lease *locks.Lease, intentRef, graphDigest string, candidate, prior uint64, observed safety.StopObservation, accessMayRemain bool) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil || state.Headscale.Reactivating == nil || state.Headscale.Reactivating.PlanID != intentRef || state.Headscale.Reactivating.Generation != candidate || state.Headscale.Reactivating.PriorGeneration != prior {
		return fmt.Errorf("headscale ingress fence authority changed: %w", err)
	}
	inventoryDigest := shaDigest([]byte(fmt.Sprintf("%s/%t/%t/%t/%t/%s", graphDigest, observed.MasterStopped, observed.WorkersStopped, observed.ListenersStopped, accessMayRemain, observed.ObservedAt.UTC().Format(time.RFC3339Nano))))
	fence := &safety.StopFence{Kind: safety.StopFenceIngressActivation, OriginOperation: "headscale_deploy", Scope: safety.FenceScope{Kind: "headscale"}, FenceGeneration: state.StopFenceSequence + 1, CreatedAt: time.Now().UTC(), SafetyGenerations: applicableHeadscaleMarkers(state), OwnedGraphDigest: graphDigest, InventoryDigest: inventoryDigest, Observation: observed, AccessMayRemain: accessMayRemain, IngressActivation: &safety.IngressActivationFence{IntentRef: intentRef, CandidateGeneration: candidate, PriorGeneration: prior}}
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

func (s *FixedService) MarkHeadscaleCertificateActivationUncertain(ctx context.Context, lease *locks.Lease, binding string, deadline time.Time) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil {
		return err
	}
	if state.Headscale.ActiveCertificate == nil || state.Headscale.ActiveCertificate.Binding != binding {
		return fmt.Errorf("headscale uncertain certificate binding changed")
	}
	next := state
	next.Revision++
	next.Headscale.GenerationSequence++
	next.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: next.Headscale.GenerationSequence, Deadline: deadline, Binding: binding}
	_, err = s.safety.Commit(ctx, lease, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
	return err
}

func (s *FixedService) WriteHeadscaleCertificateActivationFence(ctx context.Context, lease *locks.Lease, journalRef, priorPointer, candidatePointer string, observed safety.StopObservation, accessMayRemain bool) error {
	state, err := s.safety.ReadForRecovery(lease)
	if err != nil || state.Headscale.CertificateExpiry == nil {
		return fmt.Errorf("headscale certificate activation fence authority missing: %w", err)
	}
	graphDigest := shaDigest([]byte(journalRef + "/" + priorPointer + "/" + candidatePointer))
	fence := &safety.StopFence{Kind: safety.StopFenceCertificateActivation, OriginOperation: "certificate_renew", Scope: safety.FenceScope{Kind: "headscale"}, FenceGeneration: state.StopFenceSequence + 1, CreatedAt: time.Now().UTC(), SafetyGenerations: applicableHeadscaleMarkers(state), OwnedGraphDigest: graphDigest, InventoryDigest: graphDigest, Observation: observed, AccessMayRemain: accessMayRemain, CertificateActivation: &safety.CertificateActivationFence{JournalRef: journalRef, ResourceGeneration: state.Headscale.GenerationSequence, PriorPointer: priorPointer, CandidatePointer: candidatePointer, ExpiryGeneration: state.Headscale.CertificateExpiry.Generation}}
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

func (s *FixedService) WriteHeadscaleCertificateContractionFence(ctx context.Context, lease *locks.Lease, graphDigest string, observed safety.StopObservation, accessMayRemain bool) error {
	return commitHeadscaleCertificateContractionFence(ctx, lease, s.emergency, s.safety, graphDigest, observed, accessMayRemain)
}

func (s *FixedService) UpdateHeadscaleCertificateContractionFence(ctx context.Context, lease *locks.Lease, observation safety.StopObservation, accessMayRemain bool) error {
	return updateHeadscaleCertificateContractionFence(ctx, lease, s.emergency, s.safety, observation, accessMayRemain)
}

// commitHeadscaleCertificateContractionFence writes the fixed-format emergency
// authority before projecting the same exact fence into normal safety state.
// A one-sided emergency commit is projected on retry; it is never replaced by
// a newly inferred fence.
func commitHeadscaleCertificateContractionFence(ctx context.Context, lease *locks.Lease, emergency *safety.EmergencyStore, store *safety.Store, graphDigest string, observed safety.StopObservation, accessMayRemain bool) error {
	state, err := store.ReadForRecovery(lease)
	if err != nil || state.Headscale.CertificateExpiry == nil || state.StopFence != nil || observed.ObservedAt.IsZero() {
		return errors.Join(err, fmt.Errorf("headscale certificate contraction fence authority missing"))
	}
	marker := safety.MarkerGeneration{Kind: "certificate_expiry", Generation: state.Headscale.CertificateExpiry.Generation}
	authority, err := emergency.Authority()
	if err != nil {
		return err
	}
	var emergencyFence safety.EmergencyStopFence
	if authority.StopFence == nil {
		if authority.StopFenceSequence != state.StopFenceSequence {
			return fmt.Errorf("headscale certificate contraction fence high-water changed")
		}
		inventoryDigest, inventoryErr := store.OwnershipInventoryDigest()
		if inventoryErr != nil {
			return inventoryErr
		}
		emergencyFence = safety.EmergencyStopFence{Kind: safety.StopFenceContraction, OriginOperation: "certificate_expiry", ScopeKind: "headscale", Generation: authority.StopFenceSequence + 1, CertificateGeneration: marker.Generation, SafetyIntentGeneration: marker.Generation, SafetyIntentID: "headscale_certificate_expiry", OwnershipDigest: graphDigest, OwnedGraphDigest: graphDigest, InventoryDigest: inventoryDigest, MasterStopped: observed.MasterStopped, WorkersStopped: observed.WorkersStopped, ListenersStopped: observed.ListenersStopped, ObservedUnix: observed.ObservedAt.Unix(), AccessMayRemain: accessMayRemain}
		nextAuthority := authority
		nextAuthority.Sequence++
		nextAuthority.StopFenceSequence++
		nextAuthority.ReservedStopFenceKind = safety.StopFenceContraction
		nextAuthority.ReservedStopFenceDigest = ""
		nextAuthority.StopFence = &emergencyFence
		if err := emergency.Commit(lease, safety.RoleContraction, authority.Sequence, nextAuthority); err != nil {
			return err
		}
		authority = nextAuthority
	} else {
		emergencyFence = *authority.StopFence
		if emergencyFence.Kind != safety.StopFenceContraction || emergencyFence.OriginOperation != "certificate_expiry" || emergencyFence.ScopeKind != "headscale" || emergencyFence.CertificateGeneration != marker.Generation || emergencyFence.SafetyIntentGeneration != marker.Generation || emergencyFence.SafetyIntentID != "headscale_certificate_expiry" || emergencyFence.OwnershipDigest != graphDigest || emergencyFence.OwnedGraphDigest != graphDigest || authority.StopFenceSequence != state.StopFenceSequence+1 {
			return fmt.Errorf("one-sided Headscale certificate contraction fence identity changed")
		}
	}
	createdAt := time.Unix(emergencyFence.ObservedUnix, 0).UTC()
	fence := &safety.StopFence{Kind: safety.StopFenceContraction, OriginOperation: emergencyFence.OriginOperation, Scope: safety.FenceScope{Kind: "headscale"}, FenceGeneration: emergencyFence.Generation, CreatedAt: createdAt, SafetyGenerations: applicableHeadscaleMarkers(state), OwnedGraphDigest: emergencyFence.OwnedGraphDigest, InventoryDigest: emergencyFence.InventoryDigest, Observation: safety.StopObservation{MasterStopped: emergencyFence.MasterStopped, WorkersStopped: emergencyFence.WorkersStopped, ListenersStopped: emergencyFence.ListenersStopped, ObservedAt: createdAt}, AccessMayRemain: emergencyFence.AccessMayRemain, Contraction: &safety.ContractionFence{Authorities: []safety.MarkerGeneration{marker}, OwnershipDigest: emergencyFence.OwnershipDigest, SafetyIntentID: emergencyFence.SafetyIntentID, SafetyIntentGeneration: emergencyFence.SafetyIntentGeneration}}
	next := state
	next.Revision++
	next.AuthoritySequence = authority.Sequence
	next.StopFenceSequence = authority.StopFenceSequence
	next.StopFence = fence
	if _, err := store.Commit(ctx, lease, safety.RoleContraction, state.Revision, next, safety.TransitionProof{}); err != nil {
		return fmt.Errorf("emergency Headscale certificate contraction fence committed but normal projection failed: %w", err)
	}
	return nil
}

func updateHeadscaleCertificateContractionFence(ctx context.Context, lease *locks.Lease, emergency *safety.EmergencyStore, store *safety.Store, observation safety.StopObservation, accessMayRemain bool) error {
	state, err := store.ReadForRecovery(lease)
	if err != nil || observation.ObservedAt.IsZero() || state.StopFence == nil || state.StopFence.Kind != safety.StopFenceContraction || state.StopFence.OriginOperation != "certificate_expiry" || state.StopFence.Scope.Kind != "headscale" {
		return errors.Join(err, fmt.Errorf("headscale certificate contraction fence missing"))
	}
	authority, err := emergency.Authority()
	if err != nil || authority.StopFence == nil || !safety.FenceMatchesEmergency(state.StopFence, *authority.StopFence) {
		return errors.Join(err, fmt.Errorf("headscale emergency certificate contraction fence missing or mismatched"))
	}
	emergencyFence := *authority.StopFence
	emergencyFence.MasterStopped = observation.MasterStopped
	emergencyFence.WorkersStopped = observation.WorkersStopped
	emergencyFence.ListenersStopped = observation.ListenersStopped
	emergencyFence.ObservedUnix = observation.ObservedAt.Unix()
	emergencyFence.AccessMayRemain = accessMayRemain
	nextAuthority := authority
	nextAuthority.Sequence++
	nextAuthority.StopFence = &emergencyFence
	if err := emergency.Commit(lease, safety.RoleContraction, authority.Sequence, nextAuthority); err != nil {
		return err
	}
	next := state
	next.Revision++
	next.AuthoritySequence = nextAuthority.Sequence
	copy := *state.StopFence
	copy.Observation = safety.StopObservation{MasterStopped: emergencyFence.MasterStopped, WorkersStopped: emergencyFence.WorkersStopped, ListenersStopped: emergencyFence.ListenersStopped, ObservedAt: time.Unix(emergencyFence.ObservedUnix, 0).UTC()}
	copy.AccessMayRemain = emergencyFence.AccessMayRemain
	next.StopFence = &copy
	if _, err := store.Commit(ctx, lease, safety.RoleContraction, state.Revision, next, safety.TransitionProof{}); err != nil {
		return fmt.Errorf("emergency Headscale stop observation committed but normal projection failed: %w", err)
	}
	return nil
}

func applicableHeadscaleMarkers(state safety.State) []safety.MarkerGeneration {
	result := []safety.MarkerGeneration{}
	if state.GlobalClose.Phase != safety.GlobalCloseNone {
		result = append(result, safety.MarkerGeneration{Kind: "global_close", Generation: state.GlobalClose.Generation})
	}
	if state.Headscale.CertificateExpiry != nil {
		result = append(result, safety.MarkerGeneration{Kind: "certificate_expiry", Generation: state.Headscale.CertificateExpiry.Generation})
	}
	if state.Headscale.ChallengePending != nil {
		result = append(result, safety.MarkerGeneration{Kind: "challenge_pending", Generation: state.Headscale.ChallengePending.Generation})
	}
	if state.Headscale.Reactivating != nil {
		result = append(result, safety.MarkerGeneration{Kind: "reactivating", Generation: state.Headscale.Reactivating.Generation})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Kind < result[j].Kind })
	return result
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
	for _, resource := range state.Resources {
		if resource.ResourceID == resourceID {
			for _, value := range []struct {
				kind       string
				generation uint64
			}{{"sticky_unpublished", generation(resource.StickyUnpublished)}, {"closing", generation(resource.Closing)}, {"contraction", generation(resource.Contraction)}, {"certificate_expiry", deadlineGeneration(resource.CertificateExpiry)}, {"challenge_pending", challengeGeneration(resource.ChallengePending)}, {"reactivating", reactivationGeneration(resource.Reactivating)}} {
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
	return operations.PendingCertificateRecovery(document)
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
	return operations.PendingPublicationRecovery(document, state)
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

func (s *FixedService) OwnershipContractPublication(ctx context.Context, lease *locks.Lease, expected uint64, record ownership.Record) (ownership.Record, error) {
	if _, err := s.ownership.Write(ctx, lease, ownership.ContractionWriter, expected, record); err != nil {
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
	if err := operations.PendingPublicationRecovery(document, state); err != nil {
		return false, err
	}
	if err := operations.PendingCertificateRecovery(document); err != nil {
		return false, err
	}
	if err := operations.PendingJournalRecovery(document); err != nil {
		return false, err
	}
	if err := ValidateHeadscaleRecovery(document); err != nil {
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
	if err := VerifyInstalledPackageProfile(context.Background()); err != nil {
		return false, err
	}
	manifest, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return false, err
	}
	ownershipAuthority, err := fixedOwnershipAuthority(s.ownership)
	if err != nil {
		return false, err
	}
	return nginx.Guard(nginx.GuardInput{Action: nginx.GuardStart, Manifest: manifest, Safety: state, Installation: &installation, Ownership: ownershipAuthority, Now: now}).Allowed, nil
}

func fixedOwnershipAuthority(store *ownership.Store) (map[string]string, error) {
	inventory, err := store.Inventory()
	if err != nil || !inventory.Complete {
		return nil, fmt.Errorf("ownership inventory is incomplete: %w", err)
	}
	result := make(map[string]string, len(inventory.Records))
	for _, record := range inventory.Records {
		result[record.ResourceID] = record.Checksum
	}
	return result, nil
}

func (s *FixedService) CreatePlan(ctx context.Context, actor Actor, payload PlanPayload) (plans.Plan, error) {
	authority, err := actorAuthority(actor)
	if err != nil {
		return plans.Plan{}, err
	}
	if err := domain.ValidateOperationTarget(payload.Operation, payload.Target); err != nil {
		return plans.Plan{}, err
	}
	if payload.Operation != domain.OperationAdminTokenRotate && payload.Operation != domain.OperationCloseAll && payload.Operation != domain.OperationUnpublish && payload.Operation != domain.OperationPublish && payload.Operation != domain.OperationManagedBasicDelete && payload.Operation != domain.OperationManagedBasicRotate && payload.Operation != domain.OperationResourceDelete {
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
	if payload.Operation == domain.OperationResourceDelete {
		installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
		if err != nil {
			return plans.Plan{}, err
		}
		var resource *domain.AppResource
		for index := range installation.Resources {
			if installation.Resources[index].ID == payload.Target.ID {
				resource = &installation.Resources[index]
			}
		}
		if resource == nil || resource.Lifecycle != domain.LifecycleActive || resource.PublicationRecord.State != domain.PublicationUnpublished || resource.PublicationRecord.ActivationIntent != nil || resource.PublicationRecord.ContractionIntent != nil {
			return plans.Plan{}, fmt.Errorf("resource delete requires fresh unpublished closure")
		}
		if resource.ManagedProcess != nil && resource.ManagedProcess.Requested != domain.ProcessRequestedStopped {
			return plans.Plan{}, fmt.Errorf("resource delete requires stopped process")
		}
		if resourceHasManagedCredential(installation, resource.ID) {
			return plans.Plan{}, fmt.Errorf("resource delete requires managed credentials to be deleted first")
		}
		owned, err := s.ownership.Read(resource.ID)
		if err != nil || owned.State != ownership.Owned {
			return plans.Plan{}, fmt.Errorf("resource delete ownership authority unavailable: %w", err)
		}
		admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
		if err != nil {
			return plans.Plan{}, err
		}
		defer func(ignore func() error) { _ = ignore() }(admission.Release)
		return s.plans.Create(ctx, admission, document.Revision, plans.Spec{Operation: string(payload.Operation), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: authority, Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Applied: plans.DigestBinding{Applicable: true, Digest: owned.Checksum}, ExposureSummary: "deletes only LanPanel-managed inventory for resource " + resource.ID, Prerequisites: "fresh unpublished closure and stopped local cgroup", Lifetime: 10 * time.Minute})
	}
	if payload.Operation == domain.OperationManagedBasicDelete || payload.Operation == domain.OperationManagedBasicRotate {
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
		if payload.Operation == domain.OperationManagedBasicDelete {
			for _, resource := range installation.Resources {
				if applicationCredentialReferenced(resource, credential.ID) {
					return plans.Plan{}, fmt.Errorf("active resource reference blocks credential delete")
				}
			}
		}
		admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
		if err != nil {
			return plans.Plan{}, err
		}
		defer func(ignore func() error) { _ = ignore() }(admission.Release)
		spec := plans.Spec{Operation: string(payload.Operation), Target: plans.Target{Kind: plans.TargetCredential, ID: credential.ID}, ActorIdentity: authority, Config: plans.DigestBinding{Applicable: true, Digest: credential.Fingerprint}, ExposureSummary: "", Prerequisites: "", Lifetime: 10 * time.Minute}
		if payload.Operation == domain.OperationManagedBasicDelete {
			spec.ExposureSummary = "deletes_managed_basic_credential_" + credential.ID
			spec.Prerequisites = "credential_has_no_current_applied_or_activating_reference"
		} else {
			spec.ExposureSummary = "rotates_managed_basic_credential_" + credential.ID
			spec.Prerequisites = "credential_fingerprint_unchanged; old_password_becomes_invalid"
		}
		return s.plans.Create(ctx, admission, document.Revision, spec)
	}
	admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(admission.Release)
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
	if _, err := loadInstalledReleaseIdentity(); err != nil {
		return plans.Plan{}, fmt.Errorf("temporary publication requires an installed release identity: %w", err)
	}
	if resource.Target.WebSocket.Enabled || !publishTargetConfigured(installation, *resource) {
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
	readinessEvidence := plans.Evidence{Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: targetEvidenceGeneration(*resource), Digest: readiness.Digest, ObservedAt: readiness.ObservedAt}
	applied := plans.DigestBinding{}
	if resource.PublicationRecord.LastAppliedDigest != nil {
		applied = plans.DigestBinding{Applicable: true, Digest: *resource.PublicationRecord.LastAppliedDigest}
	}
	temporary := resource.Publication.TemporaryHTTP
	spec := plans.Spec{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: authority, Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Applied: applied, Evidence: []plans.Evidence{preflightEvidence, readinessEvidence}, ExposureSummary: fmt.Sprintf("url=http://%s:%d/ listener=0.0.0.0:%d auth=none cidrs=none static=disabled goaccess=disabled certificate=none target=resource/%s", temporary.PublicIPv4, temporary.Port, temporary.Port, resource.ID), Prerequisites: publication.PlaintextWarning, Lifetime: 10 * time.Minute}
	_ = request
	admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(admission.Release)
	return s.plans.Create(ctx, admission, document.Revision, spec)
}

func publishTargetConfigured(installation domain.Installation, resource domain.AppResource) bool {
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		return installation.Connector != nil && resource.ManagedProcess == nil
	}
	return resource.Target.Kind == domain.AppTargetLocalHTTP && resource.ManagedProcess != nil && resource.ManagedProcess.Requested == domain.ProcessRequestedRunning && resource.ManagedProcess.Applied != nil && resource.ManagedProcess.Applied.ConfigDigest == resource.CurrentConfigDigest
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
	if !publishTargetConfigured(installation, resource) {
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
	preflightEvidence.Digest, err = headscalePreflightObservationDigest(preflightResult)
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
	readinessEvidence := plans.Evidence{Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: targetEvidenceGeneration(resource), Digest: readiness.Digest, ObservedAt: readiness.ObservedAt}
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
	defer func(ignore func() error) { _ = ignore() }(admission.Release)
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
