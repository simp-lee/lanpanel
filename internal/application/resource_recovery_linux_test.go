//go:build linux

package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"lanpanel/internal/activation"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/resource"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSafetyCommittedTailnetCreateRecovery(t *testing.T) {
	created := recoveryTailnetResource()
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(nil))
	service := fixture.open(t)
	admitter, err := service.resourceAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	job, err := admitter.Admit(context.Background(), admission, operations.AdmitRequest{Operation: operations.ResourceCreate, Target: "installation", ActorIdentity: "ui/session/generation/1", Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{ResourceID: created.ID}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		t.Fatal(errors.Join(err, releaseErr))
	}
	mutationSet, mutation, exposure := fixture.acquire(t, service, "installation")
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	intent, err := admitter.BeginUI(context.Background(), mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1})
	if err != nil {
		t.Fatal(err)
	}
	owned := writeRecoveryOwnershipAndSafety(t, service, exposure, created.ID)
	journal := ResourceCreateJournal{SchemaVersion: "lanpanel.resource.create.v1", JobID: job.ID, ResourceID: created.ID, Resource: created, Phase: "safety_committed", OwnershipDigest: owned.Checksum}
	journalPath := filepath.Join(fixture.root, "safety", "resource-create", created.ID+".json")
	writeCanonicalRecoveryJournal(t, journalPath, journal)
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}

	if err := reconcileResourceCreateWithRuntime(context.Background(), journalPath, fixture.runtime()); err != nil {
		t.Fatal(err)
	}
	service = fixture.open(t)
	defer func() { _ = service.Close() }()
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	normal := findNormalResource(installation, created.ID)
	terminal, err := jobs.LoadEntries(document.Entries, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.safety.Read()
	if err != nil {
		t.Fatal(err)
	}
	if intent.Phase != operations.PhaseLocalIntent || normal == nil || normal.ManagedProcess != nil || normal.PublicationRecord.LastOperation != domain.OperationResourceCreate || terminal.Status != jobs.StatusTerminal || terminal.Result != jobs.ResultSucceeded || findSafetyResource(state, created.ID) == nil {
		t.Fatalf("normal=%#v terminal=%#v safety=%#v", normal, terminal, state)
	}
	if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("create recovery journal remains: %v", err)
	}
}

func TestTailnetUpdateJournalRecovery(t *testing.T) {
	prior := recoveryTailnetResource()
	runResourceUpdateJournalRecovery(t, prior, func(installation domain.Installation, prior domain.AppResource) (domain.AppResource, error) {
		candidate := prior
		candidate.Target.TailnetHTTP = &domain.TailnetHTTPTarget{IP: "100.64.0.3", SourceIP: "100.64.0.1", Port: 8081}
		return resource.PrepareUpdate(installation, candidate)
	}, func(t *testing.T, _, candidate, normal domain.AppResource) {
		if normal.ManagedProcess != nil || normal.Name != candidate.Name || !reflect.DeepEqual(normal.Target, candidate.Target) {
			t.Fatalf("Tailnet update normal=%#v candidate=%#v", normal, candidate)
		}
	})
}

func TestLocalUpdateJournalRecoveryPreservesProcessState(t *testing.T) {
	t.Run("service_configuration", func(t *testing.T) {
		prior := recoveryLocalResource(t)
		runResourceUpdateJournalRecovery(t, prior, func(installation domain.Installation, prior domain.AppResource) (domain.AppResource, error) {
			candidate := prior
			process := *prior.ManagedProcess
			process.Service.Arguments = []string{"--updated"}
			candidate.ManagedProcess = &process
			return resource.PrepareUpdate(installation, candidate)
		}, func(t *testing.T, prior, candidate, normal domain.AppResource) {
			if normal.ManagedProcess == nil || !reflect.DeepEqual(normal.ManagedProcess, candidate.ManagedProcess) || reflect.DeepEqual(normal.ManagedProcess.Service, prior.ManagedProcess.Service) {
				t.Fatalf("prior process=%#v candidate process=%#v normal process=%#v", prior.ManagedProcess, candidate.ManagedProcess, normal.ManagedProcess)
			}
		})
	})

	t.Run("reference_bound_reapply", func(t *testing.T) {
		prior := recoveryLocalResource(t)
		runResourceUpdateJournalRecovery(t, prior, func(installation domain.Installation, prior domain.AppResource) (domain.AppResource, error) {
			candidate := prior
			process := *prior.ManagedProcess
			candidate.ManagedProcess = &process
			candidate, err := resource.PrepareUpdate(installation, candidate)
			if err != nil {
				return domain.AppResource{}, err
			}
			applied := prior.ManagedProcess.Applied
			binding := domain.ProcessReferenceBinding{ExecutableDigest: applied.ExecutableDigest, WorkingDirectoryIdentity: applied.WorkingDirectoryIdentity, EnvironmentFingerprint: applied.EnvironmentFingerprint, WritePathIdentities: append([]string(nil), applied.WritePathIdentities...)}
			candidate.ManagedProcess.ReferenceBinding = &binding
			candidate.CurrentConfigDigest = ""
			candidate.CurrentConfigDigest, err = resource.ConfigDigest(candidate)
			return candidate, err
		}, func(t *testing.T, _, candidate, normal domain.AppResource) {
			if normal.ManagedProcess == nil || normal.ManagedProcess.ReferenceBinding == nil || !reflect.DeepEqual(normal.ManagedProcess.ReferenceBinding, candidate.ManagedProcess.ReferenceBinding) {
				t.Fatalf("reference binding was not recovered: candidate=%#v normal=%#v", candidate.ManagedProcess, normal.ManagedProcess)
			}
		})
	})

	t.Run("publication_only_with_applied_process", func(t *testing.T) {
		prior := recoveryLocalResource(t)
		runResourceUpdateJournalRecovery(t, prior, func(installation domain.Installation, prior domain.AppResource) (domain.AppResource, error) {
			candidate := prior
			publication := *prior.Publication.DomainHTTPS
			publication.CanonicalDomain = "updated-local.example.test"
			candidate.Publication.DomainHTTPS = &publication
			return resource.PrepareUpdate(installation, candidate)
		}, func(t *testing.T, prior, candidate, normal domain.AppResource) {
			if normal.ManagedProcess == nil || !reflect.DeepEqual(normal.ManagedProcess, candidate.ManagedProcess) || !reflect.DeepEqual(normal.ManagedProcess.Applied, prior.ManagedProcess.Applied) {
				t.Fatalf("prior process=%#v candidate process=%#v normal process=%#v", prior.ManagedProcess, candidate.ManagedProcess, normal.ManagedProcess)
			}
		})
	})
}

func runResourceUpdateJournalRecovery(t *testing.T, prior domain.AppResource, prepare func(domain.Installation, domain.AppResource) (domain.AppResource, error), verify func(*testing.T, domain.AppResource, domain.AppResource, domain.AppResource)) {
	t.Helper()
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(&prior))
	service := fixture.open(t)
	setupSet, mutation, exposure := fixture.acquire(t, service, "resource/"+prior.ID)
	writeRecoveryOwnershipAndSafety(t, service, exposure, prior.ID)
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), setupSet.Close()); err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	persistedPrior := findNormalResource(installation, prior.ID)
	if persistedPrior == nil {
		t.Fatal("resource update prior is missing")
	}
	candidate, err := prepare(installation, *persistedPrior)
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	job, err := admitter.Admit(context.Background(), admission, operations.AdmitRequest{Operation: operations.ResourceUpdate, Target: "resource/" + prior.ID, ActorIdentity: "ui/session/generation/1", Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{ResourceID: prior.ID, CandidateDigest: candidate.CurrentConfigDigest, CandidateBundle: persistedPrior.CurrentConfigDigest}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		t.Fatal(errors.Join(err, releaseErr))
	}
	mutationSet, mutation, exposure := fixture.acquire(t, service, "resource/"+prior.ID)
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.BeginUI(context.Background(), mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1}); err != nil {
		t.Fatal(err)
	}
	journal := ResourceUpdateJournal{SchemaVersion: resourceUpdateJournalSchema, JobID: job.ID, ResourceID: prior.ID, Prior: *persistedPrior, Candidate: candidate}
	journalPath := filepath.Join(fixture.root, "safety", "resource-update", prior.ID+".json")
	writeCanonicalRecoveryJournal(t, journalPath, journal)
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}
	if err := reconcileResourceUpdateWithRuntime(context.Background(), journalPath, fixture.runtime()); err != nil {
		t.Fatal(err)
	}
	service = fixture.open(t)
	defer func() { _ = service.Close() }()
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	installation, err = installationFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	normal := findNormalResource(installation, prior.ID)
	terminal, err := jobs.LoadEntries(document.Entries, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if normal == nil || normal.PublicationRecord.LastOperation != domain.OperationResourceUpdate || terminal.Status != jobs.StatusTerminal || terminal.Result != jobs.ResultSucceeded {
		t.Fatalf("normal=%#v terminal=%#v", normal, terminal)
	}
	verify(t, *persistedPrior, candidate, *normal)
	if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("update recovery journal remains: %v", err)
	}
}

func TestHeadscalePriorReloadAuthorityGuardsPriorInsteadOfInvalidCandidate(t *testing.T) {
	currentTime := time.Unix(1_800_000_000, 0).UTC()
	priorDeadline := currentTime.Add(time.Hour)
	prior := domain.CertificateBundleIdentity{Generation: 1, Fingerprint: recoveryDigest("prior-certificate"), BindingIdentity: recoveryDigest("prior-binding"), NotAfter: priorDeadline.Format(time.RFC3339), LastTrustedWall: currentTime.Add(-time.Hour).Format(time.RFC3339)}
	entry := nginx.Entry{Kind: nginx.EntryControl, Relative: nginx.ControlDirectory + "/headscale.conf", Digest: recoveryDigest("control-entry"), Domains: []string{"control.example.test"}, Listeners: []string{"tcp:0.0.0.0:443", "tcp:0.0.0.0:80", "tcp:[::]:443", "tcp:[::]:80"}, Generation: 1, Domain: &nginx.DomainSite{Hosts: []string{"control.example.test"}, CertificatePointer: "/var/lib/lanpanel/certificates/active/cert_headscale", RejectionAuditPath: "/var/log/lanpanel/nginx-rejections.log", AuthMode: "application_managed", UpstreamNetwork: "unix", UpstreamAddress: "/run/lanpanel-headscale-control/control.sock", WebSocket: true}}
	manifest := nginx.Manifest{SchemaVersion: nginx.ManifestSchema, InstallationID: "ins_00000000000000000000000000000001", GenerationID: "gen_control", DefaultCertFingerprint: recoveryDigest("default-certificate"), MainDigest: recoveryDigest("main"), SanitizerDigest: recoveryDigest("sanitizer"), Entries: []nginx.Entry{entry}}
	applied := domain.HeadscaleAppliedIdentity{Generation: entry.Generation}
	installation := domain.Installation{InstallationID: manifest.InstallationID, Headscale: &domain.HeadscaleDomain{Enabled: true, Applied: &applied, Certificate: &prior}}
	state := safety.EmptyState()
	state.Headscale.GenerationSequence = 2
	state.Headscale.ControlEntryDigest = entry.Digest
	state.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: prior.Generation, Fingerprint: prior.Fingerprint, Binding: prior.BindingIdentity, NotAfter: priorDeadline, LastTrustedWall: currentTime.Add(-time.Hour)}
	base := headscaleBaseSnapshot(state.Headscale)
	state.Headscale.Reactivating = &safety.HeadscaleReactivating{Generation: 2, PriorGeneration: 1, PlanID: "plan_reissue", ControlGeneration: entry.Generation, CertificateGeneration: 2, CertificateFingerprint: recoveryDigest("candidate-certificate"), CandidateDigest: recoveryDigest("candidate-config"), CandidateBundle: recoveryDigest("candidate-bundle"), ActivationDigest: recoveryDigest("candidate-activation"), ControlEntryDigest: entry.Digest, BaseMarkers: base, CertificateUntil: currentTime.Add(-time.Second), CertificateLastTrustedWall: currentTime.Add(-time.Hour)}
	if err := safety.Validate(state); err != nil {
		t.Fatal(err)
	}
	authority, err := activation.NewReloadAuthority(func() (activation.ReloadAuthoritySnapshot, error) {
		return activation.ReloadAuthoritySnapshot{Safety: state, Installation: installation, Ownership: map[string]string{}, ObservedAt: currentTime}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Guard(manifest); err == nil {
		t.Fatal("expired candidate unexpectedly authorized the reactivation graph")
	}
	expectedReactivating := *state.Headscale.Reactivating
	priorAuthority, err := headscalePriorCertificateReloadAuthority(authority, prior, expectedReactivating)
	if err != nil {
		t.Fatal(err)
	}
	if err := priorAuthority.Guard(manifest); err != nil {
		t.Fatalf("valid prior certificate rollback was rejected by candidate authority: %v", err)
	}
	installation.InstallationID = "ins_00000000000000000000000000000002"
	if err := priorAuthority.Guard(manifest); err == nil {
		t.Fatal("mismatched installation authorized prior rollback")
	}
	installation.InstallationID = manifest.InstallationID
	changedReactivating := expectedReactivating
	changedReactivating.PlanID = "plan_changed"
	state.Headscale.Reactivating = &changedReactivating
	if err := priorAuthority.Guard(manifest); err == nil {
		t.Fatal("changed Headscale reactivation marker authorized prior rollback")
	}
	state.Headscale.Reactivating = &expectedReactivating
	currentTime = priorDeadline
	if err := priorAuthority.Guard(manifest); err == nil {
		t.Fatal("expired prior Headscale certificate authorized rollback reload")
	}
}

func TestChallengeRecoveryReloadAuthorityIsRereadInsideExposureLock(t *testing.T) {
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(nil))
	service := fixture.open(t)
	defer func() { _ = service.Close() }()
	if _, err := challengeReloadAuthorityForExposure(service, nil); err == nil {
		t.Fatal("challenge reload authority was read without the exposure lock")
	}
	before, err := service.safety.Read()
	if err != nil {
		t.Fatal(err)
	}
	resourceID := "res_00000000000000000000000000000001"
	set, mutation, exposure := fixture.acquire(t, service, "resource/"+resourceID)
	defer func() { _ = errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()) }()
	record := writeRecoveryOwnershipAndSafety(t, service, exposure, resourceID)
	authority, err := challengeReloadAuthorityForExposure(service, exposure)
	if err != nil {
		t.Fatal(err)
	}
	current, err := authority.Current()
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Resources) != 0 || findSafetyResource(current.Safety, resourceID) == nil || current.Ownership[resourceID] != record.Checksum || current.Installation.InstallationID != "ins_00000000000000000000000000000001" || current.ObservedAt.IsZero() {
		t.Fatalf("locked challenge reload authority is stale: before=%#v authority=%#v", before, current)
	}
	if err := operations.ReleaseExposure(mutation, exposure); err != nil {
		t.Fatal(err)
	}
	mutation, exposure = nil, nil
	if _, err := authority.Current(); err == nil {
		t.Fatal("challenge reload authority reused stale state after the exposure lock was released")
	}
}

type resourceRecoveryFixture struct {
	root  string
	owner filetxn.Owner
}

func newResourceRecoveryFixture(t *testing.T, installation domain.Installation) resourceRecoveryFixture {
	t.Helper()
	fixture := resourceRecoveryFixture{root: t.TempDir(), owner: filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}
	if err := os.Chmod(fixture.root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fixture.lockRoot(), filepath.Join(fixture.root, "state"), filepath.Join(fixture.root, "state", ".filetxn"), filepath.Join(fixture.root, "ownership"), filepath.Join(fixture.root, "ownership", ".filetxn"), filepath.Join(fixture.root, "ownership", "records"), filepath.Join(fixture.root, "safety"), filepath.Join(fixture.root, "safety", ".filetxn")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := locks.Open(locks.Config{RootPath: fixture.lockRoot(), Owner: fixture.owner.UID, Group: fixture.owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	emergency, err := safety.CreateEmergency(fixture.emergencyPath(), fixture.owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(emergency.Close(), manager.Close()); err != nil {
		t.Fatal(err)
	}
	service := fixture.open(t)
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.normal.Initialize(context.Background(), admission); err != nil {
		t.Fatal(err)
	}
	raw, err := persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.normal.Update(context.Background(), admission, 1, func(transaction *persist.Transaction) error {
		return transaction.Create("installations/current", raw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}
	exposure, err := service.manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.safety.Initialize(context.Background(), exposure); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(exposure.Release(), service.Close()); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture resourceRecoveryFixture) open(t *testing.T) *FixedService {
	t.Helper()
	service, err := fixture.openService()
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (fixture resourceRecoveryFixture) openService() (*FixedService, error) {
	manager, err := locks.Open(locks.Config{RootPath: fixture.lockRoot(), Owner: fixture.owner.UID, Group: fixture.owner.GID, Mode: 0o700})
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*FixedService, error) {
		_ = manager.Close()
		return nil, cause
	}
	normal, err := persist.Open(persist.Config{RootPath: filepath.Join(fixture.root, "state"), StagingPath: filepath.Join(fixture.root, "state", ".filetxn"), StatePath: filepath.Join(fixture.root, "state", "normal.json"), Owner: fixture.owner, LockAuthority: manager.Authority()})
	if err != nil {
		return fail(err)
	}
	if err := operations.Register(normal); err != nil {
		_ = normal.Close()
		return fail(err)
	}
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: filepath.Join(fixture.root, "ownership"), StagingPath: filepath.Join(fixture.root, "ownership", ".filetxn"), RecordsPath: filepath.Join(fixture.root, "ownership", "records"), Owner: fixture.owner, Policy: ownership.FixedPolicy(), LockAuthority: manager.Authority()})
	if err != nil {
		_ = normal.Close()
		return fail(err)
	}
	emergency, err := safety.OpenEmergency(fixture.emergencyPath(), fixture.owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		_ = ownershipStore.Close()
		_ = normal.Close()
		return fail(err)
	}
	safetyStore, err := safety.OpenStore(safety.StoreConfig{RootPath: filepath.Join(fixture.root, "safety"), StagingPath: filepath.Join(fixture.root, "safety", ".filetxn"), StatePath: filepath.Join(fixture.root, "safety", "state.json"), Owner: fixture.owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		_ = emergency.Close()
		_ = ownershipStore.Close()
		_ = normal.Close()
		return fail(err)
	}
	return &FixedService{root: fixture.root, owner: fixture.owner, normal: normal, manager: manager, safety: safetyStore, emergency: emergency, ownership: ownershipStore}, nil
}

func (fixture resourceRecoveryFixture) acquire(t *testing.T, service *FixedService, target string) (*operations.MutationSet, *operations.MutationLease, *locks.Lease) {
	t.Helper()
	set, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixture.lockRoot(), Owner: fixture.owner.UID, Group: fixture.owner.GID, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	mutation, exposure, err := set.AcquireExposure(context.Background(), target, service.manager)
	if err != nil {
		_ = set.Close()
		t.Fatal(err)
	}
	return set, mutation, exposure
}

func (fixture resourceRecoveryFixture) runtime() resourceRecoveryRuntime {
	return resourceRecoveryRuntime{openService: fixture.openService, lockRoot: fixture.lockRoot(), owner: fixture.owner.UID, group: fixture.owner.GID}
}

func (fixture resourceRecoveryFixture) lockRoot() string { return filepath.Join(fixture.root, "locks") }
func (fixture resourceRecoveryFixture) emergencyPath() string {
	return filepath.Join(fixture.root, "safety", "emergency")
}

func writeRecoveryOwnershipAndSafety(t *testing.T, service *FixedService, exposure *locks.Lease, resourceID string) ownership.Record {
	t.Helper()
	paths, err := resource.DerivePaths(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	record := ownership.Record{Revision: 1, ResourceID: resourceID, State: ownership.Owned, Paths: []ownership.OwnedPath{{Kind: ownership.PathService, Path: paths.ResourceRoot, IdentityDigest: ownership.PathIdentity(resourceID, ownership.PathService, paths.ResourceRoot)}}}
	if _, err := service.ownership.Write(context.Background(), exposure, ownership.ActivationWriter, 0, record); err != nil {
		t.Fatal(err)
	}
	persisted, err := service.ownership.Read(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		t.Fatal(err)
	}
	next := state
	next.Revision++
	next.Resources = append(append([]safety.ResourceSafety(nil), state.Resources...), initialResourceSafety(resourceID, persisted.Checksum))
	if _, err := service.safety.Commit(context.Background(), exposure, safety.RoleResourceCreate, state.Revision, next, safety.TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	return persisted
}

func recoveryResourceInstallation(value *domain.AppResource) domain.Installation {
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.23.45.67", Port: 23456}, Connector: &domain.TailnetConnector{ID: "con_00000000000000000000000000000001", ControlURL: "https://control.example.test", ManagedPaths: domain.ConnectorManagedPaths()}}
	if value != nil {
		installation.Resources = []domain.AppResource{*value}
	}
	return installation
}

func recoveryTailnetResource() domain.AppResource {
	value := domain.AppResource{ID: "res_00000000000000000000000000000001", Name: "Peer App", Lifecycle: domain.LifecycleActive, Target: domain.AppTarget{Kind: domain.AppTargetTailnetHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, TailnetHTTP: &domain.TailnetHTTPTarget{IP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "peer.example.test", AccessMode: domain.AppAccessPublic}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}}
	value.CurrentConfigDigest, _ = resource.ConfigDigest(value)
	return value
}

func recoveryLocalResource(t *testing.T) domain.AppResource {
	t.Helper()
	value, err := resource.NewLocal(resource.LocalSpec{Name: "Local App", EndpointKind: domain.LocalEndpointUnixSocketActivation, ReadinessPath: "/ready", Service: domain.ManagedService{Executable: "/usr/local/bin/local-app", WorkingDirectory: "/srv/local-app", WritePaths: []string{"/srv/local-app/data"}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "local.example.test", AccessMode: domain.AppAccessPublic}}}, bytes.NewReader(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	value.ManagedProcess.Applied = &domain.ProcessBundle{Generation: 1, ConfigDigest: value.CurrentConfigDigest, UnitDigest: recoveryDigest("unit"), SocketUnitDigest: recoveryDigest("socket"), PolicyDigest: recoveryDigest("policy"), AccountDigest: recoveryDigest("account"), ExecutableDigest: recoveryDigest("executable"), WorkingDirectoryIdentity: recoveryDigest("working-directory"), Cgroup: "/sys/fs/cgroup/lanpanel-local-app", FrontendEndpoint: "/run/lanpanel/local-app.sock", EndpointSocketUnits: []string{"lanpanel-local-app.socket"}, ApplicationUID: 1000, ApplicationGID: 1000, FrontendGID: 33, FrontendMode: 0o660, ManagedPaths: append([]string(nil), value.ManagedPaths...)}
	value.ManagedProcess.LastOperation = domain.OperationProcessStop
	value.ManagedProcess.LastOperationResult = domain.OperationSucceeded
	value.ManagedProcess.LastJobID = "job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return value
}

func recoveryDigest(seed string) string {
	character := "abcdef0123456789"[len(seed)%16]
	return "sha256:" + strings.Repeat(string(character), 64)
}

func writeCanonicalRecoveryJournal(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
