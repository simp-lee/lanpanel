package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/preflight"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTrustedMeshCandidateIsPrivateAndDeterministic(t *testing.T) {
	rendered := testRendered(t)
	if err := VerifyRendered(rendered); err != nil {
		t.Fatal(err)
	}
	if rendered.Candidate.PublicSTUN || !strings.Contains(string(rendered.Unit), "PrivateNetwork=yes") || !strings.Contains(string(rendered.Unit), "CapabilityBoundingSet=\n") || strings.Contains(string(rendered.Config), "derpmap") {
		t.Fatal("candidate service lost its private, empty-capability, no-external-DERP contract")
	}
	if !strings.Contains(string(rendered.Policy), `"src":["*"]`) || !strings.Contains(string(rendered.Policy), `"dst":["*:*"`) {
		t.Fatal("trusted-mesh all-member allow policy missing")
	}
	second := testRendered(t)
	if rendered.Candidate != second.Candidate || !slices.Equal(rendered.Config, second.Config) || !slices.Equal(rendered.Policy, second.Policy) || !slices.Equal(rendered.Unit, second.Unit) {
		t.Fatal("same authority rendered different Headscale candidate bytes")
	}
	changed := testBinding()
	changed.AccountKeyFingerprint = testDigest("other-account")
	third, err := Build(BuildRequest{InstallationID: "ins_00000000000000000000000000000001", Headscale: testHeadscale(), Binding: changed, CertificateID: "cert_00000000000000000000000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	if third.Candidate.CertificateBinding == rendered.Candidate.CertificateBinding || third.Candidate.ControlIdentity == rendered.Candidate.ControlIdentity {
		t.Fatal("credential binding change did not change control authority")
	}
}

func TestCandidateJournalStopsBeforeRemoteAndRejectsPublicSTUN(t *testing.T) {
	rendered := testRendered(t)
	request, result := testPreflight(t, rendered.Candidate)
	store := testStore(t)
	host := &fakeCandidateHost{}
	execution, err := Prepare(context.Background(), store, host, StageRequest{InstallationID: "ins_00000000000000000000000000000001", JobID: "job_control_candidate", PlanID: "plan_control_candidate", IntentGeneration: 9, Rendered: rendered, Preflight: request, PreflightResult: result})
	if err != nil {
		t.Fatal(err)
	}
	if execution.Journal().Phase != PhaseCertificatePending || host.databaseCalls != 1 || host.serviceCalls != 1 || host.stopCalls != 0 {
		t.Fatalf("unexpected local stage state: %+v host=%+v", execution.Journal(), host)
	}
	issue, err := execution.IssueRequest()
	if err != nil || issue.CertificateID != rendered.Candidate.CertificateID || issue.BindingDigest != rendered.Candidate.CertificateBinding {
		t.Fatalf("issue=%+v err=%v", issue, err)
	}
	resumed, err := ResumeLocal(context.Background(), store, host, rendered)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Journal().Phase != PhaseCertificatePending || host.databaseCalls != 1 || host.serviceCalls != 1 {
		t.Fatal("resume repeated local or remote work")
	}
	if _, err := ResumeStoppedLocal(context.Background(), store, host, rendered); err != nil || host.databaseCalls != 1 || host.serviceCalls != 2 {
		t.Fatalf("stopped local recovery did not re-probe exact journal: calls=%+v err=%v", host, err)
	}

	publicStore := testStore(t)
	publicHost := &fakeCandidateHost{public: true}
	if _, err := Prepare(context.Background(), publicStore, publicHost, StageRequest{InstallationID: "ins_00000000000000000000000000000001", JobID: "job_public_candidate", PlanID: "plan_public_candidate", IntentGeneration: 10, Rendered: rendered, Preflight: request, PreflightResult: result}); err == nil || publicHost.stopCalls != 1 {
		t.Fatal("premature public STUN did not fail closed and stop candidate")
	}
}

func TestCertificateResultMustMatchSameDeployAuthority(t *testing.T) {
	rendered := testRendered(t)
	request, result := testPreflight(t, rendered.Candidate)
	store := testStore(t)
	host := &fakeCandidateHost{}
	execution, err := Prepare(context.Background(), store, host, StageRequest{InstallationID: "ins_00000000000000000000000000000001", JobID: "job_certificate_candidate", PlanID: "plan_certificate_candidate", IntentGeneration: 11, Rendered: rendered, Preflight: request, PreflightResult: result})
	if err != nil {
		t.Fatal(err)
	}
	issue, _ := execution.IssueRequest()
	identity := testCertificateIdentity(issue)
	wrong := issue
	wrong.IntentGeneration++
	if err := execution.StageCertificate(context.Background(), wrong, identity); err == nil {
		t.Fatal("cross-generation certificate result accepted")
	}
	if execution.Journal().Phase != PhaseCertificatePending {
		t.Fatal("rejected certificate changed journal")
	}
	if err := execution.StageCertificate(context.Background(), issue, identity); err != nil {
		t.Fatal(err)
	}
	if execution.Journal().Phase != PhaseCertificateStaged {
		t.Fatal("exact certificate did not stage")
	}
	if err := execution.VerifyPrivateCandidate(context.Background()); err != nil || host.serviceCalls != 2 {
		t.Fatalf("activation-time private verification failed: calls=%d err=%v", host.serviceCalls, err)
	}
	activationBundle, bundleErr := BuildActivation("ins_00000000000000000000000000000001", rendered.Candidate, identity)
	if bundleErr != nil {
		t.Fatal(bundleErr)
	}
	activationIntent := execution.Journal()
	activationIntent.Phase = PhaseActivationIntent
	activationIntent.ActivationDigest = activationBundle.Digest
	if err := store.Replace(context.Background(), execution.Journal(), activationIntent); err != nil {
		t.Fatal(err)
	}
	activated := activationIntent
	activated.Phase = PhaseActivated
	activated.RuntimeDigest = testDigest("runtime")
	if err := store.Replace(context.Background(), activationIntent, activated); err != nil {
		t.Fatal(err)
	}
	contracted, err := store.Contract(context.Background(), activated)
	if err != nil || contracted.Phase != PhaseContracted || contracted.Certificate == nil || contracted.Certificate.Fingerprint != identity.Fingerprint || contracted.RuntimeDigest != "" || contracted.ActivationDigest != activationIntent.ActivationDigest {
		t.Fatalf("activated certificate contraction lost durable identity: %+v err=%v", contracted, err)
	}
	if repeated, err := store.Contract(context.Background(), contracted); err != nil || repeated.Phase != PhaseContracted {
		t.Fatalf("contracted journal was not idempotent: %+v err=%v", repeated, err)
	}
}

type fakeCandidateHost struct {
	databaseCalls int
	serviceCalls  int
	stopCalls     int
	public        bool
}

func (host *fakeCandidateHost) ValidateFreshCandidate(context.Context, Rendered) error { return nil }
func (host *fakeCandidateHost) CommitFreshBoundary(context.Context, Rendered) error    { return nil }
func (host *fakeCandidateHost) InitializeDatabase(_ context.Context, rendered Rendered) (DatabaseEvidence, error) {
	host.databaseCalls++
	return DatabaseEvidence{UUID: rendered.Candidate.DatabaseUUID, Generation: rendered.Candidate.DatabaseGeneration, MainDigest: testDigest("database-main"), InitializedDigest: testDigest("database")}, nil
}
func (host *fakeCandidateHost) StagePrivateService(_ context.Context, rendered Rendered, _ DatabaseEvidence) (ServiceEvidence, error) {
	host.serviceCalls++
	return ServiceEvidence{Identity: rendered.Candidate.ServiceIdentity, PrivateProbe: testDigest("private-probe"), PublicSTUNOpen: host.public}, nil
}
func (host *fakeCandidateHost) VerifyActiveCandidate(_ context.Context, rendered Rendered, _ DatabaseEvidence, expected ServiceEvidence) error {
	host.serviceCalls++
	actual := ServiceEvidence{Identity: rendered.Candidate.ServiceIdentity, PrivateProbe: testDigest("private-probe"), PublicSTUNOpen: host.public}
	if actual != expected {
		return fmt.Errorf("active evidence changed")
	}
	return nil
}
func (host *fakeCandidateHost) StopPrivateService(context.Context, Candidate) error {
	host.stopCalls++
	return nil
}

func testRendered(t *testing.T) Rendered {
	t.Helper()
	value, err := Build(BuildRequest{InstallationID: "ins_00000000000000000000000000000001", Headscale: testHeadscale(), Binding: testBinding(), CertificateID: "cert_00000000000000000000000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func testHeadscale() domain.HeadscaleDomain {
	return domain.HeadscaleDomain{ID: "hds_00000000000000000000000000000001", ControlDomain: "control.example.test", MagicDNSNamespace: "mesh.example.test", Policy: "trusted_mesh", Artifact: domain.HeadscaleArtifactIdentity{BaselineDigest: testDigest("baseline"), Version: "0.25.1", ArchiveDigest: testDigest("archive"), ExecutableDigest: testDigest("executable"), ConfigContract: ConfigContract, ConfigContractDigest: testDigest("contract")}, Database: domain.HeadscaleDatabaseIdentity{UUID: "hdb_00000000000000000000000000000001", SQLitePath: FixedPaths().Database, IdentityBundleDigest: testDigest("bundle"), Generation: 1, Phase: domain.HeadscaleIdentityCommitted}, DesiredDigest: testDigest("desired"), ManagedPaths: domain.HeadscaleManagedPaths()}
}
func testBinding() acme.Binding {
	return acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/var/lib/lanpanel/credentials/acme-account.key", AccountKeyFingerprint: testDigest("account"), Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}, AccountEmail: "admin@example.test", TermsAccepted: true}
}
func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func testStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := FixedPaths()
	paths.JournalRoot = root
	paths.RuntimeRoot = filepath.Join(root, "runtime")
	paths.Database = filepath.Join(paths.RuntimeRoot, "db.sqlite")
	paths.Journal = filepath.Join(root, "deploy.json")
	paths.JournalStaging = filepath.Join(root, ".filetxn")
	return NewStore(paths, filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())})
}
func testPreflight(t *testing.T, candidate Candidate) (preflight.ExpansionRequest, preflight.Result) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	profile := preflight.ExpectedProfile{ID: "debian", VersionID: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: testDigest("packages"), ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8"}, QualificationDigest: testDigest("confinement")}, Authority: preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: testDigest("profile"), LiveQualified: true}}
	request := preflight.ExpansionRequest{Scope: preflight.ExpansionHeadscale, Target: "headscale", Generation: candidate.DatabaseGeneration, Profile: profile, Domains: []string{candidate.ControlDomain}, Disks: []preflight.DiskRequirement{{Path: "/var/lib/lanpanel", MinimumAvailableBytes: 1}}, LastTrustedWall: now.Add(-time.Second)}
	result, err := preflight.EvaluateExpansion(request, preflight.ExpansionObservations{OperatingSystem: "linux", Architecture: "amd64", Platform: preflight.PlatformInfo{ID: "debian", VersionID: "13"}, Clock: preflight.ClockObservation{Now: now, Synchronized: true, Source: "kernel"}, ExecutorUID: 0, Systemd: preflight.ComponentObservation{Available: true, Identity: "systemd/1"}, APT: preflight.ComponentObservation{Available: true, Identity: "apt/1"}, DPKG: preflight.ComponentObservation{Available: true, Identity: "dpkg/1"}, Packages: preflight.PackageObservation{Ready: true, Identity: testDigest("package-observation"), SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: testDigest("packages")}, DNS: []preflight.DNSObservation{{Domain: candidate.ControlDomain, Addresses: []string{"8.8.8.8"}}}, ListenerInventoryComplete: true, Disks: []preflight.DiskObservation{{Path: "/var/lib/lanpanel", Device: 1, AvailableBytes: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return request, result
}
func testCertificateIdentity(request IssueRequest) certificates.Identity {
	now := time.Now().UTC().Truncate(time.Second)
	value := certificates.Identity{SchemaVersion: certificates.SchemaVersion, ID: request.CertificateID, Generation: 1, Domains: []string{request.Domain}, SANIdentity: testDigest("san"), Fingerprint: testDigest("fingerprint"), ChainIdentity: testDigest("chain"), IssuerIdentity: testDigest("issuer"), BindingIdentity: request.BindingDigest, LastTrustedWall: now, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), CertificatePath: "/var/lib/lanpanel/certificates/headscale/certificate.pem", PrivateKeyPath: "/var/lib/lanpanel/certificates/headscale/private-key.pem"}
	copy := value
	copy.DirectoryIdentity = ""
	raw, _ := json.Marshal(copy)
	value.DirectoryIdentity = testDigest(string(raw))
	return value
}
