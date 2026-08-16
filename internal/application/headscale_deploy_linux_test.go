//go:build linux

package application

import (
	"crypto/sha256"
	"encoding/hex"
	"lanpanel/internal/acme"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"strings"
	"testing"
	"time"
)

func TestHeadscaleDeployPlanBindsFirstCertificateAndPublicScope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	installation := headscaleDeployInstallation()
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/var/lib/lanpanel/credentials/acme-account.key", AccountKeyFingerprint: deployTestDigest("account"), Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}, AccountEmail: "admin@example.test", TermsAccepted: true}
	request, result := headscaleDeployPreflight(t, now)
	authority, err := buildHeadscaleDeployAuthority(installation, binding, "cert_00000000000000000000000000000001", "ui/session/generation/1", request, result, safety.EmptyState(), now)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Spec.Operation != string(domain.OperationDeploy) || authority.Spec.Target.Kind != plans.TargetHeadscale || authority.Spec.Target.ID != installation.Headscale.ID || !authority.Spec.Config.Applicable || authority.Spec.Config.Digest != authority.Rendered.Candidate.ConfigDigest || authority.Spec.Applied.Applicable {
		t.Fatalf("Headscale Plan spec=%+v", authority.Spec)
	}
	if !strings.Contains(authority.Spec.ExposureSummary, "80/tcp,443/tcp,3478/udp") || strings.Contains(authority.Spec.ExposureSummary, binding.AccountKeyPath) || !strings.Contains(authority.Spec.Prerequisites, "first real control certificate") {
		t.Fatal("Headscale Plan exposure or redaction contract changed")
	}
	kinds := map[string]bool{}
	for _, evidence := range authority.Spec.Evidence {
		kinds[evidence.Kind] = true
	}
	if !kinds[preflight.ExpansionEvidencePrefix+string(preflight.ExpansionHeadscale)] || !kinds["acme_binding"] || !kinds["headscale_control_candidate"] || !kinds["headscale_safety"] {
		t.Fatalf("Plan evidence=%+v", authority.Spec.Evidence)
	}
	if authority.Rendered.Candidate.PublicSTUN {
		t.Fatal("Plan candidate exposed STUN before activation")
	}
	plan := plans.Plan{Operation: authority.Spec.Operation, Target: authority.Spec.Target, ActorIdentity: authority.Spec.ActorIdentity, Config: authority.Spec.Config, Applied: authority.Spec.Applied, Evidence: authority.Spec.Evidence}
	volatileResult := result
	volatileResult.ObservedAt = result.ObservedAt.Add(time.Second)
	volatileResult.ValidUntil = result.ValidUntil.Add(time.Second)
	volatileResult.Findings = append([]preflight.Finding(nil), result.Findings...)
	for index := range volatileResult.Findings {
		if volatileResult.Findings[index].Code == "trusted_clock" {
			volatileResult.Findings[index].Identity = "kernel/" + volatileResult.ObservedAt.Format(time.RFC3339Nano)
		}
		if volatileResult.Findings[index].Code == "disk" {
			volatileResult.Findings[index].Identity += "/changed-free-bytes"
		}
	}
	volatileAuthority, err := buildHeadscaleDeployAuthority(installation, binding, "cert_00000000000000000000000000000001", "ui/session/generation/1", request, volatileResult, safety.EmptyState(), volatileResult.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !headscaleDeployPlanMatches(plan, volatileAuthority) {
		t.Fatal("fresh clock/capacity reevaluation invalidated semantic Plan")
	}
	changedResult := result
	changedResult.Findings = append([]preflight.Finding(nil), result.Findings...)
	changedResult.Findings[0].Identity = deployTestDigest("changed-observation")
	changedAuthority, err := buildHeadscaleDeployAuthority(installation, binding, "cert_00000000000000000000000000000001", "ui/session/generation/1", request, changedResult, safety.EmptyState(), now)
	if err != nil {
		t.Fatal(err)
	}
	if headscaleDeployPlanMatches(plan, changedAuthority) {
		t.Fatal("changed preflight observation retained Plan identity")
	}
	changedSafety := safety.EmptyState()
	changedSafety.Headscale.GenerationSequence = 1
	if _, err := buildHeadscaleDeployAuthority(installation, binding, "cert_00000000000000000000000000000001", "ui/session/generation/1", request, result, changedSafety, now); err == nil {
		t.Fatal("changed Headscale safety generation accepted for first deploy")
	}
	wrong := result
	wrong.Target = "other"
	if _, err := buildHeadscaleDeployAuthority(installation, binding, "cert_00000000000000000000000000000001", "ui/session/generation/1", request, wrong, safety.EmptyState(), now); err == nil {
		t.Fatal("target-mismatched preflight accepted")
	}
}

func headscaleDeployInstallation() domain.Installation {
	headscale := &domain.HeadscaleDomain{ID: "hds_00000000000000000000000000000001", ControlDomain: "control.example.test", MagicDNSNamespace: "mesh.example.test", Policy: "trusted_mesh", Artifact: domain.HeadscaleArtifactIdentity{BaselineDigest: deployTestDigest("baseline"), Version: "0.25.1", ArchiveDigest: deployTestDigest("archive"), ExecutableDigest: deployTestDigest("executable"), ConfigContract: control.ConfigContract, ConfigContractDigest: deployTestDigest("contract")}, Database: domain.HeadscaleDatabaseIdentity{UUID: "hdb_00000000000000000000000000000001", SQLitePath: control.FixedPaths().Database, IdentityBundleDigest: deployTestDigest("identity"), Generation: 1, Phase: domain.HeadscaleIdentityCommitted}, DesiredDigest: deployTestDigest("desired"), ManagedPaths: domain.HeadscaleManagedPaths()}
	return domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.23.45.67", Port: 23456}, Headscale: headscale}
}

func headscaleDeployPreflight(t *testing.T, now time.Time) (preflight.ExpansionRequest, preflight.Result) {
	t.Helper()
	profile := preflight.ExpectedProfile{ID: "debian", VersionID: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: deployTestDigest("packages"), ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8"}, QualificationDigest: deployTestDigest("confinement")}, Authority: preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: deployTestDigest("profile"), LiveQualified: true}}
	request := preflight.ExpansionRequest{Scope: preflight.ExpansionHeadscale, Target: "headscale", Generation: 1, Profile: profile, Domains: []string{"control.example.test"}, Disks: []preflight.DiskRequirement{{Path: "/var/lib/lanpanel", MinimumAvailableBytes: 1}}, LastTrustedWall: now.Add(-time.Second)}
	result, err := preflight.EvaluateExpansion(request, preflight.ExpansionObservations{OperatingSystem: "linux", Architecture: "amd64", Platform: preflight.PlatformInfo{ID: "debian", VersionID: "13"}, Clock: preflight.ClockObservation{Now: now, Synchronized: true, Source: "kernel"}, ExecutorUID: 0, Systemd: preflight.ComponentObservation{Available: true, Identity: "systemd/1"}, APT: preflight.ComponentObservation{Available: true, Identity: "apt/1"}, DPKG: preflight.ComponentObservation{Available: true, Identity: "dpkg/1"}, Packages: preflight.PackageObservation{Ready: true, Identity: deployTestDigest("observation"), SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: deployTestDigest("packages")}, DNS: []preflight.DNSObservation{{Domain: "control.example.test", Addresses: []string{"8.8.8.8"}}}, ListenerInventoryComplete: true, Disks: []preflight.DiskObservation{{Path: "/var/lib/lanpanel", Device: 1, AvailableBytes: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return request, result
}
func deployTestDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
