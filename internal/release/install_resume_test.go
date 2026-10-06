package release

import (
	"encoding/json"
	"lanpanel/internal/packages"
	"strings"
	"testing"
	"time"
)

func TestBindResumeInstallAuthorityNormalizesPersistedEmptySlices(t *testing.T) {
	identity := resumeIdentityFixture(t)
	identity.Profile.Repositories = make([]packages.Repository, 0)
	identity.ProfileDigest, _ = ProfileDigest(identity.Profile)
	verifiedIdentity := identity
	verifiedIdentity.AuthorityCreatedAt = identity.AuthorityCreatedAt.Add(time.Minute)
	verified, err := RehydrateInstallAuthority(verifiedIdentity)
	if err != nil {
		t.Fatal(err)
	}

	persistedBytes, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var persisted InstallIdentity
	if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Profile.Repositories == nil {
		t.Fatal("JSON resume fixture did not preserve its empty repository slice")
	}
	bound, err := BindResumeInstallAuthority(verified, persisted)
	if err != nil {
		t.Fatalf("same authority changed only by cross-version slice normalization: %v", err)
	}
	if bound.Identity().AuthorityCreatedAt != persisted.AuthorityCreatedAt {
		t.Fatal("resume binding did not retain the persisted authority timestamp")
	}
}

func TestBindResumeInstallAuthorityRejectsChangedImmutableIdentity(t *testing.T) {
	identity := resumeIdentityFixture(t)
	verified, err := RehydrateInstallAuthority(identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.Binary.Digest = strings.Repeat("f", 64)
	if _, err := BindResumeInstallAuthority(verified, identity); err == nil || !strings.Contains(err.Error(), "differs from verified immutable input") {
		t.Fatalf("changed binary authority was accepted: %v", err)
	}
}

func resumeIdentityFixture(t *testing.T) InstallIdentity {
	t.Helper()
	digest := func(value byte) string { return strings.Repeat(string(value), 64) }
	profile := OSProfile{
		ID: "linux-amd64-apt-dpkg-systemd", Architecture: "amd64", ServiceManager: "systemd", PackageManager: "apt-dpkg",
		Nginx:              NginxCapabilityContract{Package: "nginx", MinimumVersion: "1.18.0", Service: "nginx.service"},
		Confinement:        ConfinementCapabilityContract{UnifiedCgroupV2: true, CgroupKill: true, SystemdDelegate: true},
		Packages:           []PackageTuple{{Name: "nginx", Version: "1.24.0", VersionMinimum: "1.18.0", Architecture: "amd64"}},
		ManagedConfinement: ConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.1.0", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_baseline_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8"}, PolicyDigest: digest('1')},
	}
	profileDigest, err := ProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	headscale := HeadscaleArtifactAuthority{
		Version: "0.29.0", ArtifactIdentity: "https://downloads.example.test/headscale-0.29.0", Archive: AssetIdentity{Path: "headscale.tar.gz", Digest: digest('2'), Bytes: 1}, ArchiveFormat: "tar_gzip", MaximumExtractedBytes: 1 << 20,
		RedirectAuthorities: []string{"downloads.example.test"}, Members: []ArchiveMemberAuthority{{Path: "headscale", Asset: AssetIdentity{Path: "headscale", Digest: digest('3'), Bytes: 1}, Destination: "/usr/lib/lanpanel/dependencies/headscale", Mode: 0o755}}, ExecutableAsset: "headscale", InstallPath: "/usr/lib/lanpanel/dependencies/headscale", ConfigContract: SupportedHeadscaleConfigContract, ConfigContractDigest: SupportedHeadscaleConfigContractDigest(),
	}
	identity := InstallIdentity{
		Kind: InstallPublicRelease, ReleaseTag: "v1.0.0", ReleaseManifestDigest: digest('4'),
		Binary: AssetIdentity{Path: "lanpanel", Digest: digest('5'), Bytes: 1}, Profile: profile, ProfileDigest: profileDigest, HostFingerprint: "host-resume", AuthorityCreatedAt: time.Unix(1_700_000_000, 0).UTC(),
		DependencyBaseline: AssetIdentity{Path: "dependency-baseline.json", Digest: digest('6'), Bytes: 1}, DependencyManifestDigest: digest('7'), Headscale: headscale,
		Lego: AssetIdentity{Path: "lego", Digest: digest('8'), Bytes: 1}, Tailscale: AssetIdentity{Path: "tailscale", Digest: digest('9'), Bytes: 1}, TailscaleVersion: "1.82.0", GoAccess: AssetIdentity{Path: "goaccess", Digest: digest('a'), Bytes: 1}, GoAccessVersion: "1.12",
	}
	if err := ValidateInstallIdentity(identity); err != nil {
		t.Fatal(err)
	}
	return identity
}
