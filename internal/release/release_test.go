package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"lanpanel/internal/dependencies"
	"strings"
	"testing"
	"time"
)

func TestLiveCleanupMustCoverImmutablePlanExactly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	plan := LiveSideEffectPlan{SchemaVersion: LiveSideEffectPlanSchemaVersion, RunID: "run-one", AuthorizedHostFingerprint: "host-one", CreatedAt: now, Mutations: []PlannedMutation{{ID: "delete", ScopeDigest: digest("scope"), PriorStateDigest: digest("prior"), PlannedMutationDigest: digest("mutation"), SelectorDigest: digest("selector"), CleanupPolicy: "delete_exact"}, {ID: "retained", ScopeDigest: digest("scope-2"), PriorStateDigest: digest("prior-2"), PlannedMutationDigest: digest("mutation-2"), SelectorDigest: digest("selector-2"), CleanupPolicy: "retain_authorized"}}}
	planBytes, err := MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest("install-manifest")
	report := LiveCleanupReport{SchemaVersion: LiveCleanupReportSchemaVersion, RunID: plan.RunID, SideEffectPlanDigest: DigestBytes(planBytes), QualificationInstallManifestDigest: manifestDigest, ProtectedInputDigest: DigestBytes([]byte("input")), JourneySucceeded: true, UpdatedAt: now.Add(time.Second), Items: []CleanupItem{{MutationID: "delete", ObservedIdentity: "dns/example", Result: CleanupCleaned}, {MutationID: "retained", ObservedIdentity: "host/package", Result: CleanupRetained}}}
	reportBytes, err := MarshalCanonical(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLiveCleanup(planBytes, reportBytes, manifestDigest, DigestBytes([]byte("input"))); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLiveCleanup(planBytes, reportBytes, manifestDigest, DigestBytes([]byte("changed-input"))); err == nil {
		t.Fatal("cleanup report accepted different protected input")
	}
	report.JourneySucceeded = false
	reportBytes, _ = MarshalCanonical(report)
	if _, err := VerifyLiveCleanup(planBytes, reportBytes, manifestDigest, DigestBytes([]byte("input"))); err == nil {
		t.Fatal("cleanup-only report was accepted as successful journey")
	}
	report.JourneySucceeded = true
	report.Items[0].Result = CleanupRetained
	reportBytes, _ = MarshalCanonical(report)
	if _, err := VerifyLiveCleanup(planBytes, reportBytes, manifestDigest, DigestBytes([]byte("input"))); err == nil {
		t.Fatal("delete_exact residue was accepted")
	}
}

func TestSingleReleaseManifestVerifiesExactAssetsAndSecurityGate(t *testing.T) {
	manifest, manifestBytes, checksums, assets := releaseFixture(t, ResolutionNotAffected)
	verified, err := VerifyRelease(DigestBytes(manifestBytes), manifestBytes, checksums, assets)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest().Binary != manifest.Binary || verified.Digest() != DigestBytes(manifestBytes) {
		t.Fatal("verified release view changed identity")
	}
	if err := AuthorizePublication(verified); err != nil {
		t.Fatal(err)
	}
	tampered := cloneBytesMap(assets)
	tampered[manifest.Binary.Path] = []byte("tampered")
	if _, err := VerifyRelease(DigestBytes(manifestBytes), manifestBytes, checksums, tampered); err == nil {
		t.Fatal("tampered binary passed release verification")
	}
	if _, err := VerifyRelease(digest("wrong-root"), manifestBytes, checksums, assets); err == nil {
		t.Fatal("wrong selected release.json digest was accepted")
	}
}

func TestReleaseSchemaHasNoDualEnvelopeEdgeOneOrEvidenceGraph(t *testing.T) {
	_, manifestBytes, _, _ := releaseFixture(t, ResolutionNotAffected)
	for _, field := range []string{`"kind":"qualification_candidate"`, `"edgeone":{}`, `"qualification_candidate_digest":"` + digest("candidate") + `"`, `"checklist_digest":"` + digest("checklist") + `"`, `"envelope_digest":"` + digest("envelope") + `"`} {
		hostile := append([]byte(nil), manifestBytes[:len(manifestBytes)-1]...)
		hostile = append(hostile, []byte(","+field+"}")...)
		if _, err := DecodeReleaseManifest(hostile); err == nil {
			t.Fatalf("removed release field accepted: %s", field)
		}
	}
}

func TestResumeInstallAuthorityChangesOnlyObservationTime(t *testing.T) {
	manifest, manifestBytes, checksums, assets := releaseFixture(t, ResolutionNotAffected)
	verified, err := VerifyPublicInstallAuthority(DigestBytes(manifestBytes), manifestBytes, checksums, assets, PublicInstallObservation{HostFingerprint: "host/fingerprint", ObservedAt: time.Unix(1_700_000_100, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	persisted := verified.Identity()
	persisted.AuthorityCreatedAt = persisted.AuthorityCreatedAt.Add(-time.Second)
	if _, err := BindResumeInstallAuthority(verified, persisted); err != nil {
		t.Fatal(err)
	}
	persisted.Binary.Digest = digest("changed")
	if _, err := BindResumeInstallAuthority(verified, persisted); err == nil {
		t.Fatal("changed immutable resume authority was accepted")
	}
	_ = manifest
}

func TestQualificationInstallBindsCandidateTargetHostAndImmutablePlan(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	profile := testProfile()
	target := QualificationTargetProfile{SchemaVersion: QualificationTargetProfileSchemaVersion, Profile: profile, CapturedAt: now}
	targetBytes, _ := MarshalCanonical(target)
	profileDigest, _ := ProfileDigest(profile)
	plan := LiveSideEffectPlan{SchemaVersion: LiveSideEffectPlanSchemaVersion, RunID: "run-one", AuthorizedHostFingerprint: "host-one", CreatedAt: now, Mutations: []PlannedMutation{{ID: "clean_install", ScopeDigest: digest("scope"), PriorStateDigest: digest("prior"), PlannedMutationDigest: digest("mutation"), SelectorDigest: digest("selector"), CleanupPolicy: "retain_authorized"}}}
	planBytes, _ := MarshalCanonical(plan)
	dependencyBytes, _, dependencyAssets, baseline := dependencyAuthorityFixture(t, profile)
	dependencyAssets["dependency-baseline.json"] = baseline
	binary := []byte("candidate-binary")
	manifest := QualificationInstallManifest{SchemaVersion: QualificationInstallManifestSchemaVersion, RunID: plan.RunID, ReleaseTag: "v1.0.0", CandidateBinary: identity("lanpanel", binary), SourceTreeDigest: digest("source"), DependencyManifestDigest: DigestBytes(dependencyBytes), TargetProfileDigest: profileDigest, AuthorizedHostFingerprint: plan.AuthorizedHostFingerprint, SideEffectPlanDigest: DigestBytes(planBytes), ProtectedAuthorityDigest: digest("protected-authority"), ACMEAccountContact: "admin@example.test", CreatedAt: now.Add(time.Second)}
	manifestBytes, _ := MarshalCanonical(manifest)
	authority, err := VerifyQualificationInstallAuthority(DigestBytes(manifestBytes), manifestBytes, targetBytes, planBytes, dependencyBytes, binary, dependencyAssets, QualificationInstallObservation{HostFingerprint: "host-one", ObservedAt: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	installed := authority.Identity()
	if installed.Kind != InstallQualification || installed.ReleaseManifestDigest != "" || installed.QualificationInstallManifestDigest != DigestBytes(manifestBytes) || installed.SideEffectPlanDigest != DigestBytes(planBytes) {
		t.Fatalf("qualification install identity=%#v", installed)
	}
	wrongPlan := plan
	wrongPlan.Mutations = append([]PlannedMutation(nil), plan.Mutations...)
	wrongPlan.Mutations[0].SelectorDigest = digest("other-selector")
	wrongPlanBytes, _ := MarshalCanonical(wrongPlan)
	if _, err := VerifyQualificationInstallAuthority(DigestBytes(manifestBytes), manifestBytes, targetBytes, wrongPlanBytes, dependencyBytes, binary, dependencyAssets, QualificationInstallObservation{HostFingerprint: "host-one", ObservedAt: now.Add(2 * time.Second)}); err == nil {
		t.Fatal("changed live side-effect plan passed bound qualification install")
	}
	if _, err := VerifyQualificationInstallAuthority(DigestBytes(manifestBytes), manifestBytes, targetBytes, planBytes, dependencyBytes, binary, dependencyAssets, QualificationInstallObservation{HostFingerprint: "other-host", ObservedAt: now.Add(2 * time.Second)}); err == nil {
		t.Fatal("unauthorized host passed qualification install")
	}
}

func TestOSProfileDigestBindsRepositorySnapshotClosureAndTuple(t *testing.T) {
	profile := testProfile()
	before, err := ProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.RepositoryMetadataDigest = digest("changed-metadata")
	after, err := ProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("repository metadata drift preserved profile identity")
	}
	profile = testProfile()
	profile.Packages[0].Version = "1.26.1"
	after, err = ProfileDigest(profile)
	if err != nil || before == after {
		t.Fatal("package tuple drift did not change profile identity")
	}
}

func TestSecurityGateRejectsUnresolvedMaterialFinding(t *testing.T) {
	_, manifestBytes, checksums, assets := releaseFixture(t, ResolutionUnresolved)
	verified, err := VerifyRelease(DigestBytes(manifestBytes), manifestBytes, checksums, assets)
	if err != nil {
		t.Fatal(err)
	}
	if err := AuthorizePublication(verified); err == nil {
		t.Fatal("unresolved high finding did not block publication")
	}
}

func releaseFixture(t *testing.T, resolution FindingResolution) (ReleaseManifest, []byte, []byte, map[string][]byte) {
	t.Helper()
	profile := testProfile()
	binary := []byte("binary")
	dependencyBytes, dependency, dependencyAssets, baseline := dependencyAuthorityFixture(t, profile)
	sourceArchive := sourceArchiveFixture(t)
	sourceTreeDigest, sourceErr := SourceArchiveTreeDigest(sourceArchive)
	if sourceErr != nil {
		t.Fatal(sourceErr)
	}
	profileDigest, _ := ProfileDigest(profile)
	providers := []ProviderLiveTest{{Provider: "cloudflare", Status: "live_tested"}, {Provider: "digitalocean", Status: "not_live_tested"}, {Provider: "gcloud", Status: "not_live_tested"}, {Provider: "route53", Status: "not_live_tested"}, {Provider: "tencentcloud", Status: "not_live_tested"}}
	sbomBytes, sbomErr := MarshalCanonical(SPDXDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "lanpanel-test", DocumentNamespace: "https://lanpanel.invalid/spdx/test", CreationInfo: SPDXCreation{Created: time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339), Creators: []string{"Tool: test"}}, Packages: []SPDXPackage{{Name: "lanpanel", SPDXID: "SPDXRef-Package-lanpanel", VersionInfo: "v1.0.0", DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Checksums: []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: DigestBytes(binary)}}}}, Relationships: []SPDXRelationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package-lanpanel"}}})
	if sbomErr != nil {
		t.Fatal(sbomErr)
	}
	summaryBytes, summaryErr := MarshalCanonical(QualificationSummary{SchemaVersion: QualificationSummarySchemaVersion, RunID: "run-one", CandidateDigest: DigestBytes(binary), SourceTreeDigest: sourceTreeDigest, TargetProfileDigest: profileDigest, InstallManifestDigest: digest("install"), SideEffectPlanDigest: digest("plan"), ProtectedInputDigest: digest("input"), CleanupReportDigest: digest("cleanup"), JourneySucceeded: true, ProviderLiveTests: providers, CompletedAt: time.Unix(1_700_000_000, 0).UTC()})
	if summaryErr != nil {
		t.Fatal(summaryErr)
	}
	assets := map[string][]byte{
		"lanpanel":                   binary,
		"lanpanel-v1.0.0.tar.gz":     sourceArchive,
		"LICENSE":                    []byte("license"),
		"NOTICE":                     []byte("notice"),
		"lanpanel.spdx.json":         sbomBytes,
		"dependency-manifest.json":   dependencyBytes,
		"dependency-baseline.json":   baseline,
		"headscale.tar.gz":           dependencyAssets["headscale.tar.gz"],
		"headscale":                  dependencyAssets["headscale"],
		"lego.tar.gz":                dependencyAssets["lego.tar.gz"],
		"lego":                       dependencyAssets["lego"],
		"tailscale.tar.gz":           dependencyAssets["tailscale.tar.gz"],
		"tailscale":                  dependencyAssets["tailscale"],
		"qualification-summary.json": summaryBytes,
		"known-limitations.md":       []byte("limitations"),
	}
	reportBytes, err := MarshalCanonical(testSecurityReport(DigestBytes(binary), resolution))
	if err != nil {
		t.Fatal(err)
	}
	assets["security-report.json"] = reportBytes
	manifest := ReleaseManifest{
		SchemaVersion: ReleaseManifestSchemaVersion, ReleaseTag: "v1.0.0", Binary: identity("lanpanel", binary), SourceArchive: identity("lanpanel-v1.0.0.tar.gz", assets["lanpanel-v1.0.0.tar.gz"]),
		License: identity("LICENSE", assets["LICENSE"]), Notice: identity("NOTICE", assets["NOTICE"]), SBOM: identity("lanpanel.spdx.json", assets["lanpanel.spdx.json"]), DependencyManifest: identity("dependency-manifest.json", dependencyBytes), Headscale: dependency.Headscale,
		SecurityReport: identity("security-report.json", reportBytes), QualificationSummary: identity("qualification-summary.json", assets["qualification-summary.json"]), KnownLimitations: identity("known-limitations.md", assets["known-limitations.md"]),
		AdditionalAssets: []AssetIdentity{identity("dependency-baseline.json", baseline), identity("lego.tar.gz", assets["lego.tar.gz"]), identity("lego", assets["lego"]), identity("tailscale.tar.gz", assets["tailscale.tar.gz"]), identity("tailscale", assets["tailscale"])}, SourceTreeDigest: sourceTreeDigest,
		SupportedProfiles: []SupportedOSProfile{{Profile: profile, QualifiedBinaryDigest: DigestBytes(binary), QualificationRunID: "run-one", QualificationSummaryDigest: DigestBytes(assets["qualification-summary.json"])}},
		ProviderLiveTests: providers,
	}
	checksums := checksumsFor(t, assets)
	manifest.Checksums = identity("SHA256SUMS", checksums)
	manifestBytes, err := MarshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, manifestBytes, checksums, assets
}

func dependencyAuthorityFixture(t *testing.T, profile OSProfile) ([]byte, QualificationDependencyAuthority, map[string][]byte, []byte) {
	t.Helper()
	headscaleExecutable := []byte("headscale-executable")
	headscaleArchive := tarGzipFixture(t, map[string][]byte{"headscale": headscaleExecutable})
	legoExecutable := []byte("lego-executable")
	legoArchive := tarGzipFixture(t, map[string][]byte{"lego": legoExecutable})
	tailscaleExecutable := []byte("tailscale-executable")
	tailscaleArchive := tarGzipFixture(t, map[string][]byte{"tailscale": tailscaleExecutable})
	baseline := validDependencyBaseline(t, profile, DigestBytes(headscaleArchive), DigestBytes(legoArchive), DigestBytes(tailscaleArchive))
	headscale := HeadscaleArtifactAuthority{Version: "0.29.0", ArtifactIdentity: "https://downloads.example.test/headscale-0.29.0", Archive: identity("headscale.tar.gz", headscaleArchive), ArchiveFormat: "tar_gzip", MaximumExtractedBytes: 1 << 20, RedirectAuthorities: []string{"downloads.example.test"}, Members: []ArchiveMemberAuthority{{Path: "headscale", Asset: identity("headscale", headscaleExecutable), Destination: "/usr/lib/lanpanel/dependencies/headscale", Mode: 0o755}}, ExecutableAsset: "headscale", InstallPath: "/usr/lib/lanpanel/dependencies/headscale", ConfigContract: SupportedHeadscaleConfigContract, ConfigContractDigest: SupportedHeadscaleConfigContractDigest()}
	lego := identity("lego", legoExecutable)
	tailscale := identity("tailscale", tailscaleExecutable)
	authority := QualificationDependencyAuthority{SchemaVersion: QualificationDependencyAuthoritySchemaVersion, DependencyBaseline: identity("dependency-baseline.json", baseline), Headscale: headscale, LegoVersion: "4.25.2", LegoArtifactIdentity: "https://github.com/go-acme/lego/releases/download/v4.25.2/lego_v4.25.2_linux_amd64.tar.gz", LegoArchive: identity("lego.tar.gz", legoArchive), LegoMembers: []ArchiveMemberAuthority{{Path: "lego", Asset: lego, Destination: "/usr/lib/lanpanel/dependencies/lego", Mode: 0o755}}, Lego: lego, Tailscale: ClientArtifactAuthority{Version: "1.82.0", ArtifactIdentity: "https://downloads.example.test/tailscale-1.82.0", Archive: identity("tailscale.tar.gz", tailscaleArchive), ArchiveFormat: "tar_gzip", MaximumExtractedBytes: 1 << 20, RedirectAuthorities: []string{"downloads.example.test"}, Members: []ArchiveMemberAuthority{{Path: "tailscale", Asset: tailscale, Destination: "/usr/lib/lanpanel/dependencies/tailscale", Mode: 0o755}}, ExecutableAsset: "tailscale", InstallPath: "/usr/lib/lanpanel/dependencies/tailscale"}}
	encoded, err := MarshalCanonical(authority)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, authority, map[string][]byte{"headscale.tar.gz": headscaleArchive, "headscale": headscaleExecutable, "lego.tar.gz": legoArchive, "lego": legoExecutable, "tailscale.tar.gz": tailscaleArchive, "tailscale": tailscaleExecutable}, baseline
}

func testProfile() OSProfile {
	return OSProfile{ID: "debian-13-amd64", Family: "debian", Release: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0-1", PackageSnapshotDigest: digest("packages"), RepositorySource: "https://deb.example.test/debian", RepositoryKeyFingerprint: digest("repo-key"), RepositoryMetadataDigest: digest("repo-metadata"), RepositoryCutoffDigest: digest("repo-cutoff"), PackageClosureDigest: digest("closure"), Packages: []PackageTuple{{Name: "apache2-utils", Version: "2.4.62-1", Architecture: "amd64"}, {Name: "goaccess", Version: "1.9.3-1", Architecture: "amd64"}, {Name: "nginx", Version: "1.26.0-1", Architecture: "amd64"}}, ManagedConfinement: ConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8", "169.254.169.254/32", "::1/128"}, QualificationDigest: digest("confinement")}}
}

func validDependencyBaseline(t *testing.T, profile OSProfile, headscaleDigest, legoDigest, tailscaleDigest string) []byte {
	t.Helper()
	cutoff := time.Unix(1_700_000_000, 0).UTC()
	published := cutoff.Add(-time.Hour)
	profileDigest, _ := ProfileDigest(profile)
	selection := func(component string, kind dependencies.SourceKind, version, artifact string) dependencies.Selection {
		value := dependencies.Selection{Component: component, SourceKind: kind, SelectedVersion: version, LatestStableVersion: version, LatestStablePublishedAt: published, MetadataSource: "https://metadata.example.test/releases", MetadataSnapshotDigest: digest("metadata-" + component), ArtifactIdentity: artifact, ArtifactDigest: digest("artifact-" + component)}
		if kind == dependencies.SourceDistroRepository {
			value.OSProfileDigest = profileDigest
		} else {
			value.OperatingSystem, value.Architecture = "linux", "amd64"
			if component == "headscale" {
				value.ArtifactDigest = headscaleDigest
			}
			if component == "lego" {
				value.ArtifactDigest = legoDigest
			}
			if component == "tailscale-client" {
				value.ArtifactDigest = tailscaleDigest
			}
		}
		return value
	}
	baseline := dependencies.Baseline{SchemaVersion: dependencies.SchemaVersion, Cutoff: cutoff, Selections: []dependencies.Selection{
		selection("apache2-utils", dependencies.SourceDistroRepository, "2.4.62-1", "apache2-utils=2.4.62-1@debian/trixie"),
		selection("goaccess", dependencies.SourceDistroRepository, "1.9.3-1", "goaccess=1.9.3-1@debian/trixie"),
		selection("headscale", dependencies.SourceCanonicalArtifact, "0.29.0", "https://downloads.example.test/headscale-0.29.0"),
		selection("lego", dependencies.SourceCanonicalArtifact, "4.25.2", "https://github.com/go-acme/lego/releases/download/v4.25.2/lego_v4.25.2_linux_amd64.tar.gz"),
		selection("nginx", dependencies.SourceDistroRepository, "1.26.0-1", "nginx=1.26.0-1@debian/trixie"),
		selection("tailscale-client", dependencies.SourceCanonicalArtifact, "1.82.0", "https://downloads.example.test/tailscale-1.82.0"),
	}}
	encoded, err := dependencies.EncodeBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func sourceArchiveFixture(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "lanpanel-v1.0.0/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	data := []byte("package main\n")
	if err := tw.WriteHeader(&tar.Header{Name: "lanpanel-v1.0.0/main.go", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func tarGzipFixture(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	gzipWriter.ModTime = time.Unix(0, 0).UTC()
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range []string{"headscale", "lego", "tailscale"} {
		data, present := members[name]
		if !present {
			continue
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func testSecurityReport(candidate string, resolution FindingResolution) SecurityReport {
	finding := SecurityFinding{ID: "GO-TEST-1", Component: "module-one", Severity: SeverityHigh, InShippedClosure: true, RuntimeReachable: true, Resolution: resolution}
	if resolution != ResolutionUnresolved {
		finding.EvidenceDigest = digest("resolution")
	}
	return SecurityReport{SchemaVersion: SecurityReportSchemaVersion, CandidateDigest: candidate, ScannedAt: time.Unix(1_700_000_000, 0).UTC(), Scanners: []ScannerIdentity{{Kind: "distro_security", Name: "debian-security-tracker", Version: "2026.08", DatabaseDigest: digest("distro-db"), Coverage: "runtime_os_packages"}, {Kind: "go_vulnerability", Name: "govulncheck", Version: "1.1.4", DatabaseDigest: digest("go-db"), Coverage: "go_binary"}, {Kind: "sbom_osv", Name: "osv-scanner", Version: "2.0.3", DatabaseDigest: digest("osv-db"), Coverage: "sbom"}}, Findings: []SecurityFinding{finding}}
}

func checksumsFor(t *testing.T, assets map[string][]byte) []byte {
	t.Helper()
	entries := make([]ChecksumEntry, 0, len(assets))
	for path, data := range assets {
		entries = append(entries, ChecksumEntry{Path: path, Digest: DigestBytes(data)})
	}
	encoded, err := EncodeChecksums(entries)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func identity(path string, data []byte) AssetIdentity {
	return AssetIdentity{Path: path, Digest: DigestBytes(data), Bytes: uint64(len(data))}
}

func digest(seed string) string {
	return strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}

func cloneBytesMap(source map[string][]byte) map[string][]byte {
	copy := make(map[string][]byte, len(source))
	for path, data := range source {
		copy[path] = append([]byte(nil), data...)
	}
	return copy
}
