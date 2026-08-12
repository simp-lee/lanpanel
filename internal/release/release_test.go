package release

import (
	"bytes"
	"lanpanel/internal/dependencies"
	"strings"
	"testing"
	"time"
)

func TestCanonicalReleaseJSONRejectsDuplicateUnknownAndNoncanonicalBytes(t *testing.T) {
	type document struct {
		Schema string `json:"schema"`
		Value  uint64 `json:"value"`
	}
	canonical := []byte(`{"schema":"one","value":2}`)
	var decoded document
	if err := DecodeCanonical(canonical, &decoded); err != nil || decoded.Value != 2 {
		t.Fatalf("canonical decode=%#v,%v", decoded, err)
	}
	for _, hostile := range [][]byte{
		[]byte(`{"schema":"one","schema":"two","value":2}`),
		[]byte(`{"schema":"one","value":2,"signature":"forbidden"}`),
		[]byte("{\n\"schema\":\"one\",\"value\":2}"),
		append(append([]byte(nil), canonical...), ' '),
	} {
		if err := DecodeCanonical(hostile, &document{}); err == nil {
			t.Fatalf("hostile canonical JSON accepted: %q", hostile)
		}
	}
}

func TestChecksumInventoryIsCanonicalExactAndBoundToBytes(t *testing.T) {
	assets := map[string][]byte{"LICENSE": []byte("license"), "lanpanel-linux-amd64": []byte("binary")}
	encoded, err := EncodeChecksums([]ChecksumEntry{{Path: "lanpanel-linux-amd64", Digest: DigestBytes(assets["lanpanel-linux-amd64"])}, {Path: "LICENSE", Digest: DigestBytes(assets["LICENSE"])}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(encoded, []byte("\n")) || !bytes.HasPrefix(encoded, []byte(DigestBytes(assets["LICENSE"])+"  LICENSE\n")) {
		t.Fatalf("checksum encoding is not path-sorted: %q", encoded)
	}
	set, err := ParseChecksums(encoded, []string{"LICENSE", "lanpanel-linux-amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAssetBytes(set, assets); err != nil {
		t.Fatal(err)
	}
	for name, hostile := range map[string][]byte{
		"one-space":  []byte(DigestBytes([]byte("license")) + " LICENSE\n"),
		"uppercase":  []byte(strings.ToUpper(DigestBytes([]byte("license"))) + "  LICENSE\n"),
		"dot-dot":    []byte(DigestBytes([]byte("license")) + "  ../LICENSE\n"),
		"backslash":  []byte(DigestBytes([]byte("license")) + "  dir\\asset\n"),
		"no-newline": []byte(DigestBytes([]byte("license")) + "  LICENSE"),
	} {
		if _, err := ParseChecksums(hostile, []string{"LICENSE"}); err == nil {
			t.Fatalf("%s checksum file was accepted", name)
		}
	}
	if _, err := ParseChecksums(encoded, []string{"LICENSE"}); err == nil {
		t.Fatal("unlisted checksum asset was accepted")
	}
}

func TestSourceTreeDigestRequiresCompleteTrackedInventory(t *testing.T) {
	entries := []TreeEntry{
		{Path: "cmd/tool", Type: TreeEntryRegular, Mode: TreeModeExec, Content: []byte("binary source")},
		{Path: "README.md", Type: TreeEntryRegular, Mode: TreeModeRegular, Content: []byte("readme")},
		{Path: "current", Type: TreeEntrySymlink, Mode: TreeModeSymlink, Content: []byte("cmd/tool")},
	}
	inventory, err := NewTrackedInventory([]string{"README.md", "cmd/tool", "current"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := SourceTreeDigest(inventory, entries)
	if err != nil || !ValidDigest(first) {
		t.Fatalf("source digest=%q error=%v", first, err)
	}
	entries[0], entries[2] = entries[2], entries[0]
	second, err := SourceTreeDigest(inventory, entries)
	if err != nil || second != first {
		t.Fatalf("source digest depends on caller order: %q %q", first, second)
	}
	entries[1].Content = []byte("changed")
	changed, err := SourceTreeDigest(inventory, entries)
	if err != nil || changed == first {
		t.Fatal("source content change did not change digest")
	}
	entries = entries[:2]
	if _, err := SourceTreeDigest(inventory, entries); err == nil {
		t.Fatal("omitted tracked path was accepted")
	}
	if _, err := NewTrackedInventory(nil); err == nil {
		t.Fatal("empty tracked source inventory was accepted")
	}
}

func TestVerifiedReleaseViewsCannotMutateInternalAuthority(t *testing.T) {
	candidate := buildCandidate(t)
	candidateView := candidate.Envelope()
	candidateView.QualificationTarget.NginxVersion = "9.99.0"
	candidateView.Network.ExternalPurposes[0] = "tampered"
	freshCandidate := candidate.Envelope()
	if freshCandidate.QualificationTarget.NginxVersion != testProfile().NginxVersion || freshCandidate.Network.ExternalPurposes[0] == "tampered" {
		t.Fatal("candidate accessor exposed mutable verified authority")
	}
	final := buildFinal(t, candidate, ResolutionNotAffected)
	finalView := final.Envelope()
	finalView.SupportedProfiles[0].Profile.NginxVersion = "9.99.0"
	finalView.Network.ExternalPurposes[0] = "tampered"
	freshFinal := final.Envelope()
	if freshFinal.SupportedProfiles[0].Profile.NginxVersion != testProfile().NginxVersion || freshFinal.Network.ExternalPurposes[0] == "tampered" {
		t.Fatal("final accessor exposed mutable verified authority")
	}
}

func TestCandidateInstallRequiresVerifiedBytesManifestAndObservation(t *testing.T) {
	candidate := buildCandidate(t)
	profile := candidate.envelope.value.QualificationTarget
	profileDigest, _ := ProfileDigest(*profile)
	manifest := QualificationManifest{
		SchemaVersion: QualificationManifestSchemaVersion, RunID: "run-one", AuthorizedHostFingerprint: "host-one", CaseID: "clean-install", Operation: "qualification-install",
		CandidateEnvelopeDigest: candidate.envelope.digest, BinaryDigest: candidate.envelope.value.Binary.Digest, SourceTreeDigest: candidate.envelope.value.SourceTreeDigest, TargetProfileDigest: profileDigest,
		BeforeInventoryDigest: digest("before"), CreatedAt: time.Unix(1_700_000_000, 0).UTC(), Effects: []QualificationEffect{{ID: "install", ScopeDigest: digest("scope"), PriorStateDigest: digest("prior"), PlannedMutationDigest: digest("mutation"), SelectorDigest: digest("selector"), CleanupPolicy: "retain_authorized", Phase: EffectPrepared}},
	}
	manifestBytes, _ := MarshalCanonical(manifest)
	verifiedManifest, err := DecodeQualificationManifest(manifestBytes, DigestBytes(manifestBytes))
	if err != nil {
		t.Fatal(err)
	}
	observed := QualificationObservation{RunID: manifest.RunID, HostFingerprint: manifest.AuthorizedHostFingerprint, CaseID: manifest.CaseID, Operation: manifest.Operation, ManifestDigest: DigestBytes(manifestBytes), BeforeInventoryDigest: manifest.BeforeInventoryDigest, ObservedAt: manifest.CreatedAt, Profile: *profile, Effect: manifest.Effects[0]}
	if err := AuthorizeCandidateInstall(candidate, verifiedManifest, observed); err != nil {
		t.Fatal(err)
	}
	observed.HostFingerprint = "other-host"
	if err := AuthorizeCandidateInstall(candidate, verifiedManifest, observed); err == nil {
		t.Fatal("mismatched qualification host observation was accepted")
	}
	observed.HostFingerprint = manifest.AuthorizedHostFingerprint
	observed.Effect.ScopeDigest = digest("other-scope")
	if err := AuthorizeCandidateInstall(candidate, verifiedManifest, observed); err == nil {
		t.Fatal("mismatched prepared qualification effect was accepted")
	}
	if _, err := DecodeQualificationManifest(manifestBytes, digest("other-manifest")); err == nil {
		t.Fatal("qualification manifest without its protected selected digest was accepted")
	}
	otherRun := manifest
	otherRun.RunID = "other-run"
	otherRunBytes, _ := MarshalCanonical(otherRun)
	otherRunManifest, err := DecodeQualificationManifest(otherRunBytes, DigestBytes(otherRunBytes))
	if err != nil {
		t.Fatal(err)
	}
	observed.RunID, observed.ManifestDigest = otherRun.RunID, DigestBytes(otherRunBytes)
	observed.Effect = otherRun.Effects[0]
	if err := AuthorizeCandidateInstall(candidate, otherRunManifest, observed); err == nil {
		t.Fatal("qualification manifest run differed from the candidate prebound run")
	}
}

func TestFinalInstallRequiresCompleteRootedChainAndExactObservedProfile(t *testing.T) {
	candidate := buildCandidate(t)
	final := buildFinal(t, candidate, ResolutionNotAffected)
	profile := final.envelope.value.SupportedProfiles[0].Profile
	observed := FinalInstallObservation{ReleaseTag: final.envelope.value.ReleaseTag, ManifestDigest: final.manifest.digest, EnvelopeDigest: final.envelope.digest, BinaryDigest: final.envelope.value.Binary.Digest, SourceTreeDigest: final.envelope.value.SourceTreeDigest, HostFingerprint: "host-one", ObservedAt: time.Unix(1_700_000_000, 0).UTC(), Profile: profile}
	if err := AuthorizeFinalInstall(final, observed); err != nil {
		t.Fatal(err)
	}
	observed.Profile.NginxVersion = "1.24.0-foreign"
	if err := AuthorizeFinalInstall(final, observed); err == nil || err.Error() != "os_profile_live_unqualified" {
		t.Fatalf("unqualified observed profile error=%v", err)
	}
}

func TestCandidateAndFinalVerificationRejectTamperedOrSelfConsistentReplacementBytes(t *testing.T) {
	candidateEnvelope, assets, checksums := candidateMaterial(t)
	envelopeBytes, _ := MarshalCanonical(candidateEnvelope)
	if _, err := VerifyCandidateRelease(digest("wrong-root"), envelopeBytes, checksums, assets); err == nil {
		t.Fatal("candidate with a different selected envelope digest was accepted")
	}
	assets[candidateEnvelope.Binary.Path] = []byte("tampered")
	if _, err := VerifyCandidateRelease(DigestBytes(envelopeBytes), envelopeBytes, checksums, assets); err == nil {
		t.Fatal("candidate with tampered binary bytes was accepted")
	}
	malformedEnvelope, malformedAssets, _ := candidateMaterial(t)
	malformedAssets[malformedEnvelope.DependencyBaseline.Path] = []byte("not-json")
	malformedEnvelope.DependencyBaseline = identity(malformedEnvelope.DependencyBaseline.Path, malformedAssets[malformedEnvelope.DependencyBaseline.Path])
	malformedChecksums := checksumsFor(t, malformedAssets)
	malformedEnvelope.Checksums = identity("checksums.txt", malformedChecksums)
	malformedBytes, _ := MarshalCanonical(malformedEnvelope)
	if _, err := VerifyCandidateRelease(DigestBytes(malformedBytes), malformedBytes, malformedChecksums, malformedAssets); err == nil {
		t.Fatal("self-consistent candidate with malformed Dependency Baseline was accepted")
	}

	candidate := buildCandidate(t)
	final, material := finalMaterial(t, candidate, ResolutionNotAffected)
	if _, err := VerifyFinalRelease(digest("wrong-manifest-root"), DigestBytes(material.envelopeBytes), material.manifestBytes, material.envelopeBytes, material.checksumBytes, material.assets); err == nil {
		t.Fatal("self-consistent final chain without selected manifest root was accepted")
	}
	if final == nil {
		t.Fatal("verified final fixture is nil")
	}
}

func TestFinalizationRejectsEdgeOneResultFromAnotherRun(t *testing.T) {
	candidate := buildCandidate(t)
	envelope, _, _ := finalEnvelopeMaterial(t, candidate, ResolutionNotAffected)
	envelope.EdgeOne.RunID = "other-run"
	encoded, _ := MarshalCanonical(envelope)
	verified, err := DecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFinalFromCandidate(verified, candidate.envelope); err == nil {
		t.Fatal("EdgeOne result from another run was wrapped as final")
	}
}

func TestReleaseSchemaRejectsSigningFloatingIdentityAndEdgeOneEnableMetadataOnDisabledVariant(t *testing.T) {
	envelope, _, _ := candidateMaterial(t)
	encoded, _ := MarshalCanonical(envelope)
	hostile := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"signature":"forbidden","key_id":"forbidden"}`)...)
	if _, err := DecodeEnvelope(hostile); err == nil {
		t.Fatal("signing ceremony fields entered checksum-only candidate schema")
	}
	for _, moving := range []string{"latest", "testing"} {
		envelope.QualificationTarget.NginxVersion = moving
		floatingBytes, _ := MarshalCanonical(envelope)
		if _, err := DecodeEnvelope(floatingBytes); err == nil {
			t.Fatalf("moving Nginx profile version %q entered candidate identity", moving)
		}
	}
	candidate := buildCandidate(t)
	finalEnvelope, _, _ := finalEnvelopeMaterial(t, candidate, ResolutionNotAffected)
	finalEnvelope.EdgeOne.ScopeKind = "exact_zone"
	finalEnvelope.EdgeOne.ScopeDigest = digest("forbidden-enable-scope")
	finalBytes, _ := MarshalCanonical(finalEnvelope)
	if _, err := DecodeEnvelope(finalBytes); err == nil {
		t.Fatal("disabled EdgeOne variant carried enable authority")
	}
}

func TestPublicationUsesBoundMandatoryScannerReportAndBlocksUnresolvedRisk(t *testing.T) {
	candidate := buildCandidate(t)
	blocked := buildFinal(t, candidate, ResolutionUnresolved)
	blockedFinalized, err := VerifyFinalization(blocked, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := AuthorizePublication(blockedFinalized); err == nil {
		t.Fatal("checksum-bound unresolved high vulnerability did not block publication")
	}
	allowed := buildFinal(t, candidate, ResolutionMitigation)
	allowedFinalized, err := VerifyFinalization(allowed, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := AuthorizePublication(allowedFinalized); err != nil {
		t.Fatal(err)
	}
	report := testSecurityReport(candidate.envelope.digest, ResolutionMitigation)
	report.Scanners = report.Scanners[:2]
	reportBytes, _ := MarshalCanonical(report)
	if _, err := DecodeSecurityReport(reportBytes); err == nil {
		t.Fatal("security report without distro/Go/SBOM scanner closure was accepted")
	}
	for _, moving := range []string{"stable", "nightly"} {
		report = testSecurityReport(candidate.envelope.digest, ResolutionMitigation)
		report.Scanners[1].Version = moving
		reportBytes, _ = MarshalCanonical(report)
		if _, err := DecodeSecurityReport(reportBytes); err == nil {
			t.Fatalf("moving scanner version %q was accepted", moving)
		}
	}
}

func buildCandidate(t *testing.T) *VerifiedCandidateRelease {
	t.Helper()
	envelope, assets, checksums := candidateMaterial(t)
	envelopeBytes, err := MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := VerifyCandidateRelease(DigestBytes(envelopeBytes), envelopeBytes, checksums, assets)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func candidateMaterial(t *testing.T) (Envelope, map[string][]byte, []byte) {
	t.Helper()
	assets := baseAssets()
	envelope := Envelope{
		SchemaVersion: EnvelopeSchemaVersion, Kind: EnvelopeQualificationCandidate, ReleaseTag: "v1.0.0",
		SourceTreeDigest: digest("tree"), QualificationTarget: ptr(testProfile()), SupportedProfiles: []QualifiedOSProfile{},
		EdgeOne: EdgeOneCapability{Variant: EdgeOneQualificationCandidate, Status: QualificationStatus{Preflight: "not_applicable", Gate: "passed", Live: "not_applicable"}, Reason: "qualification_pending", RunID: "run-one", ScopeKind: "exact_zone", ScopeDigest: digest("scope")},
		Network: NetworkPolicy{ExternalPurposes: []string{"acme", "dependency_download", "dns_provider", "edgeone_origin_acl", "tailnet_control"}}, AdditionalAssets: []AssetIdentity{},
	}
	setCoreAssets(&envelope, assets)
	checksums := checksumsFor(t, assets)
	envelope.Checksums = identity("checksums.txt", checksums)
	return envelope, assets, checksums
}

type finalBytes struct {
	envelopeBytes []byte
	manifestBytes []byte
	checksumBytes []byte
	assets        map[string][]byte
}

func buildFinal(t *testing.T, candidate *VerifiedCandidateRelease, resolution FindingResolution) *VerifiedFinalRelease {
	t.Helper()
	final, _ := finalMaterial(t, candidate, resolution)
	return final
}

func finalMaterial(t *testing.T, candidate *VerifiedCandidateRelease, resolution FindingResolution) (*VerifiedFinalRelease, finalBytes) {
	t.Helper()
	envelope, assets, checksums := finalEnvelopeMaterial(t, candidate, resolution)
	envelopeBytes, err := MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	assetIdentities, err := envelopeAssetInventory(envelope)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, ReleaseTag: envelope.ReleaseTag, EnvelopeDigest: DigestBytes(envelopeBytes), Checksums: envelope.Checksums, SourceTreeDigest: envelope.SourceTreeDigest, BinaryDigest: envelope.Binary.Digest, CandidateDigest: candidate.envelope.digest, Assets: assetIdentities}
	manifestBytes, err := MarshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	final, err := VerifyFinalRelease(DigestBytes(manifestBytes), DigestBytes(envelopeBytes), manifestBytes, envelopeBytes, checksums, assets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFinalization(final, candidate); err != nil {
		t.Fatal(err)
	}
	return final, finalBytes{envelopeBytes: envelopeBytes, manifestBytes: manifestBytes, checksumBytes: checksums, assets: assets}
}

func finalEnvelopeMaterial(t *testing.T, candidate *VerifiedCandidateRelease, resolution FindingResolution) (Envelope, map[string][]byte, []byte) {
	t.Helper()
	assets := baseAssets()
	reportBytes, err := MarshalCanonical(testSecurityReport(candidate.envelope.digest, resolution))
	if err != nil {
		t.Fatal(err)
	}
	assets["security-report.json"] = reportBytes
	profile := *candidate.envelope.value.QualificationTarget
	profileDigest, _ := ProfileDigest(profile)
	envelope := Envelope{
		SchemaVersion: EnvelopeSchemaVersion, Kind: EnvelopeFinal, ReleaseTag: candidate.envelope.value.ReleaseTag, SourceTreeDigest: candidate.envelope.value.SourceTreeDigest, QualificationCandidateOID: candidate.envelope.digest,
		SupportedProfiles: []QualifiedOSProfile{{Profile: profile, Status: QualificationStatus{Preflight: "eligible", Gate: "passed", Live: "live_qualified"}, CandidateDigest: candidate.envelope.digest, ChecklistDigest: DigestBytes(assets["stable-checklist.json"]), ChecklistItemID: "live-host-profile", LiveEvidenceDigest: digest("profile-evidence")}},
		EdgeOne:           EdgeOneCapability{Variant: EdgeOneDisabled, Status: QualificationStatus{Preflight: "ineligible", Gate: "deferred", Live: "live_unqualified"}, Reason: "entitlement_unavailable", RunID: "run-one", CandidateDigest: candidate.envelope.digest, ProfileDigest: profileDigest, ChecklistDigest: DigestBytes(assets["stable-checklist.json"]), CleanupChecklistItemID: "edgeone-cleanup", CleanupEvidenceDigest: digest("cleanup")},
		Network:           candidate.envelope.value.Network, AdditionalAssets: []AssetIdentity{}, SecurityReport: ptr(identity("security-report.json", reportBytes)),
	}
	setCoreAssets(&envelope, assets)
	checksums := checksumsFor(t, assets)
	envelope.Checksums = identity("checksums.txt", checksums)
	return envelope, assets, checksums
}

func baseAssets() map[string][]byte {
	return map[string][]byte{
		"LICENSE":                  []byte("license"),
		"NOTICE":                   []byte("notice"),
		"dependency-baseline.json": validDependencyBaseline(),
		"lanpanel-linux-amd64":     []byte("binary"),
		"lanpanel-v1.0.0.tar.gz":   []byte("source"),
		"lanpanel.spdx.json":       []byte("sbom"),
		"stable-checklist.json":    []byte("checklist"),
	}
}

func setCoreAssets(envelope *Envelope, assets map[string][]byte) {
	envelope.Binary = identity("lanpanel-linux-amd64", assets["lanpanel-linux-amd64"])
	envelope.SourceArchive = identity("lanpanel-v1.0.0.tar.gz", assets["lanpanel-v1.0.0.tar.gz"])
	envelope.License = identity("LICENSE", assets["LICENSE"])
	envelope.Notice = identity("NOTICE", assets["NOTICE"])
	envelope.SBOM = identity("lanpanel.spdx.json", assets["lanpanel.spdx.json"])
	envelope.DependencyBaseline = identity("dependency-baseline.json", assets["dependency-baseline.json"])
	envelope.StableChecklist = identity("stable-checklist.json", assets["stable-checklist.json"])
}

func checksumsFor(t *testing.T, assets map[string][]byte) []byte {
	t.Helper()
	entries := make([]ChecksumEntry, 0, len(assets))
	for assetPath, data := range assets {
		entries = append(entries, ChecksumEntry{Path: assetPath, Digest: DigestBytes(data)})
	}
	encoded, err := EncodeChecksums(entries)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testProfile() OSProfile {
	return OSProfile{ID: "debian-12-amd64", Family: "debian", Release: "12.10", Architecture: "amd64", SystemdVersion: "252.38", NginxVersion: "1.22.1-9", PackageSnapshotDigest: digest("packages")}
}

func testSecurityReport(candidateDigest string, resolution FindingResolution) SecurityReport {
	finding := SecurityFinding{ID: "GO-TEST-1", Component: "module-one", Severity: SeverityHigh, InShippedClosure: true, RuntimeReachable: true, Resolution: resolution}
	if resolution != ResolutionUnresolved {
		finding.EvidenceDigest = digest("resolution")
	}
	return SecurityReport{SchemaVersion: SecurityReportSchemaVersion, CandidateDigest: candidateDigest, ScannedAt: time.Unix(1_700_000_000, 0).UTC(), Scanners: []ScannerIdentity{
		{Kind: "distro_security", Name: "debian-security-tracker", Version: "2026.08", DatabaseDigest: digest("distro-db"), Coverage: "runtime_os_packages"},
		{Kind: "go_vulnerability", Name: "govulncheck", Version: "1.1.4", DatabaseDigest: digest("go-db"), Coverage: "go_binary"},
		{Kind: "sbom_osv", Name: "osv-scanner", Version: "2.0.3", DatabaseDigest: digest("osv-db"), Coverage: "sbom"},
	}, Findings: []SecurityFinding{finding}}
}

func validDependencyBaseline() []byte {
	cutoff := time.Unix(1_700_000_000, 0).UTC()
	published := cutoff.Add(-time.Hour)
	profileDigest, _ := ProfileDigest(testProfile())
	selection := func(component string, kind dependencies.SourceKind, version, artifact string) dependencies.Selection {
		value := dependencies.Selection{Component: component, SourceKind: kind, SelectedVersion: version, LatestStableVersion: version, LatestStablePublishedAt: published, MetadataSource: "https://metadata.example.test/releases", MetadataSnapshotDigest: digest("metadata-" + component), ArtifactIdentity: artifact, ArtifactDigest: digest("artifact-" + component)}
		if kind == dependencies.SourceDistroRepository {
			value.OSProfileDigest = profileDigest
		} else {
			value.OperatingSystem = "linux"
			value.Architecture = "amd64"
		}
		return value
	}
	baseline := dependencies.Baseline{SchemaVersion: dependencies.SchemaVersion, Cutoff: cutoff, Selections: []dependencies.Selection{
		selection("apache2-utils", dependencies.SourceDistroRepository, "2.4.62-1", "apache2-utils=2.4.62-1@debian/bookworm-security"),
		selection("goaccess", dependencies.SourceDistroRepository, "1.7-1", "goaccess=1.7-1@debian/bookworm"),
		selection("headscale", dependencies.SourceCanonicalArtifact, "0.25.1", "https://downloads.example.test/headscale-0.25.1"),
		selection("lego", dependencies.SourceCanonicalArtifact, "4.25.2", "https://downloads.example.test/lego-4.25.2"),
		selection("nginx", dependencies.SourceDistroRepository, "1.22.1-9", "nginx=1.22.1-9@debian/bookworm-security"),
		selection("tailscale-client", dependencies.SourceCanonicalArtifact, "1.82.0", "https://downloads.example.test/tailscale-1.82.0"),
	}}
	data, err := dependencies.EncodeBaseline(baseline)
	if err != nil {
		panic(err)
	}
	return data
}

func identity(path string, data []byte) AssetIdentity {
	return AssetIdentity{Path: path, Digest: DigestBytes(data), Bytes: uint64(len(data))}
}

func digest(seed string) string { return DigestBytes([]byte(seed)) }
func ptr[T any](value T) *T     { return &value }
