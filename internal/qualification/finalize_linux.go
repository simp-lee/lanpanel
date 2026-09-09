//go:build linux

package qualification

import (
	"fmt"
	"lanpanel/internal/packages"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const FinalizeInputSchemaVersion = "lanpanel.release.finalize-input.v2"

type FinalizeInput struct {
	SchemaVersion      string `json:"schema_version"`
	QualificationInput string `json:"qualification_input"`
	SecurityScanInput  string `json:"security_scan_input"`
	OutputDirectory    string `json:"output_directory"`
	ExpectedReleaseTag string `json:"expected_release_tag"`
	ExpectedCommitOID  string `json:"expected_commit_oid"`
}

type FinalizedRelease struct {
	ReleaseTag       string   `json:"release_tag"`
	ManifestDigest   string   `json:"manifest_digest"`
	CandidateDigest  string   `json:"candidate_digest"`
	SourceTreeDigest string   `json:"source_tree_digest"`
	OutputDirectory  string   `json:"output_directory"`
	Assets           []string `json:"assets"`
}

func FinalizeRelease(inputPath string, now func() time.Time) (FinalizedRelease, error) {
	data, _, err := readProtectedFile(inputPath, 1<<20, false)
	if err != nil {
		return FinalizedRelease{}, err
	}
	var input FinalizeInput
	if err := release.DecodeCanonical(data, &input); err != nil {
		return FinalizedRelease{}, err
	}
	if input.SchemaVersion != FinalizeInputSchemaVersion || !filepath.IsAbs(input.QualificationInput) || filepath.Clean(input.QualificationInput) != input.QualificationInput || !filepath.IsAbs(input.SecurityScanInput) || filepath.Clean(input.SecurityScanInput) != input.SecurityScanInput || !filepath.IsAbs(input.OutputDirectory) || filepath.Clean(input.OutputDirectory) != input.OutputDirectory || input.OutputDirectory == "/" || input.ExpectedReleaseTag == "" || !commitOIDPattern(input.ExpectedCommitOID) || now == nil {
		return FinalizedRelease{}, fmt.Errorf("release finalization input is invalid")
	}
	prepared, _, err := VerifyFinalReadiness(input.QualificationInput)
	if err != nil {
		return FinalizedRelease{}, err
	}
	if err := requireExactCleanCommit(prepared.Input.Artifacts.SourceRoot, input.ExpectedCommitOID); err != nil {
		return FinalizedRelease{}, err
	}
	identity := prepared.Install.Identity()
	if identity.ReleaseTag != input.ExpectedReleaseTag {
		return FinalizedRelease{}, fmt.Errorf("release tag differs from qualified candidate")
	}
	securityScanBytes, _, err := readProtectedFile(input.SecurityScanInput, 1<<20, false)
	if err != nil {
		return FinalizedRelease{}, err
	}
	var securityScanInput SecurityScanInput
	if err := release.DecodeCanonical(securityScanBytes, &securityScanInput); err != nil {
		return FinalizedRelease{}, fmt.Errorf("release finalization security scan input is invalid: %w", err)
	}
	if err := validateSecurityScanInput(securityScanInput); err != nil {
		return FinalizedRelease{}, fmt.Errorf("release finalization security scan authority is invalid: %w", err)
	}
	if securityScanInput.QualificationInput != input.QualificationInput {
		return FinalizedRelease{}, fmt.Errorf("release finalization does not bind the qualification security scan")
	}
	if _, err := RunReleaseSecurityScan(input.SecurityScanInput, now); err != nil {
		return FinalizedRelease{}, fmt.Errorf("mandatory fixed-feed release security scan failed: %w", err)
	}
	summaryBytes, _, err := readProtectedFile(prepared.Input.Artifacts.QualificationSummary, 4<<20, true)
	if err != nil {
		return FinalizedRelease{}, err
	}
	summary, err := release.DecodeQualificationSummary(summaryBytes)
	if err != nil {
		return FinalizedRelease{}, err
	}
	attestationBytes, _, err := readProtectedFile(prepared.Input.Artifacts.ExecutorAttestation, 4<<20, true)
	if err != nil {
		return FinalizedRelease{}, err
	}
	attestation, err := release.DecodeLiveExecutorAttestation(attestationBytes)
	if err != nil {
		return FinalizedRelease{}, err
	}
	if summary.RunID != prepared.Input.RunID || summary.CandidateDigest != identity.CandidateDigest || summary.SourceTreeDigest != prepared.SourceDigest || summary.TargetProfileDigest != identity.ProfileDigest || summary.TailnetLiveStatus != attestation.TailnetLiveStatus || !providerClaimsMatch(summary.ProviderLiveTests, attestation.DNSProvider) {
		return FinalizedRelease{}, fmt.Errorf("qualification summary differs from final readiness")
	}
	securityBytes, _, err := readProtectedFile(prepared.Input.Artifacts.SecurityReport, 16<<20, true)
	if err != nil {
		return FinalizedRelease{}, err
	}
	security, err := release.DecodeSecurityReport(securityBytes)
	if err != nil {
		return FinalizedRelease{}, fmt.Errorf("security report does not authorize qualified candidate: %w", err)
	}
	if security.CandidateDigest != identity.CandidateDigest || !securityReportMatchesScanInput(security, securityScanInput) {
		return FinalizedRelease{}, fmt.Errorf("security report does not bind the qualified candidate and fixed scan authority")
	}
	if err := release.CheckSecurityGate(security); err != nil {
		return FinalizedRelease{}, fmt.Errorf("security report does not authorize qualified candidate: %w", err)
	}
	candidateBytes, _, err := readProtectedFile(prepared.Input.Artifacts.CandidateBinary, 256<<20, false)
	if err != nil {
		return FinalizedRelease{}, err
	}
	sourceBytes, _, err := readProtectedFile(prepared.Input.Artifacts.SourceArchive, 512<<20, false)
	if err != nil {
		return FinalizedRelease{}, err
	}
	dependencyBytes, _, err := readProtectedFile(prepared.Input.Artifacts.DependencyAuthority, 4<<20, true)
	if err != nil {
		return FinalizedRelease{}, err
	}
	if release.DigestBytes(dependencyBytes) != identity.DependencyManifestDigest {
		return FinalizedRelease{}, fmt.Errorf("qualified dependency manifest bytes changed")
	}
	var dependency release.QualificationDependencyAuthority
	if err := release.DecodeCanonical(dependencyBytes, &dependency); err != nil {
		return FinalizedRelease{}, err
	}
	packageTemplateBytes, _, err := readProtectedFile(prepared.Input.Artifacts.PackageTemplate, 4<<20, true)
	if err != nil {
		return FinalizedRelease{}, err
	}
	var packageTemplate packages.Plan
	if err := release.DecodeCanonical(packageTemplateBytes, &packageTemplate); err != nil {
		return FinalizedRelease{}, err
	}
	publicPackageTemplate, err := buildPublicPackageTemplate(packageTemplate, identity.Profile, identity.CandidateDigest)
	if err != nil {
		return FinalizedRelease{}, err
	}
	createdAt := now().UTC().Truncate(time.Second)
	if createdAt.Before(summary.CompletedAt) || security.ScannedAt.After(createdAt) || createdAt.Sub(security.ScannedAt) > maximumSecurityAuthorityAge {
		return FinalizedRelease{}, fmt.Errorf("release finalization clock regressed or security report is outside its seven-day validity")
	}
	for _, scanner := range security.Scanners {
		if scanner.DatabaseCapturedAt.After(createdAt) || createdAt.Sub(scanner.DatabaseCapturedAt) > maximumSecurityAuthorityAge {
			return FinalizedRelease{}, fmt.Errorf("release vulnerability feed is outside its seven-day validity")
		}
	}
	sbomBytes, _, err := readProtectedFile(prepared.Input.Artifacts.SBOM, 16<<20, true)
	if err != nil || release.ValidateReleaseSPDX(sbomBytes, candidateBytes, identity.CandidateDigest, identity.ReleaseTag, dependency, identity.Profile) != nil {
		return FinalizedRelease{}, fmt.Errorf("qualified SBOM is unavailable or changed: %w", err)
	}
	if security.SBOMDigest != release.DigestBytes(sbomBytes) || security.DependencyManifestDigest != release.DigestBytes(dependencyBytes) || security.TargetProfileDigest != identity.ProfileDigest {
		return FinalizedRelease{}, fmt.Errorf("security report does not bind exact SBOM/dependency/profile closure")
	}
	licenseBytes, err := release.ReadSourceArchiveFile(sourceBytes, input.ExpectedReleaseTag, "LICENSE", 1<<20)
	if err != nil {
		return FinalizedRelease{}, err
	}
	noticeBytes, err := release.ReadSourceArchiveFile(sourceBytes, input.ExpectedReleaseTag, "NOTICE", 1<<20)
	if err != nil {
		return FinalizedRelease{}, err
	}
	limitationsBytes, err := release.ReadSourceArchiveFile(sourceBytes, input.ExpectedReleaseTag, "KNOWN_LIMITATIONS.md", 1<<20)
	if err != nil || release.ValidateKnownLimitations(limitationsBytes) != nil {
		return FinalizedRelease{}, fmt.Errorf("tracked known limitations are invalid: %w", err)
	}
	assets := map[string][]byte{
		"lanpanel": candidateBytes, "lanpanel-" + input.ExpectedReleaseTag + ".tar.gz": sourceBytes,
		"LICENSE": licenseBytes, "NOTICE": noticeBytes, "lanpanel.spdx.json": sbomBytes,
		"dependency-manifest.json": dependencyBytes, "security-report.json": securityBytes,
		"qualification-summary.json": summaryBytes, "known-limitations.md": limitationsBytes,
		"package-template.json": publicPackageTemplate,
	}
	additional := []release.AssetIdentity{}
	for name, path := range prepared.Input.Artifacts.DependencyAssets {
		asset, _, readErr := readProtectedFile(path, 512<<20, true)
		if readErr != nil {
			return FinalizedRelease{}, readErr
		}
		assets[name] = asset
		if name == dependency.Headscale.Archive.Path || headscaleMemberAsset(dependency.Headscale, name) {
			continue
		}
		additional = append(additional, assetIdentity(name, asset))
	}
	additional = append(additional, assetIdentity("package-template.json", publicPackageTemplate))
	slices.SortFunc(additional, func(left, right release.AssetIdentity) int { return strings.Compare(left.Path, right.Path) })
	manifest := release.ReleaseManifest{
		SchemaVersion: release.ReleaseManifestSchemaVersion, ReleaseTag: input.ExpectedReleaseTag,
		Binary: assetIdentity("lanpanel", candidateBytes), SourceArchive: assetIdentity("lanpanel-"+input.ExpectedReleaseTag+".tar.gz", sourceBytes), License: assetIdentity("LICENSE", licenseBytes), Notice: assetIdentity("NOTICE", noticeBytes),
		SBOM: assetIdentity("lanpanel.spdx.json", sbomBytes), DependencyManifest: assetIdentity("dependency-manifest.json", dependencyBytes), Headscale: dependency.Headscale,
		SecurityReport: assetIdentity("security-report.json", securityBytes), QualificationSummary: assetIdentity("qualification-summary.json", summaryBytes), ProviderLiveTests: append([]release.ProviderLiveTest(nil), summary.ProviderLiveTests...),
		KnownLimitations: assetIdentity("known-limitations.md", limitationsBytes), AdditionalAssets: additional, SourceTreeDigest: prepared.SourceDigest,
		SupportedProfiles: []release.SupportedOSProfile{{Profile: identity.Profile, QualifiedBinaryDigest: identity.CandidateDigest, QualificationRunID: summary.RunID, QualificationSummaryDigest: release.DigestBytes(summaryBytes)}},
	}
	entries := make([]release.ChecksumEntry, 0, len(assets))
	assetNames := make([]string, 0, len(assets))
	for name, asset := range assets {
		entries = append(entries, release.ChecksumEntry{Path: name, Digest: release.DigestBytes(asset)})
		assetNames = append(assetNames, name)
	}
	checksums, err := release.EncodeChecksums(entries)
	if err != nil {
		return FinalizedRelease{}, err
	}
	manifest.Checksums = assetIdentity("SHA256SUMS", checksums)
	manifestBytes, err := release.MarshalCanonical(manifest)
	if err != nil {
		return FinalizedRelease{}, err
	}
	verified, err := release.VerifyRelease(release.DigestBytes(manifestBytes), manifestBytes, checksums, assets)
	if err != nil || release.AuthorizePublication(verified) != nil {
		return FinalizedRelease{}, fmt.Errorf("final release bundle failed self-authorization: %w", err)
	}
	parentFD, temporaryName, temporaryPath, err := createStagingDirectory(input.OutputDirectory)
	if err != nil {
		return FinalizedRelease{}, err
	}
	committed := false
	defer func() {
		_ = unix.Close(parentFD)
		if !committed {
			_ = os.RemoveAll(temporaryPath)
		}
	}()
	for name, asset := range assets {
		mode := uint32(0o400)
		if name == "lanpanel" {
			mode = 0o500
		}
		if err := writeArtifact(temporaryPath, filepath.FromSlash(name), asset, mode); err != nil {
			return FinalizedRelease{}, err
		}
	}
	if err := writeArtifact(temporaryPath, "SHA256SUMS", checksums, 0o400); err != nil {
		return FinalizedRelease{}, err
	}
	if err := writeArtifact(temporaryPath, "release.json", manifestBytes, 0o400); err != nil {
		return FinalizedRelease{}, err
	}
	if err := syncTree(temporaryPath); err != nil {
		return FinalizedRelease{}, err
	}
	if err := unix.Renameat2(parentFD, temporaryName, parentFD, filepath.Base(input.OutputDirectory), unix.RENAME_NOREPLACE); err != nil {
		return FinalizedRelease{}, err
	}
	committed = true
	if err := unix.Fsync(parentFD); err != nil {
		return FinalizedRelease{}, err
	}
	assetNames = append(assetNames, "SHA256SUMS", "release.json")
	slices.Sort(assetNames)
	return FinalizedRelease{ReleaseTag: input.ExpectedReleaseTag, ManifestDigest: release.DigestBytes(manifestBytes), CandidateDigest: identity.CandidateDigest, SourceTreeDigest: prepared.SourceDigest, OutputDirectory: input.OutputDirectory, Assets: assetNames}, nil
}

func buildPublicPackageTemplate(template packages.Plan, profile release.OSProfile, binaryDigest string) ([]byte, error) {
	if err := release.ValidateQualificationPackageTemplate(template, profile); err != nil {
		return nil, err
	}
	profileDigest, err := release.ProfileDigest(profile)
	if err != nil {
		return nil, err
	}
	closureDigest, err := packages.ClosureDigest(template.Packages)
	if err != nil || closureDigest != profile.PackageClosureDigest || len(template.Packages) != len(profile.Packages) {
		return nil, fmt.Errorf("public package template closure differs from supported profile")
	}
	for index, pkg := range template.Packages {
		want := profile.Packages[index]
		if pkg.Name != want.Name || pkg.Version != want.Version || pkg.Architecture != want.Architecture {
			return nil, fmt.Errorf("public package template tuple differs from supported profile")
		}
	}
	if len(template.Repositories) != 1 || template.Repositories[0].URI != profile.RepositorySource || template.Repositories[0].KeyringDigest != profile.RepositoryKeyFingerprint || template.Repositories[0].MetadataDigest != profile.RepositoryMetadataDigest || template.Repositories[0].CutoffDigest != profile.RepositoryCutoffDigest {
		return nil, fmt.Errorf("public package template repository differs from supported profile")
	}
	repositoryDigest, err := release.RepositoryAuthorityDigest(template.Repositories[0])
	if err != nil || repositoryDigest != profile.RepositoryAuthorityDigest {
		return nil, fmt.Errorf("public package template repository authority differs from supported profile")
	}
	template.TransactionID = "pkg_" + strings.Repeat("0", 64)
	template.JobID = "job_" + strings.Repeat("1", 64)
	template.IntentGeneration = 1
	template.Deadline = time.Unix(4102444800, 0).UTC()
	template.OSProfileDigest = profileDigest
	template.NoAutostartPolicyDigest = binaryDigest
	template.PreflightDigest = "sha256:" + strings.Repeat("0", 64)
	template.PreflightRequestDigest = "sha256:" + strings.Repeat("1", 64)
	template.Authority = packages.QualificationAuthority{Kind: packages.FinalSupportedProfile, ReleaseAuthorityDigest: strings.Repeat("0", 64), BinaryDigest: binaryDigest, HostFingerprint: "host-template", Operation: "package_transaction", TargetOSProfileDigest: profileDigest, FrozenClosureDigest: profile.PackageClosureDigest}
	if err := packages.ValidatePlan(template); err != nil {
		return nil, fmt.Errorf("public package template is invalid: %w", err)
	}
	return release.MarshalCanonical(template)
}

func providerClaimsMatch(values []release.ProviderLiveTest, live string) bool {
	if len(values) != 5 {
		return false
	}
	for _, value := range values {
		if (value.Provider == live) != (value.Status == "live_tested") {
			return false
		}
	}
	return true
}

func assetIdentity(path string, data []byte) release.AssetIdentity {
	return release.AssetIdentity{Path: path, Digest: release.DigestBytes(data), Bytes: uint64(len(data))}
}

func headscaleMemberAsset(authority release.HeadscaleArtifactAuthority, name string) bool {
	for _, member := range authority.Members {
		if member.Asset.Path == name {
			return true
		}
	}
	return false
}
