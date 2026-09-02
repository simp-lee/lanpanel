package release

import (
	"encoding/json"
	"fmt"
	"lanpanel/internal/acmeaccount"
	managedarchive "lanpanel/internal/archive"
	"lanpanel/internal/dependencies"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/packages"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	ReleaseManifestSchemaVersion              = "lanpanel.release.v3"
	QualificationTargetProfileSchemaVersion   = "lanpanel.qualification.target-profile.v1"
	QualificationInstallManifestSchemaVersion = "lanpanel.qualification.install-manifest.v4"
	LiveSideEffectPlanSchemaVersion           = "lanpanel.qualification.side-effect-plan.v2"
	LiveCleanupReportSchemaVersion            = "lanpanel.qualification.cleanup-report.v3"
	LiveExecutorAttestationSchemaVersion      = "lanpanel.qualification.executor-attestation.v1"
	QualificationSummarySchemaVersion         = "lanpanel.qualification.summary.v2"
)

type InstallKind string

const (
	InstallPublicRelease InstallKind = "public_release"
	InstallQualification InstallKind = "qualification"
)

type AssetIdentity struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Bytes  uint64 `json:"bytes"`
}

type ArchiveMemberAuthority struct {
	Path        string        `json:"path"`
	Asset       AssetIdentity `json:"asset"`
	Destination string        `json:"destination"`
	Mode        uint32        `json:"mode"`
}

const (
	SupportedHeadscaleConfigContract = "headscale-trusted-mesh-v1"
	SupportedHeadscaleVersion        = "0.29.0"
)

var supportedHeadscaleConfigContractBytes = []byte(`{"schema_version":"lanpanel.headscale.config-contract.v1","control_backend":"isolated","database":"sqlite","policy":"trusted_mesh","privileged_endpoint":"unix"}`)

func SupportedHeadscaleConfigContractDigest() string {
	return DigestBytes(supportedHeadscaleConfigContractBytes)
}

type HeadscaleArtifactAuthority struct {
	Version               string                   `json:"version"`
	ArtifactIdentity      string                   `json:"artifact_identity"`
	Archive               AssetIdentity            `json:"archive"`
	ArchiveFormat         string                   `json:"archive_format"`
	MaximumExtractedBytes uint64                   `json:"maximum_extracted_bytes"`
	RedirectAuthorities   []string                 `json:"redirect_authorities"`
	Members               []ArchiveMemberAuthority `json:"members"`
	ExecutableAsset       string                   `json:"executable_asset"`
	InstallPath           string                   `json:"install_path"`
	ConfigContract        string                   `json:"config_contract"`
	ConfigContractDigest  string                   `json:"config_contract_digest"`
}

type ClientArtifactAuthority struct {
	Version               string                   `json:"version"`
	ArtifactIdentity      string                   `json:"artifact_identity"`
	Archive               AssetIdentity            `json:"archive"`
	ArchiveFormat         string                   `json:"archive_format"`
	MaximumExtractedBytes uint64                   `json:"maximum_extracted_bytes"`
	RedirectAuthorities   []string                 `json:"redirect_authorities"`
	Members               []ArchiveMemberAuthority `json:"members"`
	ExecutableAsset       string                   `json:"executable_asset"`
	InstallPath           string                   `json:"install_path"`
}

type PackageTuple struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type OSProfile struct {
	ID                        string             `json:"id"`
	Family                    string             `json:"family"`
	Release                   string             `json:"release"`
	Architecture              string             `json:"architecture"`
	SystemdVersion            string             `json:"systemd_version"`
	NginxVersion              string             `json:"nginx_version"`
	PackageSnapshotDigest     string             `json:"package_snapshot_digest"`
	RepositorySource          string             `json:"repository_source"`
	RepositoryKeyFingerprint  string             `json:"repository_key_fingerprint"`
	RepositoryMetadataDigest  string             `json:"repository_metadata_digest"`
	RepositoryCutoffDigest    string             `json:"repository_cutoff_digest"`
	RepositoryAuthorityDigest string             `json:"repository_authority_digest"`
	PackageClosureDigest      string             `json:"package_closure_digest"`
	Packages                  []PackageTuple     `json:"packages"`
	ManagedConfinement        ConfinementProfile `json:"managed_confinement"`
}

type ConfinementProfile struct {
	SchemaVersion         string   `json:"schema_version"`
	KernelRelease         string   `json:"kernel_release"`
	CgroupMode            string   `json:"cgroup_mode"`
	BindListenPolicy      string   `json:"bind_listen_policy"`
	ConnectPolicy         string   `json:"connect_policy"`
	FilesystemPolicy      string   `json:"filesystem_policy"`
	ProtectedDestinations []string `json:"protected_destinations"`
	QualificationDigest   string   `json:"qualification_digest"`
}

type SupportedOSProfile struct {
	Profile                    OSProfile `json:"profile"`
	QualifiedBinaryDigest      string    `json:"qualified_binary_digest"`
	QualificationRunID         string    `json:"qualification_run_id"`
	QualificationSummaryDigest string    `json:"qualification_summary_digest"`
}

type ProviderLiveTest struct {
	Provider string `json:"provider"`
	Status   string `json:"status"`
}

type QualificationSummary struct {
	SchemaVersion             string             `json:"schema_version"`
	RunID                     string             `json:"run_id"`
	CandidateDigest           string             `json:"candidate_digest"`
	SourceTreeDigest          string             `json:"source_tree_digest"`
	TargetProfileDigest       string             `json:"target_profile_digest"`
	InstallManifestDigest     string             `json:"install_manifest_digest"`
	SideEffectPlanDigest      string             `json:"side_effect_plan_digest"`
	ProtectedInputDigest      string             `json:"protected_input_digest"`
	CleanupReportDigest       string             `json:"cleanup_report_digest"`
	ExecutorAttestationDigest string             `json:"executor_attestation_digest"`
	JourneySucceeded          bool               `json:"journey_succeeded"`
	TailnetLiveStatus         string             `json:"tailnet_live_status"`
	ProviderLiveTests         []ProviderLiveTest `json:"provider_live_tests"`
	CompletedAt               time.Time          `json:"completed_at"`
}

func DecodeQualificationSummary(data []byte) (QualificationSummary, error) {
	var value QualificationSummary
	if DecodeCanonical(data, &value) != nil || value.SchemaVersion != QualificationSummarySchemaVersion || !refPattern.MatchString(value.RunID) || !ValidDigest(value.CandidateDigest) || !ValidDigest(value.SourceTreeDigest) || !ValidDigest(value.TargetProfileDigest) || !ValidDigest(value.InstallManifestDigest) || !ValidDigest(value.SideEffectPlanDigest) || !ValidDigest(value.ProtectedInputDigest) || !ValidDigest(value.CleanupReportDigest) || !ValidDigest(value.ExecutorAttestationDigest) || !value.JourneySucceeded || value.TailnetLiveStatus != "live_tested" && value.TailnetLiveStatus != "not_live_tested" || !sameUTCSecond(value.CompletedAt) {
		return QualificationSummary{}, fmt.Errorf("qualification summary is invalid")
	}
	expected := []string{"cloudflare", "digitalocean", "gcloud", "route53", "tencentcloud"}
	if len(value.ProviderLiveTests) != len(expected) {
		return QualificationSummary{}, fmt.Errorf("qualification summary provider inventory is invalid")
	}
	liveCount := 0
	for index, item := range value.ProviderLiveTests {
		if item.Status == "live_tested" {
			liveCount++
		}
		if item.Provider != expected[index] || item.Status != "live_tested" && item.Status != "not_live_tested" {
			return QualificationSummary{}, fmt.Errorf("qualification summary provider inventory is invalid")
		}
	}
	if liveCount != 1 {
		return QualificationSummary{}, fmt.Errorf("qualification summary must contain exactly one live-tested provider")
	}
	return value, nil
}

type ReleaseManifest struct {
	SchemaVersion        string                     `json:"schema_version"`
	ReleaseTag           string                     `json:"release_tag"`
	Binary               AssetIdentity              `json:"binary"`
	SourceArchive        AssetIdentity              `json:"source_archive"`
	License              AssetIdentity              `json:"license"`
	Notice               AssetIdentity              `json:"notice"`
	SBOM                 AssetIdentity              `json:"sbom"`
	DependencyManifest   AssetIdentity              `json:"dependency_manifest"`
	Headscale            HeadscaleArtifactAuthority `json:"headscale"`
	SecurityReport       AssetIdentity              `json:"security_report"`
	QualificationSummary AssetIdentity              `json:"qualification_summary"`
	ProviderLiveTests    []ProviderLiveTest         `json:"provider_live_tests"`
	KnownLimitations     AssetIdentity              `json:"known_limitations"`
	AdditionalAssets     []AssetIdentity            `json:"additional_assets"`
	Checksums            AssetIdentity              `json:"checksums"`
	SourceTreeDigest     string                     `json:"source_tree_digest"`
	SupportedProfiles    []SupportedOSProfile       `json:"supported_os_profiles"`
}

type VerifiedRelease struct {
	value         ReleaseManifest
	digest        string
	security      SecurityReport
	qualification QualificationSummary
}

func (verified *VerifiedRelease) Manifest() ReleaseManifest {
	if verified == nil {
		return ReleaseManifest{}
	}
	return cloneReleaseManifest(verified.value)
}

func (verified *VerifiedRelease) Digest() string {
	if verified == nil {
		return ""
	}
	return verified.digest
}

func DecodeReleaseManifest(data []byte) (*VerifiedRelease, error) {
	var manifest ReleaseManifest
	if err := DecodeCanonical(data, &manifest); err != nil {
		return nil, err
	}
	if err := validateReleaseManifest(manifest); err != nil {
		return nil, err
	}
	return &VerifiedRelease{value: manifest, digest: DigestBytes(data)}, nil
}

func VerifyRelease(expectedManifestDigest string, manifestBytes, checksumBytes []byte, assets map[string][]byte) (*VerifiedRelease, error) {
	if !ValidDigest(expectedManifestDigest) || DigestBytes(manifestBytes) != expectedManifestDigest {
		return nil, fmt.Errorf("release.json differs from the selected digest")
	}
	verified, err := DecodeReleaseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := verifyReleaseAssets(verified.value, checksumBytes, assets); err != nil {
		return nil, err
	}
	sbomBytes, present := assets[verified.value.SBOM.Path]
	if !present || ValidateSPDX(sbomBytes, verified.value.Binary.Digest) != nil {
		return nil, fmt.Errorf("release SBOM is invalid or bound to other bytes")
	}
	securityBytes, present := assets[verified.value.SecurityReport.Path]
	if !present {
		return nil, fmt.Errorf("release security report asset is missing")
	}
	security, err := DecodeSecurityReport(securityBytes)
	profileDigestForSecurity, _ := ProfileDigest(verified.value.SupportedProfiles[0].Profile)
	if err != nil || security.CandidateDigest != verified.value.Binary.Digest || security.SBOMDigest != verified.value.SBOM.Digest || security.DependencyManifestDigest != verified.value.DependencyManifest.Digest || security.TargetProfileDigest != profileDigestForSecurity {
		return nil, fmt.Errorf("release security report is invalid or bound to other bytes")
	}
	verified.security = security
	limitationsBytes, present := assets[verified.value.KnownLimitations.Path]
	if !present || ValidateKnownLimitations(limitationsBytes) != nil {
		return nil, fmt.Errorf("release known limitations are missing or incomplete")
	}
	summaryBytes, present := assets[verified.value.QualificationSummary.Path]
	if !present {
		return nil, fmt.Errorf("qualification summary asset is missing")
	}
	summary, summaryErr := DecodeQualificationSummary(summaryBytes)
	profile := verified.value.SupportedProfiles[0]
	profileDigest, _ := ProfileDigest(profile.Profile)
	packageTemplate, present := assets["package-template.json"]
	if !present || validatePublicPackageTemplate(packageTemplate, verified.value.Binary, profile.Profile, profileDigest) != nil {
		return nil, fmt.Errorf("public package template is missing, invalid, or not installable")
	}
	if summaryErr != nil || summary.RunID != profile.QualificationRunID || summary.CandidateDigest != verified.value.Binary.Digest || summary.SourceTreeDigest != verified.value.SourceTreeDigest || summary.TargetProfileDigest != profileDigest || !reflect.DeepEqual(summary.ProviderLiveTests, verified.value.ProviderLiveTests) {
		return nil, fmt.Errorf("qualification summary does not bind the supported release")
	}
	verified.qualification = summary
	return verified, nil
}

func verifyReleaseAssets(manifest ReleaseManifest, checksumBytes []byte, assets map[string][]byte) error {
	if DigestBytes(checksumBytes) != manifest.Checksums.Digest || uint64(len(checksumBytes)) != manifest.Checksums.Bytes {
		return fmt.Errorf("SHA256SUMS does not match release.json")
	}
	identities, err := releaseAssetInventory(manifest)
	if err != nil {
		return err
	}
	expectedPaths := make([]string, len(identities))
	byPath := make(map[string]AssetIdentity, len(identities))
	for index, identity := range identities {
		expectedPaths[index] = identity.Path
		byPath[identity.Path] = identity
	}
	checksums, err := ParseChecksums(checksumBytes, expectedPaths)
	if err != nil {
		return err
	}
	if len(assets) != len(identities) {
		return fmt.Errorf("release asset inventory differs from release.json")
	}
	if err := VerifyAssetBytes(checksums, assets); err != nil {
		return err
	}
	for path, data := range assets {
		identity, present := byPath[path]
		if !present || identity.Bytes != uint64(len(data)) || identity.Digest != DigestBytes(data) {
			return fmt.Errorf("asset %q size or digest differs from release.json", path)
		}
	}
	sourceBytes, present := assets[manifest.SourceArchive.Path]
	if !present {
		return fmt.Errorf("source archive asset is missing")
	}
	treeDigest, err := sourceArchiveTreeDigest(sourceBytes, "lanpanel-"+manifest.ReleaseTag)
	if err != nil || treeDigest != manifest.SourceTreeDigest {
		return fmt.Errorf("source archive does not match source-tree digest: %w", err)
	}
	dependencyBytes, present := assets[manifest.DependencyManifest.Path]
	if !present {
		return fmt.Errorf("dependency manifest asset is missing")
	}
	dependency, err := decodeQualificationDependencyAuthority(dependencyBytes, manifest.DependencyManifest.Digest)
	if err != nil || !reflect.DeepEqual(dependency.Headscale, manifest.Headscale) {
		return fmt.Errorf("dependency manifest is invalid or differs from release.json")
	}
	if sbomBytes, present := assets[manifest.SBOM.Path]; !present || ValidateReleaseSPDX(sbomBytes, assets[manifest.Binary.Path], manifest.Binary.Digest, manifest.ReleaseTag, dependency, manifest.SupportedProfiles[0].Profile) != nil {
		return fmt.Errorf("release SBOM omits the native or OS package closure")
	}
	baselineBytes, present := assets[dependency.DependencyBaseline.Path]
	if !present || dependency.DependencyBaseline.Bytes != uint64(len(baselineBytes)) || dependency.DependencyBaseline.Digest != DigestBytes(baselineBytes) {
		return fmt.Errorf("dependency baseline asset is missing or mismatched")
	}
	baseline, err := dependencies.DecodeBaseline(baselineBytes)
	if err != nil {
		return fmt.Errorf("dependency baseline is invalid: %w", err)
	}
	dependencyPaths, err := QualificationDependencyAssetPaths(dependency)
	if err != nil {
		return err
	}
	dependencyAssets := make(map[string][]byte, len(dependencyPaths))
	for _, path := range dependencyPaths {
		dependencyAssets[path] = assets[path]
	}
	return verifyDependencyAuthority(dependency, manifest.SupportedProfiles[0].Profile, dependencyAssets, baseline)
}

func validatePublicPackageTemplate(data []byte, binary AssetIdentity, profile OSProfile, profileDigest string) error {
	var plan packages.Plan
	if err := DecodeCanonical(data, &plan); err != nil || packages.ValidatePlan(plan) != nil {
		return fmt.Errorf("public package template is not canonical")
	}
	zeroDigest := strings.Repeat("0", 64)
	oneDigest := strings.Repeat("1", 64)
	if plan.Mode != packages.DistroRepository || plan.Proxy != nil || !plan.FirstNginxInstall || plan.TransactionID != "pkg_"+zeroDigest || plan.JobID != "job_"+oneDigest || plan.IntentGeneration != 1 || !plan.Deadline.Equal(time.Unix(4102444800, 0).UTC()) || plan.OSProfileDigest != profileDigest || plan.NoAutostartPolicyDigest != binary.Digest || plan.PreflightDigest != "sha256:"+zeroDigest || plan.PreflightRequestDigest != "sha256:"+oneDigest || plan.Authority.Kind != packages.FinalSupportedProfile || plan.Authority.ReleaseAuthorityDigest != zeroDigest || plan.Authority.BinaryDigest != binary.Digest || plan.Authority.HostFingerprint != "host-template" || plan.Authority.Operation != "package_transaction" || plan.Authority.TargetOSProfileDigest != profileDigest || plan.Authority.FrozenClosureDigest != profile.PackageClosureDigest {
		return fmt.Errorf("public package template carries non-template authority")
	}
	if len(plan.Packages) != len(profile.Packages) {
		return fmt.Errorf("public package template closure differs from supported profile")
	}
	for index, pkg := range plan.Packages {
		want := profile.Packages[index]
		if pkg.Name != want.Name || pkg.Version != want.Version || pkg.Architecture != want.Architecture {
			return fmt.Errorf("public package template tuple differs from supported profile")
		}
	}
	if len(plan.Repositories) != 1 || plan.Repositories[0].URI != profile.RepositorySource || plan.Repositories[0].KeyringDigest != profile.RepositoryKeyFingerprint || plan.Repositories[0].MetadataDigest != profile.RepositoryMetadataDigest || plan.Repositories[0].CutoffDigest != profile.RepositoryCutoffDigest {
		return fmt.Errorf("public package template repository differs from supported profile")
	}
	repositoryDigest, err := RepositoryAuthorityDigest(plan.Repositories[0])
	if err != nil || repositoryDigest != profile.RepositoryAuthorityDigest {
		return fmt.Errorf("public package template repository authority differs from supported profile")
	}
	return nil
}

// RepositoryAuthorityDigest binds every field of the exact apt repository
// authority, including its identity, suite, components, keyring path, and
// metadata snapshots.
func RepositoryAuthorityDigest(repository packages.Repository) (string, error) {
	data, err := json.Marshal(repository)
	if err != nil {
		return "", err
	}
	return DigestBytes(data), nil
}

// InstallAssetPaths returns the complete public release asset inventory,
// including the checksum and manifest files supplied separately to the
// installer authority document.
func InstallAssetPaths(manifest ReleaseManifest) ([]string, error) {
	identities, err := releaseAssetInventory(manifest)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(identities)+2)
	for _, identity := range identities {
		paths = append(paths, identity.Path)
	}
	paths = append(paths, manifest.Checksums.Path, "release.json")
	slices.Sort(paths)
	return paths, nil
}

func releaseAssetInventory(manifest ReleaseManifest) ([]AssetIdentity, error) {
	assets := []AssetIdentity{manifest.Binary, manifest.SourceArchive, manifest.License, manifest.Notice, manifest.SBOM, manifest.DependencyManifest, manifest.Headscale.Archive, manifest.SecurityReport, manifest.QualificationSummary, manifest.KnownLimitations}
	for _, member := range manifest.Headscale.Members {
		assets = append(assets, member.Asset)
	}
	assets = append(assets, manifest.AdditionalAssets...)
	seen := map[string]bool{}
	for _, asset := range assets {
		if err := validateAsset(asset); err != nil || seen[asset.Path] || asset.Path == manifest.Checksums.Path || asset.Path == "release.json" {
			return nil, fmt.Errorf("release asset inventory is invalid or duplicated")
		}
		seen[asset.Path] = true
	}
	slices.SortFunc(assets, func(a, b AssetIdentity) int { return strings.Compare(a.Path, b.Path) })
	return assets, nil
}

func validateReleaseManifest(manifest ReleaseManifest) error {
	if manifest.SchemaVersion != ReleaseManifestSchemaVersion || !releaseTagPattern.MatchString(manifest.ReleaseTag) || manifest.Binary.Path != "lanpanel" || !ValidDigest(manifest.SourceTreeDigest) || manifest.Checksums.Path != "SHA256SUMS" || validateAsset(manifest.Checksums) != nil || len(manifest.SupportedProfiles) != 1 || len(manifest.ProviderLiveTests) != 5 {
		return fmt.Errorf("release.json common identity is invalid")
	}
	if err := validateHeadscaleAuthority(manifest.Headscale); err != nil {
		return err
	}
	if _, err := releaseAssetInventory(manifest); err != nil {
		return err
	}
	hasPackageTemplate := false
	for _, asset := range manifest.AdditionalAssets {
		hasPackageTemplate = hasPackageTemplate || asset.Path == "package-template.json"
	}
	if !hasPackageTemplate {
		return fmt.Errorf("release public package template is missing")
	}
	if manifest.SourceArchive.Path != "lanpanel-"+manifest.ReleaseTag+".tar.gz" || manifest.License.Path != "LICENSE" || manifest.Notice.Path != "NOTICE" || manifest.SBOM.Path == "" || manifest.DependencyManifest.Path == "" || manifest.SecurityReport.Path == "" || manifest.QualificationSummary.Path == "" || manifest.KnownLimitations.Path == "" {
		return fmt.Errorf("release mandatory asset paths are invalid")
	}
	profile := manifest.SupportedProfiles[0]
	if validateOSProfile(profile.Profile) != nil || profile.QualifiedBinaryDigest != manifest.Binary.Digest || !refPattern.MatchString(profile.QualificationRunID) || !ValidDigest(profile.QualificationSummaryDigest) || profile.QualificationSummaryDigest != manifest.QualificationSummary.Digest {
		return fmt.Errorf("supported profile lacks exact same-binary qualification identity")
	}
	expectedProviders := []string{"cloudflare", "digitalocean", "gcloud", "route53", "tencentcloud"}
	liveProviders := 0
	for index, provider := range manifest.ProviderLiveTests {
		if provider.Status == "live_tested" {
			liveProviders++
		}
		if provider.Provider != expectedProviders[index] || provider.Status != "live_tested" && provider.Status != "not_live_tested" {
			return fmt.Errorf("provider live-test inventory is invalid or noncanonical")
		}
	}
	if liveProviders != 1 {
		return fmt.Errorf("release must contain exactly one live-tested provider")
	}
	return nil
}

func validateAsset(asset AssetIdentity) error {
	if !ValidRelativePath(asset.Path) || !ValidDigest(asset.Digest) || asset.Bytes == 0 || asset.Bytes > uint64(filetxn.MaximumContentBytes) {
		return fmt.Errorf("asset identity is incomplete or exceeds the installation size contract")
	}
	return nil
}

func validateHeadscaleAuthority(authority HeadscaleArtifactAuthority) error {
	if authority.Version != SupportedHeadscaleVersion || !concreteVersionPattern.MatchString(authority.Version) || authority.ArtifactIdentity == "" || authority.Archive.Path != "headscale.tar.gz" || validateAsset(authority.Archive) != nil || authority.ArchiveFormat != string(managedarchive.TarGzip) || authority.MaximumExtractedBytes == 0 || authority.MaximumExtractedBytes > 1<<30 || authority.InstallPath != "/usr/lib/lanpanel/dependencies/headscale" || !ValidRelativePath(authority.ExecutableAsset) || !refPattern.MatchString(authority.ConfigContract) || authority.ConfigContract != SupportedHeadscaleConfigContract || authority.ConfigContractDigest != SupportedHeadscaleConfigContractDigest() {
		return fmt.Errorf("headscale artifact authority is incomplete")
	}
	if !canonicalArtifactURL(authority.ArtifactIdentity) {
		return fmt.Errorf("headscale artifact identity must be an exact HTTPS URL")
	}
	if len(authority.RedirectAuthorities) == 0 || len(authority.RedirectAuthorities) > 16 || len(authority.Members) != 1 || authority.Members[0].Path != authority.ExecutableAsset || authority.Members[0].Destination != authority.InstallPath || authority.Members[0].Mode != 0o755 || validateAsset(authority.Members[0].Asset) != nil {
		return fmt.Errorf("headscale archive member authority is invalid")
	}
	for index, host := range authority.RedirectAuthorities {
		if host == "" || strings.ToLower(host) != host || strings.ContainsAny(host, "/:@") || index > 0 && authority.RedirectAuthorities[index-1] >= host {
			return fmt.Errorf("headscale redirect authority is invalid or unsorted")
		}
	}
	return nil
}

func validateClientArtifactAuthority(authority ClientArtifactAuthority, executable, installPath string) error {
	if !concreteVersionPattern.MatchString(authority.Version) || !canonicalArtifactURL(authority.ArtifactIdentity) || validateAsset(authority.Archive) != nil || authority.ArchiveFormat != string(managedarchive.TarGzip) || authority.MaximumExtractedBytes == 0 || authority.MaximumExtractedBytes > 1<<30 || authority.ExecutableAsset != executable || authority.InstallPath != installPath || len(authority.Members) == 0 || len(authority.Members) > 16 {
		return fmt.Errorf("client artifact authority is incomplete")
	}
	found := false
	previous := ""
	for _, member := range authority.Members {
		if validateAsset(member.Asset) != nil || previous != "" && previous >= member.Path || member.Mode != 0o644 && member.Mode != 0o755 {
			return fmt.Errorf("client archive member authority is invalid")
		}
		if member.Asset.Path == executable {
			found = member.Destination == installPath && member.Mode == 0o755
		}
		previous = member.Path
	}
	if !found {
		return fmt.Errorf("client executable member authority is missing")
	}
	return nil
}

func canonicalArtifactURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Opaque == "" && parsed.String() == value
}

func QualificationDependencyAssetPaths(authority QualificationDependencyAuthority) ([]string, error) {
	paths := []string{authority.DependencyBaseline.Path, authority.Headscale.Archive.Path, authority.LegoArchive.Path, authority.Tailscale.Archive.Path}
	for _, member := range authority.Headscale.Members {
		paths = append(paths, member.Asset.Path)
	}
	for _, member := range authority.LegoMembers {
		paths = append(paths, member.Asset.Path)
	}
	for _, member := range authority.Tailscale.Members {
		paths = append(paths, member.Asset.Path)
	}
	slices.Sort(paths)
	for index, path := range paths {
		if !ValidRelativePath(path) || reservedReleaseAssetPath(path) || index > 0 && paths[index-1] == path {
			return nil, fmt.Errorf("qualification dependency asset inventory is invalid or colliding")
		}
	}
	return paths, nil
}

func reservedReleaseAssetPath(path string) bool {
	switch path {
	case "lanpanel", "LICENSE", "NOTICE", "lanpanel.spdx.json", "dependency-manifest.json", "security-report.json", "qualification-summary.json", "known-limitations.md", "package-template.json", "SHA256SUMS", "release.json":
		return true
	}
	return strings.HasPrefix(path, "lanpanel-") && strings.HasSuffix(path, ".tar.gz")
}

func verifyDependencyAuthority(authority QualificationDependencyAuthority, profile OSProfile, assets map[string][]byte, decoded ...dependencies.Baseline) error {
	expectedAssets, err := QualificationDependencyAssetPaths(authority)
	if err != nil || len(assets) != len(expectedAssets) {
		return fmt.Errorf("dependency asset inventory is missing or contains extras")
	}
	for _, path := range expectedAssets {
		if _, present := assets[path]; !present {
			return fmt.Errorf("dependency asset %q is missing", path)
		}
	}
	baselineBytes, present := assets[authority.DependencyBaseline.Path]
	if !present || authority.DependencyBaseline.Bytes != uint64(len(baselineBytes)) || authority.DependencyBaseline.Digest != DigestBytes(baselineBytes) {
		return fmt.Errorf("dependency baseline bytes are missing or mismatched")
	}
	var baseline dependencies.Baseline
	err = nil
	if len(decoded) == 1 {
		baseline = decoded[0]
	} else if len(decoded) == 0 {
		baseline, err = dependencies.DecodeBaseline(baselineBytes)
	} else {
		return fmt.Errorf("dependency baseline observation is ambiguous")
	}
	if err != nil {
		return err
	}
	profileDigest, err := ProfileDigest(profile)
	if err != nil || dependencies.ValidateForOSProfile(baseline, profileDigest, profile.NginxVersion) != nil {
		return fmt.Errorf("dependency baseline does not bind the exact OS profile")
	}
	packageVersions := make(map[string]string, len(profile.Packages))
	for _, tuple := range profile.Packages {
		if prior, exists := packageVersions[tuple.Name]; exists && prior != tuple.Version {
			return fmt.Errorf("qualified OS profile contains ambiguous package versions")
		}
		packageVersions[tuple.Name] = tuple.Version
	}
	for _, selection := range baseline.Selections {
		if selection.SourceKind == dependencies.SourceDistroRepository && packageVersions[selection.Component] != selection.SelectedVersion {
			return fmt.Errorf("distro dependency %q differs from qualified package tuple", selection.Component)
		}
	}
	var headscaleSelection, legoSelection, tailscaleSelection *dependencies.Selection
	for index := range baseline.Selections {
		switch baseline.Selections[index].Component {
		case "headscale":
			headscaleSelection = &baseline.Selections[index]
		case "lego":
			legoSelection = &baseline.Selections[index]
		case "tailscale-client":
			tailscaleSelection = &baseline.Selections[index]
		}
	}
	if headscaleSelection == nil || headscaleSelection.SourceKind != dependencies.SourceCanonicalArtifact || authority.Headscale.Version != headscaleSelection.SelectedVersion || authority.Headscale.ArtifactIdentity != headscaleSelection.ArtifactIdentity || authority.Headscale.Archive.Digest != headscaleSelection.ArtifactDigest {
		return fmt.Errorf("headscale artifact does not match dependency manifest")
	}
	if err := verifyArchiveAssets(authority.Headscale.Archive, authority.Headscale.ArchiveFormat, authority.Headscale.MaximumExtractedBytes, authority.Headscale.Members, assets); err != nil {
		return fmt.Errorf("headscale artifact: %w", err)
	}
	if legoSelection == nil || legoSelection.SourceKind != dependencies.SourceCanonicalArtifact || authority.LegoVersion != legoSelection.SelectedVersion || authority.LegoArtifactIdentity != legoSelection.ArtifactIdentity || authority.LegoArchive.Digest != legoSelection.ArtifactDigest {
		return fmt.Errorf("lego artifact does not match dependency manifest")
	}
	if err := verifyArchiveAssets(authority.LegoArchive, string(managedarchive.TarGzip), 258<<20, authority.LegoMembers, assets); err != nil {
		return fmt.Errorf("lego artifact: %w", err)
	}
	if tailscaleSelection == nil || tailscaleSelection.SourceKind != dependencies.SourceCanonicalArtifact || authority.Tailscale.Version != tailscaleSelection.SelectedVersion || authority.Tailscale.ArtifactIdentity != tailscaleSelection.ArtifactIdentity || authority.Tailscale.Archive.Digest != tailscaleSelection.ArtifactDigest {
		return fmt.Errorf("tailscale artifact does not match dependency manifest")
	}
	if err := verifyArchiveAssets(authority.Tailscale.Archive, authority.Tailscale.ArchiveFormat, authority.Tailscale.MaximumExtractedBytes, authority.Tailscale.Members, assets); err != nil {
		return fmt.Errorf("tailscale artifact: %w", err)
	}
	return nil
}

func verifyArchiveAssets(archive AssetIdentity, format string, maximum uint64, members []ArchiveMemberAuthority, assets map[string][]byte) error {
	archiveBytes, present := assets[archive.Path]
	if !present || archive.Bytes != uint64(len(archiveBytes)) || archive.Digest != DigestBytes(archiveBytes) || maximum == 0 || maximum > 1<<30 {
		return fmt.Errorf("archive bytes are missing, mismatched, or unbounded")
	}
	spec := managedarchive.Spec{Format: managedarchive.Format(format), MaximumArchiveBytes: int64(maximum), MaximumExtractedBytes: int64(maximum), MaximumMembers: len(members)}
	for _, member := range members {
		data, present := assets[member.Asset.Path]
		if !present || member.Asset.Bytes != uint64(len(data)) || member.Asset.Digest != DigestBytes(data) {
			return fmt.Errorf("archive member %q bytes are missing or mismatched", member.Path)
		}
		spec.Members = append(spec.Members, managedarchive.Member{Path: member.Path, MaximumBytes: int64(member.Asset.Bytes), MaximumPhysicalBytes: int64(maximum), Destination: member.Destination, Metadata: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: os.FileMode(member.Mode)}})
	}
	extracted, err := managedarchive.Extract(archiveBytes, spec)
	if err != nil {
		return err
	}
	for _, member := range members {
		if !slices.Equal(extracted[member.Path], assets[member.Asset.Path]) {
			return fmt.Errorf("extracted member %q differs from its fixed identity", member.Path)
		}
	}
	return nil
}

func validateOSProfile(profile OSProfile) error {
	if !profileIDPattern.MatchString(profile.ID) || (profile.Family != "debian" && profile.Family != "ubuntu") || !osReleasePattern.MatchString(profile.Release) || profile.Architecture != "amd64" || !concreteVersionPattern.MatchString(profile.SystemdVersion) || !concreteVersionPattern.MatchString(profile.NginxVersion) {
		return fmt.Errorf("OS profile platform identity is invalid")
	}
	if !ValidDigest(profile.PackageSnapshotDigest) || !ValidDigest(profile.RepositoryKeyFingerprint) || !ValidDigest(profile.RepositoryMetadataDigest) || !ValidDigest(profile.RepositoryCutoffDigest) || !ValidDigest(profile.RepositoryAuthorityDigest) || !ValidDigest(profile.PackageClosureDigest) {
		return fmt.Errorf("OS profile repository digest authority is invalid")
	}
	if len(profile.Packages) == 0 || len(profile.Packages) > 4096 {
		return fmt.Errorf("OS profile exact package closure is empty or unbounded")
	}
	repository, err := url.Parse(profile.RepositorySource)
	if err != nil || repository.Scheme != "https" || repository.Host == "" || repository.User != nil || repository.RawQuery != "" || repository.Fragment != "" || repository.String() != profile.RepositorySource {
		return fmt.Errorf("OS profile repository source is invalid")
	}
	previous := ""
	for _, tuple := range profile.Packages {
		key := tuple.Name + "\x00" + tuple.Architecture
		if !profileIDPattern.MatchString(tuple.Name) || !concreteVersionPattern.MatchString(tuple.Version) || tuple.Architecture != "amd64" && tuple.Architecture != "all" || previous != "" && previous >= key {
			return fmt.Errorf("OS profile package tuple is invalid, duplicated, or unsorted")
		}
		previous = key
	}
	return validateConfinementProfile(profile.ManagedConfinement)
}

func validateConfinementProfile(profile ConfinementProfile) error {
	if profile.SchemaVersion != "lanpanel.managed.confinement.v1" || !concreteVersionPattern.MatchString(profile.KernelRelease) || profile.CgroupMode != "unified_v2" || profile.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" || profile.ConnectPolicy != "systemd_cgroup_ip_deny_v1" || profile.FilesystemPolicy != "systemd_mount_namespace_v1" || !ValidDigest(profile.QualificationDigest) || len(profile.ProtectedDestinations) == 0 || len(profile.ProtectedDestinations) > 64 {
		return fmt.Errorf("managed confinement qualification is incomplete")
	}
	for index, destination := range profile.ProtectedDestinations {
		if destination == "" || index > 0 && profile.ProtectedDestinations[index-1] >= destination {
			return fmt.Errorf("managed confinement protected destinations are noncanonical")
		}
	}
	return nil
}

func ProfileDigest(profile OSProfile) (string, error) {
	if err := validateOSProfile(profile); err != nil {
		return "", err
	}
	data, err := MarshalCanonical(profile)
	if err != nil {
		return "", err
	}
	return DigestBytes(data), nil
}

type QualificationTargetProfile struct {
	SchemaVersion string    `json:"schema_version"`
	Profile       OSProfile `json:"profile"`
	CapturedAt    time.Time `json:"captured_at"`
}

type PlannedMutation struct {
	ID                    string `json:"id"`
	Scope                 string `json:"scope"`
	ScopeDigest           string `json:"scope_digest"`
	PriorState            string `json:"prior_state"`
	PriorStateDigest      string `json:"prior_state_digest"`
	PlannedMutation       string `json:"planned_mutation"`
	PlannedMutationDigest string `json:"planned_mutation_digest"`
	Selector              string `json:"selector"`
	SelectorDigest        string `json:"selector_digest"`
	CleanupPolicy         string `json:"cleanup_policy"`
}

type LiveSideEffectPlan struct {
	SchemaVersion             string            `json:"schema_version"`
	RunID                     string            `json:"run_id"`
	AuthorizedHostFingerprint string            `json:"authorized_host_fingerprint"`
	CreatedAt                 time.Time         `json:"created_at"`
	Mutations                 []PlannedMutation `json:"mutations"`
}

type QualificationInstallManifest struct {
	SchemaVersion             string        `json:"schema_version"`
	RunID                     string        `json:"run_id"`
	ReleaseTag                string        `json:"release_tag"`
	CandidateBinary           AssetIdentity `json:"candidate_binary"`
	SourceArchive             AssetIdentity `json:"source_archive"`
	SBOM                      AssetIdentity `json:"sbom"`
	SourceTreeDigest          string        `json:"source_tree_digest"`
	DependencyManifestDigest  string        `json:"dependency_manifest_digest"`
	TargetProfileDigest       string        `json:"target_profile_digest"`
	AuthorizedHostFingerprint string        `json:"authorized_host_fingerprint"`
	SideEffectPlanDigest      string        `json:"side_effect_plan_digest"`
	JourneySpecDigest         string        `json:"journey_spec_digest"`
	PackageTemplateDigest     string        `json:"package_template_digest"`
	TailnetPeerDigest         string        `json:"tailnet_peer_digest,omitempty"`
	ExternalVantageDigest     string        `json:"external_vantage_digest"`
	ProtectedAuthorityDigest  string        `json:"protected_authority_digest"`
	ACMEAccountContact        string        `json:"acme_account_contact"`
	CreatedAt                 time.Time     `json:"created_at"`
}

type CleanupResult string

const (
	CleanupSubmitted CleanupResult = "submitted"
	CleanupExecuted  CleanupResult = "executed"
	CleanupCleaned   CleanupResult = "cleaned"
	CleanupRetained  CleanupResult = "retained"
)

type StepOutcome string

const (
	StepSubmitted StepOutcome = "submitted"
	StepPassed    StepOutcome = "passed"
	StepFailed    StepOutcome = "failed"
	StepUnknown   StepOutcome = "unknown"
)

type JourneyStepResult struct {
	MutationID     string      `json:"mutation_id"`
	AttemptID      string      `json:"attempt_id"`
	Outcome        StepOutcome `json:"outcome"`
	EvidenceDigest string      `json:"evidence_digest,omitempty"`
	ErrorDigest    string      `json:"error_digest,omitempty"`
}

type CleanupItem struct {
	MutationID       string        `json:"mutation_id"`
	ObservedIdentity string        `json:"observed_identity"`
	Result           CleanupResult `json:"result"`
}

type LiveCleanupReport struct {
	SchemaVersion                      string              `json:"schema_version"`
	RunID                              string              `json:"run_id"`
	SideEffectPlanDigest               string              `json:"side_effect_plan_digest"`
	QualificationInstallManifestDigest string              `json:"qualification_install_manifest_digest"`
	ProtectedInputDigest               string              `json:"protected_input_digest"`
	ExecutionFailed                    bool                `json:"execution_failed"`
	JourneySucceeded                   bool                `json:"journey_succeeded"`
	ExecutorAttestationDigest          string              `json:"executor_attestation_digest,omitempty"`
	UpdatedAt                          time.Time           `json:"updated_at"`
	Steps                              []JourneyStepResult `json:"steps"`
	Items                              []CleanupItem       `json:"items"`
}

type AttestedJourneyStep struct {
	MutationID     string `json:"mutation_id"`
	EvidenceDigest string `json:"evidence_digest"`
}

type LiveExecutorAttestation struct {
	SchemaVersion                      string                `json:"schema_version"`
	ExecutorIdentity                   string                `json:"executor_identity"`
	RunID                              string                `json:"run_id"`
	CandidateDigest                    string                `json:"candidate_digest"`
	TargetProfileDigest                string                `json:"target_profile_digest"`
	SideEffectPlanDigest               string                `json:"side_effect_plan_digest"`
	QualificationInstallManifestDigest string                `json:"qualification_install_manifest_digest"`
	ProtectedInputDigest               string                `json:"protected_input_digest"`
	TargetHostFingerprint              string                `json:"target_host_fingerprint"`
	ExternalVantageDigest              string                `json:"external_vantage_digest"`
	DNSProvider                        string                `json:"dns_provider"`
	DNSLiveTested                      bool                  `json:"dns_live_tested"`
	TailnetLiveStatus                  string                `json:"tailnet_live_status"`
	Steps                              []AttestedJourneyStep `json:"steps"`
	Cleanup                            []CleanupItem         `json:"cleanup"`
	CompletedAt                        time.Time             `json:"completed_at"`
}

func DecodeQualificationTargetProfile(data []byte) (QualificationTargetProfile, error) {
	var profile QualificationTargetProfile
	if err := DecodeCanonical(data, &profile); err != nil {
		return QualificationTargetProfile{}, err
	}
	if profile.SchemaVersion != QualificationTargetProfileSchemaVersion || !sameUTCSecond(profile.CapturedAt) || validateOSProfile(profile.Profile) != nil {
		return QualificationTargetProfile{}, fmt.Errorf("qualification target profile is invalid")
	}
	return profile, nil
}

func DecodeLiveSideEffectPlan(data []byte) (LiveSideEffectPlan, error) {
	var plan LiveSideEffectPlan
	if err := DecodeCanonical(data, &plan); err != nil {
		return LiveSideEffectPlan{}, err
	}
	if plan.SchemaVersion != LiveSideEffectPlanSchemaVersion || !refPattern.MatchString(plan.RunID) || !refPattern.MatchString(plan.AuthorizedHostFingerprint) || !sameUTCSecond(plan.CreatedAt) || len(plan.Mutations) == 0 || len(plan.Mutations) > 1024 {
		return LiveSideEffectPlan{}, fmt.Errorf("live side-effect plan is invalid")
	}
	previous := ""
	for _, mutation := range plan.Mutations {
		if !refPattern.MatchString(mutation.ID) || !validPlanText(mutation.Scope) || !validPlanText(mutation.PriorState) || !validPlanText(mutation.PlannedMutation) || !validPlanText(mutation.Selector) || mutation.ScopeDigest != DigestBytes([]byte(mutation.Scope)) || mutation.PriorStateDigest != DigestBytes([]byte(mutation.PriorState)) || mutation.PlannedMutationDigest != DigestBytes([]byte(mutation.PlannedMutation)) || mutation.SelectorDigest != DigestBytes([]byte(mutation.Selector)) || (mutation.CleanupPolicy != "delete_exact" && mutation.CleanupPolicy != "retain_authorized") || previous != "" && previous >= mutation.ID {
			return LiveSideEffectPlan{}, fmt.Errorf("live side-effect mutation inventory is invalid or noncanonical")
		}
		previous = mutation.ID
	}
	return plan, nil
}

func DecodeQualificationInstallManifest(data []byte) (QualificationInstallManifest, error) {
	var manifest QualificationInstallManifest
	if err := DecodeCanonical(data, &manifest); err != nil {
		return QualificationInstallManifest{}, err
	}
	if manifest.SchemaVersion != QualificationInstallManifestSchemaVersion || !refPattern.MatchString(manifest.RunID) || !releaseTagPattern.MatchString(manifest.ReleaseTag) || validateAsset(manifest.CandidateBinary) != nil || manifest.CandidateBinary.Path != "lanpanel" || validateAsset(manifest.SourceArchive) != nil || manifest.SourceArchive.Path != "lanpanel-"+manifest.ReleaseTag+".tar.gz" || validateAsset(manifest.SBOM) != nil || manifest.SBOM.Path != "lanpanel.spdx.json" || !ValidDigest(manifest.SourceTreeDigest) || !ValidDigest(manifest.DependencyManifestDigest) || !ValidDigest(manifest.TargetProfileDigest) || !refPattern.MatchString(manifest.AuthorizedHostFingerprint) || !ValidDigest(manifest.SideEffectPlanDigest) || !ValidDigest(manifest.JourneySpecDigest) || !ValidDigest(manifest.PackageTemplateDigest) || manifest.TailnetPeerDigest != "" && !ValidDigest(manifest.TailnetPeerDigest) || !ValidDigest(manifest.ExternalVantageDigest) || !ValidDigest(manifest.ProtectedAuthorityDigest) || !acmeaccount.ValidContact(manifest.ACMEAccountContact) || !sameUTCSecond(manifest.CreatedAt) {
		return QualificationInstallManifest{}, fmt.Errorf("qualification install manifest is invalid")
	}
	return manifest, nil
}

func DecodeLiveCleanupReport(data []byte) (LiveCleanupReport, error) {
	var report LiveCleanupReport
	if err := DecodeCanonical(data, &report); err != nil {
		return LiveCleanupReport{}, err
	}
	if report.SchemaVersion != LiveCleanupReportSchemaVersion || !refPattern.MatchString(report.RunID) || !ValidDigest(report.SideEffectPlanDigest) || !ValidDigest(report.QualificationInstallManifestDigest) || !ValidDigest(report.ProtectedInputDigest) || report.JourneySucceeded && (report.ExecutionFailed || !ValidDigest(report.ExecutorAttestationDigest)) || !report.JourneySucceeded && report.ExecutorAttestationDigest != "" || !sameUTCSecond(report.UpdatedAt) || len(report.Steps) == 0 || len(report.Steps) > 1024 || len(report.Items) == 0 || len(report.Items) > 1024 {
		return LiveCleanupReport{}, fmt.Errorf("live cleanup report is invalid")
	}
	previous := ""
	for _, step := range report.Steps {
		if !refPattern.MatchString(step.MutationID) || !refPattern.MatchString(step.AttemptID) || !validStepOutcome(step.Outcome) || previous != "" && previous >= step.MutationID {
			return LiveCleanupReport{}, fmt.Errorf("live cleanup report step inventory is invalid or noncanonical")
		}
		switch step.Outcome {
		case StepSubmitted:
			if step.EvidenceDigest != "" || step.ErrorDigest != "" {
				return LiveCleanupReport{}, fmt.Errorf("submitted live step carries terminal evidence")
			}
		case StepPassed:
			if !ValidDigest(step.EvidenceDigest) || step.ErrorDigest != "" {
				return LiveCleanupReport{}, fmt.Errorf("passed live step evidence is invalid")
			}
		case StepFailed, StepUnknown:
			if !ValidDigest(step.ErrorDigest) || step.EvidenceDigest != "" && !ValidDigest(step.EvidenceDigest) {
				return LiveCleanupReport{}, fmt.Errorf("failed live step evidence is invalid")
			}
		}
		previous = step.MutationID
	}
	previous = ""
	for _, item := range report.Items {
		if !refPattern.MatchString(item.MutationID) || !refPattern.MatchString(item.ObservedIdentity) || item.Result != CleanupSubmitted && item.Result != CleanupExecuted && item.Result != CleanupCleaned && item.Result != CleanupRetained || previous != "" && previous >= item.MutationID {
			return LiveCleanupReport{}, fmt.Errorf("live cleanup report inventory is invalid or noncanonical")
		}
		previous = item.MutationID
	}
	return report, nil
}

func DecodeLiveExecutorAttestation(data []byte) (LiveExecutorAttestation, error) {
	var value LiveExecutorAttestation
	if err := DecodeCanonical(data, &value); err != nil {
		return LiveExecutorAttestation{}, err
	}
	providers := []string{"cloudflare", "digitalocean", "gcloud", "route53", "tencentcloud"}
	if value.SchemaVersion != LiveExecutorAttestationSchemaVersion || value.ExecutorIdentity != "lanpanel-trusted-live-executor-v1" || !refPattern.MatchString(value.RunID) || !ValidDigest(value.CandidateDigest) || !ValidDigest(value.TargetProfileDigest) || !ValidDigest(value.SideEffectPlanDigest) || !ValidDigest(value.QualificationInstallManifestDigest) || !ValidDigest(value.ProtectedInputDigest) || !refPattern.MatchString(value.TargetHostFingerprint) || !ValidDigest(value.ExternalVantageDigest) || !slices.Contains(providers, value.DNSProvider) || !value.DNSLiveTested || value.TailnetLiveStatus != "live_tested" && value.TailnetLiveStatus != "not_live_tested" || !sameUTCSecond(value.CompletedAt) || len(value.Steps) == 0 || len(value.Steps) > 1024 || len(value.Cleanup) == 0 || len(value.Cleanup) > 1024 {
		return LiveExecutorAttestation{}, fmt.Errorf("live executor attestation is invalid")
	}
	previous := ""
	for _, step := range value.Steps {
		if !refPattern.MatchString(step.MutationID) || !ValidDigest(step.EvidenceDigest) || previous != "" && previous >= step.MutationID {
			return LiveExecutorAttestation{}, fmt.Errorf("live executor attestation step inventory is invalid")
		}
		previous = step.MutationID
	}
	previous = ""
	for _, item := range value.Cleanup {
		if !refPattern.MatchString(item.MutationID) || !refPattern.MatchString(item.ObservedIdentity) || item.Result != CleanupCleaned && item.Result != CleanupRetained || previous != "" && previous >= item.MutationID {
			return LiveExecutorAttestation{}, fmt.Errorf("live executor attestation cleanup inventory is invalid")
		}
		previous = item.MutationID
	}
	return value, nil
}

func VerifyLiveCleanup(planBytes, reportBytes, attestationBytes []byte, qualificationInstallManifestDigest, protectedInputDigest string) (LiveCleanupReport, LiveExecutorAttestation, error) {
	plan, err := DecodeLiveSideEffectPlan(planBytes)
	if err != nil {
		return LiveCleanupReport{}, LiveExecutorAttestation{}, err
	}
	report, err := DecodeLiveCleanupReport(reportBytes)
	if err != nil {
		return LiveCleanupReport{}, LiveExecutorAttestation{}, err
	}
	attestation, err := DecodeLiveExecutorAttestation(attestationBytes)
	if err != nil {
		return LiveCleanupReport{}, LiveExecutorAttestation{}, err
	}
	if !ValidDigest(qualificationInstallManifestDigest) || !ValidDigest(protectedInputDigest) || report.ExecutionFailed || report.ProtectedInputDigest != protectedInputDigest || report.RunID != plan.RunID || report.SideEffectPlanDigest != DigestBytes(planBytes) || report.QualificationInstallManifestDigest != qualificationInstallManifestDigest || !report.JourneySucceeded || report.ExecutorAttestationDigest != DigestBytes(attestationBytes) || report.UpdatedAt.Before(plan.CreatedAt) || len(report.Steps) != len(plan.Mutations) || len(report.Items) != len(plan.Mutations) {
		return LiveCleanupReport{}, LiveExecutorAttestation{}, fmt.Errorf("live cleanup report does not match immutable plan")
	}
	if attestation.RunID != report.RunID || attestation.SideEffectPlanDigest != report.SideEffectPlanDigest || attestation.QualificationInstallManifestDigest != report.QualificationInstallManifestDigest || attestation.ProtectedInputDigest != report.ProtectedInputDigest || len(attestation.Steps) != len(report.Steps) || !reflect.DeepEqual(attestation.Cleanup, report.Items) || attestation.CompletedAt.After(report.UpdatedAt) {
		return LiveCleanupReport{}, LiveExecutorAttestation{}, fmt.Errorf("live executor attestation does not match cleanup report")
	}
	for index, mutation := range plan.Mutations {
		step, attested, item := report.Steps[index], attestation.Steps[index], report.Items[index]
		if step.MutationID != mutation.ID || step.Outcome != StepPassed || attested.MutationID != mutation.ID || attested.EvidenceDigest != step.EvidenceDigest || item.MutationID != mutation.ID || item.Result != CleanupCleaned && item.Result != CleanupRetained || mutation.CleanupPolicy == "delete_exact" && item.Result != CleanupCleaned {
			return LiveCleanupReport{}, LiveExecutorAttestation{}, fmt.Errorf("live cleanup report is incomplete or violates cleanup policy")
		}
	}
	return report, attestation, nil
}

func validStepOutcome(value StepOutcome) bool {
	return value == StepSubmitted || value == StepPassed || value == StepFailed || value == StepUnknown
}

func validPlanText(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 4096 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func ValidateQualificationBinding(manifest QualificationInstallManifest, target QualificationTargetProfile, plan LiveSideEffectPlan, observedHost string) error {
	profileDigest, profileErr := ProfileDigest(target.Profile)
	planBytes, planErr := MarshalCanonical(plan)
	if profileErr != nil || planErr != nil || manifest.TargetProfileDigest != profileDigest || manifest.SideEffectPlanDigest != DigestBytes(planBytes) || manifest.RunID != plan.RunID || manifest.AuthorizedHostFingerprint != plan.AuthorizedHostFingerprint || manifest.AuthorizedHostFingerprint != observedHost || plan.CreatedAt.After(manifest.CreatedAt) {
		return fmt.Errorf("qualification install authority binding is invalid")
	}
	return nil
}

func cloneReleaseManifest(source ReleaseManifest) ReleaseManifest {
	copy := source
	copy.AdditionalAssets = append([]AssetIdentity(nil), source.AdditionalAssets...)
	copy.ProviderLiveTests = append([]ProviderLiveTest(nil), source.ProviderLiveTests...)
	copy.SupportedProfiles = append([]SupportedOSProfile(nil), source.SupportedProfiles...)
	copy.Headscale.RedirectAuthorities = append([]string(nil), source.Headscale.RedirectAuthorities...)
	copy.Headscale.Members = append([]ArchiveMemberAuthority(nil), source.Headscale.Members...)
	for index := range copy.SupportedProfiles {
		copy.SupportedProfiles[index].Profile.Packages = append([]PackageTuple(nil), source.SupportedProfiles[index].Profile.Packages...)
		copy.SupportedProfiles[index].Profile.ManagedConfinement.ProtectedDestinations = append([]string(nil), source.SupportedProfiles[index].Profile.ManagedConfinement.ProtectedDestinations...)
	}
	return copy
}

func sameUTCSecond(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

var (
	releaseTagPattern      = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	profileIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9.+_-]{0,127}$`)
	osReleasePattern       = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`)
	concreteVersionPattern = regexp.MustCompile(`^(?:v)?[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	refPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)
