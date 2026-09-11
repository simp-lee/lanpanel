package release

import (
	"crypto/ed25519"
	"fmt"
	"lanpanel/internal/packages"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const (
	ReleaseManifestSchemaVersion = "lanpanel.release.v3"
	ReleaseSignaturePath         = "release.json.sig"
	ReleaseSignatureBytes        = ed25519.SignatureSize
)

type InstallKind string

const (
	InstallPublicRelease InstallKind = "public_release"
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
	RepositoryID string `json:"repository_id,omitempty"`
}

type OSProfile struct {
	ID                    string                `json:"id"`
	Family                string                `json:"family"`
	Release               string                `json:"release"`
	Architecture          string                `json:"architecture"`
	SystemdVersion        string                `json:"systemd_version"`
	NginxVersion          string                `json:"nginx_version"`
	PackageSnapshotDigest string                `json:"package_snapshot_digest"`
	Repositories          []packages.Repository `json:"repositories"`
	Packages              []PackageTuple        `json:"packages"`
	ManagedConfinement    ConfinementProfile    `json:"managed_confinement"`
}

type ConfinementProfile struct {
	SchemaVersion         string   `json:"schema_version"`
	KernelRelease         string   `json:"kernel_release"`
	CgroupMode            string   `json:"cgroup_mode"`
	BindListenPolicy      string   `json:"bind_listen_policy"`
	ConnectPolicy         string   `json:"connect_policy"`
	FilesystemPolicy      string   `json:"filesystem_policy"`
	ProtectedDestinations []string `json:"protected_destinations"`
	PolicyDigest          string   `json:"policy_digest"`
}

type SupportedOSProfile struct {
	Profile OSProfile `json:"profile"`
}

type ReleaseManifest struct {
	SchemaVersion      string                     `json:"schema_version"`
	ReleaseTag         string                     `json:"release_tag"`
	Binary             AssetIdentity              `json:"binary"`
	SourceArchive      AssetIdentity              `json:"source_archive"`
	License            AssetIdentity              `json:"license"`
	Notice             AssetIdentity              `json:"notice"`
	DependencyManifest AssetIdentity              `json:"dependency_manifest"`
	Headscale          HeadscaleArtifactAuthority `json:"headscale"`
	KnownLimitations   AssetIdentity              `json:"known_limitations"`
	AdditionalAssets   []AssetIdentity            `json:"additional_assets"`
	Checksums          AssetIdentity              `json:"checksums"`
	SupportedProfiles  []SupportedOSProfile       `json:"supported_os_profiles"`
}

type VerifiedRelease struct {
	value  ReleaseManifest
	digest string
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

// trustedReleasePublicKey is supplied by the installer binary. It is
// deliberately not read from release material. Rotating it requires
// publishing a new authenticated installer.
var trustedReleasePublicKey = ed25519.PublicKey{
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
}

func TrustedReleasePublicKeyBytes() []byte {
	return append([]byte(nil), trustedReleasePublicKey...)
}

// VerifyRelease verifies the unsigned integrity portion of a release. Public
// installation must use VerifySignedRelease; this function remains useful to
// release tooling that has already authenticated the detached signature.
func VerifyRelease(expectedManifestDigest string, manifestBytes, checksumBytes []byte, assets map[string][]byte) (*VerifiedRelease, error) {
	return verifyRelease(expectedManifestDigest, manifestBytes, nil, checksumBytes, assets, false)
}

// VerifySignedRelease authenticates canonical release manifest bytes with the
// installer-trusted Ed25519 key and then verifies the complete inventory.
func VerifySignedRelease(expectedManifestDigest string, manifestBytes, signatureBytes, checksumBytes []byte, assets map[string][]byte) (*VerifiedRelease, error) {
	return verifyRelease(expectedManifestDigest, manifestBytes, signatureBytes, checksumBytes, assets, true)
}

func verifyRelease(expectedManifestDigest string, manifestBytes, signatureBytes, checksumBytes []byte, assets map[string][]byte, requireSignature bool) (*VerifiedRelease, error) {
	if !ValidDigest(expectedManifestDigest) || DigestBytes(manifestBytes) != expectedManifestDigest {
		return nil, fmt.Errorf("release manifest differs from selected digest")
	}
	if requireSignature {
		if len(signatureBytes) != ReleaseSignatureBytes || !ed25519.Verify(trustedReleasePublicKey, manifestBytes, signatureBytes) {
			return nil, fmt.Errorf("release manifest signature is invalid")
		}
	}
	var manifest ReleaseManifest
	if err := DecodeCanonical(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("release manifest is invalid: %w", err)
	}
	if err := validateReleaseManifest(manifest); err != nil {
		return nil, err
	}
	if err := verifyReleaseAssets(manifest, checksumBytes, assets, requireSignature); err != nil {
		return nil, err
	}
	return &VerifiedRelease{value: manifest, digest: expectedManifestDigest}, nil
}

func verifyReleaseAssets(manifest ReleaseManifest, checksumBytes []byte, assets map[string][]byte, requireSignature bool) error {
	if DigestBytes(checksumBytes) != manifest.Checksums.Digest || uint64(len(checksumBytes)) != manifest.Checksums.Bytes {
		return fmt.Errorf("release checksum file is invalid")
	}
	set, err := ParseChecksums(checksumBytes, releaseAssetPaths(manifest, requireSignature))
	if err != nil {
		return fmt.Errorf("release checksum inventory is invalid: %w", err)
	}
	if err := VerifyAssetBytes(set, assets); err != nil {
		return err
	}
	for _, asset := range mustReleaseAssets(manifest) {
		data, ok := assets[asset.Path]
		if !ok || uint64(len(data)) != asset.Bytes || DigestBytes(data) != asset.Digest {
			return fmt.Errorf("release asset %q is missing or mismatched", asset.Path)
		}
		if asset.Path == manifest.KnownLimitations.Path {
			if err := ValidateKnownLimitations(data); err != nil {
				return fmt.Errorf("known limitations asset is invalid: %w", err)
			}
		}
	}
	return nil
}

func releaseAssetPaths(manifest ReleaseManifest, requireSignature ...bool) []string {
	assets := mustReleaseAssets(manifest)
	paths := make([]string, 0, len(assets)+1)
	for _, asset := range assets {
		paths = append(paths, asset.Path)
	}
	if len(requireSignature) == 0 || requireSignature[0] {
		paths = append(paths, ReleaseSignaturePath)
	}
	return paths
}

func mustReleaseAssets(manifest ReleaseManifest) []AssetIdentity {
	assets := []AssetIdentity{manifest.Binary, manifest.SourceArchive, manifest.License, manifest.Notice, manifest.DependencyManifest, manifest.Headscale.Archive, manifest.KnownLimitations}
	for _, member := range manifest.Headscale.Members {
		assets = append(assets, member.Asset)
	}
	assets = append(assets, manifest.AdditionalAssets...)
	return assets
}

// InstallAssetPaths returns the complete public release asset inventory,
// including the checksum and manifest files supplied separately to the
// installer authority document.
func InstallAssetPaths(manifest ReleaseManifest) ([]string, error) {
	assets, err := releaseAssetInventory(manifest)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(assets)+2)
	for _, asset := range assets {
		if asset.Path != "release.json" && asset.Path != manifest.Checksums.Path {
			paths = append(paths, asset.Path)
		}
	}
	paths = append(paths, manifest.Checksums.Path, ReleaseSignaturePath, "release.json")
	slices.Sort(paths)
	return paths, nil
}

func releaseAssetInventory(manifest ReleaseManifest) ([]AssetIdentity, error) {
	assets := mustReleaseAssets(manifest)
	seen := map[string]bool{}
	for _, asset := range assets {
		if err := validateAsset(asset); err != nil || seen[asset.Path] || asset.Path == "release.json" || asset.Path == ReleaseSignaturePath || asset.Path == manifest.Checksums.Path {
			return nil, fmt.Errorf("release asset inventory is invalid")
		}
		seen[asset.Path] = true
	}
	return assets, nil
}

func validateReleaseManifest(manifest ReleaseManifest) error {
	if manifest.SchemaVersion != ReleaseManifestSchemaVersion || !releaseTagPattern.MatchString(manifest.ReleaseTag) || manifest.Binary.Path != "lanpanel" || manifest.SourceArchive.Path != "lanpanel-"+manifest.ReleaseTag+".tar.gz" || manifest.Checksums.Path != "SHA256SUMS" || validateAsset(manifest.Checksums) != nil || len(manifest.SupportedProfiles) != 1 {
		return fmt.Errorf("release manifest is incomplete")
	}
	if validateAsset(manifest.Binary) != nil || validateAsset(manifest.SourceArchive) != nil || validateAsset(manifest.License) != nil || validateAsset(manifest.Notice) != nil || validateAsset(manifest.DependencyManifest) != nil || validateAsset(manifest.KnownLimitations) != nil || validateHeadscaleAuthority(manifest.Headscale) != nil {
		return fmt.Errorf("release manifest asset authority is invalid")
	}
	requiredAdditional := map[string]bool{
		"package-template.json": false, "dependency-baseline.json": false,
		"lego.tar.gz": false, "lego": false, "tailscale.tar.gz": false, "tailscale": false,
	}
	seenAdditional := map[string]bool{}
	for _, asset := range manifest.AdditionalAssets {
		if validateAsset(asset) != nil || asset.Path == "release.json" || asset.Path == ReleaseSignaturePath || asset.Path == manifest.Checksums.Path || seenAdditional[asset.Path] {
			return fmt.Errorf("release manifest additional asset inventory is invalid")
		}
		seenAdditional[asset.Path] = true
		if _, required := requiredAdditional[asset.Path]; required {
			requiredAdditional[asset.Path] = true
		}
	}
	for assetPath, present := range requiredAdditional {
		if !present {
			return fmt.Errorf("release manifest required asset %q is missing", assetPath)
		}
	}
	profile := manifest.SupportedProfiles[0]
	if validateOSProfile(profile.Profile) != nil {
		return fmt.Errorf("release manifest OS profile is invalid")
	}
	return nil
}

func validateAsset(asset AssetIdentity) error {
	if !ValidRelativePath(asset.Path) || !ValidDigest(asset.Digest) || asset.Bytes == 0 || asset.Bytes > uint64(32<<20) {
		return fmt.Errorf("asset identity is incomplete or exceeds the installation size contract")
	}
	return nil
}

func validateHeadscaleAuthority(authority HeadscaleArtifactAuthority) error {
	if authority.Version != SupportedHeadscaleVersion || !concreteVersionPattern.MatchString(authority.Version) || authority.ArtifactIdentity == "" || authority.Archive.Path != "headscale.tar.gz" || validateAsset(authority.Archive) != nil || authority.ArchiveFormat != "tar_gzip" || authority.MaximumExtractedBytes == 0 || authority.MaximumExtractedBytes > 1<<30 || authority.InstallPath != "/usr/lib/lanpanel/dependencies/headscale" || !ValidRelativePath(authority.ExecutableAsset) || !refPattern.MatchString(authority.ConfigContract) || authority.ConfigContract != SupportedHeadscaleConfigContract || authority.ConfigContractDigest != SupportedHeadscaleConfigContractDigest() {
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
	if !concreteVersionPattern.MatchString(authority.Version) || !canonicalArtifactURL(authority.ArtifactIdentity) || validateAsset(authority.Archive) != nil || authority.ArchiveFormat != "tar_gzip" || authority.MaximumExtractedBytes == 0 || authority.MaximumExtractedBytes > 1<<30 || authority.ExecutableAsset != executable || authority.InstallPath != installPath || len(authority.Members) == 0 || len(authority.Members) > 16 {
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

func validateOSProfile(profile OSProfile) error {
	if !profileIDPattern.MatchString(profile.ID) || (profile.Family != "debian" && profile.Family != "ubuntu") || !osReleasePattern.MatchString(profile.Release) || profile.Architecture != "amd64" || !concreteVersionPattern.MatchString(profile.SystemdVersion) || !concreteVersionPattern.MatchString(profile.NginxVersion) || !ValidDigest(profile.PackageSnapshotDigest) {
		return fmt.Errorf("OS profile platform identity is invalid")
	}
	if packages.ValidateRepositories(profile.Repositories) != nil {
		return fmt.Errorf("OS profile repository configuration is invalid")
	}
	repositoryIDs := make(map[string]bool, len(profile.Repositories))
	for _, repository := range profile.Repositories {
		repositoryIDs[repository.ID] = true
	}
	if len(profile.Packages) == 0 || len(profile.Packages) > 4096 {
		return fmt.Errorf("OS profile exact package set is empty or unbounded")
	}
	for _, repository := range profile.Repositories {
		parsed, err := url.Parse(repository.URI)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != repository.URI {
			return fmt.Errorf("OS profile repository source is invalid")
		}
	}
	previous := ""
	for _, tuple := range profile.Packages {
		key := tuple.Name + "\x00" + tuple.Architecture
		if !profileIDPattern.MatchString(tuple.Name) || !concreteVersionPattern.MatchString(tuple.Version) || tuple.Architecture != "amd64" && tuple.Architecture != "all" || tuple.RepositoryID != "" && (!refPattern.MatchString(tuple.RepositoryID) || !repositoryIDs[tuple.RepositoryID]) || len(profile.Repositories) > 1 && tuple.RepositoryID == "" || previous != "" && previous >= key {
			return fmt.Errorf("OS profile package tuple is invalid, duplicated, or unsorted")
		}
		previous = key
	}
	return validateConfinementProfile(profile.ManagedConfinement)
}

func validateConfinementProfile(profile ConfinementProfile) error {
	if profile.SchemaVersion != "lanpanel.managed.confinement.v1" || profile.KernelRelease == "" || profile.CgroupMode != "unified_v2" || profile.BindListenPolicy != "systemd_bind_baseline_v1" || profile.ConnectPolicy != "systemd_cgroup_ip_deny_v1" || profile.FilesystemPolicy != "systemd_mount_namespace_v1" || !ValidDigest(profile.PolicyDigest) || len(profile.ProtectedDestinations) == 0 || len(profile.ProtectedDestinations) > 64 {
		return fmt.Errorf("managed confinement profile is incomplete")
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

func cloneReleaseManifest(source ReleaseManifest) ReleaseManifest {
	copy := source
	copy.AdditionalAssets = append([]AssetIdentity(nil), source.AdditionalAssets...)
	copy.SupportedProfiles = append([]SupportedOSProfile(nil), source.SupportedProfiles...)
	copy.Headscale.RedirectAuthorities = append([]string(nil), source.Headscale.RedirectAuthorities...)
	copy.Headscale.Members = append([]ArchiveMemberAuthority(nil), source.Headscale.Members...)
	for index := range copy.SupportedProfiles {
		copy.SupportedProfiles[index].Profile.Packages = append([]PackageTuple(nil), source.SupportedProfiles[index].Profile.Packages...)
		copy.SupportedProfiles[index].Profile.Repositories = cloneRepositories(source.SupportedProfiles[index].Profile.Repositories)
		copy.SupportedProfiles[index].Profile.ManagedConfinement.ProtectedDestinations = append([]string(nil), source.SupportedProfiles[index].Profile.ManagedConfinement.ProtectedDestinations...)
	}
	return copy
}

var (
	releaseTagPattern      = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	profileIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9.+_-]{0,127}$`)
	osReleasePattern       = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`)
	concreteVersionPattern = regexp.MustCompile(`^(?:v)?[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	refPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)
