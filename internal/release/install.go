package release

import (
	"fmt"
	"lanpanel/internal/packages"
	"reflect"
	"time"
)

// DependencyAuthority describes the exact helper assets used by Preview. It
// verifies bytes and versions needed to install and run the product; it is not
// a Preview dependency identity, not a release audit report.
type DependencyAuthority struct {
	SchemaVersion        string                     `json:"schema_version"`
	DependencyBaseline   AssetIdentity              `json:"dependency_baseline"`
	Headscale            HeadscaleArtifactAuthority `json:"headscale"`
	LegoVersion          string                     `json:"lego_version"`
	LegoArtifactIdentity string                     `json:"lego_artifact_identity"`
	LegoArchive          AssetIdentity              `json:"lego_archive"`
	LegoMembers          []ArchiveMemberAuthority   `json:"lego_members"`
	Lego                 AssetIdentity              `json:"lego"`
	Tailscale            ClientArtifactAuthority    `json:"tailscale"`
}

type InstallAuthority struct{ identity InstallIdentity }

type InstallIdentity struct {
	Kind                     InstallKind                `json:"kind"`
	ReleaseTag               string                     `json:"release_tag"`
	ReleaseManifestDigest    string                     `json:"release_manifest_digest,omitempty"`
	Binary                   AssetIdentity              `json:"binary"`
	Profile                  OSProfile                  `json:"profile"`
	ProfileDigest            string                     `json:"profile_digest"`
	HostFingerprint          string                     `json:"host_fingerprint"`
	AuthorityCreatedAt       time.Time                  `json:"authority_created_at"`
	DependencyBaseline       AssetIdentity              `json:"dependency_baseline"`
	DependencyManifestDigest string                     `json:"dependency_manifest_digest"`
	Headscale                HeadscaleArtifactAuthority `json:"headscale"`
	Lego                     AssetIdentity              `json:"lego"`
	Tailscale                AssetIdentity              `json:"tailscale"`
	TailscaleVersion         string                     `json:"tailscale_version"`
}

func (authority *InstallAuthority) Identity() InstallIdentity {
	if authority == nil {
		return InstallIdentity{}
	}
	return cloneInstallIdentity(authority.identity)
}

func BindResumeInstallAuthority(verified *InstallAuthority, persisted InstallIdentity) (*InstallAuthority, error) {
	if verified == nil || ValidateInstallIdentity(persisted) != nil {
		return nil, fmt.Errorf("resume install authority is invalid")
	}
	candidate := verified.Identity()
	candidate.AuthorityCreatedAt = persisted.AuthorityCreatedAt
	if !reflect.DeepEqual(candidate, persisted) {
		return nil, fmt.Errorf("resume install authority differs from verified immutable input")
	}
	return &InstallAuthority{identity: cloneInstallIdentity(persisted)}, nil
}

func RehydrateInstallAuthority(value InstallIdentity) (*InstallAuthority, error) {
	if err := ValidateInstallIdentity(value); err != nil {
		return nil, err
	}
	return &InstallAuthority{identity: cloneInstallIdentity(value)}, nil
}

type PublicInstallObservation struct {
	HostFingerprint string
	ObservedAt      time.Time
}

func VerifyPublicInstallAuthority(expectedReleaseManifestDigest string, releaseManifestBytes, checksumBytes []byte, assets map[string][]byte, observed PublicInstallObservation, detachedSignature []byte) (*InstallAuthority, error) {
	verified, err := VerifySignedRelease(expectedReleaseManifestDigest, releaseManifestBytes, detachedSignature, checksumBytes, assets)
	if err != nil {
		return nil, err
	}
	manifest := verified.value
	if observed.HostFingerprint == "" || observed.ObservedAt.IsZero() {
		return nil, fmt.Errorf("install host observation is missing")
	}
	profile := manifest.SupportedProfiles[0].Profile
	profileDigest, err := ProfileDigest(profile)
	if err != nil {
		return nil, err
	}
	dependencyBytes, ok := assets[manifest.DependencyManifest.Path]
	if !ok {
		return nil, fmt.Errorf("dependency manifest is missing")
	}
	dependencies, err := decodeDependencyAuthority(dependencyBytes, manifest.DependencyManifest.Digest)
	if err != nil {
		return nil, err
	}
	for _, asset := range []AssetIdentity{dependencies.DependencyBaseline, dependencies.LegoArchive, dependencies.Lego, dependencies.Tailscale.Archive} {
		data, present := assets[asset.Path]
		if !present || uint64(len(data)) != asset.Bytes || DigestBytes(data) != asset.Digest {
			return nil, fmt.Errorf("dependency asset %q is missing or mismatched", asset.Path)
		}
	}
	for _, member := range append(append([]ArchiveMemberAuthority(nil), dependencies.LegoMembers...), dependencies.Tailscale.Members...) {
		data, present := assets[member.Asset.Path]
		if !present || uint64(len(data)) != member.Asset.Bytes || DigestBytes(data) != member.Asset.Digest {
			return nil, fmt.Errorf("dependency member %q is missing or mismatched", member.Asset.Path)
		}
	}
	if !reflect.DeepEqual(manifest.Headscale, dependencies.Headscale) {
		return nil, fmt.Errorf("release and dependency Headscale authorities differ")
	}
	identity := InstallIdentity{
		Kind: InstallPublicRelease, ReleaseTag: manifest.ReleaseTag, ReleaseManifestDigest: verified.digest,
		Binary: manifest.Binary, Profile: profile, ProfileDigest: profileDigest, HostFingerprint: observed.HostFingerprint, AuthorityCreatedAt: observed.ObservedAt,
		DependencyBaseline: dependencies.DependencyBaseline, DependencyManifestDigest: manifest.DependencyManifest.Digest,
		Headscale: cloneHeadscaleAuthority(dependencies.Headscale), Lego: dependencies.Lego,
		Tailscale: findClientExecutable(dependencies.Tailscale), TailscaleVersion: dependencies.Tailscale.Version,
	}
	if err := ValidateInstallIdentity(identity); err != nil {
		return nil, err
	}
	return &InstallAuthority{identity: identity}, nil
}

func decodeDependencyAuthority(data []byte, expectedDigest string) (DependencyAuthority, error) {
	if !ValidDigest(expectedDigest) || DigestBytes(data) != expectedDigest {
		return DependencyAuthority{}, fmt.Errorf("dependency manifest digest changed")
	}
	var authority DependencyAuthority
	if err := DecodeCanonical(data, &authority); err != nil {
		return DependencyAuthority{}, err
	}
	if authority.SchemaVersion == "" || !concreteVersionPattern.MatchString(authority.LegoVersion) || !canonicalArtifactURL(authority.LegoArtifactIdentity) || validateAsset(authority.DependencyBaseline) != nil || authority.DependencyBaseline.Path != "dependency-baseline.json" || validateHeadscaleAuthority(authority.Headscale) != nil || validateAsset(authority.LegoArchive) != nil || authority.LegoArchive.Path != "lego.tar.gz" || validateAsset(authority.Lego) != nil || authority.Lego.Path != "lego" || len(authority.LegoMembers) != 1 || authority.LegoMembers[0].Path != "lego" || authority.LegoMembers[0].Destination != "/usr/lib/lanpanel/dependencies/lego" || authority.LegoMembers[0].Mode != 0o755 || authority.LegoMembers[0].Asset != authority.Lego || validateClientArtifactAuthority(authority.Tailscale, "tailscale", "/usr/lib/lanpanel/dependencies/tailscale") != nil || authority.Tailscale.Archive.Path != "tailscale.tar.gz" {
		return DependencyAuthority{}, fmt.Errorf("dependency manifest is invalid")
	}
	return authority, nil
}

func ValidateInstallIdentity(value InstallIdentity) error {
	if value.Kind != InstallPublicRelease || !releaseTagPattern.MatchString(value.ReleaseTag) || validateAsset(value.Binary) != nil || value.Binary.Path != "lanpanel" || !ValidDigest(value.ReleaseManifestDigest) || validateOSProfile(value.Profile) != nil || !ValidDigest(value.ProfileDigest) || value.HostFingerprint == "" || value.AuthorityCreatedAt.IsZero() || validateAsset(value.DependencyBaseline) != nil || !ValidDigest(value.DependencyManifestDigest) || validateHeadscaleAuthority(value.Headscale) != nil || validateAsset(value.Lego) != nil || value.Lego.Path != "lego" || validateAsset(value.Tailscale) != nil || value.Tailscale.Path != "tailscale" || value.TailscaleVersion == "" {
		return fmt.Errorf("installation release identity is invalid")
	}
	profileDigest, err := ProfileDigest(value.Profile)
	if err != nil || profileDigest != value.ProfileDigest {
		return fmt.Errorf("installation OS profile digest is mismatched")
	}
	return nil
}

func findClientExecutable(authority ClientArtifactAuthority) AssetIdentity {
	for _, member := range authority.Members {
		if member.Asset.Path == authority.ExecutableAsset {
			return member.Asset
		}
	}
	return AssetIdentity{}
}

func cloneHeadscaleAuthority(value HeadscaleArtifactAuthority) HeadscaleArtifactAuthority {
	value.RedirectAuthorities = append([]string(nil), value.RedirectAuthorities...)
	value.Members = append([]ArchiveMemberAuthority(nil), value.Members...)
	return value
}

func cloneInstallIdentity(value InstallIdentity) InstallIdentity {
	value.Headscale = cloneHeadscaleAuthority(value.Headscale)
	value.Profile.Packages = append([]PackageTuple(nil), value.Profile.Packages...)
	value.Profile.Repositories = cloneRepositories(value.Profile.Repositories)
	value.Profile.ManagedConfinement.ProtectedDestinations = append([]string(nil), value.Profile.ManagedConfinement.ProtectedDestinations...)
	return value
}

func cloneRepositories(values []packages.Repository) []packages.Repository {
	clone := append([]packages.Repository(nil), values...)
	for index := range clone {
		clone[index].Components = append([]string(nil), values[index].Components...)
	}
	return clone
}
