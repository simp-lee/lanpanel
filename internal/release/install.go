package release

import (
	"fmt"
	"lanpanel/internal/acmeaccount"
	"reflect"
	"time"
)

const QualificationDependencyAuthoritySchemaVersion = "lanpanel.qualification.dependency-authority.v1"

type QualificationDependencyAuthority struct {
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

type InstallAuthority struct {
	identity InstallIdentity
}

type InstallIdentity struct {
	Kind                               InstallKind                `json:"kind"`
	ReleaseTag                         string                     `json:"release_tag"`
	ReleaseManifestDigest              string                     `json:"release_manifest_digest,omitempty"`
	QualificationInstallManifestDigest string                     `json:"qualification_install_manifest_digest,omitempty"`
	SideEffectPlanDigest               string                     `json:"side_effect_plan_digest,omitempty"`
	RunID                              string                     `json:"run_id,omitempty"`
	ProtectedAuthorityDigest           string                     `json:"protected_authority_digest,omitempty"`
	ACMEAccountContact                 string                     `json:"acme_account_contact,omitempty"`
	Binary                             AssetIdentity              `json:"binary"`
	SourceTreeDigest                   string                     `json:"source_tree_digest"`
	Profile                            OSProfile                  `json:"profile"`
	ProfileDigest                      string                     `json:"profile_digest"`
	CandidateDigest                    string                     `json:"candidate_digest"`
	HostFingerprint                    string                     `json:"host_fingerprint"`
	AuthorityCreatedAt                 time.Time                  `json:"authority_created_at"`
	DependencyBaseline                 AssetIdentity              `json:"dependency_baseline"`
	DependencyManifestDigest           string                     `json:"dependency_manifest_digest"`
	Headscale                          HeadscaleArtifactAuthority `json:"headscale"`
	Lego                               AssetIdentity              `json:"lego"`
	Tailscale                          AssetIdentity              `json:"tailscale"`
	TailscaleVersion                   string                     `json:"tailscale_version"`
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

func VerifyPublicInstallAuthority(expectedReleaseManifestDigest string, releaseManifestBytes, checksumBytes []byte, assets map[string][]byte, observed PublicInstallObservation) (*InstallAuthority, error) {
	verified, err := VerifyRelease(expectedReleaseManifestDigest, releaseManifestBytes, checksumBytes, assets)
	if err != nil {
		return nil, err
	}
	if err := CheckSecurityGate(verified.security); err != nil {
		return nil, err
	}
	manifest := verified.value
	profile := manifest.SupportedProfiles[0].Profile
	if !refPattern.MatchString(observed.HostFingerprint) || !sameUTCSecond(observed.ObservedAt) {
		return nil, fmt.Errorf("os_profile_live_unqualified")
	}
	profileDigest, _ := ProfileDigest(profile)
	dependencies, err := decodeQualificationDependencyAuthority(assets[manifest.DependencyManifest.Path], manifest.DependencyManifest.Digest)
	if err != nil || !reflect.DeepEqual(dependencies.Headscale, manifest.Headscale) {
		return nil, fmt.Errorf("public dependency manifest authority is invalid")
	}
	identity := InstallIdentity{
		Kind: InstallPublicRelease, ReleaseTag: manifest.ReleaseTag, ReleaseManifestDigest: verified.digest,
		Binary: manifest.Binary, SourceTreeDigest: manifest.SourceTreeDigest, Profile: profile, ProfileDigest: profileDigest,
		CandidateDigest: manifest.Binary.Digest, HostFingerprint: observed.HostFingerprint, AuthorityCreatedAt: observed.ObservedAt,
		DependencyBaseline: dependencies.DependencyBaseline, DependencyManifestDigest: manifest.DependencyManifest.Digest,
		Headscale: cloneHeadscaleAuthority(dependencies.Headscale), Lego: dependencies.Lego, Tailscale: findClientExecutable(dependencies.Tailscale), TailscaleVersion: dependencies.Tailscale.Version,
	}
	if err := ValidateInstallIdentity(identity); err != nil {
		return nil, err
	}
	return &InstallAuthority{identity: identity}, nil
}

type QualificationInstallObservation struct {
	HostFingerprint string
	ObservedAt      time.Time
}

func VerifyQualificationInstallAuthority(expectedInstallManifestDigest string, installManifestBytes, targetProfileBytes, sideEffectPlanBytes, dependencyAuthorityBytes, candidateBinaryBytes []byte, assets map[string][]byte, observed QualificationInstallObservation) (*InstallAuthority, error) {
	if !ValidDigest(expectedInstallManifestDigest) || DigestBytes(installManifestBytes) != expectedInstallManifestDigest {
		return nil, fmt.Errorf("qualification install manifest differs from the selected digest")
	}
	manifest, err := DecodeQualificationInstallManifest(installManifestBytes)
	if err != nil {
		return nil, err
	}
	target, err := DecodeQualificationTargetProfile(targetProfileBytes)
	if err != nil {
		return nil, err
	}
	plan, err := DecodeLiveSideEffectPlan(sideEffectPlanBytes)
	if err != nil {
		return nil, err
	}
	if err := ValidateQualificationBinding(manifest, target, plan, observed.HostFingerprint); err != nil {
		return nil, err
	}
	if !sameUTCSecond(observed.ObservedAt) || observed.ObservedAt.Before(manifest.CreatedAt) || manifest.CandidateBinary.Digest != DigestBytes(candidateBinaryBytes) || manifest.CandidateBinary.Bytes != uint64(len(candidateBinaryBytes)) {
		return nil, fmt.Errorf("qualification candidate bytes or host observation changed")
	}
	dependencies, err := decodeQualificationDependencyAuthority(dependencyAuthorityBytes, manifest.DependencyManifestDigest)
	if err != nil {
		return nil, err
	}
	if err := verifyDependencyAuthority(dependencies, target.Profile, assets); err != nil {
		return nil, err
	}
	profileDigest, _ := ProfileDigest(target.Profile)
	identity := InstallIdentity{
		Kind: InstallQualification, ReleaseTag: manifest.ReleaseTag,
		QualificationInstallManifestDigest: expectedInstallManifestDigest, SideEffectPlanDigest: manifest.SideEffectPlanDigest, RunID: manifest.RunID, ProtectedAuthorityDigest: manifest.ProtectedAuthorityDigest, ACMEAccountContact: manifest.ACMEAccountContact,
		Binary: manifest.CandidateBinary, SourceTreeDigest: manifest.SourceTreeDigest, Profile: target.Profile, ProfileDigest: profileDigest,
		CandidateDigest: manifest.CandidateBinary.Digest, HostFingerprint: observed.HostFingerprint, AuthorityCreatedAt: manifest.CreatedAt,
		DependencyBaseline: dependencies.DependencyBaseline, DependencyManifestDigest: manifest.DependencyManifestDigest,
		Headscale: cloneHeadscaleAuthority(dependencies.Headscale), Lego: dependencies.Lego, Tailscale: findClientExecutable(dependencies.Tailscale), TailscaleVersion: dependencies.Tailscale.Version,
	}
	if err := ValidateInstallIdentity(identity); err != nil {
		return nil, err
	}
	return &InstallAuthority{identity: identity}, nil
}

func decodeQualificationDependencyAuthority(data []byte, expectedDigest string) (QualificationDependencyAuthority, error) {
	if !ValidDigest(expectedDigest) || DigestBytes(data) != expectedDigest {
		return QualificationDependencyAuthority{}, fmt.Errorf("dependency authority digest changed")
	}
	var authority QualificationDependencyAuthority
	if err := DecodeCanonical(data, &authority); err != nil {
		return QualificationDependencyAuthority{}, err
	}
	if authority.SchemaVersion != QualificationDependencyAuthoritySchemaVersion || validateAsset(authority.DependencyBaseline) != nil || validateHeadscaleAuthority(authority.Headscale) != nil || !concreteVersionPattern.MatchString(authority.LegoVersion) || !canonicalArtifactURL(authority.LegoArtifactIdentity) || validateAsset(authority.LegoArchive) != nil || authority.LegoArchive.Path != "lego.tar.gz" || len(authority.LegoMembers) == 0 || len(authority.LegoMembers) > 16 || validateAsset(authority.Lego) != nil || authority.Lego.Path != "lego" || validateClientArtifactAuthority(authority.Tailscale, "tailscale", "/usr/lib/lanpanel/dependencies/tailscale") != nil {
		return QualificationDependencyAuthority{}, fmt.Errorf("dependency authority is invalid")
	}
	previous := ""
	foundExecutable := false
	for _, member := range authority.LegoMembers {
		if validateAsset(member.Asset) != nil || previous != "" && previous >= member.Path || member.Mode != 0o644 && member.Mode != 0o755 {
			return QualificationDependencyAuthority{}, fmt.Errorf("lego archive member authority is invalid")
		}
		if member.Asset == authority.Lego {
			foundExecutable = member.Path == "lego" && member.Destination == "/usr/lib/lanpanel/dependencies/lego" && member.Mode == 0o755
		}
		previous = member.Path
	}
	if !foundExecutable {
		return QualificationDependencyAuthority{}, fmt.Errorf("lego executable member authority is missing")
	}
	return authority, nil
}

func ValidateInstallIdentity(value InstallIdentity) error {
	if value.Kind != InstallPublicRelease && value.Kind != InstallQualification || !releaseTagPattern.MatchString(value.ReleaseTag) || validateAsset(value.Binary) != nil || value.Binary.Path != "lanpanel" || !ValidDigest(value.SourceTreeDigest) || validateOSProfile(value.Profile) != nil || !ValidDigest(value.ProfileDigest) || value.CandidateDigest != value.Binary.Digest || !refPattern.MatchString(value.HostFingerprint) || !sameUTCSecond(value.AuthorityCreatedAt) || validateAsset(value.DependencyBaseline) != nil || !ValidDigest(value.DependencyManifestDigest) || validateHeadscaleAuthority(value.Headscale) != nil || validateAsset(value.Lego) != nil || value.Lego.Path != "lego" || validateAsset(value.Tailscale) != nil || value.Tailscale.Path != "tailscale" || !concreteVersionPattern.MatchString(value.TailscaleVersion) {
		return fmt.Errorf("installation release identity is invalid")
	}
	profileDigest, _ := ProfileDigest(value.Profile)
	if profileDigest != value.ProfileDigest {
		return fmt.Errorf("installation OS profile digest is mismatched")
	}
	if value.Kind == InstallPublicRelease {
		if !ValidDigest(value.ReleaseManifestDigest) || value.QualificationInstallManifestDigest != "" || value.SideEffectPlanDigest != "" || value.RunID != "" || value.ProtectedAuthorityDigest != "" || value.ACMEAccountContact != "" {
			return fmt.Errorf("public installation authority is incomplete or carries qualification fields")
		}
	} else if value.ReleaseManifestDigest != "" || !ValidDigest(value.QualificationInstallManifestDigest) || !ValidDigest(value.SideEffectPlanDigest) || !refPattern.MatchString(value.RunID) || !ValidDigest(value.ProtectedAuthorityDigest) || !acmeaccount.ValidContact(value.ACMEAccountContact) {
		return fmt.Errorf("qualification installation authority is incomplete or claims public release authority")
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
	value.Profile.ManagedConfinement.ProtectedDestinations = append([]string(nil), value.Profile.ManagedConfinement.ProtectedDestinations...)
	return value
}
