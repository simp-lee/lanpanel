package release

import (
	"fmt"
	"time"
)

// InstallAuthority is produced only after the complete candidate or public
// final install chain has been verified. Its fields are intentionally private
// so bootstrap cannot assemble partial release authority.
type InstallAuthority struct {
	kind                  EnvelopeKind
	releaseTag            string
	envelopeDigest        string
	manifestDigest        string
	binary                AssetIdentity
	sourceTreeDigest      string
	profile               OSProfile
	profileDigest         string
	capabilityDigest      string
	candidateDigest       string
	qualificationManifest string
	hostFingerprint       string
	caseID                string
	operation             string
	authorityCreatedAt    time.Time
	dependencyBaseline    AssetIdentity
	headscale             HeadscaleArtifactAuthority
	lego                  AssetIdentity
}

type InstallIdentity struct {
	Kind                  EnvelopeKind               `json:"kind"`
	ReleaseTag            string                     `json:"release_tag"`
	EnvelopeDigest        string                     `json:"envelope_digest"`
	ManifestDigest        string                     `json:"manifest_digest,omitempty"`
	Binary                AssetIdentity              `json:"binary"`
	SourceTreeDigest      string                     `json:"source_tree_digest"`
	Profile               OSProfile                  `json:"profile"`
	ProfileDigest         string                     `json:"profile_digest"`
	CapabilityDigest      string                     `json:"capability_digest"`
	CandidateDigest       string                     `json:"candidate_digest"`
	QualificationManifest string                     `json:"qualification_manifest_digest,omitempty"`
	HostFingerprint       string                     `json:"host_fingerprint"`
	CaseID                string                     `json:"case_id,omitempty"`
	Operation             string                     `json:"operation"`
	AuthorityCreatedAt    time.Time                  `json:"authority_created_at"`
	DependencyBaseline    AssetIdentity              `json:"dependency_baseline"`
	Headscale             HeadscaleArtifactAuthority `json:"headscale"`
	Lego                  AssetIdentity              `json:"lego"`
}

func (authority *InstallAuthority) Identity() InstallIdentity {
	if authority == nil {
		return InstallIdentity{}
	}
	return InstallIdentity{
		Kind: authority.kind, ReleaseTag: authority.releaseTag, EnvelopeDigest: authority.envelopeDigest,
		ManifestDigest: authority.manifestDigest, Binary: authority.binary, SourceTreeDigest: authority.sourceTreeDigest,
		Profile: authority.profile, ProfileDigest: authority.profileDigest, CapabilityDigest: authority.capabilityDigest,
		CandidateDigest: authority.candidateDigest, QualificationManifest: authority.qualificationManifest,
		HostFingerprint: authority.hostFingerprint, CaseID: authority.caseID, Operation: authority.operation,
		AuthorityCreatedAt: authority.authorityCreatedAt, DependencyBaseline: authority.dependencyBaseline,
		Headscale: cloneHeadscaleAuthority(authority.headscale), Lego: authority.lego,
	}
}

// RehydrateInstallAuthority accepts only an already persisted identity that was
// originally produced by one of the complete verification functions.
func RehydrateInstallAuthority(value InstallIdentity) (*InstallAuthority, error) {
	if err := ValidateInstallIdentity(value); err != nil {
		return nil, err
	}
	return &InstallAuthority{
		kind: value.Kind, releaseTag: value.ReleaseTag, envelopeDigest: value.EnvelopeDigest,
		manifestDigest: value.ManifestDigest, binary: value.Binary, sourceTreeDigest: value.SourceTreeDigest,
		profile: value.Profile, profileDigest: value.ProfileDigest, capabilityDigest: value.CapabilityDigest,
		candidateDigest: value.CandidateDigest, qualificationManifest: value.QualificationManifest,
		hostFingerprint: value.HostFingerprint, caseID: value.CaseID, operation: value.Operation,
		authorityCreatedAt: value.AuthorityCreatedAt, dependencyBaseline: value.DependencyBaseline,
		headscale: cloneHeadscaleAuthority(value.Headscale), lego: value.Lego,
	}, nil
}

// VerifyCandidateInstallAuthority verifies artifact bytes and the exact live
// qualification mutation scope as one indivisible authority.
func VerifyCandidateInstallAuthority(expectedEnvelopeDigest, expectedQualificationManifestDigest string, envelopeBytes, checksumBytes, qualificationManifestBytes []byte, assets map[string][]byte, observed QualificationObservation) (*InstallAuthority, error) {
	candidate, err := VerifyCandidateRelease(expectedEnvelopeDigest, envelopeBytes, checksumBytes, assets)
	if err != nil {
		return nil, err
	}
	manifest, err := DecodeQualificationManifest(qualificationManifestBytes, expectedQualificationManifestDigest)
	if err != nil {
		return nil, err
	}
	if err := AuthorizeCandidateInstall(candidate, manifest, observed); err != nil {
		return nil, err
	}
	if observed.Operation != "bootstrap_install" {
		return nil, fmt.Errorf("qualification candidate operation is not clean bootstrap")
	}
	value := candidate.envelope.value
	profile := *value.QualificationTarget
	profileDigest, _ := ProfileDigest(profile)
	capabilityBytes, err := MarshalCanonical(value.EdgeOne)
	if err != nil {
		return nil, err
	}
	return &InstallAuthority{
		kind: value.Kind, releaseTag: value.ReleaseTag, envelopeDigest: candidate.envelope.digest,
		binary: value.Binary, sourceTreeDigest: value.SourceTreeDigest, profile: profile, profileDigest: profileDigest,
		capabilityDigest: DigestBytes(capabilityBytes), candidateDigest: candidate.envelope.digest,
		qualificationManifest: manifest.digest, hostFingerprint: observed.HostFingerprint,
		caseID: observed.CaseID, operation: observed.Operation, authorityCreatedAt: manifest.value.CreatedAt,
		dependencyBaseline: value.DependencyBaseline, headscale: cloneHeadscaleAuthority(value.Headscale), lego: findAdditionalAsset(value, "lego"),
	}, nil
}

// VerifyFinalInstallAuthority verifies the selected public roots, every asset,
// the supported profile/capability, and the security gate before returning
// install authority.
func VerifyFinalInstallAuthority(expectedManifestDigest, expectedEnvelopeDigest string, manifestBytes, envelopeBytes, checksumBytes []byte, assets map[string][]byte, observed FinalInstallObservation) (*InstallAuthority, error) {
	final, err := VerifyFinalRelease(expectedManifestDigest, expectedEnvelopeDigest, manifestBytes, envelopeBytes, checksumBytes, assets)
	if err != nil {
		return nil, err
	}
	if err := AuthorizeFinalInstall(final, observed); err != nil {
		return nil, err
	}
	if err := CheckSecurityGate(final.security); err != nil {
		return nil, err
	}
	value := final.envelope.value
	profile := value.SupportedProfiles[0].Profile
	profileDigest, _ := ProfileDigest(profile)
	capabilityBytes, err := MarshalCanonical(value.EdgeOne)
	if err != nil {
		return nil, err
	}
	return &InstallAuthority{
		kind: value.Kind, releaseTag: value.ReleaseTag, envelopeDigest: final.envelope.digest,
		manifestDigest: final.manifest.digest, binary: value.Binary, sourceTreeDigest: value.SourceTreeDigest,
		profile: profile, profileDigest: profileDigest, capabilityDigest: DigestBytes(capabilityBytes),
		candidateDigest: value.QualificationCandidateOID, hostFingerprint: observed.HostFingerprint,
		operation: "bootstrap_install", authorityCreatedAt: final.security.ScannedAt,
		dependencyBaseline: value.DependencyBaseline, headscale: cloneHeadscaleAuthority(value.Headscale), lego: findAdditionalAsset(value, "lego"),
	}, nil
}

func cloneHeadscaleAuthority(value HeadscaleArtifactAuthority) HeadscaleArtifactAuthority {
	value.RedirectAuthorities = append([]string(nil), value.RedirectAuthorities...)
	value.Members = append([]ArchiveMemberAuthority(nil), value.Members...)
	return value
}

func findAdditionalAsset(value Envelope, path string) AssetIdentity {
	for _, asset := range value.AdditionalAssets {
		if asset.Path == path {
			return asset
		}
	}
	return AssetIdentity{}
}

func ValidateInstallIdentity(value InstallIdentity) error {
	if validateAsset(value.Lego) != nil || value.Lego.Path != "lego" {
		return fmt.Errorf("installation lego identity is invalid")
	}
	if validateAsset(value.DependencyBaseline) != nil || value.DependencyBaseline.Path != "dependency-baseline.json" || validateHeadscaleAuthorityShape(value.Headscale) != nil {
		return fmt.Errorf("installation dependency authority is invalid")
	}
	if value.Kind != EnvelopeQualificationCandidate && value.Kind != EnvelopeFinal || !releaseTagPattern.MatchString(value.ReleaseTag) || !ValidDigest(value.EnvelopeDigest) || value.Kind == EnvelopeFinal && !ValidDigest(value.ManifestDigest) || value.Kind == EnvelopeQualificationCandidate && value.ManifestDigest != "" || validateAsset(value.Binary) != nil || !ValidDigest(value.SourceTreeDigest) || validateOSProfile(value.Profile) != nil || !ValidDigest(value.ProfileDigest) || !ValidDigest(value.CapabilityDigest) || !ValidDigest(value.CandidateDigest) || !refPattern.MatchString(value.HostFingerprint) || value.Operation != "bootstrap_install" || !sameUTCSecond(value.AuthorityCreatedAt) {
		return fmt.Errorf("installation release identity is invalid")
	}
	profileDigest, _ := ProfileDigest(value.Profile)
	if profileDigest != value.ProfileDigest {
		return fmt.Errorf("installation OS profile digest is mismatched")
	}
	if value.Kind == EnvelopeQualificationCandidate {
		if !ValidDigest(value.QualificationManifest) || !refPattern.MatchString(value.CaseID) || value.CandidateDigest != value.EnvelopeDigest {
			return fmt.Errorf("candidate installation qualification identity is incomplete")
		}
	} else if value.QualificationManifest != "" || value.CaseID != "" {
		return fmt.Errorf("final installation carries candidate-only authority")
	}
	return nil
}
