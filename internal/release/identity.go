package release

import (
	"fmt"
	managedarchive "lanpanel/internal/archive"
	"lanpanel/internal/dependencies"
	"lanpanel/internal/filetxn"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	EnvelopeSchemaVersion              = "lanpanel.release.envelope.v1"
	ManifestSchemaVersion              = "lanpanel.release.manifest.v1"
	QualificationManifestSchemaVersion = "lanpanel.qualification.side-effects.v1"
)

type EnvelopeKind string

const (
	EnvelopeQualificationCandidate EnvelopeKind = "qualification_candidate"
	EnvelopeFinal                  EnvelopeKind = "final_release"
)

type AssetIdentity struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Bytes  uint64 `json:"bytes"`
}

type OSProfile struct {
	ID                    string             `json:"id"`
	Family                string             `json:"family"`
	Release               string             `json:"release"`
	Architecture          string             `json:"architecture"`
	SystemdVersion        string             `json:"systemd_version"`
	NginxVersion          string             `json:"nginx_version"`
	PackageSnapshotDigest string             `json:"package_snapshot_digest"`
	ManagedConfinement    ConfinementProfile `json:"managed_confinement"`
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

type QualificationStatus struct {
	Preflight string `json:"preflight_status"`
	Gate      string `json:"gate_status"`
	Live      string `json:"live_status"`
}

type QualifiedOSProfile struct {
	Profile            OSProfile           `json:"profile"`
	Status             QualificationStatus `json:"status"`
	CandidateDigest    string              `json:"candidate_digest"`
	ChecklistDigest    string              `json:"checklist_digest"`
	ChecklistItemID    string              `json:"checklist_item_id"`
	LiveEvidenceDigest string              `json:"live_evidence_digest"`
}

type EdgeOneVariant string

const (
	EdgeOneQualificationCandidate EdgeOneVariant = "edgeone_qualification_candidate"
	EdgeOneEnabled                EdgeOneVariant = "edgeone_enabled"
	EdgeOneDisabled               EdgeOneVariant = "edgeone_disabled"
)

type EdgeOneCapability struct {
	Variant                    EdgeOneVariant      `json:"variant"`
	Status                     QualificationStatus `json:"status"`
	Reason                     string              `json:"reason"`
	RunID                      string              `json:"run_id"`
	CandidateDigest            string              `json:"candidate_digest,omitempty"`
	ProfileDigest              string              `json:"profile_digest,omitempty"`
	ChecklistDigest            string              `json:"checklist_digest,omitempty"`
	ScopeKind                  string              `json:"scope_kind,omitempty"`
	ScopeDigest                string              `json:"scope_digest,omitempty"`
	RawProviderChecklistItemID string              `json:"raw_provider_checklist_item_id,omitempty"`
	RawProviderProofDigest     string              `json:"raw_provider_proof_digest,omitempty"`
	ProductChecklistItemID     string              `json:"product_checklist_item_id,omitempty"`
	ProductProofDigest         string              `json:"product_proof_digest,omitempty"`
	CleanupChecklistItemID     string              `json:"cleanup_checklist_item_id,omitempty"`
	CleanupEvidenceDigest      string              `json:"cleanup_evidence_digest,omitempty"`
}

type NetworkPolicy struct {
	TelemetryEnabled              bool     `json:"telemetry_enabled"`
	CommercialControlPlaneEnabled bool     `json:"commercial_control_plane_enabled"`
	ExternalPurposes              []string `json:"external_purposes"`
}

type Envelope struct {
	SchemaVersion             string               `json:"schema_version"`
	Kind                      EnvelopeKind         `json:"kind"`
	ReleaseTag                string               `json:"release_tag"`
	Binary                    AssetIdentity        `json:"binary"`
	SourceArchive             AssetIdentity        `json:"source_archive"`
	License                   AssetIdentity        `json:"license"`
	Notice                    AssetIdentity        `json:"notice"`
	SBOM                      AssetIdentity        `json:"sbom"`
	DependencyBaseline        AssetIdentity        `json:"dependency_baseline"`
	StableChecklist           AssetIdentity        `json:"stable_checklist"`
	SecurityReport            *AssetIdentity       `json:"security_report,omitempty"`
	AdditionalAssets          []AssetIdentity      `json:"additional_assets"`
	Checksums                 AssetIdentity        `json:"checksums"`
	SourceTreeDigest          string               `json:"source_tree_digest"`
	EdgeOne                   EdgeOneCapability    `json:"edgeone"`
	Network                   NetworkPolicy        `json:"network"`
	QualificationTarget       *OSProfile           `json:"qualification_target_os_profile,omitempty"`
	SupportedProfiles         []QualifiedOSProfile `json:"supported_os_profiles"`
	QualificationCandidateOID string               `json:"qualification_candidate_digest,omitempty"`
}

type Manifest struct {
	SchemaVersion    string          `json:"schema_version"`
	ReleaseTag       string          `json:"release_tag"`
	EnvelopeDigest   string          `json:"envelope_digest"`
	Checksums        AssetIdentity   `json:"checksums"`
	SourceTreeDigest string          `json:"source_tree_digest"`
	BinaryDigest     string          `json:"binary_digest"`
	CandidateDigest  string          `json:"qualification_candidate_digest"`
	Assets           []AssetIdentity `json:"assets"`
}

type VerifiedEnvelope struct {
	value  Envelope
	digest string
}

func (verified *VerifiedEnvelope) Value() Envelope {
	if verified == nil {
		return Envelope{}
	}
	return cloneEnvelope(verified.value)
}
func (verified *VerifiedEnvelope) Digest() string {
	if verified == nil {
		return ""
	}
	return verified.digest
}

type VerifiedManifest struct {
	value  Manifest
	digest string
}

func (verified *VerifiedManifest) Value() Manifest {
	if verified == nil {
		return Manifest{}
	}
	value := verified.value
	value.Assets = append([]AssetIdentity(nil), value.Assets...)
	return value
}
func (verified *VerifiedManifest) Digest() string {
	if verified == nil {
		return ""
	}
	return verified.digest
}

type VerifiedCandidateRelease struct {
	envelope *VerifiedEnvelope
}

func (verified *VerifiedCandidateRelease) Envelope() Envelope {
	if verified == nil || verified.envelope == nil {
		return Envelope{}
	}
	return cloneEnvelope(verified.envelope.value)
}

type VerifiedFinalRelease struct {
	envelope *VerifiedEnvelope
	manifest *VerifiedManifest
	security SecurityReport
}

type VerifiedFinalizedRelease struct {
	final *VerifiedFinalRelease
}

func (verified *VerifiedFinalRelease) Envelope() Envelope {
	if verified == nil || verified.envelope == nil {
		return Envelope{}
	}
	return cloneEnvelope(verified.envelope.value)
}
func (verified *VerifiedFinalRelease) ManifestDigest() string {
	if verified == nil || verified.manifest == nil {
		return ""
	}
	return verified.manifest.digest
}

func cloneEnvelope(source Envelope) Envelope {
	cloned := source
	cloned.AdditionalAssets = append([]AssetIdentity(nil), source.AdditionalAssets...)
	cloned.SupportedProfiles = append([]QualifiedOSProfile(nil), source.SupportedProfiles...)
	cloned.Network.ExternalPurposes = append([]string(nil), source.Network.ExternalPurposes...)
	if source.SecurityReport != nil {
		security := *source.SecurityReport
		cloned.SecurityReport = &security
	}
	if source.QualificationTarget != nil {
		profile := *source.QualificationTarget
		cloned.QualificationTarget = &profile
	}
	return cloned
}

var (
	releaseTagPattern      = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	profileIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	osReleasePattern       = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`)
	concreteVersionPattern = regexp.MustCompile(`^(?:v)?[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	refPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

func DecodeEnvelope(data []byte) (*VerifiedEnvelope, error) {
	var envelope Envelope
	if err := DecodeCanonical(data, &envelope); err != nil {
		return nil, err
	}
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	return &VerifiedEnvelope{value: envelope, digest: DigestBytes(data)}, nil
}

func DecodeManifest(data []byte) (*VerifiedManifest, error) {
	var manifest Manifest
	if err := DecodeCanonical(data, &manifest); err != nil {
		return nil, err
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	return &VerifiedManifest{value: manifest, digest: DigestBytes(data)}, nil
}

func VerifyCandidateRelease(expectedEnvelopeDigest string, envelopeBytes, checksumBytes []byte, assets map[string][]byte) (*VerifiedCandidateRelease, error) {
	if !ValidDigest(expectedEnvelopeDigest) || DigestBytes(envelopeBytes) != expectedEnvelopeDigest {
		return nil, fmt.Errorf("candidate envelope differs from its selected digest")
	}
	envelope, err := DecodeEnvelope(envelopeBytes)
	if err != nil || envelope.value.Kind != EnvelopeQualificationCandidate {
		return nil, fmt.Errorf("qualification candidate envelope is invalid")
	}
	if err := verifyEnvelopeAssets(envelope.value, checksumBytes, assets); err != nil {
		return nil, err
	}
	return &VerifiedCandidateRelease{envelope: envelope}, nil
}

func VerifyFinalRelease(expectedManifestDigest, expectedEnvelopeDigest string, manifestBytes, envelopeBytes, checksumBytes []byte, assets map[string][]byte) (*VerifiedFinalRelease, error) {
	if !ValidDigest(expectedManifestDigest) || !ValidDigest(expectedEnvelopeDigest) || DigestBytes(manifestBytes) != expectedManifestDigest || DigestBytes(envelopeBytes) != expectedEnvelopeDigest {
		return nil, fmt.Errorf("final release differs from administrator-selected root digests")
	}
	envelope, err := DecodeEnvelope(envelopeBytes)
	if err != nil || envelope.value.Kind != EnvelopeFinal {
		return nil, fmt.Errorf("final release envelope is invalid")
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := VerifyManifest(manifest, envelope); err != nil {
		return nil, err
	}
	if err := verifyEnvelopeAssets(envelope.value, checksumBytes, assets); err != nil {
		return nil, err
	}
	if envelope.value.SecurityReport == nil {
		return nil, fmt.Errorf("final release omits its security report identity")
	}
	securityBytes, present := assets[envelope.value.SecurityReport.Path]
	if !present {
		return nil, fmt.Errorf("final release security report asset is missing")
	}
	security, err := DecodeSecurityReport(securityBytes)
	if err != nil || security.CandidateDigest != envelope.value.QualificationCandidateOID {
		return nil, fmt.Errorf("security report is invalid or bound to another candidate")
	}
	return &VerifiedFinalRelease{envelope: envelope, manifest: manifest, security: security}, nil
}

func VerifyManifest(manifest *VerifiedManifest, envelope *VerifiedEnvelope) error {
	if manifest == nil || envelope == nil || envelope.value.Kind != EnvelopeFinal {
		return fmt.Errorf("final manifest and envelope are not verified")
	}
	expectedAssets, err := envelopeAssetInventory(envelope.value)
	if err != nil {
		return err
	}
	value := manifest.value
	if value.ReleaseTag != envelope.value.ReleaseTag || value.EnvelopeDigest != envelope.digest || value.Checksums != envelope.value.Checksums || value.SourceTreeDigest != envelope.value.SourceTreeDigest || value.BinaryDigest != envelope.value.Binary.Digest || value.CandidateDigest != envelope.value.QualificationCandidateOID || !reflect.DeepEqual(value.Assets, expectedAssets) {
		return fmt.Errorf("final manifest does not bind the exact envelope and asset identities")
	}
	return nil
}

func verifyEnvelopeAssets(envelope Envelope, checksumBytes []byte, assets map[string][]byte) error {
	if DigestBytes(checksumBytes) != envelope.Checksums.Digest || uint64(len(checksumBytes)) != envelope.Checksums.Bytes {
		return fmt.Errorf("checksum file does not match the envelope")
	}
	identities, err := envelopeAssetInventory(envelope)
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
	if err := VerifyAssetBytes(checksums, assets); err != nil {
		return err
	}
	for assetPath, data := range assets {
		identity := byPath[assetPath]
		if uint64(len(data)) != identity.Bytes || DigestBytes(data) != identity.Digest {
			return fmt.Errorf("asset %q size or digest differs from the envelope", assetPath)
		}
	}
	baselineBytes, present := assets[envelope.DependencyBaseline.Path]
	if !present {
		return fmt.Errorf("dependency baseline asset is missing")
	}
	baseline, err := dependencies.DecodeBaseline(baselineBytes)
	if err != nil {
		return fmt.Errorf("dependency baseline asset is invalid: %w", err)
	}
	var profile OSProfile
	if envelope.Kind == EnvelopeQualificationCandidate && envelope.QualificationTarget != nil {
		profile = *envelope.QualificationTarget
	} else if envelope.Kind == EnvelopeFinal && len(envelope.SupportedProfiles) == 1 {
		profile = envelope.SupportedProfiles[0].Profile
	} else {
		return fmt.Errorf("release envelope lacks one exact dependency OS profile")
	}
	profileDigest, err := ProfileDigest(profile)
	if err != nil || dependencies.ValidateForOSProfile(baseline, profileDigest, profile.NginxVersion) != nil {
		return fmt.Errorf("dependency baseline does not bind the exact release OS profile")
	}
	var selected *dependencies.Selection
	for index := range baseline.Selections {
		if baseline.Selections[index].Component == "lego" {
			selected = &baseline.Selections[index]
		}
	}
	var legoArchive, lego *AssetIdentity
	for index := range envelope.AdditionalAssets {
		asset := &envelope.AdditionalAssets[index]
		if asset.Path == "lego.tar.gz" {
			legoArchive = asset
		} else if asset.Path == "lego" {
			lego = asset
		}
	}
	expectedLegoArtifact := fmt.Sprintf("https://github.com/go-acme/lego/releases/download/v4.25.2/lego_v4.25.2_linux_%s.tar.gz", profile.Architecture)
	if selected == nil || legoArchive == nil || lego == nil || selected.SourceKind != dependencies.SourceCanonicalArtifact || selected.SelectedVersion != "4.25.2" || selected.LatestStableVersion != "4.25.2" || selected.OperatingSystem != "linux" || selected.Architecture != profile.Architecture || selected.ArtifactIdentity != expectedLegoArtifact || selected.ArtifactDigest != legoArchive.Digest {
		return fmt.Errorf("lego archive does not match canonical v4.25.2 dependency authority")
	}
	archiveBytes, archivePresent := assets[legoArchive.Path]
	executableBytes, executablePresent := assets[lego.Path]
	if !archivePresent || !executablePresent {
		return fmt.Errorf("lego archive or executable bytes missing")
	}
	extracted, err := managedarchive.Extract(archiveBytes, managedarchive.Spec{Format: managedarchive.TarGzip, MaximumArchiveBytes: 256 << 20, MaximumExtractedBytes: 258 << 20, MaximumMembers: 3, Members: []managedarchive.Member{{Path: "CHANGELOG.md", MaximumBytes: 1 << 20, MaximumPhysicalBytes: 256 << 20, Destination: "/usr/share/doc/lanpanel/lego/CHANGELOG.md", Metadata: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o644}}, {Path: "LICENSE", MaximumBytes: 1 << 20, MaximumPhysicalBytes: 256 << 20, Destination: "/usr/share/doc/lanpanel/lego/LICENSE", Metadata: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o644}}, {Path: "lego", MaximumBytes: 256 << 20, MaximumPhysicalBytes: 256 << 20, Destination: "/usr/lib/lanpanel/dependencies/lego", Metadata: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o755}}}})
	if err != nil {
		return fmt.Errorf("extract lego executable: %w", err)
	}
	if !executablePresent || DigestBytes(extracted["lego"]) != lego.Digest || !slices.Equal(extracted["lego"], executableBytes) {
		return fmt.Errorf("lego executable is not the exact archive member")
	}
	return nil
}

func VerifyFinalization(final *VerifiedFinalRelease, candidate *VerifiedCandidateRelease) (*VerifiedFinalizedRelease, error) {
	if final == nil || candidate == nil {
		return nil, fmt.Errorf("finalization lacks verified final or candidate release")
	}
	if err := VerifyFinalFromCandidate(final.envelope, candidate.envelope); err != nil {
		return nil, err
	}
	return &VerifiedFinalizedRelease{final: final}, nil
}

func VerifyFinalFromCandidate(final, candidate *VerifiedEnvelope) error {
	if final == nil || candidate == nil || final.value.Kind != EnvelopeFinal || candidate.value.Kind != EnvelopeQualificationCandidate {
		return fmt.Errorf("candidate/final envelope kinds are invalid")
	}
	if final.value.QualificationCandidateOID != candidate.digest || final.value.ReleaseTag != candidate.value.ReleaseTag || final.value.Binary != candidate.value.Binary || final.value.SourceArchive != candidate.value.SourceArchive || final.value.SourceTreeDigest != candidate.value.SourceTreeDigest || final.value.DependencyBaseline != candidate.value.DependencyBaseline || final.value.SBOM != candidate.value.SBOM || final.value.License != candidate.value.License || final.value.Notice != candidate.value.Notice || !reflect.DeepEqual(final.value.AdditionalAssets, candidate.value.AdditionalAssets) {
		return fmt.Errorf("final envelope does not wrap unchanged candidate source, binary, and baseline")
	}
	if len(final.value.SupportedProfiles) != 1 || candidate.value.QualificationTarget == nil || !reflect.DeepEqual(final.value.SupportedProfiles[0].Profile, *candidate.value.QualificationTarget) {
		return fmt.Errorf("final supported profile was not the candidate qualification target")
	}
	if final.value.EdgeOne.RunID != candidate.value.EdgeOne.RunID {
		return fmt.Errorf("final EdgeOne result belongs to another qualification run")
	}
	if final.value.EdgeOne.Variant == EdgeOneEnabled && (final.value.EdgeOne.ScopeKind != candidate.value.EdgeOne.ScopeKind || final.value.EdgeOne.ScopeDigest != candidate.value.EdgeOne.ScopeDigest) {
		return fmt.Errorf("enabled EdgeOne result differs from the candidate prebound scope")
	}
	return nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.SchemaVersion != EnvelopeSchemaVersion || !releaseTagPattern.MatchString(envelope.ReleaseTag) || !ValidDigest(envelope.SourceTreeDigest) {
		return fmt.Errorf("release envelope identity is invalid")
	}
	if err := validateAsset(envelope.Checksums); err != nil {
		return fmt.Errorf("checksums identity: %w", err)
	}
	if _, err := envelopeAssetInventory(envelope); err != nil {
		return err
	}
	if err := validateNetworkPolicy(envelope.Network); err != nil {
		return err
	}
	switch envelope.Kind {
	case EnvelopeQualificationCandidate:
		if envelope.QualificationTarget == nil || len(envelope.SupportedProfiles) != 0 || envelope.QualificationCandidateOID != "" || envelope.SecurityReport != nil {
			return fmt.Errorf("qualification candidate profile or security authority is invalid")
		}
		if err := validateOSProfile(*envelope.QualificationTarget); err != nil {
			return err
		}
		if envelope.EdgeOne.Variant != EdgeOneQualificationCandidate {
			return fmt.Errorf("candidate EdgeOne capability is not prebound")
		}
	case EnvelopeFinal:
		if envelope.QualificationTarget != nil || len(envelope.SupportedProfiles) != 1 || !ValidDigest(envelope.QualificationCandidateOID) || envelope.SecurityReport == nil {
			return fmt.Errorf("final release profile, candidate, or security authority is invalid")
		}
		previous := ""
		for _, qualified := range envelope.SupportedProfiles {
			if err := validateQualifiedProfile(qualified, envelope); err != nil || previous != "" && strings.Compare(previous, qualified.Profile.ID) >= 0 {
				return fmt.Errorf("supported OS profiles are invalid, unqualified, duplicated, or unsorted")
			}
			previous = qualified.Profile.ID
		}
		if envelope.EdgeOne.Variant != EdgeOneEnabled && envelope.EdgeOne.Variant != EdgeOneDisabled {
			return fmt.Errorf("final EdgeOne capability variant is invalid")
		}
	default:
		return fmt.Errorf("release envelope kind is unknown")
	}
	return validateEdgeOneCapability(envelope)
}

func envelopeAssetInventory(envelope Envelope) ([]AssetIdentity, error) {
	previousAdditional := ""
	for _, asset := range envelope.AdditionalAssets {
		if previousAdditional != "" && strings.Compare(previousAdditional, asset.Path) >= 0 {
			return nil, fmt.Errorf("additional release assets are duplicated or unsorted")
		}
		previousAdditional = asset.Path
	}
	assets := []AssetIdentity{envelope.Binary, envelope.SourceArchive, envelope.License, envelope.Notice, envelope.SBOM, envelope.DependencyBaseline, envelope.StableChecklist}
	if envelope.SecurityReport != nil {
		assets = append(assets, *envelope.SecurityReport)
	}
	assets = append(assets, envelope.AdditionalAssets...)
	slices.SortFunc(assets, func(left, right AssetIdentity) int { return strings.Compare(left.Path, right.Path) })
	previous := ""
	for _, asset := range assets {
		if err := validateAsset(asset); err != nil || previous != "" && asset.Path == previous || asset.Path == envelope.Checksums.Path {
			return nil, fmt.Errorf("release asset inventory is invalid or duplicated")
		}
		previous = asset.Path
	}
	return assets, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchemaVersion || !releaseTagPattern.MatchString(manifest.ReleaseTag) || !ValidDigest(manifest.EnvelopeDigest) || !ValidDigest(manifest.SourceTreeDigest) || !ValidDigest(manifest.BinaryDigest) || !ValidDigest(manifest.CandidateDigest) {
		return fmt.Errorf("final release manifest identity is invalid")
	}
	if err := validateAsset(manifest.Checksums); err != nil {
		return err
	}
	previous := ""
	for _, asset := range manifest.Assets {
		if err := validateAsset(asset); err != nil || previous != "" && strings.Compare(previous, asset.Path) >= 0 || asset.Path == manifest.Checksums.Path {
			return fmt.Errorf("final manifest asset inventory is invalid, duplicated, or unsorted")
		}
		previous = asset.Path
	}
	if len(manifest.Assets) == 0 {
		return fmt.Errorf("final manifest asset inventory is empty")
	}
	return nil
}

func validateAsset(asset AssetIdentity) error {
	if !ValidRelativePath(asset.Path) || !ValidDigest(asset.Digest) || asset.Bytes == 0 {
		return fmt.Errorf("asset path, digest, or byte size is invalid")
	}
	return nil
}

func validateOSProfile(profile OSProfile) error {
	if !profileIDPattern.MatchString(profile.ID) || (profile.Family != "debian" && profile.Family != "ubuntu") || !osReleasePattern.MatchString(profile.Release) || profile.Architecture != "amd64" || !concreteVersionPattern.MatchString(profile.SystemdVersion) || !concreteVersionPattern.MatchString(profile.NginxVersion) || !ValidDigest(profile.PackageSnapshotDigest) || validateConfinementProfile(profile.ManagedConfinement) != nil {
		return fmt.Errorf("OS profile is not an exact Debian/Ubuntu amd64 identity with qualified managed-process confinement")
	}
	return nil
}

func validateConfinementProfile(profile ConfinementProfile) error {
	if profile.SchemaVersion != "lanpanel.managed.confinement.v1" || !concreteVersionPattern.MatchString(profile.KernelRelease) || profile.CgroupMode != "unified_v2" || profile.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" || profile.ConnectPolicy != "systemd_cgroup_ip_deny_v1" || profile.FilesystemPolicy != "systemd_mount_namespace_v1" || !ValidDigest(profile.QualificationDigest) || len(profile.ProtectedDestinations) == 0 || len(profile.ProtectedDestinations) > 64 {
		return fmt.Errorf("managed-process confinement profile is unqualified")
	}
	previous := ""
	for _, destination := range profile.ProtectedDestinations {
		if destination == "" || strings.ContainsAny(destination, "\x00\r\n") || previous != "" && strings.Compare(previous, destination) >= 0 {
			return fmt.Errorf("managed-process protected destinations are noncanonical")
		}
		previous = destination
	}
	return nil
}

func validateQualifiedProfile(qualified QualifiedOSProfile, envelope Envelope) error {
	if err := validateOSProfile(qualified.Profile); err != nil || qualified.Status != (QualificationStatus{Preflight: "eligible", Gate: "passed", Live: "live_qualified"}) || qualified.CandidateDigest != envelope.QualificationCandidateOID || qualified.ChecklistDigest != envelope.StableChecklist.Digest || !refPattern.MatchString(qualified.ChecklistItemID) || !ValidDigest(qualified.LiveEvidenceDigest) {
		return fmt.Errorf("supported OS profile lacks exact live-qualified candidate evidence")
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

func validateEdgeOneCapability(envelope Envelope) error {
	capability := envelope.EdgeOne
	if !validQualificationStatus(capability.Status) || !refPattern.MatchString(capability.Reason) || !refPattern.MatchString(capability.RunID) {
		return fmt.Errorf("EdgeOne capability status, reason, or run is invalid")
	}
	switch capability.Variant {
	case EdgeOneQualificationCandidate:
		if envelope.Kind != EnvelopeQualificationCandidate || capability.Status != (QualificationStatus{Preflight: "not_applicable", Gate: "passed", Live: "not_applicable"}) || (capability.ScopeKind != "exact_zone" && capability.ScopeKind != "provider_contract") || !ValidDigest(capability.ScopeDigest) || capability.CandidateDigest != "" || capability.ProfileDigest != "" || capability.ChecklistDigest != "" || hasEdgeOneProof(capability) {
			return fmt.Errorf("EdgeOne candidate scope is invalid")
		}
	case EdgeOneEnabled:
		profileDigest, err := ProfileDigest(envelope.SupportedProfiles[0].Profile)
		if envelope.Kind != EnvelopeFinal || err != nil || capability.Status != (QualificationStatus{Preflight: "eligible", Gate: "passed", Live: "live_qualified"}) || capability.CandidateDigest != envelope.QualificationCandidateOID || capability.ProfileDigest != profileDigest || capability.ChecklistDigest != envelope.StableChecklist.Digest || (capability.ScopeKind != "exact_zone" && capability.ScopeKind != "provider_contract") || !ValidDigest(capability.ScopeDigest) || !refPattern.MatchString(capability.RawProviderChecklistItemID) || !ValidDigest(capability.RawProviderProofDigest) || !refPattern.MatchString(capability.ProductChecklistItemID) || !ValidDigest(capability.ProductProofDigest) || !refPattern.MatchString(capability.CleanupChecklistItemID) || !ValidDigest(capability.CleanupEvidenceDigest) {
			return fmt.Errorf("enabled EdgeOne capability lacks exact candidate/run/profile/checklist proof")
		}
	case EdgeOneDisabled:
		profileDigest, err := ProfileDigest(envelope.SupportedProfiles[0].Profile)
		allowedStatus := capability.Status == (QualificationStatus{Preflight: "ineligible", Gate: "deferred", Live: "live_unqualified"}) || capability.Status == (QualificationStatus{Preflight: "eligible", Gate: "deferred", Live: "live_unqualified"})
		if envelope.Kind != EnvelopeFinal || err != nil || !allowedStatus || capability.CandidateDigest != envelope.QualificationCandidateOID || capability.ProfileDigest != profileDigest || capability.ChecklistDigest != envelope.StableChecklist.Digest || capability.ScopeKind != "" || capability.ScopeDigest != "" || capability.RawProviderChecklistItemID != "" || capability.RawProviderProofDigest != "" || capability.ProductChecklistItemID != "" || capability.ProductProofDigest != "" || !refPattern.MatchString(capability.CleanupChecklistItemID) || !ValidDigest(capability.CleanupEvidenceDigest) {
			return fmt.Errorf("disabled EdgeOne capability carries enable authority or lacks cleanup evidence")
		}
	default:
		return fmt.Errorf("EdgeOne capability variant is unknown")
	}
	return nil
}

func hasEdgeOneProof(capability EdgeOneCapability) bool {
	return capability.RawProviderChecklistItemID != "" || capability.RawProviderProofDigest != "" || capability.ProductChecklistItemID != "" || capability.ProductProofDigest != "" || capability.CleanupChecklistItemID != "" || capability.CleanupEvidenceDigest != ""
}

func validQualificationStatus(status QualificationStatus) bool {
	switch status {
	case QualificationStatus{Preflight: "not_applicable", Gate: "passed", Live: "not_applicable"},
		QualificationStatus{Preflight: "eligible", Gate: "passed", Live: "live_qualified"},
		QualificationStatus{Preflight: "ineligible", Gate: "deferred", Live: "live_unqualified"},
		QualificationStatus{Preflight: "eligible", Gate: "deferred", Live: "live_unqualified"},
		QualificationStatus{Preflight: "ineligible", Gate: "blocked", Live: "live_unqualified"},
		QualificationStatus{Preflight: "indeterminate", Gate: "blocked", Live: "live_unqualified"},
		QualificationStatus{Preflight: "eligible", Gate: "blocked", Live: "live_unqualified"}:
		return true
	default:
		return false
	}
}

func validateNetworkPolicy(policy NetworkPolicy) error {
	if policy.TelemetryEnabled || policy.CommercialControlPlaneEnabled {
		return fmt.Errorf("community release cannot enable telemetry or a commercial control plane")
	}
	allowed := map[string]bool{"acme": true, "dependency_download": true, "dns_provider": true, "edgeone_origin_acl": true, "tailnet_control": true}
	required := map[string]bool{"acme": true, "dependency_download": true, "dns_provider": true, "tailnet_control": true}
	seen := map[string]bool{}
	previous := ""
	for _, purpose := range policy.ExternalPurposes {
		if !allowed[purpose] || previous != "" && strings.Compare(previous, purpose) >= 0 {
			return fmt.Errorf("external connection purposes are unknown, duplicated, or unsorted")
		}
		seen[purpose] = true
		previous = purpose
	}
	for purpose := range required {
		if !seen[purpose] {
			return fmt.Errorf("release omits required external connection purpose %q", purpose)
		}
	}
	return nil
}

type EffectPhase string

const (
	EffectPrepared EffectPhase = "prepared"
)

type QualificationEffect struct {
	ID                    string      `json:"id"`
	ScopeDigest           string      `json:"scope_digest"`
	PriorStateDigest      string      `json:"prior_state_digest"`
	PlannedMutationDigest string      `json:"planned_mutation_digest"`
	SelectorDigest        string      `json:"selector_digest"`
	CleanupPolicy         string      `json:"cleanup_policy"`
	Phase                 EffectPhase `json:"phase"`
}

type QualificationManifest struct {
	SchemaVersion             string                `json:"schema_version"`
	RunID                     string                `json:"run_id"`
	AuthorizedHostFingerprint string                `json:"authorized_host_fingerprint"`
	CaseID                    string                `json:"case_id"`
	Operation                 string                `json:"operation"`
	CandidateEnvelopeDigest   string                `json:"candidate_envelope_digest"`
	BinaryDigest              string                `json:"binary_digest"`
	SourceTreeDigest          string                `json:"source_tree_digest"`
	TargetProfileDigest       string                `json:"target_profile_digest"`
	BeforeInventoryDigest     string                `json:"before_inventory_digest"`
	CreatedAt                 time.Time             `json:"created_at"`
	Effects                   []QualificationEffect `json:"effects"`
}

type VerifiedQualificationManifest struct {
	value  QualificationManifest
	digest string
}

func (verified *VerifiedQualificationManifest) Value() QualificationManifest {
	if verified == nil {
		return QualificationManifest{}
	}
	value := verified.value
	value.Effects = append([]QualificationEffect(nil), verified.value.Effects...)
	return value
}
func (verified *VerifiedQualificationManifest) Digest() string {
	if verified == nil {
		return ""
	}
	return verified.digest
}

func DecodeQualificationManifest(data []byte, expectedDigest string) (*VerifiedQualificationManifest, error) {
	if !ValidDigest(expectedDigest) || DigestBytes(data) != expectedDigest {
		return nil, fmt.Errorf("qualification manifest differs from its protected expected digest")
	}
	var manifest QualificationManifest
	if err := DecodeCanonical(data, &manifest); err != nil {
		return nil, err
	}
	if err := validateQualificationManifest(manifest); err != nil {
		return nil, err
	}
	return &VerifiedQualificationManifest{value: manifest, digest: expectedDigest}, nil
}

func validateQualificationManifest(manifest QualificationManifest) error {
	if manifest.SchemaVersion != QualificationManifestSchemaVersion || !refPattern.MatchString(manifest.RunID) || !refPattern.MatchString(manifest.AuthorizedHostFingerprint) || !refPattern.MatchString(manifest.CaseID) || !refPattern.MatchString(manifest.Operation) || !ValidDigest(manifest.CandidateEnvelopeDigest) || !ValidDigest(manifest.BinaryDigest) || !ValidDigest(manifest.SourceTreeDigest) || !ValidDigest(manifest.TargetProfileDigest) || !ValidDigest(manifest.BeforeInventoryDigest) || !sameUTCSecond(manifest.CreatedAt) || len(manifest.Effects) == 0 {
		return fmt.Errorf("qualification manifest identity or before-inventory is invalid")
	}
	previous := ""
	for _, effect := range manifest.Effects {
		if !refPattern.MatchString(effect.ID) || previous != "" && strings.Compare(previous, effect.ID) >= 0 || !ValidDigest(effect.ScopeDigest) || !ValidDigest(effect.PriorStateDigest) || !ValidDigest(effect.PlannedMutationDigest) || !ValidDigest(effect.SelectorDigest) || (effect.CleanupPolicy != "cleanup_required" && effect.CleanupPolicy != "retain_authorized") || effect.Phase != EffectPrepared {
			return fmt.Errorf("qualification effects are invalid, duplicated, unsorted, or already advanced")
		}
		previous = effect.ID
	}
	return nil
}

type QualificationObservation struct {
	RunID                 string
	HostFingerprint       string
	CaseID                string
	Operation             string
	ManifestDigest        string
	BeforeInventoryDigest string
	ObservedAt            time.Time
	Profile               OSProfile
	Effect                QualificationEffect
}

func AuthorizeCandidateInstall(candidate *VerifiedCandidateRelease, manifest *VerifiedQualificationManifest, observed QualificationObservation) error {
	if candidate == nil || candidate.envelope == nil || manifest == nil || candidate.envelope.value.QualificationTarget == nil {
		return fmt.Errorf("candidate install lacks verified release or qualification authority")
	}
	profileDigest, err := ProfileDigest(observed.Profile)
	authority := manifest.value
	effectMatched := false
	for _, effect := range authority.Effects {
		if reflect.DeepEqual(effect, observed.Effect) {
			effectMatched = true
			break
		}
	}
	if err != nil || !sameUTCSecond(observed.ObservedAt) || observed.ObservedAt.Before(authority.CreatedAt) || !effectMatched || authority.RunID != candidate.envelope.value.EdgeOne.RunID || observed.RunID != authority.RunID || observed.HostFingerprint != authority.AuthorizedHostFingerprint || observed.CaseID != authority.CaseID || observed.Operation != authority.Operation || observed.ManifestDigest != manifest.digest || observed.BeforeInventoryDigest != authority.BeforeInventoryDigest || profileDigest != authority.TargetProfileDigest || !reflect.DeepEqual(observed.Profile, *candidate.envelope.value.QualificationTarget) || authority.CandidateEnvelopeDigest != candidate.envelope.digest || authority.BinaryDigest != candidate.envelope.value.Binary.Digest || authority.SourceTreeDigest != candidate.envelope.value.SourceTreeDigest {
		return fmt.Errorf("qualification candidate install authority, effect, or observation mismatched")
	}
	return nil
}

type FinalInstallObservation struct {
	ReleaseTag       string
	ManifestDigest   string
	EnvelopeDigest   string
	BinaryDigest     string
	SourceTreeDigest string
	HostFingerprint  string
	ObservedAt       time.Time
	Profile          OSProfile
}

func AuthorizeFinalInstall(final *VerifiedFinalRelease, observed FinalInstallObservation) error {
	if final == nil || final.envelope == nil || final.manifest == nil || len(final.envelope.value.SupportedProfiles) != 1 {
		return fmt.Errorf("final install lacks a completely verified release")
	}
	profileDigest, err := ProfileDigest(observed.Profile)
	supportedDigest, supportedErr := ProfileDigest(final.envelope.value.SupportedProfiles[0].Profile)
	if err != nil || supportedErr != nil || profileDigest != supportedDigest || !refPattern.MatchString(observed.HostFingerprint) || !sameUTCSecond(observed.ObservedAt) || observed.ReleaseTag != final.envelope.value.ReleaseTag || observed.ManifestDigest != final.manifest.digest || observed.EnvelopeDigest != final.envelope.digest || observed.BinaryDigest != final.envelope.value.Binary.Digest || observed.SourceTreeDigest != final.envelope.value.SourceTreeDigest {
		return fmt.Errorf("os_profile_live_unqualified")
	}
	return nil
}

func sameUTCSecond(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}
