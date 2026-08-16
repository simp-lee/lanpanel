// Package headscale owns optional Headscale release authority and immutable trust-domain initialization.
package headscale

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"net/url"
	"slices"
	"strings"
)

const (
	IdentitySnapshotSchema = "lanpanel.headscale.identity.v1"
	TrustedMeshPolicy      = "trusted_mesh"
)

type SourceChoice struct {
	Kind        sources.Kind
	MirrorURL   string
	OfflinePath string
}

type IdentitySnapshot struct {
	SchemaVersion       string                           `json:"schema_version"`
	InstallationID      string                           `json:"installation_id"`
	HeadscaleID         string                           `json:"headscale_id"`
	ControlDomain       string                           `json:"control_domain"`
	MagicDNSNamespace   string                           `json:"magicdns_namespace"`
	Policy              string                           `json:"policy"`
	Artifact            domain.HeadscaleArtifactIdentity `json:"artifact"`
	DatabaseUUID        string                           `json:"database_uuid"`
	SQLitePath          string                           `json:"sqlite_path"`
	DatabaseGeneration  uint64                           `json:"database_generation"`
	DesiredConfigDigest string                           `json:"desired_config_digest"`
}

type CandidateRequest struct {
	InstallationID    string
	ControlDomain     string
	MagicDNSNamespace string
	Release           release.InstallIdentity
	Random            io.Reader
}

func ArtifactIdentity(installed release.InstallIdentity) (domain.HeadscaleArtifactIdentity, error) {
	if err := release.ValidateInstallIdentity(installed); err != nil {
		return domain.HeadscaleArtifactIdentity{}, fmt.Errorf("installed release authority is invalid: %w", err)
	}
	authority := installed.Headscale
	var executable release.AssetIdentity
	for _, member := range authority.Members {
		if member.Asset.Path == authority.ExecutableAsset {
			executable = member.Asset
		}
	}
	if executable.Path == "" {
		return domain.HeadscaleArtifactIdentity{}, fmt.Errorf("installed release omits Headscale executable authority")
	}
	return domain.HeadscaleArtifactIdentity{
		BaselineDigest:       prefixed(installed.DependencyBaseline.Digest),
		Version:              authority.Version,
		ArchiveDigest:        prefixed(authority.Archive.Digest),
		ExecutableDigest:     prefixed(executable.Digest),
		ConfigContract:       authority.ConfigContract,
		ConfigContractDigest: prefixed(authority.ConfigContractDigest),
	}, nil
}

func BuildSource(installed release.InstallIdentity, choice SourceChoice) (sources.Source, error) {
	if err := release.ValidateInstallIdentity(installed); err != nil {
		return sources.Source{}, err
	}
	authority := installed.Headscale
	artifact := sources.Artifact{Name: "headscale", Version: authority.Version, OperatingOS: "linux", Architecture: installed.Profile.Architecture, Digest: authority.Archive.Digest}
	var source sources.Source
	switch choice.Kind {
	case sources.OfficialCanonical:
		if choice.MirrorURL != "" || choice.OfflinePath != "" {
			return sources.Source{}, fmt.Errorf("official Headscale source carries alternate location")
		}
		parsed, err := url.Parse(authority.ArtifactIdentity)
		if err != nil || parsed.Host == "" || !slices.Contains(authority.RedirectAuthorities, parsed.Host) {
			return sources.Source{}, fmt.Errorf("Headscale canonical artifact authority is inconsistent")
		}
		source = sources.Source{Kind: choice.Kind, URL: authority.ArtifactIdentity, OfficialAuthorities: append([]string(nil), authority.RedirectAuthorities...), Artifact: artifact}
	case sources.Mirror:
		if choice.MirrorURL == "" || choice.OfflinePath != "" {
			return sources.Source{}, fmt.Errorf("Headscale mirror source is incomplete")
		}
		source = sources.Source{Kind: choice.Kind, URL: choice.MirrorURL, Artifact: artifact}
	case sources.Offline:
		if choice.OfflinePath == "" || choice.MirrorURL != "" {
			return sources.Source{}, fmt.Errorf("Headscale offline source is incomplete")
		}
		source = sources.Source{Kind: choice.Kind, OfflinePath: choice.OfflinePath, Artifact: artifact}
	default:
		return sources.Source{}, fmt.Errorf("Headscale source kind is unsupported")
	}
	if err := sources.Validate(source); err != nil {
		return sources.Source{}, err
	}
	return source, nil
}

func NewCandidate(request CandidateRequest) (domain.HeadscaleDomain, IdentitySnapshot, []byte, error) {
	artifact, err := ArtifactIdentity(request.Release)
	if err != nil {
		return domain.HeadscaleDomain{}, IdentitySnapshot{}, nil, err
	}
	if request.Random == nil {
		request.Random = rand.Reader
	}
	headscaleID, err := randomID(request.Random, "hds_")
	if err != nil {
		return domain.HeadscaleDomain{}, IdentitySnapshot{}, nil, fmt.Errorf("generate Headscale identity: %w", err)
	}
	databaseUUID, err := randomID(request.Random, "hdb_")
	if err != nil {
		return domain.HeadscaleDomain{}, IdentitySnapshot{}, nil, fmt.Errorf("generate Headscale database identity: %w", err)
	}
	desiredValue := struct {
		ControlDomain     string                           `json:"control_domain"`
		MagicDNSNamespace string                           `json:"magicdns_namespace"`
		Policy            string                           `json:"policy"`
		Artifact          domain.HeadscaleArtifactIdentity `json:"artifact"`
	}{request.ControlDomain, request.MagicDNSNamespace, TrustedMeshPolicy, artifact}
	desiredBytes, err := json.Marshal(desiredValue)
	if err != nil {
		return domain.HeadscaleDomain{}, IdentitySnapshot{}, nil, err
	}
	desiredDigest := digest(desiredBytes)
	snapshot := IdentitySnapshot{SchemaVersion: IdentitySnapshotSchema, InstallationID: request.InstallationID, HeadscaleID: headscaleID, ControlDomain: request.ControlDomain, MagicDNSNamespace: request.MagicDNSNamespace, Policy: TrustedMeshPolicy, Artifact: artifact, DatabaseUUID: databaseUUID, SQLitePath: "/var/lib/lanpanel/headscale-runtime/db.sqlite", DatabaseGeneration: 1, DesiredConfigDigest: desiredDigest}
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		return domain.HeadscaleDomain{}, IdentitySnapshot{}, nil, err
	}
	bundleDigest := digest(snapshotBytes)
	candidate := domain.HeadscaleDomain{ID: headscaleID, ControlDomain: request.ControlDomain, MagicDNSNamespace: request.MagicDNSNamespace, Policy: TrustedMeshPolicy, Artifact: artifact, Database: domain.HeadscaleDatabaseIdentity{UUID: databaseUUID, SQLitePath: snapshot.SQLitePath, IdentityBundleDigest: bundleDigest, Generation: 1, Phase: domain.HeadscaleIdentityCommitted}, DesiredDigest: desiredDigest, ManagedPaths: domain.HeadscaleManagedPaths()}
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: request.InstallationID, Management: domain.ManagementAuthority{Address: "127.0.0.1", Port: 1024}, Headscale: &candidate}
	if err := domain.ValidateInstallation(installation); err != nil {
		return domain.HeadscaleDomain{}, IdentitySnapshot{}, nil, fmt.Errorf("candidate Headscale identity: %w", err)
	}
	return candidate, snapshot, snapshotBytes, nil
}

func VerifySnapshot(candidate domain.HeadscaleDomain, snapshotBytes []byte) error {
	var snapshot IdentitySnapshot
	if len(snapshotBytes) == 0 || json.Unmarshal(snapshotBytes, &snapshot) != nil {
		return fmt.Errorf("Headscale identity snapshot is invalid")
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || !slices.Equal(canonical, snapshotBytes) || snapshot.SchemaVersion != IdentitySnapshotSchema || snapshot.HeadscaleID != candidate.ID || snapshot.ControlDomain != candidate.ControlDomain || snapshot.MagicDNSNamespace != candidate.MagicDNSNamespace || snapshot.Policy != candidate.Policy || snapshot.Artifact != candidate.Artifact || snapshot.DatabaseUUID != candidate.Database.UUID || snapshot.SQLitePath != candidate.Database.SQLitePath || snapshot.DatabaseGeneration != candidate.Database.Generation || snapshot.DesiredConfigDigest != candidate.DesiredDigest || digest(snapshotBytes) != candidate.Database.IdentityBundleDigest {
		return fmt.Errorf("Headscale identity snapshot differs from candidate authority")
	}
	return nil
}

func prefixed(value string) string { return "sha256:" + value }
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func randomID(reader io.Reader, prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(reader, value); err != nil {
		clear(value)
		return "", err
	}
	encoded := prefix + hex.EncodeToString(value)
	clear(value)
	return encoded, nil
}

var _ = strings.Compare
