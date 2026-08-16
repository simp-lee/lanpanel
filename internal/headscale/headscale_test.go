package headscale

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"strings"
	"testing"
	"time"
)

func TestCandidateUsesExplicitReleaseAuthorityAndKeepsIdentityImmutable(t *testing.T) {
	installed, _ := fixtureRelease()
	candidate, snapshot, encoded, err := NewCandidate(CandidateRequest{InstallationID: "ins_00000000000000000000000000000001", ControlDomain: "control.example.com", MagicDNSNamespace: "tail.example.net", Release: installed, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Policy != TrustedMeshPolicy || candidate.Enabled || candidate.Applied != nil || candidate.Database.Phase != domain.HeadscaleIdentityCommitted || candidate.ID == "" || candidate.Database.UUID == "" {
		t.Fatalf("candidate = %#v", candidate)
	}
	if err := VerifySnapshot(candidate, encoded); err != nil || snapshot.HeadscaleID != candidate.ID {
		t.Fatalf("snapshot verification = %v", err)
	}
	changed := candidate
	changed.ControlDomain = "other.example.com"
	if err := domain.ValidateHeadscaleTransition(candidate, changed); err == nil {
		t.Fatal("immutable control domain change was accepted")
	}
	if _, _, _, err := NewCandidate(CandidateRequest{InstallationID: candidate.ID, ControlDomain: candidate.ControlDomain, MagicDNSNamespace: candidate.MagicDNSNamespace, Release: installed, Random: errorReader{}}); err == nil {
		t.Fatal("invalid installation identity or CSPRNG failure was accepted")
	}
}

func TestInitializationJournalPinsExactCandidateAcrossRetry(t *testing.T) {
	installed, _ := fixtureRelease()
	candidate, _, snapshot, err := NewCandidate(CandidateRequest{InstallationID: "ins_00000000000000000000000000000001", ControlDomain: "control.example.com", MagicDNSNamespace: "tail.example.net", Release: installed, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	source, _ := BuildSource(installed, SourceChoice{Kind: sources.OfficialCanonical})
	journal, data, err := BuildInitializationJournal(candidate, installed, snapshot, "job_00000000000000000000000000000001", source, "")
	if err != nil {
		t.Fatal(err)
	}
	var decoded InitializationJournal
	if json.Unmarshal(data, &decoded) != nil || decoded.Candidate.ID != candidate.ID || decoded.ArchiveDigest != installed.Headscale.Archive.Digest || decoded.SnapshotDigest != journal.SnapshotDigest {
		t.Fatalf("journal = %#v", decoded)
	}
	changed := installed
	changed.Headscale.Archive.Digest = strings.Repeat("f", 64)
	if _, _, err := BuildInitializationJournal(candidate, changed, snapshot, journal.JobID, source, ""); err == nil {
		t.Fatal("changed release authority accepted for pending initialization")
	}
	if _, _, err := BuildInitializationJournal(candidate, installed, append(snapshot, '\n'), journal.JobID, source, ""); err == nil {
		t.Fatal("changed identity snapshot accepted")
	}
}

func TestSourceChoiceNeverFloatsOrFallsBack(t *testing.T) {
	installed, _ := fixtureRelease()
	official, err := BuildSource(installed, SourceChoice{Kind: sources.OfficialCanonical})
	if err != nil || official.URL != installed.Headscale.ArtifactIdentity || official.Artifact.Version != installed.Headscale.Version {
		t.Fatalf("official = %#v, %v", official, err)
	}
	mirror, err := BuildSource(installed, SourceChoice{Kind: sources.Mirror, MirrorURL: "https://mirror.example.test/headscale.tar.gz"})
	if err != nil || mirror.Kind != sources.Mirror {
		t.Fatalf("mirror = %#v, %v", mirror, err)
	}
	offline, err := BuildSource(installed, SourceChoice{Kind: sources.Offline, OfflinePath: "/srv/offline/headscale.tar.gz"})
	if err != nil || offline.Kind != sources.Offline {
		t.Fatalf("offline = %#v, %v", offline, err)
	}
	if _, err := BuildSource(installed, SourceChoice{Kind: sources.OfficialCanonical, MirrorURL: "https://other.example.test/headscale"}); err == nil {
		t.Fatal("official source accepted alternate URL")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func fixtureRelease() (release.InstallIdentity, []byte) {
	archive := fixtureArchive()
	archiveDigest := release.DigestBytes(archive)
	executable := []byte("headscale-fixture")
	executableDigest := release.DigestBytes(executable)
	profile := release.OSProfile{ID: "debian-13-amd64", Family: "debian", Release: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: strings.Repeat("1", 64), ManagedConfinement: release.ConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8"}, QualificationDigest: strings.Repeat("2", 64)}}
	profileDigest, _ := release.ProfileDigest(profile)
	identity := release.InstallIdentity{Kind: release.EnvelopeFinal, ReleaseTag: "v1.0.0", EnvelopeDigest: strings.Repeat("3", 64), ManifestDigest: strings.Repeat("4", 64), Binary: release.AssetIdentity{Path: "lanpanel", Digest: strings.Repeat("5", 64), Bytes: 1}, SourceTreeDigest: strings.Repeat("6", 64), Profile: profile, ProfileDigest: profileDigest, CapabilityDigest: strings.Repeat("7", 64), CandidateDigest: strings.Repeat("8", 64), HostFingerprint: "host-fixture", Operation: "bootstrap_install", AuthorityCreatedAt: time.Unix(1_700_000_000, 0).UTC(), DependencyBaseline: release.AssetIdentity{Path: "dependency-baseline.json", Digest: strings.Repeat("9", 64), Bytes: 1}, Headscale: release.HeadscaleArtifactAuthority{Version: "0.25.1", ArtifactIdentity: "https://downloads.example.test/headscale-0.25.1.tar.gz", Archive: release.AssetIdentity{Path: "headscale.tar.gz", Digest: archiveDigest, Bytes: uint64(len(archive))}, ArchiveFormat: "tar_gzip", MaximumExtractedBytes: 1 << 20, RedirectAuthorities: []string{"downloads.example.test"}, Members: []release.ArchiveMemberAuthority{{Path: "headscale", Asset: release.AssetIdentity{Path: "headscale", Digest: executableDigest, Bytes: uint64(len(executable))}, Destination: "/usr/lib/lanpanel/dependencies/headscale", Mode: 0o755}}, ExecutableAsset: "headscale", InstallPath: "/usr/lib/lanpanel/dependencies/headscale", ConfigContract: "headscale-trusted-mesh-v1", ConfigContractDigest: release.SupportedHeadscaleConfigContractDigest()}, Lego: release.AssetIdentity{Path: "lego", Digest: strings.Repeat("b", 64), Bytes: 1}}
	return identity, archive
}

func fixtureArchive() []byte {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	compressed.Header.ModTime = time.Unix(0, 0).UTC()
	writer := tar.NewWriter(compressed)
	data := []byte("headscale-fixture")
	_ = writer.WriteHeader(&tar.Header{Name: "headscale", Mode: 0o755, Size: int64(len(data)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR})
	_, _ = writer.Write(data)
	_ = writer.Close()
	_ = compressed.Close()
	return output.Bytes()
}
