//go:build linux

package qualification

import (
	"errors"
	"fmt"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const ProtectedInputSchemaVersion = "lanpanel.qualification.protected-input.v4"

var orderedJourney = []string{
	"clean_install",
	"ui_startup_session_restart",
	"local_http_websocket",
	"temporary_public_http",
	"domain_https_controls",
	"app_http01",
	"headscale_initialize_http01",
	"headscale_entities",
	"connector_assisted_login",
	"tailnet_http_websocket",
	"dns01",
	"delete_diagnostics_export_close_reboot",
	"final_cleanup_inventory",
}

type ArtifactReferences struct {
	CandidateBinary      string            `json:"candidate_binary"`
	SourceArchive        string            `json:"source_archive"`
	SBOM                 string            `json:"sbom"`
	SourceRoot           string            `json:"source_root"`
	TargetProfile        string            `json:"target_profile"`
	SideEffectPlan       string            `json:"side_effect_plan"`
	InstallManifest      string            `json:"install_manifest"`
	DependencyAuthority  string            `json:"dependency_authority"`
	DependencyAssets     map[string]string `json:"dependency_assets"`
	JourneySpecification string            `json:"journey_specification"`
	PackageTemplate      string            `json:"package_template"`
	CleanupReport        string            `json:"cleanup_report"`
	ExecutorAttestation  string            `json:"executor_attestation"`
	QualificationSummary string            `json:"qualification_summary"`
}

type SSHAuthority struct {
	Address            string `json:"address"`
	User               string `json:"user"`
	HostKeySHA256      string `json:"host_key_sha256"`
	MachineFingerprint string `json:"machine_fingerprint"`
	CredentialRef      string `json:"credential_ref"`
}

type ACMEAuthority struct {
	DirectoryURL string `json:"directory_url"`
	Contact      string `json:"contact"`
	TOSAccepted  bool   `json:"tos_accepted"`
}

type DNSAuthority struct {
	Provider      string `json:"provider"`
	BaseDomain    string `json:"base_domain"`
	CredentialRef string `json:"credential_ref"`
}

type ProtectedInput struct {
	SchemaVersion      string             `json:"schema_version"`
	RunID              string             `json:"run_id"`
	Artifacts          ArtifactReferences `json:"artifacts"`
	SSH                SSHAuthority       `json:"ssh"`
	ACME               ACMEAuthority      `json:"acme"`
	DNS                DNSAuthority       `json:"dns"`
	ExternalVantageRef string             `json:"external_vantage_ref"`
	TailnetPeerRef     string             `json:"tailnet_peer_ref,omitempty"`
}

type Prepared struct {
	Input                    ProtectedInput
	InputDigest              string
	Install                  release.InstallAuthority
	PlanBytes                []byte
	PlanDigest               string
	InstallManifestDigest    string
	CandidateBytes           []byte
	SourceDigest             string
	ProtectedAuthorityDigest string
	ExternalVantageDigest    string
	TailnetPeerDigest        string
}

func OrderedJourney() []string { return append([]string(nil), orderedJourney...) }

func Prepare(inputPath string) (Prepared, error) {
	inputBytes, _, err := readProtectedFile(inputPath, 1<<20, false)
	if err != nil {
		return Prepared{}, err
	}
	var input ProtectedInput
	if err := release.DecodeCanonical(inputBytes, &input); err != nil {
		return Prepared{}, err
	}
	if err := validateInput(input); err != nil {
		return Prepared{}, err
	}
	cwd, cwdErr := os.Getwd()
	sourceRoot, rootErr := filepath.EvalSymlinks(input.Artifacts.SourceRoot)
	cwdRoot, resolveErr := filepath.EvalSymlinks(cwd)
	if cwdErr != nil || rootErr != nil || resolveErr != nil || sourceRoot != cwdRoot {
		return Prepared{}, fmt.Errorf("qualification source root is not the invoking clean repository")
	}
	candidate, _, err := readProtectedFile(input.Artifacts.CandidateBinary, 256<<20, false)
	if err != nil {
		return Prepared{}, err
	}
	archive, _, err := readProtectedFile(input.Artifacts.SourceArchive, 512<<20, false)
	if err != nil {
		return Prepared{}, err
	}
	sbomBytes, _, err := readProtectedFile(input.Artifacts.SBOM, 16<<20, true)
	if err != nil {
		return Prepared{}, err
	}
	targetBytes, _, err := readProtectedFile(input.Artifacts.TargetProfile, 4<<20, true)
	if err != nil {
		return Prepared{}, err
	}
	planBytes, _, err := readProtectedFile(input.Artifacts.SideEffectPlan, 4<<20, true)
	if err != nil {
		return Prepared{}, err
	}
	manifestBytes, _, err := readProtectedFile(input.Artifacts.InstallManifest, 4<<20, true)
	if err != nil {
		return Prepared{}, err
	}
	dependencyBytes, _, err := readProtectedFile(input.Artifacts.DependencyAuthority, 4<<20, true)
	if err != nil {
		return Prepared{}, err
	}
	journeyBytes, _, err := readProtectedFile(input.Artifacts.JourneySpecification, 4<<20, true)
	if err != nil {
		return Prepared{}, err
	}
	packageTemplateBytes, _, err := readProtectedFile(input.Artifacts.PackageTemplate, 4<<20, true)
	if err != nil {
		return Prepared{}, err
	}
	journey, err := DecodeJourneySpec(journeyBytes)
	if err != nil {
		return Prepared{}, err
	}
	vantage, vantageDigest, err := LoadVantageAuthority(input.ExternalVantageRef)
	if err != nil {
		return Prepared{}, err
	}
	if vantage.ExpectedSourceIPv4 == journey.PublicIPv4 {
		return Prepared{}, fmt.Errorf("external vantage and target public IPv4 must differ")
	}
	if journey.TailnetLiveEnabled != (input.TailnetPeerRef != "") {
		return Prepared{}, fmt.Errorf("tailnet journey selection and protected peer authority differ")
	}
	tailnetPeerDigest := ""
	if journey.TailnetLiveEnabled {
		_, tailnetPeerDigest, err = loadTailnetPeer(input.TailnetPeerRef)
		if err != nil {
			return Prepared{}, err
		}
	}
	assets := make(map[string][]byte, len(input.Artifacts.DependencyAssets))
	assetNames := make([]string, 0, len(input.Artifacts.DependencyAssets))
	for name := range input.Artifacts.DependencyAssets {
		assetNames = append(assetNames, name)
	}
	slices.Sort(assetNames)
	for _, name := range assetNames {
		if !release.ValidRelativePath(name) {
			return Prepared{}, fmt.Errorf("qualification dependency asset name is invalid")
		}
		value, _, readErr := readProtectedFile(input.Artifacts.DependencyAssets[name], 512<<20, true)
		if readErr != nil {
			return Prepared{}, readErr
		}
		assets[name] = value
	}
	manifest, err := release.DecodeQualificationInstallManifest(manifestBytes)
	if err != nil {
		return Prepared{}, err
	}
	protectedAuthorityBytes, authorityErr := release.MarshalCanonical(struct {
		SchemaVersion string        `json:"schema_version"`
		ACME          ACMEAuthority `json:"acme"`
		DNS           DNSAuthority  `json:"dns"`
	}{"lanpanel.qualification.protected-authority.v1", input.ACME, input.DNS})
	if authorityErr != nil {
		return Prepared{}, authorityErr
	}
	protectedAuthorityDigest := release.DigestBytes(protectedAuthorityBytes)
	if manifest.RunID != input.RunID || manifest.SourceArchive.Digest != release.DigestBytes(archive) || manifest.SourceArchive.Bytes != uint64(len(archive)) || manifest.SBOM.Digest != release.DigestBytes(sbomBytes) || manifest.SBOM.Bytes != uint64(len(sbomBytes)) || manifest.AuthorizedHostFingerprint != input.SSH.MachineFingerprint || manifest.JourneySpecDigest != release.DigestBytes(journeyBytes) || manifest.PackageTemplateDigest != release.DigestBytes(packageTemplateBytes) || manifest.TailnetPeerDigest != tailnetPeerDigest || manifest.ExternalVantageDigest != vantageDigest || manifest.ProtectedAuthorityDigest != protectedAuthorityDigest || manifest.ACMEAccountContact != input.ACME.Contact {
		return Prepared{}, fmt.Errorf("protected input does not match qualification manifest")
	}
	install, err := release.VerifyQualificationInstallAuthority(release.DigestBytes(manifestBytes), manifestBytes, targetBytes, planBytes, dependencyBytes, candidate, assets, release.QualificationInstallObservation{HostFingerprint: input.SSH.MachineFingerprint, ObservedAt: manifest.CreatedAt})
	if err != nil {
		return Prepared{}, err
	}
	var template packages.Plan
	if err := release.DecodeCanonical(packageTemplateBytes, &template); err != nil {
		return Prepared{}, err
	}
	plan, err := release.DecodeLiveSideEffectPlan(planBytes)
	if err != nil {
		return Prepared{}, err
	}
	templateProbe := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: 1, RequestDigest: "sha256:" + release.DigestBytes([]byte("prepare-package-template-request")), Allowed: true, ObservedAt: manifest.CreatedAt, ValidUntil: manifest.CreatedAt.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "template_validation", Disposition: preflight.FindingPassed, Summary: "immutable template validation", Identity: manifest.RunID}}}
	if _, err := BindQualificationPackagePlan(template, manifest, plan, install.Identity().Profile, templateProbe, manifest.CreatedAt); err != nil {
		return Prepared{}, fmt.Errorf("qualification package template differs from exact profile: %w", err)
	}
	var dependency release.QualificationDependencyAuthority
	if err := release.DecodeCanonical(dependencyBytes, &dependency); err != nil {
		return Prepared{}, err
	}
	if err := release.ValidateReleaseSPDX(sbomBytes, candidate, install.Identity().CandidateDigest, manifest.ReleaseTag, dependency, install.Identity().Profile); err != nil {
		return Prepared{}, fmt.Errorf("qualification SBOM does not bind exact candidate/dependency/profile closure: %w", err)
	}
	sourceDigest, err := release.VerifySourceArchiveAgainstCleanTree(input.Artifacts.SourceRoot, archive)
	if err != nil {
		return Prepared{}, err
	}
	if sourceDigest != manifest.SourceTreeDigest {
		return Prepared{}, fmt.Errorf("qualification source digest changed")
	}
	return Prepared{Input: input, InputDigest: release.DigestBytes(inputBytes), Install: *install, PlanBytes: planBytes, PlanDigest: release.DigestBytes(planBytes), InstallManifestDigest: release.DigestBytes(manifestBytes), CandidateBytes: candidate, SourceDigest: sourceDigest, ProtectedAuthorityDigest: protectedAuthorityDigest, ExternalVantageDigest: vantageDigest, TailnetPeerDigest: tailnetPeerDigest}, nil
}

func VerifyFinalReadiness(inputPath string) (Prepared, release.LiveCleanupReport, error) {
	prepared, err := Prepare(inputPath)
	if err != nil {
		return Prepared{}, release.LiveCleanupReport{}, err
	}
	plan, planErr := release.DecodeLiveSideEffectPlan(prepared.PlanBytes)
	if planErr != nil {
		return Prepared{}, release.LiveCleanupReport{}, planErr
	}
	if err := validateOrderedJourneyPlan(plan); err != nil {
		return Prepared{}, release.LiveCleanupReport{}, err
	}
	reportBytes, _, err := readProtectedFile(prepared.Input.Artifacts.CleanupReport, 4<<20, false)
	if err != nil {
		return Prepared{}, release.LiveCleanupReport{}, err
	}
	attestationBytes, _, err := readProtectedFile(prepared.Input.Artifacts.ExecutorAttestation, 4<<20, true)
	if err != nil {
		return Prepared{}, release.LiveCleanupReport{}, err
	}
	report, attestation, err := release.VerifyLiveCleanup(prepared.PlanBytes, reportBytes, attestationBytes, prepared.InstallManifestDigest, prepared.InputDigest)
	if err != nil {
		return Prepared{}, release.LiveCleanupReport{}, err
	}
	identity := prepared.Install.Identity()
	expectedTailnet := "not_live_tested"
	if prepared.TailnetPeerDigest != "" {
		expectedTailnet = "live_tested"
	}
	if attestation.CandidateDigest != identity.CandidateDigest || attestation.TargetProfileDigest != identity.ProfileDigest || attestation.TargetHostFingerprint != prepared.Input.SSH.MachineFingerprint || attestation.ExternalVantageDigest != prepared.ExternalVantageDigest || attestation.DNSProvider != prepared.Input.DNS.Provider || attestation.TailnetLiveStatus != expectedTailnet {
		return Prepared{}, release.LiveCleanupReport{}, fmt.Errorf("trusted live executor attestation authority differs")
	}
	return prepared, report, nil
}

func validateInput(input ProtectedInput) error {
	if input.SchemaVersion != ProtectedInputSchemaVersion || input.RunID == "" || input.RunID != strings.TrimSpace(input.RunID) || func() bool { _, err := canonicalSSHAddress(input.SSH.Address); return err != nil }() || input.SSH.User != "root" || !release.ValidDigest(input.SSH.HostKeySHA256) || !machineFingerprintPattern.MatchString(input.SSH.MachineFingerprint) || !protectedReference(input.SSH.CredentialRef) || !canonicalQualificationACMEDirectory(input.ACME.DirectoryURL) || !acmeaccount.ValidContact(input.ACME.Contact) || !input.ACME.TOSAccepted || input.DNS.Provider != "cloudflare" || !canonicalDomain(input.DNS.BaseDomain) || !protectedReference(input.DNS.CredentialRef) || !protectedReference(input.ExternalVantageRef) || input.TailnetPeerRef != "" && !protectedReference(input.TailnetPeerRef) {
		return fmt.Errorf("qualification protected input is invalid")
	}
	paths := []string{input.Artifacts.CandidateBinary, input.Artifacts.SourceArchive, input.Artifacts.SBOM, input.Artifacts.SourceRoot, input.Artifacts.TargetProfile, input.Artifacts.SideEffectPlan, input.Artifacts.InstallManifest, input.Artifacts.DependencyAuthority, input.Artifacts.JourneySpecification, input.Artifacts.PackageTemplate, input.Artifacts.CleanupReport, input.Artifacts.ExecutorAttestation, input.Artifacts.QualificationSummary}
	for _, value := range input.Artifacts.DependencyAssets {
		paths = append(paths, value)
	}
	for _, value := range paths {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("qualification artifact reference is not an exact absolute path")
		}
	}
	return nil
}

var machineFingerprintPattern = regexp.MustCompile(`^host_[0-9a-f]{32}$`)

func canonicalQualificationACMEDirectory(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func protectedReference(value string) bool {
	return value == strings.TrimSpace(value) && len(value) >= 3 && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n") && (strings.HasPrefix(value, "file:") || strings.HasPrefix(value, "agent:") || strings.HasPrefix(value, "vault:"))
}

type fileIdentity struct {
	Device uint64
	Inode  uint64
	Size   int64
	Mode   uint32
}

func readProtectedFile(path string, maximum int64, immutable bool) ([]byte, fileIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, fileIdentity{}, fmt.Errorf("protected file path or bound is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fileIdentity{}, fmt.Errorf("protected file descriptor is invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return nil, fileIdentity{}, err
	}
	mode := uint32(before.Mode)
	if mode&syscall.S_IFMT != syscall.S_IFREG || before.Uid != uint32(os.Geteuid()) || mode&0o077 != 0 || immutable && mode&0o222 != 0 || before.Size <= 0 || before.Size > maximum {
		return nil, fileIdentity{}, fmt.Errorf("protected file type, owner, mode, or size is invalid")
	}
	data := make([]byte, before.Size)
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, fileIdentity{}, err
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return nil, fileIdentity{}, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, fileIdentity{}, errors.New("protected file changed while reading")
	}
	return data, fileIdentity{Device: uint64(before.Dev), Inode: before.Ino, Size: before.Size, Mode: mode}, nil
}
