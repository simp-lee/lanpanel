//go:build linux

package qualification

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	GenerationInputSchemaVersion = "lanpanel.qualification.generation-input.v1"
	JourneySpecSchemaVersion     = "lanpanel.qualification.journey-spec.v2"
)

type JourneySpec struct {
	SchemaVersion      string `json:"schema_version"`
	PublicIPv4         string `json:"public_ipv4"`
	TemporaryHTTPPort  uint16 `json:"temporary_http_port"`
	AppDomain          string `json:"app_domain"`
	AppAlias           string `json:"app_alias"`
	HeadscaleDomain    string `json:"headscale_domain"`
	MagicDNSNamespace  string `json:"magicdns_namespace"`
	DNS01Domain        string `json:"dns01_domain"`
	AuthoritativeZone  string `json:"authoritative_zone"`
	TailnetDomain      string `json:"tailnet_domain,omitempty"`
	TailnetLiveEnabled bool   `json:"tailnet_live_enabled"`
}

type GenerationInput struct {
	SchemaVersion               string            `json:"schema_version"`
	ReleaseTag                  string            `json:"release_tag"`
	ExpectedCommitOID           string            `json:"expected_commit_oid"`
	SourceRoot                  string            `json:"source_root"`
	OutputDirectory             string            `json:"output_directory"`
	Profile                     release.OSProfile `json:"profile"`
	PackageTemplate             packages.Plan     `json:"package_template"`
	DependencyAuthority         string            `json:"dependency_authority"`
	DependencyAssets            map[string]string `json:"dependency_assets"`
	CleanInstallInventoryDigest string            `json:"clean_install_inventory_digest"`
	SSH                         SSHAuthority      `json:"ssh"`
	ACME                        ACMEAuthority     `json:"acme"`
	DNS                         DNSAuthority      `json:"dns"`
	ExternalVantageRef          string            `json:"external_vantage_ref"`
	TailnetPeerRef              string            `json:"tailnet_peer_ref,omitempty"`
	Journey                     JourneySpec       `json:"journey"`
}

type GeneratedArtifacts struct {
	RunID                 string `json:"run_id"`
	CandidateDigest       string `json:"candidate_digest"`
	SourceTreeDigest      string `json:"source_tree_digest"`
	TargetProfileDigest   string `json:"target_profile_digest"`
	SideEffectPlanDigest  string `json:"side_effect_plan_digest"`
	InstallManifestDigest string `json:"install_manifest_digest"`
	ProtectedInput        string `json:"protected_input"`
}

func DecodeJourneySpec(data []byte) (JourneySpec, error) {
	var value JourneySpec
	if err := release.DecodeCanonical(data, &value); err != nil {
		return JourneySpec{}, err
	}
	if err := validateJourneySpec(value, ""); err != nil {
		return JourneySpec{}, err
	}
	return value, nil
}

func Generate(inputPath string, now func() time.Time) (GeneratedArtifacts, error) {
	inputBytes, _, err := readProtectedFile(inputPath, 4<<20, false)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	var input GenerationInput
	if err := release.DecodeCanonical(inputBytes, &input); err != nil {
		return GeneratedArtifacts{}, err
	}
	if now == nil {
		return GeneratedArtifacts{}, fmt.Errorf("qualification artifact generator clock is missing")
	}
	createdAt := now().UTC().Truncate(time.Second)
	if err := validateGenerationInput(input, createdAt); err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := requireExactCleanCommit(input.SourceRoot, input.ExpectedCommitOID); err != nil {
		return GeneratedArtifacts{}, err
	}
	sourceBytes, sourceDigest, err := release.GenerateSourceArchive(input.SourceRoot, input.ReleaseTag)
	if err != nil {
		return GeneratedArtifacts{}, err
	}

	parentFD, temporaryName, temporaryPath, err := createStagingDirectory(input.OutputDirectory)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	committed := false
	defer func() {
		_ = unix.Close(parentFD)
		if !committed {
			_ = os.RemoveAll(temporaryPath)
		}
	}()

	candidatePath := filepath.Join(temporaryPath, "candidate", "lanpanel")
	if err := os.MkdirAll(filepath.Dir(candidatePath), 0o700); err != nil {
		return GeneratedArtifacts{}, err
	}
	materializedRoot := filepath.Join(temporaryPath, "build-source")
	buildRoot, err := materializeSourceArchive(sourceBytes, input.ReleaseTag, materializedRoot)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := buildCandidate(buildRoot, input.ReleaseTag, candidatePath); err != nil {
		return GeneratedArtifacts{}, err
	}
	candidateBytes, err := os.ReadFile(candidatePath)
	if err != nil || len(candidateBytes) == 0 || len(candidateBytes) > 256<<20 {
		return GeneratedArtifacts{}, fmt.Errorf("generated candidate binary is missing or unbounded: %w", err)
	}
	if err := os.Chmod(candidatePath, 0o500); err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := os.RemoveAll(materializedRoot); err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := requireExactCleanCommit(input.SourceRoot, input.ExpectedCommitOID); err != nil {
		return GeneratedArtifacts{}, err
	}

	sourceRelative := filepath.Join("source", "lanpanel-"+input.ReleaseTag+".tar.gz")
	if err := writeArtifact(temporaryPath, sourceRelative, sourceBytes, 0o400); err != nil {
		return GeneratedArtifacts{}, err
	}

	dependencyBytes, _, err := readProtectedFile(input.DependencyAuthority, 4<<20, true)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	var dependency release.QualificationDependencyAuthority
	if err := release.DecodeCanonical(dependencyBytes, &dependency); err != nil {
		return GeneratedArtifacts{}, err
	}
	sbomBytes, err := release.GenerateReleaseSPDX(candidatePath, dependency, input.Profile, input.ReleaseTag, createdAt)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := writeArtifact(temporaryPath, "lanpanel.spdx.json", sbomBytes, 0o400); err != nil {
		return GeneratedArtifacts{}, err
	}
	dependencyAssetBytes := make(map[string][]byte, len(input.DependencyAssets))
	assetNames := make([]string, 0, len(input.DependencyAssets))
	for name := range input.DependencyAssets {
		assetNames = append(assetNames, name)
	}
	slices.Sort(assetNames)
	finalDependencyPaths := make(map[string]string, len(assetNames))
	for _, name := range assetNames {
		if !release.ValidRelativePath(name) {
			return GeneratedArtifacts{}, fmt.Errorf("qualification dependency asset name is invalid")
		}
		data, _, readErr := readProtectedFile(input.DependencyAssets[name], 512<<20, true)
		if readErr != nil {
			return GeneratedArtifacts{}, readErr
		}
		dependencyAssetBytes[name] = data
		relative := filepath.Join("dependencies", filepath.FromSlash(name))
		if err := writeArtifact(temporaryPath, relative, data, 0o400); err != nil {
			return GeneratedArtifacts{}, err
		}
		finalDependencyPaths[name] = filepath.Join(input.OutputDirectory, relative)
	}
	if err := writeArtifact(temporaryPath, "dependency-authority.json", dependencyBytes, 0o400); err != nil {
		return GeneratedArtifacts{}, err
	}

	runID, err := randomID("run_")
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	target := release.QualificationTargetProfile{SchemaVersion: release.QualificationTargetProfileSchemaVersion, Profile: input.Profile, CapturedAt: createdAt}
	targetBytes, err := release.MarshalCanonical(target)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	profileDigest, err := release.ProfileDigest(input.Profile)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	journeyBytes, err := release.MarshalCanonical(input.Journey)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	journeyDigest := release.DigestBytes(journeyBytes)
	vantage, vantageDigest, err := LoadVantageAuthority(input.ExternalVantageRef)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	if vantage.ExpectedSourceIPv4 == input.Journey.PublicIPv4 {
		return GeneratedArtifacts{}, fmt.Errorf("external vantage and target public IPv4 must differ")
	}
	var tailnetPeer TailnetPeerAuthority
	tailnetPeerDigest := ""
	if input.Journey.TailnetLiveEnabled {
		tailnetPeer, tailnetPeerDigest, err = loadTailnetPeer(input.TailnetPeerRef)
		if err != nil {
			return GeneratedArtifacts{}, err
		}
	}
	plan := buildSideEffectPlan(runID, input, tailnetPeer, release.DigestBytes(candidateBytes), profileDigest, journeyDigest, createdAt)
	planBytes, err := release.MarshalCanonical(plan)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	if _, err := release.DecodeLiveSideEffectPlan(planBytes); err != nil {
		return GeneratedArtifacts{}, err
	}
	planDigest := release.DigestBytes(planBytes)
	protectedAuthorityDigest, err := protectedAuthorityDigest(input.ACME, input.DNS)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	packageTemplateBytes, err := release.MarshalCanonical(input.PackageTemplate)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	manifest := release.QualificationInstallManifest{
		SchemaVersion: release.QualificationInstallManifestSchemaVersion, RunID: runID, ReleaseTag: input.ReleaseTag,
		CandidateBinary: release.AssetIdentity{Path: "lanpanel", Digest: release.DigestBytes(candidateBytes), Bytes: uint64(len(candidateBytes))}, SourceArchive: release.AssetIdentity{Path: "lanpanel-" + input.ReleaseTag + ".tar.gz", Digest: release.DigestBytes(sourceBytes), Bytes: uint64(len(sourceBytes))}, SBOM: release.AssetIdentity{Path: "lanpanel.spdx.json", Digest: release.DigestBytes(sbomBytes), Bytes: uint64(len(sbomBytes))}, SourceTreeDigest: sourceDigest,
		DependencyManifestDigest: release.DigestBytes(dependencyBytes), TargetProfileDigest: profileDigest, AuthorizedHostFingerprint: input.SSH.MachineFingerprint,
		SideEffectPlanDigest: planDigest, JourneySpecDigest: journeyDigest, PackageTemplateDigest: release.DigestBytes(packageTemplateBytes), TailnetPeerDigest: tailnetPeerDigest, ExternalVantageDigest: vantageDigest, ProtectedAuthorityDigest: protectedAuthorityDigest, ACMEAccountContact: input.ACME.Contact, CreatedAt: createdAt,
	}
	manifestBytes, err := release.MarshalCanonical(manifest)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	manifestDigest := release.DigestBytes(manifestBytes)
	probeResult := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: 1, RequestDigest: "sha256:" + release.DigestBytes([]byte("generator-package-preflight-request")), Allowed: true, ObservedAt: createdAt, ValidUntil: createdAt.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "generator_validation", Disposition: preflight.FindingPassed, Summary: "template validation only", Identity: runID}}}
	if _, err := BindQualificationPackagePlan(input.PackageTemplate, manifest, plan, input.Profile, probeResult, createdAt); err != nil {
		return GeneratedArtifacts{}, fmt.Errorf("qualification package template is invalid: %w", err)
	}
	if _, err := release.VerifyQualificationInstallAuthority(manifestDigest, manifestBytes, targetBytes, planBytes, dependencyBytes, candidateBytes, dependencyAssetBytes, release.QualificationInstallObservation{HostFingerprint: input.SSH.MachineFingerprint, ObservedAt: createdAt}); err != nil {
		return GeneratedArtifacts{}, fmt.Errorf("generated qualification authority failed self-verification: %w", err)
	}

	for relative, data := range map[string][]byte{"target-profile.json": targetBytes, "side-effect-plan.json": planBytes, "install-manifest.json": manifestBytes, "journey-spec.json": journeyBytes, "package-template.json": packageTemplateBytes} {
		if err := writeArtifact(temporaryPath, relative, data, 0o400); err != nil {
			return GeneratedArtifacts{}, err
		}
	}
	protected := ProtectedInput{
		SchemaVersion: ProtectedInputSchemaVersion, RunID: runID,
		Artifacts: ArtifactReferences{
			CandidateBinary: filepath.Join(input.OutputDirectory, "candidate", "lanpanel"), SourceArchive: filepath.Join(input.OutputDirectory, sourceRelative), SBOM: filepath.Join(input.OutputDirectory, "lanpanel.spdx.json"), SourceRoot: input.SourceRoot,
			TargetProfile: filepath.Join(input.OutputDirectory, "target-profile.json"), SideEffectPlan: filepath.Join(input.OutputDirectory, "side-effect-plan.json"), InstallManifest: filepath.Join(input.OutputDirectory, "install-manifest.json"),
			DependencyAuthority: filepath.Join(input.OutputDirectory, "dependency-authority.json"), DependencyAssets: finalDependencyPaths, JourneySpecification: filepath.Join(input.OutputDirectory, "journey-spec.json"), PackageTemplate: filepath.Join(input.OutputDirectory, "package-template.json"),
			CleanupReport: filepath.Join(input.OutputDirectory, "cleanup-report.json"), ExecutorAttestation: filepath.Join(input.OutputDirectory, "executor-attestation.json"), QualificationSummary: filepath.Join(input.OutputDirectory, "qualification-summary.json"),
		},
		SSH: input.SSH, ACME: input.ACME, DNS: input.DNS, ExternalVantageRef: input.ExternalVantageRef, TailnetPeerRef: input.TailnetPeerRef,
	}
	if err := validateInput(protected); err != nil {
		return GeneratedArtifacts{}, err
	}
	protectedBytes, err := release.MarshalCanonical(protected)
	if err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := writeArtifact(temporaryPath, "qualification-input.json", protectedBytes, 0o400); err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := syncTree(temporaryPath); err != nil {
		return GeneratedArtifacts{}, err
	}
	if err := unix.Renameat2(parentFD, temporaryName, parentFD, filepath.Base(input.OutputDirectory), unix.RENAME_NOREPLACE); err != nil {
		return GeneratedArtifacts{}, err
	}
	committed = true
	if err := unix.Fsync(parentFD); err != nil {
		return GeneratedArtifacts{}, err
	}
	return GeneratedArtifacts{RunID: runID, CandidateDigest: manifest.CandidateBinary.Digest, SourceTreeDigest: sourceDigest, TargetProfileDigest: profileDigest, SideEffectPlanDigest: planDigest, InstallManifestDigest: manifestDigest, ProtectedInput: filepath.Join(input.OutputDirectory, "qualification-input.json")}, nil
}

func validateGenerationInput(input GenerationInput, createdAt time.Time) error {
	if input.SchemaVersion != GenerationInputSchemaVersion || input.ReleaseTag == "" || !commitOIDPattern(input.ExpectedCommitOID) || !filepath.IsAbs(input.SourceRoot) || filepath.Clean(input.SourceRoot) != input.SourceRoot || !filepath.IsAbs(input.OutputDirectory) || filepath.Clean(input.OutputDirectory) != input.OutputDirectory || input.OutputDirectory == "/" || !filepath.IsAbs(input.DependencyAuthority) || filepath.Clean(input.DependencyAuthority) != input.DependencyAuthority || !release.ValidDigest(input.CleanInstallInventoryDigest) || !createdAt.Equal(createdAt.UTC().Truncate(time.Second)) {
		return fmt.Errorf("qualification generation input identity or paths are invalid")
	}
	if _, err := release.ProfileDigest(input.Profile); err != nil {
		return err
	}
	if err := validateJourneySpec(input.Journey, input.DNS.BaseDomain); err != nil {
		return err
	}
	candidate := ProtectedInput{SchemaVersion: ProtectedInputSchemaVersion, RunID: "run-validation", Artifacts: ArtifactReferences{CandidateBinary: "/validation/candidate", SourceArchive: "/validation/source", SBOM: "/validation/sbom", SourceRoot: input.SourceRoot, TargetProfile: "/validation/target", SideEffectPlan: "/validation/plan", InstallManifest: "/validation/manifest", DependencyAuthority: input.DependencyAuthority, DependencyAssets: input.DependencyAssets, JourneySpecification: "/validation/journey", PackageTemplate: "/validation/package-template", CleanupReport: "/validation/cleanup", ExecutorAttestation: "/validation/attestation", QualificationSummary: "/validation/summary"}, SSH: input.SSH, ACME: input.ACME, DNS: input.DNS, ExternalVantageRef: input.ExternalVantageRef, TailnetPeerRef: input.TailnetPeerRef}
	if err := validateInput(candidate); err != nil {
		return err
	}
	if input.Journey.TailnetLiveEnabled != (input.TailnetPeerRef != "") {
		return fmt.Errorf("tailnet journey selection and protected peer authority differ")
	}
	return nil
}

func validateJourneySpec(value JourneySpec, baseDomain string) error {
	address, err := netip.ParseAddr(value.PublicIPv4)
	if value.SchemaVersion != JourneySpecSchemaVersion || err != nil || !address.Is4() || address.String() != value.PublicIPv4 || !publicIPv4(address) || value.TemporaryHTTPPort < 1024 || !canonicalDomain(value.AppDomain) || !canonicalDomain(value.AppAlias) || !canonicalDomain(value.HeadscaleDomain) || !canonicalDomain(value.MagicDNSNamespace) || !canonicalDomain(value.DNS01Domain) || !canonicalDomain(value.AuthoritativeZone) {
		return fmt.Errorf("qualification journey public address, port, or domain authority is invalid")
	}
	domains := []string{value.AppDomain, value.AppAlias, value.HeadscaleDomain, value.MagicDNSNamespace, value.DNS01Domain}
	if value.TailnetLiveEnabled {
		if !canonicalDomain(value.TailnetDomain) {
			return fmt.Errorf("qualification tailnet domain is invalid")
		}
		domains = append(domains, value.TailnetDomain)
	} else if value.TailnetDomain != "" {
		return fmt.Errorf("qualification disabled tailnet case carries a domain")
	}
	sorted := append([]string(nil), domains...)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(domains) {
		return fmt.Errorf("qualification journey domains must be unique")
	}
	if baseDomain != "" {
		if !canonicalDomain(baseDomain) || value.AuthoritativeZone != baseDomain {
			return fmt.Errorf("qualification DNS base and authoritative zone differ")
		}
		for _, domain := range domains {
			if !strings.HasSuffix(domain, "."+baseDomain) {
				return fmt.Errorf("qualification journey domain escapes authorized DNS base")
			}
		}
	}
	return nil
}

func buildSideEffectPlan(runID string, input GenerationInput, tailnetPeer TailnetPeerAuthority, candidateDigest, profileDigest, journeyDigest string, createdAt time.Time) release.LiveSideEffectPlan {
	selectors := map[string]string{
		"clean_install":                          "host=" + input.SSH.MachineFingerprint,
		"ui_startup_session_restart":             "management=installation-specific-loopback",
		"local_http_websocket":                   "resource=qualification-local-" + runID[4:16],
		"temporary_public_http":                  fmt.Sprintf("listener=%s:%d", input.Journey.PublicIPv4, input.Journey.TemporaryHTTPPort),
		"domain_https_controls":                  "domains=" + input.Journey.AppDomain + "," + input.Journey.AppAlias,
		"app_http01":                             "certificate=" + input.Journey.AppDomain,
		"headscale_initialize_http01":            "control=" + input.Journey.HeadscaleDomain,
		"headscale_entities":                     "headscale=qualification-entities-" + runID,
		"connector_assisted_login":               "connector=installation-singleton",
		"tailnet_http_websocket":                 "tailnet=" + map[bool]string{true: fmt.Sprintf("live:%s:%s:%d:%s", tailnetPeer.SourceIP, tailnetPeer.PeerIP, tailnetPeer.Port, input.Journey.TailnetDomain), false: "not-live-tested"}[input.Journey.TailnetLiveEnabled],
		"dns01":                                  "certificate=" + input.Journey.DNS01Domain + ";provider=" + input.DNS.Provider,
		"delete_diagnostics_export_close_reboot": "installation=" + runID,
		"final_cleanup_inventory":                "host=" + input.SSH.MachineFingerprint + ";dns=" + input.DNS.BaseDomain,
	}
	retained := map[string]bool{"clean_install": true, "headscale_initialize_http01": true, "headscale_entities": true, "connector_assisted_login": true, "final_cleanup_inventory": true}
	mutations := make([]release.PlannedMutation, 0, len(orderedJourney))
	for _, step := range orderedJourney {
		scope := "run=" + runID + ";host=" + input.SSH.MachineFingerprint + ";journey=" + journeyDigest
		prior := "fresh-prior/" + step + "/" + journeyDigest
		if step == "clean_install" {
			prior = "bootstrap-inventory/" + input.CleanInstallInventoryDigest
		}
		mutation := "execute=" + step + ";candidate=" + candidateDigest + ";profile=" + profileDigest
		policy := "delete_exact"
		if retained[step] {
			policy = "retain_authorized"
		}
		selector := selectors[step]
		mutations = append(mutations, release.PlannedMutation{ID: step, Scope: scope, ScopeDigest: release.DigestBytes([]byte(scope)), PriorState: prior, PriorStateDigest: release.DigestBytes([]byte(prior)), PlannedMutation: mutation, PlannedMutationDigest: release.DigestBytes([]byte(mutation)), Selector: selector, SelectorDigest: release.DigestBytes([]byte(selector)), CleanupPolicy: policy})
	}
	slices.SortFunc(mutations, func(left, right release.PlannedMutation) int { return strings.Compare(left.ID, right.ID) })
	return release.LiveSideEffectPlan{SchemaVersion: release.LiveSideEffectPlanSchemaVersion, RunID: runID, AuthorizedHostFingerprint: input.SSH.MachineFingerprint, CreatedAt: createdAt, Mutations: mutations}
}

func protectedAuthorityDigest(acme ACMEAuthority, dns DNSAuthority) (string, error) {
	data, err := release.MarshalCanonical(struct {
		SchemaVersion string        `json:"schema_version"`
		ACME          ACMEAuthority `json:"acme"`
		DNS           DNSAuthority  `json:"dns"`
	}{"lanpanel.qualification.protected-authority.v1", acme, dns})
	if err != nil {
		return "", err
	}
	return release.DigestBytes(data), nil
}

func requireExactCleanCommit(root, expected string) error {
	commands := [][]string{{"diff", "--quiet", "HEAD", "--"}, {"diff", "--cached", "--quiet", "HEAD", "--"}}
	for _, arguments := range commands {
		command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
		if err := command.Run(); err != nil {
			return fmt.Errorf("qualification source index/worktree is not clean")
		}
	}
	untracked := exec.Command("git", "-C", root, "ls-files", "--others", "--exclude-standard", "-z")
	output, err := untracked.Output()
	if err != nil || len(output) != 0 {
		return fmt.Errorf("qualification source worktree has untracked input")
	}
	head := exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD")
	output, err = head.Output()
	if err != nil || strings.TrimSpace(string(output)) != expected {
		return fmt.Errorf("qualification source commit differs from expected exact revision")
	}
	return nil
}

func materializeSourceArchive(data []byte, releaseTag, destination string) (string, error) {
	if _, err := release.SourceArchiveTreeDigest(data); err != nil {
		return "", err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return "", err
	}
	compressed, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer func() { _ = compressed.Close() }()
	archive := tar.NewReader(compressed)
	expectedRoot := "lanpanel-" + releaseTag
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		clean := filepath.Clean(filepath.FromSlash(strings.TrimSuffix(header.Name, "/")))
		if clean == "." || clean != filepath.FromSlash(strings.TrimSuffix(header.Name, "/")) || clean != expectedRoot && !strings.HasPrefix(clean, expectedRoot+string(filepath.Separator)) {
			return "", fmt.Errorf("source materialization path escaped canonical root")
		}
		path := filepath.Join(destination, clean)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(path, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return "", err
			}
			mode := os.FileMode(header.Mode)
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return "", err
			}
			written, copyErr := io.CopyN(file, archive, header.Size)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written != header.Size {
				return "", errors.Join(copyErr, closeErr, fmt.Errorf("source materialization file changed"))
			}
		default:
			return "", fmt.Errorf("source materialization rejects tracked links and special files")
		}
	}
	return filepath.Join(destination, expectedRoot), nil
}

func buildCandidate(root, releaseTag, destination string) error {
	if runtime.Version() != "go1.26.6" {
		return fmt.Errorf("candidate build requires exact Go 1.26.6, observed %s", runtime.Version())
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		return err
	}
	command := exec.Command(goBinary, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.version="+releaseTag, "-o", destination, "./cmd/lanpanel")
	command.Dir = root
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOENV=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build exact candidate: %w: %s", err, output)
	}
	return nil
}

func createStagingDirectory(final string) (int, string, string, error) {
	parentPath, finalName := filepath.Dir(final), filepath.Base(final)
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", "", err
	}
	var stat unix.Stat_t
	if unix.Fstat(parentFD, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode)&0o077 != 0 {
		_ = unix.Close(parentFD)
		return -1, "", "", fmt.Errorf("qualification output parent is unsafe")
	}
	if _, err := os.Lstat(final); err == nil || !os.IsNotExist(err) {
		_ = unix.Close(parentFD)
		return -1, "", "", fmt.Errorf("qualification output already exists or is not inspectable")
	}
	nonce, err := randomID("")
	if err != nil {
		_ = unix.Close(parentFD)
		return -1, "", "", err
	}
	temporary := "." + finalName + "." + nonce
	if err := unix.Mkdirat(parentFD, temporary, 0o700); err != nil {
		_ = unix.Close(parentFD)
		return -1, "", "", err
	}
	return parentFD, temporary, filepath.Join(parentPath, temporary), nil
}

func writeArtifact(root, relative string, data []byte, mode uint32) error {
	if !release.ValidRelativePath(filepath.ToSlash(relative)) || len(data) == 0 {
		return fmt.Errorf("generated artifact path or bytes are invalid")
	}
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("generated artifact descriptor is invalid")
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		syncErr := unix.Fsync(fd)
		closeErr := unix.Close(fd)
		return errors.Join(syncErr, closeErr)
	})
}

func randomID(prefix string) (string, error) {
	var value [32]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func commitOIDPattern(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func canonicalDomain(value string) bool {
	if value == "" || value != strings.ToLower(value) || value != strings.TrimSpace(value) || strings.HasSuffix(value, ".") || strings.Contains(value, "*") || len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func publicIPv4(address netip.Addr) bool {
	if !address.Is4() || !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4")} {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
