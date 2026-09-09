//go:build linux

package qualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/release"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	SecurityScanInputSchemaVersion = "lanpanel.qualification.security-scan-input.v1"
	PinnedGovulncheckVersion       = "1.1.4"
	PinnedOSVScannerVersion        = "2.0.3"
	securityScanTimeout            = 15 * time.Minute
	maximumSecurityAuthorityAge    = 7 * 24 * time.Hour
	maximumScannerOutputBytes      = 64 << 20
)

type FixedScanner struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type FixedVulnerabilityDatabase struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Digest     string    `json:"digest"`
	CapturedAt time.Time `json:"captured_at"`
}

type SecurityScanInput struct {
	SchemaVersion      string                     `json:"schema_version"`
	QualificationInput string                     `json:"qualification_input"`
	Govulncheck        FixedScanner               `json:"govulncheck"`
	OSVScanner         FixedScanner               `json:"osv_scanner"`
	GoDatabase         FixedVulnerabilityDatabase `json:"go_database"`
	SBOMDatabase       FixedVulnerabilityDatabase `json:"sbom_database"`
	DistroDatabase     FixedVulnerabilityDatabase `json:"distro_database"`
	RepositorySnapshot RepositorySnapshotFiles    `json:"repository_snapshot"`
}

type SecurityScanResult struct {
	CandidateDigest      string `json:"candidate_digest"`
	SecurityReport       string `json:"security_report"`
	SecurityReportDigest string `json:"security_report_digest"`
	FindingCount         int    `json:"finding_count"`
}

type securityCommand struct {
	Path        string
	Arguments   []string
	Environment []string
	Directory   string
}

type securityCommandOutput struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type securityCommandExecutor interface {
	Run(context.Context, securityCommand) (securityCommandOutput, error)
}

type systemSecurityCommandExecutor struct{}

func (systemSecurityCommandExecutor) Run(ctx context.Context, command securityCommand) (securityCommandOutput, error) {
	return runSystemSecurityCommand(ctx, command)
}

func runSystemSecurityCommand(ctx context.Context, command securityCommand) (securityCommandOutput, error) {
	process := exec.CommandContext(ctx, command.Path, command.Arguments...)
	process.Dir = command.Directory
	process.Env = command.Environment
	stdout := &boundedCommandBuffer{maximum: maximumScannerOutputBytes}
	stderr := &boundedCommandBuffer{maximum: maximumScannerOutputBytes}
	process.Stdout, process.Stderr = stdout, stderr
	err := process.Run()
	if ctx.Err() != nil {
		return securityCommandOutput{}, ctx.Err()
	}
	if err == nil {
		return securityCommandOutput{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: 0}, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return securityCommandOutput{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitError.ExitCode()}, nil
	}
	return securityCommandOutput{}, err
}

type boundedCommandBuffer struct {
	bytes.Buffer
	maximum int
}

func (buffer *boundedCommandBuffer) Write(data []byte) (int, error) {
	if len(data) > buffer.maximum-buffer.Len() {
		return 0, fmt.Errorf("security scanner output exceeds %d bytes", buffer.maximum)
	}
	return buffer.Buffer.Write(data)
}

func RunReleaseSecurityScan(inputPath string, now func() time.Time) (SecurityScanResult, error) {
	return runReleaseSecurityScan(inputPath, now, systemSecurityCommandExecutor{})
}

func runReleaseSecurityScan(inputPath string, now func() time.Time, executor securityCommandExecutor) (SecurityScanResult, error) {
	inputBytes, _, err := readProtectedFile(inputPath, 1<<20, false)
	if err != nil {
		return SecurityScanResult{}, err
	}
	var input SecurityScanInput
	if err := release.DecodeCanonical(inputBytes, &input); err != nil {
		return SecurityScanResult{}, err
	}
	if err := validateSecurityScanInput(input); err != nil {
		return SecurityScanResult{}, fmt.Errorf("release security scan input is invalid: %w", err)
	}
	if now == nil || executor == nil {
		return SecurityScanResult{}, fmt.Errorf("release security scan clock or executor is invalid")
	}
	prepared, err := Prepare(input.QualificationInput)
	if err != nil {
		return SecurityScanResult{}, err
	}
	identity := prepared.Install.Identity()
	reportPath := prepared.Input.Artifacts.SecurityReport

	govulncheckDigest, err := fixedExecutableDigest(input.Govulncheck)
	if err != nil {
		return SecurityScanResult{}, err
	}
	osvScannerDigest, err := fixedExecutableDigest(input.OSVScanner)
	if err != nil {
		return SecurityScanResult{}, err
	}
	goDatabaseDigest, err := fixedDatabaseDigest(input.GoDatabase)
	if err != nil {
		return SecurityScanResult{}, err
	}
	sbomDatabaseDigest, err := fixedDatabaseDigest(input.SBOMDatabase)
	if err != nil {
		return SecurityScanResult{}, err
	}
	distroDatabaseDigest, err := fixedDatabaseDigest(input.DistroDatabase)
	if err != nil {
		return SecurityScanResult{}, err
	}

	workspace, err := os.MkdirTemp(filepath.Dir(reportPath), ".security-scan-")
	if err != nil {
		return SecurityScanResult{}, err
	}
	defer func() { _ = os.RemoveAll(workspace) }()
	if err := os.Chmod(workspace, 0o700); err != nil {
		return SecurityScanResult{}, err
	}
	for _, name := range []string{"home", "cache", "tmp"} {
		if err := os.Mkdir(filepath.Join(workspace, name), 0o700); err != nil {
			return SecurityScanResult{}, err
		}
	}
	configPath := filepath.Join(workspace, "osv-scanner.toml")
	if err := os.WriteFile(configPath, []byte(""), 0o600); err != nil {
		return SecurityScanResult{}, err
	}
	environment := []string{
		"HOME=" + filepath.Join(workspace, "home"),
		"XDG_CACHE_HOME=" + filepath.Join(workspace, "cache"),
		"TMPDIR=" + filepath.Join(workspace, "tmp"),
		"LANG=C", "LC_ALL=C", "PATH=", "GOTELEMETRY=off",
	}

	goDatabaseURL := (&url.URL{Scheme: "file", Path: input.GoDatabase.Path}).String()
	if err := verifyScannerVersions(executor, environment, workspace, input, goDatabaseURL); err != nil {
		return SecurityScanResult{}, err
	}
	govulnOutput, err := executeSecurityCommand(executor, input.Govulncheck.Path, []string{"-mode=binary", "-scan=symbol", "-format=json", "-db=" + goDatabaseURL, prepared.Input.Artifacts.CandidateBinary}, environment, workspace, 0, 3)
	if err != nil {
		return SecurityScanResult{}, fmt.Errorf("fixed govulncheck candidate scan failed: %w", err)
	}
	govulnFindings, err := decodeGovulncheckOutput(govulnOutput.Stdout, goDatabaseURL)
	if err != nil {
		return SecurityScanResult{}, err
	}

	originalSBOM, _, err := readProtectedFile(prepared.Input.Artifacts.SBOM, 16<<20, true)
	if err != nil {
		return SecurityScanResult{}, err
	}
	mappings, err := loadRepositorySourceMapping(input.RepositorySnapshot, prepared.PackageTemplate)
	if err != nil {
		return SecurityScanResult{}, err
	}
	mappedSBOMPath := filepath.Join(workspace, "source-mapped.spdx.json")
	if err := writeSourceMappedSBOM(originalSBOM, mappings, identity.Profile.Family, mappedSBOMPath); err != nil {
		return SecurityScanResult{}, err
	}
	expectedPackages, err := expectedOSVPackageInventory(mappedSBOMPath)
	if err != nil {
		return SecurityScanResult{}, err
	}
	sbomCache := filepath.Join(workspace, "sbom-feed")
	if err := writeReleaseScopedOSVCache(input.SBOMDatabase.Path, sbomCache, identity.Profile, true); err != nil {
		return SecurityScanResult{}, err
	}
	sbomOutput, err := executeOSVScan(executor, input.OSVScanner.Path, sbomCache, mappedSBOMPath, configPath, environment, workspace)
	if err != nil {
		return SecurityScanResult{}, fmt.Errorf("fixed OSV SBOM scan failed: %w", err)
	}
	sbomFindings, err := decodeOSVOutput(sbomOutput.Stdout, mappedSBOMPath, expectedPackages, "")
	if err != nil {
		return SecurityScanResult{}, err
	}
	distroEcosystem := "Debian"
	if identity.Profile.Family == "ubuntu" {
		distroEcosystem = "Ubuntu"
	}
	distroSBOMPath := filepath.Join(workspace, "distro-closure.spdx.json")
	distroPackages, err := writeDistroClosureSBOM(mappedSBOMPath, distroSBOMPath, distroEcosystem)
	if err != nil {
		return SecurityScanResult{}, err
	}
	distroCache := filepath.Join(workspace, "distro-feed")
	if err := writeReleaseScopedOSVCache(input.DistroDatabase.Path, distroCache, identity.Profile, false); err != nil {
		return SecurityScanResult{}, err
	}
	distroOutput, err := executeOSVScan(executor, input.OSVScanner.Path, distroCache, distroSBOMPath, configPath, environment, workspace)
	if err != nil {
		return SecurityScanResult{}, fmt.Errorf("fixed distro closure scan failed: %w", err)
	}
	distroFindings, err := decodeOSVOutput(distroOutput.Stdout, distroSBOMPath, distroPackages, distroEcosystem)
	if err != nil {
		return SecurityScanResult{}, err
	}

	if changed, verifyErr := fixedExecutableDigest(input.Govulncheck); verifyErr != nil {
		return SecurityScanResult{}, fmt.Errorf("cannot verify govulncheck after scan: %w", verifyErr)
	} else if changed != govulncheckDigest {
		return SecurityScanResult{}, fmt.Errorf("govulncheck executable changed during scan")
	}
	if changed, verifyErr := fixedExecutableDigest(input.OSVScanner); verifyErr != nil {
		return SecurityScanResult{}, fmt.Errorf("cannot verify OSV scanner after scan: %w", verifyErr)
	} else if changed != osvScannerDigest {
		return SecurityScanResult{}, fmt.Errorf("OSV scanner executable changed during scan")
	}
	for _, database := range []struct {
		authority FixedVulnerabilityDatabase
		digest    string
	}{{input.GoDatabase, goDatabaseDigest}, {input.SBOMDatabase, sbomDatabaseDigest}, {input.DistroDatabase, distroDatabaseDigest}} {
		if changed, verifyErr := fixedDatabaseDigest(database.authority); verifyErr != nil {
			return SecurityScanResult{}, fmt.Errorf("cannot verify fixed vulnerability database after scan: %w", verifyErr)
		} else if changed != database.digest {
			return SecurityScanResult{}, fmt.Errorf("fixed vulnerability database changed during scan")
		}
	}
	candidate, _, err := readProtectedFile(prepared.Input.Artifacts.CandidateBinary, 256<<20, false)
	if err != nil {
		return SecurityScanResult{}, err
	}
	if !bytes.Equal(candidate, prepared.CandidateBytes) {
		return SecurityScanResult{}, fmt.Errorf("qualified candidate changed during scan")
	}
	sbom, _, err := readProtectedFile(prepared.Input.Artifacts.SBOM, 16<<20, true)
	if err != nil {
		return SecurityScanResult{}, err
	}
	if !bytes.Equal(sbom, originalSBOM) {
		return SecurityScanResult{}, fmt.Errorf("qualified SBOM changed during scan")
	}

	scannedAt := now().UTC().Truncate(time.Second)
	if err := validateSecurityDatabaseFreshness(input, scannedAt); err != nil {
		return SecurityScanResult{}, err
	}
	var existingReport []byte
	if existing, _, readErr := readProtectedFile(reportPath, 16<<20, true); readErr == nil {
		prior, decodeErr := release.DecodeSecurityReport(existing)
		if decodeErr != nil {
			return SecurityScanResult{}, decodeErr
		}
		existingReport = existing
		scannedAt = prior.ScannedAt
	} else if !os.IsNotExist(readErr) {
		return SecurityScanResult{}, readErr
	}
	findings := mergeSecurityFindings(govulnFindings, sbomFindings, distroFindings)
	report := release.SecurityReport{
		SchemaVersion:            release.SecurityReportSchemaVersion,
		CandidateDigest:          identity.CandidateDigest,
		SBOMDigest:               release.DigestBytes(sbom),
		DependencyManifestDigest: identity.DependencyManifestDigest,
		TargetProfileDigest:      identity.ProfileDigest,
		ScannedAt:                scannedAt,
		Scanners: []release.ScannerIdentity{
			{Kind: "distro_security", Name: "osv-scanner", Version: PinnedOSVScannerVersion, ExecutableDigest: osvScannerDigest, DatabaseName: input.DistroDatabase.Name, DatabaseDigest: distroDatabaseDigest, DatabaseCapturedAt: input.DistroDatabase.CapturedAt, Coverage: "runtime_os_packages"},
			{Kind: "go_vulnerability", Name: "govulncheck", Version: PinnedGovulncheckVersion, ExecutableDigest: govulncheckDigest, DatabaseName: input.GoDatabase.Name, DatabaseDigest: goDatabaseDigest, DatabaseCapturedAt: input.GoDatabase.CapturedAt, Coverage: "go_binary"},
			{Kind: "sbom_osv", Name: "osv-scanner", Version: PinnedOSVScannerVersion, ExecutableDigest: osvScannerDigest, DatabaseName: input.SBOMDatabase.Name, DatabaseDigest: sbomDatabaseDigest, DatabaseCapturedAt: input.SBOMDatabase.CapturedAt, Coverage: "sbom"},
		},
		Findings: findings,
	}
	reportBytes, err := release.MarshalCanonical(report)
	if err != nil {
		return SecurityScanResult{}, err
	}
	if _, err := release.DecodeSecurityReport(reportBytes); err != nil {
		return SecurityScanResult{}, err
	}
	if existingReport != nil {
		if !bytes.Equal(existingReport, reportBytes) {
			return SecurityScanResult{}, fmt.Errorf("existing protected security report differs from repeated fixed scan")
		}
	} else {
		if err := WriteSummary(reportPath, reportBytes); err != nil {
			return SecurityScanResult{}, err
		}
		if err := sealProtectedFile(reportPath); err != nil {
			return SecurityScanResult{}, err
		}
	}
	result := SecurityScanResult{CandidateDigest: identity.CandidateDigest, SecurityReport: reportPath, SecurityReportDigest: release.DigestBytes(reportBytes), FindingCount: len(findings)}
	if err := release.CheckSecurityGate(report); err != nil {
		return result, err
	}
	return result, nil
}

func validateSecurityDatabaseFreshness(input SecurityScanInput, scannedAt time.Time) error {
	for _, database := range []FixedVulnerabilityDatabase{input.GoDatabase, input.SBOMDatabase, input.DistroDatabase} {
		if database.CapturedAt.After(scannedAt) || scannedAt.Sub(database.CapturedAt) > maximumSecurityAuthorityAge {
			return fmt.Errorf("fixed vulnerability database capture is outside its seven-day validity")
		}
	}
	return nil
}

func securityReportMatchesScanInput(report release.SecurityReport, input SecurityScanInput) bool {
	if len(report.Scanners) != 3 {
		return false
	}
	want := map[string]release.ScannerIdentity{
		"distro_security":  {Kind: "distro_security", Name: "osv-scanner", Version: PinnedOSVScannerVersion, ExecutableDigest: input.OSVScanner.Digest, DatabaseName: input.DistroDatabase.Name, DatabaseDigest: input.DistroDatabase.Digest, DatabaseCapturedAt: input.DistroDatabase.CapturedAt, Coverage: "runtime_os_packages"},
		"go_vulnerability": {Kind: "go_vulnerability", Name: "govulncheck", Version: PinnedGovulncheckVersion, ExecutableDigest: input.Govulncheck.Digest, DatabaseName: input.GoDatabase.Name, DatabaseDigest: input.GoDatabase.Digest, DatabaseCapturedAt: input.GoDatabase.CapturedAt, Coverage: "go_binary"},
		"sbom_osv":         {Kind: "sbom_osv", Name: "osv-scanner", Version: PinnedOSVScannerVersion, ExecutableDigest: input.OSVScanner.Digest, DatabaseName: input.SBOMDatabase.Name, DatabaseDigest: input.SBOMDatabase.Digest, DatabaseCapturedAt: input.SBOMDatabase.CapturedAt, Coverage: "sbom"},
	}
	for _, scanner := range report.Scanners {
		if scanner != want[scanner.Kind] {
			return false
		}
	}
	return true
}

func validateSecurityScanInput(input SecurityScanInput) error {
	if input.SchemaVersion != SecurityScanInputSchemaVersion || !absoluteCleanPath(input.QualificationInput) {
		return fmt.Errorf("schema or qualification input path is invalid")
	}
	if err := validateRepositorySnapshotFiles(input.RepositorySnapshot); err != nil {
		return err
	}
	for _, scanner := range []FixedScanner{input.Govulncheck, input.OSVScanner} {
		if !absoluteCleanPath(scanner.Path) || !release.ValidDigest(scanner.Digest) {
			return fmt.Errorf("scanner authority is invalid")
		}
	}
	for _, database := range []FixedVulnerabilityDatabase{input.GoDatabase, input.SBOMDatabase, input.DistroDatabase} {
		if !securityReferencePattern.MatchString(database.Name) || !absoluteCleanPath(database.Path) || !release.ValidDigest(database.Digest) || database.CapturedAt.IsZero() || !database.CapturedAt.Equal(database.CapturedAt.UTC().Truncate(time.Second)) {
			return fmt.Errorf("vulnerability database authority is invalid")
		}
	}
	return nil
}

var securityReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

func absoluteCleanPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func fixedExecutableDigest(scanner FixedScanner) (string, error) {
	if !absoluteCleanPath(scanner.Path) || !release.ValidDigest(scanner.Digest) {
		return "", fmt.Errorf("fixed scanner authority is invalid")
	}
	info, err := os.Lstat(scanner.Path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > 512<<20 {
		return "", fmt.Errorf("fixed scanner executable type, mode, or size is invalid")
	}
	data, err := os.ReadFile(scanner.Path)
	if err != nil {
		return "", err
	}
	digest := release.DigestBytes(data)
	if digest != scanner.Digest {
		return "", fmt.Errorf("fixed scanner executable digest differs")
	}
	return digest, nil
}

func FixedVulnerabilityDatabaseDigest(path string) (string, error) {
	if !absoluteCleanPath(path) {
		return "", fmt.Errorf("fixed vulnerability database path is invalid")
	}
	root, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !root.IsDir() || root.Mode().Perm()&0o277 != 0 || ownerUID(root) != uint32(os.Geteuid()) {
		return "", fmt.Errorf("fixed vulnerability database root is not owner-only and read-only")
	}
	hash := sha256.New()
	entries := 0
	err = filepath.WalkDir(path, func(memberPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(memberPath)
		if err != nil {
			return err
		}
		if ownerUID(info) != uint32(os.Geteuid()) || info.Mode().Perm()&0o277 != 0 {
			return fmt.Errorf("fixed vulnerability database member is not owner-only and read-only")
		}
		relative, err := filepath.Rel(path, memberPath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		entries++
		if entries > 2_000_000 || !release.ValidRelativePath(relative) {
			return fmt.Errorf("fixed vulnerability database inventory is invalid or unbounded")
		}
		kind := byte('d')
		if !entry.IsDir() {
			if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<30 {
				return fmt.Errorf("fixed vulnerability database contains a non-regular or unbounded member")
			}
			kind = 'f'
		}
		writeDigestField(hash, []byte{kind})
		writeDigestField(hash, []byte(relative))
		if kind == 'f' {
			file, err := os.Open(memberPath)
			if err != nil {
				return err
			}
			memberHash := sha256.New()
			written, copyErr := io.Copy(memberHash, io.LimitReader(file, info.Size()+1))
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written != info.Size() {
				return errors.Join(copyErr, closeErr, fmt.Errorf("fixed vulnerability database member changed while hashing"))
			}
			writeDigestField(hash, memberHash.Sum(nil))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if entries == 0 {
		return "", fmt.Errorf("fixed vulnerability database is empty")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fixedDatabaseDigest(database FixedVulnerabilityDatabase) (string, error) {
	if !release.ValidDigest(database.Digest) {
		return "", fmt.Errorf("fixed vulnerability database authority is invalid")
	}
	digest, err := FixedVulnerabilityDatabaseDigest(database.Path)
	if err != nil {
		return "", err
	}
	if digest != database.Digest {
		return "", fmt.Errorf("fixed vulnerability database digest differs")
	}
	return digest, nil
}

func ownerUID(info os.FileInfo) uint32 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ^uint32(0)
	}
	return stat.Uid
}

func writeDigestField(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func verifyScannerVersions(executor securityCommandExecutor, environment []string, workspace string, input SecurityScanInput, goDatabaseURL string) error {
	govulncheck, err := executeSecurityCommand(executor, input.Govulncheck.Path, []string{"-db=" + goDatabaseURL, "-version"}, environment, workspace, 0)
	if err != nil {
		return fmt.Errorf("cannot verify fixed govulncheck version: %w", err)
	}
	if !containsExactLine(govulncheck.Stdout, "Scanner: govulncheck@v"+PinnedGovulncheckVersion) {
		return fmt.Errorf("fixed govulncheck version differs")
	}
	osv, err := executeSecurityCommand(executor, input.OSVScanner.Path, []string{"--version"}, environment, workspace, 0)
	if err != nil {
		return fmt.Errorf("cannot verify fixed OSV scanner version: %w", err)
	}
	if !containsExactLine(osv.Stdout, "osv-scanner version: "+PinnedOSVScannerVersion) {
		return fmt.Errorf("fixed OSV scanner version differs")
	}
	return nil
}

func containsExactLine(data []byte, expected string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if line == expected {
			return true
		}
	}
	return false
}

func executeSecurityCommand(executor securityCommandExecutor, path string, arguments, environment []string, directory string, allowedExitCodes ...int) (securityCommandOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), securityScanTimeout)
	defer cancel()
	output, err := executor.Run(ctx, securityCommand{Path: path, Arguments: append([]string(nil), arguments...), Environment: append([]string(nil), environment...), Directory: directory})
	if err != nil {
		return securityCommandOutput{}, err
	}
	for _, code := range allowedExitCodes {
		if output.ExitCode == code {
			return output, nil
		}
	}
	return securityCommandOutput{}, fmt.Errorf("scanner exited %d: %s", output.ExitCode, strings.TrimSpace(string(output.Stderr)))
}

func executeOSVScan(executor securityCommandExecutor, scannerPath, databasePath, sbomPath, configPath string, environment []string, workspace string) (securityCommandOutput, error) {
	arguments := []string{"scan", "source", "--sbom=" + sbomPath, "--config=" + configPath, "--format=json", "--offline", "--offline-vulnerabilities", "--no-resolve", "--all-packages", "--local-db-path=" + databasePath, "--verbosity=error"}
	return executeSecurityCommand(executor, scannerPath, arguments, environment, workspace, 0, 1)
}

type govulncheckMessage struct {
	Config *struct {
		ProtocolVersion string `json:"protocol_version"`
		ScannerName     string `json:"scanner_name"`
		ScannerVersion  string `json:"scanner_version"`
		Database        string `json:"db"`
		ScanLevel       string `json:"scan_level"`
		ScanMode        string `json:"scan_mode"`
	} `json:"config,omitempty"`
	SBOM *struct {
		GoVersion string `json:"go_version"`
		Modules   []struct {
			Path    string `json:"path"`
			Version string `json:"version"`
		} `json:"modules"`
	} `json:"SBOM,omitempty"`
	Finding *struct {
		OSV   string `json:"osv"`
		Trace []struct {
			Module   string `json:"module"`
			Package  string `json:"package"`
			Function string `json:"function"`
		} `json:"trace"`
	} `json:"finding,omitempty"`
}

func decodeGovulncheckOutput(data []byte, expectedDatabase string) ([]release.SecurityFinding, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	configSeen, sbomSeen := false, false
	findings := []release.SecurityFinding{}
	for {
		var message govulncheckMessage
		err := decoder.Decode(&message)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("govulncheck emitted invalid JSON: %w", err)
		}
		if message.Config != nil {
			if configSeen || message.Config.ProtocolVersion != "v1.0.0" || message.Config.ScannerName != "govulncheck" || message.Config.ScannerVersion != "v"+PinnedGovulncheckVersion || message.Config.Database != expectedDatabase || message.Config.ScanLevel != "symbol" || message.Config.ScanMode != "binary" {
				return nil, fmt.Errorf("govulncheck output does not attest the fixed binary scan")
			}
			configSeen = true
		}
		if message.SBOM != nil {
			if sbomSeen || message.SBOM.GoVersion == "" || len(message.SBOM.Modules) == 0 {
				return nil, fmt.Errorf("govulncheck output omits the candidate module inventory")
			}
			sbomSeen = true
		}
		if message.Finding != nil {
			if message.Finding.OSV == "" || len(message.Finding.Trace) == 0 || message.Finding.Trace[0].Module == "" {
				return nil, fmt.Errorf("govulncheck finding identity is incomplete")
			}
			frame := message.Finding.Trace[0]
			// Binary/symbol mode also emits module- and package-level notices.
			// They remain closure findings (and still block the security gate),
			// but only a function-level trace supplies symbol reachability evidence.
			findings = append(findings, release.SecurityFinding{ID: message.Finding.OSV, Component: frame.Module, Severity: release.SeverityHigh, InShippedClosure: true, RuntimeReachable: frame.Package != "" && frame.Function != "", Resolution: release.ResolutionUnresolved})
		}
	}
	if !configSeen || !sbomSeen {
		return nil, fmt.Errorf("govulncheck output is incomplete")
	}
	return findings, nil
}

type osvPackageIdentity struct {
	Name      string
	Version   string
	Ecosystem string
}

func (identity osvPackageIdentity) key() string {
	return identity.Ecosystem + "\x00" + identity.Name + "\x00" + identity.Version
}

func expectedOSVPackageInventory(sbomPath string) (map[string]osvPackageIdentity, error) {
	data, _, err := readProtectedFile(sbomPath, 16<<20, true)
	if err != nil {
		return nil, err
	}
	var document release.SPDXDocument
	if err := release.DecodeCanonical(data, &document); err != nil {
		return nil, err
	}
	expected := make(map[string]osvPackageIdentity, len(document.Packages)-1)
	for _, pkg := range document.Packages {
		if pkg.SPDXID == "SPDXRef-Package-lanpanel" {
			continue
		}
		if len(pkg.ExternalRefs) != 1 {
			return nil, fmt.Errorf("SBOM package %q is not scanner-addressable", pkg.SPDXID)
		}
		identity, err := osvIdentityFromPURL(pkg.ExternalRefs[0].ReferenceLocator)
		if err != nil {
			return nil, err
		}
		if _, duplicate := expected[identity.key()]; duplicate {
			return nil, fmt.Errorf("SBOM scanner package identity is duplicated")
		}
		expected[identity.key()] = identity
	}
	if len(expected) == 0 {
		return nil, fmt.Errorf("SBOM has no scanner-addressable closure")
	}
	return expected, nil
}

func writeDistroClosureSBOM(sourcePath, outputPath, ecosystem string) (map[string]osvPackageIdentity, error) {
	data, _, err := readProtectedFile(sourcePath, 16<<20, true)
	if err != nil {
		return nil, err
	}
	var document release.SPDXDocument
	if err := release.DecodeCanonical(data, &document); err != nil {
		return nil, err
	}
	packages := make([]release.SPDXPackage, 0)
	expected := map[string]osvPackageIdentity{}
	for _, pkg := range document.Packages {
		if len(pkg.ExternalRefs) != 1 {
			continue
		}
		identity, err := osvIdentityFromPURL(pkg.ExternalRefs[0].ReferenceLocator)
		if err != nil || identity.Ecosystem != ecosystem {
			continue
		}
		packages = append(packages, pkg)
		expected[identity.key()] = identity
	}
	if len(packages) == 0 || len(packages) != len(expected) {
		return nil, fmt.Errorf("exact SBOM omits or duplicates the qualified distro package closure")
	}
	document.Name += "-distro-closure"
	document.DocumentNamespace += "/distro-closure"
	document.Packages = packages
	document.Relationships = make([]release.SPDXRelationship, len(packages))
	for index, pkg := range packages {
		document.Relationships[index] = release.SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkg.SPDXID}
	}
	encoded, err := release.MarshalCanonical(document)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(outputPath, encoded, 0o400); err != nil {
		return nil, err
	}
	return expected, nil
}

func osvIdentityFromPURL(value string) (osvPackageIdentity, error) {
	var ecosystem, remainder string
	switch {
	case strings.HasPrefix(value, "pkg:golang/"):
		ecosystem, remainder = "Go", strings.TrimPrefix(value, "pkg:golang/")
	case strings.HasPrefix(value, "pkg:deb/debian/"):
		ecosystem, remainder = "Debian", strings.TrimPrefix(value, "pkg:deb/debian/")
	case strings.HasPrefix(value, "pkg:deb/ubuntu/"):
		ecosystem, remainder = "Ubuntu", strings.TrimPrefix(value, "pkg:deb/ubuntu/")
	default:
		return osvPackageIdentity{}, fmt.Errorf("SBOM package URL ecosystem is unsupported")
	}
	separator := strings.LastIndexByte(remainder, '@')
	if separator <= 0 || separator == len(remainder)-1 {
		return osvPackageIdentity{}, fmt.Errorf("SBOM package URL identity is incomplete")
	}
	name, nameErr := url.PathUnescape(remainder[:separator])
	version, versionErr := url.PathUnescape(remainder[separator+1:])
	if nameErr != nil || versionErr != nil || name == "" || version == "" {
		return osvPackageIdentity{}, fmt.Errorf("SBOM package URL encoding is invalid")
	}
	return osvPackageIdentity{Name: name, Version: version, Ecosystem: ecosystem}, nil
}

type osvScannerOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
			Groups []struct {
				IDs         []string `json:"ids"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

func decodeOSVOutput(data []byte, sbomPath string, expected map[string]osvPackageIdentity, findingEcosystem string) ([]release.SecurityFinding, error) {
	var output osvScannerOutput
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&output); err != nil {
		return nil, fmt.Errorf("OSV scanner emitted invalid JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF || len(output.Results) != 1 || output.Results[0].Source.Type != "sbom" || filepath.Clean(output.Results[0].Source.Path) != sbomPath {
		return nil, fmt.Errorf("OSV scanner output does not bind the exact SBOM")
	}
	observed := make(map[string]bool, len(output.Results[0].Packages))
	findings := []release.SecurityFinding{}
	for _, pkg := range output.Results[0].Packages {
		identity := osvPackageIdentity{Name: pkg.Package.Name, Version: pkg.Package.Version, Ecosystem: pkg.Package.Ecosystem}
		key := identity.key()
		if _, present := expected[key]; !present || observed[key] {
			return nil, fmt.Errorf("OSV scanner package inventory differs from the exact SBOM closure")
		}
		observed[key] = true
		severityByID := map[string]release.Severity{}
		for _, group := range pkg.Groups {
			severity := osvSeverity(group.MaxSeverity)
			for _, id := range group.IDs {
				severityByID[id] = severity
			}
		}
		for _, vulnerability := range pkg.Vulnerabilities {
			if vulnerability.ID == "" {
				return nil, fmt.Errorf("OSV scanner finding identity is incomplete")
			}
			if findingEcosystem != "" && identity.Ecosystem != findingEcosystem {
				continue
			}
			severity := severityByID[vulnerability.ID]
			if severity == "" {
				severity = release.SeverityHigh
			}
			findings = append(findings, release.SecurityFinding{ID: vulnerability.ID, Component: identity.Name, Severity: severity, InShippedClosure: true, RuntimeReachable: identity.Ecosystem == "Debian" || identity.Ecosystem == "Ubuntu", Resolution: release.ResolutionUnresolved})
		}
	}
	if len(observed) != len(expected) {
		return nil, fmt.Errorf("OSV scanner omitted part of the exact SBOM or distro package closure")
	}
	return findings, nil
}

func osvSeverity(value string) release.Severity {
	score, err := strconv.ParseFloat(value, 64)
	if err != nil || score < 0 || score > 10 {
		return release.SeverityHigh
	}
	switch {
	case score >= 9:
		return release.SeverityCritical
	case score >= 7:
		return release.SeverityHigh
	case score >= 4:
		return release.SeverityMedium
	default:
		return release.SeverityLow
	}
}

func mergeSecurityFindings(groups ...[]release.SecurityFinding) []release.SecurityFinding {
	merged := map[string]release.SecurityFinding{}
	for _, group := range groups {
		for _, finding := range group {
			key := finding.ID + "\x00" + finding.Component
			prior, present := merged[key]
			if !present {
				merged[key] = finding
				continue
			}
			prior.InShippedClosure = prior.InShippedClosure || finding.InShippedClosure
			prior.RuntimeReachable = prior.RuntimeReachable || finding.RuntimeReachable
			if severityRank(finding.Severity) > severityRank(prior.Severity) {
				prior.Severity = finding.Severity
			}
			merged[key] = prior
		}
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	findings := make([]release.SecurityFinding, 0, len(keys))
	for _, key := range keys {
		findings = append(findings, merged[key])
	}
	return findings
}

func severityRank(severity release.Severity) int {
	switch severity {
	case release.SeverityCritical:
		return 4
	case release.SeverityHigh:
		return 3
	case release.SeverityMedium:
		return 2
	case release.SeverityLow:
		return 1
	default:
		return 0
	}
}
