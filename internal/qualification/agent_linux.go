//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/child"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
)

const (
	AgentRequestSchemaVersion  = "lanpanel.qualification.agent-request.v1"
	AgentResponseSchemaVersion = "lanpanel.qualification.agent-response.v1"
	maximumAgentRequestBytes   = 40 << 20
)

type AgentAction string

const (
	AgentPackagePreflight AgentAction = "package_preflight"
	AgentInstall          AgentAction = "install"
	AgentRestartUI        AgentAction = "restart_ui"
	AgentReboot           AgentAction = "reboot"
	AgentSetupFixture     AgentAction = "setup_fixture"
	AgentSetupDNSProfile  AgentAction = "setup_dns_profile"
	AgentCleanupFixture   AgentAction = "cleanup_fixture"
	AgentSecretSentinel   AgentAction = "secret_sentinel"
	AgentFinalInventory   AgentAction = "final_inventory"
	AgentMagicDNSProbe    AgentAction = "magicdns_probe"
)

type AgentRequest struct {
	SchemaVersion      string      `json:"schema_version"`
	RunID              string      `json:"run_id"`
	Action             AgentAction `json:"action"`
	CandidateDigest    string      `json:"candidate_digest"`
	TargetProfile      []byte      `json:"target_profile,omitempty"`
	InstallManifest    []byte      `json:"install_manifest,omitempty"`
	SideEffectPlan     []byte      `json:"side_effect_plan,omitempty"`
	InstallerAuthority []byte      `json:"installer_authority,omitempty"`
	Provider           string      `json:"provider,omitempty"`
	Secret             []byte      `json:"secret,omitempty"`
	Secrets            [][]byte    `json:"secrets,omitempty"`
	ProbeName          string      `json:"probe_name,omitempty"`
	ExpectedIP         string      `json:"expected_ip,omitempty"`
}

type AgentResponse struct {
	SchemaVersion string           `json:"schema_version"`
	RunID         string           `json:"run_id"`
	Action        AgentAction      `json:"action"`
	Succeeded     bool             `json:"succeeded"`
	Evidence      string           `json:"evidence"`
	ErrorCode     string           `json:"error_code,omitempty"`
	Preflight     preflight.Result `json:"preflight,omitempty"`
}

func RunAgentRole(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 0 || stdin == nil || stdout == nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("qualification agent requires its fixed root invocation")
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maximumAgentRequestBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumAgentRequestBytes {
		return fmt.Errorf("qualification agent request is missing or unbounded")
	}
	var request AgentRequest
	if err := release.DecodeCanonical(data, &request); err != nil {
		return err
	}
	if request.SchemaVersion != AgentRequestSchemaVersion || request.RunID == "" || !release.ValidDigest(request.CandidateDigest) {
		return fmt.Errorf("qualification agent request authority is invalid")
	}
	if err := verifyRunningCandidate(request.CandidateDigest); err != nil {
		return err
	}
	defer clearBytes(request.Secret)
	defer func() {
		for _, secret := range request.Secrets {
			clearBytes(secret)
		}
	}()
	response := AgentResponse{SchemaVersion: AgentResponseSchemaVersion, RunID: request.RunID, Action: request.Action}
	switch request.Action {
	case AgentPackagePreflight:
		if len(request.TargetProfile) == 0 || len(request.InstallManifest) == 0 || len(request.SideEffectPlan) == 0 || len(request.InstallerAuthority) != 0 {
			return fmt.Errorf("package preflight request shape is invalid")
		}
		result, evidence, runErr := runPackagePreflight(request)
		response.Preflight = result
		response.Evidence = evidence
		response.Succeeded = runErr == nil
		if runErr != nil {
			response.ErrorCode = "package_preflight_blocked"
		}
	case AgentInstall:
		if len(request.InstallerAuthority) == 0 || len(request.TargetProfile) != 0 || len(request.InstallManifest) != 0 || len(request.SideEffectPlan) != 0 {
			return fmt.Errorf("installer agent request shape is invalid")
		}
		var output bytes.Buffer
		runErr := bootstrap.RunQualificationInstallerAuthority(request.InstallerAuthority, &output)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes(output.Bytes())
		if runErr != nil {
			response.ErrorCode = "qualification_install_failed"
		}
	case AgentRestartUI:
		if carriesAgentPayload(request) {
			return fmt.Errorf("UI restart request carries unrelated authority")
		}
		runErr := runQualificationProfile(child.ProfileQualificationUIRestart)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("systemctl/restart/lanpanel-ui.service"))
		if runErr != nil {
			response.ErrorCode = "ui_restart_failed"
		}
	case AgentReboot:
		if carriesAgentPayload(request) {
			return fmt.Errorf("reboot request carries unrelated authority")
		}
		runErr := runQualificationProfile(child.ProfileQualificationReboot)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("systemctl/reboot"))
		if runErr != nil {
			response.ErrorCode = "reboot_submission_failed"
		}
	case AgentSetupFixture:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) < 16 || len(request.Secret) > 256 {
			return fmt.Errorf("fixture setup request shape is invalid")
		}
		runErr := setupQualificationFixture(request.RunID, request.Secret)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("fixture/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "fixture_setup_failed"
		}
	case AgentSetupDNSProfile:
		if carriesCoreAgentPayload(request) || request.Provider != "cloudflare" || len(request.Secret) < 20 || len(request.Secret) > 4096 {
			return fmt.Errorf("DNS profile setup request shape is invalid")
		}
		runErr := setupQualificationDNSProfile(request.RunID, request.Provider, request.Secret)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("dns-profile/" + request.RunID + "/" + request.Provider))
		if runErr != nil {
			response.ErrorCode = "dns_profile_setup_failed"
		}
	case AgentCleanupFixture:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 {
			return fmt.Errorf("fixture cleanup request shape is invalid")
		}
		runErr := cleanupQualificationFixture(request.RunID)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("fixture-cleanup/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "fixture_cleanup_failed"
		}
	case AgentSecretSentinel:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) == 0 || len(request.Secrets) > 8 {
			return fmt.Errorf("secret sentinel request shape is invalid")
		}
		runErr := runSecretSentinel(request.Secrets)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("secret-sentinel/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "secret_residue_detected"
		}
	case AgentFinalInventory:
		if carriesAgentPayload(request) {
			return fmt.Errorf("final inventory request shape is invalid")
		}
		runErr := verifyQualificationFinalInventory(request.RunID)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("final-inventory/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "final_inventory_incomplete"
		}
	case AgentMagicDNSProbe:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 || !canonicalDomain(request.ProbeName) || net.ParseIP(request.ExpectedIP) == nil {
			return fmt.Errorf("MagicDNS probe request shape is invalid")
		}
		addresses, lookupErr := net.DefaultResolver.LookupHost(context.Background(), request.ProbeName)
		matched := false
		for _, address := range addresses {
			matched = matched || address == request.ExpectedIP
		}
		response.Succeeded = lookupErr == nil && matched
		response.Evidence = release.DigestBytes([]byte("magicdns/" + request.ProbeName + "/" + request.ExpectedIP))
		if !response.Succeeded {
			response.ErrorCode = "magicdns_probe_failed"
		}
	default:
		return fmt.Errorf("qualification agent action is not fixed")
	}
	encoded, err := release.MarshalCanonical(response)
	if err != nil {
		return err
	}
	_, err = stdout.Write(encoded)
	return err
}

func DecodeAgentResponse(data []byte, runID string, action AgentAction) (AgentResponse, error) {
	var response AgentResponse
	if err := release.DecodeCanonical(data, &response); err != nil {
		return AgentResponse{}, err
	}
	if response.SchemaVersion != AgentResponseSchemaVersion || response.RunID != runID || response.Action != action || !release.ValidDigest(response.Evidence) || response.Succeeded && response.ErrorCode != "" || !response.Succeeded && response.ErrorCode == "" {
		return AgentResponse{}, fmt.Errorf("qualification agent response authority is invalid")
	}
	if action == AgentPackagePreflight {
		if _, err := response.Preflight.Digest(); err != nil {
			return AgentResponse{}, err
		}
	} else if !reflectZeroPreflight(response.Preflight) {
		return AgentResponse{}, fmt.Errorf("qualification agent response carries unrelated preflight")
	}
	return response, nil
}

func runPackagePreflight(request AgentRequest) (preflight.Result, string, error) {
	target, err := release.DecodeQualificationTargetProfile(request.TargetProfile)
	if err != nil {
		return preflight.Result{}, "", err
	}
	manifest, err := release.DecodeQualificationInstallManifest(request.InstallManifest)
	if err != nil {
		return preflight.Result{}, "", err
	}
	plan, err := release.DecodeLiveSideEffectPlan(request.SideEffectPlan)
	if err != nil {
		return preflight.Result{}, "", err
	}
	host, err := bootstrap.ObserveHostFingerprint()
	if err != nil || release.ValidateQualificationBinding(manifest, target, plan, host) != nil || manifest.RunID != request.RunID || manifest.CandidateBinary.Digest != request.CandidateDigest {
		return preflight.Result{}, "", fmt.Errorf("qualification agent authority differs from target host: %w", err)
	}
	profileDigest, _ := release.ProfileDigest(target.Profile)
	confinement := target.Profile.ManagedConfinement
	expected := preflight.ExpectedProfile{ID: target.Profile.Family, VersionID: target.Profile.Release, Architecture: "amd64", SystemdVersion: target.Profile.SystemdVersion, NginxVersion: target.Profile.NginxVersion, PackageSnapshotDigest: "sha256:" + target.Profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: preflight.ProfileAuthority{Kind: preflight.QualificationTarget, Digest: "sha256:" + profileDigest, CandidateDigest: "sha256:" + manifest.CandidateBinary.Digest, InstallManifestDigest: "sha256:" + release.DigestBytes(request.InstallManifest), SideEffectPlanDigest: "sha256:" + release.DigestBytes(request.SideEffectPlan), HostFingerprint: host, RunID: request.RunID}}
	preflightRequest := preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: 1, Profile: expected, ManagedPaths: bootstrap.FixedManagedPathRequirements(bootstrap.FixedPaths()), Disks: bootstrap.FixedDiskRequirements(bootstrap.FixedPaths()), LastTrustedWall: manifest.CreatedAt}
	observer, err := preflight.NewLinuxObserver(func(ctx context.Context) (preflight.PackageObservation, error) {
		return preflight.ObserveBootstrapReadiness(ctx)
	})
	if err != nil {
		return preflight.Result{}, "", err
	}
	observed, err := observer.ObserveExpansion(context.Background(), preflightRequest)
	if err != nil {
		return preflight.Result{}, "", err
	}
	result, evaluateErr := preflight.EvaluateExpansion(preflightRequest, observed)
	evidenceBytes, _ := json.Marshal(struct {
		RequestDigest string `json:"request_digest"`
		ResultDigest  string `json:"result_digest"`
	}{result.RequestDigest, func() string { value, _ := result.Digest(); return value }()})
	return result, release.DigestBytes(evidenceBytes), evaluateErr
}

func verifyRunningCandidate(expected string) error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (256<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > 256<<20 || release.DigestBytes(data) != expected {
		return errors.Join(readErr, closeErr, fmt.Errorf("qualification agent binary differs from candidate authority"))
	}
	return nil
}

func carriesCoreAgentPayload(request AgentRequest) bool {
	return len(request.TargetProfile) != 0 || len(request.InstallManifest) != 0 || len(request.SideEffectPlan) != 0 || len(request.InstallerAuthority) != 0
}

func carriesAgentPayload(request AgentRequest) bool {
	return carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 || request.ProbeName != "" || request.ExpectedIP != ""
}

type QualificationFixturePaths struct {
	StaticRoot string
	StaticFile string
	HTPasswd   string
	DNSToken   string
	DNSProfile string
	SrvRunRoot string
	EtcRunRoot string
}

func FixedQualificationFixturePaths(runID string) (QualificationFixturePaths, error) {
	if !strings.HasPrefix(runID, "run_") || len(runID) != 68 || !lowerHex(strings.TrimPrefix(runID, "run_")) {
		return QualificationFixturePaths{}, fmt.Errorf("qualification fixture run identity is invalid")
	}
	srv := filepath.Join("/srv/lanpanel-qualification", runID)
	etc := filepath.Join("/etc/lanpanel-qualification", runID)
	return QualificationFixturePaths{StaticRoot: filepath.Join(srv, "static"), StaticFile: filepath.Join(srv, "static", "live.txt"), HTPasswd: filepath.Join(etc, "dashboard.htpasswd"), DNSToken: filepath.Join(etc, "cloudflare.token"), DNSProfile: filepath.Join(etc, "cloudflare.env"), SrvRunRoot: srv, EtcRunRoot: etc}, nil
}

func setupQualificationFixture(runID string, password []byte) error {
	identity, err := bootstrap.ReadCommittedInstallIdentity(bootstrap.FixedPaths())
	if err != nil || identity.Kind != release.InstallQualification || identity.RunID != runID {
		return fmt.Errorf("qualification fixture requires its exact installed run: %w", err)
	}
	paths, err := FixedQualificationFixturePaths(runID)
	if err != nil {
		return err
	}
	for _, base := range []string{"/srv/lanpanel-qualification", "/etc/lanpanel-qualification"} {
		if _, err := os.Lstat(base); err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("qualification fixture base prior state is not absent")
		}
	}
	for _, directory := range []string{"/srv/lanpanel-qualification", paths.SrvRunRoot, paths.StaticRoot, "/etc/lanpanel-qualification", paths.EtcRunRoot} {
		if err := ensureRootDirectory(directory, 0o755); err != nil {
			return err
		}
	}
	if err := writeRootExact(paths.StaticFile, []byte("lanpanel-live-static\n"), 0o644, 0); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword(password, 12)
	if err != nil {
		return err
	}
	encoded := strings.Replace(string(hash), "$2a$", "$2y$", 1)
	group, err := user.LookupGroup("www-data")
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || gid == 0 {
		return fmt.Errorf("qualification fixture www-data group is invalid")
	}
	return writeRootExact(paths.HTPasswd, []byte("ga-dashboard:"+encoded+"\n"), 0o440, int(gid))
}

func setupQualificationDNSProfile(runID, provider string, token []byte) error {
	identity, err := bootstrap.ReadCommittedInstallIdentity(bootstrap.FixedPaths())
	if err != nil || identity.Kind != release.InstallQualification || identity.RunID != runID || provider != "cloudflare" || bytes.ContainsAny(token, "\x00\r\n ") {
		return fmt.Errorf("qualification DNS profile requires its exact installed run: %w", err)
	}
	paths, err := FixedQualificationFixturePaths(runID)
	if err != nil {
		return err
	}
	for _, directory := range []string{"/etc/lanpanel-qualification", paths.EtcRunRoot} {
		if err := ensureRootDirectory(directory, 0o755); err != nil {
			return err
		}
	}
	if err := writeRootExact(paths.DNSToken, token, 0o600, 0); err != nil {
		return err
	}
	return writeRootExact(paths.DNSProfile, []byte("CF_DNS_API_TOKEN_FILE="+paths.DNSToken+"\n"), 0o600, 0)
}

func cleanupQualificationFixture(runID string) error {
	paths, err := FixedQualificationFixturePaths(runID)
	if err != nil {
		return err
	}
	for _, path := range []string{paths.DNSProfile, paths.DNSToken, paths.HTPasswd, paths.StaticFile} {
		info, statErr := os.Lstat(path)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("qualification fixture cleanup found ambiguous file: %w", statErr)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	for _, directory := range []string{paths.StaticRoot, paths.SrvRunRoot, paths.EtcRunRoot, "/srv/lanpanel-qualification", "/etc/lanpanel-qualification"} {
		entries, readErr := os.ReadDir(directory)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil || len(entries) != 0 {
			return fmt.Errorf("qualification fixture cleanup found unexplained residue: %w", readErr)
		}
		if err := os.Remove(directory); err != nil {
			return err
		}
	}
	return nil
}

func ensureRootDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return fmt.Errorf("qualification fixture directory is unsafe: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("qualification fixture directory owner is unsafe")
	}
	return nil
}

func writeRootExact(path string, data []byte, mode uint32, gid int) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("qualification fixture descriptor is invalid")
	}
	if gid != 0 {
		if err := file.Chown(0, gid); err != nil {
			_ = file.Close()
			return err
		}
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(data) {
		return errors.Join(writeErr, syncErr, closeErr, fmt.Errorf("qualification fixture write was incomplete"))
	}
	return nil
}

func runSecretSentinel(secrets [][]byte) error {
	for _, secret := range secrets {
		if len(secret) < 8 || len(secret) > 4096 || bytes.IndexByte(secret, 0) >= 0 {
			return fmt.Errorf("secret sentinel value is invalid")
		}
	}
	visited := 0
	for _, root := range []string{"/var/lib/lanpanel", "/etc/lanpanel", "/run/lanpanel", "/etc/systemd/system"} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			visited++
			if visited > 20_000 {
				return fmt.Errorf("secret sentinel inventory is unbounded")
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			info, err := entry.Info()
			if err != nil || info.Size() < 0 || info.Size() > 4<<20 {
				return fmt.Errorf("secret sentinel file is unreadable or unbounded: %w", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || int64(len(data)) != info.Size() {
				return fmt.Errorf("secret sentinel file changed: %w", err)
			}
			for _, secret := range secrets {
				if bytes.Contains(data, secret) {
					clearBytes(data)
					return fmt.Errorf("secret residue found in managed inventory")
				}
			}
			clearBytes(data)
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func verifyQualificationFinalInventory(runID string) error {
	identity, err := bootstrap.ReadCommittedInstallIdentity(bootstrap.FixedPaths())
	if err != nil || identity.Kind != release.InstallQualification || identity.RunID != runID {
		return fmt.Errorf("final inventory installation authority differs: %w", err)
	}
	paths, err := FixedQualificationFixturePaths(runID)
	if err != nil {
		return err
	}
	for _, path := range []string{paths.StaticFile, paths.StaticRoot, paths.HTPasswd, paths.DNSToken, paths.DNSProfile, paths.SrvRunRoot, paths.EtcRunRoot, "/srv/lanpanel-qualification", "/etc/lanpanel-qualification"} {
		if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("qualification fixture residue remains")
		}
	}
	result, err := runQualificationProfileResult(child.ProfileQualificationServices)
	if err != nil {
		return err
	}
	states := strings.Fields(string(result.Stdout))
	if len(states) != 5 {
		return fmt.Errorf("qualification retained service inventory is incomplete")
	}
	for _, state := range states {
		if state != "active" {
			return fmt.Errorf("qualification retained service is not active")
		}
	}
	return nil
}

func runQualificationProfile(profile child.ProfileID) error {
	_, err := runQualificationProfileResult(profile)
	return err
}

func runQualificationProfileResult(profile child.ProfileID) (child.Result, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return child.Result{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := launcher.Run(ctx, profile, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return result, fmt.Errorf("fixed qualification system action failed: %w", err)
	}
	return result, nil
}

func reflectZeroPreflight(value preflight.Result) bool {
	return value.SchemaVersion == "" && value.Scope == "" && value.Target == "" && value.Generation == 0 && value.RequestDigest == "" && !value.Allowed && value.ObservedAt.IsZero() && value.ValidUntil.IsZero() && len(value.Findings) == 0
}
