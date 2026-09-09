//go:build linux

package qualification

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/certificates"
	"lanpanel/internal/child"
	"lanpanel/internal/identity"
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
	AgentRequestSchemaVersion  = "lanpanel.qualification.agent-request.v3"
	AgentResponseSchemaVersion = "lanpanel.qualification.agent-response.v3"
	maximumAgentRequestBytes   = 40 << 20
)

type AgentAction string

const (
	AgentInstall             AgentAction = "install"
	AgentRestartUI           AgentAction = "restart_ui"
	AgentReboot              AgentAction = "reboot"
	AgentSetupFixture        AgentAction = "setup_fixture"
	AgentSetupDNSProfile     AgentAction = "setup_dns_profile"
	AgentCleanupFixture      AgentAction = "cleanup_fixture"
	AgentCleanupCertificates AgentAction = "cleanup_certificates"
	AgentSecretSentinel      AgentAction = "secret_sentinel"
	AgentFinalInventory      AgentAction = "final_inventory"
	AgentMagicDNSProbe       AgentAction = "magicdns_probe"
)

type AgentRequest struct {
	SchemaVersion      string                             `json:"schema_version"`
	RunID              string                             `json:"run_id"`
	Action             AgentAction                        `json:"action"`
	CandidateDigest    string                             `json:"candidate_digest"`
	InstallerAuthority []byte                             `json:"installer_authority,omitempty"`
	Provider           string                             `json:"provider,omitempty"`
	Secret             []byte                             `json:"secret,omitempty"`
	Secrets            [][]byte                           `json:"secrets,omitempty"`
	ProbeName          string                             `json:"probe_name,omitempty"`
	ExpectedIP         string                             `json:"expected_ip,omitempty"`
	Certificates       []qualificationCertificateArtifact `json:"certificates,omitempty"`
}

type AgentResponse struct {
	SchemaVersion        string                 `json:"schema_version"`
	RunID                string                 `json:"run_id"`
	Action               AgentAction            `json:"action"`
	Succeeded            bool                   `json:"succeeded"`
	Evidence             string                 `json:"evidence"`
	ErrorCode            string                 `json:"error_code,omitempty"`
	Preflight            preflight.Result       `json:"preflight,omitempty"`
	ObservedPackageTuple []release.PackageTuple `json:"observed_package_tuple,omitempty"`
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
	case AgentInstall:
		if len(request.InstallerAuthority) == 0 || len(request.Certificates) != 0 {
			return fmt.Errorf("installer agent request shape is invalid")
		}
		var output bytes.Buffer
		result, runErr := bootstrap.RunQualificationInstallerAuthority(request.InstallerAuthority, request.RunID, request.CandidateDigest, &output)
		response.Preflight = result
		if runErr == nil {
			identity, identityErr := bootstrap.ReadCommittedInstallIdentity(bootstrap.FixedPaths())
			if identityErr != nil || identity.Kind != release.InstallQualification || identity.RunID != request.RunID || identity.CandidateDigest != request.CandidateDigest {
				runErr = errors.Join(identityErr, fmt.Errorf("qualification installation identity changed before package observation"))
			} else {
				response.ObservedPackageTuple, runErr = observeQualificationPackageTuple(context.Background(), identity.Profile.Packages)
			}
		}
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
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) < 16 || len(request.Secret) > 256 || len(request.Certificates) != 0 {
			return fmt.Errorf("fixture setup request shape is invalid")
		}
		runErr := setupQualificationFixture(request.RunID, request.Secret)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("fixture/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "fixture_setup_failed"
		}
	case AgentSetupDNSProfile:
		if carriesCoreAgentPayload(request) || request.Provider != "cloudflare" || len(request.Secret) < 20 || len(request.Secret) > 4096 || len(request.Certificates) != 0 {
			return fmt.Errorf("DNS profile setup request shape is invalid")
		}
		runErr := setupQualificationDNSProfile(request.RunID, request.Provider, request.Secret)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("dns-profile/" + request.RunID + "/" + request.Provider))
		if runErr != nil {
			response.ErrorCode = "dns_profile_setup_failed"
		}
	case AgentCleanupFixture:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 || len(request.Certificates) != 0 {
			return fmt.Errorf("fixture cleanup request shape is invalid")
		}
		runErr := cleanupQualificationFixture(request.RunID)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("fixture-cleanup/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "fixture_cleanup_failed"
		}
	case AgentCleanupCertificates:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 || request.ProbeName != "" || request.ExpectedIP != "" || len(request.Certificates) == 0 || validateQualificationCertificateArtifacts(request.Certificates, false) != nil {
			return fmt.Errorf("certificate cleanup request shape is invalid")
		}
		runErr := cleanupQualificationCertificates(context.Background(), request.Certificates)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("certificate-cleanup/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "certificate_cleanup_failed"
		}
	case AgentSecretSentinel:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) == 0 || len(request.Secrets) > 8 || len(request.Certificates) != 0 {
			return fmt.Errorf("secret sentinel request shape is invalid")
		}
		runErr := runSecretSentinel(request.Secrets)
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("secret-sentinel/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "secret_residue_detected"
		}
	case AgentFinalInventory:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 || request.ProbeName != "" || request.ExpectedIP != "" || validateQualificationCertificateArtifacts(request.Certificates, true) != nil {
			return fmt.Errorf("final inventory request shape is invalid")
		}
		observed, runErr := verifyQualificationFinalInventory(context.Background(), request.RunID, request.Certificates[0])
		response.ObservedPackageTuple = observed
		response.Succeeded = runErr == nil
		response.Evidence = release.DigestBytes([]byte("final-inventory/" + request.RunID))
		if runErr != nil {
			response.ErrorCode = "final_inventory_incomplete"
		}
	case AgentMagicDNSProbe:
		if carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 || len(request.Certificates) != 0 || !canonicalDomain(request.ProbeName) || net.ParseIP(request.ExpectedIP) == nil {
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
	packageObservationAction := action == AgentInstall || action == AgentFinalInventory
	if len(response.ObservedPackageTuple) != 0 && (!packageObservationAction || !validObservedPackageTuple(response.ObservedPackageTuple)) || response.Succeeded && packageObservationAction && len(response.ObservedPackageTuple) == 0 {
		return AgentResponse{}, fmt.Errorf("qualification agent package observation is invalid")
	}
	if action == AgentInstall {
		if response.Succeeded || !reflectZeroPreflight(response.Preflight) {
			if _, err := response.Preflight.Digest(); err != nil {
				return AgentResponse{}, err
			}
			if response.Preflight.Scope != string(preflight.ExpansionBootstrap) || response.Preflight.Target != "installation" || response.Succeeded && !response.Preflight.Allowed {
				return AgentResponse{}, fmt.Errorf("qualification installation preflight is not an allowed bootstrap observation")
			}
		}
	} else if !reflectZeroPreflight(response.Preflight) {
		return AgentResponse{}, fmt.Errorf("qualification agent response carries unrelated preflight")
	}
	return response, nil
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
	return len(request.InstallerAuthority) != 0
}

func carriesAgentPayload(request AgentRequest) bool {
	return carriesCoreAgentPayload(request) || request.Provider != "" || len(request.Secret) != 0 || len(request.Secrets) != 0 || request.ProbeName != "" || request.ExpectedIP != "" || len(request.Certificates) != 0
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
	return runSecretSentinelRoots(secrets, []string{"/var/lib/lanpanel", "/etc/lanpanel", "/run/lanpanel", "/etc/systemd/system"})
}

func runSecretSentinelRoots(secrets [][]byte, roots []string) error {
	for _, secret := range secrets {
		if len(secret) < 8 || len(secret) > 4096 || bytes.IndexByte(secret, 0) >= 0 {
			return fmt.Errorf("secret sentinel value is invalid")
		}
	}
	visited := 0
	for _, root := range roots {
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

func cleanupQualificationCertificates(ctx context.Context, artifacts []qualificationCertificateArtifact) error {
	if len(artifacts) == 0 {
		return fmt.Errorf("qualification certificate cleanup authority is empty")
	}
	if err := validateQualificationCertificateArtifacts(artifacts, false); err != nil {
		return fmt.Errorf("qualification certificate cleanup authority is invalid: %w", err)
	}
	byID := make(map[string]map[string]qualificationCertificateArtifact, len(artifacts))
	for _, artifact := range artifacts {
		path, _ := certificates.BundlePath(artifact.CertificateID, artifact.Generation)
		if byID[artifact.CertificateID] == nil {
			byID[artifact.CertificateID] = map[string]qualificationCertificateArtifact{}
		}
		byID[artifact.CertificateID][path] = artifact
	}
	bundleEntries, err := readCertificateInventory(certificates.FixedBundlesRoot)
	if err != nil {
		return err
	}
	activeEntries, err := readCertificateInventory(certificates.FixedActiveRoot)
	if err != nil {
		return err
	}
	for id, expected := range byID {
		for _, entry := range bundleEntries {
			if strings.HasPrefix(entry, id+"-") {
				path := filepath.Join(certificates.FixedBundlesRoot, entry)
				artifact, present := expected[path]
				if !present || certificates.VerifyBundleCleanupIdentity(id, artifact.Generation, artifact.Bundle) != nil {
					return fmt.Errorf("qualification certificate bundle inventory differs from cleanup authority")
				}
			}
		}
		pointerName := id + ".current"
		pointerListed := false
		for _, entry := range activeEntries {
			if entry == pointerName {
				pointerListed = true
			} else if strings.HasPrefix(entry, id) {
				return fmt.Errorf("qualification certificate pointer inventory differs from cleanup authority")
			}
		}
		observed, observeErr := certificates.ObservePointer(id)
		if observeErr != nil && !os.IsNotExist(observeErr) {
			return observeErr
		}
		if observed == "" {
			if pointerListed {
				return fmt.Errorf("qualification certificate pointer disappeared during cleanup observation")
			}
			continue
		}
		artifact, present := expected[observed]
		if !pointerListed || !present {
			return fmt.Errorf("qualification certificate active pointer differs from cleanup authority")
		}
		pointer := certificates.Pointer{CertificateID: id, CandidateGeneration: artifact.Generation, CandidateIdentity: artifact.Bundle}
		if err := certificates.RemovePointer(ctx, pointer, observed); err != nil {
			return err
		}
	}
	for _, artifact := range artifacts {
		path, _ := certificates.BundlePath(artifact.CertificateID, artifact.Generation)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		stage, err := identity.CertificateStageIdentityFor(artifact.CertificateID)
		if err != nil {
			return err
		}
		if err := certificates.RemoveInactiveBundle(artifact.CertificateID, artifact.Generation, artifact.Bundle, stage.UID, stage.GID); err != nil {
			return err
		}
	}
	for id := range byID {
		pointer, err := certificates.ObservePointer(id)
		if err != nil && !os.IsNotExist(err) || pointer != "" {
			return fmt.Errorf("qualification certificate pointer remains after cleanup: %w", err)
		}
	}
	bundleEntries, err = readCertificateInventory(certificates.FixedBundlesRoot)
	if err != nil {
		return err
	}
	activeEntries, err = readCertificateInventory(certificates.FixedActiveRoot)
	if err != nil {
		return err
	}
	for id := range byID {
		for _, entry := range bundleEntries {
			if strings.HasPrefix(entry, id+"-") {
				return fmt.Errorf("qualification certificate bundle remains after cleanup")
			}
		}
		for _, entry := range activeEntries {
			if strings.HasPrefix(entry, id) {
				return fmt.Errorf("qualification certificate pointer remains after cleanup")
			}
		}
	}
	return nil
}

func verifyQualificationCertificateInventory(retained qualificationCertificateArtifact) error {
	if err := validateQualificationCertificateArtifacts([]qualificationCertificateArtifact{retained}, true); err != nil {
		return err
	}
	bundlePath, _ := certificates.BundlePath(retained.CertificateID, retained.Generation)
	pointerPath, _ := certificates.ActivePointerPath(retained.CertificateID)
	bundles, err := readCertificateInventory(certificates.FixedBundlesRoot)
	if err != nil {
		return err
	}
	if len(bundles) != 1 || filepath.Join(certificates.FixedBundlesRoot, bundles[0]) != bundlePath {
		return fmt.Errorf("final certificate bundle inventory is not exactly retained Headscale authority")
	}
	pointers, err := readCertificateInventory(certificates.FixedActiveRoot)
	if err != nil {
		return err
	}
	if len(pointers) != 1 || filepath.Join(certificates.FixedActiveRoot, pointers[0]) != pointerPath {
		return fmt.Errorf("final certificate pointer inventory is not exactly retained Headscale authority")
	}
	observed, err := certificates.ObservePointer(retained.CertificateID)
	if err != nil || observed != bundlePath {
		return fmt.Errorf("retained Headscale certificate pointer differs: %w", err)
	}
	if err := certificates.VerifyBundleIdentity(retained.CertificateID, retained.Generation, retained.Bundle); err != nil {
		return fmt.Errorf("retained Headscale certificate bundle differs: %w", err)
	}
	return nil
}

func readCertificateInventory(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	values := make([]string, len(entries))
	for index, entry := range entries {
		values[index] = entry.Name()
	}
	return values, nil
}

func verifyQualificationFinalInventory(ctx context.Context, runID string, retainedCertificate qualificationCertificateArtifact) ([]release.PackageTuple, error) {
	identity, err := bootstrap.ReadCommittedInstallIdentity(bootstrap.FixedPaths())
	if err != nil || identity.Kind != release.InstallQualification || identity.RunID != runID {
		return nil, fmt.Errorf("final inventory installation authority differs: %w", err)
	}
	observedPackages, err := observeQualificationPackageTuple(ctx, identity.Profile.Packages)
	if err != nil {
		return observedPackages, err
	}
	if err := verifyQualificationCertificateInventory(retainedCertificate); err != nil {
		return observedPackages, err
	}
	paths, err := FixedQualificationFixturePaths(runID)
	if err != nil {
		return observedPackages, err
	}
	for _, path := range []string{paths.StaticFile, paths.StaticRoot, paths.HTPasswd, paths.DNSToken, paths.DNSProfile, paths.SrvRunRoot, paths.EtcRunRoot, "/srv/lanpanel-qualification", "/etc/lanpanel-qualification"} {
		if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
			return observedPackages, fmt.Errorf("qualification fixture residue remains")
		}
	}
	result, err := runQualificationProfileResult(child.ProfileQualificationServices)
	if err != nil {
		return observedPackages, err
	}
	states := strings.Fields(string(result.Stdout))
	if len(states) != 7 {
		return observedPackages, fmt.Errorf("qualification retained service inventory is incomplete")
	}
	for _, state := range states {
		if state != "active" {
			return observedPackages, fmt.Errorf("qualification retained service is not active")
		}
	}
	return observedPackages, nil
}

func observeQualificationPackageTuple(ctx context.Context, expected []release.PackageTuple) ([]release.PackageTuple, error) {
	names := make([]string, len(expected))
	for index, tuple := range expected {
		names[index] = tuple.Name
	}
	observed, err := preflight.ObserveInstalledPackageTuples(ctx, names)
	values := make([]release.PackageTuple, len(observed))
	for index, tuple := range observed {
		values[index] = release.PackageTuple{Name: tuple.Name, Version: tuple.Version, Architecture: tuple.Architecture}
	}
	if err != nil {
		return values, err
	}
	if len(values) != len(expected) {
		return values, fmt.Errorf("observed package tuple differs from committed target profile")
	}
	for index, tuple := range values {
		if tuple != expected[index] {
			return values, fmt.Errorf("observed package tuple differs from committed target profile")
		}
	}
	return values, nil
}

func validObservedPackageTuple(values []release.PackageTuple) bool {
	previous := ""
	for _, tuple := range values {
		key := tuple.Name + "\x00" + tuple.Architecture
		if tuple.Name == "" || tuple.Version == "" || tuple.Name != strings.TrimSpace(tuple.Name) || tuple.Version != strings.TrimSpace(tuple.Version) || len(tuple.Name) > 128 || len(tuple.Version) > 128 || strings.ContainsAny(tuple.Name+tuple.Version, "\x00\r\n") || tuple.Architecture != "amd64" && tuple.Architecture != "all" || previous != "" && previous >= key {
			return false
		}
		previous = key
	}
	return len(values) != 0
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
