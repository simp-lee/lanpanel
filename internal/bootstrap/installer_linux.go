//go:build linux

package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/helper"
	"lanpanel/internal/identity"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const ProtectedAdminTokenPath = "/var/lib/lanpanel/installation/admin-token"

func Install(ctx context.Context, request Request) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("installer requires its fixed root invocation")
	}
	return install(ctx, request, true)
}

func install(ctx context.Context, request Request, strict bool) error {
	if request.ReleaseAuthority == nil {
		return fmt.Errorf("installer release authority is missing")
	}
	releaseIdentity := request.ReleaseAuthority.Identity()
	if err := release.ValidateInstallIdentity(releaseIdentity); err != nil {
		return err
	}
	paths := request.Paths
	if paths.PersistentRoot == "" {
		paths = FixedPaths()
	}
	now := request.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	random := request.Random
	if random == nil {
		random = rand.Reader
	}
	if strict && paths != FixedPaths() {
		return fmt.Errorf("installer paths are not release-fixed")
	}
	if request.SourceBinaryPath == "" || !filepath.IsAbs(request.SourceBinaryPath) || filepath.Clean(request.SourceBinaryPath) != request.SourceBinaryPath {
		return fmt.Errorf("installer source binary path is invalid")
	}
	if err := verifySourceBinary(request.SourceBinaryPath, releaseBinary{Digest: releaseIdentity.Binary.Digest, Bytes: releaseIdentity.Binary.Bytes}); err != nil {
		return err
	}
	if request.Preflight == nil {
		return fmt.Errorf("installer bootstrap preflight evaluator is missing")
	}
	journalPresent, err := journalExists(paths.Journal)
	if err != nil {
		return err
	}
	if journalPresent {
		store, journal, err := openJournal(paths.Journal, 0, 0)
		if err != nil {
			return err
		}
		defer store.close()
		preflightRequest := journal.PreflightRequest
		preflightResult := preflight.Result{}
		if journal.Phase == PhasePrepared {
			preflightRequest, preflightResult, err = request.Preflight(ctx, journal.Authority, journal.SafetyGeneration)
		}
		if journal.Phase != PhasePrepared {
			preflightRequest = journal.PreflightRequest
			nowValue := time.Now().UTC()
			preflightResult = preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: journal.SafetyGeneration, RequestDigest: journal.PreflightDigest, Allowed: true, ObservedAt: nowValue, ValidUntil: nowValue.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "resume", Disposition: preflight.FindingPassed, Summary: "exact journal continuation", Identity: journal.AttemptID}}}
		}
		if err != nil {
			return err
		}
		if journal.Phase == PhasePrepared {
			if err := validateBootstrapPreflight(releaseIdentity, preflightRequest, preflightResult, now()); err != nil {
				return err
			}
		}
		preflightDigest, _ := preflight.ExpansionRequestDigest(preflightRequest)
		if err := verifyResumeInventory(journal); err != nil {
			return err
		}
		if journal.Release != releaseIdentity || journal.Paths != paths || journal.SafetyGeneration != preflightRequest.Generation || journal.PreflightDigest != preflightDigest || !reflect.DeepEqual(journal.PreflightRequest, preflightRequest) {
			return fmt.Errorf("existing bootstrap attempt belongs to different exact authority")
		}
		return resume(ctx, store, journal, request, nil, strict)
	}
	if evidence, err := scanExistingEvidence(paths); err != nil {
		return err
	} else if len(evidence) != 0 {
		return fmt.Errorf("clean install found foreign installation evidence: %s", strings.Join(evidence, ","))
	}
	if _, err := os.Lstat(paths.PersistentRoot); err == nil {
		return fmt.Errorf("clean install persistent root already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	material, err := identity.Generate(random)
	if err != nil {
		return err
	}
	defer material.Destroy()
	accounts, err := identity.InstallationAccounts(material.InstallationID)
	if err != nil {
		return err
	}
	present, _, err := identity.InspectAccounts(accounts)
	if err != nil || present {
		return fmt.Errorf("installation account collision before mutation: %w", err)
	}
	preflightRequest, preflightResult, err := request.Preflight(ctx, material.Authority, material.SafetyGeneration)
	if err != nil {
		return err
	}
	if err := validateBootstrapPreflight(releaseIdentity, preflightRequest, preflightResult, now()); err != nil {
		return err
	}
	preflightDigest, _ := preflight.ExpansionRequestDigest(preflightRequest)
	plannedPaths, err := plannedBootstrapPaths(paths)
	if err != nil {
		return err
	}
	journal := Journal{SchemaVersion: JournalSchemaVersion, AttemptID: material.AttemptID, InstallationID: material.InstallationID, GenerationID: material.GenerationID, SafetyGeneration: material.SafetyGeneration, Phase: PhasePrepared, Sequence: 1, Release: releaseIdentity, Authority: material.Authority, PreflightRequest: preflightRequest, PreflightDigest: preflightDigest, Accounts: accounts, Paths: paths, ArtifactDigests: map[string]string{"release_binary": releaseIdentity.Binary.Digest}, PlannedPaths: plannedPaths}
	if err := validateJournal(journal); err != nil {
		return err
	}
	store, err := createJournal(paths.Journal, 0, 0, journal)
	if err != nil {
		return err
	}
	defer store.close()
	token := material.TakeAdminToken()
	return resume(ctx, store, journal, request, token, strict)
}

func resume(ctx context.Context, store *journalStore, journal Journal, request Request, token []byte, strict bool) error {
	if len(token) != 0 {
		defer clear(token)
	}
	advance := func(phase Phase) error {
		journal.Sequence++
		journal.Phase = phase
		if err := store.update(journal); err != nil {
			return err
		}
		return nil
	}
	if journal.Phase == PhasePrepared {
		if _, err := ensureDirectory(journal.Paths.PersistentRoot, filetxn.Owner{UID: 0, GID: 0}, 0o700); err != nil {
			return err
		}
		fingerprint, _ := identity.Fingerprint(journal.InstallationID)
		bundle := Bundle{SchemaVersion: BundleSchemaVersion, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, SafetyGeneration: journal.SafetyGeneration, Fingerprint: fingerprint, Management: journal.Authority, Release: journal.Release, PreflightDigest: journal.PreflightDigest}
		bundleBytes, _ := encodeCanonical(bundle)
		if len(token) == 0 {
			if existing, err := readCommittedArtifact(filepath.Join(journal.Paths.InstallationRoot, "admin-token"), 4096, 0o600); err == nil {
				token = existing
			} else {
				var generateErr error
				token, generateErr = identity.GenerateAdminToken(request.Random)
				if generateErr != nil {
					return generateErr
				}
			}
			defer clear(token)
		}
		members := []filetxn.DirectoryMember{
			{Name: "admin-token", Data: token, Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
			{Name: "bundle.json", Data: bundleBytes, Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: MaximumJournalBytes},
			{Name: "host-fingerprint", Data: []byte(journal.Release.HostFingerprint), Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
			{Name: "os-profile.digest", Data: []byte(journal.Release.ProfileDigest), Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
			{Name: "release-envelope.digest", Data: []byte(journal.Release.EnvelopeDigest), Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
		}
		slices.SortFunc(members, func(left, right filetxn.DirectoryMember) int { return strings.Compare(left.Name, right.Name) })
		bundleRequest := filetxn.DirectoryRequest{ParentPath: filepath.Dir(journal.Paths.InstallationRoot), Parent: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o700}, TargetName: filepath.Base(journal.Paths.InstallationRoot), Directory: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o711}, Members: members}
		directoryIdentity, err := filetxn.CommitNewDirectory(ctx, bundleRequest)
		if errors.Is(err, os.ErrExist) {
			directoryIdentity, err = filetxn.VerifyDirectory(bundleRequest)
		}
		if err != nil {
			return fmt.Errorf("installation bundle is foreign or incomplete: %w", err)
		}
		journal.ArtifactDigests["installation_bundle"] = directoryIdentity.Digest
		if err := advance(PhaseBundleCommitted); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseBundleCommitted {
		if _, err := ensureDirectory(filepath.Dir(journal.Paths.BinaryPath), filetxn.Owner{UID: 0, GID: 0}, 0o755); err != nil {
			return err
		}
		if err := copyOrVerifyBinary(request.SourceBinaryPath, journal.Paths, releaseBinary{Digest: journal.Release.Binary.Digest, Bytes: journal.Release.Binary.Bytes}); err != nil {
			return err
		}
		journal.ArtifactDigests[journal.Paths.BinaryPath] = journal.Release.Binary.Digest
		sysusers, err := identity.RenderSysusers(journal.Accounts)
		if err != nil {
			return err
		}
		if _, err := ensureDirectory(filepath.Join(journal.Paths.PersistentRoot, ".bootstrap-filetxn"), filetxn.Owner{UID: 0, GID: 0}, 0o700); err != nil {
			return err
		}
		if err := putOrVerifyTargetFile(ctx, journal.Paths.SysusersPath, sysusers, 0o600); err != nil {
			return err
		}
		journal.ArtifactDigests[journal.Paths.SysusersPath] = digestBytes(sysusers)
		if err := advance(PhaseAccountsSubmitted); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseAccountsSubmitted && strict {
		present, _, inspectErr := identity.InspectPartialAccounts(journal.Accounts)
		if inspectErr != nil {
			return inspectErr
		}
		if !present {
			launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
			if err != nil {
				return err
			}
			result, runErr := launcher.Run(ctx, child.ProfileSystemdSysusers, nil)
			if runErr != nil || result.ExitCode != 0 || result.OutputCutOff {
				return fmt.Errorf("fixed systemd-sysusers did not complete")
			}
		}
	}
	if journal.Phase == PhaseAccountsSubmitted {
		present, numeric, err := identity.InspectAccounts(journal.Accounts)
		if err != nil || !present {
			return fmt.Errorf("fixed installation accounts are incomplete: %w", err)
		}
		journal.Accounts.Identities = numeric
		if err := advance(PhaseAccountsVerified); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseAccountsVerified {
		uiIdentity, ok := identity.IdentityFor(journal.Accounts, identity.RoleUI)
		if !ok || uiIdentity.GID == 0 {
			return fmt.Errorf("UI account authority is missing")
		}
		if _, err := ensureDirectory(filepath.Dir(journal.Paths.StartupAuthority), filetxn.Owner{UID: 0, GID: uiIdentity.GID}, 0o710); err != nil {
			return err
		}
		if err := createBootstrapDirectories(journal); err != nil {
			return err
		}
		if strict {
			if err := initializeStores(ctx, journal); err != nil {
				return err
			}
		}
		if err := writeHelperIdentities(ctx, journal); err != nil {
			return err
		}
		if err := advance(PhaseStoresInitialized); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseStoresInitialized {
		artifacts, err := renderArtifacts(journal)
		if err != nil {
			return err
		}
		for path, data := range artifacts {
			if err := putOrVerifyTargetFile(ctx, path, data, 0o644); err != nil {
				return err
			}
			journal.ArtifactDigests[path] = digestBytes(data)
		}
		if err := advance(PhaseAssetsInstalled); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseAssetsInstalled {
		if err := verifyPrecommitArtifacts(journal); err != nil {
			return err
		}
		currentTime := time.Now().UTC()
		if request.Now != nil {
			currentTime = request.Now().UTC()
		}
		commit := Commit{SchemaVersion: CommitSchemaVersion, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, JournalSequence: journal.Sequence + 1, BundleDigest: journal.ArtifactDigests["installation_bundle"], ArtifactDigest: artifactInventoryDigest(journal.ArtifactDigests), CommittedAt: currentTime}
		commitBytes, _ := encodeCanonical(commit)
		if existing, err := readCommittedArtifact(journal.Paths.CommitPath, MaximumJournalBytes, 0o644); err == nil {
			var prior Commit
			if decodeCanonical(existing, &prior) != nil || prior.AttemptID != commit.AttemptID || prior.InstallationID != commit.InstallationID || prior.GenerationID != commit.GenerationID || prior.BundleDigest != commit.BundleDigest || prior.ArtifactDigest != commit.ArtifactDigest {
				return fmt.Errorf("existing final bootstrap commit is foreign")
			}
			commitBytes = existing
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else {
			staging, stagingErr := targetStaging(journal.Paths.CommitPath)
			if stagingErr != nil {
				return stagingErr
			}
			if err := putRootFile(ctx, "/", staging, journal.Paths.CommitPath, commitBytes, 0o644, filetxn.CreateOnly); err != nil {
				return err
			}
		}
		journal.FinalCommitDigest = digestBytes(commitBytes)
		startup := struct {
			SchemaVersion  string                       `json:"schema_version"`
			AttemptID      string                       `json:"attempt_id"`
			InstallationID string                       `json:"installation_id"`
			GenerationID   string                       `json:"generation_id"`
			Management     identity.ManagementAuthority `json:"management_authority"`
			CommitDigest   string                       `json:"commit_digest"`
		}{"lanpanel.startup-authority.v1", journal.AttemptID, journal.InstallationID, journal.GenerationID, journal.Authority, journal.FinalCommitDigest}
		startupBytes, _ := encodeCanonical(startup)
		uiIdentity, _ := identity.IdentityFor(journal.Accounts, identity.RoleUI)
		if err := putRootGroupFile(ctx, journal.Paths.StartupAuthority, startupBytes, uiIdentity.GID, 0o640); err != nil {
			return err
		}
		if err := advance(PhaseCommitted); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseCommitted {
		commitBytes, err := readCommittedArtifact(journal.Paths.CommitPath, MaximumJournalBytes, 0o644)
		if err != nil {
			return err
		}
		var commit Commit
		if decodeCanonical(commitBytes, &commit) != nil || digestBytes(commitBytes) != journal.FinalCommitDigest {
			return fmt.Errorf("final bootstrap commit differs from journal")
		}
		if err := verifyCommittedBundle(journal.Paths, journal, commit); err != nil {
			return err
		}
		if strict {
			if err := verifyCommittedBundle(journal.Paths, journal, commit); err != nil {
				return err
			}
			launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
			if err != nil {
				return err
			}
			if result, runErr := launcher.Run(ctx, child.ProfileSystemctl, nil); runErr != nil || result.ExitCode != 0 || result.OutputCutOff {
				return fmt.Errorf("systemd daemon reload did not complete")
			}
			if result, runErr := launcher.Run(ctx, child.ProfileSystemctlBootstrap, nil); runErr != nil || result.ExitCode != 0 || result.OutputCutOff {
				return fmt.Errorf("bootstrap services did not enable and start")
			}
			if err := verifyActivationPostconditions(journal); err != nil {
				return err
			}
		}
		if err := advance(PhaseActivated); err != nil {
			return err
		}
	}
	if journal.Phase == PhaseActivated {
		return deliverToken(store, &journal, request, token)
	}
	return fmt.Errorf("bootstrap attempt did not reach a committed phase")
}

func createBootstrapDirectories(journal Journal) error {
	owner := filetxn.Owner{UID: 0, GID: 0}
	for _, path := range []string{journal.Paths.StateRoot, journal.Paths.SafetyRoot, journal.Paths.OwnershipRoot, journal.Paths.LockRoot, journal.Paths.PackageRoot, filepath.Join(journal.Paths.PackageRoot, ".filetxn"), filepath.Join(journal.Paths.PackageRoot, "journals"), filepath.Join(journal.Paths.PackageRoot, "plans"), filepath.Join(journal.Paths.PackageRoot, "transactions"), filepath.Join(journal.Paths.PackageRoot, "staging"), filepath.Join(journal.Paths.PersistentRoot, ".bootstrap-filetxn")} {
		if _, err := ensureDirectory(path, owner, 0o700); err != nil {
			return err
		}
	}
	if _, err := ensureDirectory(filepath.Dir(journal.Paths.BinaryPath), owner, 0o755); err != nil {
		return err
	}
	ui, _ := identity.IdentityFor(journal.Accounts, identity.RoleUI)
	if _, err := ensureDirectory(journal.Paths.RuntimeRoot, filetxn.Owner{UID: 0, GID: ui.GID}, 0o710); err != nil {
		return err
	}
	return nil
}

func writeHelperIdentities(ctx context.Context, journal Journal) error {
	ui, _ := identity.IdentityFor(journal.Accounts, identity.RoleUI)
	timer, _ := identity.IdentityFor(journal.Accounts, identity.RoleTimer)
	recovery, _ := identity.IdentityFor(journal.Accounts, identity.RoleRecovery)
	payload := map[string]any{"schema_version": "lanpanel.helper.identities.v1", "socket_group": ui.GID, "identities": helper.IdentitySet{UI: helper.PeerIdentity{UID: ui.UID, GID: ui.GID}, Timer: helper.PeerIdentity{UID: timer.UID, GID: timer.GID}, Recovery: helper.PeerIdentity{UID: recovery.UID, GID: recovery.GID}}}
	data, _ := encodeCanonical(payload)
	return putOrVerifyTargetFile(ctx, helper.FixedIdentityConfigPath, data, 0o600)
}

func deliverToken(store *journalStore, journal *Journal, request Request, token []byte) error {
	if journal.TokenDeliveryAttempted {
		return nil
	}
	if request.TTY != nil && request.TTY.Attached() && len(token) == 0 {
		var err error
		token, err = readCommittedArtifact(filepath.Join(journal.Paths.InstallationRoot, "admin-token"), 4096, 0o600)
		if err != nil {
			return err
		}
		defer clear(token)
	}
	journal.Sequence++
	journal.TokenDeliveryAttempted = true
	if err := store.update(*journal); err != nil {
		return err
	}
	if request.TTY != nil && request.TTY.Attached() && len(token) != 0 {
		return request.TTY.WriteToken(token)
	}
	if request.Output != nil {
		_, err := fmt.Fprintf(request.Output, "Admin token is stored at %s\n", ProtectedAdminTokenPath)
		return err
	}
	return nil
}

func validateBootstrapPreflight(releaseIdentity release.InstallIdentity, request preflight.ExpansionRequest, result preflight.Result, now time.Time) error {
	if request.Scope != preflight.ExpansionBootstrap || request.Target != "installation" || request.Generation == 0 {
		return fmt.Errorf("installer bootstrap preflight request is invalid")
	}
	if err := preflight.RequireExpansionResultForRequest(result, request, now); err != nil {
		return err
	}
	if request.Profile.Authority.Digest != "sha256:"+releaseIdentity.ProfileDigest || request.Profile.ID != releaseIdentity.Profile.Family || request.Profile.VersionID != releaseIdentity.Profile.Release || request.Profile.Architecture != "amd64" {
		return fmt.Errorf("bootstrap preflight does not bind the selected release profile")
	}
	if len(request.BootstrapListeners) != 1 || request.BootstrapListeners[0].Protocol != "tcp" || request.BootstrapListeners[0].Purpose != "management" {
		return fmt.Errorf("bootstrap preflight Management listener is incomplete")
	}
	return nil
}

func scanExistingEvidence(paths Paths) ([]string, error) {
	candidates := []string{paths.CommitPath, paths.StartupAuthority, paths.PersistentRoot, paths.InstallationRoot, paths.StateRoot, paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, paths.SysusersPath, paths.BinaryPath, filepath.Dir(paths.BinaryPath)}
	for _, name := range []string{"lanpanel-management.socket", "lanpanel-ui.service", "lanpanel-runtime.service", "lanpanel-helper.service", "lanpanel-timer.service", "lanpanel-timer.timer", "lanpanel-recovery.service"} {
		candidates = append(candidates, filepath.Join(paths.SystemdRoot, name))
	}
	result := []string{}
	for _, path := range candidates {
		if _, err := os.Lstat(path); err == nil {
			result = append(result, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return result, nil
}

// RequireCommitted is called by every installed non-installer role before it
// reads state, creates a socket, or performs a mutation.
type StartupAuthority struct {
	SchemaVersion  string                       `json:"schema_version"`
	AttemptID      string                       `json:"attempt_id"`
	InstallationID string                       `json:"installation_id"`
	GenerationID   string                       `json:"generation_id"`
	Management     identity.ManagementAuthority `json:"management_authority"`
	CommitDigest   string                       `json:"commit_digest"`
}

func ReadPublicStartupAuthority(paths Paths) (StartupAuthority, error) {
	var value StartupAuthority
	if paths.PersistentRoot == "" {
		paths = FixedPaths()
	}
	fd, err := unix.Open(paths.StartupAuthority, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return value, fmt.Errorf("bootstrap startup authority is unavailable")
	}
	file := os.NewFile(uintptr(fd), "startup-authority")
	if file == nil {
		_ = unix.Close(fd)
		return value, fmt.Errorf("bootstrap startup authority descriptor is unavailable")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Mode&0o777 != 0o640 || stat.Size <= 0 || stat.Size > MaximumJournalBytes {
		return value, fmt.Errorf("bootstrap startup authority identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaximumJournalBytes+1))
	if err != nil || int64(len(data)) != stat.Size {
		return value, fmt.Errorf("bootstrap startup authority read failed")
	}
	if decodeCanonical(data, &value) != nil || value.SchemaVersion != "lanpanel.startup-authority.v1" || !identity.ValidateAttemptID(value.AttemptID) || !identity.ValidateInstallationID(value.InstallationID) || !identity.ValidateGenerationID(value.GenerationID) || identity.ValidateManagementAuthority(value.Management) != nil || !release.ValidDigest(value.CommitDigest) {
		return value, fmt.Errorf("bootstrap startup authority is invalid")
	}
	return value, nil
}

func requirePublicStartupAuthority(paths Paths) error {
	_, err := ReadPublicStartupAuthority(paths)
	return err
}

func verifyPrecommitArtifacts(journal Journal) error {
	data, err := readCommittedArtifact(journal.Paths.BinaryPath, int64(journal.Release.Binary.Bytes), 0o755)
	if err != nil || digestBytes(data) != journal.Release.Binary.Digest {
		return fmt.Errorf("installed binary differs before final commit")
	}
	for _, member := range []struct {
		name    string
		mode    uint32
		maximum int64
	}{{"admin-token", 0o600, 4096}, {"bundle.json", 0o600, MaximumJournalBytes}, {"host-fingerprint", 0o600, 4096}, {"os-profile.digest", 0o600, 4096}, {"release-envelope.digest", 0o600, 4096}} {
		if _, err := readCommittedArtifact(filepath.Join(journal.Paths.InstallationRoot, member.name), member.maximum, member.mode); err != nil {
			return err
		}
	}
	if _, err := readCommittedArtifact(helper.FixedIdentityConfigPath, 4096, 0o600); err != nil {
		return err
	}
	for path, digest := range journal.ArtifactDigests {
		if path == "release_binary" || path == "installation_bundle" {
			continue
		}
		maximum := int64(256 << 20)
		mode := uint32(0o755)
		if strings.Contains(path, ".service") || strings.Contains(path, ".socket") || strings.Contains(path, ".timer") {
			mode = 0o644
		}
		data, err := readCommittedArtifact(path, maximum, mode)
		if err != nil || digestBytes(data) != digest {
			return fmt.Errorf("bootstrap artifact %q differs before final commit", path)
		}
	}
	return nil
}

func verifyCommittedBundle(paths Paths, journal Journal, commit Commit) error {
	if commit.ArtifactDigest != artifactInventoryDigest(journal.ArtifactDigests) {
		return fmt.Errorf("final bootstrap artifact inventory digest mismatched")
	}
	bundleBytes, err := readCommittedArtifact(filepath.Join(paths.InstallationRoot, "bundle.json"), MaximumJournalBytes, 0o600)
	if err != nil {
		return err
	}
	var bundle Bundle
	if decodeCanonical(bundleBytes, &bundle) != nil || validateBundle(bundle) != nil || bundle.AttemptID != journal.AttemptID || bundle.InstallationID != journal.InstallationID || bundle.GenerationID != journal.GenerationID || commit.BundleDigest != journal.ArtifactDigests["installation_bundle"] || commit.ArtifactDigest != artifactInventoryDigest(journal.ArtifactDigests) {
		return fmt.Errorf("committed installation bundle differs from final commit")
	}
	for _, member := range []struct {
		name    string
		mode    uint32
		maximum int64
	}{{"admin-token", 0o600, 4096}, {"host-fingerprint", 0o600, 4096}, {"os-profile.digest", 0o600, 4096}, {"release-envelope.digest", 0o600, 4096}} {
		if _, err := readCommittedArtifact(filepath.Join(paths.InstallationRoot, member.name), member.maximum, member.mode); err != nil {
			return err
		}
	}
	for path, digest := range journal.ArtifactDigests {
		if path == "release_binary" || path == "installation_bundle" {
			continue
		}
		data, err := readCommittedArtifact(path, 256<<20, 0o755)
		if err != nil || digestBytes(data) != digest {
			return fmt.Errorf("committed bootstrap artifact %q differs from final inventory", path)
		}
	}
	return nil
}

func RequireCommitted(paths Paths) error {
	if os.Geteuid() != 0 {
		return requirePublicStartupAuthority(paths)
	}
	if paths.PersistentRoot == "" {
		paths = FixedPaths()
	}
	commitBytes, err := readCommittedArtifact(paths.CommitPath, MaximumJournalBytes, 0o644)
	if err != nil {
		return fmt.Errorf("bootstrap final commit is missing or unsafe: %w", err)
	}
	var commit Commit
	if decodeCanonical(commitBytes, &commit) != nil || commit.SchemaVersion != CommitSchemaVersion {
		return fmt.Errorf("bootstrap final commit is invalid")
	}
	store, journal, err := openJournal(paths.Journal, 0, 0)
	if err != nil {
		return fmt.Errorf("bootstrap fence is active or missing: %w", err)
	}
	defer store.close()
	if (journal.Phase != PhaseActivated && journal.Phase != PhaseCommitted) || !release.ValidDigest(journal.FinalCommitDigest) || digestBytes(commitBytes) != journal.FinalCommitDigest || commit.AttemptID != journal.AttemptID || commit.InstallationID != journal.InstallationID || commit.GenerationID != journal.GenerationID {
		return fmt.Errorf("bootstrap fence is active")
	}
	return verifyCommittedBundle(paths, journal, commit)
}
