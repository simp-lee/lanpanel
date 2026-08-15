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
	"lanpanel/internal/nginx"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
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
	if len(request.LegoBytes) == 0 || uint64(len(request.LegoBytes)) != releaseIdentity.Lego.Bytes || digestBytes(request.LegoBytes) != releaseIdentity.Lego.Digest {
		return fmt.Errorf("selected lego bytes differ from release authority")
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
		if !reflect.DeepEqual(journal.Release, releaseIdentity) || journal.Paths != paths || journal.SafetyGeneration != preflightRequest.Generation || journal.PreflightDigest != preflightDigest || !reflect.DeepEqual(journal.PreflightRequest, preflightRequest) {
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
		if _, err := ensureDirectory(journal.Paths.PersistentRoot, filetxn.Owner{UID: 0, GID: 0}, 0o711); err != nil {
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
		var defaultCertificate nginx.DefaultCertificate
		var certificateErr error
		certificatePath := filepath.Join(journal.Paths.InstallationRoot, "default-rejection.crt")
		privateKeyPath := filepath.Join(journal.Paths.InstallationRoot, "default-rejection.key")
		if certificatePEM, readErr := readCommittedArtifact(certificatePath, nginx.MaximumGraphFileSize, 0o644); readErr == nil {
			privateKeyPEM, keyErr := readCommittedArtifact(privateKeyPath, nginx.MaximumGraphFileSize, 0o600)
			if keyErr != nil {
				return fmt.Errorf("committed default rejection certificate is one-sided: %w", keyErr)
			}
			defaultCertificate, certificateErr = nginx.ParseDefaultCertificate(certificatePEM, privateKeyPEM)
			wantDNS, _ := nginx.ExpectedDefaultDNSName(journal.InstallationID)
			if certificateErr != nil || defaultCertificate.DNSName != wantDNS {
				return fmt.Errorf("committed default rejection certificate is foreign")
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		} else {
			currentTime := time.Now().UTC()
			if request.Now != nil {
				currentTime = request.Now().UTC()
			}
			defaultCertificate, certificateErr = nginx.GenerateDefaultCertificate(journal.InstallationID, request.Random, currentTime)
			if certificateErr != nil {
				return certificateErr
			}
		}
		confinementBytes, confinementErr := release.MarshalCanonical(journal.Release.Profile.ManagedConfinement)
		if confinementErr != nil {
			return confinementErr
		}
		members := []filetxn.DirectoryMember{
			{Name: "admin-token", Data: token, Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
			{Name: "bundle.json", Data: bundleBytes, Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: MaximumJournalBytes},
			{Name: "default-rejection.crt", Data: defaultCertificate.CertificatePEM, Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o644, Maximum: nginx.MaximumGraphFileSize},
			{Name: "default-rejection.key", Data: defaultCertificate.PrivateKeyPEM, Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: nginx.MaximumGraphFileSize},
			{Name: "host-fingerprint", Data: []byte(journal.Release.HostFingerprint), Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
			{Name: "managed-confinement.json", Data: confinementBytes, Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 64 << 10},
			{Name: "os-profile.digest", Data: []byte(journal.Release.ProfileDigest), Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
			{Name: "release-envelope.digest", Data: []byte(journal.Release.EnvelopeDigest), Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o600, Maximum: 4096},
		}
		slices.SortFunc(members, func(left, right filetxn.DirectoryMember) int { return strings.Compare(left.Name, right.Name) })
		bundleRequest := filetxn.DirectoryRequest{ParentPath: filepath.Dir(journal.Paths.InstallationRoot), Parent: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o711}, TargetName: filepath.Base(journal.Paths.InstallationRoot), Directory: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o711}, Members: members}
		directoryIdentity, err := filetxn.CommitNewDirectory(ctx, bundleRequest)
		if errors.Is(err, os.ErrExist) {
			directoryIdentity, err = filetxn.VerifyDirectory(bundleRequest)
		}
		if err != nil {
			return fmt.Errorf("installation bundle is foreign or incomplete: %w", err)
		}
		journal.ArtifactDigests["installation_bundle"] = directoryIdentity.Digest
		journal.ArtifactDigests["default_rejection_certificate"] = digestBytes(defaultCertificate.CertificatePEM)
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
		if err := putOrVerifyTargetFile(ctx, "/usr/lib/lanpanel/dependencies/lego", request.LegoBytes, 0o755); err != nil {
			return err
		}
		journal.ArtifactDigests["/usr/lib/lanpanel/dependencies/lego"] = journal.Release.Lego.Digest
		if err := installNginxBaseline(ctx, &journal); err != nil {
			return err
		}
		if journal.Paths == FixedPaths() {
			if err := installVendorNginxMask(journal.Paths.SystemdRoot); err != nil {
				return err
			}
			journal.ArtifactDigests[filepath.Join(journal.Paths.SystemdRoot, "nginx.service")] = digestBytes([]byte("/dev/null"))
		}
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
	nginxPaths := nginx.FixedPaths()
	if journal.Paths != FixedPaths() {
		nginxPaths = testNginxPaths(journal.Paths)
	}
	for _, path := range []string{journal.Paths.StateRoot, journal.Paths.SafetyRoot, journal.Paths.OwnershipRoot, journal.Paths.LockRoot, journal.Paths.PackageRoot, filepath.Join(journal.Paths.PackageRoot, ".filetxn"), filepath.Join(journal.Paths.PackageRoot, "journals"), filepath.Join(journal.Paths.PackageRoot, "plans"), filepath.Join(journal.Paths.PackageRoot, "transactions"), filepath.Join(journal.Paths.PackageRoot, "staging"), filepath.Join(journal.Paths.PersistentRoot, ".bootstrap-filetxn"), nginxPaths.ConfigRoot, nginxPaths.StagingPath(), filepath.Join(nginxPaths.ConfigRoot, nginx.AppsDirectory), filepath.Join(nginxPaths.ConfigRoot, nginx.ChallengesDirectory), filepath.Join(nginxPaths.ConfigRoot, nginx.ControlDirectory), filepath.Join(nginxPaths.ConfigRoot, nginx.TemporaryDirectory), nginxPaths.StateRoot} {
		if _, err := ensureDirectory(path, owner, 0o700); err != nil {
			return err
		}
	}
	auditMode := uint32(0o700)
	if journal.Paths == FixedPaths() {
		auditMode = 0o711
	}
	if _, err := ensureDirectory(filepath.Dir(nginxPaths.AuditPath), owner, auditMode); err != nil {
		return err
	}
	certificateRoot := filepath.Join(journal.Paths.PersistentRoot, "certificates")
	if _, err := ensureDirectory(certificateRoot, owner, 0o711); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(certificateRoot, "chroot"), filepath.Join(certificateRoot, "webroot")} {
		if _, err := ensureDirectory(path, owner, 0o711); err != nil {
			return err
		}
	}
	for _, path := range []string{filepath.Join(certificateRoot, "staging"), filepath.Join(certificateRoot, "active"), filepath.Join(certificateRoot, "bootstrap"), filepath.Join(certificateRoot, "bundles")} {
		if _, err := ensureDirectory(path, owner, 0o700); err != nil {
			return err
		}
	}
	if journal.Paths == FixedPaths() {
		if _, err := ensureDirectory("/var/log/lanpanel/goaccess", owner, 0o711); err != nil {
			return err
		}
		group, err := user.LookupGroup("www-data")
		if err != nil {
			return err
		}
		gid, err := strconv.ParseUint(group.Gid, 10, 32)
		if err != nil || gid == 0 {
			return fmt.Errorf("Nginx group identity invalid")
		}
		if _, err := ensureDirectory("/run/lanpanel-goaccess", filetxn.Owner{UID: 0, GID: uint32(gid)}, 0o750); err != nil {
			return err
		}
		for _, path := range []string{"/etc/lanpanel-public", "/etc/lanpanel-public/basic"} {
			if _, err := ensureDirectory(path, filetxn.Owner{UID: 0, GID: uint32(gid)}, 0o750); err != nil {
				return err
			}
		}
		if _, err := ensureDirectory("/etc/lanpanel-public/basic/.txn", owner, 0o700); err != nil {
			return err
		}
	}
	if _, err := ensureDirectory("/usr/lib/lanpanel/dependencies", owner, 0o755); err != nil {
		return err
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

func testNginxPaths(paths Paths) nginx.Paths {
	return nginx.Paths{ConfigRoot: filepath.Join(paths.PersistentRoot, "etc-nginx"), StateRoot: filepath.Join(paths.PersistentRoot, "nginx"), AuditPath: filepath.Join(paths.PersistentRoot, "log", "nginx-rejections.log"), CertificatePath: filepath.Join(paths.InstallationRoot, "default-rejection.crt"), PrivateKeyPath: filepath.Join(paths.InstallationRoot, "default-rejection.key"), PIDPath: filepath.Join(paths.RuntimeRoot, "nginx.pid")}
}

func installNginxBaseline(ctx context.Context, journal *Journal) error {
	paths := nginx.FixedPaths()
	if journal == nil {
		return fmt.Errorf("bootstrap journal is missing")
	}
	if journal.Paths != FixedPaths() {
		paths = testNginxPaths(journal.Paths)
	} else if err := rejectForeignNginxAuthority(); err != nil {
		return err
	}
	certificatePEM, err := readCommittedArtifact(paths.CertificatePath, nginx.MaximumGraphFileSize, 0o644)
	if err != nil {
		return err
	}
	privateKeyPEM, err := readCommittedArtifact(paths.PrivateKeyPath, nginx.MaximumGraphFileSize, 0o600)
	if err != nil {
		return err
	}
	certificate, err := nginx.ParseDefaultCertificate(certificatePEM, privateKeyPEM)
	if err != nil {
		return err
	}
	wantDNS, _ := nginx.ExpectedDefaultDNSName(journal.InstallationID)
	if certificate.DNSName != wantDNS {
		return fmt.Errorf("default rejection certificate does not bind installation identity")
	}
	baseline, err := nginx.RenderBaseline(paths, journal.InstallationID, journal.GenerationID, certificate.Fingerprint)
	if err != nil {
		return err
	}
	for path, data := range baseline.Files {
		if err := putOrVerifyTargetFile(ctx, path, data, 0o600); err != nil {
			return err
		}
		// Main and sanitizer are immutable release assets. The manifest and
		// rejection audit are mutable authorities verified by nginx.Audit.
		if path == paths.MainPath() || path == paths.SanitizerPath() {
			journal.ArtifactDigests[path] = digestBytes(data)
		}
	}
	_, err = nginx.Audit(paths, filetxn.Owner{UID: 0, GID: 0})
	return err
}

func verifyVendorNginxMask(path string) error {
	target, err := os.Readlink(path)
	if err != nil || target != "/dev/null" {
		return fmt.Errorf("vendor Nginx unit is not exactly masked")
	}
	return nil
}
func installVendorNginxMask(systemdRoot string) error {
	path := filepath.Join(systemdRoot, "nginx.service")
	if target, err := os.Readlink(path); err == nil {
		if target == "/dev/null" {
			return nil
		}
		return fmt.Errorf("foreign Nginx unit mask target")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		return err
	}
	dir, err := os.Open(systemdRoot)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func rejectForeignNginxAuthority() error {
	for _, path := range []string{"/etc/nginx/sites-enabled/default", "/etc/systemd/system/nginx.service.d", "/run/systemd/system.control/nginx.service", "/run/systemd/system.control/nginx.service.d", "/run/systemd/transient/nginx.service", "/run/systemd/transient/nginx.service.d", "/run/systemd/system.attached/nginx.service", "/run/systemd/system.attached/nginx.service.d", "/run/systemd/generator.early/nginx.service", "/run/systemd/generator.early/nginx.service.d", "/run/systemd/system/nginx.service", "/run/systemd/system/nginx.service.d", "/run/systemd/generator/nginx.service", "/run/systemd/generator/nginx.service.d", "/usr/local/lib/systemd/system/nginx.service", "/usr/local/lib/systemd/system/nginx.service.d", "/run/systemd/generator.late/nginx.service", "/run/systemd/generator.late/nginx.service.d"} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("foreign Nginx site or unit authority exists at %q", path)
		}
	}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(table)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 3 && fields[3] == "0A" && (strings.HasSuffix(fields[1], ":0050") || strings.HasSuffix(fields[1], ":01BB")) {
				return fmt.Errorf("foreign listener already owns required Nginx port")
			}
		}
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
	nginxPaths := nginx.FixedPaths()
	if paths != FixedPaths() {
		nginxPaths = testNginxPaths(paths)
	}
	candidates = append(candidates, nginxPaths.ConfigRoot, nginxPaths.StateRoot, nginxPaths.AuditPath)
	for _, name := range []string{"lanpanel-management.socket", "lanpanel-ui.service", "lanpanel-runtime.service", "lanpanel-process-guard.service", "lanpanel-helper.service", "lanpanel-timer.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"} {
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
	}{{"admin-token", 0o600, 4096}, {"bundle.json", 0o600, MaximumJournalBytes}, {"default-rejection.crt", 0o644, nginx.MaximumGraphFileSize}, {"default-rejection.key", 0o600, nginx.MaximumGraphFileSize}, {"host-fingerprint", 0o600, 4096}, {"managed-confinement.json", 0o600, 64 << 10}, {"os-profile.digest", 0o600, 4096}, {"release-envelope.digest", 0o600, 4096}} {
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
		if path == "default_rejection_certificate" {
			data, err := readCommittedArtifact(filepath.Join(journal.Paths.InstallationRoot, "default-rejection.crt"), nginx.MaximumGraphFileSize, 0o644)
			if err != nil || digestBytes(data) != digest {
				return fmt.Errorf("default rejection certificate differs")
			}
			continue
		}
		if path == filepath.Join(journal.Paths.SystemdRoot, "nginx.service") {
			if digest != digestBytes([]byte("/dev/null")) || verifyVendorNginxMask(path) != nil {
				return fmt.Errorf("vendor Nginx unit mask differs")
			}
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
	}{{"admin-token", 0o600, 4096}, {"default-rejection.crt", 0o644, nginx.MaximumGraphFileSize}, {"default-rejection.key", 0o600, nginx.MaximumGraphFileSize}, {"host-fingerprint", 0o600, 4096}, {"os-profile.digest", 0o600, 4096}, {"release-envelope.digest", 0o600, 4096}} {
		if _, err := readCommittedArtifact(filepath.Join(paths.InstallationRoot, member.name), member.maximum, member.mode); err != nil {
			return err
		}
	}
	for path, digest := range journal.ArtifactDigests {
		if path == "release_binary" || path == "installation_bundle" {
			continue
		}
		if path == "default_rejection_certificate" {
			data, err := readCommittedArtifact(filepath.Join(paths.InstallationRoot, "default-rejection.crt"), nginx.MaximumGraphFileSize, 0o644)
			if err != nil || digestBytes(data) != digest {
				return fmt.Errorf("default rejection certificate differs")
			}
			continue
		}
		if path == filepath.Join(paths.SystemdRoot, "nginx.service") {
			if digest != digestBytes([]byte("/dev/null")) || verifyVendorNginxMask(path) != nil {
				return fmt.Errorf("vendor Nginx unit mask differs")
			}
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
