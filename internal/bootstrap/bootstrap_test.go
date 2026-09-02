//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/child"
	"lanpanel/internal/identity"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBPFGuardDirectoryRequiresExactBPFFSMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root runtime-guard test")
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), " /sys/fs/bpf ") {
		t.Skip("test runner has no bpffs")
	}
	if err := ensureBPFGuardDirectory(); err != nil {
		t.Fatal(err)
	}
}

func TestCommittedReleaseRejectsManagedACMEAccountKeyReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned installation authority test")
	}
	root := t.TempDir()
	paths := testPaths(root)
	if err := os.Mkdir(paths.InstallationRoot, 0o711); err != nil {
		t.Fatal(err)
	}
	journal := testJournal(root)
	key, err := acmeaccount.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ACMEAccountKey, key, 0o600); err != nil {
		t.Fatal(err)
	}
	keyFingerprint, _ := acmeaccount.Fingerprint(key)
	fingerprint, _ := identity.Fingerprint(journal.InstallationID)
	bundle := Bundle{SchemaVersion: BundleSchemaVersion, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, SafetyGeneration: journal.SafetyGeneration, Fingerprint: fingerprint, Management: journal.Authority, Release: journal.Release, PreflightDigest: journal.PreflightDigest, ACMEAccountContact: journal.ACMEAccountContact, ACMEAccountKeyFingerprint: keyFingerprint}
	bundleBytes, _ := encodeCanonical(bundle)
	if err := os.WriteFile(filepath.Join(paths.InstallationRoot, "bundle.json"), bundleBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	commit := Commit{SchemaVersion: CommitSchemaVersion, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, JournalSequence: 2, BundleDigest: digestBytes(bundleBytes), ArtifactDigest: strings.Repeat("f", 64), CommittedAt: time.Unix(1_700_000_000, 0).UTC()}
	commitBytes, _ := encodeCanonical(commit)
	if err := os.WriteFile(paths.CommitPath, commitBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCommittedReleaseIdentity(paths); err != nil {
		t.Fatal(err)
	}
	replacement, _ := acmeaccount.Generate(rand.Reader)
	if err := os.WriteFile(paths.ACMEAccountKey, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCommittedReleaseIdentity(paths); err == nil {
		t.Fatal("replacement managed ACME account key retained release authority")
	}
}

func TestFixedManagedACMEAccountKeyIsPlannedAndBundleBound(t *testing.T) {
	paths := FixedPaths()
	if paths.ACMEAccountKey != "/var/lib/lanpanel/installation/acme-account.key" {
		t.Fatal(paths.ACMEAccountKey)
	}
	planned, err := plannedBootstrapPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(planned, paths.ACMEAccountKey) {
		t.Fatal("managed ACME account key is absent from bootstrap inventory")
	}
	journal := testJournal(t.TempDir())
	fingerprint, _ := identity.Fingerprint(journal.InstallationID)
	bundle := Bundle{SchemaVersion: BundleSchemaVersion, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, SafetyGeneration: journal.SafetyGeneration, Fingerprint: fingerprint, Management: journal.Authority, Release: journal.Release, PreflightDigest: journal.PreflightDigest, ACMEAccountContact: journal.ACMEAccountContact, ACMEAccountKeyFingerprint: "sha256:" + strings.Repeat("a", 64)}
	if err := validateBundle(bundle); err != nil {
		t.Fatal(err)
	}
	bundle.ACMEAccountKeyFingerprint = ""
	if err := validateBundle(bundle); err == nil {
		t.Fatal("bundle accepted no ACME account key authority")
	}
}

func TestFixedBootstrapPreflightRequirementsAreCanonical(t *testing.T) {
	paths := FixedPaths()
	managed := FixedManagedPathRequirements(paths)
	for index := 1; index < len(managed); index++ {
		if managed[index-1].Path >= managed[index].Path {
			t.Fatal("fixed managed paths are not canonical")
		}
	}
	disks := FixedDiskRequirements(paths)
	for index := 1; index < len(disks); index++ {
		if disks[index-1].Path >= disks[index].Path {
			t.Fatal("fixed disk requirements are not canonical")
		}
	}
}

func TestBootstrapRejectsBeforeFirstSideEffect(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	request := Request{Paths: paths, Random: errorReader{}, Preflight: func(context.Context, identity.ManagementAuthority, uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		t.Fatal("preflight called without release authority")
		return preflight.ExpansionRequest{}, preflight.Result{}, nil
	}}
	if err := install(context.Background(), request, false); err == nil {
		t.Fatal("missing release authority accepted")
	}
	if _, err := os.Lstat(paths.Journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal side effect exists: %v", err)
	}
}

func TestInstallerPackagePhaseBindsReleaseRepositoryClosureAndPreflight(t *testing.T) {
	installed := testJournal(t.TempDir()).Release
	now := time.Now().UTC().Truncate(time.Second)
	packageValues := []packages.Package{
		{Name: "apache2-utils", Version: "2.4.62-1", Architecture: "amd64", ArtifactDigest: strings.Repeat("a", 64), ArtifactBytes: 1, MaximumInstalledFileBytes: 1 << 20, AffectedUnits: []string{}, PossibleListeners: []string{}},
		{Name: "goaccess", Version: "1.9.3-1", Architecture: "amd64", ArtifactDigest: strings.Repeat("b", 64), ArtifactBytes: 1, MaximumInstalledFileBytes: 1 << 20, AffectedUnits: []string{}, PossibleListeners: []string{}},
		{Name: "nginx", Version: "1.26.0-1", Architecture: "amd64", ArtifactDigest: strings.Repeat("c", 64), ArtifactBytes: 1, MaximumInstalledFileBytes: 1 << 20, AffectedUnits: []string{"nginx.service"}, PossibleListeners: []string{"tcp/443", "tcp/80"}},
	}
	for index := range packageValues {
		pkg := &packageValues[index]
		pkg.Source = sources.Source{Kind: sources.OfficialDistro, Artifact: sources.Artifact{Name: pkg.Name, Version: pkg.Version, OperatingOS: "linux", Architecture: pkg.Architecture, Digest: pkg.ArtifactDigest}, OfficialAuthorities: []string{}}
	}
	closure, err := packages.ClosureDigest(packageValues)
	if err != nil {
		t.Fatal(err)
	}
	installed.Profile.Packages = []release.PackageTuple{{Name: "apache2-utils", Version: "2.4.62-1", Architecture: "amd64"}, {Name: "goaccess", Version: "1.9.3-1", Architecture: "amd64"}, {Name: "nginx", Version: "1.26.0-1", Architecture: "amd64"}}
	installed.Profile.PackageClosureDigest = closure
	installed.Profile.NginxVersion = "1.26.0-1"
	repository := packages.Repository{ID: "debian", URI: installed.Profile.RepositorySource, Suite: "trixie", Components: []string{"main"}, KeyringPath: "/etc/apt/keyrings/lanpanel.gpg", KeyringDigest: installed.Profile.RepositoryKeyFingerprint, MetadataDigest: installed.Profile.RepositoryMetadataDigest, CutoffDigest: installed.Profile.RepositoryCutoffDigest}
	installed.Profile.RepositoryAuthorityDigest, err = release.RepositoryAuthorityDigest(repository)
	if err != nil {
		t.Fatal(err)
	}
	installed.ProfileDigest, err = release.ProfileDigest(installed.Profile)
	if err != nil {
		t.Fatal(err)
	}
	plan := packages.Plan{TransactionID: "pkg_" + strings.Repeat("1", 64), JobID: "job_" + strings.Repeat("2", 64), IntentGeneration: 1, Deadline: now.Add(time.Minute), OSProfileDigest: installed.ProfileDigest, Mode: packages.DistroRepository, Packages: packageValues, Repositories: []packages.Repository{repository}, FirstNginxInstall: true, LockWait: 30 * time.Second, ConnectTimeout: 15 * time.Second, ReadTimeout: 30 * time.Second, TotalTimeout: time.Minute, NoAutostartPolicyDigest: strings.Repeat("9", 64), Authority: packages.QualificationAuthority{Kind: packages.FinalSupportedProfile, ReleaseAuthorityDigest: installed.ReleaseManifestDigest, BinaryDigest: installed.Binary.Digest, HostFingerprint: installed.HostFingerprint, Operation: "package_transaction", TargetOSProfileDigest: installed.ProfileDigest, FrozenClosureDigest: closure}}
	result := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: 1, RequestDigest: "sha256:" + strings.Repeat("6", 64), Allowed: true, ObservedAt: now, ValidUntil: now.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "package_ready", Disposition: preflight.FindingPassed, Summary: "package preflight", Identity: "fixture"}}}
	plan.PreflightDigest, err = result.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.PreflightRequestDigest = result.RequestDigest
	if _, err := validateInstallerPackageAuthority(installed, plan, result); err != nil {
		t.Fatal(err)
	}
	plan.Repositories[0].MetadataDigest = strings.Repeat("0", 64)
	if _, err := validateInstallerPackageAuthority(installed, plan, result); err == nil {
		t.Fatal("repository metadata drift retained installer package authority")
	}
}

func TestBootstrapJournalPackageAuthorityUsesExactPersistedPlan(t *testing.T) {
	journal := testJournal(t.TempDir())
	profile := journal.Release.Profile
	packageValue := packages.Package{Name: "nginx", Version: profile.NginxVersion, Architecture: "amd64", ArtifactDigest: strings.Repeat("a", 64), ArtifactBytes: 1, MaximumInstalledFileBytes: 1 << 20, AffectedUnits: []string{}, PossibleListeners: []string{}, Source: sources.Source{Kind: sources.OfficialDistro, Artifact: sources.Artifact{Name: "nginx", Version: profile.NginxVersion, OperatingOS: "linux", Architecture: "amd64", Digest: strings.Repeat("a", 64)}}}
	closure, err := packages.ClosureDigest([]packages.Package{packageValue})
	if err != nil {
		t.Fatal(err)
	}
	profile.PackageClosureDigest = closure
	repository := packages.Repository{ID: "debian", URI: profile.RepositorySource, Suite: "trixie", Components: []string{"main"}, KeyringPath: "/etc/apt/keyrings/lanpanel.gpg", KeyringDigest: profile.RepositoryKeyFingerprint, MetadataDigest: profile.RepositoryMetadataDigest, CutoffDigest: profile.RepositoryCutoffDigest}
	profile.RepositoryAuthorityDigest, err = release.RepositoryAuthorityDigest(repository)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := release.ProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	journal.Release.Profile = profile
	journal.Release.ProfileDigest = profileDigest
	request := journal.PreflightRequest
	requestDigest, err := preflight.ExpansionRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	result := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: 1, RequestDigest: requestDigest, Allowed: true, ObservedAt: now, ValidUntil: now.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "package_ready", Disposition: preflight.FindingPassed, Summary: "package preflight", Identity: "fixture"}}}
	plan := packages.Plan{TransactionID: journal.PackageTransactionID, JobID: "job_" + strings.Repeat("1", 64), IntentGeneration: 1, Deadline: now.Add(time.Minute), OSProfileDigest: profileDigest, Mode: packages.DistroRepository, Packages: []packages.Package{packageValue}, Repositories: []packages.Repository{repository}, FirstNginxInstall: false, LockWait: 30 * time.Second, ConnectTimeout: 15 * time.Second, ReadTimeout: 30 * time.Second, TotalTimeout: time.Minute, NoAutostartPolicyDigest: journal.Release.Binary.Digest, PreflightRequestDigest: requestDigest, Authority: packages.QualificationAuthority{Kind: packages.FinalSupportedProfile, ReleaseAuthorityDigest: journal.Release.ReleaseManifestDigest, BinaryDigest: journal.Release.Binary.Digest, HostFingerprint: journal.Release.HostFingerprint, Operation: "package_transaction", TargetOSProfileDigest: profileDigest, FrozenClosureDigest: closure}}
	plan.PreflightDigest, err = result.Digest()
	if err != nil {
		t.Fatal(err)
	}
	journal.PackagePlan = plan
	journal.PackagePreflight = result
	journal.PackagePlanDigest, err = packages.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	journal.PackageInputPlanDigest = journal.PackagePlanDigest
	if err := validateJournalPackageAuthority(journal); err != nil {
		t.Fatal(err)
	}
	fresh := result
	fresh.ObservedAt = now.Add(time.Second)
	fresh.ValidUntil = fresh.ObservedAt.Add(preflight.MaximumAge)
	refreshed, refreshedDigest, err := refreshPackagePlanForResume(journal.Release, plan, request, fresh, fresh.ObservedAt.Add(time.Second))
	if err != nil || refreshedDigest == journal.PackagePlanDigest || refreshed.PreflightDigest == plan.PreflightDigest {
		t.Fatalf("fresh package authority did not produce a distinct plan: plan=%#v digest=%q err=%v", refreshed, refreshedDigest, err)
	}
	if journal.PackagePlanDigest != journal.PackageInputPlanDigest {
		t.Fatal("persisted exact package authority was unexpectedly substituted")
	}
}

func TestPackagePolicyCleanupRecoversAfterSideEffectBeforeJournalAdvance(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	policyPath := filepath.Join(root, "sbin", "policy-rc.d")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	policy := []byte("exact package no-autostart policy")
	if err := os.WriteFile(policyPath, policy, 0o755); err != nil {
		t.Fatal(err)
	}
	durable := testJournal(root)
	durable.Phase = PhaseNginxMasked
	durable.Paths = paths
	durable.Release.Binary.Bytes = uint64(len(policy))
	durable.Release.Binary.Digest = digestBytes(policy)
	durable.Release.CandidateDigest = durable.Release.Binary.Digest
	durable.ArtifactDigests["/usr/sbin/policy-rc.d"] = durable.Release.Binary.Digest
	packageJournal := packages.Journal{
		SchemaVersion: packages.PackageJournalSchemaVersion, TransactionID: durable.PackageTransactionID,
		NormalJournalID: "package-" + durable.PackageTransactionID, ChildID: "package-child-" + durable.PackageTransactionID,
		JobID: "job_" + strings.Repeat("1", 64), PlanDigest: durable.PackagePlanDigest, AuthorityDigest: strings.Repeat("2", 64), PackageProfile: child.ProfileAPTTransaction,
		Prior: packages.RuntimeSnapshot{}, Phase: packages.JournalCleaned, Masks: []packages.MaskIdentity{}, MasksComplete: true,
		ChildResultDigest: strings.Repeat("3", 64), ChildSucceeded: true, PostconditionDigest: strings.Repeat("4", 64),
	}
	cloneDurable := func() Journal {
		value := durable
		value.ArtifactDigests = make(map[string]string, len(durable.ArtifactDigests))
		for path, digest := range durable.ArtifactDigests {
			value.ArtifactDigests[path] = digest
		}
		return value
	}

	syncFailure := errors.New("simulated policy directory sync failure")
	if err := removeBootstrapPolicyWithSync(durable.Release.Binary, durable.Paths, func(int) error { return syncFailure }, syncParentDirectory); !errors.Is(err, syncFailure) {
		t.Fatalf("policy namespace interruption error=%v", err)
	}
	if _, err := os.Lstat(policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted policy cleanup remains: %v", err)
	}
	// Simulate failure to advance the bootstrap journal by reloading its old phase.
	// The retry must synchronize the already-absent namespace before advancing.
	retried := cloneDurable()
	if err := reconcilePackageCommit(&retried, packageJournal); err != nil {
		t.Fatalf("exact cleaned package state was not idempotently recovered: %v", err)
	}
	foreign := packageJournal
	foreign.PlanDigest = strings.Repeat("5", 64)
	if err := reconcilePackageCommit(&retried, foreign); err == nil {
		t.Fatal("missing policy was accepted for a different package journal identity")
	}
}

func TestStartupAuthorityRecoversAfterCreateBeforeJournalAdvance(t *testing.T) {
	journal := testJournal(t.TempDir())
	journal.FinalCommitDigest = strings.Repeat("f", 64)
	expected := StartupAuthority{SchemaVersion: "lanpanel.startup-authority.v1", AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, Management: journal.Authority, CommitDigest: journal.FinalCommitDigest}
	data, err := encodeCanonical(expected)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "startup-authority.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if err := finalizeStartupAuthorityFile(path, expected, uid, gid); err != nil {
		t.Fatalf("exact startup side effect was not durably accepted on old-phase retry: %v", err)
	}

	changed := expected
	changed.CommitDigest = strings.Repeat("e", 64)
	if err := verifyStartupAuthorityFile(path, changed, uid, gid); err == nil {
		t.Fatal("startup authority bound to another commit was accepted")
	}
	if err := verifyStartupAuthorityFile(path, expected, uid+1, gid); err == nil {
		t.Fatal("startup authority with a foreign UID was accepted")
	}
	if err := verifyStartupAuthorityFile(path, expected, uid, gid+1); err == nil {
		t.Fatal("startup authority with a foreign GID was accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyStartupAuthorityFile(path, expected, uid, gid); err == nil {
		t.Fatal("startup authority with a foreign mode was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	foreignBytes, _ := encodeCanonical(changed)
	if err := os.WriteFile(path, foreignBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := verifyStartupAuthorityFile(path, expected, uid, gid); err == nil {
		t.Fatal("foreign canonical startup authority bytes were accepted")
	}
}

func TestLegacyBootstrapJournalSchemaIsRejected(t *testing.T) {
	journal := testJournal(t.TempDir())
	journal.SchemaVersion = "lanpanel.bootstrap.journal.v2"
	if err := validateJournal(journal); err == nil {
		t.Fatal("legacy bootstrap journal wire was accepted as current schema")
	}
}

func TestBootstrapJournalSlotsPreserveExactAttempt(t *testing.T) {
	root := t.TempDir()
	if err := os.Chown(root, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "bootstrap-journal")
	journal := testJournal(root)
	store, err := createJournal(journalPath, uint32(os.Geteuid()), uint32(os.Getegid()), journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.Sequence = 2
	journal.Phase = PhaseBundleCommitted
	journal.PackageJournalDigest = strings.Repeat("c", 64)
	journal.ArtifactDigests["bundle"] = strings.Repeat("b", 64)
	if err := store.update(journal); err != nil {
		t.Fatal(err)
	}
	_ = store.close()
	opened, loaded, err := openJournal(journalPath, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(opened.close)
	if loaded.AttemptID != journal.AttemptID || loaded.InstallationID != journal.InstallationID || loaded.Sequence != 2 || loaded.Phase != PhaseBundleCommitted {
		t.Fatalf("loaded=%#v", loaded)
	}
}

func TestManagementAuthorityConflictFailsClosed(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.71.72.73:52345")
	if err != nil {
		t.Skip(err)
	}
	defer func(ignore func() error) { _ = ignore() }(listener.Close)
	if ManagementAuthorityAvailable(identity.ManagementAuthority{Address: "127.71.72.73", Port: 52345}) == nil {
		t.Fatal("hostile Management binding was accepted")
	}
}

func TestSystemdAssetsReserveExactAuthorityAndKeepRolesIndependent(t *testing.T) {
	journal := testJournal(t.TempDir())
	journal.Accounts.Identities = []identity.AccountIdentity{{Role: identity.RoleUI, UID: 1101, GID: 1201}, {Role: identity.RoleTimer, UID: 1102, GID: 1201}, {Role: identity.RoleRecovery, UID: 1103, GID: 1201}}
	artifacts, err := renderArtifacts(journal)
	if err != nil {
		t.Fatal(err)
	}
	helperUnit := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-helper.service")])
	for _, required := range []string{"Type=notify", "NotifyAccess=main"} {
		if !strings.Contains(helperUnit, required) {
			t.Fatalf("helper unit omitted %q: %s", required, helperUnit)
		}
	}
	socket := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-management.socket")])
	if !strings.Contains(socket, "ListenStream=127.41.42.43:52345") || !strings.Contains(socket, "FileDescriptorName=lanpanel-management-"+journal.GenerationID) || !strings.Contains(socket, "RemoveOnStop=no") {
		t.Fatalf("socket=%s", socket)
	}
	recoveryUnit := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-recovery.service")])
	for _, required := range []string{"Type=oneshot", "Before=lanpanel-nginx.service", "Requires=lanpanel-helper.service", "RestrictAddressFamilies=AF_UNIX", "RemainAfterExit=yes"} {
		if !strings.Contains(recoveryUnit, required) {
			t.Fatalf("recovery unit omitted %q: %s", required, recoveryUnit)
		}
	}
	nginxUnit := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-nginx.service")])
	for _, required := range []string{"Type=simple", "Requires=lanpanel-helper.service lanpanel-recovery.service", "After=network.target lanpanel-helper.service lanpanel-recovery.service", "ExecStart=" + journal.Paths.BinaryPath + " startup-guard", "ExecReload=" + journal.Paths.BinaryPath + " reload-guard", "ExecStop=" + journal.Paths.BinaryPath + " reload-guard stop", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE"} {
		if !strings.Contains(nginxUnit, required) {
			t.Fatalf("Nginx unit omitted %q: %s", required, nginxUnit)
		}
	}
	for _, forbidden := range []string{"Type=forking", "CAP_SYS_ADMIN", "CAP_NET_ADMIN"} {
		if strings.Contains(nginxUnit, forbidden) {
			t.Fatalf("Nginx unit contains %q: %s", forbidden, nginxUnit)
		}
	}
	ui := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-ui.service")])
	for _, forbidden := range []string{"PartOf=", "BindsTo=", "lanpanel-timer.service", "nginx", "headscale"} {
		if strings.Contains(ui, forbidden) {
			t.Fatalf("UI couples independent role through %q", forbidden)
		}
	}
}

func TestVendorNginxMaskIsExactAndPersistent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installVendorNginxMask(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nginx.service")
	if err := verifyVendorNginxMask(path); err != nil {
		t.Fatal(err)
	}
	if err := installVendorNginxMask(root); err != nil {
		t.Fatalf("exact mask retry failed: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installVendorNginxMask(root); err == nil {
		t.Fatal("foreign vendor unit was replaced by a mask")
	}
}

func TestTokenDeliveryMarksAttemptBeforeOutputAndNeverRedirectsSecret(t *testing.T) {
	root := t.TempDir()
	if err := os.Chown(root, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := testJournal(root)
	store, err := createJournal(journal.Paths.Journal, uint32(os.Geteuid()), uint32(os.Getegid()), journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.Sequence = 2
	journal.Phase = PhaseActivated
	journal.PackageJournalDigest = strings.Repeat("c", 64)
	journal.FinalCommitDigest = strings.Repeat("f", 64)
	if err := store.update(journal); err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(store.close)
	var output bytes.Buffer
	token := []byte("sentinel-admin-token")
	if err := deliverToken(store, &journal, Request{Output: &output}, token); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), string(token)) || !strings.Contains(output.String(), ProtectedAdminTokenPath) {
		t.Fatalf("redirected output=%q", output.String())
	}
	if !journal.TokenDeliveryAttempted {
		t.Fatal("delivery attempt was not durable")
	}
	output.Reset()
	if err := deliverToken(store, &journal, Request{Output: &output}, token); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatal("token delivery was replayed")
	}
}

func testJournal(root string) Journal {
	digest := func(value byte) string { return strings.Repeat(string(value), 64) }
	profile := release.OSProfile{ID: "debian-13", Family: "debian", Release: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: digest('1'), RepositorySource: "https://deb.example.test/debian", RepositoryKeyFingerprint: digest('2'), RepositoryMetadataDigest: digest('3'), RepositoryCutoffDigest: digest('4'), RepositoryAuthorityDigest: digest('6'), PackageClosureDigest: digest('5'), Packages: []release.PackageTuple{{Name: "nginx", Version: "1.26.0", Architecture: "amd64"}}, ManagedConfinement: release.ConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8", "169.254.169.254/32", "::1/128"}, QualificationDigest: digest('8')}}
	profileDigest, _ := release.ProfileDigest(profile)
	paths := testPaths(root)
	request := preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: 1, Profile: preflight.ExpectedProfile{ID: "debian", VersionID: "13", Architecture: "amd64", SystemdVersion: profile.SystemdVersion, NginxVersion: profile.NginxVersion, PackageSnapshotDigest: "sha256:" + profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: profile.ManagedConfinement.SchemaVersion, KernelRelease: profile.ManagedConfinement.KernelRelease, CgroupMode: profile.ManagedConfinement.CgroupMode, BindListenPolicy: profile.ManagedConfinement.BindListenPolicy, ConnectPolicy: profile.ManagedConfinement.ConnectPolicy, FilesystemPolicy: profile.ManagedConfinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), profile.ManagedConfinement.ProtectedDestinations...), QualificationDigest: "sha256:" + profile.ManagedConfinement.QualificationDigest}, Authority: preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + profileDigest, LiveQualified: true}}, BootstrapListeners: []preflight.ListenerRequirement{{Protocol: "tcp", Address: "127.41.42.43", Port: 52345, Purpose: "management"}}, Disks: []preflight.DiskRequirement{{Path: root, MinimumAvailableBytes: 1}}, LastTrustedWall: time.Unix(1700000000, 0).UTC()}
	requestDigest, _ := preflight.ExpansionRequestDigest(request)
	accounts, _ := identity.InstallationAccounts("ins_00000000000000000000000000000001")
	binaryDigest := digest('4')
	return Journal{SchemaVersion: JournalSchemaVersion, AttemptID: "bst_" + strings.Repeat("a", 64), InstallationID: "ins_00000000000000000000000000000001", GenerationID: "gen_00000000000000000000000000000001", SafetyGeneration: 1, Phase: PhasePrepared, Sequence: 1, Release: release.InstallIdentity{Kind: release.InstallPublicRelease, ReleaseTag: "v1.0.0", ReleaseManifestDigest: digest('2'), Binary: release.AssetIdentity{Path: "lanpanel", Digest: binaryDigest, Bytes: 1}, SourceTreeDigest: digest('5'), DependencyBaseline: release.AssetIdentity{Path: "dependency-baseline.json", Digest: digest('9'), Bytes: 1}, DependencyManifestDigest: digest('6'), Headscale: testHeadscaleAuthority(), Lego: release.AssetIdentity{Path: "lego", Digest: digest('8'), Bytes: 1}, Tailscale: release.AssetIdentity{Path: "tailscale", Digest: digest('7'), Bytes: 1}, TailscaleVersion: "1.82.0", Profile: profile, ProfileDigest: profileDigest, CandidateDigest: binaryDigest, HostFingerprint: "host-one", AuthorityCreatedAt: time.Unix(1700000000, 0).UTC()}, Authority: identity.ManagementAuthority{Address: "127.41.42.43", Port: 52345}, PreflightRequest: request, PreflightDigest: requestDigest, ACMEAccountContact: "admin@example.test", PackageTransactionID: "pkg_" + strings.Repeat("c", 64), PackagePlanDigest: strings.Repeat("d", 64), Accounts: accounts, Paths: paths, ArtifactDigests: map[string]string{"release_binary": strings.Repeat("4", 64)}, PlannedPaths: canonicalPaths([]string{paths.Journal, paths.CommitPath, paths.PersistentRoot})}
}

func testHeadscaleAuthority() release.HeadscaleArtifactAuthority {
	return release.HeadscaleArtifactAuthority{Version: "0.29.0", ArtifactIdentity: "https://downloads.example.test/headscale-0.29.0", Archive: release.AssetIdentity{Path: "headscale.tar.gz", Digest: strings.Repeat("a", 64), Bytes: 512}, ArchiveFormat: "tar_gzip", MaximumExtractedBytes: 1 << 20, RedirectAuthorities: []string{"downloads.example.test"}, Members: []release.ArchiveMemberAuthority{{Path: "headscale", Asset: release.AssetIdentity{Path: "headscale", Digest: strings.Repeat("b", 64), Bytes: 1}, Destination: "/usr/lib/lanpanel/dependencies/headscale", Mode: 0o755}}, ExecutableAsset: "headscale", InstallPath: "/usr/lib/lanpanel/dependencies/headscale", ConfigContract: "headscale-trusted-mesh-v1", ConfigContractDigest: release.SupportedHeadscaleConfigContractDigest()}
}

func testPaths(root string) Paths {
	return Paths{Journal: filepath.Join(root, "bootstrap-journal"), StartupAuthority: filepath.Join(root, "startup-authority.json"), CommitPath: filepath.Join(root, "bootstrap-commit.json"), PersistentRoot: root, InstallationRoot: filepath.Join(root, "installation"), ACMEAccountKey: filepath.Join(root, "installation", "acme-account.key"), StateRoot: filepath.Join(root, "state"), SafetyRoot: filepath.Join(root, "safety"), OwnershipRoot: filepath.Join(root, "ownership"), LockRoot: filepath.Join(root, "locks"), PackageRoot: filepath.Join(root, "packages"), RuntimeRoot: filepath.Join(root, "run"), SystemdRoot: filepath.Join(root, "systemd"), SysusersPath: filepath.Join(root, "etc", "sysusers.conf"), BinaryPath: filepath.Join(root, "usr", "lanpanel")}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

var _ io.Reader = errorReader{}
