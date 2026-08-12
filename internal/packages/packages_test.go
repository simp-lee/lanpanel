package packages

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"lanpanel/internal/child"
	"lanpanel/internal/preflight"
	"lanpanel/internal/sources"
)

func TestPackageNoAutostartRoleAlwaysDeniesMaintainerStarts(t *testing.T) {
	for _, arguments := range [][]string{{"nginx", "start"}, {"apache2", "restart"}, {"--hostile"}, nil} {
		if code := NoAutostartExitCode(arguments); code != 101 {
			t.Fatalf("policy exit=%d for %v", code, arguments)
		}
	}
}

func TestDistroPackageClosureAllowsOnlyAmd64AndArchitectureIndependentPackages(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	plan.Packages = clonePackages(plan.Packages)
	plan.Packages[0].Architecture = "all"
	plan.Packages[0].Source.Artifact.Architecture = "all"
	closure, _ := ClosureDigest(plan.Packages)
	plan.Authority.FrozenClosureDigest = closure
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	plan.Packages[0].Architecture = "arm64"
	plan.Packages[0].Source.Artifact.Architecture = "arm64"
	closure, _ = ClosureDigest(plan.Packages)
	plan.Authority.FrozenClosureDigest = closure
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("unsupported package architecture was accepted")
	}
}

func TestPackagePlanBindsExactQualifiedClosureRepositoriesAndNoNetwork(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	offline := testPlan(t, OfflineDebs)
	if err := ValidatePlan(offline); err != nil {
		t.Fatal(err)
	}
	changed := offline
	changed.Packages = clonePackages(offline.Packages)
	changed.Packages[0].Version = "latest"
	if err := ValidatePlan(changed); err == nil {
		t.Fatal("floating package version was accepted")
	}
	changed = offline
	changed.NoNetwork = false
	if err := ValidatePlan(changed); err == nil {
		t.Fatal("offline package transaction without no-network authority was accepted")
	}
	changed = offline
	changed.Authority.FrozenClosureDigest = strings.Repeat("0", 64)
	if err := ValidatePlan(changed); err == nil {
		t.Fatal("qualification authority with a different closure was accepted")
	}
	apache := testPlan(t, DistroRepository)
	apache.Packages = clonePackages(apache.Packages)
	apache.Packages[0].Name = "apache2"
	closure, _ := ClosureDigest(apache.Packages)
	apache.Authority.FrozenClosureDigest = closure
	if err := ValidatePlan(apache); err == nil {
		t.Fatal("Apache HTTP Server package was accepted in the closure")
	}
}

func TestPackageConfigurationRejectsHooksAmbientProxyUnsafeFilesAndRepositoryDrift(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	keyring := []byte("test keyring identity")
	keyringDigest := fmt.Sprintf("%x", sha256.Sum256(keyring))
	plan.Repositories[0].KeyringDigest = keyringDigest
	files := []ObservedConfig{
		{Path: "/etc/apt/apt.conf", Kind: APTConfig, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte(`APT::Get::Assume-Yes "false";`)},
		{Path: "/etc/apt/keyrings/lanpanel.gpg", Kind: APTKeyring, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: keyring},
		{Path: "/etc/apt/sources.list", Kind: APTSource, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte("deb [signed-by=/etc/apt/keyrings/lanpanel.gpg] https://deb.example.test/debian stable main\n")},
	}
	repositories := []ObservedRepository{{ID: plan.Repositories[0].ID, URI: plan.Repositories[0].URI, Suite: plan.Repositories[0].Suite, Components: []string{"main"}, KeyringPath: plan.Repositories[0].KeyringPath, KeyringDigest: keyringDigest, Enabled: true}}
	if err := ValidateAPTConfiguration(files, repositories, plan.Repositories); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []string{`DPkg::Pre-Invoke { "bad"; };`, `Acquire::http::Proxy "http://ambient";`, `Dir::Bin::dpkg "/tmp/other";`, `Dir { Bin { dpkg "/tmp/other"; }; };`, `Acquire { http { Proxy "http://ambient"; }; };`, `APT::Get::AllowUnauthenticated "true";`} {
		changed := append([]ObservedConfig(nil), files...)
		changed[0].Bytes = []byte(hostile)
		if err := ValidateAPTConfiguration(changed, repositories, plan.Repositories); err == nil {
			t.Fatalf("hostile APT config %q was accepted", hostile)
		}
	}
	unsafe := append([]ObservedConfig(nil), files...)
	unsafe[0].ParentsSafe = false
	if err := ValidateAPTConfiguration(unsafe, repositories, plan.Repositories); err == nil {
		t.Fatal("APT config below an unsafe parent was accepted")
	}
	drifted := append([]ObservedRepository(nil), repositories...)
	drifted[0].URI = "https://other.example.test/debian"
	if err := ValidateAPTConfiguration(files, drifted, plan.Repositories); err == nil {
		t.Fatal("unexpected repository was accepted")
	}
	if err := ValidateDPKGReady(DPKGState{HalfConfigured: []string{"nginx"}}); err == nil {
		t.Fatal("half-configured dpkg state was accepted")
	}
}

func TestPackageTransactionRequiresFreshSharedExpansionPreflight(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	engine, result := testEngine(&memoryJournals{}, executor, &fakeMonitor{})
	blocked := result
	blocked.Allowed = false
	blocked.Findings[0].Disposition = preflight.FindingBlocked
	if _, err := engine.Execute(context.Background(), plan, blocked); err == nil {
		t.Fatal("package transaction ran without allowed shared expansion preflight")
	}
	result.Target = "resource/other"
	if _, err := engine.Execute(context.Background(), plan, result); err == nil {
		t.Fatal("package transaction accepted target-mismatched preflight")
	}
	engine, result = testEngine(&memoryJournals{}, executor, &fakeMonitor{})
	engine.Now = func() time.Time { return result.ValidUntil.Add(time.Nanosecond) }
	if _, err := engine.Execute(context.Background(), plan, result); err == nil {
		t.Fatal("package transaction accepted stale preflight")
	}
}

func TestPackageTransactionJournalsMasksMonitorsAndUsesTypedChild(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	journals := &memoryJournals{}
	monitor := &fakeMonitor{}
	engine, result := testEngine(journals, executor, monitor)
	journal, err := engine.Execute(context.Background(), plan, result)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != JournalCleaned || executor.profile != child.ProfileAPTOfflineTransaction || executor.invocation.Package == nil || executor.invocation.Package.TransactionID != plan.TransactionID || !reflect.DeepEqual(executor.unmasked, []string{"nginx.service"}) {
		t.Fatalf("journal=%#v profile=%q invocation=%#v unmasked=%v", journal, executor.profile, executor.invocation, executor.unmasked)
	}
	if !reflect.DeepEqual(monitor.units, []string{"nginx.service"}) || !reflect.DeepEqual(monitor.listeners, []string{"tcp/443", "tcp/80"}) {
		t.Fatalf("monitor units=%v listeners=%v", monitor.units, monitor.listeners)
	}
	wantPhases := []JournalPhase{JournalPrepared, JournalFilesPrepared, JournalArtifactsStaged, JournalMasking, JournalMasking, JournalMasksApplied, JournalChildSubmitted, JournalChildTerminal, JournalVerified, JournalCommitted, JournalCleaned}
	if !slices.Equal(journals.phases, wantPhases) {
		t.Fatalf("journal phases=%v want=%v", journals.phases, wantPhases)
	}
}

func TestPackageTransactionPreservesPreparedJournalAcrossMaskCommitFault(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	journals := &memoryJournals{failAt: JournalMasksApplied}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalMasking || len(journal.Masks) != 1 || len(executor.unmasked) != 0 || !reflect.DeepEqual(journal.Prior, executor.audit.Before) {
		t.Fatalf("journal=%#v unmasked=%v error=%v", journal, executor.unmasked, err)
	}
}

func TestPackageTransactionPreservesPartialJournalAndMasksOnTimeout(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	executor.runErr = context.DeadlineExceeded
	journals := &memoryJournals{}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalChildTerminal || journal.ErrorCode != "package_child_interrupted" || len(executor.unmasked) != 0 {
		t.Fatalf("journal=%#v unmasked=%v error=%v", journal, executor.unmasked, err)
	}
}

func TestPackageTransactionPreservesPartialJournalAndMasksOnBypass(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	executor := newFakeExecutor(plan)
	journals := &memoryJournals{}
	monitor := &fakeMonitor{terminal: errors.New("new listener observed")}
	engine, result := testEngine(journals, executor, monitor)
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalChildTerminal || journal.ErrorCode != "unit_or_listener_bypass" || len(executor.unmasked) != 0 {
		t.Fatalf("journal=%#v unmasked=%v error=%v", journal, executor.unmasked, err)
	}
	if !slices.Contains(maskNames(journal.Masks), "nginx.service") {
		t.Fatal("partial journal lost the retained no-start mask")
	}
}

func testEngine(journals JournalStore, executor Executor, monitor Monitor) (Engine, preflight.Result) {
	now := time.Unix(1_700_000_000, 0).UTC()
	result := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: 1, RequestDigest: "sha256:" + strings.Repeat("6", 64), Allowed: true, ObservedAt: now, ValidUntil: now.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "ready", Disposition: preflight.FindingPassed, Summary: "shared expansion preflight passed", Identity: "fixture"}}}
	return Engine{Journals: journals, Executor: executor, Monitor: monitor, Now: func() time.Time { return now }}, result
}

func testPlan(t *testing.T, mode Mode) Plan {
	t.Helper()
	packages := []Package{
		{Name: "apache2-utils", Version: "2.4.62-1", Architecture: "amd64", ArtifactDigest: strings.Repeat("b", 64), ArtifactBytes: 1024, MaximumInstalledFileBytes: 8 << 20, AffectedUnits: []string{}, PossibleListeners: []string{}},
		{Name: "nginx", Version: "1.22.1-9", Architecture: "amd64", ArtifactDigest: strings.Repeat("c", 64), ArtifactBytes: 2048, MaximumInstalledFileBytes: 16 << 20, AffectedUnits: []string{"nginx.service"}, PossibleListeners: []string{"tcp/443", "tcp/80"}},
	}
	noNetwork := mode != DistroRepository
	for index := range packages {
		artifact := sources.Artifact{Name: packages[index].Name, Version: packages[index].Version, OperatingOS: "linux", Architecture: "amd64", Digest: packages[index].ArtifactDigest}
		switch mode {
		case DistroRepository:
			packages[index].Source = sources.Source{Kind: sources.OfficialDistro, Artifact: artifact, OfficialAuthorities: []string{}}
		case StagedDebs:
			packages[index].StagedIdentity = "sha256:" + packages[index].ArtifactDigest
			packages[index].Source = sources.Source{Kind: sources.OfficialCanonical, URL: "https://downloads.example.test/" + packages[index].Name + ".deb", OfficialAuthorities: []string{"downloads.example.test"}, Artifact: artifact}
		case OfflineDebs:
			packages[index].StagedIdentity = "sha256:" + packages[index].ArtifactDigest
			packages[index].Source = sources.Source{Kind: sources.Offline, OfflinePath: "/var/lib/lanpanel/imports/" + packages[index].ArtifactDigest + ".deb", Artifact: artifact, OfficialAuthorities: []string{}}
		}
	}
	closure, err := ClosureDigest(packages)
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		TransactionID: "pkg_" + strings.Repeat("1", 64), JobID: "job_" + strings.Repeat("2", 64), IntentGeneration: 1, Deadline: time.Unix(2_000_000_000, 0).UTC(), OSProfileDigest: strings.Repeat("a", 64), Mode: mode, Packages: packages, FirstNginxInstall: true,
		LockWait: 30 * time.Second, ConnectTimeout: 15 * time.Second, ReadTimeout: 30 * time.Second, TotalTimeout: 2 * time.Minute, NoNetwork: noNetwork, NoAutostartPolicyDigest: strings.Repeat("9", 64), PreflightDigest: "sha256:" + strings.Repeat("6", 64), PreflightRequestDigest: "sha256:" + strings.Repeat("6", 64),
		Authority: QualificationAuthority{Kind: QualificationCandidate, EnvelopeDigest: strings.Repeat("d", 64), BinaryDigest: strings.Repeat("e", 64), RunID: "run-1", ManifestDigest: strings.Repeat("7", 64), HostFingerprint: "host/fingerprint", CaseID: "package-install", Operation: "package_transaction", TargetOSProfileDigest: strings.Repeat("a", 64), FrozenClosureDigest: closure},
	}
	if mode == DistroRepository {
		keyringDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("keyring")))
		plan.Repositories = []Repository{{ID: "debian-stable", URI: "https://deb.example.test/debian", Suite: "stable", Components: []string{"main"}, KeyringPath: "/etc/apt/keyrings/lanpanel.gpg", KeyringDigest: keyringDigest}}
	}
	return plan
}

func clonePackages(values []Package) []Package {
	result := append([]Package(nil), values...)
	for index := range result {
		result[index].AffectedUnits = append([]string(nil), result[index].AffectedUnits...)
		result[index].PossibleListeners = append([]string(nil), result[index].PossibleListeners...)
	}
	return result
}

type memoryJournals struct {
	current *Journal
	phases  []JournalPhase
	failAt  JournalPhase
}

func (store *memoryJournals) Create(_ context.Context, journal Journal) error {
	if store.current != nil {
		return errors.New("collision")
	}
	copy := journal
	store.current = &copy
	store.phases = append(store.phases, journal.Phase)
	return nil
}
func (store *memoryJournals) Advance(_ context.Context, before, after Journal) error {
	if store.failAt == after.Phase {
		return errors.New("journal fault")
	}
	if store.current == nil || !reflect.DeepEqual(*store.current, before) {
		return errors.New("stale journal")
	}
	if err := ValidateJournalTransition(before, after); err != nil {
		return err
	}
	copy := after
	store.current = &copy
	store.phases = append(store.phases, after.Phase)
	return nil
}

type fakeExecutor struct {
	audit      Audit
	observed   Postcondition
	profile    child.ProfileID
	invocation child.Invocation
	unmasked   []string
	runErr     error
}

func newFakeExecutor(plan Plan) *fakeExecutor {
	before := RuntimeSnapshot{SystemPackages: []InstalledPackage{{Name: "base-files", Version: "1", Architecture: "amd64"}}, Units: []UnitState{{Name: "nginx.service"}}, Listeners: []Listener{{Protocol: "tcp", Port: 22, Owner: "sshd"}}}
	configuration := []ObservedConfig{{Path: "/etc/apt/apt.conf", Kind: APTConfig, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte("// safe\n")}}
	repositories := []ObservedRepository{}
	if plan.Mode == DistroRepository {
		keyring := []byte("keyring")
		digest := fmt.Sprintf("%x", sha256.Sum256(keyring))
		configuration = append(configuration,
			ObservedConfig{Path: "/etc/apt/keyrings/lanpanel.gpg", Kind: APTKeyring, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: keyring},
		)
		repositories = append(repositories, ObservedRepository{ID: plan.Repositories[0].ID, URI: plan.Repositories[0].URI, Suite: plan.Repositories[0].Suite, Components: append([]string(nil), plan.Repositories[0].Components...), KeyringPath: plan.Repositories[0].KeyringPath, KeyringDigest: digest, Enabled: true})
	}
	policy := NoAutostartPolicy{Path: "/usr/sbin/policy-rc.d", Digest: plan.NoAutostartPolicyDigest, UID: 0, GID: 0, Mode: 0o755, Regular: true, ParentsSafe: true, SameLanPanelBinary: true}
	htpasswd := &FileIdentity{Path: "/usr/bin/htpasswd", UID: 0, GID: 0, Mode: 0o755, Regular: true, ParentsSafe: true, Digest: strings.Repeat("8", 64)}
	systemPackages := append(append([]InstalledPackage(nil), before.SystemPackages...), InstalledPackage{Name: "apache2-utils", Version: plan.Packages[0].Version, Architecture: "amd64"}, InstalledPackage{Name: "nginx", Version: plan.Packages[1].Version, Architecture: "amd64"})
	slices.SortFunc(systemPackages, func(left, right InstalledPackage) int { return strings.Compare(left.Name, right.Name) })
	return &fakeExecutor{audit: Audit{Configuration: configuration, Repositories: repositories, Before: before, NoAutostart: policy}, observed: Postcondition{Installed: clonePackages(plan.Packages), SystemPackages: systemPackages, Units: []UnitState{{Name: "nginx.service", Masked: true}}, Listeners: append([]Listener(nil), before.Listeners...), HTPasswd: htpasswd}}
}
func (executor *fakeExecutor) Audit(_ context.Context, _ Plan) (Audit, error) {
	return executor.audit, nil
}
func (executor *fakeExecutor) Stage(_ context.Context, _ Plan) error { return nil }
func (executor *fakeExecutor) Prepare(_ context.Context, _ Plan, config, _ []byte) error {
	if len(config) == 0 {
		return errors.New("missing package config")
	}
	return nil
}
func (executor *fakeExecutor) Resolve(_ context.Context, plan Plan) ([]Package, error) {
	return clonePackages(plan.Packages), nil
}
func (executor *fakeExecutor) Mask(_ context.Context, units []string, persist func(MaskIdentity) error) (MaskResult, error) {
	identities := make([]MaskIdentity, 0, len(units))
	for index, unit := range units {
		identity := MaskIdentity{Unit: unit, Device: 1, Inode: uint64(index + 1)}
		if err := persist(identity); err != nil {
			return MaskResult{Masks: identities}, err
		}
		identities = append(identities, identity)
	}
	return MaskResult{Masks: identities}, nil
}
func (executor *fakeExecutor) Run(_ context.Context, profile child.ProfileID, invocation child.Invocation) (child.Result, error) {
	executor.profile, executor.invocation = profile, invocation
	return child.Result{ExitCode: 0, StdoutDigest: "sha256:" + strings.Repeat("1", 64), StderrDigest: "sha256:" + strings.Repeat("2", 64)}, executor.runErr
}
func (executor *fakeExecutor) Observe(_ context.Context, _ Plan) (Postcondition, error) {
	return executor.observed, nil
}
func (executor *fakeExecutor) Unmask(_ context.Context, masks []MaskIdentity) error {
	executor.unmasked = createdMaskNames(masks)
	return nil
}

type fakeMonitor struct {
	units, listeners []string
	terminal         error
}

func (monitor *fakeMonitor) Start(ctx context.Context, units, listeners []string) (context.Context, func() error, error) {
	monitor.units = append([]string(nil), units...)
	monitor.listeners = append([]string(nil), listeners...)
	return ctx, func() error { return monitor.terminal }, nil
}
