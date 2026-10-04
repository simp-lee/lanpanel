package packages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/preflight"
	"lanpanel/internal/sources"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNginxOwnershipPolicyDistinguishesForeignAndLanPanelPackages(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	before := RuntimeSnapshot{
		Installed: []Package{{Name: "nginx"}},
		Units:     []UnitState{{Name: "nginx.service", Active: false}},
	}
	if err := validateBefore(plan, before); err == nil || !strings.Contains(err.Error(), "already installed outside LanPanel") {
		t.Fatalf("foreign Nginx package was not rejected clearly: %v", err)
	}
	plan.FirstNginxInstall = false
	if err := validateBefore(plan, before); err != nil {
		t.Fatalf("LanPanel-owned Nginx package was rejected: %v", err)
	}
	plan.FirstNginxInstall = true
	before.Installed = []Package{{Name: "goaccess"}}
	if err := validateBefore(plan, before); err != nil {
		t.Fatalf("pre-existing GoAccess blocked an otherwise fresh Nginx install: %v", err)
	}
}

func TestExternalNginxPlanOmitsOnlyNginx(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	plan.FirstNginxInstall = false
	plan.ExternalNginx = true
	original := clonePackages(plan.Packages)
	plan.Packages = slices.DeleteFunc(clonePackages(plan.Packages), func(pkg Package) bool { return pkg.Name == "nginx" })
	if err := ValidatePlan(plan); err != nil {
		t.Fatalf("external Nginx plan was rejected: %v", err)
	}
	for _, pkg := range original {
		if pkg.Name == "nginx" {
			plan.Packages = append(plan.Packages, pkg)
		}
	}
	if err := ValidatePlan(plan); err == nil || !strings.Contains(err.Error(), "must omit nginx") {
		t.Fatalf("external Nginx plan accepted a package mutation: %v", err)
	}
	plan.Packages = nil
	if err := ValidatePlan(plan); err != nil {
		t.Fatalf("Nginx-only read-only reuse plan was rejected: %v", err)
	}
}

func TestPackageNoAutostartRoleAlwaysDeniesMaintainerStarts(t *testing.T) {
	for _, arguments := range [][]string{{"nginx", "start"}, {"apache2", "restart"}, {"--hostile"}, nil} {
		if code := NoAutostartExitCode(arguments); code != 101 {
			t.Fatalf("policy exit=%d for %v", code, arguments)
		}
	}
}

func TestUserMirrorDistroPackagePlanAcceptsVersionRange(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	plan.Repositories = nil
	plan.Packages = clonePackages(plan.Packages)
	for index := range plan.Packages {
		plan.Packages[index].RepositoryID = ""
		plan.Packages[index].RepositoryFilename = ""
		plan.Packages[index].ArtifactDigest = ""
		plan.Packages[index].ArtifactBytes = 0
		plan.Packages[index].Source.Artifact.Digest = ""
		plan.Packages[index].VersionMinimum = plan.Packages[index].Version
		plan.Packages[index].VersionMaximum = ""
	}
	if err := ValidatePublicReleasePlan(plan); err != nil {
		t.Fatal(err)
	}
	if !PackageVersionMatches(plan.Packages[0], plan.Packages[0].Version) {
		t.Fatal("minimum package version did not match")
	}
	changed := plan
	changed.Packages = clonePackages(plan.Packages)
	changed.Packages[0].VersionMinimum = "9:999"
	if PackageVersionMatches(changed.Packages[0], plan.Packages[0].Version) {
		t.Fatal("out-of-range package version matched")
	}
}

func TestDistroPackagePlanAllowsOnlyAmd64AndArchitectureIndependentPackages(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	plan.Packages = clonePackages(plan.Packages)
	plan.Packages[0].Architecture = "all"
	plan.Packages[0].Source.Artifact.Architecture = "all"
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	plan.Packages[0].Architecture = "arm64"
	plan.Packages[0].Source.Artifact.Architecture = "arm64"
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("unsupported package architecture was accepted")
	}
}

func TestMultiRepositoryPlanBindsEachPackageAndRejectsAmbiguousAuthority(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	second := plan.Repositories[0]
	second.ID = "debian-security"
	second.Suite = "stable-security"
	plan.Repositories[0].ID = "debian-main"
	plan.Repositories = append(plan.Repositories, second)
	plan.Packages = clonePackages(plan.Packages)
	for index := range plan.Packages {
		if index == len(plan.Packages)-1 {
			plan.Packages[index].RepositoryID = "debian-security"
		} else {
			plan.Packages[index].RepositoryID = "debian-main"
		}
	}
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Repositories = append([]Repository(nil), plan.Repositories...)
	changed.Repositories[1].ID = changed.Repositories[0].ID
	if err := ValidatePlan(changed); err == nil {
		t.Fatal("duplicate repository identity was accepted")
	}
	changed = plan
	changed.Packages = clonePackages(plan.Packages)
	changed.Packages[0].RepositoryID = ""
	if err := ValidatePlan(changed); err == nil {
		t.Fatal("unbound multi-repository package was accepted")
	}
	changed = plan
	changed.Repositories = append([]Repository(nil), plan.Repositories...)
	slices.Reverse(changed.Repositories)
	if err := ValidatePlan(changed); err == nil {
		t.Fatal("noncanonical repository ordering was accepted")
	}
}

func TestAPTSourceFormatsAllowOptionlessTrustedAuthorities(t *testing.T) {
	binary, err := parseSourceFile("/etc/apt/sources.list", []byte("deb [arch=amd64] https://deb.example.test/debian stable main\n"))
	if err != nil || len(binary) != 1 || binary[0].KeyringPath != "" {
		t.Fatalf("optionless binary source=%#v err=%v", binary, err)
	}
	deb822, err := parseDeb822Sources([]byte("Types: deb\nURIs: https://deb.example.test/debian\nSuites: stable\nComponents: main\n\n"))
	if err != nil || len(deb822) != 1 || deb822[0].KeyringPath != "" {
		t.Fatalf("optionless deb822 source=%#v err=%v", deb822, err)
	}
}

func TestDeb822SourcesAcceptCommentsAndMultipleSuites(t *testing.T) {
	data := []byte("# Ubuntu archive authority\nTypes: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: noble noble-updates noble-security\nComponents: main universe restricted multiverse\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n")
	values, err := parseDeb822Sources(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 3 || values[0].Suite != "noble" || values[1].Suite != "noble-updates" || values[2].Suite != "noble-security" || values[0].KeyringPath != "/usr/share/keyrings/ubuntu-archive-keyring.gpg" {
		t.Fatalf("parsed deb822 repositories = %#v", values)
	}
}

func TestPackagePlanBindsExactQualifiedClosureRepositoriesAndNoNetwork(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	missingRepository := plan
	missingRepository.Packages = clonePackages(plan.Packages)
	missingRepository.Packages[0].RepositoryID = ""
	if err := ValidatePlan(missingRepository); err == nil {
		t.Fatal("distro package without a RepositoryID was accepted")
	}
	missingFilename := plan
	missingFilename.Packages = clonePackages(plan.Packages)
	missingFilename.Packages[0].RepositoryFilename = ""
	if err := ValidatePlan(missingFilename); err == nil {
		t.Fatal("distro package without the signed repository Filename was accepted")
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
}

func TestAPTConfigurationAcceptsDistroSharedKeyringPath(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	plan.Repositories[0].KeyringPath = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
	files := []ObservedConfig{
		{Path: "/etc/apt/apt.conf", Kind: APTConfig, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte(`Dir::Etc::sourceparts "-";`)},
		{Path: "/etc/apt/sources.list", Kind: APTSource, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte("deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://deb.example.test/debian stable main\n")},
		{Path: plan.Repositories[0].KeyringPath, Kind: APTKeyring, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte("keyring")},
	}
	observed := []ObservedRepository{{ID: plan.Repositories[0].ID, URI: plan.Repositories[0].URI, Suite: plan.Repositories[0].Suite, Components: []string{"main"}, KeyringPath: plan.Repositories[0].KeyringPath, KeyringDigest: digestBytes([]byte("keyring")), MetadataDigest: plan.Repositories[0].MetadataDigest, CutoffDigest: plan.Repositories[0].CutoffDigest, Enabled: true}}
	if err := ValidateAPTConfiguration(files, observed, plan.Repositories); err != nil {
		t.Fatal(err)
	}
}

func TestAPTMetadataRefreshRejectsConfigurationRedirects(t *testing.T) {
	for _, value := range []string{`Dir::Etc::sourcelist "/tmp/sources.list";`, `Dir::State::lists "/tmp/lists";`, `Dir::Cache::archives "/tmp/archives";`, `Dir::Media::Other "/tmp/other";`, `Dir { Etc { sourcelist "/tmp/sources.list"; }; };`, `APT { Update { Post-Invoke { "/tmp/hook"; }; }; };`, `Acquire::http::Proxy-Auto-Detect "/tmp/helper";`} {
		if !forbiddenAPTMetadataRefreshConfiguration([]byte(value)) {
			t.Fatalf("APT metadata refresh accepted configuration redirect %q", value)
		}
	}
	if forbiddenAPTMetadataRefreshConfiguration([]byte(`Dir::Etc::sourceparts "-";`)) == false {
		t.Fatal("APT metadata refresh accepted a sourceparts redirect")
	}
	for _, value := range []string{`Dir::Media::MountPath "/media/cdrom";`, `Dir { Media { MountPath "/media/cdrom"; }; };`, `Dir::Etc::apt-listchanges-main "listchanges.conf";`, `Dir::Etc::apt-listchanges-parts "listchanges.conf.d";`} {
		if forbiddenAPTMetadataRefreshConfiguration([]byte(value)) {
			t.Fatalf("APT metadata refresh rejected harmless standard configuration %q", value)
		}
	}
}

func TestObservedAPTRepositoryAuthorityRequiresApprovedKeyring(t *testing.T) {
	base := ObservedRepository{URI: "https://deb.example.test/debian", Suite: "stable", Components: []string{"main"}, KeyringPath: "/etc/apt/keyrings/release.gpg", Enabled: true}
	if err := validateObservedRepositoryAuthorities([]ObservedRepository{base}, map[string][]byte{base.KeyringPath: []byte("keyring")}); err != nil {
		t.Fatal(err)
	}
	optionless := base
	optionless.KeyringPath = ""
	if err := validateObservedRepositoryAuthorities([]ObservedRepository{optionless}, map[string][]byte{"/etc/apt/trusted.gpg.d/release.gpg": []byte("keyring")}); err != nil {
		t.Fatalf("optionless trusted APT source was rejected: %v", err)
	}
	for _, changed := range []ObservedRepository{
		{URI: "file:///tmp/repo", Suite: base.Suite, Components: base.Components, KeyringPath: base.KeyringPath, Enabled: true},
		{URI: base.URI, Suite: base.Suite, Components: base.Components, KeyringPath: "/tmp/release.gpg", Enabled: true},
		{URI: base.URI, Suite: base.Suite, Components: base.Components, KeyringPath: base.KeyringPath, Enabled: false},
	} {
		keyrings := map[string][]byte{base.KeyringPath: []byte("keyring")}
		if changed.KeyringPath != base.KeyringPath {
			keyrings = map[string][]byte{}
		}
		if err := validateObservedRepositoryAuthorities([]ObservedRepository{changed}, keyrings); err == nil {
			t.Fatalf("unsafe observed APT repository was accepted: %#v", changed)
		}
	}
}

func TestAPTSourceIgnoresDebSrcLines(t *testing.T) {
	values, err := parseSourceFile("/etc/apt/sources.list", []byte("deb-src https://deb.example.test/debian stable main\ndeb https://deb.example.test/debian stable main\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].URI != "https://deb.example.test/debian" {
		t.Fatalf("binary APT sources=%#v", values)
	}
}

func TestAPTSourceAcceptsOptionlessLineOnlyWithAuthorizedSharedKeyring(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	plan.Repositories[0].KeyringPath = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
	files := []ObservedConfig{{Path: "/etc/apt/sources.list", Kind: APTSource, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte("deb https://deb.example.test/debian stable main\n")}}
	observed, err := parseObservedRepositories(files, plan.Repositories)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 || observed[0].ID != plan.Repositories[0].ID || observed[0].KeyringPath != plan.Repositories[0].KeyringPath {
		t.Fatalf("optionless source was not bound exactly: %#v", observed)
	}
	plan.Repositories[0].KeyringPath = "/etc/apt/keyrings/lanpanel.gpg"
	if _, err := parseObservedRepositories(files, plan.Repositories); err == nil {
		t.Fatal("optionless source was accepted without its authorized shared keyring")
	}
	if _, err := parseSourceFile("/etc/apt/sources.list", []byte("deb [[signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg]] https://deb.example.test/debian stable main\n")); err == nil {
		t.Fatal("malformed source option brackets were accepted")
	}
}

func TestRenderAPTConfigurationInheritsHostNetworkAuthentication(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	plan.Repositories = nil
	for index := range plan.Packages {
		plan.Packages[index].RepositoryID = ""
		plan.Packages[index].RepositoryFilename = ""
		plan.Packages[index].VersionMinimum = plan.Packages[index].Version
	}
	config, sources, err := RenderAPTConfiguration(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Acquire::http::Proxy", "Acquire::https::Proxy", "Dir::Etc::netrc", "Dir::Etc::preferences"} {
		if strings.Contains(string(config), forbidden) {
			t.Fatalf("host APT setting %q was overridden: %s", forbidden, config)
		}
	}
	if len(sources) != 0 {
		t.Fatalf("host source list was replaced: %q", sources)
	}
}

func TestPackageConfigurationAllowsDistroHooksButRejectsUnsafeOverrides(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	keyring := []byte("test keyring identity")
	keyringDigest := fmt.Sprintf("%x", sha256.Sum256(keyring))
	plan.Repositories[0].KeyringDigest = keyringDigest
	files := []ObservedConfig{
		{Path: "/etc/apt/apt.conf", Kind: APTConfig, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte(`APT::Get::Assume-Yes "false";`)},
		{Path: "/etc/apt/keyrings/lanpanel.gpg", Kind: APTKeyring, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: keyring},
		{Path: "/etc/apt/sources.list", Kind: APTSource, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte("deb [signed-by=/etc/apt/keyrings/lanpanel.gpg] https://deb.example.test/debian stable main\n")},
	}
	repositories := []ObservedRepository{{ID: plan.Repositories[0].ID, URI: plan.Repositories[0].URI, Suite: plan.Repositories[0].Suite, Components: []string{"main"}, KeyringPath: plan.Repositories[0].KeyringPath, KeyringDigest: keyringDigest, MetadataDigest: plan.Repositories[0].MetadataDigest, CutoffDigest: plan.Repositories[0].CutoffDigest, Enabled: true}}
	if err := ValidateAPTConfiguration(files, repositories, plan.Repositories); err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []string{`DPkg::Pre-Invoke { "needrestart"; };`, `status-logger "/usr/lib/needrestart/dpkg-status";`} {
		changed := append([]ObservedConfig(nil), files...)
		changed[0].Bytes = []byte(allowed)
		if err := ValidateAPTConfiguration(changed, repositories, plan.Repositories); err != nil {
			t.Fatalf("standard distro hook %q was rejected: %v", allowed, err)
		}
	}
	for _, allowed := range []string{`Acquire::http::Proxy "http://ambient";`, `Acquire { http { Proxy "http://ambient"; }; };`} {
		changed := append([]ObservedConfig(nil), files...)
		changed[0].Bytes = []byte(allowed)
		if err := ValidateAPTConfiguration(changed, repositories, plan.Repositories); err != nil {
			t.Fatalf("user APT proxy %q was rejected: %v", allowed, err)
		}
	}
	for _, hostile := range []string{`Dir::Bin::dpkg "/tmp/other";`, `Dir { Bin { dpkg "/tmp/other"; }; };`, `DPkg::Options { "--admindir=/tmp/other"; };`, `DPkg::Options { "--instdir=/tmp/other"; };`, `APT::Get::AllowUnauthenticated "true";`, `APT::Update::Post-Invoke-Success { "/tmp/hook"; };`} {
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
	for _, change := range []func(*ObservedRepository){
		func(repository *ObservedRepository) { repository.MetadataDigest = strings.Repeat("0", 64) },
		func(repository *ObservedRepository) { repository.CutoffDigest = strings.Repeat("0", 64) },
	} {
		changed := append([]ObservedRepository(nil), repositories...)
		change(&changed[0])
		if err := ValidateAPTConfiguration(files, changed, plan.Repositories); err != nil {
			t.Fatalf("obsolete repository snapshot identity blocked configuration: %v", err)
		}
	}
	if err := ValidateDPKGReady(DPKGState{HalfConfigured: []string{"nginx"}}); err == nil {
		t.Fatal("half-configured dpkg state was accepted")
	}
}

func TestPostconditionRejectsRepositorySnapshotDrift(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	executor := newFakeExecutor(plan)
	executor.observed.RetainedMasks = []string{"nginx.service"}
	if err := ValidatePostcondition(plan, executor.audit.Before, executor.observed, []string{"nginx.service"}); err != nil {
		t.Fatal(err)
	}
	missingBindings := executor.observed
	missingBindings.Repositories = append([]ObservedRepository(nil), executor.observed.Repositories...)
	missingBindings.Repositories[0].PackageBindings = nil
	if err := ValidatePostcondition(plan, executor.audit.Before, missingBindings, []string{"nginx.service"}); err == nil {
		t.Fatal("postcondition accepted installed packages without signed repository bindings")
	}
	for _, change := range []func(*ObservedRepository){
		func(repository *ObservedRepository) { repository.MetadataDigest = strings.Repeat("0", 64) },
		func(repository *ObservedRepository) { repository.CutoffDigest = strings.Repeat("0", 64) },
	} {
		observed := executor.observed
		observed.Repositories = append([]ObservedRepository(nil), executor.observed.Repositories...)
		change(&observed.Repositories[0])
		if err := ValidatePostcondition(plan, executor.audit.Before, observed, []string{"nginx.service"}); err != nil {
			t.Fatalf("obsolete repository snapshot identity blocked postcondition: %v", err)
		}
	}
}

func TestDistroArtifactVerificationBindsSignedFilenameBeforeChild(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	root := t.TempDir()
	cache := filepath.Join(root, "var/lib/lanpanel/packages/transactions", plan.TransactionID, "archives")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	artifact := bytes.Repeat([]byte{'b'}, int(plan.Packages[0].ArtifactBytes))
	cacheName := "goaccess_1.9.3-1_amd64.deb"
	if err := os.WriteFile(filepath.Join(cache, cacheName), artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	auditor := newTestLinuxAuditor(&auditLauncher{}, root)
	repositories := []ObservedRepository{{ID: plan.Repositories[0].ID, PackageBindings: []RepositoryPackageBinding{{Name: plan.Packages[0].Name, Version: plan.Packages[0].Version, Architecture: plan.Packages[0].Architecture, Filename: "pool/main/a/other.deb", Size: plan.Packages[0].ArtifactBytes, Digest: plan.Packages[0].ArtifactDigest}}}}
	if err := auditor.verifyDistroPackageArtifacts(plan, repositories); err == nil {
		t.Fatal("distro artifact with a mismatched signed filename was accepted")
	}
}

func TestSignedPackageIndexBindsRepositoryFilenameAndArtifactIdentity(t *testing.T) {
	entries, err := parseRepositoryPackageIndex([]byte("Package: nginx\nVersion: 1.22.1-9\nArchitecture: amd64\nFilename: pool/main/n/nginx_1.22.1-9_amd64.deb\nSize: 2048\nSHA256: "+strings.Repeat("c", 64)+"\n"), "debian-main", "main", "amd64")
	if err != nil || len(entries) != 1 || entries[0].Filename != "pool/main/n/nginx_1.22.1-9_amd64.deb" || entries[0].Digest != strings.Repeat("c", 64) {
		t.Fatalf("parsed signed package entry=%#v error=%v", entries, err)
	}
	pkg := Package{Name: "nginx", Version: "1.22.1-9", Architecture: "amd64", RepositoryID: "debian-security", ArtifactDigest: strings.Repeat("c", 64), ArtifactBytes: 2048}
	repositories := []ObservedRepository{{ID: "debian-main"}, {ID: "debian-security"}}
	if err := validateExpectedRepositoryPackages([]Package{pkg}, "debian-security", repositories, nil); err == nil {
		t.Fatal("package absent from its assigned repository was accepted")
	}
	wrongRepository := []ObservedRepository{{ID: "debian-main", PackageBindings: []RepositoryPackageBinding{{Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Architecture, Filename: entries[0].Filename, Size: pkg.ArtifactBytes, Digest: pkg.ArtifactDigest}}}}
	if _, err := repositoryPackageBinding(pkg, wrongRepository); err == nil {
		t.Fatal("package binding from the wrong repository was accepted")
	}
	for _, field := range []string{"Filename", "Size", "SHA256"} {
		data := "Package: nginx\nVersion: 1.22.1-9\nArchitecture: amd64\nFilename: pool/main/n/nginx_1.22.1-9_amd64.deb\nSize: 2048\nSHA256: " + strings.Repeat("c", 64) + "\n"
		data = strings.Replace(data, field+": ", "", 1)
		if _, err := parseRepositoryPackageIndex([]byte(data), "debian-main", "main", "amd64"); err == nil {
			t.Fatalf("package index without %s was accepted", field)
		}
	}
}

func TestRuntimeSnapshotCloneOwnsNestedPackageSlices(t *testing.T) {
	plan := testPlan(t, StagedDebs)
	original := RuntimeSnapshot{Installed: clonePackages(plan.Packages)}
	cloned := cloneRuntimeSnapshot(original)
	original.Installed[1].AffectedUnits[0] = "other.service"
	original.Installed[1].PossibleListeners[0] = "tcp/8080"
	original.Installed[1].Source.OfficialAuthorities[0] = "other.example.test"
	if cloned.Installed[1].AffectedUnits[0] != "nginx.service" || cloned.Installed[1].PossibleListeners[0] != "tcp/443" || cloned.Installed[1].Source.OfficialAuthorities[0] != "downloads.example.test" {
		t.Fatalf("runtime snapshot clone shared nested package slices: %#v", cloned.Installed[1])
	}
}

func TestPackageTransactionRejectsStagedArtifactDriftBeforeChild(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	executor.verifyStagedErr = errors.New("staged artifact changed")
	engine, result := testEngine(&memoryJournals{}, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalMasksApplied || executor.runCount != 0 {
		t.Fatalf("staged artifact drift reached package child: journal=%#v runs=%d err=%v", journal, executor.runCount, err)
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

func TestPackageResumePreflightErrorsReturnFencedJournal(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	tests := []struct {
		name   string
		change func(*Engine, *preflight.Result)
	}{
		{name: "blocked", change: func(_ *Engine, result *preflight.Result) {
			result.Allowed = false
			result.Findings[0].Disposition = preflight.FindingBlocked
		}},
		{name: "deadline", change: func(engine *Engine, _ *preflight.Result) {
			engine.Now = func() time.Time { return plan.Deadline }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := newFakeExecutor(plan)
			journal := testJournal(t, plan, executor.audit.Before, JournalPrepared, nil)
			current := journal
			journals := &memoryJournals{current: &current}
			engine, result := testEngine(journals, executor, &fakeMonitor{})
			test.change(&engine, &result)
			resumed, err := engine.Resume(context.Background(), plan, result, journal)
			if err == nil || !reflect.DeepEqual(resumed, journal) || !reflect.DeepEqual(*journals.current, journal) || executor.mutationCount() != 0 {
				t.Fatalf("preflight error lost fenced journal: resumed=%#v durable=%#v calls=%d err=%v", resumed, journals.current, executor.mutationCount(), err)
			}
		})
	}
}

func TestPackageTransactionIgnoresRepositorySnapshotIdentityBeforeChild(t *testing.T) {
	plan := testPlan(t, DistroRepository)
	executor := newFakeExecutor(plan)
	executor.afterStage = func() {
		executor.audit.Repositories[0].MetadataDigest = strings.Repeat("0", 64)
	}
	engine, result := testEngine(&memoryJournals{}, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err != nil || journal.Phase != JournalCleaned || executor.runCount != 1 {
		t.Fatalf("obsolete repository snapshot identity blocked package child: journal=%#v runs=%d err=%v", journal, executor.runCount, err)
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
	wantPhases := []JournalPhase{JournalPrepared, JournalFilesPrepared, JournalArtifactsStaged, JournalMasking, JournalMasking, JournalMasking, JournalMasksApplied, JournalChildSubmitted, JournalChildTerminal, JournalVerified, JournalCommitted, JournalCleaned}
	if !slices.Equal(journals.phases, wantPhases) {
		t.Fatalf("journal phases=%v want=%v", journals.phases, wantPhases)
	}
}

func TestPackageTransactionPreservesPreparedJournalAcrossMaskCommitFault(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	prior := cloneRuntimeSnapshot(executor.audit.Before)
	journals := &memoryJournals{failAt: JournalMasksApplied}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalMasking || len(journal.Masks) != 1 || len(executor.unmasked) != 0 || !reflect.DeepEqual(journal.Prior, prior) {
		t.Fatalf("journal=%#v unmasked=%v error=%v", journal, executor.unmasked, err)
	}
}

func TestPackageTransactionDoesNotStartAfterPlanDeadline(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	journals := &memoryJournals{}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	engine.Now = func() time.Time { return plan.Deadline }
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != "" || journals.current != nil {
		t.Fatalf("expired package Plan started mutation: journal=%#v err=%v", journal, err)
	}
}

func TestPackageTransactionResumesOnlyExactMaskAndChildJournals(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	journals := &memoryJournals{failAt: JournalMasksApplied}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalMasking {
		t.Fatalf("mask fault journal=%#v err=%v", journal, err)
	}
	journals.failAt = ""
	resumed, err := engine.Resume(context.Background(), plan, result, journal)
	if err != nil || resumed.Phase != JournalCleaned {
		t.Fatalf("mask resume journal=%#v err=%v", resumed, err)
	}
	changed := plan
	changed.Authority.BinaryDigest = strings.Repeat("0", 64)
	if _, err := engine.Resume(context.Background(), changed, result, journal); err == nil {
		t.Fatal("changed package authority resumed exact journal")
	}

	executor = newFakeExecutor(plan)
	journals = &memoryJournals{failAt: JournalChildTerminal}
	engine, result = testEngine(journals, executor, &fakeMonitor{})
	journal, err = engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalChildSubmitted {
		t.Fatalf("child submission fault journal=%#v err=%v", journal, err)
	}
	journals.failAt = ""
	resumed, err = engine.Resume(context.Background(), plan, result, journal)
	if err == nil || resumed.Phase != JournalChildSubmitted || executor.runCount != 1 {
		t.Fatalf("unknown submitted child was repeated or accepted: journal=%#v runs=%d err=%v", resumed, executor.runCount, err)
	}
}

func TestSuccessfulTerminalPackageRecoveryIgnoresExpiredMutationAuthority(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	journals := &memoryJournals{failAt: JournalVerified}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalChildTerminal || !journal.ChildSucceeded {
		t.Fatalf("terminal fixture=%#v err=%v", journal, err)
	}
	journals.failAt = ""
	engine.Now = func() time.Time { return plan.Deadline.Add(time.Hour) }
	resumed, err := engine.Resume(context.Background(), plan, preflight.Result{}, journal)
	if err != nil || resumed.Phase != JournalCleaned || executor.runCount != 1 {
		t.Fatalf("terminal local recovery failed/repeated: %#v runs=%d err=%v", resumed, executor.runCount, err)
	}
}

func TestCommittedPackageCleanupResumesAfterPlanAndPreflightExpiry(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	journals := &memoryJournals{failAt: JournalCleaned}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err == nil || journal.Phase != JournalCommitted {
		t.Fatalf("committed cleanup fault journal=%#v err=%v", journal, err)
	}
	journals.failAt = ""
	engine.Now = func() time.Time { return plan.Deadline.Add(time.Hour) }
	expired := result
	expired.ObservedAt = plan.Deadline.Add(-time.Hour)
	resumed, err := engine.Resume(context.Background(), plan, expired, journal)
	if err != nil || resumed.Phase != JournalCleaned {
		t.Fatalf("local committed cleanup did not resume after expiry: journal=%#v err=%v", resumed, err)
	}
}

func TestPackageResumeRejectsRuntimeDriftBeforeNextMutation(t *testing.T) {
	phases := []JournalPhase{JournalPrepared, JournalFilesPrepared, JournalArtifactsStaged, JournalMasking, JournalMasksApplied}
	drifts := []struct {
		name   string
		change func(*RuntimeSnapshot, Plan)
	}{
		{name: "installed", change: func(snapshot *RuntimeSnapshot, plan Plan) {
			snapshot.Installed = clonePackages(plan.Packages[:1])
		}},
		{name: "system_packages", change: func(snapshot *RuntimeSnapshot, _ Plan) {
			snapshot.SystemPackages[0].Version = "2"
		}},
		{name: "unit", change: func(snapshot *RuntimeSnapshot, _ Plan) {
			snapshot.Units[0].Active = true
		}},
		{name: "listener", change: func(snapshot *RuntimeSnapshot, _ Plan) {
			snapshot.Listeners[0].Port = 23
		}},
	}
	for _, phase := range phases {
		for _, drift := range drifts {
			t.Run(string(phase)+"/"+drift.name, func(t *testing.T) {
				plan := testPlan(t, OfflineDebs)
				executor := newFakeExecutor(plan)
				masks := []MaskIdentity(nil)
				if phase == JournalMasksApplied {
					masks = []MaskIdentity{{Unit: "nginx.service", Device: 1, Inode: 1, CTimeSec: 1}}
				}
				journal := testJournal(t, plan, executor.audit.Before, phase, masks)
				if phase == JournalMasksApplied {
					executor.audit.Before.Units[0].Masked = true
				}
				current := journal
				journals := &memoryJournals{current: &current}
				drift.change(&executor.audit.Before, plan)
				engine, result := testEngine(journals, executor, &fakeMonitor{})
				resumed, err := engine.Resume(context.Background(), plan, result, journal)
				if err == nil || resumed.Phase != phase {
					t.Fatalf("drift resumed from %s: journal=%#v err=%v", phase, resumed, err)
				}
				if executor.mutationCount() != 0 || !reflect.DeepEqual(*journals.current, journal) {
					t.Fatalf("drift mutated after %s: calls=%d durable=%#v", phase, executor.mutationCount(), journals.current)
				}
			})
		}
	}
}

func TestPackageResumeAcceptsExactPreMaskRuntime(t *testing.T) {
	for _, phase := range []JournalPhase{JournalPrepared, JournalFilesPrepared, JournalArtifactsStaged} {
		t.Run(string(phase), func(t *testing.T) {
			plan := testPlan(t, OfflineDebs)
			executor := newFakeExecutor(plan)
			journal := testJournal(t, plan, executor.audit.Before, phase, nil)
			current := journal
			journals := &memoryJournals{current: &current}
			engine, result := testEngine(journals, executor, &fakeMonitor{})
			resumed, err := engine.Resume(context.Background(), plan, result, journal)
			if err != nil || resumed.Phase != JournalCleaned || executor.runCount != 1 {
				t.Fatalf("exact %s runtime did not recover: journal=%#v runs=%d err=%v", phase, resumed, executor.runCount, err)
			}
		})
	}
}

func TestPackageResumeRejectsUnsafeNoAutostartPolicyBeforeMutation(t *testing.T) {
	for _, phase := range []JournalPhase{JournalPrepared, JournalFilesPrepared, JournalArtifactsStaged, JournalMasking, JournalMasksApplied} {
		t.Run(string(phase), func(t *testing.T) {
			plan := testPlan(t, OfflineDebs)
			executor := newFakeExecutor(plan)
			masks := []MaskIdentity(nil)
			if phase == JournalMasksApplied {
				masks = []MaskIdentity{{Unit: "nginx.service", Device: 1, Inode: 1, CTimeSec: 1}}
			}
			journal := testJournal(t, plan, executor.audit.Before, phase, masks)
			if phase == JournalMasksApplied {
				executor.audit.Before.Units[0].Masked = true
			}
			executor.audit.NoAutostart.Mode = 0o644
			current := journal
			journals := &memoryJournals{current: &current}
			engine, result := testEngine(journals, executor, &fakeMonitor{})
			resumed, err := engine.Resume(context.Background(), plan, result, journal)
			if err == nil || resumed.Phase != phase || executor.mutationCount() != 0 || !reflect.DeepEqual(*journals.current, journal) {
				t.Fatalf("unsafe policy resumed %s: journal=%#v calls=%d durable=%#v err=%v", phase, resumed, executor.mutationCount(), journals.current, err)
			}
		})
	}
}

func TestPackageResumeMaskingAllowsOnlyPersistedMaskRuntimeDifference(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	identity := MaskIdentity{Unit: "nginx.service", Device: 1, Inode: 1, CTimeSec: 1}

	t.Run("persisted mask", func(t *testing.T) {
		executor := newFakeExecutor(plan)
		journal := testJournal(t, plan, executor.audit.Before, JournalMasking, []MaskIdentity{identity})
		executor.audit.Before.Units[0].Masked = true
		current := journal
		journals := &memoryJournals{current: &current}
		engine, result := testEngine(journals, executor, &fakeMonitor{})
		resumed, err := engine.Resume(context.Background(), plan, result, journal)
		if err != nil || resumed.Phase != JournalCleaned || executor.maskCount != 0 || executor.runCount != 1 {
			t.Fatalf("exact persisted mask did not resume: journal=%#v masks=%d runs=%d err=%v", resumed, executor.maskCount, executor.runCount, err)
		}
	})

	t.Run("durable created-mask intent", func(t *testing.T) {
		executor := newFakeExecutor(plan)
		journal := testJournal(t, plan, executor.audit.Before, JournalMasking, nil)
		journal.MaskIntent = "nginx.service"
		if err := ValidateJournal(journal); err != nil {
			t.Fatal(err)
		}
		executor.audit.Before.Units[0].Masked = true
		current := journal
		journals := &memoryJournals{current: &current}
		engine, result := testEngine(journals, executor, &fakeMonitor{})
		resumed, err := engine.Resume(context.Background(), plan, result, journal)
		if err == nil || resumed.Phase != JournalMasking || len(resumed.Masks) != 0 || resumed.MaskIntent != "nginx.service" {
			t.Fatalf("ambiguous durable mask intent did not fail closed: journal=%#v err=%v", resumed, err)
		}
	})

	t.Run("missing persisted effect", func(t *testing.T) {
		executor := newFakeExecutor(plan)
		journal := testJournal(t, plan, executor.audit.Before, JournalMasking, []MaskIdentity{identity})
		current := journal
		journals := &memoryJournals{current: &current}
		engine, result := testEngine(journals, executor, &fakeMonitor{})
		if _, err := engine.Resume(context.Background(), plan, result, journal); err == nil {
			t.Fatal("recorded created mask was accepted while runtime remained unmasked")
		}
		if executor.mutationCount() != 0 || !reflect.DeepEqual(*journals.current, journal) {
			t.Fatalf("missing mask effect changed fenced journal: calls=%d durable=%#v", executor.mutationCount(), journals.current)
		}
	})

	t.Run("unpersisted unrelated mask", func(t *testing.T) {
		executor := newFakeExecutor(plan)
		executor.audit.Before.Units = append(executor.audit.Before.Units, UnitState{Name: "other.service"})
		journal := testJournal(t, plan, executor.audit.Before, JournalMasking, []MaskIdentity{identity})
		executor.audit.Before.Units[0].Masked = true
		executor.audit.Before.Units[1].Masked = true
		current := journal
		journals := &memoryJournals{current: &current}
		engine, result := testEngine(journals, executor, &fakeMonitor{})
		if _, err := engine.Resume(context.Background(), plan, result, journal); err == nil {
			t.Fatal("unpersisted unit mask was adopted during resume")
		}
		if executor.mutationCount() != 0 || !reflect.DeepEqual(*journals.current, journal) {
			t.Fatalf("unpersisted mask changed fenced journal: calls=%d durable=%#v", executor.mutationCount(), journals.current)
		}
	})

	t.Run("unpersisted affected mask", func(t *testing.T) {
		plan := testPlanWithTwoUnits(t)
		executor := newFakeExecutor(plan)
		units := affectedUnits(plan.Packages)
		prefix := []MaskIdentity{{Unit: units[0], Device: 1, Inode: 1, CTimeSec: 1}}
		journal := testJournal(t, plan, executor.audit.Before, JournalMasking, prefix)
		executor.audit.Before.Units[0].Masked = true
		executor.audit.Before.Units[1].Masked = true
		current := journal
		journals := &memoryJournals{current: &current}
		engine, result := testEngine(journals, executor, &fakeMonitor{})
		if _, err := engine.Resume(context.Background(), plan, result, journal); err == nil {
			t.Fatal("unpersisted affected-unit mask was re-adopted during resume")
		}
		if executor.mutationCount() != 0 || !reflect.DeepEqual(*journals.current, journal) {
			t.Fatalf("affected-unit adoption changed fenced prefix: calls=%d durable=%#v", executor.mutationCount(), journals.current)
		}
	})
}

func TestPackageMaskCallbackRequiresExactUnitPrefix(t *testing.T) {
	plan := testPlanWithTwoUnits(t)
	units := affectedUnits(plan.Packages)
	exact := []MaskIdentity{
		{Unit: units[0], Device: 1, Inode: 1, CTimeSec: 1},
		{Unit: units[1], Device: 1, Inode: 2, CTimeSec: 1},
	}
	wrongOwnership := exact[0]
	wrongOwnership.Preexisting = true
	tests := []struct {
		name      string
		callbacks []MaskIdentity
		persisted int
	}{
		{name: "wrong first unit", callbacks: []MaskIdentity{exact[1]}},
		{name: "wrong ownership", callbacks: []MaskIdentity{wrongOwnership}},
		{name: "duplicate unit", callbacks: []MaskIdentity{exact[0], exact[0]}, persisted: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := newFakeExecutor(plan)
			executor.maskFunc = func(_ []string, _ string, persistIntent func(string) error, persistIdentity func(MaskIdentity) error) (MaskResult, error) {
				persisted := []MaskIdentity{}
				for _, identity := range test.callbacks {
					if !identity.Preexisting {
						if err := persistIntent(identity.Unit); err != nil {
							return MaskResult{Masks: persisted}, err
						}
					}
					if err := persistIdentity(identity); err != nil {
						return MaskResult{Masks: persisted}, err
					}
					persisted = append(persisted, identity)
				}
				return MaskResult{Masks: persisted}, nil
			}
			journals := &memoryJournals{}
			engine, result := testEngine(journals, executor, &fakeMonitor{})
			journal, err := engine.Execute(context.Background(), plan, result)
			if err == nil || journal.Phase != JournalMasking || len(journal.Masks) != test.persisted || executor.runCount != 0 {
				t.Fatalf("callback prefix accepted: journal=%#v runs=%d err=%v", journal, executor.runCount, err)
			}
		})
	}
}

func TestPackageMaskResultMustEqualPersistedIdentities(t *testing.T) {
	plan := testPlanWithTwoUnits(t)
	units := affectedUnits(plan.Packages)
	recorded := []MaskIdentity{
		{Unit: units[0], Device: 1, Inode: 1, CTimeSec: 1},
		{Unit: units[1], Device: 1, Inode: 2, CTimeSec: 1},
	}
	tests := []struct {
		name   string
		result func([]MaskIdentity) []MaskIdentity
	}{
		{name: "identity", result: func(values []MaskIdentity) []MaskIdentity {
			values[0].Inode++
			return values
		}},
		{name: "list", result: func(values []MaskIdentity) []MaskIdentity { return values[:1] }},
		{name: "order", result: func(values []MaskIdentity) []MaskIdentity {
			return []MaskIdentity{values[1], values[0]}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := newFakeExecutor(plan)
			executor.maskFunc = func(_ []string, _ string, persistIntent func(string) error, persistIdentity func(MaskIdentity) error) (MaskResult, error) {
				for _, identity := range recorded {
					if err := persistIntent(identity.Unit); err != nil {
						return MaskResult{}, err
					}
					if err := persistIdentity(identity); err != nil {
						return MaskResult{}, err
					}
				}
				returned := test.result(append([]MaskIdentity(nil), recorded...))
				return MaskResult{Masks: returned}, nil
			}
			journals := &memoryJournals{}
			engine, result := testEngine(journals, executor, &fakeMonitor{})
			journal, err := engine.Execute(context.Background(), plan, result)
			if err == nil || journal.Phase != JournalMasking || !slices.Equal(journal.Masks, recorded) || executor.runCount != 0 || len(executor.unmaskCalls) != 0 {
				t.Fatalf("mask result mismatch was accepted: journal=%#v runs=%d unmask=%#v err=%v", journal, executor.runCount, executor.unmaskCalls, err)
			}
			if journals.current == nil || !reflect.DeepEqual(*journals.current, journal) {
				t.Fatalf("exact persisted mask journal was not retained: %#v", journals.current)
			}
		})
	}
}

func TestCreatedMaskJournalRequiresDurableIntentBeforeIdentity(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	before := testJournal(t, plan, executor.audit.Before, JournalMasking, nil)
	identity := MaskIdentity{Unit: "nginx.service", Device: 1, Inode: 1, CTimeSec: 1}

	direct := before
	direct.Masks = []MaskIdentity{identity}
	if err := ValidateJournalTransition(before, direct); err == nil {
		t.Fatal("created mask identity was journaled without prior durable intent")
	}
	intended := before
	intended.MaskIntent = identity.Unit
	if err := ValidateJournalTransition(before, intended); err != nil {
		t.Fatalf("exact created mask intent transition failed: %v", err)
	}
	completed := intended
	completed.MaskIntent = ""
	completed.Masks = []MaskIdentity{identity}
	if err := ValidateJournalTransition(intended, completed); err != nil {
		t.Fatalf("exact intended mask identity transition failed: %v", err)
	}
}

func TestMaskingTransitionCannotRewritePersistedIdentity(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	mask := MaskIdentity{Unit: "nginx.service", Device: 1, Inode: 1, CTimeSec: 1, CTimeNsec: 1}
	before := testJournal(t, plan, executor.audit.Before, JournalMasking, []MaskIdentity{mask})
	after := before
	after.Phase = JournalMasksApplied
	after.MasksComplete = true
	if err := ValidateJournalTransition(before, after); err != nil {
		t.Fatalf("exact mask completion transition failed: %v", err)
	}
	changes := []struct {
		name   string
		change func(*MaskIdentity)
	}{
		{name: "unit", change: func(value *MaskIdentity) { value.Unit = "other.service" }},
		{name: "preexisting", change: func(value *MaskIdentity) { value.Preexisting = true }},
		{name: "device", change: func(value *MaskIdentity) { value.Device++ }},
		{name: "inode", change: func(value *MaskIdentity) { value.Inode++ }},
		{name: "ctime_sec", change: func(value *MaskIdentity) { value.CTimeSec++ }},
		{name: "ctime_nsec", change: func(value *MaskIdentity) { value.CTimeNsec++ }},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			rewritten := after
			rewritten.Masks = append([]MaskIdentity(nil), after.Masks...)
			change.change(&rewritten.Masks[0])
			if err := ValidateJournalTransition(before, rewritten); err == nil {
				t.Fatal("mask identity rewrite was accepted")
			}
		})
	}
}

func TestPackageTransactionNeverDeletesPreexistingMask(t *testing.T) {
	plan := testPlan(t, OfflineDebs)
	executor := newFakeExecutor(plan)
	executor.audit.Before.Units[0].Masked = true
	journals := &memoryJournals{}
	engine, result := testEngine(journals, executor, &fakeMonitor{})
	journal, err := engine.Execute(context.Background(), plan, result)
	if err != nil || journal.Phase != JournalCleaned || len(journal.Masks) != 1 || !journal.Masks[0].Preexisting {
		t.Fatalf("preexisting mask transaction failed: journal=%#v err=%v", journal, err)
	}
	if len(executor.unmaskCalls) != 1 || len(executor.unmaskCalls[0]) != 0 {
		t.Fatalf("preexisting mask reached unmask: %#v", executor.unmaskCalls)
	}
	if len(executor.verifyCalls) == 0 || !slices.Equal(executor.verifyCalls[len(executor.verifyCalls)-1], journal.Masks) {
		t.Fatalf("preexisting mask was not verified before cleanup: %#v", executor.verifyCalls)
	}

	executor = newFakeExecutor(plan)
	executor.audit.Before.Units[0].Masked = true
	identity := MaskIdentity{Unit: "nginx.service", Device: 1, Inode: 1, CTimeSec: 1}
	committed := testJournal(t, plan, executor.audit.Before, JournalMasking, []MaskIdentity{identity})
	committed.Phase = JournalCommitted
	committed.MasksComplete = true
	committed.ChildSucceeded = true
	committed.ChildResultDigest = strings.Repeat("3", 64)
	committed.PostconditionDigest = strings.Repeat("4", 64)
	current := committed
	journals = &memoryJournals{current: &current}
	engine, result = testEngine(journals, executor, &fakeMonitor{})
	resumed, err := engine.Resume(context.Background(), plan, result, committed)
	if err == nil || resumed.Phase != JournalCommitted || len(executor.unmaskCalls) != 0 || !reflect.DeepEqual(*journals.current, committed) {
		t.Fatalf("wrong ownership reached cleanup: journal=%#v unmask=%#v err=%v", resumed, executor.unmaskCalls, err)
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
		{Name: "goaccess", Version: "1.9.3-1", Architecture: "amd64", ArtifactDigest: strings.Repeat("b", 64), ArtifactBytes: 1024, MaximumInstalledFileBytes: 8 << 20, AffectedUnits: []string{}, PossibleListeners: []string{}},
		{Name: "nginx", Version: "1.22.1-9", Architecture: "amd64", ArtifactDigest: strings.Repeat("c", 64), ArtifactBytes: 2048, MaximumInstalledFileBytes: 16 << 20, AffectedUnits: []string{"nginx.service"}, PossibleListeners: []string{"tcp/443", "tcp/80"}},
	}
	noNetwork := mode != DistroRepository
	for index := range packages {
		artifact := sources.Artifact{Name: packages[index].Name, Version: packages[index].Version, OperatingOS: "linux", Architecture: "amd64", Digest: packages[index].ArtifactDigest}
		switch mode {
		case DistroRepository:
			packages[index].RepositoryID = "debian-stable"
			packages[index].RepositoryFilename = "pool/main/" + string(packages[index].Name[0]) + "/" + packages[index].Name + "_" + packages[index].Version + "_amd64.deb"
			packages[index].Source = sources.Source{Kind: sources.OfficialDistro, Artifact: artifact, OfficialAuthorities: []string{}}
		case StagedDebs:
			packages[index].StagedIdentity = "sha256:" + packages[index].ArtifactDigest
			packages[index].Source = sources.Source{Kind: sources.OfficialCanonical, URL: "https://downloads.example.test/" + packages[index].Name + ".deb", OfficialAuthorities: []string{"downloads.example.test"}, Artifact: artifact}
		case OfflineDebs:
			packages[index].StagedIdentity = "sha256:" + packages[index].ArtifactDigest
			packages[index].Source = sources.Source{Kind: sources.Offline, OfflinePath: "/var/lib/lanpanel/imports/" + packages[index].ArtifactDigest + ".deb", Artifact: artifact, OfficialAuthorities: []string{}}
		}
	}
	plan := Plan{
		TransactionID: "pkg_" + strings.Repeat("1", 64), JobID: "job_" + strings.Repeat("2", 64), IntentGeneration: 1, Deadline: time.Unix(2_000_000_000, 0).UTC(), OSProfileDigest: strings.Repeat("a", 64), Mode: mode, Packages: packages, FirstNginxInstall: true,
		LockWait: 30 * time.Second, ConnectTimeout: 15 * time.Second, ReadTimeout: 30 * time.Second, TotalTimeout: 2 * time.Minute, NoNetwork: noNetwork, NoAutostartPolicyDigest: strings.Repeat("9", 64), PreflightDigest: "sha256:" + strings.Repeat("6", 64), PreflightRequestDigest: "sha256:" + strings.Repeat("6", 64),
		Authority: Authority{Kind: PreviewProfile, ReleaseAuthorityDigest: strings.Repeat("d", 64), BinaryDigest: strings.Repeat("e", 64), HostFingerprint: "host/fingerprint", TargetOSProfileDigest: strings.Repeat("a", 64)},
	}
	if mode == DistroRepository {
		keyringDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("keyring")))
		plan.Repositories = []Repository{{ID: "debian-stable", URI: "https://deb.example.test/debian", Suite: "stable", Components: []string{"main"}, KeyringPath: "/etc/apt/keyrings/lanpanel.gpg", KeyringDigest: keyringDigest, MetadataDigest: strings.Repeat("6", 64), CutoffDigest: strings.Repeat("7", 64)}}
	}
	return plan
}

func testPlanWithTwoUnits(t *testing.T) Plan {
	t.Helper()
	plan := testPlan(t, OfflineDebs)
	plan.Packages = clonePackages(plan.Packages)
	plan.Packages[1].AffectedUnits = []string{"nginx.service", "nginx.socket"}
	return plan
}

func testJournal(t *testing.T, plan Plan, prior RuntimeSnapshot, phase JournalPhase, masks []MaskIdentity) Journal {
	t.Helper()
	planDigest, authorityDigest, err := transactionDigests(plan)
	if err != nil {
		t.Fatal(err)
	}
	journal := Journal{
		SchemaVersion:   PackageJournalSchemaVersion,
		TransactionID:   plan.TransactionID,
		NormalJournalID: "package-" + plan.TransactionID,
		ChildID:         "package-child-" + plan.TransactionID,
		JobID:           plan.JobID,
		PlanDigest:      planDigest,
		AuthorityDigest: authorityDigest,
		PackageProfile:  child.ProfileAPTOfflineTransaction,
		Prior:           cloneRuntimeSnapshot(prior),
		Phase:           phase,
		Masks:           append([]MaskIdentity{}, masks...),
	}
	if phase == JournalMasksApplied {
		journal.MasksComplete = true
	}
	if err := ValidateJournal(journal); err != nil {
		t.Fatal(err)
	}
	return journal
}

func clonePackages(values []Package) []Package {
	result := append([]Package(nil), values...)
	for index := range result {
		result[index].AffectedUnits = append([]string(nil), result[index].AffectedUnits...)
		result[index].PossibleListeners = append([]string(nil), result[index].PossibleListeners...)
		result[index].Source.OfficialAuthorities = slices.Clone(result[index].Source.OfficialAuthorities)
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
	audit           Audit
	observed        Postcondition
	profile         child.ProfileID
	invocation      child.Invocation
	unmasked        []string
	unmaskCalls     [][]MaskIdentity
	verifyCalls     [][]MaskIdentity
	maskFunc        func([]string, string, func(string) error, func(MaskIdentity) error) (MaskResult, error)
	afterStage      func()
	runErr          error
	verifyStagedErr error
	prepareCount    int
	stageCount      int
	resolveCount    int
	maskCount       int
	runCount        int
}

func newFakeExecutor(plan Plan) *fakeExecutor {
	units := make([]UnitState, 0, len(affectedUnits(plan.Packages)))
	maskedUnits := make([]UnitState, 0, len(affectedUnits(plan.Packages)))
	for _, unit := range affectedUnits(plan.Packages) {
		units = append(units, UnitState{Name: unit})
		maskedUnits = append(maskedUnits, UnitState{Name: unit, Masked: true})
	}
	before := RuntimeSnapshot{SystemPackages: []InstalledPackage{{Name: "base-files", Version: "1", Architecture: "amd64"}}, Units: units, Listeners: []Listener{{Protocol: "tcp", Port: 22, Owner: "sshd"}}}
	configuration := []ObservedConfig{{Path: "/etc/apt/apt.conf", Kind: APTConfig, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: []byte("// safe\n")}}
	repositories := []ObservedRepository{}
	if plan.Mode == DistroRepository {
		keyring := []byte("keyring")
		digest := fmt.Sprintf("%x", sha256.Sum256(keyring))
		configuration = append(configuration, ObservedConfig{Path: "/etc/apt/keyrings/lanpanel.gpg", Kind: APTKeyring, UID: 0, GID: 0, Mode: 0o644, Regular: true, ParentsSafe: true, Bytes: keyring})
		repositories = append(repositories, ObservedRepository{ID: plan.Repositories[0].ID, URI: plan.Repositories[0].URI, Suite: plan.Repositories[0].Suite, Components: append([]string(nil), plan.Repositories[0].Components...), KeyringPath: plan.Repositories[0].KeyringPath, KeyringDigest: digest, MetadataDigest: plan.Repositories[0].MetadataDigest, CutoffDigest: plan.Repositories[0].CutoffDigest, Enabled: true})
		for _, pkg := range plan.Packages {
			repositories[0].PackageBindings = append(repositories[0].PackageBindings, RepositoryPackageBinding{Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Architecture, Filename: pkg.RepositoryFilename, Size: pkg.ArtifactBytes, Digest: pkg.ArtifactDigest})
		}
	}
	policy := NoAutostartPolicy{Path: "/usr/sbin/policy-rc.d", Digest: plan.NoAutostartPolicyDigest, UID: 0, GID: 0, Mode: 0o755, Regular: true, ParentsSafe: true, SameLanPanelBinary: true}
	systemPackages := append([]InstalledPackage(nil), before.SystemPackages...)
	for _, pkg := range plan.Packages {
		systemPackages = append(systemPackages, InstalledPackage{Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Architecture})
	}
	slices.SortFunc(systemPackages, func(left, right InstalledPackage) int { return strings.Compare(left.Name, right.Name) })
	return &fakeExecutor{audit: Audit{Configuration: configuration, Repositories: repositories, Before: before, NoAutostart: policy}, observed: Postcondition{Repositories: append([]ObservedRepository(nil), repositories...), Installed: clonePackages(plan.Packages), SystemPackages: systemPackages, Units: maskedUnits, Listeners: append([]Listener(nil), before.Listeners...)}}
}

func (executor *fakeExecutor) LockRepositories(_ context.Context, _ Plan) (func(), error) {
	return func() {}, nil
}

func (executor *fakeExecutor) Audit(_ context.Context, _ Plan) (Audit, error) {
	audit := executor.audit
	audit.Before = cloneRuntimeSnapshot(executor.audit.Before)
	return audit, nil
}

func (executor *fakeExecutor) VerifyStaged(_ context.Context, _ Plan) error {
	return executor.verifyStagedErr
}

func (executor *fakeExecutor) Stage(_ context.Context, _ Plan) error {
	executor.stageCount++
	if executor.afterStage != nil {
		executor.afterStage()
	}
	return nil
}

func (executor *fakeExecutor) Prepare(_ context.Context, _ Plan, config, _ []byte) error {
	executor.prepareCount++
	if len(config) == 0 {
		return errors.New("missing package config")
	}
	return nil
}

func (executor *fakeExecutor) Resolve(_ context.Context, plan Plan) ([]Package, error) {
	executor.resolveCount++
	return clonePackages(plan.Packages), nil
}

func (executor *fakeExecutor) Mask(_ context.Context, units []string, pendingIntent string, persistIntent func(string) error, persistIdentity func(MaskIdentity) error) (MaskResult, error) {
	executor.maskCount++
	if executor.maskFunc != nil {
		return executor.maskFunc(units, pendingIntent, persistIntent, persistIdentity)
	}
	identities := make([]MaskIdentity, 0, len(units))
	if pendingIntent != "" {
		index := slices.IndexFunc(executor.audit.Before.Units, func(unit UnitState) bool { return unit.Name == pendingIntent })
		if index >= 0 && executor.audit.Before.Units[index].Masked {
			return MaskResult{}, fmt.Errorf("package mask intent lacks an exact created-inode identity")
		}
	}
	for _, unit := range units {
		index := slices.IndexFunc(executor.audit.Before.Units, func(state UnitState) bool { return state.Name == unit })
		if index < 0 {
			return MaskResult{Masks: identities}, fmt.Errorf("unknown fake unit %q", unit)
		}
		preexisting := executor.audit.Before.Units[index].Masked && pendingIntent == ""
		if !preexisting && pendingIntent == "" {
			if err := persistIntent(unit); err != nil {
				return MaskResult{Masks: identities}, err
			}
		}
		identity := MaskIdentity{Unit: unit, Preexisting: preexisting, Device: 1, Inode: uint64(index + 1), CTimeSec: 1}
		executor.audit.Before.Units[index].Masked = true
		if err := persistIdentity(identity); err != nil {
			return MaskResult{Masks: identities}, err
		}
		identities = append(identities, identity)
		pendingIntent = ""
	}
	return MaskResult{Masks: identities}, nil
}

func (executor *fakeExecutor) VerifyMasks(_ context.Context, masks []MaskIdentity) error {
	executor.verifyCalls = append(executor.verifyCalls, append([]MaskIdentity(nil), masks...))
	if !validMaskIdentities(masks) {
		return errors.New("invalid masks")
	}
	return nil
}

func (executor *fakeExecutor) Run(_ context.Context, profile child.ProfileID, invocation child.Invocation) (child.Result, error) {
	executor.runCount++
	executor.profile, executor.invocation = profile, invocation
	return child.Result{ExitCode: 0, StdoutDigest: "sha256:" + strings.Repeat("1", 64), StderrDigest: "sha256:" + strings.Repeat("2", 64)}, executor.runErr
}

func (executor *fakeExecutor) Observe(_ context.Context, _ Plan) (Postcondition, error) {
	return executor.observed, nil
}

func (executor *fakeExecutor) Unmask(_ context.Context, masks []MaskIdentity) error {
	executor.unmaskCalls = append(executor.unmaskCalls, append([]MaskIdentity(nil), masks...))
	for _, mask := range masks {
		if mask.Preexisting {
			return errors.New("fake executor was asked to remove a preexisting mask")
		}
	}
	executor.unmasked = maskNames(masks)
	return nil
}

func (executor *fakeExecutor) mutationCount() int {
	return executor.prepareCount + executor.stageCount + executor.resolveCount + executor.maskCount + executor.runCount
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
