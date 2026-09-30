//go:build linux

package packages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"lanpanel/internal/child"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/pierrec/lz4/v4"
	"golang.org/x/sys/unix"
)

func TestReleaseSHA256FilesStopsAtAcquireByHash(t *testing.T) {
	files, err := releaseSHA256Files([]byte("SHA256:\n abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd 1 Packages\nAcquire-By-Hash: yes\n"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%#v err=%v", files, err)
	}
}

func TestSignedAPTReleaseMatchesCodenameAndComponentSubset(t *testing.T) {
	release := []byte("Suite: stable\nCodename: trixie\nComponents: main contrib non-free\n")
	if !releaseSuiteMatches(release, "trixie") || !releaseComponentsAuthorize(release, []string{"main", "contrib"}) {
		t.Fatal("valid APT codename/component subset was rejected")
	}
	if releaseSuiteMatches(release, "bookworm") || releaseComponentsAuthorize(release, []string{"main", "security"}) {
		t.Fatal("unauthorized APT suite/component was accepted")
	}
}

func TestAPTListRepositoryPrefixUsesAPTCanonicalPath(t *testing.T) {
	for _, test := range []struct {
		uri, suite, want string
	}{
		{uri: "https://deb.example.test/debian", suite: "stable", want: "deb.example.test_debian_dists_stable_"},
		{uri: "https://deb.example.test/debian/", suite: "stable", want: "deb.example.test_debian_dists_stable_"},
		{uri: "https://deb.example.test/debian//", suite: "stable", want: "deb.example.test_debian__dists_stable_"},
		{uri: "https://deb.example.test/", suite: "stable", want: "deb.example.test_dists_stable_"},
		{uri: "https://deb.example.test:8080/repo_with+plus/", suite: "stable+updates", want: "deb.example.test:8080_repo%5fwith+plus_dists_stable+updates_"},
		{uri: "https://[2001:db8::1]/debian", suite: "stable", want: "2001:db8::1_debian_dists_stable_"},
		{uri: "https://deb.example.test/repo%20name", suite: "stable", want: "deb.example.test_repo%2520name_dists_stable_"},
	} {
		got, err := aptListRepositoryPrefix(test.uri, test.suite)
		if err != nil || got != test.want {
			t.Fatalf("aptListRepositoryPrefix(%q, %q) = %q, %v; want %q", test.uri, test.suite, got, err, test.want)
		}
	}
}

func TestLinuxAuditorReadsExactRepositoryDPKGPolicyAndRuntimeAuthority(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{
		"etc/apt/apt.conf.d", "etc/apt/keyrings", "etc/apt/sources.list.d", "etc/apt/trusted.gpg.d", "etc/dpkg/dpkg.cfg.d",
		"var/lib/apt/lists", "var/lib/dpkg", "cgroup/nginx.service", "proc", "usr/sbin", "usr/lib/lanpanel", "etc/systemd/system",
	} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	plan := testPlan(t, DistroRepository)
	binary := []byte("same lanpanel policy binary")
	binaryDigest := fmt.Sprintf("%x", sha256.Sum256(binary))
	plan.NoAutostartPolicyDigest = binaryDigest
	signer, err := openpgp.NewEntity("APT Fixture", "", "apt@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	var keyringBuffer bytes.Buffer
	if err := signer.Serialize(&keyringBuffer); err != nil {
		t.Fatal(err)
	}
	keyring := keyringBuffer.Bytes()
	plan.Repositories[0].KeyringDigest = fmt.Sprintf("%x", sha256.Sum256(keyring))
	writeFixture(t, root, "etc/apt/apt.conf", []byte("// no hooks\n"), 0o644)
	writeFixture(t, root, "etc/apt/keyrings/lanpanel.gpg", keyring, 0o644)
	writeFixture(t, root, "etc/apt/sources.list", []byte("deb [arch=amd64 signed-by=/etc/apt/keyrings/lanpanel.gpg] https://deb.example.test/debian stable main\n"), 0o644)
	packageIndex := []byte("Package: goaccess\nVersion: 1.9.3-1\nArchitecture: amd64\nFilename: pool/main/g/goaccess_1.9.3-1_amd64.deb\nSize: 1024\nSHA256: " + strings.Repeat("b", 64) + "\n\nPackage: nginx\nVersion: 1.22.1-9\nArchitecture: amd64\nFilename: pool/main/n/nginx_1.22.1-9_amd64.deb\nSize: 2048\nSHA256: " + strings.Repeat("c", 64) + "\n")
	packageDigest := fmt.Sprintf("%x", sha256.Sum256(packageIndex))
	signRelease := func(plaintext string) []byte {
		t.Helper()
		var signed bytes.Buffer
		writer, err := clearsign.Encode(&signed, signer.PrivateKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(plaintext)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return signed.Bytes()
	}
	releaseDate := time.Now().UTC().Add(-time.Hour).Format(time.RFC1123)
	releasePlaintext := fmt.Sprintf("Origin: fixture\nSuite: stable\nComponents: main\nDate: %s\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages\n", releaseDate, packageDigest, len(packageIndex))
	release := signRelease(releasePlaintext)
	var compressedPackageIndex bytes.Buffer
	compressor := lz4.NewWriter(&compressedPackageIndex)
	if _, err := compressor.Write(packageIndex); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "var/lib/apt/lists/deb.example.test_debian_dists_stable_InRelease", release, 0o644)
	writeFixture(t, root, "var/lib/apt/lists/deb.example.test_debian_dists_stable_main_binary-amd64_Packages.lz4", compressedPackageIndex.Bytes(), 0o644)
	writeFixture(t, root, "etc/dpkg/dpkg.cfg", []byte("# safe\n"), 0o644)
	writeFixture(t, root, "var/lib/dpkg/status", []byte("Package: base-files\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n"), 0o644)
	writeFixture(t, root, "cgroup/nginx.service/cgroup.procs", nil, 0o644)
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		writeFixture(t, root, "proc/"+table, []byte("  sl  local_address rem_address st\n"), 0o644)
	}
	writeFixture(t, root, "usr/lib/lanpanel/lanpanel", binary, 0o755)
	writeFixture(t, root, "usr/sbin/policy-rc.d", binary, 0o755)
	launcher := &auditLauncher{}
	auditor := newTestLinuxAuditor(launcher, root)
	observedRepositories := []ObservedRepository{{URI: plan.Repositories[0].URI, Suite: plan.Repositories[0].Suite, Components: plan.Repositories[0].Components, KeyringPath: plan.Repositories[0].KeyringPath}}
	if err := auditor.observeRepositoryMetadata(context.Background(), observedRepositories, map[string][]byte{plan.Repositories[0].KeyringPath: keyring}, nil); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "var/lib/apt/lists/deb.example.test_debian_dists_stable_InRelease", []byte(releasePlaintext), 0o644)
	if err := auditor.observeRepositoryMetadata(context.Background(), observedRepositories, map[string][]byte{plan.Repositories[0].KeyringPath: keyring}, nil); err == nil {
		t.Fatal("unsigned InRelease metadata was accepted")
	}
	wrongSuite := signRelease(strings.Replace(releasePlaintext, "Suite: stable", "Suite: other", 1))
	writeFixture(t, root, "var/lib/apt/lists/deb.example.test_debian_dists_stable_InRelease", wrongSuite, 0o644)
	if err := auditor.observeRepositoryMetadata(context.Background(), observedRepositories, map[string][]byte{plan.Repositories[0].KeyringPath: keyring}, nil); err == nil {
		t.Fatal("signed metadata for a different suite was accepted")
	}
	writeFixture(t, root, "var/lib/apt/lists/deb.example.test_debian_dists_stable_InRelease", release, 0o644)
	wrongSigner, err := openpgp.NewEntity("Wrong APT Fixture", "", "wrong@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	var wrongKeyring bytes.Buffer
	if err := wrongSigner.Serialize(&wrongKeyring); err != nil {
		t.Fatal(err)
	}
	if err := auditor.observeRepositoryMetadata(context.Background(), observedRepositories, map[string][]byte{plan.Repositories[0].KeyringPath: wrongKeyring.Bytes()}, nil); err == nil {
		t.Fatal("InRelease signed by a different key was accepted")
	}
	audit, err := auditor.AuditPackages(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAPTConfiguration(audit.Configuration, audit.Repositories, plan.Repositories); err != nil {
		t.Fatalf("non-authoritative InRelease identity blocked a valid signed repository: %v", err)
	}
	if audit.Repositories[0].MetadataDigest != observedRepositories[0].MetadataDigest || audit.Repositories[0].CutoffDigest != observedRepositories[0].CutoffDigest {
		t.Fatalf("audit did not return host-derived repository authority: %#v", audit.Repositories[0])
	}
	wantCutoff, err := repositoryCutoffDigest([]byte(releasePlaintext))
	if err != nil || observedRepositories[0].CutoffDigest != wantCutoff {
		t.Fatalf("unexpected canonical cutoff digest: got=%s want=%s error=%v", observedRepositories[0].CutoffDigest, wantCutoff, err)
	}
	if err := ValidateDPKGReady(audit.DPKG); err != nil {
		t.Fatal(err)
	}
	if !audit.NoAutostart.SameLanPanelBinary || audit.NoAutostart.Digest != binaryDigest || len(audit.Before.Units) != 1 || audit.Before.Units[0].Active {
		t.Fatalf("audit=%#v", audit)
	}
	executor := &HostExecutor{Auditor: auditor, Launcher: launcher}
	resolved, err := executor.Resolve(context.Background(), plan)
	if err != nil || !reflectPackages(resolved, plan.Packages) {
		t.Fatalf("resolved=%#v error=%v", resolved, err)
	}
	changedResolved := append([]Package(nil), resolved...)
	changedResolved[0].RepositoryID = "other-repository"
	if reflectPackages(changedResolved, plan.Packages) {
		t.Fatal("package postcondition ignored repository ownership")
	}
	plan.FirstNginxInstall = false
	emptyLauncher := &auditLauncher{emptySimulation: true}
	resolved, err = (&HostExecutor{Auditor: auditor, Launcher: emptyLauncher}).Resolve(context.Background(), plan)
	if err != nil || !reflectPackages(resolved, plan.Packages) {
		t.Fatalf("no-op distro package resolution failed: resolved=%#v error=%v", resolved, err)
	}

	writeFixture(t, root, "etc/apt/apt.conf", []byte(`DPkg::Pre-Invoke { "needrestart"; };`), 0o644)
	audit, err = auditor.AuditPackages(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAPTConfiguration(audit.Configuration, audit.Repositories, plan.Repositories); err != nil {
		t.Fatalf("standard distro APT hook was rejected: %v", err)
	}
	writeFixture(t, root, "etc/apt/apt.conf", []byte("// no hooks\n"), 0o644)
	writeFixture(t, root, "var/lib/apt/lists/deb.example.test_debian_dists_stable_InRelease", signRelease(fmt.Sprintf("Origin: fixture\nSuite: stable\nDate: %s\nArchitectures: amd64\nDescription: changed\nSHA256:\n %s %d main/binary-amd64/Packages\n", releaseDate, packageDigest, len(packageIndex))), 0o644)
	if _, err := auditor.ObservePackages(context.Background(), plan); err == nil {
		t.Fatal("post-transaction repository metadata drift was accepted")
	}
}

func TestValidateReleaseFreshnessRequiresBoundedMetadataAge(t *testing.T) {
	fresh := time.Now().UTC().Add(-time.Hour).Format(time.RFC1123)
	if err := validateReleaseFreshness([]byte("Date: " + fresh + "\n")); err != nil {
		t.Fatalf("fresh metadata without Valid-Until was rejected: %v", err)
	}
	stale := time.Now().UTC().Add(-maxAPTReleaseAge - time.Hour).Format(time.RFC1123)
	if err := validateReleaseFreshness([]byte("Date: " + stale + "\n")); err == nil {
		t.Fatal("stale metadata without Valid-Until was accepted")
	}
}

func TestLinuxAuditorReadDPKGClassifiesHeldAndInstalledStates(t *testing.T) {
	fixture := strings.Join([]string{
		"Package: base-files\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\nDescription: fixture\n\ttab continuation\n",
		"Package: held-installed\nStatus: hold ok installed\nVersion: 2\nArchitecture: amd64\n",
		"Package: held-half-configured\nStatus: hold ok half-configured\nVersion: 3\nArchitecture: amd64\n",
		"Package: held-unpacked\nStatus: hold ok unpacked\nVersion: 4\nArchitecture: amd64\n",
		"Package: held-triggers\nStatus: hold ok triggers-pending\nVersion: 5\nArchitecture: amd64\n",
		"Package: held-broken\nStatus: hold reinstreq installed\nVersion: 6\nArchitecture: amd64\n",
	}, "\n")
	auditor := dpkgFixtureAuditor(t, fixture)
	state, installed, systemPackages, err := auditor.readDPKG(context.Background(), []Package{{Name: "held-installed"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(installed) != 1 || installed[0].Name != "held-installed" || installed[0].Version != "2" || installed[0].Architecture != "amd64" {
		t.Fatalf("installed closure=%#v", installed)
	}
	if len(systemPackages) != 2 || systemPackages[0].Name != "base-files" || systemPackages[1].Name != "held-installed" {
		t.Fatalf("system packages=%#v", systemPackages)
	}
	if strings.Join(state.HalfConfigured, ",") != "held-half-configured" || strings.Join(state.Unpacked, ",") != "held-unpacked" || strings.Join(state.TriggersPending, ",") != "held-triggers" || strings.Join(state.Broken, ",") != "held-broken" {
		t.Fatalf("dpkg state=%#v", state)
	}
}

func TestLinuxAuditorReadDPKGRejectsMissingRequiredFields(t *testing.T) {
	fixture := "Package: base-files\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n"
	for _, missing := range []string{"Package", "Status", "Version", "Architecture"} {
		t.Run(missing, func(t *testing.T) {
			lines := []string{}
			for _, line := range strings.Split(fixture, "\n") {
				if line != "" && !strings.HasPrefix(line, missing+":") {
					lines = append(lines, line)
				}
			}
			auditor := dpkgFixtureAuditor(t, strings.Join(lines, "\n")+"\n")
			if _, _, _, err := auditor.readDPKG(context.Background(), nil); err == nil {
				t.Fatalf("dpkg stanza without %s was accepted", missing)
			}
		})
	}
}

func dpkgFixtureAuditor(t *testing.T, status string) *LinuxAuditor {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "var/lib/dpkg/status", []byte(status), 0o644)
	return newTestLinuxAuditor(&auditLauncher{}, root)
}

func TestLinuxAuditorVerifiesExactPackageMaskCTime(t *testing.T) {
	root := t.TempDir()
	maskRoot := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(maskRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	const unit = "nginx.service"
	path := filepath.Join(maskRoot, unit)
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatal(err)
	}
	exact := MaskIdentity{Unit: unit, Device: uint64(stat.Dev), Inode: stat.Ino, CTimeSec: stat.Ctim.Sec, CTimeNsec: stat.Ctim.Nsec}
	tests := []struct {
		name    string
		change  func(*MaskIdentity)
		wantErr bool
	}{
		{name: "exact"},
		{name: "ctime seconds", change: func(identity *MaskIdentity) { identity.CTimeSec++ }, wantErr: true},
		{name: "ctime nanoseconds", change: func(identity *MaskIdentity) { identity.CTimeNsec++ }, wantErr: true},
	}
	auditor := newTestLinuxAuditor(&auditLauncher{}, root)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := exact
			if test.change != nil {
				test.change(&identity)
			}
			err := auditor.VerifyPackageMasks(context.Background(), []MaskIdentity{identity}, true)
			if (err != nil) != test.wantErr {
				t.Fatalf("VerifyPackageMasks() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func writeFixture(t *testing.T, root, relative string, data []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

type auditLauncher struct {
	emptySimulation bool
	lastStaged      bool
}

func (launcher *auditLauncher) RunInvocation(_ context.Context, profile child.ProfileID, invocation child.Invocation, _ []byte) (child.Result, error) {
	if profile == child.ProfileAPTSimulate {
		launcher.lastStaged = invocation.Package.Staged
	}
	result := child.Result{ExitCode: 0, StdoutDigest: "sha256:" + strings.Repeat("1", 64), StderrDigest: "sha256:" + strings.Repeat("2", 64), PackageChanges: []child.PackageChange{}}
	if profile == child.ProfileAPTSimulate && !launcher.emptySimulation {
		for _, pkg := range invocation.Package.Packages {
			result.PackageChanges = append(result.PackageChanges, child.PackageChange{Name: pkg.Name, Version: pkg.Version})
		}
	}
	return result, nil
}

func TestHostExecutorResolveUsesStagedSimulationForArtifactPlans(t *testing.T) {
	for _, mode := range []Mode{StagedDebs, OfflineDebs} {
		t.Run(string(mode), func(t *testing.T) {
			plan := testPlan(t, mode)
			launcher := &auditLauncher{}
			resolved, err := (&HostExecutor{Launcher: launcher}).Resolve(context.Background(), plan)
			if err != nil || !reflectPackages(resolved, plan.Packages) {
				t.Fatalf("resolved=%#v error=%v", resolved, err)
			}
			if !launcher.lastStaged {
				t.Fatal("artifact package simulation was not staged")
			}
		})
	}
}
