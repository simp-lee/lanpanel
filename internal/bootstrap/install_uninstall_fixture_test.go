//go:build linux

package bootstrap

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/helper"
	"lanpanel/internal/identity"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This fixture runs the real installer kernel and committed public teardown in
// a private mount/user namespace. It deliberately does not use the fabricated
// committed-state helper used by the narrower uninstall predicate tests.
func TestRealInstallThenPublicUninstallFixture(t *testing.T) {
	if os.Getenv("LANPANEL_REAL_LIFECYCLE_CHILD") != "1" {
		namespaceRoot := t.TempDir()
		if err := os.Chmod(namespaceRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"tmp", "etc", "var", "run", "usr/bin", "usr/sbin", "usr/lib/x86_64-linux-gnu", "usr/lib64", "usr/lib/lanpanel", "usr/local/bin", "bin", "sbin", "lib", "lib64", "sys/fs/bpf"} {
			if err := os.MkdirAll(filepath.Join(namespaceRoot, path), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		args := []string{
			"--unshare-user", "--uid", "0", "--gid", "0", "--unshare-pid", "--bind", namespaceRoot, "/",
			"--proc", "/proc", "--dev-bind", "/dev", "/dev", "--ro-bind", "/bin", "/bin", "--ro-bind", "/sbin", "/sbin", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/usr/bin", "/usr/bin", "--ro-bind", "/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "--ro-bind", "/usr/lib64", "/usr/lib64", "--ro-bind", os.Args[0], "/tmp/lifecycle.test",
			"/tmp/lifecycle.test", "-test.run=^TestRealInstallThenPublicUninstallFixture$", "-test.v",
		}
		master, slave := openFixturePTY(t, "UNINSTALL LANPANEL\n")
		defer func() { _ = master.Close() }()
		defer func() { _ = slave.Close() }()
		command := exec.Command("bwrap", args...)
		command.ExtraFiles = []*os.File{slave}
		command.Env = append(os.Environ(), "LANPANEL_REAL_LIFECYCLE_CHILD=1", "TMPDIR=/tmp")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated real lifecycle failed: %v\n%s", err, output)
		}
		return
	}

	prepareLifecycleNamespace(t)
	material, err := identity.Generate(bytes.NewReader(bytes.Repeat([]byte{0x41}, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()

	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := testPaths(filepath.Join(base, "installation"))
	paths.Journal = filepath.Join(base, "bootstrap-journal")
	paths.CommitPath = filepath.Join(base, "bootstrap-commit.json")
	startupDir := filepath.Join(base, "startup-parent")
	if err := os.Mkdir(startupDir, 0o710); err != nil {
		t.Fatal(err)
	}
	paths.StartupAuthority = filepath.Join(startupDir, "startup-authority.json")
	binaryBase := t.TempDir()
	if err := os.Chmod(binaryBase, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryDir := filepath.Join(binaryBase, "binary-parent")
	if err := os.Mkdir(binaryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	paths.BinaryPath = filepath.Join(binaryDir, "lanpanel")
	paths.SysusersPath = filepath.Join(base, "sysusers.conf")
	paths.SystemdRoot = filepath.Join(base, "systemd")
	if err := os.Mkdir(paths.SystemdRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := testJournal(t.TempDir())
	sourceBinary := []byte("real-lifecycle-lanpanel")
	fixture.Release.Binary.Bytes = uint64(len(sourceBinary))
	fixture.Release.Binary.Digest = release.DigestBytes(sourceBinary)
	lego := []byte("real-lifecycle-lego")
	tailscale := []byte("real-lifecycle-tailscale")
	headscale, member := lifecycleHeadscaleArchive(t)
	fixture.Release.Lego.Bytes = uint64(len(lego))
	fixture.Release.Lego.Digest = release.DigestBytes(lego)
	fixture.Release.Tailscale.Bytes = uint64(len(tailscale))
	fixture.Release.Tailscale.Digest = release.DigestBytes(tailscale)
	fixture.Release.Headscale.Archive.Bytes = uint64(len(headscale))
	fixture.Release.Headscale.Archive.Digest = release.DigestBytes(headscale)
	fixture.Release.Headscale.Members[0].Mode = 0o755
	fixture.Release.Headscale.Members[0].Asset = release.AssetIdentity{Path: "headscale", Digest: release.DigestBytes(member), Bytes: uint64(len(member))}
	fixture.Release.DependencyBaseline.Bytes = 1
	fixture.Release.DependencyBaseline.Digest = release.DigestBytes([]byte("b"))
	fixture.Release.Profile.Packages = []release.PackageTuple{{Name: "nginx", Version: fixture.Release.Profile.NginxVersion, Architecture: "amd64", RepositoryID: fixture.Release.Profile.Repositories[0].ID}}
	fixture.Release.ProfileDigest, err = release.ProfileDigest(fixture.Release.Profile)
	if err != nil {
		t.Fatal(err)
	}

	request := installerFixtureRequest(t, fixture, material, sourceBinary, lego, tailscale, headscale, paths)
	if err := install(context.Background(), request, false); err != nil {
		phase := "unknown"
		if store, journal, readErr := openJournal(paths.Journal, 0, 0); readErr == nil {
			phase = fmt.Sprintf("%s/%d", journal.Phase, journal.Sequence)
			_ = store.close()
		}
		t.Fatalf("real installer did not commit: %v (phase %s)", err, phase)
	}
	store, journal, err := openJournal(paths.Journal, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != PhaseActivated || journal.FinalCommitDigest == "" {
		t.Fatalf("installer did not reach activated committed state: phase=%s commit=%q", journal.Phase, journal.FinalCommitDigest)
	}
	_ = store.close()
	if _, err := os.Stat(paths.CommitPath); err != nil {
		t.Fatal(err)
	}
	inventoryBytes, err := readCommittedArtifact(ownershipInventoryPath(paths), MaximumJournalBytes, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var inventory OwnershipInventory
	if err := decodeCanonical(inventoryBytes, &inventory); err != nil {
		t.Fatal(err)
	}

	tty := os.NewFile(uintptr(3), "lifecycle-confirmation-tty")
	if tty == nil {
		t.Fatal("isolated confirmation terminal was not inherited")
	}
	defer func() { _ = tty.Close() }()
	var output bytes.Buffer
	if err := runPublicUninstallAt(nil, tty, &output, paths); err != nil {
		t.Fatalf("public teardown of real committed state failed: %v\n%s", err, output.String())
	}
	for _, path := range append(inventory.Paths, helper.FixedIdentityConfigPath, "/usr/lib/lanpanel/dependencies/lego", "/usr/lib/lanpanel/dependencies/tailscale", "/usr/lib/lanpanel/dependencies/headscale") {
		if path == filepath.Dir(paths.BinaryPath) || path == filepath.Dir(publicCommandPath(paths)) {
			continue
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("owned lifecycle residue remains at %s: %v", path, err)
		}
	}
}

func writeFixtureAccounts(t *testing.T, installationID string) {
	accounts, err := identity.InstallationAccounts(installationID)
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]uint32{"root": 0, "www-data": 33}
	for index, spec := range accounts.Specs {
		if _, ok := groups[spec.Group]; !ok {
			groups[spec.Group] = uint32(11000 + index)
		}
	}
	var passwd, group, shadow strings.Builder
	passwd.WriteString("root:x:0:0:root:/root:/bin/sh\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
	group.WriteString("root:x:0:\nwww-data:x:33:\n")
	shadow.WriteString("root:!:1:0:99999:7:::\nwww-data:!:1:0:99999:7:::\n")
	writtenGroups := map[string]bool{}
	for index, spec := range accounts.Specs {
		gid := groups[spec.Group]
		uid := uint32(10000 + index)
		if !writtenGroups[spec.Group] {
			_, _ = fmt.Fprintf(&group, "%s:x:%d:\n", spec.Group, gid)
			writtenGroups[spec.Group] = true
		}
		_, _ = fmt.Fprintf(&passwd, "%s:x:%d:%d:%s:%s:%s\n", spec.User, uid, gid, spec.Comment, spec.Home, spec.Shell)
		_, _ = fmt.Fprintf(&shadow, "%s:!:1:0:99999:7:::\n", spec.User)
	}
	if err := os.WriteFile("/etc/passwd", []byte(passwd.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/group", []byte(group.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/shadow", []byte(shadow.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func prepareLifecycleNamespace(t *testing.T) {
	t.Helper()
	for _, path := range []string{"/etc/systemd/system", "/etc/sysusers.d", "/etc/apt/keyrings", "/etc/nginx", "/etc/lanpanel", "/usr/lib/lanpanel", "/var/lib", "/var/lib/lanpanel/installation", "/var/log", "/run"} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/group", []byte("root:x:0:\nwww-data:x:33:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/shadow", []byte("root:!:1:0:99999:7:::\nwww-data:!:1:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	write := func(name, body string) {
		path := filepath.Join(bin, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("systemctl", "#!/bin/sh\ncase \"$1\" in is-active) exit 1;; show) exit 0;; *) exit 0;; esac\n")
	write("userdel", "#!/bin/sh\nexit 0\n")
	write("groupdel", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func installerFixtureRequest(t *testing.T, fixture Journal, material identity.Material, sourceBinary, lego, tailscale, headscale []byte, paths Paths) Request {
	t.Helper()
	request := installerPreflightRequest(fixture.Release, material.Authority, material.SafetyGeneration)
	requestDigest, err := preflight.ExpansionRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	result := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: material.SafetyGeneration, RequestDigest: requestDigest, Allowed: true, ObservedAt: now, ValidUntil: now.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "fixture_ready", Disposition: preflight.FindingPassed, Summary: "isolated lifecycle fixture", Identity: "fixture"}}}
	repositoryID := fixture.Release.Profile.Repositories[0].ID
	nginxPackage := packages.Package{Name: "nginx", Version: fixture.Release.Profile.NginxVersion, Architecture: "amd64", RepositoryID: repositoryID, RepositoryFilename: "pool/main/n/nginx_" + fixture.Release.Profile.NginxVersion + "_amd64.deb", ArtifactDigest: strings.Repeat("e", 64), ArtifactBytes: 1, MaximumInstalledFileBytes: 1 << 20, AffectedUnits: []string{"nginx.service"}, PossibleListeners: []string{"tcp/443", "tcp/80"}, Source: sources.Source{Kind: sources.OfficialDistro, Artifact: sources.Artifact{Name: "nginx", Version: fixture.Release.Profile.NginxVersion, OperatingOS: "linux", Architecture: "amd64", Digest: strings.Repeat("e", 64)}}}
	plan := packages.Plan{TransactionID: "pkg_" + strings.Repeat("1", 64), JobID: "job_" + strings.Repeat("2", 64), IntentGeneration: material.SafetyGeneration, Deadline: now.Add(20 * time.Minute), OSProfileDigest: fixture.Release.ProfileDigest, Mode: packages.DistroRepository, Packages: []packages.Package{nginxPackage}, Repositories: fixture.Release.Profile.Repositories, FirstNginxInstall: true, LockWait: time.Minute, ConnectTimeout: time.Minute, ReadTimeout: time.Minute, TotalTimeout: 20 * time.Minute, NoAutostartPolicyDigest: fixture.Release.Binary.Digest, PreflightRequestDigest: requestDigest, Authority: packages.Authority{Kind: packages.PreviewProfile, ReleaseAuthorityDigest: fixture.Release.ReleaseManifestDigest, BinaryDigest: fixture.Release.Binary.Digest, TargetOSProfileDigest: fixture.Release.ProfileDigest, HostFingerprint: fixture.Release.HostFingerprint}}
	plan.PreflightDigest, err = result.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateInstallerPackageAuthority(fixture.Release, plan, result); err != nil {
		t.Fatal(err)
	}
	return Request{ReleaseAuthority: authorityForFixture(fixture.Release), Material: &material, Preflight: func(context.Context, identity.ManagementAuthority, uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		writeFixtureAccounts(t, material.InstallationID)
		return request, result, nil
	}, PackagePlan: plan, PackagePreflight: result, PackageTransaction: func(context.Context, packages.Plan, preflight.Result) (packages.Journal, error) {
		return packages.Journal{SchemaVersion: packages.PackageJournalSchemaVersion, TransactionID: plan.TransactionID, NormalJournalID: "package-" + plan.TransactionID, ChildID: "package-child-" + plan.TransactionID, JobID: plan.JobID, PlanDigest: mustPlanDigest(plan), AuthorityDigest: strings.Repeat("a", 64), PackageProfile: child.ProfileAPTTransaction, Phase: packages.JournalCleaned, Masks: []packages.MaskIdentity{}, MasksComplete: true, ChildResultDigest: strings.Repeat("b", 64), ChildSucceeded: true, PostconditionDigest: strings.Repeat("c", 64)}, nil
	}, SourceBinary: sourceBinary, LegoBytes: lego, TailscaleBytes: tailscale, HeadscaleBytes: headscale, Random: bytes.NewReader(bytes.Repeat([]byte{0x52}, 8192)), Now: func() time.Time { return now }, Paths: paths, Output: io.Discard}
}

func authorityForFixture(value release.InstallIdentity) *release.InstallAuthority {
	authority, err := release.RehydrateInstallAuthority(value)
	if err != nil {
		panic(err)
	}
	return authority
}

func mustPlanDigest(plan packages.Plan) string {
	digest, err := packages.PlanDigest(plan)
	if err != nil {
		panic(err)
	}
	return digest
}

func lifecycleHeadscaleArchive(t *testing.T) ([]byte, []byte) {
	t.Helper()
	version, err := exec.Command("tar", "--version").Output()
	if err != nil || !bytes.Contains(version, []byte("GNU tar")) {
		t.Skip("GNU tar is not available")
	}
	directory := t.TempDir()
	member := bytes.Repeat([]byte("x"), 64<<10)
	memberPath := filepath.Join(directory, "headscale")
	if err := os.WriteFile(memberPath, member, 0o755); err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(directory, "headscale.tar")
	command := exec.Command("tar", "--create", "--format=ustar", "--blocking-factor=20", "--owner=0", "--group=0", "--numeric-owner", "--mode=755", "--mtime=UTC 1970-01-01", "--directory", directory, "--file", tarPath, "headscale")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("GNU tar failed: %v: %s", err, output)
	}
	raw, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes(), member
}
