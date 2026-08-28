//go:build linux

package packages

import (
	"context"
	"crypto/sha256"
	"fmt"
	"lanpanel/internal/child"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxAuditorReadsExactRepositoryDPKGPolicyAndRuntimeAuthority(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{
		"etc/apt/apt.conf.d", "etc/apt/keyrings", "etc/apt/sources.list.d", "etc/apt/trusted.gpg.d", "etc/dpkg/dpkg.cfg.d",
		"var/lib/dpkg", "cgroup/nginx.service", "proc", "usr/sbin", "usr/lib/lanpanel", "etc/systemd/system",
	} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	plan := testPlan(t, DistroRepository)
	binary := []byte("same lanpanel policy binary")
	binaryDigest := fmt.Sprintf("%x", sha256.Sum256(binary))
	plan.NoAutostartPolicyDigest = binaryDigest
	keyring := []byte("exact distro keyring")
	plan.Repositories[0].KeyringDigest = fmt.Sprintf("%x", sha256.Sum256(keyring))
	writeFixture(t, root, "etc/apt/apt.conf", []byte("// no hooks\n"), 0o644)
	writeFixture(t, root, "etc/apt/keyrings/lanpanel.gpg", keyring, 0o644)
	writeFixture(t, root, "etc/apt/sources.list", []byte("deb [arch=amd64 signed-by=/etc/apt/keyrings/lanpanel.gpg] https://deb.example.test/debian stable main\n"), 0o644)
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
	audit, err := auditor.AuditPackages(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAPTConfiguration(audit.Configuration, audit.Repositories, plan.Repositories); err != nil {
		t.Fatal(err)
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

	writeFixture(t, root, "etc/apt/apt.conf", []byte(`DPkg::Pre-Invoke { "bad"; };`), 0o644)
	audit, err = auditor.AuditPackages(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAPTConfiguration(audit.Configuration, audit.Repositories, plan.Repositories); err == nil {
		t.Fatal("malicious active APT hook was accepted")
	}
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

type auditLauncher struct{}

func (*auditLauncher) RunInvocation(_ context.Context, profile child.ProfileID, invocation child.Invocation, _ []byte) (child.Result, error) {
	result := child.Result{ExitCode: 0, StdoutDigest: "sha256:" + strings.Repeat("1", 64), StderrDigest: "sha256:" + strings.Repeat("2", 64), PackageChanges: []child.PackageChange{}}
	if profile == child.ProfileAPTSimulate {
		for _, pkg := range invocation.Package.Packages {
			result.PackageChanges = append(result.PackageChanges, child.PackageChange{Name: pkg.Name, Version: pkg.Version})
		}
	}
	return result, nil
}
