//go:build linux

package preflight

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLinuxObserverReadsWithoutMutationAndParsesExactSocketIdentity(t *testing.T) {
	root := t.TempDir()
	osRelease := filepath.Join(root, "os-release")
	kernelRelease := filepath.Join(root, "kernel-release")
	cgroupMountpoint := filepath.Join(root, "cgroup")
	cgroupSession := filepath.Join(cgroupMountpoint, "session.scope")
	cgroupControllers := filepath.Join(cgroupMountpoint, "cgroup.controllers")
	cgroupKill := filepath.Join(cgroupSession, "cgroup.kill")
	cgroupMountInfo := filepath.Join(root, "mountinfo")
	systemd := filepath.Join(root, "systemd")
	systemdExecutable := filepath.Join(root, "systemd-bin")
	apt := filepath.Join(root, "apt-get")
	dpkg := filepath.Join(root, "dpkg")
	tcp := filepath.Join(root, "tcp")
	tcp6 := filepath.Join(root, "tcp6")
	udp := filepath.Join(root, "udp")
	udp6 := filepath.Join(root, "udp6")
	managedParent := filepath.Join(root, "managed")
	managed := filepath.Join(managedParent, "app")
	for _, path := range []string{systemd, cgroupMountpoint, cgroupSession, managedParent, managed} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(osRelease, "ID=debian\nVERSION_ID=13\n", 0o644)
	write(kernelRelease, "6.12.1-fixture\n", 0o644)
	write(cgroupControllers, "cpu memory pids\n", 0o644)
	write(cgroupKill, "", 0o200)
	write(filepath.Join(cgroupSession, "cgroup.procs"), "", 0o600)
	write(filepath.Join(cgroupSession, "cgroup.events"), "populated 0\n", 0o600)
	write(cgroupMountInfo, "29 23 0:26 / "+cgroupMountpoint+" rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n", 0o644)
	write(filepath.Join(root, "self-cgroup"), "0::/session.scope\n", 0o644)
	write(systemdExecutable, "#!/bin/sh\necho systemd 257\n", 0o755)
	write(apt, "fixture", 0o700)
	write(dpkg, "fixture", 0o700)
	write(tcp, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 101\n", 0o600)
	write(tcp6, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n", 0o600)
	write(udp, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   1: 00000000:0D96 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 102\n", 0o600)
	write(udp6, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n", 0o600)
	before, err := treeSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	observer := newTestLinuxObserver(LinuxPaths{OSRelease: osRelease, KernelRelease: kernelRelease, CgroupControllers: cgroupControllers, CgroupMountpoint: cgroupMountpoint, CgroupMountInfo: cgroupMountInfo, CgroupCurrent: filepath.Join(root, "self-cgroup"), SystemdRoot: systemd, SystemdExecutable: systemdExecutable, APTExecutable: apt, DPKGExecutable: dpkg, TCP: tcp, TCP6: tcp6, UDP: udp, UDP6: udp6}, func(context.Context) (PackageObservation, error) {
		return PackageObservation{Ready: true, Identity: "packages/ready", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: "sha256:" + strings.Repeat("9", 64)}, nil
	}, func() time.Time { return now })
	request := expansionRequest(ExpansionBootstrap)
	request.Target = "installation"
	request.Domains = nil
	request.BootstrapListeners = []ListenerRequirement{{Protocol: "tcp", Address: "127.0.0.1", Port: 52345, Purpose: "management"}}
	request.ManagedPaths = []ManagedPathRequirement{{Path: managed, Kind: ManagedPathDirectory, OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()), RequiredMode: 0o700, MaximumMode: 0o700}}
	request.Disks = []DiskRequirement{{Path: managed, MinimumAvailableBytes: 1}}
	observed, err := observer.ObserveExpansion(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Platform.ID != "debian" || observed.Platform.VersionID != "13" || observed.KernelRelease != "6.12.1-fixture" || observed.CgroupMode != "unified_v2" || observed.CgroupMountpoint != cgroupMountpoint || observed.CgroupMountRoot != "/" || !observed.CgroupKillAvailable || !observed.SystemdDelegation.Available || len(observed.Listeners) != 2 || observed.Listeners[0].Port != 80 || observed.Listeners[0].SocketInode != 101 || observed.Listeners[1].Port != 3478 || observed.Listeners[1].SocketInode != 102 {
		t.Fatalf("observed=%#v", observed)
	}
	after, err := treeSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("read-only observer mutated fixture tree\nbefore=%s\nafter=%s", before, after)
	}
}

func TestVerifyInstalledProfileIgnoresPackageVersionsAndSnapshot(t *testing.T) {
	digest := "sha256:" + strings.Repeat("9", 64)
	expected := ExpectedProfile{
		ID: "debian", VersionID: "13", Architecture: runtime.GOARCH,
		SystemdVersion: "1:257.8-1~deb13u1", NginxVersion: "1.26.3-3+deb13u1", PackageSnapshotDigest: digest,
		ManagedConfinement: ManagedConfinementProfile{KernelRelease: "6.12.1", CgroupMode: "unified_v2"},
	}
	observed := InstalledProfileObservation{
		Architecture: runtime.GOARCH, Platform: PlatformInfo{ID: "debian", VersionID: "13"},
		KernelRelease: "6.12.1", CgroupMode: "unified_v2", CgroupMountpoint: "/sys/fs/cgroup", CgroupMountRoot: "/", CgroupKillAvailable: true, SystemdDelegation: ComponentObservation{Available: true, Identity: "systemd/257 Delegate=yes"},
		Packages: PackageObservation{Ready: true, Identity: "package-observation", SystemdVersion: "1:257.8-1~deb13u1", NginxVersion: "1.26.3-3+deb13u1", PackageSnapshotDigest: digest},
	}
	if err := VerifyInstalledProfile(expected, observed); err != nil {
		t.Fatalf("matching installed profile rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*InstalledProfileObservation)
	}{
		{name: "systemd", change: func(value *InstalledProfileObservation) { value.Packages.SystemdVersion = "different" }},
		{name: "nginx", change: func(value *InstalledProfileObservation) { value.Packages.NginxVersion = "different" }},
		{name: "package_snapshot", change: func(value *InstalledProfileObservation) { value.Packages.PackageSnapshotDigest = "different" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := observed
			test.change(&candidate)
			if err := VerifyInstalledProfile(expected, candidate); err != nil {
				t.Fatalf("obsolete package identity blocked: %v", err)
			}
		})
	}
	candidate := observed
	candidate.Platform.VersionID = "14"
	if err := VerifyInstalledProfile(expected, candidate); err != nil {
		t.Fatalf("OS release change should remain compatible with the family profile: %v", err)
	}
	candidate = observed
	candidate.CgroupKillAvailable = false
	if err := VerifyInstalledProfile(expected, candidate); err == nil || !IsProfileDrift(err) {
		t.Fatalf("missing cgroup.kill was not classified: %v", err)
	}
	candidate = observed
	candidate.SystemdDelegation.Available = false
	if err := VerifyInstalledProfile(expected, candidate); err == nil || !IsProfileDrift(err) {
		t.Fatalf("missing systemd delegation was not classified: %v", err)
	}
	candidate = observed
	candidate.Platform.ID = "ubuntu"
	if err := VerifyInstalledProfile(expected, candidate); err != nil {
		t.Fatalf("OS family change should remain compatible with the capability contract: %v", err)
	}
	candidate = observed
	candidate.Packages.Ready = false
	candidate.Packages.Reason = "dpkg_partial_state"
	if err := VerifyInstalledProfile(expected, candidate); err == nil || !IsProfileDrift(err) {
		t.Fatalf("package readiness drift was not classified: %v", err)
	}
}

func TestParseBootstrapDPKGStatusClassifiesHeldPackages(t *testing.T) {
	for _, status := range []string{"install ok installed", "hold ok installed"} {
		t.Run(status, func(t *testing.T) {
			fixture := []byte("Package: systemd\nStatus: " + status + "\nVersion: 1:257.8-1~deb13u1\nArchitecture: amd64\nDescription: fixture\n\ttab continuation\n")
			installed, partial, err := parseBootstrapDPKGStatus(fixture)
			if err != nil || partial || len(installed) != 1 || installed[0].Name != "systemd" || installed[0].Version != "1:257.8-1~deb13u1" || installed[0].Architecture != "amd64" {
				t.Fatalf("installed=%#v partial=%t err=%v", installed, partial, err)
			}
		})
	}

	heldHalfConfigured := []byte("Package: systemd\nStatus: hold ok half-configured\nVersion: 257.1\nArchitecture: amd64\n")
	installed, partial, err := parseBootstrapDPKGStatus(heldHalfConfigured)
	if err != nil || !partial || len(installed) != 0 {
		t.Fatalf("held half-configured installed=%#v partial=%t err=%v", installed, partial, err)
	}
}

func TestObserveInstalledPackageTuplesReturnsExactRequestedTuple(t *testing.T) {
	status := filepath.Join(t.TempDir(), "status")
	fixture := "Package: goaccess\nStatus: install ok installed\nVersion: 1.9.3-1\nArchitecture: amd64\n\nPackage: nginx\nStatus: install ok installed\nVersion: 1.26.0-1\nArchitecture: amd64\n\nPackage: unrelated\nStatus: install ok installed\nVersion: 1.0\nArchitecture: all\n"
	if err := os.WriteFile(status, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	observed, err := observeInstalledPackageTuples(context.Background(), status, []string{"goaccess", "nginx"}, false)
	if err != nil || len(observed) != 2 || observed[0] != (InstalledPackageTuple{Name: "goaccess", Version: "1.9.3-1", Architecture: "amd64"}) || observed[1] != (InstalledPackageTuple{Name: "nginx", Version: "1.26.0-1", Architecture: "amd64"}) {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	if _, err := observeInstalledPackageTuples(context.Background(), status, []string{"nginx", "goaccess"}, false); err == nil {
		t.Fatal("unsorted package selector was accepted")
	}
	if _, err := observeInstalledPackageTuples(context.Background(), status, []string{"missing"}, false); err == nil {
		t.Fatal("missing package tuple was accepted")
	}
}

func TestParseBootstrapDPKGStatusRejectsMissingRequiredFields(t *testing.T) {
	fixture := "Package: systemd\nStatus: install ok installed\nVersion: 257.1\nArchitecture: amd64\n"
	for _, missing := range []string{"Package", "Status", "Version", "Architecture"} {
		t.Run(missing, func(t *testing.T) {
			lines := []string{}
			for _, line := range strings.Split(fixture, "\n") {
				if line != "" && !strings.HasPrefix(line, missing+":") {
					lines = append(lines, line)
				}
			}
			if _, _, err := parseBootstrapDPKGStatus([]byte(strings.Join(lines, "\n") + "\n")); err == nil {
				t.Fatalf("dpkg stanza without %s was accepted", missing)
			}
		})
	}
}

func TestLinuxObserverRecordsNonUnifiedCgroupV2(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "missing", path: filepath.Join(root, "missing-cgroup.controllers")},
		{name: "empty", path: filepath.Join(root, "empty-cgroup.controllers")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "empty" {
				if err := os.WriteFile(test.path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			observer := &LinuxObserver{paths: LinuxPaths{CgroupControllers: test.path}}
			mode, err := observer.readCgroupMode()
			if err != nil || mode != "not_unified_v2" {
				t.Fatalf("mode=%q err=%v", mode, err)
			}
		})
	}
}

func TestLinuxObserverClassifiesHybridCgroupV2(t *testing.T) {
	root := t.TempDir()
	controllers := filepath.Join(root, "unified", "cgroup.controllers")
	if err := os.MkdirAll(filepath.Dir(controllers), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controllers, []byte("cpu memory pids\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	observer := &LinuxObserver{paths: LinuxPaths{CgroupControllers: filepath.Join(root, "root", "cgroup.controllers"), CgroupHybridControllers: controllers}}
	mode, err := observer.readCgroupMode()
	if err != nil || mode != "hybrid_v2" {
		t.Fatalf("mode=%q err=%v", mode, err)
	}
}

func TestParseProcNetIncludesBoundUDPStates(t *testing.T) {
	data := []byte("header\n0: 00000000:0D96 00000000:0000 01 0:0 0:0 0 0 0 55\n")
	observed, err := parseProcNet(data, "udp", false)
	if err != nil || len(observed) != 1 || observed[0].Port != 3478 {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
}

func TestParseProcNetRejectsMissingSocketIdentity(t *testing.T) {
	data := []byte("header\n0: 00000000:01BB 00000000:0000 0A 0:0 0:0 0 0 0\n")
	if _, err := parseProcNet(data, "tcp", false); err == nil {
		t.Fatal("listener without inode was accepted")
	}
}

func treeSnapshot(root string) (string, error) {
	values := []string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		values = append(values, relative+"/"+info.Mode().String()+"/"+strings.TrimSpace(info.ModTime().UTC().Format(time.RFC3339Nano)))
		return nil
	})
	return strings.Join(values, "\n"), err
}
