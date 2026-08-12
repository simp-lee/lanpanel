//go:build linux

package preflight

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxObserverReadsWithoutMutationAndParsesExactSocketIdentity(t *testing.T) {
	root := t.TempDir()
	osRelease := filepath.Join(root, "os-release")
	systemd := filepath.Join(root, "systemd")
	apt := filepath.Join(root, "apt-get")
	dpkg := filepath.Join(root, "dpkg")
	tcp := filepath.Join(root, "tcp")
	tcp6 := filepath.Join(root, "tcp6")
	udp := filepath.Join(root, "udp")
	udp6 := filepath.Join(root, "udp6")
	managedParent := filepath.Join(root, "managed")
	managed := filepath.Join(managedParent, "app")
	for _, path := range []string{systemd, managedParent, managed} {
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
	observer := newTestLinuxObserver(LinuxPaths{OSRelease: osRelease, SystemdRoot: systemd, APTExecutable: apt, DPKGExecutable: dpkg, TCP: tcp, TCP6: tcp6, UDP: udp, UDP6: udp6}, func(context.Context) (PackageObservation, error) {
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
	if observed.Platform.ID != "debian" || observed.Platform.VersionID != "13" || len(observed.Listeners) != 2 || observed.Listeners[0].Port != 80 || observed.Listeners[0].SocketInode != 101 || observed.Listeners[1].Port != 3478 || observed.Listeners[1].SocketInode != 102 {
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
