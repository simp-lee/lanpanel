//go:build linux

package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRuntimeViolationReasonsAreClosedAndTyped(t *testing.T) {
	for _, kind := range []RuntimeViolationKind{RuntimeViolationPolicyInvalid, RuntimeViolationExtraListener} {
		reason, err := RuntimeViolationReason(kind)
		if err != nil || reason != string(kind)+"_contracted" {
			t.Fatalf("kind=%q reason=%q error=%v", kind, reason, err)
		}
	}
	if _, err := RuntimeViolationReason("unknown"); err == nil {
		t.Fatal("unknown runtime violation kind was accepted")
	}
}

func TestStoppedTCPInventoryRejectsExactListener(t *testing.T) {
	data := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0900007F:4A39 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42\n")
	present, err := procTCPListenerPresent(data, netip.MustParseAddr("127.0.0.9"), 19001)
	if err != nil || !present {
		t.Fatalf("present=%t err=%v", present, err)
	}
	present, err = procTCPListenerPresent(data, netip.MustParseAddr("127.0.0.10"), 19001)
	if err != nil || present {
		t.Fatalf("foreign present=%t err=%v", present, err)
	}
	path := filepath.Join(t.TempDir(), "tcp")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	listeners, err := readListeners(path)
	if err != nil || len(listeners) != 1 || listeners[0].Address != netip.MustParseAddr("127.0.0.9") || listeners[0].Port != 19001 || listeners[0].Inode != 42 {
		t.Fatalf("listeners=%#v err=%v", listeners, err)
	}
}

func TestStoppedObservationRejectsOwnedEndpointResidue(t *testing.T) {
	root := t.TempDir()
	cgroup := "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-00000000000000000000.slice/lanpanel-app-00000000000000000000.service"
	bundle := domain.ProcessBundle{Cgroup: cgroup, FrontendEndpoint: filepath.Join(root, "frontend.sock"), EndpointSocketUnits: []string{"lanpanel-app-00000000000000000000.socket"}}
	if err := os.MkdirAll(filepath.Join(root, cgroup), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, cgroup, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, cgroup, "cgroup.events"), []byte("populated 0\nfrozen 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle.FrontendEndpoint, []byte("residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ObserveStopped(context.Background(), root, bundle); err == nil {
		t.Fatal("endpoint residue accepted")
	}
	if err := os.Remove(bundle.FrontendEndpoint); err != nil {
		t.Fatal(err)
	}
	observation, err := ObserveStopped(context.Background(), root, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStopped(observation); err != nil {
		t.Fatal(err)
	}
}

func TestStoppedObservationRejectsPopulatedRelayCgroup(t *testing.T) {
	root := t.TempDir()
	short := "00000000000000000000"
	applicationCgroup := "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-" + short + ".slice/lanpanel-app-" + short + ".service"
	relayCgroup := "/system.slice/lanpanel-relay-" + short + ".service"
	writeCgroup := func(path, processes, events string) {
		t.Helper()
		directory := filepath.Join(root, strings.TrimPrefix(path, "/"))
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "cgroup.procs"), []byte(processes), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "cgroup.events"), []byte(events), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCgroup(applicationCgroup, "", "populated 0\nfrozen 0\n")
	writeCgroup(relayCgroup, "123\n", "populated 1\nfrozen 0\n")
	bundle := domain.ProcessBundle{Cgroup: applicationCgroup, FrontendEndpoint: filepath.Join(root, "frontend.sock"), BackendEndpoint: filepath.Join(root, "backend.sock"), EndpointSocketUnits: []string{"lanpanel-app-" + short + ".socket"}, RelayRequired: true}
	if _, err := ObserveStopped(context.Background(), root, bundle); err == nil {
		t.Fatal("populated relay cgroup was accepted as stopped")
	}
}

func TestProcUnixListenerParsingAndRelayOwnership(t *testing.T) {
	frontend := "/run/lanpanel/apps/00000000000000000000.sock"
	backend := "/var/lib/lanpanel/resources/res_00000000000000000000000000000000/backend/http.sock"
	extra := "/tmp/undeclared.sock"
	path := filepath.Join(t.TempDir(), "unix")
	writeUnixProcFixture(t, path,
		procUnixRow("00010000", "0001", "01", 101, frontend),
		procUnixRow("00010000", "0001", "01", 202, backend),
		procUnixRow("00000000", "0001", "03", 404, "/tmp/connected.sock"),
	)
	listeners, err := readUnixListeners(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []unixEndpointExpectation{
		{Role: "frontend", Path: frontend, Owners: []string{unixOwnerPID1, unixOwnerRelay}},
		{Role: "backend", Path: backend, Owners: []string{unixOwnerApplication}},
	}
	owners := map[string][]uint64{unixOwnerPID1: {101}, unixOwnerRelay: {101}, unixOwnerApplication: {202}}
	evidence, err := verifyUnixListeners(listeners, want, owners, []string{unixOwnerApplication, unixOwnerRelay})
	if err != nil || len(evidence) != 2 || evidence[0].Role != "backend" || evidence[0].Inode != 202 || evidence[1].Role != "frontend" || evidence[1].Inode != 101 {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}

	t.Run("relay missing backend", func(t *testing.T) {
		missingPath := filepath.Join(t.TempDir(), "unix")
		writeUnixProcFixture(t, missingPath, procUnixRow("00010000", "0001", "01", 101, frontend))
		missing, err := readUnixListeners(missingPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyUnixListeners(missing, want, owners, []string{unixOwnerApplication, unixOwnerRelay}); err == nil {
			t.Fatal("relay without backend listener accepted")
		}
	})

	t.Run("wrong inode owner", func(t *testing.T) {
		wrongOwners := map[string][]uint64{unixOwnerPID1: {101}, unixOwnerRelay: {999}, unixOwnerApplication: {202}}
		if _, err := verifyUnixListeners(listeners, want, wrongOwners, []string{unixOwnerApplication, unixOwnerRelay}); err == nil {
			t.Fatal("listener with wrong relay inode owner accepted")
		}
	})

	t.Run("extra managed listener", func(t *testing.T) {
		extraPath := filepath.Join(t.TempDir(), "unix")
		writeUnixProcFixture(t, extraPath,
			procUnixRow("00010000", "0001", "01", 101, frontend),
			procUnixRow("00010000", "0001", "01", 202, backend),
			procUnixRow("00010000", "0001", "01", 303, extra),
		)
		extraListeners, err := readUnixListeners(extraPath)
		if err != nil {
			t.Fatal(err)
		}
		extraOwners := map[string][]uint64{unixOwnerPID1: {101}, unixOwnerRelay: {101}, unixOwnerApplication: {202, 303}}
		_, err = verifyUnixListeners(extraListeners, want, extraOwners, []string{unixOwnerApplication, unixOwnerRelay})
		var violation *RuntimeViolation
		if !errors.As(err, &violation) || violation.Kind != RuntimeViolationExtraListener {
			t.Fatalf("undeclared application listener was not a typed contraction violation: %v", err)
		}
	})

	t.Run("duplicate endpoint", func(t *testing.T) {
		duplicatePath := filepath.Join(t.TempDir(), "unix")
		writeUnixProcFixture(t, duplicatePath,
			procUnixRow("00010000", "0001", "01", 101, frontend),
			procUnixRow("00010000", "0001", "01", 102, frontend),
			procUnixRow("00010000", "0001", "01", 202, backend),
		)
		duplicate, err := readUnixListeners(duplicatePath)
		if err != nil {
			t.Fatal(err)
		}
		duplicateOwners := map[string][]uint64{unixOwnerPID1: {101, 102}, unixOwnerRelay: {101, 102}, unixOwnerApplication: {202}}
		if _, err := verifyUnixListeners(duplicate, want, duplicateOwners, []string{unixOwnerApplication, unixOwnerRelay}); err == nil {
			t.Fatal("duplicate frontend listeners accepted")
		}
	})

	t.Run("malformed table", func(t *testing.T) {
		malformed := filepath.Join(t.TempDir(), "unix")
		data := unixProcHeader + strings.Replace(procUnixRow("00010000", "0001", "01", 101, frontend), " 01 ", " GG ", 1) + "\n"
		if err := os.WriteFile(malformed, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readUnixListeners(malformed); err == nil {
			t.Fatal("malformed Unix proc table accepted")
		}
	})

	firstDigest := runtimeObservationDigest("/cgroup", "app", "relay", true, nil, evidence)
	changed := append([]unixListenerEvidence(nil), evidence...)
	changed[0].Inode++
	secondDigest := runtimeObservationDigest("/cgroup", "app", "relay", true, nil, changed)
	if firstDigest == secondDigest {
		t.Fatal("Unix listener inode replacement did not change runtime digest")
	}
}

func TestTCPApplicationOwnerRejectsUndeclaredUnixListener(t *testing.T) {
	listeners := []unixListener{{Path: "/tmp/undeclared.sock", Inode: 303, Type: unix.SOCK_STREAM}}
	owners := map[string][]uint64{unixOwnerApplication: {303}}
	if _, err := verifyUnixListeners(listeners, nil, owners, []string{unixOwnerApplication}); err == nil {
		t.Fatal("TCP application owner accepted an undeclared Unix listener")
	} else {
		var violation *RuntimeViolation
		if !errors.As(err, &violation) || violation.Kind != RuntimeViolationExtraListener {
			t.Fatalf("undeclared Unix listener was not typed: %v", err)
		}
	}
	if _, err := verifyUnixListeners(listeners, nil, map[string][]uint64{unixOwnerApplication: {404}}, []string{unixOwnerApplication}); err != nil {
		t.Fatalf("unowned Unix listener affected exact application inventory: %v", err)
	}
}

func TestUnixSocketActivationRejectsClosedInheritedFDAndStaleNode(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "lanpanel-unix-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(directory) }()
	path := filepath.Join(directory, "endpoint.sock")
	address := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	inherited, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestUnixSocketFDHolder$")
	command.Env = append(os.Environ(), "LANPANEL_TEST_UNIX_FD_HOLDER=1")
	command.Stdin = stdinRead
	command.Stdout = io.Discard
	command.Stderr = os.Stderr
	command.ExtraFiles = []*os.File{inherited, readyWrite}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = inherited.Close()
	_ = readyWrite.Close()
	_ = stdinRead.Close()
	childRunning := true
	defer func() {
		_ = stdinWrite.Close()
		_ = readyRead.Close()
		if childRunning {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready := []byte{0}
	if _, err := io.ReadFull(readyRead, ready); err != nil || ready[0] != 1 {
		t.Fatalf("socket FD holder readiness=%v err=%v", ready, err)
	}

	listeners, err := readUnixListeners("/proc/net/unix")
	if err != nil {
		t.Fatal(err)
	}
	parentInodes, err := cgroupSocketInodes([]int{os.Getpid()})
	if err != nil {
		t.Fatal(err)
	}
	childInodes, err := cgroupSocketInodes([]int{command.Process.Pid})
	if err != nil {
		t.Fatal(err)
	}
	expected := []unixEndpointExpectation{{Role: "frontend", Path: path, Owners: []string{unixOwnerPID1, unixOwnerApplication}}}
	if _, err := verifyUnixListeners(listeners, expected, map[string][]uint64{unixOwnerPID1: parentInodes, unixOwnerApplication: childInodes}, []string{unixOwnerApplication}); err != nil {
		t.Fatalf("complete socket-activation ownership rejected: %v", err)
	}

	if _, err := stdinWrite.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(readyRead, ready); err != nil || ready[0] != 2 {
		t.Fatalf("socket FD close readiness=%v err=%v", ready, err)
	}
	closedChildInodes, err := cgroupSocketInodes([]int{command.Process.Pid})
	if err != nil {
		t.Fatal(err)
	}
	if err := requireSocket(path); err != nil {
		t.Fatalf("socket node disappeared with application FD: %v", err)
	}
	if _, err := verifyUnixListeners(listeners, expected, map[string][]uint64{unixOwnerPID1: parentInodes, unixOwnerApplication: closedChildInodes}, []string{unixOwnerApplication}); err == nil {
		t.Fatal("closed application socket FD accepted while PID1 listener remained")
	}
	if err := stdinWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	childRunning = false

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := requireSocket(path); err != nil {
		t.Fatalf("stale Unix socket node unavailable: %v", err)
	}
	listeners, err = readUnixListeners("/proc/net/unix")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyUnixListeners(listeners, expected, map[string][]uint64{unixOwnerPID1: parentInodes, unixOwnerApplication: closedChildInodes}, []string{unixOwnerApplication}); err == nil {
		t.Fatal("Unix socket node without listening inode accepted")
	}
}

func TestUnixSocketFDHolder(t *testing.T) {
	if os.Getenv("LANPANEL_TEST_UNIX_FD_HOLDER") != "1" {
		return
	}
	inherited := os.NewFile(3, "inherited-unix-listener")
	ready := os.NewFile(4, "ready")
	if inherited == nil || ready == nil {
		t.Fatal("inherited descriptors missing")
	}
	defer func() {
		_ = inherited.Close()
		_ = ready.Close()
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(int(inherited.Fd()), &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		t.Fatalf("inherited descriptor is not a Unix socket: %v", err)
	}
	if _, err := ready.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	control := []byte{0}
	if _, err := io.ReadFull(os.Stdin, control); err != nil {
		t.Fatal(err)
	}
	if err := inherited.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ready.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

const unixProcHeader = "Num       RefCount Protocol Flags    Type St Inode Path\n"

func procUnixRow(flags, socketType, state string, inode uint64, path string) string {
	return fmt.Sprintf("0000000000000001: 00000002 00000000 %s %s %s %d %s", flags, socketType, state, inode, path)
}

func writeUnixProcFixture(t *testing.T, path string, rows ...string) {
	t.Helper()
	data := unixProcHeader + strings.Join(rows, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
