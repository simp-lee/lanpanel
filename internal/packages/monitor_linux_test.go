//go:build linux

package packages

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newMonitorFixture(t *testing.T, initialUnits ...string) (string, string) {
	t.Helper()
	root := t.TempDir()
	cgroups := filepath.Join(root, "cgroups")
	proc := filepath.Join(root, "proc")
	if err := os.MkdirAll(cgroups, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proc, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range initialUnits {
		if err := os.MkdirAll(filepath.Join(cgroups, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cgroups, name, "cgroup.procs"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := os.WriteFile(filepath.Join(proc, name), []byte("  sl  local_address rem_address st\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cgroups, proc
}

func TestLinuxMonitorAllowsTransientInactiveUnmanagedUnitCgroup(t *testing.T) {
	cgroups, proc := newMonitorFixture(t, "nginx.service", "cron.service")
	monitor := newTestLinuxMonitor(cgroups, proc, time.Millisecond)
	_, stop, err := monitor.Start(context.Background(), []string{"nginx.service"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgroups, "ufw.service"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroups, "ufw.service", "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatalf("transient inactive unit cgroup was rejected: %v", err)
	}
}

func TestLinuxMonitorCancelsOnTransientActiveUnmanagedUnitCgroup(t *testing.T) {
	cgroups, proc := newMonitorFixture(t, "nginx.service", "cron.service")
	monitor := newTestLinuxMonitor(cgroups, proc, time.Millisecond)
	monitored, stop, err := monitor.Start(context.Background(), []string{"nginx.service"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgroups, "ufw.service"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroups, "ufw.service", "cgroup.procs"), []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-monitored.Done():
	case <-time.After(time.Second):
		t.Fatal("active unmanaged unit cgroup did not cancel package child context")
	}
	if err := stop(); err == nil {
		t.Fatal("active unmanaged unit cgroup was accepted")
	}
}
