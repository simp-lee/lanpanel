//go:build linux

package preflight

import (
	"context"
	"fmt"
	cgroupfs "lanpanel/internal/cgroup"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// activeDelegationProbe asks PID 1 to create a disposable delegated scope and
// runs the same cgroup lifecycle that LanPanel uses for package and helper
// children. A read-only Delegate=yes unit-file check is not sufficient: the
// kernel must accept cgroup.procs writes and cgroup.kill in the effective scope.
func activeDelegationProbe(ctx context.Context) ComponentObservation {
	if ctx == nil {
		ctx = context.Background()
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return ComponentObservation{Identity: "delegation probe executable is unavailable"}
	}
	unit := "lanpanel-delegation-probe-" + strconv.Itoa(os.Getpid())
	command := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--unit="+unit, "--property=Delegate=yes", executable, "delegation-probe-child")
	output, err := command.CombinedOutput()
	if err != nil {
		identity := strings.TrimSpace(string(output))
		if identity == "" {
			identity = err.Error()
		}
		return ComponentObservation{Identity: "systemd delegation probe failed: " + identity}
	}
	return ComponentObservation{Available: true, Identity: "systemd delegated scope probe passed"}
}

// RunDelegationProbeChild is the executable role launched inside a temporary
// Delegate=yes scope. It is intentionally narrow and leaves no cgroup behind.
func RunDelegationProbeChild() error {
	topology, err := cgroupfs.Discover()
	if err != nil {
		return err
	}
	if topology.Root != "/" {
		return fmt.Errorf("delegation probe requires a unified cgroup v2 hierarchy rooted at /")
	}
	name := fmt.Sprintf("lanpanel-probe-%d", os.Getpid())
	path := filepath.Join(topology.Current, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create delegated probe cgroup: %w", err)
	}
	cleanup := func(cause error) error {
		return fmt.Errorf("%w (cleanup: %v)", cause, os.Remove(path))
	}
	for _, file := range []string{"cgroup.kill", "cgroup.procs", "cgroup.events"} {
		info, statErr := os.Stat(filepath.Join(path, file))
		if statErr != nil || !info.Mode().IsRegular() {
			return cleanup(fmt.Errorf("delegated probe control %s is unavailable", file))
		}
	}
	child := exec.Command("/bin/sleep", "60")
	if err := child.Start(); err != nil {
		return cleanup(fmt.Errorf("start delegated probe child: %w", err))
	}
	childPID := child.Process.Pid
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(childPID)), 0o600); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		return cleanup(fmt.Errorf("write delegated probe cgroup.procs: %w", err))
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o600); err != nil && err != syscall.ESRCH {
		_ = child.Process.Kill()
		_ = child.Wait()
		return cleanup(fmt.Errorf("write delegated probe cgroup.kill: %w", err))
	}
	_ = child.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(filepath.Join(path, "cgroup.events"))
		if readErr == nil && strings.Contains(string(data), "populated 0") {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove delegated probe cgroup: %w", err)
			}
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cleanup(fmt.Errorf("delegated probe cgroup did not become empty"))
}
