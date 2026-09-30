//go:build linux

package preflight

import (
	"context"
	"crypto/rand"
	"errors"
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
// children. It deliberately avoids systemd-run --wait/--collect so the probe
// remains usable with older systemd versions that support Delegate=yes.
func activeDelegationProbe(ctx context.Context) ComponentObservation {
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return ComponentObservation{Identity: "delegation probe executable is unavailable"}
	}
	unit := delegationProbeUnitName()
	systemdRun := exec.CommandContext(probeCtx, "/usr/bin/systemd-run", "--quiet", "--unit="+unit, "--property=Delegate=yes", executable, "delegation-probe-child")
	output, err := systemdRun.CombinedOutput()
	if err != nil {
		stopTransientUnit(unit)
		identity := strings.TrimSpace(string(output))
		if identity == "" {
			identity = err.Error()
		}
		return ComponentObservation{Identity: "systemd delegation probe failed: " + identity}
	}
	defer stopTransientUnit(unit)
	for {
		if err := probeCtx.Err(); err != nil {
			return ComponentObservation{Identity: "systemd delegation probe cancelled"}
		}
		state, status, showErr := transientUnitState(probeCtx, unit)
		if showErr != nil {
			return ComponentObservation{Identity: "systemd delegation probe observation failed: " + showErr.Error()}
		}
		if state == "inactive" || state == "failed" {
			if status != "0" {
				return ComponentObservation{Identity: "systemd delegation probe child failed with status " + status}
			}
			return ComponentObservation{Available: true, Identity: "systemd delegated scope probe passed"}
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func delegationProbeUnitName() string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err == nil {
		return fmt.Sprintf("lanpanel-delegation-probe-%d-%x", os.Getpid(), random[:])
	}
	return fmt.Sprintf("lanpanel-delegation-probe-%d-%d", os.Getpid(), time.Now().UnixNano())
}

func transientUnitState(ctx context.Context, unit string) (string, string, error) {
	data, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--property=ExecMainStatus").Output()
	if err != nil {
		return "", "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	state, stateOK := values["ActiveState"]
	status, statusOK := values["ExecMainStatus"]
	if !stateOK || !statusOK || state == "" || status == "" {
		return "", "", fmt.Errorf("transient unit state is malformed")
	}
	return state, status, nil
}

func stopTransientUnit(unit string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", unit).Run()
	_ = exec.CommandContext(ctx, "/usr/bin/systemctl", "reset-failed", unit).Run()
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
	var child *exec.Cmd
	childDone := true
	cleanup := func(cause error) error {
		if child != nil && !childDone {
			_ = child.Process.Kill()
			_ = child.Wait()
			childDone = true
		}
		return fmt.Errorf("%w (cleanup: %v)", cause, os.Remove(path))
	}
	for _, file := range []string{"cgroup.kill", "cgroup.procs", "cgroup.events"} {
		info, statErr := os.Stat(filepath.Join(path, file))
		if statErr != nil || !info.Mode().IsRegular() {
			return cleanup(fmt.Errorf("delegated probe control %s is unavailable", file))
		}
	}
	child = exec.Command("/bin/sleep", "60")
	if err := child.Start(); err != nil {
		return cleanup(fmt.Errorf("start delegated probe child: %w", err))
	}
	childDone = false
	defer func() {
		if !childDone {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	childPID := child.Process.Pid
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(childPID)), 0o600); err != nil {
		return cleanup(fmt.Errorf("write delegated probe cgroup.procs: %w", err))
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o600); err != nil && !errors.Is(err, syscall.ESRCH) {
		return cleanup(fmt.Errorf("write delegated probe cgroup.kill: %w", err))
	}
	_ = child.Wait()
	childDone = true
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
