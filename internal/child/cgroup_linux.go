//go:build linux

package child

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type CgroupClosureError struct{ Cause error }

func (value *CgroupClosureError) Error() string {
	return "lego cgroup closure unproved: " + value.Cause.Error()
}
func (value *CgroupClosureError) Unwrap() error { return value.Cause }
func CgroupClosureUnproved(err error) bool {
	var value *CgroupClosureError
	return errors.As(err, &value)
}

type invocationCgroup struct{ path string }

func currentUnifiedCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	path := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::/") || line == "0::/" {
			if path != "" {
				return "", fmt.Errorf("helper cgroup identity duplicated")
			}
			path = strings.TrimPrefix(line, "0::")
		}
	}
	if path == "" || filepath.Clean(path) != path || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return "", fmt.Errorf("helper requires unified cgroup identity")
	}
	return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(path, "/")), nil
}
func createInvocationCgroup(certificateID string, pid int) (*invocationCgroup, error) {
	if !strings.HasPrefix(certificateID, "cert_") || len(certificateID) != 37 || pid <= 0 {
		return nil, fmt.Errorf("lego cgroup identity invalid")
	}
	parent, err := currentUnifiedCgroupPath()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(parent, "lanpanel-lego-"+certificateID)
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	cleanup := func(cause error) (*invocationCgroup, error) {
		removeErr := os.Remove(path)
		return nil, errors.Join(cause, removeErr)
	}
	processes, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil || len(strings.Fields(string(processes))) != 0 {
		return cleanup(fmt.Errorf("lego cgroup is not empty: %w", err))
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return cleanup(err)
	}
	return &invocationCgroup{path: path}, nil
}
func (group *invocationCgroup) KillAndRemove() error {
	if group == nil || group.path == "" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(group.path, "cgroup.kill"), []byte("1"), 0o600); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := os.ReadFile(filepath.Join(group.path, "cgroup.events"))
		if err != nil {
			return err
		}
		populated := ""
		fields := strings.Fields(string(events))
		for index := 0; index+1 < len(fields); index += 2 {
			if fields[index] == "populated" {
				populated = fields[index+1]
			}
		}
		if populated == "0" {
			break
		}
		if populated != "1" || !time.Now().Before(deadline) {
			return fmt.Errorf("lego cgroup closure unproved")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Remove(group.path); err != nil {
		return err
	}
	group.path = ""
	return nil
}
func closeStaleInvocationCgroups(parent string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "lanpanel-lego-cert_") {
			continue
		}
		if !entry.IsDir() || strings.Contains(entry.Name(), "/") {
			return fmt.Errorf("owned lego cgroup identity unsafe")
		}
		group := &invocationCgroup{path: filepath.Join(parent, entry.Name())}
		if err := group.KillAndRemove(); err != nil {
			return err
		}
	}
	return nil
}
func ObserveExclusiveCurrentCgroup() (string, error) {
	parent, err := currentUnifiedCgroupPath()
	if err != nil {
		return "", err
	}
	if err := closeStaleInvocationCgroups(parent); err != nil {
		return "", err
	}
	processes, err := os.ReadFile(filepath.Join(parent, "cgroup.procs"))
	if err != nil {
		return "", err
	}
	current := os.Getpid()
	seen := false
	for _, field := range strings.Fields(string(processes)) {
		pid, parseErr := strconv.Atoi(field)
		if parseErr != nil || pid <= 0 {
			return "", fmt.Errorf("helper cgroup process inventory invalid")
		}
		if pid != current {
			return "", fmt.Errorf("helper cgroup retains process %d", pid)
		}
		if seen {
			return "", fmt.Errorf("helper cgroup process inventory duplicated")
		}
		seen = true
	}
	if !seen {
		return "", fmt.Errorf("helper cgroup omits current process")
	}
	path := strings.TrimPrefix(parent, "/sys/fs/cgroup")
	if path == "" {
		path = "/"
	}
	sum := sha256.Sum256([]byte(path + "\x00" + strconv.Itoa(current)))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
