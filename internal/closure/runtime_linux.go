//go:build linux

package closure

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const MaximumRuntimeProcesses = 1024

type ProcessIdentity struct {
	PID        int    `json:"pid"`
	ParentPID  int    `json:"parent_pid"`
	StartTicks uint64 `json:"start_ticks"`
	Executable string `json:"executable"`
	Arguments  string `json:"arguments"`
	Cgroup     string `json:"cgroup"`
	State      string `json:"state"`
}

type ListenerIdentity struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Inode    uint64 `json:"inode"`
}

type RuntimeSnapshot struct {
	ObservedAt time.Time          `json:"observed_at"`
	Master     *ProcessIdentity   `json:"master,omitempty"`
	Workers    []ProcessIdentity  `json:"workers"`
	Listeners  []ListenerIdentity `json:"listeners"`
	Complete   bool               `json:"complete"`
	Generation string             `json:"generation,omitempty"`
}

type RuntimeObserver interface {
	Observe(context.Context) (RuntimeSnapshot, error)
}

type ProcObserver struct {
	ProcRoot       string
	UnitCgroup     string
	Executable     string
	ExpectedArgv   string
	ControlPID     int
	PIDPath        string
	Generation     string
	OwnedListeners []string
	Now            func() time.Time
}

func (observer ProcObserver) Observe(ctx context.Context) (RuntimeSnapshot, error) {
	if observer.ProcRoot == "" {
		observer.ProcRoot = "/proc"
	}
	if observer.Now == nil {
		observer.Now = func() time.Time { return time.Now().UTC() }
	}
	if !filepath.IsAbs(observer.ProcRoot) || filepath.Clean(observer.ProcRoot) != observer.ProcRoot || observer.UnitCgroup == "" || observer.Executable == "" || observer.ExpectedArgv == "" || observer.Generation == "" || observer.PIDPath == "" || !filepath.IsAbs(observer.PIDPath) {
		return RuntimeSnapshot{}, fmt.Errorf("runtime observer authority is incomplete")
	}
	entries, err := os.ReadDir(observer.ProcRoot)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	processes := []ProcessIdentity{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return RuntimeSnapshot{}, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		identity, err := observeProcess(observer.ProcRoot, pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return RuntimeSnapshot{}, err
		}
		if identity.Executable == observer.Executable && identity.Cgroup != observer.UnitCgroup {
			return RuntimeSnapshot{}, fmt.Errorf("nginx executable exists outside its fixed unit cgroup")
		}
		if identity.Cgroup == observer.UnitCgroup {
			processes = append(processes, identity)
			if len(processes) > MaximumRuntimeProcesses {
				return RuntimeSnapshot{}, fmt.Errorf("runtime process inventory exceeds bound")
			}
		}
	}
	slices.SortFunc(processes, func(left, right ProcessIdentity) int { return left.PID - right.PID })
	masterPID, err := readMasterPID(observer.PIDPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return RuntimeSnapshot{}, err
	}
	snapshot := RuntimeSnapshot{ObservedAt: observer.Now().UTC(), Workers: []ProcessIdentity{}, Listeners: []ListenerIdentity{}, Complete: true, Generation: observer.Generation}
	for _, process := range processes {
		if observer.ControlPID != 0 && process.PID == observer.ControlPID {
			continue
		}
		if process.PID == masterPID && process.Executable == observer.Executable && process.ParentPID == 1 && validMasterArguments(process.Arguments, observer.ExpectedArgv) {
			if snapshot.Master != nil {
				return RuntimeSnapshot{}, fmt.Errorf("multiple exact Nginx masters in unit cgroup")
			}
			copy := process
			snapshot.Master = &copy
			continue
		}
		if process.Executable != observer.Executable || process.ParentPID != masterPID || process.Arguments != "nginx: worker process" {
			return RuntimeSnapshot{}, fmt.Errorf("unknown process exists in exact Nginx unit cgroup")
		}
		snapshot.Workers = append(snapshot.Workers, process)
	}
	listeners, err := observeProcListeners(observer.ProcRoot)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	ownedInodes, err := processSocketInodes(observer.ProcRoot, processes)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	owned := map[string]bool{}
	for _, value := range observer.OwnedListeners {
		owned[value] = true
	}
	for _, listener := range listeners {
		key := fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port)
		if owned[key] {
			if !ownedInodes[listener.Inode] {
				return RuntimeSnapshot{}, fmt.Errorf("owned endpoint listener inode is outside the exact Nginx process generation")
			}
			snapshot.Listeners = append(snapshot.Listeners, listener)
		}
	}
	return snapshot, nil
}

func WaitPriorWorkers(ctx context.Context, observer RuntimeObserver, prior []ProcessIdentity, timeout time.Duration) (RuntimeSnapshot, error) {
	if observer == nil || timeout <= 0 || timeout > time.Minute || len(prior) > MaximumRuntimeProcesses {
		return RuntimeSnapshot{}, fmt.Errorf("prior-worker drain authority is invalid")
	}
	deadline := time.Now().Add(timeout)
	for {
		snapshot, err := observer.Observe(ctx)
		if err != nil {
			return RuntimeSnapshot{}, err
		}
		live := map[string]bool{}
		for _, worker := range snapshot.Workers {
			live[processKey(worker)] = true
		}
		remaining := false
		for _, process := range prior {
			if live[processKey(process)] {
				remaining = true
				break
			}
		}
		if !remaining {
			return snapshot, nil
		}
		if !time.Now().Before(deadline) {
			return snapshot, fmt.Errorf("prior Nginx worker generation did not drain")
		}
		select {
		case <-ctx.Done():
			return snapshot, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func VerifyStopped(snapshot RuntimeSnapshot) error {
	if !snapshot.Complete || snapshot.Master != nil || len(snapshot.Workers) != 0 || len(snapshot.Listeners) != 0 || snapshot.ObservedAt.IsZero() || snapshot.Generation == "" {
		return fmt.Errorf("nginx master, workers, or owned listeners may remain")
	}
	return nil
}

func processKey(process ProcessIdentity) string {
	return fmt.Sprintf("%d:%d:%s", process.PID, process.StartTicks, process.Cgroup)
}

func observeProcess(procRoot string, pid int) (ProcessIdentity, error) {
	root := filepath.Join(procRoot, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	parent, state, start, err := parseProcessStat(stat)
	if err != nil {
		return ProcessIdentity{}, err
	}
	executable, err := os.Readlink(filepath.Join(root, "exe"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	commands, err := os.ReadFile(filepath.Join(root, "cmdline"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	arguments := strings.Join(bytesToArgv(commands), "\x00")
	cgroups, err := os.ReadFile(filepath.Join(root, "cgroup"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	cgroup := ""
	for _, line := range strings.Split(strings.TrimSpace(string(cgroups)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			cgroup = parts[2]
		}
	}
	if cgroup == "" {
		return ProcessIdentity{}, fmt.Errorf("process lacks exact unified cgroup")
	}
	return ProcessIdentity{PID: pid, ParentPID: parent, StartTicks: start, Executable: executable, Arguments: arguments, Cgroup: cgroup, State: state}, nil
}

func parseProcessStat(payload []byte) (int, string, uint64, error) {
	closing := bytes.LastIndexByte(payload, ')')
	if closing < 0 || closing+1 >= len(payload) {
		return 0, "", 0, fmt.Errorf("process stat is malformed")
	}
	fields := strings.Fields(string(payload[closing+1:]))
	// fields begin with state; Linux stat field 22 (starttime) is index 19 here.
	if len(fields) < 20 || len(fields[0]) != 1 {
		return 0, "", 0, fmt.Errorf("process stat is incomplete")
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent < 0 {
		return 0, "", 0, fmt.Errorf("process parent is invalid")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, "", 0, fmt.Errorf("process start identity is invalid")
	}
	return parent, fields[0], start, nil
}

func bytesToArgv(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	payload = bytes.TrimRight(payload, "\x00")
	if len(payload) == 0 {
		return nil
	}
	parts := bytes.Split(payload, []byte{0})
	values := make([]string, len(parts))
	for index, part := range parts {
		values[index] = string(part)
	}
	return values
}

func validMasterArguments(actual, expected string) bool {
	if actual == expected {
		return true
	}
	return actual == "nginx: master process "+strings.ReplaceAll(expected, "\x00", " ")
}

func readMasterPID(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), "nginx-pid")
	if file == nil {
		_ = unix.Close(fd)
		return 0, fmt.Errorf("wrap Nginx PID descriptor")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 32 {
		return 0, fmt.Errorf("nginx PID file identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("nginx PID file is malformed")
	}
	return pid, nil
}

func processSocketInodes(procRoot string, processes []ProcessIdentity) (map[uint64]bool, error) {
	result := map[uint64]bool{}
	for _, process := range processes {
		entries, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(process.PID), "fd"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(process.PID), "fd", entry.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
				if err != nil || inode == 0 {
					return nil, fmt.Errorf("process socket inode is malformed")
				}
				result[inode] = true
			}
		}
	}
	return result, nil
}

func observeProcListeners(procRoot string) ([]ListenerIdentity, error) {
	result := []ListenerIdentity{}
	for _, source := range []struct {
		name, protocol string
		ipv6           bool
	}{{"net/tcp", "tcp", false}, {"net/tcp6", "tcp", true}} {
		data, err := os.ReadFile(filepath.Join(procRoot, source.name))
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		if !scanner.Scan() {
			return nil, fmt.Errorf("listener header missing")
		}
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				return nil, fmt.Errorf("listener row malformed")
			}
			if fields[3] != "0A" {
				continue
			}
			addressText, portText, found := strings.Cut(fields[1], ":")
			if !found {
				return nil, fmt.Errorf("listener address malformed")
			}
			address, err := parseProcAddress(addressText, source.ipv6)
			port, portErr := strconv.ParseUint(portText, 16, 16)
			inode, inodeErr := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || portErr != nil || inodeErr != nil || port == 0 || inode == 0 {
				return nil, fmt.Errorf("listener identity invalid")
			}
			result = append(result, ListenerIdentity{Protocol: source.protocol, Address: address, Port: uint16(port), Inode: inode})
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(result, func(left, right ListenerIdentity) int {
		return strings.Compare(fmt.Sprintf("%s:%s:%05d:%020d", left.Protocol, left.Address, left.Port, left.Inode), fmt.Sprintf("%s:%s:%05d:%020d", right.Protocol, right.Address, right.Port, right.Inode))
	})
	return result, nil
}

func parseProcAddress(value string, ipv6 bool) (string, error) {
	length := 8
	if ipv6 {
		length = 32
	}
	if len(value) != length {
		return "", fmt.Errorf("proc address length invalid")
	}
	decoded := make([]byte, length/2)
	for word := 0; word < len(decoded)/4; word++ {
		for offset := 0; offset < 4; offset++ {
			parsed, err := strconv.ParseUint(value[word*8+(3-offset)*2:word*8+(4-offset)*2], 16, 8)
			if err != nil {
				return "", err
			}
			decoded[word*4+offset] = byte(parsed)
		}
	}
	address, ok := netip.AddrFromSlice(decoded)
	if !ok {
		return "", fmt.Errorf("proc address invalid")
	}
	return address.String(), nil
}

var _ = unix.AF_INET
