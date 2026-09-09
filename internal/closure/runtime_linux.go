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
	nginxProcesses := append([]ProcessIdentity(nil), snapshot.Workers...)
	if snapshot.Master != nil {
		nginxProcesses = append(nginxProcesses, *snapshot.Master)
	}
	ownedInodes, err := processSocketInodes(observer.ProcRoot, nginxProcesses)
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

func VerifyServing(snapshot RuntimeSnapshot, generation string, expectedListeners []string) error {
	if !snapshot.Complete || snapshot.Master == nil || len(snapshot.Workers) == 0 || snapshot.ObservedAt.IsZero() || generation == "" || snapshot.Generation != generation {
		return fmt.Errorf("nginx serving process evidence is incomplete")
	}
	if len(expectedListeners) == 0 {
		return fmt.Errorf("nginx expected listener authority is incomplete")
	}
	observed := make(map[string]bool, len(snapshot.Listeners))
	for _, listener := range snapshot.Listeners {
		observed[fmt.Sprintf("%s:%s:%d", listener.Protocol, listener.Address, listener.Port)] = true
	}
	for _, listener := range expectedListeners {
		if !observed[listener] {
			return fmt.Errorf("nginx expected listener evidence is incomplete")
		}
	}
	return nil
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

type FileIdentity struct {
	Device uint64
	Inode  uint64
}

// WaitFileReopen waits until the exact runtime has switched away from a
// renamed file. Two complete observations with no old write descriptor close
// the process-inventory race around a worker exit or respawn.
func WaitFileReopen(ctx context.Context, observer RuntimeObserver, procRoot, activePath string, priorMaster ProcessIdentity, old, active FileIdentity, timeout time.Duration, retrySignal func(context.Context) error) error {
	if observer == nil || !filepath.IsAbs(procRoot) || filepath.Clean(procRoot) != procRoot || !filepath.IsAbs(activePath) || filepath.Clean(activePath) != activePath || priorMaster.PID <= 1 || priorMaster.StartTicks == 0 || priorMaster.Cgroup == "" || old.Device == 0 || old.Inode == 0 || active.Device == 0 || active.Inode == 0 || old == active || timeout <= 0 || timeout > time.Minute {
		return fmt.Errorf("file reopen authority is invalid")
	}
	deadline := time.Now().Add(timeout)
	nextRetry := time.Now().Add(100 * time.Millisecond)
	retries := 0
	clearObservations := 0
	for {
		var stat unix.Stat_t
		if err := unix.Lstat(activePath, &stat); err != nil {
			return fmt.Errorf("replacement file identity unavailable: %w", err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || uint64(stat.Dev) != active.Device || stat.Ino != active.Inode {
			return fmt.Errorf("replacement file identity changed")
		}
		snapshot, err := observer.Observe(ctx)
		if err != nil {
			return err
		}
		if snapshot.Master == nil {
			if err := VerifyStopped(snapshot); err != nil {
				return err
			}
			return nil
		}
		if !snapshot.Complete {
			return fmt.Errorf("file reopen runtime inventory is incomplete")
		}
		if processKey(*snapshot.Master) != processKey(priorMaster) {
			return fmt.Errorf("file reopen Nginx master identity changed")
		}
		processes := make([]ProcessIdentity, 0, len(snapshot.Workers)+1)
		processes = append(processes, *snapshot.Master)
		processes = append(processes, snapshot.Workers...)
		writers, err := WritableFileReferences(procRoot, processes, old.Device, old.Inode)
		if err != nil {
			return err
		}
		activeMaster, err := WritableFileReferences(procRoot, []ProcessIdentity{*snapshot.Master}, active.Device, active.Inode)
		if err != nil {
			return err
		}
		if len(writers) == 0 && len(activeMaster) == 1 {
			clearObservations++
			if clearObservations == 2 {
				return nil
			}
		} else {
			clearObservations = 0
		}
		now := time.Now()
		if len(writers) != 0 && retrySignal != nil && retries < 2 && !now.Before(nextRetry) {
			if err = retrySignal(ctx); err != nil {
				return err
			}
			retries++
			now = time.Now()
			nextRetry = now.Add(100 * time.Millisecond)
		}
		if !now.Before(deadline) {
			return fmt.Errorf("runtime did not release the renamed file before the fixed deadline")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// WritableFileReferences returns the exact process identities that still hold a
// write-capable descriptor for one inode. Each process is rebound to its PID
// start time before and after inspection so PID reuse cannot create false
// reopen completion evidence.
func WritableFileReferences(procRoot string, processes []ProcessIdentity, device, inode uint64) ([]ProcessIdentity, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if !filepath.IsAbs(procRoot) || filepath.Clean(procRoot) != procRoot || device == 0 || inode == 0 || len(processes) > MaximumRuntimeProcesses {
		return nil, fmt.Errorf("writable file reference authority is invalid")
	}
	result := []ProcessIdentity{}
	entriesSeen := 0
	for _, process := range processes {
		before, err := observeProcess(procRoot, process.PID)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if processKey(before) != processKey(process) {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(process.PID), "fd"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		entriesSeen += len(entries)
		if entriesSeen > 131072 {
			return nil, fmt.Errorf("writable file descriptor inventory exceeds bound")
		}
		matched := false
		for _, entry := range entries {
			fdPath := filepath.Join(procRoot, strconv.Itoa(process.PID), "fd", entry.Name())
			var stat unix.Stat_t
			if err := unix.Stat(fdPath, &stat); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				return nil, err
			}
			if uint64(stat.Dev) != device || stat.Ino != inode {
				continue
			}
			flags, err := descriptorFlags(filepath.Join(procRoot, strconv.Itoa(process.PID), "fdinfo", entry.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if flags&unix.O_ACCMODE == unix.O_WRONLY || flags&unix.O_ACCMODE == unix.O_RDWR {
				matched = true
				break
			}
		}
		after, err := observeProcess(procRoot, process.PID)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if processKey(after) != processKey(process) {
			continue
		}
		if matched {
			result = append(result, process)
		}
	}
	return result, nil
}

func descriptorFlags(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || key != "flags" {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimSpace(value), 8, 32)
		if err != nil {
			return 0, fmt.Errorf("process descriptor flags are malformed")
		}
		return int(flags), nil
	}
	return 0, fmt.Errorf("process descriptor flags are missing")
}

func processSocketInodes(procRoot string, processes []ProcessIdentity) (map[uint64]bool, error) {
	result := map[uint64]bool{}
	for _, process := range processes {
		before, err := observeProcess(procRoot, process.PID)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !sameSocketOwnerProcess(before, process) {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(process.PID), "fd"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		observed := map[uint64]bool{}
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
				observed[inode] = true
			}
		}
		after, err := observeProcess(procRoot, process.PID)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !sameSocketOwnerProcess(after, process) {
			continue
		}
		for inode := range observed {
			result[inode] = true
		}
	}
	return result, nil
}

func sameSocketOwnerProcess(left, right ProcessIdentity) bool {
	return processKey(left) == processKey(right) && left.ParentPID == right.ParentPID && left.Executable == right.Executable && left.Arguments == right.Arguments
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
