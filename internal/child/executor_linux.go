//go:build linux

package child

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const bootstrapSchema = "lanpanel.child.bootstrap.v1"
const maximumBootstrapBytes = 32 << 10
const FixedLanPanelExecutable = "/usr/lib/lanpanel/lanpanel"

var errOutputLimit = errors.New("external child output limit reached")

type Launcher struct {
	self       string
	identities Identities
}

type Result struct {
	ExitCode       int
	StdoutDigest   string
	Stdout         []byte
	StderrDigest   string
	OutputCutOff   bool
	PackageChanges []PackageChange
}

type bootstrapInstruction struct {
	SchemaVersion string     `json:"schema_version"`
	ProfileID     ProfileID  `json:"profile_id"`
	Identities    Identities `json:"identities"`
	Invocation    Invocation `json:"invocation"`
	HasInput      bool       `json:"has_input"`
}

func NewLauncher(selfExecutable string, identities Identities) (*Launcher, error) {
	if selfExecutable != FixedLanPanelExecutable || !filepath.IsAbs(selfExecutable) || filepath.Clean(selfExecutable) != selfExecutable {
		return nil, fmt.Errorf("child launcher requires the fixed absolute LanPanel executable")
	}
	return &Launcher{self: selfExecutable, identities: identities}, nil
}

func (launcher *Launcher) Run(ctx context.Context, profileID ProfileID, input []byte) (Result, error) {
	return launcher.RunInvocation(ctx, profileID, Invocation{}, input)
}

func (launcher *Launcher) RunInvocation(ctx context.Context, profileID ProfileID, invocation Invocation, input []byte) (Result, error) {
	if launcher == nil || os.Geteuid() != 0 {
		return Result{}, fmt.Errorf("external child launch requires the root helper")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	profile, err := ResolveInvocation(profileID, launcher.identities, invocation)
	if err != nil {
		return Result{}, err
	}
	if !profile.Complete {
		return Result{}, fmt.Errorf("external child profile is unavailable until its complete confinement is qualified")
	}
	if profile.PersistentDaemon {
		return Result{}, fmt.Errorf("persistent daemon profile requires direct PID1 supervision")
	}
	if len(input) > profile.MaximumInputBytes || profile.MaximumInputBytes == 0 && len(input) != 0 {
		return Result{}, fmt.Errorf("external child input exceeds its fixed profile")
	}
	if err := verifyRootExecutable(launcher.self); err != nil {
		return Result{}, fmt.Errorf("LanPanel child bootstrap executable: %w", err)
	}
	if err := verifyRootExecutable(profile.Executable); err != nil {
		return Result{}, fmt.Errorf("external child executable: %w", err)
	}
	if profile.ExecutableDigest != "" {
		digest, err := executableDigest(profile.Executable)
		if err != nil || digest != profile.ExecutableDigest {
			return Result{}, fmt.Errorf("external child executable digest mismatched")
		}
	}
	instruction := bootstrapInstruction{SchemaVersion: bootstrapSchema, ProfileID: profileID, Identities: launcher.identities, Invocation: invocation, HasInput: len(input) != 0}
	instructionBytes, err := json.Marshal(instruction)
	if err != nil || len(instructionBytes) > maximumBootstrapBytes {
		return Result{}, fmt.Errorf("encode child bootstrap instruction")
	}
	instructionRead, instructionWrite, err := os.Pipe()
	if err != nil {
		return Result{}, err
	}
	defer instructionRead.Close()
	defer instructionWrite.Close()
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		return Result{}, err
	}
	defer inputRead.Close()
	defer inputWrite.Close()
	command := exec.Command(launcher.self, "child-executor")
	command.Env = []string{}
	command.ExtraFiles = []*os.File{instructionRead, inputRead}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	stdout := newDigestWriter(profile.MaximumOutputBytes, profileID == ProfileAPTSimulate || profileID == ProfileResourceShow)
	stderr := newDigestWriter(profile.MaximumOutputBytes)
	command.Stdout, command.Stderr = stdout, stderr
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := command.Start(); err != nil {
		return Result{}, err
	}
	var legoGroup *invocationCgroup
	if profileID == ProfileLego {
		if invocation.Lego == nil {
			return Result{}, fmt.Errorf("lego cgroup invocation missing")
		}
		legoGroup, err = createInvocationCgroup(invocation.Lego.CertificateID, command.Process.Pid)
		if err != nil {
			terminateErr := terminateProcessGroupBeforeReap(command.Process.Pid)
			waitErr := command.Wait()
			return Result{}, errors.Join(err, terminateErr, waitErr)
		}
	}
	_ = instructionRead.Close()
	_ = inputRead.Close()
	writeDone := make(chan error, 1)
	go func() {
		instructionErr := writePipeFull(instructionWrite, instructionBytes)
		instructionCloseErr := instructionWrite.Close()
		inputErr := writePipeFull(inputWrite, input)
		inputCloseErr := inputWrite.Close()
		writeDone <- errors.Join(instructionErr, instructionCloseErr, inputErr, inputCloseErr)
	}()

	timeout := profile.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	exitObserved := make(chan error, 1)
	go func() { exitObserved <- waitForProcessExit(command.Process.Pid) }()
	var terminalErr error
	select {
	case observeErr := <-exitObserved:
		if observeErr != nil {
			terminalErr = observeErr
		}
	case <-ctx.Done():
		terminalErr = ctx.Err()
	case <-timer.C:
		terminalErr = fmt.Errorf("external child exceeded fixed timeout")
	}
	// Keep the leader unreaped while terminating and checking its process group.
	// This prevents its numeric PID/PGID from being reused for an unrelated host
	// process before the final group signal.
	cgroupErr := legoGroup.KillAndRemove()
	if cgroupErr != nil {
		cgroupErr = &CgroupClosureError{Cause: cgroupErr}
	}
	groupErr := terminateProcessGroupBeforeReap(command.Process.Pid)
	waitErr := command.Wait()
	var writeErr error
	select {
	case writeErr = <-writeDone:
	case <-time.After(time.Second):
		writeErr = fmt.Errorf("external child input writer did not close")
	}
	exitCode := -1
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	result := Result{ExitCode: exitCode, StdoutDigest: stdout.Digest(), Stdout: stdout.Bytes(), StderrDigest: stderr.Digest(), OutputCutOff: stdout.CutOff() || stderr.CutOff(), PackageChanges: []PackageChange{}}
	if profileID == ProfileAPTSimulate && exitCode == 0 && !result.OutputCutOff {
		changes, parseErr := parseAPTSimulation(stdout.Bytes())
		if parseErr != nil {
			terminalErr = errors.Join(terminalErr, parseErr)
		} else {
			result.PackageChanges = changes
		}
	}
	if terminalErr != nil || waitErr != nil || writeErr != nil || groupErr != nil || cgroupErr != nil {
		return result, errors.Join(terminalErr, waitErr, writeErr, groupErr, cgroupErr, fmt.Errorf("external child failed with redacted exit status %d", result.ExitCode))
	}
	return result, nil
}

// ExecutePersistentProfile replaces a fixed systemd guard with its one
// qualified persistent daemon. PID1 retains direct supervision; the generic
// one-shot launcher, timeout, and process-group teardown are not involved.
func ExecutePersistentProfile(profileID ProfileID) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("persistent child execution requires root")
	}
	profile, err := ResolveProfile(profileID, Identities{})
	if err != nil || !profile.Complete || !profile.PersistentDaemon {
		return fmt.Errorf("persistent child profile is unavailable")
	}
	if err := verifyRootExecutable(profile.Executable); err != nil {
		return err
	}
	if err := applyProfile(profile, false); err != nil {
		return err
	}
	argv := append([]string{profile.Executable}, profile.Arguments...)
	return unix.Exec(profile.Executable, argv, profile.Environment)
}

// ExecuteBootstrap is the release-fixed child-executor role. It accepts no
// argv-controlled executable or flags; the root helper supplies a typed profile
// over inherited fd 3 and optional bounded stdin over fd 4.
func ExecuteBootstrap(args []string) error {
	runtime.LockOSThread()
	if len(args) != 0 {
		return fmt.Errorf("child bootstrap accepts no arguments")
	}
	instructionFile := os.NewFile(3, "child-profile")
	if instructionFile == nil {
		return fmt.Errorf("child bootstrap profile descriptor is missing")
	}
	payload, err := io.ReadAll(io.LimitReader(instructionFile, maximumBootstrapBytes+1))
	_ = instructionFile.Close()
	if err != nil || len(payload) == 0 || len(payload) > maximumBootstrapBytes {
		return fmt.Errorf("child bootstrap profile is missing or unbounded")
	}
	var instruction bootstrapInstruction
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&instruction); err != nil {
		return fmt.Errorf("child bootstrap profile is invalid")
	}
	canonical, err := json.Marshal(instruction)
	if err != nil || !bytes.Equal(canonical, payload) || instruction.SchemaVersion != bootstrapSchema {
		return fmt.Errorf("child bootstrap profile is noncanonical")
	}
	profile, err := ResolveInvocation(instruction.ProfileID, instruction.Identities, instruction.Invocation)
	if err != nil || !profile.Complete {
		return fmt.Errorf("child bootstrap profile is unavailable")
	}
	if err := verifyRootExecutable(profile.Executable); err != nil {
		return err
	}
	if err := applyProfile(profile, instruction.HasInput); err != nil {
		return err
	}
	if instruction.ProfileID == ProfileLego {
		environment, err := decodeEnvironmentFrame(os.Stdin, 64<<10)
		if err != nil {
			return err
		}
		if instruction.Invocation.Lego == nil || !slices.Equal(environment, instruction.Invocation.Lego.Environment) {
			return fmt.Errorf("child environment differs from typed invocation")
		}
		profile.Environment = environment
	}
	argv := append([]string{profile.Executable}, profile.Arguments...)
	return unix.Exec(profile.Executable, argv, profile.Environment)
}

func mountLegoInputs(profile Profile) error {
	certificateID := filepath.Base(profile.Chroot)
	if profile.Chroot != "/var/lib/lanpanel/certificates/chroot/"+certificateID {
		return fmt.Errorf("ACME chroot identity invalid")
	}
	readonly := []string{"/usr/lib/lanpanel/dependencies/lego", "/etc/ssl/certs/ca-certificates.crt", "/etc/resolv.conf", "/etc/hosts"}
	for _, source := range readonly {
		target := filepath.Join(profile.Chroot, strings.TrimPrefix(source, "/"))
		if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind ACME child input: %w", err)
		}
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return fmt.Errorf("protect ACME child input: %w", err)
		}
	}
	webroot := "/var/lib/lanpanel/certificates/webroot/" + certificateID
	target := filepath.Join(profile.Chroot, strings.TrimPrefix(webroot, "/"))
	if err := unix.Mount(webroot, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind ACME child webroot: %w", err)
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("protect ACME child webroot: %w", err)
	}
	return nil
}

func applyProfile(profile Profile, hasInput bool) error {
	if profile.ID == ProfileLego {
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			return fmt.Errorf("create ACME mount namespace: %w", err)
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return fmt.Errorf("make ACME mounts private: %w", err)
		}
		if err := mountLegoInputs(profile); err != nil {
			return err
		}
	}
	originalNetwork := ""
	if profile.Network == NetworkNone || profile.Network == NetworkNoSockets {
		var err error
		originalNetwork, err = os.Readlink("/proc/self/ns/net")
		if err != nil {
			return fmt.Errorf("observe original child network namespace: %w", err)
		}
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return fmt.Errorf("create no-network child namespace: %w", err)
		}
		isolatedNetwork, err := os.Readlink("/proc/self/ns/net")
		if err != nil || isolatedNetwork == originalNetwork {
			return fmt.Errorf("child no-network namespace did not change")
		}
	}
	if profile.Network != NetworkNone && profile.Network != NetworkNoSockets && profile.Network != NetworkUnixOnly && profile.Network != NetworkHostQualified && profile.Network != NetworkProviderOnly && profile.Network != NetworkLocalAPIOnly {
		return fmt.Errorf("child network profile is unsupported")
	}
	if profile.Network == NetworkNone || profile.Network == NetworkNoSockets || profile.Network == NetworkUnixOnly || len(profile.AllowedAddressFamilies) > 0 {
		if err := installAddressFamilyFilter(profile.AllowedAddressFamilies); err != nil {
			return err
		}
	}
	if profile.Chroot != "" {
		if err := unix.Chroot(profile.Chroot); err != nil {
			return fmt.Errorf("enter child filesystem root: %w", err)
		}
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	allowed := map[int]bool{}
	for _, capability := range profile.AllowedCapabilities {
		allowed[capability] = true
	}
	for capability := 0; capability <= 63; capability++ {
		if allowed[capability] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop child capability bounding set: %w", err)
		}
	}
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("clear child supplementary groups: %w", err)
	}
	if err := unix.Setresgid(int(profile.GID), int(profile.GID), int(profile.GID)); err != nil {
		return fmt.Errorf("set child GID: %w", err)
	}
	if err := unix.Setresuid(int(profile.UID), int(profile.UID), int(profile.UID)); err != nil {
		return fmt.Errorf("set child UID: %w", err)
	}
	if err := setExactCapabilities(profile.AllowedCapabilities); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear child ambient capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set child no-new-privileges: %w", err)
	}
	if err := assertAppliedIdentity(profile); err != nil {
		return err
	}
	limits := map[int]unix.Rlimit{unix.RLIMIT_CORE: {Cur: 0, Max: 0}}
	if profile.PersistentDaemon {
		limits[unix.RLIMIT_NOFILE] = unix.Rlimit{Cur: 65536, Max: 65536}
		limits[unix.RLIMIT_NPROC] = unix.Rlimit{Cur: 1024, Max: 1024}
	} else {
		cpuSeconds := uint64(profile.Timeout/time.Second) + 1
		maximumFileBytes := profile.MaximumFileBytes
		if maximumFileBytes == 0 {
			maximumFileBytes = uint64(profile.MaximumOutputBytes + profile.MaximumInputBytes + 4096)
		}
		limits[unix.RLIMIT_CPU] = unix.Rlimit{Cur: cpuSeconds, Max: cpuSeconds}
		limits[unix.RLIMIT_FSIZE] = unix.Rlimit{Cur: maximumFileBytes, Max: maximumFileBytes}
		limits[unix.RLIMIT_NOFILE] = unix.Rlimit{Cur: 32, Max: 32}
		limits[unix.RLIMIT_NPROC] = unix.Rlimit{Cur: 32, Max: 32}
	}
	for resource, limit := range limits {
		if err := unix.Setrlimit(resource, &limit); err != nil {
			return fmt.Errorf("set child resource limit: %w", err)
		}
	}
	mask := profile.Umask
	if mask == 0 {
		mask = 0o077
	}
	unix.Umask(int(mask))
	if hasInput {
		if err := unix.Dup2(4, 0); err != nil {
			return fmt.Errorf("install child stdin: %w", err)
		}
	} else {
		null, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Dup2(null, 0); err != nil {
			_ = unix.Close(null)
			return err
		}
		_ = unix.Close(null)
	}
	if err := unix.CloseRange(3, ^uint(0), 0); err != nil {
		return fmt.Errorf("close inherited child descriptors: %w", err)
	}
	return nil
}

func addressFamilyFilter(allowed []int) ([]unix.SockFilter, error) {
	if len(allowed) == 0 {
		return []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SOCKET), Jt: 0, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EAFNOSUPPORT)},
			{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_ALLOW)},
		}, nil
	}
	unixOnly := slices.Equal(allowed, []int{unix.AF_UNIX})
	internetOnly := slices.Equal(allowed, []int{unix.AF_INET, unix.AF_INET6})
	if !unixOnly && !internetOnly {
		return nil, fmt.Errorf("child address-family policy is invalid")
	}
	filter := []unix.SockFilter{{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, {Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SOCKET), Jf: uint8(len(allowed) + 2)}, {Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16}}
	for index, family := range allowed {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(family), Jt: uint8(len(allowed) - index)})
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EAFNOSUPPORT)}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: uint32(unix.SECCOMP_RET_ALLOW)})
	return filter, nil
}

func installAddressFamilyFilter(allowed []int) error {
	filter, err := addressFamilyFilter(allowed)
	if err != nil {
		return err
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no-new-privileges before address-family filter: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)), 0, 0); err != nil {
		return fmt.Errorf("install no-network child address-family filter: %w", err)
	}
	return nil
}

func decodeEnvironmentFrame(reader io.Reader, maximum int) ([]string, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, int64(maximum+1)))
	if err != nil || len(payload) > maximum {
		return nil, fmt.Errorf("child environment frame invalid")
	}
	parts := bytes.Split(payload, []byte{0})
	if len(parts) < 4 || string(parts[0]) != "lanpanel.acme.environment.v1" || len(parts[len(parts)-1]) != 0 {
		return nil, fmt.Errorf("child environment frame invalid")
	}
	result := make([]string, len(parts)-2)
	seen := map[string]bool{}
	for index, raw := range parts[1 : len(parts)-1] {
		value := string(raw)
		key, _, found := strings.Cut(value, "=")
		if !found || key == "" || seen[key] || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("child environment frame invalid")
		}
		seen[key] = true
		result[index] = value
	}
	if result[0] != "LANG=C" || result[1] != "LC_ALL=C" {
		return nil, fmt.Errorf("child environment locale invalid")
	}
	return result, nil
}

func writePipeFull(file *os.File, value []byte) error {
	for len(value) != 0 {
		written, err := file.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func waitForProcessExit(pid int) error {
	if pid <= 1 {
		return fmt.Errorf("external child PID is invalid")
	}
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("observe external child exit without reaping: %w", err)
		}
		if info.Signo != 0 {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func terminateProcessGroupBeforeReap(processGroup int) error {
	if processGroup <= 1 {
		return fmt.Errorf("external child process group is invalid")
	}
	if err := unix.Kill(-processGroup, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("terminate external child process group: %w", err)
	}
	for range 100 {
		live, err := processGroupHasLiveMember(processGroup, processGroup)
		if err != nil {
			return err
		}
		if !live {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("external child process group did not terminate before leader reap")
}

func processGroupHasLiveMember(processGroup, leader int) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, fmt.Errorf("enumerate child process group: %w", err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == leader {
			continue
		}
		payload, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("observe child process group member: %w", err)
		}
		group, state, err := parseProcStat(payload)
		if err != nil {
			return false, err
		}
		if group == processGroup && state != "Z" && state != "X" && state != "x" {
			return true, nil
		}
	}
	return false, nil
}

func parseProcStat(payload []byte) (int, string, error) {
	closing := bytes.LastIndexByte(payload, ')')
	if closing < 0 || closing+1 >= len(payload) {
		return 0, "", fmt.Errorf("child process stat is malformed")
	}
	fields := strings.Fields(string(payload[closing+1:]))
	if len(fields) < 3 || len(fields[0]) != 1 {
		return 0, "", fmt.Errorf("child process stat is incomplete")
	}
	processGroup, err := strconv.Atoi(fields[2])
	if err != nil || processGroup < 0 {
		return 0, "", fmt.Errorf("child process group identity is invalid")
	}
	return processGroup, fields[0], nil
}

func setExactCapabilities(capabilities []int) error {
	var data [2]unix.CapUserData
	for _, capability := range capabilities {
		if capability < 0 || capability >= 64 {
			return fmt.Errorf("child capability is outside the Linux v3 set")
		}
		index, bit := capability/32, uint(capability%32)
		mask := uint32(1) << bit
		data[index].Effective |= mask
		data[index].Permitted |= mask
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("set exact child capabilities: %w", err)
	}
	return nil
}

func assertAppliedIdentity(profile Profile) error {
	if os.Geteuid() != int(profile.UID) || os.Getegid() != int(profile.GID) {
		return fmt.Errorf("child effective identity does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return fmt.Errorf("child supplementary groups are not empty")
	}
	nnp, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if errno != 0 || nnp != 1 {
		return fmt.Errorf("child no-new-privileges assertion failed")
	}
	var data [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read child capabilities: %w", err)
	}
	var expected [2]uint32
	for _, capability := range profile.AllowedCapabilities {
		expected[capability/32] |= uint32(1) << uint(capability%32)
	}
	for index := range data {
		if data[index].Effective != expected[index] || data[index].Permitted != expected[index] || data[index].Inheritable != 0 {
			return fmt.Errorf("child effective, permitted, or inheritable capability assertion failed")
		}
	}
	for capability := 0; capability < 64; capability++ {
		want := expected[capability/32]&(uint32(1)<<uint(capability%32)) != 0
		bounding, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, uintptr(capability), 0, 0, 0, 0)
		if errno == unix.EINVAL {
			continue
		}
		if errno != 0 || (bounding == 1) != want {
			return fmt.Errorf("child capability bounding-set assertion failed")
		}
		ambient, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(capability), 0, 0, 0)
		if errno == unix.EINVAL && !want {
			continue
		}
		if errno != 0 || ambient != 0 {
			return fmt.Errorf("child ambient capability assertion failed")
		}
	}
	return nil
}

func executableDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func verifyRootExecutable(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("executable path is not absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("executable is missing, linked, non-regular, or writable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("executable is not root-owned")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("executable parent is unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("executable parent is not root-owned")
		}
		if parent == "/" {
			break
		}
	}
	return nil
}

type digestWriter struct {
	mu      sync.Mutex
	hash    hash.Hash
	written int
	maximum int
	cutoff  bool
	capture bool
	bytes   []byte
}

func newDigestWriter(maximum int, capture ...bool) *digestWriter {
	keep := len(capture) == 1 && capture[0]
	return &digestWriter{hash: sha256.New(), maximum: maximum, capture: keep}
}

func (writer *digestWriter) Write(value []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.written+len(value) > writer.maximum {
		remaining := writer.maximum - writer.written
		if remaining > 0 {
			_, _ = writer.hash.Write(value[:remaining])
			if writer.capture {
				writer.bytes = append(writer.bytes, value[:remaining]...)
			}
			writer.written += remaining
		}
		writer.cutoff = true
		return remaining, errOutputLimit
	}
	_, _ = writer.hash.Write(value)
	if writer.capture {
		writer.bytes = append(writer.bytes, value...)
	}
	writer.written += len(value)
	return len(value), nil
}
func (writer *digestWriter) Digest() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return "sha256:" + hex.EncodeToString(writer.hash.Sum(nil))
}
func (writer *digestWriter) Bytes() []byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]byte(nil), writer.bytes...)
}
func (writer *digestWriter) CutOff() bool {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.cutoff
}

func parseAPTSimulation(output []byte) ([]PackageChange, error) {
	changes := []PackageChange{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Purg ") {
			return nil, fmt.Errorf("APT simulation contains a removal")
		}
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		rest := strings.TrimPrefix(line, "Inst ")
		name, detail, found := strings.Cut(rest, " ")
		if !found || !packageNamePattern.MatchString(name) {
			return nil, fmt.Errorf("APT simulation package identity is invalid")
		}
		detail = strings.TrimSpace(detail)
		if !strings.HasPrefix(detail, "(") {
			return nil, fmt.Errorf("APT simulation package version is missing")
		}
		version, _, found := strings.Cut(strings.TrimPrefix(detail, "("), " ")
		version = strings.TrimSuffix(version, ")")
		if !found && !strings.HasSuffix(detail, ")") || !packageVersionPattern.MatchString(version) {
			return nil, fmt.Errorf("APT simulation package version is invalid")
		}
		changes = append(changes, PackageChange{Name: name, Version: version})
	}
	if err := scanner.Err(); err != nil || len(changes) == 0 || len(changes) > 256 {
		return nil, fmt.Errorf("APT simulation output is missing, malformed, or unbounded")
	}
	slices.SortFunc(changes, func(left, right PackageChange) int { return strings.Compare(left.Name, right.Name) })
	for index := 1; index < len(changes); index++ {
		if changes[index-1].Name == changes[index].Name {
			return nil, fmt.Errorf("APT simulation contains duplicate package change")
		}
	}
	return changes, nil
}

func ParseExitCode(value string) (int, error) {
	code, err := strconv.Atoi(value)
	if err != nil || code < 0 || code > 255 || strings.TrimSpace(value) != value {
		return 0, fmt.Errorf("child exit code is invalid")
	}
	return code, nil
}
