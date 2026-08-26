//go:build linux

package control

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type SystemdRuntime struct{ launcher *child.Launcher }

func NewSystemdRuntime() (*SystemdRuntime, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return nil, err
	}
	return &SystemdRuntime{launcher: launcher}, nil
}

func (runtime *SystemdRuntime) RequireAbsent(ctx context.Context, candidate Candidate, _ identity.AccountIdentity) error {
	if runtime == nil || runtime.launcher == nil || Validate(candidate) != nil {
		return fmt.Errorf("headscale absent-unit authority invalid")
	}
	if err := runtime.run(ctx, child.ProfileSystemctl, child.Invocation{}); err != nil {
		return err
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: candidate.HeadscaleID}}
	result, err := runtime.launcher.RunInvocation(ctx, child.ProfileHeadscaleShow, invocation, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff || len(result.Stdout) == 0 {
		return fmt.Errorf("fixed Headscale absent-unit observation failed: %w", err)
	}
	properties, err := parseHeadscaleUnitProperties(result.Stdout)
	if err != nil {
		return err
	}
	if properties["Id"] != "lanpanel-headscale.service" || properties["LoadState"] != "not-found" || properties["ActiveState"] != "inactive" || properties["MainPID"] != "0" || properties["FragmentPath"] != "" || properties["DropInPaths"] != "" {
		return fmt.Errorf("foreign Headscale service authority already exists")
	}
	return nil
}

func (runtime *SystemdRuntime) InitializeDatabase(ctx context.Context, rendered Rendered, account identity.AccountIdentity) (DatabaseEvidence, error) {
	if runtime == nil || runtime.launcher == nil || VerifyRendered(rendered) != nil {
		return DatabaseEvidence{}, fmt.Errorf("headscale systemd database authority invalid")
	}
	if err := runtime.run(ctx, child.ProfileSystemctl, child.Invocation{}); err != nil {
		return DatabaseEvidence{}, err
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: rendered.Candidate.HeadscaleID}}
	if _, err := runtime.show(ctx, invocation, rendered, account, false); err != nil {
		return DatabaseEvidence{}, err
	}
	if err := runtime.run(ctx, child.ProfileHeadscaleStart, invocation); err != nil {
		return DatabaseEvidence{}, err
	}
	if _, err := runtime.show(ctx, invocation, rendered, account, true); err != nil {
		_ = runtime.run(context.WithoutCancel(ctx), child.ProfileHeadscaleStop, invocation)
		return DatabaseEvidence{}, err
	}
	if err := runtime.run(ctx, child.ProfileHeadscaleStop, invocation); err != nil {
		return DatabaseEvidence{}, err
	}
	if _, err := runtime.show(ctx, invocation, rendered, account, false); err != nil {
		return DatabaseEvidence{}, err
	}
	return observeDatabase(rendered.Candidate, account)
}

func (runtime *SystemdRuntime) StartAndProbe(ctx context.Context, rendered Rendered, account identity.AccountIdentity) (ServiceEvidence, error) {
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: rendered.Candidate.HeadscaleID}}
	if _, err := runtime.show(ctx, invocation, rendered, account, false); err != nil {
		return ServiceEvidence{}, err
	}
	if err := runtime.run(ctx, child.ProfileHeadscaleStart, invocation); err != nil {
		return ServiceEvidence{}, err
	}
	show, err := runtime.show(ctx, invocation, rendered, account, true)
	if err != nil {
		_ = runtime.run(context.WithoutCancel(ctx), child.ProfileHeadscaleStop, invocation)
		return ServiceEvidence{}, err
	}
	return ServiceEvidence{Identity: rendered.Candidate.ServiceIdentity, PrivateProbe: hashBytes(append([]byte(rendered.Candidate.ServiceIdentity+"\x00"), show...)), PublicSTUNOpen: false}, nil
}

func (runtime *SystemdRuntime) ObserveActive(ctx context.Context, rendered Rendered, account identity.AccountIdentity) (ServiceEvidence, error) {
	if runtime == nil || runtime.launcher == nil || VerifyRendered(rendered) != nil {
		return ServiceEvidence{}, fmt.Errorf("headscale active observation authority invalid")
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: rendered.Candidate.HeadscaleID}}
	show, err := runtime.show(ctx, invocation, rendered, account, true)
	if err != nil {
		return ServiceEvidence{}, err
	}
	return ServiceEvidence{Identity: rendered.Candidate.ServiceIdentity, PrivateProbe: hashBytes(append([]byte(rendered.Candidate.ServiceIdentity+"\x00"), show...)), PublicSTUNOpen: false}, nil
}

func (runtime *SystemdRuntime) StopAndVerify(ctx context.Context, candidate Candidate, account identity.AccountIdentity) error {
	var unitStat unix.Stat_t
	if err := unix.Lstat(candidate.Paths.Unit, &unitStat); errors.Is(err, unix.ENOENT) {
		return runtime.RequireAbsent(context.WithoutCancel(ctx), candidate, account)
	} else if err != nil {
		return err
	} else if unitStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("headscale unit path is not regular")
	}
	invocation := child.Invocation{Headscale: &child.HeadscaleInvocation{HeadscaleID: candidate.HeadscaleID}}
	stopErr := runtime.run(context.WithoutCancel(ctx), child.ProfileHeadscaleStop, invocation)
	show, showErr := runtime.show(context.WithoutCancel(ctx), invocation, Rendered{Candidate: candidate}, account, false)
	_ = show
	return errors.Join(stopErr, showErr)
}

func (runtime *SystemdRuntime) run(ctx context.Context, profile child.ProfileID, invocation child.Invocation) error {
	result, err := runtime.launcher.RunInvocation(ctx, profile, invocation, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff || len(result.Stdout) != 0 {
		return fmt.Errorf("fixed Headscale systemd action failed: %w", err)
	}
	return nil
}

func (runtime *SystemdRuntime) show(ctx context.Context, invocation child.Invocation, rendered Rendered, account identity.AccountIdentity, active bool) ([]byte, error) {
	result, err := runtime.launcher.RunInvocation(ctx, child.ProfileHeadscaleShow, invocation, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff || len(result.Stdout) == 0 {
		return nil, fmt.Errorf("fixed Headscale systemd observation failed: %w", err)
	}
	properties, err := parseHeadscaleUnitProperties(result.Stdout)
	if err != nil {
		return nil, err
	}
	exact := map[string]string{"Id": "lanpanel-headscale.service", "LoadState": "loaded", "UnitFileState": "disabled", "ControlGroup": "/system.slice/lanpanel-headscale.service", "User": account.User, "Group": account.Group, "SupplementaryGroups": "", "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictSUIDSGID": "yes", "PrivateNetwork": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes", "RuntimeDirectory": "lanpanel/headscale", "RuntimeDirectoryMode": "0700", "ProtectSystem": "strict", "ProtectHome": "yes", "ProtectProc": "invisible", "ProcSubset": "pid", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "yes", "SystemCallArchitectures": "native", "UMask": "0077", "KillMode": "control-group", "FragmentPath": rendered.Candidate.Paths.Unit, "DropInPaths": ""}
	for key, expected := range exact {
		if properties[key] != expected {
			return nil, fmt.Errorf("effective Headscale unit property %s changed", key)
		}
	}
	if !sameWords(properties["RestrictAddressFamilies"], "AF_UNIX AF_INET AF_INET6") || !sameWords(properties["ReadWritePaths"], rendered.Candidate.Paths.RuntimeRoot+" /run/lanpanel/headscale") {
		return nil, fmt.Errorf("effective Headscale unit namespace paths changed")
	}
	executable := rendered.Candidate.Paths.Executable
	config := rendered.Candidate.Paths.Config
	if strings.Count(properties["ExecStart"], "path=") != 1 || !strings.Contains(properties["ExecStart"], "path="+executable+" ;") || !strings.Contains(properties["ExecStart"], "argv[]="+executable+" serve --config "+config+" ;") || strings.Count(properties["ExecStartPost"], "path=") != 1 || !strings.Contains(properties["ExecStartPost"], "path=/usr/lib/lanpanel/lanpanel ;") || !strings.Contains(properties["ExecStartPost"], "argv[]=/usr/lib/lanpanel/lanpanel headscale-private-probe ;") {
		return nil, fmt.Errorf("effective Headscale unit executable changed")
	}
	if active {
		if properties["ActiveState"] != "active" || properties["SubState"] != "running" || properties["MainPID"] == "" || properties["MainPID"] == "0" {
			return nil, fmt.Errorf("headscale candidate service is not privately probed")
		}
		mainPID, err := strconv.Atoi(properties["MainPID"])
		if err != nil || mainPID <= 1 {
			return nil, fmt.Errorf("headscale candidate MainPID is invalid")
		}
		if err := requireHostCandidateListenersAbsent(mainPID); err != nil {
			return nil, err
		}
	} else if properties["ActiveState"] != "inactive" || properties["SubState"] == "running" || properties["MainPID"] != "0" {
		return nil, fmt.Errorf("headscale candidate service remained active")
	}
	return result.Stdout, nil
}

func parseHeadscaleUnitProperties(raw []byte) (map[string]string, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, present := strings.Cut(line, "=")
		if !present || key == "" {
			return nil, fmt.Errorf("effective Headscale unit output is malformed")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("effective Headscale unit property is duplicated")
		}
		values[key] = value
	}
	for _, key := range []string{"Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "ControlGroup", "User", "Group", "SupplementaryGroups", "NoNewPrivileges", "CapabilityBoundingSet", "AmbientCapabilities", "RestrictSUIDSGID", "PrivateNetwork", "PrivateTmp", "PrivateDevices", "RuntimeDirectory", "RuntimeDirectoryMode", "ProtectSystem", "ProtectHome", "ProtectProc", "ProcSubset", "ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups", "LockPersonality", "MemoryDenyWriteExecute", "SystemCallArchitectures", "RestrictAddressFamilies", "ReadWritePaths", "UMask", "KillMode", "ExecStart", "ExecStartPost", "FragmentPath", "DropInPaths"} {
		if _, present := values[key]; !present {
			return nil, fmt.Errorf("effective Headscale unit property %s is missing", key)
		}
	}
	if len(values) != 37 {
		return nil, fmt.Errorf("effective Headscale unit output contains unrequested properties")
	}
	return values, nil
}

func sameWords(actual, expected string) bool {
	left, right := strings.Fields(actual), strings.Fields(expected)
	sort.Strings(left)
	sort.Strings(right)
	return reflect.DeepEqual(left, right)
}

func observeDatabase(candidate Candidate, account identity.AccountIdentity) (DatabaseEvidence, error) {
	evidence := DatabaseEvidence{UUID: candidate.DatabaseUUID, Generation: candidate.DatabaseGeneration}
	paths := []struct {
		path     string
		target   *string
		required bool
	}{{candidate.Paths.Database, &evidence.MainDigest, true}, {candidate.Paths.Database + "-wal", &evidence.WALDigest, false}, {candidate.Paths.Database + "-shm", &evidence.SHMDigest, false}, {candidate.Paths.Database + "-journal", &evidence.JournalDigest, false}}
	for _, item := range paths {
		digest, present, err := protectedRuntimeFile(item.path, account, item.required)
		if err != nil || item.required && !present {
			return DatabaseEvidence{}, errors.Join(err, fmt.Errorf("headscale SQLite evidence incomplete"))
		}
		if present {
			*item.target = digest
		}
	}
	raw, _ := json.Marshal(struct {
		UUID       string `json:"uuid"`
		Generation uint64 `json:"generation"`
		Main       string `json:"main"`
		WAL        string `json:"wal,omitempty"`
		SHM        string `json:"shm,omitempty"`
		Journal    string `json:"journal,omitempty"`
	}{evidence.UUID, evidence.Generation, evidence.MainDigest, evidence.WALDigest, evidence.SHMDigest, evidence.JournalDigest})
	evidence.InitializedDigest = hashBytes(raw)
	return evidence, nil
}

func protectedRuntimeFile(path string, account identity.AccountIdentity, sqliteMain bool) (string, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return "", false, fmt.Errorf("SQLite descriptor unavailable")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != account.UID || stat.Gid != account.GID || stat.Mode&0o7777 != 0o600 || stat.Size <= 0 || stat.Size > 4<<30 {
		return "", false, fmt.Errorf("SQLite file metadata unsafe")
	}
	if sqliteMain {
		header := make([]byte, 100)
		if _, err := file.ReadAt(header, 0); err != nil || string(header[:16]) != "SQLite format 3\x00" {
			return "", false, fmt.Errorf("headscale SQLite header is invalid")
		}
		pageSize := uint64(binary.BigEndian.Uint16(header[16:18]))
		if pageSize == 1 {
			pageSize = 65536
		}
		if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 || stat.Size%int64(pageSize) != 0 || (header[18] != 1 && header[18] != 2) || (header[19] != 1 && header[19] != 2) || header[20] > 32 || header[21] != 64 || header[22] != 32 || header[23] != 32 || binary.BigEndian.Uint32(header[44:48]) < 1 || binary.BigEndian.Uint32(header[44:48]) > 4 || binary.BigEndian.Uint32(header[56:60]) < 1 || binary.BigEndian.Uint32(header[56:60]) > 3 {
			return "", false, fmt.Errorf("headscale SQLite structural envelope is invalid")
		}
	}
	hash := sha256.New()
	if _, err := file.Seek(0, 0); err != nil {
		return "", false, err
	}
	buffer := make([]byte, 64<<10)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", false, readErr
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), true, nil
}

func requireHostCandidateListenersAbsent(mainPID int) error {
	return requireHostCandidateListenersAbsentAt("/proc", mainPID)
}

func requireHostCandidateListenersAbsentAt(procRoot string, mainPID int) error {
	if !filepath.IsAbs(procRoot) || filepath.Clean(procRoot) != procRoot || mainPID <= 1 {
		return fmt.Errorf("headscale candidate listener authority is invalid")
	}
	hostNamespace, err := os.Stat(filepath.Join(procRoot, "1", "ns", "net"))
	if err != nil {
		return fmt.Errorf("observe host network namespace: %w", err)
	}
	candidateNamespace, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(mainPID), "ns", "net"))
	if err != nil {
		return fmt.Errorf("observe Headscale candidate network namespace: %w", err)
	}
	if os.SameFile(hostNamespace, candidateNamespace) {
		return fmt.Errorf("headscale candidate endpoint escaped private network namespace")
	}
	return nil
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
