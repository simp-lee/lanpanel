//go:build linux

package process

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"lanpanel/internal/release"
	"lanpanel/internal/resource"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type Host struct{ Launcher *child.Launcher }

func NewFixedHost() (Host, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	return Host{Launcher: launcher}, err
}

func (host Host) InstallAccounts(ctx context.Context, set identity.ResourceAccountSet) (identity.ResourceAccountSet, []string, error) {
	if host.Launcher == nil {
		return identity.ResourceAccountSet{}, nil, fmt.Errorf("managed-process host launcher is missing")
	}
	present, identities, err := identity.InspectResourceAccountFiles(set, "/etc/passwd", "/etc/group", "/etc/shadow")
	if err != nil {
		return identity.ResourceAccountSet{}, nil, err
	}
	if present {
		set.Identities = identities
		return set, nil, nil
	}
	data, err := identity.RenderResourceSysusers(set)
	if err != nil {
		return identity.ResourceAccountSet{}, nil, err
	}
	paths, err := resource.DerivePaths(set.ResourceID)
	if err != nil {
		return identity.ResourceAccountSet{}, nil, err
	}
	if err := putManagedFile(ctx, paths.SysusersFile, data, 0o600); err != nil {
		return identity.ResourceAccountSet{}, nil, err
	}
	result, runErr := host.Launcher.RunInvocation(ctx, child.ProfileResourceAccounts, child.Invocation{Resource: &child.ResourceInvocation{ResourceID: set.ResourceID}}, nil)
	if runErr != nil || result.ExitCode != 0 || result.OutputCutOff {
		return identity.ResourceAccountSet{}, []string{paths.SysusersFile}, fmt.Errorf("resource account creation failed: %w", runErr)
	}
	present, identities, err = identity.InspectResourceAccountFiles(set, "/etc/passwd", "/etc/group", "/etc/shadow")
	if err != nil || !present {
		return identity.ResourceAccountSet{}, []string{paths.SysusersFile}, fmt.Errorf("resource accounts did not verify: %w", err)
	}
	set.Identities = identities
	return set, []string{paths.SysusersFile}, nil
}

func LoadConfinementProfile() (confinement.Profile, error) {
	path := "/var/lib/lanpanel/installation/managed-confinement.json"
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return confinement.Profile{}, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return confinement.Profile{}, fmt.Errorf("confinement descriptor invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 64<<10 {
		return confinement.Profile{}, fmt.Errorf("confinement authority file is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || int64(len(data)) != stat.Size {
		return confinement.Profile{}, fmt.Errorf("confinement authority changed")
	}
	var source release.ConfinementProfile
	if err := release.DecodeCanonical(data, &source); err != nil {
		return confinement.Profile{}, err
	}
	profile := confinement.Profile{SchemaVersion: source.SchemaVersion, KernelRelease: source.KernelRelease, CgroupMode: source.CgroupMode, BindListenPolicy: source.BindListenPolicy, ConnectPolicy: source.ConnectPolicy, FilesystemPolicy: source.FilesystemPolicy, ProtectedDestinations: append([]string(nil), source.ProtectedDestinations...), QualificationDigest: "sha256:" + source.QualificationDigest}
	if err := confinement.ValidateProfile(profile); err != nil {
		return confinement.Profile{}, err
	}
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return confinement.Profile{}, err
	}
	kernel := strings.TrimRight(string(uname.Release[:]), "\x00")
	if kernel != profile.KernelRelease {
		return confinement.Profile{}, fmt.Errorf("running kernel differs from qualified confinement profile")
	}
	data, err = os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil || len(data) == 0 {
		return confinement.Profile{}, fmt.Errorf("unified cgroup v2 authority unavailable")
	}
	return profile, nil
}

func (host Host) Install(ctx context.Context, resourceID string, units UnitSet) ([]string, error) {
	if host.Launcher == nil {
		return nil, fmt.Errorf("managed-process host launcher is missing")
	}
	paths, err := resource.DerivePaths(resourceID)
	if err != nil {
		return nil, err
	}
	if paths != units.Paths {
		return nil, fmt.Errorf("managed-process unit path identity mismatched")
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	managed := []struct {
		path string
		data []byte
	}{{paths.SysusersFile, units.Sysusers}, {AuthorityPath(resourceID), units.ExecAuthority}, {filepath.Join("/etc/systemd/system", paths.PolicyUnit), units.Policy}, {filepath.Join("/etc/systemd/system", paths.SocketUnit), units.Socket}, {filepath.Join("/etc/systemd/system", paths.ServiceUnit), units.Application}}
	if len(units.BackendSocket) != 0 {
		managed = append(managed, struct {
			path string
			data []byte
		}{filepath.Join("/etc/systemd/system", paths.BackendSocketUnit), units.BackendSocket})
	}
	if len(units.Relay) != 0 {
		managed = append(managed, struct {
			path string
			data []byte
		}{filepath.Join("/etc/systemd/system", paths.RelayUnit), units.Relay})
	}
	modified := []string{}
	for _, directory := range []string{filepath.Dir(paths.SysusersFile), paths.ResourceRoot, filepath.Dir(paths.BackendSocket), filepath.Dir(paths.FrontendSocket)} {
		mode := uint32(0o700)
		if directory == filepath.Dir(paths.FrontendSocket) || directory == paths.ResourceRoot {
			mode = 0o711
		}
		owner, group := 0, 0
		if directory == filepath.Dir(paths.BackendSocket) {
			mode = 0o2770
			owner = int(units.ApplicationUID)
			group = int(units.RelayGID)
		}
		if err := ensureDirectory(directory, mode, owner, group); err != nil {
			return modified, err
		}
	}
	for _, item := range managed {
		staging := filepath.Join(filepath.Dir(item.path), ".lanpanel-filetxn")
		if err := ensureRootDirectory(staging, 0o700); err != nil {
			return modified, err
		}
		store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: owner, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
		if err != nil {
			return modified, err
		}
		mode := os.FileMode(0o644)
		if item.path == AuthorityPath(resourceID) || item.path == paths.SysusersFile {
			mode = 0o600
		}
		metadata := filetxn.Metadata{Owner: owner, Mode: mode}
		disposition := filetxn.CreateOnly
		if _, statErr := os.Lstat(item.path); statErr == nil {
			disposition = filetxn.ReplaceOnly
		} else if !errors.Is(statErr, os.ErrNotExist) {
			_ = store.Close()
			return modified, statErr
		}
		_, err = store.Put(ctx, filetxn.Request{Path: item.path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, Existing: &metadata, New: metadata, MaxBytes: int64(len(item.data))}, item.data, disposition)
		closeErr := store.Close()
		if err != nil || closeErr != nil {
			return modified, errors.Join(err, closeErr)
		}
		modified = append(modified, item.path)
	}
	invocation := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID}}
	for _, profile := range []child.ProfileID{child.ProfileResourceDaemonReload} {
		result, runErr := host.Launcher.RunInvocation(ctx, profile, invocation, nil)
		if runErr != nil || result.ExitCode != 0 || result.OutputCutOff {
			return modified, fmt.Errorf("managed-process fixed setup %q failed: %w", profile, runErr)
		}
	}
	return modified, nil
}

func (host Host) Start(ctx context.Context, resourceID string, units UnitSet) error {
	relay := units.Bundle.RelayRequired
	if err := ensureListenGuard(resourceID, units.ApplicationUID, units.Confinement); err != nil {
		return err
	}
	if err := host.run(ctx, child.ProfileResourceStart, resourceID, relay); err != nil {
		return err
	}
	if err := host.verifyEffectiveUnit(ctx, resourceID, false, units.Confinement); err != nil {
		_ = host.run(context.WithoutCancel(ctx), child.ProfileResourceStop, resourceID, relay)
		return err
	}
	if err := host.waitApplicationIdentity(ctx, resourceID, units); err != nil {
		_ = host.run(context.WithoutCancel(ctx), child.ProfileResourceStop, resourceID, relay)
		return err
	}
	if relay {
		if err := host.verifyEffectiveRelay(ctx, resourceID, units); err != nil {
			_ = host.run(context.WithoutCancel(ctx), child.ProfileResourceStop, resourceID, true)
			return err
		}
	}
	return nil
}

func (host Host) VerifyApplied(ctx context.Context, resourceID string, bundle domain.ProcessBundle, policy confinement.UnitPolicy) error {
	if err := host.verifyEffectiveUnit(ctx, resourceID, false, policy); err != nil {
		return err
	}
	units := UnitSet{Bundle: bundle, Confinement: policy, ApplicationUID: bundle.ApplicationUID, ApplicationGID: bundle.ApplicationGID, RelayUID: bundle.RelayUID, RelayGID: bundle.RelayGID}
	if err := host.waitApplicationIdentity(ctx, resourceID, units); err != nil {
		return err
	}
	if bundle.RelayRequired {
		return host.verifyEffectiveRelay(ctx, resourceID, units)
	}
	return nil
}

func (host Host) VerifyCommittedJournal(ctx context.Context, journal Journal, running bool) error {
	if journal.Applied == nil {
		if running {
			return fmt.Errorf("running process journal omits applied bundle")
		}
		return verifyUnappliedStopped(journal)
	}
	if !running {
		observation, err := ObserveStopped(ctx, "/sys/fs/cgroup", *journal.Applied)
		if err != nil {
			return err
		}
		if err := VerifyStopped(observation); err != nil {
			return err
		}
		return releaseListenGuardUID(journal.Applied.ApplicationUID)
	}
	if journal.Operation != "process_start" || journal.Phase != "host_mutated" {
		return fmt.Errorf("committed process journal operation is invalid")
	}
	paths, err := resource.DerivePaths(journal.ResourceID)
	if err != nil {
		return err
	}
	units := UnitSet{Paths: paths, Bundle: *journal.Applied, Confinement: journal.Policy, ApplicationUID: journal.ApplicationUID, ApplicationGID: journal.ApplicationGID, RelayUID: journal.RelayUID, RelayGID: journal.RelayGID}
	if err := host.verifyEffectiveUnit(ctx, journal.ResourceID, false, journal.Policy); err != nil {
		return err
	}
	if err := host.waitApplicationIdentity(ctx, journal.ResourceID, units); err != nil {
		return err
	}
	if journal.RelayRequired {
		if err := host.verifyEffectiveRelay(ctx, journal.ResourceID, units); err != nil {
			return err
		}
	}
	kind := domain.LocalEndpointUnixSocketActivation
	if journal.RelayRequired {
		kind = domain.LocalEndpointRelayUnix
	} else if journal.Applied.TCPAddress != "" {
		kind = domain.LocalEndpointTCPSocketActivation
	}
	observation, err := Observe(ctx, "/sys/fs/cgroup", *journal.Applied, kind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
	if err != nil {
		return err
	}
	return VerifyRunning(observation)
}

func verifyUnappliedStopped(journal Journal) error {
	paths, err := resource.DerivePaths(journal.ResourceID)
	if err != nil {
		return err
	}
	for _, endpoint := range []string{paths.FrontendSocket, paths.BackendSocket} {
		var stat unix.Stat_t
		if err := unix.Lstat(endpoint, &stat); err == nil {
			return fmt.Errorf("unapplied process endpoint remains")
		} else if !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	short := strings.TrimPrefix(journal.ResourceID, "res_")[:20]
	cgroups := []string{"/lanpanel.slice/lanpanel-app.slice/lanpanel-app-" + short + ".slice/lanpanel-app-" + short + ".service"}
	if journal.RelayRequired {
		cgroups = append(cgroups, "/system.slice/lanpanel-relay-"+short+".service")
	}
	for _, cgroup := range cgroups {
		observation, err := confinement.ObserveCgroup("/sys/fs/cgroup", cgroup)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		if observation.Populated || len(observation.PIDs) != 0 {
			return fmt.Errorf("unapplied process cgroup remains populated")
		}
	}
	return nil
}

func (host Host) Stop(ctx context.Context, resourceID string, relay bool) error {
	if err := host.run(ctx, child.ProfileResourceStop, resourceID, relay); err != nil {
		return err
	}
	if relay {
		paths, err := resource.DerivePaths(resourceID)
		if err != nil {
			return err
		}
		if err := removeStoppedBackend(paths.BackendSocket); err != nil {
			return err
		}
	}
	return waitOwnedEndpointsGone(ctx, resourceID)
}

func removeStoppedBackend(path string) error {
	var parent, stat unix.Stat_t
	if err := unix.Lstat(filepath.Dir(path), &parent); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0o7777 != 0o2770 || parent.Uid == 0 || parent.Gid == 0 {
		return fmt.Errorf("stopped managed backend parent identity is unsafe")
	}
	if err := unix.Lstat(path, &stat); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != parent.Uid || stat.Gid != parent.Gid || stat.Mode&0o777 != 0o660 {
		return fmt.Errorf("stopped managed backend identity is unsafe")
	}
	return unix.Unlink(path)
}

func (host Host) run(ctx context.Context, profile child.ProfileID, resourceID string, relay bool) error {
	if host.Launcher == nil {
		return fmt.Errorf("managed-process host launcher is missing")
	}
	result, err := host.Launcher.RunInvocation(ctx, profile, child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Relay: relay}}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("managed-process fixed transition %q failed: %w", profile, err)
	}
	return nil
}

func (host Host) verifyEffectiveUnit(ctx context.Context, resourceID string, relay bool, policy confinement.UnitPolicy) error {
	if policy.ResourceID == "" || policy.Digest == "" {
		return fmt.Errorf("effective confinement authority incomplete")
	}
	result, err := host.Launcher.RunInvocation(ctx, child.ProfileResourceShow, child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Relay: relay}}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("effective systemd property observation failed: %w", err)
	}
	effective, parseErr := parseShowProperties(result.Stdout)
	clear(result.Stdout)
	if parseErr != nil {
		return parseErr
	}
	if !singleProperty(effective, "ActiveState", "active") || !singleProperty(effective, "SubState", "running") || !singleProperty(effective, "ControlGroup", policy.Cgroup) {
		return fmt.Errorf("effective managed service state or cgroup differs")
	}
	observed, err := confinement.ObserveCgroup("/sys/fs/cgroup", policy.Cgroup)
	if err != nil || !observed.Populated || len(observed.PIDs) == 0 {
		return fmt.Errorf("effective confinement cgroup unavailable: %w", err)
	}
	return confinement.VerifyEffective(policy, effective)
}

func (host Host) waitApplicationIdentity(ctx context.Context, resourceID string, units UnitSet) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		effective, err := host.showResource(ctx, resourceID, false)
		if err == nil {
			err = verifyApplicationIdentity(effective, units)
		}
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("managed application identity wait: %w", errors.Join(ctx.Err(), last))
		case <-timer.C:
			return fmt.Errorf("managed application identity not established: %w", last)
		case <-ticker.C:
		}
	}
}

func (host Host) showResource(ctx context.Context, resourceID string, relay bool) (map[string][]string, error) {
	result, err := host.Launcher.RunInvocation(ctx, child.ProfileResourceShow, child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Relay: relay}}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return nil, fmt.Errorf("effective systemd property observation failed: %w", err)
	}
	effective, parseErr := parseShowProperties(result.Stdout)
	clear(result.Stdout)
	return effective, parseErr
}

func verifyApplicationIdentity(effective map[string][]string, units UnitSet) error {
	if !singleProperty(effective, "ActiveState", "active") || !singleProperty(effective, "SubState", "running") || !singleProperty(effective, "ControlGroup", units.Confinement.Cgroup) {
		return fmt.Errorf("managed application unit is not active in exact cgroup")
	}
	pid64, err := strconv.ParseInt(singleValue(effective, "MainPID"), 10, 32)
	if err != nil || pid64 <= 1 {
		return fmt.Errorf("managed application MainPID is invalid")
	}
	observation, err := confinement.ObserveCgroup("/sys/fs/cgroup", units.Confinement.Cgroup)
	if err != nil || !observation.Populated || !slices.Contains(observation.PIDs, int(pid64)) {
		return fmt.Errorf("managed application MainPID is outside exact cgroup: %w", err)
	}
	for _, pid := range observation.PIDs {
		uid, gid, identityErr := processIdentity(pid)
		if identityErr != nil || uid != units.ApplicationUID || gid != units.ApplicationGID {
			return fmt.Errorf("managed application cgroup identity differs: %w", identityErr)
		}
	}
	digest, err := processExecutableDigest(int(pid64))
	if err != nil || digest != units.Bundle.ExecutableDigest {
		return fmt.Errorf("managed application executable identity differs: %w", err)
	}
	return nil
}

func singleValue(values map[string][]string, name string) string {
	if len(values[name]) != 1 {
		return ""
	}
	return values[name][0]
}

func processIdentity(pid int) (uint32, uint32, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, 0, err
	}
	var uid, gid uint64
	foundUID, foundGID := false, false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			values := make([]uint64, 4)
			for i := range values {
				values[i], err = strconv.ParseUint(fields[i+1], 10, 32)
				if err != nil || values[i] != values[0] {
					return 0, 0, fmt.Errorf("process UID set differs")
				}
			}
			uid = values[0]
			foundUID = true
		case "Gid:":
			values := make([]uint64, 4)
			for i := range values {
				values[i], err = strconv.ParseUint(fields[i+1], 10, 32)
				if err != nil || values[i] != values[0] {
					return 0, 0, fmt.Errorf("process GID set differs")
				}
			}
			gid = values[0]
			foundGID = true
		}
	}
	if !foundUID || !foundGID {
		return 0, 0, fmt.Errorf("process credential identity absent")
	}
	return uint32(uid), uint32(gid), nil
}

func processExecutableDigest(pid int) (string, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (host Host) verifyEffectiveRelay(ctx context.Context, resourceID string, units UnitSet) error {
	short := strings.TrimPrefix(resourceID, "res_")[:20]
	cgroup := "/system.slice/lanpanel-relay-" + short + ".service"
	directives := []string{"ActiveState=active", "SubState=running", "User=" + fmt.Sprint(units.RelayUID), "Group=" + fmt.Sprint(units.RelayGID), "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictSUIDSGID=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectProc=invisible", "ProcSubset=pid", "RestrictAddressFamilies=AF_UNIX", "TemporaryFileSystem=/run:ro", "BindReadOnlyPaths=" + filepath.Dir(units.Paths.BackendSocket) + ":/backend", "InaccessiblePaths=/proc", "UMask=0007"}
	policy, err := confinement.RelayPolicy(resourceID, cgroup, directives)
	if err != nil {
		return err
	}
	if units.RelayUID == 0 || units.RelayGID == 0 {
		return fmt.Errorf("relay identity unavailable")
	}
	if err := host.verifyEffectiveRelayUnit(ctx, resourceID, policy); err != nil {
		return fmt.Errorf("effective relay confinement: %w", err)
	}
	return nil
}

func (host Host) verifyEffectiveRelayUnit(ctx context.Context, resourceID string, policy confinement.UnitPolicy) error {
	result, err := host.Launcher.RunInvocation(ctx, child.ProfileResourceShow, child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Relay: true}}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("effective relay property observation failed: %w", err)
	}
	effective, err := parseShowProperties(result.Stdout)
	clear(result.Stdout)
	if err != nil {
		return err
	}
	if !singleProperty(effective, "ActiveState", "active") || !singleProperty(effective, "SubState", "running") || !singleProperty(effective, "ControlGroup", policy.Cgroup) {
		return fmt.Errorf("effective relay service state or cgroup differs")
	}
	observed, err := confinement.ObserveCgroup("/sys/fs/cgroup", policy.Cgroup)
	if err != nil || !observed.Populated || len(observed.PIDs) == 0 {
		return fmt.Errorf("effective relay cgroup unavailable: %w", err)
	}
	return confinement.VerifyEffectiveRelay(policy, effective)
}

func singleProperty(values map[string][]string, name, want string) bool {
	return len(values[name]) == 1 && values[name][0] == want
}

func parseShowProperties(data []byte) (map[string][]string, error) {
	result := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || name == "" {
			return nil, fmt.Errorf("effective systemd property malformed")
		}
		result[name] = append(result[name], value)
	}
	return result, nil
}

func putManagedFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := ensureRootDirectory(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	staging := filepath.Join(filepath.Dir(path), ".lanpanel-filetxn")
	if err := ensureRootDirectory(staging, 0o700); err != nil {
		return err
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: owner, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(store.Close)
	metadata := filetxn.Metadata{Owner: owner, Mode: mode}
	disposition := filetxn.CreateOnly
	if _, statErr := os.Lstat(path); statErr == nil {
		disposition = filetxn.ReplaceOnly
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	_, err = store.Put(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, Existing: &metadata, New: metadata, MaxBytes: int64(len(data))}, data, disposition)
	return err
}

func waitOwnedEndpointsGone(ctx context.Context, resourceID string) error {
	paths, err := resource.DerivePaths(resourceID)
	if err != nil {
		return err
	}
	timer := time.NewTicker(20 * time.Millisecond)
	defer timer.Stop()
	for {
		missing := true
		for _, path := range []string{paths.FrontendSocket, paths.BackendSocket} {
			var stat unix.Stat_t
			if err := unix.Lstat(path, &stat); err == nil {
				missing = false
			} else if !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
		if missing {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("owned endpoint stop observation timed out: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func ensureDirectory(path string, mode uint32, owner, group int) error {
	if owner == 0 && group == 0 {
		return ensureRootDirectory(path, mode)
	}
	if err := validateOwnedDirectory(path, mode, owner, group); err == nil {
		return nil
	}
	if err := ensureRootDirectory(path, 0o700); err != nil {
		return err
	}
	if err := os.Chown(path, owner, group); err != nil {
		return err
	}
	fileMode := os.FileMode(mode & 0o777)
	if mode&0o2000 != 0 {
		fileMode |= os.ModeSetgid
	}
	if err := os.Chmod(path, fileMode); err != nil {
		return err
	}
	return validateOwnedDirectory(path, mode, owner, group)
}

func validateOwnedDirectory(path string, mode uint32, owner, group int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat := info.Sys().(*unix.Stat_t)
	if !info.IsDir() || stat.Mode&0o7777 != mode || int(stat.Uid) != owner || int(stat.Gid) != group {
		return fmt.Errorf("managed directory identity differs")
	}
	return nil
}

func ensureRootDirectory(path string, mode uint32) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("managed-process directory is invalid")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	for index, component := range components {
		wanted := uint32(0o755)
		if index == len(components)-1 {
			wanted = mode
		}
		created := false
		if err := unix.Mkdirat(fd, component, wanted); err == nil {
			created = true
		} else if !errors.Is(err, unix.EEXIST) {
			return err
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		if unix.Fstat(next, &stat) != nil {
			_ = unix.Close(next)
			return fmt.Errorf("inspect managed-process directory")
		}
		writableAllowed := index == len(components)-1 && mode == 0o777
		trustedBootstrapGroup := stat.Uid == 0 && stat.Gid != 0 && (strings.HasPrefix(path, "/etc/lanpanel") || strings.HasPrefix(path, "/run/lanpanel"))
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Gid != 0 && !trustedBootstrapGroup || !writableAllowed && stat.Mode&0o022 != 0 || index == len(components)-1 && stat.Mode&0o777 != mode {
			_ = unix.Close(next)
			return fmt.Errorf("managed-process directory identity is unsafe")
		}
		if created {
			if unix.Fsync(fd) != nil {
				_ = unix.Close(next)
				return fmt.Errorf("sync managed-process directory parent")
			}
		}
		_ = unix.Close(fd)
		fd = next
	}
	return nil
}
