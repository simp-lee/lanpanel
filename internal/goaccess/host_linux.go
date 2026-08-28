//go:build linux

package goaccess

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/identity"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type invocationLauncher interface {
	RunInvocation(context.Context, child.ProfileID, child.Invocation, []byte) (child.Result, error)
}

const (
	finalRetentionTimeout       = 90 * time.Second
	retentionQuiesceTimeout     = 90 * time.Second
	unitInventoryTimeout        = 30 * time.Second
	stopTimeout                 = time.Minute
	daemonReloadTimeout         = 30 * time.Second
	endpointEvidenceTimeout     = 2 * time.Second
	retentionSettlementTimeout  = 2 * time.Second
	retirementDeadlineSlack     = 5 * time.Second
	GenerationRetirementTimeout = unitInventoryTimeout + stopTimeout + retentionQuiesceTimeout + finalRetentionTimeout + stopTimeout + unitInventoryTimeout + endpointEvidenceTimeout + retentionSettlementTimeout + retentionSettlementTimeout + daemonReloadTimeout + retentionSettlementTimeout + unitInventoryTimeout + endpointEvidenceTimeout + retirementDeadlineSlack
)

type (
	Host struct {
		launcher         invocationLauncher
		endpointObserver func(context.Context, string, bool) error
	}
	ServiceGeneration struct {
		ResourceID string
		Generation uint64
	}
)

func boundedDirectoryEntries(ctx context.Context, path string, count *int) ([]os.DirEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	result := []os.DirEntry{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, readErr := file.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, readErr
		}
		*count += len(entries)
		if *count > 8192 {
			return nil, fmt.Errorf("GoAccess inventory entry limit exceeded")
		}
		result = append(result, entries...)
		if errors.Is(readErr, io.EOF) {
			return result, nil
		}
	}
}

func DiscoverServiceGenerations(ctx context.Context) ([]ServiceGeneration, error) {
	count := 0
	entries, err := boundedDirectoryEntries(ctx, "/etc/systemd/system", &count)
	if err != nil {
		return nil, err
	}
	result := []ServiceGeneration{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "lanpanel-goaccess-res_") || !strings.HasSuffix(name, ".service") {
			continue
		}
		identity := strings.TrimSuffix(strings.TrimPrefix(name, "lanpanel-goaccess-"), ".service")
		separator := strings.LastIndexByte(identity, '-')
		if separator < 0 {
			return nil, fmt.Errorf("GoAccess service unit name invalid")
		}
		resourceID := identity[:separator]
		generation, parseErr := strconv.ParseUint(identity[separator+1:], 10, 64)
		if parseErr != nil || generation == 0 || !validResourceID(resourceID) {
			return nil, fmt.Errorf("GoAccess service unit generation invalid")
		}
		info, observeErr := os.Lstat(filepath.Join("/etc/systemd/system", name))
		if observeErr != nil {
			return nil, observeErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0o644 {
			return nil, fmt.Errorf("GoAccess service unit inventory unsafe")
		}
		result = append(result, ServiceGeneration{ResourceID: resourceID, Generation: generation})
	}
	slices.SortFunc(result, func(a, b ServiceGeneration) int {
		if value := strings.Compare(a.ResourceID, b.ResourceID); value != 0 {
			return value
		}
		return cmp.Compare(a.Generation, b.Generation)
	})
	return result, nil
}

func NewFixedHost() (Host, error) {
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	return Host{launcher: launcher}, err
}

func (host Host) Stage(ctx context.Context, resourceID string, candidate Candidate) error {
	if host.launcher == nil || candidate.ServiceIdentity == "" || resourceID != candidate.ResourceID || !validInstallationID(candidate.InstallationID) {
		return fmt.Errorf("GoAccess host authority incomplete")
	}
	if err := verifyAccountAuthority(candidate, candidate.RetainShared, candidate.RetainShared); err != nil {
		return err
	}
	if candidate.ReuseApplied {
		if err := host.Verify(ctx, candidate); err != nil {
			return err
		}
		return probeWebSocket(ctx, candidate.Paths.Endpoint, candidate.WebSocketPath)
	}
	if candidate.RetainState {
		if err := host.ensureRetainedStateStopped(ctx, candidate); err != nil {
			return err
		}
	}
	if err := cleanupCandidateStaging(candidate); err != nil {
		return err
	}
	inv := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Generation: candidate.Generation}}
	if !candidate.RetainShared {
		if _, markerErr := os.Lstat(candidate.Paths.Sysusers); errors.Is(markerErr, os.ErrNotExist) {
			if err := verifyAbsentAccountTraces(candidate); err != nil {
				return err
			}
		} else if markerErr != nil {
			return markerErr
		}
		for _, path := range []string{candidate.Paths.ResourceRoot, filepath.Dir(candidate.Paths.AccessLog), candidate.Paths.Sysusers} {
			if _, observeErr := os.Lstat(path); observeErr == nil {
				return fmt.Errorf("first GoAccess enable found retained shared state")
			} else if !errors.Is(observeErr, os.ErrNotExist) {
				return observeErr
			}
		}
		if err := replaceFile(candidate.Paths.Sysusers, candidate.Sysusers, 0, 0, 0o644); err != nil {
			return err
		}
		accountResult, accountErr := host.launcher.RunInvocation(ctx, child.ProfileGoAccessAccounts, inv, nil)
		if accountErr != nil || accountResult.ExitCode != 0 {
			return fmt.Errorf("GoAccess account creation failed: exit=%d: %w", accountResult.ExitCode, accountErr)
		}
		if err := verifyAccountAuthority(candidate, true, true); err != nil {
			return err
		}
	}
	for _, directory := range []struct {
		path           string
		uid, gid, mode uint32
	}{{"/var/lib/lanpanel/goaccess", 0, 0, 0o711}, {candidate.Paths.ResourceRoot, 0, 0, 0o711}, {filepath.Join(candidate.Paths.ResourceRoot, "generations"), 0, 0, 0o711}, {candidate.Paths.StateRoot, 0, 0, 0o711}, {candidate.Paths.Database, candidate.UID, candidate.GID, 0o750}, {filepath.Dir(candidate.Paths.Report), candidate.UID, candidate.NginxGID, 0o2750}, {"/var/log/lanpanel/goaccess", 0, 0, 0o711}, {filepath.Dir(candidate.Paths.AccessLog), candidate.UID, candidate.GID, resourceLogDirectoryMode}, {"/run/lanpanel-goaccess", 0, candidate.NginxGID, 0o750}} {
		if err := ensureDirectory(directory.path, directory.uid, directory.gid, directory.mode); err != nil {
			return err
		}
	}
	if err := ensureEmptyFile(globalRetentionLockPath, 0, 0, 0o600); err != nil {
		return err
	}
	if err := ensureFile(candidate.Paths.AccessLog, candidate.UID, candidate.GID, 0o640); err != nil {
		return err
	}
	if err := ensureEmptyFile(candidate.Paths.RetentionLock, candidate.UID, candidate.GID, 0o600); err != nil {
		return err
	}
	for _, file := range []struct {
		path string
		data []byte
	}{{candidate.Paths.ServiceUnit, candidate.Service}, {candidate.Paths.RelayUnit, candidate.Relay}, {candidate.Paths.SocketUnit, candidate.Socket}, {candidate.Paths.RetentionUnit, candidate.RetentionService}, {candidate.Paths.RetentionTimer, candidate.RetentionTimer}} {
		if err := replaceFile(file.path, file.data, 0, 0, 0o644); err != nil {
			return err
		}
	}
	reload, reloadErr := host.launcher.RunInvocation(ctx, child.ProfileSystemctl, child.Invocation{}, nil)
	if reloadErr != nil || reload.ExitCode != 0 {
		return fmt.Errorf("GoAccess daemon reload failed: exit=%d: %w", reload.ExitCode, reloadErr)
	}
	result, runErr := host.launcher.RunInvocation(ctx, child.ProfileGoAccessStart, inv, nil)
	if runErr != nil || result.ExitCode != 0 {
		return fmt.Errorf("GoAccess start failed: exit=%d: %w", result.ExitCode, runErr)
	}
	if err := host.Verify(ctx, candidate); err != nil {
		return err
	}
	return probeWebSocket(ctx, candidate.Paths.Endpoint, candidate.WebSocketPath)
}

func verifyAbsentAccountTraces(candidate Candidate) error {
	names := map[string]bool{candidate.User: true, candidate.RelayUser: true}
	for _, path := range []string{"/etc/shadow", "/etc/gshadow"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			name, _, _ := strings.Cut(line, ":")
			if names[name] {
				return fmt.Errorf("GoAccess account trace exists without origin marker")
			}
		}
	}
	return nil
}

func verifyAccountAuthority(candidate Candidate, requireComplete, requireLocked bool) error {
	markerInfo, observeMarkerErr := os.Lstat(candidate.Paths.Sysusers)
	markerPresent := observeMarkerErr == nil
	if markerPresent {
		stat, ok := markerInfo.Sys().(*syscall.Stat_t)
		if !ok || !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || markerInfo.Mode().Perm() != 0o644 {
			return fmt.Errorf("GoAccess account origin marker unsafe")
		}
	} else if !errors.Is(observeMarkerErr, os.ErrNotExist) {
		return observeMarkerErr
	}
	marker, markerErr := os.ReadFile(candidate.Paths.Sysusers)
	if !markerPresent {
		marker = nil
		markerErr = observeMarkerErr
	}
	if markerPresent && !bytes.Equal(marker, candidate.Sysusers) {
		return fmt.Errorf("GoAccess account origin marker changed")
	}
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return markerErr
	}
	if requireComplete && !markerPresent {
		return fmt.Errorf("GoAccess retained account origin marker missing")
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return err
	}
	groupBytes, err := os.ReadFile("/etc/group")
	if err != nil {
		return err
	}
	if err := verifyGoAccessAccountDatabases(candidate, markerPresent, requireComplete, passwd, groupBytes); err != nil {
		return err
	}
	if markerPresent && requireLocked {
		present, identities, inspectErr := identity.InspectResourceAccountFiles(candidate.Accounts, "/etc/passwd", "/etc/group", "/etc/shadow")
		if inspectErr != nil {
			return inspectErr
		}
		if !present || len(identities) != 2 {
			return fmt.Errorf("GoAccess exact account inventory missing")
		}
		expectedIdentities := map[string]struct{ uid, gid uint32 }{candidate.User: {candidate.UID, candidate.GID}, candidate.RelayUser: {candidate.RelayUID, candidate.RelayGID}}
		for _, observed := range identities {
			expected, ok := expectedIdentities[observed.User]
			if !ok || observed.UID != expected.uid || observed.GID != expected.gid {
				return fmt.Errorf("GoAccess exact account identity differs")
			}
		}
		shadow, shadowErr := os.ReadFile("/etc/shadow")
		if shadowErr != nil {
			return shadowErr
		}
		locked := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(string(shadow)), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) > 1 && (strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*")) {
				locked[fields[0]] = true
			}
		}
		for _, name := range []string{candidate.User, candidate.RelayUser} {
			if !locked[name] {
				return fmt.Errorf("GoAccess user is not locked")
			}
		}
	}
	return nil
}

func verifyGoAccessAccountDatabases(candidate Candidate, markerPresent, requireComplete bool, passwd, groupBytes []byte) error {
	type expected struct {
		name        string
		id, primary uint32
	}
	users := []expected{{candidate.User, candidate.UID, candidate.GID}, {candidate.RelayUser, candidate.RelayUID, candidate.RelayGID}}
	primaryOwners := map[uint32]string{candidate.GID: candidate.User, candidate.RelayGID: candidate.RelayUser}
	comments := map[string]string{candidate.User: candidate.Accounts.Application.Comment, candidate.RelayUser: candidate.Accounts.Relay.Comment}
	groups := []expected{{candidate.Group, candidate.GID, 0}, {candidate.RelayGroup, candidate.RelayGID, 0}}
	foundUsers := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(passwd)), "\n") {
		fields := strings.Split(line, ":")
		managedName := fields[0] == candidate.User || fields[0] == candidate.RelayUser
		if len(fields) != 7 {
			if managedName {
				return fmt.Errorf("GoAccess user identity is malformed")
			}
			continue
		}
		id, idErr := strconv.ParseUint(fields[2], 10, 32)
		primary, primaryErr := strconv.ParseUint(fields[3], 10, 32)
		if idErr != nil || primaryErr != nil {
			if managedName {
				return fmt.Errorf("GoAccess user identity is malformed")
			}
			continue
		}
		if owner, protected := primaryOwners[uint32(primary)]; protected && fields[0] != owner {
			return fmt.Errorf("GoAccess primary group identity collides")
		}
		for _, want := range users {
			if fields[0] == want.name && uint32(id) != want.id || uint32(id) == want.id && fields[0] != want.name {
				return fmt.Errorf("GoAccess user identity collides")
			}
			if fields[0] == want.name {
				if !markerPresent || fields[1] != identity.ManagedPasswordPlaceholder || uint32(primary) != want.primary || fields[4] != comments[want.name] || fields[5] != "/nonexistent" || fields[6] != "/usr/sbin/nologin" {
					return fmt.Errorf("GoAccess user identity differs")
				}
				foundUsers[want.name] = true
			}
		}
	}
	foundGroups := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(groupBytes)), "\n") {
		fields := strings.Split(line, ":")
		managedName := fields[0] == candidate.Group || fields[0] == candidate.RelayGroup
		if len(fields) != 4 {
			if managedName {
				return fmt.Errorf("GoAccess group identity is malformed")
			}
			continue
		}
		id, idErr := strconv.ParseUint(fields[2], 10, 32)
		if idErr != nil {
			if managedName {
				return fmt.Errorf("GoAccess group identity is malformed")
			}
			continue
		}
		for _, want := range groups {
			if fields[0] == want.name && uint32(id) != want.id || uint32(id) == want.id && fields[0] != want.name {
				return fmt.Errorf("GoAccess group identity collides")
			}
			if fields[0] == want.name {
				if !markerPresent || fields[1] != identity.ManagedPasswordPlaceholder || fields[3] != "" {
					return fmt.Errorf("GoAccess group identity differs")
				}
				foundGroups[want.name] = true
			}
		}
		for _, user := range users {
			for _, member := range strings.Split(fields[3], ",") {
				if member == user.name {
					return fmt.Errorf("GoAccess user has supplementary group")
				}
			}
		}
	}
	if markerPresent && requireComplete {
		for _, want := range users {
			if !foundUsers[want.name] {
				return fmt.Errorf("GoAccess user missing")
			}
		}
		for _, want := range groups {
			if !foundGroups[want.name] {
				return fmt.Errorf("GoAccess group missing")
			}
		}
	}
	return nil
}

func RunAccountGuard(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("goaccess-account-guard accepts no arguments")
	}
	installationID, resourceID, generationText := os.Getenv("LANPANEL_INSTALLATION_ID"), os.Getenv("LANPANEL_RESOURCE_ID"), os.Getenv("LANPANEL_GOACCESS_GENERATION")
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil || generation == 0 || !validInstallationID(installationID) || !validResourceID(resourceID) {
		return fmt.Errorf("GoAccess account guard environment invalid")
	}
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	authority, err := deriveAccountAuthority(installationID, resourceID)
	if err != nil {
		return err
	}
	candidate := Candidate{InstallationID: installationID, ResourceID: resourceID, Generation: generation, Paths: paths, UID: authority.uid, GID: authority.gid, RelayUID: authority.relayUID, RelayGID: authority.relayGID, User: authority.user, Group: authority.group, RelayUser: authority.relayUser, RelayGroup: authority.relayGroup, Accounts: authority.accounts, Sysusers: authority.sysusers}
	return verifyAccountAuthority(candidate, true, true)
}

func Installed(resourceID string, generation uint64) (bool, error) {
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(paths.ServiceUnit)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("GoAccess service unit identity unsafe")
	}
	return true, nil
}

func (host Host) Verify(ctx context.Context, candidate Candidate) error {
	if err := verifyAccountAuthority(candidate, true, true); err != nil {
		return err
	}
	if host.launcher == nil {
		return fmt.Errorf("GoAccess host unavailable")
	}
	if err := verifyManagedServiceFiles(candidate.Paths, candidate.ServiceIdentity); err != nil {
		return err
	}
	result, err := host.launcher.RunInvocation(ctx, child.ProfileGoAccessShow, child.Invocation{Resource: &child.ResourceInvocation{ResourceID: candidate.ResourceID, Generation: candidate.Generation}}, nil)
	if err != nil || result.ExitCode != 0 {
		return fmt.Errorf("GoAccess effective units unavailable: %w", err)
	}
	units, parseErr := parseEffectiveUnits(string(result.Stdout))
	if parseErr != nil {
		return parseErr
	}
	serviceName, relayName, socketName, timerName, retentionName := filepath.Base(candidate.Paths.ServiceUnit), filepath.Base(candidate.Paths.RelayUnit), filepath.Base(candidate.Paths.SocketUnit), filepath.Base(candidate.Paths.RetentionTimer), filepath.Base(candidate.Paths.RetentionUnit)
	service, serviceOK := units[serviceName]
	relay, relayOK := units[relayName]
	socket, socketOK := units[socketName]
	timer, timerOK := units[timerName]
	retention, retentionOK := units[retentionName]
	exact := func(values map[string]string, key, want string) bool { return values[key] == want }
	if !serviceOK || !relayOK || !socketOK || !exact(service, "LoadState", "loaded") || !exact(relay, "LoadState", "loaded") || !exact(socket, "LoadState", "loaded") || !exact(timer, "LoadState", "loaded") || !exact(retention, "LoadState", "loaded") || !exact(service, "UnitFileState", "enabled") || !exact(relay, "UnitFileState", "enabled") || !exact(socket, "UnitFileState", "enabled") || !exact(timer, "UnitFileState", "enabled") || !exact(service, "ActiveState", "active") || !exact(service, "User", fmt.Sprint(candidate.UID)) || !exact(service, "Group", fmt.Sprint(candidate.GID)) || !exact(service, "SupplementaryGroups", "") || !exact(service, "PrivateNetwork", "yes") || !exact(service, "RestrictAddressFamilies", "AF_INET") || !exact(service, "CapabilityBoundingSet", "") || !exact(service, "AmbientCapabilities", "") || !exact(service, "FragmentPath", candidate.Paths.ServiceUnit) || !exact(service, "DropInPaths", "") || !exact(relay, "ActiveState", "active") || !exact(relay, "User", fmt.Sprint(candidate.RelayUID)) || !exact(relay, "Group", fmt.Sprint(candidate.RelayGID)) || !exact(relay, "PrivateNetwork", "yes") || !exact(relay, "JoinsNamespaceOf", serviceName) || !exact(relay, "RestrictAddressFamilies", "AF_INET") || !exact(relay, "FragmentPath", candidate.Paths.RelayUnit) || !exact(relay, "DropInPaths", "") || !exact(socket, "ActiveState", "active") || !exact(socket, "User", "root") || !exact(socket, "Group", fmt.Sprint(candidate.NginxGID)) || !exact(socket, "SocketUser", "root") || !exact(socket, "SocketGroup", fmt.Sprint(candidate.NginxGID)) || !exact(socket, "SocketMode", "0660") || !exact(socket, "RuntimeDirectory", "lanpanel-goaccess") || !exact(socket, "RuntimeDirectoryMode", "0750") || !exact(socket, "RuntimeDirectoryPreserve", "yes") || !exact(socket, "FragmentPath", candidate.Paths.SocketUnit) || !exact(socket, "DropInPaths", "") || !timerOK || !exact(timer, "ActiveState", "active") || !exact(timer, "FragmentPath", candidate.Paths.RetentionTimer) || !exact(timer, "DropInPaths", "") || !retentionOK || !validRetentionRuntime(retention) || !exact(retention, "User", "root") || !exact(retention, "Group", "root") || !exact(retention, "PrivateNetwork", "yes") || !exact(retention, "CapabilityBoundingSet", "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_SYS_PTRACE") || !exact(retention, "AmbientCapabilities", "") || !exact(retention, "FragmentPath", candidate.Paths.RetentionUnit) || !exact(retention, "DropInPaths", "") {
		return fmt.Errorf("GoAccess effective isolation differs")
	}
	require := func(values map[string]string, expected map[string]string) bool {
		for key, want := range expected {
			if values[key] != want {
				return false
			}
		}
		return true
	}
	common := map[string]string{"NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictSUIDSGID": "yes", "PrivateNetwork": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "KillMode": "control-group"}
	serviceExpected := map[string]string{}
	relayExpected := map[string]string{}
	retentionExpected := map[string]string{}
	for key, value := range common {
		serviceExpected[key] = value
		relayExpected[key] = value
		retentionExpected[key] = value
	}
	serviceExpected["ReadWritePaths"] = candidate.Paths.StateRoot
	serviceExpected["UMask"] = "0027"
	relayExpected["ReadWritePaths"] = ""
	relayExpected["UMask"] = "0077"
	relayExpected["ProtectProc"] = "invisible"
	relayExpected["ProcSubset"] = "pid"
	retentionExpected["ReadWritePaths"] = filepath.Dir(candidate.Paths.AccessLog) + " " + candidate.Paths.RetentionLock + " /var/log/lanpanel/goaccess /var/log/lanpanel/nginx-rejections.log"
	retentionExpected["CapabilityBoundingSet"] = "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_SYS_PTRACE"
	retentionExpected["UMask"] = "0077"
	retentionExpected["RestrictAddressFamilies"] = "AF_UNIX"
	retentionExpected["TimeoutStartUSec"] = "1min 15s"
	if !require(service, serviceExpected) || !require(relay, relayExpected) || !require(retention, retentionExpected) || socket["Listen"] != candidate.Paths.Endpoint+" (Stream)" || socket["Service"] != relayName || timer["Unit"] != retentionName || relay["Sockets"] != socketName || !strings.Contains(service["ExecStart"], "/usr/bin/goaccess --no-global-config") || !strings.Contains(service["ExecStart"], candidate.Paths.Database) || !strings.Contains(service["ExecStart"], candidate.Paths.Report) || !strings.Contains(relay["ExecStart"], "/usr/lib/lanpanel/lanpanel goaccess-relay") || !strings.Contains(relay["Environment"], "LANPANEL_INSTALLATION_ID="+candidate.InstallationID) || !strings.Contains(relay["Environment"], "LANPANEL_RESOURCE_ID="+candidate.ResourceID) || !strings.Contains(relay["Environment"], fmt.Sprintf("LANPANEL_GOACCESS_GENERATION=%d", candidate.Generation)) || !strings.Contains(retention["ExecStart"], "/usr/lib/lanpanel/lanpanel goaccess-retention") || strings.Contains(retention["ExecStartEx"], "flags=privileged") || !strings.Contains(retention["Environment"], "LANPANEL_INSTALLATION_ID="+candidate.InstallationID) || !strings.Contains(retention["Environment"], "LANPANEL_RESOURCE_ID="+candidate.ResourceID) || !strings.Contains(retention["Environment"], fmt.Sprintf("LANPANEL_GOACCESS_GENERATION=%d", candidate.Generation)) {
		return fmt.Errorf("GoAccess effective hardening differs")
	}
	paths, err := DerivePaths(candidate.ResourceID, candidate.Generation)
	if err != nil {
		return err
	}
	if err = verifyEnablementLinks(candidate.Paths, true); err != nil {
		return err
	}
	if err = verifyRuntimePaths(ctx, candidate); err != nil {
		return err
	}
	return host.waitEndpoint(ctx, paths.Endpoint, true)
}

func enablementLinks(paths Paths) map[string]string {
	return map[string]string{paths.ServiceEnablement: paths.ServiceUnit, paths.RelayEnablement: paths.RelayUnit, paths.SocketEnablement: paths.SocketUnit, paths.RetentionEnablement: paths.RetentionTimer}
}

func verifyEnablementLinks(paths Paths, requirePresent bool) error {
	for path, target := range enablementLinks(paths) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && !requirePresent {
			continue
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		observed, readErr := os.Readlink(path)
		if !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 || stat.Gid != 0 || readErr != nil || observed != target {
			return errors.Join(fmt.Errorf("GoAccess enablement link authority changed"), readErr)
		}
	}
	return nil
}

func verifyEnablementLinksAbsent(paths Paths) error {
	for path := range enablementLinks(paths) {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return fmt.Errorf("GoAccess enablement link remained")
			}
			return err
		}
	}
	return nil
}

func (host Host) CleanupCandidate(ctx context.Context, candidate Candidate) error {
	if host.launcher == nil {
		return fmt.Errorf("GoAccess host unavailable")
	}
	if candidate.ReuseApplied {
		return nil
	}
	if err := cleanupCandidateStaging(candidate); err != nil {
		return err
	}
	files := []struct {
		path    string
		content []byte
	}{{candidate.Paths.ServiceUnit, candidate.Service}, {candidate.Paths.RelayUnit, candidate.Relay}, {candidate.Paths.SocketUnit, candidate.Socket}, {candidate.Paths.RetentionUnit, candidate.RetentionService}, {candidate.Paths.RetentionTimer, candidate.RetentionTimer}}
	present := 0
	for _, file := range files {
		info, err := os.Lstat(file.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0o644 {
			return fmt.Errorf("GoAccess candidate cleanup authority unsafe")
		}
		current, readErr := os.ReadFile(file.path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(current, file.content) {
			return fmt.Errorf("GoAccess candidate cleanup authority changed")
		}
		present++
	}
	if present == len(files) {
		if err := host.Retire(ctx, candidate.ResourceID, candidate.Generation, candidate.ServiceIdentity, candidate.UnitIdentities); err != nil {
			return err
		}
	} else {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		endpointErr := host.waitEndpoint(probeCtx, candidate.Paths.Endpoint, false)
		cancel()
		if endpointErr != nil {
			return endpointErr
		}
		for _, file := range files {
			if removeErr := os.Remove(file.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return removeErr
			}
		}
		parent, openErr := os.Open("/etc/systemd/system")
		if openErr != nil {
			return openErr
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if err := errors.Join(syncErr, closeErr); err != nil {
			return err
		}
		reload, reloadErr := host.launcher.RunInvocation(ctx, child.ProfileSystemctl, child.Invocation{}, nil)
		if reloadErr != nil || reload.ExitCode != 0 {
			return errors.Join(reloadErr, fmt.Errorf("GoAccess partial cleanup reload failed"))
		}
		complete, verifyErr := host.RetirementComplete(ctx, candidate.ResourceID, candidate.Generation, candidate.StateGeneration, false)
		if verifyErr != nil {
			return verifyErr
		}
		if !complete {
			return fmt.Errorf("GoAccess partial cleanup remains loaded")
		}
	}
	if !candidate.RetainState {
		if err := removeCandidateState(ctx, candidate); err != nil {
			return err
		}
	}
	if !candidate.RetainShared {
		if err := verifyRetainedInventory(ctx, candidate.InstallationID, candidate.ResourceID, nil); err != nil {
			return err
		}
		return host.cleanupRetainedShared(ctx, candidate.InstallationID, candidate.ResourceID)
	}
	return nil
}

func cleanupCandidateStaging(candidate Candidate) error {
	files := []struct {
		path string
		data []byte
	}{{candidate.Paths.Sysusers, candidate.Sysusers}, {candidate.Paths.ServiceUnit, candidate.Service}, {candidate.Paths.RelayUnit, candidate.Relay}, {candidate.Paths.SocketUnit, candidate.Socket}, {candidate.Paths.RetentionUnit, candidate.RetentionService}, {candidate.Paths.RetentionTimer, candidate.RetentionTimer}}
	for _, file := range files {
		staging := filepath.Join(filepath.Dir(file.path), "."+filepath.Base(file.path)+".lanpanel")
		if err := cleanupExactStaging(staging, file.data, 0, 0); err != nil {
			return err
		}
	}
	return nil
}

func cleanupExactStaging(staging string, expected []byte, uid, gid uint32) error {
	fd, err := unix.Open(staging, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	handle := os.NewFile(uintptr(fd), staging)
	data, readErr := io.ReadAll(io.LimitReader(handle, int64(len(expected))+1))
	closeErr := handle.Close()
	if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != 0o644 || stat.Size < 0 || stat.Size > int64(len(expected)) || readErr != nil || len(data) > len(expected) || !bytes.Equal(data, expected[:len(data)]) {
		return errors.Join(fmt.Errorf("GoAccess staging recovery authority changed"), statErr, readErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	parentPath := filepath.Dir(staging)
	parent, openErr := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return openErr
	}
	var current unix.Stat_t
	observeErr := unix.Fstatat(parent, filepath.Base(staging), &current, unix.AT_SYMLINK_NOFOLLOW)
	if observeErr == nil && (current.Dev != stat.Dev || current.Ino != stat.Ino || current.Mode&unix.S_IFMT != unix.S_IFREG) {
		observeErr = fmt.Errorf("GoAccess staging recovery identity raced")
	}
	unlinkErr := error(nil)
	if observeErr == nil {
		unlinkErr = unix.Unlinkat(parent, filepath.Base(staging), 0)
	}
	if observeErr == nil && unlinkErr == nil {
		unlinkErr = unix.Fsync(parent)
	}
	parentCloseErr := unix.Close(parent)
	return errors.Join(observeErr, unlinkErr, parentCloseErr)
}

func removeCandidateState(ctx context.Context, candidate Candidate) error {
	return removeOwnedTree(ctx, candidate.Paths.StateRoot, 0, 0, 0o711)
}

func (host Host) ensureRetainedStateStopped(ctx context.Context, candidate Candidate) error {
	if candidate.RetainedServiceGeneration == 0 || candidate.RetainedServiceGeneration >= candidate.Generation || candidate.RetainedServiceIdentity == "" || len(candidate.RetainedUnitIdentities) != 5 {
		return fmt.Errorf("retained GoAccess service authority incomplete")
	}
	if _, err := verifyGenerationUnitFiles(candidate.ResourceID, candidate.RetainedServiceGeneration, candidate.RetainedUnitIdentities); err != nil {
		return err
	}
	paths, err := DerivePaths(candidate.ResourceID, candidate.RetainedServiceGeneration)
	if err != nil {
		return err
	}
	if err = verifyEnablementLinks(paths, false); err != nil {
		return err
	}
	return host.EnsureStopped(ctx, candidate.ResourceID, candidate.RetainedServiceGeneration)
}

func verifyGenerationUnitFiles(resourceID string, generation uint64, unitIdentities []string) ([]string, error) {
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return nil, err
	}
	if len(unitIdentities) != 5 {
		return nil, fmt.Errorf("GoAccess unit retirement inventory incomplete")
	}
	unitPaths := []string{paths.ServiceUnit, paths.RelayUnit, paths.SocketUnit, paths.RetentionUnit, paths.RetentionTimer}
	for index, path := range unitPaths {
		if !strings.HasPrefix(unitIdentities[index], "sha256:") {
			return nil, fmt.Errorf("GoAccess unit retirement identity invalid")
		}
		info, observeErr := os.Lstat(path)
		if errors.Is(observeErr, os.ErrNotExist) {
			continue
		}
		if observeErr != nil {
			return nil, observeErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0o644 || info.Size() < 0 || info.Size() > 64<<10 {
			return nil, fmt.Errorf("GoAccess remaining unit file unsafe")
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		if digest(data) != unitIdentities[index] {
			return nil, fmt.Errorf("GoAccess remaining unit identity changed")
		}
	}
	return unitPaths, nil
}

func (host Host) Retire(ctx context.Context, resourceID string, generation uint64, expectedIdentity string, unitIdentities []string) error {
	if host.launcher == nil || expectedIdentity == "" {
		return fmt.Errorf("GoAccess retirement authority incomplete")
	}
	unitPaths, err := verifyGenerationUnitFiles(resourceID, generation, unitIdentities)
	if err != nil {
		return err
	}
	generationPaths, pathErr := DerivePaths(resourceID, generation)
	if pathErr != nil {
		return pathErr
	}
	if err = verifyEnablementLinks(generationPaths, false); err != nil {
		return err
	}
	alreadyRetired, completeErr := host.RetirementComplete(ctx, resourceID, generation, generation, false)
	if completeErr == nil && alreadyRetired {
		return nil
	}
	allFilesAbsent := true
	for _, path := range unitPaths {
		if _, observeErr := os.Lstat(path); observeErr == nil {
			allFilesAbsent = false
			break
		} else if !errors.Is(observeErr, os.ErrNotExist) {
			return observeErr
		}
	}
	if allFilesAbsent {
		reloadCtx, cancelReload := context.WithTimeout(ctx, daemonReloadTimeout)
		reload, reloadErr := host.launcher.RunInvocation(reloadCtx, child.ProfileSystemctl, child.Invocation{}, nil)
		cancelReload()
		if reloadErr != nil || reload.ExitCode != 0 {
			return errors.Join(completeErr, reloadErr, fmt.Errorf("GoAccess retirement recovery reload failed: exit=%d", reload.ExitCode))
		}
		alreadyRetired, completeErr = host.RetirementComplete(ctx, resourceID, generation, generation, false)
		if completeErr != nil {
			return completeErr
		}
		if !alreadyRetired {
			return fmt.Errorf("GoAccess retirement recovery remained loaded")
		}
		return nil
	}
	if completeErr != nil {
		return completeErr
	}
	mask, observeErr := host.observedUnitMask(ctx, resourceID, generation)
	if observeErr != nil {
		return observeErr
	}
	if mask != 0 {
		if err = host.stopObservedGeneration(ctx, resourceID, generation, mask); err != nil {
			return err
		}
	} else if err = host.verifyStoppedGenerationEvidence(ctx, generationPaths); err != nil {
		return err
	}
	removalPaths := []string{unitPaths[0], unitPaths[1], unitPaths[2], unitPaths[4], unitPaths[3]}
	if err = removeGenerationUnitFiles(ctx, generationPaths, removalPaths); err != nil {
		return err
	}
	parent, err := os.Open("/etc/systemd/system")
	if err != nil {
		return err
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if err = errors.Join(syncErr, closeErr); err != nil {
		return err
	}
	reloadCtx, cancelReload := context.WithTimeout(ctx, daemonReloadTimeout)
	reload, reloadErr := host.launcher.RunInvocation(reloadCtx, child.ProfileSystemctl, child.Invocation{}, nil)
	cancelReload()
	if reloadErr != nil || reload.ExitCode != 0 {
		return errors.Join(reloadErr, fmt.Errorf("GoAccess cleanup reload failed"))
	}
	complete, verifyErr := host.RetirementComplete(ctx, resourceID, generation, generation, false)
	if verifyErr != nil {
		return verifyErr
	}
	if !complete {
		return fmt.Errorf("GoAccess retirement post-removal evidence incomplete")
	}
	return nil
}

func (host Host) RemoveGenerationState(ctx context.Context, resourceID string, generation uint64) error {
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	return removeOwnedTree(ctx, paths.StateRoot, 0, 0, 0o711)
}

type RetainedGeneration struct {
	Generation      uint64
	StateGeneration uint64
	ServiceIdentity string
	UnitIdentities  []string
}

func (host Host) CleanupRetained(ctx context.Context, installationID, resourceID string, generations []RetainedGeneration) error {
	if !validInstallationID(installationID) || !validResourceID(resourceID) {
		return fmt.Errorf("GoAccess retained cleanup identity invalid")
	}
	prior := uint64(0)
	for _, item := range generations {
		if item.Generation <= prior || item.StateGeneration == 0 || item.StateGeneration > item.Generation || item.ServiceIdentity == "" || len(item.UnitIdentities) != 5 {
			return fmt.Errorf("GoAccess retained generation inventory invalid")
		}
		prior = item.Generation
	}
	if err := verifyRetainedInventory(ctx, installationID, resourceID, generations); err != nil {
		return err
	}
	for _, item := range generations {
		if err := host.Retire(ctx, resourceID, item.Generation, item.ServiceIdentity, item.UnitIdentities); err != nil {
			return err
		}
	}
	if err := verifySettledRetentionLogs(ctx, installationID, resourceID); err != nil {
		return err
	}
	return host.cleanupRetainedShared(ctx, installationID, resourceID)
}

func (host Host) CleanupUncommittedShared(ctx context.Context, installationID, resourceID string) error {
	if err := verifyRetainedInventory(ctx, installationID, resourceID, nil); err != nil {
		return err
	}
	if err := verifySettledRetentionLogs(ctx, installationID, resourceID); err != nil {
		return err
	}
	return host.cleanupRetainedShared(ctx, installationID, resourceID)
}

func (host Host) cleanupRetainedShared(ctx context.Context, installationID, resourceID string) error {
	if err := verifySettledRetentionLogs(ctx, installationID, resourceID); err != nil {
		return err
	}
	paths, err := DerivePaths(resourceID, 1)
	if err != nil {
		return err
	}
	uid, gid, _, _ := numeric(installationID, resourceID)
	if err = removeOwnedTree(ctx, paths.ResourceRoot, 0, 0, 0o711); err != nil {
		return err
	}
	if err = removeOwnedTree(ctx, filepath.Dir(paths.AccessLog), uid, gid, resourceLogDirectoryMode); err != nil {
		return err
	}
	authority, err := deriveAccountAuthority(installationID, resourceID)
	if err != nil {
		return err
	}
	candidate := Candidate{InstallationID: installationID, ResourceID: resourceID, Paths: paths, UID: authority.uid, GID: authority.gid, RelayUID: authority.relayUID, RelayGID: authority.relayGID, User: authority.user, Group: authority.group, RelayUser: authority.relayUser, RelayGroup: authority.relayGroup, Accounts: authority.accounts, Sysusers: authority.sysusers}
	return host.cleanupAccounts(ctx, candidate)
}

func (host Host) cleanupAccounts(ctx context.Context, candidate Candidate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	markerInfo, markerErr := os.Lstat(candidate.Paths.Sysusers)
	markerPresent := markerErr == nil
	if markerPresent {
		stat, ok := markerInfo.Sys().(*syscall.Stat_t)
		if !ok || !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || markerInfo.Mode().Perm() != 0o644 {
			return fmt.Errorf("GoAccess account cleanup marker unsafe")
		}
		data, readErr := os.ReadFile(candidate.Paths.Sysusers)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(data, candidate.Sysusers) {
			return fmt.Errorf("GoAccess account cleanup marker changed")
		}
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return markerErr
	}
	lockFD, lockErr := unix.Open("/etc/.pwd.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if lockErr != nil {
		return lockErr
	}
	defer func() { _ = unix.Close(lockFD) }()
	var lockStat unix.Stat_t
	if lockErr = unix.Fstat(lockFD, &lockStat); lockErr != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Nlink != 1 || lockStat.Uid != 0 || lockStat.Gid != 0 || lockStat.Mode&0o7777 != 0o600 {
		return fmt.Errorf("GoAccess account lock unsafe")
	}
	if lockErr = acquireBoundedFlock(ctx, lockFD, 5*time.Second); lockErr != nil {
		return lockErr
	}
	defer func() { _ = unix.Flock(lockFD, unix.LOCK_UN) }()
	observe := func() (identity.AccountDeletionState, error) {
		state, err := identity.InspectResourceAccountDeletionFiles(candidate.Accounts, "/etc/passwd", "/etc/group", "/etc/shadow")
		if err != nil {
			return state, err
		}
		gshadow, err := os.ReadFile("/etc/gshadow")
		if err != nil {
			return state, err
		}
		entries := map[string][]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(gshadow)), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) == 4 {
				entries[fields[0]] = fields
			}
		}
		groups := []string{candidate.Group, candidate.RelayGroup}
		for index, name := range groups {
			fields, present := entries[name]
			if present && ((!strings.HasPrefix(fields[1], "!") && !strings.HasPrefix(fields[1], "*")) || fields[2] != "" || fields[3] != "") {
				return state, fmt.Errorf("GoAccess gshadow cleanup identity differs")
			}
			state.Groups[index] = state.Groups[index] || present
		}
		return state, nil
	}
	state, err := observe()
	if err != nil {
		return err
	}
	if !markerPresent {
		for _, present := range append(append([]bool{}, state.Users...), state.Groups...) {
			if present {
				return fmt.Errorf("GoAccess accounts exist without origin marker")
			}
		}
		return nil
	}
	for index, present := range state.Users {
		if !present {
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = deleteAccountRecords(candidate, index, true); err != nil {
			return err
		}
		state, err = observe()
		if err != nil {
			return err
		}
	}
	for index, present := range state.Groups {
		if !present {
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = deleteAccountRecords(candidate, index, false); err != nil {
			return err
		}
		state, err = observe()
		if err != nil {
			return err
		}
	}
	for _, present := range append(append([]bool{}, state.Users...), state.Groups...) {
		if present {
			return fmt.Errorf("GoAccess account deletion incomplete")
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	parent, err := unix.Open(filepath.Dir(candidate.Paths.Sysusers), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	if err = unix.Unlinkat(parent, filepath.Base(candidate.Paths.Sysusers), 0); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func deleteAccountRecords(candidate Candidate, index int, user bool) error {
	if index < 0 || index > 1 {
		return fmt.Errorf("GoAccess account deletion index invalid")
	}
	names := []string{candidate.User, candidate.RelayUser}
	groups := []string{candidate.Group, candidate.RelayGroup}
	if user {
		for _, path := range []string{"/etc/passwd", "/etc/shadow"} {
			if err := removeAccountLine(path, names[index]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, path := range []string{"/etc/group", "/etc/gshadow"} {
		if err := removeAccountLine(path, groups[index]); err != nil {
			return err
		}
	}
	return nil
}

func acquireBoundedFlock(ctx context.Context, fd int, maximum time.Duration) error {
	if maximum <= 0 {
		return fmt.Errorf("account lock deadline invalid")
	}
	lockCtx, cancel := context.WithTimeout(ctx, maximum)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		select {
		case <-lockCtx.Done():
			return fmt.Errorf("GoAccess account lock deadline reached: %w", lockCtx.Err())
		case <-ticker.C:
		}
	}
}

func removeAccountLine(path, name string) error {
	if name == "" || strings.ContainsAny(name, ":\r\n") {
		return fmt.Errorf("GoAccess account record name invalid")
	}
	if err := verifyParentChain(path, 0, 0, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != 0 || stat.Size < 0 || stat.Size > 16<<20 {
		return fmt.Errorf("GoAccess account database unsafe")
	}
	if path == "/etc/passwd" || path == "/etc/group" {
		if stat.Gid != 0 || info.Mode().Perm() != 0o644 {
			return fmt.Errorf("GoAccess public account database metadata differs")
		}
	} else if info.Mode().Perm()&0o007 != 0 || info.Mode().Perm()&0o600 != 0o600 {
		return fmt.Errorf("GoAccess private account database metadata differs")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	prefix := name + ":"
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	removed := 0
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return nil
	}
	if removed != 1 {
		return fmt.Errorf("GoAccess account database contains duplicate identity")
	}
	next := []byte(strings.Join(kept, "\n"))
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	temp := "." + filepath.Base(path) + ".lanpanel-goaccess-account"
	fd, openErr := unix.Openat(parent, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(info.Mode().Perm()))
	staged := false
	if errors.Is(openErr, unix.EEXIST) {
		stagePath := filepath.Join(filepath.Dir(path), temp)
		stageInfo, stageErr := os.Lstat(stagePath)
		if stageErr != nil {
			return stageErr
		}
		stageStat, valid := stageInfo.Sys().(*syscall.Stat_t)
		stageData, readErr := os.ReadFile(stagePath)
		if !valid || !stageInfo.Mode().IsRegular() || stageInfo.Mode()&os.ModeSymlink != 0 || stageStat.Nlink != 1 || stageStat.Uid != stat.Uid || stageStat.Gid != stat.Gid || stageInfo.Mode().Perm() != info.Mode().Perm() || readErr != nil || !bytes.Equal(stageData, next) {
			return errors.Join(fmt.Errorf("GoAccess account staging collision"), readErr)
		}
		staged = true
	} else if openErr != nil {
		return openErr
	}
	created := true
	defer func() {
		if created {
			_ = unix.Unlinkat(parent, temp, 0)
		}
	}()
	if !staged {
		if err = unix.Fchown(fd, int(stat.Uid), int(stat.Gid)); err == nil {
			err = unix.Fchmod(fd, uint32(info.Mode().Perm()))
		}
		file := os.NewFile(uintptr(fd), temp)
		if err != nil {
			_ = file.Close()
			return err
		}
		_, writeErr := file.Write(next)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
	}
	fresh, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(fresh, data) {
		return errors.Join(fmt.Errorf("GoAccess account database changed under lock"), readErr)
	}
	if err = unix.Renameat(parent, temp, parent, filepath.Base(path)); err != nil {
		return err
	}
	created = false
	return unix.Fsync(parent)
}

func removeOwnedTree(ctx context.Context, path string, uid, gid, mode uint32) error {
	if err := rejectDescendantMounts(path); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("cleanup root metadata mismatch")
	}
	if err = removeDirectoryContents(ctx, fd, uint64(stat.Dev), new(int)); err != nil {
		return err
	}
	parent, openErr := os.Open(filepath.Dir(path))
	if openErr != nil {
		return openErr
	}
	removeErr := unix.Rmdir(path)
	syncErr := error(nil)
	if removeErr == nil {
		syncErr = parent.Sync()
	}
	closeErr := parent.Close()
	return errors.Join(removeErr, syncErr, closeErr)
}

func verifyRetainedInventory(ctx context.Context, installationID, resourceID string, generations []RetainedGeneration) error {
	inventoryCount := 0
	allowedUnits := map[string]bool{}
	allowedEnablements := map[string]map[string]bool{"/etc/systemd/system/multi-user.target.wants": {}, "/etc/systemd/system/sockets.target.wants": {}, "/etc/systemd/system/timers.target.wants": {}}
	allowedEndpoints := map[string]bool{}
	allowedStates := map[string]bool{}
	for _, item := range generations {
		paths, err := DerivePaths(resourceID, item.Generation)
		if err != nil {
			return err
		}
		for _, path := range []string{paths.ServiceUnit, paths.RelayUnit, paths.SocketUnit, paths.RetentionUnit, paths.RetentionTimer} {
			allowedUnits[filepath.Base(path)] = true
		}
		for path := range enablementLinks(paths) {
			allowedEnablements[filepath.Dir(path)][filepath.Base(path)] = true
		}
		allowedEndpoints[filepath.Base(paths.Endpoint)] = true
		if item.StateGeneration == 0 || item.StateGeneration > item.Generation {
			return fmt.Errorf("GoAccess retained state generation invalid")
		}
		allowedStates[strconv.FormatUint(item.StateGeneration, 10)] = true
	}
	check := func(directory string, relevant func(string) bool, allowed map[string]bool, rejectStaging bool) error {
		entries, err := boundedDirectoryEntries(ctx, directory, &inventoryCount)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !relevant(entry.Name()) {
				continue
			}
			if rejectStaging && strings.HasPrefix(entry.Name(), ".") && strings.HasSuffix(entry.Name(), ".lanpanel") {
				return fmt.Errorf("GoAccess cleanup inventory contains staging residue %q", entry.Name())
			}
			if !allowed[entry.Name()] {
				return fmt.Errorf("GoAccess cleanup inventory contains unexpected %q", entry.Name())
			}
		}
		return nil
	}
	normalizeStaging := func(name string) string {
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".lanpanel") {
			return strings.TrimSuffix(strings.TrimPrefix(name, "."), ".lanpanel")
		}
		return name
	}
	if err := check("/etc/systemd/system", func(name string) bool {
		normalized := normalizeStaging(name)
		return strings.Contains(normalized, resourceID) && strings.HasPrefix(normalized, "lanpanel-goaccess-")
	}, allowedUnits, true); err != nil {
		return err
	}
	basePaths, pathErr := DerivePaths(resourceID, 1)
	if pathErr != nil {
		return pathErr
	}
	for directory, allowed := range allowedEnablements {
		if err := check(directory, func(name string) bool {
			return strings.Contains(name, resourceID) && strings.HasPrefix(name, "lanpanel-goaccess-")
		}, allowed, false); err != nil {
			return err
		}
	}
	if err := check("/etc/sysusers.d", func(name string) bool {
		return normalizeStaging(name) == filepath.Base(basePaths.Sysusers)
	}, map[string]bool{filepath.Base(basePaths.Sysusers): true}, true); err != nil {
		return err
	}
	if err := check("/run/lanpanel-goaccess", func(name string) bool {
		return strings.HasPrefix(name, resourceID+"-") && strings.HasSuffix(name, ".sock")
	}, allowedEndpoints, false); err != nil {
		return err
	}
	paths, err := DerivePaths(resourceID, 1)
	if err != nil {
		return err
	}
	resourceInfo, observeErr := os.Lstat(paths.ResourceRoot)
	if observeErr == nil {
		stat, ok := resourceInfo.Sys().(*syscall.Stat_t)
		if !ok || !resourceInfo.IsDir() || resourceInfo.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != 0 || resourceInfo.Mode().Perm() != 0o711 {
			return fmt.Errorf("GoAccess resource cleanup root unsafe")
		}
	} else if !errors.Is(observeErr, os.ErrNotExist) {
		return observeErr
	}
	generationRoot := filepath.Join(paths.ResourceRoot, "generations")
	if err = check(paths.ResourceRoot, func(string) bool { return true }, map[string]bool{"generations": true}, false); err != nil {
		return err
	}
	if err = check(generationRoot, func(string) bool { return true }, allowedStates, false); err != nil {
		return err
	}
	for name := range allowedStates {
		info, entryErr := os.Lstat(filepath.Join(generationRoot, name))
		if errors.Is(entryErr, os.ErrNotExist) {
			continue
		}
		if entryErr != nil {
			return entryErr
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("GoAccess generation cleanup root unsafe")
		}
	}
	uid, gid, _, _ := numeric(installationID, resourceID)
	logRoot := filepath.Dir(paths.AccessLog)
	logInfo, logErr := os.Lstat(logRoot)
	if logErr == nil {
		stat, ok := logInfo.Sys().(*syscall.Stat_t)
		if !ok || !logInfo.IsDir() || logInfo.Mode()&os.ModeSymlink != 0 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != resourceLogDirectoryMode {
			return fmt.Errorf("GoAccess log cleanup root unsafe")
		}
	} else if !errors.Is(logErr, os.ErrNotExist) {
		return logErr
	}
	allowedLogs := map[string]bool{"access.log": true, "access.log.1": true, "access.log.1.lanpanel": true, "access.log.retention-old": true, "access.log.retention-new": true, "access.log.retention-state": true, "access.log.retention-state.lanpanel": true, ".retention.lock": true}
	if err := check(logRoot, func(string) bool { return true }, allowedLogs, false); err != nil {
		return err
	}
	worker, workerErr := user.Lookup("www-data")
	if workerErr != nil {
		return workerErr
	}
	nginxUIDValue, parseWorkerErr := strconv.ParseUint(worker.Uid, 10, 32)
	if parseWorkerErr != nil || nginxUIDValue == 0 {
		return fmt.Errorf("fixed Nginx worker identity invalid during GoAccess cleanup")
	}
	nginxUID := uint32(nginxUIDValue)
	for name := range allowedLogs {
		info, observeErr := os.Lstat(filepath.Join(logRoot, name))
		if errors.Is(observeErr, os.ErrNotExist) {
			continue
		}
		if observeErr != nil {
			return observeErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		modeOK := false
		if ok {
			mode := stat.Mode & 0o7777
			switch name {
			case "access.log", "access.log.1", "access.log.retention-old":
				modeOK = mode == 0o640
			case "access.log.1.lanpanel", "access.log.retention-new":
				modeOK = mode == 0o600 || mode == 0o640
			case "access.log.retention-state", "access.log.retention-state.lanpanel", ".retention.lock":
				modeOK = mode == 0o600
			}
		}
		ownerOK := ok && stat.Uid == uid && stat.Gid == gid
		if ok && (name == "access.log" || name == "access.log.retention-old" || name == "access.log.retention-new") && stat.Uid == nginxUID && stat.Gid == gid {
			ownerOK = true
		}
		rootStaging := name == "access.log.1.lanpanel" || name == "access.log.retention-new" || name == "access.log.retention-state.lanpanel"
		if ok && rootStaging && stat.Uid == 0 && stat.Gid == 0 && stat.Mode&0o7777 == 0o600 && stat.Size == 0 {
			ownerOK = true
		}
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || !ownerOK || !modeOK {
			return fmt.Errorf("GoAccess retained log cleanup identity unsafe")
		}
		if name == ".retention.lock" && stat.Size != 0 || name == "access.log.retention-new" && stat.Size != 0 || (name == "access.log.1" || name == "access.log.1.lanpanel") && (stat.Size < 0 || stat.Size > maximumAccessLogBytes) || (name == "access.log.retention-state" || name == "access.log.retention-state.lanpanel") && (stat.Size < 0 || stat.Size > maximumRetentionState) {
			return fmt.Errorf("GoAccess retained log cleanup size unsafe")
		}
	}
	return nil
}

func verifySettledRetentionLogs(ctx context.Context, installationID, resourceID string) error {
	paths, err := DerivePaths(resourceID, 1)
	if err != nil || !validInstallationID(installationID) {
		return errors.Join(err, fmt.Errorf("settled GoAccess retention identity invalid"))
	}
	uid, gid, _, _ := numeric(installationID, resourceID)
	return verifySettledRetentionLogRoot(ctx, filepath.Dir(paths.AccessLog), uid, gid)
}

func verifySettledRetentionLogRoot(ctx context.Context, root string, uid, gid uint32) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != resourceLogDirectoryMode {
		return fmt.Errorf("settled GoAccess retention directory unsafe")
	}
	count := 0
	entries, err := boundedDirectoryEntries(ctx, root, &count)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		mode := uint32(0)
		maximum := int64(-1)
		switch entry.Name() {
		case "access.log":
			mode = 0o640
		case "access.log.1":
			mode, maximum = 0o640, maximumAccessLogBytes
		case ".retention.lock":
			mode, maximum = 0o600, 0
		default:
			return fmt.Errorf("settled GoAccess retention contains unknown artifact %q", entry.Name())
		}
		entryInfo, observeErr := os.Lstat(filepath.Join(root, entry.Name()))
		if observeErr != nil {
			return observeErr
		}
		entryStat, entryOK := entryInfo.Sys().(*syscall.Stat_t)
		if !entryOK || !entryInfo.Mode().IsRegular() || entryInfo.Mode()&os.ModeSymlink != 0 || entryStat.Nlink != 1 || entryStat.Uid != uid || entryStat.Gid != gid || entryStat.Mode&0o7777 != mode || entryStat.Size < 0 || maximum >= 0 && entryStat.Size > maximum {
			return fmt.Errorf("settled GoAccess retention artifact unsafe")
		}
	}
	return nil
}

func rejectDescendantMounts(root string) error {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	root = filepath.Clean(root)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return fmt.Errorf("mountinfo entry is malformed")
		}
		mount := decodeMountPath(fields[4])
		if mount == root || strings.HasPrefix(mount, root+string(filepath.Separator)) {
			return fmt.Errorf("GoAccess cleanup root contains nested mount %q", mount)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func decodeMountPath(value string) string {
	value = strings.ReplaceAll(value, `\040`, " ")
	value = strings.ReplaceAll(value, `\011`, "\t")
	value = strings.ReplaceAll(value, `\012`, "\n")
	return strings.ReplaceAll(value, `\134`, `\`)
}

func removeDirectoryContents(ctx context.Context, fd int, device uint64, count *int) error {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(duplicate), "goaccess-cleanup")
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	for {
		names, readErr := file.Readdirnames(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			*count++
			if *count > 8192 {
				return fmt.Errorf("GoAccess cleanup entry limit exceeded")
			}
			if name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
				return fmt.Errorf("GoAccess cleanup entry name invalid")
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if uint64(stat.Dev) != device {
				return fmt.Errorf("GoAccess cleanup entry crosses device")
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if err != nil {
					return err
				}
				err = removeDirectoryContents(ctx, child, device, count)
				closeErr := unix.Close(child)
				if err = errors.Join(err, closeErr); err != nil {
					return err
				}
				if err = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); err != nil {
					return err
				}
			case unix.S_IFREG:
				if stat.Nlink != 1 {
					return fmt.Errorf("GoAccess cleanup refuses hard-linked file")
				}
				if err := unix.Unlinkat(fd, name, 0); err != nil {
					return err
				}
			default:
				return fmt.Errorf("GoAccess cleanup refuses symlink or special entry")
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

func (host Host) EnsureStopped(ctx context.Context, resourceID string, generation uint64) error {
	if host.launcher == nil {
		return fmt.Errorf("GoAccess host unavailable")
	}
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	mask, err := host.observedUnitMask(ctx, resourceID, generation)
	if err != nil {
		return err
	}
	if mask == 0 {
		return host.verifyStoppedGenerationEvidence(ctx, paths)
	}
	return host.stopObservedGeneration(ctx, resourceID, generation, mask)
}

func goAccessUnitBits(resourceID string, generation uint64) map[string]uint8 {
	unitID := resourceID + "-" + strconv.FormatUint(generation, 10)
	return map[string]uint8{
		"lanpanel-goaccess-" + unitID + ".service":           1,
		"lanpanel-goaccess-relay-" + unitID + ".service":     2,
		"lanpanel-goaccess-" + unitID + ".socket":            4,
		"lanpanel-goaccess-retention-" + unitID + ".service": 8,
		"lanpanel-goaccess-retention-" + unitID + ".timer":   16,
	}
}

func (host Host) observedUnitMask(ctx context.Context, resourceID string, generation uint64) (uint8, error) {
	inventoryCtx, cancel := context.WithTimeout(ctx, unitInventoryTimeout)
	defer cancel()
	invocation := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Generation: generation}}
	shown, err := host.launcher.RunInvocation(inventoryCtx, child.ProfileGoAccessShow, invocation, nil)
	if err != nil || shown.ExitCode != 0 {
		return 0, fmt.Errorf("GoAccess unit inventory unavailable: exit=%d: %w", shown.ExitCode, err)
	}
	return unitMaskFromOutput(shown.Stdout, resourceID, generation)
}

func unitMaskFromOutput(output []byte, resourceID string, generation uint64) (uint8, error) {
	units, err := parseEffectiveUnits(string(output))
	if err != nil {
		return 0, err
	}
	mask := uint8(0)
	for id, bit := range goAccessUnitBits(resourceID, generation) {
		properties, present := units[id]
		if !present {
			return 0, fmt.Errorf("GoAccess unit inventory missing %s", id)
		}
		if properties["LoadState"] == "not-found" {
			if properties["ActiveState"] != "inactive" || !stoppedMainPID(id, properties) || properties["UnitFileState"] != "" {
				return 0, fmt.Errorf("not-found GoAccess unit retains runtime authority")
			}
			continue
		}
		if properties["LoadState"] != "loaded" {
			return 0, fmt.Errorf("GoAccess unit load state is unsafe")
		}
		mask |= bit
	}
	return mask, nil
}

func (host Host) finalRetention(ctx context.Context, resourceID string, generation uint64) error {
	if host.launcher == nil || !validResourceID(resourceID) || generation == 0 {
		return fmt.Errorf("GoAccess retention authority invalid")
	}
	retentionCtx, cancel := context.WithTimeout(ctx, finalRetentionTimeout)
	defer cancel()
	invocation := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Generation: generation}}
	retention, err := host.launcher.RunInvocation(retentionCtx, child.ProfileGoAccessRetain, invocation, nil)
	if err != nil || retention.ExitCode != 0 {
		return errors.Join(err, fmt.Errorf("final GoAccess retention failed: exit=%d", retention.ExitCode))
	}
	return nil
}

func (host Host) Stop(ctx context.Context, resourceID string, generation uint64) error {
	return host.EnsureStopped(ctx, resourceID, generation)
}

func (host Host) stopObservedGeneration(ctx context.Context, resourceID string, generation uint64, mask uint8) error {
	if host.launcher == nil || mask == 0 || mask&^uint8(31) != 0 {
		return fmt.Errorf("GoAccess stop authority invalid")
	}
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	quiesceErr := host.quiesceRetentionTimer(ctx, resourceID, generation, mask)
	retentionErr := error(nil)
	stopMask := mask
	if quiesceErr == nil {
		retentionErr = host.finalRetention(ctx, resourceID, generation)
		stopMask &^= 16
	}
	stopErr := error(nil)
	if stopMask != 0 {
		stopErr = host.runStopUnits(ctx, resourceID, generation, stopMask)
	}
	unitErr := host.verifyStoppedUnits(ctx, resourceID, generation, mask)
	endpointErr := host.verifyEndpointAbsent(ctx, paths.Endpoint)
	enablementErr := verifyEnablementLinksAbsent(paths)
	settlementErr := verifyRetentionStateSettledBounded(ctx, paths)
	return errors.Join(quiesceErr, retentionErr, stopErr, unitErr, endpointErr, enablementErr, settlementErr)
}

func (host Host) quiesceRetentionTimer(ctx context.Context, resourceID string, generation uint64, expectedMask uint8) error {
	if expectedMask&16 != 0 {
		if err := host.runStopUnits(ctx, resourceID, generation, 16); err != nil {
			return fmt.Errorf("GoAccess retention timer quiesce failed: %w", err)
		}
	}
	quiesceCtx, cancelQuiesce := context.WithTimeout(ctx, retentionQuiesceTimeout)
	defer cancelQuiesce()
	invocation := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Generation: generation}}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		inventoryCtx, cancelInventory := context.WithTimeout(quiesceCtx, unitInventoryTimeout)
		shown, showErr := host.launcher.RunInvocation(inventoryCtx, child.ProfileGoAccessShow, invocation, nil)
		cancelInventory()
		if showErr != nil || shown.ExitCode != 0 {
			return fmt.Errorf("GoAccess retention quiesce evidence unavailable: exit=%d: %w", shown.ExitCode, showErr)
		}
		settled, err := retentionInvocationQuiesced(shown.Stdout, resourceID, generation, expectedMask)
		if err != nil {
			return err
		}
		if settled {
			return nil
		}
		select {
		case <-quiesceCtx.Done():
			return fmt.Errorf("GoAccess retention invocation did not quiesce: %w", quiesceCtx.Err())
		case <-ticker.C:
		}
	}
}

func retentionInvocationQuiesced(output []byte, resourceID string, generation uint64, expectedMask uint8) (bool, error) {
	mask, err := unitMaskFromOutput(output, resourceID, generation)
	if err != nil {
		return false, err
	}
	if mask != expectedMask {
		return false, fmt.Errorf("GoAccess retention quiesce unit authority changed")
	}
	units, err := parseEffectiveUnits(string(output))
	if err != nil {
		return false, err
	}
	unitID := resourceID + "-" + strconv.FormatUint(generation, 10)
	timerID := "lanpanel-goaccess-retention-" + unitID + ".timer"
	timer := units[timerID]
	timerJob, timerJobPresent := timer["Job"]
	if !timerJobPresent {
		return false, fmt.Errorf("GoAccess retention timer job evidence is missing")
	}
	if expectedMask&16 == 0 {
		if timer["LoadState"] != "not-found" {
			return false, fmt.Errorf("GoAccess absent retention timer regained authority")
		}
	} else if timer["LoadState"] != "loaded" || timer["ActiveState"] != "inactive" || !stoppedMainPID(timerID, timer) || timer["UnitFileState"] != "disabled" {
		return false, fmt.Errorf("GoAccess retention timer remained active or enabled")
	}
	if timerJob != "" {
		return false, nil
	}
	retention := units["lanpanel-goaccess-retention-"+unitID+".service"]
	retentionJob, retentionJobPresent := retention["Job"]
	if !retentionJobPresent {
		return false, fmt.Errorf("GoAccess retention service job evidence is missing")
	}
	if expectedMask&8 == 0 {
		return retentionJob == "", nil
	}
	switch retention["ActiveState"] {
	case "inactive":
		if retention["MainPID"] != "0" {
			return false, fmt.Errorf("inactive GoAccess retention retained a process")
		}
		return retentionJob == "", nil
	case "failed":
		if retention["MainPID"] != "0" {
			return false, fmt.Errorf("failed GoAccess retention retained a process")
		}
		return retentionJob == "", nil
	case "activating", "deactivating":
		return false, nil
	default:
		return false, fmt.Errorf("GoAccess retention invocation state is unsafe")
	}
}

func (host Host) runStopUnits(ctx context.Context, resourceID string, generation uint64, mask uint8) error {
	if host.launcher == nil || mask == 0 || mask&^uint8(31) != 0 {
		return fmt.Errorf("GoAccess stop authority invalid")
	}
	stopCtx, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()
	invocation := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Generation: generation, UnitMask: mask}}
	result, err := host.launcher.RunInvocation(stopCtx, child.ProfileGoAccessStop, invocation, nil)
	if err != nil || result.ExitCode != 0 {
		return fmt.Errorf("GoAccess stop failed: exit=%d: %w", result.ExitCode, err)
	}
	return nil
}

func (host Host) verifyStoppedUnits(ctx context.Context, resourceID string, generation uint64, mask uint8) error {
	inventoryCtx, cancel := context.WithTimeout(ctx, unitInventoryTimeout)
	defer cancel()
	invocation := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Generation: generation}}
	shown, showErr := host.launcher.RunInvocation(inventoryCtx, child.ProfileGoAccessShow, invocation, nil)
	if showErr != nil || shown.ExitCode != 0 {
		return fmt.Errorf("GoAccess stopped-unit evidence unavailable: exit=%d: %w", shown.ExitCode, showErr)
	}
	return verifyStoppedUnitOutput(shown.Stdout, resourceID, generation, mask)
}

func (host Host) verifyEndpointAbsent(ctx context.Context, path string) error {
	endpointCtx, cancel := context.WithTimeout(ctx, endpointEvidenceTimeout)
	defer cancel()
	return host.waitEndpoint(endpointCtx, path, false)
}

func (host Host) verifyStoppedGenerationEvidence(ctx context.Context, paths Paths) error {
	return errors.Join(host.verifyEndpointAbsent(ctx, paths.Endpoint), verifyEnablementLinksAbsent(paths), verifyRetentionStateSettledBounded(ctx, paths))
}

func verifyStoppedUnitOutput(output []byte, resourceID string, generation uint64, mask uint8) error {
	units, err := parseEffectiveUnits(string(output))
	if err != nil {
		return err
	}
	for id, bit := range goAccessUnitBits(resourceID, generation) {
		properties, present := units[id]
		if !present {
			return fmt.Errorf("GoAccess stopped unit missing")
		}
		if mask&bit == 0 {
			if properties["LoadState"] != "not-found" || properties["ActiveState"] != "inactive" || !stoppedMainPID(id, properties) || properties["UnitFileState"] != "" {
				return fmt.Errorf("excluded GoAccess unit retained authority")
			}
			continue
		}
		wantState := "disabled"
		if bit == 8 {
			wantState = "static"
		}
		if properties["LoadState"] != "loaded" || properties["ActiveState"] != "inactive" || !stoppedMainPID(id, properties) || properties["UnitFileState"] != wantState {
			return fmt.Errorf("GoAccess unit remained active or enabled")
		}
	}
	return nil
}

func validRetentionRuntime(properties map[string]string) bool {
	switch properties["ActiveState"] {
	case "inactive":
		return properties["SubState"] == "dead" && properties["MainPID"] == "0"
	case "activating":
		pid, err := strconv.ParseUint(properties["MainPID"], 10, 32)
		return err == nil && pid > 1 && properties["SubState"] == "start"
	default:
		return false
	}
}

func stoppedMainPID(id string, properties map[string]string) bool {
	pid, present := properties["MainPID"]
	if strings.HasSuffix(id, ".service") {
		return present && pid == "0"
	}
	return !present
}

func verifyRemovedUnitOutput(output []byte) error {
	units, err := parseEffectiveUnits(string(output))
	if err != nil {
		return err
	}
	for id, properties := range units {
		if properties["LoadState"] != "not-found" || properties["ActiveState"] != "inactive" || !stoppedMainPID(id, properties) || properties["UnitFileState"] != "" {
			return fmt.Errorf("removed GoAccess unit remains loaded or enabled")
		}
	}
	return nil
}

func (host Host) RetirementComplete(ctx context.Context, resourceID string, generation, stateGeneration uint64, removeState bool) (bool, error) {
	if stateGeneration == 0 || stateGeneration > generation {
		return false, fmt.Errorf("GoAccess retirement state generation invalid")
	}
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return false, err
	}
	for _, path := range []string{paths.ServiceUnit, paths.RelayUnit, paths.SocketUnit, paths.RetentionUnit, paths.RetentionTimer} {
		if _, observeErr := os.Lstat(path); observeErr == nil {
			return false, nil
		} else if !errors.Is(observeErr, os.ErrNotExist) {
			return false, observeErr
		}
	}
	if err = verifyEnablementLinksAbsent(paths); err != nil {
		return false, err
	}
	if removeState {
		statePaths, stateErr := DerivePaths(resourceID, stateGeneration)
		if stateErr != nil {
			return false, stateErr
		}
		if _, observeErr := os.Lstat(statePaths.StateRoot); observeErr == nil {
			return false, nil
		} else if !errors.Is(observeErr, os.ErrNotExist) {
			return false, observeErr
		}
	}
	if err = verifyRetentionStateSettledBounded(ctx, paths); err != nil {
		return false, err
	}
	invocation := child.Invocation{Resource: &child.ResourceInvocation{ResourceID: resourceID, Generation: generation}}
	inventoryCtx, cancelInventory := context.WithTimeout(ctx, unitInventoryTimeout)
	shown, showErr := host.launcher.RunInvocation(inventoryCtx, child.ProfileGoAccessShow, invocation, nil)
	cancelInventory()
	if showErr != nil || shown.ExitCode != 0 {
		return false, fmt.Errorf("GoAccess retirement evidence unavailable: exit=%d: %w", shown.ExitCode, showErr)
	}
	if err = verifyRemovedUnitOutput(shown.Stdout); err != nil {
		return false, err
	}
	if err = host.verifyEndpointAbsent(ctx, paths.Endpoint); err != nil {
		return false, err
	}
	return true, nil
}

func removeGenerationUnitFiles(ctx context.Context, paths Paths, unitPaths []string) error {
	if err := verifyRetentionStateSettledBounded(ctx, paths); err != nil {
		return err
	}
	for _, path := range unitPaths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func verifyRetentionStateSettledBounded(ctx context.Context, paths Paths) error {
	settlementCtx, cancel := context.WithTimeout(ctx, retentionSettlementTimeout)
	defer cancel()
	return verifyRetentionStateSettled(settlementCtx, paths)
}

func (host Host) waitEndpoint(ctx context.Context, path string, present bool) error {
	if host.endpointObserver != nil {
		return host.endpointObserver(ctx, path, present)
	}
	deadline := time.NewTicker(50 * time.Millisecond)
	defer deadline.Stop()
	for {
		var stat unix.Stat_t
		err := unix.Lstat(path, &stat)
		matched := err == nil && stat.Mode&unix.S_IFMT == unix.S_IFSOCK
		if present && matched || !present && errors.Is(err, unix.ENOENT) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("GoAccess endpoint state not reached: %w", ctx.Err())
		case <-deadline.C:
		}
	}
}

func verifyRuntimePaths(ctx context.Context, candidate Candidate) error {
	checks := []struct {
		path           string
		kind           uint32
		uid, gid, mode uint32
	}{{filepath.Dir(candidate.Paths.Endpoint), unix.S_IFDIR, 0, candidate.NginxGID, 0o750}, {"/var/log/lanpanel/goaccess", unix.S_IFDIR, 0, 0, 0o711}, {filepath.Dir(candidate.Paths.AccessLog), unix.S_IFDIR, candidate.UID, candidate.GID, resourceLogDirectoryMode}, {globalRetentionLockPath, unix.S_IFREG, 0, 0, 0o600}, {candidate.Paths.StateRoot, unix.S_IFDIR, 0, 0, 0o711}, {candidate.Paths.Database, unix.S_IFDIR, candidate.UID, candidate.GID, 0o750}, {filepath.Dir(candidate.Paths.Report), unix.S_IFDIR, candidate.UID, candidate.NginxGID, 0o2750}, {candidate.Paths.Report, unix.S_IFREG, candidate.UID, candidate.NginxGID, 0o640}, {candidate.Paths.AccessLog, unix.S_IFREG, candidate.UID, candidate.GID, 0o640}, {candidate.Paths.RetentionLock, unix.S_IFREG, candidate.UID, candidate.GID, 0o600}, {candidate.Paths.Endpoint, unix.S_IFSOCK, 0, candidate.NginxGID, 0o660}}
	for {
		missing := false
		for _, check := range checks {
			var stat unix.Stat_t
			if err := unix.Lstat(check.path, &stat); errors.Is(err, unix.ENOENT) {
				missing = true
				continue
			} else if err != nil {
				return fmt.Errorf("GoAccess runtime path unavailable: %w", err)
			}
			fixedEmpty := check.path == globalRetentionLockPath || check.path == candidate.Paths.RetentionLock
			if stat.Mode&unix.S_IFMT != check.kind || stat.Nlink != 1 && check.kind == unix.S_IFREG || stat.Uid != check.uid || stat.Gid != check.gid || stat.Mode&0o7777 != check.mode || fixedEmpty && stat.Size != 0 {
				return fmt.Errorf("GoAccess runtime path identity differs: %s", check.path)
			}
		}
		if !missing {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("GoAccess runtime paths not ready: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func verifyManagedServiceFiles(paths Paths, expectedIdentity string) error {
	contents := [][]byte{}
	for _, path := range []string{paths.ServiceUnit, paths.RelayUnit, paths.SocketUnit, paths.Sysusers, paths.RetentionUnit, paths.RetentionTimer} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("GoAccess service authority incomplete: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0o644 {
			return fmt.Errorf("GoAccess service authority unsafe")
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		contents = append(contents, content)
	}
	if expectedIdentity == "" || managedServiceIdentity(contents...) != expectedIdentity {
		return fmt.Errorf("GoAccess service authority changed")
	}
	return nil
}

func parseEffectiveUnits(value string) (map[string]map[string]string, error) {
	result := map[string]map[string]string{}
	for _, block := range strings.Split(strings.TrimSpace(value), "\n\n") {
		properties := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, current, ok := strings.Cut(line, "=")
			if !ok || key == "" {
				return nil, fmt.Errorf("GoAccess effective unit output malformed")
			}
			properties[key] = current
		}
		id := properties["Id"]
		if id == "" || result[id] != nil {
			return nil, fmt.Errorf("GoAccess effective unit identity malformed")
		}
		result[id] = properties
	}
	if len(result) != 5 {
		return nil, fmt.Errorf("GoAccess effective unit count invalid")
	}
	return result, nil
}

func probeWebSocket(ctx context.Context, endpoint, path string) error {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", endpoint)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err = fmt.Fprintf(connection, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", path); err != nil {
		return err
	}
	status, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 101 ") {
		return fmt.Errorf("GoAccess WebSocket probe failed: %q: %w", strings.TrimSpace(status), err)
	}
	return nil
}

func verifyParentChain(path string, finalUID, finalGID uint32, allowFinalOwner bool) error {
	parent := filepath.Dir(filepath.Clean(path))
	if !filepath.IsAbs(parent) || parent == "/" {
		return nil
	}
	current := ""
	parts := strings.Split(strings.TrimPrefix(parent, "/"), "/")
	for index, part := range parts {
		current += "/" + part
		fd, err := unix.Open(current, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		closeErr := unix.Close(fd)
		if err = errors.Join(statErr, closeErr); err != nil {
			return err
		}
		final := index == len(parts)-1
		ownerOK := stat.Uid == 0 && stat.Gid == 0 || final && allowFinalOwner && stat.Uid == finalUID && stat.Gid == finalGID
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || !ownerOK || stat.Mode&0o022 != 0 {
			return fmt.Errorf("GoAccess parent chain unsafe: %s", current)
		}
	}
	return nil
}

func ensureDirectory(path string, uid, gid, mode uint32) error {
	if err := verifyParentChain(path, 0, 0, false); err != nil {
		return err
	}
	created := false
	if mkdirErr := unix.Mkdir(path, mode); mkdirErr == nil {
		created = true
	} else if !errors.Is(mkdirErr, unix.EEXIST) {
		return mkdirErr
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if err = rejectDescendantMounts(path); err != nil {
		return err
	}
	if stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode {
		if created && stat.Uid == 0 && stat.Gid == 0 && stat.Mode&0o7777 == mode {
			if err = unix.Fchown(fd, int(uid), int(gid)); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("GoAccess directory identity differs")
		}
	}
	return unix.Fsync(fd)
}

func ensureEmptyFile(path string, uid, gid, mode uint32) error {
	if err := ensureFile(path, uid, gid, mode); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode || stat.Size != 0 {
		return errors.Join(err, fmt.Errorf("GoAccess fixed empty file identity differs"))
	}
	return nil
}

func ensureFile(path string, uid, gid, mode uint32) error {
	if err := verifyParentChain(path, uid, gid, true); err != nil {
		return err
	}
	if err := rejectDescendantMounts(filepath.Dir(path)); err != nil {
		return err
	}
	flags := unix.O_WRONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	created := false
	if _, observeErr := os.Lstat(path); errors.Is(observeErr, os.ErrNotExist) {
		flags |= unix.O_CREAT | unix.O_EXCL
		created = true
	} else if observeErr != nil {
		return observeErr
	}
	fd, err := unix.Open(path, flags, mode)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return fmt.Errorf("GoAccess file identity unsafe")
	}
	if created && stat.Uid == 0 && stat.Gid == 0 && stat.Size == 0 {
		if err = unix.Fchown(fd, int(uid), int(gid)); err != nil {
			return err
		}
		if err = unix.Fchmod(fd, mode); err != nil {
			return err
		}
	} else if stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode {
		return fmt.Errorf("GoAccess file identity differs")
	}
	if err = unix.Fsync(fd); err != nil || !created {
		return err
	}
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	syncErr := unix.Fsync(parent)
	closeErr := unix.Close(parent)
	return errors.Join(syncErr, closeErr)
}

func replaceFile(path string, data []byte, uid, gid, mode uint32) error {
	if err := verifyParentChain(path, 0, 0, false); err != nil {
		return err
	}
	if err := rejectDescendantMounts(filepath.Dir(path)); err != nil {
		return err
	}
	stagingPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lanpanel")
	if _, observeErr := os.Lstat(stagingPath); observeErr == nil {
		return fmt.Errorf("GoAccess staging collision")
	} else if !errors.Is(observeErr, os.ErrNotExist) {
		return observeErr
	}
	if info, observeErr := os.Lstat(path); observeErr == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || info.Mode().Perm() != os.FileMode(mode) {
			return fmt.Errorf("GoAccess managed file identity differs")
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("GoAccess managed file content differs")
		}
		return nil
	} else if !errors.Is(observeErr, os.ErrNotExist) {
		return observeErr
	}
	parent := filepath.Dir(path)
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	name := "." + filepath.Base(path) + ".lanpanel"
	out, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	if err = unix.Fchown(out, int(uid), int(gid)); err == nil {
		err = unix.Fchmod(out, mode)
	}
	if err != nil {
		_ = unix.Close(out)
		_ = unix.Unlinkat(fd, name, 0)
		return err
	}
	file := os.NewFile(uintptr(out), name)
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr == nil && syncErr == nil && closeErr == nil {
		var stat unix.Stat_t
		if unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode {
			writeErr = fmt.Errorf("GoAccess staged file unsafe")
		}
	}
	if writeErr == nil {
		writeErr = unix.Renameat2(fd, name, fd, filepath.Base(path), unix.RENAME_NOREPLACE)
	}
	if writeErr != nil {
		_ = unix.Unlinkat(fd, name, 0)
		return errors.Join(writeErr, syncErr, closeErr)
	}
	return unix.Fsync(fd)
}
