//go:build linux

package packages

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type LinuxAuditor struct {
	launcher   ChildLauncher
	aptRoot    string
	dpkgRoot   string
	cgroupRoot string
	procRoot   string
	policyPath string
	binaryPath string
	maskRoot   string
	strict     bool
}

func NewLinuxAuditor(launcher ChildLauncher) (*LinuxAuditor, error) {
	if launcher == nil {
		return nil, fmt.Errorf("package auditor requires the typed child launcher")
	}
	paths := []string{"/etc/apt", "/etc/dpkg", "/var/lib/dpkg", "/sys/fs/cgroup/system.slice", "/proc/net", "/usr/sbin", filepath.Dir(child.FixedLanPanelExecutable), FixedSystemdMaskDirectory}
	for _, path := range paths {
		if err := validateAuditorParent(path); err != nil {
			return nil, err
		}
	}
	return &LinuxAuditor{launcher: launcher, aptRoot: "/etc/apt", dpkgRoot: "/var/lib/dpkg", cgroupRoot: "/sys/fs/cgroup/system.slice", procRoot: "/proc/net", policyPath: "/usr/sbin/policy-rc.d", binaryPath: child.FixedLanPanelExecutable, maskRoot: FixedSystemdMaskDirectory, strict: true}, nil
}

func newTestLinuxAuditor(launcher ChildLauncher, root string) *LinuxAuditor {
	return &LinuxAuditor{launcher: launcher, aptRoot: filepath.Join(root, "etc/apt"), dpkgRoot: filepath.Join(root, "var/lib/dpkg"), cgroupRoot: filepath.Join(root, "cgroup"), procRoot: filepath.Join(root, "proc"), policyPath: filepath.Join(root, "usr/sbin/policy-rc.d"), binaryPath: filepath.Join(root, "usr/lib/lanpanel/lanpanel"), maskRoot: filepath.Join(root, "etc/systemd/system")}
}

func (auditor *LinuxAuditor) AuditPackages(ctx context.Context, plan Plan) (Audit, error) {
	if auditor == nil || auditor.launcher == nil {
		return Audit{}, fmt.Errorf("package auditor is unavailable")
	}
	configuration, repositories, err := auditor.readConfiguration(ctx, plan)
	if err != nil {
		return Audit{}, err
	}
	dpkg, installed, systemPackages, err := auditor.readDPKG(ctx, plan.Packages)
	if err != nil {
		return Audit{}, err
	}
	runtime, err := auditor.runtimeSnapshot(plan, installed, systemPackages)
	if err != nil {
		return Audit{}, err
	}
	policy, err := auditor.noAutostartPolicy(plan.NoAutostartPolicyDigest)
	if err != nil {
		return Audit{}, err
	}
	return Audit{Configuration: configuration, Repositories: repositories, DPKG: dpkg, Before: runtime, NoAutostart: policy}, nil
}

// PreflightReadiness reuses the exact no-follow APT/dpkg inventory and parser
// used by package execution without starting a child or changing host state.
func (auditor *LinuxAuditor) PreflightReadiness(ctx context.Context, repositories []Repository) (string, error) {
	if auditor == nil || auditor.launcher == nil {
		return "", fmt.Errorf("package auditor is unavailable")
	}
	plan := Plan{Repositories: append([]Repository(nil), repositories...)}
	configuration, observedRepositories, err := auditor.readConfiguration(ctx, plan)
	if err != nil {
		return "", err
	}
	if err := ValidateAPTConfiguration(configuration, observedRepositories, repositories); err != nil {
		return "", err
	}
	dpkg, _, packages, err := auditor.readDPKG(ctx, nil)
	if err != nil {
		return "", err
	}
	if err := ValidateDPKGReady(dpkg); err != nil {
		return "", err
	}
	identity, err := digestValue(struct {
		Configuration []ObservedConfig
		Repositories  []ObservedRepository
		Packages      []InstalledPackage
	}{configuration, observedRepositories, packages})
	if err != nil {
		return "", err
	}
	return identity, nil
}

func (auditor *LinuxAuditor) ObservePackages(ctx context.Context, plan Plan) (Postcondition, error) {
	_, installed, systemPackages, err := auditor.readDPKG(ctx, plan.Packages)
	if err != nil {
		return Postcondition{}, err
	}
	if !reflectPackages(installed, plan.Packages) {
		return Postcondition{}, fmt.Errorf("installed package closure differs from the exact Plan")
	}
	runtime, err := auditor.runtimeSnapshot(plan, installed, systemPackages)
	if err != nil {
		return Postcondition{}, err
	}
	postcondition := Postcondition{Installed: installed, SystemPackages: runtime.SystemPackages, Units: runtime.Units, Listeners: runtime.Listeners}
	if hasPackage(plan.Packages, "apache2-utils") {
		identity, err := auditor.fileIdentity("/usr/bin/htpasswd")
		if err != nil {
			return Postcondition{}, err
		}
		postcondition.HTPasswd = &identity
	}
	return postcondition, nil
}

func (auditor *LinuxAuditor) VerifyPackageMasks(ctx context.Context, identities []MaskIdentity, present bool) error {
	if !validMaskIdentities(identities) {
		return fmt.Errorf("package mask verification authority is invalid")
	}
	result, err := auditor.launcher.RunInvocation(ctx, child.ProfileSystemctl, child.Invocation{}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return fmt.Errorf("systemd daemon-reload did not reach a bounded terminal result")
	}
	for _, identity := range identities {
		path := filepath.Join(auditor.maskRoot, identity.Unit)
		var stat unix.Stat_t
		err := unix.Lstat(path, &stat)
		if present {
			if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFLNK || uint64(stat.Dev) != identity.Device || stat.Ino != identity.Inode || stat.Ctim.Sec != identity.CTimeSec || stat.Ctim.Nsec != identity.CTimeNsec {
				return fmt.Errorf("PID 1 mask identity changed before verification")
			}
			target, err := os.Readlink(path)
			if err != nil || target != "/dev/null" {
				return fmt.Errorf("PID 1 package mask target is invalid")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("transaction-created package mask remains after cleanup")
		}
		active, err := cgroupHasProcesses(filepath.Join(auditor.cgroupRoot, identity.Unit, "cgroup.procs"))
		if err != nil || active {
			return fmt.Errorf("masked package unit is active")
		}
	}
	return nil
}

func (auditor *LinuxAuditor) readConfiguration(ctx context.Context, plan Plan) ([]ObservedConfig, []ObservedRepository, error) {
	files := []ObservedConfig{}
	for _, entry := range []struct {
		path string
		kind ConfigKind
		dir  bool
	}{
		{filepath.Join(auditor.aptRoot, "apt.conf"), APTConfig, false},
		{filepath.Join(auditor.aptRoot, "apt.conf.d"), APTConfig, true},
		{filepath.Join(auditor.aptRoot, "auth.conf"), APTConfig, false},
		{filepath.Join(auditor.aptRoot, "auth.conf.d"), APTConfig, true},
		{filepath.Join(auditor.aptRoot, "keyrings"), APTKeyring, true},
		{filepath.Join(auditor.aptRoot, "preferences"), APTConfig, false},
		{filepath.Join(auditor.aptRoot, "preferences.d"), APTConfig, true},
		{filepath.Join(auditor.aptRoot, "sources.list"), APTSource, false},
		{filepath.Join(auditor.aptRoot, "sources.list.d"), APTSource, true},
		{filepath.Join(auditor.aptRoot, "trusted.gpg"), APTKeyring, false},
		{filepath.Join(auditor.aptRoot, "trusted.gpg.d"), APTKeyring, true},
		{filepath.Join(filepath.Dir(auditor.aptRoot), "dpkg/dpkg.cfg"), DPKGConfig, false},
		{filepath.Join(filepath.Dir(auditor.aptRoot), "dpkg/dpkg.cfg.d"), DPKGConfig, true},
	} {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		observed, err := auditor.readConfigEntry(entry.path, entry.kind, entry.dir)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, observed...)
	}
	slices.SortFunc(files, func(left, right ObservedConfig) int { return strings.Compare(left.Path, right.Path) })
	repositories, err := parseObservedRepositories(files, plan.Repositories)
	if err != nil {
		return nil, nil, err
	}
	return files, repositories, nil
}

func (auditor *LinuxAuditor) readConfigEntry(path string, kind ConfigKind, directory bool) ([]ObservedConfig, error) {
	if directory {
		fd, err := openSafeDirectory(path, auditor.strict)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		defer func() { _ = unix.Close(fd) }()
		entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return nil, err
		}
		result := []ObservedConfig{}
		for _, entry := range entries {
			if entry.IsDir() {
				return nil, fmt.Errorf("APT/dpkg configuration directory contains a nested directory")
			}
			observed, err := readObservedAt(fd, filepath.Join(path, entry.Name()), entry.Name(), kind, auditor.strict)
			if err != nil {
				return nil, err
			}
			result = append(result, observed)
		}
		return result, nil
	}
	parentFD, err := openSafeDirectory(filepath.Dir(path), auditor.strict)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	observed, err := readObservedAt(parentFD, path, filepath.Base(path), kind, auditor.strict)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []ObservedConfig{observed}, nil
}

func readObservedAt(parentFD int, path, name string, kind ConfigKind, strict bool) (ObservedConfig, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ObservedConfig{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	owner, group := uint32(0), uint32(0)
	if !strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o022 != 0 || stat.Size < 0 || stat.Size > 1<<20 {
		return ObservedConfig{}, fmt.Errorf("APT/dpkg file type, owner, group, link, mode, or size is unsafe")
	}
	data, err := readExactFD(fd, stat.Size+1)
	if err != nil || int64(len(data)) != stat.Size {
		return ObservedConfig{}, fmt.Errorf("read exact APT/dpkg configuration")
	}
	return ObservedConfig{Path: canonicalAuditPath(path, kind, strict), Kind: kind, UID: 0, GID: 0, Mode: stat.Mode & 0o777, Regular: true, ParentsSafe: true, Bytes: data}, nil
}

func canonicalAuditPath(path string, kind ConfigKind, strict bool) string {
	if strict {
		return path
	}
	base := filepath.Base(path)
	switch kind {
	case APTConfig:
		if strings.Contains(path, "/apt.conf.d/") {
			return "/etc/apt/apt.conf.d/" + base
		}
		return "/etc/apt/apt.conf"
	case APTSource:
		if strings.HasSuffix(path, "/sources.list") {
			return "/etc/apt/sources.list"
		}
		return "/etc/apt/sources.list.d/" + base
	case APTKeyring:
		switch {
		case strings.Contains(path, "/trusted.gpg.d/"):
			return "/etc/apt/trusted.gpg.d/" + base
		case strings.HasSuffix(path, "/trusted.gpg"):
			return "/etc/apt/trusted.gpg"
		default:
			return "/etc/apt/keyrings/" + base
		}
	case DPKGConfig:
		if strings.Contains(path, "/dpkg.cfg.d/") {
			return "/etc/dpkg/dpkg.cfg.d/" + base
		}
		return "/etc/dpkg/dpkg.cfg"
	default:
		return path
	}
}

func parseObservedRepositories(files []ObservedConfig, expected []Repository) ([]ObservedRepository, error) {
	parsed := []ObservedRepository{}
	for _, file := range files {
		if file.Kind != APTSource {
			continue
		}
		values, err := parseSourceFile(file.Path, file.Bytes)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, values...)
	}
	result := make([]ObservedRepository, 0, len(parsed))
	for _, observed := range parsed {
		matched := false
		for _, want := range expected {
			if observed.URI == want.URI && observed.Suite == want.Suite && slices.Equal(observed.Components, want.Components) && observed.KeyringPath == want.KeyringPath {
				observed.ID, observed.KeyringDigest, observed.Enabled = want.ID, want.KeyringDigest, true
				result = append(result, observed)
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("active APT source is not authorized by the package Plan")
		}
	}
	slices.SortFunc(result, func(left, right ObservedRepository) int { return strings.Compare(left.ID, right.ID) })
	return result, nil
}

func parseSourceFile(path string, data []byte) ([]ObservedRepository, error) {
	if strings.HasSuffix(path, ".sources") {
		return parseDeb822Sources(data)
	}
	result := []ObservedRepository{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "deb" || !strings.HasPrefix(fields[1], "[") {
			return nil, fmt.Errorf("APT source line is unsupported or malformed")
		}
		closing := slices.IndexFunc(fields, func(value string) bool { return strings.HasSuffix(value, "]") })
		if closing < 1 || closing+3 >= len(fields) {
			return nil, fmt.Errorf("APT source options are incomplete")
		}
		options := strings.Trim(strings.Join(fields[1:closing+1], " "), "[]")
		signedBy := ""
		for _, option := range strings.Fields(options) {
			key, value, found := strings.Cut(option, "=")
			if !found || key != "arch" && key != "signed-by" || key == "arch" && value != "amd64" {
				return nil, fmt.Errorf("APT source option is unauthorized")
			}
			if key == "signed-by" {
				signedBy = value
			}
		}
		if signedBy == "" {
			return nil, fmt.Errorf("APT source omits exact signed-by authority")
		}
		result = append(result, ObservedRepository{URI: fields[closing+1], Suite: fields[closing+2], Components: append([]string(nil), fields[closing+3:]...), KeyringPath: signedBy, Enabled: true})
	}
	return result, nil
}

func parseDeb822Sources(data []byte) ([]ObservedRepository, error) {
	result := []ObservedRepository{}
	for _, paragraph := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			key, value, found := strings.Cut(line, ":")
			if !found || strings.TrimSpace(key) != key || fields[key] != "" {
				return nil, fmt.Errorf("deb822 APT source is malformed or duplicated")
			}
			fields[key] = strings.TrimSpace(value)
		}
		for key := range fields {
			if key != "Types" && key != "URIs" && key != "Suites" && key != "Components" && key != "Signed-By" && key != "Architectures" && key != "Enabled" {
				return nil, fmt.Errorf("deb822 APT source contains an unsupported field")
			}
		}
		if fields["Types"] != "deb" || len(strings.Fields(fields["URIs"])) != 1 || len(strings.Fields(fields["Suites"])) != 1 || len(strings.Fields(fields["Signed-By"])) != 1 || len(strings.Fields(fields["Components"])) == 0 || fields["Architectures"] != "" && fields["Architectures"] != "amd64" || fields["Enabled"] != "" && fields["Enabled"] != "yes" {
			return nil, fmt.Errorf("deb822 APT source authority is unsupported")
		}
		result = append(result, ObservedRepository{URI: fields["URIs"], Suite: fields["Suites"], Components: strings.Fields(fields["Components"]), KeyringPath: fields["Signed-By"], Enabled: true})
	}
	return result, nil
}

func (auditor *LinuxAuditor) readDPKG(ctx context.Context, closure []Package) (DPKGState, []Package, []InstalledPackage, error) {
	path := filepath.Join(auditor.dpkgRoot, "status")
	data, err := auditor.readSafeFile(path, 32<<20)
	if err != nil {
		return DPKGState{}, nil, nil, err
	}
	state := DPKGState{}
	installedByName := map[string]Package{}
	systemPackages := []InstalledPackage{}
	for stanzaIndex, paragraph := range strings.Split(string(data), "\n\n") {
		if strings.TrimSpace(paragraph) == "" {
			continue
		}
		fields := map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(paragraph))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key, value, found := strings.Cut(line, ":")
			if !found || key == "" {
				return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d is malformed", stanzaIndex+1)
			}
			if _, duplicate := fields[key]; duplicate {
				return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d duplicates %s", stanzaIndex+1, key)
			}
			fields[key] = strings.TrimSpace(value)
		}
		if err := scanner.Err(); err != nil {
			return DPKGState{}, nil, nil, fmt.Errorf("scan dpkg status stanza %d: %w", stanzaIndex+1, err)
		}
		for _, required := range []string{"Package", "Status", "Version", "Architecture"} {
			if fields[required] == "" {
				return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d is missing %s", stanzaIndex+1, required)
			}
		}
		name := fields["Package"]
		_, errorState, packageState, err := parseDPKGStatusFields(fields["Status"])
		if err != nil {
			return DPKGState{}, nil, nil, fmt.Errorf("dpkg status stanza %d: %w", stanzaIndex+1, err)
		}
		if errorState != "ok" {
			state.Broken = append(state.Broken, name)
			continue
		}
		switch packageState {
		case "installed":
			systemPackages = append(systemPackages, InstalledPackage{Name: name, Version: fields["Version"], Architecture: fields["Architecture"]})
			if wanted, ok := packageByName(closure, name); ok {
				wanted.Version = fields["Version"]
				wanted.Architecture = fields["Architecture"]
				installedByName[name] = wanted
			}
		case "unpacked":
			state.Unpacked = append(state.Unpacked, name)
		case "half-configured":
			state.HalfConfigured = append(state.HalfConfigured, name)
		case "triggers-awaited", "triggers-pending":
			state.TriggersPending = append(state.TriggersPending, name)
		case "half-installed":
			state.Broken = append(state.Broken, name)
		case "not-installed", "config-files":
		}
	}
	for _, values := range [][]string{state.HalfConfigured, state.Unpacked, state.TriggersPending, state.Broken} {
		slices.Sort(values)
	}
	installed := []Package{}
	for _, pkg := range closure {
		if current, ok := installedByName[pkg.Name]; ok {
			installed = append(installed, current)
		}
	}
	if err := ctx.Err(); err != nil {
		return DPKGState{}, nil, nil, err
	}
	slices.SortFunc(systemPackages, func(left, right InstalledPackage) int { return strings.Compare(left.Name, right.Name) })
	if err := validateInstalledPackages(systemPackages); err != nil {
		return DPKGState{}, nil, nil, err
	}
	return state, installed, systemPackages, nil
}

func parseDPKGStatusFields(value string) (string, string, string, error) {
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("dpkg Status must contain exactly selection, error, and state fields")
	}
	selection, errorState, packageState := fields[0], fields[1], fields[2]
	switch selection {
	case "unknown", "install", "hold", "deinstall", "purge":
	default:
		return "", "", "", fmt.Errorf("dpkg Status selection field is invalid")
	}
	if errorState != "ok" && errorState != "reinstreq" {
		return "", "", "", fmt.Errorf("dpkg Status error field is invalid")
	}
	switch packageState {
	case "not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed":
	default:
		return "", "", "", fmt.Errorf("dpkg Status state field is invalid")
	}
	return selection, errorState, packageState, nil
}

func (auditor *LinuxAuditor) runtimeSnapshot(plan Plan, installed []Package, systemPackages []InstalledPackage) (RuntimeSnapshot, error) {
	entries, err := os.ReadDir(auditor.cgroupRoot)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	unitNames := affectedUnits(plan.Packages)
	for _, entry := range entries {
		if entry.IsDir() {
			unitNames = append(unitNames, entry.Name())
		}
	}
	slices.Sort(unitNames)
	unitNames = slices.Compact(unitNames)
	units := make([]UnitState, 0, len(unitNames))
	for _, name := range unitNames {
		active, err := cgroupHasProcesses(filepath.Join(auditor.cgroupRoot, name, "cgroup.procs"))
		if err != nil {
			return RuntimeSnapshot{}, err
		}
		masked := false
		if target, err := os.Readlink(filepath.Join(auditor.maskRoot, name)); err == nil {
			masked = target == "/dev/null"
		} else if !errors.Is(err, os.ErrNotExist) {
			return RuntimeSnapshot{}, fmt.Errorf("observe systemd unit mask: %w", err)
		}
		units = append(units, UnitState{Name: name, Active: active, Masked: masked})
	}
	bound, err := readBoundListeners(auditor.procRoot)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	keys := make([]string, 0, len(bound))
	for key := range bound {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	listeners := make([]Listener, 0, len(keys))
	for _, key := range keys {
		protocol, portText, _ := strings.Cut(key, "/")
		port, _ := strconv.Atoi(portText)
		listeners = append(listeners, Listener{Protocol: protocol, Port: uint16(port), Owner: "host"})
	}
	return RuntimeSnapshot{Installed: clonePackagesForJournal(installed), SystemPackages: append([]InstalledPackage(nil), systemPackages...), Units: units, Listeners: listeners}, nil
}

func (auditor *LinuxAuditor) noAutostartPolicy(expectedDigest string) (NoAutostartPolicy, error) {
	policy, policyStat, err := auditor.readFileAndStat(auditor.policyPath, 8<<20)
	if err != nil {
		return NoAutostartPolicy{}, err
	}
	binary, _, err := auditor.readFileAndStat(auditor.binaryPath, 256<<20)
	if err != nil {
		return NoAutostartPolicy{}, err
	}
	policyDigest := sha256.Sum256(policy)
	binaryDigest := sha256.Sum256(binary)
	digest := hex.EncodeToString(policyDigest[:])
	if digest != expectedDigest {
		return NoAutostartPolicy{}, fmt.Errorf("package no-autostart policy digest differs from Plan")
	}
	return NoAutostartPolicy{Path: "/usr/sbin/policy-rc.d", Digest: digest, UID: policyStat.Uid, GID: policyStat.Gid, Mode: policyStat.Mode & 0o777, Regular: policyStat.Mode&unix.S_IFMT == unix.S_IFREG, ParentsSafe: true, SameLanPanelBinary: bytes.Equal(policyDigest[:], binaryDigest[:])}, nil
}

func (auditor *LinuxAuditor) fileIdentity(path string) (FileIdentity, error) {
	data, stat, err := auditor.readFileAndStat(path, 8<<20)
	if err != nil {
		return FileIdentity{}, err
	}
	digest := sha256.Sum256(data)
	return FileIdentity{Path: path, UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode & 0o777, Regular: stat.Mode&unix.S_IFMT == unix.S_IFREG, ParentsSafe: true, Digest: hex.EncodeToString(digest[:])}, nil
}

func (auditor *LinuxAuditor) readSafeFile(path string, maximum int64) ([]byte, error) {
	data, _, err := auditor.readFileAndStat(path, maximum)
	return data, err
}

func (auditor *LinuxAuditor) readFileAndStat(path string, maximum int64) ([]byte, unix.Stat_t, error) {
	parent, err := openSafeDirectory(filepath.Dir(path), auditor.strict)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	var before, after unix.Stat_t
	owner, group := uint32(0), uint32(0)
	if !auditor.strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != owner || before.Gid != group || before.Mode&0o022 != 0 || before.Size < 0 || before.Size > maximum {
		return nil, unix.Stat_t{}, fmt.Errorf("package audit file identity is unsafe")
	}
	data, err := readExactFD(fd, before.Size+1)
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim {
		return nil, unix.Stat_t{}, fmt.Errorf("package audit file changed while reading")
	}
	return data, after, nil
}

func openSafeDirectory(path string, strict bool) (int, error) {
	if !strict {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Mode&0o022 != 0 {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("test package audit directory is unsafe")
		}
		return fd, nil
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	relative := strings.TrimPrefix(path, "/")
	if relative == "" {
		return current, nil
	}
	owner, group := uint32(0), uint32(0)
	if !strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	for _, component := range strings.Split(relative, "/") {
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
		var stat unix.Stat_t
		if err := unix.Fstat(current, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || strict && (stat.Uid != 0 || stat.Gid != 0) || !strict && (stat.Uid != owner || stat.Gid != group) || stat.Mode&0o022 != 0 {
			_ = unix.Close(current)
			return -1, fmt.Errorf("package audit parent is linked, non-directory, incorrectly owned, or writable")
		}
	}
	return current, nil
}

func validateAuditorParent(path string) error {
	fd, err := openSafeDirectory(path, true)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func packageByName(packages []Package, name string) (Package, bool) {
	for _, pkg := range packages {
		if pkg.Name == name {
			return pkg, true
		}
	}
	return Package{}, false
}
