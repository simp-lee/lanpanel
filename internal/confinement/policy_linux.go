//go:build linux

// Package confinement owns the qualification-bound kernel policy for managed processes.
package confinement

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"
)

const SchemaVersion = "lanpanel.managed.confinement.v1"

// BPFLSMActive reports whether the kernel enabled the BPF LSM at boot. The
// compatibility installer may run without it; callers must report the weaker
// isolation rather than treating its absence as an installation failure.
func BPFLSMActive() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, value := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if strings.TrimSpace(value) == "bpf" {
			return true
		}
	}
	return false
}

type Profile struct {
	SchemaVersion         string   `json:"schema_version"`
	KernelRelease         string   `json:"kernel_release"`
	CgroupMode            string   `json:"cgroup_mode"`
	BindListenPolicy      string   `json:"bind_listen_policy"`
	ConnectPolicy         string   `json:"connect_policy"`
	FilesystemPolicy      string   `json:"filesystem_policy"`
	ProtectedDestinations []string `json:"protected_destinations"`
	QualificationDigest   string   `json:"qualification_digest"`
}

type UnitPolicy struct {
	ResourceID       string
	Cgroup           string
	BindListenPolicy string
	Directives       []string
	Digest           string
}

func ValidateUnitPolicy(policy UnitPolicy) error {
	short := strings.TrimPrefix(policy.ResourceID, "res_")
	if len(policy.ResourceID) != 36 || len(short) != 32 || !lowerHex(short) || policy.Cgroup != "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-"+short[:20]+".slice/lanpanel-app-"+short[:20]+".service" || policy.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" || !validDigest(policy.Digest) || strings.ToLower(policy.Digest) != policy.Digest || len(policy.Directives) == 0 {
		return fmt.Errorf("managed-process unit policy is invalid")
	}
	for index, directive := range policy.Directives {
		name, _, found := strings.Cut(directive, "=")
		if !found || name == "" || strings.ContainsAny(directive, "\x00\r\n") || index > 0 && policy.Directives[index-1] >= directive {
			return fmt.Errorf("managed-process unit policy directives are invalid")
		}
	}
	return nil
}

func ValidateProfile(profile Profile) error {
	if profile.SchemaVersion != SchemaVersion || profile.KernelRelease == "" || profile.CgroupMode != "unified_v2" || profile.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" || profile.ConnectPolicy != "systemd_cgroup_ip_deny_v1" || profile.FilesystemPolicy != "systemd_mount_namespace_v1" || !validDigest(profile.QualificationDigest) || len(profile.ProtectedDestinations) == 0 || len(profile.ProtectedDestinations) > 64 {
		return fmt.Errorf("managed-process confinement profile is incomplete or unqualified")
	}
	for index, destination := range profile.ProtectedDestinations {
		if !validCIDR(destination) || index > 0 && profile.ProtectedDestinations[index-1] >= destination {
			return fmt.Errorf("protected destination inventory is invalid or noncanonical")
		}
	}
	return nil
}

func Render(profile Profile, resourceID, workingDirectory, environmentFile, frontend, backend string, writePaths []string) (UnitPolicy, error) {
	if err := ValidateProfile(profile); err != nil {
		return UnitPolicy{}, err
	}
	short := strings.TrimPrefix(resourceID, "res_")
	if len(resourceID) != 36 || len(short) != 32 || !lowerHex(short) || !validSystemdPath(workingDirectory) || environmentFile != "" && !validSystemdPath(environmentFile) || frontend != "" && !validSystemdPath(frontend) || backend != "" && !validSystemdPath(backend) {
		return UnitPolicy{}, fmt.Errorf("managed-process policy authority is invalid")
	}
	cgroup := "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-" + short[:20] + ".slice/lanpanel-app-" + short[:20] + ".service"
	directives := []string{
		"NoNewPrivileges=yes", "AmbientCapabilities=", "RestrictSUIDSGID=yes",
		"PrivateTmp=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectProc=invisible", "ProcSubset=pid",
		"LockPersonality=yes", "RestrictRealtime=yes", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"SocketBindDeny=any", "UMask=" + map[bool]string{true: "0117", false: "0077"}[backend != ""],
		"TemporaryFileSystem=/run:ro", "InaccessiblePaths=/etc/lanpanel /var/lib/lanpanel/installation /var/lib/lanpanel/state /var/lib/lanpanel/safety /var/lib/lanpanel/ownership /var/lib/lanpanel/locks",
		"BindReadOnlyPaths=" + filepath.Join("/var/lib/lanpanel/resources", resourceID, "exec-authority.json"),
		"ReadOnlyPaths=" + workingDirectory,
	}
	if frontend != "" {
		directives = append(directives, "BindReadOnlyPaths="+frontend)
	}
	if backend != "" {
		directives = append(directives, "BindPaths="+filepath.Dir(backend))
	}
	if environmentFile != "" {
		directives = append(directives, "BindReadOnlyPaths="+environmentFile)
	}
	for _, destination := range profile.ProtectedDestinations {
		directives = append(directives, "IPAddressDeny="+destination)
	}
	for _, path := range writePaths {
		if !validSystemdPath(path) {
			return UnitPolicy{}, fmt.Errorf("managed-process write path is invalid")
		}
		directives = append(directives, "ReadWritePaths="+path)
	}
	slices.Sort(directives)
	sum := sha256.Sum256([]byte(strings.Join(directives, "\n") + "\n" + profile.QualificationDigest + "\n" + cgroup))
	return UnitPolicy{ResourceID: resourceID, Cgroup: cgroup, BindListenPolicy: profile.BindListenPolicy, Directives: directives, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func RelayPolicy(resourceID, cgroup string, directives []string) (UnitPolicy, error) {
	short := strings.TrimPrefix(resourceID, "res_")
	if len(short) != 32 || !lowerHex(short) || !validManagedCgroup(cgroup) || !strings.HasPrefix(cgroup, "/system.slice/lanpanel-relay-") || len(directives) == 0 {
		return UnitPolicy{}, fmt.Errorf("relay confinement policy identity is invalid")
	}
	values := append([]string(nil), directives...)
	slices.Sort(values)
	for _, directive := range values {
		name, _, found := strings.Cut(directive, "=")
		if !found || name == "" {
			return UnitPolicy{}, fmt.Errorf("relay confinement directive is invalid")
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "\n") + "\n" + cgroup + "\nsystemd_relay_unix_only_v1\n"))
	return UnitPolicy{ResourceID: resourceID, Cgroup: cgroup, BindListenPolicy: "systemd_relay_unix_only_v1", Directives: values, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func VerifyEffectiveRelay(policy UnitPolicy, effective map[string][]string) error {
	expected, err := RelayPolicy(policy.ResourceID, policy.Cgroup, policy.Directives)
	if err != nil || policy.BindListenPolicy != expected.BindListenPolicy || policy.Digest != expected.Digest {
		return fmt.Errorf("relay confinement policy identity is invalid")
	}
	return verifyEffectiveDirectives(policy.Directives, effective)
}

func VerifyEffective(policy UnitPolicy, effective map[string][]string) error {
	if policy.ResourceID == "" || policy.Cgroup == "" || policy.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" || !validDigest(policy.Digest) {
		return fmt.Errorf("confinement policy identity is invalid")
	}
	return verifyEffectiveDirectives(policy.Directives, effective)
}

func verifyEffectiveDirectives(directives []string, effective map[string][]string) error {
	want := map[string][]string{}
	for _, directive := range directives {
		name, value, _ := strings.Cut(directive, "=")
		want[name] = append(want[name], value)
	}
	for name, values := range want {
		actual := append([]string(nil), effective[name]...)
		if len(actual) == 0 {
			return fmt.Errorf("effective confinement property %q missing", name)
		}
		if listProperty(name) {
			actual = splitPropertyValues(actual)
			values = splitPropertyValues(values)
		}
		slices.Sort(actual)
		slices.Sort(values)
		if !slices.Equal(actual, values) {
			return fmt.Errorf("effective confinement property %q mismatched", name)
		}
	}
	return nil
}

type CgroupObservation struct {
	Cgroup    string
	PIDs      []int
	Populated bool
	Frozen    bool
	Digest    string
}

func ObserveCgroup(root, cgroup string) (CgroupObservation, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !validManagedCgroup(cgroup) {
		return CgroupObservation{}, fmt.Errorf("managed-process cgroup identity is invalid")
	}
	path := filepath.Join(root, strings.TrimPrefix(cgroup, "/"))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return CgroupObservation{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	read := func(name string, maximum int64) ([]byte, error) {
		child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(child), name)
		if file == nil {
			_ = unix.Close(child)
			return nil, fmt.Errorf("cgroup descriptor invalid")
		}
		defer func(ignore func() error) { _ = ignore() }(file.Close)
		return io.ReadAll(io.LimitReader(file, maximum+1))
	}
	processes, err := read("cgroup.procs", 1<<20)
	if err != nil {
		return CgroupObservation{}, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return CgroupObservation{}, err
	}
	childPopulated := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		child, childErr := ObserveCgroup(root, filepath.Join(cgroup, entry.Name()))
		if childErr != nil {
			return CgroupObservation{}, childErr
		}
		if child.Populated {
			childPopulated = true
		}
		for _, pid := range child.PIDs {
			processes = append(processes, []byte(strconv.Itoa(pid)+"\n")...)
		}
	}
	events, err := read("cgroup.events", 4096)
	if err != nil {
		return CgroupObservation{}, err
	}
	result := CgroupObservation{Cgroup: cgroup, PIDs: []int{}}
	for _, line := range strings.Fields(string(processes)) {
		pid, err := strconv.Atoi(line)
		if err != nil || pid <= 1 {
			return CgroupObservation{}, fmt.Errorf("cgroup process inventory is invalid")
		}
		result.PIDs = append(result.PIDs, pid)
	}
	slices.Sort(result.PIDs)
	fields := strings.Fields(string(events))
	if len(fields)%2 != 0 {
		return CgroupObservation{}, fmt.Errorf("cgroup event authority is malformed")
	}
	for index := 0; index < len(fields); index += 2 {
		switch fields[index] {
		case "populated":
			result.Populated = fields[index+1] == "1"
		case "frozen":
			result.Frozen = fields[index+1] == "1"
		}
	}
	result.PIDs = slices.Compact(result.PIDs)
	result.Populated = result.Populated || childPopulated
	if result.Populated != (len(result.PIDs) != 0) {
		return CgroupObservation{}, fmt.Errorf("cgroup populated state contradicts process inventory")
	}
	sum := sha256.Sum256([]byte(cgroup + "\x00" + string(processes) + "\x00" + string(events)))
	result.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return result, nil
}

func listProperty(name string) bool {
	switch name {
	case "IPAddressDeny", "BindReadOnlyPaths", "BindPaths", "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "RestrictAddressFamilies", "CapabilityBoundingSet", "AmbientCapabilities", "TemporaryFileSystem":
		return true
	}
	return false
}

func splitPropertyValues(values []string) []string {
	result := []string{}
	for _, value := range values {
		if value == "" {
			result = append(result, "")
			continue
		}
		result = append(result, strings.Fields(value)...)
	}
	return result
}

func validManagedCgroup(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, "/"), "/")
	rootParts := 0
	if len(parts) >= 4 && parts[0] == "lanpanel.slice" && parts[1] == "lanpanel-app.slice" && strings.HasPrefix(parts[2], "lanpanel-app-") && strings.HasSuffix(parts[2], ".slice") {
		id := strings.TrimSuffix(strings.TrimPrefix(parts[2], "lanpanel-app-"), ".slice")
		if len(id) != 20 || !lowerHex(id) || parts[3] != "lanpanel-app-"+id+".service" {
			return false
		}
		rootParts = 4
	} else if len(parts) >= 2 && parts[0] == "system.slice" && strings.HasPrefix(parts[1], "lanpanel-relay-") && strings.HasSuffix(parts[1], ".service") {
		id := strings.TrimSuffix(strings.TrimPrefix(parts[1], "lanpanel-relay-"), ".service")
		if len(id) != 20 || !lowerHex(id) {
			return false
		}
		rootParts = 2
	} else {
		return false
	}
	for _, part := range parts[rootParts:] {
		if part == "" || len(part) > 255 {
			return false
		}
		for _, character := range part {
			allowed := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:@-", character)
			if !allowed {
				return false
			}
		}
	}
	return true
}

func lowerHex(value string) bool {
	for _, character := range value {
		allowed := character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
		if !allowed {
			return false
		}
	}
	return true
}

func validSystemdPath(value string) bool {
	if value == "" || value == "/" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, `%:\\"'`) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validCIDR(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.String() == value
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
