//go:build linux

package process

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"lanpanel/internal/resource"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	managedExecSchema       = "lanpanel.managed.exec.v2"
	maximumManagedExecBytes = 32 << 10
)

type ExecAuthority struct {
	SchemaVersion string                     `json:"schema_version"`
	ResourceID    string                     `json:"resource_id"`
	UID           uint32                     `json:"uid"`
	GID           uint32                     `json:"gid"`
	Service       domain.ManagedService      `json:"service"`
	Endpoint      string                     `json:"endpoint"`
	Policy        confinement.UnitPolicy     `json:"policy"`
	Evidence      resource.ReferenceEvidence `json:"evidence"`
	SecretDigests []string                   `json:"secret_digests"`
}

func LoadExecAuthority(resourceID string) (ExecAuthority, error) {
	path := AuthorityPath(resourceID)
	file, err := os.Open(path)
	if err != nil {
		return ExecAuthority{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximumManagedExecBytes {
		return ExecAuthority{}, fmt.Errorf("managed execution authority file unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumManagedExecBytes+1))
	if err != nil || int64(len(payload)) != stat.Size {
		return ExecAuthority{}, fmt.Errorf("managed execution authority changed")
	}
	var authority ExecAuthority
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&authority); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ExecAuthority{}, fmt.Errorf("managed execution authority malformed")
	}
	canonical, _ := json.Marshal(authority)
	if !bytes.Equal(canonical, payload) || authority.SchemaVersion != managedExecSchema || authority.ResourceID != resourceID {
		return ExecAuthority{}, fmt.Errorf("managed execution authority noncanonical")
	}
	if _, err := secretInventory(authority.SecretDigests); err != nil {
		return ExecAuthority{}, err
	}
	return authority, nil
}

func Execute(args []string) error {
	runtime.LockOSThread()
	if len(args) != 0 || os.Geteuid() != 0 {
		return fmt.Errorf("managed executor requires fixed root PID1 invocation")
	}
	authorityPath := os.Getenv("LANPANEL_EXEC_AUTHORITY")
	if authorityPath == "" || authorityPath != filepath.Clean(authorityPath) || !filepath.IsAbs(authorityPath) || !strings.HasPrefix(authorityPath, "/var/lib/lanpanel/resources/res_") {
		return fmt.Errorf("managed execution authority path invalid")
	}
	file, err := os.Open(authorityPath)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximumManagedExecBytes {
		return fmt.Errorf("managed execution authority file unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumManagedExecBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumManagedExecBytes {
		return fmt.Errorf("managed execution authority invalid")
	}
	var authority ExecAuthority
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&authority); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("managed execution authority malformed")
	}
	canonical, _ := json.Marshal(authority)
	endpointEnv := os.Getenv("LANPANEL_HTTP_SOCKET")
	if !bytes.Equal(canonical, payload) || authority.SchemaVersion != managedExecSchema || authority.ResourceID == "" || AuthorityPath(authority.ResourceID) != authorityPath || authority.UID == 0 || authority.GID == 0 || authority.Endpoint == "" || authority.Policy.ResourceID != authority.ResourceID || endpointEnv != "" && endpointEnv != "/proc/self/fd/3" || endpointEnv == "" && (strings.HasPrefix(authority.Endpoint, "/proc/") || authority.Endpoint != filepath.Join("/var/lib/lanpanel/resources", authority.ResourceID, "backend/http.sock")) {
		return fmt.Errorf("managed execution authority noncanonical")
	}
	if endpointEnv == "" {
		if err := removeStaleBackend(authority.Endpoint, authority.UID); err != nil {
			return err
		}
	}
	knownSecrets, err := secretInventory(authority.SecretDigests)
	if err != nil {
		return err
	}
	evidence, err := resource.ValidateServiceReferences(authority.Service, authority.UID, knownSecrets)
	if err != nil {
		return err
	}
	if evidence.ExecutableDigest != authority.Evidence.ExecutableDigest || evidence.WorkingDirectoryIdentity != authority.Evidence.WorkingDirectoryIdentity || evidence.EnvironmentFingerprint != authority.Evidence.EnvironmentFingerprint || !slices.Equal(evidence.WritePathIdentities, authority.Evidence.WritePathIdentities) {
		return fmt.Errorf("managed external reference evidence changed")
	}
	environment := []string{"LANG=C", "LC_ALL=C"}
	if authority.Service.EnvironmentFile != "" {
		values, fingerprint, err := resource.ReadEnvironmentFileWithFingerprint(authority.Service.EnvironmentFile)
		if err != nil {
			return err
		}
		if fingerprint != authority.Evidence.EnvironmentFingerprint {
			return fmt.Errorf("managed environment reference changed")
		}
		environment = append(environment, values...)
	}
	for capability := 0; capability <= 63; capability++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil && err != unix.EINVAL {
			return err
		}
	}
	if err := unix.Setgroups(nil); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Setresgid(int(authority.GID), int(authority.GID), int(authority.GID)); err != nil {
		return err
	}
	if err := unix.Setresuid(int(authority.UID), int(authority.UID), int(authority.UID)); err != nil {
		return err
	}
	if os.Geteuid() != int(authority.UID) || os.Getegid() != int(authority.GID) {
		return fmt.Errorf("managed executor failed to enter exact identity")
	}
	if err := dropManagedCapabilities(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := verifyBindListenDenied(authority.Policy); err != nil {
		return err
	}
	endpoint := authority.Endpoint
	if endpointEnv != "" {
		endpoint = endpointEnv
	}
	environment = append(environment, "LANPANEL_HTTP_SOCKET="+endpoint)
	if endpointEnv != "" {
		environment = append(environment, "LISTEN_PID="+fmt.Sprint(os.Getpid()), "LISTEN_FDS=1", "LISTEN_FDNAMES=lanpanel-http")
	}
	argv := append([]string{authority.Service.Executable}, authority.Service.Arguments...)
	return unix.Exec(authority.Service.Executable, argv, environment)
}

func secretInventory(values []string) (map[string]struct{}, error) {
	if values == nil || !slices.IsSorted(values) {
		return nil, fmt.Errorf("managed execution secret inventory is not canonical")
	}
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validSecretDigest(value) {
			return nil, fmt.Errorf("managed execution secret inventory is not canonical")
		}
		if _, duplicate := result[value]; duplicate {
			return nil, fmt.Errorf("managed execution secret inventory is not canonical")
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func validSecretDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && strings.ToLower(value) == value
}

func removeStaleBackend(path string, uid uint32) error {
	var parent, stat unix.Stat_t
	if err := unix.Lstat(filepath.Dir(path), &parent); err != nil {
		return err
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0o7777 != 0o2770 || parent.Uid != uid || parent.Gid == 0 {
		return fmt.Errorf("managed backend parent identity is unsafe")
	}
	if err := unix.Lstat(path, &stat); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != uid || stat.Gid != parent.Gid || stat.Mode&0o777 != 0o660 {
		return fmt.Errorf("stale managed backend identity is unsafe")
	}
	return unix.Unlink(path)
}

func verifyBindListenDenied(policy confinement.UnitPolicy) error {
	if policy.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" {
		return fmt.Errorf("managed bind/listen policy identity is unsupported")
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		listenErr := unix.Listen(fd, 1)
		_ = unix.Close(fd)
		if !errors.Is(listenErr, unix.EACCES) {
			return fmt.Errorf("BPF LSM unbound INET listen probe was not denied: %w", listenErr)
		}
		fd, err = unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		var bindErr error
		if family == unix.AF_INET {
			bindErr = unix.Bind(fd, &unix.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}})
		} else {
			bindErr = unix.Bind(fd, &unix.SockaddrInet6{Port: 0, Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
		}
		_ = unix.Close(fd)
		if !errors.Is(bindErr, unix.EACCES) {
			return fmt.Errorf("systemd explicit INET bind probe was not denied: %w", bindErr)
		}
	}
	return nil
}

func dropManagedCapabilities() error {
	var data [2]unix.CapUserData
	header := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capset(header, &data[0]); err != nil {
		return err
	}
	var observed [2]unix.CapUserData
	if err := unix.Capget(header, &observed[0]); err != nil {
		return err
	}
	for _, word := range observed {
		if word.Effective != 0 || word.Permitted != 0 || word.Inheritable != 0 {
			return fmt.Errorf("managed capability state is not empty")
		}
	}
	return nil
}

func AuthorityPath(resourceID string) string {
	return filepath.Join("/var/lib/lanpanel/resources", resourceID, "exec-authority.json")
}
