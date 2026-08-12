//go:build linux

package preflight

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxOSReleaseBytes = 64 << 10

type LinuxPaths struct {
	OSRelease      string
	SystemdRoot    string
	APTExecutable  string
	DPKGExecutable string
	TCP            string
	TCP6           string
	UDP            string
	UDP6           string
}

type LinuxObserver struct {
	paths       LinuxPaths
	packageRead func(context.Context) (PackageObservation, error)
	now         func() time.Time
	strictRoot  bool
}

func NewLinuxObserver(packageRead func(context.Context) (PackageObservation, error)) (*LinuxObserver, error) {
	if packageRead == nil {
		return nil, fmt.Errorf("preflight requires the shared apt/dpkg readiness observer")
	}
	return &LinuxObserver{paths: LinuxPaths{OSRelease: "/etc/os-release", SystemdRoot: "/run/systemd/system", APTExecutable: "/usr/bin/apt-get", DPKGExecutable: "/usr/bin/dpkg", TCP: "/proc/net/tcp", TCP6: "/proc/net/tcp6", UDP: "/proc/net/udp", UDP6: "/proc/net/udp6"}, packageRead: packageRead, now: func() time.Time { return time.Now().UTC() }, strictRoot: true}, nil
}

func newTestLinuxObserver(paths LinuxPaths, packageRead func(context.Context) (PackageObservation, error), now func() time.Time) *LinuxObserver {
	return &LinuxObserver{paths: paths, packageRead: packageRead, now: now}
}

func (observer *LinuxObserver) ObserveExpansion(ctx context.Context, request ExpansionRequest) (ExpansionObservations, error) {
	if observer == nil || observer.packageRead == nil || observer.now == nil {
		return ExpansionObservations{}, fmt.Errorf("Linux preflight observer is unavailable")
	}
	if err := validateExpansionRequest(request); err != nil {
		return ExpansionObservations{}, err
	}
	platform, err := observer.readPlatform()
	if err != nil {
		return ExpansionObservations{}, err
	}
	systemd, err := observeDirectoryComponent(observer.paths.SystemdRoot)
	if err != nil {
		return ExpansionObservations{}, err
	}
	apt, err := observeExecutableComponent(observer.paths.APTExecutable)
	if err != nil {
		return ExpansionObservations{}, err
	}
	dpkg, err := observeExecutableComponent(observer.paths.DPKGExecutable)
	if err != nil {
		return ExpansionObservations{}, err
	}
	packages, err := observer.packageRead(ctx)
	if err != nil {
		return ExpansionObservations{}, err
	}
	dns, err := observer.ObserveDNS(ctx, request.Domains)
	if err != nil {
		return ExpansionObservations{}, err
	}
	listeners, err := observer.readListeners(ctx)
	if err != nil {
		return ExpansionObservations{}, err
	}
	paths := make([]PathObservation, 0, len(request.ManagedPaths))
	for _, requirement := range request.ManagedPaths {
		observation, err := observeManagedPath(requirement.Path)
		if err != nil {
			return ExpansionObservations{}, err
		}
		paths = append(paths, observation)
	}
	disks := make([]DiskObservation, 0, len(request.Disks))
	for _, requirement := range request.Disks {
		observation, err := observeDisk(requirement.Path)
		if err != nil {
			return ExpansionObservations{}, err
		}
		disks = append(disks, observation)
	}
	return ExpansionObservations{
		OperatingSystem: "linux", Architecture: runtime.GOARCH, Platform: platform,
		Clock:       observeClock(observer.now().UTC()),
		ExecutorUID: uint32(os.Geteuid()), Systemd: systemd, APT: apt, DPKG: dpkg, Packages: packages,
		DNS: dns, Listeners: listeners, ListenerInventoryComplete: true, Paths: paths, Disks: disks,
	}, nil
}

func (observer *LinuxObserver) readPlatform() (PlatformInfo, error) {
	path := observer.paths.OSRelease
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	} else if !errors.Is(err, os.ErrNotExist) {
		return PlatformInfo{}, fmt.Errorf("resolve exact OS release identity: %w", err)
	}
	data, err := readSafeBoundedFile(path, maxOSReleaseBytes, observer.strictRoot)
	if err != nil {
		return PlatformInfo{}, fmt.Errorf("observe exact OS release: %w", err)
	}
	return ParseOSRelease(string(data)), nil
}

func (observer *LinuxObserver) readListeners(ctx context.Context) ([]ListenerObservation, error) {
	result := []ListenerObservation{}
	for _, source := range []struct {
		path     string
		protocol string
		ipv6     bool
	}{{observer.paths.TCP, "tcp", false}, {observer.paths.TCP6, "tcp", true}, {observer.paths.UDP, "udp", false}, {observer.paths.UDP6, "udp", true}} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := readBoundedProcFile(source.path, 32<<20)
		if err != nil {
			return nil, fmt.Errorf("observe listener inventory: %w", err)
		}
		values, err := parseProcNet(data, source.protocol, source.ipv6)
		if err != nil {
			return nil, err
		}
		result = append(result, values...)
	}
	slices.SortFunc(result, compareListenerObservation)
	for index := 1; index < len(result); index++ {
		if compareListenerObservation(result[index-1], result[index]) == 0 {
			return nil, fmt.Errorf("listener inventory contains a duplicate socket identity")
		}
	}
	return result, nil
}

func (observer *LinuxObserver) ObserveDNS(ctx context.Context, domains []string) ([]DNSObservation, error) {
	if !canonicalStringSet(domains, canonicalDomain) {
		return nil, fmt.Errorf("DNS observation domains are noncanonical")
	}
	result := make([]DNSObservation, 0, len(domains))
	for _, domain := range domains {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
		if err != nil {
			result = append(result, DNSObservation{Domain: domain, Failure: "dns_lookup_failed"})
			continue
		}
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.Unmap().String())
		}
		slices.Sort(values)
		values = slices.Compact(values)
		result = append(result, DNSObservation{Domain: domain, Addresses: values})
	}
	return result, nil
}

func observeClock(now time.Time) ClockObservation {
	var timex unix.Timex
	state, err := unix.Adjtimex(&timex)
	return ClockObservation{Now: now, Synchronized: err == nil && state != unix.TIME_ERROR && timex.Status&unix.STA_UNSYNC == 0, Source: "kernel_adjtimex"}
}

func parseProcNet(data []byte, protocol string, ipv6 bool) ([]ListenerObservation, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	if !scanner.Scan() {
		return nil, fmt.Errorf("listener inventory header is missing")
	}
	result := []ListenerObservation{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return nil, fmt.Errorf("listener inventory row is malformed")
		}
		state := fields[3]
		if protocol == "tcp" && state != "0A" {
			continue
		}
		addressText, portText, found := strings.Cut(fields[1], ":")
		if !found {
			return nil, fmt.Errorf("listener address is malformed")
		}
		address, err := parseProcAddress(addressText, ipv6)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 16, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("listener port is invalid")
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			return nil, fmt.Errorf("listener socket identity is invalid")
		}
		result = append(result, ListenerObservation{Protocol: protocol, Address: address, Port: uint16(port), SocketInode: inode})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func parseProcAddress(value string, ipv6 bool) (string, error) {
	if ipv6 {
		if len(value) != 32 {
			return "", fmt.Errorf("IPv6 listener address is malformed")
		}
		bytes := make([]byte, 16)
		for word := 0; word < 4; word++ {
			for offset := 0; offset < 4; offset++ {
				parsed, err := strconv.ParseUint(value[word*8+(3-offset)*2:word*8+(4-offset)*2], 16, 8)
				if err != nil {
					return "", fmt.Errorf("IPv6 listener address is malformed")
				}
				bytes[word*4+offset] = byte(parsed)
			}
		}
		address, ok := netipAddrFrom16(bytes)
		if !ok {
			return "", fmt.Errorf("IPv6 listener address is invalid")
		}
		return address, nil
	}
	if len(value) != 8 {
		return "", fmt.Errorf("IPv4 listener address is malformed")
	}
	bytes := make([]byte, 4)
	for index := range bytes {
		parsed, err := strconv.ParseUint(value[(3-index)*2:(4-index)*2], 16, 8)
		if err != nil {
			return "", fmt.Errorf("IPv4 listener address is malformed")
		}
		bytes[index] = byte(parsed)
	}
	return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]), nil
}

func netipAddrFrom16(value []byte) (string, bool) {
	if len(value) != 16 {
		return "", false
	}
	var bytes [16]byte
	copy(bytes[:], value)
	address := netip.AddrFrom16(bytes)
	return address.String(), address.IsValid()
}

func observeManagedPath(path string) (PathObservation, error) {
	observation := PathObservation{Path: path}
	if err := validateSafeParents(path); err != nil {
		observation.Failure = err.Error()
		return observation, nil
	}
	observation.ParentsSafe = true
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); errors.Is(err, os.ErrNotExist) {
		return observation, nil
	} else if err != nil {
		return PathObservation{}, err
	}
	observation.Exists, observation.UID, observation.GID, observation.Mode, observation.Device, observation.Inode = true, stat.Uid, stat.Gid, stat.Mode&0o7777, uint64(stat.Dev), stat.Ino
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		observation.Kind = ManagedPathDirectory
	case unix.S_IFREG:
		observation.Kind = ManagedPathRegular
	default:
		observation.Failure = "managed path has an unsupported type"
	}
	return observation, nil
}

func observeDisk(path string) (DiskObservation, error) {
	if err := validateSafeParents(path); err != nil {
		return DiskObservation{Path: path, Failure: err.Error()}, nil
	}
	probe := path
	for {
		var stat unix.Stat_t
		if err := unix.Lstat(probe, &stat); err == nil {
			var filesystem unix.Statfs_t
			if err := unix.Statfs(probe, &filesystem); err != nil {
				return DiskObservation{}, err
			}
			available := filesystem.Bavail * uint64(filesystem.Bsize)
			return DiskObservation{Path: path, Device: uint64(stat.Dev), AvailableBytes: available, ReadOnly: filesystem.Flags&unix.ST_RDONLY != 0}, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return DiskObservation{}, err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return DiskObservation{Path: path, Failure: "no existing managed filesystem ancestor"}, nil
		}
		probe = parent
	}
}

func observeDirectoryComponent(path string) (ComponentObservation, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ComponentObservation{}, nil
		}
		return ComponentObservation{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
		return ComponentObservation{}, nil
	}
	return ComponentObservation{Available: true, Identity: fmt.Sprintf("%d:%d:%o", stat.Dev, stat.Ino, stat.Mode&0o7777)}, nil
}

func observeExecutableComponent(path string) (ComponentObservation, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ComponentObservation{}, nil
		}
		return ComponentObservation{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Mode&0o111 == 0 || stat.Nlink != 1 {
		return ComponentObservation{}, nil
	}
	return ComponentObservation{Available: true, Identity: fmt.Sprintf("%d:%d:%o:%d", stat.Dev, stat.Ino, stat.Mode&0o7777, stat.Size)}, nil
}

func readBoundedProcFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, fmt.Errorf("procfs preflight path or bound is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("procfs preflight descriptor is invalid")
	}
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("procfs preflight file identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		return nil, fmt.Errorf("procfs preflight file changed or exceeded its bound")
	}
	return data, nil
}

func readSafeBoundedFile(path string, maximum int64, requireRoot bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, fmt.Errorf("read-only preflight path or bound is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("read-only preflight descriptor is invalid")
	}
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 0 || before.Size > maximum || requireRoot && (before.Uid != 0 || before.Mode&0o022 != 0) {
		return nil, fmt.Errorf("read-only preflight file identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size || int64(len(data)) > maximum || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		return nil, fmt.Errorf("read-only preflight file changed or exceeded its bound")
	}
	return data, nil
}

func validateSafeParents(path string) error {
	parent := filepath.Dir(path)
	for {
		var stat unix.Stat_t
		if err := unix.Lstat(parent, &stat); errors.Is(err, os.ErrNotExist) {
			parent = filepath.Dir(parent)
			continue
		} else if err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return fmt.Errorf("managed path parent is non-directory, non-root-owned, or writable")
		}
		if parent == "/" {
			break
		}
		parent = filepath.Dir(parent)
	}
	return nil
}
