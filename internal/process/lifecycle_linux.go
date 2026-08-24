//go:build linux

package process

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type RuntimeObservation struct {
	Cgroup         confinement.CgroupObservation
	SocketPresent  bool
	ListenerInodes []uint64
	ObservedAt     time.Time
	Digest         string
}

func Observe(ctx context.Context, cgroupRoot string, bundle domain.ProcessBundle, endpointKind domain.LocalEndpointKind, procNetFiles []string) (RuntimeObservation, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeObservation{}, err
	}
	cgroup, err := confinement.ObserveCgroup(cgroupRoot, bundle.Cgroup)
	if err != nil {
		return RuntimeObservation{}, err
	}
	result := RuntimeObservation{Cgroup: cgroup, ObservedAt: time.Now().UTC(), ListenerInodes: []uint64{}}
	switch endpointKind {
	case domain.LocalEndpointUnixSocketActivation:
		if err := requireSocket(bundle.FrontendEndpoint); err != nil {
			return RuntimeObservation{}, err
		}
		result.SocketPresent = true
	case domain.LocalEndpointRelayUnix:
		if err := requireSocket(bundle.FrontendEndpoint); err != nil {
			return RuntimeObservation{}, err
		}
		if err := requireSocket(bundle.BackendEndpoint); err != nil {
			return RuntimeObservation{}, err
		}
		result.SocketPresent = true
	case domain.LocalEndpointTCPSocketActivation:
		if len(bundle.EndpointSocketUnits) != 1 {
			return RuntimeObservation{}, fmt.Errorf("PID1 TCP socket authority incomplete")
		}
		result.SocketPresent = true
	default:
		return RuntimeObservation{}, fmt.Errorf("managed-process endpoint kind is invalid")
	}
	owned, err := cgroupSocketInodes(cgroup.PIDs)
	if err != nil {
		return RuntimeObservation{}, err
	}
	ownedSet := map[uint64]struct{}{}
	for _, inode := range owned {
		ownedSet[inode] = struct{}{}
	}
	wantAddress := netip.Addr{}
	if endpointKind == domain.LocalEndpointTCPSocketActivation {
		wantAddress, err = netip.ParseAddr(bundle.TCPAddress)
		if err != nil || bundle.TCPPort == 0 {
			return RuntimeObservation{}, fmt.Errorf("PID1 TCP socket address authority incomplete")
		}
	}
	for _, path := range procNetFiles {
		listeners, err := readListeners(path)
		if err != nil {
			return RuntimeObservation{}, err
		}
		for _, listener := range listeners {
			if _, present := ownedSet[listener.Inode]; !present {
				continue
			}
			if endpointKind == domain.LocalEndpointTCPSocketActivation && (listener.Address != wantAddress || listener.Port != bundle.TCPPort) {
				return RuntimeObservation{}, fmt.Errorf("inherited TCP listener differs from declared address or port")
			}
			result.ListenerInodes = append(result.ListenerInodes, listener.Inode)
		}
	}
	if endpointKind == domain.LocalEndpointTCPSocketActivation {
		if len(result.ListenerInodes) != 1 {
			return RuntimeObservation{}, fmt.Errorf("exact inherited TCP listener not observed")
		}
	} else if len(result.ListenerInodes) != 0 {
		return RuntimeObservation{}, fmt.Errorf("managed process cgroup owns forbidden INET listener")
	}
	slices.Sort(result.ListenerInodes)
	result.ListenerInodes = slices.Compact(result.ListenerInodes)
	data := fmt.Sprintf("%s\x00%s\x00%t\x00%v", bundle.Cgroup, cgroup.Digest, result.SocketPresent, result.ListenerInodes)
	sum := sha256.Sum256([]byte(data))
	result.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return result, nil
}

func VerifyRunning(observation RuntimeObservation) error {
	if !observation.Cgroup.Populated || len(observation.Cgroup.PIDs) == 0 || !observation.SocketPresent || observation.Digest == "" {
		return fmt.Errorf("managed process cgroup or protected endpoint is not running")
	}
	return nil
}

func ObserveStopped(ctx context.Context, cgroupRoot string, bundle domain.ProcessBundle) (RuntimeObservation, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeObservation{}, err
	}
	path := filepath.Join(cgroupRoot, strings.TrimPrefix(bundle.Cgroup, "/"))
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err == nil {
		observed, observeErr := confinement.ObserveCgroup(cgroupRoot, bundle.Cgroup)
		if observeErr != nil {
			return RuntimeObservation{}, observeErr
		}
		if observed.Populated || len(observed.PIDs) != 0 {
			return RuntimeObservation{}, fmt.Errorf("managed-process cgroup remains populated after stop")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return RuntimeObservation{}, err
	}
	for _, endpoint := range []string{bundle.FrontendEndpoint, bundle.BackendEndpoint} {
		if endpoint == "" {
			continue
		}
		if err := unix.Lstat(endpoint, &stat); err == nil {
			return RuntimeObservation{}, fmt.Errorf("managed-process endpoint remains after stop")
		} else if !errors.Is(err, unix.ENOENT) {
			return RuntimeObservation{}, err
		}
	}
	if bundle.TCPAddress != "" {
		address, err := netip.ParseAddr(bundle.TCPAddress)
		if err != nil {
			return RuntimeObservation{}, err
		}
		path := "/proc/net/tcp"
		if address.Is6() {
			path = "/proc/net/tcp6"
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return RuntimeObservation{}, err
		}
		present, err := procTCPListenerPresent(data, address, bundle.TCPPort)
		if err != nil {
			return RuntimeObservation{}, err
		}
		if present {
			return RuntimeObservation{}, fmt.Errorf("managed-process TCP endpoint remains after stop")
		}
	}
	if bundle.FrontendEndpoint == "" || len(bundle.EndpointSocketUnits) == 0 {
		return RuntimeObservation{}, fmt.Errorf("applied endpoint unit inventory incomplete")
	}
	observedAt := time.Now().UTC()
	sum := sha256.Sum256([]byte(bundle.Cgroup + "\x00stopped\x00" + observedAt.Format(time.RFC3339Nano)))
	return RuntimeObservation{Cgroup: confinement.CgroupObservation{Cgroup: bundle.Cgroup, PIDs: []int{}, Populated: false}, ListenerInodes: []uint64{}, ObservedAt: observedAt, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func VerifyStopped(observation RuntimeObservation) error {
	if observation.Cgroup.Populated || len(observation.Cgroup.PIDs) != 0 || len(observation.ListenerInodes) != 0 {
		return fmt.Errorf("managed process cgroup or listener remains")
	}
	return nil
}

func requireSocket(path string) error {
	var stat unix.Stat_t
	if path == "" || unix.Lstat(path, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("PID1-owned socket is absent or unsafe")
	}
	return nil
}

func cgroupSocketInodes(pids []int) ([]uint64, error) {
	result := []uint64{}
	for _, pid := range pids {
		directory := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join(directory, entry.Name()))
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if err != nil || inode == 0 {
				return nil, fmt.Errorf("process socket inode is invalid")
			}
			result = append(result, inode)
		}
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

func procTCPListenerPresent(data []byte, want netip.Addr, port uint16) (bool, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	if !scanner.Scan() {
		return false, fmt.Errorf("TCP listener inventory header missing")
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return false, fmt.Errorf("TCP listener inventory row malformed")
		}
		if fields[3] != "0A" {
			continue
		}
		addressText, portText, found := strings.Cut(fields[1], ":")
		if !found {
			return false, fmt.Errorf("TCP listener address malformed")
		}
		observed, err := parseProcTCPAddress(addressText, want.Is6())
		if err != nil {
			return false, err
		}
		observedPort, err := strconv.ParseUint(portText, 16, 16)
		if err != nil {
			return false, fmt.Errorf("TCP listener port malformed")
		}
		if observed == want && uint16(observedPort) == port {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func parseProcTCPAddress(value string, ipv6 bool) (netip.Addr, error) {
	size := 4
	if ipv6 {
		size = 16
	}
	if len(value) != size*2 {
		return netip.Addr{}, fmt.Errorf("TCP listener address width invalid")
	}
	bytes := make([]byte, size)
	if ipv6 {
		for word := 0; word < 4; word++ {
			for offset := 0; offset < 4; offset++ {
				parsed, err := strconv.ParseUint(value[word*8+(3-offset)*2:word*8+(4-offset)*2], 16, 8)
				if err != nil {
					return netip.Addr{}, err
				}
				bytes[word*4+offset] = byte(parsed)
			}
		}
		var value16 [16]byte
		copy(value16[:], bytes)
		return netip.AddrFrom16(value16), nil
	}
	for index := range bytes {
		parsed, err := strconv.ParseUint(value[(3-index)*2:(4-index)*2], 16, 8)
		if err != nil {
			return netip.Addr{}, err
		}
		bytes[index] = byte(parsed)
	}
	var value4 [4]byte
	copy(value4[:], bytes)
	return netip.AddrFrom4(value4), nil
}

type tcpListener struct {
	Address netip.Addr
	Port    uint16
	Inode   uint64
}

func readListeners(path string) ([]tcpListener, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	result := []tcpListener{}
	scanner := bufio.NewScanner(io.LimitReader(file, 32<<20))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		addressText, portText, found := strings.Cut(fields[1], ":")
		if !found {
			return nil, fmt.Errorf("listener address is invalid")
		}
		address, err := parseProcTCPAddress(addressText, len(addressText) == 32)
		if err != nil {
			return nil, fmt.Errorf("listener address is invalid: %w", err)
		}
		port, err := strconv.ParseUint(portText, 16, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("listener port is invalid")
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			return nil, fmt.Errorf("listener inode is invalid")
		}
		result = append(result, tcpListener{Address: address, Port: uint16(port), Inode: inode})
	}
	return result, scanner.Err()
}
