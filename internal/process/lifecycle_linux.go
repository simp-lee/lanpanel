//go:build linux

package process

import (
	"bufio"
	"bytes"
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

const maximumProcUnixBytes = 32 << 20

const (
	unixOwnerPID1        = "pid1/socket-unit"
	unixOwnerApplication = "application-cgroup"
	unixOwnerRelay       = "relay-cgroup"
)

type RuntimeObservation struct {
	Cgroup         confinement.CgroupObservation
	SocketPresent  bool
	ListenerInodes []uint64
	ObservedAt     time.Time
	Digest         string
}

type unixListener struct {
	Path  string
	Inode uint64
	Type  uint64
}

type unixEndpointExpectation struct {
	Role   string
	Path   string
	Owners []string
}

type unixListenerEvidence struct {
	Role   string
	Path   string
	Inode  uint64
	Type   uint64
	Owners []string
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
	applicationInodes, err := cgroupSocketInodes(cgroup.PIDs)
	if err != nil {
		return RuntimeObservation{}, err
	}
	applicationSet := socketInodeSet(applicationInodes)
	inetInodes := []uint64{}
	wantAddress := netip.Addr{}
	if endpointKind == domain.LocalEndpointTCPSocketActivation {
		if len(bundle.EndpointSocketUnits) != 1 {
			return RuntimeObservation{}, fmt.Errorf("PID1 TCP socket authority incomplete")
		}
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
			if _, present := applicationSet[listener.Inode]; !present {
				continue
			}
			if endpointKind == domain.LocalEndpointTCPSocketActivation && (listener.Address != wantAddress || listener.Port != bundle.TCPPort) {
				return RuntimeObservation{}, fmt.Errorf("inherited TCP listener differs from declared address or port")
			}
			inetInodes = append(inetInodes, listener.Inode)
		}
	}
	slices.Sort(inetInodes)
	inetInodes = slices.Compact(inetInodes)

	unixEvidence := []unixListenerEvidence{}
	relayCgroupDigest := ""
	switch endpointKind {
	case domain.LocalEndpointUnixSocketActivation:
		if _, err := unixTopology(bundle, endpointKind); err != nil {
			return RuntimeObservation{}, err
		}
		if len(inetInodes) != 0 {
			return RuntimeObservation{}, fmt.Errorf("managed process cgroup owns forbidden INET listener")
		}
		if err := requireSocket(bundle.FrontendEndpoint); err != nil {
			return RuntimeObservation{}, err
		}
		listeners, err := readUnixListeners("/proc/net/unix")
		if err != nil {
			return RuntimeObservation{}, err
		}
		pid1Inodes, err := cgroupSocketInodes([]int{1})
		if err != nil {
			return RuntimeObservation{}, err
		}
		unixEvidence, err = verifyUnixListeners(
			listeners,
			[]unixEndpointExpectation{{Role: "frontend", Path: bundle.FrontendEndpoint, Owners: []string{unixOwnerPID1, unixOwnerApplication}}},
			map[string][]uint64{unixOwnerPID1: pid1Inodes, unixOwnerApplication: applicationInodes},
			[]string{unixOwnerApplication},
		)
		if err != nil {
			return RuntimeObservation{}, err
		}
		result.SocketPresent = true
	case domain.LocalEndpointRelayUnix:
		relayCgroup, err := unixTopology(bundle, endpointKind)
		if err != nil {
			return RuntimeObservation{}, err
		}
		if len(inetInodes) != 0 {
			return RuntimeObservation{}, fmt.Errorf("managed process cgroup owns forbidden INET listener")
		}
		if err := requireSocket(bundle.FrontendEndpoint); err != nil {
			return RuntimeObservation{}, err
		}
		if err := requireSocket(bundle.BackendEndpoint); err != nil {
			return RuntimeObservation{}, err
		}
		relay, err := confinement.ObserveCgroup(cgroupRoot, relayCgroup)
		if err != nil {
			return RuntimeObservation{}, err
		}
		if !relay.Populated || len(relay.PIDs) == 0 {
			return RuntimeObservation{}, fmt.Errorf("relay cgroup is not running")
		}
		relayInodes, err := cgroupSocketInodes(relay.PIDs)
		if err != nil {
			return RuntimeObservation{}, err
		}
		pid1Inodes, err := cgroupSocketInodes([]int{1})
		if err != nil {
			return RuntimeObservation{}, err
		}
		listeners, err := readUnixListeners("/proc/net/unix")
		if err != nil {
			return RuntimeObservation{}, err
		}
		unixEvidence, err = verifyUnixListeners(
			listeners,
			[]unixEndpointExpectation{
				{Role: "frontend", Path: bundle.FrontendEndpoint, Owners: []string{unixOwnerPID1, unixOwnerRelay}},
				{Role: "backend", Path: bundle.BackendEndpoint, Owners: []string{unixOwnerApplication}},
			},
			map[string][]uint64{unixOwnerPID1: pid1Inodes, unixOwnerApplication: applicationInodes, unixOwnerRelay: relayInodes},
			[]string{unixOwnerApplication, unixOwnerRelay},
		)
		if err != nil {
			return RuntimeObservation{}, err
		}
		relayCgroupDigest = relay.Digest
		result.SocketPresent = true
	case domain.LocalEndpointTCPSocketActivation:
		if len(inetInodes) != 1 {
			return RuntimeObservation{}, fmt.Errorf("exact inherited TCP listener not observed")
		}
		listeners, err := readUnixListeners("/proc/net/unix")
		if err != nil {
			return RuntimeObservation{}, err
		}
		if _, err := verifyUnixListeners(listeners, nil, map[string][]uint64{unixOwnerApplication: applicationInodes}, []string{unixOwnerApplication}); err != nil {
			return RuntimeObservation{}, err
		}
		result.SocketPresent = true
	default:
		return RuntimeObservation{}, fmt.Errorf("managed-process endpoint kind is invalid")
	}

	result.ListenerInodes = append(result.ListenerInodes, inetInodes...)
	for _, evidence := range unixEvidence {
		result.ListenerInodes = append(result.ListenerInodes, evidence.Inode)
	}
	slices.Sort(result.ListenerInodes)
	result.ListenerInodes = slices.Compact(result.ListenerInodes)
	result.Digest = runtimeObservationDigest(bundle.Cgroup, cgroup.Digest, relayCgroupDigest, result.SocketPresent, inetInodes, unixEvidence)
	return result, nil
}

func VerifyRunning(observation RuntimeObservation) error {
	if !observation.Cgroup.Populated || len(observation.Cgroup.PIDs) == 0 || !observation.SocketPresent || len(observation.ListenerInodes) == 0 || observation.Digest == "" {
		return fmt.Errorf("managed process cgroup or protected endpoint is not running")
	}
	return nil
}

func ObserveStopped(ctx context.Context, cgroupRoot string, bundle domain.ProcessBundle) (RuntimeObservation, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeObservation{}, err
	}
	if err := requireStoppedCgroup(cgroupRoot, bundle.Cgroup); err != nil {
		return RuntimeObservation{}, err
	}
	if bundle.RelayRequired {
		relayCgroup, err := unixTopology(bundle, domain.LocalEndpointRelayUnix)
		if err != nil {
			return RuntimeObservation{}, err
		}
		if err := requireStoppedCgroup(cgroupRoot, relayCgroup); err != nil {
			return RuntimeObservation{}, fmt.Errorf("managed-process relay: %w", err)
		}
	}
	var stat unix.Stat_t
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

func requireStoppedCgroup(cgroupRoot, cgroup string) error {
	path := filepath.Join(cgroupRoot, strings.TrimPrefix(cgroup, "/"))
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	observed, err := confinement.ObserveCgroup(cgroupRoot, cgroup)
	if err != nil {
		return err
	}
	if observed.Populated || len(observed.PIDs) != 0 {
		return fmt.Errorf("cgroup remains populated after stop")
	}
	return nil
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

func unixTopology(bundle domain.ProcessBundle, endpointKind domain.LocalEndpointKind) (string, error) {
	parts := strings.Split(strings.TrimPrefix(bundle.Cgroup, "/"), "/")
	if len(parts) != 4 || parts[0] != "lanpanel.slice" || parts[1] != "lanpanel-app.slice" || !strings.HasPrefix(parts[2], "lanpanel-app-") || !strings.HasSuffix(parts[2], ".slice") {
		return "", fmt.Errorf("unix endpoint cgroup topology is invalid")
	}
	short := strings.TrimSuffix(strings.TrimPrefix(parts[2], "lanpanel-app-"), ".slice")
	if len(short) != 20 || parts[3] != "lanpanel-app-"+short+".service" {
		return "", fmt.Errorf("unix endpoint cgroup topology is invalid")
	}
	for _, character := range short {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", fmt.Errorf("unix endpoint cgroup topology is invalid")
		}
	}
	if len(bundle.EndpointSocketUnits) != 1 || bundle.EndpointSocketUnits[0] != "lanpanel-app-"+short+".socket" {
		return "", fmt.Errorf("PID1 Unix socket authority incomplete")
	}
	switch endpointKind {
	case domain.LocalEndpointUnixSocketActivation:
		if bundle.RelayRequired || bundle.FrontendEndpoint == "" || bundle.BackendEndpoint != "" {
			return "", fmt.Errorf("unix socket-activation topology is invalid")
		}
		return "", nil
	case domain.LocalEndpointRelayUnix:
		if !bundle.RelayRequired || bundle.FrontendEndpoint == "" || bundle.BackendEndpoint == "" {
			return "", fmt.Errorf("unix relay topology is invalid")
		}
		return "/system.slice/lanpanel-relay-" + short + ".service", nil
	default:
		return "", fmt.Errorf("unix endpoint kind is invalid")
	}
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
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
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

func socketInodeSet(inodes []uint64) map[uint64]struct{} {
	result := make(map[uint64]struct{}, len(inodes))
	for _, inode := range inodes {
		result[inode] = struct{}{}
	}
	return result
}

func readUnixListeners(path string) ([]unixListener, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	data, err := io.ReadAll(io.LimitReader(file, maximumProcUnixBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximumProcUnixBytes {
		return nil, fmt.Errorf("unix socket inventory exceeds limit")
	}
	return parseProcUnixListeners(data)
}

func parseProcUnixListeners(data []byte) ([]unixListener, error) {
	if len(data) == 0 || len(data) > maximumProcUnixBytes || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 || bytes.IndexByte(data, '\r') >= 0 {
		return nil, fmt.Errorf("unix socket inventory framing is invalid")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 4096)
	wantHeader := []string{"Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path"}
	if !scanner.Scan() || !slices.Equal(strings.Fields(scanner.Text()), wantHeader) {
		return nil, fmt.Errorf("unix socket inventory header is invalid")
	}
	result := []unixListener{}
	seenInodes := map[uint64]struct{}{}
	for scanner.Scan() {
		columns, path, err := splitProcUnixRow(scanner.Text())
		if err != nil {
			return nil, err
		}
		if len(columns[0]) != 17 || columns[0][16] != ':' {
			return nil, fmt.Errorf("unix socket inventory number is malformed")
		}
		if _, err := parseFixedHex(columns[0][:16], 16); err != nil {
			return nil, fmt.Errorf("unix socket inventory number is malformed")
		}
		if _, err := parseFixedHex(columns[1], 8); err != nil {
			return nil, fmt.Errorf("unix socket reference count is malformed")
		}
		if _, err := parseFixedHex(columns[2], 8); err != nil {
			return nil, fmt.Errorf("unix socket protocol is malformed")
		}
		flags, err := parseFixedHex(columns[3], 8)
		if err != nil {
			return nil, fmt.Errorf("unix socket flags are malformed")
		}
		typeValue, err := parseFixedHex(columns[4], 4)
		if err != nil {
			return nil, fmt.Errorf("unix socket type is malformed")
		}
		state, err := parseFixedHex(columns[5], 2)
		if err != nil {
			return nil, fmt.Errorf("unix socket state is malformed")
		}
		inode, err := strconv.ParseUint(columns[6], 10, 64)
		if err != nil || inode == 0 {
			return nil, fmt.Errorf("unix socket inode is malformed")
		}
		if _, duplicate := seenInodes[inode]; duplicate {
			return nil, fmt.Errorf("unix socket inventory contains duplicate inode")
		}
		seenInodes[inode] = struct{}{}
		if flags&0x00010000 != 0 && state == 0x01 {
			result = append(result, unixListener{Path: path, Inode: inode, Type: typeValue})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unix socket inventory row exceeds limit: %w", err)
	}
	return result, nil
}

func splitProcUnixRow(line string) ([7]string, string, error) {
	columns := [7]string{}
	position := 0
	for index := range columns {
		for position < len(line) && (line[position] == ' ' || line[position] == '\t') {
			position++
		}
		start := position
		for position < len(line) && line[position] != ' ' && line[position] != '\t' {
			position++
		}
		if start == position {
			return columns, "", fmt.Errorf("unix socket inventory row is malformed")
		}
		columns[index] = line[start:position]
	}
	for position < len(line) && (line[position] == ' ' || line[position] == '\t') {
		position++
	}
	return columns, line[position:], nil
}

func parseFixedHex(value string, width int) (uint64, error) {
	if len(value) != width {
		return 0, fmt.Errorf("hexadecimal width is invalid")
	}
	return strconv.ParseUint(value, 16, 64)
}

func verifyUnixListeners(listeners []unixListener, expected []unixEndpointExpectation, owners map[string][]uint64, exactOwners []string) ([]unixListenerEvidence, error) {
	byPath := map[string][]unixListener{}
	for _, listener := range listeners {
		byPath[listener.Path] = append(byPath[listener.Path], listener)
	}
	ownerSets := make(map[string]map[uint64]struct{}, len(owners))
	for owner, inodes := range owners {
		ownerSets[owner] = socketInodeSet(inodes)
	}
	allowed := map[string]map[uint64]struct{}{}
	evidence := make([]unixListenerEvidence, 0, len(expected))
	seenRoles := map[string]struct{}{}
	seenPaths := map[string]struct{}{}
	for _, expectation := range expected {
		if expectation.Role == "" || expectation.Path == "" || len(expectation.Owners) == 0 {
			return nil, fmt.Errorf("unix listener expectation is incomplete")
		}
		if _, duplicate := seenRoles[expectation.Role]; duplicate {
			return nil, fmt.Errorf("unix listener expectation role is duplicated")
		}
		if _, duplicate := seenPaths[expectation.Path]; duplicate {
			return nil, fmt.Errorf("unix listener expectation path is duplicated")
		}
		seenRoles[expectation.Role] = struct{}{}
		seenPaths[expectation.Path] = struct{}{}
		matches := byPath[expectation.Path]
		if len(matches) != 1 {
			return nil, fmt.Errorf("exact listening Unix endpoint %q not observed", expectation.Role)
		}
		if matches[0].Type != unix.SOCK_STREAM {
			return nil, fmt.Errorf("unix listener %q is not SOCK_STREAM", expectation.Role)
		}
		ownerNames := append([]string(nil), expectation.Owners...)
		slices.Sort(ownerNames)
		ownerNames = slices.Compact(ownerNames)
		if len(ownerNames) != len(expectation.Owners) {
			return nil, fmt.Errorf("unix listener owner expectation is duplicated")
		}
		for _, owner := range ownerNames {
			set, present := ownerSets[owner]
			if !present {
				return nil, fmt.Errorf("unix listener owner inventory %q is missing", owner)
			}
			if _, present := set[matches[0].Inode]; !present {
				return nil, fmt.Errorf("unix listener %q is not owned by %s", expectation.Role, owner)
			}
			if allowed[owner] == nil {
				allowed[owner] = map[uint64]struct{}{}
			}
			allowed[owner][matches[0].Inode] = struct{}{}
		}
		evidence = append(evidence, unixListenerEvidence{Role: expectation.Role, Path: expectation.Path, Inode: matches[0].Inode, Type: matches[0].Type, Owners: ownerNames})
	}
	for _, owner := range exactOwners {
		set, present := ownerSets[owner]
		if !present {
			return nil, fmt.Errorf("exact Unix listener owner inventory %q is missing", owner)
		}
		for _, listener := range listeners {
			if _, owned := set[listener.Inode]; !owned {
				continue
			}
			if _, expected := allowed[owner][listener.Inode]; !expected {
				return nil, fmt.Errorf("%s owns an undeclared Unix listener", owner)
			}
		}
	}
	slices.SortFunc(evidence, func(left, right unixListenerEvidence) int {
		if order := strings.Compare(left.Role, right.Role); order != 0 {
			return order
		}
		if order := strings.Compare(left.Path, right.Path); order != 0 {
			return order
		}
		return int64Compare(left.Inode, right.Inode)
	})
	return evidence, nil
}

func int64Compare(left, right uint64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func runtimeObservationDigest(cgroup, cgroupDigest, relayCgroupDigest string, socketPresent bool, inetInodes []uint64, unixEvidence []unixListenerEvidence) string {
	var canonical strings.Builder
	writeDigestField(&canonical, "lanpanel.process.runtime.v2")
	writeDigestField(&canonical, cgroup)
	writeDigestField(&canonical, cgroupDigest)
	writeDigestField(&canonical, relayCgroupDigest)
	writeDigestField(&canonical, strconv.FormatBool(socketPresent))
	for _, inode := range inetInodes {
		writeDigestField(&canonical, "inet")
		writeDigestField(&canonical, strconv.FormatUint(inode, 10))
	}
	for _, evidence := range unixEvidence {
		writeDigestField(&canonical, "unix")
		writeDigestField(&canonical, evidence.Role)
		writeDigestField(&canonical, evidence.Path)
		writeDigestField(&canonical, strconv.FormatUint(evidence.Inode, 10))
		writeDigestField(&canonical, strconv.FormatUint(evidence.Type, 10))
		for _, owner := range evidence.Owners {
			writeDigestField(&canonical, owner)
		}
	}
	sum := sha256.Sum256([]byte(canonical.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeDigestField(destination *strings.Builder, value string) {
	destination.WriteString(strconv.Itoa(len(value)))
	destination.WriteByte(':')
	destination.WriteString(value)
	destination.WriteByte(0)
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
