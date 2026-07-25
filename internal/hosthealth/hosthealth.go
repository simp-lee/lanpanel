// Package hosthealth derives a read-only local host health summary.
package hosthealth

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	SummarySourceLocalRuntimeProbe = "local_runtime_probe"
	DefaultProbeTimeout            = 3 * time.Second
)

type Inputs struct {
	GeneratedAt        time.Time
	OSRelease          []byte
	CPUInfo            []byte
	LoadAverage        []byte
	MemInfo            []byte
	MountInfo          []byte
	DiskStats          []DiskFact
	NetworkInterfaces  []NetworkInterfaceFact
	PortListenOutput   []byte
	CommandStatuses    map[string]error
	CommandDiagnostics map[string]domain.DiagnosticStatus
	DNSDiagnostics     []domain.DiagnosticRef
	Certificates       []CertificateFact
	PublicPrechecks    []domain.DiagnosticRef
	ExpectedPorts      []ExpectedPort
}

type LocalReadOptions struct {
	Context            context.Context
	ProbeTimeout       time.Duration
	DNSTargets         []string
	CertificateTargets []CertificateTarget
	ExpectedPorts      []ExpectedPort
}

type ExpectedPort struct {
	ID       string
	Protocol string
	Port     int
}

type CertificateTarget struct {
	Domain string
	Path   string
}

type DiskFact struct {
	Mountpoint string
	FSType     string
	TotalBytes int64
	UsedBytes  int64
}

type NetworkInterfaceFact struct {
	Interface string
	Addresses []string
}

type CertificateFact struct {
	Domain     string
	NotAfter   string
	Diagnostic domain.DiagnosticRef
}

func Summarize(inputs Inputs) domain.HostHealthSummary {
	generatedAt := inputs.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	return domain.HostHealthSummary{
		SchemaVersion: domain.HostHealthSchemaVersion,
		GeneratedAt:   generatedAt.UTC().Format(time.RFC3339),
		Source:        SummarySourceLocalRuntimeProbe,
		Host: domain.HostHealthHost{
			OS:               osSummary(inputs.OSRelease),
			CPU:              cpuSummary(inputs.CPUInfo, inputs.LoadAverage),
			Memory:           memorySummary(inputs.MemInfo),
			Disks:            diskFacts(inputs.MountInfo, inputs.DiskStats),
			NetworkAddresses: networkAddresses(inputs.NetworkInterfaces),
		},
		Checks: domain.HostHealthChecks{
			DNS:             dnsRefs(inputs.DNSDiagnostics),
			Ports:           portCheckRefs(inputs.PortListenOutput, inputs.ExpectedPorts, inputs.CommandStatuses, inputs.CommandDiagnostics),
			PortListeners:   portListeners(inputs.PortListenOutput),
			AptDpkgSystemd:  []domain.DiagnosticRef{commandRef("apt", "apt", inputs.CommandStatuses, inputs.CommandDiagnostics), commandRef("dpkg", "dpkg", inputs.CommandStatuses, inputs.CommandDiagnostics), commandRef("systemd", "systemd", inputs.CommandStatuses, inputs.CommandDiagnostics)},
			NginxConfigTest: []domain.DiagnosticRef{commandRef("nginx-config", "nginx-config", inputs.CommandStatuses, inputs.CommandDiagnostics)},
			Certificates:    certificateRefs(inputs.Certificates),
			PublicPreflight: publicPrecheckRefs(inputs.PublicPrechecks),
		},
		Certificates: certificateFacts(inputs.Certificates),
		AllowedActions: []domain.HostHealthAction{
			domain.HostHealthActionOpenDiagnostics,
			domain.HostHealthActionOpenCertificatesNginx,
			domain.HostHealthActionOpenServiceStatus,
			domain.HostHealthActionOpenVerifyJob,
			domain.HostHealthActionOpenDeployJob,
		},
		ForbiddenActions: []domain.HostHealthAction{
			domain.HostHealthActionEditSystemSettings,
			domain.HostHealthActionPackageManagerOperation,
			domain.HostHealthActionArbitrarySystemdManagement,
			domain.HostHealthActionArbitraryNginxEdit,
			domain.HostHealthActionDiskCleanup,
			domain.HostHealthActionNetworkConfigurationChange,
		},
		RedactionStatus: domain.RedactionStatusNoSensitiveData,
	}
}

func ReadLocalInputs() Inputs {
	return ReadLocalInputsWithOptions(LocalReadOptions{})
}

func ReadLocalMetricInputs() Inputs {
	return Inputs{
		GeneratedAt: time.Now().UTC(),
		OSRelease:   readOptionalFile("/etc/os-release"),
		CPUInfo:     readOptionalFile("/proc/cpuinfo"),
		LoadAverage: readOptionalFile("/proc/loadavg"),
		MemInfo:     readOptionalFile("/proc/meminfo"),
		MountInfo:   readOptionalFile("/proc/self/mountinfo"),
		DiskStats:   rootDiskStats(),
	}
}

func ReadLocalInputsWithOptions(options LocalReadOptions) Inputs {
	if len(options.ExpectedPorts) == 0 {
		options.ExpectedPorts = defaultExpectedPorts()
	}
	baseContext := options.Context
	if baseContext == nil {
		baseContext = context.Background()
	}
	timeout := options.ProbeTimeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	portOutput, portErr, portStatus := runReadOnlyProbeOutput(baseContext, timeout, "ss", "-ltnu")
	aptErr, aptStatus := runReadOnlyProbe(baseContext, timeout, "apt-get", "--version")
	dpkgErr, dpkgStatus := runReadOnlyProbe(baseContext, timeout, "dpkg", "--version")
	systemdErr, systemdStatus := runSystemdManagerProbe(baseContext, timeout)
	nginxErr, nginxStatus := runReadOnlyProbe(baseContext, timeout, "nginx", "-t")
	return Inputs{
		GeneratedAt:       time.Now().UTC(),
		OSRelease:         readOptionalFile("/etc/os-release"),
		CPUInfo:           readOptionalFile("/proc/cpuinfo"),
		LoadAverage:       readOptionalFile("/proc/loadavg"),
		MemInfo:           readOptionalFile("/proc/meminfo"),
		MountInfo:         readOptionalFile("/proc/self/mountinfo"),
		DiskStats:         rootDiskStats(),
		NetworkInterfaces: localNetworkInterfaces(),
		PortListenOutput:  portOutput,
		DNSDiagnostics:    dnsDiagnostics(baseContext, timeout, options.DNSTargets),
		Certificates:      certificateDiagnostics(options.CertificateTargets),
		ExpectedPorts:     append([]ExpectedPort(nil), options.ExpectedPorts...),
		CommandStatuses: map[string]error{
			"ports":        portErr,
			"apt":          aptErr,
			"dpkg":         dpkgErr,
			"systemd":      systemdErr,
			"nginx-config": nginxErr,
		},
		CommandDiagnostics: map[string]domain.DiagnosticStatus{
			"ports":        portStatus,
			"apt":          aptStatus,
			"dpkg":         dpkgStatus,
			"systemd":      systemdStatus,
			"nginx-config": nginxStatus,
		},
		PublicPrechecks: []domain.DiagnosticRef{
			{ID: "public-port:80", Status: domain.DiagnosticStatusManual},
			{ID: "public-port:443", Status: domain.DiagnosticStatusManual},
			{ID: "public-port:3478", Status: domain.DiagnosticStatusManual},
		},
	}
}

func defaultExpectedPorts() []ExpectedPort {
	return []ExpectedPort{
		{ID: "port:tcp:80", Protocol: "tcp", Port: 80},
		{ID: "port:tcp:443", Protocol: "tcp", Port: 443},
		{ID: "port:udp:3478", Protocol: "udp", Port: 3478},
	}
}

func readOptionalFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func runReadOnlyProbe(ctx context.Context, timeout time.Duration, name string, args ...string) (error, domain.DiagnosticStatus) {
	_, err, status := runReadOnlyProbeOutput(ctx, timeout, name, args...)
	return err, status
}

func runReadOnlyProbeOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error, domain.DiagnosticStatus) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, name, args...)
	output, err := cmd.CombinedOutput()
	if probeCtx.Err() != nil {
		return output, probeCtx.Err(), domain.DiagnosticStatusUnknown
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		return output, errors.New(detail), domain.DiagnosticStatusFail
	}
	return output, nil, domain.DiagnosticStatusPass
}

func runSystemdManagerProbe(ctx context.Context, timeout time.Duration) (error, domain.DiagnosticStatus) {
	output, err, status := runReadOnlyProbeOutput(ctx, timeout, "systemctl", "is-system-running")
	if status == domain.DiagnosticStatusUnknown {
		return err, status
	}
	return systemdManagerStatus(output, err)
}

func systemdManagerStatus(output []byte, err error) (error, domain.DiagnosticStatus) {
	state := strings.ToLower(strings.TrimSpace(string(output)))
	if fields := strings.Fields(state); len(fields) > 0 {
		state = fields[0]
	}
	if state == "" && err != nil {
		return err, domain.DiagnosticStatusFail
	}
	switch state {
	case "running":
		return nil, domain.DiagnosticStatusPass
	case "degraded", "initializing", "starting", "maintenance", "stopping":
		return nil, domain.DiagnosticStatusWarn
	case "offline", "unknown":
		if err != nil {
			return err, domain.DiagnosticStatusFail
		}
		return fmt.Errorf("systemd manager state is %s", state), domain.DiagnosticStatusFail
	default:
		if err != nil {
			return err, domain.DiagnosticStatusFail
		}
		return fmt.Errorf("systemd manager returned unsupported state %q", state), domain.DiagnosticStatusUnknown
	}
}

func dnsRefs(refs []domain.DiagnosticRef) []domain.DiagnosticRef {
	if len(refs) == 0 {
		return []domain.DiagnosticRef{
			normalizeHostRef(domain.DiagnosticRef{ID: "dns", Status: domain.DiagnosticStatusUnknown}, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin, true),
		}
	}
	normalized := make([]domain.DiagnosticRef, 0, len(refs))
	for _, ref := range refs {
		normalized = append(normalized, normalizeHostRef(ref, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin, true))
	}
	return normalized
}

func commandRef(id string, statusKey string, statuses map[string]error, diagnostics map[string]domain.DiagnosticStatus) domain.DiagnosticRef {
	status := domain.DiagnosticStatusUnknown
	err, checked := statuses[statusKey]
	if explicit := diagnostics[statusKey]; explicit != "" {
		status = explicit
	} else if checked && err == nil {
		status = domain.DiagnosticStatusPass
	} else if checked && err != nil {
		status = domain.DiagnosticStatusFail
	}
	return normalizeHostRef(domain.DiagnosticRef{ID: id, Status: status}, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin, true)
}

func portCheckRefs(data []byte, expected []ExpectedPort, statuses map[string]error, diagnostics map[string]domain.DiagnosticStatus) []domain.DiagnosticRef {
	err, checked := statuses["ports"]
	if checked && err != nil {
		status := diagnostics["ports"]
		if status == "" {
			status = domain.DiagnosticStatusFail
		}
		return []domain.DiagnosticRef{normalizeHostRef(domain.DiagnosticRef{ID: "ports", Status: status}, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin, true)}
	}
	if len(expected) == 0 {
		return []domain.DiagnosticRef{commandRef("ports", "ports", statuses, diagnostics)}
	}
	listeners := portListeners(data)
	refs := make([]domain.DiagnosticRef, 0, len(expected))
	for _, want := range expected {
		id := strings.TrimSpace(want.ID)
		protocol := strings.ToLower(strings.TrimSpace(want.Protocol))
		if id == "" {
			id = fmt.Sprintf("port:%s:%d", protocol, want.Port)
		}
		status := domain.DiagnosticStatusFail
		if portListening(listeners, protocol, want.Port) {
			status = domain.DiagnosticStatusPass
		}
		if !checked {
			status = domain.DiagnosticStatusUnknown
		}
		refs = append(refs, normalizeHostRef(domain.DiagnosticRef{ID: id, Status: status}, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin, true))
	}
	return refs
}

func portListening(listeners []domain.HostHealthPortListener, protocol string, port int) bool {
	if protocol == "" || port <= 0 {
		return false
	}
	for _, listener := range listeners {
		if listener.Protocol == protocol && listener.Port == port {
			return true
		}
	}
	return false
}

func dnsDiagnostics(ctx context.Context, timeout time.Duration, targets []string) []domain.DiagnosticRef {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	seen := map[string]struct{}{}
	refs := []domain.DiagnosticRef{}
	resolver := net.DefaultResolver
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		status := domain.DiagnosticStatusPass
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := resolver.LookupHost(lookupCtx, target)
		contextErr := lookupCtx.Err()
		cancel()
		if contextErr != nil {
			status = domain.DiagnosticStatusUnknown
		} else if err != nil || len(addrs) == 0 {
			status = domain.DiagnosticStatusFail
		}
		refs = append(refs, domain.DiagnosticRef{ID: "dns:" + target, Status: status})
	}
	return refs
}

func certificateRefs(certs []CertificateFact) []domain.DiagnosticRef {
	refs := make([]domain.DiagnosticRef, 0, len(certs))
	for _, cert := range certs {
		status := cert.Diagnostic.Status
		if status == "" {
			status = domain.DiagnosticStatusUnknown
		}
		ref := cert.Diagnostic
		ref.ID = "certificate:" + cert.Domain
		ref.Status = status
		if ref.Scope == "" {
			ref.Scope = domain.DiagnosticScopeCertificate
		}
		refs = append(refs, normalizeHostRef(ref, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin, false))
	}
	if len(refs) == 0 {
		return []domain.DiagnosticRef{normalizeHostRef(domain.DiagnosticRef{ID: "certificates", Status: domain.DiagnosticStatusUnknown, Scope: domain.DiagnosticScopeCertificate}, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin, true)}
	}
	return refs
}

func certificateDiagnostics(targets []CertificateTarget) []CertificateFact {
	facts := []CertificateFact{}
	seen := map[string]struct{}{}
	now := time.Now().UTC()
	for _, target := range targets {
		domainName := strings.TrimSpace(target.Domain)
		path := strings.TrimSpace(target.Path)
		if domainName == "" || path == "" {
			continue
		}
		key := domainName + "\x00" + path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		fact := CertificateFact{Domain: domainName}
		cert, err := readLeafCertificate(path)
		if err != nil {
			fact.Diagnostic = domain.DiagnosticRef{Status: domain.DiagnosticStatusFail}
			facts = append(facts, fact)
			continue
		}
		fact.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		status := domain.DiagnosticStatusPass
		if !cert.NotAfter.After(now) {
			status = domain.DiagnosticStatusFail
		} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
			status = domain.DiagnosticStatusWarn
		}
		fact.Diagnostic = domain.DiagnosticRef{Status: status}
		facts = append(facts, fact)
	}
	return facts
}

func readLeafCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate %s does not contain a PEM CERTIFICATE block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}

func certificateFacts(certs []CertificateFact) []domain.HostHealthCertificate {
	facts := make([]domain.HostHealthCertificate, 0, len(certs))
	for _, cert := range certs {
		domainName := strings.TrimSpace(cert.Domain)
		notAfter := strings.TrimSpace(cert.NotAfter)
		if domainName == "" || notAfter == "" {
			continue
		}
		facts = append(facts, domain.HostHealthCertificate{
			Domain:       domainName,
			NotAfter:     notAfter,
			DiagnosticID: "certificate:" + domainName,
		})
	}
	return facts
}

func portListeners(data []byte) []domain.HostHealthPortListener {
	lines := strings.Split(string(data), "\n")
	listeners := []domain.HostHealthPortListener{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] == "Netid" {
			continue
		}
		protocol := strings.ToLower(fields[0])
		if protocol != "tcp" && protocol != "udp" {
			continue
		}
		address, port, ok := splitSocketAddress(fields[4])
		if !ok {
			continue
		}
		listeners = append(listeners, domain.HostHealthPortListener{
			Protocol:     protocol,
			LocalAddress: address,
			Port:         port,
		})
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].Protocol != listeners[j].Protocol {
			return listeners[i].Protocol < listeners[j].Protocol
		}
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		return listeners[i].LocalAddress < listeners[j].LocalAddress
	})
	return listeners
}

func splitSocketAddress(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}
	index := strings.LastIndex(value, ":")
	if index < 0 || index == len(value)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	address := strings.Trim(value[:index], "[]")
	if address == "" {
		address = "*"
	}
	return address, port, true
}

func publicPrecheckRefs(refs []domain.DiagnosticRef) []domain.DiagnosticRef {
	byID := map[string]domain.DiagnosticRef{}
	for _, ref := range refs {
		byID[ref.ID] = ref
	}
	required := []string{"public-port:80", "public-port:443", "public-port:3478"}
	normalized := make([]domain.DiagnosticRef, 0, len(required))
	for _, id := range required {
		ref, ok := byID[id]
		if !ok {
			ref = domain.DiagnosticRef{ID: id, Status: domain.DiagnosticStatusManual}
		}
		normalized = append(normalized, normalizeHostRef(ref, domain.DiagnosticEvidenceManual, domain.DiagnosticResponsibleLocalAdmin, true))
	}
	return normalized
}

func normalizeHostRef(ref domain.DiagnosticRef, evidence domain.DiagnosticEvidenceSource, responsible domain.DiagnosticResponsibleParty, deriveBlocks bool) domain.DiagnosticRef {
	if ref.Scope == "" {
		ref.Scope = domain.DiagnosticScopeInstance
	}
	if ref.Severity == "" {
		ref.Severity = severityForStatus(ref.Status)
	}
	if ref.EvidenceSource == "" {
		ref.EvidenceSource = evidence
	}
	if ref.ResponsibleParty == "" {
		ref.ResponsibleParty = responsible
	}
	if ref.Redaction == "" {
		ref.Redaction = domain.RedactionNone
	}
	if ref.RedactionStatus == "" {
		ref.RedactionStatus = domain.RedactionStatusNoSensitiveData
	}
	if deriveBlocks && !ref.BlocksActivation {
		ref.BlocksActivation = statusBlocksActivation(ref.Status)
	}
	return ref
}

func severityForStatus(status domain.DiagnosticStatus) domain.DiagnosticSeverity {
	switch status {
	case domain.DiagnosticStatusFail:
		return domain.DiagnosticSeverityCritical
	case domain.DiagnosticStatusWarn, domain.DiagnosticStatusManual, domain.DiagnosticStatusUnknown:
		return domain.DiagnosticSeverityMedium
	default:
		return domain.DiagnosticSeverityInfo
	}
}

func statusBlocksActivation(status domain.DiagnosticStatus) bool {
	switch status {
	case domain.DiagnosticStatusFail, domain.DiagnosticStatusManual, domain.DiagnosticStatusUnknown:
		return true
	default:
		return false
	}
}

func osSummary(data []byte) string {
	values := keyValues(data)
	parts := []string{}
	if pretty := values["PRETTY_NAME"]; pretty != "" {
		parts = append(parts, pretty)
	} else if id := values["ID"]; id != "" {
		parts = append(parts, id)
	} else {
		parts = append(parts, runtime.GOOS)
	}
	parts = append(parts, runtime.GOARCH)
	return strings.Join(parts, "/")
}

func cpuSummary(cpuInfo []byte, loadAverage []byte) domain.HostHealthCPU {
	return domain.HostHealthCPU{
		Model:        cpuModel(cpuInfo),
		LogicalCores: runtime.NumCPU(),
		Load:         loadSummary(loadAverage),
	}
}

func cpuModel(data []byte) string {
	values := keyValues(data)
	if model := values["model name"]; model != "" {
		return model
	}
	if hardware := values["Hardware"]; hardware != "" {
		return hardware
	}
	return "unknown"
}

func loadSummary(data []byte) string {
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return strings.Join(fields[:3], " ")
	}
	return "unknown"
}

func memorySummary(data []byte) domain.HostHealthMemory {
	values := keyValues(data)
	total := kibValue(values["MemTotal"])
	available := kibValue(values["MemAvailable"])
	usage := float64(0)
	if total > 0 {
		usage = float64(total-available) * 100 / float64(total)
	}
	return domain.HostHealthMemory{
		TotalBytes:     total,
		AvailableBytes: available,
		UsagePercent:   usage,
	}
}

func kibValue(value string) int64 {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	raw, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return raw * 1024
}

func diskFacts(mountInfo []byte, stats []DiskFact) []domain.HostHealthDisk {
	statByMount := map[string]DiskFact{}
	for _, stat := range stats {
		statByMount[stat.Mountpoint] = stat
	}
	disks := []domain.HostHealthDisk{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(mountInfo)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+1 >= len(fields) || len(fields) <= 4 {
			continue
		}
		mountpoint := fields[4]
		if seen[mountpoint] {
			continue
		}
		seen[mountpoint] = true
		fsType := fields[separator+1]
		if pseudoFilesystem(fsType) {
			continue
		}
		stat, ok := statByMount[mountpoint]
		if !ok || stat.TotalBytes <= 0 {
			continue
		}
		disks = append(disks, diskFact(mountpoint, fsType, stat.TotalBytes, stat.UsedBytes))
	}
	if len(disks) == 0 {
		for _, stat := range stats {
			if stat.TotalBytes <= 0 || pseudoFilesystem(stat.FSType) {
				continue
			}
			disks = append(disks, diskFact(stat.Mountpoint, stat.FSType, stat.TotalBytes, stat.UsedBytes))
		}
	}
	if len(disks) == 0 {
		return []domain.HostHealthDisk{{Mountpoint: "/", FSType: "unknown"}}
	}
	return disks
}

func pseudoFilesystem(fsType string) bool {
	switch fsType {
	case "proc",
		"sysfs",
		"tmpfs",
		"devtmpfs",
		"devpts",
		"cgroup",
		"cgroup2",
		"pstore",
		"securityfs",
		"debugfs",
		"tracefs",
		"fusectl",
		"mqueue",
		"hugetlbfs",
		"configfs",
		"binfmt_misc",
		"ramfs",
		"autofs",
		"nsfs":
		return true
	default:
		return false
	}
}

func diskFact(mountpoint string, fsType string, total int64, used int64) domain.HostHealthDisk {
	if mountpoint == "" {
		mountpoint = "/"
	}
	if fsType == "" {
		fsType = "unknown"
	}
	usage := float64(0)
	if total > 0 {
		usage = float64(used) * 100 / float64(total)
	}
	return domain.HostHealthDisk{
		Mountpoint:   mountpoint,
		FSType:       fsType,
		TotalBytes:   total,
		UsedBytes:    used,
		UsagePercent: usage,
	}
}

func rootDiskStats() []DiskFact {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return nil
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	return []DiskFact{{Mountpoint: "/", TotalBytes: total, UsedBytes: total - available}}
}

func localNetworkInterfaces() []NetworkInterfaceFact {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	facts := []NetworkInterfaceFact{}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		values := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			values = append(values, addr.String())
		}
		if len(values) == 0 {
			continue
		}
		facts = append(facts, NetworkInterfaceFact{Interface: iface.Name, Addresses: values})
	}
	return facts
}

func networkAddresses(facts []NetworkInterfaceFact) []domain.HostHealthNetworkAddresses {
	addresses := make([]domain.HostHealthNetworkAddresses, 0, len(facts))
	for _, fact := range facts {
		if strings.TrimSpace(fact.Interface) == "" || len(fact.Addresses) == 0 {
			continue
		}
		addresses = append(addresses, domain.HostHealthNetworkAddresses{
			Interface: fact.Interface,
			Addresses: append([]string(nil), fact.Addresses...),
		})
	}
	if len(addresses) == 0 {
		return []domain.HostHealthNetworkAddresses{{Interface: "unknown", Addresses: []string{"unknown"}}}
	}
	return addresses
}

func keyValues(data []byte) map[string]string {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			key, value, ok = strings.Cut(scanner.Text(), "=")
		}
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return values
}
