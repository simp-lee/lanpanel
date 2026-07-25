package hosthealth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"lanpanel/internal/domain"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSummarizeMatchesHostHealthSchema(t *testing.T) {
	t.Parallel()

	summary := Summarize(Inputs{
		GeneratedAt: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		OSRelease:   []byte(`PRETTY_NAME="Debian GNU/Linux"`),
		CPUInfo:     []byte("model name\t: Example CPU\n"),
		LoadAverage: []byte("0.10 0.20 0.30 1/100 123\n"),
		MemInfo:     []byte("MemTotal:       2048000 kB\nMemAvailable:   1024000 kB\n"),
		MountInfo: []byte(strings.Join([]string{
			"1 1 0:1 / / rw - ext4 /dev/root rw",
			"2 1 0:2 / /proc rw - proc proc rw",
			"3 1 0:3 / /sys rw - sysfs sysfs rw",
			"4 1 0:4 / /run rw - tmpfs tmpfs rw",
			"",
		}, "\n")),
		DiskStats: []DiskFact{{Mountpoint: "/", TotalBytes: 1000, UsedBytes: 250}},
		NetworkInterfaces: []NetworkInterfaceFact{
			{Interface: "lo", Addresses: []string{"127.0.0.1/8"}},
		},
		PortListenOutput: []byte(strings.Join([]string{
			"Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port",
			"tcp   LISTEN 0      4096   127.0.0.1:80      0.0.0.0:*",
			"udp   UNCONN 0      0      [::]:3478         [::]:*",
			"",
		}, "\n")),
		CommandStatuses: map[string]error{
			"ports":        nil,
			"apt":          nil,
			"dpkg":         nil,
			"systemd":      nil,
			"nginx-config": errors.New("nginx failed"),
		},
		DNSDiagnostics:  []domain.DiagnosticRef{{ID: "dns:api.example.com", Status: domain.DiagnosticStatusPass}},
		Certificates:    []CertificateFact{{Domain: "example.com", NotAfter: "2026-08-01T00:00:00Z", Diagnostic: domain.DiagnosticRef{Status: domain.DiagnosticStatusWarn}}},
		PublicPrechecks: []domain.DiagnosticRef{{ID: "public-port:443", Status: domain.DiagnosticStatusManual}},
	})

	if summary.SchemaVersion != domain.HostHealthSchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", summary.SchemaVersion, domain.HostHealthSchemaVersion)
	}
	if summary.GeneratedAt != "2026-06-20T12:00:00Z" {
		t.Fatalf("GeneratedAt = %q", summary.GeneratedAt)
	}
	if summary.Source != SummarySourceLocalRuntimeProbe {
		t.Fatalf("Source = %q", summary.Source)
	}
	if !strings.Contains(summary.Host.OS, "Debian GNU/Linux") {
		t.Fatalf("OS = %q", summary.Host.OS)
	}
	if summary.Host.CPU.Model != "Example CPU" || summary.Host.CPU.Load != "0.10 0.20 0.30" {
		t.Fatalf("CPU = %#v", summary.Host.CPU)
	}
	if summary.Host.Memory.TotalBytes != 2048000*1024 || summary.Host.Memory.AvailableBytes != 1024000*1024 {
		t.Fatalf("Memory = %#v", summary.Host.Memory)
	}
	if len(summary.Host.Disks) != 1 || summary.Host.Disks[0].Mountpoint != "/" || summary.Host.Disks[0].FSType != "ext4" || summary.Host.Disks[0].UsagePercent != 25 {
		t.Fatalf("Disks = %#v", summary.Host.Disks)
	}
	if len(summary.Host.NetworkAddresses) != 1 || summary.Host.NetworkAddresses[0].Interface != "lo" {
		t.Fatalf("NetworkAddresses = %#v", summary.Host.NetworkAddresses)
	}
	if statusOf(summary.Checks.NginxConfigTest, "nginx-config") != domain.DiagnosticStatusFail {
		t.Fatalf("nginx-config status = %q", statusOf(summary.Checks.NginxConfigTest, "nginx-config"))
	}
	if len(summary.Checks.PortListeners) != 2 || summary.Checks.PortListeners[0].Port != 80 || summary.Checks.PortListeners[1].Port != 3478 {
		t.Fatalf("PortListeners = %#v, want parsed 80 and 3478 listeners", summary.Checks.PortListeners)
	}
	nginxRef := refByID(summary.Checks.NginxConfigTest, "nginx-config")
	if nginxRef.Scope != domain.DiagnosticScopeInstance || nginxRef.EvidenceSource != domain.DiagnosticEvidenceRuntimeProbe || nginxRef.ResponsibleParty != domain.DiagnosticResponsibleLocalAdmin || nginxRef.Severity != domain.DiagnosticSeverityCritical || !nginxRef.BlocksActivation {
		t.Fatalf("nginx-config metadata = %#v", nginxRef)
	}
	dnsRef := refByID(summary.Checks.DNS, "dns:api.example.com")
	if dnsRef.Scope != domain.DiagnosticScopeInstance || dnsRef.EvidenceSource != domain.DiagnosticEvidenceRuntimeProbe || dnsRef.ResponsibleParty != domain.DiagnosticResponsibleLocalAdmin || dnsRef.Severity != domain.DiagnosticSeverityInfo || dnsRef.BlocksActivation {
		t.Fatalf("dns metadata = %#v", dnsRef)
	}
	if statusOf(summary.Checks.PublicPreflight, "public-port:443") != domain.DiagnosticStatusManual {
		t.Fatalf("public-port:443 status = %q", statusOf(summary.Checks.PublicPreflight, "public-port:443"))
	}
	publicRef := refByID(summary.Checks.PublicPreflight, "public-port:443")
	if publicRef.Scope != domain.DiagnosticScopeInstance || publicRef.EvidenceSource != domain.DiagnosticEvidenceManual || publicRef.ResponsibleParty != domain.DiagnosticResponsibleLocalAdmin || publicRef.Severity != domain.DiagnosticSeverityMedium || !publicRef.BlocksActivation || publicRef.Redaction != domain.RedactionNone || publicRef.RedactionStatus != domain.RedactionStatusNoSensitiveData {
		t.Fatalf("public precheck metadata = %#v", publicRef)
	}
	for _, id := range []string{"public-port:80", "public-port:443", "public-port:3478"} {
		if refByID(summary.Checks.PublicPreflight, id).ID == "" {
			t.Fatalf("public prechecks missing %s: %#v", id, summary.Checks.PublicPreflight)
		}
	}
	certRef := refByID(summary.Checks.Certificates, "certificate:example.com")
	if certRef.Scope != domain.DiagnosticScopeCertificate || certRef.EvidenceSource != domain.DiagnosticEvidenceRuntimeProbe || certRef.ResponsibleParty != domain.DiagnosticResponsibleLocalAdmin || certRef.Severity != domain.DiagnosticSeverityMedium || certRef.BlocksActivation || certRef.Redaction != domain.RedactionNone || certRef.RedactionStatus != domain.RedactionStatusNoSensitiveData {
		t.Fatalf("certificate metadata = %#v", certRef)
	}
	if len(summary.Certificates) != 1 || summary.Certificates[0].Domain != "example.com" || summary.Certificates[0].NotAfter != "2026-08-01T00:00:00Z" || summary.Certificates[0].DiagnosticID != "certificate:example.com" {
		t.Fatalf("Certificates = %#v, want expiry fact", summary.Certificates)
	}
	wantAllowed := []domain.HostHealthAction{
		domain.HostHealthActionOpenDiagnostics,
		domain.HostHealthActionOpenCertificatesNginx,
		domain.HostHealthActionOpenServiceStatus,
		domain.HostHealthActionOpenVerifyJob,
		domain.HostHealthActionOpenDeployJob,
	}
	if !reflect.DeepEqual(summary.AllowedActions, wantAllowed) {
		t.Fatalf("AllowedActions = %#v", summary.AllowedActions)
	}
	wantForbidden := []domain.HostHealthAction{
		domain.HostHealthActionEditSystemSettings,
		domain.HostHealthActionPackageManagerOperation,
		domain.HostHealthActionArbitrarySystemdManagement,
		domain.HostHealthActionArbitraryNginxEdit,
		domain.HostHealthActionDiskCleanup,
		domain.HostHealthActionNetworkConfigurationChange,
	}
	if !reflect.DeepEqual(summary.ForbiddenActions, wantForbidden) {
		t.Fatalf("ForbiddenActions = %#v", summary.ForbiddenActions)
	}
	if summary.RedactionStatus != domain.RedactionStatusNoSensitiveData {
		t.Fatalf("RedactionStatus = %q", summary.RedactionStatus)
	}
}

func TestSummarizePreservesSuppliedDiagnosticMetadata(t *testing.T) {
	t.Parallel()

	summary := Summarize(Inputs{
		Certificates: []CertificateFact{{
			Domain: "example.com",
			Diagnostic: domain.DiagnosticRef{
				Status:           domain.DiagnosticStatusFail,
				Scope:            domain.DiagnosticScopeResource,
				Severity:         domain.DiagnosticSeverityCritical,
				EvidenceSource:   domain.DiagnosticEvidenceCheckpoint,
				ResponsibleParty: domain.DiagnosticResponsibleDNSProvider,
				BlocksActivation: false,
				Redaction:        domain.RedactionFingerprint,
			},
		}},
		PublicPrechecks: []domain.DiagnosticRef{{
			ID:               "public-port:443",
			Status:           domain.DiagnosticStatusUnknown,
			Scope:            domain.DiagnosticScopeResource,
			Severity:         domain.DiagnosticSeverityCritical,
			EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
			ResponsibleParty: domain.DiagnosticResponsibleDNSProvider,
			BlocksActivation: false,
			Redaction:        domain.RedactionFingerprint,
		}},
	})

	certRef := refByID(summary.Checks.Certificates, "certificate:example.com")
	if certRef.Scope != domain.DiagnosticScopeResource || certRef.EvidenceSource != domain.DiagnosticEvidenceCheckpoint || certRef.ResponsibleParty != domain.DiagnosticResponsibleDNSProvider || certRef.Severity != domain.DiagnosticSeverityCritical || certRef.BlocksActivation || certRef.Redaction != domain.RedactionFingerprint {
		t.Fatalf("certificate metadata = %#v, want supplied metadata preserved", certRef)
	}
	publicRef := refByID(summary.Checks.PublicPreflight, "public-port:443")
	if publicRef.Scope != domain.DiagnosticScopeResource || publicRef.EvidenceSource != domain.DiagnosticEvidenceRuntimeProbe || publicRef.ResponsibleParty != domain.DiagnosticResponsibleDNSProvider || publicRef.Severity != domain.DiagnosticSeverityCritical || !publicRef.BlocksActivation || publicRef.Redaction != domain.RedactionFingerprint {
		t.Fatalf("public precheck metadata = %#v, want supplied metadata preserved", publicRef)
	}
	defaultSummary := Summarize(Inputs{})
	defaultPublicRef := refByID(defaultSummary.Checks.PublicPreflight, "public-port:443")
	if !defaultPublicRef.BlocksActivation || defaultPublicRef.Redaction != domain.RedactionNone {
		t.Fatalf("default public precheck metadata = %#v, want generated blocking metadata", defaultPublicRef)
	}
}

func TestSummarizeDefaultsDNSUnknownWithoutExplicitTarget(t *testing.T) {
	t.Parallel()

	summary := Summarize(Inputs{})
	dnsRef := refByID(summary.Checks.DNS, "dns")
	if dnsRef.Status != domain.DiagnosticStatusUnknown || !dnsRef.BlocksActivation || dnsRef.EvidenceSource != domain.DiagnosticEvidenceRuntimeProbe {
		t.Fatalf("default DNS ref = %#v, want blocking unknown without explicit DNS target", dnsRef)
	}
}

func TestSummarizeFailsMissingExpectedPortDespiteSuccessfulSS(t *testing.T) {
	t.Parallel()

	summary := Summarize(Inputs{
		PortListenOutput: []byte(strings.Join([]string{
			"Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port",
			"tcp   LISTEN 0      4096   0.0.0.0:80      0.0.0.0:*",
			"",
		}, "\n")),
		CommandStatuses: map[string]error{"ports": nil},
		ExpectedPorts: []ExpectedPort{
			{ID: "port:tcp:80", Protocol: "tcp", Port: 80},
			{ID: "port:tcp:443", Protocol: "tcp", Port: 443},
		},
	})

	if statusOf(summary.Checks.Ports, "port:tcp:80") != domain.DiagnosticStatusPass {
		t.Fatalf("port:tcp:80 status = %q, want pass", statusOf(summary.Checks.Ports, "port:tcp:80"))
	}
	if statusOf(summary.Checks.Ports, "port:tcp:443") != domain.DiagnosticStatusFail {
		t.Fatalf("port:tcp:443 status = %q, want fail", statusOf(summary.Checks.Ports, "port:tcp:443"))
	}
}

func TestSummarizeUsesExplicitCommandDiagnosticStatus(t *testing.T) {
	t.Parallel()

	summary := Summarize(Inputs{
		CommandStatuses: map[string]error{
			"ports":   contextDeadlineExceeded(),
			"systemd": nil,
		},
		CommandDiagnostics: map[string]domain.DiagnosticStatus{
			"ports":   domain.DiagnosticStatusUnknown,
			"systemd": domain.DiagnosticStatusWarn,
		},
	})

	if statusOf(summary.Checks.Ports, "ports") != domain.DiagnosticStatusUnknown {
		t.Fatalf("ports status = %q, want unknown", statusOf(summary.Checks.Ports, "ports"))
	}
	if statusOf(summary.Checks.AptDpkgSystemd, "systemd") != domain.DiagnosticStatusWarn {
		t.Fatalf("systemd status = %q, want warn", statusOf(summary.Checks.AptDpkgSystemd, "systemd"))
	}
}

func TestSystemdManagerStatusMapsManagerStates(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		state string
		err   error
		want  domain.DiagnosticStatus
	}{
		{state: "running\n", want: domain.DiagnosticStatusPass},
		{state: "degraded\n", err: errors.New("exit status 1"), want: domain.DiagnosticStatusWarn},
		{state: "starting\n", err: errors.New("exit status 1"), want: domain.DiagnosticStatusWarn},
		{state: "offline\n", err: errors.New("exit status 1"), want: domain.DiagnosticStatusFail},
		{state: "", err: errors.New("System has not been booted with systemd as init system"), want: domain.DiagnosticStatusFail},
	} {
		tt := tt
		t.Run(strings.TrimSpace(tt.state), func(t *testing.T) {
			t.Parallel()

			_, got := systemdManagerStatus([]byte(tt.state), tt.err)
			if got != tt.want {
				t.Fatalf("systemdManagerStatus(%q) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func TestReadOnlyProbeTimesOutAsUnknown(t *testing.T) {
	t.Parallel()

	_, err, status := runReadOnlyProbeOutput(nil, time.Nanosecond, "sh", "-c", "sleep 1")
	if err == nil {
		t.Fatal("runReadOnlyProbeOutput() error = nil, want timeout")
	}
	if status != domain.DiagnosticStatusUnknown {
		t.Fatalf("status = %q, want unknown", status)
	}
}

func TestReadLocalInputsWithOptionsPopulatesDNSAndCertificateFacts(t *testing.T) {
	t.Parallel()

	certPath := writeTestCertificate(t, "localhost", time.Now().Add(60*24*time.Hour))
	inputs := ReadLocalInputsWithOptions(LocalReadOptions{
		DNSTargets: []string{"localhost"},
		CertificateTargets: []CertificateTarget{{
			Domain: "localhost",
			Path:   certPath,
		}},
	})

	if len(inputs.DNSDiagnostics) != 1 || inputs.DNSDiagnostics[0].ID != "dns:localhost" || inputs.DNSDiagnostics[0].Status != domain.DiagnosticStatusPass {
		t.Fatalf("DNSDiagnostics = %#v, want localhost pass", inputs.DNSDiagnostics)
	}
	if len(inputs.Certificates) != 1 || inputs.Certificates[0].Domain != "localhost" || inputs.Certificates[0].NotAfter == "" || inputs.Certificates[0].Diagnostic.Status != domain.DiagnosticStatusPass {
		t.Fatalf("Certificates = %#v, want parsed pass certificate", inputs.Certificates)
	}
}

func contextDeadlineExceeded() error {
	return errors.New("context deadline exceeded")
}

func TestSummarizeJSONShapeUsesRequiredKeys(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(Summarize(Inputs{GeneratedAt: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	text := string(data)
	for _, want := range []string{
		`"schema_version":"lanpanel.host_health.v1"`,
		`"generated_at":"2026-06-20T12:00:00Z"`,
		`"source":"local_runtime_probe"`,
		`"host":`,
		`"checks":`,
		`"port_listeners":`,
		`"allowed_actions":`,
		`"forbidden_actions":`,
		`"open_diagnostics"`,
		`"open_certificates_nginx"`,
		`"open_service_status"`,
		`"open_verify_job"`,
		`"open_deploy_job"`,
		`"edit_system_settings"`,
		`"package_manager_operation"`,
		`"arbitrary_systemd_management"`,
		`"arbitrary_nginx_edit"`,
		`"disk_cleanup"`,
		`"network_configuration_change"`,
		`"redaction_status":"no_sensitive_data"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON = %s, want %s", text, want)
		}
	}
	for _, forbidden := range []string{`"facts":`, `"diagnostics":`, `"actions":`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("JSON = %s, did not expect old key %s", text, forbidden)
		}
	}
}

func writeTestCertificate(t *testing.T, domainName string, notAfter time.Time) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domainName},
		DNSNames:     []string{domainName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "fullchain.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	return path
}

func statusOf(refs []domain.DiagnosticRef, id string) domain.DiagnosticStatus {
	return refByID(refs, id).Status
}

func refByID(refs []domain.DiagnosticRef, id string) domain.DiagnosticRef {
	for _, ref := range refs {
		if ref.ID == id {
			return ref
		}
	}
	return domain.DiagnosticRef{}
}
