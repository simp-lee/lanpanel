package preflight

import (
	"lanpanel/internal/config"
	"strings"
	"testing"
)

func TestBuildReportDoesNotBlockOnAdvisoryManualChecklist(t *testing.T) {
	t.Parallel()

	report := BuildReport(config.ExampleConfig(), Inputs{
		Permissions: PermissionState{User: "deployer", SudoWorks: true},
		Platform:    PlatformInfo{ID: "debian", VersionID: "13", PrettyName: "Debian GNU/Linux 13"},
		Capabilities: HostCapabilityState{
			AptGetAvailable:         true,
			DpkgAvailable:           true,
			SystemctlAvailable:      true,
			SystemdRuntimeAvailable: true,
		},
		DNS: DNSProbe{Host: "hs.example.com", ResolvedIPs: []string{"8.8.8.8"}},
		Ports: []PortBinding{
			{Port: 80, Protocol: "tcp", InUse: false},
			{Port: 443, Protocol: "tcp", InUse: false},
			{Port: 8080, Protocol: "tcp", InUse: false},
			{Port: config.DefaultHeadscaleMetricsPort, Protocol: "tcp", InUse: false},
			{Port: 50443, Protocol: "tcp", InUse: false},
			{Port: 3478, Protocol: "udp", InUse: false},
		},
		Firewall: FirewallState{Inspected: true, Active: true, AllowedPorts: []string{"80/tcp", "443/tcp", "3478/udp"}},
		Services: []ServiceState{},
		PackageSource: PackageSourceState{
			Mode:                    config.PackageSourceModeDirect,
			Version:                 config.DefaultHeadscaleVersion,
			ExpectedSHA256:          strings.Repeat("a", 64),
			ReachabilityChecked:     true,
			Reachable:               true,
			IntegrityChecked:        true,
			ActualSHA256:            strings.Repeat("a", 64),
			LegoVersion:             "v5.2.2",
			LegoURL:                 "https://github.com/go-acme/lego/releases/download/v5.2.2/lego_v5.2.2_linux_amd64.tar.gz",
			LegoExpectedSHA256:      strings.Repeat("b", 64),
			LegoReachabilityChecked: true,
			LegoReachable:           true,
			LegoIntegrityChecked:    true,
			LegoActualSHA256:        strings.Repeat("b", 64),
		},
		ACME: ACMEState{HTTP01Checked: true, HTTP01Ready: true},
	})

	if len(report.ManualChecklists) == 0 {
		t.Fatal("BuildReport() manual checklists = empty, want advisory checklist output")
	}
	if report.ManualCount() != 0 {
		t.Fatalf("BuildReport() manual count = %d, want 0 blocking manual checks", report.ManualCount())
	}
	if report.OverallStatus() != StatusPass {
		t.Fatalf("BuildReport() overall status = %q, want %q", report.OverallStatus(), StatusPass)
	}
	if report.Summary() != "automatic checks passed" {
		t.Fatalf("BuildReport() summary = %q, want %q", report.Summary(), "automatic checks passed")
	}
}

func TestBuildReportAllowsDigitalOceanDNS01OnDebian13(t *testing.T) {
	t.Parallel()

	cfg := config.ExampleConfig()
	cfg.Default.ACMEChallenge = config.ACMEChallengeDNS01
	cfg.Advanced.DNS01.Provider = "digitalocean"
	cfg.Advanced.DNS01.EnvFile = "/etc/lanpanel/dns01/digitalocean.env"

	report := BuildReport(cfg, Inputs{
		Permissions: PermissionState{User: "deployer", SudoWorks: true},
		Platform:    PlatformInfo{ID: "debian", VersionID: "13", PrettyName: "Debian GNU/Linux 13"},
		Capabilities: HostCapabilityState{
			AptGetAvailable:         true,
			DpkgAvailable:           true,
			SystemctlAvailable:      true,
			SystemdRuntimeAvailable: true,
		},
		DNS: DNSProbe{Host: "hs.example.com", ResolvedIPs: []string{"8.8.8.8"}},
		Ports: []PortBinding{
			{Port: 80, Protocol: "tcp", InUse: false},
			{Port: 443, Protocol: "tcp", InUse: false},
			{Port: 8080, Protocol: "tcp", InUse: false},
			{Port: config.DefaultHeadscaleMetricsPort, Protocol: "tcp", InUse: false},
			{Port: 50443, Protocol: "tcp", InUse: false},
			{Port: 3478, Protocol: "udp", InUse: false},
		},
		Firewall: FirewallState{Inspected: true, Active: true, AllowedPorts: []string{"80/tcp", "443/tcp", "3478/udp"}},
		Services: []ServiceState{},
		PackageSource: PackageSourceState{
			Mode:                    config.PackageSourceModeDirect,
			Version:                 config.DefaultHeadscaleVersion,
			ExpectedSHA256:          strings.Repeat("a", 64),
			ReachabilityChecked:     true,
			Reachable:               true,
			IntegrityChecked:        true,
			ActualSHA256:            strings.Repeat("a", 64),
			LegoVersion:             "v5.2.2",
			LegoURL:                 "https://github.com/go-acme/lego/releases/download/v5.2.2/lego_v5.2.2_linux_amd64.tar.gz",
			LegoExpectedSHA256:      strings.Repeat("b", 64),
			LegoReachabilityChecked: true,
			LegoReachable:           true,
			LegoIntegrityChecked:    true,
			LegoActualSHA256:        strings.Repeat("b", 64),
		},
		ACME: ACMEState{DNSCredentialsChecked: true, DNSCredentialsReady: true},
	})

	if report.OverallStatus() != StatusPass {
		t.Fatalf("BuildReport() overall status = %q, want %q", report.OverallStatus(), StatusPass)
	}
	for _, check := range report.Checks {
		if check.ID == "acme" && check.Status == StatusPass && strings.Contains(strings.Join(check.Findings, "\n"), "DNS-01 env file") {
			return
		}
	}
	t.Fatalf("BuildReport() checks = %#v, want passing acme check with env file finding", report.Checks)
}
