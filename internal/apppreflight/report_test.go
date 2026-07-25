package apppreflight

import (
	"lanpanel/internal/appconfig"
	"lanpanel/internal/domain"
	"lanpanel/internal/preflight"
	"slices"
	"strings"
	"testing"
)

func TestBuildReportChecksAuthKeyFileReadiness(t *testing.T) {
	t.Parallel()

	cfg := appconfig.New()
	cfg.App.Name = "tailapp"
	cfg.App.Domains = []string{"tailapp.example.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.Upstream = "100.64.10.20:18001"
	cfg.Access.AccessMode = appconfig.AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = true
	cfg.Tailscale.AuthKeyFile = "/run/lanpanel/auth.key"
	report := BuildReport(cfg, Inputs{
		Permissions:                 preflight.PermissionState{IsRoot: true},
		DNS:                         map[string]preflight.DNSProbe{"tailapp.example.com": {Host: "tailapp.example.com", ResolvedIPs: []string{"8.8.8.8"}, ExpectedIPv4: "8.8.8.8"}},
		Ports:                       availableAppPorts(),
		ServiceBinaryOK:             true,
		TailscaleRequired:           true,
		TailscaleAuthKeyFile:        cfg.Tailscale.AuthKeyFile,
		TailscaleAuthKeyFileChecked: true,
		TailscaleAuthKeyFileReady:   false,
		TailscaleAuthKeyFileDetail:  "tailscale auth key file must be root-only",
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want auth key file readiness failure")
	}
	if got := checkSummary(report, "tailscale-auth-key-file"); !strings.Contains(got, "root-only") {
		t.Fatalf("tailscale-auth-key-file summary = %q, want readiness detail", got)
	}

	report = BuildReport(cfg, Inputs{
		Permissions: preflight.PermissionState{IsRoot: true},
		DNS: map[string]preflight.DNSProbe{"tailapp.example.com": {
			Host: "tailapp.example.com", ResolvedIPs: []string{"8.8.8.8"}, ExpectedIPv4: "8.8.8.8",
		}},
		Ports:                       availableAppPorts(),
		ServiceBinaryOK:             true,
		TailscaleRequired:           true,
		TailscaleAuthKeyFile:        cfg.Tailscale.AuthKeyFile,
		TailscaleAuthKeyFileChecked: true,
		TailscaleAuthKeyFileReady:   true,
		TailscaleAuthKeyFileDetail:  "tailscale.auth_key_file passed root-only validation",
	})
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want auth key file readiness pass", report.FailedCount())
	}
}

func TestBuildReportRequiresCurrentRootForAppDeploy(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	report := BuildReport(cfg, Inputs{
		Permissions:     preflight.PermissionState{User: "deploy", SudoWorks: true},
		DNS:             validDNS(cfg),
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want non-root failure even when sudo works")
	}
	if got := checkSummary(report, "permissions"); !strings.Contains(got, "root privileges") {
		t.Fatalf("permissions summary = %q, want root-only app deploy requirement", got)
	}
}

func TestBuildReportChecksServiceEnvFileReadiness(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	cfg.Service.EnvFile = "/opt/app/web.env"
	report := BuildReport(cfg, Inputs{
		Permissions:           preflight.PermissionState{IsRoot: true},
		DNS:                   validDNS(cfg),
		Ports:                 availableAppPorts(),
		ServiceBinaryOK:       true,
		ServiceEnvFile:        cfg.Service.EnvFile,
		ServiceEnvFileChecked: true,
		ServiceEnvFileReady:   false,
		ServiceEnvFileDetail:  "service.env_file must be root-only",
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want service env file readiness failure")
	}
	if got := checkSummary(report, "service-env-file"); !strings.Contains(got, "root-only") {
		t.Fatalf("service-env-file summary = %q, want readiness detail", got)
	}

	report = BuildReport(cfg, Inputs{
		Permissions:           preflight.PermissionState{IsRoot: true},
		DNS:                   validDNS(cfg),
		Ports:                 availableAppPorts(),
		ServiceBinaryOK:       true,
		ServiceEnvFile:        cfg.Service.EnvFile,
		ServiceEnvFileChecked: true,
		ServiceEnvFileReady:   true,
		ServiceEnvFileDetail:  "service.env_file passed root-only validation",
	})
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want service env file readiness pass", report.FailedCount())
	}
}

func TestBuildReportRejectsDNSWithoutPublicOrExpectedAddress(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	report := BuildReport(cfg, Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             map[string]preflight.DNSProbe{"app.example.com": {Host: "app.example.com", ResolvedIPs: []string{"127.0.0.1"}}},
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want private DNS failure")
	}

	report = BuildReport(cfg, Inputs{
		Permissions: preflight.PermissionState{IsRoot: true},
		DNS: map[string]preflight.DNSProbe{"app.example.com": {
			Host:         "app.example.com",
			ResolvedIPs:  []string{"8.8.8.8"},
			ExpectedIPv4: "1.1.1.1",
		}},
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want missing expected DNS failure")
	}

	report = BuildReport(cfg, Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             map[string]preflight.DNSProbe{"app.example.com": {Host: "app.example.com", ResolvedIPs: []string{"8.8.8.8"}}},
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want HTTP-01 unproven host alignment failure")
	}
}

func TestBuildReportWarnsWhenDNSHostAlignmentIsUnproven(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "route53"
	report := BuildReport(cfg, Inputs{
		Permissions:           preflight.PermissionState{IsRoot: true},
		DNS:                   map[string]preflight.DNSProbe{"app.example.com": {Host: "app.example.com", ResolvedIPs: []string{"8.8.8.8"}}},
		Ports:                 availableAppPorts(),
		ServiceBinaryOK:       true,
		DNSCredentialsChecked: true,
		DNSCredentialsReady:   true,
	})
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want warning-only DNS uncertainty", report.FailedCount())
	}
	if got := checkSummary(report, "dns:app.example.com"); !strings.Contains(got, "could not confirm") {
		t.Fatalf("dns summary = %q, want unproven host alignment warning", got)
	}
}

func TestBuildReportDoesNotBlockDNS01WhenPublicDNSIsNotReady(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "route53"

	tests := []struct {
		name string
		dns  map[string]preflight.DNSProbe
		want string
	}{
		{
			name: "lookup missing",
			dns:  map[string]preflight.DNSProbe{"app.example.com": {Host: "app.example.com", LookupError: "no such host"}},
			want: "DNS resolution is unconfirmed",
		},
		{
			name: "private only",
			dns:  map[string]preflight.DNSProbe{"app.example.com": {Host: "app.example.com", ResolvedIPs: []string{"127.0.0.1"}}},
			want: "did not resolve to a public routable address",
		},
		{
			name: "expected mismatch",
			dns:  map[string]preflight.DNSProbe{"app.example.com": {Host: "app.example.com", ResolvedIPs: []string{"8.8.8.8"}, ExpectedIPv4: "1.1.1.1"}},
			want: "missing expected address",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := BuildReport(cfg, Inputs{
				Permissions:           preflight.PermissionState{IsRoot: true},
				DNS:                   tt.dns,
				Ports:                 availableAppPorts(),
				ServiceBinaryOK:       true,
				DNSCredentialsChecked: true,
				DNSCredentialsReady:   true,
			})
			if report.FailedCount() != 0 {
				t.Fatalf("FailedCount() = %d, want DNS-01 warning only", report.FailedCount())
			}
			if got := checkSummary(report, "dns:app.example.com"); !strings.Contains(got, tt.want) || !strings.Contains(got, "does not block deploy") {
				t.Fatalf("dns summary = %q, want warning containing %q", got, tt.want)
			}
		})
	}
}

func TestBuildReportTreatsEdgeOneRealIPDNSAsCDNDNS(t *testing.T) {
	t.Parallel()

	enabled := true
	cfg := validAppConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-2abcDEF123",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns/tencentcloud.env"

	tests := []struct {
		name string
		dns  preflight.DNSProbe
	}{
		{
			name: "no expected origin ip",
			dns:  preflight.DNSProbe{Host: "app.example.com", ResolvedIPs: []string{"8.8.8.8"}},
		},
		{
			name: "expected origin mismatch",
			dns:  preflight.DNSProbe{Host: "app.example.com", ResolvedIPs: []string{"8.8.8.8"}, ExpectedIPv4: "1.1.1.1"},
		},
		{
			name: "direct origin match still warned",
			dns:  preflight.DNSProbe{Host: "app.example.com", ResolvedIPs: []string{"8.8.8.8"}, ExpectedIPv4: "8.8.8.8"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := BuildReport(cfg, Inputs{
				Permissions:                     preflight.PermissionState{IsRoot: true},
				DNS:                             map[string]preflight.DNSProbe{"app.example.com": tt.dns},
				Ports:                           availableAppPorts(),
				ServiceBinaryOK:                 true,
				DNSCredentialsChecked:           true,
				DNSCredentialsReady:             true,
				OriginProtectionManualConfirmed: true,
			})
			if report.FailedCount() != 0 {
				t.Fatalf("FailedCount() = %d, want EdgeOne DNS warning only", report.FailedCount())
			}
			summary := checkSummary(report, "dns:app.example.com")
			if !strings.Contains(summary, "public DNS address") || !strings.Contains(summary, "does not require DNS to match the origin address") {
				t.Fatalf("dns summary = %q, want EdgeOne realip DNS warning", summary)
			}
			for _, forbidden := range []string{"public CDN DNS address", "could not confirm whether these addresses belong to the current cloud server", "missing expected address", "resolved to public address"} {
				if strings.Contains(summary, forbidden) {
					t.Fatalf("dns summary = %q, must not use origin-alignment wording %q", summary, forbidden)
				}
			}
		})
	}
}

func TestBuildReportBlocksEdgeOneRealIPWithoutOriginProtectionConfirmation(t *testing.T) {
	t.Parallel()

	enabled := true
	cfg := validAppConfig()
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-2abcDEF123",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	baseInputs := Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             validDNS(cfg),
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	}

	report := BuildReport(cfg, baseInputs)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want EdgeOne origin ingress confirmation failure")
	}
	if got := checkStatus(report, "realip-firewall"); got != StatusUnknown {
		t.Fatalf("realip-firewall status = %q, want %q", got, StatusUnknown)
	}
	if got := checkSummary(report, "realip-firewall"); !strings.Contains(got, "cannot automatically verify") {
		t.Fatalf("realip-firewall summary = %q, want manual verification failure", got)
	}

	baseInputs.OriginProtectionManualConfirmed = true
	report = BuildReport(cfg, baseInputs)
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want confirmed EdgeOne origin ingress non-blocking manual status", report.FailedCount())
	}
	if got := checkStatus(report, "realip-firewall"); got != StatusManual {
		t.Fatalf("realip-firewall status = %q, want %q", got, StatusManual)
	}
	if got := checkSummary(report, "realip-firewall"); !strings.Contains(got, "manual confirmation was recorded") {
		t.Fatalf("realip-firewall summary = %q, want recorded confirmation", got)
	}

	baseInputs.OriginProtectionManualConfirmed = false
	baseInputs.OriginProtectionStatus = domain.OriginProtectionConfiguredPass
	report = BuildReport(cfg, baseInputs)
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want configured_pass EdgeOne origin protection pass", report.FailedCount())
	}
	if got := checkSummary(report, "realip-firewall"); !strings.Contains(got, "origin protection checks passed") {
		t.Fatalf("realip-firewall summary = %q, want configured_pass summary", got)
	}

	baseInputs.OriginProtectionStatus = domain.OriginProtectionConfiguredFail
	report = BuildReport(cfg, baseInputs)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want configured_fail EdgeOne origin protection failure")
	}
	if got := checkStatus(report, "realip-firewall"); got != StatusFail {
		t.Fatalf("realip-firewall status = %q, want %q", got, StatusFail)
	}
	if got := checkSummary(report, "realip-firewall"); !strings.Contains(got, "checks failed") {
		t.Fatalf("realip-firewall summary = %q, want configured_fail summary", got)
	}
}

func TestBuildReportChecksAppPorts(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	report := BuildReport(cfg, Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             validDNS(cfg),
		Ports:           []preflight.PortBinding{{Port: 80, Protocol: "tcp", InUse: true, Process: "caddy"}, {Port: 443, Protocol: "tcp"}},
		ServiceBinaryOK: true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want non-nginx port conflict")
	}

	report = BuildReport(cfg, Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             validDNS(cfg),
		Ports:           []preflight.PortBinding{{Port: 80, Protocol: "tcp", InUse: true, Process: "nginx"}, {Port: 443, Protocol: "tcp"}},
		ServiceBinaryOK: true,
	})
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want nginx coexistence warning only", report.FailedCount())
	}

	report = BuildReport(cfg, Inputs{
		Permissions: preflight.PermissionState{IsRoot: true},
		DNS:         validDNS(cfg),
		Ports: []preflight.PortBinding{
			{Port: 80, Protocol: "tcp", InUse: true, LocalAddress: "0.0.0.0", Process: "nginx"},
			{Port: 80, Protocol: "tcp", InUse: true, LocalAddress: "127.0.0.1", Process: "caddy"},
			{Port: 443, Protocol: "tcp"},
		},
		ServiceBinaryOK: true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want duplicate non-nginx port conflict")
	}
	if got := checkSummary(report, "port:80/tcp"); !strings.Contains(got, "caddy") {
		t.Fatalf("port:80/tcp summary = %q, want caddy conflict", got)
	}
}

func TestBuildReportChecksAppListenReadiness(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	report := BuildReport(cfg, Inputs{
		Permissions:      preflight.PermissionState{IsRoot: true},
		DNS:              validDNS(cfg),
		Ports:            availableAppPorts(),
		AppListenChecked: true,
		AppListenReady:   false,
		AppListenDetail:  "app.listen 127.0.0.1:18001 is already used by other-service",
		ServiceBinaryOK:  true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want app.listen readiness failure")
	}
	if got := checkSummary(report, "app-listen"); !strings.Contains(got, "other-service") {
		t.Fatalf("app-listen summary = %q, want conflicting process", got)
	}

	report = BuildReport(cfg, Inputs{
		Permissions:      preflight.PermissionState{IsRoot: true},
		DNS:              validDNS(cfg),
		Ports:            availableAppPorts(),
		AppListenChecked: true,
		AppListenReady:   true,
		AppListenDetail:  "app.listen 127.0.0.1:18001 is available",
		ServiceBinaryOK:  true,
	})
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want app.listen readiness pass", report.FailedCount())
	}
}

func TestBuildReportChecksDNS01Credentials(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "cloudflare"
	cfg.DNS01.EnvFile = "/etc/example-app/dns/cloudflare.env"

	report := BuildReport(cfg, Inputs{
		Permissions:           preflight.PermissionState{IsRoot: true},
		DNS:                   validDNS(cfg),
		Ports:                 availableAppPorts(),
		ServiceBinaryOK:       true,
		DNSCredentialsChecked: true,
		DNSCredentialsReady:   false,
		DNSCredentialsDetail:  "env_file contains raw DNS token",
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want DNS credentials failure")
	}

	report = BuildReport(cfg, Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             validDNS(cfg),
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want unchecked DNS credentials to block activation")
	}
	if got := checkStatus(report, "dns01-credentials"); got != StatusUnknown {
		t.Fatalf("dns01-credentials status = %q, want %q", got, StatusUnknown)
	}

	report = BuildReport(cfg, Inputs{
		Permissions:           preflight.PermissionState{IsRoot: true},
		DNS:                   validDNS(cfg),
		Ports:                 availableAppPorts(),
		ServiceBinaryOK:       true,
		DNSCredentialsChecked: true,
		DNSCredentialsReady:   true,
		DNSCredentialsDetail:  "DNS-01 provider env_file passed validation",
	})
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want DNS credentials pass", report.FailedCount())
	}
}

func TestBuildReportChecksGoAccessReadiness(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/app/goaccess.htpasswd"

	report := BuildReport(cfg, Inputs{
		Permissions:             preflight.PermissionState{IsRoot: true},
		DNS:                     validDNS(cfg),
		Ports:                   availableAppPorts(),
		ServiceBinaryOK:         true,
		GoAccessAuthFileChecked: true,
		GoAccessAuthFileReady:   false,
		GoAccessAuthFileDetail:  "htpasswd is group-writable",
		GoAccessPortChecked:     true,
		GoAccessPortReady:       true,
		GoAccessLocaleChecked:   true,
		GoAccessLocaleReady:     true,
		GoAccessLogFileChecked:  true,
		GoAccessLogFileReady:    true,
		GoAccessLogFileDetail:   "log readable",
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want GoAccess auth failure")
	}
	if got := checkSummary(report, "goaccess-auth-file"); !strings.Contains(got, "group-writable") {
		t.Fatalf("goaccess-auth-file summary = %q, want auth detail", got)
	}

	report = BuildReport(cfg, Inputs{
		Permissions:             preflight.PermissionState{IsRoot: true},
		DNS:                     validDNS(cfg),
		Ports:                   availableAppPorts(),
		ServiceBinaryOK:         true,
		GoAccessAuthFileChecked: true,
		GoAccessAuthFileReady:   true,
		GoAccessPortChecked:     true,
		GoAccessPortReady:       false,
		GoAccessPortDetail:      "port 40123 occupied",
		GoAccessLocaleChecked:   true,
		GoAccessLocaleReady:     true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want GoAccess port failure")
	}
	if got := checkSummary(report, "goaccess-port"); !strings.Contains(got, "occupied") {
		t.Fatalf("goaccess-port summary = %q, want port detail", got)
	}

	explicitLog := cfg
	explicitLog.Nginx.AccessLog = "/var/log/lanpanel/custom/app.access.log"
	report = BuildReport(explicitLog, Inputs{
		Permissions:             preflight.PermissionState{IsRoot: true},
		DNS:                     validDNS(explicitLog),
		Ports:                   availableAppPorts(),
		ServiceBinaryOK:         true,
		GoAccessAuthFileChecked: true,
		GoAccessAuthFileReady:   true,
		GoAccessPortChecked:     true,
		GoAccessPortReady:       true,
		GoAccessLocaleChecked:   true,
		GoAccessLocaleReady:     true,
	})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want explicit GoAccess log readiness check failure")
	}
	if got := checkSummary(report, "goaccess-log-file"); !strings.Contains(got, "was not validated automatically") {
		t.Fatalf("goaccess-log-file summary = %q, want unchecked explicit log failure", got)
	}
	nextSteps := report.NextSteps()
	if !slices.ContainsFunc(nextSteps, func(step string) bool {
		return strings.Contains(step, "explicit nginx.access_log") &&
			strings.Contains(step, "file must already exist") &&
			strings.Contains(step, "GoAccess runtime user")
	}) {
		t.Fatalf("NextSteps() = %#v, want explicit nginx.access_log readiness remediation", nextSteps)
	}

	explicitManagedLog := cfg
	explicitManagedLog.Nginx.AccessLog = "/var/log/lanpanel/apps/app/access.log"
	report = BuildReport(explicitManagedLog, Inputs{
		Permissions:             preflight.PermissionState{IsRoot: true},
		DNS:                     validDNS(explicitManagedLog),
		Ports:                   availableAppPorts(),
		ServiceBinaryOK:         true,
		GoAccessAuthFileChecked: true,
		GoAccessAuthFileReady:   true,
		GoAccessPortChecked:     true,
		GoAccessPortReady:       true,
		GoAccessLocaleChecked:   true,
		GoAccessLocaleReady:     true,
	})
	if got := checkSummary(report, "goaccess-log-file"); got != "" {
		t.Fatalf("goaccess-log-file summary = %q, want no explicit log preflight for Lanpanel-managed log", got)
	}

	report = BuildReport(cfg, Inputs{
		Permissions:             preflight.PermissionState{IsRoot: true},
		DNS:                     validDNS(cfg),
		Ports:                   availableAppPorts(),
		ServiceBinaryOK:         true,
		GoAccessAuthFileChecked: true,
		GoAccessAuthFileReady:   true,
		GoAccessPortChecked:     true,
		GoAccessPortReady:       true,
		GoAccessLocaleChecked:   true,
		GoAccessLocaleReady:     true,
	})
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want GoAccess checks pass", report.FailedCount())
	}
}

func TestBuildReportChecksBrowserAuthReadiness(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.AuthBasicUserFile = "/etc/app/browser.htpasswd"

	baseInputs := Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             validDNS(cfg),
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	}

	report := BuildReport(cfg, baseInputs)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want unchecked browser auth failure")
	}
	if got := checkStatus(report, "browser-auth-file"); got != StatusUnknown {
		t.Fatalf("browser-auth-file status = %q, want %q", got, StatusUnknown)
	}
	if got := checkSummary(report, "browser-auth-file"); !strings.Contains(got, "not validated automatically") {
		t.Fatalf("browser-auth-file summary = %q, want unchecked failure", got)
	}

	inputs := baseInputs
	inputs.BrowserAuthFileChecked = true
	inputs.BrowserAuthFileReady = false
	inputs.BrowserAuthFileDetail = "parent directory is group-writable"
	report = BuildReport(cfg, inputs)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want browser auth readiness failure")
	}
	if got := checkSummary(report, "browser-auth-file"); !strings.Contains(got, "group-writable") {
		t.Fatalf("browser-auth-file summary = %q, want readiness detail", got)
	}

	inputs.BrowserAuthFileReady = true
	inputs.BrowserAuthFileDetail = "access.browser_auth htpasswd file passed validation"
	report = BuildReport(cfg, inputs)
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want browser auth readiness pass", report.FailedCount())
	}
	if got := checkSummary(report, "browser-auth-file"); !strings.Contains(got, "passed validation") {
		t.Fatalf("browser-auth-file summary = %q, want pass detail", got)
	}
}

func TestBuildReportMarksDisabledChecksNotApplicable(t *testing.T) {
	t.Parallel()

	cfg := validAppConfig()
	report := BuildReport(cfg, Inputs{
		Permissions:     preflight.PermissionState{IsRoot: true},
		DNS:             validDNS(cfg),
		Ports:           availableAppPorts(),
		ServiceBinaryOK: true,
	})

	for _, id := range []string{"dns01-credentials", "realip-firewall", "browser-auth-file", "tailscale"} {
		if got := checkStatus(report, id); got != StatusNotApplicable {
			t.Fatalf("%s status = %q, want %q", id, got, StatusNotApplicable)
		}
	}
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want not_applicable checks non-blocking", report.FailedCount())
	}
}

func validAppConfig() appconfig.Config {
	cfg := appconfig.New()
	cfg.App.Name = "app"
	cfg.App.Domains = []string{"app.example.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.Listen = "127.0.0.1:18001"
	cfg.Access.AccessMode = appconfig.AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = true
	cfg.Service.ExecStart = "/opt/app/app --listen 127.0.0.1:18001"
	return cfg
}

func validDNS(cfg appconfig.Config) map[string]preflight.DNSProbe {
	return map[string]preflight.DNSProbe{
		cfg.App.Domains[0]: {Host: cfg.App.Domains[0], ResolvedIPs: []string{"8.8.8.8"}, ExpectedIPv4: "8.8.8.8"},
	}
}

func availableAppPorts() []preflight.PortBinding {
	return []preflight.PortBinding{
		{Port: 80, Protocol: "tcp"},
		{Port: 443, Protocol: "tcp"},
	}
}

func checkSummary(report Report, id string) string {
	for _, check := range report.Checks {
		if check.ID == id {
			return check.Summary
		}
	}
	return ""
}

func checkStatus(report Report, id string) Status {
	for _, check := range report.Checks {
		if check.ID == id {
			return check.Status
		}
	}
	return ""
}
