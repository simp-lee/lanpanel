package appverify

import (
	"lanpanel/internal/appassets"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apprender"
	"lanpanel/internal/components/appsvc"
	"strings"
	"testing"
)

func testAppConfig() appconfig.Config {
	cfg := appconfig.New()
	cfg.App.Name = "api"
	cfg.App.Domains = []string{"api.example.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.Listen = "127.0.0.1:18001"
	cfg.Access.AccessMode = appconfig.AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = true
	cfg.Service.ExecStart = "/opt/api/api --listen 127.0.0.1:18001"
	return cfg
}

func TestStaticReportRejectsForeignMarkerPrefix(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	report := StaticReport(cfg, []apprender.StagedFile{{
		SourcePath: "templates/app/service.tmpl",
		HostPath:   "/etc/systemd/system/api.service",
		Content:    []byte("# " + appsvc.ManagedMarker("api-admin") + "\n"),
	}})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want foreign marker failure")
	}
	if got := checkSummary(report, "ownership"); !strings.Contains(got, "different Lanpanel app") {
		t.Fatalf("ownership summary = %q, want foreign marker detail", got)
	}
}

func TestStaticReportAllowsManualActivationConfirmations(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	cfg.Access.PublicRiskConfirmed = false
	report := StaticReport(cfg, mustStageRuntime(t, cfg))
	if got := checkSummary(report, "config"); !strings.Contains(got, "valid") {
		t.Fatalf("config summary = %q, want exposure-plan valid config", got)
	}
}

func TestStaticReportRejectsSensitiveValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "tailscale auth key", content: "tskey-auth-secret-value", want: "tskey-auth-"},
		{name: "headscale auth key", content: "hskey-auth-secret-value", want: "hskey-auth-"},
		{name: "legacy tailscale auth key", content: "authkey-secret-value", want: "authkey-"},
		{name: "raw dns token", content: "CF_DNS_API_TOKEN=secret-value", want: "CF_DNS_API_TOKEN"},
		{name: "raw browser auth password", content: "BROWSER_AUTH_PASSWORD=secret-value", want: "BROWSER_AUTH_PASSWORD"},
		{name: "raw dns token in systemd environment", content: "Environment=DO_AUTH_TOKEN=secret-value", want: "DO_AUTH_TOKEN"},
		{name: "raw password in systemd environment", content: "Environment=BROWSER_AUTH_PASSWORD=secret-value", want: "BROWSER_AUTH_PASSWORD"},
		{name: "raw dns token after safe systemd environment", content: "Environment=SAFE=1 CF_DNS_API_TOKEN=secret-value", want: "CF_DNS_API_TOKEN"},
		{name: "raw auth token after safe systemd environment", content: "Environment=FOO=bar DO_AUTH_TOKEN=secret-value", want: "DO_AUTH_TOKEN"},
		{name: "raw auth token after spaced systemd environment", content: "Environment = FOO=bar DO_AUTH_TOKEN=secret-value", want: "DO_AUTH_TOKEN"},
		{name: "quoted raw dns token with spaced value in systemd environment", content: "Environment='CF_DNS_API_TOKEN=secret value'", want: "CF_DNS_API_TOKEN"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := testAppConfig()
			report := StaticReport(cfg, []apprender.StagedFile{{
				SourcePath: "templates/app/service.tmpl",
				HostPath:   "/etc/systemd/system/api.service",
				Content:    []byte("# " + appsvc.ManagedMarker("api") + "\n" + tt.content + "\n"),
			}})
			if report.FailedCount() == 0 {
				t.Fatal("FailedCount() = 0, want sensitive-value failure")
			}
			if got := checkSummary(report, "secrets"); !strings.Contains(got, tt.want) {
				t.Fatalf("secrets summary = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStaticReportRejectsMalformedSystemdEnvironmentSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "unterminated quote", content: "Environment='SAFE=value\n", want: "unterminated quote"},
		{name: "trailing escape", content: "Environment=SAFE=value\\\n", want: "trailing escape"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := testAppConfig()
			staged := mustStageRuntime(t, cfg)
			for i := range staged {
				if staged[i].SourcePath == appassets.ServiceTemplate {
					staged[i].Content = append(staged[i].Content, []byte(tt.content)...)
					break
				}
			}
			report := StaticReport(cfg, staged)
			if report.FailedCount() == 0 {
				t.Fatal("FailedCount() = 0, want invalid Environment syntax failure")
			}
			if got := checkSummary(report, "secrets"); !strings.Contains(got, "valid systemd assignment syntax") || !strings.Contains(got, tt.want) {
				t.Fatalf("secrets summary = %q, want syntax failure containing %q", got, tt.want)
			}
		})
	}
}

func TestStaticReportAllowsCredentialFileReferences(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	report := StaticReport(cfg, []apprender.StagedFile{{
		SourcePath: "templates/app/service.tmpl",
		HostPath:   "/etc/systemd/system/api.service",
		Content:    []byte("# " + appsvc.ManagedMarker("api") + "\nCF_DNS_API_TOKEN_FILE=/run/secrets/cf-token\nBROWSER_AUTH_PASSWORD_FILE=/run/secrets/browser-password\n"),
	}})
	if got := checkSummary(report, "secrets"); !strings.Contains(got, "do not contain") {
		t.Fatalf("secrets summary = %q, want pass", got)
	}
}

func TestStaticReportRejectsLegacyLegoV4Forms(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	report := StaticReport(cfg, []apprender.StagedFile{{
		SourcePath: "templates/app/lego-renew.service.tmpl",
		HostPath:   "/etc/systemd/system/api-lego-renew.service",
		Content:    []byte("# " + appsvc.ManagedMarker("api") + "\nExecStart=/opt/lanpanel/bin/lego renew --renew-hook /hook\n"),
	}})
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want legacy lego v4 failure")
	}
	if got := checkSummary(report, "lego-v5"); !strings.Contains(got, "--renew-hook") {
		t.Fatalf("lego-v5 summary = %q, want stale hook detail", got)
	}
}

func TestStaticReportRejectsSystemdUnsafeConfig(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	cfg.Service.ExecStart = "/opt/api/api --listen 127.0.0.1:18001 ; /bin/true"
	report := StaticReport(cfg, nil)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want config failure")
	}
	if got := checkSummary(report, "config"); !strings.Contains(got, "service.exec_start must not contain systemd separators") {
		t.Fatalf("config summary = %q, want unsafe exec_start detail", got)
	}

	cfg = testAppConfig()
	cfg.App.CertificateEmail = "o'ps@example.com"
	report = StaticReport(cfg, nil)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want config failure")
	}
	if got := checkSummary(report, "config"); !strings.Contains(got, "app.certificate_email must be a systemd-safe email token") {
		t.Fatalf("config summary = %q, want unsafe email detail", got)
	}
}

func TestStaticReportRejectsMissingRuntimeFiles(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	staged := mustStageRuntime(t, cfg)
	report := StaticReport(cfg, withoutSource(staged, appassets.RenewTimerTemplate))
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want missing renew timer failure")
	}
	if got := checkSummary(report, "templates"); !strings.Contains(got, "missing app runtime file: "+appassets.RenewTimerTemplate) {
		t.Fatalf("templates summary = %q, want missing renew timer detail", got)
	}

	report = StaticReport(cfg, withoutSource(staged, appassets.ServiceTemplate))
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want missing listen service failure")
	}
	if got := checkSummary(report, "templates"); !strings.Contains(got, appassets.ServiceTemplate) {
		t.Fatalf("templates summary = %q, want missing service detail", got)
	}
}

func TestStaticReportRejectsRuntimeHostPathDrift(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	staged := mustStageRuntime(t, cfg)
	staged[0].HostPath = "/tmp/wrong-app-target"
	report := StaticReport(cfg, staged)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want runtime host path drift failure")
	}
	if got := checkSummary(report, "templates"); !strings.Contains(got, "host path does not match runtime catalog") {
		t.Fatalf("templates summary = %q, want host path drift detail", got)
	}
}

func TestStaticReportRejectsAppServiceRuntimeDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cfg    func() appconfig.Config
		mutate func(string) string
		want   string
	}{
		{
			name: "type drift",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "Type=simple", "Type=forking", 1)
			},
			want: "app service must set exactly one Type=simple directive",
		},
		{
			name: "root user",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "User=api", "User=root", 1)
			},
			want: "app service must run as dedicated user api",
		},
		{
			name: "root group",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "Group=api", "Group=root", 1)
			},
			want: "app service must run as dedicated group api",
		},
		{
			name: "exec start drift",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "ExecStart=/opt/api/api --listen 127.0.0.1:18001", "ExecStart=/bin/true", 1)
			},
			want: "app service must start configured service.exec_start",
		},
		{
			name: "extra exec directive",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return content + "\nExecStartPre=/bin/true\n"
			},
			want: "app service must not contain extra Exec directive ExecStartPre",
		},
		{
			name: "restart removed",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "Restart=on-failure\n", "", 1)
			},
			want: "app service must set exactly one Restart=on-failure directive",
		},
		{
			name: "no new privileges removed",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "NoNewPrivileges=true\n", "", 1)
			},
			want: "app service must set exactly one NoNewPrivileges=true directive",
		},
		{
			name: "protect system weakened",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "ProtectSystem=full", "ProtectSystem=false", 1)
			},
			want: "app service must set exactly one ProtectSystem=full directive",
		},
		{
			name: "unconfigured working directory injected",
			cfg:  testAppConfig,
			mutate: func(content string) string {
				return strings.Replace(content, "ExecStart=", "WorkingDirectory=/srv/api\nExecStart=", 1)
			},
			want: "app service must not set WorkingDirectory when not configured",
		},
		{
			name: "configured working directory removed",
			cfg: func() appconfig.Config {
				cfg := testAppConfig()
				cfg.Service.WorkingDirectory = "/srv/api"
				return cfg
			},
			mutate: func(content string) string {
				return strings.Replace(content, "WorkingDirectory=/srv/api\n", "", 1)
			},
			want: "app service must set exactly one WorkingDirectory=/srv/api",
		},
		{
			name: "configured environment file removed",
			cfg: func() appconfig.Config {
				cfg := testAppConfig()
				cfg.Service.EnvFile = "/etc/api/service.env"
				return cfg
			},
			mutate: func(content string) string {
				return strings.Replace(content, "EnvironmentFile=/etc/api/service.env\n", "", 1)
			},
			want: "app service must set exactly one EnvironmentFile=/etc/api/service.env",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := tt.cfg()
			staged := mutateStagedSource(mustStageRuntime(t, cfg), appassets.ServiceTemplate, tt.mutate)
			report := StaticReport(cfg, staged)
			if report.FailedCount() == 0 {
				t.Fatal("FailedCount() = 0, want app service runtime drift failure")
			}
			if got := checkSummary(report, "templates"); !strings.Contains(got, tt.want) {
				t.Fatalf("templates summary = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStaticReportOmitsGoAccessChecksWhenDisabled(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	report := StaticReport(cfg, mustStageRuntime(t, cfg))
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want disabled GoAccess static checks pass: %#v", report.FailedCount(), report.Checks)
	}
	for _, check := range report.Checks {
		if check.ID == "goaccess" || check.ID == "goaccess-scope" {
			t.Fatalf("check %#v present with nginx.goaccess.enabled=false, want omitted", check)
		}
	}
}

func TestStaticReportValidatesGoAccessRuntime(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/api/goaccess.htpasswd"
	staged := mustStageRuntime(t, cfg)
	report := StaticReport(cfg, staged)
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want GoAccess static checks pass: %#v", report.FailedCount(), report.Checks)
	}
	if got := checkSummary(report, "goaccess"); !strings.Contains(got, "HTML/WebSocket") {
		t.Fatalf("goaccess summary = %q, want real-time chain summary", got)
	}
	if got := checkSummary(report, "goaccess"); !strings.Contains(got, "logrotate") {
		t.Fatalf("goaccess summary = %q, want managed logrotate summary", got)
	}
	if got := checkSummary(report, "goaccess-scope"); !strings.Contains(got, "request serving time") || !strings.Contains(got, "nginx.error_log") {
		t.Fatalf("goaccess-scope summary = %q, want metric scope and error-log limitation", got)
	}

	explicitLog := cfg
	explicitLog.Nginx.AccessLog = "/var/log/lanpanel/custom/api.access.log"
	report = StaticReport(explicitLog, mustStageRuntime(t, explicitLog))
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want explicit-log GoAccess static checks pass: %#v", report.FailedCount(), report.Checks)
	}
	if got := checkSummary(report, "goaccess"); strings.Contains(got, "logrotate") {
		t.Fatalf("goaccess summary = %q, did not expect explicit-log managed logrotate summary", got)
	}

	loopback7890 := cfg
	loopback7890.Nginx.GoAccess.WebSocketListen = "127.0.0.1:7890"
	report = StaticReport(loopback7890, mustStageRuntime(t, loopback7890))
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want loopback :7890 override to pass: %#v", report.FailedCount(), report.Checks)
	}

	report = StaticReport(cfg, withoutSource(staged, appassets.GoAccessServiceTemplate))
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want missing GoAccess service failure")
	}
	if got := checkSummary(report, "templates"); !strings.Contains(got, appassets.GoAccessServiceTemplate) {
		t.Fatalf("templates summary = %q, want missing goaccess service", got)
	}
}

func TestStaticReportRejectsBrokenGoAccessNginxChain(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/api/goaccess.htpasswd"
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"203.0.113.0/24"}
	staged := mustStageRuntime(t, cfg)
	for i := range staged {
		if staged[i].SourcePath == appassets.NginxTemplate {
			staged[i].Content = []byte(strings.Replace(string(staged[i].Content), "auth_basic_user_file /etc/api/goaccess.htpasswd;", "# auth removed", 1))
			break
		}
	}
	report := StaticReport(cfg, staged)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want broken GoAccess auth failure")
	}
	if got := checkSummary(report, "nginx"); !strings.Contains(got, "GoAccess dashboard auth_basic_user_file") {
		t.Fatalf("nginx summary = %q, want GoAccess auth failure", got)
	}
}

func TestStaticReportRejectsGoAccessRuntimeDrift(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/api/goaccess.htpasswd"

	tests := []struct {
		name   string
		source string
		mutate func(string) string
		check  string
		want   string
	}{
		{
			name:   "service inline runtime flags",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content,
					"ExecStart="+appsvc.GoAccessBinaryPath+" --no-global-config --config-file /etc/api/goaccess.conf",
					"ExecStart="+appsvc.GoAccessBinaryPath+" --no-global-config --config-file /etc/api/goaccess.conf --addr 0.0.0.0 --port 7890",
					1,
				)
			},
			want: "GoAccess service must start goaccess with the rendered config file",
		},
		{
			name:   "enhanced nginx log format order drift",
			source: appassets.NginxTemplate,
			mutate: func(content string) string {
				return strings.Replace(content,
					`"$http_referer" "$http_user_agent" "$host" $request_time`,
					`"$host" "$http_user_agent" "$http_referer" $request_time`,
					1,
				)
			},
			check: "nginx",
			want:  "GoAccess enhanced log_format",
		},
		{
			name:   "dashboard default type drift",
			source: appassets.NginxTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "        default_type text/html;\n", "", 1)
			},
			check: "nginx",
			want:  "GoAccess dashboard default_type",
		},
		{
			name:   "dashboard disable symlinks drift",
			source: appassets.NginxTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "        disable_symlinks on;\n", "", 1)
			},
			check: "nginx",
			want:  "GoAccess dashboard disable_symlinks",
		},
		{
			name:   "websocket authorization clear drift",
			source: appassets.NginxTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, `        proxy_set_header Authorization "";`+"\n", "", 1)
			},
			check: "nginx",
			want:  "GoAccess WebSocket Authorization header clearing",
		},
		{
			name:   "origin suffix drift",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "origin https://api.example.com", "origin https://api.example.com.evil", 1)
			},
			want: "GoAccess config",
		},
		{
			name:   "appended unsafe addr",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\naddr 0.0.0.0\n"
			},
			want: "GoAccess config must set exactly one addr",
		},
		{
			name:   "appended conflicting port",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\nport 7890\n"
			},
			want: "GoAccess config must set exactly one port",
		},
		{
			name:   "appended conflicting origin",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\norigin https://api.example.com.evil\n"
			},
			want: "GoAccess config must set exactly one origin",
		},
		{
			name:   "appended conflicting log format",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\nlog-format COMBINED\n"
			},
			want: "GoAccess config must set exactly one log-format",
		},
		{
			name:   "appended datetime reset",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\ndatetime-format\n"
			},
			want: "GoAccess config must set exactly one datetime-format",
		},
		{
			name:   "appended date format in enhanced mode",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\ndate-format %d/%b/%Y\n"
			},
			want: "GoAccess config date-format must be absent",
		},
		{
			name:   "missing static file extensions",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "static-file .css\n", "", 1)
			},
			want: "GoAccess config static-file directives must exactly match the managed extension list",
		},
		{
			name:   "appended static file extension",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\nstatic-file .map\n"
			},
			want: "GoAccess config static-file directives must exactly match the managed extension list",
		},
		{
			name:   "appended htpasswd content",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\nadmin:$apr1$01234567$0123456789abcdefghijklmn\n"
			},
			want: "GoAccess config contains unmanaged directive or credential content",
		},
		{
			name:   "appended unmanaged directive",
			source: appassets.GoAccessConfigTemplate,
			mutate: func(content string) string {
				return content + "\npassword secret\n"
			},
			want: "GoAccess config contains unmanaged directive or credential content",
		},
		{
			name:   "service lang drift",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Environment=LANG=C.UTF-8", "Environment=LANG=en_US.UTF-8", 1)
			},
			want: "GoAccess service must set exactly one Environment=LANG=C.UTF-8",
		},
		{
			name:   "service type forking",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Type=simple", "Type=forking", 1)
			},
			want: "GoAccess service must set exactly one Type=simple directive",
		},
		{
			name:   "service missing type",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Type=simple\n", "", 1)
			},
			want: "GoAccess service must set exactly one Type=simple directive",
		},
		{
			name:   "service umask drift",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "UMask=0027", "UMask=0077", 1)
			},
			want: "GoAccess service must set exactly one UMask=0027 directive",
		},
		{
			name:   "service missing umask",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "UMask=0027\n", "", 1)
			},
			want: "GoAccess service must set exactly one UMask=0027 directive",
		},
		{
			name:   "service restart drift",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Restart=on-failure", "Restart=always", 1)
			},
			want: "GoAccess service must set exactly one Restart=on-failure directive",
		},
		{
			name:   "service missing restart",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Restart=on-failure\n", "", 1)
			},
			want: "GoAccess service must set exactly one Restart=on-failure directive",
		},
		{
			name:   "service no new privileges drift",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "NoNewPrivileges=true", "NoNewPrivileges=false", 1)
			},
			want: "GoAccess service must set exactly one NoNewPrivileges=true directive",
		},
		{
			name:   "service missing no new privileges",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "NoNewPrivileges=true\n", "", 1)
			},
			want: "GoAccess service must set exactly one NoNewPrivileges=true directive",
		},
		{
			name:   "service missing lc time",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Environment=LC_TIME=C.UTF-8\n", "", 1)
			},
			want: "GoAccess service must set exactly one Environment=LC_TIME=C.UTF-8",
		},
		{
			name:   "service lc all override",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nEnvironment=LC_ALL=zh_CN.UTF-8\n"
			},
			want: "GoAccess service must not set locale override Environment=LC_ALL",
		},
		{
			name:   "service language override",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nEnvironment=LANGUAGE=zh_CN:en\n"
			},
			want: "GoAccess service must not set locale override Environment=LANGUAGE",
		},
		{
			name:   "service spaced lc all override",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nEnvironment = LC_ALL=zh_CN.UTF-8\n"
			},
			want: "GoAccess service must not set locale override Environment=LC_ALL",
		},
		{
			name:   "service quoted lc all override",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nEnvironment=\"LC_ALL=zh_CN.UTF-8\"\n"
			},
			want: "GoAccess service must not set locale override Environment=LC_ALL",
		},
		{
			name:   "service quoted lc all override with spaced value",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nEnvironment='LC_ALL=zh_CN.UTF-8 LANG=C.UTF-8'\n"
			},
			want: "GoAccess service must not set locale override Environment=LC_ALL",
		},
		{
			name:   "service quoted language override",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nEnvironment='LANGUAGE=zh_CN:en'\n"
			},
			want: "GoAccess service must not set locale override Environment=LANGUAGE",
		},
		{
			name:   "service root user",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "User=lanpanel-goaccess-api", "User=root", 1)
			},
			want: "GoAccess service must run as dedicated user lanpanel-goaccess-api",
		},
		{
			name:   "service spaced root user",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nUser = root\n"
			},
			want: "GoAccess service must run as dedicated user lanpanel-goaccess-api",
		},
		{
			name:   "service app user reuse",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "User=lanpanel-goaccess-api", "User=api", 1)
			},
			want: "GoAccess service must run as dedicated user lanpanel-goaccess-api",
		},
		{
			name:   "service missing user",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "User=lanpanel-goaccess-api\n", "", 1)
			},
			want: "GoAccess service must run as dedicated user lanpanel-goaccess-api",
		},
		{
			name:   "service user reset",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nUser=\n"
			},
			want: "GoAccess service must run as dedicated user lanpanel-goaccess-api",
		},
		{
			name:   "service root group",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Group=lanpanel-goaccess-api", "Group=root", 1)
			},
			want: "GoAccess service must run as dedicated group lanpanel-goaccess-api",
		},
		{
			name:   "service app group reuse",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Group=lanpanel-goaccess-api", "Group=api", 1)
			},
			want: "GoAccess service must run as dedicated group lanpanel-goaccess-api",
		},
		{
			name:   "service missing group",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "Group=lanpanel-goaccess-api\n", "", 1)
			},
			want: "GoAccess service must run as dedicated group lanpanel-goaccess-api",
		},
		{
			name:   "service group reset",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nGroup=\n"
			},
			want: "GoAccess service must run as dedicated group lanpanel-goaccess-api",
		},
		{
			name:   "service broad writable path drift",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "ReadWritePaths=/var/lib/api/goaccess/report.html /var/lib/api/goaccess/db", "ReadWritePaths=/var/lib/api/goaccess", 1)
			},
			want: "GoAccess service writable paths must be limited to report file and db",
		},
		{
			name:   "service spaced broad writable path drift",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nReadWritePaths = /\n"
			},
			want: "GoAccess service writable paths must be limited to report file and db",
		},
		{
			name:   "service writable path reset",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nReadWritePaths=\n"
			},
			want: "GoAccess service writable paths must be limited to report file and db",
		},
		{
			name:   "service protect system downgrade",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "ProtectSystem=strict", "ProtectSystem=full", 1)
			},
			want: "GoAccess service must set exactly one ProtectSystem=strict directive",
		},
		{
			name:   "service protect system reset",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nProtectSystem=\n"
			},
			want: "GoAccess service must set exactly one ProtectSystem=strict directive",
		},
		{
			name:   "service private tmp downgrade",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "PrivateTmp=true", "PrivateTmp=false", 1)
			},
			want: "GoAccess service must set exactly one PrivateTmp=true directive",
		},
		{
			name:   "service private tmp reset",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nPrivateTmp=\n"
			},
			want: "GoAccess service must set exactly one PrivateTmp=true directive",
		},
		{
			name:   "service protect home downgrade",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "ProtectHome=true", "ProtectHome=false", 1)
			},
			want: "GoAccess service must set exactly one ProtectHome=true directive",
		},
		{
			name:   "service protect home reset",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nProtectHome=\n"
			},
			want: "GoAccess service must set exactly one ProtectHome=true directive",
		},
		{
			name:   "service appended exec start",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nExecStart=" + appsvc.GoAccessBinaryPath + " --no-global-config --config-file /etc/api/goaccess.conf --addr 0.0.0.0 --port 7890\n"
			},
			want: "GoAccess service must start goaccess with the rendered config file",
		},
		{
			name:   "service extra exec start post",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nExecStartPost=" + appsvc.GoAccessBinaryPath + " --addr 0.0.0.0 --port 7890\n"
			},
			want: "GoAccess service must not contain extra Exec directive ExecStartPost",
		},
		{
			name:   "service spaced extra exec start post",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nExecStartPost = " + appsvc.GoAccessBinaryPath + " --addr 0.0.0.0 --port 7890\n"
			},
			want: "GoAccess service must not contain extra Exec directive ExecStartPost",
		},
		{
			name:   "service exec start reset",
			source: appassets.GoAccessServiceTemplate,
			mutate: func(content string) string {
				return content + "\nExecStart=\n"
			},
			want: "GoAccess service must start goaccess with the rendered config file",
		},
		{
			name:   "logrotate broad path",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "/var/log/lanpanel/apps/api/access.log {", "/var/log/lanpanel/apps/api/*.log {", 1)
			},
			want: "GoAccess logrotate must rotate exactly /var/log/lanpanel/apps/api/access.log",
		},
		{
			name:   "logrotate unrelated path",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "/var/log/lanpanel/apps/api/access.log {", "/var/log/nginx/*.log {", 1)
			},
			want: "GoAccess logrotate must rotate exactly /var/log/lanpanel/apps/api/access.log",
		},
		{
			name:   "logrotate extra unrelated block",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return content + "\n/var/log/nginx/*.log {\n    missingok\n}\n"
			},
			want: "GoAccess logrotate must contain exactly one managed log block",
		},
		{
			name:   "logrotate create mode drift",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "create 0640 www-data lanpanel-goaccess-api", "create 0644 www-data lanpanel-goaccess-api", 1)
			},
			want: "GoAccess logrotate must set create 0640 www-data lanpanel-goaccess-api",
		},
		{
			name:   "logrotate create owner drift",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "create 0640 www-data lanpanel-goaccess-api", "create 0640 root lanpanel-goaccess-api", 1)
			},
			want: "GoAccess logrotate must set create 0640 www-data lanpanel-goaccess-api",
		},
		{
			name:   "logrotate missing create",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "    create 0640 www-data lanpanel-goaccess-api\n", "", 1)
			},
			want: "GoAccess logrotate must set create 0640 www-data lanpanel-goaccess-api",
		},
		{
			name:   "logrotate missing sharedscripts",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "    sharedscripts\n", "", 1)
			},
			want: "GoAccess logrotate must include sharedscripts",
		},
		{
			name:   "logrotate missing postrotate",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "    postrotate\n", "", 1)
			},
			want: "GoAccess logrotate must include postrotate",
		},
		{
			name:   "logrotate reload service drift",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "systemctl reload nginx.service", "systemctl reload nginx", 1)
			},
			want: "GoAccess logrotate must reload nginx.service in postrotate",
		},
		{
			name:   "logrotate missing reload",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "                systemctl reload nginx.service || exit $?\n", "", 1)
			},
			want: "GoAccess logrotate must reload nginx.service in postrotate",
		},
		{
			name:   "logrotate restart goaccess service drift",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "systemctl restart api-goaccess.service", "systemctl restart goaccess.service", 1)
			},
			want: "GoAccess logrotate must restart api-goaccess.service in postrotate",
		},
		{
			name:   "logrotate missing goaccess restart",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "        systemctl restart api-goaccess.service || exit $?\n", "", 1)
			},
			want: "GoAccess logrotate must restart api-goaccess.service in postrotate",
		},
		{
			name:   "logrotate unexpected status error swallowed",
			source: appassets.GoAccessLogrotateTemplate,
			mutate: func(content string) string {
				return strings.Replace(content, "                    exit \"$nginx_state_status\"\n", "", 1)
			},
			want: "GoAccess logrotate must fail on unexpected nginx.service status errors",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			staged := mustStageRuntime(t, cfg)
			for i := range staged {
				if staged[i].SourcePath == tt.source {
					staged[i].Content = []byte(tt.mutate(string(staged[i].Content)))
					break
				}
			}
			report := StaticReport(cfg, staged)
			if report.FailedCount() == 0 {
				t.Fatal("FailedCount() = 0, want GoAccess runtime drift failure")
			}
			checkID := tt.check
			if checkID == "" {
				checkID = "goaccess"
			}
			if got := checkSummary(report, checkID); !strings.Contains(got, tt.want) {
				t.Fatalf("%s summary = %q, want substring %q", checkID, got, tt.want)
			}
		})
	}
}

func TestStaticReportRejectsGoAccessChineseLocaleDrift(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.Language = appconfig.NginxGoAccessLanguageSimplifiedChinese
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/api/goaccess.htpasswd"
	staged := mustStageRuntime(t, cfg)
	report := StaticReport(cfg, staged)
	if report.FailedCount() != 0 {
		t.Fatalf("FailedCount() = %d, want zh-CN GoAccess static checks pass: %#v", report.FailedCount(), report.Checks)
	}

	for i := range staged {
		if staged[i].SourcePath == appassets.GoAccessServiceTemplate {
			staged[i].Content = []byte(strings.Replace(string(staged[i].Content), "Environment=LC_MESSAGES=zh_CN.UTF-8", "Environment=LC_MESSAGES=C.UTF-8", 1))
			break
		}
	}
	report = StaticReport(cfg, staged)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want zh-CN locale drift failure")
	}
	if got := checkSummary(report, "goaccess"); !strings.Contains(got, "GoAccess service must set exactly one Environment=LC_MESSAGES=zh_CN.UTF-8") {
		t.Fatalf("goaccess summary = %q, want zh-CN LC_MESSAGES failure", got)
	}

	staged = mustStageRuntime(t, cfg)
	for i := range staged {
		if staged[i].SourcePath == appassets.GoAccessServiceTemplate {
			staged[i].Content = []byte(string(staged[i].Content) + "\nEnvironment=LC_ALL=C.UTF-8\n")
			break
		}
	}
	report = StaticReport(cfg, staged)
	if report.FailedCount() == 0 {
		t.Fatal("FailedCount() = 0, want zh-CN LC_ALL override failure")
	}
	if got := checkSummary(report, "goaccess"); !strings.Contains(got, "GoAccess service must not set locale override Environment=LC_ALL") {
		t.Fatalf("goaccess summary = %q, want zh-CN LC_ALL failure", got)
	}
}

func TestStaticReportValidatesSNIGuard(t *testing.T) {
	t.Parallel()

	cfg := testAppConfig()
	tests := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{
			name: "missing SNI map",
			mutate: func(content string) string {
				return strings.Replace(content, "map $ssl_server_name $api_sni_valid", "map $host $api_sni_valid", 1)
			},
			want: "SNI allowlist map",
		},
		{
			name: "missing SNI entry",
			mutate: func(content string) string {
				return strings.Replace(content, "map $ssl_server_name $api_sni_valid {\n    default 0;\n    \"api.example.com\" 1;\n}", "map $ssl_server_name $api_sni_valid {\n    default 0;\n}", 1)
			},
			want: "SNI allowlist for api.example.com",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			staged := mustStageRuntime(t, cfg)
			for i := range staged {
				if staged[i].SourcePath != appassets.NginxTemplate {
					continue
				}
				staged[i].Content = []byte(tt.mutate(string(staged[i].Content)))
				break
			}
			report := StaticReport(cfg, staged)
			if report.FailedCount() == 0 {
				t.Fatal("FailedCount() = 0, want missing SNI guard failure")
			}
			if got := checkSummary(report, "nginx"); !strings.Contains(got, tt.want) {
				t.Fatalf("nginx summary = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStaticReportReportsTailscaleRequirement(t *testing.T) {
	t.Parallel()

	listen := testAppConfig()
	report := StaticReport(listen, []apprender.StagedFile{{
		SourcePath: "templates/app/service.tmpl",
		HostPath:   "/etc/systemd/system/api.service",
		Content:    []byte("# " + appsvc.ManagedMarker("api") + "\n"),
	}})
	if got := checkSummary(report, "tailscale"); !strings.Contains(got, "does not require") {
		t.Fatalf("listen tailscale summary = %q, want not-required summary", got)
	}

	upstream := testAppConfig()
	upstream.App.Listen = ""
	upstream.App.Upstream = "100.64.10.20:18001"
	upstream.Service = appconfig.ServiceConfig{}
	report = StaticReport(upstream, []apprender.StagedFile{{
		SourcePath: "templates/app/service.tmpl",
		HostPath:   "/etc/systemd/system/api.service",
		Content:    []byte("# " + appsvc.ManagedMarker("api") + "\n"),
	}})
	if got := checkSummary(report, "tailscale"); !strings.Contains(got, "requires") || strings.Contains(got, "does not require") {
		t.Fatalf("upstream tailscale summary = %q, want required summary", got)
	}
}

func mustStageRuntime(t *testing.T, cfg appconfig.Config) []apprender.StagedFile {
	t.Helper()

	staged, err := apprender.StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	return staged
}

func withoutSource(staged []apprender.StagedFile, sourcePath string) []apprender.StagedFile {
	filtered := make([]apprender.StagedFile, 0, len(staged))
	for _, file := range staged {
		if file.SourcePath == sourcePath {
			continue
		}
		filtered = append(filtered, file)
	}
	return filtered
}

func mutateStagedSource(staged []apprender.StagedFile, sourcePath string, mutate func(string) string) []apprender.StagedFile {
	for i := range staged {
		if staged[i].SourcePath == sourcePath {
			staged[i].Content = []byte(mutate(string(staged[i].Content)))
			return staged
		}
	}
	return staged
}

func checkSummary(report Report, id string) string {
	for _, check := range report.Checks {
		if check.ID == id {
			return check.Summary
		}
	}
	return ""
}
