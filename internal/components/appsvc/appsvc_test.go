package appsvc

import (
	"lanpanel/internal/appconfig"
	"lanpanel/internal/host"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func testConfig() appconfig.Config {
	cfg := appconfig.New()
	cfg.App.Name = "example-app"
	cfg.App.Domains = []string{"abc.com", "www.abc.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.Listen = "127.0.0.1:18001"
	cfg.Access.AccessMode = appconfig.AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = true
	cfg.Service.ExecStart = "/opt/example-app/example-app --listen 127.0.0.1:18001"
	cfg.Service.WorkingDirectory = "/opt/example-app"
	return cfg
}

func TestNewNamesDerivesAppResourcePaths(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}

	tests := map[string]string{
		"AppName":                        names.AppName,
		"VarPrefix":                      names.VarPrefix,
		"SystemUser":                     names.SystemUser,
		"ServiceUnit":                    names.ServiceUnit,
		"RenewServiceUnit":               names.RenewServiceUnit,
		"RenewTimerUnit":                 names.RenewTimerUnit,
		"VarLibDir":                      names.VarLibDir,
		"EtcDir":                         names.EtcDir,
		"HookDir":                        names.HookDir,
		"NginxAvailablePath":             names.NginxAvailablePath,
		"NginxEnabledPath":               names.NginxEnabledPath,
		"WebrootPath":                    names.WebrootPath,
		"LegoDataPath":                   names.LegoDataPath,
		"TLSDir":                         names.TLSDir,
		"VarLibMarkerPath":               names.VarLibMarkerPath,
		"EtcMarkerPath":                  names.EtcMarkerPath,
		"HookDirMarkerPath":              names.HookDirMarkerPath,
		"FullchainPath":                  names.FullchainPath,
		"PrivateKeyPath":                 names.PrivateKeyPath,
		"TLSMarkerPath":                  names.TLSMarkerPath,
		"HookPath":                       names.HookPath,
		"GoAccessSystemUser":             names.GoAccessSystemUser,
		"GoAccessServiceUnit":            names.GoAccessServiceUnit,
		"GoAccessConfigPath":             names.GoAccessConfigPath,
		"GoAccessReportPath":             names.GoAccessReportPath,
		"GoAccessDBPath":                 names.GoAccessDBPath,
		"GoAccessLogDir":                 names.GoAccessLogDir,
		"GoAccessLogDirMarkerPath":       names.GoAccessLogDirMarkerPath,
		"GoAccessCanonicalAccessLogPath": names.GoAccessCanonicalAccessLogPath,
		"GoAccessLogrotatePath":          names.GoAccessLogrotatePath,
		"GoAccessWebSocketListen":        names.GoAccessWebSocketListen,
		"GoAccessNginxLogFormatName":     names.GoAccessNginxLogFormatName,
		"RealIPRejectionLogPath":         names.RealIPRejectionLogPath,
		"RealIPRejectionLogFormatName":   names.RealIPRejectionLogFormatName,
	}
	for field, got := range tests {
		if strings.Contains(got, "lanpanel/tls") {
			t.Fatalf("%s = %q, must not use main lanpanel TLS path", field, got)
		}
	}
	if names.ServiceUnit != "example-app.service" {
		t.Fatalf("ServiceUnit = %q, want example-app.service", names.ServiceUnit)
	}
	if names.TLSDir != "/etc/example-app/tls/abc.com" {
		t.Fatalf("TLSDir = %q, want app-specific cert dir", names.TLSDir)
	}
	if names.TLSMarkerPath != "/etc/example-app/tls/abc.com/.lanpanel-managed" {
		t.Fatalf("TLSMarkerPath = %q, want app-specific TLS marker", names.TLSMarkerPath)
	}
	if names.VarLibMarkerPath != "/var/lib/example-app/.lanpanel-managed" {
		t.Fatalf("VarLibMarkerPath = %q, want app root marker", names.VarLibMarkerPath)
	}
	if names.EtcMarkerPath != "/etc/example-app/.lanpanel-managed" {
		t.Fatalf("EtcMarkerPath = %q, want app etc marker", names.EtcMarkerPath)
	}
	if names.HookDirMarkerPath != "/usr/local/lib/lanpanel/apps/example-app/.lanpanel-managed" {
		t.Fatalf("HookDirMarkerPath = %q, want app hook dir marker", names.HookDirMarkerPath)
	}
	if names.GoAccessSystemUser != "lanpanel-goaccess-example-app" || names.GoAccessSystemGroup != names.GoAccessSystemUser {
		t.Fatalf("GoAccess identity = %q/%q, want dedicated app-scoped identity", names.GoAccessSystemUser, names.GoAccessSystemGroup)
	}
	if names.GoAccessServiceUnit != "example-app-goaccess.service" {
		t.Fatalf("GoAccessServiceUnit = %q, want example-app-goaccess.service", names.GoAccessServiceUnit)
	}
	if names.GoAccessConfigPath != "/etc/example-app/goaccess.conf" {
		t.Fatalf("GoAccessConfigPath = %q, want /etc/example-app/goaccess.conf", names.GoAccessConfigPath)
	}
	if names.GoAccessReportPath != "/var/lib/example-app/goaccess/report.html" {
		t.Fatalf("GoAccessReportPath = %q, want app-specific report path", names.GoAccessReportPath)
	}
	if names.GoAccessDBPath != "/var/lib/example-app/goaccess/db" {
		t.Fatalf("GoAccessDBPath = %q, want app-specific db path", names.GoAccessDBPath)
	}
	if names.GoAccessLogDir != "/var/log/lanpanel/apps/example-app" {
		t.Fatalf("GoAccessLogDir = %q, want app-specific log dir", names.GoAccessLogDir)
	}
	if names.GoAccessLogDirMarkerPath != "/var/log/lanpanel/apps/example-app/.lanpanel-managed" {
		t.Fatalf("GoAccessLogDirMarkerPath = %q, want app-specific log marker", names.GoAccessLogDirMarkerPath)
	}
	if names.GoAccessCanonicalAccessLogPath != "/var/log/lanpanel/apps/example-app/access.log" {
		t.Fatalf("GoAccessCanonicalAccessLogPath = %q, want derived access log", names.GoAccessCanonicalAccessLogPath)
	}
	if names.GoAccessLogrotatePath != "/etc/logrotate.d/example-app-goaccess" {
		t.Fatalf("GoAccessLogrotatePath = %q, want app-specific logrotate path", names.GoAccessLogrotatePath)
	}
	if names.GoAccessSuggestedAuthBasicUserFile != "/etc/example-app/goaccess.htpasswd" {
		t.Fatalf("GoAccessSuggestedAuthBasicUserFile = %q, want recommended auth path", names.GoAccessSuggestedAuthBasicUserFile)
	}
	if names.BrowserSuggestedAuthBasicUserFile != "/etc/example-app/browser.htpasswd" {
		t.Fatalf("BrowserSuggestedAuthBasicUserFile = %q, want recommended browser auth path", names.BrowserSuggestedAuthBasicUserFile)
	}
	if names.GoAccessWebSocketHost != "127.0.0.1" || names.GoAccessWebSocketPort == 7890 || names.GoAccessWebSocketListen == "0.0.0.0:7890" {
		t.Fatalf("GoAccess websocket listen = %q (%s:%d), want stable loopback non-default", names.GoAccessWebSocketListen, names.GoAccessWebSocketHost, names.GoAccessWebSocketPort)
	}
	if names.GoAccessNginxLogFormatName != "lanpanel_app_example_app_enhanced" {
		t.Fatalf("GoAccessNginxLogFormatName = %q, want app scoped enhanced format", names.GoAccessNginxLogFormatName)
	}
	if names.RealIPRejectionLogPath != "/var/log/nginx/example-app-realip-rejections.log" {
		t.Fatalf("RealIPRejectionLogPath = %q, want Nginx-managed rejection log path", names.RealIPRejectionLogPath)
	}
	if names.RealIPRejectionLogFormatName != "lanpanel_app_example_app_realip_rejection" {
		t.Fatalf("RealIPRejectionLogFormatName = %q, want app scoped realip rejection format", names.RealIPRejectionLogFormatName)
	}
}

func TestNewRealIPProfileNamesDerivesSharedProfilePaths(t *testing.T) {
	t.Parallel()

	names, err := NewRealIPProfileNames("edgeone-prod", appconfig.RealIPProviderEdgeOne, "example-app")
	if err != nil {
		t.Fatalf("NewRealIPProfileNames() error = %v", err)
	}
	if names.NginxIncludePath != "/etc/nginx/lanpanel/realip/edgeone-prod/active.conf" {
		t.Fatalf("NginxIncludePath = %q", names.NginxIncludePath)
	}
	if names.TrustedCIDRPath != "/etc/nginx/lanpanel/realip/edgeone-prod/trusted-cidrs.conf" {
		t.Fatalf("TrustedCIDRPath = %q", names.TrustedCIDRPath)
	}
	if names.StatePath != "/var/lib/lanpanel/realip/edgeone-prod/state.json" {
		t.Fatalf("StatePath = %q", names.StatePath)
	}
	if names.ReferencePathForApp != "/var/lib/lanpanel/realip/edgeone-prod/references/example-app.json" {
		t.Fatalf("ReferencePathForApp = %q", names.ReferencePathForApp)
	}
	if names.RefreshServiceUnit != "lanpanel-realip-edgeone-prod-refresh.service" {
		t.Fatalf("RefreshServiceUnit = %q", names.RefreshServiceUnit)
	}
	if names.RefreshTimerUnit != "lanpanel-realip-edgeone-prod-refresh.timer" {
		t.Fatalf("RefreshTimerUnit = %q", names.RefreshTimerUnit)
	}

	if _, err := NewRealIPProfileNames("Bad", appconfig.RealIPProviderEdgeOne, "example-app"); err == nil {
		t.Fatal("NewRealIPProfileNames() unsafe profile name error = nil, want non-nil")
	}
	if _, err := NewRealIPProfileNames("edgeone-prod", "custom", "example-app"); err == nil {
		t.Fatal("NewRealIPProfileNames() unsupported provider error = nil, want non-nil")
	}
}

func TestNginxRealIPDetectionParsesDirectiveContext(t *testing.T) {
	t.Parallel()

	text := `
server {
    # real_ip_recursive off;
    location /real_ip_header/ {
        alias /opt/example-app/web/set_real_ip_from/;
        add_header X-Note "real_ip_recursive";
    }
}
`
	for _, name := range []string{"real_ip_header", "set_real_ip_from", "real_ip_recursive"} {
		if nginxHasDirectiveName(text, name) {
			t.Fatalf("nginxHasDirectiveName(%q) = true for directive name inside values/comments", name)
		}
	}
	if nginxHasVariableReference(text, "$example_app_realip_reject_reason") {
		t.Fatal("nginxHasVariableReference() = true for variable name without nginx variable token")
	}

	if !nginxHasDirectiveName("server {\n    real_ip_recursive off;\n}\n", "real_ip_recursive") {
		t.Fatal("nginxHasDirectiveName(real_ip_recursive) = false for actual directive")
	}
	if !nginxHasVariableReference("map $http_eo_connecting_ip $example_app_realip_reject_reason {\n    default \"\";\n}\n", "$example_app_realip_reject_reason") {
		t.Fatal("nginxHasVariableReference() = false for variable in map header")
	}
}

func TestGuardRealIPConflictsCommandChecksTargetSiteAndSkipsManagedRoot(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	realIPNames, err := NewRealIPProfileNames("edgeone-prod", appconfig.RealIPProviderEdgeOne, names.AppName)
	if err != nil {
		t.Fatalf("NewRealIPProfileNames() error = %v", err)
	}
	command := GuardRealIPConflictsCommand(names, realIPNames)
	if command.Name != "sh" || len(command.Args) < 2 {
		t.Fatalf("GuardRealIPConflictsCommand() = %#v, want sh script", command)
	}
	script := command.Args[1]
	for _, want := range []string{
		`managed_realip_root=$(dirname "$managed_realip_dir")`,
		`function count_char`,
		`server_depth`,
		`current_file_managed_realip = managed_realip_files[current_file]`,
		`current_file_managed_app = managed_app_files[current_file]`,
		`index(current_file, managed_realip_root "/") == 1 && index($0, "Lanpanel-managed: realip.profile=") > 0`,
		`index($0, app_marker) > 0`,
		`managed_app_files[current_file] = 1`,
		`index(current_file, managed_realip_root "/") == 1 && current_file_managed_realip`,
		`current_file_managed_app && normalized == "real_ip_header EO-Connecting-IP;"`,
		`scan_file "$current_available"`,
		`contains multi-line include directive; refusing realip conflict scan`,
		`contains dynamic include`,
		`contains non-absolute include`,
		`did not match a file; refusing realip conflict scan`,
		`contains non-Lanpanel realip directive`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("realip conflict guard script missing %q\n%s", want, script)
		}
	}
	if strings.Contains(script, `current_file == current_enabled || current_file == current_available { next }`) {
		t.Fatalf("realip conflict guard must inspect target app site for non-Lanpanel realip directives\n%s", script)
	}
}

func TestGuardRealIPConflictsCommandRejectsTargetMultiLineInclude(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	realIPNames, err := NewRealIPProfileNames("edgeone-prod", appconfig.RealIPProviderEdgeOne, names.AppName)
	if err != nil {
		t.Fatalf("NewRealIPProfileNames() error = %v", err)
	}
	command := GuardRealIPConflictsCommand(names, realIPNames)
	script := command.Args[1]

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(binDir) error = %v", err)
	}
	availablePath := filepath.Join(dir, "example-app.conf")
	snippetPath := filepath.Join(dir, "realip.conf")
	fakeNginx := filepath.Join(binDir, "nginx")
	nginxDump := `# configuration file /etc/nginx/nginx.conf:
http {
# configuration file ` + availablePath + `:
# Lanpanel-managed: app.name=example-app
server {
}
}
`
	if err := os.WriteFile(fakeNginx, []byte("#!/bin/sh\ncat <<'EOF'\n"+nginxDump+"EOF\n"), 0o755); err != nil {
		t.Fatalf("write fake nginx: %v", err)
	}
	if err := os.WriteFile(snippetPath, []byte("real_ip_header X-Forwarded-For;\n"), 0o644); err != nil {
		t.Fatalf("write realip snippet: %v", err)
	}
	available := "# " + ManagedMarker(names.AppName) + "\nserver {\n    include\n        " + snippetPath + ";\n    real_ip_header EO-Connecting-IP;\n}\n"
	if err := os.WriteFile(availablePath, []byte(available), 0o644); err != nil {
		t.Fatalf("write available site: %v", err)
	}

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-realip-conflict-guard", fakeNginx, filepath.Join(dir, "enabled.conf"), availablePath, realIPNames.NginxDir, names.AppName)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "contains multi-line include directive") {
		t.Fatalf("guard error = %v output=%s, want multi-line include refusal", err, output)
	}
}

func TestGuardRealIPConflictsCommandScansTargetSameLineInclude(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	realIPNames, err := NewRealIPProfileNames("edgeone-prod", appconfig.RealIPProviderEdgeOne, names.AppName)
	if err != nil {
		t.Fatalf("NewRealIPProfileNames() error = %v", err)
	}
	command := GuardRealIPConflictsCommand(names, realIPNames)
	script := command.Args[1]

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(binDir) error = %v", err)
	}
	availablePath := filepath.Join(dir, "example-app.conf")
	snippetPath := filepath.Join(dir, "realip.conf")
	fakeNginx := filepath.Join(binDir, "nginx")
	nginxDump := `# configuration file /etc/nginx/nginx.conf:
http {
# configuration file ` + availablePath + `:
# Lanpanel-managed: app.name=example-app
server {
}
}
`
	if err := os.WriteFile(fakeNginx, []byte("#!/bin/sh\ncat <<'EOF'\n"+nginxDump+"EOF\n"), 0o755); err != nil {
		t.Fatalf("write fake nginx: %v", err)
	}
	if err := os.WriteFile(snippetPath, []byte("set_real_ip_from 203.0.113.1;\n"), 0o644); err != nil {
		t.Fatalf("write realip snippet: %v", err)
	}
	available := "# " + ManagedMarker(names.AppName) + "\nserver { include " + snippetPath + "; }\n"
	if err := os.WriteFile(availablePath, []byte(available), 0o644); err != nil {
		t.Fatalf("write available site: %v", err)
	}

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-realip-conflict-guard", fakeNginx, filepath.Join(dir, "enabled.conf"), availablePath, realIPNames.NginxDir, names.AppName)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "contains non-Lanpanel realip directive") {
		t.Fatalf("guard error = %v output=%s, want included realip directive refusal", err, output)
	}
}

func TestGuardRealIPConflictsCommandAllowsUnrelatedServerRealIPButRejectsGlobalRealIP(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	realIPNames, err := NewRealIPProfileNames("edgeone-prod", appconfig.RealIPProviderEdgeOne, names.AppName)
	if err != nil {
		t.Fatalf("NewRealIPProfileNames() error = %v", err)
	}
	command := GuardRealIPConflictsCommand(names, realIPNames)
	script := command.Args[1]

	for _, tt := range []struct {
		name      string
		nginxDump string
		wantErr   string
	}{
		{
			name: "unrelated server realip is scoped away",
			nginxDump: `# configuration file /etc/nginx/nginx.conf:
http {
# configuration file /etc/nginx/sites-enabled/other-app.conf:
# Lanpanel-managed: app.name=other-app
server {
    real_ip_header EO-Connecting-IP;
}
# configuration file /etc/nginx/sites-enabled/foreign.conf:
server {
    real_ip_header X-Forwarded-For;
}
}
`,
		},
		{
			name: "unrelated split server block realip is scoped away",
			nginxDump: `# configuration file /etc/nginx/nginx.conf:
http {
# configuration file /etc/nginx/sites-enabled/foreign.conf:
server
{
    real_ip_header X-Forwarded-For;
}
}
`,
		},
		{
			name: "unrelated server included realip is scoped away",
			nginxDump: `# configuration file /etc/nginx/nginx.conf:
http {
# configuration file /etc/nginx/sites-enabled/foreign.conf:
server {
    include /etc/nginx/snippets/realip.conf;
# configuration file /etc/nginx/snippets/realip.conf:
    real_ip_header X-Forwarded-For;
    set_real_ip_from 203.0.113.1;
# configuration file /etc/nginx/sites-enabled/foreign.conf:
}
}
`,
		},
		{
			name: "global realip affects target",
			nginxDump: `# configuration file /etc/nginx/nginx.conf:
http {
    real_ip_header X-Forwarded-For;
}
`,
			wantErr: "contains non-Lanpanel realip directive",
		},
		{
			name: "http included realip affects target",
			nginxDump: `# configuration file /etc/nginx/nginx.conf:
http {
    include /etc/nginx/snippets/global-realip.conf;
# configuration file /etc/nginx/snippets/global-realip.conf:
    real_ip_header X-Forwarded-For;
}
`,
			wantErr: "contains non-Lanpanel realip directive",
		},
		{
			name: "managed app marker survives managed realip include roundtrip",
			nginxDump: `# configuration file /etc/nginx/nginx.conf:
http {
# configuration file {{AVAILABLE}}:
# Lanpanel-managed: app.name=example-app
server {
    include /etc/nginx/lanpanel/realip/edgeone-prod/active.conf;
# configuration file /etc/nginx/lanpanel/realip/edgeone-prod/active.conf:
# Lanpanel-managed: realip.profile=edgeone-prod provider=edgeone
    set_real_ip_from 8.8.8.8/32;
# configuration file {{AVAILABLE}}:
    real_ip_header EO-Connecting-IP;
}
}
`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			binDir := filepath.Join(dir, "bin")
			if err := os.MkdirAll(binDir, 0o755); err != nil {
				t.Fatalf("MkdirAll() error = %v", err)
			}
			availablePath := filepath.Join(dir, "example-app.conf")
			fakeNginx := filepath.Join(binDir, "nginx")
			nginxDump := strings.ReplaceAll(tt.nginxDump, "{{AVAILABLE}}", availablePath)
			if err := os.WriteFile(fakeNginx, []byte("#!/bin/sh\ncat <<'EOF'\n"+nginxDump+"EOF\n"), 0o755); err != nil {
				t.Fatalf("write fake nginx: %v", err)
			}
			available := "# " + ManagedMarker(names.AppName) + "\nserver {\n    real_ip_header EO-Connecting-IP;\n}\n"
			if err := os.WriteFile(availablePath, []byte(available), 0o644); err != nil {
				t.Fatalf("write available site: %v", err)
			}

			cmd := exec.Command("sh", "-c", script, "lanpanel-app-realip-conflict-guard", fakeNginx, filepath.Join(dir, "enabled.conf"), availablePath, realIPNames.NginxDir, names.AppName)
			cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("guard error = %v output=%s", err, output)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), tt.wantErr) {
				t.Fatalf("guard error = %v output=%s, want %q", err, output, tt.wantErr)
			}
		})
	}
}

func TestNewNamesGoAccessCanonicalLogAndWebSocketOverrides(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	cfg.Nginx.GoAccess.WebSocketListen = "127.0.0.1:40123"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	if names.GoAccessCanonicalAccessLogPath != "/var/log/lanpanel/custom/example-app.access.log" {
		t.Fatalf("GoAccessCanonicalAccessLogPath = %q, want explicit access log", names.GoAccessCanonicalAccessLogPath)
	}
	if names.GoAccessWebSocketHost != "127.0.0.1" || names.GoAccessWebSocketPort != 40123 || names.GoAccessWebSocketListen != "127.0.0.1:40123" {
		t.Fatalf("GoAccess websocket override = %q (%s:%d), want 127.0.0.1:40123", names.GoAccessWebSocketListen, names.GoAccessWebSocketHost, names.GoAccessWebSocketPort)
	}
}

func TestGoAccessWebSocketListenPartsRejectsInvalidOverride(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	cfg.Nginx.GoAccess.WebSocketListen = "127.0.0.1:not-a-port"

	if _, _, err := goAccessWebSocketListenParts(cfg); err == nil || !strings.Contains(err.Error(), "parse GoAccess websocket listen port") {
		t.Fatalf("goAccessWebSocketListenParts() error = %v, want explicit GoAccess websocket listen parse failure", err)
	}
}

func TestGoAccessManagesCanonicalAccessLogForCurrentAppLogRoot(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	if !GoAccessManagesCanonicalAccessLog(cfg) {
		t.Fatal("GoAccessManagesCanonicalAccessLog(derived) = false, want true")
	}

	cfg.Nginx.AccessLog = "/var/log/lanpanel/apps/example-app/access.log"
	if !GoAccessManagesCanonicalAccessLog(cfg) {
		t.Fatal("GoAccessManagesCanonicalAccessLog(explicit current app log root) = false, want true")
	}

	cfg.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
	if GoAccessManagesCanonicalAccessLog(cfg) {
		t.Fatal("GoAccessManagesCanonicalAccessLog(custom explicit log) = true, want false")
	}
}

func TestGoAccessDerivedPortsAreStableAndAppScoped(t *testing.T) {
	t.Parallel()

	first, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames(first) error = %v", err)
	}
	second, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames(second) error = %v", err)
	}
	if first.GoAccessWebSocketPort != second.GoAccessWebSocketPort {
		t.Fatalf("GoAccessWebSocketPort changed between calls: %d vs %d", first.GoAccessWebSocketPort, second.GoAccessWebSocketPort)
	}
	if first.GoAccessWebSocketPort < appconfig.NginxGoAccessWebSocketPortBase || first.GoAccessWebSocketPort >= appconfig.NginxGoAccessWebSocketPortBase+appconfig.NginxGoAccessWebSocketPortSpan {
		t.Fatalf("GoAccessWebSocketPort = %d, want within app-derived high port range", first.GoAccessWebSocketPort)
	}

	otherCfg := testConfig()
	otherCfg.App.Name = "other-app"
	other, err := NewNames(otherCfg)
	if err != nil {
		t.Fatalf("NewNames(other) error = %v", err)
	}
	if first.GoAccessWebSocketPort == other.GoAccessWebSocketPort {
		t.Fatalf("two app names derived the same default GoAccess port %d", first.GoAccessWebSocketPort)
	}
	if first.GoAccessCanonicalAccessLogPath == other.GoAccessCanonicalAccessLogPath {
		t.Fatalf("two app names derived the same canonical access log %q", first.GoAccessCanonicalAccessLogPath)
	}
}

func TestGoAccessIdentityNameFitsLinuxUserLimit(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.App.Name = "app-name-that-is-thirty-two-long"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	if len(names.GoAccessSystemUser) > linuxUserNameMaxLen {
		t.Fatalf("GoAccessSystemUser = %q length %d, want <= %d", names.GoAccessSystemUser, len(names.GoAccessSystemUser), linuxUserNameMaxLen)
	}
	if names.GoAccessSystemUser != names.GoAccessSystemGroup {
		t.Fatalf("GoAccess identity = %q/%q, want matching user/group", names.GoAccessSystemUser, names.GoAccessSystemGroup)
	}

	again, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames(again) error = %v", err)
	}
	if names.GoAccessSystemUser != again.GoAccessSystemUser {
		t.Fatalf("GoAccessSystemUser changed between calls: %q vs %q", names.GoAccessSystemUser, again.GoAccessSystemUser)
	}
	if !strings.HasPrefix(names.GoAccessSystemUser, "mga-app-name-that-is-t") {
		t.Fatalf("GoAccessSystemUser = %q, want readable hashed fallback", names.GoAccessSystemUser)
	}
}

func TestGuardServerNameConflictsCommandRejectsEnabledDuplicate(t *testing.T) {
	t.Parallel()

	current := "/etc/nginx/sites-enabled/example-app.conf"
	available := "/etc/nginx/sites-available/example-app.conf"
	command := guardServerNameConflictsCommand(current, available, []string{"abc.com"})
	output, err := runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		current:                   "server { server_name abc.com; }\n",
		"/etc/nginx/conf.d/other": "server { server_name other.example.com; }\n",
		"/etc/nginx/conf.d/app":   "server { server_name abc.com other.example.com; }\n",
		"/etc/nginx/nginx.conf":   "events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n",
		"/etc/nginx/mime.types":   "types {}\n",
		"/etc/nginx/fastcgi.conf": "",
		"/etc/nginx/proxy_params": "",
		"/etc/nginx/scgi_params":  "",
		"/etc/nginx/uwsgi_params": "",
		"/etc/nginx/modules.conf": "",
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want duplicate domain failure; output:\n%s", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/conf.d/multiline-app.conf": `server {
    listen 443 ssl;
    server_name
        other.example.com
        abc.com;
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want multiline duplicate domain failure; output:\n%s", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		current:                 "server { server_name abc.com; }\n",
		"/etc/nginx/conf.d/app": "server { server_name other.example.com; }\n",
	}))
	if err != nil {
		t.Fatalf("guard command error = %v; output:\n%s", err, output)
	}
}

func TestGuardDefaultServerCommandAllowsOnlyLanpanelCatchAll(t *testing.T) {
	t.Parallel()

	current := "/etc/nginx/sites-enabled/example-app.conf"
	available := "/etc/nginx/sites-available/example-app.conf"
	command := guardDefaultServerCommand(current, available)
	output, err := runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/conf.d/custom-default.conf": "server { listen 80 default_server; root /var/www/html; }\n",
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want custom default_server failure; output:\n%s", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/conf.d/multiline-default.conf": `server {
    listen
        80
        default_server;
    server_name custom.example.com;
    return 200;
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want multiline custom default_server failure; output:\n%s", output)
	}

	lanpanel := `server {
    listen 80 default_server;
    server_name "";
    return 444;
}
server {
    listen 443 ssl default_server;
    server_name "";
    ssl_certificate /etc/lanpanel/tls/hs.example.com/fullchain.pem;
    return 421;
}
`
	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/conf.d/lanpanel-default.conf": lanpanel,
	}))
	if err != nil {
		t.Fatalf("guard command error = %v; output:\n%s", err, output)
	}

	mixed := lanpanel + `
server {
    listen 8080 default_server;
    server_name custom.example.com;
    return 200;
}
`
	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/conf.d/mixed-default.conf": mixed,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want custom default_server in mixed file failure; output:\n%s", output)
	}
}

func TestGuardGoAccessWebSocketPortAssignmentCommandRejectsExistingProxyTarget(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.App.Name = "app-139"
	cfg.App.Domains = []string{"app-139.example.com"}
	cfg.Service.ExecStart = "/opt/app-139/app-139 --listen 127.0.0.1:18001"
	cfg.Service.WorkingDirectory = "/opt/app-139"
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/app-139/goaccess.htpasswd"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames(app-139) error = %v", err)
	}

	otherCfg := testConfig()
	otherCfg.App.Name = "app-1192"
	otherCfg.App.Domains = []string{"app-1192.example.com"}
	otherCfg.Service.ExecStart = "/opt/app-1192/app-1192 --listen 127.0.0.1:18002"
	otherCfg.Service.WorkingDirectory = "/opt/app-1192"
	otherCfg.Nginx.GoAccess.Enabled = true
	otherCfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/app-1192/goaccess.htpasswd"
	otherNames, err := NewNames(otherCfg)
	if err != nil {
		t.Fatalf("NewNames(app-1192) error = %v", err)
	}
	t.Logf("collision fixture ports: app-139=%d app-1192=%d", names.GoAccessWebSocketPort, otherNames.GoAccessWebSocketPort)

	command := GuardGoAccessWebSocketPortAssignmentCommand(names)
	conflictingSite := `# Lanpanel-managed: app.name=app-1192
server {
    listen 443 ssl;
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://` + names.GoAccessWebSocketListen + `;
    }
}
`
	output, err := runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": conflictingSite,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want GoAccess websocket assignment conflict; output:\n%s", output)
	}
	if !strings.Contains(string(output), "app-1192.conf") || !strings.Contains(string(output), "nginx.goaccess.websocket_listen") {
		t.Fatalf("guard command output = %q, want conflicting file and override guidance", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass
            http://` + names.GoAccessWebSocketListen + `;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want multiline GoAccess websocket assignment conflict; output:\n%s", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://` + names.GoAccessWebSocketListen + `/;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want GoAccess websocket assignment conflict with URI suffix; output:\n%s", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://` + names.GoAccessWebSocketListen + `$request_uri;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want GoAccess websocket assignment conflict with variable URI suffix; output:\n%s", output)
	}

	localhostProxyTarget := "localhost:" + strconv.Itoa(names.GoAccessWebSocketPort)
	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://` + localhostProxyTarget + `;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want localhost GoAccess websocket assignment conflict; output:\n%s", output)
	}
	if !strings.Contains(string(output), "http://"+localhostProxyTarget) || !strings.Contains(string(output), "nginx.goaccess.websocket_listen") {
		t.Fatalf("guard command output = %q, want localhost conflict and override guidance", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `upstream leaked_goaccess {
    server ` + names.GoAccessWebSocketListen + `;
}

server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://leaked_goaccess;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want upstream GoAccess websocket assignment conflict; output:\n%s", output)
	}
	if !strings.Contains(string(output), "upstream leaked_goaccess") || !strings.Contains(string(output), "nginx.goaccess.websocket_listen") {
		t.Fatalf("guard command output = %q, want upstream conflict and override guidance", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `upstream split_goaccess
{
    server ` + names.GoAccessWebSocketListen + `;
}

server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://split_goaccess;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want split upstream GoAccess websocket assignment conflict; output:\n%s", output)
	}
	if !strings.Contains(string(output), "upstream split_goaccess") || !strings.Contains(string(output), "nginx.goaccess.websocket_listen") {
		t.Fatalf("guard command output = %q, want split upstream conflict and override guidance", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `upstream leaked_localhost_goaccess {
    server ` + localhostProxyTarget + `;
}

server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://leaked_localhost_goaccess;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want localhost upstream GoAccess websocket assignment conflict; output:\n%s", output)
	}
	if !strings.Contains(string(output), "upstream leaked_localhost_goaccess") || !strings.Contains(string(output), "nginx.goaccess.websocket_listen") {
		t.Fatalf("guard command output = %q, want localhost upstream conflict and override guidance", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		"/etc/nginx/sites-enabled/app-1192.conf": `upstream split_localhost_goaccess
{
    server ` + localhostProxyTarget + `;
}

server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://split_localhost_goaccess;
    }
}
`,
	}))
	if err == nil {
		t.Fatalf("guard command error = nil, want split localhost upstream GoAccess websocket assignment conflict; output:\n%s", output)
	}
	if !strings.Contains(string(output), "upstream split_localhost_goaccess") || !strings.Contains(string(output), "nginx.goaccess.websocket_listen") {
		t.Fatalf("guard command output = %q, want split localhost upstream conflict and override guidance", output)
	}

	output, err = runGuardCommandWithNginxDump(t, command, nginxDump(map[string]string{
		names.NginxAvailablePath: `server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_pass http://` + names.GoAccessWebSocketListen + `;
    }
}
`,
	}))
	if err != nil {
		t.Fatalf("guard command rejected current app config: %v; output:\n%s", err, output)
	}
}

func TestCertificatePlanRepeatsDomainsAndMasksEnvFileDisplay(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "google"
	cfg.DNS01.EnvFile = "/etc/example-app/dns/gcloud.env"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}

	plan, err := NewCertificatePlan(cfg, names)
	if err != nil {
		t.Fatalf("NewCertificatePlan() error = %v", err)
	}
	display := plan.Command.String()
	for _, want := range []string{
		"--domains abc.com",
		"--domains www.abc.com",
		"--dns gcloud",
		"run --path /var/lib/example-app/lego",
		"--force-cert-domains --deploy-hook /usr/local/lib/lanpanel/apps/example-app/install-cert-and-reload-nginx.sh",
	} {
		if !strings.Contains(display, want) {
			t.Fatalf("command = %q, want substring %q", display, want)
		}
	}
	if strings.Contains(display, cfg.DNS01.EnvFile) {
		t.Fatalf("command display leaks env_file path: %q", display)
	}
}

func TestCertificatePlanIssueOrRenewWrapper(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	plan, err := NewCertificatePlan(cfg, names)
	if err != nil {
		t.Fatalf("NewCertificatePlan() error = %v", err)
	}
	if plan.Command.Name != "sh" || len(plan.Command.Args) < 8 || plan.Command.Args[2] != "lanpanel-app-lego-issue-or-renew" {
		t.Fatalf("command = %#v, want issue-or-renew shell wrapper", plan.Command)
	}

	for _, tt := range []struct {
		name           string
		existingCert   bool
		wantSubstrings []string
	}{
		{
			name:           "first issue",
			wantSubstrings: []string{" run ", " --force-cert-domains ", " --deploy-hook "},
		},
		{
			name:           "renew existing",
			existingCert:   true,
			wantSubstrings: []string{" run ", " --force-cert-domains ", " --deploy-hook "},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			legoPath := filepath.Join(dir, "lego")
			if tt.existingCert {
				certDir := filepath.Join(legoPath, "certificates")
				if err := os.MkdirAll(certDir, 0o755); err != nil {
					t.Fatalf("MkdirAll() error = %v", err)
				}
				for _, name := range []string{"abc.com.crt", "abc.com.key", "abc.com.json"} {
					if err := os.WriteFile(filepath.Join(certDir, name), []byte("present"), 0o600); err != nil {
						t.Fatalf("WriteFile() error = %v", err)
					}
				}
			}
			fakeLego := filepath.Join(dir, "lego-bin")
			fakeHook := filepath.Join(dir, "hook")
			outputFile := filepath.Join(dir, "args")
			writeExecutable(t, fakeLego, "#!/bin/sh\nprintf ' %s' \"$@\" > "+outputFile+"\n")
			writeExecutable(t, fakeHook, "#!/bin/sh\nexit 0\n")

			args := append([]string(nil), plan.Command.Args...)
			args[3] = fakeLego
			args[4] = legoPath
			args[6] = fakeHook
			output, err := exec.Command(plan.Command.Name, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("wrapper error = %v; output:\n%s", err, output)
			}
			got, err := os.ReadFile(outputFile)
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			for _, want := range tt.wantSubstrings {
				if !strings.Contains(string(got), want) {
					t.Fatalf("lego args = %q, want substring %q", got, want)
				}
			}
		})
	}
}

func TestCertificatePlanInstallsCachedLegoCertificateBeforeRenew(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	plan, err := NewCertificatePlan(cfg, names)
	if err != nil {
		t.Fatalf("NewCertificatePlan() error = %v", err)
	}

	dir := t.TempDir()
	legoPath := filepath.Join(dir, "lego")
	certDir := filepath.Join(legoPath, "certificates")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	for name, content := range map[string]string{
		"abc.com.crt":  "cached cert",
		"abc.com.key":  "cached key",
		"abc.com.json": "{}",
	} {
		if err := os.WriteFile(filepath.Join(certDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}
	hookLog := filepath.Join(dir, "hook.log")
	hook := filepath.Join(dir, "hook")
	writeExecutable(t, hook, `#!/bin/sh
printf 'hook cert=%s key=%s\n' "$LEGO_HOOK_CERT_PATH" "$LEGO_HOOK_CERT_KEY_PATH" >> "`+hookLog+`"
`)
	fakeLegoLog := filepath.Join(dir, "lego.log")
	fakeLego := filepath.Join(dir, "lego-bin")
	writeExecutable(t, fakeLego, `#!/bin/sh
printf 'lego %s\n' "$*" >> "`+fakeLegoLog+`"
`)

	args := append([]string(nil), plan.Command.Args...)
	args[3] = fakeLego
	args[4] = legoPath
	args[6] = hook
	output, err := exec.Command(plan.Command.Name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("wrapper error = %v; output:\n%s", err, output)
	}
	hookOutput, err := os.ReadFile(hookLog)
	if err != nil {
		t.Fatalf("ReadFile(hook log) error = %v", err)
	}
	wantHook := "hook cert=" + filepath.Join(certDir, "abc.com.crt") + " key=" + filepath.Join(certDir, "abc.com.key") + "\n"
	if string(hookOutput) != wantHook {
		t.Fatalf("hook log = %q, want %q", hookOutput, wantHook)
	}
	legoOutput, err := os.ReadFile(fakeLegoLog)
	if err != nil {
		t.Fatalf("ReadFile(lego log) error = %v", err)
	}
	if !strings.Contains(string(legoOutput), " run ") || !strings.Contains(string(legoOutput), " --deploy-hook "+hook) {
		t.Fatalf("lego log = %q, want run after cached install hook", legoOutput)
	}
}

func TestDNS01CommandEnvFileParserMatchesSystemdStyle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	envFile := filepath.Join(dir, "dns.env")
	if err := os.WriteFile(envFile, []byte(`
# comment
; another comment
CF_DNS_API_TOKEN_FILE = '`+filepath.Join(dir, "cf token")+`'
GCE_PROJECT = "lanpanel-project"
EMPTY =
ignored note
`), 0o600); err != nil {
		t.Fatalf("WriteFile(envFile) error = %v", err)
	}
	printer := filepath.Join(dir, "print-env")
	writeExecutable(t, printer, `#!/bin/sh
printf 'CF=%s\nGCE=%s\nEMPTY=%s\n' "$CF_DNS_API_TOKEN_FILE" "$GCE_PROJECT" "${EMPTY-unset}"
`)
	command := legoCommandWithEnvFile(envFile, []string{"run"})
	script := command.Args[1]

	output, err := exec.Command("sh", "-c", script, "lanpanel-app-lego-dns01", envFile, printer).CombinedOutput()
	if err != nil {
		t.Fatalf("env parser script error = %v; output:\n%s", err, output)
	}
	want := "CF=" + filepath.Join(dir, "cf token") + "\nGCE=lanpanel-project\nEMPTY=unset\n"
	if string(output) != want {
		t.Fatalf("output = %q, want %q", output, want)
	}
	for _, unwanted := range []string{`. "$env_file"`, `source "$env_file"`} {
		if strings.Contains(script, unwanted) {
			t.Fatalf("script must not execute env_file through %q", unwanted)
		}
	}
}

func TestDNS01CommandEnvFileParserRejectsUnsafeSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "export", content: "export CF_DNS_API_TOKEN_FILE=/run/secrets/cf\n", want: "unsupported export syntax"},
		{name: "invalid variable name", content: "CF-DNS-API-TOKEN=/run/secrets/cf\n", want: "unsupported DNS env_file variable name"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			envFile := filepath.Join(dir, "dns.env")
			if err := os.WriteFile(envFile, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("WriteFile(envFile) error = %v", err)
			}
			command := legoCommandWithEnvFile(envFile, []string{"run"})
			output, err := exec.Command("sh", "-c", command.Args[1], "lanpanel-app-lego-dns01", envFile, "true").CombinedOutput()
			if err == nil {
				t.Fatalf("env parser script error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("output = %q, want substring %q", output, tt.want)
			}
		})
	}
}

func TestGuardTLSOwnershipCommandProtectsCertificateTargets(t *testing.T) {
	t.Parallel()

	baseNames, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T, names Names)
		wantErr bool
		want    string
	}{
		{name: "empty dir installs marker", wantErr: false},
		{
			name: "matching marker",
			prepare: func(t *testing.T, names Names) {
				writeFile(t, names.TLSMarkerPath, ManagedMarker(names.AppName)+"\n", 0o600)
			},
			wantErr: false,
		},
		{
			name: "foreign marker",
			prepare: func(t *testing.T, names Names) {
				writeFile(t, names.TLSMarkerPath, ManagedMarker("other-app")+"\n", 0o600)
			},
			wantErr: true,
			want:    "managed by a different Lanpanel app",
		},
		{
			name: "existing cert without marker",
			prepare: func(t *testing.T, names Names) {
				writeFile(t, names.FullchainPath, "foreign cert\n", 0o644)
			},
			wantErr: true,
			want:    "refusing to overwrite non-Lanpanel TLS file",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			names := baseNames
			names.TLSDir = filepath.Join(dir, "tls")
			names.FullchainPath = filepath.Join(names.TLSDir, "fullchain.pem")
			names.PrivateKeyPath = filepath.Join(names.TLSDir, "privkey.pem")
			names.TLSMarkerPath = filepath.Join(names.TLSDir, ".lanpanel-managed")
			if tt.prepare != nil {
				tt.prepare(t, names)
			}
			command := GuardTLSOwnershipCommand(names)
			args := append([]string{"-c", command.Args[1]}, command.Args[2:]...)
			output, err := exec.Command("sh", args...).CombinedOutput()
			if tt.wantErr && err == nil {
				t.Fatalf("script error = nil, want failure; output:\n%s", output)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("script error = %v; output:\n%s", err, output)
			}
			if tt.want != "" && !strings.Contains(string(output), tt.want) {
				t.Fatalf("output = %q, want %q", output, tt.want)
			}
			if !tt.wantErr {
				content, err := os.ReadFile(names.TLSMarkerPath)
				if err != nil {
					t.Fatalf("ReadFile(marker) error = %v", err)
				}
				if strings.TrimSpace(string(content)) != ManagedMarker(names.AppName) {
					t.Fatalf("marker = %q, want %q", content, ManagedMarker(names.AppName))
				}
			}
		})
	}
}

func TestEnsureSystemUserCommandRejectsExistingIdentityConflicts(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	command := EnsureSystemUserCommands(names)[0]
	script := command.Args[1]

	tests := []struct {
		name     string
		scenario string
		want     string
	}{
		{
			name:     "existing group without user",
			scenario: "group-only",
			want:     "already exists without matching app user",
		},
		{
			name:     "existing user without group",
			scenario: "user-only",
			want:     "already exists without matching app group",
		},
		{
			name:     "mismatched primary group",
			scenario: "mismatched-group",
			want:     "primary group does not match app group",
		},
		{
			name:     "mismatched home",
			scenario: "mismatched-home",
			want:     "expected /var/lib/example-app",
		},
		{
			name:     "login shell",
			scenario: "login-shell",
			want:     "expected /usr/sbin/nologin",
		},
		{
			name:     "regular uid",
			scenario: "regular-uid",
			want:     "not a non-root system identity",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			output, err := runSystemUserScript(t, script, tt.scenario)
			if err == nil {
				t.Fatalf("script error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("script output = %q, want substring %q", output, tt.want)
			}
		})
	}
}

func TestEnsureSystemUserCommandAcceptsMatchingSystemIdentity(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	output, err := runSystemUserScript(t, EnsureSystemUserCommands(names)[0].Args[1], "matching")
	if err != nil {
		t.Fatalf("script error = %v; output:\n%s", err, output)
	}
}

func TestGuardSystemUserCommandRejectsConflictsWithoutCreating(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	script := GuardSystemUserCommand(names).Args[1]

	output, err := runSystemUserGuardScript(t, script, "group-only")
	if err == nil {
		t.Fatalf("guard script error = nil, want group conflict; output:\n%s", output)
	}
	if !strings.Contains(output, "already exists without matching app user") {
		t.Fatalf("guard output = %q, want group conflict", output)
	}

	output, err = runSystemUserGuardScript(t, script, "missing")
	if err != nil {
		t.Fatalf("guard script for missing identity error = %v; output:\n%s", err, output)
	}
}

func TestGuardRootDirectoriesCommandCreatesAndProtectsMarkers(t *testing.T) {
	t.Parallel()

	baseNames, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	names := baseNames
	names.VarLibDir = filepath.Join(dir, "var-lib", "example-app")
	names.EtcDir = filepath.Join(dir, "etc", "example-app")
	names.HookDir = filepath.Join(dir, "hooks", "example-app")
	names.VarLibMarkerPath = filepath.Join(names.VarLibDir, ".lanpanel-managed")
	names.EtcMarkerPath = filepath.Join(names.EtcDir, ".lanpanel-managed")
	names.HookDirMarkerPath = filepath.Join(names.HookDir, ".lanpanel-managed")

	command := GuardRootDirectoriesCommand(names)
	output, err := exec.Command("sh", append([]string{"-c", command.Args[1]}, command.Args[2:]...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("root directory guard error = %v; output:\n%s", err, output)
	}
	for _, marker := range []string{names.VarLibMarkerPath, names.EtcMarkerPath, names.HookDirMarkerPath} {
		content, err := os.ReadFile(marker)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", marker, err)
		}
		if strings.TrimSpace(string(content)) != ManagedMarker(names.AppName) {
			t.Fatalf("marker %s = %q, want %q", marker, content, ManagedMarker(names.AppName))
		}
	}

	foreign := baseNames
	foreign.VarLibDir = filepath.Join(dir, "foreign-var-lib")
	foreign.EtcDir = filepath.Join(dir, "foreign-etc")
	foreign.HookDir = filepath.Join(dir, "foreign-hooks")
	foreign.VarLibMarkerPath = filepath.Join(foreign.VarLibDir, ".lanpanel-managed")
	foreign.EtcMarkerPath = filepath.Join(foreign.EtcDir, ".lanpanel-managed")
	foreign.HookDirMarkerPath = filepath.Join(foreign.HookDir, ".lanpanel-managed")
	if err := os.MkdirAll(foreign.EtcDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(foreign) error = %v", err)
	}
	output, err = exec.Command("sh", append([]string{"-c", GuardRootDirectoriesCommand(foreign).Args[1]}, GuardRootDirectoriesCommand(foreign).Args[2:]...)...).CombinedOutput()
	if err == nil {
		t.Fatalf("root directory guard error = nil, want foreign directory failure; output:\n%s", output)
	}
	if !strings.Contains(string(output), "must be owned by root") {
		t.Fatalf("output = %q, want root ownership refusal", output)
	}
	info, statErr := os.Stat(foreign.EtcDir)
	if statErr != nil {
		t.Fatalf("Stat(foreign.EtcDir) error = %v", statErr)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("foreign dir mode = %o, want unchanged 0700", info.Mode().Perm())
	}

	bootstrap := baseNames
	bootstrap.VarLibDir = filepath.Join(dir, "bootstrap-var-lib")
	bootstrap.EtcDir = filepath.Join(dir, "bootstrap-etc")
	bootstrap.HookDir = filepath.Join(dir, "bootstrap-hooks")
	bootstrap.VarLibMarkerPath = filepath.Join(bootstrap.VarLibDir, ".lanpanel-managed")
	bootstrap.EtcMarkerPath = filepath.Join(bootstrap.EtcDir, ".lanpanel-managed")
	bootstrap.HookDirMarkerPath = filepath.Join(bootstrap.HookDir, ".lanpanel-managed")
	if err := os.MkdirAll(bootstrap.EtcDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(bootstrap etc) error = %v", err)
	}
	authFile := filepath.Join(bootstrap.EtcDir, "goaccess.htpasswd")
	if err := os.WriteFile(authFile, []byte("user:hash\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(authFile) error = %v", err)
	}
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "stat"), `#!/bin/sh
if [ "$1:$2" = "-c:%u" ]; then
    echo 0
    exit 0
fi
exec /usr/bin/stat "$@"
`)
	command = GuardRootDirectoriesWithGoAccessAuthBootstrapCommand(bootstrap, authFile)
	cmd := exec.Command("sh", append([]string{"-c", command.Args[1]}, command.Args[2:]...)...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bootstrap root directory guard error = %v; output:\n%s", err, output)
	}
	content, err := os.ReadFile(bootstrap.EtcMarkerPath)
	if err != nil {
		t.Fatalf("ReadFile(bootstrap marker) error = %v", err)
	}
	if strings.TrimSpace(string(content)) != ManagedMarker(bootstrap.AppName) {
		t.Fatalf("bootstrap marker = %q, want %q", content, ManagedMarker(bootstrap.AppName))
	}

	dualBootstrap := baseNames
	dualBootstrap.VarLibDir = filepath.Join(dir, "dual-bootstrap-var-lib")
	dualBootstrap.EtcDir = filepath.Join(dir, "dual-bootstrap-etc")
	dualBootstrap.HookDir = filepath.Join(dir, "dual-bootstrap-hooks")
	dualBootstrap.VarLibMarkerPath = filepath.Join(dualBootstrap.VarLibDir, ".lanpanel-managed")
	dualBootstrap.EtcMarkerPath = filepath.Join(dualBootstrap.EtcDir, ".lanpanel-managed")
	dualBootstrap.HookDirMarkerPath = filepath.Join(dualBootstrap.HookDir, ".lanpanel-managed")
	dualBootstrap.GoAccessSuggestedAuthBasicUserFile = filepath.Join(dualBootstrap.EtcDir, "goaccess.htpasswd")
	dualBootstrap.BrowserSuggestedAuthBasicUserFile = filepath.Join(dualBootstrap.EtcDir, "browser.htpasswd")
	if err := os.MkdirAll(dualBootstrap.EtcDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(dual bootstrap etc) error = %v", err)
	}
	browserAuthFile := filepath.Join(dualBootstrap.EtcDir, "browser.htpasswd")
	goAccessAuthFile := filepath.Join(dualBootstrap.EtcDir, "goaccess.htpasswd")
	for _, path := range []string{browserAuthFile, goAccessAuthFile} {
		if err := os.WriteFile(path, []byte("user:hash\n"), 0o640); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	command = GuardRootDirectoriesWithAuthBootstrapsCommand(dualBootstrap, browserAuthFile, goAccessAuthFile)
	cmd = exec.Command("sh", append([]string{"-c", command.Args[1]}, command.Args[2:]...)...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dual bootstrap root directory guard error = %v; output:\n%s", err, output)
	}
	content, err = os.ReadFile(dualBootstrap.EtcMarkerPath)
	if err != nil {
		t.Fatalf("ReadFile(dual bootstrap marker) error = %v", err)
	}
	if strings.TrimSpace(string(content)) != ManagedMarker(dualBootstrap.AppName) {
		t.Fatalf("dual bootstrap marker = %q, want %q", content, ManagedMarker(dualBootstrap.AppName))
	}
}

func TestGuardRootDirectoriesGoAccessAuthBootstrapRequiresSuggestedPath(t *testing.T) {
	t.Parallel()

	baseNames, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	names := baseNames
	names.VarLibDir = filepath.Join(dir, "var-lib", "example-app")
	names.EtcDir = filepath.Join(dir, "etc", "example-app")
	names.HookDir = filepath.Join(dir, "hooks", "example-app")
	names.VarLibMarkerPath = filepath.Join(names.VarLibDir, ".lanpanel-managed")
	names.EtcMarkerPath = filepath.Join(names.EtcDir, ".lanpanel-managed")
	names.HookDirMarkerPath = filepath.Join(names.HookDir, ".lanpanel-managed")
	names.GoAccessSuggestedAuthBasicUserFile = filepath.Join(names.EtcDir, "goaccess.htpasswd")

	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "stat"), `#!/bin/sh
if [ "$1:$2" = "-c:%u" ]; then
    echo 0
    exit 0
fi
exec /usr/bin/stat "$@"
`)

	tests := []struct {
		name     string
		authFile string
		rootDir  string
	}{
		{name: "var lib root", authFile: filepath.Join(names.VarLibDir, "goaccess.htpasswd"), rootDir: names.VarLibDir},
		{name: "hook root", authFile: filepath.Join(names.HookDir, "goaccess.htpasswd"), rootDir: names.HookDir},
		{name: "wrong etc file", authFile: filepath.Join(names.EtcDir, "auth.htpasswd"), rootDir: names.EtcDir},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if err := os.MkdirAll(tt.rootDir, 0o755); err != nil {
				t.Fatalf("MkdirAll(root) error = %v", err)
			}
			if err := os.WriteFile(tt.authFile, []byte("user:hash\n"), 0o640); err != nil {
				t.Fatalf("WriteFile(auth file) error = %v", err)
			}
			t.Cleanup(func() {
				_ = os.RemoveAll(tt.rootDir)
			})

			command := GuardRootDirectoriesWithGoAccessAuthBootstrapCommand(names, tt.authFile)
			cmd := exec.Command("sh", append([]string{"-c", command.Args[1]}, command.Args[2:]...)...)
			cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("root directory guard error = nil, want suggested auth path failure; output:\n%s", output)
			}
			if !strings.Contains(string(output), "must be "+names.GoAccessSuggestedAuthBasicUserFile) {
				t.Fatalf("output = %q, want suggested auth path refusal", output)
			}
		})
	}
}

func TestGuardRootDirectoriesCommandFailsClosedOnFindError(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	names.VarLibDir = filepath.Join(dir, "var-lib", "example-app")
	names.EtcDir = filepath.Join(dir, "etc", "example-app")
	names.HookDir = filepath.Join(dir, "hooks", "example-app")
	names.VarLibMarkerPath = filepath.Join(names.VarLibDir, ".lanpanel-managed")
	names.EtcMarkerPath = filepath.Join(names.EtcDir, ".lanpanel-managed")
	names.HookDirMarkerPath = filepath.Join(names.HookDir, ".lanpanel-managed")
	if err := os.MkdirAll(names.VarLibDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(var lib) error = %v", err)
	}
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "stat"), `#!/bin/sh
if [ "$1:$2" = "-c:%u" ]; then
    echo 0
    exit 0
fi
exec /usr/bin/stat "$@"
`)
	writeExecutable(t, filepath.Join(binDir, "find"), "#!/bin/sh\nexit 23\n")

	command := GuardRootDirectoriesCommand(names)
	cmd := exec.Command("sh", append([]string{"-c", command.Args[1]}, command.Args[2:]...)...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("root directory guard error = nil, want find failure; output:\n%s", output)
	}
	if !strings.Contains(string(output), "failed to inspect app root directory") {
		t.Fatalf("output = %q, want find inspection failure", output)
	}
}

func TestGuardServiceAccessCommandChecksAppUserPermissions(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	command := GuardServiceAccessCommand(names, "/opt/example-app/example-app", "/opt/example-app")
	script := command.Args[1]
	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "runuser"), `#!/bin/sh
case "$SCENARIO:$5:$6" in
  binary-denied:-x:/opt/example-app/example-app) exit 1 ;;
  workdir-not-dir:-d:/opt/example-app) exit 1 ;;
  workdir-denied:-x:/opt/example-app) exit 1 ;;
esac
exit 0
`)

	tests := []struct {
		name     string
		scenario string
		want     string
	}{
		{name: "binary denied", scenario: "binary-denied", want: "cannot execute service binary"},
		{name: "working directory missing", scenario: "workdir-not-dir", want: "cannot access working_directory"},
		{name: "working directory denied", scenario: "workdir-denied", want: "cannot enter working_directory"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			output, err := runServiceAccessScript(t, script, dir, tt.scenario)
			if err == nil {
				t.Fatalf("service access guard error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("output = %q, want substring %q", output, tt.want)
			}
		})
	}

	output, err := runServiceAccessScript(t, script, dir, "ok")
	if err != nil {
		t.Fatalf("service access guard error = %v; output:\n%s", err, output)
	}
}

func TestGuardGoAccessAuthFileCommandFailsClosed(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	authDir := t.TempDir()
	if err := os.Chmod(authDir, 0o700); err != nil {
		t.Fatalf("Chmod(authDir) error = %v", err)
	}
	authFile := filepath.Join(authDir, "goaccess.htpasswd")
	if err := os.WriteFile(authFile, []byte("user:hash\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(authFile) error = %v", err)
	}
	worldReadableAuthFile := filepath.Join(authDir, "world-readable.htpasswd")
	if err := os.WriteFile(worldReadableAuthFile, []byte("user:hash\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(worldReadableAuthFile) error = %v", err)
	}
	script := GuardGoAccessAuthFileCommand(names, authFile).Args[1]

	tests := []struct {
		name     string
		authFile string
		scenario string
		want     string
	}{
		{name: "missing runuser", authFile: authFile, scenario: "missing-runuser", want: "runuser is required"},
		{name: "missing nginx user", authFile: authFile, scenario: "missing-nginx-user", want: "nginx runtime user www-data does not exist"},
		{name: "unreadable by nginx user", authFile: authFile, scenario: "unreadable", want: "cannot read nginx.goaccess.auth_basic_user_file"},
		{name: "find error", authFile: authFile, scenario: "find-error", want: "failed to inspect nginx.goaccess.auth_basic_user_file permissions"},
		{name: "world readable", authFile: worldReadableAuthFile, scenario: "real-find", want: "must not be group-writable or accessible by others"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			output, err := runGoAccessAuthGuardScript(t, script, tt.authFile, tt.scenario)
			if err == nil {
				t.Fatalf("auth guard error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("output = %q, want substring %q", output, tt.want)
			}
		})
	}

	output, err := runGoAccessAuthGuardScript(t, script, authFile, "ok")
	if err != nil {
		t.Fatalf("auth guard error = %v; output:\n%s", err, output)
	}

	emptyAuthFile := filepath.Join(authDir, "empty.htpasswd")
	if err := os.WriteFile(emptyAuthFile, nil, 0o640); err != nil {
		t.Fatalf("WriteFile(emptyAuthFile) error = %v", err)
	}
	output, err = runGoAccessAuthGuardScript(t, script, emptyAuthFile, "ok")
	if err == nil {
		t.Fatalf("auth guard error = nil, want empty auth file failure; output:\n%s", output)
	}
	if !strings.Contains(output, "must not be empty") {
		t.Fatalf("output = %q, want empty auth file refusal", output)
	}

	malformedAuthFile := filepath.Join(authDir, "malformed.htpasswd")
	if err := os.WriteFile(malformedAuthFile, []byte("not-a-credential\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(malformedAuthFile) error = %v", err)
	}
	output, err = runGoAccessAuthGuardScript(t, script, malformedAuthFile, "ok")
	if err == nil {
		t.Fatalf("auth guard error = nil, want malformed auth file failure; output:\n%s", output)
	}
	if !strings.Contains(output, "must contain at least one user:hash credential line") {
		t.Fatalf("output = %q, want malformed auth file refusal", output)
	}

	hashWithWhitespaceAuthFile := filepath.Join(authDir, "hash-with-whitespace.htpasswd")
	if err := os.WriteFile(hashWithWhitespaceAuthFile, []byte("user:ha sh\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(hashWithWhitespaceAuthFile) error = %v", err)
	}
	output, err = runGoAccessAuthGuardScript(t, script, hashWithWhitespaceAuthFile, "ok")
	if err == nil {
		t.Fatalf("auth guard error = nil, want whitespace in hash failure; output:\n%s", output)
	}
	if !strings.Contains(output, "must contain at least one user:hash credential line") {
		t.Fatalf("output = %q, want whitespace-in-hash auth file refusal", output)
	}

	writableDir := filepath.Join(filepath.Dir(authFile), "writable")
	if err := os.Mkdir(writableDir, 0o700); err != nil {
		t.Fatalf("Mkdir(writableDir) error = %v", err)
	}
	if err := os.Chmod(writableDir, 0o777); err != nil {
		t.Fatalf("Chmod(writableDir) error = %v", err)
	}
	writableParentAuthFile := filepath.Join(writableDir, "goaccess.htpasswd")
	if err := os.WriteFile(writableParentAuthFile, []byte("user:hash\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(writableParentAuthFile) error = %v", err)
	}
	output, err = runGoAccessAuthGuardScript(t, script, writableParentAuthFile, "writable-parent")
	if err == nil {
		t.Fatalf("auth guard error = nil, want writable parent failure; output:\n%s", output)
	}
	if !strings.Contains(output, "parent directory") || !strings.Contains(output, "must not be writable by group or others") {
		t.Fatalf("output = %q, want writable parent refusal", output)
	}

	stickyAncestorDir := filepath.Join(filepath.Dir(authFile), "sticky")
	if err := os.Mkdir(stickyAncestorDir, 0o755); err != nil {
		t.Fatalf("Mkdir(stickyAncestorDir) error = %v", err)
	}
	if err := os.Chmod(stickyAncestorDir, os.ModeSticky|0o777); err != nil {
		t.Fatalf("Chmod(stickyAncestorDir) error = %v", err)
	}
	stickyChildDir := filepath.Join(stickyAncestorDir, "safe")
	if err := os.Mkdir(stickyChildDir, 0o755); err != nil {
		t.Fatalf("Mkdir(stickyChildDir) error = %v", err)
	}
	stickyAncestorAuthFile := filepath.Join(stickyChildDir, "goaccess.htpasswd")
	if err := os.WriteFile(stickyAncestorAuthFile, []byte("user:hash\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(stickyAncestorAuthFile) error = %v", err)
	}
	output, err = runGoAccessAuthGuardScript(t, script, stickyAncestorAuthFile, "sticky-ancestor")
	if err == nil {
		t.Fatalf("auth guard error = nil, want sticky ancestor failure; output:\n%s", output)
	}
	if !strings.Contains(output, "parent directory") || !strings.Contains(output, "must not be writable by group or others") {
		t.Fatalf("output = %q, want sticky ancestor refusal", output)
	}
}

func TestGuardGoAccessAuthFileMetadataCommandOmitsRuntimeReadability(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	command := GuardGoAccessAuthFileMetadataCommand(names, "/etc/review-app/goaccess.htpasswd")
	if command.DisplayName != "guard-goaccess-auth-file-metadata" {
		t.Fatalf("DisplayName = %q, want guard-goaccess-auth-file-metadata", command.DisplayName)
	}
	script := command.Args[1]
	for _, want := range []string{
		`if [ ! -f "$auth_file" ]; then`,
		`if [ ! -s "$auth_file" ]; then`,
		`must contain at least one user:hash credential line`,
		`stat -c %u "$auth_file"`,
		`find "$auth_file" -maxdepth 0`,
		`-perm -004`,
		`-perm -002`,
		`-perm -001`,
		`parent directory $dir must be owned by root`,
		`parent directory $dir must not be writable by group or others`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("metadata auth guard script missing %q\n%s", want, script)
		}
	}
	for _, omitted := range []string{
		"runuser",
		"getent passwd",
		"nginx runtime user",
		"www-data",
	} {
		if strings.Contains(script, omitted) {
			t.Fatalf("metadata auth guard script contains runtime readability dependency %q\n%s", omitted, script)
		}
	}
}

func TestGuardBrowserAuthFileCommandFailsClosed(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	authDir := t.TempDir()
	if err := os.Chmod(authDir, 0o700); err != nil {
		t.Fatalf("Chmod(authDir) error = %v", err)
	}
	authFile := filepath.Join(authDir, "browser.htpasswd")
	if err := os.WriteFile(authFile, []byte("user:hash\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(authFile) error = %v", err)
	}
	script := GuardBrowserAuthFileCommand(names, authFile).Args[1]

	output, err := runGoAccessAuthGuardScript(t, script, authFile, "unreadable")
	if err == nil {
		t.Fatalf("browser auth guard error = nil, want failure; output:\n%s", output)
	}
	if !strings.Contains(output, "cannot read access.browser_auth htpasswd file") {
		t.Fatalf("output = %q, want browser auth readability failure", output)
	}

	output, err = runGoAccessAuthGuardScript(t, script, authFile, "ok")
	if err != nil {
		t.Fatalf("browser auth guard error = %v; output:\n%s", err, output)
	}
}

func TestGuardManagedBrowserAuthFileCommandRequiresMarkerAndStrongBcrypt(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	authDir := t.TempDir()
	if err := os.Chmod(authDir, 0o700); err != nil {
		t.Fatalf("Chmod(authDir) error = %v", err)
	}
	authFile := filepath.Join(authDir, "browser.htpasswd")
	validHash := "admin:$2y$12$" + strings.Repeat("a", 53)
	if err := os.WriteFile(authFile, []byte("# LanPanel-managed browser-auth\n"+validHash+"\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(authFile) error = %v", err)
	}
	script := GuardManagedBrowserAuthFileCommand(names, authFile).Args[1]

	output, err := runGoAccessAuthGuardScript(t, script, authFile, "ok")
	if err != nil {
		t.Fatalf("managed browser auth guard error = %v; output:\n%s", err, output)
	}

	if err := os.WriteFile(authFile, []byte(validHash+"\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(authFile without marker) error = %v", err)
	}
	output, err = runGoAccessAuthGuardScript(t, script, authFile, "ok")
	if err == nil || !strings.Contains(output, "must keep the LanPanel marker") {
		t.Fatalf("managed browser auth guard output = %q error = %v, want marker failure", output, err)
	}

	if err := os.WriteFile(authFile, []byte("# LanPanel-managed browser-auth\nadmin:$2y$10$"+strings.Repeat("a", 53)+"\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(authFile weak hash) error = %v", err)
	}
	output, err = runGoAccessAuthGuardScript(t, script, authFile, "ok")
	if err == nil || !strings.Contains(output, "bcrypt credential with cost at least 12") {
		t.Fatalf("managed browser auth guard output = %q error = %v, want weak hash failure", output, err)
	}
}

func TestGuardGoAccessCanonicalLogReadableCommandRejectsUnsafeParents(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.Mkdir(logDir, 0o755); err != nil {
		t.Fatalf("Mkdir(logDir) error = %v", err)
	}
	logFile := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(logFile, []byte("log\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(logFile) error = %v", err)
	}
	names.GoAccessCanonicalAccessLogPath = logFile
	script := GuardGoAccessCanonicalLogReadableCommand(names).Args[1]

	output, err := runGoAccessLogReadableScript(t, script, logFile, "ok")
	if err != nil {
		t.Fatalf("log readable guard error = %v; output:\n%s", err, output)
	}

	tests := []struct {
		name     string
		logFile  string
		scenario string
		want     string
	}{
		{
			name:     "writable parent",
			logFile:  logFile,
			scenario: "writable-parent",
			want:     "parent directory " + logDir + " must not be writable by group or others",
		},
		{
			name:     "writable log file",
			logFile:  logFile,
			scenario: "file-writable",
			want:     "GoAccess canonical access log must not be writable by group or others",
		},
		{
			name:     "nonroot log owner",
			logFile:  logFile,
			scenario: "nonroot-log-owner",
			want:     "GoAccess canonical access log must be owned by root or www-data",
		},
		{
			name:     "unreadable by GoAccess user",
			logFile:  logFile,
			scenario: "unreadable",
			want:     "cannot read canonical access log",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			output, err := runGoAccessLogReadableScript(t, script, tt.logFile, tt.scenario)
			if err == nil {
				t.Fatalf("log readable guard error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("output = %q, want substring %q", output, tt.want)
			}
		})
	}

	targetDir := filepath.Join(dir, "target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("Mkdir(targetDir) error = %v", err)
	}
	targetLog := filepath.Join(targetDir, "access.log")
	if err := os.WriteFile(targetLog, []byte("log\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(targetLog) error = %v", err)
	}
	symlinkDir := filepath.Join(dir, "symlink-parent")
	if err := os.Symlink(targetDir, symlinkDir); err != nil {
		t.Fatalf("Symlink(symlinkDir) error = %v", err)
	}
	output, err = runGoAccessLogReadableScript(t, script, filepath.Join(symlinkDir, "access.log"), "ok")
	if err == nil {
		t.Fatalf("log readable guard error = nil, want symlink parent failure; output:\n%s", output)
	}
	if !strings.Contains(output, "parent directory "+symlinkDir+" must not be a symlink") {
		t.Fatalf("output = %q, want symlink parent refusal", output)
	}
}

func TestGuardManagedGoAccessCanonicalLogReadableCommandUsesManagedDirectoryPolicy(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.Mkdir(logDir, 0o775); err != nil {
		t.Fatalf("Mkdir(logDir) error = %v", err)
	}
	logFile := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(logFile, []byte("log\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(logFile) error = %v", err)
	}
	names.GoAccessCanonicalAccessLogPath = logFile
	command := GuardManagedGoAccessCanonicalLogReadableCommand(names)
	if command.DisplayName != "guard-goaccess-managed-log-readable" {
		t.Fatalf("DisplayName = %q, want guard-goaccess-managed-log-readable", command.DisplayName)
	}
	script := command.Args[1]
	if strings.Contains(script, "parent directory") || strings.Contains(script, `stat -c %u "$dir"`) {
		t.Fatalf("managed log readability guard must not enforce explicit-log parent policy\n%s", script)
	}

	output, err := runGoAccessLogReadableScript(t, script, logFile, "writable-parent")
	if err != nil {
		t.Fatalf("managed log readable guard error = %v; output:\n%s", err, output)
	}

	tests := []struct {
		name     string
		scenario string
		want     string
	}{
		{name: "writable log file", scenario: "file-writable", want: "GoAccess canonical access log must not be writable by group or others"},
		{name: "unreadable by GoAccess user", scenario: "unreadable", want: "cannot read canonical access log"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			output, err := runGoAccessLogReadableScript(t, script, logFile, tt.scenario)
			if err == nil {
				t.Fatalf("managed log readable guard error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("output = %q, want substring %q", output, tt.want)
			}
		})
	}
}

func TestGuardGoAccessLogDirectoryCommandRejectsWritableMarker(t *testing.T) {
	t.Parallel()

	baseNames, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	names := baseNames
	names.GoAccessLogDir = filepath.Join(dir, "logs")
	names.GoAccessLogDirMarkerPath = filepath.Join(names.GoAccessLogDir, ".lanpanel-managed")
	if err := os.MkdirAll(names.GoAccessLogDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(log dir) error = %v", err)
	}
	if err := os.WriteFile(names.GoAccessLogDirMarkerPath, []byte(ManagedMarker(names.AppName)+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(marker) error = %v", err)
	}
	script := GuardGoAccessLogDirectoryCommand(names).Args[1]

	output, err := runGoAccessLogDirectoryGuardScript(t, script, names, "ok")
	if err != nil {
		t.Fatalf("log guard error = %v; output:\n%s", err, output)
	}

	output, err = runGoAccessLogDirectoryGuardScript(t, script, names, "find-error")
	if err == nil {
		t.Fatalf("log guard error = nil, want find failure; output:\n%s", output)
	}
	if !strings.Contains(output, "failed to inspect GoAccess log directory") {
		t.Fatalf("output = %q, want find inspection failure", output)
	}

	for _, scenario := range []string{"marker-group-writable", "marker-world-writable"} {
		scenario := scenario
		t.Run(scenario, func(t *testing.T) {
			output, err := runGoAccessLogDirectoryGuardScript(t, script, names, scenario)
			if err == nil {
				t.Fatalf("log guard error = nil, want writable marker failure; output:\n%s", output)
			}
			if !strings.Contains(output, "GoAccess log marker") || !strings.Contains(output, "must not be writable") {
				t.Fatalf("output = %q, want writable marker refusal", output)
			}
		})
	}
}

func TestRemoveManagedGoAccessRuntimeCommandRemovesOnlyManagedFiles(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	unitPath := filepath.Join(dir, names.GoAccessServiceUnit)
	names.GoAccessConfigPath = filepath.Join(dir, "goaccess.conf")
	names.GoAccessLogrotatePath = filepath.Join(dir, "goaccess-logrotate")
	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if err := os.WriteFile(path, []byte("# "+ManagedMarker(names.AppName)+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	binDir := t.TempDir()
	systemctlLog := filepath.Join(dir, "systemctl.log")
	writeExecutable(t, filepath.Join(binDir, "systemctl"), "#!/bin/sh\nprintf '%s\\n' \"$*\" > "+systemctlLog+"\n")

	guardCommand := guardManagedGoAccessRuntimeRemovalCommand(names, unitPath)
	guardArgs := append([]string{"-c", guardCommand.Args[1]}, guardCommand.Args[2:]...)
	guardCmd := exec.Command("sh", guardArgs...)
	guardCmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err := guardCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("guard GoAccess runtime removal error = %v; output:\n%s", err, output)
	}
	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("Lstat(%s) error = %v, want managed file retained by guard", path, err)
		}
	}
	if _, err := os.Lstat(systemctlLog); !os.IsNotExist(err) {
		t.Fatalf("Lstat(systemctl log) error = %v, want no disable from guard", err)
	}

	command := removeManagedGoAccessRuntimeCommand(names, unitPath)
	args := append([]string{"-c", command.Args[1]}, command.Args[2:]...)
	cmd := exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("remove GoAccess runtime error = %v; output:\n%s", err, output)
	}
	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if !strings.Contains(string(output), path) {
			t.Fatalf("output = %q, want removed path %s", output, path)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("Lstat(%s) error = %v, want not exist", path, err)
		}
	}
	systemctlOutput, err := os.ReadFile(systemctlLog)
	if err != nil {
		t.Fatalf("ReadFile(systemctl log) error = %v", err)
	}
	if strings.TrimSpace(string(systemctlOutput)) != "disable --now "+names.GoAccessServiceUnit {
		t.Fatalf("systemctl log = %q, want disable --now", systemctlOutput)
	}

	if err := os.Remove(systemctlLog); err != nil {
		t.Fatalf("Remove(systemctl log) error = %v", err)
	}
	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if err := os.WriteFile(path, []byte("# foreign file\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	cmd = exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("remove GoAccess runtime with foreign files error = nil, want refusal; output:\n%s", output)
	}
	if !strings.Contains(string(output), "not a Lanpanel-managed GoAccess") {
		t.Fatalf("output = %q, want foreign GoAccess runtime refusal", output)
	}
	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("Lstat(%s) error = %v, want foreign file retained", path, err)
		}
	}
	if _, err := os.Lstat(systemctlLog); !os.IsNotExist(err) {
		t.Fatalf("Lstat(systemctl log) error = %v, want no disable for foreign unit", err)
	}

	if err := os.Remove(systemctlLog); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Remove(systemctl log) error = %v", err)
	}
	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if err := os.WriteFile(path, []byte("# "+ManagedMarker(names.AppName)+"\n# "+ManagedMarker("other-app")+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s mixed marker) error = %v", path, err)
		}
	}
	cmd = exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("remove GoAccess runtime with mixed markers error = nil, want refusal; output:\n%s", output)
	}
	if !strings.Contains(string(output), "not a Lanpanel-managed GoAccess") {
		t.Fatalf("output = %q, want mixed marker refusal", output)
	}
	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("Lstat(%s) error = %v, want mixed marker file retained", path, err)
		}
	}
	if _, err := os.Lstat(systemctlLog); !os.IsNotExist(err) {
		t.Fatalf("Lstat(systemctl log) error = %v, want no disable for mixed marker unit", err)
	}

	for _, path := range []string{unitPath, names.GoAccessConfigPath, names.GoAccessLogrotatePath} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("Remove(%s) error = %v", path, err)
		}
	}
	for _, path := range []string{unitPath, names.GoAccessLogrotatePath} {
		if err := os.WriteFile(path, []byte("# "+ManagedMarker(names.AppName)+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "missing-target"), names.GoAccessConfigPath); err != nil {
		t.Fatalf("Symlink(broken config) error = %v", err)
	}
	cmd = exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("remove GoAccess runtime with symlink error = nil, want refusal; output:\n%s", output)
	}
	if !strings.Contains(string(output), "is a symlink; refusing to remove it as Lanpanel-managed GoAccess config") {
		t.Fatalf("output = %q, want symlink refusal", output)
	}
	if info, err := os.Lstat(names.GoAccessConfigPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat(config symlink) = %#v, %v; want retained symlink", info, err)
	}
}

func TestRemoveManagedGoAccessLogrotateCommandRemovesOnlyManagedFile(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	names.GoAccessLogrotatePath = filepath.Join(dir, "goaccess-logrotate")
	if err := os.WriteFile(names.GoAccessLogrotatePath, []byte("# "+ManagedMarker(names.AppName)+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(logrotate) error = %v", err)
	}

	guardCommand := GuardManagedGoAccessLogrotateRemovalCommand(names)
	guardArgs := append([]string{"-c", guardCommand.Args[1]}, guardCommand.Args[2:]...)
	cmd := exec.Command("sh", guardArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("guard GoAccess logrotate removal error = %v; output:\n%s", err, output)
	}
	if _, err := os.Lstat(names.GoAccessLogrotatePath); err != nil {
		t.Fatalf("Lstat(logrotate) error = %v, want managed file retained by guard", err)
	}

	command := RemoveManagedGoAccessLogrotateCommand(names)
	args := append([]string{"-c", command.Args[1]}, command.Args[2:]...)
	cmd = exec.Command("sh", args...)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("remove GoAccess logrotate error = %v; output:\n%s", err, output)
	}
	if !strings.Contains(string(output), names.GoAccessLogrotatePath) {
		t.Fatalf("output = %q, want removed path %s", output, names.GoAccessLogrotatePath)
	}
	if _, err := os.Lstat(names.GoAccessLogrotatePath); !os.IsNotExist(err) {
		t.Fatalf("Lstat(logrotate) error = %v, want not exist", err)
	}

	if err := os.WriteFile(names.GoAccessLogrotatePath, []byte("# foreign file\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(foreign logrotate) error = %v", err)
	}
	cmd = exec.Command("sh", args...)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("remove GoAccess logrotate error = nil, want foreign file failure; output:\n%s", output)
	}
	if !strings.Contains(string(output), "not a Lanpanel-managed GoAccess logrotate file") {
		t.Fatalf("output = %q, want foreign file refusal", output)
	}

	if err := os.WriteFile(names.GoAccessLogrotatePath, []byte("# "+ManagedMarker(names.AppName)+"\n# "+ManagedMarker("other-app")+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(mixed logrotate) error = %v", err)
	}
	cmd = exec.Command("sh", args...)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("remove GoAccess logrotate error = nil, want mixed marker failure; output:\n%s", output)
	}
	if !strings.Contains(string(output), "not a Lanpanel-managed GoAccess logrotate file") {
		t.Fatalf("output = %q, want mixed marker refusal", output)
	}

	if err := os.Remove(names.GoAccessLogrotatePath); err != nil {
		t.Fatalf("Remove(mixed logrotate) error = %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing-target"), names.GoAccessLogrotatePath); err != nil {
		t.Fatalf("Symlink(logrotate) error = %v", err)
	}
	cmd = exec.Command("sh", args...)
	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("remove GoAccess logrotate error = nil, want symlink failure; output:\n%s", output)
	}
	if !strings.Contains(string(output), "is a symlink") {
		t.Fatalf("output = %q, want symlink refusal", output)
	}
}

func TestGuardGoAccessRuntimeAccessCommandFailsWithPathAndIdentity(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	names.GoAccessConfigPath = filepath.Join(dir, "goaccess.conf")
	names.GoAccessReportDir = filepath.Join(dir, "goaccess")
	names.GoAccessDBPath = filepath.Join(dir, "goaccess", "db")
	names.GoAccessReportPath = filepath.Join(dir, "goaccess", "report.html")
	command := GuardGoAccessRuntimeAccessCommand(names)
	if command.DisplayName != "guard-goaccess-runtime-access" {
		t.Fatalf("DisplayName = %q, want guard-goaccess-runtime-access", command.DisplayName)
	}
	script := command.Args[1]
	for _, want := range []string{
		`if [ -L "$config_file" ]; then`,
		`if [ ! -f "$config_file" ]; then`,
		`stat -c %u "$config_file"`,
		`stat -c %a "$config_file"`,
		`guard_root_owned_safe_parents "$config_file" "GoAccess config file"`,
		`runuser -u "$goaccess_user" -- test -r "$config_file"`,
		`stat -c %U:%G "$report_dir"`,
		`stat -c %a "$report_dir"`,
		`if runuser -u "$goaccess_user" -- test -w "$report_dir"; then`,
		`runuser -u "$nginx_user" -- test -r "$report_dir"`,
		`runuser -u "$nginx_user" -- test -x "$report_dir"`,
		`if [ -L "$db_path" ]; then`,
		`if [ ! -d "$db_path" ]; then`,
		`stat -c %U:%G "$db_path"`,
		`stat -c %a "$db_path"`,
		`runuser -u "$goaccess_user" -- test -w "$db_path"`,
		`if [ -L "$report_file" ]; then`,
		`if [ ! -f "$report_file" ]; then`,
		`stat -c %U:%G "$report_file"`,
		`stat -c %a "$report_file"`,
		`runuser -u "$goaccess_user" -- test -w "$report_file"`,
		`runuser -u "$nginx_user" -- test -r "$report_file"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("runtime access script missing %q\n%s", want, script)
		}
	}

	tests := []struct {
		name     string
		scenario string
		wantUser string
		wantPath string
	}{
		{
			name:     "config unreadable by GoAccess user",
			scenario: "config-unreadable",
			wantUser: names.GoAccessSystemUser,
			wantPath: names.GoAccessConfigPath,
		},
		{
			name:     "config symlink",
			scenario: "config-symlink",
			wantUser: "",
			wantPath: names.GoAccessConfigPath,
		},
		{
			name:     "config non-regular",
			scenario: "config-dir",
			wantUser: "",
			wantPath: names.GoAccessConfigPath,
		},
		{
			name:     "config wrong owner",
			scenario: "config-wrong-owner",
			wantUser: "",
			wantPath: names.GoAccessConfigPath,
		},
		{
			name:     "config unsafe mode",
			scenario: "config-unsafe-mode",
			wantUser: "",
			wantPath: names.GoAccessConfigPath,
		},
		{
			name:     "config writable parent",
			scenario: "config-writable-parent",
			wantUser: "",
			wantPath: filepath.Dir(names.GoAccessConfigPath),
		},
		{
			name:     "report directory writable by GoAccess user",
			scenario: "report-dir-writable",
			wantUser: names.GoAccessSystemUser,
			wantPath: names.GoAccessReportDir,
		},
		{
			name:     "report directory wrong owner",
			scenario: "report-dir-wrong-owner",
			wantUser: "",
			wantPath: names.GoAccessReportDir,
		},
		{
			name:     "report directory unsafe mode",
			scenario: "report-dir-unsafe-mode",
			wantUser: "",
			wantPath: names.GoAccessReportDir,
		},
		{
			name:     "report directory unreadable by nginx user",
			scenario: "report-dir-unreadable-nginx",
			wantUser: "www-data",
			wantPath: names.GoAccessReportDir,
		},
		{
			name:     "db path unwritable by GoAccess user",
			scenario: "db-unwritable",
			wantUser: names.GoAccessSystemUser,
			wantPath: names.GoAccessDBPath,
		},
		{
			name:     "db path symlink",
			scenario: "db-symlink",
			wantUser: "",
			wantPath: names.GoAccessDBPath,
		},
		{
			name:     "db path non-directory",
			scenario: "db-file",
			wantUser: "",
			wantPath: names.GoAccessDBPath,
		},
		{
			name:     "db path wrong owner",
			scenario: "db-wrong-owner",
			wantUser: names.GoAccessSystemUser,
			wantPath: names.GoAccessDBPath,
		},
		{
			name:     "db path unsafe mode",
			scenario: "db-unsafe-mode",
			wantUser: "",
			wantPath: names.GoAccessDBPath,
		},
		{
			name:     "report file symlink",
			scenario: "report-file-symlink",
			wantUser: "",
			wantPath: names.GoAccessReportPath,
		},
		{
			name:     "report file unwritable by GoAccess user",
			scenario: "report-file-unwritable",
			wantUser: names.GoAccessSystemUser,
			wantPath: names.GoAccessReportPath,
		},
		{
			name:     "report file wrong owner",
			scenario: "report-file-wrong-owner",
			wantUser: names.GoAccessSystemUser,
			wantPath: names.GoAccessReportPath,
		},
		{
			name:     "report file unsafe mode",
			scenario: "report-file-unsafe-mode",
			wantUser: "",
			wantPath: names.GoAccessReportPath,
		},
		{
			name:     "report file unreadable by nginx user",
			scenario: "report-file-unreadable",
			wantUser: "www-data",
			wantPath: names.GoAccessReportPath,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			output, err := runGoAccessRuntimeAccessScript(t, command, tt.scenario)
			if err == nil {
				t.Fatalf("runtime access guard error = nil, want failure; output:\n%s", output)
			}
			if tt.wantUser != "" && !strings.Contains(output, tt.wantUser) {
				t.Fatalf("output = %q, want user %q", output, tt.wantUser)
			}
			if !strings.Contains(output, tt.wantPath) {
				t.Fatalf("output = %q, want user %q and path %q", output, tt.wantUser, tt.wantPath)
			}
		})
	}

	output, err := runGoAccessRuntimeAccessScript(t, command, "ok")
	if err != nil {
		t.Fatalf("runtime access guard error = %v; output:\n%s", err, output)
	}
}

func TestEnsureGoAccessDirectoryCommandsSplitsRuntimePermissions(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}

	commands := EnsureGoAccessDirectoryCommands(names, true)
	if len(commands) != 4 {
		t.Fatalf("len(EnsureGoAccessDirectoryCommands) = %d, want 4", len(commands))
	}

	reportDirScript := commands[0].Args[1]
	for _, want := range []string{
		`if [ -L "$report_dir" ]; then`,
		`install -d -m 0755 -o root -g root "$report_dir"`,
		`chown root:root "$report_dir"`,
		`chmod 0755 "$report_dir"`,
	} {
		if !strings.Contains(reportDirScript, want) {
			t.Fatalf("report dir script missing %q\n%s", want, reportDirScript)
		}
	}

	dbDirScript := commands[1].Args[1]
	for _, want := range []string{
		`if [ -L "$db_dir" ]; then`,
		`install -d -m 0750 -o "$goaccess_user" -g "$goaccess_group" "$db_dir"`,
		`chown "$goaccess_user:$goaccess_group" "$db_dir"`,
		`chmod 0750 "$db_dir"`,
	} {
		if !strings.Contains(dbDirScript, want) {
			t.Fatalf("db dir script missing %q\n%s", want, dbDirScript)
		}
	}

	reportScript := commands[2].Args[1]
	for _, want := range []string{
		`if [ -L "$report_file" ]; then`,
		`install -m 0640 -o "$goaccess_user" -g "$nginx_group" /dev/null "$report_file"`,
		`chown "$goaccess_user:$nginx_group" "$report_file"`,
		`chmod 0640 "$report_file"`,
	} {
		if !strings.Contains(reportScript, want) {
			t.Fatalf("report file script missing %q\n%s", want, reportScript)
		}
	}

	logScript := commands[3].Args[1]
	for _, want := range []string{
		`ensure_safe_parent "$lanpanel_log_root"`,
		`ensure_safe_parent "$apps_log_root"`,
		`must be searchable by others`,
		`if [ -L "$log_dir" ]; then`,
		`if [ -L "$marker" ]; then`,
		`if [ "$(stat -c %u "$log_dir")" != "0" ]; then`,
		`if [ -L "$log_file" ]; then`,
		`if [ -e "$log_file" ] && [ ! -f "$log_file" ]; then`,
		`install -d -m 0751 -o root -g root "$log_dir"`,
		`chown root:root "$log_dir"`,
		`chmod 0751 "$log_dir"`,
	} {
		if !strings.Contains(logScript, want) {
			t.Fatalf("managed log script missing %q\n%s", want, logScript)
		}
	}
}

func TestEnsureGoAccessLogDirectoryCommandRejectsUnsafeManagedPaths(t *testing.T) {
	t.Parallel()

	baseNames, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T, names Names)
		want    string
	}{
		{
			name: "log directory symlink",
			prepare: func(t *testing.T, names Names) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatalf("Mkdir(target) error = %v", err)
				}
				if err := os.Symlink(target, names.GoAccessLogDir); err != nil {
					t.Fatalf("Symlink(log dir) error = %v", err)
				}
			},
			want: "is a symlink",
		},
		{
			name: "marker symlink",
			prepare: func(t *testing.T, names Names) {
				t.Helper()
				if err := os.Mkdir(names.GoAccessLogDir, 0o755); err != nil {
					t.Fatalf("Mkdir(log dir) error = %v", err)
				}
				target := filepath.Join(t.TempDir(), "marker-target")
				if err := os.WriteFile(target, []byte(ManagedMarker(names.AppName)+"\n"), 0o644); err != nil {
					t.Fatalf("WriteFile(marker target) error = %v", err)
				}
				if err := os.Symlink(target, names.GoAccessLogDirMarkerPath); err != nil {
					t.Fatalf("Symlink(marker) error = %v", err)
				}
			},
			want: "refusing to trust GoAccess log ownership",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			names := baseNames
			names.GoAccessLogDir = filepath.Join(dir, "logs")
			names.GoAccessLogDirMarkerPath = filepath.Join(names.GoAccessLogDir, ".lanpanel-managed")
			names.GoAccessCanonicalAccessLogPath = filepath.Join(names.GoAccessLogDir, "access.log")
			tt.prepare(t, names)

			command := EnsureGoAccessDirectoryCommands(names, true)[3]
			output, err := runEnsureGoAccessLogDirectoryScript(t, command.Args[1], names)
			if err == nil {
				t.Fatalf("ensure log script error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("output = %q, want substring %q", output, tt.want)
			}
		})
	}
}

func TestEnsureGoAccessLogDirectoryCommandRejectsUnsafeManagedParents(t *testing.T) {
	t.Parallel()

	baseNames, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dir := t.TempDir()
	names := baseNames
	names.GoAccessLogDir = filepath.Join(dir, "lanpanel", "apps", "example-app")
	names.GoAccessLogDirMarkerPath = filepath.Join(names.GoAccessLogDir, ".lanpanel-managed")
	names.GoAccessCanonicalAccessLogPath = filepath.Join(names.GoAccessLogDir, "access.log")
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "lanpanel")); err != nil {
		t.Fatalf("Symlink(lanpanel parent) error = %v", err)
	}

	command := EnsureGoAccessDirectoryCommands(names, true)[3]
	output, err := runEnsureGoAccessLogDirectoryScript(t, command.Args[1], names)
	if err == nil {
		t.Fatalf("ensure log script error = nil, want symlinked parent failure; output:\n%s", output)
	}
	if !strings.Contains(output, "is a symlink") || !strings.Contains(output, "log parent") {
		t.Fatalf("output = %q, want symlinked parent refusal", output)
	}
}

func TestEnsureGoAccessLogDirectoryCommandRejectsUnsafeExistingLogFile(t *testing.T) {
	t.Parallel()

	baseNames, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T, path string)
		want    string
	}{
		{
			name: "symlink",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("log\n"), 0o600); err != nil {
					t.Fatalf("WriteFile(target) error = %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			},
			want: "must not be a symlink",
		},
		{
			name: "directory",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatalf("Mkdir(log path) error = %v", err)
				}
			},
			want: "must be a regular file",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			names := baseNames
			names.GoAccessLogDir = filepath.Join(dir, "logs")
			names.GoAccessLogDirMarkerPath = filepath.Join(names.GoAccessLogDir, ".lanpanel-managed")
			names.GoAccessCanonicalAccessLogPath = filepath.Join(names.GoAccessLogDir, "access.log")
			if err := os.MkdirAll(names.GoAccessLogDir, 0o755); err != nil {
				t.Fatalf("MkdirAll(log dir) error = %v", err)
			}
			if err := os.WriteFile(names.GoAccessLogDirMarkerPath, []byte(ManagedMarker(names.AppName)+"\n"), 0o644); err != nil {
				t.Fatalf("WriteFile(marker) error = %v", err)
			}
			tt.prepare(t, names.GoAccessCanonicalAccessLogPath)

			command := EnsureGoAccessDirectoryCommands(names, true)[3]
			output, err := runEnsureGoAccessLogDirectoryScript(t, command.Args[1], names)
			if err == nil {
				t.Fatalf("ensure log script error = nil, want failure; output:\n%s", output)
			}
			if !strings.Contains(output, tt.want) {
				t.Fatalf("output = %q, want substring %q", output, tt.want)
			}
		})
	}
}

func TestValidateGoAccessAccessControlsRejectsBypasses(t *testing.T) {
	t.Parallel()

	goaccess := appconfig.NginxGoAccessConfig{
		AuthBasicUserFile: "/etc/example-app/goaccess.htpasswd",
		AuthCIDRAllowlist: []string{"203.0.113.0/24"},
	}
	validBlock := `location = /_lanpanel/apps/example-app/goaccess {
        satisfy all;
        auth_basic "Lanpanel GoAccess";
        auth_basic_user_file /etc/example-app/goaccess.htpasswd;
        allow 203.0.113.0/24;
        deny all;
    }`
	if got := validateGoAccessAccessControlErrors(validBlock, goaccess); got != "" {
		t.Fatalf("valid access controls errors = %q", got)
	}

	tests := []struct {
		name  string
		block string
		want  string
	}{
		{
			name:  "satisfy any bypass",
			block: strings.Replace(validBlock, "deny all;", "satisfy any;\n        deny all;", 1),
			want:  "must require both basic auth and CIDR allowlist checks",
		},
		{
			name:  "satisfy any whitespace bypass",
			block: strings.Replace(validBlock, "deny all;", "satisfy    any ;\n        deny all;", 1),
			want:  "must require both basic auth and CIDR allowlist checks",
		},
		{
			name:  "satisfy any line wrapped bypass",
			block: strings.Replace(validBlock, "deny all;", "satisfy\n            any;\n        deny all;", 1),
			want:  "must require both basic auth and CIDR allowlist checks",
		},
		{
			name:  "basic auth disabled",
			block: strings.Replace(validBlock, `auth_basic "Lanpanel GoAccess";`, "auth_basic off;", 1),
			want:  "must not disable basic auth",
		},
		{
			name:  "missing explicit satisfy all",
			block: strings.Replace(validBlock, "        satisfy all;\n", "", 1),
			want:  "satisfy all missing",
		},
		{
			name:  "commented satisfy all",
			block: strings.Replace(validBlock, "        satisfy all;", "        # satisfy all;", 1),
			want:  "satisfy all missing",
		},
		{
			name:  "commented basic auth",
			block: strings.Replace(validBlock, `        auth_basic "Lanpanel GoAccess";`, `        # auth_basic "Lanpanel GoAccess";`, 1),
			want:  "basic auth missing",
		},
		{
			name:  "commented auth file",
			block: strings.Replace(validBlock, "        auth_basic_user_file /etc/example-app/goaccess.htpasswd;", "        # auth_basic_user_file /etc/example-app/goaccess.htpasswd;", 1),
			want:  "auth_basic_user_file missing",
		},
		{
			name:  "extra allow",
			block: strings.Replace(validBlock, "deny all;", "allow all;\n        deny all;", 1),
			want:  "CIDR allow/deny directives must exactly match",
		},
		{
			name:  "extra allow tab whitespace",
			block: strings.Replace(validBlock, "deny all;", "allow\tall;\n        deny all;", 1),
			want:  "CIDR allow/deny directives must exactly match",
		},
		{
			name:  "extra allow line wrapped",
			block: strings.Replace(validBlock, "deny all;", "allow\n            all;\n        deny all;", 1),
			want:  "CIDR allow/deny directives must exactly match",
		},
		{
			name:  "missing deny",
			block: strings.Replace(validBlock, "        deny all;\n", "", 1),
			want:  "CIDR allow/deny directives must exactly match",
		},
		{
			name: "allow without configured allowlist",
			block: `location = /_lanpanel/apps/example-app/goaccess {
        satisfy all;
        auth_basic "Lanpanel GoAccess";
        auth_basic_user_file /etc/example-app/goaccess.htpasswd;
        allow all;
    }`,
			want: "CIDR allow/deny directives must exactly match",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cfg := goaccess
			if tt.name == "allow without configured allowlist" {
				cfg.AuthCIDRAllowlist = nil
			}
			if got := validateGoAccessAccessControlErrors(tt.block, cfg); !strings.Contains(got, tt.want) {
				t.Fatalf("errors = %q, want substring %q", got, tt.want)
			}
		})
	}
}

func TestValidateGoAccessNginxRejectsNestedAllowDeny(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"203.0.113.0/24"}
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dashboardGuard := `if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`
	websocketGuard := `if ($host != "abc.com") {
            return 421;
        }`
	text, httpBlock, httpsBlock := minimalGoAccessNginxText(names, dashboardGuard, websocketGuard)
	allowDeny := "	        allow 203.0.113.0/24;\n	        deny all;"
	httpsBlock = strings.ReplaceAll(httpsBlock,
		"	        auth_basic_user_file /etc/example-app/goaccess.htpasswd;\n	        access_log off;",
		"	        auth_basic_user_file /etc/example-app/goaccess.htpasswd;\n"+allowDeny+"\n	        access_log off;",
	)
	var validErrs []string
	validateGoAccessNginx(&validErrs, text, httpBlock, httpsBlock, cfg, names)
	if len(validErrs) != 0 {
		t.Fatalf("valid GoAccess Nginx errors = %v", validErrs)
	}
	websocketAllowDenyIndex := strings.LastIndex(httpsBlock, allowDeny)
	if websocketAllowDenyIndex < 0 {
		t.Fatalf("websocket allow/deny block not found in test fixture")
	}

	nestedAllowDeny := "	        if ($arg_debug) {\n	            allow 203.0.113.0/24;\n	            deny all;\n	        }"
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "dashboard",
			text: strings.Replace(httpsBlock, allowDeny, nestedAllowDeny, 1),
			want: "GoAccess dashboard CIDR allow/deny directives must exactly match",
		},
		{
			name: "websocket",
			text: httpsBlock[:websocketAllowDenyIndex] + nestedAllowDeny + httpsBlock[websocketAllowDenyIndex+len(allowDeny):],
			want: "GoAccess WebSocket CIDR allow/deny directives must exactly match",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var errs []string
			validateGoAccessNginx(&errs, text, httpBlock, tt.text, cfg, names)
			if !strings.Contains(strings.Join(errs, "; "), tt.want) {
				t.Fatalf("errors = %v, want substring %q", errs, tt.want)
			}
		})
	}
}

func TestValidateGoAccessNginxRejectsParentSatisfyAny(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dashboardGuard := `if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`
	websocketGuard := `if ($host != "abc.com") {
            return 421;
        }`
	validText, httpBlock, httpsBlock := minimalGoAccessNginxText(names, dashboardGuard, websocketGuard)

	tests := []struct {
		name       string
		text       string
		httpBlock  string
		httpsBlock string
	}{
		{
			name:       "http context",
			text:       "satisfy any;\n" + validText,
			httpBlock:  httpBlock,
			httpsBlock: httpsBlock,
		},
		{
			name:       "https server context",
			text:       strings.Replace(validText, "    access_log "+names.GoAccessCanonicalAccessLogPath+" "+names.GoAccessNginxLogFormatName+";", "    access_log "+names.GoAccessCanonicalAccessLogPath+" "+names.GoAccessNginxLogFormatName+";\n    satisfy any;", 1),
			httpBlock:  httpBlock,
			httpsBlock: strings.Replace(httpsBlock, "    access_log "+names.GoAccessCanonicalAccessLogPath+" "+names.GoAccessNginxLogFormatName+";", "    access_log "+names.GoAccessCanonicalAccessLogPath+" "+names.GoAccessNginxLogFormatName+";\n    satisfy any;", 1),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var errs []string
			validateGoAccessNginx(&errs, tt.text, tt.httpBlock, tt.httpsBlock, cfg, names)
			if !strings.Contains(strings.Join(errs, "; "), "GoAccess Nginx must not render satisfy any") {
				t.Fatalf("errors = %v, want parent satisfy any failure", errs)
			}
		})
	}
}

func TestValidateGoAccessNginxRejectsExtraServerAccessLog(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dashboardGuard := `if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`
	websocketGuard := `if ($host != "abc.com") {
            return 421;
        }`
	for _, tt := range []struct {
		name string
		http bool
		want string
	}{
		{name: "http", http: true, want: "GoAccess HTTP server contains unexpected access_log directive"},
		{name: "https", want: "GoAccess HTTPS server contains unexpected access_log directive"},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, httpBlock, httpsBlock := minimalGoAccessNginxText(names, dashboardGuard, websocketGuard)
			if tt.http {
				httpBlock = strings.Replace(httpBlock, "    location = /_lanpanel/apps/example-app/goaccess {", "    access_log\t/var/log/nginx/example-app.extra.log;\n\n    location = /_lanpanel/apps/example-app/goaccess {", 1)
			} else {
				httpsBlock = strings.Replace(httpsBlock, "    location = /_lanpanel/apps/example-app/goaccess {", "    access_log\t/var/log/nginx/example-app.extra.log;\n\n    location = /_lanpanel/apps/example-app/goaccess {", 1)
			}
			text := goAccessEnhancedLogFormatDirective(names) + "\n" + httpBlock + "\n" + httpsBlock

			var errs []string
			validateGoAccessNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
			if !strings.Contains(strings.Join(errs, "; "), tt.want) {
				t.Fatalf("errors = %v, want extra server access_log failure %q", errs, tt.want)
			}
		})
	}
}

func TestValidateGoAccessNginxRequiresDirectWebSocketHTTP11(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dashboardGuard := `if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`
	websocketGuard := `if ($host != "abc.com") {
            return 421;
        }`

	tests := []struct {
		name        string
		replacement string
	}{
		{
			name:        "commented",
			replacement: "        # proxy_http_version 1.1;\n",
		},
		{
			name:        "nested",
			replacement: "        if ($host = \"abc.com\") {\n            proxy_http_version 1.1;\n        }\n",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			text, httpBlock, httpsBlock := minimalGoAccessNginxText(names, dashboardGuard, websocketGuard)
			text = strings.Replace(text, "        proxy_http_version 1.1;\n", tt.replacement, 1)
			httpsBlock = strings.Replace(httpsBlock, "        proxy_http_version 1.1;\n", tt.replacement, 1)

			var errs []string
			validateGoAccessNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
			if !strings.Contains(strings.Join(errs, "; "), "GoAccess WebSocket HTTP/1.1 proxy missing") {
				t.Fatalf("errors = %v, want missing WebSocket HTTP/1.1 failure", errs)
			}
		})
	}
}

func TestValidateGoAccessNginxIgnoresCommentedGoAccessDirectives(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dashboardGuard := `if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`
	websocketGuard := `if ($host != "abc.com") {
            return 421;
        }`

	tests := []struct {
		name   string
		mutate func(text string, httpBlock string, httpsBlock string) (string, string, string)
		want   string
	}{
		{
			name: "commented dashboard auth",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := `auth_basic "Lanpanel GoAccess";`
				new := `# auth_basic "Lanpanel GoAccess";`
				return strings.Replace(text, old, new, 1), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess dashboard basic auth missing",
		},
		{
			name: "commented dashboard default type",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "default_type text/html;"
				new := "# default_type text/html;"
				return strings.Replace(text, old, new, 1), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess dashboard default_type missing",
		},
		{
			name: "commented dashboard disable symlinks",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "disable_symlinks on;"
				new := "# disable_symlinks on;"
				return strings.Replace(text, old, new, 1), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess dashboard disable_symlinks missing",
		},
		{
			name: "commented dashboard access log off",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "access_log off;"
				new := "# access_log off;"
				return strings.Replace(text, old, new, 3), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess dashboard access_log off missing",
		},
		{
			name: "commented websocket upgrade header",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "proxy_set_header Upgrade $http_upgrade;"
				new := "# proxy_set_header Upgrade $http_upgrade;"
				return strings.Replace(text, old, new, 1), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess WebSocket Upgrade header missing",
		},
		{
			name: "commented websocket connection header",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "proxy_set_header Connection $" + names.VarPrefix + "_connection_upgrade;"
				new := "# proxy_set_header Connection $" + names.VarPrefix + "_connection_upgrade;"
				return strings.Replace(text, old, new, 1), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess WebSocket Connection header missing",
		},
		{
			name: "commented websocket forwarded host",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "proxy_set_header X-Forwarded-Host $" + names.VarPrefix + "_validated_host;"
				new := "# proxy_set_header X-Forwarded-Host $" + names.VarPrefix + "_validated_host;"
				return strings.Replace(text, old, new, 1), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess WebSocket validated X-Forwarded-Host forwarding missing",
		},
		{
			name: "commented websocket read timeout",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "proxy_read_timeout 3600s;"
				new := "# proxy_read_timeout 3600s;"
				return strings.Replace(text, old, new, 1), httpBlock, strings.Replace(httpsBlock, old, new, 1)
			},
			want: "GoAccess WebSocket read timeout missing",
		},
		{
			name: "commented websocket access log off",
			mutate: func(text string, httpBlock string, httpsBlock string) (string, string, string) {
				old := "access_log off;"
				new := "# access_log off;"
				return strings.Replace(text, old, new, 4), httpBlock, strings.Replace(httpsBlock, old, new, 2)
			},
			want: "GoAccess WebSocket access_log off missing",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			text, httpBlock, httpsBlock := minimalGoAccessNginxText(names, dashboardGuard, websocketGuard)
			text, httpBlock, httpsBlock = tt.mutate(text, httpBlock, httpsBlock)

			var errs []string
			validateGoAccessNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
			if !strings.Contains(strings.Join(errs, "; "), tt.want) {
				t.Fatalf("errors = %v, want substring %q", errs, tt.want)
			}
		})
	}
}

func TestValidateAppProxyLocationIgnoresGoAccessWebSocketDirectives(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	httpsBlock := `server {
    location = /_lanpanel/apps/example-app/goaccess/ws {
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $example_app_connection_upgrade;
    }

    location / {
        proxy_pass http://example_app_upstream;
        proxy_http_version 1.1;
        proxy_set_header Host $example_app_validated_host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $example_app_connection_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $example_app_validated_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}`
	var errs []string
	validateAppProxyLocation(&errs, httpsBlock, cfg, names)
	if len(errs) > 0 {
		t.Fatalf("valid app proxy errors = %v", errs)
	}

	broken := strings.Replace(httpsBlock, "        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection $example_app_connection_upgrade;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Host $example_app_validated_host;", "        # proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection $example_app_connection_upgrade;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Host $example_app_validated_host;", 1)
	errs = nil
	validateAppProxyLocation(&errs, broken, cfg, names)
	if !strings.Contains(strings.Join(errs, "; "), "HTTPS app WebSocket Upgrade header missing") {
		t.Fatalf("errors = %v, want app proxy Upgrade failure", errs)
	}
}

func TestValidateGoAccessNginxRequiresFullEnhancedLogFormat(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dashboardGuard := `if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`
	websocketGuard := `if ($host != "abc.com") {
            return 421;
        }`
	text, httpBlock, httpsBlock := minimalGoAccessNginxText(names, dashboardGuard, websocketGuard)
	text = strings.Replace(text, goAccessEnhancedLogFormatDirective(names), `log_format `+names.GoAccessNginxLogFormatName+` '$request_time "$upstream_status" "$upstream_response_time"';`, 1)

	var errs []string
	validateGoAccessNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
	if !strings.Contains(strings.Join(errs, "; "), "GoAccess enhanced log_format missing") {
		t.Fatalf("errors = %v, want full enhanced log_format failure", errs)
	}
}

func TestValidateGoAccessNginxRequiresConditionalPrimaryDomainGuards(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	dashboardGuard := `if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`
	websocketGuard := `if ($host != "abc.com") {
            return 421;
        }`
	text, httpBlock, httpsBlock := minimalGoAccessNginxText(names, dashboardGuard, websocketGuard)
	var errs []string
	validateGoAccessNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
	if len(errs) > 0 {
		t.Fatalf("valid GoAccess nginx errors = %v", errs)
	}

	tests := []struct {
		name           string
		dashboardGuard string
		websocketGuard string
		want           string
	}{
		{
			name:           "unconditional dashboard redirect",
			dashboardGuard: `return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;`,
			websocketGuard: websocketGuard,
			want:           "GoAccess dashboard primary-domain redirect guard missing",
		},
		{
			name:           "unconditional websocket block",
			dashboardGuard: dashboardGuard,
			websocketGuard: `return 421;`,
			want:           "GoAccess WebSocket secondary-domain guard missing",
		},
		{
			name: "commented dashboard guard opener",
			dashboardGuard: `# if ($host != "abc.com") {
            return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
        }`,
			websocketGuard: websocketGuard,
			want:           "GoAccess dashboard primary-domain redirect guard missing",
		},
		{
			name:           "commented websocket guard opener",
			dashboardGuard: dashboardGuard,
			websocketGuard: `# if ($host != "abc.com") {
            return 421;
        }`,
			want: "GoAccess WebSocket secondary-domain guard missing",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			text, httpBlock, httpsBlock := minimalGoAccessNginxText(names, tt.dashboardGuard, tt.websocketGuard)
			var errs []string
			validateGoAccessNginx(&errs, text, httpBlock, httpsBlock, cfg, names)
			if !strings.Contains(strings.Join(errs, "; "), tt.want) {
				t.Fatalf("errors = %v, want substring %q", errs, tt.want)
			}
		})
	}
}

func TestValidateGoAccessNginxDisabledDoesNotRejectAppNameOnly(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.App.Name = "goaccess-app"
	cfg.Service.ExecStart = "/opt/goaccess-app/goaccess-app --listen 127.0.0.1:18001"
	cfg.Service.WorkingDirectory = "/opt/goaccess-app"
	names, err := NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	var errs []string
	validateGoAccessNginx(&errs, "# Lanpanel-managed: app.name=goaccess-app\nserver_name abc.com;", "", "", cfg, names)
	if len(errs) > 0 {
		t.Fatalf("disabled GoAccess app-name-only errors = %v", errs)
	}

	staticLocation := `server {
    location = /_lanpanel/apps/example-app/goaccess {
        alias /opt/goaccess-app/web/static/goaccess.html;
    }
}`
	validateGoAccessNginx(&errs, staticLocation, "", staticLocation, cfg, names)
	if len(errs) > 0 {
		t.Fatalf("disabled GoAccess static location errors = %v", errs)
	}

	validateGoAccessNginx(&errs, "location = /_lanpanel/apps/example-app/goaccess {\n    auth_basic \"Lanpanel GoAccess\";\n}", "", "", cfg, names)
	if !strings.Contains(strings.Join(errs, "; "), "GoAccess basic auth must be absent") {
		t.Fatalf("errors = %v, want disabled GoAccess auth refusal", errs)
	}
}

func TestManagedMarkerRejectsForeignFiles(t *testing.T) {
	t.Parallel()

	if err := CheckManagedContent("example-app", []byte("# "+ManagedMarker("example-app"))); err != nil {
		t.Fatalf("CheckManagedContent() error = %v", err)
	}
	if err := CheckManagedContent("api", []byte("# "+ManagedMarker("api-admin"))); err == nil {
		t.Fatal("CheckManagedContent() error = nil, want prefix-name foreign marker failure")
	}
	if err := CheckManagedContent("example-app", []byte("# "+ManagedMarker("example-app")+"\n# "+ManagedMarker("other-app"))); err == nil {
		t.Fatal("CheckManagedContent() error = nil, want mixed marker failure")
	}
	if err := CheckManagedContent("example-app", []byte("# Lanpanel-managed: app.name=other")); err == nil {
		t.Fatal("CheckManagedContent() error = nil, want foreign marker failure")
	}
	if err := CheckManagedContent("example-app", []byte("plain config")); err == nil {
		t.Fatal("CheckManagedContent() error = nil, want unmanaged failure")
	}
}

func TestGuardEnabledSiteCommandProtectsForeignEnabledPath(t *testing.T) {
	t.Parallel()

	names, err := NewNames(testConfig())
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	command := GuardEnabledSiteCommand(names)
	script := command.Args[1]
	dir := t.TempDir()
	available := filepath.Join(dir, "sites-available", "example-app.conf")
	enabled := filepath.Join(dir, "sites-enabled", "example-app.conf")
	if err := os.MkdirAll(filepath.Dir(available), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(enabled), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(available, []byte("# app\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T)
		wantErr bool
		want    string
	}{
		{name: "missing", prepare: func(t *testing.T) {}, wantErr: false},
		{
			name: "matching symlink",
			prepare: func(t *testing.T) {
				if err := os.Symlink(available, enabled); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			},
			wantErr: false,
		},
		{
			name: "foreign symlink",
			prepare: func(t *testing.T) {
				if err := os.Symlink(filepath.Join(dir, "other.conf"), enabled); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			},
			wantErr: true,
			want:    "refusing to replace it",
		},
		{
			name: "regular file",
			prepare: func(t *testing.T) {
				if err := os.WriteFile(enabled, []byte("# foreign\n"), 0o644); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
			},
			wantErr: true,
			want:    "not a Lanpanel-managed app symlink",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Remove(enabled); err != nil && !os.IsNotExist(err) {
				t.Fatalf("Remove() error = %v", err)
			}
			tt.prepare(t)
			cmd := exec.Command("sh", "-c", script, "lanpanel-app-nginx-enabled-guard", enabled, available)
			output, err := cmd.CombinedOutput()
			if tt.wantErr && err == nil {
				t.Fatalf("script error = nil, want failure; output:\n%s", output)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("script error = %v; output:\n%s", err, output)
			}
			if tt.want != "" && !strings.Contains(string(output), tt.want) {
				t.Fatalf("script output = %q, want %q", output, tt.want)
			}
		})
	}
}

func runServiceAccessScript(t *testing.T, script string, binDir string, scenario string) (string, error) {
	t.Helper()

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-service-access", "example-app", "/opt/example-app/example-app", "/opt/example-app")
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "SCENARIO="+scenario)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runGoAccessAuthGuardScript(t *testing.T, script string, authFile string, scenario string) (string, error) {
	t.Helper()

	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "stat"), `#!/bin/sh
if [ "$1:$2" = "-c:%u" ]; then
    if [ "$SCENARIO" = "nonroot-log-owner" ] && [ "$3" = "$LOG_FILE" ]; then
        echo 1000
        exit 0
    fi
    echo 0
    exit 0
fi
exec /usr/bin/stat "$@"
`)
	writeExecutable(t, filepath.Join(dir, "find"), `#!/bin/sh
if [ "$SCENARIO" = "real-find" ]; then
    exec /usr/bin/find "$@"
fi
if [ "$SCENARIO" = "find-error" ]; then
    exit 23
fi
if [ "$SCENARIO" = "writable-parent" ] && [ "$1" = "$WRITABLE_PARENT" ]; then
    printf '%s\n' "$1"
    exit 0
fi
if [ "$SCENARIO" = "sticky-ancestor" ] && [ "$1" = "$STICKY_ANCESTOR" ]; then
    printf '%s\n' "$1"
    exit 0
fi
exit 0
`)
	path := dir + ":/usr/bin:/bin"
	if scenario != "missing-runuser" {
		writeExecutable(t, filepath.Join(dir, "getent"), `#!/bin/sh
case "$1:$2:$SCENARIO" in
  passwd:www-data:missing-nginx-user) exit 2 ;;
  passwd:www-data:*) echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"; exit 0 ;;
esac
exec /usr/bin/getent "$@"
`)
		writeExecutable(t, filepath.Join(dir, "runuser"), `#!/bin/sh
if [ "$SCENARIO" = "unreadable" ]; then
    exit 1
fi
exit 0
`)
		path = dir + ":" + path
	}

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-goaccess-auth-file", authFile, "www-data")
	cmd.Env = append(os.Environ(),
		"PATH="+path,
		"SCENARIO="+scenario,
		"GOACCESS_AUTH_FILE="+authFile,
		"WRITABLE_PARENT="+filepath.Dir(authFile),
		"STICKY_ANCESTOR="+filepath.Dir(filepath.Dir(authFile)),
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runGoAccessLogReadableScript(t *testing.T, script string, logFile string, scenario string) (string, error) {
	t.Helper()

	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "stat"), `#!/bin/sh
	if [ "$1:$2" = "-c:%u" ]; then
	    if [ "$SCENARIO" = "nonroot-log-owner" ] && [ "$3" = "$LOG_FILE" ]; then
	        echo 1000
	        exit 0
	    fi
	    echo 0
	    exit 0
	fi
	exec /usr/bin/stat "$@"
`)
	writeExecutable(t, filepath.Join(dir, "find"), `#!/bin/sh
case "$SCENARIO:$1" in
  writable-parent:"$LOG_PARENT"|file-writable:"$LOG_FILE")
    printf '%s\n' "$1"
    exit 0
    ;;
esac
exit 0
`)
	writeExecutable(t, filepath.Join(dir, "runuser"), `#!/bin/sh
if [ "$SCENARIO" = "unreadable" ]; then
    exit 1
fi
exit 0
`)

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-goaccess-log-readable", "lanpanel-goaccess-example-app", logFile)
	cmd.Env = []string{
		"PATH=" + dir + ":/usr/bin:/bin",
		"SCENARIO=" + scenario,
		"LOG_PARENT=" + filepath.Dir(logFile),
		"LOG_FILE=" + logFile,
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runGoAccessRuntimeAccessScript(t *testing.T, command host.Command, scenario string) (string, error) {
	t.Helper()

	dir := t.TempDir()
	configFile := command.Args[6]
	reportDir := command.Args[7]
	dbPath := command.Args[8]
	reportFile := command.Args[9]
	if err := os.RemoveAll(configFile); err != nil {
		t.Fatalf("RemoveAll(config) error = %v", err)
	}
	if err := os.RemoveAll(dbPath); err != nil {
		t.Fatalf("RemoveAll(db path) error = %v", err)
	}
	if err := os.MkdirAll(dbPath, 0o755); err != nil {
		t.Fatalf("MkdirAll(db path) error = %v", err)
	}
	if scenario == "db-symlink" || scenario == "db-file" {
		if err := os.RemoveAll(dbPath); err != nil {
			t.Fatalf("RemoveAll(db path) error = %v", err)
		}
		switch scenario {
		case "db-symlink":
			if err := os.Symlink(filepath.Dir(dbPath), dbPath); err != nil {
				t.Fatalf("Symlink(db path) error = %v", err)
			}
		case "db-file":
			if err := os.WriteFile(dbPath, []byte("db\n"), 0o640); err != nil {
				t.Fatalf("WriteFile(db path) error = %v", err)
			}
		}
	}
	if scenario == "config-symlink" || scenario == "config-dir" {
		if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
			t.Fatalf("Remove(config) error = %v", err)
		}
		switch scenario {
		case "config-symlink":
			if err := os.Symlink(filepath.Dir(configFile), configFile); err != nil {
				t.Fatalf("Symlink(config) error = %v", err)
			}
		case "config-dir":
			if err := os.Mkdir(configFile, 0o755); err != nil {
				t.Fatalf("Mkdir(config) error = %v", err)
			}
		}
	} else {
		if err := os.WriteFile(configFile, []byte("config\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(config) error = %v", err)
		}
	}
	if err := os.Remove(reportFile); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Remove(report) error = %v", err)
	}
	if err := os.WriteFile(reportFile, []byte("report\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(report) error = %v", err)
	}
	if scenario == "report-file-symlink" {
		if err := os.Remove(reportFile); err != nil {
			t.Fatalf("Remove(report) error = %v", err)
		}
		if err := os.Symlink(configFile, reportFile); err != nil {
			t.Fatalf("Symlink(report) error = %v", err)
		}
	}
	writeExecutable(t, filepath.Join(dir, "getent"), `#!/bin/sh
case "$1:$2" in
  passwd:lanpanel-goaccess-example-app) echo "lanpanel-goaccess-example-app:x:998:998::/var/lib/example-app/goaccess:/usr/sbin/nologin"; exit 0 ;;
  passwd:www-data) echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"; exit 0 ;;
esac
exit 2
`)
	writeExecutable(t, filepath.Join(dir, "runuser"), `#!/bin/sh
user=
if [ "$1" = "-u" ]; then
    user=$2
    shift 3
fi
mode=$2
path=$3
case "$SCENARIO:$user:$mode:$path" in
  config-unreadable:lanpanel-goaccess-example-app:-r:"$GOACCESS_CONFIG") exit 1 ;;
  report-dir-writable:lanpanel-goaccess-example-app:-w:"$GOACCESS_REPORT_DIR") exit 0 ;;
  *:lanpanel-goaccess-example-app:-w:"$GOACCESS_REPORT_DIR") exit 1 ;;
  report-dir-unreadable-nginx:www-data:-r:"$GOACCESS_REPORT_DIR") exit 1 ;;
  db-unwritable:lanpanel-goaccess-example-app:-w:"$GOACCESS_DB_PATH") exit 1 ;;
  report-file-unwritable:lanpanel-goaccess-example-app:-w:"$GOACCESS_REPORT_FILE") exit 1 ;;
  report-file-unreadable:www-data:-r:"$GOACCESS_REPORT_FILE") exit 1 ;;
esac
exit 0
	`)
	writeExecutable(t, filepath.Join(dir, "stat"), `#!/bin/sh
case "$1:$2" in
  -c:%u)
    if [ "$SCENARIO" = "config-wrong-owner" ] && [ "$3" = "$GOACCESS_CONFIG" ]; then
      echo 1000
    else
      echo 0
    fi
    exit 0
    ;;
esac
case "$1:$2:$3" in
  -c:%U:%G:"$GOACCESS_REPORT_DIR")
    if [ "$SCENARIO" = "report-dir-wrong-owner" ]; then
      echo www-data:www-data
    else
      echo root:root
    fi
    exit 0
    ;;
  -c:%U:%G:"$GOACCESS_DB_PATH")
    if [ "$SCENARIO" = "db-wrong-owner" ]; then
      echo root:root
    else
      echo lanpanel-goaccess-example-app:lanpanel-goaccess-example-app
    fi
    exit 0
    ;;
  -c:%U:%G:"$GOACCESS_REPORT_FILE")
    if [ "$SCENARIO" = "report-file-wrong-owner" ]; then
      echo root:root
    else
      echo lanpanel-goaccess-example-app:www-data
    fi
    exit 0
    ;;
  -c:%a:"$GOACCESS_CONFIG")
    if [ "$SCENARIO" = "config-unsafe-mode" ]; then
      echo 666
    else
      echo 644
    fi
    exit 0
    ;;
  -c:%a:"$GOACCESS_REPORT_DIR")
    if [ "$SCENARIO" = "report-dir-unsafe-mode" ]; then
      echo 775
    else
      echo 755
    fi
    exit 0
    ;;
  -c:%a:"$GOACCESS_DB_PATH")
    if [ "$SCENARIO" = "db-unsafe-mode" ]; then
      echo 775
    else
      echo 750
    fi
    exit 0
    ;;
  -c:%a:"$GOACCESS_REPORT_FILE")
    if [ "$SCENARIO" = "report-file-unsafe-mode" ]; then
      echo 666
    else
      echo 640
    fi
    exit 0
    ;;
esac
exec /usr/bin/stat "$@"
	`)
	writeExecutable(t, filepath.Join(dir, "find"), `#!/bin/sh
if [ "$SCENARIO" = "config-writable-parent" ] && [ "$1" = "$GOACCESS_CONFIG_PARENT" ]; then
    printf '%s\n' "$1"
fi
exit 0
	`)

	cmd := exec.Command("sh", append([]string{"-c", command.Args[1]}, command.Args[2:]...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+dir+":/usr/bin:/bin",
		"SCENARIO="+scenario,
		"GOACCESS_CONFIG="+configFile,
		"GOACCESS_CONFIG_PARENT="+filepath.Dir(configFile),
		"GOACCESS_REPORT_DIR="+reportDir,
		"GOACCESS_DB_PATH="+dbPath,
		"GOACCESS_REPORT_FILE="+reportFile,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runGoAccessLogDirectoryGuardScript(t *testing.T, script string, names Names, scenario string) (string, error) {
	t.Helper()

	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "stat"), `#!/bin/sh
if [ "$1:$2" = "-c:%u" ]; then
    echo 0
    exit 0
fi
exec /usr/bin/stat "$@"
`)
	writeExecutable(t, filepath.Join(dir, "find"), `#!/bin/sh
if [ "$SCENARIO" = "find-error" ] && [ "$1" = "$GOACCESS_LOG_DIR" ]; then
    exit 23
fi
case "$SCENARIO:$1" in
  marker-group-writable:"$GOACCESS_LOG_MARKER"|marker-world-writable:"$GOACCESS_LOG_MARKER")
    printf '%s\n' "$1"
    exit 0
    ;;
esac
exit 0
`)

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-goaccess-log-guard", names.AppName, names.GoAccessLogDir, names.GoAccessLogDirMarkerPath)
	cmd.Env = append(os.Environ(),
		"PATH="+dir+":/usr/bin:/bin",
		"SCENARIO="+scenario,
		"GOACCESS_LOG_DIR="+names.GoAccessLogDir,
		"GOACCESS_LOG_MARKER="+names.GoAccessLogDirMarkerPath,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runEnsureGoAccessLogDirectoryScript(t *testing.T, script string, names Names) (string, error) {
	t.Helper()

	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "stat"), `#!/bin/sh
if [ "$1:$2" = "-c:%u" ]; then
    echo 0
    exit 0
fi
exec /usr/bin/stat "$@"
`)
	writeExecutable(t, filepath.Join(binDir, "find"), `#!/bin/sh
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "install"), `#!/bin/sh
if [ "$1" = "-d" ]; then
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -m|-o|-g) shift 2 ;;
            --) shift; break ;;
            *) shift ;;
        esac
    done
    mkdir -p "$@"
    exit 0
fi
exec /usr/bin/install "$@"
`)

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-goaccess-log-dir", names.AppName, names.GoAccessLogDir, names.GoAccessLogDirMarkerPath, names.GoAccessCanonicalAccessLogPath, names.GoAccessSystemGroup)
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+":/usr/bin:/bin",
		"GOACCESS_LOG_DIR="+names.GoAccessLogDir,
		"GOACCESS_LOG_MARKER="+names.GoAccessLogDirMarkerPath,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runSystemUserGuardScript(t *testing.T, script string, scenario string) (string, error) {
	t.Helper()

	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "getent"), `#!/bin/sh
case "$1:$2:$SCENARIO" in
  group:example-app:group-only) echo "example-app:x:998:"; exit 0 ;;
  passwd:example-app:group-only) exit 2 ;;
  group:example-app:missing) exit 2 ;;
  passwd:example-app:missing) exit 2 ;;
esac
exit 2
`)
	writeExecutable(t, filepath.Join(dir, "groupadd"), "#!/bin/sh\necho unexpected groupadd >&2\nexit 99\n")
	writeExecutable(t, filepath.Join(dir, "useradd"), "#!/bin/sh\necho unexpected useradd >&2\nexit 99\n")

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-user-guard", "example-app", "/var/lib/example-app")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SCENARIO="+scenario)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runSystemUserScript(t *testing.T, script string, scenario string) (string, error) {
	t.Helper()

	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "getent"), `#!/bin/sh
case "$1:$2:$SCENARIO" in
  group:example-app:group-only) echo "example-app:x:998:"; exit 0 ;;
  passwd:example-app:group-only) exit 2 ;;
  group:example-app:user-only) exit 2 ;;
  passwd:example-app:user-only) echo "example-app:x:998:998::/var/lib/example-app:/usr/sbin/nologin"; exit 0 ;;
  group:example-app:mismatched-group) echo "example-app:x:998:"; exit 0 ;;
  passwd:example-app:mismatched-group) echo "example-app:x:998:997::/var/lib/example-app:/usr/sbin/nologin"; exit 0 ;;
  group:example-app:mismatched-home) echo "example-app:x:998:"; exit 0 ;;
  passwd:example-app:mismatched-home) echo "example-app:x:998:998::/srv/example-app:/usr/sbin/nologin"; exit 0 ;;
  group:example-app:login-shell) echo "example-app:x:998:"; exit 0 ;;
  passwd:example-app:login-shell) echo "example-app:x:998:998::/var/lib/example-app:/bin/sh"; exit 0 ;;
  group:example-app:regular-uid) echo "example-app:x:1001:"; exit 0 ;;
  passwd:example-app:regular-uid) echo "example-app:x:1001:1001::/var/lib/example-app:/usr/sbin/nologin"; exit 0 ;;
  group:example-app:matching) echo "example-app:x:998:"; exit 0 ;;
  passwd:example-app:matching) echo "example-app:x:998:998::/var/lib/example-app:/usr/sbin/nologin"; exit 0 ;;
esac
exit 2
`)
	writeExecutable(t, filepath.Join(dir, "groupadd"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(dir, "useradd"), "#!/bin/sh\nexit 0\n")

	cmd := exec.Command("sh", "-c", script, "lanpanel-app-user", "example-app", "/var/lib/example-app")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SCENARIO="+scenario)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func writeExecutable(t *testing.T, path string, content string) {
	t.Helper()

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		t.Fatalf("CreateTemp(%s) error = %v", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		t.Fatalf("WriteString(%s) error = %v", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("Close(%s) error = %v", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		t.Fatalf("Chmod(%s) error = %v", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		t.Fatalf("Rename(%s, %s) error = %v", tmpPath, path, err)
	}
}

func runGuardCommandWithNginxDump(t *testing.T, command host.Command, dump string) ([]byte, error) {
	t.Helper()

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", binDir, err)
	}
	dumpPath := filepath.Join(dir, "nginx.dump")
	if err := os.WriteFile(dumpPath, []byte(dump), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", dumpPath, err)
	}
	writeExecutable(t, filepath.Join(binDir, "nginx"), `#!/bin/sh
if [ "$1" = "-T" ]; then
    cat "$NGINX_DUMP_PATH"
    exit 0
fi
exit 64
`)

	args := append([]string{"-c", command.Args[1]}, command.Args[2:]...)
	for i := range args {
		if args[i] == NginxBinaryPath {
			args[i] = filepath.Join(binDir, "nginx")
		}
	}
	cmd := exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "NGINX_DUMP_PATH="+dumpPath)
	return cmd.CombinedOutput()
}

func validateGoAccessAccessControlErrors(block string, goaccess appconfig.NginxGoAccessConfig) string {
	var errs []string
	validateGoAccessAccessControls(&errs, block, goaccess, "GoAccess test")
	return strings.Join(errs, "; ")
}

func minimalGoAccessNginxText(names Names, dashboardGuard string, websocketGuard string) (string, string, string) {
	httpBlock := `server {
    listen 80;
    access_log ` + names.GoAccessCanonicalAccessLogPath + ` ` + names.GoAccessNginxLogFormatName + `;

    location = /_lanpanel/apps/example-app/goaccess {
        access_log off;
        return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;
    }

    location = /_lanpanel/apps/example-app/goaccess/ws {
        access_log off;
        return 421;
    }

    location / {
        return 301 https://$example_app_validated_host$request_uri;
    }
}`
	httpsBlock := `server {
    listen 443 ssl;
    access_log ` + names.GoAccessCanonicalAccessLogPath + ` ` + names.GoAccessNginxLogFormatName + `;

	    location = /_lanpanel/apps/example-app/goaccess {
	        ` + dashboardGuard + `
	        alias ` + names.GoAccessReportPath + `;
	        default_type text/html;
	        disable_symlinks on;
	        satisfy all;
	        auth_basic "Lanpanel GoAccess";
	        auth_basic_user_file /etc/example-app/goaccess.htpasswd;
	        access_log off;
    }

    location = /_lanpanel/apps/example-app/goaccess/ws {
        ` + websocketGuard + `
        proxy_pass http://` + names.GoAccessWebSocketListen + `;
        proxy_http_version 1.1;
	        proxy_set_header Authorization "";
	        proxy_set_header Upgrade $http_upgrade;
	        proxy_set_header Connection $` + names.VarPrefix + `_connection_upgrade;
	        proxy_set_header X-Real-IP $remote_addr;
	        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	        proxy_set_header X-Forwarded-Host $` + names.VarPrefix + `_validated_host;
	        proxy_set_header X-Forwarded-Proto $scheme;
	        proxy_read_timeout 3600s;
	        satisfy all;
	        auth_basic "Lanpanel GoAccess";
	        auth_basic_user_file /etc/example-app/goaccess.htpasswd;
	        access_log off;
    }

    location / {
        proxy_pass http://` + names.VarPrefix + `_upstream;
    }
}`
	text := goAccessEnhancedLogFormatDirective(names) + `
` + httpBlock + `
` + httpsBlock
	return text, httpBlock, httpsBlock
}

func nginxDump(sections map[string]string) string {
	paths := make([]string, 0, len(sections))
	for path := range sections {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var builder strings.Builder
	for _, path := range paths {
		builder.WriteString("# configuration file ")
		builder.WriteString(path)
		builder.WriteString(":\n")
		builder.WriteString(sections[path])
		if !strings.HasSuffix(sections[path], "\n") {
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func writeFile(t *testing.T, path string, content string, mode os.FileMode) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
