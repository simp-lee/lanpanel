package appverify

import (
	"fmt"
	"lanpanel/internal/appassets"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apprender"
	"lanpanel/internal/components/appsvc"
	"strings"
	"unicode"
)

type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
)

type Check struct {
	ID      string
	Status  Status
	Summary string
}

type Report struct {
	Checks []Check
}

func StaticReport(cfg appconfig.Config, staged []apprender.StagedFile) Report {
	checks := []Check{}
	add := func(id string, status Status, summary string) {
		checks = append(checks, Check{ID: id, Status: status, Summary: summary})
	}

	if err := cfg.ValidateForExposurePlan(); err != nil {
		add("config", StatusFail, "app config validation failed: "+err.Error())
		return Report{Checks: checks}
	}
	add("config", StatusPass, "app config schema and static fields are valid")
	if cfg.RequiresTailscale() {
		add("tailscale", StatusPass, "app config requires Tailscale client prerequisites")
	} else {
		add("tailscale", StatusPass, "app config does not require Tailscale client prerequisites")
	}

	names, err := appsvc.NewNames(cfg)
	if err != nil {
		add("names", StatusFail, err.Error())
	} else {
		add("names", StatusPass, "app resource names and derived paths are valid")
	}

	if len(staged) == 0 {
		add("templates", StatusFail, "no app runtime templates were rendered")
		return Report{Checks: checks}
	}

	hasNginx := false
	for _, file := range staged {
		text := string(file.Content)
		if stale, label := containsLegacyLegoV4Form(text); stale {
			add("lego-v5", StatusFail, "rendered file contains lego v4 syntax: "+label)
			return Report{Checks: checks}
		}
		sensitive, label, err := containsSensitiveValue(text)
		if err != nil {
			add("secrets", StatusFail, "rendered file contains invalid systemd Environment syntax: "+err.Error())
			return Report{Checks: checks}
		}
		if sensitive {
			add("secrets", StatusFail, "rendered file contains a suspected sensitive value: "+label)
			return Report{Checks: checks}
		}
		if err := appsvc.CheckManagedContent(cfg.App.Name, file.Content); err != nil {
			add("ownership", StatusFail, file.HostPath+" "+err.Error())
			return Report{Checks: checks}
		}
		if file.SourcePath == "templates/app/nginx.conf.tmpl" {
			hasNginx = true
			if err == nil {
				if validateErr := appsvc.ValidateRenderedNginx(cfg, names, file.Content); validateErr != nil {
					add("nginx", StatusFail, validateErr.Error())
					return Report{Checks: checks}
				}
			}
		}
	}
	add("ownership", StatusPass, "rendered files contain the Lanpanel-managed marker for this app")
	add("secrets", StatusPass, "rendered files do not contain Tailscale auth keys or DNS tokens")
	add("lego-v5", StatusPass, "rendered files do not contain lego v4 renew or legacy hook syntax")
	if err := validateStagedRuntimeSet(cfg, staged); err != nil {
		add("templates", StatusFail, err.Error())
		return Report{Checks: checks}
	}
	if err == nil {
		if validateErr := validateAppServiceStatic(cfg, names, staged); validateErr != nil {
			add("templates", StatusFail, validateErr.Error())
			return Report{Checks: checks}
		}
	}
	add("templates", StatusPass, fmt.Sprintf("rendered %d app runtime files with complete systemd, Nginx, and deploy hook plans", len(staged)))
	if hasNginx {
		add("nginx", StatusPass, "Nginx app site includes multiple domains, Host/SNI guards, WebSocket handling, and fixed upstream support")
	} else {
		add("nginx", StatusFail, "missing Nginx app site template")
	}
	if cfg.Nginx.GoAccess.Enabled {
		if err := validateGoAccessStatic(cfg, names, staged); err != nil {
			add("goaccess", StatusFail, err.Error())
			return Report{Checks: checks}
		}
		summary := "GoAccess runtime config, service, and Nginx HTML/WebSocket static chain is complete"
		if appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
			summary = "GoAccess runtime config, service, Nginx HTML/WebSocket, and managed logrotate static chain is complete"
		}
		add("goaccess", StatusPass, summary)
		add("goaccess-scope", StatusPass, "GoAccess dashboard covers request volume, visitors, URLs, 404/status codes, IP/Host, referrer, UA/browser/OS, bandwidth, and visit time; enhanced mode includes request serving time; upstream fields and nginx.error_log remain raw-log/troubleshooting inputs")
	}

	return Report{Checks: checks}
}

func validateAppServiceStatic(cfg appconfig.Config, names appsvc.Names, staged []apprender.StagedFile) error {
	if cfg.Mode() != appconfig.ModeListen {
		return nil
	}
	serviceText := ""
	for _, file := range staged {
		if file.SourcePath == appassets.ServiceTemplate {
			serviceText = string(file.Content)
			break
		}
	}
	if strings.TrimSpace(serviceText) == "" {
		return fmt.Errorf("missing app service runtime file: %s", appassets.ServiceTemplate)
	}
	expectedExecStart := "ExecStart=" + strings.TrimSpace(cfg.Service.ExecStart)
	execStartLines := systemdDirectiveLines(serviceText, "ExecStart")
	if len(execStartLines) != 1 || execStartLines[0] != expectedExecStart {
		return fmt.Errorf("app service must start configured service.exec_start")
	}
	if err := rejectExtraAppExecDirectives(serviceText); err != nil {
		return err
	}
	typeValues := systemdDirectiveValues(serviceText, "Type")
	if len(typeValues) != 1 || typeValues[0] != "simple" {
		return fmt.Errorf("app service must set exactly one Type=simple directive")
	}
	userValues := systemdDirectiveValues(serviceText, "User")
	if len(userValues) != 1 || userValues[0] != names.SystemUser {
		return fmt.Errorf("app service must run as dedicated user %s", names.SystemUser)
	}
	groupValues := systemdDirectiveValues(serviceText, "Group")
	if len(groupValues) != 1 || groupValues[0] != names.SystemGroup {
		return fmt.Errorf("app service must run as dedicated group %s", names.SystemGroup)
	}
	if err := requireOptionalSystemdDirective(serviceText, "WorkingDirectory", strings.TrimSpace(cfg.Service.WorkingDirectory)); err != nil {
		return fmt.Errorf("app service %w", err)
	}
	if err := requireOptionalSystemdDirective(serviceText, "EnvironmentFile", strings.TrimSpace(cfg.Service.EnvFile)); err != nil {
		return fmt.Errorf("app service %w", err)
	}
	if err := requireSingleSystemdDirective(serviceText, "Restart", "on-failure", "app service"); err != nil {
		return err
	}
	if err := requireSingleSystemdDirective(serviceText, "NoNewPrivileges", "true", "app service"); err != nil {
		return err
	}
	if err := requireSingleSystemdDirective(serviceText, "PrivateTmp", "true", "app service"); err != nil {
		return err
	}
	if err := requireSingleSystemdDirective(serviceText, "ProtectSystem", "full", "app service"); err != nil {
		return err
	}
	if err := requireSingleSystemdDirective(serviceText, "ProtectHome", "true", "app service"); err != nil {
		return err
	}
	return nil
}

func rejectExtraAppExecDirectives(serviceText string) error {
	for _, line := range systemdDirectiveLinesWithPrefix(serviceText, "Exec") {
		if strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		return fmt.Errorf("app service must not contain extra Exec directive %s", strings.SplitN(line, "=", 2)[0])
	}
	return nil
}

func requireOptionalSystemdDirective(text string, key string, want string) error {
	values := systemdDirectiveValues(text, key)
	if want == "" {
		if len(values) != 0 {
			return fmt.Errorf("must not set %s when not configured", key)
		}
		return nil
	}
	if len(values) != 1 || values[0] != want {
		return fmt.Errorf("must set exactly one %s=%s", key, want)
	}
	return nil
}

func requireSingleSystemdDirective(text string, key string, want string, label string) error {
	values := systemdDirectiveValues(text, key)
	if len(values) != 1 || values[0] != want {
		return fmt.Errorf("%s must set exactly one %s=%s directive", label, key, want)
	}
	return nil
}

func validateGoAccessStatic(cfg appconfig.Config, names appsvc.Names, staged []apprender.StagedFile) error {
	if !cfg.Nginx.GoAccess.Enabled {
		return nil
	}
	bySource := make(map[string]string, len(staged))
	for _, file := range staged {
		bySource[file.SourcePath] = string(file.Content)
	}
	nginxText := bySource[appassets.NginxTemplate]
	configText := bySource[appassets.GoAccessConfigTemplate]
	serviceText := bySource[appassets.GoAccessServiceTemplate]
	if strings.TrimSpace(configText) == "" {
		return fmt.Errorf("missing GoAccess config runtime file: %s", appassets.GoAccessConfigTemplate)
	}
	if strings.TrimSpace(serviceText) == "" {
		return fmt.Errorf("missing GoAccess service runtime file: %s", appassets.GoAccessServiceTemplate)
	}
	if appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
		logrotateText := bySource[appassets.GoAccessLogrotateTemplate]
		if strings.TrimSpace(logrotateText) == "" {
			return fmt.Errorf("missing GoAccess logrotate runtime file: %s", appassets.GoAccessLogrotateTemplate)
		}
		if err := validateGoAccessLogrotateStatic(names, logrotateText); err != nil {
			return err
		}
	}
	expectedConfig := map[string]string{
		"log-file":          names.GoAccessCanonicalAccessLogPath,
		"output":            names.GoAccessReportPath,
		"real-time-html":    "true",
		"addr":              names.GoAccessWebSocketHost,
		"port":              fmt.Sprintf("%d", names.GoAccessWebSocketPort),
		"ws-url":            "wss://" + cfg.PrimaryDomain() + ":443" + cfg.NginxGoAccessWebSocketPath(),
		"origin":            "https://" + cfg.PrimaryDomain(),
		"ping-interval":     "10",
		"persist":           "true",
		"restore":           "true",
		"db-path":           names.GoAccessDBPath,
		"html-report-title": "Lanpanel-GoAccess-" + names.AppName,
	}
	for key, want := range expectedConfig {
		if err := requireSingleGoAccessConfigValue(configText, key, want); err != nil {
			return err
		}
	}
	if err := requireGoAccessStaticFiles(configText); err != nil {
		return err
	}
	if cfg.Nginx.GoAccess.EffectiveLogFormat() == appconfig.NginxGoAccessLogFormatEnhanced {
		if !hasExactLine(nginxText, expectedEnhancedNginxLogFormatLine(names)) {
			return fmt.Errorf("GoAccess enhanced parser is missing %q", expectedEnhancedNginxLogFormatLine(names))
		}
		if err := requireSingleGoAccessConfigValue(configText, "log-format", `%h %^ %^ [%x] "%r" %s %b "%R" "%u" "%v" %T "%^" "%^"`); err != nil {
			return err
		}
		if err := requireSingleGoAccessConfigValue(configText, "datetime-format", "%Y-%m-%dT%H:%M:%S%z"); err != nil {
			return err
		}
		if values := goAccessConfigValues(configText, "date-format"); len(values) > 0 {
			return fmt.Errorf("GoAccess config date-format must be absent when datetime-format is used")
		}
		if values := goAccessConfigValues(configText, "time-format"); len(values) > 0 {
			return fmt.Errorf("GoAccess config time-format must be absent when datetime-format is used")
		}
	} else {
		if err := requireSingleGoAccessConfigValue(configText, "log-format", "COMBINED"); err != nil {
			return err
		}
		if err := requireSingleGoAccessConfigValue(configText, "date-format", "%d/%b/%Y"); err != nil {
			return err
		}
		if err := requireSingleGoAccessConfigValue(configText, "time-format", "%H:%M:%S"); err != nil {
			return err
		}
		if values := goAccessConfigValues(configText, "datetime-format"); len(values) > 0 {
			return fmt.Errorf("GoAccess config datetime-format must be absent when date-format/time-format are used")
		}
	}
	if err := validateGoAccessConfigManagedKeys(configText, expectedGoAccessConfigKeys(cfg)); err != nil {
		return err
	}
	if strings.Contains(configText, cfg.Nginx.GoAccess.AuthBasicUserFile) {
		return fmt.Errorf("GoAccess config must not reference auth_basic_user_file")
	}
	expectedExecStart := "ExecStart=" + appsvc.GoAccessBinaryPath + " --no-global-config --config-file " + names.GoAccessConfigPath
	execStartLines := systemdDirectiveLines(serviceText, "ExecStart")
	if len(execStartLines) != 1 || execStartLines[0] != expectedExecStart {
		return fmt.Errorf("GoAccess service must start goaccess with the rendered config file")
	}
	if err := rejectExtraGoAccessExecDirectives(serviceText); err != nil {
		return err
	}
	typeValues := systemdDirectiveValues(serviceText, "Type")
	if len(typeValues) != 1 || typeValues[0] != "simple" {
		return fmt.Errorf("GoAccess service must set exactly one Type=simple directive")
	}
	userValues := systemdDirectiveValues(serviceText, "User")
	if len(userValues) != 1 || userValues[0] != names.GoAccessSystemUser {
		return fmt.Errorf("GoAccess service must run as dedicated user %s", names.GoAccessSystemUser)
	}
	groupValues := systemdDirectiveValues(serviceText, "Group")
	if len(groupValues) != 1 || groupValues[0] != names.GoAccessSystemGroup {
		return fmt.Errorf("GoAccess service must run as dedicated group %s", names.GoAccessSystemGroup)
	}
	if err := validateGoAccessServiceLocale(serviceText, cfg.Nginx.GoAccess.EffectiveLanguage()); err != nil {
		return err
	}
	umaskValues := systemdDirectiveValues(serviceText, "UMask")
	if len(umaskValues) != 1 || umaskValues[0] != "0027" {
		return fmt.Errorf("GoAccess service must set exactly one UMask=0027 directive")
	}
	restartValues := systemdDirectiveValues(serviceText, "Restart")
	if len(restartValues) != 1 || restartValues[0] != "on-failure" {
		return fmt.Errorf("GoAccess service must set exactly one Restart=on-failure directive")
	}
	noNewPrivilegesValues := systemdDirectiveValues(serviceText, "NoNewPrivileges")
	if len(noNewPrivilegesValues) != 1 || noNewPrivilegesValues[0] != "true" {
		return fmt.Errorf("GoAccess service must set exactly one NoNewPrivileges=true directive")
	}
	protectSystemValues := systemdDirectiveValues(serviceText, "ProtectSystem")
	if len(protectSystemValues) != 1 || protectSystemValues[0] != "strict" {
		return fmt.Errorf("GoAccess service must set exactly one ProtectSystem=strict directive")
	}
	privateTmpValues := systemdDirectiveValues(serviceText, "PrivateTmp")
	if len(privateTmpValues) != 1 || privateTmpValues[0] != "true" {
		return fmt.Errorf("GoAccess service must set exactly one PrivateTmp=true directive")
	}
	protectHomeValues := systemdDirectiveValues(serviceText, "ProtectHome")
	if len(protectHomeValues) != 1 || protectHomeValues[0] != "true" {
		return fmt.Errorf("GoAccess service must set exactly one ProtectHome=true directive")
	}
	readWritePathValues := systemdDirectiveValues(serviceText, "ReadWritePaths")
	if len(readWritePathValues) != 1 {
		return fmt.Errorf("GoAccess service writable paths must be limited to report file and db")
	}
	readWritePaths := strings.Fields(readWritePathValues[0])
	if len(readWritePaths) != 2 || readWritePaths[0] != names.GoAccessReportPath || readWritePaths[1] != names.GoAccessDBPath {
		return fmt.Errorf("GoAccess service writable paths must be limited to report file and db")
	}
	for _, forbidden := range []string{
		"--daemonize",
		"--log-file",
		"--output",
		"--log-format",
		"--date-format",
		"--time-format",
		"--datetime-format",
		"--real-time-html",
		"--addr",
		"--port",
		"--ws-url",
		"--origin",
		"--ping-interval",
		"--persist",
		"--restore",
		"--db-path",
		"--html-report-title",
	} {
		if strings.Contains(serviceText, forbidden) {
			return fmt.Errorf("GoAccess service must not inline runtime option %s", forbidden)
		}
	}
	if strings.Contains(nginxText, "0.0.0.0:7890") || strings.Contains(serviceText, "0.0.0.0:7890") || containsString(goAccessConfigValues(configText, "addr"), "0.0.0.0") {
		return fmt.Errorf("GoAccess must not use unsafe default 0.0.0.0:7890")
	}
	return nil
}

func validateGoAccessLogrotateStatic(names appsvc.Names, text string) error {
	expected := []string{
		names.GoAccessCanonicalAccessLogPath + " {",
		"daily",
		"rotate 14",
		"missingok",
		"notifempty",
		"compress",
		"delaycompress",
		"create 0640 www-data " + names.GoAccessSystemGroup,
		"sharedscripts",
		"postrotate",
		"if nginx_state_output=$(systemctl is-active nginx.service 2>&1); then",
		`if [ "$nginx_state_output" = "active" ]; then`,
		"systemctl reload nginx.service || exit $?",
		"fi",
		"else",
		"nginx_state_status=$?",
		`case "$nginx_state_output" in`,
		"inactive)",
		";;",
		"*)",
		`printf '%s\n' "$nginx_state_output" >&2`,
		`exit "$nginx_state_status"`,
		";;",
		"esac",
		"fi",
		"systemctl restart " + names.GoAccessServiceUnit + " || exit $?",
		"endscript",
		"}",
	}
	lines := activeLogrotateLines(text)
	if len(lines) == 0 {
		return fmt.Errorf("GoAccess logrotate must not be empty")
	}
	if lines[0] != expected[0] {
		return fmt.Errorf("GoAccess logrotate must rotate exactly %s", names.GoAccessCanonicalAccessLogPath)
	}
	for _, line := range lines[1:] {
		if strings.HasSuffix(line, "{") {
			return fmt.Errorf("GoAccess logrotate must contain exactly one managed log block")
		}
	}
	if countExactLine(lines, "create 0640 www-data "+names.GoAccessSystemGroup) != 1 {
		return fmt.Errorf("GoAccess logrotate must set create 0640 www-data %s", names.GoAccessSystemGroup)
	}
	if countExactLine(lines, "sharedscripts") != 1 {
		return fmt.Errorf("GoAccess logrotate must include sharedscripts")
	}
	if countExactLine(lines, "postrotate") != 1 {
		return fmt.Errorf("GoAccess logrotate must include postrotate")
	}
	if countExactLine(lines, "systemctl reload nginx.service || exit $?") != 1 {
		return fmt.Errorf("GoAccess logrotate must reload nginx.service in postrotate")
	}
	if countExactLine(lines, "systemctl restart "+names.GoAccessServiceUnit+" || exit $?") != 1 {
		return fmt.Errorf("GoAccess logrotate must restart %s in postrotate", names.GoAccessServiceUnit)
	}
	if countExactLine(lines, `printf '%s\n' "$nginx_state_output" >&2`) != 1 || countExactLine(lines, `exit "$nginx_state_status"`) != 1 {
		return fmt.Errorf("GoAccess logrotate must fail on unexpected nginx.service status errors")
	}
	if len(lines) != len(expected) {
		return fmt.Errorf("GoAccess logrotate must match the managed canonical logrotate policy")
	}
	for i, want := range expected {
		if lines[i] == want {
			continue
		}
		switch want {
		case "create 0640 www-data " + names.GoAccessSystemGroup:
			return fmt.Errorf("GoAccess logrotate must set create 0640 www-data %s", names.GoAccessSystemGroup)
		case "sharedscripts":
			return fmt.Errorf("GoAccess logrotate must include sharedscripts")
		case "postrotate":
			return fmt.Errorf("GoAccess logrotate must include postrotate")
		case "systemctl reload nginx.service || exit $?":
			return fmt.Errorf("GoAccess logrotate must reload nginx.service in postrotate")
		case "systemctl restart " + names.GoAccessServiceUnit + " || exit $?":
			return fmt.Errorf("GoAccess logrotate must restart %s in postrotate", names.GoAccessServiceUnit)
		default:
			return fmt.Errorf("GoAccess logrotate directive drift: got %q, want %q", lines[i], want)
		}
	}
	return nil
}

func activeLogrotateLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

func countExactLine(lines []string, want string) int {
	count := 0
	for _, line := range lines {
		if line == want {
			count++
		}
	}
	return count
}

func rejectExtraGoAccessExecDirectives(serviceText string) error {
	for _, line := range systemdDirectiveLinesWithPrefix(serviceText, "Exec") {
		if strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		return fmt.Errorf("GoAccess service must not contain extra Exec directive %s", strings.SplitN(line, "=", 2)[0])
	}
	return nil
}

func expectedGoAccessConfigKeys(cfg appconfig.Config) map[string]struct{} {
	keys := map[string]struct{}{
		"log-file":          {},
		"output":            {},
		"log-format":        {},
		"real-time-html":    {},
		"addr":              {},
		"port":              {},
		"ws-url":            {},
		"origin":            {},
		"ping-interval":     {},
		"persist":           {},
		"restore":           {},
		"db-path":           {},
		"html-report-title": {},
		"static-file":       {},
	}
	if cfg.Nginx.GoAccess.EffectiveLogFormat() == appconfig.NginxGoAccessLogFormatEnhanced {
		keys["datetime-format"] = struct{}{}
	} else {
		keys["date-format"] = struct{}{}
		keys["time-format"] = struct{}{}
	}
	return keys
}

var expectedGoAccessStaticFiles = []string{
	".css", ".js", ".jpg", ".png", ".gif", ".ico", ".jpeg", ".pdf",
	".csv", ".mpeg", ".mpg", ".swf", ".woff", ".woff2", ".xls", ".xlsx",
	".doc", ".docx", ".ppt", ".pptx", ".txt", ".zip", ".ogg", ".mp3",
	".mp4", ".exe", ".iso", ".gz", ".rar", ".svg", ".bmp", ".tar",
	".tgz", ".tiff", ".tif", ".ttf", ".flv", ".dmg", ".webp", ".xz",
	".zst",
}

func requireGoAccessStaticFiles(text string) error {
	values := goAccessConfigValues(text, "static-file")
	if len(values) != len(expectedGoAccessStaticFiles) {
		return fmt.Errorf("GoAccess config static-file directives must exactly match the managed extension list")
	}
	for i, want := range expectedGoAccessStaticFiles {
		if values[i] != want {
			return fmt.Errorf("GoAccess config static-file directives must exactly match the managed extension list")
		}
	}
	return nil
}

func validateGoAccessConfigManagedKeys(text string, allowed map[string]struct{}) error {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		if _, ok := allowed[fields[0]]; !ok {
			return fmt.Errorf("GoAccess config contains unmanaged directive or credential content: %s", fields[0])
		}
	}
	return nil
}

func validateGoAccessServiceLocale(serviceText string, language string) error {
	expected := map[string]string{
		"LANG":        "C.UTF-8",
		"LC_MESSAGES": "C.UTF-8",
		"LC_CTYPE":    "C.UTF-8",
		"LC_TIME":     "C.UTF-8",
	}
	if language == appconfig.NginxGoAccessLanguageSimplifiedChinese {
		expected["LANG"] = "zh_CN.UTF-8"
		expected["LC_MESSAGES"] = "zh_CN.UTF-8"
		expected["LC_CTYPE"] = "zh_CN.UTF-8"
	}
	if err := rejectGoAccessLocaleOverrides(serviceText, expected); err != nil {
		return err
	}
	for key, want := range expected {
		if got := systemdEnvironmentValues(serviceText, key); len(got) != 1 || got[0] != want {
			return fmt.Errorf("GoAccess service must set exactly one Environment=%s=%s", key, want)
		}
	}
	return nil
}

func rejectGoAccessLocaleOverrides(serviceText string, expected map[string]string) error {
	for _, directive := range systemdDirectiveValues(serviceText, "Environment") {
		assignments, err := systemdEnvironmentAssignments(directive)
		if err != nil {
			return fmt.Errorf("GoAccess service Environment directive must use valid systemd assignment syntax: %v", err)
		}
		for _, assignment := range assignments {
			key, _, ok := strings.Cut(assignment, "=")
			if !ok {
				continue
			}
			if key == "LANGUAGE" || strings.HasPrefix(key, "LC_") {
				if _, allowed := expected[key]; !allowed {
					return fmt.Errorf("GoAccess service must not set locale override Environment=%s", key)
				}
			}
		}
	}
	return nil
}

func systemdEnvironmentValues(text string, key string) []string {
	var values []string
	prefix := key + "="
	for _, directive := range systemdDirectiveValues(text, "Environment") {
		assignments, err := systemdEnvironmentAssignments(directive)
		if err != nil {
			continue
		}
		for _, assignment := range assignments {
			if strings.HasPrefix(assignment, prefix) {
				values = append(values, strings.TrimPrefix(assignment, prefix))
			}
		}
	}
	return values
}

func requireSingleGoAccessConfigValue(text string, key string, want string) error {
	values := goAccessConfigValues(text, key)
	if len(values) != 1 || values[0] != want {
		return fmt.Errorf("GoAccess config must set exactly one %s %s", key, want)
	}
	return nil
}

func expectedEnhancedNginxLogFormatLine(names appsvc.Names) string {
	return `log_format ` + names.GoAccessNginxLogFormatName + ` '$remote_addr - $remote_user [$time_iso8601] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$host" $request_time "$upstream_status" "$upstream_response_time"';`
}

func hasExactLine(text string, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

type systemdDirective struct {
	Key   string
	Value string
	Line  string
}

func systemdDirectives(text string) []systemdDirective {
	directives := []systemdDirective{}
	for _, line := range strings.Split(text, "\n") {
		if directive, ok := systemdDirectiveFromLine(line); ok {
			directives = append(directives, directive)
		}
	}
	return directives
}

func systemdDirectiveFromLine(line string) (systemdDirective, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return systemdDirective{}, false
	}
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return systemdDirective{}, false
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return systemdDirective{}, false
	}
	return systemdDirective{Key: key, Value: value, Line: key + "=" + value}, true
}

func systemdDirectiveLines(text string, key string) []string {
	var lines []string
	for _, directive := range systemdDirectives(text) {
		if directive.Key == key {
			lines = append(lines, directive.Line)
		}
	}
	return lines
}

func systemdDirectiveLinesWithPrefix(text string, prefix string) []string {
	var lines []string
	for _, directive := range systemdDirectives(text) {
		if strings.HasPrefix(directive.Key, prefix) {
			lines = append(lines, directive.Line)
		}
	}
	return lines
}

func systemdDirectiveValues(text string, key string) []string {
	var values []string
	for _, directive := range systemdDirectives(text) {
		if directive.Key == key {
			values = append(values, directive.Value)
		}
	}
	return values
}

func goAccessConfigValues(text string, key string) []string {
	var values []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || fields[0] != key {
			continue
		}
		value := ""
		if len(trimmed) > len(key) {
			value = strings.TrimSpace(trimmed[len(key):])
		}
		values = append(values, value)
	}
	return values
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsLegacyLegoV4Form(text string) (bool, string) {
	for _, stale := range []string{" renew --renew-hook", "--run-hook", "--renew-hook", "LEGO_CERT_", "LEGO_ACCOUNT_EMAIL"} {
		if strings.Contains(text, stale) {
			return true, stale
		}
	}
	return false, ""
}

func validateStagedRuntimeSet(cfg appconfig.Config, staged []apprender.StagedFile) error {
	expected, err := appassets.RuntimeCatalog(cfg)
	if err != nil {
		return err
	}
	expectedBySource := make(map[string]appassets.Asset, len(expected))
	for _, asset := range expected {
		expectedBySource[asset.SourcePath] = asset
	}
	seen := make(map[string]struct{}, len(staged))
	for _, file := range staged {
		asset, ok := expectedBySource[file.SourcePath]
		if !ok {
			return fmt.Errorf("rendered unexpected app runtime file: %s", file.SourcePath)
		}
		if _, exists := seen[file.SourcePath]; exists {
			return fmt.Errorf("rendered duplicate app runtime file: %s", file.SourcePath)
		}
		seen[file.SourcePath] = struct{}{}
		if strings.TrimSpace(file.HostPath) == "" {
			return fmt.Errorf("%s is missing host path", file.SourcePath)
		}
		if file.HostPath != asset.HostPath {
			return fmt.Errorf("%s host path does not match runtime catalog: %s != %s", file.SourcePath, file.HostPath, asset.HostPath)
		}
		if file.ContentMode != asset.ContentMode || file.Mode != asset.Mode {
			return fmt.Errorf("%s render mode or file permissions do not match runtime catalog", file.SourcePath)
		}
	}
	for _, asset := range expected {
		if _, ok := seen[asset.SourcePath]; !ok {
			return fmt.Errorf("missing app runtime file: %s", asset.SourcePath)
		}
	}
	return nil
}

func (report Report) FailedCount() int {
	count := 0
	for _, check := range report.Checks {
		if check.Status == StatusFail {
			count++
		}
	}
	return count
}

func (report Report) Summary() string {
	if report.FailedCount() > 0 {
		return fmt.Sprintf("app verify found %d failed checks", report.FailedCount())
	}
	return "app static checks passed"
}

func SummarizeChecks(checks []Check) string {
	parts := make([]string, 0, len(checks))
	for _, check := range checks {
		parts = append(parts, check.ID+"="+string(check.Status))
	}
	return strings.Join(parts, ", ")
}

func containsSensitiveValue(text string) (bool, string, error) {
	lower := strings.ToLower(text)
	for _, prefix := range []string{"authkey-", "tskey-auth-", "hskey-auth-"} {
		if strings.Contains(lower, prefix) {
			return true, prefix, nil
		}
	}
	for _, line := range strings.Split(text, "\n") {
		keys, err := envAssignmentKeys(line)
		if err != nil {
			return false, "", err
		}
		for _, key := range keys {
			if isRawCredentialKey(key) {
				return true, key, nil
			}
		}
	}
	return false, "", nil
}

func envAssignmentKeys(line string) ([]string, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return nil, nil
	}
	if directive, ok := systemdDirectiveFromLine(line); ok && directive.Key == "Environment" {
		keys := []string{}
		assignments, err := systemdEnvironmentAssignments(directive.Value)
		if err != nil {
			return nil, fmt.Errorf("Environment directive must use valid systemd assignment syntax: %w", err)
		}
		for _, assignment := range assignments {
			key, _, ok := strings.Cut(assignment, "=")
			if !ok {
				continue
			}
			key = strings.ToUpper(strings.TrimSpace(key))
			if key != "" {
				keys = append(keys, key)
			}
		}
		return keys, nil
	}
	line = strings.TrimPrefix(line, "export ")
	key, _, ok := strings.Cut(line, "=")
	if !ok {
		return nil, nil
	}
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return nil, nil
	}
	return []string{key}, nil
}

func systemdEnvironmentAssignments(value string) ([]string, error) {
	assignments := []string{}
	var builder strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if builder.Len() == 0 {
			return
		}
		assignments = append(assignments, builder.String())
		builder.Reset()
	}

	for _, r := range value {
		if escaped {
			builder.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			builder.WriteRune(r)
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
		case unicode.IsSpace(r):
			flush()
		default:
			builder.WriteRune(r)
		}
	}
	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return assignments, nil
}

func isRawCredentialKey(key string) bool {
	if strings.HasSuffix(key, "_FILE") {
		return false
	}
	return strings.Contains(key, "TOKEN") ||
		strings.Contains(key, "PASSWORD") ||
		strings.Contains(key, "SECRET") ||
		strings.Contains(key, "API_KEY") ||
		key == "AWS_ACCESS_KEY_ID"
}
