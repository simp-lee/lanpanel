package ui

import (
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/components/headscale"
	legocomponent "lanpanel/internal/components/lego"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/resource"
	"lanpanel/internal/workflow"
	"path/filepath"
)

func mainConfigFormHTML(path string, cfg config.Config) string {
	sections := formSection("Server", input("Config path", "config_path", path)+
		input("Server URL", "server_url", cfg.Default.ServerURL)+
		input("Base domain", "base_domain", cfg.Default.BaseDomain)+
		input("Certificate email", "certificate_email", cfg.Default.CertificateEmail)+
		selectInput("ACME challenge", "acme_challenge", cfg.Default.ACMEChallenge, []string{config.ACMEChallengeHTTP01, config.ACMEChallengeDNS01})) +
		formSection("Package sources", selectInput("Headscale source", "headscale_source_mode", cfg.Advanced.HeadscaleSource.Mode, []string{config.PackageSourceModeDirect, config.PackageSourceModeMirror, config.PackageSourceModeOffline})+
			input("Headscale version", "headscale_source_version", cfg.Advanced.HeadscaleSource.Version)+
			input("Headscale source URL", "headscale_source_url", cfg.Advanced.HeadscaleSource.URL)+
			input("Headscale SHA-256", "headscale_source_sha256", cfg.Advanced.HeadscaleSource.SHA256)+
			input("Headscale file path", "headscale_source_file_path", cfg.Advanced.HeadscaleSource.FilePath)+
			input("Headscale metrics port", "headscale_metrics_port", fmt.Sprintf("%d", cfg.Advanced.Headscale.MetricsPort))+
			selectInput("Lego source", "lego_source_mode", cfg.Advanced.LegoSource.Mode, []string{config.PackageSourceModeDirect, config.PackageSourceModeOffline})+
			input("Lego file path", "lego_source_file_path", cfg.Advanced.LegoSource.FilePath)+
			input("Package probe reachability", "package_probe_reachability_timeout", cfg.Advanced.PackageProbe.ReachabilityTimeout)+
			input("Package probe artifact", "package_probe_artifact_timeout", cfg.Advanced.PackageProbe.ArtifactTimeout)) +
		formSection("Network and DNS", input("HTTP proxy", "http_proxy", cfg.Advanced.Proxy.HTTPProxy)+
			input("HTTPS proxy", "https_proxy", cfg.Advanced.Proxy.HTTPSProxy)+
			input("No proxy", "no_proxy", cfg.Advanced.Proxy.NoProxy)+
			input("DNS-01 provider", "dns01_provider", cfg.Advanced.DNS01.Provider)+
			input("DNS-01 env file", "dns01_env_file", cfg.Advanced.DNS01.EnvFile)+
			input("Public IPv4 override", "public_ipv4", cfg.Advanced.Network.PublicIPv4)+
			input("Public IPv6 override", "public_ipv6", cfg.Advanced.Network.PublicIPv6)+
			selectInput("Platform arch", "platform_arch", cfg.Advanced.Platform.Arch, []string{config.ArchAMD64, config.ArchARM64}))
	return `<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
` + sections + `
<div class="toolbar">
  <button type="submit" name="operation" value="main_config_save">Save</button>
</div>
</form>` + mainDependencyUploadFormsHTML(path, cfg) + `<div class="toolbar">` +
		jobButtonHTML("main_verify", "Verify", "secondary", path, "", "") +
		jobButtonHTML("main_deploy", "Deploy", "secondary", path, "", "") +
		`</div>`
}

func appConfigFormHTML(path string, cfg appconfig.Config, appDeployConfirmations []string, realIPRefreshConfirmations []string) string {
	mode := string(cfg.Mode())
	if mode == "" {
		mode = string(appconfig.ModeListen)
	}
	origin := string(cfg.Access.OriginProtection.Mode)
	if origin == "" {
		origin = string(appconfig.OriginProtectionModeNone)
	}
	access := string(cfg.Access.AccessMode)
	sections := formDisclosureSection("Resource", input("App config path", "app_config_path", path)+
		input("App name", "app_name", cfg.App.Name)+
		textarea("Domains", "app_domains", joinList(cfg.App.Domains))+
		input("Certificate email", "app_certificate_email", cfg.App.CertificateEmail)+
		selectInput("ACME challenge", "app_acme_challenge", cfg.App.ACMEChallenge, []string{appconfig.ACMEChallengeHTTP01, appconfig.ACMEChallengeDNS01})+
		selectInput("Target mode", "app_target_mode", mode, []string{string(appconfig.ModeListen), string(appconfig.ModeUpstream)})+
		input("Listen", "app_listen", cfg.App.Listen)+
		input("Tailnet upstream", "app_upstream", cfg.App.Upstream), true) +
		formDisclosureSection("Access", accessModeInput(access)+
			checkbox("Public risk confirmed", "public_risk_confirmed", cfg.Access.PublicRiskConfirmed)+
			textarea("CIDR allowlist", "cidr_allowlist", joinList(cfg.Access.CIDRAllowlist))+
			input("External browser auth file", "browser_auth_file", cfg.Access.BrowserAuth.AuthBasicUserFile)+
			input("Managed browser auth ID", "browser_auth_credential_id", cfg.Access.BrowserAuth.Managed.CredentialID)+
			input("Managed htpasswd path", "browser_auth_managed_path", cfg.Access.BrowserAuth.Managed.HtpasswdPath)+
			input("Managed username", "browser_auth_username", cfg.Access.BrowserAuth.Managed.Username)+
			input("Password fingerprint", "browser_auth_password_fingerprint", cfg.Access.BrowserAuth.Managed.PasswordFingerprint), true) +
		formDisclosureSection("Origin protection", selectInput("Origin protection", "origin_mode", origin, []string{string(appconfig.OriginProtectionModeNone), string(appconfig.OriginProtectionModeEdgeOne)})+
			checkbox("Direct origin risk confirmed", "direct_origin_risk_confirmed", cfg.Access.OriginProtection.DirectOriginRiskConfirmed)+
			input("EdgeOne profile", "edgeone_profile", cfg.Access.OriginProtection.EdgeOneProfile)+
			checkbox("EdgeOne profile enabled", "edgeone_profile_enabled", edgeOneEnabled(cfg))+
			input("EdgeOne zone ID", "edgeone_zone_id", edgeOneZoneID(cfg))+
			input("EdgeOne env file", "edgeone_env_file", edgeOneEnvFile(cfg))+
			input("EdgeOne refresh interval", "edgeone_refresh_interval", edgeOneRefreshInterval(cfg)), true) +
		formDisclosureSection("Runtime service", input("Service exec start", "service_exec_start", cfg.Service.ExecStart)+
			input("Working directory", "service_working_directory", cfg.Service.WorkingDirectory)+
			input("Service env file", "service_env_file", cfg.Service.EnvFile)+
			input("Client max body size", "nginx_client_max_body_size", cfg.Nginx.EffectiveClientMaxBodySize()), false) +
		formDisclosureSection("Nginx and observability", checkbox("Nginx HTTP/2", "nginx_http2", cfg.Nginx.HTTP2Enabled())+
			input("Access log", "nginx_access_log", cfg.Nginx.AccessLog)+
			input("Error log", "nginx_error_log", cfg.Nginx.ErrorLog)+
			input("Proxy connect timeout", "proxy_connect_timeout", cfg.Nginx.Proxy.ConnectTimeout)+
			input("Proxy read timeout", "proxy_read_timeout", cfg.Nginx.Proxy.ReadTimeout)+
			input("Proxy send timeout", "proxy_send_timeout", cfg.Nginx.Proxy.SendTimeout)+
			checkbox("GoAccess enabled", "goaccess_enabled", cfg.Nginx.GoAccess.Enabled)+
			selectInput("GoAccess language", "goaccess_language", cfg.Nginx.GoAccess.EffectiveLanguage(), []string{appconfig.NginxGoAccessLanguageEnglish, appconfig.NginxGoAccessLanguageSimplifiedChinese})+
			selectInput("GoAccess log format", "goaccess_log_format", cfg.Nginx.GoAccess.EffectiveLogFormat(), []string{appconfig.NginxGoAccessLogFormatEnhanced, appconfig.NginxGoAccessLogFormatCombined})+
			input("GoAccess auth file", "goaccess_auth_file", cfg.Nginx.GoAccess.AuthBasicUserFile)+
			textarea("GoAccess CIDR allowlist", "goaccess_cidr_allowlist", joinList(cfg.Nginx.GoAccess.AuthCIDRAllowlist))+
			input("GoAccess path", "goaccess_path", cfg.Nginx.GoAccess.Path)+
			input("GoAccess websocket path", "goaccess_websocket_path", cfg.Nginx.GoAccess.WebSocketPath)+
			input("GoAccess websocket listen", "goaccess_websocket_listen", cfg.Nginx.GoAccess.WebSocketListen), false) +
		formDisclosureSection("Dependencies", selectInput("Lego source", "app_lego_source_mode", cfg.Dependencies.LegoSource.Mode, []string{config.PackageSourceModeDirect, config.PackageSourceModeOffline})+
			input("Lego file path", "app_lego_source_file_path", cfg.Dependencies.LegoSource.FilePath)+
			input("Package probe reachability", "app_package_probe_reachability_timeout", cfg.Dependencies.PackageProbe.ReachabilityTimeout)+
			input("Package probe artifact", "app_package_probe_artifact_timeout", cfg.Dependencies.PackageProbe.ArtifactTimeout)+
			input("HTTP proxy", "app_http_proxy", cfg.Dependencies.Proxy.HTTPProxy)+
			input("HTTPS proxy", "app_https_proxy", cfg.Dependencies.Proxy.HTTPSProxy)+
			input("No proxy", "app_no_proxy", cfg.Dependencies.Proxy.NoProxy)+
			selectInput("Platform arch", "app_platform_arch", cfg.Dependencies.Platform.Arch, []string{config.ArchAMD64, config.ArchARM64}), false) +
		formDisclosureSection("Tailnet and DNS", input("App DNS-01 provider", "app_dns01_provider", cfg.DNS01.Provider)+
			input("App DNS-01 env file", "app_dns01_env_file", cfg.DNS01.EnvFile)+
			checkbox("Tailscale for listen", "tailscale_enabled_for_listen", cfg.Tailscale.EnabledForListen)+
			input("Tailscale lanpanel config", "tailscale_lanpanel_config", cfg.Tailscale.LanpanelConfig)+
			input("Tailscale login server", "tailscale_login_server", cfg.Tailscale.LoginServer)+
			input("Tailscale hostname", "tailscale_hostname", cfg.Tailscale.Hostname)+
			input("Tailscale auth key file", "tailscale_auth_key_file", cfg.Tailscale.AuthKeyFile), false)
	return `<form id="app-config-form" method="post" action="/jobs/run">
	<input type="hidden" name="csrf_token" value="__CSRF__">
	<div class="resource-actionbar">
	  <button type="submit" name="operation" value="app_config_save">Save</button>
	  <button type="submit" hx-post="/fragments/exposure-preview" hx-target="#exposure-preview" hx-swap="innerHTML" class="secondary">Preview Exposure</button>
	</div>
	<div class="config-sections">` + sections + `</div>
	</form>` + appDependencyUploadFormsHTML(path, cfg) + `<div class="toolbar resource-job-actions">` +
		jobButtonHTML("app_verify", "Verify", "secondary", "", path, "") +
		appDeployButtonHTML(path, appDeployConfirmations) +
		`</div>` + realIPFormsHTML(path, cfg, realIPRefreshConfirmations)
}

func mainDependencyUploadFormsHTML(path string, cfg config.Config) string {
	arch := cfg.Advanced.Platform.Arch
	legoArchive := legocomponent.OfficialArchiveAssetName(legocomponent.Version, arch)
	headscalePackage := headscale.OfficialPackageAssetName(headscale.Version, arch)
	return dependencyUploadSectionHTML(`<div class="grid">` +
		dependencyUploadFormHTML("Upload lego archive", "main_lego_archive_upload", "config_path", path, "Expected archive", legoArchive, ".tar.gz") +
		dependencyUploadFormHTML("Upload Headscale deb", "main_headscale_deb_upload", "config_path", path, "Expected package", headscalePackage, ".deb") +
		`</div>`)
}

func appDependencyUploadFormsHTML(path string, cfg appconfig.Config) string {
	arch := cfg.Dependencies.Platform.Arch
	legoArchive := legocomponent.OfficialArchiveAssetName(legocomponent.Version, arch)
	return dependencyUploadSectionHTML(`<div class="grid">` +
		dependencyUploadFormHTML("Upload lego archive", "app_lego_archive_upload", "app_config_path", path, "Expected archive", legoArchive, ".tar.gz") +
		`</div>`)
}

func dependencyUploadSectionHTML(body string) string {
	return `<section class="form-section"><h3>Dependency Uploads</h3>` + body + `</section>`
}

func dependencyUploadFormHTML(title string, operation string, pathField string, path string, expectedLabel string, expectedName string, accept string) string {
	fileID := fieldID(operation + "_" + dependencyUploadFileField)
	return miniPanel(title, `<form method="post" action="/jobs/run" enctype="multipart/form-data">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="`+esc(operation)+`">
<input type="hidden" name="`+esc(pathField)+`" value="`+esc(path)+`">
`+readonlyInput(expectedLabel, operation+"_expected_artifact", expectedName)+`
<div class="field"><label for="`+esc(fileID)+`">Artifact file</label><input id="`+esc(fileID)+`" type="file" name="`+esc(dependencyUploadFileField)+`" accept="`+esc(accept)+`" required></div>
<button type="submit">Upload</button></form>`)
}

func realIPFormsHTML(path string, cfg appconfig.Config, refreshConfirmations []string) string {
	profile := cfg.Access.OriginProtection.EdgeOneProfile
	if profile == "" {
		profile = "edgeone-prod"
	}
	return `<div class="action-grid">
` + jobButtonHTML("realip_diagnostics", "RealIP Diagnostics", "secondary", "", path, profile) +
		`<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="realip_refresh">
<input type="hidden" name="app_config_path" value="` + esc(path) + `">
<input type="hidden" name="profile" value="` + esc(profile) + `">
	` + exposureConfirmationControlsHTML(refreshConfirmations) + `
	<button type="submit" class="secondary">RealIP Refresh</button></form>
<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="realip_validate_reference">
<input type="hidden" name="app_config_path" value="` + esc(path) + `">
<input type="hidden" name="profile" value="` + esc(profile) + `">
` + input("Reference app", "realip_reference_app", cfg.App.Name) +
		input("Reference path", "realip_reference_path", "") +
		`<button type="submit" class="secondary">Validate RealIP Reference</button></form>` +
		`</div>`
}

func browserAuthFormsHTML(appConfigPath string, cfg appconfig.Config) string {
	id := cfg.App.Name
	if id == "" {
		id = "example-app"
	}
	path := cfg.Access.BrowserAuth.Managed.HtpasswdPath
	if path == "" {
		path = defaultBrowserAuthPath(id)
	}
	return panel("Browser Auth Credentials", `<div class="grid">`+
		miniPanel("Create", `<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="browser_auth_create">
`+input("Directory", "browser_auth_dir", "/etc/lanpanel/browser-auth")+
			input("Credential ID", "browser_auth_id", id)+
			input("Username", "browser_auth_create_username", "admin")+
			passwordInput("Password", "browser_auth_create_password")+
			`<button type="submit">Create</button></form>`)+
		miniPanel("Rotate", `<form method="post" action="/jobs/run">
	<input type="hidden" name="csrf_token" value="__CSRF__">
	<input type="hidden" name="operation" value="browser_auth_rotate">
	<input type="hidden" name="app_config_path" value="`+esc(appConfigPath)+`">
	`+input("Htpasswd path", "browser_auth_rotate_path", path)+
			input("Username", "browser_auth_rotate_username", cfg.Access.BrowserAuth.Managed.Username)+
			passwordInput("Password", "browser_auth_rotate_password")+
			`<button type="submit">Rotate</button></form>`)+
		miniPanel("Delete", `<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="browser_auth_delete">
`+input("Htpasswd path", "browser_auth_delete_path", path)+
			`<button type="submit">Delete</button></form>`)+
		`</div>`)
}

func preauthFormHTML() string {
	return `<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="preauth_key_create">
` + input("User", "preauth_user", "lanpanel") +
		input("TTL", "preauth_ttl", "24h") +
		`<button type="submit">Create One-Time Key</button></form>`
}

func jobButtonHTML(operation string, label string, class string, configPath string, appConfigPath string, profile string) string {
	if class != "" {
		class = ` class="` + esc(class) + `"`
	}
	return `<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="` + esc(operation) + `">
<input type="hidden" name="config_path" value="` + esc(configPath) + `">
<input type="hidden" name="app_config_path" value="` + esc(appConfigPath) + `">
<input type="hidden" name="profile" value="` + esc(profile) + `">
<button type="submit"` + class + `>` + esc(label) + `</button></form>`
}

func appDeployButtonHTML(appConfigPath string, confirmations []string) string {
	return `<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="app_deploy">
<input type="hidden" name="app_config_path" value="` + esc(appConfigPath) + `">
	` + exposureConfirmationControlsHTML(confirmations) + `
	<button type="submit" class="secondary">Deploy</button></form>`
}

func exposureConfirmationControlsHTML(confirmations []string) string {
	body := ""
	for _, confirmation := range confirmations {
		body += confirmationCheckbox(confirmation, exposureConfirmationLabel(confirmation))
	}
	return body
}

func exposureConfirmationLabel(confirmation string) string {
	switch confirmation {
	case "public-app-risk":
		return "Public internet exposure confirmed"
	case "direct-origin-risk":
		return "Direct origin exposure confirmed"
	case "origin-protection-manual":
		return "EdgeOne origin protection/firewall manually confirmed"
	default:
		panic("unsupported exposure confirmation " + confirmation)
	}
}

func initConfigFormHTML(operation string, label string, pathField string, path string) string {
	return `<form method="post" action="/jobs/run">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input type="hidden" name="operation" value="` + esc(operation) + `">
<input type="hidden" name="` + esc(pathField) + `" value="` + esc(path) + `">
<button type="submit">` + esc(label) + `</button></form>`
}

func input(label string, name string, value string) string {
	id := fieldID(name)
	return `<div class="field"><label for="` + esc(id) + `">` + esc(label) + `</label><input id="` + esc(id) + `" name="` + esc(name) + `" value="` + esc(value) + `"></div>`
}

func passwordInput(label string, name string) string {
	id := fieldID(name)
	return `<div class="field"><label for="` + esc(id) + `">` + esc(label) + `</label><input id="` + esc(id) + `" type="password" name="` + esc(name) + `" value=""></div>`
}

func textarea(label string, name string, value string) string {
	id := fieldID(name)
	return `<div class="field"><label for="` + esc(id) + `">` + esc(label) + `</label><textarea id="` + esc(id) + `" name="` + esc(name) + `">` + esc(value) + `</textarea></div>`
}

func checkbox(label string, name string, checked bool) string {
	attr := ""
	if checked {
		attr = " checked"
	}
	return `<div class="field field-checkbox"><label class="checkbox-line"><input type="checkbox" name="` + esc(name) + `"` + attr + `><span>` + esc(label) + `</span></label></div>`
}

func accessModeInput(selected string) string {
	input := requiredSelectInput("Access mode", "access_mode", selected, []string{string(appconfig.AccessModeBrowser), string(appconfig.AccessModePublic)})
	if selected != string(appconfig.AccessModePrivateClient) {
		return input
	}
	return readonlyInput("Current access mode", "current_access_mode", selected) + requiredSelectInput("Access mode", "access_mode", "", []string{string(appconfig.AccessModeBrowser), string(appconfig.AccessModePublic)})
}

func readonlyInput(label string, name string, value string) string {
	id := fieldID(name)
	return `<div class="field"><label for="` + esc(id) + `">` + esc(label) + `</label><input id="` + esc(id) + `" value="` + esc(value) + `" readonly disabled></div>`
}

func confirmationCheckbox(value string, label string) string {
	return `<label class="checkbox-line"><input type="checkbox" name="confirmation" value="` + esc(value) + `"><span>` + esc(label) + `</span></label>`
}

func selectInput(label string, name string, selected string, options []string) string {
	return selectInputWithPlaceholder(label, name, selected, options, "")
}

func requiredSelectInput(label string, name string, selected string, options []string) string {
	return selectInputWithPlaceholder(label, name, selected, options, "Select "+label)
}

func selectInputWithPlaceholder(label string, name string, selected string, options []string, placeholder string) string {
	id := fieldID(name)
	body := `<div class="field"><label for="` + esc(id) + `">` + esc(label) + `</label><select id="` + esc(id) + `" name="` + esc(name) + `">`
	if placeholder != "" {
		attr := ""
		if selected == "" {
			attr = " selected"
		}
		body += `<option value=""` + attr + `>` + esc(placeholder) + `</option>`
	}
	for _, option := range options {
		attr := ""
		if option == selected {
			attr = " selected"
		}
		body += `<option value="` + esc(option) + `"` + attr + `>` + esc(option) + `</option>`
	}
	return body + `</select></div>`
}

func formSection(title string, fields string) string {
	return `<section class="form-section"><h3>` + esc(title) + `</h3><div class="field-grid">` + fields + `</div></section>`
}

func formDisclosureSection(title string, fields string, open bool) string {
	openAttr := ""
	if open {
		openAttr = " open"
	}
	return `<details class="config-section"` + openAttr + `><summary>` + esc(title) + `</summary><div class="field-grid">` + fields + `</div></details>`
}

func fieldID(name string) string {
	return "field-" + name
}

func edgeOneProfile(cfg appconfig.Config) (appconfig.RealIPProfileConfig, bool) {
	return cfg.RealIPProfile(cfg.Access.OriginProtection.EdgeOneProfile)
}

func edgeOneEnabled(cfg appconfig.Config) bool {
	profile, ok := edgeOneProfile(cfg)
	return ok && profile.IsEnabled()
}

func edgeOneZoneID(cfg appconfig.Config) string {
	profile, ok := edgeOneProfile(cfg)
	if !ok {
		return ""
	}
	return profile.EdgeOne.ZoneID
}

func edgeOneEnvFile(cfg appconfig.Config) string {
	profile, ok := edgeOneProfile(cfg)
	if !ok {
		return ""
	}
	return profile.EdgeOne.EnvFile
}

func edgeOneRefreshInterval(cfg appconfig.Config) string {
	profile, ok := edgeOneProfile(cfg)
	if !ok {
		return ""
	}
	return profile.EffectiveRefreshInterval()
}

func runMainDiagnostics(path string, version string) []domain.DiagnosticItem {
	result, err := workflow.RunMainVerify(workflow.Context{Version: version}, path)
	if err != nil {
		return []domain.DiagnosticItem{{ID: "main-config", Status: domain.DiagnosticStatusFail, Summary: err.Error()}}
	}
	return result.Diagnostics
}

func runAppDiagnostics(path string, stateDir string, version string, hostWorkflow workflow.HostWorkflow) []domain.DiagnosticItem {
	result, err := workflow.RunAppVerify(workflow.Context{
		Version:      version,
		HostWorkflow: hostWorkflow,
		AppInstanceIDProvider: func() (string, string, error) {
			instance, err := resource.NewStore(filepath.Join(stateDir, "resources")).LoadInstance()
			if err != nil {
				return "", "", err
			}
			return instance.ID, "persisted resource state", nil
		},
	}, path, "")
	if err != nil {
		return []domain.DiagnosticItem{{ID: "app-config", Status: domain.DiagnosticStatusFail, Summary: err.Error()}}
	}
	return result.Diagnostics
}
