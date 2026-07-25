package ui

import (
	"errors"
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/config"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultPreAuthTTL = 24 * time.Hour

func (server *Server) mainConfigPath(r *http.Request) (string, error) {
	path := strings.TrimSpace(r.FormValue("config_path"))
	if path == "" {
		path = server.options.ConfigPath
	}
	clean, err := canonicalMainConfigPath(path)
	if err != nil {
		return "", err
	}
	configured, err := canonicalMainConfigPath(server.options.ConfigPath)
	if err != nil {
		return "", err
	}
	if clean != configured {
		return "", fmt.Errorf("main config path must match configured UI path %s", configured)
	}
	return clean, nil
}

func (server *Server) appConfigPath(r *http.Request) (string, error) {
	path := strings.TrimSpace(r.FormValue("app_config_path"))
	if path == "" {
		path = server.options.AppConfigPath
	}
	clean, err := canonicalAppConfigPath(path)
	if err != nil {
		return "", err
	}
	if err := server.validateAppConfigPath(clean); err != nil {
		return "", err
	}
	return clean, nil
}

func (server *Server) mainConfigFromRequest(r *http.Request) (string, config.Config, error) {
	if err := r.ParseForm(); err != nil {
		return "", config.Config{}, fmt.Errorf("parse main config form: %w", err)
	}
	path, err := server.mainConfigPath(r)
	if err != nil {
		return "", config.Config{}, err
	}
	cfg := config.New()
	cfg.APIVersion = config.APIVersion
	cfg.Default.ServerURL = formValue(r, "server_url")
	cfg.Default.BaseDomain = formValue(r, "base_domain")
	cfg.Default.CertificateEmail = formValue(r, "certificate_email")
	cfg.Default.ACMEChallenge = formValue(r, "acme_challenge")
	cfg.Advanced.HeadscaleSource.Mode = formValue(r, "headscale_source_mode")
	cfg.Advanced.HeadscaleSource.Version = formValue(r, "headscale_source_version")
	cfg.Advanced.HeadscaleSource.URL = formValue(r, "headscale_source_url")
	cfg.Advanced.HeadscaleSource.SHA256 = formValue(r, "headscale_source_sha256")
	cfg.Advanced.HeadscaleSource.FilePath = formValue(r, "headscale_source_file_path")
	metricsPort, err := intForm(r, "headscale_metrics_port")
	if err != nil {
		return "", config.Config{}, err
	}
	cfg.Advanced.Headscale.MetricsPort = metricsPort
	cfg.Advanced.LegoSource.Mode = formValue(r, "lego_source_mode")
	cfg.Advanced.LegoSource.FilePath = formValue(r, "lego_source_file_path")
	cfg.Advanced.PackageProbe.ReachabilityTimeout = formValue(r, "package_probe_reachability_timeout")
	cfg.Advanced.PackageProbe.ArtifactTimeout = formValue(r, "package_probe_artifact_timeout")
	cfg.Advanced.Proxy.HTTPProxy = formValue(r, "http_proxy")
	cfg.Advanced.Proxy.HTTPSProxy = formValue(r, "https_proxy")
	cfg.Advanced.Proxy.NoProxy = formValue(r, "no_proxy")
	cfg.Advanced.DNS01.Provider = formValue(r, "dns01_provider")
	cfg.Advanced.DNS01.EnvFile = formValue(r, "dns01_env_file")
	cfg.Advanced.Network.PublicIPv4 = formValue(r, "public_ipv4")
	cfg.Advanced.Network.PublicIPv6 = formValue(r, "public_ipv6")
	cfg.Advanced.Platform.Arch = formValue(r, "platform_arch")
	return path, cfg, nil
}

func (server *Server) appConfigFromRequest(r *http.Request) (string, appconfig.Config, error) {
	if err := r.ParseForm(); err != nil {
		return "", appconfig.Config{}, fmt.Errorf("parse app config form: %w", err)
	}
	path, err := server.appConfigPath(r)
	if err != nil {
		return "", appconfig.Config{}, err
	}
	cfg, err := appConfigBaseForForm(path)
	if err != nil {
		return "", appconfig.Config{}, err
	}
	cfg.APIVersion = appconfig.APIVersion
	cfg.App.Name = formValue(r, "app_name")
	cfg.App.Domains = splitList(formValue(r, "app_domains"))
	cfg.App.CertificateEmail = formValue(r, "app_certificate_email")
	cfg.App.ACMEChallenge = formValue(r, "app_acme_challenge")
	switch formValue(r, "app_target_mode") {
	case string(appconfig.ModeListen):
		cfg.App.Listen = formValue(r, "app_listen")
		cfg.App.Upstream = ""
	case string(appconfig.ModeUpstream):
		cfg.App.Listen = ""
		cfg.App.Upstream = formValue(r, "app_upstream")
	default:
		cfg.App.Listen = formValue(r, "app_listen")
		cfg.App.Upstream = formValue(r, "app_upstream")
	}
	cfg.Access.AccessMode = appconfig.AccessMode(formValue(r, "access_mode"))
	if cfg.Access.AccessMode == appconfig.AccessModePrivateClient {
		return "", appconfig.Config{}, fmt.Errorf("access.access_mode is reserved for P1 and cannot be managed from the P0 UI")
	}
	cfg.Access.CIDRAllowlist = splitList(formValue(r, "cidr_allowlist"))
	cfg.Access.PublicRiskConfirmed = boolForm(r, "public_risk_confirmed")
	cfg.Access.BrowserAuth.AuthBasicUserFile = formValue(r, "browser_auth_file")
	cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        formValue(r, "browser_auth_credential_id"),
		HtpasswdPath:        formValue(r, "browser_auth_managed_path"),
		Username:            formValue(r, "browser_auth_username"),
		PasswordFingerprint: formValue(r, "browser_auth_password_fingerprint"),
	}
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionMode(formValue(r, "origin_mode"))
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = boolForm(r, "direct_origin_risk_confirmed")
	cfg.Access.OriginProtection.EdgeOneProfile = formValue(r, "edgeone_profile")
	cfg.Service.ExecStart = formValue(r, "service_exec_start")
	cfg.Service.WorkingDirectory = formValue(r, "service_working_directory")
	cfg.Service.EnvFile = formValue(r, "service_env_file")
	cfg.Nginx.ClientMaxBodySize = formValue(r, "nginx_client_max_body_size")
	cfg.Nginx.AccessLog = formValue(r, "nginx_access_log")
	cfg.Nginx.ErrorLog = formValue(r, "nginx_error_log")
	cfg.Nginx.Proxy.ConnectTimeout = formValue(r, "proxy_connect_timeout")
	cfg.Nginx.Proxy.ReadTimeout = formValue(r, "proxy_read_timeout")
	cfg.Nginx.Proxy.SendTimeout = formValue(r, "proxy_send_timeout")
	http2 := boolForm(r, "nginx_http2")
	cfg.Nginx.HTTP2 = &http2
	cfg.Nginx.GoAccess.Enabled = boolForm(r, "goaccess_enabled")
	if cfg.Nginx.GoAccess.Enabled {
		cfg.Nginx.GoAccess.Language = formValue(r, "goaccess_language")
		cfg.Nginx.GoAccess.LogFormat = formValue(r, "goaccess_log_format")
		cfg.Nginx.GoAccess.AuthBasicUserFile = formValue(r, "goaccess_auth_file")
		cfg.Nginx.GoAccess.AuthCIDRAllowlist = splitList(formValue(r, "goaccess_cidr_allowlist"))
		cfg.Nginx.GoAccess.Path = formValue(r, "goaccess_path")
		cfg.Nginx.GoAccess.WebSocketPath = formValue(r, "goaccess_websocket_path")
		cfg.Nginx.GoAccess.WebSocketListen = formValue(r, "goaccess_websocket_listen")
	} else {
		cfg.Nginx.GoAccess = appconfig.NginxGoAccessConfig{}
	}
	cfg.Dependencies.LegoSource.Mode = formValue(r, "app_lego_source_mode")
	cfg.Dependencies.LegoSource.FilePath = formValue(r, "app_lego_source_file_path")
	cfg.Dependencies.PackageProbe.ReachabilityTimeout = formValue(r, "app_package_probe_reachability_timeout")
	cfg.Dependencies.PackageProbe.ArtifactTimeout = formValue(r, "app_package_probe_artifact_timeout")
	cfg.Dependencies.Proxy.HTTPProxy = formValue(r, "app_http_proxy")
	cfg.Dependencies.Proxy.HTTPSProxy = formValue(r, "app_https_proxy")
	cfg.Dependencies.Proxy.NoProxy = formValue(r, "app_no_proxy")
	cfg.Dependencies.Platform.Arch = formValue(r, "app_platform_arch")
	cfg.DNS01.Provider = formValue(r, "app_dns01_provider")
	cfg.DNS01.EnvFile = formValue(r, "app_dns01_env_file")
	cfg.Tailscale.EnabledForListen = boolForm(r, "tailscale_enabled_for_listen")
	cfg.Tailscale.LanpanelConfig = formValue(r, "tailscale_lanpanel_config")
	cfg.Tailscale.LoginServer = formValue(r, "tailscale_login_server")
	cfg.Tailscale.Hostname = formValue(r, "tailscale_hostname")
	cfg.Tailscale.AuthKeyFile = formValue(r, "tailscale_auth_key_file")
	if profileName := formValue(r, "edgeone_profile"); profileName != "" {
		enabled := boolForm(r, "edgeone_profile_enabled")
		if cfg.RealIP.Profiles == nil {
			cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{}
		}
		profile := cfg.RealIP.Profiles[profileName]
		profile.Enabled = &enabled
		profile.Provider = appconfig.RealIPProviderEdgeOne
		profile.RefreshInterval = formValue(r, "edgeone_refresh_interval")
		profile.EdgeOne = appconfig.RealIPEdgeOneConfig{
			ZoneID:  formValue(r, "edgeone_zone_id"),
			EnvFile: formValue(r, "edgeone_env_file"),
		}
		cfg.RealIP.Profiles[profileName] = profile
	}
	return path, cfg, nil
}

func appConfigBaseForForm(path string) (appconfig.Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return appconfig.New(), nil
		}
		return appconfig.Config{}, fmt.Errorf("stat existing app config file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return appconfig.Config{}, fmt.Errorf("existing app config file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return appconfig.Config{}, fmt.Errorf("existing app config path must be a regular file")
	}
	cfg, err := appconfig.LoadFile(path)
	if err != nil {
		return appconfig.Config{}, fmt.Errorf("load existing app config before form save: %w", err)
	}
	return cfg, nil
}
func formValue(r *http.Request, name string) string {
	return strings.TrimSpace(r.FormValue(name))
}

func boolForm(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.FormValue(name))) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

func intForm(r *http.Request, name string) (int, error) {
	value := strings.TrimSpace(r.FormValue(name))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	return parsed, nil
}

func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	})
	items := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			items = append(items, field)
		}
	}
	return items
}

func joinList(values []string) string {
	return strings.Join(values, "\n")
}

func defaultBrowserAuthPath(appName string) string {
	appName = strings.TrimSpace(appName)
	if appName == "" {
		appName = "example-app"
	}
	return filepath.Join("/etc/lanpanel/browser-auth", appName+".htpasswd")
}

func canonicalMainConfigPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("main config path is required")
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("main config path must not contain control characters")
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve main config path: %w", err)
	}
	clean := filepath.Clean(absolute)
	if clean == "." || !filepath.IsAbs(clean) {
		return "", fmt.Errorf("main config path must resolve to a clean absolute path")
	}
	return clean, nil
}

func (server *Server) validateAppConfigPath(path string) error {
	configured, err := canonicalAppConfigPath(server.options.AppConfigPath)
	if err != nil {
		return err
	}
	if path == configured {
		return nil
	}
	registeredPaths, err := server.state.ListAppConfigPaths()
	if err != nil {
		return fmt.Errorf("list known app config paths: %w", err)
	}
	for _, registered := range registeredPaths {
		clean, err := canonicalAppConfigPath(registered)
		if err != nil {
			return err
		}
		if path == clean {
			return nil
		}
	}
	if isNamedAppConfigSibling(path, configured) {
		return nil
	}
	return fmt.Errorf("app config path must be the configured UI path %s, a known app config path, or a same-directory *lanpanel-app.yaml file", configured)
}

func isNamedAppConfigSibling(path string, configured string) bool {
	if filepath.Dir(path) != filepath.Dir(configured) {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "lanpanel-app.yaml", base == "lanpanel-app.yml":
		return true
	case strings.HasSuffix(base, "-lanpanel-app.yaml"), strings.HasSuffix(base, "-lanpanel-app.yml"):
		return true
	default:
		return false
	}
}
