package appconfig

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func validListenConfig() Config {
	cfg := New()
	cfg.App.Name = "example-app"
	cfg.App.Domains = []string{"abc.com", "www.abc.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.Listen = "127.0.0.1:18001"
	cfg.Access.AccessMode = AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = true
	cfg.Service.ExecStart = "/opt/example-app/example-app --listen 127.0.0.1:18001"
	cfg.Service.WorkingDirectory = "/opt/example-app"
	return cfg
}

func validUpstreamConfig() Config {
	cfg := validListenConfig()
	cfg.App.Listen = ""
	cfg.App.Upstream = "100.64.10.20:18001"
	cfg.Service = ServiceConfig{}
	return cfg
}

func TestNewAppliesDefaultsAndRequiresUserInputs(t *testing.T) {
	t.Parallel()

	cfg := New()
	if cfg.APIVersion != APIVersion {
		t.Fatalf("APIVersion = %q, want %q", cfg.APIVersion, APIVersion)
	}
	if cfg.App.ACMEChallenge != ACMEChallengeHTTP01 {
		t.Fatalf("ACMEChallenge = %q, want %q", cfg.App.ACMEChallenge, ACMEChallengeHTTP01)
	}
	if got := cfg.Nginx.EffectiveClientMaxBodySize(); got != DefaultNginxClientMaxBodySize {
		t.Fatalf("nginx.client_max_body_size default = %q, want %q", got, DefaultNginxClientMaxBodySize)
	}
	if cfg.NginxHTTP2Enabled() {
		t.Fatal("nginx.http2 default = true, want false")
	}
	if got := cfg.Nginx.Proxy.EffectiveReadTimeout(); got != DefaultNginxProxyReadTimeout {
		t.Fatalf("nginx.proxy.read_timeout default = %q, want %q", got, DefaultNginxProxyReadTimeout)
	}
	if cfg.Nginx.GoAccess.Enabled {
		t.Fatal("nginx.goaccess.enabled default = true, want false")
	}
	if got := cfg.Nginx.GoAccess.EffectiveLanguage(); got != DefaultNginxGoAccessLanguage {
		t.Fatalf("nginx.goaccess.language effective default = %q, want %q", got, DefaultNginxGoAccessLanguage)
	}
	if got := cfg.Nginx.GoAccess.EffectiveLogFormat(); got != DefaultNginxGoAccessLogFormat {
		t.Fatalf("nginx.goaccess.log_format effective default = %q, want %q", got, DefaultNginxGoAccessLogFormat)
	}
	if got := cfg.Nginx.GoAccess.EffectivePath(); got != "/_lanpanel/apps/<app-name>/goaccess" {
		t.Fatalf("nginx.goaccess.path effective default = %q, want app-scoped placeholder", got)
	}
	if got := cfg.Nginx.GoAccess.EffectiveWebSocketPath(); got != "/_lanpanel/apps/<app-name>/goaccess/ws" {
		t.Fatalf("nginx.goaccess.websocket_path effective default = %q, want app-scoped placeholder", got)
	}
	if cfg.Dependencies.LegoSource.Mode != "direct" {
		t.Fatalf("dependencies.lego_source.mode = %q, want direct", cfg.Dependencies.LegoSource.Mode)
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
	for _, want := range []string{
		"app.name is required",
		"app.domains must contain at least one domain",
		"app.certificate_email is required",
		"one of app.listen or app.upstream is required",
		"access.access_mode is required",
		"access.origin_protection.mode is required",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error = %q, want substring %q", err.Error(), want)
		}
	}
}

func TestLoadBytesValidListenConfig(t *testing.T) {
	t.Parallel()

	cfg, err := LoadBytes([]byte(`
api_version: lanpanel/app/v1alpha2
app:
  name: example-app
  domains:
    - ABC.COM.
    - www.abc.com
  certificate_email: ops@example.com
  listen: 127.0.0.1:18001
access:
  access_mode: browser
  cidr_allowlist:
    - 198.51.100.0/24
  browser_auth:
    auth_basic_user_file: /etc/example-app/browser.htpasswd
  origin_protection:
    mode: none
    direct_origin_risk_confirmed: true
service:
  exec_start: /opt/example-app/example-app --listen 127.0.0.1:18001
  working_directory: /opt/example-app
  env_file: /opt/example-app/web.env
nginx:
  client_max_body_size: 100m
  http2: true
  access_log: /var/log/lanpanel/custom/example-app.access.log
  error_log: /var/log/nginx/example-app.error.log
  goaccess:
    enabled: true
    language: zh-CN
    log_format: combined
    path: /_ops/goaccess
    websocket_path: /_ops/goaccess/ws
    websocket_listen: 127.0.0.1:39001
    auth_basic_user_file: /etc/example-app/goaccess.htpasswd
    auth_cidr_allowlist:
      - 203.0.113.0/24
  proxy:
    connect_timeout: 30s
    read_timeout: 600s
    send_timeout: 600s
    buffering: false
    request_buffering: false
  static_locations:
    - path: /static/
      alias: /opt/example-app/web/static/
      cache_control: public, max-age=2592000
      try_files: true
      gzip_static: true
      access_log: false
    - path: /sitemap.xml
      match: exact
      alias: /opt/example-app/web/static/sitemap.xml
      default_type: application/xml
`))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if got := cfg.Mode(); got != ModeListen {
		t.Fatalf("Mode() = %q, want %q", got, ModeListen)
	}
	if cfg.RequiresTailscale() {
		t.Fatal("RequiresTailscale() = true, want false")
	}
	if got := cfg.PrimaryDomain(); got != "abc.com" {
		t.Fatalf("PrimaryDomain() = %q, want abc.com", got)
	}
	if got := cfg.ResourceName(); got != "example-app" {
		t.Fatalf("ResourceName() = %q, want example-app", got)
	}
	if got := cfg.EffectiveLanpanelConfig(); got != DefaultLanpanelConfigPath {
		t.Fatalf("EffectiveLanpanelConfig() = %q, want %q", got, DefaultLanpanelConfigPath)
	}
	if got := cfg.App.Domains[0]; got != "abc.com" {
		t.Fatalf("normalized domain = %q, want abc.com", got)
	}
	if got := cfg.Service.EnvFile; got != "/opt/example-app/web.env" {
		t.Fatalf("service.env_file = %q, want /opt/example-app/web.env", got)
	}
	if got := cfg.Access.AccessMode; got != AccessModeBrowser {
		t.Fatalf("access.access_mode = %q, want browser", got)
	}
	if got := cfg.BrowserAuthUserFile(); got != "/etc/example-app/browser.htpasswd" {
		t.Fatalf("BrowserAuthUserFile() = %q, want /etc/example-app/browser.htpasswd", got)
	}
	if got := cfg.Access.CIDRAllowlist; len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("access.cidr_allowlist = %#v, want 198.51.100.0/24", got)
	}
	if len(cfg.Nginx.StaticLocations) != 2 {
		t.Fatalf("len(nginx.static_locations) = %d, want 2", len(cfg.Nginx.StaticLocations))
	}
	if got := cfg.Nginx.StaticLocations[0].Path; got != "/static/" {
		t.Fatalf("nginx.static_locations[0].path = %q, want /static/", got)
	}
	if got := cfg.Nginx.ClientMaxBodySize; got != "100m" {
		t.Fatalf("nginx.client_max_body_size = %q, want 100m", got)
	}
	if !cfg.Nginx.HTTP2Enabled() {
		t.Fatal("nginx.http2 enabled = false, want true")
	}
	if got := cfg.Nginx.Proxy.ConnectTimeout; got != "30s" {
		t.Fatalf("nginx.proxy.connect_timeout = %q, want 30s", got)
	}
	if !cfg.Nginx.GoAccess.Enabled {
		t.Fatal("nginx.goaccess.enabled = false, want true")
	}
	if got := cfg.Nginx.GoAccess.Language; got != NginxGoAccessLanguageSimplifiedChinese {
		t.Fatalf("nginx.goaccess.language = %q, want zh-CN", got)
	}
	if got := cfg.Nginx.GoAccess.LogFormat; got != NginxGoAccessLogFormatCombined {
		t.Fatalf("nginx.goaccess.log_format = %q, want combined", got)
	}
	if got := cfg.Nginx.GoAccess.Path; got != "/_ops/goaccess" {
		t.Fatalf("nginx.goaccess.path = %q, want /_ops/goaccess", got)
	}
	if got := cfg.Nginx.GoAccess.WebSocketPath; got != "/_ops/goaccess/ws" {
		t.Fatalf("nginx.goaccess.websocket_path = %q, want /_ops/goaccess/ws", got)
	}
	if got := cfg.Nginx.GoAccess.WebSocketListen; got != "127.0.0.1:39001" {
		t.Fatalf("nginx.goaccess.websocket_listen = %q, want 127.0.0.1:39001", got)
	}
	if got := cfg.Nginx.GoAccess.AuthBasicUserFile; got != "/etc/example-app/goaccess.htpasswd" {
		t.Fatalf("nginx.goaccess.auth_basic_user_file = %q, want /etc/example-app/goaccess.htpasswd", got)
	}
	if got := cfg.Nginx.GoAccess.AuthCIDRAllowlist; len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("nginx.goaccess.auth_cidr_allowlist = %#v, want 203.0.113.0/24", got)
	}
	if cfg.Nginx.Proxy.Buffering == nil || *cfg.Nginx.Proxy.Buffering {
		t.Fatalf("nginx.proxy.buffering = %#v, want false", cfg.Nginx.Proxy.Buffering)
	}
	if cfg.Nginx.Proxy.RequestBuffering == nil || *cfg.Nginx.Proxy.RequestBuffering {
		t.Fatalf("nginx.proxy.request_buffering = %#v, want false", cfg.Nginx.Proxy.RequestBuffering)
	}
	if got := cfg.Nginx.StaticLocations[0].CacheControl; got != "public, max-age=2592000" {
		t.Fatalf("nginx.static_locations[0].cache_control = %q, want cache-control value", got)
	}
	if !cfg.Nginx.StaticLocations[0].GzipStatic {
		t.Fatal("nginx.static_locations[0].gzip_static = false, want true")
	}
	if cfg.Nginx.StaticLocations[0].AccessLog == nil || *cfg.Nginx.StaticLocations[0].AccessLog {
		t.Fatalf("nginx.static_locations[0].access_log = %#v, want false", cfg.Nginx.StaticLocations[0].AccessLog)
	}
	if got := cfg.Nginx.StaticLocations[1].Match; got != "exact" {
		t.Fatalf("nginx.static_locations[1].match = %q, want exact", got)
	}
	if got := cfg.Nginx.StaticLocations[1].DefaultType; got != "application/xml" {
		t.Fatalf("nginx.static_locations[1].default_type = %q, want application/xml", got)
	}
}

func TestLoadBytesValidUpstreamConfigRequiresTailscale(t *testing.T) {
	t.Parallel()

	cfg := validUpstreamConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got := cfg.Mode(); got != ModeUpstream {
		t.Fatalf("Mode() = %q, want %q", got, ModeUpstream)
	}
	if !cfg.RequiresTailscale() {
		t.Fatal("RequiresTailscale() = false, want true")
	}
}

func TestListenModeCanOptIntoTailscale(t *testing.T) {
	t.Parallel()

	cfg := validListenConfig()
	cfg.Tailscale.EnabledForListen = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !cfg.RequiresTailscale() {
		t.Fatal("RequiresTailscale() = false, want true")
	}
}

func TestLoadBytesRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	t.Parallel()

	if _, err := LoadBytes([]byte(`
app:
  name: example-app
  domains: [abc.com]
  certificate_email: ops@example.com
  listen: 127.0.0.1:18001
service:
  exec_start: /opt/example-app/example-app
`)); err == nil || !strings.Contains(err.Error(), "api_version is required") {
		t.Fatalf("LoadBytes() missing api_version error = %v, want required version failure", err)
	}

	if _, err := LoadBytes([]byte(`
api_version: lanpanel/app/v1alpha2
app:
  name: example-app
  domains: [abc.com]
  certificate_email: ops@example.com
  listen: 127.0.0.1:18001
  tailnet: true
access:
  access_mode: public
  public_risk_confirmed: true
  origin_protection:
    mode: none
    direct_origin_risk_confirmed: true
service:
  exec_start: /opt/example-app/example-app
`)); err == nil || !strings.Contains(err.Error(), "tailnet") {
		t.Fatalf("LoadBytes() unknown app field error = %v, want tailnet field failure", err)
	}

	if _, err := LoadBytes([]byte(`
api_version: lanpanel/app/v1alpha2
app:
  name: example-app
  domains: [abc.com]
  certificate_email: ops@example.com
  listen: 127.0.0.1:18001
access:
  access_mode: public
  public_risk_confirmed: true
  origin_protection:
    mode: none
    direct_origin_risk_confirmed: true
service:
  exec_start: /opt/example-app/example-app
nginx:
  goaccess:
    public: true
`)); err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("LoadBytes() unknown nginx.goaccess field error = %v, want public field failure", err)
	}

	if _, err := LoadBytes([]byte(`
api_version: lanpanel/app/v1alpha2
---
api_version: lanpanel/app/v1alpha2
`)); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("LoadBytes() multiple documents error = %v, want multiple document failure", err)
	}
}

func TestLoadBytesDefaultsACMEChallengeButNotAPIVersion(t *testing.T) {
	t.Parallel()

	cfg, err := LoadBytes([]byte(`
api_version: lanpanel/app/v1alpha2
app:
  name: example-app
  domains: [abc.com]
  certificate_email: ops@example.com
  listen: 127.0.0.1:18001
access:
  access_mode: public
  public_risk_confirmed: true
  origin_protection:
    mode: none
    direct_origin_risk_confirmed: true
service:
  exec_start: /opt/example-app/example-app
`))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}
	if cfg.App.ACMEChallenge != ACMEChallengeHTTP01 {
		t.Fatalf("ACMEChallenge = %q, want %q", cfg.App.ACMEChallenge, ACMEChallengeHTTP01)
	}
}

func TestValidateRejectsModeConflicts(t *testing.T) {
	t.Parallel()

	both := validListenConfig()
	both.App.Upstream = "100.64.10.20:18001"
	expectValidationError(t, both, "app.listen and app.upstream must not both be set")

	neither := validListenConfig()
	neither.App.Listen = ""
	expectValidationError(t, neither, "one of app.listen or app.upstream is required")
}

func TestValidateAccessRules(t *testing.T) {
	t.Parallel()

	publicUnconfirmed := validListenConfig()
	publicUnconfirmed.Access.PublicRiskConfirmed = false
	expectValidationError(t, publicUnconfirmed, "access.public_risk_confirmed must be true when access.access_mode is public")

	originUnconfirmed := validListenConfig()
	originUnconfirmed.Access.OriginProtection.DirectOriginRiskConfirmed = false
	expectValidationError(t, originUnconfirmed, "access.origin_protection.direct_origin_risk_confirmed must be true when access.origin_protection.mode is none")

	browserMissingAuth := validListenConfig()
	browserMissingAuth.Access.AccessMode = AccessModeBrowser
	browserMissingAuth.Access.PublicRiskConfirmed = false
	expectValidationError(t, browserMissingAuth, "access.browser_auth.auth_basic_user_file or access.browser_auth.managed.htpasswd_path is required")

	browserInvalidCIDR := validListenConfig()
	browserInvalidCIDR.Access.AccessMode = AccessModeBrowser
	browserInvalidCIDR.Access.PublicRiskConfirmed = false
	browserInvalidCIDR.Access.BrowserAuth.AuthBasicUserFile = "/etc/example-app/browser.htpasswd"
	browserInvalidCIDR.Access.CIDRAllowlist = []string{"not-cidr"}
	expectValidationError(t, browserInvalidCIDR, "access.cidr_allowlist[0] must be a valid CIDR")

	browser := validListenConfig()
	browser.Access.AccessMode = AccessModeBrowser
	browser.Access.PublicRiskConfirmed = false
	browser.Access.BrowserAuth.AuthBasicUserFile = "/etc/example-app/browser.htpasswd"
	browser.Access.CIDRAllowlist = []string{"203.0.113.0/24"}
	if err := browser.Validate(); err != nil {
		t.Fatalf("Validate() browser error = %v", err)
	}

	browserExternalManagedRoot := browser
	browserExternalManagedRoot.Access.BrowserAuth.AuthBasicUserFile = "/etc/lanpanel/browser-auth/review.htpasswd"
	expectValidationError(t, browserExternalManagedRoot, "access.browser_auth.auth_basic_user_file must not be under LanPanel-managed browser auth directory")

	for _, tt := range []struct {
		name string
		path string
	}{
		{name: "variable", path: "/etc/example-app/$host.htpasswd"},
		{name: "semicolon", path: "/etc/example-app/browser.htpasswd;return"},
		{name: "open brace", path: "/etc/example-app/{browser}.htpasswd"},
		{name: "close brace", path: "/etc/example-app/browser}.htpasswd"},
		{name: "comment", path: "/etc/example-app/browser.htpasswd#comment"},
	} {
		tt := tt
		t.Run("browser auth file rejects nginx syntax "+tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := browser
			cfg.Access.BrowserAuth.AuthBasicUserFile = tt.path
			expectValidationError(t, cfg, "access.browser_auth.auth_basic_user_file must not contain")
		})
	}

	browserManaged := validListenConfig()
	browserManaged.Access.AccessMode = AccessModeBrowser
	browserManaged.Access.PublicRiskConfirmed = false
	browserManaged.Access.BrowserAuth.Managed = ManagedBrowserAuthRef{
		CredentialID:        "review",
		HtpasswdPath:        "/etc/lanpanel/browser-auth/review.htpasswd",
		Username:            "review.user",
		PasswordFingerprint: "sha256:0011223344556677",
	}
	if err := browserManaged.Validate(); err != nil {
		t.Fatalf("Validate() managed browser auth error = %v", err)
	}

	browserManagedLeadingHyphenUser := browserManaged
	browserManagedLeadingHyphenUser.Access.BrowserAuth.Managed.Username = "-admin"
	expectValidationError(t, browserManagedLeadingHyphenUser, "access.browser_auth.managed.username must contain only ASCII letters, digits, dot, underscore, and hyphen, and must not start with hyphen")

	browserManagedOutsideRoot := browserManaged
	browserManagedOutsideRoot.Access.BrowserAuth.Managed.HtpasswdPath = "/etc/example-app/browser.htpasswd"
	expectValidationError(t, browserManagedOutsideRoot, "access.browser_auth.managed.htpasswd_path must be under /etc/lanpanel/browser-auth")

	browserManagedRootDir := browserManaged
	browserManagedRootDir.Access.BrowserAuth.Managed.HtpasswdPath = "/etc/lanpanel/browser-auth"
	expectValidationError(t, browserManagedRootDir, "access.browser_auth.managed.htpasswd_path must be under /etc/lanpanel/browser-auth")

	browserManagedWrongFile := browserManaged
	browserManagedWrongFile.Access.BrowserAuth.Managed.HtpasswdPath = "/etc/lanpanel/browser-auth/other.htpasswd"
	expectValidationError(t, browserManagedWrongFile, "access.browser_auth.managed.htpasswd_path must be /etc/lanpanel/browser-auth/<credential_id>.htpasswd")

	browserManagedPlainFingerprint := browserManaged
	browserManagedPlainFingerprint.Access.BrowserAuth.Managed.PasswordFingerprint = "plaintext-password"
	expectValidationError(t, browserManagedPlainFingerprint, "access.browser_auth.managed.password_fingerprint must be sha256: followed by 16 lowercase hex characters")

	publicWithBrowserAuth := validListenConfig()
	publicWithBrowserAuth.Access.BrowserAuth.AuthBasicUserFile = "/etc/example-app/browser.htpasswd"
	expectValidationError(t, publicWithBrowserAuth, "access.browser_auth must be empty when access.access_mode is public")

	publicWithCIDR := validListenConfig()
	publicWithCIDR.Access.CIDRAllowlist = []string{"203.0.113.0/24"}
	expectValidationError(t, publicWithCIDR, "access.cidr_allowlist is only supported when access.access_mode is browser")

	privateClient := validListenConfig()
	privateClient.Access.AccessMode = AccessModePrivateClient
	privateClient.Access.PublicRiskConfirmed = false
	privateClient.Access.OriginProtection.DirectOriginRiskConfirmed = false
	privateClient.Access.OriginProtection.Mode = OriginProtectionModeNone
	if err := privateClient.ValidateForExposurePlan(); err != nil {
		t.Fatalf("ValidateForExposurePlan() private_client error = %v", err)
	}
	expectValidationError(t, privateClient, "access.access_mode private_client is reserved for P1 and cannot be activated in P0")

	privateClientWithPublicFields := privateClient
	privateClientWithPublicFields.Access.PublicRiskConfirmed = true
	expectValidationError(t, privateClientWithPublicFields, "access.public_risk_confirmed must be false when access.access_mode is private_client")
}

func TestLoadAndExportAllowMissingRiskConfirmations(t *testing.T) {
	t.Parallel()

	cfg, err := LoadBytes([]byte(`
api_version: lanpanel/app/v1alpha2
app:
  name: example-app
  domains: [abc.com]
  certificate_email: ops@example.com
  acme_challenge: http-01
  listen: 127.0.0.1:18001
access:
  access_mode: public
  public_risk_confirmed: false
  origin_protection:
    mode: none
    direct_origin_risk_confirmed: false
service:
  exec_start: /opt/example-app/example-app --listen 127.0.0.1:18001
`))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v, want config load to allow missing manual confirmations", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want activation-level confirmation failure")
	}
	if _, err := cfg.ExportYAML(); err != nil {
		t.Fatalf("ExportYAML() error = %v, want config export to allow missing manual confirmations", err)
	}
}

func TestValidateRejectsUnsafeAppNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
	}{
		{name: "Example", want: "app.name must start with a lowercase letter"},
		{name: "-example", want: "app.name must start with a lowercase letter"},
		{name: "example-", want: "app.name must start with a lowercase letter"},
		{name: "0", want: "app.name must start with a lowercase letter"},
		{name: "123", want: "app.name must start with a lowercase letter"},
		{name: "1-app", want: "app.name must start with a lowercase letter"},
		{name: "app-name-that-is-longer-than-32-chars", want: "app.name must be 32 characters or shorter"},
		{name: "lanpanel", want: "app.name is reserved"},
		{name: "bin", want: "app.name is reserved"},
		{name: "daemon", want: "app.name is reserved"},
		{name: "nogroup", want: "app.name is reserved"},
		{name: "operator", want: "app.name is reserved"},
		{name: "nobody", want: "app.name is reserved"},
		{name: "messagebus", want: "app.name is reserved"},
		{name: "sshd", want: "app.name is reserved"},
		{name: "staff", want: "app.name is reserved"},
		{name: "sudo", want: "app.name is reserved"},
		{name: "syslog", want: "app.name is reserved"},
		{name: "users", want: "app.name is reserved"},
		{name: "systemd-journal", want: "app.name is reserved"},
		{name: "systemd-network", want: "app.name is reserved"},
		{name: "systemd-resolve", want: "app.name is reserved"},
		{name: "systemd-timesync", want: "app.name is reserved"},
		{name: "www-data", want: "app.name is reserved"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validListenConfig()
			cfg.App.Name = tt.name
			expectValidationError(t, cfg, tt.want)
		})
	}

	cfg := validListenConfig()
	cfg.App.Name = "www"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with app.name www error = %v", err)
	}

	for _, name := range []string{"api-goaccess", "lanpanel-goaccess-api", "mga-api"} {
		cfg := validListenConfig()
		cfg.App.Name = name
		cfg.Service.ExecStart = "/opt/" + name + "/" + name
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() with existing valid app.name %s error = %v", name, err)
		}
	}
}

func TestValidateRejectsInvalidDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		domains []string
		want    string
	}{
		{name: "empty", domains: nil, want: "app.domains must contain at least one domain"},
		{name: "wildcard", domains: []string{"*.example.com"}, want: "app.domains[0] must be an exact DNS name"},
		{name: "ip", domains: []string{"100.64.10.20"}, want: "app.domains[0] must be an exact DNS name"},
		{name: "duplicate", domains: []string{"abc.com", "ABC.COM."}, want: "app.domains must not contain duplicate domains"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validListenConfig()
			cfg.App.Domains = tt.domains
			expectValidationError(t, cfg, tt.want)
		})
	}
}

func TestValidateRejectsSystemdUnsafeCertificateEmails(t *testing.T) {
	t.Parallel()

	tests := []string{
		"o'ps@example.com",
		"ops$token@example.com",
		"ops%team@example.com",
	}
	for _, email := range tests {
		email := email
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			cfg := validListenConfig()
			cfg.App.CertificateEmail = email
			expectValidationError(t, cfg, "app.certificate_email must be a systemd-safe email token")
		})
	}
}

func TestValidateRejectsListenAddressesOutsideLoopbackOrReservedPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		listen string
		want   string
	}{
		{name: "public", listen: "0.0.0.0:18001", want: "app.listen must use a loopback host"},
		{name: "public ipv4", listen: "203.0.113.10:18001", want: "app.listen must use a loopback host"},
		{name: "reserved", listen: "127.0.0.1:8080", want: "app.listen must not reuse"},
		{name: "bad port", listen: "127.0.0.1:bad", want: "app.listen port must be between 1 and 65535"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validListenConfig()
			cfg.App.Listen = tt.listen
			expectValidationError(t, cfg, tt.want)
		})
	}
}

func TestValidateRejectsInvalidUpstreamAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		upstream string
		want     string
	}{
		{name: "magic dns", upstream: "node.tailnet.ts.net:18001", want: "app.upstream must use a fixed Tailscale IPv4 address"},
		{name: "outside tailnet", upstream: "192.168.1.10:18001", want: "app.upstream must use a fixed Tailscale IPv4 address"},
		{name: "database", upstream: "100.64.10.20:5432", want: "app.upstream must not expose common database ports"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validUpstreamConfig()
			cfg.App.Upstream = tt.upstream
			expectValidationError(t, cfg, tt.want)
		})
	}
}

func TestValidateServiceRules(t *testing.T) {
	t.Parallel()

	missingExec := validListenConfig()
	missingExec.Service.ExecStart = ""
	expectValidationError(t, missingExec, "service.exec_start is required when app.listen is set")

	relativeExec := validListenConfig()
	relativeExec.Service.ExecStart = "example-app --listen 127.0.0.1:18001"
	expectValidationError(t, relativeExec, "service.exec_start must start with an absolute business binary path")

	commandSeparatorExec := validListenConfig()
	commandSeparatorExec.Service.ExecStart = "/opt/example-app/example-app --listen 127.0.0.1:18001 ; /bin/true"
	expectValidationError(t, commandSeparatorExec, "service.exec_start must not contain systemd separators")

	variableExec := validListenConfig()
	variableExec.Service.ExecStart = "/opt/example-app/example-app --listen ${APP_LISTEN}"
	expectValidationError(t, variableExec, "service.exec_start must not contain systemd separators")

	quotedExec := validListenConfig()
	quotedExec.Service.ExecStart = `/opt/example-app/example-app --name "example app"`
	expectValidationError(t, quotedExec, "service.exec_start must not contain systemd separators")

	relativeDir := validListenConfig()
	relativeDir.Service.WorkingDirectory = "opt/example-app"
	expectValidationError(t, relativeDir, "service.working_directory must be an absolute directory path")

	relativeEnvFile := validListenConfig()
	relativeEnvFile.Service.EnvFile = "web.env"
	expectValidationError(t, relativeEnvFile, "service.env_file must be an absolute path")

	badEnvFile := validListenConfig()
	badEnvFile.Service.EnvFile = "/opt/example-app/web env"
	expectValidationError(t, badEnvFile, "service.env_file must not contain whitespace")

	upstreamWithService := validUpstreamConfig()
	upstreamWithService.Service.ExecStart = "/opt/example-app/example-app"
	expectValidationError(t, upstreamWithService, "service.exec_start must be empty when app.upstream is set")

	upstreamWithServiceEnv := validUpstreamConfig()
	upstreamWithServiceEnv.Service.EnvFile = "/opt/example-app/web.env"
	expectValidationError(t, upstreamWithServiceEnv, "service.env_file must be empty when app.upstream is set")
}

func TestValidateDNS01Rules(t *testing.T) {
	t.Parallel()

	missingProvider := validListenConfig()
	missingProvider.App.ACMEChallenge = ACMEChallengeDNS01
	expectValidationError(t, missingProvider, "dns01.provider is required when app.acme_challenge is dns-01")

	missingEnvFile := validListenConfig()
	missingEnvFile.App.ACMEChallenge = ACMEChallengeDNS01
	missingEnvFile.DNS01.Provider = "cloudflare"
	expectValidationError(t, missingEnvFile, "dns01.env_file is required for DNS-01 renewal with lego DNS provider cloudflare")

	valid := validListenConfig()
	valid.App.ACMEChallenge = ACMEChallengeDNS01
	valid.DNS01.Provider = "cloudflare"
	valid.DNS01.EnvFile = "/etc/lanpanel/dns/cloudflare.env"
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tencentcloud := validListenConfig()
	tencentcloud.App.ACMEChallenge = ACMEChallengeDNS01
	tencentcloud.DNS01.Provider = "tencentcloud"
	expectValidationError(t, tencentcloud, "dns01.env_file is required for DNS-01 renewal with lego DNS provider tencentcloud")
	tencentcloud.DNS01.EnvFile = "/etc/lanpanel/dns/tencentcloud.env"
	if err := tencentcloud.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	badPath := valid
	badPath.DNS01.EnvFile = "relative.env"
	expectValidationError(t, badPath, "dns01.env_file must be an absolute path")
}

func TestValidateRealIPRules(t *testing.T) {
	t.Parallel()

	enabled := true
	disabled := false

	valid := validListenConfig()
	valid.App.ACMEChallenge = ACMEChallengeDNS01
	valid.DNS01.Provider = "tencentcloud"
	valid.DNS01.EnvFile = "/etc/lanpanel/dns/tencentcloud.env"
	valid.Access.OriginProtection.Mode = OriginProtectionModeEdgeOne
	valid.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	valid.Access.OriginProtection.DirectOriginRiskConfirmed = false
	valid.RealIP.Profiles = map[string]RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:         &enabled,
			Provider:        RealIPProviderEdgeOne,
			RefreshInterval: "72h",
			EdgeOne: RealIPEdgeOneConfig{
				ZoneID:  "zone-2abcDEF123",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() with EdgeOne realip profile error = %v", err)
	}
	if !valid.RealIPEnabled() {
		t.Fatal("RealIPEnabled() = false, want true")
	}
	profile, ok := valid.RealIPProfile("edgeone-prod")
	if !ok || profile.EffectiveRefreshInterval() != "72h" || !profile.IsEnabled() {
		t.Fatalf("RealIPProfile(edgeone-prod) = %#v, %v; want enabled profile", profile, ok)
	}

	staleDirectOriginConfirmation := valid
	staleDirectOriginConfirmation.Access.OriginProtection.DirectOriginRiskConfirmed = true
	expectValidationError(t, staleDirectOriginConfirmation, "access.origin_protection.direct_origin_risk_confirmed must be false when access.origin_protection.mode is edgeone")

	noReference := validListenConfig()
	noReference.RealIP.Profiles = map[string]RealIPProfileConfig{
		"edgeone-prod": {Enabled: &disabled, Provider: RealIPProviderEdgeOne},
	}
	if err := noReference.Validate(); err != nil {
		t.Fatalf("Validate() with unreferenced disabled profile error = %v", err)
	}
	if noReference.RealIPEnabled() {
		t.Fatal("RealIPEnabled() = true for unreferenced disabled profile, want false")
	}

	missingEnabled := validListenConfig()
	missingEnabled.RealIP.Profiles = map[string]RealIPProfileConfig{
		"edgeone-prod": {Provider: RealIPProviderEdgeOne},
	}
	expectValidationError(t, missingEnabled, "realip.profiles.edgeone-prod.enabled is required")

	badName := validListenConfig()
	badName.RealIP.Profiles = map[string]RealIPProfileConfig{
		"EdgeOne": {Enabled: &disabled, Provider: RealIPProviderEdgeOne},
	}
	expectValidationError(t, badName, "realip.profiles.EdgeOne name must start with a lowercase letter")

	unknownProvider := validListenConfig()
	unknownProvider.RealIP.Profiles = map[string]RealIPProfileConfig{
		"cdn": {Enabled: &disabled, Provider: "custom"},
	}
	expectValidationError(t, unknownProvider, "realip.profiles.cdn.provider must be edgeone")

	missingReference := validListenConfig()
	missingReference.Access.OriginProtection.Mode = OriginProtectionModeEdgeOne
	missingReference.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	expectValidationError(t, missingReference, "access.origin_protection.edgeone_profile references undefined realip profile edgeone-prod")

	disabledReference := validListenConfig()
	disabledReference.Access.OriginProtection.Mode = OriginProtectionModeEdgeOne
	disabledReference.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	disabledReference.RealIP.Profiles = map[string]RealIPProfileConfig{
		"edgeone-prod": {Enabled: &disabled, Provider: RealIPProviderEdgeOne},
	}
	expectValidationError(t, disabledReference, "access.origin_protection.edgeone_profile references disabled realip profile edgeone-prod")

	http01Reference := validListenConfig()
	http01Reference.Access.OriginProtection.Mode = OriginProtectionModeEdgeOne
	http01Reference.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	http01Reference.RealIP.Profiles = map[string]RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: RealIPProviderEdgeOne,
			EdgeOne: RealIPEdgeOneConfig{
				ZoneID:  "zone-2abcDEF123",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	expectValidationError(t, http01Reference, "app.acme_challenge must be dns-01 when access.origin_protection.mode is edgeone")

	expectLoadBytesError(t, `
api_version: lanpanel/app/v1alpha2
app:
  name: example-app
  domains: [abc.com]
  certificate_email: ops@example.com
  listen: 127.0.0.1:18001
access:
  access_mode: public
  public_risk_confirmed: true
  origin_protection:
    mode: none
    direct_origin_risk_confirmed: true
service:
  exec_start: /opt/example-app/example-app
nginx:
  realip_profile: edgeone-prod
`, "realip_profile")

	goAccessSharedExternalBrowserAuth := validListenConfig()
	goAccessSharedExternalBrowserAuth.Access.AccessMode = AccessModeBrowser
	goAccessSharedExternalBrowserAuth.Access.PublicRiskConfirmed = false
	goAccessSharedExternalBrowserAuth.Access.BrowserAuth.AuthBasicUserFile = "/etc/example-app/shared.htpasswd"
	goAccessSharedExternalBrowserAuth.Nginx.GoAccess.Enabled = true
	goAccessSharedExternalBrowserAuth.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/shared.htpasswd"
	expectValidationError(t, goAccessSharedExternalBrowserAuth, "nginx.goaccess.auth_basic_user_file must not equal access.browser_auth")

	goAccessSharedManagedBrowserAuth := validListenConfig()
	goAccessSharedManagedBrowserAuth.Access.AccessMode = AccessModeBrowser
	goAccessSharedManagedBrowserAuth.Access.PublicRiskConfirmed = false
	goAccessSharedManagedBrowserAuth.Access.BrowserAuth.Managed = ManagedBrowserAuthRef{
		CredentialID:        "review",
		HtpasswdPath:        "/etc/lanpanel/browser-auth/review.htpasswd",
		Username:            "review.user",
		PasswordFingerprint: "sha256:0011223344556677",
	}
	goAccessSharedManagedBrowserAuth.Nginx.GoAccess.Enabled = true
	goAccessSharedManagedBrowserAuth.Nginx.GoAccess.AuthBasicUserFile = "/etc/lanpanel/browser-auth/review.htpasswd"
	expectValidationError(t, goAccessSharedManagedBrowserAuth, "nginx.goaccess.auth_basic_user_file must not equal access.browser_auth")

	missingEdgeOneFields := valid
	missingEdgeOneFields.RealIP.Profiles = map[string]RealIPProfileConfig{
		"edgeone-prod": {Enabled: &enabled, Provider: RealIPProviderEdgeOne},
	}
	expectValidationError(t, missingEdgeOneFields, "realip.profiles.edgeone-prod.edgeone.zone_id is required")
	expectValidationError(t, missingEdgeOneFields, "realip.profiles.edgeone-prod.edgeone.env_file is required")

	badEnvFile := valid
	badEnvFile.RealIP.Profiles["edgeone-prod"] = RealIPProfileConfig{
		Enabled:  &enabled,
		Provider: RealIPProviderEdgeOne,
		EdgeOne:  RealIPEdgeOneConfig{ZoneID: "zone-2abcDEF123", EnvFile: "relative.env"},
	}
	expectValidationError(t, badEnvFile, "realip.profiles.edgeone-prod.edgeone.env_file must be an absolute path")

	fastRefresh := valid
	fastRefresh.RealIP.Profiles["edgeone-prod"] = RealIPProfileConfig{
		Enabled:         &enabled,
		Provider:        RealIPProviderEdgeOne,
		RefreshInterval: "30m",
		EdgeOne:         RealIPEdgeOneConfig{ZoneID: "zone-2abcDEF123", EnvFile: "/etc/lanpanel/realip/edgeone-prod.env"},
	}
	expectValidationError(t, fastRefresh, "realip.profiles.edgeone-prod.refresh_interval must be at least 1h")

	subSecondRefresh := valid
	subSecondRefresh.RealIP.Profiles["edgeone-prod"] = RealIPProfileConfig{
		Enabled:         &enabled,
		Provider:        RealIPProviderEdgeOne,
		RefreshInterval: "3600000000001ns",
		EdgeOne:         RealIPEdgeOneConfig{ZoneID: "zone-2abcDEF123", EnvFile: "/etc/lanpanel/realip/edgeone-prod.env"},
	}
	expectValidationError(t, subSecondRefresh, "realip.profiles.edgeone-prod.refresh_interval must resolve to whole seconds")
}

func TestLoadBytesRejectsUnknownRealIPFields(t *testing.T) {
	t.Parallel()

	_, err := LoadBytes([]byte(`
api_version: lanpanel/app/v1alpha2
app:
  name: example-app
  domains: [abc.com]
  certificate_email: ops@example.com
  acme_challenge: dns-01
  listen: 127.0.0.1:18001
access:
  access_mode: public
  public_risk_confirmed: true
  origin_protection:
    mode: edgeone
    direct_origin_risk_confirmed: false
    edgeone_profile: edgeone-prod
service:
  exec_start: /opt/example-app/example-app
realip:
  profiles:
    edgeone-prod:
      enabled: true
      provider: edgeone
      header_override: X-Forwarded-For
      edgeone:
        zone_id: zone-2abcDEF123
        env_file: /etc/lanpanel/realip/edgeone-prod.env
dns01:
  provider: tencentcloud
  env_file: /etc/lanpanel/dns/tencentcloud.env
`))
	if err == nil || !strings.Contains(err.Error(), "header_override") {
		t.Fatalf("LoadBytes() unknown realip profile field error = %v, want header_override field failure", err)
	}
}

func TestValidateNginxStaticLocationRules(t *testing.T) {
	t.Parallel()

	valid := validListenConfig()
	staticAccessLog := false
	proxyBuffering := false
	valid.Nginx.StaticLocations = []NginxStaticLocationConfig{
		{
			Path:         "/static/",
			Alias:        "/opt/example-app/web/static/",
			CacheControl: "public, max-age=2592000",
			TryFiles:     true,
			GzipStatic:   true,
			AccessLog:    &staticAccessLog,
		},
		{
			Path:        "/sitemap.xml",
			Match:       "exact",
			Alias:       "/opt/example-app/web/static/sitemap.xml",
			DefaultType: "application/xml",
		},
	}
	valid.Nginx.ClientMaxBodySize = "100m"
	valid.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
	valid.Nginx.ErrorLog = "/var/log/nginx/example-app.error.log"
	valid.Nginx.Proxy.ConnectTimeout = "30s"
	valid.Nginx.Proxy.ReadTimeout = "600s"
	valid.Nginx.Proxy.SendTimeout = "600s"
	valid.Nginx.Proxy.Buffering = &proxyBuffering
	valid.Nginx.Proxy.RequestBuffering = &proxyBuffering
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	missingPath := validListenConfig()
	missingPath.Nginx.StaticLocations = []NginxStaticLocationConfig{{Alias: "/opt/example-app/web/static/"}}
	expectValidationError(t, missingPath, "nginx.static_locations[0].path is required")

	relativeAlias := validListenConfig()
	relativeAlias.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/", Alias: "web/static/"}}
	expectValidationError(t, relativeAlias, "nginx.static_locations[0].alias must be an absolute path")

	prefixWithoutSlash := validListenConfig()
	prefixWithoutSlash.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static", Alias: "/opt/example-app/web/static/"}}
	expectValidationError(t, prefixWithoutSlash, "nginx.static_locations[0].path must end with /")

	prefixAliasWithoutSlash := validListenConfig()
	prefixAliasWithoutSlash.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/", Alias: "/opt/example-app/web/static"}}
	expectValidationError(t, prefixAliasWithoutSlash, "nginx.static_locations[0].alias must end with /")

	exactWithSlash := validListenConfig()
	exactWithSlash.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/sitemap.xml/", Match: "exact", Alias: "/opt/example-app/web/static/sitemap.xml"}}
	expectValidationError(t, exactWithSlash, "nginx.static_locations[0].path must not end with /")

	overlapACME := validListenConfig()
	overlapACME.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/.well-known/", Alias: "/opt/example-app/web/static/"}}
	expectValidationError(t, overlapACME, "nginx.static_locations[0].path must not overlap /.well-known/acme-challenge/")

	commentedStaticPath := validListenConfig()
	commentedStaticPath.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/#/", Alias: "/opt/example-app/web/static/"}}
	expectValidationError(t, commentedStaticPath, "nginx.static_locations[0].path must not contain")

	commentedStaticAlias := validListenConfig()
	commentedStaticAlias.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/", Alias: "/opt/example-app/web/#/"}}
	expectValidationError(t, commentedStaticAlias, "nginx.static_locations[0].alias must not contain")

	injectedHeader := validListenConfig()
	injectedHeader.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/", Alias: "/opt/example-app/web/static/", CacheControl: "public\";\nreturn 200"}}
	expectValidationError(t, injectedHeader, "nginx.static_locations[0].cache_control must not contain")

	badExpires := validListenConfig()
	badExpires.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/", Alias: "/opt/example-app/web/static/", Expires: "30 days"}}
	expectValidationError(t, badExpires, "nginx.static_locations[0].expires must be off, epoch, max, or a simple nginx time")

	existingCacheHeaderPair := validListenConfig()
	existingCacheHeaderPair.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/", Alias: "/opt/example-app/web/static/", Expires: "30d", CacheControl: "public, max-age=2592000"}}
	if err := existingCacheHeaderPair.Validate(); err != nil {
		t.Fatalf("Validate() with existing expires/cache_control pair error = %v", err)
	}

	badDefaultType := validListenConfig()
	badDefaultType.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/sitemap.xml", Match: "exact", Alias: "/opt/example-app/web/static/sitemap.xml", DefaultType: "application/xml;\nreturn 200"}}
	expectValidationError(t, badDefaultType, "nginx.static_locations[0].default_type must be a simple MIME type")

	duplicatePath := validListenConfig()
	duplicatePath.Nginx.StaticLocations = []NginxStaticLocationConfig{
		{Path: "/static/", Alias: "/opt/example-app/web/static/"},
		{Path: "/static/", Alias: "/opt/example-app/web/static2/"},
	}
	expectValidationError(t, duplicatePath, "nginx.static_locations[1].path must not duplicate another static location")

	badClientSize := validListenConfig()
	badClientSize.Nginx.ClientMaxBodySize = "20 mb"
	expectValidationError(t, badClientSize, "nginx.client_max_body_size must be a simple nginx size")

	badProxyTimeout := validListenConfig()
	badProxyTimeout.Nginx.Proxy.ReadTimeout = "five minutes"
	expectValidationError(t, badProxyTimeout, "nginx.proxy.read_timeout must be a simple nginx time")

	badAccessLog := validListenConfig()
	badAccessLog.Nginx.AccessLog = "relative.log"
	expectValidationError(t, badAccessLog, "nginx.access_log must be an absolute path")

	commentedAccessLog := validListenConfig()
	commentedAccessLog.Nginx.AccessLog = "/var/log/nginx/example#app.access.log"
	expectValidationError(t, commentedAccessLog, "nginx.access_log must not contain")

	badErrorLog := validListenConfig()
	badErrorLog.Nginx.ErrorLog = "/var/log/nginx/error log"
	expectValidationError(t, badErrorLog, "nginx.error_log must not contain whitespace")

	commentedErrorLog := validListenConfig()
	commentedErrorLog.Nginx.ErrorLog = "/var/log/nginx/example#app.error.log"
	expectValidationError(t, commentedErrorLog, "nginx.error_log must not contain")

	staticAccessLogOn := true
	badStaticAccessLog := validListenConfig()
	badStaticAccessLog.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/static/", Alias: "/opt/example-app/web/static/", AccessLog: &staticAccessLogOn}}
	expectValidationError(t, badStaticAccessLog, "nginx.static_locations[0].access_log only supports false")
}

func TestValidateNginxGoAccessRules(t *testing.T) {
	t.Parallel()

	valid := validListenConfig()
	valid.Nginx.GoAccess.Enabled = true
	valid.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() with enabled GoAccess defaults error = %v", err)
	}
	if got := valid.Nginx.GoAccess.EffectiveLanguage(); got != NginxGoAccessLanguageEnglish {
		t.Fatalf("EffectiveLanguage() = %q, want en", got)
	}
	if got := valid.Nginx.GoAccess.EffectiveLogFormat(); got != NginxGoAccessLogFormatEnhanced {
		t.Fatalf("EffectiveLogFormat() = %q, want enhanced", got)
	}
	if got := valid.NginxGoAccessDashboardPath(); got != "/_lanpanel/apps/example-app/goaccess" {
		t.Fatalf("NginxGoAccessDashboardPath() = %q, want app-scoped default", got)
	}
	if got := valid.NginxGoAccessWebSocketPath(); got != "/_lanpanel/apps/example-app/goaccess/ws" {
		t.Fatalf("NginxGoAccessWebSocketPath() = %q, want app-scoped default", got)
	}
	if got := DefaultNginxGoAccessWebSocketPort("i3t"); got != 50444 {
		t.Fatalf("DefaultNginxGoAccessWebSocketPort(i3t) = %d, want 50444 to skip reserved port 50443", got)
	}

	ipv6Loopback := valid
	ipv6Loopback.Nginx.GoAccess.WebSocketListen = "[::1]:39001"
	if err := ipv6Loopback.Validate(); err != nil {
		t.Fatalf("Validate() with GoAccess IPv6 loopback listen error = %v", err)
	}
	if listenHostsOverlap("0.0.0.0", "::1") {
		t.Fatal("listenHostsOverlap(0.0.0.0, ::1) = true, want address-family-specific non-overlap")
	}
	if !listenHostsOverlap("::", "127.0.0.1") {
		t.Fatal("listenHostsOverlap(::, 127.0.0.1) = false, want conservative dual-stack overlap")
	}
	if !listenHostsOverlap("0.0.0.0", "127.0.0.1") || !listenHostsOverlap("::", "::1") {
		t.Fatal("listenHostsOverlap wildcard same-family checks failed")
	}

	nonOverlappingLoopbackPorts := valid
	nonOverlappingLoopbackPorts.App.Listen = "127.0.0.2:39001"
	nonOverlappingLoopbackPorts.Nginx.GoAccess.WebSocketListen = "127.0.0.1:39001"
	if err := nonOverlappingLoopbackPorts.Validate(); err != nil {
		t.Fatalf("Validate() with distinct loopback hosts on same GoAccess/app port error = %v", err)
	}

	explicitManagedLog := valid
	explicitManagedLog.Nginx.AccessLog = "/var/log/lanpanel/apps/example-app/access.log"
	if err := explicitManagedLog.Validate(); err != nil {
		t.Fatalf("Validate() with explicit Lanpanel-managed GoAccess access log error = %v", err)
	}
	if !explicitManagedLog.NginxGoAccessManagesCanonicalAccessLog() {
		t.Fatal("NginxGoAccessManagesCanonicalAccessLog(explicit Lanpanel log root) = false, want true")
	}
	if got := explicitManagedLog.NginxGoAccessCanonicalAccessLogPath(); got != "/var/log/lanpanel/apps/example-app/access.log" {
		t.Fatalf("NginxGoAccessCanonicalAccessLogPath() = %q, want explicit managed path", got)
	}

	explicitCustomLog := valid
	explicitCustomLog.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
	if explicitCustomLog.NginxGoAccessManagesCanonicalAccessLog() {
		t.Fatal("NginxGoAccessManagesCanonicalAccessLog(custom explicit log) = true, want false")
	}

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "access log off conflict",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "off"
			},
			want: "nginx.access_log must not be off when nginx.goaccess.enabled is true",
		},
		{
			name: "access log hidden by ProtectHome home",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/home/app/logs/access.log"
			},
			want: "nginx.access_log must not be under /home, /root, /run/user, /tmp, or /var/tmp when nginx.goaccess.enabled is true",
		},
		{
			name: "access log hidden by ProtectHome root",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/root/app/access.log"
			},
			want: "nginx.access_log must not be under /home, /root, /run/user, /tmp, or /var/tmp when nginx.goaccess.enabled is true",
		},
		{
			name: "access log hidden by ProtectHome run user",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/run/user/1000/access.log"
			},
			want: "nginx.access_log must not be under /home, /root, /run/user, /tmp, or /var/tmp when nginx.goaccess.enabled is true",
		},
		{
			name: "access log hidden by PrivateTmp tmp",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/tmp/access.log"
			},
			want: "nginx.access_log must not be under /home, /root, /run/user, /tmp, or /var/tmp when nginx.goaccess.enabled is true",
		},
		{
			name: "access log hidden by PrivateTmp var tmp",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/tmp/access.log"
			},
			want: "nginx.access_log must not be under /home, /root, /run/user, /tmp, or /var/tmp when nginx.goaccess.enabled is true",
		},
		{
			name: "access log under distro nginx logrotate wildcard",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/log/nginx/example-app.access.log"
			},
			want: "nginx.access_log must not be under /var/log/nginx when nginx.goaccess.enabled is true",
		},
		{
			name: "access log under different Lanpanel app log root",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/log/lanpanel/apps/other-app/access.log"
			},
			want: "nginx.access_log under /var/log/lanpanel/apps must stay under the current app log directory",
		},
		{
			name: "access log equals current Lanpanel app log directory",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/log/lanpanel/apps/example-app"
			},
			want: "nginx.access_log must be a file under the Lanpanel-managed GoAccess log directory",
		},
		{
			name: "access log equals Lanpanel app log marker",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/log/lanpanel/apps/example-app/.lanpanel-managed"
			},
			want: "nginx.access_log under the Lanpanel-managed GoAccess log directory must be the direct access.log file",
		},
		{
			name: "access log equals app var marker",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/lib/example-app/.lanpanel-managed"
			},
			want: "nginx.access_log must not point to Lanpanel-managed app var marker path",
		},
		{
			name: "access log under app var root",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/lib/example-app/runtime.log"
			},
			want: "nginx.access_log must not be under Lanpanel-managed app var root directory",
		},
		{
			name: "access log nested under current Lanpanel app log directory",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/log/lanpanel/apps/example-app/nested/access.log"
			},
			want: "nginx.access_log under the Lanpanel-managed GoAccess log directory must be the direct access.log file",
		},
		{
			name: "error log equals derived canonical access log",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/var/log/lanpanel/apps/example-app/access.log"
			},
			want: "nginx.error_log must not equal the GoAccess canonical access log",
		},
		{
			name: "error log equals explicit canonical access log",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
				cfg.Nginx.ErrorLog = "/var/log/lanpanel/custom/example-app.access.log"
			},
			want: "nginx.error_log must not equal the GoAccess canonical access log",
		},
		{
			name: "error log equals auth file",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/etc/example-app/goaccess.htpasswd"
			},
			want: "nginx.error_log must not equal nginx.goaccess.auth_basic_user_file",
		},
		{
			name: "error log equals app etc marker",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/etc/example-app/.lanpanel-managed"
			},
			want: "nginx.error_log must not point to Lanpanel-managed app etc marker path",
		},
		{
			name: "error log under app hook root",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/usr/local/lib/lanpanel/apps/example-app/error.log"
			},
			want: "nginx.error_log must not be under Lanpanel-managed app hook root directory",
		},
		{
			name: "error log collides with goaccess config",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/etc/example-app/goaccess.conf"
			},
			want: "nginx.error_log must not point to Lanpanel-managed GoAccess config path",
		},
		{
			name: "error log collides with goaccess report",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/var/lib/example-app/goaccess/report.html"
			},
			want: "nginx.error_log must not point to Lanpanel-managed GoAccess report path",
		},
		{
			name: "error log under goaccess report directory",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/var/lib/example-app/goaccess/error.log"
			},
			want: "nginx.error_log must not be under Lanpanel-managed GoAccess report directory",
		},
		{
			name: "error log collides with goaccess db",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/var/lib/example-app/goaccess/db"
			},
			want: "nginx.error_log must not point to Lanpanel-managed GoAccess db path",
		},
		{
			name: "error log under another Lanpanel app log namespace",
			mutate: func(cfg *Config) {
				cfg.Nginx.ErrorLog = "/var/log/lanpanel/apps/other-app/error.log"
			},
			want: "nginx.error_log must not be under Lanpanel-managed app log namespace",
		},
		{
			name: "access log collides with goaccess config",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/etc/example-app/goaccess.conf"
			},
			want: "nginx.access_log must not point to Lanpanel-managed GoAccess config path",
		},
		{
			name: "access log collides with goaccess report",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/lib/example-app/goaccess/report.html"
			},
			want: "nginx.access_log must not point to Lanpanel-managed GoAccess report path",
		},
		{
			name: "access log under goaccess report directory",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/var/lib/example-app/goaccess/access.log"
			},
			want: "nginx.access_log must not be under Lanpanel-managed GoAccess report directory",
		},
		{
			name: "access log equals auth file",
			mutate: func(cfg *Config) {
				cfg.Nginx.AccessLog = "/etc/example-app/goaccess.htpasswd"
			},
			want: "nginx.access_log must not equal nginx.goaccess.auth_basic_user_file",
		},
		{
			name: "bad language",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Language = "fr"
			},
			want: "nginx.goaccess.language must be one of: en, zh-CN",
		},
		{
			name: "bad log format",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.LogFormat = "json"
			},
			want: "nginx.goaccess.log_format must be one of: enhanced, combined",
		},
		{
			name: "bad CIDR",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"203.0.113.10"}
			},
			want: "nginx.goaccess.auth_cidr_allowlist[0] must be a valid CIDR",
		},
		{
			name: "missing auth file",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = ""
			},
			want: "nginx.goaccess.auth_basic_user_file is required when nginx.goaccess.enabled is true",
		},
		{
			name: "relative auth file",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must be an absolute path",
		},
		{
			name: "auth file with directive separator",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd;return"
			},
			want: "nginx.goaccess.auth_basic_user_file must not contain",
		},
		{
			name: "auth file with comment marker",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd#comment"
			},
			want: "nginx.goaccess.auth_basic_user_file must not contain",
		},
		{
			name: "auth file with nginx variables",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/${goaccess}.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must not contain",
		},
		{
			name: "auth file nested under app etc root",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/auth/goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file under /etc/example-app must be the direct /etc/example-app/goaccess.htpasswd bootstrap path",
		},
		{
			name: "auth file under app var root",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/lib/example-app/goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed app var root directory",
		},
		{
			name: "auth file under app hook root",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/usr/local/lib/lanpanel/apps/example-app/goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed app hook root directory",
		},
		{
			name: "auth file under goaccess log root",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/log/lanpanel/apps/example-app/goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed GoAccess log directory",
		},
		{
			name: "auth file collides with goaccess config",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.conf"
			},
			want: "nginx.goaccess.auth_basic_user_file must not point to Lanpanel-managed GoAccess config path",
		},
		{
			name: "auth file collides with goaccess logrotate",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/logrotate.d/example-app-goaccess"
			},
			want: "nginx.goaccess.auth_basic_user_file must not point to Lanpanel-managed GoAccess logrotate path",
		},
		{
			name: "auth file collides with goaccess report",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/lib/example-app/goaccess/report.html"
			},
			want: "nginx.goaccess.auth_basic_user_file must not point to Lanpanel-managed GoAccess report path",
		},
		{
			name: "auth file under goaccess report directory",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/lib/example-app/goaccess/goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed GoAccess report directory",
		},
		{
			name: "auth file collides with goaccess db",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/lib/example-app/goaccess/db"
			},
			want: "nginx.goaccess.auth_basic_user_file must not point to Lanpanel-managed GoAccess db path",
		},
		{
			name: "auth file under goaccess db",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/lib/example-app/goaccess/db/goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed GoAccess report directory",
		},
		{
			name: "auth file collides with canonical access log",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/log/lanpanel/apps/example-app/access.log"
			},
			want: "nginx.goaccess.auth_basic_user_file must not point to Lanpanel-managed GoAccess canonical access log path",
		},
		{
			name: "auth file under another Lanpanel app log namespace",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/var/log/lanpanel/apps/other-app/goaccess.htpasswd"
			},
			want: "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed app log namespace",
		},
		{
			name: "auth file collides with TLS private key",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/tls/abc.com/privkey.pem"
			},
			want: "nginx.goaccess.auth_basic_user_file must not point to Lanpanel-managed TLS private key path",
		},
		{
			name: "non-loopback websocket listen",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.WebSocketListen = "0.0.0.0:7890"
			},
			want: "nginx.goaccess.websocket_listen must use a loopback IP",
		},
		{
			name: "hostname websocket listen",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.WebSocketListen = "localhost:39001"
			},
			want: "nginx.goaccess.websocket_listen must use a loopback IP",
		},
		{
			name: "websocket listen reuses app listen port",
			mutate: func(cfg *Config) {
				cfg.App.Listen = "127.0.0.1:39001"
				cfg.Nginx.GoAccess.WebSocketListen = "127.0.0.1:39001"
			},
			want: "nginx.goaccess.websocket_listen must not overlap app.listen bind host and port",
		},
		{
			name: "default websocket listen reuses app listen port",
			mutate: func(cfg *Config) {
				port := strconv.Itoa(DefaultNginxGoAccessWebSocketPort(cfg.App.Name))
				cfg.App.Listen = "127.0.0.1:" + port
				cfg.Nginx.GoAccess.WebSocketListen = ""
			},
			want: "nginx.goaccess.websocket_listen must not overlap app.listen bind host and port",
		},
		{
			name: "dashboard root",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Path = "/"
			},
			want: "nginx.goaccess.path must not be /",
		},
		{
			name: "dashboard acme overlap",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Path = "/.well-known/"
			},
			want: "nginx.goaccess.path must not overlap /.well-known/acme-challenge/",
		},
		{
			name: "unsafe dashboard path",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Path = "/_lanpanel/goaccess;return"
			},
			want: "nginx.goaccess.path must not contain",
		},
		{
			name: "dashboard path with query marker",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Path = "/_lanpanel/goaccess?debug=1"
			},
			want: "nginx.goaccess.path must be a canonical URL path",
		},
		{
			name: "dashboard path with repeated slashes",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Path = "/_lanpanel//goaccess"
			},
			want: "nginx.goaccess.path must not contain repeated slashes",
		},
		{
			name: "websocket path with percent encoding",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.WebSocketPath = "/_lanpanel/goaccess/%77s"
			},
			want: "nginx.goaccess.websocket_path must be a canonical URL path",
		},
		{
			name: "websocket path with glob marker",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.WebSocketPath = "/_lanpanel/goaccess/ws[0]"
			},
			want: "nginx.goaccess.websocket_path must be a canonical URL path",
		},
		{
			name: "duplicate websocket path",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Path = "/_lanpanel/goaccess"
				cfg.Nginx.GoAccess.WebSocketPath = "/_lanpanel/goaccess"
			},
			want: "nginx.goaccess.websocket_path must not duplicate nginx.goaccess.path",
		},
		{
			name: "prefix dashboard would swallow websocket",
			mutate: func(cfg *Config) {
				cfg.Nginx.GoAccess.Path = "/_lanpanel/goaccess/"
				cfg.Nginx.GoAccess.WebSocketPath = "/_lanpanel/goaccess/ws"
			},
			want: "nginx.goaccess.path must not end with /",
		},
		{
			name: "static dashboard overlap",
			mutate: func(cfg *Config) {
				cfg.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/_lanpanel/", Alias: "/opt/example-app/web/static/"}}
			},
			want: "nginx.goaccess.path must not overlap nginx.static_locations[0].path",
		},
		{
			name: "static websocket overlap",
			mutate: func(cfg *Config) {
				cfg.Nginx.StaticLocations = []NginxStaticLocationConfig{{Path: "/_lanpanel/apps/example-app/goaccess/ws", Match: "exact", Alias: "/opt/example-app/web/static/ws.html"}}
			},
			want: "nginx.goaccess.websocket_path must not overlap nginx.static_locations[0].path",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.mutate(&cfg)
			expectValidationError(t, cfg, tt.want)
		})
	}

	disabledWithNoAuth := validListenConfig()
	disabledWithNoAuth.Nginx.GoAccess.Path = "/_lanpanel/apps/example-app/goaccess"
	expectValidationError(t, disabledWithNoAuth, "nginx.goaccess.enabled must be true when nginx.goaccess fields are set")
}

func TestValidateTailscaleRules(t *testing.T) {
	t.Parallel()

	cfg := validUpstreamConfig()
	cfg.Tailscale.LoginServer = "http://hs.example.com"
	expectValidationError(t, cfg, "tailscale.login_server must use https")

	cfg = validUpstreamConfig()
	cfg.Tailscale.LoginServer = "https://user:pass@hs.example.com"
	expectValidationError(t, cfg, "tailscale.login_server must be an origin URL")

	cfg = validUpstreamConfig()
	cfg.Tailscale.LoginServer = "https://hs.example.com/headscale"
	expectValidationError(t, cfg, "tailscale.login_server must not include a path")

	cfg = validUpstreamConfig()
	cfg.Tailscale.LoginServer = "https://hs.example.com?token=secret"
	expectValidationError(t, cfg, "tailscale.login_server must be an origin URL")

	cfg = validUpstreamConfig()
	cfg.Tailscale.LoginServer = "https://HS.EXAMPLE.COM:443/"
	cfg.normalize()
	if cfg.Tailscale.LoginServer != "https://hs.example.com" {
		t.Fatalf("normalized login_server = %q, want https://hs.example.com", cfg.Tailscale.LoginServer)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with canonical login_server error = %v", err)
	}

	cfg = validUpstreamConfig()
	cfg.Tailscale.LoginServer = "https://hs.example.com"
	cfg.Tailscale.LanpanelConfig = "lanpanel.yaml"
	expectValidationError(t, cfg, "tailscale.lanpanel_config must be empty when tailscale.login_server is set")

	cfg = validUpstreamConfig()
	cfg.Tailscale.LoginServer = "https://abc.com"
	expectValidationError(t, cfg, "tailscale.login_server host must not reuse an app domain")

	cfg = validUpstreamConfig()
	cfg.Tailscale.LanpanelConfig = "./lanpanel.yaml"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with relative lanpanel config error = %v", err)
	}

	cfg = validUpstreamConfig()
	cfg.Tailscale.Hostname = "Bad_Host"
	expectValidationError(t, cfg, "tailscale.hostname must contain only lowercase")

	cfg = validUpstreamConfig()
	cfg.Tailscale.AuthKeyFile = "auth.key"
	expectValidationError(t, cfg, "tailscale.auth_key_file must be an absolute path")

	cfg = validUpstreamConfig()
	cfg.Tailscale.AuthKeyFile = "/run/lanpanel/tailscale-auth.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestExampleYAMLMatchesDeployTemplateAndDoesNotCarrySecrets(t *testing.T) {
	t.Parallel()

	got, err := ExampleYAML()
	if err != nil {
		t.Fatalf("ExampleYAML() error = %v", err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "deploy", "config", "lanpanel-app.yaml.example"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("ExampleYAML() mismatch with deploy example\n got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(string(got), "authkey-") || strings.Contains(string(got), "CF_DNS_API_TOKEN=") {
		t.Fatalf("ExampleYAML() contains secret-looking value:\n%s", got)
	}
	if _, err := LoadBytes(got); err != nil {
		t.Fatalf("LoadBytes(ExampleYAML()) error = %v", err)
	}
}

func TestWriteFileUsesStrictPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "lanpanel-app.yaml")
	if err := validListenConfig().WriteFile(path); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %v, want 0600", got)
	}
}

func TestWriteFileRejectsSymlinkPath(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		write func(string) error
	}{
		{name: "app config", write: validListenConfig().WriteFile},
		{name: "example", write: WriteExampleFile},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			target := filepath.Join(dir, "target.yaml")
			link := filepath.Join(dir, "lanpanel-app.yaml")
			if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
				t.Fatalf("WriteFile(target) error = %v", err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}

			err := tt.write(link)
			if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
				t.Fatalf("write() error = %v, want symlink refusal", err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("ReadFile(target) error = %v", err)
			}
			if string(got) != "sentinel" {
				t.Fatalf("target content = %q, want sentinel", got)
			}
			info, err := os.Lstat(link)
			if err != nil {
				t.Fatalf("Lstat(link) error = %v", err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("link mode = %v, want symlink retained", info.Mode())
			}
		})
	}
}

func TestWriteFileRejectsSymlinkParentComponent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	realParent := filepath.Join(dir, "real")
	if err := os.MkdirAll(filepath.Join(realParent, "child"), 0o755); err != nil {
		t.Fatalf("MkdirAll(real parent) error = %v", err)
	}
	linkParent := filepath.Join(dir, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatalf("Symlink(parent) error = %v", err)
	}
	path := filepath.Join(linkParent, "child", "lanpanel-app.yaml")

	err := validListenConfig().WriteFile(path)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("WriteFile() error = %v, want symlink parent refusal", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("Lstat(path) error = %v, want no file created through symlink parent", err)
	}
}

func TestWriteFileRejectsOtherWritableParent(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("Mkdir(unsafe) error = %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod(unsafe) error = %v", err)
	}
	path := filepath.Join(dir, "lanpanel-app.yaml")

	err := validListenConfig().WriteFile(path)
	if err == nil || !strings.Contains(err.Error(), "untrusted local users") {
		t.Fatalf("WriteFile() error = %v, want unsafe parent refusal", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("Lstat(path) error = %v, want no file created in unsafe parent", err)
	}
}

func expectValidationError(t *testing.T, cfg Config, want string) {
	t.Helper()

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() error = %q, want substring %q", err.Error(), want)
	}
}

func expectLoadBytesError(t *testing.T, data string, want string) {
	t.Helper()

	_, err := LoadBytes([]byte(data))
	if err == nil {
		t.Fatalf("LoadBytes() error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("LoadBytes() error = %q, want substring %q", err.Error(), want)
	}
}
