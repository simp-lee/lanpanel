package appconfig

import "lanpanel/internal/config"

const (
	APIVersion                = "lanpanel/app/v1alpha2"
	DefaultConfigPath         = "lanpanel-app.yaml"
	DefaultLanpanelConfigPath = "lanpanel.yaml"

	DefaultNginxClientMaxBodySize = "20m"
	DefaultNginxProxyReadTimeout  = "600s"
	DefaultNginxProxySendTimeout  = "600s"
	DefaultRealIPRefreshInterval  = "72h"

	DefaultNginxGoAccessLanguage            = "en"
	DefaultNginxGoAccessLogFormat           = NginxGoAccessLogFormatEnhanced
	DefaultNginxGoAccessPathSuffix          = "goaccess"
	DefaultNginxGoAccessWebSocketPathSuffix = "ws"

	NginxGoAccessLanguageEnglish           = "en"
	NginxGoAccessLanguageSimplifiedChinese = "zh-CN"

	NginxGoAccessLogFormatEnhanced = "enhanced"
	NginxGoAccessLogFormatCombined = "combined"

	NginxGoAccessDefaultWebSocketHost = "127.0.0.1"
	NginxGoAccessWebSocketPortBase    = 39000
	NginxGoAccessWebSocketPortSpan    = 20000

	ACMEChallengeHTTP01 = "http-01"
	ACMEChallengeDNS01  = "dns-01"

	RealIPProviderEdgeOne = "edgeone"
	RealIPHeaderEdgeOne   = "EO-Connecting-IP"

	ModeListen   Mode = "listen"
	ModeUpstream Mode = "upstream"

	AccessModeBrowser       AccessMode = "browser"
	AccessModePublic        AccessMode = "public"
	AccessModePrivateClient AccessMode = "private_client"

	OriginProtectionModeNone    OriginProtectionMode = "none"
	OriginProtectionModeEdgeOne OriginProtectionMode = "edgeone"
)

type Mode string
type AccessMode string
type OriginProtectionMode string

type Config struct {
	APIVersion   string                  `yaml:"api_version"`
	App          AppConfig               `yaml:"app"`
	Access       AccessConfig            `yaml:"access"`
	Service      ServiceConfig           `yaml:"service"`
	Nginx        NginxConfig             `yaml:"nginx"`
	RealIP       RealIPConfig            `yaml:"realip"`
	DNS01        DNS01Config             `yaml:"dns01"`
	Tailscale    TailscaleConfig         `yaml:"tailscale"`
	Dependencies config.DependencyConfig `yaml:"dependencies"`
}

type AppConfig struct {
	Name             string   `yaml:"name"`
	Domains          []string `yaml:"domains"`
	CertificateEmail string   `yaml:"certificate_email"`
	ACMEChallenge    string   `yaml:"acme_challenge"`
	Listen           string   `yaml:"listen"`
	Upstream         string   `yaml:"upstream"`
}

type AccessConfig struct {
	AccessMode          AccessMode             `yaml:"access_mode"`
	BrowserAuth         BrowserAuthConfig      `yaml:"browser_auth"`
	CIDRAllowlist       []string               `yaml:"cidr_allowlist"`
	PublicRiskConfirmed bool                   `yaml:"public_risk_confirmed"`
	OriginProtection    OriginProtectionConfig `yaml:"origin_protection"`
}

type BrowserAuthConfig struct {
	AuthBasicUserFile string                `yaml:"auth_basic_user_file"`
	Managed           ManagedBrowserAuthRef `yaml:"managed"`
}

type ManagedBrowserAuthRef struct {
	CredentialID        string `yaml:"credential_id"`
	HtpasswdPath        string `yaml:"htpasswd_path"`
	Username            string `yaml:"username"`
	PasswordFingerprint string `yaml:"password_fingerprint"`
}

type OriginProtectionConfig struct {
	Mode                      OriginProtectionMode `yaml:"mode"`
	EdgeOneProfile            string               `yaml:"edgeone_profile"`
	DirectOriginRiskConfirmed bool                 `yaml:"direct_origin_risk_confirmed"`
}

type ServiceConfig struct {
	ExecStart        string `yaml:"exec_start"`
	WorkingDirectory string `yaml:"working_directory"`
	EnvFile          string `yaml:"env_file"`
}

type NginxConfig struct {
	ClientMaxBodySize string                      `yaml:"client_max_body_size"`
	HTTP2             *bool                       `yaml:"http2"`
	AccessLog         string                      `yaml:"access_log"`
	ErrorLog          string                      `yaml:"error_log"`
	GoAccess          NginxGoAccessConfig         `yaml:"goaccess"`
	Proxy             NginxProxyConfig            `yaml:"proxy"`
	StaticLocations   []NginxStaticLocationConfig `yaml:"static_locations"`
}

type RealIPConfig struct {
	Profiles map[string]RealIPProfileConfig `yaml:"profiles"`
}

type RealIPProfileConfig struct {
	Enabled         *bool               `yaml:"enabled"`
	Provider        string              `yaml:"provider"`
	RefreshInterval string              `yaml:"refresh_interval"`
	EdgeOne         RealIPEdgeOneConfig `yaml:"edgeone"`
}

type RealIPEdgeOneConfig struct {
	ZoneID  string `yaml:"zone_id"`
	EnvFile string `yaml:"env_file"`
}

type NginxGoAccessConfig struct {
	Enabled           bool     `yaml:"enabled"`
	Language          string   `yaml:"language"`
	LogFormat         string   `yaml:"log_format"`
	Path              string   `yaml:"path"`
	WebSocketPath     string   `yaml:"websocket_path"`
	WebSocketListen   string   `yaml:"websocket_listen"`
	AuthBasicUserFile string   `yaml:"auth_basic_user_file"`
	AuthCIDRAllowlist []string `yaml:"auth_cidr_allowlist"`
}

type NginxProxyConfig struct {
	ConnectTimeout   string `yaml:"connect_timeout"`
	ReadTimeout      string `yaml:"read_timeout"`
	SendTimeout      string `yaml:"send_timeout"`
	Buffering        *bool  `yaml:"buffering"`
	RequestBuffering *bool  `yaml:"request_buffering"`
}

type NginxStaticLocationConfig struct {
	Path         string `yaml:"path"`
	Match        string `yaml:"match"`
	Alias        string `yaml:"alias"`
	DefaultType  string `yaml:"default_type"`
	Expires      string `yaml:"expires"`
	CacheControl string `yaml:"cache_control"`
	TryFiles     bool   `yaml:"try_files"`
	GzipStatic   bool   `yaml:"gzip_static"`
	AccessLog    *bool  `yaml:"access_log"`
}

type DNS01Config struct {
	Provider string `yaml:"provider"`
	EnvFile  string `yaml:"env_file"`
}

type TailscaleConfig struct {
	EnabledForListen bool   `yaml:"enabled_for_listen"`
	LanpanelConfig   string `yaml:"lanpanel_config"`
	LoginServer      string `yaml:"login_server"`
	Hostname         string `yaml:"hostname"`
	AuthKeyFile      string `yaml:"auth_key_file"`
}
