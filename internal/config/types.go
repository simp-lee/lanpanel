package config

const (
	APIVersion                             = "lanpanel/v1alpha1"
	DefaultHeadscaleVersion                = "0.29.1"
	DefaultLegoVersion                     = "v5.2.2"
	DefaultHeadscaleMetricsPort            = 19090
	DefaultPackageProbeReachabilityTimeout = "30s"
	DefaultPackageProbeArtifactTimeout     = "5m"

	ACMEChallengeHTTP01 = "http-01"
	ACMEChallengeDNS01  = "dns-01"

	PackageSourceModeDirect  = "direct"
	PackageSourceModeMirror  = "mirror"
	PackageSourceModeOffline = "offline"

	ArchAMD64 = "amd64"
	ArchARM64 = "arm64"
)

type Config struct {
	APIVersion string         `yaml:"api_version"`
	Default    DefaultConfig  `yaml:"default"`
	Advanced   AdvancedConfig `yaml:"advanced"`
}

type DefaultConfig struct {
	ServerURL        string `yaml:"server_url"`
	BaseDomain       string `yaml:"base_domain"`
	CertificateEmail string `yaml:"certificate_email"`
	ACMEChallenge    string `yaml:"acme_challenge"`
}

type AdvancedConfig struct {
	HeadscaleSource HeadscaleSourceConfig `yaml:"headscale_source"`
	Headscale       HeadscaleConfig       `yaml:"headscale"`
	LegoSource      LegoSourceConfig      `yaml:"lego_source"`
	PackageProbe    PackageProbeConfig    `yaml:"package_probe"`
	Proxy           ProxyConfig           `yaml:"proxy"`
	DNS01           DNS01Config           `yaml:"dns01"`
	Network         NetworkConfig         `yaml:"network"`
	Platform        PlatformConfig        `yaml:"platform"`
}

type DependencyConfig struct {
	LegoSource   LegoSourceConfig   `yaml:"lego_source"`
	PackageProbe PackageProbeConfig `yaml:"package_probe"`
	Proxy        ProxyConfig        `yaml:"proxy"`
	Platform     PlatformConfig     `yaml:"platform"`
}

type HeadscaleSourceConfig struct {
	Mode     string `yaml:"mode"`
	Version  string `yaml:"version"`
	URL      string `yaml:"url"`
	SHA256   string `yaml:"sha256"`
	FilePath string `yaml:"file_path"`
}

type HeadscaleConfig struct {
	MetricsPort int `yaml:"metrics_port"`
}

type LegoSourceConfig struct {
	Mode     string `yaml:"mode"`
	FilePath string `yaml:"file_path"`
}

type PackageProbeConfig struct {
	ReachabilityTimeout string `yaml:"reachability_timeout"`
	ArtifactTimeout     string `yaml:"artifact_timeout"`
}

type ProxyConfig struct {
	HTTPProxy  string `yaml:"http_proxy"`
	HTTPSProxy string `yaml:"https_proxy"`
	NoProxy    string `yaml:"no_proxy"`
}

type DNS01Config struct {
	Provider string `yaml:"provider"`
	EnvFile  string `yaml:"env_file"`

	// Deprecated: retained only so in-memory legacy configs fail validation
	// explicitly. YAML loading rejects credentials_file as an unknown field.
	CredentialsFile string `yaml:"-"`
}

type NetworkConfig struct {
	PublicIPv4 string `yaml:"public_ipv4"`
	PublicIPv6 string `yaml:"public_ipv6"`
}

type PlatformConfig struct {
	Arch string `yaml:"arch"`
}
