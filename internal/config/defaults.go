package config

import "runtime"

func New() Config {
	dependencies := NewDependencyConfig()
	return Config{
		APIVersion: APIVersion,
		Default: DefaultConfig{
			ACMEChallenge: ACMEChallengeHTTP01,
		},
		Advanced: AdvancedConfig{
			HeadscaleSource: HeadscaleSourceConfig{
				Mode:    PackageSourceModeDirect,
				Version: DefaultHeadscaleVersion,
			},
			Headscale: HeadscaleConfig{
				MetricsPort: DefaultHeadscaleMetricsPort,
			},
			LegoSource:   dependencies.LegoSource,
			PackageProbe: dependencies.PackageProbe,
			Proxy:        dependencies.Proxy,
			Platform:     dependencies.Platform,
		},
	}
}

func ExampleConfig() Config {
	cfg := New()
	cfg.Default.ServerURL = "https://hs.example.com"
	cfg.Default.BaseDomain = "tailnet.example.com"
	cfg.Default.CertificateEmail = "ops@example.com"
	return cfg
}

func NewDependencyConfig() DependencyConfig {
	return DependencyConfig{
		LegoSource: LegoSourceConfig{
			Mode: PackageSourceModeDirect,
		},
		PackageProbe: PackageProbeConfig{
			ReachabilityTimeout: DefaultPackageProbeReachabilityTimeout,
			ArtifactTimeout:     DefaultPackageProbeArtifactTimeout,
		},
		Platform: PlatformConfig{
			Arch: DefaultPlatformArch(),
		},
	}
}

func (d *DependencyConfig) ApplyDefaults() {
	defaults := NewDependencyConfig()
	if d.LegoSource.Mode == "" {
		d.LegoSource.Mode = defaults.LegoSource.Mode
	}
	if d.PackageProbe.ReachabilityTimeout == "" {
		d.PackageProbe.ReachabilityTimeout = defaults.PackageProbe.ReachabilityTimeout
	}
	if d.PackageProbe.ArtifactTimeout == "" {
		d.PackageProbe.ArtifactTimeout = defaults.PackageProbe.ArtifactTimeout
	}
	if d.Platform.Arch == "" {
		d.Platform.Arch = defaults.Platform.Arch
	}
}

func (a AdvancedConfig) DependencyConfig() DependencyConfig {
	return DependencyConfig{
		LegoSource:   a.LegoSource,
		PackageProbe: a.PackageProbe,
		Proxy:        a.Proxy,
		Platform:     a.Platform,
	}
}

func DefaultPlatformArch() string {
	return runtime.GOARCH
}
