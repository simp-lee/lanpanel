// Package workflow orchestrates user-facing lanpanel flows.
package workflow

import (
	"fmt"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/prompt"
	"net/url"
	"path/filepath"
	"strings"

	tlscomponent "lanpanel/internal/components/tls"
)

type InitMode string

const (
	InitModeDefault  InitMode = "default"
	InitModeAdvanced InitMode = "advanced"
)

type InitSource string

const (
	InitSourceExample InitSource = "example"
	InitSourceGuided  InitSource = "guided"
)

type InitOptions struct {
	Advanced bool
}

type InitResult struct {
	Config config.Config
	Mode   InitMode
	Source InitSource
}

func ExampleInitResult() InitResult {
	return InitResult{
		Config: config.ExampleConfig(),
		Source: InitSourceExample,
	}
}

func RunInit(prompter prompt.Prompter, options InitOptions) (InitResult, error) {
	if prompter == nil || !prompter.Enabled() {
		return InitResult{}, fmt.Errorf("guided init requires interactive input")
	}

	cfg := config.New()
	mode := InitModeDefault
	if options.Advanced {
		mode = InitModeAdvanced
	} else {
		advanced, err := prompter.Confirm("Use advanced mode now?", prompt.ConfirmPrompt{
			Default: false,
			Help:    "Choose advanced if you need DNS-01, mirror or offline packages, offline lego archives, package probe timeouts, proxy, architecture, or public IP overrides.",
		})
		if err != nil {
			return InitResult{}, err
		}
		if advanced {
			mode = InitModeAdvanced
		}
	}

	var err error
	if cfg.Default.ServerURL, err = prompter.Text("Headscale server URL", prompt.TextPrompt{
		Help:     "Use the public HTTPS URL clients will open, for example https://hs.example.com",
		Validate: validateServerURL,
	}); err != nil {
		return InitResult{}, err
	}

	if cfg.Default.BaseDomain, err = prompter.Text("MagicDNS base domain", prompt.TextPrompt{
		Help: "Must differ from the Headscale host name, for example tailnet.example.com",
		Validate: func(value string) error {
			return validateBaseDomain(cfg.Default.ServerURL, value)
		},
	}); err != nil {
		return InitResult{}, err
	}

	if cfg.Default.CertificateEmail, err = prompter.Text("Certificate email", prompt.TextPrompt{
		Help:     "Used for ACME registration and renewal notices",
		Validate: validateCertificateEmail,
	}); err != nil {
		return InitResult{}, err
	}

	if mode == InitModeAdvanced {
		if err := collectAdvancedFields(prompter, &cfg); err != nil {
			return InitResult{}, err
		}
	}

	if err := cfg.Validate(); err != nil {
		return InitResult{}, fmt.Errorf("validate guided config: %w", err)
	}

	return InitResult{
		Config: cfg,
		Mode:   mode,
		Source: InitSourceGuided,
	}, nil
}

func (result InitResult) Summary() string {
	if result.Source == InitSourceGuided {
		return "wrote guided config"
	}
	return "wrote example config"
}

func (result InitResult) SourceLabel() string {
	if result.Source == InitSourceGuided {
		return "guided " + string(result.Mode)
	}
	return "example template"
}

func (result InitResult) Fields(configPath string) []domain.ResultField {
	return []domain.ResultField{
		{Label: "config path", Value: configPath},
		{Label: "config source", Value: result.SourceLabel()},
		{Label: "server url", Value: result.Config.Default.ServerURL},
		{Label: "base domain", Value: result.Config.Default.BaseDomain},
		{Label: "acme challenge", Value: result.Config.Default.ACMEChallenge},
	}
}

func (result InitResult) NextSteps(configPath string) []string {
	return result.nextSteps(configPath)
}

func (result InitResult) nextSteps(configPath string) []string {
	steps := []string{}
	advancedConfigPath := suggestAdvancedConfigPath(configPath)

	switch result.Source {
	case InitSourceExample:
		steps = append(steps,
			"Edit default.server_url, default.base_domain, and default.certificate_email for your environment.",
			fmt.Sprintf("If you want guided advanced questions later, generate a separate advanced config with 'lanpanel init --advanced --config %s' and copy the advanced values you need into %s.", advancedConfigPath, configPath),
		)
	case InitSourceGuided:
		if result.Mode == InitModeDefault {
			steps = append(steps,
				"Review the generated default section and edit the advanced section only if your environment needs it.",
				fmt.Sprintf("If you later need guided advanced answers for DNS-01, mirror or offline packages, offline lego archives, package probe timeouts, proxy, architecture, or public IP overrides, generate a separate advanced config with 'lanpanel init --advanced --config %s' and copy the advanced values you need into %s.", advancedConfigPath, configPath),
			)
		} else {
			steps = append(steps, "Review the generated advanced section before deploy, especially Headscale source, lego source, package probe timeouts, proxy, DNS-01, architecture, and public IP overrides.")
			if result.Config.Default.ACMEChallenge == config.ACMEChallengeDNS01 {
				if provider, err := tlscomponent.DNSProvider(result.Config.Advanced.DNS01.Provider); err == nil && provider.AmbientCredentialsSupported && strings.TrimSpace(result.Config.Advanced.DNS01.EnvFile) == "" {
					steps = append(steps, "Confirm the selected lego DNS provider's ambient credentials are available to both deploy and systemd renewal.")
					if provider.LegoCode == "gcloud" {
						steps = append(steps, "For gcloud ambient mode, confirm Google Cloud metadata also provides the project; otherwise set an env file with GCE_PROJECT.")
					}
				} else {
					steps = append(steps, "Prepare the root-only DNS-01 env file required by the selected lego provider.")
				}
			}
		}
	}

	steps = append(steps,
		fmt.Sprintf("Run 'lanpanel deploy --config %s' to validate the deploy surface with this config.", configPath),
		fmt.Sprintf("Run 'lanpanel verify --config %s' to validate this config now.", configPath),
	)

	return steps
}

func suggestAdvancedConfigPath(configPath string) string {
	extension := filepath.Ext(configPath)
	if extension == "" {
		return configPath + ".advanced"
	}

	return strings.TrimSuffix(configPath, extension) + ".advanced" + extension
}

func collectAdvancedFields(prompter prompt.Prompter, cfg *config.Config) error {
	var err error

	if cfg.Default.ACMEChallenge, err = prompter.Select("ACME challenge", prompt.SelectPrompt{
		Default: config.ACMEChallengeHTTP01,
		Help:    "Keep http-01 unless your environment specifically requires DNS-01",
		Options: []string{config.ACMEChallengeHTTP01, config.ACMEChallengeDNS01},
	}); err != nil {
		return err
	}

	if cfg.Default.ACMEChallenge == config.ACMEChallengeDNS01 {
		if cfg.Advanced.DNS01.Provider, err = prompter.Text("DNS-01 provider", prompt.TextPrompt{
			Help:     "Use a lego DNS provider: " + tlscomponent.SupportedDNSProviderNames() + " (google is accepted as a gcloud alias)",
			Validate: validateDNS01Provider,
		}); err != nil {
			return err
		}

		providerInfo, err := tlscomponent.DNSProvider(cfg.Advanced.DNS01.Provider)
		if err != nil {
			return err
		}
		if cfg.Advanced.DNS01.EnvFile, err = prompter.Text("DNS-01 env file", prompt.TextPrompt{
			Help:     dns01EnvFileHelp(providerInfo),
			Validate: validateDNS01EnvFile(providerInfo),
		}); err != nil {
			return err
		}
	}

	if cfg.Advanced.HeadscaleSource.Mode, err = prompter.Select("Headscale source mode", prompt.SelectPrompt{
		Default: config.PackageSourceModeDirect,
		Help:    "Use mirror or offline only when direct package download is not suitable",
		Options: []string{config.PackageSourceModeDirect, config.PackageSourceModeMirror, config.PackageSourceModeOffline},
	}); err != nil {
		return err
	}

	if cfg.Advanced.HeadscaleSource.Version, err = prompter.Text("Headscale package version", prompt.TextPrompt{
		Default: config.DefaultHeadscaleVersion,
		Help:    "Press Enter to keep the default tested version",
		Validate: func(value string) error {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("advanced.headscale_source.version is required")
			}
			return nil
		},
	}); err != nil {
		return err
	}

	switch cfg.Advanced.HeadscaleSource.Mode {
	case config.PackageSourceModeMirror:
		if cfg.Advanced.HeadscaleSource.URL, err = prompter.Text("Headscale mirror package URL", prompt.TextPrompt{
			Help:     "Use the full URL to the headscale .deb package",
			Validate: validateMirrorURL,
		}); err != nil {
			return err
		}
		if cfg.Advanced.HeadscaleSource.SHA256, err = prompter.Text("Headscale mirror package SHA-256", prompt.TextPrompt{
			Help:     "Use the lowercase 64-character checksum for the package",
			Validate: validateMirrorSHA256,
		}); err != nil {
			return err
		}
	case config.PackageSourceModeOffline:
		if cfg.Advanced.HeadscaleSource.FilePath, err = prompter.Text("Offline Headscale package path", prompt.TextPrompt{
			Help:     "Use the absolute or relative path to the local headscale .deb file",
			Validate: validateOfflinePath,
		}); err != nil {
			return err
		}
		if cfg.Advanced.HeadscaleSource.SHA256, err = prompter.Text("Offline Headscale package SHA-256", prompt.TextPrompt{
			Help:     "Use the lowercase 64-character checksum for the package",
			Validate: validateOfflineSHA256,
		}); err != nil {
			return err
		}
	}

	if cfg.Advanced.LegoSource.Mode, err = prompter.Select("lego archive source mode", prompt.SelectPrompt{
		Default: config.PackageSourceModeDirect,
		Help:    "Use offline only when this host cannot download the pinned lego GitHub release archive",
		Options: []string{config.PackageSourceModeDirect, config.PackageSourceModeOffline},
	}); err != nil {
		return err
	}
	if cfg.Advanced.LegoSource.Mode == config.PackageSourceModeOffline {
		if cfg.Advanced.LegoSource.FilePath, err = prompter.Text("Offline lego archive path", prompt.TextPrompt{
			Help:     "Use the absolute or relative path to the local pinned lego .tar.gz archive",
			Validate: validateLegoOfflinePath,
		}); err != nil {
			return err
		}
	}

	configureProxy, err := prompter.Confirm("Configure HTTP or HTTPS proxy settings?", prompt.ConfirmPrompt{
		Default: false,
		Help:    "Leave this off unless the host needs a proxy to reach package or ACME endpoints",
	})
	if err != nil {
		return err
	}
	if configureProxy {
		if cfg.Advanced.Proxy.HTTPProxy, err = prompter.Text("http_proxy", prompt.TextPrompt{
			Help:     "Optional. Leave empty to skip.",
			Validate: validateHTTPProxy,
		}); err != nil {
			return err
		}
		if cfg.Advanced.Proxy.HTTPSProxy, err = prompter.Text("https_proxy", prompt.TextPrompt{
			Help:     "Optional. Leave empty to skip.",
			Validate: validateHTTPSProxy,
		}); err != nil {
			return err
		}
		if cfg.Advanced.Proxy.NoProxy, err = prompter.Text("no_proxy", prompt.TextPrompt{
			Help: "Optional. Use a comma-separated list such as 127.0.0.1,localhost",
		}); err != nil {
			return err
		}
	}

	if cfg.Advanced.Platform.Arch, err = prompter.Select("Target architecture", prompt.SelectPrompt{
		Default: config.ArchAMD64,
		Help:    "Keep amd64 unless the host is arm64",
		Options: []string{config.ArchAMD64, config.ArchARM64},
	}); err != nil {
		return err
	}

	overrideIPs, err := prompter.Confirm("Override public IP detection?", prompt.ConfirmPrompt{
		Default: false,
		Help:    "Only use this if the host cannot advertise the right public address on its own",
	})
	if err != nil {
		return err
	}
	if overrideIPs {
		if cfg.Advanced.Network.PublicIPv4, err = prompter.Text("Public IPv4 override", prompt.TextPrompt{
			Help:     "Optional. Leave empty to skip.",
			Validate: validatePublicIPv4,
		}); err != nil {
			return err
		}
		if cfg.Advanced.Network.PublicIPv6, err = prompter.Text("Public IPv6 override", prompt.TextPrompt{
			Help:     "Optional enhancement. Leave empty when the host has no usable IPv6.",
			Validate: validatePublicIPv6,
		}); err != nil {
			return err
		}
	}

	return nil
}

func validateServerURL(value string) error {
	candidate := config.ExampleConfig()
	candidate.Default.ServerURL = value
	candidate.Default.BaseDomain = validationBaseDomainForServerURL(value)
	return candidate.Validate()
}

func validationBaseDomainForServerURL(value string) string {
	parsedURL, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return config.ExampleConfig().Default.BaseDomain
	}

	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsedURL.Hostname()), "."))
	for _, baseDomain := range []string{"lanpanel-init.invalid", "lanpanel-init.example", "lanpanel-init.test"} {
		if host != baseDomain && !strings.HasSuffix(host, "."+baseDomain) {
			return baseDomain
		}
	}
	return config.ExampleConfig().Default.BaseDomain
}

func validateBaseDomain(serverURL string, value string) error {
	candidate := config.ExampleConfig()
	candidate.Default.ServerURL = serverURL
	candidate.Default.BaseDomain = value
	return candidate.Validate()
}

func validateCertificateEmail(value string) error {
	candidate := config.ExampleConfig()
	candidate.Default.CertificateEmail = value
	return candidate.Validate()
}

func validateDNS01Provider(value string) error {
	_, err := tlscomponent.DNSProvider(value)
	return err
}

func dns01EnvFileHelp(provider tlscomponent.DNSProviderInfo) string {
	if provider.AmbientCredentialsSupported {
		if provider.LegoCode == "gcloud" {
			return "Optional for gcloud when the host has ambient credentials available to both deploy and systemd renewal and Google Cloud metadata provides the project. If metadata does not provide the project, set an absolute path to a root-only env file with GCE_PROJECT; the same env file may carry non-secret settings such as GCE_ZONE_ID. Store raw DNS secrets in separate root-only files and reference them with lego _FILE variables."
		}
		return fmt.Sprintf("Optional for %s when the host has ambient credentials available to both deploy and systemd renewal. If set, use an absolute path to a root-only env file for non-secret provider settings or provider _FILE references; store raw DNS secrets in separate root-only files and reference them with lego _FILE variables.", provider.LegoCode)
	}
	return fmt.Sprintf("Required for %s. Use an absolute path to a root-only env file. Store raw DNS secrets in separate root-only files and reference them with lego _FILE variables.", provider.LegoCode)
}

func validateDNS01EnvFile(provider tlscomponent.DNSProviderInfo) func(string) error {
	return func(value string) error {
		value = strings.TrimSpace(value)

		candidate := config.ExampleConfig()
		candidate.Default.ACMEChallenge = config.ACMEChallengeDNS01
		candidate.Advanced.DNS01.Provider = provider.Name
		candidate.Advanced.DNS01.EnvFile = value
		return candidate.Validate()
	}
}

func validateMirrorURL(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.HeadscaleSource.Mode = config.PackageSourceModeMirror
	candidate.Advanced.HeadscaleSource.URL = value
	candidate.Advanced.HeadscaleSource.SHA256 = strings.Repeat("a", 64)
	return candidate.Validate()
}

func validateMirrorSHA256(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.HeadscaleSource.Mode = config.PackageSourceModeMirror
	candidate.Advanced.HeadscaleSource.URL = "https://mirror.example.com/headscale.deb"
	candidate.Advanced.HeadscaleSource.SHA256 = value
	return candidate.Validate()
}

func validateOfflinePath(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.HeadscaleSource.Mode = config.PackageSourceModeOffline
	candidate.Advanced.HeadscaleSource.FilePath = value
	candidate.Advanced.HeadscaleSource.SHA256 = strings.Repeat("b", 64)
	return candidate.Validate()
}

func validateOfflineSHA256(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.HeadscaleSource.Mode = config.PackageSourceModeOffline
	candidate.Advanced.HeadscaleSource.FilePath = "/tmp/headscale.deb"
	candidate.Advanced.HeadscaleSource.SHA256 = value
	return candidate.Validate()
}

func validateLegoOfflinePath(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.LegoSource.Mode = config.PackageSourceModeOffline
	candidate.Advanced.LegoSource.FilePath = value
	return candidate.Validate()
}

func validateHTTPProxy(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.Proxy.HTTPProxy = value
	return candidate.Validate()
}

func validateHTTPSProxy(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.Proxy.HTTPSProxy = value
	return candidate.Validate()
}

func validatePublicIPv4(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.Network.PublicIPv4 = value
	return candidate.Validate()
}

func validatePublicIPv6(value string) error {
	candidate := config.ExampleConfig()
	candidate.Advanced.Network.PublicIPv6 = value
	return candidate.Validate()
}
