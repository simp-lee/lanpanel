package config

import (
	"fmt"
	"lanpanel/internal/acme"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

type validationErrors []string

func (errs validationErrors) Error() string {
	return strings.Join(errs, "; ")
}

func (c Config) Validate() error {
	var errs validationErrors

	if strings.TrimSpace(c.APIVersion) == "" {
		errs = append(errs, "api_version is required")
	} else if c.APIVersion != APIVersion {
		errs = append(errs, fmt.Sprintf("api_version must be %q", APIVersion))
	}

	serverHost := ""
	serverURL := strings.TrimSpace(c.Default.ServerURL)
	if serverURL == "" {
		errs = append(errs, "default.server_url is required")
	} else {
		parsedURL, err := url.Parse(serverURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("default.server_url must be a valid URL: %v", err))
		} else {
			if parsedURL.Scheme != "https" {
				errs = append(errs, "default.server_url must use https")
			}
			if port := parsedURL.Port(); port != "" && port != "443" {
				errs = append(errs, "default.server_url must not specify a port other than 443")
			}
			serverHost = normalizeDomain(parsedURL.Hostname())
			if serverHost == "" {
				errs = append(errs, "default.server_url host is required")
			} else if !looksLikeDNSName(serverHost) {
				errs = append(errs, "default.server_url host must be a DNS name")
			}
		}
	}

	baseDomain := normalizeDomain(c.Default.BaseDomain)
	if baseDomain == "" {
		errs = append(errs, "default.base_domain is required")
	} else if !looksLikeDNSName(baseDomain) {
		errs = append(errs, "default.base_domain must be a DNS name")
	}

	if baseDomain != "" && serverHost != "" {
		if baseDomain == serverHost {
			errs = append(errs, "default.base_domain must not equal default.server_url host")
		}
		if hasDomainSuffix(serverHost, baseDomain) {
			errs = append(errs, "default.base_domain must not be a parent domain of default.server_url host")
		}
	}

	email := strings.TrimSpace(c.Default.CertificateEmail)
	if email == "" {
		errs = append(errs, "default.certificate_email is required")
	} else {
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email {
			errs = append(errs, "default.certificate_email must be a plain email address")
		}
		if strings.Contains(email, "%") {
			errs = append(errs, "default.certificate_email must not contain % because systemd unit files treat it as a specifier")
		}
	}

	acmeChallenge := strings.TrimSpace(c.Default.ACMEChallenge)
	switch acmeChallenge {
	case ACMEChallengeHTTP01, ACMEChallengeDNS01:
	case "":
		errs = append(errs, "default.acme_challenge is required")
	default:
		errs = append(errs, "default.acme_challenge must be one of: http-01, dns-01")
	}

	validateHeadscaleSource(&errs, c.Advanced.HeadscaleSource)
	validateHeadscale(&errs, c.Advanced.Headscale)
	validateDependencyConfig(&errs, "advanced", c.Advanced.DependencyConfig())
	validateDNS01(&errs, acmeChallenge, c.Advanced.DNS01)
	validateIPOverride(&errs, "advanced.network.public_ipv4", c.Advanced.Network.PublicIPv4, false)
	validateIPOverride(&errs, "advanced.network.public_ipv6", c.Advanced.Network.PublicIPv6, true)

	if len(errs) == 0 {
		return nil
	}

	return errs
}

func validateHeadscale(errs *validationErrors, headscale HeadscaleConfig) {
	port := headscale.MetricsPort
	if port == 0 {
		*errs = append(*errs, "advanced.headscale.metrics_port is required")
		return
	}
	if port < 1 || port > 65535 {
		*errs = append(*errs, "advanced.headscale.metrics_port must be between 1 and 65535")
		return
	}
	switch port {
	case 80, 443, 3478, 8080, 50443:
		*errs = append(*errs, "advanced.headscale.metrics_port must not reuse lanpanel public, Headscale control-plane, gRPC, or STUN ports")
	}
}

func validateHeadscaleSource(errs *validationErrors, source HeadscaleSourceConfig) {
	mode := strings.TrimSpace(source.Mode)
	version := strings.TrimSpace(source.Version)
	urlValue := strings.TrimSpace(source.URL)
	sha256 := strings.TrimSpace(source.SHA256)
	filePath := strings.TrimSpace(source.FilePath)

	if mode == "" {
		*errs = append(*errs, "advanced.headscale_source.mode is required")
		return
	}
	if version == "" {
		*errs = append(*errs, "advanced.headscale_source.version is required")
	}

	switch mode {
	case PackageSourceModeDirect:
		if urlValue != "" {
			*errs = append(*errs, "advanced.headscale_source.url is only allowed when advanced.headscale_source.mode is mirror")
		}
		if filePath != "" {
			*errs = append(*errs, "advanced.headscale_source.file_path is only allowed when advanced.headscale_source.mode is offline")
		}
		if sha256 != "" {
			*errs = append(*errs, "advanced.headscale_source.sha256 is only allowed when advanced.headscale_source.mode is mirror or offline")
		}
	case PackageSourceModeMirror:
		if urlValue == "" {
			*errs = append(*errs, "advanced.headscale_source.url is required when advanced.headscale_source.mode is mirror")
		} else {
			validateAbsoluteURL(errs, "advanced.headscale_source.url", urlValue)
		}
		if filePath != "" {
			*errs = append(*errs, "advanced.headscale_source.file_path is only allowed when advanced.headscale_source.mode is offline")
		}
		if sha256 == "" {
			*errs = append(*errs, "advanced.headscale_source.sha256 is required when advanced.headscale_source.mode is mirror")
		}
	case PackageSourceModeOffline:
		if filePath == "" {
			*errs = append(*errs, "advanced.headscale_source.file_path is required when advanced.headscale_source.mode is offline")
		} else if filepath.Clean(filePath) == "." {
			*errs = append(*errs, "advanced.headscale_source.file_path must be a valid file path")
		}
		if urlValue != "" {
			*errs = append(*errs, "advanced.headscale_source.url is only allowed when advanced.headscale_source.mode is mirror")
		}
		if sha256 == "" {
			*errs = append(*errs, "advanced.headscale_source.sha256 is required when advanced.headscale_source.mode is offline")
		}
	default:
		*errs = append(*errs, "advanced.headscale_source.mode must be one of: direct, mirror, offline")
	}

	if sha256 != "" && !isHexSHA256(sha256) {
		*errs = append(*errs, "advanced.headscale_source.sha256 must be a 64-character lowercase hexadecimal SHA-256 digest")
	}
}

func ValidateDependencyConfig(fieldPrefix string, dependencies DependencyConfig) error {
	var errs validationErrors
	validateDependencyConfig(&errs, strings.TrimSpace(fieldPrefix), dependencies)
	if len(errs) == 0 {
		return nil
	}
	return errs
}

func validateDependencyConfig(errs *validationErrors, fieldPrefix string, dependencies DependencyConfig) {
	if fieldPrefix == "" {
		fieldPrefix = "dependencies"
	}
	validateLegoSource(errs, fieldPrefix+".lego_source", dependencies.LegoSource)
	validatePackageProbe(errs, fieldPrefix+".package_probe", dependencies.PackageProbe)
	validateProxyURL(errs, fieldPrefix+".proxy.http_proxy", dependencies.Proxy.HTTPProxy)
	validateProxyURL(errs, fieldPrefix+".proxy.https_proxy", dependencies.Proxy.HTTPSProxy)
	validatePlatform(errs, fieldPrefix+".platform", dependencies.Platform)
}

func validateLegoSource(errs *validationErrors, field string, source LegoSourceConfig) {
	mode := strings.TrimSpace(source.Mode)
	filePath := strings.TrimSpace(source.FilePath)

	if mode == "" {
		*errs = append(*errs, field+".mode is required")
		return
	}

	switch mode {
	case PackageSourceModeDirect:
		if filePath != "" {
			*errs = append(*errs, field+".file_path is only allowed when "+field+".mode is offline")
		}
	case PackageSourceModeOffline:
		if filePath == "" {
			*errs = append(*errs, field+".file_path is required when "+field+".mode is offline")
		} else if filepath.Clean(filePath) == "." {
			*errs = append(*errs, field+".file_path must be a valid file path")
		}
	default:
		*errs = append(*errs, field+".mode must be one of: direct, offline")
	}
}

func validatePackageProbe(errs *validationErrors, field string, probe PackageProbeConfig) {
	validatePositiveDuration(errs, field+".reachability_timeout", probe.ReachabilityTimeout)
	validatePositiveDuration(errs, field+".artifact_timeout", probe.ArtifactTimeout)
}

func validatePositiveDuration(errs *validationErrors, field string, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		*errs = append(*errs, field+" is required")
		return
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 {
		*errs = append(*errs, field+" must be a positive duration such as 30s or 5m")
	}
}

func validateDNS01(errs *validationErrors, acmeChallenge string, dns01 DNS01Config) {
	provider := strings.TrimSpace(dns01.Provider)
	envFile := strings.TrimSpace(dns01.EnvFile)
	credentialsFile := strings.TrimSpace(dns01.CredentialsFile)
	var providerInfo acme.DNSProviderInfo
	providerValid := false

	if credentialsFile != "" {
		*errs = append(*errs, "advanced.dns01.credentials_file is no longer supported; use advanced.dns01.env_file for lego DNS provider environment")
	}
	if acmeChallenge == ACMEChallengeDNS01 && provider == "" {
		*errs = append(*errs, "advanced.dns01.provider is required when default.acme_challenge is dns-01")
	}
	if provider != "" {
		info, err := acme.DNSProvider(provider)
		if err != nil {
			*errs = append(*errs, err.Error())
		} else {
			providerInfo = info
			providerValid = true
		}
	}
	if envFile != "" && provider == "" {
		*errs = append(*errs, "advanced.dns01.provider is required when advanced.dns01.env_file is set")
	}
	if envFile != "" {
		validateDNSEnvFilePath(errs, envFile)
	}
	if acmeChallenge == ACMEChallengeDNS01 && providerValid && envFile == "" && !providerInfo.AmbientCredentialsSupported {
		*errs = append(*errs, "advanced.dns01.env_file is required for DNS-01 renewal with lego DNS provider "+providerInfo.LegoCode)
	}
}

func validateDNSEnvFilePath(errs *validationErrors, envFile string) {
	if !filepath.IsAbs(envFile) {
		*errs = append(*errs, "advanced.dns01.env_file must be an absolute path when set")
		return
	}
	if filepath.Clean(envFile) != envFile {
		*errs = append(*errs, "advanced.dns01.env_file must be a clean absolute path without . or .. segments")
	}
	for _, r := range envFile {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			*errs = append(*errs, "advanced.dns01.env_file must not contain whitespace or control characters because it is rendered into systemd EnvironmentFile")
			break
		}
	}
	if strings.ContainsAny(envFile, "*?[]%\"'\\") {
		*errs = append(*errs, "advanced.dns01.env_file must not contain systemd glob, specifier, quote, or escape characters")
	}
}

func validateProxyURL(errs *validationErrors, field string, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}

	if !validProxyEnvironmentValue(raw) {
		*errs = append(*errs, field+" must be a proxy URL or host[:port]")
	}
}

func validProxyEnvironmentValue(raw string) bool {
	for _, r := range raw {
		if unicode.IsSpace(r) {
			return false
		}
	}
	parsedURL, err := url.Parse(raw)
	if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
		return true
	}

	parsedURL, err = url.Parse("http://" + raw)
	return err == nil &&
		parsedURL.Host != "" &&
		parsedURL.Path == "" &&
		parsedURL.RawQuery == "" &&
		parsedURL.Fragment == ""
}

func validateAbsoluteURL(errs *validationErrors, field string, raw string) {
	parsedURL, err := url.Parse(raw)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		*errs = append(*errs, field+" must be an absolute URL")
	}
}

func validateIPOverride(errs *validationErrors, field string, raw string, wantIPv6 bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}

	ip := net.ParseIP(raw)
	if ip == nil {
		*errs = append(*errs, field+" must be a valid IP address")
		return
	}

	if wantIPv6 {
		if ip.To4() != nil {
			*errs = append(*errs, field+" must be an IPv6 address")
		}
		return
	}

	if ip.To4() == nil {
		*errs = append(*errs, field+" must be an IPv4 address")
	}
}

func validatePlatform(errs *validationErrors, field string, platform PlatformConfig) {
	arch := strings.TrimSpace(platform.Arch)
	if arch == "" {
		*errs = append(*errs, field+".arch is required")
		return
	}

	switch arch {
	case ArchAMD64, ArchARM64:
		return
	default:
		*errs = append(*errs, field+".arch must be one of: amd64, arm64")
	}
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimSuffix(value, ".")
}

func hasDomainSuffix(host string, domain string) bool {
	return host != domain && strings.HasSuffix(host, "."+domain)
}

func looksLikeDNSName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}

	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}

	return true
}

func isHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}

	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}

	return true
}
