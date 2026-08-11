package acme

import (
	"fmt"
	"strings"
)

type DNSProvider string

const (
	DNSProviderCloudflare   DNSProvider = "cloudflare"
	DNSProviderRoute53      DNSProvider = "route53"
	DNSProviderDigitalOcean DNSProvider = "digitalocean"
	DNSProviderGCloud       DNSProvider = "gcloud"
	DNSProviderTencentCloud DNSProvider = "tencentcloud"
)

var supportedDNSProviders = [...]DNSProvider{
	DNSProviderCloudflare,
	DNSProviderRoute53,
	DNSProviderDigitalOcean,
	DNSProviderGCloud,
	DNSProviderTencentCloud,
}

func SupportedDNSProviders() []DNSProvider {
	return append([]DNSProvider(nil), supportedDNSProviders[:]...)
}

func ParseDNSProvider(value string) (DNSProvider, error) {
	if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) {
		return "", fmt.Errorf("DNS-01 provider must be one exact canonical code")
	}
	provider := DNSProvider(value)
	for _, supported := range supportedDNSProviders {
		if provider == supported {
			return provider, nil
		}
	}
	return "", fmt.Errorf("unsupported DNS-01 provider %q", value)
}
