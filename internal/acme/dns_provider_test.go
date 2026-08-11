package acme

import (
	"reflect"
	"testing"
)

func TestDNSProviderCodesAreExactAndClosed(t *testing.T) {
	want := []DNSProvider{
		DNSProviderCloudflare,
		DNSProviderRoute53,
		DNSProviderDigitalOcean,
		DNSProviderGCloud,
		DNSProviderTencentCloud,
	}
	if got := SupportedDNSProviders(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedDNSProviders() = %#v, want %#v", got, want)
	}
	for _, provider := range want {
		if got, err := ParseDNSProvider(string(provider)); err != nil || got != provider {
			t.Fatalf("ParseDNSProvider(%q) = %q, %v", provider, got, err)
		}
	}
}

func TestDNSProviderAliasesAndAmbientShapesAreRejected(t *testing.T) {
	for _, value := range []string{
		"google",
		"tencent-cloud",
		"Cloudflare",
		" cloudflare",
		"cloudflare ",
		"aws",
		"ambient",
		"",
	} {
		if provider, err := ParseDNSProvider(value); err == nil || provider != "" {
			t.Fatalf("ParseDNSProvider(%q) = %q, %v", value, provider, err)
		}
	}
}
