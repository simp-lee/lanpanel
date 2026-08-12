package sources

import (
	"strings"
	"testing"
)

func TestSourcesAreClosedCanonicalAndPinned(t *testing.T) {
	artifact := Artifact{Name: "headscale", Version: "0.25.1", OperatingOS: "linux", Architecture: "amd64", Digest: strings.Repeat("a", 64)}
	official := Source{Kind: OfficialCanonical, URL: "https://downloads.example.test/headscale-0.25.1", OfficialAuthorities: []string{"cdn.example.test", "downloads.example.test"}, Artifact: artifact}
	if err := Validate(official); err != nil {
		t.Fatal(err)
	}
	redirected := "https://cdn.example.test/headscale-0.25.1?short_lived=value"
	if err := ValidateRedirect(official, official.URL, redirected, 1, 3); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRedirect(official, redirected, "https://downloads.example.test/headscale-0.25.1?short_lived=next", 2, 3); err != nil {
		t.Fatal(err)
	}
	mirror := Source{Kind: Mirror, URL: "http://mirror.example.test/headscale-0.25.1", Artifact: artifact}
	if err := Validate(mirror); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRedirect(mirror, mirror.URL, "https://mirror.example.test/headscale-0.25.1", 1, 2); err != nil {
		t.Fatal(err)
	}
	offline := Source{Kind: Offline, OfflinePath: "/var/lib/lanpanel/imports/headscale-0.25.1", Artifact: artifact}
	if err := Validate(offline); err != nil {
		t.Fatal(err)
	}
}

func TestSourcesRejectFallbackAliasesCredentialsAndDowngrades(t *testing.T) {
	artifact := Artifact{Name: "headscale", Version: "0.25.1", OperatingOS: "linux", Architecture: "amd64", Digest: strings.Repeat("b", 64)}
	for _, rawURL := range []string{
		"https://user:pass@example.test/artifact", "https://example.test/artifact?query=x", "https://example.test/artifact#fragment", "https://example.test:/artifact", "https://example.test:443/artifact", "https://example.test/%61rtifact", "http://example.test:80/artifact", "https://-bad.example.test/artifact", "https://bad..example.test/artifact", "file:///artifact",
	} {
		if err := Validate(Source{Kind: Mirror, URL: rawURL, Artifact: artifact}); err == nil {
			t.Fatalf("unsafe URL %q was accepted", rawURL)
		}
	}
	if err := Validate(Source{Kind: Offline, OfflinePath: "relative/file", Artifact: artifact}); err == nil {
		t.Fatal("relative offline path was accepted")
	}
	if err := ValidateProxy(&Proxy{URL: "https://proxy.example.test:8443"}); err != nil {
		t.Fatal(err)
	}
	for _, proxyURL := range []string{"https://user:pass@proxy.example.test", "https://proxy.example.test/path", "https://proxy.example.test?query"} {
		if err := ValidateProxy(&Proxy{URL: proxyURL}); err == nil {
			t.Fatalf("unsafe proxy %q was accepted", proxyURL)
		}
	}
	mirror := Source{Kind: Mirror, URL: "https://mirror.example.test/artifact", Artifact: artifact}
	if err := ValidateRedirect(mirror, mirror.URL, "http://mirror.example.test/artifact", 1, 2); err == nil {
		t.Fatal("HTTPS mirror downgrade was accepted")
	}
	if err := ValidateRedirect(mirror, mirror.URL, "https://other.example.test/artifact", 1, 2); err == nil {
		t.Fatal("mirror authority fallback was accepted")
	}
	artifact.Version = "latest"
	if err := Validate(Source{Kind: Offline, OfflinePath: "/var/lib/lanpanel/import", Artifact: artifact}); err == nil {
		t.Fatal("floating artifact version was accepted")
	}
}
