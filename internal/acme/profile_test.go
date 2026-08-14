package acme

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChallengeMethodIsClosed(t *testing.T) {
	for _, value := range []string{"http-01", "dns-01"} {
		if _, err := ParseChallengeMethod(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"tls-alpn-01", "HTTP-01", ""} {
		if _, err := ParseChallengeMethod(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
func TestProviderSchemasAreClosed(t *testing.T) {
	for _, provider := range SupportedDNSProviders() {
		schema, err := ProviderSchemaFor(provider)
		if err != nil || len(schema.EnvironmentKeys) == 0 {
			t.Fatalf("schema %q: %v", provider, err)
		}
	}
	if _, err := ProviderSchemaFor("plugin"); err == nil {
		t.Fatal("plugin provider accepted")
	}
}
func TestLoadDNSBindingPinsTransitiveCredentialFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	account := filepath.Join(root, "account.key")
	token := filepath.Join(root, "token")
	profile := filepath.Join(root, "cloudflare.env")
	for path, data := range map[string]string{account: "account", token: "token", profile: "CF_DNS_API_TOKEN_FILE=" + token + "\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binding, err := LoadDNSBinding("https://acme.example.test/directory", account, "admin@example.test", true, DNSProviderCloudflare, profile, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBinding(binding); err != nil {
		t.Fatal(err)
	}
	if len(binding.CredentialFiles) != 1 || binding.CredentialFiles[0].Path != token {
		t.Fatalf("credential binding=%#v", binding.CredentialFiles)
	}
	if _, err := BindingDigest(binding); err != nil {
		t.Fatal(err)
	}
}
func TestEveryDNSProviderBindsClosedEnvironment(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	account := filepath.Join(root, "account.key")
	_ = os.WriteFile(account, []byte("account"), 0o600)
	cases := []struct {
		provider DNSProvider
		lines    []string
	}{{DNSProviderCloudflare, []string{"CF_DNS_API_TOKEN_FILE"}}, {DNSProviderRoute53, []string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_REGION=us-east-1", "AWS_HOSTED_ZONE_ID=zone123", "AWS_PROFILE=lanpanel"}}, {DNSProviderDigitalOcean, []string{"DO_AUTH_TOKEN_FILE"}}, {DNSProviderGCloud, []string{"GCE_SERVICE_ACCOUNT_FILE", "GCE_PROJECT=test-project"}}, {DNSProviderTencentCloud, []string{"TENCENTCLOUD_SECRET_ID_FILE", "TENCENTCLOUD_SECRET_KEY_FILE", "TENCENTCLOUD_SESSION_TOKEN_FILE", "TENCENTCLOUD_REGION=ap-guangzhou"}}}
	for _, test := range cases {
		t.Run(string(test.provider), func(t *testing.T) {
			profile := filepath.Join(root, string(test.provider)+".env")
			content := ""
			for index, line := range test.lines {
				if strings.Contains(line, "=") {
					content += line + "\n"
					continue
				}
				secret := filepath.Join(root, fmt.Sprintf("%s-%d.secret", test.provider, index))
				secretData := "sentinel"
				if test.provider == DNSProviderRoute53 {
					secretData = "[lanpanel]\naws_access_key_id = id\naws_secret_access_key = secret\n"
				}
				if test.provider == DNSProviderGCloud {
					secretData = `{"type":"service_account","project_id":"test-project","private_key_id":"id","private_key":"key","client_email":"account@example.test","token_uri":"https://oauth2.googleapis.com/token"}`
				}
				if err := os.WriteFile(secret, []byte(secretData), 0o600); err != nil {
					t.Fatal(err)
				}
				content += line + "=" + secret + "\n"
			}
			if err := os.WriteFile(profile, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			binding, err := LoadDNSBinding("https://acme.example.test/directory", account, "admin@example.test", true, test.provider, profile, "example.test")
			if err != nil {
				t.Fatal(err)
			}
			environment, err := BuildEnvironment(binding)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range environment {
				if strings.Contains(value, "sentinel") {
					t.Fatal("secret value entered environment frame")
				}
			}
		})
	}
}
func TestLoadDNSBindingRejectsUnknownAndDirectSecretKeys(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	account := filepath.Join(root, "account.key")
	profile := filepath.Join(root, "provider.env")
	_ = os.WriteFile(account, []byte("account"), 0o600)
	for _, line := range []string{"CF_DNS_API_TOKEN=secret\n", "UNKNOWN_FILE=/root/value\n", "CF_DNS_API_TOKEN_FILE=relative\n"} {
		_ = os.WriteFile(profile, []byte(line), 0o600)
		if _, err := LoadDNSBinding("https://acme.example.test/directory", account, "admin@example.test", true, DNSProviderCloudflare, profile, "example.test"); err == nil {
			t.Fatalf("accepted profile %q", line)
		}
	}
}
func TestHTTPBindingRejectsNonHTTPSDirectory(t *testing.T) {
	if _, err := canonicalDirectory("http://acme.example.test/directory"); err == nil {
		t.Fatal("HTTP ACME directory accepted")
	}
}
