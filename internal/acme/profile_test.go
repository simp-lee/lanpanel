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

func TestValidateBindingClosesChallengeSpecificAuthority(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	if validPrincipalValue("profile;injected") {
		t.Fatal("DNS principal value containing frame separator accepted")
	}
	if !DNS01ZoneCoversDomains("example.test", []string{"app.example.test", "alias.example.test"}) || DNS01ZoneCoversDomains("other.test", []string{"app.example.test"}) {
		t.Fatal("DNS-01 zone coverage relation is invalid")
	}
	httpBinding := Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: digest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: ChallengeHTTP01, CredentialFiles: []CredentialFile{}}
	if err := ValidateBinding(httpBinding); err != nil {
		t.Fatalf("complete HTTP-01 binding rejected: %v", err)
	}
	uppercaseDigest := "sha256:" + strings.Repeat("A", 64)
	uppercaseAccount := httpBinding
	uppercaseAccount.AccountKeyFingerprint = uppercaseDigest
	if err := ValidateBinding(uppercaseAccount); err == nil {
		t.Fatal("uppercase account key fingerprint accepted")
	}
	for name, mutate := range map[string]func(*Binding){
		"provider":            func(binding *Binding) { binding.Provider = DNSProviderCloudflare },
		"profile_path":        func(binding *Binding) { binding.ProfilePath = "/root/cloudflare.env" },
		"profile_fingerprint": func(binding *Binding) { binding.ProfileFingerprint = digest },
		"credential_file": func(binding *Binding) {
			binding.CredentialFiles = []CredentialFile{{Key: "CF_DNS_API_TOKEN_FILE", Path: "/root/token", Fingerprint: digest}}
		},
		"zone":      func(binding *Binding) { binding.Zone = "example.test" },
		"principal": func(binding *Binding) { binding.Principal = "AWS_REGION=us-east-1;" },
	} {
		t.Run("http_with_"+name, func(t *testing.T) {
			candidate := httpBinding
			mutate(&candidate)
			if err := ValidateBinding(candidate); err == nil {
				t.Fatalf("HTTP-01 binding with %s accepted", name)
			}
		})
	}

	route53 := Binding{DirectoryURL: httpBinding.DirectoryURL, AccountKeyPath: httpBinding.AccountKeyPath, AccountKeyFingerprint: digest, AccountEmail: httpBinding.AccountEmail, TermsAccepted: true, Method: ChallengeDNS01, Provider: DNSProviderRoute53, ProfilePath: "/root/route53.env", ProfileFingerprint: digest, CredentialFiles: []CredentialFile{{Key: "AWS_SHARED_CREDENTIALS_FILE", Path: "/root/aws-credentials", Fingerprint: digest}}, Zone: "example.test", Principal: "AWS_HOSTED_ZONE_ID=zone123;AWS_PROFILE=lanpanel;AWS_REGION=us-east-1;"}
	if err := ValidateBinding(route53); err != nil {
		t.Fatalf("complete DNS-01 binding rejected: %v", err)
	}
	uppercaseProfile := route53
	uppercaseProfile.ProfileFingerprint = uppercaseDigest
	if err := ValidateBinding(uppercaseProfile); err == nil {
		t.Fatal("uppercase DNS profile fingerprint accepted")
	}
	uppercaseCredential := route53
	uppercaseCredential.CredentialFiles = append([]CredentialFile(nil), route53.CredentialFiles...)
	uppercaseCredential.CredentialFiles[0].Fingerprint = uppercaseDigest
	if err := ValidateBinding(uppercaseCredential); err == nil {
		t.Fatal("uppercase DNS credential fingerprint accepted")
	}
	route53.Principal = ""
	if err := ValidateBinding(route53); err == nil {
		t.Fatal("DNS-01 binding without required principal accepted")
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

// Protected sources require every ancestor to be root-owned and not writable
// by other users. A private t.TempDir under /tmp or /var/tmp does not satisfy it.
func protectedTestDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/root", "lanpanel-acme-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove protected fixture: %v", err)
		}
	})
	return root
}

func TestLoadDNSBindingPinsTransitiveCredentialFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	root := protectedTestDir(t)
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
	root := protectedTestDir(t)
	account := filepath.Join(root, "account.key")
	if err := os.WriteFile(account, []byte("account"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	root := protectedTestDir(t)
	account := filepath.Join(root, "account.key")
	profile := filepath.Join(root, "provider.env")
	token := filepath.Join(root, "token")
	for path, data := range map[string]string{account: "account", token: "token", profile: "CF_DNS_API_TOKEN_FILE=" + token + "\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDNSBinding("https://acme.example.test/directory", account, "admin@example.test", true, DNSProviderCloudflare, profile, "example.test"); err != nil {
		t.Fatalf("valid profile baseline: %v", err)
	}
	for _, test := range []struct{ line, wantError string }{
		{"CF_DNS_API_TOKEN=secret\n", `unknown key "CF_DNS_API_TOKEN"`},
		{"UNKNOWN_FILE=/root/value\n", `unknown key "UNKNOWN_FILE"`},
		{"CF_DNS_API_TOKEN_FILE=relative\n", `DNS credential "CF_DNS_API_TOKEN_FILE": protected path invalid`},
	} {
		if err := os.WriteFile(profile, []byte(test.line), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDNSBinding("https://acme.example.test/directory", account, "admin@example.test", true, DNSProviderCloudflare, profile, "example.test"); err == nil || !strings.Contains(err.Error(), test.wantError) {
			t.Fatalf("profile %q: want %q, got %v", test.line, test.wantError, err)
		}
	}
}

func TestHTTPBindingRejectsNonHTTPSDirectory(t *testing.T) {
	if _, err := canonicalDirectory("http://acme.example.test/directory"); err == nil {
		t.Fatal("HTTP ACME directory accepted")
	}
}
