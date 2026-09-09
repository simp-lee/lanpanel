//go:build linux

package acme

import (
	"context"
	"lanpanel/internal/child"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fakeLegoRunner struct {
	invocation child.Invocation
	input      []byte
	result     child.Result
	err        error
}

func (runner *fakeLegoRunner) RunInvocation(_ context.Context, profile child.ProfileID, invocation child.Invocation, input []byte) (child.Result, error) {
	if profile != child.ProfileLego {
		return child.Result{}, os.ErrInvalid
	}
	runner.invocation = invocation
	runner.input = append([]byte(nil), input...)
	return runner.result, runner.err
}

func TestLegoOrchestrationUsesEveryTypedProviderFrameAndRejectsChildFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	for _, provider := range SupportedDNSProviders() {
		t.Run(string(provider), func(t *testing.T) {
			root := protectedTestDir(t)
			account := filepath.Join(root, "account.key")
			profile := filepath.Join(root, "provider.env")
			files := map[string]string{account: "account-key-sentinel"}
			var profileData string
			switch provider {
			case DNSProviderCloudflare:
				secret := filepath.Join(root, "cloudflare-token")
				files[secret] = "provider-secret-sentinel"
				profileData = "CF_DNS_API_TOKEN_FILE=" + secret + "\n"
			case DNSProviderRoute53:
				secret := filepath.Join(root, "aws-credentials")
				files[secret] = "[lanpanel]\naws_access_key_id = id\naws_secret_access_key = provider-secret-sentinel\n"
				profileData = "AWS_SHARED_CREDENTIALS_FILE=" + secret + "\nAWS_REGION=us-east-1\nAWS_HOSTED_ZONE_ID=zone123\nAWS_PROFILE=lanpanel\n"
			case DNSProviderDigitalOcean:
				secret := filepath.Join(root, "digitalocean-token")
				files[secret] = "provider-secret-sentinel"
				profileData = "DO_AUTH_TOKEN_FILE=" + secret + "\n"
			case DNSProviderGCloud:
				secret := filepath.Join(root, "gcloud-service-account")
				files[secret] = `{"type":"service_account","project_id":"test-project","private_key_id":"id","private_key":"provider-secret-sentinel","client_email":"account@example.test","token_uri":"https://oauth2.googleapis.com/token"}`
				profileData = "GCE_SERVICE_ACCOUNT_FILE=" + secret + "\nGCE_PROJECT=test-project\n"
			case DNSProviderTencentCloud:
				secretID := filepath.Join(root, "tencentcloud-secret-id")
				secretKey := filepath.Join(root, "tencentcloud-secret-key")
				files[secretID] = "provider-secret-sentinel"
				files[secretKey] = "provider-secret-sentinel"
				profileData = "TENCENTCLOUD_SECRET_ID_FILE=" + secretID + "\nTENCENTCLOUD_SECRET_KEY_FILE=" + secretKey + "\nTENCENTCLOUD_REGION=ap-guangzhou\n"
			default:
				t.Fatalf("missing fake-process fixture for provider %q", provider)
			}
			files[profile] = profileData
			for path, data := range files {
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			binding, err := LoadDNSBinding("https://acme.example.test/directory", account, "admin@example.test", true, provider, profile, "example.test")
			if err != nil {
				t.Fatal(err)
			}
			id := "cert_00000000000000000000000000000000"
			request := IssueRequest{CertificateID: id, Domains: []string{"app.example.test"}, Binding: binding, UID: 2200000, GID: 2200000, Chroot: "/var/lib/lanpanel/certificates/chroot/" + id, ExecutableDigest: strings.Repeat("a", 64)}
			runner := &fakeLegoRunner{result: child.Result{ExitCode: 0, StdoutDigest: "sha256:" + strings.Repeat("b", 64), StderrDigest: "sha256:" + strings.Repeat("c", 64)}}
			result, err := RunLego(context.Background(), runner, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.StdoutDigest != runner.result.StdoutDigest || runner.invocation.Lego == nil || runner.invocation.Lego.Provider != string(provider) {
				t.Fatal("typed lego result or provider missing")
			}
			environment, err := DecodeEnvironmentFrame(strings.NewReader(string(runner.input)))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(environment, runner.invocation.Lego.Environment) {
				t.Fatalf("process frame environment=%v invocation environment=%v", environment, runner.invocation.Lego.Environment)
			}
			for _, value := range environment {
				if strings.Contains(value, "provider-secret-sentinel") || strings.Contains(value, "account-key-sentinel") {
					t.Fatal("secret entered child environment frame")
				}
			}
			runner.result.ExitCode = 1
			if _, err := RunLego(context.Background(), runner, request); err == nil {
				t.Fatal("failed lego child accepted")
			}
		})
	}
}
