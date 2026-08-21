//go:build linux

package acme

import (
	"context"
	"lanpanel/internal/child"
	"os"
	"path/filepath"
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

func TestLegoOrchestrationUsesTypedProviderFrameAndRejectsChildFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	account := filepath.Join(root, "account.key")
	profile := filepath.Join(root, "provider.env")
	secret := filepath.Join(root, "token")
	for path, data := range map[string]string{account: "account-key-sentinel", secret: "provider-secret-sentinel", profile: "CF_DNS_API_TOKEN_FILE=" + secret + "\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binding, err := LoadDNSBinding("https://acme.example.test/directory", account, "admin@example.test", true, DNSProviderCloudflare, profile, "example.test")
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
	if result.StdoutDigest != runner.result.StdoutDigest || runner.invocation.Lego == nil || runner.invocation.Lego.Provider != "cloudflare" {
		t.Fatal("typed lego result or provider missing")
	}
	environment, err := DecodeEnvironmentFrame(strings.NewReader(string(runner.input)))
	if err != nil {
		t.Fatal(err)
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
}
