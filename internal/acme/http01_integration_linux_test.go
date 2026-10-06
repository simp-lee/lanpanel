//go:build linux

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"lanpanel/internal/acmeaccount"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeHTTP01CA struct {
	mu              sync.Mutex
	accountCalls    int
	challengeAccept bool
	server          *httptest.Server
}

func newFakeHTTP01CA() *fakeHTTP01CA {
	ca := &fakeHTTP01CA{}
	ca.server = httptest.NewTLSServer(http.HandlerFunc(ca.serveHTTP))
	return ca
}

func (ca *fakeHTTP01CA) close() { ca.server.Close() }

func (ca *fakeHTTP01CA) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	ca.mu.Lock()
	accepted := ca.challengeAccept
	ca.mu.Unlock()
	writer.Header().Set("Replay-Nonce", "test-nonce")
	writer.Header().Set("Content-Type", "application/json")
	base := "https://" + request.Host
	writeJSON := func(status int, value any) {
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(value)
	}
	switch request.URL.Path {
	case "/directory":
		writeJSON(http.StatusOK, map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order"})
	case "/nonce":
		writer.WriteHeader(http.StatusOK)
	case "/account":
		ca.mu.Lock()
		ca.accountCalls++
		accountCall := ca.accountCalls
		ca.mu.Unlock()
		if accountCall == 1 {
			writeJSON(http.StatusBadRequest, map[string]string{"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "account not found"})
			return
		}
		writer.Header().Set("Location", base+"/account/1")
		writeJSON(http.StatusCreated, map[string]any{"status": "valid", "contact": []string{"mailto:admin@example.test"}, "orders": base + "/orders"})
	case "/order":
		writer.Header().Set("Location", base+"/order/1")
		writeJSON(http.StatusCreated, map[string]any{"status": map[bool]string{true: "ready", false: "pending"}[accepted], "identifiers": []map[string]string{{"type": "dns", "value": "app.example.test"}}, "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1"})
	case "/authz/1":
		status := "pending"
		challengeStatus := "pending"
		if accepted {
			status = "valid"
			challengeStatus = "valid"
		}
		writeJSON(http.StatusOK, map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": "app.example.test"}, "challenges": []map[string]string{{"type": "http-01", "url": base + "/challenge/1", "token": "abcdefghijklmnopqrstuv", "status": challengeStatus}}})
	case "/challenge/1":
		ca.mu.Lock()
		ca.challengeAccept = true
		ca.mu.Unlock()
		writeJSON(http.StatusOK, map[string]string{"type": "http-01", "url": base + "/challenge/1", "token": "abcdefghijklmnopqrstuv", "status": "valid"})
	case "/finalize/1":
		writeJSON(http.StatusOK, map[string]any{"status": "valid", "identifiers": []map[string]string{{"type": "dns", "value": "app.example.test"}}, "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1", "certificate": base + "/cert/1"})
	case "/order/1":
		writeJSON(http.StatusOK, map[string]any{"status": "ready", "identifiers": []map[string]string{{"type": "dns", "value": "app.example.test"}}, "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1", "certificate": base + "/cert/1"})
	case "/cert/1":
		writer.Header().Set("Content-Type", "application/pem-certificate-chain")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("-----BEGIN CERTIFICATE-----\n bGVhZg==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n aXNzdWVy\n-----END CERTIFICATE-----\n"))
	default:
		http.NotFound(writer, request)
	}
}

type recordingHTTP01Presenter struct {
	mu      sync.Mutex
	present []HTTP01Presentation
	clean   []HTTP01Presentation
}

func (presenter *recordingHTTP01Presenter) PresentHTTP01(_ context.Context, value HTTP01Presentation) error {
	presenter.mu.Lock()
	defer presenter.mu.Unlock()
	presenter.present = append(presenter.present, value)
	return nil
}

func (presenter *recordingHTTP01Presenter) CleanUpHTTP01(_ context.Context, value HTTP01Presentation) error {
	presenter.mu.Lock()
	defer presenter.mu.Unlock()
	presenter.clean = append(presenter.clean, value)
	return nil
}

func TestRunHTTP01AgainstDeterministicLocalCA(t *testing.T) {
	ca := newFakeHTTP01CA()
	defer ca.close()
	accountKey, err := acmeaccount.Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	accountPath := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(accountPath, accountKey, 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := acmeaccount.Fingerprint(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{DirectoryURL: ca.server.URL + "/directory", AccountKeyPath: accountPath, AccountKeyFingerprint: fingerprint, AccountEmail: "admin@example.test", TermsAccepted: true, Method: ChallengeHTTP01, CredentialFiles: []CredentialFile{}}
	presenter := &recordingHTTP01Presenter{}
	stageRoot := t.TempDir()
	outputRoot := filepath.Join(stageRoot, "chroot")
	if err := os.MkdirAll(filepath.Join(outputRoot, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid = 1
	}
	if gid == 0 {
		gid = 1
	}
	request := IssueRequest{CertificateID: "cert_00000000000000000000000000000000", Domains: []string{"app.example.test"}, Binding: binding, UID: uid, GID: gid, Chroot: filepath.Join(stageRoot, "chroot")}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := runHTTP01(ctx, request, presenter, func(value IssueRequest, key *ecdsa.PrivateKey, chain [][]byte) error {
		return writeHTTP01IssuedAt(value, key, chain, outputRoot)
	}, ca.server.Client(), func(Binding) (*ecdsa.PrivateKey, error) {
		block, _ := pem.Decode(accountKey)
		if block == nil {
			return nil, fmt.Errorf("test account key PEM missing")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.StdoutDigest, "sha256:") || !strings.HasPrefix(result.StderrDigest, "sha256:") {
		t.Fatalf("unexpected ACME result=%#v", result)
	}
	if len(presenter.present) != 1 || len(presenter.clean) != 1 || presenter.present[0].Token != presenter.clean[0].Token || presenter.present[0].KeyAuthorizationDigest != presenter.clean[0].KeyAuthorizationDigest {
		t.Fatalf("challenge lifecycle present=%#v cleanup=%#v", presenter.present, presenter.clean)
	}
	for _, suffix := range []string{".crt", ".issuer.crt", ".key"} {
		if _, err := os.Stat(filepath.Join(outputRoot, "work", "certificates", "app.example.test"+suffix)); err != nil {
			t.Fatal(err)
		}
	}
}
