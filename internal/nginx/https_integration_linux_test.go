//go:build linux

package nginx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/domain"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagementHTTPSRenderedGraphServesThroughRealNginx(t *testing.T) {
	nginxBinary, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx is not installed")
	}

	root := t.TempDir()
	configRoot := filepath.Join(root, "config")
	if err := os.MkdirAll(configRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM, certificate := nginxIntegrationCertificate(t, "panel.example.test")
	certificateRoot := filepath.Join(root, "certificate")
	if err := os.MkdirAll(certificateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(certificateRoot, "certificate.pem")
	privateKeyPath := filepath.Join(certificateRoot, "private-key.pem")
	writeNginxIntegrationFile(t, certificatePath, certificatePEM, 0o644)
	writeNginxIntegrationFile(t, privateKeyPath, privateKeyPEM, 0o600)

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	requests := make(chan *http.Request, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		clone := request.Clone(context.Background())
		requests <- clone
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "management upstream\n")
	})}
	go func() { _ = server.Serve(upstream) }()
	defer func() { _ = server.Close() }()

	host := "panel.example.test"
	upstreamPort := upstream.Addr().(*net.TCPAddr).Port
	directoryURL := "https://acme.example.test/directory"
	certificateID := "cert_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	accountKeyFingerprint := "sha256:" + strings.Repeat("b", 64)
	binding, err := acme.BindingDigest(acme.Binding{DirectoryURL: directoryURL, AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: accountKeyFingerprint, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01})
	if err != nil {
		t.Fatal(err)
	}
	sanSum := sha256.Sum256([]byte(host))
	sanIdentity := "sha256:" + hex.EncodeToString(sanSum[:])
	now := time.Now().UTC().Truncate(time.Second)
	bundle := &domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/" + certificateID + ".current", BindingIdentity: binding, Generation: 1, Fingerprint: "sha256:" + strings.Repeat("a", 64), SANIdentity: sanIdentity, ChainIdentity: "sha256:" + strings.Repeat("c", 64), IssuerIdentity: "sha256:" + strings.Repeat("d", 64), DirectoryIdentity: "sha256:" + strings.Repeat("e", 64), NotAfter: now.Add(time.Hour).Format(time.RFC3339), LastTrustedWall: now.Add(-time.Minute).Format(time.RFC3339), Authority: &domain.CertificateAuthorityIdentity{CertificateID: certificateID, DirectoryURL: directoryURL, AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: accountKeyFingerprint, AccountEmail: "admin@example.test", TermsAccepted: true, Method: string(acme.ChallengeHTTP01)}}
	installation := domain.Installation{InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.0.0.1", Port: uint16(upstreamPort)}, ManagementHTTPS: &domain.ManagementHTTPSConfig{Domain: host, Certificate: domain.CertificateRequest{ChallengeMethod: string(acme.ChallengeHTTP01), DirectoryURL: directoryURL, TermsAccepted: true}, ACMEBinding: binding, Phase: domain.ManagementHTTPSActive, Generation: 1, CertificateBundle: bundle}}
	entry, err := BuildManagementEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	entryBytes, err := RenderEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	httpPort := freeNginxIntegrationPort(t)
	httpsPort := freeNginxIntegrationPort(t)
	if httpPort == httpsPort {
		t.Fatal("integration listener ports unexpectedly matched")
	}
	rendered := string(entryBytes)
	rendered = strings.ReplaceAll(rendered, "listen 80;", "listen "+strconv.Itoa(httpPort)+";")
	rendered = strings.ReplaceAll(rendered, "listen [::]:80;", "listen [::]:"+strconv.Itoa(httpPort)+";")
	rendered = strings.ReplaceAll(rendered, "listen 443 ssl http2;", "listen "+strconv.Itoa(httpsPort)+" ssl http2;")
	rendered = strings.ReplaceAll(rendered, "listen [::]:443 ssl http2;", "listen [::]:"+strconv.Itoa(httpsPort)+" ssl http2;")
	rendered = strings.ReplaceAll(rendered, "/var/lib/lanpanel/certificates/active/cert_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.current/certificate.pem", certificatePath)
	rendered = strings.ReplaceAll(rendered, "/var/lib/lanpanel/certificates/active/cert_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.current/private-key.pem", privateKeyPath)
	rendered = strings.ReplaceAll(rendered, "/var/log/lanpanel/nginx-rejections.log", filepath.Join(root, "rejections.log"))
	entryPath := filepath.Join(configRoot, "management.conf")
	writeNginxIntegrationFile(t, entryPath, []byte(rendered), 0o600)
	writeNginxIntegrationFile(t, filepath.Join(configRoot, "sanitizer.conf"), []byte(HeaderSanitizer()), 0o600)
	tempRoot := filepath.Join(root, "nginx-temp")
	for _, name := range []string{"client-body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		if err := os.MkdirAll(filepath.Join(tempRoot, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	nginxConfig := fmt.Sprintf("pid %s;\nerror_log stderr notice;\nevents { worker_connections 64; }\nhttp { access_log off; client_body_temp_path %s; proxy_temp_path %s; fastcgi_temp_path %s; uwsgi_temp_path %s; scgi_temp_path %s; include %s; log_format lanpanel_rejection '$status'; map $status $lanpanel_rejection_loggable { default 0; 421 1; } include %s; }\n", filepath.Join(root, "nginx.pid"), filepath.Join(tempRoot, "client-body"), filepath.Join(tempRoot, "proxy"), filepath.Join(tempRoot, "fastcgi"), filepath.Join(tempRoot, "uwsgi"), filepath.Join(tempRoot, "scgi"), filepath.Join(configRoot, "sanitizer.conf"), entryPath)
	configPath := filepath.Join(root, "nginx.conf")
	writeNginxIntegrationFile(t, configPath, []byte(nginxConfig), 0o600)

	check := exec.Command(nginxBinary, "-p", root, "-c", configPath, "-t")
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("nginx -t rejected the rendered graph: %v\n%s\n%s", err, output, rendered)
	}
	process := exec.Command(nginxBinary, "-p", root, "-c", configPath, "-g", "daemon off; master_process off;")
	process.Env = append(os.Environ(), "NGINX_ENTRY_TEST=1")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = process.Process.Kill()
		_, _ = process.Process.Wait()
	}()

	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort)))
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	var response *http.Response
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		request, requestErr := http.NewRequest(http.MethodGet, "https://"+host+"/health", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Origin", "https://"+host)
		request.Header.Set("Cookie", "session=fixture")
		request.Header.Set("X-LanPanel-CSRF", "csrf-fixture")
		response, err = client.Do(request)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("real Nginx HTTPS request failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "management upstream\n" || response.TLS == nil || len(response.TLS.PeerCertificates) != 1 || response.TLS.PeerCertificates[0].Subject.CommonName != host {
		t.Fatalf("served Management response=%d body=%q tls=%v err=%v", response.StatusCode, body, response.TLS, err)
	}
	select {
	case observed := <-requests:
		if observed.Host != host {
			t.Fatalf("upstream Host=%q, want %q", observed.Host, host)
		}
		for header, expected := range map[string]string{"Origin": "https://" + host, "Cookie": "session=fixture", "X-LanPanel-Csrf": "csrf-fixture", "X-Forwarded-Proto": "https"} {
			if observed.Header.Get(header) != expected {
				t.Fatalf("upstream %s=%q, want %q", header, observed.Header.Get(header), expected)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive the proxied request")
	}

	wrongHost := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	wrongRequest, _ := http.NewRequest(http.MethodGet, "https://"+host+"/health", nil)
	wrongRequest.Host = "other.example.test"
	wrongResponse, err := wrongHost.Do(wrongRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongResponse.Body.Close()
	if wrongResponse.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("wrong Host status=%d, want 421", wrongResponse.StatusCode)
	}

	// #nosec G402 -- this negative test intentionally reaches the server with a wrong SNI.
	wrongSNITransport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "other.example.test", MinVersion: tls.VersionTLS12}, DialContext: transport.DialContext}
	wrongSNIClient := &http.Client{Transport: wrongSNITransport, Timeout: 5 * time.Second}
	wrongSNIRequest, _ := http.NewRequest(http.MethodGet, "https://"+host+"/health", nil)
	wrongSNIResponse, err := wrongSNIClient.Do(wrongSNIRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongSNIResponse.Body.Close()
	if wrongSNIResponse.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("wrong SNI status=%d, want 421", wrongSNIResponse.StatusCode)
	}
}

func nginxIntegrationCertificate(t *testing.T, host string) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), certificate
}

func writeNginxIntegrationFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func freeNginxIntegrationPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}
