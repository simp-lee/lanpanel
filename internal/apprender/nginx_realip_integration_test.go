package apprender

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"lanpanel/internal/appconfig"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nginxRuntimeFixturePath = "/usr/sbin/nginx"

func TestNginxRealIPRuntimeBehavior(t *testing.T) {
	nginxPath, err := nginxRuntimeFixtureBinary()
	if err != nil {
		if requireNginxRuntimeFixture() {
			t.Fatalf("nginx is required for realip runtime fixture: %v", err)
		}
		t.Skip(err.Error())
	}
	versionOutput, err := exec.Command(nginxPath, "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("nginx -V failed: %v\n%s", err, string(versionOutput))
	}
	if !strings.Contains(string(versionOutput), "--with-http_realip_module") {
		if requireNginxRuntimeFixture() {
			t.Fatalf("nginx is not built with ngx_http_realip_module\n%s", string(versionOutput))
		}
		t.Skip("nginx is not built with ngx_http_realip_module")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		headers := map[string]string{}
		for _, name := range []string{
			"X-Real-IP",
			"X-Forwarded-For",
			"X-Forwarded-Proto",
			"Forwarded",
			"X-Forwarded-Port",
			"X-Forwarded-Prefix",
			"X-Original-Forwarded-For",
			"X-Client-IP",
			"Client-IP",
			"True-Client-IP",
			"EO-Connecting-IP",
			"EO-Client-IP",
		} {
			headers[name] = request.Header.Get(name)
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(headers); err != nil {
			t.Errorf("encode upstream response: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	dir := t.TempDir()
	trustedHTTPPort := freeLocalPort(t)
	trustedHTTPSPort := freeLocalPort(t)
	untrustedHTTPPort := freeLocalPort(t)
	untrustedHTTPSPort := freeLocalPort(t)
	accessLog := filepath.Join(dir, "access.log")
	rejectLog := filepath.Join(dir, "reject.log")
	trustedConfPath := filepath.Join(dir, "trusted-nginx.conf")
	untrustedConfPath := filepath.Join(dir, "untrusted-nginx.conf")
	trustedActivePath := filepath.Join(dir, "trusted-active.conf")
	untrustedActivePath := filepath.Join(dir, "untrusted-active.conf")
	trustedCIDRPath := filepath.Join(dir, "trusted.conf")
	untrustedCIDRPath := filepath.Join(dir, "untrusted.conf")
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	authPath := filepath.Join(dir, "goaccess.htpasswd")

	writeSelfSignedCertificate(t, certPath, keyPath, "app.example.com")
	if err := os.WriteFile(authPath, []byte("ops:$apr1$lanpanel$w3oRNoH6P1nrl2sZ1C0vr0\n"), 0o600); err != nil {
		t.Fatalf("write auth fixture: %v", err)
	}
	if err := os.WriteFile(trustedActivePath, []byte("set_real_ip_from 127.0.0.1;\n"), 0o644); err != nil {
		t.Fatalf("write trusted active fixture: %v", err)
	}
	if err := os.WriteFile(untrustedActivePath, []byte("set_real_ip_from 127.0.0.2;\n"), 0o644); err != nil {
		t.Fatalf("write untrusted active fixture: %v", err)
	}
	if err := os.WriteFile(trustedCIDRPath, []byte("127.0.0.1 1;\n"), 0o644); err != nil {
		t.Fatalf("write trusted CIDR fixture: %v", err)
	}
	if err := os.WriteFile(untrustedCIDRPath, []byte("127.0.0.2 1;\n"), 0o644); err != nil {
		t.Fatalf("write untrusted CIDR fixture: %v", err)
	}
	if err := os.WriteFile(trustedConfPath, []byte(renderedNginxRealIPFixtureConfig(t, dir, trustedHTTPPort, trustedHTTPSPort, upstreamURL.Host, trustedActivePath, trustedCIDRPath, accessLog, rejectLog, certPath, keyPath, authPath)), 0o644); err != nil {
		t.Fatalf("write trusted nginx fixture config: %v", err)
	}
	if err := os.WriteFile(untrustedConfPath, []byte(renderedNginxRealIPFixtureConfig(t, dir, untrustedHTTPPort, untrustedHTTPSPort, upstreamURL.Host, untrustedActivePath, untrustedCIDRPath, accessLog, rejectLog, certPath, keyPath, authPath)), 0o644); err != nil {
		t.Fatalf("write untrusted nginx fixture config: %v", err)
	}

	startNginxFixture(t, nginxPath, filepath.Join(dir, "trusted"), trustedConfPath, trustedHTTPPort, trustedHTTPSPort)
	startNginxFixture(t, nginxPath, filepath.Join(dir, "untrusted"), untrustedConfPath, untrustedHTTPPort, untrustedHTTPSPort)

	trustedHeaders := map[string][]string{"EO-Connecting-IP": {"9.9.9.9"}}
	trustedBody := requestFixture(t, trustedHTTPSPort, trustedHeaders, http.StatusOK)
	if trustedBody["X-Real-IP"] != "9.9.9.9" || trustedBody["X-Forwarded-For"] != "9.9.9.9" {
		t.Fatalf("trusted upstream IP headers = %#v", trustedBody)
	}
	if trustedBody["X-Forwarded-Proto"] != "https" {
		t.Fatalf("trusted X-Forwarded-Proto = %q, want https", trustedBody["X-Forwarded-Proto"])
	}
	assertSensitiveHeadersCleared(t, trustedBody)
	waitForFileContains(t, accessLog, "9.9.9.9 - ")

	_ = requestFixturePath(t, trustedHTTPSPort, "/_lanpanel/apps/example-app/goaccess", trustedHeaders, http.StatusUnauthorized)
	_ = requestFixturePath(t, trustedHTTPSPort, "/_lanpanel/apps/example-app/goaccess", map[string][]string{"EO-Connecting-IP": {"8.8.8.8"}}, http.StatusForbidden)

	_ = requestFixture(t, trustedHTTPSPort, nil, http.StatusBadRequest)
	waitForFileContains(t, rejectLog, `reason="missing_or_invalid_eo_connecting_ip"`)

	_ = requestFixture(t, trustedHTTPSPort, map[string][]string{"EO-Connecting-IP": {""}}, http.StatusBadRequest)
	waitForFileContains(t, rejectLog, `reason="missing_or_invalid_eo_connecting_ip"`)

	for _, invalidClientIP := range []string{"not-an-ip", "999.999.999.999", "2001:::1", "2001:db8:::1", "1:2", "1:2:3:4:5:6:7", "abcd:ef"} {
		t.Run("reject invalid client IP "+invalidClientIP, func(t *testing.T) {
			_ = requestFixture(t, trustedHTTPSPort, map[string][]string{"EO-Connecting-IP": {invalidClientIP}}, http.StatusBadRequest)
			waitForFileContains(t, rejectLog, `reason="missing_or_invalid_eo_connecting_ip"`)
		})
	}

	for _, illegalClientIP := range []string{"127.0.0.1", "10.0.0.1", "0.0.0.0", "::1", "::2", "4000::1", "8000::1", "fc00::1", "::ffff:9.9.9.9", "::ffff:10.0.0.1", "::ffff:127.0.0.1"} {
		t.Run("reject illegal client IP "+illegalClientIP, func(t *testing.T) {
			_ = requestFixture(t, trustedHTTPSPort, map[string][]string{"EO-Connecting-IP": {illegalClientIP}}, http.StatusBadRequest)
			waitForFileContains(t, rejectLog, `reason="missing_or_invalid_eo_connecting_ip"`)
		})
	}

	_ = requestFixture(t, trustedHTTPSPort, map[string][]string{"EO-Connecting-IP": {"9.9.9.9", "8.8.8.8"}}, http.StatusBadRequest)
	waitForFileContains(t, rejectLog, `reason="duplicate_eo_connecting_ip"`)

	untrustedHeaders := map[string][]string{
		"EO-Connecting-IP":         {"9.9.9.9"},
		"X-Forwarded-For":          {"1.1.1.1"},
		"X-Real-IP":                {"2.2.2.2"},
		"Forwarded":                {"for=3.3.3.3"},
		"X-Forwarded-Port":         {"443"},
		"X-Forwarded-Prefix":       {"/polluted"},
		"X-Original-Forwarded-For": {"5.5.5.5"},
		"X-Client-IP":              {"6.6.6.6"},
		"Client-IP":                {"7.7.7.7"},
		"True-Client-IP":           {"8.8.4.4"},
		"EO-Client-IP":             {"4.4.4.4"},
	}
	_ = requestFixture(t, untrustedHTTPSPort, untrustedHeaders, http.StatusBadRequest)
	waitForFileContains(t, rejectLog, `reason="untrusted_source_ip"`)

	_ = requestFixturePath(t, untrustedHTTPSPort, "/_lanpanel/apps/example-app/goaccess", untrustedHeaders, http.StatusBadRequest)
}

func TestRenderedNginxRealIPRuntimeFixtureUsesAppTemplate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	text := renderedNginxRealIPFixtureConfig(t, dir, 18080, 18443, "127.0.0.1:19191", "/tmp/active.conf", "/tmp/trusted.conf", "/tmp/access.log", "/tmp/reject.log", "/tmp/cert.pem", "/tmp/key.pem", "/tmp/auth.htpasswd")
	for _, want := range []string{
		"# Source: deploy/templates/app/nginx.conf.tmpl",
		"include /tmp/active.conf;",
		"include /tmp/trusted.conf;",
		"map $http_eo_connecting_ip $example_app_eo_connecting_ip_is_ip {",
		"geo $http_eo_connecting_ip $example_app_eo_connecting_ip_is_public {",
		`map "$example_app_realip_source_trusted:$example_app_eo_connecting_ip_is_ip:$example_app_eo_connecting_ip_is_public:$http_eo_connecting_ip" $example_app_realip_reject_reason {`,
		`~^0:[01]:[01]: "untrusted_source_ip";`,
		"real_ip_header EO-Connecting-IP;",
		"error_page 418 = @example_app_realip_reject;",
		"return 418;",
		"location @example_app_realip_reject {\n        internal;\n        access_log /tmp/reject.log lanpanel_app_example_app_realip_rejection if=$example_app_realip_reject_log;",
		`return 400 "lanpanel realip rejected: $example_app_realip_reject_reason\n";`,
		"proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $remote_addr;",
		`proxy_set_header Forwarded "";`,
		`proxy_set_header X-Original-Forwarded-For "";`,
		`proxy_set_header EO-Connecting-IP "";`,
		"allow 9.9.9.9/32;",
		"deny all;",
		"listen 127.0.0.1:18080;",
		"listen 127.0.0.1:18443 ssl;",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered realip runtime fixture missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "$proxy_add_x_forwarded_for") {
		t.Fatalf("rendered realip runtime fixture must not append inbound X-Forwarded-For\n%s", text)
	}
}

func requireNginxRuntimeFixture() bool {
	return os.Getenv("LANPANEL_REQUIRE_NGINX_TESTS") == "1" || strings.EqualFold(os.Getenv("CI"), "true")
}

func nginxRuntimeFixtureBinary() (string, error) {
	info, err := os.Stat(nginxRuntimeFixturePath)
	if err != nil {
		return "", fmt.Errorf("%s is unavailable: %w", nginxRuntimeFixturePath, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular executable", nginxRuntimeFixturePath)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("%s is not executable", nginxRuntimeFixturePath)
	}
	return nginxRuntimeFixturePath, nil
}

func renderedNginxRealIPFixtureConfig(t *testing.T, dir string, httpPort int, httpsPort int, upstreamAddress string, activePath string, trustedCIDRPath string, accessLog string, rejectLog string, certPath string, keyPath string, authPath string) string {
	t.Helper()

	enabled := true
	http2 := false
	cfg := appconfig.New()
	cfg.App.Name = "example-app"
	cfg.App.Domains = []string{"app.example.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.App.Listen = upstreamAddress
	cfg.Access.AccessMode = appconfig.AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Service.ExecStart = "/bin/true --listen " + upstreamAddress
	cfg.Service.WorkingDirectory = "/tmp"
	cfg.Nginx.HTTP2 = &http2
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = authPath
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"9.9.9.9/32"}
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-2abcDEF123",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns/tencentcloud.env"

	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	nginxText := ""
	for _, file := range staged {
		if file.SourcePath == "templates/app/nginx.conf.tmpl" {
			nginxText = string(file.Content)
			break
		}
	}
	if nginxText == "" {
		t.Fatal("rendered app Nginx site is missing")
	}

	replacements := map[string]string{
		"listen 80;\n    listen [::]:80;":                            fmt.Sprintf("listen 127.0.0.1:%d;", httpPort),
		"listen 443 ssl;\n    listen [::]:443 ssl;":                  fmt.Sprintf("listen 127.0.0.1:%d ssl;", httpsPort),
		"/etc/nginx/lanpanel/realip/edgeone-prod/active.conf":        activePath,
		"/etc/nginx/lanpanel/realip/edgeone-prod/trusted-cidrs.conf": trustedCIDRPath,
		"/var/log/lanpanel/apps/example-app/access.log":              accessLog,
		"/var/log/nginx/example-app-realip-rejections.log":           rejectLog,
		"/etc/example-app/tls/app.example.com/fullchain.pem":         certPath,
		"/etc/example-app/tls/app.example.com/privkey.pem":           keyPath,
	}
	for oldValue, newValue := range replacements {
		if !strings.Contains(nginxText, oldValue) {
			t.Fatalf("rendered app Nginx site missing replacement target %q\n%s", oldValue, nginxText)
		}
		nginxText = strings.ReplaceAll(nginxText, oldValue, newValue)
	}

	return fmt.Sprintf(`pid %s;
error_log %s info;
worker_processes 1;

events {
    worker_connections 64;
}

http {
%s
}
`, filepath.Join(dir, fmt.Sprintf("nginx-%d.pid", httpsPort)), filepath.Join(dir, fmt.Sprintf("nginx-%d.error.log", httpsPort)), nginxText)
}

func startNginxFixture(t *testing.T, nginxPath string, prefix string, confPath string, ports ...int) {
	t.Helper()

	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatalf("create nginx fixture prefix: %v", err)
	}
	output, err := exec.Command(nginxPath, "-p", prefix, "-c", confPath).CombinedOutput()
	if err != nil {
		t.Fatalf("start nginx fixture: %v\n%s", err, string(output))
	}
	t.Cleanup(func() {
		_ = exec.Command(nginxPath, "-p", prefix, "-c", confPath, "-s", "quit").Run()
	})
	for _, port := range ports {
		waitForTCPPort(t, port)
	}
}

func freeLocalPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local ephemeral port: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Fatalf("close local ephemeral listener: %v", err)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForTCPPort(t *testing.T, port int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nginx fixture did not open port %d: %v", port, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func requestFixture(t *testing.T, port int, headers map[string][]string, wantStatus int) map[string]string {
	t.Helper()

	return requestFixturePath(t, port, "/", headers, wantStatus)
}

func requestFixturePath(t *testing.T, port int, path string, headers map[string][]string, wantStatus int) map[string]string {
	t.Helper()

	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+fmt.Sprintf("%d", port)+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Host = "app.example.com"
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request fixture: %v", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Fatalf("close response body: %v", err)
		}
	}()
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d", response.StatusCode, wantStatus)
	}
	if wantStatus != http.StatusOK {
		return nil
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode upstream response: %v", err)
	}
	return body
}

func writeSelfSignedCertificate(t *testing.T, certPath string, keyPath string, domain string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate TLS key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate TLS serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create TLS certificate: %v", err)
	}
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open TLS certificate: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certFile.Close()
		t.Fatalf("write TLS certificate: %v", err)
	}
	if err := certFile.Close(); err != nil {
		t.Fatalf("close TLS certificate: %v", err)
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open TLS key: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		_ = keyFile.Close()
		t.Fatalf("write TLS key: %v", err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatalf("close TLS key: %v", err)
	}
}

func assertSensitiveHeadersCleared(t *testing.T, body map[string]string) {
	t.Helper()

	for _, name := range []string{
		"Forwarded",
		"X-Forwarded-Port",
		"X-Forwarded-Prefix",
		"X-Original-Forwarded-For",
		"X-Client-IP",
		"Client-IP",
		"True-Client-IP",
		"EO-Connecting-IP",
		"EO-Client-IP",
	} {
		if body[name] != "" {
			t.Fatalf("upstream received sensitive header %s=%q in %#v", name, body[name], body)
		}
	}
}

func waitForFileContains(t *testing.T, path string, want string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), want) {
			return
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			lastErr = err
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(path)
			t.Fatalf("%s did not contain %q; lastErr=%v content=%q", path, want, lastErr, string(data))
		}
		time.Sleep(25 * time.Millisecond)
	}
}
