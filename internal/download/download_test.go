package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"lanpanel/internal/sources"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDownloadStreamsExactBoundedDigestWithoutFallback(t *testing.T) {
	payload := []byte("release artifact bytes")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/redirect":
			http.Redirect(response, request, "/artifact", http.StatusFound)
		case "/artifact":
			_, _ = response.Write(payload)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	source := sources.Source{Kind: sources.Mirror, URL: server.URL + "/redirect", Artifact: sources.Artifact{Name: "headscale", Version: "0.25.1", OperatingOS: "linux", Architecture: "amd64", Digest: digest}}
	downloader, err := New(Config{Source: source, MaximumRedirects: 2, Timeouts: testTimeouts()})
	if err != nil {
		t.Fatal(err)
	}
	var destination bytes.Buffer
	result, err := downloader.fetch(context.Background(), Request{MaximumBytes: 1024, ExpectedSize: int64(len(payload))}, &destination)
	if err != nil || !bytes.Equal(destination.Bytes(), payload) || result.Digest != digest || result.Bytes != int64(len(payload)) {
		t.Fatalf("download=%#v bytes=%q error=%v", result, destination.Bytes(), err)
	}

	proxy := &sources.Proxy{URL: "http://127.0.0.1:1"}
	proxied, err := New(Config{Source: source, Proxy: proxy, MaximumRedirects: 2, Timeouts: testTimeouts()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxied.fetch(context.Background(), Request{MaximumBytes: 1024}, &bytes.Buffer{}); err == nil {
		t.Fatal("failed explicit proxy was bypassed")
	}
}

func TestDownloaderCopiesPinnedRedirectAndProxyAuthority(t *testing.T) {
	authorities := []string{"cdn.example.test", "downloads.example.test"}
	proxy := &sources.Proxy{URL: "https://proxy.example.test"}
	source := sources.Source{Kind: sources.OfficialCanonical, URL: "https://downloads.example.test/artifact", OfficialAuthorities: authorities, Artifact: sources.Artifact{Name: "lego", Version: "4.25.2", OperatingOS: "linux", Architecture: "amd64", Digest: strings.Repeat("a", 64)}}
	downloader, err := New(Config{Source: source, Proxy: proxy, MaximumRedirects: 2, Timeouts: testTimeouts()})
	if err != nil {
		t.Fatal(err)
	}
	authorities[0] = "attacker.example.test"
	proxy.URL = "http://attacker.example.test"
	if downloader.config.Source.OfficialAuthorities[0] != "cdn.example.test" || downloader.config.Proxy.URL != "https://proxy.example.test" {
		t.Fatal("validated download authority remained caller-mutable")
	}
}

func TestOfficialSignedRedirectDoesNotForwardQueryAsReferer(t *testing.T) {
	payload := []byte("official redirected artifact")
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	headers := make(chan http.Header, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		headers <- request.Header.Clone()
		_, _ = response.Write(payload)
	}))
	defer target.Close()
	sourceServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+"/artifact?short_lived=sentinel-query", http.StatusFound)
	}))
	defer sourceServer.Close()
	authorities := []string{strings.TrimPrefix(sourceServer.URL, "https://"), strings.TrimPrefix(target.URL, "https://")}
	slices.Sort(authorities)
	source := sources.Source{Kind: sources.OfficialCanonical, URL: sourceServer.URL + "/artifact", OfficialAuthorities: authorities, Artifact: sources.Artifact{Name: "headscale", Version: "0.25.1", OperatingOS: "linux", Architecture: "amd64", Digest: digest}}
	downloader, err := New(Config{Source: source, MaximumRedirects: 2, Timeouts: testTimeouts()})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(sourceServer.Certificate())
	roots.AddCert(target.Certificate())
	downloader.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableKeepAlives: true}
	if _, err := downloader.fetch(context.Background(), Request{MaximumBytes: 1024, ExpectedSize: int64(len(payload))}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got := <-headers
	if got.Get("Referer") != "" || got.Get("Authorization") != "" || got.Get("Cookie") != "" {
		t.Fatalf("redirect forwarded sensitive headers: %v", got)
	}
}

func TestDownloadReadIdleDeadlineClosesStalledBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Length", "2")
		response.WriteHeader(http.StatusOK)
		response.(http.Flusher).Flush()
		time.Sleep(150 * time.Millisecond)
		_, _ = response.Write([]byte("ok"))
	}))
	defer server.Close()
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("ok")))
	source := sources.Source{Kind: sources.Mirror, URL: server.URL + "/artifact", Artifact: sources.Artifact{Name: "lego", Version: "4.25.2", OperatingOS: "linux", Architecture: "amd64", Digest: digest}}
	timeouts := testTimeouts()
	timeouts.ReadIdle = 20 * time.Millisecond
	downloader, err := New(Config{Source: source, MaximumRedirects: 1, Timeouts: timeouts})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := downloader.fetch(context.Background(), Request{MaximumBytes: 16, ExpectedSize: 2}, &bytes.Buffer{}); err == nil {
		t.Fatal("stalled download body escaped read-idle deadline")
	}
}

func TestDownloadRejectsDigestMismatchTruncationAndOversize(t *testing.T) {
	payload := []byte(strings.Repeat("x", 32))
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/truncated" {
			response.Header().Set("Content-Length", "64")
		}
		_, _ = response.Write(payload)
	}))
	defer server.Close()
	artifact := sources.Artifact{Name: "lego", Version: "4.25.2", OperatingOS: "linux", Architecture: "amd64", Digest: strings.Repeat("0", 64)}
	for name, test := range map[string]struct {
		path    string
		maximum int64
	}{"digest": {path: "/artifact", maximum: 64}, "truncated": {path: "/truncated", maximum: 64}, "oversize": {path: "/artifact", maximum: 8}} {
		source := sources.Source{Kind: sources.Mirror, URL: server.URL + test.path, Artifact: artifact}
		downloader, err := New(Config{Source: source, MaximumRedirects: 1, Timeouts: testTimeouts()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := downloader.fetch(context.Background(), Request{MaximumBytes: test.maximum}, &bytes.Buffer{}); err == nil {
			t.Fatalf("%s download was accepted", name)
		}
	}
}

func testTimeouts() Timeouts {
	return Timeouts{Connect: time.Second, TLSHandshake: time.Second, ResponseHeader: time.Second, ReadIdle: time.Second, Total: 3 * time.Second}
}
