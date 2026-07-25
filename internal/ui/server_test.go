package ui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/browserauth"
	"lanpanel/internal/components/headscale"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/host"
	"lanpanel/internal/state"
	"lanpanel/internal/uistate"
	"lanpanel/internal/workflow"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var activeNginxSitesDirTestMu sync.Mutex

func useActiveNginxSitesDirForTest(t *testing.T, dir string) {
	t.Helper()
	activeNginxSitesDirTestMu.Lock()
	previous := activeNginxSitesAvailableDir
	activeNginxSitesAvailableDir = dir
	t.Cleanup(func() {
		activeNginxSitesAvailableDir = previous
		activeNginxSitesDirTestMu.Unlock()
	})
}

func assertNoStoreHeaders(t *testing.T, response *http.Response, label string) {
	t.Helper()
	if got := response.Header.Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Fatalf("%s Cache-Control = %q, want no-store", label, got)
	}
	if got := response.Header.Get("Pragma"); got != "no-cache" {
		t.Fatalf("%s Pragma = %q, want no-cache", label, got)
	}
	if got := response.Header.Get("Expires"); got != "0" {
		t.Fatalf("%s Expires = %q, want 0", label, got)
	}
}

func TestValidateLoopbackAddrRejectsPublicListen(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{"0.0.0.0:18080", "[::]:18080", "203.0.113.10:18080", "localhost:18080"} {
		if err := ValidateLoopbackAddr(addr); err == nil {
			t.Fatalf("ValidateLoopbackAddr(%q) error = nil", addr)
		}
	}
	if err := ValidateLoopbackAddr("127.0.0.1:18080"); err != nil {
		t.Fatalf("ValidateLoopbackAddr(loopback) error = %v", err)
	}
	if err := ValidateLoopbackAddr("[::1]:18080"); err != nil {
		t.Fatalf("ValidateLoopbackAddr(ipv6 loopback) error = %v", err)
	}
}

func TestHTMXMetadataMatchesVendoredAsset(t *testing.T) {
	t.Parallel()

	meta, err := loadHTMXMetadata()
	if err != nil {
		t.Fatalf("loadHTMXMetadata() error = %v", err)
	}
	if meta.Version == "" || meta.Source == "" || meta.SHA256 == "" || meta.CheckedAt == "" {
		t.Fatalf("metadata = %#v, want required provenance fields", meta)
	}
	if !strings.Contains(meta.Source, "htmx.org@"+meta.Version) {
		t.Fatalf("source = %q, want versioned htmx source for %s", meta.Source, meta.Version)
	}
}

func TestNewServerRejectsUnsafeTokenTTL(t *testing.T) {
	t.Parallel()

	if _, err := NewServer(Options{Addr: "127.0.0.1:18080", TokenTTL: 31 * time.Minute}); err == nil {
		t.Fatal("NewServer() error = nil, want token ttl failure")
	}
}

func TestNewServerRejectsEmptyStateDir(t *testing.T) {
	t.Parallel()

	if _, err := NewServer(Options{Addr: "127.0.0.1:18080", StateDir: ""}); err == nil || !strings.Contains(err.Error(), "ui state dir is required") {
		t.Fatalf("NewServer() error = %v, want state dir failure", err)
	}
}

func TestNewServerRejectsWhitespacePaddedStateDir(t *testing.T) {
	t.Parallel()

	if _, err := NewServer(Options{Addr: "127.0.0.1:18080", StateDir: " " + secureStateDir(t) + " "}); err == nil || !strings.Contains(err.Error(), "ui state dir must be a clean absolute path") {
		t.Fatalf("NewServer() error = %v, want clean absolute path failure", err)
	}
}

func TestHTTPServerUsesExplicitTimeouts(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	httpServer := server.httpServer()
	if httpServer.Addr != "127.0.0.1:18080" {
		t.Fatalf("Addr = %q, want configured listen address", httpServer.Addr)
	}
	if httpServer.Handler == nil {
		t.Fatal("Handler = nil")
	}
	if httpServer.ReadHeaderTimeout != DefaultReadHeaderTimeout ||
		httpServer.ReadTimeout != DefaultReadTimeout ||
		httpServer.WriteTimeout != DefaultWriteTimeout ||
		httpServer.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("timeouts = read_header %s read %s write %s idle %s", httpServer.ReadHeaderTimeout, httpServer.ReadTimeout, httpServer.WriteTimeout, httpServer.IdleTimeout)
	}
}

func TestStartupTokenExchangeRedirectsAndSetsCookieFlags(t *testing.T) {
	t.Parallel()

	stateDir := secureStateDir(t)
	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: stateDir, Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	request := newUIRequest(http.MethodGet, server.StartupURL(), nil)
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want /", location)
	}
	assertNoStoreHeaders(t, recorder.Result(), "login redirect")
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookies = %#v, want HttpOnly SameSite strict session", cookies)
	}
}

func TestStartupTokenIsSingleUseAndExpires(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	startupURL := server.StartupURL()
	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, newUIRequest(http.MethodGet, startupURL, nil))
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first login status = %d, want 303", first.Code)
	}
	reuse := httptest.NewRecorder()
	server.Handler().ServeHTTP(reuse, newUIRequest(http.MethodGet, startupURL, nil))
	if reuse.Code != http.StatusForbidden {
		t.Fatalf("reuse login status = %d, want 403", reuse.Code)
	}

	now := fixedNow()
	expiring, err := NewServer(Options{
		Addr:     "127.0.0.1:18080",
		Version:  "test",
		StateDir: secureStateDir(t),
		TokenTTL: time.Minute,
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewServer(expiring) error = %v", err)
	}
	expiredURL := expiring.StartupURL()
	now = now.Add(2 * time.Minute)
	expired := httptest.NewRecorder()
	expiring.Handler().ServeHTTP(expired, newUIRequest(http.MethodGet, expiredURL, nil))
	if expired.Code != http.StatusForbidden {
		t.Fatalf("expired login status = %d, want 403", expired.Code)
	}
}

func TestStartupURLUsesBracketedIPv6Loopback(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "[::1]:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if !strings.HasPrefix(server.StartupURL(), "http://[::1]:18080/login?token=") {
		t.Fatalf("StartupURL() = %q, want bracketed IPv6 loopback URL", server.StartupURL())
	}
}

func TestSessionCSRFAndLocalHTMXAsset(t *testing.T) {
	t.Parallel()

	stateDir := secureStateDir(t)
	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: stateDir, Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, newUIRequest(http.MethodGet, server.StartupURL(), nil))
	cookie := login.Result().Cookies()[0]

	page := httptest.NewRecorder()
	request := newUIRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	server.Handler().ServeHTTP(page, request)
	if page.Code != http.StatusOK {
		t.Fatalf("overview status = %d body = %q", page.Code, page.Body.String())
	}
	if body := page.Body.String(); strings.Contains(body, "https://cdn") || !strings.Contains(body, "/static/vendor/htmx/htmx.min.js") {
		t.Fatalf("overview body has invalid htmx reference:\n%s", body)
	}

	fragment := httptest.NewRecorder()
	fragmentRequest := newUIRequest(http.MethodGet, "/fragments/job-history", nil)
	fragmentRequest.AddCookie(cookie)
	server.Handler().ServeHTTP(fragment, fragmentRequest)
	if fragment.Code != http.StatusOK {
		t.Fatalf("job history fragment status = %d body = %q", fragment.Code, fragment.Body.String())
	}
	assertNoStoreHeaders(t, fragment.Result(), "job history fragment")

	post := httptest.NewRecorder()
	postRequest := newUIRequest(http.MethodPost, "/jobs/create", strings.NewReader(url.Values{}.Encode()))
	postRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRequest.AddCookie(cookie)
	server.Handler().ServeHTTP(post, postRequest)
	if post.Code != http.StatusForbidden {
		t.Fatalf("csrf status = %d, want 403", post.Code)
	}

	asset := httptest.NewRecorder()
	server.Handler().ServeHTTP(asset, newUIRequest(http.MethodGet, "/static/vendor/htmx/htmx.min.js", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "htmx") {
		t.Fatalf("htmx asset status=%d len=%d", asset.Code, asset.Body.Len())
	}
	if got := asset.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("htmx Cache-Control = %q, want immutable", got)
	}
	if got := asset.Header().Get("Pragma"); got != "" {
		t.Fatalf("htmx Pragma = %q, want empty", got)
	}
	if got := asset.Header().Get("Expires"); got != "" {
		t.Fatalf("htmx Expires = %q, want empty", got)
	}
}

func TestStartJobRejectsAfterBackgroundStoreFailure(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.rememberStoreFailure(errors.New("append failure event: permission denied"))

	_, err = server.startJob(newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(url.Values{"operation": {"main_status"}}.Encode())))
	if err == nil || !strings.Contains(err.Error(), "ui job store is failed") || !strings.Contains(err.Error(), "append failure event") {
		t.Fatalf("startJob() error = %v, want stored failure", err)
	}
}

func TestSecurityHeadersBodyLimitAndPanicRecovery(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)

	headers := httptest.NewRecorder()
	request := newUIRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	server.Handler().ServeHTTP(headers, request)
	if headers.Code != http.StatusOK {
		t.Fatalf("headers page status = %d body = %q", headers.Code, headers.Body.String())
	}
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := headers.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if csp := headers.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy = %q, want self-only and no frames", csp)
	}
	assertNoStoreHeaders(t, headers.Result(), "dynamic page")

	sessionRequest := newUIRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(cookie)
	sess, ok := server.sessionFromRequest(sessionRequest)
	if !ok {
		t.Fatal("sessionFromRequest() = false")
	}
	body := "csrf_token=" + url.QueryEscape(sess.CSRF) + "&operation=main_init&padding=" + strings.Repeat("a", (1<<20)+1)
	tooLarge := httptest.NewRecorder()
	post := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(body))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookie)
	server.Handler().ServeHTTP(tooLarge, post)
	if tooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status = %d body = %q, want 413", tooLarge.Code, tooLarge.Body.String())
	}

	panicHandler := secureHeaders(recoverPanic(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret panic detail")
	})))
	panicResponse := httptest.NewRecorder()
	panicHandler.ServeHTTP(panicResponse, newUIRequest(http.MethodGet, "/panic", nil))
	if panicResponse.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d, want 500", panicResponse.Code)
	}
	if strings.Contains(panicResponse.Body.String(), "secret panic detail") {
		t.Fatalf("panic body leaked detail: %q", panicResponse.Body.String())
	}
	if got := panicResponse.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("panic X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestWriteRouteRequiresRootAfterCSRF(t *testing.T) {
	previousEUID := currentEUID
	currentEUID = func() int { return 1000 }
	t.Cleanup(func() { currentEUID = previousEUID })

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	sessionRequest := newUIRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(cookie)
	sess, ok := server.sessionFromRequest(sessionRequest)
	if !ok {
		t.Fatal("sessionFromRequest() = false")
	}

	form := url.Values{"operation": {"main_init"}, "csrf_token": {sess.CSRF}}
	post := httptest.NewRecorder()
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Handler().ServeHTTP(post, request)
	if post.Code != http.StatusForbidden {
		t.Fatalf("write route status = %d body = %q, want 403", post.Code, post.Body.String())
	}
	if !strings.Contains(post.Body.String(), "write operations require sudo lanpanel ui") {
		t.Fatalf("write route body = %q, want root requirement", post.Body.String())
	}
}

func TestReadOnlyJobRouteDoesNotRequireRoot(t *testing.T) {
	previousEUID := currentEUID
	currentEUID = func() int { return 1000 }
	t.Cleanup(func() { currentEUID = previousEUID })

	for _, path := range []string{"/jobs/run", "/jobs/create"} {
		t.Run(path, func(t *testing.T) {
			dir := secureStateDir(t)
			configPath := filepath.Join(dir, "lanpanel.yaml")
			if err := config.ExampleConfig().WriteFile(configPath); err != nil {
				t.Fatalf("WriteFile(config) error = %v", err)
			}
			hostWorkflow := &fakeHostWorkflow{}
			server, err := NewServer(Options{
				Addr:         "127.0.0.1:18080",
				Version:      "test",
				StateDir:     secureStateDir(t),
				ConfigPath:   configPath,
				HostWorkflow: hostWorkflow,
				Now:          fixedNow,
			})
			if err != nil {
				t.Fatalf("NewServer() error = %v", err)
			}
			cookie := loginCookie(t, server)
			sessionRequest := newUIRequest(http.MethodGet, "/", nil)
			sessionRequest.AddCookie(cookie)
			sess, ok := server.sessionFromRequest(sessionRequest)
			if !ok {
				t.Fatal("sessionFromRequest() = false")
			}

			form := url.Values{"operation": {"main_status"}, "config_path": {configPath}, "csrf_token": {sess.CSRF}}
			post := httptest.NewRecorder()
			request := newUIRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookie)
			server.Handler().ServeHTTP(post, request)
			if post.Code != http.StatusSeeOther {
				t.Fatalf("read-only route status = %d body = %q, want 303", post.Code, post.Body.String())
			}
			record := waitForSingleRecordStatus(t, server, domain.JobStatusSucceeded)
			if record.Kind != domain.JobKindStatus {
				t.Fatalf("record kind = %q, want status", record.Kind)
			}
			if !hostWorkflow.hasCall("status:" + configPath) {
				t.Fatalf("host workflow calls = %#v, want main_status call", hostWorkflow.calls)
			}
		})
	}
}

func TestHandleRunJobStartsBackgroundJob(t *testing.T) {
	t.Parallel()

	dir := secureStateDir(t)
	configPath := filepath.Join(dir, "lanpanel.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	hostWorkflow := &fakeHostWorkflow{
		mainDeployStarted: make(chan struct{}),
		mainDeployRelease: release,
	}
	server, err := NewServer(Options{
		Addr:                            "127.0.0.1:18080",
		Version:                         "test",
		StateDir:                        secureStateDir(t),
		ConfigPath:                      configPath,
		HostWorkflow:                    hostWorkflow,
		Now:                             fixedNow,
		UnsafeAllowNonRootWritesForTest: true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	sessionRequest := newUIRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(cookie)
	sess, ok := server.sessionFromRequest(sessionRequest)
	if !ok {
		t.Fatal("sessionFromRequest() = false")
	}
	form := url.Values{
		"operation":   {"main_deploy"},
		"config_path": {configPath},
		"csrf_token":  {sess.CSRF},
	}
	recorder := httptest.NewRecorder()
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	done := make(chan struct{})
	go func() {
		server.Handler().ServeHTTP(recorder, request)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleRunJob did not return while workflow was blocked")
	}
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body = %q, want 303", recorder.Code, recorder.Body.String())
	}
	running := waitForSingleRecordStatus(t, server, domain.JobStatusRunning)
	if running.Kind != domain.JobKindDeploy {
		t.Fatalf("running record = %#v, want deploy job", running)
	}
	select {
	case <-hostWorkflow.mainDeployStarted:
	case <-time.After(time.Second):
		t.Fatal("background deploy workflow did not start")
	}
	releaseOnce.Do(func() { close(release) })
	succeeded := waitForSingleRecordStatus(t, server, domain.JobStatusSucceeded)
	if succeeded.ID != running.ID || succeeded.ResultSummary != "main host workflow executed" {
		t.Fatalf("succeeded record = %#v, want completed background job %s", succeeded, running.ID)
	}
}

func TestRunJobDependencyUploadRejectsWrongArtifactAndCleansStaging(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	cfg := config.ExampleConfig()
	cfg.Advanced.Platform.Arch = config.ArchAMD64
	if err := cfg.WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	stateDir := secureStateDir(t)
	server, err := NewServer(Options{
		Addr:                            "127.0.0.1:18080",
		Version:                         "test",
		StateDir:                        stateDir,
		ConfigPath:                      configPath,
		Now:                             fixedNow,
		UnsafeAllowNonRootWritesForTest: true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("operation", "main_lego_archive_upload"); err != nil {
		t.Fatalf("WriteField(operation) error = %v", err)
	}
	if err := writer.WriteField("config_path", configPath); err != nil {
		t.Fatalf("WriteField(config_path) error = %v", err)
	}
	part, err := writer.CreateFormFile(dependencyUploadFileField, "renamed.tar.gz")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write([]byte("not the official lego archive")); err != nil {
		t.Fatalf("Write(upload) error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart Close() error = %v", err)
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.AddCookie(loginCookie(t, server))

	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Kind != domain.JobKindDependencyUpload || record.Status != domain.JobStatusFailed {
		t.Fatalf("record = %#v, want failed dependency_upload job", record)
	}
	if !strings.Contains(record.ErrorSummary, "must be named lego_") {
		t.Fatalf("ErrorSummary = %q, want controlled filename rejection", record.ErrorSummary)
	}
	if wantRetry := workflow.ShellCommand("sudo", "lanpanel", "ui", "--config", configPath); record.RetryCommand != wantRetry {
		t.Fatalf("RetryCommand = %q, want %q", record.RetryCommand, wantRetry)
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "uploads", "dependencies"))
	if err != nil {
		t.Fatalf("ReadDir(staging) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging entries = %#v, want cleaned upload staging directory", entries)
	}
}

func TestPrepareJobRejectsConcurrentHostMutationKinds(t *testing.T) {
	t.Parallel()

	blockers := []struct {
		name string
		form url.Values
	}{
		{
			name: "main deploy",
			form: url.Values{"operation": {"main_deploy"}},
		},
		{
			name: "app config save",
			form: url.Values{"operation": {"app_config_save"}},
		},
		{
			name: "realip refresh",
			form: url.Values{"operation": {"realip_refresh"}, "profile": {"edgeone-prod"}},
		},
	}
	for _, blocker := range blockers {
		blocker := blocker
		t.Run(blocker.name, func(t *testing.T) {
			dir := secureStateDir(t)
			mainConfigPath := filepath.Join(dir, "lanpanel.yaml")
			appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
			if err := config.ExampleConfig().WriteFile(mainConfigPath); err != nil {
				t.Fatalf("WriteFile(main config) error = %v", err)
			}
			if err := appconfig.ExampleConfig().WriteFile(appConfigPath); err != nil {
				t.Fatalf("WriteFile(app config) error = %v", err)
			}
			server, err := NewServer(Options{
				Addr:          "127.0.0.1:18080",
				Version:       "test",
				StateDir:      secureStateDir(t),
				ConfigPath:    mainConfigPath,
				AppConfigPath: appConfigPath,
				Now:           fixedNow,
			})
			if err != nil {
				t.Fatalf("NewServer() error = %v", err)
			}
			cookie := loginCookie(t, server)
			newJobRequest := func(form url.Values) *http.Request {
				if form.Get("config_path") == "" {
					form.Set("config_path", mainConfigPath)
				}
				if form.Get("app_config_path") == "" {
					form.Set("app_config_path", appConfigPath)
				}
				request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookie)
				return request
			}

			first, err := server.prepareJob(newJobRequest(blocker.form), context.Background())
			if err != nil {
				t.Fatalf("prepareJob(blocker) error = %v", err)
			}
			defer func() {
				if err := releaseJobLocks(first.locks); err != nil {
					t.Fatalf("release blocker locks error = %v", err)
				}
			}()

			_, err = server.prepareJob(newJobRequest(url.Values{"operation": {"app_deploy"}}), context.Background())
			if err == nil || !strings.Contains(err.Error(), uistate.HostMutationLockName) {
				t.Fatalf("prepareJob(app_deploy) error = %v, want host mutation lock contention", err)
			}
		})
	}
}

func TestRecordBackgroundJobFailurePreservesPersistedResultFields(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	actor := domain.Actor{
		Source:                  domain.ActorSourceUI,
		EffectiveUID:            0,
		EffectiveUser:           "uid:0",
		ProcessID:               1234,
		SessionIDFingerprint:    "sha256:0011223344556677",
		RequestSource:           "loopback",
		StartupTokenFingerprint: "sha256:8899aabbccddeeff",
	}
	stale, err := server.state.CreateJob(domain.JobRecord{
		Kind:              domain.JobKindVerify,
		Status:            domain.JobStatusRunning,
		Actor:             actor,
		CheckpointRef:     domain.NotApplicableActivationRef(),
		ConfigSnapshotRef: "not_applicable",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	persisted := stale
	persisted.Status = domain.JobStatusSucceeded
	persisted.ResultSummary = "verify completed before release failed"
	persisted.ModifiedPaths = []string{"/etc/lanpanel/lanpanel.yaml"}
	persisted.ConfigSnapshotRef = "/var/lib/lanpanel/ui-state/jobs/job/config-snapshots/main-config.yaml"
	persisted.ResourceIDs = []string{"res_00112233445566778899aabbccddeeff"}
	persisted.RetryCommand = "lanpanel verify --config /etc/lanpanel/lanpanel.yaml"
	if err := server.state.SaveRecord(persisted); err != nil {
		t.Fatalf("SaveRecord() error = %v", err)
	}

	server.recordBackgroundJobFailure(stale, errors.New("release job lock failed: active job lock changed before release"))

	loaded, err := server.state.LoadRecord(stale.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusFailed || !strings.Contains(loaded.ErrorSummary, "release job lock failed") {
		t.Fatalf("loaded failure record = %#v, want failed release error", loaded)
	}
	if loaded.ResultSummary != persisted.ResultSummary ||
		loaded.ConfigSnapshotRef != persisted.ConfigSnapshotRef ||
		loaded.RetryCommand != persisted.RetryCommand ||
		strings.Join(loaded.ModifiedPaths, ",") != strings.Join(persisted.ModifiedPaths, ",") ||
		strings.Join(loaded.ResourceIDs, ",") != strings.Join(persisted.ResourceIDs, ",") {
		t.Fatalf("loaded failure record = %#v, want persisted result fields preserved from %#v", loaded, persisted)
	}
}

func TestMarkPreparedJobFailedPersistsTerminalRecord(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	actor := domain.Actor{
		Source:                  domain.ActorSourceUI,
		EffectiveUID:            0,
		EffectiveUser:           "uid:0",
		ProcessID:               1234,
		SessionIDFingerprint:    "sha256:0011223344556677",
		RequestSource:           "loopback",
		StartupTokenFingerprint: "sha256:8899aabbccddeeff",
	}
	record, err := server.state.CreateJob(domain.JobRecord{
		Kind:              domain.JobKindVerify,
		Status:            domain.JobStatusRunning,
		Actor:             actor,
		CheckpointRef:     domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: filepath.Join(server.options.StateDir, "lanpanel-app.checkpoint.json"), Digest: "sha256:test"},
		ConfigSnapshotRef: "not_applicable",
		RetryCommand:      "lanpanel verify --config lanpanel.yaml",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}

	if err := server.markPreparedJobFailed(record, jobOperation{kind: domain.JobKindVerify, retryCommand: "lanpanel verify --config lanpanel.yaml"}, errors.New("attach job lock failed")); err != nil {
		t.Fatalf("markPreparedJobFailed() error = %v", err)
	}
	loaded, err := server.state.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusFailed || !strings.Contains(loaded.ErrorSummary, "attach job lock failed") {
		t.Fatalf("loaded record = %#v, want failed preparation error", loaded)
	}
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].Status != domain.DiagnosticStatusFail || !strings.Contains(events[0].Message, "job preparation failed") {
		t.Fatalf("events = %#v, want preparation failure event", events)
	}
}

func TestJobsPagePollsHistoryFragment(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	record, err := server.state.CreateJob(domain.JobRecord{
		Kind:   domain.JobKindAppDeploy,
		Status: domain.JobStatusRunning,
		Actor: domain.Actor{
			Source:                  domain.ActorSourceUI,
			EffectiveUID:            0,
			EffectiveUser:           "uid:0",
			ProcessID:               1234,
			SessionIDFingerprint:    "sha256:0011223344556677",
			RequestSource:           "loopback",
			StartupTokenFingerprint: "sha256:8899aabbccddeeff",
		},
		CheckpointRef:     domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: filepath.Join(server.options.StateDir, "lanpanel-app.checkpoint.json"), Digest: "sha256:test"},
		ConfigSnapshotRef: "not_applicable",
		RetryCommand:      "sudo lanpanel app deploy --config lanpanel-app.yaml --confirmation origin-protection-manual",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusManual, Message: "job started"}); err != nil {
		t.Fatalf("AppendEvent(start) error = %v", err)
	}

	cookie := loginCookie(t, server)
	jobs := authenticatedGET(t, server, cookie, "/jobs?job="+url.QueryEscape(record.ID))
	if !strings.Contains(jobs, `id="job-history"`) || !strings.Contains(jobs, `hx-get="/fragments/job-history?job=`+record.ID+`"`) {
		t.Fatalf("jobs page missing polling history fragment for %s:\n%s", record.ID, jobs)
	}

	record.Status = domain.JobStatusSucceeded
	record.ResultSummary = "e2e app deploy simulated"
	if err := server.state.SaveRecord(record); err != nil {
		t.Fatalf("SaveRecord() error = %v", err)
	}
	if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusManual, Message: "manual confirmation submitted: origin-protection-manual"}); err != nil {
		t.Fatalf("AppendEvent(confirm) error = %v", err)
	}

	fragment := authenticatedGET(t, server, cookie, "/fragments/job-history?job="+url.QueryEscape(record.ID))
	if !strings.Contains(fragment, "e2e app deploy simulated") || !strings.Contains(fragment, "manual confirmation submitted: origin-protection-manual") {
		t.Fatalf("job history fragment = %q, want updated summary and manual confirmation event", fragment)
	}
}

func TestProductPagesRenderTypedFormsAndFragments(t *testing.T) {
	t.Parallel()

	dir := secureStateDir(t)
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	if err := appconfig.ExampleConfig().WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, newUIRequest(http.MethodGet, server.StartupURL(), nil))
	cookie := login.Result().Cookies()[0]

	for _, tt := range []struct {
		path string
		want []string
	}{
		{path: "/settings", want: []string{"certificate_email", "dns01_provider", "headscale_source_mode", "platform_arch"}},
		{path: "/resources", want: []string{"access_mode", "public_risk_confirmed", "origin_mode", `hx-post="/fragments/exposure-preview"`, `type="password" name="browser_auth_create_password"`, `type="password" name="browser_auth_rotate_password"`}},
		{path: "/diagnostics", want: []string{"Runtime Diagnostics", "Host Check Summary"}},
		{path: "/services", want: []string{"headscale.service", "nginx.service", "Refresh Status"}},
		{path: "/certificates", want: []string{"Certificate / Nginx Summary", "Runtime Evidence", "main fullchain", "reload hook", "Certificate Expiry", "Nginx Config Test", "nginx-config", "Run Verify"}},
		{path: "/onboarding", want: []string{"preauth_key_create", "Tailscale-compatible client"}},
		{path: "/migration", want: []string{"No machine-readable export manifest"}},
	} {
		page := httptest.NewRecorder()
		request := newUIRequest(http.MethodGet, tt.path, nil)
		request.AddCookie(cookie)
		server.Handler().ServeHTTP(page, request)
		if page.Code != http.StatusOK {
			t.Fatalf("%s status = %d body = %q", tt.path, page.Code, page.Body.String())
		}
		body := page.Body.String()
		if strings.Contains(body, "placeholder") {
			t.Fatalf("%s body still contains placeholder text:\n%s", tt.path, body)
		}
		for _, want := range tt.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s body missing %q:\n%s", tt.path, want, body)
			}
		}
	}
}

func TestHostHealthFullHTMLRendersTypedFacts(t *testing.T) {
	t.Parallel()

	html := hostHealthFullHTML(domain.HostHealthSummary{
		Host: domain.HostHealthHost{
			Disks: []domain.HostHealthDisk{{
				Mountpoint:   "/",
				FSType:       "ext4",
				TotalBytes:   1000,
				UsedBytes:    250,
				UsagePercent: 25,
			}},
			NetworkAddresses: []domain.HostHealthNetworkAddresses{{
				Interface: "eth0",
				Addresses: []string{"192.0.2.10/24"},
			}},
		},
		Checks: domain.HostHealthChecks{
			PortListeners: []domain.HostHealthPortListener{{Protocol: "tcp", LocalAddress: "127.0.0.1", Port: 18080}},
			Certificates:  []domain.DiagnosticRef{{ID: "certificate:app.example.com", Status: domain.DiagnosticStatusWarn}},
		},
		Certificates: []domain.HostHealthCertificate{{
			Domain:       "app.example.com",
			NotAfter:     "2026-08-01T00:00:00Z",
			DiagnosticID: "certificate:app.example.com",
		}},
		AllowedActions:   []domain.HostHealthAction{domain.HostHealthActionOpenDiagnostics},
		ForbiddenActions: []domain.HostHealthAction{domain.HostHealthActionDiskCleanup},
	})

	for _, want := range []string{"/", "ext4", "eth0", "192.0.2.10/24", "Loopback", "127.0.0.1", "18080", "app.example.com", "2026-08-01T00:00:00Z", "certificate:app.example.com", "disk_cleanup"} {
		if !strings.Contains(html, want) {
			t.Fatalf("hostHealthFullHTML() = %s, want %q", html, want)
		}
	}
}

func TestResourcesDeployFormSubmitsManualConfirmation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	appCfg := appconfig.ExampleConfig()
	appCfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	appCfg.DNS01.Provider = "tencentcloud"
	appCfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	appCfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	appCfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	appCfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	appCfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-123456",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := appCfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	hostWorkflow := &fakeHostWorkflow{exposureObservations: map[domain.ExposurePlanOperation]exposure.AppObservations{
		domain.ExposurePlanOperationDeploy:        manualOriginProtectionObservation(),
		domain.ExposurePlanOperationRealIPRefresh: passOriginProtectionObservation(),
	}}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		HostWorkflow:  hostWorkflow,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	cookie := loginCookie(t, server)
	body := authenticatedGET(t, server, cookie, "/resources")
	deployForm, ok := formContainingOperation(body, "app_deploy")
	if !ok {
		t.Fatalf("resources page missing app_deploy form:\n%s", body)
	}
	if !strings.Contains(deployForm, `name="confirmation" value="origin-protection-manual"`) {
		t.Fatalf("app_deploy form does not submit manual confirmation:\n%s", deployForm)
	}
	realIPRefreshForm, ok := formContainingOperation(body, "realip_refresh")
	if !ok {
		t.Fatalf("resources page missing realip_refresh form:\n%s", body)
	}
	if strings.Contains(realIPRefreshForm, `name="confirmation" value="origin-protection-manual"`) {
		t.Fatalf("realip_refresh form submits unnecessary manual confirmation for configured_pass:\n%s", realIPRefreshForm)
	}

	form := url.Values{
		"operation":       {"app_deploy"},
		"app_config_path": {appConfigPath},
		"confirmation":    {"origin-protection-manual"},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if result.Kind != domain.JobKindAppDeploy || record.Status != domain.JobStatusSucceeded {
		t.Fatalf("result=%#v record=%#v, want confirmed app deploy", result, record)
	}
	if !hostWorkflow.hasCall("app:" + appConfigPath) {
		t.Fatalf("host workflow calls = %v, missing confirmed app deploy", hostWorkflow.calls)
	}
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if !eventsContain(events, "manual confirmation submitted: origin-protection-manual") {
		t.Fatalf("events = %#v, want manual confirmation event", events)
	}
	confirmationEvent, ok := eventWithMessage(events, "manual confirmation submitted: origin-protection-manual")
	if !ok {
		t.Fatalf("events = %#v, want manual confirmation event", events)
	}
	if result.ExposurePlan == nil || len(result.ExposurePlan.Access.ManualConfirmations) != 1 {
		t.Fatalf("ExposurePlan = %#v, want one structured manual confirmation", result.ExposurePlan)
	}
	manual := result.ExposurePlan.Access.ManualConfirmations[0]
	if manual.ConfirmationID != confirmationEvent.ID || manual.Reason != "origin_firewall_confirmed" || manual.ConfirmedAt != confirmationEvent.At.UTC().Format(time.RFC3339) {
		t.Fatalf("ManualConfirmation = %#v, event = %#v", manual, confirmationEvent)
	}
	if manual.Actor.Source != domain.ActorSourceUI || manual.Actor.SessionIDFingerprint != record.Actor.SessionIDFingerprint || manual.Actor.RequestSource == "" {
		t.Fatalf("ManualConfirmation.Actor = %#v, record actor = %#v", manual.Actor, record.Actor)
	}
}

func TestServerStartupInitializesResourceInstanceIDForPreview(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	stateDir := secureStateDir(t)
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	if err := appconfig.ExampleConfig().WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      stateDir,
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	assertResourceInstanceID(t, stateDir)
	summary, err := server.resourceExposureMap()
	if err != nil {
		t.Fatalf("resourceExposureMap() error = %v", err)
	}
	if summary.Instance.BaseDomain != "tailnet.example.com" || summary.Instance.ServerURL != "https://hs.example.com" {
		t.Fatalf("summary.Instance = %#v, want main config base_domain and server_url", summary.Instance)
	}
	cookie := loginCookie(t, server)
	body := authenticatedGET(t, server, cookie, "/")
	if !strings.Contains(body, "Control Center") || !strings.Contains(body, "Host Health") || !strings.Contains(body, "Last Job") {
		t.Fatalf("overview body = %q, want control center rollup", body)
	}
	if !strings.Contains(body, "Detailed resource exposure map and per-resource controls are on") || strings.Contains(body, "lanpanel.exposure.v1") {
		t.Fatalf("overview body = %q, want resource exposure rollup without full schema map", body)
	}

	resourcesBody := authenticatedGET(t, server, cookie, "/resources")
	if !strings.Contains(resourcesBody, "Current Exposure") || !strings.Contains(resourcesBody, "lanpanel.exposure.v1") || !strings.Contains(resourcesBody, "example-app") {
		t.Fatalf("resources body = %q, want typed resource exposure details", resourcesBody)
	}

	sessionRequest := newUIRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(cookie)
	sess, ok := server.sessionFromRequest(sessionRequest)
	if !ok {
		t.Fatal("sessionFromRequest() = false")
	}
	form := validPublicAppForm(appConfigPath)
	form.Set("csrf_token", sess.CSRF)
	preview := httptest.NewRecorder()
	request := newUIRequest(http.MethodPost, "/fragments/exposure-preview", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	server.Handler().ServeHTTP(preview, request)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), "lanpanel.exposure_plan.v1") {
		t.Fatalf("preview status=%d body=%q, want first-run exposure plan preview", preview.Code, preview.Body.String())
	}
}

func TestResourceExposureSummaryDoesNotUseMainCheckpointAsAppActivation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	if err := appconfig.ExampleConfig().WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	checkpointPath := state.DefaultCheckpointPath(configPath)
	if err := state.NewStore(checkpointPath).Save(state.Checkpoint{
		DesiredStateDigest: "sha256:" + strings.Repeat("a", 64),
	}); err != nil {
		t.Fatalf("Save(main checkpoint) error = %v", err)
	}

	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	appCfg, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		t.Fatalf("LoadFile(app config) error = %v", err)
	}
	instanceID, err := server.readInstanceID()
	if err != nil {
		t.Fatalf("readInstanceID() error = %v", err)
	}
	observations, err := server.exposureSummaryObservations(appConfigPath, appCfg)
	if err != nil {
		t.Fatalf("exposureSummaryObservations() error = %v", err)
	}
	summary, err := exposure.AppSummaryWithObservations(instanceID, "test", appCfg, observations)
	if err != nil {
		t.Fatalf("AppSummaryWithObservations() error = %v", err)
	}
	entry := summary.Resources[0]
	if entry.Activation.Kind != domain.ActivationRefNotApplicable {
		t.Fatalf("Activation = %#v, want app activation not_applicable despite main checkpoint %s", entry.Activation, checkpointPath)
	}
	if entry.Resource.State != domain.ResourceStatePlanned {
		t.Fatalf("Resource.State = %q, want planned without app activation evidence", entry.Resource.State)
	}
}

func TestResourceExposureSummaryUsesMatchingAppCheckpointActivation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	if err := appconfig.ExampleConfig().WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	appCfg, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		t.Fatalf("LoadFile(app config) error = %v", err)
	}
	digest, err := appDesiredStateDigest(appCfg)
	if err != nil {
		t.Fatalf("appDesiredStateDigest() error = %v", err)
	}
	checkpointPath := state.DefaultCheckpointPath(appConfigPath)
	checkpoint := state.Checkpoint{DesiredStateDigest: digest}
	checkpoint.MarkCompleted("app-runtime-assets-installed")
	checkpoint.RecordModifiedPaths("/etc/nginx/sites-available/example-app.conf")
	checkpoint.FinalizeSuccessfulDeploy()
	if err := state.NewStore(checkpointPath).Save(checkpoint); err != nil {
		t.Fatalf("Save(app checkpoint) error = %v", err)
	}

	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	summary, err := server.resourceExposureMap()
	if err != nil {
		t.Fatalf("resourceExposureMap() error = %v", err)
	}
	entry := summary.Resources[0]
	if entry.Activation.Kind != domain.ActivationRefCheckpoint || entry.Activation.Path != checkpointPath || entry.Activation.Digest != digest {
		t.Fatalf("Activation = %#v, want app checkpoint %s", entry.Activation, checkpointPath)
	}
	if entry.Resource.State != domain.ResourceStateActive {
		t.Fatalf("Resource.State = %q, want active", entry.Resource.State)
	}
}

func TestResourceExposureSummaryIncludesRegisteredAppConfigs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mainConfigPath := filepath.Join(dir, "lanpanel.yaml")
	defaultAppPath := filepath.Join(dir, "lanpanel-app.yaml")
	otherAppPath := filepath.Join(dir, "other-app.yaml")
	if err := config.ExampleConfig().WriteFile(mainConfigPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	defaultCfg := appconfig.ExampleConfig()
	defaultCfg.App.Name = "first-app"
	defaultCfg.App.Domains = []string{"first.example.com"}
	if err := defaultCfg.WriteFile(defaultAppPath); err != nil {
		t.Fatalf("WriteFile(default app config) error = %v", err)
	}
	otherCfg := appconfig.ExampleConfig()
	otherCfg.App.Name = "second-app"
	otherCfg.App.Domains = []string{"second.example.com"}
	otherCfg.App.Listen = "127.0.0.1:18002"
	otherCfg.Service.ExecStart = "/opt/second-app/second-app --listen 127.0.0.1:18002"
	if err := otherCfg.WriteFile(otherAppPath); err != nil {
		t.Fatalf("WriteFile(other app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    mainConfigPath,
		AppConfigPath: defaultAppPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if err := server.state.RegisterAppConfigPath(otherAppPath); err != nil {
		t.Fatalf("RegisterAppConfigPath() error = %v", err)
	}

	body := server.resourceExposureHTML()
	for _, want := range []string{"first-app", "second-app", "<th>Resources</th><td>2</td>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("resource exposure body missing %q:\n%s", want, body)
		}
	}
}

func TestProductPagesDoNotRenderSaveFormsWhenConfigLoadFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := os.WriteFile(configPath, []byte(":\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	if err := os.WriteFile(appConfigPath, []byte(":\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, newUIRequest(http.MethodGet, server.StartupURL(), nil))
	cookie := login.Result().Cookies()[0]

	settings := authenticatedGET(t, server, cookie, "/settings")
	if strings.Contains(settings, `value="main_config_save"`) || !strings.Contains(settings, `value="main_init"`) {
		t.Fatalf("settings body did not fail closed:\n%s", settings)
	}
	resources := authenticatedGET(t, server, cookie, "/resources")
	if strings.Contains(resources, `value="app_config_save"`) || !strings.Contains(resources, `value="app_init"`) {
		t.Fatalf("resources body did not fail closed:\n%s", resources)
	}
}

func TestRunJobSavesAppConfigAndRecordsTypedResult(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                              {"app_config_save"},
		"app_config_path":                        {appConfigPath},
		"app_name":                               {"review-app"},
		"app_domains":                            {"app.example.com\nwww.example.com"},
		"app_certificate_email":                  {"ops@example.com"},
		"app_acme_challenge":                     {appconfig.ACMEChallengeHTTP01},
		"app_target_mode":                        {string(appconfig.ModeListen)},
		"app_listen":                             {"127.0.0.1:18001"},
		"access_mode":                            {string(appconfig.AccessModePublic)},
		"public_risk_confirmed":                  {"on"},
		"origin_mode":                            {string(appconfig.OriginProtectionModeNone)},
		"direct_origin_risk_confirmed":           {"on"},
		"service_exec_start":                     {"/opt/review-app/review-app --listen 127.0.0.1:18001"},
		"service_working_directory":              {"/opt/review-app"},
		"nginx_client_max_body_size":             {"20m"},
		"nginx_http2":                            {"on"},
		"proxy_read_timeout":                     {"600s"},
		"proxy_send_timeout":                     {"600s"},
		"goaccess_language":                      {appconfig.NginxGoAccessLanguageEnglish},
		"goaccess_log_format":                    {appconfig.NginxGoAccessLogFormatEnhanced},
		"app_lego_source_mode":                   {config.PackageSourceModeDirect},
		"app_package_probe_reachability_timeout": {config.DefaultPackageProbeReachabilityTimeout},
		"app_package_probe_artifact_timeout":     {config.DefaultPackageProbeArtifactTimeout},
		"app_platform_arch":                      {config.ArchAMD64},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	result, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if result.Kind != domain.JobKindAppConfigSave || record.Status != domain.JobStatusSucceeded {
		t.Fatalf("result=%#v record=%#v, want app_config_save succeeded", result, record)
	}
	if strings.Contains(record.ResultSummary, "placeholder") {
		t.Fatalf("ResultSummary = %q, want non-placeholder typed result", record.ResultSummary)
	}
	loaded, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		t.Fatalf("LoadFile(app config) error = %v", err)
	}
	if loaded.App.Name != "review-app" || loaded.Access.AccessMode != appconfig.AccessModePublic {
		t.Fatalf("loaded app config = %#v, want saved typed form values", loaded)
	}
	assertJobConfigSnapshot(t, record, "review-app")
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if !eventsContain(events, "job started") || !eventsContain(events, "app config saved") || !eventsContain(events, "result detail: app config path: "+appConfigPath) {
		t.Fatalf("events = %#v, want started, completed, and safe result details", events)
	}
}

func TestRunJobRejectsPrivateClientAppConfigSaveFromUI(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := validPublicAppForm(appConfigPath)
	form.Set("operation", "app_config_save")
	form.Set("access_mode", string(appconfig.AccessModePrivateClient))
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))

	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed || !strings.Contains(record.ErrorSummary, "reserved for P1") {
		t.Fatalf("record = %#v, want failed private_client UI rejection", record)
	}
	wantRetry := workflow.ShellCommand("lanpanel", "ui", "--app-config", appConfigPath)
	if record.RetryCommand != wantRetry {
		t.Fatalf("RetryCommand = %q, want %q", record.RetryCommand, wantRetry)
	}
	if _, err := os.Stat(appConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("app config stat error = %v, want not written", err)
	}
}

func TestRunJobAppConfigSaveAllowsManualRiskConfirmations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		removeForm string
		want       string
	}{
		{
			name:       "public risk",
			removeForm: "public_risk_confirmed",
			want:       "public-app-risk",
		},
		{
			name:       "direct origin risk",
			removeForm: "direct_origin_risk_confirmed",
			want:       "direct-origin-risk",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
			existing := appconfig.ExampleConfig()
			existing.App.Name = "existing-app"
			if err := existing.WriteFile(appConfigPath); err != nil {
				t.Fatalf("WriteFile(existing app config) error = %v", err)
			}
			server, err := NewServer(Options{
				Addr:          "127.0.0.1:18080",
				Version:       "test",
				StateDir:      secureStateDir(t),
				AppConfigPath: appConfigPath,
				Now:           fixedNow,
			})
			if err != nil {
				t.Fatalf("NewServer() error = %v", err)
			}
			form := validPublicAppForm(appConfigPath)
			form.Del(tt.removeForm)
			request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(loginCookie(t, server))

			result, record, err := server.runJob(request)
			if err != nil {
				t.Fatalf("runJob() error = %v", err)
			}
			if record.Status != domain.JobStatusSucceeded || record.ErrorSummary != "" {
				t.Fatalf("record = %#v, want successful manual-plan save", record)
			}
			if result.ExposurePlan == nil || result.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionManual {
				t.Fatalf("ExposurePlan = %#v, want manual save plan", result.ExposurePlan)
			}
			if got := strings.Join(result.ExposurePlan.Decision.RequiredConfirmations, ","); got != tt.want {
				t.Fatalf("RequiredConfirmations = %q, want %q", got, tt.want)
			}
			loaded, err := appconfig.LoadFile(appConfigPath)
			if err != nil {
				t.Fatalf("LoadFile(app config) error = %v", err)
			}
			if loaded.App.Name != "review-app" {
				t.Fatalf("loaded app name = %q, want saved form config", loaded.App.Name)
			}
		})
	}
}

func TestRunJobAppConfigSavePreservesFieldsOutsideForm(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	buffering := false
	requestBuffering := false
	enabled := true
	cfg := appconfig.ExampleConfig()
	cfg.App.Name = "review-app"
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	cfg.Nginx.Proxy.Buffering = &buffering
	cfg.Nginx.Proxy.RequestBuffering = &requestBuffering
	cfg.Nginx.StaticLocations = []appconfig.NginxStaticLocationConfig{{
		Path:         "/static/",
		Alias:        "/opt/review-app/web/static/",
		CacheControl: "public, max-age=2592000",
	}}
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:         &enabled,
			Provider:        appconfig.RealIPProviderEdgeOne,
			RefreshInterval: "72h",
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-prod",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
		"edgeone-next": {
			Enabled:         &enabled,
			Provider:        appconfig.RealIPProviderEdgeOne,
			RefreshInterval: "72h",
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-next",
				EnvFile: "/etc/lanpanel/realip/edgeone-next.env",
			},
		},
	}
	if err := cfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                              {"app_config_save"},
		"app_config_path":                        {appConfigPath},
		"app_name":                               {"review-app"},
		"app_domains":                            {"app.example.com\nwww.app.example.com"},
		"app_certificate_email":                  {"ops@example.com"},
		"app_acme_challenge":                     {appconfig.ACMEChallengeDNS01},
		"app_target_mode":                        {string(appconfig.ModeListen)},
		"app_listen":                             {"127.0.0.1:18001"},
		"access_mode":                            {string(appconfig.AccessModePublic)},
		"public_risk_confirmed":                  {"on"},
		"origin_mode":                            {string(appconfig.OriginProtectionModeEdgeOne)},
		"edgeone_profile":                        {"edgeone-prod"},
		"edgeone_profile_enabled":                {"on"},
		"edgeone_zone_id":                        {"zone-prod"},
		"edgeone_env_file":                       {"/etc/lanpanel/realip/edgeone-prod.env"},
		"edgeone_refresh_interval":               {"24h"},
		"service_exec_start":                     {"/opt/review-app/review-app --listen 127.0.0.1:18001"},
		"service_working_directory":              {"/opt/review-app"},
		"nginx_client_max_body_size":             {"20m"},
		"nginx_http2":                            {"on"},
		"proxy_connect_timeout":                  {"30s"},
		"proxy_read_timeout":                     {"600s"},
		"proxy_send_timeout":                     {"600s"},
		"app_lego_source_mode":                   {config.PackageSourceModeDirect},
		"app_package_probe_reachability_timeout": {config.DefaultPackageProbeReachabilityTimeout},
		"app_package_probe_artifact_timeout":     {config.DefaultPackageProbeArtifactTimeout},
		"app_platform_arch":                      {config.ArchAMD64},
		"app_dns01_provider":                     {"tencentcloud"},
		"app_dns01_env_file":                     {"/etc/lanpanel/dns01/tencentcloud.env"},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	result, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if result.Kind != domain.JobKindAppConfigSave || record.Status != domain.JobStatusSucceeded {
		t.Fatalf("result=%#v record=%#v, want app_config_save succeeded", result, record)
	}
	loaded, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		t.Fatalf("LoadFile(app config) error = %v", err)
	}
	if len(loaded.Nginx.StaticLocations) != 1 || loaded.Nginx.StaticLocations[0].Path != "/static/" {
		t.Fatalf("StaticLocations = %#v, want preserved static location", loaded.Nginx.StaticLocations)
	}
	if loaded.Nginx.Proxy.Buffering == nil || *loaded.Nginx.Proxy.Buffering {
		t.Fatalf("Proxy.Buffering = %#v, want preserved false", loaded.Nginx.Proxy.Buffering)
	}
	if loaded.Nginx.Proxy.RequestBuffering == nil || *loaded.Nginx.Proxy.RequestBuffering {
		t.Fatalf("Proxy.RequestBuffering = %#v, want preserved false", loaded.Nginx.Proxy.RequestBuffering)
	}
	if _, ok := loaded.RealIP.Profiles["edgeone-next"]; !ok {
		t.Fatalf("RealIP.Profiles = %#v, want preserved secondary profile", loaded.RealIP.Profiles)
	}
	if loaded.RealIP.Profiles["edgeone-prod"].EffectiveRefreshInterval() != "24h" {
		t.Fatalf("edgeone-prod refresh interval = %q, want updated form value", loaded.RealIP.Profiles["edgeone-prod"].EffectiveRefreshInterval())
	}
}

func TestRunJobFailurePersistsSnapshotErrorWhenSourceCannotBeValidated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appConfigPath := filepath.Join(dir, "missing-app.yaml")
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":       {"app_config_save"},
		"app_config_path": {appConfigPath},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if record.ConfigSnapshotRef != "" {
		t.Fatalf("ConfigSnapshotRef = %q, want empty ref for failed snapshot", record.ConfigSnapshotRef)
	}
	if !strings.Contains(record.ErrorSummary, "config snapshot failed") || !strings.Contains(record.ErrorSummary, "missing-app.yaml") {
		t.Fatalf("ErrorSummary = %q, want snapshot failure recorded", record.ErrorSummary)
	}
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if !eventsContainStatus(events, domain.DiagnosticStatusFail) {
		t.Fatalf("events = %#v, want fail-fast failure event", events)
	}
}

func TestRunJobRejectsConfigPathOutsideUIScope(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	if err := appconfig.ExampleConfig().WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	secretPath := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secretPath, []byte("root:secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	for _, tt := range []struct {
		name string
		form url.Values
		want string
	}{
		{
			name: "main",
			form: url.Values{"operation": {"main_verify"}, "config_path": {secretPath}},
			want: "main config path must match configured UI path",
		},
		{
			name: "app",
			form: url.Values{"operation": {"app_verify"}, "app_config_path": {secretPath}},
			want: "app config path must be the configured UI path",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(tt.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookie)
			_, _, err := server.runJob(request)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runJob() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRunJobConfigWritesRejectSymlinkTargets(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		form        func(mainConfigPath string, appConfigPath string) url.Values
		mainSymlink bool
		appSymlink  bool
		wantKind    domain.JobKind
	}{
		{
			name: "main init",
			form: func(mainConfigPath string, _ string) url.Values {
				return url.Values{"operation": {"main_init"}, "config_path": {mainConfigPath}}
			},
			mainSymlink: true,
			wantKind:    domain.JobKindConfigSave,
		},
		{
			name: "main config save",
			form: func(mainConfigPath string, _ string) url.Values {
				return validMainForm(mainConfigPath)
			},
			mainSymlink: true,
			wantKind:    domain.JobKindConfigSave,
		},
		{
			name: "app init",
			form: func(_ string, appConfigPath string) url.Values {
				return url.Values{"operation": {"app_init"}, "app_config_path": {appConfigPath}}
			},
			appSymlink: true,
			wantKind:   domain.JobKindAppInit,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			mainConfigPath := filepath.Join(dir, "lanpanel.yaml")
			appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
			linkPath := mainConfigPath
			if tt.mainSymlink {
				writeSentinelSymlink(t, mainConfigPath)
			} else if err := config.WriteExampleFile(mainConfigPath); err != nil {
				t.Fatalf("WriteExampleFile(main config) error = %v", err)
			}
			if tt.appSymlink {
				linkPath = appConfigPath
				writeSentinelSymlink(t, appConfigPath)
			} else if err := appconfig.WriteExampleFile(appConfigPath); err != nil {
				t.Fatalf("WriteExampleFile(app config) error = %v", err)
			}

			server, err := NewServer(Options{
				Addr:          "127.0.0.1:18080",
				Version:       "test",
				StateDir:      secureStateDir(t),
				ConfigPath:    mainConfigPath,
				AppConfigPath: appConfigPath,
				Now:           fixedNow,
			})
			if err != nil {
				t.Fatalf("NewServer() error = %v", err)
			}
			cookie := loginCookie(t, server)
			form := tt.form(mainConfigPath, appConfigPath)
			request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookie)

			_, record, err := server.runJob(request)
			if err != nil {
				t.Fatalf("runJob() error = %v", err)
			}
			if record.Kind != tt.wantKind || record.Status != domain.JobStatusFailed {
				t.Fatalf("record = %#v, want failed %s record", record, tt.wantKind)
			}
			if !strings.Contains(record.ErrorSummary, "must not be a symlink") {
				t.Fatalf("ErrorSummary = %q, want symlink refusal", record.ErrorSummary)
			}
			assertSentinelSymlinkRetained(t, linkPath)
			if record.ConfigSnapshotRef != "" {
				t.Fatalf("ConfigSnapshotRef = %q, want empty ref for refused symlink source", record.ConfigSnapshotRef)
			}
		})
	}
}

func TestDiagnosticsHTMLRendersMetadata(t *testing.T) {
	t.Parallel()

	body := diagnosticsHTML([]domain.DiagnosticItem{{
		ID:               "nginx-config",
		Status:           domain.DiagnosticStatusFail,
		Scope:            domain.DiagnosticScopeInstance,
		Severity:         domain.DiagnosticSeverityCritical,
		EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
		ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
		BlocksActivation: true,
		Summary:          "nginx -t failed",
	}})
	for _, want := range []string{"Scope", "Severity", "Evidence", "Owner", "Blocks activation", "instance", "critical", "runtime_probe", "local_admin", "true"} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnosticsHTML() = %q, want %q", body, want)
		}
	}
}

func TestRunJobDelegatesHostChangingOperationsToHostWorkflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	appCfg := appconfig.ExampleConfig()
	appCfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	appCfg.DNS01.Provider = "tencentcloud"
	appCfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	appCfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	appCfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	appCfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	appCfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-123456",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := appCfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	hostWorkflow := &fakeHostWorkflow{}
	server, err := NewServer(Options{
		Addr:                 "127.0.0.1:18080",
		Version:              "test",
		StateDir:             secureStateDir(t),
		ConfigPath:           configPath,
		AppConfigPath:        appConfigPath,
		HostWorkflow:         hostWorkflow,
		ExposureObservations: manualOriginProtectionObservation(),
		Now:                  fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	cookie := loginCookie(t, server)
	for _, tt := range []struct {
		operation    string
		wantKind     domain.JobKind
		wantCall     string
		wantResource bool
		wantSnapshot string
	}{
		{operation: "main_deploy", wantKind: domain.JobKindDeploy, wantCall: "main:" + configPath, wantSnapshot: "server_url"},
		{operation: "app_deploy", wantKind: domain.JobKindAppDeploy, wantCall: "app:" + appConfigPath, wantResource: true, wantSnapshot: "edgeone-prod"},
		{operation: "realip_refresh", wantKind: domain.JobKindRealIPRefresh, wantCall: "realip:" + appConfigPath + ":edgeone-prod", wantResource: true, wantSnapshot: "edgeone-prod"},
	} {
		form := url.Values{
			"operation":       {tt.operation},
			"config_path":     {configPath},
			"app_config_path": {appConfigPath},
			"profile":         {"edgeone-prod"},
		}
		if tt.operation == "app_deploy" || tt.operation == "realip_refresh" {
			form.Set("confirmation", "origin-protection-manual")
		}
		request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		result, record, err := server.runJob(request)
		if err != nil {
			t.Fatalf("%s runJob() error = %v", tt.operation, err)
		}
		if result.Kind != tt.wantKind || record.Status != domain.JobStatusSucceeded || record.RetryCommand == "" || len(record.ModifiedPaths) == 0 {
			t.Fatalf("%s result=%#v record=%#v, want delegated succeeded record with retry and paths", tt.operation, result, record)
		}
		if record.CheckpointRef.Kind != domain.ActivationRefCheckpoint || record.CheckpointRef.Path == "" {
			t.Fatalf("%s CheckpointRef = %#v, want JSON checkpoint", tt.operation, record.CheckpointRef)
		}
		if tt.operation == "realip_refresh" && !strings.Contains(record.RetryCommand, "--config "+appConfigPath) {
			t.Fatalf("%s RetryCommand = %q, want app config path", tt.operation, record.RetryCommand)
		}
		if !hostWorkflow.hasCall(tt.wantCall) {
			t.Fatalf("%s host workflow calls = %v, missing %q", tt.operation, hostWorkflow.calls, tt.wantCall)
		}
		if tt.wantResource && len(record.ResourceIDs) != 1 {
			t.Fatalf("%s ResourceIDs = %#v, want one app resource id", tt.operation, record.ResourceIDs)
		}
		assertJobConfigSnapshot(t, record, tt.wantSnapshot)
		if tt.operation == "app_deploy" || tt.operation == "realip_refresh" {
			events, err := server.state.ListEvents(record.ID)
			if err != nil {
				t.Fatalf("%s ListEvents() error = %v", tt.operation, err)
			}
			if !eventsContain(events, "manual confirmation submitted: origin-protection-manual") {
				t.Fatalf("%s events = %#v, want manual confirmation event", tt.operation, events)
			}
			if result.ExposurePlan == nil || len(result.ExposurePlan.Access.ManualConfirmations) != 1 {
				t.Fatalf("%s ExposurePlan = %#v, want structured manual confirmation", tt.operation, result.ExposurePlan)
			}
			manual := result.ExposurePlan.Access.ManualConfirmations[0]
			if manual.Reason != "origin_firewall_confirmed" || manual.Actor.Source != domain.ActorSourceUI || manual.ConfirmedAt == "" {
				t.Fatalf("%s ManualConfirmation = %#v", tt.operation, manual)
			}
		}
	}
}

func TestRunJobRejectsUnknownManualConfirmation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	appCfg := appconfig.ExampleConfig()
	if err := appCfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":       {"app_deploy"},
		"app_config_path": {appConfigPath},
		"confirmation":    {"token-with-secret-shape hskey-auth-abc123"},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))

	_, _, err = server.runJob(request)
	if err == nil || !strings.Contains(err.Error(), "confirmation is not allowed for this operation") {
		t.Fatalf("runJob() error = %v, want unknown confirmation rejection", err)
	}
	records, listErr := server.state.ListRecords()
	if listErr != nil {
		t.Fatalf("ListRecords() error = %v", listErr)
	}
	if len(records) != 0 {
		t.Fatalf("records = %#v, want no persisted job for rejected confirmation", records)
	}
}

func TestRunJobRejectsStaleManualConfirmationWithoutRecording(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	if err := appconfig.ExampleConfig().WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		HostWorkflow:  &fakeHostWorkflow{},
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":       {"app_deploy"},
		"config_path":     {configPath},
		"app_config_path": {appConfigPath},
		"confirmation":    {"origin-protection-manual"},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))

	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed || !strings.Contains(record.ErrorSummary, "rejected manual confirmations") {
		t.Fatalf("record = %#v, want stale confirmation failure", record)
	}
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if eventsContain(events, "manual confirmation submitted: origin-protection-manual") {
		t.Fatalf("events = %#v, want no manual confirmation event for stale confirmation", events)
	}
}

func TestRunJobMainDeployUsesSavedConfigInsteadOfSubmittedEditForm(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	cfg := config.ExampleConfig()
	cfg.Default.ServerURL = "https://saved.example.com"
	if err := cfg.WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	hostWorkflow := &fakeHostWorkflow{}
	server, err := NewServer(Options{
		Addr:         "127.0.0.1:18080",
		Version:      "test",
		StateDir:     secureStateDir(t),
		ConfigPath:   configPath,
		HostWorkflow: hostWorkflow,
		Now:          fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	form := validMainForm(configPath)
	form.Set("operation", "main_deploy")
	form.Set("server_url", "https://submitted.example.com")
	form.Set("base_domain", "tailnet.example.net")
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	result, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if result.Kind != domain.JobKindDeploy || record.Status != domain.JobStatusSucceeded {
		t.Fatalf("result=%#v record=%#v, want main deploy succeeded", result, record)
	}
	if !hostWorkflow.hasCall("main:" + configPath) {
		t.Fatalf("host workflow calls = %v, missing main deploy", hostWorkflow.calls)
	}
	loaded, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("LoadFile(main config) error = %v", err)
	}
	if loaded.Default.ServerURL != "https://saved.example.com" {
		t.Fatalf("server_url = %q, want saved config value", loaded.Default.ServerURL)
	}
	assertJobConfigSnapshot(t, record, "saved.example.com")
}

func TestRunJobAppDeployUsesSavedConfigInsteadOfSubmittedEditForm(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.App.Name = "saved-app"
	cfg.App.Domains = []string{"saved.example.com"}
	if err := cfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	hostWorkflow := &fakeHostWorkflow{}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		HostWorkflow:  hostWorkflow,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	form := validPublicAppForm(appConfigPath)
	form.Set("operation", "app_deploy")
	form.Set("app_name", "submitted-app")
	form.Set("app_domains", "submitted.example.com")
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	result, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if result.Kind != domain.JobKindAppDeploy || record.Status != domain.JobStatusSucceeded {
		t.Fatalf("result=%#v record=%#v, want app deploy succeeded", result, record)
	}
	if !hostWorkflow.hasCall("app:" + appConfigPath) {
		t.Fatalf("host workflow calls = %v, missing app deploy", hostWorkflow.calls)
	}
	loaded, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		t.Fatalf("LoadFile(app config) error = %v", err)
	}
	if loaded.App.Name != "saved-app" || strings.Join(loaded.App.Domains, ",") != "saved.example.com" {
		t.Fatalf("loaded app config = %#v, want saved config values", loaded)
	}
	assertJobConfigSnapshot(t, record, "saved-app")
}

func TestRunJobRequiresExposureConfirmationBeforeHostWorkflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	appCfg := appconfig.ExampleConfig()
	appCfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	appCfg.DNS01.Provider = "tencentcloud"
	appCfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	appCfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	appCfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	appCfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	appCfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-123456",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := appCfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	hostWorkflow := &fakeHostWorkflow{}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		HostWorkflow:  hostWorkflow,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	cookie := loginCookie(t, server)
	for _, tt := range []struct {
		operation string
		wantKind  domain.JobKind
		wantCall  string
	}{
		{operation: "app_deploy", wantKind: domain.JobKindAppDeploy, wantCall: "app:" + appConfigPath},
		{operation: "realip_refresh", wantKind: domain.JobKindRealIPRefresh, wantCall: "realip:" + appConfigPath + ":edgeone-prod"},
	} {
		form := url.Values{
			"operation":       {tt.operation},
			"config_path":     {configPath},
			"app_config_path": {appConfigPath},
			"profile":         {"edgeone-prod"},
		}
		request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		result, record, err := server.runJob(request)
		if err != nil {
			t.Fatalf("%s runJob() error = %v", tt.operation, err)
		}
		if result.Kind != "" {
			t.Fatalf("%s result = %#v, want empty failed UI result", tt.operation, result)
		}
		if record.Kind != tt.wantKind || record.Status != domain.JobStatusFailed || !strings.Contains(record.ErrorSummary, "exposure plan is blocked") {
			t.Fatalf("%s record = %#v, want failed exposure plan block record", tt.operation, record)
		}
		if hostWorkflow.hasCall(tt.wantCall) {
			t.Fatalf("%s host workflow calls = %#v, must not include %q", tt.operation, hostWorkflow.calls, tt.wantCall)
		}
	}
}

func TestRunJobFailureRecordsAppResourceIDs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	appCfg := appconfig.ExampleConfig()
	appCfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	appCfg.DNS01.Provider = "tencentcloud"
	appCfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	appCfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	appCfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	appCfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	appCfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-123456",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := appCfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		HostWorkflow:  &fakeHostWorkflow{appErr: errors.New("app deploy failed"), realIPErr: errors.New("realip refresh failed")},
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	cookie := loginCookie(t, server)
	for _, tt := range []struct {
		operation string
		wantKind  domain.JobKind
	}{
		{operation: "app_deploy", wantKind: domain.JobKindAppDeploy},
		{operation: "realip_refresh", wantKind: domain.JobKindRealIPRefresh},
	} {
		form := url.Values{
			"operation":       {tt.operation},
			"config_path":     {configPath},
			"app_config_path": {appConfigPath},
			"profile":         {"edgeone-prod"},
			"confirmation":    {"origin-protection-manual"},
		}
		request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		result, record, err := server.runJob(request)
		if err != nil {
			t.Fatalf("%s runJob() error = %v", tt.operation, err)
		}
		if result.Kind != "" {
			t.Fatalf("%s result = %#v, want empty result returned for failed UI job", tt.operation, result)
		}
		if record.Kind != tt.wantKind || record.Status != domain.JobStatusFailed || len(record.ResourceIDs) != 1 {
			t.Fatalf("%s record = %#v, want failed record with one resource id", tt.operation, record)
		}
		assertJobConfigSnapshot(t, record, "edgeone-prod")
	}
}

func TestRunJobFailureOmitsRawCommandOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(configPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	appCfg := appconfig.ExampleConfig()
	appCfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	appCfg.DNS01.Provider = "tencentcloud"
	appCfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	appCfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	appCfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	appCfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	appCfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-123456",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := appCfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:                 "127.0.0.1:18080",
		Version:              "test",
		StateDir:             secureStateDir(t),
		ConfigPath:           configPath,
		AppConfigPath:        appConfigPath,
		HostWorkflow:         &fakeHostWorkflow{appErr: errors.New("nginx failed; output: raw stdout line with upstream host")},
		ExposureObservations: manualOriginProtectionObservation(),
		Now:                  fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	form := url.Values{
		"operation":       {"app_deploy"},
		"config_path":     {configPath},
		"app_config_path": {appConfigPath},
		"profile":         {"edgeone-prod"},
		"confirmation":    {"origin-protection-manual"},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	result, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if result.Kind != "" || record.Status != domain.JobStatusFailed {
		t.Fatalf("result = %#v record = %#v, want failed persisted job and empty returned result", result, record)
	}
	for _, text := range []string{record.ErrorSummary, record.ResultSummary} {
		if strings.Contains(text, "output:") || strings.Contains(text, "raw stdout line") {
			t.Fatalf("record text leaked raw command output: %#v", record)
		}
	}
	if !strings.Contains(record.ErrorSummary, "command output omitted") {
		t.Fatalf("ErrorSummary = %q, want omitted command output marker", record.ErrorSummary)
	}
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "output:") || strings.Contains(event.Message, "raw stdout line") {
			t.Fatalf("event leaked raw command output: %#v", event)
		}
	}
}

func TestRunJobVerifyFailuresPersistTypedResultAndRetry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := os.WriteFile(configPath, []byte("api_version: wrong\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}
	if err := os.WriteFile(appConfigPath, []byte("api_version: wrong\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	for _, tt := range []struct {
		operation string
		wantKind  domain.JobKind
		wantRetry string
	}{
		{operation: "main_verify", wantKind: domain.JobKindVerify, wantRetry: workflow.ShellCommand("lanpanel", "verify", "--config", configPath)},
		{operation: "app_verify", wantKind: domain.JobKindAppVerify, wantRetry: workflow.ShellCommand("lanpanel", "app", "verify", "--config", appConfigPath)},
	} {
		form := url.Values{
			"operation":       {tt.operation},
			"config_path":     {configPath},
			"app_config_path": {appConfigPath},
		}
		request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		result, record, err := server.runJob(request)
		if err != nil {
			t.Fatalf("%s runJob() error = %v", tt.operation, err)
		}
		if result.Kind != tt.wantKind || result.Status != domain.JobStatusFailed || len(result.Diagnostics) == 0 {
			t.Fatalf("%s result = %#v, want typed failed verify result with diagnostics", tt.operation, result)
		}
		if record.Kind != tt.wantKind || record.Status != domain.JobStatusFailed || record.RetryCommand != tt.wantRetry || record.ResultSummary == "" {
			t.Fatalf("%s record = %#v, want failed record with retry %q", tt.operation, record, tt.wantRetry)
		}
		events, err := server.state.ListEvents(record.ID)
		if err != nil {
			t.Fatalf("%s ListEvents() error = %v", tt.operation, err)
		}
		if !eventsContain(events, result.Summary) {
			t.Fatalf("%s events = %#v, want result summary %q", tt.operation, events, result.Summary)
		}
	}
}

func TestRunJobPreWorkflowFailuresAreTyped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	if err := config.WriteExampleFile(configPath); err != nil {
		t.Fatalf("WriteExampleFile(main config) error = %v", err)
	}
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := os.WriteFile(appConfigPath, []byte("api_version: wrong\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		ConfigPath:    configPath,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	for _, tt := range []struct {
		name     string
		form     url.Values
		wantKind domain.JobKind
	}{
		{
			name: "main config save parse",
			form: url.Values{
				"operation":              {"main_config_save"},
				"config_path":            {configPath},
				"headscale_metrics_port": {"bad-port"},
			},
			wantKind: domain.JobKindConfigSave,
		},
		{
			name: "app config save existing invalid config",
			form: url.Values{
				"operation":       {"app_config_save"},
				"app_config_path": {appConfigPath},
			},
			wantKind: domain.JobKindAppConfigSave,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(tt.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookie)
			_, record, err := server.runJob(request)
			if err != nil {
				t.Fatalf("runJob() error = %v", err)
			}
			if record.Kind != tt.wantKind || record.Status != domain.JobStatusFailed || record.ResultSummary == "" || record.RetryCommand == "" || record.RetryCommand == "not_applicable" {
				t.Fatalf("record = %#v, want typed failed pre-workflow record with retry", record)
			}
			events, err := server.state.ListEvents(record.ID)
			if err != nil {
				t.Fatalf("ListEvents() error = %v", err)
			}
			if !eventsContainStatus(events, domain.DiagnosticStatusFail) {
				t.Fatalf("events = %#v, want failed progress event", events)
			}
		})
	}
}

func TestRunJobPersistsSafeResultFieldsAsEvents(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{
		Addr:              "127.0.0.1:18080",
		Version:           "test",
		StateDir:          secureStateDir(t),
		PreAuthKeyCreator: stubPreAuthKeyCreator{key: "hskey-auth-history-secret"},
		Now:               fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	form := url.Values{
		"operation":    {"preauth_key_create"},
		"preauth_user": {"ops"},
		"preauth_ttl":  {"1h"},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	for _, want := range []string{"result detail: target user: ops", "result detail: expires at:", "result detail: fingerprint: sha256:"} {
		if !eventsContainPrefix(events, want) {
			t.Fatalf("events = %#v, want prefix %q", events, want)
		}
	}
	jobs := authenticatedGET(t, server, cookie, "/jobs")
	if strings.Contains(jobs, "hskey-auth-history-secret") {
		t.Fatalf("jobs page leaked preauth key:\n%s", jobs)
	}
	if !strings.Contains(jobs, "result detail: target user: ops") || !strings.Contains(jobs, "result detail: fingerprint: sha256:") {
		t.Fatalf("jobs page missing safe result details:\n%s", jobs)
	}
}

func TestRunJobUIOnlyFailuresPersistTypedRetryAndProgress(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{
		Addr:     "127.0.0.1:18080",
		Version:  "test",
		StateDir: secureStateDir(t),
		Now:      fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	for _, tt := range []struct {
		name     string
		form     url.Values
		wantKind domain.JobKind
	}{
		{
			name: "preauth ttl",
			form: url.Values{
				"operation":    {"preauth_key_create"},
				"preauth_user": {"ops"},
				"preauth_ttl":  {"not-a-duration"},
			},
			wantKind: domain.JobKindPreAuthKeyCreate,
		},
		{
			name: "browser auth create",
			form: url.Values{
				"operation":                    {"browser_auth_create"},
				"browser_auth_dir":             {filepath.Join(t.TempDir(), "browser-auth")},
				"browser_auth_id":              {"bad id"},
				"browser_auth_create_username": {"ops"},
				"browser_auth_create_password": {"secret-password"},
			},
			wantKind: domain.JobKindBrowserAuthCreate,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(tt.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(cookie)
			_, record, err := server.runJob(request)
			if err != nil {
				t.Fatalf("runJob() error = %v", err)
			}
			if record.Kind != tt.wantKind || record.Status != domain.JobStatusFailed || record.RetryCommand != workflow.ShellCommand("sudo", "lanpanel", "ui") || record.ResultSummary == "" {
				t.Fatalf("record = %#v, want typed failed UI-only job with retry", record)
			}
			events, err := server.state.ListEvents(record.ID)
			if err != nil {
				t.Fatalf("ListEvents() error = %v", err)
			}
			if !eventsContainStatus(events, domain.DiagnosticStatusFail) {
				t.Fatalf("events = %#v, want failed typed progress event", events)
			}
		})
	}
}

func TestRunJobBrowserAuthRotatePersistsResourceLink(t *testing.T) {
	dir := secureStateDir(t)
	managedDir := filepath.Join(dir, "browser-auth")
	restoreRoot, err := browserauth.UnsafeSetManagedRootForTest(managedDir)
	if err != nil {
		t.Fatalf("UnsafeSetManagedRootForTest() error = %v", err)
	}
	t.Cleanup(restoreRoot)
	restoreConfigRoot := appconfig.UnsafeSetBrowserAuthManagedRootForTest(managedDir)
	t.Cleanup(restoreConfigRoot)
	restoreChown := browserauth.UnsafeDisableManagedChownForTest()
	t.Cleanup(restoreChown)
	credential, err := browserauth.CreateManaged(managedDir, "review-app", "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateManaged() error = %v", err)
	}
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        credential.ID,
		HtpasswdPath:        credential.HtpasswdPath,
		Username:            credential.Username,
		PasswordFingerprint: credential.PasswordFingerprint,
	}
	if err := cfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
		ExposureObservations: exposure.AppObservations{
			BrowserAuthRuntimeStatus: domain.DiagnosticStatusPass,
			BrowserAuthMarkerStatus:  domain.DiagnosticStatusPass,
		},
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                    {"browser_auth_rotate"},
		"app_config_path":              {appConfigPath},
		"browser_auth_rotate_path":     {credential.HtpasswdPath},
		"browser_auth_rotate_username": {"admin"},
		"browser_auth_rotate_password": {"another correct horse battery staple"},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))

	result, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if result.ExposurePlan == nil || result.ExposurePlan.Operation != domain.ExposurePlanOperationBrowserAuthRotate {
		t.Fatalf("result=%#v record=%#v, want browser_auth_rotate exposure plan", result, record)
	}
	if len(record.ResourceIDs) != 1 || record.ResourceIDs[0] != result.ExposurePlan.Resource.ID {
		t.Fatalf("ResourceIDs = %#v, plan resource = %#v", record.ResourceIDs, result.ExposurePlan.Resource)
	}
	if record.Status != domain.JobStatusSucceeded || record.ResultSummary != "browser auth credential rotated" {
		t.Fatalf("record = %#v, want succeeded rotate record", record)
	}
}

func TestAppendResultFieldEventsKeepsCredentialFingerprintReadable(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	record, err := server.state.CreateJob(domain.JobRecord{
		Kind:          domain.JobKindBrowserAuthCreate,
		Status:        domain.JobStatusRunning,
		Actor:         testUIActor(),
		CheckpointRef: domain.NotApplicableActivationRef(),
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if err := server.appendResultFieldEvents(record.ID, []domain.ResultField{{Label: "password fingerprint", Value: "sha256:0011223344556677"}}, domain.DiagnosticStatusPass); err != nil {
		t.Fatalf("appendResultFieldEvents() error = %v", err)
	}
	events, err := server.state.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if !eventsContain(events, "result detail: credential fingerprint: sha256:0011223344556677") {
		t.Fatalf("events = %#v, want readable credential fingerprint", events)
	}
}

func TestBrowserAuthDeleteFailsWhenAppConfigCannotBeLoaded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	useActiveNginxSitesDirForTest(t, t.TempDir())
	appConfigPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := os.WriteFile(appConfigPath, []byte(":\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {appConfigPath},
		"browser_auth_delete_path": {filepath.Join(dir, "review-app.htpasswd")},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if !strings.Contains(record.ErrorSummary, "load app config before deleting browser auth credential") {
		t.Fatalf("record error = %q, want config load failure", record.ErrorSummary)
	}
	if strings.Contains(record.ErrorSummary, "browser auth htpasswd file unavailable") {
		t.Fatalf("record error = %q, delete validation ran before config reference check", record.ErrorSummary)
	}
	if record.ConfigSnapshotRef != "not_applicable" {
		t.Fatalf("ConfigSnapshotRef = %q, want not_applicable", record.ConfigSnapshotRef)
	}
}

func TestBrowserAuthDeleteRejectsCurrentAppReferenceBeforeFileValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	useActiveNginxSitesDirForTest(t, t.TempDir())
	appConfigPath := filepath.Join(dir, "current-app.yaml")
	target := "/etc/lanpanel/browser-auth/shared.htpasswd"

	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        "shared",
		HtpasswdPath:        target,
		Username:            "admin",
		PasswordFingerprint: "sha256:0011223344556677",
	}
	if err := cfg.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {appConfigPath},
		"browser_auth_delete_path": {target},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if !strings.Contains(record.ErrorSummary, "still referenced by an active or staged browser app") {
		t.Fatalf("record error = %q, want referenced credential failure", record.ErrorSummary)
	}
	if strings.Contains(record.ErrorSummary, "unavailable") {
		t.Fatalf("record error = %q, delete validation ran before current config reference check", record.ErrorSummary)
	}
}

func TestBrowserAuthDeleteAllowsCurrentAppUnreferencedCredential(t *testing.T) {
	dir := secureStateDir(t)
	useActiveNginxSitesDirForTest(t, t.TempDir())
	currentPath := filepath.Join(dir, "current-app.yaml")
	managedDir := filepath.Join(dir, "browser-auth")
	if err := os.Mkdir(managedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(managed browser auth dir) error = %v", err)
	}
	restoreRoot, err := browserauth.UnsafeSetManagedRootForTest(managedDir)
	if err != nil {
		t.Fatalf("UnsafeSetManagedRootForTest() error = %v", err)
	}
	t.Cleanup(restoreRoot)
	target := filepath.Join(managedDir, "shared.htpasswd")
	content := browserauth.Marker + "\nadmin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(managed htpasswd) error = %v", err)
	}

	current := appconfig.ExampleConfig()
	if err := current.WriteFile(currentPath); err != nil {
		t.Fatalf("WriteFile(current app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: currentPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {currentPath},
		"browser_auth_delete_path": {target},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusSucceeded {
		t.Fatalf("record status = %q, want succeeded; error = %q", record.Status, record.ErrorSummary)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed credential stat error = %v, want deleted file", err)
	}
}

func TestBrowserAuthDeleteRejectsSameDirectoryAppReference(t *testing.T) {
	dir := secureStateDir(t)
	useActiveNginxSitesDirForTest(t, t.TempDir())
	currentPath := filepath.Join(dir, "current-app.yaml")
	otherPath := filepath.Join(dir, "other-app.yaml")
	target := "/etc/lanpanel/browser-auth/shared.htpasswd"

	current := appconfig.ExampleConfig()
	if err := current.WriteFile(currentPath); err != nil {
		t.Fatalf("WriteFile(current app config) error = %v", err)
	}
	other := appconfig.ExampleConfig()
	other.App.Name = "other-app"
	other.Access.AccessMode = appconfig.AccessModeBrowser
	other.Access.PublicRiskConfirmed = false
	other.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        "shared",
		HtpasswdPath:        target,
		Username:            "admin",
		PasswordFingerprint: "sha256:0011223344556677",
	}
	if err := other.WriteFile(otherPath); err != nil {
		t.Fatalf("WriteFile(other app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: currentPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {currentPath},
		"browser_auth_delete_path": {target},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if !strings.Contains(record.ErrorSummary, "still referenced by an active or staged browser app") {
		t.Fatalf("record error = %q, want referenced credential failure", record.ErrorSummary)
	}
	if strings.Contains(record.ErrorSummary, "unavailable") {
		t.Fatalf("record error = %q, delete validation ran before same-directory reference check", record.ErrorSummary)
	}
}

func TestBrowserAuthDeleteRejectsKnownCrossDirectoryAppReference(t *testing.T) {
	dir := secureStateDir(t)
	useActiveNginxSitesDirForTest(t, t.TempDir())
	managedDir := filepath.Join(dir, "managed-browser-auth")
	if err := os.Mkdir(managedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(managed browser auth dir) error = %v", err)
	}
	restoreRoot, err := browserauth.UnsafeSetManagedRootForTest(managedDir)
	if err != nil {
		t.Fatalf("UnsafeSetManagedRootForTest() error = %v", err)
	}
	t.Cleanup(restoreRoot)

	target := filepath.Join(managedDir, "cross-dir.htpasswd")
	content := browserauth.Marker + "\nadmin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(managed htpasswd) error = %v", err)
	}

	currentDir := filepath.Join(dir, "current")
	otherDir := filepath.Join(dir, "other")
	if err := os.Mkdir(currentDir, 0o700); err != nil {
		t.Fatalf("Mkdir(current dir) error = %v", err)
	}
	if err := os.Mkdir(otherDir, 0o700); err != nil {
		t.Fatalf("Mkdir(other dir) error = %v", err)
	}
	currentPath := filepath.Join(currentDir, "current-app.yaml")
	otherPath := filepath.Join(otherDir, "other-app.yaml")
	current := appconfig.ExampleConfig()
	if err := current.WriteFile(currentPath); err != nil {
		t.Fatalf("WriteFile(current app config) error = %v", err)
	}
	other := appconfig.ExampleConfig()
	other.App.Name = "other-app"
	other.Access.AccessMode = appconfig.AccessModeBrowser
	other.Access.PublicRiskConfirmed = false
	other.Access.BrowserAuth.AuthBasicUserFile = target
	if err := other.WriteFile(otherPath); err != nil {
		t.Fatalf("WriteFile(other app config) error = %v", err)
	}

	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: currentPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if err := server.state.RegisterAppConfigPath(otherPath); err != nil {
		t.Fatalf("RegisterAppConfigPath(other) error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {currentPath},
		"browser_auth_delete_path": {target},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if !strings.Contains(record.ErrorSummary, "still referenced by an active or staged browser app") {
		t.Fatalf("record error = %q, want known cross-directory reference failure", record.ErrorSummary)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("managed credential stat error = %v, want preserved file", err)
	}
}

func TestBrowserAuthDeleteRejectsActiveNginxReference(t *testing.T) {
	dir := secureStateDir(t)
	sitesDir := t.TempDir()
	useActiveNginxSitesDirForTest(t, sitesDir)

	managedDir := filepath.Join(dir, "managed-browser-auth")
	if err := os.Mkdir(managedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(managed browser auth dir) error = %v", err)
	}
	restoreRoot, err := browserauth.UnsafeSetManagedRootForTest(managedDir)
	if err != nil {
		t.Fatalf("UnsafeSetManagedRootForTest() error = %v", err)
	}
	t.Cleanup(restoreRoot)

	target := filepath.Join(managedDir, "active.htpasswd")
	content := browserauth.Marker + "\nadmin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(managed htpasswd) error = %v", err)
	}
	site := "# Lanpanel-managed: app.name=deployed-app\nserver {\n    auth_basic_user_file " + target + ";\n}\n"
	if err := os.WriteFile(filepath.Join(sitesDir, "deployed-app"), []byte(site), 0o600); err != nil {
		t.Fatalf("WriteFile(active site) error = %v", err)
	}

	currentPath := filepath.Join(dir, "current-app.yaml")
	current := appconfig.ExampleConfig()
	if err := current.WriteFile(currentPath); err != nil {
		t.Fatalf("WriteFile(current app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: currentPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {currentPath},
		"browser_auth_delete_path": {target},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if !strings.Contains(record.ErrorSummary, "still referenced by an active or staged browser app") {
		t.Fatalf("record error = %q, want active Nginx reference failure", record.ErrorSummary)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("managed credential stat error = %v, want preserved file", err)
	}
}

func TestBrowserAuthDeleteRejectsStagedNginxReference(t *testing.T) {
	dir := secureStateDir(t)
	useActiveNginxSitesDirForTest(t, t.TempDir())

	managedDir := filepath.Join(dir, "managed-browser-auth")
	if err := os.Mkdir(managedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(managed browser auth dir) error = %v", err)
	}
	restoreRoot, err := browserauth.UnsafeSetManagedRootForTest(managedDir)
	if err != nil {
		t.Fatalf("UnsafeSetManagedRootForTest() error = %v", err)
	}
	t.Cleanup(restoreRoot)

	target := filepath.Join(managedDir, "staged.htpasswd")
	content := browserauth.Marker + "\nadmin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(managed htpasswd) error = %v", err)
	}

	currentPath := filepath.Join(dir, "current-app.yaml")
	current := appconfig.ExampleConfig()
	current.Nginx.GoAccess.Enabled = true
	current.Nginx.GoAccess.AuthBasicUserFile = target
	if err := current.WriteFile(currentPath); err != nil {
		t.Fatalf("WriteFile(current app config) error = %v", err)
	}
	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      secureStateDir(t),
		AppConfigPath: currentPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {currentPath},
		"browser_auth_delete_path": {target},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if !strings.Contains(record.ErrorSummary, "still referenced by an active or staged browser app") {
		t.Fatalf("record error = %q, want staged Nginx reference failure", record.ErrorSummary)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("managed credential stat error = %v, want preserved file", err)
	}
}

func TestBrowserAuthDeleteIgnoresHistoricalConfigSnapshots(t *testing.T) {
	dir := secureStateDir(t)
	useActiveNginxSitesDirForTest(t, t.TempDir())
	managedDir := filepath.Join(dir, "managed-browser-auth")
	if err := os.Mkdir(managedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(managed browser auth dir) error = %v", err)
	}
	restoreRoot, err := browserauth.UnsafeSetManagedRootForTest(managedDir)
	if err != nil {
		t.Fatalf("UnsafeSetManagedRootForTest() error = %v", err)
	}
	t.Cleanup(restoreRoot)

	target := filepath.Join(managedDir, "archived.htpasswd")
	content := browserauth.Marker + "\nadmin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(managed htpasswd) error = %v", err)
	}

	appConfigPath := filepath.Join(dir, "current-app.yaml")
	current := appconfig.ExampleConfig()
	if err := current.WriteFile(appConfigPath); err != nil {
		t.Fatalf("WriteFile(current app config) error = %v", err)
	}
	stateDir := secureStateDir(t)
	snapshotDir := filepath.Join(stateDir, "jobs", "job_historical", "config-snapshots")
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(snapshot dir) error = %v", err)
	}
	redactedSnapshot := []byte("api_version: lanpanel/app/v1alpha2\n[redacted] [redacted]\n")
	if err := os.WriteFile(filepath.Join(snapshotDir, "app-config.yaml"), redactedSnapshot, 0o600); err != nil {
		t.Fatalf("WriteFile(redacted app config snapshot) error = %v", err)
	}

	server, err := NewServer(Options{
		Addr:          "127.0.0.1:18080",
		Version:       "test",
		StateDir:      stateDir,
		AppConfigPath: appConfigPath,
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	form := url.Values{
		"operation":                {"browser_auth_delete"},
		"app_config_path":          {appConfigPath},
		"browser_auth_delete_path": {target},
	}
	request := newUIRequest(http.MethodPost, "/jobs/run", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCookie(t, server))
	_, record, err := server.runJob(request)
	if err != nil {
		t.Fatalf("runJob() error = %v", err)
	}
	if record.Status != domain.JobStatusSucceeded {
		t.Fatalf("record status = %q, want succeeded; error = %q", record.Status, record.ErrorSummary)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed credential stat error = %v, want deleted file", err)
	}
}

func TestOneTimeSecretRevealConsumesInMemoryOnly(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	cookie := loginCookie(t, server)
	sessionRequest := newUIRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(cookie)
	sessionFingerprint, ok := server.sessionFingerprintFromRequest(sessionRequest)
	if !ok {
		t.Fatal("sessionFingerprintFromRequest() = false")
	}
	server.secrets["secret_handle"] = oneTimeSecret{Label: "preauth key", Value: "hskey-auth-real", Fingerprint: "sha256:abc", RevealExpiresAt: fixedNow().Add(time.Minute), SessionIDFingerprint: sessionFingerprint}
	recorder := httptest.NewRecorder()
	handlerRequest := newUIRequest(http.MethodGet, "/jobs?secret=secret_handle", nil)
	handlerRequest.AddCookie(cookie)
	server.Handler().ServeHTTP(recorder, handlerRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("secret reveal status = %d body = %q, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "hskey-auth-real") {
		t.Fatalf("secret reveal body = %q, want one-time secret", recorder.Body.String())
	}
	assertNoStoreHeaders(t, recorder.Result(), "secret reveal")
	server.secrets["secret_handle"] = oneTimeSecret{Label: "preauth key", Value: "hskey-auth-real", Fingerprint: "sha256:abc", RevealExpiresAt: fixedNow().Add(time.Minute), SessionIDFingerprint: sessionFingerprint}
	request := newUIRequest(http.MethodGet, "/jobs?secret=secret_handle", nil)
	request.AddCookie(cookie)
	first := secretRevealHTML(server, request)
	if !strings.Contains(first, "hskey-auth-real") {
		t.Fatalf("first secret HTML = %q, want one-time secret", first)
	}
	second := secretRevealHTML(server, request)
	if strings.Contains(second, "hskey-auth-real") || !strings.Contains(second, "no longer available") {
		t.Fatalf("second secret HTML = %q, want consumed message without secret", second)
	}
}

func TestOneTimeSecretRevealRequiresHandleSessionAndTTL(t *testing.T) {
	t.Parallel()

	server, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: secureStateDir(t), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.mu.Lock()
	server.sessions["owner_session"] = session{CSRF: "owner_csrf", CreatedAt: fixedNow()}
	server.sessions["other_session"] = session{CSRF: "other_csrf", CreatedAt: fixedNow()}
	server.secrets["random_handle"] = oneTimeSecret{
		Label:                "browser auth password",
		Value:                "plain-password",
		Fingerprint:          "sha256:def",
		RevealExpiresAt:      fixedNow().Add(time.Minute),
		SessionIDFingerprint: fingerprintSecret("owner_session"),
	}
	server.secrets["expired_handle"] = oneTimeSecret{
		Label:                "preauth key",
		Value:                "expired-secret",
		Fingerprint:          "sha256:expired",
		RevealExpiresAt:      fixedNow().Add(-time.Second),
		SessionIDFingerprint: fingerprintSecret("owner_session"),
	}
	server.mu.Unlock()

	otherRequest := newUIRequest(http.MethodGet, "/jobs?secret=random_handle", nil)
	otherRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: "other_session"})
	other := secretRevealHTML(server, otherRequest)
	if strings.Contains(other, "plain-password") {
		t.Fatalf("other session reveal = %q, leaked secret", other)
	}

	jobIDRequest := newUIRequest(http.MethodGet, "/jobs?secret=job_visible", nil)
	jobIDRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: "owner_session"})
	jobID := secretRevealHTML(server, jobIDRequest)
	if strings.Contains(jobID, "plain-password") {
		t.Fatalf("job id reveal = %q, leaked secret through visible job id", jobID)
	}

	expiredRequest := newUIRequest(http.MethodGet, "/jobs?secret=expired_handle", nil)
	expiredRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: "owner_session"})
	expired := secretRevealHTML(server, expiredRequest)
	if strings.Contains(expired, "expired-secret") {
		t.Fatalf("expired reveal = %q, leaked expired secret", expired)
	}

	ownerRequest := newUIRequest(http.MethodGet, "/jobs?secret=random_handle", nil)
	ownerRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: "owner_session"})
	owner := secretRevealHTML(server, ownerRequest)
	if !strings.Contains(owner, "plain-password") {
		t.Fatalf("owner reveal = %q, want bound secret", owner)
	}
}

func TestNewServerRejectsInvalidStateStore(t *testing.T) {
	t.Parallel()

	dir := secureStateDir(t)
	statePath := filepath.Join(dir, "state-file")
	if err := os.WriteFile(statePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := NewServer(Options{Addr: "127.0.0.1:18080", Version: "test", StateDir: statePath, Now: fixedNow}); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("NewServer() error = %v, want state store startup failure", err)
	}
}

func TestSessionExpiresAndUnknownRoutes404(t *testing.T) {
	t.Parallel()

	now := fixedNow()
	server, err := NewServer(Options{
		Addr:       "127.0.0.1:18080",
		Version:    "test",
		StateDir:   secureStateDir(t),
		SessionTTL: time.Minute,
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, newUIRequest(http.MethodGet, server.StartupURL(), nil))
	cookie := login.Result().Cookies()[0]

	unknown := httptest.NewRecorder()
	unknownRequest := newUIRequest(http.MethodGet, "/does-not-exist", nil)
	unknownRequest.AddCookie(cookie)
	server.Handler().ServeHTTP(unknown, unknownRequest)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404", unknown.Code)
	}

	now = now.Add(2 * time.Minute)
	expired := httptest.NewRecorder()
	expiredRequest := newUIRequest(http.MethodGet, "/", nil)
	expiredRequest.AddCookie(cookie)
	server.Handler().ServeHTTP(expired, expiredRequest)
	if expired.Code != http.StatusUnauthorized {
		t.Fatalf("expired session status = %d, want 401", expired.Code)
	}
}

func assertJobConfigSnapshot(t *testing.T, record domain.JobRecord, wantContent string) {
	t.Helper()
	if record.ConfigSnapshotRef == "" || record.ConfigSnapshotRef == "not_applicable" {
		t.Fatalf("ConfigSnapshotRef = %q, want config snapshot path", record.ConfigSnapshotRef)
	}
	data, err := os.ReadFile(record.ConfigSnapshotRef)
	if err != nil {
		t.Fatalf("ReadFile(config snapshot) error = %v", err)
	}
	if !strings.Contains(string(data), wantContent) {
		t.Fatalf("config snapshot %s = %q, want content %q", record.ConfigSnapshotRef, data, wantContent)
	}
	info, err := os.Stat(record.ConfigSnapshotRef)
	if err != nil {
		t.Fatalf("Stat(config snapshot) error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config snapshot mode = %o, want 600", info.Mode().Perm())
	}
}

func assertResourceInstanceID(t *testing.T, stateDir string) {
	t.Helper()
	instancePath := filepath.Join(stateDir, "resources", "instance_id")
	info, err := os.Stat(instancePath)
	if err != nil {
		t.Fatalf("resource instance_id stat error = %v, want file at %s", err, instancePath)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("resource instance_id mode = %o, want 600", info.Mode().Perm())
	}
}

func waitForSingleRecordStatus(t *testing.T, server *Server, status domain.JobStatus) domain.JobRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		records, err := server.state.ListRecords()
		if err != nil {
			t.Fatalf("ListRecords() error = %v", err)
		}
		if len(records) == 1 && records[0].Status == status {
			return records[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("records = %#v, want single %s record", records, status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func validPublicAppForm(appConfigPath string) url.Values {
	return url.Values{
		"operation":                              {"app_config_save"},
		"app_config_path":                        {appConfigPath},
		"app_name":                               {"review-app"},
		"app_domains":                            {"app.example.com"},
		"app_certificate_email":                  {"ops@example.com"},
		"app_acme_challenge":                     {appconfig.ACMEChallengeHTTP01},
		"app_target_mode":                        {string(appconfig.ModeListen)},
		"app_listen":                             {"127.0.0.1:18001"},
		"access_mode":                            {string(appconfig.AccessModePublic)},
		"public_risk_confirmed":                  {"on"},
		"origin_mode":                            {string(appconfig.OriginProtectionModeNone)},
		"direct_origin_risk_confirmed":           {"on"},
		"service_exec_start":                     {"/opt/review-app/review-app --listen 127.0.0.1:18001"},
		"service_working_directory":              {"/opt/review-app"},
		"nginx_client_max_body_size":             {"20m"},
		"nginx_http2":                            {"on"},
		"proxy_read_timeout":                     {"600s"},
		"proxy_send_timeout":                     {"600s"},
		"goaccess_language":                      {appconfig.NginxGoAccessLanguageEnglish},
		"goaccess_log_format":                    {appconfig.NginxGoAccessLogFormatEnhanced},
		"app_lego_source_mode":                   {config.PackageSourceModeDirect},
		"app_package_probe_reachability_timeout": {config.DefaultPackageProbeReachabilityTimeout},
		"app_package_probe_artifact_timeout":     {config.DefaultPackageProbeArtifactTimeout},
		"app_platform_arch":                      {config.ArchAMD64},
	}
}

func validMainForm(configPath string) url.Values {
	return url.Values{
		"operation":                          {"main_config_save"},
		"config_path":                        {configPath},
		"server_url":                         {"https://hs.example.com"},
		"base_domain":                        {"tailnet.example.com"},
		"certificate_email":                  {"ops@example.com"},
		"acme_challenge":                     {config.ACMEChallengeHTTP01},
		"headscale_source_mode":              {config.PackageSourceModeDirect},
		"headscale_source_version":           {config.DefaultHeadscaleVersion},
		"headscale_metrics_port":             {"19090"},
		"lego_source_mode":                   {config.PackageSourceModeDirect},
		"package_probe_reachability_timeout": {config.DefaultPackageProbeReachabilityTimeout},
		"package_probe_artifact_timeout":     {config.DefaultPackageProbeArtifactTimeout},
		"platform_arch":                      {config.ArchAMD64},
	}
}

func writeSentinelSymlink(t *testing.T, linkPath string) {
	t.Helper()
	target := linkPath + ".target"
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
}

func assertSentinelSymlinkRetained(t *testing.T, linkPath string) {
	t.Helper()
	target := linkPath + ".target"
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target) error = %v", err)
	}
	if string(got) != "sentinel" {
		t.Fatalf("target content = %q, want sentinel", got)
	}
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Lstat(link) error = %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link mode = %v, want symlink retained", info.Mode())
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
}

func secureStateDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	dir, err := os.MkdirTemp(home, ".lanpanel-ui-state-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	return dir
}

func authenticatedGET(t *testing.T, server *Server, cookie *http.Cookie, path string) string {
	t.Helper()
	page := httptest.NewRecorder()
	request := newUIRequest(http.MethodGet, path, nil)
	request.AddCookie(cookie)
	server.Handler().ServeHTTP(page, request)
	if page.Code != http.StatusOK {
		t.Fatalf("%s status = %d body = %q", path, page.Code, page.Body.String())
	}
	return page.Body.String()
}

func newUIRequest(method string, target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.RemoteAddr = "127.0.0.1:12345"
	return request
}

func formContainingOperation(body string, operation string) (string, bool) {
	needle := `name="operation" value="` + operation + `"`
	operationIndex := strings.Index(body, needle)
	if operationIndex == -1 {
		return "", false
	}
	start := strings.LastIndex(body[:operationIndex], "<form")
	if start == -1 {
		return "", false
	}
	endOffset := strings.Index(body[operationIndex:], "</form>")
	if endOffset == -1 {
		return "", false
	}
	end := operationIndex + endOffset + len("</form>")
	return body[start:end], true
}

func loginCookie(t *testing.T, server *Server) *http.Cookie {
	t.Helper()
	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, newUIRequest(http.MethodGet, server.StartupURL(), nil))
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d body = %q", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %#v, want one session cookie", cookies)
	}
	return cookies[0]
}

func eventsContain(events []uistate.Event, message string) bool {
	for _, event := range events {
		if event.Message == message {
			return true
		}
	}
	return false
}

func eventWithMessage(events []uistate.Event, message string) (uistate.Event, bool) {
	for _, event := range events {
		if event.Message == message {
			return event, true
		}
	}
	return uistate.Event{}, false
}

func eventsContainStatus(events []uistate.Event, status domain.DiagnosticStatus) bool {
	for _, event := range events {
		if event.Status == status {
			return true
		}
	}
	return false
}

func eventsContainPrefix(events []uistate.Event, prefix string) bool {
	for _, event := range events {
		if strings.HasPrefix(event.Message, prefix) {
			return true
		}
	}
	return false
}

func manualOriginProtectionObservation() exposure.AppObservations {
	return exposure.AppObservations{OriginProtectionStatus: domain.OriginProtectionConfiguredManual}
}

func passOriginProtectionObservation() exposure.AppObservations {
	return exposure.AppObservations{
		OriginProtectionStatus:          domain.OriginProtectionConfiguredPass,
		OriginProtectionReferenceDigest: "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		RealIPTrustedCIDRCount:          2,
		RealIPClientIPHeader:            appconfig.RealIPHeaderEdgeOne,
		RealIPSpoofingRejection:         domain.DiagnosticStatusPass,
	}
}

func testUIActor() domain.Actor {
	return domain.Actor{
		Source:                  domain.ActorSourceUI,
		EffectiveUID:            0,
		EffectiveUser:           "uid:0",
		ProcessID:               1234,
		SessionIDFingerprint:    "sha256:0011223344556677",
		RequestSource:           "127.0.0.1:12345",
		StartupTokenFingerprint: "sha256:8899aabbccddeeff",
	}
}

type stubPreAuthKeyCreator struct {
	key string
}

func (creator stubPreAuthKeyCreator) CreatePreAuthKey(context.Context, headscale.OnboardingPlan) (string, []host.Result, error) {
	return creator.key, nil, nil
}

type fakeHostWorkflow struct {
	calls                []string
	appErr               error
	realIPErr            error
	exposureObservations map[domain.ExposurePlanOperation]exposure.AppObservations
	exposureErr          error
	mainDeployStarted    chan struct{}
	mainDeployRelease    chan struct{}
}

func (host *fakeHostWorkflow) EnsureBrowserAuthDependencies(context.Context) error {
	return nil
}

func (host *fakeHostWorkflow) AppExposureObservations(_ context.Context, _ string, _ appconfig.Config, operation domain.ExposurePlanOperation) (exposure.AppObservations, error) {
	if host.exposureErr != nil {
		return exposure.AppObservations{}, host.exposureErr
	}
	return host.exposureObservations[operation], nil
}

func (host *fakeHostWorkflow) RunMainStatus(_ context.Context, configPath string) (workflow.OperationResult, error) {
	host.calls = append(host.calls, "status:"+configPath)
	return workflow.OperationResult{
		Kind:         domain.JobKindStatus,
		Status:       domain.JobStatusSucceeded,
		Summary:      "main status host workflow executed",
		Fields:       []domain.ResultField{{Label: "checkpoint path", Value: filepath.Join(filepath.Dir(configPath), ".lanpanel", "checkpoint.json")}},
		RetryCommand: workflow.ShellCommand("lanpanel", "status", "--config", configPath),
	}, nil
}

func (host *fakeHostWorkflow) RunMainDeploy(_ context.Context, configPath string) (workflow.OperationResult, error) {
	host.calls = append(host.calls, "main:"+configPath)
	if host.mainDeployStarted != nil {
		close(host.mainDeployStarted)
	}
	if host.mainDeployRelease != nil {
		<-host.mainDeployRelease
	}
	return workflow.OperationResult{
		Kind:          domain.JobKindDeploy,
		Status:        domain.JobStatusSucceeded,
		Summary:       "main host workflow executed",
		ModifiedPaths: []string{"/etc/headscale/config.yaml"},
		RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "deploy", "--config", configPath),
	}, nil
}

func (host *fakeHostWorkflow) RunAppDeploy(_ context.Context, appConfigPath string, _ domain.ExposurePlan, _ []string) (workflow.OperationResult, error) {
	host.calls = append(host.calls, "app:"+appConfigPath)
	if host.appErr != nil {
		return workflow.OperationResult{
			Kind:          domain.JobKindAppDeploy,
			Status:        domain.JobStatusFailed,
			Summary:       "app host workflow failed",
			ModifiedPaths: []string{"/etc/nginx/sites-available/example-app.conf"},
			RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", appConfigPath, "--confirmation", "origin-protection-manual"),
		}, host.appErr
	}
	return workflow.OperationResult{
		Kind:          domain.JobKindAppDeploy,
		Status:        domain.JobStatusSucceeded,
		Summary:       "app host workflow executed",
		ModifiedPaths: []string{"/etc/nginx/sites-available/example-app.conf"},
		RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", appConfigPath, "--confirmation", "origin-protection-manual"),
	}, nil
}

func (host *fakeHostWorkflow) RunRealIPDiagnostics(_ context.Context, appConfigPath string, profileName string) (workflow.OperationResult, error) {
	host.calls = append(host.calls, "realip-diagnostics:"+appConfigPath+":"+profileName)
	return workflow.OperationResult{
		Kind:         domain.JobKindRealIPDiagnostics,
		Status:       domain.JobStatusSucceeded,
		Summary:      "realip diagnostics host workflow executed",
		Fields:       []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "profile", Value: profileName}},
		RetryCommand: workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profileName),
	}, nil
}

func (host *fakeHostWorkflow) RunRealIPRefresh(_ context.Context, appConfigPath string, profileName string, _ domain.ExposurePlan, _ []string) (workflow.OperationResult, error) {
	host.calls = append(host.calls, "realip:"+appConfigPath+":"+profileName)
	if host.realIPErr != nil {
		return workflow.OperationResult{
			Kind:          domain.JobKindRealIPRefresh,
			Status:        domain.JobStatusFailed,
			Summary:       "realip host workflow failed",
			ModifiedPaths: []string{"/etc/nginx/lanpanel/realip/edgeone-prod/active.conf"},
			RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName, "--confirmation", "origin-protection-manual"),
		}, host.realIPErr
	}
	return workflow.OperationResult{
		Kind:          domain.JobKindRealIPRefresh,
		Status:        domain.JobStatusSucceeded,
		Summary:       "realip host workflow executed",
		ModifiedPaths: []string{"/etc/nginx/lanpanel/realip/edgeone-prod/active.conf"},
		RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName, "--confirmation", "origin-protection-manual"),
	}, nil
}

func (host *fakeHostWorkflow) hasCall(want string) bool {
	for _, call := range host.calls {
		if call == want {
			return true
		}
	}
	return false
}
