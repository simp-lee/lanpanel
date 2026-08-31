package ui

import (
	"bytes"
	"context"
	"lanpanel/internal/application"
	"lanpanel/internal/domain"
	"lanpanel/internal/session"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type (
	verifier      struct{ fp string }
	normalProfile struct{}
)

func (normalProfile) Current(context.Context) (Profile, error) { return ProfileNormal, nil }

func (v verifier) Verify(context.Context, []byte) (string, error) { return v.fp, nil }
func (v verifier) Source(context.Context) (string, error)         { return v.fp, nil }

type dummyListener struct{}

type gatedRequestBody struct {
	entered chan struct{}
	release chan struct{}
	reader  *bytes.Reader
	once    sync.Once
}

func (body *gatedRequestBody) Read(target []byte) (int, error) {
	body.once.Do(func() {
		close(body.entered)
		<-body.release
	})
	return body.reader.Read(target)
}

func (*gatedRequestBody) Close() error { return nil }

func (dummyListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (dummyListener) Close() error              { return nil }
func (dummyListener) Addr() net.Addr            { return &net.TCPAddr{} }
func testServer(t *testing.T) *Server {
	t.Helper()
	manager, err := session.New("fp", session.Options{Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }, Random: bytes.NewReader(make([]byte, 96*4))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	server, err := New(Config{Listener: dummyListener{}, Authority: "127.1.2.3:52345", InstallationFingerprint: "abcdef", Verifier: verifier{"fp"}, Sessions: manager, Profile: normalProfile{}})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestActionLeaseCancelsOnSessionInvalidation(t *testing.T) {
	server := testServer(t)
	principal := session.Principal{Selector: "selector", Generation: 1}
	lease := server.beginAction(context.Background(), principal, false)
	defer server.endAction(lease)
	server.cancelActions(&principal, nil)
	select {
	case <-lease.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("action lease was not canceled")
	}
}

func TestActionLeaseRevalidatesSessionAfterRegistration(t *testing.T) {
	server := testServer(t)
	credentials, err := server.config.Sessions.Issue(server.origin(), "fp")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := server.config.Sessions.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, server.origin(), "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	server.config.Sessions.Logout(principal)
	lease := server.beginAction(context.Background(), principal, false)
	if lease == nil {
		t.Fatal("stale action lease was not registered for boundary validation")
	}
	defer server.endAction(lease)
	if server.revalidateAction(lease) {
		t.Fatal("logged-out principal remained valid at the action boundary")
	}
	select {
	case <-lease.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("unauthorized action lease was not canceled")
	}
}

func TestActionLeaseRejectsRotationCancellationAtDispatchBoundary(t *testing.T) {
	server := testServer(t)
	credentials, err := server.config.Sessions.Issue(server.origin(), "fp")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := server.config.Sessions.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, server.origin(), "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	lease := server.beginAction(context.Background(), principal, false)
	if lease == nil {
		t.Fatal("ordinary action lease was not registered")
	}
	rotation := make(chan *actionLease, 1)
	go func() {
		rotation <- server.beginAction(context.Background(), principal, true)
	}()
	select {
	case <-lease.ctx.Done():
	case <-time.After(time.Second):
		server.endAction(lease)
		t.Fatal("exclusive rotation did not cancel the registered action")
	}
	if server.revalidateAction(lease) {
		server.endAction(lease)
		t.Fatal("rotation-canceled action crossed the dispatch boundary")
	}
	server.endAction(lease)
	select {
	case rotationLease := <-rotation:
		if rotationLease == nil {
			t.Fatal("exclusive rotation lease was canceled")
		}
		server.endAction(rotationLease)
	case <-time.After(time.Second):
		t.Fatal("exclusive rotation did not acquire after canceled action exited")
	}
}

func TestActionDispatchRejectsRotationAfterRequestValidation(t *testing.T) {
	server := testServer(t)
	var invoked atomic.Bool
	registration, err := application.RegisterAction(domain.OperationConnectorBindingSet, application.ConnectorBindingPayload{}, true, false, func(_ context.Context, _ application.Actor, call application.Call) (application.Result, error) {
		invoked.Store(true)
		return application.Result{Operation: call.Operation, Target: call.Target, Payload: application.ConnectorMutationResult{}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server.config.Actions, err = application.New([]application.Registration{registration})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := server.config.Sessions.Issue(server.origin(), "fp")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := server.config.Sessions.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, server.origin(), "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	body := &gatedRequestBody{entered: make(chan struct{}), release: make(chan struct{}), reader: bytes.NewReader([]byte(`{"control_url":"https://control.example.test"}`))}
	request := httptest.NewRequest(http.MethodPost, server.origin()+"/api/actions/connector_binding_set", body)
	request.Header.Set("Origin", server.origin())
	request.Header.Set(session.ProofHeader, credentials.Proof)
	request.Header.Set(session.CSRFHeader, credentials.CSRF)
	request.AddCookie(&http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector})
	writer := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		server.action(writer, request)
		close(requestDone)
	}()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		close(body.release)
		t.Fatal("action did not reach post-validation request decoding")
	}
	rotation := make(chan *actionLease, 1)
	go func() { rotation <- server.beginAction(context.Background(), principal, true) }()
	deadline := time.Now().Add(time.Second)
	for {
		server.actionMu.Lock()
		pending := server.rotationPending
		server.actionMu.Unlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			close(body.release)
			t.Fatal("exclusive rotation did not select the in-flight action")
		}
		time.Sleep(time.Millisecond)
	}
	close(body.release)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("canceled HTTP action did not exit")
	}
	if invoked.Load() {
		t.Fatal("rotation-canceled action reached its application handler")
	}
	if writer.Code != http.StatusServiceUnavailable {
		t.Fatalf("canceled action status=%d", writer.Code)
	}
	select {
	case rotationLease := <-rotation:
		if rotationLease == nil {
			t.Fatal("exclusive rotation lease was canceled")
		}
		server.endAction(rotationLease)
	case <-time.After(time.Second):
		t.Fatal("exclusive rotation did not acquire after canceled HTTP action exited")
	}
}

func TestManagementPageExposesDomainCredentialStaticAndContractionControls(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "http://127.1.2.3:52345/", nil)
	request.Host = "127.1.2.3:52345"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	for _, id := range []string{"headscale-initialize", "headscale-control", "headscale-reissue", "resource-create", "resource-update-json", "process-control", "resource-delete", "headscale-user-create", "headscale-key-create", "headscale-key-revoke", "headscale-device-expire", "headscale-reads", "connector-binding", "connector-login", "connector-verify", "product-reads", "job-detail", "domain-config", "basic-create", "basic-rotate", "basic-delete", "static-register", "external-htpasswd-register", "domain-status", "unpublish"} {
		if !strings.Contains(response.Body.String(), `id="`+id+`"`) {
			t.Fatalf("management control %s missing", id)
		}
	}
	if strings.Count(appJS, `JSON.stringify({plan_id:"",confirmation:"",certificate})`) != 2 {
		t.Fatal("Headscale Plan requests are not canonical")
	}
	if strings.Contains(response.Body.String(), `name="account_key_path"`) || strings.Contains(appJS, "account_key_path") || strings.Contains(response.Body.String(), `name="account_email"`) || strings.Contains(appJS, "account_email") || strings.Count(response.Body.String(), "installation-managed ACME account key") != 2 {
		t.Fatal("ACME account key is still caller-selected or its managed authority is not disclosed")
	}
	for _, field := range []string{"control_domain", "magicdns_namespace", "source_kind", "mirror_url", "offline_path", "proxy_url"} {
		if !strings.Contains(response.Body.String(), `name="`+field+`"`) {
			t.Fatalf("Headscale UI field %s missing", field)
		}
	}
	for _, required := range []string{"trusted_mesh", "/api/actions/headscale_initialize", "cannot be changed or removed", "control service and ingress remain inactive", "foreign Headscale database, account, or artifact evidence"} {
		if !strings.Contains(response.Body.String(), required) && !strings.Contains(appJS, required) {
			t.Fatalf("Headscale initialization warning/action missing %q", required)
		}
	}
	if !strings.Contains(response.Body.String(), "Static mappings (one URL|relative") {
		t.Fatal("repeatable static mapping editor missing")
	}
	for _, field := range []string{"goaccess_enabled", "goaccess_credential_id", "goaccess_cidrs", "goaccess_dashboard_path", "goaccess_websocket_path"} {
		if !strings.Contains(response.Body.String(), `name="`+field+`"`) {
			t.Fatalf("GoAccess UI field %s missing", field)
		}
	}
	for _, required := range []string{"GoAccess retirement pending; job", "goaccess_retirement_job_id", "goaccess_retirement_generations", "App credential ", "GoAccess credential ", "goaccess_credential_fingerprint", "goaccess_credential_changed"} {
		if !strings.Contains(appJS, required) {
			t.Fatalf("GoAccess retirement UI evidence missing %q", required)
		}
	}
}

func TestLoginRequiresExactHostOriginAndBoundedBody(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "http://127.1.2.3:52345/login", strings.NewReader("token=secret"))
	request.Host = "127.1.2.3:52345"
	request.Header.Set("Origin", "http://127.1.2.3:52345")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login status %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store, private" || response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("browser defenses absent")
	}
	if len(response.Result().Cookies()) != 1 || !response.Result().Cookies()[0].HttpOnly {
		t.Fatal("selector cookie not protected")
	}
}

func TestHostOriginAndDuplicateCookieFailClosed(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	request.Host = "example.invalid"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unexpected Host accepted: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "http://127.1.2.3:52345/login", strings.NewReader("token=secret"))
	request.Host = "127.1.2.3:52345"
	request.Header.Add("Origin", "http://127.1.2.3:52345")
	request.Header.Add("Origin", "http://127.1.2.3:52345")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatal("duplicate Origin accepted")
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.1.2.3:52345/api/session", nil)
	request.Host = "127.1.2.3:52345"
	request.Header.Add("Cookie", session.SelectorCookie+"=one; "+session.SelectorCookie+"=two")
	request.Header.Set(session.ProofHeader, "proof")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("duplicate selector accepted")
	}
}
