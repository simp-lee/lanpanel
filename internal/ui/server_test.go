package ui

import (
	"bytes"
	"context"
	"errors"
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

	"github.com/coder/websocket"
)

type (
	verifier      struct{ fp string }
	normalProfile struct{}
	gatedVerifier struct {
		fp                     string
		entered, release       chan struct{}
		enterOnce, releaseOnce sync.Once
	}
)

func (normalProfile) Current(context.Context) (Profile, error) { return ProfileNormal, nil }

func (v verifier) Verify(context.Context, []byte) (string, error) { return v.fp, nil }
func (v verifier) Source(context.Context) (string, error)         { return v.fp, nil }

func (v *gatedVerifier) Verify(ctx context.Context, _ []byte) (string, error) {
	v.enterOnce.Do(func() { close(v.entered) })
	select {
	case <-v.release:
		return v.fp, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
func (v *gatedVerifier) Source(context.Context) (string, error) { return v.fp, nil }
func (v *gatedVerifier) releaseVerify() {
	v.releaseOnce.Do(func() { close(v.release) })
}

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
	server.actionMu.Lock()
	var action *actionLease
	for candidate := range server.actions {
		action = candidate
	}
	server.actionMu.Unlock()
	if action == nil {
		close(body.release)
		t.Fatal("in-flight action lease was not registered")
	}
	rotation := make(chan *actionLease, 1)
	go func() { rotation <- server.beginAction(context.Background(), principal, true) }()
	select {
	case <-action.ctx.Done():
	case <-time.After(time.Second):
		close(body.release)
		t.Fatal("exclusive rotation did not select the in-flight action")
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

func TestShutdownFenceRejectsActionAuthenticatedBeforeLeaseRegistration(t *testing.T) {
	server := testServer(t)
	credentials, err := server.config.Sessions.Issue(server.origin(), "fp")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := server.config.Sessions.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, server.origin(), "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	server.stopActions()
	if !server.config.Sessions.Valid(principal) {
		t.Fatal("test principal became invalid before the shutdown session boundary")
	}
	if lease := server.beginAction(context.Background(), principal, false); lease != nil {
		server.endAction(lease)
		t.Fatal("action authenticated before shutdown registered after the terminal action fence")
	}
}

func TestRotationPlanDoesNotCancelConcurrentAction(t *testing.T) {
	server := testServer(t)
	planInvoked := make(chan struct{})
	connectorInvoked := make(chan struct{})
	plan, err := application.RegisterAction(domain.OperationPlan, application.PlanPayload{}, true, false, func(_ context.Context, _ application.Actor, call application.Call) (application.Result, error) {
		close(planInvoked)
		return application.Result{Operation: call.Operation, Target: call.Target, Payload: map[string]string{"plan_id": "plan-fixture"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	connector, err := application.RegisterAction(domain.OperationConnectorBindingSet, application.ConnectorBindingPayload{}, true, false, func(_ context.Context, _ application.Actor, call application.Call) (application.Result, error) {
		close(connectorInvoked)
		return application.Result{Operation: call.Operation, Target: call.Target, Payload: application.ConnectorMutationResult{JobID: "job-fixture"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server.config.Actions, err = application.New([]application.Registration{plan, connector})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := server.config.Sessions.Issue(server.origin(), "fp")
	if err != nil {
		t.Fatal(err)
	}
	body := &gatedRequestBody{entered: make(chan struct{}), release: make(chan struct{}), reader: bytes.NewReader([]byte(`{"control_url":"https://control.example.test"}`))}
	actionRequest := httptest.NewRequest(http.MethodPost, server.origin()+"/api/actions/connector_binding_set", body)
	actionRequest.Header.Set("Origin", server.origin())
	actionRequest.Header.Set(session.ProofHeader, credentials.Proof)
	actionRequest.Header.Set(session.CSRFHeader, credentials.CSRF)
	actionRequest.AddCookie(&http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector})
	actionWriter := httptest.NewRecorder()
	actionDone := make(chan struct{})
	go func() {
		server.action(actionWriter, actionRequest)
		close(actionDone)
	}()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		close(body.release)
		t.Fatal("concurrent action did not reach its synchronization barrier")
	}

	planRequest := httptest.NewRequest(http.MethodPost, server.origin()+"/api/actions/admin_token_rotate/plan", strings.NewReader("{}"))
	planRequest.Header.Set("Origin", server.origin())
	planRequest.Header.Set(session.ProofHeader, credentials.Proof)
	planRequest.Header.Set(session.CSRFHeader, credentials.CSRF)
	planRequest.AddCookie(&http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector})
	planWriter := httptest.NewRecorder()
	planDone := make(chan struct{})
	go func() {
		server.action(planWriter, planRequest)
		close(planDone)
	}()
	select {
	case <-planInvoked:
	case <-time.After(time.Second):
		close(body.release)
		<-actionDone
		t.Fatal("rotation Plan blocked behind the concurrent action")
	}
	select {
	case <-planDone:
	case <-time.After(time.Second):
		close(body.release)
		<-actionDone
		t.Fatal("rotation Plan did not complete while the concurrent action was active")
	}
	if planWriter.Code != http.StatusOK {
		close(body.release)
		<-actionDone
		t.Fatalf("rotation Plan status=%d", planWriter.Code)
	}

	server.actionMu.Lock()
	for lease := range server.actions {
		if lease.ctx.Err() != nil {
			server.actionMu.Unlock()
			close(body.release)
			<-actionDone
			t.Fatal("rotation Plan canceled the concurrent action")
		}
	}
	server.actionMu.Unlock()
	close(body.release)
	select {
	case <-connectorInvoked:
	case <-time.After(time.Second):
		t.Fatal("concurrent action was not dispatched after Plan review")
	}
	select {
	case <-actionDone:
	case <-time.After(time.Second):
		t.Fatal("concurrent action did not complete")
	}
	if actionWriter.Code != http.StatusOK {
		t.Fatalf("concurrent action status=%d", actionWriter.Code)
	}
}

func TestShutdownTerminatesConcurrentLoginActionAndSocketAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "fp"
	manager, err := session.New(fingerprint, session.Options{Random: bytes.NewReader(make([]byte, 192))})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	credentials, err := manager.Issue("http://"+listener.Addr().String(), fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := manager.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, "http://"+listener.Addr().String(), fingerprint, true)
	if err != nil {
		t.Fatal(err)
	}

	actionEntered := make(chan struct{})
	actionCanceled := make(chan struct{})
	registration, err := application.RegisterAction(domain.OperationConnectorBindingSet, application.ConnectorBindingPayload{}, true, false, func(ctx context.Context, _ application.Actor, _ application.Call) (application.Result, error) {
		close(actionEntered)
		<-ctx.Done()
		close(actionCanceled)
		return application.Result{}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	actions, err := application.New([]application.Registration{registration})
	if err != nil {
		t.Fatal(err)
	}
	verifyGate := &gatedVerifier{fp: fingerprint, entered: make(chan struct{}), release: make(chan struct{})}
	defer verifyGate.releaseVerify()
	server, err := New(Config{Listener: listener, Authority: listener.Addr().String(), InstallationFingerprint: "abcdef", Verifier: verifyGate, Sessions: manager, Profile: normalProfile{}, Actions: actions})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()

	requestContext, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	client := &http.Client{}
	actionRequest, err := http.NewRequestWithContext(requestContext, http.MethodPost, server.origin()+"/api/actions/connector_binding_set", strings.NewReader(`{"control_url":"https://control.example.test"}`))
	if err != nil {
		t.Fatal(err)
	}
	actionRequest.Header.Set("Origin", server.origin())
	actionRequest.Header.Set(session.ProofHeader, credentials.Proof)
	actionRequest.Header.Set(session.CSRFHeader, credentials.CSRF)
	actionRequest.Header.Set("Content-Type", "application/json")
	actionRequest.AddCookie(&http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector})
	actionDone := make(chan int, 1)
	go func() {
		response, requestErr := client.Do(actionRequest)
		if requestErr != nil {
			actionDone <- 0
			return
		}
		defer func() { _ = response.Body.Close() }()
		actionDone <- response.StatusCode
	}()
	select {
	case <-actionEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("action did not reach its handler")
	}

	socketHeader := http.Header{}
	socketHeader.Set("Origin", server.origin())
	socketHeader.Set("Cookie", session.SelectorCookie+"="+credentials.Selector)
	dialContext, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	delayedSocket, _, err := websocket.Dial(dialContext, server.origin()+"/api/events", &websocket.DialOptions{HTTPHeader: socketHeader, Subprotocols: []string{WebSocketSubprotocol}})
	cancelDial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = delayedSocket.CloseNow() }()

	loginRequest, err := http.NewRequestWithContext(requestContext, http.MethodPost, server.origin()+"/login", strings.NewReader("token=admin"))
	if err != nil {
		t.Fatal(err)
	}
	loginRequest.Header.Set("Origin", server.origin())
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginDone := make(chan int, 1)
	go func() {
		response, requestErr := client.Do(loginRequest)
		if requestErr != nil {
			loginDone <- 0
			return
		}
		defer func() { _ = response.Body.Close() }()
		loginDone <- response.StatusCode
	}()
	select {
	case <-verifyGate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("login did not reach its verifier barrier")
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- server.Shutdown(shutdownContext) }()
	select {
	case <-actionCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not cancel the concurrent action")
	}
	if manager.Valid(principal) {
		t.Fatal("Shutdown left the preexisting principal valid")
	}

	authContext, cancelAuth := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAuth()
	authFrame := []byte(`{"type":"auth","proof":"` + credentials.Proof + `"}`)
	if err := delayedSocket.Write(authContext, websocket.MessageText, authFrame); err != nil {
		verifyGate.releaseVerify()
		t.Fatalf("delayed WebSocket authentication write failed: %v", err)
	}
	verifyGate.releaseVerify()
	_, payload, readErr := delayedSocket.Read(authContext)
	if readErr == nil {
		t.Fatalf("WebSocket attached after session closure: %s", payload)
	}
	select {
	case status := <-loginDone:
		if status != http.StatusServiceUnavailable {
			t.Fatalf("concurrent login status=%d", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent login did not exit after its verifier was released")
	}
	select {
	case status := <-actionDone:
		if status != http.StatusServiceUnavailable {
			t.Fatalf("canceled action status=%d", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled action request did not exit")
	}
	select {
	case shutdownErr := <-shutdownDone:
		if shutdownErr != nil {
			t.Fatal(shutdownErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not complete")
	}
	if _, err := manager.Issue(server.origin(), fingerprint); err == nil {
		t.Fatal("Shutdown permitted a new session")
	}
	select {
	case serveErr := <-serveDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("Serve returned %v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit after Shutdown")
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
