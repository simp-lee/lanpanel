// Package ui serves the exact loopback Management authority.
package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"lanpanel/internal/application"
	"lanpanel/internal/audit"
	"lanpanel/internal/domain"
	"lanpanel/internal/session"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const (
	fixedCSP                  = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'"
	WebSocketSubprotocol      = "lanpanel.events.v1"
	maximumLoginBytes         = 4096
	maximumEmptyPayloadBytes  = 4096
	maximumWebSocketAuthBytes = 4096
)

type TokenVerifier interface {
	Verify(context.Context, []byte) (string, error)
	Source(context.Context) (string, error)
}
type Profile string

const (
	ProfileNormal    Profile = "normal"
	ProfileEmergency Profile = "emergency"
)

type ProfileProvider interface {
	Current(context.Context) (Profile, error)
}
type Config struct {
	Listener                           net.Listener
	Authority, InstallationFingerprint string
	Verifier                           TokenVerifier
	Sessions                           *session.Manager
	Profile                            ProfileProvider
	Actions                            *application.Service
	Audit                              audit.Sink
}
type Server struct {
	config          Config
	http            *http.Server
	barrier         sync.RWMutex
	output          sync.Mutex
	actionMu        sync.Mutex
	actions         map[*actionLease]struct{}
	eventMu         sync.Mutex
	eventSockets    map[session.Principal]map[*socket]struct{}
	nextAction      atomic.Uint64
	rotationPending bool
	shuttingDown    bool
}
type actionLease struct {
	id        string
	principal session.Principal
	ctx       context.Context
	cancel    context.CancelFunc
	exclusive bool
}

type actionEvent struct {
	Type      string                 `json:"type"`
	ActionID  string                 `json:"action_id"`
	State     string                 `json:"state"`
	Operation domain.OperationCode   `json:"operation"`
	Target    domain.OperationTarget `json:"target"`
	Progress  *int                   `json:"progress"`
	Message   string                 `json:"message"`
	StartedAt time.Time              `json:"started_at"`
	At        time.Time              `json:"at"`
}
type socket struct {
	connection *websocket.Conn
	mu         sync.Mutex
	stateMu    sync.Mutex
	closed     bool
}

func (s *socket) Close() error {
	return s.closeWith(websocket.StatusGoingAway, "", true)
}

func (s *socket) closeWith(code websocket.StatusCode, reason string, immediate bool) error {
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return nil
	}
	s.closed = true
	s.stateMu.Unlock()
	if immediate {
		return s.connection.CloseNow()
	}
	return s.connection.Close(code, reason)
}

func (s *socket) Write(ctx context.Context, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateMu.Lock()
	closed := s.closed
	s.stateMu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return s.connection.Write(ctx, websocket.MessageText, payload)
}

func New(config Config) (*Server, error) {
	if config.Listener == nil || config.Authority == "" || config.InstallationFingerprint == "" || config.Verifier == nil || config.Sessions == nil || config.Profile == nil {
		return nil, fmt.Errorf("management UI config is incomplete")
	}
	if config.Audit == nil {
		return nil, fmt.Errorf("management UI audit sink is unavailable")
	}
	server := &Server{config: config, actions: map[*actionLease]struct{}{}, eventSockets: map[session.Principal]map[*socket]struct{}{}}
	server.http = &http.Server{Handler: server, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return server, nil
}
func (s *Server) Serve() error { return s.http.Serve(s.config.Listener) }
func (s *Server) beginAction(parent context.Context, principal session.Principal, exclusive bool) *actionLease {
	ctx, cancel := context.WithCancel(parent)
	lease := &actionLease{id: fmt.Sprintf("action_%d", s.nextAction.Add(1)), principal: principal, ctx: ctx, cancel: cancel, exclusive: exclusive}
	s.actionMu.Lock()
	if s.shuttingDown || s.rotationPending {
		s.actionMu.Unlock()
		cancel()
		return nil
	}
	if exclusive {
		s.rotationPending = true
	}
	if exclusive {
		for current := range s.actions {
			current.cancel()
		}
	}
	s.actions[lease] = struct{}{}
	s.actionMu.Unlock()
	if exclusive {
		for {
			if ctx.Err() != nil {
				s.endAction(lease)
				return nil
			}
			s.actionMu.Lock()
			remaining := len(s.actions)
			s.actionMu.Unlock()
			if remaining == 1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	return lease
}

func (s *Server) revalidateAction(lease *actionLease) bool {
	if lease == nil || lease.ctx.Err() != nil {
		return false
	}
	s.barrier.RLock()
	valid := s.config.Sessions.Valid(lease.principal)
	s.barrier.RUnlock()
	if !valid || lease.ctx.Err() != nil {
		lease.cancel()
		return false
	}
	return true
}

func (s *Server) endAction(lease *actionLease) {
	if lease == nil {
		return
	}
	s.actionMu.Lock()
	delete(s.actions, lease)
	if lease.exclusive {
		s.rotationPending = false
	}
	s.actionMu.Unlock()
	lease.cancel()
}

func (s *Server) cancelActions(principal *session.Principal, except *actionLease) {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	for lease := range s.actions {
		if lease != except && (principal == nil || lease.principal == *principal) {
			lease.cancel()
		}
	}
}

func (s *Server) stopActions() {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	s.shuttingDown = true
	for lease := range s.actions {
		lease.cancel()
	}
}

func (s *Server) registerEventSocket(principal session.Principal, managed *socket) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.eventSockets[principal] == nil {
		s.eventSockets[principal] = map[*socket]struct{}{}
	}
	s.eventSockets[principal][managed] = struct{}{}
}

func (s *Server) unregisterEventSocket(principal session.Principal, managed *socket) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if sockets := s.eventSockets[principal]; sockets != nil {
		delete(sockets, managed)
		if len(sockets) == 0 {
			delete(s.eventSockets, principal)
		}
	}
}

func (s *Server) sendEvent(principal session.Principal, event actionEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	s.eventMu.Lock()
	sockets := make([]*socket, 0, len(s.eventSockets[principal]))
	for managed := range s.eventSockets[principal] {
		sockets = append(sockets, managed)
	}
	s.eventMu.Unlock()
	for _, managed := range sockets {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := managed.Write(ctx, payload)
		cancel()
		if err != nil {
			s.unregisterEventSocket(principal, managed)
		}
	}
}

func (s *Server) actionEvent(principal session.Principal, actionID string, operation domain.OperationCode, target domain.OperationTarget, state, message string, started time.Time) {
	s.sendEvent(principal, actionEvent{Type: "action", ActionID: actionID, State: state, Operation: operation, Target: target, Message: message, StartedAt: started, At: time.Now().UTC()})
}

func (s *Server) actionHeartbeat(done <-chan struct{}, principal session.Principal, lease *actionLease, operation domain.OperationCode, target domain.OperationTarget, started time.Time) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.actionEvent(principal, lease.id, operation, target, "running", fmt.Sprintf("Action is still running (%s elapsed)", time.Since(started).Round(time.Second)), started)
		case <-done:
			return
		}
	}
}

func (s *Server) sessionJSON(writer http.ResponseWriter, principal session.Principal, payload any) bool {
	s.barrier.RLock()
	defer s.barrier.RUnlock()
	if !s.config.Sessions.Valid(principal) {
		reject(writer, http.StatusUnauthorized)
		return false
	}
	writer.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(writer).Encode(payload) == nil
}

func (s *Server) sessionStatusJSON(writer http.ResponseWriter, principal session.Principal, status int, payload any) bool {
	s.barrier.RLock()
	defer s.barrier.RUnlock()
	if !s.config.Sessions.Valid(principal) {
		reject(writer, http.StatusUnauthorized)
		return false
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	return json.NewEncoder(writer).Encode(payload) == nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.stopActions()
	s.config.Sessions.Close()
	return s.http.Shutdown(ctx)
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	securityHeaders(writer)
	if s.isHTTPSProxyRequest(request) {
		writer.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	actionRoute := request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/api/actions/")
	if !s.isHTTPSProxyRequest(request) && request.Host != s.config.Authority || request.URL.RawQuery != "" && !actionRoute || request.URL.RawPath != "" {
		reject(writer, http.StatusMisdirectedRequest)
		return
	}
	if request.Method == http.MethodHead {
		request.Method = http.MethodGet
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/":
		s.shell(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == appCSSPath:
		if presentOriginInvalid(request, s.originFor(request)) {
			reject(writer, http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "text/css; charset=utf-8")
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = io.WriteString(writer, appCSS)
	case request.Method == http.MethodGet && request.URL.Path == appJSPath:
		if presentOriginInvalid(request, s.originFor(request)) {
			reject(writer, http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = io.WriteString(writer, appJS)
	case request.Method == http.MethodPost && request.URL.Path == "/login":
		s.login(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/api/logout":
		s.logout(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/api/session":
		s.current(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/api/events":
		s.events(writer, request)
	case request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/api/actions/"):
		s.action(writer, request)
	default:
		reject(writer, http.StatusNotFound)
	}
}

func (s *Server) shell(writer http.ResponseWriter, request *http.Request) {
	if presentOriginInvalid(request, s.originFor(request)) {
		reject(writer, http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.writeStructuredShell(writer)
}

func (s *Server) writeStructuredShell(writer http.ResponseWriter) {
	page := strings.Replace(uiShell, "{{fingerprint}}", template.HTMLEscapeString(s.config.InstallationFingerprint), 1)
	page = strings.Replace(page, "{{app_css_path}}", appCSSPath, 1)
	page = strings.Replace(page, "{{app_js_path}}", appJSPath, 1)
	_, _ = io.WriteString(writer, page)
}

func (s *Server) login(writer http.ResponseWriter, request *http.Request) {
	contentType, ok := exactHeader(request, "Content-Type")
	if !exactOrigin(request, s.originFor(request)) || !ok || contentType != "application/x-www-form-urlencoded" {
		reject(writer, http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumLoginBytes)
	data, err := io.ReadAll(request.Body)
	if err != nil {
		reject(writer, http.StatusBadRequest)
		return
	}
	values, err := url.ParseQuery(string(data))
	clear(data)
	if err != nil || len(values) != 1 || len(values["token"]) != 1 || values.Get("token") == "" {
		reject(writer, http.StatusBadRequest)
		return
	}
	token := []byte(values.Get("token"))
	defer clear(token)
	s.barrier.Lock()
	fingerprint, err := s.config.Verifier.Verify(request.Context(), token)
	if err != nil {
		s.barrier.Unlock()
		if auditErr := s.appendAudit(audit.Record{Operation: "login", Target: "installation", Actor: "unknown", At: time.Now().UTC(), Result: "failed", ErrorCode: "authentication_failed", Paths: []string{}}); auditErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		reject(writer, http.StatusUnauthorized)
		return
	}
	credentials, err := s.config.Sessions.Issue(s.originFor(request), fingerprint)
	s.barrier.Unlock()
	if err != nil {
		if auditErr := s.appendAudit(audit.Record{Operation: "login", Target: "installation", Actor: fingerprint, At: time.Now().UTC(), Result: "failed", ErrorCode: "session_issue_failed", Paths: []string{}}); auditErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	if err := s.appendAudit(audit.Record{Operation: "login", Target: "installation", Actor: fingerprint, At: time.Now().UTC(), Result: "succeeded", Paths: []string{}}); err != nil {
		s.config.Sessions.Logout(session.Principal{Selector: credentials.Selector, Generation: 0})
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector, Path: "/", HttpOnly: true, Secure: s.isHTTPSProxyRequest(request), SameSite: http.SameSiteStrictMode})
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]string{"proof": credentials.Proof, "csrf": credentials.CSRF})
}

func (s *Server) appendAudit(record audit.Record) error {
	if s.config.Audit == nil {
		return fmt.Errorf("management UI audit sink is unavailable")
	}
	return s.config.Audit.Append(record)
}

func auditTarget(target domain.OperationTarget) string {
	if target.ID == "" {
		return string(target.Kind)
	}
	return string(target.Kind) + "/" + target.ID
}

func (s *Server) appendActionAudit(operation domain.OperationCode, target domain.OperationTarget, actor, result, errorCode string) error {
	if errorCode == "" && result == "failed" {
		errorCode = "action_failed"
	}
	return s.appendAudit(audit.Record{Operation: string(operation), Target: auditTarget(target), Actor: actor, At: time.Now().UTC(), Result: result, ErrorCode: errorCode, Paths: []string{}})
}

func (s *Server) current(writer http.ResponseWriter, request *http.Request) {
	s.barrier.RLock()
	defer s.barrier.RUnlock()
	s.output.Lock()
	defer s.output.Unlock()
	principal, ok := s.authenticate(request, false)
	if !ok {
		reject(writer, http.StatusUnauthorized)
		return
	}
	_ = principal
	profile, profileErr := s.config.Profile.Current(request.Context())
	if profileErr != nil || profile != ProfileNormal && profile != ProfileEmergency {
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"authenticated": true, "profile": profile, "emergency_actions": profile == ProfileEmergency})
}

func (s *Server) logout(writer http.ResponseWriter, request *http.Request) {
	if !exactOrigin(request, s.originFor(request)) {
		reject(writer, http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumEmptyPayloadBytes)
	data, err := io.ReadAll(request.Body)
	defer clear(data)
	if err != nil || len(data) != 0 {
		reject(writer, http.StatusBadRequest)
		return
	}
	s.barrier.Lock()
	defer s.barrier.Unlock()
	s.output.Lock()
	defer s.output.Unlock()
	principal, ok := s.authenticate(request, true)
	if !ok {
		if auditErr := s.appendAudit(audit.Record{Operation: "logout", Target: "installation", Actor: "unknown", At: time.Now().UTC(), Result: "failed", ErrorCode: "authentication_failed", Paths: []string{}}); auditErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		reject(writer, http.StatusUnauthorized)
		return
	}
	actor := s.config.Sessions.Identity(principal)
	if err := s.appendAudit(audit.Record{Operation: "logout", Target: "installation", Actor: actor, At: time.Now().UTC(), Result: "succeeded", Paths: []string{}}); err != nil {
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	s.cancelActions(&principal, nil)
	s.config.Sessions.Logout(principal)
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.isHTTPSProxyRequest(request), SameSite: http.SameSiteStrictMode})
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) events(writer http.ResponseWriter, request *http.Request) {
	if !exactOrigin(request, s.originFor(request)) {
		reject(writer, http.StatusForbidden)
		return
	}
	selector, ok := exactCookie(request, session.SelectorCookie)
	if !ok {
		reject(writer, http.StatusUnauthorized)
		return
	}
	protocol, ok := exactHeader(request, "Sec-WebSocket-Protocol")
	if !ok || protocol != WebSocketSubprotocol {
		reject(writer, http.StatusBadRequest)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{WebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	managed := &socket{connection: connection}
	defer func() { _ = managed.closeWith(websocket.StatusNormalClosure, "closed", false) }()
	authContext, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	kind, payload, err := connection.Read(authContext)
	if err != nil || kind != websocket.MessageText || len(payload) == 0 || len(payload) > maximumWebSocketAuthBytes {
		_ = managed.closeWith(websocket.StatusPolicyViolation, "authentication required", false)
		return
	}
	var frame struct {
		Type  string `json:"type"`
		Proof string `json:"proof"`
	}
	if decodeExactJSON(payload, &frame) != nil || frame.Type != "auth" || frame.Proof == "" {
		clear(payload)
		_ = managed.closeWith(websocket.StatusPolicyViolation, "authentication required", false)
		return
	}
	clear(payload)
	s.barrier.RLock()
	fingerprint, err := s.config.Verifier.Source(request.Context())
	if err != nil {
		s.cancelActions(nil, nil)
		s.config.Sessions.InvalidateFingerprint("unavailable")
		s.barrier.RUnlock()
		return
	}
	if !s.config.Sessions.RequireFingerprint(fingerprint) {
		s.cancelActions(nil, nil)
		s.barrier.RUnlock()
		return
	}
	principal, err := s.config.Sessions.AuthenticateSocket(selector, frame.Proof, s.originFor(request), fingerprint)
	if err != nil {
		s.barrier.RUnlock()
		return
	}
	if s.config.Sessions.Attach(principal, managed) != nil {
		s.barrier.RUnlock()
		return
	}
	s.barrier.RUnlock()
	defer func() {
		s.unregisterEventSocket(principal, managed)
		s.config.Sessions.Detach(principal, managed)
	}()
	sendContext, sendCancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer sendCancel()
	sendErr := s.config.Sessions.Send(principal, fingerprint, func() error { return managed.Write(sendContext, []byte(`{"type":"ready"}`)) })
	if sendErr != nil {
		return
	}
	s.registerEventSocket(principal, managed)
	for {
		kind, _, err := connection.Read(request.Context())
		if err != nil {
			return
		}
		if kind == websocket.MessageText || kind == websocket.MessageBinary {
			_ = connection.Close(websocket.StatusPolicyViolation, "client events forbidden")
			return
		}
	}
}

func (s *Server) action(writer http.ResponseWriter, request *http.Request) {
	controller := http.NewResponseController(writer)
	_ = controller.SetWriteDeadline(time.Now().Add(12 * time.Minute))
	if !exactOrigin(request, s.originFor(request)) {
		reject(writer, http.StatusForbidden)
		return
	}
	pathValue := strings.TrimPrefix(request.URL.Path, "/api/actions/")
	planRoute := strings.HasSuffix(pathValue, "/plan")
	if planRoute {
		pathValue = strings.TrimSuffix(pathValue, "/plan")
	}
	operation, err := domain.ParseOperationCode(pathValue)
	if err != nil {
		reject(writer, http.StatusNotFound)
		return
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || !validActionQuery(operation, query) {
		reject(writer, http.StatusBadRequest)
		return
	}
	target := domain.OperationTarget{Kind: domain.OperationTargetInstallation}
	resourceTarget := operation == domain.OperationUnpublish || operation == domain.OperationPublish || operation == domain.OperationResourceUpdate || operation == domain.OperationResourceDelete || operation == domain.OperationProcessStart || operation == domain.OperationProcessStop || operation == domain.OperationManagedBasicCreate || operation == domain.OperationStaticRootRegister || operation == domain.OperationExternalHTPasswdRegister
	if resourceTarget {
		resourceID, ok := firstExact(query["resource_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetResource, ID: resourceID}
	}
	if operation == domain.OperationStatus {
		if values, present := query["resource_id"]; present {
			resourceID, ok := firstExact(values)
			if !ok {
				reject(writer, http.StatusBadRequest)
				return
			}
			target = domain.OperationTarget{Kind: domain.OperationTargetResource, ID: resourceID}
		}
	}
	if operation == domain.OperationJobDetail {
		id, ok := firstExact(query["job_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetJob, ID: id}
	}
	if operation == domain.OperationManagedBasicRotate || operation == domain.OperationManagedBasicDelete {
		credentialID, ok := firstExact(query["credential_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetCredential, ID: credentialID}
	}
	headscaleOperation := operation == domain.OperationHeadscaleInitialize
	headscaleControlOperation := operation == domain.OperationHeadscaleControlDeploy
	headscaleReissueOperation := operation == domain.OperationHeadscaleReissue
	headscaleReadOperation := operation == domain.OperationHeadscaleUserList || operation == domain.OperationPreauthKeyList || operation == domain.OperationDeviceList
	headscaleUserCreateOperation := operation == domain.OperationHeadscaleUserCreate
	headscaleLifecycleOperation := operation == domain.OperationPreauthKeyCreate || operation == domain.OperationPreauthKeyRevoke || operation == domain.OperationDeviceExpire
	connectorBindingOperation := operation == domain.OperationConnectorBindingSet
	connectorVerifyOperation := operation == domain.OperationConnectorVerify
	connectorLoginOperation := operation == domain.OperationConnectorLogin
	if connectorBindingOperation || connectorVerifyOperation || connectorLoginOperation {
		target = domain.OperationTarget{Kind: domain.OperationTargetConnector}
	}
	if headscaleControlOperation || headscaleReissueOperation {
		target = domain.OperationTarget{Kind: domain.OperationTargetHeadscale}
	}
	if operation == domain.OperationPreauthKeyCreate {
		id, ok := firstExact(query["user_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetHeadscaleUser, ID: id}
	} else if operation == domain.OperationPreauthKeyRevoke {
		id, ok := firstExact(query["key_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetPreauthKey, ID: id}
	} else if operation == domain.OperationDeviceExpire {
		id, ok := firstExact(query["device_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetDevice, ID: id}
	} else if headscaleReadOperation || headscaleUserCreateOperation {
		target = domain.OperationTarget{Kind: domain.OperationTargetHeadscale}
	}
	resourceOperation := operation == domain.OperationResourceCreate || operation == domain.OperationResourceUpdate
	resourceDeleteOperation := operation == domain.OperationResourceDelete
	processOperation := operation == domain.OperationProcessStart || operation == domain.OperationProcessStop
	publishOperation := operation == domain.OperationPublish
	basicOperation := operation == domain.OperationManagedBasicCreate || operation == domain.OperationManagedBasicRotate || operation == domain.OperationManagedBasicDelete
	staticOperation := operation == domain.OperationStaticRootRegister || operation == domain.OperationExternalHTPasswdRegister
	managementHTTPSOperation := operation == domain.OperationManagementHTTPSConfigure
	statusOperation := operation == domain.OperationStatus
	productReadOperation := operation == domain.OperationDiagnostics || operation == domain.OperationConfigurationExport || operation == domain.OperationJobList || operation == domain.OperationJobDetail
	if operation != domain.OperationAdminTokenRotate && operation != domain.OperationCloseAll && operation != domain.OperationUnpublish && !headscaleOperation && !headscaleControlOperation && !headscaleReissueOperation && !headscaleReadOperation && !headscaleUserCreateOperation && !headscaleLifecycleOperation && !connectorBindingOperation && !connectorVerifyOperation && !connectorLoginOperation && !resourceOperation && !resourceDeleteOperation && !processOperation && !publishOperation && !basicOperation && !staticOperation && !managementHTTPSOperation && !statusOperation && !productReadOperation || s.config.Actions == nil {
		reject(writer, http.StatusNotFound)
		return
	}
	s.barrier.Lock()
	principal, ok := s.authenticate(request, true)
	s.barrier.Unlock()
	if !ok {
		if auditErr := s.appendActionAudit(operation, target, "unknown", "failed", "authentication_failed"); auditErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		reject(writer, http.StatusUnauthorized)
		return
	}
	lease := s.beginAction(request.Context(), principal, operation == domain.OperationAdminTokenRotate && !planRoute)
	if lease == nil {
		s.barrier.RLock()
		valid := s.config.Sessions.Valid(principal)
		s.barrier.RUnlock()
		if !valid {
			if auditErr := s.appendActionAudit(operation, target, s.config.Sessions.Identity(principal), "failed", "authentication_failed"); auditErr != nil {
				reject(writer, http.StatusServiceUnavailable)
				return
			}
			reject(writer, http.StatusUnauthorized)
			return
		}
		if auditErr := s.appendActionAudit(operation, target, s.config.Sessions.Identity(principal), "failed", "action_conflict"); auditErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		reject(writer, http.StatusConflict)
		return
	}
	request = request.WithContext(lease.ctx)
	if !s.revalidateAction(lease) {
		auditErr := s.appendActionAudit(operation, target, s.config.Sessions.Identity(principal), "cancelled", "action_cancelled")
		s.endAction(lease)
		if auditErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		reject(writer, http.StatusUnauthorized)
		return
	}
	responseWriter := writer
	bufferedWriter := &actionResponseWriter{header: make(http.Header)}
	writer = bufferedWriter
	actionFailed := false
	actionErrorCode := ""
	actionErrorTyped := false
	secretResponse := false
	auditActor := s.config.Sessions.Identity(principal)
	reject := func(writer http.ResponseWriter, status int) {
		actionFailed = true
		actionErrorCode = httpErrorCode(status)
		rejectWithError(writer, status, nil)
	}
	progressAction := !planRoute && progressOperation(operation)
	var actionDone, heartbeatDone chan struct{}
	var started time.Time
	if progressAction {
		started = time.Now().UTC()
		s.actionEvent(principal, lease.id, operation, target, "running", "Action started; live status polling is active", started)
		actionDone = make(chan struct{})
		heartbeatDone = make(chan struct{})
		go func() {
			defer close(heartbeatDone)
			s.actionHeartbeat(actionDone, principal, lease, operation, target, started)
		}()
	}
	defer func() {
		result := "succeeded"
		if actionFailed {
			result = "failed"
		}
		if lease.ctx.Err() != nil {
			result = "cancelled"
			if !actionErrorTyped {
				actionErrorCode = "action_cancelled"
			}
		}
		if auditErr := s.appendActionAudit(operation, target, auditActor, result, actionErrorCode); auditErr != nil {
			if secretResponse {
				_, _ = bufferedWriter.commit(responseWriter)
			} else {
				actionFailed = true
				actionErrorCode = httpErrorCode(http.StatusServiceUnavailable)
				bufferedWriter.discard()
				rejectWithError(responseWriter, http.StatusServiceUnavailable, nil)
			}
		} else {
			_, _ = bufferedWriter.commit(responseWriter)
		}
		if progressAction {
			close(actionDone)
			<-heartbeatDone
			state := "completed"
			message := "Action completed"
			if actionFailed {
				state = "failed"
				message = "Action failed; review status and Job result"
			}
			if lease.ctx.Err() != nil {
				state = "cancelled"
				message = "Action cancellation requested"
			}
			s.actionEvent(principal, lease.id, operation, target, state, message, started)
		}
		s.endAction(lease)
	}()
	actionFailure := func(err error, status int) {
		actionFailed = true
		var rejected application.HelperRejection
		if errors.As(err, &rejected) {
			actionErrorCode = rejected.Code
			actionErrorTyped = true
			s.sessionStatusJSON(writer, principal, http.StatusConflict, map[string]string{"error": rejected.Code, "error_code": rejected.Code, "job_id": rejected.JobID})
			return
		}
		actionErrorCode = httpErrorCode(status)
		rejectWithError(writer, status, err)
	}
	if planRoute && (headscaleOperation || headscaleReadOperation || headscaleUserCreateOperation || connectorBindingOperation || connectorVerifyOperation || productReadOperation || resourceOperation || processOperation || staticOperation || managementHTTPSOperation || statusOperation || basicOperation && operation != domain.OperationManagedBasicDelete && operation != domain.OperationManagedBasicRotate) {
		reject(writer, http.StatusNotFound)
		return
	}
	if planRoute && !headscaleControlOperation && !headscaleReissueOperation && !headscaleLifecycleOperation && !connectorLoginOperation {
		if !requireExactEmptyJSONBody(writer, request) {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: domain.OperationPlan, Target: target, Payload: application.PlanPayload{Operation: operation, Target: target}})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusNotFound)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if productReadOperation {
		if planRoute {
			reject(writer, http.StatusNotFound)
			return
		}
		if !requireExactEmptyJSONBody(writer, request) {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: application.EmptyPayload{}})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if connectorVerifyOperation {
		if planRoute {
			reject(writer, http.StatusNotFound)
			return
		}
		if !requireExactEmptyJSONBody(writer, request) {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: application.EmptyPayload{}})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if connectorBindingOperation {
		if planRoute {
			reject(writer, http.StatusNotFound)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, 4096)
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.ConnectorBindingPayload
		if decodeExactJSON(data, &payload) != nil || payload.ControlURL == "" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if connectorLoginOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 8192)
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var wire struct {
			PlanID       string `json:"plan_id,omitempty"`
			Confirmation string `json:"confirmation,omitempty"`
			AuthKey      []byte `json:"auth_key,omitempty"`
		}
		if decodeExactJSON(data, &wire) != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		payload := application.ConnectorLoginActionPayload{PlanID: wire.PlanID, Confirmation: wire.Confirmation, AuthKey: wire.AuthKey}
		wire.AuthKey = nil
		if planRoute {
			if payload.PlanID != "" || payload.Confirmation != "" || len(payload.AuthKey) != 0 {
				clear(payload.AuthKey)
				reject(writer, http.StatusBadRequest)
				return
			}
		} else if payload.PlanID == "" || payload.Confirmation != "login" || len(payload.AuthKey) == 0 {
			clear(payload.AuthKey)
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		clear(payload.AuthKey)
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if headscaleReadOperation {
		if planRoute {
			reject(writer, http.StatusNotFound)
			return
		}
		if !requireExactEmptyJSONBody(writer, request) {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: application.EmptyPayload{}})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if headscaleUserCreateOperation {
		if planRoute {
			reject(writer, http.StatusNotFound)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, 4096)
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.HeadscaleUserPayload
		if decodeExactJSON(data, &payload) != nil || payload.Name == "" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if headscaleLifecycleOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 4096)
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.HeadscaleLifecyclePayload
		if decodeExactJSON(data, &payload) != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		if operation != domain.OperationPreauthKeyCreate && payload.ExpirationSeconds != 0 {
			reject(writer, http.StatusBadRequest)
			return
		}
		if operation == domain.OperationPreauthKeyCreate && payload.ExpirationSeconds == 0 {
			payload.ExpirationSeconds = 3600
		}
		if planRoute {
			if payload.PlanID != "" || payload.Confirmation != "" {
				reject(writer, http.StatusBadRequest)
				return
			}
		} else {
			want := "create"
			if operation == domain.OperationPreauthKeyRevoke {
				want = "revoke"
			}
			if operation == domain.OperationDeviceExpire {
				want = "expire"
			}
			if payload.PlanID == "" || payload.Confirmation != want {
				reject(writer, http.StatusBadRequest)
				return
			}
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		if operation == domain.OperationPreauthKeyCreate {
			if value, ok := result.Payload.(application.HeadscaleKeyResult); ok {
				secretResponse = len(value.Secret) != 0
				defer clear(value.Secret)
				result.Payload = value
			}
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if headscaleReissueOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 8192)
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.HeadscaleReissuePayload
		if decodeExactJSON(data, &payload) != nil || payload.Certificate.DirectoryURL == "" || !payload.Certificate.TermsAccepted {
			reject(writer, http.StatusBadRequest)
			return
		}
		if planRoute {
			if payload.PlanID != "" || payload.Confirmation != "" {
				reject(writer, http.StatusBadRequest)
				return
			}
		} else if payload.PlanID == "" || payload.Confirmation != "reissue" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: domain.OperationTarget{Kind: domain.OperationTargetHeadscale}, Payload: payload})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if headscaleControlOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 8192)
		data, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.HeadscaleDeployPayload
		if decodeExactJSON(data, &payload) != nil || payload.Certificate.DirectoryURL == "" || !payload.Certificate.TermsAccepted {
			reject(writer, http.StatusBadRequest)
			return
		}
		if planRoute {
			if payload.PlanID != "" || payload.Confirmation != "" {
				reject(writer, http.StatusBadRequest)
				return
			}
		} else if payload.PlanID == "" || payload.Confirmation != "deploy" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: domain.OperationTarget{Kind: domain.OperationTargetHeadscale}, Payload: payload})
		if invokeErr != nil {
			actionFailure(invokeErr, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if statusOperation {
		if !requireExactEmptyJSONBody(writer, request) {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: application.DomainStatusPayload{}})
		if err != nil {
			actionFailure(err, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if staticOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 4096)
		data, err := io.ReadAll(request.Body)
		if err != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.StaticRootPayload
		if decodeExactJSON(data, &payload) != nil || payload.Path == "" || payload.Confirmation != "register" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if err != nil {
			actionFailure(err, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if basicOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 4096)
		data, err := io.ReadAll(request.Body)
		if err != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.ManagedBasicPayload
		if decodeExactJSON(data, &payload) != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		if operation == domain.OperationManagedBasicCreate {
			if payload.Confirmation != "generate" || payload.Username == "" || payload.PlanID != "" {
				reject(writer, http.StatusBadRequest)
				return
			}
		} else if operation == domain.OperationManagedBasicRotate {
			if payload.Confirmation != "rotate" || payload.Username != "" || payload.PlanID == "" {
				reject(writer, http.StatusBadRequest)
				return
			}
		} else if payload.Confirmation != "delete" || payload.Username != "" || payload.PlanID == "" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if err != nil {
			actionFailure(err, http.StatusServiceUnavailable)
			return
		}
		if value, ok := result.Payload.(application.ManagedBasicActionResult); ok {
			secretResponse = len(value.Password) != 0
			defer clear(value.Password)
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if headscaleOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 4096)
		data, err := io.ReadAll(request.Body)
		if err != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.HeadscaleInitializePayload
		if decodeExactJSON(data, &payload) != nil || payload.ControlDomain == "" || payload.MagicDNSNamespace == "" || payload.Confirmation != "initialize" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if err != nil {
			actionFailure(err, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if resourceOperation || processOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 16<<10)
		data, err := io.ReadAll(request.Body)
		if err != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload any = application.ProcessMutationPayload{}
		if resourceOperation {
			if len(data) == 0 {
				reject(writer, http.StatusBadRequest)
				return
			}
			if operation == domain.OperationResourceCreate {
				var value domain.ResourceCreateRequest
				if decodeExactJSON(data, &value) != nil || domain.ValidateResourceCreateRequest(value) != nil {
					reject(writer, http.StatusBadRequest)
					return
				}
				payload = application.ResourceMutationPayload{Create: &value}
			} else {
				var value domain.ResourceUpdateRequest
				if decodeExactJSON(data, &value) == nil && domain.ValidateResourceUpdateRequest(value) == nil {
					payload = application.ResourceMutationPayload{Update: &value}
				} else {
					var publication application.DomainPublicationUpdate
					if decodeExactJSON(data, &publication) != nil || domain.ValidateDomainPublicationUpdate(publication) != nil {
						reject(writer, http.StatusBadRequest)
						return
					}
					payload = application.ResourceMutationPayload{Publication: &publication}
				}
			}
		} else if len(bytes.TrimSpace(data)) != 0 {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if err != nil {
			actionFailure(err, http.StatusServiceUnavailable)
			return
		}
		if value, ok := result.Payload.(application.ResourceCreateResult); ok {
			secretResponse = len(value.Password) != 0
			defer clear(value.Password)
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if managementHTTPSOperation {
		request.Body = http.MaxBytesReader(writer, request.Body, 16<<10)
		data, err := io.ReadAll(request.Body)
		if err != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload application.ManagementHTTPSPayload
		if decodeExactJSON(data, &payload) != nil || payload.Confirmation != "configure" {
			reject(writer, http.StatusBadRequest)
			return
		}
		candidate := payload.Config
		candidate.Phase = domain.ManagementHTTPSPending
		candidate.Generation = 1
		candidate.CertificateBundle = nil
		candidate.LastFailureCode = ""
		if err := domain.ValidateManagementHTTPSConfig(candidate); err != nil {
			reject(writer, http.StatusBadRequest)
			return
		}
		payload.Config = candidate
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if err != nil {
			actionFailure(err, http.StatusServiceUnavailable)
			return
		}
		value, ok := result.Payload.(application.ManagementHTTPSActionResult)
		if !ok || value.JobID == "" {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, value)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 4096)
	data, err := io.ReadAll(request.Body)
	if err != nil {
		reject(writer, http.StatusBadRequest)
		return
	}
	defer clear(data)
	var payload application.ConfirmationPayload
	confirmation := "rotate"
	switch operation {
	case domain.OperationCloseAll:
		confirmation = "close"
	case domain.OperationUnpublish:
		confirmation = "unpublish"
	case domain.OperationPublish:
		confirmation = "publish"
	case domain.OperationResourceDelete:
		confirmation = "delete"
	}
	if decodeExactJSON(data, &payload) != nil || payload.PlanID == "" || payload.Confirmation != confirmation {
		reject(writer, http.StatusBadRequest)
		return
	}
	result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
	if err != nil {
		actionFailed = true
		var rejected application.HelperRejection
		if errors.As(err, &rejected) {
			actionErrorCode = rejected.Code
			actionErrorTyped = true
			s.sessionStatusJSON(writer, principal, http.StatusConflict, map[string]string{"error": rejected.Code, "error_code": rejected.Code, "job_id": rejected.JobID})
			return
		}
		if operation == domain.OperationAdminTokenRotate {
			reconcileCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			reply, reconcileErr := HelperAdminTokenReconcile(reconcileCtx)
			cancel()
			current := reply.Digest
			s.barrier.Lock()
			s.cancelActions(nil, lease)
			if reconcileErr != nil || current == "" {
				s.config.Sessions.InvalidateFingerprint("unavailable")
			} else {
				s.config.Sessions.RequireFingerprint(current)
			}
			s.barrier.Unlock()
		}
		actionErrorCode = httpErrorCode(http.StatusServiceUnavailable)
		rejectWithError(writer, http.StatusServiceUnavailable, err)
		return
	}
	if operation == domain.OperationCloseAll || operation == domain.OperationUnpublish {
		contraction, ok := result.Payload.(application.ContractionResult)
		if !ok || contraction.Outcome == "" {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		payload := struct {
			JobID             string `json:"job_id,omitempty"`
			JobResult         string `json:"job_result,omitempty"`
			PlanID            string `json:"plan_id,omitempty"`
			Emergency         bool   `json:"emergency,omitempty"`
			Outcome           string `json:"outcome"`
			AccessClosed      bool   `json:"access_closed"`
			SharedIngressDown bool   `json:"shared_ingress_down"`
			AccessMayRemain   bool   `json:"access_may_remain"`
		}{contraction.JobID, contraction.JobResult, contraction.PlanID, contraction.Emergency, contraction.Outcome, contraction.AccessClosed, contraction.SharedIngressDown, contraction.AccessMayRemain}
		s.sessionJSON(writer, principal, payload)
		return
	}
	if operation == domain.OperationResourceDelete {
		deletion, ok := result.Payload.(application.ResourceDeleteResult)
		if !ok || deletion.JobID == "" {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, deletion)
		return
	}
	if operation == domain.OperationPublish {
		publication, ok := result.Payload.(application.PublicationResult)
		if !ok || publication.JobID == "" || publication.JobResult != "succeeded" && publication.JobResult != "partial" {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, publication)
		return
	}
	rotation, ok := result.Payload.(application.RotationResult)
	if !ok || rotation.JobID == "" || len(rotation.Token) == 0 {
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	defer clear(rotation.Token)
	current, sourceErr := s.config.Verifier.Source(request.Context())
	s.barrier.Lock()
	defer s.barrier.Unlock()
	s.cancelActions(nil, lease)
	if sourceErr != nil || current != rotation.Fingerprint {
		if sourceErr != nil {
			s.config.Sessions.InvalidateFingerprint("unavailable")
		} else {
			s.config.Sessions.CommitTokenRotation(current)
		}
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	s.config.Sessions.CommitTokenRotation(rotation.Fingerprint)
	secretResponse = true
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.isHTTPSProxyRequest(request), SameSite: http.SameSiteStrictMode})
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		JobID string `json:"job_id"`
		Token string `json:"token"`
	}{rotation.JobID, string(rotation.Token)})
}

func (s *Server) authenticate(request *http.Request, mutation bool) (session.Principal, bool) {
	if presentOriginInvalid(request, s.originFor(request)) {
		return session.Principal{}, false
	}
	selector, ok := exactCookie(request, session.SelectorCookie)
	if !ok {
		return session.Principal{}, false
	}
	proof, ok := exactHeader(request, session.ProofHeader)
	if !ok {
		return session.Principal{}, false
	}
	csrf := ""
	if mutation {
		var valid bool
		csrf, valid = exactHeader(request, session.CSRFHeader)
		if !valid {
			return session.Principal{}, false
		}
	}
	fingerprint, err := s.config.Verifier.Source(request.Context())
	if err != nil {
		s.cancelActions(nil, nil)
		s.config.Sessions.InvalidateFingerprint("unavailable")
		return session.Principal{}, false
	}
	if !s.config.Sessions.RequireFingerprint(fingerprint) {
		s.cancelActions(nil, nil)
		return session.Principal{}, false
	}
	principal, err := s.config.Sessions.Authenticate(selector, proof, csrf, s.originFor(request), fingerprint, mutation)
	return principal, err == nil
}
func (s *Server) origin() string { return "http://" + s.config.Authority }

func (s *Server) isHTTPSProxyRequest(request *http.Request) bool {
	if request == nil {
		return false
	}
	return request.TLS != nil || len(request.Header.Values("X-Forwarded-Proto")) == 1 && request.Header.Get("X-Forwarded-Proto") == "https"
}

func (s *Server) originFor(request *http.Request) string {
	if s.isHTTPSProxyRequest(request) && request.Host != "" {
		return "https://" + request.Host
	}
	return s.origin()
}

func securityHeaders(writer http.ResponseWriter) {
	h := writer.Header()
	h.Set("Cache-Control", "no-store, private")
	h.Set("Content-Security-Policy", fixedCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

type actionResponseWriter struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func (writer *actionResponseWriter) Header() http.Header { return writer.header }

func (writer *actionResponseWriter) WriteHeader(status int) {
	if writer.wroteHeader {
		return
	}
	writer.status = status
	writer.wroteHeader = true
}

func (writer *actionResponseWriter) Write(payload []byte) (int, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.body.Write(payload)
}

func (writer *actionResponseWriter) discard() {
	writer.header = make(http.Header)
	writer.body.Reset()
	writer.status = 0
	writer.wroteHeader = false
}

func (writer *actionResponseWriter) commit(destination http.ResponseWriter) (int, error) {
	for key, values := range writer.header {
		destination.Header()[key] = append([]string(nil), values...)
	}
	if writer.wroteHeader {
		destination.WriteHeader(writer.status)
	}
	return destination.Write(writer.body.Bytes())
}

type errorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code,omitempty"`
}

func reject(writer http.ResponseWriter, status int) {
	rejectWithError(writer, status, nil)
}

func rejectWithError(writer http.ResponseWriter, status int, _ error) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(errorResponse{Error: http.StatusText(status), ErrorCode: httpErrorCode(status)})
}

func httpErrorCode(status int) string {
	text := strings.TrimSpace(strings.ToLower(http.StatusText(status)))
	return strings.ReplaceAll(text, " ", "_")
}

func exactOrigin(request *http.Request, want string) bool {
	values := request.Header.Values("Origin")
	return len(values) == 1 && values[0] == want && !strings.Contains(values[0], ",")
}

func presentOriginInvalid(request *http.Request, want string) bool {
	values := request.Header.Values("Origin")
	return len(values) != 0 && (len(values) != 1 || values[0] != want || strings.Contains(values[0], ","))
}

func exactHeader(request *http.Request, name string) (string, bool) {
	return firstExact(request.Header.Values(name))
}

func firstExact(values []string) (string, bool) {
	if len(values) != 1 || values[0] == "" || strings.Contains(values[0], ",") {
		return "", false
	}
	return values[0], true
}

func progressOperation(operation domain.OperationCode) bool {
	switch operation {
	case domain.OperationAdminTokenRotate, domain.OperationHeadscaleInitialize, domain.OperationHeadscaleControlDeploy, domain.OperationHeadscaleReissue, domain.OperationHeadscaleUserCreate, domain.OperationPreauthKeyCreate, domain.OperationPreauthKeyRevoke, domain.OperationDeviceExpire, domain.OperationConnectorBindingSet, domain.OperationConnectorLogin, domain.OperationResourceDelete, domain.OperationResourceCreate, domain.OperationResourceUpdate, domain.OperationPublish, domain.OperationUnpublish, domain.OperationCloseAll, domain.OperationProcessStart, domain.OperationProcessStop, domain.OperationManagedBasicCreate, domain.OperationManagedBasicRotate, domain.OperationManagedBasicDelete, domain.OperationStaticRootRegister, domain.OperationExternalHTPasswdRegister:
		return true
	default:
		return false
	}
}

func validActionQuery(operation domain.OperationCode, query url.Values) bool {
	selector := ""
	optional := false
	switch operation {
	case domain.OperationResourceUpdate, domain.OperationResourceDelete, domain.OperationPublish, domain.OperationUnpublish, domain.OperationProcessStart, domain.OperationProcessStop, domain.OperationManagedBasicCreate, domain.OperationStaticRootRegister, domain.OperationExternalHTPasswdRegister:
		selector = "resource_id"
	case domain.OperationManagedBasicRotate, domain.OperationManagedBasicDelete:
		selector = "credential_id"
	case domain.OperationPreauthKeyCreate:
		selector = "user_id"
	case domain.OperationPreauthKeyRevoke:
		selector = "key_id"
	case domain.OperationDeviceExpire:
		selector = "device_id"
	case domain.OperationJobDetail:
		selector = "job_id"
	case domain.OperationStatus:
		selector = "resource_id"
		optional = true
	}
	if selector == "" {
		return len(query) == 0
	}
	if len(query) == 0 {
		return optional
	}
	if len(query) != 1 {
		return false
	}
	_, ok := firstExact(query[selector])
	return ok
}

func exactCookie(request *http.Request, name string) (string, bool) {
	values := []string{}
	for _, header := range request.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			key, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && key == name {
				values = append(values, value)
			}
		}
	}
	return firstExact(values)
}

func InputDigest(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func requireExactEmptyJSONBody(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumEmptyPayloadBytes)
	data, err := io.ReadAll(request.Body)
	defer clear(data)
	if err != nil {
		return false
	}
	var payload application.EmptyPayload
	return decodeExactJSON(data, &payload) == nil
}

func decodeExactJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, payload) {
		return fmt.Errorf("noncanonical JSON")
	}
	return nil
}

//go:embed assets/app.css
var appCSS string

//go:embed assets/app.js
var appJS string

//go:embed assets/shell.html
var uiShell string

var (
	appCSSPath = func() string {
		digest := sha256.Sum256([]byte(appCSS))
		return "/assets/app." + hex.EncodeToString(digest[:4]) + ".css"
	}()
	appJSPath = func() string {
		digest := sha256.Sum256([]byte(appJS))
		return "/assets/app." + hex.EncodeToString(digest[:4]) + ".js"
	}()
)
