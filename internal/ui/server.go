// Package ui serves the exact loopback Management authority.
package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"lanpanel/internal/application"
	"lanpanel/internal/domain"
	"lanpanel/internal/session"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	fixedCSP                  = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'"
	WebSocketSubprotocol      = "lanpanel.events.v1"
	maximumLoginBytes         = 4096
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
}
type Server struct {
	config          Config
	http            *http.Server
	barrier         sync.RWMutex
	output          sync.Mutex
	actionMu        sync.Mutex
	actions         map[*actionLease]struct{}
	rotationPending bool
}
type actionLease struct {
	principal session.Principal
	ctx       context.Context
	cancel    context.CancelFunc
	exclusive bool
}
type socket struct {
	connection *websocket.Conn
	mu         sync.Mutex
}

func (s *socket) Close() error {
	return s.connection.Close(websocket.StatusPolicyViolation, "session invalidated")
}

func (s *socket) Write(ctx context.Context, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connection.Write(ctx, websocket.MessageText, payload)
}

func New(config Config) (*Server, error) {
	if config.Listener == nil || config.Authority == "" || config.InstallationFingerprint == "" || config.Verifier == nil || config.Sessions == nil || config.Profile == nil {
		return nil, fmt.Errorf("management UI config is incomplete")
	}
	server := &Server{config: config, actions: map[*actionLease]struct{}{}}
	server.http = &http.Server{Handler: server, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return server, nil
}
func (s *Server) Serve() error { return s.http.Serve(s.config.Listener) }
func (s *Server) beginAction(parent context.Context, principal session.Principal, exclusive bool) *actionLease {
	ctx, cancel := context.WithCancel(parent)
	lease := &actionLease{principal: principal, ctx: ctx, cancel: cancel, exclusive: exclusive}
	s.actionMu.Lock()
	if s.rotationPending {
		s.actionMu.Unlock()
		cancel()
		return nil
	}
	if exclusive {
		s.rotationPending = true
	}
	existing := make([]*actionLease, 0, len(s.actions))
	for current := range s.actions {
		existing = append(existing, current)
	}
	s.actions[lease] = struct{}{}
	s.actionMu.Unlock()
	if exclusive {
		for _, current := range existing {
			current.cancel()
		}
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
	leases := make([]*actionLease, 0, len(s.actions))
	for lease := range s.actions {
		if lease != except && (principal == nil || lease.principal == *principal) {
			leases = append(leases, lease)
		}
	}
	s.actionMu.Unlock()
	for _, lease := range leases {
		lease.cancel()
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
	s.config.Sessions.Close()
	return s.http.Shutdown(ctx)
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	securityHeaders(writer)
	actionQuery := request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/api/actions/") && len(request.URL.Query()) == 1 && (request.URL.Query().Has("resource_id") || request.URL.Query().Has("credential_id") || request.URL.Query().Has("user_id") || request.URL.Query().Has("key_id") || request.URL.Query().Has("device_id") || request.URL.Query().Has("job_id"))
	if request.Host != s.config.Authority || request.URL.RawQuery != "" && !actionQuery || request.URL.RawPath != "" {
		reject(writer, http.StatusMisdirectedRequest)
		return
	}
	if request.Method == http.MethodHead {
		request.Method = http.MethodGet
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/":
		s.shell(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/assets/app.8d13f0c2.css":
		if presentOriginInvalid(request, s.origin()) {
			reject(writer, http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "text/css; charset=utf-8")
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = io.WriteString(writer, appCSS)
	case request.Method == http.MethodGet && request.URL.Path == "/assets/app.39499dde.js":
		if presentOriginInvalid(request, s.origin()) {
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
	if presentOriginInvalid(request, s.origin()) {
		reject(writer, http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(writer, `<!doctype html><html><head><meta charset="utf-8"><title>LanPanel</title><link rel="stylesheet" href="/assets/app.8d13f0c2.css"></head><body><main><h1>LanPanel</h1><p id="fingerprint">`+template.HTMLEscapeString(s.config.InstallationFingerprint)+`</p><form id="login" method="post" action="/login" enctype="application/x-www-form-urlencoded"><label>Admin token<input name="token" type="password" autocomplete="current-password"></label><button>Login</button></form><form id="headscale-initialize" hidden><fieldset><legend>Initialize optional Headscale trust domain</legend><p>Policy: trusted_mesh (all members trust one another). Identity and database cannot be adopted, disabled, removed, or renamed.</p><label>Control domain<input name="control_domain" required></label><label>MagicDNS namespace<input name="magicdns_namespace" required></label><label>Artifact source<select name="source_kind"><option value="official_canonical_artifact">official</option><option value="mirror">mirror</option><option value="offline">offline</option></select></label><label>Mirror URL<input name="mirror_url"></label><label>Offline archive path<input name="offline_path"></label><label>Download proxy URL<input name="proxy_url"></label><button>Initialize Headscale identity</button></fieldset></form><form id="headscale-control" hidden><fieldset><legend>Deploy Headscale control</legend><label>ACME challenge<select name="challenge_method"><option value="http-01">http-01</option><option value="dns-01">dns-01</option></select></label><label>ACME directory URL<input name="directory_url" required></label><p>LanPanel uses its installation-managed ACME account key and contact.</p><label>DNS provider<input name="dns_provider"></label><label>Provider profile path<input name="provider_profile_path"></label><label>Authoritative zone<input name="authoritative_zone"></label><label><input name="terms_accepted" type="checkbox" required>Approved ACME terms</label><button>Deploy control ingress</button></fieldset></form><button id="headscale-reissue" hidden>Reissue Headscale certificate</button><form id="resource-create" hidden><fieldset><legend>Create App resource</legend><label>Canonical App resource JSON<textarea name="resource_json" required rows="8"></textarea></label><button>Create resource</button></fieldset></form><form id="resource-update-json" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><label>Canonical resource update JSON<textarea name="resource_json" required rows="8"></textarea></label><button>Update resource</button></form><form id="process-control" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><button name="action" value="start">Start process</button><button name="action" value="stop">Stop process</button></form><form id="resource-delete" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><button>Delete resource</button></form><form id="headscale-user-create" hidden><label>User name<input name="name" required></label><button>Create Headscale user</button></form><form id="headscale-key-create" hidden><label>User ID<input name="user_id" required></label><label>Expiration seconds<input name="expiration_seconds" type="number" min="1" max="86400" value="3600"></label><button>Create preauth key</button></form><form id="headscale-key-revoke" hidden><label>Key ID<input name="key_id" required></label><button>Revoke preauth key</button></form><form id="headscale-device-expire" hidden><label>Device ID<input name="device_id" required></label><button>Expire device</button></form><p hidden id="headscale-reads"><button data-read="headscale_user_list">List users</button><button data-read="preauth_key_list">List keys</button><button data-read="device_list">List devices</button></p><form id="connector-binding" hidden><label>Control URL<input name="control_url" type="url" required></label><button>Set connector binding</button></form><form id="connector-login" hidden><label>One-time auth key<input name="auth_key" type="password" required autocomplete="off"></label><button>Login connector</button></form><button id="connector-verify" hidden>Verify connector</button><p hidden id="product-reads"><button data-read="status">System status</button><button data-read="diagnostics">Diagnostics</button><button data-read="configuration_export">Configuration export</button><button data-read="job_list">Jobs</button></p><form id="job-detail" hidden><label>Job ID<input name="job_id" required pattern="job_[0-9a-f]{64}"></label><button>Job detail</button></form><form id="publish" hidden><label>Resource ID<input id="publish-resource" name="resource_id" required pattern="res_[0-9a-f]{32}"></label><button>Publish App</button></form><form id="domain-config" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><label>Canonical domain<input name="canonical_domain" required></label><label>Aliases (comma-separated)<input name="aliases"></label><label>Access mode<select name="access_mode"><option value="public">public</option><option value="application_managed">application_managed</option><option value="basic">basic</option></select></label><label>Credential ID<input name="credential_id" pattern="cred_[0-9a-f]{32}"></label><label>Basic CIDRs (comma-separated)<input name="cidrs"></label><label>Static root ID<input name="static_root_id" pattern="static_[0-9a-f]{32}"></label><label>Static mappings (one URL|relative|file-or-directory|authenticated-or-anonymous per line)<textarea name="static_mappings" rows="6" placeholder="/assets/|public|directory|anonymous"></textarea></label><label><input name="goaccess_enabled" type="checkbox">Enable isolated GoAccess</label><label>GoAccess external htpasswd credential ID<input name="goaccess_credential_id" pattern="cred_[0-9a-f]{32}"></label><label>GoAccess CIDRs (comma-separated)<input name="goaccess_cidrs"></label><label>GoAccess dashboard path<input name="goaccess_dashboard_path" placeholder="/__lanpanel/goaccess/"></label><label>GoAccess WebSocket path<input name="goaccess_websocket_path" placeholder="/__lanpanel/goaccess-ws"></label><label>ACME challenge<select name="challenge_method"><option value="http-01">http-01</option><option value="dns-01">dns-01</option></select></label><label>ACME directory URL<input name="directory_url" required></label><p>LanPanel uses its installation-managed ACME account key and contact.</p><label>DNS provider<input name="dns_provider"></label><label>Provider profile path<input name="provider_profile_path"></label><label>Authoritative zone<input name="authoritative_zone"></label><label><input name="terms_accepted" type="checkbox" required>Approved ACME terms</label><button>Save pending domain HTTPS config</button></form><form id="basic-create" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><label>Basic username<input name="username" required pattern="[A-Za-z0-9][A-Za-z0-9._@-]{0,63}"></label><button>Create Managed Basic</button></form><form id="basic-rotate" hidden><label>Credential ID<input name="credential_id" required pattern="cred_[0-9a-f]{32}"></label><button>Rotate Managed Basic</button></form><form id="basic-delete" hidden><label>Credential ID<input name="credential_id" required pattern="cred_[0-9a-f]{32}"></label><button>Delete Managed Basic</button></form><form id="static-register" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><label>Static root absolute path<input name="path" required></label><button>Register static root</button></form><form id="external-htpasswd-register" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><label>External htpasswd absolute path<input name="path" required></label><button>Register external htpasswd</button></form><form id="domain-status" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><button>Check domain source status</button></form><form id="unpublish" hidden><label>Resource ID<input name="resource_id" required pattern="res_[0-9a-f]{32}"></label><button>Unpublish App</button></form><button id="close-all" hidden>Close all App ingress</button><button id="rotate" hidden>Rotate admin token</button><button id="logout" hidden>Logout</button><p id="status"></p></main><script src="/assets/app.39499dde.js" defer></script></body></html>`)
}

func (s *Server) login(writer http.ResponseWriter, request *http.Request) {
	contentType, ok := exactHeader(request, "Content-Type")
	if !exactOrigin(request, s.origin()) || !ok || contentType != "application/x-www-form-urlencoded" {
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
		reject(writer, http.StatusUnauthorized)
		return
	}
	credentials, err := s.config.Sessions.Issue(s.origin(), fingerprint)
	s.barrier.Unlock()
	if err != nil {
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]string{"proof": credentials.Proof, "csrf": credentials.CSRF})
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
	s.barrier.Lock()
	defer s.barrier.Unlock()
	s.output.Lock()
	defer s.output.Unlock()
	if !exactOrigin(request, s.origin()) {
		reject(writer, http.StatusForbidden)
		return
	}
	principal, ok := s.authenticate(request, true)
	if !ok {
		reject(writer, http.StatusUnauthorized)
		return
	}
	s.cancelActions(&principal, nil)
	s.config.Sessions.Logout(principal)
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) events(writer http.ResponseWriter, request *http.Request) {
	if !exactOrigin(request, s.origin()) {
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
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "closed") }()
	authContext, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	kind, payload, err := connection.Read(authContext)
	if err != nil || kind != websocket.MessageText || len(payload) == 0 || len(payload) > maximumWebSocketAuthBytes {
		_ = connection.Close(websocket.StatusPolicyViolation, "authentication required")
		return
	}
	var frame struct {
		Type  string `json:"type"`
		Proof string `json:"proof"`
	}
	if decodeExactJSON(payload, &frame) != nil || frame.Type != "auth" || frame.Proof == "" {
		clear(payload)
		_ = connection.Close(websocket.StatusPolicyViolation, "authentication required")
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
	principal, err := s.config.Sessions.AuthenticateSocket(selector, frame.Proof, s.origin(), fingerprint)
	if err != nil {
		s.barrier.RUnlock()
		return
	}
	managed := &socket{connection: connection}
	if s.config.Sessions.Attach(principal, managed) != nil {
		s.barrier.RUnlock()
		return
	}
	s.barrier.RUnlock()
	defer s.config.Sessions.Detach(principal, managed)
	sendContext, sendCancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer sendCancel()
	s.barrier.RLock()
	sendErr := s.config.Sessions.Send(principal, fingerprint, func() error { return managed.Write(sendContext, []byte(`{"type":"ready"}`)) })
	s.barrier.RUnlock()
	if sendErr != nil {
		return
	}
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
	if !exactOrigin(request, s.origin()) {
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
	target := domain.OperationTarget{Kind: domain.OperationTargetInstallation}
	resourceTarget := operation == domain.OperationUnpublish || operation == domain.OperationPublish || operation == domain.OperationResourceUpdate || operation == domain.OperationResourceDelete || operation == domain.OperationProcessStart || operation == domain.OperationProcessStop || operation == domain.OperationManagedBasicCreate || operation == domain.OperationStaticRootRegister || operation == domain.OperationExternalHTPasswdRegister
	if resourceTarget {
		resourceID, ok := firstExact(request.URL.Query()["resource_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetResource, ID: resourceID}
	}
	if operation == domain.OperationStatus {
		if values, present := request.URL.Query()["resource_id"]; present {
			resourceID, ok := firstExact(values)
			if !ok {
				reject(writer, http.StatusBadRequest)
				return
			}
			target = domain.OperationTarget{Kind: domain.OperationTargetResource, ID: resourceID}
		}
	}
	if operation == domain.OperationJobDetail {
		id, ok := firstExact(request.URL.Query()["job_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetJob, ID: id}
	}
	if operation == domain.OperationManagedBasicRotate || operation == domain.OperationManagedBasicDelete {
		credentialID, ok := firstExact(request.URL.Query()["credential_id"])
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
	if operation == domain.OperationPreauthKeyCreate {
		id, ok := firstExact(request.URL.Query()["user_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetHeadscaleUser, ID: id}
	} else if operation == domain.OperationPreauthKeyRevoke {
		id, ok := firstExact(request.URL.Query()["key_id"])
		if !ok {
			reject(writer, http.StatusBadRequest)
			return
		}
		target = domain.OperationTarget{Kind: domain.OperationTargetPreauthKey, ID: id}
	} else if operation == domain.OperationDeviceExpire {
		id, ok := firstExact(request.URL.Query()["device_id"])
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
	statusOperation := operation == domain.OperationStatus
	productReadOperation := operation == domain.OperationDiagnostics || operation == domain.OperationConfigurationExport || operation == domain.OperationJobList || operation == domain.OperationJobDetail
	if operation != domain.OperationAdminTokenRotate && operation != domain.OperationCloseAll && operation != domain.OperationUnpublish && !headscaleOperation && !headscaleControlOperation && !headscaleReissueOperation && !headscaleReadOperation && !headscaleUserCreateOperation && !headscaleLifecycleOperation && !connectorBindingOperation && !connectorVerifyOperation && !connectorLoginOperation && !resourceOperation && !resourceDeleteOperation && !processOperation && !publishOperation && !basicOperation && !staticOperation && !statusOperation && !productReadOperation || s.config.Actions == nil {
		reject(writer, http.StatusNotFound)
		return
	}
	s.barrier.Lock()
	principal, ok := s.authenticate(request, true)
	s.barrier.Unlock()
	if !ok {
		reject(writer, http.StatusUnauthorized)
		return
	}
	lease := s.beginAction(request.Context(), principal, operation == domain.OperationAdminTokenRotate)
	if lease == nil {
		reject(writer, http.StatusConflict)
		return
	}
	defer s.endAction(lease)
	request = request.WithContext(lease.ctx)
	actionFailure := func(err error, status int) {
		var rejected application.HelperRejection
		if errors.As(err, &rejected) {
			s.sessionStatusJSON(writer, principal, http.StatusConflict, map[string]string{"error_code": rejected.Code, "job_id": rejected.JobID})
			return
		}
		reject(writer, status)
	}
	if planRoute && (headscaleOperation || headscaleReadOperation || headscaleUserCreateOperation || connectorBindingOperation || connectorVerifyOperation || productReadOperation || resourceOperation || processOperation || staticOperation || statusOperation || basicOperation && operation != domain.OperationManagedBasicDelete) {
		reject(writer, http.StatusNotFound)
		return
	}
	if planRoute && !headscaleControlOperation && !headscaleReissueOperation && !headscaleLifecycleOperation && !connectorLoginOperation {
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: domain.OperationPlan, Target: target, Payload: application.PlanPayload{Operation: operation, Target: target}})
		if invokeErr != nil {
			reject(writer, http.StatusNotFound)
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
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: application.EmptyPayload{}})
		if invokeErr != nil {
			reject(writer, http.StatusServiceUnavailable)
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
			payload.PlanID, payload.Confirmation = "", ""
			clear(payload.AuthKey)
			payload.AuthKey = nil
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
		if operation == domain.OperationPreauthKeyCreate && payload.ExpirationSeconds == 0 {
			payload.ExpirationSeconds = 3600
		}
		if planRoute {
			payload.PlanID, payload.Confirmation = "", ""
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
			payload.PlanID = ""
			payload.Confirmation = ""
		} else if payload.PlanID == "" || payload.Confirmation != "reissue" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: domain.OperationTarget{Kind: domain.OperationTargetHeadscale}, Payload: payload})
		if invokeErr != nil {
			reject(writer, http.StatusServiceUnavailable)
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
			payload.PlanID = ""
			payload.Confirmation = ""
		} else if payload.PlanID == "" || payload.Confirmation != "deploy" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, invokeErr := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: domain.OperationTarget{Kind: domain.OperationTargetHeadscale}, Payload: payload})
		if invokeErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
		return
	}
	if statusOperation {
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: application.DomainStatusPayload{}})
		if err != nil {
			reject(writer, http.StatusServiceUnavailable)
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
			reject(writer, http.StatusServiceUnavailable)
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
			if payload.Confirmation != "generate" || payload.Username != "" || payload.PlanID != "" {
				reject(writer, http.StatusBadRequest)
				return
			}
		} else if payload.Confirmation != "delete" || payload.Username != "" || payload.PlanID == "" {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if err != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		if value, ok := result.Payload.(application.ManagedBasicActionResult); ok {
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
			var rejected application.HelperRejection
			if errors.As(err, &rejected) && rejected.Code == "foreign_database_evidence" {
				s.sessionStatusJSON(writer, principal, http.StatusConflict, map[string]string{"error_code": rejected.Code, "job_id": rejected.JobID})
				return
			}
			reject(writer, http.StatusServiceUnavailable)
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
			if len(data) == 0 || !json.Valid(data) {
				reject(writer, http.StatusBadRequest)
				return
			}
			body := append(json.RawMessage(nil), data...)
			payload = application.ResourceMutationPayload{Resource: body}
		} else if len(bytes.TrimSpace(data)) != 0 {
			reject(writer, http.StatusBadRequest)
			return
		}
		result, err := s.config.Actions.Invoke(request.Context(), application.Actor{Kind: application.ActorUI, Identity: principal.Selector, Generation: principal.Generation}, application.Call{Operation: operation, Target: target, Payload: payload})
		if err != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		s.sessionJSON(writer, principal, result.Payload)
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
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	if operation == domain.OperationCloseAll || operation == domain.OperationUnpublish {
		contraction, ok := result.Payload.(application.ContractionResult)
		if !ok || contraction.Outcome == "" {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		payload := struct {
			Outcome           string `json:"outcome"`
			AccessClosed      bool   `json:"access_closed"`
			SharedIngressDown bool   `json:"shared_ingress_down"`
			AccessMayRemain   bool   `json:"access_may_remain"`
		}{contraction.Outcome, contraction.AccessClosed, contraction.SharedIngressDown, contraction.AccessMayRemain}
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
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		JobID string `json:"job_id"`
		Token string `json:"token"`
	}{rotation.JobID, string(rotation.Token)})
}

func (s *Server) authenticate(request *http.Request, mutation bool) (session.Principal, bool) {
	if presentOriginInvalid(request, s.origin()) {
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
	principal, err := s.config.Sessions.Authenticate(selector, proof, csrf, s.origin(), fingerprint, mutation)
	return principal, err == nil
}
func (s *Server) origin() string { return "http://" + s.config.Authority }
func securityHeaders(writer http.ResponseWriter) {
	h := writer.Header()
	h.Set("Cache-Control", "no-store, private")
	h.Set("Content-Security-Policy", fixedCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

func reject(writer http.ResponseWriter, status int) {
	http.Error(writer, http.StatusText(status), status)
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

const (
	appCSS = "body{font-family:sans-serif;max-width:48rem;margin:4rem auto}label,input{display:block}"
	appJS  = `(()=>{"use strict";let proof=sessionStorage.getItem("lp.proof")||"",csrf=sessionStorage.getItem("lp.csrf")||"",blockedResource="";const status=document.getElementById("status"),login=document.getElementById("login"),logout=document.getElementById("logout"),rotate=document.getElementById("rotate"),closeAll=document.getElementById("close-all"),headscale=document.getElementById("headscale-initialize"),headscaleControl=document.getElementById("headscale-control"),headscaleReissue=document.getElementById("headscale-reissue"),publish=document.getElementById("publish"),publishResource=document.getElementById("publish-resource"),basicCreate=document.getElementById("basic-create"),basicRotate=document.getElementById("basic-rotate"),basicDelete=document.getElementById("basic-delete"),staticRegister=document.getElementById("static-register"),externalHTPasswd=document.getElementById("external-htpasswd-register"),domainStatus=document.getElementById("domain-status"),unpublish=document.getElementById("unpublish"),domainConfig=document.getElementById("domain-config"),resourceCreate=document.getElementById("resource-create"),resourceUpdateJSON=document.getElementById("resource-update-json"),processControl=document.getElementById("process-control"),resourceDelete=document.getElementById("resource-delete"),headscaleUserCreate=document.getElementById("headscale-user-create"),headscaleKeyCreate=document.getElementById("headscale-key-create"),headscaleKeyRevoke=document.getElementById("headscale-key-revoke"),headscaleDeviceExpire=document.getElementById("headscale-device-expire"),headscaleReads=document.getElementById("headscale-reads"),connectorBinding=document.getElementById("connector-binding"),connectorLogin=document.getElementById("connector-login"),connectorVerify=document.getElementById("connector-verify"),productReads=document.getElementById("product-reads"),jobDetail=document.getElementById("job-detail");const managed=[headscale,headscaleControl,headscaleReissue,resourceCreate,resourceUpdateJSON,processControl,resourceDelete,headscaleUserCreate,headscaleKeyCreate,headscaleKeyRevoke,headscaleDeviceExpire,headscaleReads,connectorBinding,connectorLogin,connectorVerify,productReads,jobDetail,publish,domainConfig,basicCreate,basicRotate,basicDelete,staticRegister,externalHTPasswd,domainStatus,unpublish];const show=(authenticated,emergency=false)=>{login.hidden=authenticated;logout.hidden=!authenticated;rotate.hidden=!authenticated||emergency;closeAll.hidden=!authenticated;managed.forEach(value=>value.hidden=!authenticated||emergency);if(authenticated&&emergency){productReads.hidden=false;headscaleReads.hidden=false;connectorVerify.hidden=false;domainStatus.hidden=false}};const clear=()=>{proof="";csrf="";blockedResource="";sessionStorage.clear();status.textContent="";show(false)};const headers=()=>({"X-LanPanel-Session-Proof":proof,"X-LanPanel-CSRF":csrf,"Content-Type":"application/json"}),headscaleCertificate=f=>{const value={challenge_method:f.challenge_method.value,directory_url:f.directory_url.value,terms_accepted:f.terms_accepted.checked};if(f.dns_provider.value)value.dns_provider=f.dns_provider.value;if(f.provider_profile_path.value)value.provider_profile_path=f.provider_profile_path.value;if(f.authoritative_zone.value)value.authoritative_zone=f.authoritative_zone.value;return value};login.addEventListener("submit",async event=>{event.preventDefault();const input=login.elements.token,body=new URLSearchParams({token:input.value});input.value="";const response=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});if(!response.ok){status.textContent="Authentication failed";return}const value=await response.json();proof=value.proof;csrf=value.csrf;sessionStorage.setItem("lp.proof",proof);sessionStorage.setItem("lp.csrf",csrf);const session=await fetch("/api/session",{headers:{"X-LanPanel-Session-Proof":proof}}),sessionValue=session.ok?await session.json():{profile:"emergency"},emergency=sessionValue.profile==="emergency";status.textContent=emergency?"Authenticated: startup recovery incomplete; expansion actions are disabled":"Authenticated";show(true,emergency)});headscale.addEventListener("submit",async event=>{event.preventDefault();const f=headscale.elements,body={control_domain:f.control_domain.value,magicdns_namespace:f.magicdns_namespace.value,source_kind:f.source_kind.value};if(f.mirror_url.value)body.mirror_url=f.mirror_url.value;if(f.offline_path.value)body.offline_path=f.offline_path.value;if(f.proxy_url.value)body.proxy_url=f.proxy_url.value;body.confirmation="initialize";if(!confirm("Initialize this immutable trusted-mesh identity? Control domain and database identity cannot be changed or removed."))return;const r=await fetch("/api/actions/headscale_initialize",{method:"POST",headers:headers(),body:JSON.stringify(body)});if(!r.ok){let v={};try{v=await r.json()}catch{}status.textContent=v.error_code==="foreign_database_evidence"?"Blocked: foreign Headscale database, account, or artifact evidence; job "+v.job_id:"Headscale initialization failed";return}const v=await r.json();status.textContent="Headscale identity "+v.target_id+" initialized; control service and ingress remain inactive";headscale.hidden=true});headscaleControl.addEventListener("submit",async event=>{event.preventDefault();const f=headscaleControl.elements,certificate=headscaleCertificate(f),pr=await fetch("/api/actions/headscale_control_deploy/plan",{method:"POST",headers:headers(),body:JSON.stringify({plan_id:"",confirmation:"",certificate})});if(!pr.ok){status.textContent="Headscale deploy Plan failed";return}const p=await pr.json();if(!confirm(p.exposure_summary+". "+p.prerequisites+". Deploy?"))return;const r=await fetch("/api/actions/headscale_control_deploy",{method:"POST",headers:headers(),body:JSON.stringify({plan_id:p.plan_id,confirmation:"deploy",certificate})});if(!r.ok){status.textContent="Headscale control deploy failed";return}const v=await r.json();status.textContent="Headscale control deployed; job "+v.job_id});headscaleReissue.addEventListener("click",async()=>{const f=headscaleControl.elements,certificate=headscaleCertificate(f),pr=await fetch("/api/actions/headscale_certificate_reissue/plan",{method:"POST",headers:headers(),body:JSON.stringify({plan_id:"",confirmation:"",certificate})});if(!pr.ok){status.textContent="Headscale reissue Plan failed";return}const p=await pr.json();if(!confirm(p.exposure_summary+". Reissue?"))return;const r=await fetch("/api/actions/headscale_certificate_reissue",{method:"POST",headers:headers(),body:JSON.stringify({plan_id:p.plan_id,confirmation:"reissue",certificate})});status.textContent=r.ok?"Headscale certificate reissued":"Headscale reissue failed"});const display=async r=>{let v={};try{v=await r.json()}catch{}status.textContent=r.ok?JSON.stringify(v):"Action failed";return v};resourceCreate.addEventListener("submit",async e=>{e.preventDefault();let body;try{body=JSON.parse(resourceCreate.elements.resource_json.value)}catch{status.textContent="Invalid resource JSON";return}await display(await fetch("/api/actions/resource_create",{method:"POST",headers:headers(),body:JSON.stringify(body)}))});resourceUpdateJSON.addEventListener("submit",async e=>{e.preventDefault();const f=resourceUpdateJSON.elements;let body;try{body=JSON.parse(f.resource_json.value)}catch{status.textContent="Invalid update JSON";return}await display(await fetch("/api/actions/resource_update?resource_id="+encodeURIComponent(f.resource_id.value),{method:"POST",headers:headers(),body:JSON.stringify(body)}))});processControl.addEventListener("submit",async e=>{e.preventDefault();const op=e.submitter.value==="start"?"process_start":"process_stop";await display(await fetch("/api/actions/"+op+"?resource_id="+encodeURIComponent(processControl.elements.resource_id.value),{method:"POST",headers:headers()}))});resourceDelete.addEventListener("submit",async e=>{e.preventDefault();const q="?resource_id="+encodeURIComponent(resourceDelete.elements.resource_id.value),p=await fetch("/api/actions/resource_delete/plan"+q,{method:"POST",headers:headers(),body:"{}"});if(!p.ok){status.textContent="Delete Plan failed";return}const plan=await p.json();if(!confirm(plan.exposure_summary+". Delete?"))return;await display(await fetch("/api/actions/resource_delete"+q,{method:"POST",headers:headers(),body:JSON.stringify({plan_id:plan.plan_id,confirmation:"delete"})}))});headscaleUserCreate.addEventListener("submit",async e=>{e.preventDefault();await display(await fetch("/api/actions/headscale_user_create",{method:"POST",headers:headers(),body:JSON.stringify({name:headscaleUserCreate.elements.name.value})}))});const lifecycle=async(op,param,id,body,confirmation)=>{const q="?"+param+"="+encodeURIComponent(id),p=await fetch("/api/actions/"+op+"/plan"+q,{method:"POST",headers:headers(),body:JSON.stringify(body)});if(!p.ok){status.textContent="Lifecycle Plan failed";return}const plan=await p.json();if(!confirm(plan.exposure_summary+". Continue?"))return;body.plan_id=plan.plan_id;body.confirmation=confirmation;const response=await fetch("/api/actions/"+op+q,{method:"POST",headers:headers(),body:JSON.stringify(body)});if(op==="preauth_key_create"&&response.ok){const value=await response.json();status.textContent="Preauth key (shown once): "+atob(value.secret);return}await display(response)};headscaleKeyCreate.addEventListener("submit",e=>{e.preventDefault();const f=headscaleKeyCreate.elements;lifecycle("preauth_key_create","user_id",f.user_id.value,{expiration_seconds:Number(f.expiration_seconds.value)},"create")});headscaleKeyRevoke.addEventListener("submit",e=>{e.preventDefault();lifecycle("preauth_key_revoke","key_id",headscaleKeyRevoke.elements.key_id.value,{},"revoke")});headscaleDeviceExpire.addEventListener("submit",e=>{e.preventDefault();lifecycle("device_expire","device_id",headscaleDeviceExpire.elements.device_id.value,{},"expire")});headscaleReads.addEventListener("click",async e=>{const op=e.target.dataset.read;if(op)await display(await fetch("/api/actions/"+op,{method:"POST",headers:headers(),body:"{}"}))});connectorBinding.addEventListener("submit",async e=>{e.preventDefault();await display(await fetch("/api/actions/connector_binding_set",{method:"POST",headers:headers(),body:JSON.stringify({control_url:connectorBinding.elements.control_url.value})}))});connectorLogin.addEventListener("submit",async e=>{e.preventDefault();const p=await fetch("/api/actions/connector_login/plan",{method:"POST",headers:headers(),body:"{}"});if(!p.ok){status.textContent="Connector Plan failed";return}const plan=await p.json(),input=connectorLogin.elements.auth_key,key=input.value;input.value="";if(!confirm(plan.exposure_summary+". Login?"))return;await display(await fetch("/api/actions/connector_login",{method:"POST",headers:headers(),body:JSON.stringify({plan_id:plan.plan_id,confirmation:"login",auth_key:btoa(key)})}))});connectorVerify.addEventListener("click",async()=>display(await fetch("/api/actions/connector_verify",{method:"POST",headers:headers(),body:"{}"})));productReads.addEventListener("click",async e=>{const op=e.target.dataset.read;if(op)await display(await fetch("/api/actions/"+op,{method:"POST",headers:headers(),body:"{}"}))});jobDetail.addEventListener("submit",async e=>{e.preventDefault();await display(await fetch("/api/actions/job_detail?job_id="+encodeURIComponent(jobDetail.elements.job_id.value),{method:"POST",headers:headers(),body:"{}"}))});publish.addEventListener("submit",async event=>{event.preventDefault();const id=publishResource.value,query="?resource_id="+encodeURIComponent(id),pr=await fetch("/api/actions/publish/plan"+query,{method:"POST",headers:headers(),body:"{}"});if(!pr.ok){status.textContent="Publish Plan failed";return}const p=await pr.json();if(!confirm("Review publication\n"+p.exposure_summary+"\n"+p.prerequisites+"\nExpires "+p.expires_at+"\nPublish?"))return;const r=await fetch("/api/actions/publish"+query,{method:"POST",headers:headers(),body:JSON.stringify({plan_id:p.plan_id,confirmation:"publish"})});if(!r.ok){status.textContent="Publish failed";return}const v=await r.json();status.textContent=v.job_result==="partial"?"Published; GoAccess retirement pending; job "+v.job_id:"Published "+v.public_url});const list=value=>value.split(",").map(item=>item.trim()).filter(Boolean).sort();domainConfig.addEventListener("submit",async event=>{event.preventDefault();const f=domainConfig.elements,resource=f.resource_id.value,staticMappings=f.static_mappings.value.split("\n").map(line=>line.trim()).filter(Boolean).slice(0,129).map(line=>{const p=line.split("|");return{url_path:p[0],relative_path:p[1],directory:p[2]==="directory",anonymous:p[3]==="anonymous"}}).sort((a,b)=>a.url_path.localeCompare(b.url_path)),body={schema_version:"lanpanel.domain-publication.update.v1",resource_id:resource,publication:{canonical_domain:f.canonical_domain.value,aliases:list(f.aliases.value),access_mode:f.access_mode.value,credential_id:f.credential_id.value,cidrs:list(f.cidrs.value),static_root_id:f.static_root_id.value,static_mappings:staticMappings,goaccess:{enabled:f.goaccess_enabled.checked,credential_id:f.goaccess_credential_id.value,cidrs:list(f.goaccess_cidrs.value),dashboard_path:f.goaccess_dashboard_path.value,websocket_path:f.goaccess_websocket_path.value},certificate:{challenge_method:f.challenge_method.value,directory_url:f.directory_url.value,terms_accepted:f.terms_accepted.checked,dns_provider:f.dns_provider.value,provider_profile_path:f.provider_profile_path.value,authoritative_zone:f.authoritative_zone.value}}},r=await fetch("/api/actions/resource_update?resource_id="+encodeURIComponent(resource),{method:"POST",headers:headers(),body:JSON.stringify(body)});status.textContent=r.ok?"Pending domain HTTPS config saved":"Domain HTTPS config save failed"});basicCreate.addEventListener("submit",async event=>{event.preventDefault();const resource=basicCreate.elements.resource_id.value,username=basicCreate.elements.username.value,r=await fetch("/api/actions/managed_basic_create?resource_id="+encodeURIComponent(resource),{method:"POST",headers:headers(),body:JSON.stringify({username,confirmation:"generate"})});if(!r.ok){status.textContent="Managed Basic create failed";return}const v=await r.json();basicCreate.elements.username.value="";status.textContent="Managed Basic "+v.credential_id+" password: "+atob(v.password)});basicRotate.addEventListener("submit",async event=>{event.preventDefault();const credential=basicRotate.elements.credential_id.value;if(!confirm("Rotate this credential? The old password will stop working."))return;const r=await fetch("/api/actions/managed_basic_rotate?credential_id="+encodeURIComponent(credential),{method:"POST",headers:headers(),body:JSON.stringify({confirmation:"generate"})});if(!r.ok){status.textContent="Managed Basic rotate failed";return}const v=await r.json();status.textContent="Managed Basic "+v.credential_id+" password: "+atob(v.password)});basicDelete.addEventListener("submit",async event=>{event.preventDefault();const credential=basicDelete.elements.credential_id.value,query="?credential_id="+encodeURIComponent(credential),pr=await fetch("/api/actions/managed_basic_delete/plan"+query,{method:"POST",headers:headers(),body:"{}"});if(!pr.ok){status.textContent="Managed Basic delete Plan failed";return}const p=await pr.json();if(!confirm(p.exposure_summary+". "+p.prerequisites+". Delete?"))return;const r=await fetch("/api/actions/managed_basic_delete"+query,{method:"POST",headers:headers(),body:JSON.stringify({plan_id:p.plan_id,confirmation:"delete"})});status.textContent=r.ok?"Managed Basic deleted":"Managed Basic delete failed"});staticRegister.addEventListener("submit",async event=>{event.preventDefault();const resource=staticRegister.elements.resource_id.value,path=staticRegister.elements.path.value,r=await fetch("/api/actions/static_root_register?resource_id="+encodeURIComponent(resource),{method:"POST",headers:headers(),body:JSON.stringify({path,confirmation:"register"})});if(!r.ok){status.textContent="Static root registration failed";return}const v=await r.json();status.textContent="Static root registered: "+v.target_id});externalHTPasswd.addEventListener("submit",async event=>{event.preventDefault();const resource=externalHTPasswd.elements.resource_id.value,path=externalHTPasswd.elements.path.value,r=await fetch("/api/actions/external_htpasswd_register?resource_id="+encodeURIComponent(resource),{method:"POST",headers:headers(),body:JSON.stringify({path,confirmation:"register"})});if(!r.ok){status.textContent="External htpasswd registration failed";return}const v=await r.json();status.textContent="External htpasswd registered: "+v.target_id});domainStatus.addEventListener("submit",async event=>{event.preventDefault();const resource=domainStatus.elements.resource_id.value,r=await fetch("/api/actions/status?resource_id="+encodeURIComponent(resource),{method:"POST",headers:headers(),body:"{}"});if(!r.ok){status.textContent="Domain status failed";return}const v=await r.json();blockedResource=v.status==="degraded"?resource:"";[publish,domainConfig,basicCreate,basicRotate,basicDelete,staticRegister,externalHTPasswd].forEach(value=>value.hidden=!!blockedResource);status.textContent=v.status+": "+v.reason+(v.credential_id?"; App credential "+v.credential_id+" fingerprint "+v.credential_fingerprint+(v.credential_changed?" (changed)":""):"")+(v.goaccess_credential_id?"; GoAccess credential "+v.goaccess_credential_id+" fingerprint "+v.goaccess_credential_fingerprint+(v.goaccess_credential_changed?" (changed)":""):"")+((v.credential_ids||[]).length?"; credentials: "+v.credential_ids.join(", "):"")+((v.goaccess_retirement_generations||[]).length?"; GoAccess retirement job "+v.goaccess_retirement_job_id+" generations "+v.goaccess_retirement_generations.join(", "):"")+(v.access_may_remain?"; allowed actions: "+v.allowed_actions.join(", "):"")});unpublish.addEventListener("submit",async event=>{event.preventDefault();const resource=unpublish.elements.resource_id.value,query="?resource_id="+encodeURIComponent(resource),pr=await fetch("/api/actions/unpublish/plan"+query,{method:"POST",headers:headers(),body:"{}"});if(!pr.ok){status.textContent="Unpublish Plan failed";return}const p=await pr.json();if(!confirm(p.exposure_summary+". "+p.prerequisites+". Unpublish?"))return;const r=await fetch("/api/actions/unpublish"+query,{method:"POST",headers:headers(),body:JSON.stringify({plan_id:p.plan_id,confirmation:"unpublish"})});status.textContent=r.ok?"App unpublished":"Unpublish failed"});closeAll.addEventListener("click",async()=>{const pr=await fetch("/api/actions/close_all/plan",{method:"POST",headers:headers(),body:"{}"});if(!pr.ok){status.textContent="Close-all Plan failed";return}const p=await pr.json();if(!confirm("Review: "+p.operation+" for "+p.target_kind+". "+p.exposure_summary+". "+p.prerequisites+". Expires "+p.expires_at+". Continue?"))return;const r=await fetch("/api/actions/close_all",{method:"POST",headers:headers(),body:JSON.stringify({plan_id:p.plan_id,confirmation:"close"})});if(!r.ok){status.textContent="Close-all failed";return}const v=await r.json();status.textContent=v.access_may_remain?"Unknown: App access may remain":v.shared_ingress_down?"App access closed; shared ingress is down":"All App origin ingress closed"});rotate.addEventListener("click",async()=>{const pr=await fetch("/api/actions/admin_token_rotate/plan",{method:"POST",headers:headers(),body:"{}"});if(!pr.ok){status.textContent="Rotation Plan failed";return}const p=await pr.json();if(!confirm("Review: "+p.operation+" for "+p.target_kind+". "+p.exposure_summary+". "+p.prerequisites+". Expires "+p.expires_at+". Continue?"))return;const r=await fetch("/api/actions/admin_token_rotate",{method:"POST",headers:headers(),body:JSON.stringify({plan_id:p.plan_id,confirmation:"rotate"})});if(!r.ok){status.textContent="Rotation failed";return}const v=await r.json();clear();status.textContent="New admin token: "+v.token});logout.addEventListener("click",async()=>{try{await fetch("/api/logout",{method:"POST",headers:{"X-LanPanel-Session-Proof":proof,"X-LanPanel-CSRF":csrf}})}finally{clear();history.replaceState(null,"","/");location.replace("/")}});addEventListener("pagehide",clear);addEventListener("pageshow",event=>{if(event.persisted){clear();location.replace("/")}})})();`
)
