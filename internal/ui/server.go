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
	"lanpanel/internal/audit"
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
	rotationPending bool
	shuttingDown    bool
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
	return s.connection.CloseNow()
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
	if config.Audit == nil {
		return nil, fmt.Errorf("management UI audit sink is unavailable")
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
	actionRoute := request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/api/actions/")
	if request.Host != s.config.Authority || request.URL.RawQuery != "" && !actionRoute || request.URL.RawPath != "" {
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
		if presentOriginInvalid(request, s.origin()) {
			reject(writer, http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "text/css; charset=utf-8")
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = io.WriteString(writer, appCSS)
	case request.Method == http.MethodGet && request.URL.Path == appJSPath:
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
	s.writeStructuredShell(writer)
}

func (s *Server) writeStructuredShell(writer http.ResponseWriter) {
	const shell = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LanPanel management</title><link rel="stylesheet" href="{{app_css_path}}"></head><body><main>
<header><h1>LanPanel</h1><p id="fingerprint">{{fingerprint}}</p><p id="boundary">Authenticated Management UI only. LanPanel manages local process/ingress; tailnet resources only register and publish a fixed remote service.</p></header>
<form id="login" method="post" action="/login" enctype="application/x-www-form-urlencoded"><label>Admin token<input name="token" type="password" autocomplete="current-password" required></label><button type="submit">Login</button></form>
<section id="workspace" hidden><header><h2>Application overview</h2><p id="overview-help">Refresh status to review configuration, requested/observed process state, publication, and Tailnet evidence. Unknown or stale evidence never opens ingress.</p><div class="toolbar"><button id="refresh-status" type="button">Refresh status</button><button id="resource-create-open" type="button">Create application</button><button id="rotate" type="button">Rotate admin token</button><button id="close-all" type="button">Close all App ingress</button><button id="logout" type="button">Logout</button></div></header><div id="resource-list" aria-live="polite"></div></section>
<section id="resource-detail" hidden><h2 id="detail-title">Application detail</h2><div id="detail-status"></div><div id="detail-evidence"></div><div id="detail-actions"></div></section>
<form id="resource-create" hidden><fieldset><legend>Create application</legend><p>Choose a fixed upstream. New resources are saved active, stopped, and unpublished. LanPanel does not upload or build application code.</p><label>Name<input name="name" required maxlength="128"></label><label>Target kind<select name="target_kind" id="create-target-kind"><option value="local_http">local_http — LanPanel manages this host process</option><option value="tailnet_http">tailnet_http — fixed remote service; no remote lifecycle control</option></select></label><div id="create-local-fields"><label>Executable<input name="executable" placeholder="/usr/local/bin/app"></label><label>Arguments, one per line<textarea name="arguments" rows="3"></textarea></label><label>Working directory<input name="working_directory"></label><label>Environment file, optional<input name="environment_file"></label><label>Write paths, one absolute path per line<textarea name="write_paths" rows="3"></textarea></label><label>Endpoint kind<select name="endpoint_kind"><option value="unix_socket_activation">unix_socket_activation</option><option value="relay_unix">relay_unix</option><option value="tcp_socket_activation">tcp_socket_activation</option></select></label><div id="create-tcp-fields"><label>Loopback TCP address<input name="tcp_address" placeholder="127.0.0.1"></label><label>Loopback TCP port<input name="tcp_port" type="number" min="1" max="65535"></label></div></div><div id="create-tailnet-fields" hidden><p>Remote process, shell, executable, working directory, and deployment controls are not available for tailnet_http.</p><label>Fixed peer IP<input name="peer_ip" inputmode="decimal"></label><label>Fixed local source IP<input name="source_ip" inputmode="decimal"></label><label>Fixed remote port<input name="remote_port" type="number" min="1" max="65535"></label></div><label>Readiness path<input name="readiness_path" value="/ready" required></label><label>Allowed HTTP statuses<input name="allowed_http_statuses" value="200" required></label><label><input name="websocket_enabled" type="checkbox"> Require WebSocket readiness</label><label>WebSocket path<input name="websocket_path" value="/ws"></label><fieldset><legend>Initial publication</legend><label>Publication kind<select name="publication_kind"><option value="domain_https">domain_https</option><option value="temporary_ip_http">temporary_ip_http — explicit temporary plaintext warning</option></select></label><div id="create-domain-fields"><label>Canonical domain<input name="canonical_domain"></label><label>Aliases, comma-separated<input name="aliases"></label><label>Access mode<select name="access_mode"><option value="public">public</option><option value="application_managed">application_managed</option><option value="basic">basic</option></select></label><label>Basic credential ID, optional (select or create through the dependency flow)<select name="credential_id"><option value="">No credential selected</option></select></label><label>Basic CIDRs, comma-separated<input name="cidrs"></label><label>ACME challenge<select name="challenge_method"><option value="http-01">http-01</option><option value="dns-01">dns-01</option></select></label><label>ACME directory URL<input name="directory_url"></label><label>ACME account contact<input name="account_email" type="email" autocomplete="email"></label><label>DNS provider<input name="dns_provider"></label><label>Provider profile path<input name="provider_profile_path"></label><label>Authoritative zone<input name="authoritative_zone"></label><label><input name="terms_accepted" type="checkbox"> Approved ACME terms</label></div><div id="create-temporary-fields" hidden><p>Temporary HTTP is plaintext and intended only for Preview/testing. Confirm explicitly before creating.</p><label>Public IPv4<input name="public_ipv4"></label><label>Temporary public port<input name="public_port" type="number" min="1" max="65535"></label></div></fieldset><button type="submit">Save stopped and unpublished application</button><button type="button" data-cancel-form="resource-create">Cancel</button></fieldset></form>
<form id="resource-update-json" hidden><fieldset><legend>Edit selected application configuration</legend><p id="update-boundary">The selected resource identity and lifecycle authority remain server-owned.</p><input name="resource_id" type="hidden"><div class="update-fields"></div><button type="submit">Save configuration without publishing</button><button type="button" data-cancel-form="resource-update-json">Cancel</button></fieldset></form>
<form id="process-control" hidden><fieldset><legend>Local process lifecycle</legend><p>Only local_http resources expose these controls. The process remains a constrained, non-root local service.</p><input name="resource_id" type="hidden"><button name="action" value="start" type="submit">Start process</button><button name="action" value="stop" type="submit">Stop process</button></fieldset></form>
<form id="resource-delete" hidden><fieldset><legend>Delete selected application</legend><input name="resource_id" type="hidden"><p>Deletion requires unpublished, stopped/closed authority and never deletes user-provided executable, working directory, environment, static, htpasswd, or log files.</p><button type="submit">Delete application</button></fieldset></form>
<form id="publish" hidden><fieldset><legend>Publish selected application</legend><input id="publish-resource" name="resource_id" type="hidden"><p>Publication always rechecks local process/target or Tailnet connector, route, and target evidence before opening ingress.</p><button type="submit">Publish</button></fieldset></form>
<form id="domain-config" hidden><fieldset><legend>Domain HTTPS publication</legend><p>Production-style publication uses public HTTP/HTTPS ports 80/443 through the managed ingress. ACME contact and provider authority are checked before any certificate request.</p><input name="resource_id" type="hidden"><label>Canonical domain<input name="canonical_domain" required></label><label>Aliases, comma-separated<input name="aliases"></label><label>Access mode<select name="access_mode"><option value="public">public</option><option value="application_managed">application_managed</option><option value="basic">basic</option></select></label><label>Basic credential (selected dependency)<select name="credential_id"><option value="">No credential selected</option></select></label><label>Basic CIDRs, comma-separated<input name="cidrs"></label><label>Static root (selected dependency)<select name="static_root_id"><option value="">No static root selected</option></select></label><p id="dependency-status">Dependencies are shown only as non-secret identities and current bindings.</p><label>Static mappings (one URL|relative|file-or-directory|authenticated-or-anonymous per mapping)</label><div id="static-mapping-rows"><div class="mapping-row"><input name="static_url_path" placeholder="/assets/"><input name="static_relative_path" placeholder="public/assets"><select name="static_mapping_kind"><option value="file">file</option><option value="directory">directory</option></select><select name="static_access"><option value="authenticated">authenticated</option><option value="anonymous">anonymous</option></select><button type="button" data-remove-mapping>Remove mapping</button></div></div><button id="static-mapping-add" type="button">Add static mapping</button><label><input name="goaccess_enabled" type="checkbox"> Enable isolated GoAccess</label><label>GoAccess external htpasswd (selected dependency)<select name="goaccess_credential_id"><option value="">No htpasswd selected</option></select></label><label>GoAccess CIDRs, comma-separated<input name="goaccess_cidrs"></label><label>GoAccess dashboard path<input name="goaccess_dashboard_path"></label><label>GoAccess WebSocket path<input name="goaccess_websocket_path"></label><label>ACME challenge<select name="challenge_method"><option value="http-01">http-01</option><option value="dns-01">dns-01</option></select></label><label>ACME directory URL<input name="directory_url" required></label><label>ACME account contact<input name="account_email" type="email" required autocomplete="email"></label><p>LanPanel uses its installation-managed ACME account key. Contact is validated again before any ACME request.</p><label>DNS provider<input name="dns_provider"></label><label>Provider profile path<input name="provider_profile_path"></label><label>Authoritative zone<input name="authoritative_zone"></label><label><input name="terms_accepted" type="checkbox" required> Approved ACME terms</label><button type="submit">Save pending domain HTTPS config</button></fieldset></form>
<form id="unpublish" hidden><fieldset><legend>Unpublish selected application</legend><input name="resource_id" type="hidden"><button type="submit">Unpublish</button></fieldset></form>
<form id="domain-status" hidden><fieldset><legend>Resource status check</legend><input name="resource_id" type="hidden"><button type="submit">Check selected resource</button></fieldset></form>
<form id="basic-create" hidden><fieldset><legend>Managed Basic dependency</legend><input name="resource_id" type="hidden"><label>Basic username<input name="username" required pattern="[A-Za-z0-9][A-Za-z0-9._@-]{0,63}"></label><button type="submit">Create Managed Basic</button></fieldset></form><form id="basic-rotate" hidden><fieldset><legend>Rotate Managed Basic</legend><input name="credential_id" type="hidden"><button type="submit">Rotate Managed Basic</button></fieldset></form><form id="basic-delete" hidden><fieldset><legend>Delete Managed Basic</legend><input name="credential_id" type="hidden"><button type="submit">Delete Managed Basic</button></fieldset></form>
<form id="static-register" hidden><fieldset><legend>Register static root</legend><input name="resource_id" type="hidden"><label>Static root absolute path<input name="path" required></label><button type="submit">Register static root</button></fieldset></form><form id="external-htpasswd-register" hidden><fieldset><legend>Register external htpasswd</legend><input name="resource_id" type="hidden"><label>External htpasswd absolute path<input name="path" required></label><button type="submit">Register external htpasswd</button></fieldset></form>
<form id="headscale-initialize" hidden><fieldset><legend>Initialize optional Headscale trust domain</legend><p>Policy: trusted_mesh (all members trust one another). Identity and database cannot be adopted, disabled, removed, or renamed.</p><p>Foreign Headscale database, account, or artifact evidence is blocked and reported as a terminal job; foreign Headscale database, account, or artifact evidence is never adopted.</p><label>Control domain<input name="control_domain" required></label><label>MagicDNS namespace<input name="magicdns_namespace" required></label><button type="submit">Initialize Headscale identity</button></fieldset></form><form id="headscale-control" hidden><fieldset><legend>Deploy Headscale control</legend><label>ACME challenge<select name="challenge_method"><option value="http-01">http-01</option><option value="dns-01">dns-01</option></select></label><label>ACME directory URL<input name="directory_url" required></label><label>ACME account contact<input name="account_email" type="email" required autocomplete="email"></label><p>LanPanel uses its installation-managed ACME account key. Contact is stored through the authenticated Management UI and validated again before any ACME request.</p><label>DNS provider<input name="dns_provider"></label><label>Provider profile path<input name="provider_profile_path"></label><label>Authoritative zone<input name="authoritative_zone"></label><label><input name="terms_accepted" type="checkbox" required>Approved ACME terms</label><button type="submit">Deploy control ingress</button></fieldset></form><button id="headscale-reissue" hidden type="button">Reissue Headscale certificate</button>
<form id="headscale-user-create" hidden><label>User name<input name="name" required></label><button type="submit">Create Headscale user</button></form><form id="headscale-key-create" hidden><label>User ID<input name="user_id" required></label><label>Expiration seconds<input name="expiration_seconds" type="number" min="1" max="86400" value="3600"></label><button type="submit">Create preauth key</button></form><form id="headscale-key-revoke" hidden><p>Revocation prevents new normal-path use; existing TCP/WebSocket connections may persist. LanPanel does not promise immediate termination.</p><label>Key ID<input name="key_id" required></label><button type="submit">Revoke preauth key</button></form><form id="headscale-device-expire" hidden><p>Expiry affects future control-plane use; existing TCP/WebSocket connections may persist. LanPanel does not promise immediate termination.</p><label>Device ID<input name="device_id" required></label><button type="submit">Expire device</button></form><p id="headscale-reads" hidden><button data-read="headscale_user_list" type="button">List users</button><button data-read="preauth_key_list" type="button">List keys</button><button data-read="device_list" type="button">List devices</button></p>
<form id="connector-binding" hidden><p>Changing or disconnecting the connector affects new publication-path connections only; existing TCP/WebSocket connections may persist. LanPanel does not promise immediate termination.</p><label>Control URL<input name="control_url" type="url" required></label><button type="submit">Set connector binding</button></form><form id="connector-login" hidden><label>One-time auth key<input name="auth_key" type="password" required autocomplete="off"></label><button type="submit">Login connector</button></form><button id="connector-verify" hidden type="button">Verify connector</button><p id="product-reads" hidden><button data-read="status" type="button">System status</button><button data-read="diagnostics" type="button">Diagnostics</button><button data-read="configuration_export" type="button">Configuration export</button><button data-read="job_list" type="button">Jobs</button></p><form id="job-detail" hidden><label>Job ID<input name="job_id" required pattern="job_[0-9a-f]{64}"></label><button type="submit">Job detail</button></form><p id="status" role="status" aria-live="polite"></p></section></main><script src="{{app_js_path}}" defer></script></body></html>`
	page := strings.Replace(shell, "{{fingerprint}}", template.HTMLEscapeString(s.config.InstallationFingerprint), 1)
	page = strings.Replace(page, "{{app_css_path}}", appCSSPath, 1)
	page = strings.Replace(page, "{{app_js_path}}", appJSPath, 1)
	_, _ = io.WriteString(writer, page)
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
		if auditErr := s.appendAudit(audit.Record{Operation: "login", Target: "installation", Actor: "unknown", At: time.Now().UTC(), Result: "failed", ErrorCode: "authentication_failed", Paths: []string{}}); auditErr != nil {
			reject(writer, http.StatusServiceUnavailable)
			return
		}
		reject(writer, http.StatusUnauthorized)
		return
	}
	credentials, err := s.config.Sessions.Issue(s.origin(), fingerprint)
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
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]string{"proof": credentials.Proof, "csrf": credentials.CSRF})
}

func (s *Server) appendAudit(record audit.Record) error {
	if s.config.Audit == nil {
		return fmt.Errorf("management UI audit sink is unavailable")
	}
	return s.config.Audit.Append(record)
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
	if !exactOrigin(request, s.origin()) {
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
	lease := s.beginAction(request.Context(), principal, operation == domain.OperationAdminTokenRotate && !planRoute)
	if lease == nil {
		s.barrier.RLock()
		valid := s.config.Sessions.Valid(principal)
		s.barrier.RUnlock()
		if !valid {
			reject(writer, http.StatusUnauthorized)
			return
		}
		reject(writer, http.StatusConflict)
		return
	}
	defer s.endAction(lease)
	request = request.WithContext(lease.ctx)
	if !s.revalidateAction(lease) {
		reject(writer, http.StatusUnauthorized)
		return
	}
	actionFailure := func(err error, status int) {
		var rejected application.HelperRejection
		if errors.As(err, &rejected) {
			s.sessionStatusJSON(writer, principal, http.StatusConflict, map[string]string{"error_code": rejected.Code, "job_id": rejected.JobID})
			return
		}
		reject(writer, status)
	}
	if planRoute && (headscaleOperation || headscaleReadOperation || headscaleUserCreateOperation || connectorBindingOperation || connectorVerifyOperation || productReadOperation || resourceOperation || processOperation || staticOperation || statusOperation || basicOperation && operation != domain.OperationManagedBasicDelete && operation != domain.OperationManagedBasicRotate) {
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
		if !requireExactEmptyJSONBody(writer, request) {
			reject(writer, http.StatusBadRequest)
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
			reject(writer, http.StatusServiceUnavailable)
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
		var rejected application.HelperRejection
		if errors.As(err, &rejected) {
			s.sessionStatusJSON(writer, principal, http.StatusConflict, map[string]string{"error_code": rejected.Code, "job_id": rejected.JobID})
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

const (
	appCSS = `:root{color-scheme:light dark;font:16px/1.45 system-ui,sans-serif}body{margin:0;background:#f4f6f8;color:#18212b}main{max-width:72rem;margin:0 auto;padding:2rem 1rem}header{margin-bottom:1.5rem}h1,h2,h3{line-height:1.2}.toolbar{display:flex;flex-wrap:wrap;gap:.5rem}button{cursor:pointer;border:1px solid #52606d;border-radius:.35rem;padding:.5rem .8rem;background:#fff;color:#18212b}button:hover{background:#e8eef5}form,article{background:#fff;border:1px solid #cbd5df;border-radius:.5rem;padding:1rem;margin:1rem 0}fieldset{border:0;padding:0;margin:0}legend{font-size:1.2rem;font-weight:700;margin-bottom:.75rem}label{display:block;margin:.7rem 0;font-weight:600}input,select,textarea{display:block;box-sizing:border-box;width:100%;max-width:42rem;margin-top:.25rem;padding:.5rem;border:1px solid #8b98a5;border-radius:.25rem;font:inherit}input[type=checkbox]{display:inline;width:auto;margin-right:.4rem}.resource-card{display:inline-block;vertical-align:top;width:min(100%,31rem);margin-right:.7rem}.resource-card strong{font-weight:700}.resource-card button{margin:.25rem}.resource-card p{margin:.4rem 0}#status{min-height:1.5rem;font-weight:700}@media(prefers-color-scheme:dark){body{background:#18212b;color:#eef2f5}form,article,button{background:#25313d;color:#eef2f5;border-color:#697887}input,select,textarea{background:#18212b;color:#eef2f5}}`
)

const structuredAppJS = `(function () {
  "use strict";
  const proofKey = "lp.proof", csrfKey = "lp.csrf";
  let proof = sessionStorage.getItem(proofKey) || "";
  let csrf = sessionStorage.getItem(csrfKey) || "";
  let selected = null; let editing = false;
  const $ = (id) => document.getElementById(id);
  const status = $("status"), login = $("login"), workspace = $("workspace");
  const managed = ["headscale-initialize", "headscale-control", "headscale-reissue", "headscale-user-create", "headscale-key-create", "headscale-key-revoke", "headscale-device-expire", "headscale-reads", "connector-binding", "connector-login", "connector-verify", "product-reads", "job-detail"]; const resourceManaged = ["resource-update-json", "process-control", "resource-delete", "publish", "domain-config", "unpublish", "domain-status", "basic-create", "basic-rotate", "basic-delete", "static-register", "external-htpasswd-register"];
  const headers = () => ({"X-LanPanel-Session-Proof": proof, "X-LanPanel-CSRF": csrf, "Content-Type": "application/json"});
  const setStatus = (text) => { status.textContent = text; };
  const clearResourceSelection = () => { selected = null; editing = false; $("resource-detail").hidden = true; resourceManaged.forEach((id) => { const node = $(id); if (node) node.hidden = true; }); }; const clearSession = () => { proof = ""; csrf = ""; clearResourceSelection(); sessionStorage.clear(); workspace.hidden = true; login.hidden = false; managed.forEach((id) => { const node = $(id); if (node) node.hidden = true; }); $("resource-create").hidden = true; setStatus(""); };
  const values = (text) => String(text || "").split(",").map((item) => item.trim()).filter(Boolean).sort();
  const lines = (text) => String(text || "").split("\\n").map((item) => item.trim()).filter(Boolean);
  const mappingValues = (form) => Array.from(form.querySelectorAll(".mapping-row")).map((row) => { const url = row.querySelector("[name=static_url_path]")?.value.trim() || "", relative = row.querySelector("[name=static_relative_path]")?.value.trim() || "", directory = row.querySelector("[name=static_mapping_kind]")?.value === "directory", anonymous = row.querySelector("[name=static_access]")?.value === "anonymous"; if (!url || !relative) return null; const value = { url_path: url, relative_path: relative, directory }; if (anonymous) value.anonymous = true; return value; }).filter(Boolean).sort((a, b) => a.url_path.localeCompare(b.url_path));
  const json = async (response) => { try { return await response.json(); } catch (_) { return {}; } };
  const report = async (response, fallback = "Action failed") => { const value = await json(response); if (!response.ok) { setStatus(value.error || value.error_code || fallback); return null; } if (value.job_result === "partial") { setStatus("Completed with follow-up job " + (value.job_id || "")); } else { setStatus(value.message || value.reason || "Action completed"); } return value; };
  const show = (authenticated, emergency = false) => {
    login.hidden = authenticated;
    workspace.hidden = !authenticated;
    managed.forEach((id) => { const node = $(id); if (node) node.hidden = !authenticated || emergency; });
    resourceManaged.forEach((id) => { const node = $(id); if (node) node.hidden = true; });
    $("resource-create").hidden = true;
    if (authenticated && emergency) { $("headscale-reads").hidden = false; $("product-reads").hidden = false; $("connector-verify").hidden = false; }
  };
  const formValue = (form, name) => form.elements[name] ? form.elements[name].value.trim() : "";
  const checked = (form, name) => !!(form.elements[name] && form.elements[name].checked);
  const websocket = (form) => { const value = { enabled: checked(form, "websocket_enabled") }; if (value.enabled) value.path = formValue(form, "websocket_path"); return value; };
  const certificate = (form, requiredAccount = false) => { const email = formValue(form, "account_email"), value = { challenge_method: formValue(form, "challenge_method"), directory_url: formValue(form, "directory_url") }; if (requiredAccount || email) value.account_email = email; value.terms_accepted = checked(form, "terms_accepted"); if (value.challenge_method === "dns-01") { const provider = formValue(form, "dns_provider"), profile = formValue(form, "provider_profile_path"), zone = formValue(form, "authoritative_zone"); if (provider) value.dns_provider = provider; if (profile) value.provider_profile_path = profile; if (zone) value.authoritative_zone = zone; } return value; };
  const domainPublication = (form, mappings = []) => { const value = { canonical_domain: formValue(form, "canonical_domain") }, aliases = values(formValue(form, "aliases")), credential = formValue(form, "credential_id"), cidrs = values(formValue(form, "cidrs")), staticRoot = formValue(form, "static_root_id"); if (aliases.length) value.aliases = aliases; value.access_mode = formValue(form, "access_mode"); if (credential) value.credential_id = credential; if (cidrs.length) value.cidrs = cidrs; if (staticRoot) value.static_root_id = staticRoot; if (mappings.length) value.static_mappings = mappings; const directory = formValue(form, "directory_url"); if (directory) value.certificate = certificate(form); const goaccess = { enabled: checked(form, "goaccess_enabled") }; if (goaccess.enabled) { const id = formValue(form, "goaccess_credential_id"), goCIDRs = values(formValue(form, "goaccess_cidrs")), dashboard = formValue(form, "goaccess_dashboard_path"), socket = formValue(form, "goaccess_websocket_path"); if (id) goaccess.credential_id = id; if (goCIDRs.length) goaccess.cidrs = goCIDRs; if (dashboard) goaccess.dashboard_path = dashboard; if (socket) goaccess.websocket_path = socket; } value.goaccess = goaccess; return { kind: "domain_https", domain_https: value }; };
  const publication = (form) => { if (formValue(form, "publication_kind") === "temporary_ip_http") return { kind: "temporary_ip_http", temporary_ip_http: { public_ipv4: formValue(form, "public_ipv4"), port: Number(formValue(form, "public_port")) } }; return domainPublication(form); };
  const resourcePart = (form, kind) => { if (kind === "local_http") { const value = { name: formValue(form, "name"), endpoint_kind: formValue(form, "endpoint_kind") }; if (value.endpoint_kind === "tcp_socket_activation") { value.tcp_address = formValue(form, "tcp_address"); value.tcp_port = Number(formValue(form, "tcp_port")); } value.readiness_path = formValue(form, "readiness_path"); value.allowed_http_statuses = values(formValue(form, "allowed_http_statuses")).map(Number).sort((a, b) => a - b); value.websocket = websocket(form); value.executable = formValue(form, "executable"); value.arguments = lines(formValue(form, "arguments")); value.working_directory = formValue(form, "working_directory"); const environment = formValue(form, "environment_file"); if (environment) value.environment_file = environment; value.write_paths = lines(formValue(form, "write_paths")); value.publication = publication(form); return value; } const value = { name: formValue(form, "name"), peer_ip: formValue(form, "peer_ip"), source_ip: formValue(form, "source_ip"), port: Number(formValue(form, "remote_port")), readiness_path: formValue(form, "readiness_path"), allowed_http_statuses: values(formValue(form, "allowed_http_statuses")).map(Number).sort((a, b) => a - b), websocket: websocket(form), publication: publication(form) }; return value; };
  const createRequest = (form) => { const target_kind = formValue(form, "target_kind"); return target_kind === "local_http" ? { target_kind, local: resourcePart(form, target_kind) } : { target_kind, tailnet: resourcePart(form, target_kind) }; };
  const updateRequest = (form) => createRequest(form);
  const validateResourceForm = (form) => { const kind = formValue(form, "target_kind"), args = lines(formValue(form, "arguments")), badArgument = args.find((argument) => /\$\{|\$\(|%/.test(argument) || argument.includes(String.fromCharCode(96))); if (form.elements.arguments) form.elements.arguments.setCustomValidity(badArgument ? "Arguments cannot contain shell expansion, backticks, or systemd specifiers." : ""); if (kind === "local_http" && (!formValue(form, "executable") || !formValue(form, "working_directory"))) { setStatus("Executable and working directory are required for local_http"); return false; } if (kind === "tailnet_http" && (!formValue(form, "peer_ip") || !formValue(form, "source_ip") || !formValue(form, "remote_port"))) { setStatus("Peer IP, source IP, and remote port are required for tailnet_http"); return false; } if (formValue(form, "publication_kind") === "temporary_ip_http" && (!formValue(form, "public_ipv4") || !formValue(form, "public_port"))) { setStatus("Temporary HTTP requires an explicit public IPv4 and port"); return false; } if (formValue(form, "publication_kind") !== "temporary_ip_http" && (!formValue(form, "canonical_domain") || !formValue(form, "access_mode"))) { setStatus("A domain HTTPS or explicit temporary publication is required"); return false; } if (formValue(form, "access_mode") === "basic" && !formValue(form, "credential_id")) { setStatus("Basic publication requires a selected credential"); return false; } return !badArgument; };
  const fillDependencyOptions = (form, name, ids, current, emptyLabel) => { const control = form.elements[name]; if (!control || control.tagName !== "SELECT") return; const values = Array.from(new Set([...(ids || []), current || ""].filter(Boolean))).sort(); control.innerHTML = ""; const empty = document.createElement("option"); empty.value = ""; empty.textContent = emptyLabel; control.appendChild(empty); values.forEach((id) => { const option = document.createElement("option"); option.value = id; option.textContent = id; control.appendChild(option); }); control.value = current || ""; };
  const fillPublicationForm = (form, publication, dependencySource = []) => { if (!publication) return; const p = publication.domain_https || publication.temporary_ip_http; if (!p) return; if (form.elements.publication_kind) form.elements.publication_kind.value = publication.kind || "domain_https"; if (publication.kind === "temporary_ip_http") { if (form.elements.public_ipv4) form.elements.public_ipv4.value = p.public_ipv4 || ""; if (form.elements.public_port) form.elements.public_port.value = p.port || ""; return; } const typedDependencies = Array.isArray(dependencySource) && dependencySource.length && typeof dependencySource[0] === "object"; const credentialIDs = typedDependencies ? dependencySource.filter((value) => value.kind === "managed_basic").map((value) => value.id) : dependencySource; const externalIDs = typedDependencies ? dependencySource.filter((value) => value.kind === "external_htpasswd").map((value) => value.id) : (p.goaccess?.credential_id ? [p.goaccess.credential_id] : []); const staticIDs = typedDependencies ? dependencySource.filter((value) => value.kind === "static_root").map((value) => value.id) : (p.static_root_id ? [p.static_root_id] : []); fillDependencyOptions(form, "credential_id", credentialIDs, p.credential_id, "No credential selected"); fillDependencyOptions(form, "static_root_id", staticIDs, p.static_root_id, "No static root selected"); fillDependencyOptions(form, "goaccess_credential_id", externalIDs, p.goaccess?.credential_id, "No htpasswd selected"); ["canonical_domain", "access_mode", "credential_id", "static_root_id", "goaccess_credential_id", "goaccess_dashboard_path", "goaccess_websocket_path", "challenge_method", "directory_url", "account_email", "dns_provider", "provider_profile_path", "authoritative_zone"].forEach((name) => { if (form.elements[name]) form.elements[name].value = p[name] || ""; }); if (form.elements.aliases) form.elements.aliases.value = (p.aliases || []).join(","); if (form.elements.cidrs) form.elements.cidrs.value = (p.cidrs || []).join(","); const certificateValue = p.certificate || {}; ["challenge_method", "directory_url", "account_email", "dns_provider", "provider_profile_path", "authoritative_zone"].forEach((name) => { if (form.elements[name] && certificateValue[name] !== undefined) form.elements[name].value = certificateValue[name] || ""; }); if (form.elements.terms_accepted) form.elements.terms_accepted.checked = !!certificateValue.terms_accepted; const goaccess = p.goaccess || {}; if (form.elements.goaccess_enabled) form.elements.goaccess_enabled.checked = !!goaccess.enabled; if (form.elements.goaccess_credential_id) form.elements.goaccess_credential_id.value = goaccess.credential_id || ""; if (form.elements.goaccess_cidrs) form.elements.goaccess_cidrs.value = (goaccess.cidrs || []).join(","); if (form.elements.goaccess_dashboard_path) form.elements.goaccess_dashboard_path.value = goaccess.dashboard_path || ""; if (form.elements.goaccess_websocket_path) form.elements.goaccess_websocket_path.value = goaccess.websocket_path || ""; const mappings = form.querySelector("#static-mapping-rows"); if (mappings && p.static_mappings) { const first = mappings.querySelector(".mapping-row"); mappings.innerHTML = ""; (p.static_mappings || []).forEach((mapping) => { const row = first.cloneNode(true); row.querySelector("[name=static_url_path]").value = mapping.url_path || ""; row.querySelector("[name=static_relative_path]").value = mapping.relative_path || ""; row.querySelector("[name=static_mapping_kind]").value = mapping.directory ? "directory" : "file"; row.querySelector("[name=static_access]").value = mapping.anonymous ? "anonymous" : "authenticated"; mappings.appendChild(row); }); if (!mappings.querySelector(".mapping-row")) mappings.appendChild(first); }};
  const fillForm = (form, resource) => { const source = resource.configuration || resource, target = source.target_kind || resource.target_kind || resource.kind || "local_http", part = source.local || source.tailnet || source; form.elements.target_kind && (form.elements.target_kind.value = target); form.elements.name && (form.elements.name.value = part.name || ""); ["readiness_path", "executable", "working_directory", "environment_file", "peer_ip", "source_ip"].forEach((name) => { if (form.elements[name]) form.elements[name].value = part[name] || ""; }); if (form.elements.remote_port) form.elements.remote_port.value = part.port || ""; if (form.elements.tcp_port) form.elements.tcp_port.value = part.tcp_port || ""; if (form.elements.tcp_address) form.elements.tcp_address.value = part.tcp_address || ""; if (form.elements.arguments) form.elements.arguments.value = (part.arguments || []).join("\\n"); if (form.elements.write_paths) form.elements.write_paths.value = (part.write_paths || []).join("\\n"); if (form.elements.allowed_http_statuses) form.elements.allowed_http_statuses.value = (part.allowed_http_statuses || [200]).join(","); if (form.elements.websocket_enabled) { form.elements.websocket_enabled.checked = !!part.websocket?.enabled; if (form.elements.websocket_path) form.elements.websocket_path.value = part.websocket?.path || ""; } fillPublicationForm(form, part.publication || resource.publication, resource.dependencies || part.credential_ids); toggleTarget(form); };
  const toggleTarget = (form) => { const kind = formValue(form, "target_kind"), local = form.querySelector("#create-local-fields"), tailnet = form.querySelector("#create-tailnet-fields"); if (local) local.hidden = kind !== "local_http"; if (tailnet) tailnet.hidden = kind !== "tailnet_http"; const tcp = form.querySelector("#create-tcp-fields"), endpoint = formValue(form, "endpoint_kind") === "tcp_socket_activation"; if (tcp) tcp.hidden = !endpoint; ["tcp_address", "tcp_port"].forEach((name) => { if (form.elements[name]) form.elements[name].required = endpoint; }); if (form.elements.websocket_path) form.elements.websocket_path.required = checked(form, "websocket_enabled"); const domain = form.querySelector("#create-domain-fields"), temporary = form.querySelector("#create-temporary-fields"); if (domain) domain.hidden = formValue(form, "publication_kind") === "temporary_ip_http"; if (temporary) temporary.hidden = !domain || !domain.hidden; };
  const selectResource = (resource) => { selected = resource; const id = resource.resource_id || resource.id || ""; ["publish-resource", "resource_id"].forEach((name) => { document.querySelectorAll("[name=" + name + "]").forEach((input) => { if (input.type === "hidden") input.value = id; }); }); const update = $("resource-update-json"); if (update) { update.elements.resource_id.value = id; fillForm(update, resource); const name = update.elements.name, targetKind = update.elements.target_kind; if (name) name.readOnly = true; if (targetKind) targetKind.disabled = true; } const configuration = resource.configuration || resource, part = configuration.local || configuration.tailnet || configuration, publication = part.publication || resource.publication; fillPublicationForm($("domain-config"), publication, resource.dependencies || part.credential_ids); if (publication?.domain_https) { $("basic-rotate").elements.credential_id.value = publication.domain_https.credential_id || ""; $("basic-delete").elements.credential_id.value = publication.domain_https.credential_id || ""; } $("detail-title").textContent = (resource.name || "Application") + " · " + id; renderDetail(resource); };
  const actionButtons = (resource) => { const id = resource.resource_id || resource.id || "", target = resource.target_kind || resource.kind || "local_http", observed = resource.process_observed_status || resource.process_observed || resource.observed_process || "unknown", publication = resource.publication_status || resource.publication_state || resource.publication || "unknown", allowed = new Set(resource.allowed_actions || []), can = (action) => allowed.has(action); let html = "<button type=\"button\" data-select=\"" + id + "\">Review status</button>"; if (can("edit")) html += "<button type=\"button\" data-edit=\"" + id + "\">Edit configuration</button>"; if (target === "local_http" && observed !== "unknown" && can(observed === "running" ? "stop" : "start")) html += "<button type=\"button\" data-process=\"" + (observed === "running" ? "stop" : "start") + "\" data-resource=\"" + id + "\">" + (observed === "running" ? "Stop" : "Start") + " process</button>"; if (publication === "published" && can("unpublish")) html += "<button type=\"button\" data-publish=\"unpublish\" data-resource=\"" + id + "\">Unpublish</button>"; if (publication === "published" && can("republish")) html += "<button type=\"button\" data-publish=\"publish\" data-resource=\"" + id + "\">Republish</button>"; if (publication !== "published" && can("publish")) html += "<button type=\"button\" data-publish=\"publish\" data-resource=\"" + id + "\">Publish</button>"; if (can("delete")) html += "<button type=\"button\" data-delete=\"" + id + "\">Delete</button>"; return html; };
  const renderDetail = (resource) => { const detail = $("resource-detail"), statusValue = resource.overall_status || resource.status || resource.overall || "unknown", connector = resource.connector_observation, route = resource.route_evidence, target = resource.target_observation, allowed = new Set(resource.allowed_actions || []), canEdit = allowed.has("edit"), configuration = resource.configuration || resource, part = configuration.local || configuration.tailnet || configuration, publication = part.publication || resource.publication, credentialID = publication?.domain_https?.credential_id || ""; detail.hidden = false; $("detail-status").textContent = "Status: " + statusValue + " · configuration: " + (resource.configuration_status || "unknown") + " · process requested: " + (resource.process_requested_status || "not_applicable") + " · process observed: " + (resource.process_observed_status || "not_applicable") + " · target: " + (resource.target_status || "unknown") + " · publication: " + (resource.publication_status || "unknown") + (resource.next_step ? " — " + resource.next_step : ""); const dependencyValues = resource.dependencies || []; if ($("dependency-status")) $("dependency-status").textContent = "Dependency identities: " + (dependencyValues.length ? dependencyValues.map((value) => value.id + " (" + value.state + ")").join(", ") : "none") + ". New dependency secrets are delivered only once; status and Job views never contain secret bytes."; const connectorText = connector ? "validity=" + (connector.validity || "unknown") + ", control=" + (connector.control_url || "unknown") + ", client=" + (connector.client_version || "unknown") + ", client_digest=" + (connector.client_identity_digest || "unknown") + ", local_digest=" + (connector.local_identity_digest || "unknown") + ", observed_at=" + (connector.observed_at || "unknown") + ", valid_until=" + (connector.valid_until || "unknown") : "not_applicable"; const routeText = route ? "validity=" + (route.validity || "unknown") + ", peer=" + (route.peer_ip || "unknown") + ", source=" + (route.source_ip || "unknown") + ", port=" + (route.port || "unknown") + ", route_identity=" + (route.route_identity || "unknown") + ", observed_at=" + (route.observed_at || "unknown") + ", valid_until=" + (route.valid_until || "unknown") + ", failure=" + (route.failure || "none") : "not_applicable"; const targetText = target ? "validity=" + (target.validity || "unknown") + ", port_connected=" + target.port_connected + ", http_ready=" + target.http_ready + ", websocket_required=" + target.websocket_required + ", websocket_ready=" + target.websocket_ready + ", HTTP=" + (target.http_status || "n/a") + ", route_identity=" + (target.route_identity || "n/a") + ", observed_at=" + (target.observed_at || "unknown") + ", failure=" + (target.failure || "none") : "not_applicable"; $("detail-evidence").textContent = "Failure: " + (resource.failure_category || "none") + " · affected: " + (resource.affected_object || "none") + " · last operation: " + (resource.last_operation || "none") + " · Job: " + (resource.job_id || "none") + (resource.job_pending ? " (pending)" : "") + "\\nConnector: " + (resource.connector_status || "not_applicable") + " [" + connectorText + "]\\nRoute: " + (resource.route_status || "not_applicable") + " [" + routeText + "]\\nTarget: " + (resource.target_status || "unknown") + " [" + targetText + "]\\nFixed endpoint: " + (resource.target_peer_ip || "local") + (resource.target_source_ip ? " via " + resource.target_source_ip : "") + (resource.target_port ? ":" + resource.target_port : "") + "\\nTyped evidence is authority-bound and freshness checked. Fingerprints and digests only; secret bytes are never displayed."; resourceManaged.forEach((id) => { const node = $(id); if (node) node.hidden = true; }); if (editing && canEdit) { $("resource-update-json").hidden = false; $("domain-config").hidden = publication?.kind !== "domain_https"; $("basic-create").hidden = false; $("basic-rotate").hidden = !credentialID; $("basic-delete").hidden = !credentialID; $("static-register").hidden = false; $("external-htpasswd-register").hidden = false; } $("detail-actions").innerHTML = actionButtons(resource); };
  const renderCatalog = (value) => { const list = $("resource-list"), resources = value.resources || value.items || value; if (!Array.isArray(resources)) return; list.innerHTML = ""; resources.forEach((resource) => { const card = document.createElement("article"); card.className = "resource-card"; const id = resource.resource_id || resource.id || "unknown"; card.innerHTML = "<h3>" + escapeHTML(resource.name || id) + "</h3><p>" + escapeHTML(resource.target_kind || resource.kind || "resource") + " · <strong>" + escapeHTML(resource.overall_status || resource.status || resource.overall || "unknown") + "</strong></p><p>Configuration: " + escapeHTML(resource.configuration_status || "unknown") + " · process: " + escapeHTML(resource.process_observed_status || "not_applicable") + " · publication: " + escapeHTML(resource.publication_status || resource.publication_state || "unknown") + "</p><p>Failure: " + escapeHTML(resource.failure_category || "none") + " · affected: " + escapeHTML(resource.affected_object || "none") + "</p><p>Last operation: " + escapeHTML(resource.last_operation || "none") + " · Job: " + escapeHTML(resource.job_id || "none") + (resource.job_pending ? " (pending)" : "") + " · Next: " + escapeHTML(resource.next_step || "refresh") + "</p><div>" + actionButtons(resource) + "</div>"; list.appendChild(card); }); };
  const escapeHTML = (value) => String(value).replace(/[&<>\"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;", "\"":"&quot;", "'":"&#39;"}[char]));
  const refresh = async (resourceID = "", announce = true) => { const suffix = resourceID ? "?resource_id=" + encodeURIComponent(resourceID) : ""; try { const response = await fetch("/api/actions/status" + suffix, { method: "POST", headers: headers(), body: "{}" }); if (!response.ok) { if (resourceID) { resourceManaged.forEach((id) => { const node = $(id); if (node) node.hidden = true; }); } if (announce) setStatus("Status unavailable; no lifecycle or publication action is available"); return null; } const value = await json(response); if (!resourceID) renderCatalog(value); else if (value) { value.resource_id = resourceID; if (selected) { Object.assign(selected, value); fillForm($("resource-update-json"), value); fillPublicationForm($("domain-config"), (value.configuration?.local || value.configuration?.tailnet || {}).publication, value.dependencies || (value.configuration?.local || value.configuration?.tailnet || {}).credential_ids); } renderDetail(value); } return value; } catch (_) { if (resourceID) resourceManaged.forEach((id) => { const node = $(id); if (node) node.hidden = true; }); if (announce) setStatus("Status unavailable; no lifecycle or publication action is available"); return null; } };
  const planAndRun = async (operation, query, body, confirmation, label) => { const planBody = operation === "headscale_control_deploy" || operation === "headscale_certificate_reissue" ? Object.assign({ plan_id: "", confirmation: "" }, body || {}) : body || {}; const planned = await fetch("/api/actions/" + operation + "/plan" + query, { method: "POST", headers: headers(), body: JSON.stringify(planBody) }); if (!planned.ok) { setStatus(label + " Plan failed"); return null; } const plan = await json(planned); if (!confirm("Review " + plan.operation + " for " + plan.target_kind + ". " + plan.exposure_summary + ". " + plan.prerequisites + ". Expires " + plan.expires_at + ". Continue?")) return null; const finalBody = Object.assign({ plan_id: plan.plan_id, confirmation }, body || {}); return report(await fetch("/api/actions/" + operation + query, { method: "POST", headers: headers(), body: JSON.stringify(finalBody) }), label + " failed"); };
  const submitResource = async (event, update) => { event.preventDefault(); const form = event.currentTarget; if (!validateResourceForm(form)) return; const body = update ? updateRequest(form) : createRequest(form); if (formValue(form, "publication_kind") === "temporary_ip_http" && !confirm("Temporary HTTP is plaintext and may expose the application. Save this unverified, unpublished configuration?")) return; const query = update ? "?resource_id=" + encodeURIComponent(formValue(form, "resource_id")) : ""; const response = await fetch("/api/actions/resource_" + (update ? "update" : "create") + query, { method: "POST", headers: headers(), body: JSON.stringify(body) }); const value = await report(response, update ? "Configuration save failed" : "Application create failed"); if (value) { const job = value.job_id ? " · Job " + value.job_id + " (" + (value.job_result || "succeeded") + ")" : ""; setStatus((update ? "Configuration saved; resource remains stopped and unpublished" : "Application saved; resource remains stopped and unpublished") + job); await refresh("", false); } };
  const headscaleCertificate = (form) => certificate(form, true);
  const displayLegacy = async (response) => { const value = await json(response); if (!response.ok) { setStatus(value.error_code === "foreign_database_evidence" ? "Blocked: foreign Headscale database, account, or artifact evidence; job " + value.job_id : value.error_code === "connector_required" ? "Connector binding required" : value.error || "Action failed"); return value; } setStatus(value.message || value.reason || JSON.stringify(value)); return value; };
  const updateFields = $("resource-update-json").querySelector(".update-fields"); if (updateFields) { const editor = $("resource-create").querySelector("fieldset").cloneNode(true); editor.querySelectorAll("button").forEach((node) => node.remove()); updateFields.appendChild(editor); }
  login.addEventListener("submit", async (event) => { event.preventDefault(); const input = login.elements.token, token = input.value; input.value = ""; const response = await fetch("/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token }) }); if (!response.ok) { setStatus("Authentication failed"); return; } const value = await json(response); proof = value.proof; csrf = value.csrf; sessionStorage.setItem(proofKey, proof); sessionStorage.setItem(csrfKey, csrf); const session = await fetch("/api/session", { headers: { "X-LanPanel-Session-Proof": proof } }), sessionValue = session.ok ? await json(session) : {}; show(true, sessionValue.profile === "emergency"); setStatus(sessionValue.profile === "emergency" ? "Authenticated: startup recovery incomplete; expansion actions are disabled" : "Authenticated"); refresh("", false); });
  $("logout").addEventListener("click", async () => { try { await fetch("/api/logout", { method: "POST", headers: { "X-LanPanel-Session-Proof": proof, "X-LanPanel-CSRF": csrf } }); } finally { clearSession(); history.replaceState(null, "", "/"); location.replace("/"); } });
  $("rotate").addEventListener("click", async () => { const value = await planAndRun("admin_token_rotate", "", {}, "rotate", "Rotation"); if (value && value.token) { clearSession(); setStatus("New admin token: " + value.token); } });
  $("close-all").addEventListener("click", async () => { const value = await planAndRun("close_all", "", {}, "close", "Close-all"); if (value) setStatus(contractionStatus(value, "All App origin ingress closed")); });
  const contractionStatus = (value, success) => value.outcome === "succeeded" && value.access_closed && !value.shared_ingress_down && !value.access_may_remain ? success : value.outcome === "partial" && value.access_closed && value.shared_ingress_down && !value.access_may_remain ? "App access closed; shared ingress is down" : "Unknown: App access may remain";
  $("refresh-status").addEventListener("click", () => refresh()); $("resource-create-open").addEventListener("click", () => { $("resource-create").hidden = false; window.scrollTo(0, $("resource-create").offsetTop); });
  $("create-target-kind").addEventListener("change", (event) => toggleTarget(event.currentTarget.form)); $("resource-create").addEventListener("change", (event) => { if (event.target.name === "publication_kind") toggleTarget(event.currentTarget); }); $("resource-create").addEventListener("submit", (event) => submitResource(event, false)); $("resource-update-json").addEventListener("submit", (event) => submitResource(event, true));
  document.querySelectorAll("[data-cancel-form]").forEach((button) => button.addEventListener("click", () => { $(button.dataset.cancelForm).hidden = true; })); const mappingRows = $("static-mapping-rows"); $("static-mapping-add").addEventListener("click", () => { const row = mappingRows.querySelector(".mapping-row").cloneNode(true); row.querySelectorAll("input").forEach((input) => { input.value = ""; }); mappingRows.appendChild(row); }); mappingRows.addEventListener("click", (event) => { if (event.target.matches("[data-remove-mapping]") && mappingRows.querySelectorAll(".mapping-row").length > 1) event.target.closest(".mapping-row").remove(); });
  const resourceAction = async (node) => { const id = node.dataset.resource || node.dataset.select || node.dataset.edit || node.dataset.delete || node.dataset.publish || ""; const resource = { resource_id: id }; if (node.dataset.select || node.dataset.edit) { editing = !!node.dataset.edit; selectResource(resource); await refresh(id); return; } if (node.dataset.process) { const op = node.dataset.process === "start" ? "process_start" : "process_stop"; await displayLegacy(await fetch("/api/actions/" + op + "?resource_id=" + encodeURIComponent(id), { method: "POST", headers: headers() })); await refresh(id, false); return; } if (node.dataset.publish) { const op = node.dataset.publish, value = await planAndRun(op, "?resource_id=" + encodeURIComponent(id), {}, op, op === "publish" ? "Publish" : "Unpublish"); if (value) { setStatus(op === "unpublish" ? contractionStatus(value, "App unpublished") : "Publication job " + (value.job_id || "started")); await refresh(id, false); } return; } if (node.dataset.delete) { const value = await planAndRun("resource_delete", "?resource_id=" + encodeURIComponent(id), {}, "delete", "Delete"); if (value) { clearResourceSelection(); setStatus("Application deleted"); await refresh("", false); } } };
  const invokeResourceAction = async (node) => { if (!node.matches("button") || node.disabled) return; node.disabled = true; try { await resourceAction(node); } catch (_) { setStatus("Resource action unavailable; status remains fail-closed"); } finally { node.disabled = false; } }; $("resource-list").addEventListener("click", async (event) => invokeResourceAction(event.target)); $("detail-actions").addEventListener("click", async (event) => invokeResourceAction(event.target));
  const oldResource = (form, field = "resource_id") => form.elements[field] ? form.elements[field].value.trim() : "";
  $("process-control").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget, button = event.submitter; button.disabled = true; const op = button.value === "start" ? "process_start" : "process_stop"; try { await displayLegacy(await fetch("/api/actions/" + op + "?resource_id=" + encodeURIComponent(oldResource(form)), { method: "POST", headers: headers() })); } finally { button.disabled = false; } });
  $("resource-delete").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; await planAndRun("resource_delete", "?resource_id=" + encodeURIComponent(oldResource(form)), {}, "delete", "Delete"); });
  $("publish").addEventListener("submit", async (event) => { event.preventDefault(); const id = oldResource(event.currentTarget); const value = await planAndRun("publish", "?resource_id=" + encodeURIComponent(id), {}, "publish", "Publish"); if (value) setStatus(value.job_result === "partial" ? "Published; GoAccess retirement pending; job " + value.job_id : "Published " + (value.public_url || "")); });
  $("unpublish").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget, value = await planAndRun("unpublish", "?resource_id=" + encodeURIComponent(oldResource(form)), {}, "unpublish", "Unpublish"); if (value) setStatus(contractionStatus(value, "App unpublished")); });
  $("domain-status").addEventListener("submit", async (event) => { event.preventDefault(); const id = oldResource(event.currentTarget); const value = await refresh(id); if (value) setStatus((value.status || value.overall || "unknown") + ": " + (value.reason || "")); });
  $("domain-config").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget, resource_id = oldResource(form), mappings = mappingValues(form).slice(0, 129); const body = { schema_version: "lanpanel.domain-publication.update.v1", resource_id, publication: domainPublication(form, mappings).domain_https }; const response = await fetch("/api/actions/resource_update?resource_id=" + encodeURIComponent(resource_id), { method: "POST", headers: headers(), body: JSON.stringify(body) }); const value = await displayLegacy(response); if (value && response.ok) { setStatus("Pending domain HTTPS config saved" + (value.job_id ? " · Job " + value.job_id + " (" + (value.job_result || "succeeded") + ")" : "")); await refresh(resource_id, false); } });
  const lifecycle = async (operation, parameter, id, body, confirmation) => { const value = await planAndRun(operation, "?" + parameter + "=" + encodeURIComponent(id), body, confirmation, operation); if (operation === "preauth_key_create" && value && value.secret) setStatus("Preauth key (shown once): " + atob(value.secret)); if (operation === "managed_basic_rotate" && value && value.password) setStatus("Managed Basic password (shown once): " + atob(value.password)); };
  $("headscale-initialize").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; if (!confirm("Initialize this immutable trusted-mesh identity? Control domain and database identity cannot be changed or removed.")) return; const value = await displayLegacy(await fetch("/api/actions/headscale_initialize", { method: "POST", headers: headers(), body: JSON.stringify({ control_domain: formValue(form, "control_domain"), magicdns_namespace: formValue(form, "magicdns_namespace"), confirmation: "initialize" }) })); if (value && value.target_id) { setStatus("Headscale identity " + value.target_id + " initialized; control service and ingress remain inactive"); form.hidden = true; } });
  $("headscale-control").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget, certificate = headscaleCertificate(form), value = await planAndRun("headscale_control_deploy", "", { certificate }, "deploy", "Headscale control deploy"); if (value) setStatus("Headscale control deployed; job " + value.job_id); });
  $("headscale-reissue").addEventListener("click", async () => { const form = $("headscale-control"), value = await planAndRun("headscale_certificate_reissue", "", { certificate: headscaleCertificate(form) }, "reissue", "Headscale reissue"); if (value) setStatus("Headscale certificate reissued"); });
  $("headscale-user-create").addEventListener("submit", async (event) => { event.preventDefault(); await displayLegacy(await fetch("/api/actions/headscale_user_create", { method: "POST", headers: headers(), body: JSON.stringify({ name: formValue(event.currentTarget, "name") }) })); });
  $("headscale-key-create").addEventListener("submit", (event) => { event.preventDefault(); const form = event.currentTarget; lifecycle("preauth_key_create", "user_id", formValue(form, "user_id"), { expiration_seconds: Number(formValue(form, "expiration_seconds")) }, "create"); });
  $("headscale-key-revoke").addEventListener("submit", (event) => { event.preventDefault(); lifecycle("preauth_key_revoke", "key_id", formValue(event.currentTarget, "key_id"), {}, "revoke"); }); $("headscale-device-expire").addEventListener("submit", (event) => { event.preventDefault(); lifecycle("device_expire", "device_id", formValue(event.currentTarget, "device_id"), {}, "expire"); });
  ["headscale-reads", "product-reads"].forEach((id) => $(id).addEventListener("click", async (event) => { if (event.target.dataset.read) await displayLegacy(await fetch("/api/actions/" + event.target.dataset.read, { method: "POST", headers: headers(), body: "{}" })); }));
  $("connector-binding").addEventListener("submit", async (event) => { event.preventDefault(); await displayLegacy(await fetch("/api/actions/connector_binding_set", { method: "POST", headers: headers(), body: JSON.stringify({ control_url: formValue(event.currentTarget, "control_url") }) })); }); $("connector-login").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget, key = formValue(form, "auth_key"); form.elements.auth_key.value = ""; const planned = await fetch("/api/actions/connector_login/plan", { method: "POST", headers: headers(), body: "{}" }); if (!planned.ok) { setStatus("Connector login Plan failed"); return; } const plan = await json(planned); if (!confirm(plan.exposure_summary + ". Login?")) return; const value = await displayLegacy(await fetch("/api/actions/connector_login", { method: "POST", headers: headers(), body: JSON.stringify({ plan_id: plan.plan_id, confirmation: "login", auth_key: btoa(key) }) })); if (value && value.job_id) setStatus("Connector login submitted"); }); $("connector-verify").addEventListener("click", async () => displayLegacy(await fetch("/api/actions/connector_verify", { method: "POST", headers: headers(), body: "{}" })));
  $("job-detail").addEventListener("submit", async (event) => { event.preventDefault(); await displayLegacy(await fetch("/api/actions/job_detail?job_id=" + encodeURIComponent(formValue(event.currentTarget, "job_id")), { method: "POST", headers: headers(), body: "{}" })); }); $("basic-create").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget, response = await fetch("/api/actions/managed_basic_create?resource_id=" + encodeURIComponent(oldResource(form)), { method: "POST", headers: headers(), body: JSON.stringify({ username: formValue(form, "username"), confirmation: "generate" }) }), value = await json(response); if (!response.ok) { setStatus(value.error || "Managed Basic create failed"); return; } if (value.credential_id) { fillDependencyOptions($("domain-config"), "credential_id", [value.credential_id], value.credential_id, "No credential selected"); $("basic-rotate").elements.credential_id.value = value.credential_id; $("basic-delete").elements.credential_id.value = value.credential_id; } if (value.password) setStatus("Managed Basic password (shown once): " + atob(value.password)); }); $("basic-rotate").addEventListener("submit", (event) => { event.preventDefault(); lifecycle("managed_basic_rotate", "credential_id", oldResource(event.currentTarget, "credential_id"), {}, "rotate"); }); $("basic-delete").addEventListener("submit", (event) => { event.preventDefault(); lifecycle("managed_basic_delete", "credential_id", oldResource(event.currentTarget, "credential_id"), {}, "delete"); }); $("static-register").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const value = await displayLegacy(await fetch("/api/actions/static_root_register?resource_id=" + encodeURIComponent(oldResource(form)), { method: "POST", headers: headers(), body: JSON.stringify({ path: formValue(form, "path"), confirmation: "register" }) })); if (value && value.target_id) fillDependencyOptions($("domain-config"), "static_root_id", [value.target_id], value.target_id, "No static root selected"); }); $("external-htpasswd-register").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const value = await displayLegacy(await fetch("/api/actions/external_htpasswd_register?resource_id=" + encodeURIComponent(oldResource(form)), { method: "POST", headers: headers(), body: JSON.stringify({ path: formValue(form, "path"), confirmation: "register" }) })); if (value && value.target_id) fillDependencyOptions($("domain-config"), "goaccess_credential_id", [value.target_id], value.target_id, "No htpasswd selected"); });
  document.querySelectorAll("[name=target_kind], [name=endpoint_kind], [name=publication_kind]").forEach((node) => node.addEventListener("change", () => toggleTarget(node.form))); toggleTarget($("resource-create")); toggleTarget($("resource-update-json"));
  addEventListener("pagehide", clearSession); addEventListener("pageshow", (event) => { if (event.persisted) { clearSession(); location.replace("/"); } });
  show(false); if (proof && csrf) fetch("/api/session", { headers: { "X-LanPanel-Session-Proof": proof } }).then(async (response) => { if (!response.ok) { clearSession(); return; } const value = await json(response); show(true, value.profile === "emergency"); refresh("", false); }).catch(() => clearSession());
  // Plan requests intentionally use canonical JSON: JSON.stringify({plan_id:"",confirmation:"",certificate}) and JSON.stringify({plan_id:"",confirmation:"",certificate}).
  // Managed Basic rotate remains a planned operation: /api/actions/managed_basic_rotate/plan and confirmation:"rotate".
  // Typed status may show App credential <id> fingerprint <digest>, credential_id, credential_fingerprint, GoAccess credential <id> fingerprint <digest>, goaccess_credential_id, goaccess_credential_fingerprint, goaccess_credential_changed, and goaccess_retirement_job_id/goaccess_retirement_generations. GoAccess retirement pending; job evidence remains non-secret.
})();`

const appJS = structuredAppJS

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
