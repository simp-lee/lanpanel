// Package ui serves the exact loopback Management authority.
package ui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"lanpanel/internal/session"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
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
}
type Server struct {
	config  Config
	http    *http.Server
	barrier sync.RWMutex
	output  sync.Mutex
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
		return nil, fmt.Errorf("Management UI config is incomplete")
	}
	server := &Server{config: config}
	server.http = &http.Server{Handler: server, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return server, nil
}
func (s *Server) Serve() error { return s.http.Serve(s.config.Listener) }
func (s *Server) Shutdown(ctx context.Context) error {
	s.config.Sessions.Close()
	return s.http.Shutdown(ctx)
}
func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	securityHeaders(writer)
	if request.Host != s.config.Authority || request.URL.RawQuery != "" || request.URL.RawPath != "" {
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
	case request.Method == http.MethodGet && request.URL.Path == "/assets/app.1b6c82e4.js":
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
	_, _ = io.WriteString(writer, `<!doctype html><html><head><meta charset="utf-8"><title>LanPanel</title><link rel="stylesheet" href="/assets/app.8d13f0c2.css"></head><body><main><h1>LanPanel</h1><p id="fingerprint">`+template.HTMLEscapeString(s.config.InstallationFingerprint)+`</p><form id="login" method="post" action="/login" enctype="application/x-www-form-urlencoded"><label>Admin token<input name="token" type="password" autocomplete="current-password"></label><button>Login</button></form><button id="logout" hidden>Logout</button><p id="status"></p></main><script src="/assets/app.1b6c82e4.js" defer></script></body></html>`)
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
	s.barrier.RLock()
	fingerprint, err := s.config.Verifier.Verify(request.Context(), token)
	if err != nil {
		s.barrier.RUnlock()
		reject(writer, http.StatusUnauthorized)
		return
	}
	credentials, err := s.config.Sessions.Issue(s.origin(), fingerprint)
	s.barrier.RUnlock()
	if err != nil {
		reject(writer, http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: session.SelectorCookie, Value: credentials.Selector, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]string{"proof": credentials.Proof, "csrf": credentials.CSRF})
}
func (s *Server) current(writer http.ResponseWriter, request *http.Request) {
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
	defer connection.Close(websocket.StatusNormalClosure, "closed")
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
	fingerprint, err := s.config.Verifier.Source(request.Context())
	if err != nil {
		s.config.Sessions.InvalidateFingerprint("unavailable")
		return
	}
	if !s.config.Sessions.RequireFingerprint(fingerprint) {
		return
	}
	principal, err := s.config.Sessions.AuthenticateSocket(selector, frame.Proof, s.origin(), fingerprint)
	if err != nil {
		return
	}
	managed := &socket{connection: connection}
	if s.config.Sessions.Attach(principal, managed) != nil {
		return
	}
	defer s.config.Sessions.Detach(principal, managed)
	sendContext, sendCancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer sendCancel()
	if s.config.Sessions.Send(principal, fingerprint, func() error { return managed.Write(sendContext, []byte(`{"type":"ready"}`)) }) != nil {
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
		s.config.Sessions.InvalidateFingerprint("unavailable")
		return session.Principal{}, false
	}
	if !s.config.Sessions.RequireFingerprint(fingerprint) {
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
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || string(canonical) != string(payload) {
		return fmt.Errorf("noncanonical JSON")
	}
	return nil
}

const appCSS = "body{font-family:sans-serif;max-width:48rem;margin:4rem auto}label,input{display:block}"
const appJS = `(()=>{"use strict";let proof=sessionStorage.getItem("lp.proof")||"",csrf=sessionStorage.getItem("lp.csrf")||"";const status=document.getElementById("status"),login=document.getElementById("login"),logout=document.getElementById("logout");const clear=()=>{proof="";csrf="";sessionStorage.clear();status.textContent="";logout.hidden=true;login.hidden=false};login.addEventListener("submit",async event=>{event.preventDefault();const input=login.elements.token,body=new URLSearchParams({token:input.value});input.value="";const response=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});if(!response.ok){status.textContent="Authentication failed";return}const value=await response.json();proof=value.proof;csrf=value.csrf;sessionStorage.setItem("lp.proof",proof);sessionStorage.setItem("lp.csrf",csrf);status.textContent="Authenticated";login.hidden=true;logout.hidden=false});logout.addEventListener("click",async()=>{try{await fetch("/api/logout",{method:"POST",headers:{"X-LanPanel-Session-Proof":proof,"X-LanPanel-CSRF":csrf}})}finally{clear();history.replaceState(null,"","/");location.replace("/")}});addEventListener("pagehide",clear);addEventListener("pageshow",event=>{if(event.persisted){clear();location.replace("/")}})})();`
