// Package ui implements the local loopback-only LanPanel Management UI.
package ui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/hosthealth"
	"lanpanel/internal/resource"
	"lanpanel/internal/uistate"
	"lanpanel/internal/workflow"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed assets/vendor/htmx/htmx.min.js assets/vendor/htmx/VERSION
var assets embed.FS

var currentEUID = os.Geteuid

const (
	DefaultAddr              = "127.0.0.1:18080"
	DefaultStateDir          = "/var/lib/lanpanel/ui-state"
	DefaultTokenTTL          = 10 * time.Minute
	DefaultSessionTTL        = 12 * time.Hour
	DefaultOneTimeSecretTTL  = 10 * time.Minute
	DefaultFormMaxBytes      = 1 << 20
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultReadTimeout       = 30 * time.Second
	DefaultWriteTimeout      = 2 * time.Hour
	DefaultIdleTimeout       = 2 * time.Minute
	sessionCookie            = "lanpanel_ui_session"
)

type Options struct {
	Addr                 string
	Version              string
	StateDir             string
	ConfigPath           string
	AppConfigPath        string
	TokenTTL             time.Duration
	SessionTTL           time.Duration
	HostWorkflow         workflow.HostWorkflow
	PreAuthKeyCreator    workflow.PreAuthKeyCreator
	ExposureObservations exposure.AppObservations
	Now                  func() time.Time

	UnsafeAllowNonRootWritesForTest bool
}

type Server struct {
	options Options
	token   startupToken
	mux     *http.ServeMux
	state   uistate.Store
	htmx    htmxMetadata

	mu       sync.Mutex
	sessions map[string]session
	secrets  map[string]oneTimeSecret
	storeErr error
}

type startupToken struct {
	value     string
	expiresAt time.Time
	used      bool
}

type session struct {
	CSRF                    string
	CreatedAt               time.Time
	StartupTokenFingerprint string
}

type pageData struct {
	Title         string
	Version       string
	CSRF          string
	CurrentPath   string
	HTMXVersion   string
	ConfigPath    string
	AppConfigPath string
	StateDir      string
	JobRecords    []domain.JobRecord
}

type oneTimeSecret struct {
	Label                string
	Value                string
	Fingerprint          string
	JobID                string
	ExpiresAt            time.Time
	RevealExpiresAt      time.Time
	SessionIDFingerprint string
}

type htmxMetadata struct {
	Version   string
	Source    string
	SHA256    string
	CheckedAt string
}

func NewServer(options Options) (*Server, error) {
	if strings.TrimSpace(options.Addr) == "" {
		options.Addr = DefaultAddr
	}
	if options.TokenTTL == 0 {
		options.TokenTTL = DefaultTokenTTL
	}
	if options.SessionTTL == 0 {
		options.SessionTTL = DefaultSessionTTL
	}
	if strings.TrimSpace(options.ConfigPath) == "" {
		options.ConfigPath = "lanpanel.yaml"
	}
	if strings.TrimSpace(options.AppConfigPath) == "" {
		options.AppConfigPath = "lanpanel-app.yaml"
	}
	if options.TokenTTL < 0 {
		return nil, fmt.Errorf("ui token ttl must be positive")
	}
	if options.TokenTTL > 30*time.Minute {
		return nil, fmt.Errorf("ui token ttl must be at most 30m")
	}
	if options.SessionTTL < 0 {
		return nil, fmt.Errorf("ui session ttl must be positive")
	}
	if options.StateDir == "" {
		return nil, fmt.Errorf("ui state dir is required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if err := ValidateLoopbackAddr(options.Addr); err != nil {
		return nil, err
	}
	htmx, err := loadHTMXMetadata()
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	state := uistate.NewStore(options.StateDir)
	if err := state.Open(); err != nil {
		return nil, err
	}
	if err := state.RecoverInterrupted(); err != nil {
		return nil, fmt.Errorf("recover interrupted ui jobs: %w", err)
	}
	if err := state.RegisterAppConfigPath(options.AppConfigPath); err != nil {
		return nil, fmt.Errorf("register app config path: %w", err)
	}
	if _, err := resource.NewStore(filepath.Join(options.StateDir, "resources")).LoadOrCreateInstance(); err != nil {
		return nil, fmt.Errorf("initialize resource instance id: %w", err)
	}
	server := &Server{
		options:  options,
		token:    startupToken{value: token, expiresAt: options.Now().Add(options.TokenTTL)},
		mux:      http.NewServeMux(),
		state:    state,
		htmx:     htmx,
		sessions: map[string]session{},
		secrets:  map[string]oneTimeSecret{},
	}
	server.routes()
	return server, nil
}

func (server *Server) Handler() http.Handler {
	return secureHeaders(recoverPanic(maxBytesByRequest(server.mux)))
}

func (server *Server) StartupURL() string {
	host, port, err := net.SplitHostPort(server.options.Addr)
	if err != nil {
		panic("validated ui listen address became invalid: " + err.Error())
	}
	return "http://" + net.JoinHostPort(host, port) + "/login?token=" + url.QueryEscape(server.token.value)
}

func (server *Server) SSHExample() string {
	host, port, err := net.SplitHostPort(server.options.Addr)
	if err != nil || host == "" || port == "" {
		return "ssh -L 18080:127.0.0.1:18080 user@server"
	}
	if host == "::1" {
		host = "127.0.0.1"
	}
	return "ssh -L " + port + ":" + host + ":" + port + " user@server"
}

func (server *Server) TokenTTL() time.Duration {
	return server.options.TokenTTL
}

func (server *Server) ListenAndServe() error {
	return server.httpServer().ListenAndServe()
}

func (server *Server) httpServer() *http.Server {
	return &http.Server{
		Addr:              server.options.Addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       DefaultReadTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		IdleTimeout:       DefaultIdleTimeout,
	}
}

func ValidateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("ui listen address must be host:port: %w", err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return fmt.Errorf("ui listen host must be a loopback IP literal")
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("ui listen host must be loopback-only")
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("ui listen host must not be unspecified")
	}
	return nil
}

func (server *Server) routes() {
	server.mux.HandleFunc("/login", server.handleLogin)
	server.mux.HandleFunc("/static/vendor/htmx/htmx.min.js", server.handleHTMX)
	server.mux.HandleFunc("/", server.requireSession(server.handleOverview))
	server.mux.HandleFunc("/settings", server.requireSession(server.handleSettings))
	server.mux.HandleFunc("/resources", server.requireSession(server.handleResources))
	server.mux.HandleFunc("/diagnostics", server.requireSession(server.handleDiagnostics))
	server.mux.HandleFunc("/services", server.requireSession(server.handleServices))
	server.mux.HandleFunc("/certificates", server.requireSession(server.handleCertificates))
	server.mux.HandleFunc("/host-health", server.requireSession(server.handleHostHealth))
	server.mux.HandleFunc("/onboarding", server.requireSession(server.handleOnboarding))
	server.mux.HandleFunc("/jobs", server.requireSession(server.handleJobs))
	server.mux.HandleFunc("/migration", server.requireSession(server.handleMigration))
	server.mux.HandleFunc("/fragments/job-status", server.requireSession(server.handleJobFragment))
	server.mux.HandleFunc("/fragments/job-history", server.requireSession(server.handleJobHistoryFragment))
	server.mux.HandleFunc("/fragments/host-status", server.requireSession(server.handleHostStatusFragment))
	server.mux.HandleFunc("/fragments/exposure-preview", server.requireSession(server.requireCSRF(server.handleExposurePreview)))
	server.mux.HandleFunc("/jobs/run", server.requireSession(server.requireCSRF(server.requireRootForWriteJob(server.handleRunJob))))
	server.mux.HandleFunc("/jobs/create", server.requireSession(server.requireCSRF(server.requireRootForWriteJob(server.handleCreateJob))))
}

func (server *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.token.used || server.options.Now().After(server.token.expiresAt) || subtle.ConstantTimeCompare([]byte(token), []byte(server.token.value)) != 1 {
		http.Error(w, "invalid or expired startup token", http.StatusForbidden)
		return
	}
	sessionID, err := randomToken()
	if err != nil {
		http.Error(w, "create session failed", http.StatusInternalServerError)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "create csrf token failed", http.StatusInternalServerError)
		return
	}
	server.token.used = true
	server.sessions[sessionID] = session{CSRF: csrf, CreatedAt: server.options.Now(), StartupTokenFingerprint: fingerprintSecret(token)}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  server.options.Now().Add(server.options.SessionTTL),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (server *Server) handleHTMX(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := assets.ReadFile("assets/vendor/htmx/htmx.min.js")
	if err != nil {
		http.Error(w, "asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Del("Pragma")
	w.Header().Del("Expires")
	_, _ = w.Write(data)
}

func (server *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	server.renderDynamic(w, r, "Overview", server.overviewBody)
}

func (server *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Settings", server.settingsBody)
}

func (server *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Resources", server.resourcesBody)
}

func (server *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Diagnostics", server.diagnosticsBody)
}

func (server *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Services", server.servicesBody)
}

func (server *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Certificates / Nginx", server.certificatesBody)
}

func (server *Server) handleHostHealth(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Host Health", server.hostHealthBody)
}

func (server *Server) handleOnboarding(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Headscale Onboarding", server.onboardingBody)
}

func (server *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Jobs", server.jobsBody)
}

func (server *Server) handleMigration(w http.ResponseWriter, r *http.Request) {
	server.renderDynamic(w, r, "Exit / Migration", server.migrationBody)
}

func (server *Server) handleJobFragment(w http.ResponseWriter, r *http.Request) {
	records, err := server.safeRecords()
	if err != nil {
		http.Error(w, "load job records failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if len(records) == 0 {
		_, _ = io.WriteString(w, `<li class="job-feed-empty">No jobs recorded yet.</li>`)
		return
	}
	for index, record := range records {
		if index >= 6 {
			break
		}
		summary := strings.TrimSpace(record.ResultSummary)
		if summary == "" {
			summary = strings.TrimSpace(record.ErrorSummary)
		}
		if summary == "" {
			summary = string(record.Kind)
		}
		_, _ = fmt.Fprintf(w, `<li class="job-feed-item"><span class="job-feed-main"><strong>%s</strong><span>%s</span></span><span class="job-feed-kind">%s</span><span class="job-feed-state">%s</span></li>`,
			template.HTMLEscapeString(record.ID),
			template.HTMLEscapeString(summary),
			template.HTMLEscapeString(string(record.Kind)),
			statusBadge(string(record.Status)),
		)
	}
}

func (server *Server) handleJobHistoryFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	records, err := server.safeRecords()
	if err != nil {
		http.Error(w, "load job records failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, jobsHistoryHTML(server, r, records))
}

func (server *Server) handleHostStatusFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	health := hosthealth.Summarize(hosthealth.ReadLocalMetricInputs())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(hostHealthCompactHTML(health)))
}

func (server *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	server.handleRunJob(w, r)
}

func (server *Server) handleRunJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	record, err := server.startJob(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/jobs?job="+url.QueryEscape(record.ID), http.StatusSeeOther)
}

func (server *Server) handleExposurePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := server.exposurePreviewBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(body))
}

func (server *Server) renderDynamic(w http.ResponseWriter, r *http.Request, title string, build func(*http.Request) (string, error)) {
	body, err := build(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	server.render(w, r, title, body)
}

func (server *Server) render(w http.ResponseWriter, r *http.Request, title string, body string) {
	sess, ok := server.sessionFromRequest(r)
	if !ok {
		http.Error(w, "session required", http.StatusUnauthorized)
		return
	}
	records, err := server.safeRecords()
	if err != nil {
		http.Error(w, "load job records failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	body = strings.ReplaceAll(body, "__CSRF__", template.HTMLEscapeString(sess.CSRF))
	body = strings.ReplaceAll(body, "__CONFIG_PATH__", template.HTMLEscapeString(server.options.ConfigPath))
	data := pageData{
		Title:         title,
		Version:       server.options.Version,
		CSRF:          sess.CSRF,
		CurrentPath:   r.URL.Path,
		HTMXVersion:   server.htmx.Version,
		ConfigPath:    server.options.ConfigPath,
		AppConfigPath: server.options.AppConfigPath,
		StateDir:      server.options.StateDir,
		JobRecords:    records,
	}
	tmpl := template.Must(template.New("page").Parse(layoutTemplate))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, struct {
		pageData
		Body template.HTML
	}{pageData: data, Body: template.HTML(body)}); err != nil {
		http.Error(w, "render page failed", http.StatusInternalServerError)
	}
}

func (server *Server) safeRecords() ([]domain.JobRecord, error) {
	if err := server.state.Open(); err != nil {
		return nil, err
	}
	return server.state.ListRecords()
}

func (server *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := server.sessionFromRequest(r); !ok {
			http.Error(w, "session required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (server *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		sess, ok := server.sessionFromRequest(r)
		if !ok {
			http.Error(w, "session required", http.StatusUnauthorized)
			return
		}
		if err := parseUIForm(r); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "parse form failed", http.StatusBadRequest)
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.Form.Get("csrf_token")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) != 1 {
			http.Error(w, "csrf token required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func maxBytesByRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(DefaultFormMaxBytes)
		if r.URL.Path == "/jobs/run" && isMultipartForm(r) {
			limit = workflow.DependencyUploadMaxBytes + int64(DefaultFormMaxBytes)
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func parseUIForm(r *http.Request) error {
	if isMultipartForm(r) {
		return r.ParseMultipartForm(DefaultFormMaxBytes)
	}
	return r.ParseForm()
}

func isMultipartForm(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "multipart/form-data")
}

func (server *Server) requireRoot(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !server.options.UnsafeAllowNonRootWritesForTest && currentEUID() != 0 {
			http.Error(w, "write operations require the supervised Management UI role", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (server *Server) requireRootForWriteJob(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !server.options.UnsafeAllowNonRootWritesForTest && jobOperationRequiresRoot(formValue(r, "operation")) && currentEUID() != 0 {
			http.Error(w, "write operations require the supervised Management UI role", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func jobOperationRequiresRoot(operation string) bool {
	switch strings.TrimSpace(operation) {
	case "main_verify", "main_status", "app_verify", "realip_diagnostics":
		return false
	default:
		return true
	}
}

func (server *Server) sessionFromRequest(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	sess, ok := server.sessions[cookie.Value]
	if ok && server.options.Now().After(sess.CreatedAt.Add(server.options.SessionTTL)) {
		delete(server.sessions, cookie.Value)
		return session{}, false
	}
	return sess, ok
}

func (server *Server) sessionFingerprintFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	if _, ok := server.sessionFromRequest(r); !ok {
		return "", false
	}
	return fingerprintSecret(cookie.Value), true
}

func (server *Server) storeOneTimeSecretForJob(jobID string, sessionFingerprint string, secret *workflow.OneTimeSecret) (string, bool, error) {
	value, ok := secret.Consume()
	if !ok {
		return "", false, nil
	}
	if strings.TrimSpace(jobID) == "" {
		return "", false, fmt.Errorf("job id is required for one-time secret handoff")
	}
	if strings.TrimSpace(sessionFingerprint) == "" {
		return "", false, fmt.Errorf("session fingerprint is required for one-time secret handoff")
	}
	handle, err := randomToken()
	if err != nil {
		return "", false, err
	}
	server.mu.Lock()
	server.secrets[handle] = oneTimeSecret{
		Label:                secret.Label,
		Value:                value,
		Fingerprint:          secret.Fingerprint,
		JobID:                jobID,
		ExpiresAt:            secret.ExpiresAt,
		RevealExpiresAt:      server.options.Now().Add(DefaultOneTimeSecretTTL),
		SessionIDFingerprint: sessionFingerprint,
	}
	server.mu.Unlock()
	return handle, true, nil
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func fingerprintSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func loadHTMXMetadata() (htmxMetadata, error) {
	versionData, err := assets.ReadFile("assets/vendor/htmx/VERSION")
	if err != nil {
		return htmxMetadata{}, fmt.Errorf("read htmx metadata: %w", err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(versionData), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			if strings.TrimSpace(line) == "" {
				continue
			}
			return htmxMetadata{}, fmt.Errorf("parse htmx metadata line %q", line)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	meta := htmxMetadata{
		Version:   values["version"],
		Source:    values["source"],
		SHA256:    values["sha256"],
		CheckedAt: values["checked_at"],
	}
	if meta.Version == "" {
		return htmxMetadata{}, fmt.Errorf("htmx metadata version is required")
	}
	if meta.Source == "" {
		return htmxMetadata{}, fmt.Errorf("htmx metadata source is required")
	}
	if len(meta.SHA256) != sha256.Size*2 {
		return htmxMetadata{}, fmt.Errorf("htmx metadata sha256 must be %d lowercase hex characters", sha256.Size*2)
	}
	for _, r := range meta.SHA256 {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return htmxMetadata{}, fmt.Errorf("htmx metadata sha256 must be lowercase hex")
		}
	}
	if meta.CheckedAt == "" {
		return htmxMetadata{}, fmt.Errorf("htmx metadata checked_at is required")
	}
	assetData, err := assets.ReadFile("assets/vendor/htmx/htmx.min.js")
	if err != nil {
		return htmxMetadata{}, fmt.Errorf("read htmx asset: %w", err)
	}
	sum := sha256.Sum256(assetData)
	if got := hex.EncodeToString(sum[:]); got != meta.SHA256 {
		return htmxMetadata{}, fmt.Errorf("htmx asset sha256 %s does not match metadata %s", got, meta.SHA256)
	}
	if !strings.Contains(string(assetData), `version:"`+meta.Version+`"`) {
		return htmxMetadata{}, fmt.Errorf("htmx asset does not expose metadata version %s", meta.Version)
	}
	return meta, nil
}

func CopyHTMXAsset(w io.Writer) error {
	data, err := assets.ReadFile("assets/vendor/htmx/htmx.min.js")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

const layoutTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .Title }} · LanPanel</title>
  <script src="/static/vendor/htmx/htmx.min.js"></script>
  <style>
    * { box-sizing: border-box; }
    :root {
      color-scheme: light;
      --bg: #f5f6f7;
      --surface: #ffffff;
      --surface-subtle: #f9fafb;
      --surface-muted: #eef2f3;
      --border: #d9e0e3;
      --border-strong: #b9c5ca;
      --text: #182029;
      --muted: #5f6b76;
      --soft: #7a8792;
      --accent: #0f766e;
      --accent-strong: #0b5f59;
      --accent-soft: #e6f3f1;
      --danger: #b42318;
      --danger-soft: #fff1f0;
      --success: #1f7a3b;
      --success-soft: #edf8f0;
      --warning: #93630b;
      --warning-soft: #fff8e5;
      --shadow: 0 1px 2px rgba(18, 32, 41, 0.06), 0 10px 24px rgba(18, 32, 41, 0.04);
    }
    body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--text); background: var(--bg); }
    a:focus-visible, button:focus-visible, summary:focus-visible { outline: 0; box-shadow: 0 0 0 3px rgba(15,118,110,.18); }
    .app-shell { display: grid; grid-template-columns: 264px minmax(0, 1fr); min-height: 100vh; }
    .sidebar { position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column; gap: 18px; padding: 18px 14px; background: #fbfcfc; border-right: 1px solid var(--border); }
    .brand { display: flex; gap: 12px; align-items: center; padding: 4px 8px 14px; color: var(--text); text-decoration: none; border-bottom: 1px solid var(--border); }
    .brand-mark { display: grid; place-items: center; width: 34px; height: 34px; border-radius: 8px; color: #fff; background: linear-gradient(135deg, #0f766e, #12312f); font-weight: 800; letter-spacing: 0; }
    .brand-title { display: block; font-size: 15px; font-weight: 750; }
    .brand-subtitle { display: block; margin-top: 2px; color: var(--muted); font-size: 12px; }
    .side-nav { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
    .nav-section { margin: 14px 8px 5px; color: var(--soft); font-size: 11px; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }
    .side-nav a { display: flex; align-items: center; gap: 10px; min-width: 0; min-height: 34px; overflow: hidden; padding: 7px 10px; color: #26313b; text-decoration: none; text-overflow: ellipsis; white-space: nowrap; border-radius: 8px; font-size: 14px; font-weight: 550; }
    .side-nav a::before { content: ""; width: 7px; height: 7px; border-radius: 999px; background: #c3ccd1; flex: 0 0 auto; }
    .side-nav a:hover { background: var(--surface-muted); }
    .side-nav a.active { color: var(--accent-strong); background: var(--accent-soft); box-shadow: inset 0 0 0 1px rgba(15, 118, 110, 0.12); }
    .side-nav a.active::before { background: var(--accent); }
    .sidebar-meta { margin-top: auto; padding: 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--muted); font-size: 12px; }
    .sidebar-meta strong { display: block; margin-bottom: 4px; color: var(--text); font-size: 12px; }
    .workspace { min-width: 0; }
    .topbar { display: flex; justify-content: space-between; gap: 20px; align-items: flex-start; padding: 26px 32px 18px; border-bottom: 1px solid var(--border); background: rgba(255,255,255,.86); backdrop-filter: blur(10px); }
    .eyebrow { margin: 0 0 6px; color: var(--accent-strong); font-size: 12px; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }
    .topbar h1 { margin: 0; font-size: 30px; line-height: 1.15; letter-spacing: 0; }
    .topbar-meta { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; max-width: 420px; }
    .meta-pill { display: inline-flex; align-items: center; min-height: 28px; max-width: 100%; padding: 4px 9px; border: 1px solid var(--border); border-radius: 999px; background: var(--surface); color: var(--muted); font-size: 12px; white-space: nowrap; }
    .content { width: 100%; min-width: 0; max-width: 1480px; padding: 24px 32px 36px; }
    h1, h2, h3 { line-height: 1.25; margin-top: 0; letter-spacing: 0; }
    h2 { font-size: 20px; }
    h3 { font-size: 16px; }
    .panel { min-width: 0; overflow: visible; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 18px; box-shadow: var(--shadow); }
    .subpanel { min-width: 0; overflow: hidden; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
    .panel > h2, .subpanel > h3 { margin-bottom: 14px; }
    .panel > :last-child, .subpanel > :last-child { margin-bottom: 0; }
    .form-section { padding: 18px 0; border-top: 1px solid var(--border); }
    .form-section:first-of-type { padding-top: 0; border-top: 0; }
    .form-section h3 { margin-bottom: 12px; color: #26313b; }
    label { font-weight: 650; color: #28333d; }
    .field { min-width: 0; }
    .field > label { display: block; margin: 0 0 6px; font-size: 13px; }
    .field-checkbox { display: flex; align-items: center; min-height: 38px; }
    .checkbox-line { display: flex; gap: 8px; align-items: center; margin: 0; }
    .checkbox-line span { min-width: 0; overflow-wrap: anywhere; }
    input, select, textarea { width: 100%; max-width: 100%; padding: 8px 10px; border: 1px solid var(--border-strong); border-radius: 7px; background: #fff; color: var(--text); font: inherit; transition: border-color .15s ease, box-shadow .15s ease; }
    input:focus, select:focus, textarea:focus { outline: 0; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(15,118,110,.14); }
    input[type="checkbox"] { width: auto; max-width: none; margin: 0; padding: 0; }
    button { min-height: 34px; padding: 8px 13px; border: 1px solid var(--accent-strong); border-radius: 7px; background: var(--accent-strong); color: #fff; font: inherit; font-weight: 650; cursor: pointer; }
    button:hover { background: #084f4a; }
    button.secondary { background: #fff; color: #26313b; border-color: var(--border-strong); }
    button.secondary:hover { background: var(--surface-muted); }
    .toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 14px; }
    .toolbar form { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 0; }
    .job-feed { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
    .job-feed-item { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 12px; align-items: center; min-width: 0; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-subtle); }
    .job-feed-main { display: grid; gap: 2px; min-width: 0; }
    .job-feed-main strong, .job-feed-main span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .job-feed-main strong { font-size: 13px; }
    .job-feed-main span, .job-feed-kind, .job-feed-empty { color: var(--muted); font-size: 12px; }
    .job-feed-kind { white-space: nowrap; }
    .job-feed-state { justify-self: end; }
    .job-feed-empty { padding: 10px 12px; border: 1px dashed var(--border-strong); border-radius: 8px; background: var(--surface-subtle); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 340px), 1fr)); gap: 14px; align-items: start; }
    .field-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); gap: 14px 16px; align-items: start; }
    .action-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr)); gap: 12px; align-items: start; margin-top: 14px; }
    .action-grid form { min-width: 0; display: flex; flex-direction: column; gap: 10px; align-items: flex-start; margin: 0; padding: 12px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-subtle); }
    .status { display: inline-flex; align-items: center; gap: 6px; max-width: 100%; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border-strong); background: var(--surface-muted); color: #34404a; font-size: 12px; font-weight: 650; white-space: nowrap; }
    .status::before { content: ""; width: 6px; height: 6px; border-radius: 999px; background: #8a96a3; flex: 0 0 auto; }
    .status.fail, .status.failed, .status.interrupted { border-color: #f0b4ae; background: var(--danger-soft); color: var(--danger); }
    .status.pass, .status.succeeded { border-color: #b7dfc1; background: var(--success-soft); color: var(--success); }
    .status.warn, .status.manual, .status.unknown, .status.queued, .status.running { border-color: #edd38c; background: var(--warning-soft); color: var(--warning); }
    .status.fail::before, .status.failed::before, .status.interrupted::before { background: var(--danger); }
    .status.pass::before, .status.succeeded::before { background: var(--success); }
    .status.warn::before, .status.manual::before, .status.unknown::before, .status.queued::before, .status.running::before { background: #d99000; }
    table { width: 100%; border-collapse: separate; border-spacing: 0; background: #fff; font-size: 13px; }
    th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    th { background: var(--surface-subtle); color: #26313b; font-size: 12px; font-weight: 750; }
    th { overflow-wrap: normal; }
    td { overflow-wrap: anywhere; }
    tbody tr:hover td { background: #fcfdfd; }
    .table-wrap { width: 100%; overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; background: #fff; scrollbar-color: var(--border-strong) transparent; scrollbar-width: thin; -webkit-overflow-scrolling: touch; }
    .table-wrap::-webkit-scrollbar { height: 8px; }
    .table-wrap::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 999px; }
    .table-wrap::-webkit-scrollbar-track { background: transparent; }
    .table-wrap table { margin: 0; }
    .table-wrap tr:last-child th, .table-wrap tr:last-child td { border-bottom: 0; }
    .kv-table { min-width: 100%; table-layout: fixed; }
    .kv-table th { width: 32%; color: var(--muted); overflow-wrap: anywhere; background: #fff; }
    .data-table { min-width: 760px; table-layout: fixed; }
    .diagnostics-table { min-width: 1060px; }
    .records-table { min-width: 920px; }
    .events-table { min-width: 780px; }
    .checks-table { min-width: 100%; }
    .checks-table th:first-child { width: 72%; }
    .compact-table { min-width: 560px; }
    .diagnostics-refs-table { min-width: 560px; }
    .cell-nowrap { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .cell-code { display: block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .cell-summary { vertical-align: top; }
    .cell-summary span { display: -webkit-box; overflow: hidden; -webkit-box-orient: vertical; -webkit-line-clamp: 2; line-height: 1.45; }
    .ref-list { display: grid; margin: 0; padding: 0; list-style: none; border: 1px solid var(--border); border-radius: 8px; background: #fff; overflow: hidden; }
    .ref-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px 12px; align-items: center; min-width: 0; padding: 10px 12px; border-bottom: 1px solid var(--border); }
    .ref-row:last-child { border-bottom: 0; }
    .ref-row code { display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .ref-status { justify-self: end; }
    .ref-meta { grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: 4px 12px; min-width: 0; color: var(--muted); font-size: 12px; line-height: 1.4; }
    .ref-meta span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .diag-col-id { width: 230px; }
    .diag-col-status { width: 92px; }
    .diag-col-scope { width: 96px; }
    .diag-col-severity { width: 86px; }
    .diag-col-evidence { width: 118px; }
    .diag-col-owner { width: 84px; }
    .diag-col-blocks { width: 118px; }
    .record-col-id { width: 245px; }
    .record-col-kind { width: 170px; }
    .record-col-status { width: 120px; }
    .event-col-at { width: 190px; }
    .event-col-status { width: 120px; }
    .grid-wide { grid-column: 1 / -1; }
    .host-status-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .control-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; }
    .control-card { display: flex; min-width: 0; min-height: 118px; flex-direction: column; gap: 10px; padding: 14px; border: 1px solid var(--border); border-radius: 8px; background: #fff; color: var(--text); text-decoration: none; box-shadow: 0 1px 0 rgba(18, 32, 41, .03); transition: border-color .15s ease, box-shadow .15s ease, background .15s ease; }
    .control-card:hover { border-color: var(--border-strong); box-shadow: 0 8px 18px rgba(15, 23, 42, .06); }
    .control-card:focus-visible { outline: 0; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(15,118,110,.14); }
    .control-card-label { color: var(--muted); font-size: 12px; font-weight: 750; letter-spacing: .04em; text-transform: uppercase; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .control-card-value { display: flex; align-items: center; min-height: 26px; }
    .control-card-detail { display: -webkit-box; overflow: hidden; -webkit-box-orient: vertical; -webkit-line-clamp: 3; color: var(--muted); font-size: 13px; line-height: 1.35; }
    .metric-card { min-width: 0; padding: 14px; border: 1px solid var(--border); border-radius: 8px; background: linear-gradient(180deg, #fff, #fbfcfc); }
    .metric-label { color: var(--muted); font-size: 12px; font-weight: 750; letter-spacing: .04em; text-transform: uppercase; }
    .metric-value { margin-top: 8px; font-size: 24px; line-height: 1.1; font-weight: 760; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .metric-detail { margin-top: 5px; min-height: 17px; color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .meter { height: 7px; margin-top: 12px; border-radius: 999px; background: var(--surface-muted); overflow: hidden; }
    .meter-fill { height: 100%; width: 0; border-radius: inherit; background: var(--accent); }
    .metric-card.warn .meter-fill { background: #d99000; }
    .metric-card.danger .meter-fill { background: var(--danger); }
    .metric-card.neutral .meter-fill { background: #8a96a3; }
    .host-status-footer { margin-top: 10px; color: var(--muted); font-size: 12px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .summary-card { min-width: 0; padding: 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-subtle); }
    .summary-label { color: var(--muted); font-size: 12px; font-weight: 750; letter-spacing: .04em; text-transform: uppercase; }
    .summary-value { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
    .summary-value strong { font-size: 24px; line-height: 1; }
    .summary-detail, .summary-note { color: var(--muted); font-size: 13px; }
    .summary-detail { margin-top: 6px; }
    .summary-note { margin: 12px 0 0; }
    .resource-console-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; }
    .checks-grid { grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr)); }
    .resource-actionbar { position: sticky; top: 8px; z-index: 3; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 16px 0 12px; padding: 12px; border: 1px solid var(--border); border-radius: 8px; background: rgba(249,250,251,.96); box-shadow: 0 8px 18px rgba(15, 23, 42, .06); backdrop-filter: blur(8px); }
    .resource-job-actions { margin-bottom: 14px; }
    .config-sections { display: grid; gap: 10px; margin-top: 12px; }
    .config-section { border: 1px solid var(--border); border-radius: 8px; background: #fff; overflow: hidden; }
    .config-section summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; cursor: pointer; font-size: 15px; font-weight: 750; color: var(--text); }
    .config-section summary:hover { background: var(--surface-muted); }
    .config-section .field-grid { padding: 0 14px 14px; }
    .diagnostic-area-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    .diagnostic-area-card { display: block; min-width: 0; padding: 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-subtle); color: var(--text); text-decoration: none; }
    .diagnostic-area-card:hover { border-color: rgba(0, 104, 93, .35); box-shadow: 0 8px 18px rgba(15, 23, 42, .06); }
    .diagnostic-area-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .diagnostic-area-head strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .diagnostic-area-head span { color: var(--muted); font-weight: 750; }
    .diagnostic-area-detail { display: block; margin-top: 7px; min-height: 34px; color: var(--muted); font-size: 13px; line-height: 1.3; }
    .diagnostic-area-statuses { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    .diagnostic-count { display: inline-flex; align-items: center; gap: 5px; }
    .diagnostic-count strong { font-size: 13px; color: var(--text); }
    .detail-block, .port-group { border: 1px solid var(--border); border-radius: 8px; background: var(--surface-subtle); overflow: hidden; }
    .detail-block summary, .port-group summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; cursor: pointer; font-weight: 750; color: var(--text); }
    .detail-block summary:hover, .port-group summary:hover { background: var(--surface-muted); }
    .detail-block-body { padding: 0 14px 14px; }
    .port-groups { display: grid; gap: 10px; }
    .port-group summary span:first-child { min-width: 0; display: grid; gap: 3px; }
    .port-group summary strong, .port-group summary small { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .port-group summary small { color: var(--muted); font-size: 12px; font-weight: 550; }
    .port-count { flex: 0 0 auto; min-width: 28px; padding: 2px 7px; border: 1px solid var(--border-strong); border-radius: 999px; background: #fff; color: var(--muted); font-size: 12px; text-align: center; }
    .port-group .table-wrap { border-right: 0; border-left: 0; border-bottom: 0; border-radius: 0; }
    a { color: var(--accent-strong); font-weight: 650; }
    textarea { min-height: 88px; }
    .error { color: var(--danger); font-weight: 650; }
    .secret { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; background: var(--warning-soft); border: 1px solid #ddb85d; padding: 10px; border-radius: 8px; }
    code { background: var(--surface-muted); padding: 2px 5px; border-radius: 5px; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .mobile-nav-more { display: none; }
    @media (max-width: 720px) {
      .app-shell { display: block; }
      .sidebar { position: static; height: auto; gap: 10px; padding: 12px 14px 8px; border-right: 0; border-bottom: 1px solid var(--border); }
      .brand { padding: 0 0 10px; }
      .side-nav { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 4px; padding-bottom: 0; }
      .nav-section, .side-nav a::before, .sidebar-meta { display: none; }
      .side-nav a { justify-content: center; min-height: 32px; white-space: nowrap; padding: 6px 4px; font-size: 12px; }
      .side-nav a.mobile-secondary { display: none; }
      .mobile-nav-more { display: block; min-width: 0; }
      .mobile-nav-more summary { display: flex; align-items: center; justify-content: center; min-height: 32px; overflow: hidden; padding: 6px 4px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: #26313b; cursor: pointer; font-size: 12px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
      .mobile-nav-more.active summary { color: var(--accent-strong); background: var(--accent-soft); box-shadow: inset 0 0 0 1px rgba(15, 118, 110, 0.12); }
      .mobile-nav-menu { position: absolute; left: 14px; right: 14px; z-index: 5; display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 6px; padding: 8px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); box-shadow: var(--shadow); }
      .mobile-nav-menu a { min-width: 0; overflow: hidden; padding: 8px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: #26313b; text-decoration: none; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; font-weight: 600; }
      .mobile-nav-menu a.active { color: var(--accent-strong); background: var(--accent-soft); box-shadow: inset 0 0 0 1px rgba(15, 118, 110, 0.12); }
      .topbar { display: block; padding: 18px 14px 14px; }
      .topbar h1 { font-size: 24px; }
      .topbar-meta { justify-content: flex-start; margin-top: 10px; }
      .content { padding: 16px 14px 28px; }
      h2 { font-size: 20px; }
      h3 { font-size: 17px; }
      .panel { padding: 14px; }
      .job-feed-item { grid-template-columns: minmax(0, 1fr); gap: 6px; }
      .job-feed-kind, .job-feed-state { justify-self: start; }
      .host-status-grid { grid-template-columns: 1fr 1fr; }
      .control-grid { grid-template-columns: 1fr; }
      .summary-grid { grid-template-columns: 1fr 1fr; }
      .resource-console-grid { grid-template-columns: 1fr; }
      .resource-actionbar { position: static; margin-top: 14px; box-shadow: none; backdrop-filter: none; }
      .diagnostic-area-grid { grid-template-columns: 1fr; }
      .data-table { min-width: 640px; }
      .diagnostics-table { min-width: 1080px; }
      .checks-table { min-width: 100%; }
    }
    @media (max-width: 420px) {
      .host-status-grid { grid-template-columns: 1fr; }
      .control-grid { grid-template-columns: 1fr; }
      .summary-grid { grid-template-columns: 1fr; }
      .diagnostic-area-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
<div class="app-shell">
<aside class="sidebar">
  <a class="brand" href="/">
    <span class="brand-mark">LP</span>
    <span><span class="brand-title">LanPanel Management UI</span><span class="brand-subtitle">version {{ .Version }}</span></span>
  </a>
  <nav class="side-nav" aria-label="Primary">
    <p class="nav-section">Control</p>
    <a href="/" class="mobile-primary {{ if eq .CurrentPath "/" }}active{{ end }}"{{ if eq .CurrentPath "/" }} aria-current="page"{{ end }}>Overview</a>
    <a href="/settings" class="mobile-primary {{ if eq .CurrentPath "/settings" }}active{{ end }}"{{ if eq .CurrentPath "/settings" }} aria-current="page"{{ end }}>Settings</a>
    <a href="/resources" class="mobile-primary {{ if eq .CurrentPath "/resources" }}active{{ end }}"{{ if eq .CurrentPath "/resources" }} aria-current="page"{{ end }}>Resources</a>
    <p class="nav-section">Observe</p>
    <a href="/diagnostics" class="mobile-primary {{ if eq .CurrentPath "/diagnostics" }}active{{ end }}"{{ if eq .CurrentPath "/diagnostics" }} aria-current="page"{{ end }}>Diagnostics</a>
    <a href="/host-health" class="mobile-secondary {{ if eq .CurrentPath "/host-health" }}active{{ end }}"{{ if eq .CurrentPath "/host-health" }} aria-current="page"{{ end }}>Host Health</a>
    <a href="/services" class="mobile-secondary {{ if eq .CurrentPath "/services" }}active{{ end }}"{{ if eq .CurrentPath "/services" }} aria-current="page"{{ end }}>Services</a>
    <a href="/certificates" class="mobile-secondary {{ if eq .CurrentPath "/certificates" }}active{{ end }}"{{ if eq .CurrentPath "/certificates" }} aria-current="page"{{ end }}>Certificates / Nginx</a>
    <p class="nav-section">Operate</p>
    <a href="/onboarding" class="mobile-secondary {{ if eq .CurrentPath "/onboarding" }}active{{ end }}"{{ if eq .CurrentPath "/onboarding" }} aria-current="page"{{ end }}>Headscale Onboarding</a>
    <a href="/jobs" class="mobile-secondary {{ if eq .CurrentPath "/jobs" }}active{{ end }}"{{ if eq .CurrentPath "/jobs" }} aria-current="page"{{ end }}>Jobs</a>
    <a href="/migration" class="mobile-secondary {{ if eq .CurrentPath "/migration" }}active{{ end }}"{{ if eq .CurrentPath "/migration" }} aria-current="page"{{ end }}>Exit / Migration</a>
    <details class="mobile-nav-more {{ if or (eq .CurrentPath "/host-health") (eq .CurrentPath "/services") (eq .CurrentPath "/certificates") (eq .CurrentPath "/onboarding") (eq .CurrentPath "/jobs") (eq .CurrentPath "/migration") }}active{{ end }}">
      <summary aria-label="More navigation">More</summary>
      <div class="mobile-nav-menu">
        <a href="/host-health" class="{{ if eq .CurrentPath "/host-health" }}active{{ end }}"{{ if eq .CurrentPath "/host-health" }} aria-current="page"{{ end }}>Host Health</a>
        <a href="/services" class="{{ if eq .CurrentPath "/services" }}active{{ end }}"{{ if eq .CurrentPath "/services" }} aria-current="page"{{ end }}>Services</a>
        <a href="/certificates" class="{{ if eq .CurrentPath "/certificates" }}active{{ end }}"{{ if eq .CurrentPath "/certificates" }} aria-current="page"{{ end }}>Certificates / Nginx</a>
        <a href="/onboarding" class="{{ if eq .CurrentPath "/onboarding" }}active{{ end }}"{{ if eq .CurrentPath "/onboarding" }} aria-current="page"{{ end }}>Headscale Onboarding</a>
        <a href="/jobs" class="{{ if eq .CurrentPath "/jobs" }}active{{ end }}"{{ if eq .CurrentPath "/jobs" }} aria-current="page"{{ end }}>Jobs</a>
        <a href="/migration" class="{{ if eq .CurrentPath "/migration" }}active{{ end }}"{{ if eq .CurrentPath "/migration" }} aria-current="page"{{ end }}>Exit / Migration</a>
      </div>
    </details>
  </nav>
  <div class="sidebar-meta"><strong>Loopback-only</strong><span>Use over a local tunnel.</span></div>
</aside>
<div class="workspace">
<header class="topbar">
  <div>
    <p class="eyebrow">Local Control</p>
    <h1>{{ .Title }}</h1>
  </div>
  <div class="topbar-meta">
    <span class="meta-pill">v{{ .Version }}</span>
    <span class="meta-pill">HTMX {{ .HTMXVersion }}</span>
  </div>
</header>
<main class="content">
  {{ .Body }}
</main>
</div>
</div>
</body>
</html>`
