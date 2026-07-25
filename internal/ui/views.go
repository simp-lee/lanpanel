package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apprender"
	"lanpanel/internal/components/appsvc"
	tlscomponent "lanpanel/internal/components/tls"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/hosthealth"
	"lanpanel/internal/resource"
	"lanpanel/internal/state"
	"lanpanel/internal/workflow"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (server *Server) overviewBody(r *http.Request) (string, error) {
	mainCfg, mainErr := loadMainConfigForView(server.options.ConfigPath)
	appCfg, appErr := loadAppConfigForView(server.options.AppConfigPath)
	health := hosthealth.Summarize(hosthealth.ReadLocalInputsWithOptions(viewHostHealthOptions(mainCfg, mainErr, appCfg, appErr)))
	exposureSummary, exposureErr := server.resourceExposureMap()
	records, err := server.safeRecords()
	if err != nil {
		return "", err
	}
	body := errorBlock(appErr)
	body += panel("Control Center", controlCenterHTML(nil, health, exposureSummary, exposureErr, records))
	body += panel("Host Health Snapshot", hostHealthCompactHTML(health))
	body += panel("Config Summary", mainConfigSummaryHTML(server.options.ConfigPath, mainCfg, mainErr))
	body += panel("Resource Exposure", exposureOverviewOrUnavailableHTML(exposureSummary, exposureErr))
	body += panel("Recent Jobs", recordsTableHTML(records, 6))
	return body, nil
}

func (server *Server) settingsBody(r *http.Request) (string, error) {
	cfg, loadErr := loadMainConfigForView(server.options.ConfigPath)
	if loadErr != nil {
		return panel("Main Config", errorBlock(loadErr)+initConfigFormHTML("main_init", "Create Example Main Config", "config_path", server.options.ConfigPath)), nil
	}
	return panel("Main Config", errorBlock(loadErr)+mainConfigFormHTML(server.options.ConfigPath, cfg)), nil
}

func (server *Server) resourcesBody(r *http.Request) (string, error) {
	cfg, loadErr := loadAppConfigForView(server.options.AppConfigPath)
	if loadErr != nil {
		return panel("App Config", errorBlock(loadErr)+initConfigFormHTML("app_init", "Create Example App Config", "app_config_path", server.options.AppConfigPath)), nil
	}
	appDeployConfirmations, err := server.exposureRequiredConfirmations(r, server.options.AppConfigPath, cfg, domain.ExposurePlanOperationDeploy)
	if err != nil {
		return "", err
	}
	realIPRefreshConfirmations, err := server.exposureRequiredConfirmations(r, server.options.AppConfigPath, cfg, domain.ExposurePlanOperationRealIPRefresh)
	if err != nil {
		return "", err
	}
	exposureSummary, exposureErr := server.resourceExposureMap()
	body := panel("Resource Console", resourceConsoleHTML(server.options.AppConfigPath, cfg, exposureSummary, exposureErr)+appConfigFormHTML(server.options.AppConfigPath, cfg, appDeployConfirmations, realIPRefreshConfirmations))
	body += panel("Current Exposure", exposureSummaryOrUnavailableHTML(exposureSummary, exposureErr))
	body += panel("Exposure Preview", `<div id="exposure-preview">Submit preview from the resource form to calculate the typed exposure plan.</div>`)
	body += browserAuthFormsHTML(server.options.AppConfigPath, cfg)
	return body, nil
}

func (server *Server) exposureRequiredConfirmations(r *http.Request, appConfigPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation) ([]string, error) {
	instanceID, err := server.readInstanceID()
	if err != nil {
		return nil, err
	}
	actor, err := server.actorForRequest(r)
	if err != nil {
		return nil, err
	}
	observations := server.options.ExposureObservations
	if observer, ok := server.options.HostWorkflow.(workflow.AppExposureObserver); ok {
		observed, err := observer.AppExposureObservations(r.Context(), appConfigPath, cfg, operation)
		if err != nil {
			return nil, err
		}
		observations = mergeAppExposureObservations(observations, observed)
	}
	plan, err := exposure.AppPlanWithObservations(instanceID, server.options.Version, cfg, exposure.AppPlanOptions{
		ConfigPath:   appConfigPath,
		Actor:        actor,
		Operation:    operation,
		CreatedAt:    server.options.Now(),
		BeforeDigest: "none",
	}, observations)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), plan.Decision.RequiredConfirmations...), nil
}

func mergeAppExposureObservations(base exposure.AppObservations, observed exposure.AppObservations) exposure.AppObservations {
	if strings.TrimSpace(observed.ConfigPath) != "" {
		base.ConfigPath = observed.ConfigPath
	}
	if !observed.GeneratedAt.IsZero() {
		base.GeneratedAt = observed.GeneratedAt
	}
	if observed.Activation.Kind != "" {
		base.Activation = observed.Activation
	}
	if len(observed.Diagnostics) > 0 {
		base.Diagnostics = append([]domain.DiagnosticRef(nil), observed.Diagnostics...)
	}
	if observed.OriginProtectionStatus != "" {
		base.OriginProtectionStatus = observed.OriginProtectionStatus
	}
	if strings.TrimSpace(observed.OriginProtectionReferenceDigest) != "" {
		base.OriginProtectionReferenceDigest = observed.OriginProtectionReferenceDigest
	}
	if observed.RealIPTrustedCIDRCount != 0 {
		base.RealIPTrustedCIDRCount = observed.RealIPTrustedCIDRCount
	}
	if strings.TrimSpace(observed.RealIPClientIPHeader) != "" {
		base.RealIPClientIPHeader = observed.RealIPClientIPHeader
	}
	if observed.RealIPSpoofingRejection != "" {
		base.RealIPSpoofingRejection = observed.RealIPSpoofingRejection
	}
	if observed.GoAccessAuthBasicStatus != "" {
		base.GoAccessAuthBasicStatus = observed.GoAccessAuthBasicStatus
	}
	if observed.BrowserAuthRuntimeStatus != "" {
		base.BrowserAuthRuntimeStatus = observed.BrowserAuthRuntimeStatus
	}
	if observed.BrowserAuthMarkerStatus != "" {
		base.BrowserAuthMarkerStatus = observed.BrowserAuthMarkerStatus
	}
	return base
}

func viewHostHealthOptions(mainCfg config.Config, mainErr error, appCfg appconfig.Config, appErr error) hosthealth.LocalReadOptions {
	options := hosthealth.LocalReadOptions{}
	if mainErr == nil {
		serverName := hostFromURL(mainCfg.Default.ServerURL)
		if serverName != "" {
			options.DNSTargets = append(options.DNSTargets, serverName)
			options.CertificateTargets = append(options.CertificateTargets, hosthealth.CertificateTarget{
				Domain: serverName,
				Path:   tlscomponent.StableFullchainPath(serverName),
			})
		}
	}
	if appErr == nil {
		options.DNSTargets = append(options.DNSTargets, appCfg.App.Domains...)
		if names, err := appsvc.NewNames(appCfg); err == nil {
			for _, domainName := range appCfg.App.Domains {
				options.CertificateTargets = append(options.CertificateTargets, hosthealth.CertificateTarget{
					Domain: domainName,
					Path:   names.FullchainPath,
				})
			}
		}
	}
	return options
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return strings.TrimSpace(raw)
	}
	return parsed.Hostname()
}

func (server *Server) diagnosticsBody(r *http.Request) (string, error) {
	status, err := workflow.RunRuntimeStatus(server.runtimeStatusContext(), server.options.ConfigPath, server.options.AppConfigPath)
	mainCfg, mainErr := loadMainConfigForView(server.options.ConfigPath)
	appCfg, appErr := loadAppConfigForView(server.options.AppConfigPath)
	health := hosthealth.Summarize(hosthealth.ReadLocalInputsWithOptions(viewHostHealthOptions(mainCfg, mainErr, appCfg, appErr)))
	body := errorBlock(err)
	body += panel("Runtime Diagnostics", diagnosticAreasHTML(diagnosticsWithoutHostHealth(status.Diagnostics)))
	body += panel("Host Check Summary", hostHealthCheckSummaryHTML(health))
	return body, nil
}

func (server *Server) servicesBody(r *http.Request) (string, error) {
	status, err := workflow.RunRuntimeStatus(server.runtimeStatusContext(), server.options.ConfigPath, server.options.AppConfigPath)
	body := errorBlock(err)
	body += diagnosticsHTML(diagnosticsByScope(status.Diagnostics, domain.DiagnosticScopeService))
	body += jobButtonHTML("main_status", "Refresh Status", "secondary", server.options.ConfigPath, server.options.AppConfigPath, "")
	return panel("Managed Services", body), nil
}

func (server *Server) certificatesBody(r *http.Request) (string, error) {
	status, err := workflow.RunRuntimeStatus(server.runtimeStatusContext(), server.options.ConfigPath, server.options.AppConfigPath)
	mainCfg, mainErr := loadMainConfigForView(server.options.ConfigPath)
	appCfg, appErr := loadAppConfigForView(server.options.AppConfigPath)
	health := hosthealth.Summarize(hosthealth.ReadLocalInputsWithOptions(viewHostHealthOptions(mainCfg, mainErr, appCfg, appErr)))
	body := errorBlock(err)
	body += panel("Certificate / Nginx Summary", certificateNginxSummaryHTML(status, health))
	details := disclosureHTML("Runtime paths and generated files", resultFieldsHTML(status.Fields), false)
	details += diagnosticsHTML(diagnosticsByID(status.Diagnostics, "runtime:nginx-service", "runtime:main-renew-timer", "runtime:app-renew-timer"))
	body += panel("Runtime Evidence", details)
	checks := `<div class="grid checks-grid">`
	checks += miniPanel("Certificate Expiry", certificateFactsHTML(health.Certificates))
	checks += miniPanel("Certificate Checks", compactDiagnosticRefsHTML(health.Checks.Certificates))
	checks += miniPanel("Nginx Config Test", compactDiagnosticRefsHTML(health.Checks.NginxConfigTest))
	checks += `</div>`
	body += panel("Checks", checks)
	body += panel("Actions", jobButtonHTML("main_verify", "Run Verify", "", server.options.ConfigPath, server.options.AppConfigPath, ""))
	return body, nil
}

func (server *Server) runtimeStatusContext() workflow.Context {
	return workflow.Context{
		Version:      server.options.Version,
		HostWorkflow: server.options.HostWorkflow,
	}
}

func (server *Server) hostHealthBody(r *http.Request) (string, error) {
	mainCfg, mainErr := loadMainConfigForView(server.options.ConfigPath)
	appCfg, appErr := loadAppConfigForView(server.options.AppConfigPath)
	health := hosthealth.Summarize(hosthealth.ReadLocalInputsWithOptions(viewHostHealthOptions(mainCfg, mainErr, appCfg, appErr)))
	body := hostHealthFullHTML(health)
	return panel("Read-Only Facts", body), nil
}

func (server *Server) onboardingBody(r *http.Request) (string, error) {
	mainCfg, err := loadMainConfigForView(server.options.ConfigPath)
	status, statusErr := workflow.RunOnboardingStatus(workflow.Context{Version: server.options.Version, BaseContext: r.Context()}, server.options.ConfigPath)
	body := errorBlock(err)
	body += errorBlock(statusErr)
	body += `<div class="grid">`
	body += miniPanel("Virtual LAN Baseline", kvTableHTML([]kv{
		{"Default user", "lanpanel"},
		{"Server URL", mainCfg.Default.ServerURL},
		{"MagicDNS suffix", mainCfg.Default.BaseDomain},
		{"Client baseline", "Tailscale-compatible client >= v1.80.0"},
		{"DERP/STUN", "embedded baseline from rendered Headscale config"},
	}))
	body += miniPanel("Preauth Handoff", preauthFormHTML())
	body += `<div class="subpanel grid-wide"><h3>Onboarding Readiness</h3>` + diagnosticsHTML(diagnosticsByScopeOrIDPrefix(status.Diagnostics, []domain.DiagnosticScope{domain.DiagnosticScopeHeadscale}, []string{"runtime:onboarding-headscale-service"})) + `</div>`
	body += `</div>`
	return panel("Headscale Onboarding", body), nil
}

func (server *Server) jobsBody(r *http.Request) (string, error) {
	records, err := server.safeRecords()
	if err != nil {
		return "", err
	}
	body := secretRevealHTML(server, r)
	body += `<div class="panel job-poll-panel"><h2>Job Activity</h2><ul class="job-feed" hx-get="/fragments/job-status" hx-trigger="load, every 5s" hx-swap="innerHTML"><li class="job-feed-empty">Loading recent jobs...</li></ul></div>`
	historyURL := "/fragments/job-history"
	if jobID := strings.TrimSpace(r.URL.Query().Get("job")); jobID != "" {
		historyURL += "?job=" + url.QueryEscape(jobID)
	}
	body += `<div id="job-history" hx-get="` + esc(historyURL) + `" hx-trigger="load, every 1s" hx-swap="innerHTML">` + jobsHistoryHTML(server, r, records) + `</div>`
	return body, nil
}

func (server *Server) migrationBody(r *http.Request) (string, error) {
	body := `<div class="grid">`
	body += miniPanel("Keep", kvTableHTML([]kv{
		{"Main config", server.options.ConfigPath},
		{"App config", server.options.AppConfigPath},
		{"UI state", server.options.StateDir},
		{"Browser auth", "/etc/lanpanel/browser-auth/"},
	}))
	body += miniPanel("Exposure Data Location", `<p>Resource exposure details stay in <a href="/resources">Resources</a>. Overview only shows rollup counts, and this migration page only lists what is kept or excluded.</p>`)
	body += miniPanel("Not Exported In P0", `<ul><li>No machine-readable export manifest.</li><li>No raw secrets, htpasswd content, provider credentials, GoAccess raw database, or full logs.</li><li>Preauth keys and browser passwords must be recreated.</li></ul>`)
	body += `</div>`
	return panel("Exit / Migration Boundary", body), nil
}

func (server *Server) exposurePreviewBody(r *http.Request) (string, error) {
	_, cfg, err := server.appConfigFromRequest(r)
	if err != nil {
		return "", err
	}
	instanceID, err := server.readInstanceID()
	if err != nil {
		return "", err
	}
	actor, err := server.actorForRequest(r)
	if err != nil {
		return "", err
	}
	plan, err := exposure.AppPlan(instanceID, server.options.Version, cfg, exposure.AppPlanOptions{
		ConfigPath:   server.options.AppConfigPath,
		Actor:        actor,
		Operation:    domain.ExposurePlanOperationUpdateResource,
		CreatedAt:    server.options.Now(),
		BeforeDigest: "none",
	})
	if err != nil {
		return "", err
	}
	return exposurePlanHTML(plan), nil
}

func loadMainConfigForView(path string) (config.Config, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func loadAppConfigForView(path string) (appconfig.Config, error) {
	cfg, err := appconfig.LoadFile(path)
	if err != nil {
		return appconfig.Config{}, err
	}
	return cfg, nil
}

func (server *Server) readInstanceID() (string, error) {
	instance, err := resource.NewStore(filepath.Join(server.options.StateDir, "resources")).LoadInstance()
	if err != nil {
		return "", err
	}
	return instance.ID, nil
}

func (server *Server) resourceExposureHTML() string {
	summary, err := server.resourceExposureMap()
	if err != nil {
		return exposureUnavailableHTML(err)
	}
	return exposureSummaryHTML(summary)
}

func exposureSummaryOrUnavailableHTML(summary exposure.ResourceExposureMap, err error) string {
	if err != nil {
		return exposureUnavailableHTML(err)
	}
	return exposureSummaryHTML(summary)
}

func (server *Server) resourceExposureOverviewHTML() string {
	summary, err := server.resourceExposureMap()
	if err != nil {
		return exposureUnavailableHTML(err)
	}
	return exposureOverviewHTML(summary)
}

func exposureOverviewOrUnavailableHTML(summary exposure.ResourceExposureMap, err error) string {
	if err != nil {
		return exposureUnavailableHTML(err)
	}
	return exposureOverviewHTML(summary)
}

func (server *Server) resourceExposureMap() (exposure.ResourceExposureMap, error) {
	instanceID, instanceErr := server.readInstanceID()
	appConfigs, appErr := server.appConfigsForExposure()
	mainCfg, mainErr := loadMainConfigForView(server.options.ConfigPath)
	if appErr != nil || instanceErr != nil || mainErr != nil {
		return exposure.ResourceExposureMap{}, firstErr(firstErr(appErr, instanceErr), mainErr)
	}
	instanceOptions := exposure.InstanceSummaryOptions{
		BaseDomain: mainCfg.Default.BaseDomain,
		ServerURL:  mainCfg.Default.ServerURL,
	}
	summaries := make([]exposure.ResourceExposureMap, 0, len(appConfigs))
	for _, appConfig := range appConfigs {
		observations, err := server.exposureSummaryObservations(appConfig.Path, appConfig.Config)
		if err != nil {
			return exposure.ResourceExposureMap{}, err
		}
		summary, err := exposure.AppSummaryWithObservationsAndInstance(instanceID, server.options.Version, appConfig.Config, observations, instanceOptions)
		if err != nil {
			return exposure.ResourceExposureMap{}, err
		}
		summaries = append(summaries, summary)
	}
	return combineExposureSummaries(instanceID, server.options.Version, instanceOptions, summaries), nil
}

type appExposureConfig struct {
	Path   string
	Config appconfig.Config
}

func (server *Server) appConfigsForExposure() ([]appExposureConfig, error) {
	paths := []string{server.options.AppConfigPath}
	registered, err := server.state.ListAppConfigPaths()
	if err != nil {
		return nil, err
	}
	paths = append(paths, registered...)
	seen := map[string]struct{}{}
	configs := []appExposureConfig{}
	for _, path := range paths {
		canonical, err := canonicalAppConfigPath(path)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		cfg, err := loadAppConfigForView(canonical)
		if err != nil {
			return nil, err
		}
		configs = append(configs, appExposureConfig{Path: canonical, Config: cfg})
	}
	return configs, nil
}

func combineExposureSummaries(instanceID string, version string, instanceOptions exposure.InstanceSummaryOptions, summaries []exposure.ResourceExposureMap) exposure.ResourceExposureMap {
	combined := exposure.ResourceExposureMap{
		SchemaVersion: domain.ResourceExposureSchemaV1,
		GeneratedAt:   firstExposureGeneratedAt(summaries),
		Instance: exposure.InstanceMetadata{
			InstanceID:      instanceID,
			LanpanelVersion: strings.TrimSpace(version),
			BaseDomain:      strings.TrimSpace(instanceOptions.BaseDomain),
			ServerURL:       strings.TrimSpace(instanceOptions.ServerURL),
		},
		Summary: exposure.ExposureSummary{
			ByAccessMode: map[domain.AccessMode]int{},
			RiskCounts:   map[domain.DiagnosticStatus]int{},
		},
	}
	for _, mode := range []domain.AccessMode{domain.AccessModeBrowser, domain.AccessModePublic, domain.AccessModePrivateClient} {
		combined.Summary.ByAccessMode[mode] = 0
	}
	for _, status := range []domain.DiagnosticStatus{domain.DiagnosticStatusPass, domain.DiagnosticStatusWarn, domain.DiagnosticStatusManual, domain.DiagnosticStatusUnknown, domain.DiagnosticStatusFail} {
		combined.Summary.RiskCounts[status] = 0
	}
	for _, summary := range summaries {
		combined.Resources = append(combined.Resources, summary.Resources...)
		combined.Summary.Total += summary.Summary.Total
		for mode, count := range summary.Summary.ByAccessMode {
			combined.Summary.ByAccessMode[mode] += count
		}
		for status, count := range summary.Summary.RiskCounts {
			combined.Summary.RiskCounts[status] += count
		}
	}
	return combined
}

func firstExposureGeneratedAt(summaries []exposure.ResourceExposureMap) time.Time {
	for _, summary := range summaries {
		if !summary.GeneratedAt.IsZero() {
			return summary.GeneratedAt
		}
	}
	return time.Now().UTC()
}

func (server *Server) exposureSummaryObservations(appConfigPath string, appCfg appconfig.Config) (exposure.AppObservations, error) {
	observations := server.options.ExposureObservations
	observations.ConfigPath = appConfigPath
	activation, err := appCheckpointActivationRef(appConfigPath, appCfg)
	if err != nil {
		return observations, err
	}
	observations.Activation = activation

	status, err := workflow.RunRuntimeStatus(server.runtimeStatusContext(), server.options.ConfigPath, appConfigPath)
	if err != nil {
		observations.Diagnostics = append(observations.Diagnostics, domain.DiagnosticRef{
			ID:               "runtime-status",
			Status:           domain.DiagnosticStatusUnknown,
			Scope:            domain.DiagnosticScopeResource,
			Severity:         domain.DiagnosticSeverityMedium,
			EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
			ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		})
	} else {
		observations.Diagnostics = append(observations.Diagnostics, diagnosticRefsFromItems(status.Diagnostics)...)
	}
	if appCfg.Nginx.GoAccess.Enabled && observations.GoAccessAuthBasicStatus == "" {
		observations.GoAccessAuthBasicStatus = diagnosticStatusByID(observations.Diagnostics, "goaccess-auth-file", domain.DiagnosticStatusUnknown)
	}
	if appCfg.BrowserAuthEnabled() {
		browserAuthStatus := diagnosticStatusByID(observations.Diagnostics, "browser-auth-file", domain.DiagnosticStatusUnknown)
		if observations.BrowserAuthRuntimeStatus == "" {
			observations.BrowserAuthRuntimeStatus = browserAuthStatus
		}
		if appCfg.Access.BrowserAuth.Managed.HtpasswdPath != "" && observations.BrowserAuthMarkerStatus == "" {
			observations.BrowserAuthMarkerStatus = browserAuthStatus
		}
	}
	if appCfg.EffectiveRealIPProfileName() != "" && observations.RealIPSpoofingRejection == "" {
		observations.RealIPSpoofingRejection = diagnosticStatusByScope(observations.Diagnostics, domain.DiagnosticScopeRealIP, domain.DiagnosticStatusUnknown)
	}
	return observations, nil
}

func appCheckpointActivationRef(appConfigPath string, appCfg appconfig.Config) (domain.ActivationRef, error) {
	if appCfg.PrivateClientAccessEnabled() {
		return domain.NotApplicableActivationRef(), nil
	}
	checkpointPath := state.DefaultCheckpointPath(appConfigPath)
	checkpoint, err := state.NewStore(checkpointPath).Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.NotApplicableActivationRef(), nil
		}
		return domain.NotApplicableActivationRef(), fmt.Errorf("load app exposure checkpoint %s: %w", checkpointPath, err)
	}
	if checkpoint.LastFailure != nil || strings.TrimSpace(checkpoint.CurrentCheckpoint) != "" || !checkpoint.HasDeployContext() {
		return domain.NotApplicableActivationRef(), nil
	}
	digest, err := appDesiredStateDigest(appCfg)
	if err != nil {
		return domain.NotApplicableActivationRef(), err
	}
	if !checkpoint.MatchesDesiredState(digest) {
		return domain.NotApplicableActivationRef(), nil
	}
	return domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: checkpointPath, Digest: digest}, nil
}

func appDesiredStateDigest(appCfg appconfig.Config) (string, error) {
	staged, err := apprender.StageRuntime(appCfg)
	if err != nil {
		return "", fmt.Errorf("stage app runtime for exposure checkpoint digest: %w", err)
	}
	sort.Slice(staged, func(i int, j int) bool {
		if staged[i].HostPath != staged[j].HostPath {
			return staged[i].HostPath < staged[j].HostPath
		}
		return staged[i].SourcePath < staged[j].SourcePath
	})
	type stagedDigestEntry struct {
		SourcePath    string `json:"source_path"`
		HostPath      string `json:"host_path"`
		ContentMode   string `json:"content_mode"`
		Mode          string `json:"mode"`
		ContentDigest string `json:"content_digest"`
	}
	entries := make([]stagedDigestEntry, 0, len(staged))
	for _, file := range staged {
		sum := sha256.Sum256(file.Content)
		entries = append(entries, stagedDigestEntry{
			SourcePath:    file.SourcePath,
			HostPath:      file.HostPath,
			ContentMode:   string(file.ContentMode),
			Mode:          fmt.Sprintf("%04o", file.Mode.Perm()),
			ContentDigest: "sha256:" + hex.EncodeToString(sum[:]),
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("marshal app exposure checkpoint digest input: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func diagnosticRefsFromItems(items []domain.DiagnosticItem) []domain.DiagnosticRef {
	refs := make([]domain.DiagnosticRef, 0, len(items))
	for _, item := range items {
		redaction := item.Redaction
		if redaction == "" {
			redaction = domain.RedactionNone
		}
		redactionStatus := item.RedactionStatus
		if redactionStatus == "" {
			redactionStatus = domain.RedactionStatusNoSensitiveData
		}
		refs = append(refs, domain.DiagnosticRef{
			ID:               item.ID,
			Status:           item.Status,
			Scope:            item.Scope,
			ResourceID:       item.ResourceID,
			Severity:         item.Severity,
			EvidenceSource:   item.EvidenceSource,
			ResponsibleParty: item.ResponsibleParty,
			BlocksActivation: item.BlocksActivation,
			Redaction:        redaction,
			RedactionStatus:  redactionStatus,
		})
	}
	return refs
}

func diagnosticStatusByID(refs []domain.DiagnosticRef, id string, fallback domain.DiagnosticStatus) domain.DiagnosticStatus {
	for _, ref := range refs {
		if ref.ID == id {
			return ref.Status
		}
	}
	return fallback
}

func diagnosticStatusByScope(refs []domain.DiagnosticRef, scope domain.DiagnosticScope, fallback domain.DiagnosticStatus) domain.DiagnosticStatus {
	status := fallback
	for _, ref := range refs {
		if ref.Scope != scope {
			continue
		}
		if ref.Status == domain.DiagnosticStatusFail {
			return ref.Status
		}
		status = ref.Status
	}
	return status
}

func exposureUnavailableHTML(err error) string {
	if err == nil {
		return ""
	}
	return errorHTML(err)
}

type kv struct {
	Key   string
	Value string
}

func panel(title string, body string) string {
	return `<div class="panel"><h2>` + esc(title) + `</h2>` + body + `</div>`
}

func miniPanel(title string, body string) string {
	return `<div class="subpanel"><h3>` + esc(title) + `</h3>` + body + `</div>`
}

func esc(value string) string {
	return template.HTMLEscapeString(value)
}

func statusBadge(value string) string {
	class := strings.ToLower(strings.ReplaceAll(value, "_", "-"))
	return `<span class="status ` + esc(class) + `" title="` + esc(value) + `">` + esc(value) + `</span>`
}

func errorBlock(err error) string {
	if err == nil {
		return ""
	}
	return `<p class="error">` + esc(err.Error()) + `</p>`
}

func errorHTML(err error) string {
	if err == nil {
		return ""
	}
	return `<span class="error">` + esc(err.Error()) + `</span>`
}

func tableWrap(table string) string {
	return `<div class="table-wrap">` + table + `</div>`
}

func codeCell(value string) string {
	return `<td class="cell-nowrap" title="` + esc(value) + `"><code class="cell-code">` + esc(value) + `</code></td>`
}

func nowrapCell(value string) string {
	return `<td class="cell-nowrap" title="` + esc(value) + `">` + esc(value) + `</td>`
}

func summaryCell(value string) string {
	return `<td class="cell-summary" title="` + esc(value) + `"><span>` + esc(value) + `</span></td>`
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func kvTableHTML(rows []kv) string {
	body := `<table class="kv-table"><tbody>`
	for _, row := range rows {
		body += `<tr><th>` + esc(row.Key) + `</th><td>` + esc(row.Value) + `</td></tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

func resultFieldsHTML(fields []domain.ResultField) string {
	if len(fields) == 0 {
		return `<p>No runtime evidence available.</p>`
	}
	rows := make([]kv, 0, len(fields))
	for _, field := range fields {
		rows = append(rows, kv{field.Label, field.Value})
	}
	return kvTableHTML(rows)
}

func diagnosticsByScope(items []domain.DiagnosticItem, scopes ...domain.DiagnosticScope) []domain.DiagnosticItem {
	scopeSet := map[domain.DiagnosticScope]struct{}{}
	for _, scope := range scopes {
		scopeSet[scope] = struct{}{}
	}
	filtered := []domain.DiagnosticItem{}
	for _, item := range items {
		if _, ok := scopeSet[item.Scope]; ok {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func diagnosticsByID(items []domain.DiagnosticItem, ids ...string) []domain.DiagnosticItem {
	idSet := map[string]struct{}{}
	for _, id := range ids {
		idSet[strings.TrimSpace(id)] = struct{}{}
	}
	filtered := []domain.DiagnosticItem{}
	for _, item := range items {
		if _, ok := idSet[item.ID]; ok {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func diagnosticsByScopeOrIDPrefix(items []domain.DiagnosticItem, scopes []domain.DiagnosticScope, prefixes []string) []domain.DiagnosticItem {
	scopeSet := map[domain.DiagnosticScope]struct{}{}
	for _, scope := range scopes {
		scopeSet[scope] = struct{}{}
	}
	filtered := []domain.DiagnosticItem{}
	for _, item := range items {
		if _, ok := scopeSet[item.Scope]; ok {
			filtered = append(filtered, item)
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(item.ID, prefix) {
				filtered = append(filtered, item)
				break
			}
		}
	}
	return filtered
}

func diagnosticsWithoutHostHealth(items []domain.DiagnosticItem) []domain.DiagnosticItem {
	filtered := []domain.DiagnosticItem{}
	for _, item := range items {
		if item.ID == "host-health" || strings.HasPrefix(item.ID, "host-health:") {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func recordsTableHTML(records []domain.JobRecord, limit int) string {
	if len(records) == 0 {
		return `<p>No jobs recorded yet.</p>`
	}
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	body := `<table class="data-table records-table"><thead><tr><th class="record-col-id">ID</th><th class="record-col-kind">Kind</th><th class="record-col-status">Status</th><th>Summary</th></tr></thead><tbody>`
	for _, record := range records {
		summary := record.ResultSummary
		if summary == "" {
			summary = record.ErrorSummary
		}
		body += `<tr>` + codeCell(record.ID) + nowrapCell(string(record.Kind)) + `<td class="cell-nowrap">` + statusBadge(string(record.Status)) + `</td>` + summaryCell(summary) + `</tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

func mainConfigSummaryHTML(path string, cfg config.Config, err error) string {
	return errorBlock(err) + kvTableHTML([]kv{
		{"Config path", path},
		{"Server URL", cfg.Default.ServerURL},
		{"Base domain", cfg.Default.BaseDomain},
		{"Certificate email", cfg.Default.CertificateEmail},
		{"ACME challenge", cfg.Default.ACMEChallenge},
		{"DNS-01 provider", cfg.Advanced.DNS01.Provider},
		{"Platform arch", cfg.Advanced.Platform.Arch},
	})
}

func controlCenterHTML(diagnostics []domain.DiagnosticItem, health domain.HostHealthSummary, exposureSummary exposure.ResourceExposureMap, exposureErr error, records []domain.JobRecord) string {
	serviceItems := diagnosticsByScope(diagnostics, domain.DiagnosticScopeService)
	certificateItems := diagnosticsByScope(diagnostics, domain.DiagnosticScopeCertificate)
	hostRefs := hostHealthCheckRefs(health)
	certificateRefs := append([]domain.DiagnosticRef{}, health.Checks.Certificates...)
	certificateRefs = append(certificateRefs, health.Checks.NginxConfigTest...)
	jobStatus, jobValue, jobDetail := latestJobControlStatus(records)
	serviceDetail := statusCountsText(diagnosticStatusCounts(serviceItems))
	if len(serviceItems) == 0 {
		serviceDetail = "Open Services for live runtime checks"
	}
	return `<div class="control-grid">` +
		controlCardHTML("Host Health", string(worstRefStatus(hostRefs)), statusCountsText(refStatusCounts(hostRefs)), "/host-health", worstRefStatus(hostRefs)) +
		controlCardHTML("Services", string(worstItemStatus(serviceItems)), serviceDetail, "/services", worstItemStatus(serviceItems)) +
		controlCardHTML("Certificates / Nginx", string(worseDiagnosticStatus(worstItemStatus(certificateItems), worstRefStatus(certificateRefs))), statusCountsText(mergeStatusCounts(diagnosticStatusCounts(certificateItems), refStatusCounts(certificateRefs))), "/certificates", worseDiagnosticStatus(worstItemStatus(certificateItems), worstRefStatus(certificateRefs))) +
		controlCardHTML("Exposure", string(exposureControlStatus(exposureSummary, exposureErr)), exposureControlDetail(exposureSummary, exposureErr), "/resources", exposureControlStatus(exposureSummary, exposureErr)) +
		controlCardHTML("Last Job", jobValue, jobDetail, "/jobs", jobStatus) +
		`</div>`
}

func controlCardHTML(label string, value string, detail string, href string, status domain.DiagnosticStatus) string {
	if strings.TrimSpace(value) == "" {
		value = string(domain.DiagnosticStatusUnknown)
	}
	return `<a class="control-card ` + esc(string(status)) + `" href="` + esc(href) + `" aria-label="` + esc(label+": "+value+". "+detail) + `">` +
		`<span class="control-card-label">` + esc(label) + `</span>` +
		`<span class="control-card-value">` + statusBadge(value) + `</span>` +
		`<span class="control-card-detail">` + esc(detail) + `</span>` +
		`</a>`
}

func latestJobControlStatus(records []domain.JobRecord) (domain.DiagnosticStatus, string, string) {
	if len(records) == 0 {
		return domain.DiagnosticStatusUnknown, "none", "No jobs recorded"
	}
	record := records[0]
	detail := string(record.Kind)
	if strings.TrimSpace(record.ResultSummary) != "" {
		detail += " · " + record.ResultSummary
	} else if strings.TrimSpace(record.ErrorSummary) != "" {
		detail += " · " + record.ErrorSummary
	}
	return diagnosticStatusForJobStatus(record.Status), string(record.Status), detail
}

func diagnosticStatusForJobStatus(status domain.JobStatus) domain.DiagnosticStatus {
	switch status {
	case domain.JobStatusSucceeded:
		return domain.DiagnosticStatusPass
	case domain.JobStatusFailed, domain.JobStatusInterrupted:
		return domain.DiagnosticStatusFail
	case domain.JobStatusQueued, domain.JobStatusRunning, domain.JobStatusUnknown:
		return domain.DiagnosticStatusUnknown
	default:
		return domain.DiagnosticStatusUnknown
	}
}

func exposureControlStatus(summary exposure.ResourceExposureMap, err error) domain.DiagnosticStatus {
	if err != nil {
		return domain.DiagnosticStatusFail
	}
	return worstStatusFromCounts(summary.Summary.RiskCounts)
}

func exposureControlDetail(summary exposure.ResourceExposureMap, err error) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("%d resources, %d public", summary.Summary.Total, summary.Summary.ByAccessMode[domain.AccessModePublic])
}

func hostHealthCompactHTML(health domain.HostHealthSummary) string {
	cpuPercent := cpuLoadPercent(health.Host.CPU)
	rootDisk, hasDisk := primaryDisk(health.Host.Disks)
	diskPercent := float64(0)
	diskValue := "unknown"
	diskDetail := "root disk not available"
	if hasDisk && rootDisk.TotalBytes > 0 {
		diskPercent = rootDisk.UsagePercent
		diskValue = fmt.Sprintf("%.1f%%", rootDisk.UsagePercent)
		diskDetail = rootDisk.Mountpoint + " " + bytesText(rootDisk.UsedBytes) + " / " + bytesText(rootDisk.TotalBytes)
	}
	return `<div id="host-status" hx-get="/fragments/host-status" hx-trigger="every 5s" hx-swap="outerHTML">` +
		`<div class="host-status-grid">` +
		metricCardHTML("CPU load", fmt.Sprintf("%.0f%%", cpuPercent), fmt.Sprintf("%d cores, load %s", health.Host.CPU.LogicalCores, health.Host.CPU.Load), cpuPercent) +
		metricCardHTML("Memory", fmt.Sprintf("%.1f%%", health.Host.Memory.UsagePercent), bytesText(health.Host.Memory.TotalBytes-health.Host.Memory.AvailableBytes)+" / "+bytesText(health.Host.Memory.TotalBytes), health.Host.Memory.UsagePercent) +
		metricCardHTML("Disk", diskValue, diskDetail, diskPercent) +
		metricCardHTML("System", health.Host.OS, "Last update "+health.GeneratedAt, 0) +
		`</div><div class="host-status-footer">Auto-refreshes every 5 seconds from local read-only metrics.</div></div>`
}

func metricCardHTML(label string, value string, detail string, percent float64) string {
	percent = clampPercent(percent)
	return `<div class="metric-card ` + metricClass(percent) + `"><div class="metric-label">` + esc(label) + `</div><div class="metric-value" title="` + esc(value) + `">` + esc(value) + `</div><div class="metric-detail" title="` + esc(detail) + `">` + esc(detail) + `</div><div class="meter"><div class="meter-fill" style="width: ` + esc(fmt.Sprintf("%.0f%%", percent)) + `"></div></div></div>`
}

func metricClass(percent float64) string {
	if percent >= 90 {
		return "danger"
	}
	if percent >= 75 {
		return "warn"
	}
	return "ok"
}

func clampPercent(percent float64) float64 {
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func cpuLoadPercent(cpu domain.HostHealthCPU) float64 {
	fields := strings.Fields(cpu.Load)
	if len(fields) == 0 || cpu.LogicalCores <= 0 {
		return 0
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return load * 100 / float64(cpu.LogicalCores)
}

func primaryDisk(disks []domain.HostHealthDisk) (domain.HostHealthDisk, bool) {
	for _, disk := range disks {
		if disk.Mountpoint == "/" {
			return disk, true
		}
	}
	for _, disk := range disks {
		if disk.TotalBytes > 0 {
			return disk, true
		}
	}
	return domain.HostHealthDisk{}, false
}

func bytesText(value int64) string {
	if value <= 0 {
		return "unknown"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	size := float64(value)
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size = size / 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", value, units[unit])
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func exposureOverviewHTML(summary exposure.ResourceExposureMap) string {
	return `<div class="summary-grid">` +
		statCardHTML("Resources", fmt.Sprintf("%d", summary.Summary.Total), "Managed exposure entries") +
		statCardHTML("Public", fmt.Sprintf("%d", summary.Summary.ByAccessMode[domain.AccessModePublic]), "Internet-facing resources") +
		statCardHTML("Browser Auth", fmt.Sprintf("%d", summary.Summary.ByAccessMode[domain.AccessModeBrowser]), "Protected by browser credentials") +
		statCardHTML("Tailnet Only", fmt.Sprintf("%d", summary.Summary.ByAccessMode[domain.AccessModePrivateClient]), "Private client resources") +
		`</div><p class="summary-note">Detailed resource exposure map and per-resource controls are on <a href="/resources">Resources</a>.</p>`
}

func statCardHTML(label string, value string, detail string) string {
	return `<div class="summary-card"><div class="summary-label">` + esc(label) + `</div><div class="summary-value"><strong>` + esc(value) + `</strong></div><div class="summary-detail">` + esc(detail) + `</div></div>`
}

func resourceConsoleHTML(path string, cfg appconfig.Config, summary exposure.ResourceExposureMap, err error) string {
	exposureValue := "unavailable"
	exposureDetail := "Exposure summary could not be calculated"
	if err == nil {
		exposureValue = fmt.Sprintf("%d", summary.Summary.Total)
		exposureDetail = fmt.Sprintf("%d public, %d browser auth, %d tailnet only",
			summary.Summary.ByAccessMode[domain.AccessModePublic],
			summary.Summary.ByAccessMode[domain.AccessModeBrowser],
			summary.Summary.ByAccessMode[domain.AccessModePrivateClient])
	}
	appName := strings.TrimSpace(cfg.App.Name)
	if appName == "" {
		appName = "unnamed"
	}
	body := `<div class="resource-console-grid">`
	body += statCardHTML("App", appName, appTargetDetail(cfg))
	body += statCardHTML("Exposure", exposureValue, exposureDetail)
	body += statCardHTML("Access", effectiveAccessMode(cfg), accessDetail(cfg))
	body += statCardHTML("Origin", effectiveOriginMode(cfg), originDetail(cfg))
	body += statCardHTML("GoAccess", enabledLabel(cfg.Nginx.GoAccess.Enabled), goAccessDetail(cfg))
	body += `</div>`
	body += `<p class="summary-note">Editing ` + esc(path) + `. Save updates the app config; Preview calculates the typed exposure plan without writing.</p>`
	return body
}

func appTargetDetail(cfg appconfig.Config) string {
	switch cfg.Mode() {
	case appconfig.ModeUpstream:
		if strings.TrimSpace(cfg.App.Upstream) == "" {
			return "upstream target not set"
		}
		return "upstream " + strings.TrimSpace(cfg.App.Upstream)
	default:
		if strings.TrimSpace(cfg.App.Listen) == "" {
			return "listen target not set"
		}
		return "listen " + strings.TrimSpace(cfg.App.Listen)
	}
}

func effectiveAccessMode(cfg appconfig.Config) string {
	if strings.TrimSpace(string(cfg.Access.AccessMode)) == "" {
		return string(appconfig.AccessModePublic)
	}
	return string(cfg.Access.AccessMode)
}

func accessDetail(cfg appconfig.Config) string {
	if cfg.BrowserAuthEnabled() {
		return "browser credential required"
	}
	if cfg.Access.PublicRiskConfirmed {
		return "public risk confirmed"
	}
	return "public risk not confirmed"
}

func effectiveOriginMode(cfg appconfig.Config) string {
	if strings.TrimSpace(string(cfg.Access.OriginProtection.Mode)) == "" {
		return string(appconfig.OriginProtectionModeNone)
	}
	return string(cfg.Access.OriginProtection.Mode)
}

func originDetail(cfg appconfig.Config) string {
	switch cfg.Access.OriginProtection.Mode {
	case appconfig.OriginProtectionModeEdgeOne:
		if strings.TrimSpace(cfg.Access.OriginProtection.EdgeOneProfile) == "" {
			return "EdgeOne profile not set"
		}
		return "profile " + strings.TrimSpace(cfg.Access.OriginProtection.EdgeOneProfile)
	default:
		if cfg.Access.OriginProtection.DirectOriginRiskConfirmed {
			return "direct origin risk confirmed"
		}
		return "no origin protection"
	}
}

func enabledLabel(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func goAccessDetail(cfg appconfig.Config) string {
	if !cfg.Nginx.GoAccess.Enabled {
		return "observability disabled"
	}
	if strings.TrimSpace(cfg.Nginx.GoAccess.AuthBasicUserFile) != "" {
		return "protected by auth file"
	}
	if len(cfg.Nginx.GoAccess.AuthCIDRAllowlist) > 0 {
		return "protected by CIDR allowlist"
	}
	return "enabled without extra guard"
}

func exposureSummaryHTML(summary exposure.ResourceExposureMap) string {
	body := kvTableHTML([]kv{
		{"Schema", summary.SchemaVersion},
		{"Instance", summary.Instance.InstanceID},
		{"Resources", fmt.Sprintf("%d", summary.Summary.Total)},
	})
	for _, entry := range summary.Resources {
		body += miniPanel(entry.Resource.CanonicalName, kvTableHTML([]kv{
			{"Resource ID", entry.Resource.ID},
			{"Access", string(entry.Access.AccessMode)},
			{"Target", targetSummary(entry.Target)},
			{"Browser auth", entry.Protection.BrowserAuth.Status},
			{"Origin protection", string(entry.Protection.OriginProtection.Status)},
			{"GoAccess", entry.Observability.GoAccess.Status},
		}))
	}
	return body
}

func exposurePlanHTML(plan domain.ExposurePlan) string {
	body := kvTableHTML([]kv{
		{"Schema", plan.SchemaVersion},
		{"Resource", plan.Resource.CanonicalName},
		{"Resource ID", plan.Resource.ID},
		{"Access", string(plan.Access.AccessMode)},
		{"Origin protection", string(plan.OriginProtection)},
		{"Decision", string(plan.Decision.Status)},
		{"Required confirmations", strings.Join(plan.Decision.RequiredConfirmations, ", ")},
	})
	if len(plan.DiagnosticBlockers) > 0 {
		body += diagnosticsHTML(plan.DiagnosticBlockers)
	}
	return body
}

func targetSummary(target domain.ResourceTarget) string {
	switch target.TargetKind {
	case domain.ResourceTargetKindListen:
		return fmt.Sprintf("listen %s:%d", target.Listen.Address, target.Listen.Port)
	case domain.ResourceTargetKindUpstream:
		return "upstream " + target.Upstream.URL
	case domain.ResourceTargetKindPrivateResource:
		return "private_resource"
	default:
		return string(target.TargetKind)
	}
}

func diagnosticsHTML(items []domain.DiagnosticItem) string {
	if len(items) == 0 {
		return `<p>No diagnostics available yet.</p>`
	}
	body := `<table class="data-table diagnostics-table"><thead><tr><th class="diag-col-id">ID</th><th class="diag-col-status">Status</th><th class="diag-col-scope">Scope</th><th class="diag-col-severity">Severity</th><th class="diag-col-evidence">Evidence</th><th class="diag-col-owner">Owner</th><th class="diag-col-blocks">Blocks activation</th><th>Summary</th></tr></thead><tbody>`
	for _, item := range items {
		body += `<tr>` + codeCell(item.ID) + `<td class="cell-nowrap">` + statusBadge(string(item.Status)) + `</td>` + nowrapCell(string(item.Scope)) + nowrapCell(string(item.Severity)) + nowrapCell(string(item.EvidenceSource)) + nowrapCell(string(item.ResponsibleParty)) + nowrapCell(fmt.Sprintf("%t", item.BlocksActivation)) + summaryCell(item.Summary) + `</tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

type diagnosticArea struct {
	Label  string
	Detail string
	Href   string
	Scopes []domain.DiagnosticScope
}

func diagnosticAreasHTML(items []domain.DiagnosticItem) string {
	if len(items) == 0 {
		return `<p>No runtime diagnostics available.</p>`
	}
	areas := []diagnosticArea{
		{Label: "Headscale", Detail: "Control-plane and onboarding readiness", Href: "/onboarding", Scopes: []domain.DiagnosticScope{domain.DiagnosticScopeHeadscale}},
		{Label: "Resources", Detail: "App config, exposure, RealIP, and GoAccess", Href: "/resources", Scopes: []domain.DiagnosticScope{domain.DiagnosticScopeResource, domain.DiagnosticScopeRealIP, domain.DiagnosticScopeGoAccess}},
		{Label: "Services", Detail: "Systemd units and runtime service probes", Href: "/services", Scopes: []domain.DiagnosticScope{domain.DiagnosticScopeService}},
		{Label: "Certificates / Nginx", Detail: "Certificate hooks, renew timers, and Nginx checks", Href: "/certificates", Scopes: []domain.DiagnosticScope{domain.DiagnosticScopeCertificate}},
		{Label: "Settings", Detail: "Instance-level configuration checks", Href: "/settings", Scopes: []domain.DiagnosticScope{domain.DiagnosticScopeInstance}},
	}
	body := `<div class="diagnostic-area-grid">`
	assigned := map[int]struct{}{}
	for _, area := range areas {
		matches := diagnosticsByArea(items, area.Scopes, assigned)
		body += diagnosticAreaCardHTML(area, matches)
	}
	remaining := []domain.DiagnosticItem{}
	for index, item := range items {
		if _, ok := assigned[index]; !ok {
			remaining = append(remaining, item)
		}
	}
	if len(remaining) > 0 {
		body += diagnosticAreaCardHTML(diagnosticArea{Label: "Other", Detail: "Diagnostics without a dedicated P0 page", Href: "/diagnostics"}, remaining)
	}
	return body + `</div><p class="summary-note">Open each area for detailed rows and actions. Diagnostics keeps cross-area counts here to avoid repeating page-level details.</p>`
}

func diagnosticsByArea(items []domain.DiagnosticItem, scopes []domain.DiagnosticScope, assigned map[int]struct{}) []domain.DiagnosticItem {
	scopeSet := map[domain.DiagnosticScope]struct{}{}
	for _, scope := range scopes {
		scopeSet[scope] = struct{}{}
	}
	matches := []domain.DiagnosticItem{}
	for index, item := range items {
		if _, ok := scopeSet[item.Scope]; ok {
			matches = append(matches, item)
			assigned[index] = struct{}{}
		}
	}
	return matches
}

func diagnosticAreaCardHTML(area diagnosticArea, items []domain.DiagnosticItem) string {
	counts := diagnosticStatusCounts(items)
	return `<a class="diagnostic-area-card" href="` + esc(area.Href) + `">` +
		`<span class="diagnostic-area-head"><strong>` + esc(area.Label) + `</strong><span>` + esc(fmt.Sprintf("%d", len(items))) + `</span></span>` +
		`<span class="diagnostic-area-detail">` + esc(area.Detail) + `</span>` +
		`<span class="diagnostic-area-statuses">` +
		diagnosticCountHTML("fail", counts[domain.DiagnosticStatusFail]) +
		diagnosticCountHTML("warn", counts[domain.DiagnosticStatusWarn]) +
		diagnosticCountHTML("manual", counts[domain.DiagnosticStatusManual]) +
		diagnosticCountHTML("unknown", counts[domain.DiagnosticStatusUnknown]) +
		diagnosticCountHTML("pass", counts[domain.DiagnosticStatusPass]) +
		`</span></a>`
}

func diagnosticStatusCounts(items []domain.DiagnosticItem) map[domain.DiagnosticStatus]int {
	counts := map[domain.DiagnosticStatus]int{}
	for _, item := range items {
		counts[item.Status]++
	}
	return counts
}

func refStatusCounts(refs []domain.DiagnosticRef) map[domain.DiagnosticStatus]int {
	counts := map[domain.DiagnosticStatus]int{}
	for _, ref := range refs {
		counts[ref.Status]++
	}
	return counts
}

func mergeStatusCounts(counts ...map[domain.DiagnosticStatus]int) map[domain.DiagnosticStatus]int {
	merged := map[domain.DiagnosticStatus]int{}
	for _, group := range counts {
		for status, count := range group {
			merged[status] += count
		}
	}
	return merged
}

func statusCountsText(counts map[domain.DiagnosticStatus]int) string {
	parts := []string{}
	for _, status := range []domain.DiagnosticStatus{domain.DiagnosticStatusFail, domain.DiagnosticStatusManual, domain.DiagnosticStatusWarn, domain.DiagnosticStatusUnknown, domain.DiagnosticStatusPass} {
		if counts[status] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[status], status))
		}
	}
	if len(parts) == 0 {
		return "No checks available"
	}
	return strings.Join(parts, " · ")
}

func worstItemStatus(items []domain.DiagnosticItem) domain.DiagnosticStatus {
	return worstStatusFromCounts(diagnosticStatusCounts(items))
}

func worstRefStatus(refs []domain.DiagnosticRef) domain.DiagnosticStatus {
	return worstStatusFromCounts(refStatusCounts(refs))
}

func worstStatusFromCounts(counts map[domain.DiagnosticStatus]int) domain.DiagnosticStatus {
	result := domain.DiagnosticStatusPass
	seen := false
	for status, count := range counts {
		if count <= 0 || status == domain.DiagnosticStatusNotApplicable {
			continue
		}
		seen = true
		result = worseDiagnosticStatus(result, status)
	}
	if !seen {
		return domain.DiagnosticStatusUnknown
	}
	return result
}

func worseDiagnosticStatus(left domain.DiagnosticStatus, right domain.DiagnosticStatus) domain.DiagnosticStatus {
	if diagnosticStatusRank(right) > diagnosticStatusRank(left) {
		return right
	}
	return left
}

func diagnosticStatusRank(status domain.DiagnosticStatus) int {
	switch status {
	case domain.DiagnosticStatusFail:
		return 5
	case domain.DiagnosticStatusManual:
		return 4
	case domain.DiagnosticStatusUnknown:
		return 3
	case domain.DiagnosticStatusWarn:
		return 2
	case domain.DiagnosticStatusPass:
		return 1
	default:
		return 0
	}
}

func diagnosticCountHTML(status string, count int) string {
	return `<span class="diagnostic-count">` + statusBadge(status) + `<strong>` + esc(fmt.Sprintf("%d", count)) + `</strong></span>`
}

func hostHealthCheckSummaryHTML(health domain.HostHealthSummary) string {
	refs := hostHealthCheckRefs(health)
	counts := map[domain.DiagnosticStatus]int{}
	for _, ref := range refs {
		counts[ref.Status]++
	}
	return `<div class="summary-grid">` +
		summaryCardHTML("Fail", fmt.Sprintf("%d", counts[domain.DiagnosticStatusFail]), "Requires attention", "fail") +
		summaryCardHTML("Manual", fmt.Sprintf("%d", counts[domain.DiagnosticStatusManual]), "Needs operator confirmation", "manual") +
		summaryCardHTML("Unknown", fmt.Sprintf("%d", counts[domain.DiagnosticStatusUnknown]), "Probe unavailable or inconclusive", "unknown") +
		summaryCardHTML("Pass", fmt.Sprintf("%d", counts[domain.DiagnosticStatusPass]), "Checks currently healthy", "pass") +
		`</div><p class="summary-note">Detailed host facts, live CPU, memory, disk, ports, certificates, and the full check table are on <a href="/host-health">Host Health</a>.</p>`
}

func summaryCardHTML(label string, value string, detail string, status string) string {
	return `<div class="summary-card"><div class="summary-label">` + esc(label) + `</div><div class="summary-value">` + statusBadge(status) + `<strong>` + esc(value) + `</strong></div><div class="summary-detail">` + esc(detail) + `</div></div>`
}

func hostHealthCheckRefs(health domain.HostHealthSummary) []domain.DiagnosticRef {
	refs := []domain.DiagnosticRef{}
	refs = append(refs, health.Checks.DNS...)
	refs = append(refs, health.Checks.Ports...)
	refs = append(refs, health.Checks.AptDpkgSystemd...)
	refs = append(refs, health.Checks.PublicPreflight...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	return refs
}

func hostHealthChecksHTML(health domain.HostHealthSummary) string {
	refs := hostHealthCheckRefs(health)
	body := `<table class="data-table checks-table"><thead><tr><th>Check</th><th>Status</th></tr></thead><tbody>`
	for _, ref := range refs {
		body += `<tr>` + codeCell(ref.ID) + `<td class="cell-nowrap">` + statusBadge(string(ref.Status)) + `</td></tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

func certificateNginxSummaryHTML(result workflow.OperationResult, health domain.HostHealthSummary) string {
	nginxItems := diagnosticsByID(result.Diagnostics, "runtime:nginx-service")
	renewItems := diagnosticsByID(result.Diagnostics, "runtime:main-renew-timer", "runtime:app-renew-timer")
	certificateRefs := health.Checks.Certificates
	nginxConfigRefs := health.Checks.NginxConfigTest
	nginxStatus := worstItemStatus(nginxItems)
	renewStatus := worstItemStatus(renewItems)
	certificateStatus := worstRefStatus(certificateRefs)
	nginxConfigStatus := worstRefStatus(nginxConfigRefs)
	return `<div class="summary-grid">` +
		summaryCardHTML("Nginx service", string(nginxStatus), fmt.Sprintf("%d runtime checks", len(nginxItems)), string(nginxStatus)) +
		summaryCardHTML("Renew timers", string(renewStatus), fmt.Sprintf("%d timer checks", len(renewItems)), string(renewStatus)) +
		summaryCardHTML("Certificate checks", string(certificateStatus), fmt.Sprintf("%d refs, %d expiry facts", len(certificateRefs), len(health.Certificates)), string(certificateStatus)) +
		summaryCardHTML("Nginx config", string(nginxConfigStatus), fmt.Sprintf("%d config checks", len(nginxConfigRefs)), string(nginxConfigStatus)) +
		`</div>`
}

func disclosureHTML(title string, body string, open bool) string {
	openAttr := ""
	if open {
		openAttr = " open"
	}
	return `<details class="detail-block"` + openAttr + `><summary>` + esc(title) + `</summary><div class="detail-block-body">` + body + `</div></details>`
}

func hostHealthFullHTML(health domain.HostHealthSummary) string {
	body := hostHealthCompactHTML(health)
	body += `<h3>Disks</h3>` + disksHTML(health.Host.Disks)
	body += `<h3>Network Addresses</h3>` + networkAddressesHTML(health.Host.NetworkAddresses)
	body += `<h3>Port Listeners</h3>` + portListenersHTML(health.Checks.PortListeners)
	body += `<h3>Certificates</h3>` + certificateFactsHTML(health.Certificates)
	body += `<h3>Host Checks</h3>`
	body += hostHealthChecksHTML(health)
	body += `<h3>Allowed Actions</h3><p>` + esc(actionsText(health.AllowedActions)) + `</p>`
	body += `<h3>Forbidden Actions</h3><p>` + esc(actionsText(health.ForbiddenActions)) + `</p>`
	return body
}

func disksHTML(disks []domain.HostHealthDisk) string {
	if len(disks) == 0 {
		return `<p>No disk facts available.</p>`
	}
	body := `<table class="data-table"><thead><tr><th>Mountpoint</th><th>FS</th><th>Total</th><th>Used</th><th>Usage</th></tr></thead><tbody>`
	for _, disk := range disks {
		body += `<tr><td>` + esc(disk.Mountpoint) + `</td><td>` + esc(disk.FSType) + `</td><td>` + esc(fmt.Sprintf("%d", disk.TotalBytes)) + `</td><td>` + esc(fmt.Sprintf("%d", disk.UsedBytes)) + `</td><td>` + esc(fmt.Sprintf("%.1f%%", disk.UsagePercent)) + `</td></tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

func networkAddressesHTML(addresses []domain.HostHealthNetworkAddresses) string {
	if len(addresses) == 0 {
		return `<p>No network address facts available.</p>`
	}
	body := `<table class="data-table compact-table"><thead><tr><th>Interface</th><th>Addresses</th></tr></thead><tbody>`
	for _, item := range addresses {
		body += `<tr><td>` + esc(item.Interface) + `</td><td>` + esc(strings.Join(item.Addresses, ", ")) + `</td></tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

func portListenersHTML(listeners []domain.HostHealthPortListener) string {
	if len(listeners) == 0 {
		return `<p>No port listener facts available.</p>`
	}
	groups := portListenerGroups(listeners)
	body := `<div class="port-groups">`
	for _, group := range groups {
		if len(group.Listeners) == 0 {
			continue
		}
		openAttr := ""
		if group.Open {
			openAttr = " open"
		}
		body += `<details class="port-group"` + openAttr + `><summary><span><strong>` + esc(group.Title) + `</strong><small>` + esc(group.Detail) + `</small></span><span class="port-count">` + esc(fmt.Sprintf("%d", len(group.Listeners))) + `</span></summary>` + portListenersTableHTML(group.Listeners) + `</details>`
	}
	return body + `</div>`
}

type portListenerGroup struct {
	Title     string
	Detail    string
	Open      bool
	Listeners []domain.HostHealthPortListener
}

func portListenersTableHTML(listeners []domain.HostHealthPortListener) string {
	body := `<table class="data-table compact-table"><thead><tr><th>Protocol</th><th>Address</th><th>Port</th></tr></thead><tbody>`
	for _, listener := range listeners {
		body += `<tr><td>` + esc(listener.Protocol) + `</td><td>` + esc(listener.LocalAddress) + `</td><td>` + esc(fmt.Sprintf("%d", listener.Port)) + `</td></tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

func portListenerGroups(listeners []domain.HostHealthPortListener) []portListenerGroup {
	groups := []portListenerGroup{
		{Title: "Public / All Interfaces", Detail: "Wildcard listeners reachable through host interfaces"},
		{Title: "Loopback", Detail: "Local-only listeners bound to loopback"},
		{Title: "Private / Tailnet", Detail: "Private, link-local, or tailnet-scoped listeners"},
		{Title: "Other", Detail: "Listeners that do not match the common host scopes"},
	}
	for _, listener := range listeners {
		index := portListenerGroupIndex(listener.LocalAddress)
		groups[index].Listeners = append(groups[index].Listeners, listener)
	}
	return groups
}

func portListenerGroupIndex(address string) int {
	normalized := normalizeListenerAddress(address)
	if isWildcardListenerAddress(normalized) {
		return 0
	}
	parsed, err := netip.ParseAddr(normalized)
	if err != nil {
		return 3
	}
	parsed = parsed.Unmap()
	if parsed.IsUnspecified() {
		return 0
	}
	if parsed.IsLoopback() {
		return 1
	}
	if parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || tailnetPrefix().Contains(parsed) {
		return 2
	}
	return 3
}

func normalizeListenerAddress(address string) string {
	normalized := strings.TrimSpace(address)
	normalized = strings.TrimPrefix(normalized, "[")
	normalized = strings.TrimSuffix(normalized, "]")
	return normalized
}

func isWildcardListenerAddress(address string) bool {
	return address == "" || address == "*" || strings.HasPrefix(address, "*%") || address == "0.0.0.0" || address == "::"
}

func tailnetPrefix() netip.Prefix {
	return netip.MustParsePrefix("100.64.0.0/10")
}

func certificateFactsHTML(certs []domain.HostHealthCertificate) string {
	if len(certs) > 0 {
		certTable := `<table class="data-table compact-table"><thead><tr><th>Domain</th><th>Not After</th><th>Diagnostic</th></tr></thead><tbody>`
		for _, cert := range certs {
			certTable += `<tr><td>` + esc(cert.Domain) + `</td><td>` + esc(cert.NotAfter) + `</td><td><code>` + esc(cert.DiagnosticID) + `</code></td></tr>`
		}
		return tableWrap(certTable + `</tbody></table>`)
	}
	return `<p>No certificate expiry facts available.</p>`
}

func diagnosticRefsHTML(refs []domain.DiagnosticRef) string {
	if len(refs) == 0 {
		return `<p>No diagnostic refs available.</p>`
	}
	body := `<table class="data-table diagnostics-refs-table"><thead><tr><th>ID</th><th>Status</th><th>Evidence</th><th>Owner</th><th>Blocks activation</th></tr></thead><tbody>`
	for _, ref := range refs {
		body += `<tr>` + codeCell(ref.ID) + `<td class="cell-nowrap">` + statusBadge(string(ref.Status)) + `</td>` + nowrapCell(string(ref.EvidenceSource)) + nowrapCell(string(ref.ResponsibleParty)) + nowrapCell(fmt.Sprintf("%t", ref.BlocksActivation)) + `</tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}

func compactDiagnosticRefsHTML(refs []domain.DiagnosticRef) string {
	if len(refs) == 0 {
		return `<p>No diagnostic refs available.</p>`
	}
	body := `<ul class="ref-list">`
	for _, ref := range refs {
		body += `<li class="ref-row"><code>` + esc(ref.ID) + `</code><span class="ref-status">` + statusBadge(string(ref.Status)) + `</span><span class="ref-meta"><span>Evidence: ` + esc(string(ref.EvidenceSource)) + `</span><span>Owner: ` + esc(string(ref.ResponsibleParty)) + `</span><span>Blocks activation: ` + esc(fmt.Sprintf("%t", ref.BlocksActivation)) + `</span></span></li>`
	}
	return body + `</ul>`
}

func actionsText(actions []domain.HostHealthAction) string {
	values := make([]string, 0, len(actions))
	for _, action := range actions {
		values = append(values, string(action))
	}
	return strings.Join(values, ", ")
}
