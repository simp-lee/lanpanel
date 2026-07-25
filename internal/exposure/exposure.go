// Package exposure derives P0 resource exposure plans and summaries from
// configuration and runtime observations. It does not drive deploy or recovery.
package exposure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/domain"
	"lanpanel/internal/resource"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type InstanceMetadata struct {
	InstanceID      string `json:"instance_id"`
	LanpanelVersion string `json:"lanpanel_version"`
	BaseDomain      string `json:"base_domain"`
	ServerURL       string `json:"server_url"`
}

type InstanceSummaryOptions struct {
	BaseDomain string
	ServerURL  string
}

type ResourceExposureMap struct {
	SchemaVersion string                  `json:"schema_version"`
	GeneratedAt   time.Time               `json:"generated_at"`
	Instance      InstanceMetadata        `json:"instance"`
	Resources     []ResourceExposureEntry `json:"resources"`
	Summary       ExposureSummary         `json:"summary"`
}

type ResourceExposureEntry struct {
	Resource      domain.Resource        `json:"resource"`
	Target        domain.ResourceTarget  `json:"target"`
	Access        domain.AccessSurface   `json:"access"`
	Protection    ProtectionSummary      `json:"protection"`
	Observability ObservabilitySummary   `json:"observability"`
	Diagnostics   []domain.DiagnosticRef `json:"diagnostics,omitempty"`
	Activation    domain.ActivationRef   `json:"activation"`
	ConfigDigest  string                 `json:"config_digest"`
}

type ProtectionSummary struct {
	BrowserAuth      BrowserAuthProtection   `json:"browser_auth"`
	CIDRAllowlist    CIDRAllowlistSummary    `json:"cidr_allowlist"`
	OriginProtection OriginProtectionSummary `json:"origin_protection"`
	RealIP           RealIPProtectionSummary `json:"realip"`
}

type BrowserAuthProtection struct {
	Status          string `json:"status"`
	Mode            string `json:"mode"`
	AuthFileRef     string `json:"auth_file_ref"`
	MarkerPresent   string `json:"marker_present"`
	RuntimeReadable string `json:"runtime_readable"`
}

type CIDRAllowlistSummary struct {
	Status       string   `json:"status"`
	CIDRs        []string `json:"cidrs,omitempty"`
	NginxSatisfy string   `json:"nginx_satisfy"`
}

type OriginProtectionSummary struct {
	Status          domain.OriginProtectionStatus `json:"status"`
	Provider        string                        `json:"provider"`
	ProfileID       string                        `json:"profile_id"`
	ReferenceDigest string                        `json:"reference_digest"`
}

type RealIPProtectionSummary struct {
	Status            domain.DiagnosticStatus `json:"status"`
	TrustedCIDRCount  int                     `json:"trusted_cidr_count"`
	ClientIPHeader    string                  `json:"client_ip_header"`
	SpoofingRejection string                  `json:"spoofing_rejection"`
}

type ObservabilitySummary struct {
	GoAccess    GoAccessObservability    `json:"goaccess"`
	AccessLog   AccessLogObservability   `json:"access_log"`
	Service     ServiceObservability     `json:"service"`
	Certificate CertificateObservability `json:"certificate"`
}

type GoAccessObservability struct {
	Status        string `json:"status"`
	DashboardPath string `json:"dashboard_path"`
	WebSocketPath string `json:"websocket_path"`
	AuthBasic     string `json:"auth_basic"`
	CIDRAllowlist string `json:"cidr_allowlist"`
	LogFormat     string `json:"log_format"`
	RuntimeScope  string `json:"runtime_scope"`
}

type AccessLogObservability struct {
	Status      string `json:"status"`
	PathRef     string `json:"path_ref"`
	ExportedRaw bool   `json:"exported_raw"`
}

type ServiceObservability struct {
	SystemdUnit string `json:"systemd_unit"`
	Status      string `json:"status"`
}

type CertificateObservability struct {
	Domains    []string `json:"domains,omitempty"`
	Status     string   `json:"status"`
	RenewTimer string   `json:"renew_timer"`
}

type ExposureSummary struct {
	Total        int                             `json:"total"`
	ByAccessMode map[domain.AccessMode]int       `json:"by_access_mode"`
	RiskCounts   map[domain.DiagnosticStatus]int `json:"risk_counts"`
}

type AppObservations struct {
	ConfigPath                      string
	GeneratedAt                     time.Time
	Activation                      domain.ActivationRef
	Diagnostics                     []domain.DiagnosticRef
	OriginProtectionStatus          domain.OriginProtectionStatus
	OriginProtectionReferenceDigest string
	RealIPTrustedCIDRCount          int
	RealIPClientIPHeader            string
	RealIPSpoofingRejection         domain.DiagnosticStatus
	GoAccessAuthBasicStatus         domain.DiagnosticStatus
	BrowserAuthRuntimeStatus        domain.DiagnosticStatus
	BrowserAuthMarkerStatus         domain.DiagnosticStatus
}

type AppPlanOptions struct {
	ConfigPath          string
	Actor               domain.Actor
	Operation           domain.ExposurePlanOperation
	CreatedAt           time.Time
	ModifiedPaths       []string
	ManualConfirmations []domain.ManualConfirmation
	BeforeDigest        string
	ActivationPreview   domain.ExposureActivationPreview
}

func AppPlan(instanceID string, version string, cfg appconfig.Config, options AppPlanOptions) (domain.ExposurePlan, error) {
	return AppPlanWithObservations(instanceID, version, cfg, options, AppObservations{})
}

func AppPlanWithObservations(instanceID string, version string, cfg appconfig.Config, options AppPlanOptions, observations AppObservations) (domain.ExposurePlan, error) {
	if strings.TrimSpace(string(options.Operation)) == "" {
		return domain.ExposurePlan{}, fmt.Errorf("exposure plan operation is required")
	}
	if err := validateExposurePlanOperation(options.Operation); err != nil {
		return domain.ExposurePlan{}, err
	}
	if strings.TrimSpace(options.BeforeDigest) == "" {
		options.BeforeDigest = "none"
	}
	createdAt := options.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	if strings.TrimSpace(observations.ConfigPath) == "" {
		observations.ConfigPath = options.ConfigPath
	}
	observations.Activation = domain.NotApplicableActivationRef()
	observations.GeneratedAt = createdAt
	summary, err := appSummaryWithObservations(instanceID, version, cfg, observations, InstanceSummaryOptions{})
	if err != nil {
		return domain.ExposurePlan{}, err
	}
	decisionStatus := domain.ExposurePlanDecisionPass
	confirmations := []string{}
	hasResidualWarning := false
	exposureActivationGate := operationChangesExposureSurface(options.Operation)
	if exposureActivationGate {
		if !cfg.PrivateClientAccessEnabled() {
			if cfg.PublicAccessEnabled() && !cfg.Access.PublicRiskConfirmed {
				confirmations = append(confirmations, "public-app-risk")
			} else if cfg.PublicAccessEnabled() {
				hasResidualWarning = true
			}
			if cfg.Access.OriginProtection.Mode == appconfig.OriginProtectionModeNone && !cfg.Access.OriginProtection.DirectOriginRiskConfirmed {
				confirmations = append(confirmations, "direct-origin-risk")
			} else if cfg.Access.OriginProtection.Mode == appconfig.OriginProtectionModeNone {
				hasResidualWarning = true
			}
		}
	}
	if len(confirmations) > 0 {
		decisionStatus = domain.ExposurePlanDecisionManual
	} else if hasResidualWarning {
		decisionStatus = domain.ExposurePlanDecisionWarn
	}
	if len(summary.Resources) != 1 {
		return domain.ExposurePlan{}, fmt.Errorf("app exposure plan expected one resource, got %d", len(summary.Resources))
	}
	entry := summary.Resources[0]
	entry.Access.ManualConfirmations = append([]domain.ManualConfirmation(nil), options.ManualConfirmations...)
	diagnosticBlockers := []domain.DiagnosticItem{}
	blockerIDs := []string{}
	if entry.Access.AccessMode == domain.AccessModePrivateClient && exposureActivationGate {
		decisionStatus = domain.ExposurePlanDecisionFail
		blocker := domain.DiagnosticItem{
			ID:               "private-client-p1",
			Status:           domain.DiagnosticStatusFail,
			Scope:            domain.DiagnosticScopeResource,
			ResourceID:       entry.Resource.ID,
			Severity:         domain.DiagnosticSeverityCritical,
			Summary:          "private_client resources are reserved for P1 and cannot be activated in P0",
			EvidenceSource:   domain.DiagnosticEvidenceConfig,
			ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
			BlocksActivation: true,
			Redaction:        domain.RedactionNone,
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		}
		diagnosticBlockers = append(diagnosticBlockers, blocker)
		blockerIDs = append(blockerIDs, blocker.ID)
	}
	for _, blocker := range browserAuthDiagnosticBlockers(entry) {
		decisionStatus = combineExposurePlanDecision(decisionStatus, diagnosticStatusPlanDecision(blocker.Status))
		diagnosticBlockers = append(diagnosticBlockers, blocker)
		blockerIDs = append(blockerIDs, blocker.ID)
	}
	switch entry.Protection.OriginProtection.Status {
	case domain.OriginProtectionConfiguredFail, domain.OriginProtectionConfiguredUnknown:
		if exposureActivationGate {
			decisionStatus = combineExposurePlanDecision(decisionStatus, originProtectionPlanDecisionStatus(entry.Protection.OriginProtection.Status))
			blocker := domain.DiagnosticItem{
				ID:               "origin-protection",
				Status:           originProtectionDiagnosticStatus(entry.Protection.OriginProtection.Status),
				Scope:            domain.DiagnosticScopeResource,
				ResourceID:       entry.Resource.ID,
				Severity:         domain.DiagnosticSeverityCritical,
				Summary:          fmt.Sprintf("origin protection is %s", entry.Protection.OriginProtection.Status),
				EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
				ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
				BlocksActivation: true,
				Redaction:        domain.RedactionNone,
				RedactionStatus:  domain.RedactionStatusNoSensitiveData,
			}
			diagnosticBlockers = append(diagnosticBlockers, blocker)
			blockerIDs = append(blockerIDs, blocker.ID)
		} else if decisionStatus == domain.ExposurePlanDecisionPass {
			decisionStatus = domain.ExposurePlanDecisionWarn
		}
	case domain.OriginProtectionConfiguredPass:
		if !exposureActivationGate && decisionStatus == domain.ExposurePlanDecisionPass {
			decisionStatus = domain.ExposurePlanDecisionWarn
		}
	case domain.OriginProtectionConfiguredManual:
		if exposureActivationGate {
			if decisionStatus != domain.ExposurePlanDecisionFail && decisionStatus != domain.ExposurePlanDecisionUnknown {
				decisionStatus = domain.ExposurePlanDecisionManual
			}
			confirmations = append(confirmations, "origin-protection-manual")
		} else if decisionStatus == domain.ExposurePlanDecisionPass {
			decisionStatus = domain.ExposurePlanDecisionWarn
		}
	}
	afterDigest := ""
	if len(summary.Resources) == 1 {
		afterDigest = summary.Resources[0].ConfigDigest
	}
	if strings.TrimSpace(afterDigest) == "" {
		return domain.ExposurePlan{}, fmt.Errorf("exposure plan after_digest is required")
	}
	activationPreview := defaultActivationPreview(options.Operation, entry)
	if len(options.ActivationPreview.ReloadServices) > 0 {
		activationPreview.ReloadServices = append([]string(nil), options.ActivationPreview.ReloadServices...)
	}
	if len(options.ActivationPreview.CertificatesChanged) > 0 {
		activationPreview.CertificatesChanged = append([]string(nil), options.ActivationPreview.CertificatesChanged...)
	}
	if options.ActivationPreview.PublicExposureChanged {
		activationPreview.PublicExposureChanged = true
	}
	return domain.ExposurePlan{
		SchemaVersion:    domain.ExposurePlanSchemaVersion,
		PlanID:           exposurePlanID(createdAt, entry.Resource.ID),
		CreatedAt:        createdAt.UTC(),
		Actor:            options.Actor,
		Operation:        options.Operation,
		ResourcesChanged: []string{entry.Resource.ID},
		ModifiedPaths:    compact(options.ModifiedPaths),
		BeforeDigest:     options.BeforeDigest,
		AfterDigest:      afterDigest,
		Decision: domain.ExposurePlanDecisionSummary{
			Status:                decisionStatus,
			Blockers:              blockerIDs,
			RequiredConfirmations: compact(confirmations),
		},
		ActivationPreview:  activationPreview,
		Resource:           entry.Resource,
		Access:             entry.Access,
		OriginProtection:   entry.Protection.OriginProtection.Status,
		DiagnosticBlockers: diagnosticBlockers,
	}, nil
}

func AppSummary(instanceID string, version string, cfg appconfig.Config, activation domain.ActivationRef, diagnostics []domain.DiagnosticRef) (ResourceExposureMap, error) {
	return AppSummaryWithObservations(instanceID, version, cfg, AppObservations{
		Activation:  activation,
		Diagnostics: diagnostics,
	})
}

func AppSummaryForConfigPath(instanceID string, version string, configPath string, cfg appconfig.Config, activation domain.ActivationRef, diagnostics []domain.DiagnosticRef) (ResourceExposureMap, error) {
	return AppSummaryWithObservations(instanceID, version, cfg, AppObservations{
		ConfigPath:  configPath,
		Activation:  activation,
		Diagnostics: diagnostics,
	})
}

func AppSummaryWithObservations(instanceID string, version string, cfg appconfig.Config, observations AppObservations) (ResourceExposureMap, error) {
	return AppSummaryWithObservationsAndInstance(instanceID, version, cfg, observations, InstanceSummaryOptions{})
}

func AppSummaryWithObservationsAndInstance(instanceID string, version string, cfg appconfig.Config, observations AppObservations, instanceOptions InstanceSummaryOptions) (ResourceExposureMap, error) {
	return appSummaryWithObservations(instanceID, version, cfg, observations, instanceOptions)
}

func appSummaryWithObservations(instanceID string, version string, cfg appconfig.Config, observations AppObservations, instanceOptions InstanceSummaryOptions) (ResourceExposureMap, error) {
	if err := cfg.ValidateForExposurePlan(); err != nil {
		return ResourceExposureMap{}, err
	}
	if err := validateAppObservations(cfg, observations); err != nil {
		return ResourceExposureMap{}, err
	}
	if err := validateDiagnosticRefs(observations.Diagnostics); err != nil {
		return ResourceExposureMap{}, err
	}
	generatedAt := observations.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	activation := observations.Activation
	if activation.Kind == "" {
		activation = domain.NotApplicableActivationRef()
	}
	if err := validateActivationRef(activation); err != nil {
		return ResourceExposureMap{}, err
	}
	entry, err := appEntry(instanceID, observations.ConfigPath, cfg, activation, observations)
	if err != nil {
		return ResourceExposureMap{}, err
	}
	return ResourceExposureMap{
		SchemaVersion: domain.ResourceExposureSchemaV1,
		GeneratedAt:   generatedAt.UTC(),
		Instance: InstanceMetadata{
			InstanceID:      instanceID,
			LanpanelVersion: strings.TrimSpace(version),
			BaseDomain:      strings.TrimSpace(instanceOptions.BaseDomain),
			ServerURL:       strings.TrimSpace(instanceOptions.ServerURL),
		},
		Resources: []ResourceExposureEntry{entry},
		Summary:   summarize([]ResourceExposureEntry{entry}),
	}, nil
}

func appEntry(instanceID string, configPath string, cfg appconfig.Config, activation domain.ActivationRef, observations AppObservations) (ResourceExposureEntry, error) {
	id, err := resource.ResourceID(instanceID, domain.ResourceTypeHTTPApp, cfg.ResourceName())
	if err != nil {
		return ResourceExposureEntry{}, err
	}
	configPathRef, err := canonicalConfigPathRef(configPath)
	if err != nil {
		return ResourceExposureEntry{}, err
	}
	accessMode := domain.AccessMode(cfg.Access.AccessMode)
	if accessMode != domain.AccessModeBrowser && accessMode != domain.AccessModePublic && accessMode != domain.AccessModePrivateClient {
		return ResourceExposureEntry{}, fmt.Errorf("unsupported access surface %q", cfg.Access.AccessMode)
	}
	target, err := resourceTarget(cfg)
	if err != nil {
		return ResourceExposureEntry{}, err
	}
	digest, err := configDigest(cfg)
	if err != nil {
		return ResourceExposureEntry{}, err
	}
	res := domain.Resource{
		ID:            id,
		Type:          domain.ResourceTypeHTTPApp,
		Name:          cfg.App.Name,
		CanonicalName: cfg.ResourceName(),
		OwnerScope:    domain.ResourceOwnerScopeLocalInstance,
		ConfigRef: domain.ResourceConfigRef{
			Path:   configPathRef,
			Digest: digest,
		},
		State:     resourceStateForActivation(activation),
		CreatedAt: "unknown",
		UpdatedAt: "unknown",
	}
	return ResourceExposureEntry{
		Resource: res,
		Target:   target,
		Access:   accessSurface(cfg, accessMode),
		Protection: ProtectionSummary{
			BrowserAuth:      browserProtection(cfg, observations),
			CIDRAllowlist:    cidrAllowlistProtection(cfg),
			OriginProtection: originProtection(cfg, observations),
			RealIP:           realIPProtection(cfg, observations),
		},
		Observability: observabilityState(cfg, observations),
		Diagnostics:   append([]domain.DiagnosticRef(nil), observations.Diagnostics...),
		Activation:    activation,
		ConfigDigest:  digest,
	}, nil
}

func resourceStateForActivation(activation domain.ActivationRef) domain.ResourceState {
	switch activation.Kind {
	case domain.ActivationRefCheckpoint:
		return domain.ResourceStateActive
	default:
		return domain.ResourceStatePlanned
	}
}

func canonicalConfigPathRef(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "not_applicable", nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve app config path: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func resourceTarget(cfg appconfig.Config) (domain.ResourceTarget, error) {
	if cfg.PrivateClientAccessEnabled() {
		return domain.ResourceTarget{
			TargetKind: domain.ResourceTargetKindPrivateResource,
			PrivateResource: domain.PrivateResourceTarget{
				DNSNames: append([]string(nil), cfg.App.Domains...),
			},
			NotApplicableFields: []string{"listen", "upstream"},
		}, nil
	}
	switch cfg.Mode() {
	case appconfig.ModeListen:
		host, portString, err := net.SplitHostPort(cfg.App.Listen)
		if err != nil {
			return domain.ResourceTarget{}, fmt.Errorf("parse listen target: %w", err)
		}
		port, err := strconv.Atoi(portString)
		if err != nil {
			return domain.ResourceTarget{}, fmt.Errorf("parse listen target port: %w", err)
		}
		return domain.ResourceTarget{
			TargetKind: domain.ResourceTargetKindListen,
			Listen: domain.ListenResourceTarget{
				Address:     host,
				Port:        port,
				ServiceName: cfg.ResourceName() + ".service",
			},
			NotApplicableFields: []string{"upstream", "private_resource"},
		}, nil
	case appconfig.ModeUpstream:
		host, portString, err := net.SplitHostPort(cfg.App.Upstream)
		if err != nil {
			return domain.ResourceTarget{}, fmt.Errorf("parse upstream target: %w", err)
		}
		if _, err := strconv.Atoi(portString); err != nil {
			return domain.ResourceTarget{}, fmt.Errorf("parse upstream target port: %w", err)
		}
		return domain.ResourceTarget{
			TargetKind: domain.ResourceTargetKindUpstream,
			Upstream: domain.UpstreamResourceTarget{
				URL:       "http://" + net.JoinHostPort(host, portString),
				TailnetIP: host,
				Protocol:  "http",
			},
			NotApplicableFields: []string{"listen", "private_resource"},
		}, nil
	default:
		return domain.ResourceTarget{}, fmt.Errorf("unsupported app target mode %q", cfg.Mode())
	}
}

func accessSurface(cfg appconfig.Config, mode domain.AccessMode) domain.AccessSurface {
	access := domain.AccessSurface{
		AccessMode: mode,
		PublicEntry: domain.PublicEntry{
			Status:    domain.PublicEntryEnabled,
			Domains:   append([]string(nil), cfg.App.Domains...),
			TLS:       "enabled",
			NginxSite: "enabled",
		},
		PrivateEntry: domain.PrivateEntry{Status: domain.PrivateEntryNotApplicable},
	}
	switch mode {
	case domain.AccessModeBrowser:
		access.RiskLabel = domain.AccessRiskBrowserAuthRequired
	case domain.AccessModePublic:
		access.RiskLabel = domain.AccessRiskPublicInternet
	default:
		access.RiskLabel = domain.AccessRiskPrivateOnly
		access.PublicEntry.Status = domain.PublicEntryNotApplicable
		access.PublicEntry.Domains = nil
		access.PublicEntry.TLS = "not_applicable"
		access.PublicEntry.NginxSite = "not_applicable"
		access.PublicEntry.NotApplicableFields = []string{"domains", "tls", "nginx_site"}
		access.PrivateEntry.Status = domain.PrivateEntryEnabled
	}
	return access
}

func browserProtection(cfg appconfig.Config, observations AppObservations) BrowserAuthProtection {
	if cfg.PrivateClientAccessEnabled() {
		return BrowserAuthProtection{
			Status:          "not_applicable",
			Mode:            "not_applicable",
			AuthFileRef:     "not_applicable",
			MarkerPresent:   "not_applicable",
			RuntimeReadable: "not_applicable",
		}
	}
	if cfg.BrowserAuthEnabled() {
		protection := BrowserAuthProtection{
			Status:          "required",
			AuthFileRef:     cfg.BrowserAuthUserFile(),
			RuntimeReadable: string(browserAuthRuntimeStatus(observations)),
		}
		if cfg.Access.BrowserAuth.Managed.HtpasswdPath != "" {
			protection.Mode = "lanpanel_managed"
			protection.MarkerPresent = string(browserAuthMarkerStatus(observations))
		} else {
			protection.Mode = "external_file"
			protection.MarkerPresent = "not_applicable"
		}
		return protection
	}
	return BrowserAuthProtection{
		Status:          "not_required",
		Mode:            "not_applicable",
		AuthFileRef:     "not_applicable",
		MarkerPresent:   "not_applicable",
		RuntimeReadable: "not_applicable",
	}
}

func browserAuthRuntimeStatus(observations AppObservations) domain.DiagnosticStatus {
	if observations.BrowserAuthRuntimeStatus != "" {
		return observations.BrowserAuthRuntimeStatus
	}
	return diagnosticStatusByID(observations.Diagnostics, "browser-auth-file", domain.DiagnosticStatusUnknown)
}

func browserAuthMarkerStatus(observations AppObservations) domain.DiagnosticStatus {
	if observations.BrowserAuthMarkerStatus != "" {
		return observations.BrowserAuthMarkerStatus
	}
	return diagnosticStatusByID(observations.Diagnostics, "browser-auth-file", domain.DiagnosticStatusUnknown)
}

func diagnosticStatusByID(refs []domain.DiagnosticRef, id string, fallback domain.DiagnosticStatus) domain.DiagnosticStatus {
	for _, ref := range refs {
		if ref.ID == id {
			return ref.Status
		}
	}
	return fallback
}

func cidrAllowlistProtection(cfg appconfig.Config) CIDRAllowlistSummary {
	if !cfg.BrowserAuthEnabled() {
		return CIDRAllowlistSummary{Status: "not_applicable", NginxSatisfy: "not_applicable"}
	}
	if len(cfg.Access.CIDRAllowlist) == 0 {
		return CIDRAllowlistSummary{Status: "disabled", NginxSatisfy: "not_applicable"}
	}
	return CIDRAllowlistSummary{Status: "enabled", CIDRs: append([]string(nil), cfg.Access.CIDRAllowlist...), NginxSatisfy: "all"}
}

func originProtection(cfg appconfig.Config, observations AppObservations) OriginProtectionSummary {
	if cfg.PrivateClientAccessEnabled() {
		return OriginProtectionSummary{
			Status:          domain.OriginProtectionNotApplicable,
			Provider:        "not_applicable",
			ProfileID:       "not_applicable",
			ReferenceDigest: "not_applicable",
		}
	}
	switch cfg.Access.OriginProtection.Mode {
	case appconfig.OriginProtectionModeNone:
		return OriginProtectionSummary{
			Status:          domain.OriginProtectionNone,
			Provider:        "none",
			ProfileID:       "not_applicable",
			ReferenceDigest: "not_applicable",
		}
	case appconfig.OriginProtectionModeEdgeOne:
		referenceDigest := strings.TrimSpace(observations.OriginProtectionReferenceDigest)
		if referenceDigest == "" {
			referenceDigest = "not_applicable"
		}
		return OriginProtectionSummary{
			Status:          effectiveOriginProtectionStatus(observations),
			Provider:        appconfig.RealIPProviderEdgeOne,
			ProfileID:       cfg.Access.OriginProtection.EdgeOneProfile,
			ReferenceDigest: referenceDigest,
		}
	default:
		return OriginProtectionSummary{
			Status:          domain.OriginProtectionNotApplicable,
			Provider:        "not_applicable",
			ProfileID:       "not_applicable",
			ReferenceDigest: "not_applicable",
		}
	}
}

func realIPProtection(cfg appconfig.Config, observations AppObservations) RealIPProtectionSummary {
	if cfg.Access.OriginProtection.Mode != appconfig.OriginProtectionModeEdgeOne {
		return RealIPProtectionSummary{
			Status:            domain.DiagnosticStatusNotApplicable,
			ClientIPHeader:    "not_applicable",
			SpoofingRejection: "not_applicable",
		}
	}
	status := domain.DiagnosticStatusUnknown
	switch effectiveOriginProtectionStatus(observations) {
	case domain.OriginProtectionConfiguredPass:
		status = domain.DiagnosticStatusPass
	case domain.OriginProtectionConfiguredManual:
		status = domain.DiagnosticStatusManual
	case domain.OriginProtectionConfiguredFail:
		status = domain.DiagnosticStatusFail
	case domain.OriginProtectionConfiguredUnknown, "":
		status = domain.DiagnosticStatusUnknown
	}
	clientIPHeader := strings.TrimSpace(observations.RealIPClientIPHeader)
	if clientIPHeader == "" {
		clientIPHeader = appconfig.RealIPHeaderEdgeOne
	}
	spoofingRejection := observations.RealIPSpoofingRejection
	if spoofingRejection == "" {
		spoofingRejection = domain.DiagnosticStatusUnknown
	}
	return RealIPProtectionSummary{
		Status:            status,
		TrustedCIDRCount:  observations.RealIPTrustedCIDRCount,
		ClientIPHeader:    clientIPHeader,
		SpoofingRejection: string(spoofingRejection),
	}
}

func effectiveOriginProtectionStatus(observations AppObservations) domain.OriginProtectionStatus {
	switch observations.OriginProtectionStatus {
	case "":
		return domain.OriginProtectionConfiguredUnknown
	case domain.OriginProtectionConfiguredPass:
		if hasConfiguredPassEvidence(observations) {
			return domain.OriginProtectionConfiguredPass
		}
		return domain.OriginProtectionConfiguredUnknown
	default:
		return observations.OriginProtectionStatus
	}
}

func hasConfiguredPassEvidence(observations AppObservations) bool {
	return isSHA256Digest(observations.OriginProtectionReferenceDigest) &&
		observations.RealIPTrustedCIDRCount > 0 &&
		strings.TrimSpace(observations.RealIPClientIPHeader) == appconfig.RealIPHeaderEdgeOne &&
		observations.RealIPSpoofingRejection == domain.DiagnosticStatusPass
}

func observabilityState(cfg appconfig.Config, observations AppObservations) ObservabilitySummary {
	return ObservabilitySummary{
		GoAccess:    goAccessState(cfg, observations),
		AccessLog:   accessLogState(cfg),
		Service:     serviceState(cfg),
		Certificate: certificateState(cfg),
	}
}

func goAccessState(cfg appconfig.Config, observations AppObservations) GoAccessObservability {
	if cfg.Nginx.GoAccess.Enabled {
		cidr := "disabled"
		if len(cfg.Nginx.GoAccess.AuthCIDRAllowlist) > 0 {
			cidr = "enabled"
		}
		return GoAccessObservability{
			Status:        "enabled",
			DashboardPath: cfg.NginxGoAccessDashboardPath(),
			WebSocketPath: cfg.NginxGoAccessWebSocketPath(),
			AuthBasic:     string(goAccessAuthBasicStatus(observations)),
			CIDRAllowlist: cidr,
			LogFormat:     cfg.Nginx.GoAccess.EffectiveLogFormat(),
			RuntimeScope:  "unknown",
		}
	}
	return GoAccessObservability{
		Status:        "disabled",
		DashboardPath: "not_applicable",
		WebSocketPath: "not_applicable",
		AuthBasic:     "not_applicable",
		CIDRAllowlist: "not_applicable",
		LogFormat:     "not_applicable",
		RuntimeScope:  "not_applicable",
	}
}

func goAccessAuthBasicStatus(observations AppObservations) domain.DiagnosticStatus {
	if observations.GoAccessAuthBasicStatus != "" {
		return observations.GoAccessAuthBasicStatus
	}
	for _, ref := range observations.Diagnostics {
		if ref.ID == "goaccess-auth-file" {
			return ref.Status
		}
	}
	return domain.DiagnosticStatusUnknown
}

func accessLogState(cfg appconfig.Config) AccessLogObservability {
	accessLog := strings.TrimSpace(cfg.Nginx.AccessLog)
	if cfg.Nginx.GoAccess.Enabled {
		return AccessLogObservability{Status: "enabled", PathRef: cfg.NginxGoAccessCanonicalAccessLogPath(), ExportedRaw: false}
	}
	switch accessLog {
	case "":
		return AccessLogObservability{Status: "enabled", PathRef: "nginx_default", ExportedRaw: false}
	case "off":
		return AccessLogObservability{Status: "disabled", PathRef: "not_applicable", ExportedRaw: false}
	default:
		return AccessLogObservability{Status: "enabled", PathRef: accessLog, ExportedRaw: false}
	}
}

func serviceState(cfg appconfig.Config) ServiceObservability {
	if cfg.PrivateClientAccessEnabled() {
		return ServiceObservability{SystemdUnit: "not_applicable", Status: "not_applicable"}
	}
	if cfg.Mode() != appconfig.ModeListen {
		return ServiceObservability{SystemdUnit: "not_applicable", Status: "not_applicable"}
	}
	return ServiceObservability{SystemdUnit: cfg.ResourceName() + ".service", Status: "unknown"}
}

func certificateState(cfg appconfig.Config) CertificateObservability {
	if cfg.PrivateClientAccessEnabled() {
		return CertificateObservability{
			Status:     "not_applicable",
			RenewTimer: "not_applicable",
		}
	}
	return CertificateObservability{
		Domains:    append([]string(nil), cfg.App.Domains...),
		Status:     "unknown",
		RenewTimer: cfg.ResourceName() + "-lego-renew.timer",
	}
}

func configDigest(cfg appconfig.Config) (string, error) {
	payload := configDigestPayload(cfg)
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal app config for exposure digest: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func configDigestPayload(cfg appconfig.Config) map[string]any {
	return map[string]any{
		"api_version": strings.TrimSpace(cfg.APIVersion),
		"app": map[string]any{
			"name":              strings.TrimSpace(cfg.App.Name),
			"domains":           canonicalDomains(cfg.App.Domains),
			"certificate_email": strings.TrimSpace(cfg.App.CertificateEmail),
			"acme_challenge":    strings.TrimSpace(cfg.App.ACMEChallenge),
			"listen":            strings.TrimSpace(cfg.App.Listen),
			"upstream":          strings.TrimSpace(cfg.App.Upstream),
		},
		"access": map[string]any{
			"access_mode":           strings.TrimSpace(string(cfg.Access.AccessMode)),
			"cidr_allowlist":        canonicalSortedStrings(cfg.Access.CIDRAllowlist),
			"public_risk_confirmed": cfg.Access.PublicRiskConfirmed,
			"browser_auth": map[string]any{
				"auth_basic_user_file": strings.TrimSpace(cfg.Access.BrowserAuth.AuthBasicUserFile),
				"managed": map[string]any{
					"credential_id":        strings.TrimSpace(cfg.Access.BrowserAuth.Managed.CredentialID),
					"htpasswd_path":        strings.TrimSpace(cfg.Access.BrowserAuth.Managed.HtpasswdPath),
					"username":             strings.TrimSpace(cfg.Access.BrowserAuth.Managed.Username),
					"password_fingerprint": strings.TrimSpace(cfg.Access.BrowserAuth.Managed.PasswordFingerprint),
				},
			},
			"origin_protection": map[string]any{
				"mode":                         strings.TrimSpace(string(cfg.Access.OriginProtection.Mode)),
				"edgeone_profile":              strings.TrimSpace(cfg.Access.OriginProtection.EdgeOneProfile),
				"direct_origin_risk_confirmed": cfg.Access.OriginProtection.DirectOriginRiskConfirmed,
			},
		},
		"service": map[string]any{
			"exec_start":        strings.TrimSpace(cfg.Service.ExecStart),
			"working_directory": strings.TrimSpace(cfg.Service.WorkingDirectory),
			"env_file":          strings.TrimSpace(cfg.Service.EnvFile),
		},
		"nginx": map[string]any{
			"client_max_body_size": cfg.Nginx.EffectiveClientMaxBodySize(),
			"http2":                cfg.Nginx.HTTP2Enabled(),
			"access_log":           strings.TrimSpace(cfg.Nginx.AccessLog),
			"error_log":            strings.TrimSpace(cfg.Nginx.ErrorLog),
			"goaccess": map[string]any{
				"enabled":              cfg.Nginx.GoAccess.Enabled,
				"language":             cfg.Nginx.GoAccess.EffectiveLanguage(),
				"log_format":           cfg.Nginx.GoAccess.EffectiveLogFormat(),
				"path":                 cfg.NginxGoAccessDashboardPath(),
				"websocket_path":       cfg.NginxGoAccessWebSocketPath(),
				"websocket_listen":     appconfig.EffectiveNginxGoAccessWebSocketListen(cfg.App.Name, cfg.Nginx.GoAccess),
				"auth_basic_user_file": strings.TrimSpace(cfg.Nginx.GoAccess.AuthBasicUserFile),
				"auth_cidr_allowlist":  canonicalSortedStrings(cfg.Nginx.GoAccess.AuthCIDRAllowlist),
			},
			"proxy": map[string]any{
				"connect_timeout":   strings.TrimSpace(cfg.Nginx.Proxy.ConnectTimeout),
				"read_timeout":      cfg.Nginx.Proxy.EffectiveReadTimeout(),
				"send_timeout":      cfg.Nginx.Proxy.EffectiveSendTimeout(),
				"buffering":         optionalBoolDigest(cfg.Nginx.Proxy.Buffering),
				"request_buffering": optionalBoolDigest(cfg.Nginx.Proxy.RequestBuffering),
			},
			"static_locations": staticLocationDigestPayload(cfg.Nginx.StaticLocations),
		},
		"realip": map[string]any{
			"profiles": realIPProfilesDigestPayload(cfg.RealIP.Profiles),
		},
		"dns01": map[string]any{
			"provider": strings.TrimSpace(cfg.DNS01.Provider),
			"env_file": strings.TrimSpace(cfg.DNS01.EnvFile),
		},
		"tailscale": map[string]any{
			"enabled_for_listen": cfg.Tailscale.EnabledForListen,
			"lanpanel_config":    strings.TrimSpace(cfg.Tailscale.LanpanelConfig),
			"login_server":       canonicalLoginServer(cfg.Tailscale.LoginServer),
			"hostname":           strings.TrimSpace(cfg.Tailscale.Hostname),
			"auth_key_file":      strings.TrimSpace(cfg.Tailscale.AuthKeyFile),
		},
	}
}

func canonicalDomains(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.TrimSuffix(value, ".")
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func canonicalSortedStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func canonicalLoginServer(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, "/")
	return strings.ToLower(value)
}

func optionalBoolDigest(value *bool) string {
	if value == nil {
		return "default"
	}
	if *value {
		return "true"
	}
	return "false"
}

func staticLocationDigestPayload(locations []appconfig.NginxStaticLocationConfig) []map[string]any {
	result := make([]map[string]any, 0, len(locations))
	for _, location := range locations {
		match := strings.TrimSpace(location.Match)
		if match == "" {
			match = "prefix"
		}
		result = append(result, map[string]any{
			"path":          strings.TrimSpace(location.Path),
			"match":         match,
			"alias":         strings.TrimSpace(location.Alias),
			"default_type":  strings.TrimSpace(location.DefaultType),
			"expires":       strings.TrimSpace(location.Expires),
			"cache_control": strings.TrimSpace(location.CacheControl),
			"try_files":     location.TryFiles,
			"gzip_static":   location.GzipStatic,
			"access_log":    optionalBoolDigest(location.AccessLog),
		})
	}
	return result
}

func realIPProfilesDigestPayload(profiles map[string]appconfig.RealIPProfileConfig) []map[string]any {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]map[string]any, 0, len(names))
	for _, name := range names {
		profile := profiles[name]
		result = append(result, map[string]any{
			"name":             strings.TrimSpace(name),
			"enabled":          optionalBoolDigest(profile.Enabled),
			"provider":         strings.TrimSpace(profile.Provider),
			"refresh_interval": profile.EffectiveRefreshInterval(),
			"edgeone": map[string]any{
				"zone_id":  strings.TrimSpace(profile.EdgeOne.ZoneID),
				"env_file": strings.TrimSpace(profile.EdgeOne.EnvFile),
			},
		})
	}
	return result
}

func defaultActivationPreview(operation domain.ExposurePlanOperation, entry ResourceExposureEntry) domain.ExposureActivationPreview {
	if entry.Access.AccessMode == domain.AccessModePrivateClient {
		return domain.ExposureActivationPreview{}
	}
	switch operation {
	case domain.ExposurePlanOperationCreateResource,
		domain.ExposurePlanOperationUpdateResource,
		domain.ExposurePlanOperationDeleteResource,
		domain.ExposurePlanOperationDeploy:
		return domain.ExposureActivationPreview{
			ReloadServices:        []string{"nginx.service"},
			CertificatesChanged:   append([]string(nil), entry.Access.PublicEntry.Domains...),
			PublicExposureChanged: true,
		}
	case domain.ExposurePlanOperationRealIPRefresh:
		return domain.ExposureActivationPreview{ReloadServices: []string{"nginx.service"}}
	case domain.ExposurePlanOperationBrowserAuthRotate:
		return domain.ExposureActivationPreview{}
	default:
		return domain.ExposureActivationPreview{}
	}
}

func summarize(entries []ResourceExposureEntry) ExposureSummary {
	summary := ExposureSummary{
		Total:        len(entries),
		ByAccessMode: map[domain.AccessMode]int{},
		RiskCounts:   map[domain.DiagnosticStatus]int{},
	}
	for _, mode := range []domain.AccessMode{
		domain.AccessModeBrowser,
		domain.AccessModePublic,
		domain.AccessModePrivateClient,
	} {
		summary.ByAccessMode[mode] = 0
	}
	for _, status := range []domain.DiagnosticStatus{
		domain.DiagnosticStatusPass,
		domain.DiagnosticStatusWarn,
		domain.DiagnosticStatusManual,
		domain.DiagnosticStatusUnknown,
		domain.DiagnosticStatusFail,
	} {
		summary.RiskCounts[status] = 0
	}
	for _, entry := range entries {
		summary.ByAccessMode[entry.Access.AccessMode]++
		summary.RiskCounts[riskStatus(entry)]++
	}
	return summary
}

func riskStatus(entry ResourceExposureEntry) domain.DiagnosticStatus {
	status := domain.DiagnosticStatusPass
	status = combineRiskStatus(status, diagnosticStatusFromString(entry.Protection.BrowserAuth.RuntimeReadable))
	status = combineRiskStatus(status, diagnosticStatusFromString(entry.Protection.BrowserAuth.MarkerPresent))
	for _, ref := range entry.Diagnostics {
		status = combineRiskStatus(status, ref.Status)
	}
	switch entry.Protection.OriginProtection.Status {
	case domain.OriginProtectionConfiguredFail:
		status = combineRiskStatus(status, domain.DiagnosticStatusFail)
	case domain.OriginProtectionConfiguredUnknown:
		status = combineRiskStatus(status, domain.DiagnosticStatusUnknown)
	case domain.OriginProtectionConfiguredManual:
		status = combineRiskStatus(status, domain.DiagnosticStatusManual)
	case domain.OriginProtectionNone:
		status = combineRiskStatus(status, domain.DiagnosticStatusWarn)
	}
	if entry.Access.AccessMode == domain.AccessModePublic && status == domain.DiagnosticStatusPass {
		status = domain.DiagnosticStatusWarn
	}
	return status
}

func combineRiskStatus(current domain.DiagnosticStatus, next domain.DiagnosticStatus) domain.DiagnosticStatus {
	switch next {
	case domain.DiagnosticStatusFail:
		return domain.DiagnosticStatusFail
	case domain.DiagnosticStatusUnknown:
		if current != domain.DiagnosticStatusFail {
			return domain.DiagnosticStatusUnknown
		}
	case domain.DiagnosticStatusManual:
		if current != domain.DiagnosticStatusFail && current != domain.DiagnosticStatusUnknown {
			return domain.DiagnosticStatusManual
		}
	case domain.DiagnosticStatusWarn:
		if current == domain.DiagnosticStatusPass {
			return domain.DiagnosticStatusWarn
		}
	}
	return current
}

func diagnosticStatusFromString(value string) domain.DiagnosticStatus {
	status, err := domain.ParseDiagnosticStatus(strings.TrimSpace(value))
	if err != nil || status == domain.DiagnosticStatusNotApplicable {
		return domain.DiagnosticStatusPass
	}
	return status
}

func browserAuthDiagnosticBlockers(entry ResourceExposureEntry) []domain.DiagnosticItem {
	if entry.Access.AccessMode != domain.AccessModeBrowser || entry.Protection.BrowserAuth.Status != "required" {
		return nil
	}
	checks := []struct {
		id      string
		value   string
		summary string
	}{
		{
			id:      "browser-auth-runtime-readable",
			value:   entry.Protection.BrowserAuth.RuntimeReadable,
			summary: "browser auth htpasswd file runtime readability is %s",
		},
		{
			id:      "browser-auth-marker-present",
			value:   entry.Protection.BrowserAuth.MarkerPresent,
			summary: "managed browser auth marker presence is %s",
		},
	}
	blockers := []domain.DiagnosticItem{}
	for _, check := range checks {
		status := diagnosticStatusFromString(check.value)
		if status != domain.DiagnosticStatusFail && status != domain.DiagnosticStatusUnknown {
			continue
		}
		blockers = append(blockers, domain.DiagnosticItem{
			ID:               check.id,
			Status:           status,
			Scope:            domain.DiagnosticScopeResource,
			ResourceID:       entry.Resource.ID,
			Severity:         domain.DiagnosticSeverityCritical,
			Summary:          fmt.Sprintf(check.summary, status),
			EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
			ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
			BlocksActivation: true,
			Redaction:        domain.RedactionNone,
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		})
	}
	return blockers
}

func validateOriginProtectionStatus(status domain.OriginProtectionStatus) error {
	switch status {
	case "",
		domain.OriginProtectionNone,
		domain.OriginProtectionConfiguredPass,
		domain.OriginProtectionConfiguredManual,
		domain.OriginProtectionConfiguredUnknown,
		domain.OriginProtectionConfiguredFail,
		domain.OriginProtectionNotApplicable:
		return nil
	default:
		return fmt.Errorf("origin protection status %q is not supported", status)
	}
}

func validateAppObservations(cfg appconfig.Config, observations AppObservations) error {
	if err := validateOriginProtectionObservation(cfg, observations.OriginProtectionStatus); err != nil {
		return err
	}
	if observations.RealIPTrustedCIDRCount < 0 {
		return fmt.Errorf("realip trusted CIDR count must not be negative")
	}
	if err := validateOptionalDiagnosticStatus("realip spoofing_rejection", observations.RealIPSpoofingRejection); err != nil {
		return err
	}
	if err := validateOptionalDiagnosticStatus("goaccess auth_basic", observations.GoAccessAuthBasicStatus); err != nil {
		return err
	}
	if err := validateOptionalDiagnosticStatus("browser auth runtime_readable", observations.BrowserAuthRuntimeStatus); err != nil {
		return err
	}
	if err := validateOptionalDiagnosticStatus("browser auth marker_present", observations.BrowserAuthMarkerStatus); err != nil {
		return err
	}
	referenceDigest := observations.OriginProtectionReferenceDigest
	if referenceDigest != strings.TrimSpace(referenceDigest) {
		return fmt.Errorf("origin protection reference digest must not include leading or trailing whitespace")
	}
	if referenceDigest != "" && referenceDigest != "not_applicable" && !isSHA256Digest(referenceDigest) {
		return fmt.Errorf("origin protection reference digest %q must be sha256:<64 lowercase hex characters>", referenceDigest)
	}
	return nil
}

func validateOriginProtectionObservation(cfg appconfig.Config, status domain.OriginProtectionStatus) error {
	if err := validateOriginProtectionStatus(status); err != nil {
		return err
	}
	switch cfg.Access.OriginProtection.Mode {
	case appconfig.OriginProtectionModeNone:
		switch status {
		case "", domain.OriginProtectionNone:
			return nil
		default:
			return fmt.Errorf("origin protection status %q is incompatible with none origin protection", status)
		}
	case appconfig.OriginProtectionModeEdgeOne:
		switch status {
		case "", domain.OriginProtectionConfiguredPass, domain.OriginProtectionConfiguredManual, domain.OriginProtectionConfiguredUnknown, domain.OriginProtectionConfiguredFail:
			return nil
		default:
			return fmt.Errorf("origin protection status %q is incompatible with edgeone origin protection", status)
		}
	default:
		return nil
	}
}

func validateOptionalDiagnosticStatus(label string, status domain.DiagnosticStatus) error {
	if status == "" {
		return nil
	}
	if _, err := domain.ParseDiagnosticStatus(string(status)); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func isSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validateDiagnosticRefs(refs []domain.DiagnosticRef) error {
	for i, ref := range refs {
		if strings.TrimSpace(ref.ID) == "" {
			return fmt.Errorf("diagnostics[%d].diagnostic_id is required", i)
		}
		if _, err := domain.ParseDiagnosticStatus(string(ref.Status)); err != nil {
			return fmt.Errorf("diagnostics[%d].status: %w", i, err)
		}
		if err := validateOptionalDiagnosticScope(ref.Scope); err != nil {
			return fmt.Errorf("diagnostics[%d].scope: %w", i, err)
		}
		if err := validateOptionalDiagnosticSeverity(ref.Severity); err != nil {
			return fmt.Errorf("diagnostics[%d].severity: %w", i, err)
		}
		if err := validateOptionalDiagnosticEvidenceSource(ref.EvidenceSource); err != nil {
			return fmt.Errorf("diagnostics[%d].evidence_source: %w", i, err)
		}
		if err := validateOptionalDiagnosticResponsibleParty(ref.ResponsibleParty); err != nil {
			return fmt.Errorf("diagnostics[%d].responsible_party: %w", i, err)
		}
		if err := validateOptionalRedaction(ref.Redaction); err != nil {
			return fmt.Errorf("diagnostics[%d].redaction: %w", i, err)
		}
		if err := validateRequiredRedactionStatus(ref.RedactionStatus); err != nil {
			return fmt.Errorf("diagnostics[%d].redaction_status: %w", i, err)
		}
	}
	return nil
}

func validateActivationRef(ref domain.ActivationRef) error {
	switch ref.Kind {
	case domain.ActivationRefNotApplicable:
		if strings.TrimSpace(ref.Path) != "" || strings.TrimSpace(ref.Digest) != "" {
			return fmt.Errorf("activation not_applicable ref must not include path or digest")
		}
	case domain.ActivationRefCheckpoint:
		if strings.TrimSpace(ref.Path) == "" {
			return fmt.Errorf("activation checkpoint ref path is required")
		}
		if !isSHA256Digest(ref.Digest) {
			return fmt.Errorf("activation checkpoint ref digest must be sha256:<64 lowercase hex characters>")
		}
	default:
		return fmt.Errorf("activation ref kind %q is not supported", ref.Kind)
	}
	return nil
}

func validateOptionalDiagnosticScope(scope domain.DiagnosticScope) error {
	if scope == "" {
		return nil
	}
	switch scope {
	case domain.DiagnosticScopeInstance,
		domain.DiagnosticScopeResource,
		domain.DiagnosticScopeService,
		domain.DiagnosticScopeCertificate,
		domain.DiagnosticScopeRealIP,
		domain.DiagnosticScopeHeadscale,
		domain.DiagnosticScopeGoAccess,
		domain.DiagnosticScopeExport:
		return nil
	default:
		return fmt.Errorf("diagnostic scope %q is not supported", scope)
	}
}

func validateOptionalDiagnosticSeverity(severity domain.DiagnosticSeverity) error {
	if severity == "" {
		return nil
	}
	switch severity {
	case domain.DiagnosticSeverityInfo,
		domain.DiagnosticSeverityLow,
		domain.DiagnosticSeverityMedium,
		domain.DiagnosticSeverityHigh,
		domain.DiagnosticSeverityCritical:
		return nil
	default:
		return fmt.Errorf("diagnostic severity %q is not supported", severity)
	}
}

func validateOptionalDiagnosticEvidenceSource(source domain.DiagnosticEvidenceSource) error {
	if source == "" {
		return nil
	}
	switch source {
	case domain.DiagnosticEvidenceConfig,
		domain.DiagnosticEvidenceRenderedFile,
		domain.DiagnosticEvidenceRuntimeProbe,
		domain.DiagnosticEvidenceProviderAPI,
		domain.DiagnosticEvidenceManual,
		domain.DiagnosticEvidenceCheckpoint:
		return nil
	default:
		return fmt.Errorf("diagnostic evidence source %q is not supported", source)
	}
}

func validateOptionalDiagnosticResponsibleParty(party domain.DiagnosticResponsibleParty) error {
	if party == "" {
		return nil
	}
	switch party {
	case domain.DiagnosticResponsibleLanPanel,
		domain.DiagnosticResponsibleLocalAdmin,
		domain.DiagnosticResponsibleDNSProvider,
		domain.DiagnosticResponsibleCloudProvider,
		domain.DiagnosticResponsibleAppOwner,
		domain.DiagnosticResponsibleExternalNetwork:
		return nil
	default:
		return fmt.Errorf("diagnostic responsible party %q is not supported", party)
	}
}

func validateOptionalRedaction(redaction domain.Redaction) error {
	if redaction == "" {
		return nil
	}
	switch redaction {
	case domain.RedactionNone,
		domain.RedactionSecret,
		domain.RedactionFingerprint:
		return nil
	default:
		return fmt.Errorf("redaction %q is not supported", redaction)
	}
}

func validateOptionalRedactionStatus(status domain.RedactionStatus) error {
	if status == "" {
		return nil
	}
	switch status {
	case domain.RedactionStatusRedacted,
		domain.RedactionStatusNoSensitiveData,
		domain.RedactionStatusBlockedSensitiveData:
		return nil
	default:
		return fmt.Errorf("redaction status %q is not supported", status)
	}
}

func validateRequiredRedactionStatus(status domain.RedactionStatus) error {
	if status == "" {
		return fmt.Errorf("redaction status is required")
	}
	return validateOptionalRedactionStatus(status)
}

func validateExposurePlanOperation(operation domain.ExposurePlanOperation) error {
	switch operation {
	case domain.ExposurePlanOperationCreateResource,
		domain.ExposurePlanOperationUpdateResource,
		domain.ExposurePlanOperationDeleteResource,
		domain.ExposurePlanOperationDeploy,
		domain.ExposurePlanOperationRealIPRefresh,
		domain.ExposurePlanOperationBrowserAuthRotate:
		return nil
	default:
		return fmt.Errorf("exposure plan operation %q is not supported", operation)
	}
}

func operationChangesExposureSurface(operation domain.ExposurePlanOperation) bool {
	return operation != domain.ExposurePlanOperationBrowserAuthRotate
}

func combineExposurePlanDecision(current domain.ExposurePlanDecision, next domain.ExposurePlanDecision) domain.ExposurePlanDecision {
	switch next {
	case domain.ExposurePlanDecisionFail:
		return domain.ExposurePlanDecisionFail
	case domain.ExposurePlanDecisionUnknown:
		if current != domain.ExposurePlanDecisionFail {
			return domain.ExposurePlanDecisionUnknown
		}
	case domain.ExposurePlanDecisionManual:
		if current != domain.ExposurePlanDecisionFail && current != domain.ExposurePlanDecisionUnknown {
			return domain.ExposurePlanDecisionManual
		}
	case domain.ExposurePlanDecisionWarn:
		if current == domain.ExposurePlanDecisionPass {
			return domain.ExposurePlanDecisionWarn
		}
	}
	return current
}

func diagnosticStatusPlanDecision(status domain.DiagnosticStatus) domain.ExposurePlanDecision {
	switch status {
	case domain.DiagnosticStatusFail:
		return domain.ExposurePlanDecisionFail
	case domain.DiagnosticStatusUnknown:
		return domain.ExposurePlanDecisionUnknown
	case domain.DiagnosticStatusManual:
		return domain.ExposurePlanDecisionManual
	case domain.DiagnosticStatusWarn:
		return domain.ExposurePlanDecisionWarn
	default:
		return domain.ExposurePlanDecisionPass
	}
}

func originProtectionPlanDecisionStatus(status domain.OriginProtectionStatus) domain.ExposurePlanDecision {
	switch status {
	case domain.OriginProtectionConfiguredFail:
		return domain.ExposurePlanDecisionFail
	case domain.OriginProtectionConfiguredUnknown:
		return domain.ExposurePlanDecisionUnknown
	default:
		return domain.ExposurePlanDecisionManual
	}
}

func originProtectionDiagnosticStatus(status domain.OriginProtectionStatus) domain.DiagnosticStatus {
	switch status {
	case domain.OriginProtectionConfiguredFail:
		return domain.DiagnosticStatusFail
	case domain.OriginProtectionConfiguredUnknown:
		return domain.DiagnosticStatusUnknown
	default:
		return domain.DiagnosticStatusManual
	}
}

func exposurePlanID(createdAt time.Time, resourceID string) string {
	input := createdAt.UTC().Format(time.RFC3339Nano) + "\x00" + strings.TrimSpace(resourceID)
	sum := sha256.Sum256([]byte(input))
	return "plan_" + createdAt.UTC().Format("20060102T150405.000000000Z") + "_" + hex.EncodeToString(sum[:4])
}

func compact(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
