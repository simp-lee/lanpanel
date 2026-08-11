// Package domain defines shared typed contracts. DecodeInstallation is the
// sole installation-owned Community GA schema and rejects every other shape.
package domain

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	InstanceSchemaVersion     = "lanpanel.instance.v1"
	ExposurePlanSchemaVersion = "lanpanel.exposure_plan.v1"
	HostHealthSchemaVersion   = "lanpanel.host_health.v1"
	JobRecordSchemaVersion    = "lanpanel.job.v1"
	JobEventSchemaVersion     = "lanpanel.job_event.v1"
	ResourceExposureSchemaV1  = "lanpanel.exposure.v1"
)

type DiagnosticStatus string

const (
	DiagnosticStatusPass          DiagnosticStatus = "pass"
	DiagnosticStatusWarn          DiagnosticStatus = "warn"
	DiagnosticStatusManual        DiagnosticStatus = "manual"
	DiagnosticStatusUnknown       DiagnosticStatus = "unknown"
	DiagnosticStatusFail          DiagnosticStatus = "fail"
	DiagnosticStatusNotApplicable DiagnosticStatus = "not_applicable"
)

type OriginProtectionStatus string

const (
	OriginProtectionNone              OriginProtectionStatus = "none"
	OriginProtectionConfiguredPass    OriginProtectionStatus = "configured_pass"
	OriginProtectionConfiguredManual  OriginProtectionStatus = "configured_manual"
	OriginProtectionConfiguredUnknown OriginProtectionStatus = "configured_unknown"
	OriginProtectionConfiguredFail    OriginProtectionStatus = "configured_fail"
	OriginProtectionNotApplicable     OriginProtectionStatus = "not_applicable"
)

type ResourceType string

const (
	ResourceTypeHTTPApp               ResourceType = "http_app"
	ResourceTypeWebSocketApp          ResourceType = "websocket_app"
	ResourceTypePrivateEndpoint       ResourceType = "private_endpoint"
	ResourceTypePrivateHost           ResourceType = "private_host"
	ResourceTypePrivateNetworkService ResourceType = "private_network_service"
)

type AccessMode string

const (
	AccessModeBrowser       AccessMode = "browser"
	AccessModePublic        AccessMode = "public"
	AccessModePrivateClient AccessMode = "private_client"
)

type ActivationRefKind string

const (
	ActivationRefCheckpoint    ActivationRefKind = "checkpoint"
	ActivationRefNotApplicable ActivationRefKind = "not_applicable"
)

type JobKind string

const (
	JobKindConfigSave        JobKind = "config_save"
	JobKindDeploy            JobKind = "deploy"
	JobKindVerify            JobKind = "verify"
	JobKindStatus            JobKind = "status"
	JobKindAppInit           JobKind = "app_init"
	JobKindAppConfigSave     JobKind = "app_config_save"
	JobKindAppVerify         JobKind = "app_verify"
	JobKindAppDeploy         JobKind = "app_deploy"
	JobKindRealIPDiagnostics JobKind = "realip_diagnostics"
	JobKindRealIPRefresh     JobKind = "realip_refresh"
	JobKindRealIPValidateRef JobKind = "realip_validate_reference"
	JobKindPreAuthKeyCreate  JobKind = "preauth_key_create"
	JobKindBrowserAuthCreate JobKind = "browser_auth_create"
	JobKindBrowserAuthRotate JobKind = "browser_auth_rotate"
	JobKindBrowserAuthDelete JobKind = "browser_auth_delete"
	JobKindDependencyUpload  JobKind = "dependency_upload"
)

type JobStatus string

const (
	JobStatusQueued      JobStatus = "queued"
	JobStatusRunning     JobStatus = "running"
	JobStatusSucceeded   JobStatus = "succeeded"
	JobStatusFailed      JobStatus = "failed"
	JobStatusInterrupted JobStatus = "interrupted"
	JobStatusUnknown     JobStatus = "unknown"
)

type Redaction string

const (
	RedactionNone        Redaction = "none"
	RedactionSecret      Redaction = "secret"
	RedactionFingerprint Redaction = "fingerprint"
)

type RedactionStatus string

const (
	RedactionStatusRedacted             RedactionStatus = "redacted"
	RedactionStatusNoSensitiveData      RedactionStatus = "no_sensitive_data"
	RedactionStatusBlockedSensitiveData RedactionStatus = "blocked_sensitive_data"
)

type ResultField struct {
	Label           string          `json:"label"`
	Value           string          `json:"value"`
	Redaction       Redaction       `json:"redaction,omitempty"`
	RedactionStatus RedactionStatus `json:"redaction_status,omitempty"`
}

type ActorSource string

const (
	ActorSourceUI  ActorSource = "ui"
	ActorSourceCLI ActorSource = "cli"
)

type Actor struct {
	Source                  ActorSource `json:"source"`
	EffectiveUID            int         `json:"effective_uid"`
	EffectiveUser           string      `json:"effective_user"`
	ProcessID               int         `json:"process_id,omitempty"`
	SessionIDFingerprint    string      `json:"session_id_fingerprint,omitempty"`
	RequestSource           string      `json:"request_source,omitempty"`
	StartupTokenFingerprint string      `json:"startup_token_fingerprint,omitempty"`
}

type DiagnosticScope string

const (
	DiagnosticScopeInstance    DiagnosticScope = "instance"
	DiagnosticScopeResource    DiagnosticScope = "resource"
	DiagnosticScopeService     DiagnosticScope = "service"
	DiagnosticScopeCertificate DiagnosticScope = "certificate"
	DiagnosticScopeRealIP      DiagnosticScope = "realip"
	DiagnosticScopeHeadscale   DiagnosticScope = "headscale"
	DiagnosticScopeGoAccess    DiagnosticScope = "goaccess"
	DiagnosticScopeExport      DiagnosticScope = "export"
)

type DiagnosticSeverity string

const (
	DiagnosticSeverityInfo     DiagnosticSeverity = "info"
	DiagnosticSeverityLow      DiagnosticSeverity = "low"
	DiagnosticSeverityMedium   DiagnosticSeverity = "medium"
	DiagnosticSeverityHigh     DiagnosticSeverity = "high"
	DiagnosticSeverityCritical DiagnosticSeverity = "critical"
)

type DiagnosticEvidenceSource string

const (
	DiagnosticEvidenceConfig       DiagnosticEvidenceSource = "config"
	DiagnosticEvidenceRenderedFile DiagnosticEvidenceSource = "rendered_file"
	DiagnosticEvidenceRuntimeProbe DiagnosticEvidenceSource = "runtime_probe"
	DiagnosticEvidenceProviderAPI  DiagnosticEvidenceSource = "provider_api"
	DiagnosticEvidenceManual       DiagnosticEvidenceSource = "manual_confirmation"
	DiagnosticEvidenceCheckpoint   DiagnosticEvidenceSource = "checkpoint"
)

type DiagnosticResponsibleParty string

const (
	DiagnosticResponsibleLanPanel        DiagnosticResponsibleParty = "lanpanel"
	DiagnosticResponsibleLocalAdmin      DiagnosticResponsibleParty = "local_admin"
	DiagnosticResponsibleDNSProvider     DiagnosticResponsibleParty = "dns_provider"
	DiagnosticResponsibleCloudProvider   DiagnosticResponsibleParty = "cloud_provider"
	DiagnosticResponsibleAppOwner        DiagnosticResponsibleParty = "app_owner"
	DiagnosticResponsibleExternalNetwork DiagnosticResponsibleParty = "external_network"
)

type DiagnosticRef struct {
	ID               string                     `json:"diagnostic_id"`
	Status           DiagnosticStatus           `json:"status"`
	Scope            DiagnosticScope            `json:"scope,omitempty"`
	ResourceID       string                     `json:"resource_id,omitempty"`
	Severity         DiagnosticSeverity         `json:"severity,omitempty"`
	EvidenceSource   DiagnosticEvidenceSource   `json:"evidence_source,omitempty"`
	ResponsibleParty DiagnosticResponsibleParty `json:"responsible_party,omitempty"`
	BlocksActivation bool                       `json:"blocking_activation,omitempty"`
	Redaction        Redaction                  `json:"redaction,omitempty"`
	RedactionStatus  RedactionStatus            `json:"redaction_status"`
}

type DiagnosticItem struct {
	ID               string                     `json:"diagnostic_id"`
	Title            string                     `json:"title"`
	Status           DiagnosticStatus           `json:"status"`
	Scope            DiagnosticScope            `json:"scope,omitempty"`
	ResourceID       string                     `json:"resource_id,omitempty"`
	Severity         DiagnosticSeverity         `json:"severity,omitempty"`
	Summary          string                     `json:"summary"`
	EvidenceSource   DiagnosticEvidenceSource   `json:"evidence_source,omitempty"`
	ResponsibleParty DiagnosticResponsibleParty `json:"responsible_party,omitempty"`
	BlocksActivation bool                       `json:"blocking_activation,omitempty"`
	Remediation      []string                   `json:"remediation,omitempty"`
	Redaction        Redaction                  `json:"redaction,omitempty"`
	RedactionStatus  RedactionStatus            `json:"redaction_status"`
}

type ResourceTarget struct {
	TargetKind          ResourceTargetKind     `json:"target_kind"`
	Listen              ListenResourceTarget   `json:"listen,omitempty"`
	Upstream            UpstreamResourceTarget `json:"upstream,omitempty"`
	PrivateResource     PrivateResourceTarget  `json:"private_resource,omitempty"`
	NotApplicableFields []string               `json:"not_applicable_fields,omitempty"`
}

type ResourceTargetKind string

const (
	ResourceTargetKindListen          ResourceTargetKind = "listen"
	ResourceTargetKindUpstream        ResourceTargetKind = "upstream"
	ResourceTargetKindPrivateResource ResourceTargetKind = "private_resource"
)

type ListenResourceTarget struct {
	Address     string `json:"address,omitempty"`
	Port        int    `json:"port,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

type UpstreamResourceTarget struct {
	URL       string `json:"url,omitempty"`
	TailnetIP string `json:"tailnet_ip,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}

type PrivateResourceTarget struct {
	DNSNames   []string `json:"dns_names,omitempty"`
	NodeIDs    []string `json:"node_ids,omitempty"`
	TailnetIPs []string `json:"tailnet_ips,omitempty"`
	Ports      []string `json:"ports,omitempty"`
}

type ResourceOwnerScope string

const (
	ResourceOwnerScopeLocalInstance ResourceOwnerScope = "local_instance"
)

type ResourceState string

const (
	ResourceStateDraft   ResourceState = "draft"
	ResourceStatePlanned ResourceState = "planned"
	ResourceStateActive  ResourceState = "active"
	ResourceStateFailed  ResourceState = "failed"
	ResourceStateDeleted ResourceState = "deleted"
)

type ResourceConfigRef struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type Resource struct {
	ID            string             `json:"resource_id"`
	Type          ResourceType       `json:"resource_type"`
	Name          string             `json:"name"`
	CanonicalName string             `json:"canonical_name"`
	OwnerScope    ResourceOwnerScope `json:"owner_scope"`
	ConfigRef     ResourceConfigRef  `json:"config_ref"`
	State         ResourceState      `json:"state"`
	CreatedAt     string             `json:"created_at"`
	UpdatedAt     string             `json:"updated_at"`
}

type AccessSurface struct {
	AccessMode          AccessMode           `json:"access_mode"`
	PublicEntry         PublicEntry          `json:"public_entry"`
	PrivateEntry        PrivateEntry         `json:"private_entry"`
	RiskLabel           AccessRiskLabel      `json:"risk_label"`
	ManualConfirmations []ManualConfirmation `json:"manual_confirmations,omitempty"`
}

type PublicEntry struct {
	Status              PublicEntryStatus `json:"status"`
	Domains             []string          `json:"domains"`
	TLS                 string            `json:"tls"`
	NginxSite           string            `json:"nginx_site"`
	NotApplicableFields []string          `json:"not_applicable_fields,omitempty"`
}

type PublicEntryStatus string

const (
	PublicEntryEnabled       PublicEntryStatus = "enabled"
	PublicEntryNotApplicable PublicEntryStatus = "not_applicable"
)

type PrivateEntry struct {
	Status          PrivateEntryStatus `json:"status"`
	MagicDNSNames   []string           `json:"magic_dns_names,omitempty"`
	DNSExtraRecords []string           `json:"dns_extra_records,omitempty"`
}

type PrivateEntryStatus string

const (
	PrivateEntryEnabled       PrivateEntryStatus = "enabled"
	PrivateEntryDisabled      PrivateEntryStatus = "disabled"
	PrivateEntryNotApplicable PrivateEntryStatus = "not_applicable"
)

type AccessRiskLabel string

const (
	AccessRiskPrivateOnly         AccessRiskLabel = "private_only"
	AccessRiskBrowserAuthRequired AccessRiskLabel = "browser_auth_required"
	AccessRiskPublicInternet      AccessRiskLabel = "public_internet"
)

type ManualConfirmation struct {
	ConfirmationID string `json:"confirmation_id"`
	Reason         string `json:"reason"`
	Actor          Actor  `json:"actor"`
	ConfirmedAt    string `json:"confirmed_at"`
}

func ManualConfirmationReason(confirmation string) (string, error) {
	switch strings.TrimSpace(confirmation) {
	case "public-app-risk":
		return "public_exposure_confirmed", nil
	case "direct-origin-risk", "origin-protection-manual":
		return "origin_firewall_confirmed", nil
	default:
		return "", fmt.Errorf("manual confirmation %q has no audit reason", confirmation)
	}
}

func ValidateManualConfirmationRecords(confirmations []string, records []ManualConfirmation) error {
	requiredReasons := map[string]int{}
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation == "" {
			continue
		}
		reason, err := ManualConfirmationReason(confirmation)
		if err != nil {
			return err
		}
		requiredReasons[reason]++
	}
	for _, record := range records {
		if strings.TrimSpace(record.ConfirmationID) == "" {
			return fmt.Errorf("manual confirmation record is missing confirmation_id")
		}
		if strings.TrimSpace(record.ConfirmedAt) == "" {
			return fmt.Errorf("manual confirmation record %q is missing confirmed_at", record.ConfirmationID)
		}
		if record.Actor.Source == "" {
			return fmt.Errorf("manual confirmation record %q is missing actor source", record.ConfirmationID)
		}
		reason := strings.TrimSpace(record.Reason)
		if requiredReasons[reason] == 0 {
			return fmt.Errorf("manual confirmation record %q has unexpected reason %q", record.ConfirmationID, reason)
		}
		requiredReasons[reason]--
	}
	for reason, count := range requiredReasons {
		if count > 0 {
			return fmt.Errorf("manual confirmation record missing reason %q", reason)
		}
	}
	return nil
}

type ActivationRef struct {
	Kind   ActivationRefKind `json:"kind"`
	Path   string            `json:"path,omitempty"`
	Digest string            `json:"digest,omitempty"`
}

type ExposurePlanDecision string

const (
	ExposurePlanDecisionPass    ExposurePlanDecision = "pass"
	ExposurePlanDecisionWarn    ExposurePlanDecision = "warn"
	ExposurePlanDecisionManual  ExposurePlanDecision = "manual"
	ExposurePlanDecisionUnknown ExposurePlanDecision = "unknown"
	ExposurePlanDecisionFail    ExposurePlanDecision = "fail"
)

type ExposurePlanOperation string

const (
	ExposurePlanOperationCreateResource    ExposurePlanOperation = "create_resource"
	ExposurePlanOperationUpdateResource    ExposurePlanOperation = "update_resource"
	ExposurePlanOperationDeleteResource    ExposurePlanOperation = "delete_resource"
	ExposurePlanOperationDeploy            ExposurePlanOperation = "deploy"
	ExposurePlanOperationRealIPRefresh     ExposurePlanOperation = "realip_refresh"
	ExposurePlanOperationBrowserAuthRotate ExposurePlanOperation = "browser_auth_rotate"
)

type ExposurePlanDecisionSummary struct {
	Status                ExposurePlanDecision `json:"status"`
	Blockers              []string             `json:"blockers,omitempty"`
	RequiredConfirmations []string             `json:"required_confirmations,omitempty"`
}

type ExposureActivationPreview struct {
	ReloadServices        []string `json:"reload_services,omitempty"`
	CertificatesChanged   []string `json:"certificates_changed,omitempty"`
	PublicExposureChanged bool     `json:"public_exposure_changed"`
}

type ExposurePlan struct {
	SchemaVersion      string                      `json:"schema_version"`
	PlanID             string                      `json:"plan_id"`
	CreatedAt          time.Time                   `json:"created_at"`
	Actor              Actor                       `json:"actor"`
	Operation          ExposurePlanOperation       `json:"operation"`
	ResourcesChanged   []string                    `json:"resources_changed"`
	ModifiedPaths      []string                    `json:"modified_paths,omitempty"`
	BeforeDigest       string                      `json:"before_digest"`
	AfterDigest        string                      `json:"after_digest"`
	Decision           ExposurePlanDecisionSummary `json:"decision"`
	ActivationPreview  ExposureActivationPreview   `json:"activation_preview"`
	Resource           Resource                    `json:"resource"`
	Access             AccessSurface               `json:"access"`
	OriginProtection   OriginProtectionStatus      `json:"origin_protection"`
	DiagnosticBlockers []DiagnosticItem            `json:"diagnostic_blockers,omitempty"`
}

type HostHealthFact struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type HostHealthHost struct {
	OS               string                       `json:"os"`
	CPU              HostHealthCPU                `json:"cpu"`
	Memory           HostHealthMemory             `json:"memory"`
	Disks            []HostHealthDisk             `json:"disks"`
	NetworkAddresses []HostHealthNetworkAddresses `json:"network_addresses"`
}

type HostHealthCPU struct {
	Model        string `json:"model"`
	LogicalCores int    `json:"logical_cores"`
	Load         string `json:"load"`
}

type HostHealthMemory struct {
	TotalBytes     int64   `json:"total_bytes"`
	AvailableBytes int64   `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
}

type HostHealthDisk struct {
	Mountpoint   string  `json:"mountpoint"`
	FSType       string  `json:"fs_type"`
	TotalBytes   int64   `json:"total_bytes"`
	UsedBytes    int64   `json:"used_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

type HostHealthNetworkAddresses struct {
	Interface string   `json:"interface"`
	Addresses []string `json:"addresses"`
}

type HostHealthChecks struct {
	DNS             []DiagnosticRef          `json:"dns"`
	Ports           []DiagnosticRef          `json:"ports"`
	PortListeners   []HostHealthPortListener `json:"port_listeners"`
	AptDpkgSystemd  []DiagnosticRef          `json:"apt_dpkg_systemd"`
	NginxConfigTest []DiagnosticRef          `json:"nginx_config_test"`
	Certificates    []DiagnosticRef          `json:"certificates"`
	PublicPreflight []DiagnosticRef          `json:"public_preflight_80_443_3478"`
}

type HostHealthPortListener struct {
	Protocol     string `json:"protocol"`
	LocalAddress string `json:"local_address"`
	Port         int    `json:"port"`
}

type HostHealthCertificate struct {
	Domain       string `json:"domain"`
	NotAfter     string `json:"not_after"`
	DiagnosticID string `json:"diagnostic_id"`
}

type HostHealthAction string

const (
	HostHealthActionOpenDiagnostics            HostHealthAction = "open_diagnostics"
	HostHealthActionOpenCertificatesNginx      HostHealthAction = "open_certificates_nginx"
	HostHealthActionOpenServiceStatus          HostHealthAction = "open_service_status"
	HostHealthActionOpenVerifyJob              HostHealthAction = "open_verify_job"
	HostHealthActionOpenDeployJob              HostHealthAction = "open_deploy_job"
	HostHealthActionEditSystemSettings         HostHealthAction = "edit_system_settings"
	HostHealthActionPackageManagerOperation    HostHealthAction = "package_manager_operation"
	HostHealthActionArbitrarySystemdManagement HostHealthAction = "arbitrary_systemd_management"
	HostHealthActionArbitraryNginxEdit         HostHealthAction = "arbitrary_nginx_edit"
	HostHealthActionDiskCleanup                HostHealthAction = "disk_cleanup"
	HostHealthActionNetworkConfigurationChange HostHealthAction = "network_configuration_change"
)

type HostHealthSummary struct {
	SchemaVersion    string                  `json:"schema_version"`
	GeneratedAt      string                  `json:"generated_at"`
	Source           string                  `json:"source"`
	Host             HostHealthHost          `json:"host"`
	Checks           HostHealthChecks        `json:"checks"`
	Certificates     []HostHealthCertificate `json:"certificates,omitempty"`
	AllowedActions   []HostHealthAction      `json:"allowed_actions"`
	ForbiddenActions []HostHealthAction      `json:"forbidden_actions"`
	RedactionStatus  RedactionStatus         `json:"redaction_status"`
}

type JobRecord struct {
	SchemaVersion     string          `json:"schema_version"`
	ID                string          `json:"job_id"`
	Kind              JobKind         `json:"kind"`
	Status            JobStatus       `json:"status"`
	Actor             Actor           `json:"actor"`
	CreatedAt         time.Time       `json:"created_at"`
	StartedAt         OptionalTime    `json:"started_at"`
	CompletedAt       OptionalTime    `json:"completed_at"`
	ResourceIDs       []string        `json:"resource_ids,omitempty"`
	CheckpointRef     ActivationRef   `json:"checkpoint_ref"`
	ModifiedPaths     []string        `json:"modified_paths,omitempty"`
	RetryCommand      string          `json:"retry_command,omitempty"`
	ConfigSnapshotRef string          `json:"config_snapshot_ref,omitempty"`
	ResultSummary     string          `json:"result_summary,omitempty"`
	ErrorSummary      string          `json:"error_summary,omitempty"`
	RedactionStatus   RedactionStatus `json:"redaction_status"`
	ContainsSecret    bool            `json:"contains_secret"`
	AuditEventRefs    []string        `json:"audit_event_refs,omitempty"`
}

type OptionalTime struct {
	Time time.Time
}

func NewOptionalTime(value time.Time) OptionalTime {
	return OptionalTime{Time: value.UTC()}
}

func (value OptionalTime) IsZero() bool {
	return value.Time.IsZero()
}

func (value OptionalTime) MarshalJSON() ([]byte, error) {
	if value.Time.IsZero() {
		return []byte(`"not_applicable"`), nil
	}
	return json.Marshal(value.Time.UTC())
}

func (value *OptionalTime) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == "not_applicable" {
		value.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return fmt.Errorf("optional time must be RFC3339 or not_applicable: %w", err)
	}
	value.Time = parsed.UTC()
	return nil
}

func ParseDiagnosticStatus(value string) (DiagnosticStatus, error) {
	switch DiagnosticStatus(value) {
	case DiagnosticStatusPass:
		return DiagnosticStatusPass, nil
	case DiagnosticStatusWarn:
		return DiagnosticStatusWarn, nil
	case DiagnosticStatusManual:
		return DiagnosticStatusManual, nil
	case DiagnosticStatusUnknown:
		return DiagnosticStatusUnknown, nil
	case DiagnosticStatusFail:
		return DiagnosticStatusFail, nil
	case DiagnosticStatusNotApplicable:
		return DiagnosticStatusNotApplicable, nil
	default:
		return "", fmt.Errorf("diagnostic status %q is not supported", value)
	}
}

func NotApplicableActivationRef() ActivationRef {
	return ActivationRef{Kind: ActivationRefNotApplicable}
}
