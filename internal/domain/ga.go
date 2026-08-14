package domain

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

const InstallationSchemaVersion = "lanpanel.installation.ga.v1"

type LifecycleState string

const (
	LifecycleActive   LifecycleState = "active"
	LifecycleDeleting LifecycleState = "deleting"
)

type AppTargetKind string

const (
	AppTargetLocalHTTP   AppTargetKind = "local_http"
	AppTargetTailnetHTTP AppTargetKind = "tailnet_http"
)

type LocalEndpointKind string

const (
	LocalEndpointUnixSocketActivation LocalEndpointKind = "unix_socket_activation"
	LocalEndpointRelayUnix            LocalEndpointKind = "relay_unix"
	LocalEndpointTCPSocketActivation  LocalEndpointKind = "tcp_socket_activation"
)

type PublicationKind string

const (
	PublicationDomainHTTPS   PublicationKind = "domain_https"
	PublicationTemporaryHTTP PublicationKind = "temporary_ip_http"
)

type AppAccessMode string

const (
	AppAccessPublic             AppAccessMode = "public"
	AppAccessApplicationManaged AppAccessMode = "application_managed"
	AppAccessBasic              AppAccessMode = "basic"
)

type PublicationState string

const (
	PublicationPublished   PublicationState = "published"
	PublicationUnpublished PublicationState = "unpublished"
	PublicationActivating  PublicationState = "activating"
)

type ProcessRequestedState string

const (
	ProcessRequestedRunning ProcessRequestedState = "running"
	ProcessRequestedStopped ProcessRequestedState = "stopped"
)

type OperationResult string

const (
	OperationSucceeded   OperationResult = "succeeded"
	OperationFailed      OperationResult = "failed"
	OperationPartial     OperationResult = "partial"
	OperationInterrupted OperationResult = "interrupted"
	OperationUnknown     OperationResult = "unknown"
)

type PrerequisiteCode string

const (
	PrerequisiteHeadscaleNotConfigured       PrerequisiteCode = "headscale_not_configured"
	PrerequisiteConnectorRequired            PrerequisiteCode = "connector_required"
	PrerequisiteOSProfileLiveUnqualified     PrerequisiteCode = "os_profile_live_unqualified"
	PrerequisiteDependencyTransitionRequired PrerequisiteCode = "dependency_transition_required"
)

type OperationCode string

type OperationTargetKind string

const (
	OperationTargetInstallation  OperationTargetKind = "installation"
	OperationTargetResource      OperationTargetKind = "resource"
	OperationTargetCredential    OperationTargetKind = "credential"
	OperationTargetHeadscaleUser OperationTargetKind = "headscale_user"
	OperationTargetPreauthKey    OperationTargetKind = "preauth_key"
	OperationTargetDevice        OperationTargetKind = "device"
	OperationTargetJob           OperationTargetKind = "job"
)

type OperationTarget struct {
	Kind OperationTargetKind `json:"kind"`
	ID   string              `json:"id,omitempty"`
}

const (
	OperationInstanceConfigCreate     OperationCode = "instance_config_create"
	OperationInstanceConfigUpdate     OperationCode = "instance_config_update"
	OperationValidate                 OperationCode = "validate"
	OperationPlan                     OperationCode = "plan"
	OperationDeploy                   OperationCode = "deploy"
	OperationStatus                   OperationCode = "status"
	OperationDiagnostics              OperationCode = "diagnostics"
	OperationConfigurationExport      OperationCode = "configuration_export"
	OperationAdminTokenRotate         OperationCode = "admin_token_rotate"
	OperationHeadscaleReissue         OperationCode = "headscale_certificate_reissue"
	OperationDependencyUpload         OperationCode = "dependency_upload"
	OperationDependencyImport         OperationCode = "dependency_import"
	OperationMaintenance              OperationCode = "maintenance"
	OperationBackupEnter              OperationCode = "backup_enter"
	OperationBackupPreparingAbort     OperationCode = "backup_preparing_abort"
	OperationBackupExit               OperationCode = "backup_exit"
	OperationRestoreEvidenceImport    OperationCode = "restore_evidence_import"
	OperationRestoreCutover           OperationCode = "restore_cutover"
	OperationConnectorVerify          OperationCode = "connector_verify"
	OperationConnectorAuthKeyImport   OperationCode = "connector_auth_key_import"
	OperationConnectorAuthKeyAdopt    OperationCode = "connector_auth_key_adopt"
	OperationConnectorAuthKeyDiscard  OperationCode = "connector_auth_key_discard"
	OperationConnectorLogin           OperationCode = "connector_login"
	OperationConnectorDisconnect      OperationCode = "connector_disconnect"
	OperationConnectorRebind          OperationCode = "connector_rebind"
	OperationResourceCreate           OperationCode = "resource_create"
	OperationResourceUpdate           OperationCode = "resource_update"
	OperationResourceDelete           OperationCode = "resource_delete"
	OperationPublish                  OperationCode = "publish"
	OperationUnpublish                OperationCode = "unpublish"
	OperationCloseAll                 OperationCode = "close_all"
	OperationProcessStart             OperationCode = "process_start"
	OperationProcessStop              OperationCode = "process_stop"
	OperationUnpublishAndStop         OperationCode = "unpublish_and_stop"
	OperationHeadscaleUserCreate      OperationCode = "headscale_user_create"
	OperationHeadscaleUserList        OperationCode = "headscale_user_list"
	OperationPreauthKeyCreate         OperationCode = "preauth_key_create"
	OperationPreauthKeyList           OperationCode = "preauth_key_list"
	OperationPreauthKeyRevoke         OperationCode = "preauth_key_revoke"
	OperationDeviceList               OperationCode = "device_list"
	OperationDeviceExpire             OperationCode = "device_expire"
	OperationManagedBasicCreate       OperationCode = "managed_basic_create"
	OperationManagedBasicRotate       OperationCode = "managed_basic_rotate"
	OperationManagedBasicDelete       OperationCode = "managed_basic_delete"
	OperationStaticRootRegister       OperationCode = "static_root_register"
	OperationExternalHTPasswdRegister OperationCode = "external_htpasswd_register"
	OperationEdgeOneDiagnostics       OperationCode = "edgeone_diagnostics"
	OperationEdgeOneRefresh           OperationCode = "edgeone_refresh"
	OperationJobList                  OperationCode = "job_list"
	OperationJobDetail                OperationCode = "job_detail"
	OperationSessionLogout            OperationCode = "session_logout"
)

type Installation struct {
	SchemaVersion  string              `json:"schema_version"`
	InstallationID string              `json:"installation_id"`
	Management     ManagementAuthority `json:"management"`
	Headscale      *HeadscaleDomain    `json:"headscale,omitempty"`
	Connector      *TailnetConnector   `json:"connector,omitempty"`
	Credentials    []Credential        `json:"credentials,omitempty"`
	StaticRoots    []StaticContentRoot `json:"static_roots,omitempty"`
	ManagedPaths   []string            `json:"managed_paths,omitempty"`
	Resources      []AppResource       `json:"resources,omitempty"`
}

type ManagementAuthority struct {
	Address      string   `json:"address"`
	Port         uint16   `json:"port"`
	ManagedPaths []string `json:"managed_paths,omitempty"`
}

type HeadscaleDomain struct {
	ID                string   `json:"id"`
	ControlDomain     string   `json:"control_domain"`
	MagicDNSNamespace string   `json:"magicdns_namespace"`
	ManagedPaths      []string `json:"managed_paths,omitempty"`
}

type TailnetConnector struct {
	ID           string   `json:"id"`
	LoginServer  string   `json:"login_server"`
	ManagedPaths []string `json:"managed_paths,omitempty"`
}

type Credential struct {
	ID              string `json:"id"`
	Kind            string `json:"kind,omitempty"`
	OwnerResourceID string `json:"owner_resource_id,omitempty"`
	Username        string `json:"username,omitempty"`
	ManagedPath     string `json:"managed_path,omitempty"`
	ExternalPath    string `json:"external_path,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`
}
type StaticContentRoot struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	Device      uint64 `json:"device"`
}
type StaticMapping struct {
	URLPath      string `json:"url_path"`
	RelativePath string `json:"relative_path"`
	Directory    bool   `json:"directory"`
	Anonymous    bool   `json:"anonymous,omitempty"`
}

type AppResource struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Lifecycle           LifecycleState    `json:"lifecycle"`
	CurrentConfigDigest string            `json:"current_config_digest"`
	Target              AppTarget         `json:"target"`
	Publication         AppPublication    `json:"publication"`
	PublicationRecord   PublicationRecord `json:"publication_record"`
	ManagedProcess      *ManagedProcess   `json:"managed_process,omitempty"`
	CredentialIDs       []string          `json:"credential_ids,omitempty"`
	ManagedPaths        []string          `json:"managed_paths,omitempty"`
}

type AppTarget struct {
	Kind                AppTargetKind      `json:"kind"`
	ReadinessPath       string             `json:"readiness_path"`
	AllowedHTTPStatuses []uint16           `json:"allowed_http_statuses"`
	WebSocket           WebSocketReadiness `json:"websocket"`
	LocalHTTP           *LocalHTTPTarget   `json:"local_http,omitempty"`
	TailnetHTTP         *TailnetHTTPTarget `json:"tailnet_http,omitempty"`
}

type WebSocketReadiness struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"`
}

type LocalHTTPTarget struct {
	EndpointKind LocalEndpointKind `json:"endpoint_kind"`
	TCPAddress   string            `json:"tcp_address,omitempty"`
	TCPPort      uint16            `json:"tcp_port,omitempty"`
}

type TailnetHTTPTarget struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type AppPublication struct {
	Kind          PublicationKind         `json:"kind"`
	DomainHTTPS   *DomainHTTPSPublication `json:"domain_https,omitempty"`
	TemporaryHTTP *TemporaryIPPublication `json:"temporary_ip_http,omitempty"`
}

type DomainHTTPSPublication struct {
	CanonicalDomain string              `json:"canonical_domain"`
	Aliases         []string            `json:"aliases,omitempty"`
	AccessMode      AppAccessMode       `json:"access_mode"`
	CredentialID    string              `json:"credential_id,omitempty"`
	CIDRs           []string            `json:"cidrs,omitempty"`
	StaticRootID    string              `json:"static_root_id,omitempty"`
	StaticMappings  []StaticMapping     `json:"static_mappings,omitempty"`
	Certificate     *CertificateRequest `json:"certificate,omitempty"`
}
type CertificateRequest struct {
	ChallengeMethod     string `json:"challenge_method"`
	DirectoryURL        string `json:"directory_url"`
	AccountKeyPath      string `json:"account_key_path"`
	AccountEmail        string `json:"account_email"`
	TermsAccepted       bool   `json:"terms_accepted"`
	DNSProvider         string `json:"dns_provider,omitempty"`
	ProviderProfilePath string `json:"provider_profile_path,omitempty"`
	AuthoritativeZone   string `json:"authoritative_zone,omitempty"`
}

type TemporaryIPPublication struct {
	PublicIPv4 string `json:"public_ipv4"`
	Port       uint16 `json:"port"`
}

type ManagedProcess struct {
	ID                  string                   `json:"id"`
	Requested           ProcessRequestedState    `json:"requested"`
	Service             ManagedService           `json:"service"`
	ReferenceBinding    *ProcessReferenceBinding `json:"reference_binding,omitempty"`
	Applied             *ProcessBundle           `json:"applied,omitempty"`
	RuntimeObservation  *RuntimeObservation      `json:"runtime_observation,omitempty"`
	LastOperation       OperationCode            `json:"last_operation,omitempty"`
	LastOperationResult OperationResult          `json:"last_operation_result,omitempty"`
	LastJobID           string                   `json:"last_job_id,omitempty"`
}

type ProcessReferenceBinding struct {
	ExecutableDigest         string   `json:"executable_digest"`
	WorkingDirectoryIdentity string   `json:"working_directory_identity"`
	EnvironmentFingerprint   string   `json:"environment_fingerprint,omitempty"`
	WritePathIdentities      []string `json:"write_path_identities"`
}

type ManagedService struct {
	Executable       string   `json:"executable"`
	Arguments        []string `json:"arguments"`
	WorkingDirectory string   `json:"working_directory"`
	EnvironmentFile  string   `json:"environment_file,omitempty"`
	WritePaths       []string `json:"write_paths"`
}

type ProcessBundle struct {
	Generation               uint64   `json:"generation"`
	ConfigDigest             string   `json:"config_digest"`
	UnitDigest               string   `json:"unit_digest"`
	SocketUnitDigest         string   `json:"socket_unit_digest"`
	PolicyDigest             string   `json:"policy_digest"`
	AccountDigest            string   `json:"account_digest"`
	ExecutableDigest         string   `json:"executable_digest"`
	WorkingDirectoryIdentity string   `json:"working_directory_identity"`
	WritePathIdentities      []string `json:"write_path_identities"`
	EnvironmentFingerprint   string   `json:"environment_fingerprint,omitempty"`
	Cgroup                   string   `json:"cgroup"`
	FrontendEndpoint         string   `json:"frontend_endpoint"`
	BackendEndpoint          string   `json:"backend_endpoint,omitempty"`
	EndpointSocketUnits      []string `json:"endpoint_socket_units"`
	RelayRequired            bool     `json:"relay_required"`
	ApplicationUID           uint32   `json:"application_uid"`
	ApplicationGID           uint32   `json:"application_gid"`
	FrontendUID              uint32   `json:"frontend_uid,omitempty"`
	FrontendGID              uint32   `json:"frontend_gid,omitempty"`
	FrontendMode             uint32   `json:"frontend_mode,omitempty"`
	RelayUID                 uint32   `json:"relay_uid,omitempty"`
	RelayGID                 uint32   `json:"relay_gid,omitempty"`
	TCPAddress               string   `json:"tcp_address,omitempty"`
	TCPPort                  uint16   `json:"tcp_port,omitempty"`
	ManagedPaths             []string `json:"managed_paths"`
}

type PublicationRecord struct {
	State                 PublicationState           `json:"state"`
	UnpublishedGeneration uint64                     `json:"unpublished_generation"`
	LastAppliedDigest     *string                    `json:"last_applied_digest,omitempty"`
	LastAppliedBundle     *PublicationBundle         `json:"last_applied_bundle,omitempty"`
	EffectiveSecurity     *EffectiveSecurityIdentity `json:"effective_security,omitempty"`
	ActivationIntent      *ActivationIntent          `json:"activation_intent,omitempty"`
	ContractionIntent     *ContractionIntent         `json:"contraction_intent,omitempty"`
	RuntimeObservation    *RuntimeObservation        `json:"runtime_observation,omitempty"`
	LastOperation         OperationCode              `json:"last_operation,omitempty"`
	LastOperationResult   OperationResult            `json:"last_operation_result,omitempty"`
	LastJobID             string                     `json:"last_job_id,omitempty"`
}

type ContractionIntent struct {
	JobID                  string             `json:"job_id"`
	Operation              string             `json:"operation"`
	Generation             uint64             `json:"generation"`
	ClosureAuthorityDigest string             `json:"closure_authority_digest"`
	Prior                  *PublicationBundle `json:"prior,omitempty"`
	Candidate              *PublicationBundle `json:"candidate,omitempty"`
}

type PublicationBundle struct {
	ID               string                       `json:"id"`
	Generation       uint64                       `json:"generation"`
	ConfigDigest     string                       `json:"config_digest"`
	Kind             PublicationKind              `json:"kind"`
	EndpointIdentity string                       `json:"endpoint_identity"`
	SiteIdentity     string                       `json:"site_identity"`
	ManagedPaths     []string                     `json:"managed_paths"`
	CredentialIDs    []string                     `json:"credential_ids"`
	Listeners        []BundleListenerIdentity     `json:"listeners"`
	DomainHTTPS      *DomainHTTPSBundleIdentity   `json:"domain_https,omitempty"`
	TemporaryHTTP    *TemporaryHTTPBundleIdentity `json:"temporary_ip_http,omitempty"`
}

type BundleListenerIdentity struct {
	Network string `json:"network"`
	Port    uint16 `json:"port"`
}

type DomainHTTPSBundleIdentity struct {
	ExactDomains []string                  `json:"exact_domains"`
	Certificate  CertificateBundleIdentity `json:"certificate"`
	Auth         AuthBundleIdentity        `json:"auth"`
	Static       StaticBundleIdentity      `json:"static"`
	GoAccess     GoAccessBundleIdentity    `json:"goaccess"`
	EdgeOne      EdgeOneBundleIdentity     `json:"edgeone"`
}

type CertificateBundleIdentity struct {
	PointerIdentity string                        `json:"pointer_identity"`
	BindingIdentity string                        `json:"binding_identity"`
	Generation      uint64                        `json:"generation,omitempty"`
	Fingerprint     string                        `json:"fingerprint,omitempty"`
	SANIdentity     string                        `json:"san_identity,omitempty"`
	NotAfter        string                        `json:"not_after,omitempty"`
	LastTrustedWall string                        `json:"last_trusted_wall,omitempty"`
	ChainIdentity   string                        `json:"chain_identity,omitempty"`
	IssuerIdentity  string                        `json:"issuer_identity,omitempty"`
	Authority       *CertificateAuthorityIdentity `json:"authority,omitempty"`
}
type CertificateAuthorityIdentity struct {
	CertificateID         string                          `json:"certificate_id"`
	DirectoryURL          string                          `json:"directory_url"`
	AccountKeyPath        string                          `json:"account_key_path"`
	AccountKeyFingerprint string                          `json:"account_key_fingerprint"`
	AccountEmail          string                          `json:"account_email"`
	TermsAccepted         bool                            `json:"terms_accepted"`
	Method                string                          `json:"method"`
	Provider              string                          `json:"provider,omitempty"`
	ProfilePath           string                          `json:"profile_path,omitempty"`
	ProfileFingerprint    string                          `json:"profile_fingerprint,omitempty"`
	CredentialFiles       []CertificateCredentialIdentity `json:"credential_files"`
	Zone                  string                          `json:"zone,omitempty"`
	Principal             string                          `json:"principal,omitempty"`
}
type CertificateCredentialIdentity struct {
	Key         string `json:"key"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
}

type AuthBundleIdentity struct {
	Mode               AppAccessMode `json:"mode"`
	CredentialIdentity string        `json:"credential_identity,omitempty"`
	ReferenceIdentity  string        `json:"reference_identity,omitempty"`
}

type StaticBundleIdentity struct {
	RootID          string                      `json:"root_id,omitempty"`
	Routes          []StaticRouteBundleIdentity `json:"routes"`
	RouteIdentities []string                    `json:"route_identities"`
}
type StaticRouteBundleIdentity struct {
	URLPath      string `json:"url_path"`
	RelativePath string `json:"relative_path"`
	SourcePath   string `json:"source_path"`
	Directory    bool   `json:"directory"`
	Anonymous    bool   `json:"anonymous,omitempty"`
	Fingerprint  string `json:"fingerprint"`
}

type GoAccessBundleIdentity struct {
	Enabled         bool   `json:"enabled"`
	RouteIdentity   string `json:"route_identity,omitempty"`
	ServiceIdentity string `json:"service_identity,omitempty"`
}

type EdgeOneBundleIdentity struct {
	Enabled              bool   `json:"enabled"`
	PublishBinding       string `json:"publish_binding,omitempty"`
	InitialACLGeneration uint64 `json:"initial_acl_generation,omitempty"`
}

type EffectiveSecurityIdentity struct {
	Generation        uint64   `json:"generation"`
	ACLVersion        string   `json:"acl_version"`
	CIDRs             []string `json:"cidrs"`
	EffectiveDeadline string   `json:"effective_deadline"`
}

type TemporaryHTTPBundleIdentity struct {
	PublicIPv4       string `json:"public_ipv4"`
	Port             uint16 `json:"port"`
	HostAuthority    string `json:"host_authority"`
	ListenerIdentity string `json:"listener_identity"`
}

type ActivationIntent struct {
	ID         string             `json:"id"`
	JobID      string             `json:"job_id"`
	PlanID     string             `json:"plan_id"`
	Generation uint64             `json:"generation"`
	Candidate  PublicationBundle  `json:"candidate"`
	PriorState PublicationState   `json:"prior_state"`
	Prior      *PublicationBundle `json:"prior,omitempty"`
}

type RuntimeObservation struct {
	Status     RuntimeHealth `json:"status"`
	ObservedAt string        `json:"observed_at"`
	Reason     string        `json:"reason,omitempty"`
}

type RuntimeHealth string

const (
	RuntimeHealthy  RuntimeHealth = "healthy"
	RuntimeDegraded RuntimeHealth = "degraded"
	RuntimeUnknown  RuntimeHealth = "unknown"
)

type PrerequisiteError struct {
	Code PrerequisiteCode
}

func (err PrerequisiteError) Error() string { return string(err.Code) }

func ParseOperationCode(value string) (OperationCode, error) {
	switch OperationCode(value) {
	case OperationInstanceConfigCreate, OperationInstanceConfigUpdate, OperationValidate,
		OperationPlan, OperationDeploy, OperationStatus, OperationDiagnostics,
		OperationConfigurationExport, OperationAdminTokenRotate, OperationHeadscaleReissue,
		OperationDependencyUpload, OperationDependencyImport, OperationMaintenance,
		OperationBackupEnter, OperationBackupPreparingAbort, OperationBackupExit,
		OperationRestoreEvidenceImport, OperationRestoreCutover, OperationConnectorVerify,
		OperationConnectorAuthKeyImport, OperationConnectorAuthKeyAdopt,
		OperationConnectorAuthKeyDiscard, OperationConnectorLogin,
		OperationConnectorDisconnect, OperationConnectorRebind, OperationResourceCreate,
		OperationResourceUpdate, OperationResourceDelete, OperationPublish,
		OperationUnpublish, OperationCloseAll, OperationProcessStart,
		OperationProcessStop, OperationUnpublishAndStop, OperationHeadscaleUserCreate,
		OperationHeadscaleUserList, OperationPreauthKeyCreate, OperationPreauthKeyList,
		OperationPreauthKeyRevoke, OperationDeviceList, OperationDeviceExpire,
		OperationManagedBasicCreate, OperationManagedBasicRotate,
		OperationManagedBasicDelete, OperationStaticRootRegister, OperationExternalHTPasswdRegister, OperationEdgeOneDiagnostics,
		OperationEdgeOneRefresh, OperationJobList, OperationJobDetail,
		OperationSessionLogout:
		return OperationCode(value), nil
	default:
		return "", fmt.Errorf("operation code %q is not supported", value)
	}
}

func ValidateOperationTarget(operation OperationCode, target OperationTarget) error {
	if _, err := ParseOperationCode(string(operation)); err != nil {
		return err
	}
	allowed := false
	switch operation {
	case OperationPlan, OperationStatus, OperationDiagnostics:
		allowed = target.Kind == OperationTargetInstallation || target.Kind == OperationTargetResource
	case OperationResourceUpdate, OperationResourceDelete, OperationPublish, OperationUnpublish,
		OperationProcessStart, OperationProcessStop, OperationUnpublishAndStop,
		OperationManagedBasicCreate, OperationStaticRootRegister, OperationExternalHTPasswdRegister, OperationEdgeOneDiagnostics, OperationEdgeOneRefresh:
		allowed = target.Kind == OperationTargetResource
	case OperationManagedBasicRotate, OperationManagedBasicDelete:
		allowed = target.Kind == OperationTargetCredential
	case OperationPreauthKeyCreate:
		allowed = target.Kind == OperationTargetHeadscaleUser
	case OperationPreauthKeyRevoke:
		allowed = target.Kind == OperationTargetPreauthKey
	case OperationDeviceExpire:
		allowed = target.Kind == OperationTargetDevice
	case OperationJobDetail:
		allowed = target.Kind == OperationTargetJob
	default:
		allowed = target.Kind == OperationTargetInstallation
	}
	if !allowed {
		return fmt.Errorf("operation %q does not accept target kind %q", operation, target.Kind)
	}
	switch target.Kind {
	case OperationTargetInstallation:
		if target.ID != "" {
			return fmt.Errorf("installation target must not include id")
		}
	case OperationTargetResource:
		if !strings.HasPrefix(target.ID, "res_") || !idPattern.MatchString(target.ID) {
			return fmt.Errorf("resource target id is invalid")
		}
	case OperationTargetCredential:
		if !strings.HasPrefix(target.ID, "cred_") || !idPattern.MatchString(target.ID) {
			return fmt.Errorf("credential target id is invalid")
		}
	case OperationTargetHeadscaleUser, OperationTargetPreauthKey, OperationTargetDevice, OperationTargetJob:
		if !validOpaqueTargetID(target.ID) {
			return fmt.Errorf("%s target id is invalid", target.Kind)
		}
	default:
		return fmt.Errorf("operation target kind %q is not supported", target.Kind)
	}
	return nil
}

func ParseOperationResult(value string) (OperationResult, error) {
	switch OperationResult(value) {
	case OperationSucceeded, OperationFailed, OperationPartial, OperationInterrupted, OperationUnknown:
		return OperationResult(value), nil
	default:
		return "", fmt.Errorf("operation result %q is not supported", value)
	}
}

func ParsePrerequisiteCode(value string) (PrerequisiteCode, error) {
	switch PrerequisiteCode(value) {
	case PrerequisiteHeadscaleNotConfigured, PrerequisiteConnectorRequired, PrerequisiteOSProfileLiveUnqualified, PrerequisiteDependencyTransitionRequired:
		return PrerequisiteCode(value), nil
	default:
		return "", fmt.Errorf("prerequisite code %q is not supported", value)
	}
}

func RequireHeadscale(installation Installation) error {
	if installation.Headscale == nil {
		return PrerequisiteError{Code: PrerequisiteHeadscaleNotConfigured}
	}
	return nil
}

func RequireConnector(installation Installation) error {
	if installation.Connector == nil {
		return PrerequisiteError{Code: PrerequisiteConnectorRequired}
	}
	return nil
}

func PublicationPrerequisites(installation Installation, resourceID string) error {
	for _, resource := range installation.Resources {
		if resource.ID != resourceID {
			continue
		}
		if resource.Target.Kind == AppTargetTailnetHTTP {
			return RequireConnector(installation)
		}
		return nil
	}
	return fmt.Errorf("resource %q does not exist", resourceID)
}

var idPattern = regexp.MustCompile(`^(?:ins|hds|con|res|proc|cred)_[0-9a-f]{32}$`)

func ValidateInstallation(installation Installation) error {
	if installation.SchemaVersion != InstallationSchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", installation.SchemaVersion)
	}
	if !strings.HasPrefix(installation.InstallationID, "ins_") || !idPattern.MatchString(installation.InstallationID) {
		return fmt.Errorf("installation_id is invalid")
	}
	if err := validateManagement(installation.Management); err != nil {
		return fmt.Errorf("management: %w", err)
	}
	if err := validatePaths("managed_paths", installation.ManagedPaths); err != nil {
		return err
	}
	if installation.Headscale != nil {
		if !strings.HasPrefix(installation.Headscale.ID, "hds_") || !idPattern.MatchString(installation.Headscale.ID) {
			return fmt.Errorf("headscale.id is invalid")
		}
		if err := validateDomain(installation.Headscale.ControlDomain); err != nil {
			return fmt.Errorf("headscale.control_domain: %w", err)
		}
		if err := validateDomain(installation.Headscale.MagicDNSNamespace); err != nil {
			return fmt.Errorf("headscale.magicdns_namespace: %w", err)
		}
		if err := validatePaths("headscale.managed_paths", installation.Headscale.ManagedPaths); err != nil {
			return err
		}
	}
	if installation.Connector != nil {
		if !strings.HasPrefix(installation.Connector.ID, "con_") || !idPattern.MatchString(installation.Connector.ID) {
			return fmt.Errorf("connector.id is invalid")
		}
		if err := validateHTTPSURL(installation.Connector.LoginServer); err != nil {
			return fmt.Errorf("connector.login_server: %w", err)
		}
		if err := validatePaths("connector.managed_paths", installation.Connector.ManagedPaths); err != nil {
			return err
		}
	}
	credentialIDs := make(map[string]struct{}, len(installation.Credentials))
	credentialOwners := make(map[string]string, len(installation.Credentials))
	for index, credential := range installation.Credentials {
		if !strings.HasPrefix(credential.ID, "cred_") || !idPattern.MatchString(credential.ID) {
			return fmt.Errorf("credentials[%d].id is invalid", index)
		}
		if _, exists := credentialIDs[credential.ID]; exists {
			return fmt.Errorf("credential id %q is duplicated", credential.ID)
		}
		credentialIDs[credential.ID] = struct{}{}
		credentialOwners[credential.ID] = credential.OwnerResourceID
		switch credential.Kind {
		case "managed_basic":
			if !validBasicUsername(credential.Username) || !idPattern.MatchString(credential.OwnerResourceID) || credential.ManagedPath != "/etc/lanpanel-public/basic/"+credential.ID+".htpasswd" || credential.ExternalPath != "" || !validSHA256Digest(credential.Fingerprint) {
				return fmt.Errorf("credentials[%d] managed Basic identity invalid", index)
			}
		case "external_htpasswd":
			if !idPattern.MatchString(credential.OwnerResourceID) || credential.Username != "" || credential.ManagedPath != "" || !cleanAbsolutePath(credential.ExternalPath) || !validSHA256Digest(credential.Fingerprint) {
				return fmt.Errorf("credentials[%d] external htpasswd identity invalid", index)
			}
		default:
			return fmt.Errorf("credentials[%d] kind invalid", index)
		}
	}
	staticRootIDs := map[string]struct{}{}
	for index, root := range installation.StaticRoots {
		if !strings.HasPrefix(root.ID, "static_") || len(root.ID) != 39 || !cleanAbsolutePath(root.Path) || !validSHA256Digest(root.Fingerprint) || root.Device == 0 {
			return fmt.Errorf("static_roots[%d] identity invalid", index)
		}
		if _, duplicate := staticRootIDs[root.ID]; duplicate {
			return fmt.Errorf("static root duplicated")
		}
		staticRootIDs[root.ID] = struct{}{}
	}
	resourceIDs := make(map[string]struct{}, len(installation.Resources))
	for index := range installation.Resources {
		resource := &installation.Resources[index]
		if _, exists := resourceIDs[resource.ID]; exists {
			return fmt.Errorf("resource id %q is duplicated", resource.ID)
		}
		resourceIDs[resource.ID] = struct{}{}
		if err := validateResource(*resource, credentialIDs, credentialOwners, staticRootIDs); err != nil {
			return fmt.Errorf("resources[%d]: %w", index, err)
		}
	}
	for id, owner := range credentialOwners {
		if _, present := resourceIDs[owner]; !present {
			return fmt.Errorf("credential %q owner resource is missing", id)
		}
	}
	return nil
}

func validateManagement(authority ManagementAuthority) error {
	address, err := netip.ParseAddr(authority.Address)
	if err != nil || !address.Is4() || !address.IsLoopback() || address.IsUnspecified() {
		return fmt.Errorf("address must be an exact IPv4 127/8 literal")
	}
	if authority.Port < 1024 {
		return fmt.Errorf("port must be in 1024..65535")
	}
	return validatePaths("management.managed_paths", authority.ManagedPaths)
}

func validateResource(resource AppResource, credentialIDs map[string]struct{}, credentialOwners map[string]string, staticRootIDs map[string]struct{}) error {
	if !strings.HasPrefix(resource.ID, "res_") || !idPattern.MatchString(resource.ID) {
		return fmt.Errorf("id is invalid")
	}
	if err := validateDisplayName(resource.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	switch resource.Lifecycle {
	case LifecycleActive, LifecycleDeleting:
	default:
		return fmt.Errorf("lifecycle %q is not supported", resource.Lifecycle)
	}
	if !validSHA256Digest(resource.CurrentConfigDigest) {
		return fmt.Errorf("current_config_digest must be sha256:<64 lowercase hex>")
	}
	if err := validateTarget(resource.Target); err != nil {
		return err
	}
	if err := validatePublication(resource.Publication); err != nil {
		return err
	}
	if resource.Publication.Kind == PublicationTemporaryHTTP && resource.Target.WebSocket.Enabled {
		return fmt.Errorf("temporary_ip_http does not support WebSocket")
	}
	if resource.Target.Kind == AppTargetLocalHTTP {
		if resource.ManagedProcess == nil {
			return fmt.Errorf("local_http requires managed_process")
		}
		if err := validateManagedProcess(*resource.ManagedProcess); err != nil {
			return err
		}
	} else if resource.ManagedProcess != nil {
		return fmt.Errorf("tailnet_http must not include managed_process")
	}
	if err := validatePublicationRecord(resource.PublicationRecord, resource.Publication, resource.CurrentConfigDigest); err != nil {
		return err
	}
	seenCredentials := map[string]struct{}{}
	for _, credentialID := range resource.CredentialIDs {
		if _, duplicate := seenCredentials[credentialID]; duplicate {
			return fmt.Errorf("credential_id %q is duplicated in resource", credentialID)
		}
		seenCredentials[credentialID] = struct{}{}
		if _, exists := credentialIDs[credentialID]; !exists {
			return fmt.Errorf("credential_id %q does not exist", credentialID)
		}
		if owner := credentialOwners[credentialID]; owner != "" && owner != resource.ID {
			return fmt.Errorf("credential_id %q belongs to another resource", credentialID)
		}
	}
	if publication := resource.Publication.DomainHTTPS; publication != nil && publication.StaticRootID != "" {
		if _, present := staticRootIDs[publication.StaticRootID]; !present {
			return fmt.Errorf("publication static_root_id does not exist")
		}
	}
	if resource.Publication.DomainHTTPS != nil && resource.Publication.DomainHTTPS.CredentialID != "" {
		credentialID := resource.Publication.DomainHTTPS.CredentialID
		if _, exists := credentialIDs[credentialID]; !exists {
			return fmt.Errorf("publication credential_id %q does not exist", credentialID)
		}
		if owner := credentialOwners[credentialID]; owner != "" && owner != resource.ID {
			return fmt.Errorf("publication credential belongs to another resource")
		}
		if _, referenced := seenCredentials[credentialID]; !referenced {
			return fmt.Errorf("publication credential_id %q must be declared in resource credential_ids", credentialID)
		}
	}
	return validatePaths("resource.managed_paths", resource.ManagedPaths)
}

func validateTarget(target AppTarget) error {
	if err := validateReadinessPath(target.ReadinessPath); err != nil {
		return fmt.Errorf("target.readiness_path: %w", err)
	}
	if len(target.AllowedHTTPStatuses) == 0 || len(target.AllowedHTTPStatuses) > 32 {
		return fmt.Errorf("target.allowed_http_statuses must be a bounded nonempty set")
	}
	for index, status := range target.AllowedHTTPStatuses {
		if status < 200 || status > 399 || index > 0 && target.AllowedHTTPStatuses[index-1] >= status {
			return fmt.Errorf("target.allowed_http_statuses must contain sorted unique 2xx/3xx values")
		}
	}
	if target.WebSocket.Enabled {
		if err := validateReadinessPath(target.WebSocket.Path); err != nil {
			return fmt.Errorf("target.websocket.path: %w", err)
		}
	} else if target.WebSocket.Path != "" {
		return fmt.Errorf("target.websocket.path requires enabled=true")
	}
	switch target.Kind {
	case AppTargetLocalHTTP:
		if target.LocalHTTP == nil || target.TailnetHTTP != nil {
			return fmt.Errorf("target local_http must contain only local_http")
		}
		local := target.LocalHTTP
		switch local.EndpointKind {
		case LocalEndpointUnixSocketActivation:
			if local.TCPAddress != "" || local.TCPPort != 0 {
				return fmt.Errorf("local_http %s must not include TCP authority", local.EndpointKind)
			}
			return nil
		case LocalEndpointRelayUnix:
			if local.TCPAddress != "" || local.TCPPort != 0 {
				return fmt.Errorf("local_http %s must not include TCP authority", local.EndpointKind)
			}
			return nil
		case LocalEndpointTCPSocketActivation:
			address, err := netip.ParseAddr(local.TCPAddress)
			if err != nil || !address.IsLoopback() || address.IsUnspecified() {
				return fmt.Errorf("local_http TCP address must be an exact loopback IP literal")
			}
			if local.TCPPort == 0 {
				return fmt.Errorf("local_http TCP port must be nonzero")
			}
			return nil
		default:
			return fmt.Errorf("local_http.endpoint_kind %q is not supported", local.EndpointKind)
		}
	case AppTargetTailnetHTTP:
		if target.TailnetHTTP == nil || target.LocalHTTP != nil {
			return fmt.Errorf("target tailnet_http must contain only tailnet_http")
		}
		address, err := netip.ParseAddr(target.TailnetHTTP.IP)
		if err != nil || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
			return fmt.Errorf("tailnet_http.ip must be a non-local IP literal")
		}
		if target.TailnetHTTP.Port == 0 {
			return fmt.Errorf("tailnet_http.port must be nonzero")
		}
		return nil
	default:
		return fmt.Errorf("target kind %q is not supported", target.Kind)
	}
}

func validatePublication(publication AppPublication) error {
	switch publication.Kind {
	case PublicationDomainHTTPS:
		if publication.DomainHTTPS == nil || publication.TemporaryHTTP != nil {
			return fmt.Errorf("publication domain_https must contain only domain_https")
		}
		if err := validateDomain(publication.DomainHTTPS.CanonicalDomain); err != nil {
			return fmt.Errorf("domain_https.canonical_domain: %w", err)
		}
		seen := map[string]struct{}{publication.DomainHTTPS.CanonicalDomain: {}}
		for _, alias := range publication.DomainHTTPS.Aliases {
			if err := validateDomain(alias); err != nil {
				return fmt.Errorf("domain_https.alias: %w", err)
			}
			if _, duplicate := seen[alias]; duplicate {
				return fmt.Errorf("domain_https domain %q is duplicated", alias)
			}
			seen[alias] = struct{}{}
		}
		switch publication.DomainHTTPS.AccessMode {
		case AppAccessPublic, AppAccessApplicationManaged:
			if publication.DomainHTTPS.CredentialID != "" {
				return fmt.Errorf("credential_id is only valid for basic access")
			}
		case AppAccessBasic:
			if publication.DomainHTTPS.CredentialID == "" {
				return fmt.Errorf("basic access requires credential_id")
			}
			if err := validatePublicationCIDRs(publication.DomainHTTPS.CIDRs); err != nil {
				return err
			}
		default:
			return fmt.Errorf("access mode %q is not supported", publication.DomainHTTPS.AccessMode)
		}
		if publication.DomainHTTPS.AccessMode != AppAccessBasic && len(publication.DomainHTTPS.CIDRs) != 0 {
			return fmt.Errorf("CIDR allowlist requires basic access")
		}
		if err := validateStaticMappings(*publication.DomainHTTPS); err != nil {
			return err
		}
		certificate := publication.DomainHTTPS.Certificate
		if certificate != nil {
			if certificate.ChallengeMethod != "http-01" && certificate.ChallengeMethod != "dns-01" || !canonicalHTTPSURL(certificate.DirectoryURL) || !cleanAbsolutePath(certificate.AccountKeyPath) || !validACMEEmail(certificate.AccountEmail) || !certificate.TermsAccepted {
				return fmt.Errorf("domain_https certificate authority is invalid")
			}
			if certificate.ChallengeMethod == "http-01" && (certificate.DNSProvider != "" || certificate.ProviderProfilePath != "" || certificate.AuthoritativeZone != "") {
				return fmt.Errorf("http-01 must not contain DNS provider authority")
			}
			if certificate.ChallengeMethod == "dns-01" && (!validDNSProvider(certificate.DNSProvider) || !cleanAbsolutePath(certificate.ProviderProfilePath) || certificate.AuthoritativeZone == "") {
				return fmt.Errorf("dns-01 provider authority is incomplete")
			}
		}
		return nil
	case PublicationTemporaryHTTP:
		if publication.TemporaryHTTP == nil || publication.DomainHTTPS != nil {
			return fmt.Errorf("publication temporary_ip_http must contain only temporary_ip_http")
		}
		if err := ValidateTemporaryPublicIPv4(publication.TemporaryHTTP.PublicIPv4); err != nil {
			return err
		}
		if publication.TemporaryHTTP.Port < 1024 || publication.TemporaryHTTP.Port == 80 || publication.TemporaryHTTP.Port == 443 {
			return fmt.Errorf("temporary_ip_http.port must be in 1024..65535 and not 80 or 443")
		}
		return nil
	default:
		return fmt.Errorf("publication kind %q is not supported", publication.Kind)
	}
}

func validatePublicationCIDRs(values []string) error {
	if len(values) > 128 {
		return fmt.Errorf("CIDR allowlist oversized")
	}
	prior := ""
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || prefix.Bits() == 0 || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prior != "" && prior >= value {
			return fmt.Errorf("CIDR allowlist noncanonical")
		}
		prior = value
	}
	return nil
}
func validateStaticMappings(publication DomainHTTPSPublication) error {
	if len(publication.StaticMappings) > 128 {
		return fmt.Errorf("static mapping inventory oversized")
	}
	if (publication.StaticRootID == "") != (len(publication.StaticMappings) == 0) {
		return fmt.Errorf("static root and mapping inventory must be paired")
	}
	prior := ""
	for _, mapping := range publication.StaticMappings {
		if !validStaticURL(mapping.URLPath, mapping.Directory) || mapping.RelativePath == "" || filepath.IsAbs(mapping.RelativePath) || filepath.Clean(mapping.RelativePath) != mapping.RelativePath || strings.HasPrefix(mapping.RelativePath, "..") || prior != "" && prior >= mapping.URLPath {
			return fmt.Errorf("static mapping invalid")
		}
		if publication.AccessMode == AppAccessApplicationManaged && !mapping.Anonymous {
			return fmt.Errorf("application-managed static requires anonymous confirmation")
		}
		prior = mapping.URLPath
	}
	return nil
}
func validStaticURL(value string, directory bool) bool {
	if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\%\x00\r\n \t;{}$\"'") || filepath.Clean(value) != strings.TrimSuffix(value, "/") {
		return false
	}
	return directory == (value != "/" && strings.HasSuffix(value, "/"))
}
func validBasicUsername(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if index == 0 && ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')) {
			continue
		}
		if index > 0 && ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("._@-", character)) {
			continue
		}
		return false
	}
	return true
}
func validACMEEmail(value string) bool {
	return len(value) >= 3 && len(value) <= 254 && strings.Count(value, "@") == 1 && !strings.ContainsAny(value, "\x00\r\n /=")
}
func validateManagedProcess(process ManagedProcess) error {
	if !strings.HasPrefix(process.ID, "proc_") || !idPattern.MatchString(process.ID) {
		return fmt.Errorf("managed_process.id is invalid")
	}
	switch process.Requested {
	case ProcessRequestedRunning, ProcessRequestedStopped:
	default:
		return fmt.Errorf("managed_process.requested %q is not supported", process.Requested)
	}
	if err := validateManagedService(process.Service); err != nil {
		return fmt.Errorf("managed_process.service: %w", err)
	}
	if process.ReferenceBinding != nil {
		binding := process.ReferenceBinding
		if !validSHA256Digest(binding.ExecutableDigest) || !validSHA256Digest(binding.WorkingDirectoryIdentity) || binding.EnvironmentFingerprint != "" && !validSHA256Digest(binding.EnvironmentFingerprint) {
			return fmt.Errorf("managed_process.reference_binding is invalid")
		}
		for index, value := range binding.WritePathIdentities {
			if !validSHA256Digest(value) || index > 0 && binding.WritePathIdentities[index-1] >= value {
				return fmt.Errorf("managed_process.reference_binding write paths are invalid")
			}
		}
	}
	if process.Applied != nil {
		if err := validateProcessBundle(*process.Applied); err != nil {
			return fmt.Errorf("managed_process.applied: %w", err)
		}
	}
	if process.RuntimeObservation != nil {
		if err := validateRuntimeObservation(*process.RuntimeObservation); err != nil {
			return fmt.Errorf("managed_process.runtime_observation: %w", err)
		}
	}
	if (process.LastOperation == "") != (process.LastJobID == "") || process.LastOperation == "" && process.LastOperationResult != "" {
		return fmt.Errorf("managed_process operation identity is one-sided")
	}
	if process.LastOperation != "" {
		if process.LastOperation != OperationProcessStart && process.LastOperation != OperationProcessStop && process.LastOperation != OperationUnpublishAndStop {
			return fmt.Errorf("managed_process last_operation is unsupported")
		}
		if process.LastOperationResult != "" {
			if _, err := ParseOperationResult(string(process.LastOperationResult)); err != nil {
				return fmt.Errorf("managed_process terminal result is invalid")
			}
		}
		if !validOpaqueTargetID(process.LastJobID) {
			return fmt.Errorf("managed_process operation job identity is invalid")
		}
	}
	return nil
}

func validateManagedService(service ManagedService) error {
	if err := validateExternalAbsolute(service.Executable, "executable"); err != nil {
		return err
	}
	if err := validateExternalAbsolute(service.WorkingDirectory, "working_directory"); err != nil {
		return err
	}
	if service.EnvironmentFile != "" {
		if err := validateExternalAbsolute(service.EnvironmentFile, "environment_file"); err != nil {
			return err
		}
	}
	if len(service.Arguments) > 64 {
		return fmt.Errorf("arguments exceed fixed count")
	}
	bytes := 0
	for _, argument := range service.Arguments {
		bytes += len(argument)
		if argument == "" || len(argument) > 1024 || containsControl(argument) || strings.Contains(argument, "${") || strings.Contains(argument, "$(") || strings.Contains(argument, "`") || strings.Contains(argument, "%") {
			return fmt.Errorf("arguments contain empty, expansion, systemd specifier, control, or unbounded value")
		}
	}
	if bytes > 4096 {
		return fmt.Errorf("arguments exceed fixed byte bound")
	}
	return validatePaths("managed_process.service.write_paths", service.WritePaths)
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
func validateExternalAbsolute(value, label string) error {
	if value == "" || value != strings.TrimSpace(value) || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
		return fmt.Errorf("%s must be a clean absolute non-root path", label)
	}
	return nil
}

func validateProcessBundle(bundle ProcessBundle) error {
	if bundle.Generation == 0 || !validSHA256Digest(bundle.ConfigDigest) || !validSHA256Digest(bundle.UnitDigest) || !validSHA256Digest(bundle.SocketUnitDigest) || !validSHA256Digest(bundle.PolicyDigest) || !validSHA256Digest(bundle.AccountDigest) || !validSHA256Digest(bundle.ExecutableDigest) || !validSHA256Digest(bundle.WorkingDirectoryIdentity) || bundle.EnvironmentFingerprint != "" && !validSHA256Digest(bundle.EnvironmentFingerprint) || bundle.Cgroup == "" || bundle.FrontendEndpoint == "" || len(bundle.EndpointSocketUnits) > 2 || bundle.ApplicationUID == 0 || bundle.ApplicationGID == 0 || bundle.RelayRequired && (bundle.RelayUID == 0 || bundle.RelayGID == 0) || !bundle.RelayRequired && (bundle.RelayUID != 0 || bundle.RelayGID != 0) {
		return fmt.Errorf("process bundle identity is incomplete")
	}
	if err := validateExternalAbsolute(bundle.Cgroup, "cgroup"); err != nil {
		return err
	}
	if err := validateExternalAbsolute(bundle.FrontendEndpoint, "frontend_endpoint"); err != nil {
		return err
	}
	if bundle.TCPAddress == "" {
		if bundle.FrontendUID != 0 || bundle.FrontendGID == 0 || bundle.FrontendMode != 0o660 {
			return fmt.Errorf("Unix frontend ownership authority is incomplete")
		}
	} else if bundle.FrontendUID != 0 || bundle.FrontendGID != 0 || bundle.FrontendMode != 0 {
		return fmt.Errorf("TCP frontend must not carry Unix ownership authority")
	}
	if (bundle.TCPAddress == "") != (bundle.TCPPort == 0) {
		return fmt.Errorf("TCP endpoint authority one-sided")
	}
	if bundle.TCPAddress != "" {
		address, err := netip.ParseAddr(bundle.TCPAddress)
		if err != nil || !address.IsLoopback() {
			return fmt.Errorf("TCP endpoint authority invalid")
		}
	}
	for index, value := range bundle.WritePathIdentities {
		if !validSHA256Digest(value) || index > 0 && bundle.WritePathIdentities[index-1] >= value {
			return fmt.Errorf("write path identity inventory invalid")
		}
	}
	if len(bundle.EndpointSocketUnits) == 0 && !bundle.RelayRequired {
		return fmt.Errorf("endpoint socket unit inventory missing")
	}
	for index, unit := range bundle.EndpointSocketUnits {
		if unit == "" || strings.ContainsAny(unit, "/\x00\r\n") || !strings.HasSuffix(unit, ".socket") || index > 0 && bundle.EndpointSocketUnits[index-1] >= unit {
			return fmt.Errorf("endpoint socket unit inventory is invalid")
		}
	}
	if bundle.BackendEndpoint != "" {
		if err := validateExternalAbsolute(bundle.BackendEndpoint, "backend_endpoint"); err != nil {
			return err
		}
	}
	return validatePaths("managed_process.applied.managed_paths", bundle.ManagedPaths)
}

func validatePublicationRecord(record PublicationRecord, publication AppPublication, currentConfigDigest string) error {
	kind := publication.Kind
	if record.UnpublishedGeneration == 0 {
		return fmt.Errorf("publication_record.unpublished_generation must be nonzero")
	}
	if (record.LastAppliedDigest == nil) != (record.LastAppliedBundle == nil) {
		return fmt.Errorf("last_applied_digest and last_applied_bundle must both be present or absent")
	}
	if record.LastAppliedDigest != nil {
		if !validSHA256Digest(*record.LastAppliedDigest) {
			return fmt.Errorf("last_applied_digest must be sha256:<64 lowercase hex>")
		}
		if err := validateBundle(*record.LastAppliedBundle, record.LastAppliedBundle.Kind); err != nil {
			return fmt.Errorf("last_applied_bundle: %w", err)
		}
		if record.LastAppliedBundle.ConfigDigest != *record.LastAppliedDigest {
			return fmt.Errorf("last_applied_digest must match last_applied_bundle.config_digest")
		}
	}
	if record.EffectiveSecurity != nil {
		security := record.EffectiveSecurity
		if security.Generation == 0 || strings.TrimSpace(security.ACLVersion) == "" {
			return fmt.Errorf("effective_security generation and ACL version are required")
		}
		if len(security.CIDRs) == 0 {
			return fmt.Errorf("effective_security CIDRs are required")
		}
		seenCIDRs := map[string]struct{}{}
		for _, value := range security.CIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.String() != value || prefix.Bits() == 0 || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() {
				return fmt.Errorf("effective_security CIDR %q must be canonical globally routable unicast and non-default", value)
			}
			if _, duplicate := seenCIDRs[value]; duplicate {
				return fmt.Errorf("effective_security CIDR %q is duplicated", value)
			}
			seenCIDRs[value] = struct{}{}
		}
		if _, err := time.Parse(time.RFC3339, security.EffectiveDeadline); err != nil {
			return fmt.Errorf("effective_security.effective_deadline must be RFC3339: %w", err)
		}
	}
	if record.ContractionIntent != nil {
		intent := record.ContractionIntent
		if record.State != PublicationUnpublished || record.ActivationIntent != nil || intent.JobID == "" || intent.JobID != strings.TrimSpace(intent.JobID) || strings.ContainsAny(intent.JobID, "\r\n") || intent.Generation != record.UnpublishedGeneration || !validSHA256Digest(intent.ClosureAuthorityDigest) {
			return fmt.Errorf("contraction_intent requires exact unpublished job, generation, and closure authority")
		}
		switch intent.Operation {
		case "publish", "unpublish", "close_all", "certificate_expiry", "edgeone_expiry", "automatic_exact_journal_reconciliation", "startup_activation_contraction":
		default:
			return fmt.Errorf("contraction_intent operation %q is unsupported", intent.Operation)
		}
		for name, bundle := range map[string]*PublicationBundle{"prior": intent.Prior, "candidate": intent.Candidate} {
			if bundle != nil {
				if err := validateBundle(*bundle, bundle.Kind); err != nil {
					return fmt.Errorf("contraction_intent.%s: %w", name, err)
				}
			}
		}
	}
	switch record.State {
	case PublicationPublished:
		if record.ContractionIntent != nil {
			return fmt.Errorf("published state must not retain contraction_intent")
		}
		if record.LastAppliedBundle == nil {
			return fmt.Errorf("published state requires last applied identity")
		}
		if record.LastAppliedBundle.Kind != publication.Kind {
			return fmt.Errorf("published publication kind cannot change before unpublish")
		}
		if publication.Kind == PublicationTemporaryHTTP &&
			(record.LastAppliedBundle.TemporaryHTTP.PublicIPv4 != publication.TemporaryHTTP.PublicIPv4 ||
				record.LastAppliedBundle.TemporaryHTTP.Port != publication.TemporaryHTTP.Port) {
			return fmt.Errorf("published temporary public IPv4 and port cannot change before unpublish")
		}
		if record.ActivationIntent != nil {
			return fmt.Errorf("published state must not retain activation_intent")
		}
	case PublicationUnpublished:
		if record.ActivationIntent != nil {
			return fmt.Errorf("unpublished state must not contain activation_intent")
		}
	case PublicationActivating:
		if record.ContractionIntent != nil {
			return fmt.Errorf("activating state must not retain contraction_intent")
		}
		if record.ActivationIntent == nil {
			return fmt.Errorf("activating state requires activation_intent")
		}
		intent := record.ActivationIntent
		if strings.TrimSpace(intent.ID) == "" || intent.JobID == "" || intent.PlanID == "" || intent.Generation == 0 || intent.Candidate.Generation != intent.Generation {
			return fmt.Errorf("activation_intent identity, job, Plan, and generation are required")
		}
		if err := validateBundle(intent.Candidate, kind); err != nil {
			return fmt.Errorf("activation_intent.candidate: %w", err)
		}
		if intent.Candidate.ConfigDigest != currentConfigDigest {
			return fmt.Errorf("activation_intent.candidate must bind current_config_digest")
		}
		if err := validateCandidateMatchesPublication(intent.Candidate, publication); err != nil {
			return fmt.Errorf("activation_intent.candidate: %w", err)
		}
		switch intent.PriorState {
		case PublicationUnpublished:
			if intent.Prior != nil {
				return fmt.Errorf("unpublished activation prior_state must not include a restorable prior bundle")
			}
		case PublicationPublished:
			if intent.Prior == nil || record.LastAppliedBundle == nil {
				return fmt.Errorf("published activation prior_state requires prior and last applied bundles")
			}
			if intent.Prior.Kind != kind {
				return fmt.Errorf("published activation prior kind cannot change")
			}
			if err := validateBundle(*intent.Prior, intent.Prior.Kind); err != nil {
				return fmt.Errorf("activation_intent.prior: %w", err)
			}
			if !publicationBundlesEqual(*intent.Prior, *record.LastAppliedBundle) {
				return fmt.Errorf("activation_intent.prior must match last_applied_bundle")
			}
		default:
			return fmt.Errorf("activation_intent.prior_state %q is not supported", intent.PriorState)
		}
	default:
		return fmt.Errorf("publication_record.state %q is not supported", record.State)
	}
	appliedEdgeOne := record.LastAppliedBundle != nil && record.LastAppliedBundle.DomainHTTPS != nil && record.LastAppliedBundle.DomainHTTPS.EdgeOne.Enabled
	if record.EffectiveSecurity != nil && !appliedEdgeOne {
		return fmt.Errorf("effective_security requires an applied EdgeOne bundle")
	}
	if record.State == PublicationPublished && appliedEdgeOne && record.EffectiveSecurity == nil {
		return fmt.Errorf("published EdgeOne bundle requires effective_security")
	}
	if appliedEdgeOne && record.EffectiveSecurity != nil && record.EffectiveSecurity.Generation < record.LastAppliedBundle.DomainHTTPS.EdgeOne.InitialACLGeneration {
		return fmt.Errorf("effective_security generation predates the applied EdgeOne ACL generation")
	}
	if record.RuntimeObservation != nil {
		if err := validateRuntimeObservation(*record.RuntimeObservation); err != nil {
			return fmt.Errorf("runtime_observation: %w", err)
		}
	}
	if (record.LastOperation == "") != (record.LastOperationResult == "") {
		return fmt.Errorf("last_operation and last_operation_result must both be present or absent")
	}
	if record.LastOperation != "" {
		if _, err := ParseOperationCode(string(record.LastOperation)); err != nil {
			return err
		}
		if _, err := ParseOperationResult(string(record.LastOperationResult)); err != nil {
			return err
		}
	}
	if record.LastJobID != "" && (record.LastJobID != strings.TrimSpace(record.LastJobID) || strings.ContainsAny(record.LastJobID, "\r\n")) {
		return fmt.Errorf("last_job_id must be trimmed")
	}
	return nil
}

func validateRuntimeObservation(observation RuntimeObservation) error {
	switch observation.Status {
	case RuntimeHealthy, RuntimeDegraded, RuntimeUnknown:
	default:
		return fmt.Errorf("status %q is not supported", observation.Status)
	}
	if _, err := time.Parse(time.RFC3339, observation.ObservedAt); err != nil {
		return fmt.Errorf("observed_at must be RFC3339: %w", err)
	}
	return nil
}

func validateBundle(bundle PublicationBundle, kind PublicationKind) error {
	if strings.TrimSpace(bundle.ID) == "" || bundle.Generation == 0 || strings.TrimSpace(bundle.EndpointIdentity) == "" || strings.TrimSpace(bundle.SiteIdentity) == "" {
		return fmt.Errorf("id, endpoint_identity, and site_identity are required")
	}
	if !validSHA256Digest(bundle.ConfigDigest) {
		return fmt.Errorf("config_digest must be sha256:<64 lowercase hex>")
	}
	if bundle.Kind != kind {
		return fmt.Errorf("kind %q does not match publication kind %q", bundle.Kind, kind)
	}
	if err := validatePaths("bundle.managed_paths", bundle.ManagedPaths); err != nil {
		return err
	}
	seenCredentials := map[string]struct{}{}
	for _, credentialID := range bundle.CredentialIDs {
		if !strings.HasPrefix(credentialID, "cred_") || !idPattern.MatchString(credentialID) {
			return fmt.Errorf("bundle credential_id %q is invalid", credentialID)
		}
		if _, duplicate := seenCredentials[credentialID]; duplicate {
			return fmt.Errorf("bundle credential_id %q is duplicated", credentialID)
		}
		seenCredentials[credentialID] = struct{}{}
	}
	seenListeners := map[string]struct{}{}
	for _, listener := range bundle.Listeners {
		if (listener.Network != "tcp" && listener.Network != "udp") || listener.Port == 0 {
			return fmt.Errorf("bundle listener must use tcp|udp and a nonzero port")
		}
		key := fmt.Sprintf("%s:%d", listener.Network, listener.Port)
		if _, duplicate := seenListeners[key]; duplicate {
			return fmt.Errorf("bundle listener %q is duplicated", key)
		}
		seenListeners[key] = struct{}{}
	}
	switch bundle.Kind {
	case PublicationDomainHTTPS:
		if bundle.DomainHTTPS == nil || bundle.TemporaryHTTP != nil {
			return fmt.Errorf("domain_https bundle must contain only domain_https identity")
		}
		identity := bundle.DomainHTTPS
		if len(identity.ExactDomains) == 0 {
			return fmt.Errorf("domain_https.exact_domains must not be empty")
		}
		seen := map[string]struct{}{}
		for _, exactDomain := range identity.ExactDomains {
			if err := validateDomain(exactDomain); err != nil {
				return fmt.Errorf("domain_https.exact_domains: %w", err)
			}
			if _, duplicate := seen[exactDomain]; duplicate {
				return fmt.Errorf("domain_https exact domain %q is duplicated", exactDomain)
			}
			seen[exactDomain] = struct{}{}
		}
		certificate := identity.Certificate
		if certificate.PointerIdentity == "" || certificate.BindingIdentity == "" || certificate.PointerIdentity != strings.TrimSpace(certificate.PointerIdentity) || certificate.BindingIdentity != strings.TrimSpace(certificate.BindingIdentity) {
			return fmt.Errorf("domain_https certificate pointer and binding identities are required")
		}
		if certificate.Generation == 0 || !validSHA256Digest(certificate.Fingerprint) || !validSHA256Digest(certificate.SANIdentity) || !validSHA256Digest(certificate.ChainIdentity) || !validSHA256Digest(certificate.IssuerIdentity) {
			return fmt.Errorf("domain_https certificate complete identity is invalid")
		}
		deadline, err := time.Parse(time.RFC3339, certificate.NotAfter)
		wall, wallErr := time.Parse(time.RFC3339, certificate.LastTrustedWall)
		if err != nil || wallErr != nil || deadline.IsZero() || wall.IsZero() || deadline.Before(wall) {
			return fmt.Errorf("domain_https certificate deadline evidence invalid")
		}
		switch identity.Auth.Mode {
		case AppAccessPublic, AppAccessApplicationManaged:
			if identity.Auth.CredentialIdentity != "" || identity.Auth.ReferenceIdentity != "" {
				return fmt.Errorf("domain_https %s auth must not include credential identity", identity.Auth.Mode)
			}
		case AppAccessBasic:
			if !strings.HasPrefix(identity.Auth.CredentialIdentity, "cred_") || !validSHA256Digest(identity.Auth.ReferenceIdentity) {
				return fmt.Errorf("domain_https basic auth requires complete credential identity")
			}
		default:
			return fmt.Errorf("domain_https auth mode %q is not supported", identity.Auth.Mode)
		}
		if (identity.Static.RootID == "") != (len(identity.Static.Routes) == 0) || len(identity.Static.Routes) != len(identity.Static.RouteIdentities) {
			return fmt.Errorf("domain_https static bundle inventory incomplete")
		}
		for index, route := range identity.Static.Routes {
			if !strings.HasPrefix(identity.Static.RootID, "static_") || !validStaticURL(route.URLPath, route.Directory) || route.RelativePath == "" || filepath.IsAbs(route.RelativePath) || filepath.Clean(route.RelativePath) != route.RelativePath || !cleanAbsolutePath(route.SourcePath) || !validSHA256Digest(route.Fingerprint) || index > 0 && identity.Static.Routes[index-1].URLPath >= route.URLPath {
				return fmt.Errorf("domain_https static route bundle invalid")
			}
		}
		seenRoutes := map[string]struct{}{}
		for _, routeIdentity := range identity.Static.RouteIdentities {
			if routeIdentity == "" || routeIdentity != strings.TrimSpace(routeIdentity) {
				return fmt.Errorf("domain_https static route identity is invalid")
			}
			if _, duplicate := seenRoutes[routeIdentity]; duplicate {
				return fmt.Errorf("domain_https static route identity %q is duplicated", routeIdentity)
			}
			seenRoutes[routeIdentity] = struct{}{}
		}
		if identity.GoAccess.Enabled {
			if identity.GoAccess.RouteIdentity == "" || identity.GoAccess.ServiceIdentity == "" {
				return fmt.Errorf("enabled GoAccess requires route and service identities")
			}
		} else if identity.GoAccess.RouteIdentity != "" || identity.GoAccess.ServiceIdentity != "" {
			return fmt.Errorf("disabled GoAccess must not include route or service identity")
		}
		if identity.EdgeOne.Enabled {
			if identity.Auth.Mode != AppAccessPublic || identity.GoAccess.Enabled {
				return fmt.Errorf("enabled EdgeOne requires public auth and disabled GoAccess")
			}
			if identity.EdgeOne.PublishBinding == "" || identity.EdgeOne.InitialACLGeneration == 0 {
				return fmt.Errorf("enabled EdgeOne requires publish binding and initial ACL generation")
			}
		} else if identity.EdgeOne.PublishBinding != "" || identity.EdgeOne.InitialACLGeneration != 0 {
			return fmt.Errorf("disabled EdgeOne must not include publish binding or ACL generation")
		}
	case PublicationTemporaryHTTP:
		if bundle.TemporaryHTTP == nil || bundle.DomainHTTPS != nil {
			return fmt.Errorf("temporary_ip_http bundle must contain only temporary_ip_http identity")
		}
		identity := bundle.TemporaryHTTP
		if err := ValidateTemporaryPublicIPv4(identity.PublicIPv4); err != nil {
			return err
		}
		if identity.Port < 1024 || identity.Port == 80 || identity.Port == 443 {
			return fmt.Errorf("temporary_ip_http.port must be in 1024..65535 and not 80 or 443")
		}
		expectedAuthority := fmt.Sprintf("%s:%d", identity.PublicIPv4, identity.Port)
		if identity.HostAuthority != expectedAuthority {
			return fmt.Errorf("temporary_ip_http.host_authority must be %q", expectedAuthority)
		}
		if identity.ListenerIdentity == "" || identity.ListenerIdentity != strings.TrimSpace(identity.ListenerIdentity) {
			return fmt.Errorf("temporary_ip_http.listener_identity is required")
		}
	default:
		return fmt.Errorf("bundle kind %q is not supported", bundle.Kind)
	}
	return nil
}

func publicationBundlesEqual(left, right PublicationBundle) bool {
	return reflect.DeepEqual(left, right)
}

func validateCandidateMatchesPublication(candidate PublicationBundle, publication AppPublication) error {
	switch publication.Kind {
	case PublicationDomainHTTPS:
		expectedDomains := append([]string{publication.DomainHTTPS.CanonicalDomain}, publication.DomainHTTPS.Aliases...)
		slices.Sort(expectedDomains)
		candidateDomains := []string(nil)
		if candidate.DomainHTTPS != nil {
			candidateDomains = append(candidateDomains, candidate.DomainHTTPS.ExactDomains...)
			slices.Sort(candidateDomains)
		}
		if candidate.DomainHTTPS == nil || !reflect.DeepEqual(candidateDomains, expectedDomains) {
			return fmt.Errorf("domain identity must match current publication exact domains")
		}
		if candidate.DomainHTTPS.Auth.Mode != publication.DomainHTTPS.AccessMode {
			return fmt.Errorf("auth identity must match current publication access mode")
		}
		if publication.DomainHTTPS.AccessMode == AppAccessBasic && candidate.DomainHTTPS.Auth.CredentialIdentity != publication.DomainHTTPS.CredentialID {
			return fmt.Errorf("auth identity must match current publication credential")
		}
	case PublicationTemporaryHTTP:
		if candidate.TemporaryHTTP == nil ||
			candidate.TemporaryHTTP.PublicIPv4 != publication.TemporaryHTTP.PublicIPv4 ||
			candidate.TemporaryHTTP.Port != publication.TemporaryHTTP.Port {
			return fmt.Errorf("temporary identity must match current public IPv4 and port")
		}
	default:
		return fmt.Errorf("publication kind %q is not supported", publication.Kind)
	}
	return nil
}

func ValidateTemporaryPublicIPv4(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value || !address.IsGlobalUnicast() {
		return fmt.Errorf("temporary_ip_http.public_ipv4 must be a canonical publicly routable IPv4 literal")
	}
	for _, prefix := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4")} {
		if prefix.Contains(address) {
			return fmt.Errorf("temporary_ip_http.public_ipv4 must be a canonical publicly routable IPv4 literal")
		}
	}
	return nil
}

func validateDomain(value string) error {
	if value == "" || value != strings.ToLower(value) || value != strings.TrimSpace(value) || strings.HasSuffix(value, ".") || strings.Contains(value, "*") || len(value) > 253 {
		return fmt.Errorf("must be a canonical lowercase exact domain without wildcard or trailing dot")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return fmt.Errorf("must contain at least two labels")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("contains an invalid label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("contains an invalid label character")
			}
		}
	}
	return nil
}

func validateHTTPSURL(value string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return fmt.Errorf("must be an exact HTTPS URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("must be a hierarchical HTTPS URL without userinfo, query, or fragment")
	}
	return nil
}

func canonicalHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Opaque == "" && parsed.String() == value
}
func cleanAbsolutePath(value string) bool {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
func validDNSProvider(value string) bool {
	switch value {
	case "cloudflare", "route53", "digitalocean", "gcloud", "tencentcloud":
		return true
	default:
		return false
	}
}

func validateReadinessPath(value string) error {
	if value == "" || len(value) > 2048 || value != strings.TrimSpace(value) || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\%") {
		return fmt.Errorf("must be a normalized absolute HTTP path")
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return fmt.Errorf("must be a normalized absolute HTTP path")
		}
	}
	segments := strings.Split(value, "/")
	for index, segment := range segments[1:] {
		isTrailing := index == len(segments)-2
		if segment == "." || segment == ".." || (segment == "" && !isTrailing) {
			return fmt.Errorf("must be a normalized absolute HTTP path")
		}
	}
	return nil
}

func validOpaqueTargetID(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateDisplayName(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return fmt.Errorf("must be nonempty, trimmed, and at most 128 bytes")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

func validatePaths(label string, paths []string) error {
	seen := map[string]struct{}{}
	for index, path := range paths {
		if err := validateManagedPath(path); err != nil {
			return fmt.Errorf("%s[%d]: %w", label, index, err)
		}
		if _, duplicate := seen[path]; duplicate {
			return fmt.Errorf("%s contains duplicate path %q", label, path)
		}
		seen[path] = struct{}{}
	}
	return nil
}

func validateManagedPath(path string) error {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("must be a clean absolute non-root path")
	}
	return nil
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
