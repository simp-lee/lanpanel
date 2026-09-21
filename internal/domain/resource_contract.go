package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// LocalResourceCreateRequest is the user-owned portion of a local_http
// resource. Resource and process identities, applied bundles, and lifecycle
// state are deliberately not part of this request.
type LocalResourceCreateRequest struct {
	Name                string             `json:"name"`
	EndpointKind        LocalEndpointKind  `json:"endpoint_kind"`
	TCPAddress          string             `json:"tcp_address,omitempty"`
	TCPPort             uint16             `json:"tcp_port,omitempty"`
	ReadinessPath       string             `json:"readiness_path"`
	AllowedHTTPStatuses []uint16           `json:"allowed_http_statuses"`
	WebSocket           WebSocketReadiness `json:"websocket"`
	Executable          string             `json:"executable"`
	Arguments           []string           `json:"arguments"`
	WorkingDirectory    string             `json:"working_directory"`
	EnvironmentFile     string             `json:"environment_file,omitempty"`
	WritePaths          []string           `json:"write_paths"`
	Publication         AppPublication     `json:"publication"`
	CredentialIDs       []string           `json:"credential_ids,omitempty"`
}

// TailnetResourceCreateRequest is a fixed remote upstream declaration. It
// contains no local process or remote-control fields.
type TailnetResourceCreateRequest struct {
	Name                string             `json:"name"`
	PeerIP              string             `json:"peer_ip"`
	SourceIP            string             `json:"source_ip"`
	Port                uint16             `json:"port"`
	ReadinessPath       string             `json:"readiness_path"`
	AllowedHTTPStatuses []uint16           `json:"allowed_http_statuses"`
	WebSocket           WebSocketReadiness `json:"websocket"`
	Publication         AppPublication     `json:"publication"`
	CredentialIDs       []string           `json:"credential_ids,omitempty"`
}

const DomainPublicationUpdateSchema = "lanpanel.domain-publication.update.v1"

type DomainPublicationUpdate struct {
	SchemaVersion string                 `json:"schema_version"`
	ResourceID    string                 `json:"resource_id"`
	Publication   DomainHTTPSPublication `json:"publication"`
}

func ValidateDomainPublicationUpdate(value DomainPublicationUpdate) error {
	if value.SchemaVersion != DomainPublicationUpdateSchema || !strings.HasPrefix(value.ResourceID, "res_") || !idPattern.MatchString(value.ResourceID) {
		return fmt.Errorf("domain publication update identity is invalid")
	}
	if err := validatePublication(AppPublication{Kind: PublicationDomainHTTPS, DomainHTTPS: &value.Publication}); err != nil {
		return err
	}
	return nil
}

// ResourceCreateRequest is a closed one-of for the two supported resource
// kinds. The helper accepts this DTO, never a complete AppResource.
type ResourceCreateRequest struct {
	TargetKind AppTargetKind                 `json:"target_kind"`
	Local      *LocalResourceCreateRequest   `json:"local,omitempty"`
	Tailnet    *TailnetResourceCreateRequest `json:"tailnet,omitempty"`
}

type LocalResourceUpdateRequest struct {
	Name                string             `json:"name"`
	EndpointKind        LocalEndpointKind  `json:"endpoint_kind"`
	TCPAddress          string             `json:"tcp_address,omitempty"`
	TCPPort             uint16             `json:"tcp_port,omitempty"`
	ReadinessPath       string             `json:"readiness_path"`
	AllowedHTTPStatuses []uint16           `json:"allowed_http_statuses"`
	WebSocket           WebSocketReadiness `json:"websocket"`
	Executable          string             `json:"executable"`
	Arguments           []string           `json:"arguments"`
	WorkingDirectory    string             `json:"working_directory"`
	EnvironmentFile     string             `json:"environment_file,omitempty"`
	WritePaths          []string           `json:"write_paths"`
	Publication         AppPublication     `json:"publication"`
	CredentialIDs       []string           `json:"credential_ids,omitempty"`
}

type TailnetResourceUpdateRequest struct {
	Name                string             `json:"name"`
	PeerIP              string             `json:"peer_ip"`
	SourceIP            string             `json:"source_ip"`
	Port                uint16             `json:"port"`
	ReadinessPath       string             `json:"readiness_path"`
	AllowedHTTPStatuses []uint16           `json:"allowed_http_statuses"`
	WebSocket           WebSocketReadiness `json:"websocket"`
	Publication         AppPublication     `json:"publication"`
	CredentialIDs       []string           `json:"credential_ids,omitempty"`
}

// ResourceUpdateRequest is bound to the resource target in the enclosing
// helper request. It has no client-controlled resource identity or authority.
type ResourceUpdateRequest struct {
	TargetKind AppTargetKind                 `json:"target_kind"`
	Local      *LocalResourceUpdateRequest   `json:"local,omitempty"`
	Tailnet    *TailnetResourceUpdateRequest `json:"tailnet,omitempty"`
}

func ValidateResourceCreateRequest(value ResourceCreateRequest) error {
	switch value.TargetKind {
	case AppTargetLocalHTTP:
		if value.Local == nil || value.Tailnet != nil {
			return fmt.Errorf("local resource request must contain only local")
		}
		return validateLocalRequest(value.Local.Name, value.Local.EndpointKind, value.Local.TCPAddress, value.Local.TCPPort, value.Local.ReadinessPath, value.Local.AllowedHTTPStatuses, value.Local.WebSocket, value.Local.Executable, value.Local.Arguments, value.Local.WorkingDirectory, value.Local.EnvironmentFile, value.Local.WritePaths, value.Local.Publication, value.Local.CredentialIDs)
	case AppTargetTailnetHTTP:
		if value.Tailnet == nil || value.Local != nil {
			return fmt.Errorf("tailnet resource request must contain only tailnet")
		}
		return validateTailnetRequest(value.Tailnet.Name, value.Tailnet.PeerIP, value.Tailnet.SourceIP, value.Tailnet.Port, value.Tailnet.ReadinessPath, value.Tailnet.AllowedHTTPStatuses, value.Tailnet.WebSocket, value.Tailnet.Publication, value.Tailnet.CredentialIDs)
	default:
		return fmt.Errorf("resource request target kind %q is unsupported", value.TargetKind)
	}
}

func ValidateResourceUpdateRequest(value ResourceUpdateRequest) error {
	switch value.TargetKind {
	case AppTargetLocalHTTP:
		if value.Local == nil || value.Tailnet != nil {
			return fmt.Errorf("local resource update must contain only local")
		}
		return validateLocalRequest(value.Local.Name, value.Local.EndpointKind, value.Local.TCPAddress, value.Local.TCPPort, value.Local.ReadinessPath, value.Local.AllowedHTTPStatuses, value.Local.WebSocket, value.Local.Executable, value.Local.Arguments, value.Local.WorkingDirectory, value.Local.EnvironmentFile, value.Local.WritePaths, value.Local.Publication, value.Local.CredentialIDs)
	case AppTargetTailnetHTTP:
		if value.Tailnet == nil || value.Local != nil {
			return fmt.Errorf("tailnet resource update must contain only tailnet")
		}
		return validateTailnetRequest(value.Tailnet.Name, value.Tailnet.PeerIP, value.Tailnet.SourceIP, value.Tailnet.Port, value.Tailnet.ReadinessPath, value.Tailnet.AllowedHTTPStatuses, value.Tailnet.WebSocket, value.Tailnet.Publication, value.Tailnet.CredentialIDs)
	default:
		return fmt.Errorf("resource update target kind %q is unsupported", value.TargetKind)
	}
}

func validateLocalRequest(name string, endpoint LocalEndpointKind, address string, port uint16, readiness string, statuses []uint16, websocket WebSocketReadiness, executable string, arguments []string, workingDirectory string, environmentFile string, writePaths []string, publication AppPublication, credentialIDs []string) error {
	if err := validateDisplayName(name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if err := validateTarget(AppTarget{Kind: AppTargetLocalHTTP, ReadinessPath: readiness, AllowedHTTPStatuses: statuses, WebSocket: websocket, LocalHTTP: &LocalHTTPTarget{EndpointKind: endpoint, TCPAddress: address, TCPPort: port}}); err != nil {
		return err
	}
	service := ManagedService{Executable: executable, Arguments: arguments, WorkingDirectory: workingDirectory, EnvironmentFile: environmentFile, WritePaths: writePaths}
	if err := validateManagedService(service); err != nil {
		return fmt.Errorf("service: %w", err)
	}
	if err := validatePublication(publication); err != nil {
		return err
	}
	return validateRequestCredentialIDs(credentialIDs)
}

func validateTailnetRequest(name, peerText, sourceText string, port uint16, readiness string, statuses []uint16, websocket WebSocketReadiness, publication AppPublication, credentialIDs []string) error {
	if err := validateDisplayName(name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if err := validateTarget(AppTarget{Kind: AppTargetTailnetHTTP, ReadinessPath: readiness, AllowedHTTPStatuses: statuses, WebSocket: websocket, TailnetHTTP: &TailnetHTTPTarget{IP: peerText, SourceIP: sourceText, Port: port}}); err != nil {
		return err
	}
	if err := validatePublication(publication); err != nil {
		return err
	}
	return validateRequestCredentialIDs(credentialIDs)
}

func validateRequestCredentialIDs(values []string) error {
	prior := ""
	for _, value := range values {
		if !strings.HasPrefix(value, "cred_") || !idPattern.MatchString(value) || prior != "" && prior >= value {
			return fmt.Errorf("credential_ids must contain sorted unique credential identities")
		}
		prior = value
	}
	return nil
}

func ValidateAppPublication(value AppPublication) error { return validatePublication(value) }
func ValidateAppTarget(value AppTarget) error           { return validateTarget(value) }

// ResourceStatusOverall is intentionally separate from process and
// publication state. In particular, unpublished is not unreachable.
type ResourceStatusOverall string

const (
	ResourceStatusClosed      ResourceStatusOverall = "closed"
	ResourceStatusHealthy     ResourceStatusOverall = "healthy"
	ResourceStatusDegraded    ResourceStatusOverall = "degraded"
	ResourceStatusUnreachable ResourceStatusOverall = "unreachable"
	ResourceStatusUnknown     ResourceStatusOverall = "unknown"
)

type ResourceConfigurationStatus string

const (
	ConfigurationComplete   ResourceConfigurationStatus = "complete"
	ConfigurationIncomplete ResourceConfigurationStatus = "incomplete"
	ConfigurationInvalid    ResourceConfigurationStatus = "invalid"
	ConfigurationUnknown    ResourceConfigurationStatus = "unknown"
)

type ResourceProcessStatus string

const (
	ProcessNotApplicable ResourceProcessStatus = "not_applicable"
	ProcessRequestedRun  ResourceProcessStatus = "requested_running"
	ProcessRequestedStop ResourceProcessStatus = "requested_stopped"
	ProcessRunning       ResourceProcessStatus = "running"
	ProcessStopped       ResourceProcessStatus = "stopped"
	ProcessStarting      ResourceProcessStatus = "starting"
	ProcessStopping      ResourceProcessStatus = "stopping"
	ProcessUnknown       ResourceProcessStatus = "unknown"
)

type ResourcePublicationStatus string

const (
	PublicationStatusPublished   ResourcePublicationStatus = "published"
	PublicationStatusUnpublished ResourcePublicationStatus = "unpublished"
	PublicationStatusActivating  ResourcePublicationStatus = "activating"
	PublicationStatusContracting ResourcePublicationStatus = "contracting"
	PublicationStatusFenced      ResourcePublicationStatus = "fenced"
	PublicationStatusUnknown     ResourcePublicationStatus = "unknown"
)

type ResourceEvidenceStatus string

const (
	EvidenceNotApplicable ResourceEvidenceStatus = "not_applicable"
	EvidenceUnverified    ResourceEvidenceStatus = "unverified"
	EvidenceFresh         ResourceEvidenceStatus = "fresh"
	EvidenceExpired       ResourceEvidenceStatus = "expired"
	EvidenceUnreachable   ResourceEvidenceStatus = "unreachable"
	EvidenceUnknown       ResourceEvidenceStatus = "unknown"
)

type ConnectorBindingStatus string

const (
	ConnectorBindingNotApplicable ConnectorBindingStatus = "not_applicable"
	ConnectorBindingMissing       ConnectorBindingStatus = "missing"
	ConnectorBindingBound         ConnectorBindingStatus = "bound"
	ConnectorBindingUnknown       ConnectorBindingStatus = "unknown"
)

type ResourceAction string

const (
	ResourceActionEdit      ResourceAction = "edit"
	ResourceActionRefresh   ResourceAction = "refresh"
	ResourceActionStart     ResourceAction = "start"
	ResourceActionStop      ResourceAction = "stop"
	ResourceActionPublish   ResourceAction = "publish"
	ResourceActionUnpublish ResourceAction = "unpublish"
	ResourceActionRepublish ResourceAction = "republish"
	ResourceActionDelete    ResourceAction = "delete"
)

type ResourceFailureCategory string

const (
	FailureNone              ResourceFailureCategory = "none"
	FailureConfiguration     ResourceFailureCategory = "configuration_invalid"
	FailureAuthorityMissing  ResourceFailureCategory = "authority_missing"
	FailureAuthorityConflict ResourceFailureCategory = "authority_conflict"
	FailureEvidenceMissing   ResourceFailureCategory = "evidence_missing"
	FailureEvidenceExpired   ResourceFailureCategory = "evidence_expired"
	FailureEvidenceMismatch  ResourceFailureCategory = "evidence_mismatch"
	FailureCertificate       ResourceFailureCategory = "certificate_invalid"
	FailureConnectorDown     ResourceFailureCategory = "connector_unreachable"
	FailureRouteDown         ResourceFailureCategory = "route_unreachable"
	FailurePeerOffline       ResourceFailureCategory = "peer_offline"
	FailureTargetDown        ResourceFailureCategory = "target_unreachable"
	FailureTargetNotReady    ResourceFailureCategory = "target_not_ready"
	FailureHTTPStatus        ResourceFailureCategory = "http_status_disallowed"
	FailureWebSocket         ResourceFailureCategory = "websocket_not_ready"
	FailureProcess           ResourceFailureCategory = "process_not_running"
	FailurePublication       ResourceFailureCategory = "publication_fenced"
	FailureOperation         ResourceFailureCategory = "operation_failed"
)

type ConnectorValidity string

const (
	ConnectorObservationMissing ConnectorValidity = "missing"
	ConnectorObservationFresh   ConnectorValidity = "fresh"
	ConnectorObservationExpired ConnectorValidity = "expired"
	ConnectorObservationInvalid ConnectorValidity = "invalid"
)

type ConnectorObservation struct {
	ControlURL           string            `json:"control_url"`
	ClientVersion        string            `json:"client_version"`
	ClientIdentityDigest string            `json:"client_identity_digest"`
	LocalIdentityDigest  string            `json:"local_identity_digest"`
	Validity             ConnectorValidity `json:"validity"`
	ObservedAt           time.Time         `json:"observed_at"`
	ValidUntil           time.Time         `json:"valid_until"`
}

type RouteEvidence struct {
	PeerIP                  string                  `json:"peer_ip"`
	SourceIP                string                  `json:"source_ip"`
	Port                    uint16                  `json:"port"`
	PeerOnline              *bool                   `json:"peer_online"`
	ConnectorIdentityDigest string                  `json:"connector_identity_digest"`
	RouteIdentity           string                  `json:"route_identity"`
	Validity                ResourceEvidenceStatus  `json:"validity"`
	ObservedAt              time.Time               `json:"observed_at"`
	ValidUntil              time.Time               `json:"valid_until"`
	Failure                 ResourceFailureCategory `json:"failure"`
}

type TargetObservation struct {
	RouteIdentity     string                  `json:"route_identity"`
	PortConnected     bool                    `json:"port_connected"`
	HTTPReady         bool                    `json:"http_ready"`
	WebSocketRequired bool                    `json:"websocket_required"`
	WebSocketReady    bool                    `json:"websocket_ready"`
	HTTPStatus        uint16                  `json:"http_status"`
	Validity          ResourceEvidenceStatus  `json:"validity"`
	ObservedAt        time.Time               `json:"observed_at"`
	Failure           ResourceFailureCategory `json:"failure"`
}

type ResourceStatusCatalog struct {
	InstallationID string                 `json:"installation_id"`
	ObservedAt     time.Time              `json:"observed_at"`
	Resources      []ResourceStatusResult `json:"resources"`
}

func ValidateResourceStatusCatalog(value ResourceStatusCatalog) error {
	now := time.Now().UTC()
	if !strings.HasPrefix(value.InstallationID, "ins_") || !idPattern.MatchString(value.InstallationID) || value.ObservedAt.IsZero() || value.ObservedAt.After(now) || now.Sub(value.ObservedAt) > 5*time.Minute {
		return fmt.Errorf("resource status catalog identity is invalid")
	}
	prior := ""
	for _, resource := range value.Resources {
		if prior != "" && prior >= resource.ResourceID {
			return fmt.Errorf("resource status catalog is not sorted")
		}
		if resource.ObservedAt.After(value.ObservedAt) {
			return fmt.Errorf("resource status is observed after catalog")
		}
		if err := ValidateResourceStatusResult(resource); err != nil {
			return err
		}
		prior = resource.ResourceID
	}
	return nil
}

func ResourceStatusCatalogDigest(value ResourceStatusCatalog) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type ResourceDependencyKind string

const (
	DependencyManagedBasic     ResourceDependencyKind = "managed_basic"
	DependencyExternalHTPasswd ResourceDependencyKind = "external_htpasswd"
	DependencyStaticRoot       ResourceDependencyKind = "static_root"
)

type ResourceDependencyState string

const (
	DependencyBound     ResourceDependencyState = "bound"
	DependencyAvailable ResourceDependencyState = "available"
)

// ResourceDependencyStatus exposes only non-secret identities that the
// structured publication wizard may select. It never carries passwords,
// external file contents, or credential paths.
type ResourceDependencyStatus struct {
	ID              string                  `json:"id"`
	Kind            ResourceDependencyKind  `json:"kind"`
	State           ResourceDependencyState `json:"state"`
	OwnerResourceID string                  `json:"owner_resource_id"`
	Fingerprint     string                  `json:"fingerprint"`
}

// ResourceStatusConfiguration is the editable, typed configuration snapshot
// returned with status details. It contains no lifecycle authority or secret
// bytes and is suitable for repopulating the management wizard.
type ResourceStatusConfiguration struct {
	TargetKind AppTargetKind                 `json:"target_kind"`
	Local      *LocalResourceUpdateRequest   `json:"local,omitempty"`
	Tailnet    *TailnetResourceUpdateRequest `json:"tailnet,omitempty"`
}

// ResourceStatusConfigurationFor projects only user-editable configuration
// fields from a durable resource; process identities and publication authority
// remain outside this DTO.
func ResourceStatusConfigurationFor(resource AppResource) *ResourceStatusConfiguration {
	switch resource.Target.Kind {
	case AppTargetLocalHTTP:
		if resource.Target.LocalHTTP == nil || resource.ManagedProcess == nil {
			return nil
		}
		service := resource.ManagedProcess.Service
		return &ResourceStatusConfiguration{TargetKind: AppTargetLocalHTTP, Local: &LocalResourceUpdateRequest{
			Name: resource.Name, EndpointKind: resource.Target.LocalHTTP.EndpointKind, TCPAddress: resource.Target.LocalHTTP.TCPAddress, TCPPort: resource.Target.LocalHTTP.TCPPort,
			ReadinessPath: resource.Target.ReadinessPath, AllowedHTTPStatuses: append([]uint16(nil), resource.Target.AllowedHTTPStatuses...), WebSocket: resource.Target.WebSocket,
			Executable: service.Executable, Arguments: append([]string(nil), service.Arguments...), WorkingDirectory: service.WorkingDirectory, EnvironmentFile: service.EnvironmentFile,
			WritePaths: append([]string(nil), service.WritePaths...), Publication: resource.Publication, CredentialIDs: append([]string(nil), resource.CredentialIDs...),
		}}
	case AppTargetTailnetHTTP:
		if resource.Target.TailnetHTTP == nil {
			return nil
		}
		return &ResourceStatusConfiguration{TargetKind: AppTargetTailnetHTTP, Tailnet: &TailnetResourceUpdateRequest{
			Name: resource.Name, PeerIP: resource.Target.TailnetHTTP.IP, SourceIP: resource.Target.TailnetHTTP.SourceIP, Port: resource.Target.TailnetHTTP.Port,
			ReadinessPath: resource.Target.ReadinessPath, AllowedHTTPStatuses: append([]uint16(nil), resource.Target.AllowedHTTPStatuses...), WebSocket: resource.Target.WebSocket,
			Publication: resource.Publication, CredentialIDs: append([]string(nil), resource.CredentialIDs...),
		}}
	default:
		return nil
	}
}

type JobErrorCode string

var resourceStatusJobErrorCodes = map[JobErrorCode]struct{}{
	"activation_contracted": {}, "activation_restored_prior": {}, "admin_token_delivery_failed": {}, "admin_token_rotation_failed": {},
	"admin_token_rotation_interrupted": {}, "admin_token_source_unknown": {}, "binding_refresh_failed": {}, "certificate_remote_failed": {},
	"certificate_handoff_interrupted": {}, "certificate_executor_interrupted": {}, "certificate_setup_failed": {}, "confirmation_invalid": {},
	"confirmation_rejected": {}, "exact_reconciliation_closed": {}, "interrupted_lifecycle_contracted": {}, "managed_basic_interrupted": {},
	"managed_basic_hash_failed": {}, "managed_basic_generation_failed": {}, "managed_basic_revalidation_failed": {}, "static_root_registration_interrupted": {},
	"static_root_revalidation_failed": {}, "temporary_http_activation_recovery": {}, "temporary_http_no_effect": {}, "external_htpasswd_registration_interrupted": {},
	"external_htpasswd_revalidation_failed": {}, "foreign_database_evidence": {}, "goaccess_retirement_recovery": {}, "goaccess_staging_restored_prior": {},
	"goaccess_stop_failed": {}, "headscale_control_stop_fenced": {}, "headscale_deploy_revalidation_failed": {}, "headscale_user_create_failed": {},
	"preauth_key_create_failed": {}, "preauth_key_revoke_failed": {}, "device_expire_failed": {}, "connector_login_failed": {}, "connector_login_unknown": {},
	"headscale_lifecycle_interrupted": {}, "headscale_journal_failed": {}, "connector_mutation_interrupted": {}, "normal_revision_changed": {},
	"plan_consumption_rejected": {}, "planless_start_rejected": {}, "process_lifecycle_not_started": {}, "preflight_rejected": {},
	"publication_revalidation_failed": {}, "contraction_authority_failed": {}, "resource_create_not_started": {}, "resource_delete_not_started": {},
	"resource_update_not_started": {}, "safety_authority_changed": {}, "safety_recheck_unavailable": {}, "safety_refresh_failed": {},
}

type ResourceStatusResult struct {
	ResourceID             string                       `json:"resource_id"`
	Name                   string                       `json:"name"`
	TargetKind             AppTargetKind                `json:"target_kind"`
	TargetPeerIP           string                       `json:"target_peer_ip,omitempty"`
	TargetSourceIP         string                       `json:"target_source_ip,omitempty"`
	TargetPort             uint16                       `json:"target_port,omitempty"`
	OverallStatus          ResourceStatusOverall        `json:"overall_status"`
	ConfigurationStatus    ResourceConfigurationStatus  `json:"configuration_status"`
	ProcessRequestedStatus ResourceProcessStatus        `json:"process_requested_status"`
	ProcessObservedStatus  ResourceProcessStatus        `json:"process_observed_status"`
	ProcessStatus          ResourceProcessStatus        `json:"process_status"`
	PublicationStatus      ResourcePublicationStatus    `json:"publication_status"`
	ConnectorBindingStatus ConnectorBindingStatus       `json:"connector_binding_status"`
	ConnectorStatus        ResourceEvidenceStatus       `json:"connector_status"`
	RouteStatus            ResourceEvidenceStatus       `json:"route_status"`
	TargetStatus           ResourceEvidenceStatus       `json:"target_status"`
	FailureCategory        ResourceFailureCategory      `json:"failure_category"`
	AllowedActions         []ResourceAction             `json:"allowed_actions"`
	ClosureVerified        bool                         `json:"closure_verified"`
	ClosureDigest          string                       `json:"closure_digest"`
	ClosureObservedAt      time.Time                    `json:"closure_observed_at"`
	AffectedObject         string                       `json:"affected_object"`
	NextStep               string                       `json:"next_step"`
	LastOperation          OperationCode                `json:"last_operation"`
	JobID                  string                       `json:"job_id"`
	JobPending             bool                         `json:"job_pending"`
	JobResult              OperationResult              `json:"job_result"`
	JobErrorCode           JobErrorCode                 `json:"job_error_code"`
	ConfigDigest           string                       `json:"config_digest"`
	AuthorityDigest        string                       `json:"authority_digest"`
	ObservedAt             time.Time                    `json:"observed_at"`
	ConnectorObservation   *ConnectorObservation        `json:"connector_observation"`
	RouteEvidence          *RouteEvidence               `json:"route_evidence"`
	TargetObservation      *TargetObservation           `json:"target_observation"`
	Configuration          *ResourceStatusConfiguration `json:"configuration,omitempty"`
	Dependencies           []ResourceDependencyStatus   `json:"dependencies,omitempty"`
}

func ResourceStatusAuthorityDigest(resourceID, configDigest string) string {
	sum := sha256.Sum256([]byte(resourceID + "\x00" + configDigest))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TailnetConnectorIdentity(controlURL, clientVersion, clientIdentityDigest, localIdentityDigest string) string {
	sum := sha256.Sum256([]byte(controlURL + "\x00" + clientVersion + "\x00" + clientIdentityDigest + "\x00" + localIdentityDigest))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TailnetRouteIdentity(connectorIdentityDigest, peerIP, sourceIP string, port uint16) string {
	sum := sha256.Sum256([]byte(connectorIdentityDigest + "\x00" + peerIP + "\x00" + sourceIP + "\x00" + fmt.Sprint(port)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ResourceStatusDigest(value ResourceStatusResult) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateResourceStatusResult(value ResourceStatusResult) error {
	if !strings.HasPrefix(value.ResourceID, "res_") || !idPattern.MatchString(value.ResourceID) || validateDisplayName(value.Name) != nil || value.TargetKind != AppTargetLocalHTTP && value.TargetKind != AppTargetTailnetHTTP || !validSHA256Digest(value.ConfigDigest) || value.AuthorityDigest != ResourceStatusAuthorityDigest(value.ResourceID, value.ConfigDigest) || value.ObservedAt.IsZero() || !validOpaqueTargetID(value.AffectedObject) || !validStatusText(value.NextStep) || !validJobID(value.JobID) && value.JobID != "" || value.JobPending && value.JobID == "" || value.JobResult != "" && value.JobID == "" || value.JobID != "" && !value.JobPending && value.JobResult == "" || value.JobResult != "" && func() bool { _, err := ParseOperationResult(string(value.JobResult)); return err != nil }() || value.JobResult != "" && value.JobResult != OperationSucceeded && value.JobErrorCode == "" || value.JobErrorCode != "" && (!validJobErrorCode(value.JobErrorCode) || value.JobResult == "" || value.JobResult == OperationSucceeded) || value.JobPending && (value.JobResult != "" || value.JobErrorCode != "") || value.LastOperation != "" && func() bool { _, err := ParseOperationCode(string(value.LastOperation)); return err != nil }() || value.ClosureVerified && (!validSHA256Digest(value.ClosureDigest) || value.ClosureObservedAt.IsZero()) || !value.ClosureVerified && (value.ClosureDigest != "" || !value.ClosureObservedAt.IsZero()) {
		return fmt.Errorf("resource status identity is invalid")
	}
	if !validResourceStatusOverall(value.OverallStatus) || !validResourceConfiguration(value.ConfigurationStatus) || !validResourceProcess(value.ProcessRequestedStatus) || !validResourceProcess(value.ProcessObservedStatus) || !validResourceProcess(value.ProcessStatus) || !validResourcePublication(value.PublicationStatus) || !validConnectorBindingStatus(value.ConnectorBindingStatus) || !validEvidenceStatus(value.ConnectorStatus) || !validEvidenceStatus(value.RouteStatus) || !validEvidenceStatus(value.TargetStatus) || !validFailure(value.FailureCategory) || !validResourceActions(value.AllowedActions) {
		return fmt.Errorf("resource status enum is invalid")
	}
	if err := validateStatusCombination(value); err != nil {
		return err
	}
	if value.ConnectorObservation != nil {
		if err := validateConnectorObservation(*value.ConnectorObservation); err != nil {
			return err
		}
	} else if value.TargetKind == AppTargetTailnetHTTP && value.ConnectorStatus != EvidenceNotApplicable && value.ConnectorStatus != EvidenceUnknown {
		return fmt.Errorf("tailnet status lacks connector observation")
	}
	if value.RouteEvidence != nil {
		if err := validateRouteEvidence(*value.RouteEvidence); err != nil {
			return err
		}
	} else if value.TargetKind == AppTargetTailnetHTTP && value.RouteStatus != EvidenceNotApplicable && value.RouteStatus != EvidenceUnknown {
		return fmt.Errorf("tailnet status lacks route evidence")
	}
	if value.TargetObservation != nil {
		if err := validateTargetObservation(*value.TargetObservation); err != nil {
			return err
		}
	} else if value.TargetStatus != EvidenceNotApplicable && value.TargetStatus != EvidenceUnknown {
		return fmt.Errorf("status lacks target observation")
	}
	if value.TargetKind == AppTargetLocalHTTP && (value.ConnectorBindingStatus != ConnectorBindingNotApplicable || value.ConnectorStatus != EvidenceNotApplicable || value.RouteStatus != EvidenceNotApplicable || value.ConnectorObservation != nil || value.RouteEvidence != nil) {
		return fmt.Errorf("local status carries tailnet evidence")
	}
	if value.TargetKind == AppTargetTailnetHTTP && !validTailnetConnectorBindingStatus(value.ConnectorBindingStatus) {
		return fmt.Errorf("tailnet status connector binding state is invalid")
	}
	if value.TargetKind == AppTargetLocalHTTP && (value.TargetPeerIP != "" || value.TargetSourceIP != "" || value.TargetPort != 0) {
		return fmt.Errorf("local status carries tailnet endpoint authority")
	}
	if value.TargetKind == AppTargetTailnetHTTP {
		peer, peerErr := netip.ParseAddr(value.TargetPeerIP)
		source, sourceErr := netip.ParseAddr(value.TargetSourceIP)
		if peerErr != nil || sourceErr != nil || !peer.IsGlobalUnicast() || !source.IsGlobalUnicast() || peer.BitLen() != source.BitLen() || value.TargetPort == 0 {
			return fmt.Errorf("tailnet status endpoint authority is invalid")
		}
		if value.RouteEvidence != nil && (value.RouteEvidence.PeerIP != value.TargetPeerIP || value.RouteEvidence.SourceIP != value.TargetSourceIP || value.RouteEvidence.Port != value.TargetPort) {
			return fmt.Errorf("route evidence endpoint differs from resource authority")
		}
	}
	if err := validateResourceDependencies(value.Dependencies, value.ResourceID); err != nil {
		return err
	}
	if value.Configuration != nil {
		if value.Configuration.TargetKind != value.TargetKind {
			return fmt.Errorf("status configuration target differs from status")
		}
		if err := ValidateResourceUpdateRequest(ResourceUpdateRequest{TargetKind: value.Configuration.TargetKind, Local: value.Configuration.Local, Tailnet: value.Configuration.Tailnet}); err != nil {
			return fmt.Errorf("status configuration is invalid: %w", err)
		}
	}
	if value.OverallStatus == ResourceStatusClosed && !value.ClosureVerified {
		return fmt.Errorf("closed status lacks fresh closure evidence")
	}
	if value.OverallStatus != ResourceStatusClosed && value.ClosureVerified {
		return fmt.Errorf("non-closed status carries closure evidence")
	}
	if err := validateStatusFreshness(value, time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

func validateResourceDependencies(values []ResourceDependencyStatus, resourceID string) error {
	prior := ""
	for _, value := range values {
		if value.OwnerResourceID != resourceID || value.State != DependencyBound && value.State != DependencyAvailable || !validSHA256Digest(value.Fingerprint) {
			return fmt.Errorf("resource dependency authority is invalid")
		}
		switch value.Kind {
		case DependencyManagedBasic, DependencyExternalHTPasswd:
			if !strings.HasPrefix(value.ID, "cred_") || !idPattern.MatchString(value.ID) {
				return fmt.Errorf("resource credential dependency identity is invalid")
			}
		case DependencyStaticRoot:
			if !staticRootIDPattern.MatchString(value.ID) {
				return fmt.Errorf("resource static dependency identity is invalid")
			}
		default:
			return fmt.Errorf("resource dependency kind is invalid")
		}
		key := string(value.Kind) + "\x00" + value.ID
		if prior != "" && prior >= key {
			return fmt.Errorf("resource dependencies are not sorted")
		}
		prior = key
	}
	return nil
}

func validStatusText(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

func validJobID(value string) bool {
	if len(value) != len("job_")+64 || !strings.HasPrefix(value, "job_") {
		return false
	}
	digits := value[len("job_"):]
	if strings.ToLower(digits) != digits {
		return false
	}
	_, err := hex.DecodeString(digits)
	return err == nil
}

func validJobErrorCode(value JobErrorCode) bool {
	_, ok := resourceStatusJobErrorCodes[value]
	return ok
}

func validResourceStatusOverall(value ResourceStatusOverall) bool {
	return value == ResourceStatusClosed || value == ResourceStatusHealthy || value == ResourceStatusDegraded || value == ResourceStatusUnreachable || value == ResourceStatusUnknown
}

func validResourceConfiguration(value ResourceConfigurationStatus) bool {
	return value == ConfigurationComplete || value == ConfigurationIncomplete || value == ConfigurationInvalid || value == ConfigurationUnknown
}

func validResourceProcess(value ResourceProcessStatus) bool {
	return value == ProcessNotApplicable || value == ProcessRequestedRun || value == ProcessRequestedStop || value == ProcessRunning || value == ProcessStopped || value == ProcessStarting || value == ProcessStopping || value == ProcessUnknown
}

func validResourcePublication(value ResourcePublicationStatus) bool {
	return value == PublicationStatusPublished || value == PublicationStatusUnpublished || value == PublicationStatusActivating || value == PublicationStatusContracting || value == PublicationStatusFenced || value == PublicationStatusUnknown
}

func validEvidenceStatus(value ResourceEvidenceStatus) bool {
	return value == EvidenceNotApplicable || value == EvidenceUnverified || value == EvidenceFresh || value == EvidenceExpired || value == EvidenceUnreachable || value == EvidenceUnknown
}

func validConnectorBindingStatus(value ConnectorBindingStatus) bool {
	return value == ConnectorBindingNotApplicable || value == ConnectorBindingMissing || value == ConnectorBindingBound || value == ConnectorBindingUnknown
}

func validTailnetConnectorBindingStatus(value ConnectorBindingStatus) bool {
	return value == ConnectorBindingMissing || value == ConnectorBindingBound || value == ConnectorBindingUnknown
}

func validResourceActions(values []ResourceAction) bool {
	if values == nil {
		return false
	}
	prior := ResourceAction("")
	for _, value := range values {
		switch value {
		case ResourceActionEdit, ResourceActionRefresh, ResourceActionStart, ResourceActionStop, ResourceActionPublish, ResourceActionUnpublish, ResourceActionRepublish, ResourceActionDelete:
		default:
			return false
		}
		if prior != "" && prior >= value {
			return false
		}
		prior = value
	}
	return true
}

func validFailure(value ResourceFailureCategory) bool {
	switch value {
	case FailureNone, FailureConfiguration, FailureAuthorityMissing, FailureAuthorityConflict, FailureEvidenceMissing, FailureEvidenceExpired, FailureEvidenceMismatch, FailureCertificate, FailureConnectorDown, FailureRouteDown, FailurePeerOffline, FailureTargetDown, FailureTargetNotReady, FailureHTTPStatus, FailureWebSocket, FailureProcess, FailurePublication, FailureOperation:
		return true
	default:
		return false
	}
}

func validateStatusFreshness(value ResourceStatusResult, now time.Time) error {
	if now.IsZero() || value.ObservedAt.After(now) || now.Sub(value.ObservedAt) > 5*time.Minute {
		return fmt.Errorf("resource status observation is stale or from the future")
	}
	if value.ClosureVerified && (value.ClosureObservedAt.After(value.ObservedAt) || now.Sub(value.ClosureObservedAt) > 5*time.Minute) {
		return fmt.Errorf("closure evidence is stale or observed after status")
	}
	if value.ConnectorObservation != nil && value.ConnectorObservation.Validity == ConnectorObservationFresh {
		if value.ConnectorObservation.ObservedAt.After(value.ObservedAt) || !value.ConnectorObservation.ValidUntil.After(now) || now.Sub(value.ConnectorObservation.ObservedAt) > 5*time.Minute {
			return fmt.Errorf("fresh connector observation is stale for status")
		}
	}
	if value.ConnectorObservation != nil && value.ConnectorObservation.Validity != ConnectorObservationMissing {
		if value.ConnectorObservation.ObservedAt.After(now) || now.Sub(value.ConnectorObservation.ObservedAt) > 5*time.Minute {
			return fmt.Errorf("connector observation is stale or from the future")
		}
		if value.ConnectorObservation.Validity == ConnectorObservationExpired && value.ConnectorObservation.ValidUntil.After(now) {
			return fmt.Errorf("expired connector observation is not expired for status")
		}
	}
	if value.RouteEvidence != nil && value.RouteEvidence.Validity != EvidenceUnverified && value.RouteEvidence.Validity != EvidenceUnknown {
		if value.RouteEvidence.ObservedAt.After(value.ObservedAt) || value.RouteEvidence.ObservedAt.After(now) || now.Sub(value.RouteEvidence.ObservedAt) > 5*time.Minute {
			return fmt.Errorf("route evidence is stale or observed after status")
		}
		if value.RouteEvidence.Validity == EvidenceFresh && !value.RouteEvidence.ValidUntil.After(now) || value.RouteEvidence.Validity == EvidenceExpired && value.RouteEvidence.ValidUntil.After(now) {
			return fmt.Errorf("route evidence freshness does not match status")
		}
	}
	if value.TargetObservation != nil {
		if value.TargetObservation.ObservedAt.After(value.ObservedAt) || value.TargetObservation.ObservedAt.After(now) || now.Sub(value.TargetObservation.ObservedAt) > 5*time.Minute {
			return fmt.Errorf("target observation is stale or observed after status")
		}
	}
	if value.TargetKind == AppTargetTailnetHTTP && value.TargetStatus == EvidenceFresh && (value.TargetObservation == nil || value.TargetObservation.RouteIdentity == "") {
		return fmt.Errorf("fresh target observation lacks route identity")
	}
	if value.TargetStatus == EvidenceUnreachable && (value.TargetObservation == nil || value.TargetObservation.Validity != EvidenceUnreachable) {
		return fmt.Errorf("unreachable target status lacks unreachable observation")
	}
	if value.RouteStatus == EvidenceUnreachable && (value.RouteEvidence == nil || value.RouteEvidence.Validity != EvidenceUnreachable) {
		return fmt.Errorf("unreachable route status lacks unreachable evidence")
	}
	return nil
}

func validateStatusCombination(value ResourceStatusResult) error {
	if value.TargetKind == AppTargetLocalHTTP {
		if value.ProcessRequestedStatus != ProcessRequestedRun && value.ProcessRequestedStatus != ProcessRequestedStop || value.ProcessObservedStatus != ProcessUnknown && value.ProcessObservedStatus != ProcessRunning && value.ProcessObservedStatus != ProcessStopped && value.ProcessObservedStatus != ProcessStarting && value.ProcessObservedStatus != ProcessStopping || value.ProcessStatus == ProcessNotApplicable {
			return fmt.Errorf("local status process state is invalid")
		}
	} else if value.ProcessRequestedStatus != ProcessNotApplicable || value.ProcessObservedStatus != ProcessNotApplicable || value.ProcessStatus != ProcessNotApplicable {
		return fmt.Errorf("tailnet status carries local process state")
	}
	if value.ProcessObservedStatus != ProcessUnknown && value.ProcessObservedStatus != value.ProcessStatus {
		return fmt.Errorf("observed process state differs from effective process state")
	}
	failureRequired := value.OverallStatus == ResourceStatusDegraded || value.OverallStatus == ResourceStatusUnreachable || value.OverallStatus == ResourceStatusUnknown
	if failureRequired && value.FailureCategory == FailureNone || value.OverallStatus == ResourceStatusClosed && (value.PublicationStatus != PublicationStatusUnpublished || value.FailureCategory != FailureNone) || value.OverallStatus == ResourceStatusHealthy && (value.PublicationStatus != PublicationStatusPublished || value.ConfigurationStatus != ConfigurationComplete || value.FailureCategory != FailureNone || value.TargetStatus != EvidenceFresh) || value.OverallStatus == ResourceStatusDegraded && value.PublicationStatus != PublicationStatusPublished || value.OverallStatus == ResourceStatusHealthy && value.TargetKind == AppTargetLocalHTTP && (value.ProcessStatus != ProcessRunning || value.ConnectorStatus != EvidenceNotApplicable || value.RouteStatus != EvidenceNotApplicable) || value.OverallStatus == ResourceStatusHealthy && value.TargetKind == AppTargetTailnetHTTP && (value.ProcessStatus != ProcessNotApplicable || value.ConnectorStatus != EvidenceFresh || value.RouteStatus != EvidenceFresh) || value.OverallStatus == ResourceStatusUnreachable && (value.TargetKind != AppTargetTailnetHTTP || value.PublicationStatus != PublicationStatusPublished || value.ConnectorStatus != EvidenceUnreachable && value.RouteStatus != EvidenceUnreachable && value.TargetStatus != EvidenceUnreachable) || value.OverallStatus == ResourceStatusUnreachable && value.FailureCategory != FailureTargetDown && value.FailureCategory != FailureRouteDown && value.FailureCategory != FailureConnectorDown && value.FailureCategory != FailurePeerOffline {
		return fmt.Errorf("resource status overall and substate combination is invalid")
	}
	if value.JobPending && value.OverallStatus != ResourceStatusUnknown || (value.PublicationStatus == PublicationStatusActivating || value.PublicationStatus == PublicationStatusContracting || value.PublicationStatus == PublicationStatusFenced) && value.OverallStatus != ResourceStatusUnknown {
		return fmt.Errorf("in-progress or fenced resource status is not unknown")
	}
	if value.TargetKind == AppTargetTailnetHTTP && value.TargetStatus == EvidenceFresh && value.RouteStatus != EvidenceFresh {
		return fmt.Errorf("tailnet target evidence is not bound to fresh route evidence")
	}
	if value.TargetKind == AppTargetTailnetHTTP && value.RouteStatus == EvidenceFresh {
		if value.ConnectorStatus != EvidenceFresh || value.ConnectorObservation == nil || value.RouteEvidence == nil || value.RouteEvidence.ConnectorIdentityDigest != TailnetConnectorIdentity(value.ConnectorObservation.ControlURL, value.ConnectorObservation.ClientVersion, value.ConnectorObservation.ClientIdentityDigest, value.ConnectorObservation.LocalIdentityDigest) || value.RouteEvidence.RouteIdentity != TailnetRouteIdentity(value.RouteEvidence.ConnectorIdentityDigest, value.RouteEvidence.PeerIP, value.RouteEvidence.SourceIP, value.RouteEvidence.Port) {
			return fmt.Errorf("fresh route evidence is not bound to connector and endpoint authority")
		}
	}
	if value.RouteEvidence != nil && value.TargetObservation != nil && value.TargetObservation.RouteIdentity != "" && value.RouteEvidence.RouteIdentity != value.TargetObservation.RouteIdentity {
		return fmt.Errorf("target observation route identity differs from route evidence")
	}
	if value.ConnectorStatus == EvidenceFresh && (value.ConnectorObservation == nil || value.ConnectorObservation.Validity != ConnectorObservationFresh) || value.ConnectorStatus == EvidenceExpired && (value.ConnectorObservation == nil || value.ConnectorObservation.Validity != ConnectorObservationExpired) || value.RouteStatus == EvidenceFresh && (value.RouteEvidence == nil || value.RouteEvidence.Validity != EvidenceFresh) || value.RouteStatus == EvidenceExpired && (value.RouteEvidence == nil || value.RouteEvidence.Validity != EvidenceExpired) || value.TargetStatus == EvidenceFresh && (value.TargetObservation == nil || value.TargetObservation.Validity != EvidenceFresh) {
		return fmt.Errorf("resource status evidence state is not backed by matching observation")
	}
	if value.ConnectorStatus == EvidenceNotApplicable && value.TargetKind == AppTargetTailnetHTTP || value.RouteStatus == EvidenceNotApplicable && value.TargetKind == AppTargetTailnetHTTP {
		return fmt.Errorf("tailnet status omits required evidence stages")
	}
	return validateStatusActions(value)
}

func validateStatusActions(value ResourceStatusResult) error {
	if !hasResourceAction(value.AllowedActions, ResourceActionRefresh) {
		return fmt.Errorf("resource status cannot be refreshed")
	}
	transient := value.JobPending || value.OverallStatus == ResourceStatusUnknown || value.PublicationStatus == PublicationStatusUnknown || value.PublicationStatus == PublicationStatusActivating || value.PublicationStatus == PublicationStatusContracting || value.PublicationStatus == PublicationStatusFenced
	if transient && (len(value.AllowedActions) != 1 || value.AllowedActions[0] != ResourceActionRefresh) {
		return fmt.Errorf("transient resource status carries conflicting actions")
	}
	if value.TargetKind == AppTargetTailnetHTTP && (hasResourceAction(value.AllowedActions, ResourceActionStart) || hasResourceAction(value.AllowedActions, ResourceActionStop)) {
		return fmt.Errorf("tailnet status carries process actions")
	}
	if hasResourceAction(value.AllowedActions, ResourceActionStart) && (value.TargetKind != AppTargetLocalHTTP || value.ProcessRequestedStatus != ProcessRequestedStop || value.ProcessObservedStatus != ProcessStopped) || hasResourceAction(value.AllowedActions, ResourceActionStop) && (value.TargetKind != AppTargetLocalHTTP || value.ProcessRequestedStatus != ProcessRequestedRun || value.ProcessObservedStatus != ProcessRunning) {
		return fmt.Errorf("resource process action differs from current state")
	}
	publishable := value.OverallStatus == ResourceStatusClosed && value.PublicationStatus == PublicationStatusUnpublished && value.ConfigurationStatus == ConfigurationComplete && (value.TargetKind == AppTargetLocalHTTP && value.ProcessStatus == ProcessRunning && value.TargetStatus == EvidenceFresh || value.TargetKind == AppTargetTailnetHTTP && value.ConnectorStatus == EvidenceFresh && value.RouteStatus == EvidenceFresh && value.TargetStatus == EvidenceFresh)
	if hasResourceAction(value.AllowedActions, ResourceActionPublish) && !publishable || hasResourceAction(value.AllowedActions, ResourceActionUnpublish) && value.PublicationStatus != PublicationStatusPublished || hasResourceAction(value.AllowedActions, ResourceActionRepublish) && (value.PublicationStatus != PublicationStatusPublished || value.OverallStatus != ResourceStatusHealthy && value.OverallStatus != ResourceStatusDegraded) {
		return fmt.Errorf("resource publication action differs from current state")
	}
	processClosed := value.TargetKind == AppTargetTailnetHTTP && value.ProcessStatus == ProcessNotApplicable || value.TargetKind == AppTargetLocalHTTP && value.ProcessStatus == ProcessStopped
	if hasResourceAction(value.AllowedActions, ResourceActionDelete) && (!value.ClosureVerified || value.PublicationStatus != PublicationStatusUnpublished || !processClosed) {
		return fmt.Errorf("resource delete action lacks closure")
	}
	return nil
}

func hasResourceAction(values []ResourceAction, wanted ResourceAction) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validateConnectorObservation(value ConnectorObservation) error {
	if value.Validity != ConnectorObservationMissing && value.Validity != ConnectorObservationFresh && value.Validity != ConnectorObservationExpired && value.Validity != ConnectorObservationInvalid {
		return fmt.Errorf("connector observation validity is invalid")
	}
	if value.Validity == ConnectorObservationMissing {
		if value.ControlURL != "" || value.ClientVersion != "" || value.ClientIdentityDigest != "" || value.LocalIdentityDigest != "" || !value.ObservedAt.IsZero() || !value.ValidUntil.IsZero() {
			return fmt.Errorf("missing connector observation carries authority")
		}
		return nil
	}
	if err := validateHTTPSURL(value.ControlURL); err != nil || value.ClientVersion == "" || !validSHA256Digest(value.ClientIdentityDigest) || !validSHA256Digest(value.LocalIdentityDigest) || value.ObservedAt.IsZero() || value.ValidUntil.IsZero() || value.ValidUntil.Before(value.ObservedAt) {
		return fmt.Errorf("connector observation authority is invalid")
	}
	if value.Validity == ConnectorObservationFresh && !value.ValidUntil.After(value.ObservedAt) {
		return fmt.Errorf("fresh connector observation is not time-valid")
	}
	return nil
}

func validateRouteEvidence(value RouteEvidence) error {
	peer, peerErr := netip.ParseAddr(value.PeerIP)
	source, sourceErr := netip.ParseAddr(value.SourceIP)
	if peerErr != nil || sourceErr != nil || !peer.IsGlobalUnicast() || !source.IsGlobalUnicast() || peer.IsLoopback() || source.IsLoopback() || peer.BitLen() != source.BitLen() || value.Port == 0 || !validEvidenceStatus(value.Validity) || !validFailure(value.Failure) {
		return fmt.Errorf("route evidence authority is invalid")
	}
	if value.Failure == FailurePeerOffline && (value.Validity != EvidenceUnreachable || value.PeerOnline == nil || *value.PeerOnline) {
		return fmt.Errorf("peer offline route evidence lacks offline peer observation")
	}
	if value.Validity == EvidenceUnverified || value.Validity == EvidenceUnknown {
		if value.PeerOnline != nil || value.ConnectorIdentityDigest != "" || value.RouteIdentity != "" || !value.ObservedAt.IsZero() || !value.ValidUntil.IsZero() {
			return fmt.Errorf("unverified route evidence carries freshness authority")
		}
		return nil
	}
	if value.Validity == EvidenceFresh && (value.PeerOnline == nil || !*value.PeerOnline) {
		return fmt.Errorf("fresh route evidence lacks online peer observation")
	}
	if !validSHA256Digest(value.ConnectorIdentityDigest) || !validSHA256Digest(value.RouteIdentity) || value.ObservedAt.IsZero() || value.ValidUntil.IsZero() || value.ValidUntil.Before(value.ObservedAt) {
		return fmt.Errorf("route evidence freshness authority is invalid")
	}
	if value.Validity == EvidenceFresh && (value.Failure != FailureNone || !value.ValidUntil.After(value.ObservedAt)) || value.Validity == EvidenceUnreachable && value.Failure == FailureNone {
		return fmt.Errorf("route evidence validity and failure disagree")
	}
	return nil
}

func validateTargetObservation(value TargetObservation) error {
	if !validEvidenceStatus(value.Validity) || value.ObservedAt.IsZero() || value.HTTPStatus > 599 || !validFailure(value.Failure) || value.Validity == EvidenceFresh && (!value.PortConnected || !value.HTTPReady || value.WebSocketRequired && !value.WebSocketReady || value.Failure != FailureNone) || value.Validity == EvidenceUnreachable && value.Failure == FailureNone || value.WebSocketReady && !value.HTTPReady || value.HTTPReady && value.HTTPStatus < 100 {
		return fmt.Errorf("target observation is invalid")
	}
	if value.RouteIdentity != "" && !validSHA256Digest(value.RouteIdentity) {
		return fmt.Errorf("target observation route identity is invalid")
	}
	return nil
}
