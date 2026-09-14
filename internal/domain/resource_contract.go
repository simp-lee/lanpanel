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

type ResourceFailureCategory string

const (
	FailureNone              ResourceFailureCategory = "none"
	FailureConfiguration     ResourceFailureCategory = "configuration_invalid"
	FailureAuthorityMissing  ResourceFailureCategory = "authority_missing"
	FailureAuthorityConflict ResourceFailureCategory = "authority_conflict"
	FailureEvidenceMissing   ResourceFailureCategory = "evidence_missing"
	FailureEvidenceExpired   ResourceFailureCategory = "evidence_expired"
	FailureEvidenceMismatch  ResourceFailureCategory = "evidence_mismatch"
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

type ResourceStatusResult struct {
	ResourceID           string                      `json:"resource_id"`
	Name                 string                      `json:"name"`
	TargetKind           AppTargetKind               `json:"target_kind"`
	TargetPeerIP         string                      `json:"target_peer_ip,omitempty"`
	TargetSourceIP       string                      `json:"target_source_ip,omitempty"`
	TargetPort           uint16                      `json:"target_port,omitempty"`
	OverallStatus        ResourceStatusOverall       `json:"overall_status"`
	ConfigurationStatus  ResourceConfigurationStatus `json:"configuration_status"`
	ProcessStatus        ResourceProcessStatus       `json:"process_status"`
	PublicationStatus    ResourcePublicationStatus   `json:"publication_status"`
	ConnectorStatus      ResourceEvidenceStatus      `json:"connector_status"`
	RouteStatus          ResourceEvidenceStatus      `json:"route_status"`
	TargetStatus         ResourceEvidenceStatus      `json:"target_status"`
	FailureCategory      ResourceFailureCategory     `json:"failure_category"`
	ClosureVerified      bool                        `json:"closure_verified"`
	ClosureDigest        string                      `json:"closure_digest"`
	ClosureObservedAt    time.Time                   `json:"closure_observed_at"`
	AffectedObject       string                      `json:"affected_object"`
	NextStep             string                      `json:"next_step"`
	LastOperation        OperationCode               `json:"last_operation"`
	JobID                string                      `json:"job_id"`
	ConfigDigest         string                      `json:"config_digest"`
	AuthorityDigest      string                      `json:"authority_digest"`
	ObservedAt           time.Time                   `json:"observed_at"`
	ConnectorObservation *ConnectorObservation       `json:"connector_observation"`
	RouteEvidence        *RouteEvidence              `json:"route_evidence"`
	TargetObservation    *TargetObservation          `json:"target_observation"`
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
	if !strings.HasPrefix(value.ResourceID, "res_") || !idPattern.MatchString(value.ResourceID) || validateDisplayName(value.Name) != nil || value.TargetKind != AppTargetLocalHTTP && value.TargetKind != AppTargetTailnetHTTP || !validSHA256Digest(value.ConfigDigest) || value.AuthorityDigest != ResourceStatusAuthorityDigest(value.ResourceID, value.ConfigDigest) || value.ObservedAt.IsZero() || !validOpaqueTargetID(value.AffectedObject) || !validStatusText(value.NextStep) || !validOpaqueTargetID(value.JobID) && value.JobID != "" || value.LastOperation != "" && func() bool { _, err := ParseOperationCode(string(value.LastOperation)); return err != nil }() || value.ClosureVerified && (!validSHA256Digest(value.ClosureDigest) || value.ClosureObservedAt.IsZero()) || !value.ClosureVerified && (value.ClosureDigest != "" || !value.ClosureObservedAt.IsZero()) {
		return fmt.Errorf("resource status identity is invalid")
	}
	if !validResourceStatusOverall(value.OverallStatus) || !validResourceConfiguration(value.ConfigurationStatus) || !validResourceProcess(value.ProcessStatus) || !validResourcePublication(value.PublicationStatus) || !validEvidenceStatus(value.ConnectorStatus) || !validEvidenceStatus(value.RouteStatus) || !validEvidenceStatus(value.TargetStatus) || !validFailure(value.FailureCategory) {
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
	if value.TargetKind == AppTargetLocalHTTP && (value.ConnectorStatus != EvidenceNotApplicable || value.RouteStatus != EvidenceNotApplicable || value.ConnectorObservation != nil || value.RouteEvidence != nil) {
		return fmt.Errorf("local status carries tailnet evidence")
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

func validStatusText(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
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
func validFailure(value ResourceFailureCategory) bool {
	switch value {
	case FailureNone, FailureConfiguration, FailureAuthorityMissing, FailureAuthorityConflict, FailureEvidenceMissing, FailureEvidenceExpired, FailureEvidenceMismatch, FailureConnectorDown, FailureRouteDown, FailurePeerOffline, FailureTargetDown, FailureTargetNotReady, FailureHTTPStatus, FailureWebSocket, FailureProcess, FailurePublication, FailureOperation:
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
	if value.ConnectorObservation != nil && value.ConnectorObservation.Validity == ConnectorObservationExpired && value.ConnectorObservation.ValidUntil.After(now) {
		return fmt.Errorf("expired connector observation is not expired for status")
	}
	if value.RouteEvidence != nil && value.RouteEvidence.Validity != EvidenceUnverified && value.RouteEvidence.Validity != EvidenceUnknown {
		if value.RouteEvidence.ObservedAt.After(value.ObservedAt) || now.Sub(value.RouteEvidence.ObservedAt) > 5*time.Minute {
			return fmt.Errorf("route evidence is observed after status")
		}
		if value.RouteEvidence.Validity == EvidenceFresh && !value.RouteEvidence.ValidUntil.After(now) || value.RouteEvidence.Validity == EvidenceExpired && value.RouteEvidence.ValidUntil.After(now) {
			return fmt.Errorf("route evidence freshness does not match status")
		}
	}
	if value.TargetObservation != nil && (value.TargetObservation.ObservedAt.After(value.ObservedAt) || now.Sub(value.TargetObservation.ObservedAt) > 5*time.Minute) {
		return fmt.Errorf("target observation is observed after status")
	}
	if value.TargetKind == AppTargetTailnetHTTP && value.TargetStatus == EvidenceFresh && (value.TargetObservation == nil || value.TargetObservation.RouteIdentity == "") {
		return fmt.Errorf("fresh target observation lacks route identity")
	}
	return nil
}

func validateStatusCombination(value ResourceStatusResult) error {
	if value.OverallStatus == ResourceStatusClosed && (value.PublicationStatus != PublicationStatusUnpublished || value.FailureCategory != FailureNone) || value.OverallStatus == ResourceStatusHealthy && (value.PublicationStatus != PublicationStatusPublished || value.ConfigurationStatus != ConfigurationComplete || value.FailureCategory != FailureNone || value.TargetStatus != EvidenceFresh) || value.OverallStatus == ResourceStatusHealthy && value.TargetKind == AppTargetLocalHTTP && (value.ProcessStatus != ProcessRunning || value.ConnectorStatus != EvidenceNotApplicable || value.RouteStatus != EvidenceNotApplicable) || value.OverallStatus == ResourceStatusHealthy && value.TargetKind == AppTargetTailnetHTTP && (value.ProcessStatus != ProcessNotApplicable || value.ConnectorStatus != EvidenceFresh || value.RouteStatus != EvidenceFresh) || value.OverallStatus == ResourceStatusUnreachable && (value.TargetKind != AppTargetTailnetHTTP || value.FailureCategory == FailureNone || value.ConnectorStatus != EvidenceUnreachable && value.RouteStatus != EvidenceUnreachable && value.TargetStatus != EvidenceUnreachable) || value.OverallStatus == ResourceStatusUnreachable && value.FailureCategory != FailureTargetDown && value.FailureCategory != FailureRouteDown && value.FailureCategory != FailureConnectorDown && value.FailureCategory != FailurePeerOffline {
		return fmt.Errorf("resource status overall and substate combination is invalid")
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
	return nil
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
	if value.Validity == EvidenceUnverified || value.Validity == EvidenceUnknown {
		if value.ConnectorIdentityDigest != "" || value.RouteIdentity != "" || !value.ObservedAt.IsZero() || !value.ValidUntil.IsZero() {
			return fmt.Errorf("unverified route evidence carries freshness authority")
		}
		return nil
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
	if !validEvidenceStatus(value.Validity) || value.ObservedAt.IsZero() || value.HTTPStatus > 599 || !validFailure(value.Failure) || value.Validity == EvidenceFresh && (!value.PortConnected || !value.HTTPReady || value.WebSocketRequired && !value.WebSocketReady || value.Failure != FailureNone) || value.WebSocketReady && !value.HTTPReady || value.HTTPReady && value.HTTPStatus < 100 {
		return fmt.Errorf("target observation is invalid")
	}
	if value.RouteIdentity != "" && !validSHA256Digest(value.RouteIdentity) {
		return fmt.Errorf("target observation route identity is invalid")
	}
	return nil
}
