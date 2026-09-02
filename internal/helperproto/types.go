// Package helperproto defines the bounded typed UI/timer/recovery-to-helper protocol.
package helperproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = "lanpanel.helper.request.v1"

// Caller is derived only from SO_PEERCRED. It is never accepted from a frame.
type Caller string

const (
	CallerUI       Caller = "ui"
	CallerTimer    Caller = "timer"
	CallerRecovery Caller = "startup_recovery"
)

// Operation is the complete helper protocol operation vocabulary. None of the
// operations carries a command, argv, unit name, or filesystem path.
type Operation string

const (
	OperationApplicationPlan          Operation = "application_plan"
	OperationAdminTokenVerify         Operation = "admin_token_verify"
	OperationAdminTokenSource         Operation = "admin_token_source_status"
	OperationManagementProfile        Operation = "management_profile_status"
	OperationAdminTokenRotate         Operation = "admin_token_rotate"
	OperationAdminTokenReconcile      Operation = "admin_token_rotate_reconcile"
	OperationCertificateRenew         Operation = "certificate_renew"
	OperationManagedBasicGenerate     Operation = "managed_basic_generate"
	OperationManagedBasicDelete       Operation = "managed_basic_delete"
	OperationStaticRootRegister       Operation = "static_root_register"
	OperationExternalHTPasswdRegister Operation = "external_htpasswd_register"
	OperationDomainStatus             Operation = "domain_status"
	OperationContractionClose         Operation = "contraction_close"
	OperationStartupContraction       Operation = "startup_contraction"
	OperationHeadscaleInitialize      Operation = "headscale_initialize"
	OperationHeadscaleDeploy          Operation = "headscale_deploy"
	OperationHeadscaleReissue         Operation = "headscale_reissue"
	OperationHeadscaleRead            Operation = "headscale_read"
	OperationHeadscaleMutation        Operation = "headscale_mutation"
	OperationPreauthKeyPlan           Operation = "preauth_key_plan"
	OperationPreauthKeyCreate         Operation = "preauth_key_create"
	OperationConnectorMutation        Operation = "connector_mutation"
	OperationConnectorRead            Operation = "connector_read"
	OperationConnectorLoginPlan       Operation = "connector_login_plan"
	OperationConnectorLogin           Operation = "connector_login"
	OperationProductRead              Operation = "product_read"
	OperationResourceDelete           Operation = "resource_delete"
	OperationResourceMutation         Operation = "resource_mutation"
	OperationProcessLifecycle         Operation = "process_lifecycle"
	OperationPublicationActivate      Operation = "publication_activate"
)

type Policy struct {
	Callers         []Caller
	SecretInput     bool
	SecretOutput    bool
	MaximumDuration time.Duration
}

var policies = map[Operation]Policy{
	OperationApplicationPlan:          {Callers: []Caller{CallerUI}},
	OperationAdminTokenVerify:         {Callers: []Caller{CallerUI}, SecretInput: true},
	OperationAdminTokenSource:         {Callers: []Caller{CallerUI}},
	OperationManagementProfile:        {Callers: []Caller{CallerUI}},
	OperationAdminTokenRotate:         {Callers: []Caller{CallerUI}, SecretOutput: true},
	OperationAdminTokenReconcile:      {Callers: []Caller{CallerUI}},
	OperationCertificateRenew:         {Callers: []Caller{CallerUI, CallerTimer}},
	OperationManagedBasicGenerate:     {Callers: []Caller{CallerUI}, SecretOutput: true},
	OperationManagedBasicDelete:       {Callers: []Caller{CallerUI}},
	OperationStaticRootRegister:       {Callers: []Caller{CallerUI}},
	OperationExternalHTPasswdRegister: {Callers: []Caller{CallerUI}},
	OperationDomainStatus:             {Callers: []Caller{CallerUI}},
	OperationContractionClose:         {Callers: []Caller{CallerUI}},
	OperationStartupContraction:       {Callers: []Caller{CallerRecovery}},
	OperationHeadscaleInitialize:      {Callers: []Caller{CallerUI}, MaximumDuration: 6 * time.Minute},
	OperationHeadscaleDeploy:          {Callers: []Caller{CallerUI}, MaximumDuration: 12 * time.Minute},
	OperationHeadscaleReissue:         {Callers: []Caller{CallerUI}, MaximumDuration: 12 * time.Minute},
	OperationHeadscaleRead:            {Callers: []Caller{CallerUI}},
	OperationHeadscaleMutation:        {Callers: []Caller{CallerUI}},
	OperationPreauthKeyPlan:           {Callers: []Caller{CallerUI}},
	OperationPreauthKeyCreate:         {Callers: []Caller{CallerUI}, SecretOutput: true},
	OperationConnectorMutation:        {Callers: []Caller{CallerUI}},
	OperationConnectorRead:            {Callers: []Caller{CallerUI}},
	OperationConnectorLoginPlan:       {Callers: []Caller{CallerUI}},
	OperationConnectorLogin:           {Callers: []Caller{CallerUI}, SecretInput: true},
	OperationProductRead:              {Callers: []Caller{CallerUI}},
	OperationResourceDelete:           {Callers: []Caller{CallerUI}},
	OperationResourceMutation:         {Callers: []Caller{CallerUI}},
	OperationProcessLifecycle:         {Callers: []Caller{CallerUI}},
	OperationPublicationActivate:      {Callers: []Caller{CallerUI}, MaximumDuration: 11 * time.Minute},
}

var (
	refPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type ActionPayload struct {
	Operation            string `json:"operation"`
	TargetKind           string `json:"target_kind"`
	TargetID             string `json:"target_id,omitempty"`
	ActorIdentity        string `json:"actor_identity"`
	ActorGeneration      uint64 `json:"actor_generation"`
	PlanID               string `json:"plan_id,omitempty"`
	Confirmation         string `json:"confirmation,omitempty"`
	Username             string `json:"username,omitempty"`
	StaticRoot           string `json:"static_root_path,omitempty"`
	ExternalHTPasswdFile string `json:"external_htpasswd_path,omitempty"`
}
type ResourcePayload struct {
	Operation       string          `json:"operation"`
	ActorIdentity   string          `json:"actor_identity"`
	ActorGeneration uint64          `json:"actor_generation"`
	PlanID          string          `json:"plan_id,omitempty"`
	Confirmation    string          `json:"confirmation,omitempty"`
	Resource        json.RawMessage `json:"resource,omitempty"`
}

type ActionResult struct {
	PlanID             string    `json:"plan_id,omitempty"`
	Confirmation       string    `json:"confirmation,omitempty"`
	JobID              string    `json:"job_id,omitempty"`
	JobResult          string    `json:"job_result,omitempty"`
	Operation          string    `json:"operation,omitempty"`
	TargetKind         string    `json:"target_kind,omitempty"`
	TargetID           string    `json:"target_id,omitempty"`
	ExposureSummary    string    `json:"exposure_summary,omitempty"`
	Prerequisites      string    `json:"prerequisites,omitempty"`
	ExpiresAt          time.Time `json:"expires_at,omitzero"`
	ContractionOutcome string    `json:"contraction_outcome,omitempty"`
	AccessClosed       bool      `json:"access_closed,omitempty"`
	SharedIngressDown  bool      `json:"shared_ingress_down,omitempty"`
	AccessMayRemain    bool      `json:"access_may_remain,omitempty"`
	PublicURL          string    `json:"public_url,omitempty"`
}
type Request struct {
	SchemaVersion    string           `json:"schema_version"`
	RequestID        string           `json:"request_id"`
	Operation        Operation        `json:"operation"`
	Target           string           `json:"target"`
	IntentGeneration uint64           `json:"intent_generation"`
	Deadline         time.Time        `json:"deadline"`
	InputDigest      string           `json:"input_digest"`
	Action           *ActionPayload   `json:"action,omitempty"`
	Resource         *ResourcePayload `json:"resource,omitempty"`
}

type ResponseCode string

const (
	ResponseSucceeded ResponseCode = "succeeded"
	ResponseRejected  ResponseCode = "rejected"
	ResponseFailed    ResponseCode = "failed"
)

type HeadscaleUserRecord struct {
	ID             uint64    `json:"id"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"created_at"`
	DeviceCount    int       `json:"device_count"`
	ActiveKeyCount int       `json:"active_key_count"`
}
type HeadscaleKeyRecord struct {
	ID         uint64    `json:"id"`
	UserID     uint64    `json:"user_id"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"created_at"`
}
type HeadscaleDeviceRecord struct {
	ID          uint64    `json:"id"`
	Name        string    `json:"name"`
	UserID      uint64    `json:"user_id"`
	IPAddresses []string  `json:"ip_addresses"`
	Online      bool      `json:"online"`
	Expiry      time.Time `json:"expiry,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
}
type HeadscaleResult struct {
	Operation       string                  `json:"operation"`
	JobID           string                  `json:"job_id,omitempty"`
	PlanID          string                  `json:"plan_id,omitempty"`
	ExposureSummary string                  `json:"exposure_summary,omitempty"`
	Prerequisites   string                  `json:"prerequisites,omitempty"`
	ExpiresAt       time.Time               `json:"expires_at,omitzero"`
	Users           []HeadscaleUserRecord   `json:"users,omitempty"`
	Keys            []HeadscaleKeyRecord    `json:"keys,omitempty"`
	Devices         []HeadscaleDeviceRecord `json:"devices,omitempty"`
	User            *HeadscaleUserRecord    `json:"user,omitempty"`
	Key             *HeadscaleKeyRecord     `json:"key,omitempty"`
	Device          *HeadscaleDeviceRecord  `json:"device,omitempty"`
}

type ConnectorResult struct {
	Operation       string    `json:"operation"`
	JobID           string    `json:"job_id,omitempty"`
	PlanID          string    `json:"plan_id,omitempty"`
	ExposureSummary string    `json:"exposure_summary,omitempty"`
	Prerequisites   string    `json:"prerequisites,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitzero"`
	ClientVersion   string    `json:"client_version,omitempty"`
	ControlURL      string    `json:"control_url,omitempty"`
	LocalIPs        []string  `json:"local_ips,omitempty"`
	PeerIPs         []string  `json:"peer_ips,omitempty"`
	ValidUntil      time.Time `json:"valid_until,omitzero"`
}

type ReadResult struct {
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
}

type ResourceResult struct {
	ResourceID                    string    `json:"resource_id"`
	Status                        string    `json:"status,omitempty"`
	AccessMayRemain               bool      `json:"access_may_remain,omitempty"`
	CredentialID                  string    `json:"credential_id,omitempty"`
	CredentialFingerprint         string    `json:"credential_fingerprint,omitempty"`
	CredentialChanged             bool      `json:"credential_changed,omitempty"`
	GoAccessCredentialID          string    `json:"goaccess_credential_id,omitempty"`
	GoAccessCredentialFingerprint string    `json:"goaccess_credential_fingerprint,omitempty"`
	GoAccessCredentialChanged     bool      `json:"goaccess_credential_changed,omitempty"`
	StaticFingerprint             string    `json:"static_fingerprint,omitempty"`
	StaticChanged                 bool      `json:"static_changed,omitempty"`
	ObservedAt                    time.Time `json:"observed_at,omitempty"`
	Reason                        string    `json:"reason,omitempty"`
	AllowedActions                []string  `json:"allowed_actions,omitempty"`
	CredentialIDs                 []string  `json:"credential_ids,omitempty"`
	GoAccessRetirementJobID       string    `json:"goaccess_retirement_job_id,omitempty"`
	GoAccessRetirementGenerations []uint64  `json:"goaccess_retirement_generations,omitempty"`
}
type Response struct {
	SchemaVersion string           `json:"schema_version"`
	RequestID     string           `json:"request_id"`
	Code          ResponseCode     `json:"code"`
	ResultDigest  string           `json:"result_digest,omitempty"`
	ErrorCode     string           `json:"error_code,omitempty"`
	ErrorJobID    string           `json:"error_job_id,omitempty"`
	Action        *ActionResult    `json:"action,omitempty"`
	Resource      *ResourceResult  `json:"resource,omitempty"`
	Headscale     *HeadscaleResult `json:"headscale,omitempty"`
	Connector     *ConnectorResult `json:"connector,omitempty"`
	Read          *ReadResult      `json:"read,omitempty"`
}

func PolicyFor(operation Operation) (Policy, bool) {
	policy, ok := policies[operation]
	if !ok {
		return Policy{}, false
	}
	policy.Callers = append([]Caller(nil), policy.Callers...)
	policy.MaximumDuration = maximumDuration(operation)
	return policy, true
}

func Authorized(caller Caller, operation Operation) bool {
	policy, ok := policies[operation]
	if !ok {
		return false
	}
	for _, allowed := range policy.Callers {
		if caller == allowed {
			return true
		}
	}
	return false
}

func ValidateRequest(request Request, now time.Time) error {
	_, known := policies[request.Operation]
	maximum := maximumDuration(request.Operation)
	if request.SchemaVersion != SchemaVersion || !known || !refPattern.MatchString(request.RequestID) || !validOperationTarget(request.Operation, request.Target) || request.IntentGeneration == 0 || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.Sub(now) > maximum || !digestPattern.MatchString(request.InputDigest) {
		return fmt.Errorf("helper request schema or immutable authority is invalid")
	}
	actionOperation := request.Operation == OperationApplicationPlan || request.Operation == OperationAdminTokenRotate || request.Operation == OperationContractionClose || request.Operation == OperationManagedBasicGenerate || request.Operation == OperationManagedBasicDelete || request.Operation == OperationStaticRootRegister || request.Operation == OperationExternalHTPasswdRegister || request.Operation == OperationDomainStatus
	resourceOperation := request.Operation == OperationHeadscaleInitialize || request.Operation == OperationHeadscaleDeploy || request.Operation == OperationHeadscaleReissue || request.Operation == OperationHeadscaleRead || request.Operation == OperationHeadscaleMutation || request.Operation == OperationPreauthKeyPlan || request.Operation == OperationPreauthKeyCreate || request.Operation == OperationConnectorMutation || request.Operation == OperationConnectorRead || request.Operation == OperationConnectorLoginPlan || request.Operation == OperationConnectorLogin || request.Operation == OperationProductRead || request.Operation == OperationResourceDelete || request.Operation == OperationResourceMutation || request.Operation == OperationProcessLifecycle || request.Operation == OperationPublicationActivate
	if actionOperation != (request.Action != nil) || resourceOperation != (request.Resource != nil) || actionOperation && request.Resource != nil || resourceOperation && request.Action != nil {
		return fmt.Errorf("helper typed payload shape is invalid")
	}
	planAction := request.Operation == OperationApplicationPlan && (((request.Action.Operation == "admin_token_rotate" || request.Action.Operation == "close_all") && request.Action.TargetKind == "installation" && request.Action.TargetID == "") || ((request.Action.Operation == "publish" || request.Action.Operation == "unpublish" || request.Action.Operation == "resource_delete") && request.Action.TargetKind == "resource" && request.Action.TargetID != "") || ((request.Action.Operation == "managed_basic_delete" || request.Action.Operation == "managed_basic_rotate") && request.Action.TargetKind == "credential" && request.Action.TargetID != "")) && request.Action.PlanID == "" && request.Action.Confirmation == ""
	rotationAction := request.Operation == OperationAdminTokenRotate && request.Action.Operation == "admin_token_rotate" && request.Action.TargetKind == "installation" && request.Action.TargetID == "" && request.Action.PlanID != "" && request.Action.Confirmation == "rotate"
	contractionAction := request.Operation == OperationContractionClose && ((request.Action.Operation == "close_all" && request.Action.TargetKind == "installation" && request.Action.TargetID == "" && request.Action.Confirmation == "close") || (request.Action.Operation == "unpublish" && request.Action.TargetKind == "resource" && request.Action.TargetID != "" && request.Action.Confirmation == "unpublish")) && request.Action.PlanID != ""
	managedGenerate := request.Operation == OperationManagedBasicGenerate && ((request.Action.Operation == "managed_basic_create" && request.Action.TargetKind == "resource" && request.Action.TargetID != "" && request.Target == "resource/"+request.Action.TargetID && basicUsernamePattern.MatchString(request.Action.Username) && request.Action.PlanID == "" && request.Action.Confirmation == "generate") || (request.Action.Operation == "managed_basic_rotate" && request.Action.TargetKind == "credential" && request.Action.TargetID != "" && request.Target == "credential/"+request.Action.TargetID && request.Action.Username == "" && refPattern.MatchString(request.Action.PlanID) && request.Action.Confirmation == "rotate"))
	staticRegister := request.Operation == OperationStaticRootRegister && request.Action.Operation == "static_root_register" && request.Action.TargetKind == "resource" && request.Action.TargetID != "" && request.Target == "resource/"+request.Action.TargetID && request.Action.Username == "" && request.Action.PlanID == "" && request.Action.Confirmation == "register" && filepath.IsAbs(request.Action.StaticRoot) && filepath.Clean(request.Action.StaticRoot) == request.Action.StaticRoot && request.Action.ExternalHTPasswdFile == ""
	externalRegister := request.Operation == OperationExternalHTPasswdRegister && request.Action.Operation == "external_htpasswd_register" && request.Action.TargetKind == "resource" && request.Action.TargetID != "" && request.Target == "resource/"+request.Action.TargetID && request.Action.Username == "" && request.Action.PlanID == "" && request.Action.Confirmation == "register" && filepath.IsAbs(request.Action.ExternalHTPasswdFile) && filepath.Clean(request.Action.ExternalHTPasswdFile) == request.Action.ExternalHTPasswdFile && request.Action.StaticRoot == ""
	statusAction := request.Operation == OperationDomainStatus && request.Action.Operation == "status" && request.Action.TargetKind == "resource" && request.Action.TargetID != "" && request.Target == "resource/"+request.Action.TargetID && request.Action.Username == "" && request.Action.PlanID == "" && request.Action.Confirmation == "" && request.Action.StaticRoot == "" && request.Action.ExternalHTPasswdFile == ""
	managedDelete := request.Operation == OperationManagedBasicDelete && request.Action.Operation == "managed_basic_delete" && request.Action.TargetKind == "credential" && request.Action.TargetID != "" && request.Target == "credential/"+request.Action.TargetID && request.Action.Username == "" && request.Action.PlanID != "" && request.Action.Confirmation == "delete"
	if request.Action != nil && (!validAction(*request.Action) || !planAction && !rotationAction && !contractionAction && !managedGenerate && !managedDelete && !staticRegister && !externalRegister && !statusAction || (request.Operation != OperationManagedBasicGenerate && request.Action.Username != "") || (request.Operation != OperationStaticRootRegister && request.Action.StaticRoot != "") || (request.Operation != OperationExternalHTPasswdRegister && request.Action.ExternalHTPasswdFile != "")) {
		return fmt.Errorf("helper action payload is invalid")
	}
	if request.Action != nil || request.Resource != nil {
		digest, err := ApplicationInputDigest(request)
		if err != nil || request.InputDigest != digest {
			return fmt.Errorf("helper typed payload digest is invalid")
		}
	}
	if request.Resource != nil {
		if !validResourcePayload(request.Operation, *request.Resource) {
			return fmt.Errorf("helper resource payload is invalid")
		}
	}
	return nil
}

// ApplicationInputDigest binds the complete immutable application request,
// including its typed action payload, nonce, generation, and deadline.
func ApplicationInputDigest(request Request) (string, error) {
	if request.Action == nil && request.Resource == nil || request.Operation != OperationApplicationPlan && request.Operation != OperationAdminTokenRotate && request.Operation != OperationContractionClose && request.Operation != OperationManagedBasicGenerate && request.Operation != OperationManagedBasicDelete && request.Operation != OperationStaticRootRegister && request.Operation != OperationExternalHTPasswdRegister && request.Operation != OperationDomainStatus && request.Operation != OperationHeadscaleInitialize && request.Operation != OperationHeadscaleDeploy && request.Operation != OperationHeadscaleReissue && request.Operation != OperationHeadscaleRead && request.Operation != OperationHeadscaleMutation && request.Operation != OperationPreauthKeyPlan && request.Operation != OperationPreauthKeyCreate && request.Operation != OperationConnectorMutation && request.Operation != OperationConnectorRead && request.Operation != OperationConnectorLoginPlan && request.Operation != OperationConnectorLogin && request.Operation != OperationProductRead && request.Operation != OperationResourceDelete && request.Operation != OperationResourceMutation && request.Operation != OperationProcessLifecycle && request.Operation != OperationPublicationActivate {
		return "", fmt.Errorf("application helper request is invalid")
	}
	request.InputDigest = ""
	payload, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func maximumDuration(operation Operation) time.Duration {
	switch operation {
	case OperationCertificateRenew:
		return 10 * time.Minute
	case OperationPublicationActivate:
		return 11 * time.Minute
	case OperationHeadscaleDeploy, OperationHeadscaleReissue:
		return 12 * time.Minute
	case OperationHeadscaleInitialize, OperationStartupContraction:
		return 6 * time.Minute
	default:
		return time.Minute
	}
}

func validOperationTarget(operation Operation, target string) bool {
	kind, identity, found := strings.Cut(target, "/")
	exactID := found && refPattern.MatchString(identity) && !strings.Contains(identity, "/")
	switch operation {
	case OperationApplicationPlan:
		return target == "installation" || exactID && (kind == "resource" || kind == "credential")
	case OperationAdminTokenVerify, OperationAdminTokenSource, OperationManagementProfile, OperationAdminTokenRotate, OperationAdminTokenReconcile:
		return target == "installation"
	case OperationContractionClose:
		return target == "installation" || exactID && kind == "resource"
	case OperationCertificateRenew:
		return target == "installation" || target == "headscale" || exactID && kind == "resource"
	case OperationManagedBasicGenerate:
		return exactID && (kind == "credential" || kind == "resource")
	case OperationManagedBasicDelete:
		return exactID && kind == "credential"
	case OperationStaticRootRegister, OperationExternalHTPasswdRegister, OperationDomainStatus:
		return exactID && kind == "resource"
	case OperationStartupContraction:
		return target == "installation" || target == "headscale" || exactID && kind == "resource"
	case OperationHeadscaleInitialize:
		return target == "installation"
	case OperationHeadscaleDeploy, OperationHeadscaleReissue, OperationHeadscaleRead:
		return target == "headscale"
	case OperationHeadscaleMutation:
		return target == "headscale" || exactID && (kind == "preauth_key" || kind == "device")
	case OperationPreauthKeyPlan, OperationPreauthKeyCreate:
		return exactID && kind == "headscale_user"
	case OperationConnectorMutation, OperationConnectorRead, OperationConnectorLoginPlan, OperationConnectorLogin:
		return target == "connector"
	case OperationProductRead:
		return target == "installation" || exactID && (kind == "resource" || kind == "job")
	case OperationResourceDelete:
		return exactID && kind == "resource"
	case OperationResourceMutation:
		return target == "installation" || exactID && kind == "resource"
	case OperationProcessLifecycle, OperationPublicationActivate:
		return exactID && kind == "resource"
	default:
		return false
	}
}

func validResourcePayload(operation Operation, value ResourcePayload) bool {
	if !refPattern.MatchString(value.Operation) || !refPattern.MatchString(value.ActorIdentity) || value.ActorGeneration == 0 || len(value.Resource) > 12<<10 || len(value.Resource) != 0 && !json.Valid(value.Resource) {
		return false
	}
	switch operation {
	case OperationHeadscaleInitialize:
		return value.Operation == "headscale_initialize" && len(value.Resource) != 0 && value.PlanID == "" && value.Confirmation == "initialize"
	case OperationHeadscaleDeploy:
		return value.Operation == "headscale_deploy" && len(value.Resource) != 0 && ((value.PlanID == "" && value.Confirmation == "plan") || (refPattern.MatchString(value.PlanID) && value.Confirmation == "deploy"))
	case OperationHeadscaleReissue:
		return value.Operation == "headscale_reissue" && len(value.Resource) != 0 && ((value.PlanID == "" && value.Confirmation == "plan") || (refPattern.MatchString(value.PlanID) && value.Confirmation == "reissue"))
	case OperationHeadscaleRead:
		return (value.Operation == "headscale_user_list" || value.Operation == "preauth_key_list" || value.Operation == "device_list") && len(value.Resource) == 0 && value.PlanID == "" && value.Confirmation == ""
	case OperationHeadscaleMutation:
		userCreate := value.Operation == "headscale_user_create" && len(value.Resource) != 0 && value.PlanID == "" && value.Confirmation == "create"
		planned := (value.Operation == "preauth_key_revoke" || value.Operation == "device_expire") && len(value.Resource) != 0 && ((value.PlanID == "" && value.Confirmation == "plan") || (refPattern.MatchString(value.PlanID) && (value.Confirmation == "revoke" || value.Confirmation == "expire")))
		return userCreate || planned
	case OperationPreauthKeyPlan:
		return value.Operation == "preauth_key_create" && len(value.Resource) != 0 && value.PlanID == "" && value.Confirmation == "plan"
	case OperationPreauthKeyCreate:
		return value.Operation == "preauth_key_create" && len(value.Resource) != 0 && refPattern.MatchString(value.PlanID) && value.Confirmation == "create"
	case OperationConnectorMutation:
		return value.Operation == "connector_binding_set" && len(value.Resource) != 0 && value.PlanID == "" && value.Confirmation == "set"
	case OperationConnectorRead:
		return value.Operation == "connector_verify" && len(value.Resource) == 0 && value.PlanID == "" && value.Confirmation == ""
	case OperationConnectorLoginPlan:
		return value.Operation == "connector_login" && len(value.Resource) == 0 && value.PlanID == "" && value.Confirmation == "plan"
	case OperationConnectorLogin:
		return value.Operation == "connector_login" && len(value.Resource) == 0 && refPattern.MatchString(value.PlanID) && value.Confirmation == "login"
	case OperationResourceDelete:
		return value.Operation == "resource_delete" && len(value.Resource) == 0 && refPattern.MatchString(value.PlanID) && value.Confirmation == "delete"
	case OperationProductRead:
		return (value.Operation == "status" || value.Operation == "diagnostics" || value.Operation == "configuration_export" || value.Operation == "job_list" || value.Operation == "job_detail") && len(value.Resource) == 0 && value.PlanID == "" && value.Confirmation == ""
	case OperationResourceMutation:
		return (value.Operation == "resource_create" || value.Operation == "resource_update") && len(value.Resource) != 0
	case OperationProcessLifecycle:
		return (value.Operation == "process_start" || value.Operation == "process_stop") && len(value.Resource) == 0 && value.PlanID == "" && value.Confirmation == ""
	case OperationPublicationActivate:
		return value.Operation == "publish" && len(value.Resource) == 0 && refPattern.MatchString(value.PlanID) && value.Confirmation == "publish"
	default:
		return false
	}
}

func validCredentialStatusIDs(values []string) bool {
	if len(values) > 128 {
		return false
	}
	prior := ""
	for _, value := range values {
		if !strings.HasPrefix(value, "cred_") || !refPattern.MatchString(value) || prior != "" && prior >= value {
			return false
		}
		prior = value
	}
	return true
}

func validStatusCredential(id, fingerprint string, changed bool) bool {
	if id == "" || fingerprint == "" {
		return id == "" && fingerprint == "" && !changed
	}
	return strings.HasPrefix(id, "cred_") && refPattern.MatchString(id) && digestPattern.MatchString(fingerprint)
}

func validDomainStatus(value ResourceResult) bool {
	if value.Status != "healthy" && value.Status != "degraded" && value.Status != "unknown" && value.Status != "source_verified_runtime_unknown" || value.ObservedAt.IsZero() || !validDisplay(value.Reason) || !validStatusCredential(value.CredentialID, value.CredentialFingerprint, value.CredentialChanged) || !validStatusCredential(value.GoAccessCredentialID, value.GoAccessCredentialFingerprint, value.GoAccessCredentialChanged) || (value.StaticFingerprint != "" && !digestPattern.MatchString(value.StaticFingerprint)) || !validCredentialStatusIDs(value.CredentialIDs) || value.StaticChanged && value.StaticFingerprint == "" {
		return false
	}
	retirement := value.GoAccessRetirementJobID != "" || len(value.GoAccessRetirementGenerations) != 0
	if retirement {
		if !refPattern.MatchString(value.GoAccessRetirementJobID) || value.Reason != "GoAccess retirement pending" || len(value.GoAccessRetirementGenerations) == 0 || len(value.GoAccessRetirementGenerations) > 128 {
			return false
		}
		prior := uint64(0)
		for _, generation := range value.GoAccessRetirementGenerations {
			if generation <= prior {
				return false
			}
			prior = generation
		}
	}
	degradedActions := len(value.AllowedActions) == 2 && value.AllowedActions[0] == "unpublish" && value.AllowedActions[1] == "close_all"
	return value.Status == "degraded" && value.AccessMayRemain && degradedActions && (!retirement || value.Reason == "GoAccess retirement pending") || (value.Status == "healthy" || value.Status == "unknown" || value.Status == "source_verified_runtime_unknown") && !value.AccessMayRemain && !value.StaticChanged && len(value.AllowedActions) == 0 && !retirement
}

func validDisplay(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

func validContractionOutcome(outcome string, accessClosed, sharedDown, mayRemain bool) bool {
	switch outcome {
	case "succeeded":
		return accessClosed && !sharedDown && !mayRemain
	case "partial":
		return accessClosed && sharedDown && !mayRemain
	case "unknown":
		return !accessClosed && mayRemain
	default:
		return false
	}
}

var basicUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

func validAction(value ActionPayload) bool {
	return refPattern.MatchString(value.Operation) && refPattern.MatchString(value.TargetKind) && (value.TargetID == "" || refPattern.MatchString(value.TargetID)) && refPattern.MatchString(value.ActorIdentity) && value.ActorGeneration != 0 && (value.PlanID == "" || refPattern.MatchString(value.PlanID)) && (value.Confirmation == "" || refPattern.MatchString(value.Confirmation)) && (value.Username == "" || basicUsernamePattern.MatchString(value.Username)) && len(value.StaticRoot) <= 4096 && !strings.ContainsAny(value.StaticRoot, "\x00\r\n") && len(value.ExternalHTPasswdFile) <= 4096 && !strings.ContainsAny(value.ExternalHTPasswdFile, "\x00\r\n")
}

func validHeadscalePlanOrSuccess(action ActionResult, operation string) bool {
	planned := refPattern.MatchString(action.PlanID) && action.JobID == "" && action.Operation == operation && action.TargetKind == "headscale"
	completed := refPattern.MatchString(action.JobID) && action.PlanID == "" && action.Operation == operation && action.TargetKind == "headscale" && action.JobResult == "succeeded"
	return planned || completed
}

func validHeadscaleResult(operation Operation, result *HeadscaleResult) bool {
	if result == nil || !refPattern.MatchString(result.Operation) {
		return false
	}
	validUsers := func(values []HeadscaleUserRecord) bool {
		prior := uint64(0)
		for _, value := range values {
			if value.ID == 0 || value.Name == "" || strings.ContainsAny(value.Name, "\x00\r\n") || value.CreatedAt.IsZero() || value.DeviceCount < 0 || value.ActiveKeyCount < 0 || prior >= value.ID && prior != 0 {
				return false
			}
			prior = value.ID
		}
		return true
	}
	validKeys := func(values []HeadscaleKeyRecord) bool {
		prior := uint64(0)
		for _, value := range values {
			if value.ID == 0 || value.UserID == 0 || value.CreatedAt.IsZero() || value.Expiration.IsZero() || prior >= value.ID && prior != 0 {
				return false
			}
			prior = value.ID
		}
		return true
	}
	validDevices := func(values []HeadscaleDeviceRecord) bool {
		prior := uint64(0)
		for _, value := range values {
			if value.ID == 0 || value.UserID == 0 || value.Name == "" || strings.ContainsAny(value.Name, "\x00\r\n") || value.CreatedAt.IsZero() || prior >= value.ID && prior != 0 {
				return false
			}
			prior = value.ID
		}
		return true
	}
	if !validUsers(result.Users) || !validKeys(result.Keys) || !validDevices(result.Devices) {
		return false
	}
	planOnly := refPattern.MatchString(result.PlanID) && result.JobID == "" && validDisplay(result.ExposureSummary) && validDisplay(result.Prerequisites) && !result.ExpiresAt.IsZero() && result.User == nil && result.Key == nil && result.Device == nil && len(result.Users)+len(result.Keys)+len(result.Devices) == 0
	switch operation {
	case OperationHeadscaleRead:
		if result.PlanID != "" || result.ExposureSummary != "" || result.Prerequisites != "" || !result.ExpiresAt.IsZero() || result.JobID != "" || result.User != nil || result.Key != nil || result.Device != nil {
			return false
		}
		return result.Operation == "headscale_user_list" && len(result.Keys)+len(result.Devices) == 0 || result.Operation == "preauth_key_list" && len(result.Users)+len(result.Devices) == 0 || result.Operation == "device_list" && len(result.Users)+len(result.Keys) == 0
	case OperationPreauthKeyPlan:
		return result.Operation == "preauth_key_create" && planOnly
	case OperationPreauthKeyCreate:
		return result.Operation == "preauth_key_create" && result.ExposureSummary == "" && result.Prerequisites == "" && result.ExpiresAt.IsZero() && refPattern.MatchString(result.JobID) && result.PlanID == "" && result.Key != nil && validKeys([]HeadscaleKeyRecord{*result.Key}) && result.User == nil && result.Device == nil && len(result.Users)+len(result.Keys)+len(result.Devices) == 0
	case OperationHeadscaleMutation:
		if planOnly {
			return result.Operation == "preauth_key_revoke" || result.Operation == "device_expire"
		}
		if !refPattern.MatchString(result.JobID) || result.PlanID != "" || result.ExposureSummary != "" || result.Prerequisites != "" || !result.ExpiresAt.IsZero() || len(result.Users)+len(result.Keys)+len(result.Devices) != 0 {
			return false
		}
		return result.Operation == "headscale_user_create" && result.User != nil && validUsers([]HeadscaleUserRecord{*result.User}) && result.Key == nil && result.Device == nil || result.Operation == "preauth_key_revoke" && result.Key != nil && validKeys([]HeadscaleKeyRecord{*result.Key}) && result.User == nil && result.Device == nil || result.Operation == "device_expire" && result.Device != nil && validDevices([]HeadscaleDeviceRecord{*result.Device}) && result.User == nil && result.Key == nil
	default:
		return false
	}
}

func validConnectorResult(operation Operation, result *ConnectorResult) bool {
	if result == nil || !refPattern.MatchString(result.Operation) {
		return false
	}
	planOnly := result.Operation == "connector_login" && refPattern.MatchString(result.PlanID) && result.JobID == "" && validDisplay(result.ExposureSummary) && validDisplay(result.Prerequisites) && !result.ExpiresAt.IsZero() && result.ClientVersion == "" && result.ControlURL == "" && len(result.LocalIPs)+len(result.PeerIPs) == 0 && result.ValidUntil.IsZero()
	switch operation {
	case OperationConnectorLoginPlan:
		return planOnly
	case OperationConnectorMutation, OperationConnectorLogin:
		return (result.Operation == "connector_binding_set" || result.Operation == "connector_login") && refPattern.MatchString(result.JobID) && result.PlanID == "" && result.ExposureSummary == "" && result.Prerequisites == "" && result.ExpiresAt.IsZero() && result.ClientVersion == "" && result.ControlURL == "" && len(result.LocalIPs)+len(result.PeerIPs) == 0 && result.ValidUntil.IsZero()
	case OperationConnectorRead:
		if result.Operation != "connector_verify" || result.JobID != "" || result.PlanID != "" || result.ClientVersion == "" || result.ControlURL == "" || len(result.LocalIPs) == 0 || result.ValidUntil.IsZero() {
			return false
		}
		for _, values := range [][]string{result.LocalIPs, result.PeerIPs} {
			prior := ""
			for _, value := range values {
				if value == "" || prior != "" && prior >= value {
					return false
				}
				prior = value
			}
		}
		return true
	default:
		return false
	}
}

func validReadResult(result *ReadResult) bool {
	return result != nil && (result.Operation == "status" || result.Operation == "diagnostics" || result.Operation == "configuration_export" || result.Operation == "job_list" || result.Operation == "job_detail") && len(result.Payload) > 0 && len(result.Payload) <= 12<<20 && json.Valid(result.Payload)
}

func ValidateResponse(operation Operation, response Response) error {
	if _, known := policies[operation]; !known || response.SchemaVersion != SchemaVersion || !refPattern.MatchString(response.RequestID) {
		return fmt.Errorf("helper response identity is invalid")
	}
	switch response.Code {
	case ResponseSucceeded:
		if !digestPattern.MatchString(response.ResultDigest) || response.ErrorCode != "" || response.ErrorJobID != "" {
			return fmt.Errorf("successful helper response is incomplete")
		}
		if operation != OperationPublicationActivate && response.Action != nil && response.Action.JobResult != "" {
			return fmt.Errorf("unrelated helper response carried a job result")
		}
		if operation != OperationDomainStatus && response.Resource != nil && (response.Resource.GoAccessRetirementJobID != "" || len(response.Resource.GoAccessRetirementGenerations) != 0) {
			return fmt.Errorf("unrelated helper response carried GoAccess retirement status")
		}
		headscaleOperation := operation == OperationHeadscaleRead || operation == OperationHeadscaleMutation || operation == OperationPreauthKeyPlan || operation == OperationPreauthKeyCreate
		if !headscaleOperation && response.Headscale != nil {
			return fmt.Errorf("unrelated helper response carried Headscale lifecycle data")
		}
		connectorOperation := operation == OperationConnectorMutation || operation == OperationConnectorRead || operation == OperationConnectorLoginPlan || operation == OperationConnectorLogin
		if !connectorOperation && response.Connector != nil {
			return fmt.Errorf("unrelated helper response carried connector data")
		}
		if operation != OperationProductRead && response.Read != nil {
			return fmt.Errorf("unrelated helper response carried product read data")
		}
		switch operation {
		case OperationApplicationPlan:
			action := response.Action
			validTarget := action != nil && ((action.Operation == "admin_token_rotate" || action.Operation == "close_all") && action.TargetKind == "installation" && action.TargetID == "" || (action.Operation == "publish" || action.Operation == "unpublish" || action.Operation == "resource_delete") && action.TargetKind == "resource" && action.TargetID != "" || (action.Operation == "managed_basic_delete" || action.Operation == "managed_basic_rotate") && action.TargetKind == "credential" && action.TargetID != "")
			if !validTarget || !refPattern.MatchString(action.PlanID) || !digestPattern.MatchString(action.Confirmation) || action.JobID != "" || !validDisplay(action.ExposureSummary) || !validDisplay(action.Prerequisites) || action.ExpiresAt.IsZero() || action.ContractionOutcome != "" || action.AccessClosed || action.SharedIngressDown || action.AccessMayRemain {
				return fmt.Errorf("application Plan response shape is invalid")
			}
		case OperationAdminTokenRotate:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.PlanID != "" || response.Action.Confirmation != "" || response.Action.Operation != "" || response.Action.TargetKind != "" || response.Action.TargetID != "" || response.Action.ExposureSummary != "" || response.Action.Prerequisites != "" || !response.Action.ExpiresAt.IsZero() || response.Action.ContractionOutcome != "" || response.Action.AccessClosed || response.Action.SharedIngressDown || response.Action.AccessMayRemain {
				return fmt.Errorf("admin token response shape is invalid")
			}
		case OperationManagedBasicGenerate:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || (response.Action.Operation != "managed_basic_create" && response.Action.Operation != "managed_basic_rotate") || response.Action.TargetKind != "credential" || !refPattern.MatchString(response.Action.TargetID) || response.Resource != nil {
				return fmt.Errorf("managed Basic response shape invalid")
			}
		case OperationManagedBasicDelete:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.Operation != "managed_basic_delete" || response.Action.TargetKind != "credential" || !refPattern.MatchString(response.Action.TargetID) || response.Resource != nil {
				return fmt.Errorf("managed Basic delete response shape invalid")
			}
		case OperationStaticRootRegister:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.Operation != "static_root_register" || response.Action.TargetKind != "static" || !refPattern.MatchString(response.Action.TargetID) || response.Resource != nil {
				return fmt.Errorf("static root response shape invalid")
			}
		case OperationExternalHTPasswdRegister:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.Operation != "external_htpasswd_register" || response.Action.TargetKind != "credential" || !refPattern.MatchString(response.Action.TargetID) || response.Resource != nil {
				return fmt.Errorf("external htpasswd response shape invalid")
			}
		case OperationDomainStatus:
			if response.Resource == nil || !refPattern.MatchString(response.Resource.ResourceID) || !validDomainStatus(*response.Resource) || response.Action != nil {
				return fmt.Errorf("domain status response shape invalid")
			}
		case OperationContractionClose:
			if response.Action == nil || response.Action.PlanID != "" || response.Action.Confirmation != "" || response.Action.JobID != "" || response.Action.Operation != "" || response.Action.TargetKind != "" || response.Action.TargetID != "" || response.Action.ExposureSummary != "" || response.Action.Prerequisites != "" || !response.Action.ExpiresAt.IsZero() || !validContractionOutcome(response.Action.ContractionOutcome, response.Action.AccessClosed, response.Action.SharedIngressDown, response.Action.AccessMayRemain) {
				return fmt.Errorf("contraction response shape is invalid")
			}
		case OperationHeadscaleInitialize:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.Operation != "headscale_initialize" || response.Action.TargetKind != "installation" || !strings.HasPrefix(response.Action.TargetID, "hds_") || !refPattern.MatchString(response.Action.TargetID) || response.Resource != nil || response.Action.JobResult != "" || response.Action.PublicURL != "" {
				return fmt.Errorf("headscale initialization response shape invalid")
			}
		case OperationHeadscaleDeploy:
			valid := response.Action != nil && validHeadscalePlanOrSuccess(*response.Action, "headscale_control_deploy")
			if response.Resource != nil || !valid {
				return fmt.Errorf("headscale deploy response shape invalid")
			}
		case OperationHeadscaleReissue:
			valid := response.Action != nil && validHeadscalePlanOrSuccess(*response.Action, "headscale_certificate_reissue")
			if response.Resource != nil || !valid {
				return fmt.Errorf("headscale reissue response shape invalid")
			}
		case OperationHeadscaleRead, OperationHeadscaleMutation, OperationPreauthKeyPlan, OperationPreauthKeyCreate:
			if response.Action != nil || response.Resource != nil || !validHeadscaleResult(operation, response.Headscale) {
				return fmt.Errorf("headscale lifecycle response shape invalid")
			}
		case OperationConnectorMutation, OperationConnectorRead, OperationConnectorLoginPlan, OperationConnectorLogin:
			if response.Action != nil || response.Resource != nil || response.Headscale != nil || !validConnectorResult(operation, response.Connector) {
				return fmt.Errorf("connector response shape invalid")
			}
		case OperationResourceDelete:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Resource != nil || response.Headscale != nil || response.Connector != nil || response.Read != nil {
				return fmt.Errorf("resource delete response shape invalid")
			}
		case OperationProductRead:
			if response.Action != nil || response.Resource != nil || response.Headscale != nil || response.Connector != nil || !validReadResult(response.Read) {
				return fmt.Errorf("product read response shape invalid")
			}
		case OperationResourceMutation:
			if response.Action != nil || response.Resource == nil || !strings.HasPrefix(response.Resource.ResourceID, "res_") || !refPattern.MatchString(response.Resource.ResourceID) {
				return fmt.Errorf("resource helper response shape invalid")
			}
		case OperationProcessLifecycle:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Resource != nil || response.Action.PublicURL != "" {
				return fmt.Errorf("process helper response shape invalid")
			}
		case OperationPublicationActivate:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.PublicURL == "" || response.Action.JobResult != "succeeded" && response.Action.JobResult != "partial" || response.Resource != nil {
				return fmt.Errorf("publication helper response shape invalid")
			}
		default:
			if response.Action != nil {
				return fmt.Errorf("unrelated helper response carried an action result")
			}
		}
	case ResponseRejected, ResponseFailed:
		foreignCode := operation == OperationHeadscaleInitialize && response.ErrorCode == "foreign_database_evidence"
		headscaleEvidence := foreignCode && strings.HasPrefix(response.ErrorJobID, "job_") && refPattern.MatchString(response.ErrorJobID)
		if response.ResultDigest != "" || !refPattern.MatchString(response.ErrorCode) || response.Action != nil || response.Resource != nil || response.Headscale != nil || response.Connector != nil || response.Read != nil || foreignCode != headscaleEvidence || response.ErrorJobID != "" && !headscaleEvidence {
			return fmt.Errorf("failed helper response is not redacted")
		}
	default:
		return fmt.Errorf("helper response code is unknown")
	}
	return nil
}
