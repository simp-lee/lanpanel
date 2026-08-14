// Package helperproto defines the bounded typed UI/timer/recovery-to-helper protocol.
package helperproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	OperationApplicationPlan      Operation = "application_plan"
	OperationManagedFileCommit    Operation = "managed_file_commit"
	OperationAccountCreate        Operation = "account_create"
	OperationAdminTokenVerify     Operation = "admin_token_verify"
	OperationAdminTokenSource     Operation = "admin_token_source_status"
	OperationManagementProfile    Operation = "management_profile_status"
	OperationAdminTokenRotate     Operation = "admin_token_rotate"
	OperationAdminTokenReconcile  Operation = "admin_token_rotate_reconcile"
	OperationPackageTransaction   Operation = "package_transaction"
	OperationSystemdTransition    Operation = "systemd_transition"
	OperationNginxTest            Operation = "nginx_test"
	OperationNginxReload          Operation = "nginx_reload"
	OperationCredentialImport     Operation = "credential_import"
	OperationCredentialAdopt      Operation = "credential_adopt"
	OperationCertificateIssue     Operation = "certificate_issue"
	OperationCertificateRenew     Operation = "certificate_renew"
	OperationEdgeOneRefresh       Operation = "edgeone_refresh"
	OperationHeadscaleAdmin       Operation = "headscale_admin"
	OperationPreauthKeyCreate     Operation = "preauth_key_create"
	OperationTailscaleAuthImport  Operation = "tailscale_auth_import"
	OperationTailscaleAuthAdopt   Operation = "tailscale_auth_adopt"
	OperationTailscaleAdmin       Operation = "tailscale_admin"
	OperationGoAccessProbe        Operation = "goaccess_probe"
	OperationManagedBasicGenerate Operation = "managed_basic_generate"
	OperationContractionClose     Operation = "contraction_close"
	OperationStartupContraction   Operation = "startup_contraction"
	OperationResourceMutation     Operation = "resource_mutation"
	OperationProcessLifecycle     Operation = "process_lifecycle"
	OperationPublicationActivate  Operation = "publication_activate"
)

type Policy struct {
	Callers         []Caller
	SecretInput     bool
	SecretOutput    bool
	MaximumDuration time.Duration
}

var policies = map[Operation]Policy{
	OperationApplicationPlan:      {Callers: []Caller{CallerUI}},
	OperationManagedFileCommit:    {Callers: []Caller{CallerUI}},
	OperationAccountCreate:        {Callers: []Caller{CallerUI}},
	OperationAdminTokenVerify:     {Callers: []Caller{CallerUI}, SecretInput: true},
	OperationAdminTokenSource:     {Callers: []Caller{CallerUI}},
	OperationManagementProfile:    {Callers: []Caller{CallerUI}},
	OperationAdminTokenRotate:     {Callers: []Caller{CallerUI}, SecretOutput: true},
	OperationAdminTokenReconcile:  {Callers: []Caller{CallerUI}},
	OperationPackageTransaction:   {Callers: []Caller{CallerUI}},
	OperationSystemdTransition:    {Callers: []Caller{CallerUI}},
	OperationNginxTest:            {Callers: []Caller{CallerUI, CallerRecovery}},
	OperationNginxReload:          {Callers: []Caller{CallerUI}},
	OperationCredentialImport:     {Callers: []Caller{CallerUI}, SecretInput: true},
	OperationCredentialAdopt:      {Callers: []Caller{CallerUI}},
	OperationCertificateIssue:     {Callers: []Caller{CallerUI}},
	OperationCertificateRenew:     {Callers: []Caller{CallerUI, CallerTimer}},
	OperationEdgeOneRefresh:       {Callers: []Caller{CallerUI, CallerTimer}},
	OperationHeadscaleAdmin:       {Callers: []Caller{CallerUI}},
	OperationPreauthKeyCreate:     {Callers: []Caller{CallerUI}, SecretOutput: true},
	OperationTailscaleAuthImport:  {Callers: []Caller{CallerUI}, SecretInput: true},
	OperationTailscaleAuthAdopt:   {Callers: []Caller{CallerUI}},
	OperationTailscaleAdmin:       {Callers: []Caller{CallerUI}},
	OperationGoAccessProbe:        {Callers: []Caller{CallerUI}},
	OperationManagedBasicGenerate: {Callers: []Caller{CallerUI}, SecretOutput: true},
	OperationContractionClose:     {Callers: []Caller{CallerUI}},
	OperationStartupContraction:   {Callers: []Caller{CallerRecovery}},
	OperationResourceMutation:     {Callers: []Caller{CallerUI}},
	OperationProcessLifecycle:     {Callers: []Caller{CallerUI}},
	OperationPublicationActivate:  {Callers: []Caller{CallerUI}, MaximumDuration: time.Minute},
}

var refPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type ActionPayload struct {
	Operation       string `json:"operation"`
	TargetKind      string `json:"target_kind"`
	TargetID        string `json:"target_id,omitempty"`
	ActorIdentity   string `json:"actor_identity"`
	ActorGeneration uint64 `json:"actor_generation"`
	PlanID          string `json:"plan_id,omitempty"`
	Confirmation    string `json:"confirmation,omitempty"`
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

type ResourceResult struct {
	ResourceID string `json:"resource_id"`
}
type Response struct {
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	Code          ResponseCode    `json:"code"`
	ResultDigest  string          `json:"result_digest,omitempty"`
	ErrorCode     string          `json:"error_code,omitempty"`
	Action        *ActionResult   `json:"action,omitempty"`
	Resource      *ResourceResult `json:"resource,omitempty"`
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
	actionOperation := request.Operation == OperationApplicationPlan || request.Operation == OperationAdminTokenRotate || request.Operation == OperationContractionClose
	resourceOperation := request.Operation == OperationResourceMutation || request.Operation == OperationProcessLifecycle || request.Operation == OperationPublicationActivate
	if actionOperation != (request.Action != nil) || resourceOperation != (request.Resource != nil) || actionOperation && request.Resource != nil || resourceOperation && request.Action != nil {
		return fmt.Errorf("helper typed payload shape is invalid")
	}
	planAction := request.Operation == OperationApplicationPlan && ((request.Action.Operation == "admin_token_rotate" || request.Action.Operation == "close_all") && request.Action.TargetKind == "installation" && request.Action.TargetID == "" || request.Action.Operation == "unpublish" && request.Action.TargetKind == "resource" && request.Action.TargetID != "") && request.Action.PlanID == "" && request.Action.Confirmation == ""
	rotationAction := request.Operation == OperationAdminTokenRotate && request.Action.Operation == "admin_token_rotate" && request.Action.TargetKind == "installation" && request.Action.TargetID == "" && request.Action.PlanID != "" && request.Action.Confirmation == "rotate"
	contractionAction := request.Operation == OperationContractionClose && ((request.Action.Operation == "close_all" && request.Action.TargetKind == "installation" && request.Action.TargetID == "" && request.Action.Confirmation == "close") || (request.Action.Operation == "unpublish" && request.Action.TargetKind == "resource" && request.Action.TargetID != "" && request.Action.Confirmation == "unpublish")) && request.Action.PlanID != ""
	if request.Action != nil && (!validAction(*request.Action) || !planAction && !rotationAction && !contractionAction) {
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
	if request.Action == nil && request.Resource == nil || request.Operation != OperationApplicationPlan && request.Operation != OperationAdminTokenRotate && request.Operation != OperationContractionClose && request.Operation != OperationResourceMutation && request.Operation != OperationProcessLifecycle && request.Operation != OperationPublicationActivate {
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
	case OperationPackageTransaction:
		return 30 * time.Minute
	case OperationCertificateIssue, OperationCertificateRenew, OperationEdgeOneRefresh:
		return 10 * time.Minute
	default:
		return time.Minute
	}
}

func validOperationTarget(operation Operation, target string) bool {
	kind, identity, found := strings.Cut(target, "/")
	exactID := found && refPattern.MatchString(identity) && !strings.Contains(identity, "/")
	switch operation {
	case OperationManagedFileCommit:
		return exactID && (kind == "resource" || kind == "credential" || kind == "certificate")
	case OperationAccountCreate:
		return target == "installation" || exactID && (kind == "resource" || kind == "service")
	case OperationApplicationPlan:
		return target == "installation" || exactID && kind == "resource"
	case OperationPackageTransaction, OperationSystemdTransition, OperationNginxTest, OperationNginxReload, OperationAdminTokenVerify, OperationAdminTokenSource, OperationManagementProfile, OperationAdminTokenRotate, OperationAdminTokenReconcile:
		return target == "installation"
	case OperationContractionClose:
		return target == "installation" || exactID && kind == "resource"
	case OperationCredentialImport, OperationCredentialAdopt:
		return exactID && kind == "credential"
	case OperationCertificateIssue:
		return target == "headscale" || exactID && kind == "resource"
	case OperationCertificateRenew:
		return target == "installation" || target == "headscale" || exactID && kind == "resource"
	case OperationEdgeOneRefresh, OperationGoAccessProbe:
		return exactID && kind == "resource"
	case OperationHeadscaleAdmin, OperationPreauthKeyCreate:
		return target == "headscale"
	case OperationTailscaleAuthImport, OperationTailscaleAuthAdopt, OperationTailscaleAdmin:
		return target == "connector"
	case OperationManagedBasicGenerate:
		return exactID && kind == "credential"
	case OperationStartupContraction:
		return target == "installation" || target == "headscale" || exactID && kind == "resource"
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

func validAction(value ActionPayload) bool {
	return refPattern.MatchString(value.Operation) && refPattern.MatchString(value.TargetKind) && (value.TargetID == "" || refPattern.MatchString(value.TargetID)) && refPattern.MatchString(value.ActorIdentity) && value.ActorGeneration != 0 && (value.PlanID == "" || refPattern.MatchString(value.PlanID)) && (value.Confirmation == "" || refPattern.MatchString(value.Confirmation))
}

func ValidateResponse(operation Operation, response Response) error {
	if _, known := policies[operation]; !known || response.SchemaVersion != SchemaVersion || !refPattern.MatchString(response.RequestID) {
		return fmt.Errorf("helper response identity is invalid")
	}
	switch response.Code {
	case ResponseSucceeded:
		if !digestPattern.MatchString(response.ResultDigest) || response.ErrorCode != "" {
			return fmt.Errorf("successful helper response is incomplete")
		}
		switch operation {
		case OperationApplicationPlan:
			if response.Action == nil || !refPattern.MatchString(response.Action.PlanID) || !digestPattern.MatchString(response.Action.Confirmation) || response.Action.JobID != "" || response.Action.Operation != "admin_token_rotate" && response.Action.Operation != "close_all" && response.Action.Operation != "unpublish" || (response.Action.Operation == "unpublish") != (response.Action.TargetKind == "resource" && response.Action.TargetID != "") || response.Action.Operation != "unpublish" && (response.Action.TargetKind != "installation" || response.Action.TargetID != "") || !refPattern.MatchString(response.Action.ExposureSummary) || !refPattern.MatchString(response.Action.Prerequisites) || response.Action.ExpiresAt.IsZero() || response.Action.ContractionOutcome != "" || response.Action.AccessClosed || response.Action.SharedIngressDown || response.Action.AccessMayRemain {
				return fmt.Errorf("application Plan response shape is invalid")
			}
		case OperationAdminTokenRotate:
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.PlanID != "" || response.Action.Confirmation != "" || response.Action.Operation != "" || response.Action.TargetKind != "" || response.Action.TargetID != "" || response.Action.ExposureSummary != "" || response.Action.Prerequisites != "" || !response.Action.ExpiresAt.IsZero() || response.Action.ContractionOutcome != "" || response.Action.AccessClosed || response.Action.SharedIngressDown || response.Action.AccessMayRemain {
				return fmt.Errorf("admin token response shape is invalid")
			}
		case OperationContractionClose:
			if response.Action == nil || response.Action.PlanID != "" || response.Action.Confirmation != "" || response.Action.JobID != "" || response.Action.Operation != "" || response.Action.TargetKind != "" || response.Action.TargetID != "" || response.Action.ExposureSummary != "" || response.Action.Prerequisites != "" || !response.Action.ExpiresAt.IsZero() || !validContractionOutcome(response.Action.ContractionOutcome, response.Action.AccessClosed, response.Action.SharedIngressDown, response.Action.AccessMayRemain) {
				return fmt.Errorf("contraction response shape is invalid")
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
			if response.Action == nil || !refPattern.MatchString(response.Action.JobID) || response.Action.PublicURL == "" || response.Resource != nil {
				return fmt.Errorf("publication helper response shape invalid")
			}
		default:
			if response.Action != nil {
				return fmt.Errorf("unrelated helper response carried an action result")
			}
		}
	case ResponseRejected, ResponseFailed:
		if response.ResultDigest != "" || !refPattern.MatchString(response.ErrorCode) || response.Action != nil || response.Resource != nil {
			return fmt.Errorf("failed helper response is not redacted")
		}
	default:
		return fmt.Errorf("helper response code is unknown")
	}
	return nil
}
