// Package helperproto defines the bounded typed UI/timer/recovery-to-helper protocol.
package helperproto

import (
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
	OperationManagedFileCommit    Operation = "managed_file_commit"
	OperationAccountCreate        Operation = "account_create"
	OperationAdminTokenRotate     Operation = "admin_token_rotate"
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
)

type Policy struct {
	Callers         []Caller
	SecretInput     bool
	SecretOutput    bool
	MaximumDuration time.Duration
}

var policies = map[Operation]Policy{
	OperationManagedFileCommit:    {Callers: []Caller{CallerUI}},
	OperationAccountCreate:        {Callers: []Caller{CallerUI}},
	OperationAdminTokenRotate:     {Callers: []Caller{CallerUI}, SecretOutput: true},
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
	OperationContractionClose:     {Callers: []Caller{CallerUI, CallerTimer, CallerRecovery}},
	OperationStartupContraction:   {Callers: []Caller{CallerRecovery}},
}

var refPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Request struct {
	SchemaVersion    string    `json:"schema_version"`
	RequestID        string    `json:"request_id"`
	Operation        Operation `json:"operation"`
	Target           string    `json:"target"`
	IntentGeneration uint64    `json:"intent_generation"`
	Deadline         time.Time `json:"deadline"`
	InputDigest      string    `json:"input_digest"`
}

type ResponseCode string

const (
	ResponseSucceeded ResponseCode = "succeeded"
	ResponseRejected  ResponseCode = "rejected"
	ResponseFailed    ResponseCode = "failed"
)

type Response struct {
	SchemaVersion string       `json:"schema_version"`
	RequestID     string       `json:"request_id"`
	Code          ResponseCode `json:"code"`
	ResultDigest  string       `json:"result_digest,omitempty"`
	ErrorCode     string       `json:"error_code,omitempty"`
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
	return nil
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
	case OperationPackageTransaction, OperationSystemdTransition, OperationNginxTest, OperationNginxReload, OperationAdminTokenRotate:
		return target == "installation"
	case OperationCredentialImport, OperationCredentialAdopt:
		return exactID && kind == "credential"
	case OperationCertificateIssue, OperationCertificateRenew:
		return target == "headscale" || exactID && kind == "resource"
	case OperationEdgeOneRefresh, OperationGoAccessProbe:
		return exactID && kind == "resource"
	case OperationHeadscaleAdmin, OperationPreauthKeyCreate:
		return target == "headscale"
	case OperationTailscaleAuthImport, OperationTailscaleAuthAdopt, OperationTailscaleAdmin:
		return target == "connector"
	case OperationManagedBasicGenerate:
		return exactID && kind == "credential"
	case OperationContractionClose:
		return target == "installation" || target == "headscale" || exactID && kind == "resource"
	case OperationStartupContraction:
		return target == "headscale" || exactID && kind == "resource"
	default:
		return false
	}
}

func ValidateResponse(response Response) error {
	if response.SchemaVersion != SchemaVersion || !refPattern.MatchString(response.RequestID) {
		return fmt.Errorf("helper response identity is invalid")
	}
	switch response.Code {
	case ResponseSucceeded:
		if !digestPattern.MatchString(response.ResultDigest) || response.ErrorCode != "" {
			return fmt.Errorf("successful helper response is incomplete")
		}
	case ResponseRejected, ResponseFailed:
		if response.ResultDigest != "" || !refPattern.MatchString(response.ErrorCode) {
			return fmt.Errorf("failed helper response is not redacted")
		}
	default:
		return fmt.Errorf("helper response code is unknown")
	}
	return nil
}
