package apphost

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/workflow"
	"strings"
	"time"
)

type commandResult struct {
	Command          string
	OutputStatus     string
	JobStatus        domain.JobStatus
	DiagnosticStatus domain.DiagnosticStatus
	Summary          string
	Fields           []domain.ResultField
	NextSteps        []string
	Operation        workflow.OperationResult
}

type commandResponse struct {
	Command     string
	Status      string
	Summary     string
	Fields      []domain.ResultField
	Diagnostics []domain.DiagnosticItem
	NextSteps   []string
}

func (result commandResult) result() Result {
	return operationResult(result.Command, result.OutputStatus, result.Operation, result.NextSteps)
}

func (result commandResult) operationResult(kind domain.JobKind, retryCommand string) workflow.OperationResult {
	operation := result.Operation
	if operation.Kind == "" {
		operation.Kind = kind
	}
	if strings.TrimSpace(operation.RetryCommand) == "" {
		operation.RetryCommand = retryCommand
	}
	return operation
}

func (result *commandResult) setFields(fields []domain.ResultField) {
	result.Fields = append([]domain.ResultField(nil), fields...)
	result.Operation.Fields = append([]domain.ResultField(nil), fields...)
}

func newCommandResult(command string, outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, summary string, fields []domain.ResultField, nextSteps []string) commandResult {
	operation := commandOperationResult(command, outputStatus, jobStatus, diagnosticStatus, summary, fields, "")
	return commandResult{
		Command:          command,
		OutputStatus:     outputStatus,
		JobStatus:        jobStatus,
		DiagnosticStatus: diagnosticStatus,
		Summary:          summary,
		Fields:           append([]domain.ResultField(nil), fields...),
		NextSteps:        append([]string(nil), nextSteps...),
		Operation:        operation,
	}
}

func commandOperationResult(command string, outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, summary string, fields []domain.ResultField, retryCommand string) workflow.OperationResult {
	kind := commandResultKind(command)
	operation := workflow.OperationResult{
		Kind:         kind,
		Status:       jobStatus,
		Summary:      strings.TrimSpace(summary),
		Fields:       append([]domain.ResultField(nil), fields...),
		RetryCommand: strings.TrimSpace(retryCommand),
	}
	if kind != "" {
		if diagnosticStatus == "" || diagnosticStatus == domain.DiagnosticStatusNotApplicable {
			diagnosticStatus = commandDiagnosticStatus(jobStatus)
		}
		operation.Diagnostics = []domain.DiagnosticItem{commandDiagnosticItem(kind, command, outputStatus, diagnosticStatus, operation.Summary)}
	}
	return operation
}

func commandResultFromFailure(command string, outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, failure workflow.Failure) commandResult {
	snapshot := failure.Snapshot()
	return newCommandResult(command, outputStatus, jobStatus, diagnosticStatus, snapshot.SummaryText(), snapshot.ResultFields(), snapshot.NextSteps())
}

func commandResultFromFailureSnapshot(command string, outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, snapshot workflow.FailureSnapshot) commandResult {
	return newCommandResult(command, outputStatus, jobStatus, diagnosticStatus, snapshot.SummaryText(), snapshot.ResultFields(), snapshot.NextSteps())
}

func commandDiagnosticID(kind domain.JobKind, outputStatus string) string {
	status := strings.TrimSpace(outputStatus)
	if status == "" {
		status = "result"
	}
	status = strings.NewReplacer(" ", "-", "_", "-").Replace(status)
	return string(kind) + ":" + status
}

func commandDiagnosticItem(kind domain.JobKind, command string, outputStatus string, status domain.DiagnosticStatus, summary string) domain.DiagnosticItem {
	return domain.DiagnosticItem{
		ID:               commandDiagnosticID(kind, outputStatus),
		Title:            command,
		Status:           status,
		Scope:            domain.DiagnosticScopeInstance,
		Severity:         commandDiagnosticSeverity(status),
		Summary:          strings.TrimSpace(summary),
		EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
		ResponsibleParty: domain.DiagnosticResponsibleLanPanel,
		BlocksActivation: status == domain.DiagnosticStatusFail,
		Redaction:        domain.RedactionNone,
		RedactionStatus:  domain.RedactionStatusNoSensitiveData,
	}
}

func commandDiagnosticStatus(status domain.JobStatus) domain.DiagnosticStatus {
	switch status {
	case domain.JobStatusSucceeded:
		return domain.DiagnosticStatusPass
	case domain.JobStatusFailed, domain.JobStatusInterrupted:
		return domain.DiagnosticStatusFail
	case domain.JobStatusUnknown:
		return domain.DiagnosticStatusUnknown
	case domain.JobStatusQueued, domain.JobStatusRunning:
		return domain.DiagnosticStatusManual
	default:
		return domain.DiagnosticStatusUnknown
	}
}

func commandDiagnosticSeverity(status domain.DiagnosticStatus) domain.DiagnosticSeverity {
	switch status {
	case domain.DiagnosticStatusFail:
		return domain.DiagnosticSeverityCritical
	case domain.DiagnosticStatusWarn, domain.DiagnosticStatusManual, domain.DiagnosticStatusUnknown:
		return domain.DiagnosticSeverityMedium
	default:
		return domain.DiagnosticSeverityInfo
	}
}

func operationResult(command string, outputStatus string, result workflow.OperationResult, nextSteps []string) Result {
	status := strings.TrimSpace(outputStatus)
	if status == "" {
		status = outputStatusForJobStatus(result.Status)
	}
	summary := strings.TrimSpace(result.Summary)
	if summary == "" {
		summary = string(result.Kind)
	}
	operation := result
	if operation.Kind == "" {
		operation.Kind = commandResultKind(command)
	}
	operation.Summary = summary
	if len(operation.Fields) == 0 {
		operation.Fields = append([]domain.ResultField(nil), result.Fields...)
	}
	return Result{
		Operation:    operation,
		OutputStatus: status,
		NextSteps:    append([]string(nil), nextSteps...),
	}
}

func operationProgressEvents(kind domain.JobKind, startMessage string, endStatus domain.DiagnosticStatus, endMessage string) []workflow.ProgressEvent {
	now := time.Now().UTC()
	events := make([]workflow.ProgressEvent, 0, 2)
	if strings.TrimSpace(startMessage) != "" {
		events = append(events, workflow.ProgressEvent{At: now, Kind: kind, Status: domain.DiagnosticStatusManual, Message: startMessage})
	}
	if strings.TrimSpace(endMessage) != "" {
		events = append(events, workflow.ProgressEvent{At: now, Kind: kind, Status: endStatus, Message: endMessage})
	}
	return events
}

func genericHostOperationResult(kind domain.JobKind, status domain.JobStatus, summary string, retryCommand string, cause error) workflow.OperationResult {
	fields := []domain.ResultField{}
	if cause != nil {
		fields = append(fields, domain.ResultField{Label: "details", Value: cause.Error()})
	}
	return workflow.OperationResult{
		Kind:         kind,
		Status:       status,
		Summary:      summary,
		Fields:       fields,
		RetryCommand: retryCommand,
		Progress:     operationProgressEvents(kind, string(kind)+" host workflow started", commandDiagnosticStatus(status), string(kind)+" host workflow finished"),
	}
}

func outputStatusForJobStatus(status domain.JobStatus) string {
	switch status {
	case domain.JobStatusSucceeded:
		return "passed"
	case domain.JobStatusFailed:
		return "failed"
	case domain.JobStatusQueued:
		return "queued"
	case domain.JobStatusRunning:
		return "running"
	case domain.JobStatusInterrupted:
		return "interrupted"
	case domain.JobStatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

func commandResultKind(command string) domain.JobKind {
	switch strings.TrimSpace(command) {
	case "deploy":
		return domain.JobKindDeploy
	case "verify":
		return domain.JobKindVerify
	case "status":
		return domain.JobKindStatus
	case "app init":
		return domain.JobKindAppInit
	case "app verify":
		return domain.JobKindAppVerify
	case "app deploy":
		return domain.JobKindAppDeploy
	case "app realip diagnostics":
		return domain.JobKindRealIPDiagnostics
	case "app realip refresh":
		return domain.JobKindRealIPRefresh
	case "app realip validate-reference":
		return domain.JobKindRealIPValidateRef
	default:
		return ""
	}
}
