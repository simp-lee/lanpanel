package cli

import (
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/output"
	"lanpanel/internal/workflow"
	"strings"
	"time"
)

type responseWriter interface {
	Write(output.Response) error
}

type commandResult struct {
	Command          string
	OutputStatus     string
	JobStatus        domain.JobStatus
	DiagnosticStatus domain.DiagnosticStatus
	Summary          string
	Fields           []output.Field
	NextSteps        []string
	Operation        workflow.OperationResult
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

func (result *commandResult) setFields(fields []output.Field) {
	result.Fields = append([]output.Field(nil), fields...)
	result.Operation.Fields = append([]output.Field(nil), fields...)
}

func newCommandResult(command string, outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, summary string, fields []output.Field, nextSteps []string) commandResult {
	operation := commandOperationResult(command, outputStatus, jobStatus, diagnosticStatus, summary, fields, "")
	return commandResult{
		Command:          command,
		OutputStatus:     outputStatus,
		JobStatus:        jobStatus,
		DiagnosticStatus: diagnosticStatus,
		Summary:          summary,
		Fields:           append([]output.Field(nil), fields...),
		NextSteps:        append([]string(nil), nextSteps...),
		Operation:        operation,
	}
}

func commandOperationResult(command string, outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, summary string, fields []output.Field, retryCommand string) workflow.OperationResult {
	kind := commandResultKind(command)
	operation := workflow.OperationResult{
		Kind:         kind,
		Status:       jobStatus,
		Summary:      strings.TrimSpace(summary),
		Fields:       append([]output.Field(nil), fields...),
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

func failureResponse(command string, failure workflow.Failure) output.Response {
	snapshot := failure.Snapshot()
	return output.Response{
		Command:   command,
		Status:    "failed",
		Summary:   snapshot.SummaryText(),
		Fields:    snapshot.ResultFields(),
		NextSteps: snapshot.NextSteps(),
	}
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

func operationResultResponse(command string, outputStatus string, result workflow.OperationResult, nextSteps []string) output.Response {
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
		operation.Fields = append([]output.Field(nil), result.Fields...)
	}
	responseNextSteps := append([]string(nil), nextSteps...)
	if len(responseNextSteps) == 0 {
		responseNextSteps = append([]string(nil), result.NextSteps...)
	}
	operation.NextSteps = append([]string(nil), responseNextSteps...)
	response := output.Response{
		Command:   command,
		Status:    status,
		Summary:   summary,
		Fields:    append([]output.Field(nil), result.Fields...),
		NextSteps: responseNextSteps,
	}
	if operation.Kind != "" {
		response.OperationResult = operation
	}
	return response
}

func validatedOperationResultResponse(command string, outputStatus string, result workflow.OperationResult, nextSteps []string) (output.Response, error) {
	response := operationResultResponse(command, outputStatus, result, nextSteps)
	if response.OperationResult != nil {
		operation, ok := response.OperationResult.(workflow.OperationResult)
		if !ok {
			return output.Response{}, fmt.Errorf("operation result response contains %T, want workflow.OperationResult", response.OperationResult)
		}
		if err := workflow.ValidateNoSecretOutput(operation); err != nil {
			return output.Response{}, err
		}
	}
	return response, nil
}

func writeOperationResult(formatter responseWriter, command string, outputStatus string, result workflow.OperationResult, nextSteps []string) error {
	response, err := validatedOperationResultResponse(command, outputStatus, result, nextSteps)
	if err != nil {
		return err
	}
	return formatter.Write(response)
}

func workflowOutputStatus(command string, result workflow.OperationResult) string {
	if status := workflowOutputStatusFromDiagnostics(command, result); status != "" {
		return status
	}
	switch result.Kind {
	case domain.JobKindDeploy:
		if result.Status == domain.JobStatusSucceeded {
			return "applied"
		}
		for _, field := range result.Fields {
			if strings.TrimSpace(field.Label) == "preflight status" && strings.TrimSpace(field.Value) != "" {
				return strings.TrimSpace(field.Value)
			}
		}
		switch strings.TrimSpace(result.Summary) {
		case "no config file found":
			return "missing-config"
		case "config file exists but failed validation":
			return "invalid-config"
		}
		for _, diagnostic := range result.Diagnostics {
			if strings.HasPrefix(diagnostic.ID, "preflight-") {
				return "blocked"
			}
		}
	case domain.JobKindAppDeploy:
		if result.Status == domain.JobStatusSucceeded {
			return "applied"
		}
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.ID == "app-config" || diagnostic.ID == "app-main-config" {
				return "invalid-config"
			}
			if diagnostic.ID == "app-exposure-plan" || diagnostic.ID == "exposure-plan" || strings.HasPrefix(diagnostic.ID, "exposure-plan:") {
				return "blocked"
			}
		}
		if strings.Contains(strings.ToLower(result.Summary), "preflight") {
			return "blocked"
		}
	case domain.JobKindRealIPRefresh:
		if result.Status == domain.JobStatusSucceeded {
			return "refreshed"
		}
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.ID == "app-config" || diagnostic.ID == "realip-refresh-config" {
				return "invalid-config"
			}
			if diagnostic.ID == "app-exposure-plan" || diagnostic.ID == "exposure-plan" || strings.HasPrefix(diagnostic.ID, "exposure-plan:") {
				return "blocked"
			}
		}
		if strings.Contains(strings.ToLower(result.Summary), "preflight") || strings.Contains(strings.ToLower(result.Summary), "exposure plan") {
			return "blocked"
		}
	}
	return outputStatusForJobStatus(result.Status)
}

func workflowOutputStatusFromDiagnostics(command string, result workflow.OperationResult) string {
	prefix := strings.NewReplacer(" ", "_").Replace(strings.TrimSpace(command)) + ":"
	for _, diagnostic := range result.Diagnostics {
		id := strings.TrimSpace(diagnostic.ID)
		if strings.HasPrefix(id, prefix) {
			status := strings.TrimPrefix(id, prefix)
			status = strings.ReplaceAll(status, "_", "-")
			if strings.TrimSpace(status) != "" {
				return status
			}
		}
	}
	return ""
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
	fields := []output.Field{}
	if cause != nil {
		fields = append(fields, output.Field{Label: "details", Value: cause.Error()})
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
