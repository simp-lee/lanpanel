package hostworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/assets"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/render"
	"lanpanel/internal/state"
	"lanpanel/internal/verify"
	"lanpanel/internal/workflow"
	"os"
	"sort"
	"strings"
)

const (
	statusCheckpointLegoCommandDeferred         = "lego-command-deferred"
	statusCheckpointNginxActivated              = "nginx-site-activated"
	statusCheckpointSystemdDaemonReloadDeferred = "systemd-daemon-reload-deferred"
)

type StatusOptions struct {
	CheckpointPath     func(string) string
	CheckpointStore    func(string) state.Store
	StageRuntimeFiles  func(config.Config) ([]render.StagedFile, error)
	LoadMainConfigFile func(string) (config.Config, error)
}

type StatusResult struct {
	Operation    workflow.OperationResult
	OutputStatus string
	NextSteps    []string
}

func MainStatus(ctx context.Context, configPath string) (StatusResult, error) {
	return MainStatusWithOptions(ctx, configPath, StatusOptions{})
}

func MainStatusWithOptions(ctx context.Context, configPath string, options StatusOptions) (StatusResult, error) {
	if err := ctx.Err(); err != nil {
		result := statusOperation("failed", domain.JobStatusFailed, domain.DiagnosticStatusFail, "main status canceled before host workflow started", nil, retryStatusCommand(configPath))
		return StatusResult{Operation: result, OutputStatus: "failed"}, err
	}

	checkpointPathForConfig := options.CheckpointPath
	if checkpointPathForConfig == nil {
		checkpointPathForConfig = state.DefaultCheckpointPath
	}
	checkpointStoreForConfig := options.CheckpointStore
	if checkpointStoreForConfig == nil {
		checkpointStoreForConfig = func(configPath string) state.Store { return state.NewStore(checkpointPathForConfig(configPath)) }
	}
	loadConfigFile := options.LoadMainConfigFile
	if loadConfigFile == nil {
		loadConfigFile = config.LoadFile
	}
	stageRuntimeFiles := options.StageRuntimeFiles
	if stageRuntimeFiles == nil {
		stageRuntimeFiles = render.StageRuntime
	}

	checkpointPath := checkpointPathForConfig(configPath)
	if _, err := os.Stat(configPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newStatusResult(configPath, "missing-config", domain.JobStatusFailed, domain.DiagnosticStatusNotApplicable, "no config file found", []domain.ResultField{
				{Label: "config path", Value: configPath},
				{Label: "happy path", Value: "init -> deploy -> verify"},
			}, []string{
				fmt.Sprintf("Create the configuration for %s from the Management UI.", configPath),
			}), nil
		}
		return StatusResult{}, fmt.Errorf("stat config file: %w", err)
	}

	cfg, err := loadConfigFile(configPath)
	if err != nil {
		return newStatusResult(configPath, "invalid-config", domain.JobStatusFailed, domain.DiagnosticStatusNotApplicable, "config file exists but failed validation", []domain.ResultField{
			{Label: "config path", Value: configPath},
			{Label: "details", Value: err.Error()},
		}, []string{
			fmt.Sprintf("Fix the configuration at %s and retry verification from the Management UI.", configPath),
		}), nil
	}
	statusFields := func(extra ...domain.ResultField) []domain.ResultField {
		fields := append(mainConfigFields(configPath, cfg),
			domain.ResultField{Label: "minimum client version", Value: "Tailscale >= v" + verify.MinimumTailscaleClientVersion},
		)
		fields = append(fields, extra...)
		return fields
	}

	checkpoint, err := checkpointStoreForConfig(configPath).Load()
	if err != nil {
		return checkpointLoadFailureStatus(configPath, checkpointPath, err, statusFields())
	}
	if checkpoint.HasDeployContext() && strings.TrimSpace(checkpoint.DesiredStateDigest) == "" {
		return newStatusResult(configPath, "stale-deploy-context", domain.JobStatusUnknown, domain.DiagnosticStatusNotApplicable, "config is valid; persisted deploy context is missing its desired-state fingerprint", statusFields(
			domain.ResultField{Label: "checkpoint path", Value: checkpointPath},
			domain.ResultField{Label: "stale context", Value: "checkpoint data has no desired-state fingerprint; lanpanel will ignore that recovery data on the next deploy"},
		), []string{
			fmt.Sprintf("Regenerate recovery state for %s from the Management UI.", configPath),
			fmt.Sprintf("Inspect runtime readiness for %s from the Management UI.", configPath),
		}), nil
	}
	if checkpoint.HasDeployContext() && strings.TrimSpace(checkpoint.DesiredStateDigest) != "" {
		desiredStateDigest, err := deployDesiredStateDigest(cfg, stageRuntimeFiles)
		if err != nil {
			failure := desiredStateDigestFailure("status", configPath, err)
			result := failureStatusResult("failed", domain.JobStatusFailed, domain.DiagnosticStatusFail, failure.Snapshot())
			result.Operation.Fields = append(statusFields(), result.Operation.Fields...)
			return result, failure
		}
		if !checkpoint.MatchesDesiredState(desiredStateDigest) {
			return newStatusResult(configPath, "stale-deploy-context", domain.JobStatusUnknown, domain.DiagnosticStatusNotApplicable, "config is valid; persisted deploy context is stale for the current desired state", statusFields(
				domain.ResultField{Label: "checkpoint path", Value: checkpointPath},
				domain.ResultField{Label: "stale context", Value: "config changed since the recorded deploy context was saved; lanpanel will ignore that recovery data on the next deploy"},
			), []string{
				fmt.Sprintf("Record a fresh recovery point for %s from the Management UI.", configPath),
				fmt.Sprintf("Re-run runtime and onboarding readiness checks for %s from the Management UI.", configPath),
			}), nil
		}
	}

	checkpointFields := []domain.ResultField{{Label: "checkpoint path", Value: checkpointPath}}
	if checkpoint.CurrentCheckpoint != "" {
		checkpointFields = append(checkpointFields, domain.ResultField{Label: "current checkpoint", Value: checkpoint.CurrentCheckpoint})
	}
	if len(checkpoint.CompletedCheckpoints) > 0 {
		checkpointFields = append(checkpointFields, domain.ResultField{Label: "completed checkpoints", Value: strings.Join(checkpoint.CompletedCheckpoints, ", ")})
	}
	if len(checkpoint.ModifiedPaths) > 0 {
		checkpointFields = append(checkpointFields, domain.ResultField{Label: "modified paths", Value: summarizeModifiedPaths(checkpoint.ModifiedPaths)})
	}
	if len(checkpoint.ActivationHistory) > 0 {
		checkpointFields = append(checkpointFields, domain.ResultField{Label: "activation history", Value: joinActivations(checkpoint.ActivationHistory)})
	}
	if warnings := deferredCheckpointWarnings(checkpoint.CompletedCheckpoints); len(warnings) > 0 {
		checkpointFields = append(checkpointFields, domain.ResultField{Label: "warnings", Value: strings.Join(warnings, "; ")})
	}

	if checkpoint.LastFailure != nil {
		result := failureStatusResult("deploy-failed", domain.JobStatusFailed, domain.DiagnosticStatusFail, *checkpoint.LastFailure)
		result.Operation.Fields = append(statusFields(checkpointFields...), result.Operation.Fields...)
		return result, nil
	}

	if checkpoint.CurrentCheckpoint != "" {
		return newStatusResult(configPath, "deploy-checkpoint", domain.JobStatusUnknown, domain.DiagnosticStatusNotApplicable, "config is valid; resumable deploy checkpoint is available", statusFields(checkpointFields...), []string{
			fmt.Sprintf("Resume the recorded host checkpoint for %s from the Management UI.", configPath),
			fmt.Sprintf("Inspect runtime readiness for %s from the Management UI.", configPath),
		}), nil
	}

	if len(checkpoint.CompletedCheckpoints) > 0 || len(checkpoint.ModifiedPaths) > 0 || len(checkpoint.ActivationHistory) > 0 {
		return newStatusResult(configPath, "deploy-history", domain.JobStatusSucceeded, domain.DiagnosticStatusNotApplicable, "config is valid; last deploy context is available", statusFields(checkpointFields...), []string{
			fmt.Sprintf("Apply the current runtime asset set for %s again from the Management UI.", configPath),
			fmt.Sprintf("Inspect runtime readiness and client-version requirements for %s from the Management UI.", configPath),
		}), nil
	}

	return newStatusResult(configPath, "config-ready", domain.JobStatusSucceeded, domain.DiagnosticStatusNotApplicable, "config file is present and valid; no persisted deploy context yet", statusFields(checkpointFields...), []string{
		fmt.Sprintf("Apply the current runtime asset set for %s from the Management UI.", configPath),
		fmt.Sprintf("Run runtime and onboarding readiness checks for %s from the Management UI.", configPath),
	}), nil
}

func newStatusResult(configPath string, outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, summary string, fields []domain.ResultField, nextSteps []string) StatusResult {
	return StatusResult{
		Operation:    statusOperation(outputStatus, jobStatus, diagnosticStatus, summary, fields, retryStatusCommand(configPath)),
		OutputStatus: outputStatus,
		NextSteps:    append([]string(nil), nextSteps...),
	}
}

func statusOperation(outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, summary string, fields []domain.ResultField, retryCommand string) workflow.OperationResult {
	summary = strings.TrimSpace(summary)
	if diagnosticStatus == "" || diagnosticStatus == domain.DiagnosticStatusNotApplicable {
		diagnosticStatus = commandDiagnosticStatus(jobStatus)
	}
	return workflow.OperationResult{
		Kind:         domain.JobKindStatus,
		Status:       jobStatus,
		Summary:      summary,
		Fields:       append([]domain.ResultField(nil), fields...),
		RetryCommand: strings.TrimSpace(retryCommand),
		Diagnostics: []domain.DiagnosticItem{{
			ID:               "status:" + strings.NewReplacer(" ", "-", "_", "-").Replace(strings.TrimSpace(outputStatus)),
			Title:            "status",
			Status:           diagnosticStatus,
			Scope:            domain.DiagnosticScopeInstance,
			Severity:         commandDiagnosticSeverity(diagnosticStatus),
			Summary:          summary,
			EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
			ResponsibleParty: domain.DiagnosticResponsibleLanPanel,
			BlocksActivation: diagnosticStatus == domain.DiagnosticStatusFail,
			Redaction:        domain.RedactionNone,
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		}},
	}
}

func checkpointLoadFailureStatus(configPath string, checkpointPath string, err error, prefixFields []domain.ResultField) (StatusResult, error) {
	failure := checkpointLoadFailure("status", configPath, checkpointPath, err)
	snapshot := failure.Snapshot()
	result := failureStatusResult("failed", domain.JobStatusFailed, domain.DiagnosticStatusFail, snapshot)
	result.Operation.Fields = append(append([]domain.ResultField(nil), prefixFields...), result.Operation.Fields...)
	result.Operation.Fields = append(result.Operation.Fields, domain.ResultField{Label: "checkpoint path", Value: checkpointPath})
	return result, failure
}

func checkpointLoadFailure(command string, configPath string, checkpointPath string, err error) workflow.Failure {
	retryCommand := workflow.ShellCommand("lanpanel", command, "--config", configPath)
	failure := workflow.Failure{
		Step:         "load deploy checkpoint",
		Operation:    "reading persisted deploy recovery state",
		Impact:       "lanpanel cannot use the saved recovery state until the checkpoint file can be read",
		RetryCommand: retryCommand,
		Cause:        err,
		Remediation: []string{
			fmt.Sprintf("Repair or remove the checkpoint at %s so lanpanel can continue.", checkpointPath),
			fmt.Sprintf("Fix the checkpoint path permissions and rerun %s.", retryCommand),
		},
	}

	var loadErr *state.LoadError
	if errors.As(err, &loadErr) && loadErr.Kind == state.LoadErrorDecode {
		failure.Impact = "lanpanel cannot trust the saved recovery state until the checkpoint file is repaired or removed"
		failure.Remediation = []string{
			fmt.Sprintf("Repair or remove the checkpoint at %s if you do not need to resume the previous deploy.", checkpointPath),
			fmt.Sprintf("Remove the unreadable checkpoint and rerun %s to regenerate recovery state.", retryCommand),
		}
	}
	return failure
}

func desiredStateDigestFailure(command string, configPath string, err error) workflow.Failure {
	impact := "lanpanel cannot compare or apply the current runtime asset set until the desired state fingerprint succeeds"
	if command == "status" {
		impact = "lanpanel cannot summarize deploy recovery state until the desired state fingerprint succeeds"
	}

	return workflow.Failure{
		Step:         "fingerprint desired state",
		Operation:    "building the current runtime asset fingerprint",
		Impact:       impact,
		RetryCommand: workflow.ShellCommand("lanpanel", command, "--config", configPath),
		Cause:        err,
		Remediation: []string{
			"Fix the runtime template or config inputs that prevented staging the current runtime assets.",
		},
	}
}

func failureStatusResult(outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, snapshot workflow.FailureSnapshot) StatusResult {
	result := StatusResult{
		Operation:    statusOperation(outputStatus, jobStatus, diagnosticStatus, snapshot.SummaryText(), snapshot.ResultFields(), snapshot.RetryCommand),
		OutputStatus: outputStatus,
		NextSteps:    snapshot.NextSteps(),
	}
	return result
}

func mainConfigFields(path string, cfg config.Config) []domain.ResultField {
	return []domain.ResultField{
		{Label: "config path", Value: path},
		{Label: "server url", Value: cfg.Default.ServerURL},
		{Label: "base domain", Value: cfg.Default.BaseDomain},
		{Label: "acme challenge", Value: cfg.Default.ACMEChallenge},
	}
}

func deployDesiredStateDigest(cfg config.Config, stageRuntimeFiles func(config.Config) ([]render.StagedFile, error)) (string, error) {
	stagedFiles, err := stageRuntimeFiles(cfg)
	if err != nil {
		return "", err
	}
	return deployDesiredStateDigestForStaged(cfg, stagedFiles)
}

func deployDesiredStateDigestForStaged(cfg config.Config, stagedFiles []render.StagedFile) (string, error) {
	type runtimeAssetFingerprint struct {
		SourcePath    string   `json:"source_path"`
		HostPath      string   `json:"host_path"`
		ContentMode   string   `json:"content_mode"`
		Mode          uint32   `json:"mode"`
		Activations   []string `json:"activations,omitempty"`
		ContentSHA256 string   `json:"content_sha256"`
	}
	type desiredStateFingerprint struct {
		Config       config.Config             `json:"config"`
		RuntimeFiles []runtimeAssetFingerprint `json:"runtime_files"`
	}

	runtimeFiles := make([]runtimeAssetFingerprint, 0, len(stagedFiles))
	for _, file := range stagedFiles {
		activations := make([]string, 0, len(file.Activations))
		for _, activation := range file.Activations {
			activations = append(activations, string(activation))
		}

		contentSum := sha256.Sum256(file.Content)
		runtimeFiles = append(runtimeFiles, runtimeAssetFingerprint{
			SourcePath:    file.SourcePath,
			HostPath:      file.HostPath,
			ContentMode:   string(file.ContentMode),
			Mode:          uint32(file.Mode.Perm()),
			Activations:   activations,
			ContentSHA256: hex.EncodeToString(contentSum[:]),
		})
	}
	sort.Slice(runtimeFiles, func(i, j int) bool {
		if runtimeFiles[i].HostPath == runtimeFiles[j].HostPath {
			return runtimeFiles[i].SourcePath < runtimeFiles[j].SourcePath
		}
		return runtimeFiles[i].HostPath < runtimeFiles[j].HostPath
	})

	payload, err := json.Marshal(desiredStateFingerprint{Config: cfg, RuntimeFiles: runtimeFiles})
	if err != nil {
		return "", fmt.Errorf("marshal desired state fingerprint: %w", err)
	}

	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func joinActivations(activations []assets.Activation) string {
	if len(activations) == 0 {
		return "none"
	}

	labels := make([]string, 0, len(activations))
	for _, activation := range activations {
		labels = append(labels, string(activation))
	}
	return strings.Join(labels, ", ")
}

func summarizeModifiedPaths(paths []string) string {
	if len(paths) == 0 {
		return "none"
	}

	const maxPaths = 5
	shown := paths
	suffix := ""
	if len(paths) > maxPaths {
		shown = paths[:maxPaths]
		suffix = fmt.Sprintf(", ... (%d more; see checkpoint file for the full list)", len(paths)-maxPaths)
	}
	return fmt.Sprintf("%d total: %s%s", len(paths), strings.Join(shown, ", "), suffix)
}

func deferredCheckpointWarnings(completedCheckpoints []string) []string {
	warnings := make([]string, 0, 2)
	if containsCompletedCheckpoint(completedCheckpoints, statusCheckpointLegoCommandDeferred) {
		if containsCompletedCheckpoint(completedCheckpoints, statusCheckpointNginxActivated) {
			warnings = append(warnings, "lego is not installed; public certificate issuance was deferred and Nginx remains on the temporary HTTP-01 bootstrap certificate")
		} else {
			warnings = append(warnings, "lego is not installed; certificate issuance and Nginx activation were deferred")
		}
	}
	if containsCompletedCheckpoint(completedCheckpoints, statusCheckpointSystemdDaemonReloadDeferred) {
		warnings = append(warnings, "systemd is unavailable; service enablement and onboarding were deferred")
	}
	return warnings
}

func containsCompletedCheckpoint(completedCheckpoints []string, want string) bool {
	trimmedWant := strings.TrimSpace(want)
	for _, checkpoint := range completedCheckpoints {
		if strings.TrimSpace(checkpoint) == trimmedWant {
			return true
		}
	}
	return false
}

func retryStatusCommand(configPath string) string {
	if strings.TrimSpace(configPath) == "" {
		return ""
	}
	return workflow.ShellCommand("lanpanel", "status", "--config", configPath)
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
