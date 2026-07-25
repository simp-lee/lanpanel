package ui

import (
	"bytes"
	stdcontext "context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apprender"
	"lanpanel/internal/browserauth"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/resource"
	"lanpanel/internal/state"
	"lanpanel/internal/uistate"
	"lanpanel/internal/workflow"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

var activeNginxSitesAvailableDir = "/etc/nginx/sites-available"

const dependencyUploadFileField = "dependency_upload_file"

type jobOperation struct {
	kind                 domain.JobKind
	confirmations        []string
	checkpointRef        domain.ActivationRef
	retryCommand         string
	configSnapshotSource string
	configSnapshotName   string
	appConfigPath        string
	cleanup              func() error
	run                  func(workflow.ManualConfirmationRecorder) (workflow.OperationResult, error)
}

type jobExecution struct {
	operation          jobOperation
	record             domain.JobRecord
	locks              []*uistate.Lock
	sessionFingerprint string
}

func (server *Server) startJob(r *http.Request) (domain.JobRecord, error) {
	if err := server.currentStoreFailure(); err != nil {
		return domain.JobRecord{}, err
	}
	execution, err := server.prepareJob(r, stdcontext.Background())
	if err != nil {
		return domain.JobRecord{}, err
	}
	go func() {
		_, record, err := server.executePreparedJob(execution)
		if err != nil {
			if strings.TrimSpace(record.ID) == "" {
				record = execution.record
			}
			server.recordBackgroundJobFailure(record, err)
		}
	}()
	return execution.record, nil
}

// runJob is the synchronous test/integration helper; HTTP handlers use startJob.
func (server *Server) runJob(r *http.Request) (result workflow.OperationResult, record domain.JobRecord, returnErr error) {
	if err := server.currentStoreFailure(); err != nil {
		return workflow.OperationResult{}, domain.JobRecord{}, err
	}
	execution, err := server.prepareJob(r, r.Context())
	if err != nil {
		return workflow.OperationResult{}, domain.JobRecord{}, err
	}
	return server.executePreparedJob(execution)
}

func (server *Server) prepareJob(r *http.Request, baseContext stdcontext.Context) (jobExecution, error) {
	if err := server.currentStoreFailure(); err != nil {
		return jobExecution{}, err
	}
	jobRequest, err := cloneJobRequest(r, baseContext)
	if err != nil {
		return jobExecution{}, err
	}
	operation, err := server.jobOperation(jobRequest, baseContext)
	if err != nil {
		return jobExecution{}, appendJobCleanupError(err, cleanupRequestMultipartForm(jobRequest))
	}
	actor, err := server.actorForRequest(jobRequest)
	if err != nil {
		return jobExecution{}, cleanupJobOperation(&operation, err)
	}
	sessionFingerprint, ok := server.sessionFingerprintFromRequest(jobRequest)
	if !ok {
		return jobExecution{}, cleanupJobOperation(&operation, fmt.Errorf("valid session is required for job handoff"))
	}
	locks, err := server.acquireJobLocks(operation)
	if err != nil {
		return jobExecution{}, cleanupJobOperation(&operation, err)
	}
	releaseOnError := func(cause error) error {
		cause = cleanupJobOperation(&operation, cause)
		if releaseErr := releaseJobLocks(locks); releaseErr != nil {
			return fmt.Errorf("%w; release job locks failed: %v", cause, releaseErr)
		}
		return cause
	}
	checkpointRef := operation.checkpointRef
	if checkpointRef.Kind == "" {
		checkpointRef = domain.NotApplicableActivationRef()
	}
	configSnapshotRef := ""
	if strings.TrimSpace(operation.configSnapshotSource) == "" {
		configSnapshotRef = "not_applicable"
	}
	record, err := server.state.CreateJob(domain.JobRecord{
		Kind:              operation.kind,
		Status:            domain.JobStatusRunning,
		Actor:             actor,
		CheckpointRef:     checkpointRef,
		RetryCommand:      explicitJobField(operation.retryCommand),
		ConfigSnapshotRef: configSnapshotRef,
	})
	if err != nil {
		return jobExecution{}, releaseOnError(err)
	}
	failPreparedJob := func(cause error) error {
		if persistErr := server.markPreparedJobFailed(record, operation, cause); persistErr != nil {
			cause = fmt.Errorf("%w; %v", cause, persistErr)
		}
		return releaseOnError(cause)
	}
	for _, lock := range locks {
		if err := lock.AttachJob(record.ID); err != nil {
			return jobExecution{}, failPreparedJob(err)
		}
	}
	if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusManual, Message: "job started"}); err != nil {
		return jobExecution{}, failPreparedJob(err)
	}
	return jobExecution{operation: operation, record: record, locks: locks, sessionFingerprint: sessionFingerprint}, nil
}

func (server *Server) markPreparedJobFailed(record domain.JobRecord, operation jobOperation, cause error) error {
	record.Status = domain.JobStatusFailed
	record.ErrorSummary = safeJobText("job preparation failed: " + cause.Error())
	record.RetryCommand = explicitJobField(operation.retryCommand)
	record.ConfigSnapshotRef = explicitJobField(record.ConfigSnapshotRef)
	var persistErr error
	if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusFail, Message: record.ErrorSummary}); err != nil {
		persistErr = fmt.Errorf("append job preparation failure event: %w", err)
	}
	if err := server.state.SaveRecord(record); err != nil {
		if persistErr != nil {
			persistErr = fmt.Errorf("%w; save job preparation failure record: %v", persistErr, err)
		} else {
			persistErr = fmt.Errorf("save job preparation failure record: %w", err)
		}
	}
	return persistErr
}

func (server *Server) acquireJobLocks(operation jobOperation) ([]*uistate.Lock, error) {
	locks := []*uistate.Lock{}
	if hostMutationJobKind(operation.kind) {
		lock, err := server.state.AcquireNamedLock(operation.kind, uistate.HostMutationLockName)
		if err != nil {
			return nil, err
		}
		locks = append(locks, lock)
	}
	lock, err := server.state.AcquireLock(operation.kind)
	if err != nil {
		if releaseErr := releaseJobLocks(locks); releaseErr != nil {
			return nil, fmt.Errorf("%w; release job locks failed: %v", err, releaseErr)
		}
		return nil, err
	}
	locks = append(locks, lock)
	return locks, nil
}

func hostMutationJobKind(kind domain.JobKind) bool {
	switch kind {
	case domain.JobKindConfigSave,
		domain.JobKindDeploy,
		domain.JobKindDependencyUpload,
		domain.JobKindAppInit,
		domain.JobKindAppConfigSave,
		domain.JobKindAppDeploy,
		domain.JobKindRealIPRefresh,
		domain.JobKindPreAuthKeyCreate,
		domain.JobKindBrowserAuthCreate,
		domain.JobKindBrowserAuthRotate,
		domain.JobKindBrowserAuthDelete:
		return true
	default:
		return false
	}
}

func releaseJobLocks(locks []*uistate.Lock) error {
	var releaseErr error
	for i := len(locks) - 1; i >= 0; i-- {
		if err := locks[i].Release(); err != nil {
			if releaseErr == nil {
				releaseErr = err
			} else {
				releaseErr = fmt.Errorf("%w; %v", releaseErr, err)
			}
		}
	}
	return releaseErr
}

func (server *Server) executePreparedJob(execution jobExecution) (result workflow.OperationResult, record domain.JobRecord, returnErr error) {
	operation := execution.operation
	record = execution.record
	defer func() {
		returnErr = cleanupJobOperation(&operation, returnErr)
		if err := releaseJobLocks(execution.locks); err != nil {
			if returnErr != nil {
				returnErr = fmt.Errorf("%w; release job locks failed: %v", returnErr, err)
				return
			}
			returnErr = fmt.Errorf("release job locks failed: %w", err)
		}
	}()
	result, runErr := operation.run(func(confirmations []string) ([]domain.ManualConfirmation, error) {
		return server.recordManualConfirmations(record.ID, record.Actor, confirmations)
	})
	if runErr != nil {
		failureCause := runErr
		result = typedJobRunFailureResult(operation, result, runErr, server.options.Now)
		if secretErr := workflow.ValidateNoSecretOutput(result); secretErr != nil {
			failureCause = secretErr
			result = workflow.OperationResult{
				Kind:         operation.kind,
				Status:       domain.JobStatusFailed,
				Summary:      secretErr.Error(),
				RetryCommand: operation.retryCommand,
				Progress:     []workflow.ProgressEvent{{At: server.options.Now().UTC(), Kind: operation.kind, Status: domain.DiagnosticStatusFail, Message: secretErr.Error()}},
			}
		}
		runErrText := safeJobText(failureCause.Error())
		record.Status = domain.JobStatusFailed
		record.ErrorSummary = runErrText
		if result.Kind != "" && result.Kind != operation.kind {
			return workflow.OperationResult{}, domain.JobRecord{}, fmt.Errorf("operation returned kind %q, want %q", result.Kind, operation.kind)
		}
		if result.Status == domain.JobStatusFailed || result.Status == domain.JobStatusInterrupted || result.Status == domain.JobStatusUnknown {
			record.Status = result.Status
		}
		record.ResultSummary = safeJobText(result.Summary)
		record.ModifiedPaths = append([]string(nil), result.ModifiedPaths...)
		record.RetryCommand = explicitJobField(jobRetryCommand(result.RetryCommand, operation.retryCommand))
		if result.ExposurePlan != nil {
			record.ResourceIDs = []string{result.ExposurePlan.Resource.ID}
		}
		snapshotRef, snapshotErr := server.configSnapshotRef(record.ID, operation)
		if snapshotErr != nil {
			record, err := server.persistSnapshotFailure(record, result, "operation failed: "+runErrText, snapshotErr)
			if err != nil {
				return workflow.OperationResult{}, domain.JobRecord{}, err
			}
			return workflow.OperationResult{}, record, nil
		}
		record.ConfigSnapshotRef = snapshotRef
		if err := server.appendProgressEvents(record.ID, result.Progress); err != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, err
		}
		if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusFail, Message: runErrText}); err != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, err
		}
		if err := server.state.SaveRecord(record); err != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, err
		}
		return workflow.OperationResult{}, record, nil
	}
	if result.Kind != operation.kind {
		return workflow.OperationResult{}, domain.JobRecord{}, fmt.Errorf("operation returned kind %q, want %q", result.Kind, operation.kind)
	}
	if result.Status == "" {
		result.Status = domain.JobStatusSucceeded
	}
	if err := workflow.ValidateNoSecretOutput(result); err != nil {
		record.Status = domain.JobStatusFailed
		record.ErrorSummary = safeJobText(err.Error())
		if _, appendErr := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusFail, Message: record.ErrorSummary}); appendErr != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, appendErr
		}
		if saveErr := server.state.SaveRecord(record); saveErr != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, saveErr
		}
		return workflow.OperationResult{}, record, nil
	}
	record.Status = result.Status
	record.ResultSummary = safeJobText(result.Summary)
	record.ModifiedPaths = append([]string(nil), result.ModifiedPaths...)
	record.RetryCommand = explicitJobField(jobRetryCommand(result.RetryCommand, operation.retryCommand))
	if result.ExposurePlan != nil {
		record.ResourceIDs = []string{result.ExposurePlan.Resource.ID}
	}
	snapshotRef, err := server.configSnapshotRef(record.ID, operation)
	if err != nil {
		record, saveErr := server.persistSnapshotFailure(record, result, snapshotFailurePrimary(record, result), err)
		if saveErr != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, saveErr
		}
		return result, record, nil
	}
	record.ConfigSnapshotRef = snapshotRef
	if strings.TrimSpace(operation.appConfigPath) != "" && record.Status == domain.JobStatusSucceeded {
		if err := server.state.RegisterAppConfigPath(operation.appConfigPath); err != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, err
		}
	}
	if err := server.state.SaveRecord(record); err != nil {
		return workflow.OperationResult{}, domain.JobRecord{}, err
	}
	if err := server.appendProgressEvents(record.ID, result.Progress); err != nil {
		return workflow.OperationResult{}, domain.JobRecord{}, err
	}
	if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: diagnosticForJobStatus(record.Status), Message: safeJobText(result.Summary)}); err != nil {
		return workflow.OperationResult{}, domain.JobRecord{}, err
	}
	if err := server.appendResultFieldEvents(record.ID, result.Fields, diagnosticForJobStatus(record.Status)); err != nil {
		return workflow.OperationResult{}, domain.JobRecord{}, err
	}
	if result.OneTimeSecret != nil {
		if _, stored, err := server.storeOneTimeSecretForJob(record.ID, execution.sessionFingerprint, result.OneTimeSecret); err != nil {
			return workflow.OperationResult{}, domain.JobRecord{}, err
		} else if stored {
			if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusManual, Message: "handoff ready for current session"}); err != nil {
				return workflow.OperationResult{}, domain.JobRecord{}, err
			}
		}
	}
	return result, record, nil
}

func cleanupJobOperation(operation *jobOperation, cause error) error {
	if operation == nil || operation.cleanup == nil {
		return cause
	}
	cleanup := operation.cleanup
	operation.cleanup = nil
	if err := cleanup(); err != nil {
		return appendJobCleanupError(cause, err)
	}
	return cause
}

func appendJobCleanupError(cause error, cleanupErr error) error {
	if cleanupErr == nil {
		return cause
	}
	if cause == nil {
		return fmt.Errorf("cleanup job staging failed: %w", cleanupErr)
	}
	return fmt.Errorf("%w; cleanup job staging failed: %v", cause, cleanupErr)
}

func cleanupRequestMultipartForm(r *http.Request) error {
	if r == nil || r.MultipartForm == nil {
		return nil
	}
	if err := r.MultipartForm.RemoveAll(); err != nil {
		return fmt.Errorf("remove multipart upload files: %w", err)
	}
	return nil
}

func (server *Server) persistSnapshotFailure(record domain.JobRecord, result workflow.OperationResult, primary string, cause error) (domain.JobRecord, error) {
	record.ConfigSnapshotRef = ""
	if record.Status == "" || record.Status == domain.JobStatusSucceeded {
		record.Status = domain.JobStatusFailed
	}
	record.ErrorSummary = combineJobFailureSummaries(primary, fmt.Sprintf("config snapshot failed: %v", cause))
	if err := server.appendProgressEvents(record.ID, result.Progress); err != nil {
		return domain.JobRecord{}, err
	}
	resultSummary := safeJobText(result.Summary)
	if resultSummary != "" && resultSummary != record.ErrorSummary {
		if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusFail, Message: resultSummary}); err != nil {
			return domain.JobRecord{}, err
		}
	}
	if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusFail, Message: record.ErrorSummary}); err != nil {
		return domain.JobRecord{}, err
	}
	if err := server.state.SaveRecord(record); err != nil {
		return domain.JobRecord{}, err
	}
	return record, nil
}

func snapshotFailurePrimary(record domain.JobRecord, result workflow.OperationResult) string {
	for _, value := range []string{record.ErrorSummary, result.Summary, record.ResultSummary} {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	if result.Status != "" {
		return "operation status: " + string(result.Status)
	}
	return ""
}

func combineJobFailureSummaries(primary string, secondary string) string {
	primary = safeJobText(primary)
	secondary = safeJobText(secondary)
	switch {
	case primary == "":
		return secondary
	case secondary == "":
		return primary
	default:
		return primary + "; " + secondary
	}
}

func safeJobText(text string) string {
	return uistate.SanitizeJobText(text)
}

func typedJobRunFailureResult(operation jobOperation, result workflow.OperationResult, cause error, now func() time.Time) workflow.OperationResult {
	if result.Kind != "" || result.Status != "" || strings.TrimSpace(result.Summary) != "" || len(result.Diagnostics) > 0 || len(result.Progress) > 0 || strings.TrimSpace(result.RetryCommand) != "" {
		return result
	}
	if now == nil {
		now = time.Now
	}
	summary := string(operation.kind) + " failed before workflow execution"
	causeText := safeJobText(cause.Error())
	return workflow.OperationResult{
		Kind:    operation.kind,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "details", Value: causeText},
		},
		Diagnostics: []domain.DiagnosticItem{{
			ID:               "ui-job-input",
			Title:            string(operation.kind),
			Status:           domain.DiagnosticStatusFail,
			Scope:            domain.DiagnosticScopeInstance,
			Severity:         domain.DiagnosticSeverityCritical,
			Summary:          causeText,
			EvidenceSource:   domain.DiagnosticEvidenceConfig,
			ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
			BlocksActivation: true,
			Redaction:        domain.RedactionNone,
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		}},
		RetryCommand: jobRetryCommand("", operation.retryCommand),
		Progress: []workflow.ProgressEvent{{
			At:      now().UTC(),
			Kind:    operation.kind,
			Status:  domain.DiagnosticStatusFail,
			Message: summary,
		}},
	}
}

func (server *Server) appendProgressEvents(jobID string, events []workflow.ProgressEvent) error {
	for _, event := range events {
		status := event.Status
		if status == "" {
			status = domain.DiagnosticStatusManual
		}
		if _, err := server.state.AppendEvent(jobID, uistate.Event{At: event.At, Status: status, Message: safeJobText(event.Message)}); err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) appendResultFieldEvents(jobID string, fields []domain.ResultField, status domain.DiagnosticStatus) error {
	seen := map[string]struct{}{}
	for _, field := range fields {
		label := safeResultFieldLabel(field.Label)
		value := safeJobText(field.Value)
		if label == "" && value == "" {
			continue
		}
		message := "result detail"
		if label != "" {
			message += ": " + label
		}
		if value != "" {
			message += ": " + value
		}
		if _, ok := seen[message]; ok {
			continue
		}
		seen[message] = struct{}{}
		if _, err := server.state.AppendEvent(jobID, uistate.Event{Status: status, Message: message}); err != nil {
			return err
		}
	}
	return nil
}

func safeResultFieldLabel(label string) string {
	label = strings.TrimSpace(label)
	lower := strings.ToLower(label)
	if strings.Contains(lower, "fingerprint") && (strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "auth")) {
		return "credential fingerprint"
	}
	if uistate.RedactText(label) != label {
		return "result field"
	}
	return label
}

func (server *Server) recordBackgroundJobFailure(record domain.JobRecord, cause error) {
	if persisted, err := server.state.LoadRecord(record.ID); err == nil {
		record = persisted
	} else {
		server.rememberStoreFailure(fmt.Errorf("background job %s failed and current failure record could not be loaded: %w", record.ID, err))
	}
	record.Status = domain.JobStatusFailed
	causeText := safeJobText(cause.Error())
	record.ErrorSummary = causeText
	if _, err := server.state.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusFail, Message: causeText}); err != nil {
		server.rememberStoreFailure(fmt.Errorf("background job %s failed and failure event could not be persisted: %w", record.ID, err))
		return
	}
	if err := server.state.SaveRecord(record); err != nil {
		server.rememberStoreFailure(fmt.Errorf("background job %s failed and failure record could not be persisted: %w", record.ID, err))
	}
}

func (server *Server) rememberStoreFailure(cause error) {
	if cause == nil {
		return
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.storeErr == nil {
		server.storeErr = cause
	}
}

func (server *Server) currentStoreFailure() error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.storeErr == nil {
		return nil
	}
	return fmt.Errorf("ui job store is failed: %w", server.storeErr)
}

func cloneJobRequest(r *http.Request, baseContext stdcontext.Context) (*http.Request, error) {
	if err := parseUIForm(r); err != nil {
		return nil, fmt.Errorf("parse job form: %w", err)
	}
	cloned := r.Clone(baseContext)
	cloned.Header = r.Header.Clone()
	cloned.Form = cloneValues(r.Form)
	cloned.PostForm = cloneValues(r.PostForm)
	cloned.MultipartForm = r.MultipartForm
	return cloned, nil
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, vals := range values {
		cloned[key] = append([]string(nil), vals...)
	}
	return cloned
}

func (server *Server) stageDependencyUpload(r *http.Request) (workflow.UploadedDependencyArtifact, func() error, error) {
	if r.MultipartForm == nil {
		return workflow.UploadedDependencyArtifact{}, nil, fmt.Errorf("dependency upload must use multipart/form-data")
	}
	files := r.MultipartForm.File[dependencyUploadFileField]
	if len(files) != 1 {
		return workflow.UploadedDependencyArtifact{}, nil, appendJobCleanupError(fmt.Errorf("exactly one dependency upload file is required"), cleanupRequestMultipartForm(r))
	}
	header := files[0]
	filename := strings.TrimSpace(header.Filename)
	if filename == "" {
		return workflow.UploadedDependencyArtifact{}, nil, appendJobCleanupError(fmt.Errorf("dependency upload filename is required"), cleanupRequestMultipartForm(r))
	}
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return workflow.UploadedDependencyArtifact{}, nil, appendJobCleanupError(fmt.Errorf("dependency upload filename must not contain path separators"), cleanupRequestMultipartForm(r))
	}
	file, err := header.Open()
	if err != nil {
		return workflow.UploadedDependencyArtifact{}, nil, appendJobCleanupError(fmt.Errorf("open dependency upload: %w", err), cleanupRequestMultipartForm(r))
	}
	sourceClosed := false
	closeSource := func(cause error) error {
		if sourceClosed {
			return cause
		}
		sourceClosed = true
		if err := file.Close(); err != nil {
			if cause == nil {
				return fmt.Errorf("close dependency upload source file: %w", err)
			}
			return fmt.Errorf("%w; close dependency upload source file: %v", cause, err)
		}
		return cause
	}
	stagingDir := filepath.Join(server.options.StateDir, "uploads", "dependencies")
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return workflow.UploadedDependencyArtifact{}, nil, appendJobCleanupError(closeSource(fmt.Errorf("create dependency upload staging directory: %w", err)), cleanupRequestMultipartForm(r))
	}
	tmp, err := os.CreateTemp(stagingDir, ".dependency-upload-*.artifact")
	if err != nil {
		return workflow.UploadedDependencyArtifact{}, nil, appendJobCleanupError(closeSource(fmt.Errorf("create dependency upload staging file: %w", err)), cleanupRequestMultipartForm(r))
	}
	tmpPath := tmp.Name()
	closed := false
	closeTmp := func() error {
		if closed {
			return nil
		}
		closed = true
		return tmp.Close()
	}
	cleanup := func() error {
		var cleanupErr error
		if err := closeTmp(); err != nil {
			cleanupErr = fmt.Errorf("close dependency upload staging file: %w", err)
		}
		if err := os.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			if cleanupErr == nil {
				cleanupErr = fmt.Errorf("remove dependency upload staging file: %w", err)
			} else {
				cleanupErr = fmt.Errorf("%w; remove dependency upload staging file: %v", cleanupErr, err)
			}
		}
		if r.MultipartForm != nil {
			if err := r.MultipartForm.RemoveAll(); err != nil {
				if cleanupErr == nil {
					cleanupErr = fmt.Errorf("remove dependency upload multipart files: %w", err)
				} else {
					cleanupErr = fmt.Errorf("%w; remove dependency upload multipart files: %v", cleanupErr, err)
				}
			}
		}
		return cleanupErr
	}
	fail := func(cause error) (workflow.UploadedDependencyArtifact, func() error, error) {
		cause = closeSource(cause)
		return workflow.UploadedDependencyArtifact{}, nil, appendJobCleanupError(cause, cleanup())
	}
	written, err := io.Copy(tmp, io.LimitReader(file, workflow.DependencyUploadMaxBytes+1))
	if err != nil {
		return fail(fmt.Errorf("write dependency upload staging file: %w", err))
	}
	if err := closeSource(nil); err != nil {
		return fail(err)
	}
	if written <= 0 {
		return fail(fmt.Errorf("dependency upload file must not be empty"))
	}
	if written > workflow.DependencyUploadMaxBytes {
		return fail(fmt.Errorf("dependency upload file exceeds %d bytes", workflow.DependencyUploadMaxBytes))
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("chmod dependency upload staging file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("sync dependency upload staging file: %w", err))
	}
	if err := closeTmp(); err != nil {
		return fail(fmt.Errorf("close dependency upload staging file: %w", err))
	}
	return workflow.UploadedDependencyArtifact{Path: tmpPath, Filename: filename, Size: written}, cleanup, nil
}

func (server *Server) jobOperation(r *http.Request, baseContext stdcontext.Context) (jobOperation, error) {
	if err := parseUIForm(r); err != nil {
		return jobOperation{}, fmt.Errorf("parse job form: %w", err)
	}
	actor, err := server.actorForRequest(r)
	if err != nil {
		return jobOperation{}, err
	}
	confirmations, err := confirmationValues(r)
	if err != nil {
		return jobOperation{}, err
	}
	instanceID := func() (string, error) {
		instance, err := resource.NewStore(filepath.Join(server.options.StateDir, "resources")).LoadOrCreateInstance()
		if err != nil {
			return "", err
		}
		return instance.ID, nil
	}
	ctx := workflow.Context{
		Version:              server.options.Version,
		Actor:                actor,
		BaseContext:          baseContext,
		HostWorkflow:         server.options.HostWorkflow,
		PreAuthKeyCreator:    server.options.PreAuthKeyCreator,
		Confirmations:        confirmations,
		ExposureObservations: server.options.ExposureObservations,
		AppInstanceIDProvider: func() (string, string, error) {
			id, err := instanceID()
			return id, "persisted resource state", err
		},
		Now: server.options.Now,
	}
	if server.options.HostWorkflow != nil {
		ctx.BrowserAuthDependencyEnsurer = server.options.HostWorkflow.EnsureBrowserAuthDependencies
	}
	switch formValue(r, "operation") {
	case "main_init":
		mainConfigPath, err := server.mainConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindConfigSave, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "init", "--config", mainConfigPath), configSnapshotSource: mainConfigPath, configSnapshotName: "main-config.yaml", run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunMainInit(ctx, mainConfigPath)
		}}, nil
	case "main_config_save":
		mainConfigPath, err := server.mainConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindConfigSave, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "ui", "--config", mainConfigPath), configSnapshotSource: mainConfigPath, configSnapshotName: "main-config.yaml", run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			path, cfg, err := server.mainConfigFromRequest(r)
			if err != nil {
				return workflow.OperationResult{}, err
			}
			return workflow.RunMainConfigSave(ctx, path, cfg)
		}}, nil
	case "main_lego_archive_upload":
		mainConfigPath, err := server.mainConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		artifact, cleanup, err := server.stageDependencyUpload(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindDependencyUpload, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui", "--config", mainConfigPath), configSnapshotSource: mainConfigPath, configSnapshotName: "main-config.yaml", cleanup: cleanup, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunMainLegoArchiveUpload(ctx, mainConfigPath, artifact)
		}}, nil
	case "main_headscale_deb_upload":
		mainConfigPath, err := server.mainConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		artifact, cleanup, err := server.stageDependencyUpload(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindDependencyUpload, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui", "--config", mainConfigPath), configSnapshotSource: mainConfigPath, configSnapshotName: "main-config.yaml", cleanup: cleanup, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunMainHeadscalePackageUpload(ctx, mainConfigPath, artifact)
		}}, nil
	case "main_verify":
		mainConfigPath, err := server.mainConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindVerify, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "verify", "--config", mainConfigPath), configSnapshotSource: mainConfigPath, configSnapshotName: "main-config.yaml", run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunMainVerify(ctx, mainConfigPath)
		}}, nil
	case "main_deploy":
		mainConfigPath, err := server.mainConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindDeploy, confirmations: confirmations, checkpointRef: domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: state.DefaultCheckpointPath(mainConfigPath)}, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "deploy", "--config", mainConfigPath), configSnapshotSource: mainConfigPath, configSnapshotName: "main-config.yaml", run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunMainDeploy(ctx, mainConfigPath)
		}}, nil
	case "main_status":
		mainConfigPath, err := server.mainConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindStatus, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "status", "--config", mainConfigPath), configSnapshotSource: mainConfigPath, configSnapshotName: "main-config.yaml", run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunMainStatus(ctx, mainConfigPath)
		}}, nil
	case "app_init":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindAppInit, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "app", "init", "--config", appConfigPath), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunAppInit(ctx, appConfigPath)
		}}, nil
	case "app_config_save":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindAppConfigSave, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "ui", "--app-config", appConfigPath), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			path, cfg, err := server.appConfigFromRequest(r)
			if err != nil {
				return workflow.OperationResult{}, err
			}
			id, err := instanceID()
			if err != nil {
				return workflow.OperationResult{}, err
			}
			return workflow.RunAppConfigSave(ctx, path, id, cfg)
		}}, nil
	case "app_lego_archive_upload":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		artifact, cleanup, err := server.stageDependencyUpload(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindDependencyUpload, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui", "--app-config", appConfigPath), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, cleanup: cleanup, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunAppLegoArchiveUpload(ctx, appConfigPath, artifact)
		}}, nil
	case "app_verify":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindAppVerify, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "app", "verify", "--config", appConfigPath), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunAppVerify(ctx, appConfigPath, "")
		}}, nil
	case "app_deploy":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindAppDeploy, confirmations: confirmations, checkpointRef: domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: state.DefaultCheckpointPath(appConfigPath)}, retryCommand: jobRetryWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", appConfigPath), confirmations), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, run: func(recorder workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			id, err := instanceID()
			if err != nil {
				return workflow.OperationResult{}, err
			}
			runCtx := ctx
			runCtx.ManualConfirmationRecorder = recorder
			return workflow.RunAppDeploy(runCtx, appConfigPath, id)
		}}, nil
	case "realip_diagnostics":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		profile := formValue(r, "profile")
		return jobOperation{kind: domain.JobKindRealIPDiagnostics, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profile), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunRealIPDiagnostics(ctx, appConfigPath, formValue(r, "profile"))
		}}, nil
	case "realip_refresh":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		profile := formValue(r, "profile")
		return jobOperation{kind: domain.JobKindRealIPRefresh, confirmations: confirmations, checkpointRef: domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: state.DefaultCheckpointPath(appConfigPath)}, retryCommand: jobRetryWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profile), confirmations), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, run: func(recorder workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			id, err := instanceID()
			if err != nil {
				return workflow.OperationResult{}, err
			}
			runCtx := ctx
			runCtx.ManualConfirmationRecorder = recorder
			return workflow.RunRealIPRefresh(runCtx, appConfigPath, formValue(r, "profile"), id)
		}}, nil
	case "realip_validate_reference":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		profile := formValue(r, "profile")
		appName := formValue(r, "realip_reference_app")
		referencePath := formValue(r, "realip_reference_path")
		return jobOperation{kind: domain.JobKindRealIPValidateRef, confirmations: confirmations, retryCommand: workflow.ShellCommand("lanpanel", "app", "realip", "validate-reference", "--profile", profile, "--app", appName, "--path", referencePath), configSnapshotSource: appConfigPath, configSnapshotName: "app-config.yaml", appConfigPath: appConfigPath, run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunRealIPValidateReference(ctx, profile, appName, referencePath)
		}}, nil
	case "preauth_key_create":
		return jobOperation{kind: domain.JobKindPreAuthKeyCreate, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui"), run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			ttl := defaultPreAuthTTL
			if value := formValue(r, "preauth_ttl"); value != "" {
				parsed, err := time.ParseDuration(value)
				if err != nil {
					cause := fmt.Errorf("preauth_ttl must be a Go duration such as 24h: %w", err)
					return workflow.OperationResult{
						Kind:    domain.JobKindPreAuthKeyCreate,
						Status:  domain.JobStatusFailed,
						Summary: "preauth key handoff input failed",
						Fields: []domain.ResultField{
							{Label: "target user", Value: formValue(r, "preauth_user")},
							{Label: "ttl", Value: value},
							{Label: "details", Value: cause.Error()},
						},
						Diagnostics: []domain.DiagnosticItem{{
							ID:               "preauth-input",
							Title:            string(domain.JobKindPreAuthKeyCreate),
							Status:           domain.DiagnosticStatusFail,
							Scope:            domain.DiagnosticScopeHeadscale,
							Severity:         domain.DiagnosticSeverityCritical,
							Summary:          cause.Error(),
							EvidenceSource:   domain.DiagnosticEvidenceConfig,
							ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
							BlocksActivation: true,
							Redaction:        domain.RedactionNone,
							RedactionStatus:  domain.RedactionStatusNoSensitiveData,
						}},
						RetryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui"),
						Progress:     []workflow.ProgressEvent{{At: server.options.Now().UTC(), Kind: domain.JobKindPreAuthKeyCreate, Status: domain.DiagnosticStatusFail, Message: "preauth key handoff input failed"}},
					}, cause
				}
				ttl = parsed
			}
			return workflow.RunPreAuthKeyCreate(ctx, formValue(r, "preauth_user"), ttl)
		}}, nil
	case "browser_auth_create":
		return jobOperation{kind: domain.JobKindBrowserAuthCreate, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui"), run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			return workflow.RunBrowserAuthCreate(ctx, formValue(r, "browser_auth_dir"), formValue(r, "browser_auth_id"), formValue(r, "browser_auth_create_username"), formValue(r, "browser_auth_create_password"))
		}}, nil
	case "browser_auth_rotate":
		appConfigPath, err := server.appConfigPath(r)
		if err != nil {
			return jobOperation{}, err
		}
		return jobOperation{kind: domain.JobKindBrowserAuthRotate, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui"), run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			id, err := instanceID()
			if err != nil {
				return workflow.OperationResult{}, err
			}
			return workflow.RunBrowserAuthRotate(ctx, appConfigPath, id, formValue(r, "browser_auth_rotate_path"), formValue(r, "browser_auth_rotate_username"), formValue(r, "browser_auth_rotate_password"))
		}}, nil
	case "browser_auth_delete":
		return jobOperation{kind: domain.JobKindBrowserAuthDelete, confirmations: confirmations, retryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui"), run: func(_ workflow.ManualConfirmationRecorder) (workflow.OperationResult, error) {
			referencedPaths, err := server.referencedBrowserAuthPaths(r)
			if err != nil {
				return workflow.OperationResult{
					Kind:    domain.JobKindBrowserAuthDelete,
					Status:  domain.JobStatusFailed,
					Summary: "browser auth credential delete failed",
					Fields:  []domain.ResultField{{Label: "htpasswd path", Value: formValue(r, "browser_auth_delete_path")}, {Label: "details", Value: err.Error()}},
					Diagnostics: []domain.DiagnosticItem{{
						ID:               "browser-auth-delete-reference",
						Title:            string(domain.JobKindBrowserAuthDelete),
						Status:           domain.DiagnosticStatusFail,
						Scope:            domain.DiagnosticScopeResource,
						Severity:         domain.DiagnosticSeverityCritical,
						Summary:          err.Error(),
						EvidenceSource:   domain.DiagnosticEvidenceConfig,
						ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
						BlocksActivation: true,
						Redaction:        domain.RedactionNone,
						RedactionStatus:  domain.RedactionStatusNoSensitiveData,
					}},
					RetryCommand: workflow.ShellCommand("sudo", "lanpanel", "ui"),
					Progress:     []workflow.ProgressEvent{{At: server.options.Now().UTC(), Kind: domain.JobKindBrowserAuthDelete, Status: domain.DiagnosticStatusFail, Message: "browser auth credential delete failed"}},
				}, err
			}
			return workflow.RunBrowserAuthDelete(ctx, formValue(r, "browser_auth_delete_path"), referencedPaths)
		}}, nil
	default:
		return jobOperation{}, fmt.Errorf("operation %q is not supported", formValue(r, "operation"))
	}
}

func explicitJobField(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "not_applicable"
	}
	return value
}

func jobRetryCommand(resultRetry string, operationRetry string) string {
	resultRetry = strings.TrimSpace(resultRetry)
	if resultRetry != "" {
		return resultRetry
	}
	return strings.TrimSpace(operationRetry)
}

func jobRetryWithConfirmations(command string, confirmations []string) string {
	command = strings.TrimSpace(command)
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation == "" {
			continue
		}
		command = strings.TrimSpace(command + " " + workflow.ShellCommand("--confirmation", confirmation))
	}
	return command
}

func (server *Server) configSnapshotRef(jobID string, operation jobOperation) (string, error) {
	source := strings.TrimSpace(operation.configSnapshotSource)
	if source == "" {
		return "not_applicable", nil
	}
	name := strings.TrimSpace(operation.configSnapshotName)
	if name == "" {
		return "", fmt.Errorf("config snapshot name is required")
	}
	data, err := server.configSnapshotData(source, name)
	if err != nil {
		return "", err
	}
	ref, err := server.state.WriteConfigSnapshot(jobID, name, data)
	if err != nil {
		return "", err
	}
	return ref, nil
}

func (server *Server) configSnapshotData(source string, name string) ([]byte, error) {
	switch name {
	case "main-config.yaml":
		source, err := server.authorizedMainSnapshotSource(source)
		if err != nil {
			return nil, err
		}
		if err := validateConfigSnapshotFile(source, "main config snapshot source"); err != nil {
			return nil, err
		}
		cfg, err := config.LoadFile(source)
		if err != nil {
			return nil, fmt.Errorf("load main config snapshot source %s: %w", source, err)
		}
		data, err := cfg.ExportYAML()
		if err != nil {
			return nil, fmt.Errorf("export main config snapshot source %s: %w", source, err)
		}
		return data, nil
	case "app-config.yaml":
		source, err := server.authorizedAppSnapshotSource(source)
		if err != nil {
			return nil, err
		}
		if err := validateConfigSnapshotFile(source, "app config snapshot source"); err != nil {
			return nil, err
		}
		cfg, err := appconfig.LoadFile(source)
		if err != nil {
			return nil, fmt.Errorf("load app config snapshot source %s: %w", source, err)
		}
		data, err := cfg.ExportYAML()
		if err != nil {
			return nil, fmt.Errorf("export app config snapshot source %s: %w", source, err)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("config snapshot name %q is not supported", name)
	}
}

func (server *Server) authorizedMainSnapshotSource(source string) (string, error) {
	clean, err := canonicalMainConfigPath(source)
	if err != nil {
		return "", err
	}
	configured, err := canonicalMainConfigPath(server.options.ConfigPath)
	if err != nil {
		return "", err
	}
	if clean != configured {
		return "", fmt.Errorf("main config snapshot source must match configured UI path %s", configured)
	}
	return clean, nil
}

func (server *Server) authorizedAppSnapshotSource(source string) (string, error) {
	clean, err := canonicalAppConfigPath(source)
	if err != nil {
		return "", err
	}
	if err := server.validateAppConfigPath(clean); err != nil {
		return "", err
	}
	return clean, nil
}

func validateConfigSnapshotFile(path string, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s must not be a symlink", label, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s must be a regular file", label, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s %s must not be writable by group or others", label, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s %s owner could not be inspected", label, path)
	}
	expectedUID := uint32(os.Geteuid())
	if stat.Uid != expectedUID && stat.Uid != 0 {
		return fmt.Errorf("%s %s owner uid %d does not match expected uid %d", label, path, stat.Uid, expectedUID)
	}
	return nil
}

func confirmationValues(r *http.Request) ([]string, error) {
	allowed := allowedConfirmationsForOperation(formValue(r, "operation"))
	seen := map[string]struct{}{}
	values := []string{}
	for _, value := range r.Form["confirmation"] {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := allowed[value]; !ok {
			return nil, fmt.Errorf("confirmation is not allowed for this operation")
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values, nil
}

func allowedConfirmationsForOperation(operation string) map[string]struct{} {
	switch strings.TrimSpace(operation) {
	case "app_deploy", "realip_refresh":
		return map[string]struct{}{
			"public-app-risk":          {},
			"direct-origin-risk":       {},
			"origin-protection-manual": {},
		}
	default:
		return map[string]struct{}{}
	}
}

func (server *Server) recordManualConfirmations(jobID string, actor domain.Actor, confirmations []string) ([]domain.ManualConfirmation, error) {
	manualConfirmations := make([]domain.ManualConfirmation, 0, len(confirmations))
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation == "" {
			continue
		}
		event, err := server.state.AppendEvent(jobID, uistate.Event{Status: domain.DiagnosticStatusManual, Message: "manual confirmation submitted: " + confirmation})
		if err != nil {
			return nil, err
		}
		manualConfirmation, err := manualConfirmationFromEvent(confirmation, actor, event)
		if err != nil {
			return nil, err
		}
		manualConfirmations = append(manualConfirmations, manualConfirmation)
	}
	return manualConfirmations, nil
}

func manualConfirmationFromEvent(confirmation string, actor domain.Actor, event uistate.Event) (domain.ManualConfirmation, error) {
	reason, err := manualConfirmationReason(confirmation)
	if err != nil {
		return domain.ManualConfirmation{}, err
	}
	return domain.ManualConfirmation{
		ConfirmationID: event.ID,
		Reason:         reason,
		Actor:          actor,
		ConfirmedAt:    event.At.UTC().Format(time.RFC3339),
	}, nil
}

func manualConfirmationReason(confirmation string) (string, error) {
	return domain.ManualConfirmationReason(confirmation)
}

func (server *Server) actorForRequest(r *http.Request) (domain.Actor, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return domain.Actor{}, fmt.Errorf("session cookie is required for actor context")
	}
	sess, ok := server.sessionFromRequest(r)
	if !ok {
		return domain.Actor{}, fmt.Errorf("valid session is required for actor context")
	}
	return domain.Actor{
		Source:                  domain.ActorSourceUI,
		EffectiveUID:            os.Geteuid(),
		EffectiveUser:           fmt.Sprintf("uid:%d", os.Geteuid()),
		ProcessID:               os.Getpid(),
		SessionIDFingerprint:    fingerprintSecret(cookie.Value),
		RequestSource:           strings.TrimSpace(r.RemoteAddr),
		StartupTokenFingerprint: sess.StartupTokenFingerprint,
	}, nil
}

func (server *Server) referencedBrowserAuthPaths(r *http.Request) ([]string, error) {
	target := filepath.Clean(strings.TrimSpace(formValue(r, "browser_auth_delete_path")))
	if target == "." || target == "" {
		return nil, fmt.Errorf("browser auth delete path is required")
	}
	current, err := server.appConfigPath(r)
	if err != nil {
		return nil, err
	}
	paths, err := server.knownAppConfigReferenceSetPaths(current)
	if err != nil {
		return nil, err
	}
	referenced := []string{}
	for _, path := range paths {
		cfg, err := appconfig.LoadFile(path)
		if err != nil {
			return nil, fmt.Errorf("load app config before deleting browser auth credential %s: %w", path, err)
		}
		if cfg.BrowserAuthEnabled() {
			referencedPath := filepath.Clean(strings.TrimSpace(cfg.BrowserAuthUserFile()))
			if referencedPath != "." && referencedPath != "" {
				referenced = append(referenced, referencedPath)
			}
		}
		stagedReferences, err := stagedAppBrowserAuthReferencePaths(path, cfg)
		if err != nil {
			return nil, err
		}
		referenced = append(referenced, stagedReferences...)
	}
	activeReferences, err := activeAppBrowserAuthReferencePaths(activeNginxSitesAvailableDir)
	if err != nil {
		return nil, err
	}
	referenced = append(referenced, activeReferences...)
	sort.Strings(referenced)
	return referenced, nil
}

func (server *Server) knownAppConfigReferenceSetPaths(current string) ([]string, error) {
	current, err := canonicalAppConfigPath(current)
	if err != nil {
		return nil, err
	}
	paths := map[string]struct{}{current: {}}
	siblingPaths, err := appConfigReferenceSetPaths(current)
	if err != nil {
		return nil, err
	}
	for _, path := range siblingPaths {
		paths[path] = struct{}{}
	}
	registeredPaths, err := server.state.ListAppConfigPaths()
	if err != nil {
		return nil, fmt.Errorf("list known app configs before deleting browser auth credential: %w", err)
	}
	for _, path := range registeredPaths {
		clean, err := canonicalAppConfigPath(path)
		if err != nil {
			return nil, err
		}
		paths[clean] = struct{}{}
	}
	out := make([]string, 0, len(paths))
	for path := range paths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func appConfigReferenceSetPaths(current string) ([]string, error) {
	current, err := canonicalAppConfigPath(current)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(current)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("scan app config directory before deleting browser auth credential %s: %w", dir, err)
	}
	paths := map[string]struct{}{current: {}}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, name)
		if filepath.Clean(path) == current {
			continue
		}
		isApp, err := yamlDeclaresAppConfig(path)
		if err != nil {
			return nil, err
		}
		if isApp {
			clean, err := canonicalAppConfigPath(path)
			if err != nil {
				return nil, err
			}
			paths[clean] = struct{}{}
		}
	}
	out := make([]string, 0, len(paths))
	for path := range paths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func canonicalAppConfigPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("app config path is required")
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("app config path must not contain control characters")
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve app config path: %w", err)
	}
	clean := filepath.Clean(absolute)
	if clean == "." || !filepath.IsAbs(clean) {
		return "", fmt.Errorf("app config path must resolve to a clean absolute path")
	}
	return clean, nil
}

func yamlDeclaresAppConfig(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read app config candidate %s: %w", path, err)
	}
	var header struct {
		APIVersion string `yaml:"api_version"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&header); err != nil {
		return false, fmt.Errorf("decode app config candidate %s: %w", path, err)
	}
	version := strings.TrimSpace(header.APIVersion)
	if version == appconfig.APIVersion {
		return true, nil
	}
	if strings.HasPrefix(version, "lanpanel/app/") {
		return true, nil
	}
	return false, nil
}

func stagedAppBrowserAuthReferencePaths(configPath string, cfg appconfig.Config) ([]string, error) {
	staged, err := apprender.StageRuntime(cfg)
	if err != nil {
		return nil, fmt.Errorf("render staged app runtime before deleting browser auth credential %s: %w", configPath, err)
	}
	referenced := map[string]struct{}{}
	for _, file := range staged {
		if !bytes.Contains(file.Content, []byte("Lanpanel-managed: app.name=")) {
			continue
		}
		hostPath := filepath.Clean(strings.TrimSpace(file.HostPath))
		if hostPath == "." || hostPath == "" || !filepath.IsAbs(hostPath) {
			return nil, fmt.Errorf("inspect staged app Nginx before deleting browser auth credential %s: staged host path must be a clean absolute path", configPath)
		}
		for _, reference := range nginxAuthBasicUserFileReferences(file.Content) {
			clean, err := cleanStagedAuthBasicUserFileReference(hostPath, reference)
			if err != nil {
				return nil, err
			}
			referenced[clean] = struct{}{}
		}
	}
	out := make([]string, 0, len(referenced))
	for path := range referenced {
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func cleanStagedAuthBasicUserFileReference(hostPath string, reference string) (string, error) {
	reference = strings.TrimSpace(reference)
	for _, r := range reference {
		if r <= 0x20 || r == 0x7f {
			return "", fmt.Errorf("inspect staged app Nginx before deleting browser auth credential %s: auth_basic_user_file must not contain whitespace or control characters", hostPath)
		}
	}
	clean := filepath.Clean(reference)
	if clean == "." || clean == "" || !filepath.IsAbs(clean) || clean != reference {
		return "", fmt.Errorf("inspect staged app Nginx before deleting browser auth credential %s: auth_basic_user_file must be a clean absolute path", hostPath)
	}
	return clean, nil
}

func activeAppBrowserAuthReferencePaths(dir string) ([]string, error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "." || dir == "" {
		return nil, fmt.Errorf("active Nginx sites directory is required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan active Nginx sites before deleting browser auth credential %s: %w", dir, err)
	}
	referenced := map[string]struct{}{}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("inspect active Nginx site before deleting browser auth credential %s: symlinks are not allowed", path)
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat active Nginx site before deleting browser auth credential %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("inspect active Nginx site before deleting browser auth credential %s: regular file is required", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read active Nginx site before deleting browser auth credential %s: %w", path, err)
		}
		if !bytes.Contains(data, []byte("Lanpanel-managed: app.name=")) {
			continue
		}
		for _, reference := range nginxAuthBasicUserFileReferences(data) {
			referenced[reference] = struct{}{}
		}
	}
	out := make([]string, 0, len(referenced))
	for path := range referenced {
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func nginxAuthBasicUserFileReferences(data []byte) []string {
	references := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "auth_basic_user_file") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "auth_basic_user_file"))
		if index := strings.Index(value, "#"); index >= 0 {
			value = strings.TrimSpace(value[:index])
		}
		value = strings.TrimSpace(strings.TrimSuffix(value, ";"))
		value = strings.Trim(value, `"'`)
		value = filepath.Clean(strings.TrimSpace(value))
		if value == "." || value == "" {
			continue
		}
		references = append(references, value)
	}
	return references
}

func diagnosticForJobStatus(status domain.JobStatus) domain.DiagnosticStatus {
	switch status {
	case domain.JobStatusSucceeded:
		return domain.DiagnosticStatusPass
	case domain.JobStatusFailed:
		return domain.DiagnosticStatusFail
	case domain.JobStatusInterrupted, domain.JobStatusUnknown:
		return domain.DiagnosticStatusUnknown
	default:
		return domain.DiagnosticStatusManual
	}
}

func managedBrowserAuthRef(credential browserauth.Credential) appconfig.ManagedBrowserAuthRef {
	return appconfig.ManagedBrowserAuthRef{
		CredentialID:        credential.ID,
		HtpasswdPath:        credential.HtpasswdPath,
		Username:            credential.Username,
		PasswordFingerprint: credential.PasswordFingerprint,
	}
}
