package workflow

import (
	stdcontext "context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/appguard"
	"lanpanel/internal/apprender"
	"lanpanel/internal/appverify"
	"lanpanel/internal/browserauth"
	"lanpanel/internal/components/appsvc"
	"lanpanel/internal/components/headscale"
	legocomponent "lanpanel/internal/components/lego"
	tlscomponent "lanpanel/internal/components/tls"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/host"
	"lanpanel/internal/hosthealth"
	"lanpanel/internal/realip"
	"lanpanel/internal/render"
	"lanpanel/internal/sensitive"
	"lanpanel/internal/verify"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type Context struct {
	Version                      string
	Actor                        domain.Actor
	BaseContext                  stdcontext.Context
	HostWorkflow                 HostWorkflow
	PreAuthKeyCreator            PreAuthKeyCreator
	Confirmations                []string
	ManualConfirmationRecorder   ManualConfirmationRecorder
	ExposureObservations         exposure.AppObservations
	AppInstanceIDProvider        func() (string, string, error)
	AppVerifyInstanceSource      string
	BrowserAuthDependencyEnsurer func(stdcontext.Context) error
	Now                          func() time.Time
}

const DependencyUploadMaxBytes int64 = 64 << 20

var dependencyUploadCacheRoot = "/var/cache/lanpanel/dependencies"

type UploadedDependencyArtifact struct {
	Path     string
	Filename string
	Size     int64
}

func UnsafeSetDependencyUploadCacheRootForTest(root string) func() {
	previous := dependencyUploadCacheRoot
	dependencyUploadCacheRoot = root
	return func() {
		dependencyUploadCacheRoot = previous
	}
}

type ManualConfirmationRecorder func(confirmations []string) ([]domain.ManualConfirmation, error)

var (
	lstatRealIPReferenceFn    = os.Lstat
	readRealIPReferenceFileFn = os.ReadFile
)

type HostWorkflow interface {
	EnsureBrowserAuthDependencies(ctx stdcontext.Context) error
	RunMainStatus(ctx stdcontext.Context, configPath string) (OperationResult, error)
	RunMainDeploy(ctx stdcontext.Context, configPath string) (OperationResult, error)
	RunAppDeploy(ctx stdcontext.Context, appConfigPath string, plan domain.ExposurePlan, confirmations []string) (OperationResult, error)
	RunRealIPDiagnostics(ctx stdcontext.Context, appConfigPath string, profileName string) (OperationResult, error)
	RunRealIPRefresh(ctx stdcontext.Context, appConfigPath string, profileName string, plan domain.ExposurePlan, confirmations []string) (OperationResult, error)
}

type AppExposureObserver interface {
	AppExposureObservations(ctx stdcontext.Context, appConfigPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation) (exposure.AppObservations, error)
}

type PreAuthKeyCreator interface {
	CreatePreAuthKey(ctx stdcontext.Context, plan headscale.OnboardingPlan) (string, []host.Result, error)
}

type OperationResult struct {
	Kind          domain.JobKind          `json:"kind"`
	Status        domain.JobStatus        `json:"status"`
	Summary       string                  `json:"summary"`
	Fields        []domain.ResultField    `json:"fields,omitempty"`
	Diagnostics   []domain.DiagnosticItem `json:"diagnostics,omitempty"`
	ExposurePlan  *domain.ExposurePlan    `json:"exposure_plan,omitempty"`
	ModifiedPaths []string                `json:"modified_paths,omitempty"`
	RetryCommand  string                  `json:"retry_command,omitempty"`
	NextSteps     []string                `json:"next_steps,omitempty"`
	Progress      []ProgressEvent         `json:"progress,omitempty"`
	OneTimeSecret *OneTimeSecret          `json:"-"`
}

type ProgressEvent struct {
	At      time.Time               `json:"at"`
	Kind    domain.JobKind          `json:"kind"`
	Status  domain.DiagnosticStatus `json:"status"`
	Message string                  `json:"message"`
}

type OneTimeSecret struct {
	Label       string
	Value       string
	Fingerprint string
	ExpiresAt   time.Time
	consumed    bool
}

func (secret *OneTimeSecret) Consume() (string, bool) {
	if secret == nil || secret.consumed {
		return "", false
	}
	secret.consumed = true
	return secret.Value, true
}

func (ctx Context) progressEvent(kind domain.JobKind, status domain.DiagnosticStatus, message string) ProgressEvent {
	now := time.Now
	if ctx.Now != nil {
		now = ctx.Now
	}
	return ProgressEvent{At: now().UTC(), Kind: kind, Status: status, Message: strings.TrimSpace(message)}
}

func prependProgress(result OperationResult, events ...ProgressEvent) OperationResult {
	filtered := make([]ProgressEvent, 0, len(events)+len(result.Progress))
	for _, event := range events {
		if strings.TrimSpace(event.Message) == "" {
			continue
		}
		filtered = append(filtered, event)
	}
	result.Progress = append(filtered, result.Progress...)
	return result
}

func RunMainInit(ctx Context, path string) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("config path is required")
	}
	if err := ensureNewConfigTarget(path, "config file"); err != nil {
		result := mainInitFailureResult(path, err)
		return result, err
	}
	if err := config.WriteExampleFile(path); err != nil {
		result := mainInitFailureResult(path, err)
		return result, err
	}
	return OperationResult{
		Kind:          domain.JobKindConfigSave,
		Status:        domain.JobStatusSucceeded,
		Summary:       "wrote example config",
		Fields:        []domain.ResultField{{Label: "config path", Value: path}, {Label: "lanpanel version", Value: ctx.Version}},
		ModifiedPaths: []string{path},
	}, nil
}

func EnsureNewConfigTarget(path string, label string) error {
	return ensureNewConfigTarget(path, label)
}

func ensureNewConfigTarget(path string, label string) error {
	path = strings.TrimSpace(path)
	label = strings.TrimSpace(label)
	if path == "" {
		return fmt.Errorf("%s path is required", label)
	}
	if label == "" {
		label = "config file"
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s must not be a symlink", label, path)
	}
	return fmt.Errorf("%s already exists at %s", label, path)
}

func mainInitFailureResult(path string, cause error) OperationResult {
	summary := "failed to write example config"
	if strings.Contains(cause.Error(), "already exists") {
		summary = "config file already exists"
	} else if strings.Contains(cause.Error(), "must not be a symlink") {
		summary = "config file target is unsafe"
	} else if strings.HasPrefix(cause.Error(), "stat ") {
		summary = "failed to inspect config file"
	}
	return OperationResult{
		Kind:    domain.JobKindConfigSave,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "config path", Value: path},
			{Label: "details", Value: cause.Error()},
		},
		Diagnostics:  []domain.DiagnosticItem{diagnosticItem("main-config-init", domain.DiagnosticStatusFail, summary, domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: ShellCommand("lanpanel", "init", "--config", path),
		Progress:     []ProgressEvent{{At: time.Now().UTC(), Kind: domain.JobKindConfigSave, Status: domain.DiagnosticStatusFail, Message: summary}},
	}
}

func RunMainConfigSave(ctx Context, path string, cfg config.Config) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("config path is required")
	}
	if err := cfg.WriteFile(path); err != nil {
		return OperationResult{}, err
	}
	return OperationResult{
		Kind:          domain.JobKindConfigSave,
		Status:        domain.JobStatusSucceeded,
		Summary:       "main config saved",
		Fields:        mainConfigFields(path, cfg, ctx.Version),
		ModifiedPaths: []string{path},
	}, nil
}

func RunMainLegoArchiveUpload(ctx Context, configPath string, artifact UploadedDependencyArtifact) (OperationResult, error) {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "lego archive upload failed", artifact, configPath, err), err
	}
	arch := strings.TrimSpace(cfg.Advanced.Platform.Arch)
	expectedName := legocomponent.OfficialArchiveAssetName(legocomponent.Version, arch)
	expectedSHA256, err := legocomponent.ArchiveSHA256(arch)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "lego archive upload failed", artifact, configPath, err), err
	}
	finalPath, err := storeUploadedDependency("lego", artifact, expectedName, expectedSHA256)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "lego archive upload failed", artifact, configPath, err), err
	}
	cfg.Advanced.LegoSource.Mode = config.PackageSourceModeOffline
	cfg.Advanced.LegoSource.FilePath = finalPath
	if err := cfg.WriteFile(configPath); err != nil {
		return dependencyUploadFailureResult(ctx, "lego archive upload failed", artifact, configPath, err), err
	}
	return dependencyUploadSuccessResult(ctx, "lego archive uploaded", artifact, configPath, finalPath, expectedSHA256), nil
}

func RunMainHeadscalePackageUpload(ctx Context, configPath string, artifact UploadedDependencyArtifact) (OperationResult, error) {
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "headscale package upload failed", artifact, configPath, err), err
	}
	arch := strings.TrimSpace(cfg.Advanced.Platform.Arch)
	expectedName := headscale.OfficialPackageAssetName(headscale.Version, arch)
	expectedSHA256, err := headscale.PackageSHA256(headscale.Version, arch)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "headscale package upload failed", artifact, configPath, err), err
	}
	finalPath, err := storeUploadedDependency("headscale", artifact, expectedName, expectedSHA256)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "headscale package upload failed", artifact, configPath, err), err
	}
	cfg.Advanced.HeadscaleSource.Mode = config.PackageSourceModeOffline
	cfg.Advanced.HeadscaleSource.Version = headscale.Version
	cfg.Advanced.HeadscaleSource.URL = ""
	cfg.Advanced.HeadscaleSource.SHA256 = expectedSHA256
	cfg.Advanced.HeadscaleSource.FilePath = finalPath
	if err := cfg.WriteFile(configPath); err != nil {
		return dependencyUploadFailureResult(ctx, "headscale package upload failed", artifact, configPath, err), err
	}
	return dependencyUploadSuccessResult(ctx, "headscale package uploaded", artifact, configPath, finalPath, expectedSHA256), nil
}

func RunAppLegoArchiveUpload(ctx Context, appConfigPath string, artifact UploadedDependencyArtifact) (OperationResult, error) {
	cfg, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "app lego archive upload failed", artifact, appConfigPath, err), err
	}
	arch := strings.TrimSpace(cfg.Dependencies.Platform.Arch)
	expectedName := legocomponent.OfficialArchiveAssetName(legocomponent.Version, arch)
	expectedSHA256, err := legocomponent.ArchiveSHA256(arch)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "app lego archive upload failed", artifact, appConfigPath, err), err
	}
	finalPath, err := storeUploadedDependency("lego", artifact, expectedName, expectedSHA256)
	if err != nil {
		return dependencyUploadFailureResult(ctx, "app lego archive upload failed", artifact, appConfigPath, err), err
	}
	cfg.Dependencies.LegoSource.Mode = config.PackageSourceModeOffline
	cfg.Dependencies.LegoSource.FilePath = finalPath
	if err := cfg.WriteFile(appConfigPath); err != nil {
		return dependencyUploadFailureResult(ctx, "app lego archive upload failed", artifact, appConfigPath, err), err
	}
	return dependencyUploadSuccessResult(ctx, "app lego archive uploaded", artifact, appConfigPath, finalPath, expectedSHA256), nil
}

func storeUploadedDependency(kind string, artifact UploadedDependencyArtifact, expectedName string, expectedSHA256 string) (string, error) {
	kind = strings.TrimSpace(kind)
	expectedName = strings.TrimSpace(expectedName)
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	switch kind {
	case "headscale", "lego":
	default:
		return "", fmt.Errorf("dependency kind must be one of: headscale, lego")
	}
	if expectedName == "" {
		return "", fmt.Errorf("expected dependency artifact name is required")
	}
	if expectedSHA256 == "" {
		return "", fmt.Errorf("expected dependency SHA-256 is required")
	}
	if strings.TrimSpace(artifact.Path) == "" {
		return "", fmt.Errorf("uploaded dependency artifact path is required")
	}
	if filepath.Base(strings.TrimSpace(artifact.Filename)) != expectedName {
		return "", fmt.Errorf("uploaded dependency artifact must be named %s", expectedName)
	}
	info, err := os.Lstat(artifact.Path)
	if err != nil {
		return "", fmt.Errorf("inspect uploaded dependency artifact: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("uploaded dependency artifact must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("uploaded dependency artifact must be a regular file")
	}
	if info.Size() <= 0 {
		return "", fmt.Errorf("uploaded dependency artifact must not be empty")
	}
	if info.Size() > DependencyUploadMaxBytes {
		return "", fmt.Errorf("uploaded dependency artifact exceeds %d bytes", DependencyUploadMaxBytes)
	}
	dir, err := dependencyUploadCacheDir(kind)
	if err != nil {
		return "", err
	}
	finalPath := filepath.Join(dir, expectedName)
	if existing, err := os.Lstat(finalPath); err == nil && existing.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("dependency cache target must not be a symlink: %s", finalPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect dependency cache target: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+expectedName+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("create dependency upload temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmpClosed := false
	closeTmp := func(cause error) error {
		if tmpClosed {
			return cause
		}
		tmpClosed = true
		if err := tmp.Close(); err != nil {
			return appendDependencyCleanupError(cause, fmt.Errorf("close dependency upload temp file: %w", err))
		}
		return cause
	}
	cleanupTmp := func(cause error) error {
		cause = closeTmp(cause)
		if err := os.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return appendDependencyCleanupError(cause, fmt.Errorf("remove dependency upload temp file: %w", err))
		}
		return cause
	}
	source, err := os.Open(artifact.Path)
	if err != nil {
		return "", cleanupTmp(fmt.Errorf("open uploaded dependency artifact: %w", err))
	}
	sourceClosed := false
	closeSource := func(cause error) error {
		if sourceClosed {
			return cause
		}
		sourceClosed = true
		if err := source.Close(); err != nil {
			return appendDependencyCleanupError(cause, fmt.Errorf("close uploaded dependency artifact: %w", err))
		}
		return cause
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hasher), source)
	if err != nil {
		return "", cleanupTmp(closeSource(fmt.Errorf("write dependency upload temp file: %w", err)))
	}
	if err := closeSource(nil); err != nil {
		return "", cleanupTmp(err)
	}
	if written != info.Size() {
		return "", cleanupTmp(fmt.Errorf("uploaded dependency artifact changed while being stored"))
	}
	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA256 != expectedSHA256 {
		return "", cleanupTmp(fmt.Errorf("uploaded dependency SHA-256 %s does not match expected %s", actualSHA256, expectedSHA256))
	}
	if err := tmp.Chmod(0o644); err != nil {
		return "", cleanupTmp(fmt.Errorf("chmod dependency upload temp file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return "", cleanupTmp(fmt.Errorf("sync dependency upload temp file: %w", err))
	}
	if err := closeTmp(nil); err != nil {
		return "", cleanupTmp(err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", cleanupTmp(fmt.Errorf("install dependency upload: %w", err))
	}
	if err := syncDirectory(dir); err != nil {
		return "", err
	}
	return finalPath, nil
}

func appendDependencyCleanupError(cause error, cleanupErr error) error {
	if cleanupErr == nil {
		return cause
	}
	if cause == nil {
		return cleanupErr
	}
	return fmt.Errorf("%w; %v", cause, cleanupErr)
}

func dependencyUploadCacheDir(kind string) (string, error) {
	root := filepath.Clean(strings.TrimSpace(dependencyUploadCacheRoot))
	if root == "." || !filepath.IsAbs(root) {
		return "", fmt.Errorf("dependency upload cache root must be an absolute path")
	}
	if err := ensureDependencyUploadDir(root, "dependency upload cache root"); err != nil {
		return "", err
	}
	dir := filepath.Join(root, kind)
	if err := ensureDependencyUploadDir(dir, "dependency upload cache directory"); err != nil {
		return "", err
	}
	return dir, nil
}

func ensureDependencyUploadDir(dir string, label string) error {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "." || !filepath.IsAbs(dir) {
		return fmt.Errorf("%s must be an absolute path", label)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", label, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink: %s", label, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory: %s", label, dir)
	}
	return nil
}

func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		if closeErr := handle.Close(); closeErr != nil {
			return fmt.Errorf("sync directory: %w; close directory after sync failure: %v", err, closeErr)
		}
		return fmt.Errorf("sync directory: %w", err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close directory after sync: %w", err)
	}
	return nil
}

func dependencyUploadSuccessResult(ctx Context, summary string, artifact UploadedDependencyArtifact, configPath string, finalPath string, sha256sum string) OperationResult {
	return OperationResult{
		Kind:    domain.JobKindDependencyUpload,
		Status:  domain.JobStatusSucceeded,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "uploaded file", Value: filepath.Base(artifact.Filename)},
			{Label: "stored path", Value: finalPath},
			{Label: "config path", Value: configPath},
			{Label: "sha256", Value: sha256sum},
			{Label: "lanpanel version", Value: ctx.Version},
		},
		ModifiedPaths: []string{finalPath, configPath},
		Diagnostics:   []domain.DiagnosticItem{operationDiagnostic(domain.JobKindDependencyUpload, domain.DiagnosticStatusPass, "dependency-upload", summary, domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel)},
		Progress:      []ProgressEvent{ctx.progressEvent(domain.JobKindDependencyUpload, domain.DiagnosticStatusPass, summary)},
	}
}

func dependencyUploadFailureResult(ctx Context, summary string, artifact UploadedDependencyArtifact, configPath string, cause error) OperationResult {
	return OperationResult{
		Kind:    domain.JobKindDependencyUpload,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "uploaded file", Value: filepath.Base(artifact.Filename)},
			{Label: "config path", Value: configPath},
			{Label: "details", Value: cause.Error()},
			{Label: "lanpanel version", Value: ctx.Version},
		},
		Diagnostics: []domain.DiagnosticItem{operationDiagnostic(domain.JobKindDependencyUpload, domain.DiagnosticStatusFail, "dependency-upload", cause.Error(), domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLocalAdmin)},
		Progress:    []ProgressEvent{ctx.progressEvent(domain.JobKindDependencyUpload, domain.DiagnosticStatusFail, summary)},
	}
}

func RunMainVerify(ctx Context, path string) (OperationResult, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return mainVerifyLoadFailureResult(path, err), nil
	}
	staged, err := render.StageRuntime(cfg)
	if err != nil {
		return mainVerifyStageFailureResult(ctx, path, cfg, err), nil
	}
	report := verify.StaticReport(cfg, staged)
	status := domain.JobStatusSucceeded
	if report.FailedCount() > 0 {
		status = domain.JobStatusFailed
	}
	fields := append(mainConfigFields(path, cfg, ctx.Version),
		domain.ResultField{Label: "checks", Value: verify.SummarizeChecks(report.Checks)},
		domain.ResultField{Label: "minimum client version", Value: "Tailscale >= v" + verify.MinimumTailscaleClientVersion},
	)
	for _, check := range report.Checks {
		fields = append(fields, domain.ResultField{Label: "check " + check.ID, Value: string(check.Status) + ": " + check.Summary})
	}
	return OperationResult{
		Kind:        domain.JobKindVerify,
		Status:      status,
		Summary:     report.Summary(),
		Fields:      fields,
		Diagnostics: mainVerifyDiagnostics(report),
		RetryCommand: ShellCommand(
			"lanpanel",
			"verify",
			"--config",
			path,
		),
	}, nil
}

func mainVerifyLoadFailureResult(path string, cause error) OperationResult {
	summary := "config file exists but failed validation"
	fields := []domain.ResultField{{Label: "config path", Value: path}, {Label: "details", Value: cause.Error()}}
	if errors.Is(cause, os.ErrNotExist) {
		summary = "no config file found"
		fields = []domain.ResultField{
			{Label: "config path", Value: path},
			{Label: "happy path", Value: "init -> deploy -> verify"},
		}
	}
	return OperationResult{
		Kind:         domain.JobKindVerify,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       fields,
		Diagnostics:  []domain.DiagnosticItem{diagnosticItem("main-config", domain.DiagnosticStatusFail, summary, domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: ShellCommand("lanpanel", "verify", "--config", path),
	}
}

func mainVerifyStageFailureResult(ctx Context, path string, cfg config.Config, cause error) OperationResult {
	summary := "runtime asset rendering failed"
	return OperationResult{
		Kind:    domain.JobKindVerify,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: append(mainConfigFields(path, cfg, ctx.Version),
			domain.ResultField{Label: "details", Value: cause.Error()},
		),
		Diagnostics:  []domain.DiagnosticItem{diagnosticItem("main-runtime-stage", domain.DiagnosticStatusFail, cause.Error(), domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel)},
		RetryCommand: ShellCommand("lanpanel", "verify", "--config", path),
	}
}

func RunMainStatus(ctx Context, path string) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("config path is required")
	}
	if ctx.HostWorkflow == nil {
		return OperationResult{}, fmt.Errorf("host workflow is required for main status")
	}
	result, err := ctx.HostWorkflow.RunMainStatus(ctx.stdContext(), path)
	return finishHostOperationResult(result, err, domain.JobKindStatus, ShellCommand("lanpanel", "status", "--config", path))
}

func RunRuntimeStatus(ctx Context, mainConfigPath string, appConfigPath string) (OperationResult, error) {
	cfg, err := config.LoadFile(mainConfigPath)
	if err != nil {
		return OperationResult{}, err
	}
	staged, err := render.StageRuntime(cfg)
	if err != nil {
		return OperationResult{}, err
	}
	report := verify.StaticReport(cfg, staged)
	fields := mainConfigFields(mainConfigPath, cfg, ctx.Version)
	fields = append(fields, []domain.ResultField{
		{Label: "headscale service", Value: "headscale.service"},
		{Label: "nginx service", Value: "nginx.service"},
		{Label: "renew timer", Value: tlscomponent.RenewTimer},
		{Label: "reload hook", Value: tlscomponent.RunHookPath},
		{Label: "main fullchain", Value: tlscomponent.StableFullchainPath(serverNameFromURL(cfg.Default.ServerURL))},
		{Label: "main staged paths", Value: strings.Join(mainStagedPaths(staged), ", ")},
	}...)
	diagnostics := mainVerifyDiagnostics(report)
	var appCfgForHealth *appconfig.Config
	if strings.TrimSpace(appConfigPath) != "" {
		appCfg, appErr := appconfig.LoadFile(appConfigPath)
		if appErr != nil {
			diagnostics = append(diagnostics, diagnosticItem("app-config", domain.DiagnosticStatusFail, appErr.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin))
		} else {
			appCfgForHealth = &appCfg
			appStaged, appErr := apprender.StageRuntime(appCfg)
			if appErr != nil {
				diagnostics = append(diagnostics, diagnosticItem("app-runtime-stage", domain.DiagnosticStatusFail, appErr.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel))
			} else {
				appReport := appverify.StaticReport(appCfg, appStaged)
				diagnostics = append(diagnostics, appVerifyDiagnostics(appReport)...)
				fields = append(fields, appRuntimeFields(appConfigPath, appCfg)...)
			}
		}
	}
	if appCfgForHealth != nil {
		realIPFields, realIPDiagnostics := runtimeRealIPDiagnostics(ctx, appConfigPath, *appCfgForHealth)
		fields = append(fields, realIPFields...)
		diagnostics = append(diagnostics, realIPDiagnostics...)
	}
	runtimeFields, runtimeDiagnostics := runtimeStatusEvidence(ctx, cfg, appCfgForHealth)
	fields = append(fields, runtimeFields...)
	diagnostics = append(diagnostics, runtimeDiagnostics...)
	diagnostics = append(diagnostics, hostHealthDiagnostics(hosthealth.Summarize(hosthealth.ReadLocalInputsWithOptions(runtimeHostHealthOptions(cfg, appCfgForHealth))))...)
	status := domain.JobStatusSucceeded
	if hasFailedDiagnostic(diagnostics) {
		status = domain.JobStatusFailed
	}
	return OperationResult{
		Kind:        domain.JobKindStatus,
		Status:      status,
		Summary:     "runtime status evidence collected",
		Fields:      fields,
		Diagnostics: diagnostics,
	}, nil
}

func runtimeRealIPDiagnostics(ctx Context, appConfigPath string, cfg appconfig.Config) ([]domain.ResultField, []domain.DiagnosticItem) {
	profileName := cfg.EffectiveRealIPProfileName()
	if strings.TrimSpace(profileName) == "" {
		return nil, nil
	}
	if ctx.HostWorkflow == nil {
		return nil, []domain.DiagnosticItem{
			diagnosticItem("realip-diagnostics", domain.DiagnosticStatusUnknown, "host workflow is required for realip diagnostics", domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin),
		}
	}
	result, err := RunRealIPDiagnostics(ctx, appConfigPath, profileName)
	fields := append([]domain.ResultField(nil), result.Fields...)
	diagnostics := append([]domain.DiagnosticItem(nil), result.Diagnostics...)
	if len(diagnostics) == 0 {
		summary := strings.TrimSpace(result.Summary)
		if err != nil {
			summary = err.Error()
		}
		if summary == "" {
			summary = "realip diagnostics returned no summary"
		}
		diagnostics = append(diagnostics, diagnosticItem("realip-diagnostics", diagnosticStatusForJobStatus(result.Status), summary, domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin))
	}
	if err != nil && !hasFailedDiagnostic(diagnostics) {
		diagnostics = append(diagnostics, diagnosticItem("realip-diagnostics-error", domain.DiagnosticStatusFail, err.Error(), domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin))
	}
	return fields, diagnostics
}

func diagnosticStatusForJobStatus(status domain.JobStatus) domain.DiagnosticStatus {
	switch status {
	case domain.JobStatusSucceeded:
		return domain.DiagnosticStatusPass
	case domain.JobStatusFailed, domain.JobStatusInterrupted:
		return domain.DiagnosticStatusFail
	case domain.JobStatusUnknown:
		return domain.DiagnosticStatusUnknown
	default:
		return domain.DiagnosticStatusWarn
	}
}

func runtimeHostHealthOptions(cfg config.Config, appCfg *appconfig.Config) hosthealth.LocalReadOptions {
	options := hosthealth.LocalReadOptions{}
	serverName := serverNameFromURL(cfg.Default.ServerURL)
	if strings.TrimSpace(serverName) != "" {
		options.DNSTargets = append(options.DNSTargets, serverName)
		options.CertificateTargets = append(options.CertificateTargets, hosthealth.CertificateTarget{
			Domain: serverName,
			Path:   tlscomponent.StableFullchainPath(serverName),
		})
	}
	if appCfg != nil {
		options.DNSTargets = append(options.DNSTargets, appCfg.App.Domains...)
		if names, err := appsvc.NewNames(*appCfg); err == nil {
			for _, domainName := range appCfg.App.Domains {
				options.CertificateTargets = append(options.CertificateTargets, hosthealth.CertificateTarget{
					Domain: domainName,
					Path:   names.FullchainPath,
				})
			}
		}
	}
	return options
}

func RunMainDeploy(ctx Context, path string) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("config path is required")
	}
	if ctx.HostWorkflow == nil {
		return OperationResult{}, fmt.Errorf("host workflow is required for main deploy")
	}
	events := []ProgressEvent{ctx.progressEvent(domain.JobKindDeploy, domain.DiagnosticStatusManual, "main deploy host workflow started")}
	result, err := ctx.HostWorkflow.RunMainDeploy(ctx.stdContext(), path)
	result, err = finishHostOperationResult(result, err, domain.JobKindDeploy, ShellCommand("sudo", "lanpanel", "deploy", "--config", path))
	events = append(events, ctx.progressEvent(domain.JobKindDeploy, diagnosticForResult(result, err), "main deploy host workflow finished"))
	return prependProgress(result, events...), err
}

func RunAppInit(ctx Context, path string) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("app config path is required")
	}
	if err := ensureNewConfigTarget(path, "app config file"); err != nil {
		result := appInitFailureResult(ctx, path, err)
		return result, err
	}
	if err := appconfig.WriteExampleFile(path); err != nil {
		result := appInitFailureResult(ctx, path, err)
		return result, err
	}
	return OperationResult{
		Kind:          domain.JobKindAppInit,
		Status:        domain.JobStatusSucceeded,
		Summary:       "App example config written",
		Fields:        []domain.ResultField{{Label: "config path", Value: path}},
		ModifiedPaths: []string{path},
	}, nil
}

func appInitFailureResult(ctx Context, path string, cause error) OperationResult {
	summary := "Failed to write app example config"
	if strings.Contains(cause.Error(), "already exists") {
		summary = "App config file already exists"
	} else if strings.Contains(cause.Error(), "must not be a symlink") {
		summary = "App config file target is unsafe"
	} else if strings.HasPrefix(cause.Error(), "stat ") {
		summary = "Failed to inspect app config file"
	}
	return OperationResult{
		Kind:    domain.JobKindAppInit,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "config path", Value: path},
			{Label: "details", Value: cause.Error()},
		},
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(domain.JobKindAppInit, domain.DiagnosticStatusFail, "app-config-init", summary, domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: ShellCommand("lanpanel", "app", "init", "--config", path),
		Progress:     []ProgressEvent{ctx.progressEvent(domain.JobKindAppInit, domain.DiagnosticStatusFail, summary)},
	}
}

func RunAppConfigSave(ctx Context, path string, instanceID string, cfg appconfig.Config) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("app config path is required")
	}
	if cfg.PrivateClientAccessEnabled() {
		err := fmt.Errorf("access.access_mode private_client is reserved for P1 and cannot be managed from P0")
		return appConfigSaveFailureResult(ctx, path, cfg, err), err
	}
	if err := cfg.ValidateForExposurePlan(); err != nil {
		return appConfigSaveFailureResult(ctx, path, cfg, err), err
	}
	staged, err := apprender.StageRuntime(cfg)
	if err != nil {
		return OperationResult{}, err
	}
	plan, err := exposure.AppPlan(instanceID, ctx.Version, cfg, ctx.exposurePlanOptions(path, domain.ExposurePlanOperationUpdateResource, stagedPaths(staged)))
	if err != nil {
		return OperationResult{}, err
	}
	if err := cfg.WriteFile(path); err != nil {
		return OperationResult{}, err
	}
	return OperationResult{
		Kind:          domain.JobKindAppConfigSave,
		Status:        domain.JobStatusSucceeded,
		Summary:       "app config saved",
		Fields:        appConfigFields(path, cfg, ctx.Version),
		ExposurePlan:  &plan,
		ModifiedPaths: []string{path},
	}, nil
}

func appConfigSaveFailureResult(ctx Context, path string, cfg appconfig.Config, cause error) OperationResult {
	summary := "app config save rejected"
	return OperationResult{
		Kind:    domain.JobKindAppConfigSave,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: append(appConfigFields(path, cfg, ctx.Version),
			domain.ResultField{Label: "details", Value: cause.Error()},
		),
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(domain.JobKindAppConfigSave, domain.DiagnosticStatusFail, "app-config-save", cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: ShellCommand("lanpanel", "ui", "--app-config", path),
		Progress:     []ProgressEvent{ctx.progressEvent(domain.JobKindAppConfigSave, domain.DiagnosticStatusFail, summary)},
	}
}

func RunAppVerify(ctx Context, path string, instanceID string) (OperationResult, error) {
	cfg, err := appconfig.LoadFile(path)
	if err != nil {
		return appVerifyLoadFailureResult(path, err), nil
	}
	if err := appguard.ValidateAgainstMainConfig(cfg); err != nil {
		return appVerifyMainConfigConflictResult(path, err), nil
	}
	instanceSource := strings.TrimSpace(ctx.AppVerifyInstanceSource)
	if strings.TrimSpace(instanceID) == "" {
		if ctx.AppInstanceIDProvider == nil {
			return appVerifyInstanceFailureResult(path, fmt.Errorf("app verify instance id provider is required")), nil
		}
		var err error
		instanceID, instanceSource, err = ctx.AppInstanceIDProvider()
		if err != nil {
			return appVerifyInstanceFailureResult(path, err), nil
		}
	}
	observations, err := ctx.appExposureObservations(path, cfg, domain.ExposurePlanOperationUpdateResource)
	if err != nil {
		return appVerifyExposurePlanFailureResult(ctx, path, cfg, nil, fmt.Errorf("read app exposure observations: %w", err)), nil
	}
	preflightPlan, err := exposure.AppPlanWithObservations(instanceID, ctx.Version, cfg, ctx.exposurePlanOptions(path, domain.ExposurePlanOperationUpdateResource, nil), observations)
	if err != nil {
		return appVerifyExposurePlanFailureResult(ctx, path, cfg, nil, err), nil
	}
	if preflightPlan.Decision.Status == domain.ExposurePlanDecisionFail || preflightPlan.Decision.Status == domain.ExposurePlanDecisionUnknown {
		return appVerifyBlockedExposurePlanResult(ctx, path, cfg, preflightPlan), nil
	}
	staged, err := apprender.StageRuntime(cfg)
	if err != nil {
		return appVerifyStageFailureResult(ctx, path, cfg, err), nil
	}
	report := appverify.StaticReport(cfg, staged)
	status := domain.JobStatusSucceeded
	if report.FailedCount() > 0 {
		status = domain.JobStatusFailed
	}
	plan, err := exposure.AppPlanWithObservations(instanceID, ctx.Version, cfg, ctx.exposurePlanOptions(path, domain.ExposurePlanOperationUpdateResource, stagedPaths(staged)), observations)
	if err != nil {
		return appVerifyExposurePlanFailureResult(ctx, path, cfg, staged, err), nil
	}
	fields := append(appConfigFields(path, cfg, ctx.Version),
		domain.ResultField{Label: "verification scope", Value: "static render checks plus read-only exposure observations; does not mutate host state"},
		domain.ResultField{Label: "checks", Value: appverify.SummarizeChecks(report.Checks)},
		domain.ResultField{Label: "exposure decision", Value: string(plan.Decision.Status)},
	)
	if len(plan.Decision.RequiredConfirmations) > 0 {
		fields = append(fields, domain.ResultField{Label: "required confirmations", Value: strings.Join(plan.Decision.RequiredConfirmations, ", ")})
	}
	for _, check := range report.Checks {
		fields = append(fields, domain.ResultField{Label: "check " + check.ID, Value: string(check.Status) + ": " + check.Summary})
	}
	if instanceSource != "" {
		fields = append(fields, domain.ResultField{Label: "instance id source", Value: instanceSource})
	}
	return OperationResult{
		Kind:          domain.JobKindAppVerify,
		Status:        status,
		Summary:       report.Summary(),
		Fields:        fields,
		Diagnostics:   appVerifyDiagnostics(report),
		ExposurePlan:  &plan,
		ModifiedPaths: stagedPaths(staged),
		RetryCommand:  ShellCommand("lanpanel", "app", "verify", "--config", path),
	}, nil
}

func appVerifyMainConfigConflictResult(path string, cause error) OperationResult {
	summary := "App config conflicts with main Headscale server_url or metrics_port"
	return OperationResult{
		Kind:    domain.JobKindAppVerify,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "config path", Value: path},
			{Label: "details", Value: cause.Error()},
		},
		Diagnostics:  []domain.DiagnosticItem{diagnosticItem("app-main-config", domain.DiagnosticStatusFail, cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: ShellCommand("lanpanel", "app", "verify", "--config", path),
	}
}

func appVerifyInstanceFailureResult(path string, cause error) OperationResult {
	summary := "App exposure instance initialization failed"
	return OperationResult{
		Kind:    domain.JobKindAppVerify,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "config path", Value: path},
			{Label: "details", Value: cause.Error()},
		},
		Diagnostics:  []domain.DiagnosticItem{diagnosticItem("app-resource-instance", domain.DiagnosticStatusFail, cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLanPanel)},
		RetryCommand: ShellCommand("lanpanel", "app", "verify", "--config", path),
	}
}

func appVerifyLoadFailureResult(path string, cause error) OperationResult {
	summary := "App config file exists but validation failed"
	fields := []domain.ResultField{{Label: "config path", Value: path}, {Label: "details", Value: cause.Error()}}
	if errors.Is(cause, os.ErrNotExist) {
		summary = "App config file not found"
		fields = []domain.ResultField{{Label: "config path", Value: path}}
	}
	return OperationResult{
		Kind:         domain.JobKindAppVerify,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       fields,
		Diagnostics:  []domain.DiagnosticItem{diagnosticItem("app-config", domain.DiagnosticStatusFail, summary, domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: ShellCommand("lanpanel", "app", "verify", "--config", path),
	}
}

func appVerifyStageFailureResult(ctx Context, path string, cfg appconfig.Config, cause error) OperationResult {
	summary := "App runtime template rendering failed"
	return OperationResult{
		Kind:    domain.JobKindAppVerify,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: append(appConfigFields(path, cfg, ctx.Version),
			domain.ResultField{Label: "details", Value: cause.Error()},
		),
		Diagnostics:  []domain.DiagnosticItem{diagnosticItem("app-runtime-stage", domain.DiagnosticStatusFail, cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel)},
		RetryCommand: ShellCommand("lanpanel", "app", "verify", "--config", path),
	}
}

func appVerifyExposurePlanFailureResult(ctx Context, path string, cfg appconfig.Config, staged []apprender.StagedFile, cause error) OperationResult {
	summary := "App exposure plan validation failed"
	return OperationResult{
		Kind:    domain.JobKindAppVerify,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: append(appConfigFields(path, cfg, ctx.Version),
			domain.ResultField{Label: "details", Value: cause.Error()},
		),
		Diagnostics:   []domain.DiagnosticItem{diagnosticItem("app-exposure-plan", domain.DiagnosticStatusFail, cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		ModifiedPaths: stagedPaths(staged),
		RetryCommand:  ShellCommand("lanpanel", "app", "verify", "--config", path),
	}
}

func appVerifyBlockedExposurePlanResult(ctx Context, path string, cfg appconfig.Config, plan domain.ExposurePlan) OperationResult {
	summary := "App exposure plan blocks static verify"
	fields := append(appConfigFields(path, cfg, ctx.Version),
		domain.ResultField{Label: "verification scope", Value: "static-only: exposure plan evaluated before rendering runtime files"},
	)
	fields = append(fields, exposurePlanResultFields(plan, nil)...)
	return OperationResult{
		Kind:         domain.JobKindAppVerify,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       fields,
		Diagnostics:  exposurePlanDiagnostics(domain.JobKindAppVerify, plan),
		ExposurePlan: &plan,
		RetryCommand: ShellCommand("lanpanel", "app", "verify", "--config", path),
	}
}

func appHostMutationConfigFailureResult(ctx Context, kind domain.JobKind, path string, cause error, retryCommand string, summary string, progressMessage string) OperationResult {
	return OperationResult{
		Kind:    kind,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "app config path", Value: path},
			{Label: "details", Value: cause.Error()},
			{Label: "lanpanel version", Value: ctx.Version},
		},
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(kind, domain.DiagnosticStatusFail, "app-config", cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: retryCommand,
		Progress:     []ProgressEvent{ctx.progressEvent(kind, domain.DiagnosticStatusFail, progressMessage)},
	}
}

func appHostMutationExposureFailureResult(ctx Context, kind domain.JobKind, path string, cfg appconfig.Config, cause error, retryCommand string, summary string, progressMessage string) OperationResult {
	return OperationResult{
		Kind:    kind,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: append(appConfigFields(path, cfg, ctx.Version),
			domain.ResultField{Label: "details", Value: cause.Error()},
		),
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(kind, domain.DiagnosticStatusFail, "app-exposure-plan", cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: retryCommand,
		Progress:     []ProgressEvent{ctx.progressEvent(kind, domain.DiagnosticStatusFail, progressMessage)},
	}
}

func RunAppDeploy(ctx Context, path string, instanceID string) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("app config path is required")
	}
	if ctx.HostWorkflow == nil {
		return OperationResult{}, fmt.Errorf("host workflow is required for app deploy")
	}
	cfg, err := appconfig.LoadFile(path)
	if err != nil {
		return appHostMutationConfigFailureResult(ctx, domain.JobKindAppDeploy, path, err, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path), "app deploy app config validation failed", "app deploy config validation failed"), err
	}
	if err := appguard.ValidateAgainstMainConfig(cfg); err != nil {
		return appHostMutationConfigFailureResult(ctx, domain.JobKindAppDeploy, path, err, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path), "app deploy app config validation failed", "app deploy config validation failed"), err
	}
	instanceID, err = ctx.requireAppInstanceID(instanceID)
	if err != nil {
		return appHostMutationExposureFailureResult(ctx, domain.JobKindAppDeploy, path, cfg, err, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path), "app deploy exposure instance initialization failed", "app deploy exposure instance failed"), err
	}
	plan, err := ctx.appHostMutationExposurePlan(path, instanceID, cfg, domain.ExposurePlanOperationDeploy, nil)
	if err != nil {
		return appHostMutationExposureFailureResult(ctx, domain.JobKindAppDeploy, path, cfg, err, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path), "app deploy exposure plan validation failed", "app deploy exposure plan failed"), err
	}
	events := []ProgressEvent{ctx.progressEvent(domain.JobKindAppDeploy, domain.DiagnosticStatusManual, "app deploy exposure plan evaluated")}
	if result, blocked := blockedExposurePlanResult(domain.JobKindAppDeploy, plan, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path)); blocked {
		return prependProgress(result, events...), fmt.Errorf("app deploy exposure plan is blocked")
	}
	if result, required := requiredExposureConfirmationsResult(ctx, domain.JobKindAppDeploy, plan, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path)); required {
		return prependProgress(result, events...), fmt.Errorf("app deploy exposure plan requires manual confirmations")
	}
	if result, invalid := unexpectedExposureConfirmationsResult(ctx, domain.JobKindAppDeploy, plan, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path)); invalid {
		return prependProgress(result, events...), fmt.Errorf("app deploy exposure plan rejected manual confirmations")
	}
	manualConfirmations, err := ctx.recordManualConfirmations(plan.Decision.RequiredConfirmations)
	if err != nil {
		return prependProgress(manualConfirmationRecordFailureResult(domain.JobKindAppDeploy, plan, ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path), err), events...), err
	}
	plan.Access.ManualConfirmations = manualConfirmations
	appDeployRetryCommand := retryCommandWithConfirmations(ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", path), ctx.Confirmations)
	events = append(events, ctx.progressEvent(domain.JobKindAppDeploy, domain.DiagnosticStatusManual, "app deploy host workflow started"))
	result, err := ctx.HostWorkflow.RunAppDeploy(ctx.stdContext(), path, plan, ctx.Confirmations)
	result, err = finishHostOperationResult(result, err, domain.JobKindAppDeploy, appDeployRetryCommand)
	plan.ModifiedPaths = append([]string(nil), result.ModifiedPaths...)
	result.ExposurePlan = &plan
	events = append(events, ctx.progressEvent(domain.JobKindAppDeploy, diagnosticForResult(result, err), "app deploy host workflow finished"))
	result = prependProgress(result, events...)
	if err != nil {
		return result, err
	}
	return result, nil
}

func RunRealIPDiagnostics(ctx Context, appConfigPath string, profileName string) (OperationResult, error) {
	if strings.TrimSpace(profileName) == "" {
		result := realIPDiagnosticsInputFailureResult(ctx, appConfigPath, profileName, "--profile is required", []string{"Pass --profile with the deployed realip profile name."})
		return result, fmt.Errorf("--profile is required")
	}
	if strings.TrimSpace(appConfigPath) == "" {
		result := realIPDiagnosticsInputFailureResult(ctx, appConfigPath, profileName, "--config is required", []string{"Pass --config with the app config that selects the deployed realip profile."})
		return result, fmt.Errorf("--config is required")
	}
	if ctx.HostWorkflow == nil {
		return OperationResult{}, fmt.Errorf("host workflow is required for realip diagnostics")
	}
	events := []ProgressEvent{ctx.progressEvent(domain.JobKindRealIPDiagnostics, domain.DiagnosticStatusManual, "realip diagnostics host workflow started")}
	result, err := ctx.HostWorkflow.RunRealIPDiagnostics(ctx.stdContext(), appConfigPath, profileName)
	result, err = finishHostOperationResult(result, err, domain.JobKindRealIPDiagnostics, ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profileName))
	events = append(events, ctx.progressEvent(domain.JobKindRealIPDiagnostics, diagnosticForResult(result, err), "realip diagnostics host workflow finished"))
	return prependProgress(result, events...), err
}

func realIPDiagnosticsInputFailureResult(ctx Context, appConfigPath string, profileName string, summary string, nextSteps []string) OperationResult {
	return realIPInputFailureResult(ctx, domain.JobKindRealIPDiagnostics, "app realip diagnostics", appConfigPath, profileName, summary, nextSteps)
}

func realIPRefreshInputFailureResult(ctx Context, appConfigPath string, profileName string, summary string, nextSteps []string) OperationResult {
	return realIPInputFailureResult(ctx, domain.JobKindRealIPRefresh, "app realip refresh", appConfigPath, profileName, summary, nextSteps)
}

func realIPInputFailureResult(ctx Context, kind domain.JobKind, command string, appConfigPath string, profileName string, summary string, nextSteps []string) OperationResult {
	retryCommand := ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName)
	if kind == domain.JobKindRealIPDiagnostics {
		retryCommand = ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profileName)
	}
	fields := []domain.ResultField{
		{Label: "app config path", Value: appConfigPath},
		{Label: "profile", Value: profileName},
		{Label: "lanpanel version", Value: ctx.Version},
	}
	return OperationResult{
		Kind:         kind,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       fields,
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(kind, domain.DiagnosticStatusFail, strings.ReplaceAll(command, " ", "_")+":invalid-config", summary, domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: retryCommand,
		NextSteps:    append([]string(nil), nextSteps...),
		Progress:     []ProgressEvent{ctx.progressEvent(kind, domain.DiagnosticStatusFail, command+" input rejected")},
	}
}

func RunRealIPValidateReference(ctx Context, profileName string, appName string, path string) (OperationResult, error) {
	profileName = strings.TrimSpace(profileName)
	appName = strings.TrimSpace(appName)
	path = strings.TrimSpace(path)
	retryCommand := ShellCommand("lanpanel", "app", "realip", "validate-reference", "--profile", profileName, "--app", appName, "--path", path)
	fields := []domain.ResultField{
		{Label: "profile", Value: profileName},
		{Label: "app", Value: appName},
		{Label: "reference path", Value: path},
		{Label: "lanpanel version", Value: ctx.Version},
	}
	if profileName == "" || appName == "" || path == "" {
		result := OperationResult{
			Kind:         domain.JobKindRealIPValidateRef,
			Status:       domain.JobStatusFailed,
			Summary:      "realip reference validation requires profile, app, and path",
			Fields:       fields,
			Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(domain.JobKindRealIPValidateRef, domain.DiagnosticStatusFail, "realip-reference-input", "profile, app, and path are required", domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
			RetryCommand: retryCommand,
			Progress:     []ProgressEvent{ctx.progressEvent(domain.JobKindRealIPValidateRef, domain.DiagnosticStatusFail, "realip reference validation input rejected")},
		}
		return result, fmt.Errorf("realip reference validation requires profile, app, and path")
	}
	reference, err := validateRealIPReferenceFile(profileName, appName, path)
	if err != nil {
		result := OperationResult{
			Kind:         domain.JobKindRealIPValidateRef,
			Status:       domain.JobStatusFailed,
			Summary:      "realip reference validation failed",
			Fields:       fields,
			Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(domain.JobKindRealIPValidateRef, domain.DiagnosticStatusFail, "realip-reference-file", err.Error(), domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel)},
			RetryCommand: retryCommand,
			Progress:     []ProgressEvent{ctx.progressEvent(domain.JobKindRealIPValidateRef, domain.DiagnosticStatusFail, "realip reference validation failed")},
		}
		return result, err
	}
	fields = append(fields, domain.ResultField{Label: "domains", Value: strings.Join(reference.Domains, ", ")})
	return OperationResult{
		Kind:         domain.JobKindRealIPValidateRef,
		Status:       domain.JobStatusSucceeded,
		Summary:      "realip reference validation passed",
		Fields:       fields,
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(domain.JobKindRealIPValidateRef, domain.DiagnosticStatusPass, "realip-reference-file", "realip reference file matches the managed contract", domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel)},
		RetryCommand: retryCommand,
		Progress:     []ProgressEvent{ctx.progressEvent(domain.JobKindRealIPValidateRef, domain.DiagnosticStatusPass, "realip reference validation passed")},
	}, nil
}

func RunRealIPRefresh(ctx Context, appConfigPath string, profileName string, instanceID string) (OperationResult, error) {
	if strings.TrimSpace(profileName) == "" {
		result := realIPRefreshInputFailureResult(ctx, appConfigPath, profileName, "--profile is required", []string{"Pass --profile with the deployed realip profile name."})
		return result, fmt.Errorf("--profile is required")
	}
	if strings.TrimSpace(appConfigPath) == "" {
		result := realIPRefreshInputFailureResult(ctx, appConfigPath, profileName, "--config is required", []string{"Pass --config with the app config that selects the deployed realip profile."})
		return result, fmt.Errorf("--config is required")
	}
	cfg, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		return appHostMutationConfigFailureResult(ctx, domain.JobKindRealIPRefresh, appConfigPath, err, ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName), "realip refresh app config validation failed", "realip refresh config validation failed"), err
	}
	instanceID, err = ctx.requireAppInstanceID(instanceID)
	if err != nil {
		return appHostMutationExposureFailureResult(ctx, domain.JobKindRealIPRefresh, appConfigPath, cfg, err, ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName), "realip refresh exposure instance initialization failed", "realip refresh exposure instance failed"), err
	}
	plan, err := ctx.appHostMutationExposurePlan(appConfigPath, instanceID, cfg, domain.ExposurePlanOperationRealIPRefresh, nil)
	if err != nil {
		return appHostMutationExposureFailureResult(ctx, domain.JobKindRealIPRefresh, appConfigPath, cfg, err, ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName), "realip refresh exposure plan validation failed", "realip refresh exposure plan failed"), err
	}
	events := []ProgressEvent{ctx.progressEvent(domain.JobKindRealIPRefresh, domain.DiagnosticStatusManual, "realip refresh exposure plan evaluated")}
	if result, blocked := blockedExposurePlanResult(domain.JobKindRealIPRefresh, plan, ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName)); blocked {
		return prependProgress(result, events...), fmt.Errorf("realip refresh exposure plan is blocked")
	}
	if err := validateRealIPRefreshConfig(cfg, profileName); err != nil {
		return prependProgress(OperationResult{
			Kind:         domain.JobKindRealIPRefresh,
			Status:       domain.JobStatusFailed,
			Summary:      err.Error(),
			Fields:       []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "profile", Value: profileName}},
			Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(domain.JobKindRealIPRefresh, domain.DiagnosticStatusFail, "realip-refresh-config", err.Error(), domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
			ExposurePlan: &plan,
			RetryCommand: ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName),
		}, events...), err
	}
	if result, required := requiredExposureConfirmationsResult(ctx, domain.JobKindRealIPRefresh, plan, ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName)); required {
		return prependProgress(result, events...), fmt.Errorf("realip refresh exposure plan requires manual confirmations")
	}
	if result, invalid := unexpectedExposureConfirmationsResult(ctx, domain.JobKindRealIPRefresh, plan, ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName)); invalid {
		return prependProgress(result, events...), fmt.Errorf("realip refresh exposure plan rejected manual confirmations")
	}
	manualConfirmations, err := ctx.recordManualConfirmations(plan.Decision.RequiredConfirmations)
	if err != nil {
		return prependProgress(manualConfirmationRecordFailureResult(domain.JobKindRealIPRefresh, plan, ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName), err), events...), err
	}
	plan.Access.ManualConfirmations = manualConfirmations
	if ctx.HostWorkflow == nil {
		return OperationResult{}, fmt.Errorf("host workflow is required for realip refresh")
	}
	realIPRefreshRetryCommand := retryCommandWithConfirmations(ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName), ctx.Confirmations)
	events = append(events, ctx.progressEvent(domain.JobKindRealIPRefresh, domain.DiagnosticStatusManual, "realip refresh host workflow started"))
	result, err := ctx.HostWorkflow.RunRealIPRefresh(ctx.stdContext(), appConfigPath, profileName, plan, ctx.Confirmations)
	result, err = finishHostOperationResult(result, err, domain.JobKindRealIPRefresh, realIPRefreshRetryCommand)
	plan.ModifiedPaths = append([]string(nil), result.ModifiedPaths...)
	result.ExposurePlan = &plan
	events = append(events, ctx.progressEvent(domain.JobKindRealIPRefresh, diagnosticForResult(result, err), "realip refresh host workflow finished"))
	result = prependProgress(result, events...)
	if err != nil {
		return result, err
	}
	return result, nil
}

func validateRealIPRefreshConfig(cfg appconfig.Config, profileName string) error {
	profile, ok := cfg.RealIPProfile(profileName)
	if !ok {
		return fmt.Errorf("realip profile %q is not defined in app config", profileName)
	}
	if cfg.EffectiveRealIPProfileName() != profileName {
		return fmt.Errorf("realip profile %q is not the active origin protection profile", profileName)
	}
	if !profile.IsEnabled() {
		return fmt.Errorf("realip profile %q is disabled", profileName)
	}
	return nil
}

func validateRealIPReferenceFile(profileName string, appName string, path string) (realip.Reference, error) {
	if err := validateRealIPReferencePath(path, profileName, appName); err != nil {
		return realip.Reference{}, err
	}
	info, err := lstatRealIPReferenceFn(path)
	if err != nil {
		return realip.Reference{}, fmt.Errorf("stat deployed realip reference %s: %w", path, err)
	}
	if err := validateRealIPReferenceInfo(path, info); err != nil {
		return realip.Reference{}, err
	}
	data, err := readRealIPReferenceFileFn(path)
	if err != nil {
		return realip.Reference{}, fmt.Errorf("read deployed realip reference %s: %w", path, err)
	}
	return parseRealIPReference(data, path, profileName, appName)
}

func validateRealIPReferencePath(path string, profileName string, appName string) error {
	path = strings.TrimSpace(path)
	profileName = strings.TrimSpace(profileName)
	appName = strings.TrimSpace(appName)
	names, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, appName)
	if err != nil {
		return fmt.Errorf("deployed realip reference path identity is invalid: %w", err)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("deployed realip reference path must be a clean absolute path")
	}
	if path != names.ReferencePathForApp {
		return fmt.Errorf("deployed realip reference path %s must be %s", path, names.ReferencePathForApp)
	}
	return nil
}

func validateRealIPReferenceInfo(path string, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("deployed realip reference %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("deployed realip reference %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("deployed realip reference %s must be root-only, for example mode 0600", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("deployed realip reference %s owner could not be inspected", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("deployed realip reference %s must be owned by root", path)
	}
	return nil
}

func parseRealIPReference(data []byte, path string, profileName string, appName string) (realip.Reference, error) {
	var managed struct {
		LanpanelManaged string `json:"lanpanel_managed"`
		realip.Reference
	}
	if err := json.Unmarshal(data, &managed); err != nil {
		return realip.Reference{}, fmt.Errorf("parse deployed realip reference %s: %w", path, err)
	}
	expectedMarker := realIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne)
	if managed.LanpanelManaged != expectedMarker {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s has lanpanel_managed marker %q, want %q", path, managed.LanpanelManaged, expectedMarker)
	}
	if _, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, appName); err != nil {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s filename app name is not safe: %w", path, err)
	}
	if managed.Profile != profileName {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s profile %q does not match %q", path, managed.Profile, profileName)
	}
	if managed.AppName != appName {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s app_name %q does not match filename %q", path, managed.AppName, appName+".json")
	}
	cleanDomains := make([]string, 0, len(managed.Domains))
	for _, domain := range managed.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return realip.Reference{}, fmt.Errorf("deployed realip reference %s domains must not contain empty values", path)
		}
		cleanDomains = append(cleanDomains, domain)
	}
	if len(cleanDomains) == 0 {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s domains must not be empty", path)
	}
	return realip.Reference{AppName: managed.AppName, Profile: managed.Profile, Domains: cleanDomains}, nil
}

func realIPManagedMarker(profileName string, provider string) string {
	return "Lanpanel-managed: realip.profile=" + strings.TrimSpace(profileName) + " provider=" + strings.TrimSpace(provider)
}

func (ctx Context) appHostMutationExposurePlan(appConfigPath string, instanceID string, cfg appconfig.Config, operation domain.ExposurePlanOperation, modifiedPaths []string) (domain.ExposurePlan, error) {
	observations, err := ctx.appExposureObservations(appConfigPath, cfg, operation)
	if err != nil {
		return domain.ExposurePlan{}, err
	}
	return exposure.AppPlanWithObservations(instanceID, ctx.Version, cfg, ctx.exposurePlanOptions(appConfigPath, operation, modifiedPaths), observations)
}

func (ctx Context) requireAppInstanceID(instanceID string) (string, error) {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID != "" {
		return instanceID, nil
	}
	if ctx.AppInstanceIDProvider == nil {
		return "", fmt.Errorf("app instance id provider is required")
	}
	instanceID, _, err := ctx.AppInstanceIDProvider()
	if err != nil {
		return "", err
	}
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return "", fmt.Errorf("app instance id provider returned an empty instance id")
	}
	return instanceID, nil
}

func (ctx Context) appExposureObservations(appConfigPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation) (exposure.AppObservations, error) {
	observations := ctx.ExposureObservations
	observer, ok := ctx.HostWorkflow.(AppExposureObserver)
	if !ok {
		return observations, nil
	}
	hostObservations, err := observer.AppExposureObservations(ctx.stdContext(), appConfigPath, cfg, operation)
	if err != nil {
		return exposure.AppObservations{}, err
	}
	return mergeAppExposureObservations(observations, hostObservations), nil
}

func mergeAppExposureObservations(base exposure.AppObservations, observed exposure.AppObservations) exposure.AppObservations {
	if strings.TrimSpace(observed.ConfigPath) != "" {
		base.ConfigPath = observed.ConfigPath
	}
	if !observed.GeneratedAt.IsZero() {
		base.GeneratedAt = observed.GeneratedAt
	}
	if observed.Activation.Kind != "" {
		base.Activation = observed.Activation
	}
	if len(observed.Diagnostics) > 0 {
		base.Diagnostics = append([]domain.DiagnosticRef(nil), observed.Diagnostics...)
	}
	if observed.OriginProtectionStatus != "" {
		base.OriginProtectionStatus = observed.OriginProtectionStatus
		base.OriginProtectionReferenceDigest = observed.OriginProtectionReferenceDigest
		base.RealIPTrustedCIDRCount = observed.RealIPTrustedCIDRCount
		base.RealIPClientIPHeader = observed.RealIPClientIPHeader
		base.RealIPSpoofingRejection = observed.RealIPSpoofingRejection
	}
	if observed.GoAccessAuthBasicStatus != "" {
		base.GoAccessAuthBasicStatus = observed.GoAccessAuthBasicStatus
	}
	if observed.BrowserAuthRuntimeStatus != "" {
		base.BrowserAuthRuntimeStatus = observed.BrowserAuthRuntimeStatus
	}
	if observed.BrowserAuthMarkerStatus != "" {
		base.BrowserAuthMarkerStatus = observed.BrowserAuthMarkerStatus
	}
	return base
}

func blockedExposurePlanResult(kind domain.JobKind, plan domain.ExposurePlan, retryCommand string) (OperationResult, bool) {
	if plan.Decision.Status != domain.ExposurePlanDecisionFail && plan.Decision.Status != domain.ExposurePlanDecisionUnknown {
		return OperationResult{}, false
	}
	return OperationResult{
		Kind:         kind,
		Status:       domain.JobStatusFailed,
		Summary:      "exposure plan blocked host mutation",
		Fields:       exposurePlanResultFields(plan, nil),
		Diagnostics:  exposurePlanDiagnostics(kind, plan),
		ExposurePlan: &plan,
		RetryCommand: retryCommand,
	}, true
}

func requiredExposureConfirmationsResult(ctx Context, kind domain.JobKind, plan domain.ExposurePlan, retryCommand string) (OperationResult, bool) {
	if plan.Decision.Status != domain.ExposurePlanDecisionManual {
		return OperationResult{}, false
	}
	missing := missingConfirmations(plan.Decision.RequiredConfirmations, ctx.Confirmations)
	if len(missing) == 0 {
		return OperationResult{}, false
	}
	return OperationResult{
		Kind:         kind,
		Status:       domain.JobStatusFailed,
		Summary:      "exposure plan requires manual confirmations",
		Fields:       exposurePlanResultFields(plan, missing),
		Diagnostics:  exposurePlanDiagnostics(kind, plan),
		ExposurePlan: &plan,
		RetryCommand: retryCommandWithConfirmations(retryCommand, missing),
	}, true
}

func unexpectedExposureConfirmationsResult(ctx Context, kind domain.JobKind, plan domain.ExposurePlan, retryCommand string) (OperationResult, bool) {
	extra := unexpectedConfirmations(plan.Decision.RequiredConfirmations, ctx.Confirmations)
	if len(extra) == 0 {
		return OperationResult{}, false
	}
	fields := exposurePlanResultFields(plan, nil)
	fields = append(fields, domain.ResultField{Label: "unexpected confirmations", Value: strings.Join(extra, ", ")})
	return OperationResult{
		Kind:         kind,
		Status:       domain.JobStatusFailed,
		Summary:      "exposure plan rejected manual confirmations",
		Fields:       fields,
		Diagnostics:  exposurePlanDiagnostics(kind, plan),
		ExposurePlan: &plan,
		RetryCommand: retryCommand,
	}, true
}

func manualConfirmationRecordFailureResult(kind domain.JobKind, plan domain.ExposurePlan, retryCommand string, cause error) OperationResult {
	return OperationResult{
		Kind:         kind,
		Status:       domain.JobStatusFailed,
		Summary:      "manual confirmation recording failed",
		Fields:       append(exposurePlanResultFields(plan, nil), domain.ResultField{Label: "details", Value: cause.Error()}),
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(kind, domain.DiagnosticStatusFail, "manual-confirmation-record", cause.Error(), domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLanPanel)},
		ExposurePlan: &plan,
		RetryCommand: retryCommand,
	}
}

func exposurePlanResultFields(plan domain.ExposurePlan, missing []string) []domain.ResultField {
	fields := []domain.ResultField{
		{Label: "resource id", Value: plan.Resource.ID},
		{Label: "resource name", Value: plan.Resource.CanonicalName},
		{Label: "access", Value: string(plan.Access.AccessMode)},
		{Label: "origin protection", Value: string(plan.OriginProtection)},
		{Label: "exposure decision", Value: string(plan.Decision.Status)},
	}
	if len(plan.Decision.RequiredConfirmations) > 0 {
		fields = append(fields, domain.ResultField{Label: "required confirmations", Value: strings.Join(plan.Decision.RequiredConfirmations, ", ")})
	}
	if len(missing) > 0 {
		fields = append(fields, domain.ResultField{Label: "missing confirmations", Value: strings.Join(missing, ", ")})
	}
	for _, blocker := range plan.DiagnosticBlockers {
		fields = append(fields, domain.ResultField{Label: "blocker " + blocker.ID, Value: string(blocker.Status) + ": " + blocker.Summary})
	}
	return fields
}

func exposurePlanDiagnostics(kind domain.JobKind, plan domain.ExposurePlan) []domain.DiagnosticItem {
	diagnostics := make([]domain.DiagnosticItem, 0, len(plan.DiagnosticBlockers)+1)
	for _, blocker := range plan.DiagnosticBlockers {
		item := blocker
		item.ID = "exposure-plan:" + item.ID
		diagnostics = append(diagnostics, item)
	}
	if len(diagnostics) == 0 {
		status := domain.DiagnosticStatusManual
		if plan.Decision.Status == domain.ExposurePlanDecisionFail || plan.Decision.Status == domain.ExposurePlanDecisionUnknown {
			status = domain.DiagnosticStatusFail
		}
		diagnostics = append(diagnostics, operationDiagnostic(kind, status, "exposure-plan", "exposure plan decision: "+string(plan.Decision.Status), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin))
	}
	return diagnostics
}

func (ctx Context) exposurePlanOptions(configPath string, operation domain.ExposurePlanOperation, modifiedPaths []string) exposure.AppPlanOptions {
	now := time.Now
	if ctx.Now != nil {
		now = ctx.Now
	}
	return exposure.AppPlanOptions{
		ConfigPath:    configPath,
		Actor:         ctx.Actor,
		Operation:     operation,
		CreatedAt:     now().UTC(),
		ModifiedPaths: append([]string(nil), modifiedPaths...),
		BeforeDigest:  "none",
	}
}

func retryCommandWithConfirmations(retryCommand string, confirmations []string) string {
	retryCommand = strings.TrimSpace(retryCommand)
	if retryCommand == "Management UI" {
		return retryCommand
	}
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation == "" {
			continue
		}
		retryCommand = strings.TrimSpace(retryCommand + " " + ShellCommand("--confirmation", confirmation))
	}
	return retryCommand
}

func missingConfirmations(required []string, confirmed []string) []string {
	seen := map[string]struct{}{}
	for _, value := range confirmed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	missing := []string{}
	for _, value := range required {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; !ok {
			missing = append(missing, value)
		}
	}
	return missing
}

func unexpectedConfirmations(required []string, confirmed []string) []string {
	requiredSet := map[string]struct{}{}
	for _, value := range required {
		value = strings.TrimSpace(value)
		if value != "" {
			requiredSet[value] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	extra := []string{}
	for _, value := range confirmed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		if _, ok := requiredSet[value]; !ok {
			extra = append(extra, value)
		}
	}
	return extra
}

func (ctx Context) recordManualConfirmations(confirmations []string) ([]domain.ManualConfirmation, error) {
	if len(confirmations) == 0 {
		return nil, nil
	}
	if ctx.ManualConfirmationRecorder == nil {
		return nil, fmt.Errorf("manual confirmation recorder is required for: %s", strings.Join(confirmations, ", "))
	}
	records, err := ctx.ManualConfirmationRecorder(confirmations)
	if err != nil {
		return nil, err
	}
	if err := domain.ValidateManualConfirmationRecords(confirmations, records); err != nil {
		return nil, err
	}
	return records, nil
}

func RunPreAuthKeyCreate(ctx Context, user string, ttl time.Duration) (OperationResult, error) {
	if ctx.PreAuthKeyCreator == nil {
		err := fmt.Errorf("headscale preauth key creator is required")
		return preAuthKeyCreateFailureResult(ctx, user, ttl, err.Error()), err
	}
	plan, err := headscale.NewOnboardingPlan(headscale.OnboardingOptions{
		UserName:   user,
		Expiration: ttl,
	})
	if err != nil {
		return preAuthKeyCreateFailureResult(ctx, user, ttl, err.Error()), err
	}
	key, _, err := ctx.PreAuthKeyCreator.CreatePreAuthKey(ctx.stdContext(), plan)
	if err != nil {
		err := fmt.Errorf("create headscale preauth key: %s", redactAuthKeyMarkers(err.Error()))
		return preAuthKeyCreateFailureResult(ctx, plan.UserName, plan.Expiration, err.Error()), err
	}
	key = strings.TrimSpace(key)
	if key == "" {
		err := fmt.Errorf("headscale preauth key creator returned an empty key")
		return preAuthKeyCreateFailureResult(ctx, plan.UserName, plan.Expiration, err.Error()), err
	}
	now := time.Now
	if ctx.Now != nil {
		now = ctx.Now
	}
	expiresAt := now().Add(plan.Expiration).UTC()
	return OperationResult{
		Kind:    domain.JobKindPreAuthKeyCreate,
		Status:  domain.JobStatusSucceeded,
		Summary: "preauth key created for one-time handoff",
		Fields: []domain.ResultField{
			{Label: "target user", Value: plan.UserName},
			{Label: "expires at", Value: expiresAt.Format(time.RFC3339)},
			{Label: "fingerprint", Value: fingerprint(key)},
		},
		RetryCommand:  ShellCommand("sudo", "lanpanel", "ui"),
		Progress:      []ProgressEvent{ctx.progressEvent(domain.JobKindPreAuthKeyCreate, domain.DiagnosticStatusPass, "preauth key handoff created")},
		OneTimeSecret: &OneTimeSecret{Label: "preauth key", Value: key, Fingerprint: fingerprint(key), ExpiresAt: expiresAt},
	}, nil
}

func preAuthKeyCreateFailureResult(ctx Context, user string, ttl time.Duration, summary string) OperationResult {
	fields := []domain.ResultField{{Label: "target user", Value: strings.TrimSpace(user)}}
	if ttl != 0 {
		fields = append(fields, domain.ResultField{Label: "ttl", Value: ttl.String()})
	}
	return OperationResult{
		Kind:         domain.JobKindPreAuthKeyCreate,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       fields,
		RetryCommand: ShellCommand("sudo", "lanpanel", "ui"),
		Progress:     []ProgressEvent{ctx.progressEvent(domain.JobKindPreAuthKeyCreate, domain.DiagnosticStatusFail, "preauth key handoff failed")},
	}
}

func RunBrowserAuthCreate(ctx Context, dir string, id string, username string, password string) (OperationResult, error) {
	if ctx.BrowserAuthDependencyEnsurer == nil {
		err := fmt.Errorf("browser auth dependency ensurer is required")
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthCreate, "browser auth credential create failed", err, []domain.ResultField{{Label: "browser auth dir", Value: dir}, {Label: "credential id", Value: id}, {Label: "username", Value: username}}), err
	}
	if err := ctx.BrowserAuthDependencyEnsurer(ctx.stdContext()); err != nil {
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthCreate, "browser auth credential create failed", err, []domain.ResultField{{Label: "browser auth dir", Value: dir}, {Label: "credential id", Value: id}, {Label: "username", Value: username}}), err
	}
	credential, err := browserauth.CreateManaged(dir, id, username, password)
	if err != nil {
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthCreate, "browser auth credential create failed", err, []domain.ResultField{{Label: "browser auth dir", Value: dir}, {Label: "credential id", Value: id}, {Label: "username", Value: username}}), err
	}
	return browserAuthResult(ctx, domain.JobKindBrowserAuthCreate, "browser auth credential created", credential), nil
}

func RunBrowserAuthRotate(ctx Context, appConfigPath string, instanceID string, path string, username string, password string) (OperationResult, error) {
	if strings.TrimSpace(appConfigPath) == "" {
		err := fmt.Errorf("app config path is required")
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthRotate, "browser auth credential rotate failed", err, []domain.ResultField{{Label: "htpasswd path", Value: path}, {Label: "username", Value: username}}), err
	}
	if strings.TrimSpace(instanceID) == "" {
		err := fmt.Errorf("instance id is required")
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthRotate, "browser auth credential rotate failed", err, []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "htpasswd path", Value: path}, {Label: "username", Value: username}}), err
	}
	cfg, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthRotate, "browser auth credential rotate failed", err, []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "htpasswd path", Value: path}, {Label: "username", Value: username}}), err
	}
	if err := validateBrowserAuthRotateTarget(cfg, path); err != nil {
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthRotate, "browser auth credential rotate failed", err, []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "htpasswd path", Value: path}, {Label: "username", Value: username}}), err
	}
	plan, err := ctx.appHostMutationExposurePlan(appConfigPath, instanceID, cfg, domain.ExposurePlanOperationBrowserAuthRotate, []string{path})
	if err != nil {
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthRotate, "browser auth credential rotate failed", err, []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "htpasswd path", Value: path}, {Label: "username", Value: username}}), err
	}
	events := []ProgressEvent{ctx.progressEvent(domain.JobKindBrowserAuthRotate, domain.DiagnosticStatusManual, "browser auth rotate exposure plan evaluated")}
	if result, blocked := blockedExposurePlanResult(domain.JobKindBrowserAuthRotate, plan, ShellCommand("sudo", "lanpanel", "ui")); blocked {
		return prependProgress(result, events...), fmt.Errorf("browser auth rotate exposure plan is blocked")
	}
	if result, required := requiredExposureConfirmationsResult(ctx, domain.JobKindBrowserAuthRotate, plan, ShellCommand("sudo", "lanpanel", "ui")); required {
		return prependProgress(result, events...), fmt.Errorf("browser auth rotate exposure plan requires manual confirmations")
	}
	credential, err := browserauth.RotateManaged(path, username, password)
	if err != nil {
		return prependProgress(browserAuthFailureResult(ctx, domain.JobKindBrowserAuthRotate, "browser auth credential rotate failed", err, []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "htpasswd path", Value: path}, {Label: "username", Value: username}}), events...), err
	}
	result := browserAuthResult(ctx, domain.JobKindBrowserAuthRotate, "browser auth credential rotated", credential)
	result.ExposurePlan = &plan
	result.Progress = append(events, result.Progress...)
	return result, nil
}

func validateBrowserAuthRotateTarget(cfg appconfig.Config, path string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" {
		return fmt.Errorf("browser auth rotate htpasswd path is required")
	}
	if !cfg.BrowserAuthEnabled() || cfg.Access.AccessMode != appconfig.AccessModeBrowser {
		return fmt.Errorf("browser auth rotate requires a browser app that references the managed credential")
	}
	managedPath := filepath.Clean(strings.TrimSpace(cfg.Access.BrowserAuth.Managed.HtpasswdPath))
	if managedPath == "." || managedPath == "" {
		return fmt.Errorf("browser auth rotate requires access.browser_auth.managed.htpasswd_path")
	}
	if managedPath != path {
		return fmt.Errorf("browser auth rotate target %s is not referenced by app %s", path, cfg.App.Name)
	}
	if strings.TrimSpace(cfg.Access.BrowserAuth.Managed.CredentialID) == "" {
		return fmt.Errorf("browser auth rotate requires access.browser_auth.managed.credential_id")
	}
	return nil
}

func RunBrowserAuthDelete(ctx Context, path string, referencedPaths []string) (OperationResult, error) {
	if err := browserauth.DeleteManaged(path, referencedPaths); err != nil {
		fields := []domain.ResultField{{Label: "htpasswd path", Value: path}}
		if len(referencedPaths) > 0 {
			fields = append(fields, domain.ResultField{Label: "referenced by", Value: strings.Join(referencedPaths, ", ")})
		}
		return browserAuthFailureResult(ctx, domain.JobKindBrowserAuthDelete, "browser auth credential delete failed", err, fields), err
	}
	return OperationResult{
		Kind:          domain.JobKindBrowserAuthDelete,
		Status:        domain.JobStatusSucceeded,
		Summary:       "browser auth credential deleted",
		Fields:        []domain.ResultField{{Label: "htpasswd path", Value: path}, {Label: "lanpanel version", Value: ctx.Version}},
		ModifiedPaths: []string{path},
		RetryCommand:  ShellCommand("sudo", "lanpanel", "ui"),
		Progress:      []ProgressEvent{ctx.progressEvent(domain.JobKindBrowserAuthDelete, domain.DiagnosticStatusPass, "browser auth credential deleted")},
	}, nil
}

func (ctx Context) stdContext() stdcontext.Context {
	if ctx.BaseContext != nil {
		return ctx.BaseContext
	}
	return stdcontext.Background()
}

func finishHostOperationResult(result OperationResult, err error, kind domain.JobKind, retryCommand string) (OperationResult, error) {
	if result.Kind == "" {
		result.Kind = kind
	}
	if result.Kind != kind {
		if err != nil {
			return result, fmt.Errorf("%w; host workflow returned kind %q, want %q", err, result.Kind, kind)
		}
		return OperationResult{}, fmt.Errorf("host workflow returned kind %q, want %q", result.Kind, kind)
	}
	if result.RetryCommand == "" {
		result.RetryCommand = retryCommand
	}
	if err != nil {
		if result.Status == "" {
			result.Status = domain.JobStatusFailed
		}
		if strings.TrimSpace(result.Summary) == "" {
			result.Summary = string(kind) + " failed"
		}
		return result, err
	}
	if result.Status == "" {
		return OperationResult{}, fmt.Errorf("host workflow returned empty status for %s", kind)
	}
	if strings.TrimSpace(result.Summary) == "" {
		return OperationResult{}, fmt.Errorf("host workflow returned empty summary for %s", kind)
	}
	if strings.TrimSpace(result.RetryCommand) == "" {
		return OperationResult{}, fmt.Errorf("host workflow returned empty retry command for %s", kind)
	}
	return result, nil
}

func diagnosticForResult(result OperationResult, err error) domain.DiagnosticStatus {
	if err != nil {
		return domain.DiagnosticStatusFail
	}
	switch result.Status {
	case domain.JobStatusSucceeded:
		return domain.DiagnosticStatusPass
	case domain.JobStatusInterrupted, domain.JobStatusUnknown:
		return domain.DiagnosticStatusUnknown
	case domain.JobStatusFailed:
		return domain.DiagnosticStatusFail
	default:
		return domain.DiagnosticStatusManual
	}
}

func browserAuthResult(ctx Context, kind domain.JobKind, summary string, credential browserauth.Credential) OperationResult {
	return OperationResult{
		Kind:    kind,
		Status:  domain.JobStatusSucceeded,
		Summary: summary,
		Fields: []domain.ResultField{
			{Label: "credential id", Value: credential.ID},
			{Label: "username", Value: credential.Username},
			{Label: "htpasswd path", Value: credential.HtpasswdPath},
			{Label: "password fingerprint", Value: credential.PasswordFingerprint},
			{Label: "lanpanel version", Value: ctx.Version},
		},
		ModifiedPaths: []string{credential.HtpasswdPath},
		RetryCommand:  ShellCommand("sudo", "lanpanel", "ui"),
		Progress:      []ProgressEvent{ctx.progressEvent(kind, domain.DiagnosticStatusPass, summary)},
		OneTimeSecret: &OneTimeSecret{
			Label:       "browser auth password",
			Value:       credential.Password,
			Fingerprint: credential.PasswordFingerprint,
		},
	}
}

func browserAuthFailureResult(ctx Context, kind domain.JobKind, summary string, cause error, fields []domain.ResultField) OperationResult {
	fields = append(append([]domain.ResultField(nil), fields...), domain.ResultField{Label: "details", Value: cause.Error()}, domain.ResultField{Label: "lanpanel version", Value: ctx.Version})
	return OperationResult{
		Kind:         kind,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       fields,
		Diagnostics:  []domain.DiagnosticItem{operationDiagnostic(kind, domain.DiagnosticStatusFail, "browser-auth", cause.Error(), domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin)},
		RetryCommand: ShellCommand("sudo", "lanpanel", "ui"),
		Progress:     []ProgressEvent{ctx.progressEvent(kind, domain.DiagnosticStatusFail, summary)},
	}
}

func operationDiagnostic(kind domain.JobKind, status domain.DiagnosticStatus, id string, summary string, scope domain.DiagnosticScope, evidence domain.DiagnosticEvidenceSource, responsible domain.DiagnosticResponsibleParty) domain.DiagnosticItem {
	item := diagnosticItem(id, status, summary, scope, evidence, responsible)
	item.Title = string(kind)
	return item
}

func mainConfigFields(path string, cfg config.Config, version string) []domain.ResultField {
	return []domain.ResultField{
		{Label: "config path", Value: path},
		{Label: "server url", Value: cfg.Default.ServerURL},
		{Label: "base domain", Value: cfg.Default.BaseDomain},
		{Label: "certificate email", Value: cfg.Default.CertificateEmail},
		{Label: "acme challenge", Value: cfg.Default.ACMEChallenge},
		{Label: "dns01 provider", Value: cfg.Advanced.DNS01.Provider},
		{Label: "headscale source", Value: cfg.Advanced.HeadscaleSource.Mode},
		{Label: "lego source", Value: cfg.Advanced.LegoSource.Mode},
		{Label: "platform arch", Value: cfg.Advanced.Platform.Arch},
		{Label: "lanpanel version", Value: version},
	}
}

func appConfigFields(path string, cfg appconfig.Config, version string) []domain.ResultField {
	return []domain.ResultField{
		{Label: "app config path", Value: path},
		{Label: "app name", Value: cfg.App.Name},
		{Label: "domains", Value: strings.Join(cfg.App.Domains, ", ")},
		{Label: "target mode", Value: string(cfg.Mode())},
		{Label: "access mode", Value: string(cfg.Access.AccessMode)},
		{Label: "origin protection", Value: string(cfg.Access.OriginProtection.Mode)},
		{Label: "goaccess", Value: fmt.Sprintf("%t", cfg.Nginx.GoAccess.Enabled)},
		{Label: "lanpanel version", Value: version},
	}
}

func appRuntimeFields(path string, cfg appconfig.Config) []domain.ResultField {
	fields := []domain.ResultField{{Label: "app config path", Value: path}}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		fields = append(fields, domain.ResultField{Label: "app names", Value: "failed: " + err.Error()})
		return fields
	}
	fields = append(fields, []domain.ResultField{
		{Label: "app service", Value: names.ServiceUnit},
		{Label: "app renew timer", Value: names.RenewTimerUnit},
		{Label: "app nginx available", Value: names.NginxAvailablePath},
		{Label: "app nginx enabled", Value: names.NginxEnabledPath},
		{Label: "app fullchain", Value: names.FullchainPath},
		{Label: "app reload hook", Value: names.HookPath},
		{Label: "app access log", Value: cfg.NginxGoAccessCanonicalAccessLogPath()},
	}...)
	if cfg.Nginx.GoAccess.Enabled {
		fields = append(fields,
			domain.ResultField{Label: "goaccess service", Value: names.GoAccessServiceUnit},
			domain.ResultField{Label: "goaccess report", Value: names.GoAccessReportPath},
			domain.ResultField{Label: "goaccess websocket", Value: names.GoAccessWebSocketListen},
		)
	}
	if profileName := cfg.EffectiveRealIPProfileName(); profileName != "" {
		profile, ok := cfg.RealIPProfile(profileName)
		if ok {
			realIPNames, err := appsvc.NewRealIPProfileNames(profileName, profile.Provider, cfg.App.Name)
			if err == nil {
				fields = append(fields,
					domain.ResultField{Label: "realip refresh service", Value: realIPNames.RefreshServiceUnit},
					domain.ResultField{Label: "realip refresh timer", Value: realIPNames.RefreshTimerUnit},
					domain.ResultField{Label: "realip state", Value: realIPNames.StatePath},
					domain.ResultField{Label: "realip reference", Value: realIPNames.ReferencePathForApp},
				)
			}
		}
	}
	return fields
}

func hostHealthDiagnostics(summary domain.HostHealthSummary) []domain.DiagnosticItem {
	refs := []domain.DiagnosticRef{}
	refs = append(refs, summary.Checks.DNS...)
	refs = append(refs, summary.Checks.Ports...)
	refs = append(refs, summary.Checks.AptDpkgSystemd...)
	refs = append(refs, summary.Checks.NginxConfigTest...)
	refs = append(refs, summary.Checks.Certificates...)
	refs = append(refs, summary.Checks.PublicPreflight...)
	items := make([]domain.DiagnosticItem, 0, len(refs)+1)
	items = append(items, diagnosticItem("host-health", domain.DiagnosticStatusPass, summary.Host.OS, domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin))
	for _, ref := range refs {
		items = append(items, diagnosticItemFromRef("host-health:"+ref.ID, ref, string(ref.Status)))
	}
	return items
}

func hasFailedDiagnostic(items []domain.DiagnosticItem) bool {
	for _, item := range items {
		if item.Status == domain.DiagnosticStatusFail {
			return true
		}
	}
	return false
}

func serverNameFromURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return strings.TrimSpace(raw)
	}
	return parsed.Hostname()
}

func mainVerifyDiagnostics(report verify.Report) []domain.DiagnosticItem {
	items := make([]domain.DiagnosticItem, 0, len(report.Checks))
	for _, check := range report.Checks {
		status := verifyStatus(check.Status)
		scope, evidence, responsible := mainDiagnosticMetadata(check.ID)
		items = append(items, diagnosticItem(check.ID, status, check.Summary, scope, evidence, responsible))
	}
	return items
}

func appVerifyDiagnostics(report appverify.Report) []domain.DiagnosticItem {
	items := make([]domain.DiagnosticItem, 0, len(report.Checks))
	for _, check := range report.Checks {
		status := appVerifyStatus(check.Status)
		scope, evidence, responsible := appDiagnosticMetadata(check.ID)
		items = append(items, diagnosticItem(check.ID, status, check.Summary, scope, evidence, responsible))
	}
	return items
}

func diagnosticItem(id string, status domain.DiagnosticStatus, summary string, scope domain.DiagnosticScope, evidence domain.DiagnosticEvidenceSource, responsible domain.DiagnosticResponsibleParty) domain.DiagnosticItem {
	return domain.DiagnosticItem{
		ID:               id,
		Status:           status,
		Scope:            scope,
		Severity:         diagnosticSeverity(status),
		Summary:          summary,
		EvidenceSource:   evidence,
		ResponsibleParty: responsible,
		BlocksActivation: diagnosticBlocksActivation(status),
		Redaction:        domain.RedactionNone,
		RedactionStatus:  domain.RedactionStatusNoSensitiveData,
	}
}

func diagnosticItemFromRef(id string, ref domain.DiagnosticRef, summary string) domain.DiagnosticItem {
	item := domain.DiagnosticItem{
		ID:               id,
		Status:           ref.Status,
		Scope:            ref.Scope,
		ResourceID:       ref.ResourceID,
		Severity:         ref.Severity,
		Summary:          summary,
		EvidenceSource:   ref.EvidenceSource,
		ResponsibleParty: ref.ResponsibleParty,
		BlocksActivation: ref.BlocksActivation,
		Redaction:        ref.Redaction,
		RedactionStatus:  ref.RedactionStatus,
	}
	if item.Scope == "" {
		item.Scope = domain.DiagnosticScopeInstance
	}
	if item.Severity == "" {
		item.Severity = diagnosticSeverity(ref.Status)
	}
	if item.EvidenceSource == "" {
		item.EvidenceSource = domain.DiagnosticEvidenceRuntimeProbe
	}
	if item.ResponsibleParty == "" {
		item.ResponsibleParty = domain.DiagnosticResponsibleLocalAdmin
	}
	if item.RedactionStatus == "" {
		item.RedactionStatus = domain.RedactionStatusNoSensitiveData
	}
	return item
}

func mainDiagnosticMetadata(id string) (domain.DiagnosticScope, domain.DiagnosticEvidenceSource, domain.DiagnosticResponsibleParty) {
	switch id {
	case "certificate-plan":
		return domain.DiagnosticScopeCertificate, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin
	case "certificate-hook", "renewal-service", "renewal-timer":
		return domain.DiagnosticScopeCertificate, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel
	case "headscale-config", "acl-policy", "client-version":
		return domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel
	case "nginx-site":
		return domain.DiagnosticScopeService, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel
	case "config":
		return domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin
	default:
		return domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel
	}
}

func appDiagnosticMetadata(id string) (domain.DiagnosticScope, domain.DiagnosticEvidenceSource, domain.DiagnosticResponsibleParty) {
	switch id {
	case "config", "tailscale", "names":
		return domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin
	case "goaccess", "goaccess-scope":
		return domain.DiagnosticScopeGoAccess, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel
	case "nginx":
		return domain.DiagnosticScopeService, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel
	default:
		return domain.DiagnosticScopeResource, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLanPanel
	}
}

func diagnosticSeverity(status domain.DiagnosticStatus) domain.DiagnosticSeverity {
	switch status {
	case domain.DiagnosticStatusFail:
		return domain.DiagnosticSeverityCritical
	case domain.DiagnosticStatusWarn, domain.DiagnosticStatusManual, domain.DiagnosticStatusUnknown:
		return domain.DiagnosticSeverityMedium
	default:
		return domain.DiagnosticSeverityInfo
	}
}

func diagnosticBlocksActivation(status domain.DiagnosticStatus) bool {
	return status == domain.DiagnosticStatusFail
}

func verifyStatus(status verify.Status) domain.DiagnosticStatus {
	if status == verify.StatusPass {
		return domain.DiagnosticStatusPass
	}
	if status == verify.StatusWarn {
		return domain.DiagnosticStatusWarn
	}
	return domain.DiagnosticStatusFail
}

func appVerifyStatus(status appverify.Status) domain.DiagnosticStatus {
	if status == appverify.StatusPass {
		return domain.DiagnosticStatusPass
	}
	return domain.DiagnosticStatusFail
}

func stagedPaths(files []apprender.StagedFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.HostPath)
	}
	return paths
}

func mainStagedPaths(files []render.StagedFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.HostPath)
	}
	return paths
}

func fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func ValidateNoSecretOutput(result OperationResult) error {
	if err := validateNoSensitiveText("summary", result.Summary); err != nil {
		return err
	}
	if err := validateNoSensitiveRetryCommand(result.RetryCommand); err != nil {
		return err
	}
	for _, path := range result.ModifiedPaths {
		if err := validateNoSensitivePathText("modified path", path); err != nil {
			return err
		}
	}
	for _, step := range result.NextSteps {
		if err := validateNoSensitiveText("next step", step); err != nil {
			return err
		}
	}
	for _, field := range result.Fields {
		if !safeSensitiveResultLabel(field.Label) {
			if err := validateNoSensitiveText("result field label", field.Label); err != nil {
				return err
			}
		}
		if fieldValueIsCheckSummary(field.Label) && workflowCheckSummaryPattern.MatchString(strings.TrimSpace(field.Value)) {
			continue
		}
		if fieldValueIsPath(field.Label) {
			if err := validateNoSensitivePathText("result field "+field.Label, field.Value); err != nil {
				return err
			}
			continue
		}
		if err := validateNoSensitiveText("result field "+field.Label, field.Value); err != nil {
			return err
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if err := validateNoSensitiveText("diagnostic title", diagnostic.Title); err != nil {
			return err
		}
		if err := validateNoSensitiveText("diagnostic summary", diagnostic.Summary); err != nil {
			return err
		}
		for _, remediation := range diagnostic.Remediation {
			if err := validateNoSensitiveText("diagnostic remediation", remediation); err != nil {
				return err
			}
		}
	}
	for _, progress := range result.Progress {
		if err := validateNoSensitiveText("progress message", progress.Message); err != nil {
			return err
		}
	}
	if result.ExposurePlan != nil {
		if err := validateNoSensitiveExposurePlan(*result.ExposurePlan); err != nil {
			return err
		}
	}
	return nil
}

func validateNoSensitiveExposurePlan(plan domain.ExposurePlan) error {
	for _, path := range plan.ModifiedPaths {
		if err := validateNoSensitivePathText("exposure plan modified path", path); err != nil {
			return err
		}
	}
	for _, resourceID := range plan.ResourcesChanged {
		if err := validateNoSensitiveText("exposure plan resource id", resourceID); err != nil {
			return err
		}
	}
	if err := validateNoSensitiveText("exposure plan resource name", plan.Resource.Name); err != nil {
		return err
	}
	if err := validateNoSensitiveText("exposure plan resource canonical name", plan.Resource.CanonicalName); err != nil {
		return err
	}
	if err := validateNoSensitivePathText("exposure plan config path", plan.Resource.ConfigRef.Path); err != nil {
		return err
	}
	if err := validateNoSensitivePathText("exposure plan nginx site", plan.Access.PublicEntry.NginxSite); err != nil {
		return err
	}
	for _, domainName := range plan.Access.PublicEntry.Domains {
		if err := validateNoSensitiveText("exposure plan domain", domainName); err != nil {
			return err
		}
	}
	for _, magicDNSName := range plan.Access.PrivateEntry.MagicDNSNames {
		if err := validateNoSensitiveText("exposure plan magicdns name", magicDNSName); err != nil {
			return err
		}
	}
	for _, record := range plan.Access.PrivateEntry.DNSExtraRecords {
		if err := validateNoSensitiveText("exposure plan dns record", record); err != nil {
			return err
		}
	}
	for _, blocker := range plan.DiagnosticBlockers {
		if err := validateNoSensitiveText("exposure diagnostic title", blocker.Title); err != nil {
			return err
		}
		if err := validateNoSensitiveText("exposure diagnostic summary", blocker.Summary); err != nil {
			return err
		}
		for _, remediation := range blocker.Remediation {
			if err := validateNoSensitiveText("exposure diagnostic remediation", remediation); err != nil {
				return err
			}
		}
	}
	return nil
}

func safeSensitiveResultLabel(label string) bool {
	normalized := strings.TrimSpace(strings.ToLower(label))
	if workflowCheckFieldLabelPattern.MatchString(normalized) {
		return true
	}
	if strings.Contains(normalized, "auth-key-file") || strings.Contains(normalized, "auth key file") {
		return true
	}
	switch normalized {
	case "browser auth dir",
		"browser auth",
		"browser auth mode",
		"browser auth runtime",
		"browser auth marker",
		"browser protection",
		"exposure decision",
		"goaccess auth",
		"goaccess auth file",
		"password fingerprint",
		"public exposure risk",
		"startup token fingerprint":
		return true
	default:
		return false
	}
}

func validateNoSensitiveText(label string, text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	if strings.TrimSpace(strings.ToLower(label)) == "result field host actions" {
		return nil
	}
	if containsRawSecretMarker(text) {
		return fmt.Errorf("workflow result contains secret marker in %s: %s", label, sensitive.RedactText(text))
	}
	scanText := acmeChallengeTokenPlaceholderPattern.ReplaceAllString(text, "/.well-known/acme-challenge/<placeholder>")
	if safeSensitiveResultText(scanText) {
		return nil
	}
	if sensitive.ContainsText(scanText) {
		return fmt.Errorf("workflow result %s contains sensitive text: %s", label, sensitive.RedactText(text))
	}
	return nil
}

func validateNoSensitivePathText(label string, text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	if containsRawSecretMarker(text) || sensitive.ContainsURLUserinfo(text) {
		return fmt.Errorf("workflow result contains secret marker in %s: %s", label, sensitive.RedactText(text))
	}
	return nil
}

func validateNoSensitiveRetryCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	if containsRawSecretMarker(command) {
		return fmt.Errorf("workflow result contains secret marker in retry command: %s", sensitive.RedactText(command))
	}
	return validateNoSensitiveText("retry command", retryCommandWithoutPathArguments(command))
}

func retryCommandWithoutPathArguments(command string) string {
	fields := strings.Fields(command)
	filtered := make([]string, 0, len(fields))
	skipNext := false
	for _, field := range fields {
		if skipNext {
			skipNext = false
			continue
		}
		switch field {
		case "--config", "--app-config":
			filtered = append(filtered, field)
			skipNext = true
			continue
		}
		if strings.HasPrefix(field, "--config=") {
			filtered = append(filtered, "--config=<path>")
			continue
		}
		if strings.HasPrefix(field, "--app-config=") {
			filtered = append(filtered, "--app-config=<path>")
			continue
		}
		filtered = append(filtered, field)
	}
	return strings.Join(filtered, " ")
}

func fieldValueIsPath(label string) bool {
	normalized := strings.TrimSpace(strings.ToLower(label))
	return strings.Contains(normalized, " path") ||
		strings.HasSuffix(normalized, "path") ||
		strings.Contains(normalized, " file") ||
		strings.HasSuffix(normalized, "file") ||
		strings.Contains(normalized, " dir") ||
		strings.HasSuffix(normalized, "dir")
}

func fieldValueIsCheckSummary(label string) bool {
	return strings.TrimSpace(strings.ToLower(label)) == "checks"
}

func safeSensitiveResultText(text string) bool {
	lower := strings.TrimSpace(strings.ToLower(text))
	switch lower {
	case "preauth key created for one-time handoff",
		"preauth key handoff created",
		"preauth key handoff failed",
		"headscale preauth key creator is required",
		"headscale preauth key creator returned an empty key",
		"lanpanel basic auth enabled; upstream authorization header is cleared":
		return true
	}
	if strings.Contains(lower, "no lanpanel basic auth is rendered") {
		return true
	}
	if strings.Contains(lower, "rendered files do not contain tailscale auth keys or dns tokens") {
		return true
	}
	if strings.Contains(lower, "rendered file contains a suspected sensitive value:") {
		return true
	}
	if strings.Contains(lower, "headscale onboarding") && strings.Contains(lower, "preauth key") {
		return true
	}
	if strings.Contains(lower, "preauth key handoff") {
		return true
	}
	if strings.Contains(lower, "does not create headscale preauth keys") {
		return true
	}
	if strings.Contains(lower, "one-time preauth") {
		return true
	}
	if strings.Contains(lower, "auth_key_file") {
		return true
	}
	if strings.Contains(lower, "auth-key-file") {
		return true
	}
	if strings.Contains(lower, "auth key file") {
		return true
	}
	if strings.Contains(lower, "tailscale") && strings.Contains(lower, "auth key") {
		return true
	}
	if strings.Contains(lower, "single systemd execstart token") {
		return true
	}
	if strings.Contains(lower, "<redacted>") && strings.Contains(lower, "preauth key") {
		return true
	}
	return false
}

func containsRawSecretMarker(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"tskey-auth",
		"hskey-auth",
		"authkey-",
		"mkey:",
		"/login?token=",
		"password=",
		"secret=",
		"token=",
		"authorization:",
		"cookie:",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.HasPrefix(strings.TrimSpace(lower), "bearer ")
}

var (
	acmeChallengeTokenPlaceholderPattern = regexp.MustCompile(`/\.well-known/acme-challenge/<token>`)
	workflowCheckSummaryPattern          = regexp.MustCompile(`\A(?:none|(?:(?:[a-z0-9][a-z0-9_-]*=(?:pass|fail|warn|manual|unknown|not_applicable)|(?:pass|fail|warn|manual|unknown|not_applicable):[a-z0-9][a-z0-9_-]*)(?:, (?:[a-z0-9][a-z0-9_-]*=(?:pass|fail|warn|manual|unknown|not_applicable)|(?:pass|fail|warn|manual|unknown|not_applicable):[a-z0-9][a-z0-9_-]*))*))\z`)
	workflowCheckFieldLabelPattern       = regexp.MustCompile(`\Acheck [a-z0-9][a-z0-9_-]*\z`)
	workflowSensitiveAuthKeyPattern      = regexp.MustCompile(`(?:(?:tskey|hskey|authkey)-|mkey:)[^\s]+`)
)

func redactAuthKeyMarkers(text string) string {
	return workflowSensitiveAuthKeyPattern.ReplaceAllString(text, "<redacted>")
}

func RemoveIfCreated(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
