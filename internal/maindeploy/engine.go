package maindeploy

import (
	"bufio"
	stdcontext "context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"lanpanel/internal/assets"
	"lanpanel/internal/components/headscale"
	"lanpanel/internal/components/nginx"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/host"
	"lanpanel/internal/preflight"
	"lanpanel/internal/render"
	"lanpanel/internal/state"
	"lanpanel/internal/verify"
	"lanpanel/internal/workflow"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	acmecatalog "lanpanel/internal/acme"

	legocomponent "lanpanel/internal/components/lego"

	tlscomponent "lanpanel/internal/components/tls"

	"golang.org/x/net/http/httpproxy"
)

type StagedFileInstaller interface {
	Install(files []render.StagedFile) ([]host.FileInstallResult, error)
}

type HeadscalePackageInstaller interface {
	Install(ctx stdcontext.Context, plan headscale.InstallPlan) ([]host.Result, error)
}

type LegoInstaller interface {
	Install(ctx stdcontext.Context, plan legocomponent.InstallPlan) ([]host.Result, error)
}

type NginxSiteActivator interface {
	EnableTestAndReload(ctx stdcontext.Context) ([]host.Result, error)
}

type HeadscaleOnboarder interface {
	EnsureUser(ctx stdcontext.Context, userName string) ([]host.Result, error)
	CreatePreAuthKey(ctx stdcontext.Context, plan headscale.OnboardingPlan) (string, []host.Result, error)
}

const (
	deployCheckpointPackageManagerReady          = "package-manager-ready"
	deployCheckpointHostDependenciesInstalled    = "host-dependencies-installed"
	deployCheckpointPackageArchitectureConfirmed = "package-architecture-confirmed"
	deployCheckpointLegoInstalled                = "lego-installed"
	deployCheckpointHeadscalePackageInstalled    = "headscale-package-installed"
	deployCheckpointRuntimeAssetsInstalled       = "runtime-assets-installed"
	deployCheckpointTLSBootstrapReady            = "tls-bootstrap-ready"
	deployCheckpointLegoCommandReady             = "lego-command-ready"
	deployCheckpointLegoCommandDeferred          = "lego-command-deferred"
	deployCheckpointCertificateIssued            = "certificate-issued"
	deployCheckpointNginxActivated               = "nginx-site-activated"
	deployCheckpointSystemdDaemonReloaded        = "systemd-daemon-reloaded"
	deployCheckpointSystemdDaemonReloadDeferred  = "systemd-daemon-reload-deferred"
	deployCheckpointServicesEnabled              = "services-enabled"
	deployCheckpointOnboardingReady              = "onboarding-ready"
	deployCheckpointStaticVerifyPassed           = "static-verify-passed"
)

var (
	collectDeployPreflightInputs  = defaultDeployPreflightInputs
	detectPermissionStateFn       = detectPermissionState
	detectPlatformInfoFn          = detectPlatformInfo
	detectHostCapabilityStateFn   = detectHostCapabilityState
	detectDNSProbeFn              = detectDNSProbe
	detectPortBindingsFn          = detectPortBindings
	detectFirewallStateFn         = detectFirewallState
	detectServiceStatesFn         = detectServiceStates
	detectPackageSourceStateFn    = detectPackageSourceState
	detectACMEStateFn             = detectACMEState
	probePackageURLFn             = probePackageURL
	hashRemoteArtifactFn          = hashRemoteArtifact
	lookupOfficialPackageDigestFn = lookupOfficialPackageDigest
	stageRuntimeFilesFn           = render.StageRuntime
	statDNSCredentialsFileFn      = os.Stat
	readDNSCredentialsFileFn      = os.ReadFile
	readDeployManagedHostFileFn   = os.ReadFile
	newDeployFileInstallerFn      = func(executor host.Executor, privilege host.PrivilegeStrategy) StagedFileInstaller {
		if privilege.RequiresSudo() {
			return host.NewFileInstaller(host.NewCommandFileSystem(executor), "")
		}
		return host.NewFileInstaller(nil, "")
	}
	newDeployHostFileSystemFn = func(executor host.Executor, privilege host.PrivilegeStrategy) host.FileSystem {
		if privilege.RequiresSudo() {
			return host.NewCommandFileSystem(executor)
		}
		return host.OSFileSystem{}
	}
	checkpointPathForConfigFn  = defaultCheckpointPath
	checkpointStoreForConfigFn = func(configPath string) state.Store { return state.NewStore(checkpointPathForConfigFn(configPath)) }
	newHostExecutorFn          = func(env map[string]string) host.Executor { return host.NewExecutor(nil, env) }
	newHostSystemdFn           = func(executor host.Executor) host.Systemd { return host.NewSystemd(executor) }
	newHeadscaleInstallerFn    = func(executor host.Executor) HeadscalePackageInstaller { return headscale.NewInstaller(executor) }
	newLegoInstallerFn         = func(executor host.Executor) LegoInstaller { return legocomponent.NewInstaller(executor) }
	newNginxActivatorFn        = func(executor host.Executor) NginxSiteActivator { return nginx.NewActivator(executor) }
	newHeadscaleOnboarderFn    = func(executor host.Executor) HeadscaleOnboarder { return headscale.NewOnboarding(executor) }
	dependencyMu               sync.Mutex
)

var requiredFirewallPorts = []string{"80/tcp", "443/tcp", "3478/udp"}

var knownConflictServices = []string{"headscale", "nginx", "apache2", "caddy", "traefik"}

var (
	ufwStatusColumnSeparator  = regexp.MustCompile(`[[:space:]]{2,}`)
	dnsEnvFileKeyPattern      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	socketProcessTuplePattern = regexp.MustCompile(`\("([^"]*)",pid=([0-9]+)[^)]*\)`)
)

var ufwApplicationProfilePorts = map[string][]string{
	"nginx full":  {"80/tcp", "443/tcp"},
	"nginx http":  {"80/tcp"},
	"nginx https": {"443/tcp"},
}

type Result struct {
	Operation       workflow.OperationResult
	OutputStatus    string
	NextSteps       []string
	PreflightReport *preflight.Report
}

type Dependencies struct {
	CollectDeployPreflightInputs func(config.Config) preflight.Inputs
	DetectPermissionState        func() preflight.PermissionState
	DetectPlatformInfo           func() preflight.PlatformInfo
	DetectHostCapabilityState    func() preflight.HostCapabilityState
	DetectDNSProbe               func(string) preflight.DNSProbe
	DetectPortBindings           func(config.Config) []preflight.PortBinding
	DetectFirewallState          func() preflight.FirewallState
	DetectServiceStates          func() []preflight.ServiceState
	DetectPackageSourceState     func(config.Config) preflight.PackageSourceState
	DetectACMEState              func(config.Config) preflight.ACMEState
	ProbePackageURL              func(*http.Client, string) (bool, bool, string)
	HashRemoteArtifact           func(*http.Client, string) (string, error)
	LookupOfficialPackageDigest  func(*http.Client, string, string) (string, error)
	StageRuntimeFiles            func(config.Config) ([]render.StagedFile, error)
	StatDNSCredentialsFile       func(string) (os.FileInfo, error)
	ReadDNSCredentialsFile       func(string) ([]byte, error)
	ReadDeployManagedHostFile    func(string) ([]byte, error)
	NewDeployFileInstaller       func(host.Executor, host.PrivilegeStrategy) StagedFileInstaller
	NewDeployHostFileSystem      func(host.Executor, host.PrivilegeStrategy) host.FileSystem
	CheckpointPathForConfig      func(string) string
	CheckpointStoreForConfig     func(string) state.Store
	NewHostExecutor              func(map[string]string) host.Executor
	NewHostSystemd               func(host.Executor) host.Systemd
	NewHeadscaleInstaller        func(host.Executor) HeadscalePackageInstaller
	NewLegoInstaller             func(host.Executor) LegoInstaller
	NewNginxActivator            func(host.Executor) NginxSiteActivator
	NewHeadscaleOnboarder        func(host.Executor) HeadscaleOnboarder
}

type Options struct {
	Dependencies Dependencies
}

type deployRunOptions struct {
	configPath string
}

func Run(ctx stdcontext.Context, configPath string, options Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		retryCommand := workflow.ShellCommand("sudo", "lanpanel", "deploy", "--config", configPath)
		return Result{Operation: workflow.OperationResult{
			Kind:         domain.JobKindDeploy,
			Status:       domain.JobStatusInterrupted,
			Summary:      "main deploy canceled before host workflow started",
			RetryCommand: retryCommand,
		}, OutputStatus: "interrupted"}, err
	}
	restore := applyDependencies(options.Dependencies)
	defer restore()

	commandResult, err := runDeployCommandResult(configPath)
	if !commandResult.hasResponse {
		if err != nil {
			return Result{Operation: workflow.OperationResult{
				Kind:         domain.JobKindDeploy,
				Status:       domain.JobStatusFailed,
				Summary:      "deploy returned no typed operation result",
				RetryCommand: deployRetryCommand(configPath),
			}, OutputStatus: "failed"}, err
		}
		return Result{}, fmt.Errorf("deploy returned no typed operation result")
	}
	result := Result{
		Operation:    commandResult.operation,
		OutputStatus: commandResult.outputStatus,
		NextSteps:    append([]string(nil), commandResult.nextSteps...),
	}
	if commandResult.preflightReport != nil {
		report := *commandResult.preflightReport
		result.PreflightReport = &report
	}
	return result, err
}

func applyDependencies(dependencies Dependencies) func() {
	dependencyMu.Lock()
	restore := applyDependenciesLocked(dependencies)
	return func() {
		restore()
		dependencyMu.Unlock()
	}
}

func applyDependenciesForHelper(dependencies Dependencies) func() {
	if !dependencyMu.TryLock() {
		return func() {}
	}
	restore := applyDependenciesLocked(dependencies)
	return func() {
		restore()
		dependencyMu.Unlock()
	}
}

func applyDependenciesLocked(dependencies Dependencies) func() {
	previous := Dependencies{
		CollectDeployPreflightInputs: collectDeployPreflightInputs,
		DetectPermissionState:        detectPermissionStateFn,
		DetectPlatformInfo:           detectPlatformInfoFn,
		DetectHostCapabilityState:    detectHostCapabilityStateFn,
		DetectDNSProbe:               detectDNSProbeFn,
		DetectPortBindings:           detectPortBindingsFn,
		DetectFirewallState:          detectFirewallStateFn,
		DetectServiceStates:          detectServiceStatesFn,
		DetectPackageSourceState:     detectPackageSourceStateFn,
		DetectACMEState:              detectACMEStateFn,
		ProbePackageURL:              probePackageURLFn,
		HashRemoteArtifact:           hashRemoteArtifactFn,
		LookupOfficialPackageDigest:  lookupOfficialPackageDigestFn,
		StageRuntimeFiles:            stageRuntimeFilesFn,
		StatDNSCredentialsFile:       statDNSCredentialsFileFn,
		ReadDNSCredentialsFile:       readDNSCredentialsFileFn,
		ReadDeployManagedHostFile:    readDeployManagedHostFileFn,
		NewDeployFileInstaller:       newDeployFileInstallerFn,
		NewDeployHostFileSystem:      newDeployHostFileSystemFn,
		CheckpointPathForConfig:      checkpointPathForConfigFn,
		CheckpointStoreForConfig:     checkpointStoreForConfigFn,
		NewHostExecutor:              newHostExecutorFn,
		NewHostSystemd:               newHostSystemdFn,
		NewHeadscaleInstaller:        newHeadscaleInstallerFn,
		NewLegoInstaller:             newLegoInstallerFn,
		NewNginxActivator:            newNginxActivatorFn,
		NewHeadscaleOnboarder:        newHeadscaleOnboarderFn,
	}
	if dependencies.CollectDeployPreflightInputs != nil {
		collectDeployPreflightInputs = dependencies.CollectDeployPreflightInputs
	}
	if dependencies.DetectPermissionState != nil {
		detectPermissionStateFn = dependencies.DetectPermissionState
	}
	if dependencies.DetectPlatformInfo != nil {
		detectPlatformInfoFn = dependencies.DetectPlatformInfo
	}
	if dependencies.DetectHostCapabilityState != nil {
		detectHostCapabilityStateFn = dependencies.DetectHostCapabilityState
	}
	if dependencies.DetectDNSProbe != nil {
		detectDNSProbeFn = dependencies.DetectDNSProbe
	}
	if dependencies.DetectPortBindings != nil {
		detectPortBindingsFn = dependencies.DetectPortBindings
	}
	if dependencies.DetectFirewallState != nil {
		detectFirewallStateFn = dependencies.DetectFirewallState
	}
	if dependencies.DetectServiceStates != nil {
		detectServiceStatesFn = dependencies.DetectServiceStates
	}
	if dependencies.DetectPackageSourceState != nil {
		detectPackageSourceStateFn = dependencies.DetectPackageSourceState
	}
	if dependencies.DetectACMEState != nil {
		detectACMEStateFn = dependencies.DetectACMEState
	}
	if dependencies.ProbePackageURL != nil {
		probePackageURLFn = dependencies.ProbePackageURL
	}
	if dependencies.HashRemoteArtifact != nil {
		hashRemoteArtifactFn = dependencies.HashRemoteArtifact
	}
	if dependencies.LookupOfficialPackageDigest != nil {
		lookupOfficialPackageDigestFn = dependencies.LookupOfficialPackageDigest
	}
	if dependencies.StageRuntimeFiles != nil {
		stageRuntimeFilesFn = dependencies.StageRuntimeFiles
	}
	if dependencies.StatDNSCredentialsFile != nil {
		statDNSCredentialsFileFn = dependencies.StatDNSCredentialsFile
	}
	if dependencies.ReadDNSCredentialsFile != nil {
		readDNSCredentialsFileFn = dependencies.ReadDNSCredentialsFile
	}
	if dependencies.ReadDeployManagedHostFile != nil {
		readDeployManagedHostFileFn = dependencies.ReadDeployManagedHostFile
	}
	if dependencies.NewDeployFileInstaller != nil {
		newDeployFileInstallerFn = dependencies.NewDeployFileInstaller
	}
	if dependencies.NewDeployHostFileSystem != nil {
		newDeployHostFileSystemFn = dependencies.NewDeployHostFileSystem
	}
	if dependencies.CheckpointPathForConfig != nil {
		checkpointPathForConfigFn = dependencies.CheckpointPathForConfig
	}
	if dependencies.CheckpointStoreForConfig != nil {
		checkpointStoreForConfigFn = dependencies.CheckpointStoreForConfig
	}
	if dependencies.NewHostExecutor != nil {
		newHostExecutorFn = dependencies.NewHostExecutor
	}
	if dependencies.NewHostSystemd != nil {
		newHostSystemdFn = dependencies.NewHostSystemd
	}
	if dependencies.NewHeadscaleInstaller != nil {
		newHeadscaleInstallerFn = dependencies.NewHeadscaleInstaller
	}
	if dependencies.NewLegoInstaller != nil {
		newLegoInstallerFn = dependencies.NewLegoInstaller
	}
	if dependencies.NewNginxActivator != nil {
		newNginxActivatorFn = dependencies.NewNginxActivator
	}
	if dependencies.NewHeadscaleOnboarder != nil {
		newHeadscaleOnboarderFn = dependencies.NewHeadscaleOnboarder
	}
	return func() {
		collectDeployPreflightInputs = previous.CollectDeployPreflightInputs
		detectPermissionStateFn = previous.DetectPermissionState
		detectPlatformInfoFn = previous.DetectPlatformInfo
		detectHostCapabilityStateFn = previous.DetectHostCapabilityState
		detectDNSProbeFn = previous.DetectDNSProbe
		detectPortBindingsFn = previous.DetectPortBindings
		detectFirewallStateFn = previous.DetectFirewallState
		detectServiceStatesFn = previous.DetectServiceStates
		detectPackageSourceStateFn = previous.DetectPackageSourceState
		detectACMEStateFn = previous.DetectACMEState
		probePackageURLFn = previous.ProbePackageURL
		hashRemoteArtifactFn = previous.HashRemoteArtifact
		lookupOfficialPackageDigestFn = previous.LookupOfficialPackageDigest
		stageRuntimeFilesFn = previous.StageRuntimeFiles
		statDNSCredentialsFileFn = previous.StatDNSCredentialsFile
		readDNSCredentialsFileFn = previous.ReadDNSCredentialsFile
		readDeployManagedHostFileFn = previous.ReadDeployManagedHostFile
		newDeployFileInstallerFn = previous.NewDeployFileInstaller
		newDeployHostFileSystemFn = previous.NewDeployHostFileSystem
		checkpointPathForConfigFn = previous.CheckpointPathForConfig
		checkpointStoreForConfigFn = previous.CheckpointStoreForConfig
		newHostExecutorFn = previous.NewHostExecutor
		newHostSystemdFn = previous.NewHostSystemd
		newHeadscaleInstallerFn = previous.NewHeadscaleInstaller
		newLegoInstallerFn = previous.NewLegoInstaller
		newNginxActivatorFn = previous.NewNginxActivator
		newHeadscaleOnboarderFn = previous.NewHeadscaleOnboarder
	}
}

type deployCommandResult struct {
	operation       workflow.OperationResult
	outputStatus    string
	nextSteps       []string
	preflightReport *preflight.Report
	hasResponse     bool
}

func deployOperationCommandResult(outputStatus string, result workflow.OperationResult, nextSteps []string) deployCommandResult {
	return deployCommandResult{
		operation:    result,
		outputStatus: strings.TrimSpace(outputStatus),
		nextSteps:    append([]string(nil), nextSteps...),
		hasResponse:  true,
	}
}

func deployFailureCommandResult(failure workflow.Failure) deployCommandResult {
	snapshot := failure.Snapshot()
	return deployOperationCommandResult("failed", deployFailureOperationResult(snapshot, failure.RetryCommand), snapshot.NextSteps())
}

func deployFailureOperationResult(snapshot workflow.FailureSnapshot, retryCommand string) workflow.OperationResult {
	summary := snapshot.SummaryText()
	return workflow.OperationResult{
		Kind:         domain.JobKindDeploy,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       snapshot.ResultFields(),
		Diagnostics:  []domain.DiagnosticItem{deployDiagnosticItem("failed", domain.DiagnosticStatusFail, summary)},
		RetryCommand: retryCommand,
		Progress:     operationProgressEvents(domain.JobKindDeploy, "main deploy host workflow started", domain.DiagnosticStatusFail, "main deploy host workflow failed"),
	}
}

func deployDiagnosticItem(outputStatus string, status domain.DiagnosticStatus, summary string) domain.DiagnosticItem {
	return domain.DiagnosticItem{
		ID:               "deploy:" + strings.NewReplacer(" ", "-", "_", "-").Replace(strings.TrimSpace(outputStatus)),
		Title:            "deploy",
		Status:           status,
		Scope:            domain.DiagnosticScopeInstance,
		Severity:         deployDiagnosticSeverity(status),
		Summary:          strings.TrimSpace(summary),
		EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
		ResponsibleParty: domain.DiagnosticResponsibleLanPanel,
		BlocksActivation: status == domain.DiagnosticStatusFail,
		Redaction:        domain.RedactionNone,
		RedactionStatus:  domain.RedactionStatusNoSensitiveData,
	}
}

func deployDiagnosticSeverity(status domain.DiagnosticStatus) domain.DiagnosticSeverity {
	switch status {
	case domain.DiagnosticStatusFail:
		return domain.DiagnosticSeverityCritical
	case domain.DiagnosticStatusWarn, domain.DiagnosticStatusManual, domain.DiagnosticStatusUnknown:
		return domain.DiagnosticSeverityMedium
	default:
		return domain.DiagnosticSeverityInfo
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

func runDeployCommandResult(configPath string) (deployCommandResult, error) {
	options := deployRunOptions{configPath: configPath}
	checkpointPath := checkpointPathForConfigFn(options.configPath)
	checkpointStore := checkpointStoreForConfigFn(options.configPath)

	if _, err := os.Stat(options.configPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return deployOperationCommandResult("missing-config", workflow.OperationResult{
				Kind:    domain.JobKindDeploy,
				Status:  domain.JobStatusFailed,
				Summary: "no config file found",
				Fields: []domain.ResultField{
					{Label: "config path", Value: options.configPath},
					{Label: "happy path", Value: "init -> deploy -> verify"},
				},
				RetryCommand: deployRetryCommand(options.configPath),
			}, []string{
				fmt.Sprintf("Create the configuration for %s from the Management UI.", options.configPath),
			}), nil
		}
		return deployCommandResult{}, fmt.Errorf("stat config file: %w", err)
	}

	cfg, err := config.LoadFile(options.configPath)
	if err != nil {
		return deployOperationCommandResult("invalid-config", workflow.OperationResult{
			Kind:    domain.JobKindDeploy,
			Status:  domain.JobStatusFailed,
			Summary: "config file exists but failed validation",
			Fields: []domain.ResultField{
				{Label: "config path", Value: options.configPath},
				{Label: "details", Value: err.Error()},
			},
			RetryCommand: deployRetryCommand(options.configPath),
		}, []string{
			fmt.Sprintf("Fix the configuration at %s and retry from the Management UI.", options.configPath),
		}), nil
	}

	checkpoint, err := checkpointStore.Load()
	if err != nil {
		result, failure := checkpointLoadFailureResult("deploy", options.configPath, checkpointPath, err, nil)
		return result, failure
	}

	desiredStateDigest, err := deployDesiredStateDigest(cfg)
	if err != nil {
		return deployFailureWithCheckpointSave(checkpointStore, checkpoint, desiredStateDigestFailure("deploy", options.configPath, err))
	}
	preflightInputs := collectDeployPreflightInputs(cfg)
	preflightInputs.Managed = deployManagedServiceState(checkpoint, desiredStateDigest)
	preflightInputs.Managed = mergeManagedServiceState(preflightInputs.Managed, detectDeployManagedServiceStateFromHost())

	privilege := deployPrivilegeStrategy(preflightInputs.Permissions)
	executor := newHostExecutorFn(deployProxyEnv(cfg))
	privilegedExecutor := executor.WithPrivilege(privilege)
	systemd := newHostSystemdFn(privilegedExecutor)
	var results []host.FileInstallResult
	var stagedFiles []render.StagedFile
	runtimeFileSystem := newDeployHostFileSystemFn(privilegedExecutor, privilege)
	if result, err, failed := restorePendingDeployCheckpointSnapshots(stdcontext.Background(), checkpointStore, &checkpoint, privilegedExecutor, runtimeFileSystem, options.configPath); failed {
		return result, err
	}
	checkpoint.BeginDeploy(desiredStateDigest)
	report := preflight.BuildReport(cfg, preflightInputs)
	if report.FailedCount() > 0 || report.ManualCount() > 0 {
		checkpoint.RecordFailure(workflow.Failure{
			Step:         "preflight",
			Operation:    report.Summary(),
			Impact:       "deploy cannot continue until the blocking preflight items are resolved",
			Remediation:  report.NextSteps(),
			RetryCommand: deployRetryCommand(options.configPath),
		}.Snapshot())
		if err := checkpointStore.Save(checkpoint); err != nil {
			return deployCommandResult{}, fmt.Errorf("save checkpoint: %w", err)
		}
		result := deployOperationCommandResult(string(report.OverallStatus()), deployPreflightOperationResult(report, options.configPath), report.NextSteps())
		result.preflightReport = &report
		return result, workflow.Failure{Step: "preflight", Operation: report.Summary()}
	}
	runtimeFileSnapshots, err := deployRuntimeFileSnapshotsFromCheckpoint(checkpoint.RuntimeFileSnapshots)
	if err != nil {
		return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
			Step:         "load runtime rollback snapshot",
			Operation:    "reading the persisted runtime file rollback snapshot",
			Impact:       "deploy cannot safely continue to Nginx activation until recovery state is valid",
			Remediation:  []string{"Inspect the checkpoint file and rerun deploy after removing malformed runtime_file_snapshots."},
			RetryCommand: deployRetryCommand(options.configPath),
			Cause:        err,
		})
	}
	headscaleRestarted := false
	if !deployPhaseCompleted(checkpoint, deployCheckpointPackageManagerReady) {
		if _, err := executor.AptGet(stdcontext.Background(), "--version"); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "check package manager",
				Operation:    "running apt-get --version to confirm host package manager access",
				Impact:       "package-backed host changes cannot continue until apt-get is available",
				Remediation:  []string{"Confirm apt-get is installed and reachable in PATH, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointPackageManagerReady, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointPackageArchitectureConfirmed) {
		packageArchResult, err := executor.Dpkg(stdcontext.Background(), "--print-architecture")
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "confirm package architecture",
				Operation:    "collecting host package architecture via dpkg",
				Impact:       "lanpanel cannot choose the right package inputs until dpkg reports host architecture",
				Remediation:  []string{"Confirm dpkg is installed and reachable in PATH, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		expectedArch := packageArch(cfg)
		if detectedArch := strings.TrimSpace(packageArchResult.Stdout); detectedArch != "" && detectedArch != expectedArch {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:      "confirm package architecture",
				Operation: fmt.Sprintf("matching dpkg architecture %q to config target %q", detectedArch, expectedArch),
				Impact:    "lanpanel cannot safely continue until package architecture matches the target host",
				Remediation: []string{
					fmt.Sprintf("Update advanced.platform.arch to %s or rerun deploy on a matching host.", detectedArch),
				},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        fmt.Errorf("dpkg reported %s while config expects %s", detectedArch, expectedArch),
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointPackageArchitectureConfirmed, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointHostDependenciesInstalled) {
		dependencyPackages, err := deployHostDependencyPackages(cfg)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "plan host dependencies",
				Operation:    "selecting Nginx and archive installation helper packages",
				Impact:       "lanpanel cannot install HTTPS ingress and pinned release artifacts until host dependencies are known",
				Remediation:  []string{"Use a supported platform architecture or switch Headscale source settings, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if _, err := privilegedExecutor.AptGet(stdcontext.Background(), "update"); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "install host dependencies",
				Operation:    "refreshing package metadata before installing Nginx and artifact helper packages",
				Impact:       "lanpanel cannot install the reverse proxy and pinned release artifacts until package metadata refresh succeeds",
				Remediation:  []string{"Fix apt repository access, proxy settings, or package locks, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		installArgs := append([]string{"install", "-y"}, dependencyPackages...)
		if _, err := privilegedExecutor.AptGet(stdcontext.Background(), installArgs...); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "install host dependencies",
				Operation:    "installing Nginx and artifact helper packages through apt-get",
				Impact:       "lanpanel cannot configure HTTPS ingress or install pinned release artifacts until host dependencies are installed",
				Remediation:  []string{"Fix apt repository access or install the listed dependency packages manually, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointHostDependenciesInstalled, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointLegoInstalled) {
		installPlan, err := legocomponent.NewInstallPlan(cfg, legocomponent.InstallPlanOptions{
			ReachabilityTimeout: cfg.Advanced.PackageProbe.EffectiveReachabilityTimeout(),
			ArtifactTimeout:     cfg.Advanced.PackageProbe.EffectiveArtifactTimeout(),
		})
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "plan lego install",
				Operation:    fmt.Sprintf("selecting the pinned lego %s Linux archive source and SHA-256 digest", legocomponent.Version),
				Impact:       "lanpanel cannot continue certificate automation until the lego release artifact is fully pinned",
				Remediation:  []string{"Use advanced.platform.arch amd64 or arm64, fix advanced.lego_source settings, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if _, err := newLegoInstallerFn(privilegedExecutor).Install(stdcontext.Background(), installPlan); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "install lego binary",
				Operation:    fmt.Sprintf("verifying and installing the pinned lego %s archive to /opt/lanpanel/bin/lego", legocomponent.Version),
				Impact:       "lanpanel cannot continue ACME automation until the pinned lego binary is installed",
				Remediation:  []string{"Fix GitHub release reachability, proxy settings, advanced.lego_source.file_path, archive permissions, or digest mismatches, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointLegoInstalled, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointHeadscalePackageInstalled) {
		installPlan, err := headscale.NewInstallPlan(cfg, headscale.InstallPlanOptions{
			VerifiedPackageSHA256: strings.TrimSpace(preflightInputs.PackageSource.ExpectedSHA256),
			ReachabilityTimeout:   cfg.Advanced.PackageProbe.EffectiveReachabilityTimeout(),
			ArtifactTimeout:       cfg.Advanced.PackageProbe.EffectiveArtifactTimeout(),
		})
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "plan Headscale package install",
				Operation:    fmt.Sprintf("building the verified Headscale v%s package install plan", headscale.Version),
				Impact:       "lanpanel cannot install Headscale until Headscale source metadata is complete",
				Remediation:  []string{"Fix advanced.headscale_source settings or rerun preflight with reachable package metadata."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if _, err := newHeadscaleInstallerFn(privilegedExecutor).Install(stdcontext.Background(), installPlan); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "install Headscale package",
				Operation:    fmt.Sprintf("installing the verified Headscale v%s .deb package", headscale.Version),
				Impact:       "lanpanel cannot continue to service configuration until Headscale installs successfully",
				Remediation:  []string{"Fix package download, checksum, or apt installation errors, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointHeadscalePackageInstalled, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointRuntimeAssetsInstalled) {
		var err error
		stagedFiles, err = stageDeployFiles(cfg)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "render runtime assets",
				Operation:    "building the current runtime asset set",
				Impact:       "deploy cannot continue until the runtime templates render cleanly",
				Remediation:  []string{"Fix the config values or runtime templates and rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}

		runtimeFileSnapshots, err = snapshotDeployRuntimeFiles(runtimeFileSystem, stagedFiles)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "snapshot runtime assets",
				Operation:    "capturing existing runtime files before host writes",
				Impact:       "deploy cannot safely apply runtime assets until existing files can be restored on activation failure",
				Remediation:  []string{"Inspect the reported runtime path and replace unsupported symlinks or non-regular files, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		checkpoint.SetRuntimeFileSnapshots(stateRuntimeFileSnapshots(runtimeFileSnapshots))
		if err := checkpointStore.Save(checkpoint); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "persist runtime rollback snapshot",
				Operation:    "saving existing runtime file contents before host writes",
				Impact:       "deploy cannot safely apply runtime assets until rollback state is durable",
				Remediation:  []string{"Ensure the checkpoint directory is writable and rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}

		results, err = newDeployFileInstallerFn(privilegedExecutor, privilege).Install(stagedFiles)
		modifiedPaths := host.CollectModifiedPaths(results)
		checkpoint.RecordModifiedPaths(modifiedPaths...)
		checkpoint.RecordActivations(host.CollectActivations(results)...)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "install runtime assets",
				Operation:    "writing runtime files to host paths",
				Impact:       "deploy may be partially applied until the blocking host error is resolved",
				Remediation:  []string{"Inspect the persisted checkpoint, correct the host filesystem issue, and rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}

		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointRuntimeAssetsInstalled, options.configPath); err != nil {
			return result, err
		}
	}

	if cfg.Default.ACMEChallenge == config.ACMEChallengeHTTP01 && !deployPhaseCompleted(checkpoint, deployCheckpointTLSBootstrapReady) {
		certificatePlan, err := tlscomponent.NewCertificatePlan(cfg)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "plan HTTP-01 bootstrap",
				Operation:    "building the temporary certificate and webroot preparation commands",
				Impact:       "lanpanel cannot prepare Nginx for first HTTP-01 issuance until TLS inputs are valid",
				Remediation:  []string{"Fix default.server_url, default.certificate_email, or ACME settings, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		for _, command := range tlscomponent.HTTP01BootstrapCommands(certificatePlan.ServerName) {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), command); err != nil {
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "prepare HTTP-01 bootstrap",
					Operation:    "creating the ACME webroot and temporary certificate for initial Nginx activation",
					Impact:       "lanpanel cannot serve HTTP-01 challenges through Nginx until bootstrap files are ready",
					Remediation:  []string{"Fix filesystem permissions or openssl availability, then rerun deploy."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			}
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointTLSBootstrapReady, options.configPath); err != nil {
			return result, err
		}
	}

	if cfg.Default.ACMEChallenge == config.ACMEChallengeHTTP01 && deployPhaseCompleted(checkpoint, deployCheckpointTLSBootstrapReady) && !deployPhaseCompleted(checkpoint, deployCheckpointNginxActivated) {
		if result, err, failed := requireDeployRuntimeRollbackSnapshot(checkpointStore, checkpoint, options.configPath, runtimeFileSnapshots); failed {
			return result, err
		}
		if _, err := newNginxActivatorFn(privilegedExecutor).EnableTestAndReload(stdcontext.Background()); err != nil {
			restored, cause := rollbackDeployRuntimeFilesAfterNginxFailure(stdcontext.Background(), privilegedExecutor, runtimeFileSystem, runtimeFileSnapshots, err)
			if restored {
				removeDeployCheckpoint(&checkpoint, deployCheckpointRuntimeAssetsInstalled)
				checkpoint.ClearRuntimeFileSnapshots()
			}
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "activate Nginx site",
				Operation:    "enabling the Headscale Nginx site, testing config, and reloading Nginx",
				Impact:       "lanpanel cannot expose the HTTP-01 webroot, HTTPS control plane, or DERP WebSocket endpoint until Nginx accepts the site",
				Remediation:  []string{"Fix the Nginx config test output, conflicting default_server sites, certificate paths, or service reload issue, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        cause,
			})
		}
		checkpoint.ClearRuntimeFileSnapshots()
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointNginxActivated, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointLegoCommandReady) {
		legoResult, err := executor.Run(stdcontext.Background(), host.Command{Name: legocomponent.BinaryPath, Args: []string{"--version"}})
		if err != nil {
			if host.CommandMissing(legoResult, err, legocomponent.BinaryPath, "lego") {
				if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointLegoCommandDeferred, options.configPath); err != nil {
					return result, err
				}
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "check lego command",
					Operation:    "running /opt/lanpanel/bin/lego --version to confirm certificate tooling reachability",
					Impact:       "lanpanel cannot issue the public TLS certificate, activate the final HTTPS site, or complete deploy until lego is available",
					Remediation:  []string{"Rerun deploy so lanpanel can reinstall the pinned lego binary, or fix /opt/lanpanel/bin/lego permissions."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			} else {
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "check lego command",
					Operation:    "running /opt/lanpanel/bin/lego --version to confirm certificate tooling reachability",
					Impact:       "certificate-related host changes cannot continue until lego commands succeed",
					Remediation:  []string{"Rerun deploy so lanpanel can reinstall the pinned lego binary, or fix /opt/lanpanel/bin/lego permissions."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			}
		} else {
			removeDeployCheckpoint(&checkpoint, deployCheckpointLegoCommandDeferred)
			if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointLegoCommandReady, options.configPath); err != nil {
				return result, err
			}
		}
	}

	if deployPhaseCompleted(checkpoint, deployCheckpointLegoCommandReady) && !deployPhaseCompleted(checkpoint, deployCheckpointCertificateIssued) {
		certificatePlan, err := tlscomponent.NewCertificatePlan(cfg)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "plan certificate issuance",
				Operation:    "building the lego command for the configured ACME challenge",
				Impact:       "lanpanel cannot request the public TLS certificate until ACME inputs are valid",
				Remediation:  []string{"Fix default.acme_challenge, default.certificate_email, or DNS-01 provider settings, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if _, err := privilegedExecutor.Run(stdcontext.Background(), legocomponent.MigrationGateCommand(tlscomponent.LegoDataPath)); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "migrate lego storage",
				Operation:    "running the guarded lego v5 storage migration before certificate issuance",
				Impact:       "lanpanel cannot run lego v5 against existing certificate data until storage migration succeeds",
				Remediation:  []string{"Inspect the lego data path, restore from the preserved backup if needed, fix permissions or unsupported legacy storage, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if cfg.Default.ACMEChallenge == config.ACMEChallengeHTTP01 {
			_, err := privilegedExecutor.Run(stdcontext.Background(), http01ChallengeRouteCommand(certificatePlan.ServerName, certificatePlan.Challenge.Webroot))
			if err != nil {
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:      "verify HTTP-01 routing",
					Operation: "checking that lanpanel-managed Nginx serves the ACME webroot for the Headscale hostname",
					Impact:    "lego cannot complete HTTP-01 certificate issuance until Nginx serves challenge tokens for the public hostname",
					Remediation: []string{
						"Inspect /etc/nginx/sites-available/headscale.conf and run 'nginx -t' to confirm the ACME location is active.",
						fmt.Sprintf("Confirm local HTTP-01 routing with: curl --noproxy '*' --resolve %s:80:127.0.0.1 http://%s/.well-known/acme-challenge/<token>", certificatePlan.ServerName, certificatePlan.ServerName),
					},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			}
		}
		_, err = privilegedExecutor.Run(stdcontext.Background(), certificatePlan.Command)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "issue certificate",
				Operation:    "running lego for the Headscale public hostname",
				Impact:       "lanpanel cannot activate the HTTPS Nginx site until a fullchain certificate is available",
				Remediation:  certificateIssueRemediations(cfg.Default.ACMEChallenge, certificatePlan.ServerName),
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointCertificateIssued, options.configPath); err != nil {
			return result, err
		}
	}

	if cfg.Default.ACMEChallenge != config.ACMEChallengeHTTP01 && deployPhaseCompleted(checkpoint, deployCheckpointCertificateIssued) && !deployPhaseCompleted(checkpoint, deployCheckpointNginxActivated) {
		if result, err, failed := requireDeployRuntimeRollbackSnapshot(checkpointStore, checkpoint, options.configPath, runtimeFileSnapshots); failed {
			return result, err
		}
		if _, err := newNginxActivatorFn(privilegedExecutor).EnableTestAndReload(stdcontext.Background()); err != nil {
			restored, cause := rollbackDeployRuntimeFilesAfterNginxFailure(stdcontext.Background(), privilegedExecutor, runtimeFileSystem, runtimeFileSnapshots, err)
			if restored {
				removeDeployCheckpoint(&checkpoint, deployCheckpointRuntimeAssetsInstalled)
				checkpoint.ClearRuntimeFileSnapshots()
			}
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "activate Nginx site",
				Operation:    "enabling the Headscale Nginx site, testing config, and reloading Nginx",
				Impact:       "lanpanel cannot expose the HTTPS control plane or DERP WebSocket endpoint until Nginx accepts the site",
				Remediation:  []string{"Fix the Nginx config test output, conflicting default_server sites, certificate paths, or service reload issue, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        cause,
			})
		}
		checkpoint.ClearRuntimeFileSnapshots()
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointNginxActivated, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointSystemdDaemonReloaded) {
		systemdResult, err := systemd.DaemonReload(stdcontext.Background())
		if err != nil {
			if systemdCommandDeferred(systemdResult, err) {
				if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointSystemdDaemonReloadDeferred, options.configPath); err != nil {
					return result, err
				}
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "reload systemd",
					Operation:    "running systemctl daemon-reload to confirm service manager reachability",
					Impact:       "lanpanel cannot enable services, start the renewal timer, or prepare onboarding until systemd is available",
					Remediation:  []string{"Run deploy on a booted systemd host, or fix systemctl bus access, then rerun deploy."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			} else {
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "reload systemd",
					Operation:    "running systemctl daemon-reload to confirm service manager reachability",
					Impact:       "service-backed host changes cannot continue until systemctl accepts deploy commands",
					Remediation:  []string{"Confirm the host is running systemd and that deploy has permission to talk to it, then rerun deploy."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			}
		} else {
			removeDeployCheckpoint(&checkpoint, deployCheckpointSystemdDaemonReloadDeferred)
			if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointSystemdDaemonReloaded, options.configPath); err != nil {
				return result, err
			}
		}
	}

	if deployPhaseCompleted(checkpoint, deployCheckpointSystemdDaemonReloaded) &&
		deployPhaseCompleted(checkpoint, deployCheckpointCertificateIssued) &&
		deployPhaseCompleted(checkpoint, deployCheckpointNginxActivated) &&
		!deployPhaseCompleted(checkpoint, deployCheckpointServicesEnabled) {
		serviceUnits := []string{headscale.ServiceName, "nginx.service", tlscomponent.RenewTimer}
		serviceSystemdSnapshots, err := snapshotDeploySystemdUnits(stdcontext.Background(), privilegedExecutor, serviceUnits)
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "snapshot service systemd state",
				Operation:    "recording exact pre-mutation systemd state for Headscale, Nginx, and the renewal timer",
				Impact:       "lanpanel cannot safely mutate service state without a precise rollback point",
				Remediation:  []string{"Inspect the reported systemd unit state, make it enabled or disabled and active or inactive, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		checkpoint.SetSystemdUnitSnapshots(stateDeploySystemdUnitSnapshots(serviceSystemdSnapshots))
		if err := checkpointStore.Save(checkpoint); err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "persist service systemd rollback snapshot",
				Operation:    "saving pre-mutation systemd state for Headscale, Nginx, and the renewal timer",
				Impact:       "lanpanel cannot safely mutate service state until rollback state is durable",
				Remediation:  []string{"Ensure the checkpoint directory is writable and rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		serviceSystemdMutated := map[string]bool{}
		failAfterServiceMutation := func(failure workflow.Failure) (deployCommandResult, error) {
			if rollbackErr := restoreDeploySystemdUnits(stdcontext.Background(), privilegedExecutor, serviceSystemdSnapshots, serviceSystemdMutated); rollbackErr != nil {
				failure.Cause = fmt.Errorf("%w; rollback service systemd state failed: %v", failure.Cause, rollbackErr)
			} else {
				checkpoint.SetSystemdUnitSnapshots(nil)
			}
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, failure)
		}
		for _, unit := range serviceUnits {
			serviceSystemdMutated[unit] = true
		}
		if _, err := systemd.Enable(stdcontext.Background(), headscale.ServiceName, "nginx.service", tlscomponent.RenewTimer); err != nil {
			return failAfterServiceMutation(workflow.Failure{
				Step:         "enable services",
				Operation:    "enabling Headscale, Nginx, and lanpanel lego renewal systemd units",
				Impact:       "services or certificate renewals may not restart after reboot until systemd enablement succeeds",
				Remediation:  []string{"Fix systemd access or unit availability, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		serviceSystemdMutated[tlscomponent.RenewTimer] = true
		if _, err := systemd.Start(stdcontext.Background(), tlscomponent.RenewTimer); err != nil {
			return failAfterServiceMutation(workflow.Failure{
				Step:         "start renewal timer",
				Operation:    "starting the lanpanel lego renewal timer",
				Impact:       "certificate renewal will not run automatically until the timer starts",
				Remediation:  []string{"Inspect 'systemctl status lanpanel-lego-renew.timer', fix the timer unit, and rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		serviceSystemdMutated[headscale.ServiceName] = true
		if _, err := systemd.Restart(stdcontext.Background(), headscale.ServiceName); err != nil {
			return failAfterServiceMutation(workflow.Failure{
				Step:         "restart Headscale",
				Operation:    "restarting the Headscale systemd unit after runtime asset installation",
				Impact:       "clients cannot register or reconnect until Headscale starts with the rendered config",
				Remediation:  []string{"Inspect 'systemctl status headscale.service', fix the reported config or runtime error, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		headscaleRestarted = true
		checkpoint.SetSystemdUnitSnapshots(nil)
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointServicesEnabled, options.configPath); err != nil {
			return result, err
		}
	}

	if deployPhaseCompleted(checkpoint, deployCheckpointServicesEnabled) && !deployPhaseCompleted(checkpoint, deployCheckpointOnboardingReady) {
		if !headscaleRestarted {
			headscaleSnapshot, err := snapshotDeploySystemdUnits(stdcontext.Background(), privilegedExecutor, []string{headscale.ServiceName})
			if err != nil {
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "snapshot Headscale systemd state",
					Operation:    "recording exact pre-restart systemd state for Headscale before onboarding",
					Impact:       "lanpanel cannot safely restart Headscale without a precise rollback point",
					Remediation:  []string{"Inspect headscale.service state, make it enabled or disabled and active or inactive, then rerun deploy."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			}
			if _, err := systemd.Restart(stdcontext.Background(), headscale.ServiceName); err != nil {
				if rollbackErr := restoreDeploySystemdUnits(stdcontext.Background(), privilegedExecutor, headscaleSnapshot, map[string]bool{headscale.ServiceName: true}); rollbackErr != nil {
					err = fmt.Errorf("%w; rollback Headscale systemd state failed: %v", err, rollbackErr)
				}
				removeDeployCheckpoint(&checkpoint, deployCheckpointServicesEnabled)
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "restart Headscale",
					Operation:    "restarting the Headscale systemd unit before resumed onboarding",
					Impact:       "clients cannot register or reconnect until Headscale starts with the rendered config",
					Remediation:  []string{"Inspect 'systemctl status headscale.service --no-pager --full' and 'journalctl -u headscale.service -n 100 --no-pager', fix the reported config or runtime error, and rerun deploy."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			}
		}
		onboardingPlan, err := headscale.NewOnboardingPlan(headscale.OnboardingOptions{})
		if err != nil {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "plan onboarding",
				Operation:    "building the local unix-socket onboarding plan",
				Impact:       "lanpanel cannot prepare the first onboarding user until onboarding inputs are valid",
				Remediation:  []string{"Fix onboarding defaults or create the first user manually with headscale, then rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		_, err = newHeadscaleOnboarderFn(privilegedExecutor).EnsureUser(stdcontext.Background(), onboardingPlan.UserName)
		if err != nil {
			removeDeployCheckpoint(&checkpoint, deployCheckpointServicesEnabled)
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "prepare onboarding user",
				Operation:    "creating or verifying the first Headscale user through local CLI management",
				Impact:       "server deployment may be complete, but preauth key handoff cannot run until the onboarding user exists",
				Remediation:  []string{"Inspect 'systemctl status headscale.service --no-pager --full' and 'journalctl -u headscale.service -n 100 --no-pager', fix Headscale service health, and rerun deploy."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointOnboardingReady, options.configPath); err != nil {
			return result, err
		}
	}

	if !deployPhaseCompleted(checkpoint, deployCheckpointStaticVerifyPassed) {
		if missing := missingRequiredDeployCheckpoints(checkpoint,
			deployCheckpointCertificateIssued,
			deployCheckpointNginxActivated,
			deployCheckpointSystemdDaemonReloaded,
			deployCheckpointServicesEnabled,
			deployCheckpointOnboardingReady,
		); len(missing) > 0 {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "complete deploy prerequisites",
				Operation:    "checking required deploy checkpoints before static verification",
				Impact:       "lanpanel cannot call the deployment ready until certificate issuance, Nginx activation, renewal scheduling, services, and onboarding complete",
				Remediation:  []string{"Rerun deploy after fixing the earlier deferred or failed host step."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        fmt.Errorf("missing required checkpoints: %s", strings.Join(missing, ", ")),
			})
		}
		if stagedFiles == nil {
			var err error
			stagedFiles, err = stageDeployFiles(cfg)
			if err != nil {
				return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
					Step:         "render runtime assets for verification",
					Operation:    "building the runtime asset set for static verification",
					Impact:       "lanpanel cannot verify runtime readiness until templates render cleanly",
					Remediation:  []string{"Fix the config values or runtime templates and rerun deploy."},
					RetryCommand: deployRetryCommand(options.configPath),
					Cause:        err,
				})
			}
		}
		verifyReport := verify.StaticReport(cfg, stagedFiles)
		if verifyReport.FailedCount() > 0 {
			return deployFailureWithCheckpointSave(checkpointStore, checkpoint, workflow.Failure{
				Step:         "verify runtime assets",
				Operation:    verifyReport.Summary(),
				Impact:       "lanpanel cannot call the deployment ready until static runtime checks pass",
				Remediation:  []string{"Inspect failed checks in the Management UI, fix the configuration or templates, and retry."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        fmt.Errorf("%s", verify.SummarizeChecks(verifyReport.Checks)),
			})
		}
		if result, err := recordDeployCheckpointResult(checkpointStore, &checkpoint, deployCheckpointStaticVerifyPassed, options.configPath); err != nil {
			return result, err
		}
	}

	if checkpoint.FinalizeSuccessfulDeploy() {
		if err := checkpointStore.Save(checkpoint); err != nil {
			return deployFailureWithoutCheckpointSave(workflow.Failure{
				Step:         "finalize deploy checkpoint",
				Operation:    "retiring resumable deploy state after successful host changes",
				Impact:       "future deploy runs may continue using stale resume history until checkpoint persistence succeeds",
				Remediation:  []string{"Ensure the checkpoint directory is writable and rerun deploy so lanpanel can retire the stale resume state."},
				RetryCommand: deployRetryCommand(options.configPath),
				Cause:        err,
			})
		}
	}

	modifiedPaths := append([]string(nil), checkpoint.ModifiedPaths...)
	activations := append([]assets.Activation(nil), checkpoint.ActivationHistory...)
	summary := "preflight passed, server components were installed, runtime assets were applied, and verification checks passed"
	if len(host.CollectModifiedPaths(results)) == 0 {
		summary = "preflight passed; runtime assets already match the desired state and verification checks passed"
	}
	warnings := deferredCheckpointWarnings(checkpoint.CompletedCheckpoints)

	fields := append(configFields(options.configPath, cfg),
		domain.ResultField{Label: "checkpoint path", Value: checkpointPath},
		domain.ResultField{Label: "modified paths", Value: summarizeModifiedPaths(modifiedPaths)},
		domain.ResultField{Label: "activation history", Value: joinActivations(activations)},
	)
	if len(checkpoint.CompletedCheckpoints) > 0 {
		fields = append(fields, domain.ResultField{Label: "completed checkpoints", Value: strings.Join(checkpoint.CompletedCheckpoints, ", ")})
	}
	if len(warnings) > 0 {
		fields = append(fields, domain.ResultField{Label: "warnings", Value: strings.Join(warnings, "; ")})
	}
	return deployOperationCommandResult("applied", workflow.OperationResult{
		Kind:          domain.JobKindDeploy,
		Status:        domain.JobStatusSucceeded,
		Summary:       summary,
		Fields:        fields,
		ModifiedPaths: modifiedPaths,
		RetryCommand:  deployRetryCommand(options.configPath),
		Progress:      operationProgressEvents(domain.JobKindDeploy, "main deploy host workflow started", domain.DiagnosticStatusPass, "main deploy host workflow finished"),
	}, []string{
		fmt.Sprintf("Inspect persisted context for %s in the Management UI.", options.configPath),
		fmt.Sprintf("Re-run runtime and onboarding readiness checks for %s in the Management UI.", options.configPath),
		"Open the Management UI through its authenticated access path and use Headscale onboarding to create a short-lived one-time preauth key handoff.",
	}), nil
}

func deployPreflightOperationResult(report preflight.Report, configPath string) workflow.OperationResult {
	fields := []domain.ResultField{
		{Label: "config path", Value: configPath},
		{Label: "preflight status", Value: string(report.OverallStatus())},
		{Label: "failed checks", Value: strconv.Itoa(report.FailedCount())},
		{Label: "manual checks", Value: strconv.Itoa(report.ManualCount())},
		{Label: "warning checks", Value: strconv.Itoa(report.WarningCount())},
	}
	return workflow.OperationResult{
		Kind:         domain.JobKindDeploy,
		Status:       domain.JobStatusFailed,
		Summary:      report.Summary(),
		Fields:       fields,
		Diagnostics:  deployPreflightDiagnostics(report),
		RetryCommand: deployRetryCommand(configPath),
		Progress:     operationProgressEvents(domain.JobKindDeploy, "main deploy preflight evaluated", diagnosticStatusForPreflight(report.OverallStatus()), "main deploy preflight blocked host workflow"),
	}
}

func deployPreflightDiagnostics(report preflight.Report) []domain.DiagnosticItem {
	diagnostics := make([]domain.DiagnosticItem, 0, len(report.Checks))
	for _, check := range report.Checks {
		diagnostics = append(diagnostics, domain.DiagnosticItem{
			ID:               "preflight-" + strings.TrimSpace(check.ID),
			Title:            check.Title,
			Status:           diagnosticStatusForPreflight(check.Status),
			Scope:            domain.DiagnosticScopeInstance,
			Severity:         diagnosticSeverityForPreflight(check.Severity),
			Summary:          check.Summary,
			EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
			ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
			BlocksActivation: check.Status == preflight.StatusFail || check.Status == preflight.StatusManual,
			Remediation:      append([]string(nil), check.Remediations...),
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		})
	}
	return diagnostics
}

func configFields(path string, cfg config.Config) []domain.ResultField {
	return []domain.ResultField{
		{Label: "config path", Value: path},
		{Label: "server url", Value: cfg.Default.ServerURL},
		{Label: "base domain", Value: cfg.Default.BaseDomain},
		{Label: "acme challenge", Value: cfg.Default.ACMEChallenge},
	}
}

func diagnosticStatusForPreflight(status preflight.Status) domain.DiagnosticStatus {
	switch status {
	case preflight.StatusPass:
		return domain.DiagnosticStatusPass
	case preflight.StatusWarn:
		return domain.DiagnosticStatusWarn
	case preflight.StatusManual:
		return domain.DiagnosticStatusManual
	case preflight.StatusFail:
		return domain.DiagnosticStatusFail
	default:
		return domain.DiagnosticStatusUnknown
	}
}

func diagnosticSeverityForPreflight(severity preflight.Severity) domain.DiagnosticSeverity {
	switch severity {
	case preflight.SeverityInfo:
		return domain.DiagnosticSeverityInfo
	case preflight.SeverityWarning:
		return domain.DiagnosticSeverityMedium
	case preflight.SeverityManual:
		return domain.DiagnosticSeverityHigh
	case preflight.SeverityError:
		return domain.DiagnosticSeverityCritical
	default:
		return domain.DiagnosticSeverityMedium
	}
}

func defaultDeployPreflightInputs(cfg config.Config) preflight.Inputs {
	return preflight.Inputs{
		Permissions:   detectPermissionStateFn(),
		Platform:      detectPlatformInfoFn(),
		Capabilities:  detectHostCapabilityStateFn(),
		DNS:           detectDNSProbeFn(cfg.Default.ServerURL),
		Ports:         detectPortBindingsFn(cfg),
		Firewall:      detectFirewallStateFn(),
		Services:      detectServiceStatesFn(),
		PackageSource: detectPackageSourceStateFn(cfg),
		ACME:          detectACMEStateFn(cfg),
	}
}

func deployManagedServiceState(checkpoint state.Checkpoint, desiredStateDigest string) preflight.ManagedServiceState {
	if !checkpoint.MatchesDesiredState(desiredStateDigest) {
		return preflight.ManagedServiceState{}
	}

	return preflight.ManagedServiceState{
		Headscale: checkpoint.HasCompleted(deployCheckpointHeadscalePackageInstalled) ||
			checkpoint.HasCompleted(deployCheckpointRuntimeAssetsInstalled) ||
			checkpoint.HasCompleted(deployCheckpointServicesEnabled),
		Nginx: checkpoint.HasCompleted(deployCheckpointHostDependenciesInstalled) ||
			checkpoint.HasCompleted(deployCheckpointTLSBootstrapReady) ||
			checkpoint.HasCompleted(deployCheckpointNginxActivated),
	}
}

func detectDeployManagedServiceStateFromHost() preflight.ManagedServiceState {
	return preflight.ManagedServiceState{
		Headscale: deployHostFileLooksManaged(headscale.ConfigPath, deployedHeadscaleConfigLooksManaged),
		Nginx:     deployHostFileLooksManaged(nginx.SiteAvailablePath, deployedNginxSiteLooksManaged),
	}
}

func deployHostFileLooksManaged(path string, validator func([]byte) bool) bool {
	content, err := readDeployManagedHostFileFn(path)
	if err != nil {
		return false
	}
	return validator(content)
}

func deployedHeadscaleConfigLooksManaged(content []byte) bool {
	runtimeConfig, err := headscale.ParseRuntimeConfig(content)
	if err != nil {
		return false
	}

	return strings.TrimSpace(runtimeConfig.ListenAddr) == headscale.ListenAddress &&
		strings.TrimSpace(runtimeConfig.GRPCListenAddr) == headscale.GRPCListenAddress &&
		!runtimeConfig.GRPCAllowInsecure &&
		runtimeConfig.DERP.Server.Enabled &&
		runtimeConfig.DERP.Server.VerifyClients &&
		runtimeConfig.DERP.Server.AutomaticallyAddEmbeddedDERPRegion &&
		strings.TrimSpace(runtimeConfig.DERP.Server.RegionCode) == "lanpanel" &&
		strings.TrimSpace(runtimeConfig.DERP.Server.RegionName) == "Lanpanel Embedded DERP" &&
		strings.TrimSpace(runtimeConfig.DERP.Server.STUNListenAddr) == headscale.STUNListenAddress &&
		len(runtimeConfig.DERP.URLs) == 0 &&
		len(runtimeConfig.DERP.Paths) == 0 &&
		!runtimeConfig.DERP.AutoUpdateEnabled &&
		strings.TrimSpace(runtimeConfig.Policy.Mode) == "file" &&
		strings.TrimSpace(runtimeConfig.Policy.Path) == headscale.PolicyPath &&
		strings.TrimSpace(runtimeConfig.UnixSocket) == headscale.UnixSocketPath &&
		strings.TrimSpace(runtimeConfig.UnixSocketPermission) == headscale.UnixSocketPermission
}

func deployedNginxSiteLooksManaged(content []byte) bool {
	text := string(content)
	for _, marker := range []string{
		"map $http_host $lanpanel_host_header_valid",
		"map $ssl_server_name $lanpanel_sni_valid",
		"upstream headscale_upstream",
		"server 127.0.0.1:8080;",
		"root /var/lib/lanpanel/acme-challenges;",
		"ssl_certificate /etc/lanpanel/tls/",
		"proxy_pass http://headscale_upstream;",
	} {
		if !strings.Contains(text, marker) {
			return false
		}
	}
	return true
}

func mergeManagedServiceState(left preflight.ManagedServiceState, right preflight.ManagedServiceState) preflight.ManagedServiceState {
	return preflight.ManagedServiceState{
		Headscale: left.Headscale || right.Headscale,
		Nginx:     left.Nginx || right.Nginx,
	}
}

func http01ChallengeRouteCommand(serverName string, webroot string) host.Command {
	script := `set -eu
server_name=$1
webroot=$2
token="lanpanel-http01-probe-$(date +%s)-$$"
expected="lanpanel-http01-ok-$token"
challenge_dir="$webroot/.well-known/acme-challenge"
challenge_file="$challenge_dir/$token"
mkdir -p "$challenge_dir"
trap 'rm -f "$challenge_file"' EXIT
printf '%s' "$expected" > "$challenge_file"
body=$(curl -fsS --noproxy '*' --max-time 5 --resolve "$server_name:80:127.0.0.1" "http://$server_name/.well-known/acme-challenge/$token")
if [ "$body" != "$expected" ]; then
    echo "local HTTP-01 webroot probe returned unexpected response" >&2
    exit 1
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-http01-route-check", strings.TrimSpace(serverName), strings.TrimSpace(webroot)},
		DisplayName: "curl",
		DisplayArgs: []string{"--noproxy", "*", "--resolve", strings.TrimSpace(serverName) + ":80:127.0.0.1", "http://" + strings.TrimSpace(serverName) + "/.well-known/acme-challenge/<token>"},
	}
}

func certificateIssueRemediations(acmeChallenge string, serverName string) []string {
	switch strings.TrimSpace(acmeChallenge) {
	case config.ACMEChallengeHTTP01:
		return []string{
			"Fix public ACME HTTP-01 reachability or rate-limit issues, then rerun deploy.",
			fmt.Sprintf("For HTTP-01, confirm public port 80 reaches this host and %s is not behind a CDN or proxy that blocks /.well-known/acme-challenge/.", strings.TrimSpace(serverName)),
			fmt.Sprintf("On the cloud server, confirm the lanpanel Nginx route with: curl --noproxy '*' --resolve %s:80:127.0.0.1 http://%s/.well-known/acme-challenge/<token>", strings.TrimSpace(serverName), strings.TrimSpace(serverName)),
			fmt.Sprintf("From an external network, confirm http://%s/.well-known/acme-challenge/<token> reaches this server while the challenge file exists, or switch default.acme_challenge to dns-01 when public port 80 cannot be opened reliably.", strings.TrimSpace(serverName)),
		}
	case config.ACMEChallengeDNS01:
		return []string{"Fix DNS-01 provider credentials, DNS propagation, or ACME rate-limit issues, then rerun deploy."}
	default:
		return []string{"Fix ACME reachability, credentials, or rate-limit issues, then rerun deploy."}
	}
}

func detectPermissionState() preflight.PermissionState {
	state := preflight.PermissionState{}
	if currentUser, err := user.Current(); err == nil {
		state.User = currentUser.Username
	}
	if os.Geteuid() == 0 {
		state.IsRoot = true
		return state
	}

	if _, err := exec.LookPath("sudo"); err == nil {
		state.SudoInstalled = true
		if _, err := newHostExecutorFn(nil).Run(stdcontext.Background(), host.Command{Name: "sudo", Args: []string{"-n", "true"}}); err == nil {
			state.SudoWorks = true
		}
	}

	return state
}

func deployPrivilegeStrategy(state preflight.PermissionState) host.PrivilegeStrategy {
	if !state.IsRoot && state.SudoWorks {
		return host.PrivilegeSudo
	}
	return host.PrivilegeDirect
}

func detectPlatformInfo() preflight.PlatformInfo {
	return parsePlatformInfoFromOSRelease(os.ReadFile, "/etc/os-release", "/usr/lib/os-release")
}

func parsePlatformInfoFromOSRelease(readFile func(string) ([]byte, error), paths ...string) preflight.PlatformInfo {
	for _, path := range paths {
		content, err := readFile(path)
		if err == nil {
			return preflight.ParseOSRelease(string(content))
		}
	}
	return preflight.PlatformInfo{}
}

func detectHostCapabilityState() preflight.HostCapabilityState {
	state := preflight.HostCapabilityState{}
	if path, ok := commandAvailable("apt-get"); ok {
		state.AptGetAvailable = true
		state.AptGetDetail = path
	} else {
		state.AptGetDetail = "not found in PATH"
	}
	if path, ok := commandAvailable("dpkg"); ok {
		state.DpkgAvailable = true
		state.DpkgDetail = path
	} else {
		state.DpkgDetail = "not found in PATH"
	}
	if path, ok := commandAvailable("systemctl"); ok {
		state.SystemctlAvailable = true
		state.SystemctlDetail = path
	} else {
		state.SystemctlDetail = "not found in PATH"
	}
	if info, err := os.Stat("/run/systemd/system"); err == nil && info.IsDir() {
		state.SystemdRuntimeAvailable = true
		state.SystemdRuntimeDetail = "/run/systemd/system exists"
	} else if err != nil {
		state.SystemdRuntimeDetail = err.Error()
	} else {
		state.SystemdRuntimeDetail = "/run/systemd/system is not a directory"
	}
	return state
}

func commandAvailable(name string) (string, bool) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return path, true
}

func detectDNSProbe(serverURL string) preflight.DNSProbe {
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return preflight.DNSProbe{}
	}

	host := parsedURL.Hostname()
	if host == "" {
		return preflight.DNSProbe{}
	}

	resolved, err := net.LookupHost(host)
	probe := preflight.DNSProbe{Host: host, ResolvedIPs: resolved}
	if err != nil {
		probe.LookupError = err.Error()
	}
	return probe
}

func detectPortBindings(cfg config.Config) []preflight.PortBinding {
	metricsPort := cfg.Advanced.Headscale.MetricsPort
	if metricsPort == 0 {
		metricsPort = config.DefaultHeadscaleMetricsPort
	}
	tcpPorts := []int{80, 443, 8080, metricsPort, 50443}
	tcpBindings, tcpDetected := detectSSBindingList("tcp", uniqueInts(tcpPorts))
	udpBindings, udpDetected := detectSSBindingList("udp", []int{3478})
	if !tcpDetected && !udpDetected {
		return nil
	}

	required := []preflight.PortBinding{
		{Port: 80, Protocol: "tcp"},
		{Port: 443, Protocol: "tcp"},
		{Port: 8080, Protocol: "tcp"},
		{Port: metricsPort, Protocol: "tcp"},
		{Port: 50443, Protocol: "tcp"},
		{Port: 3478, Protocol: "udp"},
	}
	bindings := make([]preflight.PortBinding, 0, len(required))
	for _, requiredBinding := range required {
		switch requiredBinding.Protocol {
		case "tcp":
			if !tcpDetected {
				continue
			}
			matched := false
			for _, binding := range tcpBindings {
				if binding.Port != requiredBinding.Port || !strings.EqualFold(binding.Protocol, requiredBinding.Protocol) {
					continue
				}
				bindings = append(bindings, binding)
				matched = true
			}
			if matched {
				continue
			}
		case "udp":
			if !udpDetected {
				continue
			}
			matched := false
			for _, binding := range udpBindings {
				if binding.Port != requiredBinding.Port || !strings.EqualFold(binding.Protocol, requiredBinding.Protocol) {
					continue
				}
				bindings = append(bindings, binding)
				matched = true
			}
			if matched {
				continue
			}
		}
		bindings = append(bindings, requiredBinding)
	}

	return bindings
}

func uniqueInts(values []int) []int {
	unique := make([]int, 0, len(values))
	seen := map[int]struct{}{}
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func detectSSBindings(protocol string, ports []int) (map[int]preflight.PortBinding, bool) {
	bindings, detected := detectSSBindingList(protocol, ports)
	if !detected {
		return nil, false
	}
	return selectSSPortBindings(bindings), true
}

func detectSSBindingList(protocol string, ports []int) ([]preflight.PortBinding, bool) {
	if _, err := exec.LookPath("ss"); err != nil {
		return nil, false
	}

	args := []string{"-H"}
	switch protocol {
	case "tcp":
		args = append(args, "-ltnp")
	case "udp":
		args = append(args, "-lunp")
	default:
		return nil, false
	}

	raw, err := exec.Command("ss", args...).CombinedOutput()
	if err != nil && len(raw) == 0 {
		return nil, false
	}
	return parseSSBindingList(string(raw), protocol, ports)
}

func parseSSBindings(raw string, protocol string, ports []int) (map[int]preflight.PortBinding, bool) {
	bindings, detected := parseSSBindingList(raw, protocol, ports)
	if !detected {
		return nil, false
	}
	return selectSSPortBindings(bindings), true
}

func parseSSBindingList(raw string, protocol string, ports []int) ([]preflight.PortBinding, bool) {
	portSet := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		portSet[port] = struct{}{}
	}

	bindings := make([]preflight.PortBinding, 0, len(ports))
	if strings.TrimSpace(raw) == "" {
		return bindings, true
	}

	parsedAny := false
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddress, port, ok := parseSocketEndpoint(fields[3])
		if !ok {
			continue
		}
		parsedAny = true
		if _, wanted := portSet[port]; !wanted {
			continue
		}

		processes := parseSocketProcesses(line)
		if len(processes) == 0 {
			bindings = append(bindings, preflight.PortBinding{Port: port, Protocol: protocol, InUse: true, LocalAddress: localAddress})
			continue
		}
		for _, process := range processes {
			bindings = append(bindings, preflight.PortBinding{Port: port, Protocol: protocol, InUse: true, LocalAddress: localAddress, Process: process.name, PID: process.pid})
		}
	}

	return compactSSBindingList(bindings), parsedAny
}

func selectSSPortBindings(bindingList []preflight.PortBinding) map[int]preflight.PortBinding {
	bindings := make(map[int]preflight.PortBinding, len(bindingList))
	for _, binding := range bindingList {
		if existing, ok := bindings[binding.Port]; ok && (existing.Process != "" || binding.Process == "") {
			continue
		}
		bindings[binding.Port] = binding
	}
	return bindings
}

type ssBindingSocketKey struct {
	protocol     string
	localAddress string
	port         int
}

type socketProcess struct {
	name string
	pid  int
}

func compactSSBindingList(bindings []preflight.PortBinding) []preflight.PortBinding {
	keyOrder := make([]ssBindingSocketKey, 0, len(bindings))
	grouped := make(map[ssBindingSocketKey][]preflight.PortBinding, len(bindings))
	for _, binding := range bindings {
		key := ssBindingSocketKey{
			protocol:     strings.ToLower(strings.TrimSpace(binding.Protocol)),
			localAddress: strings.TrimSpace(binding.LocalAddress),
			port:         binding.Port,
		}
		if _, ok := grouped[key]; !ok {
			keyOrder = append(keyOrder, key)
		}
		grouped[key] = append(grouped[key], binding)
	}

	compact := make([]preflight.PortBinding, 0, len(bindings))
	for _, key := range keyOrder {
		group := grouped[key]
		detailed := make([]preflight.PortBinding, 0, len(group))
		for _, binding := range group {
			if !ssBindingHasProcessDetails(binding) {
				continue
			}
			duplicate := false
			for _, existing := range detailed {
				if ssBindingProcessDetailsEqual(existing, binding) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				detailed = append(detailed, binding)
			}
		}
		if len(detailed) > 0 {
			compact = append(compact, detailed...)
			continue
		}
		compact = append(compact, group[0])
	}
	return compact
}

func ssBindingHasProcessDetails(binding preflight.PortBinding) bool {
	return strings.TrimSpace(binding.Process) != "" || binding.PID != 0
}

func ssBindingProcessDetailsEqual(left preflight.PortBinding, right preflight.PortBinding) bool {
	return strings.TrimSpace(left.Process) == strings.TrimSpace(right.Process) && left.PID == right.PID
}

func detectFirewallState() preflight.FirewallState {
	if _, err := exec.LookPath("ufw"); err == nil {
		return detectUFWFirewallState()
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		return detectFirewalldState()
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return detectNFTablesState()
	}
	return preflight.FirewallState{DetectionError: "No supported firewall backend was detected on this host."}
}

func detectUFWFirewallState() preflight.FirewallState {
	raw, err := exec.Command("ufw", "status").CombinedOutput()
	text := strings.TrimSpace(string(raw))
	state := preflight.FirewallState{Backend: "ufw"}
	if err != nil && text == "" {
		state.DetectionError = err.Error()
		return state
	}

	lowerText := strings.ToLower(text)
	if strings.Contains(lowerText, "status: inactive") {
		state.Inspected = true
		return state
	}
	if !strings.Contains(lowerText, "status: active") {
		state.DetectionError = commandProbeDetail(err, text)
		return state
	}

	state.Inspected = true
	state.Active = true
	state.AllowedPorts = parseUFWAllowedPorts(text)
	state.MissingPorts = missingFirewallPorts(state.AllowedPorts)
	return state
}

func detectFirewalldState() preflight.FirewallState {
	state := preflight.FirewallState{Backend: "firewalld"}
	rawState, err := exec.Command("firewall-cmd", "--state").CombinedOutput()
	stateText := strings.TrimSpace(string(rawState))
	if err != nil {
		if strings.Contains(strings.ToLower(stateText), "not running") {
			state.Inspected = true
			return state
		}
		state.DetectionError = commandProbeDetail(err, stateText)
		return state
	}

	state.Inspected = true
	if strings.TrimSpace(stateText) != "running" {
		return state
	}
	state.Active = true

	rawPorts, portsErr := exec.Command("firewall-cmd", "--list-ports").CombinedOutput()
	rawServices, servicesErr := exec.Command("firewall-cmd", "--list-services").CombinedOutput()
	if portsErr != nil && servicesErr != nil {
		state.Inspected = false
		state.DetectionError = commandProbeDetail(portsErr, strings.TrimSpace(string(rawPorts)))
		return state
	}

	allowed := append(parseDelimitedPorts(string(rawPorts)), mapFirewalldServicesToPorts(string(rawServices))...)
	state.AllowedPorts = uniqueStrings(allowed)
	state.MissingPorts = missingFirewallPorts(state.AllowedPorts)
	return state
}

func detectNFTablesState() preflight.FirewallState {
	raw, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	text := strings.ToLower(strings.TrimSpace(string(raw)))
	state := preflight.FirewallState{Backend: "nftables"}
	if err != nil {
		state.DetectionError = commandProbeDetail(err, strings.TrimSpace(string(raw)))
		return state
	}

	state.Inspected = true
	if text == "" || !strings.Contains(text, "table ") {
		return state
	}
	state.Active = true

	allowed := []string{}
	for _, requiredPort := range requiredFirewallPorts {
		port, protocol, ok := splitLabeledPort(requiredPort)
		if !ok {
			continue
		}
		if nftRulesetAllowsPort(text, protocol, port) {
			allowed = append(allowed, requiredPort)
		}
	}
	state.AllowedPorts = uniqueStrings(allowed)
	state.MissingPorts = missingFirewallPorts(state.AllowedPorts)
	if len(state.MissingPorts) > 0 {
		state.Inspected = false
		state.DetectionError = "nftables ruleset is present but lanpanel could not confirm explicit allow rules for all required service ports."
	}
	return state
}

func detectServiceStates() []preflight.ServiceState {
	if services, ok := detectSystemdServiceStates(); ok {
		return services
	}
	if services, ok := detectPgrepServiceStates(); ok {
		return services
	}
	return nil
}

func detectSystemdServiceStates() ([]preflight.ServiceState, bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, false
	}

	executor := newHostExecutorFn(nil)
	systemd := newHostSystemdFn(executor)
	services := []preflight.ServiceState{}
	inspected := false
	for _, serviceName := range knownConflictServices {
		active, err := systemd.IsActive(stdcontext.Background(), serviceName)
		if err != nil {
			text := strings.TrimSpace(err.Error())
			if strings.Contains(text, "System has not been booted with systemd") || strings.Contains(text, "Failed to connect to bus") {
				return nil, false
			}
			continue
		}
		inspected = true
		if !active {
			continue
		}

		detail := "active"
		result, err := executor.Systemctl(stdcontext.Background(), "show", "--property=SubState", serviceName)
		text := strings.TrimSpace(result.Stdout)
		if text == "" {
			text = strings.TrimSpace(result.Stderr)
		}
		if strings.Contains(text, "System has not been booted with systemd") || strings.Contains(text, "Failed to connect to bus") {
			return nil, false
		}
		if err == nil {
			properties := parseSystemdProperties(text)
			if subState := strings.TrimSpace(properties["SubState"]); subState != "" {
				detail = subState
			}
		}

		services = append(services, preflight.ServiceState{
			Name:   serviceName,
			Active: true,
			Detail: detail,
		})
	}

	if !inspected {
		return nil, false
	}
	return services, true
}

func detectPgrepServiceStates() ([]preflight.ServiceState, bool) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		return nil, false
	}

	services := []preflight.ServiceState{}
	inspected := false
	for _, serviceName := range knownConflictServices {
		err := exec.Command("pgrep", "-x", serviceName).Run()
		if err == nil {
			inspected = true
			services = append(services, preflight.ServiceState{Name: serviceName, Active: true, Detail: "process detected"})
			continue
		}
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			inspected = true
		}
	}

	if !inspected {
		return nil, false
	}
	return services, true
}

func detectPackageSourceState(cfg config.Config) preflight.PackageSourceState {
	probeClient := newDeployHTTPClient(cfg.Advanced.Proxy, cfg.Advanced.PackageProbe.EffectiveReachabilityTimeout())
	artifactClient := newDeployHTTPClient(cfg.Advanced.Proxy, cfg.Advanced.PackageProbe.EffectiveArtifactTimeout())
	state := preflight.PackageSourceState{
		Mode:     strings.TrimSpace(cfg.Advanced.HeadscaleSource.Mode),
		Version:  strings.TrimSpace(cfg.Advanced.HeadscaleSource.Version),
		URL:      strings.TrimSpace(cfg.Advanced.HeadscaleSource.URL),
		FilePath: strings.TrimSpace(cfg.Advanced.HeadscaleSource.FilePath),
	}
	if state.Mode == config.PackageSourceModeDirect {
		if digest, err := headscale.PackageSHA256(state.Version, packageArch(cfg)); err == nil {
			state.ExpectedSHA256 = digest
		} else {
			state.ReachabilityDetail = appendProbeDetail(state.ReachabilityDetail, fmt.Sprintf("Built-in package checksum lookup failed: %s", err))
		}
	} else {
		state.ExpectedSHA256 = strings.TrimSpace(cfg.Advanced.HeadscaleSource.SHA256)
	}
	if legoArchive, err := legocomponent.NewArchivePlan(cfg, legocomponent.InstallPlanOptions{}); err == nil {
		state.LegoMode = legoArchive.Mode
		state.LegoVersion = legoArchive.Version
		state.LegoURL = legoArchive.SourceURL
		state.LegoFilePath = legoArchive.SourcePath
		state.LegoExpectedSHA256 = legoArchive.ExpectedSHA256
		switch legoArchive.Mode {
		case config.PackageSourceModeOffline:
			if state.LegoFilePath != "" {
				info, err := os.Stat(state.LegoFilePath)
				if err == nil && !info.IsDir() {
					state.LegoFileExists = true
					actualSHA256, err := hashLocalFile(state.LegoFilePath)
					if err == nil {
						state.LegoIntegrityChecked = true
						state.LegoActualSHA256 = actualSHA256
					} else {
						state.LegoReachabilityDetail = fmt.Sprintf("SHA-256 probe failed: %s", err)
					}
				}
			}
		default:
			state.LegoReachabilityChecked, state.LegoReachable, state.LegoReachabilityDetail = probePackageURLFn(probeClient, state.LegoURL)
			if state.LegoReachable && state.LegoExpectedSHA256 != "" {
				actualSHA256, err := hashRemoteArtifactFn(artifactClient, state.LegoURL)
				if err == nil {
					state.LegoIntegrityChecked = true
					state.LegoActualSHA256 = actualSHA256
				} else {
					state.LegoReachabilityDetail = appendProbeDetail(state.LegoReachabilityDetail, fmt.Sprintf("SHA-256 probe failed: %s", err))
				}
			}
		}
	} else {
		state.LegoReachabilityDetail = err.Error()
	}

	switch state.Mode {
	case config.PackageSourceModeDirect:
		packageURL := headscale.OfficialPackageURL(state.Version, packageArch(cfg))
		state.ReachabilityChecked, state.Reachable, state.ReachabilityDetail = probePackageURLFn(probeClient, packageURL)
		if state.Reachable && state.ExpectedSHA256 != "" {
			actualSHA256, err := hashRemoteArtifactFn(artifactClient, packageURL)
			if err == nil {
				state.IntegrityChecked = true
				state.ActualSHA256 = actualSHA256
			} else {
				state.ReachabilityDetail = appendProbeDetail(state.ReachabilityDetail, fmt.Sprintf("SHA-256 probe failed: %s", err))
			}
		}
	case config.PackageSourceModeMirror:
		state.ReachabilityChecked, state.Reachable, state.ReachabilityDetail = probePackageURLFn(probeClient, state.URL)
		if state.Reachable && state.ExpectedSHA256 != "" {
			actualSHA256, err := hashRemoteArtifactFn(artifactClient, state.URL)
			if err == nil {
				state.IntegrityChecked = true
				state.ActualSHA256 = actualSHA256
			} else {
				state.ReachabilityDetail = appendProbeDetail(state.ReachabilityDetail, fmt.Sprintf("SHA-256 probe failed: %s", err))
			}
		}
	case config.PackageSourceModeOffline:
		if state.FilePath == "" {
			return state
		}
		info, err := os.Stat(state.FilePath)
		if err != nil || info.IsDir() {
			return state
		}
		state.FileExists = true
		actualSHA256, err := hashLocalFile(state.FilePath)
		if err == nil {
			state.IntegrityChecked = true
			state.ActualSHA256 = actualSHA256
		}
	}

	return state
}

func detectACMEState(cfg config.Config) preflight.ACMEState {
	state := preflight.ACMEState{
		Challenge:            strings.TrimSpace(cfg.Default.ACMEChallenge),
		ServerHost:           parseServerHost(cfg.Default.ServerURL),
		CertificateEmail:     strings.TrimSpace(cfg.Default.CertificateEmail),
		DNSProvider:          strings.TrimSpace(cfg.Advanced.DNS01.Provider),
		DNSCredentialsFile:   strings.TrimSpace(cfg.Advanced.DNS01.CredentialsFile),
		DNSCredentialEnvFile: strings.TrimSpace(cfg.Advanced.DNS01.EnvFile),
	}

	switch state.Challenge {
	case config.ACMEChallengeHTTP01:
		if state.ServerHost == "" {
			return state
		}
		state.HTTP01Detail = "lanpanel verifies HTTP-01 challenge routing during deploy after installing and activating Nginx."
	case config.ACMEChallengeDNS01:
		if state.DNSProvider == "" {
			return state
		}
		state.DNSCredentialsChecked, state.DNSCredentialsReady, state.DNSCredentialsDetail = detectDNSCredentialState(cfg.Advanced.DNS01)
	}

	return state
}

func parseSocketPort(endpoint string) (int, bool) {
	_, port, ok := parseSocketEndpoint(endpoint)
	return port, ok
}

func parseSocketEndpoint(endpoint string) (string, int, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", 0, false
	}
	host := ""
	portString := ""
	if strings.HasPrefix(endpoint, "[") {
		closeBracket := strings.LastIndex(endpoint, "]:")
		if closeBracket == -1 {
			return "", 0, false
		}
		host = endpoint[1:closeBracket]
		portString = endpoint[closeBracket+2:]
	} else {
		lastColon := strings.LastIndex(endpoint, ":")
		if lastColon == -1 {
			return "", 0, false
		}
		host = endpoint[:lastColon]
		portString = endpoint[lastColon+1:]
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return "", 0, false
	}
	return strings.TrimSpace(host), port, true
}

func parseSocketProcesses(line string) []socketProcess {
	matches := socketProcessTuplePattern.FindAllStringSubmatch(line, -1)
	processes := make([]socketProcess, 0, len(matches))
	for _, match := range matches {
		pid, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		processes = append(processes, socketProcess{name: strings.TrimSpace(match[1]), pid: pid})
	}
	return processes
}

func parseUFWAllowedPorts(output string) []string {
	allowed := []string{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		columns := splitUFWStatusColumns(scanner.Text())
		if len(columns) < 2 || strings.ToUpper(columns[1]) != "ALLOW" {
			continue
		}
		allowed = append(allowed, expandUFWRuleTarget(columns[0])...)
	}
	return uniqueStrings(allowed)
}

func splitUFWStatusColumns(line string) []string {
	parts := ufwStatusColumnSeparator.Split(strings.TrimSpace(line), -1)
	columns := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		columns = append(columns, part)
	}
	return columns
}

func expandUFWRuleTarget(target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}

	normalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(target, "(v6)")))
	if ports, ok := ufwApplicationProfilePorts[normalized]; ok {
		return append([]string(nil), ports...)
	}

	fields := strings.Fields(target)
	if len(fields) == 0 {
		return nil
	}
	return expandDelimitedPortToken(fields[0])
}

func parseDelimitedPorts(raw string) []string {
	ports := []string{}
	for _, token := range strings.Fields(raw) {
		ports = append(ports, expandDelimitedPortToken(token)...)
	}
	return uniqueStrings(ports)
}

func expandDelimitedPortToken(token string) []string {
	token = strings.TrimSpace(token)
	if token == "" || !strings.Contains(token, "/") {
		return nil
	}
	portRange, protocol, ok := strings.Cut(token, "/")
	if !ok {
		return nil
	}
	ports := []string{}
	for _, part := range strings.Split(portRange, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ports = append(ports, fmt.Sprintf("%s/%s", part, strings.ToLower(strings.TrimSpace(protocol))))
	}
	return ports
}

func mapFirewalldServicesToPorts(output string) []string {
	allowed := []string{}
	for _, service := range strings.Fields(strings.ToLower(output)) {
		switch strings.TrimSpace(service) {
		case "http":
			allowed = append(allowed, "80/tcp")
		case "https":
			allowed = append(allowed, "443/tcp")
		case "stun":
			allowed = append(allowed, "3478/udp")
		}
	}
	return uniqueStrings(allowed)
}

func nftRulesetAllowsPort(ruleset string, protocol string, port int) bool {
	scanner := bufio.NewScanner(strings.NewReader(strings.ToLower(ruleset)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, protocol) || !strings.Contains(line, "accept") || !strings.Contains(line, "dport") {
			continue
		}
		if nftRuleLineAllowsPort(line, protocol, port) {
			return true
		}
	}
	return false
}

func nftRuleLineAllowsPort(line string, protocol string, port int) bool {
	tokens := nftRuleTokens(line)
	for index := 0; index+2 < len(tokens); index++ {
		if tokens[index] != protocol || tokens[index+1] != "dport" {
			continue
		}
		return nftPortExpressionAllows(tokens[index+2:], port)
	}
	return false
}

func nftRuleTokens(line string) []string {
	replacer := strings.NewReplacer("{", " { ", "}", " } ", ",", " , ")
	return strings.Fields(replacer.Replace(line))
}

func nftPortExpressionAllows(tokens []string, port int) bool {
	if len(tokens) == 0 {
		return false
	}
	if tokens[0] == "{" {
		for _, token := range tokens[1:] {
			if token == "}" {
				return false
			}
			if token == "," {
				continue
			}
			if nftPortTokenAllows(token, port) {
				return true
			}
		}
		return false
	}
	return nftPortTokenAllows(tokens[0], port)
}

func nftPortTokenAllows(token string, port int) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	if startRaw, endRaw, ok := strings.Cut(token, "-"); ok {
		start, startErr := strconv.Atoi(strings.TrimSpace(startRaw))
		end, endErr := strconv.Atoi(strings.TrimSpace(endRaw))
		if startErr != nil || endErr != nil || start > end {
			return false
		}
		return port >= start && port <= end
	}
	value, err := strconv.Atoi(token)
	return err == nil && value == port
}

func missingFirewallPorts(allowed []string) []string {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowedSet[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}

	missing := make([]string, 0, len(requiredFirewallPorts))
	for _, requiredPort := range requiredFirewallPorts {
		if _, ok := allowedSet[strings.ToLower(requiredPort)]; ok {
			continue
		}
		missing = append(missing, requiredPort)
	}
	return missing
}

func parseSystemdProperties(output string) map[string]string {
	properties := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		properties[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return properties
}

func probePackageURL(client *http.Client, rawURL string) (bool, bool, string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return false, false, ""
	}

	statusCode, finalURL, err := probeURL(client, rawURL, http.MethodHead)
	if err == nil && (statusCode == http.StatusMethodNotAllowed || statusCode == http.StatusNotImplemented) {
		statusCode, finalURL, err = probeURL(client, rawURL, http.MethodGet)
	}
	if err != nil {
		return true, false, err.Error()
	}
	if statusCode >= http.StatusOK && statusCode < http.StatusBadRequest {
		return true, true, fmt.Sprintf("%s returned %d.", finalURL, statusCode)
	}
	return true, false, fmt.Sprintf("%s returned %d.", finalURL, statusCode)
}

func packageArch(cfg config.Config) string {
	arch := strings.TrimSpace(cfg.Advanced.Platform.Arch)
	if arch == "" {
		arch = config.ArchAMD64
	}
	return arch
}

func deployHostDependencyPackages(cfg config.Config) ([]string, error) {
	return []string{"nginx", "ca-certificates", "curl", "tar", "openssl"}, cfg.Validate()
}

func hashRemoteArtifact(client *http.Client, rawURL string) (string, error) {
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "lanpanel-preflight/1.0")

	client = httpClientOrDefault(client, 20*time.Second)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("%s returned %s", response.Request.URL.String(), response.Status)
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, response.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func lookupOfficialPackageDigest(client *http.Client, version string, arch string) (string, error) {
	assetName := headscale.OfficialPackageAssetName(version, arch)
	if assetName == "" {
		return "", fmt.Errorf("missing Headscale version or architecture")
	}

	checksums, err := fetchOfficialReleaseChecksums(client, version)
	if err != nil {
		return "", err
	}

	digest := strings.TrimSpace(checksums[assetName])
	if digest == "" {
		return "", fmt.Errorf("official checksum missing for %s", assetName)
	}
	return digest, nil
}

func fetchOfficialReleaseChecksums(client *http.Client, version string) (map[string]string, error) {
	checksumURL := headscale.OfficialChecksumsURL(version)
	if checksumURL == "" {
		return nil, fmt.Errorf("missing Headscale version")
	}

	request, err := http.NewRequest(http.MethodGet, checksumURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "lanpanel-preflight/1.0")

	client = httpClientOrDefault(client, 20*time.Second)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%s returned %s", response.Request.URL.String(), response.Status)
	}

	checksums := map[string]string{}
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		digest := strings.ToLower(strings.TrimSpace(fields[0]))
		assetName := strings.TrimSpace(fields[len(fields)-1])
		if len(digest) != 64 || assetName == "" {
			continue
		}
		checksums[assetName] = digest
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(checksums) == 0 {
		return nil, fmt.Errorf("%s did not contain any checksums", response.Request.URL.String())
	}

	return checksums, nil
}

func hashLocalFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func stageDeployFiles(cfg config.Config) ([]render.StagedFile, error) {
	return stageRuntimeFilesFn(cfg)
}

func stageDeployFingerprintFiles(cfg config.Config) ([]render.StagedFile, error) {
	return stageRuntimeFilesFn(cfg)
}

func detectDNSCredentialState(dns01 config.DNS01Config) (bool, bool, string) {
	providerInfo, err := tlscomponent.DNSProvider(dns01.Provider)
	if err != nil {
		return false, false, err.Error()
	}

	envFile := strings.TrimSpace(dns01.EnvFile)
	if envFile != "" {
		env, ready, detail := inspectDNSEnvFile(envFile)
		if !ready {
			return true, false, fmt.Sprintf("DNS provider %q env_file is not ready: %s", providerInfo.LegoCode, detail)
		}
		if env != nil {
			if err := acmecatalog.ValidateDNSProviderEnvironment(providerInfo.LegoCode, env); err != nil {
				return true, false, err.Error()
			}
			if ready, detail := inspectDNSCredentialEnvFileReferences(providerInfo.LegoCode, env); !ready {
				return true, false, fmt.Sprintf("DNS provider %q env_file contains credential file references that are not ready: %s.", providerInfo.LegoCode, detail)
			}
		}
		return true, true, fmt.Sprintf("Using lego env_file for DNS provider %q: %s. %s", providerInfo.LegoCode, envFile, detail)
	}
	env := nonEmptyEnvironmentByKey()
	if providerInfo.LegoCode == "route53" && route53RawSecretEnvironmentPresent(env) && strings.TrimSpace(env["AWS_SHARED_CREDENTIALS_FILE"]) == "" {
		return true, false, "Detected Route53 AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in the current environment, but lanpanel will not pass raw AWS secrets through sudo or systemd. Use advanced.dns01.env_file for DNS-01 deploy and renewal."
	}
	if providerInfo.AmbientCredentialsSupported {
		detail := fmt.Sprintf("Using lego ambient credential chain for DNS provider %q; confirm deploy and lanpanel-lego-renew.service run with the same host identity.", providerInfo.LegoCode)
		if providerInfo.LegoCode == "gcloud" {
			detail += " For gcloud, confirm Google Cloud metadata also provides the project, or set advanced.dns01.env_file with GCE_PROJECT."
		}
		return true, true, detail
	}
	return true, false, fmt.Sprintf("DNS provider %q requires advanced.dns01.env_file so initial issuance and lanpanel-lego-renew.service use the same provider environment.", providerInfo.LegoCode)
}

func inspectDNSCredentialsFile(filePath string) (bool, string) {
	info, err := statDNSCredentialsFileFn(filePath)
	if err != nil {
		if os.IsPermission(err) {
			return false, fmt.Sprintf("%s cannot be inspected by the current user; verify it is a root-owned private credentials file before retrying.", filePath)
		}
		return false, fmt.Sprintf("%s cannot be inspected: %v.", filePath, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Sprintf("%s is not a regular credentials file.", filePath)
	}
	if info.Size() == 0 {
		return false, fmt.Sprintf("%s is empty.", filePath)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false, fmt.Sprintf("%s must be readable only by root; remove group/other permissions before retrying.", filePath)
	}
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		return false, fmt.Sprintf("%s must be owned by root before lanpanel uses it as a DNS credentials file.", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsPermission(err) {
			return true, "Root-owned private credentials file exists but is not readable by the current user; lego will read it through deploy privileges."
		}
		return false, fmt.Sprintf("%s cannot be opened: %v.", filePath, err)
	}
	_ = file.Close()
	return true, "Root-owned private credentials file exists and is readable by the current user."
}

func inspectDNSEnvFile(filePath string) (map[string]string, bool, string) {
	ready, detail := inspectDNSCredentialsFile(filePath)
	if !ready {
		return nil, false, detail
	}
	content, readDetail, err := readDNSCredentialEnvFile(filePath)
	if err != nil {
		return nil, false, fmt.Sprintf("%s cannot be opened for validation: %s.", filePath, err)
	}
	if readDetail != "" {
		detail = strings.TrimSpace(detail + " " + readDetail)
	}
	env, syntaxDetail := parseDNSEnvFileContent(content)
	if syntaxDetail != "" {
		return env, false, fmt.Sprintf("%s contains unsupported syntax for systemd EnvironmentFile: %s. Use KEY=value lines without export.", filePath, syntaxDetail)
	}
	if len(env) == 0 {
		return env, false, fmt.Sprintf("%s does not contain any KEY=value environment assignments.", filePath)
	}
	return env, true, detail
}

func readDNSCredentialEnvFile(filePath string) ([]byte, string, error) {
	content, err := readDNSCredentialsFileFn(filePath)
	if err == nil {
		return content, "", nil
	}
	if !os.IsPermission(err) {
		return nil, "", err
	}

	content, detail, ok := readDNSCredentialEnvFileWithPrivilege(filePath)
	if !ok {
		return nil, "", fmt.Errorf("%s", detail)
	}
	return content, detail, nil
}

func readDNSCredentialEnvFileWithPrivilege(filePath string) ([]byte, string, bool) {
	permissions := detectPermissionStateFn()
	if !permissions.IsRoot && !permissions.SudoWorks {
		return nil, "the current user cannot read it and deploy privileges are not available for secret-safe validation", false
	}

	executor := newHostExecutorFn(nil).WithPrivilege(deployPrivilegeStrategy(permissions))
	result, err := executor.Run(stdcontext.Background(), host.Command{
		Name:        "cat",
		Args:        []string{"--", filePath},
		DisplayName: "cat",
		DisplayArgs: []string{"--", "<dns-env-file>"},
	})
	if err != nil {
		return nil, "deploy privileges could not read the env file without exposing secret values", false
	}
	return []byte(result.Stdout), "Validated env_file content through deploy privileges without printing secret values.", true
}

func parseDNSEnvFileContent(content []byte) (map[string]string, string) {
	env := map[string]string{}
	for lineNumber, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			return env, fmt.Sprintf("line %d uses shell export syntax", lineNumber+1)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !dnsEnvFileKeyPattern.MatchString(key) {
			return env, fmt.Sprintf("line %d uses an invalid environment variable name", lineNumber+1)
		}
		value = unquoteDNSEnvValue(value)
		if key == "" || value == "" {
			continue
		}
		env[key] = value
	}
	return env, ""
}

func unquoteDNSEnvValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if first == last && (first == '"' || first == '\'') {
			return value[1 : len(value)-1]
		}
	}
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return value
}

func route53RawSecretEnvironmentPresent(env map[string]string) bool {
	_, hasAccessKey := env["AWS_ACCESS_KEY_ID"]
	_, hasSecretKey := env["AWS_SECRET_ACCESS_KEY"]
	return hasAccessKey && hasSecretKey
}

func inspectDNSCredentialEnvFileReferences(provider string, env map[string]string) (bool, string) {
	invalidDetails := []string{}
	for key, value := range env {
		if !dnsCredentialEnvironmentValueIsFile(provider, key) {
			continue
		}
		if !filepath.IsAbs(value) {
			invalidDetails = append(invalidDetails, fmt.Sprintf("%s: referenced credential file path %q must be absolute so deploy and systemd renewal use the same runtime path", key, value))
			continue
		}
		ready, detail := inspectDNSCredentialsFile(value)
		if !ready {
			invalidDetails = append(invalidDetails, fmt.Sprintf("%s: %s", key, detail))
		}
	}
	invalidDetails = uniqueStrings(invalidDetails)
	sort.Strings(invalidDetails)
	if len(invalidDetails) > 0 {
		return false, strings.Join(invalidDetails, "; ")
	}
	return true, ""
}

func supportedDNSCredentialFileEnvKeys(provider string) map[string]struct{} {
	keys, err := acmecatalog.SupportedDNSProviderEnvFileVars(provider)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, key := range keys {
		seen[key] = struct{}{}
	}
	return seen
}

func dnsCredentialEnvironmentValueIsFile(provider string, key string) bool {
	canonical, err := tlscomponent.CanonicalDNSProvider(provider)
	if err != nil {
		return false
	}

	key = strings.TrimSpace(key)
	switch key {
	case "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GCE_SERVICE_ACCOUNT_FILE", "GOOGLE_APPLICATION_CREDENTIALS":
		return true
	}
	if canonical == "route53" && strings.HasPrefix(key, "AWS_") && strings.HasSuffix(key, "_FILE") {
		return false
	}
	if _, ok := supportedDNSCredentialFileEnvKeys(canonical)[key]; ok {
		return true
	}
	return false
}

func nonEmptyEnvironmentByKey() map[string]string {
	env := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		env[key] = value
	}
	return env
}

func fileOwnerUID(info os.FileInfo) (uint64, bool) {
	return fileSysUintField(info, "Uid", "UID")
}

func fileOwnerGID(info os.FileInfo) (uint64, bool) {
	return fileSysUintField(info, "Gid", "GID")
}

func fileSysUintField(info os.FileInfo, fieldNames ...string) (uint64, bool) {
	sys := reflect.ValueOf(info.Sys())
	if !sys.IsValid() {
		return 0, false
	}
	if sys.Kind() == reflect.Pointer {
		if sys.IsNil() {
			return 0, false
		}
		sys = sys.Elem()
	}
	if sys.Kind() != reflect.Struct {
		return 0, false
	}
	var field reflect.Value
	for _, fieldName := range fieldNames {
		field = sys.FieldByName(fieldName)
		if field.IsValid() {
			break
		}
	}
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value := field.Int()
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	default:
		return 0, false
	}
}

func defaultCheckpointPath(configPath string) string {
	return state.DefaultCheckpointPath(configPath)
}

func deployRetryCommand(configPath string) string {
	return workflow.ShellCommand("lanpanel", "deploy", "--config", configPath)
}

func deployProxyEnv(cfg config.Config) map[string]string {
	return host.ProxyEnv(
		cfg.Advanced.Proxy.HTTPProxy,
		cfg.Advanced.Proxy.HTTPSProxy,
		cfg.Advanced.Proxy.NoProxy,
	)
}

func newDeployHTTPClient(proxy config.ProxyConfig, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if !deployProxyConfigured(proxy) {
		return &http.Client{Timeout: timeout, Transport: transport}
	}

	transport.Proxy = deployProxyFunc(proxy)
	return &http.Client{Timeout: timeout, Transport: transport}
}

func deployProxyConfigured(proxy config.ProxyConfig) bool {
	return strings.TrimSpace(proxy.HTTPProxy) != "" ||
		strings.TrimSpace(proxy.HTTPSProxy) != "" ||
		strings.TrimSpace(proxy.NoProxy) != ""
}

func httpClientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	return newDeployHTTPClient(config.ProxyConfig{}, timeout)
}

func deployProxyFunc(proxy config.ProxyConfig) func(*http.Request) (*url.URL, error) {
	proxyForURL := (&httpproxy.Config{
		HTTPProxy:  strings.TrimSpace(proxy.HTTPProxy),
		HTTPSProxy: strings.TrimSpace(proxy.HTTPSProxy),
		NoProxy:    strings.TrimSpace(proxy.NoProxy),
	}).ProxyFunc()

	return func(request *http.Request) (*url.URL, error) {
		if request == nil || request.URL == nil {
			return nil, nil
		}
		return proxyForURL(request.URL)
	}
}

func deployPhaseCompleted(checkpoint state.Checkpoint, names ...string) bool {
	for _, name := range names {
		if checkpoint.HasCompleted(name) {
			return true
		}
	}
	return false
}

type deployRuntimeFileSnapshot struct {
	hostPath string
	exists   bool
	content  []byte
	mode     fs.FileMode
}

func stateRuntimeFileSnapshots(snapshots []deployRuntimeFileSnapshot) []state.FileSnapshot {
	converted := make([]state.FileSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, state.FileSnapshot{
			HostPath: snapshot.hostPath,
			Exists:   snapshot.exists,
			Content:  append([]byte(nil), snapshot.content...),
			Mode:     uint32(snapshot.mode.Perm()),
		})
	}
	return converted
}

func deployRuntimeFileSnapshotsFromCheckpoint(snapshots []state.FileSnapshot) ([]deployRuntimeFileSnapshot, error) {
	converted := make([]deployRuntimeFileSnapshot, 0, len(snapshots))
	seen := make(map[string]struct{}, len(snapshots))
	for _, snapshot := range snapshots {
		hostPath := filepath.Clean(strings.TrimSpace(snapshot.HostPath))
		if hostPath == "" || hostPath == "." || !filepath.IsAbs(hostPath) {
			return nil, fmt.Errorf("runtime rollback snapshot host path is required and must be absolute")
		}
		if _, ok := seen[hostPath]; ok {
			return nil, fmt.Errorf("duplicate runtime rollback snapshot host path %s", hostPath)
		}
		seen[hostPath] = struct{}{}
		if !snapshot.Exists && (len(snapshot.Content) > 0 || snapshot.Mode != 0) {
			return nil, fmt.Errorf("absent runtime rollback snapshot %s must not include content or mode", hostPath)
		}
		converted = append(converted, deployRuntimeFileSnapshot{
			hostPath: hostPath,
			exists:   snapshot.Exists,
			content:  append([]byte(nil), snapshot.Content...),
			mode:     fs.FileMode(snapshot.Mode).Perm(),
		})
	}
	return converted, nil
}

func restorePendingDeployCheckpointSnapshots(ctx stdcontext.Context, store state.Store, checkpoint *state.Checkpoint, executor host.Executor, fileSystem host.FileSystem, configPath string) (deployCommandResult, error, bool) {
	if checkpoint == nil || !checkpoint.HasMutationSnapshots() {
		return deployCommandResult{}, nil, false
	}
	if len(checkpoint.DirectorySnapshots) > 0 || len(checkpoint.SymlinkSnapshots) > 0 {
		result, err := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
			Step:         "restore pending rollback snapshots",
			Operation:    "checking main deploy checkpoint rollback snapshot types",
			Impact:       "deploy cannot safely continue while the main checkpoint contains unsupported rollback snapshot types",
			Remediation:  []string{"Inspect the checkpoint file and use the matching lanpanel command for the config path before retrying deploy."},
			RetryCommand: deployRetryCommand(configPath),
			Cause:        fmt.Errorf("main deploy checkpoint contains directory or symlink rollback snapshots"),
		})
		return result, err, true
	}
	runtimeSnapshots, err := deployRuntimeFileSnapshotsFromCheckpoint(checkpoint.RuntimeFileSnapshots)
	if err != nil {
		result, failureErr := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
			Step:         "load pending runtime rollback snapshot",
			Operation:    "reading persisted runtime file rollback state before deploy resume",
			Impact:       "deploy cannot safely continue until checkpoint rollback state is valid",
			Remediation:  []string{"Inspect the checkpoint file and rerun deploy after removing malformed runtime_file_snapshots."},
			RetryCommand: deployRetryCommand(configPath),
			Cause:        err,
		})
		return result, failureErr, true
	}
	systemdSnapshots, err := deploySystemdUnitSnapshotsFromCheckpoint(checkpoint.SystemdUnitSnapshots)
	if err != nil {
		result, failureErr := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
			Step:         "load pending systemd rollback snapshot",
			Operation:    "reading persisted systemd rollback state before deploy resume",
			Impact:       "deploy cannot safely continue until checkpoint rollback state is valid",
			Remediation:  []string{"Inspect the checkpoint file and rerun deploy after removing malformed systemd_unit_snapshots."},
			RetryCommand: deployRetryCommand(configPath),
			Cause:        err,
		})
		return result, failureErr, true
	}
	if len(runtimeSnapshots) > 0 {
		if err := restoreDeployRuntimeFiles(ctx, executor, fileSystem, runtimeSnapshots); err != nil {
			result, failureErr := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
				Step:         "restore pending runtime files",
				Operation:    "restoring runtime files from the persisted deploy checkpoint rollback snapshot",
				Impact:       "deploy cannot safely continue until the previous interrupted host mutation is rolled back",
				Remediation:  []string{"Inspect the reported host paths, fix filesystem permissions, and rerun deploy."},
				RetryCommand: deployRetryCommand(configPath),
				Cause:        err,
			})
			return result, failureErr, true
		}
		removeDeployCheckpoint(checkpoint, deployCheckpointRuntimeAssetsInstalled)
		rewindDeployCurrentCheckpoint(checkpoint)
		systemd := newHostSystemdFn(executor)
		if _, err := systemd.DaemonReload(ctx); err != nil {
			result, failureErr := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
				Step:         "reload systemd after runtime rollback",
				Operation:    "running systemctl daemon-reload after restoring deploy runtime files",
				Impact:       "deploy cannot safely continue until systemd has re-read restored unit files",
				Remediation:  []string{"Fix systemd access and rerun deploy so lanpanel can complete the pending rollback."},
				RetryCommand: deployRetryCommand(configPath),
				Cause:        err,
			})
			return result, failureErr, true
		}
		if _, err := executor.Run(ctx, nginx.TestConfigCommand()); err != nil {
			result, failureErr := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
				Step:         "test nginx after runtime rollback",
				Operation:    "running nginx -t after restoring deploy runtime files",
				Impact:       "deploy cannot safely continue until restored Nginx runtime files pass config test",
				Remediation:  []string{"Inspect the restored Nginx config and rerun deploy after fixing the reported error."},
				RetryCommand: deployRetryCommand(configPath),
				Cause:        err,
			})
			return result, failureErr, true
		}
		if _, err := executor.Run(ctx, nginx.ReloadCommand()); err != nil {
			result, failureErr := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
				Step:         "reload nginx after runtime rollback",
				Operation:    "reloading Nginx after restoring deploy runtime files",
				Impact:       "deploy cannot safely continue until Nginx is serving the restored runtime configuration",
				Remediation:  []string{"Fix Nginx service reload errors and rerun deploy so lanpanel can complete the pending rollback."},
				RetryCommand: deployRetryCommand(configPath),
				Cause:        err,
			})
			return result, failureErr, true
		}
	}
	if len(systemdSnapshots) > 0 {
		if err := restoreDeploySystemdUnits(ctx, executor, systemdSnapshots, mutatedDeploySystemdUnits(systemdSnapshots)); err != nil {
			result, failureErr := deployFailureWithCheckpointSave(store, *checkpoint, workflow.Failure{
				Step:         "restore pending service systemd state",
				Operation:    "restoring systemd units from the persisted deploy checkpoint rollback snapshot",
				Impact:       "deploy cannot safely continue until the previous interrupted service mutation is rolled back",
				Remediation:  []string{"Inspect the reported systemd unit state, fix systemctl access, and rerun deploy."},
				RetryCommand: deployRetryCommand(configPath),
				Cause:        err,
			})
			return result, failureErr, true
		}
		removeDeployCheckpoint(checkpoint, deployCheckpointServicesEnabled)
		rewindDeployCurrentCheckpoint(checkpoint)
	}
	checkpoint.ClearMutationSnapshots()
	if err := store.Save(*checkpoint); err != nil {
		failure := workflow.Failure{
			Step:         "clear restored rollback snapshots",
			Operation:    "saving deploy checkpoint after restoring pending rollback snapshots",
			Impact:       "deploy cannot continue because the checkpoint still points at already-restored rollback snapshots",
			Remediation:  []string{"Ensure the checkpoint directory is writable and rerun deploy."},
			RetryCommand: deployRetryCommand(configPath),
			Cause:        err,
		}
		return deployFailureCommandResult(failure), failure, true
	}
	return deployCommandResult{}, nil, false
}

func snapshotDeployRuntimeFiles(fileSystem host.FileSystem, staged []render.StagedFile) ([]deployRuntimeFileSnapshot, error) {
	if fileSystem == nil {
		return nil, fmt.Errorf("deploy runtime filesystem is required")
	}
	snapshots := make([]deployRuntimeFileSnapshot, 0, len(staged))
	seen := make(map[string]struct{}, len(staged))
	for _, file := range staged {
		hostPath := filepath.Clean(strings.TrimSpace(file.HostPath))
		if hostPath == "" || hostPath == "." || !filepath.IsAbs(hostPath) {
			return nil, fmt.Errorf("deploy runtime file host path is required and must be absolute")
		}
		if _, ok := seen[hostPath]; ok {
			return nil, fmt.Errorf("duplicate deploy runtime file host path %s", hostPath)
		}
		seen[hostPath] = struct{}{}

		info, err := fileSystem.Lstat(hostPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				snapshots = append(snapshots, deployRuntimeFileSnapshot{hostPath: hostPath})
				continue
			}
			return nil, fmt.Errorf("stat existing deploy runtime file %s: %w", hostPath, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink; refusing to snapshot deploy runtime file", hostPath)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s exists and is not a regular deploy runtime file", hostPath)
		}
		content, err := fileSystem.ReadFile(hostPath)
		if err != nil {
			return nil, fmt.Errorf("read existing deploy runtime file %s: %w", hostPath, err)
		}
		snapshots = append(snapshots, deployRuntimeFileSnapshot{
			hostPath: hostPath,
			exists:   true,
			content:  append([]byte(nil), content...),
			mode:     info.Mode().Perm(),
		})
	}
	return snapshots, nil
}

func restoreDeployRuntimeFiles(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []deployRuntimeFileSnapshot) error {
	if fileSystem == nil {
		return fmt.Errorf("deploy runtime filesystem is required")
	}
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		if strings.TrimSpace(snapshot.hostPath) == "" {
			return fmt.Errorf("deploy runtime file snapshot path is required")
		}
		if snapshot.exists {
			if err := fileSystem.WriteFile(snapshot.hostPath, snapshot.content, snapshot.mode); err != nil {
				return fmt.Errorf("restore deploy runtime file %s: %w", snapshot.hostPath, err)
			}
			continue
		}
		if err := removeDeployPath(ctx, executor, "rollback-deploy-runtime-file", snapshot.hostPath); err != nil {
			return fmt.Errorf("remove new deploy runtime file %s: %w", snapshot.hostPath, err)
		}
	}
	return nil
}

func rollbackDeployRuntimeFilesAfterNginxFailure(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []deployRuntimeFileSnapshot, cause error) (bool, error) {
	if err := restoreDeployRuntimeFiles(ctx, executor, fileSystem, snapshots); err != nil {
		return false, fmt.Errorf("%w; restore previous deploy runtime files failed: %v", cause, err)
	}
	if _, err := executor.Run(ctx, nginx.TestConfigCommand()); err != nil {
		return true, fmt.Errorf("%w; restored previous deploy runtime files but nginx -t failed: %v", cause, err)
	}
	if _, err := executor.Run(ctx, nginx.ReloadCommand()); err != nil {
		return true, fmt.Errorf("%w; restored previous deploy runtime files and nginx -t passed but nginx reload failed: %v", cause, err)
	}
	return true, cause
}

func removeDeployPath(ctx stdcontext.Context, executor host.Executor, displayName string, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is required for %s", displayName)
	}
	_, err := executor.Run(ctx, host.Command{
		Name:        "rm",
		Args:        []string{"-f", "--", path},
		DisplayName: displayName,
		DisplayArgs: []string{path},
	})
	return err
}

func requireDeployRuntimeRollbackSnapshot(store state.Store, checkpoint state.Checkpoint, configPath string, snapshots []deployRuntimeFileSnapshot) (deployCommandResult, error, bool) {
	if !deployPhaseCompleted(checkpoint, deployCheckpointRuntimeAssetsInstalled) || deployPhaseCompleted(checkpoint, deployCheckpointNginxActivated) {
		return deployCommandResult{}, nil, false
	}
	if len(snapshots) > 0 {
		return deployCommandResult{}, nil, false
	}
	result, err := deployFailureWithCheckpointSave(store, checkpoint, workflow.Failure{
		Step:         "prepare Nginx activation rollback",
		Operation:    "checking persisted runtime file rollback state before Nginx activation",
		Impact:       "deploy cannot safely activate Nginx because the pre-runtime file snapshot is missing",
		Remediation:  []string{"Restore the host from backup or remove the stale checkpoint after manually inspecting runtime files, then rerun deploy."},
		RetryCommand: deployRetryCommand(configPath),
		Cause:        fmt.Errorf("runtime-assets-installed is completed but runtime_file_snapshots is empty"),
	})
	return result, err, true
}

type deploySystemdUnitSnapshot struct {
	unit         string
	enabledState string
	activeState  string
}

func stateDeploySystemdUnitSnapshots(snapshots []deploySystemdUnitSnapshot) []state.SystemdUnitSnapshot {
	converted := make([]state.SystemdUnitSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, state.SystemdUnitSnapshot{
			Unit:         snapshot.unit,
			EnabledState: snapshot.enabledState,
			ActiveState:  snapshot.activeState,
		})
	}
	return converted
}

func deploySystemdUnitSnapshotsFromCheckpoint(snapshots []state.SystemdUnitSnapshot) ([]deploySystemdUnitSnapshot, error) {
	converted := make([]deploySystemdUnitSnapshot, 0, len(snapshots))
	seen := make(map[string]struct{}, len(snapshots))
	for _, snapshot := range snapshots {
		unit := strings.TrimSpace(snapshot.Unit)
		if unit == "" {
			return nil, fmt.Errorf("systemd rollback snapshot unit is required")
		}
		if _, ok := seen[unit]; ok {
			return nil, fmt.Errorf("duplicate systemd rollback snapshot unit %s", unit)
		}
		seen[unit] = struct{}{}
		enabledState := strings.TrimSpace(snapshot.EnabledState)
		if enabledState != "enabled" && enabledState != "disabled" {
			return nil, fmt.Errorf("systemd rollback snapshot unit %s has unsupported enabled state %q", unit, enabledState)
		}
		activeState := strings.TrimSpace(snapshot.ActiveState)
		if activeState != "active" && activeState != "inactive" {
			return nil, fmt.Errorf("systemd rollback snapshot unit %s has unsupported active state %q", unit, activeState)
		}
		converted = append(converted, deploySystemdUnitSnapshot{
			unit:         unit,
			enabledState: enabledState,
			activeState:  activeState,
		})
	}
	return converted, nil
}

func mutatedDeploySystemdUnits(snapshots []deploySystemdUnitSnapshot) map[string]bool {
	mutated := make(map[string]bool, len(snapshots))
	for _, snapshot := range snapshots {
		unit := strings.TrimSpace(snapshot.unit)
		if unit != "" {
			mutated[unit] = true
		}
	}
	return mutated
}

func snapshotDeploySystemdUnits(ctx stdcontext.Context, executor host.Executor, units []string) ([]deploySystemdUnitSnapshot, error) {
	snapshots := make([]deploySystemdUnitSnapshot, 0, len(units))
	seen := map[string]struct{}{}
	for _, unit := range units {
		unit = strings.TrimSpace(unit)
		if unit == "" {
			return nil, fmt.Errorf("systemd unit is required")
		}
		if _, ok := seen[unit]; ok {
			continue
		}
		seen[unit] = struct{}{}
		enabledState, err := snapshotDeploySystemdUnitEnabledState(ctx, executor, unit)
		if err != nil {
			return nil, err
		}
		activeState, err := snapshotDeploySystemdUnitActiveState(ctx, executor, unit)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, deploySystemdUnitSnapshot{unit: unit, enabledState: enabledState, activeState: activeState})
	}
	return snapshots, nil
}

func snapshotDeploySystemdUnitEnabledState(ctx stdcontext.Context, executor host.Executor, unit string) (string, error) {
	state, err := snapshotDeploySystemdUnitState(ctx, executor, "is-enabled", unit)
	switch state {
	case "enabled", "disabled":
		return state, nil
	}
	if err != nil {
		return "", fmt.Errorf("systemctl is-enabled %s returned unsupported state %q: %w", unit, state, err)
	}
	return "", fmt.Errorf("systemctl is-enabled %s returned unsupported state %q; only enabled and disabled can be restored exactly", unit, state)
}

func snapshotDeploySystemdUnitActiveState(ctx stdcontext.Context, executor host.Executor, unit string) (string, error) {
	state, err := snapshotDeploySystemdUnitState(ctx, executor, "is-active", unit)
	switch state {
	case "active", "inactive":
		return state, nil
	}
	if err != nil {
		return "", fmt.Errorf("systemctl is-active %s returned unsupported state %q: %w", unit, state, err)
	}
	return "", fmt.Errorf("systemctl is-active %s returned unsupported state %q; only active and inactive can be restored exactly", unit, state)
}

func snapshotDeploySystemdUnitState(ctx stdcontext.Context, executor host.Executor, action string, unit string) (string, error) {
	result, err := executor.Systemctl(ctx, action, unit)
	output := strings.TrimSpace(result.Stdout)
	if output == "" {
		output = strings.TrimSpace(result.Stderr)
	}
	var commandErr *host.CommandError
	if err != nil && errors.As(err, &commandErr) {
		if output == "" {
			output = strings.TrimSpace(commandErr.Result.Stdout)
		}
		if output == "" {
			output = strings.TrimSpace(commandErr.Result.Stderr)
		}
	}
	if output == "" {
		if err != nil {
			return "", fmt.Errorf("systemctl %s %s produced no state: %w", action, unit, err)
		}
		return "", fmt.Errorf("systemctl %s %s produced no state", action, unit)
	}
	return strings.Fields(output)[0], err
}

func restoreDeploySystemdUnits(ctx stdcontext.Context, executor host.Executor, snapshots []deploySystemdUnitSnapshot, mutated map[string]bool) error {
	systemd := newHostSystemdFn(executor)
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		if !mutated[snapshot.unit] {
			continue
		}
		if snapshot.activeState == "inactive" {
			if _, err := systemd.Stop(ctx, snapshot.unit); err != nil {
				return fmt.Errorf("restore inactive systemd unit %s: %w", snapshot.unit, err)
			}
		}
		if snapshot.enabledState == "disabled" {
			if _, err := executor.Systemctl(ctx, "disable", snapshot.unit); err != nil {
				return fmt.Errorf("restore disabled systemd unit %s: %w", snapshot.unit, err)
			}
		}
	}
	for _, snapshot := range snapshots {
		if !mutated[snapshot.unit] {
			continue
		}
		if snapshot.enabledState == "enabled" {
			if _, err := systemd.Enable(ctx, snapshot.unit); err != nil {
				return fmt.Errorf("restore enabled systemd unit %s: %w", snapshot.unit, err)
			}
		}
		if snapshot.activeState == "active" {
			if _, err := systemd.Start(ctx, snapshot.unit); err != nil {
				return fmt.Errorf("restore active systemd unit %s: %w", snapshot.unit, err)
			}
		}
	}
	return nil
}

func removeDeployCheckpoint(checkpoint *state.Checkpoint, name string) {
	if checkpoint == nil {
		return
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return
	}
	filtered := checkpoint.CompletedCheckpoints[:0]
	for _, completed := range checkpoint.CompletedCheckpoints {
		if strings.TrimSpace(completed) == trimmed {
			continue
		}
		filtered = append(filtered, completed)
	}
	checkpoint.CompletedCheckpoints = filtered
	if strings.TrimSpace(checkpoint.CurrentCheckpoint) == trimmed {
		checkpoint.CurrentCheckpoint = ""
	}
}

func rewindDeployCurrentCheckpoint(checkpoint *state.Checkpoint) {
	if checkpoint == nil || strings.TrimSpace(checkpoint.CurrentCheckpoint) != "" {
		return
	}
	for i := len(checkpoint.CompletedCheckpoints) - 1; i >= 0; i-- {
		completed := strings.TrimSpace(checkpoint.CompletedCheckpoints[i])
		if completed == "" {
			continue
		}
		checkpoint.MarkCompleted(completed)
		return
	}
}

func missingRequiredDeployCheckpoints(checkpoint state.Checkpoint, names ...string) []string {
	missing := []string{}
	for _, name := range names {
		if !deployPhaseCompleted(checkpoint, name) {
			missing = append(missing, name)
		}
	}
	return missing
}

func recordDeployCheckpointResult(store state.Store, checkpoint *state.Checkpoint, name string, configPath string) (deployCommandResult, error) {
	checkpoint.MarkCompleted(name)
	checkpoint.RecordFailure(workflow.FailureSnapshot{})
	if err := store.Save(*checkpoint); err != nil {
		failure := workflow.Failure{
			Step:         "persist deploy checkpoint",
			Operation:    fmt.Sprintf("recording deploy checkpoint %s", name),
			Impact:       "lanpanel completed a host phase but could not persist the recovery point",
			Remediation:  []string{"Ensure the checkpoint directory is writable and rerun deploy."},
			RetryCommand: deployRetryCommand(configPath),
			Cause:        err,
		}
		return deployFailureCommandResult(failure), failure
	}
	return deployCommandResult{}, nil
}

func deployFailureWithCheckpointSave(store state.Store, checkpoint state.Checkpoint, failure workflow.Failure) (deployCommandResult, error) {
	checkpoint.RecordFailure(failure.Snapshot())
	if err := store.Save(checkpoint); err != nil {
		persistFailure := workflow.Failure{
			Step:         "persist deploy failure",
			Operation:    "saving deploy failure recovery state",
			Impact:       "lanpanel could not persist the authoritative recovery point after a failed host mutation",
			Remediation:  []string{"Fix checkpoint storage permissions before rerunning deploy.", "Inspect the host manually before retrying because the failed recovery point was not persisted."},
			RetryCommand: failure.RetryCommand,
			Cause:        fmt.Errorf("%s; could not save recovery point: %w", failure.Summary(), err),
		}
		return deployFailureCommandResult(persistFailure), persistFailure
	}
	return deployFailureCommandResult(failure), failure
}

func deployFailureWithoutCheckpointSave(failure workflow.Failure) (deployCommandResult, error) {
	return deployFailureCommandResult(failure), failure
}

func checkpointLoadFailureResult(command string, configPath string, checkpointPath string, err error, prefixFields []domain.ResultField) (deployCommandResult, workflow.Failure) {
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

	snapshot := failure.Snapshot()
	fields := snapshot.ResultFields()
	if len(prefixFields) > 0 {
		fields = append(append([]domain.ResultField(nil), prefixFields...), fields...)
	}
	fields = append(fields, domain.ResultField{Label: "checkpoint path", Value: checkpointPath})
	return deployOperationCommandResult("failed", workflow.OperationResult{
		Kind:         domain.JobKindDeploy,
		Status:       domain.JobStatusFailed,
		Summary:      snapshot.SummaryText(),
		Fields:       fields,
		RetryCommand: retryCommand,
		Progress:     operationProgressEvents(domain.JobKindDeploy, "main deploy host workflow started", domain.DiagnosticStatusFail, "main deploy host workflow failed"),
	}, snapshot.NextSteps()), failure
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

func summarizeDeployError(err error) string {
	if err == nil {
		return "unknown error"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "unknown error"
	}
	line, _, _ := strings.Cut(message, "\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return "unknown error"
	}
	return line
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

func deployDesiredStateDigest(cfg config.Config) (string, error) {
	stagedFiles, err := stageDeployFingerprintFiles(cfg)
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

func deferredCheckpointWarnings(completedCheckpoints []string) []string {
	warnings := make([]string, 0, 2)
	if containsCompletedCheckpoint(completedCheckpoints, deployCheckpointLegoCommandDeferred) {
		if containsCompletedCheckpoint(completedCheckpoints, deployCheckpointNginxActivated) {
			warnings = append(warnings, "lego is not installed; public certificate issuance was deferred and Nginx remains on the temporary HTTP-01 bootstrap certificate")
		} else {
			warnings = append(warnings, "lego is not installed; certificate issuance and Nginx activation were deferred")
		}
	}
	if containsCompletedCheckpoint(completedCheckpoints, deployCheckpointSystemdDaemonReloadDeferred) {
		warnings = append(warnings, "systemd is unavailable; service enablement and onboarding were deferred")
	}
	return warnings
}

func containsCompletedCheckpoint(completedCheckpoints []string, want string) bool {
	trimmedWant := strings.TrimSpace(want)
	if trimmedWant == "" {
		return false
	}
	for _, checkpoint := range completedCheckpoints {
		if strings.TrimSpace(checkpoint) == trimmedWant {
			return true
		}
	}
	return false
}

func systemdCommandDeferred(result host.Result, err error) bool {
	if err == nil {
		return false
	}

	messages := []string{result.Stdout, result.Stderr, err.Error()}
	var commandErr *host.CommandError
	if errors.As(err, &commandErr) {
		messages = append(messages, commandErr.Result.Stdout, commandErr.Result.Stderr)
	}

	for _, message := range messages {
		if systemdUnavailableMessage(message) {
			return true
		}
	}
	return false
}

func systemdUnavailableMessage(message string) bool {
	text := strings.ToLower(strings.TrimSpace(message))
	if text == "" {
		return false
	}
	return strings.Contains(text, "system has not been booted with systemd") ||
		strings.Contains(text, "failed to connect to bus: no such file or directory")
}

func probeURL(client *http.Client, rawURL string, method string) (int, string, error) {
	request, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return 0, rawURL, err
	}
	request.Header.Set("User-Agent", "lanpanel-preflight/1.0")
	if method == http.MethodGet {
		request.Header.Set("Range", "bytes=0-0")
	}

	client = httpClientOrDefault(client, 5*time.Second)
	response, err := client.Do(request)
	if err != nil {
		return 0, rawURL, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if method == http.MethodGet {
		_, _ = io.CopyN(io.Discard, response.Body, 1)
	}
	return response.StatusCode, response.Request.URL.String(), nil
}

func appendProbeDetail(existing string, addition string) string {
	existing = strings.TrimSpace(existing)
	addition = strings.TrimSpace(addition)
	if addition == "" {
		return existing
	}
	if existing == "" {
		return addition
	}
	return existing + " " + addition
}

func commandProbeDetail(err error, output string) string {
	output = strings.TrimSpace(output)
	switch {
	case output != "" && err != nil:
		return fmt.Sprintf("%s (%v)", output, err)
	case output != "":
		return output
	case err != nil:
		return err.Error()
	default:
		return ""
	}
}

func splitLabeledPort(value string) (int, string, bool) {
	portText, protocol, ok := strings.Cut(value, "/")
	if !ok {
		return 0, "", false
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil {
		return 0, "", false
	}
	return port, strings.ToLower(strings.TrimSpace(protocol)), true
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func parseServerHost(raw string) string {
	parsedURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsedURL.Hostname())
}

const (
	CheckpointPackageManagerReady          = deployCheckpointPackageManagerReady
	CheckpointHostDependenciesInstalled    = deployCheckpointHostDependenciesInstalled
	CheckpointPackageArchitectureConfirmed = deployCheckpointPackageArchitectureConfirmed
	CheckpointLegoInstalled                = deployCheckpointLegoInstalled
	CheckpointHeadscalePackageInstalled    = deployCheckpointHeadscalePackageInstalled
	CheckpointRuntimeAssetsInstalled       = deployCheckpointRuntimeAssetsInstalled
	CheckpointTLSBootstrapReady            = deployCheckpointTLSBootstrapReady
	CheckpointLegoCommandReady             = deployCheckpointLegoCommandReady
	CheckpointLegoCommandDeferred          = deployCheckpointLegoCommandDeferred
	CheckpointCertificateIssued            = deployCheckpointCertificateIssued
	CheckpointNginxActivated               = deployCheckpointNginxActivated
	CheckpointSystemdDaemonReloaded        = deployCheckpointSystemdDaemonReloaded
	CheckpointSystemdDaemonReloadDeferred  = deployCheckpointSystemdDaemonReloadDeferred
	CheckpointServicesEnabled              = deployCheckpointServicesEnabled
	CheckpointOnboardingReady              = deployCheckpointOnboardingReady
	CheckpointStaticVerifyPassed           = deployCheckpointStaticVerifyPassed
)

func DetectPermissionState() preflight.PermissionState {
	return detectPermissionState()
}

func DeployPrivilegeStrategy(state preflight.PermissionState) host.PrivilegeStrategy {
	return deployPrivilegeStrategy(state)
}

func DetectPlatformInfo() preflight.PlatformInfo {
	return detectPlatformInfo()
}

func ParsePlatformInfoFromOSRelease(readFile func(string) ([]byte, error), paths ...string) preflight.PlatformInfo {
	return parsePlatformInfoFromOSRelease(readFile, paths...)
}

func DetectHostCapabilityState() preflight.HostCapabilityState {
	return detectHostCapabilityState()
}

func DetectDNSProbe(serverURL string) preflight.DNSProbe {
	return detectDNSProbe(serverURL)
}

func DetectPortBindings(cfg config.Config) []preflight.PortBinding {
	return detectPortBindings(cfg)
}

func DetectFirewallState() preflight.FirewallState {
	return detectFirewallState()
}

func DetectServiceStates() []preflight.ServiceState {
	return detectServiceStates()
}

func DetectPackageSourceState(cfg config.Config) preflight.PackageSourceState {
	return detectPackageSourceState(cfg)
}

func DetectACMEState(cfg config.Config) preflight.ACMEState {
	return detectACMEState(cfg)
}

func ProbePackageURL(client *http.Client, rawURL string) (bool, bool, string) {
	return probePackageURL(client, rawURL)
}

func HashRemoteArtifact(client *http.Client, rawURL string) (string, error) {
	return hashRemoteArtifact(client, rawURL)
}

func LookupOfficialPackageDigest(client *http.Client, version string, arch string) (string, error) {
	return lookupOfficialPackageDigest(client, version, arch)
}

func StageDeployFiles(cfg config.Config) ([]render.StagedFile, error) {
	return stageDeployFiles(cfg)
}

func DeployDesiredStateDigest(cfg config.Config) (string, error) {
	return deployDesiredStateDigest(cfg)
}

func DeployDesiredStateDigestForStaged(cfg config.Config, stagedFiles []render.StagedFile) (string, error) {
	return deployDesiredStateDigestForStaged(cfg, stagedFiles)
}

func DeployManagedServiceState(checkpoint state.Checkpoint, desiredStateDigest string) preflight.ManagedServiceState {
	return deployManagedServiceState(checkpoint, desiredStateDigest)
}

func DetectDeployManagedServiceStateFromHost() preflight.ManagedServiceState {
	return detectDeployManagedServiceStateFromHost()
}

func DetectDeployManagedServiceStateFromHostWithDependencies(dependencies Dependencies) preflight.ManagedServiceState {
	restore := applyDependenciesForHelper(dependencies)
	defer restore()
	return detectDeployManagedServiceStateFromHost()
}

func HTTP01ChallengeRouteCommand(serverName string, webroot string) host.Command {
	return http01ChallengeRouteCommand(serverName, webroot)
}

func CertificateIssueRemediations(acmeChallenge string, serverName string) []string {
	return certificateIssueRemediations(acmeChallenge, serverName)
}

func DetectDNSCredentialState(dns01 config.DNS01Config) (bool, bool, string) {
	return detectDNSCredentialState(dns01)
}

func DetectDNSCredentialStateWithDependencies(dns01 config.DNS01Config, dependencies Dependencies) (bool, bool, string) {
	restore := applyDependenciesForHelper(dependencies)
	defer restore()
	return detectDNSCredentialState(dns01)
}

func InspectDNSCredentialsFile(filePath string) (bool, string) {
	return inspectDNSCredentialsFile(filePath)
}

func InspectDNSCredentialsFileWithDependencies(filePath string, dependencies Dependencies) (bool, string) {
	restore := applyDependenciesForHelper(dependencies)
	defer restore()
	return inspectDNSCredentialsFile(filePath)
}

func ReadDNSCredentialEnvFileWithDependencies(filePath string, dependencies Dependencies) ([]byte, string, error) {
	restore := applyDependenciesForHelper(dependencies)
	defer restore()
	return readDNSCredentialEnvFile(filePath)
}

func ParseDNSEnvFileContent(content []byte) (map[string]string, string) {
	return parseDNSEnvFileContent(content)
}

func DNSCredentialEnvironmentValueIsFile(provider string, key string) bool {
	return dnsCredentialEnvironmentValueIsFile(provider, key)
}

func DetectPackageSourceStateWithDependencies(cfg config.Config, dependencies Dependencies) preflight.PackageSourceState {
	restore := applyDependenciesForHelper(dependencies)
	defer restore()
	return detectPackageSourceState(cfg)
}

func DetectACMEStateWithDependencies(cfg config.Config, dependencies Dependencies) preflight.ACMEState {
	restore := applyDependenciesForHelper(dependencies)
	defer restore()
	return detectACMEState(cfg)
}

func DeployProxyConfigured(proxy config.ProxyConfig) bool {
	return deployProxyConfigured(proxy)
}

func DeployProxyFunc(proxy config.ProxyConfig) func(*http.Request) (*url.URL, error) {
	return deployProxyFunc(proxy)
}

func NewDeployHTTPClient(proxy config.ProxyConfig, timeout time.Duration) *http.Client {
	return newDeployHTTPClient(proxy, timeout)
}

func HTTPClientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	return httpClientOrDefault(client, timeout)
}

func ParseSSBindings(raw string, protocol string, ports []int) (map[int]preflight.PortBinding, bool) {
	return parseSSBindings(raw, protocol, ports)
}

func ParseSSBindingList(raw string, protocol string, ports []int) ([]preflight.PortBinding, bool) {
	return parseSSBindingList(raw, protocol, ports)
}

func DetectSSBindingList(protocol string, ports []int) ([]preflight.PortBinding, bool) {
	return detectSSBindingList(protocol, ports)
}

func ParseUFWAllowedPorts(output string) []string {
	return parseUFWAllowedPorts(output)
}

func NFTRulesetAllowsPort(ruleset string, protocol string, port int) bool {
	return nftRulesetAllowsPort(ruleset, protocol, port)
}

func SystemdCommandDeferred(result host.Result, err error) bool {
	return systemdCommandDeferred(result, err)
}

func Route53RawSecretEnvironmentPresent(env map[string]string) bool {
	return route53RawSecretEnvironmentPresent(env)
}

func NonEmptyEnvironmentByKey() map[string]string {
	return nonEmptyEnvironmentByKey()
}

func FileOwnerUID(info os.FileInfo) (uint64, bool) {
	return fileOwnerUID(info)
}

func FileOwnerGID(info os.FileInfo) (uint64, bool) {
	return fileOwnerGID(info)
}

func UniqueStrings(values []string) []string {
	return uniqueStrings(values)
}
