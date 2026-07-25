package cli

import (
	stdcontext "context"
	"fmt"
	"io"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apphost"
	"lanpanel/internal/apprender"
	"lanpanel/internal/components/appsvc"
	"lanpanel/internal/domain"
	"lanpanel/internal/host"
	"lanpanel/internal/hostworkflow"
	"lanpanel/internal/output"
	"lanpanel/internal/preflight"
	"lanpanel/internal/realip/edgeone"
	"lanpanel/internal/realiprender"
	"lanpanel/internal/render"
	"lanpanel/internal/resource"
	"lanpanel/internal/state"
	uipkg "lanpanel/internal/ui"
	"lanpanel/internal/uistate"
	"lanpanel/internal/workflow"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const DefaultAppConfigPath = appconfig.DefaultConfigPath

const appOriginProtectionManualConfirmation = "origin-protection-manual"

var runAppVerifyWorkflowFn = workflow.RunAppVerify

type appCommand struct {
	summary string
	usage   func(io.Writer) error
	run     func(context, []string) error
}

type appOptions struct {
	configPath    string
	formatValue   string
	confirmations appConfirmationFlag
}

type appConfirmationFlag []string

func (confirmations *appConfirmationFlag) String() string {
	if confirmations == nil {
		return ""
	}
	return strings.Join(*confirmations, ",")
}

func (confirmations *appConfirmationFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("confirmation token must not be empty")
	}
	*confirmations = append(*confirmations, value)
	return nil
}

type appStagedFileInstaller interface {
	Install(files []render.StagedFile) ([]host.FileInstallResult, error)
}

func summarizeAppModifiedPaths(paths []string) string {
	if len(paths) == 0 {
		return "none"
	}
	return fmt.Sprintf("%d total: %s", len(paths), strings.Join(paths, ", "))
}

func apphostDependencies() apphost.Dependencies {
	return apphostDependenciesFn()
}

var apphostDependenciesFn = func() apphost.Dependencies {
	return apphost.Dependencies{}
}

var (
	appCommands = map[string]appCommand{
		"deploy": {summary: "Deploy a same-host service or tailnet upstream from app config.", usage: writeAppDeployHelp, run: runAppDeploy},
		"init":   {summary: "Generate an editable app example config.", usage: writeAppInitHelp, run: runAppInit},
		"realip": {summary: "Manage app real client IP profile runtime artifacts.", usage: writeAppRealIPHelp, run: runAppRealIP},
		"verify": {summary: "Validate app config and runtime templates.", usage: writeAppVerifyHelp, run: runAppVerify},
	}

	stageAppRuntimeFilesFn               = apprender.StageRuntime
	statAppServiceBinaryFn               = os.Stat
	lstatAppServicePathFn                = os.Lstat
	readAppServicePathFn                 = os.ReadFile
	detectAppDNSFn                       = apphost.DetectAppDNS
	detectAppCurrentPublicIPsFn          = apphost.DetectAppCurrentPublicIPs
	detectAppPortBindingsFn              = apphost.DetectAppPortBindings
	detectAppListenPortStateFn           = apphost.DetectAppListenPortState
	detectAppDNSCredentialStateFn        = apphost.DetectAppDNSCredentialState
	detectAppServiceEnvFileStateFn       = apphost.DetectAppServiceEnvFileState
	detectAppTailscaleAuthKeyFileStateFn = apphost.DetectAppTailscaleAuthKeyFileState
	detectAppGoAccessAuthFileStateFn     = apphost.DetectAppGoAccessAuthFileState
	detectAppBrowserAuthFileStateFn      = apphost.DetectAppBrowserAuthFileState
	detectAppGoAccessPortStateFn         = apphost.DetectAppGoAccessPortState
	detectAppGoAccessAppListenBlockersFn = apphost.DetectAppGoAccessAppListenBlockers
	detectAppGoAccessAppPortBlockersFn   = apphost.DetectAppGoAccessAppPortBlockers
	detectAppGoAccessLocaleStateFn       = apphost.DetectAppGoAccessLocaleState
	detectAppGoAccessLogFileStateFn      = apphost.DetectAppGoAccessLogFileState
	isAppGoAccessManagedPortBindingFn    = apphost.IsAppGoAccessManagedPortBinding
	isAppManagedPortBindingFn            = apphost.IsAppManagedPortBinding
	readAppServiceUnitFileFn             = os.ReadFile
	readAppProcessCgroupFileFn           = os.ReadFile
	ensureAppNginxCompatibilityFn        = apphost.EnsureAppNginxRuntimeCompatibility
	loadEdgeOneCredentialsFn             = edgeone.LoadCredentialsFromEnvFile
	describeEdgeOneOriginACLFn           = func(ctx stdcontext.Context, credentials edgeone.Credentials, zoneID string) (*edgeone.OriginACLInfo, error) {
		return edgeone.Client{}.DescribeOriginACL(ctx, credentials, zoneID)
	}
	stageRealIPRuntimeFilesFn      = realiprender.StageRuntime
	readDeployedRealIPProfileFn    = apphost.ReadDeployedRealIPProfile
	readDeployedRealIPStateFn      = apphost.ReadDeployedRealIPState
	readDeployedRealIPReferencesFn = apphost.ReadDeployedRealIPReferences
	runRealIPValidateReferenceFn   = workflow.RunRealIPValidateReference
	lstatDeployedRealIPReferenceFn = os.Lstat
	lstatDeployedRealIPArtifactFn  = os.Lstat
	readDeployedRealIPArtifactFn   = os.ReadFile
	lstatRealIPCleanupPathFn       = os.Lstat
	acquireRealIPProfileLockFn     = apphost.AcquireRealIPProfileLock
	realIPCleanupRoot              = "/var/lib/lanpanel/realip"
	cliResourceStoreDir            = filepath.Join(uipkg.DefaultStateDir, "resources")
	currentExecutablePathFn        = os.Executable
	newAppFileInstallerFn          = func(executor host.Executor, privilege host.PrivilegeStrategy) appStagedFileInstaller {
		if privilege.RequiresSudo() {
			return host.NewFileInstaller(host.NewCommandFileSystem(executor), "")
		}
		return host.NewFileInstaller(nil, "")
	}
	newAppHostFileSystemFn = func(executor host.Executor, privilege host.PrivilegeStrategy) host.FileSystem {
		if privilege.RequiresSudo() {
			return host.NewCommandFileSystem(executor)
		}
		return host.OSFileSystem{}
	}
)

func newAppCommand() command {
	return command{
		summary: "Manage additional app deployments.",
		usage:   writeAppHelp,
		run:     runApp,
	}
}

func runApp(ctx context, args []string) error {
	if len(args) == 0 {
		return writeAppHelp(ctx.stdout)
	}
	switch args[0] {
	case "help", "-h", "--help":
		return runAppHelp(ctx, args[1:])
	}
	selected, ok := appCommands[args[0]]
	if !ok {
		if err := writeAppHelp(ctx.stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown app command %q", args[0])
	}
	return selected.run(ctx, args[1:])
}

func runAppHelp(ctx context, args []string) error {
	if len(args) == 0 {
		return writeAppHelp(ctx.stdout)
	}
	if args[0] == "realip" {
		return runAppRealIPHelp(ctx, args[1:])
	}
	selected, ok := appCommands[args[0]]
	if !ok {
		if err := writeAppHelp(ctx.stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown app command %q", args[0])
	}
	return selected.usage(ctx.stdout)
}

func runAppRealIP(ctx context, args []string) error {
	if len(args) == 0 {
		return writeAppRealIPHelp(ctx.stdout)
	}
	switch args[0] {
	case "help", "-h", "--help":
		return runAppRealIPHelp(ctx, args[1:])
	case "diagnostics":
		return runAppRealIPDiagnostics(ctx, args[1:])
	case "refresh":
		return runAppRealIPRefresh(ctx, args[1:])
	case "validate-reference":
		return runAppRealIPValidateReference(ctx, args[1:])
	default:
		if err := writeAppRealIPHelp(ctx.stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown app realip command %q", args[0])
	}
}

func runAppRealIPHelp(ctx context, args []string) error {
	if len(args) == 0 {
		return writeAppRealIPHelp(ctx.stdout)
	}
	switch args[0] {
	case "diagnostics":
		return writeAppRealIPDiagnosticsHelp(ctx.stdout)
	case "refresh":
		return writeAppRealIPRefreshHelp(ctx.stdout)
	case "validate-reference":
		return writeAppRealIPValidateReferenceHelp(ctx.stdout)
	default:
		if err := writeAppRealIPHelp(ctx.stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown app realip command %q", args[0])
	}
}

func runAppRealIPDiagnostics(ctx context, args []string) (returnErr error) {
	flagSet := newFlagSet("app realip diagnostics")
	var profileName string
	var configPath string
	var formatValue string
	flagSet.StringVar(&profileName, "profile", "", "Name of the deployed realip profile to diagnose.")
	flagSet.StringVar(&configPath, "config", "", "Required app config path used to confirm the active realip profile.")
	flagSet.StringVar(&formatValue, "format", string(output.FormatHuman), "Output format: human | json")
	shown, err := parseFlags(flagSet, args, writeAppRealIPDiagnosticsHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse app realip diagnostics flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("app realip diagnostics", flagSet); err != nil {
		return err
	}
	format, err := output.ParseFormat(formatValue)
	if err != nil {
		return err
	}
	formatter := ctx.formatter(format)
	result, resultErr := workflow.RunRealIPDiagnostics(workflow.Context{
		Version:      ctx.version,
		Actor:        cliActor(),
		HostWorkflow: newCLIHostWorkflow(ctx),
	}, configPath, profileName)
	if result.Kind != "" {
		if err := writeOperationResult(formatter, "app realip diagnostics", workflowOutputStatus("app realip diagnostics", result), result, nil); err != nil {
			return err
		}
	}
	return resultErr
}

func cliRealIPDiagnosticsOptions() hostworkflow.RealIPDiagnosticsOptions {
	return hostworkflow.RealIPDiagnosticsOptions{
		DetectPermissions: detectPermissionStateFn,
		LoadAppConfig:     loadRealIPAppConfigProfile,
		RuntimeConfigPath: realIPRuntimeAppConfigPath,
		AcquireLock: func(profileName string) (hostworkflow.RealIPProfileLock, error) {
			return acquireRealIPProfileLockFn(profileName)
		},
		FileSystem: func(permissions preflight.PermissionState) host.FileSystem {
			privilege := deployPrivilegeStrategy(permissions)
			return newAppHostFileSystemFn(newHostExecutorFn(nil).WithPrivilege(privilege), privilege)
		},
		ReadProfile:       readDeployedRealIPProfileFn,
		ReadState:         readDeployedRealIPStateFn,
		ReadReferences:    readDeployedRealIPReferencesFn,
		LoadCredentials:   loadEdgeOneCredentialsFn,
		LstatArtifact:     lstatDeployedRealIPArtifactFn,
		ReadArtifact:      readDeployedRealIPArtifactFn,
		CredentialFileSys: edgeone.OSFileSystem{},
	}
}

func runAppRealIPValidateReference(ctx context, args []string) error {
	flagSet := newFlagSet("app realip validate-reference")
	var profileName string
	var appName string
	var path string
	var formatValue string
	flagSet.StringVar(&profileName, "profile", "", "Expected deployed realip profile name.")
	flagSet.StringVar(&appName, "app", "", "Expected app name from the reference filename.")
	flagSet.StringVar(&path, "path", "", "Path to the deployed realip reference JSON.")
	flagSet.StringVar(&formatValue, "format", string(output.FormatHuman), "Output format: human | json")
	shown, err := parseFlags(flagSet, args, writeAppRealIPValidateReferenceHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse app realip validate-reference flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("app realip validate-reference", flagSet); err != nil {
		return err
	}
	format, err := output.ParseFormat(formatValue)
	if err != nil {
		return err
	}
	formatter := ctx.formatter(format)
	profileName = strings.TrimSpace(profileName)
	appName = strings.TrimSpace(appName)
	path = strings.TrimSpace(path)
	result, opErr := runRealIPValidateReferenceFn(workflow.Context{Version: ctx.version}, profileName, appName, path)
	response, err := realIPValidateReferenceResponse(result, opErr)
	if err != nil {
		return err
	}
	if err := formatter.Write(response); err != nil {
		return err
	}
	if opErr != nil {
		return appFailureError(response)
	}
	return nil
}

func realIPValidateReferenceResponse(result workflow.OperationResult, opErr error) (output.Response, error) {
	status := "passed"
	if opErr != nil || result.Status == domain.JobStatusFailed {
		status = "failed"
	}
	summary := strings.TrimSpace(result.Summary)
	if opErr != nil {
		summary = opErr.Error()
	}
	if summary == "" {
		summary = "Realip reference validation passed"
	}
	nextSteps := []string{}
	if opErr != nil {
		nextSteps = []string{"Fix the deployed realip reference path, owner, marker, profile, app name, or domains, then rerun validation."}
	}
	result.Kind = domain.JobKindRealIPValidateRef
	result.Summary = summary
	return validatedOperationResultResponse("app realip validate-reference", status, result, nextSteps)
}

func runAppRealIPRefresh(ctx context, args []string) error {
	flagSet := newFlagSet("app realip refresh")
	var profileName string
	var configPath string
	var formatValue string
	var confirmations appConfirmationFlag
	flagSet.StringVar(&profileName, "profile", "", "Name of the deployed realip profile to refresh.")
	flagSet.StringVar(&configPath, "config", "", "Required app config path used to confirm the active realip profile.")
	flagSet.StringVar(&formatValue, "format", string(output.FormatHuman), "Output format: human | json")
	flagSet.Var(&confirmations, "confirmation", "Manual confirmation token. Repeatable when the exposure plan requires it.")
	shown, err := parseFlags(flagSet, args, writeAppRealIPRefreshHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse app realip refresh flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("app realip refresh", flagSet); err != nil {
		return err
	}
	format, err := output.ParseFormat(formatValue)
	if err != nil {
		return err
	}
	formatter := ctx.formatter(format)
	return runAppRealIPRefreshWithFormatter(ctx, profileName, configPath, confirmations, formatter)
}

func runAppRealIPRefreshWithFormatter(ctx context, profileName string, configPath string, confirmations appConfirmationFlag, formatter responseWriter) error {
	actor := cliActor()
	retryCommand := retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", configPath, "--profile", profileName), []string(confirmations))
	result, err := workflow.RunRealIPRefresh(workflow.Context{
		Version:                    ctx.version,
		Actor:                      actor,
		HostWorkflow:               newCLIHostWorkflow(ctx),
		Confirmations:              []string(confirmations),
		ManualConfirmationRecorder: cliManualConfirmationRecorder(domain.JobKindRealIPRefresh, configPath, retryCommand, actor),
		AppInstanceIDProvider:      cliAppInstanceIDProvider,
	}, configPath, profileName, "")
	if result.Kind != "" {
		if writeErr := writeOperationResult(formatter, "app realip refresh", workflowOutputStatus("app realip refresh", result), result, nil); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func appRealIPRefreshFailureFields(profileName string, cause error) []output.Field {
	profileName = strings.TrimSpace(profileName)
	fields := []output.Field{{Label: "profile", Value: profileName}}
	names, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, "")
	if err != nil {
		fields = append(fields, output.Field{Label: "runtime paths", Value: "unavailable: " + err.Error()})
	} else {
		fields = append(fields,
			output.Field{Label: "active include", Value: names.NginxIncludePath},
			output.Field{Label: "trusted CIDRs", Value: names.TrustedCIDRPath},
			output.Field{Label: "state metadata", Value: names.StatePath},
			output.Field{Label: "profile metadata", Value: names.MetadataPath},
			output.Field{Label: "reference dir", Value: names.ReferenceDir},
			output.Field{Label: "refresh service", Value: names.RefreshServicePath},
			output.Field{Label: "refresh timer", Value: names.RefreshTimerPath},
		)
	}
	if cause != nil {
		fields = append(fields, output.Field{Label: "details", Value: cause.Error()})
	}
	return fields
}

func validateRealIPAppConfigProfile(configPath string, profileName string) error {
	_, err := loadRealIPAppConfigProfile(configPath, profileName)
	return err
}

func loadRealIPAppConfigProfile(configPath string, profileName string) (appconfig.Config, error) {
	cfg, err := appconfig.LoadFile(configPath)
	if err != nil {
		return appconfig.Config{}, err
	}
	profile, ok := cfg.RealIPProfile(profileName)
	if !ok {
		return appconfig.Config{}, fmt.Errorf("realip profile %q is not defined in app config", profileName)
	}
	if cfg.EffectiveRealIPProfileName() != profileName {
		return appconfig.Config{}, fmt.Errorf("realip profile %q is not the active origin protection profile in app config", profileName)
	}
	if !profile.IsEnabled() {
		return appconfig.Config{}, fmt.Errorf("realip profile %q is disabled in app config", profileName)
	}
	return cfg, nil
}

func realIPRuntimeAppConfigPath(configPath string) (string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return "", fmt.Errorf("realip refresh app config path is required")
	}
	absolutePath, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("resolve realip refresh app config path: %w", err)
	}
	if !isSystemdExecToken(absolutePath) {
		return "", fmt.Errorf("realip refresh app config path must be a single systemd ExecStart token")
	}
	return absolutePath, nil
}

func isSystemdExecToken(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune("%;\"'\\${}", r) {
			return false
		}
	}
	return true
}

func appRealIPConfigFailureResult(command string, configPath string, profileName string, cause error) commandResult {
	return newCommandResult(command, "invalid-config", domain.JobStatusFailed, domain.DiagnosticStatusFail, "Realip app config validation failed", []output.Field{
		{Label: "app config path", Value: configPath},
		{Label: "profile", Value: profileName},
		{Label: "details", Value: cause.Error()},
	}, []string{"Pass the app config whose access.origin_protection.edgeone_profile matches --profile."})
}

func appRealIPRefreshCommand(configPath string, profileName string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = "<app-config>"
	}
	return workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", configPath, "--profile", strings.TrimSpace(profileName), "--confirmation", appOriginProtectionManualConfirmation)
}

func (options *appOptions) bind(flagSet interface {
	StringVar(*string, string, string, string)
}) {
	flagSet.StringVar(&options.configPath, "config", DefaultAppConfigPath, "Path to the lanpanel app config file.")
	flagSet.StringVar(&options.formatValue, "format", string(output.FormatHuman), "Output format: human | json")
}

func (options appOptions) formatter(stdout io.Writer) (output.Formatter, error) {
	format, err := output.ParseFormat(options.formatValue)
	if err != nil {
		return output.Formatter{}, err
	}
	return output.NewFormatter(stdout, format), nil
}

func cliActor() domain.Actor {
	uid := os.Geteuid()
	return domain.Actor{
		Source:        domain.ActorSourceCLI,
		EffectiveUID:  uid,
		EffectiveUser: fmt.Sprintf("uid:%d", uid),
		ProcessID:     os.Getpid(),
	}
}

func cliExposureInstanceID() (string, error) {
	instance, err := resource.NewStore(cliResourceStoreDir).LoadOrCreateInstance()
	if err != nil {
		return "", fmt.Errorf("load CLI exposure instance_id: %w", err)
	}
	return instance.ID, nil
}

func cliAppInstanceIDProvider() (string, string, error) {
	instanceID, err := cliExposureInstanceID()
	if err != nil {
		return "", "", err
	}
	return instanceID, "cli-resource-store", nil
}

func missingAppConfirmations(required []string, confirmed []string) []string {
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

func appExposurePlanFields(plan domain.ExposurePlan, missing []string) []output.Field {
	fields := []output.Field{
		{Label: "resource id", Value: plan.Resource.ID},
		{Label: "resource name", Value: plan.Resource.CanonicalName},
		{Label: "access", Value: string(plan.Access.AccessMode)},
		{Label: "origin protection", Value: string(plan.OriginProtection)},
		{Label: "exposure decision", Value: string(plan.Decision.Status)},
	}
	if len(plan.Decision.RequiredConfirmations) > 0 {
		fields = append(fields, output.Field{Label: "required confirmations", Value: strings.Join(plan.Decision.RequiredConfirmations, ", ")})
	}
	if len(missing) > 0 {
		fields = append(fields, output.Field{Label: "missing confirmations", Value: strings.Join(missing, ", ")})
	}
	for _, blocker := range plan.DiagnosticBlockers {
		fields = append(fields, output.Field{Label: "blocker " + blocker.ID, Value: string(blocker.Status) + ": " + blocker.Summary})
	}
	return fields
}

func retryCommandWithConfirmations(retryCommand string, confirmations []string) string {
	retryCommand = strings.TrimSpace(retryCommand)
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation == "" {
			continue
		}
		retryCommand = strings.TrimSpace(retryCommand + " " + workflow.ShellCommand("--confirmation", confirmation))
	}
	return retryCommand
}

func cliManualConfirmationRecorder(kind domain.JobKind, configPath string, retryCommand string, actor domain.Actor) workflow.ManualConfirmationRecorder {
	return func(confirmations []string) ([]domain.ManualConfirmation, error) {
		if len(confirmations) == 0 {
			return nil, nil
		}
		store := uistate.NewStore(cliUIStateDir())
		record, err := store.CreateJob(domain.JobRecord{
			Kind:          kind,
			Status:        domain.JobStatusRunning,
			Actor:         actor,
			CheckpointRef: cliManualConfirmationCheckpoint(kind, configPath),
			RetryCommand:  retryCommand,
		})
		if err != nil {
			return nil, fmt.Errorf("create CLI manual confirmation job: %w", err)
		}
		manualConfirmations := make([]domain.ManualConfirmation, 0, len(confirmations))
		for _, confirmation := range confirmations {
			confirmation = strings.TrimSpace(confirmation)
			if confirmation == "" {
				continue
			}
			reason, err := domain.ManualConfirmationReason(confirmation)
			if err != nil {
				return nil, err
			}
			event, err := store.AppendEvent(record.ID, uistate.Event{Status: domain.DiagnosticStatusManual, Message: "manual confirmation submitted: " + confirmation})
			if err != nil {
				return nil, err
			}
			manualConfirmations = append(manualConfirmations, domain.ManualConfirmation{
				ConfirmationID: event.ID,
				Reason:         reason,
				Actor:          actor,
				ConfirmedAt:    event.At.UTC().Format(time.RFC3339),
			})
		}
		record.Status = domain.JobStatusSucceeded
		record.ResultSummary = "manual confirmations recorded for CLI operation"
		if err := store.SaveRecord(record); err != nil {
			return nil, fmt.Errorf("save CLI manual confirmation job: %w", err)
		}
		return manualConfirmations, nil
	}
}

func cliUIStateDir() string {
	return filepath.Dir(cliResourceStoreDir)
}

func cliManualConfirmationCheckpoint(kind domain.JobKind, configPath string) domain.ActivationRef {
	switch kind {
	case domain.JobKindAppDeploy, domain.JobKindRealIPRefresh:
		return domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: state.DefaultCheckpointPath(configPath)}
	default:
		return domain.NotApplicableActivationRef()
	}
}

func runAppInit(ctx context, args []string) error {
	flagSet := newFlagSet("app init")
	options := appOptions{configPath: DefaultAppConfigPath, formatValue: string(output.FormatHuman)}
	options.bind(flagSet)
	shown, err := parseFlags(flagSet, args, writeAppInitHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse app init flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("app init", flagSet); err != nil {
		return err
	}
	formatter, err := options.formatter(ctx.stdout)
	if err != nil {
		return err
	}
	result, err := workflow.RunAppInit(workflow.Context{Version: ctx.version}, options.configPath)
	if result.Kind != "" {
		status := "created"
		nextSteps := []string{
			"Edit app.domains, listen or upstream, and service settings.",
			"Before deploying the default browser app, create access.browser_auth.auth_basic_user_file or create a managed Browser Auth credential in the Management UI.",
			fmt.Sprintf("Run 'sudo lanpanel app deploy --config %s' to deploy the app.", options.configPath),
		}
		if result.Status == domain.JobStatusFailed {
			status = appInitFailureOutputStatus(result)
			nextSteps = []string{"Choose a different --config path or remove the existing failed target and rerun app init."}
		}
		if writeErr := writeOperationResult(formatter, "app init", status, result, nextSteps); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func appInitFailureOutputStatus(result workflow.OperationResult) string {
	switch result.Summary {
	case "App config file already exists":
		return "already-exists"
	case "Failed to inspect app config file":
		return "failed"
	default:
		return "failed"
	}
}

func writeAppInitFailureResponse(formatter output.Formatter, configPath string, outputStatus string, summary string, cause error) error {
	result := workflow.OperationResult{
		Kind:    domain.JobKindAppInit,
		Status:  domain.JobStatusFailed,
		Summary: summary,
		Fields: []output.Field{
			{Label: "config path", Value: configPath},
			{Label: "details", Value: cause.Error()},
		},
		Diagnostics:  []domain.DiagnosticItem{commandDiagnosticItem(domain.JobKindAppInit, "app init", outputStatus, domain.DiagnosticStatusFail, summary)},
		RetryCommand: workflow.ShellCommand("lanpanel", "app", "init", "--config", configPath),
	}
	if err := writeOperationResult(formatter, "app init", outputStatus, result, []string{"Choose a different --config path or remove the existing failed target and rerun app init."}); err != nil {
		return err
	}
	return cause
}

func runAppVerify(ctx context, args []string) error {
	flagSet := newFlagSet("app verify")
	options := appOptions{configPath: DefaultAppConfigPath, formatValue: string(output.FormatHuman)}
	options.bind(flagSet)
	shown, err := parseFlags(flagSet, args, writeAppVerifyHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse app verify flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("app verify", flagSet); err != nil {
		return err
	}
	formatter, err := options.formatter(ctx.stdout)
	if err != nil {
		return err
	}
	verifyContext := workflow.Context{
		Version:               ctx.version,
		Actor:                 cliActor(),
		HostWorkflow:          newCLIHostWorkflow(ctx),
		AppInstanceIDProvider: cliAppInstanceIDProvider,
	}
	result, err := runAppVerifyWorkflowFn(verifyContext, options.configPath, "")
	if err != nil {
		return err
	}
	return writeAppVerifyResult(formatter, options.configPath, result)
}

func writeAppVerifyResult(formatter output.Formatter, configPath string, result workflow.OperationResult) error {
	response, err := validatedOperationResultResponse("app verify", appVerifyOutputStatus(result), result, appVerifyNextSteps(configPath, result))
	if err != nil {
		return err
	}
	if result.Status == domain.JobStatusFailed {
		return writeAppFailureResponse(formatter, response)
	}
	return formatter.Write(response)
}

func appVerifyOutputStatus(result workflow.OperationResult) string {
	if result.Status == domain.JobStatusSucceeded {
		return "static-passed"
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.ID != "app-config" && diagnostic.ID != "app-main-config" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(result.Summary), "App config file not found") {
			return "missing-config"
		}
		return "invalid-config"
	}
	return "failed"
}

func appVerifyNextSteps(configPath string, result workflow.OperationResult) []string {
	switch appVerifyOutputStatus(result) {
	case "missing-config":
		return []string{fmt.Sprintf("Run 'lanpanel app init --config %s' to generate an example config.", configPath)}
	case "invalid-config":
		return []string{fmt.Sprintf("Fix %s and rerun the command.", configPath)}
	case "failed":
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.ID == "app-runtime-stage" {
				return []string{"Fix app config or template inputs and rerun verify."}
			}
			if diagnostic.ID == "app-exposure-plan" {
				return []string{"Fix app config exposure settings and rerun verify."}
			}
			if diagnostic.ID == "app-main-config" {
				return []string{"Change app.domains, app.listen, or nginx.goaccess.websocket_listen so the app uses separate domains and does not reuse the main Headscale port."}
			}
			if diagnostic.ID == "app-resource-instance" {
				return []string{"Fix LanPanel resource state permissions and rerun verify."}
			}
		}
	}
	nextSteps := appVerifyBrowserAuthNextSteps(result)
	nextSteps = append(nextSteps,
		fmt.Sprintf("Run 'sudo lanpanel app deploy --config %s' to apply or refresh app runtime files.", configPath),
		"After deploy, use nginx -t, systemctl, certificate checks, curl, and tailscale status as applicable to verify host runtime state.",
	)
	return nextSteps
}

func appVerifyBrowserAuthNextSteps(result workflow.OperationResult) []string {
	if result.ExposurePlan == nil || result.ExposurePlan.Access.AccessMode != domain.AccessModeBrowser {
		return nil
	}
	return []string{"Before deploy, create the configured Browser Auth htpasswd file or create a managed Browser Auth credential in the Management UI."}
}

func runAppDeploy(ctx context, args []string) (returnErr error) {
	flagSet := newFlagSet("app deploy")
	options := appOptions{configPath: DefaultAppConfigPath, formatValue: string(output.FormatHuman)}
	options.bind(flagSet)
	flagSet.Var(&options.confirmations, "confirmation", "Manual confirmation token. Repeatable when the exposure plan requires it.")
	shown, err := parseFlags(flagSet, args, writeAppDeployHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse app deploy flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("app deploy", flagSet); err != nil {
		return err
	}
	format, err := output.ParseFormat(options.formatValue)
	if err != nil {
		return err
	}
	formatter := ctx.formatter(format)
	return runAppDeployWithFormatter(ctx, options, format, formatter)
}

func runAppDeployWithFormatter(ctx context, options appOptions, format output.Format, formatter responseWriter) (returnErr error) {
	_ = format
	actor := cliActor()
	retryCommand := retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", options.configPath), []string(options.confirmations))
	result, err := workflow.RunAppDeploy(workflow.Context{
		Version:                    ctx.version,
		Actor:                      actor,
		HostWorkflow:               newCLIHostWorkflow(ctx),
		Confirmations:              []string(options.confirmations),
		ManualConfirmationRecorder: cliManualConfirmationRecorder(domain.JobKindAppDeploy, options.configPath, retryCommand, actor),
		AppInstanceIDProvider:      cliAppInstanceIDProvider,
	}, options.configPath, "")
	if result.Kind != "" {
		if writeErr := writeOperationResult(formatter, "app deploy", workflowOutputStatus("app deploy", result), result, nil); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func writeAppFailureResponse(formatter responseWriter, response output.Response) error {
	if err := formatter.Write(response); err != nil {
		return err
	}
	return appFailureError(response)
}

func appFailureError(response output.Response) error {
	if strings.TrimSpace(response.Summary) == "" {
		return fmt.Errorf("%s failed", response.Command)
	}
	return fmt.Errorf("%s: %s", response.Command, response.Summary)
}

func writeAppHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"lanpanel app manages additional Go services and tailnet upstreams.",
		"",
		"Usage:",
		"  lanpanel app <command> [flags]",
		"",
		"Commands:",
		"  init    Generate an editable app example config.",
		"  deploy  Deploy an app from config.",
		"  realip  Manage app real client IP profile runtime artifacts.",
		"  verify  Validate app config and runtime templates.",
	)
}

func writeAppInitHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Generate an editable app example config.",
		"",
		"Usage:",
		"  lanpanel app init [--config path] [--format human|json]",
		"",
		"Flags:",
		"  --config string   Path to the lanpanel app config file to create.",
		"  --format string   Output format: human | json",
	)
}

func writeAppVerifyHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Validate app config and runtime templates.",
		"",
		"Usage:",
		"  lanpanel app verify [--config path] [--format human|json]",
		"",
		"Flags:",
		"  --config string   Path to the lanpanel app config file.",
		"  --format string   Output format: human | json",
	)
}

func writeAppDeployHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Deploy an app from config.",
		"",
		"Usage:",
		"  lanpanel app deploy [--config path] [--confirmation token] [--format human|json]",
		"",
		"Flags:",
		"  --config string         Path to the lanpanel app config file.",
		"  --confirmation string   Manual confirmation token. Repeatable when the exposure plan requires it.",
		"  --format string         Output format: human | json",
	)
}

func writeAppRealIPHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Manage app real client IP profile runtime artifacts.",
		"",
		"Usage:",
		"  lanpanel app realip <command> [flags]",
		"",
		"Commands:",
		"  diagnostics         Report deployed realip profile diagnostics.",
		"  refresh             Refresh a deployed realip profile from EdgeOne OriginACL.",
		"  validate-reference  Validate a deployed realip app reference.",
	)
}

func writeAppRealIPDiagnosticsHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Report deployed realip profile diagnostics.",
		"",
		"Usage:",
		"  lanpanel app realip diagnostics --config path --profile name [--format human|json]",
		"",
		"Flags:",
		"  --profile string  Name of the deployed realip profile to diagnose.",
		"  --config string   Required app config path used to confirm the active realip profile.",
		"  --format string   Output format: human | json",
	)
}

func writeAppRealIPRefreshHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Refresh a deployed realip profile from EdgeOne OriginACL.",
		"",
		"Usage:",
		"  lanpanel app realip refresh --config path --profile name [--confirmation token] [--format human|json]",
		"",
		"Flags:",
		"  --profile string        Name of the deployed realip profile to refresh.",
		"  --config string         Required app config path used to confirm the active realip profile.",
		"  --confirmation string   Manual confirmation token. Repeatable when the exposure plan requires it.",
		"  --format string         Output format: human | json",
	)
}

func writeAppRealIPValidateReferenceHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Validate a deployed realip app reference.",
		"",
		"Usage:",
		"  lanpanel app realip validate-reference --profile name --app name --path path [--format human|json]",
		"",
		"Flags:",
		"  --profile string  Expected deployed realip profile name.",
		"  --app string      Expected app name from the reference filename.",
		"  --path string     Path to the deployed realip reference JSON.",
		"  --format string   Output format: human | json",
	)
}
