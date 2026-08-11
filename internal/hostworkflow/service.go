package hostworkflow

import (
	"context"
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apphost"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/maindeploy"
	"lanpanel/internal/preflight"
	"lanpanel/internal/workflow"
	"strings"
	"time"
)

type Operations struct {
	RealIPDiagnostics          func(context.Context, string, string) (workflow.OperationResult, error)
	DetectPermissions          func() preflight.PermissionState
	LoadRealIPAppConfigProfile func(string, string) (appconfig.Config, error)
}

type Service struct {
	Version                  string
	MainStatusOptions        StatusOptions
	MainDeployOptions        maindeploy.Options
	AppHostDependencies      apphost.Dependencies
	RealIPDiagnosticsOptions RealIPDiagnosticsOptions
	Ops                      Operations
}

func (service Service) AppExposureObservations(ctx context.Context, appConfigPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation) (exposure.AppObservations, error) {
	if err := ctx.Err(); err != nil {
		return exposure.AppObservations{}, err
	}
	return apphost.AppExposureObservations(ctx, apphost.ExposureObservationOptions{
		ConfigPath:   appConfigPath,
		Config:       cfg,
		Operation:    operation,
		Permissions:  service.permissions(),
		Dependencies: service.AppHostDependencies,
	})
}

func (service Service) EnsureBrowserAuthDependencies(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return apphost.EnsureBrowserAuthDependencies(ctx, service.AppHostDependencies)
}

func (service Service) RunMainStatus(ctx context.Context, configPath string) (workflow.OperationResult, error) {
	retryCommand := workflow.ShellCommand("lanpanel", "status", "--config", configPath)
	if err := ctx.Err(); err != nil {
		return canceled(domain.JobKindStatus, "main status canceled before host workflow started", retryCommand), err
	}
	result, err := MainStatusWithOptions(ctx, configPath, service.MainStatusOptions)
	result.Operation.NextSteps = append([]string(nil), result.NextSteps...)
	return result.Operation, err
}

func (service Service) RunMainDeploy(ctx context.Context, configPath string) (workflow.OperationResult, error) {
	retryCommand := workflow.ShellCommand("sudo", "lanpanel", "deploy", "--config", configPath)
	if err := ctx.Err(); err != nil {
		return canceled(domain.JobKindDeploy, "main deploy canceled before host workflow started", retryCommand), err
	}
	result, err := maindeploy.Run(ctx, configPath, service.MainDeployOptions)
	if result.Operation.Kind == domain.JobKindDeploy && strings.TrimSpace(result.Operation.RetryCommand) == "" {
		result.Operation.RetryCommand = retryCommand
	}
	result.Operation.NextSteps = append([]string(nil), result.NextSteps...)
	return result.Operation, err
}

func (service Service) RunAppDeploy(ctx context.Context, appConfigPath string, plan domain.ExposurePlan, confirmations []string) (workflow.OperationResult, error) {
	retryCommand := retryWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", appConfigPath), confirmations)
	if err := ctx.Err(); err != nil {
		return canceled(domain.JobKindAppDeploy, "app deploy canceled before host workflow started", retryCommand), err
	}
	hostResult, err := apphost.RunAppDeploy(ctx, apphost.AppDeployOptions{
		ConfigPath:           appConfigPath,
		Confirmations:        confirmations,
		Version:              service.Version,
		Dependencies:         service.AppHostDependencies,
		ApprovedExposurePlan: &plan,
	})
	result := hostResult.Operation
	result.NextSteps = append([]string(nil), hostResult.NextSteps...)
	if strings.TrimSpace(result.RetryCommand) == "" {
		result.RetryCommand = retryCommand
	}
	return result, err
}

func (service Service) RunRealIPDiagnostics(ctx context.Context, appConfigPath string, profileName string) (workflow.OperationResult, error) {
	retryCommand := workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profileName)
	if err := ctx.Err(); err != nil {
		return canceled(domain.JobKindRealIPDiagnostics, "realip diagnostics canceled before host workflow started", retryCommand), err
	}
	if service.Ops.RealIPDiagnostics != nil {
		return service.Ops.RealIPDiagnostics(ctx, appConfigPath, profileName)
	}
	options := service.RealIPDiagnosticsOptions
	if options.DetectPermissions == nil && service.Ops.DetectPermissions != nil {
		options.DetectPermissions = service.Ops.DetectPermissions
	}
	if options.LoadAppConfig == nil && service.Ops.LoadRealIPAppConfigProfile != nil {
		options.LoadAppConfig = service.Ops.LoadRealIPAppConfigProfile
	}
	result, err := RealIPDiagnosticsWithOptions(ctx, appConfigPath, profileName, options)
	result.Operation.NextSteps = append([]string(nil), result.NextSteps...)
	return result.Operation, err
}

func (service Service) RunRealIPRefresh(ctx context.Context, appConfigPath string, profileName string, plan domain.ExposurePlan, confirmations []string) (workflow.OperationResult, error) {
	retryCommand := retryWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName), confirmations)
	if err := ctx.Err(); err != nil {
		return canceled(domain.JobKindRealIPRefresh, "realip refresh canceled before host workflow started", retryCommand), err
	}
	result, err := apphost.RunRealIPRefresh(ctx, apphost.RealIPRefreshOptions{
		ConfigPath:           appConfigPath,
		ProfileName:          profileName,
		Confirmations:        confirmations,
		Version:              service.Version,
		Dependencies:         service.AppHostDependencies,
		ApprovedExposurePlan: &plan,
	})
	operation := result.Operation
	operation.NextSteps = append([]string(nil), result.NextSteps...)
	if strings.TrimSpace(operation.RetryCommand) == "" {
		operation.RetryCommand = retryCommand
	}
	return operation, err
}

func (service Service) permissions() preflight.PermissionState {
	if service.Ops.DetectPermissions == nil {
		return preflight.PermissionState{}
	}
	return service.Ops.DetectPermissions()
}

func canceled(kind domain.JobKind, summary string, retryCommand string) workflow.OperationResult {
	return workflow.OperationResult{Kind: kind, Status: domain.JobStatusFailed, Summary: summary, RetryCommand: retryCommand}
}

func failed(kind domain.JobKind, summary string, retryCommand string, cause error) workflow.OperationResult {
	fields := []domain.ResultField{}
	if cause != nil {
		fields = append(fields, domain.ResultField{Label: "details", Value: cause.Error()})
	}
	return workflow.OperationResult{
		Kind:         kind,
		Status:       domain.JobStatusFailed,
		Summary:      summary,
		Fields:       fields,
		RetryCommand: retryCommand,
		Progress:     progressEvents(kind, domain.DiagnosticStatusFail),
	}
}

func progressEvents(kind domain.JobKind, status domain.DiagnosticStatus) []workflow.ProgressEvent {
	now := time.Now().UTC()
	return []workflow.ProgressEvent{
		{At: now, Kind: kind, Status: domain.DiagnosticStatusManual, Message: string(kind) + " host workflow started"},
		{At: now, Kind: kind, Status: status, Message: string(kind) + " host workflow finished"},
	}
}

func retryWithConfirmations(command string, confirmations []string) string {
	command = strings.TrimSpace(command)
	if command == "Management UI" {
		return command
	}
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation != "" {
			command += " --confirmation " + workflow.ShellCommand(confirmation)
		}
	}
	return command
}

func missingConfirmations(required []string, confirmations []string) []string {
	seen := map[string]struct{}{}
	for _, confirmation := range confirmations {
		seen[strings.TrimSpace(confirmation)] = struct{}{}
	}
	missing := []string{}
	for _, requiredConfirmation := range required {
		requiredConfirmation = strings.TrimSpace(requiredConfirmation)
		if requiredConfirmation == "" {
			continue
		}
		if _, ok := seen[requiredConfirmation]; !ok {
			missing = append(missing, requiredConfirmation)
		}
	}
	return missing
}

func permissionDetail(command string, permissions preflight.PermissionState) string {
	detail := "fail: " + command + " requires root privileges"
	if strings.TrimSpace(permissions.User) != "" {
		detail += ", current user: " + strings.TrimSpace(permissions.User)
	}
	return detail
}

func appconfigForRealIPProfile(path string, profileName string) (appconfig.Config, error) {
	cfg, err := appconfig.LoadFile(path)
	if err != nil {
		return appconfig.Config{}, err
	}
	if strings.TrimSpace(cfg.Access.OriginProtection.EdgeOneProfile) != strings.TrimSpace(profileName) {
		return appconfig.Config{}, fmt.Errorf("access.origin_protection.edgeone_profile %q does not match --profile %q", cfg.Access.OriginProtection.EdgeOneProfile, profileName)
	}
	return cfg, nil
}
