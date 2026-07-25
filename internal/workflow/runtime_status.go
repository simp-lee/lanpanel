package workflow

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/components/appsvc"
	"lanpanel/internal/components/headscale"
	tlscomponent "lanpanel/internal/components/tls"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/verify"
	"os/exec"
	"strings"
	"time"
)

const runtimeProbeTimeout = 2 * time.Second

var runRuntimeCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

type runtimeUnit struct {
	id    string
	label string
	unit  string
}

type commandState struct {
	value  string
	status domain.DiagnosticStatus
	detail string
}

func runtimeStatusEvidence(ctx Context, cfg config.Config, appCfg *appconfig.Config) ([]domain.ResultField, []domain.DiagnosticItem) {
	units := []runtimeUnit{
		{id: "headscale-service", label: "Headscale service", unit: headscale.ServiceName},
		{id: "nginx-service", label: "Nginx service", unit: "nginx.service"},
		{id: "main-renew-timer", label: "Main certificate renew timer", unit: tlscomponent.RenewTimer},
	}
	if appCfg != nil {
		units = append(units, appRuntimeUnits(*appCfg)...)
	}
	return runtimeUnitEvidence(ctx.stdContext(), units)
}

func appRuntimeUnits(cfg appconfig.Config) []runtimeUnit {
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		return nil
	}
	units := []runtimeUnit{
		{id: "app-renew-timer", label: "App certificate renew timer", unit: names.RenewTimerUnit},
	}
	if cfg.Mode() == appconfig.ModeListen {
		units = append(units, runtimeUnit{id: "app-service", label: "App service", unit: names.ServiceUnit})
	}
	if cfg.RequiresTailscale() {
		units = append(units, runtimeUnit{id: "tailscale-service", label: "Tailscale service", unit: "tailscaled.service"})
	}
	if cfg.Nginx.GoAccess.Enabled {
		units = append(units, runtimeUnit{id: "goaccess-service", label: "GoAccess service", unit: names.GoAccessServiceUnit})
	}
	if profileName := cfg.EffectiveRealIPProfileName(); profileName != "" {
		if profile, ok := cfg.RealIPProfile(profileName); ok {
			realIPNames, err := appsvc.NewRealIPProfileNames(profileName, profile.Provider, cfg.App.Name)
			if err == nil {
				units = append(units,
					runtimeUnit{id: "realip-refresh-service", label: "RealIP refresh service", unit: realIPNames.RefreshServiceUnit},
					runtimeUnit{id: "realip-refresh-timer", label: "RealIP refresh timer", unit: realIPNames.RefreshTimerUnit},
				)
			}
		}
	}
	return units
}

func runtimeUnitEvidence(ctx context.Context, units []runtimeUnit) ([]domain.ResultField, []domain.DiagnosticItem) {
	fields := make([]domain.ResultField, 0, len(units)*2)
	diagnostics := make([]domain.DiagnosticItem, 0, len(units))
	for _, unit := range units {
		active := probeSystemdState(ctx, "is-active", unit.unit)
		enabled := probeSystemdState(ctx, "is-enabled", unit.unit)
		fields = append(fields,
			domain.ResultField{Label: "runtime " + unit.unit + " active", Value: active.value},
			domain.ResultField{Label: "runtime " + unit.unit + " enabled", Value: enabled.value},
		)
		status := combineRuntimeStatuses(active.status, enabled.status)
		summary := fmt.Sprintf("%s (%s) runtime state: active=%s, enabled=%s", unit.label, unit.unit, active.value, enabled.value)
		if detail := strings.TrimSpace(strings.Join(nonEmpty(active.detail, enabled.detail), "; ")); detail != "" {
			summary += " (" + detail + ")"
		}
		diagnostics = append(diagnostics, diagnosticItem("runtime:"+unit.id, status, summary, domain.DiagnosticScopeService, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin))
	}
	return fields, diagnostics
}

func probeSystemdState(parent context.Context, action string, unit string) commandState {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return commandState{value: "not_applicable", status: domain.DiagnosticStatusNotApplicable}
	}
	ctx, cancel := context.WithTimeout(parentOrBackground(parent), runtimeProbeTimeout)
	defer cancel()
	output, err := runRuntimeCommand(ctx, "systemctl", action, unit)
	value := firstOutputToken(output)
	if ctx.Err() != nil {
		return commandState{value: runtimeStateValue(value), status: domain.DiagnosticStatusUnknown, detail: ctx.Err().Error()}
	}
	if action == "is-active" {
		return activeState(value, err)
	}
	return enabledState(value, err)
}

func activeState(value string, err error) commandState {
	switch value {
	case "active":
		return commandState{value: value, status: domain.DiagnosticStatusPass}
	case "activating", "deactivating", "reloading":
		return commandState{value: value, status: domain.DiagnosticStatusWarn}
	case "failed", "inactive", "unknown":
		detail := commandErrorDetail(err)
		if detail == "" {
			detail = "systemd unit is " + value
		}
		return commandState{value: value, status: domain.DiagnosticStatusFail, detail: detail}
	case "":
		return commandState{value: "unknown", status: domain.DiagnosticStatusUnknown, detail: commandErrorDetail(err)}
	default:
		if err != nil {
			return commandState{value: value, status: domain.DiagnosticStatusUnknown, detail: commandErrorDetail(err)}
		}
		return commandState{value: value, status: domain.DiagnosticStatusWarn}
	}
}

func enabledState(value string, err error) commandState {
	switch value {
	case "enabled", "static", "generated", "alias", "indirect":
		return commandState{value: value, status: domain.DiagnosticStatusPass}
	case "disabled", "masked", "bad", "unknown":
		detail := commandErrorDetail(err)
		if detail == "" {
			detail = "systemd unit is " + value
		}
		return commandState{value: value, status: domain.DiagnosticStatusFail, detail: detail}
	case "":
		return commandState{value: "unknown", status: domain.DiagnosticStatusUnknown, detail: commandErrorDetail(err)}
	default:
		if err != nil {
			return commandState{value: value, status: domain.DiagnosticStatusUnknown, detail: commandErrorDetail(err)}
		}
		return commandState{value: value, status: domain.DiagnosticStatusWarn}
	}
}

func commandErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstOutputToken(output []byte) string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(string(output))))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func runtimeStateValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func combineRuntimeStatuses(statuses ...domain.DiagnosticStatus) domain.DiagnosticStatus {
	result := domain.DiagnosticStatusPass
	for _, status := range statuses {
		switch status {
		case domain.DiagnosticStatusFail:
			return domain.DiagnosticStatusFail
		case domain.DiagnosticStatusUnknown:
			if result != domain.DiagnosticStatusFail {
				result = domain.DiagnosticStatusUnknown
			}
		case domain.DiagnosticStatusWarn, domain.DiagnosticStatusManual:
			if result == domain.DiagnosticStatusPass {
				result = status
			}
		}
	}
	return result
}

func nonEmpty(values ...string) []string {
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func parentOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func RunOnboardingStatus(ctx Context, path string) (OperationResult, error) {
	if strings.TrimSpace(path) == "" {
		return OperationResult{}, fmt.Errorf("config path is required")
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		return OperationResult{
			Kind:    domain.JobKindStatus,
			Status:  domain.JobStatusFailed,
			Summary: "onboarding readiness could not load main config",
			Diagnostics: []domain.DiagnosticItem{
				diagnosticItem("onboarding:config", domain.DiagnosticStatusFail, err.Error(), domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin),
			},
			RetryCommand: ShellCommand("lanpanel", "verify", "--config", path),
		}, nil
	}
	fields := []domain.ResultField{
		{Label: "server url", Value: cfg.Default.ServerURL},
		{Label: "login server", Value: cfg.Default.ServerURL},
		{Label: "base domain", Value: cfg.Default.BaseDomain},
		{Label: "default onboarding user", Value: "lanpanel"},
		{Label: "minimum client version", Value: "Tailscale >= v" + verify.MinimumTailscaleClientVersion},
		{Label: "derp/stun baseline", Value: "embedded Headscale baseline from rendered config"},
	}
	_, serviceDiagnostics := runtimeUnitEvidence(ctx.stdContext(), []runtimeUnit{{id: "onboarding-headscale-service", label: "Headscale service", unit: headscale.ServiceName}})
	diagnostics := []domain.DiagnosticItem{
		diagnosticItem("onboarding:login-server", domain.DiagnosticStatusPass, "login server is derived from default.server_url", domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin),
		diagnosticItem("onboarding:magicdns", domain.DiagnosticStatusPass, "MagicDNS suffix is derived from default.base_domain", domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin),
		diagnosticItem("onboarding:client-version", domain.DiagnosticStatusManual, "Client machine must run Tailscale-compatible client >= v"+verify.MinimumTailscaleClientVersion, domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceManual, domain.DiagnosticResponsibleLocalAdmin),
		diagnosticItem("onboarding:derp-stun", domain.DiagnosticStatusPass, "Rendered Headscale baseline provides embedded DERP/STUN configuration", domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLanPanel),
	}
	diagnostics = append(serviceDiagnostics, diagnostics...)
	diagnostics = append(diagnostics, headscaleUserDiagnostic(ctx.stdContext(), "lanpanel"))
	status := domain.JobStatusSucceeded
	if hasFailedDiagnostic(diagnostics) {
		status = domain.JobStatusFailed
	}
	return OperationResult{
		Kind:         domain.JobKindStatus,
		Status:       status,
		Summary:      "onboarding readiness evidence collected",
		Fields:       fields,
		Diagnostics:  diagnostics,
		RetryCommand: ShellCommand("lanpanel", "ui", "--config", path),
	}, nil
}

func headscaleUserDiagnostic(parent context.Context, user string) domain.DiagnosticItem {
	ctx, cancel := context.WithTimeout(parentOrBackground(parent), runtimeProbeTimeout)
	defer cancel()
	output, err := runRuntimeCommand(ctx, "headscale", "--config", "/etc/headscale/config.yaml", "users", "list", "--output", "json")
	if ctx.Err() != nil {
		return diagnosticItem("onboarding:user", domain.DiagnosticStatusUnknown, "Headscale user readiness probe timed out: "+ctx.Err().Error(), domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin)
	}
	if err != nil {
		return diagnosticItem("onboarding:user", domain.DiagnosticStatusUnknown, "Headscale user readiness is unknown: "+err.Error(), domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin)
	}
	if _, parseErr := headscale.FindUserID(string(output), user); parseErr == nil {
		return diagnosticItem("onboarding:user", domain.DiagnosticStatusPass, "Headscale onboarding user "+user+" exists and can be reused", domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin)
	} else {
		var notFound headscale.UserNotFoundError
		if !errors.As(parseErr, &notFound) {
			return diagnosticItem("onboarding:user", domain.DiagnosticStatusUnknown, "Headscale user list could not be parsed: "+parseErr.Error(), domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin)
		}
	}
	return diagnosticItem("onboarding:user", domain.DiagnosticStatusUnknown, "Headscale onboarding user "+user+" is not present yet; preauth handoff will create or verify it", domain.DiagnosticScopeHeadscale, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin)
}
