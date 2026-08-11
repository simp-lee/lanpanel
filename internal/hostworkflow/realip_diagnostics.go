package hostworkflow

import (
	"context"
	"fmt"
	"io/fs"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apphost"
	"lanpanel/internal/components/appsvc"
	"lanpanel/internal/domain"
	"lanpanel/internal/host"
	"lanpanel/internal/preflight"
	"lanpanel/internal/realip"
	"lanpanel/internal/realip/edgeone"
	"lanpanel/internal/realipassets"
	"lanpanel/internal/workflow"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
)

type RealIPDiagnosticsOptions struct {
	DetectPermissions func() preflight.PermissionState
	LoadAppConfig     func(string, string) (appconfig.Config, error)
	RuntimeConfigPath func(string) (string, error)
	AcquireLock       func(string) (RealIPProfileLock, error)
	FileSystem        func(preflight.PermissionState) host.FileSystem
	ReadProfile       func(string) (realip.ProfileConfig, error)
	ReadState         func(string, string) (realip.State, error)
	ReadReferences    func(string) ([]realip.Reference, error)
	LoadCredentials   func(edgeone.FileSystem, string) (edgeone.Credentials, error)
	LstatArtifact     func(string) (fs.FileInfo, error)
	ReadArtifact      func(string) ([]byte, error)
	CredentialFileSys edgeone.FileSystem
}

type RealIPDiagnosticsResult struct {
	Operation    workflow.OperationResult
	OutputStatus string
	NextSteps    []string
}

type RealIPProfileLock = apphost.RealIPProfileLock

func RealIPDiagnostics(ctx context.Context, appConfigPath string, profileName string) (RealIPDiagnosticsResult, error) {
	return RealIPDiagnosticsWithOptions(ctx, appConfigPath, profileName, RealIPDiagnosticsOptions{})
}

func RealIPDiagnosticsWithOptions(ctx context.Context, appConfigPath string, profileName string, options RealIPDiagnosticsOptions) (result RealIPDiagnosticsResult, returnErr error) {
	retryCommand := workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profileName)
	if err := ctx.Err(); err != nil {
		result.Operation = realIPDiagnosticsOperation("failed", domain.JobStatusFailed, domain.DiagnosticStatusFail, "realip diagnostics canceled before host workflow started", nil, retryCommand)
		result.OutputStatus = "failed"
		return result, err
	}

	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return realIPDiagnosticsFailure("invalid-profile", "--profile is required", nil, []string{"Pass --profile with the deployed realip profile name."}, retryCommand)
	}
	appConfigPath = strings.TrimSpace(appConfigPath)
	if appConfigPath == "" {
		return realIPDiagnosticsFailure("invalid-config", "--config is required", nil, []string{"Pass --config with the app config that selects the deployed realip profile."}, retryCommand)
	}

	options = fillRealIPDiagnosticsOptions(options)
	if _, err := options.LoadAppConfig(appConfigPath, profileName); err != nil {
		return realIPDiagnosticsConfigFailure(appConfigPath, profileName, err, retryCommand)
	}
	runtimeConfigPath, err := options.RuntimeConfigPath(appConfigPath)
	if err != nil {
		return realIPDiagnosticsConfigFailure(appConfigPath, profileName, err, retryCommand)
	}

	permissions := options.DetectPermissions()
	if !permissions.IsRoot {
		result := realIPDiagnosticsOperation("blocked", domain.JobStatusFailed, domain.DiagnosticStatusFail, "app realip diagnostics preflight found 1 failed check", []domain.ResultField{{Label: "check permissions", Value: permissionDetail("app realip diagnostics", permissions)}}, retryCommand)
		return RealIPDiagnosticsResult{Operation: result, OutputStatus: "blocked", NextSteps: []string{"Retry RealIP diagnostics from the Management UI."}}, fmt.Errorf("app realip diagnostics: %s", result.Summary)
	}

	names, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, "")
	if err != nil {
		return realIPDiagnosticsFailure("invalid-profile", "Realip profile diagnostics failed", []domain.ResultField{{Label: "profile", Value: profileName}, {Label: "details", Value: err.Error()}}, []string{"Pass a deployed EdgeOne realip profile name."}, retryCommand)
	}
	lock, err := options.AcquireLock(profileName)
	if err != nil {
		return realIPDiagnosticsDeployedFailure(profileName, names, err, retryCommand)
	}
	defer func() {
		if err := lock.Release(); err != nil {
			if returnErr != nil {
				returnErr = fmt.Errorf("%w; release EdgeOne realip profile lock failed: %v", returnErr, err)
				return
			}
			returnErr = err
		}
	}()

	if err := apphost.GuardRealIPProfileDirectories(options.FileSystem(permissions), names); err != nil {
		return realIPDiagnosticsDeployedFailure(profileName, names, err, retryCommand)
	}
	profile, err := options.ReadProfile(names.MetadataPath)
	if err != nil {
		return realIPDiagnosticsDeployedFailure(profileName, names, err, retryCommand)
	}
	state, err := options.ReadState(names.StatePath, profileName)
	if err != nil {
		return realIPDiagnosticsDeployedFailure(profileName, names, err, retryCommand)
	}
	if err := apphost.EnsureDeployedRealIPStateMatchesProfile(profile, state); err != nil {
		return realIPDiagnosticsDeployedFailure(profileName, names, err, retryCommand)
	}
	references, err := options.ReadReferences(names.ReferenceDir)
	if err != nil {
		return realIPDiagnosticsDeployedFailure(profileName, names, err, retryCommand)
	}
	if len(references) == 0 {
		return realIPDiagnosticsDeployedFailure(profileName, names, fmt.Errorf("no deployed app references found for realip profile %s", profileName), retryCommand)
	}

	fields := []domain.ResultField{
		{Label: "profile", Value: profile.Name + " (" + profile.Provider + ")"},
		{Label: "zone id", Value: profile.ZoneID},
		{Label: "refresh interval", Value: profile.RefreshInterval},
		{Label: "edgeone env file", Value: profile.EnvFile},
		{Label: "deployed references", Value: summarizeRealIPReferences(references)},
	}
	fields = append(fields, realIPRuntimeFields(names, state, "deployed state read; run refresh to validate nginx -t and reload")...)
	failures := []string{}
	credentialStatus := "passed"
	if _, err := options.LoadCredentials(options.CredentialFileSys, profile.EnvFile); err != nil {
		credentialStatus = "failed: " + err.Error()
		failures = append(failures, "edgeone credential/env file: "+err.Error())
	}
	fields = append(fields, domain.ResultField{Label: "edgeone credential/env file", Value: credentialStatus})

	marker := apphost.RealIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne)
	for _, item := range []struct {
		label    string
		path     string
		validate func(string) error
		success  string
	}{
		{label: "realip nginx include status", path: names.NginxIncludePath, validate: func(path string) error {
			return validateDeployedRealIPNginxInclude(path, marker, state.TrustedCIDRs, options.ReadArtifact)
		}, success: ", CIDRs match state"},
		{label: "realip trusted CIDR include status", path: names.TrustedCIDRPath, validate: func(path string) error {
			return validateDeployedRealIPTrustedCIDRInclude(path, marker, state.TrustedCIDRs, options.ReadArtifact)
		}, success: ", CIDRs match state"},
		{label: "realip refresh service status", path: names.RefreshServicePath, validate: func(path string) error {
			return validateDeployedRealIPRefreshService(path, marker, profileName, runtimeConfigPath, options.ReadArtifact)
		}, success: ", command matches profile and app config"},
		{label: "realip refresh timer status", path: names.RefreshTimerPath, validate: func(path string) error {
			return validateDeployedRealIPRefreshTimer(path, marker, profile, options.ReadArtifact)
		}, success: ", timer matches profile"},
	} {
		status, err := deployedRealIPRegularFileStatus(item.path, options.LstatArtifact)
		if err == nil && item.validate != nil {
			if validateErr := item.validate(item.path); validateErr != nil {
				status = "invalid: " + validateErr.Error()
				err = validateErr
			} else {
				status += item.success
			}
		}
		fields = append(fields, domain.ResultField{Label: item.label, Value: status})
		if err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		fields = append(fields, domain.ResultField{Label: "details", Value: strings.Join(failures, "; ")})
		result.Operation = realIPDiagnosticsOperation("failed", domain.JobStatusFailed, domain.DiagnosticStatusFail, "Realip profile diagnostics failed", fields, retryCommand)
		result.OutputStatus = "failed"
		result.NextSteps = []string{"Fix the reported deployed realip profile, credential, or runtime file issue and rerun diagnostics."}
		return result, fmt.Errorf("app realip diagnostics: %s", result.Operation.Summary)
	}
	result.Operation = realIPDiagnosticsOperation("passed", domain.JobStatusSucceeded, domain.DiagnosticStatusPass, "Realip profile diagnostics passed", fields, retryCommand)
	result.OutputStatus = "passed"
	result.NextSteps = []string{
		"Run " + workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", runtimeConfigPath, "--profile", profileName) + " after EdgeOne OriginACL changes; include --confirmation origin-protection-manual only if the exposure plan requires it.",
		"Keep cloud security group or host firewall allowlists aligned with current+next CIDRs.",
	}
	return result, nil
}

func fillRealIPDiagnosticsOptions(options RealIPDiagnosticsOptions) RealIPDiagnosticsOptions {
	if options.DetectPermissions == nil {
		options.DetectPermissions = detectPermissionState
	}
	if options.LoadAppConfig == nil {
		options.LoadAppConfig = loadRealIPAppConfigProfile
	}
	if options.RuntimeConfigPath == nil {
		options.RuntimeConfigPath = realIPRuntimeAppConfigPath
	}
	if options.AcquireLock == nil {
		options.AcquireLock = apphost.AcquireRealIPProfileLock
	}
	if options.FileSystem == nil {
		options.FileSystem = func(permissions preflight.PermissionState) host.FileSystem {
			if !permissions.IsRoot && permissions.SudoWorks {
				return host.NewCommandFileSystem(host.NewExecutor(nil, nil).WithPrivilege(host.PrivilegeSudo))
			}
			return host.OSFileSystem{}
		}
	}
	if options.ReadProfile == nil {
		options.ReadProfile = apphost.ReadDeployedRealIPProfile
	}
	if options.ReadState == nil {
		options.ReadState = apphost.ReadDeployedRealIPState
	}
	if options.ReadReferences == nil {
		options.ReadReferences = apphost.ReadDeployedRealIPReferences
	}
	if options.LoadCredentials == nil {
		options.LoadCredentials = edgeone.LoadCredentialsFromEnvFile
	}
	if options.LstatArtifact == nil {
		options.LstatArtifact = os.Lstat
	}
	if options.ReadArtifact == nil {
		options.ReadArtifact = os.ReadFile
	}
	if options.CredentialFileSys == nil {
		options.CredentialFileSys = edgeone.OSFileSystem{}
	}
	return options
}

func realIPDiagnosticsFailure(outputStatus string, summary string, fields []domain.ResultField, nextSteps []string, retryCommand string) (RealIPDiagnosticsResult, error) {
	result := RealIPDiagnosticsResult{
		Operation:    realIPDiagnosticsOperation(outputStatus, domain.JobStatusFailed, domain.DiagnosticStatusFail, summary, fields, retryCommand),
		OutputStatus: outputStatus,
		NextSteps:    append([]string(nil), nextSteps...),
	}
	return result, fmt.Errorf("app realip diagnostics: %s", result.Operation.Summary)
}

func realIPDiagnosticsConfigFailure(configPath string, profileName string, cause error, retryCommand string) (RealIPDiagnosticsResult, error) {
	return realIPDiagnosticsFailure("invalid-config", "Realip app config validation failed", []domain.ResultField{
		{Label: "app config path", Value: configPath},
		{Label: "profile", Value: profileName},
		{Label: "details", Value: cause.Error()},
	}, []string{"Pass the app config whose access.origin_protection.edgeone_profile matches --profile."}, retryCommand)
}

func realIPDiagnosticsDeployedFailure(profileName string, names appsvc.RealIPProfileNames, cause error, retryCommand string) (RealIPDiagnosticsResult, error) {
	fields := []domain.ResultField{
		{Label: "profile", Value: strings.TrimSpace(profileName)},
		{Label: "active include", Value: names.NginxIncludePath},
		{Label: "trusted CIDRs", Value: names.TrustedCIDRPath},
		{Label: "state metadata", Value: names.StatePath},
		{Label: "profile metadata", Value: names.MetadataPath},
		{Label: "reference dir", Value: names.ReferenceDir},
		{Label: "refresh service", Value: names.RefreshServicePath},
		{Label: "refresh timer", Value: names.RefreshTimerPath},
	}
	if cause != nil {
		fields = append(fields, domain.ResultField{Label: "details", Value: cause.Error()})
	}
	return realIPDiagnosticsFailure("failed", "Realip profile diagnostics failed", fields, []string{"Fix the reported deployed realip profile, state, reference, credential, or runtime file issue and rerun diagnostics."}, retryCommand)
}

func realIPDiagnosticsOperation(outputStatus string, jobStatus domain.JobStatus, diagnosticStatus domain.DiagnosticStatus, summary string, fields []domain.ResultField, retryCommand string) workflow.OperationResult {
	summary = strings.TrimSpace(summary)
	if diagnosticStatus == "" || diagnosticStatus == domain.DiagnosticStatusNotApplicable {
		diagnosticStatus = commandDiagnosticStatus(jobStatus)
	}
	return workflow.OperationResult{
		Kind:         domain.JobKindRealIPDiagnostics,
		Status:       jobStatus,
		Summary:      summary,
		Fields:       append([]domain.ResultField(nil), fields...),
		RetryCommand: strings.TrimSpace(retryCommand),
		Diagnostics: []domain.DiagnosticItem{{
			ID:               "realip-diagnostics:" + strings.NewReplacer(" ", "-", "_", "-").Replace(strings.TrimSpace(outputStatus)),
			Title:            "app realip diagnostics",
			Status:           diagnosticStatus,
			Scope:            domain.DiagnosticScopeRealIP,
			Severity:         commandDiagnosticSeverity(diagnosticStatus),
			Summary:          summary,
			EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
			ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
			BlocksActivation: diagnosticStatus == domain.DiagnosticStatusFail,
			Redaction:        domain.RedactionNone,
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		}},
		Progress: progressEvents(domain.JobKindRealIPDiagnostics, diagnosticStatus),
	}
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
		if _, err := host.NewExecutor(nil, nil).Run(context.Background(), host.Command{Name: "sudo", Args: []string{"-n", "true"}}); err == nil {
			state.SudoWorks = true
		}
	}
	return state
}

func realIPRuntimeFields(names appsvc.RealIPProfileNames, state realip.State, nginxStatus string) []domain.ResultField {
	return []domain.ResultField{
		{Label: "realip nginx include", Value: names.NginxIncludePath},
		{Label: "realip trusted CIDR include", Value: names.TrustedCIDRPath},
		{Label: "realip current CIDRs", Value: listAsNone(state.CurrentCIDRs)},
		{Label: "realip next CIDRs", Value: listAsNone(state.NextCIDRs)},
		{Label: "realip trusted CIDRs", Value: listAsNone(state.TrustedCIDRs)},
		{Label: "realip state", Value: names.StatePath},
		{Label: "realip refresh timer", Value: names.RefreshTimerUnit},
		{Label: "realip updated at", Value: timeAsNone(state.UpdatedAt)},
		{Label: "origin acl status", Value: emptyAsNone(state.OriginACLStatus)},
		{Label: "origin acl family", Value: emptyAsNone(state.OriginACLFamily)},
		{Label: "current acl version", Value: emptyAsNone(state.CurrentVersion)},
		{Label: "current active time", Value: emptyAsNone(state.CurrentActiveTime)},
		{Label: "next acl version", Value: emptyAsNone(state.NextVersion)},
		{Label: "next active time", Value: emptyAsNone(state.NextActiveTime)},
		{Label: "planned active time", Value: emptyAsNone(state.PlannedActiveTime)},
		{Label: "nginx realip active", Value: nginxStatus},
	}
}

func summarizeRealIPReferences(references []realip.Reference) string {
	if len(references) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(references))
	for _, reference := range references {
		parts = append(parts, reference.AppName+"="+strings.Join(reference.Domains, ","))
	}
	return strings.Join(parts, "; ")
}

func deployedRealIPRegularFileStatus(path string, lstat func(string) (fs.FileInfo, error)) (string, error) {
	info, err := lstat(path)
	if err != nil {
		return "missing: " + err.Error(), fmt.Errorf("stat deployed realip artifact %s: %w", path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return "invalid: symlink", fmt.Errorf("deployed realip artifact %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "invalid: not a regular file", fmt.Errorf("deployed realip artifact %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("invalid: mode %04o is group/other writable", info.Mode().Perm()), fmt.Errorf("deployed realip artifact %s must not be writable by group or others", path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return "invalid: owner could not be inspected", fmt.Errorf("deployed realip artifact %s owner could not be inspected", path)
	}
	if uid != 0 {
		return fmt.Sprintf("invalid: owner uid %d", uid), fmt.Errorf("deployed realip artifact %s must be owned by root", path)
	}
	return fmt.Sprintf("present root-owned mode %04o", info.Mode().Perm()), nil
}

func validateDeployedRealIPNginxInclude(path string, marker string, expectedCIDRs []string, readArtifact func(string) ([]byte, error)) error {
	content, err := readArtifact(path)
	if err != nil {
		return fmt.Errorf("read deployed realip artifact %s: %w", path, err)
	}
	text := string(content)
	if !strings.Contains(text, "# "+marker) {
		return fmt.Errorf("deployed realip artifact %s missing marker %q", path, marker)
	}
	cidrs, err := parseSetRealIPFromCIDRs(path, text)
	if err != nil {
		return err
	}
	return requireCIDRListMatch(path, cidrs, expectedCIDRs)
}

func validateDeployedRealIPTrustedCIDRInclude(path string, marker string, expectedCIDRs []string, readArtifact func(string) ([]byte, error)) error {
	content, err := readArtifact(path)
	if err != nil {
		return fmt.Errorf("read deployed realip artifact %s: %w", path, err)
	}
	text := string(content)
	if !strings.Contains(text, "# "+marker) {
		return fmt.Errorf("deployed realip artifact %s missing marker %q", path, marker)
	}
	cidrs, err := parseTrustedCIDRGeoEntries(path, text)
	if err != nil {
		return err
	}
	return requireCIDRListMatch(path, cidrs, expectedCIDRs)
}

func validateDeployedRealIPRefreshService(path string, marker string, profileName string, configPath string, readArtifact func(string) ([]byte, error)) error {
	text, err := readDeployedRealIPArtifactText(path, readArtifact)
	if err != nil {
		return err
	}
	if err := requireDeployedRealIPMarker(path, text, marker); err != nil {
		return err
	}
	for _, line := range []string{"Type=oneshot", "TimeoutStartSec=2min"} {
		if !hasTrimmedLine(text, line) {
			return fmt.Errorf("deployed realip artifact %s missing line %q", path, line)
		}
	}
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return fmt.Errorf("deployed realip artifact %s refresh service validation requires an app config path", path)
	}
	expected := "ExecStart=" + realipassets.DefaultRefreshBinaryPath + " app realip refresh --config " + configPath + " --profile " + strings.TrimSpace(profileName)
	execStartLines := deployedRealIPRefreshExecStartLines(text)
	if len(execStartLines) != 1 {
		return fmt.Errorf("deployed realip artifact %s must contain exactly one ExecStart line, found %d", path, len(execStartLines))
	}
	if execStartLines[0] != expected {
		return fmt.Errorf("deployed realip artifact %s ExecStart line %q must be %q", path, execStartLines[0], expected)
	}
	return nil
}

func deployedRealIPRefreshExecStartLines(text string) []string {
	lines := []string{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "ExecStart=") {
			lines = append(lines, line)
		}
	}
	return lines
}

func validateDeployedRealIPRefreshTimer(path string, marker string, profile realip.ProfileConfig, readArtifact func(string) ([]byte, error)) error {
	text, err := readDeployedRealIPArtifactText(path, readArtifact)
	if err != nil {
		return err
	}
	if err := requireDeployedRealIPMarker(path, text, marker); err != nil {
		return err
	}
	refreshInterval, err := realip.SystemdRefreshInterval(profile.RefreshInterval)
	if err != nil {
		return fmt.Errorf("derive deployed realip refresh timer interval for %s: %w", path, err)
	}
	for _, line := range []string{"OnBootSec=15m", "OnUnitActiveSec=" + refreshInterval, "RandomizedDelaySec=30m", "Persistent=true", "WantedBy=timers.target"} {
		if !hasTrimmedLine(text, line) {
			return fmt.Errorf("deployed realip artifact %s missing line %q", path, line)
		}
	}
	return nil
}

func readDeployedRealIPArtifactText(path string, readArtifact func(string) ([]byte, error)) (string, error) {
	content, err := readArtifact(path)
	if err != nil {
		return "", fmt.Errorf("read deployed realip artifact %s: %w", path, err)
	}
	return string(content), nil
}

func requireDeployedRealIPMarker(path string, text string, marker string) error {
	if !strings.Contains(text, "# "+marker) {
		return fmt.Errorf("deployed realip artifact %s missing marker %q", path, marker)
	}
	return nil
}

func hasTrimmedLine(text string, want string) bool {
	for _, raw := range strings.Split(text, "\n") {
		if strings.TrimSpace(raw) == want {
			return true
		}
	}
	return false
}

func parseSetRealIPFromCIDRs(path string, text string) ([]string, error) {
	cidrs := []string{}
	for lineNumber, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value, ok := strings.CutPrefix(line, "set_real_ip_from ")
		if !ok || !strings.HasSuffix(value, ";") {
			return nil, fmt.Errorf("deployed realip artifact %s line %d must be set_real_ip_from CIDR;", path, lineNumber+1)
		}
		cidrs = append(cidrs, strings.TrimSpace(strings.TrimSuffix(value, ";")))
	}
	return cidrs, nil
}

func parseTrustedCIDRGeoEntries(path string, text string) ([]string, error) {
	cidrs := []string{}
	for lineNumber, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != "1;" {
			return nil, fmt.Errorf("deployed realip artifact %s line %d must be CIDR 1;", path, lineNumber+1)
		}
		cidrs = append(cidrs, fields[0])
	}
	return cidrs, nil
}

func requireCIDRListMatch(path string, actual []string, expected []string) error {
	if _, err := realip.CanonicalCIDRs(actual); err != nil {
		return fmt.Errorf("validate deployed realip artifact %s CIDRs: %w", path, err)
	}
	if !stringSlicesEqual(actual, expected) {
		return fmt.Errorf("deployed realip artifact %s CIDRs %s do not match deployed state trusted CIDRs %s", path, listAsNone(actual), listAsNone(expected))
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) (uint64, bool) {
	return fileSysUintField(info, "Uid", "UID")
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

func emptyAsNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

func listAsNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func timeAsNone(value time.Time) string {
	if value.IsZero() {
		return "none"
	}
	return value.UTC().Format(time.RFC3339)
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
