package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/appverify"
	"lanpanel/internal/browserauth"
	"lanpanel/internal/components/headscale"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/host"
	"lanpanel/internal/verify"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fieldValue(fields []domain.ResultField, label string) (string, bool) {
	for _, field := range fields {
		if field.Label == label {
			return field.Value, true
		}
	}
	return "", false
}

func manualOriginProtectionObservation() exposure.AppObservations {
	return exposure.AppObservations{OriginProtectionStatus: domain.OriginProtectionConfiguredManual}
}

func passOriginProtectionObservation() exposure.AppObservations {
	return exposure.AppObservations{
		OriginProtectionStatus:          domain.OriginProtectionConfiguredPass,
		OriginProtectionReferenceDigest: "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		RealIPTrustedCIDRCount:          2,
		RealIPClientIPHeader:            appconfig.RealIPHeaderEdgeOne,
		RealIPSpoofingRejection:         domain.DiagnosticStatusPass,
	}
}

func originProtectionManualConfirmationRecord() domain.ManualConfirmation {
	return domain.ManualConfirmation{
		ConfirmationID: "evt_20260620T120000Z_00112233",
		Reason:         "origin_firewall_confirmed",
		Actor:          domain.Actor{Source: domain.ActorSourceCLI, EffectiveUID: 1000, EffectiveUser: "uid:1000"},
		ConfirmedAt:    "2026-06-20T12:00:00Z",
	}
}

func fixedManualConfirmationRecorder(records ...domain.ManualConfirmation) ManualConfirmationRecorder {
	return func([]string) ([]domain.ManualConfirmation, error) {
		return append([]domain.ManualConfirmation(nil), records...), nil
	}
}

func progressContains(events []ProgressEvent, message string) bool {
	for _, event := range events {
		if event.Message == message {
			return true
		}
	}
	return false
}

func TestStoreUploadedDependencyInstallsVerifiedArtifact(t *testing.T) {
	root := t.TempDir()
	restoreRoot := UnsafeSetDependencyUploadCacheRootForTest(root)
	t.Cleanup(restoreRoot)
	expectedName := "lego_expected_linux_amd64.tar.gz"
	source := filepath.Join(t.TempDir(), expectedName)
	content := []byte("verified artifact")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatalf("WriteFile(source) error = %v", err)
	}
	sum := sha256.Sum256(content)
	expectedSHA := hex.EncodeToString(sum[:])

	finalPath, err := storeUploadedDependency("lego", UploadedDependencyArtifact{Path: source, Filename: expectedName, Size: int64(len(content))}, expectedName, expectedSHA)
	if err != nil {
		t.Fatalf("storeUploadedDependency() error = %v", err)
	}
	if finalPath != filepath.Join(root, "lego", expectedName) {
		t.Fatalf("finalPath = %q, want cache path under test root", finalPath)
	}
	stored, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("ReadFile(finalPath) error = %v", err)
	}
	if string(stored) != string(content) {
		t.Fatalf("stored content = %q, want %q", stored, content)
	}
}

func TestStoreUploadedDependencyRejectsUnexpectedFilename(t *testing.T) {
	root := t.TempDir()
	restoreRoot := UnsafeSetDependencyUploadCacheRootForTest(root)
	t.Cleanup(restoreRoot)
	source := filepath.Join(t.TempDir(), "renamed.tar.gz")
	if err := os.WriteFile(source, []byte("artifact"), 0o600); err != nil {
		t.Fatalf("WriteFile(source) error = %v", err)
	}
	expectedName := "lego_expected_linux_amd64.tar.gz"
	_, err := storeUploadedDependency("lego", UploadedDependencyArtifact{Path: source, Filename: "renamed.tar.gz", Size: 8}, expectedName, strings.Repeat("a", 64))
	if err == nil || !strings.Contains(err.Error(), "must be named "+expectedName) {
		t.Fatalf("storeUploadedDependency() error = %v, want expected filename rejection", err)
	}
}

func TestStoreUploadedDependencyRejectsUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	restoreRoot := UnsafeSetDependencyUploadCacheRootForTest(root)
	t.Cleanup(restoreRoot)
	expectedName := "lego_expected_linux_amd64.tar.gz"
	source := filepath.Join(t.TempDir(), expectedName)
	content := []byte("verified artifact")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatalf("WriteFile(source) error = %v", err)
	}
	sum := sha256.Sum256(content)
	expectedSHA := hex.EncodeToString(sum[:])

	_, err := storeUploadedDependency("nginx", UploadedDependencyArtifact{Path: source, Filename: expectedName, Size: int64(len(content))}, expectedName, expectedSHA)
	if err == nil || !strings.Contains(err.Error(), "dependency kind must be one of") {
		t.Fatalf("storeUploadedDependency(invalid kind) error = %v, want kind rejection", err)
	}

	linkPath := filepath.Join(t.TempDir(), expectedName)
	if err := os.Symlink(source, linkPath); err != nil {
		t.Fatalf("Symlink(source) error = %v", err)
	}
	_, err = storeUploadedDependency("lego", UploadedDependencyArtifact{Path: linkPath, Filename: expectedName, Size: int64(len(content))}, expectedName, expectedSHA)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("storeUploadedDependency(source symlink) error = %v, want symlink rejection", err)
	}
}

func TestStoreUploadedDependencyRejectsSymlinkCacheRoot(t *testing.T) {
	dir := t.TempDir()
	targetRoot := filepath.Join(dir, "target")
	if err := os.Mkdir(targetRoot, 0o755); err != nil {
		t.Fatalf("Mkdir(targetRoot) error = %v", err)
	}
	rootLink := filepath.Join(dir, "cache")
	if err := os.Symlink(targetRoot, rootLink); err != nil {
		t.Fatalf("Symlink(cache root) error = %v", err)
	}
	restoreRoot := UnsafeSetDependencyUploadCacheRootForTest(rootLink)
	t.Cleanup(restoreRoot)
	expectedName := "lego_expected_linux_amd64.tar.gz"
	source := filepath.Join(t.TempDir(), expectedName)
	content := []byte("verified artifact")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatalf("WriteFile(source) error = %v", err)
	}
	sum := sha256.Sum256(content)
	expectedSHA := hex.EncodeToString(sum[:])

	_, err := storeUploadedDependency("lego", UploadedDependencyArtifact{Path: source, Filename: expectedName, Size: int64(len(content))}, expectedName, expectedSHA)
	if err == nil || !strings.Contains(err.Error(), "dependency upload cache root must not be a symlink") {
		t.Fatalf("storeUploadedDependency(cache root symlink) error = %v, want cache root symlink rejection", err)
	}
}

type realIPReferenceFileInfo struct {
	name string
	mode fs.FileMode
	sys  any
}

func (info realIPReferenceFileInfo) Name() string       { return info.name }
func (info realIPReferenceFileInfo) Size() int64        { return 128 }
func (info realIPReferenceFileInfo) Mode() fs.FileMode  { return info.mode }
func (info realIPReferenceFileInfo) ModTime() time.Time { return fixedWorkflowNow() }
func (info realIPReferenceFileInfo) IsDir() bool        { return false }
func (info realIPReferenceFileInfo) Sys() any           { return info.sys }

func TestRunPreAuthKeyCreateKeepsSecretOneTimeAndOutOfJSON(t *testing.T) {
	t.Parallel()

	creator := &fakePreAuthKeyCreator{key: "hskey-auth-real"}
	result, err := RunPreAuthKeyCreate(Context{
		Version:           "test",
		PreAuthKeyCreator: creator,
		Now:               fixedWorkflowNow,
	}, "lanpanel", time.Hour)
	if err != nil {
		t.Fatalf("RunPreAuthKeyCreate() error = %v", err)
	}
	if creator.plan.UserName != "lanpanel" || creator.plan.Expiration != time.Hour {
		t.Fatalf("plan = %#v, want lanpanel 1h plan", creator.plan)
	}
	if err := ValidateNoSecretOutput(result); err != nil {
		t.Fatalf("ValidateNoSecretOutput() error = %v", err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(data), "hskey-auth-real") {
		t.Fatalf("JSON leaked preauth key: %s", data)
	}
	first, ok := result.OneTimeSecret.Consume()
	if !ok || first != "hskey-auth-real" {
		t.Fatalf("first Consume() = %q, %v", first, ok)
	}
	second, ok := result.OneTimeSecret.Consume()
	if ok || second != "" {
		t.Fatalf("second Consume() = %q, %v; want empty false", second, ok)
	}
}

func TestRunPreAuthKeyCreateRequiresHeadscaleCreator(t *testing.T) {
	t.Parallel()

	result, err := RunPreAuthKeyCreate(Context{Version: "test", Now: fixedWorkflowNow}, "lanpanel", time.Hour)
	if err == nil {
		t.Fatal("RunPreAuthKeyCreate() error = nil, want missing creator failure")
	}
	if result.Kind != domain.JobKindPreAuthKeyCreate || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunPreAuthKeyCreate() result = %#v, want typed failed preauth result", result)
	}
	if result.RetryCommand != "Management UI" {
		t.Fatalf("RetryCommand = %q, want Management UI", result.RetryCommand)
	}
	if !progressContains(result.Progress, "preauth key handoff failed") {
		t.Fatalf("Progress = %#v, want failed handoff progress", result.Progress)
	}
}

func TestRunPreAuthKeyCreateRejectsLongTTLBeforeCreator(t *testing.T) {
	t.Parallel()

	creator := &fakePreAuthKeyCreator{key: "hskey-auth-real"}
	result, err := RunPreAuthKeyCreate(Context{Version: "test", PreAuthKeyCreator: creator, Now: fixedWorkflowNow}, "lanpanel", headscale.MaxPreAuthKeyExpiration+time.Hour)
	if err == nil {
		t.Fatal("RunPreAuthKeyCreate() error = nil, want long TTL failure")
	}
	if result.Kind != domain.JobKindPreAuthKeyCreate || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunPreAuthKeyCreate() result = %#v, want typed failed preauth result", result)
	}
	if result.RetryCommand != "Management UI" {
		t.Fatalf("RetryCommand = %q, want Management UI", result.RetryCommand)
	}
	if !progressContains(result.Progress, "preauth key handoff failed") {
		t.Fatalf("Progress = %#v, want failed handoff progress", result.Progress)
	}
	if creator.called {
		t.Fatal("PreAuthKeyCreator was called for rejected TTL")
	}
}

func TestRunPreAuthKeyCreateRedactsCreatorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		secret string
		marker string
	}{
		{name: "tailscale auth key", secret: "tskey-auth-real", marker: "tskey-auth-"},
		{name: "headscale auth key", secret: "hskey-auth-real", marker: "hskey-auth-"},
		{name: "legacy auth key", secret: "authkey-real", marker: "authkey-"},
		{name: "machine key", secret: "mkey:abcdef0123456789", marker: "mkey:"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := RunPreAuthKeyCreate(Context{
				Version:           "test",
				PreAuthKeyCreator: &fakePreAuthKeyCreator{err: errors.New("headscale failed with " + tt.secret)},
				Now:               fixedWorkflowNow,
			}, "lanpanel", time.Hour)
			if err == nil {
				t.Fatal("RunPreAuthKeyCreate() error = nil, want creator failure")
			}
			if result.Kind != domain.JobKindPreAuthKeyCreate || result.Status != domain.JobStatusFailed {
				t.Fatalf("RunPreAuthKeyCreate() result = %#v, want typed failed preauth result", result)
			}
			if strings.Contains(err.Error(), tt.secret) || strings.Contains(err.Error(), tt.marker) {
				t.Fatalf("RunPreAuthKeyCreate() error leaked preauth key: %v", err)
			}
			if strings.Contains(result.Summary, tt.secret) || strings.Contains(result.Summary, tt.marker) {
				t.Fatalf("RunPreAuthKeyCreate() result leaked preauth key: %#v", result)
			}
			if !strings.Contains(err.Error(), "<redacted>") {
				t.Fatalf("RunPreAuthKeyCreate() error = %v, want redacted marker", err)
			}
		})
	}
}

func TestValidateNoSecretOutputRejectsSensitiveResultText(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		result OperationResult
	}{
		{name: "headscale auth key", result: OperationResult{Summary: "created hskey-auth-secret"}},
		{name: "machine key", result: OperationResult{Summary: "created mkey:abcdef0123456789"}},
		{name: "authorization header", result: OperationResult{Summary: "Authorization: Basic abc123"}},
		{name: "bare bearer", result: OperationResult{Summary: "Bearer abc123"}},
		{name: "cookie header", result: OperationResult{Summary: "Cookie: session=abc123"}},
		{name: "natural password", result: OperationResult{Summary: "browser auth password is hunter2"}},
		{name: "natural password mixed with token placeholder", result: OperationResult{Summary: "browser auth password is hunter2 <token>"}},
		{name: "natural password mixed with acme token placeholder", result: OperationResult{Summary: "browser auth password is hunter2 at /.well-known/acme-challenge/<token>"}},
		{name: "progress token", result: OperationResult{Progress: []ProgressEvent{{Message: "progress leaked token=secret-value"}}}},
		{name: "diagnostic auth key", result: OperationResult{Diagnostics: []domain.DiagnosticItem{{Summary: "diagnostic leaked hskey-auth-secret"}}}},
		{name: "next step startup token", result: OperationResult{NextSteps: []string{"open /login?token=secret-value"}}},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateNoSecretOutput(tt.result); err == nil {
				t.Fatalf("ValidateNoSecretOutput(%s) error = nil, want sensitive output failure", tt.name)
			}
		})
	}
}

func TestValidateNoSecretOutputAllowsSafeSensitiveLabels(t *testing.T) {
	t.Parallel()

	result := OperationResult{
		Summary: "preauth key created for one-time handoff",
		Fields: []domain.ResultField{
			{Label: "password fingerprint", Value: "sha256:0011223344556677"},
			{Label: "browser protection", Value: "LanPanel Basic Auth enabled; upstream Authorization header is cleared"},
			{Label: "public exposure risk", Value: "confirmed=true; no LanPanel Basic Auth is rendered"},
			{Label: "checks", Value: "config=pass, secrets=pass, browserauth=pass"},
			{Label: "check secrets", Value: "pass: rendered files do not contain Tailscale auth keys or DNS tokens"},
		},
		NextSteps: []string{"Use the ACME HTTP-01 /.well-known/acme-challenge/<token> placeholder."},
		Progress:  []ProgressEvent{{Message: "preauth key handoff created"}},
	}
	if err := ValidateNoSecretOutput(result); err != nil {
		t.Fatalf("ValidateNoSecretOutput() error = %v, want safe sensitive-label text accepted", err)
	}
}

func TestValidateNoSecretOutputRejectsSensitiveFieldValueBehindSafeLabel(t *testing.T) {
	t.Parallel()

	result := OperationResult{
		Fields: []domain.ResultField{{Label: "password fingerprint", Value: "browser auth password is hunter2"}},
	}
	if err := ValidateNoSecretOutput(result); err == nil {
		t.Fatal("ValidateNoSecretOutput() error = nil, want sensitive field value failure")
	}
}
func TestDiagnosticsCarryMetadata(t *testing.T) {
	t.Parallel()

	mainItems := mainVerifyDiagnostics(verify.Report{Checks: []verify.Check{{ID: "nginx-site", Status: verify.StatusFail, Summary: "bad nginx"}}})
	if len(mainItems) != 1 {
		t.Fatalf("mainItems = %d, want 1", len(mainItems))
	}
	if mainItems[0].Scope != domain.DiagnosticScopeService || mainItems[0].EvidenceSource != domain.DiagnosticEvidenceRenderedFile || mainItems[0].ResponsibleParty != domain.DiagnosticResponsibleLanPanel || mainItems[0].Severity != domain.DiagnosticSeverityCritical || !mainItems[0].BlocksActivation {
		t.Fatalf("main diagnostic metadata = %#v", mainItems[0])
	}
	certItems := mainVerifyDiagnostics(verify.Report{Checks: []verify.Check{{ID: "certificate-plan", Status: verify.StatusPass, Summary: "cert plan ok"}}})
	if len(certItems) != 1 || certItems[0].Scope != domain.DiagnosticScopeCertificate || certItems[0].EvidenceSource != domain.DiagnosticEvidenceConfig {
		t.Fatalf("certificate diagnostic metadata = %#v", certItems)
	}

	appItems := appVerifyDiagnostics(appverify.Report{Checks: []appverify.Check{{ID: "config", Status: appverify.StatusPass, Summary: "valid"}}})
	if len(appItems) != 1 {
		t.Fatalf("appItems = %d, want 1", len(appItems))
	}
	if appItems[0].Scope != domain.DiagnosticScopeResource || appItems[0].EvidenceSource != domain.DiagnosticEvidenceConfig || appItems[0].ResponsibleParty != domain.DiagnosticResponsibleLocalAdmin || appItems[0].Severity != domain.DiagnosticSeverityInfo || appItems[0].BlocksActivation {
		t.Fatalf("app diagnostic metadata = %#v", appItems[0])
	}
	goAccessItems := appVerifyDiagnostics(appverify.Report{Checks: []appverify.Check{{ID: "goaccess", Status: appverify.StatusPass, Summary: "goaccess ok"}}})
	if len(goAccessItems) != 1 || goAccessItems[0].Scope != domain.DiagnosticScopeGoAccess || goAccessItems[0].EvidenceSource != domain.DiagnosticEvidenceRenderedFile {
		t.Fatalf("goaccess diagnostic metadata = %#v", goAccessItems)
	}

	hostItems := hostHealthDiagnostics(domain.HostHealthSummary{
		Host: domain.HostHealthHost{OS: "linux"},
		Checks: domain.HostHealthChecks{NginxConfigTest: []domain.DiagnosticRef{{
			ID:               "nginx-config",
			Status:           domain.DiagnosticStatusFail,
			Scope:            domain.DiagnosticScopeInstance,
			Severity:         domain.DiagnosticSeverityCritical,
			EvidenceSource:   domain.DiagnosticEvidenceRuntimeProbe,
			ResponsibleParty: domain.DiagnosticResponsibleLocalAdmin,
			BlocksActivation: true,
		}}},
	})
	if len(hostItems) != 2 {
		t.Fatalf("hostItems = %d, want summary plus ref", len(hostItems))
	}
	if hostItems[1].Scope != domain.DiagnosticScopeInstance || hostItems[1].EvidenceSource != domain.DiagnosticEvidenceRuntimeProbe || hostItems[1].ResponsibleParty != domain.DiagnosticResponsibleLocalAdmin || hostItems[1].Severity != domain.DiagnosticSeverityCritical || !hostItems[1].BlocksActivation {
		t.Fatalf("host diagnostic metadata = %#v", hostItems[1])
	}
}

func TestOperationRetryCommandsQuoteUnsafeArguments(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mainPath := filepath.Join(dir, "lan panel;a.yaml")
	if err := config.ExampleConfig().WriteFile(mainPath); err != nil {
		t.Fatalf("WriteFile(main) error = %v", err)
	}
	hostWorkflow := &fakeHostWorkflow{}
	mainResult, err := RunMainDeploy(Context{Version: "test", HostWorkflow: hostWorkflow}, mainPath)
	if err != nil {
		t.Fatalf("RunMainDeploy() error = %v", err)
	}
	if mainResult.RetryCommand != "Management UI" {
		t.Fatalf("RetryCommand = %q", mainResult.RetryCommand)
	}

	appPath := filepath.Join(dir, "app config;rm.yaml")
	if err := appconfig.ExampleConfig().WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app) error = %v", err)
	}
	appResult, err := RunAppDeploy(Context{Version: "test", HostWorkflow: hostWorkflow}, appPath, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppDeploy() error = %v", err)
	}
	if appResult.RetryCommand != "Management UI" {
		t.Fatalf("RetryCommand = %q", appResult.RetryCommand)
	}
	if appResult.ExposurePlan == nil || appResult.ExposurePlan.Resource.ID == "" {
		t.Fatalf("RunAppDeploy() ExposurePlan = %#v, want resource linkage", appResult.ExposurePlan)
	}
	if !progressContains(appResult.Progress, "app deploy host workflow started") || !progressContains(appResult.Progress, "app deploy host workflow finished") {
		t.Fatalf("RunAppDeploy() Progress = %#v, want host workflow progress events", appResult.Progress)
	}

	realIPConfigPath := filepath.Join(dir, "realip-app.yaml")
	realIPConfig := appconfig.ExampleConfig()
	realIPConfig.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	realIPConfig.DNS01.Provider = "tencentcloud"
	realIPConfig.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	realIPConfig.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	realIPConfig.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	realIPConfig.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	realIPConfig.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-123456",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := realIPConfig.WriteFile(realIPConfigPath); err != nil {
		t.Fatalf("WriteFile(realip app) error = %v", err)
	}
	confirmedCtx := Context{Version: "test", HostWorkflow: hostWorkflow, Confirmations: []string{"origin-protection-manual"}, ManualConfirmationRecorder: fixedManualConfirmationRecorder(originProtectionManualConfirmationRecord()), ExposureObservations: manualOriginProtectionObservation()}
	realIPResult, err := RunRealIPRefresh(confirmedCtx, realIPConfigPath, "edgeone-prod", "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunRealIPRefresh() error = %v", err)
	}
	if realIPResult.RetryCommand != ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", realIPConfigPath, "--profile", "edgeone-prod", "--confirmation", "origin-protection-manual") {
		t.Fatalf("RetryCommand = %q", realIPResult.RetryCommand)
	}
	if realIPResult.ExposurePlan == nil || realIPResult.ExposurePlan.Resource.ID == "" {
		t.Fatalf("RunRealIPRefresh() ExposurePlan = %#v, want resource linkage", realIPResult.ExposurePlan)
	}
	if realIPResult.ExposurePlan.OriginProtection != domain.OriginProtectionConfiguredManual {
		t.Fatalf("RunRealIPRefresh() OriginProtection = %q, want configured_manual", realIPResult.ExposurePlan.OriginProtection)
	}
	if realIPResult.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionManual {
		t.Fatalf("RunRealIPRefresh() Decision = %q, want manual", realIPResult.ExposurePlan.Decision.Status)
	}
	if len(realIPResult.ExposurePlan.DiagnosticBlockers) != 0 {
		t.Fatalf("RunRealIPRefresh() DiagnosticBlockers = %#v, want none", realIPResult.ExposurePlan.DiagnosticBlockers)
	}
	if !progressContains(realIPResult.Progress, "realip refresh exposure plan evaluated") || !progressContains(realIPResult.Progress, "realip refresh host workflow finished") {
		t.Fatalf("RunRealIPRefresh() Progress = %#v, want exposure and host progress events", realIPResult.Progress)
	}

	edgeOneAppResult, err := RunAppDeploy(confirmedCtx, realIPConfigPath, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppDeploy(edgeone) error = %v", err)
	}
	if edgeOneAppResult.ExposurePlan == nil || edgeOneAppResult.ExposurePlan.Resource.ID == "" {
		t.Fatalf("RunAppDeploy(edgeone) ExposurePlan = %#v, want resource linkage", edgeOneAppResult.ExposurePlan)
	}
	if edgeOneAppResult.ExposurePlan.OriginProtection != domain.OriginProtectionConfiguredManual {
		t.Fatalf("RunAppDeploy(edgeone) OriginProtection = %q, want configured_manual", edgeOneAppResult.ExposurePlan.OriginProtection)
	}
	if edgeOneAppResult.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionManual {
		t.Fatalf("RunAppDeploy(edgeone) Decision = %q, want manual", edgeOneAppResult.ExposurePlan.Decision.Status)
	}
	if len(edgeOneAppResult.ExposurePlan.DiagnosticBlockers) != 0 {
		t.Fatalf("RunAppDeploy(edgeone) DiagnosticBlockers = %#v, want none", edgeOneAppResult.ExposurePlan.DiagnosticBlockers)
	}
	if edgeOneAppResult.RetryCommand != ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", realIPConfigPath, "--confirmation", "origin-protection-manual") {
		t.Fatalf("RunAppDeploy(edgeone) RetryCommand = %q", edgeOneAppResult.RetryCommand)
	}
}

func TestRunRealIPValidateReferenceReturnsTypedResult(t *testing.T) {
	path := "/var/lib/lanpanel/realip/edgeone-prod/references/first.json"
	previousLstat := lstatRealIPReferenceFn
	previousRead := readRealIPReferenceFileFn
	lstatRealIPReferenceFn = func(string) (fs.FileInfo, error) {
		return realIPReferenceFileInfo{name: "first.json", mode: 0o600, sys: &syscall.Stat_t{Uid: 0}}, nil
	}
	readRealIPReferenceFileFn = func(string) ([]byte, error) {
		return []byte(`{"lanpanel_managed":"` + realIPManagedMarker("edgeone-prod", appconfig.RealIPProviderEdgeOne) + `","app_name":"first","profile":"edgeone-prod","domains":[" app.example.com "]}`), nil
	}
	t.Cleanup(func() {
		lstatRealIPReferenceFn = previousLstat
		readRealIPReferenceFileFn = previousRead
	})

	result, err := RunRealIPValidateReference(Context{Version: "test", Now: fixedWorkflowNow}, "edgeone-prod", "first", path)
	if err != nil {
		t.Fatalf("RunRealIPValidateReference() error = %v", err)
	}
	if result.Kind != domain.JobKindRealIPValidateRef || result.Status != domain.JobStatusSucceeded {
		t.Fatalf("RunRealIPValidateReference() result = %#v, want succeeded validate-reference kind", result)
	}
	if got, ok := fieldValue(result.Fields, "domains"); !ok || got != "app.example.com" {
		t.Fatalf("domains field = %q, %v; want trimmed domain", got, ok)
	}
	if result.RetryCommand != "Management UI" {
		t.Fatalf("RetryCommand = %q", result.RetryCommand)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Status != domain.DiagnosticStatusPass {
		t.Fatalf("Diagnostics = %#v, want passing validation diagnostic", result.Diagnostics)
	}
	if !progressContains(result.Progress, "realip reference validation passed") {
		t.Fatalf("Progress = %#v, want validation progress event", result.Progress)
	}
}

func TestRunRealIPValidateReferenceReturnsTypedFailure(t *testing.T) {
	result, err := RunRealIPValidateReference(Context{Version: "test", Now: fixedWorkflowNow}, "edgeone-prod", "first", "/tmp/first.json")
	if err == nil {
		t.Fatal("RunRealIPValidateReference() error = nil, want canonical path failure")
	}
	if result.Kind != domain.JobKindRealIPValidateRef || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunRealIPValidateReference() result = %#v, want failed validate-reference kind", result)
	}
	if !strings.Contains(err.Error(), "must be /var/lib/lanpanel/realip/edgeone-prod/references/first.json") {
		t.Fatalf("RunRealIPValidateReference() error = %v, want canonical path failure", err)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Status != domain.DiagnosticStatusFail {
		t.Fatalf("Diagnostics = %#v, want failing validation diagnostic", result.Diagnostics)
	}
	if !progressContains(result.Progress, "realip reference validation failed") {
		t.Fatalf("Progress = %#v, want failed validation progress event", result.Progress)
	}
}

func TestRunRealIPRefreshRejectsInactiveProfileBeforeHostWorkflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "realip-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-prod",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
		"edgeone-next": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-next",
				EnvFile: "/etc/lanpanel/realip/edgeone-next.env",
			},
		},
	}
	if err := cfg.WriteFile(path); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	result, err := RunRealIPRefresh(Context{Version: "test", HostWorkflow: &fakeHostWorkflow{}, ExposureObservations: manualOriginProtectionObservation()}, path, "edgeone-next", "ins_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("RunRealIPRefresh() error = nil, want inactive profile failure")
	}
	if result.Kind != domain.JobKindRealIPRefresh || result.Status != domain.JobStatusFailed || !strings.Contains(result.Summary, "active origin protection") {
		t.Fatalf("result = %#v, want failed realip refresh diagnostic", result)
	}
	if result.ExposurePlan == nil || result.ExposurePlan.Resource.ID == "" {
		t.Fatalf("RunRealIPRefresh() inactive ExposurePlan = %#v, want resource linkage", result.ExposurePlan)
	}
	if result.RetryCommand != ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", path, "--profile", "edgeone-next") {
		t.Fatalf("RetryCommand = %q", result.RetryCommand)
	}
}

func TestHostWorkflowFailuresKeepExposurePlan(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-prod",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := cfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	hostWorkflow := &fakeHostWorkflow{
		appErr:    errors.New("app deploy failed"),
		realIPErr: errors.New("realip refresh failed"),
	}
	confirmedCtx := Context{Version: "test", HostWorkflow: hostWorkflow, Confirmations: []string{"origin-protection-manual"}, ManualConfirmationRecorder: fixedManualConfirmationRecorder(originProtectionManualConfirmationRecord()), ExposureObservations: manualOriginProtectionObservation()}
	appResult, err := RunAppDeploy(confirmedCtx, appPath, "ins_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("RunAppDeploy() error = nil, want host workflow failure")
	}
	if appResult.ExposurePlan == nil || appResult.ExposurePlan.Resource.ID == "" {
		t.Fatalf("RunAppDeploy() failure ExposurePlan = %#v, want resource linkage", appResult.ExposurePlan)
	}
	realIPResult, err := RunRealIPRefresh(confirmedCtx, appPath, "edgeone-prod", "ins_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("RunRealIPRefresh() error = nil, want host workflow failure")
	}
	if realIPResult.ExposurePlan == nil || realIPResult.ExposurePlan.Resource.ID == "" {
		t.Fatalf("RunRealIPRefresh() failure ExposurePlan = %#v, want resource linkage", realIPResult.ExposurePlan)
	}
}

func TestRunAppConfigSaveAllowsManualActivationConfirmations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*appconfig.Config)
		want string
	}{
		{
			name: "public risk",
			edit: func(cfg *appconfig.Config) {
				cfg.Access.PublicRiskConfirmed = false
			},
			want: "public-app-risk",
		},
		{
			name: "direct origin risk",
			edit: func(cfg *appconfig.Config) {
				cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
			},
			want: "direct-origin-risk",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "lanpanel-app.yaml")
			cfg := appconfig.ExampleConfig()
			tt.edit(&cfg)

			result, err := RunAppConfigSave(Context{Version: "test"}, path, "ins_0123456789abcdef0123456789abcdef", cfg)
			if err != nil {
				t.Fatalf("RunAppConfigSave() error = %v", err)
			}
			if result.Kind != domain.JobKindAppConfigSave || result.Status != domain.JobStatusSucceeded {
				t.Fatalf("RunAppConfigSave() result = %#v, want typed successful save", result)
			}
			if result.ExposurePlan == nil || result.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionManual {
				t.Fatalf("RunAppConfigSave() ExposurePlan = %#v, want manual exposure plan", result.ExposurePlan)
			}
			if got := strings.Join(result.ExposurePlan.Decision.RequiredConfirmations, ","); got != tt.want {
				t.Fatalf("RequiredConfirmations = %q, want %q", got, tt.want)
			}
			if _, err := appconfig.LoadFile(path); err != nil {
				t.Fatalf("LoadFile(saved app config) error = %v", err)
			}
		})
	}
}

func TestRunAppConfigSaveRejectsPrivateClient(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModePrivateClient
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false

	result, err := RunAppConfigSave(Context{Version: "test"}, path, "ins_0123456789abcdef0123456789abcdef", cfg)
	if err == nil || !strings.Contains(err.Error(), "private_client is reserved for P1") {
		t.Fatalf("RunAppConfigSave() error = %v, want private_client rejection", err)
	}
	if result.Kind != domain.JobKindAppConfigSave || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunAppConfigSave() result = %#v, want typed failed save", result)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("app config stat error = %v, want not written", statErr)
	}
}

func TestRunAppVerifyBlocksPrivateClientBeforeRuntimeRender(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModePrivateClient
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	if err := cfg.WriteFile(path); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	result, err := RunAppVerify(Context{Version: "test"}, path, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppVerify() error = %v", err)
	}
	if result.Kind != domain.JobKindAppVerify || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunAppVerify() result = %#v, want failed app verify", result)
	}
	if result.ExposurePlan == nil || result.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionFail {
		t.Fatalf("RunAppVerify() ExposurePlan = %#v, want failed private_client plan", result.ExposurePlan)
	}
	if len(result.ModifiedPaths) != 0 {
		t.Fatalf("RunAppVerify() ModifiedPaths = %#v, want no rendered public runtime paths", result.ModifiedPaths)
	}
	if got, ok := fieldValue(result.Fields, "blocker private-client-p1"); !ok || !strings.Contains(got, "private_client resources are reserved for P1") {
		t.Fatalf("private_client blocker field = %q, %v; fields = %#v", got, ok, result.Fields)
	}
}

func TestRunAppVerifyUsesBrowserAuthExposureObservations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "browser-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.AuthBasicUserFile = "/etc/nginx/htpasswd/browser.htpasswd"
	if err := cfg.WriteFile(path); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	blocked, err := RunAppVerify(Context{Version: "test"}, path, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppVerify(blocked) error = %v", err)
	}
	if blocked.Status != domain.JobStatusFailed || blocked.ExposurePlan == nil || blocked.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionUnknown {
		t.Fatalf("RunAppVerify(blocked) = %#v, want unknown browser auth blocker", blocked)
	}

	hostWorkflow := &fakeHostWorkflow{exposureObservations: exposure.AppObservations{
		BrowserAuthRuntimeStatus: domain.DiagnosticStatusPass,
	}}
	result, err := RunAppVerify(Context{Version: "test", HostWorkflow: hostWorkflow}, path, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppVerify(observed) error = %v", err)
	}
	if result.Status != domain.JobStatusSucceeded || result.ExposurePlan == nil || result.ExposurePlan.Decision.Status == domain.ExposurePlanDecisionUnknown {
		t.Fatalf("RunAppVerify(observed) = %#v, want succeeded verify with observed browser auth", result)
	}
	if hostWorkflow.exposureObservationPath != path || hostWorkflow.exposureObservationOperation != domain.ExposurePlanOperationUpdateResource {
		t.Fatalf("app verify exposure observer = %q %q, want app path update_resource", hostWorkflow.exposureObservationPath, hostWorkflow.exposureObservationOperation)
	}
}

func TestRunAppVerifyUsesEdgeOneExposureObservations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "edgeone-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-2abcDEF123",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	cfg.DNS01.Provider = "cloudflare"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns/cloudflare.env"
	if err := cfg.WriteFile(path); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	unknown, err := RunAppVerify(Context{Version: "test", HostWorkflow: &fakeHostWorkflow{}}, path, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppVerify(unknown) error = %v", err)
	}
	if unknown.Status != domain.JobStatusFailed || unknown.ExposurePlan == nil || unknown.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionUnknown {
		t.Fatalf("RunAppVerify(unknown) = %#v, want unknown origin protection blocker", unknown)
	}

	hostWorkflow := &fakeHostWorkflow{exposureObservationStatus: domain.OriginProtectionConfiguredPass}
	result, err := RunAppVerify(Context{Version: "test", HostWorkflow: hostWorkflow}, path, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppVerify(pass) error = %v", err)
	}
	if result.Status != domain.JobStatusSucceeded || result.ExposurePlan == nil || result.ExposurePlan.OriginProtection != domain.OriginProtectionConfiguredPass {
		t.Fatalf("RunAppVerify(pass) = %#v, want configured_pass origin protection", result)
	}
}

func TestHostChangingOperationsRequireHostWorkflow(t *testing.T) {
	t.Parallel()

	if _, err := RunMainDeploy(Context{Version: "test"}, "lanpanel.yaml"); err == nil || !strings.Contains(err.Error(), "host workflow is required") {
		t.Fatalf("RunMainDeploy() error = %v, want host workflow requirement", err)
	}
	if _, err := RunAppDeploy(Context{Version: "test"}, "lanpanel-app.yaml", "ins_0123456789abcdef0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "host workflow is required") {
		t.Fatalf("RunAppDeploy() error = %v, want host workflow requirement", err)
	}
	if _, err := RunMainStatus(Context{Version: "test"}, "lanpanel.yaml"); err == nil || !strings.Contains(err.Error(), "host workflow is required") {
		t.Fatalf("RunMainStatus() error = %v, want host workflow requirement", err)
	}
	if _, err := RunRealIPDiagnostics(Context{Version: "test"}, "lanpanel-app.yaml", "edgeone-prod"); err == nil || !strings.Contains(err.Error(), "host workflow is required") {
		t.Fatalf("RunRealIPDiagnostics() error = %v, want host workflow requirement", err)
	}
}

func TestHostMutationsRequireManualExposureConfirmation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-prod",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := cfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	hostWorkflow := &fakeHostWorkflow{}
	appResult, err := RunAppDeploy(Context{Version: "test", HostWorkflow: hostWorkflow, ExposureObservations: manualOriginProtectionObservation()}, appPath, "ins_0123456789abcdef0123456789abcdef")
	if err == nil || !strings.Contains(err.Error(), "requires manual confirmations") {
		t.Fatalf("RunAppDeploy() error = %v, want manual confirmation failure", err)
	}
	if hostWorkflow.appDeployCalled {
		t.Fatal("RunAppDeploy() called host workflow without manual confirmation")
	}
	if appResult.Status != domain.JobStatusFailed || appResult.ExposurePlan == nil {
		t.Fatalf("RunAppDeploy() result = %#v, want failed exposure plan result", appResult)
	}
	if got, ok := fieldValue(appResult.Fields, "missing confirmations"); !ok || got != "origin-protection-manual" {
		t.Fatalf("missing confirmations field = %q, %v; fields = %#v", got, ok, appResult.Fields)
	}
	if appResult.RetryCommand != ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", appPath, "--confirmation", "origin-protection-manual") {
		t.Fatalf("RunAppDeploy() RetryCommand = %q, want retry command with missing confirmation", appResult.RetryCommand)
	}

	realIPResult, err := RunRealIPRefresh(Context{Version: "test", HostWorkflow: hostWorkflow, ExposureObservations: manualOriginProtectionObservation()}, appPath, "edgeone-prod", "ins_0123456789abcdef0123456789abcdef")
	if err == nil || !strings.Contains(err.Error(), "requires manual confirmations") {
		t.Fatalf("RunRealIPRefresh() error = %v, want manual confirmation failure", err)
	}
	if hostWorkflow.realIPRefreshCalled {
		t.Fatal("RunRealIPRefresh() called host workflow without manual confirmation")
	}
	if realIPResult.Status != domain.JobStatusFailed || realIPResult.ExposurePlan == nil {
		t.Fatalf("RunRealIPRefresh() result = %#v, want failed exposure plan result", realIPResult)
	}
	if realIPResult.RetryCommand != ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appPath, "--profile", "edgeone-prod", "--confirmation", "origin-protection-manual") {
		t.Fatalf("RunRealIPRefresh() RetryCommand = %q, want retry command with missing confirmation", realIPResult.RetryCommand)
	}

	unrecordedHostWorkflow := &fakeHostWorkflow{}
	unrecordedResult, err := RunAppDeploy(Context{Version: "test", HostWorkflow: unrecordedHostWorkflow, Confirmations: []string{"origin-protection-manual"}, ExposureObservations: manualOriginProtectionObservation()}, appPath, "ins_0123456789abcdef0123456789abcdef")
	if err == nil || !strings.Contains(err.Error(), "manual confirmation recorder is required") {
		t.Fatalf("RunAppDeploy(unrecorded) error = %v, want recorder requirement", err)
	}
	if unrecordedHostWorkflow.appDeployCalled {
		t.Fatal("RunAppDeploy(unrecorded) called host workflow without recorded manual confirmation")
	}
	if unrecordedResult.Status != domain.JobStatusFailed || len(unrecordedResult.Diagnostics) == 0 || unrecordedResult.Diagnostics[0].ID != "manual-confirmation-record" {
		t.Fatalf("RunAppDeploy(unrecorded) result = %#v, want manual confirmation record diagnostic", unrecordedResult)
	}

	confirmedHostWorkflow := &fakeHostWorkflow{}
	manualConfirmation := originProtectionManualConfirmationRecord()
	confirmedCtx := Context{Version: "test", HostWorkflow: confirmedHostWorkflow, Confirmations: []string{"origin-protection-manual"}, ManualConfirmationRecorder: fixedManualConfirmationRecorder(manualConfirmation), ExposureObservations: manualOriginProtectionObservation()}
	confirmedAppResult, err := RunAppDeploy(confirmedCtx, appPath, "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunAppDeploy(confirmed) error = %v", err)
	}
	if !confirmedHostWorkflow.appDeployCalled {
		t.Fatal("RunAppDeploy(confirmed) did not call host workflow")
	}
	if got := strings.Join(confirmedHostWorkflow.appDeployConfirmations, ","); got != "origin-protection-manual" {
		t.Fatalf("RunAppDeploy(confirmed) confirmations = %q", got)
	}
	if confirmedAppResult.ExposurePlan == nil || len(confirmedAppResult.ExposurePlan.Access.ManualConfirmations) != 1 || confirmedAppResult.ExposurePlan.Access.ManualConfirmations[0] != manualConfirmation {
		t.Fatalf("RunAppDeploy(confirmed) ExposurePlan = %#v, want structured manual confirmation", confirmedAppResult.ExposurePlan)
	}
	confirmedRealIPResult, err := RunRealIPRefresh(confirmedCtx, appPath, "edgeone-prod", "ins_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RunRealIPRefresh(confirmed) error = %v", err)
	}
	if !confirmedHostWorkflow.realIPRefreshCalled {
		t.Fatal("RunRealIPRefresh(confirmed) did not call host workflow")
	}
	if got := strings.Join(confirmedHostWorkflow.realIPRefreshConfirmations, ","); got != "origin-protection-manual" {
		t.Fatalf("RunRealIPRefresh(confirmed) confirmations = %q", got)
	}
	if confirmedRealIPResult.ExposurePlan == nil || len(confirmedRealIPResult.ExposurePlan.Access.ManualConfirmations) != 1 || confirmedRealIPResult.ExposurePlan.Access.ManualConfirmations[0] != manualConfirmation {
		t.Fatalf("RunRealIPRefresh(confirmed) ExposurePlan = %#v, want structured manual confirmation", confirmedRealIPResult.ExposurePlan)
	}
}

func TestHostMutationPreWorkflowFailuresReturnTypedResults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "invalid-app.yaml")
	if err := os.WriteFile(invalidPath, []byte("api_version: wrong\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid app) error = %v", err)
	}
	ctx := Context{Version: "test", HostWorkflow: &fakeHostWorkflow{}}

	appResult, err := RunAppDeploy(ctx, invalidPath, "ins_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("RunAppDeploy() error = nil, want config failure")
	}
	if appResult.Kind != domain.JobKindAppDeploy || appResult.Status != domain.JobStatusFailed || len(appResult.Diagnostics) == 0 || len(appResult.Progress) == 0 || appResult.RetryCommand == "" {
		t.Fatalf("RunAppDeploy() result = %#v, want typed failed result", appResult)
	}

	realIPResult, err := RunRealIPRefresh(ctx, invalidPath, "edgeone-prod", "ins_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("RunRealIPRefresh() error = nil, want config failure")
	}
	if realIPResult.Kind != domain.JobKindRealIPRefresh || realIPResult.Status != domain.JobStatusFailed || len(realIPResult.Diagnostics) == 0 || len(realIPResult.Progress) == 0 || realIPResult.RetryCommand == "" {
		t.Fatalf("RunRealIPRefresh() result = %#v, want typed failed result", realIPResult)
	}
}

func TestHostMutationRejectsUnexpectedManualConfirmation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := appconfig.ExampleConfig().WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	hostWorkflow := &fakeHostWorkflow{}
	result, err := RunAppDeploy(Context{Version: "test", HostWorkflow: hostWorkflow, Confirmations: []string{"origin-protection-manual"}}, appPath, "ins_0123456789abcdef0123456789abcdef")
	if err == nil || !strings.Contains(err.Error(), "rejected manual confirmations") {
		t.Fatalf("RunAppDeploy() error = %v, want unexpected confirmation rejection", err)
	}
	if hostWorkflow.appDeployCalled {
		t.Fatal("RunAppDeploy() called host workflow after unexpected confirmation")
	}
	if result.Status != domain.JobStatusFailed || result.ExposurePlan == nil {
		t.Fatalf("RunAppDeploy() result = %#v, want failed exposure plan result", result)
	}
	if got, ok := fieldValue(result.Fields, "unexpected confirmations"); !ok || got != "origin-protection-manual" {
		t.Fatalf("unexpected confirmations field = %q, %v; fields = %#v", got, ok, result.Fields)
	}
	if len(result.ExposurePlan.Access.ManualConfirmations) != 0 {
		t.Fatalf("ManualConfirmations = %#v, want none for rejected stale confirmation", result.ExposurePlan.Access.ManualConfirmations)
	}
}

func TestRunRealIPRefreshInactiveProfileFailureHasDiagnostics(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-prod",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := cfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	result, err := RunRealIPRefresh(Context{Version: "test", HostWorkflow: &fakeHostWorkflow{}, Confirmations: []string{"origin-protection-manual"}, ExposureObservations: manualOriginProtectionObservation()}, appPath, "edgeone-next", "ins_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("RunRealIPRefresh() error = nil, want inactive profile failure")
	}
	if result.Kind != domain.JobKindRealIPRefresh || result.Status != domain.JobStatusFailed || result.ExposurePlan == nil || len(result.Diagnostics) == 0 {
		t.Fatalf("RunRealIPRefresh() result = %#v, want typed failure with exposure plan and diagnostics", result)
	}
	if result.Diagnostics[0].Scope != domain.DiagnosticScopeRealIP || result.Diagnostics[0].EvidenceSource != domain.DiagnosticEvidenceConfig {
		t.Fatalf("Diagnostics = %#v, want realip config diagnostic", result.Diagnostics)
	}
}

func TestRunBrowserAuthRotateReturnsExposurePlan(t *testing.T) {
	dir := secureWorkflowTempDir(t)
	restoreRoot, err := browserauth.UnsafeSetManagedRootForTest(dir)
	if err != nil {
		t.Fatalf("UnsafeSetManagedRootForTest() error = %v", err)
	}
	t.Cleanup(restoreRoot)
	restoreConfigRoot := appconfig.UnsafeSetBrowserAuthManagedRootForTest(dir)
	t.Cleanup(restoreConfigRoot)
	restoreChown := browserauth.UnsafeDisableManagedChownForTest()
	t.Cleanup(restoreChown)
	credential, err := browserauth.CreateManaged(dir, "review-app", "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateManaged() error = %v", err)
	}
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        credential.ID,
		HtpasswdPath:        credential.HtpasswdPath,
		Username:            credential.Username,
		PasswordFingerprint: credential.PasswordFingerprint,
	}
	if err := cfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	result, err := RunBrowserAuthRotate(Context{
		Version: "test",
		Now:     fixedWorkflowNow,
		ExposureObservations: exposure.AppObservations{
			BrowserAuthRuntimeStatus: domain.DiagnosticStatusPass,
			BrowserAuthMarkerStatus:  domain.DiagnosticStatusPass,
		},
	}, appPath, "ins_0123456789abcdef0123456789abcdef", credential.HtpasswdPath, "admin", "another correct horse battery staple")
	if err != nil {
		t.Fatalf("RunBrowserAuthRotate() error = %v", err)
	}
	if result.Kind != domain.JobKindBrowserAuthRotate || result.Status != domain.JobStatusSucceeded {
		t.Fatalf("RunBrowserAuthRotate() result = %#v, want succeeded rotate", result)
	}
	if result.ExposurePlan == nil || result.ExposurePlan.Operation != domain.ExposurePlanOperationBrowserAuthRotate || result.ExposurePlan.Resource.ID == "" {
		t.Fatalf("ExposurePlan = %#v, want browser_auth_rotate plan with resource id", result.ExposurePlan)
	}
	if len(result.ExposurePlan.ModifiedPaths) != 1 || result.ExposurePlan.ModifiedPaths[0] != credential.HtpasswdPath {
		t.Fatalf("ExposurePlan.ModifiedPaths = %#v, want rotated htpasswd path", result.ExposurePlan.ModifiedPaths)
	}
	if result.OneTimeSecret == nil {
		t.Fatalf("OneTimeSecret = nil, want rotated password handoff")
	}
}

func TestRunBrowserAuthCreateRequiresDependencyEnsurer(t *testing.T) {
	result, err := RunBrowserAuthCreate(Context{Version: "test"}, "/etc/lanpanel/browser-auth", "review", "admin", "correct horse battery staple")
	if err == nil || !strings.Contains(err.Error(), "browser auth dependency ensurer is required") {
		t.Fatalf("RunBrowserAuthCreate() error = %v, want missing dependency ensurer failure", err)
	}
	if result.Kind != domain.JobKindBrowserAuthCreate || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunBrowserAuthCreate() result = %#v, want failed browser auth create", result)
	}

	cause := errors.New("apt install nginx apache2-utils failed")
	called := false
	result, err = RunBrowserAuthCreate(Context{
		Version: "test",
		BrowserAuthDependencyEnsurer: func(context.Context) error {
			called = true
			return cause
		},
	}, "/etc/lanpanel/browser-auth", "review", "admin", "correct horse battery staple")
	if !called {
		t.Fatal("BrowserAuthDependencyEnsurer was not called")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("RunBrowserAuthCreate() error = %v, want dependency cause", err)
	}
	if result.Kind != domain.JobKindBrowserAuthCreate || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunBrowserAuthCreate() result = %#v, want failed browser auth create", result)
	}
	if got, ok := fieldValue(result.Fields, "details"); !ok || !strings.Contains(got, cause.Error()) {
		t.Fatalf("details = %q, %v; fields = %#v", got, ok, result.Fields)
	}
}

func secureWorkflowTempDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	dir, err := os.MkdirTemp(home, ".lanpanel-workflow-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestRunBrowserAuthRotateRequiresReferencedManagedCredential(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        "review-app",
		HtpasswdPath:        "/etc/lanpanel/browser-auth/review-app.htpasswd",
		Username:            "admin",
		PasswordFingerprint: "sha256:0011223344556677",
	}
	if err := cfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	result, err := RunBrowserAuthRotate(Context{Version: "test", Now: fixedWorkflowNow}, appPath, "ins_0123456789abcdef0123456789abcdef", filepath.Join(dir, "review-app.htpasswd"), "admin", "another correct horse battery staple")
	if err == nil {
		t.Fatal("RunBrowserAuthRotate() error = nil, want same-basename unreferenced target failure")
	}
	if result.Kind != domain.JobKindBrowserAuthRotate || result.Status != domain.JobStatusFailed {
		t.Fatalf("RunBrowserAuthRotate() result = %#v, want typed failed rotate", result)
	}
	if !strings.Contains(result.Summary, "failed") || result.ExposurePlan != nil {
		t.Fatalf("RunBrowserAuthRotate() result = %#v, want pre-plan target failure", result)
	}
}

func TestHostMutationsUseHostExposureObserver(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-prod",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := cfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	appHostWorkflow := &fakeHostWorkflow{exposureObservationStatus: domain.OriginProtectionConfiguredManual}
	if _, err := RunAppDeploy(Context{
		Version:                    "test",
		HostWorkflow:               appHostWorkflow,
		Confirmations:              []string{"origin-protection-manual"},
		ManualConfirmationRecorder: fixedManualConfirmationRecorder(originProtectionManualConfirmationRecord()),
	}, appPath, "ins_0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("RunAppDeploy() error = %v", err)
	}
	if appHostWorkflow.exposureObservationPath != appPath || appHostWorkflow.exposureObservationOperation != domain.ExposurePlanOperationDeploy {
		t.Fatalf("app exposure observer = %q %q, want app path deploy", appHostWorkflow.exposureObservationPath, appHostWorkflow.exposureObservationOperation)
	}

	refreshHostWorkflow := &fakeHostWorkflow{exposureObservationStatus: domain.OriginProtectionConfiguredPass}
	if _, err := RunRealIPRefresh(Context{
		Version:      "test",
		HostWorkflow: refreshHostWorkflow,
	}, appPath, "edgeone-prod", "ins_0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("RunRealIPRefresh() error = %v", err)
	}
	if !refreshHostWorkflow.realIPRefreshCalled {
		t.Fatal("RunRealIPRefresh() did not call host workflow with pass observation")
	}
	if got := strings.Join(refreshHostWorkflow.realIPRefreshConfirmations, ","); got != "" {
		t.Fatalf("realIP refresh confirmations = %q, want none for configured_pass", got)
	}
	if refreshHostWorkflow.exposureObservationPath != appPath || refreshHostWorkflow.exposureObservationOperation != domain.ExposurePlanOperationRealIPRefresh {
		t.Fatalf("realip exposure observer = %q %q, want app path realip refresh", refreshHostWorkflow.exposureObservationPath, refreshHostWorkflow.exposureObservationOperation)
	}
}

func TestRunAppDeployBlocksBrowserAuthRuntimeUnknownBeforeHostWorkflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	appPath := filepath.Join(dir, "browser-app.yaml")
	cfg := appconfig.ExampleConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        "review",
		HtpasswdPath:        "/etc/lanpanel/browser-auth/review.htpasswd",
		Username:            "admin",
		PasswordFingerprint: "sha256:0011223344556677",
	}
	if err := cfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}
	hostWorkflow := &fakeHostWorkflow{exposureObservations: exposure.AppObservations{
		BrowserAuthMarkerStatus: domain.DiagnosticStatusPass,
	}}

	result, err := RunAppDeploy(Context{Version: "test", HostWorkflow: hostWorkflow}, appPath, "ins_0123456789abcdef0123456789abcdef")
	if err == nil || !strings.Contains(err.Error(), "app deploy exposure plan is blocked") {
		t.Fatalf("RunAppDeploy() error = %v, want blocked exposure plan", err)
	}
	if hostWorkflow.appDeployCalled {
		t.Fatal("RunAppDeploy() reached host workflow with unknown browser auth runtime readability")
	}
	if result.ExposurePlan == nil || result.ExposurePlan.Decision.Status != domain.ExposurePlanDecisionUnknown {
		t.Fatalf("ExposurePlan = %#v, want unknown browser auth blocker", result.ExposurePlan)
	}
}

func TestStatusAndRealIPDiagnosticsDelegateHostWorkflow(t *testing.T) {
	t.Parallel()

	hostWorkflow := &fakeHostWorkflow{}
	statusResult, err := RunMainStatus(Context{Version: "test", HostWorkflow: hostWorkflow}, "/tmp/lanpanel.yaml")
	if err != nil {
		t.Fatalf("RunMainStatus() error = %v", err)
	}
	if hostWorkflow.mainStatusPath != "/tmp/lanpanel.yaml" {
		t.Fatalf("RunMainStatus() host path = %q, want /tmp/lanpanel.yaml", hostWorkflow.mainStatusPath)
	}
	if statusResult.Kind != domain.JobKindStatus || statusResult.RetryCommand != "Management UI" {
		t.Fatalf("RunMainStatus() result = %#v, want status kind and retry command", statusResult)
	}

	diagnosticsResult, err := RunRealIPDiagnostics(Context{Version: "test", HostWorkflow: hostWorkflow}, "/tmp/lanpanel-app.yaml", "edgeone-prod")
	if err != nil {
		t.Fatalf("RunRealIPDiagnostics() error = %v", err)
	}
	if hostWorkflow.realIPDiagnosticsPath != "/tmp/lanpanel-app.yaml" || hostWorkflow.realIPDiagnosticsProfile != "edgeone-prod" {
		t.Fatalf("RunRealIPDiagnostics() host args = %q %q, want app config and profile", hostWorkflow.realIPDiagnosticsPath, hostWorkflow.realIPDiagnosticsProfile)
	}
	if diagnosticsResult.Kind != domain.JobKindRealIPDiagnostics || diagnosticsResult.RetryCommand != "Management UI" {
		t.Fatalf("RunRealIPDiagnostics() result = %#v, want diagnostics kind and retry command", diagnosticsResult)
	}
}

func TestRunRuntimeStatusIncludesActiveRealIPDiagnostics(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mainPath := filepath.Join(dir, "lanpanel.yaml")
	mainCfg := config.ExampleConfig()
	if err := mainCfg.WriteFile(mainPath); err != nil {
		t.Fatalf("WriteFile(main config) error = %v", err)
	}

	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	appCfg := appconfig.ExampleConfig()
	appCfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	appCfg.DNS01.Provider = "tencentcloud"
	appCfg.DNS01.EnvFile = "/etc/lanpanel/dns01/tencentcloud.env"
	appCfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	appCfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	appCfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	appCfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:         &enabled,
			Provider:        appconfig.RealIPProviderEdgeOne,
			RefreshInterval: "72h",
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-prod",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	if err := appCfg.WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app config) error = %v", err)
	}

	hostWorkflow := &fakeHostWorkflow{}
	result, err := RunRuntimeStatus(Context{Version: "test", HostWorkflow: hostWorkflow}, mainPath, appPath)
	if err != nil {
		t.Fatalf("RunRuntimeStatus() error = %v", err)
	}
	if hostWorkflow.realIPDiagnosticsPath != appPath || hostWorkflow.realIPDiagnosticsProfile != "edgeone-prod" {
		t.Fatalf("realip diagnostics args = %q %q, want active app profile", hostWorkflow.realIPDiagnosticsPath, hostWorkflow.realIPDiagnosticsProfile)
	}
	if !diagnosticsContain(result.Diagnostics, "realip-diagnostics") {
		t.Fatalf("RunRuntimeStatus() diagnostics = %#v, want realip diagnostics item", result.Diagnostics)
	}
}

func diagnosticsContain(items []domain.DiagnosticItem, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

type fakePreAuthKeyCreator struct {
	key    string
	err    error
	plan   headscale.OnboardingPlan
	called bool
}

func (creator *fakePreAuthKeyCreator) CreatePreAuthKey(_ context.Context, plan headscale.OnboardingPlan) (string, []host.Result, error) {
	creator.called = true
	creator.plan = plan
	if creator.err != nil {
		return "", nil, creator.err
	}
	return creator.key, nil, nil
}

func (workflow *fakeHostWorkflow) EnsureBrowserAuthDependencies(context.Context) error {
	return nil
}

type fakeHostWorkflow struct {
	appErr                       error
	realIPErr                    error
	mainStatusPath               string
	realIPDiagnosticsPath        string
	realIPDiagnosticsProfile     string
	appDeployCalled              bool
	realIPRefreshCalled          bool
	appDeployConfirmations       []string
	realIPRefreshConfirmations   []string
	exposureObservations         exposure.AppObservations
	exposureObservationStatus    domain.OriginProtectionStatus
	exposureObservationPath      string
	exposureObservationOperation domain.ExposurePlanOperation
}

func (workflow *fakeHostWorkflow) AppExposureObservations(_ context.Context, path string, _ appconfig.Config, operation domain.ExposurePlanOperation) (exposure.AppObservations, error) {
	workflow.exposureObservationPath = path
	workflow.exposureObservationOperation = operation
	if workflow.exposureObservations.BrowserAuthRuntimeStatus != "" || workflow.exposureObservations.BrowserAuthMarkerStatus != "" {
		return workflow.exposureObservations, nil
	}
	if workflow.exposureObservationStatus == domain.OriginProtectionConfiguredPass {
		return passOriginProtectionObservation(), nil
	}
	return exposure.AppObservations{OriginProtectionStatus: workflow.exposureObservationStatus}, nil
}

func (workflow *fakeHostWorkflow) RunMainStatus(_ context.Context, path string) (OperationResult, error) {
	workflow.mainStatusPath = path
	return OperationResult{Status: "succeeded", Summary: "main status host workflow executed"}, nil
}

func (workflow *fakeHostWorkflow) RunMainDeploy(_ context.Context, _ string) (OperationResult, error) {
	return OperationResult{Status: "succeeded", Summary: "main host workflow executed"}, nil
}

func (workflow *fakeHostWorkflow) RunAppDeploy(_ context.Context, _ string, _ domain.ExposurePlan, confirmations []string) (OperationResult, error) {
	workflow.appDeployCalled = true
	workflow.appDeployConfirmations = append([]string(nil), confirmations...)
	if workflow.appErr != nil {
		return OperationResult{
			Status:        domain.JobStatusFailed,
			Summary:       "app host workflow failed",
			ModifiedPaths: []string{"/etc/nginx/sites-available/example-app.conf"},
		}, workflow.appErr
	}
	return OperationResult{Status: "succeeded", Summary: "app host workflow executed"}, nil
}

func (workflow *fakeHostWorkflow) RunRealIPDiagnostics(_ context.Context, path string, profile string) (OperationResult, error) {
	workflow.realIPDiagnosticsPath = path
	workflow.realIPDiagnosticsProfile = profile
	return OperationResult{
		Status:  "succeeded",
		Summary: "realip diagnostics host workflow executed",
		Diagnostics: []domain.DiagnosticItem{
			diagnosticItem("realip-diagnostics", domain.DiagnosticStatusPass, "realip diagnostics host workflow executed", domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin),
		},
	}, nil
}

func (workflow *fakeHostWorkflow) RunRealIPRefresh(_ context.Context, _ string, _ string, _ domain.ExposurePlan, confirmations []string) (OperationResult, error) {
	workflow.realIPRefreshCalled = true
	workflow.realIPRefreshConfirmations = append([]string(nil), confirmations...)
	if workflow.realIPErr != nil {
		return OperationResult{
			Status:        domain.JobStatusFailed,
			Summary:       "realip host workflow failed",
			ModifiedPaths: []string{"/etc/nginx/lanpanel/realip/edgeone-prod/active.conf"},
		}, workflow.realIPErr
	}
	return OperationResult{Status: "succeeded", Summary: "realip host workflow executed"}, nil
}

func fixedWorkflowNow() time.Time {
	return time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
}
