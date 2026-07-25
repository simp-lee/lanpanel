//go:build e2e

package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apprender"
	"lanpanel/internal/browserauth"
	"lanpanel/internal/components/headscale"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/host"
	"lanpanel/internal/state"
	"lanpanel/internal/ui"
	"lanpanel/internal/uistate"
	"lanpanel/internal/workflow"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", ui.DefaultAddr, "Loopback listen address.")
	stateDir := flag.String("state-dir", "", "UI state directory.")
	configPath := flag.String("config", "", "Main config path.")
	appConfigPath := flag.String("app-config", "", "App config path.")
	browserAuthDir := flag.String("browser-auth-dir", "", "Managed browser-auth directory.")
	tokenURLFile := flag.String("token-url-file", "", "File where the startup token URL is written.")
	preseedConfigs := flag.Bool("preseed-configs", true, "Write example main/app config fixtures before serving.")
	seedInterrupted := flag.Bool("seed-interrupted-job", true, "Seed a running job so server startup recovery marks it interrupted.")
	seedRealIPReference := flag.Bool("seed-realip-reference", true, "Seed a deterministic RealIP validate-reference fixture through e2e hooks.")
	slowMainDeploy := flag.Duration("slow-main-deploy", 0, "Delay fake main deploy to exercise browser-level lock contention.")
	flag.Parse()

	if err := run(*addr, *stateDir, *configPath, *appConfigPath, *browserAuthDir, *tokenURLFile, *preseedConfigs, *seedInterrupted, *seedRealIPReference, *slowMainDeploy); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(addr string, stateDir string, configPath string, appConfigPath string, browserAuthDir string, tokenURLFile string, preseedConfigs bool, seedInterrupted bool, seedRealIPReference bool, slowMainDeploy time.Duration) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("state-dir is required")
	}
	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("config is required")
	}
	if strings.TrimSpace(appConfigPath) == "" {
		return fmt.Errorf("app-config is required")
	}
	if strings.TrimSpace(browserAuthDir) == "" {
		return fmt.Errorf("browser-auth-dir is required")
	}
	if strings.TrimSpace(tokenURLFile) == "" {
		return fmt.Errorf("token-url-file is required")
	}
	if _, err := browserauth.UnsafeSetManagedRootForTest(browserAuthDir); err != nil {
		return err
	}
	appconfig.UnsafeSetBrowserAuthManagedRootForTest(browserAuthDir)
	browserauth.UnsafeDisableManagedChownForTest()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if preseedConfigs {
		if err := config.ExampleConfig().WriteFile(configPath); err != nil {
			return fmt.Errorf("write main config: %w", err)
		}
		if err := e2eAppConfig().WriteFile(appConfigPath); err != nil {
			return fmt.Errorf("write app config: %w", err)
		}
		if err := seedUnknownFieldAppConfig(appConfigPath); err != nil {
			return err
		}
	}
	if seedInterrupted {
		if err := seedInterruptedJob(stateDir, appConfigPath); err != nil {
			return err
		}
	}
	if seedRealIPReference {
		workflow.UnsafeSetRealIPReferenceIOForE2E(e2eRealIPReferenceLstat, e2eRealIPReferenceRead)
	}
	server, err := ui.NewServer(ui.Options{
		Addr:                            addr,
		Version:                         "e2e",
		StateDir:                        stateDir,
		ConfigPath:                      configPath,
		AppConfigPath:                   appConfigPath,
		HostWorkflow:                    fakeHostWorkflow{slowMainDeploy: slowMainDeploy},
		PreAuthKeyCreator:               fakePreAuthKeyCreator{},
		UnsafeAllowNonRootWritesForTest: true,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	startupURL := server.StartupURL()
	if err := os.WriteFile(tokenURLFile, []byte(startupURL), 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("write token URL file: %w", err)
	}
	return http.Serve(listener, server.Handler())
}

func seedInterruptedJob(stateDir string, appConfigPath string) error {
	store := uistate.NewStore(stateDir)
	_, err := store.CreateJob(domain.JobRecord{
		Kind:          domain.JobKindAppDeploy,
		Status:        domain.JobStatusRunning,
		Actor:         e2eActor(),
		CheckpointRef: domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: state.DefaultCheckpointPath(appConfigPath)},
		RetryCommand:  "sudo lanpanel app deploy --config e2e-lanpanel-app.yaml --confirmation origin-protection-manual",
	})
	if err != nil {
		return fmt.Errorf("seed interrupted job: %w", err)
	}
	return nil
}

func seedUnknownFieldAppConfig(appConfigPath string) error {
	path := filepath.Join(filepath.Dir(appConfigPath), "unknown-field-lanpanel-app.yaml")
	content := []byte("api_version: lanpanel/app/v1alpha2\nunknown_field: true\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write unknown-field app config: %w", err)
	}
	return nil
}

func e2eActor() domain.Actor {
	uid := os.Geteuid()
	return domain.Actor{
		Source:                  domain.ActorSourceUI,
		EffectiveUID:            uid,
		EffectiveUser:           fmt.Sprintf("uid:%d", uid),
		ProcessID:               os.Getpid(),
		SessionIDFingerprint:    "sha256:0011223344556677",
		RequestSource:           "127.0.0.1:0",
		StartupTokenFingerprint: "sha256:8899aabbccddeeff",
	}
}

func e2eAppConfig() appconfig.Config {
	enabled := true
	cfg := appconfig.ExampleConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:         &enabled,
			Provider:        appconfig.RealIPProviderEdgeOne,
			RefreshInterval: "72h",
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-2abcDEF123",
				EnvFile: "/etc/lanpanel/realip/edgeone-prod.env",
			},
		},
	}
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns/tencentcloud.env"
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"203.0.113.0/24"}
	cfg.Nginx.StaticLocations = []appconfig.NginxStaticLocationConfig{{
		Path:  "/static/",
		Alias: "/opt/example-app/web/static/",
	}}
	return cfg
}

const e2eRealIPReferencePath = "/var/lib/lanpanel/realip/edgeone-prod/references/example-app.json"

type e2eRealIPReferenceInfo struct{}

func (e2eRealIPReferenceInfo) Name() string       { return "example-app.json" }
func (e2eRealIPReferenceInfo) Size() int64        { return 160 }
func (e2eRealIPReferenceInfo) Mode() fs.FileMode  { return 0o600 }
func (e2eRealIPReferenceInfo) ModTime() time.Time { return time.Unix(0, 0).UTC() }
func (e2eRealIPReferenceInfo) IsDir() bool        { return false }
func (e2eRealIPReferenceInfo) Sys() any           { return &syscall.Stat_t{Uid: 0} }

func e2eRealIPReferenceLstat(path string) (fs.FileInfo, error) {
	if path != e2eRealIPReferencePath {
		return nil, os.ErrNotExist
	}
	return e2eRealIPReferenceInfo{}, nil
}

func e2eRealIPReferenceRead(path string) ([]byte, error) {
	if path != e2eRealIPReferencePath {
		return nil, os.ErrNotExist
	}
	return []byte(`{"lanpanel_managed":"Lanpanel-managed: realip.profile=edgeone-prod provider=edgeone","app_name":"example-app","profile":"edgeone-prod","domains":["abc.com","www.abc.com"]}`), nil
}

type fakeHostWorkflow struct {
	slowMainDeploy time.Duration
}

func (hostWorkflow fakeHostWorkflow) EnsureBrowserAuthDependencies(context.Context) error {
	return nil
}

func (hostWorkflow fakeHostWorkflow) AppExposureObservations(ctx context.Context, _ string, cfg appconfig.Config, operation domain.ExposurePlanOperation) (exposure.AppObservations, error) {
	if err := ctx.Err(); err != nil {
		return exposure.AppObservations{}, err
	}
	observations := fakeBrowserAuthObservations(cfg)
	if cfg.Access.OriginProtection.Mode != appconfig.OriginProtectionModeEdgeOne {
		return observations, nil
	}
	switch operation {
	case domain.ExposurePlanOperationDeploy:
		observations.OriginProtectionStatus = domain.OriginProtectionConfiguredManual
		return observations, nil
	case domain.ExposurePlanOperationRealIPRefresh:
		observations.OriginProtectionStatus = domain.OriginProtectionConfiguredPass
		observations.OriginProtectionReferenceDigest = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
		observations.RealIPTrustedCIDRCount = 2
		observations.RealIPClientIPHeader = appconfig.RealIPHeaderEdgeOne
		observations.RealIPSpoofingRejection = domain.DiagnosticStatusPass
		return observations, nil
	case domain.ExposurePlanOperationBrowserAuthRotate:
		origin := passOriginProtectionObservation()
		observations.OriginProtectionStatus = origin.OriginProtectionStatus
		observations.OriginProtectionReferenceDigest = origin.OriginProtectionReferenceDigest
		observations.RealIPTrustedCIDRCount = origin.RealIPTrustedCIDRCount
		observations.RealIPClientIPHeader = origin.RealIPClientIPHeader
		observations.RealIPSpoofingRejection = origin.RealIPSpoofingRejection
		return observations, nil
	default:
		observations.OriginProtectionStatus = domain.OriginProtectionConfiguredUnknown
		return observations, nil
	}
}

func fakeBrowserAuthObservations(cfg appconfig.Config) exposure.AppObservations {
	if !cfg.BrowserAuthEnabled() {
		return exposure.AppObservations{}
	}
	observations := exposure.AppObservations{BrowserAuthRuntimeStatus: domain.DiagnosticStatusPass}
	if cfg.Access.BrowserAuth.Managed.HtpasswdPath != "" {
		observations.BrowserAuthMarkerStatus = domain.DiagnosticStatusPass
	}
	return observations
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

func (hostWorkflow fakeHostWorkflow) RunMainStatus(_ context.Context, configPath string) (workflow.OperationResult, error) {
	return workflow.OperationResult{
		Kind:         domain.JobKindStatus,
		Status:       domain.JobStatusSucceeded,
		Summary:      "e2e main status simulated",
		Fields:       []domain.ResultField{{Label: "config path", Value: configPath}, {Label: "checkpoint path", Value: "/tmp/lanpanel-ui-e2e/checkpoint.json"}},
		RetryCommand: workflow.ShellCommand("lanpanel", "status", "--config", configPath),
	}, nil
}

func (hostWorkflow fakeHostWorkflow) RunMainDeploy(ctx context.Context, configPath string) (workflow.OperationResult, error) {
	if hostWorkflow.slowMainDeploy > 0 {
		select {
		case <-time.After(hostWorkflow.slowMainDeploy):
		case <-ctx.Done():
			return workflow.OperationResult{}, ctx.Err()
		}
	}
	return workflow.OperationResult{
		Kind:          domain.JobKindDeploy,
		Status:        domain.JobStatusSucceeded,
		Summary:       "e2e main deploy simulated",
		Fields:        []domain.ResultField{{Label: "config path", Value: configPath}},
		ModifiedPaths: []string{"/etc/headscale/config.yaml"},
		RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "deploy", "--config", configPath),
	}, nil
}

func (hostWorkflow fakeHostWorkflow) RunAppDeploy(_ context.Context, appConfigPath string, _ domain.ExposurePlan, _ []string) (workflow.OperationResult, error) {
	if strings.Contains(appConfigPath, "missing-auth-lanpanel-app.yaml") {
		err := fmt.Errorf("access.browser_auth htpasswd file unavailable: /tmp/lanpanel-e2e-missing-browser.htpasswd")
		return workflow.OperationResult{
			Kind:         domain.JobKindAppDeploy,
			Status:       domain.JobStatusFailed,
			Summary:      err.Error(),
			RetryCommand: workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", appConfigPath, "--confirmation", "origin-protection-manual"),
		}, err
	}
	fields := []domain.ResultField{{Label: "app config path", Value: appConfigPath}}
	if renderFields, err := renderedAppNginxFieldsForE2E(appConfigPath); err != nil {
		fields = append(fields, domain.ResultField{Label: "e2e render error", Value: err.Error()})
	} else {
		fields = append(fields, renderFields...)
	}
	return workflow.OperationResult{
		Kind:          domain.JobKindAppDeploy,
		Status:        domain.JobStatusSucceeded,
		Summary:       "e2e app deploy simulated",
		Fields:        fields,
		ModifiedPaths: []string{"/etc/nginx/sites-available/example-app.conf"},
		RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", appConfigPath, "--confirmation", "origin-protection-manual"),
	}, nil
}

func renderedAppNginxFieldsForE2E(appConfigPath string) ([]domain.ResultField, error) {
	cfg, err := appconfig.LoadFile(appConfigPath)
	if err != nil {
		return nil, err
	}
	staged, err := apprender.StageRuntime(cfg)
	if err != nil {
		return nil, err
	}
	for _, file := range staged {
		if strings.Contains(file.HostPath, "/etc/nginx/sites-available/") {
			nginx := string(file.Content)
			return []domain.ResultField{
				{Label: "static location rendered", Value: fmt.Sprintf("%t", strings.Contains(nginx, "location /static/ {"))},
				{Label: "static alias rendered", Value: fmt.Sprintf("%t", strings.Contains(nginx, "alias /opt/example-app/web/static/;"))},
				{Label: "browser gate count", Value: fmt.Sprintf("%d", strings.Count(nginx, `auth_basic "Lanpanel Browser";`))},
				{Label: "managed credential file rendered", Value: fmt.Sprintf("%t", strings.Contains(nginx, "auth_basic_user_file "+cfg.BrowserAuthUserFile()+";"))},
				{Label: "proxy credential header cleared", Value: fmt.Sprintf("%t", strings.Contains(nginx, `proxy_set_header Authorization "";`))},
			}, nil
		}
	}
	return nil, fmt.Errorf("rendered app nginx site was not staged")
}

func (hostWorkflow fakeHostWorkflow) RunRealIPDiagnostics(_ context.Context, appConfigPath string, profileName string) (workflow.OperationResult, error) {
	if profileName != "edgeone-prod" {
		err := fmt.Errorf("realip profile %s is not defined", profileName)
		return workflow.OperationResult{
			Kind:         domain.JobKindRealIPDiagnostics,
			Status:       domain.JobStatusFailed,
			Summary:      err.Error(),
			RetryCommand: workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profileName),
		}, err
	}
	return workflow.OperationResult{
		Kind:         domain.JobKindRealIPDiagnostics,
		Status:       domain.JobStatusSucceeded,
		Summary:      "e2e realip diagnostics simulated",
		Fields:       []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "profile", Value: profileName}},
		RetryCommand: workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "diagnostics", "--config", appConfigPath, "--profile", profileName),
	}, nil
}

func (hostWorkflow fakeHostWorkflow) RunRealIPRefresh(_ context.Context, appConfigPath string, profileName string, _ domain.ExposurePlan, _ []string) (workflow.OperationResult, error) {
	return workflow.OperationResult{
		Kind:          domain.JobKindRealIPRefresh,
		Status:        domain.JobStatusSucceeded,
		Summary:       "e2e realip refresh simulated with rollback reference",
		Fields:        []domain.ResultField{{Label: "app config path", Value: appConfigPath}, {Label: "profile", Value: profileName}},
		ModifiedPaths: []string{"/etc/nginx/lanpanel/realip/edgeone-prod/active.conf"},
		RetryCommand:  workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", appConfigPath, "--profile", profileName, "--confirmation", "origin-protection-manual"),
	}, nil
}

type fakePreAuthKeyCreator struct{}

func (fakePreAuthKeyCreator) CreatePreAuthKey(_ context.Context, plan headscale.OnboardingPlan) (string, []host.Result, error) {
	if strings.TrimSpace(plan.UserName) == "" {
		return "", nil, fmt.Errorf("preauth user is required")
	}
	return "hskey-auth-e2e", nil, nil
}
