package exposure

import (
	"lanpanel/internal/appconfig"
	"lanpanel/internal/domain"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig() appconfig.Config {
	cfg := appconfig.New()
	cfg.App.Name = "api"
	cfg.App.Domains = []string{"api.example.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.Listen = "127.0.0.1:18001"
	cfg.Access.AccessMode = appconfig.AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = true
	cfg.Service.ExecStart = "/opt/api/api --listen 127.0.0.1:18001"
	return cfg
}

func testPlanOptions(operation domain.ExposurePlanOperation, modifiedPaths ...string) AppPlanOptions {
	return AppPlanOptions{
		Actor: domain.Actor{
			Source:        domain.ActorSourceCLI,
			EffectiveUID:  1000,
			EffectiveUser: "uid:1000",
		},
		Operation:     operation,
		CreatedAt:     time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC),
		ModifiedPaths: modifiedPaths,
		BeforeDigest:  "none",
	}
}

func TestAppSummaryIncludesStableResourceAndMetadata(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	summary, err := AppSummaryWithObservationsAndInstance("ins_00112233445566778899aabbccddeeff", "dev", cfg, AppObservations{
		GeneratedAt: time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC),
		Activation:  domain.NotApplicableActivationRef(),
	}, InstanceSummaryOptions{
		BaseDomain: "tailnet.example.com",
		ServerURL:  "https://hs.example.com",
	})
	if err != nil {
		t.Fatalf("AppSummary() error = %v", err)
	}
	if summary.Instance.InstanceID != "ins_00112233445566778899aabbccddeeff" ||
		summary.Instance.LanpanelVersion != "dev" ||
		summary.Instance.BaseDomain != "tailnet.example.com" ||
		summary.Instance.ServerURL != "https://hs.example.com" {
		t.Fatalf("instance metadata = %#v", summary.Instance)
	}
	if summary.SchemaVersion != domain.ResourceExposureSchemaV1 {
		t.Fatalf("SchemaVersion = %q, want %q", summary.SchemaVersion, domain.ResourceExposureSchemaV1)
	}
	if summary.GeneratedAt.Format(time.RFC3339) != "2026-06-20T01:02:03Z" {
		t.Fatalf("GeneratedAt = %s", summary.GeneratedAt.Format(time.RFC3339))
	}
	if len(summary.Resources) != 1 {
		t.Fatalf("Resources = %#v", summary.Resources)
	}
	entry := summary.Resources[0]
	if entry.Resource.ID == "" || entry.Resource.CanonicalName != "api" {
		t.Fatalf("resource = %#v", entry.Resource)
	}
	if summary.Summary.Total != 1 || summary.Summary.ByAccessMode[domain.AccessModePublic] != 1 {
		t.Fatalf("summary = %#v", summary.Summary)
	}
	if entry.Resource.Name != "api" || entry.Resource.OwnerScope != domain.ResourceOwnerScopeLocalInstance || entry.Resource.State != domain.ResourceStatePlanned {
		t.Fatalf("resource schema fields = %#v", entry.Resource)
	}
	if entry.Resource.ConfigRef.Path != "not_applicable" || entry.Resource.ConfigRef.Digest == "" {
		t.Fatalf("resource config ref = %#v, want not_applicable preview path and digest", entry.Resource.ConfigRef)
	}
	if entry.Target.TargetKind != domain.ResourceTargetKindListen || entry.Target.Listen.Address != "127.0.0.1" || entry.Target.Listen.Port != 18001 || entry.Target.Listen.ServiceName != "api.service" {
		t.Fatalf("target = %#v, want structured listen target", entry.Target)
	}
	if entry.Access.AccessMode != domain.AccessModePublic || entry.Access.RiskLabel != domain.AccessRiskPublicInternet || entry.Access.PublicEntry.Status != domain.PublicEntryEnabled || len(entry.Access.PublicEntry.Domains) != 1 || entry.Access.PublicEntry.TLS != "enabled" || entry.Access.PublicEntry.NginxSite != "enabled" {
		t.Fatalf("access = %#v, want structured public access", entry.Access)
	}
	if entry.Access.PrivateEntry.Status != domain.PrivateEntryNotApplicable {
		t.Fatalf("private_entry status = %q, want not_applicable", entry.Access.PrivateEntry.Status)
	}
	if entry.Protection.BrowserAuth.Status != "not_required" || entry.Protection.BrowserAuth.Mode != "not_applicable" {
		t.Fatalf("public browser auth protection = %#v, want not_required/not_applicable", entry.Protection.BrowserAuth)
	}
	if entry.Protection.CIDRAllowlist.Status != "not_applicable" || entry.Protection.CIDRAllowlist.NginxSatisfy != "not_applicable" || len(entry.Protection.CIDRAllowlist.CIDRs) != 0 {
		t.Fatalf("public CIDR allowlist protection = %#v, want not_applicable", entry.Protection.CIDRAllowlist)
	}
	if entry.Observability.Service.SystemdUnit != "api.service" || entry.Observability.Certificate.RenewTimer != "api-lego-renew.timer" || entry.Observability.AccessLog.ExportedRaw {
		t.Fatalf("observability = %#v, want service/certificate/access-log metadata without raw export", entry.Observability)
	}
	if _, ok := summary.Summary.ByAccessMode[domain.AccessModeBrowser]; !ok {
		t.Fatalf("summary by_access_mode missing browser zero value: %#v", summary.Summary.ByAccessMode)
	}
	if _, ok := summary.Summary.ByAccessMode[domain.AccessModePrivateClient]; !ok {
		t.Fatalf("summary by_access_mode missing private_client zero value: %#v", summary.Summary.ByAccessMode)
	}
	for _, status := range []domain.DiagnosticStatus{
		domain.DiagnosticStatusPass,
		domain.DiagnosticStatusWarn,
		domain.DiagnosticStatusManual,
		domain.DiagnosticStatusUnknown,
		domain.DiagnosticStatusFail,
	} {
		if _, ok := summary.Summary.RiskCounts[status]; !ok {
			t.Fatalf("summary risk_counts missing %s zero value: %#v", status, summary.Summary.RiskCounts)
		}
	}
}

func TestAppSummaryAllowsMissingActivationConfirmations(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want missing confirmation failure")
	}

	summary, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", cfg, AppObservations{
		GeneratedAt: time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC),
		Activation:  domain.NotApplicableActivationRef(),
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations() error = %v", err)
	}
	entry := summary.Resources[0]
	if entry.Access.AccessMode != domain.AccessModePublic || entry.Access.RiskLabel != domain.AccessRiskPublicInternet {
		t.Fatalf("access = %#v, want display-only public risk summary", entry.Access)
	}
	if entry.Protection.OriginProtection.Status != domain.OriginProtectionNone {
		t.Fatalf("origin protection = %#v, want display-only direct origin summary", entry.Protection.OriginProtection)
	}
}

func TestAppSummaryUsesExplicitConfigPathRef(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "custom", "app.yaml")
	summary, err := AppSummaryForConfigPath("ins_00112233445566778899aabbccddeeff", "dev", path, testConfig(), domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummaryForConfigPath() error = %v", err)
	}
	want, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("Abs() error = %v", err)
	}
	if got := summary.Resources[0].Resource.ConfigRef.Path; got != filepath.Clean(want) {
		t.Fatalf("config_ref.path = %q, want %q", got, filepath.Clean(want))
	}

	plan, err := AppPlan("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), AppPlanOptions{
		ConfigPath:    path,
		Actor:         testPlanOptions(domain.ExposurePlanOperationDeploy).Actor,
		Operation:     domain.ExposurePlanOperationDeploy,
		CreatedAt:     time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC),
		ModifiedPaths: []string{"/etc/nginx/sites-available/api.conf"},
		BeforeDigest:  "none",
	})
	if err != nil {
		t.Fatalf("AppPlan() error = %v", err)
	}
	if got := plan.Resource.ConfigRef.Path; got != filepath.Clean(want) {
		t.Fatalf("plan config_ref.path = %q, want %q", got, filepath.Clean(want))
	}
}

func TestAppSummaryAccessLogMatchesRenderedNginxBehavior(t *testing.T) {
	t.Parallel()

	defaultLog := testConfig()
	summary, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", defaultLog, AppObservations{
		GeneratedAt: time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC),
		Activation:  domain.NotApplicableActivationRef(),
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations(default log) error = %v", err)
	}
	if got := summary.Resources[0].Observability.AccessLog; got.Status != "enabled" || got.PathRef != "nginx_default" || got.ExportedRaw {
		t.Fatalf("default AccessLog = %#v, want enabled nginx_default without raw export", got)
	}

	disabledLog := testConfig()
	disabledLog.Nginx.AccessLog = "off"
	summary, err = AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", disabledLog, AppObservations{
		GeneratedAt: time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC),
		Activation:  domain.NotApplicableActivationRef(),
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations(disabled log) error = %v", err)
	}
	if got := summary.Resources[0].Observability.AccessLog; got.Status != "disabled" || got.PathRef != "not_applicable" || got.ExportedRaw {
		t.Fatalf("disabled AccessLog = %#v, want disabled not_applicable without raw export", got)
	}

	goAccessLog := testConfig()
	goAccessLog.Nginx.GoAccess.Enabled = true
	goAccessLog.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	summary, err = AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", goAccessLog, AppObservations{
		GeneratedAt: time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC),
		Activation:  domain.NotApplicableActivationRef(),
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations(goaccess log) error = %v", err)
	}
	if got := summary.Resources[0].Observability.AccessLog; got.Status != "enabled" || got.PathRef != "/var/log/lanpanel/apps/api/access.log" || got.ExportedRaw {
		t.Fatalf("goaccess AccessLog = %#v, want canonical GoAccess path without raw export", got)
	}
}

func TestAppPlanWarnsForConfirmedPublicDirectOrigin(t *testing.T) {
	t.Parallel()

	plan, err := AppPlan("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), testPlanOptions(domain.ExposurePlanOperationDeploy, "/etc/nginx/sites-available/api.conf"))
	if err != nil {
		t.Fatalf("AppPlan() error = %v", err)
	}
	if plan.Decision.Status != domain.ExposurePlanDecisionWarn {
		t.Fatalf("Decision status = %q, want warn", plan.Decision.Status)
	}
	if plan.SchemaVersion != domain.ExposurePlanSchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", plan.SchemaVersion, domain.ExposurePlanSchemaVersion)
	}
	if plan.PlanID == "" || plan.Operation != domain.ExposurePlanOperationDeploy || len(plan.ResourcesChanged) != 1 || plan.AfterDigest == "" {
		t.Fatalf("AppPlan() missing schema fields: %#v", plan)
	}
	if len(plan.Decision.RequiredConfirmations) != 0 {
		t.Fatalf("RequiredConfirmations = %#v, want none", plan.Decision.RequiredConfirmations)
	}
	if len(plan.ActivationPreview.ReloadServices) != 1 || plan.ActivationPreview.ReloadServices[0] != "nginx.service" || len(plan.ActivationPreview.CertificatesChanged) != 1 || plan.ActivationPreview.CertificatesChanged[0] != "api.example.com" || !plan.ActivationPreview.PublicExposureChanged {
		t.Fatalf("deploy ActivationPreview = %#v, want nginx reload, certificate domain, and public exposure change", plan.ActivationPreview)
	}
}

func TestAppPlanUsesOperationSpecificActivationPreviewDefaults(t *testing.T) {
	t.Parallel()

	realIPPlan, err := AppPlan("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), testPlanOptions(domain.ExposurePlanOperationRealIPRefresh))
	if err != nil {
		t.Fatalf("AppPlan(realip_refresh) error = %v", err)
	}
	if len(realIPPlan.ActivationPreview.ReloadServices) != 1 || realIPPlan.ActivationPreview.ReloadServices[0] != "nginx.service" || len(realIPPlan.ActivationPreview.CertificatesChanged) != 0 || realIPPlan.ActivationPreview.PublicExposureChanged {
		t.Fatalf("realip_refresh ActivationPreview = %#v, want nginx reload only", realIPPlan.ActivationPreview)
	}

	browserAuthPlan, err := AppPlan("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), testPlanOptions(domain.ExposurePlanOperationBrowserAuthRotate))
	if err != nil {
		t.Fatalf("AppPlan(browser_auth_rotate) error = %v", err)
	}
	if len(browserAuthPlan.ActivationPreview.ReloadServices) != 0 || len(browserAuthPlan.ActivationPreview.CertificatesChanged) != 0 || browserAuthPlan.ActivationPreview.PublicExposureChanged {
		t.Fatalf("browser_auth_rotate ActivationPreview = %#v, want no default reload, certificates, or public exposure change", browserAuthPlan.ActivationPreview)
	}
}

func TestBrowserAuthRotateDoesNotBlockOnOriginProtectionUnknown(t *testing.T) {
	t.Parallel()

	cfg := edgeOneConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.AuthBasicUserFile = "/etc/api/browser.htpasswd"
	plan, err := AppPlanWithObservations("ins_00112233445566778899aabbccddeeff", "dev", cfg, testPlanOptions(domain.ExposurePlanOperationBrowserAuthRotate), AppObservations{
		OriginProtectionStatus:   domain.OriginProtectionConfiguredUnknown,
		BrowserAuthRuntimeStatus: domain.DiagnosticStatusPass,
	})
	if err != nil {
		t.Fatalf("AppPlanWithObservations() error = %v", err)
	}
	if plan.Decision.Status != domain.ExposurePlanDecisionWarn {
		t.Fatalf("Decision.Status = %q, want warn for non-widening browser auth rotation", plan.Decision.Status)
	}
	if len(plan.DiagnosticBlockers) != 0 || len(plan.Decision.Blockers) != 0 {
		t.Fatalf("blockers = %#v/%#v, want none for browser auth rotation", plan.DiagnosticBlockers, plan.Decision.Blockers)
	}
}

func TestAppPlanBlocksBrowserAuthRuntimeFailures(t *testing.T) {
	t.Parallel()

	for _, status := range []domain.DiagnosticStatus{domain.DiagnosticStatusFail, domain.DiagnosticStatusUnknown} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()

			cfg := testConfig()
			cfg.Access.AccessMode = appconfig.AccessModeBrowser
			cfg.Access.PublicRiskConfirmed = false
			cfg.Access.BrowserAuth.AuthBasicUserFile = "/etc/api/browser.htpasswd"
			plan, err := AppPlanWithObservations("ins_00112233445566778899aabbccddeeff", "dev", cfg, testPlanOptions(domain.ExposurePlanOperationDeploy), AppObservations{
				BrowserAuthRuntimeStatus: status,
			})
			if err != nil {
				t.Fatalf("AppPlanWithObservations() error = %v", err)
			}
			want := diagnosticStatusPlanDecision(status)
			if plan.Decision.Status != want {
				t.Fatalf("Decision.Status = %q, want %q", plan.Decision.Status, want)
			}
			if len(plan.Decision.Blockers) != 1 || plan.Decision.Blockers[0] != "browser-auth-runtime-readable" {
				t.Fatalf("Decision.Blockers = %#v, want runtime blocker", plan.Decision.Blockers)
			}
			if len(plan.DiagnosticBlockers) != 1 || !plan.DiagnosticBlockers[0].BlocksActivation || plan.DiagnosticBlockers[0].Status != status {
				t.Fatalf("DiagnosticBlockers = %#v, want activation blocker with status %q", plan.DiagnosticBlockers, status)
			}
		})
	}
}

func TestAppPlanBlocksManagedBrowserAuthMarkerFailures(t *testing.T) {
	t.Parallel()

	for _, status := range []domain.DiagnosticStatus{domain.DiagnosticStatusFail, domain.DiagnosticStatusUnknown} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()

			cfg := testConfig()
			cfg.Access.AccessMode = appconfig.AccessModeBrowser
			cfg.Access.PublicRiskConfirmed = false
			cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
				CredentialID:        "api",
				HtpasswdPath:        "/etc/lanpanel/browser-auth/api.htpasswd",
				Username:            "admin",
				PasswordFingerprint: "sha256:0011223344556677",
			}
			plan, err := AppPlanWithObservations("ins_00112233445566778899aabbccddeeff", "dev", cfg, testPlanOptions(domain.ExposurePlanOperationDeploy), AppObservations{
				BrowserAuthRuntimeStatus: domain.DiagnosticStatusPass,
				BrowserAuthMarkerStatus:  status,
			})
			if err != nil {
				t.Fatalf("AppPlanWithObservations() error = %v", err)
			}
			want := diagnosticStatusPlanDecision(status)
			if plan.Decision.Status != want {
				t.Fatalf("Decision.Status = %q, want %q", plan.Decision.Status, want)
			}
			if len(plan.Decision.Blockers) != 1 || plan.Decision.Blockers[0] != "browser-auth-marker-present" {
				t.Fatalf("Decision.Blockers = %#v, want marker blocker", plan.Decision.Blockers)
			}
			if len(plan.DiagnosticBlockers) != 1 || !plan.DiagnosticBlockers[0].BlocksActivation || plan.DiagnosticBlockers[0].Status != status {
				t.Fatalf("DiagnosticBlockers = %#v, want activation blocker with status %q", plan.DiagnosticBlockers, status)
			}
		})
	}
}

func TestAppPlanRequiresMissingPublicAndDirectOriginConfirmations(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	wantDigest, err := configDigest(cfg)
	if err != nil {
		t.Fatalf("configDigest() error = %v", err)
	}
	plan, err := AppPlan("ins_00112233445566778899aabbccddeeff", "dev", cfg, testPlanOptions(domain.ExposurePlanOperationDeploy, "/etc/nginx/sites-available/api.conf"))
	if err != nil {
		t.Fatalf("AppPlan() error = %v", err)
	}
	if plan.Decision.Status != domain.ExposurePlanDecisionManual {
		t.Fatalf("Decision status = %q, want manual", plan.Decision.Status)
	}
	if len(plan.Decision.RequiredConfirmations) != 2 {
		t.Fatalf("RequiredConfirmations = %#v, want public and direct-origin confirmations", plan.Decision.RequiredConfirmations)
	}
	if plan.AfterDigest != wantDigest {
		t.Fatalf("AfterDigest = %q, want original unconfirmed config digest %q", plan.AfterDigest, wantDigest)
	}
}

func TestAppPlanBlocksUnknownEdgeOneOriginProtection(t *testing.T) {
	t.Parallel()

	cfg := edgeOneConfig()
	plan, err := AppPlan("ins_00112233445566778899aabbccddeeff", "dev", cfg, testPlanOptions(domain.ExposurePlanOperationDeploy, "/etc/nginx/sites-available/api.conf"))
	if err != nil {
		t.Fatalf("AppPlan() error = %v", err)
	}
	if plan.Decision.Status != domain.ExposurePlanDecisionUnknown {
		t.Fatalf("Decision status = %q, want unknown", plan.Decision.Status)
	}
	if len(plan.Decision.Blockers) != 1 || plan.Decision.Blockers[0] != "origin-protection" {
		t.Fatalf("Decision blockers = %#v, want origin-protection", plan.Decision.Blockers)
	}
	if len(plan.DiagnosticBlockers) != 1 || plan.DiagnosticBlockers[0].Status != domain.DiagnosticStatusUnknown || !plan.DiagnosticBlockers[0].BlocksActivation {
		t.Fatalf("DiagnosticBlockers = %#v, want activation-blocking unknown origin protection", plan.DiagnosticBlockers)
	}
}

func TestAppPlanUsesObservedOriginProtectionDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		observations AppObservations
		decision     domain.ExposurePlanDecision
		required     string
	}{
		{name: "pass", observations: edgeOnePassObservations(), decision: domain.ExposurePlanDecisionWarn},
		{name: "manual", observations: AppObservations{OriginProtectionStatus: domain.OriginProtectionConfiguredManual}, decision: domain.ExposurePlanDecisionManual, required: "origin-protection-manual"},
		{name: "unknown", observations: AppObservations{OriginProtectionStatus: domain.OriginProtectionConfiguredUnknown}, decision: domain.ExposurePlanDecisionUnknown},
		{name: "fail", observations: AppObservations{OriginProtectionStatus: domain.OriginProtectionConfiguredFail}, decision: domain.ExposurePlanDecisionFail},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan, err := AppPlanWithObservations("ins_00112233445566778899aabbccddeeff", "dev", edgeOneConfig(), testPlanOptions(domain.ExposurePlanOperationDeploy), tt.observations)
			if err != nil {
				t.Fatalf("AppPlanWithObservations() error = %v", err)
			}
			if plan.Decision.Status != tt.decision {
				t.Fatalf("Decision status = %q, want %q", plan.Decision.Status, tt.decision)
			}
			if strings.Join(plan.Decision.RequiredConfirmations, ",") != tt.required {
				t.Fatalf("RequiredConfirmations = %#v, want %q", plan.Decision.RequiredConfirmations, tt.required)
			}
		})
	}
}

func TestAppPlanDowngradesPassWithoutOriginProtectionEvidence(t *testing.T) {
	t.Parallel()

	plan, err := AppPlanWithObservations("ins_00112233445566778899aabbccddeeff", "dev", edgeOneConfig(), testPlanOptions(domain.ExposurePlanOperationDeploy), AppObservations{
		OriginProtectionStatus: domain.OriginProtectionConfiguredPass,
	})
	if err != nil {
		t.Fatalf("AppPlanWithObservations() error = %v", err)
	}
	if plan.OriginProtection != domain.OriginProtectionConfiguredUnknown {
		t.Fatalf("OriginProtection = %q, want configured_unknown", plan.OriginProtection)
	}
	if plan.Decision.Status != domain.ExposurePlanDecisionUnknown {
		t.Fatalf("Decision status = %q, want unknown", plan.Decision.Status)
	}
}

func TestAppSummaryUsesObservedOriginProtectionStatus(t *testing.T) {
	t.Parallel()

	cfg := edgeOneConfig()
	summary, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", cfg, edgeOnePassObservations())
	if err != nil {
		t.Fatalf("AppSummaryWithObservations() error = %v", err)
	}
	if got := summary.Resources[0].Protection.OriginProtection.Status; got != domain.OriginProtectionConfiguredPass {
		t.Fatalf("OriginProtection = %q, want configured_pass", got)
	}
	if got := summary.Summary.RiskCounts[domain.DiagnosticStatusWarn]; got != 1 {
		t.Fatalf("warn risk count = %d, want public risk warning", got)
	}
	entry := summary.Resources[0]
	if got := entry.Protection.OriginProtection.ReferenceDigest; got != edgeOneReferenceDigest {
		t.Fatalf("reference digest = %q, want %q", got, edgeOneReferenceDigest)
	}
	if got := entry.Protection.RealIP; got.Status != domain.DiagnosticStatusPass || got.TrustedCIDRCount != 2 || got.ClientIPHeader != appconfig.RealIPHeaderEdgeOne || got.SpoofingRejection != string(domain.DiagnosticStatusPass) {
		t.Fatalf("RealIP = %#v, want pass evidence", got)
	}
}

func TestAppSummaryRejectsWhitespacePaddedOriginReferenceDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		digest string
	}{
		{name: "leading", digest: " " + edgeOneReferenceDigest},
		{name: "trailing", digest: edgeOneReferenceDigest + " "},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", edgeOneConfig(), AppObservations{
				OriginProtectionStatus:          domain.OriginProtectionConfiguredPass,
				OriginProtectionReferenceDigest: tt.digest,
				RealIPTrustedCIDRCount:          2,
				RealIPClientIPHeader:            appconfig.RealIPHeaderEdgeOne,
				RealIPSpoofingRejection:         domain.DiagnosticStatusPass,
			})
			if err == nil || !strings.Contains(err.Error(), "must not include leading or trailing whitespace") {
				t.Fatalf("AppSummaryWithObservations() error = %v, want whitespace reference digest failure", err)
			}
		})
	}
}

func TestAppSummaryMarksCheckpointActivationActive(t *testing.T) {
	t.Parallel()

	summary, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), AppObservations{
		Activation: domain.ActivationRef{
			Kind:   domain.ActivationRefCheckpoint,
			Path:   "/var/lib/lanpanel/checkpoints/latest.json",
			Digest: "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations() error = %v", err)
	}
	if got := summary.Resources[0].Resource.State; got != domain.ResourceStateActive {
		t.Fatalf("Resource.State = %q, want active", got)
	}
}

func TestPrivateClientSummaryIsReservedAndDeployPlanBlocksActivation(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Access.AccessMode = appconfig.AccessModePrivateClient
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	summary, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() private_client error = %v", err)
	}
	entry := summary.Resources[0]
	if entry.Access.AccessMode != domain.AccessModePrivateClient || entry.Access.PublicEntry.Status != domain.PublicEntryNotApplicable || entry.Access.PrivateEntry.Status != domain.PrivateEntryEnabled {
		t.Fatalf("Access = %#v, want private_client with public not_applicable", entry.Access)
	}
	if entry.Target.TargetKind != domain.ResourceTargetKindPrivateResource {
		t.Fatalf("TargetKind = %q, want private_resource", entry.Target.TargetKind)
	}
	if entry.Protection.BrowserAuth.Status != "not_applicable" || entry.Protection.BrowserAuth.Mode != "not_applicable" || entry.Protection.BrowserAuth.AuthFileRef != "not_applicable" {
		t.Fatalf("BrowserAuth = %#v, want private_client not_applicable", entry.Protection.BrowserAuth)
	}
	plan, err := AppPlan("ins_00112233445566778899aabbccddeeff", "dev", cfg, AppPlanOptions{Operation: domain.ExposurePlanOperationDeploy, ConfigPath: "/etc/lanpanel/private-app.yaml"})
	if err != nil {
		t.Fatalf("AppPlan() private_client error = %v", err)
	}
	if plan.Decision.Status != domain.ExposurePlanDecisionFail || len(plan.DiagnosticBlockers) != 1 || plan.DiagnosticBlockers[0].ID != "private-client-p1" {
		t.Fatalf("Plan decision/blockers = %q %#v, want private_client P1 blocker", plan.Decision.Status, plan.DiagnosticBlockers)
	}
	if len(plan.ActivationPreview.ReloadServices) != 0 || plan.ActivationPreview.PublicExposureChanged || len(plan.ActivationPreview.CertificatesChanged) != 0 {
		t.Fatalf("ActivationPreview = %#v, want no P0 public activation preview", plan.ActivationPreview)
	}
}

func TestAppSummaryDoesNotMarkGoAccessAuthBasicPassWithoutEvidence(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/api/goaccess.htpasswd"
	summary, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() error = %v", err)
	}
	if got := summary.Resources[0].Observability.GoAccess.AuthBasic; got != string(domain.DiagnosticStatusUnknown) {
		t.Fatalf("GoAccess.AuthBasic = %q, want unknown", got)
	}

	summary, err = AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", cfg, AppObservations{
		Diagnostics: []domain.DiagnosticRef{{ID: "goaccess-auth-file", Status: domain.DiagnosticStatusPass, RedactionStatus: domain.RedactionStatusNoSensitiveData}},
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations() error = %v", err)
	}
	if got := summary.Resources[0].Observability.GoAccess.AuthBasic; got != string(domain.DiagnosticStatusPass) {
		t.Fatalf("GoAccess.AuthBasic = %q, want pass", got)
	}
}

func TestAppSummaryMarksBrowserAuthUnknownAndFailRisk(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.AuthBasicUserFile = "/etc/api/browser.htpasswd"
	summary, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() error = %v", err)
	}
	entry := summary.Resources[0]
	if entry.Protection.BrowserAuth.RuntimeReadable != string(domain.DiagnosticStatusUnknown) {
		t.Fatalf("BrowserAuth.RuntimeReadable = %q, want unknown", entry.Protection.BrowserAuth.RuntimeReadable)
	}
	if summary.Summary.RiskCounts[domain.DiagnosticStatusUnknown] != 1 {
		t.Fatalf("RiskCounts = %#v, want browser auth unknown risk", summary.Summary.RiskCounts)
	}

	cfg.Access.BrowserAuth.AuthBasicUserFile = ""
	cfg.Access.BrowserAuth.Managed = appconfig.ManagedBrowserAuthRef{
		CredentialID:        "api",
		HtpasswdPath:        "/etc/lanpanel/browser-auth/api.htpasswd",
		Username:            "admin",
		PasswordFingerprint: "sha256:0011223344556677",
	}
	summary, err = AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", cfg, AppObservations{
		BrowserAuthRuntimeStatus: domain.DiagnosticStatusPass,
		BrowserAuthMarkerStatus:  domain.DiagnosticStatusFail,
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations() error = %v", err)
	}
	entry = summary.Resources[0]
	if entry.Protection.BrowserAuth.RuntimeReadable != string(domain.DiagnosticStatusPass) || entry.Protection.BrowserAuth.MarkerPresent != string(domain.DiagnosticStatusFail) {
		t.Fatalf("BrowserAuth = %#v, want pass runtime and fail marker", entry.Protection.BrowserAuth)
	}
	if summary.Summary.RiskCounts[domain.DiagnosticStatusFail] != 1 {
		t.Fatalf("RiskCounts = %#v, want browser auth fail risk", summary.Summary.RiskCounts)
	}
}

func TestAppSummaryRestrictsObservedOriginProtectionToConfiguredMode(t *testing.T) {
	t.Parallel()

	directSummary, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), AppObservations{
		OriginProtectionStatus: domain.OriginProtectionNone,
	})
	if err != nil {
		t.Fatalf("AppSummaryWithObservations() direct error = %v", err)
	}
	if got := directSummary.Resources[0].Protection.OriginProtection.Status; got != domain.OriginProtectionNone {
		t.Fatalf("direct origin protection = %q, want none", got)
	}

	_, err = AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), AppObservations{
		OriginProtectionStatus: domain.OriginProtectionConfiguredPass,
	})
	if err == nil {
		t.Fatal("AppSummaryWithObservations() direct error = nil, want incompatible configured_pass failure")
	}

	for _, status := range []domain.OriginProtectionStatus{domain.OriginProtectionNone, domain.OriginProtectionNotApplicable} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()

			_, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", edgeOneConfig(), AppObservations{
				OriginProtectionStatus: status,
			})
			if err == nil {
				t.Fatalf("AppSummaryWithObservations() error = nil, want incompatible %s failure", status)
			}
		})
	}
}

func TestAppSummaryRejectsUnsupportedObservedOriginProtectionStatus(t *testing.T) {
	t.Parallel()

	_, err := AppSummaryWithObservations("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), AppObservations{
		OriginProtectionStatus: domain.OriginProtectionStatus("typo"),
	})
	if err == nil {
		t.Fatal("AppSummaryWithObservations() error = nil, want unsupported origin protection status failure")
	}
}

func TestAppSummaryRejectsUnsupportedDiagnosticStatus(t *testing.T) {
	t.Parallel()

	_, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), domain.NotApplicableActivationRef(), []domain.DiagnosticRef{
		{ID: "runtime", Status: domain.DiagnosticStatus("typo")},
	})
	if err == nil {
		t.Fatal("AppSummary() error = nil, want unsupported diagnostic status failure")
	}
}

func TestAppSummaryRejectsInvalidActivationRefs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		activation domain.ActivationRef
	}{
		{
			name:       "unsupported kind",
			activation: domain.ActivationRef{Kind: domain.ActivationRefKind("future")},
		},
		{
			name:       "checkpoint missing digest",
			activation: domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: "/var/lib/lanpanel/checkpoint.json"},
		},
		{
			name:       "checkpoint malformed digest",
			activation: domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: "/var/lib/lanpanel/checkpoint.json", Digest: "x"},
		},
		{
			name:       "not applicable with path",
			activation: domain.ActivationRef{Kind: domain.ActivationRefNotApplicable, Path: "/tmp/checkpoint.json"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), tt.activation, nil)
			if err == nil {
				t.Fatal("AppSummary() error = nil, want invalid activation ref failure")
			}
		})
	}
}

func TestConfigDigestChangesForExposureRelevantFields(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.AuthBasicUserFile = "/etc/example-app/browser.htpasswd"
	first, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() first error = %v", err)
	}
	if got := first.Resources[0].Protection.CIDRAllowlist; got.Status != "disabled" || got.NginxSatisfy != "not_applicable" || len(got.CIDRs) != 0 {
		t.Fatalf("browser CIDR allowlist protection = %#v, want disabled", got)
	}
	cfg.Access.CIDRAllowlist = []string{"198.51.100.0/24"}
	second, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() second error = %v", err)
	}
	if got := second.Resources[0].Protection.CIDRAllowlist; got.Status != "enabled" || got.NginxSatisfy != "all" || len(got.CIDRs) != 1 || got.CIDRs[0] != "198.51.100.0/24" {
		t.Fatalf("browser CIDR allowlist protection = %#v, want enabled count 1", got)
	}
	if first.Resources[0].ConfigDigest == second.Resources[0].ConfigDigest {
		t.Fatal("ConfigDigest did not change after exposure-relevant CIDR update")
	}
}

func TestConfigDigestCanonicalizesEquivalentNonSecretConfig(t *testing.T) {
	t.Parallel()

	base := testConfig()
	equivalent := testConfig()
	equivalent.App.Domains = []string{"API.EXAMPLE.COM."}
	equivalent.Nginx.HTTP2 = nil
	equivalent.Nginx.ClientMaxBodySize = ""
	equivalent.Nginx.Proxy.ReadTimeout = ""
	equivalent.Nginx.Proxy.SendTimeout = ""
	first := digestForConfig(t, base)
	second := digestForConfig(t, equivalent)
	if first != second {
		t.Fatalf("digest changed for normalized-equivalent config: %q != %q", first, second)
	}
}

func TestConfigDigestChangesForRenderedNonSecretFields(t *testing.T) {
	t.Parallel()

	base := testConfig()
	baseDigest := digestForConfig(t, base)
	tests := []struct {
		name   string
		mutate func(*appconfig.Config)
	}{
		{
			name: "static location",
			mutate: func(cfg *appconfig.Config) {
				cfg.Nginx.StaticLocations = []appconfig.NginxStaticLocationConfig{{Path: "/static/", Alias: "/opt/api/static/"}}
			},
		},
		{
			name: "proxy setting",
			mutate: func(cfg *appconfig.Config) {
				cfg.Nginx.Proxy.ReadTimeout = "30s"
			},
		},
		{
			name: "service working directory",
			mutate: func(cfg *appconfig.Config) {
				cfg.Service.WorkingDirectory = "/opt/api"
			},
		},
		{
			name: "dns01 settings",
			mutate: func(cfg *appconfig.Config) {
				cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
				cfg.DNS01.Provider = "tencentcloud"
				cfg.DNS01.EnvFile = "/etc/lanpanel/dns.env"
			},
		},
		{
			name: "tailscale listen opt-in",
			mutate: func(cfg *appconfig.Config) {
				cfg.Tailscale.EnabledForListen = true
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := base
			tt.mutate(&cfg)
			if got := digestForConfig(t, cfg); got == baseDigest {
				t.Fatalf("ConfigDigest did not change after %s update", tt.name)
			}
		})
	}
}

func edgeOneConfig() appconfig.Config {
	cfg := testConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns.env"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-12345678",
				EnvFile: "/etc/lanpanel/edgeone.env",
			},
		},
	}
	return cfg
}

const edgeOneReferenceDigest = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func edgeOnePassObservations() AppObservations {
	return AppObservations{
		OriginProtectionStatus:          domain.OriginProtectionConfiguredPass,
		OriginProtectionReferenceDigest: edgeOneReferenceDigest,
		RealIPTrustedCIDRCount:          2,
		RealIPClientIPHeader:            appconfig.RealIPHeaderEdgeOne,
		RealIPSpoofingRejection:         domain.DiagnosticStatusPass,
	}
}

func digestForConfig(t *testing.T, cfg appconfig.Config) string {
	t.Helper()
	summary, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() error = %v", err)
	}
	return summary.Resources[0].ConfigDigest
}

func TestConfigDigestChangesForRealIPAndGoAccessCIDRFields(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns.env"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/review-app/goaccess.htpasswd"
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"203.0.113.0/24"}
	enabled := true
	cfg.RealIP.Profiles = map[string]appconfig.RealIPProfileConfig{
		"edgeone-prod": {
			Enabled:  &enabled,
			Provider: appconfig.RealIPProviderEdgeOne,
			EdgeOne: appconfig.RealIPEdgeOneConfig{
				ZoneID:  "zone-12345678",
				EnvFile: "/etc/lanpanel/edgeone.env",
			},
		},
	}
	first, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() first error = %v", err)
	}
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"198.51.100.0/24"}
	second, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() second error = %v", err)
	}
	if first.Resources[0].ConfigDigest == second.Resources[0].ConfigDigest {
		t.Fatal("ConfigDigest did not change after GoAccess CIDR update")
	}
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"203.0.113.0/24"}
	cfg.RealIP.Profiles["edgeone-prod"] = appconfig.RealIPProfileConfig{
		Enabled:  &enabled,
		Provider: appconfig.RealIPProviderEdgeOne,
		EdgeOne: appconfig.RealIPEdgeOneConfig{
			ZoneID:  "zone-87654321",
			EnvFile: "/etc/lanpanel/edgeone.env",
		},
	}
	third, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", cfg, domain.NotApplicableActivationRef(), nil)
	if err != nil {
		t.Fatalf("AppSummary() third error = %v", err)
	}
	if first.Resources[0].ConfigDigest == third.Resources[0].ConfigDigest {
		t.Fatal("ConfigDigest did not change after RealIP profile update")
	}
}

func TestAppSummaryRejectsInvalidDiagnosticRefMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ref  domain.DiagnosticRef
		want string
	}{
		{
			name: "scope",
			ref:  domain.DiagnosticRef{ID: "runtime", Status: domain.DiagnosticStatusPass, Scope: domain.DiagnosticScope("future"), RedactionStatus: domain.RedactionStatusNoSensitiveData},
			want: "diagnostics[0].scope",
		},
		{
			name: "severity",
			ref:  domain.DiagnosticRef{ID: "runtime", Status: domain.DiagnosticStatusPass, Severity: domain.DiagnosticSeverity("future"), RedactionStatus: domain.RedactionStatusNoSensitiveData},
			want: "diagnostics[0].severity",
		},
		{
			name: "evidence",
			ref:  domain.DiagnosticRef{ID: "runtime", Status: domain.DiagnosticStatusPass, EvidenceSource: domain.DiagnosticEvidenceSource("future"), RedactionStatus: domain.RedactionStatusNoSensitiveData},
			want: "diagnostics[0].evidence_source",
		},
		{
			name: "responsible",
			ref:  domain.DiagnosticRef{ID: "runtime", Status: domain.DiagnosticStatusPass, ResponsibleParty: domain.DiagnosticResponsibleParty("future"), RedactionStatus: domain.RedactionStatusNoSensitiveData},
			want: "diagnostics[0].responsible_party",
		},
		{
			name: "redaction",
			ref:  domain.DiagnosticRef{ID: "runtime", Status: domain.DiagnosticStatusPass, Redaction: domain.Redaction("future"), RedactionStatus: domain.RedactionStatusNoSensitiveData},
			want: "diagnostics[0].redaction",
		},
		{
			name: "missing redaction status",
			ref:  domain.DiagnosticRef{ID: "runtime", Status: domain.DiagnosticStatusPass},
			want: "diagnostics[0].redaction_status",
		},
		{
			name: "redaction status",
			ref:  domain.DiagnosticRef{ID: "runtime", Status: domain.DiagnosticStatusPass, RedactionStatus: domain.RedactionStatus("future")},
			want: "diagnostics[0].redaction_status",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := AppSummary("ins_00112233445566778899aabbccddeeff", "dev", testConfig(), domain.NotApplicableActivationRef(), []domain.DiagnosticRef{tt.ref})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("AppSummary() error = %v, want %q", err, tt.want)
			}
		})
	}
}
