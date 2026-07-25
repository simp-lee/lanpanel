package appassets

import (
	"lanpanel/internal/appconfig"
	"lanpanel/internal/assets"
	"slices"
	"strings"
	"testing"
)

func testListenConfig() appconfig.Config {
	cfg := appconfig.New()
	cfg.App.Name = "example-app"
	cfg.App.Domains = []string{"abc.com", "www.abc.com"}
	cfg.App.CertificateEmail = "ops@example.com"
	cfg.App.Listen = "127.0.0.1:18001"
	cfg.Access.AccessMode = appconfig.AccessModePublic
	cfg.Access.PublicRiskConfirmed = true
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeNone
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = true
	cfg.Service.ExecStart = "/opt/example-app/example-app --listen 127.0.0.1:18001"
	cfg.Service.WorkingDirectory = "/opt/example-app"
	return cfg
}

func TestRuntimeCatalogIncludesServiceOnlyForListenMode(t *testing.T) {
	t.Parallel()

	listenCatalog, err := RuntimeCatalog(testListenConfig())
	if err != nil {
		t.Fatalf("RuntimeCatalog() error = %v", err)
	}
	if len(listenCatalog) != 5 {
		t.Fatalf("len(listenCatalog) = %d, want 5", len(listenCatalog))
	}
	if !hasSource(listenCatalog, ServiceTemplate) {
		t.Fatalf("listen catalog missing %s", ServiceTemplate)
	}

	upstream := testListenConfig()
	upstream.App.Listen = ""
	upstream.App.Upstream = "100.64.10.20:18001"
	upstream.Service = appconfig.ServiceConfig{}
	upstreamCatalog, err := RuntimeCatalog(upstream)
	if err != nil {
		t.Fatalf("RuntimeCatalog(upstream) error = %v", err)
	}
	if len(upstreamCatalog) != 4 {
		t.Fatalf("len(upstreamCatalog) = %d, want 4", len(upstreamCatalog))
	}
	if hasSource(upstreamCatalog, ServiceTemplate) {
		t.Fatalf("upstream catalog unexpectedly includes %s", ServiceTemplate)
	}
}

func TestRuntimeCatalogIncludesGoAccessAssetsOnlyWhenEnabled(t *testing.T) {
	t.Parallel()

	disabledCatalog, err := RuntimeCatalog(testListenConfig())
	if err != nil {
		t.Fatalf("RuntimeCatalog(disabled) error = %v", err)
	}
	for _, sourcePath := range []string{GoAccessConfigTemplate, GoAccessServiceTemplate, GoAccessLogrotateTemplate} {
		if hasSource(disabledCatalog, sourcePath) {
			t.Fatalf("disabled catalog unexpectedly includes %s", sourcePath)
		}
	}

	enabled := testListenConfig()
	enabled.Nginx.GoAccess.Enabled = true
	enabled.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	enabledCatalog, err := RuntimeCatalog(enabled)
	if err != nil {
		t.Fatalf("RuntimeCatalog(enabled) error = %v", err)
	}
	for _, sourcePath := range []string{GoAccessConfigTemplate, GoAccessServiceTemplate, GoAccessLogrotateTemplate} {
		if !hasSource(enabledCatalog, sourcePath) {
			t.Fatalf("enabled catalog missing %s", sourcePath)
		}
	}

	explicit := enabled
	explicit.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
	explicitCatalog, err := RuntimeCatalog(explicit)
	if err != nil {
		t.Fatalf("RuntimeCatalog(explicit) error = %v", err)
	}
	if !hasSource(explicitCatalog, GoAccessConfigTemplate) || !hasSource(explicitCatalog, GoAccessServiceTemplate) {
		t.Fatalf("explicit-log GoAccess catalog missing config/service assets")
	}
	if hasSource(explicitCatalog, GoAccessLogrotateTemplate) {
		t.Fatalf("explicit-log GoAccess catalog unexpectedly includes managed logrotate asset")
	}
}

func TestRuntimeCatalogMatchesCanonicalAppTemplates(t *testing.T) {
	t.Parallel()

	expected := appTemplateSourcesFromAssetCatalog(t)
	listenCatalog, err := RuntimeCatalog(testListenConfig())
	if err != nil {
		t.Fatalf("RuntimeCatalog(listen) error = %v", err)
	}
	listenSources := sourceSet(listenCatalog)
	for _, sourcePath := range expected {
		if isGoAccessTemplate(sourcePath) {
			if _, ok := listenSources[sourcePath]; ok {
				t.Fatalf("disabled listen runtime catalog unexpectedly includes GoAccess template %q", sourcePath)
			}
			continue
		}
		if _, ok := listenSources[sourcePath]; !ok {
			t.Fatalf("listen runtime catalog missing canonical app template %q", sourcePath)
		}
		if _, err := NewLoader().Read(sourcePath); err != nil {
			t.Fatalf("app embedded loader cannot read %q: %v", sourcePath, err)
		}
	}

	upstream := testListenConfig()
	upstream.App.Listen = ""
	upstream.App.Upstream = "100.64.10.20:18001"
	upstream.Service = appconfig.ServiceConfig{}
	upstreamCatalog, err := RuntimeCatalog(upstream)
	if err != nil {
		t.Fatalf("RuntimeCatalog(upstream) error = %v", err)
	}
	upstreamSources := sourceSet(upstreamCatalog)
	for _, sourcePath := range expected {
		_, ok := upstreamSources[sourcePath]
		if sourcePath == ServiceTemplate || isGoAccessTemplate(sourcePath) {
			if ok {
				t.Fatalf("upstream runtime catalog unexpectedly includes conditional template %q", sourcePath)
			}
			continue
		}
		if !ok {
			t.Fatalf("upstream runtime catalog missing canonical app template %q", sourcePath)
		}
	}

	enabled := testListenConfig()
	enabled.Nginx.GoAccess.Enabled = true
	enabled.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	enabledCatalog, err := RuntimeCatalog(enabled)
	if err != nil {
		t.Fatalf("RuntimeCatalog(enabled) error = %v", err)
	}
	enabledSources := sourceSet(enabledCatalog)
	for _, sourcePath := range expected {
		if _, ok := enabledSources[sourcePath]; !ok {
			t.Fatalf("enabled runtime catalog missing canonical app template %q", sourcePath)
		}
	}
}

func isGoAccessTemplate(sourcePath string) bool {
	switch sourcePath {
	case GoAccessConfigTemplate, GoAccessServiceTemplate, GoAccessLogrotateTemplate:
		return true
	default:
		return false
	}
}

func hasSource(catalog []Asset, source string) bool {
	for _, asset := range catalog {
		if asset.SourcePath == source {
			return true
		}
	}
	return false
}

func sourceSet(catalog []Asset) map[string]struct{} {
	sources := make(map[string]struct{}, len(catalog))
	for _, asset := range catalog {
		sources[asset.SourcePath] = struct{}{}
	}
	return sources
}

func appTemplateSourcesFromAssetCatalog(t *testing.T) []string {
	t.Helper()

	sources := []string{}
	for _, asset := range assets.Catalog() {
		if !strings.HasPrefix(asset.SourcePath, "templates/app/") {
			continue
		}
		if asset.Role != assets.RoleRuntime || asset.ContentMode != assets.ContentModeRender {
			t.Fatalf("catalog asset %q role/mode = %s/%s, want runtime/render", asset.SourcePath, asset.Role, asset.ContentMode)
		}
		sources = append(sources, asset.SourcePath)
	}
	slices.Sort(sources)
	if len(sources) == 0 {
		t.Fatal("embedded asset catalog has no app runtime templates")
	}
	return sources
}
