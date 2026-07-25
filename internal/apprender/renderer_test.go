package apprender

import (
	"lanpanel/internal/appconfig"
	"lanpanel/internal/components/appsvc"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func listenConfig() appconfig.Config {
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

func TestStageRuntimeRendersListenModeAssets(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.Service.EnvFile = "/opt/example-app/web.env"
	staticAccessLog := false
	proxyBuffering := false
	http2 := true
	cfg.Nginx.ClientMaxBodySize = "100m"
	cfg.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
	cfg.Nginx.ErrorLog = "/var/log/nginx/example-app.error.log"
	cfg.Nginx.HTTP2 = &http2
	cfg.Nginx.Proxy.ConnectTimeout = "30s"
	cfg.Nginx.Proxy.ReadTimeout = "600s"
	cfg.Nginx.Proxy.SendTimeout = "600s"
	cfg.Nginx.Proxy.Buffering = &proxyBuffering
	cfg.Nginx.Proxy.RequestBuffering = &proxyBuffering
	cfg.Nginx.StaticLocations = []appconfig.NginxStaticLocationConfig{
		{
			Path:         "/static/",
			Alias:        "/opt/example-app/web/static/",
			CacheControl: "public, max-age=2592000",
			TryFiles:     true,
			GzipStatic:   true,
			AccessLog:    &staticAccessLog,
		},
		{
			Path:        "/sitemap.xml",
			Match:       "exact",
			Alias:       "/opt/example-app/web/static/sitemap.xml",
			DefaultType: "application/xml",
		},
		{
			Path:    "/sitemaps/",
			Alias:   "/opt/example-app/web/static/sitemaps/",
			Expires: "30d",
		},
	}
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	if len(staged) != 5 {
		t.Fatalf("len(staged) = %d, want 5", len(staged))
	}

	var nginxContent []byte
	var hookContent []byte
	var serviceContent []byte
	for _, file := range staged {
		if !strings.Contains(string(file.Content), appsvc.ManagedMarker("example-app")) {
			t.Fatalf("%s missing managed marker", file.SourcePath)
		}
		if file.SourcePath == "templates/app/nginx.conf.tmpl" {
			nginxContent = file.Content
		}
		if file.SourcePath == "templates/app/install-cert-and-reload-nginx.sh.tmpl" {
			hookContent = file.Content
		}
		if file.SourcePath == "templates/app/service.tmpl" {
			serviceContent = file.Content
		}
	}
	if len(nginxContent) == 0 {
		t.Fatal("nginx content not staged")
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	if err := appsvc.ValidateRenderedNginx(cfg, names, nginxContent); err != nil {
		t.Fatalf("ValidateRenderedNginx() error = %v\n%s", err, nginxContent)
	}
	nginxText := string(nginxContent)
	for _, want := range []string{
		"access_log /var/log/lanpanel/custom/example-app.access.log;",
		"error_log /var/log/nginx/example-app.error.log;",
		"http2 on;",
		"client_max_body_size 100m;",
		"location /static/ {\n        alias /opt/example-app/web/static/;",
		`add_header Cache-Control "public, max-age=2592000";`,
		"try_files $uri =404;",
		"gzip_static on;",
		"access_log off;",
		"location = /sitemap.xml {\n        alias /opt/example-app/web/static/sitemap.xml;",
		"default_type application/xml;",
		"location /sitemaps/ {\n        alias /opt/example-app/web/static/sitemaps/;",
		"expires 30d;",
		"proxy_connect_timeout 30s;",
		"proxy_read_timeout 600s;",
		"proxy_send_timeout 600s;",
		"proxy_buffering off;",
		"proxy_request_buffering off;",
	} {
		if !strings.Contains(nginxText, want) {
			t.Fatalf("nginx content missing static location fragment %q\n%s", want, nginxText)
		}
	}
	staticIndex := strings.Index(nginxText, "location /static/ {")
	proxyIndex := strings.LastIndex(nginxText, "location / {\n        proxy_pass")
	if staticIndex < 0 || proxyIndex < 0 || staticIndex > proxyIndex {
		t.Fatalf("static locations must render before proxy location\n%s", nginxText)
	}
	hookText := string(hookContent)
	for _, want := range []string{
		`marker="/etc/example-app/tls/abc.com/.lanpanel-managed"`,
		`expected_marker="Lanpanel-managed: app.name=example-app"`,
		"certificate target is not owned by Lanpanel",
	} {
		if !strings.Contains(hookText, want) {
			t.Fatalf("hook content missing %q\n%s", want, hookText)
		}
	}
	serviceText := string(serviceContent)
	if !strings.Contains(serviceText, "EnvironmentFile=/opt/example-app/web.env") {
		t.Fatalf("service content missing service env file\n%s", serviceText)
	}
}

func TestStageRuntimeRendersBrowserAccessControls(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.Access.AccessMode = appconfig.AccessModeBrowser
	cfg.Access.PublicRiskConfirmed = false
	cfg.Access.BrowserAuth.AuthBasicUserFile = "/etc/example-app/browser.htpasswd"
	cfg.Access.CIDRAllowlist = []string{"203.0.113.0/24"}
	cfg.Nginx.StaticLocations = []appconfig.NginxStaticLocationConfig{{
		Path:  "/static/",
		Alias: "/opt/example-app/web/static/",
	}}
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	nginxText := stagedText(t, staged, "templates/app/nginx.conf.tmpl")
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	if err := appsvc.ValidateRenderedNginx(cfg, names, []byte(nginxText)); err != nil {
		t.Fatalf("ValidateRenderedNginx() error = %v\n%s", err, nginxText)
	}
	for _, want := range []string{
		`auth_basic "Lanpanel Browser";`,
		"auth_basic_user_file /etc/example-app/browser.htpasswd;",
		"allow 203.0.113.0/24;",
		"deny all;",
		`proxy_set_header Authorization "";`,
	} {
		if !strings.Contains(nginxText, want) {
			t.Fatalf("nginx content missing browser access fragment %q\n%s", want, nginxText)
		}
	}
	if strings.Count(nginxText, `auth_basic "Lanpanel Browser";`) != 2 {
		t.Fatalf("browser auth must cover static and proxy locations\n%s", nginxText)
	}
}

func TestStageRuntimePublicAccessDoesNotRenderBrowserAuth(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	nginxText := stagedText(t, staged, "templates/app/nginx.conf.tmpl")
	if strings.Contains(nginxText, `auth_basic "Lanpanel Browser";`) {
		t.Fatalf("public app rendered browser auth\n%s", nginxText)
	}
	if strings.Contains(nginxText, `proxy_set_header Authorization "";`) {
		t.Fatalf("public app cleared Authorization header\n%s", nginxText)
	}
}

func TestStageRuntimeAllowsRealIPDirectiveNamesInStaticAliasWhenRealIPDisabled(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.Nginx.StaticLocations = []appconfig.NginxStaticLocationConfig{{
		Path:  "/static/",
		Alias: "/opt/example-app/web/real_ip_header/set_real_ip_from/",
	}}
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	var nginxContent []byte
	for _, file := range staged {
		if file.SourcePath == "templates/app/nginx.conf.tmpl" {
			nginxContent = file.Content
			break
		}
	}
	if len(nginxContent) == 0 {
		t.Fatal("nginx content not staged")
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	if err := appsvc.ValidateRenderedNginx(cfg, names, nginxContent); err != nil {
		t.Fatalf("ValidateRenderedNginx() error = %v\n%s", err, nginxContent)
	}
}

func TestStageRuntimeRendersRealIPScopedDirectivesAndSanitizedHeaders(t *testing.T) {
	t.Parallel()

	enabled := true
	cfg := listenConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns/tencentcloud.env"
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
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
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	contentBySource := map[string]string{}
	for _, file := range staged {
		contentBySource[file.SourcePath] = string(file.Content)
	}
	nginxText := contentBySource["templates/app/nginx.conf.tmpl"]
	if nginxText == "" {
		t.Fatal("nginx content not staged")
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	if err := appsvc.ValidateRenderedNginx(cfg, names, []byte(nginxText)); err != nil {
		t.Fatalf("ValidateRenderedNginx() error = %v\n%s", err, nginxText)
	}
	for _, want := range []string{
		`log_format lanpanel_app_example_app_realip_rejection '$time_iso8601 app=example-app profile=edgeone-prod provider=edgeone reason="$example_app_realip_reject_reason" source="$example_app_realip_original_source" remote="$remote_addr" host="$host" status=$status';`,
		"map $realip_remote_addr $example_app_realip_original_source {",
		`"" $remote_addr;`,
		"geo $example_app_realip_original_source $example_app_realip_source_trusted {",
		"include /etc/nginx/lanpanel/realip/edgeone-prod/trusted-cidrs.conf;",
		"map $http_eo_connecting_ip $example_app_eo_connecting_ip_is_ip {",
		`"~^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$" 1;`,
		`"~*^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$" 1;`,
		`"::" 1;`,
		"geo $http_eo_connecting_ip $example_app_eo_connecting_ip_is_public {",
		"10.0.0.0/8 0;",
		"127.0.0.0/8 0;",
		"::1/128 0;",
		"::ffff:0:0/96 0;",
		"fc00::/7 0;",
		`map "$example_app_realip_source_trusted:$example_app_eo_connecting_ip_is_ip:$example_app_eo_connecting_ip_is_public:$http_eo_connecting_ip" $example_app_realip_reject_reason {`,
		`~^0:[01]:[01]: "untrusted_source_ip";`,
		`~^1:[01]:[01]:.*,.* "duplicate_eo_connecting_ip";`,
		`~^1:0:[01]: "missing_or_invalid_eo_connecting_ip";`,
		`~*^1:1:[01]:::ffff: "missing_or_invalid_eo_connecting_ip";`,
		`~^1:1:0: "missing_or_invalid_eo_connecting_ip";`,
		"map $example_app_realip_reject_reason $example_app_realip_reject_log {",
		`"" 0;`,
		"include /etc/nginx/lanpanel/realip/edgeone-prod/active.conf;",
		"real_ip_header EO-Connecting-IP;",
		"error_page 418 = @example_app_realip_reject;",
		"location @example_app_realip_reject {\n        internal;\n        access_log /var/log/nginx/example-app-realip-rejections.log lanpanel_app_example_app_realip_rejection if=$example_app_realip_reject_log;",
		"return 418;",
		"access_log /var/log/nginx/example-app-realip-rejections.log lanpanel_app_example_app_realip_rejection if=$example_app_realip_reject_log;",
		`return 400 "lanpanel realip rejected: $example_app_realip_reject_reason\n";`,
		"proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $remote_addr;",
		"proxy_set_header X-Forwarded-Host $example_app_validated_host;",
		`proxy_set_header Forwarded "";`,
		`proxy_set_header X-Original-Forwarded-For "";`,
		`proxy_set_header X-Client-IP "";`,
		`proxy_set_header Client-IP "";`,
		`proxy_set_header True-Client-IP "";`,
		`proxy_set_header EO-Connecting-IP "";`,
		`proxy_set_header EO-Client-IP "";`,
		"proxy_set_header X-Forwarded-Proto $scheme;",
	} {
		if !strings.Contains(nginxText, want) {
			t.Fatalf("realip nginx content missing %q\n%s", want, nginxText)
		}
	}
	if strings.Contains(nginxText, "$proxy_add_x_forwarded_for") {
		t.Fatalf("realip-enabled nginx must not append inbound X-Forwarded-For\n%s", nginxText)
	}
	if strings.Contains(nginxText, "proxy_set_header X-Forwarded-Host $host;") {
		t.Fatalf("realip-enabled GoAccess WebSocket must use validated X-Forwarded-Host\n%s", nginxText)
	}
	if got := strings.Count(nginxText, "proxy_set_header X-Forwarded-Host $example_app_validated_host;"); got != 2 {
		t.Fatalf("realip-enabled nginx X-Forwarded-Host validated count = %d, want app proxy and GoAccess WebSocket\n%s", got, nginxText)
	}
	if !strings.Contains(nginxText, "untrusted_source_ip") {
		t.Fatalf("realip-enabled nginx must reject untrusted origin sources\n%s", nginxText)
	}
	if strings.Contains(nginxText, "real_ip_recursive") {
		t.Fatalf("realip-enabled nginx must not render real_ip_recursive\n%s", nginxText)
	}
	if got := strings.Count(nginxText, "access_log /var/log/nginx/example-app-realip-rejections.log lanpanel_app_example_app_realip_rejection if=$example_app_realip_reject_log;"); got != 2 {
		t.Fatalf("realip rejection log count = %d, want HTTP and HTTPS rejection locations\n%s", got, nginxText)
	}
	if got := strings.Count(nginxText, "location @example_app_realip_reject {"); got != 2 {
		t.Fatalf("realip rejection location count = %d, want HTTP and HTTPS rejection locations\n%s", got, nginxText)
	}
}

func TestStageRuntimeKeepsRealIPRejectionLogWhenAccessLogOff(t *testing.T) {
	t.Parallel()

	enabled := true
	cfg := listenConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "tencentcloud"
	cfg.DNS01.EnvFile = "/etc/lanpanel/dns/tencentcloud.env"
	cfg.Nginx.AccessLog = "off"
	cfg.Access.OriginProtection.Mode = appconfig.OriginProtectionModeEdgeOne
	cfg.Access.OriginProtection.EdgeOneProfile = "edgeone-prod"
	cfg.Access.OriginProtection.DirectOriginRiskConfirmed = false
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
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	contentBySource := map[string]string{}
	for _, file := range staged {
		contentBySource[file.SourcePath] = string(file.Content)
	}
	nginxText := contentBySource["templates/app/nginx.conf.tmpl"]
	if nginxText == "" {
		t.Fatal("nginx content not staged")
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	if err := appsvc.ValidateRenderedNginx(cfg, names, []byte(nginxText)); err != nil {
		t.Fatalf("ValidateRenderedNginx() error = %v\n%s", err, nginxText)
	}
	if got := strings.Count(nginxText, "\n    access_log off;"); got != 2 {
		t.Fatalf("server-level access_log off count = %d, want HTTP and HTTPS only\n%s", got, nginxText)
	}
	if got := strings.Count(nginxText, "access_log /var/log/nginx/example-app-realip-rejections.log lanpanel_app_example_app_realip_rejection if=$example_app_realip_reject_log;"); got != 2 {
		t.Fatalf("realip rejection log count = %d, want HTTP and HTTPS rejection locations\n%s", got, nginxText)
	}
	if strings.Contains(nginxText, "location @example_app_realip_reject {\n        internal;\n        access_log off;") {
		t.Fatalf("realip rejection location must not inherit access_log off\n%s", nginxText)
	}
}

func TestStageRuntimeRendersUpstreamWithoutService(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.App.Listen = ""
	cfg.App.Upstream = "100.64.10.20:18001"
	cfg.Service = appconfig.ServiceConfig{}
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	if len(staged) != 4 {
		t.Fatalf("len(staged) = %d, want 4", len(staged))
	}
	for _, file := range staged {
		if strings.Contains(file.HostPath, "example-app.service") {
			t.Fatalf("upstream mode staged app service: %#v", file)
		}
		if file.SourcePath == "templates/app/nginx.conf.tmpl" && !strings.Contains(string(file.Content), "server 100.64.10.20:18001;") {
			t.Fatalf("nginx upstream not rendered:\n%s", file.Content)
		}
	}
}

func TestStageRuntimeRendersGoAccessAssetsAndNginxLocations(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	cfg.Nginx.GoAccess.AuthCIDRAllowlist = []string{"203.0.113.0/24"}
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	if len(staged) != 8 {
		t.Fatalf("len(staged) = %d, want 8", len(staged))
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}

	contentBySource := map[string]string{}
	for _, file := range staged {
		contentBySource[file.SourcePath] = string(file.Content)
		if !strings.Contains(string(file.Content), appsvc.ManagedMarker("example-app")) {
			t.Fatalf("%s missing managed marker", file.SourcePath)
		}
	}
	nginxText := contentBySource["templates/app/nginx.conf.tmpl"]
	if nginxText == "" {
		t.Fatal("nginx content not staged")
	}
	if err := appsvc.ValidateRenderedNginx(cfg, names, []byte(nginxText)); err != nil {
		t.Fatalf("ValidateRenderedNginx() error = %v\n%s", err, nginxText)
	}
	for _, want := range []string{
		"log_format lanpanel_app_example_app_enhanced",
		`$request_time "$upstream_status" "$upstream_response_time"`,
		"access_log /var/log/lanpanel/apps/example-app/access.log lanpanel_app_example_app_enhanced;",
		"location = /_lanpanel/apps/example-app/goaccess {\n        access_log off;\n        return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;\n    }",
		"location = /_lanpanel/apps/example-app/goaccess/ws {\n        access_log off;\n        return 421;\n    }",
		"location = /_lanpanel/apps/example-app/goaccess {",
		"return 301 https://abc.com/_lanpanel/apps/example-app/goaccess;",
		"alias /var/lib/example-app/goaccess/report.html;",
		"disable_symlinks on;",
		`auth_basic "Lanpanel GoAccess";`,
		"auth_basic_user_file /etc/example-app/goaccess.htpasswd;",
		"allow 203.0.113.0/24;",
		"deny all;",
		"location = /_lanpanel/apps/example-app/goaccess/ws {",
		"proxy_pass http://127.0.0.1:",
		`proxy_set_header Authorization "";`,
		"proxy_read_timeout 3600s;",
		"access_log off;",
	} {
		if !strings.Contains(nginxText, want) {
			t.Fatalf("GoAccess nginx content missing %q\n%s", want, nginxText)
		}
	}
	httpDashboardIndex := strings.Index(nginxText, "location = /_lanpanel/apps/example-app/goaccess {\n        access_log off;\n        return 301")
	httpWebsocketIndex := strings.Index(nginxText, "location = /_lanpanel/apps/example-app/goaccess/ws {\n        access_log off;\n        return 421;")
	httpRedirectIndex := strings.Index(nginxText, "location / {\n        return 301")
	if httpDashboardIndex < 0 || httpWebsocketIndex < 0 || httpRedirectIndex < 0 || httpDashboardIndex > httpRedirectIndex || httpWebsocketIndex > httpRedirectIndex {
		t.Fatalf("HTTP GoAccess dashboard/ws locations must render before HTTP redirect and disable access logs\n%s", nginxText)
	}
	dashboardIndex := strings.Index(nginxText, "location = /_lanpanel/apps/example-app/goaccess {")
	websocketIndex := strings.Index(nginxText, "location = /_lanpanel/apps/example-app/goaccess/ws {")
	proxyIndex := strings.LastIndex(nginxText, "location / {\n        proxy_pass")
	if dashboardIndex < 0 || websocketIndex < 0 || proxyIndex < 0 || dashboardIndex > proxyIndex || websocketIndex > proxyIndex {
		t.Fatalf("GoAccess dashboard/ws locations must render before proxy location\n%s", nginxText)
	}

	configText := contentBySource["templates/app/goaccess.conf.tmpl"]
	for _, want := range []string{
		"log-file /var/log/lanpanel/apps/example-app/access.log",
		"output /var/lib/example-app/goaccess/report.html",
		`log-format %h %^ %^ [%x] "%r" %s %b "%R" "%u" "%v" %T "%^" "%^"`,
		"datetime-format %Y-%m-%dT%H:%M:%S%z",
		"real-time-html true",
		"addr 127.0.0.1",
		"port ",
		"ws-url wss://abc.com:443/_lanpanel/apps/example-app/goaccess/ws",
		"origin https://abc.com",
		"ping-interval 10",
		"persist true",
		"restore true",
		"db-path /var/lib/example-app/goaccess/db",
		"html-report-title Lanpanel-GoAccess-example-app",
		"static-file .css",
		"static-file .js",
		"static-file .png",
		"static-file .svg",
		"static-file .woff2",
		"static-file .webp",
	} {
		if !strings.Contains(configText, want) {
			t.Fatalf("goaccess.conf missing %q\n%s", want, configText)
		}
	}
	serviceText := contentBySource["templates/app/goaccess.service.tmpl"]
	for _, want := range []string{
		"User=lanpanel-goaccess-example-app",
		"Group=lanpanel-goaccess-example-app",
		"Environment=LANG=C.UTF-8",
		"ExecStart=" + appsvc.GoAccessBinaryPath + " --no-global-config --config-file /etc/example-app/goaccess.conf",
		"UMask=0027",
		"Restart=on-failure",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/example-app/goaccess/report.html /var/lib/example-app/goaccess/db",
	} {
		if !strings.Contains(serviceText, want) {
			t.Fatalf("goaccess.service missing %q\n%s", want, serviceText)
		}
	}
	if strings.Contains(serviceText, "--daemonize") || strings.Contains(serviceText, "--real-time-html") {
		t.Fatalf("goaccess.service must rely on config file options, not inline runtime flags\n%s", serviceText)
	}

	logrotateText := contentBySource["templates/app/goaccess-logrotate.tmpl"]
	for _, want := range []string{
		"/var/log/lanpanel/apps/example-app/access.log {",
		"create 0640 www-data lanpanel-goaccess-example-app",
		"systemctl reload nginx.service",
		"systemctl restart example-app-goaccess.service",
	} {
		if !strings.Contains(logrotateText, want) {
			t.Fatalf("goaccess logrotate missing %q\n%s", want, logrotateText)
		}
	}
	if strings.Contains(logrotateText, "|| true") {
		t.Fatalf("goaccess logrotate must not swallow active nginx reload failures\n%s", logrotateText)
	}
	assertGoAccessLogrotatePostrotateBehavior(t, logrotateText)

	assertEnhancedGoAccessParserMatchesSample(t, configText, `203.0.113.10 - - [2026-05-24T21:00:00+08:00] "GET /api?q=1 HTTP/1.1" 200 123 "https://ref.example/" "curl/8.5.0" "abc.com" 0.123 "200" "0.120"`)
}

func TestStageRuntimeRendersGoAccessCombinedMode(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.Nginx.AccessLog = "/var/log/lanpanel/custom/example-app.access.log"
	cfg.Nginx.GoAccess.Enabled = true
	cfg.Nginx.GoAccess.LogFormat = appconfig.NginxGoAccessLogFormatCombined
	cfg.Nginx.GoAccess.AuthBasicUserFile = "/etc/example-app/goaccess.htpasswd"
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	contentBySource := map[string]string{}
	for _, file := range staged {
		contentBySource[file.SourcePath] = string(file.Content)
	}
	nginxText := contentBySource["templates/app/nginx.conf.tmpl"]
	if strings.Contains(nginxText, "log_format lanpanel_app_example_app_enhanced") {
		t.Fatalf("combined mode must not render enhanced log_format\n%s", nginxText)
	}
	if !strings.Contains(nginxText, "access_log /var/log/lanpanel/custom/example-app.access.log combined;") {
		t.Fatalf("combined mode nginx access_log missing combined format\n%s", nginxText)
	}
	configText := contentBySource["templates/app/goaccess.conf.tmpl"]
	if !strings.Contains(configText, "log-format COMBINED") {
		t.Fatalf("combined mode goaccess.conf missing COMBINED\n%s", configText)
	}
	if _, ok := contentBySource["templates/app/goaccess-logrotate.tmpl"]; ok {
		t.Fatalf("explicit access log must not stage managed logrotate asset")
	}
}

func assertEnhancedGoAccessParserMatchesSample(t *testing.T, configText string, sample string) {
	t.Helper()

	const wantFormat = `log-format %h %^ %^ [%x] "%r" %s %b "%R" "%u" "%v" %T "%^" "%^"`
	if !strings.Contains(configText, wantFormat) {
		t.Fatalf("goaccess.conf missing parser %q\n%s", wantFormat, configText)
	}

	pattern := regexp.MustCompile(`^(\S+) \S+ \S+ \[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\] "([^"]+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)" "([^"]+)" (\d+(?:\.\d+)?) "([^"]*)" "([^"]*)"$`)
	matches := pattern.FindStringSubmatch(sample)
	if matches == nil {
		t.Fatalf("enhanced sample line does not match GoAccess parser field order: %s", sample)
	}
	actual := map[string]string{
		"remote_addr":  matches[1],
		"datetime":     matches[2],
		"request":      matches[3],
		"status":       matches[4],
		"bytes":        matches[5],
		"referrer":     matches[6],
		"user_agent":   matches[7],
		"host":         matches[8],
		"request_time": matches[9],
	}
	expected := map[string]string{
		"remote_addr":  "203.0.113.10",
		"datetime":     "2026-05-24T21:00:00+08:00",
		"request":      "GET /api?q=1 HTTP/1.1",
		"status":       "200",
		"bytes":        "123",
		"referrer":     "https://ref.example/",
		"user_agent":   "curl/8.5.0",
		"host":         "abc.com",
		"request_time": "0.123",
	}
	for field, want := range expected {
		if actual[field] != want {
			t.Fatalf("enhanced parser field %s = %q, want %q", field, actual[field], want)
		}
	}
}

func assertGoAccessLogrotatePostrotateBehavior(t *testing.T, logrotateText string) {
	t.Helper()

	postrotate := extractLogrotatePostrotateScript(t, logrotateText)
	runPostrotate := func(systemctlScript string) (string, error) {
		t.Helper()
		binDir := t.TempDir()
		systemctlPath := binDir + "/systemctl"
		if err := os.WriteFile(systemctlPath, []byte(systemctlScript), 0o755); err != nil {
			t.Fatalf("write fake systemctl: %v", err)
		}
		cmd := exec.Command("sh", "-c", "set -eu\n"+postrotate)
		cmd.Env = append(os.Environ(), "PATH="+binDir)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}

	output, err := runPostrotate(`#!/bin/sh
if [ "$1" = "is-active" ]; then
    printf '%s\n' inactive
    exit 3
fi
if [ "$1" = "restart" ] && [ "$2" = "example-app-goaccess.service" ]; then
    printf '%s\n' goaccess-restarted
    exit 0
fi
printf 'unexpected command: %s\n' "$*" >&2
exit 99
`)
	if err != nil || !strings.Contains(output, "goaccess-restarted") {
		t.Fatalf("postrotate inactive nginx = err %v output %q, want GoAccess restart\nscript:\n%s", err, output, postrotate)
	}

	output, err = runPostrotate(`#!/bin/sh
if [ "$1" = "is-active" ]; then
    printf '%s\n' failed
    exit 3
fi
if [ "$1" = "restart" ]; then
    printf '%s\n' unexpected-restart >&2
    exit 99
fi
printf 'unexpected command: %s\n' "$*" >&2
exit 99
`)
	if err == nil || !strings.Contains(output, "failed") || strings.Contains(output, "unexpected-restart") {
		t.Fatalf("postrotate failed nginx = err %v output %q, want failed state before GoAccess restart", err, output)
	}

	output, err = runPostrotate(`#!/bin/sh
if [ "$1" = "is-active" ]; then
    printf '%s\n' active
    exit 0
fi
if [ "$1" = "reload" ]; then
    printf '%s\n' reload-failed >&2
    exit 7
fi
if [ "$1" = "restart" ]; then
    printf '%s\n' unexpected-restart >&2
    exit 99
fi
printf 'unexpected command: %s\n' "$*" >&2
exit 99
`)
	if err == nil || !strings.Contains(output, "reload-failed") || strings.Contains(output, "unexpected-restart") {
		t.Fatalf("postrotate active reload = err %v output %q, want reload failure before GoAccess restart", err, output)
	}

	output, err = runPostrotate(`#!/bin/sh
if [ "$1" = "is-active" ]; then
    printf '%s\n' active
    exit 0
fi
if [ "$1" = "reload" ] && [ "$2" = "nginx.service" ]; then
    printf '%s\n' nginx-reloaded
    exit 0
fi
if [ "$1" = "restart" ] && [ "$2" = "example-app-goaccess.service" ]; then
    printf '%s\n' restart-failed >&2
    exit 8
fi
printf 'unexpected command: %s\n' "$*" >&2
exit 99
`)
	if err == nil || !strings.Contains(output, "nginx-reloaded") || !strings.Contains(output, "restart-failed") {
		t.Fatalf("postrotate GoAccess restart = err %v output %q, want restart failure after nginx reload", err, output)
	}
}

func extractLogrotatePostrotateScript(t *testing.T, logrotateText string) string {
	t.Helper()
	start := strings.Index(logrotateText, "\n    postrotate\n")
	if start < 0 {
		t.Fatalf("logrotate missing postrotate block:\n%s", logrotateText)
	}
	start += len("\n    postrotate\n")
	end := strings.Index(logrotateText[start:], "\n    endscript")
	if end < 0 {
		t.Fatalf("logrotate missing endscript:\n%s", logrotateText)
	}
	lines := strings.Split(logrotateText[start:start+end], "\n")
	for i, line := range lines {
		lines[i] = strings.TrimPrefix(line, "        ")
	}
	return strings.Join(lines, "\n")
}

func TestStageRuntimeRejectsSystemdUnsafeValues(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.Service.ExecStart = "/opt/example-app/example-app --listen 127.0.0.1:18001 ; /bin/true"
	if _, err := StageRuntime(cfg); err == nil || !strings.Contains(err.Error(), "service.exec_start must not contain systemd separators") {
		t.Fatalf("StageRuntime() error = %v, want systemd-safe exec_start validation", err)
	}

	cfg = listenConfig()
	cfg.App.CertificateEmail = "o'ps@example.com"
	if _, err := StageRuntime(cfg); err == nil || !strings.Contains(err.Error(), "app.certificate_email must be a systemd-safe email token") {
		t.Fatalf("StageRuntime() error = %v, want systemd-safe email validation", err)
	}
}

func TestRenewServiceRendersAllSANDomains(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	cfg.App.ACMEChallenge = appconfig.ACMEChallengeDNS01
	cfg.DNS01.Provider = "cloudflare"
	cfg.DNS01.EnvFile = "/etc/example-app/dns/cloudflare.env"
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	for _, file := range staged {
		if file.SourcePath != "templates/app/lego-renew.service.tmpl" {
			continue
		}
		text := string(file.Content)
		for _, want := range []string{
			"EnvironmentFile=/etc/example-app/dns/cloudflare.env",
			"--domains abc.com --domains www.abc.com",
			"--dns cloudflare",
			"migrate --path \"$lego_path\"",
			"--force-cert-domains --deploy-hook /usr/local/lib/lanpanel/apps/example-app/install-cert-and-reload-nginx.sh",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("renew service missing %q\n%s", want, text)
			}
		}
		return
	}
	t.Fatal("renew service not staged")
}

func TestRenderedNginxValidationRejectsMissingHTTPSHostGuard(t *testing.T) {
	t.Parallel()

	cfg := listenConfig()
	staged, err := StageRuntime(cfg)
	if err != nil {
		t.Fatalf("StageRuntime() error = %v", err)
	}
	var nginxContent []byte
	for _, file := range staged {
		if file.SourcePath == "templates/app/nginx.conf.tmpl" {
			nginxContent = file.Content
			break
		}
	}
	if len(nginxContent) == 0 {
		t.Fatal("nginx content not staged")
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		t.Fatalf("NewNames() error = %v", err)
	}
	httpsGuard := "    if ($example_app_host_header_valid = 0) {\n        return 421;\n    }\n"
	text := string(nginxContent)
	index := strings.LastIndex(text, httpsGuard)
	if index < 0 {
		t.Fatalf("HTTPS host guard fixture not found:\n%s", text)
	}
	broken := text[:index] + text[index+len(httpsGuard):]
	err = appsvc.ValidateRenderedNginx(cfg, names, []byte(broken))
	if err == nil || !strings.Contains(err.Error(), "HTTPS Host allowlist before proxy location") {
		t.Fatalf("ValidateRenderedNginx() error = %v, want HTTPS Host guard failure", err)
	}
}

func stagedText(t *testing.T, staged []StagedFile, sourcePath string) string {
	t.Helper()
	for _, file := range staged {
		if file.SourcePath == sourcePath {
			return string(file.Content)
		}
	}
	t.Fatalf("staged source %s not found", sourcePath)
	return ""
}
