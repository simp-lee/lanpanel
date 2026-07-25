package assets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

func TestDeployDocsAlignWithCLIAndSupportMatrix(t *testing.T) {
	t.Parallel()

	docs := map[string]string{
		"README": readRepoDoc(t, "README.md"),
	}

	for name, content := range docs {
		lower := strings.ToLower(content)
		for _, stale := range []string{
			"later phases",
			"after later phases",
			"still stop at config validation",
			"does not perform real host execution",
			"runtime host and network verification also land",
			"future cli outputs",
			"future build step",
		} {
			if strings.Contains(lower, stale) {
				t.Fatalf("%s doc contains stale staged-workflow text %q", name, stale)
			}
		}
	}

	combined := strings.Join(mapValues(docs), "\n")
	for _, want := range []string{
		"init -> verify -> deploy -> verify -> status",
		"lanpanel status",
		"Debian-family",
		"apt/dpkg/systemd",
		"Windows",
		"macOS",
		"Debian/Ubuntu Linux",
		"Tailscale client >= v1.80.0",
		"/generate_204",
		"unix socket",
		"preauth",
		"MagicDNS",
		"tailscale ping",
		"tailscale status",
		"tailscale netcheck",
		"direct",
		"DERP",
		"China mainland",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("deploy docs missing required user guidance %q", want)
		}
	}
}

func TestRootReadmePointsToPrimaryDocs(t *testing.T) {
	t.Parallel()

	content := readRepoDoc(t, "README.md")
	for _, want := range []string{
		"lanpanel init --config lanpanel.yaml",
		"lanpanel deploy --config lanpanel.yaml",
		"lanpanel verify --config lanpanel.yaml",
		"lanpanel status --config lanpanel.yaml",
		"Debian, Ubuntu, or a Debian-family distribution with apt/dpkg/systemd",
		"pinned lego v5.2.2",
		"## Supported Scope",
		"## Server Guide",
		"## Client Guide",
		"checksums.txt",
		"[Releases](https://github.com/simp-lee/lanpanel/releases)",
		"do not copy the placeholder literally",
		"`verify` is a static config and runtime-template check",
		"it does not read host systemd state, certificate files, Nginx runtime state, Headscale process state, or client online state",
		"sudo systemctl status headscale.service nginx.service --no-pager --full",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("root README missing project entrypoint detail %q", want)
		}
	}

	for _, unwanted := range []string{
		"## Release Validation",
		"## Development And Assets",
		"## Publishing Release Assets",
		"Server gates:",
		"Client gates:",
		".github/workflows/release.yml",
		"gh attestation verify",
		"git tag -a",
		"make check",
		"make lint",
		"make tidy",
	} {
		if strings.Contains(content, unwanted) {
			t.Fatalf("root README should be user-facing, but contains maintainer detail %q", unwanted)
		}
	}
}

func TestP0DocsDocumentReviewedUIAndReleaseBoundaries(t *testing.T) {
	t.Parallel()

	uiDoc := readRepoDoc(t, "docs", "p0-ui.md")
	for _, want := range []string{
		"loopback-only Management UI",
		"does not use a CDN",
		"frontend build\npipeline",
		"main config summary, compact host health",
		"derived exposure summary",
		"Settings: structured main config fields",
		"Resources: app access mode `browser|public`",
		"Host Health: read-only OS, CPU, memory, disk, network-address, port-listener,\n  certificate-expiry facts, diagnostics checks, and allowed/forbidden action\n  boundaries",
		"Diagnostics, Services, and Certificates/Nginx: typed main/app runtime evidence",
		"modified paths, retry commands, and redacted summaries",
		"owner mismatches instead of starting in a degraded in-memory mode",
		"preauth keys are one-time",
		"handoff secrets and are not stored in history",
		"No public Management UI listen address",
		"clear upstream\n  `Authorization`",
	} {
		if !strings.Contains(uiDoc, want) {
			t.Fatalf("docs/p0-ui.md missing reviewed UI boundary %q", want)
		}
	}
	for _, unwanted := range []string{
		"active/recent jobs,\n  modified paths, and risk counts",
		"CDN script",
		"node_modules",
		"Tailwind",
		"Use a public Management UI listen address",
	} {
		if strings.Contains(uiDoc, unwanted) {
			t.Fatalf("docs/p0-ui.md contains unsupported UI claim %q", unwanted)
		}
	}

	migrationDoc := readRepoDoc(t, "docs", "p0-migration.md")
	for _, want := range []string{
		"does not generate a\nmachine-readable export manifest",
		"plaintext\n  passwords are not recoverable after the one-time display window",
		"not a restore source of truth",
		"P1 may add an export manifest",
	} {
		if !strings.Contains(migrationDoc, want) {
			t.Fatalf("docs/p0-migration.md missing migration boundary %q", want)
		}
	}

	releaseDoc := readRepoDoc(t, "docs", "p0-release-checklist.md")
	for _, want := range []string{
		"`go test ./...`",
		"`make check`",
		"`make e2e`",
		"`E2E_ADDR=127.0.0.1:18081 make e2e`",
		"No CDN htmx script reference in product pages",
		"Browser apps protect proxy and static locations with Basic Auth",
		"P1-only `private_client`, commercial, RBAC, account/OIDC/SSO, public remote\n  control, public Management UI, export manifest, and audit-log write paths are\n  not exposed in P0 UI",
		"Exposure summary and resource cards stay derived, read-only interpretation\n  from config, staged files, checkpoints, diagnostics, and runtime checks; they\n  are not deploy or restore truth",
		"Exit/Migration documents local config and state paths, non-exported secrets,\n  no export manifest, and recovery limits",
	} {
		if !strings.Contains(releaseDoc, want) {
			t.Fatalf("docs/p0-release-checklist.md missing release gate %q", want)
		}
	}
	for _, unwanted := range []string{
		"login?token=",
		"LANPANEL_UI_TOKEN_URL='http",
	} {
		if strings.Contains(releaseDoc, unwanted) {
			t.Fatalf("docs/p0-release-checklist.md leaks startup token URL guidance %q", unwanted)
		}
	}
}

func TestClientGuideIsSelfContained(t *testing.T) {
	t.Parallel()

	content := readRepoDoc(t, "README.md")
	for _, want := range []string{
		"### Windows",
		"### macOS",
		"### Debian/Ubuntu Linux",
		"Tailscale client >= v1.80.0",
		"tailscale",
		"--login-server",
		"--auth-key",
		"--accept-dns=true",
		"status",
		"ping",
		"netcheck",
		"MagicDNS",
		"DERP",
		"/generate_204",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("clients doc missing walkthrough detail %q", want)
		}
	}
	if strings.Contains(content, "tskey-example") {
		t.Fatal("clients doc contains Tailscale.com-style auth key placeholder")
	}
}

func TestOnboardingFreshKeyFlowIsConditional(t *testing.T) {
	t.Parallel()

	content := readRepoDoc(t, "README.md")
	for _, want := range []string{
		"Use `sudo lanpanel ui` on the server and open it over an SSH tunnel for the P0 handoff flow.",
		"open Headscale Onboarding",
		"create a fresh one-time preauth key from the handoff page",
		"The plaintext key is visible only in the immediate handoff result",
		"create a different short-lived key for each client",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("onboarding doc missing UI handoff guidance %q", want)
		}
	}
	if strings.Contains(content, "--reusable") {
		t.Fatal("onboarding doc must not recommend reusable preauth keys")
	}
	for _, forbidden := range []string{
		"preauthkeys create",
		"headscale --config",
		"local Headscale CLI",
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("onboarding doc must not provide direct Headscale CLI secret handoff guidance %q", forbidden)
		}
	}
}

func TestUserGuideDocumentsRuntimeSecurityBoundaries(t *testing.T) {
	t.Parallel()

	content := readRepoDoc(t, "README.md")
	for _, want := range []string{
		"Nginx serves HTTP-01 challenges from `/var/lib/lanpanel/acme-challenges`",
		"Nginx uses `/etc/lanpanel/tls/<server>/fullchain.pem` and `/etc/lanpanel/tls/<server>/privkey.pem`",
		"Explicit HTTP and HTTPS `default_server` catch-all blocks reject unmatched Host or SNI traffic",
		"Existing Nginx can coexist by `server_name`",
		"Headscale exposes STUN on `3478/udp`",
		"Cloudflare, DigitalOcean, and Tencent Cloud require a root-owned, root-only `advanced.dns01.env_file`",
		"TENCENTCLOUD_SECRET_ID_FILE=/etc/lanpanel/dns01/tencentcloud-secret-id",
		`provider: "tencentcloud"`,
		"Route53 and gcloud may use the host credential chain",
		"do not put raw tokens or keys directly in `env_file`",
		"v5.2.2",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("user README missing runtime security boundary detail %q", want)
		}
	}
	if strings.Contains(content, "Nginx owns the configured `server_name`, uses `fullchain.pem`, and does not become a `default_server`") {
		t.Fatal("user README contains stale default_server wording")
	}
	if strings.Contains(content, "coexistence with other sites depends on the host's existing default server ordering") {
		t.Fatal("user README contains stale default-server ordering caveat")
	}
}

func TestChineseDocsDocumentAppCLI(t *testing.T) {
	t.Parallel()

	readme := readRepoDoc(t, "README.zh-CN.md")
	appDoc := readRepoDoc(t, "docs", "zh-CN", "app.md")
	cliDoc := readRepoDoc(t, "docs", "zh-CN", "cli.md")
	uiDoc := readRepoDoc(t, "docs", "zh-CN", "ui.md")
	content := strings.Join([]string{readme, appDoc, cliDoc, uiDoc}, "\n")
	if !containsHan(readme) || !containsHan(appDoc) || !containsHan(cliDoc) || !containsHan(uiDoc) {
		t.Fatal("Chinese docs must remain localized")
	}
	for _, want := range []string{
		"lanpanel app init --config lanpanel-apps/example-app.yaml",
		"sudo lanpanel app deploy --config lanpanel-apps/example-app.yaml",
		"lanpanel app verify --config lanpanel-apps/example-app.yaml",
		"deploy/config/lanpanel-app.yaml.example",
		"`lanpanel app verify`",
		"systemd",
		"runtime",
		"GoAccess",
		"Tailscale",
		"`listen`",
		"`lanpanel.yaml`",
		"`--app-config` 不是必需参数",
		"省略时 UI 使用默认 App 配置路径 `lanpanel-app.yaml`",
		"点击 `Create Example App Config` 会把示例配置写到这个路径",
		"`upstream`",
		"Tailscale client",
		"`tailscale.login_server`",
		"`1.25.1`",
		"`http_v2`",
		"`service.env_file`",
		"`http2 on;`",
		"`nginx.static_locations`",
		"`nginx.goaccess`",
		"auth_basic_user_file",
		"`<app-name>-goaccess.service`",
		"`logrotate`",
		"`persist true`",
		"`restore true`",
		"GoAccess `db-path` `/var/lib/<app-name>/goaccess/db`",
		"HTML",
		"Nginx",
		"`/var/lib/<app-name>/goaccess/report.html`",
		"loopback WebSocket",
		"`nginx.goaccess.websocket_path`",
		"`nginx.access_log`",
		"`/var/log/lanpanel/apps/<app-name>/access.log`",
		"`user:hash`",
		"root-owned",
		"primary domain",
		"secondary domain",
		"`https://<primary-domain><nginx.goaccess.path>`",
		"`421`",
		"`C.UTF-8`",
		"`zh_CN.UTF-8`",
		"`locale -a`",
		"GoAccess UI",
		"raw",
		"request serving time",
		"`nginx.error_log`",
		"`<canonical-access-log>`",
		"`<error-log>`",
		"GoAccess runtime identity",
		"外部 `access_log` 安全要求",
		"`/var/log/nginx`",
		"`ProtectHome=true`",
		"`PrivateTmp=true`",
		"journalctl -u <app-name>.service -e",
		"`proxy.read_timeout`",
		"tailnet",
		"`lanpanel app status`",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("Chinese app docs missing CLI guidance %q", want)
		}
	}

	for _, unwanted := range []string{
		"docs/additional-go-services",
		"docs/templates/extra-go-service",
		"sudo cp docs/templates/extra-go-service",
		"sudoedit /etc/nginx/sites-available/example-app.conf",
		"public: true",
		"realtime: false",
		"upstream metrics",
	} {
		if strings.Contains(content, unwanted) {
			t.Fatalf("Chinese app docs still instruct manual runtime template deployment %q", unwanted)
		}
	}
}

func TestChineseDocsCarryForwardBackupOperationalGuidance(t *testing.T) {
	t.Parallel()

	readme := readRepoDoc(t, "README.zh-CN.md")
	appDoc := readRepoDoc(t, "docs", "zh-CN", "app.md")
	operationsDoc := readRepoDoc(t, "docs", "zh-CN", "operations.md")
	combined := strings.Join([]string{readme, appDoc, operationsDoc}, "\n")

	for _, want := range []string{
		"不是 VPN 客户端",
		"| Headscale | v0.29.1",
		"固定 lego v5.2.2",
		"只部署同机 `listen` App 时可以没有主 `lanpanel.yaml`",
		"配置文件名不是部署身份",
		"真正的部署身份来自 `app.name`",
		"当前版本不会自动做 `abc.com` 和 `www.abc.com` 之间的 canonical redirect",
		"`upstream` 只适合 HTTP/WebSocket 服务，不用于 PostgreSQL、MySQL、Redis 等数据库或中间件端口公网发布",
		"让客户端加入私有网络后直接连接 tailnet 地址",
		"验证通过时 human/json 输出状态为 `static-passed`",
		"sudo locale-gen zh_CN.UTF-8",
		"TENCENTCLOUD_SESSION_TOKEN_FILE",
		"DescribeOriginACL",
		"EO-Connecting-IP",
		"untrusted_source_ip",
		"`refresh_interval` 最小为 `1h`",
		"mirror 模式需要可访问 URL 和明确的 SHA-256",
		"lego v5.2.2 archive",
		"Headscale 应监听 `127.0.0.1:8080`",
		"metrics 默认监听 `127.0.0.1:<advanced.headscale.metrics_port>`",
		`& "$env:ProgramFiles\Tailscale\tailscale.exe" version`,
		"tailscale set --hostname=<name>",
		"systemctl status tailscaled --no-pager --full",
		"自建内置 DERP 没有 `/generate_204`",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("Chinese docs did not carry forward backup guidance %q", want)
		}
	}
}

func TestChineseDocsStayBeginnerOriented(t *testing.T) {
	t.Parallel()

	readme := readRepoDoc(t, "README.zh-CN.md")
	indexDoc := readRepoDoc(t, "docs", "zh-CN", "index.md")
	quickstartDoc := readRepoDoc(t, "docs", "zh-CN", "quickstart.md")
	appQuickstartDoc := readRepoDoc(t, "docs", "zh-CN", "app-quickstart.md")
	uiDoc := readRepoDoc(t, "docs", "zh-CN", "ui.md")
	appDoc := readRepoDoc(t, "docs", "zh-CN", "app.md")
	cliDoc := readRepoDoc(t, "docs", "zh-CN", "cli.md")
	operationsDoc := readRepoDoc(t, "docs", "zh-CN", "operations.md")
	developmentDoc := readRepoDoc(t, "docs", "zh-CN", "development.md")
	combined := strings.Join([]string{readme, indexDoc, quickstartDoc, appQuickstartDoc, uiDoc, appDoc, cliDoc, operationsDoc, developmentDoc}, "\n")

	for _, want := range []string{
		"第一次使用不要从命令参考开始读",
		"先不要急着改高级选项",
		"这个路径不要求先部署 Headscale 私有网络",
		"第一次使用只需要记住三步",
		"新手先记住一句话",
		"这是新手推荐路径",
		"以下是进阶配置",
		"第一次使用建议先走 UI",
		"如果你只是想发布同机业务 App，可以先跳过本文的 Headscale 和客户端接入部分",
		"普通使用者不需要阅读本文",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("Chinese docs missing beginner-oriented guidance %q", want)
		}
	}
}

func TestChineseReadmeDocumentsBeginnerArchitectureOverview(t *testing.T) {
	t.Parallel()

	readme := readRepoDoc(t, "README.zh-CN.md")
	for _, want := range []string{
		"## 一图看懂",
		"```text",
		"公网用户 / Tailscale 客户端",
		"80/tcp, 443/tcp, 3478/udp",
		"Debian/Ubuntu 服务器",
		"Nginx: 公网 HTTPS 入口",
		"Headscale: 私有网络控制面，只在本机地址监听",
		"内置 DERP/STUN: 直连失败时兜底",
		"App listen: 同机服务只监听 127.0.0.1:port",
		"App upstream: 通过本机 Tailscale client 访问 tailnet",
		"私有网络内的 Grafana / Uptime Kuma / 内部管理后台",
		"客户端通过 Headscale 登录私有网络",
		"设备之间优先 WireGuard 直连",
		"失败才通过 DERP 兜底",
		"公网用户访问业务域名时只进入 Nginx",
		"本机 App 只监听本机地址",
		"`upstream` 只适合 HTTP/WebSocket 服务",
		"不用于 PostgreSQL、MySQL、Redis 等数据库或中间件端口公网发布",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("Chinese README missing beginner architecture overview detail %q", want)
		}
	}
	for _, unwanted := range []string{
		"Lanpanel 执行逻辑<br/>Verify / Deploy / Jobs",
		"配置文件<br/>lanpanel.yaml",
		"管理员电脑<br/>浏览器 / SSH",
		"直连优先<br/>失败走 DERP",
		"flowchart LR",
		"电脑 A<br/>Tailscale 客户端",
		"手机 / 平板<br/>Tailscale 客户端",
		"电脑 B<br/>Tailscale 客户端",
		"公网访问者<br/>浏览器",
		"同机业务 App<br/>listen 模式",
		"tailnet 内业务服务<br/>100.64.x.y:port",
		"私有网络内 HTTP/WebSocket 服务<br/>Grafana: 100.64.10.20:3000<br/>Uptime Kuma: 100.64.10.30:3001",
		"私有网络内数据库 / 中间件<br/>PostgreSQL: 100.64.10.40:5432<br/>MySQL: 100.64.10.50:3306<br/>Redis: 100.64.10.60:6379",
		"私有网络直连<br/>5432/tcp",
		"私有网络直连<br/>3306/tcp",
		"私有网络直连<br/>6379/tcp",
	} {
		if strings.Contains(readme, unwanted) {
			t.Fatalf("Chinese README architecture diagram should focus on network connections, but contains %q", unwanted)
		}
	}
}

func TestChineseDocsDocumentTopologyDiagrams(t *testing.T) {
	t.Parallel()

	operationsDoc := readRepoDoc(t, "docs", "zh-CN", "operations.md")
	appDoc := readRepoDoc(t, "docs", "zh-CN", "app.md")
	combined := operationsDoc + "\n" + appDoc

	for _, want := range []string{
		"## 运行拓扑",
		"443/tcp control + DERP",
		"3478/udp STUN",
		"proxies control traffic to 127.0.0.1:8080",
		"metrics on 127.0.0.1:<metrics_port>",
		"gRPC on 127.0.0.1:50443",
		"STUN on 0.0.0.0:3478/udp",
		"## App 运行拓扑",
		"proxies / to 127.0.0.1:18001",
		"Optional GoAccess dashboard",
		"listens on loopback only",
		"Tailscale client on this server",
		"tailnet HTTP/WebSocket",
		"100.64.x.y:port on another tailnet node",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("Chinese docs missing topology diagram detail %q", want)
		}
	}
}

func TestReadmeUpstreamAppExamplesIncludeAPIVersion(t *testing.T) {
	t.Parallel()

	docs := []struct {
		name string
		path string
	}{
		{name: "README", path: "README.md"},
		{name: "Chinese app doc", path: "docs/zh-CN/app.md"},
	}
	for _, doc := range docs {
		content := readRepoDoc(t, doc.path)
		block := readmeYAMLBlockContaining(t, content, `name: "tailapp"`)
		if !strings.Contains(block, "api_version: lanpanel/app/v1alpha2") {
			t.Fatalf("%s upstream app example missing api_version", doc.name)
		}
		for _, want := range []string{"access:", `access_mode: "public"`, "public_risk_confirmed: true", "browser_auth:", "cidr_allowlist: []", "origin_protection:", `mode: "none"`, "direct_origin_risk_confirmed: true"} {
			if !strings.Contains(block, want) {
				t.Fatalf("%s upstream app example missing required access field %q", doc.name, want)
			}
		}
		if !strings.Contains(block, "tailscale:") || !strings.Contains(block, "login_server") || !strings.Contains(block, "auth_key_file") {
			t.Fatalf("%s upstream app example missing explicit external tailscale guidance", doc.name)
		}
	}
}

func TestReadmeListenAppExamplesIncludeRequiredAccessBlock(t *testing.T) {
	t.Parallel()

	docs := []struct {
		name string
		path string
	}{
		{name: "README", path: "README.md"},
		{name: "Chinese app doc", path: "docs/zh-CN/app.md"},
	}
	for _, doc := range docs {
		content := readRepoDoc(t, doc.path)
		block := readmeYAMLBlockContaining(t, content, `name: "example-app"`)
		for _, want := range []string{"api_version: lanpanel/app/v1alpha2", "access:", `access_mode: "public"`, "public_risk_confirmed: true", "browser_auth:", "cidr_allowlist: []", "origin_protection:", `mode: "none"`, "direct_origin_risk_confirmed: true"} {
			if !strings.Contains(block, want) {
				t.Fatalf("%s listen app example missing required access field %q", doc.name, want)
			}
		}
	}
}

func TestAppDocsDocumentBrowserAuthBoundary(t *testing.T) {
	t.Parallel()

	readmes := []struct {
		name            string
		path            string
		heading         string
		goAccessHeading string
		wants           []string
		unwanted        string
	}{
		{
			name:            "README",
			path:            "README.md",
			heading:         "#### Browser App Auth",
			goAccessHeading: "#### GoAccess App Log Dashboard",
			wants: []string{
				"`access_mode: \"browser\"`",
				"Basic Auth at the app gateway",
				"`access.browser_auth.auth_basic_user_file`",
				"separate from `nginx.goaccess.auth_basic_user_file`",
				"Do not reuse GoAccess dashboard credentials",
				"LanPanel-managed browser credential",
				"/etc/lanpanel/browser-auth",
				"one-time secret after create or rotate",
				"not stored in app config or job history",
				"`password_fingerprint`",
				"clears the inbound `Authorization` header",
				"business-layer `Authorization`",
				"`public` risk path",
			},
			unwanted: "set `access.browser_auth.auth_basic_user_file` to an existing htpasswd file as described below",
		},
		{
			name:            "README.zh-CN",
			path:            "docs/zh-CN/app.md",
			heading:         "### browser",
			goAccessHeading: "## GoAccess 看板",
			wants: []string{
				"`access_mode: \"browser\"`",
				"App gateway",
				"`access.browser_auth.auth_basic_user_file`",
				"Browser Auth 与 GoAccess dashboard Auth 是分开的",
				"不要复用",
				"Lanpanel 托管",
				"/etc/lanpanel/browser-auth",
				"明文密码只在一次性交接窗口展示",
				"配置和任务历史只保存",
				"`password_fingerprint`",
				"清除上游 `Authorization` header",
				"业务层 `Authorization`",
				"`public` 风险路径",
			},
			unwanted: "按下文把 `access.browser_auth.auth_basic_user_file` 指向已有 htpasswd 文件",
		},
	}
	for _, doc := range readmes {
		content := readRepoDoc(t, doc.path)
		section := markdownSection(t, content, doc.heading)
		if strings.Index(content, doc.heading) > strings.Index(content, doc.goAccessHeading) {
			t.Fatalf("%s browser auth section must appear before GoAccess section", doc.name)
		}
		for _, want := range doc.wants {
			if !strings.Contains(section, want) {
				t.Fatalf("%s browser auth section missing boundary %q", doc.name, want)
			}
		}
		if strings.Contains(content, doc.unwanted) {
			t.Fatalf("%s still points browser auth setup only to later GoAccess htpasswd guidance", doc.name)
		}
	}

	example := readRepoDoc(t, "deploy", "config", "lanpanel-app.yaml.example")
	for _, want := range []string{
		"Browser app auth is separate from nginx.goaccess.auth_basic_user_file",
		"Use exactly one browser credential source",
		"external app-gateway htpasswd, not GoAccess",
		"LanPanel-created credential under /etc/lanpanel/browser-auth",
		"Managed passwords are shown only as one-time UI secrets after create/rotate",
		"configs and job history store only credential metadata and password_fingerprint",
		"browser mode clears upstream Authorization",
		"Apps that need business-layer",
		"Authorization must use explicit public exposure",
	} {
		if !strings.Contains(example, want) {
			t.Fatalf("app config example missing browser auth boundary %q", want)
		}
	}
}

func TestReadmeDocumentsStaticLocationCacheHeaderContract(t *testing.T) {
	t.Parallel()

	english := readRepoDoc(t, "README.md")
	for _, want := range []string{
		"Prefer either `expires` or `cache_control`",
		"if both are set, Lanpanel renders both directives",
	} {
		if !strings.Contains(english, want) {
			t.Fatalf("README missing static cache-header contract %q", want)
		}
	}

	chinese := readRepoDoc(t, "docs", "zh-CN", "app.md")
	for _, want := range []string{
		"`expires`",
		"`cache_control`",
		"`Cache-Control`",
	} {
		if !strings.Contains(chinese, want) {
			t.Fatalf("README.zh-CN missing static cache-header contract %q", want)
		}
	}

	example := readRepoDoc(t, "deploy", "config", "lanpanel-app.yaml.example")
	if !strings.Contains(example, "Prefer either expires or cache_control. If both are set, both directives render.") {
		t.Fatal("app config example missing static cache-header contract")
	}
	for _, want := range []string{
		"Default is false so first app-only deploys do not require modern HTTP/2 support",
		"For app-only upstream configs without a main lanpanel.yaml",
		"login_server explicitly",
	} {
		if !strings.Contains(example, want) {
			t.Fatalf("app config example missing app-only/http2 guidance %q", want)
		}
	}
}

func TestEnglishReadmeDocumentsAppGoAccess(t *testing.T) {
	t.Parallel()

	content := readRepoDoc(t, "README.md")
	for _, want := range []string{
		"`nginx.goaccess` is optional and default-off",
		"auth_basic_user_file",
		"`<app-name>-goaccess.service`",
		"GoAccess App Log Dashboard",
		"installs `logrotate`",
		"`db-path` at `/var/lib/<app-name>/goaccess/db`",
		"real-time HTML dashboard",
		"Nginx serves `/var/lib/<app-name>/goaccess/report.html`",
		"live updates through its loopback WebSocket",
		"`nginx.goaccess.websocket_path`",
		"does not expose a static-only GoAccess mode",
		"`persist true` and `restore true`",
		"`nginx.access_log` is empty",
		"`/var/log/lanpanel/apps/<app-name>/access.log`",
		"regular, non-empty file",
		"`user:hash` credential line",
		"user and hash contain no whitespace",
		"not accessible by other local users",
		"Every parent directory for `auth_basic_user_file` must be root-owned",
		"The GoAccess dashboard is primary-domain only",
		"Dashboard requests on secondary domains redirect",
		"`https://<primary-domain><nginx.goaccess.path>`",
		"WebSocket requests on secondary domains return `421`",
		"`C.UTF-8`",
		"`zh_CN.UTF-8`",
		"Deploy checks `locale -a` and fails early",
		"Language changes only GoAccess UI text",
		"raw log fields",
		"request serving time",
		"`nginx.error_log`",
		"must stay outside Lanpanel-managed app and GoAccess runtime paths",
		"must not equal the GoAccess canonical access log",
		"Other loopback IP literals are valid",
		"external canonical access log",
		"During deploy, Lanpanel creates or confirms the GoAccess runtime identity before the final readability check",
		"Do not place explicit GoAccess access logs under",
		"`/var/log/nginx`",
		"`ProtectHome=true` and `PrivateTmp=true`",
		"Use the configured `nginx.access_log` path for `<canonical-access-log>`",
		"Use the configured `nginx.error_log` path for `<error-log>`",
		"does not create them, chown foreign log roots, or install managed logrotate",
		"journalctl -u <app-name>.service -e",
		"Static locations with `access_log: false`",
		"GoAccess process state",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("README missing GoAccess app guidance %q", want)
		}
	}
	for _, unwanted := range []string{
		"public: true",
		"realtime: false",
		"public GoAccess dashboard",
		"no-auth GoAccess dashboard",
		"GoAccess analyzes error logs",
		"error log dashboard",
		"upstream metrics",
		"first-class upstream",
	} {
		if strings.Contains(content, unwanted) {
			t.Fatalf("README contains unsupported GoAccess mode or claim %q", unwanted)
		}
	}
}

func TestAppRuntimeTemplatesAreCanonicalDeployAssets(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat(filepath.Join("..", "..", "deploy", "config", "lanpanel-app.yaml.example")); err != nil {
		t.Fatalf("canonical app config example is not present: %v", err)
	}
	if _, ok := Lookup("config/lanpanel-app.yaml.example"); !ok {
		t.Fatal("app config example is missing from embedded asset catalog")
	}
	example := readRepoDoc(t, "deploy", "config", "lanpanel-app.yaml.example")
	for _, want := range []string{
		"enabled: false",
		"auth_basic_user_file",
		"regular, non-empty htpasswd file",
		"user:hash credential line",
		"Credential line user and hash fields must not contain whitespace",
		"not accessible by other local users",
		"Every parent directory must be root-owned",
		"not writable by group or others",
		"searchable by the Nginx runtime user",
		"With GoAccess enabled and access_log empty",
		"/var/log/lanpanel/apps/<app-name>/access.log",
		"manages logrotate",
		"exact /var/log/lanpanel/apps/<app-name>/access.log path is still managed",
		"or install Lanpanel logrotate for them",
		"Deploy creates or confirms the GoAccess runtime user before the final readability check",
		"GoAccess rejects explicit access_log paths under /home, /root, /run/user",
		"/var/log/nginx",
		"ProtectHome/PrivateTmp",
		"persist true",
		"restore true",
		"db-path",
		"real-time HTML dashboard",
		"Nginx serves",
		"WebSocket updates at websocket_path",
		"language en requires C.UTF-8",
		"zh-CN requires both C.UTF-8 and zh_CN.UTF-8",
		"changes only GoAccess UI text",
		"defaults to 127.0.0.1:<app-derived-port>",
		"must be a loopback IP literal such as 127.0.0.1:<port> or [::1]:<port>",
		"With GoAccess enabled, error_log must not equal the GoAccess canonical",
	} {
		if !strings.Contains(example, want) {
			t.Fatalf("app config example missing GoAccess guidance %q", want)
		}
	}
	for _, unwanted := range []string{
		"public:",
		"realtime:",
		"unauthenticated",
		"public GoAccess dashboard",
		"error log dashboard",
		"upstream metrics",
	} {
		if strings.Contains(example, unwanted) {
			t.Fatalf("app config example contains unsupported GoAccess field or claim %q", unwanted)
		}
	}

	templatePaths := readDeployAppTemplatePaths(t)
	templateSet := make(map[string]struct{}, len(templatePaths))
	for _, sourcePath := range templatePaths {
		templateSet[sourcePath] = struct{}{}
		asset, ok := Lookup(sourcePath)
		if !ok {
			t.Fatalf("app runtime template %q is missing from embedded asset catalog", sourcePath)
		}
		if asset.Role != RoleRuntime || asset.ContentMode != ContentModeRender {
			t.Fatalf("catalog asset %q role/mode = %s/%s, want runtime/render", sourcePath, asset.Role, asset.ContentMode)
		}
		if _, err := NewLoader().Read(sourcePath); err != nil {
			t.Fatalf("embedded loader cannot read app runtime template %q: %v", sourcePath, err)
		}
	}
	for _, asset := range Catalog() {
		if !strings.HasPrefix(asset.SourcePath, "templates/app/") {
			continue
		}
		if _, ok := templateSet[asset.SourcePath]; !ok {
			t.Fatalf("embedded asset catalog has app runtime template %q that is not present under deploy/templates/app", asset.SourcePath)
		}
	}

	nginxTemplate := readRepoDoc(t, "deploy", "templates", "app", "nginx.conf.tmpl")
	for _, want := range []string{
		"map $http_host ${{ .VarPrefix }}_host_header_valid",
		"map $http_host ${{ .VarPrefix }}_validated_host",
		"map $ssl_server_name ${{ .VarPrefix }}_sni_valid",
		"if (${{ .VarPrefix }}_sni_valid = 0)",
		"if (${{ .VarPrefix }}_host_header_valid = 0)",
		"return 421;",
		"http2 on;",
		"client_max_body_size {{ .ClientMaxBodySize }};",
		"proxy_set_header Host ${{ .VarPrefix }}_validated_host;",
		"proxy_set_header X-Forwarded-Host ${{ .VarPrefix }}_validated_host;",
		"proxy_set_header Connection ${{ .VarPrefix }}_connection_upgrade;",
		"proxy_read_timeout {{ .Proxy.ReadTimeout }};",
	} {
		if !strings.Contains(nginxTemplate, want) {
			t.Fatalf("app nginx runtime template missing boundary %q", want)
		}
	}
}

func readDeployAppTemplatePaths(t *testing.T) []string {
	t.Helper()

	root := filepath.Join("..", "..", "deploy", "templates", "app")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", root, err)
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected directory in deploy/templates/app: %s", entry.Name())
		}
		paths = append(paths, filepath.ToSlash(filepath.Join("templates", "app", entry.Name())))
	}
	if len(paths) == 0 {
		t.Fatal("deploy/templates/app has no runtime templates")
	}
	return paths
}

func readmeYAMLBlockContaining(t *testing.T, content string, marker string) string {
	t.Helper()

	markerIndex := strings.Index(content, marker)
	if markerIndex < 0 {
		t.Fatalf("README marker %q missing", marker)
	}
	beforeMarker := content[:markerIndex]
	start := strings.LastIndex(beforeMarker, "```yaml")
	if start < 0 {
		t.Fatalf("README marker %q missing preceding YAML block", marker)
	}
	afterFence := content[start+len("```yaml"):]
	end := strings.Index(afterFence, "```")
	if end < 0 {
		t.Fatalf("README marker %q YAML block is unterminated", marker)
	}
	return afterFence[:end]
}

func markdownSection(t *testing.T, content string, heading string) string {
	t.Helper()

	start := strings.Index(content, heading)
	if start < 0 {
		t.Fatalf("markdown heading %q missing", heading)
	}
	afterHeading := content[start+len(heading):]
	next := strings.Index(afterHeading, "\n#### ")
	if next >= 0 {
		return afterHeading[:next]
	}
	return afterHeading
}

func containsHan(value string) bool {
	for _, r := range value {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func readRepoDoc(t *testing.T, path ...string) string {
	t.Helper()

	parts := append([]string{"..", ".."}, path...)
	content, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("ReadFile(%v) error = %v", path, err)
	}
	return string(content)
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
