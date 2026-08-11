package apppreflight

import (
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/domain"
	"lanpanel/internal/preflight"
	"net/netip"
	"strings"
)

type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusWarn          Status = "warn"
	StatusManual        Status = "manual"
	StatusUnknown       Status = "unknown"
	StatusNotApplicable Status = "not_applicable"
)

type Check struct {
	ID           string
	Status       Status
	Summary      string
	Remediations []string
}

type Inputs struct {
	Permissions                     preflight.PermissionState
	DNS                             map[string]preflight.DNSProbe
	Ports                           []preflight.PortBinding
	AppListenChecked                bool
	AppListenReady                  bool
	AppListenDetail                 string
	ServiceBinaryOK                 bool
	ServiceBinaryPath               string
	ServiceEnvFile                  string
	ServiceEnvFileChecked           bool
	ServiceEnvFileReady             bool
	ServiceEnvFileDetail            string
	TailscaleRequired               bool
	TailscaleAuthKeyFile            string
	TailscaleAuthKeyFileChecked     bool
	TailscaleAuthKeyFileReady       bool
	TailscaleAuthKeyFileDetail      string
	DNSCredentialsChecked           bool
	DNSCredentialsReady             bool
	DNSCredentialsDetail            string
	GoAccessAuthFileChecked         bool
	GoAccessAuthFileReady           bool
	GoAccessAuthFileDetail          string
	GoAccessPortChecked             bool
	GoAccessPortReady               bool
	GoAccessPortDetail              string
	GoAccessLocaleChecked           bool
	GoAccessLocaleReady             bool
	GoAccessLocaleDetail            string
	GoAccessLogFileChecked          bool
	GoAccessLogFileReady            bool
	GoAccessLogFileDetail           string
	BrowserAuthFileChecked          bool
	BrowserAuthFileReady            bool
	BrowserAuthFileDetail           string
	OriginProtectionStatus          domain.OriginProtectionStatus
	OriginProtectionManualConfirmed bool
}

type Report struct {
	Checks []Check
}

func BuildReport(cfg appconfig.Config, inputs Inputs) Report {
	checks := []Check{}
	add := func(id string, status Status, summary string, remediations ...string) {
		checks = append(checks, Check{ID: id, Status: status, Summary: summary, Remediations: compact(remediations)})
	}

	if inputs.Permissions.IsRoot {
		add("permissions", StatusPass, "Current command has root privileges")
	} else {
		add("permissions", StatusFail, "app deploy requires root privileges", "Retry App publication from the Management UI.")
	}

	for _, domain := range cfg.App.Domains {
		probe, ok := inputs.DNS[domain]
		status, summary, remediation := evaluateDNSProbe(cfg, domain, probe, ok)
		add("dns:"+domain, status, summary, remediation)
	}

	addPortChecks(&checks, inputs.Ports)

	if cfg.App.ACMEChallenge == appconfig.ACMEChallengeDNS01 {
		switch {
		case !inputs.DNSCredentialsChecked:
			add("dns01-credentials", StatusUnknown, "DNS-01 provider env_file was not validated automatically", "Prepare a root-only dns01.env_file, or confirm this provider supports environment credentials from the current host identity.")
		case !inputs.DNSCredentialsReady:
			detail := strings.TrimSpace(inputs.DNSCredentialsDetail)
			if detail == "" {
				detail = "DNS-01 provider env_file is unavailable"
			} else {
				detail = "DNS-01 provider env_file validation failed: " + detail
			}
			add("dns01-credentials", StatusFail, detail, "Fix dns01.env_file permissions, content, or referenced credential files, then rerun.")
		default:
			detail := strings.TrimSpace(inputs.DNSCredentialsDetail)
			if detail == "" {
				detail = "DNS-01 provider env_file passed validation"
			}
			add("dns01-credentials", StatusPass, detail)
		}
	} else {
		add("dns01-credentials", StatusNotApplicable, "DNS-01 credentials are not used for HTTP-01 app certificates")
	}

	if cfg.Mode() == appconfig.ModeListen {
		if inputs.AppListenChecked {
			addAppListenCheck(&checks, inputs.AppListenReady, inputs.AppListenDetail)
		}
		if inputs.ServiceBinaryOK {
			add("service-binary", StatusPass, "Service binary exists and is executable")
		} else {
			path := inputs.ServiceBinaryPath
			if path == "" {
				path = cfg.ServiceBinary()
			}
			add("service-binary", StatusFail, "Service binary does not exist or is not executable: "+path, "Place the service binary at the absolute path from service.exec_start and make it executable.")
		}
		if strings.TrimSpace(inputs.ServiceEnvFile) != "" {
			switch {
			case !inputs.ServiceEnvFileChecked:
				add("service-env-file", StatusUnknown, "service.env_file was not validated automatically", "Confirm service.env_file exists, is root-owned, and has mode 0600.")
			case !inputs.ServiceEnvFileReady:
				detail := strings.TrimSpace(inputs.ServiceEnvFileDetail)
				if detail == "" {
					detail = "service.env_file is unavailable"
				} else {
					detail = "service.env_file validation failed: " + detail
				}
				add("service-env-file", StatusFail, detail, "Fix service.env_file path, owner, or permissions, then rerun.")
			default:
				detail := strings.TrimSpace(inputs.ServiceEnvFileDetail)
				if detail == "" {
					detail = "service.env_file passed root-only validation"
				}
				add("service-env-file", StatusPass, detail)
			}
		}
	} else {
		add("app-listen", StatusNotApplicable, "app.listen is not used for upstream app targets")
		add("service-binary", StatusNotApplicable, "service.exec_start is not used for upstream app targets")
	}

	if inputs.TailscaleRequired {
		add("tailscale", StatusPass, "This app requires the tailnet; deploy will check the Tailscale client automatically")
	} else {
		add("tailscale", StatusNotApplicable, "This app does not require the tailnet; Tailscale client prerequisites are skipped")
	}
	if strings.TrimSpace(inputs.TailscaleAuthKeyFile) != "" {
		switch {
		case !inputs.TailscaleAuthKeyFileChecked:
			add("tailscale-auth-key-file", StatusUnknown, "tailscale.auth_key_file was not validated automatically", "Confirm tailscale.auth_key_file exists, is root-owned, root-only, and contains exactly one preauth key.")
		case !inputs.TailscaleAuthKeyFileReady:
			detail := strings.TrimSpace(inputs.TailscaleAuthKeyFileDetail)
			if detail == "" {
				detail = "tailscale.auth_key_file is unavailable"
			} else {
				detail = "tailscale.auth_key_file validation failed: " + detail
			}
			add("tailscale-auth-key-file", StatusFail, detail, "Fix tailscale.auth_key_file path, owner, permissions, parent directories, or token content, then rerun.")
		default:
			detail := strings.TrimSpace(inputs.TailscaleAuthKeyFileDetail)
			if detail == "" {
				detail = "tailscale.auth_key_file passed root-only validation"
			}
			add("tailscale-auth-key-file", StatusPass, detail)
		}
	}

	if cfg.Nginx.GoAccess.Enabled {
		addGoAccessCheck(&checks, "goaccess-auth-file", inputs.GoAccessAuthFileChecked, inputs.GoAccessAuthFileReady, inputs.GoAccessAuthFileDetail, "nginx.goaccess.auth_basic_user_file was not validated automatically", "Fix the htpasswd file path, owner, permissions, content, or parent-directory safety, then rerun.")
		addGoAccessCheck(&checks, "goaccess-port", inputs.GoAccessPortChecked, inputs.GoAccessPortReady, inputs.GoAccessPortDetail, "GoAccess WebSocket port was not validated automatically", "Free the conflicting port, or set nginx.goaccess.websocket_listen to an available loopback IP:port.")
		addGoAccessCheck(&checks, "goaccess-locale", inputs.GoAccessLocaleChecked, inputs.GoAccessLocaleReady, inputs.GoAccessLocaleDetail, "GoAccess locale was not validated automatically", "Install the UTF-8 locale required by the selected language, or set nginx.goaccess.language to en.")
		if strings.TrimSpace(cfg.Nginx.AccessLog) != "" && !cfg.NginxGoAccessManagesCanonicalAccessLog() {
			addGoAccessCheck(&checks, "goaccess-log-file", inputs.GoAccessLogFileChecked, inputs.GoAccessLogFileReady, inputs.GoAccessLogFileDetail, "GoAccess canonical access log was not validated automatically", "Prepare explicit nginx.access_log: the file must already exist, be a regular non-symlink file, and not be writable by group/others; parent directories must be root-owned and not writable by group/others. Deploy creates or confirms the GoAccess runtime user before checking that user can read the file and enter parent directories.")
		}
	}
	if cfg.RealIPEnabled() {
		switch {
		case inputs.OriginProtectionStatus == domain.OriginProtectionConfiguredPass:
			add("realip-firewall", StatusPass, "EdgeOne origin protection checks passed for this operation")
		case inputs.OriginProtectionManualConfirmed:
			add("realip-firewall", StatusManual, "EdgeOne origin ingress restriction manual confirmation was recorded for this operation")
		case inputs.OriginProtectionStatus == domain.OriginProtectionConfiguredFail:
			add("realip-firewall", StatusFail, "EdgeOne origin protection checks failed for this operation", "Fix EdgeOne trusted CIDRs, real client IP header handling, spoofing rejection, Host/SNI guard, deployed references, or rollback state, then rerun.")
		default:
			add("realip-firewall", StatusUnknown, "EdgeOne realip cannot automatically verify cloud security groups or host firewalls", "Manually restrict origin 80/443 ingress to EdgeOne OriginACL current+next CIDRs in Tencent Cloud security groups, host firewall, or equivalent boundary, then rerun with --confirmation origin-protection-manual.")
		}
	} else {
		add("realip-firewall", StatusNotApplicable, "EdgeOne RealIP origin protection is disabled for this app")
	}
	if cfg.BrowserAuthEnabled() {
		addGoAccessCheck(&checks, "browser-auth-file", inputs.BrowserAuthFileChecked, inputs.BrowserAuthFileReady, inputs.BrowserAuthFileDetail, "access.browser_auth htpasswd file was not validated automatically", "Fix the browser auth htpasswd path, owner, permissions, content, parent-directory safety, or Nginx readability, then rerun.")
	} else {
		add("browser-auth-file", StatusNotApplicable, "browser auth is not required for this access mode")
	}

	return Report{Checks: checks}
}

func addAppListenCheck(checks *[]Check, ready bool, detail string) {
	summary := strings.TrimSpace(detail)
	if ready {
		if summary == "" {
			summary = "app.listen port passed validation"
		}
		*checks = append(*checks, Check{ID: "app-listen", Status: StatusPass, Summary: summary})
		return
	}
	if summary == "" {
		summary = "app.listen port validation failed"
	}
	*checks = append(*checks, Check{
		ID:      "app-listen",
		Status:  StatusFail,
		Summary: summary,
		Remediations: []string{
			"Free the conflicting app.listen address, or stop the unmanaged service before retrying from the Management UI.",
		},
	})
}

func addGoAccessCheck(checks *[]Check, id string, checked bool, ready bool, detail string, uncheckedSummary string, remediation string) {
	status := StatusPass
	summary := strings.TrimSpace(detail)
	remediations := []string{}
	switch {
	case !checked:
		status = StatusUnknown
		summary = uncheckedSummary
		remediations = append(remediations, remediation)
	case !ready:
		status = StatusFail
		if summary == "" {
			summary = id + " validation failed"
		}
		remediations = append(remediations, remediation)
	default:
		if summary == "" {
			summary = id + " passed validation"
		}
	}
	*checks = append(*checks, Check{ID: id, Status: status, Summary: summary, Remediations: compact(remediations)})
}

func evaluateDNSProbe(cfg appconfig.Config, domain string, probe preflight.DNSProbe, ok bool) (Status, string, string) {
	if errText := strings.TrimSpace(probe.ExpectedIPError); errText != "" {
		return StatusFail, fmt.Sprintf("%s expected public IP detection failed: %s", domain, errText), "Fix tailscale.lanpanel_config, proxy settings, or advanced.network.public_ipv4/public_ipv6 in the main lanpanel.yaml, then rerun."
	}
	if !ok || strings.TrimSpace(probe.LookupError) != "" || len(probe.ResolvedIPs) == 0 {
		if cfg.App.ACMEChallenge == appconfig.ACMEChallengeDNS01 {
			if cfg.RealIPEnabled() {
				return StatusWarn, fmt.Sprintf("%s public DNS resolution is unconfirmed; DNS-01 mode does not block deploy for this", domain), "Confirm public DNS points to EdgeOne, DNS-01 provider/env_file covers this domain, and origin firewall allows only EdgeOne OriginACL CIDRs."
			}
			return StatusWarn, fmt.Sprintf("%s DNS resolution is unconfirmed; DNS-01 mode does not block deploy for this", domain), "Confirm dns01.provider/env_file covers this domain, and point the app domain to this cloud server before traffic cutover."
		}
		return StatusFail, fmt.Sprintf("%s DNS resolution is unconfirmed", domain), "Fix public DNS for app.domains, then rerun."
	}
	public := publicRoutableIPs(probe.ResolvedIPs)
	if len(public) == 0 {
		if cfg.App.ACMEChallenge == appconfig.ACMEChallengeDNS01 {
			if cfg.RealIPEnabled() {
				return StatusWarn, fmt.Sprintf("%s did not resolve to a public routable address: %s; DNS-01 mode does not block deploy for this", domain, strings.Join(probe.ResolvedIPs, ", ")), "Confirm public DNS points to EdgeOne and DNS-01 provider/env_file covers this domain before traffic cutover."
			}
			return StatusWarn, fmt.Sprintf("%s did not resolve to a public routable address: %s; DNS-01 mode does not block deploy for this", domain, strings.Join(probe.ResolvedIPs, ", ")), "Confirm DNS-01 provider/env_file covers this domain, and point the app domain to this cloud server before traffic cutover."
		}
		return StatusFail, fmt.Sprintf("%s did not resolve to a public routable address: %s", domain, strings.Join(probe.ResolvedIPs, ", ")), "Point the app domain to this cloud server's public A or AAAA address."
	}
	if cfg.App.ACMEChallenge == appconfig.ACMEChallengeDNS01 && cfg.RealIPEnabled() {
		return StatusWarn, fmt.Sprintf("%s resolved to public DNS address %s; EdgeOne realip mode does not require DNS to match the origin address", domain, strings.Join(public, ", ")), "Confirm public DNS points to EdgeOne, EdgeOne routes this domain to the origin, DNS-01 provider/env_file is authorized, and origin firewall allows only EdgeOne OriginACL CIDRs."
	}
	hasExpectedAddress := strings.TrimSpace(probe.ExpectedIPv4) != "" || strings.TrimSpace(probe.ExpectedIPv6) != ""
	if !hasExpectedAddress {
		if cfg.App.ACMEChallenge == appconfig.ACMEChallengeHTTP01 {
			return StatusFail, fmt.Sprintf("%s resolved to public address %s, but Lanpanel could not confirm these addresses belong to the current cloud server", domain, strings.Join(public, ", ")), "Ensure the current host can reach public IP detection services, or record this server's public address in advanced.network.public_ipv4/public_ipv6 in the main lanpanel.yaml, then rerun."
		}
		return StatusWarn, fmt.Sprintf("%s resolved to public address %s, but Lanpanel could not confirm whether these addresses belong to the current cloud server", domain, strings.Join(public, ", ")), "To let Lanpanel confirm DNS points to this cloud server, record this host's public address in advanced.network.public_ipv4 or public_ipv6 in the main lanpanel.yaml."
	}
	missing := []string{}
	if expectedIPv4 := strings.TrimSpace(probe.ExpectedIPv4); expectedIPv4 != "" && !containsString(probe.ResolvedIPs, expectedIPv4) {
		missing = append(missing, "IPv4 "+expectedIPv4)
	}
	if expectedIPv6 := strings.TrimSpace(probe.ExpectedIPv6); expectedIPv6 != "" && !containsString(probe.ResolvedIPs, expectedIPv6) {
		missing = append(missing, "IPv6 "+expectedIPv6)
	}
	if len(missing) > 0 {
		if cfg.App.ACMEChallenge == appconfig.ACMEChallengeDNS01 {
			return StatusWarn, fmt.Sprintf("%s DNS result is missing expected address: %s; DNS-01 mode does not block deploy for this", domain, strings.Join(missing, ", ")), "Confirm DNS-01 provider/env_file covers this domain, and point the app domain to this cloud server's expected public address before traffic cutover."
		}
		return StatusFail, fmt.Sprintf("%s DNS result is missing expected address: %s", domain, strings.Join(missing, ", ")), "Point the app domain to this cloud server's expected public address."
	}
	return StatusPass, fmt.Sprintf("%s resolved to public address %s", domain, strings.Join(public, ", ")), ""
}

func addPortChecks(checks *[]Check, ports []preflight.PortBinding) {
	add := func(id string, status Status, summary string, remediations ...string) {
		*checks = append(*checks, Check{ID: id, Status: status, Summary: summary, Remediations: compact(remediations)})
	}
	if len(ports) == 0 {
		add("ports", StatusFail, "Could not confirm 80/tcp and 443/tcp port usage", "Confirm the listener probe is available, then retry from the Management UI.")
		return
	}
	for _, required := range []int{80, 443} {
		bindings := findPortBindings(ports, required, "tcp")
		if len(bindings) == 0 {
			add(fmt.Sprintf("port:%d/tcp", required), StatusFail, fmt.Sprintf("Missing %d/tcp port usage probe result", required), "Retry from the Management UI and confirm port usage probing is complete.")
			continue
		}
		blockingProcesses := []string{}
		nginxInUse := false
		for _, binding := range bindings {
			if !binding.InUse {
				continue
			}
			process := strings.TrimSpace(binding.Process)
			if process == "" {
				process = "unknown process"
			}
			if strings.EqualFold(process, "nginx") {
				nginxInUse = true
				continue
			}
			blockingProcesses = append(blockingProcesses, process)
		}
		if len(blockingProcesses) > 0 {
			add(fmt.Sprintf("port:%d/tcp", required), StatusFail, fmt.Sprintf("%d/tcp is already used by %s and cannot be taken over by Lanpanel-managed Nginx", required, strings.Join(blockingProcesses, ", ")), "Stop or migrate non-Nginx services using 80/443, then rerun.")
			continue
		}
		if nginxInUse {
			add(fmt.Sprintf("port:%d/tcp", required), StatusWarn, fmt.Sprintf("%d/tcp is already used by Nginx; Lanpanel will reuse Nginx virtual hosts", required), "Confirm existing Nginx sites do not claim app.domains.")
			continue
		}
		add(fmt.Sprintf("port:%d/tcp", required), StatusPass, fmt.Sprintf("%d/tcp is available", required))
	}
}

func findPortBindings(bindings []preflight.PortBinding, port int, protocol string) []preflight.PortBinding {
	matches := []preflight.PortBinding{}
	for _, binding := range bindings {
		bindingProtocol := strings.ToLower(strings.TrimSpace(binding.Protocol))
		if bindingProtocol == "" {
			bindingProtocol = "tcp"
		}
		if binding.Port == port && bindingProtocol == strings.ToLower(protocol) {
			matches = append(matches, binding)
		}
	}
	return matches
}

func publicRoutableIPs(values []string) []string {
	var public []string
	for _, value := range values {
		if isPublicRoutableIP(value) {
			public = append(public, strings.TrimSpace(value))
		}
	}
	return public
}

func isPublicRoutableIP(value string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicRoutableIPPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

var nonPublicRoutableIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func containsString(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func (report Report) FailedCount() int {
	count := 0
	for _, check := range report.Checks {
		if check.Status == StatusFail || check.Status == StatusUnknown {
			count++
		}
	}
	return count
}

func (report Report) Summary() string {
	if report.FailedCount() > 0 {
		return fmt.Sprintf("app deploy preflight found %d blocking checks", report.FailedCount())
	}
	return "app deploy preflight passed"
}

func (report Report) NextSteps() []string {
	seen := map[string]struct{}{}
	var steps []string
	for _, check := range report.Checks {
		for _, remediation := range check.Remediations {
			if _, ok := seen[remediation]; ok {
				continue
			}
			seen[remediation] = struct{}{}
			steps = append(steps, remediation)
		}
	}
	return steps
}

func compact(values []string) []string {
	var out []string
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}
