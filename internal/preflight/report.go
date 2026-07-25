// Package preflight evaluates deployment preconditions and produces actionable diagnostics.
package preflight

import (
	"fmt"
	"lanpanel/internal/components/headscale"
	"lanpanel/internal/config"
	"net/url"
	"strings"
)

type Status string

const (
	StatusPass   Status = "pass"
	StatusWarn   Status = "warn"
	StatusFail   Status = "fail"
	StatusManual Status = "manual"
)

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
	SeverityManual  Severity = "manual"
)

type CheckResult struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Status       Status   `json:"status"`
	Severity     Severity `json:"severity"`
	Summary      string   `json:"summary"`
	Findings     []string `json:"findings,omitempty"`
	Remediations []string `json:"remediations,omitempty"`
}

type ManualChecklist struct {
	Title string   `json:"title"`
	Items []string `json:"items"`
}

type Report struct {
	Checks           []CheckResult     `json:"checks"`
	ManualChecklists []ManualChecklist `json:"manual_checklists,omitempty"`
}

type Inputs struct {
	Permissions   PermissionState
	Platform      PlatformInfo
	Capabilities  HostCapabilityState
	DNS           DNSProbe
	Ports         []PortBinding
	Firewall      FirewallState
	Services      []ServiceState
	Managed       ManagedServiceState
	ACME          ACMEState
	PackageSource PackageSourceState
}

func BuildReport(cfg config.Config, inputs Inputs) Report {
	dns := inputs.DNS
	if strings.TrimSpace(dns.Host) == "" {
		dns.Host = parseServerHost(cfg.Default.ServerURL)
	}
	if strings.TrimSpace(dns.ExpectedIPv4) == "" {
		dns.ExpectedIPv4 = cfg.Advanced.Network.PublicIPv4
	}
	if strings.TrimSpace(dns.ExpectedIPv6) == "" {
		dns.ExpectedIPv6 = cfg.Advanced.Network.PublicIPv6
	}

	packageSource := inputs.PackageSource
	if strings.TrimSpace(packageSource.Mode) == "" {
		packageSource.Mode = cfg.Advanced.HeadscaleSource.Mode
	}
	if strings.TrimSpace(packageSource.Version) == "" {
		packageSource.Version = cfg.Advanced.HeadscaleSource.Version
	}
	if strings.TrimSpace(packageSource.URL) == "" {
		packageSource.URL = cfg.Advanced.HeadscaleSource.URL
	}
	if strings.TrimSpace(packageSource.FilePath) == "" {
		packageSource.FilePath = cfg.Advanced.HeadscaleSource.FilePath
	}
	if strings.TrimSpace(packageSource.ExpectedSHA256) == "" {
		if strings.TrimSpace(packageSource.Mode) == config.PackageSourceModeDirect {
			if digest, err := headscale.PackageSHA256(packageSource.Version, cfg.Advanced.Platform.Arch); err == nil {
				packageSource.ExpectedSHA256 = digest
			}
		} else {
			packageSource.ExpectedSHA256 = cfg.Advanced.HeadscaleSource.SHA256
		}
	}

	acme := inputs.ACME
	if strings.TrimSpace(acme.Challenge) == "" {
		acme.Challenge = cfg.Default.ACMEChallenge
	}
	if strings.TrimSpace(acme.ServerHost) == "" {
		acme.ServerHost = parseServerHost(cfg.Default.ServerURL)
	}
	if strings.TrimSpace(acme.CertificateEmail) == "" {
		acme.CertificateEmail = cfg.Default.CertificateEmail
	}
	if strings.TrimSpace(acme.PlatformID) == "" {
		acme.PlatformID = inputs.Platform.ID
	}
	if strings.TrimSpace(acme.PlatformVersion) == "" {
		acme.PlatformVersion = inputs.Platform.VersionID
	}
	if strings.TrimSpace(acme.DNSProvider) == "" {
		acme.DNSProvider = cfg.Advanced.DNS01.Provider
	}
	if strings.TrimSpace(acme.DNSCredentialsFile) == "" {
		acme.DNSCredentialsFile = cfg.Advanced.DNS01.CredentialsFile
	}
	if strings.TrimSpace(acme.DNSCredentialEnvFile) == "" {
		acme.DNSCredentialEnvFile = cfg.Advanced.DNS01.EnvFile
	}

	return Report{
		Checks: []CheckResult{
			CheckPermissions(inputs.Permissions),
			CheckPlatform(inputs.Platform),
			CheckHostCapabilities(inputs.Capabilities),
			CheckServerDNS(dns),
			CheckPortAvailabilityForConfigWithManagedServices(cfg, inputs.Ports, inputs.Managed),
			CheckFirewall(inputs.Firewall),
			CheckServiceConflictsWithManagedServices(inputs.Services, inputs.Managed),
			CheckPackageSource(packageSource),
			CheckACMEPrerequisites(acme),
		},
		ManualChecklists: BuildManualChecklists(cfg),
	}
}

func (report Report) OverallStatus() Status {
	if report.FailedCount() > 0 {
		return StatusFail
	}
	if report.ManualCount() > 0 {
		return StatusManual
	}
	if report.WarningCount() > 0 {
		return StatusWarn
	}
	return StatusPass
}

func (report Report) FailedCount() int {
	count := 0
	for _, check := range report.Checks {
		if check.Status == StatusFail {
			count++
		}
	}
	return count
}

func (report Report) WarningCount() int {
	count := 0
	for _, check := range report.Checks {
		if check.Status == StatusWarn {
			count++
		}
	}
	return count
}

func (report Report) ManualCount() int {
	count := 0
	for _, check := range report.Checks {
		if check.Status == StatusManual {
			count++
		}
	}
	return count
}

func (report Report) Summary() string {
	switch {
	case report.FailedCount() > 0:
		return fmt.Sprintf("blocked by %s", pluralize(report.FailedCount(), "failed check", "failed checks"))
	case report.ManualCount() > 0:
		return fmt.Sprintf("waiting on %s", pluralize(report.ManualCount(), "manual review item", "manual review items"))
	case report.WarningCount() > 0:
		return fmt.Sprintf("needs review for %s", pluralize(report.WarningCount(), "warning", "warnings"))
	default:
		return "automatic checks passed"
	}
}

func (report Report) NextSteps() []string {
	seen := map[string]struct{}{}
	steps := []string{}

	for _, check := range report.Checks {
		for _, remediation := range check.Remediations {
			remediation = strings.TrimSpace(remediation)
			if remediation == "" {
				continue
			}
			if _, ok := seen[remediation]; ok {
				continue
			}
			seen[remediation] = struct{}{}
			steps = append(steps, remediation)
		}
	}

	return steps
}

func parseServerHost(raw string) string {
	parsedURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsedURL.Hostname()))
}

func pluralize(count int, singular string, plural string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}

func newCheckResult(id string, title string, status Status, severity Severity, summary string, findings []string, remediations []string) CheckResult {
	return CheckResult{
		ID:           id,
		Title:        title,
		Status:       status,
		Severity:     severity,
		Summary:      strings.TrimSpace(summary),
		Findings:     compactStrings(findings),
		Remediations: compactStrings(remediations),
	}
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}
