package verify

import (
	"bytes"
	"fmt"
	"lanpanel/internal/assets"
	"lanpanel/internal/components/headscale"
	"lanpanel/internal/components/nginx"
	"lanpanel/internal/config"
	"lanpanel/internal/render"
	"strings"

	tlscomponent "lanpanel/internal/components/tls"
)

const MinimumTailscaleClientVersion = "1.80.0"

type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

type Check struct {
	ID      string
	Status  Status
	Summary string
}

type Report struct {
	Checks []Check
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

func (report Report) Status() Status {
	if report.FailedCount() > 0 {
		return StatusFail
	}
	return StatusPass
}

func (report Report) Summary() string {
	if report.FailedCount() > 0 {
		return fmt.Sprintf("%d verification checks failed", report.FailedCount())
	}
	return "configuration, runtime assets, and onboarding readiness checks passed"
}

func StaticReport(cfg config.Config, staged []render.StagedFile) Report {
	checks := []Check{}
	add := func(id string, err error, passSummary string) {
		if err != nil {
			checks = append(checks, Check{ID: id, Status: StatusFail, Summary: err.Error()})
			return
		}
		checks = append(checks, Check{ID: id, Status: StatusPass, Summary: passSummary})
	}

	headscaleConfig, ok := stagedContent(staged, "templates/etc/headscale/config.yaml.tmpl")
	if !ok {
		add("headscale-config", fmt.Errorf("rendered Headscale config is missing"), "")
	} else {
		add("headscale-config", headscale.ValidateRuntimeConfig(cfg, headscaleConfig), "Headscale config keeps control-plane and auxiliary listeners inside the required boundary.")
	}

	policy, ok := stagedContent(staged, "templates/etc/headscale/policy.hujson")
	if !ok {
		add("acl-policy", fmt.Errorf("rendered policy.hujson is missing"), "")
	} else {
		add("acl-policy", headscale.ValidateAllowAllPolicy(policy), "Default policy.hujson is the allow-all Day 1 baseline.")
	}

	nginxSite, ok := stagedContent(staged, "templates/etc/nginx/sites-available/headscale.conf.tmpl")
	if !ok {
		add("nginx-site", fmt.Errorf("rendered Nginx site is missing"), "")
	} else if site, err := nginx.NewSiteConfig(cfg); err != nil {
		add("nginx-site", err, "")
	} else {
		add("nginx-site", nginx.ValidateRenderedSite(site, nginxSite), "Nginx site preserves server_name isolation, fullchain TLS and DERP WebSocket proxy semantics.")
	}

	hook, ok := stagedContent(staged, "templates/usr/local/lib/lanpanel/hooks/install-lego-cert-and-reload-nginx.sh")
	if !ok {
		add("certificate-hook", fmt.Errorf("lego certificate install hook is missing"), "")
	} else {
		add("certificate-hook", tlscomponent.ValidateReloadHook(hook), "lego deploy hook installs the issued certificate and reloads Nginx.")
	}

	renewService, ok := stagedContent(staged, "templates/etc/systemd/system/lanpanel-lego-renew.service.tmpl")
	if !ok {
		add("renewal-service", fmt.Errorf("lego renewal service is missing"), "")
	} else {
		add("renewal-service", validateRenewalServiceForConfig(cfg, renewService), "lego renewal service runs v5 migrate gate and lego run --deploy-hook against lanpanel-managed certificate paths.")
	}

	renewTimer, ok := stagedContent(staged, "templates/etc/systemd/system/lanpanel-lego-renew.timer")
	if !ok {
		add("renewal-timer", fmt.Errorf("lego renewal timer is missing"), "")
	} else {
		add("renewal-timer", tlscomponent.ValidateRenewalTimer(renewTimer), "lego renewal timer avoids synchronized midnight renewals and persists missed runs.")
	}

	_, certErr := tlscomponent.NewCertificatePlan(cfg)
	add("certificate-plan", certErr, "Certificate plan uses the configured ACME challenge and fullchain paths.")

	checks = append(checks, Check{
		ID:      "client-version",
		Status:  StatusPass,
		Summary: "Minimum supported Tailscale client version is >= v" + MinimumTailscaleClientVersion + ".",
	})

	return Report{Checks: checks}
}

func validateRenewalServiceForConfig(cfg config.Config, content []byte) error {
	if err := tlscomponent.ValidateRenewalService(content); err != nil {
		return err
	}
	if cfg.Default.ACMEChallenge != config.ACMEChallengeDNS01 {
		return nil
	}
	envFile := strings.TrimSpace(cfg.Advanced.DNS01.EnvFile)
	if envFile == "" {
		return nil
	}
	if !strings.Contains(string(content), "EnvironmentFile="+envFile) {
		return fmt.Errorf("lego DNS-01 renewal service must include EnvironmentFile=%s", envFile)
	}
	return nil
}

func stagedContent(staged []render.StagedFile, sourcePath string) ([]byte, bool) {
	for _, file := range staged {
		if file.SourcePath == sourcePath {
			return bytes.Clone(file.Content), true
		}
	}
	return nil, false
}

func RequiredActivations(staged []render.StagedFile) []assets.Activation {
	seen := map[assets.Activation]struct{}{}
	var activations []assets.Activation
	for _, file := range staged {
		for _, activation := range file.Activations {
			if _, ok := seen[activation]; ok {
				continue
			}
			seen[activation] = struct{}{}
			activations = append(activations, activation)
		}
	}
	return activations
}
