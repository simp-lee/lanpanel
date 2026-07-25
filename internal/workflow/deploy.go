package workflow

import (
	"fmt"
	"lanpanel/internal/components/headscale"
	legocomponent "lanpanel/internal/components/lego"
	"lanpanel/internal/config"
)

type DeployStep struct {
	Key         string
	Description string
}

type DeployPlan struct {
	Steps []DeployStep
}

func NewDeployPlan(cfg config.Config) (DeployPlan, error) {
	if err := cfg.Validate(); err != nil {
		return DeployPlan{}, err
	}
	steps := []DeployStep{
		{Key: "preflight", Description: "Run blocking host and network preflight checks before system writes."},
		{Key: "install-host-dependencies", Description: "Install Nginx and artifact helper packages through the host package manager."},
		{Key: "install-lego", Description: fmt.Sprintf("Install the pinned lego %s binary after archive SHA-256 verification.", legocomponent.Version)},
		{Key: "install-headscale-package", Description: fmt.Sprintf("Install the verified Headscale v%s .deb using the official systemd unit.", headscale.Version)},
		{Key: "render-runtime-assets", Description: "Render Headscale, Nginx, lego hook, and renewal timer runtime assets from deploy/."},
		{Key: "install-runtime-assets", Description: "Write Headscale config, policy, Nginx site, lego hook, and renewal timer units to host paths."},
		{Key: "issue-certificate", Description: certificateDescription(cfg)},
		{Key: "enable-services", Description: "Reload systemd, enable Headscale, Nginx and the lego renewal timer, and restart affected services."},
		{Key: "onboarding", Description: "Create or verify the first local onboarding user through Headscale local CLI management."},
		{Key: "verify", Description: "Run static and host readiness checks before directing users to client onboarding."},
	}
	return DeployPlan{Steps: steps}, nil
}

func (plan DeployPlan) Keys() []string {
	keys := make([]string, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		keys = append(keys, step.Key)
	}
	return keys
}

func (plan DeployPlan) Summary() string {
	if len(plan.Steps) == 0 {
		return "deploy plan has no steps"
	}
	return fmt.Sprintf("deploy plan contains %d ordered steps from preflight through verification", len(plan.Steps))
}

func certificateDescription(cfg config.Config) string {
	switch cfg.Default.ACMEChallenge {
	case config.ACMEChallengeDNS01:
		return "Migrate existing lego storage when needed, then issue the certificate using lego DNS-01 with externally supplied provider credentials."
	default:
		return "Migrate existing lego storage when needed, then issue the certificate using lego HTTP-01 webroot without stopping Nginx."
	}
}
