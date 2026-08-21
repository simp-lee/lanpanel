package diagnostics

import (
	"sort"
	"strings"
	"time"
)

type (
	ResourceObservation struct{ ResourceID, Status, Reason string }
	Observation         struct {
		ObservedAt                  time.Time
		Nginx, Headscale, Connector string
		Resources                   []ResourceObservation
	}
)
type Issue struct{ Code, Responsibility, Summary, Guidance string }

func Build(observation Observation) []Issue {
	issues := []Issue{}
	if observation.Nginx != "healthy" {
		issues = append(issues, Issue{"nginx_unknown", "lanpanel_or_host_administrator", "Nginx disk graph cannot be freshly verified", "keep ingress closed; export configuration and rebuild on a clean supported host"})
	}
	if observation.Connector == "unknown" {
		issues = append(issues, Issue{"connector_unknown", "host_administrator", "connector state or ControlURL cannot be proved", "resolve Tailscale state outside LanPanel, then verify again"})
	}
	if strings.Contains(observation.Headscale, "closed") || strings.Contains(observation.Headscale, "unknown") {
		issues = append(issues, Issue{"headscale_closed", "lanpanel_contraction", "Headscale control ingress is closed or unknown", "export configuration and rebuild on a clean supported host if exact reconciliation cannot converge"})
	}
	for _, resource := range observation.Resources {
		if resource.Status != "healthy" && resource.Status != "closed" {
			issues = append(issues, Issue{"resource_" + resource.ResourceID, "resource_or_host_administrator", "resource is not freshly healthy: " + resource.Reason, "keep ingress unpublished; use configuration export and clean-host rebuild"})
		}
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Code < issues[j].Code })
	return issues
}
