package preflight

import (
	"fmt"
	"lanpanel/internal/config"
	"net/netip"
	"sort"
	"strings"
)

type DNSProbe struct {
	Host            string   `json:"host,omitempty"`
	ResolvedIPs     []string `json:"resolved_ips,omitempty"`
	LookupError     string   `json:"lookup_error,omitempty"`
	ExpectedIPv4    string   `json:"expected_ipv4,omitempty"`
	ExpectedIPv6    string   `json:"expected_ipv6,omitempty"`
	ExpectedIPError string   `json:"expected_ip_error,omitempty"`
}

type PortBinding struct {
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	InUse        bool   `json:"in_use"`
	LocalAddress string `json:"local_address,omitempty"`
	Process      string `json:"process,omitempty"`
	PID          int    `json:"pid,omitempty"`
}

type PortRequirement struct {
	Port        int
	Protocol    string
	BindAddress string
	Purpose     string
	Reviewable  bool
}

type FirewallState struct {
	Backend        string   `json:"backend,omitempty"`
	Inspected      bool     `json:"inspected"`
	Active         bool     `json:"active"`
	AllowedPorts   []string `json:"allowed_ports,omitempty"`
	MissingPorts   []string `json:"missing_ports,omitempty"`
	DetectionError string   `json:"detection_error,omitempty"`
}

type ServiceState struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Detail string `json:"detail,omitempty"`
}

type ManagedServiceState struct {
	Headscale bool `json:"headscale,omitempty"`
	Nginx     bool `json:"nginx,omitempty"`
}

var requiredPublicServicePorts = []PortRequirement{
	{Port: 80, Protocol: "tcp", Purpose: "Nginx HTTP and ACME HTTP-01", Reviewable: true},
	{Port: 443, Protocol: "tcp", Purpose: "Nginx HTTPS and DERP", Reviewable: true},
	{Port: 3478, Protocol: "udp", Purpose: "Headscale embedded STUN"},
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
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func CheckServerDNS(probe DNSProbe) CheckResult {
	host := strings.TrimSpace(probe.Host)
	resolved := compactStrings(probe.ResolvedIPs)
	if host == "" {
		return newCheckResult(
			"dns",
			"DNS resolution",
			StatusFail,
			SeverityError,
			"The Headscale server host is missing, so DNS cannot be checked.",
			nil,
			[]string{"Set default.server_url to a public HTTPS host name and retry preflight."},
		)
	}

	findings := []string{}
	if len(resolved) > 0 {
		findings = append(findings, fmt.Sprintf("Resolved %s to %s.", host, strings.Join(resolved, ", ")))
	}
	if errText := strings.TrimSpace(probe.LookupError); errText != "" {
		findings = append(findings, fmt.Sprintf("Resolver error: %s.", errText))
		return newCheckResult(
			"dns",
			"DNS resolution",
			StatusFail,
			SeverityError,
			fmt.Sprintf("DNS lookup failed for %s.", host),
			findings,
			[]string{fmt.Sprintf("Create or fix the public DNS record for %s before deploy.", host)},
		)
	}
	if len(resolved) == 0 {
		return newCheckResult(
			"dns",
			"DNS resolution",
			StatusFail,
			SeverityError,
			fmt.Sprintf("%s does not resolve to any public address yet.", host),
			findings,
			[]string{fmt.Sprintf("Create an A or AAAA record for %s before deploy.", host)},
		)
	}
	if len(publicRoutableIPs(resolved)) == 0 {
		return newCheckResult(
			"dns",
			"DNS resolution",
			StatusFail,
			SeverityError,
			fmt.Sprintf("%s does not resolve to a public-routable address yet.", host),
			findings,
			[]string{fmt.Sprintf("Update DNS for %s to include a public-routable A or AAAA record before deploy.", host)},
		)
	}

	missing := []string{}
	if expectedIPv4 := strings.TrimSpace(probe.ExpectedIPv4); expectedIPv4 != "" && !containsString(resolved, expectedIPv4) {
		missing = append(missing, fmt.Sprintf("Expected public IPv4 %s is missing from DNS results.", expectedIPv4))
	}
	if expectedIPv6 := strings.TrimSpace(probe.ExpectedIPv6); expectedIPv6 != "" && !containsString(resolved, expectedIPv6) {
		missing = append(missing, fmt.Sprintf("Expected public IPv6 %s is missing from DNS results.", expectedIPv6))
	}
	if len(missing) > 0 {
		findings = append(findings, missing...)
		return newCheckResult(
			"dns",
			"DNS resolution",
			StatusFail,
			SeverityError,
			fmt.Sprintf("DNS records for %s do not match the expected public addresses.", host),
			findings,
			[]string{fmt.Sprintf("Update the public DNS records for %s so they match the server's reachable IP addresses.", host)},
		)
	}

	return newCheckResult(
		"dns",
		"DNS resolution",
		StatusPass,
		SeverityInfo,
		fmt.Sprintf("DNS for %s resolves to the expected public addresses.", host),
		findings,
		nil,
	)
}

func CheckPortAvailability(bindings []PortBinding) CheckResult {
	return checkPortAvailability(bindings, requiredPublicServicePorts, ManagedServiceState{})
}

func CheckPortAvailabilityForConfig(cfg config.Config, bindings []PortBinding) CheckResult {
	return CheckPortAvailabilityForConfigWithManagedServices(cfg, bindings, ManagedServiceState{})
}

func CheckPortAvailabilityForConfigWithManagedServices(cfg config.Config, bindings []PortBinding, managed ManagedServiceState) CheckResult {
	return checkPortAvailability(bindings, requiredPortRequirements(cfg), managed)
}

func checkPortAvailability(bindings []PortBinding, requirements []PortRequirement, managed ManagedServiceState) CheckResult {
	requiredList := formatRequiredPortList(requirements)
	if len(bindings) == 0 {
		return newCheckResult(
			"ports",
			"Port occupancy",
			StatusManual,
			SeverityManual,
			"Port occupancy still needs host-side confirmation.",
			[]string{fmt.Sprintf("Required ports: %s.", requiredList)},
			[]string{fmt.Sprintf("Confirm that %s are free before running deploy.", requiredList)},
		)
	}

	sorted := append([]PortBinding(nil), bindings...)
	sort.Slice(sorted, func(i int, j int) bool {
		if sorted[i].Port == sorted[j].Port {
			return strings.ToLower(sorted[i].Protocol) < strings.ToLower(sorted[j].Protocol)
		}
		return sorted[i].Port < sorted[j].Port
	})

	provided := make(map[string][]PortBinding, len(sorted))
	for _, binding := range sorted {
		key := portLabel(binding)
		provided[key] = append(provided[key], binding)
	}

	missing := []string{}
	blocking := []string{}
	review := []string{}
	available := []string{}
	managedActive := []string{}
	for _, required := range requirements {
		bindings := provided[portRequirementKey(required)]
		label := portRequirementLabel(required)
		if len(bindings) == 0 {
			missing = append(missing, fmt.Sprintf("Missing occupancy probe for %s.", label))
			continue
		}

		overlaps := false
		for _, binding := range bindings {
			if !bindingOverlapsRequirement(binding, required) {
				continue
			}
			overlaps = true
			if !binding.InUse {
				available = append(available, fmt.Sprintf("%s is available.", label))
				continue
			}
			process := strings.TrimSpace(binding.Process)
			if process == "" {
				process = "another process"
			}
			if isManagedPortBinding(required, binding, process, managed) {
				managedActive = append(managedActive, fmt.Sprintf("%s is already in use by lanpanel-managed %s from the current deploy context.", label, process))
				continue
			}
			if required.Reviewable && isReviewableHTTPPortBinding(binding, process) {
				review = append(review, fmt.Sprintf("%s is already in use by %s and needs a coexistence review.", label, process))
				continue
			}
			blocking = append(blocking, fmt.Sprintf("%s is already in use by %s.", label, process))
		}
		if !overlaps {
			available = append(available, fmt.Sprintf("%s is available.", label))
		}
	}

	if len(blocking) > 0 {
		findings := append([]string{}, blocking...)
		findings = append(findings, review...)
		findings = append(findings, managedActive...)
		findings = append(findings, missing...)
		return newCheckResult(
			"ports",
			"Port occupancy",
			StatusFail,
			SeverityError,
			"Required service ports have incompatible listeners.",
			findings,
			[]string{"Stop or move incompatible listeners before deploy. If only the Headscale metrics port conflicts, set advanced.headscale.metrics_port to an available loopback TCP port."},
		)
	}

	if len(missing) > 0 {
		findings := append([]string{}, review...)
		findings = append(findings, managedActive...)
		findings = append(findings, available...)
		findings = append(findings, missing...)
		return newCheckResult(
			"ports",
			"Port occupancy",
			StatusManual,
			SeverityManual,
			"Port occupancy still needs complete host-side confirmation.",
			findings,
			[]string{fmt.Sprintf("Collect occupancy results for %s before deploy.", requiredList)},
		)
	}

	if len(review) > 0 {
		findings := append([]string{}, review...)
		findings = append(findings, managedActive...)
		findings = append(findings, available...)
		return newCheckResult(
			"ports",
			"Port occupancy",
			StatusWarn,
			SeverityWarning,
			"Existing web listeners need a coexistence review before deploy.",
			findings,
			[]string{"Review server_name ownership, ACME challenge routing, and any existing 80/443 virtual hosts before deploy."},
		)
	}

	return newCheckResult(
		"ports",
		"Port occupancy",
		StatusPass,
		SeverityInfo,
		portAvailabilityPassSummary(managedActive),
		append(managedActive, available...),
		nil,
	)
}

func requiredPortRequirements(cfg config.Config) []PortRequirement {
	metricsPort := cfg.Advanced.Headscale.MetricsPort
	if metricsPort == 0 {
		metricsPort = config.DefaultHeadscaleMetricsPort
	}

	requirements := append([]PortRequirement(nil), requiredPublicServicePorts...)
	requirements = append(requirements,
		PortRequirement{Port: 8080, Protocol: "tcp", BindAddress: "127.0.0.1", Purpose: "Headscale control-plane loopback listener"},
		PortRequirement{Port: metricsPort, Protocol: "tcp", BindAddress: "127.0.0.1", Purpose: "Headscale metrics loopback listener"},
		PortRequirement{Port: 50443, Protocol: "tcp", BindAddress: "127.0.0.1", Purpose: "Headscale gRPC loopback listener"},
	)
	return uniquePortRequirements(requirements)
}

func CheckFirewall(state FirewallState) CheckResult {
	backend := strings.TrimSpace(state.Backend)
	if !state.Inspected {
		findings := []string{}
		if backend != "" {
			findings = append(findings, fmt.Sprintf("Detected firewall backend: %s.", backend))
		}
		if errText := strings.TrimSpace(state.DetectionError); errText != "" {
			findings = append(findings, fmt.Sprintf("Detection detail: %s.", errText))
		}
		return newCheckResult(
			"firewall",
			"Host firewall",
			StatusManual,
			SeverityManual,
			"Local firewall rules still need confirmation.",
			findings,
			[]string{"Confirm that the host firewall allows 80/tcp, 443/tcp, and 3478/udp before deploy."},
		)
	}

	if len(state.MissingPorts) > 0 {
		findings := make([]string, 0, len(state.MissingPorts)+1)
		if backend != "" {
			findings = append(findings, fmt.Sprintf("Firewall backend: %s.", backend))
		}
		for _, port := range compactStrings(state.MissingPorts) {
			findings = append(findings, fmt.Sprintf("Missing allow rule for %s.", port))
		}
		return newCheckResult(
			"firewall",
			"Host firewall",
			StatusFail,
			SeverityError,
			"Host firewall rules are blocking required service ports.",
			findings,
			[]string{"Allow 80/tcp, 443/tcp, and 3478/udp through the host firewall before deploy."},
		)
	}

	findings := []string{}
	if backend != "" {
		findings = append(findings, fmt.Sprintf("Firewall backend: %s.", backend))
	}
	if !state.Active {
		findings = append(findings, "No active host firewall rules were reported.")
	}
	for _, port := range compactStrings(state.AllowedPorts) {
		findings = append(findings, fmt.Sprintf("Allow rule present for %s.", port))
	}

	return newCheckResult(
		"firewall",
		"Host firewall",
		StatusPass,
		SeverityInfo,
		"Host firewall rules will not block required service ports.",
		findings,
		nil,
	)
}

func CheckServiceConflicts(services []ServiceState) CheckResult {
	return CheckServiceConflictsWithManagedServices(services, ManagedServiceState{})
}

func CheckServiceConflictsWithManagedServices(services []ServiceState, managed ManagedServiceState) CheckResult {
	if services == nil {
		return newCheckResult(
			"services",
			"Local service conflicts",
			StatusManual,
			SeverityManual,
			"Local service conflict checks still need host-side confirmation.",
			nil,
			[]string{"Inspect local web services and any existing Headscale units before deploy."},
		)
	}

	activeServices := []ServiceState{}
	for _, service := range services {
		if service.Active {
			activeServices = append(activeServices, service)
		}
	}
	if len(activeServices) == 0 {
		return newCheckResult("services", "Local service conflicts", StatusPass, SeverityInfo, "No known conflicting local services were reported.", nil, nil)
	}

	blockingHeadscale := []string{}
	blockingWeb := []string{}
	review := []string{}
	findings := []string{}
	managedActive := false
	for _, service := range activeServices {
		name := strings.ToLower(strings.TrimSpace(service.Name))
		label := strings.TrimSpace(service.Name)
		if label == "" {
			label = "unknown service"
		}
		line := label
		if detail := strings.TrimSpace(service.Detail); detail != "" {
			line = fmt.Sprintf("%s (%s)", label, detail)
		}
		if isManagedServiceName(name, managed) {
			managedActive = true
			findings = append(findings, fmt.Sprintf("Active lanpanel-managed service detected: %s.", line))
			continue
		}
		findings = append(findings, fmt.Sprintf("Active service detected: %s.", line))
		if name == "headscale" {
			blockingHeadscale = append(blockingHeadscale, label)
			continue
		}
		switch name {
		case "nginx":
			review = append(review, label)
		case "apache2", "caddy", "traefik":
			blockingWeb = append(blockingWeb, label)
		}
	}

	if len(blockingHeadscale) > 0 || len(blockingWeb) > 0 {
		summary := "Incompatible local services would conflict with a fresh lanpanel deployment."
		remediations := []string{"Stop or migrate the incompatible local services before deploy."}
		switch {
		case len(blockingHeadscale) > 0 && len(blockingWeb) == 0:
			summary = "Existing Headscale services would conflict with a fresh lanpanel deployment."
			remediations = []string{"Stop or migrate the existing Headscale service before deploy."}
		case len(blockingHeadscale) == 0 && len(blockingWeb) > 0:
			summary = "Existing non-Nginx web services would conflict with lanpanel-managed Nginx and ACME."
			remediations = []string{"Stop or move Apache, Caddy, or Traefik listeners from 80/443 before deploy, or migrate the site behind lanpanel-managed Nginx."}
		}
		return newCheckResult(
			"services",
			"Local service conflicts",
			StatusFail,
			SeverityError,
			summary,
			findings,
			remediations,
		)
	}

	if len(review) > 0 {
		return newCheckResult(
			"services",
			"Local service conflicts",
			StatusWarn,
			SeverityWarning,
			"Existing local web services need a coexistence review before deploy.",
			findings,
			[]string{"Review server_name ownership, ACME challenge routing, and any existing 80/443 virtual hosts before deploy."},
		)
	}

	return newCheckResult("services", "Local service conflicts", StatusPass, SeverityInfo, serviceConflictsPassSummary(managedActive), findings, nil)
}

func BuildManualChecklists(cfg config.Config) []ManualChecklist {
	host := parseServerHost(cfg.Default.ServerURL)
	if host == "" {
		host = "the Headscale server host"
	}

	items := []string{
		"Confirm the cloud security group allows 80/tcp, 443/tcp, and 3478/udp to this host.",
		"Confirm the cloud provider or upstream network allows public ingress on 80/tcp, 443/tcp, and 3478/udp.",
		fmt.Sprintf("Confirm %s is publicly reachable from the client networks that will join the tailnet.", host),
		"For China mainland deployments, confirm ICP filing and any cloud-provider internet access prerequisites before public launch.",
	}

	switch cfg.Default.ACMEChallenge {
	case config.ACMEChallengeDNS01:
		items = append(items, "Confirm the DNS-01 provider env file is root-only and ready before deploy.")
	default:
		items = append(items, "Confirm HTTP-01 challenge traffic can reach Nginx on 80/tcp without a CDN or upstream proxy blocking /.well-known/acme-challenge/.")
	}

	return []ManualChecklist{{
		Title: "Cloud and compliance review",
		Items: items,
	}}
}

func uniquePortRequirements(requirements []PortRequirement) []PortRequirement {
	unique := make([]PortRequirement, 0, len(requirements))
	seen := map[string]struct{}{}
	for _, requirement := range requirements {
		key := portRequirementKey(requirement)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, requirement)
	}
	return unique
}

func formatRequiredPortList(requirements []PortRequirement) string {
	labels := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		labels = append(labels, portRequirementKey(requirement))
	}
	return humanJoin(labels)
}

func portRequirementKey(requirement PortRequirement) string {
	protocol := strings.ToLower(strings.TrimSpace(requirement.Protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	return fmt.Sprintf("%d/%s", requirement.Port, protocol)
}

func portRequirementLabel(requirement PortRequirement) string {
	label := portRequirementKey(requirement)
	if purpose := strings.TrimSpace(requirement.Purpose); purpose != "" {
		return fmt.Sprintf("%s (%s)", label, purpose)
	}
	return label
}

func portAvailabilityPassSummary(managedActive []string) string {
	if len(managedActive) > 0 {
		return "Required service ports are available or already held by lanpanel-managed services."
	}
	return "Required service ports are available."
}

func serviceConflictsPassSummary(managedActive bool) string {
	if managedActive {
		return "No blocking local service conflicts were reported; lanpanel-managed services are active."
	}
	return "No blocking local service conflicts were reported."
}

func humanJoin(values []string) string {
	values = compactStrings(values)
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	case 2:
		return values[0] + " and " + values[1]
	default:
		return strings.Join(values[:len(values)-1], ", ") + ", and " + values[len(values)-1]
	}
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

func portLabel(binding PortBinding) string {
	protocol := strings.ToLower(strings.TrimSpace(binding.Protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	return fmt.Sprintf("%d/%s", binding.Port, protocol)
}

func isReviewableHTTPPortBinding(binding PortBinding, process string) bool {
	if binding.Port != 80 && binding.Port != 443 {
		return false
	}
	if strings.ToLower(strings.TrimSpace(binding.Protocol)) != "tcp" {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(process)) {
	case "nginx":
		return true
	default:
		return false
	}
}

func isManagedPortBinding(required PortRequirement, binding PortBinding, process string, managed ManagedServiceState) bool {
	name := normalizedServiceName(process)
	protocol := strings.ToLower(strings.TrimSpace(binding.Protocol))
	switch {
	case managed.Nginx && name == "nginx":
		return protocol == "tcp" && bindingMatchesRequirement(binding, required) && strings.Contains(required.Purpose, "Nginx")
	case managed.Headscale && name == "headscale":
		return bindingMatchesRequirement(binding, required) && strings.Contains(required.Purpose, "Headscale")
	default:
		return false
	}
}

func bindingMatchesRequirement(binding PortBinding, required PortRequirement) bool {
	bindingProtocol := strings.ToLower(strings.TrimSpace(binding.Protocol))
	if bindingProtocol == "" {
		bindingProtocol = "tcp"
	}
	requiredProtocol := strings.ToLower(strings.TrimSpace(required.Protocol))
	if requiredProtocol == "" {
		requiredProtocol = "tcp"
	}
	return binding.Port == required.Port && bindingProtocol == requiredProtocol
}

func bindingOverlapsRequirement(binding PortBinding, required PortRequirement) bool {
	if !bindingMatchesRequirement(binding, required) {
		return false
	}
	return socketBindHostsOverlap(binding.LocalAddress, required.BindAddress)
}

func socketBindHostsOverlap(left string, right string) bool {
	left = normalizeSocketBindHost(left)
	right = normalizeSocketBindHost(right)
	if left == "" || right == "" {
		return true
	}
	if left == "*" || right == "*" {
		return true
	}
	if socketBindHostIsWildcard(left) {
		return socketBindWildcardOverlapsHost(left, right)
	}
	if socketBindHostIsWildcard(right) {
		return socketBindWildcardOverlapsHost(right, left)
	}
	if left == right {
		return true
	}
	if left == "localhost" {
		return socketBindHostIsLoopback(right)
	}
	if right == "localhost" {
		return socketBindHostIsLoopback(left)
	}
	leftIP, leftOK := parseSocketBindIP(left)
	rightIP, rightOK := parseSocketBindIP(right)
	return leftOK && rightOK && leftIP.Compare(rightIP) == 0
}

func socketBindWildcardOverlapsHost(wildcard string, host string) bool {
	switch wildcard {
	case "0.0.0.0":
		return socketBindHostIsIPv4(host) || host == "localhost"
	case "::":
		return true
	default:
		return true
	}
}

func socketBindHostIsIPv4(host string) bool {
	ip, ok := parseSocketBindIP(host)
	return ok && ip.Is4()
}

func socketBindHostIsIPv6(host string) bool {
	ip, ok := parseSocketBindIP(host)
	return ok && ip.Is6()
}

func normalizeSocketBindHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if zoneIndex := strings.Index(host, "%"); zoneIndex >= 0 {
		host = host[:zoneIndex]
	}
	return host
}

func socketBindHostIsWildcard(host string) bool {
	switch host {
	case "*", "0.0.0.0", "::":
		return true
	default:
		return false
	}
}

func socketBindHostIsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, ok := parseSocketBindIP(host)
	return ok && ip.IsLoopback()
}

func parseSocketBindIP(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func isManagedServiceName(name string, managed ManagedServiceState) bool {
	switch normalizedServiceName(name) {
	case "headscale":
		return managed.Headscale
	case "nginx":
		return managed.Nginx
	default:
		return false
	}
}

func normalizedServiceName(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	normalized = strings.TrimSuffix(normalized, ".service")
	return normalized
}

func publicRoutableIPs(values []string) []string {
	public := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if isPublicRoutableIP(value) {
			public = append(public, value)
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
