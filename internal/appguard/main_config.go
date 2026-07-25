package appguard

import (
	"fmt"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/config"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func ValidateAgainstMainConfig(cfg appconfig.Config) error {
	mainConfigPath := cfg.EffectiveLanpanelConfig()
	mainConfigRequired := cfg.RequiresTailscale() && strings.TrimSpace(cfg.Tailscale.LoginServer) == ""
	if strings.TrimSpace(mainConfigPath) == "" {
		mainConfigPath = appconfig.DefaultLanpanelConfigPath
	}
	mainCfg, err := config.LoadFile(mainConfigPath)
	if err != nil {
		if mainConfigRequired {
			return fmt.Errorf("load tailscale.lanpanel_config %s: %w", mainConfigPath, err)
		}
		return nil
	}
	if err := validateAppDoesNotReuseMainServerDomain(cfg, mainCfg, mainConfigPath); err != nil {
		return err
	}
	if err := validateAppDoesNotReuseHeadscaleMetricsPort(cfg, mainCfg, mainConfigPath); err != nil {
		return err
	}
	return nil
}

func validateAppDoesNotReuseMainServerDomain(cfg appconfig.Config, mainCfg config.Config, mainConfigPath string) error {
	serverHost, err := serverURLHost(mainCfg.Default.ServerURL)
	if err != nil {
		return fmt.Errorf("parse Headscale server_url from %s: %w", mainConfigPath, err)
	}
	for _, domain := range cfg.App.Domains {
		if normalizeDomainForCompare(domain) == serverHost {
			return fmt.Errorf("app.domains must not reuse Headscale server_url host %q from %s", serverHost, mainConfigPath)
		}
	}
	return nil
}

func validateAppDoesNotReuseHeadscaleMetricsPort(cfg appconfig.Config, mainCfg config.Config, mainConfigPath string) error {
	const headscaleMetricsBindHost = "127.0.0.1"

	metricsPort := mainCfg.Advanced.Headscale.MetricsPort
	if metricsPort <= 0 {
		return nil
	}
	if cfg.Mode() == appconfig.ModeListen {
		host, port, ok := splitAppHostPort(cfg.App.Listen)
		if ok && port == metricsPort && SocketBindHostsOverlap(host, headscaleMetricsBindHost) {
			return fmt.Errorf("app.listen must not reuse Headscale metrics port %d from %s", metricsPort, mainConfigPath)
		}
	}
	if cfg.Nginx.GoAccess.Enabled {
		listen := appconfig.EffectiveNginxGoAccessWebSocketListen(cfg.App.Name, cfg.Nginx.GoAccess)
		host, port, ok := splitAppHostPort(listen)
		if ok && port == metricsPort && SocketBindHostsOverlap(host, headscaleMetricsBindHost) {
			return fmt.Errorf("nginx.goaccess.websocket_listen must not reuse Headscale metrics port %d from %s", metricsPort, mainConfigPath)
		}
	}
	return nil
}

func splitAppHostPort(listen string) (string, int, bool) {
	host, portString, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

func serverURLHost(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	host := normalizeDomainForCompare(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("server_url host is required")
	}
	return host, nil
}

func normalizeDomainForCompare(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func SocketBindHostsOverlap(left string, right string) bool {
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
