package appconfig

import (
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/config"
	"lanpanel/internal/realip"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type validationErrors []string

var nginxExpiresValuePattern = regexp.MustCompile(`^(?:off|epoch|max|[+-]?[0-9]+(?:ms|s|m|h|d|w|M|y)?)$`)
var nginxDefaultTypeValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*/[A-Za-z0-9][A-Za-z0-9._+-]*$`)
var nginxSizeValuePattern = regexp.MustCompile(`^[0-9]+(?:[kKmMgG])?$`)
var nginxTimeValuePattern = regexp.MustCompile(`^[0-9]+(?:ms|s|m|h|d|w|M|y)?$`)
var goAccessURLPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]+$`)
var systemdSafeEmailPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$`)
var browserAuthPasswordFingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{16}$`)

var browserAuthManagedRoot = "/etc/lanpanel/browser-auth"

func UnsafeSetBrowserAuthManagedRootForTest(root string) func() {
	previous := browserAuthManagedRoot
	browserAuthManagedRoot = filepath.Clean(strings.TrimSpace(root))
	return func() { browserAuthManagedRoot = previous }
}

func (errs validationErrors) Error() string {
	return strings.Join(errs, "; ")
}

func (c *Config) normalize() {
	c.APIVersion = strings.TrimSpace(c.APIVersion)
	c.App.Name = strings.TrimSpace(c.App.Name)
	c.App.CertificateEmail = strings.TrimSpace(c.App.CertificateEmail)
	c.App.ACMEChallenge = strings.TrimSpace(c.App.ACMEChallenge)
	c.App.Listen = strings.TrimSpace(c.App.Listen)
	c.App.Upstream = strings.TrimSpace(c.App.Upstream)
	for i, domain := range c.App.Domains {
		c.App.Domains[i] = normalizeDomain(domain)
	}
	c.Access.AccessMode = AccessMode(strings.TrimSpace(string(c.Access.AccessMode)))
	c.Access.BrowserAuth.AuthBasicUserFile = strings.TrimSpace(c.Access.BrowserAuth.AuthBasicUserFile)
	c.Access.BrowserAuth.Managed.CredentialID = strings.TrimSpace(c.Access.BrowserAuth.Managed.CredentialID)
	c.Access.BrowserAuth.Managed.HtpasswdPath = strings.TrimSpace(c.Access.BrowserAuth.Managed.HtpasswdPath)
	c.Access.BrowserAuth.Managed.Username = strings.TrimSpace(c.Access.BrowserAuth.Managed.Username)
	c.Access.BrowserAuth.Managed.PasswordFingerprint = strings.TrimSpace(c.Access.BrowserAuth.Managed.PasswordFingerprint)
	for i, cidr := range c.Access.CIDRAllowlist {
		c.Access.CIDRAllowlist[i] = strings.TrimSpace(cidr)
	}
	c.Access.OriginProtection.Mode = OriginProtectionMode(strings.TrimSpace(string(c.Access.OriginProtection.Mode)))
	c.Access.OriginProtection.EdgeOneProfile = strings.TrimSpace(c.Access.OriginProtection.EdgeOneProfile)
	c.Service.ExecStart = strings.TrimSpace(c.Service.ExecStart)
	c.Service.WorkingDirectory = strings.TrimSpace(c.Service.WorkingDirectory)
	c.Service.EnvFile = strings.TrimSpace(c.Service.EnvFile)
	c.Nginx.ClientMaxBodySize = strings.TrimSpace(c.Nginx.ClientMaxBodySize)
	c.Nginx.AccessLog = strings.TrimSpace(c.Nginx.AccessLog)
	c.Nginx.ErrorLog = strings.TrimSpace(c.Nginx.ErrorLog)
	c.Nginx.GoAccess.Language = strings.TrimSpace(c.Nginx.GoAccess.Language)
	c.Nginx.GoAccess.LogFormat = strings.TrimSpace(c.Nginx.GoAccess.LogFormat)
	c.Nginx.GoAccess.Path = strings.TrimSpace(c.Nginx.GoAccess.Path)
	c.Nginx.GoAccess.WebSocketPath = strings.TrimSpace(c.Nginx.GoAccess.WebSocketPath)
	c.Nginx.GoAccess.WebSocketListen = strings.TrimSpace(c.Nginx.GoAccess.WebSocketListen)
	c.Nginx.GoAccess.AuthBasicUserFile = strings.TrimSpace(c.Nginx.GoAccess.AuthBasicUserFile)
	for i, cidr := range c.Nginx.GoAccess.AuthCIDRAllowlist {
		c.Nginx.GoAccess.AuthCIDRAllowlist[i] = strings.TrimSpace(cidr)
	}
	c.Nginx.Proxy.ConnectTimeout = strings.TrimSpace(c.Nginx.Proxy.ConnectTimeout)
	c.Nginx.Proxy.ReadTimeout = strings.TrimSpace(c.Nginx.Proxy.ReadTimeout)
	c.Nginx.Proxy.SendTimeout = strings.TrimSpace(c.Nginx.Proxy.SendTimeout)
	for i := range c.Nginx.StaticLocations {
		c.Nginx.StaticLocations[i].Path = strings.TrimSpace(c.Nginx.StaticLocations[i].Path)
		c.Nginx.StaticLocations[i].Match = strings.TrimSpace(c.Nginx.StaticLocations[i].Match)
		c.Nginx.StaticLocations[i].Alias = strings.TrimSpace(c.Nginx.StaticLocations[i].Alias)
		c.Nginx.StaticLocations[i].DefaultType = strings.TrimSpace(c.Nginx.StaticLocations[i].DefaultType)
		c.Nginx.StaticLocations[i].Expires = strings.TrimSpace(c.Nginx.StaticLocations[i].Expires)
		c.Nginx.StaticLocations[i].CacheControl = strings.TrimSpace(c.Nginx.StaticLocations[i].CacheControl)
	}
	for name, profile := range c.RealIP.Profiles {
		profile.Provider = strings.TrimSpace(profile.Provider)
		profile.RefreshInterval = strings.TrimSpace(profile.RefreshInterval)
		profile.EdgeOne.ZoneID = strings.TrimSpace(profile.EdgeOne.ZoneID)
		profile.EdgeOne.EnvFile = strings.TrimSpace(profile.EdgeOne.EnvFile)
		c.RealIP.Profiles[name] = profile
	}
	c.DNS01.Provider = strings.TrimSpace(c.DNS01.Provider)
	c.DNS01.EnvFile = strings.TrimSpace(c.DNS01.EnvFile)
	c.Tailscale.LanpanelConfig = strings.TrimSpace(c.Tailscale.LanpanelConfig)
	c.Tailscale.LoginServer = normalizeLoginServer(c.Tailscale.LoginServer)
	c.Tailscale.Hostname = strings.TrimSpace(c.Tailscale.Hostname)
	c.Tailscale.AuthKeyFile = strings.TrimSpace(c.Tailscale.AuthKeyFile)
	c.Dependencies.LegoSource.Mode = strings.TrimSpace(c.Dependencies.LegoSource.Mode)
	c.Dependencies.LegoSource.FilePath = strings.TrimSpace(c.Dependencies.LegoSource.FilePath)
	c.Dependencies.PackageProbe.ReachabilityTimeout = strings.TrimSpace(c.Dependencies.PackageProbe.ReachabilityTimeout)
	c.Dependencies.PackageProbe.ArtifactTimeout = strings.TrimSpace(c.Dependencies.PackageProbe.ArtifactTimeout)
	c.Dependencies.Proxy.HTTPProxy = strings.TrimSpace(c.Dependencies.Proxy.HTTPProxy)
	c.Dependencies.Proxy.HTTPSProxy = strings.TrimSpace(c.Dependencies.Proxy.HTTPSProxy)
	c.Dependencies.Proxy.NoProxy = strings.TrimSpace(c.Dependencies.Proxy.NoProxy)
	c.Dependencies.Platform.Arch = strings.TrimSpace(c.Dependencies.Platform.Arch)
}

func (c Config) Validate() error {
	return c.validate(false)
}

func (c Config) ValidateForExposurePlan() error {
	return c.validate(true)
}

func (c Config) validate(allowMissingConfirmations bool) error {
	var errs validationErrors

	if c.APIVersion == "" {
		errs = append(errs, "api_version is required")
	} else if c.APIVersion != APIVersion {
		errs = append(errs, fmt.Sprintf("api_version must be %q", APIVersion))
	}

	validateAppName(&errs, c.App.Name)
	validateDomains(&errs, c.App.Domains)
	validateEmail(&errs, "app.certificate_email", c.App.CertificateEmail)
	validateACMEChallenge(&errs, c.App.ACMEChallenge)
	validateMode(&errs, c)
	validateAccess(&errs, c, allowMissingConfirmations)
	validateService(&errs, c)
	validateNginx(&errs, c)
	validateRealIP(&errs, c)
	validateGoAccessAppListenConflict(&errs, c)
	validateGoAccessPathConflicts(&errs, c)
	validateDNS01(&errs, c.App.ACMEChallenge, c.DNS01)
	validateTailscale(&errs, c)
	if err := config.ValidateDependencyConfig("dependencies", c.Dependencies); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}

func validateAccess(errs *validationErrors, c Config, allowMissingConfirmations bool) {
	switch c.Access.AccessMode {
	case AccessModeBrowser:
		validateBrowserAccess(errs, c)
	case AccessModePublic:
		if !c.Access.PublicRiskConfirmed && !allowMissingConfirmations {
			*errs = append(*errs, "access.public_risk_confirmed must be true when access.access_mode is public")
		}
		if browserAuthHasFields(c.Access.BrowserAuth) {
			*errs = append(*errs, "access.browser_auth must be empty when access.access_mode is public")
		}
		if len(c.Access.CIDRAllowlist) > 0 {
			*errs = append(*errs, "access.cidr_allowlist is only supported when access.access_mode is browser")
		}
	case AccessModePrivateClient:
		if !allowMissingConfirmations {
			*errs = append(*errs, "access.access_mode private_client is reserved for P1 and cannot be activated in P0")
		}
		if c.Access.PublicRiskConfirmed {
			*errs = append(*errs, "access.public_risk_confirmed must be false when access.access_mode is private_client")
		}
		if browserAuthHasFields(c.Access.BrowserAuth) {
			*errs = append(*errs, "access.browser_auth must be empty when access.access_mode is private_client")
		}
		if len(c.Access.CIDRAllowlist) > 0 {
			*errs = append(*errs, "access.cidr_allowlist is only supported when access.access_mode is browser")
		}
	case "":
		*errs = append(*errs, "access.access_mode is required")
	default:
		*errs = append(*errs, "access.access_mode must be one of: browser, public, private_client")
	}

	for i, cidr := range c.Access.CIDRAllowlist {
		field := fmt.Sprintf("access.cidr_allowlist[%d]", i)
		if cidr == "" {
			*errs = append(*errs, field+" is required when set")
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			*errs = append(*errs, field+" must be a valid CIDR")
		}
	}

	validateOriginProtection(errs, c, allowMissingConfirmations)
}

func validateBrowserAccess(errs *validationErrors, c Config) {
	userFile := c.BrowserAuthUserFile()
	if userFile == "" {
		*errs = append(*errs, "access.browser_auth.auth_basic_user_file or access.browser_auth.managed.htpasswd_path is required when access.access_mode is browser")
	} else {
		validateNginxDirectivePath(errs, "access.browser_auth.auth_basic_user_file", userFile, true)
	}
	if c.Access.BrowserAuth.AuthBasicUserFile != "" && pathUnderRoot(c.Access.BrowserAuth.AuthBasicUserFile, browserAuthManagedRoot) {
		*errs = append(*errs, "access.browser_auth.auth_basic_user_file must not be under LanPanel-managed browser auth directory; use access.browser_auth.managed")
	}
	if c.Access.PublicRiskConfirmed {
		*errs = append(*errs, "access.public_risk_confirmed must be false when access.access_mode is browser")
	}
	managed := c.Access.BrowserAuth.Managed
	if managed.CredentialID != "" || managed.HtpasswdPath != "" || managed.Username != "" || managed.PasswordFingerprint != "" {
		if c.Access.BrowserAuth.AuthBasicUserFile != "" {
			*errs = append(*errs, "access.browser_auth.auth_basic_user_file and access.browser_auth.managed must not both be set")
		}
		if managed.CredentialID == "" {
			*errs = append(*errs, "access.browser_auth.managed.credential_id is required when managed browser auth is used")
		} else if !isSafeAppName(managed.CredentialID) {
			*errs = append(*errs, "access.browser_auth.managed.credential_id must start with a lowercase letter, contain only lowercase letters, digits, and hyphens, and must not end with a hyphen")
		}
		if managed.HtpasswdPath == "" {
			*errs = append(*errs, "access.browser_auth.managed.htpasswd_path is required when managed browser auth is used")
		} else {
			validateNginxDirectivePath(errs, "access.browser_auth.managed.htpasswd_path", managed.HtpasswdPath, true)
			if !pathIsChildOfRoot(managed.HtpasswdPath, browserAuthManagedRoot) {
				*errs = append(*errs, "access.browser_auth.managed.htpasswd_path must be under "+browserAuthManagedRoot)
			} else if filepath.Dir(filepath.Clean(managed.HtpasswdPath)) != browserAuthManagedRoot || filepath.Base(managed.HtpasswdPath) != managed.CredentialID+".htpasswd" {
				*errs = append(*errs, "access.browser_auth.managed.htpasswd_path must be /etc/lanpanel/browser-auth/<credential_id>.htpasswd")
			}
		}
		if managed.Username == "" {
			*errs = append(*errs, "access.browser_auth.managed.username is required when managed browser auth is used")
		} else if !isSafeBrowserAuthUsername(managed.Username) {
			*errs = append(*errs, "access.browser_auth.managed.username must contain only ASCII letters, digits, dot, underscore, and hyphen, and must not start with hyphen")
		}
		if managed.PasswordFingerprint == "" {
			*errs = append(*errs, "access.browser_auth.managed.password_fingerprint is required when managed browser auth is used")
		} else if !browserAuthPasswordFingerprintPattern.MatchString(managed.PasswordFingerprint) {
			*errs = append(*errs, "access.browser_auth.managed.password_fingerprint must be sha256: followed by 16 lowercase hex characters")
		}
	}
}

func validateOriginProtection(errs *validationErrors, c Config, allowMissingConfirmations bool) {
	if c.Access.AccessMode == AccessModePrivateClient {
		if c.Access.OriginProtection.Mode != "" && c.Access.OriginProtection.Mode != OriginProtectionModeNone {
			*errs = append(*errs, "access.origin_protection.mode must be none or omitted when access.access_mode is private_client")
		}
		if c.Access.OriginProtection.DirectOriginRiskConfirmed {
			*errs = append(*errs, "access.origin_protection.direct_origin_risk_confirmed must be false when access.access_mode is private_client")
		}
		if c.Access.OriginProtection.EdgeOneProfile != "" {
			*errs = append(*errs, "access.origin_protection.edgeone_profile must be empty when access.access_mode is private_client")
		}
		return
	}
	switch c.Access.OriginProtection.Mode {
	case OriginProtectionModeNone:
		if !c.Access.OriginProtection.DirectOriginRiskConfirmed && !allowMissingConfirmations {
			*errs = append(*errs, "access.origin_protection.direct_origin_risk_confirmed must be true when access.origin_protection.mode is none")
		}
		if c.Access.OriginProtection.EdgeOneProfile != "" {
			*errs = append(*errs, "access.origin_protection.edgeone_profile must be empty when access.origin_protection.mode is none")
		}
	case OriginProtectionModeEdgeOne:
		if c.Access.OriginProtection.DirectOriginRiskConfirmed {
			*errs = append(*errs, "access.origin_protection.direct_origin_risk_confirmed must be false when access.origin_protection.mode is edgeone")
		}
		profileName := c.Access.OriginProtection.EdgeOneProfile
		if profileName == "" {
			*errs = append(*errs, "access.origin_protection.edgeone_profile is required when access.origin_protection.mode is edgeone")
			return
		}
		if !isSafeRealIPProfileName(profileName) {
			*errs = append(*errs, "access.origin_protection.edgeone_profile must start with a lowercase letter, contain only lowercase letters, digits, and hyphens, and must not end with a hyphen")
			return
		}
		profile, ok := c.RealIP.Profiles[profileName]
		if !ok {
			*errs = append(*errs, "access.origin_protection.edgeone_profile references undefined realip profile "+profileName)
			return
		}
		if !profile.IsEnabled() {
			*errs = append(*errs, "access.origin_protection.edgeone_profile references disabled realip profile "+profileName)
		}
		if strings.TrimSpace(profile.Provider) != RealIPProviderEdgeOne {
			*errs = append(*errs, "access.origin_protection.edgeone_profile must reference an EdgeOne realip profile")
		}
		if c.App.ACMEChallenge != ACMEChallengeDNS01 {
			*errs = append(*errs, "app.acme_challenge must be dns-01 when access.origin_protection.mode is edgeone")
		}
	case "":
		*errs = append(*errs, "access.origin_protection.mode is required")
	default:
		*errs = append(*errs, "access.origin_protection.mode must be one of: none, edgeone")
	}
}

func validateAppName(errs *validationErrors, name string) {
	if name == "" {
		*errs = append(*errs, "app.name is required")
		return
	}
	if len(name) > 32 {
		*errs = append(*errs, "app.name must be 32 characters or shorter")
	}
	if !isSafeAppName(name) {
		*errs = append(*errs, "app.name must start with a lowercase letter, contain only lowercase letters, digits, and hyphens, and must not end with a hyphen")
	}
	if isReservedAppName(name) {
		*errs = append(*errs, "app.name is reserved by lanpanel, Headscale, Nginx, or Tailscale")
	}
}

func validateDomains(errs *validationErrors, domains []string) {
	if len(domains) == 0 {
		*errs = append(*errs, "app.domains must contain at least one domain")
		return
	}
	seen := make(map[string]struct{}, len(domains))
	for i, domain := range domains {
		field := fmt.Sprintf("app.domains[%d]", i)
		normalized := normalizeDomain(domain)
		if normalized == "" {
			*errs = append(*errs, field+" is required")
			continue
		}
		if !looksLikeDNSName(normalized) {
			*errs = append(*errs, field+" must be an exact DNS name")
			continue
		}
		if strings.Contains(normalized, "*") {
			*errs = append(*errs, field+" must not be a wildcard domain")
			continue
		}
		if _, ok := seen[normalized]; ok {
			*errs = append(*errs, "app.domains must not contain duplicate domains")
			continue
		}
		seen[normalized] = struct{}{}
	}
}

func validateEmail(errs *validationErrors, field string, email string) {
	if email == "" {
		*errs = append(*errs, field+" is required")
		return
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		*errs = append(*errs, field+" must be a plain email address")
	}
	if strings.Contains(email, "%") {
		*errs = append(*errs, field+" must not contain % because systemd unit files treat it as a specifier")
	}
	if !systemdSafeEmailPattern.MatchString(email) || containsControlOrSpace(email) || strings.ContainsAny(email, "\"'\\;{}$") {
		*errs = append(*errs, field+" must be a systemd-safe email token using only letters, digits, dot, underscore, plus, and hyphen")
	}
}

func validateACMEChallenge(errs *validationErrors, challenge string) {
	switch challenge {
	case ACMEChallengeHTTP01, ACMEChallengeDNS01:
	case "":
		*errs = append(*errs, "app.acme_challenge is required")
	default:
		*errs = append(*errs, "app.acme_challenge must be one of: http-01, dns-01")
	}
}

func validateMode(errs *validationErrors, c Config) {
	hasListen := c.App.Listen != ""
	hasUpstream := c.App.Upstream != ""
	switch {
	case hasListen && hasUpstream:
		*errs = append(*errs, "app.listen and app.upstream must not both be set")
	case !hasListen && !hasUpstream:
		*errs = append(*errs, "one of app.listen or app.upstream is required")
	case hasListen:
		validateListenAddress(errs, "app.listen", c.App.Listen)
	case hasUpstream:
		validateUpstreamAddress(errs, "app.upstream", c.App.Upstream)
	}
}

func validateService(errs *validationErrors, c Config) {
	switch c.Mode() {
	case ModeListen:
		validateExecStart(errs, c.Service.ExecStart)
		validateWorkingDirectory(errs, c.Service.WorkingDirectory)
		validateServiceEnvFile(errs, c.Service.EnvFile)
	case ModeUpstream:
		if c.Service.ExecStart != "" {
			*errs = append(*errs, "service.exec_start must be empty when app.upstream is set")
		}
		if c.Service.WorkingDirectory != "" {
			*errs = append(*errs, "service.working_directory must be empty when app.upstream is set")
		}
		if c.Service.EnvFile != "" {
			*errs = append(*errs, "service.env_file must be empty when app.upstream is set")
		}
	}
}

func validateExecStart(errs *validationErrors, execStart string) {
	if execStart == "" {
		*errs = append(*errs, "service.exec_start is required when app.listen is set")
		return
	}
	if containsControl(execStart) {
		*errs = append(*errs, "service.exec_start must not contain control characters")
	}
	if strings.Contains(execStart, "%") {
		*errs = append(*errs, "service.exec_start must not contain % because systemd treats it as a specifier")
	}
	if strings.ContainsAny(execStart, ";\"'\\${}") {
		*errs = append(*errs, "service.exec_start must not contain systemd separators, variables, quotes, or escapes")
	}
	fields := strings.Fields(execStart)
	if len(fields) == 0 {
		*errs = append(*errs, "service.exec_start is required when app.listen is set")
		return
	}
	binary := fields[0]
	if !filepath.IsAbs(binary) {
		*errs = append(*errs, "service.exec_start must start with an absolute business binary path")
		return
	}
	if filepath.Clean(binary) != binary {
		*errs = append(*errs, "service.exec_start binary path must be clean and absolute")
	}
	if strings.ContainsAny(binary, "\"'\\") {
		*errs = append(*errs, "service.exec_start binary path must not contain quotes or escapes")
	}
}

func validateWorkingDirectory(errs *validationErrors, dir string) {
	if dir == "" {
		return
	}
	if !filepath.IsAbs(dir) {
		*errs = append(*errs, "service.working_directory must be an absolute directory path when set")
		return
	}
	if filepath.Clean(dir) != dir {
		*errs = append(*errs, "service.working_directory must be clean and absolute")
	}
	if containsControl(dir) || strings.Contains(dir, "%") || strings.ContainsAny(dir, "\"'\\") {
		*errs = append(*errs, "service.working_directory must not contain control characters, systemd specifiers, quotes, or escapes")
	}
}

func validateServiceEnvFile(errs *validationErrors, path string) {
	if path == "" {
		return
	}
	validatePathField(errs, "service.env_file", path, true)
}

func validateNginx(errs *validationErrors, c Config) {
	cfg := c.Nginx
	if cfg.ClientMaxBodySize != "" && !nginxSizeValuePattern.MatchString(cfg.ClientMaxBodySize) {
		*errs = append(*errs, "nginx.client_max_body_size must be a simple nginx size such as 20m")
	}
	validateNginxOptionalLogPath(errs, "nginx.access_log", cfg.AccessLog, true)
	validateNginxOptionalLogPath(errs, "nginx.error_log", cfg.ErrorLog, false)
	validateNginxGoAccess(errs, c)
	validateNginxProxy(errs, cfg.Proxy)

	seenPaths := map[string]struct{}{}
	for index, location := range cfg.StaticLocations {
		field := fmt.Sprintf("nginx.static_locations[%d]", index)
		match := location.Match
		if match == "" {
			match = "prefix"
		}
		validateNginxLocationPath(errs, field+".path", location.Path)
		validateNginxAliasPath(errs, field+".alias", location.Alias)
		switch match {
		case "prefix":
			if location.Path != "" && !strings.HasSuffix(location.Path, "/") {
				*errs = append(*errs, field+".path must end with / for prefix static locations")
			}
			if location.Alias != "" && !strings.HasSuffix(location.Alias, "/") {
				*errs = append(*errs, field+".alias must end with / for prefix static locations")
			}
		case "exact":
			if strings.HasSuffix(location.Path, "/") {
				*errs = append(*errs, field+".path must not end with / for exact static locations")
			}
			if strings.HasSuffix(location.Alias, "/") {
				*errs = append(*errs, field+".alias must not end with / for exact static locations")
			}
		default:
			*errs = append(*errs, field+".match must be empty, prefix, or exact")
		}
		if location.Expires != "" && !nginxExpiresValuePattern.MatchString(location.Expires) {
			*errs = append(*errs, field+".expires must be off, epoch, max, or a simple nginx time such as 30d")
		}
		if location.DefaultType != "" && !nginxDefaultTypeValuePattern.MatchString(location.DefaultType) {
			*errs = append(*errs, field+".default_type must be a simple MIME type such as application/xml")
		}
		if location.CacheControl != "" {
			validateNginxQuotedValue(errs, field+".cache_control", location.CacheControl)
		}
		if location.AccessLog != nil && *location.AccessLog {
			*errs = append(*errs, field+".access_log only supports false when set")
		}
		if location.Path == "" {
			continue
		}
		if _, exists := seenPaths[location.Path]; exists {
			*errs = append(*errs, field+".path must not duplicate another static location")
		}
		seenPaths[location.Path] = struct{}{}
	}
}

func validateRealIP(errs *validationErrors, c Config) {
	seenNames := map[string]string{}
	for rawName, profile := range c.RealIP.Profiles {
		name := strings.TrimSpace(rawName)
		field := "realip.profiles." + rawName
		if name == "" {
			*errs = append(*errs, "realip.profiles profile name must not be empty")
			continue
		}
		if name != rawName {
			*errs = append(*errs, field+" name must not contain surrounding whitespace")
		}
		if !isSafeRealIPProfileName(name) {
			*errs = append(*errs, field+" name must start with a lowercase letter, contain only lowercase letters, digits, and hyphens, and must not end with a hyphen")
		}
		if existing, ok := seenNames[name]; ok {
			*errs = append(*errs, fmt.Sprintf("realip.profiles contains duplicate normalized profile names %q and %q", existing, rawName))
		}
		seenNames[name] = rawName
		validateRealIPProfile(errs, field, profile)
	}

	profileName := c.EffectiveRealIPProfileName()
	if profileName == "" {
		return
	}
	profile, ok := c.RealIP.Profiles[profileName]
	if !ok {
		*errs = append(*errs, "access.origin_protection.edgeone_profile references undefined realip profile "+profileName)
		return
	}
	if !profile.IsEnabled() {
		*errs = append(*errs, "access.origin_protection.edgeone_profile references disabled realip profile "+profileName)
	}
	if strings.TrimSpace(profile.Provider) == RealIPProviderEdgeOne && c.App.ACMEChallenge != ACMEChallengeDNS01 {
		*errs = append(*errs, "app.acme_challenge must be dns-01 when access.origin_protection.edgeone_profile references an EdgeOne profile")
	}
}

func validateRealIPProfile(errs *validationErrors, field string, profile RealIPProfileConfig) {
	if profile.Enabled == nil {
		*errs = append(*errs, field+".enabled is required")
	}
	provider := strings.TrimSpace(profile.Provider)
	if provider == "" {
		*errs = append(*errs, field+".provider is required")
		return
	}
	if provider != RealIPProviderEdgeOne {
		*errs = append(*errs, field+".provider must be edgeone")
		return
	}
	if profile.RefreshInterval != "" {
		duration, err := realip.RefreshIntervalDuration(profile.RefreshInterval)
		if err != nil {
			*errs = append(*errs, field+"."+err.Error())
		} else if duration < time.Hour {
			*errs = append(*errs, field+".refresh_interval must be at least 1h; use an explicit refresh command for immediate synchronization")
		}
	}
	enabled := profile.IsEnabled()
	validateRealIPEdgeOne(errs, field+".edgeone", profile.EdgeOne, enabled)
}

func validateRealIPEdgeOne(errs *validationErrors, field string, edgeone RealIPEdgeOneConfig, required bool) {
	zoneID := strings.TrimSpace(edgeone.ZoneID)
	envFile := strings.TrimSpace(edgeone.EnvFile)
	if required && zoneID == "" {
		*errs = append(*errs, field+".zone_id is required when the EdgeOne realip profile is enabled")
	}
	if zoneID != "" && !isSafeEdgeOneZoneID(zoneID) {
		*errs = append(*errs, field+".zone_id must be an EdgeOne zone id such as zone-xxxxxxxx")
	}
	if required && envFile == "" {
		*errs = append(*errs, field+".env_file is required when the EdgeOne realip profile is enabled")
	}
	if envFile != "" {
		validatePathField(errs, field+".env_file", envFile, true)
	}
}

func validateNginxGoAccess(errs *validationErrors, c Config) {
	cfg := c.Nginx
	goaccess := cfg.GoAccess
	if !goaccess.Enabled && !nginxGoAccessHasFields(goaccess) {
		return
	}

	language := goaccess.EffectiveLanguage()
	switch language {
	case NginxGoAccessLanguageEnglish, NginxGoAccessLanguageSimplifiedChinese:
	default:
		*errs = append(*errs, "nginx.goaccess.language must be one of: en, zh-CN")
	}

	logFormat := goaccess.EffectiveLogFormat()
	switch logFormat {
	case NginxGoAccessLogFormatEnhanced, NginxGoAccessLogFormatCombined:
	default:
		*errs = append(*errs, "nginx.goaccess.log_format must be one of: enhanced, combined")
	}

	dashboardPath := c.NginxGoAccessDashboardPath()
	websocketPath := c.NginxGoAccessWebSocketPath()
	validateGoAccessDashboardPath(errs, "nginx.goaccess.path", dashboardPath)
	validateGoAccessWebSocketPath(errs, "nginx.goaccess.websocket_path", websocketPath)
	if dashboardPath == websocketPath {
		*errs = append(*errs, "nginx.goaccess.websocket_path must not duplicate nginx.goaccess.path")
	}
	if strings.HasSuffix(dashboardPath, "/") && strings.HasPrefix(websocketPath, dashboardPath) {
		*errs = append(*errs, "nginx.goaccess.websocket_path must not be nested under a prefix-style nginx.goaccess.path")
	}

	if goaccess.WebSocketListen != "" {
		validateGoAccessWebSocketListen(errs, goaccess.WebSocketListen)
	}
	if goaccess.AuthBasicUserFile != "" {
		validateNginxOptionalLogPath(errs, "nginx.goaccess.auth_basic_user_file", goaccess.AuthBasicUserFile, false)
	}
	for i, cidr := range goaccess.AuthCIDRAllowlist {
		field := fmt.Sprintf("nginx.goaccess.auth_cidr_allowlist[%d]", i)
		if cidr == "" {
			*errs = append(*errs, field+" is required when set")
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			*errs = append(*errs, field+" must be a valid CIDR")
		}
	}

	if !goaccess.Enabled {
		*errs = append(*errs, "nginx.goaccess.enabled must be true when nginx.goaccess fields are set")
		return
	}
	if cfg.AccessLog == "off" {
		*errs = append(*errs, "nginx.access_log must not be off when nginx.goaccess.enabled is true")
	}
	if cfg.AccessLog != "" && cfg.AccessLog != "off" && goAccessServiceIsolationHidesPath(cfg.AccessLog) {
		*errs = append(*errs, "nginx.access_log must not be under /home, /root, /run/user, /tmp, or /var/tmp when nginx.goaccess.enabled is true because the GoAccess service uses ProtectHome=true and PrivateTmp=true")
	}
	if cfg.AccessLog != "" && cfg.AccessLog != "off" && pathIsUnder(cfg.AccessLog, "/var/log/nginx") {
		*errs = append(*errs, "nginx.access_log must not be under /var/log/nginx when nginx.goaccess.enabled is true because distro logrotate commonly owns /var/log/nginx/*.log")
	}
	if goaccess.AuthBasicUserFile == "" {
		*errs = append(*errs, "nginx.goaccess.auth_basic_user_file is required when nginx.goaccess.enabled is true")
	}
	validateGoAccessStaticLocationConflicts(errs, dashboardPath, websocketPath, cfg.StaticLocations)
}

func goAccessServiceIsolationHidesPath(path string) bool {
	cleanPath := filepath.Clean(path)
	for _, root := range []string{"/home", "/root", "/run/user", "/tmp", "/var/tmp"} {
		if cleanPath == root || strings.HasPrefix(cleanPath, root+"/") {
			return true
		}
	}
	return false
}

func nginxGoAccessHasFields(cfg NginxGoAccessConfig) bool {
	return cfg.Language != "" ||
		cfg.LogFormat != "" ||
		cfg.Path != "" ||
		cfg.WebSocketPath != "" ||
		cfg.WebSocketListen != "" ||
		cfg.AuthBasicUserFile != "" ||
		len(cfg.AuthCIDRAllowlist) > 0
}

func validateGoAccessDashboardPath(errs *validationErrors, field string, path string) {
	validateNginxLocationPath(errs, field, path)
	validateGoAccessURLPath(errs, field, path)
	if strings.HasSuffix(path, "/") {
		*errs = append(*errs, field+" must not end with / because the GoAccess dashboard is served as an exact HTML report location")
	}
}

func validateGoAccessWebSocketPath(errs *validationErrors, field string, path string) {
	validateNginxLocationPath(errs, field, path)
	validateGoAccessURLPath(errs, field, path)
}

func validateGoAccessURLPath(errs *validationErrors, field string, path string) {
	if path == "" {
		return
	}
	if !goAccessURLPathPattern.MatchString(path) {
		*errs = append(*errs, field+" must be a canonical URL path using only ASCII letters, digits, slash, dot, underscore, tilde, and hyphen")
	}
	if strings.Contains(path, "//") {
		*errs = append(*errs, field+" must not contain repeated slashes")
	}
}

func browserAuthHasFields(cfg BrowserAuthConfig) bool {
	return strings.TrimSpace(cfg.AuthBasicUserFile) != "" ||
		strings.TrimSpace(cfg.Managed.CredentialID) != "" ||
		strings.TrimSpace(cfg.Managed.HtpasswdPath) != "" ||
		strings.TrimSpace(cfg.Managed.Username) != "" ||
		strings.TrimSpace(cfg.Managed.PasswordFingerprint) != ""
}

func isSafeBrowserAuthUsername(username string) bool {
	if username == "" || len(username) > 64 {
		return false
	}
	if username[0] == '-' {
		return false
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func pathUnderRoot(path string, root string) bool {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	cleanRoot := filepath.Clean(root)
	return cleanPath == cleanRoot || strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator))
}

func pathIsChildOfRoot(path string, root string) bool {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	cleanRoot := filepath.Clean(root)
	return strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator))
}

func validateGoAccessWebSocketListen(errs *validationErrors, listen string) {
	host, portString, err := net.SplitHostPort(listen)
	if err != nil {
		*errs = append(*errs, "nginx.goaccess.websocket_listen must be in host:port format")
		return
	}
	if !isLoopbackIPLiteralHost(host) {
		*errs = append(*errs, "nginx.goaccess.websocket_listen must use a loopback IP such as 127.0.0.1 or ::1")
	}
	port, ok := validatePort(errs, "nginx.goaccess.websocket_listen", portString)
	if !ok {
		return
	}
	if isReservedLanpanelPort(port) {
		*errs = append(*errs, "nginx.goaccess.websocket_listen must not reuse Lanpanel, Headscale, Nginx, or Tailscale reserved ports")
	}
}

func validateGoAccessAppListenConflict(errs *validationErrors, c Config) {
	if !c.Nginx.GoAccess.Enabled || c.App.Listen == "" {
		return
	}
	appHost, appPortString, err := net.SplitHostPort(c.App.Listen)
	if err != nil {
		return
	}
	appPort, err := strconv.Atoi(appPortString)
	if err != nil {
		return
	}
	websocketListen := EffectiveNginxGoAccessWebSocketListen(c.App.Name, c.Nginx.GoAccess)
	goAccessHost, goAccessPortString, err := net.SplitHostPort(websocketListen)
	if err != nil {
		return
	}
	goAccessPort, err := strconv.Atoi(goAccessPortString)
	if err != nil {
		return
	}
	if appPort == goAccessPort && listenHostsOverlap(appHost, goAccessHost) {
		*errs = append(*errs, "nginx.goaccess.websocket_listen must not overlap app.listen bind host and port")
	}
}

func listenHostsOverlap(left string, right string) bool {
	left = normalizeListenHost(left)
	right = normalizeListenHost(right)
	if left == "" || right == "" {
		return true
	}
	if left == "*" || right == "*" {
		return true
	}
	if listenHostIsWildcard(left) {
		return listenWildcardOverlapsHost(left, right)
	}
	if listenHostIsWildcard(right) {
		return listenWildcardOverlapsHost(right, left)
	}
	if left == right {
		return true
	}
	if left == "localhost" {
		return listenHostIsLoopback(right)
	}
	if right == "localhost" {
		return listenHostIsLoopback(left)
	}
	leftIP := net.ParseIP(left)
	rightIP := net.ParseIP(right)
	return leftIP != nil && rightIP != nil && leftIP.Equal(rightIP)
}

func listenWildcardOverlapsHost(wildcard string, host string) bool {
	switch wildcard {
	case "0.0.0.0":
		return listenHostIsIPv4(host) || host == "localhost"
	case "::":
		return true
	default:
		return true
	}
}

func listenHostIsIPv4(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

func listenHostIsIPv6(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

func normalizeListenHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if zoneIndex := strings.Index(host, "%"); zoneIndex >= 0 {
		host = host[:zoneIndex]
	}
	return host
}

func listenHostIsWildcard(host string) bool {
	switch host {
	case "*", "0.0.0.0", "::":
		return true
	default:
		return false
	}
}

func listenHostIsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && !ip.IsUnspecified()
}

func validateGoAccessPathConflicts(errs *validationErrors, c Config) {
	if !c.Nginx.GoAccess.Enabled {
		return
	}
	appName := c.ResourceName()
	if appName == "" {
		return
	}
	canonicalAccessLog := goAccessCanonicalAccessLogPath(c)
	validateGoAccessErrorLogPathConflicts(errs, c, canonicalAccessLog)
	validateGoAccessCanonicalAccessLogPathConflicts(errs, c, canonicalAccessLog)

	authFile := strings.TrimSpace(c.Nginx.GoAccess.AuthBasicUserFile)
	if authFile == "" {
		return
	}
	browserAuthFile := strings.TrimSpace(c.BrowserAuthUserFile())
	if browserAuthFile != "" && cleanPathEqual(authFile, browserAuthFile) {
		*errs = append(*errs, "nginx.goaccess.auth_basic_user_file must not equal access.browser_auth auth_basic_user_file or managed htpasswd_path")
		return
	}
	if pathIsUnder(authFile, browserAuthManagedRoot) {
		*errs = append(*errs, "nginx.goaccess.auth_basic_user_file must not be under LanPanel-managed browser auth directory")
		return
	}
	validateGoAccessAuthFileAppEtcPath(errs, c, authFile)
	for _, forbidden := range goAccessManagedArtifactPaths(c, canonicalAccessLog) {
		if cleanPathEqual(authFile, forbidden.path) {
			*errs = append(*errs, "nginx.goaccess.auth_basic_user_file must not point to Lanpanel-managed "+forbidden.label+" path")
			return
		}
	}
	reportDir := filepath.Join("/var/lib", c.ResourceName(), "goaccess")
	if pathIsUnder(authFile, reportDir) {
		*errs = append(*errs, "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed GoAccess report directory")
		return
	}
	validateGoAccessAuthFileManagedRootPath(errs, c, authFile)
}

func validateGoAccessAuthFileAppEtcPath(errs *validationErrors, c Config, authFile string) {
	appEtcDir := filepath.Join("/etc", c.ResourceName())
	if !pathIsUnder(authFile, appEtcDir) {
		return
	}
	suggestedPath := filepath.Join(appEtcDir, "goaccess.htpasswd")
	if cleanPathEqual(authFile, suggestedPath) {
		return
	}
	*errs = append(*errs, "nginx.goaccess.auth_basic_user_file under /etc/"+c.ResourceName()+" must be the direct "+suggestedPath+" bootstrap path")
}

func validateGoAccessAuthFileManagedRootPath(errs *validationErrors, c Config, authFile string) {
	suggestedPath := filepath.Join("/etc", c.ResourceName(), "goaccess.htpasswd")
	if cleanPathEqual(authFile, suggestedPath) {
		return
	}
	for _, root := range goAccessManagedRootPaths(c) {
		if pathIsUnder(authFile, root.path) {
			label := root.label
			if !strings.HasSuffix(label, "directory") {
				label += " directory"
			}
			*errs = append(*errs, "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed "+label)
			return
		}
	}
	if pathIsUnder(authFile, "/var/log/lanpanel/apps") {
		*errs = append(*errs, "nginx.goaccess.auth_basic_user_file must not be under Lanpanel-managed app log namespace")
		return
	}
}

func validateGoAccessErrorLogPathConflicts(errs *validationErrors, c Config, canonicalAccessLog string) {
	errorLog := strings.TrimSpace(c.Nginx.ErrorLog)
	if errorLog == "" {
		return
	}
	if cleanPathEqual(errorLog, canonicalAccessLog) {
		*errs = append(*errs, "nginx.error_log must not equal the GoAccess canonical access log")
		return
	}
	authFile := strings.TrimSpace(c.Nginx.GoAccess.AuthBasicUserFile)
	if authFile != "" && cleanPathEqual(errorLog, authFile) {
		*errs = append(*errs, "nginx.error_log must not equal nginx.goaccess.auth_basic_user_file")
		return
	}
	for _, forbidden := range goAccessManagedArtifactPaths(c, canonicalAccessLog) {
		if forbidden.label == "GoAccess canonical access log" {
			continue
		}
		if cleanPathEqual(errorLog, forbidden.path) {
			*errs = append(*errs, "nginx.error_log must not point to Lanpanel-managed "+forbidden.label+" path")
			return
		}
	}
	reportDir := filepath.Join("/var/lib", c.ResourceName(), "goaccess")
	if pathIsUnder(errorLog, reportDir) {
		*errs = append(*errs, "nginx.error_log must not be under Lanpanel-managed GoAccess report directory")
		return
	}
	for _, root := range goAccessManagedRootPaths(c) {
		if pathIsUnder(errorLog, root.path) {
			*errs = append(*errs, "nginx.error_log must not be under Lanpanel-managed "+root.label+" directory")
			return
		}
	}
	if pathIsUnder(errorLog, "/var/log/lanpanel/apps") {
		*errs = append(*errs, "nginx.error_log must not be under Lanpanel-managed app log namespace")
		return
	}
}

func validateGoAccessCanonicalAccessLogPathConflicts(errs *validationErrors, c Config, canonicalAccessLog string) {
	accessLog := strings.TrimSpace(c.Nginx.AccessLog)
	if accessLog == "" || accessLog == "off" {
		return
	}
	lanpanelAppsLogRoot := "/var/log/lanpanel/apps"
	currentAppLogDir := filepath.Join(lanpanelAppsLogRoot, c.ResourceName())
	currentAppManagedLog := filepath.Join(currentAppLogDir, "access.log")
	if cleanPathEqual(canonicalAccessLog, currentAppLogDir) {
		*errs = append(*errs, "nginx.access_log must be a file under the Lanpanel-managed GoAccess log directory, not the directory itself")
		return
	}
	if pathIsUnder(canonicalAccessLog, lanpanelAppsLogRoot) && !pathIsUnder(canonicalAccessLog, currentAppLogDir) {
		*errs = append(*errs, "nginx.access_log under /var/log/lanpanel/apps must stay under the current app log directory")
		return
	}
	if pathIsUnder(canonicalAccessLog, currentAppLogDir) && !cleanPathEqual(canonicalAccessLog, currentAppManagedLog) {
		*errs = append(*errs, "nginx.access_log under the Lanpanel-managed GoAccess log directory must be the direct access.log file")
		return
	}
	authFile := strings.TrimSpace(c.Nginx.GoAccess.AuthBasicUserFile)
	if authFile != "" && cleanPathEqual(canonicalAccessLog, authFile) {
		*errs = append(*errs, "nginx.access_log must not equal nginx.goaccess.auth_basic_user_file")
		return
	}
	for _, forbidden := range goAccessManagedArtifactPaths(c, canonicalAccessLog) {
		if forbidden.label == "GoAccess canonical access log" {
			continue
		}
		if cleanPathEqual(canonicalAccessLog, forbidden.path) {
			*errs = append(*errs, "nginx.access_log must not point to Lanpanel-managed "+forbidden.label+" path")
			return
		}
	}
	reportDir := filepath.Join("/var/lib", c.ResourceName(), "goaccess")
	if pathIsUnder(canonicalAccessLog, reportDir) {
		*errs = append(*errs, "nginx.access_log must not be under Lanpanel-managed GoAccess report directory")
		return
	}
	if cleanPathEqual(canonicalAccessLog, currentAppManagedLog) {
		return
	}
	for _, root := range goAccessManagedRootPaths(c) {
		if pathIsUnder(canonicalAccessLog, root.path) {
			*errs = append(*errs, "nginx.access_log must not be under Lanpanel-managed "+root.label+" directory")
			return
		}
	}
}

type goAccessManagedPath struct {
	label string
	path  string
}

func goAccessCanonicalAccessLogPath(c Config) string {
	return c.NginxGoAccessCanonicalAccessLogPath()
}

func goAccessManagedArtifactPaths(c Config, canonicalAccessLog string) []goAccessManagedPath {
	appName := c.ResourceName()
	primaryDomain := c.PrimaryDomain()
	varLibDir := filepath.Join("/var/lib", appName)
	etcDir := filepath.Join("/etc", appName)
	hookDir := filepath.Join("/usr/local/lib/lanpanel/apps", appName)
	goAccessReportDir := filepath.Join(varLibDir, "goaccess")
	paths := []goAccessManagedPath{
		{label: "Nginx site", path: filepath.Join("/etc/nginx/sites-available", appName+".conf")},
		{label: "Nginx enabled site", path: filepath.Join("/etc/nginx/sites-enabled", appName+".conf")},
		{label: "app service", path: filepath.Join("/etc/systemd/system", appName+".service")},
		{label: "lego renew service", path: filepath.Join("/etc/systemd/system", appName+"-lego-renew.service")},
		{label: "lego renew timer", path: filepath.Join("/etc/systemd/system", appName+"-lego-renew.timer")},
		{label: "deploy hook", path: filepath.Join(hookDir, "install-cert-and-reload-nginx.sh")},
		{label: "app var marker", path: filepath.Join(varLibDir, ".lanpanel-managed")},
		{label: "app etc marker", path: filepath.Join(etcDir, ".lanpanel-managed")},
		{label: "app hook marker", path: filepath.Join(hookDir, ".lanpanel-managed")},
		{label: "GoAccess config", path: filepath.Join(etcDir, "goaccess.conf")},
		{label: "GoAccess service", path: filepath.Join("/etc/systemd/system", appName+"-goaccess.service")},
		{label: "GoAccess logrotate", path: filepath.Join("/etc/logrotate.d", appName+"-goaccess")},
		{label: "GoAccess report directory", path: goAccessReportDir},
		{label: "GoAccess report", path: filepath.Join(goAccessReportDir, "report.html")},
		{label: "GoAccess db", path: filepath.Join(goAccessReportDir, "db")},
		{label: "GoAccess canonical access log", path: canonicalAccessLog},
		{label: "GoAccess log marker", path: filepath.Join("/var/log/lanpanel/apps", appName, ".lanpanel-managed")},
	}
	if primaryDomain != "" {
		tlsDir := filepath.Join(etcDir, "tls", primaryDomain)
		paths = append(paths,
			goAccessManagedPath{label: "TLS marker", path: filepath.Join(tlsDir, ".lanpanel-managed")},
			goAccessManagedPath{label: "TLS fullchain", path: filepath.Join(tlsDir, "fullchain.pem")},
			goAccessManagedPath{label: "TLS private key", path: filepath.Join(tlsDir, "privkey.pem")},
		)
	}
	return paths
}

func goAccessManagedRootPaths(c Config) []goAccessManagedPath {
	appName := c.ResourceName()
	return []goAccessManagedPath{
		{label: "app var root", path: filepath.Join("/var/lib", appName)},
		{label: "app etc root", path: filepath.Join("/etc", appName)},
		{label: "app hook root", path: filepath.Join("/usr/local/lib/lanpanel/apps", appName)},
		{label: "GoAccess log directory", path: filepath.Join("/var/log/lanpanel/apps", appName)},
	}
}

func cleanPathEqual(left string, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func pathIsUnder(path string, root string) bool {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	return cleanPath == cleanRoot || strings.HasPrefix(cleanPath, cleanRoot+"/")
}

func validateGoAccessStaticLocationConflicts(errs *validationErrors, dashboardPath string, websocketPath string, locations []NginxStaticLocationConfig) {
	for index, location := range locations {
		field := fmt.Sprintf("nginx.static_locations[%d].path", index)
		if location.Path == "" {
			continue
		}
		if goAccessPathOverlapsStaticLocation(dashboardPath, location) {
			*errs = append(*errs, "nginx.goaccess.path must not overlap "+field)
		}
		if goAccessPathOverlapsStaticLocation(websocketPath, location) {
			*errs = append(*errs, "nginx.goaccess.websocket_path must not overlap "+field)
		}
	}
}

func goAccessPathOverlapsStaticLocation(path string, location NginxStaticLocationConfig) bool {
	if location.Path == "" {
		return false
	}
	match := location.Match
	if match == "" {
		match = "prefix"
	}
	if match == "exact" {
		return path == location.Path
	}
	return strings.HasPrefix(pathWithTrailingSlash(path), location.Path) ||
		strings.HasPrefix(pathWithTrailingSlash(location.Path), pathWithTrailingSlash(path))
}

func pathWithTrailingSlash(path string) string {
	if strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}

func validateNginxProxy(errs *validationErrors, proxy NginxProxyConfig) {
	if proxy.ConnectTimeout != "" && !nginxTimeValuePattern.MatchString(proxy.ConnectTimeout) {
		*errs = append(*errs, "nginx.proxy.connect_timeout must be a simple nginx time such as 30s")
	}
	if proxy.ReadTimeout != "" && !nginxTimeValuePattern.MatchString(proxy.ReadTimeout) {
		*errs = append(*errs, "nginx.proxy.read_timeout must be a simple nginx time such as 600s")
	}
	if proxy.SendTimeout != "" && !nginxTimeValuePattern.MatchString(proxy.SendTimeout) {
		*errs = append(*errs, "nginx.proxy.send_timeout must be a simple nginx time such as 600s")
	}
}

func validateNginxOptionalLogPath(errs *validationErrors, field string, path string, allowOff bool) {
	if path == "" {
		return
	}
	if allowOff && path == "off" {
		return
	}
	validateNginxDirectivePath(errs, field, path, true)
}

func validateNginxDirectivePath(errs *validationErrors, field string, path string, requireAbs bool) {
	if !filepath.IsAbs(path) {
		if requireAbs {
			*errs = append(*errs, field+" must be an absolute path when set")
		}
		return
	}
	if filepath.Clean(path) != path {
		*errs = append(*errs, field+" must be a clean absolute path without . or .. segments")
	}
	if containsControlOrSpace(path) || strings.ContainsAny(path, "#*?[]%\"'\\;{}$") {
		*errs = append(*errs, field+" must not contain whitespace, comment, glob, specifier, quote, escape, variable, semicolon, brace, or control characters")
	}
}

func validateNginxLocationPath(errs *validationErrors, field string, path string) {
	if path == "" {
		*errs = append(*errs, field+" is required")
		return
	}
	if !strings.HasPrefix(path, "/") {
		*errs = append(*errs, field+" must start with /")
		return
	}
	if path == "/" {
		*errs = append(*errs, field+" must not be / because location / is reserved for the app proxy")
	}
	if nginxPathOverlapsACMEChallenge(path) {
		*errs = append(*errs, field+" must not overlap /.well-known/acme-challenge/")
	}
	if containsDotPathSegment(path) {
		*errs = append(*errs, field+" must not contain . or .. path segments")
	}
	if containsControlOrSpace(path) || strings.ContainsAny(path, "#\"'\\;{}$") {
		*errs = append(*errs, field+" must not contain whitespace, comments, quotes, escapes, variables, semicolons, braces, or control characters")
	}
}

func validateNginxAliasPath(errs *validationErrors, field string, path string) {
	if path == "" {
		*errs = append(*errs, field+" is required")
		return
	}
	if !filepath.IsAbs(path) {
		*errs = append(*errs, field+" must be an absolute path")
		return
	}
	cleanTarget := strings.TrimRight(path, "/")
	if cleanTarget == "" {
		*errs = append(*errs, field+" must be an absolute path")
		return
	}
	if filepath.Clean(cleanTarget) != cleanTarget {
		*errs = append(*errs, field+" must be a clean absolute path without . or .. segments")
	}
	if containsControlOrSpace(path) || strings.ContainsAny(path, "#*?[]%\"'\\;{}$") {
		*errs = append(*errs, field+" must not contain whitespace, comment, glob, specifier, quote, escape, variable, semicolon, brace, or control characters")
	}
}

func validateNginxQuotedValue(errs *validationErrors, field string, value string) {
	if containsControl(value) || strings.ContainsAny(value, "\"'\\;{}$") {
		*errs = append(*errs, field+" must not contain quotes, escapes, variables, semicolons, braces, or control characters")
	}
}

func nginxPathOverlapsACMEChallenge(path string) bool {
	const challengePath = "/.well-known/acme-challenge/"
	return strings.HasPrefix(path, challengePath) || strings.HasPrefix(challengePath, path)
}

func containsDotPathSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func containsControlOrSpace(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func validateDNS01(errs *validationErrors, challenge string, dns01 DNS01Config) {
	provider := strings.TrimSpace(dns01.Provider)
	envFile := strings.TrimSpace(dns01.EnvFile)
	var providerInfo acme.DNSProviderInfo
	providerValid := false

	if challenge == ACMEChallengeDNS01 && provider == "" {
		*errs = append(*errs, "dns01.provider is required when app.acme_challenge is dns-01")
	}
	if provider != "" {
		info, err := acme.DNSProvider(provider)
		if err != nil {
			*errs = append(*errs, err.Error())
		} else {
			providerInfo = info
			providerValid = true
		}
	}
	if envFile != "" && provider == "" {
		*errs = append(*errs, "dns01.provider is required when dns01.env_file is set")
	}
	if envFile != "" {
		validatePathField(errs, "dns01.env_file", envFile, true)
	}
	if challenge == ACMEChallengeDNS01 && providerValid && envFile == "" && providerInfo.EnvFileRequired {
		*errs = append(*errs, "dns01.env_file is required for DNS-01 renewal with lego DNS provider "+providerInfo.LegoCode)
	}
}

func validateTailscale(errs *validationErrors, c Config) {
	if c.Tailscale.LoginServer != "" {
		validateLoginServer(errs, c.Tailscale.LoginServer)
		validateLoginServerDoesNotReuseAppDomain(errs, c.Tailscale.LoginServer, c.App.Domains)
		if c.Tailscale.LanpanelConfig != "" {
			*errs = append(*errs, "tailscale.lanpanel_config must be empty when tailscale.login_server is set")
		}
	}
	if c.Tailscale.LanpanelConfig != "" {
		validateConfigPathField(errs, "tailscale.lanpanel_config", c.Tailscale.LanpanelConfig)
	}
	if c.Tailscale.Hostname != "" && !isSafeHostname(c.Tailscale.Hostname) {
		*errs = append(*errs, "tailscale.hostname must contain only lowercase letters, digits, and hyphens, and must not start or end with a hyphen")
	}
	if c.Tailscale.AuthKeyFile != "" {
		validatePathField(errs, "tailscale.auth_key_file", c.Tailscale.AuthKeyFile, true)
	}
}

func validateLoginServer(errs *validationErrors, raw string) {
	parsedURL, err := url.Parse(raw)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("tailscale.login_server must be a valid URL: %v", err))
		return
	}
	if parsedURL.Scheme != "https" {
		*errs = append(*errs, "tailscale.login_server must use https")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		*errs = append(*errs, "tailscale.login_server must be an origin URL without userinfo, query, or fragment")
	}
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		*errs = append(*errs, "tailscale.login_server must not include a path")
	}
	if parsedURL.Hostname() == "" {
		*errs = append(*errs, "tailscale.login_server host is required")
	} else if !looksLikeDNSName(normalizeDomain(parsedURL.Hostname())) {
		*errs = append(*errs, "tailscale.login_server host must be a DNS name")
	}
	if port := parsedURL.Port(); port != "" && port != "443" {
		*errs = append(*errs, "tailscale.login_server must not specify a port other than 443")
	}
}

func validateLoginServerDoesNotReuseAppDomain(errs *validationErrors, raw string, domains []string) {
	parsedURL, err := url.Parse(raw)
	if err != nil {
		return
	}
	loginHost := normalizeDomain(parsedURL.Hostname())
	if loginHost == "" {
		return
	}
	for _, domain := range domains {
		if normalizeDomain(domain) == loginHost {
			*errs = append(*errs, "tailscale.login_server host must not reuse an app domain")
			return
		}
	}
}

func validatePathField(errs *validationErrors, field string, path string, requireAbs bool) {
	if requireAbs && !filepath.IsAbs(path) {
		*errs = append(*errs, field+" must be an absolute path when set")
		return
	}
	if filepath.Clean(path) != path {
		*errs = append(*errs, field+" must be a clean path without . or .. segments")
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			*errs = append(*errs, field+" must not contain whitespace or control characters")
			break
		}
	}
	if strings.ContainsAny(path, "*?[]%\"'\\") {
		*errs = append(*errs, field+" must not contain glob, specifier, quote, or escape characters")
	}
}

func validateConfigPathField(errs *validationErrors, field string, path string) {
	if filepath.Clean(path) == "." {
		*errs = append(*errs, field+" must be a valid file path")
	}
	if containsControl(path) {
		*errs = append(*errs, field+" must not contain control characters")
	}
}

func validateListenAddress(errs *validationErrors, field string, address string) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		*errs = append(*errs, field+" must be in host:port format")
		return
	}
	if !isLoopbackHost(host) {
		*errs = append(*errs, field+" must use a loopback host such as 127.0.0.1 or ::1")
	}
	port, ok := validatePort(errs, field, portString)
	if !ok {
		return
	}
	if isReservedLanpanelPort(port) {
		*errs = append(*errs, field+" must not reuse Lanpanel, Headscale, Nginx, or Tailscale reserved ports")
	}
}

func validateUpstreamAddress(errs *validationErrors, field string, address string) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		*errs = append(*errs, field+" must be in host:port format")
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !isTailscaleIPv4(ip) {
		*errs = append(*errs, field+" must use a fixed Tailscale IPv4 address in 100.64.0.0/10")
	}
	port, ok := validatePort(errs, field, portString)
	if !ok {
		return
	}
	if isCommonDatabasePort(port) {
		*errs = append(*errs, field+" must not expose common database ports; app upstreams must be HTTP or WebSocket services")
	}
}

func validatePort(errs *validationErrors, field string, portString string) (int, bool) {
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		*errs = append(*errs, field+" port must be between 1 and 65535")
		return 0, false
	}
	return port, true
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimSuffix(value, ".")
}

func normalizeLoginServer(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsedURL, err := url.Parse(value)
	if err != nil {
		return value
	}
	if parsedURL.Scheme == "" || parsedURL.Hostname() == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return value
	}
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		return value
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	host := normalizeDomain(parsedURL.Hostname())
	port := parsedURL.Port()
	if scheme != "https" || host == "" || (port != "" && port != "443") {
		return value
	}
	return "https://" + host
}

func looksLikeDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.Contains(value, "*") {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !isSafeDNSLabel(label) {
			return false
		}
	}
	return true
}

func isSafeDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func isSafeName(value string) bool {
	return isSafeDNSLabel(value) && !strings.Contains(value, ".")
}

func isSafeAppName(value string) bool {
	return isSafeName(value) && value[0] >= 'a' && value[0] <= 'z'
}

func isSafeRealIPProfileName(value string) bool {
	return isSafeName(value) && value[0] >= 'a' && value[0] <= 'z'
}

func isSafeEdgeOneZoneID(value string) bool {
	if !strings.HasPrefix(value, "zone-") || len(value) <= len("zone-") {
		return false
	}
	for _, r := range value[len("zone-"):] {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func isSafeHostname(value string) bool {
	return isSafeName(value)
}

func isReservedAppName(name string) bool {
	switch name {
	case "adm",
		"audio",
		"backup",
		"bin",
		"bluetooth",
		"cdrom",
		"crontab",
		"daemon",
		"default",
		"dialout",
		"dip",
		"disk",
		"fax",
		"floppy",
		"games",
		"gpio",
		"gnats",
		"headscale",
		"i2c",
		"input",
		"irc",
		"kvm",
		"landscape",
		"list",
		"lp",
		"lpadmin",
		"lxd",
		"mail",
		"man",
		"messagebus",
		"lanpanel",
		"news",
		"nginx",
		"nogroup",
		"nobody",
		"operator",
		"plugdev",
		"pollinate",
		"proxy",
		"rdma",
		"render",
		"root",
		"sambashare",
		"scanner",
		"shadow",
		"spi",
		"sshd",
		"ssl-cert",
		"staff",
		"sync",
		"sys",
		"syslog",
		"sudo",
		"systemd-network",
		"systemd-resolve",
		"systemd-journal",
		"systemd-timesync",
		"tape",
		"tailscale",
		"tailscaled",
		"tty",
		"uucp",
		"users",
		"utmp",
		"uuidd",
		"video",
		"voice",
		"www-data":
		return true
	default:
		return false
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && !ip.IsUnspecified()
}

func isLoopbackIPLiteralHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && !ip.IsUnspecified()
}

func isTailscaleIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

func isReservedLanpanelPort(port int) bool {
	switch port {
	case 80, 443, 3478, 8080, 50443, 19090:
		return true
	default:
		return false
	}
}

func isCommonDatabasePort(port int) bool {
	switch port {
	case 3306, 5432, 5433, 6379, 6380, 9200, 9300, 27017:
		return true
	default:
		return false
	}
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
