package appsvc

import (
	"fmt"
	"hash/fnv"
	"lanpanel/internal/appconfig"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	LegoBinaryPath     = "/opt/lanpanel/bin/lego"
	GoAccessBinaryPath = "/usr/bin/goaccess"

	linuxUserNameMaxLen = 32
)

type Names struct {
	AppName            string
	VarPrefix          string
	SystemUser         string
	SystemGroup        string
	ServiceUnit        string
	RenewServiceUnit   string
	RenewTimerUnit     string
	VarLibDir          string
	EtcDir             string
	HookDir            string
	NginxAvailablePath string
	NginxEnabledPath   string
	WebrootPath        string
	LegoDataPath       string
	TLSDir             string
	VarLibMarkerPath   string
	EtcMarkerPath      string
	HookDirMarkerPath  string
	FullchainPath      string
	PrivateKeyPath     string
	TLSMarkerPath      string
	HookPath           string

	GoAccessSystemUser                 string
	GoAccessSystemGroup                string
	GoAccessServiceUnit                string
	GoAccessConfigPath                 string
	GoAccessReportDir                  string
	GoAccessReportPath                 string
	GoAccessDBPath                     string
	GoAccessLogDir                     string
	GoAccessLogDirMarkerPath           string
	GoAccessCanonicalAccessLogPath     string
	GoAccessLogrotatePath              string
	GoAccessSuggestedAuthBasicUserFile string
	BrowserSuggestedAuthBasicUserFile  string
	GoAccessWebSocketHost              string
	GoAccessWebSocketPort              int
	GoAccessWebSocketListen            string
	GoAccessNginxLogFormatName         string
	RealIPRejectionLogPath             string
	RealIPRejectionLogFormatName       string
}

type RealIPProfileNames struct {
	ProfileName         string
	Provider            string
	SystemdName         string
	NginxDir            string
	NginxIncludePath    string
	TrustedCIDRPath     string
	StateDir            string
	StatePath           string
	ReferenceDir        string
	ReferencePathForApp string
	MetadataPath        string
	RefreshServiceUnit  string
	RefreshTimerUnit    string
	RefreshServicePath  string
	RefreshTimerPath    string
}

func NewNames(cfg appconfig.Config) (Names, error) {
	if cfg.PrivateClientAccessEnabled() {
		return Names{}, fmt.Errorf("app service names are not available for private_client resources in P0")
	}
	if err := cfg.ValidateForExposurePlan(); err != nil {
		return Names{}, err
	}
	appName := cfg.ResourceName()
	primaryDomain := cfg.PrimaryDomain()
	if appName == "" || primaryDomain == "" {
		return Names{}, fmt.Errorf("app name and primary domain are required")
	}

	varLibDir := filepath.Join("/var/lib", appName)
	etcDir := filepath.Join("/etc", appName)
	hookDir := filepath.Join("/usr/local/lib/lanpanel/apps", appName)
	tlsDir := filepath.Join(etcDir, "tls", primaryDomain)
	goAccessReportDir := filepath.Join(varLibDir, "goaccess")
	goAccessLogDir := filepath.Join("/var/log/lanpanel/apps", appName)
	goAccessWebSocketHost, goAccessWebSocketPort, err := goAccessWebSocketListenParts(cfg)
	if err != nil {
		return Names{}, err
	}
	return Names{
		AppName:            appName,
		VarPrefix:          strings.ReplaceAll(appName, "-", "_"),
		SystemUser:         appName,
		SystemGroup:        appName,
		ServiceUnit:        appName + ".service",
		RenewServiceUnit:   appName + "-lego-renew.service",
		RenewTimerUnit:     appName + "-lego-renew.timer",
		VarLibDir:          varLibDir,
		EtcDir:             etcDir,
		HookDir:            hookDir,
		NginxAvailablePath: filepath.Join("/etc/nginx/sites-available", appName+".conf"),
		NginxEnabledPath:   filepath.Join("/etc/nginx/sites-enabled", appName+".conf"),
		WebrootPath:        filepath.Join(varLibDir, "acme-challenges"),
		LegoDataPath:       filepath.Join(varLibDir, "lego"),
		TLSDir:             tlsDir,
		VarLibMarkerPath:   filepath.Join(varLibDir, ".lanpanel-managed"),
		EtcMarkerPath:      filepath.Join(etcDir, ".lanpanel-managed"),
		HookDirMarkerPath:  filepath.Join(hookDir, ".lanpanel-managed"),
		FullchainPath:      filepath.Join(tlsDir, "fullchain.pem"),
		PrivateKeyPath:     filepath.Join(tlsDir, "privkey.pem"),
		TLSMarkerPath:      filepath.Join(tlsDir, ".lanpanel-managed"),
		HookPath:           filepath.Join(hookDir, "install-cert-and-reload-nginx.sh"),

		GoAccessSystemUser:                 goAccessIdentityName(appName),
		GoAccessSystemGroup:                goAccessIdentityName(appName),
		GoAccessServiceUnit:                appName + "-goaccess.service",
		GoAccessConfigPath:                 filepath.Join(etcDir, "goaccess.conf"),
		GoAccessReportDir:                  goAccessReportDir,
		GoAccessReportPath:                 filepath.Join(goAccessReportDir, "report.html"),
		GoAccessDBPath:                     filepath.Join(goAccessReportDir, "db"),
		GoAccessLogDir:                     goAccessLogDir,
		GoAccessLogDirMarkerPath:           filepath.Join(goAccessLogDir, ".lanpanel-managed"),
		GoAccessCanonicalAccessLogPath:     GoAccessCanonicalAccessLogPath(cfg),
		GoAccessLogrotatePath:              filepath.Join("/etc/logrotate.d", appName+"-goaccess"),
		GoAccessSuggestedAuthBasicUserFile: filepath.Join(etcDir, "goaccess.htpasswd"),
		BrowserSuggestedAuthBasicUserFile:  filepath.Join(etcDir, "browser.htpasswd"),
		GoAccessWebSocketHost:              goAccessWebSocketHost,
		GoAccessWebSocketPort:              goAccessWebSocketPort,
		GoAccessWebSocketListen:            net.JoinHostPort(goAccessWebSocketHost, strconv.Itoa(goAccessWebSocketPort)),
		GoAccessNginxLogFormatName:         "lanpanel_app_" + strings.ReplaceAll(appName, "-", "_") + "_enhanced",
		RealIPRejectionLogPath:             filepath.Join("/var/log/nginx", appName+"-realip-rejections.log"),
		RealIPRejectionLogFormatName:       "lanpanel_app_" + strings.ReplaceAll(appName, "-", "_") + "_realip_rejection",
	}, nil
}

func NewRealIPProfileNames(profileName string, provider string, appName string) (RealIPProfileNames, error) {
	profileName = strings.TrimSpace(profileName)
	provider = strings.TrimSpace(provider)
	appName = strings.TrimSpace(appName)
	if !isSafeRealIPName(profileName) {
		return RealIPProfileNames{}, fmt.Errorf("realip profile name %q is not safe for paths or systemd units", profileName)
	}
	if provider != appconfig.RealIPProviderEdgeOne {
		return RealIPProfileNames{}, fmt.Errorf("realip provider %q is not supported", provider)
	}
	if appName != "" && !isSafeRealIPName(appName) {
		return RealIPProfileNames{}, fmt.Errorf("app name %q is not safe for realip reference paths", appName)
	}
	systemdName := "lanpanel-realip-" + profileName
	nginxDir := filepath.Join("/etc/nginx/lanpanel/realip", profileName)
	stateDir := filepath.Join("/var/lib/lanpanel/realip", profileName)
	referenceDir := filepath.Join(stateDir, "references")
	referencePath := ""
	if appName != "" {
		referencePath = filepath.Join(referenceDir, appName+".json")
	}
	return RealIPProfileNames{
		ProfileName:         profileName,
		Provider:            provider,
		SystemdName:         systemdName,
		NginxDir:            nginxDir,
		NginxIncludePath:    filepath.Join(nginxDir, "active.conf"),
		TrustedCIDRPath:     filepath.Join(nginxDir, "trusted-cidrs.conf"),
		StateDir:            stateDir,
		StatePath:           filepath.Join(stateDir, "state.json"),
		ReferenceDir:        referenceDir,
		ReferencePathForApp: referencePath,
		MetadataPath:        filepath.Join(stateDir, "profile.json"),
		RefreshServiceUnit:  systemdName + "-refresh.service",
		RefreshTimerUnit:    systemdName + "-refresh.timer",
		RefreshServicePath:  filepath.Join("/etc/systemd/system", systemdName+"-refresh.service"),
		RefreshTimerPath:    filepath.Join("/etc/systemd/system", systemdName+"-refresh.timer"),
	}, nil
}

func GoAccessCanonicalAccessLogPath(cfg appconfig.Config) string {
	return cfg.NginxGoAccessCanonicalAccessLogPath()
}

func GoAccessManagesCanonicalAccessLog(cfg appconfig.Config) bool {
	return cfg.NginxGoAccessManagesCanonicalAccessLog()
}

func goAccessWebSocketListenParts(cfg appconfig.Config) (string, int, error) {
	listen := appconfig.EffectiveNginxGoAccessWebSocketListen(cfg.ResourceName(), cfg.Nginx.GoAccess)
	host, portString, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, fmt.Errorf("parse GoAccess websocket listen %q: %w", listen, err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return "", 0, fmt.Errorf("parse GoAccess websocket listen port %q: %w", portString, err)
	}
	return host, port, nil
}

func goAccessIdentityName(appName string) string {
	const prefix = "lanpanel-goaccess-"
	if len(prefix)+len(appName) <= linuxUserNameMaxLen {
		return prefix + appName
	}

	hash := fnv.New32a()
	_, _ = hash.Write([]byte(appName))
	suffix := fmt.Sprintf("%08x", hash.Sum32())
	const shortPrefix = "mga-"
	headLen := linuxUserNameMaxLen - len(shortPrefix) - len("-") - len(suffix)
	if headLen > len(appName) {
		headLen = len(appName)
	}
	return shortPrefix + appName[:headLen] + "-" + suffix
}

func isSafeRealIPName(value string) bool {
	if value == "" || len(value) > 63 || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return false
	}
	if value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
