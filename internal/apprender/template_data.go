package apprender

import (
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/components/appsvc"
	"strconv"
	"strings"
)

type TemplateData struct {
	AppName           string
	VarPrefix         string
	Domains           []string
	ServerNames       string
	PrimaryDomain     string
	CertificateEmail  string
	ACMEChallenge     string
	DNSProvider       string
	DNSEnvFile        string
	UpstreamAddress   string
	SystemUser        string
	SystemGroup       string
	ExecStart         string
	WorkingDirectory  string
	ServiceEnvFile    string
	HTTP2             bool
	ClientMaxBodySize string
	AccessLog         string
	ErrorLog          string
	Access            AccessTemplateData
	GoAccess          GoAccessTemplateData
	Proxy             ProxyTemplateData
	RealIP            RealIPTemplateData
	StaticLocations   []StaticLocationTemplateData
	WebrootPath       string
	LegoDataPath      string
	TLSDir            string
	FullchainPath     string
	PrivateKeyPath    string
	TLSMarkerPath     string
	HookPath          string
}

type AccessTemplateData struct {
	Mode              string
	Browser           bool
	Public            bool
	AuthBasicUserFile string
	CIDRAllowlist     []string
}

type GoAccessTemplateData struct {
	Enabled                    bool
	BinaryPath                 string
	Language                   string
	LogFormat                  string
	EnhancedLogFormat          bool
	CombinedLogFormat          bool
	NginxLogFormatName         string
	CanonicalAccessLogPath     string
	ManagedCanonicalAccessLog  bool
	DashboardPath              string
	WebSocketPath              string
	WebSocketHost              string
	WebSocketPort              int
	WebSocketListen            string
	WebSocketUpstream          string
	AuthBasicUserFile          string
	AuthCIDRAllowlist          []string
	ConfigPath                 string
	ReportDir                  string
	ReportPath                 string
	DBPath                     string
	ServiceUnit                string
	SystemUser                 string
	SystemGroup                string
	DashboardURL               string
	WSURL                      string
	Origin                     string
	HTMLReportTitle            string
	Lang                       string
	LCMessages                 string
	LCCType                    string
	LCTime                     string
	GoAccessLogFormatDirective string
}

type ProxyTemplateData struct {
	ConnectTimeout      string
	ReadTimeout         string
	SendTimeout         string
	BufferingSet        bool
	Buffering           string
	RequestBufferingSet bool
	RequestBuffering    string
}

type RealIPTemplateData struct {
	Enabled                bool
	ProfileName            string
	Provider               string
	Header                 string
	NginxIncludePath       string
	TrustedCIDRPath        string
	RejectionLogPath       string
	RejectionLogFormatName string
	OriginalSourceVariable string
	SourceTrustedVariable  string
	HeaderIsIPVariable     string
	HeaderPublicVariable   string
	RejectReasonVariable   string
	RejectLogVariable      string
}

type StaticLocationTemplateData struct {
	Exact        bool
	Path         string
	Alias        string
	DefaultType  string
	Expires      string
	CacheControl string
	TryFiles     bool
	GzipStatic   bool
	AccessLogOff bool
}

func NewTemplateData(cfg appconfig.Config) (TemplateData, error) {
	if err := cfg.ValidateForExposurePlan(); err != nil {
		return TemplateData{}, err
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		return TemplateData{}, err
	}
	dnsProvider := strings.TrimSpace(cfg.DNS01.Provider)
	if cfg.App.ACMEChallenge == appconfig.ACMEChallengeDNS01 && dnsProvider != "" {
		canonical, err := acme.CanonicalDNSProvider(dnsProvider)
		if err != nil {
			return TemplateData{}, err
		}
		dnsProvider = canonical
	}
	upstream := cfg.App.Listen
	if cfg.Mode() == appconfig.ModeUpstream {
		upstream = cfg.App.Upstream
	}
	realIP, err := realIPTemplateData(cfg, names)
	if err != nil {
		return TemplateData{}, err
	}
	return TemplateData{
		AppName:           names.AppName,
		VarPrefix:         names.VarPrefix,
		Domains:           append([]string(nil), cfg.App.Domains...),
		ServerNames:       strings.Join(cfg.App.Domains, " "),
		PrimaryDomain:     cfg.PrimaryDomain(),
		CertificateEmail:  cfg.App.CertificateEmail,
		ACMEChallenge:     cfg.App.ACMEChallenge,
		DNSProvider:       dnsProvider,
		DNSEnvFile:        cfg.DNS01.EnvFile,
		UpstreamAddress:   upstream,
		SystemUser:        names.SystemUser,
		SystemGroup:       names.SystemGroup,
		ExecStart:         cfg.Service.ExecStart,
		WorkingDirectory:  cfg.Service.WorkingDirectory,
		ServiceEnvFile:    cfg.Service.EnvFile,
		HTTP2:             cfg.Nginx.HTTP2Enabled(),
		ClientMaxBodySize: cfg.Nginx.EffectiveClientMaxBodySize(),
		AccessLog:         nginxAccessLogPath(cfg),
		ErrorLog:          cfg.Nginx.ErrorLog,
		Access:            accessTemplateData(cfg),
		GoAccess:          goAccessTemplateData(cfg, names),
		Proxy:             proxyTemplateData(cfg.Nginx.Proxy),
		RealIP:            realIP,
		StaticLocations:   staticLocationTemplateData(cfg.Nginx.StaticLocations),
		WebrootPath:       names.WebrootPath,
		LegoDataPath:      names.LegoDataPath,
		TLSDir:            names.TLSDir,
		FullchainPath:     names.FullchainPath,
		PrivateKeyPath:    names.PrivateKeyPath,
		TLSMarkerPath:     names.TLSMarkerPath,
		HookPath:          names.HookPath,
	}, nil
}

func accessTemplateData(cfg appconfig.Config) AccessTemplateData {
	return AccessTemplateData{
		Mode:              string(cfg.Access.AccessMode),
		Browser:           cfg.Access.AccessMode == appconfig.AccessModeBrowser,
		Public:            cfg.Access.AccessMode == appconfig.AccessModePublic,
		AuthBasicUserFile: cfg.BrowserAuthUserFile(),
		CIDRAllowlist:     append([]string(nil), cfg.Access.CIDRAllowlist...),
	}
}

func realIPTemplateData(cfg appconfig.Config, names appsvc.Names) (RealIPTemplateData, error) {
	profileName := cfg.EffectiveRealIPProfileName()
	if profileName == "" || !cfg.RealIPEnabled() {
		return RealIPTemplateData{}, nil
	}
	profile, ok := cfg.RealIPProfile(profileName)
	if !ok {
		return RealIPTemplateData{}, fmt.Errorf("realip profile %q is missing", profileName)
	}
	realIPNames, err := appsvc.NewRealIPProfileNames(profileName, profile.Provider, names.AppName)
	if err != nil {
		return RealIPTemplateData{}, err
	}
	return RealIPTemplateData{
		Enabled:                true,
		ProfileName:            profileName,
		Provider:               profile.Provider,
		Header:                 appconfig.RealIPHeaderEdgeOne,
		NginxIncludePath:       realIPNames.NginxIncludePath,
		TrustedCIDRPath:        realIPNames.TrustedCIDRPath,
		RejectionLogPath:       names.RealIPRejectionLogPath,
		RejectionLogFormatName: names.RealIPRejectionLogFormatName,
		OriginalSourceVariable: names.VarPrefix + "_realip_original_source",
		SourceTrustedVariable:  names.VarPrefix + "_realip_source_trusted",
		HeaderIsIPVariable:     names.VarPrefix + "_eo_connecting_ip_is_ip",
		HeaderPublicVariable:   names.VarPrefix + "_eo_connecting_ip_is_public",
		RejectReasonVariable:   names.VarPrefix + "_realip_reject_reason",
		RejectLogVariable:      names.VarPrefix + "_realip_reject_log",
	}, nil
}

func nginxAccessLogPath(cfg appconfig.Config) string {
	if cfg.Nginx.GoAccess.Enabled {
		return appsvc.GoAccessCanonicalAccessLogPath(cfg)
	}
	return cfg.Nginx.AccessLog
}

func goAccessTemplateData(cfg appconfig.Config, names appsvc.Names) GoAccessTemplateData {
	goaccess := cfg.Nginx.GoAccess
	if !goaccess.Enabled {
		return GoAccessTemplateData{}
	}
	logFormat := goaccess.EffectiveLogFormat()
	webSocketUpstream := names.GoAccessWebSocketHost
	if strings.Contains(webSocketUpstream, ":") {
		webSocketUpstream = "[" + webSocketUpstream + "]"
	}
	webSocketUpstream += ":" + strconv.Itoa(names.GoAccessWebSocketPort)

	data := GoAccessTemplateData{
		Enabled:                   true,
		BinaryPath:                appsvc.GoAccessBinaryPath,
		Language:                  goaccess.EffectiveLanguage(),
		LogFormat:                 logFormat,
		EnhancedLogFormat:         logFormat == appconfig.NginxGoAccessLogFormatEnhanced,
		CombinedLogFormat:         logFormat == appconfig.NginxGoAccessLogFormatCombined,
		NginxLogFormatName:        names.GoAccessNginxLogFormatName,
		CanonicalAccessLogPath:    names.GoAccessCanonicalAccessLogPath,
		ManagedCanonicalAccessLog: appsvc.GoAccessManagesCanonicalAccessLog(cfg),
		DashboardPath:             cfg.NginxGoAccessDashboardPath(),
		WebSocketPath:             cfg.NginxGoAccessWebSocketPath(),
		WebSocketHost:             names.GoAccessWebSocketHost,
		WebSocketPort:             names.GoAccessWebSocketPort,
		WebSocketListen:           names.GoAccessWebSocketListen,
		WebSocketUpstream:         webSocketUpstream,
		AuthBasicUserFile:         goaccess.AuthBasicUserFile,
		AuthCIDRAllowlist:         append([]string(nil), goaccess.AuthCIDRAllowlist...),
		ConfigPath:                names.GoAccessConfigPath,
		ReportDir:                 names.GoAccessReportDir,
		ReportPath:                names.GoAccessReportPath,
		DBPath:                    names.GoAccessDBPath,
		ServiceUnit:               names.GoAccessServiceUnit,
		SystemUser:                names.GoAccessSystemUser,
		SystemGroup:               names.GoAccessSystemGroup,
		DashboardURL:              "https://" + cfg.PrimaryDomain() + cfg.NginxGoAccessDashboardPath(),
		WSURL:                     goAccessPublicWebSocketURL(cfg.PrimaryDomain(), cfg.NginxGoAccessWebSocketPath()),
		Origin:                    "https://" + cfg.PrimaryDomain(),
		HTMLReportTitle:           "Lanpanel-GoAccess-" + names.AppName,
	}
	if data.EnhancedLogFormat {
		data.GoAccessLogFormatDirective = `%h %^ %^ [%x] "%r" %s %b "%R" "%u" "%v" %T "%^" "%^"`
	} else {
		data.GoAccessLogFormatDirective = "COMBINED"
	}
	if data.Language == appconfig.NginxGoAccessLanguageSimplifiedChinese {
		data.Lang = "zh_CN.UTF-8"
		data.LCMessages = "zh_CN.UTF-8"
		data.LCCType = "zh_CN.UTF-8"
		data.LCTime = "C.UTF-8"
	} else {
		data.Lang = "C.UTF-8"
		data.LCMessages = "C.UTF-8"
		data.LCCType = "C.UTF-8"
		data.LCTime = "C.UTF-8"
	}
	return data
}

func goAccessPublicWebSocketURL(primaryDomain string, websocketPath string) string {
	return "wss://" + primaryDomain + ":443" + websocketPath
}

func proxyTemplateData(proxy appconfig.NginxProxyConfig) ProxyTemplateData {
	data := ProxyTemplateData{
		ConnectTimeout: proxy.ConnectTimeout,
		ReadTimeout:    proxy.EffectiveReadTimeout(),
		SendTimeout:    proxy.EffectiveSendTimeout(),
	}
	if proxy.Buffering != nil {
		data.BufferingSet = true
		data.Buffering = nginxBool(*proxy.Buffering)
	}
	if proxy.RequestBuffering != nil {
		data.RequestBufferingSet = true
		data.RequestBuffering = nginxBool(*proxy.RequestBuffering)
	}
	return data
}

func staticLocationTemplateData(locations []appconfig.NginxStaticLocationConfig) []StaticLocationTemplateData {
	data := make([]StaticLocationTemplateData, 0, len(locations))
	for _, location := range locations {
		accessLogOff := false
		if location.AccessLog != nil {
			accessLogOff = !*location.AccessLog
		}
		data = append(data, StaticLocationTemplateData{
			Exact:        location.Match == "exact",
			Path:         location.Path,
			Alias:        location.Alias,
			DefaultType:  location.DefaultType,
			Expires:      location.Expires,
			CacheControl: location.CacheControl,
			TryFiles:     location.TryFiles,
			GzipStatic:   location.GzipStatic,
			AccessLogOff: accessLogOff,
		})
	}
	return data
}

func nginxBool(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
