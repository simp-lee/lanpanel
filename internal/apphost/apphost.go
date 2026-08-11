package apphost

import (
	"bytes"
	stdcontext "context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"lanpanel/internal/acme"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/appguard"
	"lanpanel/internal/apppreflight"
	"lanpanel/internal/apprender"
	"lanpanel/internal/appverify"
	"lanpanel/internal/browserauth"
	"lanpanel/internal/components/appsvc"
	legocomponent "lanpanel/internal/components/lego"
	nginxcomponent "lanpanel/internal/components/nginx"
	tailscalecomponent "lanpanel/internal/components/tailscale"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/host"
	"lanpanel/internal/maindeploy"
	"lanpanel/internal/preflight"
	"lanpanel/internal/realip"
	"lanpanel/internal/realip/edgeone"
	"lanpanel/internal/realipassets"
	"lanpanel/internal/realiprender"
	"lanpanel/internal/render"
	"lanpanel/internal/state"
	"lanpanel/internal/workflow"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

const DefaultAppConfigPath = appconfig.DefaultConfigPath

const minimumNginxHTTP2DirectiveVersion = "1.25.1"
const appOriginProtectionManualConfirmation = "origin-protection-manual"
const exposurePlanValidationInstanceID = "ins_00000000000000000000000000000000"
const appCheckpointDeployStarted = "app-deploy-started"
const appCheckpointDeployApplied = "app-deploy-applied"
const appCheckpointRealIPRefreshStarted = "realip-refresh-started"
const appCheckpointRealIPRefreshApplied = "realip-refresh-applied"

var realIPLockDir = "/run/lanpanel"

var nginxVersionPattern = regexp.MustCompile(`nginx/([0-9]+)\.([0-9]+)\.([0-9]+)`)

var appNonPublicRoutableIPPrefixes = []netip.Prefix{
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

type appOptions struct {
	configPath           string
	confirmations        appConfirmationFlag
	approvedExposurePlan *domain.ExposurePlan
}

type appConfirmationFlag []string

func (confirmations *appConfirmationFlag) String() string {
	if confirmations == nil {
		return ""
	}
	return strings.Join(*confirmations, ",")
}

func (confirmations *appConfirmationFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("confirmation token must not be empty")
	}
	*confirmations = append(*confirmations, value)
	return nil
}

type AppStagedFileInstaller interface {
	Install(files []render.StagedFile) ([]host.FileInstallResult, error)
}

type appStagedFileInstaller = AppStagedFileInstaller

type Context struct {
	Version string
}

type Result struct {
	Operation    workflow.OperationResult
	OutputStatus string
	NextSteps    []string
}

type Dependencies struct {
	StageAppRuntimeFiles               func(appconfig.Config) ([]apprender.StagedFile, error)
	DetectPermissionState              func() preflight.PermissionState
	DetectPlatformInfo                 func() preflight.PlatformInfo
	StatAppServiceBinary               func(string) (os.FileInfo, error)
	LstatAppServicePath                func(string) (os.FileInfo, error)
	ReadAppServicePath                 func(string) ([]byte, error)
	DetectAppDNS                       func(appconfig.Config) map[string]preflight.DNSProbe
	DetectAppCurrentPublicIPs          func(*http.Client) (string, string, error)
	DetectAppPortBindings              func() []preflight.PortBinding
	DetectAppListenPortState           func(appconfig.Config) (bool, bool, string)
	DetectAppDNSCredentialState        func(appconfig.Config) (bool, bool, string)
	DetectAppServiceEnvFileState       func(appconfig.Config) (bool, bool, string)
	DetectAppTailscaleAuthKeyFileState func(appconfig.Config) (bool, bool, string)
	DetectAppGoAccessAuthFileState     func(appconfig.Config) (bool, bool, string)
	DetectAppBrowserAuthFileState      func(appconfig.Config) (bool, bool, string)
	DetectAppGoAccessPortState         func(appconfig.Config) (bool, bool, string)
	DetectAppGoAccessAppListenBlockers func(appconfig.Config, appsvc.Names) ([]preflight.PortBinding, bool)
	DetectAppGoAccessAppPortBlockers   func(appconfig.Config, appsvc.Names) ([]preflight.PortBinding, bool)
	DetectAppGoAccessLocaleState       func(appconfig.Config) (bool, bool, string)
	DetectAppGoAccessLogFileState      func(appconfig.Config) (bool, bool, string)
	IsAppGoAccessManagedPortBinding    func(appsvc.Names, preflight.PortBinding) (bool, bool)
	IsAppManagedPortBinding            func(appsvc.Names, preflight.PortBinding) (bool, bool)
	ReadAppServiceUnitFile             func(string) ([]byte, error)
	ReadAppProcessCgroupFile           func(string) ([]byte, error)
	EnsureAppNginxCompatibility        func(stdcontext.Context, appconfig.Config, host.Executor) error
	LoadEdgeOneCredentials             func(edgeone.FileSystem, string) (edgeone.Credentials, error)
	DescribeEdgeOneOriginACL           func(stdcontext.Context, edgeone.Credentials, string) (*edgeone.OriginACLInfo, error)
	StageRealIPRuntimeFiles            func(realip.ProfileConfig, realip.State, realip.Reference, string) ([]realiprender.StagedFile, error)
	ReadDeployedRealIPProfile          func(string) (realip.ProfileConfig, error)
	ReadDeployedRealIPState            func(string, string) (realip.State, error)
	ReadDeployedRealIPReferences       func(string) ([]realip.Reference, error)
	LstatDeployedRealIPReference       func(string) (fs.FileInfo, error)
	LstatDeployedRealIPArtifact        func(string) (fs.FileInfo, error)
	ReadDeployedRealIPArtifact         func(string) ([]byte, error)
	LstatRealIPCleanupPath             func(string) (fs.FileInfo, error)
	AcquireRealIPProfileLock           func(string) (RealIPProfileLock, error)
	RealIPCleanupRoot                  string
	CurrentExecutablePath              func() (string, error)
	NewHostExecutor                    func(map[string]string) host.Executor
	NewHostSystemd                     func(host.Executor) host.Systemd
	NewAppFileInstaller                func(host.Executor, host.PrivilegeStrategy) AppStagedFileInstaller
	NewAppHostFileSystem               func(host.Executor, host.PrivilegeStrategy) host.FileSystem
}

type AppDeployOptions struct {
	ConfigPath           string
	Confirmations        []string
	Version              string
	Dependencies         Dependencies
	ApprovedExposurePlan *domain.ExposurePlan
}

type RealIPRefreshOptions struct {
	ConfigPath           string
	ProfileName          string
	Confirmations        []string
	Version              string
	Dependencies         Dependencies
	ApprovedExposurePlan *domain.ExposurePlan
}

type ExposureObservationOptions struct {
	ConfigPath   string
	Config       appconfig.Config
	Operation    domain.ExposurePlanOperation
	Permissions  preflight.PermissionState
	Dependencies Dependencies
}

func AppExposureObservations(ctx stdcontext.Context, options ExposureObservationOptions) (exposure.AppObservations, error) {
	if err := ctx.Err(); err != nil {
		return exposure.AppObservations{}, err
	}
	restore := applyDependencies(options.Dependencies)
	defer restore()
	return cliExposurePlanObservations(options.ConfigPath, options.Config, options.Operation, options.Permissions)
}

func WithDependencies(dependencies Dependencies, run func() error) error {
	if run == nil {
		return fmt.Errorf("apphost dependency scope requires a run function")
	}
	if !dependencyMu.TryLock() {
		return run()
	}
	restore := applyDependenciesLocked(dependencies)
	defer func() {
		restore()
		dependencyMu.Unlock()
	}()
	return run()
}

func DetectAppDNS(cfg appconfig.Config) map[string]preflight.DNSProbe {
	return detectAppDNS(cfg)
}

func DetectAppExpectedPublicIPs(cfg appconfig.Config) (string, string, error) {
	return detectAppExpectedPublicIPs(cfg)
}

func DetectAppCurrentPublicIPs(client *http.Client) (string, string, error) {
	return detectAppCurrentPublicIPs(client)
}

func DetectAppPortBindings() []preflight.PortBinding {
	return detectAppPortBindings()
}

func DetectAppListenPortState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppListenPortState(cfg)
}

func DetectAppDNSCredentialState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppDNSCredentialState(cfg)
}

func DetectAppServiceEnvFileState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppServiceEnvFileState(cfg)
}

func DetectAppTailscaleAuthKeyFileState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppTailscaleAuthKeyFileState(cfg)
}

func DetectAppGoAccessAuthFileState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppGoAccessAuthFileState(cfg)
}

func DetectAppBrowserAuthFileState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppBrowserAuthFileState(cfg)
}

func DetectAppGoAccessPortState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppGoAccessPortState(cfg)
}

func DetectAppGoAccessAppListenBlockers(cfg appconfig.Config, names appsvc.Names) ([]preflight.PortBinding, bool) {
	return detectAppGoAccessAppListenBlockers(cfg, names)
}

func DetectAppGoAccessAppPortBlockers(cfg appconfig.Config, names appsvc.Names) ([]preflight.PortBinding, bool) {
	return detectAppGoAccessAppPortBlockers(cfg, names)
}

func DetectAppGoAccessLocaleState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppGoAccessLocaleState(cfg)
}

func DetectAppGoAccessLogFileState(cfg appconfig.Config) (bool, bool, string) {
	return detectAppGoAccessLogFileState(cfg)
}

func IsAppGoAccessManagedPortBinding(names appsvc.Names, binding preflight.PortBinding) (bool, bool) {
	return isAppGoAccessManagedPortBinding(names, binding)
}

func IsAppManagedPortBinding(names appsvc.Names, binding preflight.PortBinding) (bool, bool) {
	return isAppManagedPortBinding(names, binding)
}

func EnsureAppNginxRuntimeCompatibility(ctx stdcontext.Context, cfg appconfig.Config, executor host.Executor) error {
	return ensureAppNginxRuntimeCompatibility(ctx, cfg, executor)
}

func EnsureAppGoAccessDependency(ctx stdcontext.Context, executor host.Executor) error {
	return ensureAppGoAccessDependency(ctx, executor)
}

func GoAccessRequiredRuntimeOptions() []string {
	return goAccessRequiredRuntimeOptions()
}

func AppHostDependencyPackages(cfg appconfig.Config) []string {
	return appHostDependencyPackages(cfg)
}

func GuardAppOwnership(fileSystem host.FileSystem, cfg appconfig.Config, staged []apprender.StagedFile) error {
	return guardAppOwnership(fileSystem, cfg, staged)
}

func AppGoAccessFailureNextStep(cfg appconfig.Config) string {
	return appGoAccessFailureNextStep(cfg)
}

func AppGoAccessTroubleshootingCommands(cfg appconfig.Config, names appsvc.Names) string {
	return appGoAccessTroubleshootingCommands(cfg, names)
}

func AppGoAccessDeployNextSteps(cfg appconfig.Config, names appsvc.Names) []string {
	return appGoAccessDeployNextSteps(cfg, names)
}

func AppGoAccessDashboardScope(cfg appconfig.Config) string {
	return appGoAccessDashboardScope(cfg)
}

type appDeployEffects struct {
	modifiedPaths []string
	actions       []string
}

type AppDeployEffects = appDeployEffects

func (effects *appDeployEffects) AddPaths(paths ...string) {
	seen := make(map[string]struct{}, len(effects.modifiedPaths)+len(paths))
	for _, path := range effects.modifiedPaths {
		seen[path] = struct{}{}
	}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		effects.modifiedPaths = append(effects.modifiedPaths, path)
	}
}

func (effects *appDeployEffects) AddActions(actions ...string) {
	seen := make(map[string]struct{}, len(effects.actions)+len(actions))
	for _, action := range effects.actions {
		seen[action] = struct{}{}
	}
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if action == "" {
			continue
		}
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		effects.actions = append(effects.actions, action)
	}
}

func (effects *appDeployEffects) AddTailscaleResult(result tailscalecomponent.EnsureResult) {
	if strings.TrimSpace(result.SkippedReason) != "" {
		effects.AddActions("tailscale skipped: " + result.SkippedReason)
	}
	for _, command := range result.CommandsRun {
		effects.AddActions("tailscale: " + command)
		switch {
		case strings.Contains(command, "install-tailscale-keyring"):
			effects.AddPaths("/usr/share/keyrings/tailscale-archive-keyring.gpg", "/usr/share/keyrings/tailscale-archive-keyring.gpg.lanpanel-managed")
		case strings.Contains(command, "install-tailscale-apt-source"):
			effects.AddPaths("/etc/apt/sources.list.d/tailscale.list", "/etc/apt/sources.list.d/tailscale.list.lanpanel-managed")
		case strings.Contains(command, "install-tailscale-marker"):
			effects.AddPaths(tailscalecomponent.MarkerPath)
		}
	}
}

func (effects appDeployEffects) Fields() []domain.ResultField {
	fields := []domain.ResultField{{Label: "modified paths", Value: summarizeAppModifiedPaths(effects.modifiedPaths)}}
	if len(effects.actions) > 0 {
		fields = append(fields, domain.ResultField{Label: "host actions", Value: strings.Join(effects.actions, ", ")})
	}
	return fields
}

func (effects appDeployEffects) ModifiedPaths() []string {
	return append([]string(nil), effects.modifiedPaths...)
}

func (effects appDeployEffects) Actions() []string {
	return append([]string(nil), effects.actions...)
}

func summarizeAppModifiedPaths(paths []string) string {
	if len(paths) == 0 {
		return "none"
	}
	return fmt.Sprintf("%d total: %s", len(paths), strings.Join(paths, ", "))
}

var (
	stageAppRuntimeFilesFn               = apprender.StageRuntime
	detectPermissionStateFn              = maindeploy.DetectPermissionState
	detectPlatformInfoFn                 = maindeploy.DetectPlatformInfo
	statAppServiceBinaryFn               = os.Stat
	lstatAppServicePathFn                = os.Lstat
	readAppServicePathFn                 = os.ReadFile
	detectAppDNSFn                       = detectAppDNS
	detectAppCurrentPublicIPsFn          = detectAppCurrentPublicIPs
	detectAppPortBindingsFn              = detectAppPortBindings
	detectAppListenPortStateFn           = detectAppListenPortState
	detectAppDNSCredentialStateFn        = detectAppDNSCredentialState
	detectAppServiceEnvFileStateFn       = detectAppServiceEnvFileState
	detectAppTailscaleAuthKeyFileStateFn = detectAppTailscaleAuthKeyFileState
	detectAppGoAccessAuthFileStateFn     = detectAppGoAccessAuthFileState
	detectAppBrowserAuthFileStateFn      = detectAppBrowserAuthFileState
	detectAppGoAccessPortStateFn         = detectAppGoAccessPortState
	detectAppGoAccessAppListenBlockersFn = detectAppGoAccessAppListenBlockers
	detectAppGoAccessAppPortBlockersFn   = detectAppGoAccessAppPortBlockers
	detectAppGoAccessLocaleStateFn       = detectAppGoAccessLocaleState
	detectAppGoAccessLogFileStateFn      = detectAppGoAccessLogFileState
	isAppGoAccessManagedPortBindingFn    = isAppGoAccessManagedPortBinding
	isAppManagedPortBindingFn            = isAppManagedPortBinding
	readAppServiceUnitFileFn             = os.ReadFile
	readAppProcessCgroupFileFn           = os.ReadFile
	ensureAppNginxCompatibilityFn        = ensureAppNginxRuntimeCompatibility
	loadEdgeOneCredentialsFn             = edgeone.LoadCredentialsFromEnvFile
	describeEdgeOneOriginACLFn           = func(ctx stdcontext.Context, credentials edgeone.Credentials, zoneID string) (*edgeone.OriginACLInfo, error) {
		return edgeone.Client{}.DescribeOriginACL(ctx, credentials, zoneID)
	}
	stageRealIPRuntimeFilesFn      = realiprender.StageRuntime
	readDeployedRealIPProfileFn    = readDeployedRealIPProfile
	readDeployedRealIPStateFn      = readDeployedRealIPState
	readDeployedRealIPReferencesFn = readDeployedRealIPReferences
	runRealIPValidateReferenceFn   = workflow.RunRealIPValidateReference
	lstatDeployedRealIPReferenceFn = os.Lstat
	lstatDeployedRealIPArtifactFn  = os.Lstat
	readDeployedRealIPArtifactFn   = os.ReadFile
	lstatRealIPCleanupPathFn       = os.Lstat
	acquireRealIPProfileLockFn     = acquireRealIPProfileLock
	realIPCleanupRoot              = "/var/lib/lanpanel/realip"
	currentExecutablePathFn        = os.Executable
	newHostExecutorFn              = func(env map[string]string) host.Executor { return host.NewExecutor(nil, env) }
	newHostSystemdFn               = func(executor host.Executor) host.Systemd { return host.NewSystemd(executor) }
	newAppFileInstallerFn          = func(executor host.Executor, privilege host.PrivilegeStrategy) appStagedFileInstaller {
		if privilege.RequiresSudo() {
			return host.NewFileInstaller(host.NewCommandFileSystem(executor), "")
		}
		return host.NewFileInstaller(nil, "")
	}
	newAppHostFileSystemFn = func(executor host.Executor, privilege host.PrivilegeStrategy) host.FileSystem {
		if privilege.RequiresSudo() {
			return host.NewCommandFileSystem(executor)
		}
		return host.OSFileSystem{}
	}
	dependencyMu sync.Mutex
)

func applyDependencies(dependencies Dependencies) func() {
	dependencyMu.Lock()
	restore := applyDependenciesLocked(dependencies)
	return func() {
		restore()
		dependencyMu.Unlock()
	}
}

func applyDependenciesLocked(dependencies Dependencies) func() {
	previous := Dependencies{
		StageAppRuntimeFiles:               stageAppRuntimeFilesFn,
		DetectPermissionState:              detectPermissionStateFn,
		DetectPlatformInfo:                 detectPlatformInfoFn,
		StatAppServiceBinary:               statAppServiceBinaryFn,
		LstatAppServicePath:                lstatAppServicePathFn,
		ReadAppServicePath:                 readAppServicePathFn,
		DetectAppDNS:                       detectAppDNSFn,
		DetectAppCurrentPublicIPs:          detectAppCurrentPublicIPsFn,
		DetectAppPortBindings:              detectAppPortBindingsFn,
		DetectAppListenPortState:           detectAppListenPortStateFn,
		DetectAppDNSCredentialState:        detectAppDNSCredentialStateFn,
		DetectAppServiceEnvFileState:       detectAppServiceEnvFileStateFn,
		DetectAppTailscaleAuthKeyFileState: detectAppTailscaleAuthKeyFileStateFn,
		DetectAppGoAccessAuthFileState:     detectAppGoAccessAuthFileStateFn,
		DetectAppBrowserAuthFileState:      detectAppBrowserAuthFileStateFn,
		DetectAppGoAccessPortState:         detectAppGoAccessPortStateFn,
		DetectAppGoAccessAppListenBlockers: detectAppGoAccessAppListenBlockersFn,
		DetectAppGoAccessAppPortBlockers:   detectAppGoAccessAppPortBlockersFn,
		DetectAppGoAccessLocaleState:       detectAppGoAccessLocaleStateFn,
		DetectAppGoAccessLogFileState:      detectAppGoAccessLogFileStateFn,
		IsAppGoAccessManagedPortBinding:    isAppGoAccessManagedPortBindingFn,
		IsAppManagedPortBinding:            isAppManagedPortBindingFn,
		ReadAppServiceUnitFile:             readAppServiceUnitFileFn,
		ReadAppProcessCgroupFile:           readAppProcessCgroupFileFn,
		EnsureAppNginxCompatibility:        ensureAppNginxCompatibilityFn,
		LoadEdgeOneCredentials:             loadEdgeOneCredentialsFn,
		DescribeEdgeOneOriginACL:           describeEdgeOneOriginACLFn,
		StageRealIPRuntimeFiles:            stageRealIPRuntimeFilesFn,
		ReadDeployedRealIPProfile:          readDeployedRealIPProfileFn,
		ReadDeployedRealIPState:            readDeployedRealIPStateFn,
		ReadDeployedRealIPReferences:       readDeployedRealIPReferencesFn,
		LstatDeployedRealIPReference:       lstatDeployedRealIPReferenceFn,
		LstatDeployedRealIPArtifact:        lstatDeployedRealIPArtifactFn,
		ReadDeployedRealIPArtifact:         readDeployedRealIPArtifactFn,
		LstatRealIPCleanupPath:             lstatRealIPCleanupPathFn,
		AcquireRealIPProfileLock:           acquireRealIPProfileLockFn,
		RealIPCleanupRoot:                  realIPCleanupRoot,
		CurrentExecutablePath:              currentExecutablePathFn,
		NewHostExecutor:                    newHostExecutorFn,
		NewHostSystemd:                     newHostSystemdFn,
		NewAppFileInstaller:                newAppFileInstallerFn,
		NewAppHostFileSystem:               newAppHostFileSystemFn,
	}
	if dependencies.StageAppRuntimeFiles != nil {
		stageAppRuntimeFilesFn = dependencies.StageAppRuntimeFiles
	}
	if dependencies.DetectPermissionState != nil {
		detectPermissionStateFn = dependencies.DetectPermissionState
	}
	if dependencies.DetectPlatformInfo != nil {
		detectPlatformInfoFn = dependencies.DetectPlatformInfo
	}
	if dependencies.StatAppServiceBinary != nil {
		statAppServiceBinaryFn = dependencies.StatAppServiceBinary
	}
	if dependencies.LstatAppServicePath != nil {
		lstatAppServicePathFn = dependencies.LstatAppServicePath
	}
	if dependencies.ReadAppServicePath != nil {
		readAppServicePathFn = dependencies.ReadAppServicePath
	}
	if dependencies.DetectAppDNS != nil {
		detectAppDNSFn = dependencies.DetectAppDNS
	}
	if dependencies.DetectAppCurrentPublicIPs != nil {
		detectAppCurrentPublicIPsFn = dependencies.DetectAppCurrentPublicIPs
	}
	if dependencies.DetectAppPortBindings != nil {
		detectAppPortBindingsFn = dependencies.DetectAppPortBindings
	}
	if dependencies.DetectAppListenPortState != nil {
		detectAppListenPortStateFn = dependencies.DetectAppListenPortState
	}
	if dependencies.DetectAppDNSCredentialState != nil {
		detectAppDNSCredentialStateFn = dependencies.DetectAppDNSCredentialState
	}
	if dependencies.DetectAppServiceEnvFileState != nil {
		detectAppServiceEnvFileStateFn = dependencies.DetectAppServiceEnvFileState
	}
	if dependencies.DetectAppTailscaleAuthKeyFileState != nil {
		detectAppTailscaleAuthKeyFileStateFn = dependencies.DetectAppTailscaleAuthKeyFileState
	}
	if dependencies.DetectAppGoAccessAuthFileState != nil {
		detectAppGoAccessAuthFileStateFn = dependencies.DetectAppGoAccessAuthFileState
	}
	if dependencies.DetectAppBrowserAuthFileState != nil {
		detectAppBrowserAuthFileStateFn = dependencies.DetectAppBrowserAuthFileState
	}
	if dependencies.DetectAppGoAccessPortState != nil {
		detectAppGoAccessPortStateFn = dependencies.DetectAppGoAccessPortState
	}
	if dependencies.DetectAppGoAccessAppListenBlockers != nil {
		detectAppGoAccessAppListenBlockersFn = dependencies.DetectAppGoAccessAppListenBlockers
	}
	if dependencies.DetectAppGoAccessAppPortBlockers != nil {
		detectAppGoAccessAppPortBlockersFn = dependencies.DetectAppGoAccessAppPortBlockers
	}
	if dependencies.DetectAppGoAccessLocaleState != nil {
		detectAppGoAccessLocaleStateFn = dependencies.DetectAppGoAccessLocaleState
	}
	if dependencies.DetectAppGoAccessLogFileState != nil {
		detectAppGoAccessLogFileStateFn = dependencies.DetectAppGoAccessLogFileState
	}
	if dependencies.IsAppGoAccessManagedPortBinding != nil {
		isAppGoAccessManagedPortBindingFn = dependencies.IsAppGoAccessManagedPortBinding
	}
	if dependencies.IsAppManagedPortBinding != nil {
		isAppManagedPortBindingFn = dependencies.IsAppManagedPortBinding
	}
	if dependencies.ReadAppServiceUnitFile != nil {
		readAppServiceUnitFileFn = dependencies.ReadAppServiceUnitFile
	}
	if dependencies.ReadAppProcessCgroupFile != nil {
		readAppProcessCgroupFileFn = dependencies.ReadAppProcessCgroupFile
	}
	if dependencies.EnsureAppNginxCompatibility != nil {
		ensureAppNginxCompatibilityFn = dependencies.EnsureAppNginxCompatibility
	}
	if dependencies.LoadEdgeOneCredentials != nil {
		loadEdgeOneCredentialsFn = dependencies.LoadEdgeOneCredentials
	}
	if dependencies.DescribeEdgeOneOriginACL != nil {
		describeEdgeOneOriginACLFn = dependencies.DescribeEdgeOneOriginACL
	}
	if dependencies.StageRealIPRuntimeFiles != nil {
		stageRealIPRuntimeFilesFn = dependencies.StageRealIPRuntimeFiles
	}
	if dependencies.ReadDeployedRealIPProfile != nil {
		readDeployedRealIPProfileFn = dependencies.ReadDeployedRealIPProfile
	}
	if dependencies.ReadDeployedRealIPState != nil {
		readDeployedRealIPStateFn = dependencies.ReadDeployedRealIPState
	}
	if dependencies.ReadDeployedRealIPReferences != nil {
		readDeployedRealIPReferencesFn = dependencies.ReadDeployedRealIPReferences
	}
	if dependencies.LstatDeployedRealIPReference != nil {
		lstatDeployedRealIPReferenceFn = dependencies.LstatDeployedRealIPReference
	}
	if dependencies.LstatDeployedRealIPArtifact != nil {
		lstatDeployedRealIPArtifactFn = dependencies.LstatDeployedRealIPArtifact
	}
	if dependencies.ReadDeployedRealIPArtifact != nil {
		readDeployedRealIPArtifactFn = dependencies.ReadDeployedRealIPArtifact
	}
	if dependencies.LstatRealIPCleanupPath != nil {
		lstatRealIPCleanupPathFn = dependencies.LstatRealIPCleanupPath
	}
	if dependencies.AcquireRealIPProfileLock != nil {
		acquireRealIPProfileLockFn = dependencies.AcquireRealIPProfileLock
	}
	if strings.TrimSpace(dependencies.RealIPCleanupRoot) != "" {
		realIPCleanupRoot = dependencies.RealIPCleanupRoot
	}
	if dependencies.CurrentExecutablePath != nil {
		currentExecutablePathFn = dependencies.CurrentExecutablePath
	}
	if dependencies.NewHostExecutor != nil {
		newHostExecutorFn = dependencies.NewHostExecutor
	}
	if dependencies.NewHostSystemd != nil {
		newHostSystemdFn = dependencies.NewHostSystemd
	}
	if dependencies.NewAppFileInstaller != nil {
		newAppFileInstallerFn = dependencies.NewAppFileInstaller
	}
	if dependencies.NewAppHostFileSystem != nil {
		newAppHostFileSystemFn = dependencies.NewAppHostFileSystem
	}
	return func() {
		stageAppRuntimeFilesFn = previous.StageAppRuntimeFiles
		detectPermissionStateFn = previous.DetectPermissionState
		detectPlatformInfoFn = previous.DetectPlatformInfo
		statAppServiceBinaryFn = previous.StatAppServiceBinary
		lstatAppServicePathFn = previous.LstatAppServicePath
		readAppServicePathFn = previous.ReadAppServicePath
		detectAppDNSFn = previous.DetectAppDNS
		detectAppCurrentPublicIPsFn = previous.DetectAppCurrentPublicIPs
		detectAppPortBindingsFn = previous.DetectAppPortBindings
		detectAppListenPortStateFn = previous.DetectAppListenPortState
		detectAppDNSCredentialStateFn = previous.DetectAppDNSCredentialState
		detectAppServiceEnvFileStateFn = previous.DetectAppServiceEnvFileState
		detectAppTailscaleAuthKeyFileStateFn = previous.DetectAppTailscaleAuthKeyFileState
		detectAppGoAccessAuthFileStateFn = previous.DetectAppGoAccessAuthFileState
		detectAppBrowserAuthFileStateFn = previous.DetectAppBrowserAuthFileState
		detectAppGoAccessPortStateFn = previous.DetectAppGoAccessPortState
		detectAppGoAccessAppListenBlockersFn = previous.DetectAppGoAccessAppListenBlockers
		detectAppGoAccessAppPortBlockersFn = previous.DetectAppGoAccessAppPortBlockers
		detectAppGoAccessLocaleStateFn = previous.DetectAppGoAccessLocaleState
		detectAppGoAccessLogFileStateFn = previous.DetectAppGoAccessLogFileState
		isAppGoAccessManagedPortBindingFn = previous.IsAppGoAccessManagedPortBinding
		isAppManagedPortBindingFn = previous.IsAppManagedPortBinding
		readAppServiceUnitFileFn = previous.ReadAppServiceUnitFile
		readAppProcessCgroupFileFn = previous.ReadAppProcessCgroupFile
		ensureAppNginxCompatibilityFn = previous.EnsureAppNginxCompatibility
		loadEdgeOneCredentialsFn = previous.LoadEdgeOneCredentials
		describeEdgeOneOriginACLFn = previous.DescribeEdgeOneOriginACL
		stageRealIPRuntimeFilesFn = previous.StageRealIPRuntimeFiles
		readDeployedRealIPProfileFn = previous.ReadDeployedRealIPProfile
		readDeployedRealIPStateFn = previous.ReadDeployedRealIPState
		readDeployedRealIPReferencesFn = previous.ReadDeployedRealIPReferences
		lstatDeployedRealIPReferenceFn = previous.LstatDeployedRealIPReference
		lstatDeployedRealIPArtifactFn = previous.LstatDeployedRealIPArtifact
		readDeployedRealIPArtifactFn = previous.ReadDeployedRealIPArtifact
		lstatRealIPCleanupPathFn = previous.LstatRealIPCleanupPath
		acquireRealIPProfileLockFn = previous.AcquireRealIPProfileLock
		realIPCleanupRoot = previous.RealIPCleanupRoot
		currentExecutablePathFn = previous.CurrentExecutablePath
		newHostExecutorFn = previous.NewHostExecutor
		newHostSystemdFn = previous.NewHostSystemd
		newAppFileInstallerFn = previous.NewAppFileInstaller
		newAppHostFileSystemFn = previous.NewAppHostFileSystem
	}
}

func runAppRealIPRefresh(ctx Context, profileName string, configPath string, confirmations appConfirmationFlag, approvedPlan *domain.ExposurePlan) (Result, error) {
	retryCommand := retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", configPath, "--profile", profileName), confirmations)
	realIPRefreshFailure := func(response commandResponse) (Result, error) {
		return appFailureOperationResult(domain.JobKindRealIPRefresh, response, retryCommand, appHostMutationBlockedProgress(domain.JobKindRealIPRefresh)), appFailureError(response)
	}
	if strings.TrimSpace(profileName) == "" {
		return realIPRefreshFailure(commandResponse{
			Command:   "app realip refresh",
			Status:    "invalid-profile",
			Summary:   "--profile is required",
			NextSteps: []string{"Pass --profile with the deployed realip profile name."},
		})
	}
	profileName = strings.TrimSpace(profileName)
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return realIPRefreshFailure(commandResponse{
			Command:   "app realip refresh",
			Status:    "invalid-config",
			Summary:   "--config is required",
			NextSteps: []string{"Pass --config with the app config that selects the deployed realip profile."},
		})
	}
	cfg, err := loadRealIPAppConfigProfile(configPath, profileName)
	if err != nil {
		return realIPRefreshFailure(appRealIPConfigFailureResponse("app realip refresh", configPath, profileName, err))
	}
	permissions := detectPermissionStateFn()
	if !permissions.IsRoot {
		return realIPRefreshFailure(appRealIPRefreshRootRequiredResponse(permissions))
	}
	exposurePlan, err := approvedAppHostMutationExposurePlan(approvedPlan, cfg, configPath, ctx.Version, permissions, domain.ExposurePlanOperationRealIPRefresh, []string(confirmations))
	if err != nil {
		return realIPRefreshFailure(invalidExposurePlanResponse("app realip refresh", err))
	}
	runtimeConfigPath, err := realIPRuntimeAppConfigPath(configPath)
	if err != nil {
		return realIPRefreshFailure(appRealIPConfigFailureResponse("app realip refresh", configPath, profileName, err))
	}
	checkpointDigest, err := appCheckpointDesiredStateDigestForConfig(cfg)
	if err != nil {
		return realIPRefreshFailure(appRealIPConfigFailureResponse("app realip refresh", configPath, profileName, err))
	}
	privilege := deployPrivilegeStrategy(permissions)
	checkpointExecutor := newHostExecutorFn(nil).WithPrivilege(privilege)
	checkpointFileSystem := newAppHostFileSystemFn(checkpointExecutor, privilege)
	checkpointStore, checkpoint, err := beginAppHostCheckpoint(stdcontext.Background(), configPath, checkpointDigest, appCheckpointRealIPRefreshStarted, checkpointExecutor, checkpointFileSystem)
	if err != nil {
		return realIPRefreshFailure(commandResponse{
			Command: "app realip refresh",
			Status:  "failed",
			Summary: "Realip refresh checkpoint initialization failed",
			Fields:  []domain.ResultField{{Label: "details", Value: err.Error()}},
		})
	}
	checkpointPersistor := newAppCheckpointPersistor(checkpointStore, &checkpoint)
	effects := appDeployEffects{}
	state, profile, names, err := refreshDeployedRealIPProfile(stdcontext.Background(), profileName, runtimeConfigPath, &effects, &checkpointPersistor)
	if err != nil {
		fields := appRealIPRefreshFailureFields(strings.TrimSpace(profileName), err)
		fields = append(fields, effects.Fields()...)
		operation := workflow.OperationResult{
			Kind:          domain.JobKindRealIPRefresh,
			Status:        domain.JobStatusFailed,
			Summary:       "Realip profile refresh failed",
			Fields:        fields,
			ModifiedPaths: effects.ModifiedPaths(),
			RetryCommand:  retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", configPath, "--profile", profileName), confirmations),
			Progress:      operationProgressEvents(domain.JobKindRealIPRefresh, "realip refresh host workflow started", domain.DiagnosticStatusFail, "realip refresh host workflow failed"),
		}
		plan := exposurePlanWithModifiedPaths(exposurePlan, effects.ModifiedPaths())
		operation.ExposurePlan = &plan
		result := operationResult("app realip refresh", "failed", operation, []string{"Fix the reported profile, credential, EdgeOne API, CIDR, or Nginx error and rerun the refresh command."})
		if checkpointErr := saveAppHostCheckpointFailure(checkpointStore, &checkpoint, appCheckpointRealIPRefreshStarted, operation.RetryCommand, effects.ModifiedPaths(), err); checkpointErr != nil {
			return result, fmt.Errorf("app realip refresh: %s; persist checkpoint failed: %w", result.Operation.Summary, checkpointErr)
		}
		return result, appFailureError(commandResponse{Command: "app realip refresh", Summary: result.Operation.Summary})
	}
	fields := []domain.ResultField{
		{Label: "profile", Value: profile.Name + " (" + profile.Provider + ")"},
		{Label: "manual firewall confirmation", Value: "confirm cloud security group or host firewall allows only EdgeOne current+next origin ACL CIDRs to 80/443 before confirming any EdgeOne origin ACL update outside Lanpanel"},
	}
	fields = append(fields, realIPRuntimeFields(names, state, "nginx -t passed and Nginx reloaded")...)
	fields = append(fields, effects.Fields()...)
	exposurePlan = exposurePlanWithModifiedPaths(exposurePlan, effects.ModifiedPaths())
	if err := saveAppHostCheckpointSuccess(checkpointStore, &checkpoint, appCheckpointRealIPRefreshApplied, effects.ModifiedPaths()); err != nil {
		return realIPRefreshFailure(commandResponse{
			Command: "app realip refresh",
			Status:  "failed",
			Summary: "Realip refresh checkpoint persistence failed",
			Fields:  []domain.ResultField{{Label: "details", Value: err.Error()}},
		})
	}
	return operationResult("app realip refresh", "refreshed", workflow.OperationResult{
		Kind:          domain.JobKindRealIPRefresh,
		Status:        domain.JobStatusSucceeded,
		Summary:       "Realip profile refreshed from EdgeOne OriginACL",
		Fields:        fields,
		ExposurePlan:  &exposurePlan,
		ModifiedPaths: effects.ModifiedPaths(),
		RetryCommand:  retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", configPath, "--profile", profileName), confirmations),
		Progress:      operationProgressEvents(domain.JobKindRealIPRefresh, "realip refresh host workflow started", domain.DiagnosticStatusPass, "realip refresh host workflow finished"),
	}, []string{
		"Run nginx -t and curl trusted/non-trusted request fixtures on the host if this is a production cutover.",
		"Update cloud security group or host firewall for current+next CIDRs; Lanpanel does not confirm EdgeOne origin ACL updates.",
	}), nil
}

func RunRealIPRefresh(ctx stdcontext.Context, options RealIPRefreshOptions) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{Operation: workflow.OperationResult{
			Kind:         domain.JobKindRealIPRefresh,
			Status:       domain.JobStatusInterrupted,
			Summary:      "realip refresh canceled before host workflow started",
			RetryCommand: retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", options.ConfigPath, "--profile", options.ProfileName), options.Confirmations),
		}, OutputStatus: "interrupted"}, err
	}
	restore := applyDependencies(options.Dependencies)
	defer restore()
	result, err := runAppRealIPRefresh(Context{Version: options.Version}, options.ProfileName, options.ConfigPath, appConfirmationFlag(options.Confirmations), options.ApprovedExposurePlan)
	if strings.TrimSpace(result.Operation.RetryCommand) == "" {
		result.Operation.RetryCommand = retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", options.ConfigPath, "--profile", options.ProfileName), options.Confirmations)
	}
	return result, err
}

func appRealIPRefreshFailureFields(profileName string, cause error) []domain.ResultField {
	profileName = strings.TrimSpace(profileName)
	fields := []domain.ResultField{{Label: "profile", Value: profileName}}
	names, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, "")
	if err != nil {
		fields = append(fields, domain.ResultField{Label: "runtime paths", Value: "unavailable: " + err.Error()})
	} else {
		fields = append(fields,
			domain.ResultField{Label: "active include", Value: names.NginxIncludePath},
			domain.ResultField{Label: "trusted CIDRs", Value: names.TrustedCIDRPath},
			domain.ResultField{Label: "state metadata", Value: names.StatePath},
			domain.ResultField{Label: "profile metadata", Value: names.MetadataPath},
			domain.ResultField{Label: "reference dir", Value: names.ReferenceDir},
			domain.ResultField{Label: "refresh service", Value: names.RefreshServicePath},
			domain.ResultField{Label: "refresh timer", Value: names.RefreshTimerPath},
		)
	}
	if cause != nil {
		fields = append(fields, domain.ResultField{Label: "details", Value: cause.Error()})
	}
	return fields
}

func validateRealIPAppConfigProfile(configPath string, profileName string) error {
	_, err := loadRealIPAppConfigProfile(configPath, profileName)
	return err
}

func loadRealIPAppConfigProfile(configPath string, profileName string) (appconfig.Config, error) {
	cfg, err := appconfig.LoadFile(configPath)
	if err != nil {
		return appconfig.Config{}, err
	}
	profile, ok := cfg.RealIPProfile(profileName)
	if !ok {
		return appconfig.Config{}, fmt.Errorf("realip profile %q is not defined in app config", profileName)
	}
	if cfg.EffectiveRealIPProfileName() != profileName {
		return appconfig.Config{}, fmt.Errorf("realip profile %q is not the active origin protection profile in app config", profileName)
	}
	if !profile.IsEnabled() {
		return appconfig.Config{}, fmt.Errorf("realip profile %q is disabled in app config", profileName)
	}
	return cfg, nil
}

func realIPRuntimeAppConfigPath(configPath string) (string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return "", fmt.Errorf("realip refresh app config path is required")
	}
	absolutePath, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("resolve realip refresh app config path: %w", err)
	}
	if !isSystemdExecToken(absolutePath) {
		return "", fmt.Errorf("realip refresh app config path must be a single systemd ExecStart token")
	}
	return absolutePath, nil
}

func isSystemdExecToken(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune("%;\"'\\${}", r) {
			return false
		}
	}
	return true
}

func appRealIPConfigFailureResult(command string, configPath string, profileName string, cause error) commandResult {
	return newCommandResult(command, "invalid-config", domain.JobStatusFailed, domain.DiagnosticStatusFail, "Realip app config validation failed", []domain.ResultField{
		{Label: "app config path", Value: configPath},
		{Label: "profile", Value: profileName},
		{Label: "details", Value: cause.Error()},
	}, []string{"Pass the app config whose access.origin_protection.edgeone_profile matches --profile."})
}

func appRealIPConfigFailureResponse(command string, configPath string, profileName string, cause error) commandResponse {
	result := appRealIPConfigFailureResult(command, configPath, profileName, cause)
	return commandResponse{
		Command:   result.Command,
		Status:    result.OutputStatus,
		Summary:   result.Summary,
		Fields:    append([]domain.ResultField(nil), result.Fields...),
		NextSteps: append([]string(nil), result.NextSteps...),
	}
}

func appRealIPRefreshCommand(configPath string, profileName string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = "<app-config>"
	}
	return workflow.ShellCommand("sudo", "lanpanel", "app", "realip", "refresh", "--config", configPath, "--profile", strings.TrimSpace(profileName), "--confirmation", appOriginProtectionManualConfirmation)
}

func invalidExposurePlanResponse(command string, cause error) commandResponse {
	return commandResponse{
		Command: command,
		Status:  "invalid-exposure-plan",
		Summary: "approved exposure plan rejected: " + cause.Error(),
		Fields:  []domain.ResultField{{Label: "details", Value: cause.Error()}},
	}
}

func approvedAppHostMutationExposurePlan(plan *domain.ExposurePlan, cfg appconfig.Config, configPath string, version string, permissions preflight.PermissionState, operation domain.ExposurePlanOperation, confirmations []string) (domain.ExposurePlan, error) {
	if plan == nil {
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan is required")
	}
	approved := *plan
	approved.ResourcesChanged = append([]string(nil), plan.ResourcesChanged...)
	approved.ModifiedPaths = append([]string(nil), plan.ModifiedPaths...)
	approved.Decision.Blockers = append([]string(nil), plan.Decision.Blockers...)
	approved.Decision.RequiredConfirmations = append([]string(nil), plan.Decision.RequiredConfirmations...)
	approved.Access.ManualConfirmations = append([]domain.ManualConfirmation(nil), plan.Access.ManualConfirmations...)
	approved.DiagnosticBlockers = append([]domain.DiagnosticItem(nil), plan.DiagnosticBlockers...)
	if approved.Operation != operation {
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan operation %q does not match %q", approved.Operation, operation)
	}
	if strings.TrimSpace(approved.Resource.ID) == "" {
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan resource id is required")
	}
	if len(approved.ResourcesChanged) != 1 || approved.ResourcesChanged[0] != approved.Resource.ID {
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan resource linkage does not match")
	}
	switch approved.Decision.Status {
	case domain.ExposurePlanDecisionPass, domain.ExposurePlanDecisionWarn, domain.ExposurePlanDecisionManual:
	default:
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan decision %q cannot run host mutation", approved.Decision.Status)
	}
	missing := missingAppHostMutationConfirmations(approved.Decision.RequiredConfirmations, confirmations)
	if len(missing) > 0 {
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan missing confirmations: %s", strings.Join(missing, ", "))
	}
	extra := unexpectedAppHostMutationConfirmations(approved.Decision.RequiredConfirmations, confirmations)
	if len(extra) > 0 {
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan unexpected confirmations: %s", strings.Join(extra, ", "))
	}
	if err := domain.ValidateManualConfirmationRecords(approved.Decision.RequiredConfirmations, approved.Access.ManualConfirmations); err != nil {
		return domain.ExposurePlan{}, fmt.Errorf("approved exposure plan manual confirmation records invalid: %w", err)
	}
	current, err := currentAppHostMutationExposurePlan(cfg, configPath, version, operation, approved)
	if err != nil {
		return domain.ExposurePlan{}, err
	}
	if err := validateApprovedExposurePlanMatchesCurrent(approved, current); err != nil {
		return domain.ExposurePlan{}, err
	}
	return approved, nil
}

func currentAppHostMutationExposurePlan(cfg appconfig.Config, configPath string, version string, operation domain.ExposurePlanOperation, approved domain.ExposurePlan) (domain.ExposurePlan, error) {
	return exposure.AppPlanWithObservations(exposurePlanValidationInstanceID, version, cfg, exposure.AppPlanOptions{
		ConfigPath: configPath,
		Operation:  operation,
	}, appHostMutationObservationsFromApprovedPlan(cfg, approved))
}

func appHostMutationObservationsFromApprovedPlan(cfg appconfig.Config, approved domain.ExposurePlan) exposure.AppObservations {
	observations := exposure.AppObservations{OriginProtectionStatus: approved.OriginProtection}
	if approved.OriginProtection == domain.OriginProtectionConfiguredPass {
		observations.OriginProtectionReferenceDigest = "sha256:" + strings.Repeat("0", 64)
		observations.RealIPTrustedCIDRCount = 1
		observations.RealIPClientIPHeader = appconfig.RealIPHeaderEdgeOne
		observations.RealIPSpoofingRejection = domain.DiagnosticStatusPass
	}
	if cfg.BrowserAuthEnabled() && approved.Decision.Status != domain.ExposurePlanDecisionFail && approved.Decision.Status != domain.ExposurePlanDecisionUnknown {
		observations.BrowserAuthRuntimeStatus = domain.DiagnosticStatusPass
		if strings.TrimSpace(cfg.Access.BrowserAuth.Managed.HtpasswdPath) != "" {
			observations.BrowserAuthMarkerStatus = domain.DiagnosticStatusPass
		}
	}
	return observations
}

func validateApprovedExposurePlanMatchesCurrent(approved domain.ExposurePlan, current domain.ExposurePlan) error {
	if approved.AfterDigest != current.AfterDigest || approved.Resource.ConfigRef.Digest != current.Resource.ConfigRef.Digest {
		return fmt.Errorf("approved exposure plan digest does not match current app config")
	}
	if approved.Resource.ConfigRef.Path != current.Resource.ConfigRef.Path {
		return fmt.Errorf("approved exposure plan config path %q does not match current path %q", approved.Resource.ConfigRef.Path, current.Resource.ConfigRef.Path)
	}
	if approved.Resource.Type != current.Resource.Type || approved.Resource.Name != current.Resource.Name || approved.Resource.CanonicalName != current.Resource.CanonicalName {
		return fmt.Errorf("approved exposure plan resource identity does not match current app config")
	}
	if !reflect.DeepEqual(accessSurfaceWithoutManualConfirmations(approved.Access), accessSurfaceWithoutManualConfirmations(current.Access)) {
		return fmt.Errorf("approved exposure plan access surface does not match current app config")
	}
	if approved.OriginProtection != current.OriginProtection {
		return fmt.Errorf("approved exposure plan origin protection %q does not match current %q", approved.OriginProtection, current.OriginProtection)
	}
	if approved.Decision.Status != current.Decision.Status || !sameStringSet(approved.Decision.Blockers, current.Decision.Blockers) || !sameStringSet(approved.Decision.RequiredConfirmations, current.Decision.RequiredConfirmations) {
		return fmt.Errorf("approved exposure plan decision does not match current app config")
	}
	if !reflect.DeepEqual(approved.ActivationPreview, current.ActivationPreview) {
		return fmt.Errorf("approved exposure plan activation preview does not match current app config")
	}
	return nil
}

func accessSurfaceWithoutManualConfirmations(access domain.AccessSurface) domain.AccessSurface {
	access.ManualConfirmations = nil
	return access
}

func missingAppHostMutationConfirmations(required []string, confirmations []string) []string {
	confirmed := map[string]struct{}{}
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation != "" {
			confirmed[confirmation] = struct{}{}
		}
	}
	missing := []string{}
	for _, requiredConfirmation := range required {
		requiredConfirmation = strings.TrimSpace(requiredConfirmation)
		if requiredConfirmation == "" {
			continue
		}
		if _, ok := confirmed[requiredConfirmation]; !ok {
			missing = append(missing, requiredConfirmation)
		}
	}
	return missing
}

func appHostMutationConfirmationAccepted(required []string, confirmations []string, confirmation string) bool {
	confirmation = strings.TrimSpace(confirmation)
	if confirmation == "" {
		return false
	}
	requiredMatch := false
	for _, requiredConfirmation := range required {
		if strings.TrimSpace(requiredConfirmation) == confirmation {
			requiredMatch = true
			break
		}
	}
	if !requiredMatch {
		return false
	}
	for _, submitted := range confirmations {
		if strings.TrimSpace(submitted) == confirmation {
			return true
		}
	}
	return false
}

func unexpectedAppHostMutationConfirmations(required []string, confirmations []string) []string {
	requiredSet := map[string]struct{}{}
	for _, requiredConfirmation := range required {
		requiredConfirmation = strings.TrimSpace(requiredConfirmation)
		if requiredConfirmation != "" {
			requiredSet[requiredConfirmation] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	unexpected := []string{}
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation == "" {
			continue
		}
		if _, duplicate := seen[confirmation]; duplicate {
			continue
		}
		seen[confirmation] = struct{}{}
		if _, ok := requiredSet[confirmation]; !ok {
			unexpected = append(unexpected, confirmation)
		}
	}
	return unexpected
}

func sameStringSet(left []string, right []string) bool {
	left = compactSortedStrings(left)
	right = compactSortedStrings(right)
	return reflect.DeepEqual(left, right)
}

func compactSortedStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	sort.Strings(cleaned)
	return cleaned
}

func exposurePlanWithModifiedPaths(plan domain.ExposurePlan, modifiedPaths []string) domain.ExposurePlan {
	plan.ModifiedPaths = append([]string(nil), modifiedPaths...)
	return plan
}

func cliExposurePlanObservations(configPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation, permissions preflight.PermissionState) (exposure.AppObservations, error) {
	observations := cliObservedBrowserAuthObservations(cfg)
	if cfg.Access.OriginProtection.Mode != appconfig.OriginProtectionModeEdgeOne {
		return observations, nil
	}
	edgeOneObservations := cliObservedEdgeOneOriginProtectionObservations(configPath, cfg, operation, permissions)
	if edgeOneObservations.OriginProtectionStatus != "" {
		observations.OriginProtectionStatus = edgeOneObservations.OriginProtectionStatus
		observations.OriginProtectionReferenceDigest = edgeOneObservations.OriginProtectionReferenceDigest
		observations.RealIPTrustedCIDRCount = edgeOneObservations.RealIPTrustedCIDRCount
		observations.RealIPClientIPHeader = edgeOneObservations.RealIPClientIPHeader
		observations.RealIPSpoofingRejection = edgeOneObservations.RealIPSpoofingRejection
	}
	return observations, nil
}

func cliObservedBrowserAuthObservations(cfg appconfig.Config) exposure.AppObservations {
	if !cfg.BrowserAuthEnabled() {
		return exposure.AppObservations{}
	}
	checked, ready, _ := detectAppBrowserAuthFileStateFn(cfg)
	status := domain.DiagnosticStatusUnknown
	if checked {
		status = domain.DiagnosticStatusFail
		if ready {
			status = domain.DiagnosticStatusPass
		}
	}
	observations := exposure.AppObservations{}
	if checked && !ready {
		observations.BrowserAuthRuntimeStatus = domain.DiagnosticStatusFail
	}
	if checked && ready {
		observations.BrowserAuthRuntimeStatus = domain.DiagnosticStatusPass
	}
	if strings.TrimSpace(cfg.Access.BrowserAuth.Managed.HtpasswdPath) != "" {
		observations.BrowserAuthMarkerStatus = status
	}
	return observations
}

func ObservedBrowserAuthObservations(cfg appconfig.Config) exposure.AppObservations {
	return cliObservedBrowserAuthObservations(cfg)
}

func cliObservedEdgeOneOriginProtectionObservations(configPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation, permissions preflight.PermissionState) exposure.AppObservations {
	profileName := strings.TrimSpace(cfg.EffectiveRealIPProfileName())
	if profileName == "" {
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail)
	}
	profile, ok := cfg.RealIPProfile(profileName)
	if !ok || !profile.IsEnabled() || profile.Provider != appconfig.RealIPProviderEdgeOne {
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail)
	}
	switch operation {
	case domain.ExposurePlanOperationDeploy:
		return cliObservedDeployEdgeOneOriginProtectionObservations(configPath, cfg, permissions)
	case domain.ExposurePlanOperationRealIPRefresh:
		return cliObservedDeployedEdgeOneOriginProtectionObservations(configPath, profileName, permissions)
	case domain.ExposurePlanOperationBrowserAuthRotate:
		return cliObservedDeployedEdgeOneOriginProtectionObservations(configPath, profileName, permissions)
	default:
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredUnknown)
	}
}

func edgeOneOriginProtectionObservation(status domain.OriginProtectionStatus) exposure.AppObservations {
	return exposure.AppObservations{OriginProtectionStatus: status}
}

func cliObservedDeployEdgeOneOriginProtectionObservations(configPath string, cfg appconfig.Config, permissions preflight.PermissionState) exposure.AppObservations {
	if !permissions.IsRoot {
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredManual)
	}
	runtimeConfigPath, err := realIPRuntimeAppConfigPath(configPath)
	if err != nil {
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail)
	}
	privilege := deployPrivilegeStrategy(permissions)
	fileSystem := newAppHostFileSystemFn(newHostExecutorFn(nil).WithPrivilege(privilege), privilege)
	if _, _, _, err := prepareAppRealIPProfile(stdcontext.Background(), cfg, fileSystem, runtimeConfigPath); err != nil {
		return edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err))
	}
	return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredManual)
}

func cliObservedDeployedEdgeOneOriginProtectionObservations(configPath string, profileName string, permissions preflight.PermissionState) exposure.AppObservations {
	if !permissions.IsRoot {
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredManual)
	}
	runtimeConfigPath, err := realIPRuntimeAppConfigPath(configPath)
	if err != nil {
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail)
	}
	names, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, "")
	if err != nil {
		return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail)
	}
	privilege := deployPrivilegeStrategy(permissions)
	fileSystem := newAppHostFileSystemFn(newHostExecutorFn(nil).WithPrivilege(privilege), privilege)
	if err := guardRealIPProfileDirectories(fileSystem, names); err != nil {
		return edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err))
	}
	lock, err := acquireRealIPProfileLockFn(profileName)
	if err != nil {
		return edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err))
	}
	finish := func(observations exposure.AppObservations) exposure.AppObservations {
		if err := lock.Release(); err != nil {
			return edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail)
		}
		return observations
	}
	if err := validateDeployedRealIPRefreshService(names.RefreshServicePath, realIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne), profileName, runtimeConfigPath); err != nil {
		return finish(edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err)))
	}
	profile, err := readDeployedRealIPProfileFn(names.MetadataPath)
	if err != nil {
		return finish(edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err)))
	}
	if profile.Name != profileName || profile.Provider != appconfig.RealIPProviderEdgeOne {
		return finish(edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail))
	}
	state, err := readDeployedRealIPStateFn(names.StatePath, profileName)
	if err != nil {
		return finish(edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err)))
	}
	if err := ensureDeployedRealIPStateMatchesProfile(profile, state); err != nil {
		return finish(edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail))
	}
	references, err := readDeployedRealIPReferencesFn(names.ReferenceDir)
	if err != nil {
		return finish(edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err)))
	}
	if len(references) == 0 {
		return finish(edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredUnknown))
	}
	if _, err := loadEdgeOneCredentialsFn(edgeone.OSFileSystem{}, profile.EnvFile); err != nil {
		return finish(edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err)))
	}
	marker := realIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne)
	if _, err := deployedRealIPRegularFileStatus(names.NginxIncludePath); err != nil {
		return finish(edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err)))
	}
	if err := validateDeployedRealIPNginxInclude(names.NginxIncludePath, marker, state.TrustedCIDRs); err != nil {
		return finish(edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail))
	}
	if _, err := deployedRealIPRegularFileStatus(names.TrustedCIDRPath); err != nil {
		return finish(edgeOneOriginProtectionObservation(originProtectionStatusFromObservationError(err)))
	}
	if err := validateDeployedRealIPTrustedCIDRInclude(names.TrustedCIDRPath, marker, state.TrustedCIDRs); err != nil {
		return finish(edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail))
	}
	referenceDigest, err := realIPReferenceDigest(references)
	if err != nil {
		return finish(edgeOneOriginProtectionObservation(domain.OriginProtectionConfiguredFail))
	}
	return finish(exposure.AppObservations{
		OriginProtectionStatus:          domain.OriginProtectionConfiguredPass,
		OriginProtectionReferenceDigest: referenceDigest,
		RealIPTrustedCIDRCount:          len(state.TrustedCIDRs),
		RealIPClientIPHeader:            appconfig.RealIPHeaderEdgeOne,
		RealIPSpoofingRejection:         domain.DiagnosticStatusPass,
	})
}

func realIPReferenceDigest(references []realip.Reference) (string, error) {
	canonical := make([]realip.Reference, 0, len(references))
	for _, reference := range references {
		item := realip.Reference{
			AppName: strings.TrimSpace(reference.AppName),
			Profile: strings.TrimSpace(reference.Profile),
			Domains: append([]string(nil), reference.Domains...),
		}
		sort.Strings(item.Domains)
		canonical = append(canonical, item)
	}
	sort.Slice(canonical, func(i int, j int) bool {
		if canonical[i].AppName != canonical[j].AppName {
			return canonical[i].AppName < canonical[j].AppName
		}
		return canonical[i].Profile < canonical[j].Profile
	})
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal realip references for exposure digest: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func originProtectionStatusFromObservationError(err error) domain.OriginProtectionStatus {
	if err == nil {
		return domain.OriginProtectionConfiguredManual
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist) {
		return domain.OriginProtectionConfiguredUnknown
	}
	return domain.OriginProtectionConfiguredFail
}

func appCheckpointDesiredStateDigest(staged []apprender.StagedFile) (string, error) {
	staged = append([]apprender.StagedFile(nil), staged...)
	sort.Slice(staged, func(i int, j int) bool {
		if staged[i].HostPath != staged[j].HostPath {
			return staged[i].HostPath < staged[j].HostPath
		}
		return staged[i].SourcePath < staged[j].SourcePath
	})
	type stagedDigestEntry struct {
		SourcePath    string `json:"source_path"`
		HostPath      string `json:"host_path"`
		ContentMode   string `json:"content_mode"`
		Mode          string `json:"mode"`
		ContentDigest string `json:"content_digest"`
	}
	entries := make([]stagedDigestEntry, 0, len(staged))
	for _, file := range staged {
		sum := sha256.Sum256(file.Content)
		entries = append(entries, stagedDigestEntry{
			SourcePath:    file.SourcePath,
			HostPath:      file.HostPath,
			ContentMode:   string(file.ContentMode),
			Mode:          fmt.Sprintf("%04o", file.Mode.Perm()),
			ContentDigest: "sha256:" + hex.EncodeToString(sum[:]),
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("marshal app checkpoint desired state: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func appCheckpointDesiredStateDigestForConfig(cfg appconfig.Config) (string, error) {
	staged, err := apprender.StageRuntime(cfg)
	if err != nil {
		return "", fmt.Errorf("stage app runtime for checkpoint digest: %w", err)
	}
	return appCheckpointDesiredStateDigest(staged)
}

type appCheckpointPersistor struct {
	store      state.Store
	checkpoint *state.Checkpoint
}

func beginAppHostCheckpoint(ctx stdcontext.Context, configPath string, desiredStateDigest string, startedCheckpoint string, executor host.Executor, fileSystem host.FileSystem) (state.Store, state.Checkpoint, error) {
	store := state.NewStore(state.DefaultCheckpointPath(configPath))
	checkpoint, err := store.Load()
	if err != nil {
		return store, state.Checkpoint{}, fmt.Errorf("load app checkpoint: %w", err)
	}
	if checkpoint.HasMutationSnapshots() {
		if err := restoreAppHostCheckpointSnapshots(ctx, executor, fileSystem, checkpoint); err != nil {
			return store, state.Checkpoint{}, fmt.Errorf("restore pending app checkpoint rollback snapshots: %w", err)
		}
		checkpoint.ClearMutationSnapshots()
		if err := store.Save(checkpoint); err != nil {
			return store, state.Checkpoint{}, fmt.Errorf("clear restored app checkpoint rollback snapshots: %w", err)
		}
	}
	checkpoint.DesiredStateDigest = strings.TrimSpace(desiredStateDigest)
	checkpoint.CurrentCheckpoint = ""
	checkpoint.CompletedCheckpoints = nil
	checkpoint.ModifiedPaths = nil
	checkpoint.ActivationHistory = nil
	checkpoint.RecordFailure(workflow.FailureSnapshot{})
	checkpoint.MarkCompleted(startedCheckpoint)
	if err := store.Save(checkpoint); err != nil {
		return store, state.Checkpoint{}, fmt.Errorf("save app checkpoint: %w", err)
	}
	return store, checkpoint, nil
}

func newAppCheckpointPersistor(store state.Store, checkpoint *state.Checkpoint) appCheckpointPersistor {
	return appCheckpointPersistor{store: store, checkpoint: checkpoint}
}

func (persistor appCheckpointPersistor) save() error {
	if persistor.checkpoint == nil {
		return fmt.Errorf("app checkpoint is required")
	}
	if err := persistor.store.Save(*persistor.checkpoint); err != nil {
		return fmt.Errorf("save app checkpoint rollback snapshots: %w", err)
	}
	return nil
}

func (persistor appCheckpointPersistor) recordFileSnapshots(snapshots []state.FileSnapshot) error {
	if persistor.checkpoint == nil || len(snapshots) == 0 {
		return nil
	}
	persistor.checkpoint.SetRuntimeFileSnapshots(appendUniqueStateFileSnapshots(persistor.checkpoint.RuntimeFileSnapshots, snapshots))
	return persistor.save()
}

func (persistor appCheckpointPersistor) recordDirectorySnapshots(snapshots []state.DirectorySnapshot) error {
	if persistor.checkpoint == nil || len(snapshots) == 0 {
		return nil
	}
	persistor.checkpoint.SetDirectorySnapshots(appendUniqueStateDirectorySnapshots(persistor.checkpoint.DirectorySnapshots, snapshots))
	return persistor.save()
}

func (persistor appCheckpointPersistor) recordSymlinkSnapshots(snapshots []state.SymlinkSnapshot) error {
	if persistor.checkpoint == nil || len(snapshots) == 0 {
		return nil
	}
	persistor.checkpoint.SetSymlinkSnapshots(appendUniqueStateSymlinkSnapshots(persistor.checkpoint.SymlinkSnapshots, snapshots))
	return persistor.save()
}

func (persistor appCheckpointPersistor) recordSystemdUnitSnapshots(snapshots []state.SystemdUnitSnapshot) error {
	if persistor.checkpoint == nil || len(snapshots) == 0 {
		return nil
	}
	persistor.checkpoint.SetSystemdUnitSnapshots(appendUniqueStateSystemdUnitSnapshots(persistor.checkpoint.SystemdUnitSnapshots, snapshots))
	return persistor.save()
}

func (persistor appCheckpointPersistor) clearMutationSnapshots() error {
	if persistor.checkpoint == nil || !persistor.checkpoint.ClearMutationSnapshots() {
		return nil
	}
	return persistor.save()
}

func appendUniqueStateFileSnapshots(existing []state.FileSnapshot, additions []state.FileSnapshot) []state.FileSnapshot {
	merged := append([]state.FileSnapshot(nil), existing...)
	seen := map[string]struct{}{}
	for _, snapshot := range merged {
		if path := filepath.Clean(strings.TrimSpace(snapshot.HostPath)); path != "" && path != "." {
			seen[path] = struct{}{}
		}
	}
	for _, snapshot := range additions {
		path := filepath.Clean(strings.TrimSpace(snapshot.HostPath))
		if path == "" || path == "." {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		snapshot.HostPath = path
		snapshot.Content = append([]byte(nil), snapshot.Content...)
		merged = append(merged, snapshot)
	}
	return merged
}

func appendUniqueStateDirectorySnapshots(existing []state.DirectorySnapshot, additions []state.DirectorySnapshot) []state.DirectorySnapshot {
	merged := append([]state.DirectorySnapshot(nil), existing...)
	seen := map[string]struct{}{}
	for _, snapshot := range merged {
		if path := filepath.Clean(strings.TrimSpace(snapshot.Path)); path != "" && path != "." {
			seen[path] = struct{}{}
		}
	}
	for _, snapshot := range additions {
		path := filepath.Clean(strings.TrimSpace(snapshot.Path))
		if path == "" || path == "." {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		snapshot.Path = path
		merged = append(merged, snapshot)
	}
	return merged
}

func appendUniqueStateSymlinkSnapshots(existing []state.SymlinkSnapshot, additions []state.SymlinkSnapshot) []state.SymlinkSnapshot {
	merged := append([]state.SymlinkSnapshot(nil), existing...)
	seen := map[string]struct{}{}
	for _, snapshot := range merged {
		if path := filepath.Clean(strings.TrimSpace(snapshot.Path)); path != "" && path != "." {
			seen[path] = struct{}{}
		}
	}
	for _, snapshot := range additions {
		path := filepath.Clean(strings.TrimSpace(snapshot.Path))
		if path == "" || path == "." {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		snapshot.Path = path
		snapshot.Target = strings.TrimSpace(snapshot.Target)
		merged = append(merged, snapshot)
	}
	return merged
}

func appendUniqueStateSystemdUnitSnapshots(existing []state.SystemdUnitSnapshot, additions []state.SystemdUnitSnapshot) []state.SystemdUnitSnapshot {
	merged := append([]state.SystemdUnitSnapshot(nil), existing...)
	seen := map[string]struct{}{}
	for _, snapshot := range merged {
		if unit := strings.TrimSpace(snapshot.Unit); unit != "" {
			seen[unit] = struct{}{}
		}
	}
	for _, snapshot := range additions {
		unit := strings.TrimSpace(snapshot.Unit)
		if unit == "" {
			continue
		}
		if _, ok := seen[unit]; ok {
			continue
		}
		seen[unit] = struct{}{}
		snapshot.Unit = unit
		snapshot.EnabledState = strings.TrimSpace(snapshot.EnabledState)
		snapshot.ActiveState = strings.TrimSpace(snapshot.ActiveState)
		merged = append(merged, snapshot)
	}
	return merged
}

func restoreAppHostCheckpointSnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, checkpoint state.Checkpoint) error {
	if fileSystem == nil {
		return fmt.Errorf("host file system is required for app checkpoint rollback")
	}
	systemdSnapshots := appSystemdSnapshotsFromState(checkpoint.SystemdUnitSnapshots)
	mutatedUnits := map[string]bool{}
	for _, snapshot := range systemdSnapshots {
		mutatedUnits[snapshot.unit] = true
	}
	if len(systemdSnapshots) > 0 {
		if err := prepareAppSystemdUnitRollback(ctx, executor, systemdSnapshots, mutatedUnits); err != nil {
			return err
		}
	}
	if err := restoreStateFileSnapshots(ctx, executor, fileSystem, checkpoint.RuntimeFileSnapshots); err != nil {
		return err
	}
	if err := restoreStateSymlinkSnapshots(ctx, executor, checkpoint.SymlinkSnapshots); err != nil {
		return err
	}
	if err := restoreStateDirectorySnapshots(ctx, executor, fileSystem, checkpoint.DirectorySnapshots); err != nil {
		return err
	}
	if len(systemdSnapshots) > 0 {
		if err := finishAppSystemdUnitRollback(ctx, executor, systemdSnapshots, mutatedUnits, nil); err != nil {
			return err
		}
	} else if len(checkpoint.RuntimeFileSnapshots) > 0 || len(checkpoint.SymlinkSnapshots) > 0 || len(checkpoint.DirectorySnapshots) > 0 {
		systemd := newHostSystemdFn(executor)
		if _, err := systemd.DaemonReload(ctx); err != nil {
			return fmt.Errorf("reload systemd after resumed app checkpoint rollback: %w", err)
		}
	}
	if len(checkpoint.RuntimeFileSnapshots) > 0 || len(checkpoint.SymlinkSnapshots) > 0 {
		if _, err := executor.Run(ctx, appsvc.TestNginxCommand()); err != nil {
			return fmt.Errorf("nginx -t after resumed app checkpoint rollback: %w", err)
		}
		if _, err := executor.Run(ctx, appsvc.ReloadNginxCommand()); err != nil {
			return fmt.Errorf("nginx reload after resumed app checkpoint rollback: %w", err)
		}
	}
	return nil
}

func restoreStateFileSnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []state.FileSnapshot) error {
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		path := strings.TrimSpace(snapshot.HostPath)
		if path == "" {
			return fmt.Errorf("checkpoint file snapshot path is required")
		}
		if snapshot.Exists {
			if err := fileSystem.WriteFile(path, snapshot.Content, fs.FileMode(snapshot.Mode).Perm()); err != nil {
				return fmt.Errorf("restore checkpoint file %s: %w", path, err)
			}
			continue
		}
		if err := removePath(ctx, executor, "rollback-checkpoint-file", path); err != nil {
			return fmt.Errorf("remove new checkpoint file %s: %w", path, err)
		}
	}
	return nil
}

func restoreStateSymlinkSnapshots(ctx stdcontext.Context, executor host.Executor, snapshots []state.SymlinkSnapshot) error {
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		path := strings.TrimSpace(snapshot.Path)
		if path == "" {
			return fmt.Errorf("checkpoint symlink snapshot path is required")
		}
		if !snapshot.Exists {
			if err := removePath(ctx, executor, "rollback-checkpoint-symlink", path); err != nil {
				return err
			}
			continue
		}
		target := strings.TrimSpace(snapshot.Target)
		if target == "" {
			return fmt.Errorf("checkpoint symlink snapshot target is required for %s", path)
		}
		if _, err := executor.Run(ctx, host.Command{Name: "ln", Args: []string{"-sfn", "--", target, path}, DisplayName: "rollback-checkpoint-symlink", DisplayArgs: []string{path}}); err != nil {
			return fmt.Errorf("restore checkpoint symlink %s: %w", path, err)
		}
	}
	return nil
}

func restoreStateDirectorySnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []state.DirectorySnapshot) error {
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		path := strings.TrimSpace(snapshot.Path)
		if path == "" {
			return fmt.Errorf("checkpoint directory snapshot path is required")
		}
		if snapshot.Exists {
			if err := fileSystem.MkdirAll(path, 0o755); err != nil {
				return fmt.Errorf("restore checkpoint directory %s: %w", path, err)
			}
			continue
		}
		if _, err := fileSystem.Lstat(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat checkpoint directory %s before removal: %w", path, err)
		}
		if err := removeEmptyDir(ctx, executor, "rollback-checkpoint-directory", path); err != nil {
			return err
		}
	}
	return nil
}

func appSystemdSnapshotsFromState(snapshots []state.SystemdUnitSnapshot) []appSystemdUnitSnapshot {
	converted := make([]appSystemdUnitSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, appSystemdUnitSnapshot{
			unit:         strings.TrimSpace(snapshot.Unit),
			enabledState: strings.TrimSpace(snapshot.EnabledState),
			activeState:  strings.TrimSpace(snapshot.ActiveState),
		})
	}
	return converted
}

func stateFileSnapshotFromAppNginx(snapshot appNginxSiteSnapshot) state.FileSnapshot {
	return state.FileSnapshot{
		HostPath: snapshot.availablePath,
		Exists:   snapshot.availableExists,
		Content:  append([]byte(nil), snapshot.availableContent...),
		Mode:     uint32(snapshot.availableMode.Perm()),
	}
}

func stateFileSnapshotsFromAppRuntime(snapshots []appRuntimeFileSnapshot) []state.FileSnapshot {
	converted := make([]state.FileSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, state.FileSnapshot{
			HostPath: snapshot.hostPath,
			Exists:   snapshot.exists,
			Content:  append([]byte(nil), snapshot.content...),
			Mode:     uint32(snapshot.mode.Perm()),
		})
	}
	return converted
}

func stateFileSnapshotFromAppRealIPReference(snapshot appRealIPReferenceSnapshot) state.FileSnapshot {
	return state.FileSnapshot{
		HostPath: snapshot.hostPath,
		Exists:   snapshot.exists,
		Content:  append([]byte(nil), snapshot.content...),
		Mode:     uint32(snapshot.mode.Perm()),
	}
}

func stateFileSnapshotsFromRealIP(snapshots []realIPFileSnapshot) []state.FileSnapshot {
	converted := make([]state.FileSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, state.FileSnapshot{
			HostPath: snapshot.HostPath,
			Exists:   snapshot.Exists,
			Content:  append([]byte(nil), snapshot.Content...),
			Mode:     uint32(snapshot.Mode.Perm()),
		})
	}
	return converted
}

func stateDirectorySnapshotsFromRealIP(snapshots []realIPDirectorySnapshot) []state.DirectorySnapshot {
	converted := make([]state.DirectorySnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, state.DirectorySnapshot{
			Path:   snapshot.Path,
			Exists: snapshot.Exists,
		})
	}
	return converted
}

func stateSymlinkSnapshotFromNginx(snapshot nginxEnabledSymlinkSnapshot) state.SymlinkSnapshot {
	return state.SymlinkSnapshot{
		Path:   snapshot.path,
		Exists: snapshot.exists,
		Target: snapshot.target,
	}
}

func stateSymlinkSnapshotFromAppNginx(snapshot appNginxSiteSnapshot) state.SymlinkSnapshot {
	target := ""
	if snapshot.enabledExists {
		target = snapshot.availablePath
	}
	return state.SymlinkSnapshot{
		Path:   snapshot.enabledPath,
		Exists: snapshot.enabledExists,
		Target: target,
	}
}

func stateSystemdUnitSnapshots(snapshots []appSystemdUnitSnapshot) []state.SystemdUnitSnapshot {
	converted := make([]state.SystemdUnitSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, state.SystemdUnitSnapshot{
			Unit:         snapshot.unit,
			EnabledState: snapshot.enabledState,
			ActiveState:  snapshot.activeState,
		})
	}
	return converted
}

func saveAppHostCheckpointFailure(store state.Store, checkpoint *state.Checkpoint, failedCheckpoint string, retryCommand string, modifiedPaths []string, cause error) error {
	if checkpoint == nil {
		return fmt.Errorf("app checkpoint is required")
	}
	checkpoint.MarkCompleted(failedCheckpoint)
	checkpoint.RecordModifiedPaths(modifiedPaths...)
	checkpoint.RecordFailure(workflow.Failure{
		Step:         failedCheckpoint,
		Operation:    "running app host mutation workflow",
		Impact:       "the app host workflow did not complete and the checkpoint records the retry point",
		Remediation:  []string{"Inspect modified paths and rerun the retry command after fixing the reported error."},
		RetryCommand: retryCommand,
		Cause:        cause,
	}.Snapshot())
	if err := store.Save(*checkpoint); err != nil {
		return fmt.Errorf("save app failure checkpoint: %w", err)
	}
	return nil
}

func saveAppHostCheckpointSuccess(store state.Store, checkpoint *state.Checkpoint, completedCheckpoint string, modifiedPaths []string) error {
	if checkpoint == nil {
		return fmt.Errorf("app checkpoint is required")
	}
	checkpoint.MarkCompleted(completedCheckpoint)
	checkpoint.RecordModifiedPaths(modifiedPaths...)
	checkpoint.FinalizeSuccessfulDeploy()
	if err := store.Save(*checkpoint); err != nil {
		return fmt.Errorf("save app success checkpoint: %w", err)
	}
	return nil
}

func retryCommandWithConfirmations(retryCommand string, confirmations []string) string {
	retryCommand = strings.TrimSpace(retryCommand)
	if retryCommand == "Management UI" {
		return retryCommand
	}
	for _, confirmation := range confirmations {
		confirmation = strings.TrimSpace(confirmation)
		if confirmation == "" {
			continue
		}
		retryCommand = strings.TrimSpace(retryCommand + " " + workflow.ShellCommand("--confirmation", confirmation))
	}
	return retryCommand
}

func runAppDeploy(ctx Context, options appOptions) (result Result, returnErr error) {
	appDeployRetryCommand := retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", options.configPath), options.confirmations)
	var appCheckpointStore state.Store
	var appCheckpoint state.Checkpoint
	appCheckpointReady := false
	appDeployFailure := func(response commandResponse) (Result, error) {
		result := appFailureOperationResult(domain.JobKindAppDeploy, response, appDeployRetryCommand, appHostMutationBlockedProgress(domain.JobKindAppDeploy))
		resultErr := appFailureError(response)
		if appCheckpointReady {
			if checkpointErr := saveAppHostCheckpointFailure(appCheckpointStore, &appCheckpoint, appCheckpointDeployStarted, result.Operation.RetryCommand, result.Operation.ModifiedPaths, resultErr); checkpointErr != nil {
				resultErr = fmt.Errorf("%w; persist checkpoint failed: %v", resultErr, checkpointErr)
			}
		}
		return result, resultErr
	}
	cfg, response, ok := loadAppConfigForResponse(options.configPath, "app deploy")
	if !ok {
		return appDeployFailure(response)
	}
	if err := appguard.ValidateAgainstMainConfig(cfg); err != nil {
		return appDeployFailure(appMainConfigConflictResponse(options.configPath, "app deploy", err))
	}
	effects := appDeployEffects{}
	permissions := detectPermissionStateFn()
	if !permissions.IsRoot {
		return appDeployFailure(appDeployRootRequiredResponse(permissions))
	}
	exposurePlan, err := approvedAppHostMutationExposurePlan(options.approvedExposurePlan, cfg, options.configPath, ctx.Version, permissions, domain.ExposurePlanOperationDeploy, []string(options.confirmations))
	if err != nil {
		return appDeployFailure(invalidExposurePlanResponse("app deploy", err))
	}
	appDeployFailureWithEffects := func(summary string, cause error, effects appDeployEffects) (Result, error) {
		fields := effects.Fields()
		plan := exposurePlanWithModifiedPaths(exposurePlan, effects.ModifiedPaths())
		result, resultErr := appDeployFailureWithFieldsPathsPlan(summary, cause, fields, effects.ModifiedPaths(), &plan, appDeployRetryCommand)
		if appCheckpointReady {
			if checkpointErr := saveAppHostCheckpointFailure(appCheckpointStore, &appCheckpoint, appCheckpointDeployStarted, result.Operation.RetryCommand, effects.ModifiedPaths(), cause); checkpointErr != nil {
				resultErr = fmt.Errorf("%w; persist checkpoint failed: %v", resultErr, checkpointErr)
			}
		}
		return result, resultErr
	}

	dns := detectAppDNSFn(cfg)
	binaryOK, binaryPath := detectAppServiceBinary(cfg)
	appListenChecked, appListenReady, appListenDetail := detectAppListenPortStateFn(cfg)
	dnsCredentialsChecked, dnsCredentialsReady, dnsCredentialsDetail := detectAppDNSCredentialStateFn(cfg)
	serviceEnvFileChecked, serviceEnvFileReady, serviceEnvFileDetail := detectAppServiceEnvFileStateFn(cfg)
	authKeyFileChecked, authKeyFileReady, authKeyFileDetail := detectAppTailscaleAuthKeyFileStateFn(cfg)
	goAccessAuthChecked, goAccessAuthReady, goAccessAuthDetail := detectAppGoAccessAuthFileStateFn(cfg)
	browserAuthChecked, browserAuthReady, browserAuthDetail := detectAppBrowserAuthFileStateFn(cfg)
	goAccessPortChecked, goAccessPortReady, goAccessPortDetail := detectAppGoAccessPortStateFn(cfg)
	goAccessLocaleChecked, goAccessLocaleReady, goAccessLocaleDetail := detectAppGoAccessLocaleStateFn(cfg)
	goAccessLogChecked, goAccessLogReady, goAccessLogDetail := detectAppGoAccessLogFileStateFn(cfg)
	preflightReport := apppreflight.BuildReport(cfg, apppreflight.Inputs{
		Permissions:                 permissions,
		DNS:                         dns,
		Ports:                       detectAppPortBindingsFn(),
		AppListenChecked:            appListenChecked,
		AppListenReady:              appListenReady,
		AppListenDetail:             appListenDetail,
		ServiceBinaryOK:             binaryOK,
		ServiceBinaryPath:           binaryPath,
		ServiceEnvFile:              cfg.Service.EnvFile,
		ServiceEnvFileChecked:       serviceEnvFileChecked,
		ServiceEnvFileReady:         serviceEnvFileReady,
		ServiceEnvFileDetail:        serviceEnvFileDetail,
		TailscaleRequired:           cfg.RequiresTailscale(),
		TailscaleAuthKeyFile:        cfg.Tailscale.AuthKeyFile,
		TailscaleAuthKeyFileChecked: authKeyFileChecked,
		TailscaleAuthKeyFileReady:   authKeyFileReady,
		TailscaleAuthKeyFileDetail:  authKeyFileDetail,
		DNSCredentialsChecked:       dnsCredentialsChecked,
		DNSCredentialsReady:         dnsCredentialsReady,
		DNSCredentialsDetail:        dnsCredentialsDetail,
		GoAccessAuthFileChecked:     goAccessAuthChecked,
		GoAccessAuthFileReady:       goAccessAuthReady,
		GoAccessAuthFileDetail:      goAccessAuthDetail,
		GoAccessPortChecked:         goAccessPortChecked,
		GoAccessPortReady:           goAccessPortReady,
		GoAccessPortDetail:          goAccessPortDetail,
		GoAccessLocaleChecked:       goAccessLocaleChecked,
		GoAccessLocaleReady:         goAccessLocaleReady,
		GoAccessLocaleDetail:        goAccessLocaleDetail,
		GoAccessLogFileChecked:      goAccessLogChecked,
		GoAccessLogFileReady:        goAccessLogReady,
		GoAccessLogFileDetail:       goAccessLogDetail,
		BrowserAuthFileChecked:      browserAuthChecked,
		BrowserAuthFileReady:        browserAuthReady,
		BrowserAuthFileDetail:       browserAuthDetail,
		OriginProtectionStatus:      exposurePlan.OriginProtection,
		OriginProtectionManualConfirmed: appHostMutationConfirmationAccepted(
			exposurePlan.Decision.RequiredConfirmations,
			[]string(options.confirmations),
			appOriginProtectionManualConfirmation,
		),
	})
	if preflightReport.FailedCount() > 0 {
		return appDeployFailure(commandResponse{
			Command:     "app deploy",
			Status:      "blocked",
			Summary:     preflightReport.Summary(),
			Fields:      appPreflightFields(preflightReport),
			Diagnostics: appPreflightDiagnostics(preflightReport),
			NextSteps:   preflightReport.NextSteps(),
		})
	}

	names, err := appsvc.NewNames(cfg)
	if err != nil {
		return appDeployFailureWithEffects("Failed to build app runtime names", err, effects)
	}
	staged, err := stageAppRuntimeFilesFn(cfg)
	if err != nil {
		return appDeployFailure(commandResponse{
			Command: "app deploy",
			Status:  "failed",
			Summary: "App runtime template rendering failed",
			Fields:  []domain.ResultField{{Label: "details", Value: err.Error()}},
		})
	}
	staticReport := appverify.StaticReport(cfg, staged)
	if staticReport.FailedCount() > 0 {
		return appDeployFailure(commandResponse{
			Command:   "app deploy",
			Status:    "failed",
			Summary:   staticReport.Summary(),
			Fields:    []domain.ResultField{{Label: "checks", Value: appverify.SummarizeChecks(staticReport.Checks)}},
			NextSteps: []string{"Run the Management UI verification first, then fix the failed static checks."},
		})
	}
	checkpointDigest, err := appCheckpointDesiredStateDigest(staged)
	if err != nil {
		return appDeployFailure(commandResponse{
			Command: "app deploy",
			Status:  "failed",
			Summary: "App checkpoint desired state failed",
			Fields:  []domain.ResultField{{Label: "details", Value: err.Error()}},
		})
	}
	executor := newHostExecutorFn(appDependencyProxyEnv(cfg))
	privilege := deployPrivilegeStrategy(permissions)
	privilegedExecutor := executor.WithPrivilege(privilege)
	fileSystem := newAppHostFileSystemFn(privilegedExecutor, privilege)
	systemd := newHostSystemdFn(privilegedExecutor)

	appCheckpointStore, appCheckpoint, err = beginAppHostCheckpoint(stdcontext.Background(), options.configPath, checkpointDigest, appCheckpointDeployStarted, privilegedExecutor, fileSystem)
	if err != nil {
		return appDeployFailure(commandResponse{
			Command: "app deploy",
			Status:  "failed",
			Summary: "App checkpoint initialization failed",
			Fields:  []domain.ResultField{{Label: "details", Value: err.Error()}},
		})
	}
	appCheckpointReady = true
	appCheckpointPersistor := newAppCheckpointPersistor(appCheckpointStore, &appCheckpoint)
	var appSystemdSnapshots []appSystemdUnitSnapshot
	appSystemdSnapshotTaken := false
	appSystemdUnitMutated := map[string]bool{}
	markAppSystemdUnitMutated := func(unit string) {
		unit = strings.TrimSpace(unit)
		if unit != "" {
			appSystemdUnitMutated[unit] = true
		}
	}
	var realIPLock realIPProfileLock
	realIPLockReleased := false
	releaseRealIPLock := func() error {
		if realIPLock == nil || realIPLockReleased {
			return nil
		}
		realIPLockReleased = true
		return realIPLock.Release()
	}
	defer func() {
		if returnErr == nil {
			return
		}
		if err := releaseRealIPLock(); err != nil {
			returnErr = fmt.Errorf("%w; release EdgeOne realip profile lock failed: %v", returnErr, err)
		}
	}()
	realIPPrepared := false
	var realIPNames appsvc.RealIPProfileNames
	var realIPState realip.State
	var realIPSharedStaged []realiprender.StagedFile
	var realIPReferenceStaged []realiprender.StagedFile
	if cfg.RealIPEnabled() {
		realIPRuntimeConfigPath, err := realIPRuntimeAppConfigPath(options.configPath)
		if err != nil {
			return appDeployFailureWithEffects("Failed to prepare EdgeOne realip profile", err, effects)
		}
		realIPLock, err = acquireRealIPProfileLockFn(cfg.EffectiveRealIPProfileName())
		if err != nil {
			return appDeployFailureWithEffects("Failed to lock EdgeOne realip profile", err, effects)
		}
		preparedNames, preparedState, preparedStaged, err := prepareAppRealIPProfile(stdcontext.Background(), cfg, fileSystem, realIPRuntimeConfigPath)
		if err != nil {
			return appDeployFailureWithEffects("Failed to prepare EdgeOne realip profile", err, effects)
		}
		sharedStaged, referenceStaged, err := splitAppRealIPStagedFiles(preparedStaged, preparedNames.ReferencePathForApp)
		if err != nil {
			return appDeployFailureWithEffects("Failed to prepare EdgeOne realip profile", err, effects)
		}
		realIPPrepared = true
		realIPNames = preparedNames
		realIPState = preparedState
		realIPSharedStaged = sharedStaged
		realIPReferenceStaged = referenceStaged
	}
	if err := guardAppOwnership(fileSystem, cfg, staged); err != nil {
		return appDeployFailure(commandResponse{
			Command:   "app deploy",
			Status:    "blocked",
			Summary:   "Target file exists and is not a Lanpanel-managed file for this app",
			Fields:    []domain.ResultField{{Label: "details", Value: err.Error()}},
			NextSteps: []string{"Inspect the conflicting file, then migrate/delete it manually or change app.name."},
		})
	}
	if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardEnabledSiteCommand(names)); err != nil {
		return appDeployFailure(commandResponse{
			Command:   "app deploy",
			Status:    "blocked",
			Summary:   "Nginx enabled site exists and does not belong to this app",
			Fields:    []domain.ResultField{{Label: "details", Value: err.Error()}},
			NextSteps: []string{"Inspect the conflicting Nginx enabled site, then migrate/delete it manually or change app.name."},
		})
	}

	if !cfg.Nginx.GoAccess.Enabled {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardManagedGoAccessRuntimeRemovalCommand(names)); err != nil {
			return appDeployFailureWithEffects("GoAccess stale runtime removal check failed", err, effects)
		}
		effects.AddActions("checked stale GoAccess runtime removal candidates")
	} else if !appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardManagedGoAccessLogrotateRemovalCommand(names)); err != nil {
			return appDeployFailureWithEffects("GoAccess stale logrotate removal check failed", err, effects)
		}
		effects.AddActions("checked stale GoAccess logrotate removal candidate")
	}

	goAccessPostCutoverCleanupDone := false
	var goAccessAppListenBlockers []preflight.PortBinding
	var goAccessAppPortBlockers []preflight.PortBinding
	cleanupStaleGoAccessPostCutover := func() (string, error) {
		if goAccessPostCutoverCleanupDone {
			return "", nil
		}
		goAccessPostCutoverCleanupDone = true
		if !cfg.Nginx.GoAccess.Enabled {
			removedPaths, err := removeStaleGoAccessRuntime(stdcontext.Background(), privilegedExecutor, names)
			effects.AddPaths(removedPaths...)
			if len(removedPaths) > 0 {
				effects.AddActions("removed stale GoAccess runtime")
			}
			if err != nil {
				return "Failed to remove stale GoAccess runtime", err
			}
			if hasString(removedPaths, "/etc/systemd/system/"+names.GoAccessServiceUnit) {
				if _, err := systemd.DaemonReload(stdcontext.Background()); err != nil {
					return "systemd daemon-reload failed", err
				}
				effects.AddActions("systemd daemon-reload")
			}
			return "", nil
		}
		if !appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
			removedPaths, err := removeStaleGoAccessLogrotate(stdcontext.Background(), privilegedExecutor, names)
			effects.AddPaths(removedPaths...)
			if len(removedPaths) > 0 {
				effects.AddActions("removed stale GoAccess logrotate")
			}
			if err != nil {
				return "Failed to remove stale GoAccess logrotate", err
			}
		}
		return "", nil
	}

	if cfg.Nginx.GoAccess.Enabled {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardGoAccessAuthFileMetadataCommand(names, cfg.Nginx.GoAccess.AuthBasicUserFile)); err != nil {
			return appDeployFailureWithEffects("GoAccess basic auth file metadata check failed", err, effects)
		}
		effects.AddActions("checked GoAccess basic auth file metadata")
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardGoAccessSystemUserCommand(names)); err != nil {
			return appDeployFailureWithEffects("GoAccess system user/group conflict", err, effects)
		}
		effects.AddActions("checked GoAccess system user/group")
		if appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardGoAccessLogDirectoryCommand(names)); err != nil {
				return appDeployFailureWithEffects("GoAccess log directory ownership check failed", err, effects)
			}
			effects.AddActions("checked GoAccess log directory ownership")
		}
	}

	if cfg.RequiresTailscale() {
		tailscaleResult, err := ensureAppTailscale(stdcontext.Background(), cfg, privilegedExecutor)
		effects.AddTailscaleResult(tailscaleResult)
		if err != nil {
			return appDeployFailureWithEffects("Tailscale client prerequisite failed", err, effects)
		}
	}

	if cfg.Mode() == appconfig.ModeListen {
		blockers, detected := detectAppGoAccessAppListenBlockersFn(cfg, names)
		if !detected {
			return appDeployFailureWithEffects("GoAccess current listener check failed", fmt.Errorf("could not confirm current managed GoAccess listener state before app listener reuse"), effects)
		}
		goAccessAppListenBlockers = blockers
	}
	if cfg.Nginx.GoAccess.Enabled {
		blockers, detected := detectAppGoAccessAppPortBlockersFn(cfg, names)
		if !detected {
			return appDeployFailureWithEffects("app current listener check failed", fmt.Errorf("could not confirm current managed app listener state before GoAccess listener reuse"), effects)
		}
		goAccessAppPortBlockers = blockers
	}

	if cfg.Nginx.GoAccess.Enabled && !appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
		for _, command := range appsvc.EnsureGoAccessSystemUserCommands(names) {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), command); err != nil {
				return appDeployFailureWithEffects("Failed to create or confirm GoAccess system user/group", err, effects)
			}
		}
		effects.AddActions("ensured GoAccess system user/group")
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardGoAccessCanonicalLogReadableCommand(names)); err != nil {
			return appDeployFailureWithEffects("GoAccess canonical access log readability check failed", err, effects)
		}
		effects.AddActions("checked explicit GoAccess access log readability")
	}

	effects.AddActions("started app host dependency check/install")
	if err := ensureAppHostDependencies(stdcontext.Background(), cfg, privilegedExecutor); err != nil {
		return appDeployFailureWithEffects("Failed to install app host dependencies", err, effects)
	}
	effects.AddActions("ensured app host dependencies")
	if cfg.BrowserAuthEnabled() {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardBrowserAuthFileCommand(names, cfg.BrowserAuthUserFile())); err != nil {
			return appDeployFailureWithEffects("browser auth file check failed", err, effects)
		}
		if strings.TrimSpace(cfg.Access.BrowserAuth.Managed.HtpasswdPath) != "" {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardManagedBrowserAuthFileCommand(names, cfg.BrowserAuthUserFile())); err != nil {
				return appDeployFailureWithEffects("managed browser auth file check failed", err, effects)
			}
		}
		effects.AddActions("checked browser auth file")
	}
	if cfg.Nginx.GoAccess.Enabled {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardGoAccessAuthFileCommand(names, cfg.Nginx.GoAccess.AuthBasicUserFile)); err != nil {
			return appDeployFailureWithEffects("GoAccess basic auth file check failed", err, effects)
		}
		effects.AddActions("checked GoAccess basic auth file")
		if appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
			for _, command := range appsvc.EnsureGoAccessSystemUserCommands(names) {
				if _, err := privilegedExecutor.Run(stdcontext.Background(), command); err != nil {
					return appDeployFailureWithEffects("Failed to create or confirm GoAccess system user/group", err, effects)
				}
			}
			effects.AddActions("ensured GoAccess system user/group")
		}
	}
	nginxSystemdSnapshots, err := snapshotAppSystemdUnits(stdcontext.Background(), privilegedExecutor, []string{"nginx.service"})
	if err != nil {
		return appDeployFailureWithEffects("Nginx systemd state snapshot failed", err, effects)
	}
	appSystemdSnapshots = appendUniqueAppSystemdUnitSnapshots(appSystemdSnapshots, nginxSystemdSnapshots)
	appSystemdSnapshotTaken = true
	if err := appCheckpointPersistor.recordSystemdUnitSnapshots(stateSystemdUnitSnapshots(nginxSystemdSnapshots)); err != nil {
		return appDeployFailureWithEffects("Nginx systemd state snapshot persistence failed", err, effects)
	}
	markAppSystemdUnitMutated("nginx.service")
	if _, err := privilegedExecutor.Systemctl(stdcontext.Background(), "enable", "--now", "nginx.service"); err != nil {
		return appDeployFailureWithEffects("Failed to start Nginx service", err, effects)
	}
	effects.AddActions("enabled and started Nginx service")
	defaultSiteSnapshot, err := snapshotNginxEnabledSymlink(stdcontext.Background(), privilegedExecutor, fileSystem, nginxcomponent.DefaultSiteEnabledPath, "Nginx default site")
	if err != nil {
		return appDeployFailureWithEffects("Failed to snapshot Nginx default site", err, effects)
	}
	if err := appCheckpointPersistor.recordSymlinkSnapshots([]state.SymlinkSnapshot{stateSymlinkSnapshotFromNginx(defaultSiteSnapshot)}); err != nil {
		return appDeployFailureWithEffects("Failed to persist Nginx default site rollback snapshot", err, effects)
	}
	defaultSiteMutated := false
	failAfterDefaultSiteMutation := func(summary string, err error) (Result, error) {
		if defaultSiteMutated {
			if rollbackErr := restoreNginxEnabledSymlink(stdcontext.Background(), privilegedExecutor, defaultSiteSnapshot, "rollback-nginx-default-site"); rollbackErr != nil {
				err = fmt.Errorf("%w; rollback Nginx default site failed: %v", err, rollbackErr)
			}
			defaultSiteMutated = false
		}
		return appDeployFailureWithEffects(summary, err, effects)
	}
	if _, err := privilegedExecutor.Run(stdcontext.Background(), nginxcomponent.DisableDefaultSiteCommand()); err != nil {
		return appDeployFailureWithEffects("Failed to disable Nginx default site", err, effects)
	}
	defaultSiteMutated = true
	effects.AddPaths(nginxcomponent.DefaultSiteEnabledPath)
	effects.AddActions("disabled distro Nginx default site if present")
	if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardDefaultServerCommand(names)); err != nil {
		return failAfterDefaultSiteMutation("Nginx default_server conflict", err)
	}
	if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardServerNameConflictsCommand(names, cfg.App.Domains)); err != nil {
		return failAfterDefaultSiteMutation("Nginx server_name conflict", err)
	}
	if realIPPrepared {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardRealIPConflictsCommand(names, realIPNames)); err != nil {
			return failAfterDefaultSiteMutation("Nginx realip directive conflict", err)
		}
		effects.AddActions("checked Nginx realip directive conflicts")
	}
	if err := ensureAppNginxCompatibilityFn(stdcontext.Background(), cfg, privilegedExecutor); err != nil {
		return failAfterDefaultSiteMutation("Nginx runtime compatibility check failed", err)
	}
	effects.AddActions("checked Nginx runtime compatibility")
	if cfg.Nginx.GoAccess.Enabled {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardGoAccessWebSocketPortAssignmentCommand(names)); err != nil {
			return failAfterDefaultSiteMutation("GoAccess WebSocket port assignment conflict", err)
		}
		effects.AddActions("checked GoAccess WebSocket port assignment")
	}
	if cfg.Mode() == appconfig.ModeListen {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardSystemUserCommand(names)); err != nil {
			return failAfterDefaultSiteMutation("app system user/group conflict", err)
		}
		effects.AddActions("checked app system user/group")
	}
	browserAuthBootstrapFile := ""
	if cfg.BrowserAuthEnabled() && filepath.Clean(strings.TrimSpace(cfg.Access.BrowserAuth.AuthBasicUserFile)) == names.BrowserSuggestedAuthBasicUserFile {
		browserAuthBootstrapFile = cfg.Access.BrowserAuth.AuthBasicUserFile
	}
	goAccessAuthBootstrapFile := ""
	if cfg.Nginx.GoAccess.Enabled {
		goAccessAuthBootstrapFile = cfg.Nginx.GoAccess.AuthBasicUserFile
	}
	rootGuardCommand := appsvc.GuardRootDirectoriesCommand(names)
	if browserAuthBootstrapFile != "" || goAccessAuthBootstrapFile != "" {
		rootGuardCommand = appsvc.GuardRootDirectoriesWithAuthBootstrapsCommand(names, browserAuthBootstrapFile, goAccessAuthBootstrapFile)
	}
	if _, err := privilegedExecutor.Run(stdcontext.Background(), rootGuardCommand); err != nil {
		return failAfterDefaultSiteMutation("app root directory ownership check failed", err)
	}
	effects.AddPaths(names.VarLibDir, names.VarLibMarkerPath, names.EtcDir, names.EtcMarkerPath, names.HookDir, names.HookDirMarkerPath)
	effects.AddActions("checked app root directory ownership")
	if cfg.Mode() == appconfig.ModeListen {
		for _, command := range appsvc.EnsureSystemUserCommands(names) {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), command); err != nil {
				return failAfterDefaultSiteMutation("Failed to create or confirm app system user/group", err)
			}
		}
		effects.AddActions("ensured app system user/group")
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardServiceAccessCommand(names, cfg.ServiceBinary(), cfg.Service.WorkingDirectory)); err != nil {
			return failAfterDefaultSiteMutation("app service user access check failed", err)
		}
		effects.AddActions("checked app service user access")
	}
	if cfg.Nginx.GoAccess.Enabled {
		for _, command := range appsvc.EnsureGoAccessDirectoryCommands(names, appsvc.GoAccessManagesCanonicalAccessLog(cfg)) {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), command); err != nil {
				return failAfterDefaultSiteMutation("Failed to create GoAccess directories", err)
			}
		}
		if appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardManagedGoAccessCanonicalLogReadableCommand(names)); err != nil {
				return failAfterDefaultSiteMutation("GoAccess canonical access log readability check failed", err)
			}
			effects.AddActions("checked managed GoAccess access log readability")
		}
		effects.AddPaths(names.GoAccessReportDir, names.GoAccessDBPath)
		if appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
			effects.AddPaths(names.GoAccessLogDir, names.GoAccessLogDirMarkerPath, names.GoAccessCanonicalAccessLogPath)
		}
	}
	for _, command := range appsvc.EnsureDirectoryCommands(names) {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), command); err != nil {
			return failAfterDefaultSiteMutation("Failed to create app directories", err)
		}
	}
	effects.AddPaths(names.WebrootPath, names.LegoDataPath, names.TLSDir)
	if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardTLSOwnershipCommand(names)); err != nil {
		return failAfterDefaultSiteMutation("app TLS certificate directory ownership check failed", err)
	}
	effects.AddPaths(names.TLSMarkerPath)

	realIPSharedInstalled := false
	realIPSharedCommitted := false
	realIPSharedSnapshotTaken := false
	var realIPSharedSnapshots []realIPFileSnapshot
	var realIPSharedDirectorySnapshots []realIPDirectorySnapshot
	installRealIPSharedArtifacts := func() (string, error) {
		if !realIPPrepared || realIPSharedInstalled {
			return "", nil
		}
		if err := guardRealIPProfileDirectories(fileSystem, realIPNames); err != nil {
			return "Failed to write EdgeOne realip profile artifacts", err
		}
		if len(realIPSharedStaged) == 0 {
			return "Failed to write EdgeOne realip profile artifacts", fmt.Errorf("no shared realip artifacts staged for profile %s", realIPNames.ProfileName)
		}
		if !realIPSharedSnapshotTaken {
			directorySnapshots, err := snapshotRealIPDirectories(fileSystem, realIPNames)
			if err != nil {
				return "Failed to write EdgeOne realip profile artifacts", err
			}
			snapshots, err := snapshotRealIPFiles(fileSystem, realIPSharedStaged, false)
			if err != nil {
				return "Failed to write EdgeOne realip profile artifacts", err
			}
			realIPSharedSnapshots = snapshots
			realIPSharedDirectorySnapshots = directorySnapshots
			realIPSharedSnapshotTaken = true
			if err := appCheckpointPersistor.recordDirectorySnapshots(stateDirectorySnapshotsFromRealIP(directorySnapshots)); err != nil {
				return "Failed to write EdgeOne realip profile artifacts", err
			}
			if err := appCheckpointPersistor.recordFileSnapshots(stateFileSnapshotsFromRealIP(snapshots)); err != nil {
				return "Failed to write EdgeOne realip profile artifacts", err
			}
		}
		results, err := newAppFileInstallerFn(privilegedExecutor, privilege).Install(realiprender.ConvertStagedFiles(realIPSharedStaged))
		effects.AddPaths(host.CollectModifiedPaths(results)...)
		if err != nil {
			if rollbackErr := restoreRealIPDeploySnapshots(stdcontext.Background(), privilegedExecutor, fileSystem, realIPSharedSnapshots, realIPSharedDirectorySnapshots); rollbackErr != nil {
				return "Failed to write EdgeOne realip profile artifacts", fmt.Errorf("%w; rollback EdgeOne realip profile artifacts failed: %v", err, rollbackErr)
			}
			return "Failed to write EdgeOne realip profile artifacts", err
		}
		effects.AddActions("prepared EdgeOne realip profile " + realIPNames.ProfileName)
		realIPSharedInstalled = true
		return "", nil
	}
	var appNginxSnapshot appNginxSiteSnapshot
	appNginxSnapshotTaken := false
	var appRuntimeSnapshots []appRuntimeFileSnapshot
	appRuntimeSnapshotTaken := false
	appNginxRuntimeInstalled := false
	appNginxReloadAttempted := false
	realIPNginxReloadAttempted := false
	realIPReferenceInstalled := false
	var realIPReferenceSnapshot appRealIPReferenceSnapshot
	realIPReferenceSnapshotTaken := false
	failAfterRealIPSharedInstall := func(summary string, err error) (Result, error) {
		if realIPPrepared && realIPSharedInstalled && !realIPSharedCommitted {
			err = rollbackRealIPDeploy(stdcontext.Background(), privilegedExecutor, fileSystem, realIPSharedSnapshots, realIPSharedDirectorySnapshots, err, realIPNginxReloadAttempted)
			realIPSharedInstalled = false
			realIPSharedCommitted = false
		}
		if defaultSiteMutated {
			if rollbackErr := restoreNginxEnabledSymlink(stdcontext.Background(), privilegedExecutor, defaultSiteSnapshot, "rollback-nginx-default-site"); rollbackErr != nil {
				err = fmt.Errorf("%w; rollback Nginx default site failed: %v", err, rollbackErr)
			}
			defaultSiteMutated = false
		}
		return appDeployFailureWithEffects(summary, err, effects)
	}
	failAfterAppNginxMutation := func(summary string, err error, verifyRestored bool) (Result, error) {
		systemdRollbackPrepared := false
		if appSystemdSnapshotTaken && len(appSystemdUnitMutated) > 0 {
			if rollbackErr := prepareAppSystemdUnitRollback(stdcontext.Background(), privilegedExecutor, appSystemdSnapshots, appSystemdUnitMutated); rollbackErr != nil {
				return appDeployFailureWithEffects(summary, fmt.Errorf("%w; rollback app systemd units failed: %v", err, rollbackErr), effects)
			}
			systemdRollbackPrepared = true
		}
		appRuntimeRestored := false
		if appRuntimeSnapshotTaken && appNginxRuntimeInstalled {
			if rollbackErr := restoreAppRuntimeFiles(stdcontext.Background(), privilegedExecutor, fileSystem, appRuntimeSnapshots); rollbackErr != nil {
				return appDeployFailureWithEffects(summary, fmt.Errorf("%w; rollback app runtime files failed: %v", err, rollbackErr), effects)
			}
			appRuntimeRestored = true
		}
		if appNginxSnapshotTaken && appNginxRuntimeInstalled {
			if rollbackErr := restoreAppNginxSite(stdcontext.Background(), privilegedExecutor, fileSystem, appNginxSnapshot); rollbackErr != nil {
				return appDeployFailureWithEffects(summary, fmt.Errorf("%w; rollback app Nginx site failed: %v", err, rollbackErr), effects)
			}
		}
		if realIPReferenceSnapshotTaken && realIPReferenceInstalled {
			if rollbackErr := restoreAppRealIPReference(stdcontext.Background(), privilegedExecutor, fileSystem, realIPReferenceSnapshot); rollbackErr != nil {
				return appDeployFailureWithEffects(summary, fmt.Errorf("%w; rollback app realip reference failed: %v", err, rollbackErr), effects)
			}
			realIPReferenceInstalled = false
		}
		if defaultSiteMutated {
			if rollbackErr := restoreNginxEnabledSymlink(stdcontext.Background(), privilegedExecutor, defaultSiteSnapshot, "rollback-nginx-default-site"); rollbackErr != nil {
				return appDeployFailureWithEffects(summary, fmt.Errorf("%w; rollback Nginx default site failed: %v", err, rollbackErr), effects)
			}
			defaultSiteMutated = false
		}
		if realIPPrepared && realIPSharedInstalled {
			err = rollbackRealIPDeploy(stdcontext.Background(), privilegedExecutor, fileSystem, realIPSharedSnapshots, realIPSharedDirectorySnapshots, err, realIPNginxReloadAttempted || appNginxReloadAttempted)
			realIPSharedInstalled = false
			realIPSharedCommitted = false
			if systemdRollbackPrepared {
				err = finishAppSystemdUnitRollback(stdcontext.Background(), privilegedExecutor, appSystemdSnapshots, appSystemdUnitMutated, err)
			}
			return appDeployFailureWithEffects(summary, err, effects)
		}
		if systemdRollbackPrepared {
			err = finishAppSystemdUnitRollback(stdcontext.Background(), privilegedExecutor, appSystemdSnapshots, appSystemdUnitMutated, err)
		}
		if appRuntimeRestored && verifyRestored {
			err = activateRestoredAppRuntime(stdcontext.Background(), privilegedExecutor, err, appNginxReloadAttempted)
		}
		return appDeployFailureWithEffects(summary, err, effects)
	}
	if summary, err := installRealIPSharedArtifacts(); err != nil {
		return appDeployFailureWithEffects(summary, err, effects)
	}

	snapshot, err := snapshotAppNginxSite(fileSystem, names)
	if err != nil {
		return failAfterRealIPSharedInstall("Failed to write app runtime files", err)
	}
	appNginxSnapshot = snapshot
	appNginxSnapshotTaken = true
	if err := appCheckpointPersistor.recordFileSnapshots([]state.FileSnapshot{stateFileSnapshotFromAppNginx(appNginxSnapshot)}); err != nil {
		return failAfterRealIPSharedInstall("Failed to persist app Nginx rollback snapshot", err)
	}
	if err := appCheckpointPersistor.recordSymlinkSnapshots([]state.SymlinkSnapshot{stateSymlinkSnapshotFromAppNginx(appNginxSnapshot)}); err != nil {
		return failAfterRealIPSharedInstall("Failed to persist app Nginx rollback snapshot", err)
	}
	runtimeSnapshotStaged := append([]apprender.StagedFile(nil), staged...)
	if cfg.Mode() == appconfig.ModeUpstream {
		runtimeSnapshotStaged = append(runtimeSnapshotStaged, apprender.StagedFile{HostPath: "/etc/systemd/system/" + names.ServiceUnit})
	}
	goAccessUnitPath := "/etc/systemd/system/" + names.GoAccessServiceUnit
	if !cfg.Nginx.GoAccess.Enabled {
		runtimeSnapshotStaged = append(runtimeSnapshotStaged,
			apprender.StagedFile{HostPath: goAccessUnitPath},
			apprender.StagedFile{HostPath: names.GoAccessConfigPath},
			apprender.StagedFile{HostPath: names.GoAccessLogrotatePath},
		)
	} else if !appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
		runtimeSnapshotStaged = append(runtimeSnapshotStaged, apprender.StagedFile{HostPath: names.GoAccessLogrotatePath})
	}
	snapshots, err := snapshotAppRuntimeFiles(fileSystem, runtimeSnapshotStaged)
	if err != nil {
		return failAfterRealIPSharedInstall("Failed to write app runtime files", err)
	}
	appRuntimeSnapshots = snapshots
	appRuntimeSnapshotTaken = true
	if err := appCheckpointPersistor.recordFileSnapshots(stateFileSnapshotsFromAppRuntime(appRuntimeSnapshots)); err != nil {
		return failAfterRealIPSharedInstall("Failed to persist app runtime rollback snapshots", err)
	}
	goAccessSystemdRollbackNeeded := cfg.Nginx.GoAccess.Enabled || appRuntimeSnapshotExists(appRuntimeSnapshots, goAccessUnitPath)
	results, err := newAppFileInstallerFn(privilegedExecutor, privilege).Install(convertAppStagedFiles(staged))
	effects.AddPaths(host.CollectModifiedPaths(results)...)
	if err != nil {
		appNginxRuntimeInstalled = true
		return failAfterAppNginxMutation("Failed to write app runtime files", err, false)
	}
	appNginxRuntimeInstalled = true
	installRealIPReferenceBeforeNginxReload := func() (string, error) {
		if !realIPPrepared || realIPReferenceInstalled {
			return "", nil
		}
		if err := guardRealIPProfileDirectories(fileSystem, realIPNames); err != nil {
			return "Failed to write app realip reference", err
		}
		if len(realIPReferenceStaged) == 0 {
			return "Failed to write app realip reference", fmt.Errorf("no app realip reference staged for profile %s", realIPNames.ProfileName)
		}
		if !realIPReferenceSnapshotTaken {
			snapshot, err := snapshotAppRealIPReference(fileSystem, realIPNames.ReferencePathForApp)
			if err != nil {
				return "Failed to write app realip reference", err
			}
			realIPReferenceSnapshot = snapshot
			realIPReferenceSnapshotTaken = true
			if err := appCheckpointPersistor.recordFileSnapshots([]state.FileSnapshot{stateFileSnapshotFromAppRealIPReference(realIPReferenceSnapshot)}); err != nil {
				return "Failed to write app realip reference", err
			}
		}
		results, err := newAppFileInstallerFn(privilegedExecutor, privilege).Install(realiprender.ConvertStagedFiles(realIPReferenceStaged))
		effects.AddPaths(host.CollectModifiedPaths(results)...)
		if err != nil {
			if rollbackErr := restoreAppRealIPReference(stdcontext.Background(), privilegedExecutor, fileSystem, realIPReferenceSnapshot); rollbackErr != nil {
				return "Failed to write app realip reference", fmt.Errorf("%w; rollback app realip reference failed: %v", err, rollbackErr)
			}
			return "Failed to write app realip reference", err
		}
		effects.AddActions("registered app realip reference")
		realIPReferenceInstalled = true
		return "", nil
	}
	if cfg.Nginx.GoAccess.Enabled {
		if _, err := privilegedExecutor.Run(stdcontext.Background(), appsvc.GuardGoAccessRuntimeAccessCommand(names)); err != nil {
			return failAfterAppNginxMutation("GoAccess runtime permission check failed", err, false)
		}
		effects.AddActions("checked GoAccess runtime permissions")
	}
	if _, err := systemd.DaemonReload(stdcontext.Background()); err != nil {
		return failAfterAppNginxMutation("systemd daemon-reload failed", err, false)
	}
	effects.AddActions("systemd daemon-reload")
	appRuntimeSystemdSnapshots, err := snapshotAppSystemdUnits(stdcontext.Background(), privilegedExecutor, appSystemdRollbackUnits(cfg, names, realIPNames, realIPPrepared, goAccessSystemdRollbackNeeded))
	if err != nil {
		return failAfterAppNginxMutation("systemd unit state snapshot failed", err, false)
	}
	appSystemdSnapshots = appendUniqueAppSystemdUnitSnapshots(appSystemdSnapshots, appRuntimeSystemdSnapshots)
	appSystemdSnapshotTaken = true
	if err := appCheckpointPersistor.recordSystemdUnitSnapshots(stateSystemdUnitSnapshots(appRuntimeSystemdSnapshots)); err != nil {
		return failAfterAppNginxMutation("systemd unit state snapshot persistence failed", err, false)
	}

	appServicePreparedBeforeListenerCutover := false
	appServiceRemovedBeforeListenerCutover := false
	startAppServiceBeforeListenerCutover := func(restartAction string) (string, error) {
		if appServicePreparedBeforeListenerCutover {
			return "", nil
		}
		markAppSystemdUnitMutated(names.ServiceUnit)
		if _, err := systemd.Enable(stdcontext.Background(), names.ServiceUnit); err != nil {
			return "Failed to enable app service before listener reuse", err
		}
		effects.AddActions("enabled app systemd service")
		markAppSystemdUnitMutated(names.ServiceUnit)
		if _, err := systemd.Restart(stdcontext.Background(), names.ServiceUnit); err != nil {
			return "Failed to restart app service before listener reuse", err
		}
		effects.AddActions(restartAction)
		appServicePreparedBeforeListenerCutover = true
		return "", nil
	}
	removeAppServiceBeforeListenerCutover := func() (string, error) {
		if appServiceRemovedBeforeListenerCutover {
			return "", nil
		}
		markAppSystemdUnitMutated(names.ServiceUnit)
		removedPaths, err := removeStaleAppServiceUnit(stdcontext.Background(), privilegedExecutor, names)
		effects.AddPaths(removedPaths...)
		if len(removedPaths) > 0 {
			effects.AddActions("removed stale app systemd service before GoAccess listener reuse")
		}
		if err != nil {
			return "Failed to remove stale app service before GoAccess listener reuse", err
		}
		if _, err := systemd.DaemonReload(stdcontext.Background()); err != nil {
			return "systemd daemon-reload failed", err
		}
		effects.AddActions("systemd daemon-reload")
		appServiceRemovedBeforeListenerCutover = true
		return "", nil
	}
	clearGoAccessAppListenBlockersBeforeNginxReload := func() (string, error) {
		if len(goAccessAppListenBlockers) == 0 {
			return "", nil
		}
		markAppSystemdUnitMutated(names.GoAccessServiceUnit)
		if _, err := systemd.Stop(stdcontext.Background(), names.GoAccessServiceUnit); err != nil {
			return "Failed to stop current GoAccess service before app listener reuse", err
		}
		effects.AddActions("stopped GoAccess systemd service before app listener reuse")
		return startAppServiceBeforeListenerCutover("restarted app systemd service before app listener reuse")
	}
	clearGoAccessAppPortBlockersBeforeNginxReload := func() (string, error) {
		if len(goAccessAppPortBlockers) == 0 || appServicePreparedBeforeListenerCutover || appServiceRemovedBeforeListenerCutover {
			return "", nil
		}
		switch cfg.Mode() {
		case appconfig.ModeListen:
			return startAppServiceBeforeListenerCutover("restarted app systemd service before GoAccess listener reuse")
		case appconfig.ModeUpstream:
			return removeAppServiceBeforeListenerCutover()
		}
		return "", nil
	}
	activateAppNginxBeforeReload := func() (string, error) {
		if summary, err := installRealIPSharedArtifacts(); err != nil {
			return summary, err
		}
		if summary, err := installRealIPReferenceBeforeNginxReload(); err != nil {
			return summary, err
		}
		rollbackReferenceFailure := func(summary string, err error) (string, error) {
			if !realIPReferenceSnapshotTaken || !realIPReferenceInstalled {
				return summary, err
			}
			if rollbackErr := restoreAppRealIPReference(stdcontext.Background(), privilegedExecutor, fileSystem, realIPReferenceSnapshot); rollbackErr != nil {
				return summary, fmt.Errorf("%w; rollback app realip reference failed: %v", err, rollbackErr)
			}
			realIPReferenceInstalled = false
			return summary, err
		}
		if err := prepareAppNginxActivation(stdcontext.Background(), privilegedExecutor, names, &effects); err != nil {
			return rollbackReferenceFailure("Failed to enable app Nginx site", err)
		}
		if summary, err := clearGoAccessAppListenBlockersBeforeNginxReload(); err != nil {
			return rollbackReferenceFailure(summary, err)
		}
		if summary, err := clearGoAccessAppPortBlockersBeforeNginxReload(); err != nil {
			return rollbackReferenceFailure(summary, err)
		}
		if realIPPrepared {
			realIPNginxReloadAttempted = true
		}
		appNginxReloadAttempted = true
		if err := reloadAppNginxTracking(stdcontext.Background(), privilegedExecutor, &effects); err != nil {
			return rollbackReferenceFailure("Failed to enable app Nginx site", err)
		}
		if realIPPrepared {
			realIPSharedCommitted = true
		}
		return "", nil
	}

	if cfg.App.ACMEChallenge == appconfig.ACMEChallengeHTTP01 {
		for _, command := range appsvc.HTTP01BootstrapCommands(names) {
			if _, err := privilegedExecutor.Run(stdcontext.Background(), command); err != nil {
				return failAfterAppNginxMutation("Failed to prepare HTTP-01 bootstrap certificate", err, appNginxReloadAttempted)
			}
		}
		effects.AddPaths(names.WebrootPath, names.LegoDataPath, names.TLSDir, names.FullchainPath, names.PrivateKeyPath)
		effects.AddActions("prepared HTTP-01 bootstrap certificate")
		if summary, err := activateAppNginxBeforeReload(); err != nil {
			return failAfterAppNginxMutation(summary, err, true)
		}
		if goAccessSystemdRollbackNeeded && !cfg.Nginx.GoAccess.Enabled {
			markAppSystemdUnitMutated(names.GoAccessServiceUnit)
		}
		if summary, err := cleanupStaleGoAccessPostCutover(); err != nil {
			return failAfterAppNginxMutation(summary, err, appNginxReloadAttempted)
		}
	}
	certPlan, err := appsvc.NewCertificatePlan(cfg, names)
	if err != nil {
		return failAfterAppNginxMutation("Failed to build app TLS certificate plan", err, appNginxReloadAttempted)
	}
	if _, err := privilegedExecutor.Run(stdcontext.Background(), legocomponent.MigrationGateCommand(names.LegoDataPath)); err != nil {
		return failAfterAppNginxMutation("Failed to migrate app lego v5 storage", err, appNginxReloadAttempted)
	}
	if _, err := privilegedExecutor.Run(stdcontext.Background(), certPlan.Command); err != nil {
		return failAfterAppNginxMutation("Failed to issue app TLS certificate", err, appNginxReloadAttempted)
	}
	effects.AddPaths(names.LegoDataPath, names.FullchainPath, names.PrivateKeyPath)
	effects.AddActions("issued or renewed app certificate")
	if cfg.App.ACMEChallenge != appconfig.ACMEChallengeHTTP01 {
		if summary, err := activateAppNginxBeforeReload(); err != nil {
			return failAfterAppNginxMutation(summary, err, true)
		}
		if goAccessSystemdRollbackNeeded && !cfg.Nginx.GoAccess.Enabled {
			markAppSystemdUnitMutated(names.GoAccessServiceUnit)
		}
		if summary, err := cleanupStaleGoAccessPostCutover(); err != nil {
			return failAfterAppNginxMutation(summary, err, appNginxReloadAttempted)
		}
	}

	if cfg.Mode() == appconfig.ModeUpstream && !appServiceRemovedBeforeListenerCutover {
		markAppSystemdUnitMutated(names.ServiceUnit)
		removedPaths, err := removeStaleAppServiceUnit(stdcontext.Background(), privilegedExecutor, names)
		effects.AddPaths(removedPaths...)
		if len(removedPaths) > 0 {
			effects.AddActions("removed stale app systemd service")
		}
		if err != nil {
			return failAfterAppNginxMutation("Failed to remove stale app service", err, appNginxReloadAttempted)
		}
		if _, err := systemd.DaemonReload(stdcontext.Background()); err != nil {
			return failAfterAppNginxMutation("systemd daemon-reload failed", err, appNginxReloadAttempted)
		}
		effects.AddActions("systemd daemon-reload")
	}

	if cfg.Mode() == appconfig.ModeListen && !appServicePreparedBeforeListenerCutover {
		markAppSystemdUnitMutated(names.ServiceUnit)
		if _, err := systemd.Enable(stdcontext.Background(), names.ServiceUnit); err != nil {
			return failAfterAppNginxMutation("Failed to enable app service", err, appNginxReloadAttempted)
		}
		effects.AddActions("enabled app systemd service")
		markAppSystemdUnitMutated(names.ServiceUnit)
		if _, err := systemd.Restart(stdcontext.Background(), names.ServiceUnit); err != nil {
			return failAfterAppNginxMutation("Failed to restart app service", err, appNginxReloadAttempted)
		}
		effects.AddActions("restarted app systemd service")
	}
	if cfg.Nginx.GoAccess.Enabled {
		markAppSystemdUnitMutated(names.GoAccessServiceUnit)
		if _, err := systemd.Enable(stdcontext.Background(), names.GoAccessServiceUnit); err != nil {
			return failAfterAppNginxMutation("Failed to enable GoAccess service", err, appNginxReloadAttempted)
		}
		effects.AddActions("enabled GoAccess systemd service")
		markAppSystemdUnitMutated(names.GoAccessServiceUnit)
		if _, err := systemd.Restart(stdcontext.Background(), names.GoAccessServiceUnit); err != nil {
			return failAfterAppNginxMutation("Failed to restart GoAccess service", err, appNginxReloadAttempted)
		}
		effects.AddActions("restarted GoAccess systemd service")
	}
	markAppSystemdUnitMutated(names.RenewTimerUnit)
	if _, err := systemd.Enable(stdcontext.Background(), names.RenewTimerUnit); err != nil {
		return failAfterAppNginxMutation("Failed to enable app certificate renewal timer", err, appNginxReloadAttempted)
	}
	effects.AddActions("enabled app certificate renewal timer")
	markAppSystemdUnitMutated(names.RenewTimerUnit)
	if _, err := systemd.Start(stdcontext.Background(), names.RenewTimerUnit); err != nil {
		return failAfterAppNginxMutation("Failed to start app certificate renewal timer", err, appNginxReloadAttempted)
	}
	effects.AddActions("started app certificate renewal timer")
	if realIPPrepared {
		markAppSystemdUnitMutated(realIPNames.RefreshTimerUnit)
		if _, err := systemd.Enable(stdcontext.Background(), realIPNames.RefreshTimerUnit); err != nil {
			return failAfterAppNginxMutation("Failed to enable realip refresh timer", err, appNginxReloadAttempted)
		}
		effects.AddActions("enabled realip refresh timer")
		markAppSystemdUnitMutated(realIPNames.RefreshTimerUnit)
		if _, err := systemd.Start(stdcontext.Background(), realIPNames.RefreshTimerUnit); err != nil {
			return failAfterAppNginxMutation("Failed to start realip refresh timer", err, appNginxReloadAttempted)
		}
		effects.AddActions("started realip refresh timer")
	}

	if err := releaseRealIPLock(); err != nil {
		return failAfterAppNginxMutation("Failed to release EdgeOne realip profile lock", err, appNginxReloadAttempted)
	}
	if err := cleanupStaleAppRealIPReferences(stdcontext.Background(), privilegedExecutor, cfg.App.Name, cfg.EffectiveRealIPProfileName(), &effects); err != nil {
		return failAfterAppNginxMutation("Failed to clean stale realip references", err, appNginxReloadAttempted)
	}

	fields := append(appConfigFields(options.configPath, cfg),
		domain.ResultField{Label: "nginx site", Value: names.NginxAvailablePath},
		domain.ResultField{Label: "renew timer", Value: names.RenewTimerUnit},
	)
	fields = append(fields, appGoAccessDeployFields(cfg, names)...)
	fields = append(fields, appRealIPDeployFields(cfg, realIPNames, realIPState, realIPPrepared)...)
	fields = append(fields, effects.Fields()...)
	fields = append(fields, appPreflightWarningFields(preflightReport)...)
	nextSteps := []string{
		appDeployRuntimeVerifyStep(options.configPath, cfg),
	}
	nextSteps = append(nextSteps, appGoAccessDeployNextSteps(cfg, names)...)
	nextSteps = append(nextSteps, appPreflightWarningNextSteps(preflightReport)...)
	exposurePlan = exposurePlanWithModifiedPaths(exposurePlan, effects.ModifiedPaths())
	if err := saveAppHostCheckpointSuccess(appCheckpointStore, &appCheckpoint, appCheckpointDeployApplied, effects.ModifiedPaths()); err != nil {
		return appDeployFailureWithFieldsPathsPlan("App checkpoint persistence failed", err, effects.Fields(), effects.ModifiedPaths(), &exposurePlan, appDeployRetryCommand)
	}
	return operationResult("app deploy", "applied", workflow.OperationResult{
		Kind:          domain.JobKindAppDeploy,
		Status:        domain.JobStatusSucceeded,
		Summary:       "App deployed or refreshed from config",
		Fields:        fields,
		Diagnostics:   appPreflightDiagnostics(preflightReport),
		ExposurePlan:  &exposurePlan,
		ModifiedPaths: effects.ModifiedPaths(),
		RetryCommand:  appDeployRetryCommand,
		Progress:      operationProgressEvents(domain.JobKindAppDeploy, "app deploy host workflow started", domain.DiagnosticStatusPass, "app deploy host workflow finished"),
	}, nextSteps), nil
}

func RunAppDeploy(ctx stdcontext.Context, options AppDeployOptions) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{Operation: workflow.OperationResult{
			Kind:         domain.JobKindAppDeploy,
			Status:       domain.JobStatusInterrupted,
			Summary:      "app deploy canceled before host workflow started",
			RetryCommand: retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", options.ConfigPath), options.Confirmations),
		}, OutputStatus: "interrupted"}, err
	}
	restore := applyDependencies(options.Dependencies)
	defer restore()
	result, err := runAppDeploy(Context{Version: options.Version}, appOptions{
		configPath:           options.ConfigPath,
		confirmations:        appConfirmationFlag(options.Confirmations),
		approvedExposurePlan: options.ApprovedExposurePlan,
	})
	if strings.TrimSpace(result.Operation.RetryCommand) == "" {
		result.Operation.RetryCommand = retryCommandWithConfirmations(workflow.ShellCommand("sudo", "lanpanel", "app", "deploy", "--config", options.ConfigPath), options.Confirmations)
	}
	return result, err
}

func appDeployRootRequiredResponse(permissions preflight.PermissionState) commandResponse {
	detail := "fail: app deploy requires root privileges"
	if strings.TrimSpace(permissions.User) != "" {
		detail += ", current user: " + strings.TrimSpace(permissions.User)
	}
	return commandResponse{
		Command:   "app deploy",
		Status:    "blocked",
		Summary:   "app deploy preflight found 1 failed check",
		Fields:    []domain.ResultField{{Label: "check permissions", Value: detail}},
		NextSteps: []string{"Retry the operation from the Management UI with the same settings."},
	}
}

type RealIPProfileLock interface {
	Release() error
}

type realIPProfileLock = RealIPProfileLock

type realIPFileLock struct {
	path string
	file *os.File
}

func SetRealIPLockDir(path string) func() {
	previous := realIPLockDir
	realIPLockDir = strings.TrimSpace(path)
	return func() {
		realIPLockDir = previous
	}
}

func AcquireRealIPProfileLock(profileName string) (RealIPProfileLock, error) {
	return acquireRealIPProfileLock(profileName)
}

func acquireRealIPProfileLock(profileName string) (realIPProfileLock, error) {
	path, err := realIPProfileLockPath(profileName)
	if err != nil {
		return nil, err
	}
	if err := ensureRealIPLockDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := openRealIPLockFile(path)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	lock := &realIPFileLock{path: path, file: file}
	if err := validateRealIPLockFile(file, path); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock realip profile %s with %s: %w", strings.TrimSpace(profileName), path, err)
	}
	return lock, nil
}

func realIPProfileLockPath(profileName string) (string, error) {
	profileName = strings.TrimSpace(profileName)
	if _, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, ""); err != nil {
		return "", fmt.Errorf("realip profile lock name %q is invalid: %w", profileName, err)
	}
	return filepath.Join(realIPLockDir, "lanpanel-realip-"+profileName+".lock"), nil
}

func RealIPProfileLockPath(profileName string) (string, error) {
	return realIPProfileLockPath(profileName)
}

func ensureRealIPLockDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create realip lock directory %s: %w", path, err)
	}
	var stat syscall.Stat_t
	if err := syscall.Lstat(path, &stat); err != nil {
		return fmt.Errorf("stat realip lock directory %s: %w", path, err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("realip lock directory %s must be a directory", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("realip lock directory %s must be owned by root", path)
	}
	if stat.Mode&0o077 != 0 {
		return fmt.Errorf("realip lock directory %s must be root-only, for example mode 0700", path)
	}
	return nil
}

func openRealIPLockFile(path string) (int, error) {
	flags := syscall.O_RDWR | syscall.O_CREAT | syscall.O_EXCL | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	fd, err := syscall.Open(path, flags, 0o600)
	if err == nil {
		return fd, nil
	}
	if !errors.Is(err, syscall.EEXIST) {
		return -1, fmt.Errorf("open realip lock %s: %w", path, err)
	}
	fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err == nil {
		return fd, nil
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		fd, err = syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err == nil {
			return fd, nil
		}
	}
	return -1, fmt.Errorf("open realip lock %s: %w", path, err)
}

func validateRealIPLockFile(file *os.File, path string) error {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return fmt.Errorf("stat realip lock %s: %w", path, err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("realip lock %s must be a regular file", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("realip lock %s must be owned by root", path)
	}
	if stat.Mode&0o077 != 0 {
		return fmt.Errorf("realip lock %s must be root-only, for example mode 0600", path)
	}
	return nil
}

func ValidateRealIPLockFile(file *os.File, path string) error {
	return validateRealIPLockFile(file, path)
}

func (lock *realIPFileLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return fmt.Errorf("unlock realip profile lock %s: %w", lock.path, unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close realip profile lock %s: %w", lock.path, closeErr)
	}
	return nil
}

func loadAppConfigForResponse(path string, command string) (appconfig.Config, commandResponse, bool) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return appconfig.Config{}, commandResponse{
				Command: command,
				Status:  "missing-config",
				Summary: "App config file not found",
				Fields:  []domain.ResultField{{Label: "config path", Value: path}},
				NextSteps: []string{
					fmt.Sprintf("Create the App configuration for %s from the Management UI.", path),
				},
			}, false
		}
		return appconfig.Config{}, commandResponse{Command: command, Status: "failed", Summary: "Failed to stat app config file", Fields: []domain.ResultField{{Label: "details", Value: err.Error()}}}, false
	}
	cfg, err := appconfig.LoadFile(path)
	if err != nil {
		return appconfig.Config{}, commandResponse{
			Command: command,
			Status:  "invalid-config",
			Summary: "App config file exists but validation failed",
			Fields:  []domain.ResultField{{Label: "config path", Value: path}, {Label: "details", Value: err.Error()}},
			NextSteps: []string{
				fmt.Sprintf("Fix %s and rerun the command.", path),
			},
		}, false
	}
	return cfg, commandResponse{}, true
}

func prepareAppRealIPProfile(ctx stdcontext.Context, cfg appconfig.Config, fileSystem host.FileSystem, appConfigPath string) (appsvc.RealIPProfileNames, realip.State, []realiprender.StagedFile, error) {
	profile, reference, enabled, err := realIPProfileFromAppConfig(cfg)
	if err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	if !enabled {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, nil
	}
	names, err := appsvc.NewRealIPProfileNames(profile.Name, profile.Provider, cfg.App.Name)
	if err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	if err := guardRealIPProfileDirectories(fileSystem, names); err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	if existing, ok, err := readRealIPProfileFromFS(fileSystem, names.MetadataPath); err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	} else if ok {
		if err := ensureRealIPProfileCompatible(existing, profile); err != nil {
			return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
		}
	}
	existingReferences, err := readDeployedRealIPReferencesFn(names.ReferenceDir)
	if err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	profile.Domains = domainsFromRealIPReferences(replaceRealIPReferenceForApp(existingReferences, reference))
	credentials, err := loadEdgeOneCredentialsFn(edgeone.OSFileSystem{}, profile.EnvFile)
	if err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	info, err := describeEdgeOneOriginACLFn(ctx, credentials, profile.ZoneID)
	if err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	state, err := edgeone.BuildState(profile.Name, profile.ZoneID, info, profile.Domains, time.Now())
	if err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	staged, err := stageRealIPRuntimeFilesFn(profile, state, reference, appConfigPath)
	if err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	if err := guardRealIPOwnership(fileSystem, profile.Name, profile.Provider, staged); err != nil {
		return appsvc.RealIPProfileNames{}, realip.State{}, nil, err
	}
	return names, state, staged, nil
}

func PrepareAppRealIPProfile(ctx stdcontext.Context, cfg appconfig.Config, fileSystem host.FileSystem, appConfigPath string) (appsvc.RealIPProfileNames, realip.State, []realiprender.StagedFile, error) {
	return prepareAppRealIPProfile(ctx, cfg, fileSystem, appConfigPath)
}

func realIPProfileFromAppConfig(cfg appconfig.Config) (realip.ProfileConfig, realip.Reference, bool, error) {
	profileName := cfg.EffectiveRealIPProfileName()
	if profileName == "" {
		return realip.ProfileConfig{}, realip.Reference{}, false, nil
	}
	profileCfg, ok := cfg.RealIPProfile(profileName)
	if !ok || !profileCfg.IsEnabled() {
		return realip.ProfileConfig{}, realip.Reference{}, false, fmt.Errorf("access.origin_protection.edgeone_profile %q is not an enabled profile", profileName)
	}
	profile := edgeone.ProfileConfig(profileName, profileCfg.EdgeOne.ZoneID, profileCfg.EdgeOne.EnvFile, profileCfg.EffectiveRefreshInterval(), cfg.App.Domains)
	reference := realip.Reference{
		AppName: cfg.App.Name,
		Profile: profileName,
		Domains: append([]string(nil), cfg.App.Domains...),
	}
	return profile, reference, true, nil
}

func guardRealIPOwnership(fileSystem host.FileSystem, profileName string, provider string, staged []realiprender.StagedFile) error {
	marker := realIPManagedMarker(profileName, provider)
	jsonMarker := `"lanpanel_managed": "` + marker + `"`
	for _, file := range staged {
		info, err := fileSystem.Lstat(file.HostPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat existing realip artifact %s: %w", file.HostPath, err)
		}
		if err := validateExistingRealIPArtifactInfo(file.HostPath, info); err != nil {
			return err
		}
		current, err := fileSystem.ReadFile(file.HostPath)
		if err != nil {
			return fmt.Errorf("read existing realip artifact %s: %w", file.HostPath, err)
		}
		text := string(current)
		if strings.Contains(text, marker) || strings.Contains(text, jsonMarker) {
			continue
		}
		return fmt.Errorf("%s exists and is not a Lanpanel-managed realip artifact for profile %s", file.HostPath, profileName)
	}
	return nil
}

func GuardRealIPOwnership(fileSystem host.FileSystem, profileName string, provider string, staged []realiprender.StagedFile) error {
	return guardRealIPOwnership(fileSystem, profileName, provider, staged)
}

func validateExistingRealIPArtifactInfo(path string, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("existing realip artifact %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("existing realip artifact %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("existing realip artifact %s must not be writable by group or others", path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("existing realip artifact %s owner could not be inspected", path)
	}
	if uid != 0 {
		return fmt.Errorf("existing realip artifact %s must be owned by root", path)
	}
	return nil
}

func ValidateExistingRealIPArtifactInfo(path string, info fs.FileInfo) error {
	return validateExistingRealIPArtifactInfo(path, info)
}

func guardRealIPProfileDirectories(fileSystem host.FileSystem, names appsvc.RealIPProfileNames) error {
	if fileSystem == nil {
		fileSystem = host.OSFileSystem{}
	}
	for _, dir := range []struct {
		label string
		path  string
	}{
		{label: "realip Nginx directory", path: names.NginxDir},
		{label: "realip state directory", path: names.StateDir},
		{label: "realip reference directory", path: names.ReferenceDir},
	} {
		if err := validateExistingRealIPDirectoryChain(fileSystem, dir.label, dir.path); err != nil {
			return err
		}
	}
	exists, err := realIPPathExists(fileSystem, names.StateDir)
	if err != nil {
		return err
	}
	if exists {
		return validateExistingRealIPMetadata(fileSystem, names)
	}
	return nil
}

func GuardRealIPProfileDirectories(fileSystem host.FileSystem, names appsvc.RealIPProfileNames) error {
	return guardRealIPProfileDirectories(fileSystem, names)
}

func validateExistingRealIPDirectoryChain(fileSystem host.FileSystem, label string, path string) error {
	return validateExistingRealIPDirectoryChainWithLstat(label, path, fileSystem.Lstat)
}

func validateExistingRealIPDirectoryChainWithLstat(label string, path string, lstat func(string) (fs.FileInfo, error)) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%s path is required and must be absolute", label)
	}
	current := string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(os.PathSeparator)), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := lstat(current)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("stat %s %s: %w", label, current, err)
		}
		if err := validateExistingRealIPDirectoryInfo(label, current, info); err != nil {
			return err
		}
	}
	return nil
}

func validateExistingRealIPDirectoryInfo(label string, path string, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s %s must not be a symlink", label, path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %s must be a directory", label, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s %s must not be writable by group or others", label, path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("%s %s owner could not be inspected", label, path)
	}
	if uid != 0 {
		return fmt.Errorf("%s %s must be owned by root", label, path)
	}
	return nil
}

func realIPPathExists(fileSystem host.FileSystem, path string) (bool, error) {
	_, err := fileSystem.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat realip path %s: %w", path, err)
	}
	return true, nil
}

func validateExistingRealIPMetadata(fileSystem host.FileSystem, names appsvc.RealIPProfileNames) error {
	info, err := fileSystem.Lstat(names.MetadataPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s exists without %s; refusing to write into a non-Lanpanel realip profile root", names.StateDir, names.MetadataPath)
		}
		return fmt.Errorf("stat realip profile metadata %s: %w", names.MetadataPath, err)
	}
	return validateExistingRealIPMetadataInfo(names.MetadataPath, info)
}

func validateExistingRealIPMetadataInfo(path string, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to trust realip profile ownership", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file; refusing to trust realip profile ownership", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be root-only, for example mode 0600", path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("%s owner could not be inspected", path)
	}
	if uid != 0 {
		return fmt.Errorf("%s must be owned by root", path)
	}
	return nil
}

func realIPManagedMarker(profileName string, provider string) string {
	return "Lanpanel-managed: realip.profile=" + strings.TrimSpace(profileName) + " provider=" + strings.TrimSpace(provider)
}

func RealIPManagedMarker(profileName string, provider string) string {
	return realIPManagedMarker(profileName, provider)
}

type appNginxSiteSnapshot struct {
	availablePath    string
	availableExists  bool
	availableContent []byte
	availableMode    fs.FileMode
	enabledPath      string
	enabledExists    bool
}

func snapshotAppNginxSite(fileSystem host.FileSystem, names appsvc.Names) (appNginxSiteSnapshot, error) {
	snapshot := appNginxSiteSnapshot{
		availablePath: strings.TrimSpace(names.NginxAvailablePath),
		enabledPath:   strings.TrimSpace(names.NginxEnabledPath),
	}
	if snapshot.availablePath == "" || snapshot.enabledPath == "" {
		return appNginxSiteSnapshot{}, fmt.Errorf("app Nginx site paths are required")
	}
	info, err := fileSystem.Lstat(snapshot.availablePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, os.ErrNotExist) {
			return appNginxSiteSnapshot{}, fmt.Errorf("stat existing app Nginx site %s: %w", snapshot.availablePath, err)
		}
	} else {
		if info.Mode()&fs.ModeSymlink != 0 {
			return appNginxSiteSnapshot{}, fmt.Errorf("%s is a symlink; refusing to snapshot app Nginx site", snapshot.availablePath)
		}
		if !info.Mode().IsRegular() {
			return appNginxSiteSnapshot{}, fmt.Errorf("%s exists and is not a regular app Nginx site file", snapshot.availablePath)
		}
		content, err := fileSystem.ReadFile(snapshot.availablePath)
		if err != nil {
			return appNginxSiteSnapshot{}, fmt.Errorf("read existing app Nginx site %s: %w", snapshot.availablePath, err)
		}
		snapshot.availableExists = true
		snapshot.availableContent = append([]byte(nil), content...)
		snapshot.availableMode = info.Mode().Perm()
	}
	enabledInfo, err := fileSystem.Lstat(snapshot.enabledPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, os.ErrNotExist) {
			return appNginxSiteSnapshot{}, fmt.Errorf("stat existing enabled app Nginx site %s: %w", snapshot.enabledPath, err)
		}
		return snapshot, nil
	}
	if enabledInfo.Mode()&fs.ModeSymlink == 0 {
		return appNginxSiteSnapshot{}, fmt.Errorf("%s exists and is not an enabled app Nginx symlink", snapshot.enabledPath)
	}
	snapshot.enabledExists = true
	return snapshot, nil
}

func restoreAppNginxSite(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshot appNginxSiteSnapshot) error {
	if strings.TrimSpace(snapshot.availablePath) == "" || strings.TrimSpace(snapshot.enabledPath) == "" {
		return fmt.Errorf("app Nginx site snapshot paths are required")
	}
	if snapshot.availableExists {
		if err := fileSystem.WriteFile(snapshot.availablePath, snapshot.availableContent, snapshot.availableMode); err != nil {
			return fmt.Errorf("restore app Nginx site %s: %w", snapshot.availablePath, err)
		}
	} else if err := removePath(ctx, executor, "rollback-app-nginx-site", snapshot.availablePath); err != nil {
		return err
	}
	if !snapshot.enabledExists {
		if err := removePath(ctx, executor, "rollback-app-nginx-enabled-site", snapshot.enabledPath); err != nil {
			return err
		}
	}
	return nil
}

func rollbackAppNginxSite(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshot appNginxSiteSnapshot, cause error, verifyRestored bool, reloadRestored bool) error {
	if rollbackErr := restoreAppNginxSite(ctx, executor, fileSystem, snapshot); rollbackErr != nil {
		return fmt.Errorf("%w; rollback app Nginx site failed: %v", cause, rollbackErr)
	}
	if !verifyRestored {
		return cause
	}
	if _, err := executor.Run(ctx, appsvc.TestNginxCommand()); err != nil {
		return fmt.Errorf("%w; restored previous app Nginx site but nginx -t still failed: %v", cause, err)
	}
	if reloadRestored {
		if _, err := executor.Run(ctx, appsvc.ReloadNginxCommand()); err != nil {
			return fmt.Errorf("%w; restored previous app Nginx site and nginx -t passed but nginx reload failed: %v", cause, err)
		}
	}
	return cause
}

type nginxEnabledSymlinkSnapshot struct {
	path   string
	exists bool
	target string
}

func snapshotNginxEnabledSymlink(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, path string, label string) (nginxEnabledSymlinkSnapshot, error) {
	snapshot := nginxEnabledSymlinkSnapshot{path: filepath.Clean(strings.TrimSpace(path))}
	if snapshot.path == "" || snapshot.path == "." || !filepath.IsAbs(snapshot.path) {
		return nginxEnabledSymlinkSnapshot{}, fmt.Errorf("%s path is required and must be absolute", label)
	}
	info, err := fileSystem.Lstat(snapshot.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return snapshot, nil
		}
		return nginxEnabledSymlinkSnapshot{}, fmt.Errorf("stat %s %s: %w", label, snapshot.path, err)
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		return nginxEnabledSymlinkSnapshot{}, fmt.Errorf("%s %s exists and is not an enabled Nginx symlink", label, snapshot.path)
	}
	result, err := executor.Run(ctx, host.Command{Name: "readlink", Args: []string{"--", snapshot.path}})
	if err != nil {
		return nginxEnabledSymlinkSnapshot{}, fmt.Errorf("read %s target %s: %w", label, snapshot.path, err)
	}
	target := strings.TrimSpace(result.Stdout)
	if target == "" {
		return nginxEnabledSymlinkSnapshot{}, fmt.Errorf("read %s target %s: empty target", label, snapshot.path)
	}
	snapshot.exists = true
	snapshot.target = target
	return snapshot, nil
}

func restoreNginxEnabledSymlink(ctx stdcontext.Context, executor host.Executor, snapshot nginxEnabledSymlinkSnapshot, displayName string) error {
	if strings.TrimSpace(snapshot.path) == "" {
		return fmt.Errorf("Nginx enabled symlink snapshot path is required")
	}
	if !snapshot.exists {
		return removePath(ctx, executor, displayName, snapshot.path)
	}
	if strings.TrimSpace(snapshot.target) == "" {
		return fmt.Errorf("Nginx enabled symlink snapshot target is required")
	}
	_, err := executor.Run(ctx, host.Command{
		Name:        "ln",
		Args:        []string{"-sfn", "--", snapshot.target, snapshot.path},
		DisplayName: displayName,
		DisplayArgs: []string{snapshot.path},
	})
	return err
}

type appRuntimeFileSnapshot struct {
	hostPath string
	exists   bool
	content  []byte
	mode     fs.FileMode
}

func appRuntimeSnapshotExists(snapshots []appRuntimeFileSnapshot, hostPath string) bool {
	hostPath = filepath.Clean(strings.TrimSpace(hostPath))
	for _, snapshot := range snapshots {
		if filepath.Clean(strings.TrimSpace(snapshot.hostPath)) == hostPath {
			return snapshot.exists
		}
	}
	return false
}

func snapshotAppRuntimeFiles(fileSystem host.FileSystem, staged []apprender.StagedFile) ([]appRuntimeFileSnapshot, error) {
	snapshots := make([]appRuntimeFileSnapshot, 0, len(staged))
	seen := make(map[string]struct{}, len(staged))
	for _, file := range staged {
		hostPath := filepath.Clean(strings.TrimSpace(file.HostPath))
		if hostPath == "" || hostPath == "." || !filepath.IsAbs(hostPath) {
			return nil, fmt.Errorf("app runtime file host path is required and must be absolute")
		}
		if _, ok := seen[hostPath]; ok {
			return nil, fmt.Errorf("duplicate app runtime file host path %s", hostPath)
		}
		seen[hostPath] = struct{}{}

		info, err := fileSystem.Lstat(hostPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				snapshots = append(snapshots, appRuntimeFileSnapshot{hostPath: hostPath})
				continue
			}
			return nil, fmt.Errorf("stat existing app runtime file %s: %w", hostPath, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink; refusing to snapshot app runtime file", hostPath)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s exists and is not a regular app runtime file", hostPath)
		}
		content, err := fileSystem.ReadFile(hostPath)
		if err != nil {
			return nil, fmt.Errorf("read existing app runtime file %s: %w", hostPath, err)
		}
		snapshots = append(snapshots, appRuntimeFileSnapshot{
			hostPath: hostPath,
			exists:   true,
			content:  append([]byte(nil), content...),
			mode:     info.Mode().Perm(),
		})
	}
	return snapshots, nil
}

func restoreAppRuntimeFiles(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []appRuntimeFileSnapshot) error {
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		if strings.TrimSpace(snapshot.hostPath) == "" {
			return fmt.Errorf("app runtime file snapshot path is required")
		}
		if snapshot.exists {
			if err := fileSystem.WriteFile(snapshot.hostPath, snapshot.content, snapshot.mode); err != nil {
				return fmt.Errorf("restore app runtime file %s: %w", snapshot.hostPath, err)
			}
			continue
		}
		if err := removePath(ctx, executor, "rollback-app-runtime-file", snapshot.hostPath); err != nil {
			return fmt.Errorf("remove new app runtime file %s: %w", snapshot.hostPath, err)
		}
	}
	return nil
}

func activateRestoredAppRuntime(ctx stdcontext.Context, executor host.Executor, cause error, reloadRestoredNginx bool) error {
	systemd := newHostSystemdFn(executor)
	if _, err := systemd.DaemonReload(ctx); err != nil {
		return fmt.Errorf("%w; restored previous app runtime files but systemd daemon-reload failed: %v", cause, err)
	}
	if _, err := executor.Run(ctx, appsvc.TestNginxCommand()); err != nil {
		return fmt.Errorf("%w; restored previous app runtime files but nginx -t still failed: %v", cause, err)
	}
	if reloadRestoredNginx {
		if _, err := executor.Run(ctx, appsvc.ReloadNginxCommand()); err != nil {
			return fmt.Errorf("%w; restored previous app runtime files and nginx -t passed but nginx reload failed: %v", cause, err)
		}
	}
	return cause
}

type appSystemdUnitSnapshot struct {
	unit         string
	enabledState string
	activeState  string
}

func appSystemdRollbackUnits(cfg appconfig.Config, names appsvc.Names, realIPNames appsvc.RealIPProfileNames, realIPPrepared bool, includeGoAccess bool) []string {
	units := []string{names.RenewTimerUnit, names.ServiceUnit}
	if includeGoAccess {
		units = append(units, names.GoAccessServiceUnit)
	}
	if realIPPrepared {
		units = append(units, realIPNames.RefreshTimerUnit)
	}
	return units
}

func appendUniqueAppSystemdUnitSnapshots(existing []appSystemdUnitSnapshot, additions []appSystemdUnitSnapshot) []appSystemdUnitSnapshot {
	merged := append([]appSystemdUnitSnapshot(nil), existing...)
	seen := map[string]struct{}{}
	for _, snapshot := range merged {
		if unit := strings.TrimSpace(snapshot.unit); unit != "" {
			seen[unit] = struct{}{}
		}
	}
	for _, snapshot := range additions {
		unit := strings.TrimSpace(snapshot.unit)
		if unit == "" {
			continue
		}
		if _, ok := seen[unit]; ok {
			continue
		}
		seen[unit] = struct{}{}
		snapshot.unit = unit
		snapshot.enabledState = strings.TrimSpace(snapshot.enabledState)
		snapshot.activeState = strings.TrimSpace(snapshot.activeState)
		merged = append(merged, snapshot)
	}
	return merged
}

func snapshotAppSystemdUnits(ctx stdcontext.Context, executor host.Executor, units []string) ([]appSystemdUnitSnapshot, error) {
	snapshots := make([]appSystemdUnitSnapshot, 0, len(units))
	seen := map[string]struct{}{}
	for _, unit := range units {
		unit = strings.TrimSpace(unit)
		if unit == "" {
			return nil, fmt.Errorf("systemd unit is required")
		}
		if _, ok := seen[unit]; ok {
			continue
		}
		seen[unit] = struct{}{}
		enabledState, err := snapshotSystemdUnitEnabledState(ctx, executor, unit)
		if err != nil {
			return nil, err
		}
		activeState, err := snapshotSystemdUnitActiveState(ctx, executor, unit)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, appSystemdUnitSnapshot{unit: unit, enabledState: enabledState, activeState: activeState})
	}
	return snapshots, nil
}

func snapshotSystemdUnitEnabledState(ctx stdcontext.Context, executor host.Executor, unit string) (string, error) {
	state, err := snapshotSystemdUnitState(ctx, executor, "is-enabled", unit)
	switch state {
	case "enabled", "disabled":
		return state, nil
	}
	if err != nil {
		return "", fmt.Errorf("systemctl is-enabled %s returned unsupported state %q: %w", unit, state, err)
	}
	return "", fmt.Errorf("systemctl is-enabled %s returned unsupported state %q; only enabled and disabled can be restored exactly", unit, state)
}

func snapshotSystemdUnitActiveState(ctx stdcontext.Context, executor host.Executor, unit string) (string, error) {
	state, err := snapshotSystemdUnitState(ctx, executor, "is-active", unit)
	switch state {
	case "active", "inactive":
		return state, nil
	}
	if err != nil {
		return "", fmt.Errorf("systemctl is-active %s returned unsupported state %q: %w", unit, state, err)
	}
	return "", fmt.Errorf("systemctl is-active %s returned unsupported state %q; only active and inactive can be restored exactly", unit, state)
}

func snapshotSystemdUnitState(ctx stdcontext.Context, executor host.Executor, action string, unit string) (string, error) {
	result, err := executor.Systemctl(ctx, action, unit)
	output := strings.TrimSpace(result.Stdout)
	if output == "" {
		output = strings.TrimSpace(result.Stderr)
	}
	var commandErr *host.CommandError
	if err != nil && errors.As(err, &commandErr) {
		if output == "" {
			output = strings.TrimSpace(commandErr.Result.Stdout)
		}
		if output == "" {
			output = strings.TrimSpace(commandErr.Result.Stderr)
		}
	}
	if output == "" {
		if err != nil {
			return "", fmt.Errorf("systemctl %s %s produced no state: %w", action, unit, err)
		}
		return "", fmt.Errorf("systemctl %s %s produced no state", action, unit)
	}
	return strings.Fields(output)[0], err
}

func prepareAppSystemdUnitRollback(ctx stdcontext.Context, executor host.Executor, snapshots []appSystemdUnitSnapshot, mutated map[string]bool) error {
	systemd := newHostSystemdFn(executor)
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		if !mutated[snapshot.unit] {
			continue
		}
		if snapshot.activeState == "inactive" {
			if _, err := systemd.Stop(ctx, snapshot.unit); err != nil {
				return fmt.Errorf("restore inactive systemd unit %s: %w", snapshot.unit, err)
			}
		}
		if snapshot.enabledState == "disabled" {
			if _, err := executor.Systemctl(ctx, "disable", snapshot.unit); err != nil {
				return fmt.Errorf("restore disabled systemd unit %s: %w", snapshot.unit, err)
			}
		}
	}
	return nil
}

func finishAppSystemdUnitRollback(ctx stdcontext.Context, executor host.Executor, snapshots []appSystemdUnitSnapshot, mutated map[string]bool, cause error) error {
	systemd := newHostSystemdFn(executor)
	if _, err := systemd.DaemonReload(ctx); err != nil {
		if cause == nil {
			return fmt.Errorf("systemd daemon-reload failed while restoring units: %w", err)
		}
		return fmt.Errorf("%w; restored previous app runtime files but systemd daemon-reload failed while restoring units: %v", cause, err)
	}
	for _, snapshot := range snapshots {
		if !mutated[snapshot.unit] {
			continue
		}
		if snapshot.enabledState == "enabled" {
			if _, err := systemd.Enable(ctx, snapshot.unit); err != nil {
				if cause == nil {
					return fmt.Errorf("restore enabled systemd unit %s failed: %w", snapshot.unit, err)
				}
				return fmt.Errorf("%w; restore enabled systemd unit %s failed: %v", cause, snapshot.unit, err)
			}
		}
		if snapshot.activeState == "active" {
			if _, err := systemd.Start(ctx, snapshot.unit); err != nil {
				if cause == nil {
					return fmt.Errorf("restore active systemd unit %s failed: %w", snapshot.unit, err)
				}
				return fmt.Errorf("%w; restore active systemd unit %s failed: %v", cause, snapshot.unit, err)
			}
		}
	}
	return cause
}

type appRealIPReferenceSnapshot struct {
	hostPath string
	exists   bool
	content  []byte
	mode     fs.FileMode
}

func snapshotAppRealIPReference(fileSystem host.FileSystem, path string) (appRealIPReferenceSnapshot, error) {
	snapshot := appRealIPReferenceSnapshot{hostPath: strings.TrimSpace(path)}
	if snapshot.hostPath == "" {
		return appRealIPReferenceSnapshot{}, fmt.Errorf("app realip reference path is required")
	}
	info, err := fileSystem.Lstat(snapshot.hostPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return snapshot, nil
		}
		return appRealIPReferenceSnapshot{}, fmt.Errorf("stat existing app realip reference %s: %w", snapshot.hostPath, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return appRealIPReferenceSnapshot{}, fmt.Errorf("%s is a symlink; refusing to snapshot app realip reference", snapshot.hostPath)
	}
	if !info.Mode().IsRegular() {
		return appRealIPReferenceSnapshot{}, fmt.Errorf("%s exists and is not a regular app realip reference file", snapshot.hostPath)
	}
	content, err := fileSystem.ReadFile(snapshot.hostPath)
	if err != nil {
		return appRealIPReferenceSnapshot{}, fmt.Errorf("read existing app realip reference %s: %w", snapshot.hostPath, err)
	}
	snapshot.exists = true
	snapshot.content = append([]byte(nil), content...)
	snapshot.mode = info.Mode().Perm()
	return snapshot, nil
}

func restoreAppRealIPReference(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshot appRealIPReferenceSnapshot) error {
	if strings.TrimSpace(snapshot.hostPath) == "" {
		return fmt.Errorf("app realip reference snapshot path is required")
	}
	if snapshot.exists {
		return fileSystem.WriteFile(snapshot.hostPath, snapshot.content, snapshot.mode)
	}
	return removePath(ctx, executor, "rollback-realip-reference", snapshot.hostPath)
}

func removePath(ctx stdcontext.Context, executor host.Executor, displayName string, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is required for %s", displayName)
	}
	_, err := executor.Run(ctx, host.Command{
		Name:        "rm",
		Args:        []string{"-f", "--", path},
		DisplayName: displayName,
		DisplayArgs: []string{path},
	})
	return err
}

func removeEmptyDir(ctx stdcontext.Context, executor host.Executor, displayName string, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is required for %s", displayName)
	}
	_, err := executor.Run(ctx, host.Command{
		Name:        "rmdir",
		Args:        []string{"--", path},
		DisplayName: displayName,
		DisplayArgs: []string{path},
	})
	return err
}

func readRealIPProfileFromFS(fileSystem host.FileSystem, path string) (realip.ProfileConfig, bool, error) {
	data, err := fileSystem.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return realip.ProfileConfig{}, false, nil
		}
		return realip.ProfileConfig{}, false, fmt.Errorf("read existing realip profile metadata %s: %w", path, err)
	}
	profileName, err := realIPProfileNameFromMetadataPath(path)
	if err != nil {
		return realip.ProfileConfig{}, false, fmt.Errorf("read existing realip profile metadata %s: %w", path, err)
	}
	profile, err := parseDeployedRealIPProfile(data, path, profileName)
	if err != nil {
		return realip.ProfileConfig{}, false, err
	}
	return profile, true, nil
}

func ReadRealIPProfileFromFS(fileSystem host.FileSystem, path string) (realip.ProfileConfig, bool, error) {
	return readRealIPProfileFromFS(fileSystem, path)
}

func ensureRealIPProfileCompatible(existing realip.ProfileConfig, desired realip.ProfileConfig) error {
	mismatches := []string{}
	if existing.Name != desired.Name {
		mismatches = append(mismatches, "name")
	}
	if existing.Provider != desired.Provider {
		mismatches = append(mismatches, "provider")
	}
	if existing.ZoneID != desired.ZoneID {
		mismatches = append(mismatches, "edgeone.zone_id")
	}
	if existing.EnvFile != desired.EnvFile {
		mismatches = append(mismatches, "edgeone.env_file")
	}
	if existing.RefreshInterval != desired.RefreshInterval {
		mismatches = append(mismatches, "refresh_interval")
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("existing realip profile %s differs in %s; refusing to reuse shared profile with changed contract", existing.Name, strings.Join(mismatches, ", "))
	}
	return nil
}

func EnsureRealIPProfileCompatible(existing realip.ProfileConfig, desired realip.ProfileConfig) error {
	return ensureRealIPProfileCompatible(existing, desired)
}

func cleanupStaleAppRealIPReferences(ctx stdcontext.Context, executor host.Executor, appName string, currentProfile string, effects *appDeployEffects) error {
	appName = strings.TrimSpace(appName)
	currentProfile = strings.TrimSpace(currentProfile)
	if appName == "" {
		return nil
	}
	if _, err := appsvc.NewRealIPProfileNames("edgeone-prod", appconfig.RealIPProviderEdgeOne, appName); err != nil {
		return fmt.Errorf("cleanup stale realip references for app %q: %w", appName, err)
	}
	staleProfiles, err := staleAppRealIPReferenceProfiles(appName, currentProfile)
	if err != nil {
		return err
	}
	if len(staleProfiles) == 0 {
		effects.AddActions("checked stale realip references")
		return nil
	}
	validatorPath, err := currentExecutablePathFn()
	if err != nil {
		return fmt.Errorf("resolve lanpanel executable for realip reference validation: %w", err)
	}
	validatorPath = strings.TrimSpace(validatorPath)
	if validatorPath == "" {
		return fmt.Errorf("resolve lanpanel executable for realip reference validation: empty path")
	}
	changed := false
	for _, profile := range staleProfiles {
		lock, err := acquireRealIPProfileLockFn(profile)
		if err != nil {
			return err
		}
		cleaned := false
		cleanupErr := validateLockedStaleAppRealIPCleanupTargets(appName, profile)
		if cleanupErr == nil {
			cleaned, cleanupErr = cleanupStaleAppRealIPReferenceForProfile(ctx, executor, appName, profile, validatorPath)
		}
		releaseErr := lock.Release()
		if cleanupErr != nil {
			if releaseErr != nil {
				return fmt.Errorf("%w; release realip profile lock failed: %v", cleanupErr, releaseErr)
			}
			return cleanupErr
		}
		if releaseErr != nil {
			return releaseErr
		}
		changed = changed || cleaned
	}
	if changed {
		if _, err := executor.Systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
		effects.AddActions("cleaned stale realip references")
	} else {
		effects.AddActions("checked stale realip references")
	}
	return nil
}

func CleanupStaleAppRealIPReferences(ctx stdcontext.Context, executor host.Executor, appName string, currentProfile string, effects *AppDeployEffects) error {
	return cleanupStaleAppRealIPReferences(ctx, executor, appName, currentProfile, effects)
}

func staleAppRealIPReferenceProfiles(appName string, currentProfile string) ([]string, error) {
	pattern := filepath.Join(realIPCleanupRoot, "*", "references", appName+".json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("scan stale realip references for app %s: %w", appName, err)
	}
	profiles := []string{}
	seen := map[string]struct{}{}
	for _, ref := range matches {
		profile := filepath.Base(filepath.Dir(filepath.Dir(ref)))
		if profile == currentProfile {
			continue
		}
		if _, err := appsvc.NewRealIPProfileNames(profile, appconfig.RealIPProviderEdgeOne, appName); err != nil {
			return nil, fmt.Errorf("%s profile path is not safe for Lanpanel-managed realip cleanup: %w", ref, err)
		}
		if err := validateStaleAppRealIPReferencePath(appName, profile, ref); err != nil {
			return nil, err
		}
		if _, ok := seen[profile]; ok {
			continue
		}
		seen[profile] = struct{}{}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func StaleAppRealIPReferenceProfiles(appName string, currentProfile string) ([]string, error) {
	return staleAppRealIPReferenceProfiles(appName, currentProfile)
}

func validateLockedStaleAppRealIPCleanupTargets(appName string, profile string) error {
	ref := filepath.Join(realIPCleanupRoot, profile, "references", appName+".json")
	if _, err := lstatRealIPCleanupPathFn(ref); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat stale realip reference %s: %w", ref, err)
	}
	if err := validateStaleAppRealIPReferencePath(appName, profile, ref); err != nil {
		return err
	}
	hasOtherReferences, err := staleRealIPProfileHasOtherJSONReferences(appName, profile)
	if err != nil {
		return err
	}
	if hasOtherReferences {
		return nil
	}
	return validateStaleRealIPSharedCleanupTargets(profile)
}

func staleRealIPProfileHasOtherJSONReferences(appName string, profile string) (bool, error) {
	refDir := filepath.Join(realIPCleanupRoot, profile, "references")
	currentRef := filepath.Clean(filepath.Join(refDir, appName+".json"))
	matches, err := filepath.Glob(filepath.Join(refDir, "*.json"))
	if err != nil {
		return false, fmt.Errorf("scan stale realip references for profile %s: %w", profile, err)
	}
	for _, match := range matches {
		if filepath.Clean(match) != currentRef {
			return true, nil
		}
	}
	return false, nil
}

func validateStaleRealIPSharedCleanupTargets(profile string) error {
	names, err := appsvc.NewRealIPProfileNames(profile, appconfig.RealIPProviderEdgeOne, "")
	if err != nil {
		return fmt.Errorf("stale realip cleanup profile %q is invalid: %w", profile, err)
	}
	for _, dir := range []struct {
		label string
		path  string
	}{
		{label: "stale realip systemd directory", path: filepath.Dir(names.RefreshServicePath)},
		{label: "stale realip Nginx directory", path: names.NginxDir},
	} {
		if err := validateExistingRealIPDirectoryChainWithLstat(dir.label, dir.path, lstatRealIPCleanupPathFn); err != nil {
			return err
		}
	}
	marker := realIPManagedMarker(profile, appconfig.RealIPProviderEdgeOne)
	profileDir := filepath.Join(realIPCleanupRoot, profile)
	for _, artifact := range []struct {
		label    string
		path     string
		validate func(string, fs.FileInfo) error
	}{
		{label: "stale realip refresh service", path: names.RefreshServicePath, validate: validateExistingRealIPArtifactInfo},
		{label: "stale realip refresh timer", path: names.RefreshTimerPath, validate: validateExistingRealIPArtifactInfo},
		{label: "stale realip Nginx include", path: names.NginxIncludePath, validate: validateExistingRealIPArtifactInfo},
		{label: "stale realip trusted CIDR include", path: names.TrustedCIDRPath, validate: validateExistingRealIPArtifactInfo},
		{label: "stale realip state", path: filepath.Join(profileDir, "state.json"), validate: validateDeployedRealIPStateInfo},
		{label: "stale realip metadata", path: filepath.Join(profileDir, "profile.json"), validate: validateExistingRealIPMetadataInfo},
	} {
		if err := validateOptionalStaleRealIPCleanupArtifact(artifact.label, artifact.path, marker, artifact.validate); err != nil {
			return err
		}
	}
	return nil
}

func validateOptionalStaleRealIPCleanupArtifact(label string, path string, marker string, validate func(string, fs.FileInfo) error) error {
	info, err := lstatRealIPCleanupPathFn(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s %s: %w", label, path, err)
	}
	if err := validate(path, info); err != nil {
		return err
	}
	content, err := readDeployedRealIPArtifactFn(path)
	if err != nil {
		return fmt.Errorf("read %s %s: %w", label, path, err)
	}
	if !strings.Contains(string(content), marker) {
		return fmt.Errorf("%s %s missing marker %q", label, path, marker)
	}
	return nil
}

func validateStaleAppRealIPReferencePath(appName string, profile string, ref string) error {
	root := filepath.Clean(strings.TrimSpace(realIPCleanupRoot))
	if root == "" || !filepath.IsAbs(root) {
		return fmt.Errorf("realip cleanup root %q is required and must be absolute", realIPCleanupRoot)
	}
	expected := filepath.Join(root, profile, "references", appName+".json")
	ref = filepath.Clean(ref)
	if ref != expected {
		return fmt.Errorf("%s is not the expected Lanpanel-managed stale realip reference path %s", ref, expected)
	}
	relativeRef, err := filepath.Rel(root, ref)
	if err != nil {
		return fmt.Errorf("verify stale realip reference %s is under cleanup root %s: %w", ref, root, err)
	}
	if relativeRef == "." || strings.HasPrefix(relativeRef, ".."+string(os.PathSeparator)) || relativeRef == ".." || filepath.IsAbs(relativeRef) {
		return fmt.Errorf("stale realip reference %s must remain under cleanup root %s", ref, root)
	}
	for _, dir := range []struct {
		label string
		path  string
	}{
		{label: "realip cleanup root", path: root},
		{label: "stale realip profile directory", path: filepath.Join(root, profile)},
		{label: "stale realip reference directory", path: filepath.Join(root, profile, "references")},
	} {
		info, err := lstatRealIPCleanupPathFn(dir.path)
		if err != nil {
			return fmt.Errorf("stat %s %s: %w", dir.label, dir.path, err)
		}
		if err := validateExistingRealIPDirectoryInfo(dir.label, dir.path, info); err != nil {
			return err
		}
	}
	info, err := lstatRealIPCleanupPathFn(ref)
	if err != nil {
		return fmt.Errorf("stat stale realip reference %s: %w", ref, err)
	}
	return validateDeployedRealIPReferenceInfo(ref, info)
}

func cleanupStaleAppRealIPReferenceForProfile(ctx stdcontext.Context, executor host.Executor, appName string, profile string, validatorPath string) (bool, error) {
	script := `set -eu
app=$1
profile=$2
validator=$3
root=$4
nginx_binary=$5
ref="$root/$profile/references/$app.json"
[ -e "$ref" ] || exit 0
marker="Lanpanel-managed: realip.profile=$profile provider=edgeone"
refdir=$(dirname "$ref")
profiledir=$(dirname "$refdir")
other_references=0
for other_ref in "$refdir"/*.json; do
    [ -e "$other_ref" ] || [ -L "$other_ref" ] || continue
    other_app=$(basename "$other_ref" .json)
    if ! "$validator" app realip validate-reference --profile "$profile" --app "$other_app" --path "$other_ref" >/dev/null; then
        echo "$other_ref is not a valid Lanpanel-managed realip reference for profile $profile; refusing stale cleanup" >&2
        exit 1
    fi
    if [ "$other_ref" != "$ref" ]; then
        other_references=$((other_references + 1))
    fi
done
has_other_references=false
if [ "$other_references" -gt 0 ]; then
    has_other_references=true
fi
if [ "$has_other_references" = false ]; then
    service="/etc/systemd/system/lanpanel-realip-$profile-refresh.service"
    timer="/etc/systemd/system/lanpanel-realip-$profile-refresh.timer"
    nginx_dir="/etc/nginx/lanpanel/realip/$profile"
    nginx_active="/etc/nginx/lanpanel/realip/$profile/active.conf"
    nginx_trusted="/etc/nginx/lanpanel/realip/$profile/trusted-cidrs.conf"
    state="$profiledir/state.json"
    metadata="$profiledir/profile.json"
    for artifact in "$service" "$timer" "$nginx_active" "$nginx_trusted" "$state" "$metadata"; do
        [ -e "$artifact" ] || [ -L "$artifact" ] || continue
        if [ -L "$artifact" ] || [ ! -f "$artifact" ]; then
            echo "$artifact exists but is not a regular Lanpanel-managed realip artifact; refusing stale cleanup" >&2
            exit 1
        fi
        if ! grep -Fq "$marker" "$artifact"; then
            echo "$artifact exists but is not this profile's Lanpanel-managed realip artifact; refusing stale cleanup" >&2
            exit 1
        fi
    done
    dump=$(mktemp)
    trap 'rm -f "$dump"' EXIT INT TERM
    if ! "$nginx_binary" -T > "$dump" 2>&1; then
        cat "$dump" >&2
        exit 1
    fi
    if grep -Fq "$marker" "$dump"; then
        echo "$marker is still present in active Nginx config; refusing stale cleanup" >&2
        exit 1
    fi
    for include in "$nginx_active" "$nginx_trusted"; do
        if grep -Fq "# configuration file $include:" "$dump"; then
            echo "$include is still referenced by active Nginx config; refusing stale cleanup" >&2
            exit 1
        fi
    done
    for entry in "$refdir"/* "$refdir"/.[!.]* "$refdir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "$entry" in
            "$ref")
                ;;
            *)
                echo "$refdir contains unexpected stale realip reference entry $entry; refusing stale cleanup" >&2
                exit 1
                ;;
        esac
    done
    for entry in "$profiledir"/* "$profiledir"/.[!.]* "$profiledir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "$entry" in
            "$refdir"|"$state"|"$metadata")
                ;;
            *)
                echo "$profiledir contains unexpected stale realip profile entry $entry; refusing stale cleanup" >&2
                exit 1
                ;;
        esac
    done
    for entry in "$nginx_dir"/* "$nginx_dir"/.[!.]* "$nginx_dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "$entry" in
            "$nginx_active"|"$nginx_trusted")
                ;;
            *)
                echo "$nginx_dir contains unexpected stale realip nginx entry $entry; refusing stale cleanup" >&2
                exit 1
                ;;
        esac
    done
    if [ -e "$timer" ]; then
        systemctl disable --now "lanpanel-realip-$profile-refresh.timer"
    fi
    if [ -e "$service" ]; then
        systemctl stop "lanpanel-realip-$profile-refresh.service"
    fi
    rm -f -- "$ref"
    rm -f -- "/etc/systemd/system/lanpanel-realip-$profile-refresh.service" \
              "/etc/systemd/system/lanpanel-realip-$profile-refresh.timer" \
              "/etc/nginx/lanpanel/realip/$profile/active.conf" \
              "/etc/nginx/lanpanel/realip/$profile/trusted-cidrs.conf" \
              "$profiledir/state.json" "$profiledir/profile.json"
    for stale_dir in "$refdir" "$profiledir" "$nginx_dir"; do
        [ -d "$stale_dir" ] || continue
        if ! rmdir "$stale_dir"; then
            echo "failed to remove stale realip directory $stale_dir" >&2
            exit 1
        fi
    done
else
    rm -f -- "$ref"
fi
echo lanpanel-realip-cleaned`
	result, err := executor.Run(ctx, host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-realip-stale-reference-cleanup", appName, profile, validatorPath, realIPCleanupRoot, appsvc.NginxBinaryPath},
		DisplayName: "cleanup-realip-references",
		DisplayArgs: []string{appName, profile},
	})
	if err != nil {
		return false, err
	}
	return strings.Contains(result.Stdout, "lanpanel-realip-cleaned"), nil
}

func CleanupStaleAppRealIPReferenceForProfile(ctx stdcontext.Context, executor host.Executor, appName string, profile string, validatorPath string) (bool, error) {
	return cleanupStaleAppRealIPReferenceForProfile(ctx, executor, appName, profile, validatorPath)
}

func refreshDeployedRealIPProfile(ctx stdcontext.Context, profileName string, appConfigPath string, effects *appDeployEffects, checkpoint *appCheckpointPersistor) (state realip.State, profile realip.ProfileConfig, names appsvc.RealIPProfileNames, returnErr error) {
	names, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, "")
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	lock, err := acquireRealIPProfileLockFn(profileName)
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	defer func() {
		if err := lock.Release(); err != nil {
			if returnErr != nil {
				returnErr = fmt.Errorf("%w; release EdgeOne realip profile lock failed: %v", returnErr, err)
				return
			}
			returnErr = err
		}
	}()
	permissions := detectPermissionStateFn()
	privilege := deployPrivilegeStrategy(permissions)
	executor := newHostExecutorFn(nil).WithPrivilege(privilege)
	fileSystem := newAppHostFileSystemFn(executor, privilege)
	if err := guardRealIPProfileDirectories(fileSystem, names); err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	if err := validateDeployedRealIPRefreshService(names.RefreshServicePath, realIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne), profileName, appConfigPath); err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, fmt.Errorf("deployed realip refresh service is not bound to App config %s; update the binding from the Management UI: %w", appConfigPath, err)
	}
	profile, err = readDeployedRealIPProfileFn(names.MetadataPath)
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	if profile.Name != profileName {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, fmt.Errorf("deployed profile metadata name %q does not match requested profile %q", profile.Name, profileName)
	}
	if profile.Provider != appconfig.RealIPProviderEdgeOne {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, fmt.Errorf("deployed realip provider %q is not supported", profile.Provider)
	}
	references, err := readDeployedRealIPReferencesFn(names.ReferenceDir)
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	domains := domainsFromRealIPReferences(references)
	if len(domains) == 0 {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, fmt.Errorf("no deployed app references found for realip profile %s", profileName)
	}
	profile.Domains = domains
	credentials, err := loadEdgeOneCredentialsFn(edgeone.OSFileSystem{}, profile.EnvFile)
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	info, err := describeEdgeOneOriginACLFn(ctx, credentials, profile.ZoneID)
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	state, err = edgeone.BuildState(profile.Name, profile.ZoneID, info, domains, time.Now())
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	staged, err := stageRealIPRuntimeFilesFn(profile, state, realip.Reference{}, appConfigPath)
	if err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}

	if err := guardRealIPOwnership(fileSystem, profile.Name, profile.Provider, staged); err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	if err := installAndActivateRealIPRefresh(ctx, executor, fileSystem, newAppFileInstallerFn(executor, privilege), staged, effects, checkpoint); err != nil {
		return realip.State{}, realip.ProfileConfig{}, appsvc.RealIPProfileNames{}, err
	}
	return state, profile, names, nil
}

func RefreshDeployedRealIPProfile(ctx stdcontext.Context, profileName string, appConfigPath string, effects *AppDeployEffects) (realip.State, realip.ProfileConfig, appsvc.RealIPProfileNames, error) {
	return refreshDeployedRealIPProfile(ctx, profileName, appConfigPath, effects, nil)
}

type realIPFileSnapshot struct {
	HostPath string
	Exists   bool
	Content  []byte
	Mode     fs.FileMode
}

type realIPDirectorySnapshot struct {
	Path   string
	Exists bool
}

type RealIPFileSnapshot = realIPFileSnapshot
type RealIPDirectorySnapshot = realIPDirectorySnapshot

type realIPDirectorySpec struct {
	label string
	path  string
}

func installAndActivateRealIPRefresh(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, installer appStagedFileInstaller, staged []realiprender.StagedFile, effects *appDeployEffects, checkpoint *appCheckpointPersistor) error {
	snapshots, err := snapshotRealIPFiles(fileSystem, staged, true)
	if err != nil {
		return err
	}
	if checkpoint != nil {
		if err := checkpoint.recordFileSnapshots(stateFileSnapshotsFromRealIP(snapshots)); err != nil {
			return err
		}
	}

	results, err := installer.Install(realiprender.ConvertStagedFiles(staged))
	effects.AddPaths(host.CollectModifiedPaths(results)...)
	if err != nil {
		if rollbackErr := restoreRealIPFileSnapshots(ctx, executor, fileSystem, snapshots); rollbackErr != nil {
			return fmt.Errorf("install realip artifacts failed: %w; rollback also failed: %v", err, rollbackErr)
		}
		return err
	}
	effects.AddActions("installed realip artifacts")
	systemd := newHostSystemdFn(executor)
	if _, err := systemd.DaemonReload(ctx); err != nil {
		return rollbackRealIPRefresh(ctx, executor, fileSystem, snapshots, fmt.Errorf("systemd daemon-reload failed after realip refresh: %w", err), false)
	}
	effects.AddActions("systemd daemon-reload")
	if _, err := executor.Run(ctx, appsvc.TestNginxCommand()); err != nil {
		return rollbackRealIPRefresh(ctx, executor, fileSystem, snapshots, fmt.Errorf("nginx -t failed after realip refresh: %w", err), false)
	}
	effects.AddActions("nginx -t")
	if _, err := executor.Run(ctx, appsvc.ReloadNginxCommand()); err != nil {
		return rollbackRealIPRefresh(ctx, executor, fileSystem, snapshots, fmt.Errorf("nginx reload failed after realip refresh: %w", err), true)
	}
	effects.AddActions("reloaded nginx")
	return nil
}

func InstallAndActivateRealIPRefresh(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, installer AppStagedFileInstaller, staged []realiprender.StagedFile, effects *AppDeployEffects) error {
	return installAndActivateRealIPRefresh(ctx, executor, fileSystem, installer, staged, effects, nil)
}

func snapshotRealIPFiles(fileSystem host.FileSystem, staged []realiprender.StagedFile, requireExisting bool) ([]realIPFileSnapshot, error) {
	snapshots := make([]realIPFileSnapshot, 0, len(staged))
	for _, file := range staged {
		hostPath := strings.TrimSpace(file.HostPath)
		if hostPath == "" {
			return nil, fmt.Errorf("realip artifact host path is required")
		}
		info, err := fileSystem.Lstat(hostPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				if requireExisting {
					return nil, fmt.Errorf("active realip artifact %s missing before refresh: %w", hostPath, err)
				}
				snapshots = append(snapshots, realIPFileSnapshot{HostPath: hostPath})
				continue
			}
			return nil, fmt.Errorf("stat active realip artifact %s: %w", hostPath, err)
		}
		if err := validateExistingRealIPArtifactInfo(hostPath, info); err != nil {
			return nil, err
		}
		content, err := fileSystem.ReadFile(hostPath)
		if err != nil {
			return nil, fmt.Errorf("read active realip artifact %s before refresh: %w", hostPath, err)
		}
		snapshots = append(snapshots, realIPFileSnapshot{
			HostPath: hostPath,
			Exists:   true,
			Content:  append([]byte(nil), content...),
			Mode:     info.Mode().Perm(),
		})
	}
	return snapshots, nil
}

func SnapshotRealIPFiles(fileSystem host.FileSystem, staged []realiprender.StagedFile, requireExisting bool) ([]RealIPFileSnapshot, error) {
	return snapshotRealIPFiles(fileSystem, staged, requireExisting)
}

func snapshotRealIPDirectories(fileSystem host.FileSystem, names appsvc.RealIPProfileNames) ([]realIPDirectorySnapshot, error) {
	if fileSystem == nil {
		fileSystem = host.OSFileSystem{}
	}
	dirs := realIPDeployDirectorySpecs(names)
	snapshots := make([]realIPDirectorySnapshot, 0, len(dirs))
	for _, dir := range dirs {
		path := filepath.Clean(strings.TrimSpace(dir.path))
		if path == "" || !filepath.IsAbs(path) {
			return nil, fmt.Errorf("%s path is required and must be absolute", dir.label)
		}
		info, err := fileSystem.Lstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				snapshots = append(snapshots, realIPDirectorySnapshot{Path: path})
				continue
			}
			return nil, fmt.Errorf("stat %s %s before realip deploy: %w", dir.label, path, err)
		}
		if err := validateExistingRealIPDirectoryInfo(dir.label, path, info); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, realIPDirectorySnapshot{Path: path, Exists: true})
	}
	return snapshots, nil
}

func SnapshotRealIPDirectories(fileSystem host.FileSystem, names appsvc.RealIPProfileNames) ([]RealIPDirectorySnapshot, error) {
	return snapshotRealIPDirectories(fileSystem, names)
}

func realIPDeployDirectorySpecs(names appsvc.RealIPProfileNames) []realIPDirectorySpec {
	specs := []realIPDirectorySpec{}
	add := func(label string, path string) {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "" {
			specs = append(specs, realIPDirectorySpec{label: label, path: path})
			return
		}
		for _, existing := range specs {
			if existing.path == path {
				return
			}
		}
		specs = append(specs, realIPDirectorySpec{label: label, path: path})
	}
	add("realip reference directory", names.ReferenceDir)
	add("realip state directory", names.StateDir)
	add("realip state root directory", filepath.Dir(names.StateDir))
	add("realip state base directory", filepath.Dir(filepath.Dir(names.StateDir)))
	add("realip Nginx directory", names.NginxDir)
	add("realip Nginx root directory", filepath.Dir(names.NginxDir))
	add("realip Nginx base directory", filepath.Dir(filepath.Dir(names.NginxDir)))
	return specs
}

func rollbackRealIPDeploy(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []realIPFileSnapshot, directories []realIPDirectorySnapshot, cause error, reloadRestoredNginx bool) error {
	if rollbackErr := restoreRealIPDeploySnapshots(ctx, executor, fileSystem, snapshots, directories); rollbackErr != nil {
		return fmt.Errorf("%w; rollback EdgeOne realip profile artifacts failed: %v", cause, rollbackErr)
	}
	if err := activateRestoredRealIPRuntime(ctx, executor, cause, reloadRestoredNginx); err != nil {
		return err
	}
	return cause
}

func RollbackRealIPDeploy(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []RealIPFileSnapshot, directories []RealIPDirectorySnapshot, cause error, reloadRestoredNginx bool) error {
	return rollbackRealIPDeploy(ctx, executor, fileSystem, snapshots, directories, cause, reloadRestoredNginx)
}

func rollbackRealIPRefresh(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []realIPFileSnapshot, cause error, reloadRestoredNginx bool) error {
	if rollbackErr := restoreRealIPFileSnapshots(ctx, executor, fileSystem, snapshots); rollbackErr != nil {
		return fmt.Errorf("%w; rollback also failed: %v", cause, rollbackErr)
	}
	if err := activateRestoredRealIPRuntime(ctx, executor, cause, reloadRestoredNginx); err != nil {
		return err
	}
	return cause
}

func activateRestoredRealIPRuntime(ctx stdcontext.Context, executor host.Executor, cause error, reloadRestoredNginx bool) error {
	systemd := newHostSystemdFn(executor)
	if _, err := systemd.DaemonReload(ctx); err != nil {
		return fmt.Errorf("%w; restored previous realip artifacts but systemd daemon-reload failed: %v", cause, err)
	}
	if _, err := executor.Run(ctx, appsvc.TestNginxCommand()); err != nil {
		return fmt.Errorf("%w; restored previous realip artifacts but nginx -t still failed: %v", cause, err)
	}
	if reloadRestoredNginx {
		if _, err := executor.Run(ctx, appsvc.ReloadNginxCommand()); err != nil {
			return fmt.Errorf("%w; restored previous realip artifacts and nginx -t passed but nginx reload failed: %v", cause, err)
		}
	}
	return nil
}

func restoreRealIPDeploySnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []realIPFileSnapshot, directories []realIPDirectorySnapshot) error {
	if err := restoreRealIPFileSnapshots(ctx, executor, fileSystem, snapshots); err != nil {
		return err
	}
	if err := restoreRealIPDirectorySnapshots(ctx, executor, fileSystem, directories); err != nil {
		return err
	}
	return nil
}

func RestoreRealIPDeploySnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []RealIPFileSnapshot, directories []RealIPDirectorySnapshot) error {
	return restoreRealIPDeploySnapshots(ctx, executor, fileSystem, snapshots, directories)
}

func restoreRealIPFileSnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []realIPFileSnapshot) error {
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		if !snapshot.Exists {
			if err := removePath(ctx, executor, "rollback-realip-artifact", snapshot.HostPath); err != nil {
				return fmt.Errorf("remove new realip artifact %s: %w", snapshot.HostPath, err)
			}
			continue
		}
		if err := fileSystem.WriteFile(snapshot.HostPath, snapshot.Content, snapshot.Mode); err != nil {
			return fmt.Errorf("restore %s: %w", snapshot.HostPath, err)
		}
	}
	return nil
}

func restoreRealIPDirectorySnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []realIPDirectorySnapshot) error {
	if fileSystem == nil {
		fileSystem = host.OSFileSystem{}
	}
	for _, snapshot := range snapshots {
		if snapshot.Exists {
			continue
		}
		path := filepath.Clean(strings.TrimSpace(snapshot.Path))
		if path == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("realip directory snapshot path is required and must be absolute")
		}
		info, err := fileSystem.Lstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat new realip directory %s before rollback removal: %w", path, err)
		}
		if err := validateExistingRealIPDirectoryInfo("new realip directory", path, info); err != nil {
			return err
		}
		if err := removeEmptyDir(ctx, executor, "rollback-realip-directory", path); err != nil {
			return fmt.Errorf("remove new realip directory %s: %w", path, err)
		}
	}
	return nil
}

func readDeployedRealIPProfile(path string) (realip.ProfileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return realip.ProfileConfig{}, fmt.Errorf("read deployed realip profile metadata %s: %w", path, err)
	}
	profileName, err := realIPProfileNameFromMetadataPath(path)
	if err != nil {
		return realip.ProfileConfig{}, fmt.Errorf("read deployed realip profile metadata %s: %w", path, err)
	}
	profile, err := parseDeployedRealIPProfile(data, path, profileName)
	if err != nil {
		return realip.ProfileConfig{}, err
	}
	return profile, nil
}

func ReadDeployedRealIPProfile(path string) (realip.ProfileConfig, error) {
	return readDeployedRealIPProfile(path)
}

func realIPProfileNameFromMetadataPath(path string) (string, error) {
	if filepath.Base(path) != "profile.json" {
		return "", fmt.Errorf("realip profile metadata path must end with profile.json")
	}
	profileName := strings.TrimSpace(filepath.Base(filepath.Dir(path)))
	if _, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, ""); err != nil {
		return "", fmt.Errorf("profile path name is not safe: %w", err)
	}
	return profileName, nil
}

func decodeDeployedRealIPJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("multiple JSON values")
	}
	return nil
}

func requireDeployedRealIPSchemaVersion(path string, label string, got string, want string) error {
	if got != want {
		return fmt.Errorf("deployed realip %s %s schema_version %q, want %q", label, path, got, want)
	}
	return nil
}

func parseDeployedRealIPProfile(data []byte, path string, profileName string) (realip.ProfileConfig, error) {
	var managed struct {
		SchemaVersion   string `json:"schema_version"`
		LanpanelManaged string `json:"lanpanel_managed"`
		realip.ProfileConfig
	}
	if err := decodeDeployedRealIPJSON(data, &managed); err != nil {
		return realip.ProfileConfig{}, fmt.Errorf("parse deployed realip profile metadata %s: %w", path, err)
	}
	if err := requireDeployedRealIPSchemaVersion(path, "profile metadata", managed.SchemaVersion, realip.ProfileSchemaVersion); err != nil {
		return realip.ProfileConfig{}, err
	}
	expectedMarker := realIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne)
	if managed.LanpanelManaged != expectedMarker {
		return realip.ProfileConfig{}, fmt.Errorf("deployed realip profile metadata %s has lanpanel_managed marker %q, want %q", path, managed.LanpanelManaged, expectedMarker)
	}
	profile := managed.ProfileConfig
	if profile.Name != profileName {
		return realip.ProfileConfig{}, fmt.Errorf("deployed realip profile metadata %s name %q does not match %q", path, profile.Name, profileName)
	}
	if profile.Provider != appconfig.RealIPProviderEdgeOne {
		return realip.ProfileConfig{}, fmt.Errorf("deployed realip profile metadata %s provider %q is not supported", path, profile.Provider)
	}
	if !isSafeDeployedEdgeOneZoneID(profile.ZoneID) {
		return realip.ProfileConfig{}, fmt.Errorf("deployed realip profile metadata %s zone_id must be an EdgeOne zone id such as zone-xxxxxxxx", path)
	}
	if err := validateDeployedRealIPEnvFile(path, profile.EnvFile); err != nil {
		return realip.ProfileConfig{}, err
	}
	duration, err := realip.RefreshIntervalDuration(profile.RefreshInterval)
	if err != nil {
		return realip.ProfileConfig{}, fmt.Errorf("deployed realip profile metadata %s %s", path, err.Error())
	}
	if duration < time.Hour {
		return realip.ProfileConfig{}, fmt.Errorf("deployed realip profile metadata %s refresh_interval must be at least 1h; use an explicit refresh command for immediate synchronization", path)
	}
	return profile, nil
}

func ensureDeployedRealIPStateMatchesProfile(profile realip.ProfileConfig, state realip.State) error {
	mismatches := []string{}
	if state.ProfileName != profile.Name {
		mismatches = append(mismatches, fmt.Sprintf("state profile_name %q does not match profile name %q", state.ProfileName, profile.Name))
	}
	if state.Provider != profile.Provider {
		mismatches = append(mismatches, fmt.Sprintf("state provider %q does not match profile provider %q", state.Provider, profile.Provider))
	}
	if state.ZoneID != profile.ZoneID {
		mismatches = append(mismatches, fmt.Sprintf("state zone_id %q does not match profile zone_id %q", state.ZoneID, profile.ZoneID))
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("deployed realip state does not match deployed profile metadata: %s", strings.Join(mismatches, "; "))
	}
	return nil
}

func EnsureDeployedRealIPStateMatchesProfile(profile realip.ProfileConfig, state realip.State) error {
	return ensureDeployedRealIPStateMatchesProfile(profile, state)
}

func readDeployedRealIPState(path string, profileName string) (realip.State, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return realip.State{}, fmt.Errorf("stat deployed realip state %s: %w", path, err)
	}
	if err := validateDeployedRealIPStateInfo(path, info); err != nil {
		return realip.State{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return realip.State{}, fmt.Errorf("read deployed realip state %s: %w", path, err)
	}
	state, err := parseDeployedRealIPState(data, path, profileName)
	if err != nil {
		return realip.State{}, err
	}
	return state, nil
}

func ReadDeployedRealIPState(path string, profileName string) (realip.State, error) {
	return readDeployedRealIPState(path, profileName)
}

func validateDeployedRealIPStateInfo(path string, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("deployed realip state %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("deployed realip state %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("deployed realip state %s must be root-only, for example mode 0600", path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("deployed realip state %s owner could not be inspected", path)
	}
	if uid != 0 {
		return fmt.Errorf("deployed realip state %s must be owned by root", path)
	}
	return nil
}

func ValidateDeployedRealIPStateInfo(path string, info fs.FileInfo) error {
	return validateDeployedRealIPStateInfo(path, info)
}

func parseDeployedRealIPState(data []byte, path string, profileName string) (realip.State, error) {
	var managed struct {
		SchemaVersion   string `json:"schema_version"`
		LanpanelManaged string `json:"lanpanel_managed"`
		realip.State
	}
	if err := decodeDeployedRealIPJSON(data, &managed); err != nil {
		return realip.State{}, fmt.Errorf("parse deployed realip state %s: %w", path, err)
	}
	if err := requireDeployedRealIPSchemaVersion(path, "state", managed.SchemaVersion, realip.StateSchemaVersion); err != nil {
		return realip.State{}, err
	}
	expectedMarker := realIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne)
	if managed.LanpanelManaged != expectedMarker {
		return realip.State{}, fmt.Errorf("deployed realip state %s has lanpanel_managed marker %q, want %q", path, managed.LanpanelManaged, expectedMarker)
	}
	state := managed.State
	if state.ProfileName != profileName {
		return realip.State{}, fmt.Errorf("deployed realip state %s profile_name %q does not match %q", path, state.ProfileName, profileName)
	}
	if state.Provider != appconfig.RealIPProviderEdgeOne {
		return realip.State{}, fmt.Errorf("deployed realip state %s provider %q is not supported", path, state.Provider)
	}
	if !isSafeDeployedEdgeOneZoneID(state.ZoneID) {
		return realip.State{}, fmt.Errorf("deployed realip state %s zone_id must be an EdgeOne zone id such as zone-xxxxxxxx", path)
	}
	switch strings.TrimSpace(state.OriginACLStatus) {
	case edgeone.OriginACLStatusOnline, edgeone.OriginACLStatusUpdating:
	default:
		return realip.State{}, fmt.Errorf("deployed realip state %s origin_acl_status must be online or updating", path)
	}
	if state.OriginACLStatus == edgeone.OriginACLStatusUpdating && len(state.NextCIDRs) == 0 {
		return realip.State{}, fmt.Errorf("deployed realip state %s next_cidrs is required when origin_acl_status is updating", path)
	}
	if err := validateDeployedRealIPStateCIDRs(path, &state); err != nil {
		return realip.State{}, err
	}
	if state.UpdatedAt.IsZero() {
		return realip.State{}, fmt.Errorf("deployed realip state %s updated_at is required", path)
	}
	return state, nil
}

func ParseDeployedRealIPState(data []byte, path string, profileName string) (realip.State, error) {
	return parseDeployedRealIPState(data, path, profileName)
}

func validateDeployedRealIPStateCIDRs(path string, state *realip.State) error {
	currentCIDRs, err := realip.CanonicalCIDRs(state.CurrentCIDRs)
	if err != nil {
		return fmt.Errorf("validate deployed realip state %s current_cidrs: %w", path, err)
	}
	nextCIDRs := []string(nil)
	if len(state.NextCIDRs) > 0 {
		nextCIDRs, err = realip.CanonicalCIDRs(state.NextCIDRs)
		if err != nil {
			return fmt.Errorf("validate deployed realip state %s next_cidrs: %w", path, err)
		}
	}
	trustedCIDRs, err := realip.CanonicalCIDRs(state.TrustedCIDRs)
	if err != nil {
		return fmt.Errorf("validate deployed realip state %s trusted_cidrs: %w", path, err)
	}
	expectedTrustedCIDRs, err := realip.CanonicalCIDRs(append(append([]string{}, currentCIDRs...), nextCIDRs...))
	if err != nil {
		return fmt.Errorf("validate deployed realip state %s current_cidrs+next_cidrs: %w", path, err)
	}
	if !stringSlicesEqual(trustedCIDRs, expectedTrustedCIDRs) {
		return fmt.Errorf("deployed realip state %s trusted_cidrs %s must equal current_cidrs+next_cidrs %s", path, listAsNone(trustedCIDRs), listAsNone(expectedTrustedCIDRs))
	}
	state.CurrentCIDRs = currentCIDRs
	state.NextCIDRs = nextCIDRs
	state.TrustedCIDRs = trustedCIDRs
	return nil
}

func isSafeDeployedEdgeOneZoneID(value string) bool {
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

func validateDeployedRealIPEnvFile(metadataPath string, envFile string) error {
	if envFile == "" {
		return fmt.Errorf("deployed realip profile metadata %s env_file is required", metadataPath)
	}
	if !filepath.IsAbs(envFile) {
		return fmt.Errorf("deployed realip profile metadata %s env_file must be an absolute path", metadataPath)
	}
	if filepath.Clean(envFile) != envFile {
		return fmt.Errorf("deployed realip profile metadata %s env_file must be a clean path without . or .. segments", metadataPath)
	}
	for _, r := range envFile {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("deployed realip profile metadata %s env_file must not contain whitespace or control characters", metadataPath)
		}
	}
	if strings.ContainsAny(envFile, "*?[]%\"'\\") {
		return fmt.Errorf("deployed realip profile metadata %s env_file must not contain glob, specifier, quote, or escape characters", metadataPath)
	}
	return nil
}

func readDeployedRealIPReferences(dir string) ([]realip.Reference, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read deployed realip references %s: %w", dir, err)
	}
	profileName := strings.TrimSpace(filepath.Base(filepath.Dir(dir)))
	if _, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, ""); err != nil {
		return nil, fmt.Errorf("read deployed realip references %s: invalid profile path: %w", dir, err)
	}
	references := []realip.Reference{}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			return nil, fmt.Errorf("deployed realip references directory %s contains unexpected directory %s", dir, path)
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil, fmt.Errorf("deployed realip references directory %s contains unexpected entry %s; only *.json reference files are supported", dir, path)
		}
		appName := strings.TrimSuffix(entry.Name(), ".json")
		info, err := lstatDeployedRealIPReferenceFn(path)
		if err != nil {
			return nil, fmt.Errorf("stat deployed realip reference %s: %w", path, err)
		}
		if err := validateDeployedRealIPReferenceInfo(path, info); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read deployed realip reference %s: %w", path, err)
		}
		reference, err := parseDeployedRealIPReference(data, path, profileName, appName)
		if err != nil {
			return nil, err
		}
		references = append(references, reference)
	}
	return references, nil
}

func ReadDeployedRealIPReferences(dir string) ([]realip.Reference, error) {
	return readDeployedRealIPReferences(dir)
}

func validateDeployedRealIPReferenceInfo(path string, info fs.FileInfo) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("deployed realip reference %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("deployed realip reference %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("deployed realip reference %s must be root-only, for example mode 0600", path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("deployed realip reference %s owner could not be inspected", path)
	}
	if uid != 0 {
		return fmt.Errorf("deployed realip reference %s must be owned by root", path)
	}
	return nil
}

func ValidateDeployedRealIPReferenceInfo(path string, info fs.FileInfo) error {
	return validateDeployedRealIPReferenceInfo(path, info)
}

func parseDeployedRealIPReference(data []byte, path string, profileName string, appName string) (realip.Reference, error) {
	var managed struct {
		SchemaVersion   string `json:"schema_version"`
		LanpanelManaged string `json:"lanpanel_managed"`
		realip.Reference
	}
	if err := decodeDeployedRealIPJSON(data, &managed); err != nil {
		return realip.Reference{}, fmt.Errorf("parse deployed realip reference %s: %w", path, err)
	}
	if err := requireDeployedRealIPSchemaVersion(path, "reference", managed.SchemaVersion, realip.ReferenceSchemaVersion); err != nil {
		return realip.Reference{}, err
	}
	expectedMarker := realIPManagedMarker(profileName, appconfig.RealIPProviderEdgeOne)
	if managed.LanpanelManaged != expectedMarker {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s has lanpanel_managed marker %q, want %q", path, managed.LanpanelManaged, expectedMarker)
	}
	if _, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, appName); err != nil {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s filename app name is not safe: %w", path, err)
	}
	if managed.Profile != profileName {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s profile %q does not match %q", path, managed.Profile, profileName)
	}
	if managed.AppName != appName {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s app_name %q does not match filename %q", path, managed.AppName, appName+".json")
	}
	cleanDomains := make([]string, 0, len(managed.Domains))
	for _, domain := range managed.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return realip.Reference{}, fmt.Errorf("deployed realip reference %s domains must not contain empty values", path)
		}
		cleanDomains = append(cleanDomains, domain)
	}
	if len(cleanDomains) == 0 {
		return realip.Reference{}, fmt.Errorf("deployed realip reference %s domains must not be empty", path)
	}
	return realip.Reference{AppName: managed.AppName, Profile: managed.Profile, Domains: cleanDomains}, nil
}

func ParseDeployedRealIPReference(data []byte, path string, profileName string, appName string) (realip.Reference, error) {
	return parseDeployedRealIPReference(data, path, profileName, appName)
}

func ValidateDeployedRealIPReferencePath(path string, profileName string, appName string) error {
	path = strings.TrimSpace(path)
	profileName = strings.TrimSpace(profileName)
	appName = strings.TrimSpace(appName)
	names, err := appsvc.NewRealIPProfileNames(profileName, appconfig.RealIPProviderEdgeOne, appName)
	if err != nil {
		return fmt.Errorf("deployed realip reference path identity is invalid: %w", err)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("deployed realip reference path must be a clean absolute path")
	}
	if path != names.ReferencePathForApp {
		return fmt.Errorf("deployed realip reference path %s must be %s", path, names.ReferencePathForApp)
	}
	return nil
}

func splitAppRealIPStagedFiles(staged []realiprender.StagedFile, referencePath string) ([]realiprender.StagedFile, []realiprender.StagedFile, error) {
	referencePath = strings.TrimSpace(referencePath)
	if referencePath == "" {
		return nil, nil, fmt.Errorf("realip reference path is required")
	}
	shared := make([]realiprender.StagedFile, 0, len(staged))
	reference := []realiprender.StagedFile{}
	for _, file := range staged {
		if file.HostPath == referencePath {
			reference = append(reference, file)
			continue
		}
		shared = append(shared, file)
	}
	if len(reference) != 1 {
		return nil, nil, fmt.Errorf("staged realip reference %s count = %d, want 1", referencePath, len(reference))
	}
	return shared, reference, nil
}

func replaceRealIPReferenceForApp(references []realip.Reference, reference realip.Reference) []realip.Reference {
	replaced := make([]realip.Reference, 0, len(references)+1)
	for _, existing := range references {
		if existing.AppName == reference.AppName {
			continue
		}
		replaced = append(replaced, existing)
	}
	return append(replaced, reference)
}

func domainsFromRealIPReferences(references []realip.Reference) []string {
	seen := map[string]struct{}{}
	domains := []string{}
	for _, reference := range references {
		for _, domain := range reference.Domains {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	return domains
}

func DomainsFromRealIPReferences(references []realip.Reference) []string {
	return domainsFromRealIPReferences(references)
}

func appRealIPRefreshRootRequiredResponse(permissions preflight.PermissionState) commandResponse {
	detail := "fail: app realip refresh requires root privileges"
	if strings.TrimSpace(permissions.User) != "" {
		detail += ", current user: " + strings.TrimSpace(permissions.User)
	}
	return commandResponse{
		Command:   "app realip refresh",
		Status:    "blocked",
		Summary:   "app realip refresh preflight found 1 failed check",
		Fields:    []domain.ResultField{{Label: "check permissions", Value: detail}},
		NextSteps: []string{"Retry RealIP refresh from the Management UI with confirmation " + appOriginProtectionManualConfirmation + "."},
	}
}

func emptyAsNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

func listAsNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func timeAsNone(value time.Time) string {
	if value.IsZero() {
		return "none"
	}
	return value.UTC().Format(time.RFC3339)
}

func appConfigFields(path string, cfg appconfig.Config) []domain.ResultField {
	fields := []domain.ResultField{
		{Label: "config path", Value: path},
		{Label: "app name", Value: cfg.App.Name},
		{Label: "mode", Value: string(cfg.Mode())},
		{Label: "domains", Value: strings.Join(cfg.App.Domains, ", ")},
		{Label: "access mode", Value: string(cfg.Access.AccessMode)},
		{Label: "origin protection", Value: appOriginProtectionField(cfg)},
		{Label: "direct origin risk", Value: appDirectOriginRiskField(cfg)},
	}
	if cfg.BrowserAuthEnabled() {
		fields = append(fields,
			domain.ResultField{Label: "browser protection", Value: "LanPanel Basic Auth enabled; upstream Authorization header is cleared"},
			domain.ResultField{Label: "browser cidr allowlist", Value: listAsNone(cfg.Access.CIDRAllowlist)},
		)
	}
	if cfg.PublicAccessEnabled() {
		fields = append(fields, domain.ResultField{Label: "public exposure risk", Value: fmt.Sprintf("confirmed=%t; no LanPanel Basic Auth is rendered", cfg.Access.PublicRiskConfirmed)})
	}
	return fields
}

func appDirectOriginRiskField(cfg appconfig.Config) string {
	if cfg.Access.OriginProtection.Mode != appconfig.OriginProtectionModeNone {
		return string(domain.DiagnosticStatusNotApplicable)
	}
	return fmt.Sprintf("confirmed=%t", cfg.Access.OriginProtection.DirectOriginRiskConfirmed)
}

func appOriginProtectionField(cfg appconfig.Config) string {
	switch cfg.Access.OriginProtection.Mode {
	case appconfig.OriginProtectionModeNone:
		return "none"
	case appconfig.OriginProtectionModeEdgeOne:
		return "edgeone profile " + cfg.Access.OriginProtection.EdgeOneProfile
	default:
		return string(cfg.Access.OriginProtection.Mode)
	}
}

func appRuntimeHostChecksStep(cfg appconfig.Config) string {
	return "After deploy, use " + appRuntimeHostCheckTools(cfg) + " to verify host runtime state."
}

func AppRuntimeHostChecksStep(cfg appconfig.Config) string {
	return appRuntimeHostChecksStep(cfg)
}

func appDeployRuntimeVerifyStep(configPath string, cfg appconfig.Config) string {
	return fmt.Sprintf("Recheck %s from the Management UI; then use %s to verify host runtime state.", configPath, appRuntimeHostCheckTools(cfg))
}

func AppDeployRuntimeVerifyStep(configPath string, cfg appconfig.Config) string {
	return appDeployRuntimeVerifyStep(configPath, cfg)
}

func appRuntimeHostCheckTools(cfg appconfig.Config) string {
	if cfg.RequiresTailscale() {
		return "nginx -t, systemctl, certificate checks, curl, and tailscale status"
	}
	return "nginx -t, systemctl, certificate checks, and curl"
}

func appGoAccessDeployFields(cfg appconfig.Config, names appsvc.Names) []domain.ResultField {
	if !cfg.Nginx.GoAccess.Enabled {
		return nil
	}
	errorLog := strings.TrimSpace(cfg.Nginx.ErrorLog)
	if errorLog == "" {
		errorLog = "nginx default error_log"
	}
	return []domain.ResultField{
		{Label: "goaccess dashboard", Value: "https://" + cfg.PrimaryDomain() + cfg.NginxGoAccessDashboardPath()},
		{Label: "goaccess service", Value: names.GoAccessServiceUnit},
		{Label: "canonical access log", Value: names.GoAccessCanonicalAccessLogPath},
		{Label: "goaccess report", Value: names.GoAccessReportPath},
		{Label: "goaccess db", Value: names.GoAccessDBPath},
		{Label: "nginx error log", Value: errorLog},
		{Label: "goaccess troubleshooting", Value: appGoAccessTroubleshootingCommands(cfg, names)},
		{Label: "goaccess dashboard scope", Value: appGoAccessDashboardScope(cfg)},
	}
}

func appRealIPDeployFields(cfg appconfig.Config, names appsvc.RealIPProfileNames, state realip.State, prepared bool) []domain.ResultField {
	if !prepared || !cfg.RealIPEnabled() {
		return nil
	}
	fields := []domain.ResultField{
		{Label: "realip profile", Value: names.ProfileName + " (" + names.Provider + ")"},
		{Label: "manual firewall confirmation", Value: "confirm cloud security group or host firewall allows only EdgeOne current+next origin ACL CIDRs to 80/443"},
	}
	fields = append(fields, realIPRuntimeFields(names, state, "nginx -t passed and Nginx reloaded with app site")...)
	return fields
}

func AppRealIPDeployFields(cfg appconfig.Config, names appsvc.RealIPProfileNames, state realip.State, prepared bool) []domain.ResultField {
	return appRealIPDeployFields(cfg, names, state, prepared)
}

func realIPRuntimeFields(names appsvc.RealIPProfileNames, state realip.State, nginxStatus string) []domain.ResultField {
	return []domain.ResultField{
		{Label: "realip nginx include", Value: names.NginxIncludePath},
		{Label: "realip trusted CIDR include", Value: names.TrustedCIDRPath},
		{Label: "realip current CIDRs", Value: listAsNone(state.CurrentCIDRs)},
		{Label: "realip next CIDRs", Value: listAsNone(state.NextCIDRs)},
		{Label: "realip trusted CIDRs", Value: listAsNone(state.TrustedCIDRs)},
		{Label: "realip state", Value: names.StatePath},
		{Label: "realip refresh timer", Value: names.RefreshTimerUnit},
		{Label: "realip updated at", Value: timeAsNone(state.UpdatedAt)},
		{Label: "origin acl status", Value: emptyAsNone(state.OriginACLStatus)},
		{Label: "origin acl family", Value: emptyAsNone(state.OriginACLFamily)},
		{Label: "current acl version", Value: emptyAsNone(state.CurrentVersion)},
		{Label: "current active time", Value: emptyAsNone(state.CurrentActiveTime)},
		{Label: "next acl version", Value: emptyAsNone(state.NextVersion)},
		{Label: "next active time", Value: emptyAsNone(state.NextActiveTime)},
		{Label: "planned active time", Value: emptyAsNone(state.PlannedActiveTime)},
		{Label: "nginx realip active", Value: nginxStatus},
	}
}

func summarizeRealIPReferences(references []realip.Reference) string {
	if len(references) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(references))
	for _, reference := range references {
		parts = append(parts, reference.AppName+"="+strings.Join(reference.Domains, ","))
	}
	return strings.Join(parts, "; ")
}

func deployedRealIPRegularFileStatus(path string) (string, error) {
	info, err := lstatDeployedRealIPArtifactFn(path)
	if err != nil {
		return "missing: " + err.Error(), fmt.Errorf("stat deployed realip artifact %s: %w", path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return "invalid: symlink", fmt.Errorf("deployed realip artifact %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "invalid: not a regular file", fmt.Errorf("deployed realip artifact %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("invalid: mode %04o is group/other writable", info.Mode().Perm()), fmt.Errorf("deployed realip artifact %s must not be writable by group or others", path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return "invalid: owner could not be inspected", fmt.Errorf("deployed realip artifact %s owner could not be inspected", path)
	}
	if uid != 0 {
		return fmt.Sprintf("invalid: owner uid %d", uid), fmt.Errorf("deployed realip artifact %s must be owned by root", path)
	}
	return fmt.Sprintf("present root-owned mode %04o", info.Mode().Perm()), nil
}

func DeployedRealIPRegularFileStatus(path string) (string, error) {
	return deployedRealIPRegularFileStatus(path)
}

func validateDeployedRealIPNginxInclude(path string, marker string, expectedCIDRs []string) error {
	content, err := readDeployedRealIPArtifactFn(path)
	if err != nil {
		return fmt.Errorf("read deployed realip artifact %s: %w", path, err)
	}
	text := string(content)
	if !strings.Contains(text, "# "+marker) {
		return fmt.Errorf("deployed realip artifact %s missing marker %q", path, marker)
	}
	cidrs, err := parseSetRealIPFromCIDRs(path, text)
	if err != nil {
		return err
	}
	return requireCIDRListMatch(path, cidrs, expectedCIDRs)
}

func validateDeployedRealIPTrustedCIDRInclude(path string, marker string, expectedCIDRs []string) error {
	content, err := readDeployedRealIPArtifactFn(path)
	if err != nil {
		return fmt.Errorf("read deployed realip artifact %s: %w", path, err)
	}
	text := string(content)
	if !strings.Contains(text, "# "+marker) {
		return fmt.Errorf("deployed realip artifact %s missing marker %q", path, marker)
	}
	cidrs, err := parseTrustedCIDRGeoEntries(path, text)
	if err != nil {
		return err
	}
	return requireCIDRListMatch(path, cidrs, expectedCIDRs)
}

func validateDeployedRealIPRefreshService(path string, marker string, profileName string, configPath string) error {
	text, err := readDeployedRealIPArtifactText(path)
	if err != nil {
		return err
	}
	if err := requireDeployedRealIPMarker(path, text, marker); err != nil {
		return err
	}
	for _, line := range []string{
		"Type=oneshot",
		"TimeoutStartSec=2min",
	} {
		if !hasTrimmedLine(text, line) {
			return fmt.Errorf("deployed realip artifact %s missing line %q", path, line)
		}
	}
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return fmt.Errorf("deployed realip artifact %s refresh service validation requires an app config path", path)
	}
	expected := "ExecStart=" + realipassets.DefaultRefreshBinaryPath + " app realip refresh --config " + configPath + " --profile " + strings.TrimSpace(profileName)
	execStartLines := deployedRealIPRefreshExecStartLines(text)
	if len(execStartLines) != 1 {
		return fmt.Errorf("deployed realip artifact %s must contain exactly one ExecStart line, found %d", path, len(execStartLines))
	}
	if execStartLines[0] != expected {
		return fmt.Errorf("deployed realip artifact %s ExecStart line %q must be %q", path, execStartLines[0], expected)
	}
	return nil
}

func deployedRealIPRefreshExecStartLines(text string) []string {
	lines := []string{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "ExecStart=") {
			lines = append(lines, line)
		}
	}
	return lines
}

func ValidateDeployedRealIPRefreshService(path string, marker string, profileName string, configPath string) error {
	return validateDeployedRealIPRefreshService(path, marker, profileName, configPath)
}

func validateDeployedRealIPRefreshTimer(path string, marker string, profile realip.ProfileConfig) error {
	text, err := readDeployedRealIPArtifactText(path)
	if err != nil {
		return err
	}
	if err := requireDeployedRealIPMarker(path, text, marker); err != nil {
		return err
	}
	refreshInterval, err := realip.SystemdRefreshInterval(profile.RefreshInterval)
	if err != nil {
		return fmt.Errorf("derive deployed realip refresh timer interval for %s: %w", path, err)
	}
	for _, line := range []string{
		"OnBootSec=15m",
		"OnUnitActiveSec=" + refreshInterval,
		"RandomizedDelaySec=30m",
		"Persistent=true",
		"WantedBy=timers.target",
	} {
		if !hasTrimmedLine(text, line) {
			return fmt.Errorf("deployed realip artifact %s missing line %q", path, line)
		}
	}
	return nil
}

func ValidateDeployedRealIPRefreshTimer(path string, marker string, profile realip.ProfileConfig) error {
	return validateDeployedRealIPRefreshTimer(path, marker, profile)
}

func readDeployedRealIPArtifactText(path string) (string, error) {
	content, err := readDeployedRealIPArtifactFn(path)
	if err != nil {
		return "", fmt.Errorf("read deployed realip artifact %s: %w", path, err)
	}
	return string(content), nil
}

func requireDeployedRealIPMarker(path string, text string, marker string) error {
	if !strings.Contains(text, "# "+marker) {
		return fmt.Errorf("deployed realip artifact %s missing marker %q", path, marker)
	}
	return nil
}

func hasTrimmedLine(text string, want string) bool {
	for _, raw := range strings.Split(text, "\n") {
		if strings.TrimSpace(raw) == want {
			return true
		}
	}
	return false
}

func parseSetRealIPFromCIDRs(path string, text string) ([]string, error) {
	cidrs := []string{}
	for lineNumber, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value, ok := strings.CutPrefix(line, "set_real_ip_from ")
		if !ok || !strings.HasSuffix(value, ";") {
			return nil, fmt.Errorf("deployed realip artifact %s line %d must be set_real_ip_from CIDR;", path, lineNumber+1)
		}
		cidrs = append(cidrs, strings.TrimSpace(strings.TrimSuffix(value, ";")))
	}
	return cidrs, nil
}

func parseTrustedCIDRGeoEntries(path string, text string) ([]string, error) {
	cidrs := []string{}
	for lineNumber, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != "1;" {
			return nil, fmt.Errorf("deployed realip artifact %s line %d must be CIDR 1;", path, lineNumber+1)
		}
		cidrs = append(cidrs, fields[0])
	}
	return cidrs, nil
}

func requireCIDRListMatch(path string, actual []string, expected []string) error {
	if _, err := realip.CanonicalCIDRs(actual); err != nil {
		return fmt.Errorf("validate deployed realip artifact %s CIDRs: %w", path, err)
	}
	if !stringSlicesEqual(actual, expected) {
		return fmt.Errorf("deployed realip artifact %s CIDRs %s do not match deployed state trusted CIDRs %s", path, listAsNone(actual), listAsNone(expected))
	}
	return nil
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func appGoAccessDeployNextSteps(cfg appconfig.Config, names appsvc.Names) []string {
	if !cfg.Nginx.GoAccess.Enabled {
		return nil
	}
	return []string{
		"Open https://" + cfg.PrimaryDomain() + cfg.NginxGoAccessDashboardPath() + " and sign in with the account from nginx.goaccess.auth_basic_user_file to verify the GoAccess dashboard.",
		appGoAccessFailureNextStep(cfg),
		"Common commands: " + appGoAccessTroubleshootingCommands(cfg, names),
	}
}

func appGoAccessFailureNextStep(cfg appconfig.Config) string {
	if cfg.Mode() == appconfig.ModeUpstream {
		return "For 5xx, upstream timeout, TLS, or permission denied issues, continue checking nginx.error_log, fixed tailnet upstream reachability, and remote service logs; the GoAccess dashboard does not parse Nginx error logs."
	}
	return "For 5xx, upstream timeout, TLS, or permission denied issues, continue checking nginx.error_log and the business service logs; the GoAccess dashboard does not parse Nginx error logs."
}

func appGoAccessTroubleshootingCommands(cfg appconfig.Config, names appsvc.Names) string {
	commands := []string{
		"systemctl status " + names.GoAccessServiceUnit + " --no-pager --full",
		"journalctl -u " + names.GoAccessServiceUnit + " -e",
		"tail -f " + names.GoAccessCanonicalAccessLogPath,
	}
	if errorLog := strings.TrimSpace(cfg.Nginx.ErrorLog); errorLog != "" {
		commands = append(commands, "tail -f "+errorLog)
	} else {
		commands = append(commands, "journalctl -u nginx.service -e", "tail -f /var/log/nginx/error.log")
	}
	if cfg.Mode() == appconfig.ModeListen {
		commands = append(commands, "journalctl -u "+names.ServiceUnit+" -e")
	}
	if cfg.RequiresTailscale() {
		commands = append(commands, "tailscale status")
	}
	if cfg.Mode() == appconfig.ModeUpstream {
		commands = append(commands, "curl -I http://"+cfg.App.Upstream)
	}
	return strings.Join(commands, "; ")
}

func appGoAccessDashboardScope(cfg appconfig.Config) string {
	scope := "request volume, visitors, URLs, 404/status codes, IP/Host, referrer, User-Agent/browser/OS, bandwidth, visit time"
	if cfg.Nginx.GoAccess.EffectiveLogFormat() == appconfig.NginxGoAccessLogFormatEnhanced {
		scope += ", request serving time"
	}
	return scope + "; upstream fields and nginx.error_log remain raw-log/troubleshooting inputs, not first-class GoAccess panels"
}

func appPreflightFields(report apppreflight.Report) []domain.ResultField {
	fields := make([]domain.ResultField, 0, len(report.Checks))
	for _, check := range report.Checks {
		fields = append(fields, domain.ResultField{Label: "check " + check.ID, Value: string(check.Status) + ": " + check.Summary})
	}
	return fields
}

func appPreflightDiagnostics(report apppreflight.Report) []domain.DiagnosticItem {
	diagnostics := make([]domain.DiagnosticItem, 0, len(report.Checks))
	for _, check := range report.Checks {
		status := appPreflightDiagnosticStatus(check.Status)
		scope, evidence, responsible := appPreflightDiagnosticMetadata(check.ID, check.Status)
		diagnostics = append(diagnostics, domain.DiagnosticItem{
			ID:               "app-preflight:" + check.ID,
			Title:            "app deploy preflight " + check.ID,
			Status:           status,
			Scope:            scope,
			Severity:         appPreflightDiagnosticSeverity(status),
			Summary:          strings.TrimSpace(check.Summary),
			EvidenceSource:   evidence,
			ResponsibleParty: responsible,
			BlocksActivation: appPreflightBlocksActivation(status),
			Remediation:      append([]string(nil), check.Remediations...),
			Redaction:        domain.RedactionNone,
			RedactionStatus:  domain.RedactionStatusNoSensitiveData,
		})
	}
	return diagnostics
}

func appPreflightDiagnosticStatus(status apppreflight.Status) domain.DiagnosticStatus {
	switch status {
	case apppreflight.StatusPass:
		return domain.DiagnosticStatusPass
	case apppreflight.StatusFail:
		return domain.DiagnosticStatusFail
	case apppreflight.StatusWarn:
		return domain.DiagnosticStatusWarn
	case apppreflight.StatusManual:
		return domain.DiagnosticStatusManual
	case apppreflight.StatusUnknown:
		return domain.DiagnosticStatusUnknown
	case apppreflight.StatusNotApplicable:
		return domain.DiagnosticStatusNotApplicable
	default:
		return domain.DiagnosticStatusUnknown
	}
}

func appPreflightDiagnosticMetadata(id string, status apppreflight.Status) (domain.DiagnosticScope, domain.DiagnosticEvidenceSource, domain.DiagnosticResponsibleParty) {
	if status == apppreflight.StatusManual {
		return domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceManual, domain.DiagnosticResponsibleLocalAdmin
	}
	switch {
	case id == "permissions":
		return domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin
	case strings.HasPrefix(id, "dns:"):
		return domain.DiagnosticScopeResource, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleDNSProvider
	case strings.HasPrefix(id, "port:"):
		return domain.DiagnosticScopeInstance, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin
	case id == "dns01-credentials":
		return domain.DiagnosticScopeCertificate, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin
	case id == "app-listen":
		return domain.DiagnosticScopeService, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleAppOwner
	case id == "service-binary":
		return domain.DiagnosticScopeService, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLocalAdmin
	case id == "service-env-file", id == "tailscale-auth-key-file", id == "browser-auth-file":
		return domain.DiagnosticScopeResource, domain.DiagnosticEvidenceRenderedFile, domain.DiagnosticResponsibleLocalAdmin
	case id == "tailscale":
		return domain.DiagnosticScopeResource, domain.DiagnosticEvidenceConfig, domain.DiagnosticResponsibleLocalAdmin
	case strings.HasPrefix(id, "goaccess-"):
		return domain.DiagnosticScopeGoAccess, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin
	case id == "realip-firewall":
		return domain.DiagnosticScopeRealIP, domain.DiagnosticEvidenceProviderAPI, domain.DiagnosticResponsibleLocalAdmin
	default:
		return domain.DiagnosticScopeResource, domain.DiagnosticEvidenceRuntimeProbe, domain.DiagnosticResponsibleLocalAdmin
	}
}

func appPreflightDiagnosticSeverity(status domain.DiagnosticStatus) domain.DiagnosticSeverity {
	switch status {
	case domain.DiagnosticStatusFail:
		return domain.DiagnosticSeverityCritical
	case domain.DiagnosticStatusUnknown:
		return domain.DiagnosticSeverityHigh
	case domain.DiagnosticStatusWarn, domain.DiagnosticStatusManual:
		return domain.DiagnosticSeverityMedium
	default:
		return domain.DiagnosticSeverityInfo
	}
}

func appPreflightBlocksActivation(status domain.DiagnosticStatus) bool {
	return status == domain.DiagnosticStatusFail || status == domain.DiagnosticStatusUnknown
}

func appPreflightWarningFields(report apppreflight.Report) []domain.ResultField {
	fields := []domain.ResultField{}
	for _, check := range report.Checks {
		if check.Status != apppreflight.StatusWarn && check.Status != apppreflight.StatusManual {
			continue
		}
		label := "preflight warning " + check.ID
		if check.Status == apppreflight.StatusManual {
			label = "preflight manual " + check.ID
		}
		fields = append(fields, domain.ResultField{Label: label, Value: check.Summary})
	}
	return fields
}

func appPreflightWarningNextSteps(report apppreflight.Report) []string {
	seen := map[string]struct{}{}
	steps := []string{}
	for _, check := range report.Checks {
		if check.Status != apppreflight.StatusWarn && check.Status != apppreflight.StatusManual {
			continue
		}
		for _, remediation := range check.Remediations {
			if strings.TrimSpace(remediation) == "" {
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

func detectAppDNS(cfg appconfig.Config) map[string]preflight.DNSProbe {
	probes := make(map[string]preflight.DNSProbe, len(cfg.App.Domains))
	expectedIPv4, expectedIPv6, expectedErr := detectAppExpectedPublicIPs(cfg)
	for _, domain := range cfg.App.Domains {
		resolved, err := net.LookupHost(domain)
		probe := preflight.DNSProbe{Host: domain, ResolvedIPs: resolved, ExpectedIPv4: expectedIPv4, ExpectedIPv6: expectedIPv6}
		if err != nil {
			probe.LookupError = err.Error()
		}
		if expectedErr != nil {
			probe.ExpectedIPError = expectedErr.Error()
		}
		probes[domain] = probe
	}
	return probes
}

func detectAppExpectedPublicIPs(cfg appconfig.Config) (string, string, error) {
	var client *http.Client
	mainConfigPath := cfg.EffectiveLanpanelConfig()
	if strings.TrimSpace(mainConfigPath) != "" {
		mainCfg, err := config.LoadFile(mainConfigPath)
		if err != nil {
			return "", "", fmt.Errorf("load tailscale.lanpanel_config %s: %w", mainConfigPath, err)
		}
		expectedIPv4 := strings.TrimSpace(mainCfg.Advanced.Network.PublicIPv4)
		expectedIPv6 := strings.TrimSpace(mainCfg.Advanced.Network.PublicIPv6)
		if expectedIPv4 != "" || expectedIPv6 != "" {
			return expectedIPv4, expectedIPv6, nil
		}
		client = newDeployHTTPClient(mainCfg.Advanced.Proxy, 3*time.Second)
	}
	return detectAppCurrentPublicIPsFn(client)
}

func detectAppCurrentPublicIPs(client *http.Client) (string, string, error) {
	ipv4, ipv4Err := detectAppPublicIP(client, "https://api4.ipify.org")
	ipv6, ipv6Err := detectAppPublicIP(client, "https://api6.ipify.org")
	return ipv4, ipv6, errors.Join(ipv4Err, ipv6Err)
}

func detectAppPublicIP(client *http.Client, endpoint string) (string, error) {
	client = httpClientOrDefault(client, 3*time.Second)
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build public IP request %s: %w", endpoint, err)
	}
	request.Header.Set("User-Agent", "lanpanel-app-preflight/1.0")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request public IP %s: %w", endpoint, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("request public IP %s returned HTTP %d", endpoint, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		return "", fmt.Errorf("read public IP response %s: %w", endpoint, err)
	}
	value := strings.TrimSpace(string(data))
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("parse public IP response %s: %w", endpoint, err)
	}
	if !isAppExpectedPublicIP(ip) {
		return "", fmt.Errorf("public IP response %s returned non-public address %s", endpoint, value)
	}
	return ip.Unmap().String(), nil
}

func isAppExpectedPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range appNonPublicRoutableIPPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func detectAppPortBindings() []preflight.PortBinding {
	tcpBindings, tcpDetected := detectSSBindingList("tcp", []int{80, 443})
	if !tcpDetected {
		return nil
	}
	bindings := make([]preflight.PortBinding, 0, len(tcpBindings)+2)
	for _, port := range []int{80, 443} {
		found := false
		for _, binding := range tcpBindings {
			if binding.Port != port || !strings.EqualFold(binding.Protocol, "tcp") {
				continue
			}
			bindings = append(bindings, binding)
			found = true
		}
		if found {
			continue
		}
		bindings = append(bindings, preflight.PortBinding{Port: port, Protocol: "tcp"})
	}
	return bindings
}

func detectAppListenPortState(cfg appconfig.Config) (bool, bool, string) {
	if cfg.Mode() != appconfig.ModeListen {
		return false, false, ""
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		return true, false, err.Error()
	}
	appHost, appPort, ok := splitAppHostPort(cfg.App.Listen)
	if !ok {
		return true, false, "app.listen must be in host:port format"
	}
	bindings, detected := detectSSBindingList("tcp", []int{appPort})
	if !detected {
		return true, false, "Could not confirm app.listen port usage"
	}
	overlapping := make([]preflight.PortBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Port != appPort || !binding.InUse {
			continue
		}
		if !appguard.SocketBindHostsOverlap(binding.LocalAddress, appHost) {
			continue
		}
		overlapping = append(overlapping, binding)
	}
	if len(overlapping) == 0 {
		return true, true, "app.listen " + cfg.App.Listen + " is available"
	}
	for _, binding := range overlapping {
		if strings.TrimSpace(binding.Process) == "" || binding.PID <= 0 {
			return true, false, "Could not confirm whether app.listen " + cfg.App.Listen + " is already used by current managed app or GoAccess service"
		}
		appManaged, appConfirmed := isAppManagedPortBindingFn(names, binding)
		if appConfirmed && appManaged {
			continue
		}
		goAccessManaged, goAccessConfirmed := isAppGoAccessManagedPortBindingFn(names, binding)
		if goAccessConfirmed && goAccessManaged {
			continue
		}
		if !appConfirmed {
			return true, false, "Could not confirm whether app.listen " + cfg.App.Listen + " is already used by current app service " + names.ServiceUnit
		}
		if !goAccessConfirmed {
			return true, false, "Could not confirm whether app.listen " + cfg.App.Listen + " is already used by current GoAccess service " + names.GoAccessServiceUnit
		}
		process := strings.TrimSpace(binding.Process)
		if process == "" {
			process = "unknown process"
		}
		return true, false, "app.listen " + cfg.App.Listen + " is already used by " + process
	}
	return true, true, "app.listen " + cfg.App.Listen + " is already used by current managed app or GoAccess service; deploy will refresh the owning service"
}

func detectAppDNSCredentialState(cfg appconfig.Config) (bool, bool, string) {
	if cfg.App.ACMEChallenge != appconfig.ACMEChallengeDNS01 {
		return false, false, ""
	}
	providerInfo, err := acme.DNSProvider(cfg.DNS01.Provider)
	if err != nil {
		return false, false, err.Error()
	}

	envFile := strings.TrimSpace(cfg.DNS01.EnvFile)
	if envFile != "" {
		env, ready, detail := inspectAppDNSEnvFile(envFile)
		if !ready {
			return true, false, fmt.Sprintf("DNS provider %q env_file is not ready: %s", providerInfo.LegoCode, detail)
		}
		if env != nil {
			if err := acme.ValidateDNSProviderEnvironment(providerInfo.LegoCode, env); err != nil {
				return true, false, strings.ReplaceAll(err.Error(), "advanced.dns01", "dns01")
			}
			if ready, detail := inspectAppDNSCredentialEnvFileReferences(providerInfo.LegoCode, env); !ready {
				return true, false, fmt.Sprintf("DNS provider %q env_file contains credential file references that are not ready: %s.", providerInfo.LegoCode, detail)
			}
		}
		return true, true, fmt.Sprintf("Using lego env_file for DNS provider %q: %s. %s", providerInfo.LegoCode, envFile, detail)
	}

	env := nonEmptyEnvironmentByKey()
	if providerInfo.LegoCode == "route53" && route53RawSecretEnvironmentPresent(env) && strings.TrimSpace(env["AWS_SHARED_CREDENTIALS_FILE"]) == "" {
		return true, false, "Detected Route53 AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in the current environment, but App publication will not pass raw AWS secrets to child services. Use dns01.env_file for DNS-01 publication and renewal."
	}
	if providerInfo.AmbientCredentialsSupported {
		detail := fmt.Sprintf("Using lego ambient credential chain for DNS provider %q; confirm deploy and %s run with the same host identity.", providerInfo.LegoCode, cfg.App.Name+"-lego-renew.service")
		if providerInfo.LegoCode == "gcloud" {
			detail += " For gcloud, confirm Google Cloud metadata also provides the project, or set dns01.env_file with GCE_PROJECT."
		}
		return true, true, detail
	}
	return true, false, fmt.Sprintf("DNS provider %q requires dns01.env_file so initial issuance and app lego renewal use the same provider environment.", providerInfo.LegoCode)
}

func inspectAppDNSEnvFile(filePath string) (map[string]string, bool, string) {
	ready, detail := inspectAppRootOnlyFile("dns01.env_file", filePath)
	if !ready {
		return nil, false, detail
	}
	content, readDetail, err := readDNSCredentialEnvFile(filePath)
	if err != nil {
		return nil, false, fmt.Sprintf("%s cannot be opened for validation: %s.", filePath, err)
	}
	if readDetail != "" {
		detail = strings.TrimSpace(detail + " " + readDetail)
	}
	env, syntaxDetail := parseDNSEnvFileContent(content)
	if syntaxDetail != "" {
		return env, false, fmt.Sprintf("%s contains unsupported syntax for systemd EnvironmentFile: %s. Use KEY=value lines without export.", filePath, syntaxDetail)
	}
	if len(env) == 0 {
		return env, false, fmt.Sprintf("%s does not contain any KEY=value environment assignments.", filePath)
	}
	return env, true, strings.ReplaceAll(detail, "advanced.dns01", "dns01")
}

func inspectAppDNSCredentialEnvFileReferences(provider string, env map[string]string) (bool, string) {
	invalidDetails := []string{}
	for key, value := range env {
		if !dnsCredentialEnvironmentValueIsFile(provider, key) {
			continue
		}
		if !filepath.IsAbs(value) {
			invalidDetails = append(invalidDetails, fmt.Sprintf("%s: referenced credential file path %q must be absolute so deploy and systemd renewal use the same runtime path", key, value))
			continue
		}
		ready, detail := inspectAppRootOnlyFile(key, value)
		if !ready {
			invalidDetails = append(invalidDetails, fmt.Sprintf("%s: %s", key, detail))
		}
	}
	invalidDetails = uniqueStrings(invalidDetails)
	if len(invalidDetails) > 0 {
		return false, strings.Join(invalidDetails, "; ")
	}
	return true, ""
}

func detectAppServiceEnvFileState(cfg appconfig.Config) (bool, bool, string) {
	path := strings.TrimSpace(cfg.Service.EnvFile)
	if cfg.Mode() != appconfig.ModeListen || path == "" {
		return false, false, ""
	}
	ready, detail := inspectAppRootOnlyFile("service.env_file", path)
	if !ready {
		return true, false, detail
	}
	return true, true, "service.env_file passed root-only validation"
}

func detectAppTailscaleAuthKeyFileState(cfg appconfig.Config) (bool, bool, string) {
	path := strings.TrimSpace(cfg.Tailscale.AuthKeyFile)
	if path == "" {
		return false, false, ""
	}
	if _, err := tailscalecomponent.ReadAuthKeyFile(path); err != nil {
		return true, false, err.Error()
	}
	return true, true, "tailscale.auth_key_file passed root-only validation"
}

func detectAppGoAccessAuthFileState(cfg appconfig.Config) (bool, bool, string) {
	if !cfg.Nginx.GoAccess.Enabled {
		return false, false, ""
	}
	path := strings.TrimSpace(cfg.Nginx.GoAccess.AuthBasicUserFile)
	if path == "" {
		return true, false, "nginx.goaccess.auth_basic_user_file is required"
	}
	info, err := lstatAppServicePathFn(path)
	if err != nil {
		return true, false, "nginx.goaccess.auth_basic_user_file unavailable: " + err.Error()
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, false, "nginx.goaccess.auth_basic_user_file must not be a symlink"
	}
	if !info.Mode().IsRegular() {
		return true, false, "nginx.goaccess.auth_basic_user_file must be a regular file"
	}
	if info.Size() == 0 {
		return true, false, "nginx.goaccess.auth_basic_user_file must not be empty"
	}
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		return true, false, "nginx.goaccess.auth_basic_user_file must be owned by root"
	}
	if info.Mode().Perm()&0o020 != 0 || info.Mode().Perm()&0o007 != 0 {
		return true, false, "nginx.goaccess.auth_basic_user_file must not be group-writable or accessible by others"
	}
	if err := validateGoAccessAuthBasicUserFileContent(path); err != nil {
		return true, false, err.Error()
	}
	if err := validateAppRootOwnedFileParents("nginx.goaccess.auth_basic_user_file", path, false); err != nil {
		return true, false, err.Error()
	}
	return true, true, "nginx.goaccess.auth_basic_user_file passed static path, permission, content, and parent-directory safety checks; Nginx runtime readability will be checked after host dependencies are installed"
}

func detectAppBrowserAuthFileState(cfg appconfig.Config) (bool, bool, string) {
	if !cfg.BrowserAuthEnabled() {
		return false, false, ""
	}
	path := strings.TrimSpace(cfg.BrowserAuthUserFile())
	if path == "" {
		return true, false, "access.browser_auth htpasswd file is required"
	}
	info, err := lstatAppServicePathFn(path)
	if err != nil {
		return true, false, "access.browser_auth htpasswd file unavailable: " + err.Error()
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, false, "access.browser_auth htpasswd file must not be a symlink"
	}
	if !info.Mode().IsRegular() {
		return true, false, "access.browser_auth htpasswd file must be a regular file"
	}
	if info.Size() == 0 {
		return true, false, "access.browser_auth htpasswd file must not be empty"
	}
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		return true, false, "access.browser_auth htpasswd file must be owned by root"
	}
	if info.Mode().Perm()&0o020 != 0 || info.Mode().Perm()&0o007 != 0 {
		return true, false, "access.browser_auth htpasswd file must not be group-writable or accessible by others"
	}
	if cfg.Access.BrowserAuth.Managed.HtpasswdPath != "" {
		if err := validateManagedBrowserAuthFileContent("access.browser_auth managed htpasswd file", path); err != nil {
			return true, false, err.Error()
		}
	} else if err := validateAuthBasicUserFileContent("access.browser_auth htpasswd file", path); err != nil {
		return true, false, err.Error()
	}
	if err := validateAppRootOwnedFileParents("access.browser_auth htpasswd file", path, false); err != nil {
		return true, false, err.Error()
	}
	return true, true, "access.browser_auth htpasswd file passed static path, permission, content, and parent-directory safety checks; Nginx runtime readability will be checked after host dependencies are installed"
}

func detectAppGoAccessPortState(cfg appconfig.Config) (bool, bool, string) {
	if !cfg.Nginx.GoAccess.Enabled {
		return false, false, ""
	}
	names, err := appsvc.NewNames(cfg)
	if err != nil {
		return true, false, err.Error()
	}
	bindings, detected := detectSSBindingList("tcp", []int{names.GoAccessWebSocketPort})
	if !detected {
		return true, false, "Could not confirm GoAccess WebSocket port usage"
	}
	overlapping := make([]preflight.PortBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Port != names.GoAccessWebSocketPort || !binding.InUse {
			continue
		}
		if !appguard.SocketBindHostsOverlap(binding.LocalAddress, names.GoAccessWebSocketHost) {
			continue
		}
		overlapping = append(overlapping, binding)
	}
	if len(overlapping) == 0 {
		return true, true, fmt.Sprintf("GoAccess WebSocket loopback port %d is available", names.GoAccessWebSocketPort)
	}
	for _, binding := range overlapping {
		appManaged, appConfirmed := isAppManagedPortBindingFn(names, binding)
		if appConfirmed && appManaged {
			continue
		}
		managed, confirmed := isAppGoAccessManagedPortBindingFn(names, binding)
		if confirmed && managed {
			continue
		}
		if !appConfirmed {
			return true, false, fmt.Sprintf("Could not confirm whether GoAccess WebSocket port %d is already used by current app service %s", names.GoAccessWebSocketPort, names.ServiceUnit)
		}
		if !confirmed {
			return true, false, fmt.Sprintf("Could not confirm whether GoAccess WebSocket port %d is already used by current GoAccess service %s", names.GoAccessWebSocketPort, names.GoAccessServiceUnit)
		}
		process := strings.TrimSpace(binding.Process)
		if process == "" {
			process = "unknown process"
		}
		return true, false, fmt.Sprintf("GoAccess WebSocket port %d is already used by %s", names.GoAccessWebSocketPort, process)
	}
	return true, true, fmt.Sprintf("GoAccess WebSocket port %d is already used by current managed app or GoAccess service (%s); deploy will refresh the owning service", names.GoAccessWebSocketPort, names.GoAccessServiceUnit)
}

func detectAppGoAccessAppListenBlockers(cfg appconfig.Config, names appsvc.Names) ([]preflight.PortBinding, bool) {
	if cfg.Mode() != appconfig.ModeListen {
		return nil, true
	}
	appHost, appPort, ok := splitAppHostPort(cfg.App.Listen)
	if !ok {
		return nil, false
	}
	bindings, detected := detectSSBindingList("tcp", []int{appPort})
	if !detected {
		return nil, false
	}
	blockers := make([]preflight.PortBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Port != appPort || !binding.InUse {
			continue
		}
		if !appguard.SocketBindHostsOverlap(binding.LocalAddress, appHost) {
			continue
		}
		if strings.TrimSpace(binding.Process) == "" || binding.PID <= 0 {
			return nil, false
		}
		appManaged, appConfirmed := isAppManagedPortBindingFn(names, binding)
		if appConfirmed && appManaged {
			continue
		}
		managed, confirmed := isAppGoAccessManagedPortBindingFn(names, binding)
		if confirmed && managed {
			blockers = append(blockers, binding)
			continue
		}
		if !appConfirmed || !confirmed {
			return nil, false
		}
		return nil, false
	}
	return blockers, true
}

func detectAppGoAccessAppPortBlockers(cfg appconfig.Config, names appsvc.Names) ([]preflight.PortBinding, bool) {
	if !cfg.Nginx.GoAccess.Enabled {
		return nil, true
	}
	bindings, detected := detectSSBindingList("tcp", []int{names.GoAccessWebSocketPort})
	if !detected {
		return nil, false
	}
	blockers := make([]preflight.PortBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.Port != names.GoAccessWebSocketPort || !binding.InUse {
			continue
		}
		if !appguard.SocketBindHostsOverlap(binding.LocalAddress, names.GoAccessWebSocketHost) {
			continue
		}
		if strings.TrimSpace(binding.Process) == "" || binding.PID <= 0 {
			return nil, false
		}
		managed, confirmed := isAppManagedPortBindingFn(names, binding)
		if confirmed && managed {
			blockers = append(blockers, binding)
			continue
		}
		goAccessManaged, goAccessConfirmed := isAppGoAccessManagedPortBindingFn(names, binding)
		if goAccessConfirmed && goAccessManaged {
			continue
		}
		if !confirmed || !goAccessConfirmed {
			return nil, false
		}
		return nil, false
	}
	return blockers, true
}

func validateGoAccessAuthBasicUserFileContent(path string) error {
	return validateAuthBasicUserFileContent("nginx.goaccess.auth_basic_user_file", path)
}

func validateManagedBrowserAuthFileContent(label string, path string) error {
	data, err := readAppServicePathFn(path)
	if err != nil {
		return fmt.Errorf("%s cannot be opened for validation: %w", label, err)
	}
	if err := browserauth.ValidateManagedContent(data); err != nil {
		return fmt.Errorf("%s validation failed: %w", label, err)
	}
	return nil
}

func validateAuthBasicUserFileContent(label string, path string) error {
	data, err := readAppServicePathFn(path)
	if err != nil {
		return fmt.Errorf("%s cannot be opened for validation: %w", label, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if goAccessAuthLineIsBlankOrComment(line) {
			continue
		}
		if goAccessAuthLineHasCredential(line) {
			return nil
		}
	}
	return fmt.Errorf("%s must contain at least one user:hash credential line", label)
}

func goAccessAuthLineIsBlankOrComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

func goAccessAuthLineHasCredential(line string) bool {
	if startsWithSpace(line) {
		return false
	}
	user, hash, ok := strings.Cut(line, ":")
	if !ok || user == "" || hash == "" {
		return false
	}
	if strings.IndexFunc(user, unicode.IsSpace) >= 0 {
		return false
	}
	return strings.IndexFunc(hash, unicode.IsSpace) < 0
}

func startsWithSpace(value string) bool {
	for _, r := range value {
		return unicode.IsSpace(r)
	}
	return false
}

func isAppGoAccessManagedPortBinding(names appsvc.Names, binding preflight.PortBinding) (bool, bool) {
	process := strings.TrimSpace(binding.Process)
	if process == "" || binding.PID <= 0 {
		return false, false
	}
	if !strings.EqualFold(process, "goaccess") {
		return false, true
	}
	return isLanpanelManagedSystemdUnitPortBinding(names.AppName, names.GoAccessServiceUnit, binding)
}

func isAppManagedPortBinding(names appsvc.Names, binding preflight.PortBinding) (bool, bool) {
	if strings.TrimSpace(binding.Process) == "" || binding.PID <= 0 {
		return false, false
	}
	return isLanpanelManagedSystemdUnitPortBinding(names.AppName, names.ServiceUnit, binding)
}

func isLanpanelManagedSystemdUnitPortBinding(appName string, unit string, binding preflight.PortBinding) (bool, bool) {
	if binding.PID <= 0 {
		return false, false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, false
	}
	unitPath := filepath.Join("/etc/systemd/system", unit)
	content, err := readAppServiceUnitFileFn(unitPath)
	if err != nil {
		return false, false
	}
	if err := appsvc.CheckManagedContent(appName, content); err != nil {
		return false, true
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", unit).Run(); err != nil {
		return false, false
	}
	mainPID, ok := systemdUnitMainPID(unit)
	if !ok {
		return false, false
	}
	if binding.PID == mainPID {
		return true, true
	}
	controlGroup, ok := systemdUnitControlGroup(unit)
	if !ok {
		return false, false
	}
	cgroupContent, err := readAppProcessCgroupFileFn(filepath.Join("/proc", strconv.Itoa(binding.PID), "cgroup"))
	if err != nil {
		return false, false
	}
	return processCgroupContainsSystemdControlGroup(cgroupContent, controlGroup), true
}

func systemdUnitMainPID(unit string) (int, bool) {
	output, err := exec.Command("systemctl", "show", unit, "--property=MainPID", "--value").Output()
	if err != nil {
		return 0, false
	}
	mainPID, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || mainPID <= 0 {
		return 0, false
	}
	return mainPID, true
}

func systemdUnitControlGroup(unit string) (string, bool) {
	output, err := exec.Command("systemctl", "show", unit, "--property=ControlGroup", "--value").Output()
	if err != nil {
		return "", false
	}
	controlGroup := strings.TrimSpace(string(output))
	if controlGroup == "" || !strings.HasPrefix(controlGroup, "/") {
		return "", false
	}
	return controlGroup, true
}

func nonEmptyLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func processCgroupContainsSystemdControlGroup(content []byte, controlGroup string) bool {
	controlGroup = strings.TrimRight(strings.TrimSpace(controlGroup), "/")
	if controlGroup == "" {
		return false
	}
	for _, line := range nonEmptyLines(string(content)) {
		_, path, ok := strings.Cut(strings.TrimSpace(line), "::")
		if !ok {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
			if len(parts) != 3 {
				continue
			}
			path = parts[2]
		}
		path = strings.TrimRight(strings.TrimSpace(path), "/")
		if path == controlGroup || strings.HasPrefix(path, controlGroup+"/") {
			return true
		}
	}
	return false
}

func detectAppGoAccessLocaleState(cfg appconfig.Config) (bool, bool, string) {
	if !cfg.Nginx.GoAccess.Enabled {
		return false, false, ""
	}
	language := cfg.Nginx.GoAccess.EffectiveLanguage()
	output, err := exec.Command("locale", "-a").Output()
	if err != nil {
		return true, false, "Could not read locale list: " + err.Error()
	}
	required := []struct {
		prefix string
		label  string
	}{
		{prefix: "c", label: "C.UTF-8"},
	}
	if language == appconfig.NginxGoAccessLanguageSimplifiedChinese {
		required = append(required, struct {
			prefix string
			label  string
		}{prefix: "zh_cn", label: "zh_CN.UTF-8"})
	}
	missing := make([]string, 0)
	for _, locale := range required {
		if !hasLocaleUTF8Line(string(output), locale.prefix) {
			missing = append(missing, locale.label)
		}
	}
	if len(missing) > 0 {
		return true, false, "GoAccess language " + language + " requires locale(s): " + strings.Join(missing, ", ")
	}
	return true, true, "GoAccess language " + language + " locale is available"
}

func hasLocaleUTF8Line(output string, localePrefix string) bool {
	want := strings.ToLower(strings.TrimSpace(localePrefix)) + ".utf8"
	for _, line := range strings.Split(output, "\n") {
		normalized := strings.ToLower(strings.TrimSpace(line))
		normalized = strings.ReplaceAll(normalized, "-", "")
		if normalized == want {
			return true
		}
	}
	return false
}

func detectAppGoAccessLogFileState(cfg appconfig.Config) (bool, bool, string) {
	if !cfg.Nginx.GoAccess.Enabled || strings.TrimSpace(cfg.Nginx.AccessLog) == "" || appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
		return false, false, ""
	}
	path := strings.TrimSpace(cfg.Nginx.AccessLog)
	info, err := lstatAppServicePathFn(path)
	if err != nil {
		return true, false, "explicit nginx.access_log unavailable: " + err.Error()
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, false, "explicit nginx.access_log must not be a symlink"
	}
	if !info.Mode().IsRegular() {
		return true, false, "explicit nginx.access_log must be a regular file"
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return true, false, "explicit nginx.access_log owner could not be inspected"
	}
	if uid != 0 && uid != 33 {
		return true, false, "explicit nginx.access_log must be owned by root or www-data"
	}
	if info.Mode().Perm()&0o022 != 0 {
		return true, false, "explicit nginx.access_log must not be writable by group or others"
	}
	if err := validateAppRootOwnedFileParents("explicit nginx.access_log", path, false); err != nil {
		return true, false, err.Error()
	}
	return true, true, "explicit nginx.access_log passed static file and parent-directory safety checks; GoAccess runtime readability will be checked after creating system user"
}

func inspectAppRootOnlyFile(field string, path string) (bool, string) {
	info, err := lstatAppServicePathFn(path)
	if err != nil {
		return false, field + " unavailable: " + err.Error()
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, field + " must not be a symlink"
	}
	if !info.Mode().IsRegular() {
		return false, field + " must be a regular file"
	}
	if info.Size() == 0 {
		return false, field + " must not be empty"
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false, field + " must be root-only, for example mode 0600"
	}
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		return false, field + " must be owned by root"
	}
	if err := validateAppRootOnlyFileParents(field, path); err != nil {
		return false, err.Error()
	}
	return true, field + " passed root-only validation"
}

func validateAppRootOnlyFileParents(field string, path string) error {
	return validateAppRootOwnedFileParents(field, path, true)
}

func validateAppRootOwnedFileParents(field string, path string, allowStickyAncestors bool) error {
	dir := filepath.Dir(path)
	immediateParent := dir
	for {
		info, err := lstatAppServicePathFn(dir)
		if err != nil {
			return fmt.Errorf("%s parent directory %s unavailable: %w", field, dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s parent directory %s must not be a symlink", field, dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s parent path %s must be a directory", field, dir)
		}
		if info.Mode().Perm()&0o022 != 0 && (!allowStickyAncestors || dir == immediateParent || info.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("%s parent directory %s must not be writable by group or others", field, dir)
		}
		if uid, ok := fileOwnerUID(info); ok && uid != 0 {
			return fmt.Errorf("%s parent directory %s must be owned by root", field, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

type appRuntimeReadTarget struct {
	username string
	uid      uint64
	gids     map[uint64]struct{}
	found    bool
}

func newAppRuntimeReadTarget(username string) appRuntimeReadTarget {
	target := appRuntimeReadTarget{username: strings.TrimSpace(username), gids: map[uint64]struct{}{}}
	if target.username == "" {
		return target
	}
	account, err := user.Lookup(target.username)
	if err != nil {
		return target
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 64)
	if err != nil {
		return target
	}
	target.uid = uid
	target.found = true
	if gid, err := strconv.ParseUint(account.Gid, 10, 64); err == nil {
		target.gids[gid] = struct{}{}
	}
	if groupIDs, err := account.GroupIds(); err == nil {
		for _, groupID := range groupIDs {
			gid, err := strconv.ParseUint(groupID, 10, 64)
			if err == nil {
				target.gids[gid] = struct{}{}
			}
		}
	}
	return target
}

func validateAppRuntimeReadableFile(field string, path string, info os.FileInfo, runtimeLabel string, username string) error {
	target := newAppRuntimeReadTarget(username)
	if !appRuntimeModeAllows(info, target, 0o400, 0o040, 0o004) {
		return fmt.Errorf("%s must be readable by %s runtime user %s", field, runtimeLabel, username)
	}
	dir := filepath.Dir(path)
	for {
		parentInfo, err := lstatAppServicePathFn(dir)
		if err != nil {
			return fmt.Errorf("%s parent directory %s unavailable: %w", field, dir, err)
		}
		if !appRuntimeModeAllows(parentInfo, target, 0o100, 0o010, 0o001) {
			return fmt.Errorf("%s parent directory %s must be searchable by %s runtime user %s", field, dir, runtimeLabel, username)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func appRuntimeModeAllows(info os.FileInfo, target appRuntimeReadTarget, ownerBit fs.FileMode, groupBit fs.FileMode, otherBit fs.FileMode) bool {
	mode := info.Mode().Perm()
	if target.found {
		if uid, ok := fileOwnerUID(info); ok && uid == target.uid && mode&ownerBit != 0 {
			return true
		}
		if gid, ok := fileOwnerGID(info); ok {
			if _, groupMember := target.gids[gid]; groupMember && mode&groupBit != 0 {
				return true
			}
		}
	}
	return mode&otherBit != 0
}

func detectAppServiceBinary(cfg appconfig.Config) (bool, string) {
	if cfg.Mode() != appconfig.ModeListen {
		return true, ""
	}
	path := cfg.ServiceBinary()
	if path == "" {
		return false, ""
	}
	info, err := statAppServiceBinaryFn(path)
	if err != nil || info.IsDir() {
		return false, path
	}
	return info.Mode().Perm()&0o111 != 0, path
}

func guardAppOwnership(fileSystem host.FileSystem, cfg appconfig.Config, staged []apprender.StagedFile) error {
	for _, file := range staged {
		info, err := fileSystem.Lstat(file.HostPath)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat existing %s: %w", file.HostPath, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to inspect managed app file", file.HostPath)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file; refusing to inspect managed app file", file.HostPath)
		}
		content, err := fileSystem.ReadFile(file.HostPath)
		if err != nil {
			return fmt.Errorf("read existing %s: %w", file.HostPath, err)
		}
		if err := appsvc.CheckManagedContent(cfg.App.Name, content); err != nil {
			return fmt.Errorf("%s: %w", file.HostPath, err)
		}
	}
	return nil
}

func convertAppStagedFiles(files []apprender.StagedFile) []render.StagedFile {
	converted := make([]render.StagedFile, 0, len(files))
	for _, file := range files {
		converted = append(converted, render.StagedFile{
			SourcePath:  file.SourcePath,
			HostPath:    file.HostPath,
			ContentMode: file.ContentMode,
			Mode:        file.Mode,
			Content:     file.Content,
		})
	}
	return converted
}

func ensureAppHostDependencies(ctx stdcontext.Context, cfg appconfig.Config, executor host.Executor) error {
	if _, err := executor.AptGet(ctx, "update"); err != nil {
		return err
	}
	installArgs := append([]string{"install", "-y"}, appHostDependencyPackages(cfg)...)
	if _, err := executor.AptGet(ctx, installArgs...); err != nil {
		return err
	}
	if cfg.Nginx.GoAccess.Enabled {
		if err := ensureAppGoAccessDependency(ctx, executor); err != nil {
			return err
		}
	}
	legoResult, err := executor.Run(ctx, host.Command{Name: legocomponent.BinaryPath, Args: []string{"--version"}})
	if err == nil {
		return nil
	}
	if !host.CommandMissing(legoResult, err, legocomponent.BinaryPath, "lego") {
		return err
	}
	detected, detectErr := executor.Dpkg(ctx, "--print-architecture")
	if detectErr != nil {
		return fmt.Errorf("detect package architecture with dpkg --print-architecture: %w", detectErr)
	}
	legoCfg, err := appLegoInstallConfig(cfg, detected.Stdout)
	if err != nil {
		return err
	}
	plan, err := legocomponent.NewInstallPlan(legoCfg, legocomponent.InstallPlanOptions{
		ReachabilityTimeout: cfg.Dependencies.PackageProbe.EffectiveReachabilityTimeout(),
		ArtifactTimeout:     cfg.Dependencies.PackageProbe.EffectiveArtifactTimeout(),
	})
	if err != nil {
		return err
	}
	_, err = legocomponent.NewInstaller(executor).Install(ctx, plan)
	return err
}

func appLegoInstallConfig(cfg appconfig.Config, dpkgArch string) (config.Config, error) {
	detectedArch, err := appPackageArchFromDpkg(dpkgArch)
	if err != nil {
		return config.Config{}, err
	}
	configuredArch := strings.TrimSpace(cfg.Dependencies.Platform.Arch)
	if configuredArch == "" {
		return config.Config{}, fmt.Errorf("dependencies.platform.arch is required for app lego install")
	}
	if configuredArch != detectedArch {
		return config.Config{}, fmt.Errorf("dependencies.platform.arch is %q but dpkg reports %q; update dependencies.platform.arch to %q and rerun app deploy", configuredArch, detectedArch, detectedArch)
	}
	legoCfg := config.ExampleConfig()
	legoCfg.Advanced.LegoSource = cfg.Dependencies.LegoSource
	legoCfg.Advanced.PackageProbe = cfg.Dependencies.PackageProbe
	legoCfg.Advanced.Proxy = cfg.Dependencies.Proxy
	legoCfg.Advanced.Platform = cfg.Dependencies.Platform
	return legoCfg, nil
}

func appPackageArchFromDpkg(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "amd64":
		return config.ArchAMD64, nil
	case "arm64":
		return config.ArchARM64, nil
	default:
		return "", fmt.Errorf("unsupported package architecture %q for app lego install", strings.TrimSpace(raw))
	}
}

func appDependencyProxyEnv(cfg appconfig.Config) map[string]string {
	return host.ProxyEnv(
		cfg.Dependencies.Proxy.HTTPProxy,
		cfg.Dependencies.Proxy.HTTPSProxy,
		cfg.Dependencies.Proxy.NoProxy,
	)
}

func EnsureAppHostDependencies(ctx stdcontext.Context, cfg appconfig.Config, executor host.Executor) error {
	return ensureAppHostDependencies(ctx, cfg, executor)
}

func EnsureBrowserAuthDependencies(ctx stdcontext.Context, dependencies Dependencies) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	restore := applyDependencies(dependencies)
	defer restore()
	executor := newHostExecutorFn(nil)
	privilege := deployPrivilegeStrategy(detectPermissionStateFn())
	return ensureBrowserAuthDependencies(ctx, executor.WithPrivilege(privilege))
}

func ensureBrowserAuthDependencies(ctx stdcontext.Context, executor host.Executor) error {
	if _, err := executor.AptGet(ctx, "update"); err != nil {
		return err
	}
	_, err := executor.AptGet(ctx, "install", "-y", "nginx", "apache2-utils")
	return err
}

func ensureAppNginxRuntimeCompatibility(ctx stdcontext.Context, cfg appconfig.Config, executor host.Executor) error {
	needsHTTP2 := cfg.NginxHTTP2Enabled()
	needsGzipStatic := appNginxUsesGzipStatic(cfg)
	needsRealIP := cfg.RealIPEnabled()
	if !needsHTTP2 && !needsGzipStatic && !needsRealIP {
		return nil
	}
	result, err := executor.Run(ctx, host.Command{Name: appsvc.NginxBinaryPath, Args: []string{"-V"}})
	if err != nil {
		return fmt.Errorf("run %s -V to confirm Nginx module support: %w", appsvc.NginxBinaryPath, err)
	}
	output := result.Stdout + "\n" + result.Stderr
	if needsHTTP2 {
		version, ok := parseNginxVersion(output)
		if !ok {
			return fmt.Errorf("unable to parse nginx -V output while confirming HTTP/2 directive support")
		}
		if compareDottedVersion(version, minimumNginxHTTP2DirectiveVersion) < 0 {
			return fmt.Errorf("nginx %s does not support the modern \"http2 on;\" directive; require nginx >= %s or set nginx.http2: false", version, minimumNginxHTTP2DirectiveVersion)
		}
		if !strings.Contains(output, "--with-http_v2_module") {
			return fmt.Errorf("installed Nginx was not built with --with-http_v2_module; set nginx.http2: false or install an Nginx package with HTTP/2 support")
		}
	}
	if needsGzipStatic && !strings.Contains(output, "--with-http_gzip_static_module") {
		return fmt.Errorf("installed Nginx was not built with --with-http_gzip_static_module; remove gzip_static: true or install an Nginx package with gzip_static support")
	}
	if needsRealIP && !strings.Contains(output, "--with-http_realip_module") {
		return fmt.Errorf("installed Nginx was not built with --with-http_realip_module; install an Nginx package with ngx_http_realip_module before enabling access.origin_protection.Mode: edgeone and access.origin_protection.edgeone_profile")
	}
	return nil
}

func appNginxUsesGzipStatic(cfg appconfig.Config) bool {
	for _, location := range cfg.Nginx.StaticLocations {
		if location.GzipStatic {
			return true
		}
	}
	return false
}

func parseNginxVersion(output string) (string, bool) {
	match := nginxVersionPattern.FindStringSubmatch(output)
	if len(match) != 4 {
		return "", false
	}
	return match[1] + "." + match[2] + "." + match[3], true
}

func compareDottedVersion(left string, right string) int {
	leftParts := parseDottedVersion(left)
	rightParts := parseDottedVersion(right)
	for index := 0; index < 3; index++ {
		switch {
		case leftParts[index] < rightParts[index]:
			return -1
		case leftParts[index] > rightParts[index]:
			return 1
		}
	}
	return 0
}

func parseDottedVersion(value string) [3]int {
	parts := strings.Split(value, ".")
	var parsed [3]int
	for index := 0; index < len(parsed) && index < len(parts); index++ {
		number, err := strconv.Atoi(parts[index])
		if err != nil {
			continue
		}
		parsed[index] = number
	}
	return parsed
}

func ensureAppGoAccessDependency(ctx stdcontext.Context, executor host.Executor) error {
	_, err := executor.Run(ctx, goAccessProbeCommand("--version"))
	if err != nil {
		return fmt.Errorf("%s --version failed after package install: %w", appsvc.GoAccessBinaryPath, err)
	}
	result, err := executor.Run(ctx, goAccessProbeCommand("--help"))
	help := strings.TrimSpace(result.Stdout + "\n" + result.Stderr)
	if err != nil && !goAccessHelpHasAllRequiredOptions(help) {
		return fmt.Errorf("%s --help failed while checking required runtime parameters: %w", appsvc.GoAccessBinaryPath, err)
	}
	if help == "" {
		return fmt.Errorf("%s --help returned empty output while checking required runtime parameters", appsvc.GoAccessBinaryPath)
	}
	for _, flag := range goAccessRequiredRuntimeOptions() {
		if !goAccessHelpHasOption(help, flag) {
			return fmt.Errorf("installed %s does not advertise required option %s; install a newer GoAccess package", appsvc.GoAccessBinaryPath, flag)
		}
	}
	result, err = executor.Run(ctx, goAccessFreshDBCompatibilityCommand())
	if err != nil {
		return fmt.Errorf("installed %s failed Lanpanel fresh db persist/restore compatibility check: %w", appsvc.GoAccessBinaryPath, err)
	}
	return nil
}

func goAccessProbeCommand(arg string) host.Command {
	return host.Command{
		Name: appsvc.GoAccessBinaryPath,
		Args: []string{arg},
		Env:  goAccessProbeEnv(),
	}
}

func goAccessProbeEnv() map[string]string {
	return map[string]string{
		"LANG":   "C",
		"LC_ALL": "C",
	}
}

func goAccessFreshDBCompatibilityCommand() host.Command {
	script := `set -eu
binary=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/db"
cat > "$work/access.log" <<'LOG'
203.0.113.10 - - [2026-05-24T21:00:00+08:00] "GET /lanpanel-goaccess-probe HTTP/1.1" 200 123 "-" "lanpanel-goaccess-probe" "lanpanel.invalid" 0.001 "-" "-"
LOG
cat > "$work/goaccess.conf" <<EOF
log-file $work/access.log
output $work/report.html
log-format %h %^ %^ [%x] "%r" %s %b "%R" "%u" "%v" %T "%^" "%^"
datetime-format %Y-%m-%dT%H:%M:%S%z
persist true
restore true
db-path $work/db
html-report-title Lanpanel-GoAccess-Probe
EOF
if ! "$binary" --no-global-config --config-file "$work/goaccess.conf" >"$work/stdout" 2>"$work/stderr"; then
    cat "$work/stdout" >&2
    cat "$work/stderr" >&2
    exit 1
fi
if [ ! -s "$work/report.html" ]; then
    echo "GoAccess fresh db compatibility probe did not create an HTML report" >&2
    exit 1
fi
db_file=$(find "$work/db" -maxdepth 1 -type f -name '*.db' -print -quit)
if [ -z "$db_file" ]; then
    echo "GoAccess fresh db compatibility probe did not create persisted db files" >&2
    exit 1
fi`
	return host.Command{
		Name:        "sh",
		Args:        []string{"-c", script, "lanpanel-app-goaccess-fresh-db-compatibility", appsvc.GoAccessBinaryPath},
		Env:         goAccessProbeEnv(),
		DisplayName: "check-goaccess-fresh-db-compatibility",
		DisplayArgs: []string{appsvc.GoAccessBinaryPath},
	}
}

func goAccessHelpHasOption(help string, option string) bool {
	for _, field := range strings.Fields(help) {
		token := strings.Trim(field, " ,;")
		if token == option || strings.HasPrefix(token, option+"=") {
			return true
		}
	}
	return false
}

func goAccessHelpHasAllRequiredOptions(help string) bool {
	if strings.TrimSpace(help) == "" {
		return false
	}
	for _, flag := range goAccessRequiredRuntimeOptions() {
		if !goAccessHelpHasOption(help, flag) {
			return false
		}
	}
	return true
}

func goAccessRequiredRuntimeOptions() []string {
	return []string{"--no-global-config", "--config-file", "--log-file", "--output", "--log-format", "--datetime-format", "--date-format", "--time-format", "--real-time-html", "--addr", "--port", "--ws-url", "--origin", "--ping-interval", "--persist", "--restore", "--db-path", "--html-report-title", "--static-file"}
}

func appHostDependencyPackages(cfg appconfig.Config) []string {
	packages := []string{"nginx", "apache2-utils", "ca-certificates", "curl", "tar", "openssl"}
	if cfg.Nginx.GoAccess.Enabled {
		packages = append(packages, "goaccess")
		if appsvc.GoAccessManagesCanonicalAccessLog(cfg) {
			packages = append(packages, "logrotate")
		}
	}
	return packages
}

func ensureAppTailscale(ctx stdcontext.Context, cfg appconfig.Config, executor host.Executor) (tailscalecomponent.EnsureResult, error) {
	loginServer, err := appTailscaleLoginServer(cfg)
	if err != nil {
		return tailscalecomponent.EnsureResult{}, err
	}
	client := tailscalecomponent.NewClient(executor, detectPlatformInfoFn())
	authKey := ""
	result, err := client.Ensure(ctx, tailscalecomponent.EnsurePlan{
		Required:    cfg.RequiresTailscale(),
		LoginServer: loginServer,
		Hostname:    cfg.Tailscale.Hostname,
		AuthKeyFunc: func(ctx stdcontext.Context) (string, error) {
			var err error
			authKey, err = appTailscaleAuthKey(ctx, cfg, executor)
			return authKey, err
		},
	})
	if err == nil {
		return result, nil
	}
	if authKey != "" {
		return result, fmt.Errorf("%s", tailscalecomponent.MaskText(err.Error(), authKey))
	}
	return result, err
}

func appTailscaleLoginServer(cfg appconfig.Config) (string, error) {
	if strings.TrimSpace(cfg.Tailscale.LoginServer) != "" {
		return strings.TrimSpace(cfg.Tailscale.LoginServer), nil
	}
	mainConfigPath := cfg.EffectiveLanpanelConfig()
	mainCfg, err := config.LoadFile(mainConfigPath)
	if err != nil {
		return "", fmt.Errorf("load tailscale.lanpanel_config %s: %w", mainConfigPath, err)
	}
	return mainCfg.Default.ServerURL, nil
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

func appMainConfigConflictResponse(configPath string, command string, err error) commandResponse {
	return commandResponse{
		Command: command,
		Status:  "invalid-config",
		Summary: "App config conflicts with main Headscale server_url or metrics_port",
		Fields: []domain.ResultField{
			{Label: "config path", Value: configPath},
			{Label: "details", Value: err.Error()},
		},
		NextSteps: []string{"Change app.domains, app.listen, or nginx.goaccess.websocket_listen so the app uses separate domains and does not reuse the main Headscale port."},
	}
}

func appTailscaleAuthKey(_ stdcontext.Context, cfg appconfig.Config, _ host.Executor) (string, error) {
	if cfg.Tailscale.AuthKeyFile != "" {
		key, err := tailscalecomponent.ReadAuthKeyFile(cfg.Tailscale.AuthKeyFile)
		if err != nil {
			return "", fmt.Errorf("tailscale.auth_key_file unavailable: %w", err)
		}
		return key, nil
	}
	return "", fmt.Errorf("tailscale client is not logged in; app deploy does not create Headscale preauth keys. Pre-login this host to the expected login server or set tailscale.auth_key_file to a root-owned root-only key file created through the explicit Headscale onboarding handoff")
}

func removeStaleAppServiceUnit(ctx stdcontext.Context, executor host.Executor, names appsvc.Names) ([]string, error) {
	result, err := executor.Run(ctx, appsvc.RemoveManagedServiceUnitCommand(names))
	if err != nil {
		return nil, err
	}
	return outputLines(result.Stdout), nil
}

func removeStaleGoAccessRuntime(ctx stdcontext.Context, executor host.Executor, names appsvc.Names) ([]string, error) {
	result, err := executor.Run(ctx, appsvc.RemoveManagedGoAccessRuntimeCommand(names))
	if err != nil {
		return nil, err
	}
	return outputLines(result.Stdout), nil
}

func removeStaleGoAccessLogrotate(ctx stdcontext.Context, executor host.Executor, names appsvc.Names) ([]string, error) {
	result, err := executor.Run(ctx, appsvc.RemoveManagedGoAccessLogrotateCommand(names))
	if err != nil {
		return nil, err
	}
	return outputLines(result.Stdout), nil
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func activateAppNginx(ctx stdcontext.Context, executor host.Executor, names appsvc.Names) error {
	return activateAppNginxTracking(ctx, executor, names, nil)
}

func ActivateAppNginx(ctx stdcontext.Context, executor host.Executor, names appsvc.Names) error {
	return activateAppNginx(ctx, executor, names)
}

func activateAppNginxTracking(ctx stdcontext.Context, executor host.Executor, names appsvc.Names, effects *appDeployEffects) error {
	if err := prepareAppNginxActivation(ctx, executor, names, effects); err != nil {
		return err
	}
	return reloadAppNginxTracking(ctx, executor, effects)
}

func prepareAppNginxActivation(ctx stdcontext.Context, executor host.Executor, names appsvc.Names, effects *appDeployEffects) error {
	for _, command := range []host.Command{appsvc.GuardEnabledSiteCommand(names), appsvc.EnableSiteCommand(names), appsvc.TestNginxCommand()} {
		if _, err := executor.Run(ctx, command); err != nil {
			return err
		}
		if effects == nil {
			continue
		}
		switch command.Name {
		case "ln":
			effects.AddPaths(names.NginxEnabledPath)
			effects.AddActions("enabled app Nginx site")
		case appsvc.NginxBinaryPath:
			effects.AddActions("tested Nginx config")
		}
	}
	return nil
}

func reloadAppNginxTracking(ctx stdcontext.Context, executor host.Executor, effects *appDeployEffects) error {
	if _, err := executor.Run(ctx, appsvc.ReloadNginxCommand()); err != nil {
		return err
	}
	if effects != nil {
		effects.AddActions("reloaded Nginx")
	}
	return nil
}

func appDeployFailureWithEffects(summary string, err error, effects appDeployEffects) (Result, error) {
	return appDeployFailureWithFieldsAndPaths(summary, err, effects.Fields(), effects.ModifiedPaths())
}

func appDeployFailureWithFields(summary string, err error, fields []domain.ResultField) (Result, error) {
	return appDeployFailureWithFieldsAndPaths(summary, err, fields, nil)
}

func appDeployFailureWithFieldsAndPaths(summary string, err error, fields []domain.ResultField, modifiedPaths []string) (Result, error) {
	return appDeployFailureWithFieldsPathsPlan(summary, err, fields, modifiedPaths, nil, "")
}

func appDeployFailureWithFieldsPathsPlan(summary string, err error, fields []domain.ResultField, modifiedPaths []string, exposurePlan *domain.ExposurePlan, retryCommand string) (Result, error) {
	responseFields := []domain.ResultField{{Label: "details", Value: err.Error()}}
	responseFields = append(responseFields, fields...)
	result := operationResult("app deploy", "failed", workflow.OperationResult{
		Kind:          domain.JobKindAppDeploy,
		Status:        domain.JobStatusFailed,
		Summary:       summary,
		Fields:        responseFields,
		ExposurePlan:  exposurePlan,
		ModifiedPaths: append([]string(nil), modifiedPaths...),
		RetryCommand:  retryCommand,
		Progress:      operationProgressEvents(domain.JobKindAppDeploy, "app deploy host workflow started", domain.DiagnosticStatusFail, "app deploy host workflow failed"),
	}, []string{"Fix the error and retry the same operation from the Management UI."})
	return result, fmt.Errorf("app deploy: %s: %w", summary, err)
}

func outputLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func appHostMutationBlockedProgress(kind domain.JobKind) []workflow.ProgressEvent {
	switch kind {
	case domain.JobKindAppDeploy:
		return operationProgressEvents(domain.JobKindAppDeploy, "app deploy preflight evaluated", domain.DiagnosticStatusFail, "app deploy host workflow blocked")
	case domain.JobKindRealIPRefresh:
		return operationProgressEvents(domain.JobKindRealIPRefresh, "realip refresh exposure plan evaluated", domain.DiagnosticStatusFail, "realip refresh host workflow blocked")
	default:
		return nil
	}
}

func appFailureOperationResult(kind domain.JobKind, response commandResponse, retryCommand string, progress []workflow.ProgressEvent) Result {
	result := commandOperationResult(response.Command, response.Status, domain.JobStatusFailed, domain.DiagnosticStatusFail, response.Summary, response.Fields, retryCommand)
	if len(response.Diagnostics) > 0 {
		result.Diagnostics = append([]domain.DiagnosticItem(nil), response.Diagnostics...)
	}
	result.Kind = kind
	result.Progress = append([]workflow.ProgressEvent(nil), progress...)
	return operationResult(response.Command, response.Status, result, response.NextSteps)
}

func appFailureError(response commandResponse) error {
	if strings.TrimSpace(response.Summary) == "" {
		return fmt.Errorf("%s failed", response.Command)
	}
	return fmt.Errorf("%s: %s", response.Command, response.Summary)
}

func deployPrivilegeStrategy(state preflight.PermissionState) host.PrivilegeStrategy {
	return maindeploy.DeployPrivilegeStrategy(state)
}

func detectSSBindingList(protocol string, ports []int) ([]preflight.PortBinding, bool) {
	return maindeploy.DetectSSBindingList(protocol, ports)
}

func nonEmptyEnvironmentByKey() map[string]string {
	return maindeploy.NonEmptyEnvironmentByKey()
}

func route53RawSecretEnvironmentPresent(env map[string]string) bool {
	return maindeploy.Route53RawSecretEnvironmentPresent(env)
}

func fileOwnerUID(info os.FileInfo) (uint64, bool) {
	return maindeploy.FileOwnerUID(info)
}

func fileOwnerGID(info os.FileInfo) (uint64, bool) {
	return maindeploy.FileOwnerGID(info)
}

func uniqueStrings(values []string) []string {
	return maindeploy.UniqueStrings(values)
}

func newDeployHTTPClient(proxy config.ProxyConfig, timeout time.Duration) *http.Client {
	return maindeploy.NewDeployHTTPClient(proxy, timeout)
}

func httpClientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	return maindeploy.HTTPClientOrDefault(client, timeout)
}

func readDNSCredentialEnvFile(filePath string) ([]byte, string, error) {
	return maindeploy.ReadDNSCredentialEnvFileWithDependencies(filePath, maindeploy.Dependencies{
		DetectPermissionState:  detectPermissionStateFn,
		NewHostExecutor:        newHostExecutorFn,
		StatDNSCredentialsFile: statAppServiceBinaryFn,
		ReadDNSCredentialsFile: os.ReadFile,
	})
}

func parseDNSEnvFileContent(content []byte) (map[string]string, string) {
	return maindeploy.ParseDNSEnvFileContent(content)
}

func dnsCredentialEnvironmentValueIsFile(provider string, key string) bool {
	return maindeploy.DNSCredentialEnvironmentValueIsFile(provider, key)
}
