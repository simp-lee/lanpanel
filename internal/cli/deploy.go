package cli

import (
	"fmt"
	"io"
	"lanpanel/internal/components/headscale"
	legocomponent "lanpanel/internal/components/lego"
	"lanpanel/internal/components/nginx"
	"lanpanel/internal/config"
	"lanpanel/internal/host"
	"lanpanel/internal/maindeploy"
	"lanpanel/internal/output"
	"lanpanel/internal/preflight"
	"lanpanel/internal/render"
	"lanpanel/internal/state"
	"lanpanel/internal/workflow"
	"net/http"
	"net/url"
	"os"
	"time"
)

type stagedFileInstaller = maindeploy.StagedFileInstaller
type headscalePackageInstaller = maindeploy.HeadscalePackageInstaller
type legoInstaller = maindeploy.LegoInstaller
type nginxSiteActivator = maindeploy.NginxSiteActivator
type headscaleOnboarder = maindeploy.HeadscaleOnboarder

const (
	deployCheckpointPackageManagerReady          = maindeploy.CheckpointPackageManagerReady
	deployCheckpointHostDependenciesInstalled    = maindeploy.CheckpointHostDependenciesInstalled
	deployCheckpointPackageArchitectureConfirmed = maindeploy.CheckpointPackageArchitectureConfirmed
	deployCheckpointLegoInstalled                = maindeploy.CheckpointLegoInstalled
	deployCheckpointHeadscalePackageInstalled    = maindeploy.CheckpointHeadscalePackageInstalled
	deployCheckpointRuntimeAssetsInstalled       = maindeploy.CheckpointRuntimeAssetsInstalled
	deployCheckpointTLSBootstrapReady            = maindeploy.CheckpointTLSBootstrapReady
	deployCheckpointLegoCommandReady             = maindeploy.CheckpointLegoCommandReady
	deployCheckpointLegoCommandDeferred          = maindeploy.CheckpointLegoCommandDeferred
	deployCheckpointCertificateIssued            = maindeploy.CheckpointCertificateIssued
	deployCheckpointNginxActivated               = maindeploy.CheckpointNginxActivated
	deployCheckpointSystemdDaemonReloaded        = maindeploy.CheckpointSystemdDaemonReloaded
	deployCheckpointSystemdDaemonReloadDeferred  = maindeploy.CheckpointSystemdDaemonReloadDeferred
	deployCheckpointServicesEnabled              = maindeploy.CheckpointServicesEnabled
	deployCheckpointOnboardingReady              = maindeploy.CheckpointOnboardingReady
	deployCheckpointStaticVerifyPassed           = maindeploy.CheckpointStaticVerifyPassed
)

var (
	collectDeployPreflightInputs  = defaultDeployPreflightInputs
	detectPermissionStateFn       = maindeploy.DetectPermissionState
	detectPlatformInfoFn          = maindeploy.DetectPlatformInfo
	detectHostCapabilityStateFn   = maindeploy.DetectHostCapabilityState
	detectDNSProbeFn              = maindeploy.DetectDNSProbe
	detectPortBindingsFn          = maindeploy.DetectPortBindings
	detectFirewallStateFn         = maindeploy.DetectFirewallState
	detectServiceStatesFn         = maindeploy.DetectServiceStates
	detectPackageSourceStateFn    = maindeploy.DetectPackageSourceState
	detectACMEStateFn             = maindeploy.DetectACMEState
	probePackageURLFn             = maindeploy.ProbePackageURL
	hashRemoteArtifactFn          = maindeploy.HashRemoteArtifact
	lookupOfficialPackageDigestFn = maindeploy.LookupOfficialPackageDigest
	stageRuntimeFilesFn           = render.StageRuntime
	statDNSCredentialsFileFn      = os.Stat
	readDNSCredentialsFileFn      = os.ReadFile
	readDeployManagedHostFileFn   = os.ReadFile
	newDeployFileInstallerFn      = func(executor host.Executor, privilege host.PrivilegeStrategy) stagedFileInstaller {
		if privilege.RequiresSudo() {
			return host.NewFileInstaller(host.NewCommandFileSystem(executor), "")
		}
		return host.NewFileInstaller(nil, "")
	}
	newDeployHostFileSystemFn = func(executor host.Executor, privilege host.PrivilegeStrategy) host.FileSystem {
		if privilege.RequiresSudo() {
			return host.NewCommandFileSystem(executor)
		}
		return host.OSFileSystem{}
	}
	checkpointPathForConfigFn  = state.DefaultCheckpointPath
	checkpointStoreForConfigFn = func(configPath string) state.Store { return state.NewStore(checkpointPathForConfigFn(configPath)) }
	newHostExecutorFn          = func(env map[string]string) host.Executor { return host.NewExecutor(nil, env) }
	newHostSystemdFn           = func(executor host.Executor) host.Systemd { return host.NewSystemd(executor) }
	newHeadscaleInstallerFn    = func(executor host.Executor) headscalePackageInstaller { return headscale.NewInstaller(executor) }
	newLegoInstallerFn         = func(executor host.Executor) legoInstaller { return legocomponent.NewInstaller(executor) }
	newNginxActivatorFn        = func(executor host.Executor) nginxSiteActivator { return nginx.NewActivator(executor) }
	newHeadscaleOnboarderFn    = func(executor host.Executor) headscaleOnboarder { return headscale.NewOnboarding(executor) }
)

func newDeployCommand() command {
	return command{
		summary: "Run preflight checks and apply the Headscale, Nginx, TLS, service, and onboarding workflow.",
		usage:   writeDeployHelp,
		run:     runDeploy,
	}
}

func runDeploy(ctx context, args []string) error {
	flagSet := newFlagSet("deploy")
	options := sharedOptions{configPath: DefaultConfigPath, formatValue: string(output.FormatHuman)}
	options.bind(flagSet, "Path to the lanpanel config file.")

	shown, err := parseFlags(flagSet, args, writeDeployHelp, ctx.stdout)
	if err != nil {
		return fmt.Errorf("parse deploy flags: %w", err)
	}
	if shown {
		return nil
	}
	if err := rejectPositionalArgs("deploy", flagSet); err != nil {
		return err
	}

	format, err := output.ParseFormat(options.formatValue)
	if err != nil {
		return err
	}
	return runDeployWithFormatter(ctx, options.configPath, format, ctx.formatter(format))
}

func runDeployWithFormatter(ctx context, configPath string, format output.Format, formatter responseWriter) error {
	_ = format
	result, err := workflow.RunMainDeploy(workflow.Context{
		Version:      ctx.version,
		Actor:        cliActor(),
		HostWorkflow: newCLIHostWorkflow(ctx),
	}, configPath)
	if result.Kind != "" {
		if writeErr := writeOperationResult(formatter, "deploy", workflowOutputStatus("deploy", result), result, nil); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func mainDeployDependencies() maindeploy.Dependencies {
	return maindeploy.Dependencies{
		CollectDeployPreflightInputs: collectDeployPreflightInputs,
		DetectPermissionState:        detectPermissionStateFn,
		DetectPlatformInfo:           detectPlatformInfoFn,
		DetectHostCapabilityState:    detectHostCapabilityStateFn,
		DetectDNSProbe:               detectDNSProbeFn,
		DetectPortBindings:           detectPortBindingsFn,
		DetectFirewallState:          detectFirewallStateFn,
		DetectServiceStates:          detectServiceStatesFn,
		DetectPackageSourceState:     detectPackageSourceStateFn,
		DetectACMEState:              detectACMEStateFn,
		ProbePackageURL:              probePackageURLFn,
		HashRemoteArtifact:           hashRemoteArtifactFn,
		LookupOfficialPackageDigest:  lookupOfficialPackageDigestFn,
		StageRuntimeFiles:            stageRuntimeFilesFn,
		StatDNSCredentialsFile:       statDNSCredentialsFileFn,
		ReadDNSCredentialsFile:       readDNSCredentialsFileFn,
		ReadDeployManagedHostFile:    readDeployManagedHostFileFn,
		NewDeployFileInstaller:       newDeployFileInstallerFn,
		NewDeployHostFileSystem:      newDeployHostFileSystemFn,
		CheckpointPathForConfig:      checkpointPathForConfigFn,
		CheckpointStoreForConfig:     checkpointStoreForConfigFn,
		NewHostExecutor:              newHostExecutorFn,
		NewHostSystemd:               newHostSystemdFn,
		NewHeadscaleInstaller:        newHeadscaleInstallerFn,
		NewLegoInstaller:             newLegoInstallerFn,
		NewNginxActivator:            newNginxActivatorFn,
		NewHeadscaleOnboarder:        newHeadscaleOnboarderFn,
	}
}

func writeDeployHelp(stdout io.Writer) error {
	return writeHelpLines(stdout,
		"Run preflight checks and apply the Headscale, Nginx, TLS, service, and onboarding workflow.",
		"",
		"Usage:",
		"  lanpanel deploy [--config path] [--format human|json]",
		"",
		"Flags:",
		"  --config string   Path to the lanpanel config file.",
		"  --format string   Output format: human | json",
	)
}

func defaultDeployPreflightInputs(cfg config.Config) preflight.Inputs {
	return preflight.Inputs{
		Permissions:   detectPermissionStateFn(),
		Platform:      detectPlatformInfoFn(),
		Capabilities:  detectHostCapabilityStateFn(),
		DNS:           detectDNSProbeFn(cfg.Default.ServerURL),
		Ports:         detectPortBindingsFn(cfg),
		Firewall:      detectFirewallStateFn(),
		Services:      detectServiceStatesFn(),
		PackageSource: detectPackageSourceStateFn(cfg),
		ACME:          detectACMEStateFn(cfg),
	}
}

func deployPrivilegeStrategy(state preflight.PermissionState) host.PrivilegeStrategy {
	return maindeploy.DeployPrivilegeStrategy(state)
}

func parsePlatformInfoFromOSRelease(readFile func(string) ([]byte, error), paths ...string) preflight.PlatformInfo {
	return maindeploy.ParsePlatformInfoFromOSRelease(readFile, paths...)
}

func detectPortBindings(cfg config.Config) []preflight.PortBinding {
	return maindeploy.DetectPortBindings(cfg)
}

func detectPackageSourceState(cfg config.Config) preflight.PackageSourceState {
	return maindeploy.DetectPackageSourceStateWithDependencies(cfg, mainDeployDependencies())
}

func detectACMEState(cfg config.Config) preflight.ACMEState {
	return maindeploy.DetectACMEStateWithDependencies(cfg, mainDeployDependencies())
}

func probePackageURL(client *http.Client, rawURL string) (bool, bool, string) {
	return maindeploy.ProbePackageURL(client, rawURL)
}

func hashRemoteArtifact(client *http.Client, rawURL string) (string, error) {
	return maindeploy.HashRemoteArtifact(client, rawURL)
}

func lookupOfficialPackageDigest(client *http.Client, version string, arch string) (string, error) {
	return maindeploy.LookupOfficialPackageDigest(client, version, arch)
}

func stageDeployFiles(cfg config.Config) ([]render.StagedFile, error) {
	return stageRuntimeFilesFn(cfg)
}

func deployDesiredStateDigest(cfg config.Config) (string, error) {
	staged, err := stageRuntimeFilesFn(cfg)
	if err != nil {
		return "", err
	}
	return maindeploy.DeployDesiredStateDigestForStaged(cfg, staged)
}

func deployDesiredStateDigestForStaged(cfg config.Config, stagedFiles []render.StagedFile) (string, error) {
	return maindeploy.DeployDesiredStateDigestForStaged(cfg, stagedFiles)
}

func deployManagedServiceState(checkpoint state.Checkpoint, desiredStateDigest string) preflight.ManagedServiceState {
	return maindeploy.DeployManagedServiceState(checkpoint, desiredStateDigest)
}

func detectDeployManagedServiceStateFromHost() preflight.ManagedServiceState {
	return maindeploy.DetectDeployManagedServiceStateFromHostWithDependencies(mainDeployDependencies())
}

func http01ChallengeRouteCommand(serverName string, webroot string) host.Command {
	return maindeploy.HTTP01ChallengeRouteCommand(serverName, webroot)
}

func certificateIssueRemediations(acmeChallenge string, serverName string) []string {
	return maindeploy.CertificateIssueRemediations(acmeChallenge, serverName)
}

func detectDNSCredentialState(dns01 config.DNS01Config) (bool, bool, string) {
	return maindeploy.DetectDNSCredentialStateWithDependencies(dns01, mainDeployDependencies())
}

func inspectDNSCredentialsFile(filePath string) (bool, string) {
	return maindeploy.InspectDNSCredentialsFileWithDependencies(filePath, mainDeployDependencies())
}

func deployRetryCommand(configPath string) string {
	return workflow.ShellCommand("lanpanel", "deploy", "--config", configPath)
}

func deployProxyConfigured(proxy config.ProxyConfig) bool {
	return maindeploy.DeployProxyConfigured(proxy)
}

func deployProxyFunc(proxy config.ProxyConfig) func(*http.Request) (*url.URL, error) {
	return maindeploy.DeployProxyFunc(proxy)
}

func newDeployHTTPClient(proxy config.ProxyConfig, timeout time.Duration) *http.Client {
	return maindeploy.NewDeployHTTPClient(proxy, timeout)
}

func httpClientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	return maindeploy.HTTPClientOrDefault(client, timeout)
}

func readDNSCredentialEnvFile(filePath string) ([]byte, string, error) {
	return maindeploy.ReadDNSCredentialEnvFileWithDependencies(filePath, mainDeployDependencies())
}

func parseDNSEnvFileContent(content []byte) (map[string]string, string) {
	return maindeploy.ParseDNSEnvFileContent(content)
}

func dnsCredentialEnvironmentValueIsFile(provider string, key string) bool {
	return maindeploy.DNSCredentialEnvironmentValueIsFile(provider, key)
}

func parseSSBindings(raw string, protocol string, ports []int) (map[int]preflight.PortBinding, bool) {
	return maindeploy.ParseSSBindings(raw, protocol, ports)
}

func parseSSBindingList(raw string, protocol string, ports []int) ([]preflight.PortBinding, bool) {
	return maindeploy.ParseSSBindingList(raw, protocol, ports)
}

func detectSSBindingList(protocol string, ports []int) ([]preflight.PortBinding, bool) {
	return maindeploy.DetectSSBindingList(protocol, ports)
}

func parseUFWAllowedPorts(raw string) []string {
	return maindeploy.ParseUFWAllowedPorts(raw)
}

func nftRulesetAllowsPort(ruleset string, protocol string, port int) bool {
	return maindeploy.NFTRulesetAllowsPort(ruleset, protocol, port)
}

func systemdCommandDeferred(result host.Result, err error) bool {
	return maindeploy.SystemdCommandDeferred(result, err)
}

func route53RawSecretEnvironmentPresent(env map[string]string) bool {
	return maindeploy.Route53RawSecretEnvironmentPresent(env)
}

func nonEmptyEnvironmentByKey() map[string]string {
	return maindeploy.NonEmptyEnvironmentByKey()
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
