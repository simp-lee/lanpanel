package cli

import (
	stdcontext "context"
	"io/fs"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apphost"
	"lanpanel/internal/apprender"
	"lanpanel/internal/components/appsvc"
	"lanpanel/internal/exposure"
	"lanpanel/internal/host"
	"lanpanel/internal/output"
	"lanpanel/internal/preflight"
	"lanpanel/internal/realip"
	"lanpanel/internal/realiprender"
	"net/http"
	"os"
	"strings"
)

var realIPLockDir = "/run/lanpanel"

type realIPProfileLock = apphost.RealIPProfileLock

type appDeployEffects struct {
	modifiedPaths []string
	actions       []string
}

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

func (effects appDeployEffects) Fields() []output.Field {
	fields := []output.Field{{Label: "modified paths", Value: summarizeAppModifiedPaths(effects.modifiedPaths)}}
	if len(effects.actions) > 0 {
		fields = append(fields, output.Field{Label: "host actions", Value: strings.Join(effects.actions, ", ")})
	}
	return fields
}

func (effects appDeployEffects) ModifiedPaths() []string {
	return append([]string(nil), effects.modifiedPaths...)
}

func (effects *appDeployEffects) toApphost() apphost.AppDeployEffects {
	converted := apphost.AppDeployEffects{}
	if effects == nil {
		return converted
	}
	converted.AddPaths(effects.modifiedPaths...)
	converted.AddActions(effects.actions...)
	return converted
}

func (effects *appDeployEffects) copyFrom(converted apphost.AppDeployEffects) {
	if effects == nil {
		return
	}
	effects.modifiedPaths = converted.ModifiedPaths()
	effects.actions = converted.Actions()
}

func withTestApphostDependencies(run func() error) error {
	return apphost.WithDependencies(testApphostDependencies(), run)
}

func appGoAccessFailureNextStep(cfg appconfig.Config) string {
	return apphost.AppGoAccessFailureNextStep(cfg)
}

func appGoAccessTroubleshootingCommands(cfg appconfig.Config, names appsvc.Names) string {
	return apphost.AppGoAccessTroubleshootingCommands(cfg, names)
}

func detectAppDNS(cfg appconfig.Config) map[string]preflight.DNSProbe {
	var probes map[string]preflight.DNSProbe
	if err := withTestApphostDependencies(func() error {
		probes = apphost.DetectAppDNS(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return probes
}

func detectAppExpectedPublicIPs(cfg appconfig.Config) (string, string, error) {
	var ipv4 string
	var ipv6 string
	err := withTestApphostDependencies(func() error {
		var err error
		ipv4, ipv6, err = apphost.DetectAppExpectedPublicIPs(cfg)
		return err
	})
	return ipv4, ipv6, err
}

func detectAppCurrentPublicIPs(client *http.Client) (string, string, error) {
	return apphost.DetectAppCurrentPublicIPs(client)
}

func detectAppPortBindings() []preflight.PortBinding {
	var bindings []preflight.PortBinding
	if err := withTestApphostDependencies(func() error {
		bindings = apphost.DetectAppPortBindings()
		return nil
	}); err != nil {
		panic(err)
	}
	return bindings
}

func detectAppListenPortState(cfg appconfig.Config) (bool, bool, string) {
	var checked bool
	var ready bool
	var detail string
	if err := withTestApphostDependencies(func() error {
		checked, ready, detail = apphost.DetectAppListenPortState(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return checked, ready, detail
}

func detectAppDNSCredentialState(cfg appconfig.Config) (bool, bool, string) {
	var checked bool
	var ready bool
	var detail string
	if err := withTestApphostDependencies(func() error {
		checked, ready, detail = apphost.DetectAppDNSCredentialState(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return checked, ready, detail
}

func detectAppServiceEnvFileState(cfg appconfig.Config) (bool, bool, string) {
	var checked bool
	var ready bool
	var detail string
	if err := withTestApphostDependencies(func() error {
		checked, ready, detail = apphost.DetectAppServiceEnvFileState(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return checked, ready, detail
}

func detectAppTailscaleAuthKeyFileState(cfg appconfig.Config) (bool, bool, string) {
	return apphost.DetectAppTailscaleAuthKeyFileState(cfg)
}

func detectAppGoAccessAuthFileState(cfg appconfig.Config) (bool, bool, string) {
	var checked bool
	var ready bool
	var detail string
	if err := withTestApphostDependencies(func() error {
		checked, ready, detail = apphost.DetectAppGoAccessAuthFileState(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return checked, ready, detail
}

func detectAppBrowserAuthFileState(cfg appconfig.Config) (bool, bool, string) {
	var checked bool
	var ready bool
	var detail string
	if err := withTestApphostDependencies(func() error {
		checked, ready, detail = apphost.DetectAppBrowserAuthFileState(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return checked, ready, detail
}

func detectAppGoAccessPortState(cfg appconfig.Config) (bool, bool, string) {
	var checked bool
	var ready bool
	var detail string
	if err := withTestApphostDependencies(func() error {
		checked, ready, detail = apphost.DetectAppGoAccessPortState(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return checked, ready, detail
}

func detectAppGoAccessAppListenBlockers(cfg appconfig.Config, names appsvc.Names) ([]preflight.PortBinding, bool) {
	var blockers []preflight.PortBinding
	var detected bool
	if err := withTestApphostDependencies(func() error {
		blockers, detected = apphost.DetectAppGoAccessAppListenBlockers(cfg, names)
		return nil
	}); err != nil {
		panic(err)
	}
	return blockers, detected
}

func detectAppGoAccessAppPortBlockers(cfg appconfig.Config, names appsvc.Names) ([]preflight.PortBinding, bool) {
	var blockers []preflight.PortBinding
	var detected bool
	if err := withTestApphostDependencies(func() error {
		blockers, detected = apphost.DetectAppGoAccessAppPortBlockers(cfg, names)
		return nil
	}); err != nil {
		panic(err)
	}
	return blockers, detected
}

func detectAppGoAccessLocaleState(cfg appconfig.Config) (bool, bool, string) {
	return apphost.DetectAppGoAccessLocaleState(cfg)
}

func detectAppGoAccessLogFileState(cfg appconfig.Config) (bool, bool, string) {
	var checked bool
	var ready bool
	var detail string
	if err := withTestApphostDependencies(func() error {
		checked, ready, detail = apphost.DetectAppGoAccessLogFileState(cfg)
		return nil
	}); err != nil {
		panic(err)
	}
	return checked, ready, detail
}

func isAppGoAccessManagedPortBinding(names appsvc.Names, binding preflight.PortBinding) (bool, bool) {
	var managed bool
	var confirmed bool
	if err := withTestApphostDependencies(func() error {
		managed, confirmed = apphost.IsAppGoAccessManagedPortBinding(names, binding)
		return nil
	}); err != nil {
		panic(err)
	}
	return managed, confirmed
}

func isAppManagedPortBinding(names appsvc.Names, binding preflight.PortBinding) (bool, bool) {
	var managed bool
	var confirmed bool
	if err := withTestApphostDependencies(func() error {
		managed, confirmed = apphost.IsAppManagedPortBinding(names, binding)
		return nil
	}); err != nil {
		panic(err)
	}
	return managed, confirmed
}

func guardAppOwnership(fileSystem host.FileSystem, cfg appconfig.Config, staged []apprender.StagedFile) error {
	return apphost.GuardAppOwnership(fileSystem, cfg, staged)
}

func ensureAppNginxRuntimeCompatibility(ctx stdcontext.Context, cfg appconfig.Config, executor host.Executor) error {
	return apphost.EnsureAppNginxRuntimeCompatibility(ctx, cfg, executor)
}

func ensureAppGoAccessDependency(ctx stdcontext.Context, executor host.Executor) error {
	return apphost.EnsureAppGoAccessDependency(ctx, executor)
}

func goAccessRequiredRuntimeOptions() []string {
	return apphost.GoAccessRequiredRuntimeOptions()
}

func appHostDependencyPackages(cfg appconfig.Config) []string {
	return apphost.AppHostDependencyPackages(cfg)
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type realIPFileSnapshot struct {
	hostPath string
	exists   bool
	content  []byte
	mode     fs.FileMode
}

type realIPDirectorySnapshot struct {
	path   string
	exists bool
}

func realIPProfileLockPath(profileName string) (string, error) {
	restore := apphost.SetRealIPLockDir(realIPLockDir)
	defer restore()
	return apphost.RealIPProfileLockPath(profileName)
}

func acquireRealIPProfileLock(profileName string) (realIPProfileLock, error) {
	restore := apphost.SetRealIPLockDir(realIPLockDir)
	defer restore()
	return apphost.AcquireRealIPProfileLock(profileName)
}

func validateRealIPLockFile(file *os.File, path string) error {
	return apphost.ValidateRealIPLockFile(file, path)
}

func validateDeployedRealIPReferencePath(path string, profileName string, appName string) error {
	return apphost.ValidateDeployedRealIPReferencePath(path, profileName, appName)
}

func realIPManagedMarker(profileName string, provider string) string {
	return apphost.RealIPManagedMarker(profileName, provider)
}

func guardRealIPOwnership(fileSystem host.FileSystem, profileName string, provider string, staged []realiprender.StagedFile) error {
	return apphost.GuardRealIPOwnership(fileSystem, profileName, provider, staged)
}

func validateExistingRealIPArtifactInfo(path string, info fs.FileInfo) error {
	return apphost.ValidateExistingRealIPArtifactInfo(path, info)
}

func guardRealIPProfileDirectories(fileSystem host.FileSystem, names appsvc.RealIPProfileNames) error {
	return apphost.GuardRealIPProfileDirectories(fileSystem, names)
}

func readRealIPProfileFromFS(fileSystem host.FileSystem, path string) (realip.ProfileConfig, bool, error) {
	return apphost.ReadRealIPProfileFromFS(fileSystem, path)
}

func ensureRealIPProfileCompatible(existing realip.ProfileConfig, desired realip.ProfileConfig) error {
	return apphost.EnsureRealIPProfileCompatible(existing, desired)
}

func staleAppRealIPReferenceProfiles(appName string, currentProfile string) ([]string, error) {
	var profiles []string
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		var err error
		profiles, err = apphost.StaleAppRealIPReferenceProfiles(appName, currentProfile)
		return err
	})
	return profiles, err
}

func cleanupStaleAppRealIPReferenceForProfile(ctx stdcontext.Context, executor host.Executor, appName string, profile string, validatorPath string) (bool, error) {
	var cleaned bool
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		var err error
		cleaned, err = apphost.CleanupStaleAppRealIPReferenceForProfile(ctx, executor, appName, profile, validatorPath)
		return err
	})
	return cleaned, err
}

func readDeployedRealIPProfile(path string) (realip.ProfileConfig, error) {
	return apphost.ReadDeployedRealIPProfile(path)
}

func readDeployedRealIPState(path string, profileName string) (realip.State, error) {
	return apphost.ReadDeployedRealIPState(path, profileName)
}

func validateDeployedRealIPStateInfo(path string, info fs.FileInfo) error {
	return apphost.ValidateDeployedRealIPStateInfo(path, info)
}

func parseDeployedRealIPState(data []byte, path string, profileName string) (realip.State, error) {
	return apphost.ParseDeployedRealIPState(data, path, profileName)
}

func readDeployedRealIPReferences(dir string) ([]realip.Reference, error) {
	var references []realip.Reference
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		var err error
		references, err = apphost.ReadDeployedRealIPReferences(dir)
		return err
	})
	return references, err
}

func validateDeployedRealIPReferenceInfo(path string, info fs.FileInfo) error {
	return apphost.ValidateDeployedRealIPReferenceInfo(path, info)
}

func parseDeployedRealIPReference(data []byte, path string, profileName string, appName string) (realip.Reference, error) {
	return apphost.ParseDeployedRealIPReference(data, path, profileName, appName)
}

func domainsFromRealIPReferences(references []realip.Reference) []string {
	return apphost.DomainsFromRealIPReferences(references)
}

func appRealIPDeployFields(cfg appconfig.Config, names appsvc.RealIPProfileNames, state realip.State, prepared bool) []output.Field {
	return apphost.AppRealIPDeployFields(cfg, names, state, prepared)
}

func deployedRealIPRegularFileStatus(path string) (string, error) {
	var status string
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		var err error
		status, err = apphost.DeployedRealIPRegularFileStatus(path)
		return err
	})
	return status, err
}

func validateDeployedRealIPRefreshService(path string, marker string, profileName string, configPath string) error {
	return apphost.WithDependencies(testApphostDependencies(), func() error {
		return apphost.ValidateDeployedRealIPRefreshService(path, marker, profileName, configPath)
	})
}

func validateDeployedRealIPRefreshTimer(path string, marker string, profile realip.ProfileConfig) error {
	return apphost.WithDependencies(testApphostDependencies(), func() error {
		return apphost.ValidateDeployedRealIPRefreshTimer(path, marker, profile)
	})
}

func appRuntimeHostChecksStep(cfg appconfig.Config) string {
	return apphost.AppRuntimeHostChecksStep(cfg)
}

func appDeployRuntimeVerifyStep(configPath string, cfg appconfig.Config) string {
	return apphost.AppDeployRuntimeVerifyStep(configPath, cfg)
}

func prepareAppRealIPProfile(ctx stdcontext.Context, cfg appconfig.Config, fileSystem host.FileSystem, appConfigPath string) (appsvc.RealIPProfileNames, realip.State, []realiprender.StagedFile, error) {
	var names appsvc.RealIPProfileNames
	var state realip.State
	var staged []realiprender.StagedFile
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		var err error
		names, state, staged, err = apphost.PrepareAppRealIPProfile(ctx, cfg, fileSystem, appConfigPath)
		return err
	})
	return names, state, staged, err
}

func cleanupStaleAppRealIPReferences(ctx stdcontext.Context, executor host.Executor, appName string, currentProfile string, effects *appDeployEffects) error {
	converted := effects.toApphost()
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		return apphost.CleanupStaleAppRealIPReferences(ctx, executor, appName, currentProfile, &converted)
	})
	effects.copyFrom(converted)
	return err
}

func refreshDeployedRealIPProfile(ctx stdcontext.Context, profileName string, appConfigPath string, effects *appDeployEffects) (realip.State, realip.ProfileConfig, appsvc.RealIPProfileNames, error) {
	var state realip.State
	var profile realip.ProfileConfig
	var names appsvc.RealIPProfileNames
	converted := effects.toApphost()
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		var err error
		state, profile, names, err = apphost.RefreshDeployedRealIPProfile(ctx, profileName, appConfigPath, &converted)
		return err
	})
	effects.copyFrom(converted)
	return state, profile, names, err
}

func installAndActivateRealIPRefresh(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, installer appStagedFileInstaller, staged []realiprender.StagedFile, effects *appDeployEffects) error {
	converted := effects.toApphost()
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		return apphost.InstallAndActivateRealIPRefresh(ctx, executor, fileSystem, installer, staged, &converted)
	})
	effects.copyFrom(converted)
	return err
}

func snapshotRealIPFiles(fileSystem host.FileSystem, staged []realiprender.StagedFile, requireExisting bool) ([]realIPFileSnapshot, error) {
	snapshots, err := apphost.SnapshotRealIPFiles(fileSystem, staged, requireExisting)
	if err != nil {
		return nil, err
	}
	return fromApphostRealIPFileSnapshots(snapshots), nil
}

func snapshotRealIPDirectories(fileSystem host.FileSystem, names appsvc.RealIPProfileNames) ([]realIPDirectorySnapshot, error) {
	snapshots, err := apphost.SnapshotRealIPDirectories(fileSystem, names)
	if err != nil {
		return nil, err
	}
	return fromApphostRealIPDirectorySnapshots(snapshots), nil
}

func restoreRealIPDeploySnapshots(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []realIPFileSnapshot, directories []realIPDirectorySnapshot) error {
	return apphost.RestoreRealIPDeploySnapshots(ctx, executor, fileSystem, toApphostRealIPFileSnapshots(snapshots), toApphostRealIPDirectorySnapshots(directories))
}

func rollbackRealIPDeploy(ctx stdcontext.Context, executor host.Executor, fileSystem host.FileSystem, snapshots []realIPFileSnapshot, directories []realIPDirectorySnapshot, cause error, reloadRestoredNginx bool) error {
	return apphost.RollbackRealIPDeploy(ctx, executor, fileSystem, toApphostRealIPFileSnapshots(snapshots), toApphostRealIPDirectorySnapshots(directories), cause, reloadRestoredNginx)
}

func ensureAppHostDependencies(ctx stdcontext.Context, cfg appconfig.Config, executor host.Executor) error {
	return apphost.EnsureAppHostDependencies(ctx, cfg, executor)
}

func ensureBrowserAuthDependencies(ctx stdcontext.Context, executor host.Executor) error {
	return apphost.EnsureBrowserAuthDependencies(ctx, apphost.Dependencies{
		DetectPermissionState: func() preflight.PermissionState {
			return preflight.PermissionState{IsRoot: true}
		},
		NewHostExecutor: func(map[string]string) host.Executor {
			return executor
		},
	})
}

func activateAppNginx(ctx stdcontext.Context, executor host.Executor, names appsvc.Names) error {
	return apphost.ActivateAppNginx(ctx, executor, names)
}

func cliObservedBrowserAuthObservations(cfg appconfig.Config) exposure.AppObservations {
	var observations exposure.AppObservations
	err := apphost.WithDependencies(testApphostDependencies(), func() error {
		observations = apphost.ObservedBrowserAuthObservations(cfg)
		return nil
	})
	if err != nil {
		panic(err)
	}
	return observations
}

func fromApphostRealIPFileSnapshots(snapshots []apphost.RealIPFileSnapshot) []realIPFileSnapshot {
	converted := make([]realIPFileSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, realIPFileSnapshot{
			hostPath: snapshot.HostPath,
			exists:   snapshot.Exists,
			content:  append([]byte(nil), snapshot.Content...),
			mode:     snapshot.Mode,
		})
	}
	return converted
}

func toApphostRealIPFileSnapshots(snapshots []realIPFileSnapshot) []apphost.RealIPFileSnapshot {
	converted := make([]apphost.RealIPFileSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, apphost.RealIPFileSnapshot{
			HostPath: snapshot.hostPath,
			Exists:   snapshot.exists,
			Content:  append([]byte(nil), snapshot.content...),
			Mode:     snapshot.mode,
		})
	}
	return converted
}

func fromApphostRealIPDirectorySnapshots(snapshots []apphost.RealIPDirectorySnapshot) []realIPDirectorySnapshot {
	converted := make([]realIPDirectorySnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, realIPDirectorySnapshot{
			path:   snapshot.Path,
			exists: snapshot.Exists,
		})
	}
	return converted
}

func toApphostRealIPDirectorySnapshots(snapshots []realIPDirectorySnapshot) []apphost.RealIPDirectorySnapshot {
	converted := make([]apphost.RealIPDirectorySnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		converted = append(converted, apphost.RealIPDirectorySnapshot{
			Path:   snapshot.path,
			Exists: snapshot.exists,
		})
	}
	return converted
}
