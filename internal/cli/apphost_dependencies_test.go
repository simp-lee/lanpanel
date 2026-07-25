package cli

import (
	"lanpanel/internal/apphost"
	"lanpanel/internal/host"
)

func init() {
	apphostDependenciesFn = testApphostDependencies
}

func testApphostDependencies() apphost.Dependencies {
	return apphost.Dependencies{
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
		AcquireRealIPProfileLock: func(profileName string) (apphost.RealIPProfileLock, error) {
			return acquireRealIPProfileLockFn(profileName)
		},
		RealIPCleanupRoot:     realIPCleanupRoot,
		CurrentExecutablePath: currentExecutablePathFn,
		NewHostExecutor:       newHostExecutorFn,
		NewHostSystemd:        newHostSystemdFn,
		NewAppFileInstaller: func(executor host.Executor, privilege host.PrivilegeStrategy) apphost.AppStagedFileInstaller {
			return newAppFileInstallerFn(executor, privilege)
		},
		NewAppHostFileSystem: newAppHostFileSystemFn,
	}
}
