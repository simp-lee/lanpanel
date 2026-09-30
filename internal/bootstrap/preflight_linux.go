//go:build linux

package bootstrap

import (
	"context"
	"lanpanel/internal/identity"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
)

func newInstallerPreflightEvaluator(installed release.InstallIdentity) PreflightEvaluator {
	return func(ctx context.Context, management identity.ManagementAuthority, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		request := installerPreflightRequest(installed, management, generation)
		observer, err := preflight.NewLinuxObserver(preflight.ObserveBootstrapReadiness)
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		observed, err := observer.ObserveExpansion(ctx, request)
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		result, err := preflight.EvaluateExpansion(request, observed)
		return request, result, err
	}
}

func installerPreflightRequest(installed release.InstallIdentity, management identity.ManagementAuthority, generation uint64) preflight.ExpansionRequest {
	profileAuthority := preflight.ProfileAuthority{Kind: preflight.PreviewProfile, Digest: "sha256:" + installed.ProfileDigest}
	confinement := installed.Profile.ManagedConfinement
	nginxPackage := installed.Profile.Nginx.Package
	if nginxPackage == "" {
		nginxPackage = "nginx"
	}
	nginxService := installed.Profile.Nginx.Service
	if nginxService == "" {
		nginxService = "nginx.service"
	}
	nginxMinimum := installed.Profile.Nginx.MinimumVersion
	if nginxMinimum == "" {
		nginxMinimum = installed.Profile.NginxVersionMinimum
	}
	if nginxMinimum == "" {
		nginxMinimum = "1.18.0"
	}
	paths := FixedPaths()
	return preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: generation, Profile: preflight.ExpectedProfile{ID: installed.Profile.ID, VersionID: installed.Profile.Release, Architecture: installed.Profile.Architecture, ServiceManager: installed.Profile.ServiceManager, PackageManager: installed.Profile.PackageManager, NginxPackage: nginxPackage, NginxService: nginxService, SystemdVersion: installed.Profile.SystemdVersion, NginxVersionMinimum: nginxMinimum, NginxVersionMaximum: installed.Profile.Nginx.MaximumVersion, PackageSnapshotDigest: "sha256:" + installed.Profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), PolicyDigest: "sha256:" + confinement.PolicyDigest}, Authority: profileAuthority}, BootstrapListeners: []preflight.ListenerRequirement{{Protocol: "tcp", Address: management.Address, Port: management.Port, Purpose: "management"}}, ManagedPaths: FixedManagedPathRequirements(paths), Disks: FixedDiskRequirements(paths), LastTrustedWall: installed.AuthorityCreatedAt}
}
