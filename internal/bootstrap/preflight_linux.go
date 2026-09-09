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
	profileAuthority := preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + installed.ProfileDigest, LiveQualified: true}
	if installed.Kind == release.InstallQualification {
		profileAuthority = preflight.ProfileAuthority{Kind: preflight.QualificationTarget, Digest: "sha256:" + installed.ProfileDigest, CandidateDigest: "sha256:" + installed.CandidateDigest, InstallManifestDigest: "sha256:" + installed.QualificationInstallManifestDigest, SideEffectPlanDigest: "sha256:" + installed.SideEffectPlanDigest, HostFingerprint: installed.HostFingerprint, RunID: installed.RunID}
	}
	confinement := installed.Profile.ManagedConfinement
	paths := FixedPaths()
	return preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: generation, Profile: preflight.ExpectedProfile{ID: installed.Profile.Family, VersionID: installed.Profile.Release, Architecture: "amd64", SystemdVersion: installed.Profile.SystemdVersion, NginxVersion: installed.Profile.NginxVersion, PackageSnapshotDigest: "sha256:" + installed.Profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: profileAuthority}, BootstrapListeners: []preflight.ListenerRequirement{{Protocol: "tcp", Address: management.Address, Port: management.Port, Purpose: "management"}}, ManagedPaths: FixedManagedPathRequirements(paths), Disks: FixedDiskRequirements(paths), LastTrustedWall: installed.AuthorityCreatedAt}
}
