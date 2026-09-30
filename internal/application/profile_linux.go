//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/debianversion"
	"lanpanel/internal/preflight"
	managedprocess "lanpanel/internal/process"
	"lanpanel/internal/release"
	"reflect"
)

func expectedInstalledProfile(profile release.OSProfile) preflight.ExpectedProfile {
	confinement := profile.ManagedConfinement
	nginxPackage, nginxService, nginxMinimum := profile.Nginx.Package, profile.Nginx.Service, profile.Nginx.MinimumVersion
	if nginxPackage == "" {
		nginxPackage = "nginx"
	}
	if nginxService == "" {
		nginxService = "nginx.service"
	}
	if nginxMinimum == "" {
		nginxMinimum = profile.NginxVersionMinimum
	}
	if nginxMinimum == "" {
		nginxMinimum = "1.18.0"
	}
	return preflight.ExpectedProfile{
		ID:                    profile.ID,
		VersionID:             profile.Release,
		Architecture:          profile.Architecture,
		ServiceManager:        profile.ServiceManager,
		PackageManager:        profile.PackageManager,
		NginxPackage:          nginxPackage,
		NginxService:          nginxService,
		SystemdVersion:        profile.SystemdVersion,
		SystemdVersionMinimum: profile.SystemdVersionMinimum,
		SystemdVersionMaximum: profile.SystemdVersionMaximum,
		NginxVersion:          profile.NginxVersion,
		NginxVersionMinimum:   nginxMinimum,
		NginxVersionMaximum:   profile.Nginx.MaximumVersion,
		PackageSnapshotDigest: prefixedProfileDigest(profile.PackageSnapshotDigest),
		ManagedConfinement: preflight.ManagedConfinementProfile{
			SchemaVersion:         confinement.SchemaVersion,
			KernelRelease:         confinement.KernelRelease,
			CgroupMode:            confinement.CgroupMode,
			BindListenPolicy:      confinement.BindListenPolicy,
			ConnectPolicy:         confinement.ConnectPolicy,
			FilesystemPolicy:      confinement.FilesystemPolicy,
			ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...),
			PolicyDigest:          "sha256:" + confinement.PolicyDigest,
		},
	}
}

func prefixedProfileDigest(value string) string {
	if value == "" {
		return ""
	}
	return "sha256:" + value
}

func verifyInstalledPackageProfile(ctx context.Context, profile release.OSProfile) error {
	expected := expectedInstalledProfile(profile)
	observed, err := preflight.ObserveInstalledProfile(ctx)
	if err != nil {
		return fmt.Errorf("observe current package/profile identity: %w", err)
	}
	if err := preflight.VerifyInstalledProfile(expected, observed); err != nil {
		return err
	}
	packageNames := make([]string, 0, len(profile.Packages))
	for _, packageProfile := range profile.Packages {
		packageNames = append(packageNames, packageProfile.Name)
	}
	installedPackages, err := preflight.ObserveInstalledPackageTuples(ctx, packageNames)
	if err != nil {
		return fmt.Errorf("observe installed package versions: %w", err)
	}
	for index, installedPackage := range installedPackages {
		packageProfile := profile.Packages[index]
		inRange := debianversion.Satisfies(installedPackage.Version, packageProfile.VersionMinimum, packageProfile.VersionMaximum)
		if packageProfile.VersionMinimum == "" && packageProfile.VersionMaximum == "" {
			inRange = installedPackage.Version == packageProfile.Version
		}
		if installedPackage.Name != packageProfile.Name || installedPackage.Architecture != packageProfile.Architecture || !inRange {
			return &preflight.ProfileDriftError{Component: "package/" + packageProfile.Name, Expected: packageProfile.Version, Observed: installedPackage.Version}
		}
	}
	confinement, err := managedprocess.LoadConfinementProfile()
	if err != nil {
		return fmt.Errorf("observe current managed confinement profile: %w", err)
	}
	observedConfinement := preflight.ManagedConfinementProfile{
		SchemaVersion:         confinement.SchemaVersion,
		KernelRelease:         confinement.KernelRelease,
		CgroupMode:            confinement.CgroupMode,
		BindListenPolicy:      confinement.BindListenPolicy,
		ConnectPolicy:         confinement.ConnectPolicy,
		FilesystemPolicy:      confinement.FilesystemPolicy,
		ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...),
		PolicyDigest:          confinement.PolicyDigest,
	}
	if !reflect.DeepEqual(expected.ManagedConfinement, observedConfinement) {
		return &preflight.ProfileDriftError{Component: "managed_confinement", Expected: expected.ManagedConfinement.PolicyDigest, Observed: observedConfinement.PolicyDigest}
	}
	return nil
}

// VerifyInstalledPackageProfile checks the committed release authority against
// the current read-only OS, kernel, cgroup, and package identity. It is shared
// by all Nginx start/reload boundaries; callers must fail closed on any error.
func VerifyInstalledPackageProfile(ctx context.Context) error {
	installed, err := loadInstalledReleaseIdentity()
	if err != nil {
		return fmt.Errorf("read committed release profile: %w", err)
	}
	return verifyInstalledPackageProfile(ctx, installed.Profile)
}
