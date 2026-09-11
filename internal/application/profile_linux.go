//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/preflight"
	managedprocess "lanpanel/internal/process"
	"lanpanel/internal/release"
	"reflect"
)

func expectedInstalledProfile(profile release.OSProfile) preflight.ExpectedProfile {
	confinement := profile.ManagedConfinement
	return preflight.ExpectedProfile{
		ID:                    profile.Family,
		VersionID:             profile.Release,
		Architecture:          profile.Architecture,
		SystemdVersion:        profile.SystemdVersion,
		NginxVersion:          profile.NginxVersion,
		PackageSnapshotDigest: "sha256:" + profile.PackageSnapshotDigest,
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

func verifyInstalledPackageProfile(ctx context.Context, profile release.OSProfile) error {
	expected := expectedInstalledProfile(profile)
	observed, err := preflight.ObserveInstalledProfile(ctx)
	if err != nil {
		return fmt.Errorf("observe current package/profile identity: %w", err)
	}
	if err := preflight.VerifyInstalledProfile(expected, observed); err != nil {
		return err
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
