//go:build linux

package application

import (
	"cmp"
	"context"
	"fmt"
	"lanpanel/internal/activation"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"slices"
)

func installedProfileAuthority(installed release.InstallIdentity) preflight.ProfileAuthority {
	return preflight.ProfileAuthority{Kind: preflight.PreviewProfile, Digest: "sha256:" + installed.ProfileDigest}
}

func evaluateHeadscalePreflight(ctx context.Context, installed release.InstallIdentity, controlDomain string, generation uint64, additionalPaths ...preflight.ManagedPathRequirement) (preflight.ExpansionRequest, preflight.Result, error) {
	profile := installed.Profile
	authority := installedProfileAuthority(installed)
	confinement := profile.ManagedConfinement
	host, err := activation.NewFixedHost()
	if err != nil {
		return preflight.ExpansionRequest{}, preflight.Result{}, err
	}
	runtime, err := host.ObserveCurrent(ctx)
	if err != nil {
		return preflight.ExpansionRequest{}, preflight.Result{}, fmt.Errorf("shared Nginx listener ownership invalid: %w", err)
	}
	owned := []preflight.OwnedListenerAuthority{}
	for _, listener := range runtime.Listeners {
		if listener.Protocol == "tcp" && (listener.Port == 80 || listener.Port == 443) {
			owned = append(owned, preflight.OwnedListenerAuthority{Protocol: listener.Protocol, Address: listener.Address, Port: listener.Port, SocketInode: listener.Inode, IdentityDigest: preflight.OwnedListenerDigest(listener.Protocol, listener.Address, listener.Port, listener.Inode)})
		}
	}
	slices.SortFunc(owned, func(left, right preflight.OwnedListenerAuthority) int {
		if order := cmp.Compare(left.Protocol, right.Protocol); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Address, right.Address); order != 0 {
			return order
		}
		return cmp.Compare(left.Port, right.Port)
	})
	maximum := installed.Headscale.Archive.Bytes + installed.Headscale.MaximumExtractedBytes + 1<<20
	request := preflight.ExpansionRequest{
		Scope: preflight.ExpansionHeadscale, Target: "headscale", Generation: generation,
		Profile: preflight.ExpectedProfile{ID: profile.Family, VersionID: profile.Release, Architecture: profile.Architecture, SystemdVersion: profile.SystemdVersion, NginxVersion: profile.NginxVersion, PackageSnapshotDigest: "sha256:" + profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), PolicyDigest: "sha256:" + confinement.PolicyDigest}, Authority: authority},
		Domains: []string{controlDomain}, OwnedListeners: owned,
		ManagedPaths: []preflight.ManagedPathRequirement{{Path: "/etc/sysusers.d/lanpanel-headscale.conf", Kind: preflight.ManagedPathRegular, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o600, MaximumMode: 0o600, AllowAbsent: true}, {Path: "/usr/lib/lanpanel/dependencies/headscale", Kind: preflight.ManagedPathRegular, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o755, MaximumMode: 0o755, AllowAbsent: true}, {Path: "/var/lib/lanpanel/headscale", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700, AllowAbsent: true}},
		Disks:        []preflight.DiskRequirement{{Path: "/usr/lib/lanpanel/dependencies", MinimumAvailableBytes: maximum}, {Path: "/var/lib/lanpanel", MinimumAvailableBytes: maximum}}, LastTrustedWall: installed.AuthorityCreatedAt,
	}
	request.ManagedPaths = append(request.ManagedPaths, additionalPaths...)
	slices.SortFunc(request.ManagedPaths, func(left, right preflight.ManagedPathRequirement) int { return cmp.Compare(left.Path, right.Path) })
	observer, err := preflight.NewLinuxObserver(func(ctx context.Context) (preflight.PackageObservation, error) {
		return preflight.ObserveBootstrapReadiness(ctx)
	})
	if err != nil {
		return request, preflight.Result{}, err
	}
	observed, err := observer.ObserveExpansion(ctx, request)
	if err != nil {
		return request, preflight.Result{}, err
	}
	result, err := preflight.EvaluateExpansion(request, observed)
	if err == nil {
		err = preflight.RequireExpansionResultForRequest(result, request, observed.Clock.Now)
	}
	return request, result, err
}

func evaluateHeadscaleDeployPreflight(ctx context.Context, installed release.InstallIdentity, installationID, headscaleID, controlDomain string, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
	account, err := managedheadscale.ValidateAccount(installationID, headscaleID)
	if err != nil {
		return preflight.ExpansionRequest{}, preflight.Result{}, err
	}
	return evaluateHeadscalePreflight(ctx, installed, controlDomain, generation,
		preflight.ManagedPathRequirement{Path: "/etc/lanpanel-headscale", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: account.GID, RequiredMode: 0o710, MaximumMode: 0o710, AllowAbsent: true},
		preflight.ManagedPathRequirement{Path: "/etc/systemd/system/lanpanel-headscale.service", Kind: preflight.ManagedPathRegular, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o644, MaximumMode: 0o644, AllowAbsent: true},
		preflight.ManagedPathRequirement{Path: "/var/lib/lanpanel/headscale-control", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700, AllowAbsent: true},
		preflight.ManagedPathRequirement{Path: "/var/lib/lanpanel/headscale-runtime", Kind: preflight.ManagedPathDirectory, OwnerUID: account.UID, OwnerGID: account.GID, RequiredMode: 0o700, MaximumMode: 0o700, AllowAbsent: true},
	)
}
