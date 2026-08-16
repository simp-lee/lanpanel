//go:build linux

package application

import (
	"cmp"
	"context"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"slices"
)

func evaluateHeadscalePreflight(ctx context.Context, installed release.InstallIdentity, controlDomain string, generation uint64) (preflight.ExpansionRequest, preflight.Result, error) {
	profile := installed.Profile
	authority := preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + installed.ProfileDigest, LiveQualified: true}
	if installed.Kind == release.EnvelopeQualificationCandidate {
		authority = preflight.ProfileAuthority{Kind: preflight.QualificationCandidate, Digest: "sha256:" + installed.ProfileDigest, CandidateDigest: "sha256:" + installed.CandidateDigest, ManifestDigest: "sha256:" + installed.QualificationManifest, HostFingerprint: installed.HostFingerprint, CaseID: installed.CaseID}
	}
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
		Profile: preflight.ExpectedProfile{ID: profile.Family, VersionID: profile.Release, Architecture: profile.Architecture, SystemdVersion: profile.SystemdVersion, NginxVersion: profile.NginxVersion, PackageSnapshotDigest: "sha256:" + profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: authority},
		Domains: []string{controlDomain}, OwnedListeners: owned,
		ManagedPaths: []preflight.ManagedPathRequirement{{Path: "/etc/lanpanel/headscale", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700, AllowAbsent: true}, {Path: "/etc/sysusers.d/lanpanel-headscale.conf", Kind: preflight.ManagedPathRegular, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o600, MaximumMode: 0o600, AllowAbsent: true}, {Path: "/usr/lib/lanpanel/dependencies/headscale", Kind: preflight.ManagedPathRegular, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o755, MaximumMode: 0o755, AllowAbsent: true}, {Path: "/var/lib/lanpanel/headscale", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700, AllowAbsent: true}},
		Disks:        []preflight.DiskRequirement{{Path: "/usr/lib/lanpanel/dependencies", MinimumAvailableBytes: maximum}, {Path: "/var/lib/lanpanel", MinimumAvailableBytes: maximum}}, LastTrustedWall: installed.AuthorityCreatedAt,
	}
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
