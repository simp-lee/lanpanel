//go:build linux

package application

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/activation"
	"lanpanel/internal/domain"
	"lanpanel/internal/ownership"
	"lanpanel/internal/preflight"
	"lanpanel/internal/process"
	"lanpanel/internal/release"
	"lanpanel/internal/safety"
	"lanpanel/internal/target"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func evaluateTemporaryPreflight(ctx context.Context, installation domain.Installation, resource domain.AppResource, state safety.State, owned *ownership.Record) (preflight.ExpansionRequest, preflight.Result, error) {
	publication := resource.Publication.TemporaryHTTP
	if publication == nil {
		return preflight.ExpansionRequest{}, preflight.Result{}, fmt.Errorf("temporary publication missing")
	}
	identity, err := loadInstalledReleaseIdentity()
	if err != nil {
		return preflight.ExpansionRequest{}, preflight.Result{}, err
	}
	profile := identity.Profile
	authority := preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + identity.ProfileDigest, LiveQualified: true}
	if identity.Kind == release.EnvelopeQualificationCandidate {
		authority = preflight.ProfileAuthority{Kind: preflight.QualificationCandidate, Digest: "sha256:" + identity.ProfileDigest, CandidateDigest: "sha256:" + identity.CandidateDigest, ManifestDigest: "sha256:" + identity.QualificationManifest, HostFingerprint: identity.HostFingerprint, CaseID: identity.CaseID}
	}
	confinement := profile.ManagedConfinement
	ownedListeners := []preflight.OwnedListenerAuthority{}
	if owned != nil {
		for _, listener := range owned.Listeners {
			if listener.Protocol == "tcp" && listener.Address == "0.0.0.0" && listener.Port == publication.Port {
				inode, err := nginxListenerInode("/proc/net/tcp", publication.Port)
				if err != nil {
					return preflight.ExpansionRequest{}, preflight.Result{}, err
				}
				ownedListeners = append(ownedListeners, preflight.OwnedListenerAuthority{Protocol: "tcp", Address: "0.0.0.0", Port: publication.Port, SocketInode: inode, IdentityDigest: preflight.OwnedListenerDigest("tcp", "0.0.0.0", publication.Port, inode)})
			}
		}
	}
	request := preflight.ExpansionRequest{
		Scope: preflight.ExpansionTemporaryHTTP, Target: "resource/" + resource.ID, Generation: resource.PublicationRecord.UnpublishedGeneration, OwnedListeners: ownedListeners,
		Profile:         preflight.ExpectedProfile{ID: profile.Family, VersionID: profile.Release, Architecture: "amd64", SystemdVersion: profile.SystemdVersion, NginxVersion: profile.NginxVersion, PackageSnapshotDigest: "sha256:" + profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: authority},
		PublicAddresses: []string{publication.PublicIPv4}, TemporaryPort: publication.Port,
		ManagedPaths: []preflight.ManagedPathRequirement{{Path: "/etc/lanpanel/nginx", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700}},
		Disks:        []preflight.DiskRequirement{{Path: "/etc/lanpanel/nginx", MinimumAvailableBytes: 1}}, LastTrustedWall: time.Now().UTC().Add(-time.Second),
	}
	packageRead := func(ctx context.Context) (preflight.PackageObservation, error) {
		return preflight.ObserveBootstrapReadiness(ctx)
	}
	observer, err := preflight.NewLinuxObserver(packageRead)
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
	_ = installation
	_ = state
	return request, result, err
}

func evaluateDomainPreflight(ctx context.Context, installation domain.Installation, resource domain.AppResource, state safety.State) (preflight.ExpansionRequest, preflight.Result, error) {
	publication := resource.Publication.DomainHTTPS
	if publication == nil {
		return preflight.ExpansionRequest{}, preflight.Result{}, fmt.Errorf("domain publication missing")
	}
	identity, err := loadInstalledReleaseIdentity()
	if err != nil {
		return preflight.ExpansionRequest{}, preflight.Result{}, err
	}
	profile := identity.Profile
	authority := preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + identity.ProfileDigest, LiveQualified: true}
	if identity.Kind == release.EnvelopeQualificationCandidate {
		authority = preflight.ProfileAuthority{Kind: preflight.QualificationCandidate, Digest: "sha256:" + identity.ProfileDigest, CandidateDigest: "sha256:" + identity.CandidateDigest, ManifestDigest: "sha256:" + identity.QualificationManifest, HostFingerprint: identity.HostFingerprint, CaseID: identity.CaseID}
	}
	domains := append([]string{publication.CanonicalDomain}, publication.Aliases...)
	slices.Sort(domains)
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
	lastTrustedWall := time.Unix(1, 0).UTC()
	for _, authority := range state.Resources {
		if authority.ResourceID == resource.ID && authority.ActiveCertificate != nil {
			lastTrustedWall = authority.ActiveCertificate.LastTrustedWall
		}
	}
	confinement := profile.ManagedConfinement
	request := preflight.ExpansionRequest{Scope: preflight.ExpansionDomainHTTPS, Target: "resource/" + resource.ID, Generation: resource.PublicationRecord.UnpublishedGeneration, Domains: domains, OwnedListeners: owned, Profile: preflight.ExpectedProfile{ID: profile.Family, VersionID: profile.Release, Architecture: "amd64", SystemdVersion: profile.SystemdVersion, NginxVersion: profile.NginxVersion, PackageSnapshotDigest: "sha256:" + profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: confinement.SchemaVersion, KernelRelease: confinement.KernelRelease, CgroupMode: confinement.CgroupMode, BindListenPolicy: confinement.BindListenPolicy, ConnectPolicy: confinement.ConnectPolicy, FilesystemPolicy: confinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), confinement.ProtectedDestinations...), QualificationDigest: "sha256:" + confinement.QualificationDigest}, Authority: authority}, ManagedPaths: []preflight.ManagedPathRequirement{{Path: "/etc/lanpanel/nginx", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700}, {Path: "/var/lib/lanpanel/certificates", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o711, MaximumMode: 0o711}}, Disks: []preflight.DiskRequirement{{Path: "/etc/lanpanel/nginx", MinimumAvailableBytes: 1}}, LastTrustedWall: lastTrustedWall}
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
	_ = installation
	_ = state
	return request, result, err
}

func nginxListenerInode(path string, port uint16) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}
		value, err := strconv.ParseUint(parts[1], 16, 16)
		if err == nil && uint16(value) == port {
			return strconv.ParseUint(fields[9], 10, 64)
		}
	}
	return 0, fmt.Errorf("owned Nginx listener not observed")
}

func loadInstalledReleaseIdentity() (release.InstallIdentity, error) {
	path := "/var/lib/lanpanel/installation/bundle.json"
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return release.InstallIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return release.InstallIdentity{}, fmt.Errorf("installation release descriptor invalid")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 4<<20 {
		return release.InstallIdentity{}, fmt.Errorf("installation release authority is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4<<20+1))
	if err != nil || int64(len(data)) != stat.Size {
		return release.InstallIdentity{}, fmt.Errorf("installation release authority changed")
	}
	var bundle struct {
		Release release.InstallIdentity `json:"release"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil || release.ValidateInstallIdentity(bundle.Release) != nil {
		return release.InstallIdentity{}, fmt.Errorf("installation release authority invalid")
	}
	return bundle.Release, nil
}

func probeResourceTarget(ctx context.Context, resource domain.AppResource) (target.Evidence, error) {
	bundle := resource.ManagedProcess.Applied
	if bundle == nil {
		return target.Evidence{}, fmt.Errorf("applied process bundle missing")
	}
	authority, err := process.LoadExecAuthority(resource.ID)
	if err != nil {
		return target.Evidence{}, err
	}
	if authority.Policy.Digest != bundle.PolicyDigest || authority.Evidence.ExecutableDigest != bundle.ExecutableDigest || authority.UID != bundle.ApplicationUID || authority.GID != bundle.ApplicationGID {
		return target.Evidence{}, fmt.Errorf("managed process authority changed")
	}
	host, err := process.NewFixedHost()
	if err != nil {
		return target.Evidence{}, err
	}
	if err := host.VerifyApplied(ctx, resource.ID, *bundle, authority.Policy); err != nil {
		return target.Evidence{}, err
	}
	runtime, err := process.Observe(ctx, "/sys/fs/cgroup", *bundle, resource.Target.LocalHTTP.EndpointKind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
	if err != nil {
		return target.Evidence{}, err
	}
	if err := process.VerifyRunning(runtime); err != nil {
		return target.Evidence{}, err
	}
	endpointIdentity := bundle.PolicyDigest + "/" + runtime.Digest
	accessMode := domain.AppAccessPublic
	hostName := "lanpanel-target.invalid"
	if resource.Publication.DomainHTTPS != nil {
		accessMode = resource.Publication.DomainHTTPS.AccessMode
		hostName = resource.Publication.DomainHTTPS.CanonicalDomain
	}
	request := target.ProbeRequest{ResourceID: resource.ID, ConfigDigest: resource.CurrentConfigDigest, EndpointIdentity: endpointIdentity, Target: resource.Target, AccessMode: accessMode, Host: hostName}
	if bundle.TCPAddress != "" {
		transport, err := target.NewTCPTransport(bundle.TCPAddress, bundle.TCPPort, endpointIdentity)
		if err != nil {
			return target.Evidence{}, err
		}
		return target.Probe(ctx, request, transport)
	}
	transport, err := target.NewUnixTransport(bundle.FrontendEndpoint, endpointIdentity, bundle.FrontendUID, bundle.FrontendGID, bundle.FrontendMode)
	if err != nil {
		return target.Evidence{}, err
	}
	return target.Probe(ctx, request, transport)
}
