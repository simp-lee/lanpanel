//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/closure"
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/domain"
	"lanpanel/internal/ownership"
	"lanpanel/internal/preflight"
	"lanpanel/internal/process"
	"lanpanel/internal/release"
	"lanpanel/internal/safety"
	"lanpanel/internal/target"
	"net/netip"
	"slices"
	"time"
)

func temporaryPublicationLastTrustedWall() time.Time {
	return time.Unix(1, 0).UTC()
}

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
	authority := installedProfileAuthority(identity)
	expected := expectedInstalledProfile(profile)
	expected.Authority = authority
	ownedListeners := []preflight.OwnedListenerAuthority{}
	if ownsTemporaryListener(owned, resource.ID, publication.Port) {
		host, err := activation.NewFixedHost()
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		runtime, err := host.ObserveCurrent(ctx)
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, fmt.Errorf("temporary Nginx listener ownership invalid: %w", err)
		}
		listener, err := temporaryListenerAuthorityFromRuntime(runtime, publication.Port)
		if err != nil {
			return preflight.ExpansionRequest{}, preflight.Result{}, err
		}
		ownedListeners = append(ownedListeners, listener)
	}
	request := preflight.ExpansionRequest{
		Scope: preflight.ExpansionTemporaryHTTP, Target: "resource/" + resource.ID, Generation: resource.PublicationRecord.UnpublishedGeneration, OwnedListeners: ownedListeners,
		Profile:         expected,
		PublicAddresses: []string{publication.PublicIPv4}, TemporaryPort: publication.Port,
		ManagedPaths: []preflight.ManagedPathRequirement{{Path: "/etc/lanpanel/nginx", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700}},
		Disks:        []preflight.DiskRequirement{{Path: "/etc/lanpanel/nginx", MinimumAvailableBytes: 1}}, LastTrustedWall: temporaryPublicationLastTrustedWall(),
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
	authority := installedProfileAuthority(identity)
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
	expected := expectedInstalledProfile(profile)
	expected.Authority = authority
	request := preflight.ExpansionRequest{Scope: preflight.ExpansionDomainHTTPS, Target: "resource/" + resource.ID, Generation: resource.PublicationRecord.UnpublishedGeneration, Domains: domains, OwnedListeners: owned, Profile: expected, ManagedPaths: []preflight.ManagedPathRequirement{{Path: "/etc/lanpanel/nginx", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700}, {Path: "/var/lib/lanpanel/certificates", Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o711, MaximumMode: 0o711}}, Disks: []preflight.DiskRequirement{{Path: "/etc/lanpanel/nginx", MinimumAvailableBytes: 1}}, LastTrustedWall: lastTrustedWall}
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

func ownsTemporaryListener(record *ownership.Record, resourceID string, port uint16) bool {
	if record == nil || record.ResourceID != resourceID || record.State != ownership.Owned {
		return false
	}
	identity := ownership.ListenerIdentity(resourceID, "tcp", "0.0.0.0", port)
	for _, listener := range record.Listeners {
		if listener.Protocol == "tcp" && listener.Address == "0.0.0.0" && listener.Port == port && listener.IdentityDigest == identity {
			return true
		}
	}
	return false
}

func temporaryListenerAuthorityFromRuntime(runtime closure.RuntimeSnapshot, port uint16) (preflight.OwnedListenerAuthority, error) {
	expected := fmt.Sprintf("tcp:0.0.0.0:%d", port)
	if err := closure.VerifyServing(runtime, runtime.Generation, []string{expected}); err != nil {
		return preflight.OwnedListenerAuthority{}, fmt.Errorf("owned temporary Nginx listener is not in the verified runtime generation: %w", err)
	}
	for _, listener := range runtime.Listeners {
		if listener.Protocol == "tcp" && listener.Address == "0.0.0.0" && listener.Port == port && listener.Inode != 0 {
			return preflight.OwnedListenerAuthority{Protocol: listener.Protocol, Address: listener.Address, Port: listener.Port, SocketInode: listener.Inode, IdentityDigest: preflight.OwnedListenerDigest(listener.Protocol, listener.Address, listener.Port, listener.Inode)}, nil
		}
	}
	return preflight.OwnedListenerAuthority{}, fmt.Errorf("owned temporary Nginx listener is not in the verified runtime generation")
}

func loadInstalledReleaseIdentity() (release.InstallIdentity, error) {
	return readCommittedReleaseIdentity()
}

func probeResourceTarget(ctx context.Context, resource domain.AppResource) (target.Evidence, error) {
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		verified, err := VerifyConnector(ctx, nil, nil)
		if err != nil {
			return target.Evidence{}, err
		}
		return probeTailnetResourceTarget(ctx, resource, verified.Observation)
	}
	if resource.ManagedProcess == nil {
		return target.Evidence{}, fmt.Errorf("local target managed process missing")
	}
	bundle := resource.ManagedProcess.Applied
	if bundle == nil {
		return target.Evidence{}, fmt.Errorf("applied process bundle missing")
	}
	authority, err := process.LoadExecAuthority(resource.ID)
	if err != nil {
		return target.Evidence{}, bindProcessRuntimeViolation(resource, err)
	}
	if authority.Policy.Digest != bundle.PolicyDigest || authority.Evidence.ExecutableDigest != bundle.ExecutableDigest || authority.UID != bundle.ApplicationUID || authority.GID != bundle.ApplicationGID {
		violation := process.NewRuntimeViolation(process.RuntimeViolationPolicyInvalid, fmt.Errorf("managed process authority changed"))
		return target.Evidence{}, bindProcessRuntimeViolation(resource, violation)
	}
	host, err := process.NewFixedHost()
	if err != nil {
		return target.Evidence{}, err
	}
	if err := host.VerifyApplied(ctx, resource.ID, *bundle, authority.Policy); err != nil {
		return target.Evidence{}, bindProcessRuntimeViolation(resource, err)
	}
	runtime, err := process.Observe(ctx, "/sys/fs/cgroup", *bundle, resource.Target.LocalHTTP.EndpointKind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
	if err != nil {
		return target.Evidence{}, bindProcessRuntimeViolation(resource, err)
	}
	if err := process.VerifyRunning(runtime); err != nil {
		return target.Evidence{}, err
	}
	endpointIdentity := managedProcessEndpointIdentity(bundle.PolicyDigest, runtime.Digest)
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

func probeTailnetResourceTarget(ctx context.Context, resource domain.AppResource, observation managedconnector.Observation) (target.Evidence, error) {
	if resource.Target.Kind != domain.AppTargetTailnetHTTP || resource.Target.TailnetHTTP == nil {
		return target.Evidence{}, fmt.Errorf("tailnet target authority is missing")
	}
	address, err := netip.ParseAddr(resource.Target.TailnetHTTP.IP)
	if err != nil {
		return target.Evidence{}, err
	}
	if err := managedconnector.VerifyPeer(observation, address, time.Now().UTC()); err != nil {
		return target.Evidence{}, err
	}
	source, sourceErr := netip.ParseAddr(resource.Target.TailnetHTTP.SourceIP)
	if sourceErr != nil || !slices.Contains(observation.LocalIPs, source) {
		return target.Evidence{}, fmt.Errorf("tailnet source IP is not a fresh local connector identity")
	}
	endpointIdentity := tailnetEndpointIdentity(observation, source, address, resource.Target.TailnetHTTP.Port)
	accessMode := domain.AppAccessPublic
	hostName := "lanpanel-target.invalid"
	if resource.Publication.DomainHTTPS != nil {
		accessMode = resource.Publication.DomainHTTPS.AccessMode
		hostName = resource.Publication.DomainHTTPS.CanonicalDomain
	}
	request := target.ProbeRequest{ResourceID: resource.ID, ConfigDigest: resource.CurrentConfigDigest, EndpointIdentity: endpointIdentity, Target: resource.Target, AccessMode: accessMode, Host: hostName}
	transport, err := target.NewTailnetTransport(address.String(), resource.Target.TailnetHTTP.SourceIP, resource.Target.TailnetHTTP.Port, endpointIdentity)
	if err != nil {
		return target.Evidence{}, err
	}
	return target.Probe(ctx, request, transport)
}

func tailnetEndpointIdentity(observation managedconnector.Observation, source, peer netip.Addr, port uint16) string {
	return digestLifecycle(struct {
		ClientVersion  string `json:"client_version"`
		ControlURL     string `json:"control_url"`
		SourceIP       string `json:"source_ip"`
		PeerIP         string `json:"peer_ip"`
		Port           uint16 `json:"port"`
		RouteInterface string `json:"route_interface"`
	}{
		ClientVersion:  observation.ClientVersion,
		ControlURL:     observation.ControlURL,
		SourceIP:       source.String(),
		PeerIP:         peer.String(),
		Port:           port,
		RouteInterface: "tailscale0",
	})
}

func managedProcessEndpointIdentity(policyDigest, runtimeDigest string) string {
	return digestLifecycle(struct {
		PolicyDigest  string `json:"policy_digest"`
		RuntimeDigest string `json:"runtime_digest"`
	}{PolicyDigest: policyDigest, RuntimeDigest: runtimeDigest})
}

func targetEvidenceGeneration(resource domain.AppResource) uint64 {
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		return resource.PublicationRecord.UnpublishedGeneration
	}
	if resource.ManagedProcess != nil && resource.ManagedProcess.Applied != nil {
		return resource.ManagedProcess.Applied.Generation
	}
	return 0
}
