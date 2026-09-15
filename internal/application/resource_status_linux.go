//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	managedprocess "lanpanel/internal/process"
	"lanpanel/internal/target"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type resourceStatusObservers struct {
	process     func(context.Context, domain.AppResource) error
	target      func(context.Context, domain.AppResource) error
	sources     func(string) (DomainSourceStatus, error)
	certificate func(context.Context, domain.DomainHTTPSBundleIdentity) error
}

type typedConnectorCache struct {
	loaded      bool
	managed     managedconnector.Observation
	observation *domain.ConnectorObservation
	failure     domain.ResourceFailureCategory
}

func observeTypedResourceEvidence(ctx context.Context, resource domain.AppResource, observedAt time.Time, manifest nginx.Manifest, nginxHealthy bool, connectorCache *typedConnectorCache) ResourceStatusEvidence {
	evidence := ResourceStatusEvidence{NginxHealthy: nginxHealthy, ManifestContains: manifestMatchesResource(manifest, resource), NginxGeneration: manifest.GenerationID}
	if resource.Target.Kind == domain.AppTargetLocalHTTP && resource.ManagedProcess != nil {
		if err := observeResourceProcess(ctx, resource, "/sys/fs/cgroup"); err == nil {
			if resource.ManagedProcess.Requested == domain.ProcessRequestedRunning {
				evidence.ProcessStatus = domain.ProcessRunning
			} else {
				evidence.ProcessStatus = domain.ProcessStopped
			}
		} else {
			evidence.ProcessFailure = domain.FailureProcess
		}
	}
	if projectPublicationStatus(resource.PublicationRecord) == domain.PublicationStatusPublished && resource.PublicationRecord.LastAppliedBundle == nil {
		evidence.PublicationFailure = domain.FailurePublication
	}
	if resource.Target.Kind == domain.AppTargetLocalHTTP && (projectPublicationStatus(resource.PublicationRecord) == domain.PublicationStatusPublished || projectPublicationStatus(resource.PublicationRecord) == domain.PublicationStatusUnpublished) && evidence.ProcessStatus == domain.ProcessRunning {
		evidence.TargetObservation, evidence.TargetFailure = observeTypedTarget(ctx, resource, observedAt, "", nil)
	}
	if projectPublicationStatus(resource.PublicationRecord) == domain.PublicationStatusPublished && resource.PublicationRecord.LastAppliedBundle != nil {
		bundle := resource.PublicationRecord.LastAppliedBundle
		switch bundle.Kind {
		case domain.PublicationTemporaryHTTP:
		case domain.PublicationDomainHTTPS:
			status, sourceErr := ObserveDomainLiveSources(resource.ID)
			evidence.SourceChecked = true
			evidence.SourceHealthy = sourceErr == nil && (status.Status == "source_verified_runtime_unknown" || status.Status == "healthy")
			if !evidence.SourceHealthy {
				evidence.SourceFailure = domain.FailureEvidenceMismatch
			}
			if bundle.DomainHTTPS == nil {
				evidence.PublicationFailure = domain.FailurePublication
			} else {
				host := activation.Host{Paths: nginx.FixedPaths(), Owner: filetxn.Owner{UID: 0, GID: 0}}
				evidence.CertificateChecked = true
				evidence.CertificateHealthy = observeAppCertificate(ctx, *bundle.DomainHTTPS, certificates.VerifyBundleIdentity, certificates.ObservePointer, host.VerifyServedCertificate) == nil
				if !evidence.CertificateHealthy {
					evidence.CertificateFailure = domain.FailureCertificate
				}
			}
		default:
			evidence.PublicationFailure = domain.FailurePublication
		}
	}
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		if connectorCache == nil {
			connectorCache = &typedConnectorCache{}
		}
		if !connectorCache.loaded {
			connectorCache.loaded = true
			verified, err := VerifyConnector(ctx, nil, nil)
			if err != nil {
				connectorCache.failure = typedConnectorFailure(err)
			} else {
				connectorCache.managed = verified.Observation
				value := typedConnectorObservation(verified.Observation, time.Now().UTC())
				connectorCache.observation = &value
			}
		}
		if connectorCache.observation != nil {
			observation := *connectorCache.observation
			if observation.Validity == domain.ConnectorObservationFresh && (!observation.ValidUntil.After(time.Now().UTC()) || time.Since(observation.ObservedAt) > 5*time.Minute) {
				observation.Validity = domain.ConnectorObservationExpired
			}
			evidence.ConnectorObservation = &observation
		}
		evidence.ConnectorFailure = connectorCache.failure
		if connectorCache.observation != nil && resource.Target.TailnetHTTP != nil {
			route, routeFailure := typedRouteEvidence(resource, connectorCache.managed, *connectorCache.observation, time.Now().UTC())
			evidence.RouteEvidence, evidence.RouteFailure = route, routeFailure
			if route != nil && route.Validity == domain.EvidenceFresh && projectPublicationStatus(resource.PublicationRecord) != domain.PublicationStatusActivating && projectPublicationStatus(resource.PublicationRecord) != domain.PublicationStatusContracting {
				evidence.TargetObservation, evidence.TargetFailure = observeTypedTarget(ctx, resource, observedAt, route.RouteIdentity, &connectorCache.managed)
			}
		}
	}
	return evidence
}

func observeTypedTarget(ctx context.Context, resource domain.AppResource, observedAt time.Time, routeIdentity string, connectorObservation *managedconnector.Observation) (*domain.TargetObservation, domain.ResourceFailureCategory) {
	if resource.Target.Kind == domain.AppTargetTailnetHTTP && routeIdentity == "" {
		return nil, domain.FailureEvidenceMissing
	}
	var observed target.Evidence
	var err error
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		if connectorObservation == nil {
			return nil, domain.FailureEvidenceMissing
		}
		observed, err = probeTailnetResourceTarget(ctx, resource, *connectorObservation)
	} else {
		observed, err = probeResourceTarget(ctx, resource)
	}
	if err != nil {
		failure := typedTargetFailure(err)
		return &domain.TargetObservation{RouteIdentity: routeIdentity, WebSocketRequired: resource.Target.WebSocket.Enabled, Validity: domain.EvidenceUnreachable, ObservedAt: observedAt, Failure: failure}, failure
	}
	webSocketReady := observed.WebSocketStatus == 101
	if !webSocketReady && resource.Publication.DomainHTTPS != nil && resource.Publication.DomainHTTPS.AccessMode == domain.AppAccessApplicationManaged && (observed.WebSocketStatus == 401 || observed.WebSocketStatus == 403) {
		webSocketReady = true
	}
	return &domain.TargetObservation{RouteIdentity: routeIdentity, PortConnected: true, HTTPReady: true, WebSocketRequired: resource.Target.WebSocket.Enabled, WebSocketReady: webSocketReady, HTTPStatus: uint16(observed.HTTPStatus), Validity: domain.EvidenceFresh, ObservedAt: observed.ObservedAt, Failure: domain.FailureNone}, domain.FailureNone
}

func typedConnectorObservation(observed managedconnector.Observation, now time.Time) domain.ConnectorObservation {
	local := make([]string, 0, len(observed.LocalIPs))
	for _, value := range observed.LocalIPs {
		local = append(local, value.String())
	}
	slices.Sort(local)
	clientDigest := digestLifecycle(struct {
		ControlURL    string
		ClientVersion string
	}{observed.ControlURL, observed.ClientVersion})
	localDigest := digestLifecycle(local)
	validity := domain.ConnectorObservationFresh
	if now.Before(observed.ObservedAt) || !observed.ValidUntil.After(now) || now.Sub(observed.ObservedAt) > 5*time.Minute {
		validity = domain.ConnectorObservationExpired
	}
	return domain.ConnectorObservation{ControlURL: observed.ControlURL, ClientVersion: observed.ClientVersion, ClientIdentityDigest: clientDigest, LocalIdentityDigest: localDigest, Validity: validity, ObservedAt: observed.ObservedAt, ValidUntil: observed.ValidUntil}
}

func typedConnectorFailure(err error) domain.ResourceFailureCategory {
	var prerequisite domain.PrerequisiteError
	if errors.As(err, &prerequisite) {
		return domain.FailureAuthorityMissing
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "mismatch") || strings.Contains(message, "drift") || strings.Contains(message, "invalid") || strings.Contains(message, "identity") {
		return domain.FailureEvidenceMismatch
	}
	return domain.FailureConnectorDown
}

func typedTargetFailure(err error) domain.ResourceFailureCategory {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "http readiness returned disallowed status"):
		return domain.FailureHTTPStatus
	case strings.Contains(message, "websocket readiness") || strings.Contains(message, "websocket upgrade"):
		return domain.FailureWebSocket
	case strings.Contains(message, "authority") || strings.Contains(message, "identity"):
		return domain.FailureEvidenceMismatch
	default:
		return domain.FailureTargetDown
	}
}

func typedRouteEvidence(resource domain.AppResource, observed managedconnector.Observation, connector domain.ConnectorObservation, now time.Time) (*domain.RouteEvidence, domain.ResourceFailureCategory) {
	target := resource.Target.TailnetHTTP
	if target == nil {
		return nil, domain.FailureConfiguration
	}
	peer, peerErr := netip.ParseAddr(target.IP)
	source, sourceErr := netip.ParseAddr(target.SourceIP)
	peerIP, sourceIP := target.IP, target.SourceIP
	if peerErr == nil {
		peerIP = peer.String()
	}
	if sourceErr == nil {
		sourceIP = source.String()
	}
	if peerErr != nil || sourceErr != nil || !slices.Contains(observed.LocalIPs, source) {
		return &domain.RouteEvidence{PeerIP: peerIP, SourceIP: sourceIP, Port: target.Port, Validity: domain.EvidenceUnknown, Failure: domain.FailureEvidenceMismatch}, domain.FailureEvidenceMismatch
	}
	connectorIdentity := domain.TailnetConnectorIdentity(connector.ControlURL, connector.ClientVersion, connector.ClientIdentityDigest, connector.LocalIdentityDigest)
	routeIdentity := domain.TailnetRouteIdentity(connectorIdentity, peer.String(), source.String(), target.Port)
	if err := managedconnector.VerifyPeer(observed, peer, now); err != nil {
		message := strings.ToLower(err.Error())
		failure := domain.FailureRouteDown
		validity := domain.EvidenceUnreachable
		observedAt, validUntil := now, now
		if strings.Contains(message, "offline") {
			failure = domain.FailurePeerOffline
		} else if strings.Contains(message, "stale") {
			failure = domain.FailureEvidenceExpired
			validity = domain.EvidenceUnknown
			connectorIdentity, routeIdentity = "", ""
			observedAt, validUntil = time.Time{}, time.Time{}
		} else if strings.Contains(message, "not in fresh") {
			failure = domain.FailureEvidenceMissing
			validity = domain.EvidenceUnknown
			connectorIdentity, routeIdentity = "", ""
			observedAt, validUntil = time.Time{}, time.Time{}
		}
		return &domain.RouteEvidence{PeerIP: peer.String(), SourceIP: source.String(), Port: target.Port, ConnectorIdentityDigest: connectorIdentity, RouteIdentity: routeIdentity, Validity: validity, ObservedAt: observedAt, ValidUntil: validUntil, Failure: failure}, failure
	}
	return &domain.RouteEvidence{PeerIP: peer.String(), SourceIP: source.String(), Port: target.Port, ConnectorIdentityDigest: connectorIdentity, RouteIdentity: routeIdentity, Validity: domain.EvidenceFresh, ObservedAt: observed.ObservedAt, ValidUntil: observed.ValidUntil, Failure: domain.FailureNone}, domain.FailureNone
}

func fixedResourceStatusObservers() resourceStatusObservers {
	return resourceStatusObservers{
		process: func(ctx context.Context, resource domain.AppResource) error {
			return observeResourceProcess(ctx, resource, "/sys/fs/cgroup")
		},
		target: func(ctx context.Context, resource domain.AppResource) error {
			_, err := probeResourceTarget(ctx, resource)
			return err
		},
		sources: ObserveDomainLiveSources,
		certificate: func(ctx context.Context, bundle domain.DomainHTTPSBundleIdentity) error {
			host := activation.Host{Paths: nginx.FixedPaths(), Owner: filetxn.Owner{UID: 0, GID: 0}}
			return observeAppCertificate(ctx, bundle, certificates.VerifyBundleIdentity, certificates.ObservePointer, host.VerifyServedCertificate)
		},
	}
}

func observeResourceProcess(ctx context.Context, resource domain.AppResource, cgroupRoot string) error {
	if resource.ManagedProcess == nil {
		if resource.Target.Kind != domain.AppTargetTailnetHTTP {
			return fmt.Errorf("local managed process authority missing")
		}
		return nil
	}
	if resource.ManagedProcess.Requested == domain.ProcessRequestedStopped {
		return verifyDeleteRuntimeClosedWithCgroupRoot(ctx, cgroupRoot, resource)
	}
	if resource.ManagedProcess.Requested != domain.ProcessRequestedRunning || resource.ManagedProcess.Applied == nil || resource.Target.LocalHTTP == nil {
		return fmt.Errorf("managed process applied identity missing")
	}
	observation, err := managedprocess.Observe(ctx, cgroupRoot, *resource.ManagedProcess.Applied, resource.Target.LocalHTTP.EndpointKind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
	return errors.Join(err, managedprocess.VerifyRunning(observation))
}

func observeAppCertificate(ctx context.Context, bundle domain.DomainHTTPSBundleIdentity, verify func(string, uint64, certificates.BundleIdentity) error, pointer func(string) (string, error), served func(context.Context, string, string) error) error {
	certificate := bundle.Certificate
	if certificate.Authority == nil || len(bundle.ExactDomains) == 0 {
		return fmt.Errorf("app certificate authority missing")
	}
	id := certificate.Authority.CertificateID
	if !certificateBundleMatches(certificate, id, certificate.Generation, certificateBundleIdentity(certificate)) {
		return fmt.Errorf("app certificate pointer authority differs")
	}
	if err := verify(id, certificate.Generation, certificateBundleIdentity(certificate)); err != nil {
		return fmt.Errorf("app certificate bundle unavailable: %w", err)
	}
	expected, err := certificates.BundlePath(id, certificate.Generation)
	if err != nil {
		return err
	}
	observed, err := pointer(id)
	if err != nil || observed != expected {
		return fmt.Errorf("app certificate active pointer differs: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, name := range bundle.ExactDomains {
		if err := served(ctx, name, certificate.Fingerprint); err != nil {
			return fmt.Errorf("app served certificate differs: %w", err)
		}
	}
	return nil
}

func observeResourceRuntimeStatus(ctx context.Context, resource domain.AppResource, item ResourceStatus, nginxHealthy bool, manifest nginx.Manifest, observe resourceStatusObservers) ResourceStatus {
	processErr := observe.process(ctx, resource)
	if resource.PublicationRecord.State == domain.PublicationUnpublished {
		item.ObservedStatus = "runtime_unknown"
		item.Reason = "unpublished configuration has no fresh runtime closure proof"
		if nginxHealthy && !manifestContainsResource(manifest, resource.ID) {
			item.ObservedStatus = "closed"
			item.Reason = "fresh Nginx graph and runtime exclude the unpublished resource"
		}
		if processErr != nil {
			item.ObservedStatus = "process_unknown"
			item.Reason += "; " + processErr.Error()
		}
		return item
	}
	targetErr := observe.target(ctx, resource)
	bundle := resource.PublicationRecord.LastAppliedBundle
	switch {
	case bundle == nil:
		item.Reason = "published resource has no applied bundle"
	case bundle.Kind == domain.PublicationTemporaryHTTP:
		if nginxHealthy && manifestContainsResource(manifest, resource.ID) && targetErr == nil && processErr == nil {
			item.ObservedStatus = "healthy"
			item.Reason = "fresh target, process, Nginx graph, and runtime evidence match"
		} else if targetErr != nil || processErr != nil {
			item.Reason = errors.Join(targetErr, processErr).Error()
		} else {
			item.Reason = "temporary publication runtime evidence is incomplete"
		}
	case bundle.Kind == domain.PublicationDomainHTTPS && bundle.DomainHTTPS != nil:
		status, sourceErr := observe.sources(resource.ID)
		certificateErr := observe.certificate(ctx, *bundle.DomainHTTPS)
		if err := errors.Join(sourceErr, certificateErr, processErr, targetErr); err != nil {
			item.ObservedStatus = "runtime_unknown"
			item.Reason = err.Error()
			break
		}
		item.ObservedStatus, item.Reason = status.Status, status.Reason
		if status.Status == "source_verified_runtime_unknown" && nginxHealthy && manifestContainsResource(manifest, resource.ID) {
			item.ObservedStatus = "healthy"
			item.Reason = "fresh source, certificate, target, process, Nginx graph, and runtime evidence match"
		}
	default:
		item.Reason = "applied publication kind is unsupported"
	}
	return item
}
