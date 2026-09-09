//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	managedprocess "lanpanel/internal/process"
	"time"
)

type resourceStatusObservers struct {
	process     func(context.Context, domain.AppResource) error
	target      func(context.Context, domain.AppResource) error
	sources     func(string) (DomainSourceStatus, error)
	certificate func(context.Context, domain.DomainHTTPSBundleIdentity) error
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
