//go:build linux

package application

import (
	"context"
	"errors"
	"lanpanel/internal/certificates"
	"lanpanel/internal/diagnostics"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnpublishedProcessFailuresRemainDiagnostic(t *testing.T) {
	for _, scenario := range []string{"stopped", "stopped_with_endpoint", "running_but_dead"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			resource := deletionTestLocalResource(t)
			resource.ManagedProcess.Applied = &domain.ProcessBundle{Cgroup: "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-00000000000000000000.slice/lanpanel-app-00000000000000000000.service", FrontendEndpoint: filepath.Join(root, "frontend.sock"), EndpointSocketUnits: []string{"lanpanel-app-00000000000000000000.socket"}}
			if scenario == "stopped_with_endpoint" {
				if err := os.WriteFile(resource.ManagedProcess.Applied.FrontendEndpoint, []byte("residue"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "running_but_dead" {
				resource.ManagedProcess.Requested = domain.ProcessRequestedRunning
			}
			observe := resourceStatusObservers{process: func(ctx context.Context, resource domain.AppResource) error {
				return observeResourceProcess(ctx, resource, root)
			}}
			status := observeResourceRuntimeStatus(context.Background(), resource, ResourceStatus{ResourceID: resource.ID}, true, nginx.Manifest{}, observe)
			issues := diagnostics.Build(diagnostics.Observation{ObservedAt: time.Now().UTC(), Nginx: "healthy", Headscale: "not_configured", Connector: "not_configured", Resources: []diagnostics.ResourceObservation{{ResourceID: resource.ID, Status: status.ObservedStatus, Reason: status.Reason}}})
			if scenario == "stopped" {
				if status.ObservedStatus != "closed" || len(issues) != 0 {
					t.Fatalf("stopped status=%+v issues=%+v", status, issues)
				}
			} else if status.ObservedStatus == "closed" || len(issues) == 0 {
				t.Fatalf("process failure hidden behind unpublished ingress: %+v", status)
			}
		})
	}
}

func TestAppStatusRequiresFreshCertificateBundlePointerAndEveryServedAlias(t *testing.T) {
	id := "cert_00000000000000000000000000000001"
	pointerPath, _ := certificates.ActivePointerPath(id)
	bundlePath, _ := certificates.BundlePath(id, 3)
	bundle := domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test", "alias.example.test"}, Certificate: domain.CertificateBundleIdentity{PointerIdentity: pointerPath, Generation: 3, Fingerprint: recoveryDigest("cert"), Authority: &domain.CertificateAuthorityIdentity{CertificateID: id}}}
	resource := recoveryTailnetResource()
	resource.PublicationRecord.State = domain.PublicationPublished
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &bundle}
	manifest := nginx.Manifest{Entries: []nginx.Entry{{ResourceID: resource.ID}}}
	for _, drift := range []string{"", "bundle_changed", "bundle_missing", "pointer_changed", "pointer_missing", "served_alias_changed"} {
		t.Run(drift, func(t *testing.T) {
			servedCalls := 0
			observe := resourceStatusObservers{
				process: func(context.Context, domain.AppResource) error { return nil },
				target:  func(context.Context, domain.AppResource) error { return nil },
				sources: func(string) (DomainSourceStatus, error) {
					return DomainSourceStatus{Status: "source_verified_runtime_unknown"}, nil
				},
				certificate: func(ctx context.Context, bundle domain.DomainHTTPSBundleIdentity) error {
					return observeAppCertificate(ctx, bundle, func(gotID string, generation uint64, expected certificates.BundleIdentity) error {
						if gotID != id || generation != 3 || expected.Fingerprint != bundle.Certificate.Fingerprint {
							t.Fatal("wrong certificate authority")
						}
						if drift == "bundle_missing" {
							return os.ErrNotExist
						}
						if drift == "bundle_changed" {
							return errors.New("bundle fingerprint differs")
						}
						return nil
					}, func(string) (string, error) {
						if drift == "pointer_missing" {
							return "", nil
						}
						if drift == "pointer_changed" {
							return bundlePath + "-foreign", nil
						}
						return bundlePath, nil
					}, func(_ context.Context, host, fingerprint string) error {
						servedCalls++
						if drift == "served_alias_changed" && host == "alias.example.test" {
							return errors.New("served fingerprint differs")
						}
						return nil
					})
				},
			}
			status := observeResourceRuntimeStatus(context.Background(), resource, ResourceStatus{ResourceID: resource.ID}, true, manifest, observe)
			if (status.ObservedStatus == "healthy") != (drift == "") {
				t.Fatalf("drift=%s status=%+v", drift, status)
			}
			if drift == "" && servedCalls != 2 {
				t.Fatalf("only verified %d served domains", servedCalls)
			}
		})
	}
}
