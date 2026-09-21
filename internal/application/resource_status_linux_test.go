//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"lanpanel/internal/certificates"
	"lanpanel/internal/diagnostics"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/nginx"
	"lanpanel/internal/persist"
	"lanpanel/internal/target"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestTypedStatusProjectionDistinguishesClosureHealthAndUnreachable(t *testing.T) {
	now := time.Now().UTC()
	local := recoveryLocalResource(t)
	local.PublicationRecord.State = domain.PublicationUnpublished
	closed, err := ProjectObservedResourceStatus(local, now, ResourceStatusEvidence{NginxHealthy: true, ProcessStatus: domain.ProcessStopped})
	if err != nil || closed.OverallStatus != domain.ResourceStatusClosed || !closed.ClosureVerified {
		t.Fatalf("closed status=%#v error=%v", closed, err)
	}
	unknown, err := ProjectObservedResourceStatus(local, now, ResourceStatusEvidence{ProcessStatus: domain.ProcessStopped})
	if err != nil || unknown.OverallStatus != domain.ResourceStatusUnknown || unknown.ClosureVerified {
		t.Fatalf("unproved closure status=%#v error=%v", unknown, err)
	}

	healthyLocal := recoveryLocalResource(t)
	healthyLocal.PublicationRecord.State = domain.PublicationPublished
	healthyLocal.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{Kind: domain.PublicationTemporaryHTTP, ConfigDigest: healthyLocal.CurrentConfigDigest}
	healthyLocal.PublicationRecord.LastAppliedDigest = &healthyLocal.CurrentConfigDigest
	healthyLocal.ManagedProcess.Requested = domain.ProcessRequestedRunning
	healthyLocalTarget := &domain.TargetObservation{PortConnected: true, HTTPReady: true, HTTPStatus: 200, Validity: domain.EvidenceFresh, ObservedAt: now, Failure: domain.FailureNone}
	healthy, err := ProjectObservedResourceStatus(healthyLocal, now, ResourceStatusEvidence{NginxHealthy: true, ManifestContains: true, ProcessStatus: domain.ProcessRunning, TargetObservation: healthyLocalTarget})
	if err != nil || healthy.OverallStatus != domain.ResourceStatusHealthy {
		t.Fatalf("healthy status=%#v error=%v", healthy, err)
	}
	if slices.Contains(healthy.AllowedActions, domain.ResourceActionStop) {
		t.Fatal("published local resource exposed standalone stop action")
	}

	tailnet := recoveryTailnetResource()
	tailnet.PublicationRecord.State = domain.PublicationPublished
	tailnet.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{Kind: domain.PublicationTemporaryHTTP}
	clientDigest := recoveryDigest("client")
	localDigest := recoveryDigest("local")
	connectorIdentity := domain.TailnetConnectorIdentity("https://control.example.test", "1.0", clientDigest, localDigest)
	routeIdentity := domain.TailnetRouteIdentity(connectorIdentity, "100.64.0.2", "100.64.0.1", 8080)
	connector := &domain.ConnectorObservation{ControlURL: "https://control.example.test", ClientVersion: "1.0", ClientIdentityDigest: clientDigest, LocalIdentityDigest: localDigest, Validity: domain.ConnectorObservationFresh, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
	offline := false
	route := &domain.RouteEvidence{PeerIP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080, PeerOnline: &offline, ConnectorIdentityDigest: connectorIdentity, RouteIdentity: routeIdentity, Validity: domain.EvidenceUnreachable, ObservedAt: now, ValidUntil: now, Failure: domain.FailurePeerOffline}
	unreachable, err := ProjectObservedResourceStatus(tailnet, now, ResourceStatusEvidence{NginxHealthy: true, ManifestContains: true, ConnectorObservation: connector, RouteEvidence: route})
	if err != nil || unreachable.OverallStatus != domain.ResourceStatusUnreachable || unreachable.RouteStatus != domain.EvidenceUnreachable || unreachable.RouteEvidence == nil || unreachable.RouteEvidence.PeerOnline == nil || *unreachable.RouteEvidence.PeerOnline {
		t.Fatalf("unreachable status=%#v error=%v", unreachable, err)
	}
	bound, err := ProjectObservedResourceStatus(tailnet, now, ResourceStatusEvidence{ConnectorBindingStatus: domain.ConnectorBindingBound})
	if err != nil || bound.ConnectorBindingStatus != domain.ConnectorBindingBound {
		t.Fatalf("connector binding status=%#v error=%v", bound, err)
	}

	tailnetClosed := recoveryTailnetResource()
	closedTailnet, err := ProjectObservedResourceStatus(tailnetClosed, now, ResourceStatusEvidence{NginxHealthy: true})
	if err != nil || closedTailnet.OverallStatus != domain.ResourceStatusClosed || !slices.Contains(closedTailnet.AllowedActions, domain.ResourceActionDelete) {
		t.Fatalf("tailnet closure status=%#v error=%v", closedTailnet, err)
	}

	fenced := recoveryLocalResource(t)
	fenced.PublicationRecord.State = domain.PublicationPublished
	fenced.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{Kind: domain.PublicationTemporaryHTTP, ConfigDigest: fenced.CurrentConfigDigest}
	fenced.PublicationRecord.LastAppliedDigest = &fenced.CurrentConfigDigest
	fenced.ManagedProcess.Requested = domain.ProcessRequestedRunning
	fencedStatus, err := ProjectObservedResourceStatus(fenced, now, ResourceStatusEvidence{NginxFailure: domain.FailurePublication, NginxFenced: true, ProcessStatus: domain.ProcessRunning})
	if err != nil || fencedStatus.PublicationStatus != domain.PublicationStatusFenced || !slices.Equal(fencedStatus.AllowedActions, []domain.ResourceAction{domain.ResourceActionRefresh}) {
		t.Fatalf("fenced status=%#v error=%v", fencedStatus, err)
	}

	drift := recoveryLocalResource(t)
	drift.PublicationRecord.State = domain.PublicationPublished
	drift.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{Kind: domain.PublicationTemporaryHTTP, ConfigDigest: recoveryDigest("prior-config")}
	drift.PublicationRecord.LastAppliedDigest = &drift.PublicationRecord.LastAppliedBundle.ConfigDigest
	drift.ManagedProcess.Requested = domain.ProcessRequestedRunning
	driftStatus, err := ProjectObservedResourceStatus(drift, now, ResourceStatusEvidence{NginxHealthy: true, ManifestContains: true, ProcessStatus: domain.ProcessRunning, TargetObservation: healthyLocalTarget})
	if err != nil || driftStatus.OverallStatus != domain.ResourceStatusUnknown || slices.Contains(driftStatus.AllowedActions, domain.ResourceActionRepublish) {
		t.Fatalf("drift status=%#v error=%v", driftStatus, err)
	}
}

func TestTypedTargetStatusPreservesPartialProbeEvidence(t *testing.T) {
	now := time.Now().UTC()
	resource := recoveryLocalResource(t)
	resource.Target.WebSocket.Enabled = true

	httpFailure := targetObservationFromEvidence(resource, "", target.Evidence{HTTPStatus: 503, ObservedAt: now}, now, domain.FailureHTTPStatus)
	if !httpFailure.PortConnected || httpFailure.HTTPReady || httpFailure.HTTPStatus != 503 || httpFailure.WebSocketReady || httpFailure.Validity != domain.EvidenceUnreachable || httpFailure.Failure != domain.FailureHTTPStatus {
		t.Fatalf("disallowed HTTP evidence was not preserved: %#v", httpFailure)
	}

	webSocketFailure := targetObservationFromEvidence(resource, "", target.Evidence{HTTPStatus: 204, WebSocketStatus: 503, ObservedAt: now}, now, domain.FailureWebSocket)
	if !webSocketFailure.PortConnected || !webSocketFailure.HTTPReady || webSocketFailure.HTTPStatus != 204 || webSocketFailure.WebSocketReady || webSocketFailure.Failure != domain.FailureWebSocket {
		t.Fatalf("partial HTTP readiness was not preserved after WebSocket failure: %#v", webSocketFailure)
	}

	noResponse := targetObservationFromEvidence(resource, "", target.Evidence{}, now, domain.FailureTargetDown)
	if noResponse.PortConnected || noResponse.HTTPReady || noResponse.HTTPStatus != 0 {
		t.Fatalf("no-response probe was reported as connected: %#v", noResponse)
	}

	invalidStatus := targetObservationFromEvidence(resource, "", target.Evidence{HTTPStatus: 700, ObservedAt: now}, now, domain.FailureHTTPStatus)
	if !invalidStatus.PortConnected || invalidStatus.HTTPReady || invalidStatus.HTTPStatus != 0 {
		t.Fatalf("out-of-contract HTTP status was projected: %#v", invalidStatus)
	}
}

func TestTypedStatusPreservesTerminalJobEvidence(t *testing.T) {
	now := time.Now().UTC()
	resource := recoveryTailnetResource()
	jobID := "job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, test := range []struct {
		name   string
		result domain.OperationResult
		error  string
	}{
		{name: "succeeded", result: domain.OperationSucceeded},
		{name: "failed", result: domain.OperationFailed, error: "preflight_rejected"},
		{name: "partial", result: domain.OperationPartial, error: "temporary_http_activation_recovery"},
		{name: "interrupted", result: domain.OperationInterrupted, error: "headscale_lifecycle_interrupted"},
		{name: "unknown", result: domain.OperationUnknown, error: "goaccess_retirement_recovery"},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, err := ProjectObservedResourceStatus(resource, now, ResourceStatusEvidence{JobID: jobID, JobResult: test.result, JobErrorCode: domain.JobErrorCode(test.error)})
			if err != nil {
				t.Fatal(err)
			}
			if status.JobID != jobID || status.JobResult != test.result || status.JobErrorCode != domain.JobErrorCode(test.error) || status.JobPending {
				t.Fatalf("terminal job evidence was not projected: %#v", status)
			}
		})
	}

	pending, err := ProjectObservedResourceStatus(resource, now, ResourceStatusEvidence{JobID: jobID, JobPending: true})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.JobPending || pending.JobResult != "" || pending.JobErrorCode != "" {
		t.Fatalf("pending job retained terminal evidence: %#v", pending)
	}

	fallback := recoveryTailnetResource()
	fallback.PublicationRecord.LastOperation = domain.OperationPublish
	fallback.PublicationRecord.LastJobID = jobID
	fallback.PublicationRecord.LastOperationResult = domain.OperationSucceeded
	fallbackStatus, err := ProjectResourceStatus(fallback, now)
	if err != nil || fallbackStatus.JobResult != domain.OperationSucceeded || fallbackStatus.JobID != jobID {
		t.Fatalf("durable resource result was not retained: %#v, %v", fallbackStatus, err)
	}

	terminal := jobs.Record{SchemaVersion: jobs.SchemaVersion, ID: jobID, Operation: string(domain.OperationPublish), Target: "resource/" + resource.ID, ActorIdentity: "test", StartedAt: now.Add(-time.Minute), Status: jobs.StatusTerminal, Result: jobs.ResultPartial, ModifiedPaths: []string{}, Postconditions: []jobs.Postcondition{{Kind: "recovery", Status: jobs.PostconditionKnown, Identity: resource.ID}}, ErrorCode: "temporary_http_activation_recovery"}
	ended := now.Add(-time.Second)
	terminal.EndedAt = &ended
	raw, err := persist.EncodeEntry(terminal)
	if err != nil {
		t.Fatal(err)
	}
	resource.PublicationRecord.LastJobID = jobID
	resource.PublicationRecord.LastOperation = domain.OperationPublish
	pendingObserved, observedID, observedOperation, observedResult, observedError := observeResourceJob(persist.Document{Entries: map[string]json.RawMessage{"jobs/" + jobID: raw}}, resource)
	if pendingObserved || observedID != jobID || observedOperation != domain.OperationPublish || observedResult != domain.OperationPartial || observedError != domain.JobErrorCode(terminal.ErrorCode) {
		t.Fatalf("durable job evidence was not observed: %v %q %q %q %q", pendingObserved, observedID, observedOperation, observedResult, observedError)
	}
}

func TestResourceDependencyStatusExposesBoundAndAvailableNonSecrets(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", CredentialIDs: []string{"cred_00000000000000000000000000000001"}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CredentialID: "cred_00000000000000000000000000000001", StaticRootID: "static_00000000000000000000000000000001", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000002"}}}}
	installation := domain.Installation{Credentials: []domain.Credential{{ID: "cred_00000000000000000000000000000001", Kind: "managed_basic", OwnerResourceID: resource.ID, Fingerprint: recoveryDigest("basic")}, {ID: "cred_00000000000000000000000000000002", Kind: "external_htpasswd", OwnerResourceID: resource.ID, Fingerprint: recoveryDigest("htpasswd")}, {ID: "cred_00000000000000000000000000000003", Kind: "external_htpasswd", OwnerResourceID: resource.ID, Fingerprint: recoveryDigest("available")}}, StaticRoots: []domain.StaticContentRoot{{ID: "static_00000000000000000000000000000001", OwnerResourceID: resource.ID, Fingerprint: recoveryDigest("static")}}}
	dependencies := resourceDependencyStatuses(installation, resource)
	if len(dependencies) != 4 || dependencies[0].Kind != domain.DependencyExternalHTPasswd || dependencies[0].State != domain.DependencyBound || dependencies[1].Kind != domain.DependencyExternalHTPasswd || dependencies[1].State != domain.DependencyAvailable || dependencies[2].Kind != domain.DependencyManagedBasic || dependencies[2].State != domain.DependencyBound || dependencies[3].Kind != domain.DependencyStaticRoot || dependencies[3].State != domain.DependencyBound {
		t.Fatalf("unexpected dependency projection: %#v", dependencies)
	}
	for _, dependency := range dependencies {
		if dependency.OwnerResourceID != resource.ID || dependency.Fingerprint == "" {
			t.Fatalf("dependency omitted authority identity: %#v", dependency)
		}
	}
}

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
