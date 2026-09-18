//go:build linux

package ui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/application"
	"lanpanel/internal/audit"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/jobs"
	"lanpanel/internal/session"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type playwrightCredential struct {
	token       string
	fingerprint string
}

type playwrightVerifier struct {
	current atomic.Pointer[playwrightCredential]
}

func (value *playwrightVerifier) set(token, fingerprint string) {
	value.current.Store(&playwrightCredential{token: token, fingerprint: fingerprint})
}

func (value *playwrightVerifier) Verify(_ context.Context, token []byte) (string, error) {
	current := value.current.Load()
	if current == nil || string(token) != current.token {
		return "", fmt.Errorf("invalid token")
	}
	return current.fingerprint, nil
}

func (value *playwrightVerifier) Source(context.Context) (string, error) {
	current := value.current.Load()
	if current == nil {
		return "", fmt.Errorf("token unavailable")
	}
	return current.fingerprint, nil
}

type playwrightProfile struct{}

type playwrightActionBarrier struct {
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

func newPlaywrightActionBarrier() *playwrightActionBarrier {
	return &playwrightActionBarrier{started: make(chan struct{}), release: make(chan struct{})}
}

func (barrier *playwrightActionBarrier) wait(ctx context.Context) error {
	barrier.startOnce.Do(func() { close(barrier.started) })
	select {
	case <-barrier.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (barrier *playwrightActionBarrier) unblock() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

func (playwrightProfile) Current(context.Context) (Profile, error) { return ProfileNormal, nil }

const (
	playwrightLocalResourceID   = "res_00000000000000000000000000000001"
	playwrightTailnetResourceID = "res_00000000000000000000000000000002"
)

type playwrightFixtureCounters struct {
	processStart      atomic.Int32
	processStop       atomic.Int32
	acmeRequests      atomic.Int32
	dnsRequests       atomic.Int32
	tailscaleCommands atomic.Int32
	remoteCommands    atomic.Int32
	connectorLogins   atomic.Int32
	connectorVerifies atomic.Int32
}

func (counters *playwrightFixtureCounters) reset() {
	counters.processStart.Store(0)
	counters.processStop.Store(0)
	counters.acmeRequests.Store(0)
	counters.dnsRequests.Store(0)
	counters.tailscaleCommands.Store(0)
	counters.remoteCommands.Store(0)
	counters.connectorLogins.Store(0)
	counters.connectorVerifies.Store(0)
}

type playwrightFixtureResource struct {
	id             string
	name           string
	kind           domain.AppTargetKind
	configuration  *domain.ResourceStatusConfiguration
	processRunning bool
	published      bool
	lastOperation  domain.OperationCode
	jobID          string
}

type playwrightFixtureBackend struct {
	mu        sync.Mutex
	resources map[string]*playwrightFixtureResource
	jobs      map[string]jobs.Record
	nextID    int
	scenario  string
	counters  playwrightFixtureCounters
	barrier   *playwrightActionBarrier
	verifier  *playwrightVerifier
}

var (
	_ application.ResourceStatusReadModel = (*playwrightFixtureBackend)(nil)
	_ application.ResourceProbe           = (*playwrightFixtureBackend)(nil)
	_ application.JobReadModel            = (*playwrightFixtureBackend)(nil)
	_ application.SideEffectCounter       = (*playwrightFixtureBackend)(nil)
)

func fixturePublication(domainName string) domain.AppPublication {
	return domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: domainName, AccessMode: domain.AppAccessPublic}}
}

func fixtureLocalConfiguration(name string) *domain.ResourceStatusConfiguration {
	return &domain.ResourceStatusConfiguration{TargetKind: domain.AppTargetLocalHTTP, Local: &domain.LocalResourceUpdateRequest{Name: name, EndpointKind: domain.LocalEndpointUnixSocketActivation, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, WebSocket: domain.WebSocketReadiness{}, Executable: "/usr/local/bin/fixture-app", WorkingDirectory: "/srv/fixture-app", WritePaths: []string{}, Publication: fixturePublication("fixture.example.test")}}
}

func fixtureTailnetConfiguration(name string) *domain.ResourceStatusConfiguration {
	return &domain.ResourceStatusConfiguration{TargetKind: domain.AppTargetTailnetHTTP, Tailnet: &domain.TailnetResourceUpdateRequest{Name: name, PeerIP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, WebSocket: domain.WebSocketReadiness{}, Publication: fixturePublication("fixture.example.test")}}
}

func newPlaywrightFixtureBackend() *playwrightFixtureBackend {
	backend := &playwrightFixtureBackend{}
	backend.reset()
	return backend
}

func (backend *playwrightFixtureBackend) reset() {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.resources = map[string]*playwrightFixtureResource{
		playwrightLocalResourceID:   {id: playwrightLocalResourceID, name: "Fixture local", kind: domain.AppTargetLocalHTTP, configuration: fixtureLocalConfiguration("Fixture local")},
		playwrightTailnetResourceID: {id: playwrightTailnetResourceID, name: "Fixture tailnet", kind: domain.AppTargetTailnetHTTP, configuration: fixtureTailnetConfiguration("Fixture tailnet")},
	}
	backend.jobs = map[string]jobs.Record{}
	backend.nextID = 3
	backend.scenario = "default"
	backend.counters.reset()
}

func (backend *playwrightFixtureBackend) setScenario(scenario string) error {
	switch scenario {
	case "default", "tailnet-ready", "tailnet-connector-failure", "tailnet-route-failure", "tailnet-target-failure", "tailnet-revalidation-failure", "create-preflight-failure", "update-preflight-failure":
	default:
		return fmt.Errorf("unknown fixture scenario")
	}
	backend.mu.Lock()
	backend.scenario = scenario
	backend.mu.Unlock()
	return nil
}

func fixtureDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fixtureJobID(seed string) string {
	return "job_" + strings.TrimPrefix(fixtureDigest(seed), "sha256:")
}

func fixtureIdentity(seed string) string { return fixtureDigest(seed) }

func fixtureConnector(now time.Time) *domain.ConnectorObservation {
	return &domain.ConnectorObservation{
		ControlURL:           "https://connector.example.test",
		ClientVersion:        "fixture-1.0",
		ClientIdentityDigest: fixtureIdentity("client"),
		LocalIdentityDigest:  fixtureIdentity("local"),
		Validity:             domain.ConnectorObservationFresh,
		ObservedAt:           now.Add(-time.Second),
		ValidUntil:           now.Add(time.Minute),
	}
}

func fixtureRoute(connector *domain.ConnectorObservation, now time.Time) *domain.RouteEvidence {
	connectorID := domain.TailnetConnectorIdentity(connector.ControlURL, connector.ClientVersion, connector.ClientIdentityDigest, connector.LocalIdentityDigest)
	return &domain.RouteEvidence{
		PeerIP:                  "100.64.0.2",
		SourceIP:                "100.64.0.1",
		Port:                    8080,
		ConnectorIdentityDigest: connectorID,
		RouteIdentity:           domain.TailnetRouteIdentity(connectorID, "100.64.0.2", "100.64.0.1", 8080),
		Validity:                domain.EvidenceFresh,
		ObservedAt:              now.Add(-time.Second),
		ValidUntil:              now.Add(time.Minute),
		Failure:                 domain.FailureNone,
	}
}

func fixtureStatus(resource playwrightFixtureResource, scenario string) domain.ResourceStatusResult {
	now := time.Now().UTC()
	configDigest := fixtureDigest(resource.id + ":config")
	status := domain.ResourceStatusResult{
		ResourceID:          resource.id,
		Name:                resource.name,
		TargetKind:          resource.kind,
		OverallStatus:       domain.ResourceStatusUnknown,
		ConfigurationStatus: domain.ConfigurationComplete,
		PublicationStatus:   domain.PublicationStatusUnpublished,
		FailureCategory:     domain.FailureEvidenceMissing,
		TargetStatus:        domain.EvidenceUnknown,
		AffectedObject:      "resource/" + resource.id,
		NextStep:            "refresh status and resolve missing, stale, or conflicting evidence",
		ConfigDigest:        configDigest,
		AuthorityDigest:     domain.ResourceStatusAuthorityDigest(resource.id, configDigest),
		ObservedAt:          now,
		TargetObservation:   &domain.TargetObservation{Validity: domain.EvidenceUnknown, ObservedAt: now, Failure: domain.FailureEvidenceMissing},
		LastOperation:       resource.lastOperation,
		JobID:               resource.jobID,
		Configuration:       resource.configuration,
	}
	if resource.kind == domain.AppTargetLocalHTTP {
		status.ProcessRequestedStatus = domain.ProcessRequestedStop
		status.ProcessObservedStatus = domain.ProcessStopped
		status.ProcessStatus = domain.ProcessStopped
		if resource.processRunning {
			status.ProcessRequestedStatus = domain.ProcessRequestedRun
			status.ProcessObservedStatus = domain.ProcessRunning
			status.ProcessStatus = domain.ProcessRunning
		}
		status.ConnectorStatus = domain.EvidenceNotApplicable
		status.RouteStatus = domain.EvidenceNotApplicable
		if resource.published {
			status.PublicationStatus = domain.PublicationStatusPublished
			status.OverallStatus = domain.ResourceStatusHealthy
			status.FailureCategory = domain.FailureNone
			status.TargetStatus = domain.EvidenceFresh
			status.TargetObservation = &domain.TargetObservation{PortConnected: true, HTTPReady: true, HTTPStatus: 200, Validity: domain.EvidenceFresh, ObservedAt: now, Failure: domain.FailureNone}
			status.NextStep = "no action is required; refresh status to recheck evidence"
			status.AllowedActions = []domain.ResourceAction{domain.ResourceActionEdit, domain.ResourceActionRefresh, domain.ResourceActionUnpublish}
		} else if !resource.processRunning {
			status.OverallStatus = domain.ResourceStatusClosed
			status.FailureCategory = domain.FailureNone
			status.ClosureVerified = true
			status.ClosureDigest = fixtureDigest(resource.id + ":closed")
			status.ClosureObservedAt = now
			status.NextStep = "resource is closed; start or publish explicitly when ready"
			status.AllowedActions = []domain.ResourceAction{domain.ResourceActionDelete, domain.ResourceActionEdit, domain.ResourceActionRefresh, domain.ResourceActionStart}
		} else {
			status.TargetStatus = domain.EvidenceFresh
			status.TargetObservation = &domain.TargetObservation{PortConnected: true, HTTPReady: true, HTTPStatus: 200, Validity: domain.EvidenceFresh, ObservedAt: now, Failure: domain.FailureNone}
			status.OverallStatus = domain.ResourceStatusUnknown
			status.AllowedActions = []domain.ResourceAction{domain.ResourceActionEdit, domain.ResourceActionRefresh}
		}
		return status
	}

	status.ProcessRequestedStatus = domain.ProcessNotApplicable
	status.ProcessObservedStatus = domain.ProcessNotApplicable
	status.ProcessStatus = domain.ProcessNotApplicable
	status.TargetPeerIP = "100.64.0.2"
	status.TargetSourceIP = "100.64.0.1"
	status.TargetPort = 8080
	status.ConnectorObservation = &domain.ConnectorObservation{Validity: domain.ConnectorObservationMissing}
	status.ConnectorStatus = domain.EvidenceUnverified
	status.RouteEvidence = &domain.RouteEvidence{PeerIP: status.TargetPeerIP, SourceIP: status.TargetSourceIP, Port: status.TargetPort, Validity: domain.EvidenceUnverified, Failure: domain.FailureEvidenceMissing}
	status.RouteStatus = domain.EvidenceUnverified
	status.TargetObservation = &domain.TargetObservation{RouteIdentity: "", Validity: domain.EvidenceUnknown, ObservedAt: now, Failure: domain.FailureEvidenceMissing}
	if scenario == "tailnet-ready" || resource.published && scenario == "default" {
		connector := fixtureConnector(now)
		route := fixtureRoute(connector, now)
		status.ConnectorObservation = connector
		status.ConnectorStatus = domain.EvidenceFresh
		status.RouteEvidence = route
		status.RouteStatus = domain.EvidenceFresh
		status.TargetObservation = &domain.TargetObservation{RouteIdentity: route.RouteIdentity, PortConnected: true, HTTPReady: true, HTTPStatus: 200, Validity: domain.EvidenceFresh, ObservedAt: now, Failure: domain.FailureNone}
		status.TargetStatus = domain.EvidenceFresh
		status.FailureCategory = domain.FailureNone
	}
	if resource.published {
		status.PublicationStatus = domain.PublicationStatusPublished
	}
	switch scenario {
	case "tailnet-connector-failure":
		if resource.published {
			status.OverallStatus = domain.ResourceStatusUnreachable
			status.FailureCategory = domain.FailureConnectorDown
			status.ConnectorStatus = domain.EvidenceUnreachable
			status.ConnectorObservation = &domain.ConnectorObservation{Validity: domain.ConnectorObservationMissing}
			status.RouteStatus = domain.EvidenceUnverified
			status.RouteEvidence = &domain.RouteEvidence{PeerIP: status.TargetPeerIP, SourceIP: status.TargetSourceIP, Port: status.TargetPort, Validity: domain.EvidenceUnverified, Failure: domain.FailureEvidenceMissing}
			status.TargetStatus = domain.EvidenceUnknown
			status.TargetObservation = &domain.TargetObservation{Validity: domain.EvidenceUnknown, ObservedAt: now, Failure: domain.FailureEvidenceMissing}
		}
	case "tailnet-route-failure":
		if resource.published {
			connector := fixtureConnector(now)
			route := fixtureRoute(connector, now)
			route.Validity = domain.EvidenceUnreachable
			route.ValidUntil = now
			route.Failure = domain.FailureRouteDown
			status.OverallStatus = domain.ResourceStatusUnreachable
			status.FailureCategory = domain.FailureRouteDown
			status.ConnectorObservation = connector
			status.ConnectorStatus = domain.EvidenceFresh
			status.RouteEvidence = route
			status.RouteStatus = domain.EvidenceUnreachable
			status.TargetStatus = domain.EvidenceUnknown
			status.TargetObservation = &domain.TargetObservation{Validity: domain.EvidenceUnknown, ObservedAt: now, Failure: domain.FailureEvidenceMissing}
		}
	case "tailnet-target-failure", "tailnet-revalidation-failure":
		if resource.published {
			connector := fixtureConnector(now)
			route := fixtureRoute(connector, now)
			status.OverallStatus = domain.ResourceStatusUnreachable
			status.FailureCategory = domain.FailureTargetDown
			status.ConnectorObservation = connector
			status.ConnectorStatus = domain.EvidenceFresh
			status.RouteEvidence = route
			status.RouteStatus = domain.EvidenceFresh
			status.TargetStatus = domain.EvidenceUnreachable
			status.TargetObservation = &domain.TargetObservation{RouteIdentity: route.RouteIdentity, Validity: domain.EvidenceUnreachable, ObservedAt: now, Failure: domain.FailureTargetDown}
		}
	}
	if resource.published && status.OverallStatus == domain.ResourceStatusUnknown {
		if status.TargetStatus == domain.EvidenceFresh {
			status.OverallStatus = domain.ResourceStatusHealthy
			status.NextStep = "no action is required; refresh status to recheck evidence"
		} else {
			status.FailureCategory = domain.FailureEvidenceMissing
		}
	} else if !resource.published && status.ConnectorStatus == domain.EvidenceFresh && status.RouteStatus == domain.EvidenceFresh && status.TargetStatus == domain.EvidenceFresh {
		status.OverallStatus = domain.ResourceStatusClosed
		status.ClosureVerified = true
		status.ClosureDigest = fixtureDigest(resource.id + ":closed")
		status.ClosureObservedAt = now
		status.NextStep = "publish explicitly after fresh connector, route, and target evidence"
		status.AllowedActions = []domain.ResourceAction{domain.ResourceActionDelete, domain.ResourceActionEdit, domain.ResourceActionPublish, domain.ResourceActionRefresh}
	} else if !resource.published {
		status.AllowedActions = []domain.ResourceAction{domain.ResourceActionEdit, domain.ResourceActionRefresh}
	}
	if resource.published {
		status.AllowedActions = []domain.ResourceAction{domain.ResourceActionEdit, domain.ResourceActionRefresh, domain.ResourceActionUnpublish}
		if status.OverallStatus == domain.ResourceStatusHealthy {
			status.AllowedActions = []domain.ResourceAction{domain.ResourceActionEdit, domain.ResourceActionRefresh, domain.ResourceActionRepublish, domain.ResourceActionUnpublish}
		}
	}
	return status
}

func (backend *playwrightFixtureBackend) ResourceStatus(ctx context.Context, id string) (domain.ResourceStatusResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ResourceStatusResult{}, err
	}
	return backend.resourceStatus(id)
}

func (backend *playwrightFixtureBackend) ResourceStatusCatalog(ctx context.Context) (domain.ResourceStatusCatalog, error) {
	if err := ctx.Err(); err != nil {
		return domain.ResourceStatusCatalog{}, err
	}
	return backend.catalog()
}

func (backend *playwrightFixtureBackend) ProbeResource(ctx context.Context, id string) (application.ResourceStatusEvidence, error) {
	status, err := backend.ResourceStatus(ctx, id)
	if err != nil {
		return application.ResourceStatusEvidence{}, err
	}
	evidence := application.ResourceStatusEvidence{ProcessStatus: status.ProcessStatus, ConnectorObservation: status.ConnectorObservation, RouteEvidence: status.RouteEvidence, TargetObservation: status.TargetObservation, JobPending: status.JobPending, JobID: status.JobID, LastOperation: status.LastOperation}
	if status.TargetKind == domain.AppTargetTailnetHTTP && (status.ConnectorStatus != domain.EvidenceFresh || status.RouteStatus != domain.EvidenceFresh || status.TargetStatus != domain.EvidenceFresh) {
		jobID := fixtureJobID("revalidation-" + id)
		backend.mu.Lock()
		backend.recordJobLocked(jobID, string(domain.OperationPublish), "resource/"+id, jobs.ResultFailed, "preflight_rejected")
		backend.mu.Unlock()
		return evidence, application.HelperRejection{Code: "target_preflight_failed", JobID: jobID}
	}
	return evidence, nil
}

func (backend *playwrightFixtureBackend) ListJobs(ctx context.Context) (application.JobsResult, error) {
	if err := ctx.Err(); err != nil {
		return application.JobsResult{}, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	result := application.JobsResult{Jobs: make([]jobs.Record, 0, len(backend.jobs))}
	for _, record := range backend.jobs {
		result.Jobs = append(result.Jobs, record)
	}
	for i := 0; i < len(result.Jobs); i++ {
		for j := i + 1; j < len(result.Jobs); j++ {
			if result.Jobs[j].ID < result.Jobs[i].ID {
				result.Jobs[i], result.Jobs[j] = result.Jobs[j], result.Jobs[i]
			}
		}
	}
	return result, nil
}

func (backend *playwrightFixtureBackend) ReadJob(ctx context.Context, id string) (application.JobResult, error) {
	if err := ctx.Err(); err != nil {
		return application.JobResult{}, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	record, ok := backend.jobs[id]
	if !ok {
		return application.JobResult{}, fmt.Errorf("fixture Job does not exist")
	}
	return application.JobResult{Job: record}, nil
}

func (backend *playwrightFixtureBackend) recordJobLocked(id, operation, target string, result jobs.Result, errorCode string) {
	started := time.Now().UTC()
	ended := started
	record := jobs.Record{SchemaVersion: jobs.SchemaVersion, ID: id, Operation: operation, Target: target, ActorIdentity: "fixture/ui", StartedAt: started, EndedAt: &ended, Status: jobs.StatusTerminal, Result: result, ModifiedPaths: []string{}, Postconditions: []jobs.Postcondition{{Kind: "fixture", Status: jobs.PostconditionVerified, Identity: target}}, ErrorCode: errorCode}
	if err := jobs.Validate(record); err != nil {
		panic(err)
	}
	backend.jobs[id] = record
}

func (backend *playwrightFixtureBackend) SideEffectCounts(ctx context.Context) (application.SideEffectCounts, error) {
	if err := ctx.Err(); err != nil {
		return application.SideEffectCounts{}, err
	}
	return application.SideEffectCounts{
		ProcessStart:      backend.counters.processStart.Load(),
		ProcessStop:       backend.counters.processStop.Load(),
		ACMERequests:      backend.counters.acmeRequests.Load(),
		DNSRequests:       backend.counters.dnsRequests.Load(),
		TailscaleCommands: backend.counters.tailscaleCommands.Load(),
		RemoteCommands:    backend.counters.remoteCommands.Load(),
		ConnectorLogins:   backend.counters.connectorLogins.Load(),
		ConnectorVerifies: backend.counters.connectorVerifies.Load(),
	}, nil
}

func (backend *playwrightFixtureBackend) resourceStatus(id string) (domain.ResourceStatusResult, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	resource := backend.resources[id]
	if resource == nil {
		return domain.ResourceStatusResult{}, fmt.Errorf("resource does not exist")
	}
	status := fixtureStatus(*resource, backend.scenario)
	if err := domain.ValidateResourceStatusResult(status); err != nil {
		return domain.ResourceStatusResult{}, err
	}
	return status, nil
}

func (backend *playwrightFixtureBackend) catalog() (domain.ResourceStatusCatalog, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	catalog := domain.ResourceStatusCatalog{InstallationID: "ins_00000000000000000000000000000001", Resources: []domain.ResourceStatusResult{}}
	for _, resource := range backend.resources {
		status := fixtureStatus(*resource, backend.scenario)
		if err := domain.ValidateResourceStatusResult(status); err != nil {
			return domain.ResourceStatusCatalog{}, err
		}
		catalog.Resources = append(catalog.Resources, status)
	}
	for i := 0; i < len(catalog.Resources); i++ {
		for j := i + 1; j < len(catalog.Resources); j++ {
			if catalog.Resources[j].ResourceID < catalog.Resources[i].ResourceID {
				catalog.Resources[i], catalog.Resources[j] = catalog.Resources[j], catalog.Resources[i]
			}
		}
	}
	catalog.ObservedAt = time.Now().UTC()
	if err := domain.ValidateResourceStatusCatalog(catalog); err != nil {
		return domain.ResourceStatusCatalog{}, err
	}
	return catalog, nil
}

func (backend *playwrightFixtureBackend) nextResourceID() string {
	id := fmt.Sprintf("res_%032x", backend.nextID)
	backend.nextID++
	return id
}

func (backend *playwrightFixtureBackend) actionPlan(payload helperproto.ActionPayload) *helperproto.ActionResult {
	return &helperproto.ActionResult{
		PlanID:       "plan-" + strings.TrimPrefix(fixtureDigest(payload.Operation+payload.TargetID), "sha256:"),
		Confirmation: fixtureDigest("confirmation:" + payload.Operation + payload.TargetID),
		Operation:    payload.Operation,
		TargetKind:   payload.TargetKind,
		TargetID:     payload.TargetID,
		ExposureSummary: func() string {
			if payload.Operation == "admin_token_rotate" {
				return "admin_token_rotation"
			}
			return "fixture validates the typed action and keeps ingress closed until confirmation"
		}(),
		Prerequisites: func() string {
			if payload.Operation == "admin_token_rotate" {
				return "authenticated_destructive_confirmation"
			}
			return "fresh typed authority and explicit administrator confirmation"
		}(),
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
}

func (backend *playwrightFixtureBackend) applicationCall(_ context.Context, operation helperproto.Operation, payload helperproto.ActionPayload) (application.HelperReply, error) {
	switch operation {
	case helperproto.OperationApplicationPlan:
		return application.HelperReply{Digest: fixtureDigest("plan"), Action: backend.actionPlan(payload)}, nil
	case helperproto.OperationAdminTokenRotate:
		fingerprint := fixtureIdentity("rotated-admin")
		if backend.verifier != nil {
			backend.verifier.set("new-admin-token", fingerprint)
		}
		return application.HelperReply{Digest: fingerprint, Action: &helperproto.ActionResult{JobID: fixtureJobID("admin-rotation")}, Secret: []byte("new-admin-token")}, nil
	case helperproto.OperationDomainStatus:
		status, err := backend.resourceStatus(payload.TargetID)
		if err != nil {
			return application.HelperReply{}, err
		}
		digest, err := domain.ResourceStatusDigest(status)
		if err != nil {
			return application.HelperReply{}, err
		}
		return application.HelperReply{Digest: digest, Status: (*helperproto.ResourceStatusResult)(&status)}, nil
	case helperproto.OperationContractionClose:
		return application.HelperReply{Digest: fixtureDigest("contraction"), Action: &helperproto.ActionResult{JobID: fixtureJobID("contraction"), JobResult: "succeeded", ContractionOutcome: "succeeded", AccessClosed: true}}, nil
	default:
		return application.HelperReply{}, fmt.Errorf("unsupported fixture action %q", operation)
	}
}

func (backend *playwrightFixtureBackend) resourceCall(ctx context.Context, operation helperproto.Operation, payload helperproto.ResourcePayload, target string) (application.HelperReply, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	switch operation {
	case helperproto.OperationHeadscaleInitialize:
		if strings.Contains(string(payload.Resource), `"control_domain":"foreign.example.test"`) {
			return application.HelperReply{}, application.HelperRejection{Code: "foreign_database_evidence", JobID: "job_foreign_headscale_fixture"}
		}
		if strings.Contains(string(payload.Resource), `"control_domain":"blocked.example.test"`) && backend.barrier != nil {
			if err := backend.barrier.wait(ctx); err != nil {
				return application.HelperReply{}, err
			}
		}
		return application.HelperReply{Digest: fixtureDigest("headscale"), Action: &helperproto.ActionResult{JobID: "job-headscale-fixture", Operation: string(domain.OperationHeadscaleInitialize), TargetKind: "installation", TargetID: "hds_00000000000000000000000000000001"}}, nil
	case helperproto.OperationProductRead:
		if payload.Operation != string(domain.OperationStatus) || target != "installation" {
			return application.HelperReply{}, fmt.Errorf("unsupported fixture product read")
		}
		catalog := domain.ResourceStatusCatalog{InstallationID: "ins_00000000000000000000000000000001", Resources: []domain.ResourceStatusResult{}}
		for _, resource := range backend.resources {
			status := fixtureStatus(*resource, backend.scenario)
			if err := domain.ValidateResourceStatusResult(status); err != nil {
				return application.HelperReply{}, err
			}
			catalog.Resources = append(catalog.Resources, status)
		}
		for i := 0; i < len(catalog.Resources); i++ {
			for j := i + 1; j < len(catalog.Resources); j++ {
				if catalog.Resources[j].ResourceID < catalog.Resources[i].ResourceID {
					catalog.Resources[i], catalog.Resources[j] = catalog.Resources[j], catalog.Resources[i]
				}
			}
		}
		catalog.ObservedAt = time.Now().UTC()
		if err := domain.ValidateResourceStatusCatalog(catalog); err != nil {
			return application.HelperReply{}, err
		}
		return application.HelperReply{Digest: func() string { value, _ := domain.ResourceStatusCatalogDigest(catalog); return value }(), StatusCatalog: (*helperproto.ResourceStatusCatalog)(&catalog)}, nil
	case helperproto.OperationResourceMutation:
		if (backend.scenario == "create-preflight-failure" && payload.Create != nil) || (backend.scenario == "update-preflight-failure" && payload.Update != nil) {
			jobID := fixtureJobID("preflight")
			backend.recordJobLocked(jobID, payload.Operation, target, jobs.ResultFailed, "preflight_rejected")
			return application.HelperReply{}, application.HelperRejection{Code: "authoritative_preflight_failed", JobID: jobID}
		}
		if payload.Create != nil {
			id := backend.nextResourceID()
			kind := payload.Create.TargetKind
			name := ""
			if payload.Create.Local != nil {
				name = payload.Create.Local.Name
			} else if payload.Create.Tailnet != nil {
				name = payload.Create.Tailnet.Name
			}
			jobID := fixtureJobID("create-" + id)
			configuration := fixtureTailnetConfiguration(name)
			if payload.Create.Local != nil {
				configuration = &domain.ResourceStatusConfiguration{TargetKind: domain.AppTargetLocalHTTP, Local: &domain.LocalResourceUpdateRequest{Name: payload.Create.Local.Name, EndpointKind: payload.Create.Local.EndpointKind, TCPAddress: payload.Create.Local.TCPAddress, TCPPort: payload.Create.Local.TCPPort, ReadinessPath: payload.Create.Local.ReadinessPath, AllowedHTTPStatuses: append([]uint16(nil), payload.Create.Local.AllowedHTTPStatuses...), WebSocket: payload.Create.Local.WebSocket, Executable: payload.Create.Local.Executable, Arguments: append([]string(nil), payload.Create.Local.Arguments...), WorkingDirectory: payload.Create.Local.WorkingDirectory, EnvironmentFile: payload.Create.Local.EnvironmentFile, WritePaths: append([]string(nil), payload.Create.Local.WritePaths...), Publication: payload.Create.Local.Publication, CredentialIDs: append([]string(nil), payload.Create.Local.CredentialIDs...)}}
			} else if payload.Create.Tailnet != nil {
				configuration = &domain.ResourceStatusConfiguration{TargetKind: domain.AppTargetTailnetHTTP, Tailnet: &domain.TailnetResourceUpdateRequest{Name: payload.Create.Tailnet.Name, PeerIP: payload.Create.Tailnet.PeerIP, SourceIP: payload.Create.Tailnet.SourceIP, Port: payload.Create.Tailnet.Port, ReadinessPath: payload.Create.Tailnet.ReadinessPath, AllowedHTTPStatuses: append([]uint16(nil), payload.Create.Tailnet.AllowedHTTPStatuses...), WebSocket: payload.Create.Tailnet.WebSocket, Publication: payload.Create.Tailnet.Publication, CredentialIDs: append([]string(nil), payload.Create.Tailnet.CredentialIDs...)}}
			}
			backend.resources[id] = &playwrightFixtureResource{id: id, name: name, kind: kind, configuration: configuration, lastOperation: domain.OperationResourceCreate, jobID: jobID}
			backend.recordJobLocked(jobID, string(domain.OperationResourceCreate), "installation", jobs.ResultSucceeded, "")
			return application.HelperReply{Digest: fixtureDigest(id), Resource: &helperproto.ResourceResult{ResourceID: id, JobID: fixtureJobID("create-" + id), JobResult: "succeeded"}}, nil
		}
		if payload.Update != nil {
			id := strings.TrimPrefix(target, "resource/")
			resource := backend.resources[id]
			if resource == nil {
				return application.HelperReply{}, fmt.Errorf("resource does not exist")
			}
			if payload.Update.Local != nil {
				resource.name = payload.Update.Local.Name
				resource.configuration = &domain.ResourceStatusConfiguration{TargetKind: domain.AppTargetLocalHTTP, Local: payload.Update.Local}
			} else if payload.Update.Tailnet != nil {
				resource.name = payload.Update.Tailnet.Name
				resource.configuration = &domain.ResourceStatusConfiguration{TargetKind: domain.AppTargetTailnetHTTP, Tailnet: payload.Update.Tailnet}
			}
			jobID := fixtureJobID("update-" + id)
			resource.lastOperation = domain.OperationResourceUpdate
			resource.jobID = jobID
			backend.recordJobLocked(jobID, string(domain.OperationResourceUpdate), "resource/"+id, jobs.ResultSucceeded, "")
			return application.HelperReply{Digest: fixtureDigest(id + ":update"), Resource: &helperproto.ResourceResult{ResourceID: id, JobID: fixtureJobID("update-" + id), JobResult: "succeeded"}}, nil
		}
		return application.HelperReply{}, fmt.Errorf("fixture mutation is empty")
	case helperproto.OperationProcessLifecycle:
		id := strings.TrimPrefix(target, "resource/")
		resource := backend.resources[id]
		if resource == nil || resource.kind != domain.AppTargetLocalHTTP {
			return application.HelperReply{}, application.HelperRejection{Code: "local_process_only", JobID: fixtureJobID("process")}
		}
		if payload.Operation == string(domain.OperationProcessStart) {
			backend.counters.processStart.Add(1)
			resource.processRunning = true
			resource.lastOperation = domain.OperationProcessStart
			resource.jobID = fixtureJobID("start-" + id)
		} else {
			backend.counters.processStop.Add(1)
			resource.processRunning = false
			resource.lastOperation = domain.OperationProcessStop
			resource.jobID = fixtureJobID("stop-" + id)
		}
		backend.recordJobLocked(resource.jobID, payload.Operation, "resource/"+id, jobs.ResultSucceeded, "")
		return application.HelperReply{Digest: fixtureDigest(resource.jobID), Action: &helperproto.ActionResult{JobID: resource.jobID, Operation: payload.Operation, TargetKind: "resource", TargetID: id}}, nil
	case helperproto.OperationPublicationActivate:
		id := strings.TrimPrefix(target, "resource/")
		resource := backend.resources[id]
		if resource == nil {
			return application.HelperReply{}, fmt.Errorf("resource does not exist")
		}
		resource.published = true
		resource.lastOperation = domain.OperationPublish
		resource.jobID = fixtureJobID("publish-" + id)
		backend.recordJobLocked(resource.jobID, string(domain.OperationPublish), "resource/"+id, jobs.ResultSucceeded, "")
		return application.HelperReply{Digest: fixtureDigest(resource.jobID), Action: &helperproto.ActionResult{JobID: resource.jobID, JobResult: "succeeded", PublicURL: "https://fixture.example.test/" + id}}, nil
	case helperproto.OperationContractionClose:
		id := strings.TrimPrefix(target, "resource/")
		resource := backend.resources[id]
		if resource == nil {
			return application.HelperReply{}, fmt.Errorf("resource does not exist")
		}
		resource.published = false
		resource.lastOperation = domain.OperationUnpublish
		resource.jobID = fixtureJobID("unpublish-" + id)
		backend.recordJobLocked(resource.jobID, string(domain.OperationUnpublish), "resource/"+id, jobs.ResultSucceeded, "")
		return application.HelperReply{Digest: fixtureDigest(resource.jobID), Action: &helperproto.ActionResult{JobID: resource.jobID, JobResult: "succeeded", ContractionOutcome: "succeeded", AccessClosed: true}}, nil
	case helperproto.OperationResourceDelete:
		id := strings.TrimPrefix(target, "resource/")
		if backend.resources[id] == nil {
			return application.HelperReply{}, fmt.Errorf("resource does not exist")
		}
		jobID := fixtureJobID("delete-" + id)
		delete(backend.resources, id)
		backend.recordJobLocked(jobID, string(domain.OperationResourceDelete), "resource/"+id, jobs.ResultSucceeded, "")
		return application.HelperReply{Digest: fixtureDigest("delete-" + id), Action: &helperproto.ActionResult{JobID: jobID}}, nil
	default:
		return application.HelperReply{}, fmt.Errorf("unsupported fixture resource operation %q", operation)
	}
}

func (backend *playwrightFixtureBackend) controlHandler(server *Server, shutdownResponded chan struct{}, actionBarrier *playwrightActionBarrier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/action/started", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		select {
		case <-actionBarrier.started:
			writer.WriteHeader(http.StatusNoContent)
		case <-request.Context().Done():
		}
	})
	mux.HandleFunc("/action/release", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		actionBarrier.unblock()
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/fixture/reset", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		backend.reset()
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/fixture/scenario", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var value struct {
			Scenario string `json:"scenario"`
		}
		if json.NewDecoder(request.Body).Decode(&value) != nil || backend.setScenario(value.Scenario) != nil {
			http.Error(writer, "invalid scenario", http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/fixture/state", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		backend.mu.Lock()
		state := struct {
			Scenario      string   `json:"scenario"`
			ResourceCount int      `json:"resource_count"`
			ResourceIDs   []string `json:"resource_ids"`
		}{Scenario: backend.scenario, ResourceCount: len(backend.resources)}
		for id := range backend.resources {
			state.ResourceIDs = append(state.ResourceIDs, id)
		}
		backend.mu.Unlock()
		for i := 0; i < len(state.ResourceIDs); i++ {
			for j := i + 1; j < len(state.ResourceIDs); j++ {
				if state.ResourceIDs[j] < state.ResourceIDs[i] {
					state.ResourceIDs[i], state.ResourceIDs[j] = state.ResourceIDs[j], state.ResourceIDs[i]
				}
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(state)
	})
	mux.HandleFunc("/fixture/counters", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		counts, err := backend.SideEffectCounts(request.Context())
		if err != nil {
			http.Error(writer, "counter read failed", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(counts)
	})
	mux.HandleFunc("/shutdown", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := server.Shutdown(shutdownContext)
		cancel()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		} else {
			writer.WriteHeader(http.StatusNoContent)
		}
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		close(shutdownResponded)
	})
	return mux
}

func TestPlaywrightFixture(t *testing.T) {
	if os.Getenv("LANPANEL_PLAYWRIGHT_FIXTURE") != "1" {
		t.Skip("browser fixture role is disabled")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := listener.Addr().String()
	fingerprint := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifier := &playwrightVerifier{}
	verifier.set("admin", fingerprint)
	manager, err := session.New(fingerprint, session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	backend := newPlaywrightFixtureBackend()
	backend.verifier = verifier
	actionBarrier := newPlaywrightActionBarrier()
	backend.barrier = actionBarrier
	actions, err := application.HelperServiceWithResourcesAndSeams(backend.applicationCall, backend.resourceCall, application.ReadModelSeams{
		Status:   backend,
		Probe:    backend,
		Jobs:     backend,
		Counters: backend,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Keep the fixture on replaceable typed application/helper seams:
	// status, probe, Job, and side-effect observations remain deterministic and
	// no raw resource JSON or live process/connector boundary is used.
	server, err := New(Config{Listener: listener, Authority: authority, InstallationFingerprint: "0123456789abcdef", Verifier: verifier, Sessions: manager, Profile: playwrightProfile{}, Actions: actions, Audit: audit.NewMemorySink()})
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	shutdownResponded := make(chan struct{})
	controlServer := &http.Server{Handler: backend.controlHandler(server, shutdownResponded, actionBarrier), ReadHeaderTimeout: 5 * time.Second}
	controlDone := make(chan error, 1)
	go func() { controlDone <- controlServer.Serve(controlListener) }()

	fmt.Printf("LANPANEL_FIXTURE_ORIGIN=http://%s\n", authority)
	fmt.Printf("LANPANEL_FIXTURE_CONTROL=http://%s\n", controlListener.Addr().String())
	serveErr := server.Serve()
	if !errors.Is(serveErr, http.ErrServerClosed) {
		t.Fatal(serveErr)
	}
	select {
	case <-shutdownResponded:
	case <-time.After(10 * time.Second):
		t.Fatal("fixture shutdown response did not complete")
	}
	controlContext, cancelControl := context.WithTimeout(context.Background(), 5*time.Second)
	if err := controlServer.Shutdown(controlContext); err != nil {
		cancelControl()
		t.Fatal(err)
	}
	cancelControl()
	if err := <-controlDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}
