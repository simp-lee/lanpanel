//go:build linux

package application

import (
	"context"
	"errors"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/publication"
	"lanpanel/internal/target"
	"testing"
	"time"
)

type publicationFailureHostProbe struct {
	reloadErr     error
	exhaustReload bool
	stopCtxErr    error
	reloads       int
	stops         int
}

func (host *publicationFailureHostProbe) Reload(ctx context.Context) error {
	host.reloads++
	if host.exhaustReload {
		<-ctx.Done()
		return ctx.Err()
	}
	return host.reloadErr
}

func (host *publicationFailureHostProbe) StopAndVerify(ctx context.Context) (closure.RuntimeSnapshot, error) {
	host.stops++
	host.stopCtxErr = ctx.Err()
	return closure.RuntimeSnapshot{}, nil
}

func TestUnstagedRollbackPreservesReusedAppliedGoAccessOwnership(t *testing.T) {
	execution := PublicationExecution{Candidate: publication.Candidate{Generation: 5, Bundle: domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: 4, StateGeneration: 4}}}}}
	if err := execution.rollbackUnstagedGoAccessOwnership(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTemporaryPublicationPlanRequiresFreshEvidenceDigests(t *testing.T) {
	now := time.Now().UTC()
	_, preflightResult := headscaleDeployPreflight(t, now)
	preflightEvidence, err := preflightResult.PlanEvidence()
	if err != nil {
		t.Fatal(err)
	}
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", CurrentConfigDigest: deployTestDigest("config"), PublicationRecord: domain.PublicationRecord{UnpublishedGeneration: 1}, ManagedProcess: &domain.ManagedProcess{Applied: &domain.ProcessBundle{Generation: 1}}}
	ready := target.Evidence{ResourceID: resource.ID, ConfigDigest: resource.CurrentConfigDigest, EndpointIdentity: deployTestDigest("endpoint"), TransportIdentity: deployTestDigest("transport"), HTTPStatus: 200, ObservedAt: now, Digest: deployTestDigest("ready")}
	readinessEvidence := plans.Evidence{Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: 1, Digest: ready.Digest, ObservedAt: now}
	plan := plans.Plan{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: "ui/session/generation/1", Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Evidence: []plans.Evidence{preflightEvidence, readinessEvidence}}
	if !publicationPlanBindingMatches(plan, resource, preflightResult, ready) {
		t.Fatal("exact temporary publication evidence rejected")
	}
	changed := ready
	changed.Digest = deployTestDigest("changed-ready")
	if publicationPlanBindingMatches(plan, resource, preflightResult, changed) {
		t.Fatal("changed target readiness digest retained Plan authority")
	}
	changedResult := preflightResult
	changedResult.Findings = append([]preflight.Finding(nil), preflightResult.Findings...)
	changedResult.Findings[0].Identity = deployTestDigest("changed-preflight")
	if publicationPlanBindingMatches(plan, resource, changedResult, ready) {
		t.Fatal("changed preflight digest retained Plan authority")
	}
}

func TestDomainPublicationPlanAllowsFreshClockObservation(t *testing.T) {
	now := time.Now().UTC()
	_, result := headscaleDeployPreflight(t, now)
	result.Scope = string(preflight.ExpansionDomainHTTPS)
	result.Target = "resource/res_00000000000000000000000000000001"
	result.ObservedAt = now
	result.ValidUntil = now.Add(preflight.MaximumAge)
	preflightEvidence, err := result.PlanEvidence()
	if err != nil {
		t.Fatal(err)
	}
	preflightEvidence.Digest, err = headscalePreflightObservationDigest(result)
	if err != nil {
		t.Fatal(err)
	}
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", CurrentConfigDigest: deployTestDigest("config"), PublicationRecord: domain.PublicationRecord{UnpublishedGeneration: 1}}
	ready := target.Evidence{ResourceID: resource.ID, ConfigDigest: resource.CurrentConfigDigest, Digest: deployTestDigest("ready"), ObservedAt: now}
	source := plans.Evidence{Kind: "domain_sources", Identity: "resource/" + resource.ID, Generation: 1, Digest: deployTestDigest("sources"), ObservedAt: now}
	plan := plans.Plan{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: "ui/session/generation/1", Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Evidence: []plans.Evidence{preflightEvidence, {Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: 0, Digest: ready.Digest, ObservedAt: now}, {Kind: "acme_binding", Identity: "resource/" + resource.ID, Generation: 2, Digest: deployTestDigest("acme"), ObservedAt: now}, source}}
	fresh := result
	fresh.ObservedAt = now.Add(-time.Second)
	fresh.ValidUntil = fresh.ObservedAt.Add(preflight.MaximumAge)
	for index := range fresh.Findings {
		if fresh.Findings[index].Code == "trusted_clock" {
			fresh.Findings[index].Identity = "kernel/" + fresh.ObservedAt.Format(time.RFC3339Nano)
		}
	}
	freshReady := ready
	freshReady.ObservedAt = fresh.ObservedAt
	freshSource := source
	freshSource.ObservedAt = fresh.ObservedAt
	if !domainPublicationPlanMatches(plan, resource, fresh, freshReady, deployTestDigest("acme"), freshSource) {
		t.Fatal("fresh trusted-clock observation invalidated semantic domain publication Plan")
	}
	changed := fresh
	changed.Findings = append([]preflight.Finding(nil), fresh.Findings...)
	changed.Findings[0].Identity = deployTestDigest("changed-preflight")
	if domainPublicationPlanMatches(plan, resource, changed, freshReady, deployTestDigest("acme"), freshSource) {
		t.Fatal("changed domain preflight retained Plan authority")
	}
}

func TestFailedPublicationStopsNginxDespiteReloadOrContractionFailure(t *testing.T) {
	host := &publicationFailureHostProbe{exhaustReload: true}
	_, reloadErr, stopErr := shutdownFailedPublicationRuntime(host, nil, 10*time.Millisecond, time.Second)
	if !errors.Is(reloadErr, context.DeadlineExceeded) || stopErr != nil || host.stopCtxErr != nil || host.reloads != 1 || host.stops != 1 {
		t.Fatalf("reload deadline shutdown evidence: reload=%v stop=%v stop_context=%v calls=%d/%d", reloadErr, stopErr, host.stopCtxErr, host.reloads, host.stops)
	}
	host = &publicationFailureHostProbe{}
	contractErr := errors.New("contract failed")
	_, reloadErr, stopErr = shutdownFailedPublicationRuntime(host, contractErr, time.Second, time.Second)
	if reloadErr != nil || stopErr != nil || host.stopCtxErr != nil || host.reloads != 0 || host.stops != 1 {
		t.Fatalf("contraction failure shutdown evidence: reload=%v stop=%v stop_context=%v calls=%d/%d", reloadErr, stopErr, host.stopCtxErr, host.reloads, host.stops)
	}
}
