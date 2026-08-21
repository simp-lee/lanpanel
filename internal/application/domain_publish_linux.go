//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/target"
	"reflect"
	"time"
)

func CurrentPublicationKind(target string) (domain.PublicationKind, error) {
	resourceID, ok := parseResourceTarget(target)
	if !ok {
		return "", fmt.Errorf("publication target invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return "", err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return "", err
	}
	_, resource, err := loadCertificateResource(document.Entries, resourceID)
	if err != nil {
		return "", err
	}
	return resource.Publication.Kind, nil
}

func parseResourceTarget(target string) (string, bool) {
	const prefix = "resource/"
	if len(target) != len(prefix)+36 || target[:len(prefix)] != prefix {
		return "", false
	}
	return target[len(prefix):], true
}

func (execution *CertificateExecution) PrepareDomainPublication(ctx context.Context, certificate domain.CertificateBundleIdentity) (*PublicationExecution, error) {
	document, err := execution.Service.normal.Read()
	if err != nil {
		return nil, err
	}
	installation, resource, err := loadCertificateResource(document.Entries, execution.Resource.ID)
	if err != nil {
		return nil, err
	}
	if err := requireAppliedDomainSourcesHealthy(resource); err != nil {
		return nil, err
	}
	if resource.CurrentConfigDigest != execution.Challenge.Safety.ConfigDigest {
		return nil, fmt.Errorf("domain publication config changed")
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return nil, err
	}
	safetyMatched := false
	for _, authority := range state.Resources {
		if authority.ResourceID == resource.ID && authority.GenerationSequence == execution.Challenge.Safety.Generation && authority.ChallengePending != nil && reflect.DeepEqual(*authority.ChallengePending, execution.Challenge.Safety) {
			safetyMatched = true
		}
	}
	if !safetyMatched {
		return nil, fmt.Errorf("domain publication challenge safety changed")
	}
	request, result, err := evaluateDomainPreflight(ctx, installation, resource, state)
	if err != nil {
		return nil, err
	}
	ready, err := probeResourceTarget(ctx, resource)
	if err != nil {
		return nil, err
	}
	_, bindingDigest, err := candidateACMEBinding(resource)
	if err != nil {
		return nil, err
	}
	sourceEvidence, err := observeDomainSources(execution.Service, resource)
	if err != nil {
		return nil, err
	}
	if !domainPublicationPlanMatches(execution.Plan, resource, result, ready, bindingDigest, sourceEvidence) {
		return nil, fmt.Errorf("domain publication Plan binding changed")
	}
	if request.Generation != resource.PublicationRecord.UnpublishedGeneration {
		return nil, fmt.Errorf("domain publication preflight generation changed")
	}
	candidate, err := prepareDomainCandidate(execution.Service, resource, execution.Challenge.Safety.Generation, certificate)
	if err != nil {
		return nil, err
	}
	execution.Resource = resource
	return execution.ContinueDomainPublication(ctx, candidate)
}

func domainPublicationPlanMatches(plan plans.Plan, resource domain.AppResource, result preflight.Result, ready target.Evidence, acmeDigest string, sourceEvidence plans.Evidence) bool {
	if preflight.ValidateFreshResult(result, time.Now().UTC()) != nil {
		return false
	}
	preflightEvidence, err := result.PlanEvidence()
	if err != nil {
		return false
	}
	matchedPreflight, matchedReadiness, matchedACME, matchedSources := false, false, false, false
	for _, evidence := range plan.Evidence {
		switch {
		case evidence.Kind == preflightEvidence.Kind && evidence.Identity == preflightEvidence.Identity && evidence.Generation == preflightEvidence.Generation && evidence.Digest == preflightEvidence.Digest:
			preflightEvidence.ObservedAt = evidence.ObservedAt
			matchedPreflight = true
		case evidence.Kind == "target_readiness" && evidence.Identity == "resource/"+resource.ID && evidence.Generation == targetEvidenceGeneration(resource) && evidence.Digest == ready.Digest:
			ready.ObservedAt = evidence.ObservedAt
			matchedReadiness = true
		case evidence.Kind == "acme_binding" && evidence.Identity == "resource/"+resource.ID && evidence.Digest == acmeDigest:
			matchedACME = true
		case evidence.Kind == sourceEvidence.Kind && evidence.Identity == sourceEvidence.Identity && evidence.Generation == sourceEvidence.Generation && evidence.Digest == sourceEvidence.Digest:
			sourceEvidence.ObservedAt = evidence.ObservedAt
			matchedSources = true
		}
	}
	if !matchedPreflight || !matchedReadiness || !matchedACME || !matchedSources {
		return false
	}
	binding := plans.Binding{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: plan.ActorIdentity, Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, Evidence: []plans.Evidence{preflightEvidence, {Kind: "target_readiness", Identity: "resource/" + resource.ID, Generation: targetEvidenceGeneration(resource), Digest: ready.Digest, ObservedAt: ready.ObservedAt}, {Kind: "acme_binding", Identity: "resource/" + resource.ID, Generation: executionGeneration(plan), Digest: acmeDigest, ObservedAt: plan.CreatedAt}, sourceEvidence}}
	if resource.PublicationRecord.LastAppliedDigest != nil {
		binding.Applied = plans.DigestBinding{Applicable: true, Digest: *resource.PublicationRecord.LastAppliedDigest}
	}
	expected := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
	for index := range binding.Evidence {
		for _, source := range plan.Evidence {
			if source.Kind == binding.Evidence[index].Kind && source.Identity == binding.Evidence[index].Identity {
				binding.Evidence[index].Generation = source.Generation
				binding.Evidence[index].ObservedAt = source.ObservedAt
			}
		}
	}
	return plans.SameBindingIdentity(expected, binding)
}

func executionGeneration(plan plans.Plan) uint64 {
	for _, evidence := range plan.Evidence {
		if evidence.Kind == "acme_binding" {
			return evidence.Generation
		}
	}
	return 0
}
