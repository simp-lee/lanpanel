//go:build linux

package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"sort"
	"strings"
	"time"
)

type HeadscaleCertificateConfig struct {
	ChallengeMethod     string `json:"challenge_method"`
	DirectoryURL        string `json:"directory_url"`
	AccountEmail        string `json:"account_email"`
	TermsAccepted       bool   `json:"terms_accepted"`
	DNSProvider         string `json:"dns_provider,omitempty"`
	ProviderProfilePath string `json:"provider_profile_path,omitempty"`
	AuthoritativeZone   string `json:"authoritative_zone,omitempty"`
}

type HeadscaleDeployPayload struct {
	PlanID       string                     `json:"plan_id"`
	Confirmation string                     `json:"confirmation"`
	Certificate  HeadscaleCertificateConfig `json:"certificate"`
}
type HeadscaleReissuePayload struct {
	PlanID       string                     `json:"plan_id"`
	Confirmation string                     `json:"confirmation"`
	Certificate  HeadscaleCertificateConfig `json:"certificate"`
}

type HeadscaleDeployAuthority struct {
	Rendered  control.Rendered
	Binding   acme.Binding
	Preflight preflight.ExpansionRequest
	Result    preflight.Result
	Spec      plans.Spec
}

func loadHeadscaleCertificateBinding(request HeadscaleCertificateConfig) (acme.Binding, error) {
	if request.AccountEmail != "" {
		if err := acmeaccount.WriteContact(request.AccountEmail); err != nil {
			return acme.Binding{}, err
		}
	}
	accountContact, accountKeyFingerprint, contactErr := readManagedACMEAccountAuthority()
	if contactErr != nil {
		return acme.Binding{}, contactErr
	}
	method, err := acme.ParseChallengeMethod(request.ChallengeMethod)
	if err != nil {
		return acme.Binding{}, err
	}
	var binding acme.Binding
	if method == acme.ChallengeHTTP01 {
		if request.DNSProvider != "" || request.ProviderProfilePath != "" || request.AuthoritativeZone != "" {
			return acme.Binding{}, fmt.Errorf("HTTP-01 Headscale certificate carries DNS authority")
		}
		binding, err = acme.LoadHTTPBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, accountContact, request.TermsAccepted)
	} else {
		provider, parseErr := acme.ParseDNSProvider(request.DNSProvider)
		if parseErr != nil {
			return acme.Binding{}, parseErr
		}
		binding, err = acme.LoadDNSBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, accountContact, request.TermsAccepted, provider, request.ProviderProfilePath, request.AuthoritativeZone)
	}
	if err != nil {
		return acme.Binding{}, err
	}
	if binding.AccountKeyFingerprint != accountKeyFingerprint {
		return acme.Binding{}, fmt.Errorf("managed ACME account key changed after installation verification")
	}
	return binding, nil
}

func verifyManagedACMEBinding(binding acme.Binding) error {
	contact, fingerprint, err := readManagedACMEAccountAuthority()
	if err != nil {
		return err
	}
	if binding.AccountKeyPath != acmeaccount.ManagedKeyPath || binding.AccountEmail != contact || binding.AccountKeyFingerprint != fingerprint {
		return fmt.Errorf("managed ACME account binding changed")
	}
	if _, err := acme.BuildEnvironment(binding); err != nil {
		return err
	}
	_, err = acme.BindingDigest(binding)
	return err
}

func buildHeadscaleDeployAuthority(installation domain.Installation, binding acme.Binding, certificateID, actor string, request preflight.ExpansionRequest, result preflight.Result, safetyState safety.State, now time.Time) (HeadscaleDeployAuthority, error) {
	if installation.Headscale == nil || installation.Headscale.Database.Phase != domain.HeadscaleIdentityCommitted || installation.Headscale.Applied != nil || installation.Headscale.Enabled || installation.Headscale.DeployIntent != nil {
		return HeadscaleDeployAuthority{}, fmt.Errorf("headscale initial deploy requires an identity-committed inactive trust domain")
	}
	if err := preflight.RequireExpansionResultForRequest(result, request, now); err != nil {
		return HeadscaleDeployAuthority{}, err
	}
	rendered, err := control.Build(control.BuildRequest{InstallationID: installation.InstallationID, Headscale: *installation.Headscale, Binding: binding, CertificateID: certificateID})
	if err != nil {
		return HeadscaleDeployAuthority{}, err
	}
	candidateDigest, err := control.Digest(rendered.Candidate)
	if err != nil {
		return HeadscaleDeployAuthority{}, err
	}
	preflightEvidence, err := result.PlanEvidence()
	if err != nil {
		return HeadscaleDeployAuthority{}, err
	}
	safetyEvidence, err := headscaleDeploySafetyEvidence(safetyState, rendered.Candidate.Generation, now)
	if err != nil {
		return HeadscaleDeployAuthority{}, err
	}
	bindingDigest, err := acme.BindingDigest(binding)
	if err != nil {
		return HeadscaleDeployAuthority{}, err
	}
	observationDigest, err := headscalePreflightObservationDigest(result)
	if err != nil {
		return HeadscaleDeployAuthority{}, err
	}
	evidence := []plans.Evidence{
		preflightEvidence,
		{Kind: "headscale_preflight_observation", Identity: result.RequestDigest, Generation: rendered.Candidate.Generation, Digest: observationDigest, ObservedAt: now.UTC()},
		safetyEvidence,
		{Kind: "acme_binding", Identity: "headscale", Generation: rendered.Candidate.Generation, Digest: bindingDigest, ObservedAt: now.UTC()},
		{Kind: "headscale_control_candidate", Identity: certificateID, Generation: rendered.Candidate.Generation, Digest: candidateDigest, ObservedAt: now.UTC()},
	}
	sort.Slice(evidence, func(left, right int) bool {
		if evidence[left].Kind != evidence[right].Kind {
			return evidence[left].Kind < evidence[right].Kind
		}
		return evidence[left].Identity < evidence[right].Identity
	})
	summary := fmt.Sprintf("headscale=%s control=https://%s/ listeners=80/tcp,443/tcp,3478/udp certificate=%s challenge=%s service=private-candidate", installation.Headscale.ID, installation.Headscale.ControlDomain, certificateID, binding.Method)
	spec := plans.Spec{Operation: string(domain.OperationHeadscaleControlDeploy), Target: plans.Target{Kind: plans.TargetHeadscale, ID: installation.Headscale.ID}, ActorIdentity: actor, Config: plans.DigestBinding{Applicable: true, Digest: rendered.Candidate.ConfigDigest}, Applied: plans.DigestBinding{}, Evidence: evidence, ExposureSummary: summary, Prerequisites: "Exact Headscale release/config/database, fresh expansion preflight, isolated private service probe, and first real control certificate are required before control/STUN activation.", Lifetime: 10 * time.Minute}
	return HeadscaleDeployAuthority{Rendered: rendered, Binding: binding, Preflight: request, Result: result, Spec: spec}, nil
}

// CreateHeadscaleDeployPlan is intentionally not registered in the UI action
// catalog until S17C installs the deadline and contraction owners.
func (s *FixedService) CreateHeadscaleDeployPlan(ctx context.Context, actor Actor, config HeadscaleCertificateConfig) (plans.Plan, error) {
	authority, err := actorAuthority(actor)
	if err != nil {
		return plans.Plan{}, err
	}
	document, err := s.normal.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	installation, err := loadHeadscaleInstallation(document)
	if err != nil {
		return plans.Plan{}, err
	}
	binding, err := loadHeadscaleCertificateBinding(config)
	if err != nil {
		return plans.Plan{}, err
	}
	certificateID, err := newHeadscaleCertificateID()
	if err != nil {
		return plans.Plan{}, err
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return plans.Plan{}, err
	}
	request, result, err := evaluateHeadscaleDeployPreflight(ctx, installed, installation.InstallationID, installation.Headscale.ID, installation.Headscale.ControlDomain, installation.Headscale.Database.Generation)
	if err != nil {
		return plans.Plan{}, err
	}
	safetyState, err := s.safety.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	planAuthority, err := buildHeadscaleDeployAuthority(installation, binding, certificateID, authority, request, result, safetyState, time.Now().UTC())
	if err != nil {
		return plans.Plan{}, err
	}
	admission, err := s.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(admission.Release)
	return s.plans.Create(ctx, admission, document.Revision, planAuthority.Spec)
}

func loadHeadscaleInstallation(document persist.Document) (domain.Installation, error) {
	raw, present := document.Entries["installations/current"]
	if !present {
		return domain.Installation{}, fmt.Errorf("installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil || installation.Headscale == nil {
		return domain.Installation{}, fmt.Errorf("headscale identity authority is missing")
	}
	return installation, nil
}

func headscaleDeploySafetyEvidence(state safety.State, candidateGeneration uint64, now time.Time) (plans.Evidence, error) {
	if candidateGeneration != 1 || state.Headscale.GenerationSequence != 0 || state.Headscale.CertificateExpiry != nil || state.Headscale.ChallengePending != nil || state.Headscale.Reactivating != nil || state.StopFence != nil {
		return plans.Evidence{}, fmt.Errorf("headscale first-deploy safety authority is unavailable")
	}
	binding := struct {
		Headscale safety.HeadscaleSafety `json:"headscale"`
		StopFence *safety.StopFence      `json:"stop_fence,omitempty"`
	}{state.Headscale, state.StopFence}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return plans.Evidence{}, err
	}
	sum := sha256.Sum256(encoded)
	return plans.Evidence{Kind: "headscale_safety", Identity: "headscale/first-deploy", Generation: candidateGeneration, Digest: "sha256:" + hex.EncodeToString(sum[:]), ObservedAt: now.UTC()}, nil
}

func headscalePreflightObservationDigest(result preflight.Result) (string, error) {
	result.ObservedAt = time.Time{}
	result.ValidUntil = time.Time{}
	result.Findings = append([]preflight.Finding(nil), result.Findings...)
	for index := range result.Findings {
		if result.Findings[index].Code == "trusted_clock" || result.Findings[index].Code == "disk" {
			result.Findings[index].Identity = "fresh_evaluation_required"
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func newHeadscaleCertificateID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		clear(value)
		return "", err
	}
	id := "cert_" + hex.EncodeToString(value)
	clear(value)
	return id, nil
}

func headscalePlanCandidateEvidence(plan plans.Plan) (certificateID, digest string, err error) {
	for _, evidence := range plan.Evidence {
		if evidence.Kind == "headscale_control_candidate" {
			if certificateID != "" {
				return "", "", fmt.Errorf("headscale Plan has duplicate candidate evidence")
			}
			certificateID, digest = evidence.Identity, evidence.Digest
		}
	}
	if !strings.HasPrefix(certificateID, "cert_") || digest == "" {
		return "", "", fmt.Errorf("headscale Plan candidate evidence is missing")
	}
	return certificateID, digest, nil
}
