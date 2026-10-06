//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/activation"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/safety"
	"slices"
	"time"
)

type ManagementHTTPSResult struct {
	JobID     string                      `json:"job_id"`
	JobResult string                      `json:"job_result"`
	Phase     domain.ManagementHTTPSPhase `json:"phase"`
	Domain    string                      `json:"domain"`
}

func loadManagementHTTPSBinding(request domain.CertificateRequest) (acme.Binding, error) {
	accountContact, accountKeyFingerprint, err := readManagedACMEAccountAuthority()
	if err != nil {
		return acme.Binding{}, err
	}
	if request.AccountEmail != accountContact {
		return acme.Binding{}, fmt.Errorf("management HTTPS ACME contact differs from managed account authority")
	}
	if request.ChallengeMethod == "http-01" {
		binding, err := acme.LoadHTTPBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, request.AccountEmail, request.TermsAccepted)
		if err != nil {
			return acme.Binding{}, fmt.Errorf("management HTTPS HTTP-01 preflight failed: %w", err)
		}
		if binding.AccountKeyFingerprint != accountKeyFingerprint {
			return acme.Binding{}, fmt.Errorf("management HTTPS managed ACME account key changed")
		}
		return binding, nil
	}
	provider, err := acme.ParseDNSProvider(request.DNSProvider)
	if err != nil {
		return acme.Binding{}, err
	}
	binding, err := acme.LoadDNSBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, request.AccountEmail, request.TermsAccepted, provider, request.ProviderProfilePath, request.AuthoritativeZone)
	if err != nil {
		return acme.Binding{}, fmt.Errorf("management HTTPS DNS-01 preflight failed: %w", err)
	}
	if binding.AccountKeyFingerprint != accountKeyFingerprint {
		return acme.Binding{}, fmt.Errorf("management HTTPS managed ACME account key changed")
	}
	return binding, nil
}

func managementHTTPSCandidateDigest(value domain.ManagementHTTPSConfig) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func managementHTTPSDomainOwner(installation domain.Installation, candidate string) string {
	for _, resource := range installation.Resources {
		if publication := resource.Publication.DomainHTTPS; publication != nil {
			if publication.CanonicalDomain == candidate || slices.Contains(publication.Aliases, candidate) {
				return resource.ID
			}
		}
		if bundle := resource.PublicationRecord.LastAppliedBundle; bundle != nil && bundle.DomainHTTPS != nil && slices.Contains(bundle.DomainHTTPS.ExactDomains, candidate) {
			return resource.ID
		}
	}
	return ""
}

// ConfigureManagementHTTPS durably records a validated pending request. It
// deliberately does not create a public Nginx entry or claim certificate
// activation; those require the later ACME and activation authority.
func ConfigureManagementHTTPS(ctx context.Context, candidate domain.ManagementHTTPSConfig, actor string) (result ManagementHTTPSResult, resultErr error) {
	if ctx == nil || actor == "" {
		return result, fmt.Errorf("management HTTPS configuration authority is incomplete")
	}
	candidate.Phase = domain.ManagementHTTPSPending
	candidate.CertificateBundle = nil
	candidate.LastFailureCode = ""
	service, err := OpenFixed()
	if err != nil {
		return result, err
	}
	document, err := service.normal.Read()
	if err != nil {
		_ = service.Close()
		return result, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		_ = service.Close()
		return result, err
	}
	if installation.Headscale != nil && installation.Headscale.Enabled && installation.Headscale.ControlDomain == candidate.Domain {
		_ = service.Close()
		return result, fmt.Errorf("management HTTPS domain conflicts with the Headscale control domain")
	}
	if installation.ManagementHTTPS != nil && installation.ManagementHTTPS.Phase == domain.ManagementHTTPSActive {
		_ = service.Close()
		return result, fmt.Errorf("management HTTPS is active; contract the current endpoint before reconfiguration")
	}
	if owner := managementHTTPSDomainOwner(installation, candidate.Domain); owner != "" {
		_ = service.Close()
		return result, fmt.Errorf("management HTTPS domain conflicts with application resource %s", owner)
	}
	if installation.ManagementHTTPS == nil {
		candidate.Generation = 1
	} else {
		candidate.Generation = installation.ManagementHTTPS.Generation + 1
	}
	if err := domain.ValidateManagementHTTPSConfig(candidate); err != nil {
		_ = service.Close()
		return result, err
	}
	bindingAuthority, err := loadManagementHTTPSBinding(candidate.Certificate)
	if err != nil {
		_ = service.Close()
		return result, err
	}
	bindingDigest, err := acme.BindingDigest(bindingAuthority)
	if err != nil {
		_ = service.Close()
		return result, err
	}
	candidate.ACMEBinding = bindingDigest
	if err := service.Close(); err != nil {
		return result, err
	}
	binding, err := managementHTTPSCandidateDigest(candidate)
	if err != nil {
		return result, err
	}
	execution, err := beginBasic(ctx, operations.ManagementHTTPSConfigure, "installation", actor, operations.SafetyBinding{CandidateDigest: binding, CandidateBundle: binding}, "")
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, execution.Close())
		if resultErr != nil {
			result.JobID = execution.job.ID
		}
	}()
	if err := execution.admitter.CommitManagementHTTPSConfigure(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration, execution.job.ID, candidate); err != nil {
		return result, err
	}
	record, err := execution.admitter.Complete(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration+1, execution.job.ID, "complete", nil, []jobs.Postcondition{{Kind: "management_https_pending", Status: jobs.PostconditionVerified, Identity: binding}}, "")
	if err != nil {
		return result, err
	}
	return ManagementHTTPSResult{JobID: record.ID, JobResult: string(record.Result), Phase: candidate.Phase, Domain: candidate.Domain}, nil
}

// ContractExpiredManagementHTTPS removes the public-management authority from
// the normal configuration after the independently trusted certificate has
// expired. It never issues, activates, or deletes certificate material.
func ContractExpiredManagementHTTPS(ctx context.Context, now time.Time) (returnErr error) {
	if ctx == nil || now.IsZero() {
		return fmt.Errorf("management HTTPS expiry authority is incomplete")
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return err
	}
	config := installation.ManagementHTTPS
	if config == nil || config.CertificateBundle == nil {
		return nil
	}
	if config.Phase == domain.ManagementHTTPSExpired {
		state, stateErr := service.safety.Read()
		if stateErr != nil {
			return stateErr
		}
		if state.ManagementHTTPS.EntryDigest == "" {
			return nil
		}
		activeInstallation := installation
		activeConfig := *config
		activeConfig.Phase = domain.ManagementHTTPSActive
		activeConfig.LastFailureCode = ""
		activeInstallation.ManagementHTTPS = &activeConfig
		host, err := activation.NewFixedHost()
		if err != nil {
			return err
		}
		entry, err := nginx.BuildManagementEntry(activeInstallation)
		if err != nil {
			return err
		}
		_, err = host.ContractManagement(ctx, entry, activation.ReloadAuthority{}, true)
		return err
	}
	if config.Phase != domain.ManagementHTTPSActive {
		return nil
	}
	deadline, err := time.Parse(time.RFC3339, config.CertificateBundle.NotAfter)
	if err != nil {
		return fmt.Errorf("management HTTPS certificate deadline evidence invalid: %w", err)
	}
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	if now.Before(deadline) {
		if !activeCertificateMatchesBundle(state.ManagementHTTPS.ActiveCertificate, *config.CertificateBundle) {
			host, hostErr := activation.NewFixedHost()
			if hostErr != nil {
				return hostErr
			}
			_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
			return errors.Join(fmt.Errorf("management HTTPS safety authority mismatches its normal certificate before expiry"), stopErr)
		}
		return nil
	}
	active := state.ManagementHTTPS.ActiveCertificate
	if active == nil || active.Generation != config.CertificateBundle.Generation || active.Fingerprint != config.CertificateBundle.Fingerprint || active.Binding != config.CertificateBundle.BindingIdentity || !active.NotAfter.Equal(deadline) || now.Before(active.LastTrustedWall) {
		return fmt.Errorf("management HTTPS expiry safety authority missing or stale")
	}
	expiryGeneration := state.ManagementHTTPS.GenerationSequence + 1
	if marker := state.ManagementHTTPS.CertificateExpiry; marker != nil {
		if marker.Binding != active.Binding || !marker.Deadline.Equal(active.NotAfter) {
			return fmt.Errorf("management HTTPS expiry marker changed")
		}
		expiryGeneration = marker.Generation
	}
	if expiryGeneration == 0 {
		return fmt.Errorf("management HTTPS expiry generation overflow")
	}
	_ = service.Close()
	service = nil
	binding := operations.SafetyBinding{ExpiryGeneration: expiryGeneration, Deadline: active.NotAfter, CandidateBundle: active.Binding}
	target := fmt.Sprintf("journal/management-https-expiry-%d", expiryGeneration)
	execution, err := beginPlanlessBasic(ctx, operations.AutomaticReconciliation, target, "timer/management-https-expiry", binding)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, execution.Close()) }()
	freshState, err := execution.service.safety.ReadForRecovery(execution.exposure)
	if err != nil {
		return err
	}
	if freshState.ManagementHTTPS.ActiveCertificate == nil || freshState.ManagementHTTPS.ActiveCertificate.Binding != active.Binding || freshState.ManagementHTTPS.ActiveCertificate.Fingerprint != active.Fingerprint {
		return fmt.Errorf("management HTTPS expiry authority changed under lock")
	}
	if freshState.ManagementHTTPS.CertificateExpiry == nil {
		next := freshState
		next.Revision++
		next.ManagementHTTPS.GenerationSequence = expiryGeneration
		next.ManagementHTTPS.CertificateExpiry = &safety.DeadlineMarker{Generation: expiryGeneration, Deadline: active.NotAfter, Binding: active.Binding}
		if _, err := execution.service.safety.Commit(ctx, execution.exposure, safety.RoleCertificateActivation, freshState.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
	} else if freshState.ManagementHTTPS.CertificateExpiry.Generation != expiryGeneration {
		return fmt.Errorf("management HTTPS expiry generation changed under lock")
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	entry, err := nginx.BuildManagementEntry(installation)
	if err != nil {
		return err
	}
	authority, err := challengeReloadAuthorityForExposure(execution.service, execution.exposure)
	if err != nil {
		return err
	}
	if _, err := host.ContractManagement(ctx, entry, authority, independentCertificateContractionRequiresStop(freshState)); err != nil {
		return err
	}
	freshState, err = execution.service.safety.ReadForRecovery(execution.exposure)
	if err != nil {
		return err
	}
	if freshState.ManagementHTTPS.EntryDigest != "" {
		next := freshState
		next.Revision++
		next.ManagementHTTPS.EntryDigest = ""
		if _, err := execution.service.safety.Commit(ctx, execution.exposure, safety.RoleContraction, freshState.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
	}
	candidate := *config
	candidate.Phase = domain.ManagementHTTPSExpired
	candidate.LastFailureCode = "certificate_expired"
	freshDocument, err := execution.service.normal.Read()
	if err != nil {
		return err
	}
	if err := execution.admitter.CommitManagementHTTPSExpiry(ctx, execution.mutation, execution.exposure, freshDocument.Revision, execution.job.ID, candidate); err != nil {
		return err
	}
	freshDocument, err = execution.service.normal.Read()
	if err != nil {
		return err
	}
	_, err = execution.admitter.Complete(ctx, execution.mutation, execution.exposure, freshDocument.Revision, execution.job.ID, "complete", nil, []jobs.Postcondition{{Kind: "management_https_expired", Status: jobs.PostconditionVerified, Identity: active.Fingerprint}}, "")
	return err
}
