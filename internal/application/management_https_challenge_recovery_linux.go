//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/challenge"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
	"reflect"
	"strings"
	"time"
)

func reconcileInterruptedManagementHTTPSChallenge(ctx context.Context, service *FixedService, childClosure string) error {
	runtime := service.managementHTTPSRuntime()
	state, err := service.safety.Read()
	if err != nil || state.ManagementHTTPS.ChallengePending == nil {
		return err
	}
	pending := *state.ManagementHTTPS.ChallengePending
	if pending.Method == "dns-01" {
		ownerLocks, lockErr := acme.AcquireOwnerLocks(ctx, service.managementHTTPSRoot()+"/locks", acme.DNSProvider(pending.Provider), pending.Zone, pending.Owners, pending.OwnerLock)
		if lockErr != nil {
			return lockErr
		}
		_, preflightErr := acme.PreflightDNS01(ctx, acme.NetDNSObserver{}, pending.Zone, pending.Owners)
		closeErr := ownerLocks.Close()
		if err := errors.Join(preflightErr, closeErr); err != nil {
			return fmt.Errorf("interrupted Management HTTPS DNS challenge cleanup unproved: %w", err)
		}
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: service.managementHTTPSRoot() + "/locks", Owner: service.managementHTTPSOwner().UID, Group: service.managementHTTPSOwner().GID, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "management_https", service.manager)
	if err != nil {
		_ = mutationSet.Close()
		return err
	}
	closeLeases := func() error { return errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close()) }
	if pending.Method == "http-01" && pending.Token != "" {
		authority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
		if authorityErr != nil {
			return errors.Join(authorityErr, closeLeases())
		}
		currentAuthority, authorityErr := authority.Current()
		if authorityErr != nil {
			return errors.Join(authorityErr, closeLeases())
		}
		if currentAuthority.Safety.ManagementHTTPS.ChallengePending == nil || !reflect.DeepEqual(*currentAuthority.Safety.ManagementHTTPS.ChallengePending, pending) {
			return errors.Join(fmt.Errorf("interrupted Management HTTPS challenge authority changed under exposure lock"), closeLeases())
		}
		host, paths, owner, hostErr := runtime.NewHost()
		if hostErr != nil {
			return errors.Join(hostErr, closeLeases())
		}
		manifest, auditErr := runtime.Audit(paths, owner)
		if auditErr != nil {
			return errors.Join(auditErr, closeLeases())
		}
		expected, prepareErr := challenge.PreparedHTTP("management_https", pending)
		if prepareErr != nil {
			return errors.Join(prepareErr, closeLeases())
		}
		if _, routeErr := exactHTTP01PresentationInManifest(manifest, "management_https", expected); routeErr != nil {
			return errors.Join(routeErr, closeLeases())
		}
		if _, removeErr := host.RemoveChallenge(ctx, expected, authority); removeErr != nil {
			return errors.Join(removeErr, closeLeases())
		}
		base, clearErr := challenge.ClearHTTP(expected)
		if clearErr != nil {
			return errors.Join(clearErr, closeLeases())
		}
		fresh := currentAuthority.Safety
		next := fresh
		next.Revision++
		next.ManagementHTTPS.ChallengePending = &base.Safety
		if _, commitErr := service.safety.Commit(ctx, exposure, safety.RoleChallenge, fresh.Revision, next, safety.TransitionProof{}); commitErr != nil {
			return errors.Join(commitErr, closeLeases())
		}
		pending = base.Safety
		stageIdentity, identityErr := identity.CertificateStageIdentityFor(expected.Safety.CertificateIdentity)
		if identityErr != nil {
			return errors.Join(identityErr, closeLeases())
		}
		if tokenErr := acme.VerifyHTTP01TokenDigest(expected.Safety.CertificateIdentity, stageIdentity.UID, stageIdentity.GID, expected.Safety.Token, expected.Safety.KeyAuthorizationDigest); tokenErr != nil {
			return errors.Join(tokenErr, closeLeases())
		}
	}
	document, err := service.normal.Read()
	if err != nil {
		return errors.Join(err, closeLeases())
	}
	jobID := ""
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) != nil || intent.Target != "management_https" || (intent.Operation != operations.CertificateRenew && intent.Operation != operations.AutomaticReconciliation) || intent.SafetyBinding.ResourceID != "management_https" {
			continue
		}
		matches := intent.SafetyBinding.PlanID == pending.PlanID && intent.SafetyBinding.IntentGeneration == pending.Generation && intent.SafetyBinding.CandidateBundle == pending.ACMEBinding && (intent.SafetyBinding.CandidateDigest == pending.SANIdentity || intent.SafetyBinding.CandidateDigest == pending.ConfigDigest)
		if matches {
			if jobID != "" {
				return errors.Join(fmt.Errorf("multiple Management HTTPS challenge intents"), closeLeases())
			}
			jobID = intent.JobID
		}
	}
	if jobID == "" {
		return errors.Join(fmt.Errorf("management HTTPS challenge lacks exact operation intent"), closeLeases())
	}
	raw, present := document.Entries["journals/certificate-"+jobID]
	var journal operations.JournalRecord
	if !present || json.Unmarshal(raw, &journal) != nil || journal.Certificate == nil {
		return errors.Join(fmt.Errorf("management HTTPS challenge journal missing"), closeLeases())
	}
	certificate := journal.Certificate
	if journal.Operation == operations.AutomaticReconciliation || journal.Operation == operations.CertificateRenew {
		if activationPending, pendingErr := managementHTTPSCandidateActivationPending(document, *certificate); pendingErr != nil {
			return errors.Join(pendingErr, closeLeases())
		} else if activationPending {
			if err := finishInterruptedManagementHTTPSActivation(ctx, service, mutation, exposure, jobID, *certificate); err != nil {
				return errors.Join(err, closeLeases())
			}
			return closeLeases()
		}
	}
	if journal.Operation == operations.AutomaticReconciliation {
		observedPointer, pointerErr := runtime.ObservePointer(certificate.CertificateID)
		if pointerErr != nil {
			return errors.Join(pointerErr, closeLeases())
		}
		if observedPointer == certificate.CandidatePointer {
			pointer := certificatePointerFromJournal(*certificate)
			if err := runtime.RemovePointer(ctx, pointer, certificate.CandidatePointer); err != nil {
				return errors.Join(err, closeLeases())
			}
		}
		if err := runtime.RemoveInactiveBundle(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity, certificate.StageUID, certificate.StageGID); err != nil {
			return errors.Join(err, closeLeases())
		}
	}
	if journal.Operation == operations.CertificateRenew && certificate.PriorGeneration > 0 {
		if err := rollbackInterruptedManagementHTTPSRenewal(ctx, service, mutation, exposure, document, *certificate); err != nil {
			return errors.Join(err, closeLeases())
		}
	}
	if err := errors.Join(runtime.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), runtime.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
		return errors.Join(err, closeLeases())
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return errors.Join(err, closeLeases())
	}
	if _, err := admitter.TerminalizeContractedCertificate(ctx, mutation, exposure, document.Revision, jobID, pending, shaDigest([]byte("management-https-challenge\x00"+jobID+"\x00"+childClosure))); err != nil {
		return errors.Join(err, closeLeases())
	}
	fresh, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return errors.Join(err, closeLeases())
	}
	if fresh.ManagementHTTPS.ChallengePending == nil || fresh.ManagementHTTPS.ChallengePending.Generation != pending.Generation {
		return errors.Join(fmt.Errorf("management HTTPS challenge safety authority changed"), closeLeases())
	}
	next := fresh
	next.Revision++
	next.ManagementHTTPS.ChallengePending = nil
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, fresh.Revision, next, safety.TransitionProof{}); err != nil {
		return errors.Join(err, closeLeases())
	}
	return closeLeases()
}

func managementHTTPSCandidateActivationPending(document persist.Document, journal operations.CertificateJournalIdentity) (bool, error) {
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return false, fmt.Errorf("interrupted Management HTTPS activation installation authority invalid: %w", err)
	}
	if installation.ManagementHTTPS == nil || installation.ManagementHTTPS.Phase != domain.ManagementHTTPSActive || installation.ManagementHTTPS.CertificateBundle == nil {
		return false, nil
	}
	if certificateBundleMatches(*installation.ManagementHTTPS.CertificateBundle, journal.CertificateID, journal.CandidateGeneration, journal.CandidateBundleIdentity) {
		return true, nil
	}
	return false, nil
}

func finishInterruptedManagementHTTPSActivation(ctx context.Context, service *FixedService, mutation *operations.MutationLease, exposure *locks.Lease, jobID string, journal operations.CertificateJournalIdentity) error {
	runtime := service.managementHTTPSRuntime()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil || installation.ManagementHTTPS == nil || installation.ManagementHTTPS.CertificateBundle == nil {
		return fmt.Errorf("interrupted Management HTTPS activation configuration missing")
	}
	bundle := installation.ManagementHTTPS.CertificateBundle
	if !certificateBundleMatches(*bundle, journal.CertificateID, journal.CandidateGeneration, journal.CandidateBundleIdentity) {
		return fmt.Errorf("interrupted Management HTTPS activation candidate changed")
	}
	entry, err := nginx.BuildManagementEntry(installation)
	if err != nil {
		return err
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	activationCommitted := state.ManagementHTTPS.ChallengePending == nil && state.ManagementHTTPS.EntryDigest == entry.Digest && activeCertificateMatchesBundle(state.ManagementHTTPS.ActiveCertificate, *bundle) && state.ManagementHTTPS.CertificateExpiry == nil
	if !activationCommitted && (state.ManagementHTTPS.ChallengePending == nil || journal.PriorGeneration == 0 && state.ManagementHTTPS.ActiveCertificate != nil && (state.ManagementHTTPS.EntryDigest != "" || state.ManagementHTTPS.CertificateExpiry == nil) || journal.PriorGeneration > 0 && state.ManagementHTTPS.ActiveCertificate == nil) {
		return fmt.Errorf("interrupted Management HTTPS activation safety state is not pending")
	}
	notAfter, err := time.Parse(time.RFC3339, bundle.NotAfter)
	if err != nil {
		return err
	}
	lastTrusted, err := time.Parse(time.RFC3339, bundle.LastTrustedWall)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	next.ManagementHTTPS.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: bundle.Generation, Fingerprint: bundle.Fingerprint, Binding: bundle.BindingIdentity, NotAfter: notAfter, LastTrustedWall: lastTrusted}
	next.ManagementHTTPS.EntryDigest = entry.Digest
	next.ManagementHTTPS.CertificateExpiry = nil
	next.ManagementHTTPS.ChallengePending = nil
	pointer, err := runtime.ObservePointer(journal.CertificateID)
	if err != nil || pointer != journal.CandidatePointer {
		return fmt.Errorf("interrupted Management HTTPS activation pointer changed")
	}
	if err := runtime.VerifyBundleIdentity(journal.CertificateID, journal.CandidateGeneration, journal.CandidateBundleIdentity); err != nil {
		return err
	}
	host, paths, owner, err := runtime.NewHost()
	if err != nil {
		return err
	}
	if !activationCommitted && journal.Challenge.Method == "http-01" {
		manifest, auditErr := runtime.Audit(paths, owner)
		if auditErr != nil {
			return auditErr
		}
		if journal.Challenge.Token == "" {
			if state.ManagementHTTPS.ChallengePending == nil || !reflect.DeepEqual(*state.ManagementHTTPS.ChallengePending, journal.Challenge) {
				return fmt.Errorf("interrupted Management HTTPS activation cleared challenge authority changed")
			}
			for _, current := range manifest.Entries {
				if current.Kind == nginx.EntryChallenge && current.ResourceID == "management_https" {
					return fmt.Errorf("interrupted Management HTTPS activation retained its challenge graph")
				}
			}
		} else {
			prepared, prepareErr := challenge.PreparedHTTP("management_https", journal.Challenge)
			if prepareErr != nil {
				return prepareErr
			}
			present, routeErr := exactHTTP01PresentationInManifest(manifest, "management_https", prepared)
			if routeErr != nil {
				return routeErr
			}
			if present {
				return fmt.Errorf("interrupted Management HTTPS activation retained its challenge graph")
			}
			challengeMatches := false
			if state.ManagementHTTPS.ChallengePending != nil {
				challengeMatches = challenge.Matches(*state.ManagementHTTPS.ChallengePending, prepared)
				if !challengeMatches {
					cleared, clearErr := challenge.ClearHTTP(prepared)
					challengeMatches = clearErr == nil && challenge.Matches(*state.ManagementHTTPS.ChallengePending, cleared)
				}
			}
			if !challengeMatches {
				return fmt.Errorf("interrupted Management HTTPS activation challenge authority changed")
			}
		}
	}
	if _, _, err := runtime.InstallEntry(ctx, paths, owner, entry); err != nil {
		return err
	}
	if !activationCommitted {
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{}); err != nil {
			_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
			return errors.Join(err, stopErr)
		}
	}
	authority, err := challengeReloadAuthorityForExposure(service, exposure)
	if err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return errors.Join(err, stopErr)
	}
	if err := reloadOrStartManagementHTTPS(ctx, runtime, host, paths, owner, authority); err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return errors.Join(err, stopErr)
	}
	if err := host.VerifyServedCertificate(ctx, installation.ManagementHTTPS.Domain, journal.CandidateFingerprint); err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return errors.Join(err, stopErr)
	}
	if err := errors.Join(runtime.RemoveStage(journal.CertificateID, journal.StageUID, journal.StageGID), runtime.RemoveWebroot(journal.CertificateID, journal.StageUID, journal.StageGID)); err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	document, err = service.normal.Read()
	if err != nil {
		return err
	}
	raw, present := document.Entries["journals/certificate-"+jobID]
	var current operations.JournalRecord
	if !present || json.Unmarshal(raw, &current) != nil || current.Certificate == nil {
		return fmt.Errorf("interrupted Management HTTPS activation journal changed")
	}
	current.Phase = operations.JournalTerminal
	if err := admitter.PutJournal(ctx, mutation, exposure, document.Revision, current, false); err != nil {
		return err
	}
	document, err = service.normal.Read()
	if err != nil {
		return err
	}
	_, err = admitter.Complete(ctx, mutation, exposure, document.Revision, jobID, "complete", []string{journal.CandidatePointer}, []jobs.Postcondition{{Kind: "management_https_active", Status: jobs.PostconditionVerified, Identity: journal.CandidateFingerprint}}, "")
	return err
}

func rollbackInterruptedManagementHTTPSRenewal(ctx context.Context, service *FixedService, mutation *operations.MutationLease, exposure *locks.Lease, document persist.Document, journal operations.CertificateJournalIdentity) error {
	runtime := service.managementHTTPSRuntime()
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil || installation.ManagementHTTPS == nil || installation.ManagementHTTPS.CertificateBundle == nil {
		return fmt.Errorf("interrupted Management HTTPS renewal configuration authority missing")
	}
	prior := installation.ManagementHTTPS.CertificateBundle
	if !certificateBundleMatches(*prior, journal.CertificateID, journal.PriorGeneration, journal.PriorBundleIdentity) {
		if !certificateBundleMatches(*prior, journal.CertificateID, journal.CandidateGeneration, journal.CandidateBundleIdentity) {
			return fmt.Errorf("interrupted Management HTTPS renewal normal authority differs from candidate and prior")
		}
		return fmt.Errorf("interrupted Management HTTPS renewal committed candidate requires activation recovery")
	}
	observed, err := runtime.ObservePointer(journal.CertificateID)
	if err != nil {
		return err
	}
	if observed == journal.CandidatePointer {
		host, _, _, err := runtime.NewHost()
		if err != nil {
			return err
		}
		authority, err := challengeReloadAuthorityForExposure(service, exposure)
		if err != nil {
			return err
		}
		pointer := certificatePointerFromJournal(journal)
		if err := host.RestoreCertificate(ctx, pointer, journal.CandidatePointer, installation.ManagementHTTPS.Domain, journal.PriorFingerprint, authority); err != nil {
			return err
		}
		observed = journal.PriorPointer
	}
	if observed != journal.PriorPointer {
		return fmt.Errorf("interrupted Management HTTPS renewal pointer differs from prior authority")
	}
	return runtime.RemoveInactiveBundle(journal.CertificateID, journal.CandidateGeneration, journal.CandidateBundleIdentity, journal.StageUID, journal.StageGID)
}
