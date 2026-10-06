//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/safety"
	"sort"
	"strings"
	"time"
)

func ReconcileManagementHTTPSExpiryJobs(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func() { _ = service.Close() }()
	return reconcileManagementHTTPSExpiryJobs(ctx, service)
}

func reconcileManagementHTTPSExpiryJobs(ctx context.Context, service *FixedService) error {
	runtime := service.managementHTTPSRuntime()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	jobIDs := []string{}
	jobTargets := map[string]string{}
	jobPhases := map[string]operations.Phase{}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) != nil || intent.Operation != operations.AutomaticReconciliation || !strings.HasPrefix(intent.Target, "journal/management-https-expiry-") || intent.Phase == operations.PhaseTerminal || intent.Phase == operations.PhaseRejected {
			continue
		}
		jobIDs = append(jobIDs, intent.JobID)
		jobTargets[intent.JobID] = intent.Target
		jobPhases[intent.JobID] = intent.Phase
	}
	sort.Strings(jobIDs)
	for _, jobID := range jobIDs {
		admitter, err := service.TimerAdmitter()
		if err != nil {
			return err
		}
		if jobPhases[jobID] == operations.PhaseReserved {
			admission, acquireErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if acquireErr != nil {
				return acquireErr
			}
			fresh, readErr := service.normal.Read()
			var rejectErr error
			if readErr == nil {
				rejectErr = admitter.RejectReservation(ctx, admission, fresh.Revision, jobID, "management_https_expiry_interrupted")
			}
			releaseErr := admission.Release()
			if err := errors.Join(readErr, rejectErr, releaseErr); err != nil {
				return err
			}
			continue
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: service.managementHTTPSRoot() + "/locks", Owner: service.managementHTTPSOwner().UID, Group: service.managementHTTPSOwner().GID, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, jobTargets[jobID], service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		closeLeases := func() error { return errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close()) }
		fresh, err := service.normal.Read()
		if err != nil {
			return errors.Join(err, closeLeases())
		}
		intent, err := admitter.OperationIntent(jobID)
		if err != nil || intent.Operation != operations.AutomaticReconciliation || !strings.HasPrefix(intent.Target, "journal/management-https-expiry-") || intent.Phase == operations.PhaseTerminal || intent.Phase == operations.PhaseRejected {
			return errors.Join(fmt.Errorf("management HTTPS expiry recovery intent changed"), closeLeases())
		}
		installation, err := domain.DecodeInstallation(fresh.Entries["installations/current"])
		if err != nil || installation.ManagementHTTPS == nil || installation.ManagementHTTPS.CertificateBundle == nil || installation.ManagementHTTPS.Phase != domain.ManagementHTTPSActive && installation.ManagementHTTPS.Phase != domain.ManagementHTTPSExpired {
			return errors.Join(fmt.Errorf("management HTTPS expiry recovery configuration changed"), closeLeases())
		}
		config := *installation.ManagementHTTPS
		deadline, err := time.Parse(time.RFC3339, config.CertificateBundle.NotAfter)
		if err != nil {
			return errors.Join(err, closeLeases())
		}
		if intent.SafetyBinding.ExpiryGeneration == 0 || intent.SafetyBinding.CandidateBundle != config.CertificateBundle.BindingIdentity || !intent.SafetyBinding.Deadline.Equal(deadline) || time.Now().UTC().Before(deadline) {
			return errors.Join(fmt.Errorf("management HTTPS expiry recovery deadline authority changed"), closeLeases())
		}
		state, err := service.safety.ReadForRecovery(exposure)
		if err != nil {
			return errors.Join(err, closeLeases())
		}
		if state.ManagementHTTPS.ActiveCertificate == nil || state.ManagementHTTPS.ActiveCertificate.Binding != config.CertificateBundle.BindingIdentity || state.ManagementHTTPS.ActiveCertificate.Fingerprint != config.CertificateBundle.Fingerprint {
			return errors.Join(fmt.Errorf("management HTTPS expiry recovery safety authority changed"), closeLeases())
		}
		if state.ManagementHTTPS.CertificateExpiry == nil {
			next := state
			next.Revision++
			next.ManagementHTTPS.GenerationSequence = intent.SafetyBinding.ExpiryGeneration
			next.ManagementHTTPS.CertificateExpiry = &safety.DeadlineMarker{Generation: intent.SafetyBinding.ExpiryGeneration, Deadline: deadline, Binding: config.CertificateBundle.BindingIdentity}
			if _, err := service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{}); err != nil {
				return errors.Join(err, closeLeases())
			}
			state = next
		} else if state.ManagementHTTPS.CertificateExpiry.Generation != intent.SafetyBinding.ExpiryGeneration || state.ManagementHTTPS.CertificateExpiry.Binding != config.CertificateBundle.BindingIdentity || !state.ManagementHTTPS.CertificateExpiry.Deadline.Equal(deadline) {
			return errors.Join(fmt.Errorf("management HTTPS expiry recovery marker changed"), closeLeases())
		}
		if state.ManagementHTTPS.EntryDigest != "" {
			host, _, _, err := runtime.NewHost()
			if err != nil {
				return errors.Join(err, closeLeases())
			}
			entry, err := nginx.BuildManagementEntry(installation)
			if err != nil {
				return errors.Join(err, closeLeases())
			}
			authority, err := challengeReloadAuthorityForExposure(service, exposure)
			if err != nil {
				return errors.Join(err, closeLeases())
			}
			if _, err := host.ContractManagement(ctx, entry, authority, independentCertificateContractionRequiresStop(state)); err != nil {
				return errors.Join(err, closeLeases())
			}
			fresh, err = service.normal.Read()
			if err != nil {
				return errors.Join(err, closeLeases())
			}
			state, err = service.safety.ReadForRecovery(exposure)
			if err != nil {
				return errors.Join(err, closeLeases())
			}
			next := state
			next.Revision++
			next.ManagementHTTPS.EntryDigest = ""
			if _, err := service.safety.Commit(ctx, exposure, safety.RoleContraction, state.Revision, next, safety.TransitionProof{}); err != nil {
				return errors.Join(err, closeLeases())
			}
		}
		if config.Phase == domain.ManagementHTTPSActive {
			config.Phase = domain.ManagementHTTPSExpired
			config.LastFailureCode = "certificate_expired"
			fresh, err = service.normal.Read()
			if err != nil {
				return errors.Join(err, closeLeases())
			}
			if err := admitter.CommitManagementHTTPSExpiry(ctx, mutation, exposure, fresh.Revision, jobID, config); err != nil {
				return errors.Join(err, closeLeases())
			}
			fresh, err = service.normal.Read()
			if err != nil {
				return errors.Join(err, closeLeases())
			}
		}
		_, paths, owner, err := runtime.NewHost()
		if err != nil {
			return errors.Join(err, closeLeases())
		}
		manifest, err := runtime.Audit(paths, owner)
		if err != nil {
			return errors.Join(err, closeLeases())
		}
		publicEntry := false
		for _, entry := range manifest.Entries {
			if entry.Kind == nginx.EntryManagement {
				publicEntry = true
				break
			}
		}
		if publicEntry {
			return errors.Join(fmt.Errorf("management HTTPS expiry recovery found a public entry"), closeLeases())
		}
		state, err = service.safety.ReadForRecovery(exposure)
		if err != nil {
			return errors.Join(err, closeLeases())
		}
		_, err = admitter.Complete(ctx, mutation, exposure, fresh.Revision, jobID, "complete", nil, []jobs.Postcondition{{Kind: "management_https_expired", Status: jobs.PostconditionVerified, Identity: state.ManagementHTTPS.ActiveCertificate.Fingerprint}}, "")
		if closeErr := errors.Join(err, closeLeases()); closeErr != nil {
			return closeErr
		}
	}
	return nil
}
