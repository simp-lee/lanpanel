//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/activation"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
)

func reconcileCompletedManagementHTTPSCertificate(ctx context.Context, service *FixedService, journalID string) error {
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	raw, present := document.Entries["journals/"+journalID]
	var journal operations.JournalRecord
	if !present || json.Unmarshal(raw, &journal) != nil || journal.Certificate == nil || journal.Operation != operations.AutomaticReconciliation && journal.Operation != operations.CertificateRenew || journal.Target != "management_https" || (journal.Phase != operations.JournalActive && journal.Phase != operations.JournalTerminal) {
		return fmt.Errorf("completed Management HTTPS certificate journal changed")
	}
	intentRaw, present := document.Entries["intents/"+journal.JobID]
	var intent operations.Reservation
	if !present || json.Unmarshal(intentRaw, &intent) != nil || intent.Operation != journal.Operation || intent.Target != "management_https" || (intent.Phase != operations.PhaseLocalIntent && intent.Phase != operations.PhaseRemoteWait && intent.Phase != operations.PhaseReentered) {
		return fmt.Errorf("completed Management HTTPS certificate intent changed")
	}
	certificate := journal.Certificate
	childRaw, present := document.Entries["children/"+certificateChildID(journal)]
	var childRecord operations.ChildRecord
	if !present || json.Unmarshal(childRaw, &childRecord) != nil || childRecord.State != operations.ChildTerminal || childRecord.Outcome != operations.ChildSucceeded {
		return fmt.Errorf("completed Management HTTPS issuance child result changed")
	}
	runtime := service.managementHTTPSRuntime()
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: service.managementHTTPSRoot() + "/locks", Owner: service.managementHTTPSOwner().UID, Group: service.managementHTTPSOwner().GID, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "management_https", service.manager)
	if err != nil {
		_ = mutationSet.Close()
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure); _ = mutationSet.Close() }()
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	document, err = service.normal.Read()
	if err != nil {
		return err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil || installation.ManagementHTTPS == nil || installation.ManagementHTTPS.Phase != domain.ManagementHTTPSActive || installation.ManagementHTTPS.CertificateBundle == nil {
		return fmt.Errorf("completed Management HTTPS issuance configuration authority missing")
	}
	bundle := installation.ManagementHTTPS.CertificateBundle
	if !certificateBundleMatches(*bundle, certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity) {
		return fmt.Errorf("completed Management HTTPS issuance candidate changed")
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	entry, err := nginx.BuildManagementEntry(installation)
	if err != nil {
		return err
	}
	if state.ManagementHTTPS.ChallengePending != nil || state.ManagementHTTPS.ActiveCertificate == nil || !activeCertificateMatchesBundle(state.ManagementHTTPS.ActiveCertificate, *bundle) || state.ManagementHTTPS.EntryDigest != entry.Digest {
		return fmt.Errorf("completed Management HTTPS issuance safety authority changed")
	}
	pointer, err := runtime.ObservePointer(certificate.CertificateID)
	if err != nil || pointer != certificate.CandidatePointer {
		return fmt.Errorf("completed Management HTTPS issuance pointer changed")
	}
	if err := runtime.VerifyBundleIdentity(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity); err != nil {
		return err
	}
	host, paths, owner, err := runtime.NewHost()
	if err != nil {
		return err
	}
	if _, _, err := runtime.InstallEntry(ctx, paths, owner, entry); err != nil {
		return err
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
	if err := host.VerifyServedCertificate(ctx, installation.ManagementHTTPS.Domain, certificate.CandidateFingerprint); err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return errors.Join(err, stopErr)
	}
	if err := errors.Join(runtime.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), runtime.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
		return err
	}
	revision := document.Revision
	if journal.Phase == operations.JournalActive {
		journal.Phase = operations.JournalTerminal
		if err := admitter.PutJournal(ctx, mutation, exposure, revision, journal, false); err != nil {
			return err
		}
		revision++
	}
	_, err = admitter.Complete(ctx, mutation, exposure, revision, journal.JobID, "complete", []string{certificate.CandidatePointer}, []jobs.Postcondition{{Kind: "management_https_active", Status: jobs.PostconditionVerified, Identity: certificate.CandidateFingerprint}}, "")
	return err
}

func reloadOrStartManagementHTTPS(ctx context.Context, runtime *managementHTTPSRuntime, host managementHTTPSHost, paths nginx.Paths, owner filetxn.Owner, authority activation.ReloadAuthority) error {
	manifest, err := runtime.Audit(paths, owner)
	if err != nil {
		return err
	}
	snapshot, err := host.ObserveRuntime(ctx, manifest)
	if err != nil {
		return err
	}
	if snapshot.Master == nil {
		_, err = host.StartCertificate(ctx, authority)
		return err
	}
	_, err = host.ReloadCertificate(ctx, authority)
	return err
}

func certificateChildID(journal operations.JournalRecord) string {
	if len(journal.ChildIDs) != 1 {
		return ""
	}
	return journal.ChildIDs[0]
}
