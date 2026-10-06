//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/safety"
	"time"
)

func managementCertificateAuthority(binding acme.Binding, identity string) *domain.CertificateAuthorityIdentity {
	credentials := make([]domain.CertificateCredentialIdentity, len(binding.CredentialFiles))
	for index, file := range binding.CredentialFiles {
		credentials[index] = domain.CertificateCredentialIdentity{Key: file.Key, Path: file.Path, Fingerprint: file.Fingerprint}
	}
	return &domain.CertificateAuthorityIdentity{CertificateID: identity, DirectoryURL: binding.DirectoryURL, AccountKeyPath: binding.AccountKeyPath, AccountKeyFingerprint: binding.AccountKeyFingerprint, AccountEmail: binding.AccountEmail, TermsAccepted: binding.TermsAccepted, Method: string(binding.Method), Provider: string(binding.Provider), ProfilePath: binding.ProfilePath, ProfileFingerprint: binding.ProfileFingerprint, CredentialFiles: credentials, Zone: binding.Zone, Principal: binding.Principal}
}

// CompleteManagementHTTPSIssue commits the first issued certificate only after
// the staged pointer, normal configuration, independent safety authority, and
// exact Nginx graph are all bound to the same candidate identity.
func (execution *CertificateExecution) CompleteManagementHTTPSIssue(ctx context.Context, identity certificates.Identity) (jobs.Record, error) {
	if execution == nil || execution.Service == nil || !execution.ManagementHTTPS || execution.Operation != operations.AutomaticReconciliation || execution.PriorCertificate != nil || execution.Mutation == nil || execution.Exposure == nil {
		return jobs.Record{}, fmt.Errorf("management HTTPS issuance completion authority is incomplete")
	}
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return jobs.Record{}, err
	}
	activationCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx = activationCtx
	if !time.Now().UTC().Before(execution.Deadline) {
		return jobs.Record{}, fmt.Errorf("management HTTPS issuance activation deadline elapsed")
	}
	runtime := execution.Service.managementHTTPSRuntime()
	if runtime == nil || runtime.NewHost == nil || runtime.RemoveActiveChallenge == nil {
		return jobs.Record{}, fmt.Errorf("management HTTPS activation runtime authority is incomplete")
	}
	host, paths, owner, err := runtime.NewHost()
	if err != nil {
		return jobs.Record{}, err
	}
	if err := runtime.RemoveActiveChallenge(ctx, execution, host); err != nil {
		return jobs.Record{}, err
	}
	if execution.Binding.Method == acme.ChallengeHTTP01 {
		if err := runtime.VerifyWebrootEmpty(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID); err != nil {
			return jobs.Record{}, err
		}
	}
	if err := errors.Join(runtime.RemoveStage(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID), runtime.RemoveWebroot(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID)); err != nil {
		return jobs.Record{}, err
	}
	pointerIdentity, err := runtime.ActivePointerPath(identity.ID)
	if err != nil {
		return jobs.Record{}, err
	}
	candidate := domain.CertificateBundleIdentity{PointerIdentity: pointerIdentity, BindingIdentity: identity.BindingIdentity, Generation: identity.Generation, Fingerprint: identity.Fingerprint, SANIdentity: identity.SANIdentity, NotAfter: identity.NotAfter.Format(time.RFC3339), LastTrustedWall: identity.LastTrustedWall.Format(time.RFC3339), ChainIdentity: identity.ChainIdentity, IssuerIdentity: identity.IssuerIdentity, DirectoryIdentity: identity.DirectoryIdentity, Authority: managementCertificateAuthority(execution.Binding, identity.ID)}
	candidatePath, err := runtime.BundlePath(identity.ID, identity.Generation)
	if err != nil {
		return jobs.Record{}, err
	}
	pointer := certificates.Pointer{CertificateID: identity.ID, CandidateGeneration: identity.Generation, CandidateIdentity: certificates.BundleIdentityFor(identity)}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + execution.JobID, JobID: execution.JobID, Kind: operations.JournalCertificateActivation, Operation: operations.AutomaticReconciliation, InstallationID: execution.InstallationID, Target: "management_https", Generation: execution.Child.IntentGeneration, Deadline: execution.Deadline, ArtifactDigest: execution.Child.InputDigest, ChildIDs: []string{execution.Child.ID}, Phase: operations.JournalActive, Certificate: &operations.CertificateJournalIdentity{CertificateID: identity.ID, CandidateGeneration: identity.Generation, CandidatePointer: candidatePath, CandidateFingerprint: identity.Fingerprint, CandidateBundleIdentity: certificates.BundleIdentityFor(identity), Challenge: execution.Challenge.Safety, StageUID: execution.StageUID, StageGID: execution.StageGID}}
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	if _, err := runtime.ActivatePointer(ctx, pointer); err != nil {
		return jobs.Record{}, err
	}
	execution.InitialPointer = &pointer
	freshDocument, err := execution.Service.normal.Read()
	if err != nil {
		return jobs.Record{}, err
	}
	raw, present := freshDocument.Entries["installations/current"]
	if !present {
		return jobs.Record{}, fmt.Errorf("management HTTPS installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil || installation.ManagementHTTPS == nil || installation.ManagementHTTPS.Phase != domain.ManagementHTTPSPending {
		return jobs.Record{}, fmt.Errorf("management HTTPS pending configuration changed")
	}
	candidateConfig := *installation.ManagementHTTPS
	candidateConfig.Phase = domain.ManagementHTTPSActive
	candidateConfig.CertificateBundle = &candidate
	candidateConfig.LastFailureCode = ""
	candidateInstallation := installation
	candidateInstallation.ManagementHTTPS = &candidateConfig
	entry, err := nginx.BuildManagementEntry(candidateInstallation)
	if err != nil {
		return jobs.Record{}, err
	}
	if err := execution.Admitter.CommitManagementHTTPSIssue(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, candidateConfig); err != nil {
		return jobs.Record{}, err
	}
	execution.InitialConfigCommitted = true
	execution.Revision++
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return jobs.Record{}, err
	}
	pending := state.ManagementHTTPS.ChallengePending
	if pending == nil || !challenge.Matches(*pending, execution.Challenge) {
		return jobs.Record{}, fmt.Errorf("management HTTPS issuance challenge authority changed")
	}
	next := state
	next.Revision++
	next.ManagementHTTPS.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: identity.Generation, Fingerprint: identity.Fingerprint, Binding: identity.BindingIdentity, NotAfter: identity.NotAfter, LastTrustedWall: identity.LastTrustedWall}
	next.ManagementHTTPS.EntryDigest = entry.Digest
	next.ManagementHTTPS.CertificateExpiry = nil
	next.ManagementHTTPS.ChallengePending = nil
	if _, _, err := runtime.InstallEntry(ctx, paths, owner, entry); err != nil {
		return jobs.Record{}, err
	}
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{}); err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return jobs.Record{}, errors.Join(err, stopErr)
	}
	authority, err := challengeReloadAuthorityForExposure(execution.Service, execution.Exposure)
	if err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return jobs.Record{}, errors.Join(err, stopErr)
	}
	if _, err := host.ReloadCertificate(ctx, authority); err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return jobs.Record{}, errors.Join(err, stopErr)
	}
	if err := host.VerifyServedCertificate(ctx, installation.ManagementHTTPS.Domain, identity.Fingerprint); err != nil {
		_, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
		return jobs.Record{}, errors.Join(err, stopErr)
	}
	journal.Phase = operations.JournalTerminal
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	return execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "complete", []string{identity.CertificatePath, identity.PrivateKeyPath, pointerIdentity}, []jobs.Postcondition{{Kind: "management_https_active", Status: jobs.PostconditionVerified, Identity: identity.Fingerprint}}, "")
}
