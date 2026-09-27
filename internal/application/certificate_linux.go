//go:build linux

package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/contraction"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/publication"
	"lanpanel/internal/renewal"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
)

func certificateBundleIdentity(value domain.CertificateBundleIdentity) certificates.BundleIdentity {
	return certificates.BundleIdentity{Fingerprint: value.Fingerprint, SANIdentity: value.SANIdentity, ChainIdentity: value.ChainIdentity, IssuerIdentity: value.IssuerIdentity, BindingIdentity: value.BindingIdentity, DirectoryIdentity: value.DirectoryIdentity}
}

func certificatePointerFromJournal(value operations.CertificateJournalIdentity) certificates.Pointer {
	return certificates.Pointer{CertificateID: value.CertificateID, CandidateGeneration: value.CandidateGeneration, CandidateIdentity: value.CandidateBundleIdentity, ExpectedPriorGeneration: value.PriorGeneration, ExpectedPriorIdentity: value.PriorBundleIdentity}
}

func certificateBundleMatches(value domain.CertificateBundleIdentity, certificateID string, generation uint64, identity certificates.BundleIdentity) bool {
	pointer, err := certificates.ActivePointerPath(certificateID)
	return err == nil && value.Authority != nil && value.Authority.CertificateID == certificateID && value.PointerIdentity == pointer && value.Generation == generation && certificateBundleIdentity(value) == identity
}

func activeCertificateMatchesExpected(active, expected *safety.ActiveCertificateAuthority) bool {
	return active != nil && expected != nil && active.Generation == expected.Generation && active.Fingerprint == expected.Fingerprint && active.Binding == expected.Binding && active.NotAfter.Equal(expected.NotAfter) && !active.LastTrustedWall.Before(expected.LastTrustedWall)
}

func activeCertificateMatchesBundle(active *safety.ActiveCertificateAuthority, certificate domain.CertificateBundleIdentity) bool {
	expected, err := activeCertificateAuthority(certificate)
	return err == nil && activeCertificateMatchesExpected(active, expected)
}

func activeCertificateMatchesIdentity(active *safety.ActiveCertificateAuthority, identity certificates.Identity) bool {
	expected := &safety.ActiveCertificateAuthority{Generation: identity.Generation, Fingerprint: identity.Fingerprint, Binding: identity.BindingIdentity, NotAfter: identity.NotAfter, LastTrustedWall: identity.LastTrustedWall}
	return activeCertificateMatchesExpected(active, expected)
}

type CertificateExecution struct {
	Service          *FixedService
	Admitter         *operations.Admitter
	MutationSet      *operations.MutationSet
	Mutation         *operations.MutationLease
	Exposure         *locks.Lease
	JobID            string
	Operation        operations.Type
	Revision         uint64
	Resource         domain.AppResource
	Binding          acme.Binding
	Challenge        challenge.Prepared
	DNSPreflight     *acme.DNSPreflight
	DNSLocks         *acme.OwnerLocks
	InstallationID   string
	Plan             plans.Plan
	Deadline         time.Time
	BundleGeneration uint64
	PriorCertificate *domain.CertificateBundleIdentity
	Child            operations.ChildRecord
	StageRoot        string
	StageUID         uint32
	StageGID         uint32
	LegoDigest       string
	RemoteStarted    bool
	Headscale        bool
	HeadscaleID      string
	HeadscalePrior   *domain.CertificateBundleIdentity
	ClosureUncertain bool
	RecoveryPending  bool
}

func BeginCertificateIssue(ctx context.Context, actor Actor, envelopeTarget string, payload ConfirmationPayload) (*CertificateExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	var cleanup func() error
	var mutationSet *operations.MutationSet
	var mutation *operations.MutationLease
	var exposure *locks.Lease
	var childRecord operations.ChildRecord
	admittedJobID := ""
	fail := func(cause error) (*CertificateExecution, error) {
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		mutation = nil
		exposure = nil
		if mutationSet != nil {
			releaseErr = errors.Join(releaseErr, mutationSet.Close())
			mutationSet = nil
		}
		if cleanup != nil {
			releaseErr = errors.Join(releaseErr, cleanup())
		}
		releaseErr = errors.Join(releaseErr, service.Close())
		if admittedJobID != "" {
			return nil, MutationJobError{JobID: admittedJobID, Err: errors.Join(cause, releaseErr)}
		}
		return nil, errors.Join(cause, releaseErr)
	}
	legoDigest, err := loadCertificateLegoDigest()
	if err != nil {
		return fail(err)
	}
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	plan, err := service.ReadPlan(payload.PlanID)
	if err != nil || plan.Operation != string(domain.OperationPublish) || plan.ActorIdentity != authority || plan.Target.Kind != plans.TargetResource || envelopeTarget != "resource/"+plan.Target.ID || payload.Confirmation != "publish" || plan.ReservedAt != nil || plan.ConsumedAt != nil || plan.RejectedAt != nil {
		return fail(fmt.Errorf("certificate Plan confirmation invalid"))
	}
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	installation, resource, err := loadCertificateResource(document.Entries, plan.Target.ID)
	if err != nil {
		return fail(err)
	}
	if err := requireAppliedDomainSourcesHealthy(resource); err != nil {
		return fail(err)
	}
	publication := resource.Publication.DomainHTTPS
	if publication == nil || publication.Certificate == nil {
		return fail(fmt.Errorf("domain certificate request missing"))
	}
	domains := append([]string{publication.CanonicalDomain}, publication.Aliases...)
	sort.Strings(domains)
	request := publication.Certificate
	accountContact, accountKeyFingerprint, contactErr := readManagedACMEAccountAuthority()
	if contactErr != nil {
		return fail(contactErr)
	}
	var binding acme.Binding
	if request.ChallengeMethod == "http-01" {
		binding, err = acme.LoadHTTPBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, accountContact, request.TermsAccepted)
	} else {
		provider, parseErr := acme.ParseDNSProvider(request.DNSProvider)
		if parseErr != nil {
			return fail(parseErr)
		}
		binding, err = acme.LoadDNSBinding(request.DirectoryURL, acmeaccount.ManagedKeyPath, accountContact, request.TermsAccepted, provider, request.ProviderProfilePath, request.AuthoritativeZone)
	}
	if err != nil {
		return fail(err)
	}
	if binding.AccountKeyFingerprint != accountKeyFingerprint {
		return fail(fmt.Errorf("managed ACME account key changed after installation verification"))
	}
	bindingDigest, err := acme.BindingDigest(binding)
	evidenceMatched := false
	for _, evidence := range plan.Evidence {
		if evidence.Kind == "acme_binding" && evidence.Identity == "resource/"+resource.ID && evidence.Digest == bindingDigest {
			evidenceMatched = true
		}
	}
	if err != nil || !evidenceMatched {
		return fail(fmt.Errorf("certificate Plan ACME binding changed"))
	}
	state, err := service.safety.Read()
	if err != nil {
		return fail(err)
	}
	var safetyResource *safety.ResourceSafety
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resource.ID {
			safetyResource = &state.Resources[index]
		}
	}
	if safetyResource == nil || executionGeneration(plan) != safetyResource.GenerationSequence+1 {
		return fail(fmt.Errorf("certificate safety generation changed"))
	}
	_, preflightResult, err := evaluateDomainPreflight(ctx, installation, resource, state)
	if err != nil {
		return fail(err)
	}
	readiness, err := probeResourceTarget(ctx, resource)
	if err != nil {
		return fail(err)
	}
	sourceEvidence, err := observeDomainSources(service, resource)
	if err != nil {
		return fail(err)
	}
	if !domainPublicationPlanMatches(plan, resource, preflightResult, readiness, bindingDigest, sourceEvidence) {
		return fail(fmt.Errorf("certificate Plan evidence changed before remote work"))
	}
	generation := safetyResource.GenerationSequence + 1
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return fail(err)
	}
	certificateID := fmt.Sprintf("cert_%x", idBytes)
	stageIdentity, err := identity.CertificateStageIdentityFor(certificateID)
	if err != nil {
		return fail(err)
	}
	stageUID, stageGID := stageIdentity.UID, stageIdentity.GID
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: resource.ID, PlanID: plan.ID, Generation: generation, ConfigDigest: resource.CurrentConfigDigest, Domains: domains, Binding: binding, CertificateIdentity: certificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + certificateID, BaseMarkers: baseSnapshot(*safetyResource)})
	if err != nil {
		return fail(err)
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.Publish, Target: "resource/" + resource.ID, ActorIdentity: authority, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{ResourceID: resource.ID, PlanID: plan.ID, IntentGeneration: generation, CandidateDigest: prepared.Safety.SANIdentity, CandidateBundle: bindingDigest, ChallengeMethod: string(binding.Method), CertificateIdentity: certificateID, Deadline: plan.ExpiresAt}, ExpectedRevision: document.Revision})
	if job.ID != "" {
		admittedJobID = job.ID
	}
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(fmt.Errorf("certificate admission: %v %v", err, releaseErr))
	}
	cleanup = func() error {
		return cleanupCertificateSetup(context.WithoutCancel(ctx), service, admitter, job.ID, resource.ID, prepared, []operations.ChildRecord{childRecord})
	}
	mutationSet, err = operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		_ = mutationSet.Close()
		return fail(err)
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	_, freshResource, err := loadCertificateResource(fresh.Entries, resource.ID)
	if err != nil || freshResource.CurrentConfigDigest != plan.Config.Digest || freshResource.Publication.DomainHTTPS == nil {
		return fail(fmt.Errorf("certificate Plan config changed"))
	}
	freshDomains := append([]string{freshResource.Publication.DomainHTTPS.CanonicalDomain}, freshResource.Publication.DomainHTTPS.Aliases...)
	sort.Strings(freshDomains)
	if !slices.Equal(freshDomains, domains) {
		return fail(fmt.Errorf("certificate Plan SAN changed"))
	}
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		return fail(err)
	}
	childID := "lego-" + job.ID
	childRecord = operations.ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: childID, JobID: job.ID, InstallationID: installation.InstallationID, Operation: operations.Publish, Target: "resource/" + resource.ID, IntentGeneration: intent.IntentGeneration, Profile: string(child.ProfileLego), InputDigest: bindingDigest, ArtifactDigest: bindingDigest, Deadline: plan.ExpiresAt, State: operations.ChildSubmitted, SubmittedAt: time.Now().UTC()}
	if err := admitter.BindOperationIdentity(ctx, mutation, exposure, intent.IntentGeneration, job.ID, bindingDigest); err != nil {
		return fail(err)
	}
	candidatePath, err := certificates.BundlePath(certificateID, 1)
	if err != nil {
		return fail(err)
	}
	certificateJournal := &operations.CertificateJournalIdentity{CertificateID: certificateID, CandidateGeneration: 1, CandidatePointer: candidatePath, Challenge: prepared.Safety, StageUID: stageUID, StageGID: stageGID}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + job.ID, JobID: job.ID, Kind: operations.JournalCertificateActivation, Operation: operations.Publish, InstallationID: installation.InstallationID, Target: "resource/" + resource.ID, Generation: intent.IntentGeneration, Deadline: plan.ExpiresAt, ArtifactDigest: bindingDigest, ResourceIDs: []string{resource.ID}, ChildIDs: []string{childID}, Phase: operations.JournalPrepared, Certificate: certificateJournal}
	identityDocument, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	if identityDocument.Revision != intent.IntentGeneration+1 {
		return fail(fmt.Errorf("certificate identity allocation revision changed"))
	}
	if err := validateCertificateStageIdentity(identityDocument, stageIdentity); err != nil {
		return fail(err)
	}
	if err := admitter.PutJournal(ctx, mutation, exposure, identityDocument.Revision, journal, true); err != nil {
		return fail(err)
	}
	if err := operations.ReleaseExposure(mutation, exposure); err != nil {
		return fail(err)
	}
	mutation = nil
	exposure = nil
	admission, err = service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	if err := admitter.ReserveChild(ctx, admission, intent.IntentGeneration+2, childRecord); err != nil {
		_ = admission.Release()
		return fail(err)
	}
	if err := admission.Release(); err != nil {
		return fail(err)
	}
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return fail(err)
	}
	freshState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return fail(err)
	}
	next := freshState
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), freshState.Resources...)
	matched := false
	for index := range next.Resources {
		if next.Resources[index].ResourceID == resource.ID {
			if next.Resources[index].GenerationSequence+1 != generation || !reflect.DeepEqual(baseSnapshot(next.Resources[index]), prepared.Safety.BaseMarkers) {
				return fail(fmt.Errorf("certificate generation or base-marker snapshot changed"))
			}
			next.Resources[index].GenerationSequence = generation
			next.Resources[index].ChallengePending = &prepared.Safety
			matched = true
		}
	}
	if !matched {
		return fail(fmt.Errorf("certificate resource disappeared"))
	}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleChallenge, freshState.Revision, next, safety.TransitionProof{}); err != nil {
		return fail(err)
	}
	cleanup = nil
	return &CertificateExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Operation: operations.Publish, Revision: intent.IntentGeneration + 3, Resource: resource, Binding: binding, Challenge: prepared, InstallationID: installation.InstallationID, Plan: plan, Deadline: plan.ExpiresAt, BundleGeneration: 1, StageUID: stageUID, StageGID: stageGID, Child: childRecord, LegoDigest: legoDigest}, nil
}

func bindingFromCertificateAuthority(authority *domain.CertificateAuthorityIdentity) (acme.Binding, error) {
	if authority == nil || !authority.TermsAccepted {
		return acme.Binding{}, fmt.Errorf("applied certificate authority missing")
	}
	accountContact, accountKeyFingerprint, err := readManagedACMEAccountAuthority()
	if err != nil || authority.AccountEmail != accountContact || authority.AccountKeyPath != acmeaccount.ManagedKeyPath || authority.AccountKeyFingerprint != accountKeyFingerprint {
		return acme.Binding{}, fmt.Errorf("applied certificate ACME account authority changed")
	}
	if authority.Method == string(acme.ChallengeHTTP01) {
		binding, err := acme.LoadHTTPBinding(authority.DirectoryURL, authority.AccountKeyPath, authority.AccountEmail, authority.TermsAccepted)
		if err != nil {
			return acme.Binding{}, err
		}
		return binding, nil
	}
	provider, err := acme.ParseDNSProvider(authority.Provider)
	if err != nil {
		return acme.Binding{}, err
	}
	binding, err := acme.LoadDNSBinding(authority.DirectoryURL, authority.AccountKeyPath, authority.AccountEmail, authority.TermsAccepted, provider, authority.ProfilePath, authority.Zone)
	if err != nil {
		return acme.Binding{}, err
	}
	return binding, nil
}

func BeginCertificateRenew(ctx context.Context, resourceID string) (*CertificateExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	var cleanup func() error
	var mutationSet *operations.MutationSet
	var mutation *operations.MutationLease
	var exposure *locks.Lease
	var childRecord operations.ChildRecord
	fail := func(cause error) (*CertificateExecution, error) {
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		mutation = nil
		exposure = nil
		if mutationSet != nil {
			releaseErr = errors.Join(releaseErr, mutationSet.Close())
			mutationSet = nil
		}
		if cleanup != nil {
			releaseErr = errors.Join(releaseErr, cleanup())
		}
		releaseErr = errors.Join(releaseErr, service.Close())
		return nil, errors.Join(cause, releaseErr)
	}
	legoDigest, err := loadCertificateLegoDigest()
	if err != nil {
		return fail(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	installation, resource, err := loadCertificateResource(document.Entries, resourceID)
	if err != nil {
		return fail(err)
	}
	if len(resource.PublicationRecord.PendingGoAccessRetirements) != 0 {
		return fail(fmt.Errorf("certificate renewal is blocked by pending GoAccess retirement"))
	}
	state, err := service.safety.Read()
	if err != nil {
		return fail(err)
	}
	decision, err := renewal.Evaluate(renewal.Input{Now: time.Now().UTC(), RenewBefore: 30 * 24 * time.Hour, Publication: resource.PublicationRecord, Safety: state, ResourceID: resource.ID})
	if err != nil || decision != renewal.DecisionRenew {
		return fail(fmt.Errorf("certificate is not eligible for timer renewal"))
	}
	applied := resource.PublicationRecord.LastAppliedBundle
	prior := applied.DomainHTTPS.Certificate
	if prior.Authority == nil || prior.Authority.CertificateID == "" || prior.Generation == 0 {
		return fail(fmt.Errorf("applied certificate renewal authority incomplete"))
	}
	stageIdentity, err := identity.CertificateStageIdentityFor(prior.Authority.CertificateID)
	if err != nil {
		return fail(err)
	}
	stageUID, stageGID := stageIdentity.UID, stageIdentity.GID
	binding, err := bindingFromCertificateAuthority(prior.Authority)
	if err != nil {
		return fail(err)
	}
	bindingDigest, err := acme.BindingDigest(binding)
	if err != nil || bindingDigest != prior.BindingIdentity {
		return fail(fmt.Errorf("applied ACME binding changed"))
	}
	domains := append([]string(nil), applied.DomainHTTPS.ExactDomains...)
	sort.Strings(domains)
	var safetyResource *safety.ResourceSafety
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resource.ID {
			safetyResource = &state.Resources[index]
		}
	}
	if safetyResource == nil || safetyResource.ActiveCertificate == nil || safetyResource.ActiveCertificate.Generation != prior.Generation || safetyResource.ActiveCertificate.Fingerprint != prior.Fingerprint || safetyResource.ActiveCertificate.Binding != prior.BindingIdentity {
		return fail(fmt.Errorf("renewal safety resource missing or stale"))
	}
	safetyGeneration := safetyResource.GenerationSequence + 1
	prepared, err := challenge.Prepare(challenge.Request{ResourceID: resource.ID, PlanID: prior.Authority.CertificateID, Generation: safetyGeneration, ConfigDigest: applied.ConfigDigest, Domains: domains, Binding: binding, CertificateIdentity: prior.Authority.CertificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + prior.Authority.CertificateID, BaseMarkers: baseSnapshot(*safetyResource)})
	if err != nil {
		return fail(err)
	}
	deadline, err := time.Parse(time.RFC3339, prior.NotAfter)
	if err != nil {
		return fail(err)
	}
	now := time.Now().UTC()
	operationDeadline := now.Add(10 * time.Minute)
	latestRemote := deadline.Add(-5 * time.Minute)
	if latestRemote.Before(operationDeadline) {
		operationDeadline = latestRemote
	}
	if !operationDeadline.After(now.Add(time.Minute)) {
		return fail(fmt.Errorf("certificate renewal deadline insufficient"))
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return fail(err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.CertificateRenew, Target: "resource/" + resource.ID, ActorIdentity: "timer/certificate-renewal", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ResourceID: resource.ID, PlanID: prior.Authority.CertificateID, IntentGeneration: safetyGeneration, CandidateDigest: prepared.Safety.SANIdentity, CandidateBundle: bindingDigest, ChallengeMethod: string(binding.Method), CertificateIdentity: prior.Authority.CertificateID, Deadline: operationDeadline}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	cleanup = func() error {
		return cleanupCertificateSetup(context.WithoutCancel(ctx), service, admitter, job.ID, resource.ID, prepared, []operations.ChildRecord{childRecord})
	}
	mutationSet, err = operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return fail(err)
	}
	fresh, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	_, freshResource, err := loadCertificateResource(fresh.Entries, resource.ID)
	if err != nil || freshResource.PublicationRecord.State != domain.PublicationPublished || freshResource.PublicationRecord.LastAppliedBundle == nil || freshResource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil || !reflect.DeepEqual(freshResource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate, prior) {
		return fail(fmt.Errorf("applied certificate changed before renewal"))
	}
	priorTarget, err := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation)
	if err != nil {
		return fail(err)
	}
	activeTarget, err := certificates.ObservePointer(prior.Authority.CertificateID)
	if err != nil || activeTarget != priorTarget {
		return fail(fmt.Errorf("applied certificate pointer changed before renewal: %w", err))
	}
	if err := certificates.VerifyBundleIdentity(prior.Authority.CertificateID, prior.Generation, certificateBundleIdentity(prior)); err != nil {
		return fail(err)
	}
	intent, err := admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		return fail(err)
	}
	childID := "lego-" + job.ID
	childRecord = operations.ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: childID, JobID: job.ID, InstallationID: installation.InstallationID, Operation: operations.CertificateRenew, Target: "resource/" + resource.ID, IntentGeneration: intent.IntentGeneration, Profile: string(child.ProfileLego), InputDigest: bindingDigest, ArtifactDigest: bindingDigest, Deadline: operationDeadline, State: operations.ChildSubmitted, SubmittedAt: time.Now().UTC()}
	if err := admitter.BindOperationIdentity(ctx, mutation, exposure, intent.IntentGeneration, job.ID, bindingDigest); err != nil {
		return fail(err)
	}
	priorPath, err := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation)
	if err != nil {
		return fail(err)
	}
	candidatePath, err := certificates.BundlePath(prior.Authority.CertificateID, prior.Generation+1)
	if err != nil {
		return fail(err)
	}
	certificateJournal := &operations.CertificateJournalIdentity{CertificateID: prior.Authority.CertificateID, PriorGeneration: prior.Generation, CandidateGeneration: prior.Generation + 1, PriorPointer: priorPath, CandidatePointer: candidatePath, PriorFingerprint: prior.Fingerprint, PriorBundleIdentity: certificateBundleIdentity(prior), Challenge: prepared.Safety, StageUID: stageUID, StageGID: stageGID}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + job.ID, JobID: job.ID, Kind: operations.JournalCertificateActivation, Operation: operations.CertificateRenew, InstallationID: installation.InstallationID, Target: "resource/" + resource.ID, Generation: intent.IntentGeneration, Deadline: operationDeadline, ArtifactDigest: bindingDigest, ResourceIDs: []string{resource.ID}, ChildIDs: []string{childID}, Phase: operations.JournalPrepared, Certificate: certificateJournal}
	identityDocument, err := service.normal.Read()
	if err != nil {
		return fail(err)
	}
	if identityDocument.Revision != intent.IntentGeneration+1 {
		return fail(fmt.Errorf("certificate identity allocation revision changed"))
	}
	if err := validateCertificateStageIdentity(identityDocument, stageIdentity); err != nil {
		return fail(err)
	}
	if err := admitter.PutJournal(ctx, mutation, exposure, identityDocument.Revision, journal, true); err != nil {
		return fail(err)
	}
	if err := operations.ReleaseExposure(mutation, exposure); err != nil {
		return fail(err)
	}
	mutation = nil
	exposure = nil
	admission, err = service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	reserveErr := admitter.ReserveChild(ctx, admission, intent.IntentGeneration+2, childRecord)
	releaseErr = admission.Release()
	if reserveErr != nil || releaseErr != nil {
		return fail(errors.Join(reserveErr, releaseErr))
	}
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "resource/"+resource.ID, service.manager)
	if err != nil {
		return fail(err)
	}
	freshState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return fail(err)
	}
	next := freshState
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), freshState.Resources...)
	matched := false
	for index := range next.Resources {
		if next.Resources[index].ResourceID == resource.ID {
			if next.Resources[index].GenerationSequence+1 != safetyGeneration || !reflect.DeepEqual(baseSnapshot(next.Resources[index]), prepared.Safety.BaseMarkers) {
				return fail(fmt.Errorf("renewal safety generation or base-marker snapshot changed"))
			}
			next.Resources[index].GenerationSequence = safetyGeneration
			next.Resources[index].ChallengePending = &prepared.Safety
			matched = true
		}
	}
	if !matched {
		return fail(fmt.Errorf("renewal safety resource disappeared"))
	}
	if _, err := service.safety.Commit(ctx, exposure, safety.RoleChallenge, freshState.Revision, next, safety.TransitionProof{}); err != nil {
		return fail(err)
	}
	cleanup = nil
	priorCopy := prior
	return &CertificateExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Operation: operations.CertificateRenew, Revision: intent.IntentGeneration + 3, Resource: resource, Binding: binding, Challenge: prepared, InstallationID: installation.InstallationID, Deadline: operationDeadline, BundleGeneration: prior.Generation + 1, PriorCertificate: &priorCopy, StageUID: stageUID, StageGID: stageGID, Child: childRecord, LegoDigest: legoDigest}, nil
}

const certificateReservationCleanupTimeout = time.Minute

func findCertificateExpiryIntent(document persist.Document, resourceID string, expiryGeneration uint64) (operations.Reservation, bool, error) {
	var result operations.Reservation
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var candidate operations.Reservation
		if err := json.Unmarshal(raw, &candidate); err != nil {
			return operations.Reservation{}, false, err
		}
		if candidate.Operation != operations.CertificateExpiry || candidate.SafetyBinding.ResourceID != resourceID || candidate.SafetyBinding.ExpiryGeneration != expiryGeneration {
			continue
		}
		if result.JobID != "" {
			return operations.Reservation{}, false, fmt.Errorf("multiple certificate expiry intents for resource %q generation %d", resourceID, expiryGeneration)
		}
		result = candidate
	}
	return result, result.JobID != "", nil
}

func certificateExpiryContractionGenerations(installation domain.Installation, state safety.State, resourceID string, intent operations.Reservation) (map[string]uint64, error) {
	if intent.JobID == "" {
		return contractionGenerations(installation, state, []string{resourceID})
	}
	var normalResource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == resourceID {
			normalResource = &installation.Resources[index]
			break
		}
	}
	var safetyResource *safety.ResourceSafety
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resourceID {
			safetyResource = &state.Resources[index]
			break
		}
	}
	if normalResource == nil || safetyResource == nil {
		return nil, fmt.Errorf("resumed certificate expiry resource authority is missing")
	}
	if contractionIntent := normalResource.PublicationRecord.ContractionIntent; contractionIntent != nil {
		generation := contractionIntent.Generation
		expectedGeneration := intent.SafetyBinding.ExpiryGeneration + 1
		if intent.SafetyBinding.ExpiryGeneration == 0 || generation != expectedGeneration || normalResource.PublicationRecord.State != domain.PublicationUnpublished || normalResource.PublicationRecord.UnpublishedGeneration != generation || contractionIntent.JobID != intent.JobID || contractionIntent.Operation != string(operations.CertificateExpiry) || intent.ContractionDigest == "" || contractionIntent.ClosureAuthorityDigest != intent.ContractionDigest {
			return nil, fmt.Errorf("resumed certificate expiry normal contraction authority changed")
		}
		closing := safetyResource.Closing != nil && safetyResource.Closing.Generation == generation
		closed := safetyResource.StickyUnpublished != nil && safetyResource.StickyUnpublished.Generation == generation
		if !closing && !closed {
			return nil, fmt.Errorf("resumed certificate expiry safety contraction authority changed")
		}
		return map[string]uint64{resourceID: generation}, nil
	}
	if safetyResource.Closing != nil {
		expectedGeneration := intent.SafetyBinding.ExpiryGeneration + 1
		if intent.ContractionDigest != "" || intent.SafetyBinding.ExpiryGeneration == 0 || safetyResource.Closing.Generation != expectedGeneration {
			return nil, fmt.Errorf("resumed certificate expiry closing authority changed")
		}
		return map[string]uint64{resourceID: expectedGeneration}, nil
	}
	if safetyResource.Closing == nil && safetyResource.StickyUnpublished != nil {
		expectedGeneration := intent.SafetyBinding.ExpiryGeneration + 1
		if intent.ContractionDigest != "" || intent.SafetyBinding.ExpiryGeneration == 0 || safetyResource.StickyUnpublished.Generation != expectedGeneration {
			return nil, fmt.Errorf("resumed certificate expiry closed authority changed")
		}
		return map[string]uint64{resourceID: expectedGeneration}, nil
	}
	if intent.ContractionDigest != "" {
		return nil, fmt.Errorf("resumed certificate expiry lost committed normal contraction authority")
	}
	return contractionGenerations(installation, state, []string{resourceID})
}

type certificateContractionCleanup struct {
	mutationSet     *operations.MutationSet
	mutation        *operations.MutationLease
	exposure        *locks.Lease
	reservedJobID   string
	planlessStarted bool
	rejectReserved  func(string) error
	closeService    func() error
}

func (cleanup *certificateContractionCleanup) Close() error {
	if cleanup == nil {
		return nil
	}
	var result error
	if cleanup.mutation != nil || cleanup.exposure != nil {
		result = errors.Join(result, operations.ReleaseExposure(cleanup.mutation, cleanup.exposure))
		cleanup.mutation = nil
		cleanup.exposure = nil
	}
	if cleanup.mutationSet != nil {
		result = errors.Join(result, cleanup.mutationSet.Close())
		cleanup.mutationSet = nil
	}
	if cleanup.reservedJobID != "" && !cleanup.planlessStarted && cleanup.rejectReserved != nil {
		jobID := cleanup.reservedJobID
		cleanup.reservedJobID = ""
		result = errors.Join(result, cleanup.rejectReserved(jobID))
	}
	if cleanup.closeService != nil {
		closeService := cleanup.closeService
		cleanup.closeService = nil
		result = errors.Join(result, closeService())
	}
	return result
}

func rejectReservedCertificateExpiry(ctx context.Context, service *FixedService, admitter *operations.Admitter, jobID, code string) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), certificateReservationCleanupTimeout)
	defer cancel()
	intent, err := admitter.OperationIntent(jobID)
	if err != nil {
		return err
	}
	if intent.Phase != operations.PhaseReserved {
		return nil
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	admission, err := service.manager.Acquire(cleanupCtx, locks.MutationAdmission)
	if err != nil {
		return err
	}
	rejectErr := admitter.RejectReservation(cleanupCtx, admission, document.Revision, jobID, code)
	return errors.Join(rejectErr, admission.Release())
}

func commitDiscrepantCertificateExpiryMarker(ctx context.Context, service *FixedService, resourceID string, certificate domain.CertificateBundleIdentity, expiryGeneration uint64, deadline time.Time) (returnErr error) {
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	cleanup := &certificateContractionCleanup{mutationSet: mutationSet}
	defer func() { returnErr = errors.Join(returnErr, cleanup.Close()) }()
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resourceID, service.manager)
	if err != nil {
		return err
	}
	cleanup.mutation = mutation
	cleanup.exposure = exposure
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	_, resource, err := loadCertificateResource(document.Entries, resourceID)
	if err != nil {
		return fmt.Errorf("discrepant certificate expiry normal authority changed: %w", err)
	}
	if resource.PublicationRecord.State != domain.PublicationPublished || resource.PublicationRecord.LastAppliedBundle == nil || resource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil || !reflect.DeepEqual(resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate, certificate) {
		return fmt.Errorf("discrepant certificate expiry normal authority changed")
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := state
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	for index := range next.Resources {
		current := &next.Resources[index]
		if current.ResourceID != resourceID {
			continue
		}
		if current.CertificateExpiry != nil {
			if current.CertificateExpiry.Generation == expiryGeneration && current.CertificateExpiry.Deadline.Equal(deadline) && current.CertificateExpiry.Binding == certificate.BindingIdentity {
				return nil
			}
			return fmt.Errorf("discrepant certificate expiry marker changed")
		}
		if current.ActiveCertificate == nil || current.ActiveCertificate.Generation != certificate.Generation || current.ActiveCertificate.Fingerprint != certificate.Fingerprint || current.ActiveCertificate.Binding != certificate.BindingIdentity || current.GenerationSequence+1 != expiryGeneration {
			return fmt.Errorf("discrepant certificate expiry safety authority changed")
		}
		current.GenerationSequence = expiryGeneration
		current.CertificateExpiry = &safety.DeadlineMarker{Generation: expiryGeneration, Deadline: deadline, Binding: certificate.BindingIdentity}
		next.Revision++
		_, err = service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
		return err
	}
	return fmt.Errorf("discrepant certificate expiry resource disappeared")
}

func certificateExpirySafetyClosed(state safety.State, resourceID string, generation uint64) bool {
	if state.StopFence != nil {
		return false
	}
	for _, resource := range state.Resources {
		if resource.ResourceID == resourceID {
			return resource.Closing == nil && resource.StickyUnpublished != nil && resource.StickyUnpublished.Generation == generation
		}
	}
	return false
}

func finishExpiredCertificateContraction(ctx context.Context, service *FixedService, exposure *locks.Lease, authority *contraction.NormalAuthority, inventory closure.Inventory, installation domain.Installation, resourceID, jobID string, result contraction.Result, runErr error) error {
	goaccessGenerations := goAccessContractionInventory(installation, []string{resourceID})
	result, runErr, cleanupComplete := stopGoAccessAfterClosure(ctx, goaccessGenerations, result, runErr)
	if cleanupComplete {
		if pruneErr := pruneGoAccessContractionOwnership(ctx, service, exposure, jobID, goaccessGenerations); pruneErr != nil {
			cleanupComplete = false
			if result.AccessClosed {
				result.Outcome = contraction.OutcomePartial
				result.ErrorCode = "goaccess_stop_failed"
			}
			runErr = errors.Join(runErr, pruneErr)
		}
	}
	if !cleanupComplete && !result.AccessClosed {
		return runErr
	}
	recoveryCtx, cancelRecovery := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	_, recoveredPaths, recoveryErr := nginx.Contract(recoveryCtx, nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}, []string{resourceID})
	cancelRecovery()
	if recoveryErr != nil {
		return errors.Join(runErr, recoveryErr)
	}
	result.ModifiedPaths = append(result.ModifiedPaths, recoveredPaths...)
	_, completeErr := contraction.CompleteNormal(ctx, authority, result)
	if completeErr != nil {
		return errors.Join(runErr, completeErr)
	}
	if acknowledgeErr := nginx.AcknowledgeContraction(context.WithoutCancel(ctx), nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0}, []string{resourceID}); acknowledgeErr != nil {
		return errors.Join(runErr, acknowledgeErr)
	}
	if nextState, ownershipErr := contractClosedPublicationOwnership(ctx, service, exposure, resourceID, jobID, authority.Generations[resourceID]); ownershipErr != nil {
		return errors.Join(runErr, ownershipErr)
	} else {
		authority.SafetyState = nextState
	}
	if convergeErr := authority.ConvergeClosure(context.WithoutCancel(ctx), inventory, result.ClosureDigest); convergeErr != nil {
		return errors.Join(runErr, convergeErr)
	}
	if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
		return nil
	}
	return runErr
}

func ContractExpiredCertificate(ctx context.Context, resourceID string, now time.Time) (returnErr error) {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	var admitter *operations.Admitter
	var mutationSet *operations.MutationSet
	var mutation *operations.MutationLease
	var exposure *locks.Lease
	cleanup := &certificateContractionCleanup{closeService: service.Close}
	cleanup.rejectReserved = func(jobID string) error {
		return rejectReservedCertificateExpiry(ctx, service, admitter, jobID, "certificate_setup_failed")
	}
	defer func() { returnErr = errors.Join(returnErr, cleanup.Close()) }()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	installation, resource, err := loadCertificateResource(document.Entries, resourceID)
	if err != nil {
		return err
	}
	if resource.PublicationRecord.LastAppliedBundle == nil || resource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil {
		return nil
	}
	certificate := resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate
	deadline, deadlineErr := time.Parse(time.RFC3339, certificate.NotAfter)
	lastWall, wallErr := time.Parse(time.RFC3339, certificate.LastTrustedWall)
	if deadlineErr != nil || wallErr != nil {
		return fmt.Errorf("certificate deadline evidence invalid")
	}
	effectiveDeadline := deadline
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	var safetyResource *safety.ResourceSafety
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resourceID {
			safetyResource = &state.Resources[index]
		}
	}
	if safetyResource == nil || safetyResource.ActiveCertificate == nil || safetyResource.ActiveCertificate.Generation != certificate.Generation || safetyResource.ActiveCertificate.Fingerprint != certificate.Fingerprint || safetyResource.ActiveCertificate.Binding != certificate.BindingIdentity {
		return fmt.Errorf("certificate expiry safety authority missing or stale")
	}
	active := safetyResource.ActiveCertificate
	if !active.NotAfter.Equal(deadline) || active.LastTrustedWall.Before(lastWall) || now.Before(active.LastTrustedWall) {
		effectiveDeadline = now
	} else {
		effectiveDeadline = active.NotAfter
	}
	expiryGeneration := safetyResource.GenerationSequence + 1
	markerNeeded := true
	if safetyResource.CertificateExpiry != nil {
		if safetyResource.CertificateExpiry.Binding != certificate.BindingIdentity {
			return fmt.Errorf("certificate expiry binding changed")
		}
		expiryGeneration = safetyResource.CertificateExpiry.Generation
		effectiveDeadline = safetyResource.CertificateExpiry.Deadline
		markerNeeded = false
	}
	existing, foundExisting, err := findCertificateExpiryIntent(document, resourceID, expiryGeneration)
	if err != nil {
		return err
	}
	if foundExisting && markerNeeded {
		effectiveDeadline = existing.SafetyBinding.Deadline
	}
	if markerNeeded && effectiveDeadline.After(now) && !foundExisting {
		return nil
	}
	if !foundExisting && markerNeeded && !effectiveDeadline.Equal(active.NotAfter) {
		if err := commitDiscrepantCertificateExpiryMarker(ctx, service, resourceID, certificate, expiryGeneration, effectiveDeadline); err != nil {
			return err
		}
	}
	highWater, highWaterPresent, err := operations.ExpiryGenerationHighWater(document, resourceID)
	if err != nil {
		return err
	}
	if highWaterPresent && highWater.ExpiryGeneration >= expiryGeneration && !foundExisting {
		if highWater.ExpiryGeneration != expiryGeneration {
			return fmt.Errorf("certificate expiry generation high-water is ahead of safety authority")
		}
		if resource.PublicationRecord.State != domain.PublicationPublished {
			return nil
		}
		return fmt.Errorf("recorded certificate expiry without unpublished state requires independent contraction")
	}
	admitter, err = service.TimerAdmitter()
	if err != nil {
		return err
	}
	if foundExisting {
		switch existing.Phase {
		case operations.PhaseReserved:
			if err := rejectReservedCertificateExpiry(ctx, service, admitter, existing.JobID, "certificate_executor_interrupted"); err != nil {
				return err
			}
			if resource.PublicationRecord.State != domain.PublicationPublished {
				return nil
			}
			return fmt.Errorf("recovered reserved certificate expiry requires independent contraction")
		case operations.PhaseLocalIntent:
			if existing.Target != "resource/"+resourceID || existing.SafetyBinding.CandidateBundle != certificate.BindingIdentity || !existing.SafetyBinding.Deadline.Equal(effectiveDeadline) {
				return fmt.Errorf("certificate expiry intent authority conflicts with generation %d", expiryGeneration)
			}
			cleanup.planlessStarted = true
		case operations.PhaseTerminal, operations.PhaseRejected:
			if resource.PublicationRecord.State != domain.PublicationPublished {
				return nil
			}
			return fmt.Errorf("terminal certificate expiry without unpublished state requires independent contraction")
		default:
			return fmt.Errorf("certificate expiry intent has unsupported phase %q", existing.Phase)
		}
	} else if resource.PublicationRecord.State != domain.PublicationPublished {
		return nil
	}
	var job jobs.Record
	if foundExisting {
		job.ID = existing.JobID
	} else {
		admission, acquireErr := service.manager.Acquire(ctx, locks.MutationAdmission)
		if acquireErr != nil {
			return acquireErr
		}
		job, err = admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.CertificateExpiry, Target: "resource/" + resourceID, ActorIdentity: "timer/certificate-expiry", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ResourceID: resourceID, ExpiryGeneration: expiryGeneration, Deadline: effectiveDeadline, CandidateBundle: certificate.BindingIdentity}, ExpectedRevision: document.Revision})
		if job.ID != "" {
			cleanup.reservedJobID = job.ID
		}
		releaseErr := admission.Release()
		if err != nil || releaseErr != nil {
			return errors.Join(err, releaseErr)
		}
	}
	mutationSet, err = operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	cleanup.mutationSet = mutationSet
	mutation, exposure, err = mutationSet.AcquireExposure(ctx, "resource/"+resourceID, service.manager)
	if err != nil {
		return err
	}
	cleanup.mutation = mutation
	cleanup.exposure = exposure
	freshState, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := freshState
	found := false
	markerNeeded = true
	next.Resources = append([]safety.ResourceSafety(nil), freshState.Resources...)
	for index := range next.Resources {
		current := &next.Resources[index]
		if current.ResourceID == resourceID {
			if current.ActiveCertificate == nil || current.ActiveCertificate.Generation != certificate.Generation || current.ActiveCertificate.Fingerprint != certificate.Fingerprint || current.ActiveCertificate.Binding != certificate.BindingIdentity {
				return fmt.Errorf("certificate expiry safety authority changed under lock")
			}
			if current.CertificateExpiry == nil {
				if current.GenerationSequence+1 != expiryGeneration {
					return fmt.Errorf("certificate expiry generation changed")
				}
				current.GenerationSequence = expiryGeneration
				current.CertificateExpiry = &safety.DeadlineMarker{Generation: expiryGeneration, Deadline: effectiveDeadline, Binding: certificate.BindingIdentity}
			} else {
				markerNeeded = false
				if current.CertificateExpiry.Generation != expiryGeneration || !current.CertificateExpiry.Deadline.Equal(effectiveDeadline) || current.CertificateExpiry.Binding != certificate.BindingIdentity {
					return fmt.Errorf("certificate expiry marker changed")
				}
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("certificate expiry resource disappeared")
	}
	committedState := next
	freshDocument, err := service.normal.Read()
	if err != nil {
		return err
	}
	freshInstallation, freshResource, err := loadCertificateResource(freshDocument.Entries, resourceID)
	if err != nil {
		return fmt.Errorf("certificate expiry normal authority changed under lock: %w", err)
	}
	freshPublished := freshResource.PublicationRecord.State == domain.PublicationPublished
	freshUnpublishedRecovery := foundExisting && freshResource.PublicationRecord.State == domain.PublicationUnpublished
	if (!freshPublished && !freshUnpublishedRecovery) || freshResource.PublicationRecord.LastAppliedBundle == nil || freshResource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil || !reflect.DeepEqual(freshResource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate, certificate) {
		return fmt.Errorf("certificate expiry normal authority changed under lock")
	}
	installation = freshInstallation
	if foundExisting {
		lockedIntent, present, findErr := findCertificateExpiryIntent(freshDocument, resourceID, expiryGeneration)
		if findErr != nil {
			return fmt.Errorf("certificate expiry recovery intent changed under lock: %w", findErr)
		}
		if !present || lockedIntent.JobID != job.ID || lockedIntent.Phase != operations.PhaseLocalIntent {
			return fmt.Errorf("certificate expiry recovery intent changed under lock")
		}
		existing = lockedIntent
	}
	owned, err := service.ownership.Inventory()
	if err != nil {
		return err
	}
	manifest, graphErr := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
	var graph *nginx.Manifest
	if graphErr == nil {
		graph = &manifest
	}
	inventoryInstallation := installation
	if foundExisting && existing.ContractionDigest != "" {
		inventoryInstallation.Resources = append([]domain.AppResource(nil), installation.Resources...)
		for index := range inventoryInstallation.Resources {
			if inventoryInstallation.Resources[index].ID == resourceID {
				inventoryInstallation.Resources[index].PublicationRecord.ContractionIntent = nil
			}
		}
	}
	inventory, inventoryErr := closure.BuildInventory(closure.Inputs{Installation: inventoryInstallation, Safety: &committedState, Ownership: owned, Graph: graph, ResourceIDs: []string{resourceID}})
	if inventoryErr != nil {
		inventory = closure.BuildFallbackInventory(closure.Inputs{Installation: inventoryInstallation, Safety: &committedState, Ownership: owned, Graph: graph, ResourceIDs: []string{resourceID}}, inventoryErr)
	}
	checksums := map[string]string{}
	authorities := []preflight.OwnedIngressAuthority{}
	for _, record := range owned.Records {
		if record.ResourceID == resourceID {
			checksums[record.ResourceID] = record.Checksum
			authorities = append(authorities, preflight.OwnedIngressAuthority{ResourceID: resourceID, RuntimeIdentity: inventory.Digest, OwnershipDigest: record.Checksum})
		}
	}
	request := preflight.ContractionRequest{Kind: preflight.ContractionExpiry, Target: "resource/" + resourceID, Generation: expiryGeneration, OwnershipInventoryDigest: safety.OwnershipInventoryDigest(checksums), ClosureAuthorityDigest: inventory.Digest, OwnedIngress: authorities, FallbackStop: graphErr != nil || inventoryErr != nil || !inventory.Complete}
	result, err := preflight.EvaluateContraction(request, preflight.ContractionObservations{ExecutorUID: uint32(os.Geteuid()), InventoryComplete: owned.Complete, OwnershipInventoryDigest: request.OwnershipInventoryDigest, ClosureAuthorityDigest: inventory.Digest, OwnedIngress: authorities, ObservedAt: now})
	if err != nil {
		return err
	}
	if !foundExisting {
		if _, err = admitter.BeginPlanless(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: freshDocument.Revision, IntentGeneration: freshDocument.Revision + 1, ContractionRequest: &request, ContractionPreflight: &result}); err != nil {
			return err
		}
		cleanup.planlessStarted = true
	}
	if markerNeeded {
		next.Revision++
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleCertificateActivation, freshState.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
		committedState = next
	}
	latestDocument, err := service.normal.Read()
	if err != nil {
		return err
	}
	generationIntent := operations.Reservation{}
	if foundExisting {
		generationIntent = existing
	}
	generations, generationErr := certificateExpiryContractionGenerations(installation, committedState, resourceID, generationIntent)
	if generationErr != nil {
		inventory = closure.BuildFallbackInventory(closure.Inputs{Installation: inventoryInstallation, Safety: &committedState, Ownership: owned, Graph: graph, ResourceIDs: []string{resourceID}}, generationErr)
	}
	authority := &contraction.NormalAuthority{Safety: service.safety, Emergency: service.emergency, Admitter: admitter, Mutation: mutation, Exposure: exposure, JobID: job.ID, Operation: operations.CertificateExpiry, Revision: latestDocument.Revision, SafetyState: committedState, Generations: generations}
	if generation, present := generations[resourceID]; generationErr == nil && foundExisting && present && certificateExpirySafetyClosed(committedState, resourceID, generation) {
		closureDigest := existing.ContractionDigest
		if closureDigest == "" {
			authority.InventoryDigest = inventory.Digest
			if err := authority.CommitUnpublished(ctx, inventory); err != nil {
				return err
			}
			closureDigest = inventory.Digest
		} else {
			authority.InventoryDigest = closureDigest
		}
		closed := contraction.Result{Outcome: contraction.OutcomeSucceeded, AccessClosed: true, ClosureDigest: closureDigest}
		return finishExpiredCertificateContraction(ctx, service, exposure, authority, inventory, installation, resourceID, job.ID, closed, nil)
	}
	runtime, err := contraction.FixedHost(inventory)
	if err != nil {
		runtime, err = contraction.FixedFallbackHost(inventory)
		if err != nil {
			return err
		}
	}
	contractionResult, runErr := (contraction.Engine{Authority: authority, Runtime: runtime}).Run(ctx, inventory)
	return finishExpiredCertificateContraction(ctx, service, exposure, authority, inventory, installation, resourceID, job.ID, contractionResult, runErr)
}

func cleanupCertificateSetup(ctx context.Context, service *FixedService, admitter *operations.Admitter, jobID, resourceID string, prepared challenge.Prepared, childRecords []operations.ChildRecord) error {
	intent, err := admitter.OperationIntent(jobID)
	if err != nil {
		return err
	}
	if intent.Phase == operations.PhaseReserved {
		document, err := service.normal.Read()
		if err != nil {
			return err
		}
		admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
		if err != nil {
			return err
		}
		rejectErr := admitter.RejectReservation(ctx, admission, document.Revision, jobID, "certificate_setup_failed")
		return errors.Join(rejectErr, admission.Release())
	}
	if intent.Phase != operations.PhaseLocalIntent {
		return fmt.Errorf("certificate setup cleanup found nonlocal phase %q", intent.Phase)
	}
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	journalPresent := false
	var journal operations.JournalRecord
	if raw, present := document.Entries["journals/certificate-"+jobID]; present {
		if err := json.Unmarshal(raw, &journal); err != nil {
			return err
		}
		journalPresent = true
	}
	for _, record := range childRecords {
		if record.ID == "" {
			continue
		}
		if _, present := document.Entries["children/"+record.ID]; present {
			continue
		}
		if !journalPresent {
			return fmt.Errorf("certificate child lacks journal")
		}
		admission, acquireErr := service.manager.Acquire(ctx, locks.MutationAdmission)
		if acquireErr != nil {
			return acquireErr
		}
		reserveErr := admitter.ReserveChild(ctx, admission, document.Revision, record)
		releaseErr := admission.Release()
		if err := errors.Join(reserveErr, releaseErr); err != nil {
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resourceID, service.manager)
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	for _, record := range childRecords {
		if record.ID == "" {
			continue
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
		raw, present := document.Entries["children/"+record.ID]
		if !present {
			continue
		}
		if err := json.Unmarshal(raw, &record); err != nil {
			return err
		}
		if record.State == operations.ChildTerminal {
			continue
		}
		record.State = operations.ChildTerminal
		record.Outcome = operations.ChildFailed
		now := time.Now().UTC()
		record.TerminalAt = &now
		sum := sha256.Sum256([]byte("certificate_setup_failed"))
		record.ResultDigest = "sha256:" + hex.EncodeToString(sum[:])
		if err := admitter.TransitionChild(ctx, mutation, exposure, document.Revision, record); err != nil {
			return err
		}
	}
	if journalPresent {
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
		journal.Phase = operations.JournalTerminal
		if err := admitter.PutJournal(ctx, mutation, exposure, document.Revision, journal, false); err != nil {
			return err
		}
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := state
	changed := false
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	for index := range next.Resources {
		if next.Resources[index].ResourceID == resourceID && next.Resources[index].ChallengePending != nil && challenge.Matches(*next.Resources[index].ChallengePending, prepared) {
			next.Resources[index].ChallengePending = nil
			changed = true
		}
	}
	if changed {
		next.Revision++
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleChallenge, state.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
	}
	document, err = service.normal.Read()
	if err != nil {
		return err
	}
	_, err = admitter.Complete(ctx, mutation, exposure, document.Revision, jobID, "no_effect", nil, []jobs.Postcondition{{Kind: "certificate_not_activated", Status: jobs.PostconditionVerified, Identity: resourceID}}, "certificate_setup_failed")
	return err
}

func (execution *CertificateExecution) AuthorizeStagedCertificate(ctx context.Context, identity certificates.Identity) error {
	if execution == nil || execution.Mutation == nil || execution.Exposure == nil || certificates.ValidateIdentity(identity) != nil || identity.ID != execution.Challenge.Safety.CertificateIdentity || identity.Generation != execution.BundleGeneration || identity.BindingIdentity != execution.Child.InputDigest {
		return fmt.Errorf("staged certificate authorization identity invalid")
	}
	document, err := execution.Service.normal.Read()
	if err != nil || document.Revision != execution.Revision {
		return fmt.Errorf("staged certificate authorization revision changed: %w", err)
	}
	raw, present := document.Entries["journals/certificate-"+execution.JobID]
	var journal operations.JournalRecord
	if !present || json.Unmarshal(raw, &journal) != nil || journal.Phase != operations.JournalPrepared || journal.Certificate == nil || journal.Certificate.CandidateFingerprint != "" || journal.Certificate.CandidateBundleIdentity != (certificates.BundleIdentity{}) || !reflect.DeepEqual(journal.Certificate.Challenge, execution.Challenge.Safety) {
		return fmt.Errorf("staged certificate journal authority changed")
	}
	journal.Certificate.CandidateFingerprint = identity.Fingerprint
	journal.Certificate.CandidateBundleIdentity = certificates.BundleIdentityFor(identity)
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return err
	}
	execution.Revision++
	return nil
}

func (execution *CertificateExecution) Reenter(ctx context.Context) (operations.Reservation, error) {
	return execution.reenter(ctx, false)
}

func (execution *CertificateExecution) reenter(ctx context.Context, http01Contraction bool) (operations.Reservation, error) {
	document, err := execution.Service.normal.Read()
	if err != nil {
		return operations.Reservation{}, err
	}
	var intent operations.Reservation
	var mutation *operations.MutationLease
	var exposure *locks.Lease
	if http01Contraction {
		intent, mutation, exposure, err = execution.Admitter.ReenterHTTP01Contraction(ctx, execution.MutationSet, execution.Service.manager, document.Revision, execution.JobID)
	} else {
		intent, mutation, exposure, err = execution.Admitter.Reenter(ctx, execution.MutationSet, execution.Service.manager, document.Revision, execution.JobID)
	}
	if err != nil {
		return operations.Reservation{}, err
	}
	execution.Mutation = mutation
	execution.Exposure = exposure
	execution.Revision = document.Revision + 1
	return intent, nil
}

func (execution *CertificateExecution) RunRemote(ctx context.Context, uid, gid uint32) (acme.IssueResult, error) {
	if uid != execution.StageUID || gid != execution.StageGID || uid == 0 || gid == 0 {
		return acme.IssueResult{}, fmt.Errorf("certificate stage identity changed")
	}
	if execution.Mutation != nil || execution.Exposure != nil {
		return acme.IssueResult{}, fmt.Errorf("remote ACME wait must not hold mutation or exposure lock")
	}
	intent, err := execution.Admitter.OperationIntent(execution.JobID)
	if err != nil {
		return acme.IssueResult{}, err
	}
	bindingDigest, err := acme.BindingDigest(execution.Binding)
	if err != nil || intent.Phase != operations.PhaseRemoteWait || intent.OperationBinding != bindingDigest {
		return acme.IssueResult{}, fmt.Errorf("remote ACME immutable binding changed")
	}
	identityDocument, err := execution.Service.normal.Read()
	if err != nil {
		return acme.IssueResult{}, err
	}
	stageIdentity, err := identity.CertificateStageIdentityFor(execution.Challenge.Safety.CertificateIdentity)
	if err != nil || stageIdentity.UID != uid || stageIdentity.GID != gid {
		return acme.IssueResult{}, fmt.Errorf("certificate stage allocation changed")
	}
	if err := validateCertificateStageIdentity(identityDocument, stageIdentity); err != nil {
		return acme.IssueResult{}, err
	}
	stage, err := acme.PrepareStage(ctx, execution.Challenge.Safety.CertificateIdentity, execution.Binding, uid, gid)
	if err != nil {
		return acme.IssueResult{}, err
	}
	execution.StageRoot = stage.Root
	execution.StageUID = uid
	execution.StageGID = gid
	execution.RemoteStarted = true
	remoteCtx, cancel := context.WithDeadline(ctx, execution.Deadline)
	defer cancel()
	request := acme.IssueRequest{CertificateID: execution.Challenge.Safety.CertificateIdentity, Domains: execution.Challenge.Safety.Hosts, Binding: execution.Binding, UID: uid, GID: gid, Chroot: stage.Root, ExecutableDigest: execution.LegoDigest}
	var result acme.IssueResult
	var runErr error
	if execution.Binding.Method == acme.ChallengeHTTP01 {
		result, runErr = acme.RunHTTP01(remoteCtx, request, execution)
	} else {
		launcher, launcherErr := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{CertificateStage: child.Identity{UID: uid, GID: gid, Chroot: stage.Root}})
		if launcherErr != nil {
			return acme.IssueResult{}, errors.Join(launcherErr, stage.Close())
		}
		result, runErr = acme.RunLego(remoteCtx, launcher, request)
	}
	if child.CgroupClosureUnproved(runErr) {
		return result, runErr
	}
	if execution.Binding.Method != acme.ChallengeHTTP01 || execution.Challenge.Entry == nil {
		runErr = errors.Join(runErr, stage.Close())
	}
	if execution.DNSPreflight != nil {
		runErr = errors.Join(runErr, acme.VerifyDNS01Cleanup(ctx, acme.NetDNSObserver{}, *execution.DNSPreflight))
	}
	runErr = errors.Join(runErr, verifyManagedACMEBinding(execution.Binding))
	if execution.DNSLocks != nil {
		runErr = errors.Join(runErr, execution.DNSLocks.Close())
		execution.DNSLocks = nil
	}
	return result, runErr
}

func (execution *CertificateExecution) TerminalizeChild(ctx context.Context, result acme.IssueResult, runErr error) error {
	if child.CgroupClosureUnproved(runErr) {
		return runErr
	}
	if execution.Operation == operations.CertificateRenew && !time.Now().UTC().Before(execution.Deadline) {
		return fmt.Errorf("certificate renewal remote deadline elapsed")
	}
	if _, err := execution.Reenter(ctx); err != nil {
		return err
	}
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return fmt.Errorf("ACME binding changed after remote wait: %w", err)
	}
	bindingDigest, err := acme.BindingDigest(execution.Binding)
	if err != nil || bindingDigest != execution.Child.InputDigest {
		return fmt.Errorf("ACME immutable binding changed after remote wait")
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return err
	}
	var current domain.AppResource
	if execution.Headscale {
		installation, loadErr := loadHeadscaleInstallation(document)
		if loadErr != nil || installation.Headscale.Certificate == nil || execution.HeadscalePrior == nil || !reflect.DeepEqual(*installation.Headscale.Certificate, *execution.HeadscalePrior) {
			return fmt.Errorf("headscale renewal authority changed during remote wait: %w", loadErr)
		}
	} else {
		_, current, err = loadCertificateResource(document.Entries, execution.Resource.ID)
		if err != nil {
			return err
		}
	}
	if execution.Headscale {
		// Exact committed Headscale authority was checked above.
	} else if execution.Operation == operations.Publish {
		if current.Publication.DomainHTTPS == nil {
			return fmt.Errorf("certificate publication config disappeared")
		}
		domains := append([]string{current.Publication.DomainHTTPS.CanonicalDomain}, current.Publication.DomainHTTPS.Aliases...)
		sort.Strings(domains)
		if current.CurrentConfigDigest != execution.Challenge.Safety.ConfigDigest || !slices.Equal(domains, execution.Challenge.Safety.Hosts) {
			return fmt.Errorf("certificate publication authority changed during remote wait")
		}
	} else if execution.PriorCertificate == nil || current.PublicationRecord.State != domain.PublicationPublished || current.PublicationRecord.LastAppliedBundle == nil || current.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil || !reflect.DeepEqual(current.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate, *execution.PriorCertificate) {
		return fmt.Errorf("certificate renewal authority changed during remote wait")
	}
	childRecord := execution.Child
	childRecord.State = operations.ChildTerminal
	now := time.Now().UTC()
	childRecord.TerminalAt = &now
	childRecord.Outcome = operations.ChildSucceeded
	if runErr != nil {
		childRecord.Outcome = operations.ChildUnknown
	}
	sum := sha256.Sum256([]byte(result.StdoutDigest + "\x00" + result.StderrDigest))
	childRecord.ResultDigest = "sha256:" + hex.EncodeToString(sum[:])
	if err := execution.Admitter.TransitionChild(ctx, execution.Mutation, execution.Exposure, execution.Revision, childRecord); err != nil {
		return err
	}
	execution.Revision++
	return nil
}

func (execution *CertificateExecution) Abort(ctx context.Context, cause error) error {
	if execution == nil {
		return cause
	}
	if child.CgroupClosureUnproved(cause) {
		return cause
	}
	var cleanupErr error
	if execution.DNSPreflight != nil {
		cleanupErr = acme.VerifyDNS01Cleanup(ctx, acme.NetDNSObserver{}, *execution.DNSPreflight)
	}
	if execution.DNSLocks != nil {
		cleanupErr = errors.Join(cleanupErr, execution.DNSLocks.Close())
		execution.DNSLocks = nil
	}
	if cleanupErr != nil {
		return errors.Join(cause, cleanupErr)
	}
	if execution.Mutation == nil || execution.Exposure == nil {
		http01Contraction := execution.Binding.Method == acme.ChallengeHTTP01
		if _, err := execution.reenter(ctx, http01Contraction); err != nil {
			return errors.Join(cause, err)
		}
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return errors.Join(cause, err)
	}
	if err := execution.removeActiveChallenge(ctx, host); err != nil {
		return errors.Join(cause, err)
	}
	if err := execution.clearHTTP01PresentationAuthority(ctx); err != nil {
		return errors.Join(cause, err)
	}
	if execution.StageUID != 0 {
		if err := errors.Join(acme.RemoveStage(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID), acme.RemoveWebroot(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID)); err != nil {
			return errors.Join(cause, err)
		}
	}
	contractedTerminal := false
	if document, readErr := execution.Service.normal.Read(); readErr == nil {
		if raw, present := document.Entries["journals/certificate-"+execution.JobID]; present {
			var journal operations.JournalRecord
			if json.Unmarshal(raw, &journal) == nil && journal.Certificate != nil {
				cleanupErr := certificates.RemoveInactiveBundle(journal.Certificate.CertificateID, journal.Certificate.CandidateGeneration, journal.Certificate.CandidateBundleIdentity, journal.Certificate.StageUID, journal.Certificate.StageGID)
				if cleanupErr != nil {
					return errors.Join(cause, cleanupErr)
				}
				pending := safety.ChallengePending{PlanID: execution.Challenge.Safety.PlanID, Generation: execution.Challenge.Safety.Generation, SANIdentity: execution.Challenge.Safety.SANIdentity, ACMEBinding: execution.Challenge.Safety.ACMEBinding}
				closure := shaDigest([]byte("certificate-abort\x00" + execution.JobID))
				if _, terminalErr := execution.Admitter.TerminalizeContractedCertificate(ctx, execution.Mutation, execution.Exposure, document.Revision, execution.JobID, pending, closure); terminalErr == nil {
					contractedTerminal = true
				}
			}
		}
	}
	document, err := execution.Service.normal.Read()
	if err != nil {
		return errors.Join(cause, err)
	}
	if !contractedTerminal {
		for _, record := range []operations.ChildRecord{execution.Child} {
			document, err = execution.Service.normal.Read()
			if err != nil {
				return errors.Join(cause, err)
			}
			raw, present := document.Entries["children/"+record.ID]
			if !present {
				continue
			}
			var current operations.ChildRecord
			if err := json.Unmarshal(raw, &current); err != nil {
				return errors.Join(cause, err)
			}
			if current.State == operations.ChildTerminal {
				continue
			}
			now := time.Now().UTC()
			current.State = operations.ChildTerminal
			current.Outcome = operations.ChildUnknown
			current.TerminalAt = &now
			sum := sha256.Sum256([]byte("certificate_child_failed"))
			current.ResultDigest = "sha256:" + hex.EncodeToString(sum[:])
			if err := execution.Admitter.TransitionChild(ctx, execution.Mutation, execution.Exposure, document.Revision, current); err != nil {
				return errors.Join(cause, err)
			}
		}
	}
	document, err = execution.Service.normal.Read()
	if err != nil {
		return errors.Join(cause, err)
	}
	if !contractedTerminal {
		if raw, present := document.Entries["journals/certificate-"+execution.JobID]; present {
			var journal operations.JournalRecord
			if err := json.Unmarshal(raw, &journal); err != nil {
				return errors.Join(cause, err)
			}
			if journal.Certificate != nil {
				cleanupErr := certificates.RemoveInactiveBundle(journal.Certificate.CertificateID, journal.Certificate.CandidateGeneration, journal.Certificate.CandidateBundleIdentity, journal.Certificate.StageUID, journal.Certificate.StageGID)
				if cleanupErr != nil {
					return errors.Join(cause, cleanupErr)
				}
			}
			if journal.Phase != operations.JournalTerminal {
				journal.Phase = operations.JournalTerminal
				if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, document.Revision, journal, false); err != nil {
					return errors.Join(cause, err)
				}
			}
		}
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return errors.Join(cause, err)
	}
	next := state
	changed := false
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	if execution.Headscale {
		if next.Headscale.ChallengePending != nil && challenge.Matches(*next.Headscale.ChallengePending, execution.Challenge) {
			next.Headscale.ChallengePending = nil
			changed = true
		}
	} else {
		for index := range next.Resources {
			if next.Resources[index].ResourceID == execution.Resource.ID && next.Resources[index].ChallengePending != nil && challenge.Matches(*next.Resources[index].ChallengePending, execution.Challenge) {
				next.Resources[index].ChallengePending = nil
				changed = true
			}
		}
	}
	if changed {
		next.Revision++
		if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleChallenge, state.Revision, next, safety.TransitionProof{}); err != nil {
			return errors.Join(cause, err)
		}
	}
	document, err = execution.Service.normal.Read()
	if err != nil {
		return errors.Join(cause, err)
	}
	if execution.Headscale {
		installation, loadErr := loadHeadscaleInstallation(document)
		if loadErr == nil && installation.Headscale.DeployIntent != nil && installation.Headscale.DeployIntent.JobID == execution.JobID {
			if contractErr := execution.Admitter.ContractHeadscaleReissueActivation(ctx, execution.Mutation, execution.Exposure, document.Revision, execution.JobID); contractErr != nil {
				return errors.Join(cause, contractErr)
			}
			document, err = execution.Service.normal.Read()
			if err != nil {
				return errors.Join(cause, err)
			}
		}
	}
	if contractedTerminal {
		return cause
	}
	branch := "source_unknown"
	status := jobs.PostconditionUnobserved
	kind := "certificate_provider_result"
	errorCode := "certificate_remote_failed"
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		branch = "executor_died"
		status = jobs.PostconditionKnown
		kind = "certificate_child_interrupted"
		errorCode = "certificate_executor_interrupted"
	}
	var activationFailure *activation.Failure
	if errors.As(cause, &activationFailure) && activationFailure.PriorRestored {
		branch = "known_residual"
		status = jobs.PostconditionKnown
		kind = "certificate_prior_restored"
		errorCode = "activation_contracted"
	}
	_, err = execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, document.Revision, execution.JobID, branch, nil, []jobs.Postcondition{{Kind: kind, Status: status, Identity: certificateExecutionTarget(execution)}}, errorCode)
	return errors.Join(cause, err)
}

func (execution *CertificateExecution) clearHTTP01PresentationAuthority(ctx context.Context) error {
	if execution == nil || execution.Binding.Method != acme.ChallengeHTTP01 || execution.Challenge.Entry == nil {
		return nil
	}
	base, err := challenge.ClearHTTP(execution.Challenge)
	if err != nil {
		return err
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	if execution.Headscale {
		if state.Headscale.ChallengePending == nil || !challenge.Matches(*state.Headscale.ChallengePending, execution.Challenge) {
			return fmt.Errorf("headscale HTTP-01 active authority changed")
		}
		next.Headscale.ChallengePending = &base.Safety
	} else {
		next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
		matched := false
		for index := range next.Resources {
			if next.Resources[index].ResourceID == execution.Resource.ID && next.Resources[index].ChallengePending != nil && challenge.Matches(*next.Resources[index].ChallengePending, execution.Challenge) {
				next.Resources[index].ChallengePending = &base.Safety
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("app HTTP-01 active authority changed")
		}
	}
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleChallenge, state.Revision, next, safety.TransitionProof{}); err != nil {
		return err
	}
	execution.Challenge = base
	return nil
}

func exactHTTP01PresentationInManifest(manifest nginx.Manifest, resourceID string, prepared challenge.Prepared) (bool, error) {
	if prepared.Entry == nil || prepared.Entry.Challenge == nil {
		return false, fmt.Errorf("HTTP-01 presentation graph authority is incomplete")
	}
	present := false
	for _, entry := range manifest.Entries {
		owned := entry.Kind == nginx.EntryChallenge && entry.ResourceID == resourceID
		if resourceID == "headscale" {
			owned = owned || entry.Kind == nginx.EntryControl && entry.Challenge != nil
		}
		if !owned {
			continue
		}
		exact := entry.Kind == nginx.EntryChallenge && reflect.DeepEqual(entry, *prepared.Entry)
		if entry.Kind == nginx.EntryControl {
			exact = reflect.DeepEqual(entry.Challenge, prepared.Entry.Challenge) && slices.Equal(entry.Domains, []string{prepared.Safety.Host})
		}
		if !exact || present {
			return false, fmt.Errorf("HTTP-01 presentation graph identity changed")
		}
		present = true
	}
	return present, nil
}

func (execution *CertificateExecution) removeActiveChallenge(ctx context.Context, host activation.Host) error {
	if execution == nil || execution.Challenge.Entry == nil {
		return nil
	}
	resourceID := execution.Resource.ID
	if execution.Headscale {
		resourceID = "headscale"
	}
	manifest, err := nginx.Audit(host.Paths, host.Owner)
	if err != nil {
		return err
	}
	// Disk absence is not runtime closure: a failed rollback reload can leave
	// challenge workers alive after the prior manifest has been restored.
	_, err = exactHTTP01PresentationInManifest(manifest, resourceID, execution.Challenge)
	if err != nil {
		return err
	}
	authority, err := execution.challengeReloadAuthority()
	if err != nil {
		return err
	}
	currentAuthority, err := authority.Current()
	if err != nil {
		return err
	}
	if execution.Headscale {
		if currentAuthority.Safety.Headscale.CertificateExpiry != nil {
			if currentAuthority.Safety.Headscale.ChallengePending == nil {
				return nil
			}
			_, err := host.RemoveChallenge(ctx, execution.Challenge, authority)
			return err
		}
		bundle, err := execution.headscaleActivationBundle()
		if err != nil {
			return err
		}
		controlHost, err := control.NewActivationHost()
		if err != nil {
			return err
		}
		return controlHost.RemoveCertificateChallenge(ctx, bundle, execution.Challenge, authority)
	}
	_, err = host.RemoveChallenge(ctx, execution.Challenge, authority)
	return err
}

func certificateExecutionTarget(execution *CertificateExecution) string {
	if execution != nil && execution.Headscale {
		return "headscale"
	}
	if execution == nil {
		return ""
	}
	return execution.Resource.ID
}

func (execution *CertificateExecution) LoadIssued(now time.Time) (certificates.IssuedMaterial, error) {
	certificatePath := filepath.Join("/var/lib/lanpanel/certificates/chroot", execution.Challenge.Safety.CertificateIdentity, "work", "certificates", execution.Challenge.Safety.Hosts[0]+".crt")
	keyPath := filepath.Join("/var/lib/lanpanel/certificates/chroot", execution.Challenge.Safety.CertificateIdentity, "work", "certificates", execution.Challenge.Safety.Hosts[0]+".key")
	issuerPath := filepath.Join("/var/lib/lanpanel/certificates/chroot", execution.Challenge.Safety.CertificateIdentity, "work", "certificates", execution.Challenge.Safety.Hosts[0]+".issuer.crt")
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	issuerPEM, err := os.ReadFile(issuerPath)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	chain, err := certificates.JoinLegoChain(certificatePEM, issuerPEM)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return certificates.IssuedMaterial{}, err
	}
	return certificates.ValidateIssued(chain, keyPEM, execution.Challenge.Safety.Hosts, now, execution.Binding.DirectoryURL)
}

func (execution *CertificateExecution) PreparePublicationCertificate(ctx context.Context, identity certificates.Identity) (domain.CertificateBundleIdentity, error) {
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return domain.CertificateBundleIdentity{}, err
	}
	if execution.Operation != operations.Publish {
		return domain.CertificateBundleIdentity{}, fmt.Errorf("publication certificate operation mismatched")
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return domain.CertificateBundleIdentity{}, err
	}
	if execution.Challenge.Entry != nil {
		authority, authorityErr := execution.challengeReloadAuthority()
		if authorityErr != nil {
			return domain.CertificateBundleIdentity{}, authorityErr
		}
		if _, err := host.RemoveChallenge(ctx, execution.Challenge, authority); err != nil {
			return domain.CertificateBundleIdentity{}, err
		}
	}
	if execution.Binding.Method == acme.ChallengeHTTP01 {
		if err := acme.VerifyWebrootEmpty(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID); err != nil {
			return domain.CertificateBundleIdentity{}, err
		}
	}
	if err := errors.Join(acme.RemoveStage(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID), acme.RemoveWebroot(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID)); err != nil {
		return domain.CertificateBundleIdentity{}, err
	}
	credentials := make([]domain.CertificateCredentialIdentity, len(execution.Binding.CredentialFiles))
	for index, file := range execution.Binding.CredentialFiles {
		credentials[index] = domain.CertificateCredentialIdentity{Key: file.Key, Path: file.Path, Fingerprint: file.Fingerprint}
	}
	authority := &domain.CertificateAuthorityIdentity{CertificateID: execution.Challenge.Safety.CertificateIdentity, DirectoryURL: execution.Binding.DirectoryURL, AccountKeyPath: execution.Binding.AccountKeyPath, AccountKeyFingerprint: execution.Binding.AccountKeyFingerprint, AccountEmail: execution.Binding.AccountEmail, TermsAccepted: execution.Binding.TermsAccepted, Method: string(execution.Binding.Method), Provider: string(execution.Binding.Provider), ProfilePath: execution.Binding.ProfilePath, ProfileFingerprint: execution.Binding.ProfileFingerprint, CredentialFiles: credentials, Zone: execution.Binding.Zone, Principal: execution.Binding.Principal}
	pointerIdentity, err := certificates.ActivePointerPath(identity.ID)
	if err != nil {
		return domain.CertificateBundleIdentity{}, err
	}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: pointerIdentity, BindingIdentity: identity.BindingIdentity, Generation: identity.Generation, Fingerprint: identity.Fingerprint, SANIdentity: identity.SANIdentity, NotAfter: identity.NotAfter.Format(time.RFC3339), LastTrustedWall: identity.LastTrustedWall.Format(time.RFC3339), ChainIdentity: identity.ChainIdentity, IssuerIdentity: identity.IssuerIdentity, DirectoryIdentity: identity.DirectoryIdentity, Authority: authority}
	candidatePath, err := certificates.BundlePath(identity.ID, identity.Generation)
	if err != nil {
		return domain.CertificateBundleIdentity{}, err
	}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + execution.JobID, JobID: execution.JobID, Kind: operations.JournalCertificateActivation, Operation: operations.Publish, InstallationID: execution.InstallationID, Target: "resource/" + execution.Resource.ID, Generation: execution.Child.IntentGeneration, Deadline: execution.Deadline, ArtifactDigest: execution.Child.InputDigest, ResourceIDs: []string{execution.Resource.ID}, ChildIDs: []string{execution.Child.ID}, Phase: operations.JournalActive, Certificate: &operations.CertificateJournalIdentity{CertificateID: identity.ID, CandidateGeneration: identity.Generation, CandidatePointer: candidatePath, CandidateFingerprint: identity.Fingerprint, CandidateBundleIdentity: certificates.BundleIdentityFor(identity), Challenge: execution.Challenge.Safety, StageUID: execution.StageUID, StageGID: execution.StageGID}}
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return domain.CertificateBundleIdentity{}, err
	}
	execution.Revision++
	return certificate, nil
}

func (execution *CertificateExecution) BeginPublicationHandoff(ctx context.Context, bundle domain.PublicationBundle) (domain.ActivationIntent, error) {
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return domain.ActivationIntent{}, err
	}
	if execution.Operation != operations.Publish || execution.Mutation == nil || execution.Exposure == nil {
		return domain.ActivationIntent{}, fmt.Errorf("certificate publication handoff authority missing")
	}
	if bundle.Generation != execution.Challenge.Safety.Generation || bundle.ConfigDigest != execution.Challenge.Safety.ConfigDigest || bundle.DomainHTTPS == nil || bundle.DomainHTTPS.Certificate.Authority == nil || bundle.DomainHTTPS.Certificate.Authority.CertificateID != execution.Challenge.Safety.CertificateIdentity {
		return domain.ActivationIntent{}, fmt.Errorf("certificate publication handoff candidate invalid")
	}
	certificateUntil, err := time.Parse(time.RFC3339, bundle.DomainHTTPS.Certificate.NotAfter)
	if err != nil || !certificateUntil.After(time.Now().UTC()) || !certificateUntil.Before(execution.Deadline.Add(366*24*time.Hour)) {
		return domain.ActivationIntent{}, fmt.Errorf("certificate publication deadline invalid")
	}
	bundleDigest, err := publication.BundleDigest(bundle)
	if err != nil {
		return domain.ActivationIntent{}, err
	}
	intent := domain.ActivationIntent{ID: "activation-" + execution.JobID, JobID: execution.JobID, PlanID: execution.Plan.ID, Generation: execution.Challenge.Safety.Generation, Candidate: bundle, PriorState: execution.Resource.PublicationRecord.State}
	if execution.Resource.PublicationRecord.State == domain.PublicationPublished {
		intent.Prior = execution.Resource.PublicationRecord.LastAppliedBundle
	}
	operationIntent, err := execution.Admitter.OperationIntent(execution.JobID)
	if err != nil {
		return domain.ActivationIntent{}, err
	}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "activation-" + execution.JobID, JobID: execution.JobID, Kind: operations.JournalAppActivation, Operation: operations.Publish, InstallationID: execution.InstallationID, Target: "resource/" + execution.Resource.ID, Generation: operationIntent.IntentGeneration, Deadline: execution.Deadline, ArtifactDigest: bundleDigest, ResourceIDs: []string{execution.Resource.ID}, ChildIDs: []string{}, Phase: operations.JournalPrepared}
	if err := execution.Admitter.CommitCertificatePublicationBegin(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.PublicationBeginCommit{ResourceID: execution.Resource.ID, Intent: intent}, journal); err != nil {
		return domain.ActivationIntent{}, err
	}
	execution.Revision++
	fresh, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return domain.ActivationIntent{}, err
	}
	next := fresh
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
	matched := false
	for index := range next.Resources {
		resource := &next.Resources[index]
		if resource.ResourceID != execution.Resource.ID {
			continue
		}
		if resource.ChallengePending == nil || !challenge.Matches(*resource.ChallengePending, execution.Challenge) {
			return domain.ActivationIntent{}, fmt.Errorf("certificate publication safety handoff changed")
		}
		pending := resource.ChallengePending
		resource.ChallengePending = nil
		resource.Reactivating = &safety.Reactivating{Generation: pending.Generation, PriorGeneration: pending.Generation - 1, PlanID: pending.PlanID, CandidateDigest: bundle.ConfigDigest, CandidateBundle: bundleDigest, CertificateUntil: certificateUntil, BaseMarkers: append([]safety.MarkerSnapshot(nil), pending.BaseMarkers...)}
		matched = true
	}
	if !matched {
		return domain.ActivationIntent{}, fmt.Errorf("certificate publication safety resource missing")
	}
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleCertificateHandoff, fresh.Revision, next, safety.TransitionProof{}); err != nil {
		return domain.ActivationIntent{}, err
	}
	return intent, nil
}

func (execution *CertificateExecution) ContinueDomainPublication(ctx context.Context, candidate publication.Candidate) (*PublicationExecution, error) {
	activationDeadline := time.Now().UTC().Add(time.Minute)
	if candidate.ResourceID != execution.Resource.ID || candidate.Generation != execution.Challenge.Safety.Generation {
		return nil, fmt.Errorf("domain publication candidate identity changed")
	}
	if _, err := execution.BeginPublicationHandoff(ctx, candidate.Bundle); err != nil {
		return nil, err
	}
	owned, err := execution.Service.ownership.Read(execution.Resource.ID)
	if err != nil {
		return nil, err
	}
	owned.Revision++
	paths := candidate.OwnershipPaths
	if len(paths) == 0 {
		paths = []ownership.OwnedPath{candidate.OwnershipPath}
	}
	for _, path := range paths {
		owned.Paths = upsertOwnedPath(owned.Paths, path)
	}
	for _, listener := range candidate.OwnershipListeners {
		owned.Listeners = upsertOwnedListener(owned.Listeners, listener)
	}
	slices.SortFunc(owned.Paths, func(a, b ownership.OwnedPath) int { return compare(a.Path, b.Path) })
	slices.SortFunc(owned.Listeners, func(a, b ownership.OwnedListener) int {
		return compare(fmt.Sprintf("%s:%s:%d", a.Protocol, a.Address, a.Port), fmt.Sprintf("%s:%s:%d", b.Protocol, b.Address, b.Port))
	})
	persisted, err := execution.Service.OwnershipWrite(ctx, execution.Exposure, owned.Revision-1, owned)
	if err != nil {
		return nil, err
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return nil, err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	found := false
	for index := range next.Resources {
		if next.Resources[index].ResourceID == execution.Resource.ID {
			before := next.Resources[index].OwnershipDigest
			next.Resources[index].OwnershipDigest = persisted.Checksum
			proof := &safety.OwnershipConvergenceProof{ResourceID: execution.Resource.ID, IntentRef: execution.Plan.ID, Generation: candidate.Generation, BeforeDigest: before, AfterDigest: persisted.Checksum}
			if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleOwnershipActivation, state.Revision, next, safety.TransitionProof{Ownership: proof}); err != nil {
				return nil, err
			}
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("domain publication ownership safety missing")
	}
	result := publicationExecutionFromCertificate(execution, candidate, next, persisted, activationDeadline)
	execution.Service = nil
	execution.Admitter = nil
	execution.MutationSet = nil
	execution.Mutation = nil
	execution.Exposure = nil
	return result, nil
}

func publicationExecutionFromCertificate(execution *CertificateExecution, candidate publication.Candidate, state safety.State, owned ownership.Record, deadline time.Time) *PublicationExecution {
	marker := safety.Reactivating{}
	if resource := findSafetyResource(state, execution.Resource.ID); resource != nil && resource.Reactivating != nil {
		marker = *resource.Reactivating
	}
	return &PublicationExecution{Service: execution.Service, Admitter: execution.Admitter, MutationSet: execution.MutationSet, Mutation: execution.Mutation, Exposure: execution.Exposure, JobID: execution.JobID, Revision: execution.Revision, Resource: execution.Resource, Candidate: candidate, SafetyState: state, Reactivating: marker, Ownership: owned, PlanID: execution.Plan.ID, InstallationID: execution.InstallationID, ActivationDeadline: deadline}
}

func (execution *CertificateExecution) CompleteRenewal(ctx context.Context, identity certificates.Identity) (jobs.Record, error) {
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return jobs.Record{}, err
	}
	activationCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx = activationCtx
	if !time.Now().UTC().Before(execution.Deadline) {
		return jobs.Record{}, fmt.Errorf("certificate renewal activation deadline elapsed")
	}
	if execution.Operation != operations.CertificateRenew || execution.PriorCertificate == nil {
		return jobs.Record{}, fmt.Errorf("certificate renewal completion authority missing")
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return jobs.Record{}, err
	}
	if err := execution.removeActiveChallenge(ctx, host); err != nil {
		return jobs.Record{}, err
	}
	if execution.Binding.Method == acme.ChallengeHTTP01 {
		if err := acme.VerifyWebrootEmpty(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID); err != nil {
			return jobs.Record{}, err
		}
	}
	if err := errors.Join(acme.RemoveStage(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID), acme.RemoveWebroot(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID)); err != nil {
		return jobs.Record{}, err
	}
	prior := *execution.PriorCertificate
	authority := *prior.Authority
	pointerIdentity, err := certificates.ActivePointerPath(identity.ID)
	if err != nil {
		return jobs.Record{}, err
	}
	candidate := domain.CertificateBundleIdentity{PointerIdentity: pointerIdentity, BindingIdentity: identity.BindingIdentity, Generation: identity.Generation, Fingerprint: identity.Fingerprint, SANIdentity: identity.SANIdentity, NotAfter: identity.NotAfter.Format(time.RFC3339), LastTrustedWall: identity.LastTrustedWall.Format(time.RFC3339), ChainIdentity: identity.ChainIdentity, IssuerIdentity: identity.IssuerIdentity, DirectoryIdentity: identity.DirectoryIdentity, Authority: &authority}
	if execution.Headscale {
		candidate, err = headscaleCertificateBundle(identity, execution.Binding)
		if err != nil {
			return jobs.Record{}, err
		}
	}
	priorPath, err := certificates.BundlePath(identity.ID, prior.Generation)
	if err != nil {
		return jobs.Record{}, err
	}
	candidatePath, err := certificates.BundlePath(identity.ID, identity.Generation)
	if err != nil {
		return jobs.Record{}, err
	}
	target := "resource/" + execution.Resource.ID
	resourceIDs := []string{execution.Resource.ID}
	if execution.Headscale {
		target, resourceIDs = "headscale/"+execution.HeadscaleID, nil
	}
	journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + execution.JobID, JobID: execution.JobID, Kind: operations.JournalCertificateActivation, Operation: operations.CertificateRenew, InstallationID: execution.InstallationID, Target: target, Generation: execution.Child.IntentGeneration, Deadline: execution.Deadline, ArtifactDigest: execution.Child.InputDigest, ResourceIDs: resourceIDs, ChildIDs: []string{execution.Child.ID}, Phase: operations.JournalActive, Certificate: &operations.CertificateJournalIdentity{CertificateID: identity.ID, PriorGeneration: prior.Generation, CandidateGeneration: identity.Generation, PriorPointer: priorPath, CandidatePointer: candidatePath, PriorFingerprint: prior.Fingerprint, CandidateFingerprint: identity.Fingerprint, PriorBundleIdentity: certificateBundleIdentity(prior), CandidateBundleIdentity: certificates.BundleIdentityFor(identity), Challenge: execution.Challenge.Safety, StageUID: execution.StageUID, StageGID: execution.StageGID}}
	if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	if err := verifyManagedACMEBinding(execution.Binding); err != nil {
		return jobs.Record{}, err
	}
	pointer := certificates.Pointer{CertificateID: identity.ID, CandidateGeneration: identity.Generation, CandidateIdentity: certificates.BundleIdentityFor(identity), ExpectedPriorGeneration: prior.Generation, ExpectedPriorIdentity: certificateBundleIdentity(prior)}
	reloadAuthority, err := execution.challengeReloadAuthority()
	if err != nil {
		return jobs.Record{}, err
	}
	activationResult, err := host.ActivateCertificate(ctx, pointer, execution.Challenge.Safety.Hosts[0], identity.Fingerprint, prior.Fingerprint, reloadAuthority, reloadAuthority)
	if err != nil {
		var failure *activation.Failure
		if errors.As(err, &failure) && !failure.PriorRestored {
			return jobs.Record{}, execution.fenceCertificateActivation(ctx, host, activationResult.Pointer, candidate, err)
		}
		return jobs.Record{}, err
	}
	var commitErr error
	if execution.Headscale {
		journal.RuntimeDigest = headscaleFailureDigest(activationResult.Runtime.Generation + "\x00" + identity.Fingerprint)
		journal.Phase = operations.JournalTerminal
		if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
			return jobs.Record{}, err
		}
		execution.Revision++
		commitErr = execution.Admitter.CommitHeadscaleCertificateRenewal(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, prior, candidate)
	} else {
		commitErr = execution.Admitter.CommitCertificateRenewal(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, execution.Resource.ID, prior, candidate)
	}
	if commitErr != nil {
		restoreAuthority, authorityErr := execution.challengeReloadAuthority()
		if authorityErr != nil {
			return jobs.Record{}, execution.fenceCertificateActivation(context.WithoutCancel(ctx), host, activationResult.Pointer, candidate, errors.Join(commitErr, authorityErr))
		}
		restoreErr := host.RestoreCertificate(context.WithoutCancel(ctx), pointer, activationResult.Pointer.CandidateTarget, execution.Challenge.Safety.Hosts[0], prior.Fingerprint, restoreAuthority)
		if restoreErr != nil {
			return jobs.Record{}, execution.fenceCertificateActivation(context.WithoutCancel(ctx), host, activationResult.Pointer, candidate, errors.Join(commitErr, restoreErr))
		}
		return jobs.Record{}, &activation.Failure{Cause: commitErr, PriorRestored: true}
	}
	execution.Revision++
	if !execution.Headscale {
		if err := execution.Service.CommitRenewedCertificateAuthority(ctx, execution.Exposure, execution.Resource.ID, candidate); err != nil {
			return jobs.Record{}, execution.fenceCertificateActivation(context.WithoutCancel(ctx), host, activationResult.Pointer, candidate, err)
		}
	}
	if !execution.Headscale {
		journal.Phase = operations.JournalTerminal
		if err := execution.Admitter.PutJournal(ctx, execution.Mutation, execution.Exposure, execution.Revision, journal, false); err != nil {
			return jobs.Record{}, err
		}
		execution.Revision++
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return jobs.Record{}, err
	}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	matched := false
	if execution.Headscale {
		pending := next.Headscale.ChallengePending
		if pending == nil || !challenge.Matches(*pending, execution.Challenge) {
			return jobs.Record{}, fmt.Errorf("headscale renewal challenge authority changed")
		}
		next.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: candidate.Generation, Fingerprint: candidate.Fingerprint, Binding: candidate.BindingIdentity, NotAfter: identity.NotAfter, LastTrustedWall: identity.LastTrustedWall}
		next.Headscale.ChallengePending = nil
		matched = true
	}
	for index := range next.Resources {
		if !execution.Headscale && next.Resources[index].ResourceID == execution.Resource.ID {
			pending := next.Resources[index].ChallengePending
			if pending == nil || !challenge.Matches(*pending, execution.Challenge) {
				return jobs.Record{}, fmt.Errorf("renewal challenge authority changed")
			}
			next.Resources[index].ChallengePending = nil
			matched = true
		}
	}
	if !matched {
		return jobs.Record{}, fmt.Errorf("renewal safety resource missing")
	}
	role := safety.RoleChallenge
	if execution.Headscale {
		role = safety.RoleCertificateActivation
	}
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, role, state.Revision, next, safety.TransitionProof{}); err != nil {
		return jobs.Record{}, err
	}
	if execution.Headscale {
		store := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
		priorJournal, readErr := store.Read()
		if readErr != nil {
			return jobs.Record{}, readErr
		}
		runtimeDigest := headscaleFailureDigest(activationResult.Runtime.Generation + "\x00" + identity.Fingerprint)
		if _, commitJournalErr := store.CommitRenewal(ctx, priorJournal, certificateBundleIdentity(prior), identity, runtimeDigest); commitJournalErr != nil {
			return jobs.Record{}, commitJournalErr
		}
	}
	return execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "complete", []string{identity.CertificatePath, identity.PrivateKeyPath, pointerIdentity}, []jobs.Postcondition{{Kind: "certificate_renewed_and_served", Status: jobs.PostconditionVerified, Identity: identity.Fingerprint}}, "")
}

func (execution *CertificateExecution) fenceCertificateActivation(ctx context.Context, host activation.Host, pointerResult certificates.PointerResult, candidate domain.CertificateBundleIdentity, cause error) error {
	now := time.Now().UTC()
	if execution.Headscale {
		if execution.PriorCertificate == nil {
			return errors.Join(cause, fmt.Errorf("headscale prior certificate missing"))
		}
		if err := execution.Service.MarkHeadscaleCertificateActivationUncertain(ctx, execution.Exposure, execution.PriorCertificate.BindingIdentity, now); err != nil {
			return errors.Join(cause, err)
		}
		priorDigest := sha256.Sum256([]byte(pointerResult.PriorTarget))
		candidateDigest := sha256.Sum256([]byte(pointerResult.CandidateTarget))
		observation := safety.StopObservation{ObservedAt: now}
		if err := execution.Service.WriteHeadscaleCertificateActivationFence(ctx, execution.Exposure, "certificate-"+execution.JobID, "sha256:"+hex.EncodeToString(priorDigest[:]), "sha256:"+hex.EncodeToString(candidateDigest[:]), observation, true); err != nil {
			return errors.Join(cause, err)
		}
		snapshot, stopErr := host.StopAndVerify(ctx)
		observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
		updateErr := execution.Service.UpdateCertificateActivationFence(ctx, execution.Exposure, observed, stopErr != nil)
		return errors.Join(cause, stopErr, updateErr)
	}
	if err := execution.Service.MarkCertificateActivationUncertain(ctx, execution.Exposure, execution.Resource.ID, candidate.BindingIdentity, now); err != nil {
		return errors.Join(cause, err)
	}
	priorDigest := sha256.Sum256([]byte(pointerResult.PriorTarget))
	candidateDigest := sha256.Sum256([]byte(pointerResult.CandidateTarget))
	observation := safety.StopObservation{ObservedAt: now}
	if err := execution.Service.WriteCertificateActivationFence(ctx, execution.Exposure, execution.Resource.ID, "certificate-"+execution.JobID, "sha256:"+hex.EncodeToString(priorDigest[:]), "sha256:"+hex.EncodeToString(candidateDigest[:]), observation, true); err != nil {
		return errors.Join(cause, err)
	}
	snapshot, stopErr := host.StopAndVerify(ctx)
	observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
	updateErr := execution.Service.UpdateCertificateActivationFence(ctx, execution.Exposure, observed, stopErr != nil)
	return errors.Join(cause, stopErr, updateErr)
}

func challengeReloadAuthorityForExposure(service *FixedService, exposure *locks.Lease) (activation.ChallengeReloadAuthority, error) {
	refresh := func() (activation.ReloadAuthoritySnapshot, error) {
		if service == nil {
			return activation.ReloadAuthoritySnapshot{}, fmt.Errorf("challenge reload authority unavailable")
		}
		if exposure == nil || exposure.Authority() != service.safety.LockAuthority() || !exposure.Holds(locks.Exposure) {
			return activation.ReloadAuthoritySnapshot{}, fmt.Errorf("challenge reload authority requires exposure lock")
		}
		state, err := service.safety.Read()
		if err != nil {
			return activation.ReloadAuthoritySnapshot{}, err
		}
		document, err := service.normal.Read()
		if err != nil {
			return activation.ReloadAuthoritySnapshot{}, err
		}
		raw, present := document.Entries["installations/current"]
		if !present {
			return activation.ReloadAuthoritySnapshot{}, fmt.Errorf("challenge installation authority missing")
		}
		installation, err := domain.DecodeInstallation(raw)
		if err != nil {
			return activation.ReloadAuthoritySnapshot{}, err
		}
		ownershipAuthority, err := fixedOwnershipAuthority(service.ownership)
		if err != nil {
			return activation.ReloadAuthoritySnapshot{}, err
		}
		return activation.ReloadAuthoritySnapshot{Safety: state, Installation: installation, Ownership: ownershipAuthority, ObservedAt: time.Now().UTC()}, nil
	}
	return activation.NewReloadAuthorityWithRuntimeCheck(refresh, func() error {
		return VerifyInstalledPackageProfile(context.Background())
	})
}

func headscalePriorCertificateReloadAuthority(authority activation.ReloadAuthority, prior domain.CertificateBundleIdentity, expected safety.HeadscaleReactivating) (activation.ReloadAuthority, error) {
	refresh := func() (activation.ReloadAuthoritySnapshot, error) {
		current, err := authority.Current()
		if err != nil {
			return activation.ReloadAuthoritySnapshot{}, err
		}
		active := current.Safety.Headscale.ActiveCertificate
		if !activeCertificateMatchesBundle(active, prior) || current.ObservedAt.Before(active.LastTrustedWall) || !current.ObservedAt.Before(active.NotAfter) || current.Installation.Headscale == nil || current.Installation.Headscale.Certificate == nil || !reflect.DeepEqual(*current.Installation.Headscale.Certificate, prior) {
			return activation.ReloadAuthoritySnapshot{}, fmt.Errorf("headscale prior certificate reload authority is invalid")
		}
		if marker := current.Safety.Headscale.Reactivating; marker != nil && !reflect.DeepEqual(*marker, expected) {
			return activation.ReloadAuthoritySnapshot{}, fmt.Errorf("headscale prior certificate reactivation authority changed")
		}
		current.Safety.Headscale.Reactivating = nil
		return current, nil
	}
	if runtimeCheck := authority.RuntimeCheck(); runtimeCheck != nil {
		return activation.NewReloadAuthorityWithRuntimeCheck(refresh, runtimeCheck)
	}
	return activation.NewReloadAuthority(refresh)
}

func (execution *CertificateExecution) challengeReloadAuthority() (activation.ChallengeReloadAuthority, error) {
	if execution == nil {
		return activation.ChallengeReloadAuthority{}, fmt.Errorf("challenge reload execution authority unavailable")
	}
	return challengeReloadAuthorityForExposure(execution.Service, execution.Exposure)
}

func (execution *CertificateExecution) ActivateChallenge(ctx context.Context) error {
	_, remoteErr := execution.Admitter.EnterRemoteWait(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID)
	execution.Mutation, execution.Exposure = nil, nil
	if remoteErr != nil {
		return remoteErr
	}
	execution.Revision++
	if execution.Binding.Method == acme.ChallengeHTTP01 {
		if execution.Challenge.Entry != nil || execution.Challenge.Safety.Token != "" {
			return fmt.Errorf("HTTP-01 operation loaded a route before receiving an exact token")
		}
		return nil
	}
	ownerLocks, err := acme.AcquireOwnerLocks(ctx, fixedRoot+"/locks", execution.Binding.Provider, execution.Binding.Zone, execution.Challenge.Owners, execution.Challenge.Safety.OwnerLock)
	if err != nil {
		return err
	}
	preflight, err := acme.PreflightDNS01(ctx, acme.NetDNSObserver{}, execution.Binding.Zone, execution.Challenge.Owners)
	if err != nil {
		_ = ownerLocks.Close()
		return err
	}
	execution.DNSLocks = ownerLocks
	execution.DNSPreflight = &preflight
	return nil
}

func (execution *CertificateExecution) PresentHTTP01(ctx context.Context, presentation acme.HTTP01Presentation) error {
	if execution == nil || execution.Binding.Method != acme.ChallengeHTTP01 || execution.Mutation != nil || execution.Exposure != nil || execution.Challenge.Entry != nil {
		return fmt.Errorf("HTTP-01 presentation phase is invalid")
	}
	resourceID := execution.Resource.ID
	if execution.Headscale {
		resourceID = "headscale"
	}
	active, err := challenge.PresentHTTPForResource(resourceID, execution.Challenge, presentation.Host, presentation.Token, presentation.KeyAuthorizationDigest)
	if err != nil {
		return err
	}
	if err := acme.WriteHTTP01Token(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID, presentation); err != nil {
		return err
	}
	if _, err := execution.Reenter(ctx); err != nil {
		return errors.Join(err, acme.RemoveHTTP01Token(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID, presentation))
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	if execution.Headscale {
		if state.Headscale.ChallengePending == nil || !challenge.Matches(*state.Headscale.ChallengePending, execution.Challenge) {
			return fmt.Errorf("headscale HTTP-01 base authority changed")
		}
		next.Headscale.ChallengePending = &active.Safety
	} else {
		next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
		matched := false
		for index := range next.Resources {
			if next.Resources[index].ResourceID == resourceID && next.Resources[index].ChallengePending != nil && challenge.Matches(*next.Resources[index].ChallengePending, execution.Challenge) {
				next.Resources[index].ChallengePending = &active.Safety
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("app HTTP-01 base authority changed")
		}
	}
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleChallenge, state.Revision, next, safety.TransitionProof{}); err != nil {
		return err
	}
	execution.Challenge = active
	if err := execution.activateHTTP01Route(ctx); err != nil {
		return err
	}
	_, err = execution.Admitter.EnterRemoteWait(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID)
	execution.Mutation, execution.Exposure = nil, nil
	if err == nil {
		execution.Revision++
	}
	return err
}

func (execution *CertificateExecution) CleanUpHTTP01(ctx context.Context, presentation acme.HTTP01Presentation) error {
	if execution == nil || execution.Challenge.Entry == nil || execution.Challenge.Safety.Host != presentation.Host || execution.Challenge.Safety.Token != presentation.Token || execution.Challenge.Safety.KeyAuthorizationDigest != presentation.KeyAuthorizationDigest {
		return fmt.Errorf("HTTP-01 cleanup presentation changed")
	}
	base, err := challenge.ClearHTTP(execution.Challenge)
	if err != nil {
		return err
	}
	if _, err := execution.reenter(ctx, true); err != nil {
		return err
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	if err := execution.removeActiveChallenge(ctx, host); err != nil {
		return err
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return err
	}
	next := state
	next.Revision++
	if execution.Headscale {
		if state.Headscale.ChallengePending == nil || !challenge.Matches(*state.Headscale.ChallengePending, execution.Challenge) {
			return fmt.Errorf("headscale HTTP-01 active authority changed")
		}
		next.Headscale.ChallengePending = &base.Safety
	} else {
		next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
		matched := false
		for index := range next.Resources {
			if next.Resources[index].ResourceID == execution.Resource.ID && next.Resources[index].ChallengePending != nil && challenge.Matches(*next.Resources[index].ChallengePending, execution.Challenge) {
				next.Resources[index].ChallengePending = &base.Safety
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("app HTTP-01 active authority changed")
		}
	}
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleChallenge, state.Revision, next, safety.TransitionProof{}); err != nil {
		return err
	}
	execution.Challenge = base
	if err := acme.VerifyHTTP01Token(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID, presentation); err != nil {
		return err
	}
	_, err = execution.Admitter.EnterRemoteWait(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID)
	execution.Mutation, execution.Exposure = nil, nil
	if err != nil {
		return err
	}
	execution.Revision++
	return acme.RemoveHTTP01Token(execution.Challenge.Safety.CertificateIdentity, execution.StageUID, execution.StageGID, presentation)
}

func (execution *CertificateExecution) activateHTTP01Route(ctx context.Context) error {
	host, err := activation.NewFixedHost()
	if err != nil {
		return err
	}
	authority, err := execution.challengeReloadAuthority()
	if err != nil {
		return err
	}
	current, err := authority.Current()
	if err != nil {
		return err
	}
	if execution.Headscale {
		if current.Safety.Headscale.CertificateExpiry != nil {
			_, err = host.ActivateChallenge(ctx, execution.Challenge, authority)
			return err
		}
		bundle, err := execution.headscaleActivationBundle()
		if err != nil {
			return err
		}
		controlHost, err := control.NewActivationHost()
		if err != nil {
			return err
		}
		return controlHost.ActivateCertificateChallenge(ctx, bundle, execution.Challenge, authority)
	}
	_, err = host.ActivateChallenge(ctx, execution.Challenge, authority)
	return err
}

func (execution *CertificateExecution) Close() error {
	if execution == nil {
		return nil
	}
	err := operations.ReleaseExposure(execution.Mutation, execution.Exposure)
	if execution.MutationSet != nil {
		err = errors.Join(err, execution.MutationSet.Close())
	}
	if execution.Service != nil {
		err = errors.Join(err, execution.Service.Close())
	}
	execution.Mutation = nil
	execution.Exposure = nil
	return err
}

type certificateSafetyOnly struct {
	manager   *locks.Manager
	ownership *ownership.Store
	emergency *safety.EmergencyStore
	store     *safety.Store
}

type certificateExpiryCleanup struct {
	exposure     *locks.Lease
	closeService func() error
}

func (cleanup *certificateExpiryCleanup) Close() error {
	if cleanup == nil {
		return nil
	}
	var result error
	if cleanup.exposure != nil {
		result = errors.Join(result, cleanup.exposure.Release())
		cleanup.exposure = nil
	}
	if cleanup.closeService != nil {
		closeService := cleanup.closeService
		cleanup.closeService = nil
		result = errors.Join(result, closeService())
	}
	return result
}

func (service *certificateSafetyOnly) fenceHeadscaleExpiry(ctx context.Context, lease *locks.Lease, graph string) error {
	return commitHeadscaleCertificateContractionFence(ctx, lease, service.emergency, service.store, graph, safety.StopObservation{ObservedAt: time.Now().UTC()}, true)
}

func (service *certificateSafetyOnly) updateHeadscaleExpiryFence(ctx context.Context, lease *locks.Lease, observed safety.StopObservation, access bool) error {
	return updateHeadscaleCertificateContractionFence(ctx, lease, service.emergency, service.store, observed, access)
}

func openCertificateSafetyOnly() (*certificateSafetyOnly, error) {
	owner := filetxn.Owner{UID: 0, GID: 0}
	manager, err := locks.Open(locks.Config{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*certificateSafetyOnly, error) { _ = manager.Close(); return nil, err }
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: fixedRoot + "/ownership", StagingPath: fixedRoot + "/ownership/.filetxn", RecordsPath: fixedRoot + "/ownership/records", Owner: owner, Policy: ownership.FixedPolicy(), LockAuthority: manager.Authority()})
	if err != nil {
		return fail(err)
	}
	emergency, err := safety.OpenEmergency(fixedRoot+"/safety/emergency", owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		_ = ownershipStore.Close()
		return fail(err)
	}
	store, err := safety.OpenStore(safety.StoreConfig{RootPath: fixedRoot + "/safety", StagingPath: fixedRoot + "/safety/.filetxn", StatePath: fixedRoot + "/safety/state.json", Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		_ = emergency.Close()
		_ = ownershipStore.Close()
		return fail(err)
	}
	return &certificateSafetyOnly{manager: manager, ownership: ownershipStore, emergency: emergency, store: store}, nil
}

func (service *certificateSafetyOnly) Close() error {
	if service == nil {
		return nil
	}
	return errors.Join(service.store.Close(), service.emergency.Close(), service.ownership.Close(), service.manager.Close())
}

func independentHeadscaleExpiryJournalMatches(state safety.State, journal control.Journal) bool {
	active := state.Headscale.ActiveCertificate
	marker := state.Headscale.CertificateExpiry
	certificate := journal.Certificate
	if active == nil || marker == nil || certificate == nil || certificate.Generation != active.Generation || certificate.Fingerprint != active.Fingerprint || certificate.BindingIdentity != active.Binding || !certificate.NotAfter.Equal(active.NotAfter) || active.LastTrustedWall.Before(certificate.LastTrustedWall) || marker.Generation != state.Headscale.GenerationSequence || marker.Binding != active.Binding || journal.Candidate.CertificateID != certificate.ID {
		return false
	}
	bundle, err := control.BuildActivation(journal.InstallationID, journal.Candidate, *certificate)
	return err == nil && bundle.Entry.Digest == state.Headscale.ControlEntryDigest
}

func ContractIndependentCertificateExpiries(ctx context.Context, now time.Time) (returnErr error) {
	service, err := openCertificateSafetyOnly()
	if err != nil {
		return err
	}
	cleanup := &certificateExpiryCleanup{closeService: service.Close}
	defer func() { returnErr = errors.Join(returnErr, cleanup.Close()) }()
	exposure, err := service.manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		return err
	}
	cleanup.exposure = exposure
	state, err := service.store.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	due := false
	appDue := false
	headscaleDue := false
	next := state
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	if state.GlobalClose.Phase == safety.GlobalCloseNone {
		if active := next.Headscale.ActiveCertificate; next.Headscale.CertificateExpiry != nil {
			due = true
			headscaleDue = true
		} else if active != nil {
			deadline := active.NotAfter
			if now.Before(active.LastTrustedWall) {
				deadline = now
			}
			if !deadline.After(now) {
				next.Headscale.GenerationSequence++
				next.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: next.Headscale.GenerationSequence, Deadline: deadline, Binding: active.Binding}
				due = true
				headscaleDue = true
			}
		}
	}
	for index := range next.Resources {
		resource := &next.Resources[index]
		active := resource.ActiveCertificate
		if resource.CertificateExpiry != nil {
			due = true
			appDue = true
			continue
		}
		if active == nil {
			continue
		}
		deadline := active.NotAfter
		if now.Before(active.LastTrustedWall) {
			deadline = now
		}
		if !deadline.After(now) {
			resource.GenerationSequence++
			resource.CertificateExpiry = &safety.DeadlineMarker{Generation: resource.GenerationSequence, Deadline: deadline, Binding: active.Binding}
			due = true
			appDue = true
		}
	}
	if !due {
		return nil
	}
	if !reflect.DeepEqual(state.Resources, next.Resources) || !reflect.DeepEqual(state.Headscale, next.Headscale) {
		next.Revision++
		_, err = service.store.Commit(ctx, exposure, safety.RoleCertificateActivation, state.Revision, next, safety.TransitionProof{})
	}
	if err != nil {
		return err
	}
	if headscaleDue {
		controlStore := control.NewStore(control.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
		journal, journalErr := controlStore.Read()
		var closureErr error
		if journalErr != nil {
			closureErr = journalErr
		} else if !independentHeadscaleExpiryJournalMatches(next, journal) {
			closureErr = fmt.Errorf("headscale independent expiry journal authority changed")
		} else if journal.Phase != control.PhaseExpired {
			if journal.Phase != control.PhaseCommitted {
				closureErr = fmt.Errorf("headscale independent expiry journal phase invalid")
			} else {
				bundle, bundleErr := control.BuildActivation(journal.InstallationID, journal.Candidate, *journal.Certificate)
				if bundleErr == nil {
					controlHost, hostErr := control.NewActivationHost()
					if hostErr == nil {
						closureErr = controlHost.CloseControl(ctx, bundle)
						if closureErr == nil {
							expired := journal
							expired.Phase = control.PhaseExpired
							closureErr = controlStore.Replace(ctx, journal, expired)
						} else {
							if fenceErr := service.fenceHeadscaleExpiry(context.WithoutCancel(ctx), exposure, bundle.Digest); fenceErr != nil {
								return errors.Join(closureErr, fenceErr)
							}
							observed, fallbackErr := controlHost.FallbackStop(context.WithoutCancel(ctx), bundle)
							updateErr := service.updateHeadscaleExpiryFence(context.WithoutCancel(ctx), exposure, observed, fallbackErr != nil)
							closureErr = errors.Join(closureErr, fallbackErr, updateErr)
						}
					} else {
						closureErr = hostErr
					}
				} else {
					closureErr = bundleErr
				}
			}
		}
		if closureErr != nil {
			state, readErr := service.store.ReadForRecovery(exposure)
			if readErr != nil {
				return errors.Join(closureErr, readErr)
			}
			if state.StopFence == nil {
				graph := state.Headscale.ControlEntryDigest
				if fenceErr := service.fenceHeadscaleExpiry(context.WithoutCancel(ctx), exposure, graph); fenceErr != nil {
					return errors.Join(closureErr, fenceErr)
				}
				host, hostErr := activation.NewFixedHost()
				if hostErr != nil {
					return errors.Join(closureErr, hostErr)
				}
				snapshot, stopErr := host.StopAndVerify(context.WithoutCancel(ctx))
				observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
				updateErr := service.updateHeadscaleExpiryFence(context.WithoutCancel(ctx), exposure, observed, stopErr != nil)
				return errors.Join(closureErr, stopErr, updateErr)
			}
			return closureErr
		}
	}
	if err := cleanup.Close(); err != nil {
		return err
	}
	if !appDue {
		return nil
	}
	emergency, err := contraction.OpenEmergency(ctx)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, emergency.Close()) }()
	snapshot, err := emergency.Snapshot()
	if err != nil {
		return err
	}
	result, runErr := emergency.Run(ctx, snapshot.GlobalGeneration, snapshot.Inventory.Digest)
	if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
		return nil
	}
	if runErr != nil {
		return runErr
	}
	if err := emergency.Close(); err != nil {
		return err
	}
	return ReconcileTerminalNginxContraction(ctx)
}

func (service *FixedService) ObserveCertificateTrustedWall(ctx context.Context, now time.Time) error {
	if service == nil || now.IsZero() {
		return fmt.Errorf("certificate wall observation invalid")
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "installation", service.manager)
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	next := state
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	changed := false
	for index := range next.Resources {
		active := next.Resources[index].ActiveCertificate
		if active == nil || !now.After(active.LastTrustedWall) || !active.NotAfter.After(now) {
			continue
		}
		copy := *active
		copy.LastTrustedWall = now.UTC()
		next.Resources[index].ActiveCertificate = &copy
		changed = true
	}
	if active := next.Headscale.ActiveCertificate; active != nil && now.After(active.LastTrustedWall) && active.NotAfter.After(now) {
		copy := *active
		copy.LastTrustedWall = now.UTC()
		next.Headscale.ActiveCertificate = &copy
		changed = true
	}
	if !changed {
		return nil
	}
	next.Revision++
	_, err = service.safety.Commit(ctx, exposure, safety.RoleCertificateObservation, state.Revision, next, safety.TransitionProof{})
	return err
}

func ReconcileCertificateExpiries(ctx context.Context, now time.Time) error {
	fallback := func(cause error) error {
		return errors.Join(cause, ContractIndependentCertificateExpiries(context.WithoutCancel(ctx), now))
	}
	service, err := OpenFixed()
	if err != nil {
		return ContractIndependentCertificateExpiries(ctx, now)
	}
	if err := service.ObserveCertificateTrustedWall(ctx, now); err != nil {
		_ = service.Close()
		return fallback(err)
	}
	state, err := service.safety.Read()
	if err != nil {
		_ = service.Close()
		return fallback(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		_ = service.Close()
		return fallback(err)
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		_ = service.Close()
		return fallback(fmt.Errorf("installation authority missing"))
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		_ = service.Close()
		return fallback(err)
	}
	headscaleDecision, decisionErr := renewal.EvaluateHeadscale(now, 30*24*time.Hour, installation.Headscale, state)
	if decisionErr != nil {
		_ = service.Close()
		return fallback(decisionErr)
	}
	if state.GlobalClose.Phase == safety.GlobalCloseNone && state.Headscale.CertificateExpiry != nil {
		headscaleDecision = renewal.DecisionContract
	}
	ids := []string{}
	for _, resource := range installation.Resources {
		decision, decisionErr := renewal.Evaluate(renewal.Input{Now: now, RenewBefore: 30 * 24 * time.Hour, Publication: resource.PublicationRecord, Safety: state, ResourceID: resource.ID})
		if decisionErr != nil {
			_ = service.Close()
			return fallback(decisionErr)
		}
		for _, safetyResource := range state.Resources {
			if safetyResource.ResourceID == resource.ID && safetyResource.CertificateExpiry != nil {
				decision = renewal.DecisionContract
			}
		}
		if decision == renewal.DecisionContract {
			ids = append(ids, resource.ID)
		}
	}
	if err := service.Close(); err != nil {
		return fallback(err)
	}
	if headscaleDecision == renewal.DecisionContract {
		if err := ContractExpiredHeadscaleCertificate(ctx, now); err != nil {
			return fallback(err)
		}
	}
	for _, id := range ids {
		if err := ContractExpiredCertificate(ctx, id, now); err != nil {
			return fallback(err)
		}
	}
	return nil
}

func fenceInterruptedCertificate(ctx context.Context, service *FixedService, exposure *locks.Lease, resourceID, binding, journalRef, priorPointer, candidatePointer string, cause error) error {
	now := time.Now().UTC()
	if err := service.MarkCertificateActivationUncertain(ctx, exposure, resourceID, binding, now); err != nil {
		return errors.Join(cause, err)
	}
	priorDigest := sha256.Sum256([]byte(priorPointer))
	candidateDigest := sha256.Sum256([]byte(candidatePointer))
	if err := service.WriteCertificateActivationFence(ctx, exposure, resourceID, journalRef, "sha256:"+hex.EncodeToString(priorDigest[:]), "sha256:"+hex.EncodeToString(candidateDigest[:]), safety.StopObservation{ObservedAt: now}, true); err != nil {
		return errors.Join(cause, err)
	}
	host, err := activation.NewFixedHost()
	if err != nil {
		return errors.Join(cause, err)
	}
	snapshot, stopErr := host.StopAndVerify(ctx)
	observed := safety.StopObservation{MasterStopped: snapshot.Master == nil, WorkersStopped: len(snapshot.Workers) == 0, ListenersStopped: len(snapshot.Listeners) == 0, ObservedAt: time.Now().UTC()}
	updateErr := service.UpdateCertificateActivationFence(ctx, exposure, observed, stopErr != nil)
	return errors.Join(cause, stopErr, updateErr)
}

func ReconcileJournalLessCertificateIntents(ctx context.Context, childClosure string) error {
	if !strings.HasPrefix(childClosure, "sha256:") {
		return fmt.Errorf("certificate child closure identity invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	jobIDs := []string{}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) != nil || (intent.Operation != operations.Publish && intent.Operation != operations.CertificateRenew) || (intent.Phase != operations.PhaseReserved && intent.Phase != operations.PhaseLocalIntent) || intent.SafetyBinding.CertificateIdentity == "" || (intent.SafetyBinding.ChallengeMethod != "http-01" && intent.SafetyBinding.ChallengeMethod != "dns-01") {
			continue
		}
		hasJournal, hasChild, hasChallenge := false, false, false
		for journalKey, journalRaw := range document.Entries {
			if strings.HasPrefix(journalKey, "journals/") {
				var journal operations.JournalRecord
				if json.Unmarshal(journalRaw, &journal) == nil && journal.JobID == intent.JobID {
					hasJournal = true
				}
			}
			if strings.HasPrefix(journalKey, "children/") {
				var child operations.ChildRecord
				if json.Unmarshal(journalRaw, &child) == nil && child.JobID == intent.JobID {
					hasChild = true
				}
			}
		}
		for _, resource := range state.Resources {
			pending := resource.ChallengePending
			if pending != nil && resource.ResourceID == intent.SafetyBinding.ResourceID && pending.PlanID == intent.SafetyBinding.PlanID && pending.Generation == intent.SafetyBinding.IntentGeneration {
				hasChallenge = true
			}
		}
		if !hasJournal && !hasChild && !hasChallenge {
			jobIDs = append(jobIDs, intent.JobID)
		}
	}
	sort.Strings(jobIDs)
	for _, jobID := range jobIDs {
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
		raw, present := document.Entries["intents/"+jobID]
		var intent operations.Reservation
		if !present || json.Unmarshal(raw, &intent) != nil {
			return fmt.Errorf("journal-less certificate intent changed")
		}
		admitter, err := service.TimerAdmitter()
		if err != nil {
			return err
		}
		if intent.Phase == operations.PhaseReserved {
			admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
			if err != nil {
				return err
			}
			rejectErr := admitter.RejectReservation(ctx, admission, document.Revision, jobID, "certificate_executor_interrupted")
			releaseErr := admission.Release()
			if err := errors.Join(rejectErr, releaseErr); err != nil {
				return err
			}
			continue
		}
		if intent.Phase != operations.PhaseLocalIntent {
			return fmt.Errorf("journal-less certificate phase changed")
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		freshState, err := service.safety.ReadForRecovery(exposure)
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		for _, resource := range freshState.Resources {
			pending := resource.ChallengePending
			if pending != nil && resource.ResourceID == intent.SafetyBinding.ResourceID && pending.PlanID == intent.SafetyBinding.PlanID && pending.Generation == intent.SafetyBinding.IntentGeneration {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return fmt.Errorf("journal-less certificate acquired challenge authority")
			}
		}
		if intent.SafetyBinding.ResourceID == "headscale" && freshState.Headscale.ChallengePending != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("journal-less Headscale certificate acquired challenge authority")
		}
		_, completeErr := admitter.TerminalizeJournalLessCertificate(ctx, mutation, exposure, document.Revision, jobID, childClosure)
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err := errors.Join(completeErr, releaseErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func ReconcileUnstartedCertificateJournals(ctx context.Context, childClosure string) error {
	if !strings.HasPrefix(childClosure, "sha256:") {
		return fmt.Errorf("certificate child closure identity invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	jobsToClose := []string{}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "journals/") {
			continue
		}
		var journal operations.JournalRecord
		if json.Unmarshal(raw, &journal) != nil || journal.Kind != operations.JournalCertificateActivation || journal.Phase != operations.JournalPrepared {
			continue
		}
		intentRaw, present := document.Entries["intents/"+journal.JobID]
		var intent operations.Reservation
		if !present || json.Unmarshal(intentRaw, &intent) != nil || intent.Phase != operations.PhaseLocalIntent {
			continue
		}
		hasChallenge := false
		for _, resource := range state.Resources {
			pending := resource.ChallengePending
			if pending != nil && resource.ResourceID == intent.SafetyBinding.ResourceID && pending.PlanID == intent.SafetyBinding.PlanID && pending.Generation == intent.SafetyBinding.IntentGeneration {
				hasChallenge = true
			}
		}
		if intent.SafetyBinding.ResourceID == "headscale" && state.Headscale.ChallengePending != nil && state.Headscale.ChallengePending.PlanID == intent.SafetyBinding.PlanID && state.Headscale.ChallengePending.Generation == intent.SafetyBinding.IntentGeneration {
			hasChallenge = true
		}
		if !hasChallenge {
			jobsToClose = append(jobsToClose, journal.JobID)
		}
	}
	sort.Strings(jobsToClose)
	for _, jobID := range jobsToClose {
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
		intentRaw, present := document.Entries["intents/"+jobID]
		var intent operations.Reservation
		if !present || json.Unmarshal(intentRaw, &intent) != nil || intent.Phase != operations.PhaseLocalIntent {
			return fmt.Errorf("unstarted certificate intent changed")
		}
		raw, present := document.Entries["journals/certificate-"+jobID]
		var journal operations.JournalRecord
		if !present || json.Unmarshal(raw, &journal) != nil || journal.Certificate == nil || journal.Phase != operations.JournalPrepared {
			return fmt.Errorf("unstarted certificate journal changed")
		}
		if len(journal.ChildIDs) != 1 || journal.ChildIDs[0] != "lego-"+jobID {
			return fmt.Errorf("unstarted certificate child identity changed")
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		freshState, err := service.safety.ReadForRecovery(exposure)
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		currentIntentRaw, present := document.Entries["intents/"+jobID]
		if !present || json.Unmarshal(currentIntentRaw, &intent) != nil || intent.Phase != operations.PhaseLocalIntent {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("unstarted certificate intent changed under lock")
		}
		currentJournalRaw, present := document.Entries["journals/certificate-"+jobID]
		if !present || json.Unmarshal(currentJournalRaw, &journal) != nil || journal.Certificate == nil || journal.Phase != operations.JournalPrepared {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("unstarted certificate journal changed under lock")
		}
		for _, resource := range freshState.Resources {
			if resource.ResourceID == intent.SafetyBinding.ResourceID && resource.ChallengePending != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return fmt.Errorf("unstarted certificate acquired challenge authority")
			}
		}
		if intent.SafetyBinding.ResourceID == "headscale" && freshState.Headscale.ChallengePending != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("unstarted Headscale certificate acquired challenge authority")
		}
		if err := errors.Join(acme.RemoveStage(journal.Certificate.CertificateID, journal.Certificate.StageUID, journal.Certificate.StageGID), acme.RemoveWebroot(journal.Certificate.CertificateID, journal.Certificate.StageUID, journal.Certificate.StageGID)); err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		admitter, err := service.TimerAdmitter()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		pending := safety.ChallengePending{PlanID: intent.SafetyBinding.PlanID, Generation: intent.SafetyBinding.IntentGeneration, SANIdentity: intent.SafetyBinding.CandidateDigest, ACMEBinding: intent.SafetyBinding.CandidateBundle}
		closure := shaDigest([]byte("unstarted-certificate\x00" + jobID + "\x00" + childClosure))
		_, terminalErr := admitter.TerminalizeContractedCertificate(ctx, mutation, exposure, document.Revision, jobID, pending, closure)
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err := errors.Join(terminalErr, releaseErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func ReconcileCompletedCertificateRenewals(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	journalIDs := []string{}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "journals/") {
			continue
		}
		var journal operations.JournalRecord
		if json.Unmarshal(raw, &journal) == nil && journal.Kind == operations.JournalCertificateActivation && journal.Operation == operations.CertificateRenew && (journal.Phase == operations.JournalActive || journal.Phase == operations.JournalTerminal) {
			var intent operations.Reservation
			if intentRaw, present := document.Entries["intents/"+journal.JobID]; present && json.Unmarshal(intentRaw, &intent) == nil && intent.Phase != operations.PhaseTerminal && intent.Phase != operations.PhaseRejected {
				journalIDs = append(journalIDs, journal.ID)
			}
		}
	}
	sort.Strings(journalIDs)
	for _, journalID := range journalIDs {
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
		raw, present := document.Entries["journals/"+journalID]
		var journal operations.JournalRecord
		if !present || json.Unmarshal(raw, &journal) != nil || journal.Certificate == nil {
			return fmt.Errorf("completed renewal journal changed")
		}
		if strings.HasPrefix(journal.Target, "headscale/") {
			if err := reconcileCompletedHeadscaleRenewal(ctx, journalID); err != nil {
				return err
			}
			continue
		}
		resourceID := strings.TrimPrefix(journal.Target, "resource/")
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, journal.Target, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		admitter, err := service.TimerAdmitter()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		raw, present = document.Entries["journals/"+journalID]
		if !present || json.Unmarshal(raw, &journal) != nil || journal.Certificate == nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("completed renewal journal disappeared")
		}
		certificate := journal.Certificate
		intent, err := admitter.OperationIntent(journal.JobID)
		if err != nil || intent.Operation != operations.CertificateRenew || (intent.Phase != operations.PhaseLocalIntent && intent.Phase != operations.PhaseRemoteWait && intent.Phase != operations.PhaseReentered) {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("completed renewal intent changed")
		}
		installation, resource, err := loadCertificateResource(document.Entries, resourceID)
		_ = installation
		if err != nil || resource.PublicationRecord.LastAppliedBundle == nil || resource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("completed renewal normal authority missing")
		}
		applied := resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate
		state, err := service.safety.ReadForRecovery(exposure)
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		var safetyResource *safety.ResourceSafety
		for index := range state.Resources {
			if state.Resources[index].ResourceID == resourceID {
				safetyResource = &state.Resources[index]
			}
		}
		if safetyResource == nil || safetyResource.ChallengePending != nil || safetyResource.ActiveCertificate == nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("completed renewal safety authority changed")
		}
		if !slices.Equal(journal.ChildIDs, []string{"lego-" + journal.JobID}) {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("completed renewal child inventory changed")
		}
		var childRecord operations.ChildRecord
		childRaw, present := document.Entries["children/"+journal.ChildIDs[0]]
		if !present || json.Unmarshal(childRaw, &childRecord) != nil || childRecord.State != operations.ChildTerminal {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("completed renewal child result changed")
		}
		pointer, err := certificates.ObservePointer(certificate.CertificateID)
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		candidateCommitted := certificateBundleMatches(applied, certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity) && activeCertificateMatchesBundle(safetyResource.ActiveCertificate, applied) && pointer == certificate.CandidatePointer && childRecord.Outcome == operations.ChildSucceeded
		priorRetained := journal.Phase == operations.JournalTerminal && certificate.PriorGeneration > 0 && certificateBundleMatches(applied, certificate.CertificateID, certificate.PriorGeneration, certificate.PriorBundleIdentity) && activeCertificateMatchesBundle(safetyResource.ActiveCertificate, applied) && pointer == certificate.PriorPointer
		if priorRetained {
			if err := certificates.VerifyBundleIdentity(certificate.CertificateID, certificate.PriorGeneration, certificate.PriorBundleIdentity); err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
			if err := certificates.RemoveInactiveBundle(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity, certificate.StageUID, certificate.StageGID); err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
			if err := errors.Join(acme.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), acme.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
			pending := safety.ChallengePending{PlanID: intent.SafetyBinding.PlanID, Generation: intent.SafetyBinding.IntentGeneration, SANIdentity: intent.SafetyBinding.CandidateDigest, ACMEBinding: intent.SafetyBinding.CandidateBundle}
			closure := shaDigest([]byte("failed-renewal\x00" + journal.JobID + "\x00" + childRecord.ResultDigest))
			_, terminalErr := admitter.TerminalizeContractedCertificate(ctx, mutation, exposure, document.Revision, journal.JobID, pending, closure)
			releaseErr := operations.ReleaseExposure(mutation, exposure)
			closeErr := mutationSet.Close()
			if err := errors.Join(terminalErr, releaseErr, closeErr); err != nil {
				return err
			}
			continue
		}
		if !candidateCommitted {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("completed renewal candidate changed")
		}
		if err := certificates.VerifyBundleIdentity(certificate.CertificateID, certificate.CandidateGeneration, certificate.CandidateBundleIdentity); err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		host, err := activation.NewFixedHost()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		serverName := resource.PublicationRecord.LastAppliedBundle.DomainHTTPS.ExactDomains[0]
		if err := host.VerifyServedCertificate(ctx, serverName, certificate.CandidateFingerprint); err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		if err := errors.Join(acme.RemoveStage(certificate.CertificateID, certificate.StageUID, certificate.StageGID), acme.RemoveWebroot(certificate.CertificateID, certificate.StageUID, certificate.StageGID)); err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		revision := document.Revision
		if journal.Phase == operations.JournalActive {
			journal.Phase = operations.JournalTerminal
			if err := admitter.PutJournal(ctx, mutation, exposure, revision, journal, false); err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
			revision++
		}
		_, completeErr := admitter.Complete(ctx, mutation, exposure, revision, journal.JobID, "complete", []string{certificate.CandidatePointer}, []jobs.Postcondition{{Kind: "certificate_renewed_and_served", Status: jobs.PostconditionVerified, Identity: certificate.CandidateFingerprint}}, "")
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err := errors.Join(completeErr, releaseErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func ReconcileCertificateChallenges(ctx context.Context, childClosure string) error {
	if len(childClosure) != 71 || !strings.HasPrefix(childClosure, "sha256:") {
		return fmt.Errorf("certificate recovery child closure invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	if err := reconcileInterruptedHeadscaleLocalCandidate(ctx, service); err != nil {
		return err
	}
	state, err := service.safety.Read()
	if err != nil {
		return err
	}
	if state.Headscale.ChallengePending != nil {
		if err := reconcileInterruptedHeadscaleChallenge(ctx, service, childClosure); err != nil {
			return err
		}
		state, err = service.safety.Read()
		if err != nil {
			return err
		}
	}
	for _, resource := range state.Resources {
		pending := resource.ChallengePending
		if pending == nil {
			continue
		}
		if pending.Method == "dns-01" {
			ownerLocks, lockErr := acme.AcquireOwnerLocks(ctx, fixedRoot+"/locks", acme.DNSProvider(pending.Provider), pending.Zone, pending.Owners, pending.OwnerLock)
			if lockErr != nil {
				return lockErr
			}
			_, preflightErr := acme.PreflightDNS01(ctx, acme.NetDNSObserver{}, pending.Zone, pending.Owners)
			closeErr := ownerLocks.Close()
			if err := errors.Join(preflightErr, closeErr); err != nil {
				return fmt.Errorf("interrupted DNS challenge cleanup unproved: %w", err)
			}
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resource.ResourceID, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		if pending.Method == "http-01" {
			authority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
			var currentAuthority activation.ReloadAuthoritySnapshot
			if authorityErr == nil {
				currentAuthority, authorityErr = authority.Current()
			}
			freshResource := findSafetyResource(currentAuthority.Safety, resource.ResourceID)
			if authorityErr != nil || freshResource == nil || freshResource.ChallengePending == nil || !reflect.DeepEqual(*freshResource.ChallengePending, *pending) {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return errors.Join(authorityErr, fmt.Errorf("interrupted HTTP challenge authority changed under exposure lock"))
			}
			host, hostErr := activation.NewFixedHost()
			if hostErr != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return hostErr
			}
			manifest, auditErr := nginx.Audit(host.Paths, host.Owner)
			if auditErr != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return auditErr
			}
			if freshResource.ChallengePending.Token == "" {
				for _, current := range manifest.Entries {
					if current.Kind == nginx.EntryChallenge && current.ResourceID == resource.ResourceID {
						_ = operations.ReleaseExposure(mutation, exposure)
						_ = mutationSet.Close()
						return fmt.Errorf("tokenless interrupted HTTP challenge has an active route")
					}
				}
			} else {
				expected, prepareErr := challenge.PreparedHTTP(resource.ResourceID, *freshResource.ChallengePending)
				if prepareErr != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return prepareErr
				}
				_, routeErr := exactHTTP01PresentationInManifest(manifest, resource.ResourceID, expected)
				if routeErr != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return routeErr
				}
				if _, err := host.RemoveChallenge(ctx, expected, authority); err != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return err
				}
				base, clearErr := challenge.ClearHTTP(expected)
				if clearErr != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return clearErr
				}
				fresh := currentAuthority.Safety
				next := fresh
				next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
				matched := false
				for index := range next.Resources {
					if next.Resources[index].ResourceID == resource.ResourceID && next.Resources[index].ChallengePending != nil && challenge.Matches(*next.Resources[index].ChallengePending, expected) {
						next.Resources[index].ChallengePending = &base.Safety
						matched = true
					}
				}
				if !matched {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return fmt.Errorf("interrupted HTTP challenge safety identity changed")
				}
				next.Revision++
				if _, clearErr := service.safety.Commit(ctx, exposure, safety.RoleChallenge, fresh.Revision, next, safety.TransitionProof{}); clearErr != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return clearErr
				}
				pending = &base.Safety
				stageIdentity, identityErr := identity.CertificateStageIdentityFor(expected.Safety.CertificateIdentity)
				var tokenErr error
				if identityErr == nil {
					tokenErr = acme.VerifyHTTP01TokenDigest(expected.Safety.CertificateIdentity, stageIdentity.UID, stageIdentity.GID, expected.Safety.Token, expected.Safety.KeyAuthorizationDigest)
				}
				if identityErr != nil || tokenErr != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return errors.Join(identityErr, tokenErr, fmt.Errorf("interrupted HTTP challenge token identity changed after route contraction"))
				}
			}
		}
		document, err := service.normal.Read()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		jobID := ""
		var publicationHandoff *operations.CertificatePublicationHandoff
		var publicationIntent *operations.Reservation
		for key, raw := range document.Entries {
			if !strings.HasPrefix(key, "intents/") {
				continue
			}
			var intent operations.Reservation
			if json.Unmarshal(raw, &intent) != nil || intent.Target != "resource/"+resource.ResourceID || (intent.Operation != operations.Publish && intent.Operation != operations.CertificateRenew) {
				continue
			}
			matchesChallenge := intent.SafetyBinding.PlanID == pending.PlanID && intent.SafetyBinding.IntentGeneration == pending.Generation && intent.SafetyBinding.CandidateDigest == pending.SANIdentity && intent.SafetyBinding.CandidateBundle == pending.ACMEBinding
			handoff := intent.CertificateHandoff
			matchesHandoff := handoff != nil && handoff.PlanID == pending.PlanID && handoff.Generation == pending.Generation && handoff.SANIdentity == pending.SANIdentity && handoff.ACMEBinding == pending.ACMEBinding && handoff.CertificateID == pending.CertificateIdentity
			if matchesChallenge || matchesHandoff {
				if jobID != "" {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return fmt.Errorf("multiple certificate intents match challenge")
				}
				jobID = intent.JobID
				publicationHandoff = handoff
				copyIntent := intent
				publicationIntent = &copyIntent
			}
		}
		if jobID == "" {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("certificate challenge lacks exact operation intent")
		}
		rawJournal, present := document.Entries["journals/certificate-"+jobID]
		if !present {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("certificate challenge journal missing")
		}
		var journal operations.JournalRecord
		if err := json.Unmarshal(rawJournal, &journal); err != nil || journal.Certificate == nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("certificate challenge journal invalid")
		}
		certificateIdentity := journal.Certificate
		fenceAndRelease := func(cause error) error {
			fenceErr := fenceInterruptedCertificate(ctx, service, exposure, resource.ResourceID, pending.ACMEBinding, journal.ID, certificateIdentity.PriorPointer, certificateIdentity.CandidatePointer, cause)
			releaseErr := operations.ReleaseExposure(mutation, exposure)
			closeErr := mutationSet.Close()
			emergency, openErr := contraction.OpenEmergency(context.WithoutCancel(ctx))
			var emergencyErr error
			if openErr == nil {
				snapshot, snapshotErr := emergency.Snapshot()
				if snapshotErr == nil {
					_, emergencyErr = emergency.Run(context.WithoutCancel(ctx), snapshot.GlobalGeneration, snapshot.Inventory.Digest)
				} else {
					emergencyErr = snapshotErr
				}
				emergencyErr = errors.Join(emergencyErr, emergency.Close())
			}
			return errors.Join(fenceErr, releaseErr, closeErr, openErr, emergencyErr)
		}
		committedCertificate := false
		if journal.Phase == operations.JournalActive || journal.Phase == operations.JournalTerminal {
			observedPointer, observeErr := certificates.ObservePointer(certificateIdentity.CertificateID)
			if observeErr != nil {
				return fenceAndRelease(observeErr)
			}
			installation, _, loadErr := loadCertificateResource(document.Entries, resource.ResourceID)
			if loadErr != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return loadErr
			}
			var normalResource *domain.AppResource
			for index := range installation.Resources {
				if installation.Resources[index].ID == resource.ResourceID {
					normalResource = &installation.Resources[index]
				}
			}
			appliedCandidate, appliedPrior := false, false
			serverName := pending.Host
			if normalResource != nil && normalResource.PublicationRecord.LastAppliedBundle != nil && normalResource.PublicationRecord.LastAppliedBundle.DomainHTTPS != nil {
				appliedCertificate := normalResource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate
				appliedCandidate = certificateBundleMatches(appliedCertificate, certificateIdentity.CertificateID, certificateIdentity.CandidateGeneration, certificateIdentity.CandidateBundleIdentity)
				appliedPrior = certificateIdentity.PriorGeneration > 0 && certificateBundleMatches(appliedCertificate, certificateIdentity.CertificateID, certificateIdentity.PriorGeneration, certificateIdentity.PriorBundleIdentity)
			}
			host, hostErr := activation.NewFixedHost()
			if hostErr != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return hostErr
			}
			switch {
			case certificateIdentity.PriorGeneration == 0 && observedPointer == certificateIdentity.CandidatePointer && appliedCandidate:
				return fenceAndRelease(fmt.Errorf("publication committed before certificate handoff terminalized"))
			case certificateIdentity.PriorGeneration == 0 && observedPointer == certificateIdentity.CandidatePointer:
				restoreErr := certificates.RemovePointer(ctx, certificatePointerFromJournal(*certificateIdentity), certificateIdentity.CandidatePointer)
				if restoreErr != nil {
					return fenceAndRelease(restoreErr)
				}
			case certificateIdentity.PriorGeneration > 0 && observedPointer == certificateIdentity.CandidatePointer && !appliedCandidate && !appliedPrior:
				return fenceAndRelease(fmt.Errorf("certificate normal state differs from candidate and prior authority"))
			case certificateIdentity.PriorGeneration > 0 && observedPointer == certificateIdentity.CandidatePointer && appliedPrior:
				reloadAuthority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
				if authorityErr != nil {
					return fenceAndRelease(authorityErr)
				}
				restoreErr := host.RestoreCertificate(ctx, certificatePointerFromJournal(*certificateIdentity), certificateIdentity.CandidatePointer, serverName, certificateIdentity.PriorFingerprint, reloadAuthority)
				if restoreErr != nil {
					return fenceAndRelease(restoreErr)
				}
			case certificateIdentity.PriorGeneration > 0 && observedPointer == certificateIdentity.CandidatePointer && appliedCandidate:
				if err := certificates.VerifyBundleIdentity(certificateIdentity.CertificateID, certificateIdentity.CandidateGeneration, certificateIdentity.CandidateBundleIdentity); err != nil {
					return fenceAndRelease(err)
				}
				if err := host.VerifyServedCertificate(ctx, serverName, certificateIdentity.CandidateFingerprint); err != nil {
					return fenceAndRelease(err)
				}
				committedCertificate = true
				if normalResource == nil || normalResource.PublicationRecord.LastAppliedBundle == nil || normalResource.PublicationRecord.LastAppliedBundle.DomainHTTPS == nil {
					return fenceAndRelease(fmt.Errorf("committed certificate recovery authority missing"))
				}
				candidateCertificate := normalResource.PublicationRecord.LastAppliedBundle.DomainHTTPS.Certificate
				if !activeCertificateMatchesBundle(resource.ActiveCertificate, candidateCertificate) {
					priorIdentity, observeErr := certificates.ObserveIdentity(certificates.FixedBundlesRoot, certificateIdentity.CertificateID, certificateIdentity.PriorGeneration, filetxn.Owner{UID: certificateIdentity.StageUID, GID: certificateIdentity.StageGID})
					if observeErr != nil || certificates.BundleIdentityFor(priorIdentity) != certificateIdentity.PriorBundleIdentity || !activeCertificateMatchesIdentity(resource.ActiveCertificate, priorIdentity) {
						return fenceAndRelease(errors.Join(fmt.Errorf("certificate recovery safety authority differs from candidate and prior"), observeErr))
					}
					if err := service.CommitRenewedCertificateAuthority(ctx, exposure, resource.ResourceID, candidateCertificate); err != nil {
						return fenceAndRelease(err)
					}
				}
			case certificateIdentity.PriorGeneration > 0 && observedPointer == certificateIdentity.PriorPointer && !appliedPrior:
				return fenceAndRelease(fmt.Errorf("certificate normal state differs from prior pointer"))
			case certificateIdentity.PriorGeneration > 0 && observedPointer == certificateIdentity.PriorPointer && appliedPrior:
				if err := certificates.VerifyBundleIdentity(certificateIdentity.CertificateID, certificateIdentity.PriorGeneration, certificateIdentity.PriorBundleIdentity); err != nil {
					return fenceAndRelease(err)
				}
				reloadAuthority, authorityErr := challengeReloadAuthorityForExposure(service, exposure)
				if authorityErr != nil {
					return fenceAndRelease(authorityErr)
				}
				if _, err := host.ReloadCertificate(ctx, reloadAuthority); err != nil {
					return fenceAndRelease(err)
				}
				if err := host.VerifyServedCertificate(ctx, serverName, certificateIdentity.PriorFingerprint); err != nil {
					return fenceAndRelease(err)
				}
			case certificateIdentity.PriorGeneration > 0 && observedPointer != certificateIdentity.PriorPointer || certificateIdentity.PriorGeneration == 0 && observedPointer != "":
				return fenceAndRelease(fmt.Errorf("certificate pointer differs from journal"))
			}
		}
		if !committedCertificate {
			if err := certificates.RemoveInactiveBundle(certificateIdentity.CertificateID, certificateIdentity.CandidateGeneration, certificateIdentity.CandidateBundleIdentity, certificateIdentity.StageUID, certificateIdentity.StageGID); err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
		}
		if err := errors.Join(acme.RemoveStage(certificateIdentity.CertificateID, certificateIdentity.StageUID, certificateIdentity.StageGID), acme.RemoveWebroot(certificateIdentity.CertificateID, certificateIdentity.StageUID, certificateIdentity.StageGID)); err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		admitter, err := service.TimerAdmitter()
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		stageIdentity, stageErr := identity.CertificateStageIdentityFor(certificateIdentity.CertificateID)
		if stageErr != nil || stageIdentity.UID != certificateIdentity.StageUID || stageIdentity.GID != certificateIdentity.StageGID {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("certificate recovery stage identity changed")
		}
		if stageErr := validateCertificateStageIdentity(document, stageIdentity); stageErr != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return stageErr
		}
		if !slices.Equal(journal.ChildIDs, []string{"lego-" + jobID}) {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("certificate recovery child inventory changed")
		}
		if publicationHandoff != nil {
			appRaw, present := document.Entries["journals/activation-"+jobID]
			var appJournal operations.JournalRecord
			if !present || json.Unmarshal(appRaw, &appJournal) != nil || journal.Phase != operations.JournalTerminal || appJournal.Kind != operations.JournalAppActivation || (appJournal.Phase != operations.JournalPrepared && appJournal.Phase != operations.JournalTerminal) || appJournal.JobID != jobID || appJournal.SafetyMarkerDigest == publicationHandoff.ChallengeSafetyDigest || publicationIntent == nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return fmt.Errorf("certificate publication handoff recovery identity changed")
			}
			if appJournal.Phase == operations.JournalPrepared {
				if publicationIntent.Phase != operations.PhaseLocalIntent {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return fmt.Errorf("certificate publication handoff phase changed")
				}
				if err := admitter.RejectPublication(ctx, mutation, exposure, document.Revision, jobID, "certificate_handoff_interrupted"); err != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return err
				}
			} else {
				record, recordErr := jobs.LoadEntries(document.Entries, jobID)
				if publicationIntent.Phase != operations.PhaseTerminal || recordErr != nil || record.Status != jobs.StatusTerminal || record.Result != jobs.ResultFailed {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return fmt.Errorf("certificate publication rejection is incomplete")
				}
			}
			fresh, err := service.safety.ReadForRecovery(exposure)
			if err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
			next := fresh
			next.Revision++
			next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
			matched := false
			for index := range next.Resources {
				if next.Resources[index].ResourceID == resource.ResourceID && next.Resources[index].ChallengePending != nil && challenge.Matches(*next.Resources[index].ChallengePending, challenge.Prepared{Safety: *pending}) {
					next.Resources[index].ChallengePending = nil
					matched = true
				}
			}
			if !matched {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return fmt.Errorf("certificate publication handoff safety changed")
			}
			_, commitErr := service.safety.Commit(ctx, exposure, safety.RoleContraction, fresh.Revision, next, safety.TransitionProof{})
			releaseErr := operations.ReleaseExposure(mutation, exposure)
			closeErr := mutationSet.Close()
			if err := errors.Join(commitErr, releaseErr, closeErr); err != nil {
				return err
			}
			continue
		}
		if committedCertificate {
			if journal.Operation != operations.CertificateRenew {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return fmt.Errorf("unexpected committed publication certificate journal")
			}
			completionRevision := document.Revision
			if journal.Phase == operations.JournalActive {
				terminalJournal := journal
				terminalJournal.Phase = operations.JournalTerminal
				if putErr := admitter.PutJournal(ctx, mutation, exposure, completionRevision, terminalJournal, false); putErr != nil {
					_ = operations.ReleaseExposure(mutation, exposure)
					_ = mutationSet.Close()
					return putErr
				}
				completionRevision++
			}
			fresh, readErr := service.safety.ReadForRecovery(exposure)
			if readErr != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return readErr
			}
			next := fresh
			next.Revision++
			next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
			matched := false
			for index := range next.Resources {
				if next.Resources[index].ResourceID == resource.ResourceID && next.Resources[index].ChallengePending != nil && next.Resources[index].ChallengePending.Generation == pending.Generation {
					next.Resources[index].ChallengePending = nil
					matched = true
				}
			}
			if !matched {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return fmt.Errorf("terminal certificate challenge authority changed")
			}
			if _, commitErr := service.safety.Commit(ctx, exposure, safety.RoleChallenge, fresh.Revision, next, safety.TransitionProof{}); commitErr != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return commitErr
			}
			_, completeErr := admitter.Complete(ctx, mutation, exposure, completionRevision, jobID, "complete", []string{certificateIdentity.CandidatePointer}, []jobs.Postcondition{{Kind: "certificate_renewed_and_served", Status: jobs.PostconditionVerified, Identity: certificateIdentity.CandidateFingerprint}}, "")
			releaseErr := operations.ReleaseExposure(mutation, exposure)
			closeErr := mutationSet.Close()
			if err := errors.Join(completeErr, releaseErr, closeErr); err != nil {
				return err
			}
			continue
		}
		closureRaw, _ := json.Marshal(struct {
			Resource   string `json:"resource"`
			Generation uint64 `json:"generation"`
			SAN        string `json:"san"`
			Binding    string `json:"binding"`
		}{resource.ResourceID, pending.Generation, pending.SANIdentity, pending.ACMEBinding})
		closureRaw = append(closureRaw, []byte("\x00"+childClosure)...)
		closureDigest := shaDigest(closureRaw)
		if publicationIntent == nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return fmt.Errorf("certificate recovery intent missing")
		}
		if publicationIntent.Phase != operations.PhaseTerminal {
			if _, err := admitter.TerminalizeContractedCertificate(ctx, mutation, exposure, document.Revision, jobID, *pending, closureDigest); err != nil {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return err
			}
		} else {
			record, recordErr := jobs.LoadEntries(document.Entries, jobID)
			if recordErr != nil || record.Status != jobs.StatusTerminal || record.Result != jobs.ResultInterrupted || journal.Phase != operations.JournalTerminal {
				_ = operations.ReleaseExposure(mutation, exposure)
				_ = mutationSet.Close()
				return fmt.Errorf("certificate recovery terminal authority changed")
			}
		}
		fresh, err := service.safety.ReadForRecovery(exposure)
		if err != nil {
			_ = operations.ReleaseExposure(mutation, exposure)
			_ = mutationSet.Close()
			return err
		}
		next := fresh
		next.Revision++
		next.Resources = append([]safety.ResourceSafety(nil), fresh.Resources...)
		for index := range next.Resources {
			if next.Resources[index].ResourceID == resource.ResourceID && next.Resources[index].ChallengePending != nil && next.Resources[index].ChallengePending.Generation == pending.Generation {
				next.Resources[index].ChallengePending = nil
			}
		}
		_, err = service.safety.Commit(ctx, exposure, safety.RoleContraction, fresh.Revision, next, safety.TransitionProof{})
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if errors.Join(err, releaseErr, closeErr) != nil {
			return errors.Join(err, releaseErr, closeErr)
		}
	}
	return nil
}

func loadCertificateLegoDigest() (string, error) {
	identity, err := loadInstalledReleaseIdentity()
	if err != nil {
		return "", err
	}
	if identity.Lego.Digest == "" {
		return "", fmt.Errorf("installed lego identity missing")
	}
	return identity.Lego.Digest, nil
}

func validateCertificateStageIdentity(document persist.Document, stage identity.CertificateStageIdentity) error {
	if err := identity.VerifyCertificateStageIdentityAvailable(stage, "/etc/passwd", "/etc/group"); err != nil {
		return err
	}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "journals/") {
			continue
		}
		var journal operations.JournalRecord
		if json.Unmarshal(raw, &journal) != nil || journal.Certificate == nil || journal.Certificate.CertificateID == stage.CertificateID {
			continue
		}
		other, err := identity.CertificateStageIdentityFor(journal.Certificate.CertificateID)
		if err != nil {
			return err
		}
		if other.UID == stage.UID || other.GID == stage.GID {
			return fmt.Errorf("certificate stage identity collides with journal %q", journal.ID)
		}
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return err
	}
	for _, resource := range installation.Resources {
		bundle := resource.PublicationRecord.LastAppliedBundle
		if bundle == nil || bundle.DomainHTTPS == nil || bundle.DomainHTTPS.Certificate.Authority == nil {
			continue
		}
		certificateID := bundle.DomainHTTPS.Certificate.Authority.CertificateID
		if certificateID == stage.CertificateID {
			continue
		}
		other, err := identity.CertificateStageIdentityFor(certificateID)
		if err != nil {
			return err
		}
		if other.UID == stage.UID || other.GID == stage.GID {
			return fmt.Errorf("certificate stage identity collides with applied resource %q", resource.ID)
		}
	}
	return nil
}

func loadCertificateResource(entries map[string]json.RawMessage, id string) (domain.Installation, domain.AppResource, error) {
	raw, present := entries["installations/current"]
	if !present {
		return domain.Installation{}, domain.AppResource{}, fmt.Errorf("installation missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return domain.Installation{}, domain.AppResource{}, err
	}
	for _, resource := range installation.Resources {
		if resource.ID == id {
			return installation, resource, nil
		}
	}
	return domain.Installation{}, domain.AppResource{}, fmt.Errorf("resource missing")
}
