package operations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/publication"
	"lanpanel/internal/safety"
	"strings"
	"testing"
	"time"
)

func zDigest(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}
func zID(prefix string) string    { return prefix + strings.Repeat("a", 64) }
func zShort(prefix string) string { return prefix + strings.Repeat("a", 32) }
func zCert(domains []string) (domain.CertificateBundleIdentity, certificates.BundleIdentity) {
	authority := &domain.CertificateAuthorityIdentity{CertificateID: zShort("cert_"), DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: zDigest("account"), AccountEmail: "admin@example.test", TermsAccepted: true, Method: string(acme.ChallengeHTTP01), CredentialFiles: []domain.CertificateCredentialIdentity{}}
	binding := acme.Binding{DirectoryURL: authority.DirectoryURL, AccountKeyPath: authority.AccountKeyPath, AccountKeyFingerprint: authority.AccountKeyFingerprint, AccountEmail: authority.AccountEmail, TermsAccepted: authority.TermsAccepted, Method: acme.ChallengeHTTP01}
	bind, _ := acme.BindingDigest(binding)
	h := sha256.Sum256([]byte(strings.Join(domains, "\x00")))
	san := "sha256:" + hex.EncodeToString(h[:])
	c := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/" + authority.CertificateID + ".current", BindingIdentity: bind, Generation: 1, Fingerprint: zDigest("fingerprint"), SANIdentity: san, ChainIdentity: zDigest("chain"), IssuerIdentity: zDigest("issuer"), DirectoryIdentity: zDigest("directory"), NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", Authority: authority}
	return c, certificates.BundleIdentity{Fingerprint: c.Fingerprint, SANIdentity: c.SANIdentity, ChainIdentity: c.ChainIdentity, IssuerIdentity: c.IssuerIdentity, BindingIdentity: c.BindingIdentity, DirectoryIdentity: c.DirectoryIdentity}
}

func zDoc(t *testing.T, installation domain.Installation, intent Reservation, record jobs.Record, journals ...JournalRecord) persist.Document {
	t.Helper()
	enc := func(v any) json.RawMessage {
		r, e := persist.EncodeEntry(v)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	entries := map[string]json.RawMessage{"installations/current": enc(installation), reservationKey(intent.JobID): enc(intent), "jobs/" + record.ID: enc(record)}
	planTime := intent.CreatedAt
	consumed := planTime.Add(time.Second)
	plan := plans.Plan{SchemaVersion: plans.SchemaVersion, ID: intent.PlanID, Operation: string(intent.Operation), Target: plans.Target{Kind: plans.TargetResource, ID: intent.SafetyBinding.ResourceID}, ActorIdentity: "ui/session", Config: intent.Consumption.Config, Applied: intent.Consumption.Applied, Evidence: append([]plans.Evidence(nil), intent.Consumption.Evidence...), ExposureSummary: "x", Prerequisites: "x", CreatedAt: planTime, ExpiresAt: intent.SafetyBinding.Deadline, NonceDigest: intent.Consumption.ConfirmationDigest, ReservedAt: &planTime, ReservedByJob: intent.JobID, ConsumedAt: &consumed, ConsumedByJob: intent.JobID}
	entries["plans/"+plan.ID] = enc(plan)
	for _, j := range journals {
		entries["journals/"+j.ID] = enc(j)
		for _, childID := range j.ChildIDs {
			_ = childID
		}
	}
	return persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: entries}
}

func TestCertificateHandoffTransition(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	jobID := zID("job_")
	resourceID := zShort("res_")
	planID := zID("plan_")
	config := zDigest("config")
	oldBundle := zDigest("acme")
	challengeMarker := zDigest("challenge-marker")
	operationGeneration := uint64(14)
	candidateBundle, certIdentity := zCert([]string{"app.example.test"})
	candidatePath, _ := certificates.BundlePath(candidateBundle.Authority.CertificateID, 1)
	candidate := domain.PublicationBundle{ID: zShort("pub_"), Generation: 2, ConfigDigest: config, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: zDigest("endpoint"), SiteIdentity: zDigest("site"), ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test"}, Certificate: candidateBundle, Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, Static: domain.StaticBundleIdentity{RouteIdentities: []string{}}, GoAccess: domain.GoAccessBundleIdentity{Enabled: false}}}
	bundleDigest, e := publication.BundleDigest(candidate)
	if e != nil {
		t.Fatal(e)
	}
	beforeResource := operationStateInstallation().Resources[0]
	beforeResource.ID = resourceID
	beforeResource.CurrentConfigDigest = config
	beforeResource.Publication.DomainHTTPS.CanonicalDomain = "app.example.test"
	installation := operationStateInstallation()
	installation.InstallationID = zShort("ins_")
	installation.Resources = []domain.AppResource{beforeResource}
	created := now
	running := jobs.Record{SchemaVersion: jobs.SchemaVersion, ID: jobID, Operation: string(Publish), Target: "resource/" + resourceID, ActorIdentity: "ui/session", StartedAt: created, Status: jobs.StatusRunning, ModifiedPaths: []string{}, Postconditions: []jobs.Postcondition{}}
	binding := SafetyBinding{ResourceID: resourceID, PlanID: planID, IntentGeneration: 2, CandidateDigest: zDigest("san"), CandidateBundle: oldBundle, Deadline: now.Add(time.Hour), ChallengeMethod: string(acme.ChallengeHTTP01), CertificateIdentity: candidateBundle.Authority.CertificateID}
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: jobID, PlanID: planID, OperationBinding: oldBundle, AdmissionSource: AdmissionPlan, Operation: Publish, Target: "resource/" + resourceID, Phase: PhaseReentered, SafetyDigest: zDigest("safety"), SafetyBinding: binding, CreatedAt: created, IntentGeneration: operationGeneration, JournalSafetyDigest: challengeMarker, Consumption: &ConsumptionSnapshot{Source: AdmissionPlan, ConfirmationDigest: zDigest("confirmation"), ConfirmedAt: created, SafetyDigest: zDigest("consumed")}}
	child := ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: zShort("child_"), JobID: jobID, InstallationID: installation.InstallationID, Operation: Publish, Target: intent.Target, IntentGeneration: operationGeneration, Profile: "lego", InputDigest: zDigest("input"), ArtifactDigest: zDigest("artifact"), Deadline: binding.Deadline, State: ChildRunning, SubmittedAt: created}
	certJournal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + jobID, JobID: jobID, Kind: JournalCertificateActivation, Operation: Publish, InstallationID: installation.InstallationID, Target: intent.Target, Generation: operationGeneration, Deadline: binding.Deadline, ArtifactDigest: child.ArtifactDigest, SafetyMarkerDigest: challengeMarker, ResourceIDs: []string{resourceID}, ChildIDs: []string{child.ID}, Phase: JournalActive, Certificate: &CertificateJournalIdentity{CertificateID: candidateBundle.Authority.CertificateID, CandidateGeneration: 1, CandidatePointer: candidatePath, CandidateFingerprint: candidateBundle.Fingerprint, CandidateBundleIdentity: certIdentity, Challenge: safety.ChallengePending{Generation: 2, PlanID: planID, Method: string(acme.ChallengeHTTP01), ConfigDigest: config, SANIdentity: candidateBundle.SANIdentity, ACMEBinding: zDigest("acme-binding"), CertificateIdentity: candidateBundle.Authority.CertificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + candidateBundle.Authority.CertificateID, Host: "app.example.test", Hosts: []string{"app.example.test"}}, StageUID: 1000, StageGID: 1000}}
	before := zDoc(t, installation, intent, running, certJournal)
	before.Entries["children/"+child.ID] = func() json.RawMessage { r, _ := persist.EncodeEntry(child); return r }()
	handoff := intent
	handoff.Phase = PhaseLocalIntent
	handoff.CertificateHandoff = &CertificatePublicationHandoff{PlanID: planID, Generation: 2, SANIdentity: binding.CandidateDigest, ACMEBinding: oldBundle, CertificateID: certJournal.Certificate.CertificateID, Fingerprint: certJournal.Certificate.CandidateFingerprint, ChallengeSafetyDigest: challengeMarker}
	handoff.SafetyBinding.CandidateDigest = config
	handoff.SafetyBinding.CandidateBundle = bundleDigest
	handoff.JournalSafetyDigest, _ = SafetyBindingDigest(handoff.SafetyBinding)
	activation := domain.ActivationIntent{ID: "activation-" + jobID, JobID: jobID, PlanID: planID, Generation: 2, Candidate: candidate, PriorState: domain.PublicationUnpublished}
	afterInstallation := installation
	afterInstallation.Resources = []domain.AppResource{beforeResource}
	afterInstallation.Resources[0].PublicationRecord.State = domain.PublicationActivating
	afterInstallation.Resources[0].PublicationRecord.ActivationIntent = &activation
	afterInstallation.Resources[0].PublicationRecord.LastJobID = jobID
	appJournal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "activation-" + jobID, JobID: jobID, Kind: JournalAppActivation, Operation: Publish, InstallationID: installation.InstallationID, Target: intent.Target, Generation: operationGeneration, Deadline: binding.Deadline, ArtifactDigest: bundleDigest, SafetyMarkerDigest: handoff.JournalSafetyDigest, ResourceIDs: []string{resourceID}, ChildIDs: []string{}, Phase: JournalPrepared}
	terminalCert := certJournal
	terminalCert.Phase = JournalTerminal
	terminalChild := child
	terminalChild.State = ChildTerminal
	terminalChild.Outcome = ChildSucceeded
	ended := created.Add(time.Second)
	terminalChild.TerminalAt = &ended
	terminalChild.ResultDigest = zDigest("result")
	after := zDoc(t, afterInstallation, handoff, running, appJournal, terminalCert)
	after.Entries["children/"+child.ID] = func() json.RawMessage { r, _ := persist.EncodeEntry(terminalChild); return r }()
	if err := validateOperationStateTransitions(before, after); err != nil {
		t.Fatalf("begin transition: %v", err)
	}
	if err := validateLinks(after); err != nil {
		t.Fatalf("begin links: %v", err)
	}
	finalIntent := handoff
	finalIntent.Phase = PhaseTerminal
	ended2 := created.Add(2 * time.Second)
	finalRecord := running
	finalRecord.Status = jobs.StatusTerminal
	finalRecord.Result = jobs.ResultSucceeded
	finalRecord.EndedAt = &ended2
	finalRecord.Postconditions = []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: zDigest("runtime")}}
	finalInstallation := afterInstallation
	finalInstallation.Resources[0].PublicationRecord.State = domain.PublicationPublished
	finalInstallation.Resources[0].PublicationRecord.ActivationIntent = nil
	digest := config
	finalInstallation.Resources[0].PublicationRecord.LastAppliedDigest = &digest
	finalInstallation.Resources[0].PublicationRecord.LastAppliedBundle = &candidate
	finalInstallation.Resources[0].PublicationRecord.LastOperation = domain.OperationPublish
	finalInstallation.Resources[0].PublicationRecord.LastOperationResult = domain.OperationSucceeded
	finalJournal := appJournal
	finalJournal.Phase = JournalTerminal
	final := zDoc(t, finalInstallation, finalIntent, finalRecord, finalJournal, terminalCert)
	final.Entries["children/"+child.ID] = after.Entries["children/"+child.ID]
	if err := validateOperationStateTransitions(after, final); err != nil {
		t.Fatalf("terminal transition: %v", err)
	}
	if err := validateLinks(final); err != nil {
		t.Fatalf("terminal links: %v", err)
	}
}
