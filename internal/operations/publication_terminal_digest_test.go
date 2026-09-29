package operations

import (
	"context"
	"encoding/json"
	"lanpanel/internal/acme"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/persist"
	"lanpanel/internal/publication"
	"lanpanel/internal/safety"
	"testing"
	"time"
)

func TestCertificateTerminalCommitAcceptsDurablyEquivalentBundle(t *testing.T) {
	created := time.Now().UTC()
	now := created.Add(20 * time.Minute)
	planDeadline := created.Add(9 * time.Minute)
	jobID := zID("job_")
	resourceID := zShort("res_")
	planID := zID("plan_")
	config := zDigest("config")
	candidateBundle, certIdentity := zCert([]string{"app.example.test"})
	candidatePath, _ := certificates.BundlePath(candidateBundle.Authority.CertificateID, 1)
	candidate := domain.PublicationBundle{ID: zShort("pub_"), Generation: 2, ConfigDigest: config, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: zDigest("endpoint"), SiteIdentity: zDigest("site"), ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test"}, Certificate: candidateBundle, Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, Static: domain.StaticBundleIdentity{Routes: []domain.StaticRouteBundleIdentity{}, RouteIdentities: []string{}}, GoAccess: domain.GoAccessBundleIdentity{Enabled: false}}}
	bundleDigest, err := publication.BundleDigest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	beforeResource := operationStateInstallation().Resources[0]
	beforeResource.ID = resourceID
	beforeResource.CurrentConfigDigest = config
	beforeResource.Publication.DomainHTTPS.CanonicalDomain = "app.example.test"
	installation := operationStateInstallation()
	installation.InstallationID = zShort("ins_")
	installation.Resources = []domain.AppResource{beforeResource}
	running := jobs.Record{SchemaVersion: jobs.SchemaVersion, ID: jobID, Operation: string(Publish), Target: "resource/" + resourceID, ActorIdentity: "ui/session", StartedAt: created, Status: jobs.StatusRunning, ModifiedPaths: []string{}, Postconditions: []jobs.Postcondition{}}
	binding := SafetyBinding{ResourceID: resourceID, PlanID: planID, IntentGeneration: 2, CandidateDigest: zDigest("san"), CandidateBundle: zDigest("acme"), Deadline: planDeadline, ChallengeMethod: string(acme.ChallengeHTTP01), CertificateIdentity: candidateBundle.Authority.CertificateID}
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: jobID, PlanID: planID, OperationBinding: zDigest("acme"), AdmissionSource: AdmissionPlan, Operation: Publish, Target: "resource/" + resourceID, Phase: PhaseReentered, SafetyDigest: zDigest("safety"), SafetyBinding: binding, CreatedAt: created, IntentGeneration: 14, JournalSafetyDigest: zDigest("challenge-marker"), Consumption: &ConsumptionSnapshot{Source: AdmissionPlan, ConfirmationDigest: zDigest("confirmation"), ConfirmedAt: created, SafetyDigest: zDigest("consumed")}}
	childID := zShort("child_")
	child := ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: childID, JobID: jobID, InstallationID: installation.InstallationID, Operation: Publish, Target: intent.Target, IntentGeneration: 14, Profile: "lego", InputDigest: zDigest("acme"), ArtifactDigest: zDigest("artifact"), Deadline: binding.Deadline, State: ChildRunning, SubmittedAt: created}
	certJournal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + jobID, JobID: jobID, Kind: JournalCertificateActivation, Operation: Publish, InstallationID: installation.InstallationID, Target: intent.Target, Generation: 14, Deadline: binding.Deadline, ArtifactDigest: child.ArtifactDigest, SafetyMarkerDigest: zDigest("challenge-marker"), ResourceIDs: []string{resourceID}, ChildIDs: []string{child.ID}, Phase: JournalActive, Certificate: &CertificateJournalIdentity{CertificateID: candidateBundle.Authority.CertificateID, CandidateGeneration: 1, CandidatePointer: candidatePath, CandidateFingerprint: candidateBundle.Fingerprint, CandidateBundleIdentity: certIdentity, Challenge: safety.ChallengePending{Generation: 2, PlanID: planID, Method: string(acme.ChallengeHTTP01), ConfigDigest: config, SANIdentity: candidateBundle.SANIdentity, ACMEBinding: zDigest("acme-binding"), CertificateIdentity: candidateBundle.Authority.CertificateID, Webroot: "/var/lib/lanpanel/certificates/webroot/" + candidateBundle.Authority.CertificateID, Host: "app.example.test", Hosts: []string{"app.example.test"}}, StageUID: 1000, StageGID: 1000}}
	handoff := intent
	handoff.Phase = PhaseLocalIntent
	handoff.CertificateHandoff = &CertificatePublicationHandoff{PlanID: planID, Generation: 2, SANIdentity: binding.CandidateDigest, ACMEBinding: binding.CandidateBundle, CertificateID: certJournal.Certificate.CertificateID, Fingerprint: certJournal.Certificate.CandidateFingerprint, ChallengeSafetyDigest: certJournal.SafetyMarkerDigest}
	handoff.SafetyBinding.CandidateDigest = config
	handoff.SafetyBinding.CandidateBundle = bundleDigest
	handoff.JournalSafetyDigest, _ = SafetyBindingDigest(handoff.SafetyBinding)
	afterInstallation := installation
	afterInstallation.Resources = []domain.AppResource{beforeResource}
	afterInstallation.Resources[0].PublicationRecord.State = domain.PublicationActivating
	afterInstallation.Resources[0].PublicationRecord.ActivationIntent = &domain.ActivationIntent{ID: "activation-" + jobID, JobID: jobID, PlanID: planID, Generation: 2, Candidate: candidate, PriorState: domain.PublicationUnpublished}
	afterInstallation.Resources[0].PublicationRecord.LastJobID = jobID
	appJournal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "activation-" + jobID, JobID: jobID, Kind: JournalAppActivation, Operation: Publish, InstallationID: installation.InstallationID, Target: intent.Target, Generation: 14, Deadline: binding.Deadline, ArtifactDigest: bundleDigest, SafetyMarkerDigest: handoff.JournalSafetyDigest, ResourceIDs: []string{resourceID}, ChildIDs: []string{}, Phase: JournalPrepared}
	terminalCert := certJournal
	terminalCert.Phase = JournalTerminal
	terminalChild := child
	terminalChild.State = ChildTerminal
	terminalChild.Outcome = ChildSucceeded
	ended := created.Add(time.Second)
	terminalChild.TerminalAt = &ended
	terminalChild.ResultDigest = zDigest("result")
	before := zDoc(t, installation, intent, running, certJournal)
	before.Entries["children/"+child.ID], _ = persist.EncodeEntry(child)
	after := zDoc(t, afterInstallation, handoff, running, appJournal, terminalCert)
	after.Entries["children/"+child.ID], _ = persist.EncodeEntry(terminalChild)

	normal, manager, admission, mutationSet := newOperationStores(t)
	defer func() { _ = normal.Close(); _ = mutationSet.Close(); _ = manager.Close() }()
	validator := func(string, json.RawMessage) error { return nil }
	transition := func(string, json.RawMessage, json.RawMessage) error { return nil }
	if err := normal.RegisterCanonicalNamespace("plans", "plans.v1", validator, transition); err != nil {
		t.Fatalf("register plans: %v", err)
	}
	if err := normal.RegisterCanonicalNamespace("jobs", "jobs.v1", validator, transition); err != nil {
		t.Fatalf("register jobs: %v", err)
	}
	if err := normal.RegisterCanonicalNamespace("intents", "operations.intents.v1", validator, transition); err != nil {
		t.Fatalf("register intents: %v", err)
	}
	if err := normal.RegisterCanonicalNamespace("expiry_generations", "operations.expiry.generations.v1", validator, transition); err != nil {
		t.Fatalf("register expiry: %v", err)
	}
	if err := normal.RegisterCanonicalNamespace("children", "operations.children.v1", validator, transition); err != nil {
		t.Fatalf("register children: %v", err)
	}
	if err := normal.RegisterCanonicalNamespace("journals", "operations.journals.v1", validator, transition); err != nil {
		t.Fatalf("register journals: %v", err)
	}
	if err := normal.RegisterCanonicalDocumentValidator("operations.links.v1", func(persist.Document) error { return nil }); err != nil {
		t.Fatalf("register links: %v", err)
	}
	if err := normal.RegisterCanonicalDocumentTransitionValidator("operations.resource_transitions.v1", func(persist.Document, persist.Document) error { return nil }); err != nil {
		t.Fatalf("register transitions: %v", err)
	}
	if err := normal.RegisterCanonicalDocumentTransitionValidator("plans.retention.v1", func(persist.Document, persist.Document) error { return nil }); err != nil {
		t.Fatalf("register retention: %v", err)
	}
	if err := normal.SealSchema(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	installationRaw, _ := persist.EncodeEntry(installation)
	if _, _, err := normal.Update(context.Background(), admission, 1, func(transaction *persist.Transaction) error {
		return transaction.Create("installations/current", installationRaw)
	}); err != nil {
		t.Fatalf("populate installation: %v", err)
	}
	if _, _, err := normal.Update(context.Background(), admission, 2, func(transaction *persist.Transaction) error {
		for key, raw := range after.Entries {
			if key == "installations/current" {
				if err := transaction.Replace(key, raw); err != nil {
					return err
				}
				continue
			}
			if err := transaction.Create(key, raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("populate after: %v", err)
	}
	if err := admission.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	table, err := NewBranchTable([]ResultBranch{{Name: "complete", Result: jobs.ResultSucceeded, Postcondition: jobs.PostconditionVerified}, {Name: "no_effect", Result: jobs.ResultFailed, Postcondition: jobs.PostconditionVerified}, {Name: "known_residual", Result: jobs.ResultPartial, Postcondition: jobs.PostconditionKnown}, {Name: "executor_died", Result: jobs.ResultInterrupted, Postcondition: jobs.PostconditionKnown}, {Name: "source_unknown", Result: jobs.ResultUnknown, Postcondition: jobs.PostconditionUnobserved}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Registration{{Operation: Publish, Owner: "debug", Results: table}})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := NewAdmitter(normal, &fakeSafety{state: openSafetyState(), authority: manager.Authority()}, Options{Now: func() time.Time { return now }, Bindings: trustedBindings{}, Confirmation: testConfirmation{}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(context.Background(), "resource/"+resourceID, manager)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ReleaseExposure(mutation, exposure) }()
	document, err := normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	record, err := admitter.CommitPublicationPublished(context.Background(), mutation, exposure, document.Revision, jobID, PublicationTerminalCommit{ResourceID: resourceID, Bundle: candidate, Runtime: domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: time.Now().UTC().Format(time.RFC3339), Reason: "published"}}, "activation-"+jobID, zDigest("runtime"), nil, func() error { return nil })
	if err != nil {
		t.Fatalf("terminal commit: %v", err)
	}
	if record.Status != jobs.StatusTerminal || record.Result != jobs.ResultSucceeded {
		t.Fatalf("record=%#v", record)
	}
}
