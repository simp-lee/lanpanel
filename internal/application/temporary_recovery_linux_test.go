//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"lanpanel/internal/activation"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/publication"
	"lanpanel/internal/safety"
	"os"
	"slices"
	"testing"
	"time"
)

type temporaryRecoveryRuntimeProbe struct {
	verify         bool
	entry          nginx.Entry
	verifyCalls    int
	auditCalls     int
	contractCalls  int
	probeCalls     int
	probeInventory closure.Inventory
	stopCalls      int
}

func (host *temporaryRecoveryRuntimeProbe) VerifyTemporary(context.Context, publication.Candidate, domain.AppTarget) (string, error) {
	host.verifyCalls++
	if !host.verify {
		return "", errors.New("temporary candidate is not live")
	}
	return recoveryDigest("temporary-runtime"), nil
}

func (host *temporaryRecoveryRuntimeProbe) AuditManifest(context.Context) (nginx.Manifest, error) {
	host.auditCalls++
	manifest := nginx.Manifest{DefaultCertFingerprint: recoveryDigest("default-certificate")}
	if host.entry.ResourceID != "" {
		manifest.Entries = []nginx.Entry{host.entry}
	}
	return manifest, nil
}

func (host *temporaryRecoveryRuntimeProbe) ContractResource(context.Context, string) (activation.Result, error) {
	host.contractCalls++
	return activation.Result{ModifiedPaths: []string{"/etc/lanpanel/nginx/temporary/recovered.conf"}}, nil
}

func (host *temporaryRecoveryRuntimeProbe) AcknowledgeContraction(context.Context, string) error {
	return nil
}

func (host *temporaryRecoveryRuntimeProbe) ProbeTemporaryClosure(_ context.Context, inventory closure.Inventory) (string, error) {
	host.probeCalls++
	host.probeInventory = inventory
	for _, identity := range inventory.Identities {
		if identity.Kind == closure.IdentityTemporaryListener {
			return recoveryDigest("temporary-closure-probe"), nil
		}
	}
	return "", errors.New("temporary listener missing from pre-contraction inventory")
}

func (host *temporaryRecoveryRuntimeProbe) StopAndVerify(context.Context) (closure.RuntimeSnapshot, error) {
	host.stopCalls++
	return closure.RuntimeSnapshot{ObservedAt: time.Now().UTC()}, nil
}

type temporaryRecoveryFixture struct {
	fixture   resourceRecoveryFixture
	resource  domain.AppResource
	candidate publication.Candidate
	marker    safety.Reactivating
	plan      plans.Plan
	jobID     string
}

func temporaryRecoveryResource(t *testing.T) domain.AppResource {
	t.Helper()
	value := recoveryTailnetResource()
	value.Name = "Temporary App"
	value.Publication = domain.AppPublication{Kind: domain.PublicationTemporaryHTTP, TemporaryHTTP: &domain.TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 18080}}
	return value
}

func safetyStateDigestForTest(t *testing.T, state safety.State) string {
	t.Helper()
	state.Checksum = ""
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func consumeTemporaryPlan(t *testing.T, service *FixedService, exposure *locks.Lease, plan plans.Plan, jobID string) operations.Reservation {
	t.Helper()
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.safety.Read()
	if err != nil {
		t.Fatal(err)
	}
	safetyDigest := safetyStateDigestForTest(t, state)
	confirmedAt := time.Now().UTC()
	var consumed operations.Reservation
	_, _, err = service.normal.Update(context.Background(), exposure, document.Revision, func(transaction *persist.Transaction) error {
		raw, present := transaction.Get("intents/" + jobID)
		if !present {
			return errors.New("temporary test intent missing")
		}
		var intent operations.Reservation
		if err := json.Unmarshal(raw, &intent); err != nil {
			return err
		}
		binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
		if _, err := plans.Consume(transaction, plan.ID, jobID, binding, confirmedAt); err != nil {
			return err
		}
		record, err := jobs.Load(transaction, jobID)
		if err != nil {
			return err
		}
		record, err = jobs.Start(record)
		if err != nil {
			return err
		}
		if err := jobs.Replace(transaction, record); err != nil {
			return err
		}
		intent.Phase = operations.PhaseLocalIntent
		intent.IntentGeneration = document.Revision + 1
		intent.Consumption = &operations.ConsumptionSnapshot{Source: operations.AdmissionPlan, Config: plan.Config, Applied: plan.Applied, Evidence: append([]plans.Evidence(nil), plan.Evidence...), ConfirmationDigest: plan.NonceDigest, ConfirmedAt: confirmedAt, SafetyDigest: safetyDigest}
		raw, err = persist.EncodeEntry(intent)
		if err != nil {
			return err
		}
		if err := transaction.Replace("intents/"+jobID, raw); err != nil {
			return err
		}
		consumed = intent
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return consumed
}

func newTemporaryRecoveryFixture(t *testing.T, stage string) temporaryRecoveryFixture {
	t.Helper()
	resource := temporaryRecoveryResource(t)
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(&resource))
	service := fixture.open(t)
	setupSet, mutation, exposure := fixture.acquire(t, service, "resource/"+resource.ID)
	writeRecoveryOwnershipAndSafety(t, service, exposure, resource.ID)
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), setupSet.Close()); err != nil {
		t.Fatal(err)
	}
	planStore, err := plans.NewStore(service.normal, plans.Options{})
	if err != nil {
		t.Fatal(err)
	}
	service.plans = planStore
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planStore.Create(context.Background(), admission, document.Revision, plans.Spec{Operation: string(domain.OperationPublish), Target: plans.Target{Kind: plans.TargetResource, ID: resource.ID}, ActorIdentity: "ui/test/generation/1", Config: plans.DigestBinding{Applicable: true, Digest: resource.CurrentConfigDigest}, ExposureSummary: "temporary_test_publication", Prerequisites: "test", Lifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := publication.PrepareTemporary(resource, 2)
	if err != nil {
		t.Fatal(err)
	}
	binding := operations.SafetyBinding{ResourceID: resource.ID, PlanID: plan.ID, IntentGeneration: 2, CandidateDigest: candidate.Bundle.ConfigDigest, CandidateBundle: candidate.BundleDigest, Deadline: plan.ExpiresAt}
	admitter, err := service.Admitter(plan)
	if err != nil {
		t.Fatal(err)
	}
	job, err := admitter.Admit(context.Background(), admission, operations.AdmitRequest{Operation: operations.Publish, Target: "resource/" + resource.ID, ActorIdentity: plan.ActorIdentity, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: binding, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		t.Fatal(errors.Join(err, releaseErr))
	}
	mutationSet, mutation, exposure := fixture.acquire(t, service, "resource/"+resource.ID)
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		t.Fatal(err)
	}
	marker := safety.Reactivating{Generation: 2, PriorGeneration: 1, PlanID: plan.ID, CandidateDigest: candidate.Bundle.ConfigDigest, CandidateBundle: candidate.BundleDigest, BaseMarkers: baseSnapshot(state.Resources[0]), TemporaryHTTP: true}
	next := state
	next.Revision++
	next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
	next.Resources[0].GenerationSequence = 2
	next.Resources[0].Reactivating = &marker
	if stage != "admitted" {
		if _, err := service.safety.Commit(context.Background(), exposure, safety.RolePublish, state.Revision, next, safety.TransitionProof{}); err != nil {
			t.Fatal(err)
		}
	}
	if stage == "marker_cleared" {
		if err := service.RestorePublicationSafety(context.Background(), exposure, resource.ID, marker); err != nil {
			t.Fatal(err)
		}
	}
	var intent operations.Reservation
	switch stage {
	case "admitted", "reserved", "marker_cleared":
	case "consume_failed":
		document, err := service.normal.Read()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admitter.ConsumePlan(context.Background(), mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision + 1, IntentGeneration: document.Revision + 2, ConfirmationProof: plan.NonceDigest}); err == nil {
			t.Fatal("ConsumePlan failure was not injected")
		}
	case "consumed", "intent", "journal", "terminal_failed", "ownership", "ready", "committed":
		intent = consumeTemporaryPlan(t, service, exposure, plan, job.ID)
		if stage != "consumed" {
			activationIntent := domain.ActivationIntent{ID: "activation-" + job.ID, JobID: job.ID, PlanID: plan.ID, Generation: marker.Generation, Candidate: candidate.Bundle, PriorState: domain.PublicationUnpublished}
			document, err := service.normal.Read()
			if err != nil {
				t.Fatal(err)
			}
			if err := admitter.CommitPublicationBegin(context.Background(), mutation, exposure, document.Revision, job.ID, operations.PublicationBeginCommit{ResourceID: resource.ID, Intent: activationIntent}); err != nil {
				t.Fatal(err)
			}
		}
		if stage == "journal" || stage == "terminal_failed" || stage == "ownership" || stage == "ready" || stage == "committed" {
			document, err := service.normal.Read()
			if err != nil {
				t.Fatal(err)
			}
			journal := operations.JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "activation-" + job.ID, JobID: job.ID, Kind: operations.JournalAppActivation, Operation: operations.Publish, InstallationID: recoveryResourceInstallation(&resource).InstallationID, Target: "resource/" + resource.ID, Generation: intent.IntentGeneration, Deadline: plan.ExpiresAt, ArtifactDigest: candidate.BundleDigest, ResourceIDs: []string{resource.ID}, ChildIDs: nil, Phase: operations.JournalPrepared}
			if err := admitter.PutJournal(context.Background(), mutation, exposure, document.Revision, journal, true); err != nil {
				t.Fatal(err)
			}
		}
		if stage == "terminal_failed" {
			document, err := service.normal.Read()
			if err != nil {
				t.Fatal(err)
			}
			if err := admitter.RejectPublication(context.Background(), mutation, exposure, document.Revision, job.ID, "activation_restored_prior"); err != nil {
				t.Fatal(err)
			}
		}
		if stage == "ownership" || stage == "ready" || stage == "committed" {
			owned, err := service.ownership.Read(resource.ID)
			if err != nil {
				t.Fatal(err)
			}
			owned.Revision++
			owned.Paths = upsertOwnedPath(owned.Paths, candidate.OwnershipPath)
			owned.Listeners = upsertOwnedListener(owned.Listeners, candidate.OwnershipListener)
			slices.SortFunc(owned.Paths, func(left, right ownership.OwnedPath) int { return compare(left.Path, right.Path) })
			slices.SortFunc(owned.Listeners, func(left, right ownership.OwnedListener) int {
				return compare(left.IdentityDigest, right.IdentityDigest)
			})
			persisted, err := service.OwnershipWrite(context.Background(), exposure, owned.Revision-1, owned)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "ready" || stage == "committed" {
				state, err := service.safety.ReadForRecovery(exposure)
				if err != nil {
					t.Fatal(err)
				}
				next := state
				next.Revision++
				next.Resources = append([]safety.ResourceSafety(nil), state.Resources...)
				before := next.Resources[0].OwnershipDigest
				next.Resources[0].OwnershipDigest = persisted.Checksum
				proof := &safety.OwnershipConvergenceProof{ResourceID: resource.ID, IntentRef: marker.PlanID, Generation: marker.Generation, BeforeDigest: before, AfterDigest: persisted.Checksum}
				if _, err := service.safety.Commit(context.Background(), exposure, safety.RoleOwnershipActivation, state.Revision, next, safety.TransitionProof{Ownership: proof}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if stage == "committed" {
			document, err := service.normal.Read()
			if err != nil {
				t.Fatal(err)
			}
			job, commitErr := admitter.CommitPublicationPublished(context.Background(), mutation, exposure, document.Revision, job.ID, operations.PublicationTerminalCommit{ResourceID: resource.ID, Bundle: candidate.Bundle, Runtime: domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: time.Now().UTC().Format(time.RFC3339), Reason: "published"}}, "activation-"+job.ID, recoveryDigest("temporary-runtime"), nil, func() error { return errors.New("injected safety convergence failure") })
			if commitErr == nil || job.ID == "" {
				t.Fatal("committed publication split was not injected")
			}
		}
	default:
		t.Fatalf("unknown temporary recovery stage %q", stage)
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}
	return temporaryRecoveryFixture{fixture: fixture, resource: resource, candidate: candidate, marker: marker, plan: plan, jobID: job.ID}
}

func runTemporaryRestartRecovery(t *testing.T, value temporaryRecoveryFixture, canceled bool, runtime *temporaryRecoveryRuntimeProbe) {
	t.Helper()
	runtime.entry = value.candidate.Entry
	service := value.fixture.open(t)
	state, err := readPublicationRecoverySafety(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	authority := findSafetyResource(state, value.resource.ID)
	if authority == nil {
		t.Fatal("temporary recovery safety resource missing")
	}
	ctx := context.Background()
	if canceled {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}
	if authority.Reactivating == nil && authority.Closing == nil {
		err = reconcileMarkerlessTemporaryReservations(ctx, service, state)
	} else {
		err = reconcileInterruptedTemporaryPublication(ctx, service, *authority, value.fixture.lockRoot(), uint32(os.Geteuid()), uint32(os.Getegid()), runtime)
	}
	closeErr := service.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
}

func assertTemporaryRecoveryConverged(t *testing.T, value temporaryRecoveryFixture, expectedResult jobs.Result, expectedState domain.PublicationState) {
	t.Helper()
	service := value.fixture.open(t)
	defer func() { _ = service.Close() }()
	state, err := service.safety.Read()
	if err != nil {
		t.Fatal(err)
	}
	authority := findSafetyResource(state, value.resource.ID)
	if authority == nil || authority.Reactivating != nil || authority.Closing != nil {
		t.Fatalf("temporary safety did not converge: %#v", authority)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	resource := findNormalResource(installation, value.resource.ID)
	if resource == nil || resource.PublicationRecord.State != expectedState || resource.PublicationRecord.ActivationIntent != nil {
		t.Fatalf("temporary normal state did not converge: %#v", resource)
	}
	intent, err := service.TimerAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	operationIntent, err := intent.OperationIntent(value.jobID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := jobs.LoadEntries(document.Entries, value.jobID)
	if err != nil {
		t.Fatal(err)
	}
	if operationIntent.Phase != operations.PhaseTerminal && operationIntent.Phase != operations.PhaseRejected || record.Status != jobs.StatusTerminal || record.Result != expectedResult {
		t.Fatalf("temporary operation graph remains active: intent=%#v job=%#v", operationIntent, record)
	}
	for _, key := range persist.EntryKeys(document, "journals") {
		var journal operations.JournalRecord
		if err := json.Unmarshal(document.Entries[key], &journal); err != nil {
			t.Fatal(err)
		}
		if journal.JobID == value.jobID && journal.Phase != operations.JournalTerminal {
			t.Fatalf("temporary journal remains active: %#v", journal)
		}
	}
	if err := service.PendingPublicationRecovery(); err != nil {
		t.Fatalf("temporary recovery still blocks new publication: %v", err)
	}
}

func TestTemporaryPublicationRecoveryStages(t *testing.T) {
	tests := []struct {
		name          string
		stage         string
		cancel        bool
		verify        bool
		result        jobs.Result
		state         domain.PublicationState
		wantContracts int
		wantVerifies  int
	}{
		{name: "admit_then_restart_before_safety", stage: "admitted", result: jobs.ResultFailed, state: domain.PublicationUnpublished},
		{name: "safety_commit_then_cancel", stage: "reserved", cancel: true, result: jobs.ResultFailed, state: domain.PublicationUnpublished},
		{name: "marker_clear_then_restart_before_reject", stage: "marker_cleared", result: jobs.ResultFailed, state: domain.PublicationUnpublished},
		{name: "consume_plan_failed", stage: "consume_failed", result: jobs.ResultFailed, state: domain.PublicationUnpublished},
		{name: "consume_succeeded_normal_intent_failed", stage: "consumed", result: jobs.ResultFailed, state: domain.PublicationUnpublished},
		{name: "normal_terminal_then_restart_before_marker_clear", stage: "terminal_failed", result: jobs.ResultFailed, state: domain.PublicationUnpublished},
		{name: "journal_failed", stage: "intent", result: jobs.ResultInterrupted, state: domain.PublicationUnpublished, wantContracts: 1},
		{name: "journal_committed_before_ownership", stage: "journal", result: jobs.ResultInterrupted, state: domain.PublicationUnpublished, wantContracts: 1},
		{name: "ownership_write_followed_by_failure", stage: "ownership", result: jobs.ResultInterrupted, state: domain.PublicationUnpublished, wantContracts: 1, wantVerifies: 1},
		{name: "complete_authority_and_live_runtime_finishes", stage: "ready", verify: true, result: jobs.ResultSucceeded, state: domain.PublicationPublished, wantVerifies: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTemporaryRecoveryFixture(t, test.stage)
			runtime := &temporaryRecoveryRuntimeProbe{verify: test.verify}
			runTemporaryRestartRecovery(t, fixture, test.cancel, runtime)
			assertTemporaryRecoveryConverged(t, fixture, test.result, test.state)
			if runtime.contractCalls != test.wantContracts || runtime.probeCalls != test.wantContracts || runtime.verifyCalls != test.wantVerifies {
				t.Fatalf("unexpected runtime recovery calls: verify=%d contract=%d closure_probe=%d", runtime.verifyCalls, runtime.contractCalls, runtime.probeCalls)
			}
		})
	}
}

func TestTemporaryPriorRestoreIgnoresCallerCancellation(t *testing.T) {
	fixture := newTemporaryRecoveryFixture(t, "intent")
	service := fixture.fixture.open(t)
	mutationSet, mutation, exposure := fixture.fixture.acquire(t, service, "resource/"+fixture.resource.ID)
	admitter, err := service.TimerAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	execution := PublicationExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: fixture.jobID, Revision: document.Revision, Resource: fixture.resource, Reactivating: fixture.marker}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := execution.restoreTemporaryPrior(ctx); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}
	assertTemporaryRecoveryConverged(t, fixture, jobs.ResultFailed, domain.PublicationUnpublished)
}

func TestTemporaryReservedCleanupRequiresExactBinding(t *testing.T) {
	fixture := newTemporaryRecoveryFixture(t, "admitted")
	service := fixture.fixture.open(t)
	admitter, err := service.TimerAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.safety.Read()
	if err != nil {
		t.Fatal(err)
	}
	state.Resources[0].GenerationSequence += 7
	reservations, err := markerlessTemporaryReservations(document, state)
	if err != nil || len(reservations) != 1 || reservations[0].JobID != fixture.jobID {
		t.Fatalf("unrelated safety generation hid exact markerless reservation: reservations=%#v err=%v", reservations, err)
	}
	wrong := operations.SafetyBinding{ResourceID: fixture.resource.ID, PlanID: fixture.plan.ID, IntentGeneration: fixture.marker.Generation, CandidateDigest: fixture.marker.CandidateDigest, CandidateBundle: recoveryDigest("wrong-candidate"), Deadline: fixture.plan.ExpiresAt}
	if err := rejectReservedTemporaryPublication(context.Background(), service, admitter, fixture.jobID, wrong, "test_wrong_binding"); err == nil {
		t.Fatal("wrong candidate binding rejected a temporary reservation")
	}
	intent, err := admitter.OperationIntent(fixture.jobID)
	if err != nil || intent.Phase != operations.PhaseReserved {
		t.Fatalf("reservation changed after mismatched cleanup: intent=%#v err=%v", intent, err)
	}
	if err := rejectReservedTemporaryPublication(context.Background(), service, admitter, fixture.jobID, intent.SafetyBinding, "publication_revalidation_failed"); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	assertTemporaryRecoveryConverged(t, fixture, jobs.ResultFailed, domain.PublicationUnpublished)
}

func TestTemporaryContractionFailureFenceBindsClosingAuthority(t *testing.T) {
	fixture := newTemporaryRecoveryFixture(t, "committed")
	service := fixture.fixture.open(t)
	mutationSet, mutation, exposure := fixture.fixture.acquire(t, service, "resource/"+fixture.resource.ID)
	generation, err := beginTemporaryPublicationContraction(context.Background(), service, exposure, fixture.resource.ID, fixture.marker, temporaryCommittedClosingReason)
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		t.Fatal(err)
	}
	authority := findSafetyResource(state, fixture.resource.ID)
	if authority == nil {
		t.Fatal("temporary closing safety authority missing")
	}
	inventoryDigest := safety.OwnershipInventoryDigest(map[string]string{fixture.resource.ID: authority.OwnershipDigest})
	graphDigest := recoveryDigest("temporary-graph")
	emergencyBefore, err := service.emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	oneSidedFence := safety.EmergencyStopFence{Kind: safety.StopFenceContraction, OriginOperation: string(operations.Publish), ScopeKind: "app", ResourceID: fixture.resource.ID, Generation: emergencyBefore.StopFenceSequence + 1, ClosingGeneration: generation, OperationRef: fixture.marker.PlanID, OwnershipDigest: authority.OwnershipDigest, OwnedGraphDigest: graphDigest, InventoryDigest: inventoryDigest, ObservedUnix: time.Now().UTC().Add(-2 * time.Second).Unix(), AccessMayRemain: true}
	emergencyNext := emergencyBefore
	emergencyNext.Sequence++
	emergencyNext.StopFenceSequence++
	emergencyNext.ReservedStopFenceKind = safety.StopFenceContraction
	emergencyNext.StopFence = &oneSidedFence
	if err := service.emergency.Commit(exposure, safety.RoleContraction, emergencyBefore.Sequence, emergencyNext); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}
	service = fixture.fixture.open(t)
	state, err = readPublicationRecoverySafety(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	closingAuthority := findSafetyResource(state, fixture.resource.ID)
	if closingAuthority == nil || closingAuthority.Closing == nil {
		t.Fatal("temporary closing authority missing after emergency-only fence restart")
	}
	runtime := &temporaryRecoveryRuntimeProbe{}
	if err := reconcileInterruptedTemporaryPublication(context.Background(), service, *closingAuthority, fixture.fixture.lockRoot(), uint32(os.Geteuid()), uint32(os.Getegid()), runtime); err != nil {
		t.Fatal(err)
	}
	state, err = service.safety.Read()
	if err != nil {
		t.Fatal(err)
	}
	emergency, err := service.emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.contractCalls != 0 || state.StopFence == nil || emergency.StopFence == nil || state.StopFence.Kind != safety.StopFenceContraction || !safety.FenceMatchesEmergency(state.StopFence, *emergency.StopFence) || state.StopFence.Contraction == nil || len(state.StopFence.Contraction.Authorities) != 1 || state.StopFence.Contraction.Authorities[0] != (safety.MarkerGeneration{Kind: "closing", Generation: generation}) {
		t.Fatalf("temporary emergency-only contraction fence did not converge: runtime=%d normal=%#v emergency=%#v", runtime.contractCalls, state.StopFence, emergency.StopFence)
	}
	mutationSet, mutation, exposure = fixture.fixture.acquire(t, service, "resource/"+fixture.resource.ID)
	observed := safety.StopObservation{MasterStopped: true, WorkersStopped: true, ListenersStopped: true, ObservedAt: time.Now().UTC()}
	oneSidedObservation := *emergency.StopFence
	oneSidedObservation.MasterStopped = true
	oneSidedObservation.WorkersStopped = true
	oneSidedObservation.ListenersStopped = true
	oneSidedObservation.ObservedUnix = observed.ObservedAt.Unix()
	oneSidedObservation.AccessMayRemain = false
	emergencyNext = emergency
	emergencyNext.Sequence++
	emergencyNext.StopFence = &oneSidedObservation
	if err := service.emergency.Commit(exposure, safety.RoleContraction, emergency.Sequence, emergencyNext); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}
	service = fixture.fixture.open(t)
	state, err = readPublicationRecoverySafety(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	closingAuthority = findSafetyResource(state, fixture.resource.ID)
	if closingAuthority == nil || closingAuthority.Closing == nil {
		t.Fatal("temporary closing authority missing after one-sided observation restart")
	}
	runtime = &temporaryRecoveryRuntimeProbe{}
	if err := reconcileInterruptedTemporaryPublication(context.Background(), service, *closingAuthority, fixture.fixture.lockRoot(), uint32(os.Geteuid()), uint32(os.Getegid()), runtime); err != nil {
		t.Fatal(err)
	}
	state, err = service.safety.Read()
	if err != nil {
		t.Fatal(err)
	}
	emergency, err = service.emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.contractCalls != 0 || state.StopFence == nil || emergency.StopFence == nil || state.StopFence.AccessMayRemain || emergency.StopFence.AccessMayRemain || !safety.FenceMatchesEmergency(state.StopFence, *emergency.StopFence) || !state.StopFence.CreatedAt.Before(state.StopFence.Observation.ObservedAt) {
		t.Fatalf("temporary restart did not project stop observation: runtime=%d normal=%#v emergency=%#v", runtime.contractCalls, state.StopFence, emergency.StopFence)
	}
	exposureOnly, err := service.manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		t.Fatal(err)
	}
	cleared := emergency
	cleared.Sequence++
	cleared.StopFence = nil
	cleared.ClearProof = &safety.EmergencyClearProof{StopFenceGeneration: emergency.StopFence.Generation, StopFenceDigest: safety.EmergencyFenceDigest(*emergency.StopFence), InventoryDigest: emergency.StopFence.InventoryDigest, OwnedGraphDigest: emergency.StopFence.OwnedGraphDigest, RuntimeClosureDigest: recoveryDigest("temporary-closed"), NginxTestPassed: true, RuntimeClosed: true}
	if err := service.emergency.Commit(exposureOnly, safety.RoleJournalConvergence, emergency.Sequence, cleared); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(exposureOnly.Release(), service.Close()); err != nil {
		t.Fatal(err)
	}
	service = fixture.fixture.open(t)
	state, err = readPublicationRecoverySafety(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	closingAuthority = findSafetyResource(state, fixture.resource.ID)
	if closingAuthority == nil || closingAuthority.Closing == nil {
		t.Fatal("temporary closing authority missing after emergency-only clear restart")
	}
	if err := reconcileInterruptedTemporaryPublication(context.Background(), service, *closingAuthority, fixture.fixture.lockRoot(), uint32(os.Geteuid()), uint32(os.Getegid()), &temporaryRecoveryRuntimeProbe{}); err != nil {
		t.Fatalf("emergency-cleared normal fence was reported as stale: %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTemporaryCommittedPublicationDefaultsToContractionWithoutRuntimeAuthority(t *testing.T) {
	fixture := newTemporaryRecoveryFixture(t, "committed")
	runtime := &temporaryRecoveryRuntimeProbe{}
	runTemporaryRestartRecovery(t, fixture, false, runtime)
	assertTemporaryRecoveryConverged(t, fixture, jobs.ResultSucceeded, domain.PublicationUnpublished)
	if runtime.verifyCalls != 1 || runtime.contractCalls != 1 || runtime.probeCalls != 1 {
		t.Fatalf("committed recovery did not verify then contract and prove closure: verify=%d contract=%d closure_probe=%d", runtime.verifyCalls, runtime.contractCalls, runtime.probeCalls)
	}
}

func TestTemporaryInterruptedContractionResumesAfterNormalTerminal(t *testing.T) {
	fixture := newTemporaryRecoveryFixture(t, "intent")
	service := fixture.fixture.open(t)
	mutationSet, mutation, exposure := fixture.fixture.acquire(t, service, "resource/"+fixture.resource.ID)
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := loadTemporaryPublicationRecovery(document, fixture.resource.ID, fixture.marker)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := beginTemporaryPublicationContraction(context.Background(), service, exposure, fixture.resource.ID, fixture.marker, temporaryInterruptedClosingReason)
	if err != nil {
		t.Fatal(err)
	}
	preContractionInventory, err := buildTemporaryClosureInventory(service, exposure, fixture.resource.ID, fixture.marker.PlanID, fixture.marker.Generation, nginx.Manifest{Entries: []nginx.Entry{fixture.candidate.Entry}})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.TerminalizeInterruptedTemporaryPublication(context.Background(), mutation, exposure, document.Revision, fixture.jobID, recovery.Intent.SafetyBinding, generation, []string{"/etc/lanpanel/nginx/temporary/test.conf"}, recoveryDigest("temporary-contraction")); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}
	service = fixture.fixture.open(t)
	state, err := readPublicationRecoverySafety(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	authority := findSafetyResource(state, fixture.resource.ID)
	if authority == nil || authority.Closing == nil || authority.Closing.Reason != temporaryInterruptedClosingReason {
		t.Fatalf("interrupted closing restart authority missing: %#v", authority)
	}
	runtime := &temporaryRecoveryRuntimeProbe{}
	if err := reconcileInterruptedTemporaryPublication(context.Background(), service, *authority, fixture.fixture.lockRoot(), uint32(os.Geteuid()), uint32(os.Getegid()), runtime); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	assertTemporaryRecoveryConverged(t, fixture, jobs.ResultInterrupted, domain.PublicationUnpublished)
	if runtime.contractCalls != 1 || runtime.probeCalls != 1 || runtime.probeInventory.Digest != preContractionInventory.Digest {
		t.Fatalf("interrupted closing did not preserve and prove the pre-contraction inventory: contract=%d closure_probe=%d before=%s probed=%s", runtime.contractCalls, runtime.probeCalls, preContractionInventory.Digest, runtime.probeInventory.Digest)
	}
}

func TestTemporaryCommittedContractionResumesAfterNormalCommit(t *testing.T) {
	fixture := newTemporaryRecoveryFixture(t, "committed")
	service := fixture.fixture.open(t)
	mutationSet, mutation, exposure := fixture.fixture.acquire(t, service, "resource/"+fixture.resource.ID)
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := loadTemporaryPublicationRecovery(document, fixture.resource.ID, fixture.marker)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := beginTemporaryPublicationContraction(context.Background(), service, exposure, fixture.resource.ID, fixture.marker, temporaryCommittedClosingReason)
	if err != nil {
		t.Fatal(err)
	}
	preContractionInventory, err := buildTemporaryClosureInventory(service, exposure, fixture.resource.ID, fixture.marker.PlanID, fixture.marker.Generation, nginx.Manifest{Entries: []nginx.Entry{fixture.candidate.Entry}})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	if err := admitter.ConvergeCommittedPublicationContraction(context.Background(), mutation, exposure, document.Revision, fixture.resource.ID, generation, recoveryDigest("temporary-contraction")); err != nil {
		t.Fatal(err)
	}
	if recovery.Intent.JobID != fixture.jobID {
		t.Fatal("committed recovery intent changed")
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close()); err != nil {
		t.Fatal(err)
	}

	service = fixture.fixture.open(t)
	state, err := readPublicationRecoverySafety(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	authority := findSafetyResource(state, fixture.resource.ID)
	if authority == nil || authority.Closing == nil || authority.Closing.Reason != temporaryCommittedClosingReason {
		t.Fatalf("committed closing restart authority missing: %#v", authority)
	}
	runtime := &temporaryRecoveryRuntimeProbe{}
	if err := reconcileInterruptedTemporaryPublication(context.Background(), service, *authority, fixture.fixture.lockRoot(), uint32(os.Geteuid()), uint32(os.Getegid()), runtime); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	assertTemporaryRecoveryConverged(t, fixture, jobs.ResultSucceeded, domain.PublicationUnpublished)
	if runtime.contractCalls != 1 || runtime.probeCalls != 1 || runtime.probeInventory.Digest != preContractionInventory.Digest {
		t.Fatalf("committed closing did not preserve and prove the pre-contraction inventory: contract=%d closure_probe=%d before=%s probed=%s", runtime.contractCalls, runtime.probeCalls, preContractionInventory.Digest, runtime.probeInventory.Digest)
	}
}
