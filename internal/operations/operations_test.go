package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeSafety struct {
	state     safety.State
	err       error
	authority locks.Authority
}

func (store *fakeSafety) LockAuthority() locks.Authority { return store.authority }

type trustedBindings struct{ binding plans.Binding }

func (reader trustedBindings) CurrentBinding(Type, string, time.Time) (plans.Binding, error) {
	return reader.binding, nil
}

type testConfirmation struct{}

func (testConfirmation) VerifyConfirmation(plan plans.Plan, actor string, proof string, _ time.Time) (string, error) {
	if proof != plan.NonceDigest || actor != plan.ActorIdentity {
		return "", errors.New("confirmation rejected")
	}
	return testDigest("confirmation"), nil
}

type changingSafety struct {
	states    []safety.State
	index     int
	authority locks.Authority
}

func (store *changingSafety) LockAuthority() locks.Authority { return store.authority }

func (store *changingSafety) Read() (safety.State, error) {
	state := store.states[store.index]
	if store.index < len(store.states)-1 {
		store.index++
	}
	return state, nil
}

func (store *fakeSafety) Read() (safety.State, error) { return store.state, store.err }

func TestSecretFingerprintBindingIsDurableAndImmutable(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	normal, manager, admission, mutationSet := newOperationStores(t)
	defer normal.Close()
	defer mutationSet.Close()
	defer manager.Close()
	planStore, _ := plans.NewStore(normal, plans.Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64))})
	spec := plans.Spec{Operation: string(AdminTokenRotate), Target: plans.Target{Kind: plans.TargetInstallation}, ActorIdentity: "ui/session-one/generation/1", Config: plans.DigestBinding{}, Applied: plans.DigestBinding{}, Evidence: []plans.Evidence{}, ExposureSummary: "admin_token_rotation", Prerequisites: "authenticated_confirmation"}
	plan, err := planStore.Create(context.Background(), admission, 1, spec)
	if err != nil {
		t.Fatal(err)
	}
	binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
	table, err := NewBranchTable([]ResultBranch{{"complete", jobs.ResultSucceeded, jobs.PostconditionVerified}, {"no_effect", jobs.ResultFailed, jobs.PostconditionVerified}, {"known_residual", jobs.ResultPartial, jobs.PostconditionKnown}, {"executor_died", jobs.ResultInterrupted, jobs.PostconditionKnown}, {"source_unknown", jobs.ResultUnknown, jobs.PostconditionUnobserved}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Registration{{Operation: AdminTokenRotate, Owner: "admin-token", Results: table}})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := NewAdmitter(normal, &fakeSafety{state: openSafetyState(), authority: manager.Authority()}, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{2}, 64)), Bindings: trustedBindings{binding}, Confirmation: testConfirmation{}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	record, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: AdminTokenRotate, Target: "installation", ActorIdentity: plan.ActorIdentity, PlanID: plan.ID, Source: AdmissionPlan, ExpectedRevision: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(context.Background(), "installation", manager)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.ConsumePlan(context.Background(), mutation, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 3, IntentGeneration: 4, ConfirmationProof: plan.NonceDigest}); err != nil {
		t.Fatal(err)
	}
	fingerprint := testDigest("secret")
	if err := admitter.BindSecretFingerprint(context.Background(), mutation, exposure, 4, record.ID, fingerprint); err != nil {
		t.Fatal(err)
	}
	document, err := normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	pending, found, err := FindPendingSecretIntent(document, AdminTokenRotate, "installation")
	if err != nil || !found || pending.Fingerprint != fingerprint || pending.Phase != PhaseLocalIntent {
		t.Fatalf("pending=%#v found=%t err=%v", pending, found, err)
	}
	if err := admitter.BindSecretFingerprint(context.Background(), mutation, exposure, 5, record.ID, testDigest("other")); err == nil {
		t.Fatal("secret fingerprint rebound")
	}
	if err := admitter.MarkSecretCommitted(context.Background(), mutation, exposure, 5, record.ID, fingerprint); err != nil {
		t.Fatal(err)
	}
	document, err = normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	pending, found, err = FindPendingSecretIntent(document, AdminTokenRotate, "installation")
	if err != nil || !found || !pending.Committed {
		t.Fatalf("committed pending=%#v found=%t err=%v", pending, found, err)
	}
	if err := admitter.MarkSecretCommitted(context.Background(), mutation, exposure, 6, record.ID, fingerprint); err == nil {
		t.Fatal("secret commit marked twice")
	}
	if err := ReleaseExposure(mutation, exposure); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatedResourceUpdateBindsPriorAndCandidateDigests(t *testing.T) {
	request := AdmitRequest{Operation: ResourceUpdate, Target: "resource/res_00000000000000000000000000000001", Source: AdmissionUI, SafetyBinding: SafetyBinding{ResourceID: "res_00000000000000000000000000000001", CandidateDigest: testDigest("candidate"), CandidateBundle: testDigest("prior")}}
	if err := validateSafetyTargetBinding(request); err != nil {
		t.Fatal(err)
	}
	request.Operation = ProcessStart
	if err := validateSafetyTargetBinding(request); err == nil {
		t.Fatal("process start accepted resource-update digest authority")
	}
	request.Operation = ResourceUpdate
	request.SafetyBinding.CandidateBundle = ""
	if err := validateSafetyTargetBinding(request); err == nil {
		t.Fatal("resource update accepted one-sided digest authority")
	}
	request.SafetyBinding.CandidateDigest = ""
	if err := validateSafetyTargetBinding(request); err == nil {
		t.Fatal("resource update accepted absent digest authority")
	}
}

func TestOperationAdmissionContract(t *testing.T) {
	t.Run("reservation_consumption_and_remote_wait_release_locks", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		normal, manager, admission, mutation := newOperationStores(t)
		defer normal.Close()
		defer mutation.Close()
		defer manager.Close()
		planStore, _ := plans.NewStore(normal, plans.Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64))})
		spec := operationPlanSpec(now)
		plan, err := planStore.Create(context.Background(), admission, 1, spec)
		if err != nil {
			t.Fatal(err)
		}
		safetyStore := &fakeSafety{state: openSafetyState(), authority: manager.Authority()}
		binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
		admitter, _ := NewAdmitter(normal, safetyStore, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{2}, 96)), Bindings: trustedBindings{binding}, Confirmation: testConfirmation{}, Registry: testRegistry(t)})
		deadline := now.Add(time.Hour)
		record, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/res_00000000000000000000000000000001", ActorIdentity: "session-one", PlanID: plan.ID, Source: AdmissionPlan, SafetyBinding: SafetyBinding{ResourceID: "res_00000000000000000000000000000001", Deadline: deadline}, ExpectedRevision: 2})
		if err != nil {
			t.Fatal(err)
		}
		if record.Status != jobs.StatusReserved {
			t.Fatalf("reserved job=%#v", record)
		}
		if _, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/res_00000000000000000000000000000001", ActorIdentity: "session-one", PlanID: plan.ID, Source: AdmissionPlan, SafetyBinding: SafetyBinding{ResourceID: "res_00000000000000000000000000000001", Deadline: deadline}, ExpectedRevision: 3}); err == nil {
			t.Fatal("one Plan reserved multiple jobs")
		}
		if err := admission.Release(); err != nil {
			t.Fatal(err)
		}
		reverse, err := manager.Acquire(context.Background(), locks.Exposure)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := mutation.AcquireExposure(context.Background(), "resource/res_00000000000000000000000000000001", manager); err == nil {
			t.Fatal("exposure-to-mutation reverse acquisition succeeded")
		}
		_ = reverse.Release()
		mutationLease, exposure, err := mutation.AcquireExposure(context.Background(), "resource/res_00000000000000000000000000000001", manager)
		if err != nil {
			t.Fatal(err)
		}
		foreignMutation := &MutationLease{fd: mutationLease.fd, target: mutationLease.target, authority: locks.Authority{}}
		if _, err := admitter.ConsumePlan(context.Background(), foreignMutation, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 3, IntentGeneration: 4, ConfirmationProof: plan.NonceDigest}); err == nil {
			t.Fatal("operation accepted a mutation lease from another authority")
		}
		intent, err := admitter.ConsumePlan(context.Background(), mutationLease, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 3, IntentGeneration: 4, ConfirmationProof: plan.NonceDigest})
		if err != nil {
			t.Fatal(err)
		}
		if intent.Phase != PhaseLocalIntent {
			t.Fatalf("intent=%#v", intent)
		}
		if _, err := admitter.ConsumePlan(context.Background(), mutationLease, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 4, IntentGeneration: 4, ConfirmationProof: plan.NonceDigest}); err == nil {
			t.Fatal("Plan/reservation consumed twice")
		}
		rawInstallation, err := persist.EncodeEntry(testOperationInstallation())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := normal.Update(context.Background(), exposure, 4, func(transaction *persist.Transaction) error {
			return transaction.Create("installations/current", rawInstallation)
		}); err != nil {
			t.Fatal(err)
		}
		child := ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "child-one", JobID: record.ID, InstallationID: testOperationInstallation().InstallationID, Operation: Publish, Target: "resource/res_00000000000000000000000000000001", IntentGeneration: 4, Profile: "provider", InputDigest: testDigest("input"), ArtifactDigest: testDigest("artifact"), Deadline: deadline, State: ChildSubmitted, SubmittedAt: now}
		if err := ReleaseExposure(mutationLease, exposure); err != nil {
			t.Fatal(err)
		}
		childAdmission, err := manager.Acquire(context.Background(), locks.MutationAdmission)
		if err != nil {
			t.Fatal(err)
		}
		if err := admitter.ReserveChild(context.Background(), childAdmission, 5, child); err != nil {
			t.Fatal(err)
		}
		if err := childAdmission.Release(); err != nil {
			t.Fatal(err)
		}
		mutationLease, exposure, err = mutation.AcquireExposure(context.Background(), "resource/res_00000000000000000000000000000001", manager)
		if err != nil {
			t.Fatal(err)
		}
		child.State = ChildRunning
		if err := admitter.TransitionChild(context.Background(), mutationLease, exposure, 6, child); err != nil {
			t.Fatal(err)
		}
		journalMarkerDigest, err := safetyBindingDigest(intent.SafetyBinding)
		if err != nil {
			t.Fatal(err)
		}
		journal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "journal-one", JobID: record.ID, Kind: JournalAppContraction, Operation: Publish, InstallationID: testOperationInstallation().InstallationID, Target: "resource/res_00000000000000000000000000000001", Generation: 4, Deadline: deadline, ArtifactDigest: testDigest("artifact"), SafetyMarkerDigest: journalMarkerDigest, ResourceIDs: []string{"res_00000000000000000000000000000001"}, ChildIDs: []string{"child-one"}, Phase: JournalPrepared}
		if err := admitter.PutJournal(context.Background(), mutationLease, exposure, 7, journal, true); err != nil {
			t.Fatal(err)
		}
		journal.Phase = JournalActive
		if err := admitter.PutJournal(context.Background(), mutationLease, exposure, 8, journal, false); err != nil {
			t.Fatal(err)
		}
		if _, err := admitter.EnterRemoteWait(context.Background(), mutationLease, exposure, 9, record.ID); err != nil {
			t.Fatal(err)
		}
		contraction, err := manager.Acquire(context.Background(), locks.Exposure)
		if err != nil {
			t.Fatalf("remote wait retained exposure lock: %v", err)
		}
		_ = contraction.Release()
		reentered, reentryMutation, reentryExposure, err := admitter.Reenter(context.Background(), mutation, manager, 10, record.ID)
		if err != nil || reentered.Phase != PhaseReentered {
			t.Fatalf("Reenter()=%#v,%v", reentered, err)
		}
		stamp := now.Add(time.Second)
		child.State = ChildTerminal
		child.TerminalAt = &stamp
		child.Outcome = ChildSucceeded
		child.ResultDigest = testDigest("child-result")
		if err := admitter.TransitionChild(context.Background(), reentryMutation, reentryExposure, 11, child); err != nil {
			t.Fatal(err)
		}
		journal.Phase = JournalTerminal
		if err := admitter.PutJournal(context.Background(), reentryMutation, reentryExposure, 12, journal, false); err != nil {
			t.Fatal(err)
		}
		if _, err := admitter.DecideExactReconciliation(reentryExposure, journal.ID, ExactReconciliationObservation{Deadline: journal.Deadline, ArtifactDigest: journal.ArtifactDigest, SafetyMarkerDigest: journal.SafetyMarkerDigest}); err == nil {
			t.Fatal("exact reconciliation ran without a new durable startup/timer job")
		}
		if err := ReleaseExposure(reentryMutation, reentryExposure); err != nil {
			t.Fatal(err)
		}
		reconciliationAdmission, err := manager.Acquire(context.Background(), locks.MutationAdmission)
		if err != nil {
			t.Fatal(err)
		}
		admitter.random = bytes.NewReader(bytes.Repeat([]byte{7}, 32))
		reconciliationJob, err := admitter.Admit(context.Background(), reconciliationAdmission, AdmitRequest{Operation: AutomaticReconciliation, Target: "journal/" + journal.ID, ActorIdentity: "startup-recovery", Source: AdmissionStartup, ExpectedRevision: 13})
		if err != nil {
			t.Fatal(err)
		}
		if err := reconciliationAdmission.Release(); err != nil {
			t.Fatal(err)
		}
		reconciliationMutation, reconciliationExposure, err := mutation.AcquireExposure(context.Background(), "journal/"+journal.ID, manager)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admitter.BeginPlanless(context.Background(), reconciliationMutation, reconciliationExposure, ConsumeRequest{JobID: reconciliationJob.ID, ExpectedRevision: 14, IntentGeneration: 15}); err != nil {
			t.Fatal(err)
		}
		safetyStore.state.Resources[0].GenerationSequence = 3
		safetyStore.state.Resources[0].StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 3, Reason: "exact_reconciliation"}
		observation := ExactReconciliationObservation{ReconciliationJobID: reconciliationJob.ID, Deadline: journal.Deadline, ArtifactDigest: journal.ArtifactDigest, SafetyMarkerDigest: journal.SafetyMarkerDigest, ObservedAt: now, Closures: []ExactResourceClosure{{ResourceID: "res_00000000000000000000000000000001", OwnershipDigest: testDigest("owner"), ContractionGeneration: 3, RuntimeClosureDigest: testDigest("runtime-closure"), DiskClosureDigest: testDigest("disk-closure"), ListenerClosureDigest: testDigest("listener-closure")}}}
		decision, err := admitter.DecideExactReconciliation(reconciliationExposure, journal.ID, observation)
		if err != nil || decision.Action != ReconcileContractApp || decision.Target != journal.Target {
			t.Fatalf("DecideExactReconciliation() = %#v, %v", decision, err)
		}
		if _, err := admitter.DecideExactReconciliation(nil, journal.ID, observation); err == nil {
			t.Fatal("exact reconciliation read without exposure authority")
		}
		staleObservation := observation
		staleObservation.ObservedAt = now.Add(-2 * time.Minute)
		if _, err := admitter.DecideExactReconciliation(reconciliationExposure, journal.ID, staleObservation); err == nil {
			t.Fatal("exact reconciliation accepted stale closure evidence")
		}
		mismatchedObservation := observation
		mismatchedObservation.SafetyMarkerDigest = testDigest("other-marker")
		if _, err := admitter.DecideExactReconciliation(reconciliationExposure, journal.ID, mismatchedObservation); err == nil {
			t.Fatal("exact reconciliation accepted mismatched observed marker authority")
		}
		now = now.Add(time.Second)
		terminalObservation := observation
		terminalObservation.ObservedAt = now
		reconciliationResult, err := admitter.CompleteExactReconciliation(context.Background(), reconciliationMutation, reconciliationExposure, 15, decision, terminalObservation, reconciliationJob.ID)
		if err != nil || reconciliationResult.Result != jobs.ResultSucceeded {
			t.Fatalf("CompleteExactReconciliation()=%#v,%v", reconciliationResult, err)
		}
		if err := ReleaseExposure(reconciliationMutation, reconciliationExposure); err != nil {
			t.Fatal(err)
		}
		closedDocument, err := normal.Read()
		if err != nil {
			t.Fatal(err)
		}
		closedInstallation, err := domain.DecodeInstallation(closedDocument.Entries["installations/current"])
		if err != nil {
			t.Fatal(err)
		}
		closedRecord := closedInstallation.Resources[0].PublicationRecord
		if closedRecord.State != domain.PublicationUnpublished || closedRecord.UnpublishedGeneration != 3 || closedRecord.LastJobID != reconciliationJob.ID {
			t.Fatalf("exact reconciliation did not atomically persist fresh unpublished authority: %#v", closedRecord)
		}
		if closedInstallation.Resources[0].ManagedProcess.Requested != domain.ProcessRequestedStopped {
			t.Fatal("exact reconciliation rewrote managed-process intent")
		}
		finalMutation, finalExposure, err := mutation.AcquireExposure(context.Background(), "resource/res_00000000000000000000000000000001", manager)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admitter.Complete(context.Background(), finalMutation, finalExposure, 16, record.ID, "complete", nil, []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: "res_00000000000000000000000000000001"}}, ""); err == nil {
			t.Fatal("superseded publish completed after exact reconciliation contraction")
		}
		jobStore, err := jobs.NewStore(normal, jobs.Options{})
		if err != nil {
			t.Fatal(err)
		}
		interrupted, err := jobStore.Read(record.ID)
		if err != nil || interrupted.Result != jobs.ResultInterrupted {
			t.Fatalf("superseded original job=%#v,%v", interrupted, err)
		}
		if _, _, err := normal.Update(context.Background(), finalExposure, 16, func(transaction *persist.Transaction) error {
			interrupted.Postconditions[0].Identity = "other"
			return jobs.Replace(transaction, interrupted)
		}); err == nil {
			t.Fatal("terminal interrupted job was rewritten through raw transaction")
		}
		if err := ReleaseExposure(finalMutation, finalExposure); err != nil {
			t.Fatal(err)
		}
		consumed, err := planStore.Read(plan.ID)
		if err != nil || consumed.ConsumedByJob != record.ID {
			t.Fatalf("consumed Plan=%#v,%v", consumed, err)
		}
	})

	t.Run("reservation_after_safety_race_is_terminalized_without_mutation", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		normal, manager, admission, mutation := newOperationStores(t)
		defer manager.Close()
		defer admission.Release()
		defer mutation.Close()
		defer normal.Close()
		planStore, _ := plans.NewStore(normal, plans.Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{3}, 64))})
		plan, err := planStore.Create(context.Background(), admission, 1, operationPlanSpec(now))
		if err != nil {
			t.Fatal(err)
		}
		closed := safety.EmptyState()
		closed.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseClosing, Generation: 1}
		binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
		admitter, _ := NewAdmitter(normal, &changingSafety{states: []safety.State{openSafetyState(), closed}, authority: manager.Authority()}, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{4}, 32)), Bindings: trustedBindings{binding}, Confirmation: testConfirmation{}, Registry: testRegistry(t)})
		record, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/res_00000000000000000000000000000001", ActorIdentity: "session-one", PlanID: plan.ID, Source: AdmissionPlan, SafetyBinding: SafetyBinding{ResourceID: "res_00000000000000000000000000000001"}, ExpectedRevision: 2})
		if err == nil {
			t.Fatal("safety race admitted operation")
		}
		jobStore, _ := jobs.NewStore(normal, jobs.Options{})
		terminal, readErr := jobStore.Read(record.ID)
		if readErr != nil || terminal.Status != jobs.StatusTerminal || terminal.Result != jobs.ResultFailed {
			t.Fatalf("raced job=%#v,%v", terminal, readErr)
		}
	})

	t.Run("expired_confirmation_terminalizes_reserved_job", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		clock := now
		normal, manager, admission, mutation := newOperationStores(t)
		defer normal.Close()
		defer mutation.Close()
		defer manager.Close()
		planStore, _ := plans.NewStore(normal, plans.Options{Now: func() time.Time { return clock }, Random: bytes.NewReader(bytes.Repeat([]byte{5}, 64))})
		plan, err := planStore.Create(context.Background(), admission, 1, operationPlanSpec(now))
		if err != nil {
			t.Fatal(err)
		}
		binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
		admitter, _ := NewAdmitter(normal, &fakeSafety{state: openSafetyState(), authority: manager.Authority()}, Options{Now: func() time.Time { return clock }, Random: bytes.NewReader(bytes.Repeat([]byte{6}, 32)), Bindings: trustedBindings{binding}, Confirmation: testConfirmation{}, Registry: testRegistry(t)})
		record, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/res_00000000000000000000000000000001", ActorIdentity: "session-one", PlanID: plan.ID, Source: AdmissionPlan, SafetyBinding: SafetyBinding{ResourceID: "res_00000000000000000000000000000001"}, ExpectedRevision: 2})
		if err != nil {
			t.Fatal(err)
		}
		if err := admission.Release(); err != nil {
			t.Fatal(err)
		}
		clock = now.Add(11 * time.Minute)
		mutationLease, exposure, err := mutation.AcquireExposure(context.Background(), "resource/res_00000000000000000000000000000001", manager)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admitter.ConsumePlan(context.Background(), mutationLease, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 3, IntentGeneration: 4, ConfirmationProof: plan.NonceDigest}); err == nil {
			t.Fatal("expired Plan consumed")
		}
		_ = ReleaseExposure(mutationLease, exposure)
		jobStore, _ := jobs.NewStore(normal, jobs.Options{})
		terminal, err := jobStore.Read(record.ID)
		if err != nil || terminal.Status != jobs.StatusTerminal || terminal.Result != jobs.ResultFailed {
			t.Fatalf("expired job=%#v,%v", terminal, err)
		}
		rejected, err := planStore.Read(plan.ID)
		if err != nil || rejected.RejectedByJob != record.ID {
			t.Fatalf("rejected Plan=%#v,%v", rejected, err)
		}
	})

	t.Run("marker_matrix_allows_only_exact_contraction_exceptions", func(t *testing.T) {
		state := safety.EmptyState()
		state.MaintenancePending = &safety.TransitionMarker{Generation: 1, JournalRef: "maintenance", CurrentEnvelope: testDigest("current"), TargetEnvelope: testDigest("target"), Deadline: time.Now().Add(time.Hour)}
		if err := authorize(Publish, state, SafetyBinding{}, false, time.Now()); err == nil {
			t.Fatal("ordinary publish crossed maintenance")
		}
		state = safety.EmptyState()
		state.StopFence = &safety.StopFence{Kind: safety.StopFenceContraction, FenceGeneration: 7}
		if err := authorize(Publish, state, SafetyBinding{}, false, time.Now()); err == nil {
			t.Fatal("normal admission crossed a stop fence")
		}
		if !isContraction(AutomaticReconciliation) || requiresContractionPreflight(AutomaticReconciliation) {
			t.Fatal("automatic reconciliation lost contraction-safe authorization or gained unrelated preflight")
		}
		if err := validateAdmissionSource(StartupContraction, AdmissionPlan, "plan"); err == nil {
			t.Fatal("startup contraction was exposed through Plan admission")
		}
		if err := validateAdmissionSource(Upgrade, AdmissionPlan, "plan"); err == nil {
			t.Fatal("generation upgrade was exposed through ordinary management Plan admission")
		}
		if err := validateSafetyTargetBinding(AdmitRequest{Operation: Publish, Target: "resource/app-a", PlanID: "plan", Source: AdmissionPlan, SafetyBinding: SafetyBinding{ResourceID: "app-b"}}); err == nil {
			t.Fatal("resource target was admitted under another resource's safety authority")
		}
		state = safety.EmptyState()
		state.DependencyTransitionPending = &safety.TransitionMarker{Generation: 3}
		deadline := time.Now().UTC().Add(-time.Minute)
		state.Resources = []safety.ResourceSafety{{ResourceID: "res_00000000000000000000000000000001", GenerationSequence: 4, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner"), CertificateExpiry: &safety.DeadlineMarker{Generation: 4, Deadline: deadline, Binding: "certificate"}}}
		if err := authorize(CertificateExpiry, state, SafetyBinding{DependencyGeneration: 3, ResourceID: "res_00000000000000000000000000000001", ExpiryKind: "certificate_expiry", ExpiryGeneration: 4, Deadline: deadline}, false, time.Now()); err != nil {
			t.Fatalf("deadline contraction exception rejected: %v", err)
		}
		futureDeadline := time.Now().UTC().Add(time.Hour)
		state.Resources[0].CertificateExpiry = &safety.DeadlineMarker{Generation: 5, Deadline: futureDeadline, Binding: "future"}
		state.Resources[0].GenerationSequence = 5
		if err := authorize(CertificateExpiry, state, SafetyBinding{DependencyGeneration: 3, ResourceID: "res_00000000000000000000000000000001", ExpiryKind: "certificate_expiry", ExpiryGeneration: 5, Deadline: futureDeadline}, false, time.Now()); err == nil {
			t.Fatal("timer expiry contracted before its bound deadline")
		}
		state.Resources[0].CertificateExpiry = &safety.DeadlineMarker{Generation: 4, Deadline: deadline, Binding: "certificate"}
		state.Resources[0].GenerationSequence = 4
		if err := authorize(Publish, state, SafetyBinding{}, false, time.Now()); err == nil {
			t.Fatal("publish crossed dependency transition")
		}
		independent, _, independentManager := unavailableProof(t)
		independentSafety := independent.safety.(*fakeSafety)
		exposure, err := independentManager.Acquire(context.Background(), locks.Exposure)
		if err != nil {
			t.Fatal(err)
		}
		defer exposure.Release()
		fresh := func() persist.UnavailableProof {
			proof, err := independent.normal.ProveUnavailable()
			if err != nil {
				t.Fatal(err)
			}
			return proof
		}
		independentSafety.state = state
		expiryRequest, expiryPreflight := contractionPreflight(preflight.ContractionExpiry, "resource/res_00000000000000000000000000000001", 4, time.Now().UTC())
		if err := independent.AuthorizeStateIndependentContraction(CertificateExpiry, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryKind: "certificate_expiry", ExpiryGeneration: 4, Deadline: deadline}, expiryRequest, expiryPreflight, fresh(), exposure, func(bool) error { return nil }); err != nil {
			t.Fatal(err)
		}
		wrongGeneration := expiryPreflight
		wrongGeneration.Generation++
		if err := independent.AuthorizeStateIndependentContraction(CertificateExpiry, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryKind: "certificate_expiry", ExpiryGeneration: 4, Deadline: deadline}, expiryRequest, wrongGeneration, fresh(), exposure, func(bool) error { return nil }); err == nil {
			t.Fatal("state-independent contraction accepted mismatched safety generation")
		}
		emergency := safety.EmptyState()
		independentSafety.state = emergency
		emergencyRequest, emergencyPreflight := contractionPreflight(preflight.ContractionEmergency, "installation", 1, time.Now().UTC())
		fallbackCalled := false
		emergencyRequest.FallbackStop = true
		emergencyPreflight.RequestDigest, _ = preflight.ContractionRequestDigest(emergencyRequest)
		if err := independent.AuthorizeStateIndependentContraction(EmergencyCloseAll, SafetyBinding{GlobalGeneration: 0, ProposedGeneration: 1}, emergencyRequest, emergencyPreflight, fresh(), exposure, func(fallback bool) error { fallbackCalled = fallback; return nil }); err != nil {
			t.Fatal(err)
		}
		if !fallbackCalled {
			t.Fatal("fallback-stop authority was not delivered to the contraction owner")
		}
		edge := safety.EmptyState()
		edge.Resources = []safety.ResourceSafety{{ResourceID: "res_00000000000000000000000000000001", GenerationSequence: 5, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner"), EdgeOne: safety.EdgeOneSafety{Expiry: &safety.DeadlineMarker{Generation: 5, Deadline: deadline, Binding: "edgeone"}}}}
		independentSafety.state = edge
		edgeExpiryRequest, edgeExpiryPreflight := contractionPreflight(preflight.ContractionExpiry, "resource/res_00000000000000000000000000000001", 5, time.Now().UTC())
		if err := independent.AuthorizeStateIndependentContraction(EdgeOneExpiry, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryKind: "edgeone_expiry", ExpiryGeneration: 5, Deadline: deadline}, edgeExpiryRequest, edgeExpiryPreflight, fresh(), exposure, func(bool) error { return nil }); err != nil {
			t.Fatal(err)
		}
		startup := safety.EmptyState()
		startup.Resources = []safety.ResourceSafety{{ResourceID: "res_00000000000000000000000000000001", GenerationSequence: 6, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner"), Reactivating: &safety.Reactivating{Generation: 6, PriorGeneration: 5, PlanID: "plan", CandidateDigest: testDigest("candidate"), CandidateBundle: testDigest("bundle"), BaseMarkers: absentSafetySnapshot(), CertificateUntil: time.Now().Add(time.Hour), ACLUntil: time.Now().Add(time.Hour)}}}
		independentSafety.state = startup
		startupRequest, startupPreflight := contractionPreflight(preflight.ContractionStartup, "resource/res_00000000000000000000000000000001", 6, time.Now().UTC())
		if err := independent.AuthorizeStateIndependentContraction(StartupContraction, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", PlanID: "plan", IntentGeneration: 6, CandidateDigest: testDigest("candidate"), CandidateBundle: testDigest("bundle")}, startupRequest, startupPreflight, fresh(), exposure, func(bool) error { return nil }); err != nil {
			t.Fatalf("startup contraction was rejected: %v", err)
		}
		if err := independent.AuthorizeStateIndependentContraction(Publish, SafetyBinding{}, startupRequest, startupPreflight, fresh(), exposure, func(bool) error { return nil }); err == nil {
			t.Fatal("publish entered state-independent exception")
		}
		_, otherProof, _ := unavailableProof(t)
		independentSafety.state = state
		if err := independent.AuthorizeStateIndependentContraction(CertificateExpiry, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryKind: "certificate_expiry", ExpiryGeneration: 4, Deadline: deadline}, expiryRequest, expiryPreflight, otherProof, exposure, func(bool) error { return nil }); err == nil {
			t.Fatal("unavailability proof from another store was accepted")
		}
	})

	t.Run("admission_retaining_handoff_rechecks_empty_inventory", func(t *testing.T) {
		normal, manager, admission, mutation := newOperationStores(t)
		defer normal.Close()
		defer mutation.Close()
		defer manager.Close()
		defer admission.Release()
		handoffAdmitter, err := NewAdmitter(normal, &fakeSafety{state: openSafetyState(), authority: manager.Authority()}, Options{Bindings: trustedBindings{}, Confirmation: testConfirmation{}, Registry: testRegistry(t)})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := mutation.AcquireExposure(context.Background(), "installation", manager); err == nil {
			t.Fatal("ordinary mutation retained the admission lock into exposure acquisition")
		}
		committed := false
		err = handoffAdmitter.FencedHandoff(context.Background(), admission, mutation, manager, HandoffBackupEnter, "installation", "", func(m *MutationLease, e *locks.Lease) error {
			committed = m.Active() && e.Holds(locks.Exposure)
			return nil
		})
		if err != nil || !committed {
			t.Fatalf("FencedHandoff() committed=%v err=%v", committed, err)
		}
		otherRoot := t.TempDir()
		_ = os.Chmod(otherRoot, 0o700)
		otherManager, err := locks.Open(locks.Config{RootPath: otherRoot, Owner: uint32(os.Geteuid()), Group: uint32(os.Getegid()), Mode: 0o700})
		if err != nil {
			t.Fatal(err)
		}
		otherAdmission, err := otherManager.Acquire(context.Background(), locks.MutationAdmission)
		if err != nil {
			t.Fatal(err)
		}
		if err := handoffAdmitter.FencedHandoff(context.Background(), otherAdmission, mutation, manager, HandoffBackupEnter, "installation", "", func(*MutationLease, *locks.Lease) error { return nil }); err == nil {
			t.Fatal("unrelated admission authority entered handoff")
		}
		_ = otherAdmission.Release()
		_ = otherManager.Close()
		now := time.Unix(1700000000, 0).UTC()
		planStore, _ := plans.NewStore(normal, plans.Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 64))})
		document, _ := normal.Read()
		plan, err := planStore.Create(context.Background(), admission, document.Revision, operationPlanSpec(now))
		if err != nil {
			t.Fatal(err)
		}
		binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
		admitter, _ := NewAdmitter(normal, &fakeSafety{state: openSafetyState(), authority: manager.Authority()}, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 32)), Bindings: trustedBindings{binding}, Confirmation: testConfirmation{}, Registry: testRegistry(t)})
		document, _ = normal.Read()
		if _, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/res_00000000000000000000000000000001", ActorIdentity: "session-one", PlanID: plan.ID, Source: AdmissionPlan, SafetyBinding: SafetyBinding{ResourceID: "res_00000000000000000000000000000001"}, ExpectedRevision: document.Revision}); err != nil {
			t.Fatal(err)
		}
		err = handoffAdmitter.FencedHandoff(context.Background(), admission, mutation, manager, HandoffMaintenance, "installation", "", func(*MutationLease, *locks.Lease) error {
			t.Fatal("fence committed with nonterminal inventory")
			return nil
		})
		if err == nil {
			t.Fatal("nonterminal inventory was accepted")
		}
	})
}

func TestOperationPreflightEvidenceSeparatesExpansionAndContraction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	target := "resource/res_00000000000000000000000000000001"
	expansion := []plans.Evidence{{Kind: preflight.ExpansionEvidencePrefix + string(preflight.ExpansionDomainHTTPS), Identity: target, Generation: 1, Digest: testDigest("expansion"), ObservedAt: now}}
	if err := requirePreflightEvidence(Publish, target, expansion, now); err != nil {
		t.Fatal(err)
	}
	if err := requirePreflightEvidence(Unpublish, target, expansion, now); err == nil {
		t.Fatal("unpublish accepted expansion prerequisites instead of closure authority")
	}
	contraction := []plans.Evidence{{Kind: preflight.ContractionEvidencePrefix + string(preflight.ContractionUnpublish), Identity: target, Generation: 2, Digest: testDigest("contraction"), ObservedAt: now}}
	if err := requirePreflightEvidence(Unpublish, target, contraction, now); err != nil {
		t.Fatal(err)
	}
	if err := requirePreflightEvidence(Publish, target, contraction, now); err == nil {
		t.Fatal("publish accepted contraction-only evidence")
	}
}

func TestOperationResultBranchTable(t *testing.T) {
	t.Run("exhaustive_results_keep_partial_and_unknown_distinct", func(t *testing.T) {
		values := []ResultBranch{{"complete", jobs.ResultSucceeded, jobs.PostconditionVerified}, {"no_effect", jobs.ResultFailed, jobs.PostconditionVerified}, {"known_residual", jobs.ResultPartial, jobs.PostconditionKnown}, {"executor_died", jobs.ResultInterrupted, jobs.PostconditionKnown}, {"runtime_unobservable", jobs.ResultUnknown, jobs.PostconditionUnobserved}}
		table, err := NewBranchTable(values)
		if err != nil || len(table.Names()) != 5 {
			t.Fatalf("NewBranchTable()=%#v,%v", table, err)
		}
		values = values[:4]
		if _, err := NewBranchTable(values); err == nil {
			t.Fatal("branch table omitted unknown")
		}
		values = append(values, ResultBranch{"unknown_as_partial", jobs.ResultUnknown, jobs.PostconditionKnown})
		if _, err := NewBranchTable(values); err == nil {
			t.Fatal("unknown and partial semantics were interchangeable")
		}
		if _, err := NewRegistry([]Registration{{Operation: Publish, Owner: "publication", Results: table}, {Operation: Publish, Owner: "duplicate", Results: table}}); err == nil {
			t.Fatal("duplicate operation owner registered")
		}
		duplicateNames := append(append([]ResultBranch(nil), values[:4]...), ResultBranch{"complete", jobs.ResultUnknown, jobs.PostconditionUnobserved})
		if _, err := NewBranchTable(duplicateNames); err == nil {
			t.Fatal("duplicate branch name was accepted")
		}
		registry, err := NewRegistry([]Registration{{Operation: Publish, Owner: "publication", Results: table}})
		if err != nil {
			t.Fatal(err)
		}
		if registration, ok := registry.Registration(Publish); !ok || registration.Owner != "publication" {
			t.Fatalf("registry lookup=%#v,%v", registration, ok)
		}
	})
}

func TestContractionStateCommitsBeforeRuntimeTerminalization(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	beforeInstallation := operationStateInstallation()
	beforeInstallation.Resources[0].PublicationRecord.State = domain.PublicationPublished
	bundle := domain.PublicationBundle{Generation: 1, ID: "bundle", ConfigDigest: beforeInstallation.Resources[0].CurrentConfigDigest, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: "endpoint", SiteIdentity: "site", ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.com"}, Certificate: domain.CertificateBundleIdentity{PointerIdentity: "pointer", BindingIdentity: "binding"}, Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}}}
	beforeInstallation.Resources[0].PublicationRecord.LastAppliedBundle = &bundle
	beforeInstallation.Resources[0].PublicationRecord.LastAppliedDigest = &bundle.ConfigDigest
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(Unpublish), Target: "resource/" + beforeInstallation.Resources[0].ID, ActorIdentity: "session-one"}, now, bytes.NewReader(bytes.Repeat([]byte{4}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	running, _ := jobs.Start(record)
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, PlanID: "plan-one", AdmissionSource: AdmissionPlan, Operation: Unpublish, Target: "resource/" + beforeInstallation.Resources[0].ID, Phase: PhaseLocalIntent, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{}, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionPlan, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	encode := func(value any) json.RawMessage {
		raw, encodeErr := persist.EncodeEntry(value)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return raw
	}
	before := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{"installations/current": encode(beforeInstallation), reservationKey(record.ID): encode(intent), "jobs/" + record.ID: encode(running)}}
	afterInstallation := beforeInstallation
	afterInstallation.Resources = append([]domain.AppResource(nil), beforeInstallation.Resources...)
	afterInstallation.Resources[0].PublicationRecord.State = domain.PublicationUnpublished
	afterInstallation.Resources[0].PublicationRecord.UnpublishedGeneration = 3
	afterInstallation.Resources[0].PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeUnknown, ObservedAt: now.Format(time.RFC3339), Reason: "closing_may_be_live"}
	afterInstallation.Resources[0].PublicationRecord.ContractionIntent = &domain.ContractionIntent{JobID: record.ID, Operation: string(Unpublish), Generation: 3, ClosureAuthorityDigest: testDigest("closure"), Prior: &bundle}
	afterIntent := intent
	afterIntent.ContractionDigest = testDigest("closure")
	after := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 2, Entries: map[string]json.RawMessage{"installations/current": encode(afterInstallation), reservationKey(record.ID): encode(afterIntent), "jobs/" + record.ID: encode(running)}}
	if err := validateOperationStateTransitions(before, after); err != nil {
		t.Fatalf("running contraction state rejected: %v", err)
	}
	unsafe := afterInstallation
	unsafe.Resources = append([]domain.AppResource(nil), afterInstallation.Resources...)
	unsafe.Resources[0].PublicationRecord.ContractionIntent = nil
	unsafeDocument := after
	unsafeDocument.Entries = map[string]json.RawMessage{"installations/current": encode(unsafe), reservationKey(record.ID): encode(afterIntent), "jobs/" + record.ID: encode(running)}
	if err := validateOperationStateTransitions(after, unsafeDocument); err == nil {
		t.Fatal("running contraction lost authority before terminal runtime evidence")
	}
}

func TestResourceCreateTerminalizesOnlyInitialAuthority(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	created := operationStateInstallation().Resources[0]
	created.PublicationRecord = domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}
	created.ManagedProcess.Requested = domain.ProcessRequestedStopped
	beforeInstallation := operationStateInstallation()
	beforeInstallation.Resources = []domain.AppResource{created}
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(ResourceCreate), Target: "installation", ActorIdentity: "ui/session/generation/1"}, now, bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	running, _ := jobs.Start(record)
	afterRecord, err := jobs.Finish(running, jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{{Kind: "resource_persisted_unpublished_stopped", Status: jobs.PostconditionVerified, Identity: created.CurrentConfigDigest}}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	afterInstallation := beforeInstallation
	afterInstallation.Resources = append([]domain.AppResource(nil), beforeInstallation.Resources...)
	afterInstallation.Resources[0].PublicationRecord.LastOperation = domain.OperationResourceCreate
	afterInstallation.Resources[0].PublicationRecord.LastOperationResult = domain.OperationSucceeded
	afterInstallation.Resources[0].PublicationRecord.LastJobID = record.ID
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, AdmissionSource: AdmissionUI, Operation: ResourceCreate, Target: "installation", Phase: PhaseLocalIntent, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{ResourceID: created.ID}, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionUI, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	terminal := intent
	terminal.Phase = PhaseTerminal
	encode := func(value any) json.RawMessage {
		raw, err := persist.EncodeEntry(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{"installations/current": encode(beforeInstallation), reservationKey(record.ID): encode(intent), "jobs/" + record.ID: encode(running)}}
	after := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 2, Entries: map[string]json.RawMessage{"installations/current": encode(afterInstallation), reservationKey(record.ID): encode(terminal), "jobs/" + record.ID: encode(afterRecord)}}
	if err := validateOperationStateTransitions(before, after); err != nil {
		t.Fatal(err)
	}
	tampered := afterInstallation
	tampered.Resources = append([]domain.AppResource(nil), afterInstallation.Resources...)
	tampered.Resources[0].Name = "changed"
	after.Entries["installations/current"] = encode(tampered)
	if err := validateOperationStateTransitions(before, after); err == nil {
		t.Fatal("resource create terminalization changed configuration")
	}
}

func TestOperationOwnedResourceStateRequiresAtomicIntent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	beforeInstallation := operationStateInstallation()
	afterInstallation := operationStateInstallation()
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(ResourceUpdate), Target: "resource/" + afterInstallation.Resources[0].ID, ActorIdentity: "session-one"}, now, bytes.NewReader(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	record, err = jobs.Start(record)
	if err != nil {
		t.Fatal(err)
	}
	runningRecord := record
	record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{{Kind: "state_committed", Status: jobs.PostconditionVerified, Identity: "res_00000000000000000000000000000001"}}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	afterInstallation.Resources[0].PublicationRecord.LastOperation = domain.OperationResourceUpdate
	afterInstallation.Resources[0].PublicationRecord.LastOperationResult = domain.OperationSucceeded
	afterInstallation.Resources[0].PublicationRecord.LastJobID = record.ID
	before := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{}}
	after := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 2, Entries: map[string]json.RawMessage{}}
	encode := func(value any) json.RawMessage {
		raw, err := persist.EncodeEntry(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before.Entries["installations/current"] = encode(beforeInstallation)
	after.Entries["installations/current"] = encode(afterInstallation)
	if err := validateOperationStateTransitions(before, after); err == nil {
		t.Fatal("resource operation state changed without job and intent")
	}
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, AdmissionSource: AdmissionUI, Operation: ResourceUpdate, Target: "resource/" + afterInstallation.Resources[0].ID, Phase: PhaseTerminal, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{}, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionUI, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	activeIntent := intent
	activeIntent.Phase = PhaseLocalIntent
	before.Entries[reservationKey(record.ID)] = encode(activeIntent)
	before.Entries["jobs/"+record.ID] = encode(runningRecord)
	after.Entries[reservationKey(record.ID)] = encode(intent)
	after.Entries["jobs/"+record.ID] = encode(record)
	if err := validateOperationStateTransitions(before, after); err != nil {
		t.Fatalf("atomic operation state transition rejected: %v", err)
	}
	arbitraryPrune := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 3, Entries: map[string]json.RawMessage{}}
	for key, raw := range after.Entries {
		arbitraryPrune.Entries[key] = append(json.RawMessage(nil), raw...)
	}
	delete(arbitraryPrune.Entries, reservationKey(record.ID))
	delete(arbitraryPrune.Entries, "jobs/"+record.ID)
	if err := validateOperationStateTransitions(after, arbitraryPrune); err == nil {
		t.Fatal("recent terminal operation graph was deleted outside exact overflow retention")
	}
	replayedInstallation := afterInstallation
	replayedInstallation.Resources = append([]domain.AppResource(nil), afterInstallation.Resources...)
	replayedInstallation.Resources[0].PublicationRecord.UnpublishedGeneration++
	replay := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 3, Entries: map[string]json.RawMessage{}}
	for key, raw := range after.Entries {
		replay.Entries[key] = append(json.RawMessage(nil), raw...)
	}
	replay.Entries["installations/current"] = encode(replayedInstallation)
	if err := validateOperationStateTransitions(after, replay); err == nil {
		t.Fatal("old terminal job was replayed to rewrite resource state")
	}
	afterInstallation.Resources[0].PublicationRecord.LastJobID = "job_" + strings.Repeat("f", 64)
	after.Entries["installations/current"] = encode(afterInstallation)
	if err := validateOperationStateTransitions(before, after); err == nil {
		t.Fatal("resource operation state accepted a mismatched job identity")
	}
}

func unavailableProof(t *testing.T) (*Admitter, persist.UnavailableProof, *locks.Manager) {
	t.Helper()
	lockRoot := t.TempDir()
	_ = os.Chmod(lockRoot, 0o700)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	staging := filepath.Join(root, "staging")
	_ = os.Mkdir(staging, 0o700)
	normal, err := persist.Open(persist.Config{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "normal.json"), Owner: owner, LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = normal.Close() })
	admitter, err := NewAdmitter(normal, &fakeSafety{state: openSafetyState(), authority: manager.Authority()}, Options{Bindings: trustedBindings{}, Confirmation: testConfirmation{}, Registry: testRegistry(t), StateIndependentOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := normal.ProveUnavailable()
	if err != nil {
		t.Fatal(err)
	}
	return admitter, proof, manager
}

func contractionPreflight(kind preflight.ContractionKind, target string, generation uint64, now time.Time) (preflight.ContractionRequest, preflight.Result) {
	request := preflight.ContractionRequest{Kind: kind, Target: target, Generation: generation, OwnershipInventoryDigest: testDigest("ownership"), ClosureAuthorityDigest: testDigest("closure")}
	digest, _ := preflight.ContractionRequestDigest(request)
	result := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(kind), Target: target, Generation: generation, RequestDigest: digest, Allowed: true, ObservedAt: now, ValidUntil: now.Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "closure_authority", Disposition: preflight.FindingPassed, Summary: "exact contraction authority passed", Identity: "fixture"}}}
	return request, result
}

func absentSafetySnapshot() []safety.MarkerSnapshot {
	return []safety.MarkerSnapshot{
		{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent},
		{Kind: safety.MarkerContraction, State: safety.SnapshotAbsent},
		{Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent},
		{Kind: safety.MarkerEdgeOneExpiry, State: safety.SnapshotAbsent},
	}
}

func openSafetyState() safety.State {
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "res_00000000000000000000000000000001", State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner")}}
	return state
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	table, err := NewBranchTable([]ResultBranch{{"complete", jobs.ResultSucceeded, jobs.PostconditionVerified}, {"no_effect", jobs.ResultFailed, jobs.PostconditionVerified}, {"known_residual", jobs.ResultPartial, jobs.PostconditionKnown}, {"executor_died", jobs.ResultInterrupted, jobs.PostconditionKnown}, {"runtime_unobservable", jobs.ResultUnknown, jobs.PostconditionUnobserved}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Registration{{Operation: Publish, Owner: "publication", Results: table}, {Operation: AutomaticReconciliation, Owner: "startup-recovery", Results: table}})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func operationPlanSpec(now time.Time) plans.Spec {
	return plans.Spec{Operation: "publish", Target: plans.Target{Kind: plans.TargetResource, ID: "res_00000000000000000000000000000001"}, ActorIdentity: "session-one", Config: plans.DigestBinding{Applicable: true, Digest: testDigest("config")}, Applied: plans.DigestBinding{Applicable: true, Digest: testDigest("applied")}, Evidence: []plans.Evidence{
		{Kind: "config", Identity: "res_00000000000000000000000000000001", Generation: 1, Digest: testDigest("evidence"), ObservedAt: now},
		{Kind: preflight.ExpansionEvidencePrefix + string(preflight.ExpansionDomainHTTPS), Identity: "resource/res_00000000000000000000000000000001", Generation: 1, Digest: testDigest("preflight"), ObservedAt: now},
	}, ExposureSummary: "expands_ingress", Prerequisites: "qualified"}
}
func testDigest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}
func operationStateInstallation() domain.Installation {
	return domain.Installation{
		SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001",
		Management: domain.ManagementAuthority{Address: "127.23.45.67", Port: 23456},
		Resources: []domain.AppResource{{
			ID: "res_00000000000000000000000000000001", Name: "App", Lifecycle: domain.LifecycleActive,
			CurrentConfigDigest: testDigest("config"),
			Target:              domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}},
			Publication:         domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.com", AccessMode: domain.AppAccessPublic}},
			PublicationRecord:   domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 2},
			ManagedProcess:      &domain.ManagedProcess{ID: "proc_00000000000000000000000000000001", Requested: domain.ProcessRequestedStopped, Service: domain.ManagedService{Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{"/var/lib/app"}}},
		}},
	}
}

func testOperationInstallation() domain.Installation {
	installation := operationStateInstallation()
	installation.Resources[0].CurrentConfigDigest = testDigest("operation-config")
	return installation
}
func newOperationStores(t *testing.T) (*persist.Store, *locks.Manager, *locks.Lease, *MutationSet) {
	t.Helper()
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	staging := filepath.Join(root, "staging")
	_ = os.Mkdir(staging, 0o700)
	lockRoot := t.TempDir()
	_ = os.Chmod(lockRoot, 0o700)
	mutationRoot := t.TempDir()
	_ = os.Chmod(mutationRoot, 0o700)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	normal, err := persist.Open(persist.Config{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "normal.json"), Owner: owner, LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normal.Initialize(context.Background(), admission); err != nil {
		t.Fatal(err)
	}
	mutation, err := OpenMutationSet(MutationConfig{RootPath: mutationRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700, Authority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	return normal, manager, admission, mutation
}
