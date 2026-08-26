package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/safety"
	"lanpanel/internal/sources"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	defer func(ignore func() error) { _ = ignore() }(normal.Close)
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	defer func(ignore func() error) { _ = ignore() }(manager.Close)
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
		defer func(ignore func() error) { _ = ignore() }(normal.Close)
		defer func(ignore func() error) { _ = ignore() }(mutation.Close)
		defer func(ignore func() error) { _ = ignore() }(manager.Close)
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
		defer func(ignore func() error) { _ = ignore() }(manager.Close)
		defer func(ignore func() error) { _ = ignore() }(admission.Release)
		defer func(ignore func() error) { _ = ignore() }(mutation.Close)
		defer func(ignore func() error) { _ = ignore() }(normal.Close)
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
		defer func(ignore func() error) { _ = ignore() }(normal.Close)
		defer func(ignore func() error) { _ = ignore() }(mutation.Close)
		defer func(ignore func() error) { _ = ignore() }(manager.Close)
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
		if err := validateSafetyTargetBinding(AdmitRequest{Operation: Publish, Target: "resource/app-a", PlanID: "plan", Source: AdmissionPlan, SafetyBinding: SafetyBinding{ResourceID: "app-b"}}); err == nil {
			t.Fatal("resource target was admitted under another resource's safety authority")
		}
		state = safety.EmptyState()
		deadline := time.Now().UTC().Add(-time.Minute)
		state.Resources = []safety.ResourceSafety{{ResourceID: "res_00000000000000000000000000000001", GenerationSequence: 4, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner"), ActiveCertificate: &safety.ActiveCertificateAuthority{Generation: 1, Fingerprint: testDigest("certificate"), Binding: "certificate", LastTrustedWall: deadline.Add(-time.Hour), NotAfter: deadline}, CertificateExpiry: &safety.DeadlineMarker{Generation: 4, Deadline: deadline, Binding: "certificate"}}}
		if err := authorize(CertificateExpiry, state, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryGeneration: 4, Deadline: deadline, CandidateBundle: "certificate"}, false, time.Now()); err != nil {
			t.Fatalf("deadline contraction exception rejected: %v", err)
		}
		futureDeadline := time.Now().UTC().Add(time.Hour)
		state.Resources[0].CertificateExpiry = &safety.DeadlineMarker{Generation: 5, Deadline: futureDeadline, Binding: "future"}
		state.Resources[0].GenerationSequence = 5
		if err := authorize(CertificateExpiry, state, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryGeneration: 5, Deadline: futureDeadline, CandidateBundle: "future"}, false, time.Now()); err != nil {
			t.Fatalf("durable expiry marker stopped being actionable after clock rollback: %v", err)
		}
		state.Resources[0].CertificateExpiry = &safety.DeadlineMarker{Generation: 4, Deadline: deadline, Binding: "certificate"}
		state.Resources[0].GenerationSequence = 4
		independent, _, independentManager := unavailableProof(t)
		independentSafety := independent.safety.(*fakeSafety)
		exposure, err := independentManager.Acquire(context.Background(), locks.Exposure)
		if err != nil {
			t.Fatal(err)
		}
		defer func(ignore func() error) { _ = ignore() }(exposure.Release)
		fresh := func() persist.UnavailableProof {
			proof, err := independent.normal.ProveUnavailable()
			if err != nil {
				t.Fatal(err)
			}
			return proof
		}
		independentSafety.state = state
		expiryRequest, expiryPreflight := contractionPreflight(preflight.ContractionExpiry, "resource/res_00000000000000000000000000000001", 4, time.Now().UTC())
		if err := independent.AuthorizeStateIndependentContraction(CertificateExpiry, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryGeneration: 4, Deadline: deadline, CandidateBundle: "certificate"}, expiryRequest, expiryPreflight, fresh(), exposure, func(bool) error { return nil }); err != nil {
			t.Fatal(err)
		}
		wrongGeneration := expiryPreflight
		wrongGeneration.Generation++
		if err := independent.AuthorizeStateIndependentContraction(CertificateExpiry, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryGeneration: 4, Deadline: deadline, CandidateBundle: "certificate"}, expiryRequest, wrongGeneration, fresh(), exposure, func(bool) error { return nil }); err == nil {
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
		startup := safety.EmptyState()
		startup.Resources = []safety.ResourceSafety{{ResourceID: "res_00000000000000000000000000000001", GenerationSequence: 6, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner"), Reactivating: &safety.Reactivating{Generation: 6, PriorGeneration: 5, PlanID: "plan", CandidateDigest: testDigest("candidate"), CandidateBundle: testDigest("bundle"), BaseMarkers: absentSafetySnapshot(), CertificateUntil: time.Now().Add(time.Hour)}}}
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
		if err := independent.AuthorizeStateIndependentContraction(CertificateExpiry, SafetyBinding{ResourceID: "res_00000000000000000000000000000001", ExpiryGeneration: 4, Deadline: deadline, CandidateBundle: "certificate"}, expiryRequest, expiryPreflight, otherProof, exposure, func(bool) error { return nil }); err == nil {
			t.Fatal("unavailability proof from another store was accepted")
		}
	})
}

func TestCertificateExpiryAdmissionReusesOneGenerationGraph(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	resourceID := "res_00000000000000000000000000000001"
	target := "resource/" + resourceID
	bindingID := testDigest("certificate-binding")
	deadline := now.Add(-time.Minute)

	for _, phase := range []Phase{PhaseReserved, PhaseRejected, PhaseLocalIntent, PhaseTerminal} {
		t.Run(string(phase), func(t *testing.T) {
			normal, manager, admission, mutationSet := newOperationStores(t)
			defer func() { _ = normal.Close() }()
			defer func() { _ = mutationSet.Close() }()
			defer func() { _ = manager.Close() }()
			defer func() { _ = admission.Release() }()

			state := openSafetyState()
			state.Resources[0].GenerationSequence = 3
			state.Resources[0].ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 1, Fingerprint: testDigest("certificate"), Binding: bindingID, NotAfter: deadline, LastTrustedWall: deadline.Add(-time.Hour)}
			admitter, err := NewAdmitter(normal, &fakeSafety{state: state, authority: manager.Authority()}, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 512)), Bindings: trustedBindings{}, Confirmation: testConfirmation{}, Registry: testRegistry(t)})
			if err != nil {
				t.Fatal(err)
			}
			request := AdmitRequest{Operation: CertificateExpiry, Target: target, ActorIdentity: "timer/certificate-expiry", Source: AdmissionTimer, SafetyBinding: SafetyBinding{ResourceID: resourceID, ExpiryGeneration: 4, Deadline: deadline, CandidateBundle: bindingID}, ExpectedRevision: 1}
			record, err := admitter.Admit(context.Background(), admission, request)
			if err != nil {
				t.Fatal(err)
			}
			revision := uint64(2)
			switch phase {
			case PhaseReserved:
			case PhaseRejected:
				if err := admitter.RejectReservation(context.Background(), admission, revision, record.ID, "certificate_setup_failed"); err != nil {
					t.Fatal(err)
				}
				revision++
			case PhaseLocalIntent, PhaseTerminal:
				if err := admission.Release(); err != nil {
					t.Fatal(err)
				}
				mutation, exposure, err := mutationSet.AcquireExposure(context.Background(), target, manager)
				if err != nil {
					t.Fatal(err)
				}
				preflightRequest, preflightResult := contractionPreflight(preflight.ContractionExpiry, target, 4, now)
				if _, err := admitter.BeginPlanless(context.Background(), mutation, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: revision, IntentGeneration: revision + 1, ContractionRequest: &preflightRequest, ContractionPreflight: &preflightResult}); err != nil {
					t.Fatal(err)
				}
				revision++
				if phase == PhaseTerminal {
					if _, err := admitter.Complete(context.Background(), mutation, exposure, revision, record.ID, "no_effect", nil, []jobs.Postcondition{{Kind: "mutation_not_started", Status: jobs.PostconditionVerified, Identity: record.ID}}, "contraction_authority_failed"); err != nil {
						t.Fatal(err)
					}
					revision++
				}
				if err := ReleaseExposure(mutation, exposure); err != nil {
					t.Fatal(err)
				}
				admission, err = manager.Acquire(context.Background(), locks.MutationAdmission)
				if err != nil {
					t.Fatal(err)
				}
			}
			if phase == PhaseLocalIntent {
				if err := admitter.RejectReservation(context.Background(), admission, revision, record.ID, "certificate_setup_failed"); err == nil || !strings.Contains(err.Error(), "no longer reserved") {
					t.Fatalf("local intent was overwritten by reservation cleanup: %v", err)
				}
			}
			request.ExpectedRevision = revision
			if _, err := admitter.Admit(context.Background(), admission, request); err == nil || !strings.Contains(err.Error(), "already has an operation graph") {
				t.Fatalf("duplicate expiry graph admission error=%v", err)
			}
			document, err := normal.Read()
			if err != nil {
				t.Fatal(err)
			}
			matches := 0
			for _, key := range persist.EntryKeys(document, "intents") {
				var intent Reservation
				if err := json.Unmarshal(document.Entries[key], &intent); err != nil {
					t.Fatal(err)
				}
				if intent.Operation == CertificateExpiry && intent.SafetyBinding.ResourceID == resourceID && intent.SafetyBinding.ExpiryGeneration == 4 {
					matches++
					if intent.Phase != phase {
						t.Fatalf("phase=%s want=%s", intent.Phase, phase)
					}
				}
			}
			if matches != 1 {
				t.Fatalf("matching expiry graphs=%d", matches)
			}
		})
	}
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
	bundle := domain.PublicationBundle{Generation: 1, ID: "bundle", ConfigDigest: beforeInstallation.Resources[0].CurrentConfigDigest, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: "endpoint", SiteIdentity: "site", ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.com"}, Certificate: operationCertificateIdentity(), Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, GoAccess: domain.GoAccessBundleIdentity{RetiredGeneration: 1, RetiredStateGeneration: 1, RetiredServiceIdentity: testDigest("retired-service"), RetiredUnitIdentities: operationUnitIdentities("retired")}}}
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
	afterInstallation.Resources[0].PublicationRecord.ContractionIntent = &domain.ContractionIntent{JobID: record.ID, Operation: string(Unpublish), Generation: 3, ClosureAuthorityDigest: testDigest("closure"), Prior: &bundle, GoAccessRetirements: []domain.GoAccessRetirementIdentity{{Generation: 1, StateGeneration: 1, ServiceIdentity: testDigest("retired-service"), UnitIdentities: operationUnitIdentities("retired")}}}
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
	terminal, finishErr := jobs.Finish(running, jobs.Completion{Result: jobs.ResultPartial, Postconditions: []jobs.Postcondition{{Kind: "goaccess_retirement_pending", Status: jobs.PostconditionKnown, Identity: testDigest("closure")}}, ErrorCode: "goaccess_stop_failed"}, now.Add(time.Second))
	if finishErr != nil {
		t.Fatal(finishErr)
	}
	terminalIntent := afterIntent
	terminalIntent.Phase = PhaseTerminal
	terminalInstallation := afterInstallation
	terminalInstallation.Resources = append([]domain.AppResource(nil), afterInstallation.Resources...)
	terminalResource := &terminalInstallation.Resources[0]
	terminalResource.PublicationRecord.ContractionIntent = nil
	terminalResource.PublicationRecord.PendingGoAccessRetirements = []domain.GoAccessRetirementIdentity{{Generation: 1, StateGeneration: 1, ServiceIdentity: testDigest("retired-service"), UnitIdentities: operationUnitIdentities("retired")}}
	terminalResource.PublicationRecord.GoAccessRetirementSourceJobID = record.ID
	terminalResource.PublicationRecord.GoAccessRetirementAuthorityDigest = testDigest("retirement-authority")
	terminalResource.PublicationRecord.LastOperation = domain.OperationUnpublish
	terminalResource.PublicationRecord.LastOperationResult = domain.OperationPartial
	terminalResource.PublicationRecord.LastJobID = record.ID
	terminalDocument := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 3, Entries: map[string]json.RawMessage{"installations/current": encode(terminalInstallation), reservationKey(record.ID): encode(terminalIntent), "jobs/" + record.ID: encode(terminal)}}
	if err := validateOperationStateTransitions(after, terminalDocument); err != nil {
		t.Fatalf("partial contraction retirement transition rejected: %v", err)
	}
}

func TestGoAccessRetirementModifiedPathsCoverExactCleanup(t *testing.T) {
	retirement := domain.GoAccessRetirementIdentity{Generation: 2, StateGeneration: 1, ServiceIdentity: testDigest("service"), RemoveState: true, RemoveShared: true, UnitIdentities: operationUnitIdentities("service")}
	paths, err := GoAccessRetirementModifiedPaths("res_00000000000000000000000000000001", retirement)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"/etc/systemd/system/lanpanel-goaccess-res_00000000000000000000000000000001-2.service", "/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-res_00000000000000000000000000000001-2.service", "/run/lanpanel-goaccess/res_00000000000000000000000000000001-2.sock", "/var/lib/lanpanel/goaccess/res_00000000000000000000000000000001/generations/1", "/var/log/lanpanel/goaccess/res_00000000000000000000000000000001", "/etc/sysusers.d/lanpanel-goaccess-res_00000000000000000000000000000001.conf", "/etc/passwd"} {
		if !slices.Contains(paths, required) {
			t.Fatalf("retirement modified paths omit %q: %v", required, paths)
		}
	}
	if !slices.IsSorted(paths) {
		t.Fatalf("retirement modified paths are not sorted: %v", paths)
	}
}

func TestContractionTransfersPendingGoAccessRetirementAuthority(t *testing.T) {
	pending := domain.GoAccessRetirementIdentity{Generation: 2, StateGeneration: 2, ServiceIdentity: testDigest("service"), RemoveState: true, UnitIdentities: operationUnitIdentities("service")}
	record := domain.PublicationRecord{PendingGoAccessRetirements: []domain.GoAccessRetirementIdentity{pending}, GoAccessRetirementSourceJobID: "job-source", GoAccessRetirementSourceJournalID: "journal-source", GoAccessRetirementAuthorityDigest: testDigest("authority")}
	retirements, err := transferPendingGoAccessRetirements(&record, []domain.GoAccessRetirementIdentity{{Generation: 2, StateGeneration: 2, ServiceIdentity: pending.ServiceIdentity, UnitIdentities: append([]string(nil), pending.UnitIdentities...)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(retirements) != 1 || !retirements[0].RemoveState || len(record.PendingGoAccessRetirements) != 0 || record.GoAccessRetirementSourceJobID != "" || record.GoAccessRetirementSourceJournalID != "" || record.GoAccessRetirementAuthorityDigest != "" {
		t.Fatalf("pending retirement transfer=%#v record=%#v", retirements, record)
	}
}

func TestContractionRetainsCommittedGoAccessState(t *testing.T) {
	prior := domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: 1, StateGeneration: 1, ServiceIdentity: testDigest("prior"), UnitIdentities: operationUnitIdentities("prior")}}}
	candidate := domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: 2, StateGeneration: 2, ServiceIdentity: testDigest("candidate"), UnitIdentities: operationUnitIdentities("candidate"), RetiredGeneration: 1, RetiredStateGeneration: 1, RetiredServiceIdentity: testDigest("prior"), RetiredUnitIdentities: operationUnitIdentities("prior")}}}
	retirements, err := goAccessRetirements(&prior, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(retirements) != 2 || retirements[0].Generation != 1 || retirements[0].RemoveState || retirements[0].RemoveShared || !retirements[1].RemoveState {
		t.Fatalf("retirements=%#v", retirements)
	}
	first, err := goAccessRetirements(nil, &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: 2, StateGeneration: 2, ServiceIdentity: testDigest("candidate")}}})
	if err != nil || len(first) != 1 || !first[0].RemoveShared {
		t.Fatalf("first candidate retirements=%#v %v", first, err)
	}
}

func TestRunningGoAccessRetirementAuthorityIsResumable(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(GoAccessRetirement), Target: "resource/res_00000000000000000000000000000001", ActorIdentity: "startup-recovery"}, now, bytes.NewReader(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	running, _ := jobs.Start(record)
	retirements := []domain.GoAccessRetirementIdentity{{Generation: 2, StateGeneration: 2, ServiceIdentity: testDigest("service"), UnitIdentities: operationUnitIdentities("service")}}
	authorityDigest, digestErr := GoAccessRetirementInventoryDigest(retirements)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	binding, bindingErr := GoAccessRetirementBinding("ins_00000000000000000000000000000001", "res_00000000000000000000000000000001", "contraction", "job-source", "", authorityDigest, retirements)
	if bindingErr != nil {
		t.Fatal(bindingErr)
	}
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, AdmissionSource: AdmissionStartup, Operation: GoAccessRetirement, Target: record.Target, Phase: PhaseLocalIntent, SafetyDigest: testDigest("safety"), SafetyBinding: binding, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionStartup, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	raw, err := persist.EncodeEntry(intent)
	if err != nil {
		t.Fatal(err)
	}
	jobRaw, err := persist.EncodeEntry(running)
	if err != nil {
		t.Fatal(err)
	}
	document := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 2, Entries: map[string]json.RawMessage{reservationKey(record.ID): raw, "jobs/" + record.ID: jobRaw}}
	observed, observedJob, present, err := FindRunningGoAccessRetirement(document, record.Target)
	if err != nil || !present || observed.JobID != record.ID || observedJob.ID != record.ID || observedJob.Status != jobs.StatusRunning {
		t.Fatalf("resumable retirement=%v %#v %#v %v", present, observed, observedJob, err)
	}
	reservedIntent := intent
	reservedIntent.Phase = PhaseReserved
	reservedIntent.IntentGeneration = 0
	reservedIntent.Consumption = nil
	reservedIntentRaw, encodeErr := persist.EncodeEntry(reservedIntent)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	reservedJobRaw, encodeErr := persist.EncodeEntry(record)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	reservedDocument := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{reservationKey(record.ID): reservedIntentRaw, "jobs/" + record.ID: reservedJobRaw}}
	observed, observedJob, present, err = FindRunningGoAccessRetirement(reservedDocument, record.Target)
	if err != nil || !present || observed.Phase != PhaseReserved || observedJob.Status != jobs.StatusReserved {
		t.Fatalf("reserved retirement recovery=%v %#v %#v %v", present, observed, observedJob, err)
	}
}

func TestPublicationRetirementAuthoritySurvivesCertificateJobMutation(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	installation := operationStateInstallation()
	resource := &installation.Resources[0]
	bundle := domainBundleForRetirement(resource.CurrentConfigDigest)
	retirements := []domain.GoAccessRetirementIdentity{{Generation: 2, StateGeneration: 2, ServiceIdentity: testDigest("service"), UnitIdentities: operationUnitIdentities("service")}}
	authorityDigest, err := GoAccessRetirementInventoryDigest(retirements)
	if err != nil {
		t.Fatal(err)
	}
	source, err := jobs.NewReserved(jobs.Spec{Operation: string(Publish), Target: "resource/" + resource.ID, ActorIdentity: "ui/session"}, now, bytes.NewReader(bytes.Repeat([]byte{10}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	running, _ := jobs.Start(source)
	source, err = jobs.Finish(running, jobs.Completion{Result: jobs.ResultPartial, Postconditions: []jobs.Postcondition{{Kind: "goaccess_prior_retirement", Status: jobs.PostconditionKnown, Identity: "2:" + testDigest("service")}}, ErrorCode: "goaccess_stop_failed"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := jobs.NewReserved(jobs.Spec{Operation: string(CertificateRenew), Target: "resource/" + resource.ID, ActorIdentity: "timer"}, now, bytes.NewReader(bytes.Repeat([]byte{11}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	bundle.DomainHTTPS.Certificate.Generation++
	bundle.DomainHTTPS.Certificate.Fingerprint = testDigest("renewed-cert")
	resource.PublicationRecord = domain.PublicationRecord{State: domain.PublicationPublished, UnpublishedGeneration: 2, LastAppliedDigest: &bundle.ConfigDigest, LastAppliedBundle: &bundle, LastOperation: domain.OperationPublish, LastOperationResult: domain.OperationPartial, LastJobID: renewal.ID, PendingGoAccessRetirements: retirements, GoAccessRetirementSourceJobID: source.ID, GoAccessRetirementSourceJournalID: "activation-" + source.ID, GoAccessRetirementAuthorityDigest: authorityDigest}
	binding, err := GoAccessRetirementBinding(installation.InstallationID, resource.ID, "publication", source.ID, "activation-"+source.ID, authorityDigest, retirements)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value any) json.RawMessage {
		raw, encodeErr := persist.EncodeEntry(value)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return raw
	}
	journal := JournalRecord{SchemaVersion: "lanpanel.operation.journal.v1", ID: "activation-" + source.ID, JobID: source.ID, Phase: JournalTerminal}
	document := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 3, Entries: map[string]json.RawMessage{"installations/current": encode(installation), "jobs/" + source.ID: encode(source), "journals/" + journal.ID: encode(journal)}}
	if err := ValidateGoAccessRetirementAuthority(document, binding); err != nil {
		t.Fatalf("dedicated retirement authority was invalidated by renewal metadata: %v", err)
	}
}

func TestUnpublishedGenerationRestoreExceptionIsTemporaryHTTPOnly(t *testing.T) {
	resource := operationStateInstallation().Resources[0]
	resource.Publication = domain.AppPublication{Kind: domain.PublicationTemporaryHTTP, TemporaryHTTP: &domain.TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 18080}}
	resource.PublicationRecord.State = domain.PublicationActivating
	resource.PublicationRecord.UnpublishedGeneration = 4
	resource.PublicationRecord.ActivationIntent = &domain.ActivationIntent{PriorState: domain.PublicationUnpublished, Candidate: domain.PublicationBundle{Kind: domain.PublicationTemporaryHTTP, TemporaryHTTP: &domain.TemporaryHTTPBundleIdentity{}}}
	restored := resource
	restored.PublicationRecord.State = domain.PublicationUnpublished
	if !temporaryPublicationRestoredUnpublished(resource, restored) {
		t.Fatal("exact Temporary HTTP prior restore was rejected")
	}
	domainResource := resource
	domainResource.Publication = domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{}}
	domainResource.PublicationRecord.ActivationIntent = &domain.ActivationIntent{PriorState: domain.PublicationUnpublished, Candidate: domain.PublicationBundle{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{}}}
	if temporaryPublicationRestoredUnpublished(domainResource, restored) {
		t.Fatal("Domain HTTPS received the Temporary HTTP generation exception")
	}
}

func TestGoAccessRetirementKeepsPublishJobRunningUntilFinalCommit(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	installation := operationStateInstallation()
	resource := &installation.Resources[0]
	bundle := domainBundleForRetirement(resource.CurrentConfigDigest)
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(Publish), Target: "resource/" + resource.ID, ActorIdentity: "ui/session"}, now, bytes.NewReader(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	running, _ := jobs.Start(record)
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, PlanID: "plan-one", AdmissionSource: AdmissionPlan, Operation: Publish, Target: "resource/" + resource.ID, Phase: PhaseLocalIntent, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{ResourceID: resource.ID}, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionPlan, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	resource.PublicationRecord.State = domain.PublicationActivating
	resource.PublicationRecord.ActivationIntent = &domain.ActivationIntent{ID: "activation-test", JobID: record.ID, PlanID: "plan-one", Generation: 2, PriorState: domain.PublicationUnpublished, Candidate: bundle}
	resource.PublicationRecord.LastJobID = record.ID
	encode := func(value any) json.RawMessage {
		raw, encodeErr := persist.EncodeEntry(value)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return raw
	}
	before := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{"installations/current": encode(installation), reservationKey(record.ID): encode(intent), "jobs/" + record.ID: encode(running)}}
	pendingInstallation := installation
	pendingInstallation.Resources = append([]domain.AppResource(nil), installation.Resources...)
	pending := &pendingInstallation.Resources[0]
	pending.PublicationRecord.State = domain.PublicationPublished
	pending.PublicationRecord.ActivationIntent = nil
	pending.PublicationRecord.LastAppliedBundle = &bundle
	pending.PublicationRecord.LastAppliedDigest = &bundle.ConfigDigest
	pending.PublicationRecord.LastOperation = domain.OperationPublish
	pending.PublicationRecord.LastOperationResult = domain.OperationPartial
	pending.PublicationRecord.PendingGoAccessRetirements = []domain.GoAccessRetirementIdentity{{Generation: 2, StateGeneration: 2, ServiceIdentity: testDigest("service"), UnitIdentities: operationUnitIdentities("service")}}
	pending.PublicationRecord.GoAccessRetirementSourceJobID = record.ID
	pending.PublicationRecord.GoAccessRetirementSourceJournalID = "activation-" + record.ID
	pending.PublicationRecord.GoAccessRetirementAuthorityDigest = testDigest("bundle-authority")
	pendingDocument := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 2, Entries: map[string]json.RawMessage{"installations/current": encode(pendingInstallation), reservationKey(record.ID): encode(intent), "jobs/" + record.ID: encode(running)}}
	if err := validateOperationStateTransitions(before, pendingDocument); err != nil {
		t.Fatalf("pending retirement transition rejected: %v", err)
	}
	partial, partialErr := jobs.Finish(running, jobs.Completion{Result: jobs.ResultPartial, Postconditions: []jobs.Postcondition{{Kind: "goaccess_prior_retirement", Status: jobs.PostconditionKnown, Identity: "2:" + testDigest("service")}}, ErrorCode: "goaccess_stop_failed"}, now.Add(time.Second))
	if partialErr != nil {
		t.Fatal(partialErr)
	}
	partialIntent := intent
	partialIntent.Phase = PhaseTerminal
	partialInstallation := pendingInstallation
	partialInstallation.Resources = append([]domain.AppResource(nil), pendingInstallation.Resources...)
	partialInstallation.Resources[0].PublicationRecord.LastOperationResult = domain.OperationPartial
	partialDocument := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 3, Entries: map[string]json.RawMessage{"installations/current": encode(partialInstallation), reservationKey(record.ID): encode(partialIntent), "jobs/" + record.ID: encode(partial)}}
	if err := validateOperationStateTransitions(pendingDocument, partialDocument); err != nil {
		t.Fatalf("partial retirement transition rejected: %v", err)
	}
	interrupted, interruptedErr := jobs.Finish(running, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "published_committed", Status: jobs.PostconditionKnown, Identity: "site"}, {Kind: "goaccess_prior_retirement", Status: jobs.PostconditionKnown, Identity: "2:" + testDigest("service")}}, ErrorCode: "goaccess_retirement_recovery"}, now.Add(time.Second))
	if interruptedErr != nil {
		t.Fatal(interruptedErr)
	}
	interruptedIntent := intent
	interruptedIntent.Phase = PhaseTerminal
	interruptedInstallation := pendingInstallation
	interruptedInstallation.Resources = append([]domain.AppResource(nil), pendingInstallation.Resources...)
	interruptedInstallation.Resources[0].PublicationRecord.LastOperationResult = domain.OperationInterrupted
	interruptedDocument := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 3, Entries: map[string]json.RawMessage{"installations/current": encode(interruptedInstallation), reservationKey(record.ID): encode(interruptedIntent), "jobs/" + record.ID: encode(interrupted)}}
	if err := validateOperationStateTransitions(pendingDocument, interruptedDocument); err != nil {
		t.Fatalf("interrupted retirement transition rejected: %v", err)
	}
	terminal, err := jobs.Finish(running, jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{{Kind: "goaccess_prior_retirement", Status: jobs.PostconditionVerified, Identity: "2:" + testDigest("service")}}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	terminalIntent := intent
	terminalIntent.Phase = PhaseTerminal
	terminalInstallation := pendingInstallation
	terminalInstallation.Resources = append([]domain.AppResource(nil), pendingInstallation.Resources...)
	terminalInstallation.Resources[0].PublicationRecord.LastOperationResult = domain.OperationSucceeded
	clearGoAccessRetirementAuthority(&terminalInstallation.Resources[0].PublicationRecord)
	terminalDocument := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 3, Entries: map[string]json.RawMessage{"installations/current": encode(terminalInstallation), reservationKey(record.ID): encode(terminalIntent), "jobs/" + record.ID: encode(terminal)}}
	if err := validateOperationStateTransitions(pendingDocument, terminalDocument); err != nil {
		t.Fatalf("terminal retirement transition rejected: %v", err)
	}
}

func operationUnitIdentities(label string) []string {
	return []string{testDigest(label + "-1"), testDigest(label + "-2"), testDigest(label + "-3"), testDigest(label + "-4"), testDigest(label + "-5")}
}

func domainBundleForRetirement(configDigest string) domain.PublicationBundle {
	return domain.PublicationBundle{ID: "pub_2_00000000000000000000000000000001", Generation: 2, ConfigDigest: configDigest, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: "endpoint", SiteIdentity: "site", ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 80}, {Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.com"}, Certificate: operationCertificateIdentity(), Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, Static: domain.StaticBundleIdentity{Routes: []domain.StaticRouteBundleIdentity{}, RouteIdentities: []string{}}, GoAccess: domain.GoAccessBundleIdentity{RetiredGeneration: 2, RetiredStateGeneration: 2, RetiredServiceIdentity: testDigest("service"), RetiredUnitIdentities: operationUnitIdentities("service")}}}
}

func operationCertificateIdentity() domain.CertificateBundleIdentity {
	const certificateID = "cert_00000000000000000000000000000000"
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: testDigest("account-key"), AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}}
	bindingIdentity, err := acme.BindingDigest(binding)
	if err != nil {
		panic(err)
	}
	san := sha256.Sum256([]byte("app.example.com"))
	authority := &domain.CertificateAuthorityIdentity{CertificateID: certificateID, DirectoryURL: binding.DirectoryURL, AccountKeyPath: binding.AccountKeyPath, AccountKeyFingerprint: binding.AccountKeyFingerprint, AccountEmail: binding.AccountEmail, TermsAccepted: binding.TermsAccepted, Method: string(binding.Method), CredentialFiles: []domain.CertificateCredentialIdentity{}}
	return domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/" + certificateID + ".current", BindingIdentity: bindingIdentity, Generation: 1, Fingerprint: testDigest("cert"), SANIdentity: "sha256:" + hex.EncodeToString(san[:]), ChainIdentity: testDigest("chain"), IssuerIdentity: testDigest("issuer"), NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", Authority: authority}
}

func TestCommittedPublicationCanContractWithoutRewritingTerminalJob(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	installation := operationStateInstallation()
	resource := &installation.Resources[0]
	resource.PublicationRecord.State = domain.PublicationPublished
	bundle := domain.PublicationBundle{Generation: 1, ID: "bundle", ConfigDigest: resource.CurrentConfigDigest, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: "endpoint", SiteIdentity: "site", ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 80}, {Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.com"}, Certificate: operationCertificateIdentity(), Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, Static: domain.StaticBundleIdentity{Routes: []domain.StaticRouteBundleIdentity{}, RouteIdentities: []string{}}, GoAccess: domain.GoAccessBundleIdentity{Enabled: false}}}
	resource.PublicationRecord.LastAppliedDigest = &bundle.ConfigDigest
	resource.PublicationRecord.LastAppliedBundle = &bundle
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(Publish), Target: "resource/" + resource.ID, ActorIdentity: "ui/session"}, now, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	running, _ := jobs.Start(record)
	terminal, err := jobs.Finish(running, jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: testDigest("runtime")}}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	resource.PublicationRecord.LastOperation = domain.OperationPublish
	resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
	resource.PublicationRecord.LastJobID = terminal.ID
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: terminal.ID, PlanID: "plan-one", AdmissionSource: AdmissionPlan, Operation: Publish, Target: "resource/" + resource.ID, Phase: PhaseTerminal, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{ResourceID: resource.ID}, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionPlan, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	encode := func(value any) json.RawMessage {
		raw, err := persist.EncodeEntry(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{"installations/current": encode(installation), reservationKey(terminal.ID): encode(intent), "jobs/" + terminal.ID: encode(terminal)}}
	afterInstallation := installation
	afterInstallation.Resources = append([]domain.AppResource(nil), installation.Resources...)
	afterInstallation.Resources[0].PublicationRecord.State = domain.PublicationUnpublished
	afterInstallation.Resources[0].PublicationRecord.UnpublishedGeneration = 3
	afterInstallation.Resources[0].PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: now.Add(2 * time.Second).Format(time.RFC3339), Reason: "committed_activation_recovery_contracted"}
	after := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 2, Entries: map[string]json.RawMessage{"installations/current": encode(afterInstallation), reservationKey(terminal.ID): encode(intent), "jobs/" + terminal.ID: encode(terminal)}}
	if err := validateOperationStateTransitions(before, after); err != nil {
		t.Fatal(err)
	}
}

func TestPlanBoundCertificateChallengeStartsAcrossMatchingBaseMarker(t *testing.T) {
	state := safety.State{GlobalClose: safety.GlobalClose{Phase: safety.GlobalCloseNone}, Resources: []safety.ResourceSafety{{ResourceID: "res_00000000000000000000000000000001", State: safety.ResourceActive, Ownership: safety.OwnershipOwned, StickyUnpublished: &safety.GenerationMarker{Generation: 3}}}}
	binding := SafetyBinding{ResourceID: state.Resources[0].ResourceID, PlanID: "plan_0000000000000000000000000000000", IntentGeneration: 4, CandidateDigest: testDigest("san"), CandidateBundle: testDigest("acme"), ChallengeMethod: "http-01", CertificateIdentity: "cert_00000000000000000000000000000000", Deadline: time.Now().UTC().Add(time.Hour)}
	if err := authorize(Publish, state, binding, true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	ordinary := binding
	ordinary.ChallengeMethod = ""
	ordinary.CertificateIdentity = ""
	if err := authorize(Publish, state, ordinary, true, time.Now().UTC()); err == nil {
		t.Fatal("ordinary publish crossed sticky marker")
	}
}

func TestCertificatePublicationHandoffTransitionIsExact(t *testing.T) {
	old := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: "job_00000000000000000000000000000000", PlanID: "plan_0000000000000000000000000000000", OperationBinding: testDigest("acme"), JournalSafetyDigest: testDigest("challenge-safety"), AdmissionSource: AdmissionPlan, Operation: Publish, Target: "resource/res_00000000000000000000000000000001", Phase: PhaseReentered, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{ResourceID: "res_00000000000000000000000000000001", PlanID: "plan_0000000000000000000000000000000", IntentGeneration: 2, CandidateDigest: testDigest("san"), CandidateBundle: testDigest("acme"), Deadline: time.Now().UTC().Add(time.Hour)}, CreatedAt: time.Now().UTC(), IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionPlan, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: time.Now().UTC(), SafetyDigest: testDigest("safety")}}
	next := old
	next.Phase = PhaseLocalIntent
	next.SafetyBinding.CandidateDigest = testDigest("config")
	next.SafetyBinding.CandidateBundle = testDigest("bundle")
	next.CertificateHandoff = &CertificatePublicationHandoff{PlanID: old.PlanID, Generation: 2, SANIdentity: testDigest("san"), ACMEBinding: testDigest("acme"), CertificateID: "cert_00000000000000000000000000000000", Fingerprint: testDigest("fingerprint"), ChallengeSafetyDigest: old.JournalSafetyDigest}
	next.JournalSafetyDigest, _ = safetyBindingDigest(next.SafetyBinding)
	encode := func(value Reservation) json.RawMessage {
		raw, err := persist.EncodeEntry(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if err := validateIntentTransition("", encode(old), encode(next)); err != nil {
		t.Fatal(err)
	}
	changed := next
	changed.Target = "resource/res_00000000000000000000000000000002"
	if err := validateIntentTransition("", encode(old), encode(changed)); err == nil {
		t.Fatal("rewritten certificate handoff accepted")
	}
}

func TestInterruptedCertificateRemoteWaitTerminalizesOnlyAfterContraction(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	installation := operationStateInstallation()
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(CertificateRenew), Target: "resource/" + installation.Resources[0].ID, ActorIdentity: "timer/certificate-renewal"}, now, bytes.NewReader(bytes.Repeat([]byte{8}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	running, _ := jobs.Start(record)
	terminal, err := jobs.Finish(running, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "certificate_provider_result", Status: jobs.PostconditionUnobserved, Identity: testDigest("closed")}}, ErrorCode: "certificate_executor_interrupted"}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, AdmissionSource: AdmissionTimer, Operation: CertificateRenew, Target: "resource/" + installation.Resources[0].ID, Phase: PhaseRemoteWait, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{ResourceID: installation.Resources[0].ID, PlanID: "cert_00000000000000000000000000000000", IntentGeneration: 2, CandidateDigest: testDigest("san"), CandidateBundle: testDigest("binding"), Deadline: now.Add(time.Hour)}, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionTimer, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	terminalIntent := intent
	terminalIntent.Phase = PhaseTerminal
	child := ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "lego-" + record.ID, JobID: record.ID, InstallationID: installation.InstallationID, Operation: CertificateRenew, Target: intent.Target, IntentGeneration: 2, Profile: "lego", InputDigest: testDigest("binding"), ArtifactDigest: testDigest("binding"), Deadline: intent.SafetyBinding.Deadline, State: ChildSubmitted, SubmittedAt: now}
	terminalChild := child
	terminalChild.State = ChildTerminal
	terminalChild.Outcome = ChildUnknown
	terminalChild.TerminalAt = pointerTime(now.Add(time.Second))
	terminalChild.ResultDigest = testDigest("closed")
	journal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "certificate-" + record.ID, JobID: record.ID, Kind: JournalCertificateActivation, Operation: CertificateRenew, InstallationID: installation.InstallationID, Target: intent.Target, Generation: 2, Deadline: intent.SafetyBinding.Deadline, ArtifactDigest: testDigest("binding"), SafetyMarkerDigest: testDigest("marker"), ResourceIDs: []string{installation.Resources[0].ID}, ChildIDs: []string{child.ID}, Phase: JournalPrepared, Certificate: &CertificateJournalIdentity{CertificateID: "cert_00000000000000000000000000000000", PriorGeneration: 1, CandidateGeneration: 2, PriorPointer: "/var/lib/lanpanel/certificates/bundles/cert_00000000000000000000000000000000-00000000000000000001", CandidatePointer: "/var/lib/lanpanel/certificates/bundles/cert_00000000000000000000000000000000-00000000000000000002", PriorFingerprint: testDigest("prior"), StageUID: 1200, StageGID: 1200}}
	terminalJournal := journal
	terminalJournal.Phase = JournalTerminal
	encode := func(value any) json.RawMessage {
		raw, err := persist.EncodeEntry(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{"installations/current": encode(installation), "jobs/" + record.ID: encode(running), reservationKey(record.ID): encode(intent), "children/" + child.ID: encode(child), "journals/" + journal.ID: encode(journal)}}
	after := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 2, Entries: map[string]json.RawMessage{"installations/current": encode(installation), "jobs/" + record.ID: encode(terminal), reservationKey(record.ID): encode(terminalIntent), "children/" + child.ID: encode(terminalChild), "journals/" + journal.ID: encode(terminalJournal)}}
	if err := validateOperationStateTransitions(before, after); err != nil {
		t.Fatal(err)
	}
}
func pointerTime(value time.Time) *time.Time { return &value }
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
	registry, err := NewRegistry([]Registration{{Operation: Publish, Owner: "publication", Results: table}, {Operation: CertificateExpiry, Owner: "certificate-expiry", Results: table}, {Operation: AutomaticReconciliation, Owner: "startup-recovery", Results: table}})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestExactHeadscaleCertificateChallengeAuthority(t *testing.T) {
	binding := SafetyBinding{ResourceID: "headscale", PlanID: "plan_00000000000000000000000000000001", IntentGeneration: 1, CandidateDigest: testDigest("san"), CandidateBundle: testDigest("acme"), CertificateIdentity: "cert_00000000000000000000000000000001"}
	state := safety.EmptyState()
	state.Headscale.ChallengePending = &safety.ChallengePending{Generation: 1, PlanID: binding.PlanID, ConfigDigest: testDigest("config"), SANIdentity: binding.CandidateDigest, ACMEBinding: binding.CandidateBundle, CertificateIdentity: binding.CertificateIdentity}
	if !exactCertificateChallenge(state, CertificateRenew, binding) {
		t.Fatal("exact Headscale renewal challenge rejected")
	}
	deploy := binding
	deploy.CandidateDigest = state.Headscale.ChallengePending.ConfigDigest
	deploy.CandidateBundle = testDigest("control-bundle")
	deploy.ACMEBinding = state.Headscale.ChallengePending.ACMEBinding
	if !exactCertificateChallenge(state, HeadscaleDeploy, deploy) {
		t.Fatal("exact Headscale deploy challenge rejected")
	}
	deploy.ACMEBinding = testDigest("other-acme")
	if exactCertificateChallenge(state, HeadscaleDeploy, deploy) {
		t.Fatal("mismatched Headscale deploy ACME binding accepted")
	}
	state.Headscale.ChallengePending.CertificateIdentity = "cert_11111111111111111111111111111111"
	if exactCertificateChallenge(state, CertificateRenew, binding) {
		t.Fatal("mismatched Headscale challenge accepted")
	}
}

func TestExactAppCertificateChallengeBindsCertificateIdentity(t *testing.T) {
	binding := SafetyBinding{ResourceID: "res_00000000000000000000000000000001", PlanID: "plan_00000000000000000000000000000001", IntentGeneration: 1, CandidateDigest: testDigest("san"), CandidateBundle: testDigest("acme"), CertificateIdentity: "cert_00000000000000000000000000000001"}
	state := openSafetyState()
	state.Resources[0].ChallengePending = &safety.ChallengePending{Generation: 1, PlanID: binding.PlanID, SANIdentity: binding.CandidateDigest, ACMEBinding: binding.CandidateBundle, CertificateIdentity: binding.CertificateIdentity}
	if !exactCertificateChallenge(state, Publish, binding) {
		t.Fatal("exact App challenge rejected")
	}
	state.Resources[0].ChallengePending.CertificateIdentity = "cert_11111111111111111111111111111111"
	if exactCertificateChallenge(state, Publish, binding) {
		t.Fatal("App challenge with another certificate identity accepted")
	}
}

func TestHeadscaleRemoteWaitCanResumeSameDurableUIJob(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	normal, manager, admission, mutationSet := newOperationStores(t)
	defer func(ignore func() error) { _ = ignore() }(normal.Close)
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	defer func(ignore func() error) { _ = ignore() }(manager.Close)
	table, err := NewBranchTable([]ResultBranch{{"complete", jobs.ResultSucceeded, jobs.PostconditionVerified}, {"no_effect", jobs.ResultFailed, jobs.PostconditionVerified}, {"known_residual", jobs.ResultPartial, jobs.PostconditionKnown}, {"executor_died", jobs.ResultInterrupted, jobs.PostconditionKnown}, {"source_unknown", jobs.ResultUnknown, jobs.PostconditionUnobserved}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Registration{{Operation: HeadscaleInitialize, Owner: "headscale", Results: table}})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := NewAdmitter(normal, &fakeSafety{state: openSafetyState(), authority: manager.Authority()}, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 64)), Bindings: trustedBindings{}, Confirmation: testConfirmation{}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	document, _ := normal.Read()
	candidate := domain.HeadscaleDomain{ID: "hds_00000000000000000000000000000001", ControlDomain: "control.example.test", MagicDNSNamespace: "mesh.example.test", Policy: "trusted_mesh", Artifact: domain.HeadscaleArtifactIdentity{BaselineDigest: testDigest("baseline"), Version: "0.25.1", ArchiveDigest: testDigest("archive"), ExecutableDigest: testDigest("executable"), ConfigContract: "headscale-trusted-mesh-v1", ConfigContractDigest: testDigest("contract")}, Database: domain.HeadscaleDatabaseIdentity{UUID: "hdb_00000000000000000000000000000001", SQLitePath: "/var/lib/lanpanel/headscale-runtime/db.sqlite", Generation: 1, Phase: domain.HeadscaleIdentityCommitted}, DesiredDigest: testDigest("config"), ManagedPaths: domain.HeadscaleManagedPaths()}
	snapshot := managedheadscale.IdentitySnapshot{SchemaVersion: managedheadscale.IdentitySnapshotSchema, InstallationID: "ins_00000000000000000000000000000001", HeadscaleID: candidate.ID, ControlDomain: candidate.ControlDomain, MagicDNSNamespace: candidate.MagicDNSNamespace, Policy: candidate.Policy, Artifact: candidate.Artifact, DatabaseUUID: candidate.Database.UUID, SQLitePath: candidate.Database.SQLitePath, DatabaseGeneration: candidate.Database.Generation, DesiredConfigDigest: candidate.DesiredDigest}
	snapshotBytes, _ := json.Marshal(snapshot)
	candidate.Database.IdentityBundleDigest = testDigestBytes(snapshotBytes)
	snapshot.Artifact = candidate.Artifact
	snapshotBytes, _ = json.Marshal(snapshot)
	source := sources.Source{Kind: sources.OfficialCanonical, URL: "https://downloads.example.test/headscale.tar.gz", OfficialAuthorities: []string{"downloads.example.test"}, Artifact: sources.Artifact{Name: "headscale", Version: candidate.Artifact.Version, OperatingOS: "linux", Architecture: "amd64", Digest: strings.TrimPrefix(candidate.Artifact.ArchiveDigest, "sha256:")}}
	preflightRequest := preflight.ExpansionRequest{Scope: preflight.ExpansionHeadscale, Target: "headscale", Generation: 1, Profile: preflight.ExpectedProfile{ID: "debian", VersionID: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: testDigest("packages"), ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8"}, QualificationDigest: testDigest("confinement")}, Authority: preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: testDigest("profile"), LiveQualified: true}}, Domains: []string{candidate.ControlDomain}, Disks: []preflight.DiskRequirement{{Path: "/var/lib/lanpanel", MinimumAvailableBytes: 1}}, LastTrustedWall: now.Add(-time.Second)}
	preflightResult, err := preflight.EvaluateExpansion(preflightRequest, preflight.ExpansionObservations{OperatingSystem: "linux", Architecture: "amd64", Platform: preflight.PlatformInfo{ID: "debian", VersionID: "13"}, Clock: preflight.ClockObservation{Now: now, Synchronized: true, Source: "kernel"}, ExecutorUID: 0, Systemd: preflight.ComponentObservation{Available: true, Identity: "systemd/1"}, APT: preflight.ComponentObservation{Available: true, Identity: "apt/1"}, DPKG: preflight.ComponentObservation{Available: true, Identity: "dpkg/1"}, Packages: preflight.PackageObservation{Ready: true, Identity: testDigest("package-observation"), SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: testDigest("packages")}, DNS: []preflight.DNSObservation{{Domain: candidate.ControlDomain, Addresses: []string{"8.8.8.8"}}}, ListenerInventoryComplete: true, Disks: []preflight.DiskObservation{{Path: "/var/lib/lanpanel", Device: 1, AvailableBytes: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	job, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: HeadscaleInitialize, Target: "installation", ActorIdentity: "ui/session/generation/1", Source: AdmissionUI, SafetyBinding: SafetyBinding{CandidateDigest: candidate.DesiredDigest, CandidateBundle: candidate.Artifact.ArchiveDigest}, HeadscaleBinding: &HeadscaleInitializationBinding{Candidate: candidate, Snapshot: snapshotBytes, Source: source, PreflightRequest: preflightRequest, PreflightResult: preflightResult}, ExpectedRevision: document.Revision})
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
	document, _ = normal.Read()
	intent, err := admitter.BeginUI(context.Background(), mutation, exposure, ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.EnterRemoteWait(context.Background(), mutation, exposure, intent.IntentGeneration, job.ID); err != nil {
		t.Fatal(err)
	}
	document, _ = normal.Read()
	_, mutation, exposure, err = admitter.Reenter(context.Background(), mutationSet, manager, document.Revision, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	document, _ = normal.Read()
	if _, err := admitter.EnterRemoteWait(context.Background(), mutation, exposure, document.Revision, job.ID); err != nil {
		t.Fatalf("same durable job could not resume acquisition: %v", err)
	}
	resumed, err := admitter.OperationIntent(job.ID)
	if err != nil || resumed.Phase != PhaseRemoteWait {
		t.Fatalf("resumed intent=%#v error=%v", resumed, err)
	}
}

func operationPlanSpec(now time.Time) plans.Spec {
	return plans.Spec{Operation: "publish", Target: plans.Target{Kind: plans.TargetResource, ID: "res_00000000000000000000000000000001"}, ActorIdentity: "session-one", Config: plans.DigestBinding{Applicable: true, Digest: testDigest("config")}, Applied: plans.DigestBinding{Applicable: true, Digest: testDigest("applied")}, Evidence: []plans.Evidence{
		{Kind: "config", Identity: "res_00000000000000000000000000000001", Generation: 1, Digest: testDigest("evidence"), ObservedAt: now},
		{Kind: preflight.ExpansionEvidencePrefix + string(preflight.ExpansionDomainHTTPS), Identity: "resource/res_00000000000000000000000000000001", Generation: 1, Digest: testDigest("preflight"), ObservedAt: now},
	}, ExposureSummary: "expands_ingress", Prerequisites: "qualified"}
}

func testDigestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
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

func TestHeadscaleRenewalAdmissionAndChallengeBindingAreExact(t *testing.T) {
	if err := validateAdmissionSource(CertificateRenew, AdmissionPlan, "plan_renew"); err != nil {
		t.Fatal(err)
	}
	state := safety.EmptyState()
	state.Headscale.GenerationSequence = 7
	state.Headscale.ChallengePending = &safety.ChallengePending{Generation: 7, PlanID: "plan_renew", Method: "http-01", ConfigDigest: testDigest("config"), SANIdentity: testDigest("san"), ACMEBinding: testDigest("binding"), CertificateIdentity: "cert_00000000000000000000000000000001", Host: "control.example.test", Hosts: []string{"control.example.test"}, TokenPath: "/.well-known/acme-challenge", Webroot: "/var/lib/lanpanel/certificates/webroot/cert_00000000000000000000000000000001", BootstrapIdentity: testDigest("bootstrap"), BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}}
	binding := SafetyBinding{ResourceID: "headscale", PlanID: "plan_renew", IntentGeneration: 7, CandidateDigest: testDigest("san"), CandidateBundle: testDigest("binding"), CertificateIdentity: state.Headscale.ChallengePending.CertificateIdentity}
	if !exactCertificateChallenge(state, CertificateRenew, binding) {
		t.Fatal("exact Headscale renewal challenge binding rejected")
	}
	binding.CandidateBundle = testDigest("other")
	if exactCertificateChallenge(state, CertificateRenew, binding) {
		t.Fatal("changed Headscale renewal binding accepted")
	}
}

func TestHeadscaleCertificateExpiryProposalUsesIndependentActiveAuthority(t *testing.T) {
	now := time.Now().UTC()
	state := safety.EmptyState()
	state.Headscale.GenerationSequence = 3
	state.Headscale.ControlEntryDigest = testDigest("control")
	state.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 2, Fingerprint: testDigest("certificate"), Binding: "binding", LastTrustedWall: now.Add(-time.Hour), NotAfter: now}
	binding := SafetyBinding{ResourceID: "headscale", ExpiryGeneration: 4, Deadline: now, CandidateBundle: "binding"}
	if !validExpiryProposal(CertificateExpiry, state, binding, now) {
		t.Fatal("first Headscale certificate expiry proposal rejected")
	}
	binding.ExpiryGeneration++
	if validExpiryProposal(CertificateExpiry, state, binding, now) {
		t.Fatal("stale Headscale expiry generation accepted")
	}
}

func TestNewResourceAuthorityMatchesTargetManagedProcessContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	candidate := tailnetOperationResource()
	record, err := jobs.NewReserved(jobs.Spec{Operation: string(ResourceCreate), Target: "installation", ActorIdentity: "ui/session/generation/1"}, now, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	running, err := jobs.Start(record)
	if err != nil {
		t.Fatal(err)
	}
	intent := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, AdmissionSource: AdmissionUI, Operation: ResourceCreate, Target: "installation", Phase: PhaseLocalIntent, SafetyDigest: testDigest("safety"), SafetyBinding: SafetyBinding{ResourceID: candidate.ID}, CreatedAt: now, IntentGeneration: 2, Consumption: &ConsumptionSnapshot{Source: AdmissionUI, ConfirmationDigest: testDigest("confirmation"), ConfirmedAt: now, SafetyDigest: testDigest("safety")}}
	encode := func(value any) json.RawMessage {
		raw, encodeErr := persist.EncodeEntry(value)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return raw
	}
	document := persist.Document{SchemaVersion: persist.SchemaVersion, Revision: 1, Entries: map[string]json.RawMessage{reservationKey(record.ID): encode(intent), "jobs/" + record.ID: encode(running)}}

	local := operationStateInstallation().Resources[0]
	local.PublicationRecord = domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}
	local.CurrentConfigDigest = candidate.CurrentConfigDigest
	cases := []struct {
		name      string
		resource  domain.AppResource
		wantError bool
	}{
		{name: "tailnet_without_process", resource: candidate},
		{name: "tailnet_with_process", resource: func() domain.AppResource {
			value := candidate
			value.ManagedProcess = &domain.ManagedProcess{Requested: domain.ProcessRequestedStopped}
			return value
		}(), wantError: true},
		{name: "local_with_process", resource: local},
		{name: "local_without_process", resource: func() domain.AppResource {
			value := local
			value.ManagedProcess = nil
			return value
		}(), wantError: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := validateNewResourceAuthority(document, test.resource)
			if (err != nil) != test.wantError {
				t.Fatalf("validateNewResourceAuthority() error=%v wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestResourceUpdateDeltaMatchesTargetManagedProcessContract(t *testing.T) {
	tailnet := tailnetOperationResource()
	updatedTailnet := tailnet
	updatedTailnet.Name = "Peer Updated"
	if err := validateOperationResourceDelta(tailnet, updatedTailnet, ResourceUpdate); err != nil {
		t.Fatalf("Tailnet update rejected: %v", err)
	}

	withProcess := updatedTailnet
	withProcess.ManagedProcess = &domain.ManagedProcess{Requested: domain.ProcessRequestedStopped}
	if err := validateOperationResourceDelta(tailnet, withProcess, ResourceUpdate); err == nil {
		t.Fatal("Tailnet update carrying managed process accepted")
	}

	local := operationStateInstallation().Resources[0]
	local.ManagedProcess.Applied = operationProcessBundle(local.CurrentConfigDigest)
	local.ManagedProcess.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeHealthy, ObservedAt: "2025-01-01T00:00:00Z", Reason: "observed"}
	updatedLocal := local
	process := *local.ManagedProcess
	process.Service.Arguments = []string{"--updated"}
	updatedLocal.ManagedProcess = &process
	updatedLocal.Name = "Local Updated"
	if err := validateOperationResourceDelta(local, updatedLocal, ResourceUpdate); err != nil {
		t.Fatalf("Local update preserving process state rejected: %v", err)
	}
	changedRequested := updatedLocal
	changedProcess := *updatedLocal.ManagedProcess
	changedProcess.Requested = domain.ProcessRequestedRunning
	changedRequested.ManagedProcess = &changedProcess
	if err := validateOperationResourceDelta(local, changedRequested, ResourceUpdate); err == nil {
		t.Fatal("Local update changed requested process state")
	}
	for _, test := range []struct {
		name   string
		mutate func(*domain.ManagedProcess)
	}{
		{name: "process_id", mutate: func(value *domain.ManagedProcess) { value.ID = "proc_11111111111111111111111111111111" }},
		{name: "last_operation", mutate: func(value *domain.ManagedProcess) { value.LastOperation = domain.OperationProcessStart }},
		{name: "last_operation_result", mutate: func(value *domain.ManagedProcess) { value.LastOperationResult = domain.OperationFailed }},
		{name: "last_job_id", mutate: func(value *domain.ManagedProcess) { value.LastJobID = "job_changed" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := updatedLocal
			process := *updatedLocal.ManagedProcess
			test.mutate(&process)
			changed.ManagedProcess = &process
			if err := validateOperationResourceDelta(local, changed, ResourceUpdate); err == nil {
				t.Fatal("Local update changed protected process operation state")
			}
		})
	}

	withoutProcess := local
	withoutProcess.ManagedProcess = nil
	if err := validateOperationResourceDelta(local, withoutProcess, ResourceUpdate); err == nil {
		t.Fatal("Local update without managed process accepted")
	}

	switched := tailnet
	switched.Target = local.Target
	switched.ManagedProcess = local.ManagedProcess
	if err := validateOperationResourceDelta(tailnet, switched, ResourceUpdate); err == nil {
		t.Fatal("resource update switched target kind")
	}
}

func TestTailnetResourceCreateCommitsReservationOwnershipSafetyAndNormal(t *testing.T) {
	runTailnetResourceCreate(t)
}

func TestTailnetResourceUpdatePreservesAbsentManagedProcess(t *testing.T) {
	runTailnetResourceUpdate(t)
}

func TestLocalResourceUpdatePreservesManagedRuntimeState(t *testing.T) {
	installation := operationStateInstallation()
	prior := &installation.Resources[0]
	prior.ManagedProcess.Applied = operationProcessBundle(prior.CurrentConfigDigest)
	prior.ManagedProcess.LastOperation = domain.OperationProcessStop
	prior.ManagedProcess.LastOperationResult = domain.OperationSucceeded
	prior.ManagedProcess.LastJobID = "job_prior_process"
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: prior.ID, GenerationSequence: 1, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("local-ownership"), StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: prior.PublicationRecord.UnpublishedGeneration, Reason: "initial"}}}
	candidate := *prior
	process := *prior.ManagedProcess
	process.Requested = domain.ProcessRequestedRunning
	process.Applied = nil
	process.RuntimeObservation = nil
	process.LastOperation = ""
	process.LastOperationResult = ""
	process.LastJobID = ""
	process.Service.Arguments = []string{"--updated"}
	candidate.ManagedProcess = &process
	candidate.Name = "Local Updated"
	candidate.CurrentConfigDigest = testDigest("local-update-candidate")
	harness := beginResourceOperation(t, ResourceUpdate, installation, &state, SafetyBinding{ResourceID: prior.ID, CandidateDigest: candidate.CurrentConfigDigest, CandidateBundle: prior.CurrentConfigDigest})
	if err := harness.admitter.CommitResourceUpdate(context.Background(), harness.mutation, harness.exposure, harness.revision, harness.jobID, candidate); err != nil {
		t.Fatal(err)
	}
	harness.revision++
	if _, err := harness.admitter.Complete(context.Background(), harness.mutation, harness.exposure, harness.revision, harness.jobID, "complete", nil, []jobs.Postcondition{{Kind: "resource_config_saved", Status: jobs.PostconditionVerified, Identity: candidate.CurrentConfigDigest}}, ""); err != nil {
		t.Fatal(err)
	}
	updated := readOperationResource(t, harness.normal, prior.ID)
	if updated.ManagedProcess == nil || !reflect.DeepEqual(updated.ManagedProcess.Service.Arguments, []string{"--updated"}) || updated.ManagedProcess.Requested != prior.ManagedProcess.Requested || !reflect.DeepEqual(updated.ManagedProcess.Applied, prior.ManagedProcess.Applied) || !reflect.DeepEqual(updated.ManagedProcess.RuntimeObservation, prior.ManagedProcess.RuntimeObservation) || updated.ManagedProcess.LastOperation != prior.ManagedProcess.LastOperation || updated.ManagedProcess.LastOperationResult != prior.ManagedProcess.LastOperationResult || updated.ManagedProcess.LastJobID != prior.ManagedProcess.LastJobID {
		t.Fatalf("prior process=%#v updated process=%#v", prior.ManagedProcess, updated.ManagedProcess)
	}
}

func runTailnetResourceCreate(t *testing.T) {
	t.Helper()
	candidate := tailnetOperationResource()
	installation := tailnetOperationInstallation(nil)
	state := safety.EmptyState()
	harness := beginResourceOperation(t, ResourceCreate, installation, &state, SafetyBinding{ResourceID: candidate.ID})

	ownershipDigest := testDigest("tailnet-ownership")
	state.Resources = []safety.ResourceSafety{{ResourceID: candidate.ID, GenerationSequence: 1, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: ownershipDigest, StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 1, Reason: "initial"}}}
	harness.safety.state = state
	if state.Resources[0].OwnershipDigest != ownershipDigest || state.Resources[0].StickyUnpublished == nil {
		t.Fatal("ownership and safety authority were not committed before normal authority")
	}
	if err := harness.admitter.CommitResourceCreate(context.Background(), harness.mutation, harness.exposure, harness.revision, harness.jobID, ResourceCreateCommit{Resource: candidate}); err != nil {
		t.Fatal(err)
	}
	harness.revision++
	job, err := harness.admitter.Complete(context.Background(), harness.mutation, harness.exposure, harness.revision, harness.jobID, "complete", nil, []jobs.Postcondition{{Kind: "resource_persisted_unpublished_stopped", Status: jobs.PostconditionVerified, Identity: candidate.CurrentConfigDigest}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if job.Result != jobs.ResultSucceeded {
		t.Fatalf("resource create job=%#v", job)
	}
	created := readOperationResource(t, harness.normal, candidate.ID)
	if created.ManagedProcess != nil || created.Target.Kind != domain.AppTargetTailnetHTTP || created.PublicationRecord.LastOperation != domain.OperationResourceCreate {
		t.Fatalf("created Tailnet resource=%#v", created)
	}
}

func runTailnetResourceUpdate(t *testing.T) {
	t.Helper()
	prior := tailnetOperationResource()
	installation := tailnetOperationInstallation(&prior)
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: prior.ID, GenerationSequence: 1, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("tailnet-ownership"), StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 1, Reason: "initial"}}}
	candidate := prior
	candidate.Name = "Peer Updated"
	candidate.Target.TailnetHTTP = &domain.TailnetHTTPTarget{IP: "100.64.0.3", SourceIP: "100.64.0.1", Port: 8081}
	candidate.CurrentConfigDigest = testDigest("tailnet-update-candidate")
	harness := beginResourceOperation(t, ResourceUpdate, installation, &state, SafetyBinding{ResourceID: prior.ID, CandidateDigest: candidate.CurrentConfigDigest, CandidateBundle: prior.CurrentConfigDigest})

	if err := harness.admitter.CommitResourceUpdate(context.Background(), harness.mutation, harness.exposure, harness.revision, harness.jobID, candidate); err != nil {
		t.Fatal(err)
	}
	harness.revision++
	job, err := harness.admitter.Complete(context.Background(), harness.mutation, harness.exposure, harness.revision, harness.jobID, "complete", nil, []jobs.Postcondition{{Kind: "resource_config_saved", Status: jobs.PostconditionVerified, Identity: candidate.CurrentConfigDigest}}, "")
	if err != nil {
		t.Fatal(err)
	}
	updated := readOperationResource(t, harness.normal, prior.ID)
	if job.Result != jobs.ResultSucceeded || updated.ManagedProcess != nil || updated.Name != candidate.Name || !reflect.DeepEqual(updated.Target, candidate.Target) || updated.PublicationRecord.LastOperation != domain.OperationResourceUpdate {
		t.Fatalf("job=%#v updated=%#v", job, updated)
	}
}

type resourceOperationHarness struct {
	normal      *persist.Store
	manager     *locks.Manager
	mutationSet *MutationSet
	safety      *fakeSafety
	admitter    *Admitter
	mutation    *MutationLease
	exposure    *locks.Lease
	jobID       string
	revision    uint64
}

func beginResourceOperation(t *testing.T, operation Type, installation domain.Installation, state *safety.State, binding SafetyBinding) *resourceOperationHarness {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	normal, manager, admission, mutationSet := newOperationStores(t)
	safetyStore := &fakeSafety{state: *state, authority: manager.Authority()}
	admitter := newResourceOperationAdmitter(t, normal, safetyStore, now)
	raw, err := persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := normal.Update(context.Background(), admission, 1, func(transaction *persist.Transaction) error {
		return transaction.Create("installations/current", raw)
	}); err != nil {
		t.Fatal(err)
	}
	document, err := normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	target := "installation"
	if operation == ResourceUpdate {
		target = "resource/" + binding.ResourceID
	}
	job, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: operation, Target: target, ActorIdentity: "ui/session/generation/1", Source: AdmissionUI, SafetyBinding: binding, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		t.Fatal(errors.Join(err, releaseErr))
	}
	mutation, exposure, err := mutationSet.AcquireExposure(context.Background(), target, manager)
	if err != nil {
		t.Fatal(err)
	}
	document, err = normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	intent, err := admitter.BeginUI(context.Background(), mutation, exposure, ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1})
	if err != nil {
		t.Fatal(err)
	}
	harness := &resourceOperationHarness{normal: normal, manager: manager, mutationSet: mutationSet, safety: safetyStore, admitter: admitter, mutation: mutation, exposure: exposure, jobID: job.ID, revision: intent.IntentGeneration}
	t.Cleanup(func() {
		if harness.mutation != nil || harness.exposure != nil {
			_ = ReleaseExposure(harness.mutation, harness.exposure)
		}
		_ = harness.mutationSet.Close()
		_ = harness.normal.Close()
		_ = harness.manager.Close()
	})
	return harness
}

func newResourceOperationAdmitter(t *testing.T, normal *persist.Store, state *fakeSafety, now time.Time) *Admitter {
	t.Helper()
	table, err := NewBranchTable([]ResultBranch{{Name: "complete", Result: jobs.ResultSucceeded, Postcondition: jobs.PostconditionVerified}, {Name: "no_effect", Result: jobs.ResultFailed, Postcondition: jobs.PostconditionVerified}, {Name: "known_residual", Result: jobs.ResultPartial, Postcondition: jobs.PostconditionKnown}, {Name: "executor_died", Result: jobs.ResultInterrupted, Postcondition: jobs.PostconditionKnown}, {Name: "source_unknown", Result: jobs.ResultUnknown, Postcondition: jobs.PostconditionUnobserved}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Registration{{Operation: ResourceCreate, Owner: "resource", Results: table}, {Operation: ResourceUpdate, Owner: "resource", Results: table}})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := NewAdmitter(normal, state, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 256)), Bindings: trustedBindings{}, Confirmation: testConfirmation{}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	return admitter
}

func tailnetOperationInstallation(resource *domain.AppResource) domain.Installation {
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.23.45.67", Port: 23456}, Connector: &domain.TailnetConnector{ID: "con_00000000000000000000000000000001", ControlURL: "https://control.example.test", ManagedPaths: domain.ConnectorManagedPaths()}}
	if resource != nil {
		installation.Resources = []domain.AppResource{*resource}
	}
	return installation
}

func tailnetOperationResource() domain.AppResource {
	return domain.AppResource{ID: "res_00000000000000000000000000000001", Name: "Peer App", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: testDigest("tailnet-config"), Target: domain.AppTarget{Kind: domain.AppTargetTailnetHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, TailnetHTTP: &domain.TailnetHTTPTarget{IP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "peer.example.test", AccessMode: domain.AppAccessPublic}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}}
}

func operationProcessBundle(configDigest string) *domain.ProcessBundle {
	return &domain.ProcessBundle{Generation: 1, ConfigDigest: configDigest, UnitDigest: testDigest("unit"), SocketUnitDigest: testDigest("socket"), PolicyDigest: testDigest("policy"), AccountDigest: testDigest("account"), ExecutableDigest: testDigest("executable"), WorkingDirectoryIdentity: testDigest("working-directory"), Cgroup: "/sys/fs/cgroup/lanpanel-app", FrontendEndpoint: "/run/lanpanel/app.sock", EndpointSocketUnits: []string{"lanpanel-app.socket"}, ApplicationUID: 1000, ApplicationGID: 1000, FrontendGID: 33, FrontendMode: 0o660, ManagedPaths: []string{"/var/lib/lanpanel/resources/res_00000000000000000000000000000001"}}
}

func readOperationResource(t *testing.T, normal *persist.Store, resourceID string) domain.AppResource {
	t.Helper()
	document, err := normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range installation.Resources {
		if resource.ID == resourceID {
			return resource
		}
	}
	t.Fatalf("resource %q missing", resourceID)
	return domain.AppResource{}
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
