package operations

import (
	"bytes"
	"context"
	"errors"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
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
		admitter, _ := NewAdmitter(normal, safetyStore, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{2}, 64)), Bindings: trustedBindings{binding}, Confirmation: testConfirmation{}, Registry: testRegistry(t)})
		record, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/app-one", ActorIdentity: "session-one", PlanID: plan.ID, SafetyBinding: SafetyBinding{ResourceID: "app-one"}, ExpectedRevision: 2})
		if err != nil {
			t.Fatal(err)
		}
		if record.Status != jobs.StatusReserved {
			t.Fatalf("reserved job=%#v", record)
		}
		if _, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/app-one", ActorIdentity: "session-one", PlanID: plan.ID, SafetyBinding: SafetyBinding{ResourceID: "app-one"}, ExpectedRevision: 3}); err == nil {
			t.Fatal("one Plan reserved multiple jobs")
		}
		if err := admission.Release(); err != nil {
			t.Fatal(err)
		}
		reverse, err := manager.Acquire(context.Background(), locks.Exposure)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := mutation.AcquireExposure(context.Background(), "resource/app-one", manager); err == nil {
			t.Fatal("exposure-to-mutation reverse acquisition succeeded")
		}
		_ = reverse.Release()
		mutationLease, exposure, err := mutation.AcquireExposure(context.Background(), "resource/app-one", manager)
		if err != nil {
			t.Fatal(err)
		}
		intent, err := admitter.ConsumePlan(context.Background(), mutationLease, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 3, IntentGeneration: 1, ConfirmationProof: plan.NonceDigest})
		if err != nil {
			t.Fatal(err)
		}
		if intent.Phase != PhaseLocalIntent {
			t.Fatalf("intent=%#v", intent)
		}
		if _, err := admitter.ConsumePlan(context.Background(), mutationLease, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 4, IntentGeneration: 1, ConfirmationProof: plan.NonceDigest}); err == nil {
			t.Fatal("Plan/reservation consumed twice")
		}
		child := ChildRecord{SchemaVersion: "lanpanel.child.v1", ID: "child-one", JobID: record.ID, Profile: "provider", State: ChildSubmitted, SubmittedAt: now}
		if err := ReserveChild(context.Background(), normal, mutationLease, exposure, 4, child); err != nil {
			t.Fatal(err)
		}
		child.State = ChildRunning
		if err := TransitionChild(context.Background(), normal, mutationLease, exposure, 5, child); err != nil {
			t.Fatal(err)
		}
		journal := JournalRecord{SchemaVersion: "lanpanel.journal.v1", ID: "journal-one", JobID: record.ID, Kind: "provider", Generation: 1, Phase: JournalPrepared}
		if err := PutJournal(context.Background(), normal, mutationLease, exposure, 6, journal, true); err != nil {
			t.Fatal(err)
		}
		journal.Phase = JournalActive
		if err := PutJournal(context.Background(), normal, mutationLease, exposure, 7, journal, false); err != nil {
			t.Fatal(err)
		}
		if _, err := EnterRemoteWait(context.Background(), normal, mutationLease, exposure, 8, record.ID); err != nil {
			t.Fatal(err)
		}
		contraction, err := manager.Acquire(context.Background(), locks.Exposure)
		if err != nil {
			t.Fatalf("remote wait retained exposure lock: %v", err)
		}
		_ = contraction.Release()
		reentered, reentryMutation, reentryExposure, err := admitter.Reenter(context.Background(), mutation, manager, 9, record.ID)
		if err != nil || reentered.Phase != PhaseReentered {
			t.Fatalf("Reenter()=%#v,%v", reentered, err)
		}
		stamp := now.Add(time.Second)
		child.State = ChildTerminal
		child.TerminalAt = &stamp
		if err := TransitionChild(context.Background(), normal, reentryMutation, reentryExposure, 10, child); err != nil {
			t.Fatal(err)
		}
		journal.Phase = JournalTerminal
		if err := PutJournal(context.Background(), normal, reentryMutation, reentryExposure, 11, journal, false); err != nil {
			t.Fatal(err)
		}
		completed, err := admitter.Complete(context.Background(), reentryMutation, reentryExposure, 12, record.ID, "complete", nil, []jobs.Postcondition{{Kind: "published", Status: jobs.PostconditionVerified, Identity: "app-one"}}, "")
		if err != nil || completed.Result != jobs.ResultSucceeded {
			t.Fatalf("Complete()=%#v,%v", completed, err)
		}
		if _, _, err := normal.Update(context.Background(), reentryExposure, 13, func(transaction *persist.Transaction) error {
			rewritten := completed
			rewritten.Postconditions[0].Identity = "other"
			return jobs.Replace(transaction, rewritten)
		}); err == nil {
			t.Fatal("terminal job was rewritten through raw transaction")
		}
		if err := ReleaseExposure(reentryMutation, reentryExposure); err != nil {
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
		record, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/app-one", ActorIdentity: "session-one", PlanID: plan.ID, SafetyBinding: SafetyBinding{ResourceID: "app-one"}, ExpectedRevision: 2})
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
		record, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/app-one", ActorIdentity: "session-one", PlanID: plan.ID, SafetyBinding: SafetyBinding{ResourceID: "app-one"}, ExpectedRevision: 2})
		if err != nil {
			t.Fatal(err)
		}
		if err := admission.Release(); err != nil {
			t.Fatal(err)
		}
		clock = now.Add(11 * time.Minute)
		mutationLease, exposure, err := mutation.AcquireExposure(context.Background(), "resource/app-one", manager)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admitter.ConsumePlan(context.Background(), mutationLease, exposure, ConsumeRequest{JobID: record.ID, ExpectedRevision: 3, IntentGeneration: 1, ConfirmationProof: plan.NonceDigest}); err == nil {
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
		state.MaintenancePending = &safety.TransitionMarker{Generation: 1}
		if err := authorize(Repair, state, SafetyBinding{StopFenceKind: safety.StopFenceContraction, StopFenceGeneration: 7}, false, time.Now()); err != nil {
			t.Fatalf("exact maintenance stop-fence Repair binding rejected: %v", err)
		}
		if err := authorize(Repair, state, SafetyBinding{StopFenceKind: safety.StopFenceContraction, StopFenceGeneration: 8}, false, time.Now()); err == nil {
			t.Fatal("stale Repair binding accepted")
		}
		state = safety.EmptyState()
		state.DependencyTransitionPending = &safety.TransitionMarker{Generation: 3}
		deadline := time.Now().UTC().Add(-time.Minute)
		state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", CertificateExpiry: &safety.DeadlineMarker{Generation: 4, Deadline: deadline}}}
		if err := authorize(CertificateExpiry, state, SafetyBinding{DependencyGeneration: 3, ResourceID: "app-one", ExpiryKind: "certificate_expiry", ExpiryGeneration: 4, Deadline: deadline}, false, time.Now()); err != nil {
			t.Fatalf("deadline contraction exception rejected: %v", err)
		}
		if err := authorize(Publish, state, SafetyBinding{}, false, time.Now()); err == nil {
			t.Fatal("publish crossed dependency transition")
		}
		independent, _, independentManager := unavailableProof(t)
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
		if err := independent.AuthorizeStateIndependentContraction(CertificateExpiry, state, SafetyBinding{ResourceID: "app-one", ExpiryKind: "certificate_expiry", ExpiryGeneration: 4, Deadline: deadline}, fresh(), exposure, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		emergency := safety.EmptyState()
		if err := independent.AuthorizeStateIndependentContraction(EmergencyCloseAll, emergency, SafetyBinding{GlobalGeneration: 0, ProposedGeneration: 1}, fresh(), exposure, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		edge := safety.EmptyState()
		edge.Resources = []safety.ResourceSafety{{ResourceID: "app-one", EdgeOne: safety.EdgeOneSafety{Expiry: &safety.DeadlineMarker{Generation: 5, Deadline: deadline}}}}
		if err := independent.AuthorizeStateIndependentContraction(EdgeOneExpiry, edge, SafetyBinding{ResourceID: "app-one", ExpiryKind: "edgeone_expiry", ExpiryGeneration: 5, Deadline: deadline}, fresh(), exposure, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := independent.AuthorizeStateIndependentContraction(StartupRecovery, safety.EmptyState(), SafetyBinding{RecoveryGeneration: 1}, fresh(), exposure, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := independent.AuthorizeStateIndependentContraction(Publish, safety.EmptyState(), SafetyBinding{}, fresh(), exposure, func() error { return nil }); err == nil {
			t.Fatal("publish entered state-independent exception")
		}
		_, otherProof, _ := unavailableProof(t)
		if err := independent.AuthorizeStateIndependentContraction(StartupRecovery, safety.EmptyState(), SafetyBinding{RecoveryGeneration: 1}, otherProof, exposure, func() error { return nil }); err == nil {
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
		if _, err := admitter.Admit(context.Background(), admission, AdmitRequest{Operation: Publish, Target: "resource/app-one", ActorIdentity: "session-one", PlanID: plan.ID, SafetyBinding: SafetyBinding{ResourceID: "app-one"}, ExpectedRevision: document.Revision}); err != nil {
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

func openSafetyState() safety.State {
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner")}}
	return state
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	table, err := NewBranchTable([]ResultBranch{{"complete", jobs.ResultSucceeded, jobs.PostconditionVerified}, {"no_effect", jobs.ResultFailed, jobs.PostconditionVerified}, {"known_residual", jobs.ResultPartial, jobs.PostconditionKnown}, {"executor_died", jobs.ResultInterrupted, jobs.PostconditionKnown}, {"runtime_unobservable", jobs.ResultUnknown, jobs.PostconditionUnobserved}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Registration{{Operation: Publish, Owner: "publication", Results: table}})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func operationPlanSpec(now time.Time) plans.Spec {
	return plans.Spec{Operation: "publish", Target: plans.Target{Kind: plans.TargetResource, ID: "app-one"}, ActorIdentity: "session-one", Config: plans.DigestBinding{Applicable: true, Digest: testDigest("config")}, Applied: plans.DigestBinding{Applicable: true, Digest: testDigest("applied")}, Evidence: []plans.Evidence{{Kind: "config", Identity: "app-one", Generation: 1, Digest: testDigest("evidence"), ObservedAt: now}}, ExposureSummary: "expands_ingress", Prerequisites: "qualified"}
}
func testDigest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
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
