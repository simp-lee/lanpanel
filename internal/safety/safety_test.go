package safety

import (
	"context"
	"errors"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSafetySchemaContract(t *testing.T) {
	t.Run("closed_stop_fence_payloads", func(t *testing.T) {
		for _, kind := range []StopFenceKind{StopFenceContraction, StopFenceIngressActivation, StopFenceCertificateActivation, StopFenceEdgeOneRefresh, StopFenceMaintenanceTransition, StopFenceGenerationUpgrade} {
			t.Run(string(kind), func(t *testing.T) {
				state := EmptyState()
				state.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 1}
				fence := validStopFence(kind)
				if kind == StopFenceMaintenanceTransition {
					state.MaintenancePending = validTransition(1)
				}
				if kind == StopFenceGenerationUpgrade {
					state.UpgradePending = validTransition(1)
				}
				state.StopFence = &fence
				if err := Validate(state); err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				fence.Contraction = &ContractionFence{Authorities: []MarkerGeneration{{Kind: "closing", Generation: 1}}, OwnershipDigest: digest("extra")}
				fence.IngressActivation = &IngressActivationFence{IntentRef: "extra", CandidateGeneration: 9}
				state.StopFence = &fence
				if err := Validate(state); err == nil {
					t.Fatal("Validate() accepted multiple kind payloads")
				}
			})
		}
		state := EmptyState()
		state.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 1}
		fence := validStopFence(StopFenceContraction)
		fence.Kind = StopFenceKind("unknown")
		state.StopFence = &fence
		if err := Validate(state); err == nil {
			t.Fatal("Validate() accepted unknown fence kind")
		}
		fence = validStopFence(StopFenceContraction)
		fence.SafetyGenerations[0].Generation = 2
		state.StopFence = &fence
		if err := Validate(state); err == nil {
			t.Fatal("Validate() accepted stop fence bound to stale safety generation")
		}
	})

	t.Run("resource_markers_and_intents_are_closed", func(t *testing.T) {
		state := stateWithResource()
		if err := Validate(state); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		state.Resources[0].ChallengePending.BaseMarkers = state.Resources[0].ChallengePending.BaseMarkers[:3]
		if err := Validate(state); err == nil {
			t.Fatal("Validate() accepted incomplete marker snapshot")
		}
		state = stateWithResource()
		state.Resources[0].Ownership = OwnershipOrphan
		if err := Validate(state); err == nil {
			t.Fatal("Validate() accepted orphan expansion intent")
		}
		state = stateWithResource()
		state.Resources[0].Reactivating = validAppReactivating(state.Resources[0].StickyUnpublished)
		if err := Validate(state); err == nil {
			t.Fatal("Validate() accepted simultaneous challenge and reactivation")
		}
		state = stateWithResource()
		state.Resources[0].ChallengePending = nil
		state.Resources[0].EdgeOne.RefreshJournal = "one-sided"
		if err := Validate(state); err == nil {
			t.Fatal("Validate() accepted EdgeOne journal without deadline")
		}
	})

	t.Run("unique_clear_roles", func(t *testing.T) {
		checks := []struct {
			role   ClearRole
			target ClearTarget
			kind   StopFenceKind
		}{
			{RoleGlobalCloseConvergence, ClearGlobalClose, ""}, {RoleJournalConvergence, ClearStopFence, StopFenceContraction},
			{RoleUpgradeRecovery, ClearStopFence, StopFenceGenerationUpgrade}, {RoleMaintenance, ClearMaintenance, ""},
			{RoleUpgrade, ClearDependencyTransition, ""}, {RoleBackup, ClearBackup, ""},
			{RolePublish, ClearBaseContraction, ""}, {RoleDelete, ClearDeletionTombstone, ""}, {RoleChallenge, ClearChallenge, ""},
		}
		for _, check := range checks {
			if err := AuthorizeClear(check.role, check.target, check.kind); err != nil {
				t.Fatalf("AuthorizeClear(%q,%q) error = %v", check.role, check.target, err)
			}
			if err := AuthorizeClear(RoleContraction, check.target, check.kind); err == nil {
				t.Fatalf("contraction role cleared %q", check.target)
			}
		}
	})
}

func TestMaintenanceCompoundTransitionsAreAtomicAndNarrow(t *testing.T) {
	t.Run("atomic_marker_handoff", func(t *testing.T) {
		current := EmptyState()
		current.Resources = []ResourceSafety{{ResourceID: "app-a", State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owned")}}
		next := current
		next.Resources = append([]ResourceSafety(nil), current.Resources...)
		next.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 1}
		next.MaintenancePending = validTransition(1)
		next.Resources[0].StickyUnpublished = &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 1, Reason: "maintenance"}
		if err := validateTransition(RoleMaintenance, current, next, TransitionProof{}); err == nil {
			t.Fatal("ordinary maintenance role created initial marker without atomic closure")
		}
		if err := validateTransition(RoleMaintenanceBegin, current, next, TransitionProof{}); err != nil {
			t.Fatalf("maintenance begin: %v", err)
		}
		incomplete := next
		incomplete.Resources = append([]ResourceSafety(nil), next.Resources...)
		incomplete.Resources[0].StickyUnpublished = nil
		if err := validateTransition(RoleMaintenanceBegin, current, incomplete, TransitionProof{}); err == nil {
			t.Fatal("maintenance begin omitted per-App sticky authority")
		}
		converted := next
		converted.MaintenancePending = nil
		converted.DependencyTransitionPending = &TransitionMarker{Generation: 2, JournalRef: next.MaintenancePending.JournalRef, CurrentEnvelope: next.MaintenancePending.TargetEnvelope, TargetEnvelope: digest("dependency-target")}
		if err := validateTransition(RoleMaintenanceToDependency, next, converted, TransitionProof{}); err != nil {
			t.Fatalf("maintenance conversion: %v", err)
		}
		fenced := next
		stop := validStopFence(StopFenceMaintenanceTransition)
		fenced.StopFence = &stop
		fenced.DependencyTransitionPending = validTransition(9)
		reconciled := fenced
		reconciled.StopFence = nil
		reconciled.MaintenancePending = nil
		reconciled.DependencyTransitionPending = nil
		if err := validateMaintenanceCompound(RoleJournalConvergence, fenced, reconciled); err == nil {
			t.Fatal("journal convergence erased an unrelated dependency transition")
		}
	})
}

func TestSafetyConvergenceProofs(t *testing.T) {
	t.Run("closing_normalizes_to_exact_unpublished_generation", func(t *testing.T) {
		current := EmptyState()
		current.Resources = []ResourceSafety{{ResourceID: "app-a", State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), Closing: &GenerationMarker{Kind: MarkerClosing, Generation: 3, Reason: "close"}}}
		next := current
		next.Resources = append([]ResourceSafety(nil), current.Resources...)
		next.Resources[0].Closing = nil
		next.Resources[0].StickyUnpublished = &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 4, Reason: "closed"}
		if err := validateTransition(RoleContraction, current, next, TransitionProof{}); err == nil {
			t.Fatal("closing cleared without convergence proof")
		}
		proof := &ClosingConvergenceProof{ResourceID: "app-a", ClosingGeneration: 3, UnpublishedGeneration: 4, OwnershipDigest: digest("owner"), RuntimeClosureDigest: digest("closure")}
		if err := validateTransition(RoleContraction, current, next, TransitionProof{Closing: proof}); err != nil {
			t.Fatalf("closing convergence: %v", err)
		}
	})
	t.Run("stop_clear_binds_every_unpublished_generation", func(t *testing.T) {
		current := EmptyState()
		current.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 1}
		current.Resources = []ResourceSafety{{ResourceID: "app-a", State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 2, Reason: "closed"}}}
		fence := validStopFence(StopFenceContraction)
		current.StopFence = &fence
		next := current
		next.StopFence = nil
		proof := &StopFenceConvergenceProof{Kind: fence.Kind, FenceGeneration: fence.FenceGeneration, InventoryDigest: fence.InventoryDigest, OwnedGraphDigest: fence.OwnedGraphDigest, RuntimeClosureDigest: digest("closure"), AllChildrenExited: true, AllAppsUnpublished: true, NginxTestPassed: true}
		proof.UnpublishedGenerations = map[string]uint64{"app-a": 2}
		if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: proof}); err == nil {
			t.Fatal("stop fence cleared without disk, worker, listener, and runtime closure")
		}
		proof.NoAppDisk = true
		proof.WorkersDrained = true
		proof.ListenersClosed = true
		proof.RuntimeClosed = true
		if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: proof}); err != nil {
			t.Fatalf("stop convergence: %v", err)
		}
		orphanCurrent := current
		orphanCurrent.Resources = append([]ResourceSafety(nil), current.Resources...)
		orphanCurrent.Resources[0].Ownership = OwnershipOrphan
		orphanNext := orphanCurrent
		orphanNext.Resources = append([]ResourceSafety(nil), orphanCurrent.Resources...)
		orphanNext.StopFence = nil
		if err := validateTransition(RoleJournalConvergence, orphanCurrent, orphanNext, TransitionProof{StopFence: proof}); err == nil {
			t.Fatal("stop fence cleared while ownership orphan remained")
		}
	})
	t.Run("global_close_remains_while_ownership_orphan_exists", func(t *testing.T) {
		current := EmptyState()
		current.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 3}
		current.Resources = []ResourceSafety{{ResourceID: "app-a", State: ResourceActive, Ownership: OwnershipOrphan, OwnershipDigest: digest("owner"), StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 4, Reason: "closed"}}}
		proof := &GlobalConvergenceProof{Generation: 3, InventoryDigest: digest("inventory"), OwnedGraphDigest: digest("graph"), RuntimeClosureDigest: digest("closure"), UnpublishedGenerations: map[string]uint64{"app-a": 4}, NginxTestPassed: true, RuntimeClosed: true}
		if validGlobalClearProof(current, proof) {
			t.Fatal("global close convergence accepted an ownership orphan")
		}
	})
	t.Run("headscale_expiry_clear_requires_matching_reactivation", func(t *testing.T) {
		current := EmptyState()
		current.Headscale.CertificateExpiry = &DeadlineMarker{Generation: 4, Deadline: time.Now().UTC().Add(-time.Minute), Binding: "certificate"}
		current.Headscale.Reactivating = &HeadscaleReactivating{Generation: 2, PlanID: "plan", ControlGeneration: 7, CertificateGeneration: 4, CandidateDigest: digest("candidate"), CandidateBundle: digest("bundle"), BaseMarkers: []MarkerSnapshot{{Kind: MarkerStickyUnpublished, State: SnapshotAbsent}, {Kind: MarkerContraction, State: SnapshotAbsent}, {Kind: MarkerCertificateExpiry, State: SnapshotPresent, Generation: 4}, {Kind: MarkerEdgeOneExpiry, State: SnapshotAbsent}}, CertificateUntil: time.Now().UTC().Add(time.Hour)}
		next := current
		next.Headscale.CertificateExpiry = nil
		next.Headscale.Reactivating = nil
		if err := validateTransition(RolePublish, current, next, TransitionProof{}); err == nil {
			t.Fatal("Headscale expiry cleared without convergence proof")
		}
		proof := &HeadscaleConvergenceProof{PlanID: "plan", Generation: 2, ControlGeneration: 7, CertificateGeneration: 4, CandidateDigest: digest("candidate"), CandidateBundle: digest("bundle"), RuntimeClosureDigest: digest("closure")}
		if err := validateTransition(RolePublish, current, next, TransitionProof{Headscale: proof}); err != nil {
			t.Fatalf("Headscale convergence: %v", err)
		}
	})
}

func TestSafetyTransitionOwnershipRejectsReplacementBypass(t *testing.T) {
	t.Run("ownership_can_only_contract_to_orphan", func(t *testing.T) {
		current := EmptyState()
		current.Resources = []ResourceSafety{{ResourceID: "app-a", State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 1, Reason: "initial"}}}
		next := current
		next.Resources = append([]ResourceSafety(nil), current.Resources...)
		next.Resources[0].Ownership = OwnershipOrphan
		if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{}); err == nil {
			t.Fatal("journal convergence classified an ownership orphan")
		}
		if err := validateTransition(RoleOwnershipContraction, current, next, TransitionProof{}); err != nil {
			t.Fatalf("ownership contraction: %v", err)
		}
		reopened := next
		reopened.Resources = append([]ResourceSafety(nil), next.Resources...)
		reopened.Resources[0].Ownership = OwnershipOwned
		if err := validateTransition(RoleOwnershipContraction, next, reopened, TransitionProof{}); err == nil {
			t.Fatal("ownership contraction adopted an orphan")
		}
		changed := next
		changed.Resources = append([]ResourceSafety(nil), next.Resources...)
		changed.Resources[0].OwnershipDigest = digest("replacement")
		if err := validateTransition(RoleOwnershipContraction, next, changed, TransitionProof{}); err == nil {
			t.Fatal("ownership contraction rewrote orphan identity")
		}
	})

	t.Run("delete_cannot_erase_active_or_orphan_safety_identity", func(t *testing.T) {
		current := EmptyState()
		current.Resources = []ResourceSafety{{ResourceID: "app-a", State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 1, Reason: "initial"}}}
		next := current
		next.Resources = nil
		proof := &DeleteConvergenceProof{ResourceID: "app-a", OwnershipDigest: digest("owner"), RuntimeClosureDigest: digest("closure")}
		if err := validateTransition(RoleDelete, current, next, TransitionProof{Delete: proof}); err == nil {
			t.Fatal("delete removed an active resource without a tombstone")
		}
		current.Resources[0].State = ResourceDeleting
		current.Resources[0].DeletionTombstone = "tombstone-one"
		current.Resources[0].Ownership = OwnershipOrphan
		proof.TombstoneRef = current.Resources[0].DeletionTombstone
		if err := validateTransition(RoleDelete, current, next, TransitionProof{Delete: proof}); err == nil {
			t.Fatal("delete removed an ownership orphan")
		}
		current.Resources[0].Ownership = OwnershipOwned
		if err := validateTransition(RoleDelete, current, next, TransitionProof{Delete: proof}); err != nil {
			t.Fatalf("closed tombstoned owned delete: %v", err)
		}
	})

	t.Run("wrong_role_and_binding_replacement", func(t *testing.T) {
		current := stateWithResource()
		next := current
		next.Resources = append([]ResourceSafety(nil), current.Resources...)
		next.Resources[0].StickyUnpublished = nil
		if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{}); err == nil {
			t.Fatal("journal convergence cleared a publish-owned contraction marker")
		}

		current = EmptyState()
		upgrade := validStopFence(StopFenceGenerationUpgrade)
		current.StopFence = &upgrade
		next = current
		contraction := validStopFence(StopFenceContraction)
		next.StopFence = &contraction
		if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{}); err == nil {
			t.Fatal("journal convergence downgraded generation-upgrade stop fence")
		}

		current = EmptyState()
		current.Headscale.Reactivating = &HeadscaleReactivating{Generation: 1, PlanID: "headscale", ControlGeneration: 1, CertificateGeneration: 1, CandidateDigest: digest("candidate"), CandidateBundle: digest("bundle"), BaseMarkers: absentBaseSnapshot(), CertificateUntil: time.Now().UTC().Add(time.Hour)}
		next = current
		next.Headscale.Reactivating = nil
		if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{}); err == nil {
			t.Fatal("journal convergence cleared Headscale reactivation")
		}
	})
}

func TestSafetyPriorityAndGuardContract(t *testing.T) {
	t.Run("pairwise_priority_is_fail_closed", func(t *testing.T) {
		base := stateWithResource()
		resourceID := base.Resources[0].ResourceID
		cases := []struct {
			name   string
			mutate func(*State)
			want   EffectivePriority
		}{
			{"published", func(*State) {}, PriorityChallenge},
			{"base", func(s *State) { s.Resources[0].ChallengePending = nil; s.Resources[0].Reactivating = nil }, PriorityBaseContraction},
			{"reactivating", func(s *State) {
				s.Resources[0].ChallengePending = nil
				s.Resources[0].Reactivating = validAppReactivating(s.Resources[0].StickyUnpublished)
			}, PriorityReactivating},
			{"deleting", func(s *State) { s.Resources[0].State = ResourceDeleting; s.Resources[0].DeletionTombstone = "tomb" }, PriorityDeletingOrOrphan},
			{"closing", func(s *State) {
				s.Resources[0].Closing = &GenerationMarker{Kind: MarkerClosing, Generation: 2, Reason: "close"}
			}, PriorityClosing},
			{"global", func(s *State) { s.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 3} }, PriorityGlobalClose},
			{"backup", func(s *State) { s.BackupQuiescence = &BackupQuiescence{Generation: 4, Phase: BackupPreparing} }, PriorityBackup},
			{"maintenance", func(s *State) { s.MaintenancePending = validTransition(5) }, PriorityMaintenance},
			{"stop", func(s *State) { f := validStopFence(StopFenceContraction); s.StopFence = &f }, PriorityStopFence},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				state := base
				state.Resources = append([]ResourceSafety(nil), base.Resources...)
				tc.mutate(&state)
				got := effectivePriority(state, resourceID)
				if got != tc.want {
					t.Fatalf("priority=%q want %q", got, tc.want)
				}
			})
		}
	})

	t.Run("challenge_and_reactivation_require_exact_generation", func(t *testing.T) {
		state := stateWithResource()
		resource := &state.Resources[0]
		now := time.Now().UTC()
		decision := Check(GuardInput{State: state, Action: ActionAppChallenge, ResourceID: resource.ResourceID, CandidateDigest: resource.ChallengePending.BootstrapIdentity, PlanID: resource.ChallengePending.PlanID, Generation: resource.ChallengePending.Generation, Now: now})
		if !decision.Allowed || decision.Priority != PriorityChallenge {
			t.Fatalf("challenge decision=%#v", decision)
		}
		resource.ChallengePending.BaseMarkers[0].Generation++
		if decision = Check(GuardInput{State: state, Action: ActionAppChallenge, ResourceID: resource.ResourceID, CandidateDigest: resource.ChallengePending.BootstrapIdentity, PlanID: resource.ChallengePending.PlanID, Generation: resource.ChallengePending.Generation, Now: now}); decision.Allowed {
			t.Fatalf("stale challenge allowed: %#v", decision)
		}
		state = stateWithResource()
		resource = &state.Resources[0]
		resource.StickyUnpublished = nil
		for index := range resource.ChallengePending.BaseMarkers {
			resource.ChallengePending.BaseMarkers[index] = MarkerSnapshot{Kind: resource.ChallengePending.BaseMarkers[index].Kind, State: SnapshotAbsent}
		}
		if decision = Check(GuardInput{State: state, Action: ActionPublish, ResourceID: resource.ResourceID, Now: now}); decision.Allowed {
			t.Fatalf("ordinary publish bypassed challenge intent: %#v", decision)
		}
		state = stateWithResource()
		resource = &state.Resources[0]
		resource.ChallengePending = nil
		resource.Reactivating = validAppReactivating(resource.StickyUnpublished)
		decision = Check(GuardInput{State: state, Action: ActionReactivate, ResourceID: resource.ResourceID, CandidateDigest: resource.Reactivating.CandidateDigest, PlanID: resource.Reactivating.PlanID, Generation: resource.Reactivating.Generation, CandidateBundle: resource.Reactivating.CandidateBundle, Now: now})
		if !decision.Allowed {
			t.Fatalf("reactivation decision=%#v", decision)
		}
		resource.EdgeOne.Expiry = &DeadlineMarker{Generation: 7, Deadline: now.Add(-time.Minute), Binding: "expired"}
		if decision = Check(GuardInput{State: state, Action: ActionReactivate, ResourceID: resource.ResourceID, CandidateDigest: resource.Reactivating.CandidateDigest, CandidateBundle: resource.Reactivating.CandidateBundle, PlanID: resource.Reactivating.PlanID, Generation: resource.Reactivating.Generation, Now: now}); decision.Allowed {
			t.Fatalf("stale reactivation allowed: %#v", decision)
		}
	})

	t.Run("elapsed_edgeone_deadline_is_authority_without_timer_marker", func(t *testing.T) {
		state := stateWithResource()
		resource := &state.Resources[0]
		resource.StickyUnpublished = nil
		resource.ChallengePending = nil
		resource.Reactivating = nil
		resource.EdgeOne.Expiry = nil
		resource.EdgeOne.RefreshJournal = "edge-refresh"
		resource.EdgeOne.Deadline = time.Now().UTC().Add(-time.Second)
		decision := Check(GuardInput{State: state, Action: ActionPublish, ResourceID: resource.ResourceID, Now: time.Now().UTC()})
		if decision.Allowed || decision.Priority != PriorityBaseContraction {
			t.Fatalf("elapsed EdgeOne deadline decision=%#v", decision)
		}
	})

	t.Run("global_close_blocks_app_but_not_matching_headscale_challenge", func(t *testing.T) {
		state := stateWithResource()
		state.GlobalClose = GlobalClose{Phase: GlobalCloseEmergency, Generation: 9}
		app := Check(GuardInput{State: state, Action: ActionAppChallenge, ResourceID: state.Resources[0].ResourceID, CandidateDigest: state.Resources[0].ChallengePending.BootstrapIdentity, PlanID: state.Resources[0].ChallengePending.PlanID, Generation: state.Resources[0].ChallengePending.Generation, Now: time.Now().UTC()})
		if app.Allowed {
			t.Fatalf("App challenge crossed global close: %#v", app)
		}
		challenge := *state.Resources[0].ChallengePending
		challenge.BaseMarkers = []MarkerSnapshot{{Kind: MarkerStickyUnpublished, State: SnapshotAbsent}, {Kind: MarkerContraction, State: SnapshotAbsent}, {Kind: MarkerCertificateExpiry, State: SnapshotAbsent}, {Kind: MarkerEdgeOneExpiry, State: SnapshotAbsent}}
		state.Headscale.ChallengePending = &challenge
		headscale := Check(GuardInput{State: state, Action: ActionHeadscaleChallenge, CandidateDigest: state.Headscale.ChallengePending.BootstrapIdentity, PlanID: state.Headscale.ChallengePending.PlanID, Generation: state.Headscale.ChallengePending.Generation, Now: time.Now().UTC()})
		if !headscale.Allowed {
			t.Fatalf("Headscale challenge blocked by App-only global close: %#v", headscale)
		}
		state.Headscale.ChallengePending = nil
		state.Headscale.CertificateExpiry = &DeadlineMarker{Generation: 4, Deadline: time.Now().UTC().Add(-time.Minute), Binding: "headscale-cert"}
		state.Headscale.Reactivating = &HeadscaleReactivating{Generation: 2, PlanID: "headscale-reactivate", ControlGeneration: 7, CertificateGeneration: 4, CandidateDigest: digest("headscale-candidate"), CandidateBundle: digest("headscale-bundle"), BaseMarkers: []MarkerSnapshot{{Kind: MarkerStickyUnpublished, State: SnapshotAbsent}, {Kind: MarkerContraction, State: SnapshotAbsent}, {Kind: MarkerCertificateExpiry, State: SnapshotPresent, Generation: 4}, {Kind: MarkerEdgeOneExpiry, State: SnapshotAbsent}}, CertificateUntil: time.Now().UTC().Add(time.Hour)}
		headscale = Check(GuardInput{State: state, Action: ActionHeadscaleReactivate, CandidateDigest: state.Headscale.Reactivating.CandidateDigest, CandidateBundle: state.Headscale.Reactivating.CandidateBundle, PlanID: state.Headscale.Reactivating.PlanID, Generation: state.Headscale.Reactivating.Generation, ControlGeneration: 7, CertificateGeneration: 4, Now: time.Now().UTC()})
		if !headscale.Allowed {
			t.Fatalf("matching Headscale reactivation blocked: %#v", headscale)
		}
		if headscale = Check(GuardInput{State: state, Action: ActionHeadscaleReactivate, CandidateDigest: state.Headscale.Reactivating.CandidateDigest, CandidateBundle: state.Headscale.Reactivating.CandidateBundle, PlanID: state.Headscale.Reactivating.PlanID, Generation: state.Headscale.Reactivating.Generation, ControlGeneration: 8, CertificateGeneration: 4, Now: time.Now().UTC()}); headscale.Allowed {
			t.Fatalf("mismatched Headscale control generation allowed: %#v", headscale)
		}
	})

	t.Run("unregistered_operation_is_blocked", func(t *testing.T) {
		registry, err := NewRegistry([]Registration{{Operation: "publish", Action: ActionPublish, Owner: "publication"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := registry.Check("missing", GuardInput{State: EmptyState()}); err == nil {
			t.Fatal("unregistered operation passed")
		}
		if _, err := NewRegistry([]Registration{{Operation: "x", Action: ActionPublish, Owner: "a"}, {Operation: "x", Action: ActionPublish, Owner: "b"}}); err == nil {
			t.Fatal("duplicate guard registration passed")
		}
	})
}

func TestSafetyStoreRequiresLockGenerationAndUniqueClearer(t *testing.T) {
	t.Run("missing_state_generation_pair_and_convergent_clear", func(t *testing.T) {
		store, emergency, manager, lease := newSafetyStore(t)
		defer closeSafetyStore(t, store, emergency, manager, lease)
		if _, err := store.Read(); !errors.Is(err, ErrSafetyStateMissing) {
			t.Fatalf("Read(uninitialized) error = %v", err)
		}
		if _, err := store.Initialize(context.Background(), lease); err != nil {
			t.Fatalf("Initialize() error = %v", err)
		}
		current, err := store.Read()
		if err != nil {
			t.Fatal(err)
		}
		authority := EmergencyState{Sequence: 3, NormalInitialized: true, GlobalClose: GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}}
		if err := emergency.Commit(lease, RoleContraction, 2, authority); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); err == nil {
			t.Fatal("Read() accepted one-sided emergency generation")
		}
		next := current
		next.Revision++
		next.AuthoritySequence = authority.Sequence
		next.GlobalClose = authority.GlobalClose
		if _, err := store.Commit(context.Background(), nil, RoleContraction, current.Revision, next, TransitionProof{}); err == nil {
			t.Fatal("Commit without exposure lock succeeded")
		}
		result, err := store.Commit(context.Background(), lease, RoleContraction, current.Revision, next, TransitionProof{})
		if err != nil || result.State != filetxn.StateDurable {
			t.Fatalf("Commit()=%#v,%v", result, err)
		}
		persisted, err := store.Read()
		if err != nil || persisted.Checksum == "" || persisted.GlobalClose.Phase != GlobalCloseEmergency {
			t.Fatalf("Read()=%#v,%v", persisted, err)
		}
		emergencyProof := EmergencyClearProof{Generation: 1, InventoryDigest: digest("inventory"), OwnedGraphDigest: digest("graph"), RuntimeClosureDigest: digest("closure"), NginxTestPassed: true, RuntimeClosed: true}
		clearedAuthority := EmergencyState{Sequence: 4, NormalInitialized: true, GlobalClose: GlobalClose{Phase: GlobalCloseNone, Generation: 1}, ClearProof: &emergencyProof}
		if err := emergency.Commit(lease, RoleGlobalCloseConvergence, 3, clearedAuthority); err != nil {
			t.Fatal(err)
		}
		cleared := persisted
		cleared.Revision++
		cleared.AuthoritySequence = clearedAuthority.Sequence
		cleared.GlobalClose = clearedAuthority.GlobalClose
		globalProof := &GlobalConvergenceProof{Generation: 1, InventoryDigest: emergencyProof.InventoryDigest, OwnedGraphDigest: emergencyProof.OwnedGraphDigest, RuntimeClosureDigest: emergencyProof.RuntimeClosureDigest, NginxTestPassed: true, RuntimeClosed: true}
		if _, err := store.Commit(context.Background(), lease, RoleContraction, persisted.Revision, cleared, TransitionProof{GlobalClose: globalProof}); err == nil {
			t.Fatal("wrong role cleared global close")
		}
		if _, err := store.Commit(context.Background(), lease, RoleGlobalCloseConvergence, persisted.Revision, cleared, TransitionProof{GlobalClose: globalProof}); err != nil {
			t.Fatalf("authorized clear error=%v", err)
		}
		if _, err := store.Commit(context.Background(), lease, RoleContraction, cleared.Revision, cleared, TransitionProof{}); err == nil {
			t.Fatal("stale revision commit succeeded")
		}
		if err := os.Remove(store.config.StatePath); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); !errors.Is(err, ErrSafetyStateMissing) {
			t.Fatalf("Read(lost state) error = %v", err)
		}
		if _, err := store.Initialize(context.Background(), lease); err == nil {
			t.Fatal("Initialize recreated previously initialized missing state")
		}
	})
}

func TestEmergencyGlobalAndFenceAuthoritiesConvergeSequentially(t *testing.T) {
	global := GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}
	fence := validEmergencyFenceForTest(1, 2)
	current := EmergencyState{Sequence: 2, GlobalClose: global, StopFence: &fence}
	proof := &EmergencyClearProof{Generation: 1, StopFenceGeneration: 2, InventoryDigest: digest("inventory"), OwnedGraphDigest: digest("graph"), RuntimeClosureDigest: digest("closure"), NginxTestPassed: true, RuntimeClosed: true}
	fenceCleared := EmergencyState{Sequence: 3, GlobalClose: global, ClearProof: proof}
	if !validEmergencyTransition(RoleJournalConvergence, current, fenceCleared) {
		t.Fatal("journal convergence could not clear a fence while preserving global close")
	}
	globalCleared := EmergencyState{Sequence: 4, GlobalClose: GlobalClose{Phase: GlobalCloseNone, Generation: 1}, ClearProof: proof}
	if !validEmergencyTransition(RoleGlobalCloseConvergence, fenceCleared, globalCleared) {
		t.Fatal("global convergence could not clear global close after fence convergence")
	}
}

func TestEmergencyBackingSurvivesSlotCorruptionAndCommitsWithoutAllocation(t *testing.T) {
	t.Run("slot_recovery_and_zero_allocation_commit", func(t *testing.T) {
		store, manager, lease, path := newEmergencyStore(t, nil)
		defer closeEmergencyStore(t, store, manager, lease)
		first := EmergencyState{Sequence: 2, GlobalClose: GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}}
		if err := store.Commit(lease, RoleContraction, 1, first); err != nil {
			t.Fatal(err)
		}
		if err := store.Commit(lease, RoleContraction, 2, EmergencyState{Sequence: 3, GlobalClose: GlobalClose{Phase: GlobalCloseEmergency, Generation: 2}}); !errors.Is(err, ErrEmergencyState) {
			t.Fatalf("active generation change error = %v", err)
		}
		if err := store.Commit(lease, RoleContraction, 2, EmergencyState{Sequence: 3, GlobalClose: GlobalClose{Phase: GlobalCloseNone, Generation: 1}}); !errors.Is(err, ErrEmergencyState) {
			t.Fatalf("wrong clear role error = %v", err)
		}
		fence := validEmergencyFenceForTest(1, 2)
		second := EmergencyState{Sequence: 3, GlobalClose: first.GlobalClose, StopFence: &fence}
		if err := store.Commit(lease, RoleContraction, 2, second); err != nil {
			t.Fatal(err)
		}
		if got := store.Current(); got.Sequence != 3 || got.StopFence == nil || got.StopFence.InventoryDigest != fence.InventoryDigest || got.StopFence.OriginOperation != fence.OriginOperation {
			t.Fatalf("Current()=%#v", got)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt([]byte("corrupt"), emergencySlotSize); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenEmergency(path, filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, EmergencyOptions{LockAuthority: lease.Authority()})
		if err != nil {
			t.Fatal(err)
		}
		store = reopened
		defer store.Close()
		if got := store.Current(); got.Sequence != 2 {
			t.Fatalf("recovered sequence=%d want 2", got.Sequence)
		}
		sequence := uint64(2)
		committer, err := store.PrepareCommit(lease)
		if err != nil {
			t.Fatal(err)
		}
		allocs := testing.AllocsPerRun(5, func() {
			committer.used = false
			committer.preparedSequence = sequence
			sequence++
			next := EmergencyState{Sequence: sequence, GlobalClose: first.GlobalClose}
			if err := committer.Commit(RoleContraction, sequence-1, next); err != nil {
				panic(err)
			}
		})
		if allocs != 0 {
			t.Fatalf("Emergency Commit allocations=%v want 0", allocs)
		}
	})
}

func TestEmergencyWriteInterruptionLeavesAValidCompleteSlot(t *testing.T) {
	t.Run("interrupted_write_preserves_complete_authority", func(t *testing.T) {
		fault := errors.New("crash after slot write")
		store, manager, lease, path := newEmergencyStore(t, func(point EmergencyPoint) error {
			if point == EmergencyAfterSlotWrite {
				return fault
			}
			return nil
		})
		state := EmergencyState{Sequence: 2, GlobalClose: GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}}
		if err := store.Commit(lease, RoleContraction, 1, state); !errors.Is(err, fault) {
			t.Fatalf("Commit error=%v", err)
		}
		closeEmergencyStore(t, store, manager, lease)
		reopened, err := OpenEmergency(path, filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, EmergencyOptions{LockAuthority: lease.Authority()})
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if got := reopened.Current(); got.Sequence != 1 && got.Sequence != 2 {
			t.Fatalf("recovered partial state %#v", got)
		}
	})
}

func TestEmergencyBackingReloadsAcrossInstancesAndNeverDowngradesToInactiveSlot(t *testing.T) {
	t.Run("fresh_multi_instance_authority_and_no_runtime_recreate", func(t *testing.T) {
		store, manager, lease, path := newEmergencyStore(t, nil)
		owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
		second, err := OpenEmergency(path, owner, EmergencyOptions{LockAuthority: lease.Authority()})
		if err != nil {
			t.Fatal(err)
		}
		active := EmergencyState{Sequence: 2, GlobalClose: GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}}
		if err := store.Commit(lease, RoleContraction, 1, active); err != nil {
			t.Fatal(err)
		}
		if got, err := second.Authority(); err != nil || got.Sequence != 2 {
			t.Fatalf("second Authority() = %#v, %v", got, err)
		}
		if err := second.Commit(lease, RoleContraction, 1, active); !errors.Is(err, ErrEmergencySequence) {
			t.Fatalf("stale second Commit() error = %v", err)
		}
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
		closeEmergencyStore(t, store, manager, lease)
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt(make([]byte, 8), 0); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenEmergency(path, owner, EmergencyOptions{LockAuthority: lease.Authority()}); err == nil {
			t.Fatal("OpenEmergency downgraded from corrupt active slot to inactive baseline")
		}
		missing := filepath.Join(filepath.Dir(path), "missing.slots")
		if _, err := OpenEmergency(missing, owner, EmergencyOptions{LockAuthority: lease.Authority()}); err == nil {
			t.Fatal("runtime OpenEmergency created missing backing")
		}
	})
}

func TestEmergencyBackingRejectsTotalCorruptionAndPoisonsAmbiguousWriter(t *testing.T) {
	t.Run("ambiguous_commit_poison_and_total_corruption", func(t *testing.T) {
		fault := errors.New("lost acknowledgement")
		store, manager, lease, path := newEmergencyStore(t, func(point EmergencyPoint) error {
			if point == EmergencyAfterSlotSync {
				return fault
			}
			return nil
		})
		next := EmergencyState{Sequence: 2, GlobalClose: GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}}
		if err := store.Commit(lease, RoleContraction, 1, next); !errors.Is(err, fault) {
			t.Fatalf("Commit() error = %v", err)
		}
		if err := store.Commit(lease, RoleContraction, 1, next); !errors.Is(err, ErrEmergencyAmbiguous) {
			t.Fatalf("second Commit() error = %v", err)
		}
		closeEmergencyStore(t, store, manager, lease)
		reopened, err := OpenEmergency(path, filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, EmergencyOptions{LockAuthority: lease.Authority()})
		if err != nil {
			t.Fatal(err)
		}
		if got := reopened.Current(); got.Sequence != 2 {
			t.Fatalf("reconciled sequence = %d, want 2", got.Sequence)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt(make([]byte, 8), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt(make([]byte, 8), emergencySlotSize); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenEmergency(path, filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, EmergencyOptions{LockAuthority: lease.Authority()}); err == nil {
			t.Fatal("OpenEmergency accepted two invalid slots")
		}
	})
}

func validEmergencyFenceForTest(globalGeneration, fenceGeneration uint64) EmergencyStopFence {
	return EmergencyStopFence{Kind: StopFenceContraction, OriginOperation: "emergency_close", ScopeKind: "installation", Generation: fenceGeneration, GlobalGeneration: globalGeneration, OwnershipDigest: digest("owner"), OwnedGraphDigest: digest("graph"), InventoryDigest: digest("inventory"), ObservedUnix: time.Now().Unix(), AccessMayRemain: true}
}

func validStopFence(kind StopFenceKind) StopFence {
	f := StopFence{Kind: kind, OriginOperation: "operation", Scope: FenceScope{Kind: "installation"}, FenceGeneration: 1, CreatedAt: time.Unix(100, 0).UTC(), SafetyGenerations: []MarkerGeneration{{Kind: "global_close", Generation: 1}}, OwnedGraphDigest: digest("graph"), InventoryDigest: digest("inventory"), Observation: StopObservation{ObservedAt: time.Unix(101, 0).UTC()}, AccessMayRemain: true}
	switch kind {
	case StopFenceContraction:
		f.Contraction = &ContractionFence{Authorities: []MarkerGeneration{{Kind: "global_close", Generation: 1}}, OwnershipDigest: digest("owner")}
	case StopFenceIngressActivation:
		f.IngressActivation = &IngressActivationFence{IntentRef: "intent", CandidateGeneration: 2, PriorGeneration: 1}
	case StopFenceCertificateActivation:
		f.CertificateActivation = &CertificateActivationFence{JournalRef: "journal", ResourceGeneration: 2, PriorPointer: digest("prior"), CandidatePointer: digest("candidate"), ExpiryGeneration: 1}
	case StopFenceEdgeOneRefresh:
		f.EdgeOneRefresh = &EdgeOneRefreshFence{JournalRef: "journal", ResourceGeneration: 2, PriorACL: digest("prior-acl"), CandidateACL: digest("candidate-acl"), PriorDeadline: time.Unix(200, 0).UTC(), CandidateDeadline: time.Unix(300, 0).UTC()}
	case StopFenceMaintenanceTransition, StopFenceGenerationUpgrade:
		if kind == StopFenceMaintenanceTransition {
			f.SafetyGenerations = append(f.SafetyGenerations, MarkerGeneration{Kind: "maintenance_pending", Generation: 1})
		}
		if kind == StopFenceGenerationUpgrade {
			f.SafetyGenerations = append(f.SafetyGenerations, MarkerGeneration{Kind: "upgrade_pending", Generation: 1})
		}
		f.Transition = &TransitionFence{JournalRef: "journal", CurrentEnvelope: digest("current"), TargetEnvelope: digest("target"), RuntimeClosureDigest: digest("runtime"), GenerationClosureDigest: digest("generation")}
	}
	return f
}

func absentBaseSnapshot() []MarkerSnapshot {
	return []MarkerSnapshot{{Kind: MarkerStickyUnpublished, State: SnapshotAbsent}, {Kind: MarkerContraction, State: SnapshotAbsent}, {Kind: MarkerCertificateExpiry, State: SnapshotAbsent}, {Kind: MarkerEdgeOneExpiry, State: SnapshotAbsent}}
}

func validAppReactivating(sticky *GenerationMarker) *Reactivating {
	snapshots := absentBaseSnapshot()
	if sticky != nil {
		snapshots[0] = MarkerSnapshot{Kind: MarkerStickyUnpublished, State: SnapshotPresent, Generation: sticky.Generation}
	}
	now := time.Now().UTC()
	return &Reactivating{Generation: 1, PlanID: "plan", CandidateDigest: digest("candidate"), CandidateBundle: digest("bundle"), BaseMarkers: snapshots, CertificateUntil: now.Add(time.Hour), ACLUntil: now.Add(time.Hour)}
}

func stateWithResource() State {
	snapshots := []MarkerSnapshot{{Kind: MarkerStickyUnpublished, State: SnapshotPresent, Generation: 1}, {Kind: MarkerContraction, State: SnapshotAbsent}, {Kind: MarkerCertificateExpiry, State: SnapshotAbsent}, {Kind: MarkerEdgeOneExpiry, State: SnapshotAbsent}}
	return State{SchemaVersion: SchemaVersion, Revision: 1, AuthoritySequence: 1, GlobalClose: GlobalClose{Phase: GlobalCloseNone}, Resources: []ResourceSafety{{ResourceID: "app-one", State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 1, Reason: "initial"}, ChallengePending: &ChallengePending{Generation: 1, PlanID: "plan", Host: "app.example.com", TokenPath: "/var/lib/lanpanel/token", Webroot: "/var/lib/lanpanel/webroot", BootstrapIdentity: digest("bootstrap"), BaseMarkers: append([]MarkerSnapshot(nil), snapshots...)}}}}
}

func validTransition(generation uint64) *TransitionMarker {
	return &TransitionMarker{Generation: generation, JournalRef: "journal", CurrentEnvelope: digest("current"), TargetEnvelope: digest("target"), Deadline: time.Now().Add(time.Hour).UTC()}
}
func digest(seed string) string {
	sum := strings.Repeat("a", 64)
	if seed != "" {
		sum = strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
	}
	return "sha256:" + sum
}

func newSafetyStore(t *testing.T) (*Store, *EmergencyStore, *locks.Manager, *locks.Lease) {
	t.Helper()
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	staging := filepath.Join(root, "staging")
	_ = os.Mkdir(staging, 0o700)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	lockRoot := t.TempDir()
	_ = os.Chmod(lockRoot, 0o700)
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		t.Fatal(err)
	}
	emergency, err := CreateEmergency(filepath.Join(root, "emergency.slots"), owner, EmergencyOptions{LockAuthority: lease.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(StoreConfig{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "state.json"), Owner: owner, Emergency: emergency, LockAuthority: lease.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	return store, emergency, manager, lease
}
func closeSafetyStore(t *testing.T, store *Store, emergency *EmergencyStore, manager *locks.Manager, lease *locks.Lease) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Error(err)
	}
	if err := emergency.Close(); err != nil {
		t.Error(err)
	}
	if err := lease.Release(); err != nil {
		t.Error(err)
	}
	if err := manager.Close(); err != nil {
		t.Error(err)
	}
}

func newEmergencyStore(t *testing.T, fault func(EmergencyPoint) error) (*EmergencyStore, *locks.Manager, *locks.Lease, string) {
	t.Helper()
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	lockRoot := t.TempDir()
	_ = os.Chmod(lockRoot, 0o700)
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "emergency.slots")
	store, err := CreateEmergency(path, owner, EmergencyOptions{Fault: fault, LockAuthority: lease.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	return store, manager, lease, path
}
func closeEmergencyStore(t *testing.T, store *EmergencyStore, manager *locks.Manager, lease *locks.Lease) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Error(err)
	}
	if err := lease.Release(); err != nil {
		t.Error(err)
	}
	if err := manager.Close(); err != nil {
		t.Error(err)
	}
}
