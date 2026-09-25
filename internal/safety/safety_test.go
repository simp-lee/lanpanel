package safety

import (
	"context"
	"encoding/json"
	"errors"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestP1SafetySchemaContainsOnlyLiveAuthorities(t *testing.T) {
	state := stateWithResource()
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"maintenance_pending", "dependency_transition_pending", "upgrade_pending", "backup_quiescence", "backup_transition", "edgeone"} {
		if strings.Contains(string(encoded), `"`+removed+`"`) {
			t.Fatalf("removed safety authority %q remains encoded", removed)
		}
	}
	if err := Validate(state); err != nil {
		t.Fatal(err)
	}
	state.Resources[0].ChallengePending.BaseMarkers = state.Resources[0].ChallengePending.BaseMarkers[:2]
	if err := Validate(state); err == nil {
		t.Fatal("incomplete base-marker snapshot accepted")
	}
}

func TestP1StopFenceKindsAndContractionOriginBindingAreClosed(t *testing.T) {
	for _, kind := range []StopFenceKind{StopFenceContraction, StopFenceIngressActivation, StopFenceCertificateActivation} {
		t.Run(string(kind), func(t *testing.T) {
			state, fence := stateForFence(kind)
			state.StopFenceSequence = fence.FenceGeneration
			state.StopFence = &fence
			if err := Validate(state); err != nil {
				t.Fatal(err)
			}
		})
	}
	state, fence := stateForFence(StopFenceContraction)
	fence.Contraction.OperationRef = ""
	fence.Contraction.SafetyIntentID = ""
	fence.Contraction.SafetyIntentGeneration = 0
	state.StopFenceSequence = fence.FenceGeneration
	state.StopFence = &fence
	if err := Validate(state); err == nil {
		t.Fatal("contraction fence without operation or safety-intent identity accepted")
	}
	fence.Contraction.OperationRef = "intent/job-one"
	fence.Contraction.SafetyIntentID = "emergency-close"
	fence.Contraction.SafetyIntentGeneration = 1
	if err := Validate(state); err == nil {
		t.Fatal("contraction fence carrying both origin branches accepted")
	}
	fence = validStopFence(StopFenceContraction)
	fence.Kind = "removed_or_unknown"
	state.StopFence = &fence
	if err := Validate(state); err == nil {
		t.Fatal("unknown stop-fence kind accepted")
	}
}

func TestStopFenceClearRequiresExactOriginAndCompleteClosureProof(t *testing.T) {
	current, fence := stateForFence(StopFenceContraction)
	current.Resources = []ResourceSafety{{ResourceID: "app-one", GenerationSequence: 1, State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 1, Reason: "closed"}}}
	fence.Scope = FenceScope{Kind: "installation"}
	fence.SafetyGenerations = []MarkerGeneration{{Kind: "global_close", Generation: 1}}
	fence.Contraction.Authorities = []MarkerGeneration{{Kind: "global_close", Generation: 1}}
	current.StopFenceSequence = fence.FenceGeneration
	current.StopFence = &fence
	next := current
	next.StopFence = nil
	proof := &StopFenceConvergenceProof{
		Kind: fence.Kind, FenceGeneration: fence.FenceGeneration, FenceDigest: StopFenceDigest(fence),
		JournalRef: fence.Contraction.OperationRef, InventoryDigest: fence.InventoryDigest, OwnedGraphDigest: fence.OwnedGraphDigest,
		RuntimeClosureDigest: digest("closure"), AllChildrenExited: true, AllAppsUnpublished: true, NoAppDisk: true,
		WorkersDrained: true, ListenersClosed: true, RuntimeClosed: true, NginxTestPassed: true,
		UnpublishedGenerations: map[string]uint64{"app-one": 1},
	}
	if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: proof}); err != nil {
		t.Fatal(err)
	}
	wrong := *proof
	wrong.JournalRef = "intent/other"
	if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: &wrong}); err == nil {
		t.Fatal("wrong operation reference cleared stop fence")
	}
	wrong = *proof
	wrong.AllChildrenExited = false
	if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: &wrong}); err == nil {
		t.Fatal("incomplete child closure cleared stop fence")
	}

	independent := fence
	independent.Contraction.OperationRef = ""
	independent.Contraction.SafetyIntentID = "emergency_close_all"
	independent.Contraction.SafetyIntentGeneration = 1
	current.StopFence = &independent
	independentProof := *proof
	independentProof.FenceDigest = StopFenceDigest(independent)
	independentProof.JournalRef = ""
	independentProof.SafetyIntentID = "emergency_close_all"
	independentProof.SafetyIntentGeneration = 1
	if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: &independentProof}); err != nil {
		t.Fatal(err)
	}
	independentProof.SafetyIntentGeneration = 2
	if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: &independentProof}); err == nil {
		t.Fatal("stale safety-intent generation cleared stop fence")
	}
}

func TestActivationFenceClearMayConsumeOneEmergencyGeneration(t *testing.T) {
	for _, kind := range []StopFenceKind{StopFenceIngressActivation, StopFenceCertificateActivation} {
		t.Run(string(kind), func(t *testing.T) {
			current, fence := stateForFence(kind)
			current.StopFenceSequence = fence.FenceGeneration
			current.StopFence = &fence
			current.GlobalClose = GlobalClose{Phase: GlobalCloseNone, Generation: 1}
			next := current
			next.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 1}
			next.StopFenceSequence++
			next.StopFence = nil
			next.Resources = append([]ResourceSafety(nil), current.Resources...)
			next.Resources[0].GenerationSequence++
			next.Resources[0].StickyUnpublished = &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: next.Resources[0].GenerationSequence, Reason: "closed"}
			next.Resources[0].Reactivating = nil
			proof := &StopFenceConvergenceProof{
				Kind: fence.Kind, FenceGeneration: fence.FenceGeneration, FenceDigest: StopFenceDigest(fence),
				JournalRef: func() string {
					if fence.IngressActivation != nil {
						return fence.IngressActivation.IntentRef
					}
					return fence.CertificateActivation.JournalRef
				}(), InventoryDigest: fence.InventoryDigest, OwnedGraphDigest: fence.OwnedGraphDigest,
				RuntimeClosureDigest: digest("closure"), AllChildrenExited: true, AllAppsUnpublished: true, NoAppDisk: true,
				WorkersDrained: true, ListenersClosed: true, RuntimeClosed: true, NginxTestPassed: true,
				UnpublishedGenerations: map[string]uint64{"app-one": next.Resources[0].GenerationSequence},
			}
			if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: proof}); err != nil {
				t.Fatalf("exact activation reconciliation did not consume emergency high-water: %v", err)
			}
			wrong := *proof
			wrong.JournalRef = "other-origin"
			if err := validateTransition(RoleJournalConvergence, current, next, TransitionProof{StopFence: &wrong}); err == nil {
				t.Fatal("activation fence was cleared with a different origin")
			}
		})
	}
}

func TestStoreClearsSupersededActivationFenceAgainstEmergencyProof(t *testing.T) {
	for _, kind := range []StopFenceKind{StopFenceIngressActivation, StopFenceCertificateActivation} {
		t.Run(string(kind), func(t *testing.T) {
			store, emergency, manager, lease := newSafetyStore(t)
			defer closeSafetyStore(t, store, emergency, manager, lease)
			if _, err := store.Initialize(context.Background(), lease); err != nil {
				t.Fatal(err)
			}
			ownership := testOwnershipAuthority{"app-one": digest("owner")}
			store.config.Ownership = ownership
			current, fence := stateForFence(kind)
			current.Revision = 1
			current.GlobalClose = GlobalClose{Phase: GlobalCloseNone}
			fence.SafetyGenerations = fence.SafetyGenerations[1:]
			fence.InventoryDigest = OwnershipInventoryDigest(map[string]string(ownership))
			current.StopFenceSequence = fence.FenceGeneration
			current.StopFence = &fence
			role := RoleIngressActivation
			if kind == StopFenceCertificateActivation {
				role = RoleCertificateActivation
			}
			reserved, err := ReserveEmergencyStopFenceGeneration(lease, emergency, role, kind, StopFenceDigest(fence), 0)
			if err != nil {
				t.Fatal(err)
			}
			current.AuthoritySequence = reserved.Sequence
			current.StopFenceSequence = reserved.StopFenceSequence
			if _, err := store.persist(context.Background(), current, filetxn.ReplaceOnly); err != nil {
				t.Fatal(err)
			}
			current, err = store.Read()
			if err != nil {
				t.Fatal(err)
			}

			authority := reserved
			authority.Sequence++
			authority.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 1}
			if err := emergency.Commit(lease, RoleContraction, reserved.Sequence, authority); err != nil {
				t.Fatal(err)
			}
			emergencyFence := EmergencyStopFence{Kind: StopFenceContraction, OriginOperation: "emergency_close_all", ScopeKind: "installation", Generation: 2, GlobalGeneration: 1, SafetyIntentID: "emergency_close_all", SafetyIntentGeneration: 1, OwnershipDigest: digest("emergency-owner"), OwnedGraphDigest: digest("emergency-graph"), InventoryDigest: digest("emergency-inventory"), MasterStopped: true, WorkersStopped: true, ListenersStopped: true, ObservedUnix: time.Now().Unix()}
			authority.Sequence++
			authority.StopFenceSequence = 2
			authority.ReservedStopFenceKind = StopFenceContraction
			authority.ReservedStopFenceDigest = ""
			authority.StopFence = &emergencyFence
			if err := emergency.Commit(lease, RoleContraction, authority.Sequence-1, authority); err != nil {
				t.Fatal(err)
			}
			cleared := authority
			cleared.Sequence++
			cleared.StopFence = nil
			cleared.ClearProof = &EmergencyClearProof{Generation: 1, StopFenceGeneration: 2, StopFenceDigest: EmergencyFenceDigest(emergencyFence), InventoryDigest: emergencyFence.InventoryDigest, OwnedGraphDigest: emergencyFence.OwnedGraphDigest, RuntimeClosureDigest: digest("closure"), NginxTestPassed: true, RuntimeClosed: true}
			if err := emergency.Commit(lease, RoleJournalConvergence, authority.Sequence, cleared); err != nil {
				t.Fatal(err)
			}

			next := current
			next.Revision++
			next.AuthoritySequence = cleared.Sequence
			next.GlobalClose = cleared.GlobalClose
			next.StopFenceSequence = cleared.StopFenceSequence
			next.StopFence = nil
			next.Resources = append([]ResourceSafety(nil), current.Resources...)
			next.Resources[0].GenerationSequence++
			next.Resources[0].StickyUnpublished = &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: next.Resources[0].GenerationSequence, Reason: "closed"}
			next.Resources[0].Reactivating = nil
			journalRef := fence.CertificateActivation
			proof := &StopFenceConvergenceProof{Kind: fence.Kind, FenceGeneration: fence.FenceGeneration, FenceDigest: StopFenceDigest(fence), InventoryDigest: fence.InventoryDigest, OwnedGraphDigest: fence.OwnedGraphDigest, RuntimeClosureDigest: digest("closure"), AllChildrenExited: true, AllAppsUnpublished: true, NoAppDisk: true, WorkersDrained: true, ListenersClosed: true, RuntimeClosed: true, NginxTestPassed: true, UnpublishedGenerations: map[string]uint64{"app-one": next.Resources[0].GenerationSequence}}
			if fence.IngressActivation != nil {
				proof.JournalRef = fence.IngressActivation.IntentRef
			} else {
				proof.JournalRef = journalRef.JournalRef
			}
			if _, err := store.Commit(context.Background(), lease, RoleJournalConvergence, current.Revision, next, TransitionProof{StopFence: proof}); err != nil {
				t.Fatalf("store rejected exact activation recovery: %v", err)
			}
			persisted, err := store.Read()
			if err != nil {
				t.Fatal(err)
			}
			if persisted.StopFence != nil || persisted.StopFenceSequence != 2 || persisted.GlobalClose != cleared.GlobalClose {
				t.Fatalf("activation recovery did not converge: %#v", persisted)
			}
		})
	}
}

func TestStoreConvergesSupersededActivationReservation(t *testing.T) {
	store, emergency, manager, lease := newSafetyStore(t)
	defer closeSafetyStore(t, store, emergency, manager, lease)
	if _, err := store.Initialize(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	ownership := testOwnershipAuthority{"app-one": digest("owner")}
	store.config.Ownership = ownership
	current, fence := stateForFence(StopFenceIngressActivation)
	current.Revision = 1
	current.GlobalClose = GlobalClose{Phase: GlobalCloseNone}
	fence.SafetyGenerations = fence.SafetyGenerations[1:]
	fence.InventoryDigest = OwnershipInventoryDigest(map[string]string(ownership))
	current.StopFenceSequence = fence.FenceGeneration
	current.StopFence = &fence
	reserved, err := ReserveEmergencyStopFenceGeneration(lease, emergency, RoleIngressActivation, StopFenceIngressActivation, StopFenceDigest(fence), 0)
	if err != nil {
		t.Fatal(err)
	}
	current.AuthoritySequence = reserved.Sequence
	current.StopFenceSequence = reserved.StopFenceSequence
	if _, err := store.persist(context.Background(), current, filetxn.ReplaceOnly); err != nil {
		t.Fatal(err)
	}
	orphan := reserved
	orphan.Sequence++
	orphan.StopFenceSequence++
	orphan.ReservedStopFenceDigest = digest("orphan-reservation")
	if err := emergency.Commit(lease, RoleIngressActivation, reserved.Sequence, orphan); err != nil {
		t.Fatal(err)
	}

	next := current
	next.Revision++
	next.StopFenceSequence = orphan.StopFenceSequence
	next.StopFence = nil
	next.Resources = append([]ResourceSafety(nil), current.Resources...)
	next.Resources[0].GenerationSequence++
	next.Resources[0].Reactivating = nil
	next.Resources[0].StickyUnpublished = &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: next.Resources[0].GenerationSequence, Reason: "interrupted_domain_activation"}
	proof := &StopFenceConvergenceProof{Kind: fence.Kind, FenceGeneration: fence.FenceGeneration, FenceDigest: StopFenceDigest(fence), JournalRef: fence.IngressActivation.IntentRef, InventoryDigest: fence.InventoryDigest, OwnedGraphDigest: fence.OwnedGraphDigest, RuntimeClosureDigest: digest("closure"), AllChildrenExited: true, AllAppsUnpublished: true, NoAppDisk: true, WorkersDrained: true, ListenersClosed: true, RuntimeClosed: true, NginxTestPassed: true, UnpublishedGenerations: map[string]uint64{"app-one": next.Resources[0].GenerationSequence}}
	if _, err := store.Commit(context.Background(), lease, RoleJournalConvergence, current.Revision, next, TransitionProof{StopFence: proof}); err != nil {
		t.Fatalf("superseded activation reservation was not converged: %v", err)
	}
	persisted, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.StopFence != nil || persisted.StopFenceSequence != orphan.StopFenceSequence || persisted.AuthoritySequence != authority.Sequence || authority.ClearProof == nil {
		t.Fatalf("superseded activation reservation did not converge: state=%#v authority=%#v", persisted, authority)
	}
}

func TestHTTP01PresentationMayOnlyToggleExactTokenAuthorityWithinGeneration(t *testing.T) {
	base := stateWithResource()
	active := base
	active.Revision++
	active.Resources = append([]ResourceSafety(nil), base.Resources...)
	pending := *base.Resources[0].ChallengePending
	pending.Token = "abcdefghijklmnopqrstuv"
	pending.TokenPath = "/.well-known/acme-challenge/" + pending.Token
	pending.KeyAuthorizationDigest = digest("key-authorization")
	active.Resources[0].ChallengePending = &pending
	if err := validateTransition(RoleChallenge, base, active, TransitionProof{}); err != nil {
		t.Fatalf("tokenless-to-active HTTP-01 transition rejected: %v", err)
	}
	cleared := active
	cleared.Revision++
	cleared.Resources = append([]ResourceSafety(nil), active.Resources...)
	cleared.Resources[0].ChallengePending = base.Resources[0].ChallengePending
	if err := validateTransition(RoleChallenge, active, cleared, TransitionProof{}); err != nil {
		t.Fatalf("active-to-tokenless HTTP-01 transition rejected: %v", err)
	}
	changed := active
	changed.Revision++
	changed.Resources = append([]ResourceSafety(nil), active.Resources...)
	other := pending
	other.Token = "differentabcdefghijkl"
	other.TokenPath = "/.well-known/acme-challenge/" + other.Token
	changed.Resources[0].ChallengePending = &other
	if err := validateTransition(RoleChallenge, active, changed, TransitionProof{}); err == nil {
		t.Fatal("same-generation HTTP-01 token replacement was accepted")
	}
}

func TestCertificateHandoffAndHeadscaleConvergenceAreExact(t *testing.T) {
	current := stateWithResource()
	next := current
	next.Resources = append([]ResourceSafety(nil), current.Resources...)
	pending := next.Resources[0].ChallengePending
	next.Resources[0].ChallengePending = nil
	next.Resources[0].Reactivating = &Reactivating{Generation: pending.Generation, PriorGeneration: pending.Generation - 1, PlanID: pending.PlanID, CandidateDigest: pending.ConfigDigest, CandidateBundle: digest("bundle"), BaseMarkers: append([]MarkerSnapshot(nil), pending.BaseMarkers...), CertificateUntil: time.Now().UTC().Add(time.Hour)}
	if err := validateTransition(RoleCertificateHandoff, current, next, TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	changed := next
	changed.Resources = append([]ResourceSafety(nil), next.Resources...)
	active := *changed.Resources[0].Reactivating
	active.CandidateDigest = digest("other")
	changed.Resources[0].Reactivating = &active
	if err := validateTransition(RoleCertificateHandoff, current, changed, TransitionProof{}); err == nil {
		t.Fatal("mismatched App certificate handoff accepted")
	}

	now := time.Now().UTC()
	headscale := EmptyState()
	headscale.Headscale.GenerationSequence = 2
	headscale.Headscale.ControlEntryDigest = digest("control")
	headscale.Headscale.ActiveCertificate = &ActiveCertificateAuthority{Generation: 1, Fingerprint: digest("prior"), Binding: "binding", LastTrustedWall: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}
	headscale.Headscale.CertificateExpiry = &DeadlineMarker{Generation: 1, Deadline: now.Add(-time.Hour), Binding: "binding"}
	base := absentBaseSnapshot()
	base[2] = MarkerSnapshot{Kind: MarkerCertificateExpiry, State: SnapshotPresent, Generation: 1}
	headscale.Headscale.Reactivating = &HeadscaleReactivating{Generation: 2, PriorGeneration: 1, PlanID: "plan", ControlGeneration: 3, CertificateGeneration: 2, CertificateFingerprint: digest("candidate"), CandidateDigest: digest("config"), CandidateBundle: digest("bundle"), BaseMarkers: base, CertificateUntil: now.Add(time.Hour), CertificateLastTrustedWall: now}
	complete := headscale
	complete.Headscale.ActiveCertificate = &ActiveCertificateAuthority{Generation: 2, Fingerprint: digest("candidate"), Binding: "new-binding", LastTrustedWall: now, NotAfter: now.Add(time.Hour)}
	complete.Headscale.CertificateExpiry = nil
	complete.Headscale.Reactivating = nil
	intent := headscale.Headscale.Reactivating
	headscaleProof := &HeadscaleConvergenceProof{PlanID: intent.PlanID, Generation: intent.Generation, ControlGeneration: intent.ControlGeneration, CertificateGeneration: intent.CertificateGeneration, CertificateFingerprint: intent.CertificateFingerprint, CandidateDigest: intent.CandidateDigest, CandidateBundle: intent.CandidateBundle, RuntimeClosureDigest: digest("runtime")}
	if err := validateTransition(RolePublish, headscale, complete, TransitionProof{Headscale: headscaleProof}); err != nil {
		t.Fatal(err)
	}
	headscaleProof.CandidateBundle = digest("wrong")
	if err := validateTransition(RolePublish, headscale, complete, TransitionProof{Headscale: headscaleProof}); err == nil {
		t.Fatal("wrong Headscale candidate proof accepted")
	}
}

func TestGuardKeepsContractionMonotonicAndExpansionExact(t *testing.T) {
	state := stateWithResource()
	resource := &state.Resources[0]
	now := time.Now().UTC()
	challenge := Check(GuardInput{State: state, Action: ActionAppChallenge, ResourceID: resource.ResourceID, CandidateDigest: resource.ChallengePending.BootstrapIdentity, PlanID: resource.ChallengePending.PlanID, Generation: resource.ChallengePending.Generation, Now: now})
	if !challenge.Allowed || challenge.Priority != PriorityChallenge {
		t.Fatalf("challenge=%#v", challenge)
	}
	if decision := Check(GuardInput{State: state, Action: ActionPublish, ResourceID: resource.ResourceID, Now: now}); decision.Allowed {
		t.Fatal("ordinary publish bypassed challenge")
	}
	state.Resources = append(state.Resources, ResourceSafety{ResourceID: "resource-orphan", State: ResourceActive, Ownership: OwnershipOrphan, OwnershipDigest: digest("orphan")})
	if decision := Check(GuardInput{State: state, Action: ActionAppChallenge, ResourceID: resource.ResourceID, CandidateDigest: resource.ChallengePending.BootstrapIdentity, PlanID: resource.ChallengePending.PlanID, Generation: resource.ChallengePending.Generation, Now: now}); decision.Allowed || !strings.Contains(decision.Reason, "clean-host rebuild") {
		t.Fatalf("unrelated ownership orphan did not block App expansion: %#v", decision)
	}
	state.Resources = state.Resources[:1]
	state.GlobalClose = GlobalClose{Phase: GlobalCloseEmergency, Generation: 2}
	if decision := Check(GuardInput{State: state, Action: ActionAppChallenge, ResourceID: resource.ResourceID, CandidateDigest: resource.ChallengePending.BootstrapIdentity, PlanID: resource.ChallengePending.PlanID, Generation: resource.ChallengePending.Generation, Now: now}); decision.Allowed {
		t.Fatal("App challenge crossed global close")
	}
	if decision := Check(GuardInput{State: state, Action: ActionContraction, ResourceID: resource.ResourceID, Now: now}); !decision.Allowed {
		t.Fatal("contraction was blocked by a higher-priority marker")
	}
}

func TestUniqueClearersRemainClosed(t *testing.T) {
	checks := []struct {
		role   ClearRole
		target ClearTarget
		kind   StopFenceKind
	}{
		{RoleGlobalCloseConvergence, ClearGlobalClose, ""},
		{RoleJournalConvergence, ClearStopFence, StopFenceContraction},
		{RolePublish, ClearBaseContraction, ""},
		{RoleDelete, ClearDeletionTombstone, ""},
		{RoleChallenge, ClearChallenge, ""},
	}
	for _, check := range checks {
		if err := AuthorizeClear(check.role, check.target, check.kind); err != nil {
			t.Fatal(err)
		}
		if check.role != RoleContraction && AuthorizeClear(RoleContraction, check.target, check.kind) == nil {
			t.Fatalf("contraction role cleared %q", check.target)
		}
	}
}

func TestDeleteCommitAllowsOnlyExactOwnershipOverhang(t *testing.T) {
	for _, test := range []struct {
		name       string
		extraOwner bool
		wantErr    bool
	}{
		{name: "exact delete authority"},
		{name: "unrelated ownership remains", extraOwner: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, emergency, manager, lease := newSafetyStore(t)
			defer closeSafetyStore(t, store, emergency, manager, lease)
			if _, err := store.Initialize(context.Background(), lease); err != nil {
				t.Fatal(err)
			}
			current, err := store.Read()
			if err != nil {
				t.Fatal(err)
			}
			ownerDigest := digest("owner")
			authority := testOwnershipAuthority{"app-one": ownerDigest}
			if test.extraOwner {
				authority["app-two"] = digest("other-owner")
			}
			store.config.Ownership = authority
			current.Resources = []ResourceSafety{{ResourceID: "app-one", GenerationSequence: 1, State: ResourceDeleting, Ownership: OwnershipOwned, OwnershipDigest: ownerDigest, StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 1, Reason: "closed"}, DeletionTombstone: "delete/job-one"}}
			if _, err := store.persist(context.Background(), current, filetxn.ReplaceOnly); err != nil {
				t.Fatal(err)
			}
			next := current
			next.Revision++
			next.Resources = nil
			proof := &DeleteConvergenceProof{ResourceID: "app-one", TombstoneRef: "delete/job-one", OwnershipDigest: ownerDigest, RuntimeClosureDigest: digest("closure")}
			_, err = store.Commit(context.Background(), lease, RoleDelete, current.Revision, next, TransitionProof{Delete: proof})
			if test.wantErr {
				if err == nil {
					t.Fatal("delete accepted an unrelated ownership overhang")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Read(); err == nil {
				t.Fatal("ordinary safety read accepted the transitional ownership overhang")
			}
			if _, err := store.ReadForDeleteRecovery(lease, "app-one", ownerDigest); err != nil {
				t.Fatalf("delete recovery rejected its exact ownership overhang: %v", err)
			}
			if _, err := store.ReadForDeleteRecovery(lease, "app-one", digest("changed-owner")); err == nil {
				t.Fatal("delete recovery accepted a changed ownership overhang")
			}
			delete(authority, "app-one")
			if _, err := store.Read(); err != nil {
				t.Fatalf("safety authority did not converge after ownership-last removal: %v", err)
			}
		})
	}
}

func TestSafetyStoreBindsEmergencyHighWaterAndOwnership(t *testing.T) {
	store, emergency, manager, lease := newSafetyStore(t)
	defer closeSafetyStore(t, store, emergency, manager, lease)
	if _, err := store.Initialize(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	current, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	authority := emergency.Current()
	nextAuthority := authority
	nextAuthority.Sequence++
	nextAuthority.GlobalClose = GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}
	if err := emergency.Commit(lease, RoleContraction, authority.Sequence, nextAuthority); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); err == nil {
		t.Fatal("normal read accepted one-sided emergency generation")
	}
	next := current
	next.Revision++
	next.AuthoritySequence = nextAuthority.Sequence
	next.GlobalClose = nextAuthority.GlobalClose
	if _, err := store.Commit(context.Background(), lease, RoleContraction, current.Revision, next, TransitionProof{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.config.StatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); !errors.Is(err, ErrSafetyStateMissing) {
		t.Fatalf("missing state error=%v", err)
	}
	if _, err := store.Initialize(context.Background(), lease); err == nil {
		t.Fatal("initialized safety state was recreated")
	}
}

func TestEmergencyStopFenceReservationRejectsDigestReplacement(t *testing.T) {
	store, emergency, manager, lease := newSafetyStore(t)
	defer closeSafetyStore(t, store, emergency, manager, lease)
	first, err := ReserveEmergencyStopFenceGeneration(lease, emergency, RoleIngressActivation, StopFenceIngressActivation, digest("first"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveEmergencyStopFenceGeneration(lease, emergency, RoleIngressActivation, StopFenceIngressActivation, digest("second"), 0); err == nil {
		t.Fatal("reservation digest replacement was accepted")
	}
	current, err := emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if current.Sequence != first.Sequence || current.StopFenceSequence != first.StopFenceSequence || current.ReservedStopFenceDigest != first.ReservedStopFenceDigest {
		t.Fatalf("reservation changed after rejection: %#v", current)
	}
}

func TestEmergencyBackingDirectoryAllowsExpectedChildLinkChanges(t *testing.T) {
	emergency, manager, lease, path := newEmergencyStore(t)
	defer func() {
		_ = emergency.Close()
		_ = lease.Release()
		_ = manager.Close()
	}()
	child := filepath.Join(filepath.Dir(path), "operation")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(child); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove test child: %v", err)
		}
	}()
	if _, err := emergency.Authority(); err != nil {
		t.Fatalf("directory link-count change invalidated emergency backing: %v", err)
	}
}

func TestEmergencyBackingPersistsExactContractionOrigin(t *testing.T) {
	store, manager, lease, path := newEmergencyStore(t)
	fence := EmergencyStopFence{Kind: StopFenceContraction, OriginOperation: "emergency_close_all", ScopeKind: "installation", Generation: 1, GlobalGeneration: 1, SafetyIntentID: "emergency_close_all", SafetyIntentGeneration: 1, OwnershipDigest: digest("owner"), OwnedGraphDigest: digest("graph"), InventoryDigest: digest("inventory"), ObservedUnix: time.Now().Unix(), AccessMayRemain: true}
	current := store.Current()
	next := current
	next.Sequence++
	next.GlobalClose = GlobalClose{Phase: GlobalCloseEmergency, Generation: 1}
	if err := store.Commit(lease, RoleContraction, current.Sequence, next); err != nil {
		t.Fatal(err)
	}
	current = next
	next.Sequence++
	next.StopFenceSequence = 1
	next.ReservedStopFenceKind = StopFenceContraction
	next.StopFence = &fence
	if err := store.Commit(lease, RoleContraction, current.Sequence, next); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenEmergency(path, filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	persisted := reopened.Current()
	if persisted.StopFence == nil || persisted.StopFence.SafetyIntentID != fence.SafetyIntentID || persisted.StopFence.SafetyIntentGeneration != fence.SafetyIntentGeneration {
		t.Fatal("emergency contraction origin identity was not persisted")
	}
	_ = reopened.Close()
	_ = lease.Release()
	_ = manager.Close()
}

func stateForFence(kind StopFenceKind) (State, StopFence) {
	state := EmptyState()
	state.GlobalClose = GlobalClose{Phase: GlobalCloseClosing, Generation: 1}
	fence := validStopFence(kind)
	switch kind {
	case StopFenceIngressActivation:
		fence.Scope = FenceScope{Kind: "app", ResourceID: "app-one"}
		fence.SafetyGenerations = append(fence.SafetyGenerations, MarkerGeneration{Kind: "reactivating", Generation: 2})
		state.Resources = []ResourceSafety{{ResourceID: "app-one", GenerationSequence: 2, State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), Reactivating: &Reactivating{Generation: 2, PriorGeneration: 1, PlanID: "intent", CandidateDigest: digest("candidate"), CandidateBundle: digest("bundle"), BaseMarkers: absentBaseSnapshot(), CertificateUntil: time.Now().Add(time.Hour)}}}
	case StopFenceCertificateActivation:
		fence.Scope = FenceScope{Kind: "app", ResourceID: "app-one"}
		fence.SafetyGenerations = append(fence.SafetyGenerations, MarkerGeneration{Kind: "certificate_expiry", Generation: 2})
		fence.CertificateActivation.ResourceGeneration = 2
		fence.CertificateActivation.ExpiryGeneration = 2
		state.Resources = []ResourceSafety{{ResourceID: "app-one", GenerationSequence: 2, State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), ActiveCertificate: &ActiveCertificateAuthority{Generation: 1, Fingerprint: digest("certificate"), Binding: "binding", LastTrustedWall: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, CertificateExpiry: &DeadlineMarker{Generation: 2, Deadline: time.Now(), Binding: "binding"}}}
	}
	return state, fence
}

func validStopFence(kind StopFenceKind) StopFence {
	fence := StopFence{Kind: kind, OriginOperation: "operation", Scope: FenceScope{Kind: "installation"}, FenceGeneration: 1, CreatedAt: time.Unix(100, 0).UTC(), SafetyGenerations: []MarkerGeneration{{Kind: "global_close", Generation: 1}}, OwnedGraphDigest: digest("graph"), InventoryDigest: digest("inventory"), Observation: StopObservation{ObservedAt: time.Unix(101, 0).UTC()}, AccessMayRemain: true}
	switch kind {
	case StopFenceContraction:
		fence.Contraction = &ContractionFence{Authorities: []MarkerGeneration{{Kind: "global_close", Generation: 1}}, OwnershipDigest: digest("owner"), OperationRef: "intent/job-one"}
	case StopFenceIngressActivation:
		fence.IngressActivation = &IngressActivationFence{IntentRef: "intent", CandidateGeneration: 2, PriorGeneration: 1}
	case StopFenceCertificateActivation:
		fence.CertificateActivation = &CertificateActivationFence{JournalRef: "journal", ResourceGeneration: 2, PriorPointer: digest("prior"), CandidatePointer: digest("candidate"), ExpiryGeneration: 2}
	}
	return fence
}

func absentBaseSnapshot() []MarkerSnapshot {
	return []MarkerSnapshot{{Kind: MarkerStickyUnpublished, State: SnapshotAbsent}, {Kind: MarkerContraction, State: SnapshotAbsent}, {Kind: MarkerCertificateExpiry, State: SnapshotAbsent}}
}

func stateWithResource() State {
	snapshots := []MarkerSnapshot{{Kind: MarkerStickyUnpublished, State: SnapshotPresent, Generation: 1}, {Kind: MarkerContraction, State: SnapshotAbsent}, {Kind: MarkerCertificateExpiry, State: SnapshotAbsent}}
	return State{SchemaVersion: SchemaVersion, Revision: 1, AuthoritySequence: 1, GlobalClose: GlobalClose{Phase: GlobalCloseNone}, Resources: []ResourceSafety{{ResourceID: "app-one", GenerationSequence: 1, State: ResourceActive, Ownership: OwnershipOwned, OwnershipDigest: digest("owner"), StickyUnpublished: &GenerationMarker{Kind: MarkerStickyUnpublished, Generation: 1, Reason: "initial"}, ChallengePending: &ChallengePending{Generation: 1, PlanID: "plan", Method: "http-01", ConfigDigest: digest("config"), SANIdentity: digest("san"), ACMEBinding: digest("acme"), CertificateIdentity: "cert-one", Host: "app.example.com", Hosts: []string{"app.example.com"}, Webroot: "/var/lib/lanpanel/certificates/webroot/cert-one", BootstrapIdentity: digest("bootstrap"), BaseMarkers: snapshots}}}}
}

func digest(seed string) string {
	value := 'a'
	if seed != "" {
		value = rune("abcdef0123456789"[len(seed)%16])
	}
	return "sha256:" + strings.Repeat(string(value), 64)
}

type testOwnershipAuthority map[string]string

func (authority testOwnershipAuthority) InventoryAuthority() (map[string]string, bool, error) {
	copy := make(map[string]string, len(authority))
	for id, value := range authority {
		copy[id] = value
	}
	return copy, true, nil
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
	emergency, err := CreateEmergency(filepath.Join(root, "emergency.slots"), owner, EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(StoreConfig{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "state.json"), Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: testOwnershipAuthority{}})
	if err != nil {
		t.Fatal(err)
	}
	return store, emergency, manager, lease
}

func closeSafetyStore(t *testing.T, store *Store, emergency *EmergencyStore, manager *locks.Manager, lease *locks.Lease) {
	t.Helper()
	_ = store.Close()
	_ = emergency.Close()
	_ = lease.Release()
	_ = manager.Close()
}

func newEmergencyStore(t *testing.T) (*EmergencyStore, *locks.Manager, *locks.Lease, string) {
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
	store, err := CreateEmergency(path, owner, EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	return store, manager, lease, path
}
