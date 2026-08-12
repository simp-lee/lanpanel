package contraction

import (
	"context"
	"lanpanel/internal/closure"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"testing"
)

type emptyOwnershipAuthority struct{}

func (emptyOwnershipAuthority) InventoryAuthority() (map[string]string, bool, error) {
	return map[string]string{}, true, nil
}

func TestStopFenceProjectsCommittedEmergencyGlobalAuthority(t *testing.T) {
	root := t.TempDir()
	lockRoot := filepath.Join(root, "locks")
	safetyRoot := filepath.Join(root, "safety")
	for _, path := range []string{lockRoot, safetyRoot, filepath.Join(safetyRoot, "staging")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	exposure, err := manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		t.Fatal(err)
	}
	defer exposure.Release()
	emergency, err := safety.CreateEmergency(filepath.Join(safetyRoot, "emergency.slots"), owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	defer emergency.Close()
	store, err := safety.OpenStore(safety.StoreConfig{RootPath: safetyRoot, StagingPath: filepath.Join(safetyRoot, "staging"), StatePath: filepath.Join(safetyRoot, "state.json"), Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: emptyOwnershipAuthority{}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Initialize(context.Background(), exposure); err != nil {
		t.Fatal(err)
	}
	staleNormal, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	emergencyState, err := emergency.Authority()
	if err != nil {
		t.Fatal(err)
	}
	emergencyNext := emergencyState
	emergencyNext.Sequence++
	emergencyNext.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseClosing, Generation: 1}
	if err := emergency.Commit(exposure, safety.RoleContraction, emergencyState.Sequence, emergencyNext); err != nil {
		t.Fatal(err)
	}
	inventory := closure.Inventory{Digest: testDigest("graph"), FullOwnershipDigest: safety.OwnershipInventoryDigest(map[string]string{}), ResourceOwnership: map[string]string{}}
	authority := NormalAuthority{Safety: store, Emergency: emergency, Exposure: exposure, SafetyState: staleNormal, Generations: map[string]uint64{}, Global: true, InventoryDigest: inventory.Digest}
	if err := authority.PersistStopFence(context.Background(), inventory); err != nil {
		t.Fatal(err)
	}
	if authority.SafetyState.StopFence == nil || authority.SafetyState.GlobalClose != emergencyNext.GlobalClose || authority.SafetyState.StopFence.Scope.Kind != "installation" {
		t.Fatalf("projected safety=%#v", authority.SafetyState)
	}
	current, err := emergency.Authority()
	if err != nil || current.StopFence == nil || current.StopFence.GlobalGeneration != 1 {
		t.Fatalf("emergency=%#v error=%v", current, err)
	}
}
