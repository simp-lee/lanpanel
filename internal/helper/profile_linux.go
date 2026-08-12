//go:build linux

package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
)

const (
	fixedNormalStateRoot    = "/var/lib/lanpanel/state"
	fixedNormalStateStaging = "/var/lib/lanpanel/state/.filetxn"
	fixedNormalStatePath    = "/var/lib/lanpanel/state/normal.json"
	fixedLockRoot           = "/var/lib/lanpanel/locks"
)

func managementProfile() string {
	manager, err := locks.Open(locks.Config{RootPath: fixedLockRoot, Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return "unavailable"
	}
	defer manager.Close()
	if validateIndependentAuthority(manager) != nil {
		return "unavailable"
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	store, err := persist.Open(persist.Config{RootPath: fixedNormalStateRoot, StagingPath: fixedNormalStateStaging, StatePath: fixedNormalStatePath, Owner: owner, LockAuthority: manager.Authority()})
	if err != nil {
		return "emergency"
	}
	defer store.Close()
	if _, err := store.Read(); err != nil {
		return "emergency"
	}
	return "normal"
}
func validateIndependentAuthority(manager *locks.Manager) error {
	owner := filetxn.Owner{UID: 0, GID: 0}
	ownershipStore, err := ownership.Open(ownership.Config{RootPath: "/var/lib/lanpanel/ownership", StagingPath: "/var/lib/lanpanel/ownership/.filetxn", RecordsPath: "/var/lib/lanpanel/ownership/records", Owner: owner, Policy: ownership.Policy{ManagedRoots: []string{"/etc/lanpanel", "/var/lib/lanpanel"}}, LockAuthority: manager.Authority()})
	if err != nil {
		return err
	}
	defer ownershipStore.Close()
	if _, complete, err := ownershipStore.InventoryAuthority(); err != nil || !complete {
		return fmt.Errorf("ownership authority unavailable")
	}
	emergency, err := safety.OpenEmergency("/var/lib/lanpanel/safety/emergency", owner, safety.EmergencyOptions{LockAuthority: manager.Authority()})
	if err != nil {
		return err
	}
	defer emergency.Close()
	store, err := safety.OpenStore(safety.StoreConfig{RootPath: "/var/lib/lanpanel/safety", StagingPath: "/var/lib/lanpanel/safety/.filetxn", StatePath: "/var/lib/lanpanel/safety/state.json", Owner: owner, Emergency: emergency, LockAuthority: manager.Authority(), Ownership: ownershipStore})
	if err != nil {
		return err
	}
	defer store.Close()
	_, err = store.Read()
	return err
}
func profileDigest(profile string) string {
	digest := sha256.Sum256([]byte("lanpanel.management.profile/" + profile))
	return "sha256:" + hex.EncodeToString(digest[:])
}
