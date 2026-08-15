package ownership

import (
	"context"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixedPolicyIncludesCompleteGoAccessClosure(t *testing.T) {
	policy := FixedPolicy()
	for _, required := range []string{"/etc/systemd/system", "/etc/sysusers.d", "/var/log/lanpanel", "/run/lanpanel", "/run/lanpanel-goaccess"} {
		found := false
		for _, root := range policy.ManagedRoots {
			if root == required {
				found = true
			}
		}
		if !found {
			t.Fatalf("fixed ownership policy missing %s", required)
		}
	}
	roots, err := validatePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManagedPath("/run/lanpanel-goaccess/res_00000000000000000000000000000001-2.sock", roots); err != nil {
		t.Fatal(err)
	}
}

func TestGoAccessRetirementWriterAcceptsOnlyExactGenerationClosure(t *testing.T) {
	resourceID := "res_00000000000000000000000000000001"
	generation := "2"
	unitID := resourceID + "-" + generation
	paths := []string{"/etc/systemd/system/lanpanel-goaccess-" + unitID + ".service", "/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-" + unitID + ".service", "/etc/systemd/system/lanpanel-goaccess-relay-" + unitID + ".service", "/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-relay-" + unitID + ".service", "/etc/systemd/system/lanpanel-goaccess-" + unitID + ".socket", "/etc/systemd/system/sockets.target.wants/lanpanel-goaccess-" + unitID + ".socket", "/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".service", "/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".timer", "/etc/systemd/system/timers.target.wants/lanpanel-goaccess-retention-" + unitID + ".timer", "/run/lanpanel-goaccess/" + unitID + ".sock", "/var/lib/lanpanel/goaccess/" + resourceID + "/generations/2"}
	current := Record{ResourceID: resourceID, State: Owned, Paths: []OwnedPath{}}
	for _, path := range paths {
		current.Paths = append(current.Paths, OwnedPath{Kind: PathService, Path: path, IdentityDigest: PathIdentity(resourceID, PathService, path)})
	}
	next := current
	next.Paths = []OwnedPath{}
	if !exactGoAccessRetirement(current, next) {
		t.Fatal("exact GoAccess retirement rejected")
	}
	unsafe := next
	unsafe.Paths = append(unsafe.Paths, current.Paths[0])
	if exactGoAccessRetirement(current, unsafe) {
		t.Fatal("partial GoAccess retirement accepted")
	}
	shared := []string{"/etc/sysusers.d/lanpanel-goaccess-" + resourceID + ".conf", "/var/log/lanpanel/goaccess/" + resourceID, "/var/log/lanpanel/goaccess/" + resourceID + "/.retention.lock"}
	rollbackCurrent := current
	for _, path := range shared {
		rollbackCurrent.Paths = append(rollbackCurrent.Paths, OwnedPath{Kind: PathService, Path: path, IdentityDigest: PathIdentity(resourceID, PathService, path)})
	}
	if !exactGoAccessCandidateRollback(rollbackCurrent, next) {
		t.Fatal("exact first-candidate rollback rejected")
	}
}

func TestOwnershipEvidenceContract(t *testing.T) {
	t.Run("atomic_record_inventory_and_orphan_classification", func(t *testing.T) {
		store, manager, lease, record := newTestStore(t)
		defer closeTestStore(t, store, manager, lease)
		result, err := store.Write(context.Background(), lease, ActivationWriter, 0, record)
		if err != nil || result.State != filetxn.StateDurable {
			t.Fatalf("Write() = %#v, %v", result, err)
		}
		inventory, err := store.Inventory()
		if err != nil || !inventory.Complete || len(inventory.Records) != 1 {
			t.Fatalf("Inventory() = %#v, %v", inventory, err)
		}
		if inventory.Records[0].Checksum == "" {
			t.Fatal("persisted record lacks checksum")
		}
		orphan := Classify(inventory.Records[0], false)
		if orphan.State != OwnershipOrphaned || orphan.Checksum != "" {
			t.Fatalf("Classify() = %#v", orphan)
		}
		orphan.Revision++
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 1, orphan); err == nil || !strings.Contains(err.Error(), "derived read-only") {
			t.Fatalf("Write(derived orphan) error = %v", err)
		}
		persisted, err := store.Read(record.ResourceID)
		if err != nil || persisted.State != Owned || persisted.Revision != 1 {
			t.Fatalf("Read() after rejected orphan write = %#v, %v", persisted, err)
		}
	})

	t.Run("forged_path_and_wrong_writer_are_rejected", func(t *testing.T) {
		store, manager, lease, record := newTestStore(t)
		defer closeTestStore(t, store, manager, lease)
		record.Paths[0].Path = "/etc/passwd"
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 0, record); err == nil || !strings.Contains(err.Error(), "outside fixed") {
			t.Fatalf("Write(forged path) error = %v", err)
		}
		record.Paths[0].Path = filepath.Join(store.config.Policy.ManagedRoots[0], "site.conf")
		if _, err := store.Write(context.Background(), nil, ActivationWriter, 0, record); err == nil {
			t.Fatal("Write() without exposure lease succeeded")
		}
		if _, err := store.Write(context.Background(), lease, WriterRole("other"), 0, record); err == nil {
			t.Fatal("Write() with unknown writer succeeded")
		}
		otherRoot := t.TempDir()
		if err := os.Chmod(otherRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		otherManager, err := locks.Open(locks.Config{RootPath: otherRoot, Owner: store.config.Owner.UID, Group: store.config.Owner.GID, Mode: 0o700})
		if err != nil {
			t.Fatal(err)
		}
		defer otherManager.Close()
		otherLease, err := otherManager.Acquire(context.Background(), locks.Exposure)
		if err != nil {
			t.Fatal(err)
		}
		defer otherLease.Release()
		if _, err := store.Write(context.Background(), otherLease, ActivationWriter, 0, record); err == nil {
			t.Fatal("Write() accepted an exposure lease from another installation authority")
		}
	})

	t.Run("corrupt_or_symlink_record_is_never_inventory_authority", func(t *testing.T) {
		store, manager, lease, record := newTestStore(t)
		defer closeTestStore(t, store, manager, lease)
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 0, record); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(store.config.RecordsPath, record.ResourceID+".json")
		if err := os.WriteFile(path, []byte(`{"schema_version":"lanpanel.ownership.v1"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		inventory, err := store.Inventory()
		if err != nil || inventory.Complete || len(inventory.Records) != 0 || len(inventory.Issues) != 1 {
			t.Fatalf("corrupt Inventory() = %#v, %v", inventory, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/passwd", path); err != nil {
			t.Fatal(err)
		}
		inventory, err = store.Inventory()
		if err != nil || inventory.Complete || len(inventory.Records) != 0 {
			t.Fatalf("symlink Inventory() = %#v, %v", inventory, err)
		}
	})

	t.Run("activation_updates_are_monotonic_and_never_narrow_inventory", func(t *testing.T) {
		store, manager, lease, record := newTestStore(t)
		defer closeTestStore(t, store, manager, lease)
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 0, record); err != nil {
			t.Fatal(err)
		}
		narrowed := record
		narrowed.Revision = 2
		narrowed.Listeners = nil
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 1, narrowed); err == nil {
			t.Fatal("activation update narrowed listener inventory")
		}
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 0, record); err == nil {
			t.Fatal("stale create-only ownership write succeeded")
		}
		next := record
		next.Revision = 2
		path := filepath.Join(store.config.Policy.ManagedRoots[0], "challenge")
		next.Paths = append(next.Paths, OwnedPath{Kind: PathChallenge, Path: path, IdentityDigest: PathIdentity(record.ResourceID, PathChallenge, path)})
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 1, next); err != nil {
			t.Fatalf("monotonic Write() error = %v", err)
		}
		next.Revision = 3
		next.Listeners[0].IdentityDigest = "sha256:" + strings.Repeat("a", 64)
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 2, next); err == nil {
			t.Fatal("Write() accepted caller-fabricated listener identity")
		}
	})

	t.Run("cross_resource_physical_collisions_are_rejected", func(t *testing.T) {
		store, manager, lease, record := newTestStore(t)
		defer closeTestStore(t, store, manager, lease)
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 0, record); err != nil {
			t.Fatal(err)
		}
		other := record
		other.ResourceID = "app-b"
		other.Revision = 1
		nested := filepath.Join(record.Paths[0].Path, "child")
		other.Paths = []OwnedPath{{Kind: PathSite, Path: nested, IdentityDigest: PathIdentity(other.ResourceID, PathSite, nested)}}
		other.Listeners = nil
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 0, other); err == nil {
			t.Fatal("Write() accepted nested cross-resource path collision")
		}
		distinct := filepath.Join(store.config.Policy.ManagedRoots[0], "other.conf")
		other.Paths = []OwnedPath{{Kind: PathSite, Path: distinct, IdentityDigest: PathIdentity(other.ResourceID, PathSite, distinct)}}
		other.Listeners = []OwnedListener{{Protocol: "tcp", Address: "127.0.0.1", Port: 443}}
		other.Listeners[0].IdentityDigest = ListenerIdentity(other.ResourceID, other.Listeners[0].Protocol, other.Listeners[0].Address, other.Listeners[0].Port)
		if _, err := store.Write(context.Background(), lease, ActivationWriter, 0, other); err == nil {
			t.Fatal("Write() accepted wildcard/specific cross-resource listener collision")
		}
	})

}

func newTestStore(t *testing.T) (*Store, *locks.Manager, *locks.Lease, Record) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	records := filepath.Join(root, "records")
	managed := filepath.Join(root, "managed")
	for _, path := range []string{staging, records, managed} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	lockRoot := t.TempDir()
	if err := os.Chmod(lockRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{RootPath: root, StagingPath: staging, RecordsPath: records, Owner: owner, Policy: Policy{ManagedRoots: []string{managed}}, LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(managed, "site.conf")
	record := Record{SchemaVersion: SchemaVersion, Revision: 1, ResourceID: "app-one", State: Owned,
		Paths:     []OwnedPath{{Kind: PathSite, Path: path, IdentityDigest: PathIdentity("app-one", PathSite, path)}},
		Listeners: []OwnedListener{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, IdentityDigest: ListenerIdentity("app-one", "tcp", "0.0.0.0", 443)}},
	}
	return store, manager, lease, record
}

func closeTestStore(t *testing.T, store *Store, manager *locks.Manager, lease *locks.Lease) {
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
