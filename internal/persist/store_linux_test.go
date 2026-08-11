//go:build linux

package persist

import (
	"context"
	"encoding/json"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionedNormalTransaction(t *testing.T) {
	t.Run("atomic_compare_and_swap_preserves_entries", func(t *testing.T) {
		store, manager, admission := newTestStore(t)
		defer closeTestStore(t, store, manager, admission)
		if _, err := store.Initialize(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
		unrelatedRoot := t.TempDir()
		_ = os.Chmod(unrelatedRoot, 0o700)
		unrelatedManager, err := locks.Open(locks.Config{RootPath: unrelatedRoot, Owner: uint32(os.Geteuid()), Group: uint32(os.Getegid()), Mode: 0o700})
		if err != nil {
			t.Fatal(err)
		}
		unrelated, err := unrelatedManager.Acquire(context.Background(), locks.MutationAdmission)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Update(context.Background(), unrelated, 1, func(*Transaction) error { return nil }); err == nil {
			t.Fatal("normal store accepted unrelated lock authority")
		}
		_ = unrelated.Release()
		_ = unrelatedManager.Close()
		document, err := store.Read()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := EncodeEntry(struct {
			Value string `json:"value"`
		}{Value: "one"})
		next, result, err := store.Update(context.Background(), admission, document.Revision, func(transaction *Transaction) error { return transaction.Create("fixtures/one", raw) })
		if err != nil || result.State != filetxn.StateDurable || next.Revision != 2 {
			t.Fatalf("Update()=%#v,%#v,%v", next, result, err)
		}
		if _, _, err := store.Update(context.Background(), admission, document.Revision, func(*Transaction) error { return nil }); !errors.Is(err, ErrRevision) {
			t.Fatalf("stale Update() error=%v", err)
		}
		if _, _, err := store.Update(context.Background(), admission, next.Revision, func(transaction *Transaction) error {
			raw, _ := EncodeEntry(struct {
				Value string `json:"value"`
			}{"bad"})
			return transaction.Create("unknown/item", raw)
		}); err == nil {
			t.Fatal("unregistered normal namespace was accepted")
		}
		if _, _, err := store.Update(context.Background(), admission, next.Revision, func(transaction *Transaction) error {
			raw, _ := EncodeEntry(struct {
				Value string `json:"value"`
			}{"rewrite"})
			return transaction.Replace("fixtures/one", raw)
		}); err == nil {
			t.Fatal("namespace without transition owner rewrote entry")
		}
		loaded, err := store.Read()
		if err != nil {
			t.Fatal(err)
		}
		value, present, err := DecodeEntry[struct {
			Value string `json:"value"`
		}](loaded, "fixtures/one")
		if err != nil || !present || value.Value != "one" {
			t.Fatalf("DecodeEntry()=%#v,%v,%v", value, present, err)
		}
	})

	t.Run("typed_resource_state_rejects_applied_generation_rewrite", func(t *testing.T) {
		store, manager, admission := newTestStore(t)
		defer closeTestStore(t, store, manager, admission)
		if _, err := store.Initialize(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
		installation := validInstallation()
		raw, _ := EncodeEntry(installation)
		if _, _, err := store.Update(context.Background(), admission, 1, func(transaction *Transaction) error { return transaction.Create("installations/current", raw) }); err != nil {
			t.Fatal(err)
		}
		installation.Resources[0].Name = "Renamed"
		installation.Resources[0].CurrentConfigDigest = "sha256:" + strings.Repeat("b", 64)
		raw, _ = EncodeEntry(installation)
		if _, _, err := store.Update(context.Background(), admission, 2, func(transaction *Transaction) error { return transaction.Replace("installations/current", raw) }); err != nil {
			t.Fatalf("config-only transition rejected: %v", err)
		}
		installation.Resources[0].PublicationRecord.UnpublishedGeneration = 1
		raw, _ = EncodeEntry(installation)
		if _, _, err := store.Update(context.Background(), admission, 3, func(transaction *Transaction) error { return transaction.Replace("installations/current", raw) }); err == nil {
			t.Fatal("normal transaction rewrote applied unpublished generation without operation intent")
		}
	})

	t.Run("missing_corrupt_and_unauthorized_writes_fail_closed", func(t *testing.T) {
		store, manager, admission := newTestStore(t)
		defer closeTestStore(t, store, manager, admission)
		if _, err := store.Read(); !errors.Is(err, ErrMissing) {
			t.Fatalf("Read(missing)=%v", err)
		}
		if _, err := store.Initialize(context.Background(), nil); err == nil {
			t.Fatal("Initialize without lock succeeded")
		}
		if _, err := store.Initialize(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.config.StatePath, []byte(`{"schema_version":"lanpanel.normal.v1"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); err == nil {
			t.Fatal("Read accepted corrupt normal state")
		}
	})

	t.Run("durable_acknowledgement_and_ambiguous_namespace_are_reconciled", func(t *testing.T) {
		armed := false
		fault := func(point filetxn.Point) error {
			if armed && point == filetxn.PointAfterDirectorySync {
				armed = false
				return errors.New("lost durable acknowledgement")
			}
			return nil
		}
		store, manager, admission := newTestStore(t, fault)
		defer closeTestStore(t, store, manager, admission)
		if _, err := store.Initialize(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
		document, _ := store.Read()
		raw, _ := EncodeEntry(struct {
			Value string `json:"value"`
		}{"durable"})
		armed = true
		next, result, err := store.Update(context.Background(), admission, document.Revision, func(transaction *Transaction) error { return transaction.Create("fixtures/durable", raw) })
		if err != nil || result.State != filetxn.StateDurable || next.Revision != 2 {
			t.Fatalf("durable reconciliation=%#v,%#v,%v", next, result, err)
		}
	})

	t.Run("readable_store_with_failed_durable_admission_issues_one_use_proof", func(t *testing.T) {
		armed := false
		fault := func(point filetxn.Point) error {
			if armed && point == filetxn.PointBeforeWrite {
				armed = false
				return errors.New("state filesystem became unwritable")
			}
			return nil
		}
		root := t.TempDir()
		_ = os.Chmod(root, 0o700)
		staging := filepath.Join(root, "staging")
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Fatal(err)
		}
		lockRoot := t.TempDir()
		_ = os.Chmod(lockRoot, 0o700)
		owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
		manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
		if err != nil {
			t.Fatal(err)
		}
		defer manager.Close()
		admission, err := manager.Acquire(context.Background(), locks.MutationAdmission)
		if err != nil {
			t.Fatal(err)
		}
		defer admission.Release()
		store, err := Open(Config{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "normal.json"), Owner: owner, Fault: fault, LockAuthority: manager.Authority()})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		validator := func(string, json.RawMessage) error { return nil }
		for namespace, owner := range map[string]string{"plans": "plans.v1", "jobs": "jobs.v1", "intents": "operations.intents.v1", "children": "operations.children.v1", "journals": "operations.journals.v1"} {
			if err := store.RegisterCanonicalNamespace(namespace, owner, validator, nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.RegisterCanonicalDocumentValidator("operations.links.v1", func(Document) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := store.RegisterCanonicalDocumentTransitionValidator("operations.resource_transitions.v1", func(Document, Document) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := store.RegisterCanonicalDocumentTransitionValidator("plans.retention.v1", func(Document, Document) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := store.SealSchema(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Initialize(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
		armed = true
		if _, _, err := store.Update(context.Background(), admission, 1, func(*Transaction) error { return nil }); err == nil {
			t.Fatal("unrelated failed normal write was reported as success")
		}
		if _, err := store.ProveUnavailable(); err == nil {
			t.Fatal("unrelated failed normal write opened the no-job exception")
		}
		armed = true
		if _, _, err := store.Update(context.Background(), admission, 1, func(transaction *Transaction) error {
			if err := transaction.Create("jobs/job-one", json.RawMessage(`{"id":"job-one"}`)); err != nil {
				return err
			}
			return transaction.Create("intents/job-one", json.RawMessage(`{"job_id":"job-one","phase":"reserved"}`))
		}); err == nil {
			t.Fatal("failed durable admission write was reported as success")
		}
		if document, err := store.Read(); err != nil || document.Revision != 1 {
			t.Fatalf("readable normal store after failed write = %#v, %v", document, err)
		}
		proof, err := store.ProveUnavailable()
		if err != nil || !store.ValidateUnavailable(proof) {
			t.Fatalf("failed durable admission proof = %#v, %v", proof, err)
		}
		if store.ValidateUnavailable(proof) {
			t.Fatal("durable admission failure proof was reusable")
		}
		if _, err := store.ProveUnavailable(); err == nil {
			t.Fatal("one failed write minted more than one exception proof")
		}
		if _, _, err := store.Update(context.Background(), admission, 1, func(*Transaction) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ProveUnavailable(); err == nil {
			t.Fatal("successful normal write did not clear failed-admission proof")
		}
	})

	t.Run("namespace_changed_latches_writes_until_explicit_reconcile", func(t *testing.T) {
		armed := false
		fault := func(point filetxn.Point) error {
			if armed && point == filetxn.PointAfterRename {
				armed = false
				return errors.New("crash after rename")
			}
			return nil
		}
		store, manager, admission := newTestStore(t, fault)
		defer closeTestStore(t, store, manager, admission)
		if _, err := store.Initialize(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
		document, _ := store.Read()
		raw, _ := EncodeEntry(struct {
			Value string `json:"value"`
		}{"changed"})
		armed = true
		_, result, err := store.Update(context.Background(), admission, document.Revision, func(transaction *Transaction) error { return transaction.Create("fixtures/changed", raw) })
		if !errors.Is(err, ErrRecoveryRequired) || result.State != filetxn.StateNamespaceChanged {
			t.Fatalf("namespace result=%#v,%v", result, err)
		}
		if _, _, err := store.Update(context.Background(), admission, document.Revision, func(*Transaction) error { return nil }); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("latched Update()=%v", err)
		}
		reconciled, err := store.Reconcile()
		if err != nil || reconciled.Revision != 2 {
			t.Fatalf("Reconcile()=%#v,%v", reconciled, err)
		}
	})
}

func validInstallation() domain.Installation {
	return domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.23.45.67", Port: 23456, ManagedPaths: []string{"/var/lib/lanpanel/ui"}}, Resources: []domain.AppResource{{ID: "res_00000000000000000000000000000001", Name: "App", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: "sha256:" + strings.Repeat("a", 64), Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", WebSocket: domain.WebSocketReadiness{}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.com", AccessMode: domain.AppAccessPublic}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 2}, ManagedProcess: &domain.ManagedProcess{ID: "proc_00000000000000000000000000000001", Requested: domain.ProcessRequestedStopped}}}}
}

func newTestStore(t *testing.T, faults ...filetxn.FaultFunc) (*Store, *locks.Manager, *locks.Lease) {
	t.Helper()
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	lockRoot := t.TempDir()
	_ = os.Chmod(lockRoot, 0o700)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	var fault filetxn.FaultFunc
	if len(faults) != 0 {
		fault = faults[0]
	}
	store, err := Open(Config{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "normal.json"), Owner: owner, Fault: fault, LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterNamespace("fixtures", func(_ string, value json.RawMessage) error {
		if !json.Valid(value) {
			return errors.New("invalid fixture")
		}
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	return store, manager, admission
}

func closeTestStore(t *testing.T, store *Store, manager *locks.Manager, admission *locks.Lease) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Error(err)
	}
	if err := admission.Release(); err != nil {
		t.Error(err)
	}
	if err := manager.Close(); err != nil {
		t.Error(err)
	}
}
