package plans

import (
	"bytes"
	"context"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestImmutablePlans(t *testing.T) {
	t.Run("single_use_expiry_and_stale_binding", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		normal, manager, admission := newPlanNormalStore(t)
		defer closePlanNormalStore(t, normal, manager, admission)
		store, err := NewStore(normal, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64))})
		if err != nil {
			t.Fatal(err)
		}
		spec := validSpec(now)
		plan, err := store.Create(context.Background(), admission, 1, spec)
		if err != nil {
			t.Fatal(err)
		}
		binding := bindingFor(plan)
		if err := ValidateBindingFreshness(binding, now.Add(MaximumEvidenceAge+time.Second)); err == nil {
			t.Fatal("phase-boundary binding accepted stale prerequisite evidence")
		}
		stale := binding
		stale.Config.Digest = digestFor("changed")
		if err := Match(plan, binding, now.Add(-time.Second)); err == nil {
			t.Fatal("Plan accepted trusted clock regression")
		}
		if err := Match(plan, stale, now); err == nil {
			t.Fatal("stale Plan binding matched")
		}
		if err := Match(plan, binding, plan.ExpiresAt); !errors.Is(err, ErrExpired) {
			t.Fatalf("expired Match() error=%v", err)
		}
		document, err := normal.Read()
		if err != nil {
			t.Fatal(err)
		}
		jobID := "job_" + strings.Repeat("2", 64)
		_, _, err = normal.Update(context.Background(), admission, document.Revision, func(transaction *persist.Transaction) error {
			_, err := Reserve(transaction, plan.ID, jobID, plan.Operation, "resource/app-one", plan.ActorIdentity, now)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		document, err = normal.Read()
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = normal.Update(context.Background(), admission, document.Revision, func(transaction *persist.Transaction) error {
			_, err := Consume(transaction, plan.ID, jobID, binding, now)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		consumed, err := store.Read(plan.ID)
		if err != nil || consumed.ConsumedAt == nil {
			t.Fatalf("Read(consumed)=%#v,%v", consumed, err)
		}
		document, err = normal.Read()
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = normal.Update(context.Background(), admission, document.Revision, func(transaction *persist.Transaction) error {
			_, err := Consume(transaction, plan.ID, "job_"+strings.Repeat("3", 64), binding, now)
			return err
		})
		if !errors.Is(err, ErrConsumed) {
			t.Fatalf("second Consume() error=%v", err)
		}
	})

	t.Run("evidence_must_be_fresh_when_plan_is_created", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()
		normal, manager, admission := newPlanNormalStore(t)
		defer closePlanNormalStore(t, normal, manager, admission)
		store, _ := NewStore(normal, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64))})
		spec := validSpec(now)
		spec.Evidence[0].ObservedAt = now.Add(-MaximumEvidenceAge - time.Second)
		if _, err := store.Create(context.Background(), admission, 1, spec); err == nil {
			t.Fatal("Create accepted stale evidence")
		}
		document, err := normal.Read()
		if err != nil || document.Revision != 1 {
			t.Fatalf("normal state mutated on stale evidence: %#v,%v", document, err)
		}
	})
}

func TestCreatePreservesProductionDisplayText(t *testing.T) {
	tests := []struct {
		name          string
		operation     domain.OperationCode
		target        Target
		summary       string
		prerequisites string
	}{
		{
			name:          "resource_delete",
			operation:     domain.OperationResourceDelete,
			target:        Target{Kind: TargetResource, ID: "app-one"},
			summary:       "deletes only LanPanel-managed inventory for resource app-one",
			prerequisites: "fresh unpublished closure and stopped local cgroup",
		},
		{
			name:          "managed_basic_rotation",
			operation:     domain.OperationManagedBasicRotate,
			target:        Target{Kind: TargetCredential, ID: "cred_00000000000000000000000000000001"},
			summary:       "rotates_managed_basic_credential_cred_00000000000000000000000000000001",
			prerequisites: "credential_fingerprint_unchanged; old_password_becomes_invalid",
		},
		{
			name:          "domain_publish",
			operation:     domain.OperationPublish,
			target:        Target{Kind: TargetResource, ID: "app-one"},
			summary:       "url=https://app.example.test/ listeners=80,443 domains=alias.example.test,app.example.test auth=managed_basic credential=cred_00000000000000000000000000000001 cidrs=192.0.2.0/24 static_root=static_00000000000000000000000000000001 static=/assets:assets static_anonymous_confirmed=false goaccess=true goaccess_credential=cred_00000000000000000000000000000002 goaccess_cidrs=198.51.100.0/24 goaccess_dashboard=/analytics goaccess_websocket=/analytics/ws certificate=dns-01:provider:https://acme.example.test/directory target=resource/app-one",
			prerequisites: "Exact certificate, auth, CIDR, static, isolated GoAccess staging, target, and Host/SNI validation required before activation.",
		},
		{
			name:          "headscale_deploy",
			operation:     domain.OperationHeadscaleControlDeploy,
			target:        Target{Kind: TargetHeadscale, ID: "hds_00000000000000000000000000000001"},
			summary:       "headscale=hds_00000000000000000000000000000001 control=https://control.example.test/ listeners=80/tcp,443/tcp,3478/udp certificate=cert_00000000000000000000000000000001 challenge=dns-01 service=private-candidate",
			prerequisites: "Exact Headscale release/config/database, fresh expansion preflight, isolated private service probe, and first real control certificate are required before control/STUN activation.",
		},
		{
			name:          "headscale_lifecycle",
			operation:     domain.OperationPreauthKeyRevoke,
			target:        Target{Kind: TargetPreauthKey, ID: "7"},
			summary:       "revokes preauth key 7; registered devices are unchanged",
			prerequisites: "fresh immutable Headscale ID and exact active control authority",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(1700000000, 0).UTC()
			normal, manager, admission := newPlanNormalStore(t)
			defer closePlanNormalStore(t, normal, manager, admission)
			store, err := NewStore(normal, Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64))})
			if err != nil {
				t.Fatal(err)
			}
			spec := validSpec(now)
			spec.Operation = string(test.operation)
			spec.Target = test.target
			spec.ExposureSummary = test.summary
			spec.Prerequisites = test.prerequisites
			plan, err := store.Create(context.Background(), admission, 1, spec)
			if err != nil {
				t.Fatalf("Create() error=%v", err)
			}
			stored, err := store.Read(plan.ID)
			if err != nil {
				t.Fatalf("Read() error=%v", err)
			}
			if stored.ExposureSummary != test.summary || stored.Prerequisites != test.prerequisites {
				t.Fatalf("display text changed: summary=%q prerequisites=%q", stored.ExposureSummary, stored.Prerequisites)
			}
		})
	}
}

func TestPlanDisplayTextIsBounded(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	tests := []struct {
		name          string
		summary       string
		prerequisites string
		wantErr       bool
	}{
		{name: "maximum", summary: strings.Repeat("s", MaximumDisplayBytes), prerequisites: strings.Repeat("p", MaximumDisplayBytes)},
		{name: "empty_summary", summary: "", prerequisites: "required", wantErr: true},
		{name: "empty_prerequisites", summary: "summary", prerequisites: "", wantErr: true},
		{name: "summary_too_long", summary: strings.Repeat("s", MaximumDisplayBytes+1), prerequisites: "required", wantErr: true},
		{name: "prerequisites_too_long", summary: "summary", prerequisites: strings.Repeat("p", MaximumDisplayBytes+1), wantErr: true},
		{name: "nul", summary: "bad\x00summary", prerequisites: "required", wantErr: true},
		{name: "carriage_return", summary: "summary", prerequisites: "bad\rprerequisite", wantErr: true},
		{name: "newline", summary: "summary", prerequisites: "bad\nprerequisite", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validPlan(now)
			plan.ExposureSummary = test.summary
			plan.Prerequisites = test.prerequisites
			err := Validate(plan, now)
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error=%v, wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func validSpec(now time.Time) Spec {
	return Spec{Operation: "publish", Target: Target{Kind: TargetResource, ID: "app-one"}, ActorIdentity: "session-one", Config: DigestBinding{Applicable: true, Digest: digestFor("config")}, Applied: DigestBinding{Applicable: true, Digest: digestFor("applied")}, Evidence: []Evidence{{Kind: "config", Identity: "app-one", Generation: 1, Digest: digestFor("evidence"), ObservedAt: now}}, ExposureSummary: "expands_ingress", Prerequisites: "qualified", Lifetime: MaximumLifetime}
}

func validPlan(now time.Time) Plan {
	return Plan{SchemaVersion: SchemaVersion, ID: "plan_" + strings.Repeat("1", 64), Operation: "publish", Target: Target{Kind: TargetResource, ID: "app-one"}, ActorIdentity: "session-one", Config: DigestBinding{Applicable: true, Digest: digestFor("config")}, Applied: DigestBinding{Applicable: true, Digest: digestFor("applied")}, Evidence: []Evidence{{Kind: "config", Identity: "app-one", Generation: 1, Digest: digestFor("evidence"), ObservedAt: now}}, ExposureSummary: "summary", Prerequisites: "qualified", CreatedAt: now, ExpiresAt: now.Add(MaximumLifetime), NonceDigest: digestFor("nonce")}
}

func bindingFor(plan Plan) Binding {
	return Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: append([]Evidence(nil), plan.Evidence...)}
}

func digestFor(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}

func newPlanNormalStore(t *testing.T) (*persist.Store, *locks.Manager, *locks.Lease) {
	t.Helper()
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	staging := filepath.Join(root, "staging")
	_ = os.Mkdir(staging, 0o700)
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
	normal, err := persist.Open(persist.Config{RootPath: root, StagingPath: staging, StatePath: filepath.Join(root, "normal.json"), Owner: owner, LockAuthority: manager.Authority()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normal.Initialize(context.Background(), admission); err != nil {
		t.Fatal(err)
	}
	return normal, manager, admission
}

func closePlanNormalStore(t *testing.T, normal *persist.Store, manager *locks.Manager, admission *locks.Lease) {
	t.Helper()
	if err := normal.Close(); err != nil {
		t.Error(err)
	}
	if err := admission.Release(); err != nil {
		t.Error(err)
	}
	if err := manager.Close(); err != nil {
		t.Error(err)
	}
}
