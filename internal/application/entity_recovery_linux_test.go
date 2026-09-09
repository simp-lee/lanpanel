//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"lanpanel/internal/child"
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func interruptedConnectorLogin(t *testing.T, phase operations.Phase) (resourceRecoveryFixture, string) {
	t.Helper()
	fixture := newResourceRecoveryFixture(t, recoveryResourceInstallation(nil))
	service := fixture.open(t)
	defer func() { _ = service.Close() }()
	// The original Plan is expired by the time startup recovery runs.
	now := func() time.Time { return time.Now().UTC().Add(-time.Hour) }
	planStore, err := plans.NewStore(service.normal, plans.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := service.manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planStore.Create(context.Background(), admission, document.Revision, plans.Spec{Operation: string(operations.ConnectorLogin), Target: plans.Target{Kind: plans.TargetConnector}, ActorIdentity: "ui/test/generation/1", Config: plans.DigestBinding{Applicable: true, Digest: digestLifecycle(recoveryResourceInstallation(nil).Connector)}, ExposureSummary: "connector_login", Prerequisites: "one_time_key", Lifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := operationRegistry()
	if err != nil {
		t.Fatal(err)
	}
	binding := plans.Binding{Operation: plan.Operation, Target: plan.Target, ActorIdentity: plan.ActorIdentity, Config: plan.Config, Applied: plan.Applied, Evidence: plan.Evidence}
	admitter, err := operations.NewAdmitter(service.normal, service.safety, operations.Options{Now: now, Bindings: planBinding{binding}, Confirmation: confirmation{}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	job, err := admitter.Admit(context.Background(), admission, operations.AdmitRequest{Operation: operations.ConnectorLogin, Target: "connector", ActorIdentity: plan.ActorIdentity, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{CandidateDigest: plan.Config.Digest, CandidateBundle: plan.Config.Digest, PlanID: plan.ID}, ExpectedRevision: document.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(); err != nil {
		t.Fatal(err)
	}
	if phase == operations.PhaseReserved {
		return fixture, job.ID
	}
	set, mutation, exposure := fixture.acquire(t, service, "connector")
	defer func() { _ = errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()) }()
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	intent, err := admitter.ConsumePlan(context.Background(), mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: document.Revision, IntentGeneration: document.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		t.Fatal(err)
	}
	if phase != operations.PhaseLocalIntent {
		_, err = admitter.EnterRemoteWait(context.Background(), mutation, exposure, intent.IntentGeneration, job.ID)
		mutation, exposure = nil, nil
		if err != nil {
			t.Fatal(err)
		}
	}
	if phase == operations.PhaseReentered {
		document, err = service.normal.Read()
		if err != nil {
			t.Fatal(err)
		}
		_, mutation, exposure, err = admitter.Reenter(context.Background(), set, service.manager, document.Revision, job.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	return fixture, job.ID
}

func TestConnectorLoginPreflightFailureTerminalizesAndAllowsSameProcessRetry(t *testing.T) {
	ctx := context.Background()
	fixture, jobID := interruptedConnectorLogin(t, operations.PhaseLocalIntent)
	service := fixture.open(t)
	defer func() { _ = service.Close() }()
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	var original operations.Reservation
	if err := json.Unmarshal(document.Entries["intents/"+jobID], &original); err != nil {
		t.Fatal(err)
	}
	originalPlan, err := plans.LoadEntries(document.Entries, original.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	admitter, err := service.Admitter(originalPlan)
	if err != nil {
		t.Fatal(err)
	}
	set, mutation, exposure := fixture.acquire(t, service, "connector")
	cause := errors.New("connector already logged in")
	completionErr := completeConnectorLoginNotStarted(ctx, service, admitter, mutation, exposure, jobID, cause)
	if !errors.Is(completionErr, cause) {
		t.Fatalf("lost preflight error: %v", completionErr)
	}
	if err := errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()); err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	job, err := jobs.LoadEntries(document.Entries, jobID)
	if err != nil || job.Status != jobs.StatusTerminal || job.Result != jobs.ResultFailed {
		t.Fatalf("preflight left running job: %+v %v completion=%v", job, err, completionErr)
	}
	intent, err := admitter.OperationIntent(jobID)
	if err != nil || intent.Phase != operations.PhaseTerminal {
		t.Fatalf("preflight left active intent: %+v %v", intent, err)
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admission.Release() }()
	store, err := plans.NewStore(service.normal, plans.Options{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := store.Create(ctx, admission, document.Revision, plans.Spec{Operation: string(operations.ConnectorLogin), Target: plans.Target{Kind: plans.TargetConnector}, ActorIdentity: "ui/test/generation/1", Config: plans.DigestBinding{Applicable: true, Digest: intent.SafetyBinding.CandidateDigest}, ExposureSummary: "connector_login", Prerequisites: "one_time_key"})
	if err != nil {
		t.Fatal(err)
	}
	admitter, err = service.Admitter(plan)
	if err != nil {
		t.Fatal(err)
	}
	document, err = service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	_, err = admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ConnectorLogin, Target: "connector", ActorIdentity: plan.ActorIdentity, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{CandidateDigest: plan.Config.Digest, CandidateBundle: plan.Config.Digest, PlanID: plan.ID}, ExpectedRevision: document.Revision})
	if err != nil {
		t.Fatalf("fresh login blocked until restart: %v", err)
	}
}

type recoveryConnectorRunner struct {
	t       *testing.T
	keyPath string
	failure string
	calls   []child.TailscaleAction
}

func (runner *recoveryConnectorRunner) Run(_ context.Context, invocation child.TailscaleInvocation) ([]byte, error) {
	runner.t.Helper()
	if _, err := os.Lstat(runner.keyPath); !errors.Is(err, os.ErrNotExist) {
		runner.t.Fatalf("verification ran before exact key cleanup: %v", err)
	}
	runner.calls = append(runner.calls, invocation.Action)
	switch invocation.Action {
	case child.TailscaleVersion:
		if runner.failure == "unavailable" {
			return nil, errors.New("tailscaled unavailable")
		}
		return []byte(`{"short":"1.82.0"}`), nil
	case child.TailscalePrefs:
		if runner.failure == "control_mismatch" {
			return []byte(`{"ControlURL":"https://foreign.example.test"}`), nil
		}
		return []byte(`{"ControlURL":"https://control.example.test"}`), nil
	case child.TailscaleStatus:
		if runner.failure == "logged_out" {
			return []byte(`{"BackendState":"NeedsLogin"}`), nil
		}
		return []byte(`{"BackendState":"Running","TailscaleIPs":["100.64.0.1"],"Peer":{"peer":{"TailscaleIPs":["100.64.0.2"],"Online":true}}}`), nil
	default:
		runner.t.Fatalf("startup recovery attempted mutation: %s", invocation.Action)
		return nil, errors.New("unexpected mutation")
	}
}

type recoveryConnectorRoute string

func (route recoveryConnectorRoute) InterfaceFor(netip.Addr, netip.Addr) (string, error) {
	return string(route), nil
}

func TestInterruptedConnectorRecoveryFreshVerifyWithoutLogin(t *testing.T) {
	for _, phase := range []operations.Phase{operations.PhaseLocalIntent, operations.PhaseRemoteWait, operations.PhaseReentered} {
		for _, failure := range []string{"", "logged_out", "control_mismatch", "route_mismatch", "unavailable"} {
			t.Run(string(phase)+"/"+failure, func(t *testing.T) {
				fixture, jobID := interruptedConnectorLogin(t, phase)
				keyPath := filepath.Join(t.TempDir(), jobID+".key")
				if err := os.WriteFile(keyPath, []byte("one-time-test-key"), 0o600); err != nil {
					t.Fatal(err)
				}
				service := fixture.open(t)
				defer func() { _ = service.Close() }()
				config := operations.MutationConfig{RootPath: fixture.lockRoot(), Owner: fixture.owner.UID, Group: fixture.owner.GID, Mode: 0o700, Authority: service.manager.Authority()}
				runner := &recoveryConnectorRunner{t: t, keyPath: keyPath, failure: failure}
				verifyCalls := 0
				verify := func(ctx context.Context) (ConnectorVerifyResult, error) {
					verifyCalls++
					route := recoveryConnectorRoute("tailscale0")
					if failure == "route_mismatch" {
						route = "eth0"
					}
					observation, err := managedconnector.Verify(ctx, runner, route, "1.82.0", "https://control.example.test", time.Now().UTC())
					return ConnectorVerifyResult{Observation: observation}, err
				}
				cleanup := func() error {
					err := os.Remove(keyPath)
					if errors.Is(err, os.ErrNotExist) {
						return nil
					}
					return err
				}
				if err := reconcileInterruptedEntityMutations(context.Background(), service, recoveryDigest("child-closure"), config, cleanup(), verify); err != nil {
					t.Fatal(err)
				}
				document, err := service.normal.Read()
				if err != nil {
					t.Fatal(err)
				}
				record, err := jobs.LoadEntries(document.Entries, jobID)
				if err != nil {
					t.Fatal(err)
				}
				var intent operations.Reservation
				if err := json.Unmarshal(document.Entries["intents/"+jobID], &intent); err != nil {
					t.Fatal(err)
				}
				if record.Status != jobs.StatusTerminal || record.Result != jobs.ResultUnknown || intent.Phase != operations.PhaseTerminal || verifyCalls != 1 || len(runner.calls) == 0 {
					t.Fatalf("recovery did not observe and terminalize: job=%+v phase=%s calls=%v", record, intent.Phase, runner.calls)
				}
				wantStatus := jobs.PostconditionVerified
				if failure != "" {
					wantStatus = jobs.PostconditionUnobserved
				}
				if len(record.Postconditions) != 2 || record.Postconditions[0].Kind != "connector_recovery_verification" || record.Postconditions[0].Status != wantStatus {
					t.Fatalf("fresh verification result not recorded: %+v", record.Postconditions)
				}
				installation, err := installationFromDocument(document)
				if err != nil || !reflect.DeepEqual(installation.Connector, recoveryResourceInstallation(nil).Connector) {
					t.Fatalf("recovery changed connector binding/login state: %+v, %v", installation.Connector, err)
				}
				if err := reconcileInterruptedEntityMutations(context.Background(), service, recoveryDigest("child-closure"), config, nil, verify); err != nil {
					t.Fatal(err)
				}
				after, err := service.normal.Read()
				if err != nil || after.Revision != document.Revision || verifyCalls != 1 {
					t.Fatalf("terminal recovery was repeated: revision=%d calls=%d err=%v", after.Revision, verifyCalls, err)
				}
			})
		}
	}
}

func TestInterruptedConnectorRecoveryPrerequisites(t *testing.T) {
	for _, scenario := range []string{"cleanup_failed", "child_closure_missing", "reserved"} {
		t.Run(scenario, func(t *testing.T) {
			phase := operations.PhaseRemoteWait
			if scenario == "reserved" {
				phase = operations.PhaseReserved
			}
			fixture, jobID := interruptedConnectorLogin(t, phase)
			service := fixture.open(t)
			defer func() { _ = service.Close() }()
			config := operations.MutationConfig{RootPath: fixture.lockRoot(), Owner: fixture.owner.UID, Group: fixture.owner.GID, Mode: 0o700, Authority: service.manager.Authority()}
			closure := recoveryDigest("child-closure")
			if scenario == "child_closure_missing" {
				closure = ""
			}
			cleanupCalls := 0
			cleanupErr := errors.New("exact key cleanup failed")
			var cleanupResult error
			if closure != "" {
				cleanupCalls++
				if scenario == "cleanup_failed" {
					cleanupResult = cleanupErr
				}
			}
			err := reconcileInterruptedEntityMutations(context.Background(), service, closure, config, cleanupResult, func(context.Context) (ConnectorVerifyResult, error) {
				t.Fatal("unexpected connector verification")
				return ConnectorVerifyResult{}, nil
			})
			if scenario == "reserved" && err != nil || scenario == "cleanup_failed" && err == nil || scenario == "cleanup_failed" && !errors.Is(err, cleanupErr) || scenario == "child_closure_missing" && (err == nil || cleanupCalls != 0) {
				t.Fatalf("unexpected prerequisite result: cleanup=%d err=%v", cleanupCalls, err)
			}
			admitter, err := service.resourceAdmitter()
			if err != nil {
				t.Fatal(err)
			}
			intent, err := admitter.OperationIntent(jobID)
			if scenario == "reserved" {
				phase = operations.PhaseRejected
			}
			if err != nil || intent.Phase != phase {
				t.Fatalf("unexpected intent phase: %s, %v", intent.Phase, err)
			}
		})
	}
}

func TestInterruptedConnectorCannotTerminalizeWithoutVerification(t *testing.T) {
	fixture, jobID := interruptedConnectorLogin(t, operations.PhaseRemoteWait)
	service := fixture.open(t)
	defer func() { _ = service.Close() }()
	set, mutation, exposure := fixture.acquire(t, service, "connector")
	defer func() { _ = errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close()) }()
	admitter, err := service.resourceAdmitter()
	if err != nil {
		t.Fatal(err)
	}
	document, err := service.normal.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.CompleteInterruptedEntity(context.Background(), mutation, exposure, document.Revision, jobID, recoveryDigest("child-closure"), "connector_mutation_interrupted", nil); err == nil {
		t.Fatal("child closure alone terminalized interrupted connector login")
	}
}
