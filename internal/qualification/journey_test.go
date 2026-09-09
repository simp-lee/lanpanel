package qualification

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/release"
	"slices"
	"testing"
	"time"
)

func TestEnsureManagementRejectsMissingTarget(t *testing.T) {
	executor := &LiveExecutor{}
	if err := executor.ensureManagement(context.Background()); err == nil {
		t.Fatal("missing reboot target reached management client")
	}
}

type fakeExecutor struct {
	observed int
	executed []string
	cleaned  []string
}

func (executor *fakeExecutor) Observe(_ context.Context, step string) (PriorObservation, error) {
	executor.observed++
	if executor.observed != len(executor.executed)+1 {
		return PriorObservation{}, fmt.Errorf("prior state was not observed immediately before mutation")
	}
	return priorFor(step), nil
}

func (executor *fakeExecutor) Execute(_ context.Context, step string) (MutationObservation, error) {
	executor.executed = append(executor.executed, step)
	return MutationObservation{Identity: "observed/" + step, Evidence: fakeStepEvidence(step)}, nil
}

func (executor *fakeExecutor) Recover(_ context.Context, step string) (MutationObservation, error) {
	return MutationObservation{Identity: "recovered/" + step, Evidence: fakeStepEvidence("recovered-" + step)}, nil
}

func fakeStepEvidence(kind string) []byte {
	data, _ := release.MarshalCanonical(release.LiveStepEvidence{SchemaVersion: release.LiveStepEvidenceSchemaVersion, Kind: kind, Values: map[string]string{"result": "observed"}})
	return data
}

func (executor *fakeExecutor) Cleanup(_ context.Context, step string, _ MutationObservation, policy string) (release.CleanupResult, error) {
	executor.cleaned = append(executor.cleaned, step)
	if policy == "retain_authorized" {
		return release.CleanupRetained, nil
	}
	return release.CleanupCleaned, nil
}

type memoryReports struct{ values []release.LiveCleanupReport }

func (reports *memoryReports) Read() (release.LiveCleanupReport, bool, error) {
	if len(reports.values) == 0 {
		return release.LiveCleanupReport{}, false, nil
	}
	return reports.values[len(reports.values)-1], true, nil
}

func (reports *memoryReports) Write(value release.LiveCleanupReport) error {
	reports.values = append(reports.values, value)
	return nil
}

type memoryAttestations struct{ data []byte }

func (store *memoryAttestations) Write(data []byte) error {
	store.data = append([]byte(nil), data...)
	return nil
}

type fakeAttestor struct {
	planDigest, manifestDigest, inputDigest string
	now                                     time.Time
}

func (attestor fakeAttestor) Attest(_ context.Context, report release.LiveCleanupReport) ([]byte, error) {
	steps := make([]release.AttestedJourneyStep, 0, len(report.Steps))
	for _, step := range report.Steps {
		steps = append(steps, release.AttestedJourneyStep{MutationID: step.MutationID, EvidenceDigest: step.EvidenceDigest})
	}
	return release.MarshalCanonical(release.LiveExecutorAttestation{
		SchemaVersion: release.LiveExecutorAttestationSchemaVersion, ExecutorIdentity: "lanpanel-trusted-live-executor-v1", RunID: report.RunID,
		CandidateDigest: release.DigestBytes([]byte("candidate")), TargetProfileDigest: release.DigestBytes([]byte("profile")), SideEffectPlanDigest: attestor.planDigest,
		QualificationInstallManifestDigest: attestor.manifestDigest, ProtectedInputDigest: attestor.inputDigest, TargetHostFingerprint: "host-one", ExternalVantageDigest: release.DigestBytes([]byte("vantage")),
		DNSProvider: "cloudflare", DNSLiveTested: true, TailnetLiveStatus: "not_live_tested", Steps: steps, Cleanup: append([]release.CleanupItem(nil), report.Items...), TerminalEvidence: fakeStepEvidence("terminal-cleanup"), CompletedAt: attestor.now,
	})
}

func TestRunnerObservesFreshAuthorityRunsFixedJourneyAndCleansInReverse(t *testing.T) {
	plan := testJourneyPlan(t, "run-one")
	planBytes, err := release.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, inputDigest := release.DigestBytes([]byte("manifest")), release.DigestBytes([]byte("input"))
	now := plan.CreatedAt.Add(time.Minute)
	executor := &fakeExecutor{}
	reports := &memoryReports{}
	attestations := &memoryAttestations{}
	runner := Runner{RunID: plan.RunID, Plan: plan, PlanDigest: release.DigestBytes(planBytes), InstallManifestDigest: manifestDigest, ProtectedInputDigest: inputDigest, Executor: executor, Reports: reports, Attestor: fakeAttestor{release.DigestBytes(planBytes), manifestDigest, inputDigest, now}, Attestations: attestations, Now: func() time.Time { return now }, NewAttemptID: sequenceAttempts(), ExecutionTimeout: time.Minute, CleanupTimeout: time.Minute}
	wrong := runner
	wrong.PlanDigest = release.DigestBytes([]byte("different-plan"))
	if _, err := wrong.Run(context.Background()); err == nil {
		t.Fatal("runner accepted a Plan different from its claimed digest")
	}
	report, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Steps) != len(orderedJourney) || len(report.Items) != len(orderedJourney) || len(reports.values) != 3*len(orderedJourney)+1 || !report.JourneySucceeded || len(attestations.data) == 0 {
		t.Fatal("execution, cleanup, and trusted success attestation were not persisted")
	}
	for index, step := range orderedJourney {
		if executor.executed[index] != step || executor.cleaned[index] != orderedJourney[len(orderedJourney)-1-index] {
			t.Fatal("journey or cleanup order changed")
		}
	}
}

type changedPriorExecutor struct{ fakeExecutor }

func (executor *changedPriorExecutor) Observe(_ context.Context, step string) (PriorObservation, error) {
	observed := priorFor(step)
	observed.PriorState = []byte("step=" + step + ";fresh_observation=value=changed")
	return observed, nil
}

func TestRunnerRejectsFreshPriorMismatchBeforeSubmission(t *testing.T) {
	executor := &changedPriorExecutor{}
	runner, reports := deadlineTestRunner(t, "run-prior-mismatch", executor, nil)
	report, err := runner.Run(context.Background())
	if err == nil || len(executor.executed) != 0 || len(report.Steps) != 0 || len(reports.values) != 0 {
		t.Fatalf("changed fresh prior state reached mutation submission: report=%+v err=%v", report, err)
	}
}

type uncertainExecutor struct{ fakeExecutor }

func (executor *uncertainExecutor) Execute(_ context.Context, step string) (MutationObservation, error) {
	executor.executed = append(executor.executed, step)
	return MutationObservation{Identity: "uncertain/" + step, Evidence: fakeStepEvidence("partial-" + step)}, fmt.Errorf("response lost")
}

func TestRunnerFailureIsPersistedCleanedAndNeverPromotedOnResume(t *testing.T) {
	plan := testJourneyPlan(t, "run-error")
	planBytes, _ := release.MarshalCanonical(plan)
	manifestDigest, inputDigest := release.DigestBytes([]byte("manifest")), release.DigestBytes([]byte("input"))
	now := plan.CreatedAt.Add(time.Minute)
	executor := &uncertainExecutor{}
	reports := &memoryReports{}
	runner := Runner{RunID: plan.RunID, Plan: plan, PlanDigest: release.DigestBytes(planBytes), InstallManifestDigest: manifestDigest, ProtectedInputDigest: inputDigest, Executor: executor, Reports: reports, Attestor: fakeAttestor{release.DigestBytes(planBytes), manifestDigest, inputDigest, now}, Attestations: &memoryAttestations{}, Now: func() time.Time { return now }, NewAttemptID: sequenceAttempts(), ExecutionTimeout: time.Minute, CleanupTimeout: time.Minute}
	report, err := runner.Run(context.Background())
	if err == nil || len(report.Items) != 1 || !report.ExecutionFailed || report.JourneySucceeded || len(executor.cleaned) != 1 {
		t.Fatalf("uncertain remote mutation was not terminally failed and cleaned: report=%+v err=%v", report, err)
	}
	resumed, err := runner.Run(context.Background())
	if err == nil || resumed.JourneySucceeded || !resumed.ExecutionFailed {
		t.Fatal("failed journey was promoted on resume")
	}
}

type stagedCleanupExecutor struct {
	fakeExecutor
	stagingPresent bool
	failCleanup    bool
}

func (executor *stagedCleanupExecutor) Execute(ctx context.Context, step string) (MutationObservation, error) {
	if step == "clean_install" {
		executor.stagingPresent = true
	}
	return executor.fakeExecutor.Execute(ctx, step)
}

func (executor *stagedCleanupExecutor) Cleanup(ctx context.Context, step string, observation MutationObservation, policy string) (release.CleanupResult, error) {
	if step == "app_http01" {
		if !executor.stagingPresent {
			return "", fmt.Errorf("certificate cleanup executable is absent")
		}
		if executor.failCleanup {
			return "", fmt.Errorf("certificate cleanup is temporarily unavailable")
		}
	}
	if step == "clean_install" {
		executor.stagingPresent = false
	}
	return executor.fakeExecutor.Cleanup(ctx, step, observation, policy)
}

func TestFailedCertificateCleanupRetainsStagingUntilCleanupOnlyResume(t *testing.T) {
	executor := &stagedCleanupExecutor{failCleanup: true}
	runner, _ := deadlineTestRunner(t, "run-staged-cleanup", executor, nil)
	report, err := runner.Run(context.Background())
	if err == nil || report.JourneySucceeded || !executor.stagingPresent || slices.Contains(executor.cleaned, "clean_install") {
		t.Fatalf("failed certificate cleanup lost its staged executable: staging=%t cleaned=%v err=%v", executor.stagingPresent, executor.cleaned, err)
	}
	executions := len(executor.executed)
	executor.failCleanup = false
	resumed, err := runner.Run(context.Background())
	if err == nil || !resumed.ExecutionFailed || resumed.JourneySucceeded || !allCleanupTerminal(resumed, runner.Plan) || executor.stagingPresent || len(executor.executed) != executions {
		t.Fatalf("cleanup-only resume did not remove effects without qualifying/replaying: report=%+v staging=%t err=%v", resumed, executor.stagingPresent, err)
	}
}

func testJourneyPlan(t *testing.T, runID string) release.LiveSideEffectPlan {
	t.Helper()
	mutations := make([]release.PlannedMutation, 0, len(orderedJourney))
	retained := map[string]bool{"clean_install": true, "headscale_initialize_http01": true, "headscale_entities": true, "connector_assisted_login": true, "final_cleanup_inventory": true}
	for _, step := range orderedJourney {
		prior := priorFor(step)
		policy := "delete_exact"
		if retained[step] {
			policy = "retain_authorized"
		}
		mutations = append(mutations, release.PlannedMutation{ID: step, Scope: string(prior.Scope), ScopeDigest: release.DigestBytes(prior.Scope), PriorState: string(prior.PriorState), PriorStateDigest: release.DigestBytes(prior.PriorState), PlannedMutation: string(prior.PlannedMutation), PlannedMutationDigest: release.DigestBytes(prior.PlannedMutation), Selector: string(prior.Selector), SelectorDigest: release.DigestBytes(prior.Selector), CleanupPolicy: policy})
	}
	slices.SortFunc(mutations, func(left, right release.PlannedMutation) int { return compare(left.ID, right.ID) })
	return release.LiveSideEffectPlan{SchemaVersion: release.LiveSideEffectPlanSchemaVersion, RunID: runID, AuthorizedHostFingerprint: "host-one", CreatedAt: time.Unix(1_700_000_000, 0).UTC(), Mutations: mutations}
}

func sequenceAttempts() func() (string, error) {
	value := 0
	return func() (string, error) {
		value++
		return fmt.Sprintf("attempt-%d", value), nil
	}
}

func priorFor(step string) PriorObservation {
	return PriorObservation{Scope: []byte("run=test;host=host-one;providers=test;objects=" + step), PriorState: []byte("step=" + step + ";fresh_observation=value=test"), PlannedMutation: []byte("effects=test-" + step + "[delete_exact]"), Selector: []byte("target=" + step)}
}

type observeDeadlineSuccessExecutor struct{ fakeExecutor }

func (executor *observeDeadlineSuccessExecutor) Observe(ctx context.Context, step string) (PriorObservation, error) {
	<-ctx.Done()
	return priorFor(step), nil
}

type executeDeadlineSuccessExecutor struct{ fakeExecutor }

func (executor *executeDeadlineSuccessExecutor) Execute(ctx context.Context, step string) (MutationObservation, error) {
	executor.executed = append(executor.executed, step)
	<-ctx.Done()
	return MutationObservation{Identity: "timed-out/" + step, Evidence: fakeStepEvidence("late-success-" + step)}, nil
}

type recoverDeadlineSuccessExecutor struct{ fakeExecutor }

func (executor *recoverDeadlineSuccessExecutor) Recover(ctx context.Context, step string) (MutationObservation, error) {
	<-ctx.Done()
	return MutationObservation{Identity: "late-recovery/" + step, Evidence: fakeStepEvidence("late-recovery-" + step)}, nil
}

type cleanupDeadlineSuccessExecutor struct{ fakeExecutor }

func (executor *cleanupDeadlineSuccessExecutor) Cleanup(ctx context.Context, _ string, _ MutationObservation, _ string) (release.CleanupResult, error) {
	<-ctx.Done()
	return release.CleanupCleaned, nil
}

func TestRunnerRejectsSuccessfulResultsReturnedAfterDeadlines(t *testing.T) {
	t.Run("observe", func(t *testing.T) {
		executor := &observeDeadlineSuccessExecutor{}
		runner, reports := deadlineTestRunner(t, "run-observe-timeout", executor, nil)
		report, err := runner.Run(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) || len(report.Steps) != 0 || len(reports.values) != 0 {
			t.Fatalf("late observe success was accepted: report=%+v err=%v", report, err)
		}
	})

	t.Run("execute preserves cleanup identity", func(t *testing.T) {
		executor := &executeDeadlineSuccessExecutor{}
		runner, _ := deadlineTestRunner(t, "run-execute-timeout", executor, nil)
		report, err := runner.Run(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) || len(report.Steps) != 1 || report.Steps[0].Outcome == release.StepPassed || !report.ExecutionFailed {
			t.Fatalf("late execute success was accepted: report=%+v err=%v", report, err)
		}
		if len(report.Items) != 1 || report.Items[0].ObservedIdentity != "timed-out/"+orderedJourney[0] || report.Items[0].Result != release.CleanupRetained {
			t.Fatalf("timed-out mutation cleanup identity was not preserved: %+v", report.Items)
		}
	})

	t.Run("recover", func(t *testing.T) {
		executor := &recoverDeadlineSuccessExecutor{}
		persisted := submittedTestReport(t, "run-recover-timeout", release.CleanupSubmitted)
		runner, _ := deadlineTestRunner(t, persisted.RunID, executor, &persisted)
		report, err := runner.Run(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) || len(report.Items) != 1 || report.Items[0].Result != release.CleanupSubmitted {
			t.Fatalf("late recover success was accepted: report=%+v err=%v", report, err)
		}
	})

	t.Run("cleanup", func(t *testing.T) {
		executor := &cleanupDeadlineSuccessExecutor{}
		persisted := submittedTestReport(t, "run-cleanup-timeout", release.CleanupExecuted)
		runner, _ := deadlineTestRunner(t, persisted.RunID, executor, &persisted)
		report, err := runner.Run(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) || len(report.Items) != 1 || report.Items[0].Result != release.CleanupExecuted {
			t.Fatalf("late cleanup success was accepted: report=%+v err=%v", report, err)
		}
	})
}

func deadlineTestRunner(t *testing.T, runID string, executor Executor, persisted *release.LiveCleanupReport) (Runner, *memoryReports) {
	t.Helper()
	plan := testJourneyPlan(t, runID)
	planBytes, err := release.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, inputDigest := release.DigestBytes([]byte("manifest")), release.DigestBytes([]byte("input"))
	now := plan.CreatedAt.Add(time.Minute)
	reports := &memoryReports{}
	if persisted != nil {
		persisted.SideEffectPlanDigest = release.DigestBytes(planBytes)
		persisted.QualificationInstallManifestDigest = manifestDigest
		persisted.ProtectedInputDigest = inputDigest
		reports.values = append(reports.values, *persisted)
	}
	return Runner{RunID: runID, Plan: plan, PlanDigest: release.DigestBytes(planBytes), InstallManifestDigest: manifestDigest, ProtectedInputDigest: inputDigest, Executor: executor, Reports: reports, Attestor: fakeAttestor{release.DigestBytes(planBytes), manifestDigest, inputDigest, now}, Attestations: &memoryAttestations{}, Now: func() time.Time { return now }, NewAttemptID: sequenceAttempts(), ExecutionTimeout: 20 * time.Millisecond, CleanupTimeout: 20 * time.Millisecond}, reports
}

func submittedTestReport(t *testing.T, runID string, result release.CleanupResult) release.LiveCleanupReport {
	t.Helper()
	return release.LiveCleanupReport{SchemaVersion: release.LiveCleanupReportSchemaVersion, RunID: runID, Steps: []release.JourneyStepResult{{MutationID: orderedJourney[0], AttemptID: "attempt-1", Outcome: release.StepSubmitted}}, Items: []release.CleanupItem{{MutationID: orderedJourney[0], ObservedIdentity: "pending/attempt-1", Result: result}}}
}
