package qualification

import (
	"context"
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
	return MutationObservation{Identity: "observed/" + step, Evidence: []byte("evidence/" + step)}, nil
}

func (executor *fakeExecutor) Recover(_ context.Context, step string) (MutationObservation, error) {
	return MutationObservation{Identity: "recovered/" + step, Evidence: []byte("recovered-evidence/" + step)}, nil
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
		DNSProvider: "cloudflare", DNSLiveTested: true, TailnetLiveStatus: "not_live_tested", Steps: steps, Cleanup: append([]release.CleanupItem(nil), report.Items...), CompletedAt: attestor.now,
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

type uncertainExecutor struct{ fakeExecutor }

func (executor *uncertainExecutor) Execute(_ context.Context, step string) (MutationObservation, error) {
	executor.executed = append(executor.executed, step)
	return MutationObservation{Identity: "uncertain/" + step, Evidence: []byte("partial/" + step)}, fmt.Errorf("response lost")
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
	return PriorObservation{Scope: []byte("scope/" + step), PriorState: []byte("prior/" + step), PlannedMutation: []byte("mutation/" + step), Selector: []byte("selector/" + step)}
}
