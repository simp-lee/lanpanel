package qualification

import (
	"context"
	"fmt"
	"lanpanel/internal/release"
	"slices"
	"testing"
	"time"
)

type fakeExecutor struct {
	observed int
	executed []string
	cleaned  []string
}

func (executor *fakeExecutor) Observe(_ context.Context, step string) (PriorObservation, error) {
	executor.observed++
	return priorFor(step), nil
}

func (executor *fakeExecutor) Execute(_ context.Context, step string) (MutationObservation, error) {
	if executor.observed != len(orderedJourney) {
		return MutationObservation{}, fmt.Errorf("mutation started before all prior observations")
	}
	executor.executed = append(executor.executed, step)
	return MutationObservation{Identity: "observed/" + step}, nil
}

func (executor *fakeExecutor) Recover(_ context.Context, step string) (MutationObservation, error) {
	return MutationObservation{Identity: "recovered/" + step}, nil
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

func TestRunnerObservesAllAuthorityBeforeFixedJourneyAndCleansInReverse(t *testing.T) {
	mutations := make([]release.PlannedMutation, 0, len(orderedJourney))
	for _, step := range orderedJourney {
		prior := priorFor(step)
		policy := "delete_exact"
		if step == "clean_install" {
			policy = "retain_authorized"
		}
		mutations = append(mutations, release.PlannedMutation{ID: step, ScopeDigest: release.DigestBytes(prior.Scope), PriorStateDigest: release.DigestBytes(prior.PriorState), PlannedMutationDigest: release.DigestBytes(prior.PlannedMutation), SelectorDigest: release.DigestBytes(prior.Selector), CleanupPolicy: policy})
	}
	slices.SortFunc(mutations, func(left, right release.PlannedMutation) int { return compare(left.ID, right.ID) })
	executor := &fakeExecutor{}
	reports := &memoryReports{}
	plan := release.LiveSideEffectPlan{SchemaVersion: release.LiveSideEffectPlanSchemaVersion, RunID: "run-one", AuthorizedHostFingerprint: "host", CreatedAt: time.Unix(1_700_000_000, 0).UTC(), Mutations: mutations}
	planBytes, err := release.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Runner{RunID: plan.RunID, Plan: plan, PlanDigest: release.DigestBytes([]byte("different-plan")), InstallManifestDigest: release.DigestBytes([]byte("manifest")), ProtectedInputDigest: release.DigestBytes([]byte("input")), Executor: executor, Reports: reports, Now: func() time.Time { return plan.CreatedAt.Add(time.Minute) }}).Run(context.Background()); err == nil {
		t.Fatal("runner accepted a Plan different from its claimed digest")
	}
	report, err := (Runner{RunID: plan.RunID, Plan: plan, PlanDigest: release.DigestBytes(planBytes), InstallManifestDigest: release.DigestBytes([]byte("manifest")), ProtectedInputDigest: release.DigestBytes([]byte("input")), Executor: executor, Reports: reports, Now: func() time.Time { return plan.CreatedAt.Add(time.Minute) }}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Items) != len(orderedJourney) || len(reports.values) != 3*len(orderedJourney)+1 || !report.JourneySucceeded {
		t.Fatal("cleanup report and success attestation were not persisted")
	}
	for index, step := range orderedJourney {
		if executor.executed[index] != step || executor.cleaned[index] != orderedJourney[len(orderedJourney)-1-index] {
			t.Fatal("journey or cleanup order changed")
		}
	}
}

type uncertainExecutor struct{ fakeExecutor }

func (executor *uncertainExecutor) Execute(_ context.Context, step string) (MutationObservation, error) {
	return MutationObservation{Identity: "uncertain/" + step}, fmt.Errorf("response lost")
}

func TestRunnerCleansMutationIdentityReturnedWithExecutionError(t *testing.T) {
	mutations := make([]release.PlannedMutation, 0, len(orderedJourney))
	for _, step := range orderedJourney {
		prior := priorFor(step)
		mutations = append(mutations, release.PlannedMutation{ID: step, ScopeDigest: release.DigestBytes(prior.Scope), PriorStateDigest: release.DigestBytes(prior.PriorState), PlannedMutationDigest: release.DigestBytes(prior.PlannedMutation), SelectorDigest: release.DigestBytes(prior.Selector), CleanupPolicy: func() string {
			if step == "clean_install" {
				return "retain_authorized"
			}
			return "delete_exact"
		}()})
	}
	slices.SortFunc(mutations, func(left, right release.PlannedMutation) int { return compare(left.ID, right.ID) })
	executor := &uncertainExecutor{}
	reports := &memoryReports{}
	plan := release.LiveSideEffectPlan{SchemaVersion: release.LiveSideEffectPlanSchemaVersion, RunID: "run-error", AuthorizedHostFingerprint: "host", CreatedAt: time.Unix(1_700_000_000, 0).UTC(), Mutations: mutations}
	planBytes, _ := release.MarshalCanonical(plan)
	report, err := (Runner{RunID: plan.RunID, Plan: plan, PlanDigest: release.DigestBytes(planBytes), InstallManifestDigest: release.DigestBytes([]byte("manifest")), ProtectedInputDigest: release.DigestBytes([]byte("input")), Executor: executor, Reports: reports, Now: func() time.Time { return plan.CreatedAt.Add(time.Minute) }}).Run(context.Background())
	if err == nil || len(report.Items) != 1 || report.JourneySucceeded || len(executor.cleaned) != 1 {
		t.Fatalf("uncertain remote mutation was not cleaned: report=%+v err=%v", report, err)
	}
}

func priorFor(step string) PriorObservation {
	return PriorObservation{Scope: []byte("scope/" + step), PriorState: []byte("prior/" + step), PlannedMutation: []byte("mutation/" + step), Selector: []byte("selector/" + step)}
}
