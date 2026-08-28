//go:build linux

package application

import (
	"context"
	"lanpanel/internal/contraction"
	"lanpanel/internal/domain"
	goaccessruntime "lanpanel/internal/goaccess"
	"lanpanel/internal/safety"
	"testing"
	"time"
)

func TestCloseAllGenerationInventoryMayBeExactlyEmpty(t *testing.T) {
	generations, err := contractionGenerations(domain.Installation{Resources: []domain.AppResource{}}, safety.EmptyState(), nil)
	if err != nil || len(generations) != 0 {
		t.Fatalf("empty close-all generations=%v error=%v", generations, err)
	}
}

type budgetedGoAccessContractionHost struct {
	stopBudgets []time.Duration
}

func (host *budgetedGoAccessContractionHost) Stop(ctx context.Context, _ string, _ uint64) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.DeadlineExceeded
	}
	host.stopBudgets = append(host.stopBudgets, time.Until(deadline))
	return nil
}

func (*budgetedGoAccessContractionHost) Retire(ctx context.Context, _ string, _ uint64, _ string, _ []string) error {
	<-ctx.Done()
	return ctx.Err()
}

func (*budgetedGoAccessContractionHost) RemoveGenerationState(context.Context, string, uint64) error {
	return nil
}

func (*budgetedGoAccessContractionHost) CleanupUncommittedShared(context.Context, string, string) error {
	return nil
}

func TestContractionOverallBudgetCoversEveryGenerationRetirementAndCleanup(t *testing.T) {
	budget, err := goAccessContractionTimeout(3)
	want := 3 * (goaccessruntime.GenerationRetirementTimeout + goAccessContractionCleanupTimeout)
	if err != nil || budget != want {
		t.Fatalf("contraction budget=%v want=%v error=%v", budget, want, err)
	}
	if _, err := goAccessContractionTimeout(0); err == nil {
		t.Fatal("zero-generation overall budget was accepted")
	}
}

func TestTimedOutGenerationRetentionLeavesIndependentBudgetForLaterStop(t *testing.T) {
	const generationBudget = 30 * time.Millisecond
	overall, cancel := context.WithTimeout(context.Background(), 5*generationBudget)
	defer cancel()
	host := &budgetedGoAccessContractionHost{}
	resourceID := "res_00000000000000000000000000000001"
	generations := map[string][]goaccessGeneration{resourceID: {
		{generation: 1, retiredIdentity: "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", unitIdentities: []string{"one"}},
		{generation: 2},
	}}
	_, err := stopGoAccessGenerations(overall, host, generationBudget, generationBudget, generations, contraction.Result{})
	if err == nil || len(host.stopBudgets) != 1 {
		t.Fatalf("generation cleanup error=%v stop budgets=%v", err, host.stopBudgets)
	}
	if host.stopBudgets[0] < generationBudget/2 {
		t.Fatalf("later stop inherited exhausted retention budget: %v", host.stopBudgets[0])
	}
}

func TestUnpublishRequiresMatchingNormalAndSafetyIdentity(t *testing.T) {
	installation := domain.Installation{Resources: []domain.AppResource{{ID: "app-one", PublicationRecord: domain.PublicationRecord{UnpublishedGeneration: 2}}}}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", GenerationSequence: 4}}
	generations, err := contractionGenerations(installation, state, []string{"app-one"})
	if err != nil || generations["app-one"] != 5 {
		t.Fatalf("selected generations=%v error=%v", generations, err)
	}
	if _, err := contractionGenerations(installation, safety.EmptyState(), []string{"app-one"}); err == nil {
		t.Fatal("selected App without matching safety identity was accepted")
	}
}
