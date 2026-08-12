//go:build linux

package application

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/safety"
	"testing"
)

func TestCloseAllGenerationInventoryMayBeExactlyEmpty(t *testing.T) {
	generations, err := contractionGenerations(domain.Installation{Resources: []domain.AppResource{}}, safety.EmptyState(), nil)
	if err != nil || len(generations) != 0 {
		t.Fatalf("empty close-all generations=%v error=%v", generations, err)
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
