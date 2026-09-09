package storeauthority

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/safety"
	"strings"
	"testing"
)

func TestCompleteResourceAuthorityIsExactAndOrphansStayClosed(t *testing.T) {
	const resourceID = "res_one"
	const owner = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	installation := &domain.Installation{Resources: []domain.AppResource{{ID: resourceID}}}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: resourceID, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: owner}}
	ownership := map[string]string{resourceID: owner}
	if err := ValidateNormalSafetyOwnership(installation, state, ownership); err != nil {
		t.Fatalf("exact authority rejected: %v", err)
	}

	orphan := safety.ResourceSafety{ResourceID: "res_orphan", State: safety.ResourceActive, Ownership: safety.OwnershipOrphan, OwnershipDigest: owner}
	state.Resources = append(state.Resources, orphan)
	ownership[orphan.ResourceID] = owner
	if err := ValidateNormalSafetyOwnership(installation, state, ownership); err == nil || !strings.Contains(err.Error(), "clean-host rebuild") {
		t.Fatalf("one-sided orphan error = %v", err)
	}

	state.Resources = state.Resources[:1]
	delete(ownership, orphan.ResourceID)
	ownership["res_ownership_only"] = owner
	if err := ValidateNormalSafetyOwnership(installation, state, ownership); err == nil {
		t.Fatal("ownership-only resource authority was accepted")
	}
}
