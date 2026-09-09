package storeauthority

import (
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/safety"
	"sort"
)

const rebuildGuidance = "keep ingress closed; do not adopt or delete the resource; use configuration export and clean-host rebuild"

// ValidateNormalSafety requires the complete normal resource inventory and the
// independent safety inventory to describe the same resource identities. It
// is used at publication admission and by the Nginx guard; it never repairs,
// adopts, or removes one-sided state.
func ValidateNormalSafety(installation *domain.Installation, state safety.State) error {
	if installation == nil {
		return fmt.Errorf("normal installation authority is missing; %s", rebuildGuidance)
	}
	normal := make(map[string]struct{}, len(installation.Resources))
	for _, resource := range installation.Resources {
		if _, duplicate := normal[resource.ID]; duplicate {
			return fmt.Errorf("normal resource identity %q is duplicated; %s", resource.ID, rebuildGuidance)
		}
		normal[resource.ID] = struct{}{}
	}
	independent := make(map[string]safety.ResourceSafety, len(state.Resources))
	for _, resource := range state.Resources {
		if _, duplicate := independent[resource.ResourceID]; duplicate {
			return fmt.Errorf("independent resource identity %q is duplicated; %s", resource.ResourceID, rebuildGuidance)
		}
		independent[resource.ResourceID] = resource
	}
	for _, resourceID := range sortedSafetyResourceIDs(independent) {
		resource := independent[resourceID]
		if resource.Ownership == safety.OwnershipOrphan {
			return fmt.Errorf("resource %q is an ownership orphan and blocks publication; %s", resourceID, rebuildGuidance)
		}
		if _, present := normal[resourceID]; !present {
			return fmt.Errorf("resource %q exists only in the independent safety/ownership inventory and blocks publication; %s", resourceID, rebuildGuidance)
		}
	}
	for _, resourceID := range sortedNormalResourceIDs(normal) {
		if _, present := independent[resourceID]; !present {
			return fmt.Errorf("normal resource %q lacks independent safety/ownership authority and blocks publication; %s", resourceID, rebuildGuidance)
		}
	}
	return nil
}

// ValidateNormalSafetyOwnership additionally requires the caller's complete
// ownership inventory to match every safety resource and no other identity.
func ValidateNormalSafetyOwnership(installation *domain.Installation, state safety.State, ownership map[string]string) error {
	if err := ValidateNormalSafety(installation, state); err != nil {
		return err
	}
	independent := make(map[string]safety.ResourceSafety, len(state.Resources))
	for _, resource := range state.Resources {
		independent[resource.ResourceID] = resource
	}
	for _, resourceID := range sortedSafetyResourceIDs(independent) {
		resource := independent[resourceID]
		digest, present := ownership[resourceID]
		if !present {
			return fmt.Errorf("resource %q lacks an exact ownership inventory record and blocks publication; %s", resourceID, rebuildGuidance)
		}
		if digest != resource.OwnershipDigest {
			return fmt.Errorf("resource %q safety and ownership identities differ and block publication; %s", resourceID, rebuildGuidance)
		}
	}
	ownershipIDs := make([]string, 0, len(ownership))
	for resourceID := range ownership {
		ownershipIDs = append(ownershipIDs, resourceID)
	}
	sort.Strings(ownershipIDs)
	for _, resourceID := range ownershipIDs {
		if _, present := independent[resourceID]; !present {
			return fmt.Errorf("ownership resource %q lacks normal and safety authority and blocks publication; %s", resourceID, rebuildGuidance)
		}
	}
	return nil
}

func sortedSafetyResourceIDs(resources map[string]safety.ResourceSafety) []string {
	ids := make([]string, 0, len(resources))
	for resourceID := range resources {
		ids = append(ids, resourceID)
	}
	sort.Strings(ids)
	return ids
}

func sortedNormalResourceIDs(resources map[string]struct{}) []string {
	ids := make([]string, 0, len(resources))
	for resourceID := range resources {
		ids = append(ids, resourceID)
	}
	sort.Strings(ids)
	return ids
}
