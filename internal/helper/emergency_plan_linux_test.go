//go:build linux

package helper

import (
	"fmt"
	"testing"
	"time"
)

func TestEmergencyPlanCapacityReclaimsSixtyFourExpiredPlans(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := newEmergencyPlanStore()
	clockReads := 0
	store.now = func() time.Time {
		clockReads++
		return now
	}
	for index := 0; index < 64; index++ {
		id := fmt.Sprintf("expired-%d", index)
		store.plans[id] = emergencyPlan{ID: id, ExpiresAt: now.Add(-time.Second)}
	}
	plan, err := store.insert(emergencyPlan{ID: "fresh", ActorIdentity: "actor", ActorGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if clockReads != 1 || len(store.plans) != 1 || store.plans[plan.ID].ExpiresAt != now.Add(10*time.Minute) {
		t.Fatalf("clockReads=%d plans=%#v", clockReads, store.plans)
	}
	if _, err := store.Consume(plan.ID, plan.ActorIdentity, plan.ActorGeneration, "close", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(plan.ID, plan.ActorIdentity, plan.ActorGeneration, "close", now); err == nil {
		t.Fatal("emergency Plan was consumed twice")
	}
}
