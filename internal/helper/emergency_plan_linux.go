//go:build linux

package helper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"lanpanel/internal/application"
	"lanpanel/internal/contraction"
	"sync"
	"time"
)

type emergencyPlan struct {
	ID                 string
	ActorIdentity      string
	ActorGeneration    uint64
	GlobalGeneration   uint64
	InventoryDigest    string
	ConfirmationDigest string
	Emergency          bool
	ExpiresAt          time.Time
}
type emergencyPlanStore struct {
	mu     sync.Mutex
	plans  map[string]emergencyPlan
	random io.Reader
	now    func() time.Time
}

func newEmergencyPlanStore() *emergencyPlanStore {
	return &emergencyPlanStore{plans: map[string]emergencyPlan{}, random: rand.Reader, now: func() time.Time { return time.Now().UTC() }}
}

func (store *emergencyPlanStore) Create(ctx context.Context, actor application.Actor) (emergencyPlan, error) {
	if actor.Kind != application.ActorUI || actor.Identity == "" || actor.Generation == 0 {
		return emergencyPlan{}, fmt.Errorf("emergency Plan actor is invalid")
	}
	service, err := contraction.OpenEmergency(ctx)
	if err != nil {
		return emergencyPlan{}, err
	}
	snapshot, err := service.Snapshot()
	_ = service.Close()
	if err != nil {
		return emergencyPlan{}, err
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(store.random, random); err != nil {
		return emergencyPlan{}, err
	}
	defer clear(random)
	id := "plan_" + hex.EncodeToString(random)
	confirmation := sha256.Sum256([]byte(id + "\x00" + actor.Identity + "\x00" + fmt.Sprint(actor.Generation) + "\x00" + snapshot.Inventory.Digest + "\x00" + fmt.Sprint(snapshot.GlobalGeneration)))
	plan := emergencyPlan{ID: id, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, GlobalGeneration: snapshot.GlobalGeneration, InventoryDigest: snapshot.Inventory.Digest, ConfirmationDigest: "sha256:" + hex.EncodeToString(confirmation[:]), Emergency: true}
	return store.insert(plan)
}

func (store *emergencyPlanStore) insert(plan emergencyPlan) (emergencyPlan, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	for id, existing := range store.plans {
		if now.After(existing.ExpiresAt) {
			delete(store.plans, id)
		}
	}
	if len(store.plans) >= 64 {
		return emergencyPlan{}, fmt.Errorf("emergency Plan bound reached")
	}
	plan.ExpiresAt = now.Add(10 * time.Minute)
	store.plans[plan.ID] = plan
	return plan, nil
}

func (store *emergencyPlanStore) Consume(id, actor string, generation uint64, confirmation string, now time.Time) (emergencyPlan, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	plan, ok := store.plans[id]
	if !ok {
		return emergencyPlan{}, fmt.Errorf("emergency Plan is missing or already consumed")
	}
	delete(store.plans, id)
	if actor != plan.ActorIdentity || generation != plan.ActorGeneration || confirmation != "close" || now.After(plan.ExpiresAt) || now.Before(plan.ExpiresAt.Add(-10*time.Minute)) {
		return emergencyPlan{}, fmt.Errorf("emergency Plan binding is invalid or expired")
	}
	return plan, nil
}
