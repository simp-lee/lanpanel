package application

import (
	"context"
	"errors"
	"lanpanel/internal/domain"
	"testing"
)

func TestIncompleteActionsRemainUnavailable(t *testing.T) {
	service, _ := New(nil)
	call := Call{Operation: domain.OperationAdminTokenRotate, Target: domain.OperationTarget{Kind: domain.OperationTargetInstallation}, Payload: ConfirmationPayload{}}
	if _, err := service.Invoke(context.Background(), Actor{Kind: ActorUI, Identity: "session", Generation: 1}, call); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unregistered action=%v", err)
	}
}
func TestActorAuthorityBindsSessionGeneration(t *testing.T) {
	first, err := actorAuthority(Actor{Kind: ActorUI, Identity: "selector", Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := actorAuthority(Actor{Kind: ActorUI, Identity: "selector", Generation: 2})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("actor generation was not bound")
	}
	if _, err := actorAuthority(Actor{Kind: ActorTimer, Identity: "timer", Generation: 1}); err == nil {
		t.Fatal("timer became UI Plan actor")
	}
}

func TestTypedActionRejectsWrongPayloadAndActor(t *testing.T) {
	registration, _ := RegisterAction(domain.OperationAdminTokenRotate, ConfirmationPayload{}, true, false, func(_ context.Context, _ Actor, call Call) (Result, error) {
		return Result{Operation: call.Operation, Target: call.Target}, nil
	})
	service, _ := New([]Registration{registration})
	call := Call{Operation: domain.OperationAdminTokenRotate, Target: domain.OperationTarget{Kind: domain.OperationTargetInstallation}, Payload: EmptyPayload{}}
	if _, err := service.Invoke(context.Background(), Actor{Kind: ActorUI, Identity: "session", Generation: 1}, call); err == nil {
		t.Fatal("wrong payload accepted")
	}
	call.Payload = ConfirmationPayload{}
	if _, err := service.Invoke(context.Background(), Actor{Kind: ActorTimer, Identity: "timer", Generation: 1}, call); !errors.Is(err, ErrUnavailable) {
		t.Fatal("timer used UI action")
	}
}
func TestCoreActionVocabularyIsClosed(t *testing.T) {
	seen := map[domain.OperationCode]bool{}
	for _, action := range CoreActions() {
		if seen[action] {
			t.Fatal("duplicate action")
		}
		seen[action] = true
		if _, err := domain.ParseOperationCode(string(action)); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 49 {
		t.Fatalf("core actions=%d", len(seen))
	}
}
