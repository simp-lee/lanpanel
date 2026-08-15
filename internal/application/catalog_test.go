package application

import (
	"context"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"testing"
)

func TestGoAccessManagedRootsAreNeverExternalStatic(t *testing.T) {
	installation := domain.Installation{ManagedPaths: []string{}, Resources: []domain.AppResource{{ID: "res_00000000000000000000000000000001", ManagedPaths: []string{}, PublicationRecord: domain.PublicationRecord{LastAppliedBundle: &domain.PublicationBundle{ManagedPaths: []string{"/custom/goaccess-owned"}}}}}}
	paths := protectedStaticPaths(installation)
	for _, want := range []string{"/run/lanpanel-goaccess", "/var/log/lanpanel/goaccess", "/etc/systemd/system", "/etc/sysusers.d", "/custom/goaccess-owned"} {
		found := false
		for _, path := range paths {
			if path == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("protected static path missing %s", want)
		}
	}
}

func TestGoAccessCredentialChangeIsPublicationOnly(t *testing.T) {
	prior := domain.AppResource{ID: "res_00000000000000000000000000000001", Name: "app", Lifecycle: domain.LifecycleActive, CredentialIDs: []string{"cred_app", "cred_ga_old"}, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CredentialID: "cred_app", GoAccess: domain.GoAccessPublication{CredentialID: "cred_ga_old"}}}, ManagedPaths: []string{}, ManagedProcess: &domain.ManagedProcess{ID: "process"}}
	candidate := prior
	candidate.CredentialIDs = []string{"cred_app", "cred_ga_new"}
	publication := *prior.Publication.DomainHTTPS
	publication.GoAccess.CredentialID = "cred_ga_new"
	candidate.Publication.DomainHTTPS = &publication
	if !publicationOnlyResourceUpdate(prior, candidate) {
		t.Fatal("GoAccess credential update was classified as process-affecting")
	}
}

func TestPublicationClientPropagatesPartialJobResult(t *testing.T) {
	service, err := HelperServiceWithResources(func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error) {
		return HelperReply{}, errors.New("unused action client")
	}, func(_ context.Context, operation helperproto.Operation, _ helperproto.ResourcePayload, target string) (HelperReply, error) {
		if operation != helperproto.OperationPublicationActivate || target != "resource/res_00000000000000000000000000000001" {
			return HelperReply{}, errors.New("unexpected publication authority")
		}
		return HelperReply{Action: &helperproto.ActionResult{JobID: "job-partial", JobResult: "partial", PublicURL: "https://app.example.test/"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Invoke(context.Background(), Actor{Kind: ActorUI, Identity: "session", Generation: 1}, Call{Operation: domain.OperationPublish, Target: domain.OperationTarget{Kind: domain.OperationTargetResource, ID: "res_00000000000000000000000000000001"}, Payload: ConfirmationPayload{PlanID: "plan-one", Confirmation: "publish"}})
	if err != nil {
		t.Fatal(err)
	}
	publication, ok := result.Payload.(PublicationResult)
	if !ok || publication.JobID != "job-partial" || publication.JobResult != "partial" {
		t.Fatalf("partial publication result=%#v", result.Payload)
	}
}

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
	if len(seen) != 51 {
		t.Fatalf("core actions=%d", len(seen))
	}
}
