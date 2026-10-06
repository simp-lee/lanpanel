package application

import (
	"context"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"slices"
	"strings"
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

func TestPlanPreservesTypedHelperRejections(t *testing.T) {
	expected := HelperRejection{Code: "certificate_preflight_failed", JobID: "job_" + strings.Repeat("a", 64)}
	service, err := HelperService(func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error) {
		return HelperReply{}, expected
	})
	if err != nil {
		t.Fatal(err)
	}
	installation := domain.OperationTarget{Kind: domain.OperationTargetInstallation}
	_, err = service.Invoke(context.Background(), Actor{Kind: ActorUI, Identity: "session", Generation: 1}, Call{
		Operation: domain.OperationPlan,
		Target:    installation,
		Payload:   PlanPayload{Operation: domain.OperationAdminTokenRotate, Target: installation},
	})
	var rejection HelperRejection
	if !errors.As(err, &rejection) || rejection.Code != expected.Code || rejection.JobID != expected.JobID {
		t.Fatalf("Plan rejection was not preserved: %v", err)
	}
}

func TestResourceActionPreservesTypedHelperRejections(t *testing.T) {
	expected := HelperRejection{Code: "local_process_only", JobID: "job_" + strings.Repeat("a", 64)}
	service, err := HelperServiceWithResources(func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error) {
		return HelperReply{}, errors.New("unused action client")
	}, func(_ context.Context, operation helperproto.Operation, _ helperproto.ResourcePayload, _ string) (HelperReply, error) {
		if operation == helperproto.OperationProcessLifecycle {
			return HelperReply{}, expected
		}
		return HelperReply{}, HelperRejection{Code: "resource_delete_blocked", JobID: "job_" + strings.Repeat("b", 64)}
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{Kind: ActorUI, Identity: "session", Generation: 1}
	_, err = service.Invoke(context.Background(), actor, Call{Operation: domain.OperationProcessStart, Target: domain.OperationTarget{Kind: domain.OperationTargetResource, ID: "res_00000000000000000000000000000001"}, Payload: ProcessMutationPayload{}})
	var rejection HelperRejection
	if !errors.As(err, &rejection) || rejection.Code != expected.Code || rejection.JobID != expected.JobID {
		t.Fatalf("process rejection was not preserved: %v", err)
	}
	_, err = service.Invoke(context.Background(), actor, Call{Operation: domain.OperationResourceDelete, Target: domain.OperationTarget{Kind: domain.OperationTargetResource, ID: "res_00000000000000000000000000000001"}, Payload: ConfirmationPayload{PlanID: "plan", Confirmation: "delete"}})
	if !errors.As(err, &rejection) || rejection.Code != "resource_delete_blocked" {
		t.Fatalf("delete rejection was not preserved: %v", err)
	}
}

func TestHelperBackedActionsPreserveTypedRejections(t *testing.T) {
	expected := HelperRejection{Code: "typed_helper_rejection", JobID: "job_" + strings.Repeat("c", 64)}
	service, err := HelperServiceComplete(
		func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error) {
			return HelperReply{}, expected
		},
		func(context.Context, helperproto.Operation, helperproto.ResourcePayload, string) (HelperReply, error) {
			return HelperReply{}, expected
		},
		func(context.Context, helperproto.Operation, helperproto.ResourcePayload, string, []byte) (HelperReply, error) {
			return HelperReply{}, expected
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{Kind: ActorUI, Identity: "session", Generation: 1}
	resource := domain.OperationTarget{Kind: domain.OperationTargetResource, ID: "res_00000000000000000000000000000001"}
	cases := []struct {
		name string
		call Call
	}{
		{name: "admin token rotation", call: Call{Operation: domain.OperationAdminTokenRotate, Target: domain.OperationTarget{Kind: domain.OperationTargetInstallation}, Payload: ConfirmationPayload{PlanID: "plan", Confirmation: "rotate"}}},
		{name: "status", call: Call{Operation: domain.OperationStatus, Target: resource, Payload: DomainStatusPayload{}}},
		{name: "close all", call: Call{Operation: domain.OperationCloseAll, Target: domain.OperationTarget{Kind: domain.OperationTargetInstallation}, Payload: ConfirmationPayload{PlanID: "plan", Confirmation: "close"}}},
		{name: "headscale user", call: Call{Operation: domain.OperationHeadscaleUserCreate, Target: domain.OperationTarget{Kind: domain.OperationTargetHeadscale}, Payload: HeadscaleUserPayload{Name: "alice"}}},
		{name: "headscale lifecycle", call: Call{Operation: domain.OperationPreauthKeyCreate, Target: domain.OperationTarget{Kind: domain.OperationTargetHeadscaleUser, ID: "1"}, Payload: HeadscaleLifecyclePayload{PlanID: "plan", Confirmation: "create"}}},
		{name: "connector binding", call: Call{Operation: domain.OperationConnectorBindingSet, Target: domain.OperationTarget{Kind: domain.OperationTargetConnector}, Payload: ConnectorBindingPayload{ControlURL: "https://control.example.test"}}},
		{name: "connector verify", call: Call{Operation: domain.OperationConnectorVerify, Target: domain.OperationTarget{Kind: domain.OperationTargetConnector}, Payload: EmptyPayload{}}},
		{name: "connector login", call: Call{Operation: domain.OperationConnectorLogin, Target: domain.OperationTarget{Kind: domain.OperationTargetConnector}, Payload: ConnectorLoginActionPayload{PlanID: "plan", Confirmation: "login", AuthKey: []byte("key")}}},
		{name: "product read", call: Call{Operation: domain.OperationDiagnostics, Target: domain.OperationTarget{Kind: domain.OperationTargetInstallation}, Payload: EmptyPayload{}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Invoke(context.Background(), actor, test.call)
			var rejection HelperRejection
			if !errors.As(err, &rejection) || rejection.Code != expected.Code || rejection.JobID != expected.JobID {
				t.Fatalf("typed rejection was not preserved: %v", err)
			}
		})
	}
}

func TestDependencyActionsPreserveTypedRejectionWithoutJob(t *testing.T) {
	service, err := HelperServiceWithResources(func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error) {
		return HelperReply{}, HelperRejection{Code: "connector_required"}
	}, func(context.Context, helperproto.Operation, helperproto.ResourcePayload, string) (HelperReply, error) {
		return HelperReply{}, HelperRejection{Code: "connector_required"}
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{Kind: ActorUI, Identity: "session", Generation: 1}
	target := domain.OperationTarget{Kind: domain.OperationTargetResource, ID: "res_00000000000000000000000000000001"}
	cases := []struct {
		name string
		call Call
	}{
		{name: "managed basic", call: Call{Operation: domain.OperationManagedBasicCreate, Target: target, Payload: ManagedBasicPayload{Username: "alice", Confirmation: "generate"}}},
		{name: "static root", call: Call{Operation: domain.OperationStaticRootRegister, Target: target, Payload: StaticRootPayload{Path: "/srv/app", Confirmation: "register"}}},
		{name: "external htpasswd", call: Call{Operation: domain.OperationExternalHTPasswdRegister, Target: target, Payload: StaticRootPayload{Path: "/srv/app/.htpasswd", Confirmation: "register"}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Invoke(context.Background(), actor, test.call)
			var rejection HelperRejection
			if !errors.As(err, &rejection) || rejection.Code != "connector_required" || rejection.JobID != "" {
				t.Fatalf("typed rejection was not preserved: %v", err)
			}
		})
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

func TestFinalCoreActionVocabularyIsExact(t *testing.T) {
	expected := []domain.OperationCode{
		"plan", "status", "admin_token_rotate", "management_https_configure", "headscale_initialize",
		"headscale_control_deploy", "headscale_certificate_reissue", "headscale_user_create", "headscale_user_list",
		"preauth_key_create", "preauth_key_list", "preauth_key_revoke", "device_list", "device_expire",
		"connector_binding_set", "connector_verify", "connector_login", "resource_create", "resource_update", "publish", "unpublish", "close_all",
		"process_start", "process_stop", "managed_basic_create", "managed_basic_rotate",
		"managed_basic_delete", "static_root_register", "external_htpasswd_register", "resource_delete", "diagnostics", "configuration_export", "job_list", "job_detail",
	}
	actual := CoreActions()
	if !slices.Equal(actual, expected) {
		t.Fatalf("final CoreActions=%v, want %v", actual, expected)
	}
	seen := map[domain.OperationCode]bool{}
	for _, action := range actual {
		if seen[action] {
			t.Fatal("duplicate action")
		}
		seen[action] = true
		if parsed, err := domain.ParseOperationCode(string(action)); err != nil || parsed != action {
			t.Fatalf("parse action %q: %v", action, err)
		}
	}
}
