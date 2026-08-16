//go:build linux

package application

import (
	"context"
	"encoding/json"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
)

type HelperRejection struct {
	Code  string
	JobID string
}

func (value HelperRejection) Error() string { return "helper rejected request: " + value.Code }

type HelperReply struct {
	Digest   string
	Action   *helperproto.ActionResult
	Resource *helperproto.ResourceResult
	Secret   []byte
}
type HelperClient func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error)
type ResourceHelperClient func(context.Context, helperproto.Operation, helperproto.ResourcePayload, string) (HelperReply, error)
type ResourceMutationPayload struct{ Resource any }
type ProcessMutationPayload struct{}
type HeadscaleInitializePayload struct {
	ControlDomain     string `json:"control_domain"`
	MagicDNSNamespace string `json:"magicdns_namespace"`
	SourceKind        string `json:"source_kind"`
	MirrorURL         string `json:"mirror_url,omitempty"`
	OfflinePath       string `json:"offline_path,omitempty"`
	ProxyURL          string `json:"proxy_url,omitempty"`
	Confirmation      string `json:"confirmation"`
}
type ManagedBasicPayload struct {
	Username     string `json:"username,omitempty"`
	PlanID       string `json:"plan_id,omitempty"`
	Confirmation string `json:"confirmation"`
}
type DomainStatusPayload struct{}
type StaticRootPayload struct {
	Path         string `json:"path"`
	Confirmation string `json:"confirmation"`
}
type ManagedBasicActionResult struct {
	CredentialID string `json:"credential_id"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	JobID        string `json:"job_id"`
	Password     []byte `json:"password,omitempty"`
}
type PublicationResult struct {
	JobID     string `json:"job_id"`
	JobResult string `json:"job_result"`
	PublicURL string `json:"public_url"`
}
type RotationResult struct {
	Fingerprint string
	JobID       string
	Token       []byte
}
type ContractionResult struct {
	Outcome           string
	AccessClosed      bool
	SharedIngressDown bool
	AccessMayRemain   bool
}

func HelperService(client HelperClient) (*Service, error) {
	return HelperServiceWithResources(client, nil)
}
func HelperServiceWithResources(client HelperClient, resourceClient ResourceHelperClient) (*Service, error) {
	if client == nil {
		return nil, fmt.Errorf("application helper client missing")
	}
	plan, _ := RegisterAction("plan", PlanPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
		payload := call.Payload.(PlanPayload)
		reply, err := client(ctx, helperproto.OperationApplicationPlan, helperproto.ActionPayload{Operation: string(payload.Operation), TargetKind: string(payload.Target.Kind), TargetID: payload.Target.ID, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation})
		if err != nil || reply.Action == nil || reply.Action.PlanID == "" {
			clear(reply.Secret)
			return Result{}, fmt.Errorf("application Plan failed")
		}
		return Result{Operation: call.Operation, Target: call.Target, Payload: *reply.Action}, nil
	})
	rotate, _ := RegisterAction("admin_token_rotate", ConfirmationPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
		payload := call.Payload.(ConfirmationPayload)
		reply, err := client(ctx, helperproto.OperationAdminTokenRotate, helperproto.ActionPayload{Operation: string(call.Operation), TargetKind: string(call.Target.Kind), TargetID: call.Target.ID, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: payload.Confirmation})
		if err != nil || reply.Action == nil || reply.Action.JobID == "" || len(reply.Secret) == 0 {
			clear(reply.Secret)
			return Result{}, fmt.Errorf("admin token rotation failed")
		}
		return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: RotationResult{reply.Digest, reply.Action.JobID, reply.Secret}}, nil
	})
	managedBasicAction := func(ctx context.Context, actor Actor, call Call) (Result, error) {
		payload := call.Payload.(ManagedBasicPayload)
		helperOperation := helperproto.OperationManagedBasicGenerate
		if call.Operation == domain.OperationManagedBasicDelete {
			helperOperation = helperproto.OperationManagedBasicDelete
		}
		reply, err := client(ctx, helperOperation, helperproto.ActionPayload{Operation: string(call.Operation), TargetKind: string(call.Target.Kind), TargetID: call.Target.ID, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: payload.Confirmation, Username: payload.Username})
		if err != nil || reply.Action == nil || reply.Action.JobID == "" {
			clear(reply.Secret)
			return Result{}, fmt.Errorf("managed Basic action failed")
		}
		if call.Operation != domain.OperationManagedBasicDelete && len(reply.Secret) == 0 {
			return Result{}, fmt.Errorf("managed Basic secret missing")
		}
		result := ManagedBasicActionResult{CredentialID: reply.Action.TargetID, Fingerprint: reply.Digest, JobID: reply.Action.JobID, Password: reply.Secret}
		return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: result}, nil
	}
	staticRootAction, _ := RegisterAction(domain.OperationStaticRootRegister, StaticRootPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
		payload := call.Payload.(StaticRootPayload)
		reply, err := client(ctx, helperproto.OperationStaticRootRegister, helperproto.ActionPayload{Operation: string(call.Operation), TargetKind: string(call.Target.Kind), TargetID: call.Target.ID, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, Confirmation: payload.Confirmation, StaticRoot: payload.Path})
		if err != nil || reply.Action == nil || reply.Action.JobID == "" || len(reply.Secret) != 0 {
			return Result{}, fmt.Errorf("static root registration failed")
		}
		return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: *reply.Action}, nil
	})
	externalHTPasswdAction, _ := RegisterAction(domain.OperationExternalHTPasswdRegister, StaticRootPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
		payload := call.Payload.(StaticRootPayload)
		reply, err := client(ctx, helperproto.OperationExternalHTPasswdRegister, helperproto.ActionPayload{Operation: string(call.Operation), TargetKind: string(call.Target.Kind), TargetID: call.Target.ID, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, Confirmation: payload.Confirmation, ExternalHTPasswdFile: payload.Path})
		if err != nil || reply.Action == nil || reply.Action.JobID == "" || len(reply.Secret) != 0 {
			return Result{}, fmt.Errorf("external htpasswd registration failed")
		}
		return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: *reply.Action}, nil
	})
	domainStatusAction, _ := RegisterAction(domain.OperationStatus, DomainStatusPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
		reply, err := client(ctx, helperproto.OperationDomainStatus, helperproto.ActionPayload{Operation: "status", TargetKind: "resource", TargetID: call.Target.ID, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation})
		if err != nil || reply.Resource == nil || reply.Resource.ResourceID != call.Target.ID || len(reply.Secret) != 0 {
			return Result{}, fmt.Errorf("domain status failed")
		}
		status := DomainSourceStatus{ResourceID: reply.Resource.ResourceID, Status: reply.Resource.Status, AccessMayRemain: reply.Resource.AccessMayRemain, CredentialID: reply.Resource.CredentialID, CredentialFingerprint: reply.Resource.CredentialFingerprint, CredentialChanged: reply.Resource.CredentialChanged, GoAccessCredentialID: reply.Resource.GoAccessCredentialID, GoAccessCredentialFingerprint: reply.Resource.GoAccessCredentialFingerprint, GoAccessCredentialChanged: reply.Resource.GoAccessCredentialChanged, StaticFingerprint: reply.Resource.StaticFingerprint, StaticChanged: reply.Resource.StaticChanged, ObservedAt: reply.Resource.ObservedAt, Reason: reply.Resource.Reason, AllowedActions: append([]string(nil), reply.Resource.AllowedActions...), CredentialIDs: append([]string(nil), reply.Resource.CredentialIDs...), GoAccessRetirementJobID: reply.Resource.GoAccessRetirementJobID, GoAccessRetirementGenerations: append([]uint64(nil), reply.Resource.GoAccessRetirementGenerations...)}
		return Result{Operation: call.Operation, Target: call.Target, Payload: status}, nil
	})
	basicCreate, _ := RegisterAction(domain.OperationManagedBasicCreate, ManagedBasicPayload{}, true, false, managedBasicAction)
	basicRotate, _ := RegisterAction(domain.OperationManagedBasicRotate, ManagedBasicPayload{}, true, false, managedBasicAction)
	basicDelete, _ := RegisterAction(domain.OperationManagedBasicDelete, ManagedBasicPayload{}, true, false, managedBasicAction)
	contractionAction := func(ctx context.Context, actor Actor, call Call) (Result, error) {
		payload := call.Payload.(ConfirmationPayload)
		reply, err := client(ctx, helperproto.OperationContractionClose, helperproto.ActionPayload{Operation: string(call.Operation), TargetKind: string(call.Target.Kind), TargetID: call.Target.ID, ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: payload.Confirmation})
		if err != nil || reply.Action == nil || reply.Action.ContractionOutcome == "" || len(reply.Secret) != 0 {
			clear(reply.Secret)
			return Result{}, fmt.Errorf("close-all contraction failed")
		}
		return Result{Operation: call.Operation, Target: call.Target, Payload: ContractionResult{Outcome: reply.Action.ContractionOutcome, AccessClosed: reply.Action.AccessClosed, SharedIngressDown: reply.Action.SharedIngressDown, AccessMayRemain: reply.Action.AccessMayRemain}}, nil
	}
	closeAll, _ := RegisterAction("close_all", ConfirmationPayload{}, true, false, contractionAction)
	unpublish, _ := RegisterAction("unpublish", ConfirmationPayload{}, true, false, contractionAction)
	registrations := []Registration{plan, rotate, basicCreate, basicRotate, basicDelete, staticRootAction, externalHTPasswdAction, domainStatusAction, closeAll, unpublish}
	if resourceClient != nil {
		headscaleAction, _ := RegisterAction(domain.OperationDeploy, HeadscaleInitializePayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(HeadscaleInitializePayload)
			raw, err := json.Marshal(payload)
			if err != nil {
				return Result{}, err
			}
			reply, err := resourceClient(ctx, helperproto.OperationHeadscaleInitialize, helperproto.ResourcePayload{Operation: string(domain.OperationDeploy), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, Confirmation: "initialize", Resource: raw}, "installation")
			if err != nil {
				return Result{}, err
			}
			if reply.Action == nil || reply.Action.JobID == "" || reply.Action.TargetID == "" || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("Headscale initialization failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: *reply.Action}, nil
		})
		registrations = append(registrations, headscaleAction)
		resourceAction := func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(ResourceMutationPayload)
			raw, err := json.Marshal(payload.Resource)
			if err != nil {
				return Result{}, err
			}
			target := "installation"
			if call.Operation == domain.OperationResourceUpdate {
				target = "resource/" + call.Target.ID
			}
			reply, err := resourceClient(ctx, helperproto.OperationResourceMutation, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, Resource: raw}, target)
			if err != nil || reply.Resource == nil || reply.Resource.ResourceID == "" {
				return Result{}, fmt.Errorf("resource mutation failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, Payload: *reply.Resource}, nil
		}
		create, _ := RegisterAction(domain.OperationResourceCreate, ResourceMutationPayload{}, true, false, resourceAction)
		update, _ := RegisterAction(domain.OperationResourceUpdate, ResourceMutationPayload{}, true, false, resourceAction)
		processAction := func(ctx context.Context, actor Actor, call Call) (Result, error) {
			reply, err := resourceClient(ctx, helperproto.OperationProcessLifecycle, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation}, "resource/"+call.Target.ID)
			if err != nil || reply.Action == nil || reply.Action.JobID == "" {
				return Result{}, fmt.Errorf("process lifecycle failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: *reply.Action}, nil
		}
		start, _ := RegisterAction(domain.OperationProcessStart, ProcessMutationPayload{}, true, false, processAction)
		stop, _ := RegisterAction(domain.OperationProcessStop, ProcessMutationPayload{}, true, false, processAction)
		publish, _ := RegisterAction(domain.OperationPublish, ConfirmationPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(ConfirmationPayload)
			reply, err := resourceClient(ctx, helperproto.OperationPublicationActivate, helperproto.ResourcePayload{Operation: string(domain.OperationPublish), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: payload.Confirmation}, "resource/"+call.Target.ID)
			if err != nil || reply.Action == nil || reply.Action.JobID == "" || reply.Action.JobResult != "succeeded" && reply.Action.JobResult != "partial" {
				return Result{}, fmt.Errorf("publication activation failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: PublicationResult{JobID: reply.Action.JobID, JobResult: reply.Action.JobResult, PublicURL: reply.Action.PublicURL}}, nil
		})
		registrations = append(registrations, create, update, start, stop, publish)
	}
	return New(registrations)
}
