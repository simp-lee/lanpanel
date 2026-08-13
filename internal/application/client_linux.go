//go:build linux

package application

import (
	"context"
	"encoding/json"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
)

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
	registrations := []Registration{plan, rotate, closeAll, unpublish}
	if resourceClient != nil {
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
		registrations = append(registrations, create, update, start, stop)
	}
	return New(registrations)
}
