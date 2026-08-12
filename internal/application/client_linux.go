//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/helperproto"
)

type HelperReply struct {
	Digest string
	Action *helperproto.ActionResult
	Secret []byte
}
type HelperClient func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error)
type RotationResult struct {
	Fingerprint string
	JobID       string
	Token       []byte
}

func HelperService(client HelperClient) (*Service, error) {
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
	return New([]Registration{plan, rotate})
}
