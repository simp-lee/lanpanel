//go:build linux

package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/domain"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/helperproto"
	"net/netip"
	"time"
)

type HelperRejection struct {
	Code  string
	JobID string
}

func (value HelperRejection) Error() string { return "helper rejected request: " + value.Code }

type HelperReply struct {
	Digest    string
	Action    *helperproto.ActionResult
	Resource  *helperproto.ResourceResult
	Headscale *helperproto.HeadscaleResult
	Connector *helperproto.ConnectorResult
	Read      *helperproto.ReadResult
	Secret    []byte
}
type (
	HelperClient                func(context.Context, helperproto.Operation, helperproto.ActionPayload) (HelperReply, error)
	ResourceHelperClient        func(context.Context, helperproto.Operation, helperproto.ResourcePayload, string) (HelperReply, error)
	SecretResourceHelperClient  func(context.Context, helperproto.Operation, helperproto.ResourcePayload, string, []byte) (HelperReply, error)
	ResourceMutationPayload     struct{ Resource any }
	ProcessMutationPayload      struct{}
	ConnectorLoginActionPayload struct {
		PlanID       string `json:"plan_id,omitempty"`
		Confirmation string `json:"confirmation,omitempty"`
		AuthKey      []byte `json:"auth_key,omitempty"`
	}
)

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
type (
	DomainStatusPayload struct{}
	StaticRootPayload   struct {
		Path         string `json:"path"`
		Confirmation string `json:"confirmation"`
	}
)

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
	return helperServiceComplete(client, resourceClient, nil)
}

func HelperServiceComplete(client HelperClient, resourceClient ResourceHelperClient, secretResourceClient SecretResourceHelperClient) (*Service, error) {
	return helperServiceComplete(client, resourceClient, secretResourceClient)
}

func helperServiceComplete(client HelperClient, resourceClient ResourceHelperClient, secretResourceClient SecretResourceHelperClient) (*Service, error) {
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
		if call.Target.Kind == domain.OperationTargetInstallation && resourceClient != nil {
			reply, err := resourceClient(ctx, helperproto.OperationProductRead, helperproto.ResourcePayload{Operation: string(domain.OperationStatus), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation}, "installation")
			if err != nil || reply.Read == nil || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("installation status failed")
			}
			var status SystemStatus
			if err := decodeClientRead(reply.Read.Payload, &status); err != nil {
				return Result{}, err
			}
			return Result{Operation: call.Operation, Target: call.Target, Payload: status}, nil
		}
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
		headscaleAction, _ := RegisterAction(domain.OperationHeadscaleInitialize, HeadscaleInitializePayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(HeadscaleInitializePayload)
			raw, err := json.Marshal(payload)
			if err != nil {
				return Result{}, err
			}
			reply, err := resourceClient(ctx, helperproto.OperationHeadscaleInitialize, helperproto.ResourcePayload{Operation: string(domain.OperationHeadscaleInitialize), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, Confirmation: "initialize", Resource: raw}, "installation")
			if err != nil {
				return Result{}, err
			}
			if reply.Action == nil || reply.Action.JobID == "" || reply.Action.TargetID == "" || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("headscale initialization failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: *reply.Action}, nil
		})
		registrations = append(registrations, headscaleAction)
		headscaleControlAction, _ := RegisterAction(domain.OperationHeadscaleControlDeploy, HeadscaleDeployPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(HeadscaleDeployPayload)
			raw, err := json.Marshal(payload.Certificate)
			if err != nil {
				return Result{}, err
			}
			confirmation := payload.Confirmation
			if payload.PlanID == "" {
				confirmation = "plan"
			}
			reply, err := resourceClient(ctx, helperproto.OperationHeadscaleDeploy, helperproto.ResourcePayload{Operation: "headscale_deploy", ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: confirmation, Resource: raw}, "headscale")
			if err != nil || reply.Action == nil || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("headscale control deploy failed")
			}
			if payload.PlanID == "" {
				return Result{Operation: call.Operation, Target: call.Target, Payload: *reply.Action}, nil
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: *reply.Action}, nil
		})
		registrations = append(registrations, headscaleControlAction)
		headscaleReissueAction, _ := RegisterAction(domain.OperationHeadscaleReissue, HeadscaleReissuePayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(HeadscaleReissuePayload)
			raw, marshalErr := json.Marshal(payload.Certificate)
			if marshalErr != nil {
				return Result{}, marshalErr
			}
			confirmation := payload.Confirmation
			if payload.PlanID == "" {
				confirmation = "plan"
			}
			reply, err := resourceClient(ctx, helperproto.OperationHeadscaleReissue, helperproto.ResourcePayload{Operation: "headscale_reissue", ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: confirmation, Resource: raw}, "headscale")
			if err != nil || reply.Action == nil || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("headscale certificate reissue failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: *reply.Action}, nil
		})
		registrations = append(registrations, headscaleReissueAction)
		headscaleRead := func(ctx context.Context, actor Actor, call Call) (Result, error) {
			reply, err := resourceClient(ctx, helperproto.OperationHeadscaleRead, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation}, "headscale")
			if err != nil || reply.Headscale == nil || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("headscale read failed")
			}
			switch call.Operation {
			case domain.OperationHeadscaleUserList:
				return Result{Operation: call.Operation, Target: call.Target, Payload: HeadscaleUsersResult{Users: clientUsers(reply.Headscale.Users)}}, nil
			case domain.OperationPreauthKeyList:
				return Result{Operation: call.Operation, Target: call.Target, Payload: HeadscaleKeysResult{Keys: clientKeys(reply.Headscale.Keys)}}, nil
			case domain.OperationDeviceList:
				return Result{Operation: call.Operation, Target: call.Target, Payload: HeadscaleDevicesResult{Devices: clientDevices(reply.Headscale.Devices)}}, nil
			default:
				return Result{}, fmt.Errorf("headscale read operation unavailable")
			}
		}
		userList, _ := RegisterAction(domain.OperationHeadscaleUserList, EmptyPayload{}, true, false, headscaleRead)
		keyList, _ := RegisterAction(domain.OperationPreauthKeyList, EmptyPayload{}, true, false, headscaleRead)
		deviceList, _ := RegisterAction(domain.OperationDeviceList, EmptyPayload{}, true, false, headscaleRead)
		userCreate, _ := RegisterAction(domain.OperationHeadscaleUserCreate, HeadscaleUserPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(HeadscaleUserPayload)
			raw, _ := json.Marshal(payload)
			reply, err := resourceClient(ctx, helperproto.OperationHeadscaleMutation, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, Confirmation: "create", Resource: raw}, "headscale")
			if err != nil || reply.Headscale == nil || reply.Headscale.User == nil || reply.Headscale.JobID == "" || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("headscale user create failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Headscale.JobID, Payload: HeadscaleUserResult{JobID: reply.Headscale.JobID, User: clientUser(*reply.Headscale.User)}}, nil
		})
		lifecycleAction := func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(HeadscaleLifecyclePayload)
			if call.Operation == domain.OperationPreauthKeyCreate && payload.ExpirationSeconds == 0 {
				payload.ExpirationSeconds = 3600
			}
			raw, _ := json.Marshal(payload)
			operation := helperproto.OperationHeadscaleMutation
			confirmation := payload.Confirmation
			if payload.PlanID == "" {
				confirmation = "plan"
				if call.Operation == domain.OperationPreauthKeyCreate {
					operation = helperproto.OperationPreauthKeyPlan
				}
			} else if call.Operation == domain.OperationPreauthKeyCreate {
				operation = helperproto.OperationPreauthKeyCreate
			}
			target := string(call.Target.Kind) + "/" + call.Target.ID
			reply, err := resourceClient(ctx, operation, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: confirmation, Resource: raw}, target)
			if err != nil || reply.Headscale == nil {
				clear(reply.Secret)
				return Result{}, fmt.Errorf("headscale lifecycle action failed")
			}
			if payload.PlanID == "" {
				clear(reply.Secret)
				return Result{Operation: call.Operation, Target: call.Target, Payload: *reply.Headscale}, nil
			}
			switch call.Operation {
			case domain.OperationPreauthKeyCreate:
				if reply.Headscale.Key == nil || reply.Headscale.JobID == "" || len(reply.Secret) == 0 {
					clear(reply.Secret)
					return Result{}, fmt.Errorf("preauth key secret result missing")
				}
				return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Headscale.JobID, Payload: HeadscaleKeyResult{JobID: reply.Headscale.JobID, Key: clientKey(*reply.Headscale.Key), Secret: reply.Secret}}, nil
			case domain.OperationPreauthKeyRevoke:
				if reply.Headscale.Key == nil || reply.Headscale.JobID == "" || len(reply.Secret) != 0 {
					return Result{}, fmt.Errorf("preauth revoke result invalid")
				}
				return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Headscale.JobID, Payload: HeadscaleKeyResult{JobID: reply.Headscale.JobID, Key: clientKey(*reply.Headscale.Key)}}, nil
			case domain.OperationDeviceExpire:
				if reply.Headscale.Device == nil || reply.Headscale.JobID == "" || len(reply.Secret) != 0 {
					return Result{}, fmt.Errorf("device expiry result invalid")
				}
				return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Headscale.JobID, Payload: HeadscaleDeviceResult{JobID: reply.Headscale.JobID, Device: clientDevice(*reply.Headscale.Device)}}, nil
			default:
				return Result{}, fmt.Errorf("headscale lifecycle operation unavailable")
			}
		}
		preauthCreate, _ := RegisterAction(domain.OperationPreauthKeyCreate, HeadscaleLifecyclePayload{}, true, false, lifecycleAction)
		preauthRevoke, _ := RegisterAction(domain.OperationPreauthKeyRevoke, HeadscaleLifecyclePayload{}, true, false, lifecycleAction)
		deviceExpire, _ := RegisterAction(domain.OperationDeviceExpire, HeadscaleLifecyclePayload{}, true, false, lifecycleAction)
		registrations = append(registrations, userList, keyList, deviceList, userCreate, preauthCreate, preauthRevoke, deviceExpire)
		connectorBinding, _ := RegisterAction(domain.OperationConnectorBindingSet, ConnectorBindingPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(ConnectorBindingPayload)
			raw, _ := json.Marshal(payload)
			reply, err := resourceClient(ctx, helperproto.OperationConnectorMutation, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, Confirmation: "set", Resource: raw}, "connector")
			if err != nil || reply.Connector == nil || reply.Connector.JobID == "" || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("connector binding failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Connector.JobID, Payload: ConnectorMutationResult{JobID: reply.Connector.JobID}}, nil
		})
		connectorVerify, _ := RegisterAction(domain.OperationConnectorVerify, EmptyPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			reply, err := resourceClient(ctx, helperproto.OperationConnectorRead, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation}, "connector")
			if err != nil || reply.Connector == nil || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("connector verify failed")
			}
			observation, err := clientConnectorObservation(*reply.Connector)
			if err != nil {
				return Result{}, err
			}
			return Result{Operation: call.Operation, Target: call.Target, Payload: ConnectorVerifyResult{Observation: observation}}, nil
		})
		connectorLogin, _ := RegisterAction(domain.OperationConnectorLogin, ConnectorLoginActionPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(ConnectorLoginActionPayload)
			resource := helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID}
			if payload.PlanID == "" {
				resource.Confirmation = "plan"
				reply, err := resourceClient(ctx, helperproto.OperationConnectorLoginPlan, resource, "connector")
				clear(payload.AuthKey)
				if err != nil || reply.Connector == nil {
					return Result{}, fmt.Errorf("connector login Plan failed")
				}
				return Result{Operation: call.Operation, Target: call.Target, Payload: *reply.Connector}, nil
			}
			resource.Confirmation = payload.Confirmation
			if secretResourceClient == nil || len(payload.AuthKey) == 0 {
				return Result{}, fmt.Errorf("connector login secret client unavailable")
			}
			reply, err := secretResourceClient(ctx, helperproto.OperationConnectorLogin, resource, "connector", payload.AuthKey)
			clear(payload.AuthKey)
			if err != nil || reply.Connector == nil || reply.Connector.JobID == "" || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("connector login failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Connector.JobID, Payload: ConnectorMutationResult{JobID: reply.Connector.JobID}}, nil
		})
		registrations = append(registrations, connectorBinding, connectorVerify, connectorLogin)
		productRead := func(ctx context.Context, actor Actor, call Call) (Result, error) {
			target := "installation"
			if call.Target.ID != "" {
				target = string(call.Target.Kind) + "/" + call.Target.ID
			}
			reply, err := resourceClient(ctx, helperproto.OperationProductRead, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation}, target)
			if err != nil || reply.Read == nil || reply.Read.Operation != string(call.Operation) || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("product read failed")
			}
			var payload any
			switch call.Operation {
			case domain.OperationDiagnostics:
				var value DiagnosticsResult
				err = decodeClientRead(reply.Read.Payload, &value)
				payload = value
			case domain.OperationConfigurationExport:
				var value ConfigurationExport
				err = decodeClientRead(reply.Read.Payload, &value)
				payload = value
			case domain.OperationJobList:
				var value JobsResult
				err = decodeClientRead(reply.Read.Payload, &value)
				payload = value
			case domain.OperationJobDetail:
				var value JobResult
				err = decodeClientRead(reply.Read.Payload, &value)
				payload = value
			default:
				return Result{}, fmt.Errorf("product read operation unavailable")
			}
			if err != nil {
				return Result{}, err
			}
			return Result{Operation: call.Operation, Target: call.Target, Payload: payload}, nil
		}
		diagnosticsAction, _ := RegisterAction(domain.OperationDiagnostics, EmptyPayload{}, true, false, productRead)
		exportAction, _ := RegisterAction(domain.OperationConfigurationExport, EmptyPayload{}, true, false, productRead)
		jobListAction, _ := RegisterAction(domain.OperationJobList, EmptyPayload{}, true, false, productRead)
		jobDetailAction, _ := RegisterAction(domain.OperationJobDetail, EmptyPayload{}, true, false, productRead)
		registrations = append(registrations, diagnosticsAction, exportAction, jobListAction, jobDetailAction)
		resourceDelete, _ := RegisterAction(domain.OperationResourceDelete, ConfirmationPayload{}, true, false, func(ctx context.Context, actor Actor, call Call) (Result, error) {
			payload := call.Payload.(ConfirmationPayload)
			reply, err := resourceClient(ctx, helperproto.OperationResourceDelete, helperproto.ResourcePayload{Operation: string(call.Operation), ActorIdentity: actor.Identity, ActorGeneration: actor.Generation, PlanID: payload.PlanID, Confirmation: payload.Confirmation}, "resource/"+call.Target.ID)
			if err != nil || reply.Action == nil || reply.Action.JobID == "" || len(reply.Secret) != 0 {
				return Result{}, fmt.Errorf("resource delete failed")
			}
			return Result{Operation: call.Operation, Target: call.Target, JobID: reply.Action.JobID, Payload: ResourceDeleteResult{JobID: reply.Action.JobID}}, nil
		})
		registrations = append(registrations, resourceDelete)
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
			if err != nil {
				var rejection HelperRejection
				if errors.As(err, &rejection) {
					return Result{}, err
				}
				return Result{}, fmt.Errorf("resource mutation failed")
			}
			if reply.Resource == nil || reply.Resource.ResourceID == "" {
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

func decodeClientRead(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("product read payload trailing data")
	}
	return nil
}

func clientConnectorObservation(value helperproto.ConnectorResult) (managedconnector.Observation, error) {
	observation := managedconnector.Observation{ClientVersion: value.ClientVersion, ControlURL: value.ControlURL, ObservedAt: value.ValidUntil.Add(-managedconnector.EvidenceTTL), ValidUntil: value.ValidUntil}
	for _, text := range value.LocalIPs {
		address, err := netip.ParseAddr(text)
		if err != nil {
			return managedconnector.Observation{}, err
		}
		observation.LocalIPs = append(observation.LocalIPs, address)
	}
	for _, peer := range value.Peers {
		address, err := netip.ParseAddr(peer.IP)
		if err != nil {
			return managedconnector.Observation{}, err
		}
		observation.Peers = append(observation.Peers, managedconnector.Peer{IP: address, Online: peer.Online})
	}
	if time.Now().UTC().After(observation.ValidUntil) {
		return managedconnector.Observation{}, fmt.Errorf("connector helper evidence expired")
	}
	return observation, nil
}

func clientUser(value helperproto.HeadscaleUserRecord) managedheadscale.User {
	return managedheadscale.User{ID: value.ID, Name: value.Name, CreatedAt: value.CreatedAt, DeviceCount: value.DeviceCount, ActiveKeyCount: value.ActiveKeyCount}
}

func clientUsers(values []helperproto.HeadscaleUserRecord) []managedheadscale.User {
	result := make([]managedheadscale.User, len(values))
	for index, value := range values {
		result[index] = clientUser(value)
	}
	return result
}

func clientKey(value helperproto.HeadscaleKeyRecord) managedheadscale.PreauthKey {
	return managedheadscale.PreauthKey{ID: value.ID, UserID: value.UserID, Reusable: value.Reusable, Ephemeral: value.Ephemeral, Used: value.Used, Expiration: value.Expiration, CreatedAt: value.CreatedAt}
}

func clientKeys(values []helperproto.HeadscaleKeyRecord) []managedheadscale.PreauthKey {
	result := make([]managedheadscale.PreauthKey, len(values))
	for index, value := range values {
		result[index] = clientKey(value)
	}
	return result
}

func clientDevice(value helperproto.HeadscaleDeviceRecord) managedheadscale.Device {
	return managedheadscale.Device{ID: value.ID, Name: value.Name, UserID: value.UserID, IPAddresses: append([]string(nil), value.IPAddresses...), Online: value.Online, Expiry: value.Expiry, CreatedAt: value.CreatedAt}
}

func clientDevices(values []helperproto.HeadscaleDeviceRecord) []managedheadscale.Device {
	result := make([]managedheadscale.Device, len(values))
	for index, value := range values {
		result[index] = clientDevice(value)
	}
	return result
}
