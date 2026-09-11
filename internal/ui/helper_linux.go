//go:build linux

package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/application"
	"lanpanel/internal/helper"
	"lanpanel/internal/helperproto"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type HelperVerifier struct{}

func (HelperVerifier) Verify(ctx context.Context, token []byte) (string, error) {
	reply, err := helperExchange(ctx, helperproto.OperationAdminTokenVerify, nil, nil, token)
	clear(reply.Secret)
	return reply.Digest, err
}

func (HelperVerifier) Source(ctx context.Context) (string, error) {
	reply, err := helperExchange(ctx, helperproto.OperationAdminTokenSource, nil, nil, nil)
	clear(reply.Secret)
	return reply.Digest, err
}

func HelperApplicationRequest(ctx context.Context, operation helperproto.Operation, payload helperproto.ActionPayload) (application.HelperReply, error) {
	return helperExchange(ctx, operation, &payload, nil, nil)
}

func HelperResourceRequest(ctx context.Context, operation helperproto.Operation, payload helperproto.ResourcePayload, target string) (application.HelperReply, error) {
	return helperExchange(ctx, operation, nil, &payload, nil, target)
}

func HelperSecretResourceRequest(ctx context.Context, operation helperproto.Operation, payload helperproto.ResourcePayload, target string, secret []byte) (application.HelperReply, error) {
	return helperExchange(ctx, operation, nil, &payload, secret, target)
}

func HelperAdminTokenReconcile(ctx context.Context) (application.HelperReply, error) {
	return helperExchange(ctx, helperproto.OperationAdminTokenReconcile, nil, nil, nil)
}

func helperExchange(ctx context.Context, operation helperproto.Operation, action *helperproto.ActionPayload, resource *helperproto.ResourcePayload, secret []byte, explicitTarget ...string) (application.HelperReply, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", helper.FixedSocketPath)
	if err != nil {
		return application.HelperReply{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.SetDeadline(time.Now())
		case <-finished:
		}
	}()
	policy, known := helperproto.PolicyFor(operation)
	if !known || policy.MaximumDuration <= 0 {
		return application.HelperReply{}, fmt.Errorf("helper operation policy is unavailable")
	}
	deadline := time.Now().Add(policy.MaximumDuration + 15*time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return application.HelperReply{}, err
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return application.HelperReply{}, fmt.Errorf("helper connection is not Unix")
	}
	raw, _ := unixConnection.SyscallConn()
	var credential *unix.Ucred
	var socketErr error
	_ = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if socketErr != nil || credential == nil || credential.Uid != 0 {
		return application.HelperReply{}, fmt.Errorf("helper peer is not root")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return application.HelperReply{}, fmt.Errorf("helper request entropy failed")
	}
	defer clear(random)
	nonce := hex.EncodeToString(random)
	requestDeadline := time.Now().UTC().Add(policy.MaximumDuration)
	target := "installation"
	if action != nil && action.TargetID != "" && (action.TargetKind == "resource" || action.TargetKind == "credential") {
		target = action.TargetKind + "/" + action.TargetID
	}
	if len(explicitTarget) == 1 {
		target = explicitTarget[0]
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "auth-" + nonce, Operation: operation, Target: target, IntentGeneration: 1, Deadline: requestDeadline, InputDigest: InputDigest(string(operation) + "/" + nonce), Action: action, Resource: resource}
	if action != nil || resource != nil {
		request.InputDigest, err = helperproto.ApplicationInputDigest(request)
		if err != nil {
			return application.HelperReply{}, err
		}
	}
	if err := helperproto.WriteRequest(connection, request, secret); err != nil {
		return application.HelperReply{}, err
	}
	response, responseSecret, err := helperproto.ReadResponse(connection, operation)
	if err != nil || response.RequestID != request.RequestID || response.Code != helperproto.ResponseSucceeded {
		if responseSecret != nil {
			responseSecret.Destroy()
		}
		if err == nil && response.RequestID == request.RequestID && response.Code == helperproto.ResponseRejected {
			switch response.ErrorCode {
			case "foreign_database_evidence", "headscale_not_configured", "connector_required", "package_identity_drift":
				return application.HelperReply{}, application.HelperRejection{Code: response.ErrorCode, JobID: response.ErrorJobID}
			}
		}
		return application.HelperReply{}, fmt.Errorf("helper request rejected")
	}
	var output []byte
	if responseSecret != nil {
		defer responseSecret.Destroy()
		output, err = responseSecret.OutputCopy()
		if err != nil {
			return application.HelperReply{}, err
		}
	}
	return application.HelperReply{Digest: response.ResultDigest, Action: response.Action, Resource: response.Resource, Headscale: response.Headscale, Connector: response.Connector, Read: response.Read, Secret: output}, nil
}
