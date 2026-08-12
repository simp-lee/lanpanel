//go:build linux

package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"lanpanel/internal/application"
	"lanpanel/internal/helper"
	"lanpanel/internal/helperproto"
	"net"
	"time"
)

type HelperVerifier struct{}

func (HelperVerifier) Verify(ctx context.Context, token []byte) (string, error) {
	reply, err := helperExchange(ctx, helperproto.OperationAdminTokenVerify, nil, token)
	clear(reply.Secret)
	return reply.Digest, err
}
func (HelperVerifier) Source(ctx context.Context) (string, error) {
	reply, err := helperExchange(ctx, helperproto.OperationAdminTokenSource, nil, nil)
	clear(reply.Secret)
	return reply.Digest, err
}
func HelperApplicationRequest(ctx context.Context, operation helperproto.Operation, payload helperproto.ActionPayload) (application.HelperReply, error) {
	return helperExchange(ctx, operation, &payload, nil)
}
func HelperAdminTokenReconcile(ctx context.Context) (application.HelperReply, error) {
	return helperExchange(ctx, helperproto.OperationAdminTokenReconcile, nil, nil)
}
func helperExchange(ctx context.Context, operation helperproto.Operation, action *helperproto.ActionPayload, secret []byte) (application.HelperReply, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", helper.FixedSocketPath)
	if err != nil {
		return application.HelperReply{}, err
	}
	defer connection.Close()
	deadline := time.Now().Add(75 * time.Second)
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
	requestDeadline := time.Now().UTC().Add(time.Minute)
	if operation == helperproto.OperationAdminTokenReconcile {
		requestDeadline = time.Now().UTC().Add(30 * time.Second)
	}
	target := "installation"
	if action != nil && action.TargetKind == "resource" && action.TargetID != "" {
		target = "resource/" + action.TargetID
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "auth-" + nonce, Operation: operation, Target: target, IntentGeneration: 1, Deadline: requestDeadline, InputDigest: InputDigest(string(operation) + "/" + nonce), Action: action}
	if action != nil {
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
		return application.HelperReply{}, fmt.Errorf("helper request rejected")
	}
	var output []byte
	if responseSecret != nil {
		output, err = responseSecret.OutputCopy()
		if err != nil {
			return application.HelperReply{}, err
		}
	}
	return application.HelperReply{Digest: response.ResultDigest, Action: response.Action, Secret: output}, nil
}
