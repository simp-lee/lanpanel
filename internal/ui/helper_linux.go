//go:build linux

package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"lanpanel/internal/helper"
	"lanpanel/internal/helperproto"
	"net"
	"time"
)

type HelperVerifier struct{}

func (HelperVerifier) Verify(ctx context.Context, token []byte) (string, error) {
	return helperRequest(ctx, helperproto.OperationAdminTokenVerify, token)
}
func (HelperVerifier) Source(ctx context.Context) (string, error) {
	return helperRequest(ctx, helperproto.OperationAdminTokenSource, nil)
}
func helperRequest(ctx context.Context, operation helperproto.Operation, secret []byte) (string, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", helper.FixedSocketPath)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	deadline := time.Now().Add(10 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return "", err
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return "", fmt.Errorf("helper connection is not Unix")
	}
	raw, _ := unixConnection.SyscallConn()
	var credential *unix.Ucred
	var socketErr error
	_ = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if socketErr != nil || credential == nil || credential.Uid != 0 {
		return "", fmt.Errorf("helper peer is not root")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("helper request entropy failed")
	}
	defer clear(random)
	nonce := hex.EncodeToString(random)
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "auth-" + nonce, Operation: operation, Target: "installation", IntentGeneration: 1, Deadline: time.Now().UTC().Add(time.Minute), InputDigest: InputDigest(string(operation) + "/" + nonce)}
	if err := helperproto.WriteRequest(connection, request, secret); err != nil {
		return "", err
	}
	response, responseSecret, err := helperproto.ReadResponse(connection, operation)
	if responseSecret != nil {
		responseSecret.Destroy()
	}
	if err != nil || response.Code != helperproto.ResponseSucceeded {
		return "", fmt.Errorf("helper authentication rejected")
	}
	return response.ResultDigest, nil
}
