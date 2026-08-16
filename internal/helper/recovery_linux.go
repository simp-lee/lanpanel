//go:build linux

package helper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/helperproto"
	"net"
	"time"
)

func RunFencedRecovery(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("fenced recovery rejects arguments")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	defer clear(random)
	now := time.Now().UTC()
	seed := "startup-contraction/" + hex.EncodeToString(random)
	digest := sha256.Sum256([]byte(seed))
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "recovery-" + hex.EncodeToString(random), Operation: helperproto.OperationStartupContraction, Target: "installation", IntentGeneration: 1, Deadline: now.Add(6 * time.Minute), InputDigest: "sha256:" + hex.EncodeToString(digest[:])}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(context.Background(), "unix", FixedSocketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(request.Deadline); err != nil {
		return err
	}
	if err := helperproto.WriteRequest(connection, request, nil); err != nil {
		return err
	}
	response, secret, err := helperproto.ReadResponse(connection, request.Operation)
	if secret != nil {
		secret.Destroy()
		return fmt.Errorf("startup recovery returned a secret")
	}
	if err != nil || response.RequestID != request.RequestID || response.Code != helperproto.ResponseSucceeded {
		return fmt.Errorf("startup recovery was rejected: %w", err)
	}
	return nil
}
