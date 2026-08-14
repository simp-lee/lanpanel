//go:build linux

package renewal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/helperproto"
	"net"
	"time"
)

const fixedSocketPath = "/run/lanpanel/helper.sock"

func RunTimer(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("certificate timer rejects arguments")
	}
	now := time.Now().UTC()
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: fmt.Sprintf("certificate-timer-%d", now.UnixNano()), Operation: helperproto.OperationCertificateRenew, Target: "installation", IntentGeneration: 1, Deadline: now.Add(10 * time.Minute), InputDigest: digest([]byte(now.Format(time.RFC3339Nano)))}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "unix", fixedSocketPath)
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
		return fmt.Errorf("certificate timer returned secret")
	}
	if err != nil || response.RequestID != request.RequestID || response.Code != helperproto.ResponseSucceeded {
		return fmt.Errorf("certificate timer failed: %w", err)
	}
	return nil
}
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
