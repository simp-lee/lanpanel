//go:build linux

package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/identity"
	"net"
	"os"
	"time"
)

// RunUIRole is the reserved resident Management role. S9 will attach the
// authenticated HTTP server to this already verified inherited listener.
func RunUIRole(args []string, stdout, stderr io.Writer) error {
	if len(args) != 0 || stdout == nil || stderr == nil {
		return fmt.Errorf("UI role requires its fixed service invocation")
	}
	if err := RequireCommitted(FixedPaths()); err != nil {
		return err
	}
	data, err := os.ReadFile(FixedPaths().StartupAuthority)
	if err != nil {
		return err
	}
	var startup struct {
		SchemaVersion  string                       `json:"schema_version"`
		AttemptID      string                       `json:"attempt_id"`
		InstallationID string                       `json:"installation_id"`
		GenerationID   string                       `json:"generation_id"`
		Management     identity.ManagementAuthority `json:"management_authority"`
		CommitDigest   string                       `json:"commit_digest"`
	}
	if decodeCanonical(data, &startup) != nil || startup.SchemaVersion != "lanpanel.startup-authority.v1" || !identity.ValidateGenerationID(startup.GenerationID) {
		return fmt.Errorf("UI startup authority is invalid")
	}
	listener, err := InheritedManagementListener(startup.Management, startup.GenerationID)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		if tcp, ok := listener.(*net.TCPListener); ok {
			_ = tcp.SetDeadline(time.Now().Add(time.Second))
		}
		connection, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 4)
		read, _ := connection.Read(buffer)
		if string(buffer[:read]) == "PING" {
			_, _ = connection.Write([]byte("LPUI " + startup.GenerationID + "\n"))
		}
		_ = connection.Close()
	}
}
