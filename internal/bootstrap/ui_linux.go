//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/identity"
	"lanpanel/internal/session"
	"lanpanel/internal/ui"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// RunUIRole starts the fixed non-root Management service on its generation-bound inherited listener.
func RunUIRole(args []string, stdout, stderr io.Writer) error {
	if len(args) != 0 || stdout == nil || stderr == nil {
		return fmt.Errorf("UI role requires its fixed service invocation")
	}
	if err := RequireCommitted(FixedPaths()); err != nil {
		return err
	}
	startup, err := ReadPublicStartupAuthority(FixedPaths())
	if err != nil {
		return err
	}
	listener, err := InheritedManagementListener(startup.Management, startup.GenerationID)
	if err != nil {
		return err
	}
	defer listener.Close()
	verifier := ui.HelperVerifier{}
	fingerprint := "unavailable"
	for attempt := 0; attempt < 50; attempt++ {
		value, sourceErr := verifier.Source(context.Background())
		if sourceErr == nil {
			fingerprint = value
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if fingerprint == "unavailable" {
		return fmt.Errorf("admin token source is unavailable")
	}
	sessions, err := session.New(fingerprint, session.Options{})
	if err != nil {
		return err
	}
	installationFingerprint, err := identity.Fingerprint(startup.InstallationID)
	if err != nil {
		return err
	}
	server, err := ui.New(ui.Config{Listener: listener, Authority: net.JoinHostPort(startup.Management.Address, fmt.Sprintf("%d", startup.Management.Port)), InstallationFingerprint: installationFingerprint, Verifier: verifier, Sessions: sessions, Profile: ui.FixedProfileProvider{}})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.Serve() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serveErr := server.Shutdown(shutdown)
		if errors.Is(serveErr, net.ErrClosed) || errors.Is(serveErr, os.ErrClosed) {
			return nil
		}
		return serveErr
	case serveErr := <-result:
		if errors.Is(serveErr, net.ErrClosed) || errors.Is(serveErr, os.ErrClosed) {
			return nil
		}
		return serveErr
	}
}
