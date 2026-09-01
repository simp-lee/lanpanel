package ui

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/application"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/session"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type playwrightCredential struct {
	token       string
	fingerprint string
}

type playwrightVerifier struct {
	current atomic.Pointer[playwrightCredential]
}

func (value *playwrightVerifier) set(token, fingerprint string) {
	value.current.Store(&playwrightCredential{token: token, fingerprint: fingerprint})
}

func (value *playwrightVerifier) Verify(_ context.Context, token []byte) (string, error) {
	current := value.current.Load()
	if current == nil || string(token) != current.token {
		return "", fmt.Errorf("invalid token")
	}
	return current.fingerprint, nil
}

func (value *playwrightVerifier) Source(context.Context) (string, error) {
	current := value.current.Load()
	if current == nil {
		return "", fmt.Errorf("token unavailable")
	}
	return current.fingerprint, nil
}

type playwrightProfile struct{}

type playwrightActionBarrier struct {
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

func newPlaywrightActionBarrier() *playwrightActionBarrier {
	return &playwrightActionBarrier{started: make(chan struct{}), release: make(chan struct{})}
}

func (barrier *playwrightActionBarrier) wait(ctx context.Context) error {
	barrier.startOnce.Do(func() { close(barrier.started) })
	select {
	case <-barrier.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (barrier *playwrightActionBarrier) unblock() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

func (playwrightProfile) Current(context.Context) (Profile, error) { return ProfileNormal, nil }

func TestPlaywrightFixture(t *testing.T) {
	if os.Getenv("LANPANEL_PLAYWRIGHT_FIXTURE") != "1" {
		t.Skip("browser fixture role is disabled")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := listener.Addr().String()
	fingerprint := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	verifier := &playwrightVerifier{}
	verifier.set("admin", fingerprint)
	manager, err := session.New(fingerprint, session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	actionBarrier := newPlaywrightActionBarrier()
	actions, err := application.HelperServiceWithResources(func(_ context.Context, operation helperproto.Operation, payload helperproto.ActionPayload) (application.HelperReply, error) {
		switch operation {
		case helperproto.OperationApplicationPlan:
			return application.HelperReply{Digest: InputDigest("plan"), Action: &helperproto.ActionResult{PlanID: "plan-fixture", Confirmation: InputDigest("confirmation"), Operation: string(domain.OperationAdminTokenRotate), TargetKind: string(domain.OperationTargetInstallation), ExposureSummary: "admin_token_rotation", Prerequisites: "authenticated_destructive_confirmation", ExpiresAt: time.Now().Add(time.Minute)}}, nil
		case helperproto.OperationAdminTokenRotate:
			fingerprint := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			verifier.set("new-admin-token", fingerprint)
			return application.HelperReply{Digest: fingerprint, Action: &helperproto.ActionResult{JobID: "job-fixture"}, Secret: []byte("new-admin-token")}, nil
		default:
			return application.HelperReply{}, fmt.Errorf("unsupported fixture operation %q", operation)
		}
	}, func(ctx context.Context, operation helperproto.Operation, payload helperproto.ResourcePayload, target string) (application.HelperReply, error) {
		if operation != helperproto.OperationHeadscaleInitialize || payload.Operation != string(domain.OperationHeadscaleInitialize) || target != "installation" {
			return application.HelperReply{}, fmt.Errorf("unsupported fixture resource operation %q", operation)
		}
		if strings.Contains(string(payload.Resource), `"control_domain":"foreign.example.test"`) {
			return application.HelperReply{}, application.HelperRejection{Code: "foreign_database_evidence", JobID: "job_foreign_headscale_fixture"}
		}
		if strings.Contains(string(payload.Resource), `"control_domain":"blocked.example.test"`) {
			if err := actionBarrier.wait(ctx); err != nil {
				return application.HelperReply{}, err
			}
		}
		return application.HelperReply{Digest: InputDigest("headscale"), Action: &helperproto.ActionResult{JobID: "job-headscale-fixture", Operation: string(domain.OperationHeadscaleInitialize), TargetKind: string(domain.OperationTargetInstallation), TargetID: "hds_00000000000000000000000000000001"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Listener: listener, Authority: authority, InstallationFingerprint: "0123456789abcdef", Verifier: verifier, Sessions: manager, Profile: playwrightProfile{}, Actions: actions})
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	shutdownResponded := make(chan struct{})
	controlMux := http.NewServeMux()
	controlMux.HandleFunc("/action/started", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		select {
		case <-actionBarrier.started:
			writer.WriteHeader(http.StatusNoContent)
		case <-request.Context().Done():
		}
	})
	controlMux.HandleFunc("/action/release", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		actionBarrier.unblock()
		writer.WriteHeader(http.StatusNoContent)
	})
	controlMux.HandleFunc("/shutdown", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := server.Shutdown(shutdownContext)
		cancel()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		} else {
			writer.WriteHeader(http.StatusNoContent)
		}
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		close(shutdownResponded)
	})
	controlServer := &http.Server{Handler: controlMux, ReadHeaderTimeout: 5 * time.Second}
	controlDone := make(chan error, 1)
	go func() { controlDone <- controlServer.Serve(controlListener) }()

	fmt.Printf("LANPANEL_FIXTURE_ORIGIN=http://%s\n", authority)
	fmt.Printf("LANPANEL_FIXTURE_CONTROL=http://%s\n", controlListener.Addr().String())
	serveErr := server.Serve()
	if !errors.Is(serveErr, http.ErrServerClosed) {
		t.Fatal(serveErr)
	}
	select {
	case <-shutdownResponded:
	case <-time.After(10 * time.Second):
		t.Fatal("fixture shutdown response did not complete")
	}
	controlContext, cancelControl := context.WithTimeout(context.Background(), 5*time.Second)
	if err := controlServer.Shutdown(controlContext); err != nil {
		cancelControl()
		t.Fatal(err)
	}
	cancelControl()
	if err := <-controlDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}
