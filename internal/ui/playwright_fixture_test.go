package ui

import (
	"context"
	"fmt"
	"lanpanel/internal/application"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/session"
	"net"
	"os"
	"strings"
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
	}, func(_ context.Context, operation helperproto.Operation, payload helperproto.ResourcePayload, target string) (application.HelperReply, error) {
		if operation != helperproto.OperationHeadscaleInitialize || payload.Operation != string(domain.OperationHeadscaleInitialize) || target != "installation" {
			return application.HelperReply{}, fmt.Errorf("unsupported fixture resource operation %q", operation)
		}
		if strings.Contains(string(payload.Resource), `"control_domain":"foreign.example.test"`) {
			return application.HelperReply{}, application.HelperRejection{Code: "foreign_database_evidence", JobID: "job_foreign_headscale_fixture"}
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
	fmt.Printf("LANPANEL_FIXTURE_ORIGIN=http://%s\n", authority)
	if err := server.Serve(); err != nil {
		t.Fatal(err)
	}
}
