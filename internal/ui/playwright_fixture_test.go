package ui

import (
	"context"
	"fmt"
	"lanpanel/internal/session"
	"net"
	"os"
	"testing"
)

type playwrightVerifier struct{}

func (playwrightVerifier) Verify(_ context.Context, value []byte) (string, error) {
	if string(value) != "admin" {
		return "", fmt.Errorf("invalid token")
	}
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}
func (playwrightVerifier) Source(context.Context) (string, error) {
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
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
	manager, err := session.New("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Listener: listener, Authority: authority, InstallationFingerprint: "0123456789abcdef", Verifier: playwrightVerifier{}, Sessions: manager, Profile: playwrightProfile{}})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("LANPANEL_FIXTURE_ORIGIN=http://%s\n", authority)
	if err := server.Serve(); err != nil {
		t.Fatal(err)
	}
}
