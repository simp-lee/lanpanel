package ui

import (
	"bytes"
	"context"
	"lanpanel/internal/session"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type verifier struct{ fp string }
type normalProfile struct{}

func (normalProfile) Current(context.Context) (Profile, error) { return ProfileNormal, nil }

func (v verifier) Verify(context.Context, []byte) (string, error) { return v.fp, nil }
func (v verifier) Source(context.Context) (string, error)         { return v.fp, nil }

type dummyListener struct{}

func (dummyListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (dummyListener) Close() error              { return nil }
func (dummyListener) Addr() net.Addr            { return &net.TCPAddr{} }
func testServer(t *testing.T) *Server {
	t.Helper()
	manager, err := session.New("fp", session.Options{Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }, Random: bytes.NewReader(make([]byte, 96*4))})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Listener: dummyListener{}, Authority: "127.1.2.3:52345", InstallationFingerprint: "abcdef", Verifier: verifier{"fp"}, Sessions: manager, Profile: normalProfile{}})
	if err != nil {
		t.Fatal(err)
	}
	return server
}
func TestLoginRequiresExactHostOriginAndBoundedBody(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "http://127.1.2.3:52345/login", strings.NewReader("token=secret"))
	request.Host = "127.1.2.3:52345"
	request.Header.Set("Origin", "http://127.1.2.3:52345")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login status %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store, private" || response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("browser defenses absent")
	}
	if len(response.Result().Cookies()) != 1 || !response.Result().Cookies()[0].HttpOnly {
		t.Fatal("selector cookie not protected")
	}
}
func TestHostOriginAndDuplicateCookieFailClosed(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	request.Host = "example.invalid"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unexpected Host accepted: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "http://127.1.2.3:52345/login", strings.NewReader("token=secret"))
	request.Host = "127.1.2.3:52345"
	request.Header.Add("Origin", "http://127.1.2.3:52345")
	request.Header.Add("Origin", "http://127.1.2.3:52345")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatal("duplicate Origin accepted")
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.1.2.3:52345/api/session", nil)
	request.Host = "127.1.2.3:52345"
	request.Header.Add("Cookie", session.SelectorCookie+"=one; "+session.SelectorCookie+"=two")
	request.Header.Set(session.ProofHeader, "proof")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("duplicate selector accepted")
	}
}
