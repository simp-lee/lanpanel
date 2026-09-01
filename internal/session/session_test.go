package session

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type (
	socket         struct{ closed bool }
	countingSocket struct{ closes atomic.Int32 }
)

func (s *socket) Close() error         { s.closed = true; return nil }
func (s *countingSocket) Close() error { s.closes.Add(1); return nil }
func TestSessionsRequireIndependentProofCSRFAndInvalidateSockets(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	manager, _ := New("fp", Options{Now: func() time.Time { return now }, Random: bytes.NewReader(make([]byte, 192))})
	defer manager.Close()
	credentials, err := manager.Issue("http://127.1.2.3:52345", "fp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Authenticate(credentials.Selector, credentials.Proof, "", "http://127.1.2.3:52345", "fp", false); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Authenticate(credentials.Selector, credentials.Proof, "wrong", "http://127.1.2.3:52345", "fp", true); err == nil {
		t.Fatal("wrong CSRF accepted")
	}
	principal, err := manager.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, "http://127.1.2.3:52345", "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	attached := &socket{}
	if err := manager.Attach(principal, attached); err != nil {
		t.Fatal(err)
	}
	manager.InvalidateFingerprint("fp2")
	if !attached.closed {
		t.Fatal("source drift did not close socket")
	}
}

func TestSessionExpiryAndEntropyFailure(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	manager, _ := New("fp", Options{Now: func() time.Time { return now }, Random: bytes.NewReader(make([]byte, 95))})
	defer manager.Close()
	if _, err := manager.Issue("origin", "fp"); err == nil {
		t.Fatal("short entropy succeeded")
	}
	manager.Close()
	manager, _ = New("fp", Options{Now: func() time.Time { return now }, Random: bytes.NewReader(make([]byte, 96))})
	defer manager.Close()
	credentials, _ := manager.Issue("origin", "fp")
	now = now.Add(InactivityLimit + time.Second)
	if _, err := manager.Authenticate(credentials.Selector, credentials.Proof, "", "origin", "fp", false); err == nil {
		t.Fatal("expired session accepted")
	}
}

func TestStalePrincipalCannotSurviveTokenRotation(t *testing.T) {
	manager, _ := New("fp", Options{Random: bytes.NewReader(make([]byte, 96))})
	defer manager.Close()
	credentials, _ := manager.Issue("origin", "fp")
	principal, err := manager.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, "origin", "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	if !manager.Valid(principal) {
		t.Fatal("fresh principal invalid")
	}
	manager.CommitTokenRotation("fp2")
	if manager.Valid(principal) {
		t.Fatal("rotated principal remained valid")
	}
	if err := manager.Attach(principal, &socket{}); err == nil {
		t.Fatal("stale generation attached after rotation")
	}
	if _, err := manager.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, "origin", "fp2", true); err == nil {
		t.Fatal("old session survived rotation")
	}
}

func TestRestartDoesNotReissueCredentials(t *testing.T) {
	manager, _ := New("fp", Options{Random: bytes.NewReader(make([]byte, 96))})
	defer manager.Close()
	credentials, _ := manager.Issue("origin", "fp")
	restarted, _ := New("fp", Options{})
	defer restarted.Close()
	if _, err := restarted.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, "origin", "fp", true); err == nil {
		t.Fatal("session survived restart")
	}
}

func TestCloseIsTerminalAndClosesAttachedSocketOnce(t *testing.T) {
	manager, err := New("fp", Options{Random: bytes.NewReader(make([]byte, 192))})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := manager.Issue("origin", "fp")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := manager.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, "origin", "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	attached := &countingSocket{}
	if err := manager.Attach(principal, attached); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var closes sync.WaitGroup
	for range 8 {
		closes.Add(1)
		go func() {
			defer closes.Done()
			<-start
			manager.Close()
		}()
	}
	close(start)
	closes.Wait()

	if got := attached.closes.Load(); got != 1 {
		t.Fatalf("attached socket closed %d times", got)
	}
	select {
	case <-manager.done:
	default:
		t.Fatal("Close returned before the sweeper stopped")
	}
	if manager.Valid(principal) {
		t.Fatal("principal remained valid after Close")
	}
	if _, err := manager.Issue("origin", "fp"); err == nil {
		t.Fatal("Issue reopened a closed manager")
	}
	if _, err := manager.Authenticate(credentials.Selector, credentials.Proof, credentials.CSRF, "origin", "fp", true); err == nil {
		t.Fatal("Authenticate accepted a closed manager")
	}
	if _, err := manager.AuthenticateSocket(credentials.Selector, credentials.Proof, "origin", "fp"); err == nil {
		t.Fatal("AuthenticateSocket accepted a closed manager")
	}
	if err := manager.Attach(principal, &countingSocket{}); err == nil {
		t.Fatal("Attach accepted a closed manager")
	}
	sent := false
	if err := manager.Send(principal, "fp", func() error { sent = true; return nil }); err == nil || sent {
		t.Fatal("Send accepted a closed manager")
	}
	if manager.RequireFingerprint("fp") {
		t.Fatal("RequireFingerprint reopened a closed manager")
	}
	manager.InvalidateFingerprint("fp")
	manager.CommitTokenRotation("fp")
	if manager.RequireFingerprint("fp") {
		t.Fatal("fingerprint mutation reopened a closed manager")
	}
	if _, err := manager.Issue("origin", "fp"); err == nil {
		t.Fatal("fingerprint mutation enabled Issue after Close")
	}
}
