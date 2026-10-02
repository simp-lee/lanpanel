//go:build linux

package helper

import (
	"context"
	"errors"
	"lanpanel/internal/helperproto"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestServerRestartRequestStopsAcceptLoop(t *testing.T) {
	identities := IdentitySet{UI: PeerIdentity{UID: 1001, GID: 2001}, Timer: PeerIdentity{UID: 1002, GID: 2001}, Recovery: PeerIdentity{UID: 1003, GID: 2001}}
	server, err := NewServer(identities, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(listener.Close)
	server.requestRestart()
	if err := server.serveUnix(context.Background(), listener, false); !errors.Is(err, errRestartRequested) {
		t.Fatalf("serveUnix error=%v, want restart request", err)
	}
	server.requestRestart()
}

func TestServerAuthenticatesPeerAndRevalidatesEveryRequest(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		t.Skip("test requires a dedicated non-root peer")
	}
	identities := IdentitySet{UI: PeerIdentity{UID: uid, GID: gid}, Timer: PeerIdentity{UID: uid + 1, GID: gid}, Recovery: PeerIdentity{UID: uid + 2, GID: gid}}
	var revalidated atomic.Int32
	var executed atomic.Int32
	server, err := NewServer(identities, []Registration{AdminTokenVerifyHandler(
		func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
			if caller != helperproto.CallerUI || request.Target != "installation" {
				return errors.New("wrong authority")
			}
			revalidated.Add(1)
			return nil
		},
		func(_ context.Context, _ helperproto.Caller, _ helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
			executed.Add(1)
			if err := secret.Use(func(value []byte) error {
				if string(value) != "sentinel-secret" {
					return errors.New("wrong secret")
				}
				return nil
			}); err != nil {
				return ExecutionResult{}, err
			}
			return ExecutionResult{ResultDigest: digest("result")}, nil
		},
	)}, Options{Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(listener.Close)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serveUnix(ctx, listener, false) }()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "request-one", Operation: helperproto.OperationAdminTokenVerify, Target: "installation", IntentGeneration: 2, Deadline: time.Unix(1_700_000_000, 0).UTC().Add(time.Minute), InputDigest: digest("input")}
	if err := helperproto.WriteRequest(client, request, []byte("sentinel-secret")); err != nil {
		t.Fatal(err)
	}
	response, responseSecret, err := helperproto.ReadResponse(client, request.Operation)
	if err != nil || responseSecret != nil || response.Code != helperproto.ResponseSucceeded || response.ResultDigest != digest("result") {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if revalidated.Load() != 1 || executed.Load() != 1 {
		t.Fatalf("revalidated=%d executed=%d", revalidated.Load(), executed.Load())
	}
}

func TestServerReturnsDurablePartialPublicationDespiteExecutorCleanupError(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		t.Skip("test requires a dedicated non-root peer")
	}
	now := time.Now().UTC()
	identities := IdentitySet{UI: PeerIdentity{UID: uid, GID: gid}, Timer: PeerIdentity{UID: uid + 1, GID: gid}, Recovery: PeerIdentity{UID: uid + 2, GID: gid}}
	server, err := NewServer(identities, []Registration{PublicationActivateHandler(
		func(context.Context, helperproto.Caller, helperproto.Request) error { return nil },
		func(context.Context, helperproto.Caller, helperproto.Request, *helperproto.Secret) (ExecutionResult, error) {
			return ExecutionResult{ResultDigest: digest("publication"), Action: &helperproto.ActionResult{JobID: "job-partial", JobResult: "partial", PublicURL: "https://app.example.test/"}}, errors.New("post-commit lease release failed")
		},
	)}, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(listener.Close)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serveUnix(ctx, listener, false) }()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "request-partial", Operation: helperproto.OperationPublicationActivate, Target: "resource/res_00000000000000000000000000000001", IntentGeneration: 2, Deadline: now.Add(time.Minute), Resource: &helperproto.ResourcePayload{Operation: "publish", ActorIdentity: "session-one", ActorGeneration: 1, PlanID: "plan-one", Confirmation: "publish"}}
	request.InputDigest, err = helperproto.ApplicationInputDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = helperproto.WriteRequest(client, request, nil); err != nil {
		t.Fatal(err)
	}
	response, secret, err := helperproto.ReadResponse(client, request.Operation)
	if err != nil || secret != nil || response.Code != helperproto.ResponseSucceeded || response.Action == nil || response.Action.JobResult != "partial" {
		t.Fatalf("partial publication response=%#v secret=%v err=%v", response, secret, err)
	}
	_ = client.Close()
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServerRejectsUnauthorizedLocalPeerAndIncompleteHandlers(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		t.Skip("test requires a dedicated non-root peer")
	}
	identities := IdentitySet{UI: PeerIdentity{UID: uid + 3, GID: gid}, Timer: PeerIdentity{UID: uid + 4, GID: gid}, Recovery: PeerIdentity{UID: uid + 5, GID: gid}}
	if _, err := NewServer(identities, []Registration{ManagementProfileHandler(nil, nil)}, Options{}); err == nil {
		t.Fatal("incomplete helper handler registered")
	}
	server, err := NewServer(identities, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serveUnix(ctx, listener, false) }()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "request-one", Operation: helperproto.OperationManagementProfile, Target: "installation", IntentGeneration: 2, Deadline: time.Now().Add(time.Minute), InputDigest: digest("input")}
	_ = helperproto.WriteRequest(client, request, nil)
	if _, _, err := helperproto.ReadResponse(client, request.Operation); err == nil {
		t.Fatal("unauthorized local peer received a helper response")
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProtectedPathsRejectUnsafeParentChains(t *testing.T) {
	unsafe := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateRootParentChain(unsafe, uint32(os.Getegid()), 0o710); err == nil {
		t.Fatal("unsafe helper parent chain was accepted")
	}
}

func TestStaleHelperSocketIsRemovedButActiveAndForeignPathsAreRejected(t *testing.T) {
	owner := uint32(os.Geteuid())
	group := uint32(os.Getegid())
	prepare := func(path string) (*net.UnixListener, error) {
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return nil, err
		}
		listener.SetUnlinkOnClose(false)
		if err := os.Chmod(path, 0o660); err != nil {
			_ = listener.Close()
			_ = os.Remove(path)
			return nil, err
		}
		if err := os.Chown(path, int(owner), int(group)); err != nil {
			_ = listener.Close()
			_ = os.Remove(path)
			return nil, err
		}
		return listener, nil
	}

	t.Run("stale", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "helper.sock")
		listener, err := prepare(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		if err := cleanupStaleSocket(path, owner, group); err != nil {
			t.Fatalf("stale socket was not removed: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale socket remains, lstat error=%v", err)
		}
	})

	t.Run("active", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "helper.sock")
		listener, err := prepare(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = listener.Close()
			_ = os.Remove(path)
		}()
		if err := cleanupStaleSocket(path, owner, group); err == nil {
			t.Fatal("active helper socket was removed")
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("active helper socket disappeared: %v", err)
		}
		inUse, err := helperSocketInUse(path)
		if err != nil || !inUse {
			t.Fatalf("active helper socket holder was not detected: inUse=%t error=%v", inUse, err)
		}
	})

	t.Run("foreign socket metadata", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "helper.sock")
		listener, err := prepare(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = listener.Close()
			_ = os.Remove(path)
		}()
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cleanupStaleSocket(path, owner, group); err == nil {
			t.Fatal("foreign socket metadata was removed")
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("foreign socket disappeared: %v", err)
		}
	})

	t.Run("foreign path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "helper.sock")
		if err := os.WriteFile(path, []byte("foreign"), 0o660); err != nil {
			t.Fatal(err)
		}
		if err := cleanupStaleSocket(path, owner, group); err == nil {
			t.Fatal("foreign path was removed")
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("foreign path disappeared: %v", err)
		}
	})
}

func TestProtectedListenerFailsClosedOutsideInstalledRootPath(t *testing.T) {
	listener, err := ListenProtected(uint32(os.Getegid()))
	if os.Geteuid() != 0 && err == nil {
		_ = listener.Close()
		t.Fatal("non-root process created the privileged helper socket")
	}
	if err == nil {
		if listener.path != FixedSocketPath {
			t.Fatalf("helper listened on non-fixed path %q", listener.path)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPeerIdentityMappingRequiresExactDistinctUIDs(t *testing.T) {
	identities := IdentitySet{UI: PeerIdentity{UID: 1001, GID: 2000}, Timer: PeerIdentity{UID: 1002, GID: 2000}, Recovery: PeerIdentity{UID: 1003, GID: 2000}}
	server, err := NewServer(identities, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		credential unix.Ucred
		want       helperproto.Caller
	}{{unix.Ucred{Uid: 1001, Gid: 2000}, helperproto.CallerUI}, {unix.Ucred{Uid: 1002, Gid: 2000}, helperproto.CallerTimer}, {unix.Ucred{Uid: 1003, Gid: 2000}, helperproto.CallerRecovery}} {
		if got, ok := server.callerFor(test.credential); !ok || got != test.want {
			t.Fatalf("callerFor(%#v)=%q,%v", test.credential, got, ok)
		}
	}
	if _, ok := server.callerFor(unix.Ucred{Uid: 1004, Gid: 2000}); ok {
		t.Fatal("foreign peer was accepted")
	}
	if _, err := NewServer(IdentitySet{UI: PeerIdentity{UID: 1001, GID: 1}, Timer: PeerIdentity{UID: 1001, GID: 2}, Recovery: PeerIdentity{UID: 1003, GID: 3}}, nil, Options{}); err == nil {
		t.Fatal("same peer UID under another GID was accepted")
	}
}

func digest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}
