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

func TestServerAuthenticatesPeerAndRevalidatesEveryRequest(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		t.Skip("test requires a dedicated non-root peer")
	}
	identities := IdentitySet{UI: PeerIdentity{UID: uid, GID: gid}, Timer: PeerIdentity{UID: uid + 1, GID: gid}, Recovery: PeerIdentity{UID: uid + 2, GID: gid}}
	var revalidated atomic.Int32
	var executed atomic.Int32
	server, err := NewServer(identities, []Registration{CredentialImportHandler(
		func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
			if caller != helperproto.CallerUI || request.Target != "credential/basic-one" {
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
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.serveUnix(ctx, listener, false) }()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "request-one", Operation: helperproto.OperationCredentialImport, Target: "credential/basic-one", IntentGeneration: 2, Deadline: time.Unix(1_700_000_000, 0).UTC().Add(time.Minute), InputDigest: digest("input")}
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

func TestServerRejectsUnauthorizedLocalPeerAndIncompleteHandlers(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		t.Skip("test requires a dedicated non-root peer")
	}
	identities := IdentitySet{UI: PeerIdentity{UID: uid + 3, GID: gid}, Timer: PeerIdentity{UID: uid + 4, GID: gid}, Recovery: PeerIdentity{UID: uid + 5, GID: gid}}
	if _, err := NewServer(identities, []Registration{NginxTestHandler(nil, nil)}, Options{}); err == nil {
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
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "request-one", Operation: helperproto.OperationNginxTest, Target: "installation", IntentGeneration: 2, Deadline: time.Now().Add(time.Minute), InputDigest: digest("input")}
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
