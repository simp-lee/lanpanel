//go:build linux

package relay

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestInheritedListenersRejectNonUnixAndWrongCount(t *testing.T) {
	oldPID, oldFDS := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	defer func() { _ = os.Setenv("LISTEN_PID", oldPID) }()
	defer func() { _ = os.Setenv("LISTEN_FDS", oldFDS) }()
	_ = os.Setenv("LISTEN_PID", "0")
	_ = os.Setenv("LISTEN_FDS", "2")
	if _, err := inheritedListeners(); err == nil {
		t.Fatal("invalid PID1 socket inventory accepted")
	}
}

func TestFixedBackendPathCannotBeRedirectedByConfiguration(t *testing.T) {
	if !filepath.IsAbs(fixedBackend) || filepath.Clean(fixedBackend) != fixedBackend {
		t.Fatalf("backend=%q", fixedBackend)
	}
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "test.sock"))
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
}
