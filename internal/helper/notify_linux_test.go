//go:build linux

package helper

import (
	"net"
	"path/filepath"
	"testing"
)

func TestSystemdReadinessUsesOnlyExactUnixDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := notifySystemd(path); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil || string(buffer[:count]) != "READY=1" {
		t.Fatalf("readiness=%q error=%v", buffer[:count], err)
	}
	for _, invalid := range []string{"", "relative", "@", "/tmp/bad\nname"} {
		if err := notifySystemd(invalid); err == nil {
			t.Fatalf("invalid readiness address %q accepted", invalid)
		}
	}
}
