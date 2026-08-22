//go:build linux

package qualification

import (
	"crypto/ed25519"
	"crypto/rand"
	"lanpanel/internal/release"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPinnedSSHHostKeyAndCanonicalAddress(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	digest := release.DigestBytes(key.Marshal())
	callback := pinnedHostKey(digest)
	if err := callback("ignored", &net.TCPAddr{}, key); err != nil {
		t.Fatal(err)
	}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewPublicKey(otherPublic)
	if callback("ignored", &net.TCPAddr{}, other) == nil {
		t.Fatal("pinned SSH callback accepted another host key")
	}
	if address, err := canonicalSSHAddress("192.0.2.10:22"); err != nil || address != "192.0.2.10:22" {
		t.Fatalf("canonical SSH address rejected: %q %v", address, err)
	}
	for _, invalid := range []string{"host.example:22", "192.0.2.10", "192.0.2.10:022", "0.0.0.0:0"} {
		if _, err := canonicalSSHAddress(invalid); err == nil {
			t.Fatalf("invalid SSH address accepted: %s", invalid)
		}
	}
}
