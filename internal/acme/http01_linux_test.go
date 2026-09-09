//go:build linux

package acme

import (
	"os"
	"path/filepath"
	"testing"

	xacme "golang.org/x/crypto/acme"
)

func TestHTTP01OrderIdentifiersRequireExactDNSInventory(t *testing.T) {
	domains := []string{"app.example.test", "www.example.test"}
	if !exactHTTP01OrderIdentifiers([]xacme.AuthzID{{Type: "dns", Value: domains[1]}, {Type: "dns", Value: domains[0]}}, domains) {
		t.Fatal("exact order identifiers were rejected")
	}
	for name, identifiers := range map[string][]xacme.AuthzID{
		"missing":    {{Type: "dns", Value: domains[0]}},
		"added":      {{Type: "dns", Value: domains[0]}, {Type: "dns", Value: domains[1]}, {Type: "dns", Value: "other.example.test"}},
		"changed":    {{Type: "dns", Value: domains[0]}, {Type: "dns", Value: "other.example.test"}},
		"wrong_type": {{Type: "ip", Value: domains[0]}, {Type: "dns", Value: domains[1]}},
		"duplicate":  {{Type: "dns", Value: domains[0]}, {Type: "dns", Value: domains[0]}},
	} {
		t.Run(name, func(t *testing.T) {
			if exactHTTP01OrderIdentifiers(identifiers, domains) {
				t.Fatal("non-exact order identifier inventory was accepted")
			}
		})
	}
}

func TestHTTP01TokenFileIsExactAndContentBound(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cert_00000000000000000000000000000001")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	presentation := NewHTTP01Presentation("app.example.test", "abcdefghijklmnopqrstuv", "abcdefghijklmnopqrstuv.account-thumbprint")
	if err := writeHTTP01TokenAt(root, uid, gid, presentation); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".well-known", "acme-challenge", presentation.Token)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		t.Fatalf("token metadata=%#v err=%v", info, err)
	}
	if err := verifyHTTP01TokenAt(root, uid, gid, presentation); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyHTTP01TokenAt(root, uid, gid, presentation); err == nil {
		t.Fatal("changed token mode was accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed-key-authorization"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyHTTP01TokenAt(root, uid, gid, presentation); err == nil {
		t.Fatal("changed token content was accepted")
	}
	if err := removeHTTP01TokenAt(root, uid, gid, presentation); err == nil {
		t.Fatal("cleanup removed a token whose exact content identity changed")
	}
	if err := os.WriteFile(path, []byte(presentation.KeyAuthorization), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeHTTP01TokenAt(root, uid, gid, presentation); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("exact token remains after cleanup: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".well-known")); !os.IsNotExist(err) {
		t.Fatalf("challenge directories remain after cleanup: %v", err)
	}
}

func TestHTTP01TokenFileDoesNotFollowFinalSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cert_00000000000000000000000000000001")
	challengeRoot := filepath.Join(root, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeRoot, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	presentation := NewHTTP01Presentation("app.example.test", "abcdefghijklmnopqrstuv", "abcdefghijklmnopqrstuv.account-thumbprint")
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(challengeRoot, presentation.Token)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeHTTP01TokenAt(root, uid, gid, presentation); err == nil {
		t.Fatal("token write followed or replaced a final symlink")
	}
	if err := verifyHTTP01TokenAt(root, uid, gid, presentation); err == nil {
		t.Fatal("token verification followed a final symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("symlink target changed: %q, %v", data, err)
	}
}
