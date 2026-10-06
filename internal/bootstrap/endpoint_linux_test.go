//go:build linux

package bootstrap

import (
	"lanpanel/internal/identity"
	"strings"
	"testing"
)

func TestManagementInfoUsesExactAuthority(t *testing.T) {
	endpoint, err := managementEndpoint(identity.ManagementAuthority{Address: "127.15.177.99", Port: 53639})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "http://127.15.177.99:53639" {
		t.Fatalf("endpoint=%q", endpoint)
	}
}

func TestManagementInfoRejectsForeignAuthority(t *testing.T) {
	if _, err := managementEndpoint(identity.ManagementAuthority{Address: "127.0.0.1", Port: 80}); err == nil || !strings.Contains(err.Error(), "management authority") {
		t.Fatalf("unexpected error=%v", err)
	}
}

func TestManagementInfoIncludesExactSSHAuthority(t *testing.T) {
	t.Setenv("SUDO_USER", "debian")
	t.Setenv("USER", "root")
	t.Setenv("SSH_CONNECTION", "198.51.100.9 4242 203.0.113.10 22")
	access, err := managementAccess(identity.ManagementAuthority{Address: "127.15.177.99", Port: 53639})
	if err != nil {
		t.Fatal(err)
	}
	if access.URL != "http://127.15.177.99:53639" || access.BrowserURL != access.URL+"/" || access.SSHCommand != "ssh -N -L 127.15.177.99:53639:127.15.177.99:53639 debian@203.0.113.10" {
		t.Fatalf("access=%#v", access)
	}
}
