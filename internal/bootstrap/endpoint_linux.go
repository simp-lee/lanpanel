//go:build linux

package bootstrap

import (
	"fmt"
	"io"
	"lanpanel/internal/identity"
	"net"
	"net/netip"
	"os"
	"strings"
)

type SSHAccess struct {
	User string `json:"user"`
	Host string `json:"host"`
}

type ManagementAccess struct {
	URL         string
	SSHCommand  string
	BrowserURL  string
	TokenSource string
}

func managementEndpoint(authority identity.ManagementAuthority) (string, error) {
	if err := identity.ValidateManagementAuthority(authority); err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%s:%d", authority.Address, authority.Port), nil
}

func managementAccess(authority identity.ManagementAuthority) (ManagementAccess, error) {
	return managementAccessFor(authority, discoverSSHAccess())
}

func managementAccessFor(authority identity.ManagementAuthority, configured *SSHAccess) (ManagementAccess, error) {
	endpoint, err := managementEndpoint(authority)
	if err != nil {
		return ManagementAccess{}, err
	}
	access := configured
	if access == nil || !safeSSHWord(access.User) || !safeSSHWord(access.Host) {
		access = discoverSSHAccess()
	}
	user := access.User
	host := access.Host
	remote := user + "@" + host
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && address.Is6() {
		remote = user + "@[" + host + "]"
	}
	tunnel := fmt.Sprintf("ssh -N -L %s:%d:%s:%d %s", authority.Address, authority.Port, authority.Address, authority.Port, remote)
	return ManagementAccess{URL: endpoint, SSHCommand: tunnel, BrowserURL: endpoint + "/"}, nil
}

func validateSSHAccess(access *SSHAccess) error {
	if access == nil {
		return nil
	}
	if !safeSSHWord(access.User) || !safeSSHWord(access.Host) {
		return fmt.Errorf("SSH access identity is invalid")
	}
	return nil
}

func discoverSSHAccess() *SSHAccess {
	user := os.Getenv("SUDO_USER")
	if !safeSSHWord(user) {
		user = os.Getenv("USER")
	}
	if !safeSSHWord(user) {
		user = "root"
	}
	return &SSHAccess{User: user, Host: sshRemoteHost()}
}

func safeSSHWord(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !safeSSHChar(char) {
			return false
		}
	}
	return true
}

func safeSSHChar(char rune) bool {
	return char == '-' || char == '_' || char == '.' || char == ':' || char == '@' || char == '/' || char == '[' || char == ']' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

func sshRemoteHost() string {
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(fields) >= 3 {
		if address, err := netip.ParseAddr(fields[2]); err == nil {
			return address.String()
		}
	}
	connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: netip.MustParseAddr("8.8.8.8").AsSlice(), Port: 53})
	if err == nil {
		local := connection.LocalAddr().(*net.UDPAddr)
		_ = connection.Close()
		if address, parseErr := netip.ParseAddr(local.IP.String()); parseErr == nil && !address.IsUnspecified() {
			return address.String()
		}
	}
	if hostname, err := os.Hostname(); err == nil && safeSSHWord(hostname) {
		return hostname
	}
	return "server"
}

// RunPublicInfo prints committed Management UI access information without
// exposing the administrator token or other installation authority.
func RunPublicInfo(args []string, stdout io.Writer) error {
	if len(args) != 0 || stdout == nil {
		return fmt.Errorf("info accepts no options")
	}
	paths := FixedPaths()
	if err := RequireCommitted(paths); err != nil {
		return fmt.Errorf("LanPanel installation is not committed: %w", err)
	}
	startup, err := ReadPublicStartupAuthority(paths)
	if err != nil {
		return err
	}
	access, err := managementAccessFor(startup.Management, startup.SSHAccess)
	if err != nil {
		return fmt.Errorf("committed Management UI authority is invalid: %w", err)
	}
	access.TokenSource = ProtectedAdminTokenPath
	_, err = fmt.Fprintf(stdout, "Management UI URL: %s\nSSH tunnel command: %s\nBrowser URL: %s\nAdmin token source: %s\nToken rotation: sudo lanpanel token reset\n", access.URL, access.SSHCommand, access.BrowserURL, access.TokenSource)
	return err
}
