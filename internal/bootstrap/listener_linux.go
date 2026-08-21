//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/identity"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const ManagementFDNamePrefix = "lanpanel-management-"

// InheritedManagementListener accepts only systemd's one exact fd-3 listener.
// It never binds or falls back to another address.
func InheritedManagementListener(authority identity.ManagementAuthority, generation string) (net.Listener, error) {
	expectedName := ManagementFDNamePrefix + generation
	if identity.ValidateManagementAuthority(authority) != nil || !identity.ValidateGenerationID(generation) || os.Getenv("LANPANEL_SOCKET_GENERATION") != generation || os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != expectedName {
		return nil, fmt.Errorf("management socket activation identity is mismatched")
	}
	if value, found := os.LookupEnv("LISTEN_FDS_START"); found && value != "3" {
		return nil, fmt.Errorf("management inherited descriptor start is invalid")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(3, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, fmt.Errorf("management inherited descriptor is not a socket")
	}
	file := os.NewFile(3, expectedName)
	if file == nil {
		return nil, fmt.Errorf("management inherited descriptor is unavailable")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	tcp, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcp.IP.String() != authority.Address || tcp.Port != int(authority.Port) {
		_ = listener.Close()
		return nil, fmt.Errorf("management inherited listener has another authority")
	}
	return listener, nil
}
