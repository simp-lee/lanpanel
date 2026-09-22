//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/helper"
	"lanpanel/internal/identity"
	"os"
	"os/user"
	"strconv"
)

// RunRuntimeGuard recreates the volatile helper socket directory and removes a verified stale socket after reboot.
func RunRuntimeGuard(args []string) error {
	if len(args) != 0 || os.Getuid() != 0 || os.Geteuid() != 0 {
		return fmt.Errorf("runtime guard requires its fixed root service invocation")
	}
	if err := RequireCommitted(FixedPaths()); err != nil {
		return err
	}
	config, err := helper.ReadIdentityConfig()
	if err != nil {
		return err
	}
	if config.SocketGroup == 0 {
		return fmt.Errorf("runtime socket group is missing")
	}
	if _, err = ensureDirectory(FixedPaths().RuntimeRoot, filetxn.Owner{UID: 0, GID: config.SocketGroup}, 0o710); err != nil {
		return err
	}
	if err := helper.CleanupStaleSocket(config.SocketGroup); err != nil {
		return err
	}
	nginxGroup, lookupErr := user.LookupGroup("www-data")
	if lookupErr != nil {
		return lookupErr
	}
	nginxGID, parseErr := strconv.ParseUint(nginxGroup.Gid, 10, 32)
	if parseErr != nil || nginxGID == 0 {
		return fmt.Errorf("nginx runtime group invalid")
	}
	if _, err = ensureDirectory("/run/lanpanel-goaccess", filetxn.Owner{UID: 0, GID: uint32(nginxGID)}, 0o750); err != nil {
		return err
	}
	return nil
}

var _ = identity.RoleUI
