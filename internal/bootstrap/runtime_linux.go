//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/helper"
	"lanpanel/internal/identity"
	"os"
)

// RunRuntimeGuard recreates the one volatile helper socket directory after reboot.
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
	_, err = ensureDirectory(FixedPaths().RuntimeRoot, filetxn.Owner{UID: 0, GID: config.SocketGroup}, 0o710)
	return err
}

var _ = identity.RoleUI
