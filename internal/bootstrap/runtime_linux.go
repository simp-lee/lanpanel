//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/helper"
	"lanpanel/internal/identity"
	"os"
	"strings"

	"golang.org/x/sys/unix"
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
	if _, err = ensureDirectory(FixedPaths().RuntimeRoot, filetxn.Owner{UID: 0, GID: config.SocketGroup}, 0o710); err != nil {
		return err
	}
	return ensureBPFGuardDirectory()
}

func ensureBPFGuardDirectory() error {
	const root = "/sys/fs/bpf"
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	mounted := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		separator := -1
		for index, value := range fields {
			if value == "-" {
				separator = index
				break
			}
		}
		if separator > 5 && separator+1 < len(fields) && fields[4] == root && fields[separator+1] == "bpf" {
			mounted = true
			break
		}
	}
	if !mounted {
		return fmt.Errorf("bpffs is not mounted at exact guard root")
	}
	path := root + "/lanpanel"
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("BPF guard directory identity is unsafe")
	}
	return nil
}

var _ = identity.RoleUI
