//go:build linux

package bootstrap

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// RunPublicUninstall is intentionally conservative until a committed ownership
// inventory can prove the complete deletion closure. It never touches APT/dpkg
// packages or paths outside the fixed LanPanel scope.
func RunPublicUninstall(args []string, in io.Reader, out io.Writer) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("uninstall requires root")
	}
	if len(args) != 0 {
		return fmt.Errorf("uninstall accepts no options")
	}
	if in == nil || out == nil {
		return fmt.Errorf("uninstall confirmation terminal is unavailable")
	}
	paths := FixedPaths()
	_, _ = fmt.Fprintf(out, "LanPanel uninstall will remove only committed LanPanel-owned paths: %s, %s, %s, %s, %s, and fixed runtime assets. APT/dpkg packages and external application files will not be removed.\nType UNINSTALL LANPANEL to continue: ", paths.BinaryPath, paths.PersistentRoot, paths.InstallationRoot, paths.SystemdRoot, paths.RuntimeRoot)
	var confirmation string
	if _, err := fmt.Fscanln(in, &confirmation); err != nil || strings.TrimSpace(confirmation) != "UNINSTALL LANPANEL" {
		return fmt.Errorf("uninstall requires exact confirmation UNINSTALL LANPANEL")
	}
	return fmt.Errorf("uninstall is fenced: committed ownership inventory and service stop evidence are unavailable")
}
