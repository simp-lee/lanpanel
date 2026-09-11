//go:build linux

package bootstrap

import "path/filepath"

func publicCommandPath(paths Paths) string {
	if paths == FixedPaths() {
		return "/usr/local/bin/lanpanel"
	}
	return filepath.Join(filepath.Dir(paths.BinaryPath), "lanpanel-command")
}
