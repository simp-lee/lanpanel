//go:build linux

package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"lanpanel/internal/nginx"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const machineIDPath = "/etc/machine-id"

func ObserveHostFingerprint() (string, error)            { return observeHostFingerprint() }
func ObserveBeforeInventory(paths Paths) (string, error) { return observeBeforeInventory(paths) }

func observeHostFingerprint() (string, error) {
	data, err := readRootRegular(machineIDPath, 4096, 0o644)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if len(value) != 32 {
		return "", fmt.Errorf("host machine identity is invalid")
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", fmt.Errorf("host machine identity is invalid")
		}
	}
	digest := sha256.Sum256([]byte(value))
	return "host_" + hex.EncodeToString(digest[:16]), nil
}

func observeBeforeInventory(paths Paths) (string, error) {
	nginxPaths := nginx.FixedPaths()
	if paths != FixedPaths() {
		nginxPaths = testNginxPaths(paths)
	}
	roots := []string{paths.Journal, paths.StartupAuthority, paths.CommitPath, paths.PersistentRoot, paths.RuntimeRoot, paths.SysusersPath, paths.BinaryPath, nginxPaths.ConfigRoot, nginxPaths.StateRoot, nginxPaths.AuditPath}
	for _, name := range []string{"lanpanel-management.socket", "lanpanel-ui.service", "lanpanel-runtime.service", "lanpanel-helper.service", "lanpanel-timer.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"} {
		roots = append(roots, filepath.Join(paths.SystemdRoot, name))
	}
	sort.Strings(roots)
	hasher := sha256.New()
	for _, path := range roots {
		var stat unix.Stat_t
		err := unix.Lstat(path, &stat)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(hasher, "absent:%s\n", path)
				continue
			}
			return "", err
		}
		fmt.Fprintf(hasher, "present:%s:%d:%d:%o:%d:%d:%d\n", path, stat.Uid, stat.Gid, stat.Mode, stat.Dev, stat.Ino, stat.Size)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func readCommittedArtifact(path string, maximum int64, maximumMode uint32) ([]byte, error) {
	return readRootRegular(path, maximum, maximumMode)
}

func readRootRegular(path string, maximum int64, maximumMode uint32) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("host identity descriptor is invalid")
	}
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != 0 || before.Mode&0o022 != 0 || before.Mode&0o777&^maximumMode != 0 || before.Size <= 0 || before.Size > maximum {
		return nil, fmt.Errorf("host identity source is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		return nil, fmt.Errorf("host identity source changed")
	}
	return data, nil
}
