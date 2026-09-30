//go:build linux

package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMountInfoRejectsLegacyHierarchy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	data := "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n30 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil { t.Fatal(err) }
	mounts, legacy, err := parseMountInfo(path)
	if err != nil || len(mounts) != 1 || !legacy { t.Fatalf("mounts=%#v legacy=%v err=%v", mounts, legacy, err) }
}

func TestParseMountInfoAcceptsDynamicUnifiedMountpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	data := "29 23 0:26 / /sys/fs/cgroup/unified rw,nosuid,nodev - cgroup2 cgroup rw\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil { t.Fatal(err) }
	mounts, legacy, err := parseMountInfo(path)
	if err != nil || legacy || len(mounts) != 1 || mounts[0].Mountpoint != "/sys/fs/cgroup/unified" || mounts[0].Root != "/" { t.Fatalf("mounts=%#v legacy=%v err=%v", mounts, legacy, err) }
}
