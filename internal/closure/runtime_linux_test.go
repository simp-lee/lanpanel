//go:build linux

package closure

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type sequenceObserver struct {
	snapshots []RuntimeSnapshot
	index     int
}

func (value *sequenceObserver) Observe(context.Context) (RuntimeSnapshot, error) {
	result := value.snapshots[value.index]
	if value.index < len(value.snapshots)-1 {
		value.index++
	}
	return result, nil
}

func TestPriorWorkerDrainBindsPIDStartAndCgroup(t *testing.T) {
	prior := ProcessIdentity{PID: 44, StartTicks: 100, Cgroup: "/system.slice/lanpanel-nginx.service"}
	master := ProcessIdentity{PID: 12, StartTicks: 10, Cgroup: prior.Cgroup}
	observer := &sequenceObserver{snapshots: []RuntimeSnapshot{
		{ObservedAt: time.Now(), Complete: true, Master: &master, Workers: []ProcessIdentity{{PID: 44, StartTicks: 100, Cgroup: prior.Cgroup}}},
		{ObservedAt: time.Now(), Complete: true, Master: &master, Workers: []ProcessIdentity{{PID: 44, StartTicks: 101, Cgroup: prior.Cgroup}}},
	}}
	result, err := WaitPriorWorkers(context.Background(), observer, []ProcessIdentity{prior}, time.Second)
	if err != nil || len(result.Workers) != 1 || result.Workers[0].StartTicks != 101 {
		t.Fatalf("drain=%#v,%v", result, err)
	}
}

func TestWaitFileReopenRequiresOldWritableDescriptorToClose(t *testing.T) {
	directory := t.TempDir()
	oldPath, activePath := filepath.Join(directory, "old.log"), filepath.Join(directory, "active.log")
	oldFile, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	activeFile, err := os.OpenFile(activePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = activeFile.Close() }()
	var oldStat, activeStat unix.Stat_t
	if err := unix.Fstat(int(oldFile.Fd()), &oldStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(activeFile.Fd()), &activeStat); err != nil {
		t.Fatal(err)
	}
	process, err := observeProcess("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	observer := &sequenceObserver{snapshots: []RuntimeSnapshot{{ObservedAt: time.Now(), Complete: true, Master: &process, Workers: []ProcessIdentity{}, Listeners: []ListenerIdentity{}, Generation: "test"}}}
	retries := 0
	retry := func(context.Context) error {
		retries++
		return oldFile.Close()
	}
	if err := WaitFileReopen(context.Background(), observer, "/proc", activePath, process, FileIdentity{Device: uint64(oldStat.Dev), Inode: oldStat.Ino}, FileIdentity{Device: uint64(activeStat.Dev), Inode: activeStat.Ino}, time.Second, retry); err != nil {
		t.Fatal(err)
	}
	if retries != 1 {
		t.Fatalf("reopen retry calls=%d", retries)
	}
}

func TestWaitFileReopenRequiresMasterToHoldReplacement(t *testing.T) {
	directory := t.TempDir()
	oldPath, activePath := filepath.Join(directory, "old.log"), filepath.Join(directory, "active.log")
	oldFile, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	activeFile, err := os.OpenFile(activePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var oldStat, activeStat unix.Stat_t
	if err = unix.Fstat(int(oldFile.Fd()), &oldStat); err == nil {
		err = unix.Fstat(int(activeFile.Fd()), &activeStat)
	}
	if closeErr := oldFile.Close(); err == nil {
		err = closeErr
	}
	if closeErr := activeFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	process, err := observeProcess("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	observer := &sequenceObserver{snapshots: []RuntimeSnapshot{{ObservedAt: time.Now(), Complete: true, Master: &process, Workers: []ProcessIdentity{}, Listeners: []ListenerIdentity{}, Generation: "test"}}}
	if err = WaitFileReopen(context.Background(), observer, "/proc", activePath, process, FileIdentity{Device: uint64(oldStat.Dev), Inode: oldStat.Ino}, FileIdentity{Device: uint64(activeStat.Dev), Inode: activeStat.Ino}, 30*time.Millisecond, nil); err == nil {
		t.Fatal("reopen completed without an active master write descriptor")
	}
}

func TestStoppedRequiresCompleteEmptyRuntime(t *testing.T) {
	if err := VerifyStopped(RuntimeSnapshot{ObservedAt: time.Now(), Complete: true, Generation: "gen", Workers: []ProcessIdentity{}, Listeners: []ListenerIdentity{}}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStopped(RuntimeSnapshot{ObservedAt: time.Now(), Complete: true, Generation: "gen", Listeners: []ListenerIdentity{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Inode: 1}}}); err == nil {
		t.Fatal("owned listener accepted as stopped")
	}
}
