//go:build linux

package closure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestProcObserverRejectsOwnedListenerOutsideExactNginxProcesses(t *testing.T) {
	procRoot := t.TempDir()
	netRoot := filepath.Join(procRoot, "net")
	if err := os.Mkdir(netRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	foreign := "   0: 00000000:46A0 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 91\n"
	if err := os.WriteFile(filepath.Join(netRoot, "tcp"), []byte(header+foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netRoot, "tcp6"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	observer := ProcObserver{
		ProcRoot:       procRoot,
		UnitCgroup:     "/system.slice/lanpanel-nginx.service",
		Executable:     "/usr/sbin/nginx",
		ExpectedArgv:   "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf",
		PIDPath:        filepath.Join(procRoot, "nginx.pid"),
		Generation:     "generation-one",
		OwnedListeners: []string{"tcp:0.0.0.0:18080"},
	}
	if _, err := observer.Observe(context.Background()); err == nil {
		t.Fatal("foreign wildcard listener was accepted as part of the Nginx runtime generation")
	}
}

func TestProcObserverAcceptsOwnedEmptyPIDWhenStopped(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned PID file fixture")
	}
	procRoot := t.TempDir()
	netRoot := filepath.Join(procRoot, "net")
	if err := os.Mkdir(netRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\\n"
	for _, name := range []string{"tcp", "tcp6"} {
		if err := os.WriteFile(filepath.Join(netRoot, name), []byte(header), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pidPath := filepath.Join(procRoot, "nginx.pid")
	if err := os.WriteFile(pidPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	observer := ProcObserver{
		ProcRoot:     procRoot,
		UnitCgroup:   "/system.slice/lanpanel-nginx.service",
		Executable:   "/usr/sbin/nginx",
		ExpectedArgv: "/usr/sbin/nginx\\x00-c\\x00/etc/lanpanel/nginx/nginx.conf",
		PIDPath:      pidPath,
		Generation:   "generation-stopped",
	}
	snapshot, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatalf("stopped Nginx with an owned empty PID file was rejected: %v", err)
	}
	if snapshot.Master != nil || len(snapshot.Workers) != 0 || len(snapshot.Listeners) != 0 || !snapshot.Complete {
		t.Fatalf("stopped Nginx snapshot=%#v", snapshot)
	}
}

func TestProcessSocketInodesRejectsReusedPIDIdentity(t *testing.T) {
	procRoot := t.TempDir()
	pidRoot := filepath.Join(procRoot, "123")
	if err := os.MkdirAll(filepath.Join(pidRoot, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"stat":    "123 (nginx) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 101\n",
		"cmdline": "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00",
		"cgroup":  "0::/system.slice/lanpanel-nginx.service\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(pidRoot, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/usr/sbin/nginx", filepath.Join(pidRoot, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[91]", filepath.Join(pidRoot, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	current, err := observeProcess(procRoot, 123)
	if err != nil {
		t.Fatal(err)
	}
	inodes, err := processSocketInodes(procRoot, []ProcessIdentity{current})
	if err != nil || !inodes[91] {
		t.Fatalf("stable Nginx process socket missing: inodes=%v err=%v", inodes, err)
	}
	stale := current
	stale.StartTicks--
	inodes, err = processSocketInodes(procRoot, []ProcessIdentity{stale})
	if err != nil {
		t.Fatal(err)
	}
	if inodes[91] {
		t.Fatal("socket from a reused PID was attributed to the stale Nginx process")
	}
}

func TestValidMasterArgumentsAcceptsUbuntuNginxTitleTruncation(t *testing.T) {
	expected := "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;"
	title := "nginx: master process " + strings.ReplaceAll(expected, "\x00", " ")
	if !validMasterArguments(title, expected) {
		t.Fatal("full Nginx process title was rejected")
	}
	truncated := strings.TrimSuffix(title, "on off;")
	if !validMasterArguments(truncated, expected) {
		t.Fatalf("truncated Nginx process title was rejected: %q", truncated)
	}
	if validMasterArguments(strings.TrimSuffix(title, " -g daemon off;")+" -g x", expected) {
		t.Fatal("altered prefix before the fixed global directive was accepted")
	}
	if validMasterArguments(strings.TrimSuffix(title, ";")+"x", expected) {
		t.Fatal("altered Nginx global directive was accepted")
	}
}

func TestServingRequiresWorkerAndCompleteExpectedListeners(t *testing.T) {
	master := ProcessIdentity{PID: 10}
	expected := []string{"tcp:0.0.0.0:80", "tcp::::80"}
	snapshot := RuntimeSnapshot{
		ObservedAt: time.Now(),
		Complete:   true,
		Master:     &master,
		Workers:    []ProcessIdentity{{PID: 11, ParentPID: master.PID}},
		Listeners: []ListenerIdentity{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 80, Inode: 1},
			{Protocol: "tcp", Address: "::", Port: 80, Inode: 2},
		},
		Generation: "gen",
	}
	if err := VerifyServing(snapshot, "gen", expected); err != nil {
		t.Fatalf("complete serving runtime rejected: %v", err)
	}
	if err := VerifyServing(snapshot, "gen", nil); err == nil {
		t.Fatal("empty expected listener authority accepted")
	}
	withoutWorker := snapshot
	withoutWorker.Workers = nil
	if err := VerifyServing(withoutWorker, "gen", expected); err == nil {
		t.Fatal("master without a serving worker accepted")
	}
	missingListener := snapshot
	missingListener.Listeners = missingListener.Listeners[:1]
	if err := VerifyServing(missingListener, "gen", expected); err == nil {
		t.Fatal("runtime missing an expected listener accepted")
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
