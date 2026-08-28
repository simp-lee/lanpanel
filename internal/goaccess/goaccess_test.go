//go:build linux

package goaccess

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRenderUsesPrivateNetworkAndProtectedRelay(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	candidate, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	service, relay, socket, retentionTimer := string(candidate.Service), string(candidate.Relay), string(candidate.Socket), string(candidate.RetentionTimer)
	for _, required := range []string{"PrivateNetwork=yes", "--no-global-config", "--keep-last=30", "--addr=127.0.0.1", "--port=7890", "ExecStartPre=+/usr/lib/lanpanel/lanpanel goaccess-account-guard", "Environment=LANPANEL_INSTALLATION_ID=", "WantedBy=multi-user.target"} {
		if !strings.Contains(service, required) {
			t.Fatalf("service missing %q", required)
		}
	}
	for _, required := range []string{"JoinsNamespaceOf=lanpanel-goaccess-", "ExecStart=/usr/lib/lanpanel/lanpanel goaccess-relay", "RestrictAddressFamilies=AF_INET", "WantedBy=multi-user.target"} {
		if !strings.Contains(relay, required) {
			t.Fatalf("relay missing %q", required)
		}
	}
	if strings.Contains(retentionTimer, "Persistent=") {
		t.Fatal("retention timer created untracked persistent systemd state")
	}
	retentionService := string(candidate.RetentionService)
	if candidate.Paths.RetentionUnit == "" || candidate.Paths.RetentionTimer == "" || !strings.Contains(retentionService, candidate.Paths.RetentionLock) || !strings.Contains(retentionService, "ExecStart=/usr/lib/lanpanel/lanpanel goaccess-retention") || !strings.Contains(retentionService, "User=root\nGroup=root") || !strings.Contains(retentionService, "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_SYS_PTRACE") || strings.Contains(retentionService, "CAP_NET_BIND_SERVICE") || !strings.Contains(retentionService, "TimeoutStartSec=75s") || !strings.Contains(retentionService, "/var/log/lanpanel/nginx-rejections.log") || !strings.Contains(retentionService, "LANPANEL_INSTALLATION_ID=ins_00000000000000000000000000000001") || strings.Contains(retentionService, "/bin/sh") || strings.Contains(retentionService, "/usr/bin/kill") || !strings.Contains(socket, "ListenStream=/run/lanpanel-goaccess/") || candidate.ServiceIdentity != digest && len(candidate.ServiceIdentity) != 71 {
		t.Fatal("protected endpoint identity missing")
	}
}

func TestServiceIdentityIsLengthDelimited(t *testing.T) {
	if managedServiceIdentity([]byte("a"), []byte("bc")) == managedServiceIdentity([]byte("ab"), []byte("c")) {
		t.Fatal("service identity lost file boundaries")
	}
}

func TestObserveCandidateReconstructsAccountAuthority(t *testing.T) {
	applied := domain.GoAccessBundleIdentity{Enabled: true, Generation: 2, StateGeneration: 1, ServiceIdentity: digest([]byte("service")), UnitIdentities: []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}, WebSocketPath: "/__lanpanel/goaccess-ws"}
	candidate, err := ObserveCandidate("ins_00000000000000000000000000000001", "res_00000000000000000000000000000001", 33, applied)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.User == "" || candidate.RelayUser == "" || len(candidate.Sysusers) == 0 || candidate.Accounts.Application.User != candidate.User || candidate.Paths.StateRoot != "/var/lib/lanpanel/goaccess/res_00000000000000000000000000000001/generations/1" || !candidate.ReuseApplied {
		t.Fatal("observed candidate omitted account or retained-state authority")
	}
}

func TestAccountAuthorityIsInstallationBound(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	first, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render("ins_00000000000000000000000000000002", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.User == second.User || first.UID == second.UID || first.ServiceIdentity == second.ServiceIdentity {
		t.Fatal("GoAccess account authority was not installation-bound")
	}
}

func TestCandidateCleanupRetainsSharedStateOnlyForAppliedGoAccess(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	candidate, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.RetainShared {
		t.Fatal("first enable retained candidate artifacts")
	}
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{RetiredGeneration: 1, RetiredStateGeneration: 1, RetiredServiceIdentity: digest([]byte("prior"))}}}
	candidate, err = Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil || !candidate.RetainShared || !candidate.RetainState || candidate.StateGeneration != 1 || candidate.Paths.StateRoot == "/var/lib/lanpanel/goaccess/res_00000000000000000000000000000001/generations/2" {
		t.Fatalf("applied retained state lost: %+v %v", candidate, err)
	}
}

func TestActiveRepublishReusesExactServiceAndRequiresDisableForServiceIdentityChange(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	first, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	resource.PublicationRecord.State = domain.PublicationPublished
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: first.Generation, StateGeneration: first.StateGeneration, CanonicalHost: resource.Publication.DomainHTTPS.CanonicalDomain, ServiceIdentity: first.ServiceIdentity, UnitIdentities: append([]string(nil), first.UnitIdentities...), WebSocketPath: first.WebSocketPath}}}
	reused, err := Render("ins_00000000000000000000000000000001", resource, 33, 3)
	if err != nil || !reused.ReuseApplied || reused.Generation != 2 || reused.StateGeneration != 2 || reused.ServiceIdentity != first.ServiceIdentity {
		t.Fatalf("active service was not reused exactly: %+v %v", reused, err)
	}
	resource.Publication.DomainHTTPS.GoAccess.WebSocketPath = "/changed"
	if _, err = Render("ins_00000000000000000000000000000001", resource, 33, 3); err == nil {
		t.Fatal("active service identity changed without disable")
	}
}

func TestUnpublishedRepublishStagesNewUnitsAgainstRetainedState(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	first, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	resource.PublicationRecord.State = domain.PublicationUnpublished
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: 2, StateGeneration: 2, CanonicalHost: "app.example.test", ServiceIdentity: first.ServiceIdentity, UnitIdentities: append([]string(nil), first.UnitIdentities...), WebSocketPath: "/__lanpanel/goaccess-ws"}}}
	candidate, err := Render("ins_00000000000000000000000000000001", resource, 33, 3)
	if err != nil || candidate.ReuseApplied || !candidate.RetainState || candidate.Generation != 3 || candidate.StateGeneration != 2 || candidate.Paths.StateRoot != first.Paths.StateRoot || candidate.Paths.Endpoint == first.Paths.Endpoint {
		t.Fatalf("unpublished republish candidate=%+v err=%v", candidate, err)
	}
}

func TestCandidateGenerationsHaveIsolatedStateAndEndpoints(t *testing.T) {
	first, err := DerivePaths("res_00000000000000000000000000000001", 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DerivePaths("res_00000000000000000000000000000001", 3)
	if err != nil {
		t.Fatal(err)
	}
	if first.StateRoot == second.StateRoot || first.Database == second.Database || first.Report == second.Report || first.Endpoint == second.Endpoint || first.AccessLog != second.AccessLog {
		t.Fatalf("generation paths not isolated: first=%+v second=%+v", first, second)
	}
}

func createOversizedAccessLog(t *testing.T, directory string) (string, string) {
	t.Helper()
	if err := os.Chmod(directory, resourceLogDirectoryMode); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "access.log")
	lock := filepath.Join(directory, "retention.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(maximumAccessLogBytes + 4096); err == nil {
		_, err = file.WriteAt([]byte("\nlatest\n"), maximumAccessLogBytes+4088)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return path, lock
}

func TestNginxWorkerCanTraverseResourceLogDirectoryOnReopen(t *testing.T) {
	if path := os.Getenv("LANPANEL_TEST_NGINX_REOPEN_PATH"); path != "" {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("distinct-identity traversal check requires root")
	}
	root, err := os.MkdirTemp("/tmp", "lanpanel-nginx-reopen-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err = os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	testBinary := filepath.Join(root, "goaccess.test")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(testBinary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	err = errors.Join(copyErr, source.Close(), target.Sync(), target.Close())
	if err != nil {
		t.Fatal(err)
	}
	resourceDirectory := filepath.Join(root, "resource")
	if err = os.Mkdir(resourceDirectory, 0o750); err == nil {
		err = os.Chown(resourceDirectory, 65533, 65533)
	}
	activePath := filepath.Join(resourceDirectory, "access.log")
	if err == nil {
		err = os.WriteFile(activePath, nil, 0o640)
	}
	if err == nil {
		err = os.Chown(activePath, 65534, 65533)
	}
	if err != nil {
		t.Fatal(err)
	}
	runWorker := func() error {
		command := exec.Command(testBinary, "-test.run=^TestNginxWorkerCanTraverseResourceLogDirectoryOnReopen$")
		command.Env = append(os.Environ(), "LANPANEL_TEST_NGINX_REOPEN_PATH="+activePath)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		return command.Run()
	}
	if err = runWorker(); err == nil {
		t.Fatal("worker traversed the former private directory mode")
	}
	if err = os.Chmod(resourceDirectory, 0o751); err != nil {
		t.Fatal(err)
	}
	if err = runWorker(); err != nil {
		t.Fatalf("worker could not reopen the active log through mode 0751: %v", err)
	}
}

func TestGlobalRetentionLockSerializesResourceRotations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global-retention.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := acquireExclusiveRetentionLock(context.Background(), path, uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if second, acquireErr := acquireExclusiveRetentionLock(ctx, path, uint32(os.Getuid()), uint32(os.Getgid())); acquireErr == nil {
		_ = unix.Flock(second, unix.LOCK_UN)
		_ = unix.Close(second)
		t.Fatal("concurrent resource rotation acquired the global lock")
	}
	if err = unix.Flock(first, unix.LOCK_UN); err == nil {
		err = unix.Close(first)
	}
	if err != nil {
		t.Fatal(err)
	}
	third, err := acquireExclusiveRetentionLock(context.Background(), path, uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Flock(third, unix.LOCK_UN)
	if err = unix.Close(third); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionBoundsCanonicalLogWithoutCopytruncate(t *testing.T) {
	path, lock := createOversizedAccessLog(t, t.TempDir())
	if err := rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(path)
	if err != nil || current.Size() != 0 {
		t.Fatalf("replacement log not created: info=%v err=%v", current, err)
	}
	snapshot, err := os.Stat(path + ".1")
	if err != nil || snapshot.Size() != maximumAccessLogBytes {
		t.Fatalf("snapshot not bounded: info=%v err=%v", snapshot, err)
	}
	tail, err := os.ReadFile(path + ".1")
	if err != nil || !bytes.Contains(tail, []byte("\nlatest\n")) {
		t.Fatalf("snapshot did not retain latest bytes: %v", err)
	}
	if _, err = os.Lstat(path + ".retention-old"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("renamed source remained: %v", err)
	}
}

type fixedRuntimeObserver struct {
	snapshot closure.RuntimeSnapshot
	err      error
}

func (observer fixedRuntimeObserver) Observe(context.Context) (closure.RuntimeSnapshot, error) {
	return observer.snapshot, observer.err
}

func TestRetentionCompletesAfterAuditedGraphUnbindAndCompleteNoWriterObservation(t *testing.T) {
	path, lock := createOversizedAccessLog(t, t.TempDir())
	master := closure.ProcessIdentity{PID: 42, StartTicks: 7, Cgroup: "/system.slice/lanpanel-nginx.service"}
	observer := fixedRuntimeObserver{snapshot: closure.RuntimeSnapshot{ObservedAt: time.Now(), Master: &master, Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}, Complete: true, Generation: "test"}}
	signals := 0
	reopen := func(ctx context.Context, old, active retentionFileIdentity) error {
		return waitNginxLogTransition(ctx, observer, "/proc", path, master, closure.FileIdentity{Device: old.Device, Inode: old.Inode}, closure.FileIdentity{Device: active.Device, Inode: active.Inode}, time.Second,
			func() (nginx.Manifest, error) { return nginx.Manifest{Entries: []nginx.Entry{}}, nil },
			func(string, []closure.ProcessIdentity, uint64, uint64) ([]closure.ProcessIdentity, error) {
				return nil, nil
			},
			func(context.Context) error { signals++; return nil })
	}
	if err := rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), retentionOptions{NginxUID: uint32(os.Getuid()), Reopen: reopen}); err != nil {
		t.Fatal(err)
	}
	if signals != 0 {
		t.Fatalf("unbound graph was signaled for reopen %d times", signals)
	}
	if active, err := os.Stat(path); err != nil || active.Size() != 0 {
		t.Fatalf("replacement log not settled: %v %v", active, err)
	}
	if snapshot, err := os.Stat(path + ".1"); err != nil || snapshot.Size() != maximumAccessLogBytes {
		t.Fatalf("retained snapshot not installed: %v %v", snapshot, err)
	}
}

func TestRetentionWaitsWhenConcurrentReloadRebindsAnUnboundGraph(t *testing.T) {
	path, lock := createOversizedAccessLog(t, t.TempDir())
	master := closure.ProcessIdentity{PID: 42, StartTicks: 7, Cgroup: "/system.slice/lanpanel-nginx.service"}
	observer := fixedRuntimeObserver{snapshot: closure.RuntimeSnapshot{ObservedAt: time.Now(), Master: &master, Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}, Complete: true, Generation: "test"}}
	auditCalls := 0
	reopen := func(ctx context.Context, old, active retentionFileIdentity) error {
		return waitNginxLogTransition(ctx, observer, "/proc", path, master, closure.FileIdentity{Device: old.Device, Inode: old.Inode}, closure.FileIdentity{Device: active.Device, Inode: active.Inode}, time.Second,
			func() (nginx.Manifest, error) {
				auditCalls++
				if auditCalls == 1 {
					return nginx.Manifest{Entries: []nginx.Entry{}}, nil
				}
				return nginx.Manifest{Entries: []nginx.Entry{{Domain: &nginx.DomainSite{GoAccess: &nginx.GoAccessSite{AccessLog: path}}}}}, nil
			},
			func(_ string, processes []closure.ProcessIdentity, device, inode uint64) ([]closure.ProcessIdentity, error) {
				if auditCalls >= 3 && device == active.Device && inode == active.Inode {
					return append([]closure.ProcessIdentity(nil), processes...), nil
				}
				return nil, nil
			},
			func(context.Context) error { return nil })
	}
	if err := rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), retentionOptions{NginxUID: uint32(os.Getuid()), Reopen: reopen}); err != nil {
		t.Fatal(err)
	}
	if auditCalls < 4 {
		t.Fatalf("retention did not require stable rebound evidence: audits=%d", auditCalls)
	}
}

func TestUnboundRetentionStillFailsOnGraphOrRuntimeInventoryError(t *testing.T) {
	for _, test := range []struct {
		name        string
		observer    fixedRuntimeObserver
		audit       func() (nginx.Manifest, error)
		writableErr error
		bound       bool
	}{
		{name: "graph inventory", observer: fixedRuntimeObserver{snapshot: closure.RuntimeSnapshot{Complete: true, Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}}}, audit: func() (nginx.Manifest, error) {
			return nginx.Manifest{}, fmt.Errorf("injected graph inventory failure")
		}},
		{name: "runtime observation", observer: fixedRuntimeObserver{err: fmt.Errorf("injected runtime observation failure")}, audit: func() (nginx.Manifest, error) { return nginx.Manifest{Entries: []nginx.Entry{}}, nil }},
		{name: "incomplete runtime inventory", observer: fixedRuntimeObserver{snapshot: closure.RuntimeSnapshot{Complete: false}}, audit: func() (nginx.Manifest, error) { return nginx.Manifest{Entries: []nginx.Entry{}}, nil }},
		{name: "writer inventory", observer: fixedRuntimeObserver{snapshot: closure.RuntimeSnapshot{Complete: true, Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}}}, audit: func() (nginx.Manifest, error) { return nginx.Manifest{Entries: []nginx.Entry{}}, nil }, writableErr: fmt.Errorf("injected descriptor inventory failure")},
		{name: "graph remains bound", observer: fixedRuntimeObserver{snapshot: closure.RuntimeSnapshot{Complete: true, Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}}}, bound: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, lock := createOversizedAccessLog(t, t.TempDir())
			master := closure.ProcessIdentity{PID: 42, StartTicks: 7, Cgroup: "/system.slice/lanpanel-nginx.service"}
			if test.observer.err == nil {
				test.observer.snapshot.Master = &master
				test.observer.snapshot.ObservedAt = time.Now()
				test.observer.snapshot.Generation = "test"
			}
			audit := test.audit
			if test.bound {
				audit = func() (nginx.Manifest, error) {
					return nginx.Manifest{Entries: []nginx.Entry{{Domain: &nginx.DomainSite{GoAccess: &nginx.GoAccessSite{AccessLog: path}}}}}, nil
				}
			}
			reopen := func(ctx context.Context, old, active retentionFileIdentity) error {
				return waitNginxLogTransition(ctx, test.observer, "/proc", path, master, closure.FileIdentity{Device: old.Device, Inode: old.Inode}, closure.FileIdentity{Device: active.Device, Inode: active.Inode}, time.Second, audit,
					func(string, []closure.ProcessIdentity, uint64, uint64) ([]closure.ProcessIdentity, error) {
						return nil, test.writableErr
					},
					func(context.Context) error { return nil })
			}
			if err := rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), retentionOptions{NginxUID: uint32(os.Getuid()), Reopen: reopen}); err == nil {
				t.Fatal("incomplete or failed inventory was accepted")
			}
		})
	}
}

func TestRetentionConcurrentAppendsLandExactlyOnceInOldOrNewLog(t *testing.T) {
	path, lock := createOversizedAccessLog(t, t.TempDir())
	writer, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	var writerMu sync.Mutex
	var writtenMu sync.Mutex
	written := []uint64{}
	var next atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			value := next.Add(1)
			writerMu.Lock()
			_, writeErr := fmt.Fprintf(writer, "record:%020d\n", value)
			writerMu.Unlock()
			if writeErr != nil {
				return
			}
			writtenMu.Lock()
			written = append(written, value)
			writtenMu.Unlock()
			time.Sleep(100 * time.Microsecond)
		}
	}()
	reopen := func(_ context.Context, _, _ retentionFileIdentity) error {
		writerMu.Lock()
		defer writerMu.Unlock()
		nextWriter, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if openErr != nil {
			return openErr
		}
		closeErr := writer.Close()
		writer = nextWriter
		return closeErr
	}
	err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), retentionOptions{
		NginxUID: uint32(os.Getuid()), Reopen: reopen,
		Checkpoint: func(retentionCheckpoint) error {
			time.Sleep(2 * time.Millisecond)
			return nil
		},
	})
	close(stop)
	<-done
	writerMu.Lock()
	closeErr := writer.Close()
	writerMu.Unlock()
	if err != nil || closeErr != nil {
		t.Fatalf("rotation=%v close=%v", err, closeErr)
	}
	observed := map[uint64]int{}
	for _, name := range []string{path + ".1", path} {
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if !bytes.HasPrefix(line, []byte("record:")) {
				continue
			}
			value, parseErr := strconv.ParseUint(string(bytes.TrimPrefix(line, []byte("record:"))), 10, 64)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			observed[value]++
		}
	}
	writtenMu.Lock()
	defer writtenMu.Unlock()
	if len(written) == 0 {
		t.Fatal("writer produced no concurrent records")
	}
	for _, value := range written {
		if observed[value] != 1 {
			t.Fatalf("record %d observed %d times", value, observed[value])
		}
	}
}

func TestRetentionRecoversFailuresAroundRenameAndReopen(t *testing.T) {
	for _, failure := range []retentionCheckpoint{checkpointRenamed, checkpointReplacementBound, checkpointBeforeReopen, checkpointAfterReopen, checkpointSnapshot} {
		t.Run(string(failure), func(t *testing.T) {
			path, lock := createOversizedAccessLog(t, t.TempDir())
			writer, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			reopen := func(_ context.Context, _, _ retentionFileIdentity) error {
				mu.Lock()
				defer mu.Unlock()
				if writer == nil {
					return nil
				}
				next, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if openErr != nil {
					return openErr
				}
				closeErr := writer.Close()
				writer = nil
				return errors.Join(closeErr, next.Close())
			}
			failed := false
			options := retentionOptions{NginxUID: uint32(os.Getuid()), Reopen: reopen, Checkpoint: func(current retentionCheckpoint) error {
				if current == failure && !failed {
					failed = true
					return fmt.Errorf("injected %s failure", failure)
				}
				return nil
			}}
			if err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), options); err == nil {
				t.Fatal("injected failure was not observed")
			}
			options.Checkpoint = nil
			if err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), options); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if writer != nil {
				_ = writer.Close()
			}
			mu.Unlock()
			data, err := os.ReadFile(path + ".1")
			if err != nil || !bytes.Contains(data, []byte("\nlatest\n")) {
				t.Fatalf("recovered snapshot=%v err=%v", bytes.HasSuffix(data, []byte("latest")), err)
			}
			for _, residue := range []string{path + ".retention-old", path + ".retention-new", path + ".retention-state", path + ".retention-state.lanpanel", path + ".1.lanpanel"} {
				if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("residue %s remained: %v", residue, err)
				}
			}
		})
	}
}

func TestPreparedRetentionRejectsSnapshotStagingBeforeMutation(t *testing.T) {
	path, lock := createOversizedAccessLog(t, t.TempDir())
	options := retentionOptions{NginxUID: uint32(os.Getuid()), Checkpoint: func(checkpoint retentionCheckpoint) error {
		if checkpoint == checkpointPrepared {
			return fmt.Errorf("stop after prepared state")
		}
		return nil
	}}
	if err := rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), options); err == nil {
		t.Fatal("prepared checkpoint failure was not observed")
	}
	if err := os.WriteFile(path+".1.lanpanel", []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	options.Checkpoint = nil
	if err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), options); err == nil {
		t.Fatal("prepared recovery accepted impossible snapshot staging")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("prepared source changed: %v", err)
	}
	if _, err = os.Lstat(path + ".retention-new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepared recovery created replacement before rejection: %v", err)
	}
}

func TestRetentionRejectsForeignMetadataAndLinks(t *testing.T) {
	for _, test := range []struct {
		name  string
		alter func(*testing.T, string)
		uid   func() uint32
	}{
		{name: "snapshot symlink", alter: func(t *testing.T, path string) {
			outside := path + ".outside"
			if err := os.WriteFile(outside, []byte("foreign"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path+".1"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong mode", alter: func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "multiple links", alter: func(t *testing.T, path string) {
			if err := os.Link(path, path+".foreign-link"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unknown state", alter: func(t *testing.T, path string) {
			if err := os.WriteFile(path+".retention-state", []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unknown staged replacement", alter: func(t *testing.T, path string) {
			if err := os.WriteFile(path+".retention-new", []byte("foreign"), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong owner authority", alter: func(*testing.T, string) {}, uid: func() uint32 { return uint32(os.Getuid() + 1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, lock := createOversizedAccessLog(t, t.TempDir())
			test.alter(t, path)
			uid := uint32(os.Getuid())
			if test.uid != nil {
				uid = test.uid()
			}
			before, _ := os.Lstat(path)
			if err := rotateAccessLog(path, lock, uid, uint32(os.Getgid())); err == nil {
				t.Fatal("foreign retention artifact was accepted")
			}
			after, _ := os.Lstat(path)
			if before != nil && after != nil && !os.SameFile(before, after) {
				t.Fatal("foreign source path changed")
			}
		})
	}
}

func TestRetentionRejectsUnsafeDirectoryBeforeCreatingStateOrLock(t *testing.T) {
	path, lock := createOversizedAccessLog(t, t.TempDir())
	if err := os.Chmod(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("unsafe resource log directory was accepted")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("source changed after directory rejection: %v", err)
	}
	for _, artifact := range []string{lock, path + ".retention-state", path + ".retention-new", path + ".retention-old"} {
		if _, err = os.Lstat(artifact); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("artifact created before directory rejection: %s: %v", artifact, err)
		}
	}
}

func TestRetentionBelowThresholdHasNoSideEffects(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, resourceLogDirectoryMode); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "access.log")
	lock := filepath.Join(directory, "retention.lock")
	if err := os.WriteFile(path, []byte("small\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1", []byte("prior\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), retentionOptions{NginxUID: uint32(os.Getuid()), Reopen: func(context.Context, retentionFileIdentity, retentionFileIdentity) error { calls++; return nil }}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || calls != 0 {
		t.Fatalf("below-threshold rotation changed source or reopened Nginx: same=%t calls=%d err=%v", os.SameFile(before, after), calls, err)
	}
	if data, err := os.ReadFile(path + ".1"); err != nil || string(data) != "prior\n" {
		t.Fatalf("prior snapshot changed: %q %v", data, err)
	}
	for _, residue := range []string{path + ".retention-old", path + ".retention-new", path + ".retention-state", path + ".retention-state.lanpanel", path + ".1.lanpanel"} {
		if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("below-threshold residue %s: %v", residue, err)
		}
	}
}

func TestSettledRetentionCleanupRejectsRecoveryArtifactsAndSpecialModeBits(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o751); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"access.log": []byte("active\n"), "access.log.1": []byte("retained\n"), ".retention.lock": nil} {
		mode := os.FileMode(0o640)
		if name == ".retention.lock" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(root, name), content, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifySettledRetentionLogRoot(context.Background(), root, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "access.log.retention-state")
	if err := os.WriteFile(statePath, []byte("unknown"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySettledRetentionLogRoot(context.Background(), root, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("cleanup accepted an unsettled fixed-name recovery artifact")
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	accessPath := filepath.Join(root, "access.log")
	if err := os.Chmod(accessPath, 0o640|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := verifySettledRetentionLogRoot(context.Background(), root, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("cleanup accepted special mode bits")
	}
}

func TestRetentionReopenFailurePreservesUniqueRenamedLog(t *testing.T) {
	path, lock := createOversizedAccessLog(t, t.TempDir())
	prior := []byte("prior snapshot\n")
	if err := os.WriteFile(path+".1", prior, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid()), retentionOptions{NginxUID: uint32(os.Getuid()), Reopen: func(context.Context, retentionFileIdentity, retentionFileIdentity) error {
		return fmt.Errorf("injected Nginx reopen failure")
	}})
	if err == nil {
		t.Fatal("Nginx reopen failure was hidden")
	}
	old, statErr := os.Stat(path + ".retention-old")
	if statErr != nil || !os.SameFile(before, old) || old.Size() != before.Size() {
		t.Fatalf("unique renamed log changed: before=%v old=%v err=%v", before, old, statErr)
	}
	if data, readErr := os.ReadFile(path + ".1"); readErr != nil || !bytes.Equal(data, prior) {
		t.Fatalf("prior snapshot changed on reopen failure: %q %v", data, readErr)
	}
	active, activeErr := os.Stat(path)
	if activeErr != nil || active.Size() != 0 {
		t.Fatalf("replacement log missing after reopen failure: %v %v", active, activeErr)
	}
}

type fakeLauncher struct {
	results   map[child.ProfileID]child.Result
	sequences map[child.ProfileID][]child.Result
	calls     []child.ProfileID
	budgets   map[child.ProfileID][]time.Duration
}

func (f *fakeLauncher) RunInvocation(ctx context.Context, id child.ProfileID, _ child.Invocation, _ []byte) (child.Result, error) {
	f.calls = append(f.calls, id)
	if deadline, ok := ctx.Deadline(); ok {
		if f.budgets == nil {
			f.budgets = map[child.ProfileID][]time.Duration{}
		}
		f.budgets[id] = append(f.budgets[id], time.Until(deadline))
	}
	if sequence := f.sequences[id]; len(sequence) != 0 {
		f.sequences[id] = sequence[1:]
		return sequence[0], nil
	}
	return f.results[id], nil
}

func stoppedUnits(active string) []byte {
	unitID := "res_00000000000000000000000000000001-7"
	names := []string{"lanpanel-goaccess-" + unitID + ".service", "lanpanel-goaccess-relay-" + unitID + ".service", "lanpanel-goaccess-" + unitID + ".socket", "lanpanel-goaccess-retention-" + unitID + ".timer", "lanpanel-goaccess-retention-" + unitID + ".service"}
	blocks := make([]string, len(names))
	for index, name := range names {
		state, pid := "inactive", "0"
		if strings.Contains(name, active) && active != "" {
			state, pid = "active", "42"
		}
		unitFileState := "disabled"
		if strings.HasSuffix(name, ".service") && strings.Contains(name, "goaccess-retention-") {
			unitFileState = "static"
		}
		blocks[index] = fmt.Sprintf("Id=%s\nLoadState=loaded\nActiveState=%s\nMainPID=%s\nUnitFileState=%s", name, state, pid, unitFileState)
	}
	return []byte(strings.Join(blocks, "\n\n"))
}

func TestCandidateStagingRecoveryRemovesOnlyExactOwnedPrefix(t *testing.T) {
	directory := t.TempDir()
	staging := filepath.Join(directory, ".unit.service.lanpanel")
	expected := []byte("complete candidate unit")
	if err := os.WriteFile(staging, expected[:8], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupExactStaging(staging, expected, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact staging residue remains: %v", err)
	}
	if err := os.WriteFile(staging, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupExactStaging(staging, expected, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("foreign staging residue removed")
	}
	if value, err := os.ReadFile(staging); err != nil || string(value) != "foreign" {
		t.Fatalf("foreign staging changed: %q %v", value, err)
	}
}

func TestRetainedCleanupRequiresExactUnitAndStateGenerationsBeforeObservation(t *testing.T) {
	item := RetainedGeneration{Generation: 2, StateGeneration: 3, ServiceIdentity: digest([]byte("service")), UnitIdentities: []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}}
	err := (Host{}).CleanupRetained(context.Background(), "ins_00000000000000000000000000000001", "res_00000000000000000000000000000001", []RetainedGeneration{item})
	if err == nil || !strings.Contains(err.Error(), "generation inventory invalid") {
		t.Fatalf("invalid retained state generation error=%v", err)
	}
}

func TestRetainedTreeCleanupNeverFollowsForeignSymlink(t *testing.T) {
	parent := t.TempDir()
	owned := filepath.Join(parent, "owned")
	if err := os.Mkdir(owned, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.WriteFile(outside, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(owned, "link")); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedTree(context.Background(), owned, uint32(os.Getuid()), uint32(os.Getgid()), 0o750); err == nil {
		t.Fatal("foreign symlink accepted")
	}
	value, err := os.ReadFile(outside)
	if err != nil || string(value) != "foreign" {
		t.Fatalf("foreign source changed: %q %v", value, err)
	}
	if err := os.Remove(filepath.Join(owned, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(owned); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, owned); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedTree(context.Background(), owned, uint32(os.Getuid()), uint32(os.Getgid()), 0o750); err == nil {
		t.Fatal("symlink retained root accepted")
	}
}

func TestAccountLockAcquisitionIsBoundedAndContextAware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pwd.lock")
	first, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(first.Close)
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(second.Close)
	if err := unix.Flock(int(first.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := acquireBoundedFlock(context.Background(), int(second.Fd()), 40*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended account lock error=%v", err)
	}
	if err := unix.Flock(int(first.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := acquireBoundedFlock(context.Background(), int(second.Fd()), 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(second.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestGoAccessAccountDatabasesRequireExactManagedPasswordFields(t *testing.T) {
	authority, err := deriveAccountAuthority("ins_00000000000000000000000000000001", "res_00000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	candidate := Candidate{
		UID: authority.uid, GID: authority.gid, RelayUID: authority.relayUID, RelayGID: authority.relayGID,
		User: authority.user, Group: authority.group, RelayUser: authority.relayUser, RelayGroup: authority.relayGroup,
		Accounts: authority.accounts,
	}
	passwd := fmt.Sprintf("foreign:$6$foreign:9000:9000:Foreign:/home/foreign:/bin/sh\n%s:x:%d:%d:%s:/nonexistent:/usr/sbin/nologin\n%s:x:%d:%d:%s:/nonexistent:/usr/sbin/nologin\n", candidate.User, candidate.UID, candidate.GID, candidate.Accounts.Application.Comment, candidate.RelayUser, candidate.RelayUID, candidate.RelayGID, candidate.Accounts.Relay.Comment)
	group := fmt.Sprintf("foreign::9000:\n%s:x:%d:\n%s:x:%d:\n", candidate.Group, candidate.GID, candidate.RelayGroup, candidate.RelayGID)
	if err := verifyGoAccessAccountDatabases(candidate, true, true, []byte(passwd), []byte(group)); err != nil {
		t.Fatalf("exact managed and non-x foreign records were rejected: %v", err)
	}
	tests := []struct {
		name   string
		passwd string
		group  string
	}{
		{name: "empty passwd", passwd: strings.Replace(passwd, candidate.User+":x:", candidate.User+"::", 1), group: group},
		{name: "passwd hash", passwd: strings.Replace(passwd, candidate.User+":x:", candidate.User+":$6$direct-hash:", 1), group: group},
		{name: "wrong passwd placeholder", passwd: strings.Replace(passwd, candidate.RelayUser+":x:", candidate.RelayUser+":!:", 1), group: group},
		{name: "malformed managed passwd", passwd: candidate.User + ":malformed\n", group: group},
		{name: "empty group password", passwd: passwd, group: strings.Replace(group, candidate.Group+":x:", candidate.Group+"::", 1)},
		{name: "group password hash", passwd: passwd, group: strings.Replace(group, candidate.RelayGroup+":x:", candidate.RelayGroup+":$6$direct-hash:", 1)},
		{name: "malformed managed group", passwd: passwd, group: candidate.Group + ":malformed\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyGoAccessAccountDatabases(candidate, true, true, []byte(test.passwd), []byte(test.group)); err == nil {
				t.Fatal("invalid managed GoAccess database record was accepted")
			}
		})
	}
}

func TestRetainedAccountAuthorityCannotBeRecreated(t *testing.T) {
	candidate := Candidate{Paths: Paths{Sysusers: filepath.Join(t.TempDir(), "missing.conf")}}
	if err := verifyAccountAuthority(candidate, true, true); err == nil || !strings.Contains(err.Error(), "retained account origin marker missing") {
		t.Fatalf("missing retained account authority accepted: %v", err)
	}
}

func TestCleanupRejectsCancellationAndUnavailableHostBeforeMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (Host{}).cleanupAccounts(ctx, Candidate{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled account cleanup error=%v", err)
	}
	if err := (Host{}).CleanupCandidate(context.Background(), Candidate{}); err == nil || !strings.Contains(err.Error(), "host unavailable") {
		t.Fatalf("unavailable candidate cleanup error=%v", err)
	}
}

func TestRetainedStateStagingFreshlyStopsExactPriorGeneration(t *testing.T) {
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessStop: {ExitCode: 0}, child.ProfileGoAccessShow: {ExitCode: 0, Stdout: stoppedUnits("")}}}
	host := Host{launcher: launcher}
	candidate := Candidate{ResourceID: "res_00000000000000000000000000000001", Generation: 8, RetainedServiceGeneration: 7, RetainedServiceIdentity: digest([]byte("service")), RetainedUnitIdentities: []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}}
	if err := host.ensureRetainedStateStopped(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow, child.ProfileGoAccessRetain, child.ProfileGoAccessStop, child.ProfileGoAccessShow}) {
		t.Fatalf("retained-state stop calls=%v", launcher.calls)
	}
}

func TestStopRequiresEveryUnitAndEndpointClosed(t *testing.T) {
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessStop: {ExitCode: 0}, child.ProfileGoAccessShow: {ExitCode: 0, Stdout: stoppedUnits("")}}}
	host := Host{launcher: launcher}
	if err := host.Stop(context.Background(), "res_00000000000000000000000000000001", 7); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessRetain, child.ProfileGoAccessStop, child.ProfileGoAccessShow}) {
		t.Fatalf("final retention/stop order=%v", launcher.calls)
	}
	launcher.results[child.ProfileGoAccessShow] = child.Result{ExitCode: 0, Stdout: stoppedUnits("relay")}
	if err := host.Stop(context.Background(), "res_00000000000000000000000000000001", 7); err == nil {
		t.Fatal("active relay accepted as stopped")
	}
}

func TestEnsureStoppedContractsDespiteFinalRetentionFailure(t *testing.T) {
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessRetain: {ExitCode: 1}, child.ProfileGoAccessStop: {ExitCode: 0}, child.ProfileGoAccessShow: {ExitCode: 0, Stdout: stoppedUnits("")}}}
	host := Host{launcher: launcher}
	if err := host.EnsureStopped(context.Background(), "res_00000000000000000000000000000001", 7); err == nil || !strings.Contains(err.Error(), "final GoAccess retention failed") {
		t.Fatalf("retention failure was hidden: %v", err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow, child.ProfileGoAccessRetain, child.ProfileGoAccessStop, child.ProfileGoAccessShow}) {
		t.Fatalf("emergency retention/stop calls=%v", launcher.calls)
	}
	retentionBudgets, stopBudgets := launcher.budgets[child.ProfileGoAccessRetain], launcher.budgets[child.ProfileGoAccessStop]
	if len(retentionBudgets) != 1 || retentionBudgets[0] < finalRetentionTimeout-time.Second || retentionBudgets[0] > finalRetentionTimeout || len(stopBudgets) != 1 || stopBudgets[0] < stopTimeout-time.Second || stopBudgets[0] > stopTimeout {
		t.Fatalf("independent retention/stop budgets: retention=%v stop=%v", retentionBudgets, stopBudgets)
	}
}

func TestRetireAcceptsExactAlreadyRemovedGeneration(t *testing.T) {
	removed := strings.ReplaceAll(string(stoppedUnits("")), "LoadState=loaded", "LoadState=not-found")
	removed = strings.ReplaceAll(removed, "UnitFileState=disabled", "UnitFileState=")
	removed = strings.ReplaceAll(removed, "UnitFileState=static", "UnitFileState=")
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessShow: {ExitCode: 0, Stdout: []byte(removed)}}}
	host := Host{launcher: launcher}
	identities := []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}
	if err := host.Retire(context.Background(), "res_00000000000000000000000000000001", 7, digest([]byte("service")), identities); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow}) {
		t.Fatalf("already-retired generation was restarted: %v", launcher.calls)
	}
}

func TestRetireReloadsCrashRemovedUnitFilesBeforeCompletion(t *testing.T) {
	removed := strings.ReplaceAll(string(stoppedUnits("")), "LoadState=loaded", "LoadState=not-found")
	removed = strings.ReplaceAll(removed, "UnitFileState=disabled", "UnitFileState=")
	removed = strings.ReplaceAll(removed, "UnitFileState=static", "UnitFileState=")
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileSystemctl: {ExitCode: 0}}, sequences: map[child.ProfileID][]child.Result{child.ProfileGoAccessShow: {{ExitCode: 0, Stdout: stoppedUnits("")}, {ExitCode: 0, Stdout: []byte(removed)}}}}
	host := Host{launcher: launcher}
	identities := []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}
	if err := host.Retire(context.Background(), "res_00000000000000000000000000000001", 7, digest([]byte("service")), identities); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow, child.ProfileSystemctl, child.ProfileGoAccessShow}) {
		t.Fatalf("crash removal recovery calls=%v", launcher.calls)
	}
}

func TestPartialStopAcceptsOnlyExcludedNotFoundUnits(t *testing.T) {
	resourceID := "res_00000000000000000000000000000001"
	output := string(stoppedUnits(""))
	relayID := "lanpanel-goaccess-relay-" + resourceID + "-7.service"
	output = strings.Replace(output, "Id="+relayID+"\nLoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled", "Id="+relayID+"\nLoadState=not-found\nActiveState=inactive\nMainPID=0\nUnitFileState=", 1)
	if err := verifyStoppedUnitOutput([]byte(output), resourceID, 7, 29); err != nil {
		t.Fatal(err)
	}
	if err := verifyStoppedUnitOutput([]byte(output), resourceID, 7, 31); err == nil {
		t.Fatal("required not-found relay accepted")
	}
}

func TestRemovedUnitsRequireNotFoundEvidence(t *testing.T) {
	output := strings.ReplaceAll(string(stoppedUnits("")), "LoadState=loaded", "LoadState=not-found")
	output = strings.ReplaceAll(output, "UnitFileState=disabled", "UnitFileState=")
	output = strings.ReplaceAll(output, "UnitFileState=static", "UnitFileState=")
	if err := verifyRemovedUnitOutput([]byte(output)); err != nil {
		t.Fatal(err)
	}
	if err := verifyRemovedUnitOutput(stoppedUnits("")); err == nil {
		t.Fatal("loaded stopped units accepted as removed")
	}
}

func TestRetentionRuntimeAcceptsOnlyBoundedExpectedOneshotPhases(t *testing.T) {
	for _, properties := range []map[string]string{{"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}, {"ActiveState": "activating", "SubState": "start", "MainPID": "42"}} {
		if !validRetentionRuntime(properties) {
			t.Fatalf("expected retention phase rejected: %#v", properties)
		}
	}
	for _, properties := range []map[string]string{{"ActiveState": "active", "SubState": "running", "MainPID": "42"}, {"ActiveState": "activating", "SubState": "start-pre", "MainPID": "0"}, {"ActiveState": "activating", "SubState": "start", "MainPID": "0"}, {"ActiveState": "activating", "SubState": "start-post", "MainPID": "0"}, {"ActiveState": "failed", "SubState": "failed", "MainPID": "0"}} {
		if validRetentionRuntime(properties) {
			t.Fatalf("unexpected retention phase accepted: %#v", properties)
		}
	}
}

func TestEffectiveUnitParserRequiresDistinctClosedInventory(t *testing.T) {
	blocks := []string{}
	for _, name := range []string{"service", "relay", "socket", "timer", "retention"} {
		blocks = append(blocks, fmt.Sprintf("Id=%s\nActiveState=active", name))
	}
	units, err := parseEffectiveUnits(strings.Join(blocks, "\n\n"))
	if err != nil || len(units) != 5 {
		t.Fatalf("units=%v err=%v", units, err)
	}
	if _, err = parseEffectiveUnits(strings.Join(append(blocks, blocks[0]), "\n\n")); err == nil {
		t.Fatal("duplicate effective unit accepted")
	}
}

func TestDisabledGoAccessCreatesNoCandidate(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{}}}
	if _, err := Render("ins_00000000000000000000000000000001", resource, 33, 2); err == nil {
		t.Fatal("disabled GoAccess rendered files")
	}
}
