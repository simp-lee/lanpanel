//go:build linux

package goaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/closure"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maximumAccessLogBytes int64 = 10 << 20
	maximumRetentionState       = 4096
	retentionStateSchema        = "lanpanel.goaccess.retention.v1"
)

type retentionPhase string

const (
	retentionPrepared          retentionPhase = "prepared"
	retentionReady             retentionPhase = "ready"
	retentionSnapshotInstalled retentionPhase = "snapshot_installed"

	checkpointPrepared         retentionCheckpoint = "prepared"
	checkpointRenamed          retentionCheckpoint = "renamed"
	checkpointReplacementBound retentionCheckpoint = "replacement_bound"
	checkpointBeforeReopen     retentionCheckpoint = "before_reopen"
	checkpointAfterReopen      retentionCheckpoint = "after_reopen"
	checkpointSnapshot         retentionCheckpoint = "snapshot_installed"
)

type retentionCheckpoint string

type retentionFileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest,omitempty"`
}

type retentionState struct {
	SchemaVersion string                 `json:"schema_version"`
	Phase         retentionPhase         `json:"phase"`
	Source        retentionFileIdentity  `json:"source"`
	Active        *retentionFileIdentity `json:"active,omitempty"`
	Previous      *retentionFileIdentity `json:"previous,omitempty"`
	Snapshot      *retentionFileIdentity `json:"snapshot,omitempty"`
}

type retentionOptions struct {
	NginxUID   uint32
	Reopen     func(context.Context, retentionFileIdentity, retentionFileIdentity) error
	Checkpoint func(retentionCheckpoint) error
}

type rotationPaths struct {
	active, snapshot, old, new, state, stateTemp, snapshotTemp string
}

func RunRetention(args []string) error {
	installationID, resourceID := os.Getenv("LANPANEL_INSTALLATION_ID"), os.Getenv("LANPANEL_RESOURCE_ID")
	generation, generationErr := strconv.ParseUint(os.Getenv("LANPANEL_GOACCESS_GENERATION"), 10, 64)
	if len(args) != 0 || generationErr != nil || generation == 0 || !validInstallationID(installationID) || !validResourceID(resourceID) || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("GoAccess retention requires its fixed privileged timer invocation")
	}
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	if paths.RetainedLog != paths.AccessLog+".1" || paths.RetentionOld != paths.AccessLog+".retention-old" || paths.RetentionNew != paths.AccessLog+".retention-new" || paths.RetentionState != paths.AccessLog+".retention-state" || paths.RetentionStateTemp != paths.AccessLog+".retention-state.lanpanel" || paths.RetentionTemp != paths.AccessLog+".1.lanpanel" || filepath.Dir(paths.RetentionLock) != filepath.Dir(paths.AccessLog) {
		return fmt.Errorf("GoAccess retention fixed path graph is invalid")
	}
	uid, gid, _, _ := numeric(installationID, resourceID)
	if err = validateFixedRetentionRoot(); err != nil {
		return err
	}
	worker, err := user.Lookup("www-data")
	if err != nil {
		return fmt.Errorf("resolve fixed Nginx worker identity: %w", err)
	}
	nginxUID, err := strconv.ParseUint(worker.Uid, 10, 32)
	if err != nil || nginxUID == 0 {
		return fmt.Errorf("fixed Nginx worker identity is invalid")
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	globalLock, err := acquireGlobalRetentionLock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Flock(globalLock, unix.LOCK_UN)
		_ = unix.Close(globalLock)
	}()
	reopener := fixedNginxLogReopener{launcher: launcher, installationID: installationID, nginxUID: uint32(nginxUID)}
	return rotateAccessLogWithOptions(ctx, paths.AccessLog, paths.RetentionLock, uid, gid, retentionOptions{
		NginxUID: uint32(nginxUID),
		Reopen: func(ctx context.Context, old, active retentionFileIdentity) error {
			return reopener.Reopen(ctx, paths.AccessLog, old, active)
		},
	})
}

func validateFixedRetentionRoot() error {
	fd, err := unix.Open(filepath.Dir(globalRetentionLockPath), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o7777 != 0o711 {
		return errors.Join(err, fmt.Errorf("GoAccess retention root identity unsafe"))
	}
	return nil
}

func acquireGlobalRetentionLock(ctx context.Context) (int, error) {
	return acquireExclusiveRetentionLock(ctx, globalRetentionLockPath, 0, 0)
}

func acquireExclusiveRetentionLock(ctx context.Context, path string, uid, gid uint32) (int, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("global GoAccess retention lock authority invalid")
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != 0o600 || stat.Size != 0 {
		_ = unix.Close(fd)
		return -1, errors.Join(err, fmt.Errorf("global GoAccess retention lock identity unsafe"))
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = unix.Close(fd)
			return -1, err
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(fd)
			return -1, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type fixedNginxLogReopener struct {
	launcher       *child.Launcher
	installationID string
	nginxUID       uint32
}

func (reopener fixedNginxLogReopener) Reopen(ctx context.Context, activePath string, old, active retentionFileIdentity) error {
	if reopener.launcher == nil || !validInstallationID(reopener.installationID) || reopener.nginxUID == 0 {
		return fmt.Errorf("nginx log reopen launcher is unavailable")
	}
	if err := reopener.restoreManagedLogMetadata(); err != nil {
		return err
	}
	paths := nginx.FixedPaths()
	observer := closure.ProcObserver{
		UnitCgroup:   "/system.slice/lanpanel-nginx.service",
		Executable:   "/usr/sbin/nginx",
		ExpectedArgv: "/usr/sbin/nginx\x00-c\x00/etc/lanpanel/nginx/nginx.conf\x00-p\x00/var/lib/lanpanel/nginx/\x00-g\x00daemon off;",
		PIDPath:      paths.PIDPath,
		Generation:   "log-reopen",
	}
	prior, err := observer.Observe(ctx)
	if err != nil {
		return err
	}
	if prior.Master == nil {
		return closure.VerifyStopped(prior)
	}
	signal := func(ctx context.Context) error {
		result, err := reopener.launcher.Run(ctx, child.ProfileNginxReopenSignal, nil)
		if err != nil || result.ExitCode != 0 || result.OutputCutOff {
			return errors.Join(err, fmt.Errorf("fixed Nginx log reopen failed: exit=%d", result.ExitCode))
		}
		return nil
	}
	audit := func() (nginx.Manifest, error) {
		return nginx.Audit(paths, filetxn.Owner{UID: 0, GID: 0})
	}
	transitionErr := waitNginxLogTransition(ctx, observer, "/proc", activePath, *prior.Master, closure.FileIdentity{Device: old.Device, Inode: old.Inode}, closure.FileIdentity{Device: active.Device, Inode: active.Inode}, 15*time.Second, audit, closure.WritableFileReferences, signal)
	return errors.Join(transitionErr, reopener.restoreManagedLogMetadata())
}

type writableReferenceObserver func(string, []closure.ProcessIdentity, uint64, uint64) ([]closure.ProcessIdentity, error)

// waitNginxLogTransition coordinates timer/final retention with a concurrent
// graph reload. A bound graph must reopen onto the replacement inode. Once an
// audited graph is explicitly unbound, two complete process inventories with
// no writer to either inode are the successful terminal state.
func waitNginxLogTransition(ctx context.Context, observer closure.RuntimeObserver, procRoot, activePath string, priorMaster closure.ProcessIdentity, old, active closure.FileIdentity, timeout time.Duration, audit func() (nginx.Manifest, error), writable writableReferenceObserver, signal func(context.Context) error) error {
	if ctx == nil || observer == nil || !filepath.IsAbs(procRoot) || filepath.Clean(procRoot) != procRoot || !filepath.IsAbs(activePath) || filepath.Clean(activePath) != activePath || priorMaster.PID <= 1 || priorMaster.StartTicks == 0 || priorMaster.Cgroup == "" || old.Device == 0 || old.Inode == 0 || active.Device == 0 || active.Inode == 0 || old == active || timeout <= 0 || timeout > time.Minute || audit == nil || writable == nil || signal == nil {
		return fmt.Errorf("nginx retention transition authority is invalid")
	}
	deadline := time.Now().Add(timeout)
	nextSignal := time.Now()
	signals, clearObservations := 0, 0
	sawUnbound := false
	var priorBound *bool
	for {
		var stat unix.Stat_t
		if err := unix.Lstat(activePath, &stat); err != nil {
			return fmt.Errorf("replacement file identity unavailable: %w", err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || uint64(stat.Dev) != active.Device || stat.Ino != active.Inode {
			return fmt.Errorf("replacement file identity changed")
		}
		snapshot, err := observer.Observe(ctx)
		if err != nil {
			return err
		}
		if snapshot.Master == nil {
			return closure.VerifyStopped(snapshot)
		}
		if !snapshot.Complete {
			return fmt.Errorf("nginx retention runtime inventory is incomplete")
		}
		if snapshot.Master.PID != priorMaster.PID || snapshot.Master.StartTicks != priorMaster.StartTicks || snapshot.Master.Cgroup != priorMaster.Cgroup {
			return fmt.Errorf("nginx retention master identity changed")
		}
		manifest, err := audit()
		if err != nil {
			return fmt.Errorf("nginx retention graph inventory unavailable: %w", err)
		}
		bound := manifestBindsAccessLog(manifest, activePath)
		sawUnbound = sawUnbound || !bound
		if priorBound != nil && *priorBound != bound {
			clearObservations = 0
		}
		boundCopy := bound
		priorBound = &boundCopy

		processes := make([]closure.ProcessIdentity, 0, len(snapshot.Workers)+1)
		processes = append(processes, *snapshot.Master)
		processes = append(processes, snapshot.Workers...)
		oldWriters, err := writable(procRoot, processes, old.Device, old.Inode)
		if err != nil {
			return err
		}
		clear := false
		if !bound {
			activeWriters, observeErr := writable(procRoot, processes, active.Device, active.Inode)
			if observeErr != nil {
				return observeErr
			}
			clear = len(oldWriters) == 0 && len(activeWriters) == 0
		} else {
			activeMaster, observeErr := writable(procRoot, []closure.ProcessIdentity{*snapshot.Master}, active.Device, active.Inode)
			if observeErr != nil {
				return observeErr
			}
			clear = len(oldWriters) == 0 && len(activeMaster) == 1
			if signals == 0 && !sawUnbound && len(oldWriters) == 0 && len(activeMaster) == 0 {
				return fmt.Errorf("nginx runtime is not bound to either retention log inode")
			}
		}
		if clear {
			clearObservations++
			if clearObservations == 2 {
				return nil
			}
		} else {
			clearObservations = 0
		}
		now := time.Now()
		if bound && len(oldWriters) != 0 && signals < 3 && !now.Before(nextSignal) {
			if err = signal(ctx); err != nil {
				return err
			}
			signals++
			now = time.Now()
			nextSignal = now.Add(100 * time.Millisecond)
		}
		if !now.Before(deadline) {
			return fmt.Errorf("runtime did not settle the retention log before the fixed deadline")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func manifestBindsAccessLog(manifest nginx.Manifest, activePath string) bool {
	for _, entry := range manifest.Entries {
		if entry.Domain != nil && entry.Domain.GoAccess != nil && entry.Domain.GoAccess.AccessLog == activePath {
			return true
		}
	}
	return false
}

func (reopener fixedNginxLogReopener) restoreManagedLogMetadata() error {
	if err := restoreReopenedLogPath(nginx.FixedPaths().AuditPath, 0, 0, 0o600, reopener.nginxUID); err != nil {
		return err
	}
	const root = "/var/log/lanpanel/goaccess"
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(rootFD) }()
	var rootStat unix.Stat_t
	if err = unix.Fstat(rootFD, &rootStat); err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Uid != 0 || rootStat.Gid != 0 || rootStat.Mode&0o7777 != 0o711 {
		return errors.Join(err, fmt.Errorf("GoAccess log root identity unsafe during Nginx reopen"))
	}
	duplicate, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), root)
	if directory == nil {
		_ = unix.Close(duplicate)
		return fmt.Errorf("wrap GoAccess log root during Nginx reopen")
	}
	entries, readErr := directory.ReadDir(8193)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil || len(entries) > 8192 {
		return errors.Join(readErr, closeErr, fmt.Errorf("GoAccess log inventory is unavailable or unbounded"))
	}
	for _, entry := range entries {
		if !validResourceID(entry.Name()) {
			continue
		}
		uid, gid, _, _ := numeric(reopener.installationID, entry.Name())
		resourceFD, openErr := unix.Openat(rootFD, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return openErr
		}
		var resourceStat unix.Stat_t
		statErr := unix.Fstat(resourceFD, &resourceStat)
		if statErr != nil || resourceStat.Mode&unix.S_IFMT != unix.S_IFDIR || resourceStat.Uid != uid || resourceStat.Gid != gid || resourceStat.Mode&0o7777 != resourceLogDirectoryMode {
			_ = unix.Close(resourceFD)
			return errors.Join(statErr, fmt.Errorf("GoAccess resource log directory unsafe during Nginx reopen"))
		}
		restoreErr := restoreReopenedLogAt(resourceFD, "access.log", uid, gid, 0o640, reopener.nginxUID)
		closeErr := unix.Close(resourceFD)
		if err = errors.Join(restoreErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func restoreReopenedLogPath(path string, uid, gid, mode, nginxUID uint32) error {
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	return restoreReopenedLogAt(parent, filepath.Base(path), uid, gid, mode, nginxUID)
}

func restoreReopenedLogAt(parent int, name string, uid, gid, mode, nginxUID uint32) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("wrap Nginx reopened log")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid && stat.Uid != nginxUID || stat.Gid != gid || stat.Mode&0o7777 != mode {
		_ = file.Close()
		return errors.Join(err, fmt.Errorf("nginx reopened log metadata is unsafe"))
	}
	if stat.Uid != uid {
		err = unix.Fchown(fd, int(uid), int(gid))
		if err == nil {
			err = unix.Fchmod(fd, mode)
		}
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(err, syncErr, closeErr)
}

func rotateAccessLog(path, lockPath string, expectedUID, expectedGID uint32, options ...retentionOptions) error {
	return rotateAccessLogWithOptions(context.Background(), path, lockPath, expectedUID, expectedGID, chooseRetentionOptions(expectedUID, options))
}

func chooseRetentionOptions(expectedUID uint32, options []retentionOptions) retentionOptions {
	if len(options) == 1 {
		value := options[0]
		if value.NginxUID == 0 {
			value.NginxUID = expectedUID
		}
		return value
	}
	return retentionOptions{NginxUID: expectedUID}
}

func rotateAccessLogWithOptions(ctx context.Context, path, lockPath string, expectedUID, expectedGID uint32, options retentionOptions) error {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(lockPath) || filepath.Clean(lockPath) != lockPath || filepath.Dir(path) != filepath.Dir(lockPath) || expectedUID == 0 && os.Getuid() != 0 || expectedGID == 0 && os.Getgid() != 0 {
		return fmt.Errorf("GoAccess retention path authority is invalid")
	}
	if options.NginxUID == 0 {
		options.NginxUID = expectedUID
	}
	paths := rotationPaths{active: path, snapshot: path + ".1", old: path + ".retention-old", new: path + ".retention-new", state: path + ".retention-state", stateTemp: path + ".retention-state.lanpanel", snapshotTemp: path + ".1.lanpanel"}
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	var parentStat unix.Stat_t
	if err = unix.Fstat(parent, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != expectedUID || parentStat.Gid != expectedGID || parentStat.Mode&0o7777 != resourceLogDirectoryMode {
		return errors.Join(err, fmt.Errorf("GoAccess retention directory identity unsafe"))
	}
	lock, err := unix.Openat(parent, filepath.Base(lockPath), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(lock) }()
	var lockStat unix.Stat_t
	if err = unix.Fstat(lock, &lockStat); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Nlink != 1 || lockStat.Uid != expectedUID || lockStat.Gid != expectedGID || lockStat.Mode&0o7777 != 0o600 || lockStat.Size != 0 {
		return fmt.Errorf("GoAccess retention lock identity unsafe")
	}
	if err = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("GoAccess retention already running: %w", err)
	}
	defer func() { _ = unix.Flock(lock, unix.LOCK_UN) }()

	state, stateRaw, statePresent, err := loadRetentionState(parent, filepath.Base(paths.state), expectedUID, expectedGID)
	if err != nil {
		return err
	}
	if !statePresent {
		active, present, err := restoreActiveLogMetadata(parent, filepath.Base(paths.active), nil, expectedUID, expectedGID, options.NginxUID)
		if err != nil {
			return err
		}
		if !present {
			return rejectUnboundResidue(parent, paths)
		}
		if active.Size <= maximumAccessLogBytes {
			return rejectUnboundResidue(parent, paths)
		}
		if err := requireAbsentAt(parent, filepath.Base(paths.old), filepath.Base(paths.new), filepath.Base(paths.snapshotTemp)); err != nil {
			return err
		}
		previous, err := optionalContentIdentity(parent, filepath.Base(paths.snapshot), expectedUID, expectedGID, 0o640, maximumAccessLogBytes)
		if err != nil {
			return err
		}
		state = retentionState{SchemaVersion: retentionStateSchema, Phase: retentionPrepared, Source: inodeIdentity(active), Previous: previous}
		stateRaw, err = publishRetentionState(parent, filepath.Base(paths.state), filepath.Base(paths.stateTemp), nil, state, expectedUID, expectedGID)
		if err != nil {
			return err
		}
		if err := runRetentionCheckpoint(options, checkpointPrepared); err != nil {
			return err
		}
	}

	switch state.Phase {
	case retentionPrepared:
		var err error
		state, stateRaw, err = prepareReplacementLog(parent, paths, state, stateRaw, expectedUID, expectedGID, options)
		if err != nil {
			return err
		}
		fallthrough
	case retentionReady:
		var err error
		state, stateRaw, err = reopenAndInstallSnapshot(ctx, parent, paths, state, stateRaw, expectedUID, expectedGID, options)
		if err != nil {
			return err
		}
		fallthrough
	case retentionSnapshotInstalled:
		return completeRetention(parent, paths, state, stateRaw, expectedUID, expectedGID, options.NginxUID)
	default:
		return fmt.Errorf("GoAccess retention state phase is invalid")
	}
}

func prepareReplacementLog(parent int, paths rotationPaths, state retentionState, stateRaw []byte, uid, gid uint32, options retentionOptions) (retentionState, []byte, error) {
	if err := requireAbsentAt(parent, filepath.Base(paths.old), filepath.Base(paths.snapshotTemp)); err != nil {
		return state, stateRaw, err
	}
	_, activePresent, err := restoreActiveLogMetadata(parent, filepath.Base(paths.active), &state.Source, uid, gid, options.NginxUID)
	if err != nil || !activePresent {
		return state, stateRaw, errors.Join(err, fmt.Errorf("GoAccess prepared retention source is unavailable"))
	}
	staged, stagedPresent, err := rawStatAt(parent, filepath.Base(paths.new))
	if err != nil {
		return state, stateRaw, err
	}
	if !stagedPresent {
		staged, err = createReplacementLog(parent, filepath.Base(paths.new), uid, gid)
	} else {
		staged, err = finishInterruptedReplacement(parent, filepath.Base(paths.new), staged, state.Source, uid, gid)
	}
	if err != nil {
		return state, stateRaw, err
	}
	activeIdentity := inodeIdentity(staged)
	state.Phase, state.Active = retentionReady, &activeIdentity
	nextRaw, err := publishRetentionState(parent, filepath.Base(paths.state), filepath.Base(paths.stateTemp), stateRaw, state, uid, gid)
	if err != nil {
		return state, stateRaw, err
	}
	if err = runRetentionCheckpoint(options, checkpointReplacementBound); err != nil {
		return state, nextRaw, err
	}
	if err = publishReplacementLog(parent, paths, state.Source, *state.Active, uid, gid, options.NginxUID); err != nil {
		return state, nextRaw, err
	}
	if err = runRetentionCheckpoint(options, checkpointRenamed); err != nil {
		return state, nextRaw, err
	}
	return state, nextRaw, nil
}

func reopenAndInstallSnapshot(ctx context.Context, parent int, paths rotationPaths, state retentionState, stateRaw []byte, uid, gid uint32, options retentionOptions) (retentionState, []byte, error) {
	if state.Active == nil {
		return state, stateRaw, fmt.Errorf("GoAccess ready retention state lacks replacement identity")
	}
	if err := publishReplacementLog(parent, paths, state.Source, *state.Active, uid, gid, options.NginxUID); err != nil {
		return state, stateRaw, err
	}
	if err := restoreRotatedSourceMetadata(parent, filepath.Base(paths.old), state.Source, uid, gid, options.NginxUID); err != nil {
		return state, stateRaw, err
	}
	if _, err := validateReplacementLog(parent, filepath.Base(paths.active), *state.Active, uid, gid, options.NginxUID, true); err != nil {
		return state, stateRaw, err
	}
	err := runRetentionCheckpoint(options, checkpointBeforeReopen)
	if err != nil {
		return state, stateRaw, err
	}
	if options.Reopen != nil {
		if err = options.Reopen(ctx, state.Source, *state.Active); err != nil {
			return state, stateRaw, fmt.Errorf("nginx access log reopen failed: %w", err)
		}
	}
	if _, err = validateReplacementLog(parent, filepath.Base(paths.active), *state.Active, uid, gid, options.NginxUID, true); err != nil {
		return state, stateRaw, err
	}
	if err = restoreReplacementMetadata(parent, filepath.Base(paths.active), *state.Active, uid, gid, options.NginxUID); err != nil {
		return state, stateRaw, err
	}
	if err = restoreRotatedSourceMetadata(parent, filepath.Base(paths.old), state.Source, uid, gid, options.NginxUID); err != nil {
		return state, stateRaw, err
	}
	if err = runRetentionCheckpoint(options, checkpointAfterReopen); err != nil {
		return state, stateRaw, err
	}
	buffer, err := retainedTail(parent, filepath.Base(paths.old), state.Source, uid, gid)
	if err != nil {
		return state, stateRaw, err
	}
	snapshot, err := installRetainedSnapshot(parent, filepath.Base(paths.snapshot), filepath.Base(paths.snapshotTemp), state.Previous, buffer, uid, gid)
	if err != nil {
		return state, stateRaw, err
	}
	state.Phase, state.Snapshot = retentionSnapshotInstalled, snapshot
	nextRaw, err := publishRetentionState(parent, filepath.Base(paths.state), filepath.Base(paths.stateTemp), stateRaw, state, uid, gid)
	if err != nil {
		return state, stateRaw, err
	}
	if err = runRetentionCheckpoint(options, checkpointSnapshot); err != nil {
		return state, nextRaw, err
	}
	return state, nextRaw, nil
}

func completeRetention(parent int, paths rotationPaths, state retentionState, stateRaw []byte, uid, gid, nginxUID uint32) error {
	if state.Active == nil || state.Snapshot == nil {
		return fmt.Errorf("GoAccess completed retention state is incomplete")
	}
	if _, present, err := restoreActiveLogMetadata(parent, filepath.Base(paths.active), state.Active, uid, gid, nginxUID); err != nil || !present {
		return errors.Join(err, fmt.Errorf("GoAccess completed replacement log is unavailable"))
	}
	snapshot, err := contentIdentityAt(parent, filepath.Base(paths.snapshot), uid, gid, 0o640, maximumAccessLogBytes)
	if err != nil || !sameContentIdentity(snapshot, *state.Snapshot) {
		return errors.Join(err, fmt.Errorf("GoAccess retained snapshot identity changed"))
	}
	if err = requireAbsentAt(parent, filepath.Base(paths.new), filepath.Base(paths.snapshotTemp), filepath.Base(paths.stateTemp)); err != nil {
		return err
	}
	old, present, err := managedStatAt(parent, filepath.Base(paths.old), uid, gid, 0o640)
	if err != nil {
		return err
	}
	if present {
		if !sameInode(old, state.Source) {
			return fmt.Errorf("GoAccess completed retention source identity changed")
		}
		if err = unix.Unlinkat(parent, filepath.Base(paths.old), 0); err != nil {
			return err
		}
		if err = unix.Fsync(parent); err != nil {
			return err
		}
	}
	current, _, present, err := loadRetentionState(parent, filepath.Base(paths.state), uid, gid)
	if err != nil || !present || !bytes.Equal(mustEncodeRetentionState(current), stateRaw) {
		return errors.Join(err, fmt.Errorf("GoAccess retention completion state changed"))
	}
	if err = unix.Unlinkat(parent, filepath.Base(paths.state), 0); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func runRetentionCheckpoint(options retentionOptions, checkpoint retentionCheckpoint) error {
	if options.Checkpoint == nil {
		return nil
	}
	return options.Checkpoint(checkpoint)
}

func createReplacementLog(parent int, name string, uid, gid uint32) (unix.Stat_t, error) {
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o640)
	if err != nil {
		return unix.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return unix.Stat_t{}, fmt.Errorf("wrap replacement GoAccess log")
	}
	if err = unix.Fchown(fd, int(uid), int(gid)); err == nil {
		err = unix.Fchmod(fd, 0o640)
	}
	var stat unix.Stat_t
	if err == nil {
		err = unix.Fstat(fd, &stat)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(err, syncErr, closeErr); err != nil {
		return unix.Stat_t{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != 0o640 || stat.Size != 0 {
		return unix.Stat_t{}, fmt.Errorf("GoAccess replacement log identity unsafe")
	}
	if err = unix.Fsync(parent); err != nil {
		return unix.Stat_t{}, err
	}
	return stat, nil
}

func publishReplacementLog(parent int, paths rotationPaths, source, replacement retentionFileIdentity, uid, gid, nginxUID uint32) error {
	active, activePresent, err := rawStatAt(parent, filepath.Base(paths.active))
	if err != nil {
		return err
	}
	staged, stagedPresent, err := rawStatAt(parent, filepath.Base(paths.new))
	if err != nil {
		return err
	}
	old, oldPresent, err := rawStatAt(parent, filepath.Base(paths.old))
	if err != nil {
		return err
	}
	validSource := func(stat unix.Stat_t) bool {
		ownerOK := stat.Uid == uid || stat.Uid == nginxUID
		return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1 && sameInode(stat, source) && ownerOK && stat.Gid == gid && stat.Mode&0o7777 == 0o640
	}
	validReplacement := func(stat unix.Stat_t) bool {
		ownerOK := stat.Uid == uid || stat.Uid == nginxUID
		return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1 && sameInode(stat, replacement) && ownerOK && stat.Gid == gid && stat.Mode&0o7777 == 0o640
	}
	if oldPresent {
		if !validSource(old) || !activePresent || !validReplacement(active) || stagedPresent {
			return fmt.Errorf("GoAccess replacement publication identity conflicts")
		}
		return nil
	}
	if !activePresent || !stagedPresent {
		return fmt.Errorf("GoAccess replacement publication is incomplete")
	}
	switch {
	case validSource(active) && validReplacement(staged):
		if err = unix.Renameat2(parent, filepath.Base(paths.active), parent, filepath.Base(paths.new), unix.RENAME_EXCHANGE); err != nil {
			return err
		}
		if err = unix.Fsync(parent); err != nil {
			return err
		}
	case validReplacement(active) && validSource(staged):
	default:
		return fmt.Errorf("GoAccess replacement exchange identity changed")
	}
	if err = unix.Renameat2(parent, filepath.Base(paths.new), parent, filepath.Base(paths.old), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func finishInterruptedReplacement(parent int, name string, observed unix.Stat_t, source retentionFileIdentity, uid, gid uint32) (unix.Stat_t, error) {
	ownerOK := observed.Uid == uid || observed.Uid == uint32(os.Geteuid())
	groupOK := observed.Gid == gid || observed.Gid == uint32(os.Getegid())
	mode := observed.Mode & 0o7777
	if observed.Mode&unix.S_IFMT != unix.S_IFREG || observed.Nlink != 1 || sameInode(observed, source) || observed.Size != 0 || !ownerOK || !groupOK || mode != 0o600 && mode != 0o640 {
		return unix.Stat_t{}, fmt.Errorf("GoAccess replacement log is not an exact interrupted creation")
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return unix.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return unix.Stat_t{}, fmt.Errorf("wrap interrupted replacement GoAccess log")
	}
	var current unix.Stat_t
	if err = unix.Fstat(fd, &current); err != nil || current.Dev != observed.Dev || current.Ino != observed.Ino || current.Size != 0 {
		_ = file.Close()
		return unix.Stat_t{}, errors.Join(err, fmt.Errorf("interrupted replacement GoAccess log changed"))
	}
	if err = unix.Fchown(fd, int(uid), int(gid)); err == nil {
		err = unix.Fchmod(fd, 0o640)
	}
	if err == nil {
		err = unix.Fstat(fd, &current)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(err, syncErr, closeErr); err != nil {
		return unix.Stat_t{}, err
	}
	if err = validateManagedStat(current, uid, gid, 0o640); err != nil {
		return unix.Stat_t{}, err
	}
	if err = unix.Fsync(parent); err != nil {
		return unix.Stat_t{}, err
	}
	return current, nil
}

func validateReplacementLog(parent int, name string, expected retentionFileIdentity, uid, gid, nginxUID uint32, allowNginxOwner bool) (unix.Stat_t, error) {
	stat, present, err := rawStatAt(parent, name)
	ownerOK := stat.Uid == uid || allowNginxOwner && stat.Uid == nginxUID
	if err != nil || !present || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || !sameInode(stat, expected) || !ownerOK || stat.Gid != gid || stat.Mode&0o7777 != 0o640 {
		return unix.Stat_t{}, errors.Join(err, fmt.Errorf("GoAccess replacement log identity changed"))
	}
	return stat, nil
}

func restoreActiveLogMetadata(parent int, name string, expected *retentionFileIdentity, uid, gid, nginxUID uint32) (unix.Stat_t, bool, error) {
	stat, present, err := rawStatAt(parent, name)
	if err != nil || !present {
		return stat, present, err
	}
	ownerOK := stat.Uid == uid || stat.Uid == nginxUID
	identityOK := expected == nil || sameInode(stat, *expected)
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || !identityOK || !ownerOK || stat.Gid != gid || stat.Mode&0o7777 != 0o640 || stat.Size < 0 {
		return unix.Stat_t{}, true, fmt.Errorf("GoAccess active log identity unsafe")
	}
	if stat.Uid != uid {
		identity := inodeIdentity(stat)
		if err = restoreReplacementMetadata(parent, name, identity, uid, gid, nginxUID); err != nil {
			return unix.Stat_t{}, true, err
		}
		stat, present, err = rawStatAt(parent, name)
		if err != nil || !present || validateManagedStat(stat, uid, gid, 0o640) != nil || !sameInode(stat, identity) {
			return unix.Stat_t{}, present, errors.Join(err, fmt.Errorf("GoAccess active log metadata restoration changed identity"))
		}
	}
	return stat, true, nil
}

func restoreRotatedSourceMetadata(parent int, name string, expected retentionFileIdentity, uid, gid, nginxUID uint32) error {
	stat, present, err := rawStatAt(parent, name)
	ownerOK := stat.Uid == uid || stat.Uid == nginxUID
	if err != nil || !present || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || !sameInode(stat, expected) || !ownerOK || stat.Gid != gid || stat.Mode&0o7777 != 0o640 {
		return errors.Join(err, fmt.Errorf("GoAccess rotated source identity changed"))
	}
	return restoreReplacementMetadata(parent, name, expected, uid, gid, nginxUID)
}

func restoreReplacementMetadata(parent int, name string, expected retentionFileIdentity, uid, gid, nginxUID uint32) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("wrap reopened GoAccess log")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || !sameInode(stat, expected) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid && stat.Uid != nginxUID || stat.Gid != gid || stat.Mode&0o7777 != 0o640 {
		_ = file.Close()
		return errors.Join(err, fmt.Errorf("GoAccess reopened log identity changed"))
	}
	if err = unix.Fchown(fd, int(uid), int(gid)); err == nil {
		err = unix.Fchmod(fd, 0o640)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(err, syncErr, closeErr)
}

func retainedTail(parent int, name string, expected retentionFileIdentity, uid, gid uint32) ([]byte, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap renamed GoAccess log")
	}
	defer func() { _ = file.Close() }()
	var before, after unix.Stat_t
	if err = unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uid || before.Gid != gid || before.Mode&0o7777 != 0o640 || !sameInode(before, expected) || before.Size < 0 {
		return nil, errors.Join(err, fmt.Errorf("GoAccess renamed log identity unsafe"))
	}
	if err = file.Sync(); err != nil {
		return nil, err
	}
	size := min(before.Size, maximumAccessLogBytes)
	data := make([]byte, size)
	if size != 0 {
		n, readErr := file.ReadAt(data, before.Size-size)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, readErr
		}
		if int64(n) != size {
			return nil, fmt.Errorf("GoAccess renamed log tail changed while read")
		}
	}
	if err = unix.Fstat(fd, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		return nil, errors.Join(err, fmt.Errorf("GoAccess renamed log changed after reopen completion"))
	}
	return data, nil
}

func installRetainedSnapshot(parent int, snapshotName, tempName string, previous *retentionFileIdentity, expected []byte, uid, gid uint32) (*retentionFileIdentity, error) {
	current, currentErr := optionalContentIdentity(parent, snapshotName, uid, gid, 0o640, maximumAccessLogBytes)
	if currentErr != nil {
		return nil, currentErr
	}
	expectedDigest := digest(expected)
	currentExpected := current != nil && current.Size == int64(len(expected)) && current.Digest == expectedDigest
	currentPrevious := previous != nil && current != nil && sameContentIdentity(*current, *previous)
	if previous == nil && current != nil && !currentExpected || previous != nil && !currentPrevious && !currentExpected {
		return nil, fmt.Errorf("GoAccess prior retained snapshot changed")
	}
	if currentExpected && (previous == nil || !sameInodeIdentity(*current, *previous)) {
		if err := requireAbsentAt(parent, tempName); err != nil {
			return nil, err
		}
		return current, nil
	}
	if err := writeSnapshotTemp(parent, tempName, expected, uid, gid); err != nil {
		return nil, err
	}
	fresh, err := optionalContentIdentity(parent, snapshotName, uid, gid, 0o640, maximumAccessLogBytes)
	if err != nil {
		return nil, err
	}
	if previous == nil && fresh != nil || previous != nil && (fresh == nil || !sameContentIdentity(*fresh, *previous)) {
		return nil, fmt.Errorf("GoAccess retained snapshot changed before replacement")
	}
	if err = unix.Renameat(parent, tempName, parent, snapshotName); err != nil {
		return nil, err
	}
	if err = unix.Fsync(parent); err != nil {
		return nil, err
	}
	installed, err := contentIdentityAt(parent, snapshotName, uid, gid, 0o640, maximumAccessLogBytes)
	if err != nil || installed.Size != int64(len(expected)) || installed.Digest != expectedDigest {
		return nil, errors.Join(err, fmt.Errorf("GoAccess retained snapshot replacement changed"))
	}
	return &installed, nil
}

func writeSnapshotTemp(parent int, name string, expected []byte, uid, gid uint32) error {
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parent, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("wrap retained snapshot staging file")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid && stat.Uid != uint32(os.Geteuid()) || stat.Gid != gid && stat.Gid != uint32(os.Getegid()) || stat.Mode&0o7777 != 0o600 && stat.Mode&0o7777 != 0o640 || stat.Size < 0 || stat.Size > int64(len(expected)) {
		_ = file.Close()
		return errors.Join(err, fmt.Errorf("GoAccess retained snapshot staging identity unsafe"))
	}
	if stat.Uid != uid || stat.Gid != gid {
		if err = unix.Fchown(fd, int(uid), int(gid)); err != nil {
			_ = file.Close()
			return err
		}
	}
	prefix := make([]byte, stat.Size)
	if len(prefix) != 0 {
		n, readErr := file.ReadAt(prefix, 0)
		if readErr != nil && !errors.Is(readErr, io.EOF) || n != len(prefix) || !bytes.Equal(prefix, expected[:len(prefix)]) {
			_ = file.Close()
			return errors.Join(readErr, fmt.Errorf("GoAccess retained snapshot staging is unknown"))
		}
	}
	if _, err = file.WriteAt(expected[stat.Size:], stat.Size); err == nil {
		err = file.Truncate(int64(len(expected)))
	}
	if err == nil {
		err = unix.Fchmod(fd, 0o640)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(err, syncErr, closeErr)
}

func publishRetentionState(parent int, name, tempName string, priorRaw []byte, state retentionState, uid, gid uint32) ([]byte, error) {
	raw := mustEncodeRetentionState(state)
	if len(raw) == 0 || len(raw) > maximumRetentionState {
		return nil, fmt.Errorf("GoAccess retention state encoding is invalid")
	}
	current, currentRaw, present, err := loadRetentionState(parent, name, uid, gid)
	if err != nil {
		return nil, err
	}
	_ = current
	if priorRaw == nil && present || priorRaw != nil && (!present || !bytes.Equal(currentRaw, priorRaw)) {
		return nil, fmt.Errorf("GoAccess retention state changed before publication")
	}
	fd, err := unix.Openat(parent, tempName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parent, tempName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), tempName)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap GoAccess retention state staging")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid && stat.Uid != uint32(os.Geteuid()) || stat.Gid != gid && stat.Gid != uint32(os.Getegid()) || stat.Mode&0o7777 != 0o600 || stat.Size < 0 || stat.Size > int64(len(raw)) {
		_ = file.Close()
		return nil, errors.Join(err, fmt.Errorf("GoAccess retention state staging identity unsafe"))
	}
	if stat.Uid != uid || stat.Gid != gid {
		if err = unix.Fchown(fd, int(uid), int(gid)); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	prefix := make([]byte, stat.Size)
	if len(prefix) != 0 {
		n, readErr := file.ReadAt(prefix, 0)
		if readErr != nil && !errors.Is(readErr, io.EOF) || n != len(prefix) || !bytes.Equal(prefix, raw[:len(prefix)]) {
			_ = file.Close()
			return nil, errors.Join(readErr, fmt.Errorf("GoAccess retention state staging is unknown"))
		}
	}
	if _, err = file.WriteAt(raw[stat.Size:], stat.Size); err == nil {
		err = file.Truncate(int64(len(raw)))
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(err, syncErr, closeErr); err != nil {
		return nil, err
	}
	_, currentRaw, present, err = loadRetentionState(parent, name, uid, gid)
	if err != nil || priorRaw == nil && present || priorRaw != nil && (!present || !bytes.Equal(currentRaw, priorRaw)) {
		return nil, errors.Join(err, fmt.Errorf("GoAccess retention state changed during publication"))
	}
	if priorRaw == nil {
		err = unix.Renameat2(parent, tempName, parent, name, unix.RENAME_NOREPLACE)
	} else {
		err = unix.Renameat(parent, tempName, parent, name)
	}
	if err != nil {
		return nil, err
	}
	if err = unix.Fsync(parent); err != nil {
		return nil, err
	}
	return raw, nil
}

func loadRetentionState(parent int, name string, uid, gid uint32) (retentionState, []byte, bool, error) {
	identity, raw, present, err := readManagedFileAt(parent, name, uid, gid, []uint32{0o600}, maximumRetentionState)
	_ = identity
	if err != nil || !present {
		return retentionState{}, nil, present, err
	}
	var state retentionState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&state); err != nil {
		return retentionState{}, nil, true, fmt.Errorf("GoAccess retention state is invalid")
	}
	canonical := mustEncodeRetentionState(state)
	if !bytes.Equal(canonical, raw) || validateRetentionState(state) != nil {
		return retentionState{}, nil, true, fmt.Errorf("GoAccess retention state is noncanonical")
	}
	return state, raw, true, nil
}

func validateRetentionState(state retentionState) error {
	validInode := func(value retentionFileIdentity) bool {
		return value.Device != 0 && value.Inode != 0 && value.Size == 0 && value.Digest == ""
	}
	validContent := func(value *retentionFileIdentity) bool {
		return value != nil && value.Device != 0 && value.Inode != 0 && value.Size >= 0 && value.Size <= maximumAccessLogBytes && len(value.Digest) == 71 && len(value.Digest) > 7 && value.Digest[:7] == "sha256:"
	}
	if state.SchemaVersion != retentionStateSchema || !validInode(state.Source) || state.Previous != nil && !validContent(state.Previous) {
		return fmt.Errorf("retention state authority invalid")
	}
	switch state.Phase {
	case retentionPrepared:
		if state.Active != nil || state.Snapshot != nil {
			return fmt.Errorf("prepared retention state is invalid")
		}
	case retentionReady:
		if state.Active == nil || !validInode(*state.Active) || state.Snapshot != nil || *state.Active == state.Source {
			return fmt.Errorf("ready retention state is invalid")
		}
	case retentionSnapshotInstalled:
		if state.Active == nil || !validInode(*state.Active) || !validContent(state.Snapshot) || *state.Active == state.Source {
			return fmt.Errorf("completed retention state is invalid")
		}
	default:
		return fmt.Errorf("retention state phase invalid")
	}
	return nil
}

func mustEncodeRetentionState(state retentionState) []byte {
	raw, err := json.Marshal(state)
	if err != nil {
		return nil
	}
	return raw
}

func optionalContentIdentity(parent int, name string, uid, gid, mode uint32, maximum int64) (*retentionFileIdentity, error) {
	identity, _, present, err := readManagedFileAt(parent, name, uid, gid, []uint32{mode}, maximum)
	if err != nil || !present {
		return nil, err
	}
	return &identity, nil
}

func contentIdentityAt(parent int, name string, uid, gid, mode uint32, maximum int64) (retentionFileIdentity, error) {
	identity, _, present, err := readManagedFileAt(parent, name, uid, gid, []uint32{mode}, maximum)
	if err != nil {
		return retentionFileIdentity{}, err
	}
	if !present {
		return retentionFileIdentity{}, os.ErrNotExist
	}
	return identity, nil
}

func readManagedFileAt(parent int, name string, uid, gid uint32, modes []uint32, maximum int64) (retentionFileIdentity, []byte, bool, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return retentionFileIdentity{}, nil, false, nil
	}
	if err != nil {
		return retentionFileIdentity{}, nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return retentionFileIdentity{}, nil, true, fmt.Errorf("wrap managed GoAccess file")
	}
	var before, after unix.Stat_t
	modeOK := false
	if err = unix.Fstat(fd, &before); err == nil {
		for _, mode := range modes {
			modeOK = modeOK || before.Mode&0o7777 == mode
		}
	}
	if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uid || before.Gid != gid || !modeOK || before.Size < 0 || before.Size > maximum {
		_ = file.Close()
		return retentionFileIdentity{}, nil, true, errors.Join(err, fmt.Errorf("GoAccess managed retention file identity unsafe"))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || int64(len(data)) != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		return retentionFileIdentity{}, nil, true, errors.Join(readErr, statErr, closeErr, fmt.Errorf("GoAccess managed retention file changed while read"))
	}
	return retentionFileIdentity{Device: uint64(before.Dev), Inode: before.Ino, Size: before.Size, Digest: digest(data)}, data, true, nil
}

func managedStatAt(parent int, name string, uid, gid, mode uint32) (unix.Stat_t, bool, error) {
	stat, present, err := rawStatAt(parent, name)
	if err != nil || !present {
		return stat, present, err
	}
	if err = validateManagedStat(stat, uid, gid, mode); err != nil {
		return unix.Stat_t{}, true, err
	}
	return stat, true, nil
}

func validateManagedStat(stat unix.Stat_t, uid, gid, mode uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode || stat.Size < 0 {
		return fmt.Errorf("GoAccess log identity unsafe")
	}
	return nil
}

func rawStatAt(parent int, name string) (unix.Stat_t, bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return unix.Stat_t{}, false, nil
	}
	return stat, err == nil, err
}

func rejectUnboundResidue(parent int, paths rotationPaths) error {
	return requireAbsentAt(parent, filepath.Base(paths.old), filepath.Base(paths.new), filepath.Base(paths.stateTemp), filepath.Base(paths.snapshotTemp))
}

// verifyRetentionStateSettled is the deletion fence for the recovery unit.
// Timer/service quiescence is proved through exact systemd inventory; this
// separately proves that no journal or renamed/staging artifact still needs
// that unit for recovery.
func verifyRetentionStateSettled(ctx context.Context, paths Paths) error {
	artifacts := []string{paths.RetentionOld, paths.RetentionNew, paths.RetentionState, paths.RetentionStateTemp, paths.RetentionTemp}
	for _, path := range artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("GoAccess retention settlement authority invalid")
		}
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("GoAccess retention recovery artifact remained: %s", filepath.Base(path))
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func requireAbsentAt(parent int, names ...string) error {
	for _, name := range names {
		_, present, err := rawStatAt(parent, name)
		if err != nil {
			return err
		}
		if present {
			return fmt.Errorf("GoAccess retention found unbound artifact %q", name)
		}
	}
	return nil
}

func inodeIdentity(stat unix.Stat_t) retentionFileIdentity {
	return retentionFileIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}
}

func sameInode(stat unix.Stat_t, identity retentionFileIdentity) bool {
	return uint64(stat.Dev) == identity.Device && stat.Ino == identity.Inode
}

func sameInodeIdentity(left, right retentionFileIdentity) bool {
	return left.Device == right.Device && left.Inode == right.Inode
}

func sameContentIdentity(left, right retentionFileIdentity) bool {
	return sameInodeIdentity(left, right) && left.Size == right.Size && left.Digest == right.Digest
}
