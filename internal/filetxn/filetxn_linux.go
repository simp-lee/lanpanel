//go:build linux

// Package filetxn provides bounded, no-follow, same-mount transactions for
// LanPanel-owned regular files.
package filetxn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type Owner struct{ UID, GID uint32 }

type Metadata struct {
	Owner Owner
	Mode  fs.FileMode
}

type DirectoryPolicy struct {
	AllowedOwners []Owner
	AllowedMode   fs.FileMode
}

type Config struct {
	RootPath       string
	Root           Metadata
	StagingPath    string
	Staging        Metadata
	StagingParents DirectoryPolicy
}

const MaximumContentBytes int64 = 16 << 20

type Request struct {
	Path     string
	Parents  DirectoryPolicy
	Existing *Metadata
	New      Metadata
	MaxBytes int64
}

type Disposition string

const (
	CreateOnly      Disposition = "create_only"
	ReplaceOnly     Disposition = "replace_only"
	CreateOrReplace Disposition = "create_or_replace"
)

type State string

const (
	// StateUnchanged means the target namespace was not changed.
	StateUnchanged State = "unchanged"
	// StateStaged means the target is unchanged and StagingPath identifies an inert object.
	StateStaged State = "staged"
	// StateNamespaceChanged means the atomic namespace mutation happened but its
	// directory entries have not all been synchronized.
	StateNamespaceChanged State = "namespace_changed"
	// StateDurable means the target namespace mutation and both participating
	// directories were synchronized. A cleanup tombstone may still be present.
	StateDurable State = "durable"
	// StateIndeterminate requires reconciliation from the returned paths and local observation.
	StateIndeterminate State = "indeterminate"
)

type Point string

const (
	PointAfterCreate         Point = "after_create"
	PointAfterStagingSync    Point = "after_staging_sync"
	PointBeforeWrite         Point = "before_write"
	PointAfterWrite          Point = "after_write"
	PointBeforeMetadata      Point = "before_metadata"
	PointAfterMetadata       Point = "after_metadata"
	PointBeforeFileSync      Point = "before_file_sync"
	PointAfterFileSync       Point = "after_file_sync"
	PointAfterVerify         Point = "after_verify"
	PointBeforeRename        Point = "before_rename"
	PointAfterRename         Point = "after_rename"
	PointBeforeDirectorySync Point = "before_directory_sync"
	PointAfterDirectorySync  Point = "after_directory_sync"
	PointBeforeCleanup       Point = "before_cleanup"
	PointAfterCleanup        Point = "after_cleanup"
)

// FaultFunc injects an operation failure at Before points or an interruption
// immediately after the completed boundary named by an After point.
type FaultFunc func(Point) error

type Options struct{ Fault FaultFunc }

type Result struct {
	TargetPath  string `json:"target_path"`
	StagingPath string `json:"staging_path,omitempty"`
	State       State  `json:"state"`
}

type Error struct {
	Point  Point
	Result Result
	Err    error
}

func (err *Error) Error() string {
	if err.Point == "" {
		return err.Err.Error()
	}
	return fmt.Sprintf("file transaction at %s: %v", err.Point, err.Err)
}
func (err *Error) Unwrap() error { return err.Err }

type Store struct {
	mu              sync.RWMutex
	rootPath        string
	rootFD          int
	rootStat        unix.Stat_t
	rootExpected    Metadata
	stagingPath     string
	stagingFD       int
	stagingStat     unix.Stat_t
	stagingExpected Metadata
	stagingParents  DirectoryPolicy
	fault           FaultFunc
	closed          bool
}

func Open(config Config, options Options) (*Store, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	rootFD, rootStat, err := openAbsoluteDirectory(config.RootPath)
	if err != nil {
		return nil, fmt.Errorf("open transaction root %s: %w", config.RootPath, err)
	}
	if err := validateDirectoryMetadata(rootStat, config.Root); err != nil {
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("transaction root %s: %w", config.RootPath, err)
	}
	stagingRelative, err := descendantRelative(config.RootPath, config.StagingPath)
	if err != nil || stagingRelative == "." {
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("staging path must be a descendant of the transaction root")
	}
	stagingFD, stagingStat, err := openDirectoryTreeAllowMounts(rootFD, stagingRelative, config.StagingParents)
	if err != nil {
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("open staging directory %s: %w", config.StagingPath, err)
	}
	if err := validateDirectoryMetadata(stagingStat, config.Staging); err != nil {
		_ = unix.Close(stagingFD)
		_ = unix.Close(rootFD)
		return nil, fmt.Errorf("staging directory %s: %w", config.StagingPath, err)
	}
	return &Store{
		rootPath: config.RootPath, rootFD: rootFD, rootStat: rootStat, rootExpected: config.Root,
		stagingPath: config.StagingPath, stagingFD: stagingFD, stagingStat: stagingStat, stagingExpected: config.Staging,
		stagingParents: DirectoryPolicy{AllowedOwners: append([]Owner(nil), config.StagingParents.AllowedOwners...), AllowedMode: config.StagingParents.AllowedMode},
		fault:          options.Fault,
	}, nil
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	stagingErr := unix.Close(store.stagingFD)
	rootErr := unix.Close(store.rootFD)
	return errors.Join(stagingErr, rootErr)
}

func (store *Store) Put(ctx context.Context, request Request, data []byte, disposition Disposition) (Result, error) {
	result := Result{TargetPath: request.Path, State: StateUnchanged}
	if err := validatePutRequest(request, data, disposition); err != nil {
		return result, txError("", result, err)
	}
	data = bytes.Clone(data)
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return result, txError("", result, fmt.Errorf("file transaction store is closed"))
	}
	if err := store.revalidateProtectedPaths(); err != nil {
		return result, txError("", result, err)
	}
	parentFD, base, err := store.openParent(request.Path, request.Parents)
	if err != nil {
		return result, txError("", result, err)
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return result, txError("", result, err)
	}
	existing, exists, err := inspectTarget(parentFD, base, uint64(parentStat.Dev), request.Existing)
	if err != nil {
		return result, txError("", result, err)
	}
	if err := validateDisposition(disposition, exists); err != nil {
		return result, txError("", result, err)
	}

	name, fd, err := createStaging(store.stagingFD, base, ".lanpanel-txn.")
	if err != nil {
		return result, txError(PointAfterCreate, result, err)
	}
	result.StagingPath = filepath.Join(store.stagingPath, name)
	result.State = StateStaged
	open := true
	defer func() {
		if open {
			_ = unix.Close(fd)
		}
	}()
	if err := store.check(ctx, PointAfterCreate); err != nil {
		return result, txError(PointAfterCreate, result, err)
	}
	if err := unix.Fsync(store.stagingFD); err != nil {
		return result, txError(PointAfterStagingSync, result, fmt.Errorf("sync staging directory: %w", err))
	}
	if err := store.check(ctx, PointAfterStagingSync); err != nil {
		return result, txError(PointAfterStagingSync, result, err)
	}
	if err := store.check(ctx, PointBeforeWrite); err != nil {
		return result, txError(PointBeforeWrite, result, err)
	}
	if err := writeAll(fd, data); err != nil {
		return result, txError(PointAfterWrite, result, err)
	}
	if err := store.check(ctx, PointAfterWrite); err != nil {
		return result, txError(PointAfterWrite, result, err)
	}
	if err := store.check(ctx, PointBeforeMetadata); err != nil {
		return result, txError(PointBeforeMetadata, result, err)
	}
	if err := applyMetadata(fd, request.New); err != nil {
		return result, txError(PointAfterMetadata, result, err)
	}
	if err := store.check(ctx, PointAfterMetadata); err != nil {
		return result, txError(PointAfterMetadata, result, err)
	}
	if err := store.check(ctx, PointBeforeFileSync); err != nil {
		return result, txError(PointBeforeFileSync, result, err)
	}
	if err := unix.Fsync(fd); err != nil {
		return result, txError(PointAfterFileSync, result, fmt.Errorf("sync staging file: %w", err))
	}
	if err := store.check(ctx, PointAfterFileSync); err != nil {
		return result, txError(PointAfterFileSync, result, err)
	}
	if err := unix.Close(fd); err != nil {
		open = false
		return result, txError(PointAfterFileSync, result, fmt.Errorf("close staging file: %w", err))
	}
	open = false
	staging, err := verifyFile(store.stagingFD, name, uint64(store.stagingStat.Dev), request.New, request.MaxBytes, data)
	if err != nil {
		return result, txError(PointAfterVerify, result, err)
	}
	if err := store.check(ctx, PointAfterVerify); err != nil {
		return result, txError(PointAfterVerify, result, err)
	}
	if err := store.check(ctx, PointBeforeRename); err != nil {
		return result, txError(PointBeforeRename, result, err)
	}
	if err := revalidateTarget(parentFD, base, existing, exists); err != nil {
		return result, txError(PointBeforeRename, result, err)
	}
	if err := revalidateIdentity(store.stagingFD, name, staging); err != nil {
		return result, txError(PointBeforeRename, result, fmt.Errorf("staging identity changed: %w", err))
	}
	if uint64(parentStat.Dev) != uint64(store.stagingStat.Dev) {
		return result, txError(PointBeforeRename, result, fmt.Errorf("target and staging directories are on different filesystems"))
	}

	afterRename := func() error { return store.check(ctx, PointAfterRename) }
	rollbackSync := func() error {
		if err := store.check(ctx, PointBeforeDirectorySync); err != nil {
			return err
		}
		return syncDirectories(parentFD, store.stagingFD)
	}
	var mutationErr error
	if exists {
		result.State, mutationErr = exchangeReplacement(store.stagingFD, name, parentFD, base, staging, existing, request.New, request.MaxBytes, data, afterRename, rollbackSync)
	} else {
		result.State, mutationErr = commitCreate(store.stagingFD, name, parentFD, base, staging, request.New, request.MaxBytes, data, afterRename, rollbackSync)
	}
	if mutationErr != nil {
		return result, txError(PointAfterRename, result, mutationErr)
	}
	if err := store.check(ctx, PointBeforeDirectorySync); err != nil {
		return result, txError(PointBeforeDirectorySync, result, err)
	}
	if err := syncDirectories(parentFD, store.stagingFD); err != nil {
		return result, txError(PointAfterDirectorySync, result, err)
	}
	result.State = StateDurable
	if err := store.check(ctx, PointAfterDirectorySync); err != nil {
		return result, txError(PointAfterDirectorySync, result, err)
	}
	if exists {
		if err := store.check(ctx, PointBeforeCleanup); err != nil {
			return result, txError(PointBeforeCleanup, result, err)
		}
		if err := unix.Unlinkat(store.stagingFD, name, 0); err != nil {
			return result, txError(PointAfterCleanup, result, fmt.Errorf("remove replacement tombstone: %w", err))
		}
		if err := store.check(ctx, PointAfterCleanup); err != nil {
			return result, txError(PointAfterCleanup, result, err)
		}
		if err := unix.Fsync(store.stagingFD); err != nil {
			return result, txError(PointAfterCleanup, result, fmt.Errorf("sync tombstone cleanup: %w", err))
		}
	}
	return result, nil
}

func (store *Store) Read(ctx context.Context, request Request) ([]byte, error) {
	if request.Existing == nil || request.Path == "" || request.MaxBytes <= 0 || request.MaxBytes > MaximumContentBytes || validateMetadata(*request.Existing) != nil || validateDirectoryPolicy(request.Parents) != nil {
		return nil, fmt.Errorf("file transaction read request is invalid")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return nil, fmt.Errorf("file transaction store is closed")
	}
	if err := store.revalidateProtectedPaths(); err != nil {
		return nil, err
	}
	parentFD, base, err := store.openParent(request.Path, request.Parents)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return nil, err
	}
	before, exists, err := inspectTarget(parentFD, base, uint64(parentStat.Dev), request.Existing)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fs.ErrNotExist
	}
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("file transaction read descriptor is invalid")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, request.MaxBytes+1))
	if err != nil || int64(len(data)) > request.MaxBytes {
		return nil, fmt.Errorf("file transaction read is unavailable or oversized")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || compareIdentity(after, before) != nil || after.Size != int64(len(data)) || after.Mtim != before.Mtim {
		return nil, fmt.Errorf("file transaction target changed while reading")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func (store *Store) Remove(ctx context.Context, request Request) (Result, error) {
	result := Result{TargetPath: request.Path, State: StateUnchanged}
	if err := validateRemoveRequest(request); err != nil {
		return result, txError("", result, err)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return result, txError("", result, fmt.Errorf("file transaction store is closed"))
	}
	if err := store.revalidateProtectedPaths(); err != nil {
		return result, txError("", result, err)
	}
	parentFD, base, err := store.openParent(request.Path, request.Parents)
	if err != nil {
		return result, txError("", result, err)
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return result, txError("", result, err)
	}
	existing, exists, err := inspectTarget(parentFD, base, uint64(parentStat.Dev), request.Existing)
	if err != nil {
		return result, txError("", result, err)
	}
	if !exists {
		return result, txError("", result, fs.ErrNotExist)
	}
	name, err := unusedStagingName(store.stagingFD, base, ".lanpanel-remove.")
	if err != nil {
		return result, txError(PointBeforeRename, result, err)
	}
	result.StagingPath = filepath.Join(store.stagingPath, name)
	if err := store.check(ctx, PointBeforeRename); err != nil {
		return result, txError(PointBeforeRename, result, err)
	}
	if err := revalidateTarget(parentFD, base, existing, true); err != nil {
		return result, txError(PointBeforeRename, result, err)
	}
	result.State, err = commitRemove(parentFD, base, store.stagingFD, name, existing,
		func() error { return store.check(ctx, PointAfterRename) },
	)
	if err != nil {
		return result, txError(PointAfterRename, result, err)
	}
	if err := store.check(ctx, PointBeforeDirectorySync); err != nil {
		return result, txError(PointBeforeDirectorySync, result, err)
	}
	if err := syncDirectories(parentFD, store.stagingFD); err != nil {
		return result, txError(PointAfterDirectorySync, result, err)
	}
	result.State = StateDurable
	if err := store.check(ctx, PointAfterDirectorySync); err != nil {
		return result, txError(PointAfterDirectorySync, result, err)
	}
	if err := store.check(ctx, PointBeforeCleanup); err != nil {
		return result, txError(PointBeforeCleanup, result, err)
	}
	if err := unix.Unlinkat(store.stagingFD, name, 0); err != nil {
		return result, txError(PointAfterCleanup, result, fmt.Errorf("remove tombstone: %w", err))
	}
	if err := store.check(ctx, PointAfterCleanup); err != nil {
		return result, txError(PointAfterCleanup, result, err)
	}
	if err := unix.Fsync(store.stagingFD); err != nil {
		return result, txError(PointAfterCleanup, result, fmt.Errorf("sync tombstone cleanup: %w", err))
	}
	return result, nil
}

func (store *Store) check(ctx context.Context, point Point) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.fault != nil {
		return store.fault(point)
	}
	return nil
}

func (store *Store) revalidateProtectedPaths() error {
	var cachedRoot unix.Stat_t
	if err := unix.Fstat(store.rootFD, &cachedRoot); err != nil {
		return fmt.Errorf("revalidate open transaction root: %w", err)
	}
	if err := validateDirectoryMetadata(cachedRoot, store.rootExpected); err != nil {
		return fmt.Errorf("open transaction root metadata changed: %w", err)
	}
	if !sameDirectory(cachedRoot, store.rootStat) {
		return fmt.Errorf("open transaction root identity changed")
	}
	var cachedStaging unix.Stat_t
	if err := unix.Fstat(store.stagingFD, &cachedStaging); err != nil {
		return fmt.Errorf("revalidate open staging directory: %w", err)
	}
	if err := validateDirectoryMetadata(cachedStaging, store.stagingExpected); err != nil {
		return fmt.Errorf("open staging directory metadata changed: %w", err)
	}
	if !sameDirectory(cachedStaging, store.stagingStat) {
		return fmt.Errorf("open staging directory identity changed")
	}

	freshRootFD, freshRoot, err := openAbsoluteDirectory(store.rootPath)
	if err != nil {
		return fmt.Errorf("reopen transaction root: %w", err)
	}
	defer unix.Close(freshRootFD)
	if err := validateDirectoryMetadata(freshRoot, store.rootExpected); err != nil {
		return fmt.Errorf("configured transaction root metadata changed: %w", err)
	}
	if !sameDirectory(freshRoot, store.rootStat) {
		return fmt.Errorf("configured transaction root identity changed")
	}
	stagingRelative, err := descendantRelative(store.rootPath, store.stagingPath)
	if err != nil {
		return fmt.Errorf("revalidate staging path: %w", err)
	}
	freshStagingFD, freshStaging, err := openDirectoryTreeAllowMounts(freshRootFD, stagingRelative, store.stagingParents)
	if err != nil {
		return fmt.Errorf("reopen staging directory: %w", err)
	}
	defer unix.Close(freshStagingFD)
	if err := validateDirectoryMetadata(freshStaging, store.stagingExpected); err != nil {
		return fmt.Errorf("configured staging directory metadata changed: %w", err)
	}
	if !sameDirectory(freshStaging, store.stagingStat) {
		return fmt.Errorf("configured staging directory identity changed")
	}
	return nil
}

func sameDirectory(actual, expected unix.Stat_t) bool {
	return uint64(actual.Dev) == uint64(expected.Dev) && actual.Ino == expected.Ino && actual.Mode&unix.S_IFMT == unix.S_IFDIR && actual.Uid == expected.Uid && actual.Gid == expected.Gid && actual.Mode&0o7777 == expected.Mode&0o7777
}

func (store *Store) openParent(target string, policy DirectoryPolicy) (int, string, error) {
	if err := validateAbsolutePath(target); err != nil {
		return -1, "", err
	}
	if err := validateDirectoryPolicy(policy); err != nil {
		return -1, "", err
	}
	relative, err := descendantRelative(store.rootPath, target)
	if err != nil || relative == "." {
		return -1, "", fmt.Errorf("target path %s is outside transaction root %s", target, store.rootPath)
	}
	base := filepath.Base(relative)
	parentRelative := filepath.Dir(relative)
	if err := validateDirectoryStat(store.rootStat, policy); err != nil {
		return -1, "", fmt.Errorf("transaction root parent policy: %w", err)
	}
	fd, err := unix.Dup(store.rootFD)
	if err != nil {
		return -1, "", err
	}
	unix.CloseOnExec(fd)
	if parentRelative == "." {
		return fd, base, nil
	}
	for component := range strings.SplitSeq(parentRelative, string(filepath.Separator)) {
		next, openErr := openComponent(fd, component)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, "", fmt.Errorf("open parent component %s: %w", component, openErr)
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}
		if err := validateDirectoryStat(stat, policy); err != nil {
			_ = unix.Close(fd)
			return -1, "", fmt.Errorf("parent component %s: %w", component, err)
		}
	}
	return fd, base, nil
}

func openAbsoluteDirectory(path string) (int, unix.Stat_t, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	if path != "/" {
		for component := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
			next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			_ = unix.Close(fd)
			if openErr != nil {
				return -1, unix.Stat_t{}, openErr
			}
			fd = next
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	return fd, stat, nil
}

func openDirectoryTreeAllowMounts(rootFD int, relative string, policy DirectoryPolicy) (int, unix.Stat_t, error) {
	fd, err := unix.Dup(rootFD)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	unix.CloseOnExec(fd)
	var stat unix.Stat_t
	for component := range strings.SplitSeq(relative, string(filepath.Separator)) {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, unix.Stat_t{}, openErr
		}
		fd = next
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return -1, unix.Stat_t{}, err
		}
		if err := validateDirectoryStat(stat, policy); err != nil {
			_ = unix.Close(fd)
			return -1, unix.Stat_t{}, err
		}
	}
	return fd, stat, nil
}

func openDirectoryTree(rootFD int, rootStat unix.Stat_t, relative string, policy DirectoryPolicy) (int, unix.Stat_t, error) {
	if err := validateDirectoryStat(rootStat, policy); err != nil {
		return -1, unix.Stat_t{}, fmt.Errorf("root: %w", err)
	}
	fd, err := unix.Dup(rootFD)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	unix.CloseOnExec(fd)
	stat := rootStat
	for component := range strings.SplitSeq(relative, string(filepath.Separator)) {
		next, openErr := openComponent(fd, component)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, unix.Stat_t{}, openErr
		}
		fd = next
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return -1, unix.Stat_t{}, err
		}
		if uint64(stat.Dev) != uint64(rootStat.Dev) {
			_ = unix.Close(fd)
			return -1, unix.Stat_t{}, fmt.Errorf("crosses a filesystem")
		}
		if err := validateDirectoryStat(stat, policy); err != nil {
			_ = unix.Close(fd)
			return -1, unix.Stat_t{}, err
		}
	}
	return fd, stat, nil
}

func openComponent(parentFD int, component string) (int, error) {
	return unix.Openat2(parentFD, component, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
}

func inspectTarget(parentFD int, base string, rootDev uint64, expected *Metadata) (unix.Stat_t, bool, error) {
	fd, err := openPathIdentity(parentFD, base)
	if errors.Is(err, unix.ENOENT) {
		return unix.Stat_t{}, false, nil
	}
	if err != nil {
		return unix.Stat_t{}, false, fmt.Errorf("open target without following links: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, false, err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.Stat_t{}, false, fmt.Errorf("target is a symbolic link")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return unix.Stat_t{}, false, fmt.Errorf("target is not a regular file")
	}
	if uint64(stat.Dev) != rootDev {
		return unix.Stat_t{}, false, fmt.Errorf("target crosses a filesystem")
	}
	if stat.Nlink != 1 {
		return unix.Stat_t{}, false, fmt.Errorf("target has %d hard links; exactly one is required", stat.Nlink)
	}
	if expected == nil {
		return unix.Stat_t{}, false, fmt.Errorf("existing target metadata policy is required")
	}
	if err := validateFileMetadata(stat, *expected); err != nil {
		return unix.Stat_t{}, false, err
	}
	return stat, true, nil
}

func revalidateTarget(parentFD int, base string, expected unix.Stat_t, exists bool) error {
	fd, err := openPathIdentity(parentFD, base)
	if !exists {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err == nil {
			_ = unix.Close(fd)
			return fmt.Errorf("target appeared during transaction")
		}
		return err
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	return compareIdentity(stat, expected)
}

func revalidateIdentity(dirFD int, name string, expected unix.Stat_t) error {
	fd, err := openPathIdentity(dirFD, name)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	return compareIdentity(stat, expected)
}

func openPathIdentity(dirFD int, name string) (int, error) {
	return unix.Openat2(dirFD, name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func compareIdentity(actual, expected unix.Stat_t) error {
	if uint64(actual.Dev) != uint64(expected.Dev) || actual.Ino != expected.Ino || actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Mode&0o7000 != 0 || actual.Nlink != 1 || actual.Uid != expected.Uid || actual.Gid != expected.Gid || actual.Mode&0o777 != expected.Mode&0o777 {
		return fmt.Errorf("file identity or metadata changed")
	}
	return nil
}

func commitCreate(stagingFD int, stagingName string, parentFD int, targetName string, staging unix.Stat_t, metadata Metadata, maxBytes int64, content []byte, afterRename, rollbackSync func() error) (State, error) {
	if err := unix.Renameat2(stagingFD, stagingName, parentFD, targetName, unix.RENAME_NOREPLACE); err != nil {
		return StateStaged, fmt.Errorf("commit create: %w", err)
	}
	if err := afterRename(); err != nil {
		return StateNamespaceChanged, err
	}
	if _, err := verifyFile(parentFD, targetName, uint64(staging.Dev), metadata, maxBytes, content); err == nil {
		return StateNamespaceChanged, nil
	}
	if err := revalidateIdentity(parentFD, targetName, staging); err != nil {
		return StateIndeterminate, fmt.Errorf("created target verification failed and rollback source is unsafe: %w", err)
	}
	if err := unix.Renameat2(parentFD, targetName, stagingFD, stagingName, unix.RENAME_NOREPLACE); err != nil {
		return StateIndeterminate, fmt.Errorf("created target verification failed and rollback failed: %w", err)
	}
	if err := rollbackSync(); err != nil {
		return StateIndeterminate, fmt.Errorf("sync create rollback: %w", err)
	}
	if err := revalidateTarget(parentFD, targetName, unix.Stat_t{}, false); err != nil {
		return StateIndeterminate, fmt.Errorf("create rollback target is indeterminate: %w", err)
	}
	if _, err := verifyFile(stagingFD, stagingName, uint64(staging.Dev), metadata, maxBytes, content); err != nil {
		return StateIndeterminate, fmt.Errorf("create rollback staging is indeterminate: %w", err)
	}
	return StateStaged, fmt.Errorf("created target verification failed; activation rolled back")
}

func exchangeReplacement(stagingFD int, stagingName string, parentFD int, targetName string, staging, existing unix.Stat_t, metadata Metadata, maxBytes int64, content []byte, afterRename, rollbackSync func() error) (State, error) {
	if err := unix.Renameat2(stagingFD, stagingName, parentFD, targetName, unix.RENAME_EXCHANGE); err != nil {
		return StateStaged, fmt.Errorf("exchange replacement: %w", err)
	}
	if err := afterRename(); err != nil {
		return StateNamespaceChanged, err
	}
	_, targetErr := verifyFile(parentFD, targetName, uint64(staging.Dev), metadata, maxBytes, content)
	tombErr := revalidateIdentity(stagingFD, stagingName, existing)
	if targetErr == nil && tombErr == nil {
		return StateNamespaceChanged, nil
	}
	if tombErr != nil {
		return StateIndeterminate, fmt.Errorf("replacement tombstone identity changed and the prior target cannot be restored safely")
	}
	if err := revalidateIdentity(parentFD, targetName, staging); err != nil {
		return StateIndeterminate, fmt.Errorf("replacement rollback source is unsafe: %w", err)
	}
	if err := unix.Renameat2(stagingFD, stagingName, parentFD, targetName, unix.RENAME_EXCHANGE); err != nil {
		return StateIndeterminate, fmt.Errorf("replacement verification failed and rollback failed: %w", err)
	}
	if err := rollbackSync(); err != nil {
		return StateIndeterminate, fmt.Errorf("sync replacement rollback: %w", err)
	}
	if err := revalidateIdentity(parentFD, targetName, existing); err != nil {
		return StateIndeterminate, fmt.Errorf("replacement rollback target is indeterminate: %w", err)
	}
	if _, err := verifyFile(stagingFD, stagingName, uint64(staging.Dev), metadata, maxBytes, content); err != nil {
		return StateIndeterminate, fmt.Errorf("replacement rollback staging is indeterminate: %w", err)
	}
	return StateStaged, fmt.Errorf("replacement verification failed; activation rolled back")
}

func commitRemove(parentFD int, targetName string, stagingFD int, stagingName string, existing unix.Stat_t, afterRename func() error) (State, error) {
	if err := unix.Renameat2(parentFD, targetName, stagingFD, stagingName, unix.RENAME_NOREPLACE); err != nil {
		return StateUnchanged, fmt.Errorf("commit remove: %w", err)
	}
	if err := afterRename(); err != nil {
		return StateNamespaceChanged, err
	}
	if err := revalidateIdentity(stagingFD, stagingName, existing); err != nil {
		return StateIndeterminate, fmt.Errorf("removed tombstone identity changed; refusing unsafe rollback: %w", err)
	}
	return StateNamespaceChanged, nil
}

func syncDirectories(first, second int) error {
	if err := unix.Fsync(first); err != nil {
		return fmt.Errorf("sync target directory: %w", err)
	}
	if err := unix.Fsync(second); err != nil {
		return fmt.Errorf("sync staging directory: %w", err)
	}
	return nil
}

func createStaging(dirFD int, base, prefix string) (string, int, error) {
	for range 8 {
		name, err := stagingName(base, prefix)
		if err != nil {
			return "", -1, err
		}
		fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return name, fd, err
	}
	return "", -1, fmt.Errorf("allocate unique staging name")
}

func unusedStagingName(dirFD int, base, prefix string) (string, error) {
	for range 8 {
		name, err := stagingName(base, prefix)
		if err != nil {
			return "", err
		}
		var stat unix.Stat_t
		err = unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return name, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("allocate unique staging name")
}

func stagingName(base, prefix string) (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(base))
	return prefix + hex.EncodeToString(digest[:8]) + "." + hex.EncodeToString(random[:]), nil
}

func writeAll(fd int, data []byte) error {
	for len(data) != 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return fmt.Errorf("write staging file: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func applyMetadata(fd int, metadata Metadata) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != metadata.Owner.UID || stat.Gid != metadata.Owner.GID {
		if err := unix.Fchown(fd, int(metadata.Owner.UID), int(metadata.Owner.GID)); err != nil {
			return fmt.Errorf("set staging owner: %w", err)
		}
	}
	if err := unix.Fchmod(fd, uint32(metadata.Mode.Perm())); err != nil {
		return fmt.Errorf("set staging mode: %w", err)
	}
	return nil
}

func verifyFile(dirFD int, name string, rootDev uint64, metadata Metadata, maxBytes int64, expected []byte) (unix.Stat_t, error) {
	fd, err := unix.Openat2(dirFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return unix.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return unix.Stat_t{}, fmt.Errorf("wrap staging descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || uint64(stat.Dev) != rootDev {
		return unix.Stat_t{}, fmt.Errorf("staging identity is invalid")
	}
	if err := validateFileMetadata(stat, metadata); err != nil {
		return unix.Stat_t{}, err
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return unix.Stat_t{}, err
	}
	if int64(len(content)) > maxBytes || !bytes.Equal(content, expected) {
		return unix.Stat_t{}, fmt.Errorf("staging content verification failed")
	}
	return stat, nil
}

func validateConfig(config Config) error {
	if err := validateAbsolutePath(config.RootPath); err != nil {
		return fmt.Errorf("root path: %w", err)
	}
	if err := validateAbsolutePath(config.StagingPath); err != nil {
		return fmt.Errorf("staging path: %w", err)
	}
	if err := validateMetadata(config.Root); err != nil {
		return fmt.Errorf("root metadata: %w", err)
	}
	if err := validateMetadata(config.Staging); err != nil {
		return fmt.Errorf("staging metadata: %w", err)
	}
	if config.Staging.Mode.Perm() != 0o700 {
		return fmt.Errorf("staging directory mode must be 0700")
	}
	if config.Staging.Owner.UID != uint32(os.Geteuid()) || config.Staging.Owner.GID != uint32(os.Getegid()) {
		return fmt.Errorf("staging directory must be owned by the helper identity %d:%d", os.Geteuid(), os.Getegid())
	}
	if config.RootPath == "/" && config.Root != (Metadata{Owner: Owner{UID: 0, GID: 0}, Mode: 0o755}) {
		return fmt.Errorf("filesystem-root transaction requires exact root-owned mode 0755 authority")
	}
	if err := validateDirectoryPolicy(config.StagingParents); err != nil {
		return fmt.Errorf("staging parent policy: %w", err)
	}
	return nil
}

func validatePutRequest(request Request, data []byte, disposition Disposition) error {
	if err := validateRequest(request, true); err != nil {
		return err
	}
	if int64(len(data)) > request.MaxBytes {
		return fmt.Errorf("content size %d exceeds limit %d", len(data), request.MaxBytes)
	}
	switch disposition {
	case CreateOnly, ReplaceOnly, CreateOrReplace:
		return nil
	default:
		return fmt.Errorf("unsupported disposition %q", disposition)
	}
}

func validateRemoveRequest(request Request) error { return validateRequest(request, false) }

func validateRequest(request Request, requireNew bool) error {
	if err := validateAbsolutePath(request.Path); err != nil {
		return err
	}
	if err := validateDirectoryPolicy(request.Parents); err != nil {
		return fmt.Errorf("parent policy: %w", err)
	}
	if request.Existing != nil {
		if err := validateMetadata(*request.Existing); err != nil {
			return fmt.Errorf("existing metadata: %w", err)
		}
	}
	if !requireNew {
		if request.Existing == nil {
			return fmt.Errorf("remove requires existing metadata")
		}
		return nil
	}
	if err := validateMetadata(request.New); err != nil {
		return fmt.Errorf("new metadata: %w", err)
	}
	if request.MaxBytes <= 0 || request.MaxBytes > MaximumContentBytes {
		return fmt.Errorf("max bytes must be between 1 and %d", MaximumContentBytes)
	}
	return nil
}

func validateDisposition(disposition Disposition, exists bool) error {
	if disposition == CreateOnly && exists {
		return fs.ErrExist
	}
	if disposition == ReplaceOnly && !exists {
		return fs.ErrNotExist
	}
	return nil
}

func validateAbsolutePath(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path %q must be clean, absolute, and NUL-free", path)
	}
	return nil
}

func descendantRelative(root, target string) (string, error) {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("path is outside root")
	}
	return relative, nil
}

func validateMetadata(metadata Metadata) error {
	if metadata.Mode&^fs.FileMode(0o777) != 0 {
		return fmt.Errorf("mode contains non-permission bits")
	}
	if metadata.Mode.Perm()&0o022 != 0 {
		return fmt.Errorf("mode permits group or other writes")
	}
	return nil
}

func validateDirectoryPolicy(policy DirectoryPolicy) error {
	if len(policy.AllowedOwners) == 0 {
		return fmt.Errorf("at least one allowed owner is required")
	}
	if policy.AllowedMode&^fs.FileMode(0o777) != 0 {
		return fmt.Errorf("allowed mode contains non-permission bits")
	}
	return nil
}

func validateDirectoryMetadata(stat unix.Stat_t, expected Metadata) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("is not a directory")
	}
	if stat.Mode&0o7000 != 0 {
		return fmt.Errorf("directory has special mode bits %04o", stat.Mode&0o7000)
	}
	if stat.Uid != expected.Owner.UID || stat.Gid != expected.Owner.GID {
		return fmt.Errorf("owner is %d:%d, want %d:%d", stat.Uid, stat.Gid, expected.Owner.UID, expected.Owner.GID)
	}
	if fs.FileMode(stat.Mode&0o777) != expected.Mode.Perm() {
		return fmt.Errorf("mode is %04o, want %04o", stat.Mode&0o777, expected.Mode.Perm())
	}
	if stat.Mode&0o022 != 0 {
		return fmt.Errorf("directory permits group or other writes")
	}
	return nil
}

func validateDirectoryStat(stat unix.Stat_t, policy DirectoryPolicy) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("is not a directory")
	}
	if stat.Mode&0o7000 != 0 {
		return fmt.Errorf("directory has special mode bits %04o", stat.Mode&0o7000)
	}
	allowed := false
	for _, owner := range policy.AllowedOwners {
		allowed = allowed || stat.Uid == owner.UID && stat.Gid == owner.GID
	}
	if !allowed {
		return fmt.Errorf("owner %d:%d is not allowed", stat.Uid, stat.Gid)
	}
	mode := fs.FileMode(stat.Mode & 0o777)
	if mode&0o022 != 0 {
		return fmt.Errorf("directory permits group or other writes")
	}
	if mode&^policy.AllowedMode.Perm() != 0 {
		return fmt.Errorf("mode %04o exceeds allowed mode %04o", mode, policy.AllowedMode.Perm())
	}
	return nil
}

func validateFileMetadata(stat unix.Stat_t, expected Metadata) error {
	if stat.Mode&0o7000 != 0 {
		return fmt.Errorf("file has special mode bits %04o", stat.Mode&0o7000)
	}
	if stat.Uid != expected.Owner.UID || stat.Gid != expected.Owner.GID {
		return fmt.Errorf("file owner is %d:%d, want %d:%d", stat.Uid, stat.Gid, expected.Owner.UID, expected.Owner.GID)
	}
	if fs.FileMode(stat.Mode&0o777) != expected.Mode.Perm() {
		return fmt.Errorf("file mode is %04o, want %04o", stat.Mode&0o777, expected.Mode.Perm())
	}
	return nil
}

func txError(point Point, result Result, err error) error {
	return &Error{Point: point, Result: result, Err: err}
}
