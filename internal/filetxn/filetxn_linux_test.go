//go:build linux

package filetxn

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestAtomicFileLifecycle(t *testing.T) {
	t.Run("create_replace_remove", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)

		created, err := store.Put(context.Background(), request, []byte("first\n"), CreateOnly)
		if err != nil || created.State != StateDurable {
			t.Fatalf("Put(create) = %#v, %v", created, err)
		}
		assertContent(t, request.Path, request.New, "first\n")
		assertMissing(t, created.StagingPath)

		replaced, err := store.Put(context.Background(), request, []byte("second\n"), ReplaceOnly)
		if err != nil || replaced.State != StateDurable {
			t.Fatalf("Put(replace) = %#v, %v", replaced, err)
		}
		assertContent(t, request.Path, request.New, "second\n")
		assertMissing(t, replaced.StagingPath)

		removed, err := store.Remove(context.Background(), request)
		if err != nil || removed.State != StateDurable {
			t.Fatalf("Remove() = %#v, %v", removed, err)
		}
		assertMissing(t, request.Path)
		assertMissing(t, removed.StagingPath)
	})
}

func TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging(t *testing.T) {
	fault := errors.New("injected fault")
	points := []Point{PointAfterCreate, PointAfterStagingSync, PointBeforeWrite, PointAfterWrite, PointBeforeMetadata, PointAfterMetadata, PointBeforeFileSync, PointAfterFileSync, PointAfterVerify, PointBeforeRename, PointAfterRename, PointBeforeDirectorySync, PointAfterDirectorySync, PointBeforeCleanup, PointAfterCleanup}
	for _, point := range points {
		t.Run(string(point), func(t *testing.T) {
			store, request := newTestStore(t, func(actual Point) error {
				if actual == point {
					return fault
				}
				return nil
			})
			defer func(ignore func() error) { _ = ignore() }(store.Close)
			mustWrite(t, request.Path, "old\n", request.New.Mode)

			result, err := store.Put(context.Background(), request, []byte("new\n"), ReplaceOnly)
			if !errors.Is(err, fault) {
				t.Fatalf("Put() error = %v, want fault", err)
			}
			var txErr *Error
			if !errors.As(err, &txErr) || txErr.Point != point || txErr.Result != result {
				t.Fatalf("transaction error = %#v, result = %#v", txErr, result)
			}
			if !strings.HasPrefix(filepath.Base(result.StagingPath), ".lanpanel-txn.") {
				t.Fatalf("staging path = %q", result.StagingPath)
			}
			switch point {
			case PointAfterRename, PointBeforeDirectorySync:
				if result.State != StateNamespaceChanged {
					t.Fatalf("result state = %q, want namespace_changed", result.State)
				}
				assertContent(t, request.Path, request.New, "new\n")
				assertContent(t, result.StagingPath, request.New, "old\n")
			case PointAfterDirectorySync, PointBeforeCleanup:
				if result.State != StateDurable {
					t.Fatalf("result state = %q, want durable", result.State)
				}
				assertContent(t, request.Path, request.New, "new\n")
				assertContent(t, result.StagingPath, request.New, "old\n")
			case PointAfterCleanup:
				if result.State != StateDurable {
					t.Fatalf("result state = %q, want durable", result.State)
				}
				assertContent(t, request.Path, request.New, "new\n")
				assertMissing(t, result.StagingPath)
			default:
				if result.State != StateStaged {
					t.Fatalf("result state = %q, want staged", result.State)
				}
				assertContent(t, request.Path, request.New, "old\n")
				info, statErr := os.Lstat(result.StagingPath)
				if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatalf("inert staging info = %#v, %v", info, statErr)
				}
			}
		})
	}
}

func TestRemoveFaultAfterRenameLeavesTombstone(t *testing.T) {
	fault := errors.New("remove interrupted")
	store, request := newTestStore(t, func(point Point) error {
		if point == PointAfterRename {
			return fault
		}
		return nil
	})
	defer func(ignore func() error) { _ = ignore() }(store.Close)
	mustWrite(t, request.Path, "managed\n", request.New.Mode)

	result, err := store.Remove(context.Background(), request)
	if !errors.Is(err, fault) || result.State != StateNamespaceChanged {
		t.Fatalf("Remove() = %#v, %v", result, err)
	}
	assertMissing(t, request.Path)
	if !strings.HasPrefix(filepath.Base(result.StagingPath), ".lanpanel-remove.") {
		t.Fatalf("tombstone path = %q", result.StagingPath)
	}
	assertContent(t, result.StagingPath, request.New, "managed\n")
}

func TestNoFollowMetadataAndBoundaryValidation(t *testing.T) {
	t.Run("symlink parent", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		root := filepath.Dir(filepath.Dir(request.Path))
		if err := os.Symlink(filepath.Join(root, "managed"), filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		request.Path = filepath.Join(root, "link", "file")
		if _, err := store.Put(context.Background(), request, []byte("x"), CreateOnly); err == nil {
			t.Fatal("Put() accepted symlink parent")
		}
	})

	t.Run("symlink and hardlink targets", func(t *testing.T) {
		for _, kind := range []string{"symlink", "hardlink"} {
			t.Run(kind, func(t *testing.T) {
				store, request := newTestStore(t, nil)
				defer func(ignore func() error) { _ = ignore() }(store.Close)
				other := filepath.Join(filepath.Dir(request.Path), "other")
				mustWrite(t, other, "other", 0o600)
				var err error
				if kind == "symlink" {
					err = os.Symlink(other, request.Path)
				} else {
					err = os.Link(other, request.Path)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Put(context.Background(), request, []byte("x"), ReplaceOnly); err == nil {
					t.Fatalf("Put() accepted %s target", kind)
				}
				assertContent(t, other, request.New, "other")
			})
		}
	})

	t.Run("wrong target mode", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		mustWrite(t, request.Path, "old", 0o644)
		if _, err := store.Put(context.Background(), request, []byte("new"), ReplaceOnly); err == nil || !strings.Contains(err.Error(), "file mode") {
			t.Fatalf("Put() error = %v", err)
		}
	})

	t.Run("wrong target owner", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		mustWrite(t, request.Path, "old", 0o600)
		request.Existing.Owner.UID++
		if _, err := store.Put(context.Background(), request, []byte("new"), ReplaceOnly); err == nil || !strings.Contains(err.Error(), "file owner") {
			t.Fatalf("Put() error = %v", err)
		}
	})

	t.Run("unclean and outside paths", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		root := filepath.Dir(filepath.Dir(request.Path))
		request.Path = filepath.Dir(request.Path) + string(filepath.Separator) + ".." + string(filepath.Separator) + "managed" + string(filepath.Separator) + "file"
		if _, err := store.Put(context.Background(), request, []byte("x"), CreateOnly); err == nil {
			t.Fatal("Put() accepted unclean path")
		}
		request.Path = filepath.Join(filepath.Dir(root), "outside")
		if _, err := store.Put(context.Background(), request, []byte("x"), CreateOnly); err == nil {
			t.Fatal("Put() accepted outside path")
		}
	})

	t.Run("parent mode", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		if err := os.Chmod(filepath.Dir(request.Path), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Put(context.Background(), request, []byte("x"), CreateOnly); err == nil || !strings.Contains(err.Error(), "exceeds allowed") {
			t.Fatalf("Put() error = %v", err)
		}
	})

	t.Run("parent owner including root", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request.Path = filepath.Join(filepath.Dir(filepath.Dir(request.Path)), "direct-file")
		request.Parents.AllowedOwners[0].UID++
		if _, err := store.Put(context.Background(), request, []byte("x"), CreateOnly); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("Put() error = %v", err)
		}
	})

	t.Run("safe mount traversal", func(t *testing.T) {
		rootFD, _, err := openAbsoluteDirectory("/")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = syscall.Close(rootFD) }()
		procFD, err := openComponent(rootFD, "proc")
		if err != nil {
			t.Fatalf("safe no-follow mount traversal: %v", err)
		}
		_ = syscall.Close(procFD)
	})
}

func TestCreateAndReplaceRejectConcurrentTargetChanges(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		var request Request
		store, createdRequest := newTestStore(t, func(point Point) error {
			if point == PointBeforeRename {
				mustWrite(t, request.Path, "competitor\n", 0o600)
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request = createdRequest
		result, err := store.Put(context.Background(), request, []byte("ours\n"), CreateOnly)
		if err == nil || result.State != StateStaged {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		assertContent(t, request.Path, request.New, "competitor\n")
	})

	t.Run("replace", func(t *testing.T) {
		var request Request
		store, createdRequest := newTestStore(t, func(point Point) error {
			if point == PointBeforeRename {
				temporary := request.Path + ".competitor"
				mustWrite(t, temporary, "competitor\n", 0o600)
				if err := os.Rename(temporary, request.Path); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request = createdRequest
		mustWrite(t, request.Path, "old\n", 0o600)
		result, err := store.Put(context.Background(), request, []byte("ours\n"), ReplaceOnly)
		if err == nil || result.State != StateStaged {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		assertContent(t, request.Path, request.New, "competitor\n")
		assertContent(t, result.StagingPath, request.New, "ours\n")
	})

	t.Run("staging source", func(t *testing.T) {
		var staging string
		store, request := newTestStore(t, func(point Point) error {
			if point == PointBeforeRename {
				matches, err := filepath.Glob(filepath.Join(staging, ".lanpanel-txn.*"))
				if err != nil || len(matches) != 1 {
					t.Fatalf("Glob(staging) = %v, %v", matches, err)
				}
				foreign := filepath.Join(staging, "foreign")
				mustWrite(t, foreign, "foreign\n", 0o600)
				if err := os.Rename(foreign, matches[0]); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		staging = filepath.Join(filepath.Dir(filepath.Dir(request.Path)), "staging")
		result, err := store.Put(context.Background(), request, []byte("ours\n"), CreateOnly)
		if err == nil || result.State != StateStaged {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		assertMissing(t, request.Path)
		assertContent(t, result.StagingPath, request.New, "foreign\n")
	})

	t.Run("remove", func(t *testing.T) {
		var request Request
		store, createdRequest := newTestStore(t, func(point Point) error {
			if point == PointBeforeRename {
				temporary := request.Path + ".competitor"
				mustWrite(t, temporary, "competitor\n", 0o600)
				if err := os.Rename(temporary, request.Path); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request = createdRequest
		mustWrite(t, request.Path, "old\n", 0o600)
		result, err := store.Remove(context.Background(), request)
		if err == nil || result.State != StateUnchanged {
			t.Fatalf("Remove() = %#v, %v", result, err)
		}
		assertContent(t, request.Path, request.New, "competitor\n")
	})

	t.Run("post rename replacement rollback", func(t *testing.T) {
		var request Request
		store, createdRequest := newTestStore(t, func(point Point) error {
			if point == PointAfterRename {
				mustWrite(t, request.Path, "corrupted\n", 0o600)
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request = createdRequest
		mustWrite(t, request.Path, "old\n", 0o600)
		result, err := store.Put(context.Background(), request, []byte("ours\n"), ReplaceOnly)
		if err == nil || result.State != StateIndeterminate {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		assertContent(t, request.Path, request.New, "old\n")
		assertContent(t, result.StagingPath, request.New, "corrupted\n")
	})

	t.Run("rollback sync failure", func(t *testing.T) {
		fault := errors.New("rollback sync failed")
		var request Request
		store, createdRequest := newTestStore(t, func(point Point) error {
			switch point {
			case PointAfterRename:
				mustWrite(t, request.Path, "corrupted\n", 0o600)
			case PointBeforeDirectorySync:
				return fault
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request = createdRequest
		mustWrite(t, request.Path, "old\n", 0o600)
		result, err := store.Put(context.Background(), request, []byte("ours\n"), ReplaceOnly)
		if !errors.Is(err, fault) || result.State != StateIndeterminate {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		assertContent(t, request.Path, request.New, "old\n")
		assertContent(t, result.StagingPath, request.New, "corrupted\n")
	})

	t.Run("post rename remove identity loss", func(t *testing.T) {
		var staging string
		store, request := newTestStore(t, func(point Point) error {
			if point == PointAfterRename {
				matches, err := filepath.Glob(filepath.Join(staging, ".lanpanel-remove.*"))
				if err != nil || len(matches) != 1 {
					t.Fatalf("Glob(tombstone) = %v, %v", matches, err)
				}
				foreign := filepath.Join(staging, "foreign-remove")
				mustWrite(t, foreign, "foreign\n", 0o600)
				if err := os.Rename(foreign, matches[0]); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		staging = filepath.Join(filepath.Dir(filepath.Dir(request.Path)), "staging")
		mustWrite(t, request.Path, "old\n", 0o600)
		result, err := store.Remove(context.Background(), request)
		if err == nil || result.State != StateIndeterminate {
			t.Fatalf("Remove() = %#v, %v", result, err)
		}
		assertMissing(t, request.Path)
		assertContent(t, result.StagingPath, request.New, "foreign\n")
	})
}

func TestProtectedStagingDirectory(t *testing.T) {
	t.Run("rejects_root_metadata_drift", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		root := filepath.Dir(filepath.Dir(request.Path))
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		result, err := store.Put(context.Background(), request, []byte("blocked\n"), CreateOnly)
		if err == nil || result.State != StateUnchanged || result.StagingPath != "" {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		assertMissing(t, request.Path)
	})

	t.Run("rejects_staging_path_replacement", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		root := filepath.Dir(filepath.Dir(request.Path))
		staging := filepath.Join(root, "staging")
		if err := os.Rename(staging, staging+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Fatal(err)
		}
		result, err := store.Put(context.Background(), request, []byte("blocked\n"), CreateOnly)
		if err == nil || result.State != StateUnchanged || result.StagingPath != "" {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		assertMissing(t, request.Path)
	})

	t.Run("keeps_final_file_behind_owner_only_parent", func(t *testing.T) {
		fault := errors.New("inspect staging")
		store, request := newTestStore(t, func(point Point) error {
			if point == PointAfterMetadata {
				return fault
			}
			return nil
		})
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request.New.Mode = 0o644
		result, err := store.Put(context.Background(), request, []byte("secret\n"), CreateOnly)
		if !errors.Is(err, fault) || result.State != StateStaged {
			t.Fatalf("Put() = %#v, %v", result, err)
		}
		info, err := os.Stat(filepath.Dir(result.StagingPath))
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("Stat(staging parent) = %#v, %v", info, err)
		}
		assertContent(t, result.StagingPath, request.New, "secret\n")
	})
}

func TestPutEnforcesSizeDispositionAndCancellation(t *testing.T) {
	t.Run("bounded_input_and_operation", func(t *testing.T) {
		store, request := newTestStore(t, nil)
		defer func(ignore func() error) { _ = ignore() }(store.Close)
		request.MaxBytes = 2
		if _, err := store.Put(context.Background(), request, []byte("big"), CreateOnly); err == nil {
			t.Fatal("Put() accepted oversized content")
		}
		mustWrite(t, request.Path, "x", 0o600)
		if _, err := store.Put(context.Background(), request, []byte("x"), CreateOnly); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("Put(create existing) error = %v", err)
		}
		if err := os.Remove(request.Path); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Put(context.Background(), request, []byte("x"), ReplaceOnly); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Put(replace missing) error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := store.Put(ctx, request, []byte("x"), CreateOnly)
		if !errors.Is(err, context.Canceled) || result.StagingPath == "" || result.State != StateStaged {
			t.Fatalf("Put(cancelled) = %#v, %v", result, err)
		}
	})
}

func newTestStore(t *testing.T, fault FaultFunc) (*Store, Request) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(root, "managed")
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	owner := Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	metadata := Metadata{Owner: owner, Mode: 0o600}
	directories := DirectoryPolicy{AllowedOwners: []Owner{owner}, AllowedMode: 0o700}
	store, err := Open(Config{
		RootPath: root, Root: Metadata{Owner: owner, Mode: 0o700},
		StagingPath: staging, Staging: Metadata{Owner: owner, Mode: 0o700}, StagingParents: directories,
	}, Options{Fault: fault})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store, Request{
		Path:     filepath.Join(managed, "file"),
		Parents:  directories,
		Existing: &metadata,
		New:      metadata,
		MaxBytes: 1024,
	}
}

func mustWrite(t *testing.T, path string, content string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func assertContent(t *testing.T, path string, metadata Metadata, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != expected {
		t.Fatalf("ReadFile(%s) = %q, %v; want %q", path, content, err, expected)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != metadata.Mode.Perm() {
		t.Fatalf("Lstat(%s) = %#v, %v", path, info, err)
	}
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(%s) error = %v, want not exist", path, err)
	}
}
