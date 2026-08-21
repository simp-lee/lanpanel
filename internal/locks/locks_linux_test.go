//go:build linux

package locks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIndependentLockContract(t *testing.T) {
	t.Run("ordered_handoff_and_reverse_rejection", func(t *testing.T) {
		manager := newTestManager(t)
		defer func(ignore func() error) { _ = ignore() }(manager.Close)
		admission, err := manager.Acquire(context.Background(), MutationAdmission)
		if err != nil {
			t.Fatalf("Acquire(admission) error = %v", err)
		}
		exposure, err := manager.Acquire(context.Background(), Exposure)
		if err != nil {
			t.Fatalf("Acquire(exposure) error = %v", err)
		}
		if !admission.Holds(MutationAdmission) || !exposure.Holds(Exposure) {
			t.Fatal("active leases not recognized")
		}
		if err := exposure.Release(); err != nil {
			t.Fatal(err)
		}
		if err := admission.Release(); err != nil {
			t.Fatal(err)
		}

		exposure, err = manager.Acquire(context.Background(), Exposure)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Acquire(context.Background(), MutationAdmission); !errors.Is(err, ErrLockOrder) {
			t.Fatalf("reverse Acquire() error = %v, want lock order error", err)
		}
		if err := exposure.Release(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cross_manager_contention_is_bounded", func(t *testing.T) {
		root := testLockRoot(t)
		first := openTestManager(t, root)
		defer func(ignore func() error) { _ = ignore() }(first.Close)
		second := openTestManager(t, root)
		defer func(ignore func() error) { _ = ignore() }(second.Close)
		lease, err := first.Acquire(context.Background(), Exposure)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := second.Acquire(context.Background(), MutationAdmission); !errors.Is(err, ErrLockOrder) {
			t.Fatalf("cross-manager reverse Acquire() error = %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := second.Acquire(ctx, Exposure); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contended Acquire() error = %v, want deadline", err)
		}
		if err := lease.Release(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("path_or_metadata_drift_fails_before_lock", func(t *testing.T) {
		root := testLockRoot(t)
		manager := openTestManager(t, root)
		defer func(ignore func() error) { _ = ignore() }(manager.Close)
		if err := os.Chmod(filepath.Join(root, "exposure.lock"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Acquire(context.Background(), Exposure); err == nil {
			t.Fatal("Acquire() accepted unsafe lock mode")
		}
	})

	t.Run("held_lease_detects_lock_path_replacement", func(t *testing.T) {
		root := testLockRoot(t)
		manager := openTestManager(t, root)
		defer func(ignore func() error) { _ = ignore() }(manager.Close)
		lease, err := manager.Acquire(context.Background(), Exposure)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "exposure.lock")
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := lease.Validate(); err == nil {
			t.Fatal("lease accepted replaced lock path")
		}
		if err := lease.Release(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("lock_files_are_owner_only_regular_files", func(t *testing.T) {
		root := testLockRoot(t)
		manager := openTestManager(t, root)
		defer func(ignore func() error) { _ = ignore() }(manager.Close)
		for _, name := range []string{"mutation-admission.lock", "exposure.lock"} {
			info, err := os.Lstat(filepath.Join(root, name))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("Lstat(%s) = %#v, %v", name, info, err)
			}
		}
	})

	t.Run("normal_activation_timeout_is_fixed", func(t *testing.T) {
		ctx, cancel := WithNormalActivationTimeout(context.Background())
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("normal activation context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining > NormalActivationTimeout || remaining < NormalActivationTimeout-time.Second {
			t.Fatalf("activation timeout = %v, want %v", remaining, NormalActivationTimeout)
		}
	})
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	return openTestManager(t, testLockRoot(t))
}

func testLockRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func openTestManager(t *testing.T, root string) *Manager {
	t.Helper()
	manager, err := Open(Config{RootPath: root, Owner: uint32(os.Geteuid()), Group: uint32(os.Getegid()), Mode: 0o700})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return manager
}
