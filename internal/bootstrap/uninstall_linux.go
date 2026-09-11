//go:build linux

package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/identity"
	"lanpanel/internal/locks"
	"lanpanel/internal/release"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
)

// RunPublicUninstall is the sole lifecycle removal entry point. It uses the
// committed ownership inventory, never invokes apt/dpkg, and never recursively
// deletes a directory containing unowned residue.
func RunPublicUninstall(args []string, in io.Reader, out io.Writer) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("uninstall requires root")
	}
	if len(args) != 0 {
		return fmt.Errorf("uninstall accepts no options")
	}
	if in == nil || out == nil {
		return fmt.Errorf("uninstall confirmation terminal is unavailable")
	}
	paths := FixedPaths()
	_, _ = fmt.Fprintf(out, "LanPanel uninstall will remove only committed LanPanel-owned paths: %s, %s, %s, %s, %s, and fixed runtime assets. APT/dpkg packages and external application files will not be removed.\nType UNINSTALL LANPANEL to continue: ", paths.BinaryPath, paths.PersistentRoot, paths.InstallationRoot, paths.SystemdRoot, paths.RuntimeRoot)
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != "UNINSTALL LANPANEL" {
		return fmt.Errorf("uninstall requires exact confirmation UNINSTALL LANPANEL")
	}
	return uninstallCommitted(context.Background(), paths, out)
}

func uninstallCommitted(ctx context.Context, paths Paths, out io.Writer) error {
	if err := RequireCommitted(paths); err != nil {
		return fmt.Errorf("uninstall fenced: %w", err)
	}
	commitBytes, err := readCommittedArtifact(paths.CommitPath, MaximumJournalBytes, 0o644)
	if err != nil {
		return err
	}
	var commit Commit
	if err := decodeCanonical(commitBytes, &commit); err != nil || !release.ValidDigest(commit.OwnershipDigest) {
		return fmt.Errorf("uninstall ownership commit is invalid")
	}
	store, journal, err := openJournal(paths.Journal, 0, 0)
	if err != nil {
		return err
	}
	defer func() { _ = store.close() }()
	inventoryBytes, err := readCommittedArtifact(ownershipInventoryPath(paths), MaximumJournalBytes, 0o600)
	if err != nil || release.DigestBytes(inventoryBytes) != commit.OwnershipDigest {
		return fmt.Errorf("uninstall ownership inventory is missing or changed")
	}
	var inventory OwnershipInventory
	if err := decodeCanonical(inventoryBytes, &inventory); err != nil || validateOwnershipInventory(inventory, journal) != nil {
		return fmt.Errorf("uninstall ownership inventory is invalid")
	}
	manager, err := locks.Open(locks.Config{RootPath: paths.LockRoot, Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return fmt.Errorf("uninstall mutation lock is unavailable: %w", err)
	}
	admission, err := manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fmt.Errorf("uninstall mutation lock is unavailable: %w", err)
	}
	defer func() { _ = admission.Release(); _ = manager.Close() }()
	exposure, err := manager.Acquire(ctx, locks.Exposure)
	if err != nil {
		return fmt.Errorf("uninstall exposure lock is unavailable: %w", err)
	}
	defer func() { _ = exposure.Release() }()
	if err := stopOwnedServices(ctx, inventory.Paths); err != nil {
		return err
	}
	if err := removeOwnedAccounts(journal); err != nil {
		return err
	}
	for index := len(inventory.Paths) - 1; index >= 0; index-- {
		path := inventory.Paths[index]
		if path == paths.BinaryPath || path == ownershipInventoryPath(paths) {
			continue // remove authority files only after every other postcondition.
		}
		if err := removeOwnedPath(path, inventory.Artifacts, inventory.MutablePaths); err != nil {
			return err
		}
	}
	if err := removeOwnedPath(ownershipInventoryPath(paths), map[string]string{ownershipInventoryPath(paths): commit.OwnershipDigest}, nil); err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("uninstall service fence reload failed: %w", err)
	}
	if err := unmaskOwnedServices(ctx, inventory.Paths); err != nil {
		return err
	}
	if err := exposure.Release(); err != nil {
		return fmt.Errorf("uninstall exposure lock release failed: %w", err)
	}
	if err := admission.Release(); err != nil {
		return fmt.Errorf("uninstall mutation lock release failed: %w", err)
	}
	if err := manager.Close(); err != nil {
		return fmt.Errorf("uninstall lock release failed: %w", err)
	}
	for _, lockName := range []string{"mutation-admission.lock", "exposure.lock"} {
		if err := removeOwnedLockFile(filepath.Join(paths.LockRoot, lockName)); err != nil {
			return err
		}
	}
	if err := removeOwnedPath(paths.LockRoot, inventory.Artifacts, inventory.MutablePaths); err != nil {
		return err
	}
	if err := os.Remove(paths.BinaryPath); err != nil {
		return fmt.Errorf("uninstall binary removal failed: %w", err)
	}
	_, _ = fmt.Fprintln(out, "LanPanel uninstall completed; no APT/dpkg package was removed.")
	return nil
}

func stopOwnedServices(ctx context.Context, paths []string) error {
	units := make([]string, 0)
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".socket") || strings.HasSuffix(base, ".timer") {
			units = append(units, base)
		}
	}
	slices.Sort(units)
	for _, unit := range slices.Compact(units) {
		if err := exec.CommandContext(ctx, "systemctl", "mask", "--runtime", "--now", unit).Run(); err != nil {
			return fmt.Errorf("uninstall could not fence %s; fence retained: %w", unit, err)
		}
		if err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run(); err == nil {
			return fmt.Errorf("uninstall service fence is incomplete for %s", unit)
		}
	}
	return nil
}

func unmaskOwnedServices(ctx context.Context, paths []string) error {
	units := make([]string, 0)
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".socket") || strings.HasSuffix(base, ".timer") {
			units = append(units, base)
		}
	}
	for _, unit := range slices.Compact(units) {
		if err := exec.CommandContext(ctx, "systemctl", "unmask", unit).Run(); err != nil {
			return fmt.Errorf("uninstall could not clear fence for %s: %w", unit, err)
		}
	}
	return nil
}

func removeOwnedAccounts(journal Journal) error {
	sets := []identity.AccountSet{journal.Accounts}
	if data, err := os.ReadFile("/etc/sysusers.d/lanpanel-headscale.conf"); err == nil {
		match := regexp.MustCompile(`(?m)^u ([^ ]+) -:[^ ]+ "([^"]+)" /nonexistent /usr/sbin/nologin$`).FindSubmatch(data)
		if len(match) != 3 || !strings.Contains(string(match[2]), " headscale ") {
			return fmt.Errorf("uninstall Headscale account authority is invalid")
		}
		fields := strings.Fields(string(match[2]))
		if len(fields) != 4 || fields[0] != "LanPanel" || fields[1] != journal.InstallationID || fields[2] != "headscale" || !strings.HasPrefix(string(match[1]), "lp-") {
			return fmt.Errorf("uninstall Headscale account authority is foreign")
		}
		set, err := identity.HeadscaleAccounts(journal.InstallationID, fields[3])
		if err != nil || set.Specs[0].User != string(match[1]) || set.Specs[0].Comment != string(match[2]) {
			return fmt.Errorf("uninstall Headscale account authority is foreign")
		}
		expected, err := identity.RenderSysusers(set)
		if err != nil || !bytes.Equal(expected, data) {
			return fmt.Errorf("uninstall Headscale account authority is foreign")
		}
		sets = append(sets, set)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("uninstall cannot inspect Headscale account authority: %w", err)
	}
	for _, set := range sets {
		present, _, err := identity.InspectAccounts(set)
		if err != nil || !present {
			return fmt.Errorf("uninstall account ownership is incomplete: %w", err)
		}
	}
	removedUsers := map[string]bool{}
	removedGroups := map[string]bool{}
	for _, set := range sets {
		for _, spec := range set.Specs {
			if !removedUsers[spec.User] {
				if err := exec.Command("userdel", "--system", "--force", spec.User).Run(); err != nil {
					return fmt.Errorf("uninstall could not remove owned account %s: %w", spec.User, err)
				}
				removedUsers[spec.User] = true
			}
			if !removedGroups[spec.Group] {
				if err := exec.Command("groupdel", spec.Group).Run(); err != nil {
					return fmt.Errorf("uninstall could not remove owned group %s: %w", spec.Group, err)
				}
				removedGroups[spec.Group] = true
			}
		}
	}
	return nil
}

func removeOwnedLockFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("uninstall foreign lock residue at %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) != 0 {
		return fmt.Errorf("uninstall foreign lock residue at %q", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("uninstall could not remove lock %q: %w", path, err)
	}
	return nil
}

func removeOwnedPath(path string, artifacts map[string]string, mutable []string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("uninstall cannot inspect %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil || target != "/dev/null" || artifacts[path] != release.DigestBytes([]byte("/dev/null")) {
			return fmt.Errorf("uninstall foreign residue at %q", path)
		}
		return os.Remove(path)
	}
	if info.IsDir() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			// Non-empty managed roots may contain external application data; retain
			// them rather than recursively deleting user files.
			if errors.Is(err, syscall.ENOTEMPTY) {
				return fmt.Errorf("uninstall foreign residue at %q", path)
			}
			return fmt.Errorf("uninstall could not remove owned directory %q: %w", path, err)
		}
		return nil
	}
	if digest, ok := artifacts[path]; ok {
		data, err := os.ReadFile(path)
		if err != nil || release.DigestBytes(data) != digest {
			return fmt.Errorf("uninstall foreign residue at %q", path)
		}
	} else if slices.Contains(mutable, path) {
		if info.Mode()&0o022 != 0 {
			return fmt.Errorf("uninstall foreign residue at %q", path)
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 || stat.Gid != 0 {
			return fmt.Errorf("uninstall foreign ownership at %q", path)
		}
	} else {
		return fmt.Errorf("uninstall ownership digest is missing for %q", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("uninstall could not remove %q: %w", path, err)
	}
	return nil
}
