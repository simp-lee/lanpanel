//go:build linux

package bootstrap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/release"
	"os"
	"os/exec"
	"path/filepath"
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
	if err := stopOwnedServices(ctx, inventory.Paths); err != nil {
		return err
	}
	for index := len(inventory.Paths) - 1; index >= 0; index-- {
		path := inventory.Paths[index]
		if path == paths.BinaryPath {
			continue // remove the executing file only after every other postcondition.
		}
		if err := removeOwnedPath(path, inventory.Artifacts); err != nil {
			return err
		}
	}
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("uninstall service fence reload failed: %w", err)
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
		if err := exec.CommandContext(ctx, "systemctl", "stop", unit).Run(); err != nil {
			return fmt.Errorf("uninstall could not stop %s; fence retained: %w", unit, err)
		}
	}
	return nil
}

func removeOwnedPath(path string, artifacts map[string]string) error {
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
				return nil
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
	} else if info.Mode()&0o022 != 0 {
		return fmt.Errorf("uninstall foreign residue at %q", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("uninstall could not remove %q: %w", path, err)
	}
	return nil
}
