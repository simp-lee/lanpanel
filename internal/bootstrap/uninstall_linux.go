//go:build linux

package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/goaccess"
	"lanpanel/internal/identity"
	"lanpanel/internal/locks"
	"lanpanel/internal/nginx"
	"lanpanel/internal/persist"
	"lanpanel/internal/process"
	"lanpanel/internal/release"
	appresource "lanpanel/internal/resource"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunPublicUninstall is the sole lifecycle removal entry point. It uses the
// committed ownership inventory, never invokes apt/dpkg, and never recursively
// deletes a directory containing unowned residue.
func RunPublicUninstall(args []string, in io.Reader, out io.Writer) error {
	return runPublicUninstallAt(args, in, out, FixedPaths())
}

func runPublicUninstallAt(args []string, in io.Reader, out io.Writer, paths Paths) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("uninstall requires root")
	}
	if len(args) != 0 {
		return fmt.Errorf("uninstall accepts no options")
	}
	if in == nil || out == nil {
		return fmt.Errorf("uninstall confirmation terminal is unavailable")
	}
	fdReader, ok := in.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("uninstall confirmation requires an interactive terminal")
	}
	if _, err := unix.IoctlGetTermios(int(fdReader.Fd()), unix.TCGETS); err != nil {
		return fmt.Errorf("uninstall confirmation requires an interactive terminal")
	}
	scope, err := readUninstallScope(paths)
	if err != nil {
		return fmt.Errorf("uninstall fenced: %w", err)
	}
	_, _ = fmt.Fprintf(out, "LanPanel uninstall will remove only these verified LanPanel-owned paths:\n%s\nAPT/dpkg packages and external application files will not be removed.\nType UNINSTALL LANPANEL to continue: ", strings.Join(scope, "\n"))
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() || scanner.Text() != "UNINSTALL LANPANEL" {
		return fmt.Errorf("uninstall requires exact confirmation UNINSTALL LANPANEL")
	}
	return uninstallCommitted(context.Background(), paths, out, scope)
}

func readUninstallScope(paths Paths) ([]string, error) {
	if err := RequireCommitted(paths); err != nil {
		return nil, err
	}
	commitBytes, err := readCommittedArtifact(paths.CommitPath, MaximumJournalBytes, 0o644)
	if err != nil {
		return nil, err
	}
	var commit Commit
	if err := decodeCanonical(commitBytes, &commit); err != nil || !release.ValidDigest(commit.OwnershipDigest) {
		return nil, fmt.Errorf("uninstall ownership commit is invalid")
	}
	inventoryBytes, err := readCommittedArtifact(ownershipInventoryPath(paths), MaximumJournalBytes, 0o600)
	if err != nil || release.DigestBytes(inventoryBytes) != commit.OwnershipDigest {
		return nil, fmt.Errorf("uninstall ownership inventory is missing or changed")
	}
	store, journal, err := openJournal(paths.Journal, 0, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = store.close() }()
	var inventory OwnershipInventory
	if err := decodeCanonical(inventoryBytes, &inventory); err != nil {
		return nil, fmt.Errorf("uninstall ownership inventory is invalid")
	}
	if err := validateOwnershipInventory(inventory, journal); err != nil {
		return nil, fmt.Errorf("uninstall ownership inventory is invalid: %w", err)
	}
	manager, err := locks.Open(locks.Config{RootPath: paths.LockRoot, Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		return nil, fmt.Errorf("uninstall mutation lock is unavailable: %w", err)
	}
	admission, err := manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		_ = manager.Close()
		return nil, fmt.Errorf("uninstall mutation lock is unavailable: %w", err)
	}
	exposure, err := manager.Acquire(context.Background(), locks.Exposure)
	if err != nil {
		_ = admission.Release()
		_ = manager.Close()
		return nil, fmt.Errorf("uninstall exposure lock is unavailable: %w", err)
	}
	if err := augmentCurrentLifecycleOwnership(paths, manager.Authority(), &inventory); err != nil {
		_ = exposure.Release()
		_ = admission.Release()
		_ = manager.Close()
		return nil, err
	}
	_ = exposure.Release()
	_ = admission.Release()
	_ = manager.Close()
	scope := append([]string(nil), inventory.Paths...)
	slices.Sort(scope)
	return slices.Compact(scope), nil
}

func uninstallCommitted(ctx context.Context, paths Paths, out io.Writer, expectedScope ...[]string) error {
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
	if err := augmentCurrentLifecycleOwnership(paths, manager.Authority(), &inventory); err != nil {
		return err
	}
	if len(expectedScope) > 0 {
		if !slices.Equal(inventory.Paths, expectedScope[0]) {
			return fmt.Errorf("uninstall deletion scope changed after confirmation")
		}
	}
	if err := stopOwnedServices(ctx, inventory.Paths); err != nil {
		return err
	}
	lifecycleInstallation, err := readLifecycleInstallation(paths, manager.Authority())
	if err != nil {
		return err
	}
	if err := verifyLifecycleIngressClosed(lifecycleInstallation); err != nil {
		return err
	}
	if err := verifyRuntimeIngressClosed(ctx, paths, lifecycleInstallation); err != nil {
		return err
	}
	if err := bindCurrentAuthorityArtifacts(paths, journal, commitBytes, &inventory); err != nil {
		return err
	}
	if err := stopOwnedServices(ctx, inventory.Paths); err != nil {
		return err
	}
	if err := verifyUnmaskTargets(ctx, inventory.Paths, inventory.Artifacts); err != nil {
		return err
	}
	accountRemoval, err := prepareOwnedAccounts(journal, lifecycleInstallation)
	if err != nil {
		return err
	}
	for index := len(inventory.Paths) - 1; index >= 0; index-- {
		path := inventory.Paths[index]
		if path == paths.BinaryPath || path == filepath.Dir(paths.BinaryPath) || path == filepath.Dir(publicCommandPath(paths)) || path == paths.Journal || path == paths.CommitPath || path == paths.StartupAuthority || path == ownershipInventoryPath(paths) || path == paths.OwnershipRoot || path == paths.LockRoot || path == paths.PersistentRoot || path == paths.StateRoot || path == filepath.Join(paths.StateRoot, "normal.json") || path == paths.SafetyRoot || path == filepath.Join(paths.SafetyRoot, "state.json") || path == paths.RuntimeRoot || path == paths.PackageRoot {
			continue // remove authority files only after every other postcondition.
		}
		if err := removeOwnedPath(path, inventory.Artifacts, inventory.MutablePaths); err != nil {
			return err
		}
	}
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("uninstall service fence reload failed: %w", err)
	}
	for _, stateFile := range []string{filepath.Join(paths.StateRoot, "normal.json"), filepath.Join(paths.SafetyRoot, "state.json")} {
		if err := removeOwnedPath(stateFile, inventory.Artifacts, inventory.MutablePaths); err != nil {
			return err
		}
	}
	for _, root := range []string{paths.StateRoot, paths.SafetyRoot, paths.RuntimeRoot, paths.PackageRoot} {
		if err := removeOwnedPath(root, inventory.Artifacts, inventory.MutablePaths); err != nil {
			return err
		}
	}
	if err := verifyOwnedFileIdentity(paths.BinaryPath, inventory.Artifacts); err != nil {
		return err
	}
	binaryInfo, err := os.Lstat(paths.BinaryPath)
	if err != nil {
		return fmt.Errorf("uninstall binary identity is unavailable: %w", err)
	}
	if err := verifyOwnedFileMetadata(paths.BinaryPath, binaryInfo); err != nil {
		return err
	}
	if err := accountRemoval.Remove(); err != nil {
		return err
	}
	retainFence := func(err error) error {
		_ = stopOwnedServices(ctx, inventory.Paths)
		return err
	}
	if err := unmaskOwnedServices(ctx, inventory.Paths); err != nil {
		return retainFence(err)
	}
	if err := removeOwnedPath(paths.Journal, inventory.Artifacts, inventory.MutablePaths); err != nil {
		return retainFence(err)
	}
	if err := removeOwnedPath(paths.CommitPath, inventory.Artifacts, inventory.MutablePaths); err != nil {
		return retainFence(err)
	}
	if err := removeOwnedPath(paths.StartupAuthority, inventory.Artifacts, inventory.MutablePaths); err != nil {
		return retainFence(err)
	}
	if err := removeOwnedPath(ownershipInventoryPath(paths), map[string]string{ownershipInventoryPath(paths): commit.OwnershipDigest}, nil); err != nil {
		return retainFence(err)
	}
	if err := removeOwnedPath(paths.OwnershipRoot, inventory.Artifacts, inventory.MutablePaths); err != nil {
		return retainFence(err)
	}
	if err := exposure.Release(); err != nil {
		return retainFence(fmt.Errorf("uninstall exposure lock release failed: %w", err))
	}
	if err := admission.Release(); err != nil {
		return retainFence(fmt.Errorf("uninstall mutation lock release failed: %w", err))
	}
	if err := manager.Close(); err != nil {
		return retainFence(fmt.Errorf("uninstall lock release failed: %w", err))
	}
	for _, lockName := range []string{"mutation-admission.lock", "exposure.lock"} {
		if err := removeOwnedLockFile(filepath.Join(paths.LockRoot, lockName)); err != nil {
			return retainFence(err)
		}
	}
	if err := removeOwnedPath(paths.LockRoot, inventory.Artifacts, inventory.MutablePaths); err != nil {
		return retainFence(err)
	}
	if err := removeOwnedPath(paths.PersistentRoot, inventory.Artifacts, inventory.MutablePaths); err != nil {
		return retainFence(err)
	}
	if err := os.Remove(paths.BinaryPath); err != nil {
		_ = stopOwnedServices(ctx, inventory.Paths)
		return fmt.Errorf("uninstall binary removal failed; fence retained: %w", err)
	}
	_, _ = fmt.Fprintln(out, "LanPanel uninstall completed; no APT/dpkg package was removed; package and service ownership not proven by this lifecycle remain retained.")
	return nil
}

func bindCurrentAuthorityArtifacts(paths Paths, journal Journal, commitBytes []byte, inventory *OwnershipInventory) error {
	freshStore, freshJournal, err := openJournal(paths.Journal, 0, 0)
	if err != nil {
		return fmt.Errorf("uninstall journal changed during teardown: %w", err)
	}
	_ = freshStore.close()
	if freshJournal.Sequence != journal.Sequence || freshJournal.FinalCommitDigest != journal.FinalCommitDigest {
		return fmt.Errorf("uninstall journal changed during teardown")
	}
	startup, err := ReadPublicStartupAuthority(paths)
	if err != nil {
		return err
	}
	expectedStartup := StartupAuthority{SchemaVersion: "lanpanel.startup-authority.v1", AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, Management: journal.Authority, CommitDigest: release.DigestBytes(commitBytes)}
	if startup != expectedStartup {
		return fmt.Errorf("uninstall startup authority differs from committed identity")
	}
	if inventory.Artifacts == nil {
		inventory.Artifacts = map[string]string{}
	}
	for _, path := range []string{paths.Journal, paths.CommitPath, paths.StartupAuthority} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > int64(journalFileBytes) {
			return fmt.Errorf("uninstall authority artifact is invalid at %q", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("uninstall authority artifact is unreadable at %q: %w", path, err)
		}
		if path == paths.CommitPath && release.DigestBytes(data) != release.DigestBytes(commitBytes) {
			return fmt.Errorf("uninstall commit authority changed during teardown")
		}
		inventory.Artifacts[path] = release.DigestBytes(data)
	}
	return nil
}

func verifyLifecycleIngressClosed(installation domain.Installation) error {
	for _, app := range installation.Resources {
		if app.PublicationRecord.State != domain.PublicationUnpublished || app.PublicationRecord.ActivationIntent != nil || app.PublicationRecord.ContractionIntent != nil {
			return fmt.Errorf("uninstall ingress is not closed for App %s", app.ID)
		}
		if app.ManagedProcess != nil && app.ManagedProcess.Requested != domain.ProcessRequestedStopped {
			return fmt.Errorf("uninstall managed process is not stopped for App %s", app.ID)
		}
	}
	return nil
}

func verifyRuntimeIngressClosed(ctx context.Context, paths Paths, installation domain.Installation) error {
	if paths == FixedPaths() {
		graph, err := nginx.Audit(nginx.FixedPaths(), filetxn.Owner{UID: 0, GID: 0})
		if err != nil {
			return fmt.Errorf("uninstall ingress graph is unavailable: %w", err)
		}
		for _, entry := range graph.Entries {
			if entry.Kind == nginx.EntryApp || entry.Kind == nginx.EntryTemporary {
				return fmt.Errorf("uninstall ingress graph still serves %s", entry.ResourceID)
			}
		}
	}
	for _, app := range installation.Resources {
		if app.ManagedProcess == nil || app.ManagedProcess.Applied == nil {
			continue
		}
		if _, err := process.ObserveStopped(ctx, "/sys/fs/cgroup", *app.ManagedProcess.Applied); err != nil {
			return fmt.Errorf("uninstall process closure is unproven for App %s: %w", app.ID, err)
		}
	}
	return nil
}

func augmentCurrentLifecycleOwnership(paths Paths, authority locks.Authority, inventory *OwnershipInventory) error {
	if inventory == nil {
		return fmt.Errorf("uninstall lifecycle inventory is missing")
	}
	store, err := persist.Open(persist.Config{RootPath: paths.StateRoot, StagingPath: filepath.Join(paths.StateRoot, ".filetxn"), StatePath: filepath.Join(paths.StateRoot, "normal.json"), Owner: structOwner(), LockAuthority: authority})
	if err != nil {
		return fmt.Errorf("uninstall lifecycle state is unavailable: %w", err)
	}
	defer func() { _ = store.Close() }()
	document, err := store.Read()
	if err != nil {
		return fmt.Errorf("uninstall lifecycle state is unreadable: %w", err)
	}
	installation, present, err := persist.DecodeEntry[domain.Installation](document, "installations/current")
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("uninstall lifecycle installation authority is missing")
	}
	known := make(map[string]bool, len(inventory.Paths))
	for _, path := range inventory.Paths {
		known[path] = true
	}
	mutable := make(map[string]bool, len(inventory.MutablePaths))
	for _, path := range inventory.MutablePaths {
		mutable[path] = true
	}
	add := func(path string, mutablePath bool) error {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("uninstall lifecycle ownership path is invalid")
		}
		if !known[path] {
			inventory.Paths = append(inventory.Paths, path)
			known[path] = true
		}
		if mutablePath && !mutable[path] {
			inventory.MutablePaths = append(inventory.MutablePaths, path)
			mutable[path] = true
		}
		if _, bound := inventory.Artifacts[path]; !bound {
			info, statErr := os.Lstat(path)
			if statErr == nil && info.Mode().IsRegular() {
				if info.Size() < 0 || info.Size() > MaximumJournalBytes {
					return fmt.Errorf("uninstall augmented artifact is too large at %q", path)
				}
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return fmt.Errorf("uninstall augmented artifact is unreadable at %q: %w", path, readErr)
				}
				if inventory.Artifacts == nil {
					inventory.Artifacts = map[string]string{}
				}
				inventory.Artifacts[path] = release.DigestBytes(data)
			}
		}

		return nil
	}
	addList := func(values []string, mutablePath bool) error {
		for _, value := range values {
			if err := add(value, mutablePath); err != nil {
				return err
			}
		}
		return nil
	}
	addManagedTree := func(root string) error {
		if !known[root] {
			if err := add(root, true); err != nil {
				return err
			}
		}
		count := 0
		return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("uninstall lifecycle staging contains a symlink")
			}
			if path != root && !known[path] {
				return fmt.Errorf("uninstall lifecycle staging contains foreign residue at %q", path)
			}
			count++
			if count > 4096 {
				return fmt.Errorf("uninstall lifecycle staging exceeds its fixed bound")
			}
			return add(path, true)
		})
	}
	for _, root := range []string{
		filepath.Join(paths.PersistentRoot, ".bootstrap-filetxn"), filepath.Join(paths.PersistentRoot, ".lanpanel-filetxn"), "/etc/.lanpanel-filetxn", "/usr/local/bin/.lanpanel-filetxn", filepath.Join(paths.StateRoot, ".filetxn"), filepath.Join(paths.SafetyRoot, ".filetxn"), filepath.Join(paths.OwnershipRoot, ".filetxn"), filepath.Join(paths.OwnershipRoot, "records"), filepath.Join(paths.PackageRoot, ".filetxn"), filepath.Join(paths.PackageRoot, "journals"), filepath.Join(paths.PackageRoot, "plans"), filepath.Join(paths.PackageRoot, "transactions"), filepath.Join(paths.PackageRoot, "staging"), "/etc/lanpanel/.lanpanel-filetxn", "/usr/lib/lanpanel/.lanpanel-filetxn", "/usr/sbin/.lanpanel-filetxn", "/etc/sysusers.d/.lanpanel-filetxn", "/etc/systemd/system/.lanpanel-filetxn", "/etc/lanpanel-public/basic/.txn", filepath.Join(paths.SafetyRoot, "process"), filepath.Join(paths.SafetyRoot, "resource-create"), filepath.Join(paths.SafetyRoot, "resource-update"), filepath.Join(paths.SafetyRoot, "managed-basic"), "/etc/lanpanel-headscale/.lanpanel-filetxn", "/etc/systemd/system/.lanpanel-headscale-filetxn", "/etc/lanpanel/nginx/.lanpanel-filetxn", filepath.Join(paths.StateRoot, ".lanpanel-contraction-filetxn"), "/var/lib/lanpanel/headscale/identity/.identity.lanpanel-staging", "/var/lib/lanpanel/headscale/journal/.lanpanel-filetxn",
	} {
		if err := addManagedTree(root); err != nil {
			return err
		}
	}
	if installation.Headscale != nil {
		if err := addList(installation.Headscale.ManagedPaths, true); err != nil {
			return err
		}
		if installation.Headscale.Applied != nil {
			if err := addList([]string{installation.Headscale.Database.SQLitePath, "/var/lib/lanpanel/headscale/identity/database-uuid", "/var/lib/lanpanel/headscale/identity/snapshot.json"}, true); err != nil {
				return err
			}
		}
	}
	if installation.Connector != nil {
		if err := addList(append(append([]string(nil), installation.Connector.ManagedPaths...), "/var/lib/lanpanel/connector/auth"), true); err != nil {
			return err
		}
	}
	for _, credential := range installation.Credentials {
		if credential.ManagedPath != "" {
			if err := add(credential.ManagedPath, true); err != nil {
				return err
			}
		}
	}
	for _, app := range installation.Resources {
		derived, err := appresource.DerivePaths(app.ID)
		if err != nil {
			return err
		}
		if err := addList(derived.ManagedPaths(), true); err != nil {
			return err
		}
		for _, link := range []string{
			filepath.Join("/etc/systemd/system/multi-user.target.wants", derived.ServiceUnit),
			filepath.Join("/etc/systemd/system/multi-user.target.wants", derived.RelayUnit),
			filepath.Join("/etc/systemd/system/sockets.target.wants", derived.SocketUnit),
			filepath.Join("/etc/systemd/system/sockets.target.wants", derived.BackendSocketUnit),
		} {
			if err := add(link, true); err != nil {
				return err
			}
		}
		if app.ManagedProcess != nil && app.ManagedProcess.Applied != nil {
			if err := addList(app.ManagedProcess.Applied.ManagedPaths, true); err != nil {
				return err
			}
			applied := app.ManagedProcess.Applied
			for path, digest := range map[string]string{
				filepath.Join("/etc/systemd/system", derived.ServiceUnit): applied.UnitDigest,
				filepath.Join("/etc/systemd/system", derived.SocketUnit):  applied.SocketUnitDigest,
				filepath.Join("/etc/systemd/system", derived.PolicyUnit):  applied.PolicyDigest,
			} {
				if release.ValidDigest(digest) {
					if inventory.Artifacts == nil {
						inventory.Artifacts = map[string]string{}
					}
					inventory.Artifacts[path] = digest
				}
			}
			for _, unit := range app.ManagedProcess.Applied.EndpointSocketUnits {
				if unit == "" || filepath.Base(unit) != unit || strings.ContainsAny(unit, `/\\`) {
					return fmt.Errorf("uninstall lifecycle unit identity is invalid")
				}
				if err := add(filepath.Join("/etc/systemd/system", unit), true); err != nil {
					return err
				}
			}
		}
		bundles := []*domain.PublicationBundle{app.PublicationRecord.LastAppliedBundle}
		if intent := app.PublicationRecord.ActivationIntent; intent != nil {
			bundles = append(bundles, &intent.Candidate, intent.Prior)
		}
		if intent := app.PublicationRecord.ContractionIntent; intent != nil {
			bundles = append(bundles, intent.Candidate, intent.Prior)
		}
		for _, bundle := range bundles {
			if bundle != nil {
				if err := addList(bundle.ManagedPaths, true); err != nil {
					return err
				}
			}
			if err := addBundleGoAccess(app.ID, bundle, addList); err != nil {
				return err
			}
		}
		for _, retirement := range app.PublicationRecord.PendingGoAccessRetirements {
			if err := addGoAccessGeneration(app.ID, retirement.Generation, retirement.StateGeneration, addList); err != nil {
				return err
			}
		}
		for _, artifact := range app.PublicationRecord.CertificateInventory {
			bundle, err := certificates.BundlePath(artifact.CertificateID, artifact.Generation)
			if err != nil {
				return err
			}
			if err := addList([]string{bundle, filepath.Join(certificates.FixedBundlesRoot, "."+filepath.Base(bundle)+".lanpanel-staging"), filepath.Join(certificates.FixedActiveRoot, artifact.CertificateID+".current"), filepath.Join("/var/lib/lanpanel/certificates/chroot", artifact.CertificateID), filepath.Join("/var/lib/lanpanel/certificates/webroot", artifact.CertificateID)}, true); err != nil {
				return err
			}
			for _, member := range []string{"certificate.pem", "identity.json", "private-key.pem"} {
				if err := add(bundle+string(filepath.Separator)+member, true); err != nil {
					return err
				}
			}
			if inventory.Artifacts == nil {
				inventory.Artifacts = map[string]string{}
			}
			inventory.Artifacts[bundle] = ""
		}
	}
	slices.Sort(inventory.Paths)
	inventory.Paths = slices.Compact(inventory.Paths)
	slices.Sort(inventory.MutablePaths)
	inventory.MutablePaths = slices.Compact(inventory.MutablePaths)
	return nil
}

func structOwner() filetxn.Owner { return filetxn.Owner{UID: 0, GID: 0} }

func readLifecycleInstallation(paths Paths, authority locks.Authority) (domain.Installation, error) {
	store, err := persist.Open(persist.Config{RootPath: paths.StateRoot, StagingPath: filepath.Join(paths.StateRoot, ".filetxn"), StatePath: filepath.Join(paths.StateRoot, "normal.json"), Owner: structOwner(), LockAuthority: authority})
	if err != nil {
		return domain.Installation{}, fmt.Errorf("uninstall lifecycle state is unavailable: %w", err)
	}
	defer func() { _ = store.Close() }()
	document, err := store.Read()
	if err != nil {
		return domain.Installation{}, fmt.Errorf("uninstall lifecycle state is unreadable: %w", err)
	}
	installation, present, err := persist.DecodeEntry[domain.Installation](document, "installations/current")
	if err != nil {
		return domain.Installation{}, err
	}
	if !present {
		return domain.Installation{}, nil
	}
	return installation, nil
}

func addBundleGoAccess(resourceID string, bundle *domain.PublicationBundle, addList func([]string, bool) error) error {
	if bundle == nil || bundle.DomainHTTPS == nil {
		return nil
	}
	return addGoAccessOwnership(resourceID, bundle.DomainHTTPS.GoAccess, addList)
}

func addGoAccessOwnership(resourceID string, value domain.GoAccessBundleIdentity, addList func([]string, bool) error) error {
	if !value.Enabled {
		return nil
	}
	if err := addGoAccessGeneration(resourceID, value.Generation, value.StateGeneration, addList); err != nil {
		return err
	}
	return addGoAccessGeneration(resourceID, value.RetiredGeneration, value.RetiredStateGeneration, addList)
}

func addGoAccessGeneration(resourceID string, generation, stateGeneration uint64, addList func([]string, bool) error) error {
	if generation == 0 {
		return nil
	}
	if stateGeneration == 0 {
		stateGeneration = generation
	}
	paths, err := goaccess.DerivePaths(resourceID, generation)
	if err != nil {
		return err
	}
	statePaths, err := goaccess.DerivePaths(resourceID, stateGeneration)
	if err != nil {
		return err
	}
	paths.StateRoot, paths.Database, paths.Report = statePaths.StateRoot, statePaths.Database, statePaths.Report
	return addList([]string{paths.ResourceRoot, paths.StateRoot, paths.Database, paths.Report, paths.AccessLog, paths.RetainedLog, paths.RetentionOld, paths.RetentionNew, paths.RetentionState, paths.RetentionStateTemp, paths.RetentionTemp, paths.Endpoint, paths.ServiceUnit, paths.ServiceEnablement, paths.RelayUnit, paths.RelayEnablement, paths.SocketUnit, paths.SocketEnablement, paths.Sysusers, paths.RetentionUnit, paths.RetentionTimer, paths.RetentionEnablement, paths.RetentionLock, "/var/log/lanpanel/goaccess/.retention-reopen.lock"}, true)
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

func verifyUnmaskTargets(ctx context.Context, paths []string, artifacts map[string]string) error {
	owned := make(map[string]bool, len(paths)+len(artifacts))
	for _, path := range paths {
		owned[path] = true
	}
	for path := range artifacts {
		owned[path] = true
	}
	for _, path := range paths {
		base := filepath.Base(path)
		if !strings.HasSuffix(base, ".service") && !strings.HasSuffix(base, ".socket") && !strings.HasSuffix(base, ".timer") {
			continue
		}
		output, err := exec.CommandContext(ctx, "systemctl", "show", "--property=FragmentPath", "--value", base).Output()
		if err != nil {
			for _, candidate := range paths {
				if filepath.Base(candidate) == base {
					if _, statErr := os.Lstat(candidate); statErr == nil {
						return fmt.Errorf("uninstall cannot inspect unit %s: %w", base, err)
					}
				}
			}
			continue
		}
		fragment := strings.TrimSpace(string(output))
		if fragment != "" && !owned[fragment] {
			return fmt.Errorf("uninstall cannot clear fence for foreign unit %s", base)
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
		if err := exec.CommandContext(ctx, "systemctl", "unmask", "--runtime", unit).Run(); err != nil {
			return fmt.Errorf("uninstall could not clear fence for %s: %w", unit, err)
		}
	}
	return nil
}

type ownedAccountRemoval struct {
	sets         []identity.AccountSet
	resourceSets []identity.ResourceAccountSet
}

func prepareOwnedAccounts(journal Journal, installation domain.Installation) (ownedAccountRemoval, error) {
	sets := []identity.AccountSet{journal.Accounts}
	if data, err := os.ReadFile("/etc/sysusers.d/lanpanel-headscale.conf"); err == nil {
		match := regexp.MustCompile(`(?m)^u ([^ ]+) -:[^ ]+ "([^"]+)" /nonexistent /usr/sbin/nologin$`).FindSubmatch(data)
		if len(match) != 3 || !strings.Contains(string(match[2]), " headscale ") {
			return ownedAccountRemoval{}, fmt.Errorf("uninstall Headscale account authority is invalid")
		}
		fields := strings.Fields(string(match[2]))
		if len(fields) != 4 || fields[0] != "LanPanel" || fields[1] != journal.InstallationID || fields[2] != "headscale" || !strings.HasPrefix(string(match[1]), "lp-") {
			return ownedAccountRemoval{}, fmt.Errorf("uninstall Headscale account authority is foreign")
		}
		set, err := identity.HeadscaleAccounts(journal.InstallationID, fields[3])
		if err != nil || set.Specs[0].User != string(match[1]) || set.Specs[0].Comment != string(match[2]) {
			return ownedAccountRemoval{}, fmt.Errorf("uninstall Headscale account authority is foreign")
		}
		expected, err := identity.RenderSysusers(set)
		if err != nil || !bytes.Equal(expected, data) {
			return ownedAccountRemoval{}, fmt.Errorf("uninstall Headscale account authority is foreign")
		}
		sets = append(sets, set)
	} else if errors.Is(err, os.ErrNotExist) {
		if installation.Headscale != nil {
			set, setErr := identity.HeadscaleAccounts(installation.InstallationID, installation.Headscale.ID)
			if setErr != nil {
				return ownedAccountRemoval{}, setErr
			}
			present, evidenceErr := identity.PartialAccountEvidencePresent(set)
			if evidenceErr != nil {
				return ownedAccountRemoval{}, fmt.Errorf("uninstall cannot inspect Headscale account evidence: %w", evidenceErr)
			}
			if present {
				return ownedAccountRemoval{}, fmt.Errorf("uninstall Headscale account authority is missing while account evidence remains")
			}
		}
	} else {
		return ownedAccountRemoval{}, fmt.Errorf("uninstall cannot inspect Headscale account authority: %w", err)
	}
	for _, set := range sets {
		complete, _, err := identity.InspectPartialAccounts(set)
		if err != nil {
			return ownedAccountRemoval{}, fmt.Errorf("uninstall account ownership is incomplete: %w", err)
		}
		if complete {
			continue
		}
		if _, presentErr := identity.PartialAccountEvidencePresent(set); presentErr != nil {
			return ownedAccountRemoval{}, fmt.Errorf("uninstall account ownership is incomplete: %w", presentErr)
		}
	}
	removal := ownedAccountRemoval{sets: sets}
	for _, resource := range installation.Resources {
		set, err := identity.ResourceAccounts(installation.InstallationID, resource.ID, resource.ManagedProcess != nil && resource.ManagedProcess.Applied != nil && resource.ManagedProcess.Applied.RelayRequired)
		if err != nil {
			return ownedAccountRemoval{}, err
		}
		present, identities, err := identity.InspectResourceAccountFiles(set, "/etc/passwd", "/etc/group", "/etc/shadow")
		if err != nil {
			return ownedAccountRemoval{}, err
		}
		if present {
			set.Identities = identities
			removal.resourceSets = append(removal.resourceSets, set)
		}
		ga, err := identity.GoAccessAccounts(installation.InstallationID, resource.ID)
		if err != nil {
			return ownedAccountRemoval{}, err
		}
		gaPresent, gaIdentities, err := identity.InspectResourceAccountFiles(ga, "/etc/passwd", "/etc/group", "/etc/shadow")
		if err != nil {
			return ownedAccountRemoval{}, err
		}
		if gaPresent {
			ga.Identities = gaIdentities
			removal.resourceSets = append(removal.resourceSets, ga)
		}
	}
	return removal, nil
}

func (removal ownedAccountRemoval) Remove() error {
	users := map[string]bool{}
	groups := map[string]bool{}
	addSpec := func(spec identity.AccountSpec) {
		users[spec.User] = true
		groups[spec.Group] = true
	}
	for _, set := range removal.sets {
		for _, spec := range set.Specs {
			addSpec(spec)
		}
	}
	for _, set := range removal.resourceSets {
		addSpec(set.Application)
		if set.Relay != nil {
			addSpec(*set.Relay)
		}
	}
	for name := range users {
		if _, lookupErr := osuser.Lookup(name); lookupErr == nil {
			if err := exec.Command("userdel", "--system", name).Run(); err != nil {
				return fmt.Errorf("uninstall could not remove owned account %s: %w", name, err)
			}
		} else if _, ok := lookupErr.(osuser.UnknownUserError); !ok {
			return fmt.Errorf("uninstall could not inspect owned account %s: %w", name, lookupErr)
		}
	}
	for name := range groups {
		if _, lookupErr := osuser.LookupGroup(name); lookupErr == nil {
			if err := exec.Command("groupdel", name).Run(); err != nil {
				return fmt.Errorf("uninstall could not remove owned group %s: %w", name, err)
			}
		} else if _, ok := lookupErr.(osuser.UnknownGroupError); !ok {
			return fmt.Errorf("uninstall could not inspect owned group %s: %w", name, lookupErr)
		}
	}
	return nil
}

func verifyOwnedFileIdentity(path string, artifacts map[string]string) error {
	want, ok := artifacts[path]
	if !ok {
		return fmt.Errorf("uninstall binary ownership digest is missing")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("uninstall binary is missing or foreign")
	}
	data, err := os.ReadFile(path)
	if err != nil || release.DigestBytes(data) != want {
		return fmt.Errorf("uninstall binary differs from committed ownership")
	}
	return nil
}

func mutableCertificatePointer(path, target string, owned map[string]string) bool {
	if !strings.HasPrefix(path, "/var/lib/lanpanel/certificates/active/") || filepath.Base(path) == "." || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return false
	}
	if _, ok := owned[target]; ok {
		return true
	}
	return false
}

func mutableEnablementTarget(path, target string, artifacts map[string]string) bool {
	if target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target || strings.Contains(target, "\\x00") {
		return false
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
	base := filepath.Base(path)
	if filepath.Base(resolved) != base {
		return false
	}
	_, owned := artifacts[resolved]
	return owned
}

func mutableServiceOwnedPath(path string) bool {
	for _, root := range []string{"/var/lib/lanpanel/headscale-runtime", "/var/lib/lanpanel/headscale-control", "/var/lib/lanpanel/certificates/", "/var/lib/lanpanel/headscale/", "/var/lib/lanpanel/resources/", "/var/lib/lanpanel/goaccess/", "/var/log/lanpanel/goaccess/", "/run/lanpanel/apps/", "/run/lanpanel-goaccess/"} {
		if path == strings.TrimSuffix(root, "/") || strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
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

func verifyOwnedFileMetadata(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("uninstall foreign file metadata at %q", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (stat.Uid != 0 || stat.Gid != 0) && !mutableServiceOwnedPath(path) {
		return fmt.Errorf("uninstall foreign file ownership at %q", path)
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
		if err == nil && target == "/dev/null" && artifacts[path] == release.DigestBytes([]byte("/dev/null")) {
			return os.Remove(path)
		}
		if slices.Contains(mutable, path) && err == nil && (mutableEnablementTarget(path, target, artifacts) || mutableCertificatePointer(path, target, artifacts)) {
			return os.Remove(path)
		}
		return fmt.Errorf("uninstall foreign residue at %q", path)
	}
	if info.IsDir() {
		if info.Mode()&0o022 != 0 {
			return fmt.Errorf("uninstall foreign directory metadata at %q", path)
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || (stat.Uid != 0 || stat.Gid != 0) && !mutableServiceOwnedPath(path) {
			return fmt.Errorf("uninstall foreign directory ownership at %q", path)
		}
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
		if err := verifyOwnedFileMetadata(path, info); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil || release.DigestBytes(data) != digest {
			return fmt.Errorf("uninstall foreign residue at %q", path)
		}
	} else if slices.Contains(mutable, path) {
		if info.Mode().IsRegular() {
			return fmt.Errorf("uninstall ownership digest is missing for %q", path)
		}
		if info.Mode()&0o022 != 0 {
			return fmt.Errorf("uninstall foreign residue at %q", path)
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || (stat.Uid != 0 || stat.Gid != 0) && !mutableServiceOwnedPath(path) {
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
