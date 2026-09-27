//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommittedUninstallFixtureRemovesOwnedStateAndPreservesExternalFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle fixture")
	}
	root := t.TempDir()
	paths := testPaths(root)
	for _, directory := range []string{paths.InstallationRoot, paths.StateRoot, filepath.Join(paths.StateRoot, ".filetxn"), paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, filepath.Dir(paths.BinaryPath), paths.SystemdRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	externalRoot := t.TempDir()
	externalExecutable := filepath.Join(externalRoot, "app")
	externalEnvironment := filepath.Join(externalRoot, "app.env")
	externalHTPasswd := filepath.Join(externalRoot, "users.htpasswd")
	externalLog := filepath.Join(externalRoot, "access.log")
	for _, path := range []string{externalExecutable, externalEnvironment, externalHTPasswd, externalLog} {
		if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	installFixtureState(t, paths, externalExecutable, externalEnvironment, externalHTPasswd, externalLog)
	commandLog := filepath.Join(t.TempDir(), "commands.log")
	systemctl := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >> \""+commandLog+"\"\ncase \"$1\" in is-active|show) exit 1;; *) exit 0;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"apt", "apt-get", "dpkg"} {
		wrapper := filepath.Join(filepath.Dir(systemctl), name)
		if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nprintf '"+name+" %s\\n' \"$*\" >> \""+commandLog+"\"\nexit 99\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", filepath.Dir(systemctl)+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	if err := uninstallCommitted(context.Background(), paths, &output); err != nil {
		t.Fatalf("isolated uninstall failed: %v\n%s", err, output.String())
	}
	for _, path := range []string{externalExecutable, externalEnvironment, externalHTPasswd, externalLog} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("external file was not preserved: %s: %v", path, err)
		}
	}
	if _, err := os.Stat(paths.PersistentRoot); !os.IsNotExist(err) {
		t.Fatalf("owned persistent root remains: %v", err)
	}
	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), "apt") || strings.Contains(string(commands), "dpkg") {
		t.Fatalf("APT/dpkg command was invoked: %s", commands)
	}
}

func TestCommittedUninstallFixtureRejectsStartupAuthorityDrift(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle fixture")
	}
	root := t.TempDir()
	paths := testPaths(root)
	for _, directory := range []string{paths.InstallationRoot, paths.StateRoot, filepath.Join(paths.StateRoot, ".filetxn"), paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, filepath.Dir(paths.BinaryPath), paths.SystemdRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	installFixtureState(t, paths)
	startup, err := ReadPublicStartupAuthority(paths)
	if err != nil {
		t.Fatal(err)
	}
	startup.Management.Address = "127.1.1.2"
	data, err := encodeCanonical(startup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StartupAuthority, data, 0o640); err != nil {
		t.Fatal(err)
	}
	systemctl := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\ncase \"$1\" in is-active|show) exit 1;; *) exit 0;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(systemctl)+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	if err := uninstallCommitted(context.Background(), paths, &output); err == nil || !strings.Contains(err.Error(), "startup authority") {
		t.Fatalf("startup authority drift was accepted: %v", err)
	}
	if _, err := os.Stat(paths.CommitPath); err != nil {
		t.Fatalf("commit authority was not retained: %v", err)
	}
}

func TestPublicUninstallFixtureRequiresExactPTYConfirmation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle fixture")
	}
	root := t.TempDir()
	paths := testPaths(root)
	for _, directory := range []string{paths.InstallationRoot, paths.StateRoot, filepath.Join(paths.StateRoot, ".filetxn"), paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, filepath.Dir(paths.BinaryPath), paths.SystemdRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	installFixtureState(t, paths)
	systemctl := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\ncase \"$1\" in is-active|show) exit 1;; *) exit 0;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(systemctl)+string(os.PathListSeparator)+os.Getenv("PATH"))
	master, slave := openFixturePTY(t, "UNINSTALL WRONG\n")
	var output bytes.Buffer
	if err := runPublicUninstallAt(nil, slave, &output, paths); err == nil || !strings.Contains(err.Error(), "exact confirmation") {
		t.Fatalf("wrong PTY confirmation was accepted: %v", err)
	}
	_ = slave.Close()
	_ = master.Close()
	master, slave = openFixturePTY(t, "UNINSTALL LANPANEL\n")
	output.Reset()
	if err := runPublicUninstallAt(nil, slave, &output, paths); err != nil {
		t.Fatalf("exact PTY confirmation failed: %v", err)
	}
	_ = slave.Close()
	_ = master.Close()
	if _, err := os.Stat(paths.PersistentRoot); !os.IsNotExist(err) {
		t.Fatalf("public uninstall did not remove fixture root: %v", err)
	}
}

func openFixturePTY(t *testing.T, input string) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = master.Close()
		t.Fatalf("unlock ptmx: %v", err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = master.Close()
		t.Fatalf("get pty number: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR, 0)
	if err != nil {
		_ = master.Close()
		t.Fatal(err)
	}
	if _, err := master.WriteString(input); err != nil {
		_ = slave.Close()
		_ = master.Close()
		t.Fatal(err)
	}
	return master, slave
}

func TestCommittedUninstallFixtureLateUnmaskFailureKeepsBinary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle fixture")
	}
	root := t.TempDir()
	paths := testPaths(root)
	for _, directory := range []string{paths.InstallationRoot, paths.StateRoot, filepath.Join(paths.StateRoot, ".filetxn"), paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, filepath.Dir(paths.BinaryPath), paths.SystemdRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	installFixtureState(t, paths)
	systemctl := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\ncase \"$1\" in is-active|show) exit 1;; unmask) exit 99;; *) exit 0;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(systemctl)+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	if err := uninstallCommitted(context.Background(), paths, &output); err == nil || !strings.Contains(err.Error(), "clear fence") {
		t.Fatalf("late unmask failure was not reported: %v", err)
	}
	if _, err := os.Stat(paths.BinaryPath); err != nil {
		t.Fatalf("binary was deleted before final unmask succeeded: %v", err)
	}
}

func TestRetainExternalResourcePathAcceptsOnlyAuthorizedResourceRoots(t *testing.T) {
	persistent := t.TempDir()
	resourceID := "res_" + strings.Repeat("0", 32)
	resourceParent := filepath.Join(persistent, "resources")
	resourceRoot := filepath.Join(resourceParent, resourceID)
	if err := os.MkdirAll(filepath.Join(resourceRoot, "backend"), 0o700); err != nil {
		t.Fatal(err)
	}
	installation := domain.Installation{Resources: []domain.AppResource{{ID: resourceID}}}
	for _, path := range []string{resourceRoot, filepath.Join(resourceRoot, "backend"), resourceParent, persistent} {
		if !retainExternalResourcePath(path, persistent, installation) {
			t.Fatalf("authorized retained path was rejected: %s", path)
		}
	}
	if err := os.Mkdir(filepath.Join(persistent, "foreign"), 0o700); err != nil {
		t.Fatal(err)
	}
	if retainExternalResourcePath(persistent, persistent, installation) {
		t.Fatal("foreign persistent residue was accepted")
	}
}

func TestCommittedUninstallFixtureForeignResidueFailsAndRetries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle fixture")
	}
	root := t.TempDir()
	paths := testPaths(root)
	for _, directory := range []string{paths.InstallationRoot, paths.StateRoot, filepath.Join(paths.StateRoot, ".filetxn"), paths.SafetyRoot, paths.OwnershipRoot, paths.LockRoot, paths.PackageRoot, paths.RuntimeRoot, filepath.Dir(paths.BinaryPath), paths.SystemdRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	installFixtureState(t, paths)
	staging := filepath.Join(paths.PersistentRoot, ".bootstrap-filetxn")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(staging, "foreign-residue")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	systemctl := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\ncase \"$1\" in is-active|show) exit 1;; *) exit 0;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(systemctl)+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	if err := uninstallCommitted(context.Background(), paths, &output); err == nil {
		t.Fatal("foreign residue did not fail closed")
	}
	if _, err := os.Stat(paths.CommitPath); err != nil {
		t.Fatalf("commit authority was not retained after failure: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign residue was removed: %v", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if err := uninstallCommitted(context.Background(), paths, &output); err != nil {
		t.Fatalf("retry after residue removal failed: %v", err)
	}
}

func installFixtureState(t *testing.T, paths Paths, externalPaths ...string) {
	t.Helper()
	journal := testJournal(paths.PersistentRoot)
	planned, err := plannedBootstrapPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	journal.PlannedPaths = planned
	binary := []byte("fixture-lanpanel-binary")
	journal.Release.Binary.Bytes = uint64(len(binary))
	journal.Release.Binary.Digest = release.DigestBytes(binary)
	journal.ArtifactDigests["release_binary"] = release.DigestBytes(binary)
	if err := os.WriteFile(paths.BinaryPath, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := acmeaccount.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ACMEAccountKey, key, 0o600); err != nil {
		t.Fatal(err)
	}
	keyFingerprint, err := acmeaccount.Fingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := identityFingerprint(journal.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{SchemaVersion: BundleSchemaVersion, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, SafetyGeneration: journal.SafetyGeneration, Fingerprint: fingerprint, Management: journal.Authority, Release: journal.Release, PreflightDigest: journal.PreflightDigest, ACMEAccountKeyFingerprint: keyFingerprint}
	bundleBytes, err := encodeCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.InstallationRoot, "bundle.json"), bundleBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct {
		name string
		mode os.FileMode
		data string
	}{{"admin-token", 0o600, "fixture-admin"}, {"default-rejection.crt", 0o644, "fixture-crt"}, {"default-rejection.key", 0o600, "fixture-key"}, {"host-fingerprint", 0o600, "fixture-host"}, {"os-profile.digest", 0o600, "fixture-profile"}, {"release-authority.digest", 0o600, "fixture-authority"}} {
		if err := os.WriteFile(filepath.Join(paths.InstallationRoot, file.name), []byte(file.data), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	journalStore, err := createJournal(paths.Journal, 0, 0, journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.Sequence = 2
	journal.Phase = PhaseActivated
	journalStoreValue := journal
	if err := journalStore.update(journalStoreValue); err != nil {
		_ = journalStore.close()
		t.Fatal(err)
	}
	if err := journalStore.close(); err != nil {
		t.Fatal(err)
	}
	writeFixtureInstallation(t, paths, externalPaths...)
	inventory, inventoryBytes, inventoryDigest, err := buildOwnershipInventory(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownershipInventoryPath(paths), inventoryBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	commit := Commit{SchemaVersion: CommitSchemaVersion, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, JournalSequence: journal.Sequence + 1, BundleDigest: release.DigestBytes(bundleBytes), ArtifactDigest: artifactInventoryDigest(journal.ArtifactDigests), OwnershipDigest: inventoryDigest, CommittedAt: time.Unix(1_700_000_000, 0).UTC()}
	commitBytes, err := encodeCanonical(commit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.CommitPath, commitBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	startup := StartupAuthority{SchemaVersion: "lanpanel.startup-authority.v1", AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, Management: journal.Authority, CommitDigest: release.DigestBytes(commitBytes)}
	startupBytes, err := encodeCanonical(startup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StartupAuthority, startupBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	journalStore, _, err = openJournal(paths.Journal, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	journal.Sequence++
	journal.FinalCommitDigest = release.DigestBytes(commitBytes)
	if err := journalStore.update(journal); err != nil {
		_ = journalStore.close()
		t.Fatal(err)
	}
	if err := journalStore.close(); err != nil {
		t.Fatal(err)
	}
	manager, err := locks.Open(locks.Config{RootPath: paths.LockRoot, Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		_ = manager.Close()
		t.Fatal(err)
	}
	store, err := persist.Open(persist.Config{RootPath: paths.StateRoot, StagingPath: filepath.Join(paths.StateRoot, ".filetxn"), StatePath: filepath.Join(paths.StateRoot, "normal.json"), Owner: structOwner(), LockAuthority: manager.Authority()})
	if err != nil {
		_ = lease.Release()
		_ = manager.Close()
		t.Fatal(err)
	}
	if _, err := store.Initialize(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_ = inventory
}

func writeFixtureInstallation(t *testing.T, paths Paths, externalPaths ...string) {
	t.Helper()
	manager, err := locks.Open(locks.Config{RootPath: paths.LockRoot, Owner: 0, Group: 0, Mode: 0o700})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire(context.Background(), locks.MutationAdmission)
	if err != nil {
		_ = manager.Close()
		t.Fatal(err)
	}
	store, err := persist.Open(persist.Config{RootPath: paths.StateRoot, StagingPath: filepath.Join(paths.StateRoot, ".filetxn"), StatePath: filepath.Join(paths.StateRoot, "normal.json"), Owner: structOwner(), LockAuthority: manager.Authority()})
	if err != nil {
		_ = lease.Release()
		_ = manager.Close()
		t.Fatal(err)
	}
	if _, err := store.Initialize(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 23456}, ManagedPaths: append([]string(nil), externalPaths...)}
	raw, err := persist.EncodeEntry(installation)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Update(context.Background(), lease, 1, func(transaction *persist.Transaction) error { return transaction.Create("installations/current", raw) }); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func identityFingerprint(value string) (string, error) {
	return identity.Fingerprint(value)
}
