//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
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
	external := filepath.Join(t.TempDir(), "application-data")
	if err := os.WriteFile(external, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	installFixtureState(t, paths)
	commandLog := filepath.Join(t.TempDir(), "commands.log")
	systemctl := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \""+commandLog+"\"\ncase \"$1\" in is-active|show) exit 1;; *) exit 0;; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(systemctl)+string(os.PathListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	if err := uninstallCommitted(context.Background(), paths, &output); err != nil {
		t.Fatalf("isolated uninstall failed: %v\n%s", err, output.String())
	}
	if _, err := os.Stat(external); err != nil {
		t.Fatalf("external file was not preserved: %v", err)
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

func installFixtureState(t *testing.T, paths Paths) {
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
	writeFixtureInstallation(t, paths)
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

func writeFixtureInstallation(t *testing.T, paths Paths) {
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
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 23456}}
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
