//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/control"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"slices"
)

const ownershipInventorySchema = "lanpanel.bootstrap.ownership.v1"

func ownershipInventoryPath(paths Paths) string {
	return filepath.Join(paths.OwnershipRoot, "installation.json")
}

func mutableOwnershipPaths(paths Paths) []string {
	values := []string{paths.Journal, paths.CommitPath, paths.StartupAuthority, filepath.Join(paths.StateRoot, "normal.json"), filepath.Join(paths.SafetyRoot, "state.json"), filepath.Join(paths.InstallationRoot, "acme-account.contact"), "/var/log/lanpanel/goaccess/.retention-reopen.lock"}
	for _, name := range []string{"lanpanel-runtime.service", "lanpanel-helper.service", "lanpanel-ui.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"} {
		values = append(values, filepath.Join(paths.SystemdRoot, "multi-user.target.wants", name))
	}
	values = append(values, filepath.Join(paths.SystemdRoot, "sockets.target.wants", "lanpanel-management.socket"))
	if paths == FixedPaths() {
		controlPaths := control.FixedPaths()
		values = append(values, controlPaths.Config, filepath.Join(controlPaths.ConfigRoot, ".lanpanel-filetxn"), controlPaths.Policy, controlPaths.Unit, controlPaths.Database, controlPaths.NoiseKey, controlPaths.DERPKey, controlPaths.Journal, controlPaths.JournalStaging, controlPaths.ControlSocket, controlPaths.AdminSocket, controlPaths.MetricsSocket, "/var/lib/lanpanel/headscale/identity", "/var/lib/lanpanel/headscale/identity/database-uuid", "/var/lib/lanpanel/headscale/identity/snapshot.json", "/var/lib/lanpanel/headscale/identity/.identity.lanpanel-staging")
		activationPaths := control.FixedActivationPaths()
		values = append(values, activationPaths.ControlSocketUnit, activationPaths.ControlRelayUnit, activationPaths.STUNSocketUnit, activationPaths.STUNRelayUnit, activationPaths.PrivateProbeUnit, filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale.service"), filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale-control-relay.service"), filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale-stun-relay.service"), filepath.Join(paths.SystemdRoot, "multi-user.target.wants", "lanpanel-headscale-private-probe.service"), filepath.Join(paths.SystemdRoot, "sockets.target.wants", "lanpanel-headscale-control.socket"), filepath.Join(paths.SystemdRoot, "sockets.target.wants", "lanpanel-headscale-stun.socket"))
	}
	slices.Sort(values)
	return slices.Compact(values)
}

func ownedInventoryPaths(journal Journal) ([]string, error) {
	paths := append([]string(nil), journal.PlannedPaths...)
	for _, root := range []string{journal.Paths.PersistentRoot, journal.Paths.InstallationRoot, journal.Paths.StateRoot, journal.Paths.SafetyRoot, journal.Paths.OwnershipRoot, journal.Paths.PackageRoot, journal.Paths.RuntimeRoot} {
		entries, err := walkBounded(root, 4096)
		if err != nil {
			return nil, fmt.Errorf("collect installation ownership inventory: %w", err)
		}
		paths = append(paths, entries...)
	}
	paths = append(paths, ownershipInventoryPath(journal.Paths))
	slices.Sort(paths)
	return slices.Compact(paths), nil
}

func buildOwnershipInventory(journal Journal) (OwnershipInventory, []byte, string, error) {
	if err := validateJournal(journal); err != nil {
		return OwnershipInventory{}, nil, "", err
	}
	paths, err := ownedInventoryPaths(journal)
	if err != nil {
		return OwnershipInventory{}, nil, "", err
	}
	artifacts := make(map[string]string, len(journal.ArtifactDigests)+len(paths))
	for path, digest := range journal.ArtifactDigests {
		if filepath.IsAbs(path) {
			artifacts[path] = digest
		}
	}
	for _, path := range paths {
		if _, exists := artifacts[path]; exists {
			continue
		}
		info, statErr := os.Lstat(path)
		if os.IsNotExist(statErr) || statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return OwnershipInventory{}, nil, "", fmt.Errorf("read installation ownership artifact %q: %w", path, readErr)
		}
		artifacts[path] = release.DigestBytes(data)
	}
	value := OwnershipInventory{SchemaVersion: ownershipInventorySchema, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, Paths: paths, MutablePaths: mutableOwnershipPaths(journal.Paths), Artifacts: artifacts}
	data, err := encodeCanonical(value)
	if err != nil {
		return OwnershipInventory{}, nil, "", fmt.Errorf("encode installation ownership inventory: %w", err)
	}
	return value, data, release.DigestBytes(data), nil
}

func validateOwnershipInventory(value OwnershipInventory, journal Journal) error {
	if value.SchemaVersion != ownershipInventorySchema || value.AttemptID != journal.AttemptID || value.InstallationID != journal.InstallationID || value.GenerationID != journal.GenerationID || len(value.Paths) == 0 || value.Paths[0] == "" || !slices.Equal(value.MutablePaths, mutableOwnershipPaths(journal.Paths)) {
		return fmt.Errorf("installation ownership inventory is incomplete")
	}
	expected, err := plannedBootstrapPaths(journal.Paths)
	if err != nil {
		return err
	}
	expected = append(expected, ownershipInventoryPath(journal.Paths))
	slices.Sort(expected)
	expected = slices.Compact(expected)
	inventoryPaths := make(map[string]bool, len(value.Paths))
	for _, path := range value.Paths {
		inventoryPaths[path] = true
	}
	for _, path := range expected {
		if !inventoryPaths[path] {
			return fmt.Errorf("installation ownership inventory is incomplete")
		}
	}
	for index, path := range value.Paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || index > 0 && value.Paths[index-1] >= path {
			return fmt.Errorf("installation ownership path inventory is invalid")
		}
	}
	for path, digest := range value.Artifacts {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !release.ValidDigest(digest) {
			return fmt.Errorf("installation ownership artifact inventory is invalid")
		}
	}
	return nil
}
