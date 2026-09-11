//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/release"
	"path/filepath"
	"slices"
)

const ownershipInventorySchema = "lanpanel.bootstrap.ownership.v1"

func ownershipInventoryPath(paths Paths) string {
	return filepath.Join(paths.OwnershipRoot, "installation.json")
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
	artifacts := make(map[string]string, len(journal.ArtifactDigests))
	for path, digest := range journal.ArtifactDigests {
		if filepath.IsAbs(path) {
			artifacts[path] = digest
		}
	}
	value := OwnershipInventory{SchemaVersion: ownershipInventorySchema, AttemptID: journal.AttemptID, InstallationID: journal.InstallationID, GenerationID: journal.GenerationID, Paths: paths, Artifacts: artifacts}
	data, err := encodeCanonical(value)
	if err != nil {
		return OwnershipInventory{}, nil, "", fmt.Errorf("encode installation ownership inventory: %w", err)
	}
	return value, data, release.DigestBytes(data), nil
}

func validateOwnershipInventory(value OwnershipInventory, journal Journal) error {
	if value.SchemaVersion != ownershipInventorySchema || value.AttemptID != journal.AttemptID || value.InstallationID != journal.InstallationID || value.GenerationID != journal.GenerationID || len(value.Paths) == 0 || value.Paths[0] == "" {
		return fmt.Errorf("installation ownership inventory is incomplete")
	}
	expected, err := ownedInventoryPaths(journal)
	if err != nil {
		return err
	}
	if !slices.Equal(value.Paths, expected) {
		return fmt.Errorf("installation ownership inventory is incomplete")
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
