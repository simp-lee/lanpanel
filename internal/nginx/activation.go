package nginx

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
)

type ActivationSnapshot struct {
	EntryPresent  bool
	Entry         Entry
	EntryBytes    []byte
	Manifest      Manifest
	ManifestBytes []byte
}

func SnapshotActivation(paths Paths, owner filetxn.Owner, entry Entry) (ActivationSnapshot, error) {
	manifest, err := Audit(paths, owner)
	if err != nil {
		return ActivationSnapshot{}, err
	}
	manifestBytes, err := os.ReadFile(paths.ManifestPath())
	if err != nil {
		return ActivationSnapshot{}, err
	}
	snapshot := ActivationSnapshot{Manifest: manifest, ManifestBytes: manifestBytes}
	for _, current := range manifest.Entries {
		if current.ResourceID == entry.ResourceID || current.Relative == entry.Relative {
			if current.ResourceID != entry.ResourceID || current.Relative != entry.Relative {
				return ActivationSnapshot{}, fmt.Errorf("activation prior identity conflicts")
			}
			data, err := os.ReadFile(filepath.Join(paths.ConfigRoot, filepath.FromSlash(current.Relative)))
			if err != nil {
				return ActivationSnapshot{}, err
			}
			snapshot.EntryPresent = true
			snapshot.Entry = current
			snapshot.EntryBytes = data
		}
	}
	return snapshot, nil
}

func RestoreActivation(ctx context.Context, paths Paths, owner filetxn.Owner, candidate Entry, snapshot ActivationSnapshot) ([]string, error) {
	txn, err := filetxn.Open(filetxn.Config{RootPath: paths.ConfigRoot, Root: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingPath: paths.StagingPath(), Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}}, filetxn.Options{})
	if err != nil {
		return nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(txn.Close)
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	entryPath := filepath.Join(paths.ConfigRoot, filepath.FromSlash(candidate.Relative))
	modified := []string{}
	if snapshot.EntryPresent {
		result, putErr := txn.Put(ctx, filetxn.Request{Path: entryPath, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumGraphFileSize}, snapshot.EntryBytes, filetxn.ReplaceOnly)
		if putErr != nil || result.State != filetxn.StateDurable {
			return modified, fmt.Errorf("restore prior Nginx entry: %w", putErr)
		}
		modified = append(modified, entryPath)
	} else {
		result, removeErr := txn.Remove(ctx, filetxn.Request{Path: entryPath, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata})
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) || removeErr == nil && result.State != filetxn.StateDurable {
			return modified, fmt.Errorf("remove candidate Nginx entry: %w", removeErr)
		}
		modified = append(modified, entryPath)
	}
	result, err := txn.Put(ctx, filetxn.Request{Path: paths.ManifestPath(), Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: MaximumGraphFileSize}, snapshot.ManifestBytes, filetxn.ReplaceOnly)
	if err != nil || result.State != filetxn.StateDurable {
		return modified, fmt.Errorf("restore prior Nginx manifest: %w", err)
	}
	modified = append(modified, paths.ManifestPath())
	if _, err := Audit(paths, owner); err != nil {
		return modified, err
	}
	return modified, nil
}
