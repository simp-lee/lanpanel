//go:build linux

package process

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"os"
	"path/filepath"
)

const processJournalSchema = "lanpanel.process.lifecycle.v1"

type Journal struct {
	SchemaVersion  string                 `json:"schema_version"`
	JobID          string                 `json:"job_id"`
	ResourceID     string                 `json:"resource_id"`
	Operation      string                 `json:"operation"`
	Phase          string                 `json:"phase"`
	BundleDigest   string                 `json:"bundle_digest"`
	RelayRequired  bool                   `json:"relay_required"`
	Applied        *domain.ProcessBundle  `json:"applied,omitempty"`
	Policy         confinement.UnitPolicy `json:"policy"`
	ApplicationUID uint32                 `json:"application_uid,omitempty"`
	ApplicationGID uint32                 `json:"application_gid,omitempty"`
	RelayUID       uint32                 `json:"relay_uid,omitempty"`
	RelayGID       uint32                 `json:"relay_gid,omitempty"`
}

func journalPath(resourceID string) string {
	return filepath.Join("/var/lib/lanpanel/safety/process", resourceID+".json")
}

func JournalPresent(resourceID string) (bool, error) {
	path := journalPath(resourceID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false, fmt.Errorf("process journal identity is unsafe")
	}
	return true, nil
}

func WriteJournal(ctx context.Context, value Journal) error {
	if value.SchemaVersion != processJournalSchema || value.JobID == "" || value.ResourceID == "" || (value.Operation != "process_start" && value.Operation != "process_stop") || (value.Phase != "prepared" && value.Phase != "activating" && value.Phase != "host_mutated") {
		return fmt.Errorf("process journal invalid")
	}
	if value.Applied != nil && (value.ApplicationUID != value.Applied.ApplicationUID || value.ApplicationGID != value.Applied.ApplicationGID || value.RelayUID != value.Applied.RelayUID || value.RelayGID != value.Applied.RelayGID || value.RelayRequired != value.Applied.RelayRequired) {
		return fmt.Errorf("process journal account identity differs from applied bundle")
	}
	if value.Operation == "process_start" && value.Phase != "prepared" && (value.Applied == nil || value.BundleDigest != value.Applied.PolicyDigest || value.Policy.Digest != value.Applied.PolicyDigest || value.Policy.ResourceID != value.ResourceID || value.ApplicationUID == 0 || value.ApplicationGID == 0 || value.RelayRequired && (value.RelayUID == 0 || value.RelayGID == 0)) {
		return fmt.Errorf("process start journal runtime authority incomplete")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	path := journalPath(value.ResourceID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	staging := filepath.Join(filepath.Dir(path), ".filetxn")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return err
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: owner, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(store.Close)
	meta := filetxn.Metadata{Owner: owner, Mode: 0o600}
	disposition := filetxn.CreateOnly
	if _, err := os.Lstat(path); err == nil {
		disposition = filetxn.ReplaceOnly
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, err = store.Put(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, Existing: &meta, New: meta, MaxBytes: int64(len(data))}, data, disposition)
	return err
}

type ReconcileState func(context.Context, Journal, bool) (terminal bool, running bool, err error)

func ReconcileJournals(ctx context.Context, host Host, commit ReconcileState) error {
	paths, err := filepath.Glob("/var/lib/lanpanel/safety/process/*.json")
	if err != nil {
		return err
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var journal Journal
		if err := json.Unmarshal(data, &journal); err != nil || journal.SchemaVersion != processJournalSchema || journal.ResourceID == "" || journal.JobID == "" {
			return fmt.Errorf("process lifecycle journal malformed")
		}
		if commit == nil {
			return fmt.Errorf("process lifecycle recovery state committer missing")
		}
		terminal, running, err := commit(ctx, journal, false)
		if err != nil {
			return err
		}
		if terminal {
			if err := host.VerifyCommittedJournal(ctx, journal, running); err != nil {
				return err
			}
		}
		if !terminal {
			if journal.Operation == "process_stop" || journal.Phase != "prepared" {
				if err := host.Stop(ctx, journal.ResourceID, journal.RelayRequired); err != nil {
					return fmt.Errorf("contract interrupted process lifecycle: %w", err)
				}
			}
			terminal, running, err = commit(ctx, journal, true)
			if err != nil {
				return err
			}
			if !terminal || running {
				return fmt.Errorf("process lifecycle contraction did not commit stopped terminal authority")
			}
			if err := host.VerifyCommittedJournal(ctx, journal, false); err != nil {
				return err
			}
		}
		if err := RemoveJournal(journal.ResourceID); err != nil {
			return err
		}
	}
	return nil
}

func RemoveJournal(resourceID string) error {
	path := journalPath(resourceID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(directory.Close)
	return directory.Sync()
}
