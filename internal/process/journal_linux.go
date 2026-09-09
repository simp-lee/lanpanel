//go:build linux

package process

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/resource"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	processJournalSchema       = "lanpanel.process.lifecycle.v1"
	maximumProcessJournalBytes = 64 << 10
)

type Journal struct {
	SchemaVersion   string                 `json:"schema_version"`
	JobID           string                 `json:"job_id"`
	ResourceID      string                 `json:"resource_id"`
	Operation       string                 `json:"operation"`
	Phase           string                 `json:"phase"`
	BundleDigest    string                 `json:"bundle_digest"`
	RelayRequired   bool                   `json:"relay_required"`
	ContractionKind RuntimeViolationKind   `json:"contraction_kind,omitempty"`
	Applied         *domain.ProcessBundle  `json:"applied,omitempty"`
	Policy          confinement.UnitPolicy `json:"policy"`
	ApplicationUID  uint32                 `json:"application_uid,omitempty"`
	ApplicationGID  uint32                 `json:"application_gid,omitempty"`
	RelayUID        uint32                 `json:"relay_uid,omitempty"`
	RelayGID        uint32                 `json:"relay_gid,omitempty"`
}

func journalPath(resourceID string) string {
	return filepath.Join("/var/lib/lanpanel/safety/process", resourceID+".json")
}

func JournalPresent(resourceID string) (bool, error) {
	if !validProcessJournalID(resourceID, "res_", 32) {
		return false, fmt.Errorf("process journal resource identity is invalid")
	}
	path := journalPath(resourceID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximumProcessJournalBytes {
		return false, fmt.Errorf("process journal identity is unsafe")
	}
	return true, nil
}

func WriteJournal(ctx context.Context, value Journal) error {
	if err := validateProcessJournal(value); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maximumProcessJournalBytes {
		return fmt.Errorf("process journal size invalid")
	}
	path := journalPath(value.ResourceID)
	if err := ensureProcessJournalDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	staging := filepath.Join(filepath.Dir(path), ".filetxn")
	if err := ensureProcessJournalDirectory(staging); err != nil {
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

func validateProcessJournal(value Journal) error {
	if value.SchemaVersion != processJournalSchema || !validProcessJournalID(value.JobID, "job_", 64) || !validProcessJournalID(value.ResourceID, "res_", 32) || (value.Operation != "process_start" && value.Operation != "process_stop") || (value.Phase != "prepared" && value.Phase != "activating" && value.Phase != "host_mutated") || value.Operation == "process_stop" && value.Phase == "activating" {
		return fmt.Errorf("process journal invalid")
	}
	if value.ContractionKind != "" {
		if value.Operation != "process_stop" || value.Applied == nil {
			return fmt.Errorf("process runtime violation journal must stop an exact applied process")
		}
		if _, err := RuntimeViolationReason(value.ContractionKind); err != nil {
			return err
		}
	}
	if value.Applied == nil {
		preparedRelayStart := value.Operation == "process_start" && value.Phase == "prepared" && value.RelayRequired
		if value.Phase != "prepared" || value.BundleDigest != "" || value.RelayRequired && !preparedRelayStart || value.ApplicationUID != 0 || value.ApplicationGID != 0 || value.RelayUID != 0 || value.RelayGID != 0 {
			return fmt.Errorf("process journal has account authority without an applied bundle")
		}
	} else {
		if err := domain.ValidateProcessBundle(*value.Applied); err != nil {
			return fmt.Errorf("process journal applied bundle is invalid: %w", err)
		}
		if err := validateProcessJournalBundle(value.ResourceID, *value.Applied); err != nil {
			return err
		}
		preparedStart := value.Operation == "process_start" && value.Phase == "prepared"
		if value.BundleDigest != value.Applied.PolicyDigest || value.ApplicationUID != value.Applied.ApplicationUID || value.ApplicationGID != value.Applied.ApplicationGID || value.RelayUID != value.Applied.RelayUID || value.RelayGID != value.Applied.RelayGID || !preparedStart && value.RelayRequired != value.Applied.RelayRequired {
			return fmt.Errorf("process journal account identity differs from applied bundle")
		}
	}
	if value.Operation == "process_start" && value.Phase != "prepared" {
		if value.Applied == nil || confinement.ValidateUnitPolicy(value.Policy) != nil || value.Policy.Digest != value.Applied.PolicyDigest || value.Policy.ResourceID != value.ResourceID || value.Policy.Cgroup != value.Applied.Cgroup || value.ApplicationUID == 0 || value.ApplicationGID == 0 || value.RelayRequired && (value.RelayUID == 0 || value.RelayGID == 0) {
			return fmt.Errorf("process start journal runtime authority incomplete")
		}
	} else if value.Policy.ResourceID != "" || value.Policy.Cgroup != "" || value.Policy.BindListenPolicy != "" || len(value.Policy.Directives) != 0 || value.Policy.Digest != "" {
		return fmt.Errorf("process journal has unexpected runtime policy")
	}
	return nil
}

func validateProcessJournalBundle(resourceID string, bundle domain.ProcessBundle) error {
	paths, err := resource.DerivePaths(resourceID)
	if err != nil {
		return fmt.Errorf("process journal resource identity is invalid")
	}
	short := strings.TrimPrefix(resourceID, "res_")[:20]
	cgroup := "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-" + short + ".slice/lanpanel-app-" + short + ".service"
	backend := ""
	if bundle.RelayRequired {
		backend = paths.BackendSocket
	}
	if bundle.Cgroup != cgroup || bundle.FrontendEndpoint != paths.FrontendSocket || bundle.BackendEndpoint != backend || !slices.Equal(bundle.EndpointSocketUnits, []string{paths.SocketUnit}) || !slices.Equal(bundle.ManagedPaths, paths.ManagedPaths()) {
		return fmt.Errorf("process journal applied bundle belongs to another resource")
	}
	return nil
}

func validProcessJournalID(value, prefix string, hexDigits int) bool {
	if len(value) != len(prefix)+hexDigits || !strings.HasPrefix(value, prefix) || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func readProcessJournal(path string, owner filetxn.Owner) (Journal, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return Journal{}, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return Journal{}, fmt.Errorf("process journal descriptor invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o7777 != 0o600 || before.Uid != owner.UID || before.Gid != owner.GID || before.Nlink != 1 || before.Size <= 0 || before.Size > maximumProcessJournalBytes {
		return Journal{}, fmt.Errorf("process journal identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumProcessJournalBytes+1))
	var after unix.Stat_t
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Uid != after.Uid || before.Gid != after.Gid || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return Journal{}, fmt.Errorf("process journal changed during read")
	}
	var value Journal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Journal{}, fmt.Errorf("process lifecycle journal malformed")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) || filepath.Base(path) != value.ResourceID+".json" {
		return Journal{}, fmt.Errorf("process lifecycle journal noncanonical")
	}
	if err := validateProcessJournal(value); err != nil {
		return Journal{}, err
	}
	return value, nil
}

func ensureProcessJournalDirectory(path string) error {
	created := false
	if err := os.Mkdir(path, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("process journal directory identity is unsafe")
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	if !created {
		return nil
	}
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	return unix.Fsync(parent)
}

type ReconcileState func(context.Context, Journal, bool) (terminal bool, running bool, err error)

func ReconcileJournals(ctx context.Context, host Host, commit ReconcileState) error {
	if err := filetxn.CleanPrivateStaging("/var/lib/lanpanel/safety/process/.filetxn", filetxn.Owner{UID: 0, GID: 0}, maximumProcessJournalBytes); err != nil {
		return err
	}
	paths, err := filepath.Glob("/var/lib/lanpanel/safety/process/*.json")
	if err != nil {
		return err
	}
	for _, path := range paths {
		journal, err := readProcessJournal(path, filetxn.Owner{UID: 0, GID: 0})
		if err != nil {
			return err
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
