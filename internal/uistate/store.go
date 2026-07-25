// Package uistate provides the local file-backed UI job/event index.
package uistate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/sensitive"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	appConfigPathIndexFile   = "app-config-paths.json"
	appConfigPathIndexSchema = "lanpanel.ui.app_config_paths.v1"
	HostMutationLockName     = "host_mutation"
)

var (
	fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{16}$`)
	resourceIDPattern  = regexp.MustCompile(`^res_[0-9a-f]{32}$`)
	storeIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	lockPIDPattern     = regexp.MustCompile(`"pid"\s*:\s*([0-9]+)`)
	appConfigIndexMu   sync.Mutex
)

type Store struct {
	dir         string
	expectedUID uint32
}

type Event struct {
	SchemaVersion string                  `json:"schema_version"`
	ID            string                  `json:"id"`
	JobID         string                  `json:"job_id"`
	At            time.Time               `json:"at"`
	Status        domain.DiagnosticStatus `json:"status"`
	Message       string                  `json:"message"`
	Redaction     domain.Redaction        `json:"redaction,omitempty"`
}

type appConfigPathIndex struct {
	SchemaVersion string   `json:"schema_version"`
	Paths         []string `json:"paths"`
}

type Lock struct {
	path  string
	kind  domain.JobKind
	name  string
	token string
	file  *os.File
}

type lockFile struct {
	Kind             domain.JobKind `json:"kind"`
	Name             string         `json:"name,omitempty"`
	JobID            string         `json:"job_id,omitempty"`
	PID              int            `json:"pid"`
	BootID           string         `json:"boot_id"`
	ProcessStartTime string         `json:"process_start_time"`
	Token            string         `json:"token"`
}

type recoveryLockFile struct {
	path string
	lock lockFile
}

type processIdentity struct {
	PID       int
	BootID    string
	StartTime string
}

func NewStore(dir string) Store {
	return Store{dir: dir, expectedUID: uint32(os.Geteuid())}
}

func NewStoreForUID(dir string, uid uint32) Store {
	return Store{dir: dir, expectedUID: uid}
}

func (store Store) Open() error {
	if store.dir == "" {
		return fmt.Errorf("ui state dir is required")
	}
	if err := checkCreatePath(store.dir, store.expectedUID); err != nil {
		return err
	}
	if err := os.MkdirAll(store.dir, 0o700); err != nil {
		return fmt.Errorf("create ui state dir: %w", err)
	}
	if err := checkDir(store.dir, store.expectedUID); err != nil {
		return err
	}
	for _, child := range []string{"jobs", "locks"} {
		if err := os.MkdirAll(filepath.Join(store.dir, child), 0o700); err != nil {
			return fmt.Errorf("create ui state %s dir: %w", child, err)
		}
	}
	for _, dir := range []string{filepath.Join(store.dir, "jobs"), filepath.Join(store.dir, "locks")} {
		if err := checkDir(dir, store.expectedUID); err != nil {
			return err
		}
	}
	return nil
}

func (store Store) CreateJob(record domain.JobRecord) (domain.JobRecord, error) {
	if err := store.Open(); err != nil {
		return domain.JobRecord{}, err
	}
	record.SchemaVersion = domain.JobRecordSchemaVersion
	if strings.TrimSpace(record.ID) == "" {
		record.ID = newID("job")
	}
	if err := validateStoreID("job id", record.ID); err != nil {
		return domain.JobRecord{}, err
	}
	if record.Status == "" {
		record.Status = domain.JobStatusQueued
	}
	if record.CheckpointRef.Kind == "" {
		record.CheckpointRef = domain.NotApplicableActivationRef()
	}
	stampRecord(&record, time.Now().UTC())
	if err := validateRecord(record); err != nil {
		return domain.JobRecord{}, err
	}
	record = redactRecord(record)
	jobDir := store.jobDir(record.ID)
	if err := os.Mkdir(jobDir, 0o700); err != nil {
		return domain.JobRecord{}, fmt.Errorf("create job dir: %w", err)
	}
	if err := os.Mkdir(filepath.Join(jobDir, "events"), 0o700); err != nil {
		return domain.JobRecord{}, fmt.Errorf("create job events dir: %w", err)
	}
	if err := store.checkJobDirs(record.ID); err != nil {
		return domain.JobRecord{}, err
	}
	if err := store.SaveRecord(record); err != nil {
		return domain.JobRecord{}, err
	}
	return record, nil
}

func (store Store) SaveRecord(record domain.JobRecord) error {
	if err := store.checkTree(); err != nil {
		return err
	}
	if strings.TrimSpace(record.ID) == "" {
		return fmt.Errorf("job id is required")
	}
	if err := validateStoreID("job id", record.ID); err != nil {
		return err
	}
	if record.SchemaVersion != domain.JobRecordSchemaVersion {
		return fmt.Errorf("job record schema_version must be %q", domain.JobRecordSchemaVersion)
	}
	stampRecord(&record, time.Now().UTC())
	if err := validateRecord(record); err != nil {
		return err
	}
	if err := store.checkJobDirs(record.ID); err != nil {
		return err
	}
	recordPath := filepath.Join(store.jobDir(record.ID), "record.json")
	if err := checkExistingFileForOverwrite(recordPath, store.expectedUID); err != nil {
		return err
	}
	record = redactRecord(record)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal job record: %w", err)
	}
	return atomicWrite(recordPath, append(data, '\n'), 0o600)
}

func (store Store) LoadRecord(id string) (domain.JobRecord, error) {
	if err := store.checkTree(); err != nil {
		return domain.JobRecord{}, err
	}
	if err := validateStoreID("job id", id); err != nil {
		return domain.JobRecord{}, err
	}
	if err := store.checkJobDirs(id); err != nil {
		return domain.JobRecord{}, err
	}
	path := filepath.Join(store.jobDir(id), "record.json")
	if err := checkFile(path, store.expectedUID); err != nil {
		return domain.JobRecord{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.JobRecord{}, fmt.Errorf("read job record: %w", err)
	}
	var record domain.JobRecord
	if err := decodeStrictJSON(data, &record); err != nil {
		return domain.JobRecord{}, fmt.Errorf("decode job record: %w", err)
	}
	if record.SchemaVersion != domain.JobRecordSchemaVersion {
		return domain.JobRecord{}, fmt.Errorf("job record schema_version must be %q", domain.JobRecordSchemaVersion)
	}
	if err := validateStoreID("persisted job id", record.ID); err != nil {
		return domain.JobRecord{}, err
	}
	if record.ID != strings.TrimSpace(id) {
		return domain.JobRecord{}, fmt.Errorf("persisted job id %q does not match requested job id %q", record.ID, strings.TrimSpace(id))
	}
	if err := validateRecord(record); err != nil {
		return domain.JobRecord{}, err
	}
	return record, nil
}

func (store Store) AppendEvent(jobID string, event Event) (Event, error) {
	if err := store.checkTree(); err != nil {
		return Event{}, err
	}
	if err := validateStoreID("job id", jobID); err != nil {
		return Event{}, err
	}
	if strings.TrimSpace(event.ID) == "" {
		event.ID = newID("evt")
	}
	if err := validateStoreID("event id", event.ID); err != nil {
		return Event{}, err
	}
	if err := store.checkJobDirs(jobID); err != nil {
		return Event{}, err
	}
	event.SchemaVersion = domain.JobEventSchemaVersion
	event.JobID = jobID
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	if err := validateEvent(event); err != nil {
		return Event{}, err
	}
	originalMessage := event.Message
	event.Message = SanitizeJobText(event.Message)
	if event.Message != originalMessage && event.Redaction == "" {
		event.Redaction = domain.RedactionSecret
	}
	data, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return Event{}, fmt.Errorf("marshal job event: %w", err)
	}
	path := filepath.Join(store.jobDir(jobID), "events", event.At.Format("20060102T150405.000000000Z")+"-"+event.ID+".json")
	if err := atomicWriteNew(path, append(data, '\n'), 0o600); err != nil {
		return Event{}, fmt.Errorf("write job event: %w", err)
	}
	return event, nil
}

func (store Store) WriteConfigSnapshot(jobID string, name string, data []byte) (string, error) {
	if err := store.checkTree(); err != nil {
		return "", err
	}
	if err := validateStoreID("job id", jobID); err != nil {
		return "", err
	}
	if err := validateStoreID("config snapshot name", name); err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("config snapshot data is required")
	}
	if err := store.checkJobDirs(jobID); err != nil {
		return "", err
	}
	snapshotsDir := filepath.Join(store.jobDir(jobID), "config-snapshots")
	if err := os.Mkdir(snapshotsDir, 0o700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("create config snapshots dir: %w", err)
	}
	if err := checkDir(snapshotsDir, store.expectedUID); err != nil {
		return "", err
	}
	path := filepath.Join(snapshotsDir, name)
	if err := atomicWriteNew(path, redactConfigSnapshot(data), 0o600); err != nil {
		return "", fmt.Errorf("write config snapshot: %w", err)
	}
	return path, nil
}

func (store Store) RegisterAppConfigPath(path string) error {
	path, err := cleanAppConfigPath(path)
	if err != nil {
		return err
	}
	if err := store.Open(); err != nil {
		return err
	}
	appConfigIndexMu.Lock()
	defer appConfigIndexMu.Unlock()
	paths, err := store.loadAppConfigPathIndexLocked()
	if err != nil {
		return err
	}
	for _, existing := range paths {
		if existing == path {
			return nil
		}
	}
	paths = append(paths, path)
	sort.Strings(paths)
	return store.writeAppConfigPathIndexLocked(paths)
}

func (store Store) ListAppConfigPaths() ([]string, error) {
	if err := store.checkTree(); err != nil {
		return nil, err
	}
	appConfigIndexMu.Lock()
	defer appConfigIndexMu.Unlock()
	paths, err := store.loadAppConfigPathIndexLocked()
	if err != nil {
		return nil, err
	}
	return append([]string(nil), paths...), nil
}

func (store Store) loadAppConfigPathIndexLocked() ([]string, error) {
	path := store.appConfigPathIndexPath()
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect app config path index: %w", err)
	}
	if err := checkFile(path, store.expectedUID); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read app config path index: %w", err)
	}
	var index appConfigPathIndex
	if err := decodeStrictJSON(data, &index); err != nil {
		return nil, fmt.Errorf("decode app config path index: %w", err)
	}
	if index.SchemaVersion != appConfigPathIndexSchema {
		return nil, fmt.Errorf("app config path index schema_version must be %q", appConfigPathIndexSchema)
	}
	seen := map[string]struct{}{}
	paths := make([]string, 0, len(index.Paths))
	for _, path := range index.Paths {
		clean, err := cleanAppConfigPath(path)
		if err != nil {
			return nil, fmt.Errorf("app config path index contains invalid path %q: %w", path, err)
		}
		if _, ok := seen[clean]; ok {
			return nil, fmt.Errorf("app config path index contains duplicate path %s", clean)
		}
		seen[clean] = struct{}{}
		paths = append(paths, clean)
	}
	if !sort.StringsAreSorted(paths) {
		return nil, fmt.Errorf("app config path index paths must be sorted")
	}
	return paths, nil
}

func (store Store) writeAppConfigPathIndexLocked(paths []string) error {
	index := appConfigPathIndex{
		SchemaVersion: appConfigPathIndexSchema,
		Paths:         append([]string(nil), paths...),
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal app config path index: %w", err)
	}
	path := store.appConfigPathIndexPath()
	if err := checkExistingFileForOverwrite(path, store.expectedUID); err != nil {
		return err
	}
	if err := atomicWrite(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write app config path index: %w", err)
	}
	return nil
}

func (store Store) appConfigPathIndexPath() string {
	return filepath.Join(store.dir, appConfigPathIndexFile)
}

func (store Store) ListRecords() ([]domain.JobRecord, error) {
	if err := store.checkTree(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(store.dir, "jobs"))
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	records := make([]domain.JobRecord, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(store.dir, "jobs", entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect job entry %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("ui state dir %s must not be a symlink", path)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("job entry %s must be a directory", path)
		}
		if err := validateStoreID("job id", entry.Name()); err != nil {
			return nil, err
		}
		record, ok, err := store.recoveryRecord(entry.Name())
		if err != nil {
			return nil, err
		}
		if ok {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID > records[j].ID })
	return records, nil
}

func (store Store) ListEvents(jobID string) ([]Event, error) {
	if err := store.checkTree(); err != nil {
		return nil, err
	}
	if err := validateStoreID("job id", jobID); err != nil {
		return nil, err
	}
	if err := store.checkJobDirs(jobID); err != nil {
		return nil, err
	}
	eventsDir := filepath.Join(store.jobDir(jobID), "events")
	entries, err := os.ReadDir(eventsDir)
	if err != nil {
		return nil, fmt.Errorf("list job events: %w", err)
	}
	events := make([]Event, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("job event entry %q must be a file", entry.Name())
		}
		path := filepath.Join(eventsDir, entry.Name())
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			if err := checkFile(path, store.expectedUID); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			continue
		}
		if err := checkFile(path, store.expectedUID); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read job event: %w", err)
		}
		var event Event
		if err := decodeStrictJSON(data, &event); err != nil {
			return nil, fmt.Errorf("decode job event: %w", err)
		}
		if event.SchemaVersion != domain.JobEventSchemaVersion {
			return nil, fmt.Errorf("job event schema_version must be %q", domain.JobEventSchemaVersion)
		}
		if err := validateEvent(event); err != nil {
			return nil, err
		}
		if event.JobID != jobID {
			return nil, fmt.Errorf("job event job_id %q does not match requested job id %q", event.JobID, jobID)
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].At.Equal(events[j].At) {
			return events[i].At.Before(events[j].At)
		}
		return events[i].ID < events[j].ID
	})
	return events, nil
}

func (store Store) RecoverInterrupted() error {
	if err := store.checkTree(); err != nil {
		return err
	}
	locksDir := filepath.Join(store.dir, "locks")
	if err := checkDir(locksDir, store.expectedUID); err != nil {
		return err
	}
	return withLockGuard(locksDir, func() error {
		locks, err := store.recoveryLockFilesLocked()
		if err != nil {
			return err
		}
		for _, lock := range locks {
			if lockOwnerAlive(lock.lock) {
				return fmt.Errorf("active %s job lock is held by live pid %d", lock.lock.Kind, lock.lock.PID)
			}
		}
		if err := store.removeRecoveryLockFilesLocked(locks); err != nil {
			return err
		}
		records, err := store.recoveryRecords()
		if err != nil {
			return err
		}
		for _, record := range records {
			if record.Status != domain.JobStatusQueued && record.Status != domain.JobStatusRunning {
				continue
			}
			record.Status = domain.JobStatusInterrupted
			record.ErrorSummary = "job was interrupted while lanpanel ui was not running"
			record.ConfigSnapshotRef = explicitConfigSnapshotRef(record.ConfigSnapshotRef)
			record.RetryCommand = interruptedRetryCommand(record)
			if err := store.SaveRecord(record); err != nil {
				return err
			}
			if _, err := store.AppendEvent(record.ID, Event{Status: domain.DiagnosticStatusUnknown, Message: record.ErrorSummary}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store Store) recoveryLockFilesLocked() ([]recoveryLockFile, error) {
	locksDir := filepath.Join(store.dir, "locks")
	entries, err := os.ReadDir(locksDir)
	if err != nil {
		return nil, fmt.Errorf("list active job locks: %w", err)
	}
	locks := make([]recoveryLockFile, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == ".guard" {
			continue
		}
		path := filepath.Join(locksDir, name)
		if strings.HasPrefix(name, ".tmp-") {
			if err := checkFile(path, store.expectedUID); err != nil {
				return nil, err
			}
			locks = append(locks, recoveryLockFile{path: path})
			continue
		}
		if err := validateStoreID("lock name", name); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(name, ".lock") {
			return nil, fmt.Errorf("lock file %q must use .lock suffix", name)
		}
		if err := checkFile(path, store.expectedUID); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read active job lock: %w", err)
		}
		fileName := strings.TrimSuffix(name, ".lock")
		lock := lockFile{Name: fileName}
		if err := decodeStrictJSON(data, &lock); err != nil {
			pid, ok := staleCorruptLockPID(data)
			if !ok || processAlive(pid) {
				return nil, fmt.Errorf("decode active job lock: %w", err)
			}
			locks = append(locks, recoveryLockFile{path: path, lock: lockFile{Name: fileName, PID: pid}})
			continue
		}
		if err := validateLockFile(lock, fileName); err != nil {
			if lock.PID <= 0 || processAlive(lock.PID) {
				return nil, err
			}
			locks = append(locks, recoveryLockFile{path: path, lock: lock})
			continue
		}
		locks = append(locks, recoveryLockFile{path: path, lock: lock})
	}
	return locks, nil
}

func staleCorruptLockPID(data []byte) (int, bool) {
	match := lockPIDPattern.FindSubmatch(data)
	if len(match) != 2 {
		return 0, false
	}
	pid, err := strconv.Atoi(string(match[1]))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func (store Store) removeRecoveryLockFilesLocked(locks []recoveryLockFile) error {
	for _, lock := range locks {
		if err := checkFile(lock.path, store.expectedUID); err != nil {
			return err
		}
		if err := os.Remove(lock.path); err != nil {
			return fmt.Errorf("remove stale active job lock %s: %w", lock.path, err)
		}
	}
	return syncDir(filepath.Join(store.dir, "locks"))
}

func (store Store) recoveryRecords() ([]domain.JobRecord, error) {
	entries, err := os.ReadDir(filepath.Join(store.dir, "jobs"))
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	records := make([]domain.JobRecord, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(store.dir, "jobs", entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect job entry %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("ui state dir %s must not be a symlink", path)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("job entry %s must be a directory", path)
		}
		id := entry.Name()
		if err := validateStoreID("job id", id); err != nil {
			return nil, err
		}
		record, ok, err := store.recoveryRecord(id)
		if err != nil {
			return nil, err
		}
		if ok {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID > records[j].ID })
	return records, nil
}

func (store Store) recoveryRecord(id string) (domain.JobRecord, bool, error) {
	if err := checkDir(store.jobDir(id), store.expectedUID); err != nil {
		return domain.JobRecord{}, false, err
	}
	path := filepath.Join(store.jobDir(id), "record.json")
	if err := checkFile(path, store.expectedUID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.JobRecord{}, false, nil
		}
		return domain.JobRecord{}, false, err
	}
	eventsDir := filepath.Join(store.jobDir(id), "events")
	if _, err := os.Lstat(eventsDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.JobRecord{}, false, fmt.Errorf("job events dir %s is required for committed record %s", eventsDir, path)
		}
		return domain.JobRecord{}, false, fmt.Errorf("inspect job events dir %s: %w", eventsDir, err)
	}
	if err := checkDir(eventsDir, store.expectedUID); err != nil {
		return domain.JobRecord{}, false, err
	}
	snapshotsDir := filepath.Join(store.jobDir(id), "config-snapshots")
	if _, err := os.Lstat(snapshotsDir); err == nil {
		if err := checkDir(snapshotsDir, store.expectedUID); err != nil {
			return domain.JobRecord{}, false, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return domain.JobRecord{}, false, fmt.Errorf("inspect config snapshots dir %s: %w", snapshotsDir, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.JobRecord{}, false, fmt.Errorf("read job record: %w", err)
	}
	var record domain.JobRecord
	if err := decodeStrictJSON(data, &record); err != nil {
		return domain.JobRecord{}, false, fmt.Errorf("decode recovery job record %s: %w", path, err)
	}
	if record.SchemaVersion != domain.JobRecordSchemaVersion {
		return domain.JobRecord{}, false, fmt.Errorf("recovery job record %s schema_version must be %q", path, domain.JobRecordSchemaVersion)
	}
	if err := validateStoreID("persisted job id", record.ID); err != nil {
		return domain.JobRecord{}, false, fmt.Errorf("recovery job record %s has invalid persisted job id: %w", path, err)
	}
	if record.ID != id {
		return domain.JobRecord{}, false, fmt.Errorf("recovery job record %s job_id %q does not match directory %q", path, record.ID, id)
	}
	if err := validateRecord(record); err != nil {
		return domain.JobRecord{}, false, fmt.Errorf("recovery job record %s is invalid: %w", path, err)
	}
	return record, true, nil
}

func explicitConfigSnapshotRef(value string) string {
	if strings.TrimSpace(value) == "" {
		return "not_applicable"
	}
	return value
}

func interruptedRetryCommand(record domain.JobRecord) string {
	if strings.TrimSpace(record.RetryCommand) != "" {
		return record.RetryCommand
	}
	return "not_applicable"
}

func (store Store) removeStaleLocks() error {
	if err := store.checkTree(); err != nil {
		return err
	}
	locksDir := filepath.Join(store.dir, "locks")
	if err := checkDir(locksDir, store.expectedUID); err != nil {
		return err
	}
	return withLockGuard(locksDir, func() error {
		locks, err := store.lockFilesLocked()
		if err != nil {
			return err
		}
		stale := make([]recoveryLockFile, 0, len(locks))
		for _, lock := range locks {
			if lockOwnerAlive(lock.lock) {
				return fmt.Errorf("active %s job lock is held by live pid %d", lock.lock.Kind, lock.lock.PID)
			}
			stale = append(stale, lock)
		}
		return store.removeLockFilesLocked(stale)
	})
}

func (store Store) AcquireLock(kind domain.JobKind) (*Lock, error) {
	return store.AcquireNamedLock(kind, string(kind))
}

func (store Store) AcquireNamedLock(kind domain.JobKind, name string) (*Lock, error) {
	if err := store.Open(); err != nil {
		return nil, err
	}
	if err := validateJobKind(kind); err != nil {
		return nil, err
	}
	if err := validateLockName(name); err != nil {
		return nil, err
	}
	lockName := name + ".lock"
	if err := validateStoreID("lock name", lockName); err != nil {
		return nil, err
	}
	locksDir := filepath.Join(store.dir, "locks")
	path := filepath.Join(locksDir, lockName)
	var lock *Lock
	err := withLockGuard(locksDir, func() error {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("active %s job already exists", name)
			}
			return fmt.Errorf("create active job lock: %w", err)
		}
		token := newID("lock")
		identity, err := currentProcessIdentity()
		if err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return err
		}
		payload, err := json.Marshal(lockFile{
			Kind:             kind,
			Name:             name,
			PID:              identity.PID,
			BootID:           identity.BootID,
			ProcessStartTime: identity.StartTime,
			Token:            token,
		})
		if err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("marshal active job lock: %w", err)
		}
		if _, err := file.Write(append(payload, '\n')); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("write active job lock: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("sync active job lock: %w", err)
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return fmt.Errorf("sync active job lock dir: %w", err)
		}
		lock = &Lock{path: path, kind: kind, name: name, token: token, file: file}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lock, nil
}

func (lock *Lock) AttachJob(jobID string) error {
	if lock == nil {
		return fmt.Errorf("active job lock is required")
	}
	if err := validateStoreID("job id", jobID); err != nil {
		return err
	}
	return withLockGuard(filepath.Dir(lock.path), func() error {
		data, err := os.ReadFile(lock.path)
		if err != nil {
			return fmt.Errorf("read active job lock: %w", err)
		}
		var current lockFile
		if err := decodeStrictJSON(data, &current); err != nil {
			return fmt.Errorf("decode active job lock: %w", err)
		}
		if current.Kind != lock.kind || effectiveLockName(current) != lock.name || current.Token != lock.token {
			return fmt.Errorf("active job lock changed before job attachment")
		}
		current.JobID = jobID
		payload, err := json.Marshal(current)
		if err != nil {
			return fmt.Errorf("marshal active job lock: %w", err)
		}
		if err := atomicWrite(lock.path, append(payload, '\n'), 0o600); err != nil {
			return fmt.Errorf("write active job lock: %w", err)
		}
		return nil
	})
}

func (lock *Lock) Release() error {
	if lock == nil {
		return nil
	}
	var closeErr error
	if lock.file != nil {
		closeErr = lock.file.Close()
		lock.file = nil
	}
	removeErr := releaseLockFile(lock.path, lock.kind, lock.name, lock.token)
	if closeErr != nil {
		return closeErr
	}
	if removeErr != nil {
		return removeErr
	}
	return nil
}

func (store Store) lockFilesLocked() ([]recoveryLockFile, error) {
	locksDir := filepath.Join(store.dir, "locks")
	entries, err := os.ReadDir(locksDir)
	if err != nil {
		return nil, fmt.Errorf("list active job locks: %w", err)
	}
	locks := make([]recoveryLockFile, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == ".guard" {
			continue
		}
		if strings.HasPrefix(name, ".tmp-") {
			path := filepath.Join(locksDir, name)
			if err := checkFile(path, store.expectedUID); err != nil {
				return nil, err
			}
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("remove stale active job lock temp file %s: %w", path, err)
			}
			if err := syncDir(locksDir); err != nil {
				return nil, err
			}
			continue
		}
		if err := validateStoreID("lock name", name); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(name, ".lock") {
			return nil, fmt.Errorf("lock file %q must use .lock suffix", name)
		}
		path := filepath.Join(locksDir, name)
		if err := checkFile(path, store.expectedUID); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read active job lock: %w", err)
		}
		fileName := strings.TrimSuffix(name, ".lock")
		var lock lockFile
		if err := decodeStrictJSON(data, &lock); err != nil {
			return nil, fmt.Errorf("decode active job lock: %w", err)
		}
		if err := validateLockFile(lock, fileName); err != nil {
			return nil, err
		}
		locks = append(locks, recoveryLockFile{path: path, lock: lock})
	}
	return locks, nil
}

func (store Store) removeLockFilesLocked(locks []recoveryLockFile) error {
	for _, lock := range locks {
		if err := checkFile(lock.path, store.expectedUID); err != nil {
			return err
		}
		if err := os.Remove(lock.path); err != nil {
			return fmt.Errorf("remove stale active job lock %s: %w", lock.path, err)
		}
	}
	return syncDir(filepath.Join(store.dir, "locks"))
}

func validateLockFile(lock lockFile, wantName string) error {
	if err := validateJobKind(lock.Kind); err != nil {
		return err
	}
	if err := validateLockName(wantName); err != nil {
		return err
	}
	if effectiveLockName(lock) != wantName {
		return fmt.Errorf("active job lock name %q does not match file name %q", effectiveLockName(lock), wantName)
	}
	if lock.PID <= 0 {
		return fmt.Errorf("active job lock pid must be positive")
	}
	if strings.TrimSpace(lock.BootID) == "" {
		return fmt.Errorf("active job lock boot_id is required")
	}
	if strings.TrimSpace(lock.ProcessStartTime) == "" {
		return fmt.Errorf("active job lock process_start_time is required")
	}
	if lock.BootID != strings.TrimSpace(lock.BootID) || strings.ContainsAny(lock.BootID, " \t\r\n") {
		return fmt.Errorf("active job lock boot_id must be a single token")
	}
	if lock.ProcessStartTime != strings.TrimSpace(lock.ProcessStartTime) || strings.ContainsAny(lock.ProcessStartTime, " \t\r\n") {
		return fmt.Errorf("active job lock process_start_time must be a single token")
	}
	if err := validateStoreID("lock token", lock.Token); err != nil {
		return err
	}
	if lock.JobID != "" {
		if err := validateStoreID("lock job id", lock.JobID); err != nil {
			return err
		}
	}
	return nil
}

func validateLockName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("active job lock name is required")
	}
	if name != strings.TrimSpace(name) {
		return fmt.Errorf("active job lock name must not include leading or trailing whitespace")
	}
	if err := validateStoreID("lock name", name); err != nil {
		return err
	}
	return nil
}

func effectiveLockName(lock lockFile) string {
	if strings.TrimSpace(lock.Name) != "" {
		return strings.TrimSpace(lock.Name)
	}
	return string(lock.Kind)
}

func currentProcessIdentity() (processIdentity, error) {
	return processIdentityForPID(os.Getpid())
}

func processIdentityForPID(pid int) (processIdentity, error) {
	if pid <= 0 {
		return processIdentity{}, fmt.Errorf("process pid must be positive")
	}
	bootData, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return processIdentity{}, fmt.Errorf("read boot id: %w", err)
	}
	statData, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return processIdentity{}, fmt.Errorf("read process %d stat: %w", pid, err)
	}
	startTime, err := processStartTimeFromStat(statData)
	if err != nil {
		return processIdentity{}, fmt.Errorf("read process %d start time: %w", pid, err)
	}
	bootID := strings.TrimSpace(string(bootData))
	if bootID == "" || strings.ContainsAny(bootID, " \t\r\n") {
		return processIdentity{}, fmt.Errorf("boot id must be a single token")
	}
	return processIdentity{PID: pid, BootID: bootID, StartTime: startTime}, nil
}

func processStartTimeFromStat(data []byte) (string, error) {
	text := strings.TrimSpace(string(data))
	endCommand := strings.LastIndex(text, ")")
	if endCommand < 0 || endCommand+2 >= len(text) {
		return "", fmt.Errorf("stat payload missing command terminator")
	}
	fields := strings.Fields(text[endCommand+2:])
	if len(fields) < 20 {
		return "", fmt.Errorf("stat payload has %d fields after command, want at least 20", len(fields))
	}
	startTime := fields[19]
	if _, err := strconv.ParseUint(startTime, 10, 64); err != nil {
		return "", fmt.Errorf("invalid start time %q: %w", startTime, err)
	}
	return startTime, nil
}

func lockOwnerAlive(lock lockFile) bool {
	if !processAlive(lock.PID) {
		return false
	}
	identity, err := processIdentityForPID(lock.PID)
	if err != nil {
		return true
	}
	return identity.BootID == lock.BootID && identity.StartTime == lock.ProcessStartTime
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func releaseLockFile(path string, kind domain.JobKind, name string, token string) error {
	return withLockGuard(filepath.Dir(path), func() error {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read active job lock: %w", err)
		}
		var current lockFile
		if err := decodeStrictJSON(data, &current); err != nil {
			return fmt.Errorf("decode active job lock: %w", err)
		}
		if current.Kind != kind || effectiveLockName(current) != name || current.Token != token {
			return fmt.Errorf("active job lock changed before release")
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncDir(filepath.Dir(path))
	})
}

func withLockGuard(locksDir string, fn func() error) error {
	guardPath := filepath.Join(locksDir, ".guard")
	fd, err := syscall.Open(guardPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open active job lock guard: %w", err)
	}
	guard := os.NewFile(uintptr(fd), guardPath)
	defer guard.Close()
	if err := syscall.Flock(int(guard.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock active job guard: %w", err)
	}
	defer syscall.Flock(int(guard.Fd()), syscall.LOCK_UN)
	return fn()
}

func (store Store) jobDir(id string) string {
	return filepath.Join(store.dir, "jobs", filepath.Clean(strings.TrimSpace(id)))
}

func (store Store) checkTree() error {
	if store.dir == "" {
		return fmt.Errorf("ui state dir is required")
	}
	if err := checkCreatePath(store.dir, store.expectedUID); err != nil {
		return err
	}
	for _, dir := range []string{store.dir, filepath.Join(store.dir, "jobs"), filepath.Join(store.dir, "locks")} {
		if err := checkDir(dir, store.expectedUID); err != nil {
			return err
		}
	}
	return nil
}

func checkCreatePath(path string, expectedUID uint32) error {
	trimmed := strings.TrimSpace(path)
	clean := filepath.Clean(trimmed)
	if path != trimmed || clean == "." || !filepath.IsAbs(clean) || clean != trimmed {
		return fmt.Errorf("ui state dir must be a clean absolute path")
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("ui state dir must be a clean absolute path")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("inspect ui state path component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ui state path component %s must not be a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("ui state path component %s must be a directory", current)
		}
		if groupOrOtherWritable(info.Mode()) {
			return fmt.Errorf("ui state path component %s must not be writable by group or others", current)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("ui state path component %s owner could not be inspected", current)
		}
		if stat.Uid != expectedUID && stat.Uid != 0 {
			return fmt.Errorf("ui state path component %s owner uid %d does not match effective uid %d or root", current, stat.Uid, expectedUID)
		}
	}
	return nil
}

func groupOrOtherWritable(mode os.FileMode) bool {
	return mode.Perm()&0o022 != 0
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("json payload must contain exactly one value")
		}
		return err
	}
	return nil
}

func validateStoreID(label string, id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("%s is required", label)
	}
	if id != trimmed {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", label)
	}
	if id == "." || id == ".." || strings.Contains(id, "/") || strings.Contains(id, "\\") || filepath.Clean(id) != id {
		return fmt.Errorf("%s must be a single path segment", label)
	}
	if !storeIDPattern.MatchString(id) {
		return fmt.Errorf("%s must use letters, digits, dot, underscore, or dash and start with a letter or digit", label)
	}
	if label != "lock name" && sensitive.ContainsText(id) {
		return fmt.Errorf("%s must not contain sensitive labels", label)
	}
	return nil
}

func cleanAppConfigPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("app config path is required")
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("app config path must not contain control characters")
		}
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve app config path: %w", err)
	}
	clean := filepath.Clean(absolute)
	if clean == "." || !filepath.IsAbs(clean) {
		return "", fmt.Errorf("app config path must resolve to a clean absolute path")
	}
	return clean, nil
}

func validateResourceID(id string) error {
	if err := validateStoreID("resource id", id); err != nil {
		return err
	}
	if !resourceIDPattern.MatchString(id) {
		return fmt.Errorf("resource id must match res_ followed by 32 lowercase hex characters")
	}
	return nil
}

func validateRecord(record domain.JobRecord) error {
	if err := validateJobKind(record.Kind); err != nil {
		return err
	}
	if err := validateJobStatus(record.Status); err != nil {
		return err
	}
	if err := validateActor(record.Actor); err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		return fmt.Errorf("job created_at is required")
	}
	if record.ContainsSecret {
		return fmt.Errorf("job record must not contain secrets")
	}
	if len(record.AuditEventRefs) > 0 {
		return fmt.Errorf("job record audit_event_refs is P1-only and must be empty in P0")
	}
	if record.RedactionStatus == "" {
		return fmt.Errorf("job redaction_status is required")
	}
	switch record.RedactionStatus {
	case domain.RedactionStatusRedacted, domain.RedactionStatusNoSensitiveData, domain.RedactionStatusBlockedSensitiveData:
	default:
		return fmt.Errorf("job redaction_status %q is not supported", record.RedactionStatus)
	}
	if record.CheckpointRef.Kind == "" {
		return fmt.Errorf("job checkpoint_ref is required")
	}
	switch record.CheckpointRef.Kind {
	case domain.ActivationRefCheckpoint:
		if strings.TrimSpace(record.CheckpointRef.Path) == "" {
			return fmt.Errorf("checkpoint activation ref path is required")
		}
	case domain.ActivationRefNotApplicable:
		if jobKindRequiresCheckpointRef(record.Kind) {
			return fmt.Errorf("%s job checkpoint_ref must reference the JSON checkpoint", record.Kind)
		}
	default:
		return fmt.Errorf("job checkpoint_ref.kind %q is not supported", record.CheckpointRef.Kind)
	}
	for _, id := range record.ResourceIDs {
		if err := validateResourceID(id); err != nil {
			return err
		}
	}
	return nil
}

func jobKindRequiresCheckpointRef(kind domain.JobKind) bool {
	switch kind {
	case domain.JobKindDeploy, domain.JobKindAppDeploy, domain.JobKindRealIPRefresh:
		return true
	default:
		return false
	}
}

func validateEvent(event Event) error {
	if event.SchemaVersion != domain.JobEventSchemaVersion {
		return fmt.Errorf("job event schema_version must be %q", domain.JobEventSchemaVersion)
	}
	if err := validateStoreID("event id", event.ID); err != nil {
		return err
	}
	if err := validateStoreID("event job id", event.JobID); err != nil {
		return err
	}
	if event.At.IsZero() {
		return fmt.Errorf("job event at is required")
	}
	if _, err := domain.ParseDiagnosticStatus(string(event.Status)); err != nil {
		return err
	}
	switch event.Redaction {
	case "", domain.RedactionNone, domain.RedactionSecret, domain.RedactionFingerprint:
	default:
		return fmt.Errorf("job event redaction %q is not supported", event.Redaction)
	}
	return nil
}

func validateActor(actor domain.Actor) error {
	switch actor.Source {
	case domain.ActorSourceUI, domain.ActorSourceCLI:
	default:
		return fmt.Errorf("job actor.source %q is not supported", actor.Source)
	}
	if strings.TrimSpace(actor.EffectiveUser) == "" {
		return fmt.Errorf("job actor.effective_user is required")
	}
	if actor.EffectiveUID < 0 {
		return fmt.Errorf("job actor.effective_uid must not be negative")
	}
	if actor.ProcessID < 0 {
		return fmt.Errorf("job actor.process_id must not be negative")
	}
	if actor.Source == domain.ActorSourceUI && strings.TrimSpace(actor.RequestSource) == "" {
		return fmt.Errorf("job actor.request_source is required for ui actors")
	}
	if actor.Source == domain.ActorSourceUI {
		if err := validateUIRequestSource(actor.RequestSource); err != nil {
			return err
		}
		if actor.ProcessID <= 0 {
			return fmt.Errorf("job actor.process_id is required for ui actors")
		}
		if err := validateFingerprint("job actor.session_id_fingerprint", actor.SessionIDFingerprint); err != nil {
			return err
		}
		if err := validateFingerprint("job actor.startup_token_fingerprint", actor.StartupTokenFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func validateUIRequestSource(value string) error {
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("job actor.request_source must not contain leading or trailing whitespace")
	}
	if value == "loopback" {
		return nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("job actor.request_source must be loopback or loopback host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("job actor.request_source must use a loopback IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("job actor.request_source port must be between 0 and 65535")
	}
	return nil
}

func validateFingerprint(label string, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", label)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", label)
	}
	if !fingerprintPattern.MatchString(value) {
		return fmt.Errorf("%s must be sha256: followed by 16 lowercase hex characters", label)
	}
	return nil
}

func stampRecord(record *domain.JobRecord, now time.Time) {
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.Status == domain.JobStatusRunning && record.StartedAt.IsZero() {
		record.StartedAt = domain.NewOptionalTime(now)
	}
	switch record.Status {
	case domain.JobStatusSucceeded, domain.JobStatusFailed, domain.JobStatusInterrupted, domain.JobStatusUnknown:
		if record.CompletedAt.IsZero() {
			record.CompletedAt = domain.NewOptionalTime(now)
		}
	}
	if record.RedactionStatus == "" {
		record.RedactionStatus = domain.RedactionStatusNoSensitiveData
	}
}

func redactRecord(record domain.JobRecord) domain.JobRecord {
	redacted := false
	redact := func(value string) string {
		clean := SanitizeJobText(value)
		if clean != value {
			redacted = true
		}
		return clean
	}
	record.ResultSummary = redact(record.ResultSummary)
	record.ErrorSummary = redact(record.ErrorSummary)
	record.RetryCommand = redact(record.RetryCommand)
	record.ConfigSnapshotRef = redact(record.ConfigSnapshotRef)
	record.CheckpointRef.Path = redact(record.CheckpointRef.Path)
	record.CheckpointRef.Digest = redact(record.CheckpointRef.Digest)
	for i, path := range record.ModifiedPaths {
		record.ModifiedPaths[i] = redact(path)
	}
	if redacted {
		record.RedactionStatus = domain.RedactionStatusRedacted
	}
	record.ContainsSecret = false
	return record
}

func validateJobKind(kind domain.JobKind) error {
	switch kind {
	case domain.JobKindConfigSave,
		domain.JobKindDeploy,
		domain.JobKindVerify,
		domain.JobKindStatus,
		domain.JobKindAppInit,
		domain.JobKindAppConfigSave,
		domain.JobKindAppVerify,
		domain.JobKindAppDeploy,
		domain.JobKindRealIPDiagnostics,
		domain.JobKindRealIPRefresh,
		domain.JobKindRealIPValidateRef,
		domain.JobKindPreAuthKeyCreate,
		domain.JobKindBrowserAuthCreate,
		domain.JobKindBrowserAuthRotate,
		domain.JobKindBrowserAuthDelete,
		domain.JobKindDependencyUpload:
		return nil
	default:
		return fmt.Errorf("job kind %q is not supported", kind)
	}
}

func validateJobStatus(status domain.JobStatus) error {
	switch status {
	case domain.JobStatusQueued,
		domain.JobStatusRunning,
		domain.JobStatusSucceeded,
		domain.JobStatusFailed,
		domain.JobStatusInterrupted,
		domain.JobStatusUnknown:
		return nil
	default:
		return fmt.Errorf("job status %q is not supported", status)
	}
}

func checkDir(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect ui state dir %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ui state dir %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("ui state path %s must be a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("ui state dir %s must not be writable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ui state dir %s owner could not be inspected", path)
	}
	if stat.Uid != uid {
		return fmt.Errorf("ui state dir %s owner uid %d does not match expected uid %d", path, stat.Uid, uid)
	}
	return nil
}

func checkFile(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect ui state file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ui state file %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("ui state path %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("ui state file %s must not be accessible by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ui state file %s owner could not be inspected", path)
	}
	if stat.Uid != uid {
		return fmt.Errorf("ui state file %s owner uid %d does not match expected uid %d", path, stat.Uid, uid)
	}
	return nil
}

func checkExistingFileForOverwrite(path string, uid uint32) error {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect ui state file %s: %w", path, err)
	}
	return checkFile(path, uid)
}

func (store Store) checkJobDirs(id string) error {
	if err := validateStoreID("job id", id); err != nil {
		return err
	}
	if err := checkDir(store.jobDir(id), store.expectedUID); err != nil {
		return err
	}
	if err := checkDir(filepath.Join(store.jobDir(id), "events"), store.expectedUID); err != nil {
		return err
	}
	snapshotsDir := filepath.Join(store.jobDir(id), "config-snapshots")
	if _, err := os.Lstat(snapshotsDir); err == nil {
		if err := checkDir(snapshotsDir, store.expectedUID); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect config snapshots dir %s: %w", snapshotsDir, err)
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return syncDir(dir)
}

func atomicWriteNew(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	cleanup = false
	return syncDir(dir)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func newID(prefix string) string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + time.Now().UTC().Format("20060102T150405.000000000Z") + "_" + hex.EncodeToString(raw[:])
}

func RedactText(text string) string {
	return sensitive.RedactText(text)
}

// SanitizeJobText removes command stream excerpts and redacts sensitive tokens before job text is persisted.
func SanitizeJobText(text string) string {
	return RedactText(omitRawCommandOutput(text))
}

func omitRawCommandOutput(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	markers := []string{
		"output:",
		"stdout:",
		"stderr:",
		"; output:",
		"; stdout:",
		"; stderr:",
		"\noutput:",
		"\nstdout:",
		"\nstderr:",
		" output:",
		" stdout:",
		" stderr:",
	}
	cut := -1
	for _, marker := range markers {
		if idx := strings.Index(lower, marker); idx >= 0 && (cut == -1 || idx < cut) {
			cut = idx
		}
	}
	if cut == -1 {
		return text
	}
	prefix := strings.TrimSpace(text[:cut])
	if prefix == "" {
		return "command output omitted"
	}
	return prefix + "; command output omitted"
}

func redactConfigSnapshot(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	redactingOutputBlock := false
	outputBlockIndent := 0
	for i, line := range lines {
		if redactingOutputBlock {
			if strings.TrimSpace(line) == "" {
				lines[i] = line
				continue
			}
			indent := leadingWhitespace(line)
			if indent > outputBlockIndent || !looksLikeYAMLKey(line) {
				lines[i] = redactSnapshotLine(line)
				continue
			}
			redactingOutputBlock = false
		}
		outputBlock := lineStartsOutputLabel(line)
		if sensitive.ContainsText(line) {
			line = RedactText(line)
		}
		if outputBlock {
			redactingOutputBlock = true
			outputBlockIndent = leadingWhitespace(lines[i])
		}
		lines[i] = line
	}
	return []byte(strings.Join(lines, "\n"))
}

func lineStartsOutputLabel(line string) bool {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return false
	}
	label := sensitiveLabel(strings.ToLower(fields[0]))
	return label == "stdout" || label == "stderr"
}

func redactSnapshotLine(line string) string {
	if strings.TrimSpace(line) == "" {
		return line
	}
	return line[:leadingWhitespace(line)] + "[redacted]"
}

func leadingWhitespace(line string) int {
	for i, r := range line {
		if r != ' ' && r != '\t' {
			return i
		}
	}
	return len(line)
}

func looksLikeYAMLKey(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "- ") {
		return false
	}
	label, _, ok := strings.Cut(trimmed, ":")
	if !ok {
		return false
	}
	label = strings.TrimSpace(label)
	return label != "" && !strings.ContainsAny(label, " \t{}[]")
}

func sensitiveLabel(value string) string {
	value = strings.Trim(value, " \t\r\n\"'`")
	if label, _, ok := strings.Cut(value, "="); ok {
		value = label
	}
	if label, _, ok := strings.Cut(value, ":"); ok {
		value = label
	}
	return strings.TrimRight(value, ":=")
}
