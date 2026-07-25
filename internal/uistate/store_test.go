package uistate

import (
	"encoding/json"
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func secureTempDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	dir, err := os.MkdirTemp(home, ".lanpanel-uistate-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	return dir
}

func TestStoreWritesRecordEventAndRedactsSecrets(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{
		Kind:          domain.JobKindDeploy,
		Status:        domain.JobStatusRunning,
		Actor:         testActor(),
		CheckpointRef: domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: "/var/lib/lanpanel/checkpoint.json"},
		ResultSummary: "token=secret-value should not persist",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	event, err := store.AppendEvent(record.ID, Event{ID: "evt_fixed", At: fixedEventTime(), Status: domain.DiagnosticStatusPass, Message: "password=secret-value"})
	if err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	if _, err := store.AppendEvent(record.ID, event); err == nil {
		t.Fatal("AppendEvent() duplicate error = nil, want no-overwrite failure")
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.SchemaVersion != domain.JobRecordSchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", loaded.SchemaVersion, domain.JobRecordSchemaVersion)
	}
	if strings.Contains(loaded.ResultSummary, "secret-value") {
		t.Fatalf("ResultSummary leaked secret: %q", loaded.ResultSummary)
	}
	if loaded.CreatedAt.IsZero() || loaded.StartedAt.IsZero() {
		t.Fatalf("job timestamps not populated: created=%v started=%v", loaded.CreatedAt, loaded.StartedAt)
	}
	if loaded.RedactionStatus != domain.RedactionStatusRedacted || loaded.ContainsSecret {
		t.Fatalf("redaction contract = status %q contains_secret %v", loaded.RedactionStatus, loaded.ContainsSecret)
	}
	eventsDir := filepath.Join(dir, "jobs", record.ID, "events")
	entries, err := os.ReadDir(eventsDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("event files = %d, want 1", len(entries))
	}
	eventData, err := os.ReadFile(filepath.Join(eventsDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(eventData), domain.JobEventSchemaVersion) {
		t.Fatalf("event data = %s, want schema version", eventData)
	}
	var persistedEvent Event
	if err := json.Unmarshal(eventData, &persistedEvent); err != nil {
		t.Fatalf("Unmarshal(event) error = %v", err)
	}
	if strings.Contains(string(eventData), "secret-value") || persistedEvent.Redaction != domain.RedactionSecret {
		t.Fatalf("event data = %s, want redacted message and redaction metadata", eventData)
	}
	snapshotRef, err := store.WriteConfigSnapshot(record.ID, "main-config.yaml", []byte(strings.Join([]string{
		"api_version: lanpanel.v1",
		"name: visible-app",
		"password: hunter2",
		"client_secret: abc123",
		"proxy_url: http://proxy-user:proxy-pass@proxy.invalid:8080",
		"",
	}, "\n")))
	if err != nil {
		t.Fatalf("WriteConfigSnapshot() error = %v", err)
	}
	snapshotData, err := os.ReadFile(snapshotRef)
	if err != nil {
		t.Fatalf("ReadFile(config snapshot) error = %v", err)
	}
	snapshotText := string(snapshotData)
	for _, leaked := range []string{"hunter2", "abc123", "proxy-user:proxy-pass"} {
		if strings.Contains(snapshotText, leaked) {
			t.Fatalf("config snapshot leaked %q: %s", leaked, snapshotText)
		}
	}
	if !strings.Contains(snapshotText, "visible-app") {
		t.Fatalf("config snapshot = %s, want non-sensitive field retained", snapshotText)
	}
	snapshotInfo, err := os.Stat(snapshotRef)
	if err != nil {
		t.Fatalf("Stat(config snapshot) error = %v", err)
	}
	if snapshotInfo.Mode().Perm() != 0o600 {
		t.Fatalf("config snapshot mode = %o, want 600", snapshotInfo.Mode().Perm())
	}
	if _, err := store.WriteConfigSnapshot(record.ID, "main-config.yaml", []byte("api_version: replaced\n")); err == nil {
		t.Fatal("WriteConfigSnapshot() overwrite error = nil")
	}
	outputSnapshotRef, err := store.WriteConfigSnapshot(record.ID, "output-config.yaml", []byte(strings.Join([]string{
		"name: visible-before-output",
		"stdout:",
		"  raw command output token abc123",
		"next_field: still-visible",
		"stderr: |",
		"  raw stderr output password hunter2",
		"final_field: still-visible-too",
		"",
	}, "\n")))
	if err != nil {
		t.Fatalf("WriteConfigSnapshot(output) error = %v", err)
	}
	outputSnapshotData, err := os.ReadFile(outputSnapshotRef)
	if err != nil {
		t.Fatalf("ReadFile(output config snapshot) error = %v", err)
	}
	outputSnapshotText := string(outputSnapshotData)
	for _, leaked := range []string{"stdout", "stderr", "raw command output", "raw stderr output", "abc123", "hunter2"} {
		if strings.Contains(outputSnapshotText, leaked) {
			t.Fatalf("output config snapshot leaked %q: %s", leaked, outputSnapshotText)
		}
	}
	for _, retained := range []string{"visible-before-output", "next_field: still-visible", "final_field: still-visible-too"} {
		if !strings.Contains(outputSnapshotText, retained) {
			t.Fatalf("output config snapshot = %s, want retained %q", outputSnapshotText, retained)
		}
	}
	if _, err := store.LoadRecord(record.ID); err != nil {
		t.Fatalf("LoadRecord() after config snapshot error = %v", err)
	}
}

func TestStoreOmitsRawCommandOutputFromRecordAndEvents(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{
		Kind:          domain.JobKindVerify,
		Status:        domain.JobStatusFailed,
		Actor:         testActor(),
		ErrorSummary:  "lego failed; output: raw stdout line with host detail",
		ResultSummary: "nginx failed stdout: raw nginx line",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	event, err := store.AppendEvent(record.ID, Event{
		ID:      "evt_command_output",
		At:      fixedEventTime(),
		Status:  domain.DiagnosticStatusFail,
		Message: "systemctl failed stderr: raw systemd line",
	})
	if err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	for _, text := range []string{loaded.ErrorSummary, loaded.ResultSummary, event.Message} {
		for _, leaked := range []string{"output:", "stdout:", "stderr:", "raw stdout line", "raw nginx line", "raw systemd line"} {
			if strings.Contains(text, leaked) {
				t.Fatalf("persisted text %q leaked %q", text, leaked)
			}
		}
		if !strings.Contains(text, "command output omitted") {
			t.Fatalf("persisted text = %q, want omitted command output marker", text)
		}
	}
	if loaded.RedactionStatus != domain.RedactionStatusRedacted || event.Redaction != domain.RedactionSecret {
		t.Fatalf("redaction metadata = record %q event %q, want redacted", loaded.RedactionStatus, event.Redaction)
	}
}

func TestStoreRegistersKnownAppConfigPaths(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	store := NewStore(dir)
	first := filepath.Join(dir, "apps", "first.yaml")
	second := filepath.Join(dir, "other", "second.yaml")
	if err := store.RegisterAppConfigPath(second); err != nil {
		t.Fatalf("RegisterAppConfigPath(second) error = %v", err)
	}
	if err := store.RegisterAppConfigPath(first); err != nil {
		t.Fatalf("RegisterAppConfigPath(first) error = %v", err)
	}
	if err := store.RegisterAppConfigPath(first); err != nil {
		t.Fatalf("RegisterAppConfigPath(duplicate) error = %v", err)
	}
	paths, err := store.ListAppConfigPaths()
	if err != nil {
		t.Fatalf("ListAppConfigPaths() error = %v", err)
	}
	want := []string{filepath.Clean(first), filepath.Clean(second)}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
	data, err := os.ReadFile(filepath.Join(dir, appConfigPathIndexFile))
	if err != nil {
		t.Fatalf("ReadFile(index) error = %v", err)
	}
	if !strings.Contains(string(data), appConfigPathIndexSchema) {
		t.Fatalf("index = %s, want schema", data)
	}
	info, err := os.Stat(filepath.Join(dir, appConfigPathIndexFile))
	if err != nil {
		t.Fatalf("Stat(index) error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("index mode = %o, want 600", info.Mode().Perm())
	}
}

func TestStoreRejectsCorruptKnownAppConfigPathIndex(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, appConfigPathIndexFile), []byte(`{"schema_version":"bad","paths":[]}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(index) error = %v", err)
	}
	if _, err := store.ListAppConfigPaths(); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("ListAppConfigPaths() error = %v, want schema failure", err)
	}
}

func TestStoreKeepsLiveLockDuringRecovery(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	lock, err := store.AcquireLock(domain.JobKindDeploy)
	if err != nil {
		t.Fatalf("AcquireLock() error = %v", err)
	}
	if _, err := store.AcquireLock(domain.JobKindDeploy); err == nil {
		t.Fatal("AcquireLock() contention error = nil")
	}
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if err := lock.AttachJob(record.ID); err != nil {
		t.Fatalf("AttachJob() error = %v", err)
	}
	if err := store.RecoverInterrupted(); err == nil || !strings.Contains(err.Error(), "live pid") {
		t.Fatalf("RecoverInterrupted() error = %v, want live lock failure", err)
	}
	if _, err := os.Stat(lock.path); err != nil {
		t.Fatalf("live lock stat error = %v, want lock retained", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusRunning {
		t.Fatalf("Status = %q, want running", loaded.Status)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
}

func TestStoreNamedLockBlocksDifferentKinds(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	lock, err := store.AcquireNamedLock(domain.JobKindDeploy, HostMutationLockName)
	if err != nil {
		t.Fatalf("AcquireNamedLock(deploy) error = %v", err)
	}
	if _, err := store.AcquireNamedLock(domain.JobKindAppDeploy, HostMutationLockName); err == nil || !strings.Contains(err.Error(), HostMutationLockName) {
		t.Fatalf("AcquireNamedLock(app deploy) error = %v, want host mutation contention", err)
	}
	appKindLock, err := store.AcquireLock(domain.JobKindAppDeploy)
	if err != nil {
		t.Fatalf("AcquireLock(app deploy) error = %v", err)
	}
	if err := appKindLock.Release(); err != nil {
		t.Fatalf("Release(app kind lock) error = %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release(host mutation lock) error = %v", err)
	}
}

func TestLockReleaseRejectsChangedOrMissingLock(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	lock, err := store.AcquireLock(domain.JobKindDeploy)
	if err != nil {
		t.Fatalf("AcquireLock() error = %v", err)
	}
	replacement := []byte(`{"kind":"deploy","pid":999999,"token":"lock_replacement"}` + "\n")
	if err := os.WriteFile(lock.path, replacement, 0o600); err != nil {
		t.Fatalf("WriteFile(replacement lock) error = %v", err)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "changed before release") {
		t.Fatalf("Release() error = %v, want changed lock failure", err)
	}
	data, err := os.ReadFile(lock.path)
	if err != nil {
		t.Fatalf("ReadFile(replacement lock) error = %v", err)
	}
	if !strings.Contains(string(data), "lock_replacement") {
		t.Fatalf("replacement lock data = %s", data)
	}

	lock, err = store.AcquireLock(domain.JobKindVerify)
	if err != nil {
		t.Fatalf("AcquireLock(verify) error = %v", err)
	}
	if err := os.Remove(lock.path); err != nil {
		t.Fatalf("Remove(lock) error = %v", err)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "read active job lock") {
		t.Fatalf("Release() error = %v, want missing lock failure", err)
	}
}

func TestStoreRemovesStaleLockAndRecoversInterruptedJob(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	lockPath := filepath.Join(dir, "locks", string(domain.JobKindDeploy)+".lock")
	lockData := []byte(`{"kind":"deploy","job_id":"` + record.ID + `","pid":999999,"token":"lock_stale"}` + "\n")
	if err := os.WriteFile(lockPath, lockData, 0o600); err != nil {
		t.Fatalf("WriteFile(lock) error = %v", err)
	}
	tmpPath := filepath.Join(dir, "locks", ".tmp-leftover")
	if err := os.WriteFile(tmpPath, []byte("partial"), 0o600); err != nil {
		t.Fatalf("WriteFile(lock temp) error = %v", err)
	}
	if err := store.RecoverInterrupted(); err != nil {
		t.Fatalf("RecoverInterrupted() error = %v", err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("stale lock stat error = %v, want removed lock", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusInterrupted {
		t.Fatalf("Status = %q, want interrupted", loaded.Status)
	}
	if loaded.ConfigSnapshotRef != "not_applicable" {
		t.Fatalf("ConfigSnapshotRef = %q, want not_applicable", loaded.ConfigSnapshotRef)
	}
	if loaded.RetryCommand != "not_applicable" {
		t.Fatalf("RetryCommand = %q, want not_applicable without config path", loaded.RetryCommand)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("lock temp stat error = %v, want removed temp file", err)
	}
}

func TestStoreRecoversStaleLockWithReusedLivePID(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	identity, err := currentProcessIdentity()
	if err != nil {
		t.Fatalf("currentProcessIdentity() error = %v", err)
	}
	lockPath := filepath.Join(dir, "locks", string(domain.JobKindDeploy)+".lock")
	lockData, err := json.Marshal(lockFile{
		Kind:             domain.JobKindDeploy,
		JobID:            record.ID,
		PID:              identity.PID,
		BootID:           identity.BootID,
		ProcessStartTime: "0",
		Token:            "lock_reused_pid",
	})
	if err != nil {
		t.Fatalf("Marshal(lock) error = %v", err)
	}
	if err := os.WriteFile(lockPath, append(lockData, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile(lock) error = %v", err)
	}
	if err := store.RecoverInterrupted(); err != nil {
		t.Fatalf("RecoverInterrupted() error = %v", err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("stale reused-pid lock stat error = %v, want removed lock", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusInterrupted {
		t.Fatalf("Status = %q, want interrupted", loaded.Status)
	}
}

func TestStoreRejectsLivePIDLockWithMissingOwnerIdentity(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	lockPath := filepath.Join(dir, "locks", string(domain.JobKindDeploy)+".lock")
	lockData := []byte(`{"kind":"deploy","job_id":"` + record.ID + `","pid":` + strconv.Itoa(os.Getpid()) + `,"token":"lock_missing_identity"}` + "\n")
	if err := os.WriteFile(lockPath, lockData, 0o600); err != nil {
		t.Fatalf("WriteFile(lock) error = %v", err)
	}
	err = store.RecoverInterrupted()
	if err == nil || !strings.Contains(err.Error(), "boot_id is required") {
		t.Fatalf("RecoverInterrupted() error = %v, want missing boot_id failure", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("live invalid lock stat error = %v, want lock retained", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusRunning {
		t.Fatalf("Status = %q, want running", loaded.Status)
	}
}

func TestStoreRejectsDeployWithoutCheckpoint(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want checkpoint_ref failure")
	}
}

func TestStoreRecoversPastStaleCorruptLock(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	lockPath := filepath.Join(dir, "locks", string(domain.JobKindDeploy)+".lock")
	if err := os.WriteFile(lockPath, []byte(`{"kind":"deploy","job_id":"`+record.ID+`","pid":999999,`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(lock) error = %v", err)
	}
	if err := store.RecoverInterrupted(); err != nil {
		t.Fatalf("RecoverInterrupted() error = %v", err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("stale corrupt lock stat error = %v, want removed lock", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusInterrupted {
		t.Fatalf("Status = %q, want interrupted", loaded.Status)
	}
}

func TestStoreRecoverInterruptedSkipsIncompleteJobDirsWithoutCommittedRecord(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	missingRecordDir := filepath.Join(dir, "jobs", "job_missing_record")
	if err := os.MkdirAll(filepath.Join(missingRecordDir, "events"), 0o700); err != nil {
		t.Fatalf("MkdirAll(missingRecordDir) error = %v", err)
	}
	missingEventsDir := filepath.Join(dir, "jobs", "job_missing_events")
	if err := os.Mkdir(missingEventsDir, 0o700); err != nil {
		t.Fatalf("Mkdir(missingEventsDir) error = %v", err)
	}

	if err := store.RecoverInterrupted(); err != nil {
		t.Fatalf("RecoverInterrupted() error = %v", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if loaded.Status != domain.JobStatusInterrupted {
		t.Fatalf("Status = %q, want interrupted", loaded.Status)
	}
}

func TestStoreRecoverInterruptedRejectsInvalidCommittedJobRecord(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{name: "corrupt json", data: "{", wantErr: "decode recovery job record"},
		{name: "unknown field", data: `{"schema_version":"lanpanel.job.v1","job_id":"job_unknown_field","kind":"deploy","status":"running","actor":{"source":"ui","effective_uid":0,"effective_user":"uid:0","process_id":1234,"request_source":"loopback","session_id_fingerprint":"sha256:0011223344556677","startup_token_fingerprint":"sha256:8899aabbccddeeff"},"checkpoint_ref":{"kind":"checkpoint","path":"/var/lib/lanpanel/checkpoint.json"},"created_at":"2026-06-20T12:00:00Z","started_at":"not_applicable","completed_at":"not_applicable","redaction_status":"no_sensitive_data","contains_secret":false,"unexpected":true}`, wantErr: "unknown field"},
		{name: "wrong schema", data: `{"schema_version":"lanpanel.job.v0","job_id":"job_wrong_schema","kind":"deploy","status":"running","actor":{"source":"ui","effective_uid":0,"effective_user":"uid:0","process_id":1234,"request_source":"loopback","session_id_fingerprint":"sha256:0011223344556677","startup_token_fingerprint":"sha256:8899aabbccddeeff"},"checkpoint_ref":{"kind":"checkpoint","path":"/var/lib/lanpanel/checkpoint.json"},"created_at":"2026-06-20T12:00:00Z","started_at":"not_applicable","completed_at":"not_applicable","redaction_status":"no_sensitive_data","contains_secret":false}`, wantErr: "schema_version"},
		{name: "mismatched id", data: `{"schema_version":"lanpanel.job.v1","job_id":"job_other","kind":"deploy","status":"running","actor":{"source":"ui","effective_uid":0,"effective_user":"uid:0","process_id":1234,"request_source":"loopback","session_id_fingerprint":"sha256:0011223344556677","startup_token_fingerprint":"sha256:8899aabbccddeeff"},"checkpoint_ref":{"kind":"checkpoint","path":"/var/lib/lanpanel/checkpoint.json"},"created_at":"2026-06-20T12:00:00Z","started_at":"not_applicable","completed_at":"not_applicable","redaction_status":"no_sensitive_data","contains_secret":false}`, wantErr: "does not match directory"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			jobID := "job_" + strings.ReplaceAll(tt.name, " ", "_")
			jobDir := filepath.Join(dir, "jobs", jobID)
			if err := os.MkdirAll(filepath.Join(jobDir, "events"), 0o700); err != nil {
				t.Fatalf("MkdirAll(jobDir) error = %v", err)
			}
			if err := os.WriteFile(filepath.Join(jobDir, "record.json"), []byte(tt.data), 0o600); err != nil {
				t.Fatalf("WriteFile(record) error = %v", err)
			}
			err := store.RecoverInterrupted()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("RecoverInterrupted() error = %v, want %q", err, tt.wantErr)
			}
			if err := os.RemoveAll(jobDir); err != nil {
				t.Fatalf("RemoveAll(jobDir) error = %v", err)
			}
		})
	}
}

func TestStoreRecoverInterruptedRejectsCommittedRecordWithoutEventsDir(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	jobDir := filepath.Join(dir, "jobs", "job_missing_events_committed")
	if err := os.Mkdir(jobDir, 0o700); err != nil {
		t.Fatalf("Mkdir(jobDir) error = %v", err)
	}
	data := []byte(`{"schema_version":"lanpanel.job.v1","job_id":"job_missing_events_committed","kind":"deploy","status":"running","actor":{"source":"ui","effective_uid":0,"effective_user":"uid:0","process_id":1234,"request_source":"loopback","session_id_fingerprint":"sha256:0011223344556677","startup_token_fingerprint":"sha256:8899aabbccddeeff"},"checkpoint_ref":{"kind":"checkpoint","path":"/var/lib/lanpanel/checkpoint.json"},"created_at":"2026-06-20T12:00:00Z","started_at":"not_applicable","completed_at":"not_applicable","redaction_status":"no_sensitive_data","contains_secret":false}`)
	if err := os.WriteFile(filepath.Join(jobDir, "record.json"), data, 0o600); err != nil {
		t.Fatalf("WriteFile(record) error = %v", err)
	}
	if err := store.RecoverInterrupted(); err == nil || !strings.Contains(err.Error(), "events dir") {
		t.Fatalf("RecoverInterrupted() error = %v, want committed record events dir failure", err)
	}
}

func TestStoreListRecordsSkipsUncommittedJobDirsAfterRecovery(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	for _, jobID := range []string{"job_missing_record", "job_missing_record_with_events"} {
		jobDir := filepath.Join(dir, "jobs", jobID)
		if err := os.Mkdir(jobDir, 0o700); err != nil {
			t.Fatalf("Mkdir(%s) error = %v", jobDir, err)
		}
		if strings.Contains(jobID, "with_events") {
			if err := os.Mkdir(filepath.Join(jobDir, "events"), 0o700); err != nil {
				t.Fatalf("Mkdir(events) error = %v", err)
			}
		}
	}

	if err := store.RecoverInterrupted(); err != nil {
		t.Fatalf("RecoverInterrupted() error = %v", err)
	}
	records, err := store.ListRecords()
	if err != nil {
		t.Fatalf("ListRecords() error = %v", err)
	}
	if len(records) != 1 || records[0].ID != record.ID || records[0].Status != domain.JobStatusInterrupted {
		t.Fatalf("records = %#v, want only interrupted committed job %s", records, record.ID)
	}
}

func TestStoreRecoverInterruptedRejectsNonDirectoryJobEntry(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "jobs", "job_file"), []byte("bad"), 0o600); err != nil {
		t.Fatalf("WriteFile(job_file) error = %v", err)
	}
	if err := store.RecoverInterrupted(); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("RecoverInterrupted() error = %v, want non-directory refusal", err)
	}
}

func TestStoreRecoverInterruptedRefusesUnsafeIncompleteJobDir(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "jobs", "job_link")); err != nil {
		t.Fatalf("Symlink(job_link) error = %v", err)
	}
	if err := store.RecoverInterrupted(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("RecoverInterrupted() error = %v, want symlink refusal", err)
	}
}

func TestStoreRecoverInterruptedPreservesExistingRetryCommand(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{
		Kind:          domain.JobKindDeploy,
		Status:        domain.JobStatusRunning,
		Actor:         testActor(),
		CheckpointRef: testCheckpointRef(),
		ModifiedPaths: []string{"/tmp/lan panel/main.yaml"},
		RetryCommand:  "sudo lanpanel deploy --config /etc/lanpanel/lanpanel.yaml",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if err := store.RecoverInterrupted(); err != nil {
		t.Fatalf("RecoverInterrupted() error = %v", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	want := "sudo lanpanel deploy --config /etc/lanpanel/lanpanel.yaml"
	if loaded.RetryCommand != want {
		t.Fatalf("RetryCommand = %q, want %q", loaded.RetryCommand, want)
	}
	if loaded.ConfigSnapshotRef != "not_applicable" {
		t.Fatalf("ConfigSnapshotRef = %q, want not_applicable", loaded.ConfigSnapshotRef)
	}
}

func TestStoreRejectsSymlinkStateDir(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := NewStore(link).Open(); err == nil {
		t.Fatal("Open() error = nil, want symlink refusal")
	}
}

func TestStoreRejectsUnsafeStateDirAncestors(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(dir) error = %v", err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := NewStore(filepath.Join(link, "state")).Open(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Open(symlink ancestor) error = %v, want symlink ancestor refusal", err)
	}

	writable := filepath.Join(dir, "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatalf("Mkdir(writable) error = %v", err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatalf("Chmod(writable) error = %v", err)
	}
	if err := NewStore(filepath.Join(writable, "state")).Open(); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("Open(writable ancestor) error = %v, want writable ancestor refusal", err)
	}

	sticky := filepath.Join(dir, "sticky")
	if err := os.Mkdir(sticky, 0o777); err != nil {
		t.Fatalf("Mkdir(sticky) error = %v", err)
	}
	if err := os.Chmod(sticky, 0o1777); err != nil {
		t.Fatalf("Chmod(sticky) error = %v", err)
	}
	if err := NewStore(filepath.Join(sticky, "state")).Open(); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("Open(sticky ancestor) error = %v, want sticky writable ancestor refusal", err)
	}
}

func TestStoreRejectsNonCanonicalStateDir(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	for _, path := range []string{
		dir + string(os.PathSeparator) + "state" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "state2",
		dir + string(os.PathSeparator),
		dir + string(os.PathSeparator) + string(os.PathSeparator) + "state",
		" " + filepath.Join(dir, "state"),
		filepath.Join(dir, "state") + " ",
	} {
		if err := NewStore(path).Open(); err == nil || !strings.Contains(err.Error(), "clean absolute path") {
			t.Fatalf("Open(%q) error = %v, want clean absolute path failure", path, err)
		}
	}
}

func TestStoreRejectsRecordWithMissingSchemaVersion(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	jobDir := filepath.Join(dir, "jobs", "job_missing_schema")
	if err := os.MkdirAll(jobDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(jobDir, "events"), 0o700); err != nil {
		t.Fatalf("Mkdir(events) error = %v", err)
	}
	data := []byte(`{"job_id":"job_missing_schema","kind":"deploy","status":"running","actor":{"source":"ui","effective_uid":0,"effective_user":"uid:0","request_source":"loopback"},"checkpoint_ref":{"kind":"not_applicable"}}`)
	if err := os.WriteFile(filepath.Join(jobDir, "record.json"), data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := store.LoadRecord("job_missing_schema"); err == nil {
		t.Fatal("LoadRecord() error = nil, want schema_version failure")
	}
}

func TestStoreRejectsMismatchedPersistedRecordID(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	jobDir := filepath.Join(dir, "jobs", "job_requested")
	if err := os.MkdirAll(filepath.Join(jobDir, "events"), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	data := []byte(`{"schema_version":"lanpanel.job.v1","job_id":"job_other","kind":"deploy","status":"running","actor":{"source":"ui","effective_uid":0,"effective_user":"uid:0","request_source":"loopback"},"checkpoint_ref":{"kind":"not_applicable"},"created_at":"2026-06-20T12:00:00Z","redaction_status":"no_sensitive_data","contains_secret":false}`)
	if err := os.WriteFile(filepath.Join(jobDir, "record.json"), data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := store.LoadRecord("job_requested"); err == nil || !strings.Contains(err.Error(), "does not match requested job id") {
		t.Fatalf("LoadRecord() error = %v, want mismatched id failure", err)
	}
}

func TestStoreSaveRecordRequiresSchemaVersion(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	record.SchemaVersion = ""
	if err := store.SaveRecord(record); err == nil {
		t.Fatal("SaveRecord() error = nil, want schema_version failure")
	}
}

func TestStoreSaveRecordRejectsUnsafeExistingRecordFile(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor(), CheckpointRef: testCheckpointRef()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	recordPath := filepath.Join(dir, "jobs", record.ID, "record.json")
	if err := os.Chmod(recordPath, 0o644); err != nil {
		t.Fatalf("Chmod(record) error = %v", err)
	}
	record.Status = domain.JobStatusSucceeded
	if err := store.SaveRecord(record); err == nil {
		t.Fatal("SaveRecord() error = nil, want unsafe existing record mode failure")
	}
}

func TestStoreRejectsPathTraversalIDs(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if _, err := store.CreateJob(domain.JobRecord{ID: "../escape", Kind: domain.JobKindDeploy, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want traversal id failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{ID: " job_with_space ", Kind: domain.JobKindDeploy, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want non-canonical id failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{ID: "job_with space", Kind: domain.JobKindDeploy, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want internal space id failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{ID: "job_token_abc", Kind: domain.JobKindDeploy, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want sensitive label id failure")
	}
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: testActor()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if _, err := store.AppendEvent(record.ID, Event{ID: "../escape", Status: domain.DiagnosticStatusPass, Message: "ok"}); err == nil {
		t.Fatal("AppendEvent() error = nil, want traversal event id failure")
	}
	if _, err := store.AppendEvent(record.ID, Event{ID: "evt_token_abc", Status: domain.DiagnosticStatusPass, Message: "ok"}); err == nil {
		t.Fatal("AppendEvent() error = nil, want sensitive label event id failure")
	}
	if _, err := store.AppendEvent(record.ID, Event{Status: domain.DiagnosticStatus("future"), Message: "ok"}); err == nil {
		t.Fatal("AppendEvent() error = nil, want unsupported event status failure")
	}
	eventsDir := filepath.Join(dir, "jobs", record.ID, "events")
	entries, err := os.ReadDir(eventsDir)
	if err != nil {
		t.Fatalf("ReadDir(events) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("event files = %d, want no corrupt event persisted", len(entries))
	}
	if _, err := store.AcquireLock(domain.JobKind("../escape")); err == nil {
		t.Fatal("AcquireLock() error = nil, want traversal kind failure")
	}
}

func TestStoreValidatesPersistedResourceIDs(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if _, err := store.CreateJob(domain.JobRecord{
		Kind:        domain.JobKindVerify,
		Actor:       testActor(),
		ResourceIDs: []string{"res_token_abc"},
	}); err == nil {
		t.Fatal("CreateJob() error = nil, want malformed resource id failure")
	}
	record, err := store.CreateJob(domain.JobRecord{
		Kind:        domain.JobKindVerify,
		Actor:       testActor(),
		ResourceIDs: []string{"res_00112233445566778899aabbccddeeff"},
	})
	if err != nil {
		t.Fatalf("CreateJob(valid resource id) error = %v", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	if strings.Join(loaded.ResourceIDs, ",") != "res_00112233445566778899aabbccddeeff" {
		t.Fatalf("ResourceIDs = %#v, want persisted valid resource id", loaded.ResourceIDs)
	}
}

func TestStoreValidatesUIActorRequestSource(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	for _, source := range []string{
		"https://127.0.0.1:18080/?token=secret",
		"192.0.2.10:1234",
		" 127.0.0.1:1234",
		"127.0.0.1:not-a-port",
	} {
		actor := testActor()
		actor.RequestSource = source
		if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: actor}); err == nil {
			t.Fatalf("CreateJob(request_source=%q) error = nil, want request source failure", source)
		}
	}
	actor := testActor()
	actor.RequestSource = "[::1]:443"
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: actor}); err != nil {
		t.Fatalf("CreateJob(loopback IPv6 request source) error = %v", err)
	}
}

func TestStoreRejectsUnsafeJobStatePaths(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: testActor()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	recordPath := filepath.Join(dir, "jobs", record.ID, "record.json")
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	if err := os.Remove(recordPath); err != nil {
		t.Fatalf("Remove(record) error = %v", err)
	}
	if err := os.Symlink(target, recordPath); err != nil {
		t.Fatalf("Symlink(record) error = %v", err)
	}
	record.Status = domain.JobStatusSucceeded
	if err := store.SaveRecord(record); err == nil {
		t.Fatal("SaveRecord() error = nil, want record symlink overwrite refusal")
	}
	if _, err := store.LoadRecord(record.ID); err == nil {
		t.Fatal("LoadRecord() error = nil, want record symlink failure")
	}

	eventsDir := filepath.Join(dir, "jobs", record.ID, "events")
	eventsTarget := filepath.Join(dir, "events-target")
	if err := os.Mkdir(eventsTarget, 0o700); err != nil {
		t.Fatalf("Mkdir(eventsTarget) error = %v", err)
	}
	if err := os.RemoveAll(eventsDir); err != nil {
		t.Fatalf("RemoveAll(eventsDir) error = %v", err)
	}
	if err := os.Symlink(eventsTarget, eventsDir); err != nil {
		t.Fatalf("Symlink(events) error = %v", err)
	}
	if _, err := store.AppendEvent(record.ID, Event{Status: domain.DiagnosticStatusPass, Message: "ok"}); err == nil {
		t.Fatal("AppendEvent() error = nil, want events dir symlink failure")
	}
}

func TestStoreRejectsReplacedJobsParentSymlink(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: testActor()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	target := filepath.Join(dir, "jobs-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "jobs")); err != nil {
		t.Fatalf("RemoveAll(jobs) error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "jobs")); err != nil {
		t.Fatalf("Symlink(jobs) error = %v", err)
	}
	if _, err := store.LoadRecord(record.ID); err == nil {
		t.Fatal("LoadRecord() error = nil, want jobs parent symlink failure")
	}
}

func TestStoreListRecordsRejectsUnsafeJobEntries(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if err := store.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	jobFile := filepath.Join(dir, "jobs", "job_file")
	if err := os.WriteFile(jobFile, []byte("bad"), 0o600); err != nil {
		t.Fatalf("WriteFile(job_file) error = %v", err)
	}
	if _, err := store.ListRecords(); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("ListRecords() error = %v, want non-directory refusal", err)
	}
	if err := os.Remove(jobFile); err != nil {
		t.Fatalf("Remove(job_file) error = %v", err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "jobs", "job_link")); err != nil {
		t.Fatalf("Symlink(job_link) error = %v", err)
	}
	if _, err := store.ListRecords(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("ListRecords() error = %v, want symlink refusal", err)
	}
}

func TestStoreListEventsIgnoresTempFilesWithoutRemovingThem(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: testActor()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if _, err := store.AppendEvent(record.ID, Event{Status: domain.DiagnosticStatusPass, Message: "ok"}); err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	tmpPath := filepath.Join(dir, "jobs", record.ID, "events", ".tmp-leftover")
	if err := os.WriteFile(tmpPath, []byte("partial"), 0o600); err != nil {
		t.Fatalf("WriteFile(temp) error = %v", err)
	}
	events, err := store.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want one real event", len(events))
	}
	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("temp stat error = %v, want temp file left for active writer", err)
	}
}

func TestStoreListEventsOrdersSameTimestampByID(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: testActor()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	at := fixedEventTime()
	if _, err := store.AppendEvent(record.ID, Event{ID: "evt_b", At: at, Status: domain.DiagnosticStatusPass, Message: "second"}); err != nil {
		t.Fatalf("AppendEvent(evt_b) error = %v", err)
	}
	if _, err := store.AppendEvent(record.ID, Event{ID: "evt_a", At: at, Status: domain.DiagnosticStatusPass, Message: "first"}); err != nil {
		t.Fatalf("AppendEvent(evt_a) error = %v", err)
	}
	events, err := store.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if len(events) != 2 || events[0].ID != "evt_a" || events[1].ID != "evt_b" {
		t.Fatalf("events = %#v, want same timestamp sorted by id", events)
	}
}

func TestStoreRedactsPersistedRecordReferenceFields(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{
		Kind:              domain.JobKindDeploy,
		Actor:             testActor(),
		CheckpointRef:     domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: "/var/lib/lanpanel/token abc123/checkpoint.json"},
		ModifiedPaths:     []string{"/etc/lanpanel/password hunter2"},
		RetryCommand:      "lanpanel deploy --token abc123",
		ConfigSnapshotRef: "preauth opaque",
		ResultSummary:     "proxy http://proxy-user:proxy-pass@proxy.invalid:8080/path",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	loaded, err := store.LoadRecord(record.ID)
	if err != nil {
		t.Fatalf("LoadRecord() error = %v", err)
	}
	data := strings.Join([]string{loaded.CheckpointRef.Path, strings.Join(loaded.ModifiedPaths, " "), loaded.RetryCommand, loaded.ConfigSnapshotRef, loaded.ResultSummary}, " ")
	if strings.Contains(data, "abc123") || strings.Contains(data, "hunter2") || strings.Contains(data, "opaque") || strings.Contains(data, "proxy-user:proxy-pass") {
		t.Fatalf("persisted record references leaked secret material: %#v", loaded)
	}
	if loaded.RedactionStatus != domain.RedactionStatusRedacted || loaded.ContainsSecret {
		t.Fatalf("redaction contract = status %q contains_secret %v", loaded.RedactionStatus, loaded.ContainsSecret)
	}
}

func TestStoreRedactsURLUserinfoInEvents(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	record, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: testActor()})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if _, err := store.AppendEvent(record.ID, Event{
		ID:      "evt_url",
		At:      fixedEventTime(),
		Status:  domain.DiagnosticStatusPass,
		Message: "proxy http://proxy-user:proxy-pass@proxy.invalid:8080/path",
	}); err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	events, err := store.ListEvents(record.ID)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if strings.Contains(events[0].Message, "proxy-user:proxy-pass") {
		t.Fatalf("event message leaked URL userinfo: %q", events[0].Message)
	}
	if !strings.Contains(events[0].Message, "http://[redacted]@proxy.invalid:8080/path") {
		t.Fatalf("event message = %q, want redacted URL userinfo", events[0].Message)
	}
	if events[0].Redaction != domain.RedactionSecret {
		t.Fatalf("event redaction = %q, want secret", events[0].Redaction)
	}
}

func TestStoreRejectsIncompleteRecords(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	store := NewStore(dir)
	if _, err := store.CreateJob(domain.JobRecord{Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want missing kind failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy}); err == nil {
		t.Fatal("CreateJob() error = nil, want missing actor failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Actor: testActor(), AuditEventRefs: []string{"audit_001"}}); err == nil {
		t.Fatal("CreateJob() error = nil, want P1 audit_event_refs failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindDeploy, Status: domain.JobStatusRunning, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want deploy checkpoint_ref failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindAppDeploy, Status: domain.JobStatusRunning, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want app deploy checkpoint_ref failure")
	}
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindRealIPRefresh, Status: domain.JobStatusRunning, Actor: testActor()}); err == nil {
		t.Fatal("CreateJob() error = nil, want realip refresh checkpoint_ref failure")
	}
	missingTokenActor := testActor()
	missingTokenActor.StartupTokenFingerprint = ""
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: missingTokenActor}); err == nil {
		t.Fatal("CreateJob() error = nil, want missing startup token fingerprint failure")
	}
	missingSessionActor := testActor()
	missingSessionActor.SessionIDFingerprint = ""
	if _, err := store.CreateJob(domain.JobRecord{Kind: domain.JobKindVerify, Actor: missingSessionActor}); err == nil {
		t.Fatal("CreateJob() error = nil, want missing session fingerprint failure")
	}
}

func TestRedactTextMasksAuthHeadersAndPreauthKeys(t *testing.T) {
	t.Parallel()

	redacted := RedactText("Authorization: Basic abc Bearer keep tskey-auth-secret hskey-auth-secret")
	if strings.Contains(redacted, "Authorization") || strings.Contains(redacted, "Basic") || strings.Contains(redacted, "abc") || strings.Contains(redacted, "tskey-auth-secret") || strings.Contains(redacted, "hskey-auth-secret") {
		t.Fatalf("RedactText() = %q", redacted)
	}
	bearer := RedactText("Authorization Bearer payload")
	if strings.Contains(bearer, "Bearer") || strings.Contains(bearer, "payload") {
		t.Fatalf("RedactText() = %q", bearer)
	}
	joined := RedactText("Authorization=Bearer payload")
	if strings.Contains(joined, "payload") {
		t.Fatalf("RedactText() = %q", joined)
	}
	spacedEquals := RedactText("Authorization = Bearer payload")
	if strings.Contains(spacedEquals, "Bearer") || strings.Contains(spacedEquals, "payload") {
		t.Fatalf("RedactText() = %q", spacedEquals)
	}
	spacedColon := RedactText("Authorization : Basic payload")
	if strings.Contains(spacedColon, "Basic") || strings.Contains(spacedColon, "payload") {
		t.Fatalf("RedactText() = %q", spacedColon)
	}
	opaque := RedactText("lanpanel deploy --token abc123 password hunter2 authkey xyz preauth opaque")
	for _, leaked := range []string{"abc123", "hunter2", "xyz", "opaque"} {
		if strings.Contains(opaque, leaked) {
			t.Fatalf("RedactText() = %q, leaked %q", opaque, leaked)
		}
	}
	natural := RedactText("browser auth password is hunter2")
	if strings.Contains(natural, "hunter2") {
		t.Fatalf("RedactText() = %q, leaked natural-language password", natural)
	}
	preauth := RedactText("preauth key mkey:abcdef")
	if strings.Contains(preauth, "mkey:abcdef") {
		t.Fatalf("RedactText() = %q, leaked preauth key", preauth)
	}
	urlUserinfo := RedactText("proxy http://proxy-user:proxy-pass@proxy.invalid:8080/path")
	if strings.Contains(urlUserinfo, "proxy-user:proxy-pass") || !strings.Contains(urlUserinfo, "http://[redacted]@proxy.invalid:8080/path") {
		t.Fatalf("RedactText() = %q, want URL userinfo redacted", urlUserinfo)
	}
	header := RedactText("Authorization header: Basic abc")
	if strings.Contains(header, "Basic") || strings.Contains(header, "abc") {
		t.Fatalf("RedactText() = %q, leaked authorization header", header)
	}
	cookie := RedactText("Cookie: session=abc")
	if strings.Contains(cookie, "session=abc") {
		t.Fatalf("RedactText() = %q, leaked cookie", cookie)
	}
	for _, tt := range []struct {
		name  string
		input string
		leaks []string
	}{
		{name: "bare bearer", input: "Bearer abc123", leaks: []string{"Bearer", "abc123"}},
		{name: "bare basic", input: "Basic abc123", leaks: []string{"Basic", "abc123"}},
		{name: "x api key", input: "X-API-Key: abc123", leaks: []string{"X-API-Key", "abc123"}},
		{name: "api key equals", input: "api_key=abc123", leaks: []string{"api_key", "abc123"}},
		{name: "access key", input: "access-key abc123", leaks: []string{"access-key", "abc123"}},
		{name: "client secret", input: "client_secret is abc123", leaks: []string{"client_secret", "abc123"}},
		{name: "spaced api key", input: "api key abc123", leaks: []string{"api", "key", "abc123"}},
		{name: "spaced access key", input: "access key abc123", leaks: []string{"access", "key", "abc123"}},
		{name: "spaced client secret", input: "client secret abc123", leaks: []string{"client", "secret", "abc123"}},
		{name: "spaced api key equals", input: "api key=abc123", leaks: []string{"api", "key", "abc123"}},
		{name: "spaced access key colon", input: "access key:abc123", leaks: []string{"access", "key", "abc123"}},
		{name: "spaced client secret equals", input: "client secret=abc123", leaks: []string{"client", "secret", "abc123"}},
		{name: "tailscale url", input: "https://example.invalid/login?authkey=tskey-auth-abc123", leaks: []string{"tskey-auth-abc123"}},
		{name: "stdout label", input: "stdout: raw command output token abc123", leaks: []string{"stdout", "raw", "command", "output", "token", "abc123"}},
		{name: "stderr label", input: "stderr = nginx failed with password hunter2", leaks: []string{"stderr", "nginx", "failed", "password", "hunter2"}},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			redacted := RedactText(tt.input)
			for _, leak := range tt.leaks {
				if strings.Contains(redacted, leak) {
					t.Fatalf("RedactText(%q) = %q, leaked %q", tt.input, redacted, leak)
				}
			}
		})
	}
}

func fixedEventTime() time.Time {
	return time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
}

func testActor() domain.Actor {
	return domain.Actor{
		Source:                  domain.ActorSourceUI,
		EffectiveUID:            0,
		EffectiveUser:           "uid:0",
		ProcessID:               1234,
		SessionIDFingerprint:    "sha256:0011223344556677",
		RequestSource:           "loopback",
		StartupTokenFingerprint: "sha256:8899aabbccddeeff",
	}
}

func testCheckpointRef() domain.ActivationRef {
	return domain.ActivationRef{Kind: domain.ActivationRefCheckpoint, Path: "/var/lib/lanpanel/checkpoint.json"}
}
