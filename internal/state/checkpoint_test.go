package state

import (
	"lanpanel/internal/assets"
	"lanpanel/internal/workflow"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointMutationDeduplicatesState(t *testing.T) {
	t.Parallel()

	var checkpoint Checkpoint
	if !checkpoint.MarkCompleted("packages-installed") {
		t.Fatal("MarkCompleted() = false, want true")
	}
	if checkpoint.MarkCompleted("packages-installed") {
		t.Fatal("second MarkCompleted() = true, want false")
	}
	if !checkpoint.RecordModifiedPaths("/etc/headscale/config.yaml", "/etc/headscale/config.yaml", "/etc/nginx/sites-available/headscale.conf") {
		t.Fatal("RecordModifiedPaths() = false, want true")
	}
	if !checkpoint.RecordActivations(assets.ActivationRestartHeadscale, assets.ActivationRestartHeadscale, assets.ActivationReloadNginx) {
		t.Fatal("RecordActivations() = false, want true")
	}

	if checkpoint.CurrentCheckpoint != "packages-installed" {
		t.Fatalf("CurrentCheckpoint = %q, want %q", checkpoint.CurrentCheckpoint, "packages-installed")
	}
	if len(checkpoint.CompletedCheckpoints) != 1 {
		t.Fatalf("len(CompletedCheckpoints) = %d, want 1", len(checkpoint.CompletedCheckpoints))
	}
	if len(checkpoint.ModifiedPaths) != 2 {
		t.Fatalf("len(ModifiedPaths) = %d, want 2", len(checkpoint.ModifiedPaths))
	}
	if len(checkpoint.ActivationHistory) != 2 {
		t.Fatalf("len(ActivationHistory) = %d, want 2", len(checkpoint.ActivationHistory))
	}
	if checkpoint.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt is zero, want mutation timestamp")
	}
	if !checkpoint.HasCompleted("packages-installed") {
		t.Fatal("HasCompleted() = false, want true")
	}
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state", "checkpoint.json")
	store := NewStore(path)

	checkpoint := Checkpoint{DesiredStateDigest: "desired-state-a"}
	checkpoint.MarkCompleted("staged-files-written")
	checkpoint.RecordModifiedPaths("/etc/headscale/config.yaml")
	checkpoint.RecordActivations(assets.ActivationRestartHeadscale)
	checkpoint.RecordFailure(workflow.Failure{
		Step:         "install runtime assets",
		Operation:    "writing /etc/headscale/config.yaml",
		Impact:       "deploy cannot continue until runtime config is installed",
		Remediation:  []string{"Check filesystem permissions and rerun deploy."},
		RetryCommand: "lanpanel deploy --config lanpanel.yaml",
	}.Snapshot())

	if err := store.Save(checkpoint); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.CurrentCheckpoint != "staged-files-written" {
		t.Fatalf("CurrentCheckpoint = %q, want %q", loaded.CurrentCheckpoint, "staged-files-written")
	}
	if loaded.SchemaVersion != CheckpointSchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", loaded.SchemaVersion, CheckpointSchemaVersion)
	}
	if loaded.DesiredStateDigest != "desired-state-a" {
		t.Fatalf("DesiredStateDigest = %q, want %q", loaded.DesiredStateDigest, "desired-state-a")
	}
	if len(loaded.CompletedCheckpoints) != 1 || loaded.CompletedCheckpoints[0] != "staged-files-written" {
		t.Fatalf("CompletedCheckpoints = %v, want [staged-files-written]", loaded.CompletedCheckpoints)
	}
	if len(loaded.ModifiedPaths) != 1 || loaded.ModifiedPaths[0] != "/etc/headscale/config.yaml" {
		t.Fatalf("ModifiedPaths = %v, want [/etc/headscale/config.yaml]", loaded.ModifiedPaths)
	}
	if len(loaded.ActivationHistory) != 1 || loaded.ActivationHistory[0] != assets.ActivationRestartHeadscale {
		t.Fatalf("ActivationHistory = %v, want [%q]", loaded.ActivationHistory, assets.ActivationRestartHeadscale)
	}
	if loaded.LastFailure == nil {
		t.Fatal("LastFailure = nil, want persisted failure snapshot")
	}
	if loaded.LastFailure.Summary != "install runtime assets failed: writing /etc/headscale/config.yaml" {
		t.Fatalf("LastFailure.Summary = %q, want persisted failure summary", loaded.LastFailure.Summary)
	}
	if len(loaded.LastFailure.Remediation) != 1 || loaded.LastFailure.Remediation[0] != "Check filesystem permissions and rerun deploy." {
		t.Fatalf("LastFailure.Remediation = %v, want persisted remediation", loaded.LastFailure.Remediation)
	}
	if loaded.LastFailure.RetryCommand != "lanpanel deploy --config lanpanel.yaml" {
		t.Fatalf("LastFailure.RetryCommand = %q, want persisted retry command", loaded.LastFailure.RetryCommand)
	}
	if loaded.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt is zero, want persisted timestamp")
	}
}

func TestStoreLoadRejectsMissingOrUnsupportedSchemaVersion(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		body string
	}{
		{name: "missing", body: `{"desired_state_digest":"desired-state-a"}`},
		{name: "unsupported", body: `{"schema_version":"lanpanel.checkpoint.v0","desired_state_digest":"desired-state-a"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := NewStore(path).Load(); err == nil {
				t.Fatal("Load() error = nil, want schema_version failure")
			}
		})
	}
}

func TestStoreLoadRejectsUnknownFieldsAndMultipleJSONValues(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{name: "unknown field", body: `{"schema_version":"lanpanel.checkpoint.v1","desired_state_digest":"desired-state-a","unexpected":true}`, want: "unknown field"},
		{name: "multiple values", body: `{"schema_version":"lanpanel.checkpoint.v1"} {"schema_version":"lanpanel.checkpoint.v1"}`, want: "multiple JSON values"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			_, err := NewStore(path).Load()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestStoreSaveRejectsUnsupportedSchemaVersion(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := NewStore(path).Save(Checkpoint{SchemaVersion: "lanpanel.checkpoint.v0"}); err == nil {
		t.Fatal("Save() error = nil, want schema_version failure")
	}
}

func TestStoreSaveDoesNotCollideWithStaleFixedTempFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state", "checkpoint.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path+".tmp", []byte("stale"), 0o600); err != nil {
		t.Fatalf("WriteFile(stale temp) error = %v", err)
	}

	store := NewStore(path)
	checkpoint := Checkpoint{DesiredStateDigest: "desired-state-a"}
	checkpoint.MarkCompleted("packages-installed")

	if err := store.Save(checkpoint); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !loaded.HasCompleted("packages-installed") {
		t.Fatalf("loaded checkpoint = %#v, want completed packages-installed", loaded)
	}
}

func TestStoreCreatesPrivateCheckpointDirectory(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state", "checkpoint.json")
	if err := NewStore(path).Save(Checkpoint{DesiredStateDigest: "desired-state-a"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Lstat(checkpoint dir) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("checkpoint dir mode = %o, want 0700", got)
	}
}

func TestStoreRejectsUnsafeCheckpointPathComponents(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := NewStore(filepath.Join(link, "checkpoint.json")).Save(Checkpoint{}); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Save(symlink parent) error = %v, want symlink refusal", err)
	}
	if _, err := NewStore(filepath.Join(link, "checkpoint.json")).Load(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Load(symlink parent) error = %v, want symlink refusal", err)
	}

	writable := filepath.Join(base, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatalf("Mkdir(writable) error = %v", err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatalf("Chmod(writable) error = %v", err)
	}
	if err := NewStore(filepath.Join(writable, "checkpoint.json")).Save(Checkpoint{}); err == nil || !strings.Contains(err.Error(), "must not be writable by untrusted local users") {
		t.Fatalf("Save(writable dir) error = %v, want writable directory refusal", err)
	}
	if _, err := NewStore(filepath.Join(writable, "checkpoint.json")).Load(); err == nil || !strings.Contains(err.Error(), "must not be writable by untrusted local users") {
		t.Fatalf("Load(writable dir) error = %v, want writable directory refusal", err)
	}
}

func TestStoreRejectsUnsafeCheckpointFile(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir(state) error = %v", err)
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"schema_version":"lanpanel.checkpoint.v1"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	link := filepath.Join(dir, "checkpoint-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := NewStore(link).Load(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Load(symlink file) error = %v, want symlink file refusal", err)
	}
	if err := NewStore(link).Save(Checkpoint{}); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Save(symlink file) error = %v, want symlink file refusal", err)
	}

	writable := filepath.Join(dir, "checkpoint-writable.json")
	if err := os.WriteFile(writable, []byte(`{"schema_version":"lanpanel.checkpoint.v1"}`), 0o622); err != nil {
		t.Fatalf("WriteFile(writable) error = %v", err)
	}
	if err := os.Chmod(writable, 0o622); err != nil {
		t.Fatalf("Chmod(writable) error = %v", err)
	}
	if _, err := NewStore(writable).Load(); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("Load(writable file) error = %v, want writable file refusal", err)
	}
	if err := NewStore(writable).Save(Checkpoint{}); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("Save(writable file) error = %v, want writable file refusal", err)
	}
}

func TestCheckpointBeginDeployResetsRetiredHistoryAndNewDesiredState(t *testing.T) {
	t.Parallel()

	checkpoint := Checkpoint{DesiredStateDigest: "desired-state-a"}
	checkpoint.MarkCompleted("runtime-assets-installed")
	checkpoint.RecordModifiedPaths("/etc/headscale/config.yaml")
	checkpoint.RecordActivations(assets.ActivationRestartHeadscale)
	checkpoint.RecordFailure(workflow.Failure{Step: "install runtime assets", Operation: "writing /etc/headscale/config.yaml"}.Snapshot())

	if !checkpoint.FinalizeSuccessfulDeploy() {
		t.Fatal("FinalizeSuccessfulDeploy() = false, want true")
	}
	if checkpoint.CurrentCheckpoint != "" {
		t.Fatalf("CurrentCheckpoint = %q, want empty", checkpoint.CurrentCheckpoint)
	}
	if checkpoint.LastFailure != nil {
		t.Fatalf("LastFailure = %#v, want nil", checkpoint.LastFailure)
	}
	if len(checkpoint.CompletedCheckpoints) != 1 {
		t.Fatalf("len(CompletedCheckpoints) = %d, want 1 retained history entry", len(checkpoint.CompletedCheckpoints))
	}

	if !checkpoint.BeginDeploy("desired-state-a") {
		t.Fatal("BeginDeploy(same digest) = false, want true")
	}
	if len(checkpoint.CompletedCheckpoints) != 0 {
		t.Fatalf("CompletedCheckpoints = %v, want cleared retired history", checkpoint.CompletedCheckpoints)
	}
	if len(checkpoint.ModifiedPaths) != 0 {
		t.Fatalf("ModifiedPaths = %v, want cleared retired modifications", checkpoint.ModifiedPaths)
	}
	if len(checkpoint.ActivationHistory) != 0 {
		t.Fatalf("ActivationHistory = %v, want cleared retired activations", checkpoint.ActivationHistory)
	}

	checkpoint.MarkCompleted("runtime-assets-installed")
	checkpoint.RecordModifiedPaths("/etc/headscale/config.yaml")
	checkpoint.RecordActivations(assets.ActivationRestartHeadscale)
	checkpoint.RecordFailure(workflow.Failure{Step: "install runtime assets", Operation: "writing /etc/headscale/config.yaml"}.Snapshot())

	if !checkpoint.BeginDeploy("desired-state-b") {
		t.Fatal("BeginDeploy(new digest) = false, want true")
	}
	if checkpoint.DesiredStateDigest != "desired-state-b" {
		t.Fatalf("DesiredStateDigest = %q, want %q", checkpoint.DesiredStateDigest, "desired-state-b")
	}
	if checkpoint.CurrentCheckpoint != "" {
		t.Fatalf("CurrentCheckpoint = %q, want empty after desired state change", checkpoint.CurrentCheckpoint)
	}
	if len(checkpoint.CompletedCheckpoints) != 0 {
		t.Fatalf("CompletedCheckpoints = %v, want cleared on desired state change", checkpoint.CompletedCheckpoints)
	}
	if len(checkpoint.ModifiedPaths) != 0 {
		t.Fatalf("ModifiedPaths = %v, want cleared on desired state change", checkpoint.ModifiedPaths)
	}
	if len(checkpoint.ActivationHistory) != 0 {
		t.Fatalf("ActivationHistory = %v, want cleared on desired state change", checkpoint.ActivationHistory)
	}
	if checkpoint.LastFailure != nil {
		t.Fatalf("LastFailure = %#v, want nil on desired state change", checkpoint.LastFailure)
	}
}
