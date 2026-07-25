// Package state persists resumable deploy checkpoints and host mutations.
package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/assets"
	"lanpanel/internal/workflow"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

type LoadErrorKind string

const (
	LoadErrorRead   LoadErrorKind = "read"
	LoadErrorDecode LoadErrorKind = "decode"
)

const CheckpointSchemaVersion = "lanpanel.checkpoint.v1"

func DefaultCheckpointPath(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = "lanpanel.yaml"
	}
	base := filepath.Base(configPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if name == "" {
		name = "lanpanel"
	}
	return filepath.Join(filepath.Dir(configPath), ".lanpanel", name+".checkpoint.json")
}

type LoadError struct {
	Path string
	Kind LoadErrorKind
	Err  error
}

func (err *LoadError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%s checkpoint: %v", err.Kind, err.Err)
}

func (err *LoadError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

type Checkpoint struct {
	SchemaVersion        string                    `json:"schema_version"`
	DesiredStateDigest   string                    `json:"desired_state_digest,omitempty"`
	CurrentCheckpoint    string                    `json:"current_checkpoint,omitempty"`
	CompletedCheckpoints []string                  `json:"completed_checkpoints,omitempty"`
	ModifiedPaths        []string                  `json:"modified_paths,omitempty"`
	ActivationHistory    []assets.Activation       `json:"activation_history,omitempty"`
	RuntimeFileSnapshots []FileSnapshot            `json:"runtime_file_snapshots,omitempty"`
	DirectorySnapshots   []DirectorySnapshot       `json:"directory_snapshots,omitempty"`
	SymlinkSnapshots     []SymlinkSnapshot         `json:"symlink_snapshots,omitempty"`
	SystemdUnitSnapshots []SystemdUnitSnapshot     `json:"systemd_unit_snapshots,omitempty"`
	LastFailure          *workflow.FailureSnapshot `json:"last_failure,omitempty"`
	UpdatedAt            time.Time                 `json:"updated_at,omitempty"`
}

type FileSnapshot struct {
	HostPath string `json:"host_path"`
	Exists   bool   `json:"exists"`
	Content  []byte `json:"content,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
}

type DirectorySnapshot struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
}

type SymlinkSnapshot struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Target string `json:"target,omitempty"`
}

type SystemdUnitSnapshot struct {
	Unit         string `json:"unit"`
	EnabledState string `json:"enabled_state"`
	ActiveState  string `json:"active_state"`
}

func (checkpoint Checkpoint) HasDeployContext() bool {
	return strings.TrimSpace(checkpoint.CurrentCheckpoint) != "" ||
		len(checkpoint.CompletedCheckpoints) > 0 ||
		len(checkpoint.ModifiedPaths) > 0 ||
		len(checkpoint.ActivationHistory) > 0 ||
		checkpoint.HasMutationSnapshots() ||
		checkpoint.LastFailure != nil
}

func (checkpoint Checkpoint) MatchesDesiredState(desiredStateDigest string) bool {
	return strings.TrimSpace(checkpoint.DesiredStateDigest) == strings.TrimSpace(desiredStateDigest)
}

func (checkpoint *Checkpoint) BeginDeploy(desiredStateDigest string) bool {
	trimmedDigest := strings.TrimSpace(desiredStateDigest)
	changed := false

	if checkpoint.DesiredStateDigest != trimmedDigest {
		checkpoint.DesiredStateDigest = trimmedDigest
		changed = checkpoint.resetDeployState() || changed
	} else if checkpoint.CurrentCheckpoint == "" && checkpoint.LastFailure == nil {
		if len(checkpoint.CompletedCheckpoints) > 0 {
			checkpoint.CompletedCheckpoints = nil
			changed = true
		}
		if len(checkpoint.ModifiedPaths) > 0 {
			checkpoint.ModifiedPaths = nil
			changed = true
		}
		if len(checkpoint.ActivationHistory) > 0 {
			checkpoint.ActivationHistory = nil
			changed = true
		}
	}

	if changed {
		checkpoint.touch()
	}
	return changed
}

func (checkpoint *Checkpoint) FinalizeSuccessfulDeploy() bool {
	changed := false
	if checkpoint.CurrentCheckpoint != "" {
		checkpoint.CurrentCheckpoint = ""
		changed = true
	}
	if checkpoint.LastFailure != nil {
		checkpoint.LastFailure = nil
		changed = true
	}
	if len(checkpoint.RuntimeFileSnapshots) > 0 {
		checkpoint.RuntimeFileSnapshots = nil
		changed = true
	}
	if len(checkpoint.DirectorySnapshots) > 0 {
		checkpoint.DirectorySnapshots = nil
		changed = true
	}
	if len(checkpoint.SymlinkSnapshots) > 0 {
		checkpoint.SymlinkSnapshots = nil
		changed = true
	}
	if len(checkpoint.SystemdUnitSnapshots) > 0 {
		checkpoint.SystemdUnitSnapshots = nil
		changed = true
	}
	if changed {
		checkpoint.touch()
	}
	return changed
}

func (checkpoint *Checkpoint) MarkCompleted(name string) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return false
	}
	checkpoint.CurrentCheckpoint = trimmed
	if slices.Contains(checkpoint.CompletedCheckpoints, trimmed) {
		checkpoint.touch()
		return false
	}
	checkpoint.CompletedCheckpoints = append(checkpoint.CompletedCheckpoints, trimmed)
	checkpoint.touch()
	return true
}

func (checkpoint *Checkpoint) RecordModifiedPaths(paths ...string) bool {
	changed := false
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		if containsString(checkpoint.ModifiedPaths, trimmed) {
			continue
		}
		checkpoint.ModifiedPaths = append(checkpoint.ModifiedPaths, trimmed)
		changed = true
	}
	if changed {
		checkpoint.touch()
	}
	return changed
}

func (checkpoint *Checkpoint) RecordActivations(activations ...assets.Activation) bool {
	changed := false
	for _, activation := range activations {
		if activation == "" {
			continue
		}
		if containsActivation(checkpoint.ActivationHistory, activation) {
			continue
		}
		checkpoint.ActivationHistory = append(checkpoint.ActivationHistory, activation)
		changed = true
	}
	if changed {
		checkpoint.touch()
	}
	return changed
}

func (checkpoint Checkpoint) HasCompleted(name string) bool {
	trimmed := strings.TrimSpace(name)
	return containsString(checkpoint.CompletedCheckpoints, trimmed)
}

func (checkpoint *Checkpoint) RecordFailure(failure workflow.FailureSnapshot) bool {
	if !failure.HasContent() {
		if checkpoint.LastFailure == nil {
			return false
		}
		checkpoint.LastFailure = nil
		checkpoint.touch()
		return true
	}

	snapshot := failure
	snapshot.Remediation = append([]string(nil), failure.Remediation...)
	checkpoint.LastFailure = &snapshot
	checkpoint.touch()
	return true
}

func (checkpoint *Checkpoint) SetRuntimeFileSnapshots(snapshots []FileSnapshot) bool {
	checkpoint.RuntimeFileSnapshots = cloneFileSnapshots(snapshots)
	checkpoint.touch()
	return true
}

func (checkpoint *Checkpoint) SetDirectorySnapshots(snapshots []DirectorySnapshot) bool {
	checkpoint.DirectorySnapshots = cloneDirectorySnapshots(snapshots)
	checkpoint.touch()
	return true
}

func (checkpoint *Checkpoint) SetSymlinkSnapshots(snapshots []SymlinkSnapshot) bool {
	checkpoint.SymlinkSnapshots = cloneSymlinkSnapshots(snapshots)
	checkpoint.touch()
	return true
}

func (checkpoint *Checkpoint) SetSystemdUnitSnapshots(snapshots []SystemdUnitSnapshot) bool {
	checkpoint.SystemdUnitSnapshots = cloneSystemdUnitSnapshots(snapshots)
	checkpoint.touch()
	return true
}

func (checkpoint *Checkpoint) ClearRuntimeFileSnapshots() bool {
	if len(checkpoint.RuntimeFileSnapshots) == 0 {
		return false
	}
	checkpoint.RuntimeFileSnapshots = nil
	checkpoint.touch()
	return true
}

func (checkpoint Checkpoint) HasMutationSnapshots() bool {
	return len(checkpoint.RuntimeFileSnapshots) > 0 ||
		len(checkpoint.DirectorySnapshots) > 0 ||
		len(checkpoint.SymlinkSnapshots) > 0 ||
		len(checkpoint.SystemdUnitSnapshots) > 0
}

func (checkpoint *Checkpoint) ClearMutationSnapshots() bool {
	changed := false
	if len(checkpoint.RuntimeFileSnapshots) > 0 {
		checkpoint.RuntimeFileSnapshots = nil
		changed = true
	}
	if len(checkpoint.DirectorySnapshots) > 0 {
		checkpoint.DirectorySnapshots = nil
		changed = true
	}
	if len(checkpoint.SymlinkSnapshots) > 0 {
		checkpoint.SymlinkSnapshots = nil
		changed = true
	}
	if len(checkpoint.SystemdUnitSnapshots) > 0 {
		checkpoint.SystemdUnitSnapshots = nil
		changed = true
	}
	if changed {
		checkpoint.touch()
	}
	return changed
}

type Store struct {
	path string
}

func NewStore(path string) Store {
	return Store{path: path}
}

func (store Store) Load() (Checkpoint, error) {
	path, err := store.securePath()
	if err != nil {
		return Checkpoint{}, err
	}
	if err := ensureSafeCheckpointParents(filepath.Dir(path)); err != nil {
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorRead, Err: err}
	}
	if err := checkExistingCheckpointFile(path); err != nil {
		if os.IsNotExist(err) {
			return Checkpoint{}, nil
		}
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorRead, Err: err}
	}

	file, err := openCheckpointFileNoFollow(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Checkpoint{}, nil
		}
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorRead, Err: err}
	}
	data, err := io.ReadAll(file)
	if err != nil {
		_ = file.Close()
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorRead, Err: err}
	}
	if err := file.Close(); err != nil {
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorRead, Err: err}
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var checkpoint Checkpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorDecode, Err: err}
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorDecode, Err: fmt.Errorf("multiple JSON values are not supported")}
	}
	if checkpoint.SchemaVersion != CheckpointSchemaVersion {
		return Checkpoint{}, &LoadError{Path: path, Kind: LoadErrorDecode, Err: fmt.Errorf("checkpoint schema_version must be %q", CheckpointSchemaVersion)}
	}
	return checkpoint, nil
}

func (store Store) Save(checkpoint Checkpoint) error {
	path, err := store.securePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ensureSafeCheckpointParents(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create checkpoint directory: %w", err)
	}
	if err := ensureSafeCheckpointDirectory(dir); err != nil {
		return err
	}
	if err := checkExistingCheckpointFile(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if checkpoint.SchemaVersion == "" {
		checkpoint.SchemaVersion = CheckpointSchemaVersion
	}
	if checkpoint.SchemaVersion != CheckpointSchemaVersion {
		return fmt.Errorf("checkpoint schema_version must be %q", CheckpointSchemaVersion)
	}
	if checkpoint.UpdatedAt.IsZero() {
		checkpoint.UpdatedAt = time.Now().UTC()
	}

	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	data = append(data, '\n')

	file, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	temporaryPath := file.Name()
	defer func() {
		_ = os.Remove(temporaryPath)
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync checkpoint: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace checkpoint: %w", err)
	}
	if err := syncCheckpointDirectory(dir); err != nil {
		return err
	}
	return nil
}

func (store Store) securePath() (string, error) {
	trimmed := strings.TrimSpace(store.path)
	if trimmed == "" {
		return "", fmt.Errorf("checkpoint path is required")
	}
	if trimmed != store.path {
		return "", fmt.Errorf("checkpoint path must not include leading or trailing whitespace")
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve checkpoint path: %w", err)
	}
	clean := filepath.Clean(absolute)
	if clean == "." || !filepath.IsAbs(clean) {
		return "", fmt.Errorf("checkpoint path must resolve to a clean absolute path")
	}
	return clean, nil
}

func ensureSafeCheckpointParents(dir string) error {
	clean := filepath.Clean(dir)
	if clean == "." || !filepath.IsAbs(clean) {
		return fmt.Errorf("checkpoint directory must resolve to a clean absolute path")
	}
	current := string(filepath.Separator)
	if err := checkCheckpointPathComponent(current, current == clean); err != nil {
		return err
	}
	if clean == current {
		return nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("checkpoint directory must resolve to a clean absolute path")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("inspect checkpoint path component %s: %w", current, err)
		}
		if err := validateCheckpointDirectoryComponent(current, info, current == clean); err != nil {
			return err
		}
	}
	return nil
}

func ensureSafeCheckpointDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect checkpoint directory %s: %w", dir, err)
	}
	return validateCheckpointDirectoryComponent(dir, info, true)
}

func checkCheckpointPathComponent(path string, immediate bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect checkpoint path component %s: %w", path, err)
	}
	return validateCheckpointDirectoryComponent(path, info, immediate)
}

func validateCheckpointDirectoryComponent(path string, info os.FileInfo, immediate bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("checkpoint path component %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("checkpoint path component %s must be a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checkpoint path component %s owner could not be inspected", path)
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != euid && stat.Uid != 0 {
		return fmt.Errorf("checkpoint path component %s owner uid %d does not match effective uid %d or root", path, stat.Uid, euid)
	}
	if unsafeCheckpointDirectoryMode(info.Mode(), immediate, stat.Uid, euid) {
		return fmt.Errorf("checkpoint path component %s must not be writable by untrusted local users", path)
	}
	return nil
}

func unsafeCheckpointDirectoryMode(mode os.FileMode, immediate bool, uid uint32, euid uint32) bool {
	if mode.Perm()&0o002 != 0 && (immediate || mode&os.ModeSticky == 0) {
		return true
	}
	return mode.Perm()&0o020 != 0 && uid != euid && (immediate || mode&os.ModeSticky == 0)
}

func checkExistingCheckpointFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateCheckpointFileInfo(path, info)
}

func openCheckpointFileNoFollow(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint file %s: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect opened checkpoint file %s: %w", path, err)
	}
	if err := validateCheckpointFileInfo(path, info); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateCheckpointFileInfo(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("checkpoint file %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("checkpoint file %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("checkpoint file %s must not be writable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checkpoint file %s owner could not be inspected", path)
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != euid && stat.Uid != 0 {
		return fmt.Errorf("checkpoint file %s owner uid %d does not match effective uid %d or root", path, stat.Uid, euid)
	}
	return nil
}

func syncCheckpointDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open checkpoint directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("sync checkpoint directory: %w", err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close checkpoint directory: %w", err)
	}
	return nil
}

func (checkpoint *Checkpoint) touch() {
	checkpoint.UpdatedAt = time.Now().UTC()
}

func (checkpoint *Checkpoint) resetDeployState() bool {
	changed := false
	if checkpoint.CurrentCheckpoint != "" {
		checkpoint.CurrentCheckpoint = ""
		changed = true
	}
	if len(checkpoint.CompletedCheckpoints) > 0 {
		checkpoint.CompletedCheckpoints = nil
		changed = true
	}
	if len(checkpoint.ModifiedPaths) > 0 {
		checkpoint.ModifiedPaths = nil
		changed = true
	}
	if len(checkpoint.ActivationHistory) > 0 {
		checkpoint.ActivationHistory = nil
		changed = true
	}
	if len(checkpoint.RuntimeFileSnapshots) > 0 {
		checkpoint.RuntimeFileSnapshots = nil
		changed = true
	}
	if len(checkpoint.DirectorySnapshots) > 0 {
		checkpoint.DirectorySnapshots = nil
		changed = true
	}
	if len(checkpoint.SymlinkSnapshots) > 0 {
		checkpoint.SymlinkSnapshots = nil
		changed = true
	}
	if len(checkpoint.SystemdUnitSnapshots) > 0 {
		checkpoint.SystemdUnitSnapshots = nil
		changed = true
	}
	if checkpoint.LastFailure != nil {
		checkpoint.LastFailure = nil
		changed = true
	}
	return changed
}

func cloneFileSnapshots(snapshots []FileSnapshot) []FileSnapshot {
	if len(snapshots) == 0 {
		return nil
	}
	cloned := make([]FileSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		cloned = append(cloned, FileSnapshot{
			HostPath: strings.TrimSpace(snapshot.HostPath),
			Exists:   snapshot.Exists,
			Content:  append([]byte(nil), snapshot.Content...),
			Mode:     snapshot.Mode,
		})
	}
	return cloned
}

func cloneDirectorySnapshots(snapshots []DirectorySnapshot) []DirectorySnapshot {
	if len(snapshots) == 0 {
		return nil
	}
	cloned := make([]DirectorySnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		cloned = append(cloned, DirectorySnapshot{
			Path:   strings.TrimSpace(snapshot.Path),
			Exists: snapshot.Exists,
		})
	}
	return cloned
}

func cloneSymlinkSnapshots(snapshots []SymlinkSnapshot) []SymlinkSnapshot {
	if len(snapshots) == 0 {
		return nil
	}
	cloned := make([]SymlinkSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		cloned = append(cloned, SymlinkSnapshot{
			Path:   strings.TrimSpace(snapshot.Path),
			Exists: snapshot.Exists,
			Target: strings.TrimSpace(snapshot.Target),
		})
	}
	return cloned
}

func cloneSystemdUnitSnapshots(snapshots []SystemdUnitSnapshot) []SystemdUnitSnapshot {
	if len(snapshots) == 0 {
		return nil
	}
	cloned := make([]SystemdUnitSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		cloned = append(cloned, SystemdUnitSnapshot{
			Unit:         strings.TrimSpace(snapshot.Unit),
			EnabledState: strings.TrimSpace(snapshot.EnabledState),
			ActiveState:  strings.TrimSpace(snapshot.ActiveState),
		})
	}
	return cloned
}

func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}

func containsActivation(values []assets.Activation, want assets.Activation) bool {
	return slices.Contains(values, want)
}
