package maindeploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanpanel/internal/host"
	"lanpanel/internal/state"
)

func TestDeployDependenciesAreSerialized(t *testing.T) {
	restore := applyDependencies(Dependencies{})
	defer func() {
		if restore != nil {
			restore()
		}
	}()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		restoreNested := applyDependencies(Dependencies{})
		restoreNested()
		close(done)
	}()

	<-started
	select {
	case <-done:
		t.Fatal("nested deploy dependency scope completed before outer restore")
	case <-time.After(20 * time.Millisecond):
	}
	restore()
	restore = nil
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("nested deploy dependency scope did not complete after outer restore")
	}
}

func TestRestorePendingDeployCheckpointSnapshotsRestoresAndClears(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel.yaml")
	existingPath := filepath.Join(dir, "headscale.conf")
	createdPath := filepath.Join(dir, "created.conf")

	if err := os.WriteFile(existingPath, []byte("mutated"), 0o644); err != nil {
		t.Fatalf("WriteFile(existing mutated) error = %v", err)
	}
	if err := os.WriteFile(createdPath, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteFile(created) error = %v", err)
	}

	store := state.NewStore(state.DefaultCheckpointPath(configPath))
	checkpoint := state.Checkpoint{DesiredStateDigest: "sha256:old"}
	checkpoint.SetRuntimeFileSnapshots([]state.FileSnapshot{
		{HostPath: existingPath, Exists: true, Content: []byte("old"), Mode: 0o640},
		{HostPath: createdPath, Exists: false},
	})
	checkpoint.SetSystemdUnitSnapshots([]state.SystemdUnitSnapshot{{
		Unit:         "nginx.service",
		EnabledState: "disabled",
		ActiveState:  "inactive",
	}})
	if err := store.Save(checkpoint); err != nil {
		t.Fatalf("Save(checkpoint) error = %v", err)
	}

	runner := &deployCheckpointRestoreRunner{}
	result, err, failed := restorePendingDeployCheckpointSnapshots(context.Background(), store, &checkpoint, host.NewExecutor(runner, nil), host.OSFileSystem{}, configPath)
	if failed || err != nil {
		t.Fatalf("restorePendingDeployCheckpointSnapshots() = %#v, %v, %v; want success", result, err, failed)
	}
	if got, err := os.ReadFile(existingPath); err != nil || string(got) != "old" {
		t.Fatalf("restored existing file = %q, %v; want old", got, err)
	}
	if _, err := os.Stat(createdPath); !os.IsNotExist(err) {
		t.Fatalf("created file stat error = %v, want not exist", err)
	}
	if checkpoint.HasMutationSnapshots() {
		t.Fatalf("checkpoint still has mutation snapshots: %#v", checkpoint)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load(checkpoint) error = %v", err)
	}
	if loaded.HasMutationSnapshots() {
		t.Fatalf("persisted checkpoint still has mutation snapshots: %#v", loaded)
	}
	if !runner.Saw("systemctl daemon-reload") ||
		!runner.Saw("nginx -t") ||
		!runner.Saw("systemctl reload nginx.service") ||
		!runner.Saw("systemctl stop nginx.service") ||
		!runner.Saw("systemctl disable nginx.service") {
		t.Fatalf("restore commands = %#v, want runtime and systemd rollback commands", runner.commands)
	}
}

func TestStateDeploySystemdUnitSnapshotsRoundTrip(t *testing.T) {
	snapshots := []deploySystemdUnitSnapshot{
		{unit: "headscale.service", enabledState: "enabled", activeState: "active"},
		{unit: "nginx.service", enabledState: "disabled", activeState: "inactive"},
	}

	converted, err := deploySystemdUnitSnapshotsFromCheckpoint(stateDeploySystemdUnitSnapshots(snapshots))
	if err != nil {
		t.Fatalf("deploySystemdUnitSnapshotsFromCheckpoint() error = %v", err)
	}
	if len(converted) != len(snapshots) {
		t.Fatalf("converted snapshots len = %d, want %d", len(converted), len(snapshots))
	}
	for i := range snapshots {
		if converted[i] != snapshots[i] {
			t.Fatalf("converted[%d] = %#v, want %#v", i, converted[i], snapshots[i])
		}
	}
}

type deployCheckpointRestoreRunner struct {
	commands []string
}

func (runner *deployCheckpointRestoreRunner) Run(_ context.Context, command host.Command) (host.Result, error) {
	runner.commands = append(runner.commands, strings.TrimSpace(command.Name+" "+strings.Join(command.Args, " ")))
	switch command.Name {
	case "rm":
		if len(command.Args) == 3 && command.Args[0] == "-f" && command.Args[1] == "--" {
			return host.Result{}, os.Remove(command.Args[2])
		}
	}
	return host.Result{}, nil
}

func (runner *deployCheckpointRestoreRunner) Saw(command string) bool {
	for _, got := range runner.commands {
		if got == command {
			return true
		}
	}
	return false
}
