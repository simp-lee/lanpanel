package apphost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanpanel/internal/appconfig"
	"lanpanel/internal/apppreflight"
	"lanpanel/internal/domain"
	"lanpanel/internal/host"
	"lanpanel/internal/preflight"
	"lanpanel/internal/state"
)

func TestAppHostDependenciesAreSerialized(t *testing.T) {
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
		t.Fatal("nested apphost dependency scope completed before outer restore")
	case <-time.After(20 * time.Millisecond):
	}
	restore()
	restore = nil
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("nested apphost dependency scope did not complete after outer restore")
	}
}

func TestApprovedAppHostMutationExposurePlanRejectsStaleConfig(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/lanpanel-app.yaml"
	cfg := appconfig.ExampleConfig()
	permissions := preflight.PermissionState{IsRoot: true}
	approved, err := currentAppHostMutationExposurePlan(cfg, path, "test", domain.ExposurePlanOperationDeploy, domain.ExposurePlan{})
	if err != nil {
		t.Fatalf("currentAppHostMutationExposurePlan() error = %v", err)
	}

	stale := cfg
	stale.App.Domains = []string{"changed.example.com"}
	_, err = approvedAppHostMutationExposurePlan(&approved, stale, path, "test", permissions, domain.ExposurePlanOperationDeploy, nil)
	if err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("approvedAppHostMutationExposurePlan() error = %v, want stale digest rejection", err)
	}
}

func TestApprovedAppHostMutationExposurePlanRequiresConfirmations(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/lanpanel-app.yaml"
	cfg := appconfig.ExampleConfig()
	cfg.Access.PublicRiskConfirmed = false
	permissions := preflight.PermissionState{IsRoot: true}
	approved, err := currentAppHostMutationExposurePlan(cfg, path, "test", domain.ExposurePlanOperationDeploy, domain.ExposurePlan{})
	if err != nil {
		t.Fatalf("currentAppHostMutationExposurePlan() error = %v", err)
	}

	_, err = approvedAppHostMutationExposurePlan(&approved, cfg, path, "test", permissions, domain.ExposurePlanOperationDeploy, nil)
	if err == nil || !strings.Contains(err.Error(), "missing confirmations: public-app-risk") {
		t.Fatalf("approvedAppHostMutationExposurePlan() error = %v, want missing confirmation rejection", err)
	}
	if _, err := approvedAppHostMutationExposurePlan(&approved, cfg, path, "test", permissions, domain.ExposurePlanOperationDeploy, []string{"public-app-risk"}); err == nil || !strings.Contains(err.Error(), "manual confirmation record missing reason") {
		t.Fatalf("approvedAppHostMutationExposurePlan() error = %v, want missing manual confirmation record rejection", err)
	}
}

func TestApprovedAppHostMutationExposurePlanAllowsRecordedManualConfirmations(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/lanpanel-app.yaml"
	cfg := appconfig.ExampleConfig()
	cfg.Access.PublicRiskConfirmed = false
	permissions := preflight.PermissionState{IsRoot: true}
	approved, err := currentAppHostMutationExposurePlan(cfg, path, "test", domain.ExposurePlanOperationDeploy, domain.ExposurePlan{})
	if err != nil {
		t.Fatalf("currentAppHostMutationExposurePlan() error = %v", err)
	}
	approved.Access.ManualConfirmations = []domain.ManualConfirmation{{
		ConfirmationID: "evt_20260630T120000Z_00112233",
		Reason:         "public_exposure_confirmed",
		Actor:          domain.Actor{Source: domain.ActorSourceCLI, EffectiveUID: 0, EffectiveUser: "uid:0"},
		ConfirmedAt:    time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}}

	result, err := approvedAppHostMutationExposurePlan(&approved, cfg, path, "test", permissions, domain.ExposurePlanOperationDeploy, []string{"public-app-risk"})
	if err != nil {
		t.Fatalf("approvedAppHostMutationExposurePlan() with recorded confirmation error = %v", err)
	}
	if len(result.Access.ManualConfirmations) != 1 || result.Access.ManualConfirmations[0].ConfirmationID != "evt_20260630T120000Z_00112233" {
		t.Fatalf("ManualConfirmations = %#v, want preserved recorded confirmation", result.Access.ManualConfirmations)
	}
}

func TestAppPreflightDiagnosticsPreserveTypedStatuses(t *testing.T) {
	t.Parallel()

	diagnostics := appPreflightDiagnostics(apppreflight.Report{Checks: []apppreflight.Check{
		{ID: "dns01-credentials", Status: apppreflight.StatusUnknown, Summary: "DNS credentials unchecked", Remediations: []string{"prepare dns credentials"}},
		{ID: "realip-firewall", Status: apppreflight.StatusManual, Summary: "manual firewall confirmation recorded"},
		{ID: "browser-auth-file", Status: apppreflight.StatusNotApplicable, Summary: "browser auth skipped"},
	}})
	byID := map[string]domain.DiagnosticItem{}
	for _, diagnostic := range diagnostics {
		byID[diagnostic.ID] = diagnostic
	}
	if got := byID["app-preflight:dns01-credentials"]; got.Status != domain.DiagnosticStatusUnknown || !got.BlocksActivation || got.EvidenceSource != domain.DiagnosticEvidenceConfig || len(got.Remediation) != 1 {
		t.Fatalf("dns01 diagnostic = %#v, want blocking unknown config diagnostic", got)
	}
	if got := byID["app-preflight:realip-firewall"]; got.Status != domain.DiagnosticStatusManual || got.BlocksActivation || got.EvidenceSource != domain.DiagnosticEvidenceManual {
		t.Fatalf("realip diagnostic = %#v, want nonblocking manual diagnostic", got)
	}
	if got := byID["app-preflight:browser-auth-file"]; got.Status != domain.DiagnosticStatusNotApplicable || got.BlocksActivation {
		t.Fatalf("browser auth diagnostic = %#v, want nonblocking not_applicable diagnostic", got)
	}
}

func TestBeginAppHostCheckpointRestoresPendingSnapshots(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "lanpanel-app.yaml")
	filePath := filepath.Join(dir, "active.conf")
	newFilePath := filepath.Join(dir, "created.conf")
	linkPath := filepath.Join(dir, "enabled.conf")
	oldTarget := filepath.Join(dir, "old-target.conf")
	newTarget := filepath.Join(dir, "new-target.conf")
	createdDir := filepath.Join(dir, "created-dir")

	if err := os.WriteFile(filePath, []byte("mutated"), 0o644); err != nil {
		t.Fatalf("WriteFile(mutated) error = %v", err)
	}
	if err := os.WriteFile(newFilePath, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteFile(new) error = %v", err)
	}
	if err := os.WriteFile(oldTarget, []byte("old target"), 0o644); err != nil {
		t.Fatalf("WriteFile(old target) error = %v", err)
	}
	if err := os.WriteFile(newTarget, []byte("new target"), 0o644); err != nil {
		t.Fatalf("WriteFile(new target) error = %v", err)
	}
	if err := os.Symlink(newTarget, linkPath); err != nil {
		t.Fatalf("Symlink(new target) error = %v", err)
	}
	if err := os.Mkdir(createdDir, 0o755); err != nil {
		t.Fatalf("Mkdir(created dir) error = %v", err)
	}

	store := state.NewStore(state.DefaultCheckpointPath(configPath))
	checkpoint := state.Checkpoint{DesiredStateDigest: "sha256:old"}
	checkpoint.SetRuntimeFileSnapshots([]state.FileSnapshot{
		{HostPath: filePath, Exists: true, Content: []byte("old"), Mode: 0o640},
		{HostPath: newFilePath, Exists: false},
	})
	checkpoint.SetSymlinkSnapshots([]state.SymlinkSnapshot{{Path: linkPath, Exists: true, Target: oldTarget}})
	checkpoint.SetDirectorySnapshots([]state.DirectorySnapshot{{Path: createdDir, Exists: false}})
	checkpoint.SetSystemdUnitSnapshots([]state.SystemdUnitSnapshot{{
		Unit:         "nginx.service",
		EnabledState: "disabled",
		ActiveState:  "inactive",
	}})
	if err := store.Save(checkpoint); err != nil {
		t.Fatalf("Save(checkpoint) error = %v", err)
	}

	runner := &appCheckpointRestoreRunner{}
	_, restored, err := beginAppHostCheckpoint(context.Background(), configPath, "sha256:new", appCheckpointDeployStarted, host.NewExecutor(runner, nil), host.OSFileSystem{})
	if err != nil {
		t.Fatalf("beginAppHostCheckpoint() error = %v", err)
	}
	if got, err := os.ReadFile(filePath); err != nil || string(got) != "old" {
		t.Fatalf("restored file = %q, %v; want old", got, err)
	}
	if _, err := os.Stat(newFilePath); !os.IsNotExist(err) {
		t.Fatalf("new file stat error = %v, want not exist", err)
	}
	if target, err := os.Readlink(linkPath); err != nil || target != oldTarget {
		t.Fatalf("restored symlink target = %q, %v; want %q", target, err, oldTarget)
	}
	if _, err := os.Stat(createdDir); !os.IsNotExist(err) {
		t.Fatalf("created dir stat error = %v, want not exist", err)
	}
	if restored.HasMutationSnapshots() {
		t.Fatalf("restored checkpoint still has mutation snapshots: %#v", restored)
	}
	if restored.CurrentCheckpoint != appCheckpointDeployStarted {
		t.Fatalf("CurrentCheckpoint = %q, want %q", restored.CurrentCheckpoint, appCheckpointDeployStarted)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load(checkpoint) error = %v", err)
	}
	if loaded.HasMutationSnapshots() {
		t.Fatalf("loaded checkpoint still has mutation snapshots: %#v", loaded)
	}
	if !runner.Saw("systemctl stop nginx.service") ||
		!runner.Saw("systemctl disable nginx.service") ||
		!runner.Saw("systemctl daemon-reload") ||
		!runner.Saw("/usr/sbin/nginx -t") ||
		!runner.Saw("systemctl reload nginx.service") {
		t.Fatalf("restore commands = %#v, want nginx systemd and runtime reload rollback commands", runner.commands)
	}
}

type appCheckpointRestoreRunner struct {
	commands []string
}

func (runner *appCheckpointRestoreRunner) Run(_ context.Context, command host.Command) (host.Result, error) {
	runner.commands = append(runner.commands, strings.TrimSpace(command.Name+" "+strings.Join(command.Args, " ")))
	switch command.Name {
	case "rm":
		if len(command.Args) == 3 && command.Args[0] == "-f" && command.Args[1] == "--" {
			return host.Result{}, os.Remove(command.Args[2])
		}
	case "rmdir":
		if len(command.Args) == 2 && command.Args[0] == "--" {
			return host.Result{}, os.Remove(command.Args[1])
		}
	case "ln":
		if len(command.Args) == 4 && command.Args[0] == "-sfn" && command.Args[1] == "--" {
			_ = os.Remove(command.Args[3])
			return host.Result{}, os.Symlink(command.Args[2], command.Args[3])
		}
	case "systemctl":
		if strings.Join(command.Args, " ") == "daemon-reload" || strings.Join(command.Args, " ") == "reload nginx.service" {
			return host.Result{}, nil
		}
	case "/usr/sbin/nginx":
		if strings.Join(command.Args, " ") == "-t" {
			return host.Result{}, nil
		}
	}
	return host.Result{}, nil
}

func (runner *appCheckpointRestoreRunner) Saw(command string) bool {
	for _, got := range runner.commands {
		if got == command {
			return true
		}
	}
	return false
}
