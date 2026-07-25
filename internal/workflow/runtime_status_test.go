package workflow

import (
	"context"
	"errors"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/config"
	"lanpanel/internal/domain"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRuntimeStatusIncludesRuntimeServiceEvidence(t *testing.T) {
	previousCommand := runRuntimeCommand
	t.Cleanup(func() { runRuntimeCommand = previousCommand })
	runRuntimeCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("runtime command name = %q, want systemctl", name)
		}
		if len(args) != 2 {
			t.Fatalf("systemctl args = %#v, want action and unit", args)
		}
		switch args[0] {
		case "is-active":
			return []byte("active\n"), nil
		case "is-enabled":
			return []byte("enabled\n"), nil
		default:
			t.Fatalf("systemctl action = %q", args[0])
			return nil, nil
		}
	}

	dir := t.TempDir()
	mainPath := filepath.Join(dir, "lanpanel.yaml")
	appPath := filepath.Join(dir, "lanpanel-app.yaml")
	if err := config.ExampleConfig().WriteFile(mainPath); err != nil {
		t.Fatalf("WriteFile(main) error = %v", err)
	}
	if err := appconfig.ExampleConfig().WriteFile(appPath); err != nil {
		t.Fatalf("WriteFile(app) error = %v", err)
	}

	result, err := RunRuntimeStatus(Context{Version: "test"}, mainPath, appPath)
	if err != nil {
		t.Fatalf("RunRuntimeStatus() error = %v", err)
	}
	if !diagnosticsContain(result.Diagnostics, "runtime:headscale-service") || !diagnosticsContain(result.Diagnostics, "runtime:nginx-service") || !diagnosticsContain(result.Diagnostics, "runtime:app-service") {
		t.Fatalf("RunRuntimeStatus() diagnostics missing runtime service evidence: %#v", result.Diagnostics)
	}
	if got, ok := fieldValue(result.Fields, "runtime headscale.service active"); !ok || got != "active" {
		t.Fatalf("runtime headscale active field = %q, %v", got, ok)
	}
}

func TestRunRuntimeStatusFailsForDeterminateBadSystemdStates(t *testing.T) {
	previousCommand := runRuntimeCommand
	t.Cleanup(func() { runRuntimeCommand = previousCommand })
	runRuntimeCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("runtime command name = %q, want systemctl", name)
		}
		if len(args) != 2 {
			t.Fatalf("systemctl args = %#v, want action and unit", args)
		}
		switch args[0] {
		case "is-active":
			return []byte("inactive\n"), nil
		case "is-enabled":
			return []byte("disabled\n"), nil
		default:
			t.Fatalf("systemctl action = %q", args[0])
			return nil, nil
		}
	}

	mainPath := filepath.Join(t.TempDir(), "lanpanel.yaml")
	if err := config.ExampleConfig().WriteFile(mainPath); err != nil {
		t.Fatalf("WriteFile(main) error = %v", err)
	}
	result, err := RunRuntimeStatus(Context{Version: "test"}, mainPath, "")
	if err != nil {
		t.Fatalf("RunRuntimeStatus() error = %v", err)
	}
	if result.Status != domain.JobStatusFailed {
		t.Fatalf("Status = %q, want failed; diagnostics = %#v", result.Status, result.Diagnostics)
	}
	for _, item := range result.Diagnostics {
		if item.ID == "runtime:headscale-service" {
			if item.Status != domain.DiagnosticStatusFail {
				t.Fatalf("headscale runtime status = %q, want fail", item.Status)
			}
			if !strings.Contains(item.Summary, "active=inactive") || !strings.Contains(item.Summary, "enabled=disabled") {
				t.Fatalf("headscale runtime summary = %q, want inactive/disabled evidence", item.Summary)
			}
			return
		}
	}
	t.Fatalf("diagnostics missing runtime:headscale-service: %#v", result.Diagnostics)
}

func TestRuntimeUnitEvidenceKeepsEmptyProbeErrorsUnknown(t *testing.T) {
	previousCommand := runRuntimeCommand
	t.Cleanup(func() { runRuntimeCommand = previousCommand })
	runRuntimeCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("runtime command name = %q, want systemctl", name)
		}
		return nil, errors.New("systemctl probe unavailable")
	}

	fields, diagnostics := runtimeUnitEvidence(context.Background(), []runtimeUnit{{id: "sample-service", label: "Sample service", unit: "sample.service"}})
	if got, ok := fieldValue(fields, "runtime sample.service active"); !ok || got != "unknown" {
		t.Fatalf("runtime sample.service active field = %q, %v; fields = %#v", got, ok, fields)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one runtime diagnostic", diagnostics)
	}
	if diagnostics[0].Status != domain.DiagnosticStatusUnknown {
		t.Fatalf("diagnostic status = %q, want unknown; diagnostic = %#v", diagnostics[0].Status, diagnostics[0])
	}
	if !strings.Contains(diagnostics[0].Summary, "systemctl probe unavailable") {
		t.Fatalf("diagnostic summary = %q, want probe error detail", diagnostics[0].Summary)
	}
}

func TestRunOnboardingStatusUsesRuntimeReadinessEvidence(t *testing.T) {
	previousCommand := runRuntimeCommand
	t.Cleanup(func() { runRuntimeCommand = previousCommand })
	runRuntimeCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "systemctl":
			if len(args) != 2 {
				t.Fatalf("systemctl args = %#v, want action and unit", args)
			}
			if args[0] == "is-active" {
				return []byte("active\n"), nil
			}
			if args[0] == "is-enabled" {
				return []byte("enabled\n"), nil
			}
			t.Fatalf("systemctl action = %q", args[0])
		case "headscale":
			if strings.Join(args, " ") != "--config /etc/headscale/config.yaml users list --output json" {
				t.Fatalf("headscale args = %#v", args)
			}
			return []byte(`[{"id":2,"name":"lanpanel"}]`), nil
		default:
			t.Fatalf("runtime command name = %q", name)
		}
		return nil, nil
	}

	mainPath := filepath.Join(t.TempDir(), "lanpanel.yaml")
	if err := config.ExampleConfig().WriteFile(mainPath); err != nil {
		t.Fatalf("WriteFile(main) error = %v", err)
	}
	result, err := RunOnboardingStatus(Context{Version: "test"}, mainPath)
	if err != nil {
		t.Fatalf("RunOnboardingStatus() error = %v", err)
	}
	if result.Status != domain.JobStatusSucceeded {
		t.Fatalf("Status = %q diagnostics = %#v", result.Status, result.Diagnostics)
	}
	for _, id := range []string{"runtime:onboarding-headscale-service", "onboarding:user", "onboarding:client-version", "onboarding:derp-stun"} {
		if !diagnosticsContain(result.Diagnostics, id) {
			t.Fatalf("RunOnboardingStatus() diagnostics missing %s: %#v", id, result.Diagnostics)
		}
	}
}
