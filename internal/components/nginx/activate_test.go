package nginx

import (
	"context"
	"errors"
	"lanpanel/internal/host"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActivatorEnableTestAndReloadRunsExpectedCommands(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{}
	activator := NewActivator(host.NewExecutor(runner, nil))
	results, err := activator.EnableTestAndReload(context.Background())
	if err != nil {
		t.Fatalf("EnableTestAndReload() error = %v", err)
	}
	if len(results) != 1 || len(runner.commands) != 1 {
		t.Fatalf("results = %d commands = %d, want transactional activation command", len(results), len(runner.commands))
	}
	if runner.commands[0].DisplayName != "activate-nginx-site" || !strings.Contains(strings.Join(runner.commands[0].DisplayArgs, " "), SiteEnabledPath) {
		t.Fatalf("command = %#v, want transactional site activation", runner.commands[0])
	}
}

func TestActivateSiteCommandRollsBackOnConfigTestFailure(t *testing.T) {
	paths := newActivationTestPaths(t)
	env := newActivationTestPathEnv(t, true, false)
	result, err := host.NewExecutor(host.OSRunner{}, env).Run(context.Background(), activateSiteCommand(paths.siteEnabled, paths.siteAvailable, paths.defaultEnabled, paths.defaultAvailable))
	if err == nil {
		t.Fatal("activateSiteCommand() error = nil, want nginx -t failure")
	}
	if result.ExitCode == 0 {
		t.Fatalf("ExitCode = %d, want failure", result.ExitCode)
	}
	assertMissingPath(t, paths.siteEnabled)
	assertSymlinkTarget(t, paths.defaultEnabled, paths.defaultAvailable)
	assertLogLineCount(t, env["NGINX_LOG"], 2)
	assertLogLineCount(t, env["SYSTEMCTL_LOG"], 0)
}

func TestActivateSiteCommandRollsBackAndReloadsPreviousConfigOnReloadFailure(t *testing.T) {
	paths := newActivationTestPaths(t)
	env := newActivationTestPathEnv(t, false, true)
	result, err := host.NewExecutor(host.OSRunner{}, env).Run(context.Background(), activateSiteCommand(paths.siteEnabled, paths.siteAvailable, paths.defaultEnabled, paths.defaultAvailable))
	if err == nil {
		t.Fatal("activateSiteCommand() error = nil, want reload failure")
	}
	if result.ExitCode == 0 {
		t.Fatalf("ExitCode = %d, want failure", result.ExitCode)
	}
	assertMissingPath(t, paths.siteEnabled)
	assertSymlinkTarget(t, paths.defaultEnabled, paths.defaultAvailable)
	assertLogLineCount(t, env["NGINX_LOG"], 2)
	assertLogLineCount(t, env["SYSTEMCTL_LOG"], 2)
}

func TestActivateSiteCommandLeavesActivatedLinksOnSuccess(t *testing.T) {
	paths := newActivationTestPaths(t)
	env := newActivationTestPathEnv(t, false, false)
	if _, err := host.NewExecutor(host.OSRunner{}, env).Run(context.Background(), activateSiteCommand(paths.siteEnabled, paths.siteAvailable, paths.defaultEnabled, paths.defaultAvailable)); err != nil {
		t.Fatalf("activateSiteCommand() error = %v", err)
	}
	assertSymlinkTarget(t, paths.siteEnabled, paths.siteAvailable)
	assertMissingPath(t, paths.defaultEnabled)
	assertLogLineCount(t, env["NGINX_LOG"], 1)
	assertLogLineCount(t, env["SYSTEMCTL_LOG"], 1)
}

func TestDisableDefaultSiteCommandRemovesDistributionSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	available := filepath.Join(root, "etc", "nginx", "sites-available", "default")
	enabled := filepath.Join(root, "etc", "nginx", "sites-enabled", "default")
	if err := os.MkdirAll(filepath.Dir(available), 0o755); err != nil {
		t.Fatalf("MkdirAll(available) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(enabled), 0o755); err != nil {
		t.Fatalf("MkdirAll(enabled) error = %v", err)
	}
	if err := os.WriteFile(available, []byte("server { listen 80 default_server; }\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(available, enabled); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	command := disableDefaultSiteCommand(enabled, available)
	if _, err := host.NewExecutor(host.OSRunner{}, nil).Run(context.Background(), command); err != nil {
		t.Fatalf("disable default site command error = %v", err)
	}
	if _, err := os.Lstat(enabled); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(enabled) error = %v, want %v", err, os.ErrNotExist)
	}
}

func TestDisableDefaultSiteCommandRejectsCustomSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	available := filepath.Join(root, "etc", "nginx", "sites-available", "default")
	custom := filepath.Join(root, "srv", "custom-site.conf")
	enabled := filepath.Join(root, "etc", "nginx", "sites-enabled", "default")
	if err := os.MkdirAll(filepath.Dir(available), 0o755); err != nil {
		t.Fatalf("MkdirAll(available) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(custom), 0o755); err != nil {
		t.Fatalf("MkdirAll(custom) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(enabled), 0o755); err != nil {
		t.Fatalf("MkdirAll(enabled) error = %v", err)
	}
	if err := os.WriteFile(available, []byte("default\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(default) error = %v", err)
	}
	if err := os.WriteFile(custom, []byte("custom\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(custom) error = %v", err)
	}
	if err := os.Symlink(custom, enabled); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	command := disableDefaultSiteCommand(enabled, available)
	_, err := host.NewExecutor(host.OSRunner{}, nil).Run(context.Background(), command)
	if err == nil {
		t.Fatal("disable default site command error = nil, want custom symlink rejection")
	}
	if _, statErr := os.Lstat(enabled); statErr != nil {
		t.Fatalf("Lstat(enabled) error = %v, want custom symlink preserved", statErr)
	}
}

type activationTestPaths struct {
	siteAvailable    string
	siteEnabled      string
	defaultAvailable string
	defaultEnabled   string
}

func newActivationTestPaths(t *testing.T) activationTestPaths {
	t.Helper()

	root := t.TempDir()
	paths := activationTestPaths{
		siteAvailable:    filepath.Join(root, "etc", "nginx", "sites-available", "headscale.conf"),
		siteEnabled:      filepath.Join(root, "etc", "nginx", "sites-enabled", "headscale.conf"),
		defaultAvailable: filepath.Join(root, "etc", "nginx", "sites-available", "default"),
		defaultEnabled:   filepath.Join(root, "etc", "nginx", "sites-enabled", "default"),
	}
	for _, path := range []string{paths.siteAvailable, paths.siteEnabled, paths.defaultAvailable, paths.defaultEnabled} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(path), err)
		}
	}
	if err := os.WriteFile(paths.siteAvailable, []byte("lanpanel site\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(site available) error = %v", err)
	}
	if err := os.WriteFile(paths.defaultAvailable, []byte("default site\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(default available) error = %v", err)
	}
	if err := os.Symlink(paths.defaultAvailable, paths.defaultEnabled); err != nil {
		t.Fatalf("Symlink(default enabled) error = %v", err)
	}
	return paths
}

func newActivationTestPathEnv(t *testing.T, failNginxOnce bool, failSystemctlOnce bool) map[string]string {
	t.Helper()

	dir := t.TempDir()
	nginxLog := filepath.Join(dir, "nginx.log")
	systemctlLog := filepath.Join(dir, "systemctl.log")
	failNginxPath := filepath.Join(dir, "fail-nginx-once")
	failSystemctlPath := filepath.Join(dir, "fail-systemctl-once")
	writeExecutable(t, filepath.Join(dir, "nginx"), `#!/bin/sh
echo "$*" >> "$NGINX_LOG"
if [ -n "${NGINX_FAIL_ONCE:-}" ] && [ -f "$NGINX_FAIL_ONCE" ]; then
    rm -f -- "$NGINX_FAIL_ONCE"
    exit 1
fi
exit 0
`)
	writeExecutable(t, filepath.Join(dir, "systemctl"), `#!/bin/sh
echo "$*" >> "$SYSTEMCTL_LOG"
if [ "$*" = "reload nginx.service" ] && [ -n "${SYSTEMCTL_FAIL_ONCE:-}" ] && [ -f "$SYSTEMCTL_FAIL_ONCE" ]; then
    rm -f -- "$SYSTEMCTL_FAIL_ONCE"
    exit 1
fi
exit 0
`)
	if failNginxOnce {
		if err := os.WriteFile(failNginxPath, []byte("fail\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", failNginxPath, err)
		}
	}
	if failSystemctlOnce {
		if err := os.WriteFile(failSystemctlPath, []byte("fail\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", failSystemctlPath, err)
		}
	}
	return map[string]string{
		"PATH":                dir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NGINX_LOG":           nginxLog,
		"SYSTEMCTL_LOG":       systemctlLog,
		"NGINX_FAIL_ONCE":     failNginxPath,
		"SYSTEMCTL_FAIL_ONCE": failSystemctlPath,
	}
}

func writeExecutable(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func assertSymlinkTarget(t *testing.T, path string, want string) {
	t.Helper()

	got, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("Readlink(%s) error = %v", path, err)
	}
	if got != want {
		t.Fatalf("Readlink(%s) = %q, want %q", path, got, want)
	}
}

func assertMissingPath(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(%s) error = %v, want %v", path, err, os.ErrNotExist)
	}
}

func assertLogLineCount(t *testing.T, path string, want int) {
	t.Helper()

	data, err := os.ReadFile(path)
	if want == 0 && errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	got := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) != "" {
			got++
		}
	}
	if got != want {
		t.Fatalf("%s line count = %d, want %d; content=%q", path, got, want, data)
	}
}

type recordingRunner struct {
	commands []host.Command
	failAt   int
}

func (runner *recordingRunner) Run(_ context.Context, command host.Command) (host.Result, error) {
	runner.commands = append(runner.commands, command)
	result := host.Result{Command: command}
	if runner.failAt > 0 && len(runner.commands) == runner.failAt+1 {
		return result, errors.New("command failed")
	}
	return result, nil
}
