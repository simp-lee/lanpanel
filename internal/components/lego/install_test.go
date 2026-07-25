package lego

import (
	"context"
	"errors"
	"lanpanel/internal/config"
	"lanpanel/internal/host"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewArchivePlanDirectPinsOfficialReleaseArtifact(t *testing.T) {
	t.Parallel()

	plan, err := NewArchivePlan(validConfig(), InstallPlanOptions{})
	if err != nil {
		t.Fatalf("NewArchivePlan() error = %v", err)
	}

	if plan.Mode != config.PackageSourceModeDirect {
		t.Fatalf("Mode = %q, want %q", plan.Mode, config.PackageSourceModeDirect)
	}
	if plan.Version != Version {
		t.Fatalf("Version = %q, want %q", plan.Version, Version)
	}
	if plan.Arch != config.ArchAMD64 {
		t.Fatalf("Arch = %q, want %q", plan.Arch, config.ArchAMD64)
	}
	if plan.AssetName != "lego_v5.2.2_linux_amd64.tar.gz" {
		t.Fatalf("AssetName = %q", plan.AssetName)
	}
	if plan.SourceURL != "https://github.com/go-acme/lego/releases/download/v5.2.2/lego_v5.2.2_linux_amd64.tar.gz" {
		t.Fatalf("SourceURL = %q", plan.SourceURL)
	}
	if plan.ChecksumsURL != "https://github.com/go-acme/lego/releases/download/v5.2.2/lego_5.2.2_checksums.txt" {
		t.Fatalf("ChecksumsURL = %q", plan.ChecksumsURL)
	}
	if plan.ExpectedSHA256 != sha256LinuxAMD64 {
		t.Fatalf("ExpectedSHA256 = %q", plan.ExpectedSHA256)
	}
	if plan.InstallPath() != "/var/cache/lanpanel/lego_v5.2.2_linux_amd64.tar.gz" {
		t.Fatalf("InstallPath() = %q", plan.InstallPath())
	}
	if plan.BinaryPath != BinaryPath {
		t.Fatalf("BinaryPath = %q, want %q", plan.BinaryPath, BinaryPath)
	}
}

func TestNewArchivePlanPinsARM64SHA256(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Advanced.Platform.Arch = config.ArchARM64
	plan, err := NewArchivePlan(cfg, InstallPlanOptions{})
	if err != nil {
		t.Fatalf("NewArchivePlan() error = %v", err)
	}

	if plan.AssetName != "lego_v5.2.2_linux_arm64.tar.gz" {
		t.Fatalf("AssetName = %q", plan.AssetName)
	}
	if plan.ExpectedSHA256 != sha256LinuxARM64 {
		t.Fatalf("ExpectedSHA256 = %q", plan.ExpectedSHA256)
	}
}

func TestNewArchivePlanRejectsLatestAndUnknownArchitecture(t *testing.T) {
	t.Parallel()

	if _, err := NewArchivePlan(validConfig(), InstallPlanOptions{Version: "latest"}); err == nil || !strings.Contains(err.Error(), "latest is not allowed") {
		t.Fatalf("NewArchivePlan(latest) error = %v, want latest rejection", err)
	}

	if _, err := ArchiveSHA256("riscv64"); err == nil || !strings.Contains(err.Error(), "unsupported lego archive architecture") {
		t.Fatalf("ArchiveSHA256() error = %v, want architecture rejection", err)
	}
}

func TestNewInstallPlanBuildsVerifiedInstallCommands(t *testing.T) {
	t.Parallel()

	plan, err := NewInstallPlan(validConfig(), InstallPlanOptions{CacheDir: "/tmp/lanpanel-cache"})
	if err != nil {
		t.Fatalf("NewInstallPlan() error = %v", err)
	}
	if len(plan.Commands) != 7 {
		t.Fatalf("len(Commands) = %d, want 7", len(plan.Commands))
	}
	if plan.Commands[0].Name != "mkdir" || !strings.Contains(strings.Join(plan.Commands[0].Args, " "), "/tmp/lanpanel-cache") {
		t.Fatalf("Commands[0] = %#v, want cache mkdir", plan.Commands[0])
	}
	if plan.Commands[1].Name != "curl" || !strings.Contains(strings.Join(plan.Commands[1].Args, " "), plan.Archive.SourceURL) {
		t.Fatalf("Commands[1] = %#v, want curl download", plan.Commands[1])
	}
	if plan.Commands[2].Name != "sha256sum" || !strings.Contains(string(plan.Commands[2].Stdin), sha256LinuxAMD64+"  /tmp/lanpanel-cache/lego_v5.2.2_linux_amd64.tar.gz") {
		t.Fatalf("Commands[2] = %#v, want sha256 check before install", plan.Commands[2])
	}
	if got := plan.Commands[3].String(); got != "mkdir -p -m 0755 -- /opt/lanpanel/bin" {
		t.Fatalf("Commands[3] = %q", got)
	}
	if got := plan.Commands[4].String(); got != "tar -xzf /tmp/lanpanel-cache/lego_v5.2.2_linux_amd64.tar.gz -C /opt/lanpanel/bin lego" {
		t.Fatalf("Commands[4] = %q", got)
	}
	if got := plan.Commands[5].String(); got != "chmod 0755 /opt/lanpanel/bin/lego" {
		t.Fatalf("Commands[5] = %q", got)
	}
	if got := plan.Commands[6].String(); got != "/opt/lanpanel/bin/lego --version" {
		t.Fatalf("Commands[6] = %q", got)
	}
}

func TestNewInstallPlanSupportsOfflineArchiveWithPinnedDigest(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Advanced.LegoSource.Mode = config.PackageSourceModeOffline
	cfg.Advanced.LegoSource.FilePath = "/srv/packages/lego_v5.2.2_linux_amd64.tar.gz"

	plan, err := NewInstallPlan(cfg, InstallPlanOptions{})
	if err != nil {
		t.Fatalf("NewInstallPlan() error = %v", err)
	}
	if plan.Archive.Mode != config.PackageSourceModeOffline {
		t.Fatalf("Mode = %q, want offline", plan.Archive.Mode)
	}
	if plan.Archive.SourceURL != "" {
		t.Fatalf("SourceURL = %q, want empty for offline", plan.Archive.SourceURL)
	}
	if plan.Archive.InstallPath() != "/srv/packages/lego_v5.2.2_linux_amd64.tar.gz" {
		t.Fatalf("InstallPath() = %q", plan.Archive.InstallPath())
	}
	if plan.Commands[0].Name != "sha256sum" || !strings.Contains(string(plan.Commands[0].Stdin), plan.Archive.InstallPath()) {
		t.Fatalf("Commands[0] = %#v, want offline sha256 check first", plan.Commands[0])
	}
}

func TestNewInstallPlanOptionsOfflineSourceOverridesConfig(t *testing.T) {
	t.Parallel()

	plan, err := NewInstallPlan(validConfig(), InstallPlanOptions{OfflineSourcePath: "/srv/packages/lego_v5.2.2_linux_amd64.tar.gz"})
	if err != nil {
		t.Fatalf("NewInstallPlan() error = %v", err)
	}
	if plan.Archive.Mode != config.PackageSourceModeOffline {
		t.Fatalf("Mode = %q, want offline", plan.Archive.Mode)
	}
	if plan.Archive.InstallPath() != "/srv/packages/lego_v5.2.2_linux_amd64.tar.gz" {
		t.Fatalf("InstallPath() = %q", plan.Archive.InstallPath())
	}
}

func TestMigrationGateCommandSkipsFreshStorageAndMarksReady(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "lego")
	legoLog := filepath.Join(dir, "lego.log")
	fakeLego := filepath.Join(dir, "lego-bin")
	writeExecutable(t, fakeLego, "#!/bin/sh\nprintf 'lego %s\\n' \"$*\" >> "+legoLog+"\n")

	command := MigrationGateCommand(dataPath)
	args := append([]string(nil), command.Args...)
	args[3] = fakeLego
	output, err := exec.Command(command.Name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("migration gate error = %v; output:\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(dataPath, MigrationMarkerName)); err != nil {
		t.Fatalf("marker missing after fresh gate: %v", err)
	}
	if _, err := os.Stat(legoLog); !os.IsNotExist(err) {
		t.Fatalf("lego migrate ran for fresh storage; stat err = %v", err)
	}
}

func TestMigrationGateCommandMigratesExistingStorageWithBackup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "lego")
	certDir := filepath.Join(dataPath, "certificates")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "hs.example.com.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	legoLog := filepath.Join(dir, "lego.log")
	fakeLego := filepath.Join(dir, "lego-bin")
	writeExecutable(t, fakeLego, `#!/bin/sh
answer=$(cat)
printf 'stdin=%s args=%s\n' "$answer" "$*" >> "`+legoLog+`"
`)

	command := MigrationGateCommand(dataPath)
	args := append([]string(nil), command.Args...)
	args[3] = fakeLego
	output, err := exec.Command(command.Name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("migration gate error = %v; output:\n%s", err, output)
	}
	logContent, err := os.ReadFile(legoLog)
	if err != nil {
		t.Fatalf("ReadFile(lego log) error = %v", err)
	}
	if !strings.Contains(string(logContent), "stdin=y") || !strings.Contains(string(logContent), "migrate --path "+dataPath) {
		t.Fatalf("lego log = %q, want non-interactive migrate", logContent)
	}
	if _, err := os.Stat(filepath.Join(dataPath, MigrationMarkerName)); err != nil {
		t.Fatalf("marker missing after migration: %v", err)
	}
	matches, err := filepath.Glob(dataPath + ".lanpanel-v4-backup.*")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("backup matches = %v, want one backup", matches)
	}
}

func TestMigrationGateCommandRejectsUnknownNonEmptyStorage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "lego")
	if err := os.MkdirAll(dataPath, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataPath, "unexpected"), []byte("data"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	fakeLego := filepath.Join(dir, "lego-bin")
	writeExecutable(t, fakeLego, "#!/bin/sh\nexit 0\n")

	command := MigrationGateCommand(dataPath)
	args := append([]string(nil), command.Args...)
	args[3] = fakeLego
	output, err := exec.Command(command.Name, args...).CombinedOutput()
	if err == nil {
		t.Fatalf("migration gate error = nil, want unknown storage failure; output:\n%s", output)
	}
	if !strings.Contains(string(output), "refusing lego v5 storage migration") {
		t.Fatalf("output = %q, want refusal detail", output)
	}
}

func TestInstallerRunsPlanCommandsInOrder(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{}
	installer := NewInstaller(host.NewExecutor(runner, nil))
	plan := InstallPlan{Commands: []host.Command{
		{Name: "sha256sum"},
		{Name: "tar"},
	}}

	results, err := installer.Install(context.Background(), plan)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if len(results) != 2 || len(runner.commands) != 2 {
		t.Fatalf("results = %d commands = %d, want 2", len(results), len(runner.commands))
	}
	if runner.commands[0].Name != "sha256sum" || runner.commands[1].Name != "tar" {
		t.Fatalf("commands = %#v, want plan order", runner.commands)
	}
}

func TestInstallerStopsOnFirstCommandFailure(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{errAt: 1}
	installer := NewInstaller(host.NewExecutor(runner, nil))
	plan := InstallPlan{Commands: []host.Command{
		{Name: "sha256sum"},
		{Name: "tar"},
	}}

	results, err := installer.Install(context.Background(), plan)
	if err == nil {
		t.Fatal("Install() error = nil, want failure")
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want failing result included", len(results))
	}
}

type recordingRunner struct {
	commands []host.Command
	errAt    int
}

func (runner *recordingRunner) Run(_ context.Context, command host.Command) (host.Result, error) {
	runner.commands = append(runner.commands, command)
	result := host.Result{Command: command}
	if runner.errAt > 0 && len(runner.commands) == runner.errAt+1 {
		return result, errors.New("command failed")
	}
	return result, nil
}

func validConfig() config.Config {
	cfg := config.New()
	cfg.Default.ServerURL = "https://hs.example.com"
	cfg.Default.BaseDomain = "tailnet.example.com"
	cfg.Default.CertificateEmail = "ops@example.com"
	return cfg
}

func writeExecutable(t *testing.T, path string, content string) {
	t.Helper()

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		t.Fatalf("CreateTemp(%s) error = %v", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		t.Fatalf("WriteString(%s) error = %v", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("Close(%s) error = %v", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		t.Fatalf("Chmod(%s) error = %v", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		t.Fatalf("Rename(%s, %s) error = %v", tmpPath, path, err)
	}
}
