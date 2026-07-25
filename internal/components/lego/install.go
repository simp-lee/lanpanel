package lego

import (
	"context"
	"fmt"
	"lanpanel/internal/config"
	"lanpanel/internal/host"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	Version = config.DefaultLegoVersion

	BinaryPath      = "/opt/lanpanel/bin/lego"
	DefaultCacheDir = "/var/cache/lanpanel"
)

const (
	sha256LinuxAMD64 = "018de6d3f2da09630caa2fbbe8c6aa459323ad0ac0a053d0e808268914b38a8b"
	sha256LinuxARM64 = "92c9d7d2a6377cdd4702bfaf7e0f61ea167456f1686a3899a12f289fe863c49b"
)

type ArchivePlan struct {
	Mode           string
	Version        string
	Arch           string
	AssetName      string
	SourceURL      string
	SourcePath     string
	ChecksumsURL   string
	ExpectedSHA256 string
	CachedPath     string
	BinaryPath     string
}

type InstallPlanOptions struct {
	CacheDir            string
	OfflineSourcePath   string
	Version             string
	ReachabilityTimeout time.Duration
	ArtifactTimeout     time.Duration
}

type InstallPlan struct {
	Archive  ArchivePlan
	Commands []host.Command
}

type Installer struct {
	executor host.Executor
}

func NewInstaller(executor host.Executor) Installer {
	return Installer{executor: executor}
}

func NewInstallPlan(cfg config.Config, options InstallPlanOptions) (InstallPlan, error) {
	archive, err := NewArchivePlan(cfg, options)
	if err != nil {
		return InstallPlan{}, err
	}

	archivePath := archive.InstallPath()
	commands := []host.Command{}
	if archive.Mode != config.PackageSourceModeOffline {
		curlArgs := []string{"-fL", "--retry", "3"}
		if seconds := curlTimeoutSeconds(options.ReachabilityTimeout); seconds != "" {
			curlArgs = append(curlArgs, "--connect-timeout", seconds)
		}
		if seconds := curlTimeoutSeconds(options.ArtifactTimeout); seconds != "" {
			curlArgs = append(curlArgs, "--max-time", seconds)
		}
		curlArgs = append(curlArgs, "--output", archive.CachedPath, archive.SourceURL)
		commands = append(commands,
			host.Command{Name: "mkdir", Args: []string{"-p", "-m", "0755", "--", filepath.Dir(archive.CachedPath)}},
			host.Command{Name: "curl", Args: curlArgs},
		)
	}

	commands = append(commands,
		host.Command{
			Name:  "sha256sum",
			Args:  []string{"--check", "-"},
			Stdin: []byte(archive.ExpectedSHA256 + "  " + archivePath + "\n"),
		},
		host.Command{Name: "mkdir", Args: []string{"-p", "-m", "0755", "--", filepath.Dir(archive.BinaryPath)}},
		host.Command{Name: "tar", Args: []string{"-xzf", archivePath, "-C", filepath.Dir(archive.BinaryPath), "lego"}},
		host.Command{Name: "chmod", Args: []string{"0755", archive.BinaryPath}},
		host.Command{Name: archive.BinaryPath, Args: []string{"--version"}},
	)

	return InstallPlan{Archive: archive, Commands: commands}, nil
}

func NewArchivePlan(cfg config.Config, options InstallPlanOptions) (ArchivePlan, error) {
	if err := cfg.Validate(); err != nil {
		return ArchivePlan{}, err
	}

	version := normalizeVersion(firstNonEmpty(options.Version, Version))
	if strings.EqualFold(strings.TrimSpace(options.Version), "latest") {
		return ArchivePlan{}, fmt.Errorf("lego version must be pinned to %s; latest is not allowed", Version)
	}
	if version != Version {
		return ArchivePlan{}, fmt.Errorf("lego version must be %s for this release", Version)
	}

	arch := packageArch(cfg)
	sha256, err := ArchiveSHA256(arch)
	if err != nil {
		return ArchivePlan{}, err
	}
	assetName := OfficialArchiveAssetName(version, arch)

	cacheDir := strings.TrimSpace(options.CacheDir)
	if cacheDir == "" {
		cacheDir = DefaultCacheDir
	}

	plan := ArchivePlan{
		Mode:           config.PackageSourceModeDirect,
		Version:        version,
		Arch:           arch,
		AssetName:      assetName,
		SourceURL:      OfficialArchiveURL(version, arch),
		ChecksumsURL:   OfficialChecksumsURL(version),
		ExpectedSHA256: sha256,
		CachedPath:     filepath.Join(cacheDir, assetName),
		BinaryPath:     BinaryPath,
	}
	if sourcePath := firstNonEmpty(options.OfflineSourcePath, cfg.Advanced.LegoSource.FilePath); sourcePath != "" {
		plan.Mode = config.PackageSourceModeOffline
		plan.SourceURL = ""
		plan.SourcePath = sourcePath
	}
	return plan, nil
}

func (plan ArchivePlan) InstallPath() string {
	if plan.Mode == config.PackageSourceModeOffline {
		return plan.SourcePath
	}
	return plan.CachedPath
}

func OfficialArchiveURL(version string, arch string) string {
	assetName := OfficialArchiveAssetName(version, arch)
	if assetName == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/go-acme/lego/releases/download/%s/%s", normalizeVersion(version), assetName)
}

func OfficialArchiveAssetName(version string, arch string) string {
	version = normalizeVersion(version)
	arch = strings.TrimSpace(arch)
	if version == "" || arch == "" {
		return ""
	}
	return fmt.Sprintf("lego_%s_linux_%s.tar.gz", version, arch)
}

func OfficialChecksumsURL(version string) string {
	version = strings.TrimPrefix(normalizeVersion(version), "v")
	if version == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/go-acme/lego/releases/download/v%s/lego_%s_checksums.txt", version, version)
}

func ArchiveSHA256(arch string) (string, error) {
	switch strings.TrimSpace(arch) {
	case config.ArchAMD64:
		return sha256LinuxAMD64, nil
	case config.ArchARM64:
		return sha256LinuxARM64, nil
	default:
		return "", fmt.Errorf("unsupported lego archive architecture %q; supported architectures: amd64, arm64", strings.TrimSpace(arch))
	}
}

func (installer Installer) Install(ctx context.Context, plan InstallPlan) ([]host.Result, error) {
	results := make([]host.Result, 0, len(plan.Commands))
	for _, command := range plan.Commands {
		result, err := installer.executor.Run(ctx, command)
		results = append(results, result)
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

func curlTimeoutSeconds(duration time.Duration) string {
	if duration <= 0 {
		return ""
	}
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	if seconds <= 0 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}

func packageArch(cfg config.Config) string {
	arch := strings.TrimSpace(cfg.Advanced.Platform.Arch)
	if arch == "" {
		return config.ArchAMD64
	}
	return arch
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
