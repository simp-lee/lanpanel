package headscale

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
	Version = config.DefaultHeadscaleVersion

	ServiceName = "headscale.service"
	ConfigPath  = "/etc/headscale/config.yaml"
	PolicyPath  = "/etc/headscale/policy.hujson"

	DefaultPackageCacheDir = "/var/cache/lanpanel"
)

const (
	sha256LinuxAMD64DEB = "6b92fcc25c528a0f4dea05ec8660a5da801106ff2393763cea19e2bf4a2d9ef7"
	sha256LinuxARM64DEB = "3334550d12a35f9f7923281baf80fda37ddba13accfbf2f1ef2295b5a2e3b03b"
)

type PackagePlan struct {
	Mode                   string
	Version                string
	Arch                   string
	SourceURL              string
	SourcePath             string
	AssetName              string
	ChecksumsURL           string
	ExpectedSHA256         string
	CachedPath             string
	RequiresOfficialDigest bool
}

type InstallPlanOptions struct {
	CacheDir              string
	OfficialPackageSHA256 string
	VerifiedPackageSHA256 string
	ReachabilityTimeout   time.Duration
	ArtifactTimeout       time.Duration
}

type InstallPlan struct {
	Package  PackagePlan
	Commands []host.Command
}

type Installer struct {
	executor host.Executor
}

func NewInstaller(executor host.Executor) Installer {
	return Installer{executor: executor}
}

func NewInstallPlan(cfg config.Config, options InstallPlanOptions) (InstallPlan, error) {
	packagePlan, err := NewPackagePlan(cfg, options)
	if err != nil {
		return InstallPlan{}, err
	}

	commands := []host.Command{}
	if packagePlan.Mode != config.PackageSourceModeOffline {
		curlArgs := []string{"-fL", "--retry", "3"}
		if seconds := curlTimeoutSeconds(options.ReachabilityTimeout); seconds != "" {
			curlArgs = append(curlArgs, "--connect-timeout", seconds)
		}
		if seconds := curlTimeoutSeconds(options.ArtifactTimeout); seconds != "" {
			curlArgs = append(curlArgs, "--max-time", seconds)
		}
		curlArgs = append(curlArgs, "--output", packagePlan.CachedPath, packagePlan.SourceURL)
		commands = append(commands,
			host.Command{Name: "mkdir", Args: []string{"-p", "-m", "0755", "--", filepath.Dir(packagePlan.CachedPath)}},
			host.Command{Name: "curl", Args: curlArgs},
		)
	}

	if strings.TrimSpace(packagePlan.ExpectedSHA256) != "" {
		commands = append(commands, host.Command{
			Name:  "sha256sum",
			Args:  []string{"--check", "-"},
			Stdin: []byte(packagePlan.ExpectedSHA256 + "  " + packagePlan.InstallPath() + "\n"),
		})
	}
	commands = append(commands, host.Command{
		Name: "apt-get",
		Args: []string{"install", "-y", packagePlan.InstallPath()},
		Env:  map[string]string{"DEBIAN_FRONTEND": "noninteractive"},
	})

	return InstallPlan{Package: packagePlan, Commands: commands}, nil
}

func NewPackagePlan(cfg config.Config, options InstallPlanOptions) (PackagePlan, error) {
	if err := cfg.Validate(); err != nil {
		return PackagePlan{}, err
	}

	source := cfg.Advanced.HeadscaleSource
	mode := strings.TrimSpace(source.Mode)
	version := strings.TrimSpace(source.Version)
	if version != Version {
		return PackagePlan{}, fmt.Errorf("headscale version must be %s for this release", Version)
	}
	arch := packageArch(cfg)
	assetName := OfficialPackageAssetName(version, arch)
	if assetName == "" {
		return PackagePlan{}, fmt.Errorf("headscale package version and architecture are required")
	}

	cacheDir := strings.TrimSpace(options.CacheDir)
	if cacheDir == "" {
		cacheDir = DefaultPackageCacheDir
	}

	plan := PackagePlan{
		Mode:         mode,
		Version:      version,
		Arch:         arch,
		AssetName:    assetName,
		ChecksumsURL: OfficialChecksumsURL(version),
		CachedPath:   filepath.Join(cacheDir, assetName),
	}

	switch mode {
	case config.PackageSourceModeDirect:
		digest, err := PackageSHA256(version, arch)
		if err != nil {
			return PackagePlan{}, err
		}
		if err := requireMatchingDigest("verified Headscale package SHA-256", options.VerifiedPackageSHA256, digest); err != nil {
			return PackagePlan{}, err
		}
		if err := requireMatchingDigest("official Headscale package SHA-256", options.OfficialPackageSHA256, digest); err != nil {
			return PackagePlan{}, err
		}
		plan.SourceURL = OfficialPackageURL(version, arch)
		plan.ExpectedSHA256 = digest
		plan.RequiresOfficialDigest = false
	case config.PackageSourceModeMirror:
		plan.SourceURL = strings.TrimSpace(source.URL)
		plan.ExpectedSHA256 = strings.TrimSpace(source.SHA256)
	case config.PackageSourceModeOffline:
		plan.SourcePath = strings.TrimSpace(source.FilePath)
		plan.ExpectedSHA256 = strings.TrimSpace(source.SHA256)
	default:
		return PackagePlan{}, fmt.Errorf("unsupported Headscale package source mode %q", mode)
	}

	if plan.Mode != config.PackageSourceModeOffline && strings.TrimSpace(plan.SourceURL) == "" {
		return PackagePlan{}, fmt.Errorf("headscale package URL is required")
	}
	if plan.Mode == config.PackageSourceModeOffline && strings.TrimSpace(plan.SourcePath) == "" {
		return PackagePlan{}, fmt.Errorf("headscale offline package path is required")
	}
	if strings.TrimSpace(plan.ExpectedSHA256) == "" {
		return PackagePlan{}, fmt.Errorf("headscale package SHA-256 digest is required before installation")
	}

	return plan, nil
}

func (plan PackagePlan) InstallPath() string {
	if plan.Mode == config.PackageSourceModeOffline {
		return localPackagePathForApt(plan.SourcePath)
	}
	return plan.CachedPath
}

func localPackagePathForApt(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, string(filepath.Separator)) {
		return path
	}
	return "." + string(filepath.Separator) + path
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

func OfficialPackageURL(version string, arch string) string {
	assetName := OfficialPackageAssetName(version, arch)
	if assetName == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/juanfont/headscale/releases/download/v%s/%s", strings.TrimSpace(version), assetName)
}

func OfficialPackageAssetName(version string, arch string) string {
	version = strings.TrimSpace(version)
	arch = strings.TrimSpace(arch)
	if version == "" || arch == "" {
		return ""
	}
	return fmt.Sprintf("headscale_%s_linux_%s.deb", version, arch)
}

func OfficialChecksumsURL(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/juanfont/headscale/releases/download/v%s/checksums.txt", version)
}

func PackageSHA256(version string, arch string) (string, error) {
	if strings.TrimSpace(version) != Version {
		return "", fmt.Errorf("headscale version must be %s for this release", Version)
	}
	switch strings.TrimSpace(arch) {
	case config.ArchAMD64:
		return sha256LinuxAMD64DEB, nil
	case config.ArchARM64:
		return sha256LinuxARM64DEB, nil
	default:
		return "", fmt.Errorf("unsupported Headscale package architecture %q; supported architectures: amd64, arm64", strings.TrimSpace(arch))
	}
}

func requireMatchingDigest(label string, actual string, expected string) error {
	actual = strings.TrimSpace(actual)
	if actual == "" {
		return nil
	}
	if !strings.EqualFold(actual, strings.TrimSpace(expected)) {
		return fmt.Errorf("%s %s does not match built-in digest %s", label, actual, expected)
	}
	return nil
}

func packageArch(cfg config.Config) string {
	arch := strings.TrimSpace(cfg.Advanced.Platform.Arch)
	if arch == "" {
		return config.ArchAMD64
	}
	return arch
}
