package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

func (c Config) ExportYAML() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal config yaml: %w", err)
	}

	return data, nil
}

func (c Config) WriteFile(path string) error {
	data, err := c.ExportYAML()
	if err != nil {
		return err
	}

	if err := writeFileNoFollow(path, data, 0o600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

func ExampleYAML() ([]byte, error) {
	if err := ExampleConfig().Validate(); err != nil {
		return nil, err
	}

	data := fmt.Sprintf(`api_version: %s

# Edit the default section first. It is the only part that should matter for the
# first successful deployment.
default:
  server_url: "https://hs.example.com"
  # base_domain must differ from the host part of server_url and cannot be its
  # parent domain.
  base_domain: "tailnet.example.com"
  certificate_email: "ops@example.com"
  # Keep HTTP-01 when public port 80 can reach this host. Use advanced guided
  # mode for DNS-01.
  acme_challenge: "http-01"

# The advanced section is opt-in. Leave defaults and empty values unless you
# have a real need for Headscale package mirrors/offline packages, metrics port
# changes, lego offline archives, package probe timeout overrides, proxies,
# DNS-01, architecture overrides, or public IP overrides.
advanced:
  headscale_source:
    mode: "direct" # direct | mirror | offline
    version: "%s"
    url: ""
    sha256: ""
    file_path: ""

  headscale:
    # Metrics stay on loopback. Change this when another local service, such as
    # Cockpit, already owns the default metrics port.
    metrics_port: %d

  lego_source:
    # Keep direct unless the host cannot download the pinned lego archive from
    # GitHub. Offline mode must point at the exact pinned lego archive for the
    # selected architecture; lanpanel verifies the built-in SHA-256 digest.
    mode: "direct" # direct | offline
    file_path: ""

  package_probe:
    # Increase these when GitHub release URLs are reachable but slow from the
    # target host. The artifact timeout covers the full download used for
    # SHA-256 verification.
    reachability_timeout: "%s"
    artifact_timeout: "%s"

  proxy:
    http_proxy: ""
    https_proxy: ""
    no_proxy: ""

  dns01:
    provider: ""
    # Supported lego providers: cloudflare, route53, digitalocean, gcloud,
    # tencentcloud.
    # "google" is accepted as an alias for gcloud.
    # Cloudflare, DigitalOcean, and Tencent Cloud require an absolute path to a
    # root-only env file. Route53 and gcloud may use lego's ambient credential
    # chain when deploy and systemd renewal run with the same host identity;
    # their env_file may carry plain provider settings such as
    # AWS_HOSTED_ZONE_ID, AWS_PROFILE, GCE_PROJECT, or GCE_ZONE_ID. Put
    # sensitive DNS values in separate root-only files and reference them with
    # provider _FILE variables.
    #
    # Tencent Cloud DNSPod / EdgeOne baseline env_file tuning:
    # Keep provider credential _FILE variables in the env_file, then add the
    # recursive polling baseline below. It keeps lego polling every 10 seconds
    # while skipping the authoritative NS propagation check that can fail with
    # EdgeOne / DNSPod hosted access.
    # TENCENTCLOUD_PROPAGATION_TIMEOUT=900
    # TENCENTCLOUD_POLLING_INTERVAL=10
    # TENCENTCLOUD_TTL=600
    # TENCENTCLOUD_HTTP_TIMEOUT=60
    # LEGO_DNS_RESOLVERS=119.29.29.29:53
    # LEGO_DNS_TIMEOUT=30
    # LEGO_DNS_PROPAGATION_DISABLE_ANS=true
    env_file: ""

  network:
    public_ipv4: ""
    # Optional enhancement. Leave empty when the host has no usable IPv6.
    public_ipv6: ""

  platform:
    arch: "%s"
`, APIVersion, DefaultHeadscaleVersion, DefaultHeadscaleMetricsPort, DefaultPackageProbeReachabilityTimeout, DefaultPackageProbeArtifactTimeout, DefaultPlatformArch())

	return []byte(data), nil
}

func WriteExampleFile(path string) error {
	data, err := ExampleYAML()
	if err != nil {
		return err
	}

	if err := writeFileNoFollow(path, data, 0o644); err != nil {
		return fmt.Errorf("write example config file: %w", err)
	}

	return nil
}

func writeFileNoFollow(path string, data []byte, perm os.FileMode) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config file path: %w", err)
	}
	dir := filepath.Dir(absolute)
	if err := ensureSafeConfigDirectory(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := ensureSafeConfigDirectory(dir); err != nil {
		return err
	}
	if info, err := os.Lstat(absolute); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not be a symlink", absolute)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", absolute)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat config file: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(absolute)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary config file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary config file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary config file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary config file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config file: %w", err)
	}
	if err := os.Rename(tmpPath, absolute); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func ensureSafeConfigDirectory(dir string) error {
	clean := filepath.Clean(dir)
	if clean == "." || !filepath.IsAbs(clean) {
		return fmt.Errorf("config directory must resolve to a clean absolute path")
	}
	current := string(filepath.Separator)
	if err := checkConfigDirectoryComponent(current, current == clean); err != nil {
		return err
	}
	if clean == current {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("config directory must resolve to a clean absolute path")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("inspect config directory component %s: %w", current, err)
		}
		if err := validateConfigDirectoryComponent(current, info, current == clean); err != nil {
			return err
		}
	}
	return nil
}

func checkConfigDirectoryComponent(path string, immediate bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect config directory component %s: %w", path, err)
	}
	return validateConfigDirectoryComponent(path, info, immediate)
}

func validateConfigDirectoryComponent(path string, info os.FileInfo, immediate bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config directory component %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("config directory component %s must be a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("config directory component %s owner could not be inspected", path)
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != euid && stat.Uid != 0 {
		return fmt.Errorf("config directory component %s owner uid %d does not match effective uid %d or root", path, stat.Uid, euid)
	}
	if unsafeConfigDirectoryMode(info.Mode(), immediate, stat.Uid, euid) {
		return fmt.Errorf("config directory component %s must not be writable by untrusted local users", path)
	}
	return nil
}

func unsafeConfigDirectoryMode(mode os.FileMode, immediate bool, uid uint32, euid uint32) bool {
	if mode.Perm()&0o002 != 0 && (immediate || mode&os.ModeSticky == 0) {
		return true
	}
	return mode.Perm()&0o020 != 0 && uid != euid && (immediate || mode&os.ModeSticky == 0)
}

func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("sync config directory: %w", err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close config directory: %w", err)
	}
	return nil
}
