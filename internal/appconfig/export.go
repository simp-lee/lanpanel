package appconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

func (c Config) ExportYAML() ([]byte, error) {
	if err := c.ValidateForExposurePlan(); err != nil {
		return nil, err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal app config yaml: %w", err)
	}
	return data, nil
}

func (c Config) WriteFile(path string) error {
	data, err := c.ExportYAML()
	if err != nil {
		return err
	}
	if err := writeFileNoFollow(path, data, 0o600); err != nil {
		return fmt.Errorf("write app config file: %w", err)
	}
	return nil
}

func ExampleYAML() ([]byte, error) { return ExampleConfig().ExportYAML() }

func WriteExampleFile(path string) error {
	data, err := ExampleYAML()
	if err != nil {
		return err
	}
	if err := writeFileNoFollow(path, data, 0o644); err != nil {
		return fmt.Errorf("write app example config file: %w", err)
	}
	return nil
}

func writeFileNoFollow(path string, data []byte, perm os.FileMode) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve app config file path: %w", err)
	}
	dir := filepath.Dir(absolute)
	if err := ensureSafeAppConfigDirectory(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create app config directory: %w", err)
	}
	if err := ensureSafeAppConfigDirectory(dir); err != nil {
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
		return fmt.Errorf("stat app config file: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(absolute)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary app config file: %w", err)
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
		return fmt.Errorf("write temporary app config file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary app config file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary app config file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary app config file: %w", err)
	}
	if err := os.Rename(tmpPath, absolute); err != nil {
		return fmt.Errorf("replace app config file: %w", err)
	}
	if err := syncAppConfigDirectory(dir); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func ensureSafeAppConfigDirectory(dir string) error {
	clean := filepath.Clean(dir)
	if clean == "." || !filepath.IsAbs(clean) {
		return fmt.Errorf("app config directory must resolve to a clean absolute path")
	}
	current := string(filepath.Separator)
	if err := checkAppConfigDirectoryComponent(current, current == clean); err != nil {
		return err
	}
	if clean == current {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("app config directory must resolve to a clean absolute path")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("inspect app config directory component %s: %w", current, err)
		}
		if err := validateAppConfigDirectoryComponent(current, info, current == clean); err != nil {
			return err
		}
	}
	return nil
}

func checkAppConfigDirectoryComponent(path string, immediate bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect app config directory component %s: %w", path, err)
	}
	return validateAppConfigDirectoryComponent(path, info, immediate)
}

func validateAppConfigDirectoryComponent(path string, info os.FileInfo, immediate bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("app config directory component %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("app config directory component %s must be a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("app config directory component %s owner could not be inspected", path)
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != euid && stat.Uid != 0 {
		return fmt.Errorf("app config directory component %s owner uid %d does not match effective uid %d or root", path, stat.Uid, euid)
	}
	if unsafeAppConfigDirectoryMode(info.Mode(), immediate, stat.Uid, euid) {
		return fmt.Errorf("app config directory component %s must not be writable by untrusted local users", path)
	}
	return nil
}

func unsafeAppConfigDirectoryMode(mode os.FileMode, immediate bool, uid uint32, euid uint32) bool {
	if mode.Perm()&0o002 != 0 && (immediate || mode&os.ModeSticky == 0) {
		return true
	}
	return mode.Perm()&0o020 != 0 && uid != euid && (immediate || mode&os.ModeSticky == 0)
}

func syncAppConfigDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open app config directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("sync app config directory: %w", err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close app config directory: %w", err)
	}
	return nil
}
