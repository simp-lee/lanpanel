//go:build linux

package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/download"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/sources"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type ArtifactStager struct {
	Files    *TransactionFiles
	Launcher ChildLauncher
}

func (stager *ArtifactStager) Stage(ctx context.Context, plan Plan) error {
	if stager == nil || stager.Files == nil || ValidatePlan(plan) != nil {
		return fmt.Errorf("package artifact staging authority is invalid")
	}
	directory, err := stager.Files.EnsureStaging(ctx, plan)
	if err != nil {
		return err
	}
	if plan.Mode == DistroRepository {
		if stager.Launcher == nil {
			return fmt.Errorf("distro package download child is unavailable")
		}
		result, err := stager.Launcher.RunInvocation(ctx, child.ProfileAPTDownload, packageInvocation(plan, false), nil)
		if err != nil || result.ExitCode != 0 || result.OutputCutOff {
			return fmt.Errorf("distro package download did not reach a bounded terminal result")
		}
		if err := stager.stageDistroCache(ctx, plan, directory); err != nil {
			return err
		}
		return stager.Files.validateStagedClosure(ctx, plan)
	}
	for _, pkg := range plan.Packages {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := pkg.ArtifactDigest + ".deb"
		target := filepath.Join(directory, name)
		if _, err := os.Lstat(target); err == nil {
			if err := validateStagedPath(target, pkg, stager.Files.strict); err != nil {
				return err
			}
			continue
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect package staging identity: %w", err)
		}
		staging, err := download.CreateStaging(directory, name, 0, 0, pkg.ArtifactBytes)
		if err != nil {
			return err
		}
		switch pkg.Source.Kind {
		case sources.OfficialCanonical, sources.Mirror:
			timeouts := download.Timeouts{Connect: plan.ConnectTimeout, TLSHandshake: plan.ConnectTimeout, ResponseHeader: plan.ReadTimeout, ReadIdle: plan.ReadTimeout, Total: plan.TotalTimeout}
			downloader, err := download.New(download.Config{Source: pkg.Source, Proxy: plan.Proxy, MaximumRedirects: 5, Timeouts: timeouts})
			if err != nil {
				_ = staging.Close()
				return err
			}
			if _, err := downloader.FetchToStaging(ctx, download.Request{MaximumBytes: pkg.ArtifactBytes, ExpectedSize: pkg.ArtifactBytes}, staging); err != nil {
				return err
			}
		case sources.Offline:
			source, _, err := filetxn.OpenExternalArtifact(pkg.Source.OfflinePath, filetxn.Owner{UID: 0, GID: 0}, pkg.ArtifactBytes, pkg.ArtifactDigest)
			if err != nil {
				_ = staging.Close()
				return err
			}
			written, copyErr := io.CopyBuffer(staging, io.LimitReader(source, pkg.ArtifactBytes+1), make([]byte, 32<<10))
			closeErr := source.Close()
			if copyErr != nil || closeErr != nil || written != pkg.ArtifactBytes {
				_ = staging.Close()
				return fmt.Errorf("copy exact offline package into controlled staging")
			}
			if _, err := staging.CloseVerified(pkg.ArtifactDigest, pkg.ArtifactBytes); err != nil {
				return err
			}
		default:
			_ = staging.Close()
			return fmt.Errorf("package source kind cannot stage a deb artifact")
		}
	}
	return stager.Files.validateStagedClosure(ctx, plan)
}

func (stager *ArtifactStager) stageDistroCache(ctx context.Context, plan Plan, stagingDirectory string) error {
	cachePath := filepath.Join(stager.Files.transactionRoot, plan.TransactionID, "archives")
	cacheFD, err := openPackageRoot(cachePath, stager.Files.strict)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(cacheFD) }()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", cacheFD))
	if err != nil {
		return fmt.Errorf("enumerate distro package cache: %w", err)
	}
	owner, group := uint32(0), uint32(0)
	if !stager.Files.strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	matched := map[string]bool{}
	for _, entry := range entries {
		if entry.Name() == "lock" || entry.Name() == "partial" && entry.IsDir() {
			continue
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".deb" {
			return fmt.Errorf("distro package cache contains an unexpected member")
		}
		fd, err := unix.Openat(cacheFD, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open distro package cache member no-follow: %w", err)
		}
		file := os.NewFile(uintptr(fd), entry.Name())
		if file == nil {
			_ = unix.Close(fd)
			return fmt.Errorf("distro package cache descriptor is invalid")
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o022 != 0 || stat.Size <= 0 || stat.Size > 4<<30 {
			_ = file.Close()
			return fmt.Errorf("distro package cache member identity is unsafe")
		}
		hasher := sha256.New()
		read, hashErr := io.Copy(hasher, io.LimitReader(file, stat.Size+1))
		digest := hex.EncodeToString(hasher.Sum(nil))
		if hashErr != nil || read != stat.Size {
			_ = file.Close()
			return fmt.Errorf("hash exact distro package cache member")
		}
		pkg, ok := packageByDigest(plan.Packages, digest, stat.Size)
		if !ok || matched[digest] {
			_ = file.Close()
			return fmt.Errorf("distro package cache differs from the frozen closure")
		}
		destinationPath := filepath.Join(stagingDirectory, pkg.ArtifactDigest+".deb")
		if _, err := os.Lstat(destinationPath); err == nil {
			if err := file.Close(); err != nil {
				return err
			}
			if err := validateStagedPath(destinationPath, pkg, stager.Files.strict); err != nil {
				return err
			}
			matched[digest] = true
			continue
		} else if !os.IsNotExist(err) {
			_ = file.Close()
			return fmt.Errorf("inspect distro package staging identity: %w", err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return err
		}
		destination, err := download.CreateStaging(stagingDirectory, pkg.ArtifactDigest+".deb", 0, 0, pkg.ArtifactBytes)
		if err != nil {
			_ = file.Close()
			return err
		}
		written, copyErr := io.CopyBuffer(destination, io.LimitReader(file, pkg.ArtifactBytes+1), make([]byte, 32<<10))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != pkg.ArtifactBytes {
			_ = destination.Close()
			return fmt.Errorf("copy exact distro package into controlled staging")
		}
		if _, err := destination.CloseVerified(pkg.ArtifactDigest, pkg.ArtifactBytes); err != nil {
			return err
		}
		matched[digest] = true
	}
	if len(matched) != len(plan.Packages) {
		return fmt.Errorf("distro package cache omits a frozen package artifact")
	}
	return ctx.Err()
}

func validateStagedPath(path string, pkg Package, strict bool) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open existing staged package no-follow: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("existing staged package descriptor is invalid")
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	owner, group := uint32(0), uint32(0)
	if !strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o777 != 0o600 || stat.Size != pkg.ArtifactBytes {
		return fmt.Errorf("existing staged package identity is unsafe")
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, io.LimitReader(file, pkg.ArtifactBytes+1))
	if err != nil || read != pkg.ArtifactBytes || hex.EncodeToString(hasher.Sum(nil)) != pkg.ArtifactDigest {
		return fmt.Errorf("existing staged package bytes differ from exact closure")
	}
	return nil
}

func packageByDigest(packages []Package, digest string, bytes int64) (Package, bool) {
	for _, pkg := range packages {
		if pkg.ArtifactDigest == digest && pkg.ArtifactBytes == bytes {
			return pkg, true
		}
	}
	return Package{}, false
}
