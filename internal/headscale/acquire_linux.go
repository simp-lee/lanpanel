//go:build linux

package headscale

import (
	"context"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/download"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
)

var attemptPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func AcquireArchive(ctx context.Context, installed release.InstallIdentity, choice SourceChoice, proxy *sources.Proxy, stagingDirectory, attempt string, owner filetxn.Owner) (result []byte, resultErr error) {
	source, err := BuildSource(installed, choice)
	if err != nil {
		return nil, err
	}
	if !attemptPattern.MatchString(attempt) || !filepath.IsAbs(stagingDirectory) {
		return nil, fmt.Errorf("Headscale acquisition staging authority is invalid")
	}
	expected := installed.Headscale.Archive
	if source.Kind == sources.Offline {
		file, identity, err := filetxn.OpenExternalArtifact(source.OfflinePath, owner, int64(expected.Bytes), expected.Digest)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, int64(expected.Bytes)+1))
		if err != nil || uint64(len(data)) != expected.Bytes || identity.Bytes != int64(expected.Bytes) {
			return nil, fmt.Errorf("verified offline Headscale artifact changed while copying")
		}
		return data, nil
	}
	downloader, err := download.New(download.Config{Source: source, Proxy: proxy, MaximumRedirects: 5, Timeouts: download.Timeouts{Connect: 10 * time.Second, TLSHandshake: 10 * time.Second, ResponseHeader: 15 * time.Second, ReadIdle: 15 * time.Second, Total: 5 * time.Minute}})
	if err != nil {
		return nil, err
	}
	stagingName := attempt + ".archive"
	if err := reconcileAcquisitionStaging(stagingDirectory, stagingName, owner, int64(expected.Bytes)); err != nil {
		return nil, err
	}
	staging, err := download.CreateStaging(stagingDirectory, stagingName, owner.UID, owner.GID, int64(expected.Bytes))
	if err != nil {
		return nil, err
	}
	stagingPath := filepath.Join(stagingDirectory, stagingName)
	defer func() {
		closeErr := staging.Close()
		removeErr := os.Remove(stagingPath)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		resultErr = errors.Join(resultErr, closeErr, removeErr)
	}()
	verified, err := downloader.FetchToStaging(ctx, download.Request{MaximumBytes: int64(expected.Bytes), ExpectedSize: int64(expected.Bytes)}, staging)
	if err != nil {
		return nil, err
	}
	file, identity, err := filetxn.OpenExternalArtifact(verified.Path, owner, int64(expected.Bytes), expected.Digest)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(expected.Bytes)+1))
	if err != nil || uint64(len(data)) != expected.Bytes || identity.Bytes != int64(expected.Bytes) {
		return nil, fmt.Errorf("verified network Headscale artifact changed while copying")
	}
	return data, nil
}

func reconcileAcquisitionStaging(directory, name string, owner filetxn.Owner, maximum int64) error {
	parent, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	closeErr := unix.Close(fd)
	if statErr != nil || closeErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Mode&0o7777 != 0o600 || stat.Size < 0 || stat.Size > maximum {
		return fmt.Errorf("Headscale acquisition staging evidence is foreign")
	}
	if err := unix.Unlinkat(parent, name, 0); err != nil {
		return err
	}
	return unix.Fsync(parent)
}
