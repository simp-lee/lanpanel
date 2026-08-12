//go:build linux

package filetxn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

type ExternalIdentity struct {
	Path   string
	Device uint64
	Inode  uint64
	Bytes  int64
	Digest string
}

var externalDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateExternalArtifact verifies an offline/external artifact without
// transferring ownership or modifying its bytes.
func ValidateExternalArtifact(path string, owner Owner, maximumBytes int64, expectedDigest string) (ExternalIdentity, error) {
	file, identity, err := OpenExternalArtifact(path, owner, maximumBytes, expectedDigest)
	if err != nil {
		return ExternalIdentity{}, err
	}
	if err := file.Close(); err != nil {
		return ExternalIdentity{}, err
	}
	return identity, nil
}

// OpenExternalArtifact returns the same no-follow descriptor whose identity and
// bytes were verified. The caller must close it and may only copy from it.
func OpenExternalArtifact(path string, owner Owner, maximumBytes int64, expectedDigest string) (*os.File, ExternalIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") || maximumBytes <= 0 || maximumBytes > 4<<30 || !externalDigestPattern.MatchString(expectedDigest) {
		return nil, ExternalIdentity{}, fmt.Errorf("external artifact identity or bound is invalid")
	}
	parentFD, base, err := openExternalParent(path)
	if err != nil {
		return nil, ExternalIdentity{}, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ExternalIdentity{}, fmt.Errorf("open external artifact no-follow")
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, ExternalIdentity{}, fmt.Errorf("external artifact descriptor is invalid")
	}
	fail := func(err error) (*os.File, ExternalIdentity, error) {
		_ = file.Close()
		return nil, ExternalIdentity{}, err
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != owner.UID || before.Gid != owner.GID || before.Mode&0o777 != 0o600 || before.Size <= 0 || before.Size > maximumBytes {
		return fail(fmt.Errorf("external artifact type, link, owner, mode, or size is unsafe"))
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, io.LimitReader(file, maximumBytes+1))
	if err != nil || read != before.Size || hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		return fail(fmt.Errorf("external artifact bytes or digest mismatch"))
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		return fail(fmt.Errorf("external artifact changed during validation"))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("rewind verified external artifact: %w", err))
	}
	identity := ExternalIdentity{Path: path, Device: uint64(after.Dev), Inode: after.Ino, Bytes: after.Size, Digest: expectedDigest}
	return file, identity, nil
}

func openExternalParent(path string) (int, string, error) {
	components := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, component := range components {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, "", fmt.Errorf("open external artifact parent no-follow: %w", openErr)
		}
		current = next
		var stat unix.Stat_t
		if err := unix.Fstat(current, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			_ = unix.Close(current)
			return -1, "", fmt.Errorf("external artifact parent is non-directory, non-root-owned, or writable")
		}
	}
	return current, filepath.Base(path), nil
}
