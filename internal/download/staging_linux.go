//go:build linux

package download

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type StagingFile struct {
	file        *os.File
	path        string
	maximum     int64
	written     int64
	uid, gid    uint32
	directoryFD int
}

func CreateStaging(directory, name string, uid, gid uint32, maximum int64) (*StagingFile, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, "\x00/\\\r\n") || maximum <= 0 || maximum > 4<<30 {
		return nil, fmt.Errorf("download staging identity or bound is invalid")
	}
	directoryFD, err := openRootOwnedDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("open download staging directory")
	}
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil || directoryStat.Uid != 0 || directoryStat.Mode&0o777 != 0o700 {
		_ = unix.Close(directoryFD)
		return nil, fmt.Errorf("download staging directory is not root-owned mode 0700")
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		_ = unix.Close(directoryFD)
		return nil, fmt.Errorf("create exclusive download staging file")
	}
	fail := func() (*StagingFile, error) {
		_ = unix.Close(fd)
		_ = unix.Close(directoryFD)
		return nil, fmt.Errorf("initialize download staging file")
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil || unix.Fchmod(fd, 0o600) != nil || unix.Fsync(directoryFD) != nil {
		return fail()
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		return fail()
	}
	return &StagingFile{file: file, path: filepath.Join(directory, name), maximum: maximum, uid: uid, gid: gid, directoryFD: directoryFD}, nil
}

func (staging *StagingFile) Write(data []byte) (int, error) {
	if staging == nil || staging.file == nil || staging.written+int64(len(data)) > staging.maximum {
		return 0, fmt.Errorf("download staging write exceeds its fixed bound")
	}
	written, err := staging.file.Write(data)
	staging.written += int64(written)
	return written, err
}

func (staging *StagingFile) CloseVerified(expectedDigest string, expectedBytes int64) (string, error) {
	if staging == nil || staging.file == nil || expectedBytes <= 0 || expectedBytes != staging.written || len(expectedDigest) != 64 {
		return "", fmt.Errorf("download staging verification identity is invalid")
	}
	file := staging.file
	staging.file = nil
	defer staging.closeDirectory()
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync download staging file")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return "", err
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, io.LimitReader(file, staging.maximum+1))
	if err != nil || read != expectedBytes || hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		_ = file.Close()
		return "", fmt.Errorf("reread download staging identity mismatch")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != staging.uid || stat.Gid != staging.gid || stat.Mode&0o777 != 0o600 || stat.Size != expectedBytes {
		_ = file.Close()
		return "", fmt.Errorf("download staging type, owner, mode, link, or size changed")
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := unix.Fsync(staging.directoryFD); err != nil {
		return "", fmt.Errorf("sync download staging directory: %w", err)
	}
	return staging.path, nil
}

func (staging *StagingFile) Close() error {
	if staging == nil {
		return nil
	}
	var err error
	if staging.file != nil {
		err = staging.file.Close()
		staging.file = nil
	}
	return errors.Join(err, staging.closeDirectory())
}

func (staging *StagingFile) closeDirectory() error {
	if staging == nil || staging.directoryFD < 0 {
		return nil
	}
	err := unix.Close(staging.directoryFD)
	staging.directoryFD = -1
	return err
}

func openRootOwnedDirectory(value string) (int, error) {
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	relative := strings.TrimPrefix(value, "/")
	if relative == "" {
		return current, nil
	}
	for _, component := range strings.Split(relative, "/") {
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, fmt.Errorf("open download staging parent no-follow: %w", openErr)
		}
		current = next
		var stat unix.Stat_t
		if err := unix.Fstat(current, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			_ = unix.Close(current)
			return -1, fmt.Errorf("download staging parent is non-directory, non-root-owned, or writable")
		}
	}
	return current, nil
}
