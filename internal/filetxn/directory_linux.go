//go:build linux

package filetxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const MaximumDirectoryMembers = 64

type DirectoryMember struct {
	Name    string
	Data    []byte
	Owner   Owner
	Mode    os.FileMode
	Maximum int64
}

type DirectoryRequest struct {
	ParentPath string
	Parent     Metadata
	TargetName string
	Directory  Metadata
	Members    []DirectoryMember
}

type DirectoryIdentity struct {
	Path   string
	Device uint64
	Inode  uint64
	Digest string
}

// CommitNewDirectory creates an exact flat owner-only staging bundle and then
// commits the whole directory with one no-replace rename.
func CommitNewDirectory(ctx context.Context, request DirectoryRequest) (DirectoryIdentity, error) {
	if err := validateDirectoryRequest(request); err != nil {
		return DirectoryIdentity{}, err
	}
	parentFD, parentStat, err := openAbsoluteDirectory(request.ParentPath)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if err := validateDirectoryMetadata(parentStat, request.Parent); err != nil {
		return DirectoryIdentity{}, err
	}
	if targetExists(parentFD, request.TargetName) {
		return DirectoryIdentity{}, os.ErrExist
	}
	stagingName := "." + request.TargetName + ".lanpanel-staging"
	if existing, err := unix.Openat(parentFD, stagingName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
		if removeErr := removeExactPartialStaging(existing, parentFD, stagingName, request); removeErr != nil {
			_ = unix.Close(existing)
			return DirectoryIdentity{}, removeErr
		}
		_ = unix.Close(existing)
	} else if !errors.Is(err, unix.ENOENT) {
		return DirectoryIdentity{}, err
	}
	if err := unix.Mkdirat(parentFD, stagingName, uint32(request.Directory.Mode.Perm())); err != nil {
		return DirectoryIdentity{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removeExactStaging(parentFD, stagingName, request)
		}
	}()
	stagingFD, err := unix.Openat(parentFD, stagingName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	defer func() { _ = unix.Close(stagingFD) }()
	if err := unix.Fchown(stagingFD, int(request.Directory.Owner.UID), int(request.Directory.Owner.GID)); err != nil || unix.Fchmod(stagingFD, uint32(request.Directory.Mode.Perm())) != nil {
		return DirectoryIdentity{}, fmt.Errorf("set bundle staging directory metadata")
	}
	for _, member := range request.Members {
		if err := ctx.Err(); err != nil {
			return DirectoryIdentity{}, err
		}
		fd, err := unix.Openat(stagingFD, member.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(member.Mode.Perm()))
		if err != nil {
			return DirectoryIdentity{}, err
		}
		writeErr := writeAll(fd, member.Data)
		metadataErr := applyMetadata(fd, Metadata{Owner: member.Owner, Mode: member.Mode})
		syncErr := unix.Fsync(fd)
		closeErr := unix.Close(fd)
		if err := errors.Join(writeErr, metadataErr, syncErr, closeErr); err != nil {
			return DirectoryIdentity{}, err
		}
	}
	if err := unix.Fsync(stagingFD); err != nil {
		return DirectoryIdentity{}, err
	}
	identity, err := verifyDirectoryFD(stagingFD, filepath.Join(request.ParentPath, stagingName), request)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return DirectoryIdentity{}, err
	}
	if targetExists(parentFD, request.TargetName) {
		return DirectoryIdentity{}, os.ErrExist
	}
	if err := unix.Renameat2(parentFD, stagingName, parentFD, request.TargetName, unix.RENAME_NOREPLACE); err != nil {
		return DirectoryIdentity{}, err
	}
	cleanup = false
	if err := unix.Fsync(parentFD); err != nil {
		return DirectoryIdentity{}, fmt.Errorf("bundle namespace changed but parent sync failed: %w", err)
	}
	committedFD, err := unix.Openat(parentFD, request.TargetName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	defer func() { _ = unix.Close(committedFD) }()
	committed, err := verifyDirectoryFD(committedFD, filepath.Join(request.ParentPath, request.TargetName), request)
	if err != nil || committed.Device != identity.Device || committed.Inode != identity.Inode || committed.Digest != identity.Digest {
		return DirectoryIdentity{}, fmt.Errorf("committed directory bundle identity changed")
	}
	return committed, nil
}

func VerifyDirectory(request DirectoryRequest) (DirectoryIdentity, error) {
	if err := validateDirectoryRequest(request); err != nil {
		return DirectoryIdentity{}, err
	}
	parentFD, parentStat, err := openAbsoluteDirectory(request.ParentPath)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if err := validateDirectoryMetadata(parentStat, request.Parent); err != nil {
		return DirectoryIdentity{}, err
	}
	fd, err := unix.Openat(parentFD, request.TargetName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	return verifyDirectoryFD(fd, filepath.Join(request.ParentPath, request.TargetName), request)
}

func verifyDirectoryFD(fd int, path string, request DirectoryRequest) (DirectoryIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return DirectoryIdentity{}, err
	}
	if err := validateDirectoryMetadata(stat, request.Directory); err != nil || stat.Dev == 0 || stat.Ino == 0 {
		return DirectoryIdentity{}, fmt.Errorf("directory bundle metadata is unsafe: %w", err)
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return DirectoryIdentity{}, err
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	expected := make([]string, len(request.Members))
	for index, member := range request.Members {
		expected[index] = member.Name
	}
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		return DirectoryIdentity{}, fmt.Errorf("directory bundle inventory is incomplete or contains foreign members")
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "lanpanel.directory-bundle.v1\n")
	for _, member := range request.Members {
		child, err := unix.Openat(fd, member.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return DirectoryIdentity{}, err
		}
		var before, after unix.Stat_t
		if err := unix.Fstat(child, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != member.Owner.UID || before.Gid != member.Owner.GID || before.Mode&0o7777 != uint32(member.Mode.Perm()) || before.Size != int64(len(member.Data)) || before.Size > member.Maximum {
			_ = unix.Close(child)
			return DirectoryIdentity{}, fmt.Errorf("directory member %q metadata is unsafe", member.Name)
		}
		file := os.NewFile(uintptr(child), member.Name)
		data, readErr := io.ReadAll(io.LimitReader(file, member.Maximum+1))
		statErr := unix.Fstat(child, &after)
		closeErr := file.Close()
		if readErr != nil || statErr != nil || closeErr != nil || !bytes.Equal(data, member.Data) || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
			return DirectoryIdentity{}, fmt.Errorf("directory member %q changed or differs", member.Name)
		}
		_, _ = fmt.Fprintf(hasher, "%d:%s:%04o:%d:", len(member.Name), member.Name, member.Mode.Perm(), len(data))
		_, _ = hasher.Write(data)
	}
	return DirectoryIdentity{Path: path, Device: uint64(stat.Dev), Inode: stat.Ino, Digest: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func removeExactPartialStaging(fd, parentFD int, name string, request DirectoryRequest) error {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	allowed := map[string]DirectoryMember{}
	for _, member := range request.Members {
		allowed[member.Name] = member
	}
	for _, entry := range entries {
		member, ok := allowed[entry.Name()]
		if !ok || entry.IsDir() {
			return fmt.Errorf("partial directory staging contains foreign member")
		}
		child, err := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		if unix.Fstat(child, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != member.Owner.UID || stat.Gid != member.Owner.GID || stat.Mode&0o7777 != uint32(member.Mode.Perm()) {
			_ = unix.Close(child)
			return fmt.Errorf("partial directory staging member is unsafe")
		}
		_ = unix.Close(child)
		if err := unix.Unlinkat(fd, entry.Name(), 0); err != nil {
			return err
		}
	}
	if unix.Fsync(fd) != nil {
		return fmt.Errorf("sync partial staging cleanup")
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func removeExactStaging(parentFD int, name string, request DirectoryRequest) error {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if _, err := verifyDirectoryFD(fd, "", request); err != nil {
		return err
	}
	for _, member := range request.Members {
		if err := unix.Unlinkat(fd, member.Name, 0); err != nil {
			return err
		}
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Fsync(parentFD)
}

func validateDirectoryRequest(request DirectoryRequest) error {
	if err := validateAbsolutePath(request.ParentPath); err != nil {
		return err
	}
	if request.TargetName == "" || strings.ContainsAny(request.TargetName, "/\\\x00\r\n") || filepath.Base(request.TargetName) != request.TargetName || request.TargetName == "." || request.TargetName == ".." || validateMetadata(request.Parent) != nil || validateMetadata(request.Directory) != nil || request.Directory.Mode.Perm() != 0o700 && request.Directory.Mode.Perm() != 0o711 || len(request.Members) == 0 || len(request.Members) > MaximumDirectoryMembers {
		return fmt.Errorf("directory bundle request is invalid")
	}
	previous := ""
	for _, member := range request.Members {
		if member.Name == "" || filepath.Base(member.Name) != member.Name || strings.ContainsAny(member.Name, "/\\\x00\r\n") || previous != "" && previous >= member.Name || validateMetadata(Metadata{Owner: member.Owner, Mode: member.Mode}) != nil || member.Maximum <= 0 || member.Maximum > MaximumContentBytes || len(member.Data) == 0 || int64(len(member.Data)) > member.Maximum {
			return fmt.Errorf("directory bundle member is invalid, duplicated, or unsorted")
		}
		previous = member.Name
	}
	return nil
}

func targetExists(parentFD int, name string) bool {
	var stat unix.Stat_t
	return unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW) == nil
}
