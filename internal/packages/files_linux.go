//go:build linux

package packages

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

const (
	FixedPackageTransactionRoot = "/var/lib/lanpanel/packages/transactions"
	FixedPackageStagingRoot     = "/var/lib/lanpanel/packages/staging"
)

type TransactionFiles struct {
	transactionRoot string
	stagingRoot     string
	strict          bool
}

func NewTransactionFiles() (*TransactionFiles, error) {
	for _, root := range []string{FixedPackageTransactionRoot, FixedPackageStagingRoot} {
		if err := validatePackageRootChain(root); err != nil {
			return nil, err
		}
	}
	return &TransactionFiles{transactionRoot: FixedPackageTransactionRoot, stagingRoot: FixedPackageStagingRoot, strict: true}, nil
}

func newTestTransactionFiles(transactionRoot, stagingRoot string) *TransactionFiles {
	return &TransactionFiles{transactionRoot: transactionRoot, stagingRoot: stagingRoot}
}

func (files *TransactionFiles) EnsureStaging(ctx context.Context, plan Plan) (string, error) {
	if files == nil || !filepath.IsAbs(files.stagingRoot) || ValidatePlan(plan) != nil {
		return "", fmt.Errorf("package staging directory authority is invalid")
	}
	rootFD, err := openPackageRoot(files.stagingRoot, files.strict)
	if err != nil {
		return "", err
	}
	defer unix.Close(rootFD)
	directoryFD, created, err := openOrCreateTransactionDirectory(rootFD, plan.TransactionID, files.strict)
	if err != nil {
		return "", err
	}
	defer unix.Close(directoryFD)
	if created {
		if err := unix.Fsync(rootFD); err != nil {
			return "", fmt.Errorf("sync package staging directory creation: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	expected := make([]string, 0, len(plan.Packages))
	for _, pkg := range plan.Packages {
		expected = append(expected, pkg.ArtifactDigest+".deb")
	}
	if err := requireExactDirectoryMembers(directoryFD, expected, true); err != nil {
		return "", err
	}
	return filepath.Join(files.stagingRoot, plan.TransactionID), nil
}

func (files *TransactionFiles) Prepare(ctx context.Context, plan Plan, config, sourceList []byte) error {
	if files == nil || !filepath.IsAbs(files.transactionRoot) || !filepath.IsAbs(files.stagingRoot) || len(config) == 0 || len(config) > 64<<10 || len(sourceList) > 64<<10 {
		return fmt.Errorf("package transaction file authority is invalid")
	}
	expectedConfig, expectedSources, err := RenderAPTConfiguration(plan)
	if err != nil || !bytes.Equal(config, expectedConfig) || !bytes.Equal(sourceList, expectedSources) {
		return fmt.Errorf("package transaction files differ from the exact Plan")
	}
	rootFD, err := openPackageRoot(files.transactionRoot, files.strict)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	transactionFD, created, err := openOrCreateTransactionDirectory(rootFD, plan.TransactionID, files.strict)
	if err != nil {
		return err
	}
	defer unix.Close(transactionFD)
	if created {
		if err := unix.Fsync(rootFD); err != nil {
			return fmt.Errorf("sync package transaction directory creation: %w", err)
		}
	}
	if err := requireExactDirectoryMembers(transactionFD, []string{"apt.conf", "archives", "auth.conf", "preferences", "sources.list"}, true); err != nil {
		return err
	}
	archivesFD, _, err := openOrCreateTransactionDirectory(transactionFD, "archives", files.strict)
	if err != nil {
		return err
	}
	if err := unix.Close(archivesFD); err != nil || unix.Fsync(transactionFD) != nil {
		return fmt.Errorf("sync package archive cache directory")
	}
	if err := putExactFile(ctx, transactionFD, "apt.conf", config, files.strict); err != nil {
		return err
	}
	if err := putExactFile(ctx, transactionFD, "auth.conf", []byte{}, files.strict); err != nil {
		return err
	}
	if err := putExactFile(ctx, transactionFD, "preferences", []byte{}, files.strict); err != nil {
		return err
	}
	if err := putExactFile(ctx, transactionFD, "sources.list", sourceList, files.strict); err != nil {
		return err
	}
	if err := requireExactDirectoryMembers(transactionFD, []string{"apt.conf", "archives", "auth.conf", "preferences", "sources.list"}, false); err != nil {
		return err
	}
	return nil
}

func (files *TransactionFiles) validateStagedClosure(ctx context.Context, plan Plan) error {
	rootFD, err := openPackageRoot(files.stagingRoot, files.strict)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	directoryFD, err := unix.Openat(rootFD, plan.TransactionID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open exact staged package closure: %w", err)
	}
	defer unix.Close(directoryFD)
	if err := validateOwnedDirectory(directoryFD, files.strict); err != nil {
		return err
	}
	expectedNames := make([]string, 0, len(plan.Packages))
	for _, pkg := range plan.Packages {
		expectedNames = append(expectedNames, pkg.ArtifactDigest+".deb")
	}
	slices.Sort(expectedNames)
	if err := requireExactDirectoryMembers(directoryFD, expectedNames, false); err != nil {
		return fmt.Errorf("staged package closure inventory: %w", err)
	}
	for _, name := range expectedNames {
		if err := ctx.Err(); err != nil {
			return err
		}
		var pkg Package
		for _, candidate := range plan.Packages {
			if candidate.ArtifactDigest+".deb" == name {
				pkg = candidate
				break
			}
		}
		if pkg.Name == "" {
			return fmt.Errorf("staged package identity is missing")
		}
		if err := validateStagedPackage(directoryFD, name, pkg, files.strict); err != nil {
			return err
		}
	}
	return nil
}

func openPackageRoot(path string, strict bool) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open fixed package root: %w", err)
	}
	if err := validateOwnedDirectory(fd, strict); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openOrCreateTransactionDirectory(rootFD int, name string, strict bool) (int, bool, error) {
	created := false
	if err := unix.Mkdirat(rootFD, name, 0o700); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return -1, false, fmt.Errorf("create package transaction directory: %w", err)
		}
	} else {
		created = true
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, created, fmt.Errorf("open package transaction directory: %w", err)
	}
	if err := validateOwnedDirectory(fd, strict); err != nil {
		_ = unix.Close(fd)
		return -1, created, err
	}
	return fd, created, nil
}

func validateOwnedDirectory(fd int, strict bool) error {
	var stat unix.Stat_t
	owner := uint32(0)
	if !strict {
		owner = uint32(os.Geteuid())
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner || stat.Gid != uint32(os.Getegid()) && !strict || strict && stat.Gid != 0 || stat.Mode&0o777 != 0o700 {
		return fmt.Errorf("package directory type, owner, group, or mode is unsafe")
	}
	return nil
}

func putExactFile(ctx context.Context, directoryFD int, name string, data []byte, strict bool) error {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		return verifyExactFile(ctx, directoryFD, name, data, strict)
	}
	if err != nil {
		return fmt.Errorf("create package transaction file: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("package transaction file descriptor is invalid")
	}
	defer file.Close()
	owner := 0
	if !strict {
		owner = os.Geteuid()
	}
	group := 0
	if !strict {
		group = os.Getegid()
	}
	if err := unix.Fchown(fd, owner, group); err != nil || unix.Fchmod(fd, 0o600) != nil {
		return fmt.Errorf("set package transaction file ownership")
	}
	for offset := 0; offset < len(data); {
		written, err := file.Write(data[offset:])
		if err != nil || written <= 0 {
			return fmt.Errorf("write package transaction file: %w", errors.Join(err, io.ErrShortWrite))
		}
		offset += written
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync package transaction file: %w", err)
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync package transaction directory: %w", err)
	}
	return verifyExactFD(fd, data, strict)
}

func verifyExactFile(ctx context.Context, directoryFD int, name string, expected []byte, strict bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open existing package transaction file: %w", err)
	}
	defer unix.Close(fd)
	return verifyExactFD(fd, expected, strict)
}

func verifyExactFD(fd int, expected []byte, strict bool) error {
	var stat unix.Stat_t
	owner := uint32(0)
	group := uint32(0)
	if !strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o777 != 0o600 || stat.Size != int64(len(expected)) {
		return fmt.Errorf("package transaction file identity is unsafe")
	}
	actual, err := readExactFD(fd, int64(len(expected))+1)
	if err != nil || !bytes.Equal(actual, expected) {
		return fmt.Errorf("package transaction file bytes changed")
	}
	return nil
}

func validateStagedPackage(directoryFD int, name string, pkg Package, strict bool) error {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open staged package no-follow: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	owner, group := uint32(0), uint32(0)
	if !strict {
		owner, group = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o777 != 0o600 || stat.Size != pkg.ArtifactBytes {
		return fmt.Errorf("staged package type, owner, mode, link, or size is unsafe")
	}
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		read, readErr := unix.Read(fd, buffer)
		if read > 0 {
			total += int64(read)
			if total > pkg.ArtifactBytes {
				return fmt.Errorf("staged package exceeds its exact size")
			}
			_, _ = hasher.Write(buffer[:read])
		}
		if readErr != nil {
			return fmt.Errorf("read staged package: %w", readErr)
		}
		if read == 0 {
			break
		}
	}
	var after unix.Stat_t
	if total != pkg.ArtifactBytes || hex.EncodeToString(hasher.Sum(nil)) != pkg.ArtifactDigest || unix.Fstat(fd, &after) != nil || after.Dev != stat.Dev || after.Ino != stat.Ino || after.Size != stat.Size || after.Mtim != stat.Mtim {
		return fmt.Errorf("staged package digest or opened identity changed")
	}
	return nil
}

func readExactFD(fd int, maximum int64) ([]byte, error) {
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		return nil, err
	}
	result := make([]byte, 0, min(maximum, 64<<10))
	buffer := make([]byte, 32<<10)
	for int64(len(result)) < maximum {
		remaining := maximum - int64(len(result))
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		read, err := unix.Read(fd, chunk)
		if read > 0 {
			result = append(result, chunk[:read]...)
		}
		if err != nil {
			return nil, err
		}
		if read == 0 {
			return result, nil
		}
	}
	return result, nil
}

func requireExactDirectoryMembers(directoryFD int, expected []string, allowMissing bool) error {
	path := fmt.Sprintf("/proc/self/fd/%d", directoryFD)
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("enumerate package transaction directory: %w", err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	slices.Sort(actual)
	expected = append([]string(nil), expected...)
	slices.Sort(expected)
	if allowMissing {
		for _, name := range actual {
			if !slices.Contains(expected, name) {
				return fmt.Errorf("package transaction directory contains an unexpected member")
			}
		}
		return nil
	}
	if !slices.Equal(actual, expected) {
		return fmt.Errorf("package transaction directory inventory is incomplete or unexpected")
	}
	return nil
}

func validatePackageRootChain(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("fixed package root path is invalid")
	}
	for current := path; ; current = filepath.Dir(current) {
		var stat unix.Stat_t
		if err := unix.Lstat(current, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o022 != 0 {
			return fmt.Errorf("fixed package root parent is linked, non-directory, non-root-owned, or writable")
		}
		if current == "/" {
			return nil
		}
	}
}
