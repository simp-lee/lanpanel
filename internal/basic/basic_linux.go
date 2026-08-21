//go:build linux

package basic

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/htpasswdref"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const FixedRoot = "/etc/lanpanel-public/basic"

type Generated struct {
	Username    string
	Password    []byte
	Record      []byte
	Fingerprint string
}
type runner interface {
	RunInvocation(context.Context, child.ProfileID, child.Invocation, []byte) (child.Result, error)
}

func NewPassword() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	password := make([]byte, base64.RawURLEncoding.EncodedLen(len(secret)))
	base64.RawURLEncoding.Encode(password, secret)
	clear(secret)
	return password, nil
}

func Hash(ctx context.Context, launcher runner, username string, password []byte) (Generated, error) {
	if launcher == nil || !htpasswdref.ValidUsername(username) || len(password) == 0 || len(password) > 71 {
		return Generated{}, fmt.Errorf("managed Basic generation authority invalid")
	}
	input := append(append([]byte(nil), password...), '\n')
	defer clear(input)
	result, err := launcher.RunInvocation(ctx, child.ProfileHTPasswd, child.Invocation{HTPasswd: &child.HTPasswdInvocation{Username: username, Cost: htpasswdref.FixedCost}}, input)
	defer clear(result.Stdout)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff || result.StderrDigest != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return Generated{}, fmt.Errorf("htpasswd child failed with redacted result: %w", err)
	}
	record := result.Stdout
	if len(record) == 0 || len(record) > 256 {
		return Generated{}, fmt.Errorf("htpasswd output invalid")
	}
	trimmed := strings.TrimRight(string(record), "\r\n")
	if strings.ContainsAny(trimmed, "\r\n") {
		return Generated{}, fmt.Errorf("htpasswd output authority changed")
	}
	outputUsername, encoded, found := strings.Cut(trimmed, ":")
	if !found || outputUsername != username || !htpasswdref.ValidateRecord(outputUsername, encoded) {
		return Generated{}, fmt.Errorf("htpasswd output authority changed")
	}
	canonical := []byte(trimmed + "\n")
	sum := sha256.Sum256(canonical)
	return Generated{Username: username, Record: canonical, Fingerprint: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func Generate(ctx context.Context, launcher runner, username string) (Generated, error) {
	password, err := NewPassword()
	if err != nil {
		return Generated{}, err
	}
	generated, err := Hash(ctx, launcher, username, password)
	if err != nil {
		clear(password)
		return Generated{}, err
	}
	generated.Password = password
	return generated, nil
}
func Path(credentialID string) string { return filepath.Join(FixedRoot, credentialID+".htpasswd") }
func Store(ctx context.Context, credentialID string, record []byte, nginxGID uint32) (string, error) {
	if len(credentialID) != 37 || !strings.HasPrefix(credentialID, "cred_") || len(record) == 0 || nginxGID == 0 {
		return "", fmt.Errorf("managed Basic storage identity invalid")
	}
	if err := ensureRoot(nginxGID); err != nil {
		return "", err
	}
	path := Path(credentialID)
	txn, err := filetxn.Open(filetxn.Config{RootPath: FixedRoot, Root: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: nginxGID}, Mode: 0o750}, StagingPath: filepath.Join(FixedRoot, ".txn"), Staging: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{{UID: 0, GID: 0}}, AllowedMode: 0o700}}, filetxn.Options{})
	if err != nil {
		return "", err
	}
	defer func(ignore func() error) { _ = ignore() }(txn.Close)
	metadata := filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: nginxGID}, Mode: 0o640}
	mode := filetxn.CreateOnly
	if _, err := os.Lstat(path); err == nil {
		mode = filetxn.ReplaceOnly
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	result, err := txn.Put(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{{UID: 0, GID: nginxGID}}, AllowedMode: 0o750}, Existing: &metadata, New: metadata, MaxBytes: 256}, record, mode)
	if err != nil || result.State != filetxn.StateDurable {
		return "", fmt.Errorf("managed Basic commit failed: %w", err)
	}
	return path, nil
}

func Delete(ctx context.Context, credentialID string, nginxGID uint32) error {
	if len(credentialID) != 37 || !strings.HasPrefix(credentialID, "cred_") || nginxGID == 0 {
		return fmt.Errorf("managed Basic delete identity invalid")
	}
	if err := ensureRoot(nginxGID); err != nil {
		return err
	}
	path := Path(credentialID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("managed Basic delete source unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != nginxGID || info.Mode().Perm() != 0o640 {
		return fmt.Errorf("managed Basic delete owner changed")
	}
	txn, err := filetxn.Open(filetxn.Config{RootPath: FixedRoot, Root: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: nginxGID}, Mode: 0o750}, StagingPath: filepath.Join(FixedRoot, ".txn"), Staging: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{{UID: 0, GID: 0}}, AllowedMode: 0o700}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(txn.Close)
	metadata := filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: nginxGID}, Mode: 0o640}
	result, err := txn.Remove(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{{UID: 0, GID: nginxGID}}, AllowedMode: 0o750}, Existing: &metadata})
	if err != nil || result.State != filetxn.StateDurable {
		return fmt.Errorf("managed Basic delete failed: %w", err)
	}
	return nil
}

func ensureRoot(gid uint32) error {
	etc, err := unix.Open("/etc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(etc) }()
	var etcStat unix.Stat_t
	if unix.Fstat(etc, &etcStat) != nil || etcStat.Mode&unix.S_IFMT != unix.S_IFDIR || etcStat.Uid != 0 || etcStat.Mode&0o022 != 0 {
		return fmt.Errorf("managed Basic /etc authority unsafe")
	}
	parent, err := ensureBasicDirectory(etc, "lanpanel-public", gid)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	child, err := ensureBasicDirectory(parent, "basic", gid)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(child) }()
	staging, err := ensureOwnedBasicDirectory(child, ".txn", 0, 0, 0o700)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(staging) }()
	return errors.Join(unix.Fsync(staging), unix.Fsync(child), unix.Fsync(parent), unix.Fsync(etc))
}

func ensureBasicDirectory(parent int, name string, gid uint32) (int, error) {
	return ensureOwnedBasicDirectory(parent, name, 0, gid, 0o750)
}

func ensureOwnedBasicDirectory(parent int, name string, uid, gid uint32, mode uint32) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	created := false
	if errors.Is(err, unix.ENOENT) {
		if err = unix.Mkdirat(parent, name, mode); err != nil {
			return -1, err
		}
		created = true
		fd, err = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return -1, err
	}
	if created {
		if err = unix.Fchown(fd, int(uid), int(gid)); err == nil {
			err = unix.Fchmod(fd, mode)
		}
		if err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("managed Basic directory identity differs")
	}
	return fd, nil
}
