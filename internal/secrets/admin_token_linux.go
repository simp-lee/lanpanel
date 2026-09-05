//go:build linux

package secrets

import (
	"crypto/rand"
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

const (
	AdminTokenPath = "/var/lib/lanpanel/installation/admin-token"
	tokenBytes     = 64
	candidateName  = ".admin-token.rotate"
)

type AdminTokenOptions struct {
	Random              io.Reader
	ExpectedFingerprint string
	Fault               func(string) error
}
type AdminTokenCommit struct {
	Fingerprint string
	Value       *Value
	Prepared    bool
}

func GenerateAdminToken(options AdminTokenOptions) (*Value, error) {
	reader := options.Random
	if reader == nil {
		reader = rand.Reader
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return nil, fmt.Errorf("generate admin token")
	}
	encoded := []byte(hex.EncodeToString(raw))
	clear(raw)
	if options.Fault != nil {
		if err := options.Fault("generated"); err != nil {
			clear(encoded)
			return nil, err
		}
	}
	value, err := New(encoded)
	clear(encoded)
	return value, err
}

// CommitAdminToken atomically exchanges the new source into place while
// retaining the exact old source at candidateName. The caller must durably mark
// the operation committed before FinalizeAdminToken removes that recovery copy.
func CommitAdminToken(value *Value, options AdminTokenOptions) (AdminTokenCommit, error) {
	var encoded []byte
	if err := value.Use(func(secret []byte) error { encoded = append([]byte(nil), secret...); return nil }); err != nil {
		return AdminTokenCommit{}, err
	}
	defer clear(encoded)
	if options.ExpectedFingerprint == "" {
		return AdminTokenCommit{}, fmt.Errorf("admin token expected source is missing")
	}
	return prepareAdminToken(encoded, options)
}

func prepareAdminToken(encoded []byte, options AdminTokenOptions) (AdminTokenCommit, error) {
	if len(encoded) != tokenBytes {
		return AdminTokenCommit{}, fmt.Errorf("admin token candidate invalid")
	}
	parentFD, oldFD, oldStat, err := openAdminToken(filepath.Dir(AdminTokenPath))
	if err != nil {
		return AdminTokenCommit{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	defer func() { _ = unix.Close(oldFD) }()
	if _, err := readCandidate(parentFD); err == nil {
		return AdminTokenCommit{}, fmt.Errorf("admin token recovery candidate already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return AdminTokenCommit{}, err
	}
	fd, err := unix.Openat(parentFD, candidateName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return AdminTokenCommit{}, err
	}
	if err := writeFull(fd, encoded); err != nil {
		_ = unix.Close(fd)
		_ = removeCandidate(parentFD)
		return AdminTokenCommit{}, err
	}
	if unix.Fsync(fd) != nil {
		_ = unix.Close(fd)
		_ = removeCandidate(parentFD)
		return AdminTokenCommit{}, fmt.Errorf("sync admin token candidate")
	}
	if err := unix.Close(fd); err != nil {
		_ = removeCandidate(parentFD)
		return AdminTokenCommit{}, err
	}
	if options.Fault != nil {
		if err := options.Fault("synced"); err != nil {
			_ = removeCandidate(parentFD)
			return AdminTokenCommit{}, err
		}
	}
	var fresh unix.Stat_t
	if unix.Fstat(oldFD, &fresh) != nil || fresh.Dev != oldStat.Dev || fresh.Ino != oldStat.Ino || fresh.Size != oldStat.Size || fresh.Mtim != oldStat.Mtim || fresh.Ctim != oldStat.Ctim {
		_ = removeCandidate(parentFD)
		return AdminTokenCommit{}, fmt.Errorf("admin token source changed")
	}
	oldValue, err := readFD(oldFD)
	if err != nil {
		_ = removeCandidate(parentFD)
		return AdminTokenCommit{}, err
	}
	oldFingerprint := digest(oldValue)
	clear(oldValue)
	if oldFingerprint != options.ExpectedFingerprint {
		_ = removeCandidate(parentFD)
		return AdminTokenCommit{}, fmt.Errorf("admin token source differs from Plan")
	}
	if err := unix.Renameat2(parentFD, candidateName, parentFD, filepath.Base(AdminTokenPath), unix.RENAME_EXCHANGE); err != nil {
		_ = removeCandidate(parentFD)
		return AdminTokenCommit{}, err
	}
	fingerprint := digest(encoded)
	rollback := func(cause error) (AdminTokenCommit, error) {
		if exchangeErr := unix.Renameat2(parentFD, candidateName, parentFD, filepath.Base(AdminTokenPath), unix.RENAME_EXCHANGE); exchangeErr != nil {
			return AdminTokenCommit{Fingerprint: fingerprint, Prepared: true}, fmt.Errorf("%v; restore old admin token: %w", cause, exchangeErr)
		}
		if cleanupErr := removeCandidate(parentFD); cleanupErr != nil {
			return AdminTokenCommit{}, fmt.Errorf("%v; cleanup restored candidate: %w", cause, cleanupErr)
		}
		return AdminTokenCommit{}, cause
	}
	if err := unix.Fsync(parentFD); err != nil {
		return rollback(fmt.Errorf("sync prepared admin token exchange"))
	}
	current, err := readAdminToken(parentFD)
	if err != nil {
		return rollback(err)
	}
	matches := string(current) == string(encoded)
	clear(current)
	if !matches {
		return rollback(fmt.Errorf("prepared admin token readback mismatched"))
	}
	result, err := New(encoded)
	if err != nil {
		return rollback(err)
	}
	return AdminTokenCommit{Fingerprint: fingerprint, Value: result, Prepared: true}, nil
}

func FinalizeAdminToken(expectedOldFingerprint, expectedNewFingerprint string) error {
	parentFD, oldFD, _, err := openAdminToken(filepath.Dir(AdminTokenPath))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	defer func() { _ = unix.Close(oldFD) }()
	current, err := readFD(oldFD)
	if err != nil {
		return err
	}
	currentFingerprint := digest(current)
	clear(current)
	candidate, err := readCandidate(parentFD)
	if err != nil {
		return err
	}
	candidateFingerprint := digest(candidate)
	clear(candidate)
	if currentFingerprint != expectedNewFingerprint || candidateFingerprint != expectedOldFingerprint {
		return fmt.Errorf("admin token finalize authority mismatched")
	}
	return removeCandidate(parentFD)
}

func RestorePreparedAdminToken(expectedOldFingerprint, expectedNewFingerprint string) error {
	parentFD, oldFD, _, err := openAdminToken(filepath.Dir(AdminTokenPath))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	defer func() { _ = unix.Close(oldFD) }()
	current, err := readFD(oldFD)
	if err != nil {
		return err
	}
	currentFingerprint := digest(current)
	clear(current)
	candidate, err := readCandidate(parentFD)
	if err != nil {
		return err
	}
	candidateFingerprint := digest(candidate)
	clear(candidate)
	if currentFingerprint != expectedNewFingerprint || candidateFingerprint != expectedOldFingerprint {
		return fmt.Errorf("admin token restore authority mismatched")
	}
	if err := unix.Renameat2(parentFD, candidateName, parentFD, filepath.Base(AdminTokenPath), unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	return removeCandidate(parentFD)
}

func ReconcileAdminTokenCandidate(priorFingerprint, candidateFingerprint, currentFingerprint string, committed bool) error {
	if priorFingerprint == "" || candidateFingerprint == "" || currentFingerprint == "" {
		return fmt.Errorf("admin token recovery authority is incomplete")
	}
	parentFD, oldFD, _, err := openAdminToken(filepath.Dir(AdminTokenPath))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	defer func() { _ = unix.Close(oldFD) }()
	candidate, candidateErr := readCandidate(parentFD)
	candidateAbsent := errors.Is(candidateErr, os.ErrNotExist)
	candidateDigest := ""
	if candidateErr == nil {
		candidateDigest = digest(candidate)
		clear(candidate)
	} else if !candidateAbsent {
		return candidateErr
	}
	if committed {
		if currentFingerprint != candidateFingerprint {
			return fmt.Errorf("committed admin token source mismatched")
		}
		if candidateAbsent {
			return nil
		}
		if candidateDigest != priorFingerprint {
			return fmt.Errorf("committed admin token recovery copy mismatched")
		}
		return removeCandidate(parentFD)
	}
	if currentFingerprint == priorFingerprint {
		if candidateAbsent {
			return nil
		}
		if candidateDigest != candidateFingerprint {
			return fmt.Errorf("admin token recovery candidate is foreign")
		}
		return removeCandidate(parentFD)
	}
	if currentFingerprint == candidateFingerprint {
		if candidateAbsent || candidateDigest != priorFingerprint {
			return fmt.Errorf("prepared admin token recovery copy mismatched")
		}
		return RestorePreparedAdminToken(priorFingerprint, candidateFingerprint)
	}
	return fmt.Errorf("admin token recovery source and candidate conflict")
}

func removeCandidate(parentFD int) error {
	if err := unix.Unlinkat(parentFD, candidateName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync admin token candidate cleanup")
	}
	return nil
}

func RequireNoAdminTokenCandidate() error {
	parentFD, oldFD, _, err := openAdminToken(filepath.Dir(AdminTokenPath))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	defer func() { _ = unix.Close(oldFD) }()
	candidate, err := readCandidate(parentFD)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	clear(candidate)
	if err != nil {
		return err
	}
	return fmt.Errorf("orphan admin token recovery candidate exists")
}

// KnownHostSecretDigests returns the current admin-token digest together with
// digests of other protected sources already recorded by the authoritative
// installation state. Callers supply those non-admin fingerprints because the
// secret package deliberately does not decode application state.
func KnownHostSecretDigests(additional ...string) (map[string]struct{}, error) {
	parentFD, oldFD, before, err := openAdminToken(filepath.Dir(AdminTokenPath))
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	defer func() { _ = unix.Close(oldFD) }()
	data, err := readFD(oldFD)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var after unix.Stat_t
	if unix.Fstat(oldFD, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mode != before.Mode || after.Uid != before.Uid || after.Gid != before.Gid || after.Nlink != before.Nlink || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return nil, fmt.Errorf("admin token source changed while reading")
	}
	result := map[string]struct{}{digest(data): {}}
	for _, value := range additional {
		if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
			return nil, fmt.Errorf("known protected secret fingerprint is invalid")
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:")); err != nil {
			return nil, fmt.Errorf("known protected secret fingerprint is invalid")
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func CurrentAdminTokenFingerprint() (string, error) {
	parentFD, oldFD, _, err := openAdminToken(filepath.Dir(AdminTokenPath))
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(parentFD) }()
	defer func() { _ = unix.Close(oldFD) }()
	data, err := readFD(oldFD)
	if err != nil {
		return "", err
	}
	defer clear(data)
	return digest(data), nil
}

func openAdminToken(parent string) (int, int, unix.Stat_t, error) {
	if parent != "/var/lib/lanpanel/installation" {
		return -1, -1, unix.Stat_t{}, fmt.Errorf("admin token parent is not fixed")
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, -1, unix.Stat_t{}, err
	}
	var p unix.Stat_t
	if unix.Fstat(parentFD, &p) != nil || p.Mode&unix.S_IFMT != unix.S_IFDIR || p.Uid != 0 || p.Gid != 0 || p.Mode&0o777 != 0o711 {
		_ = unix.Close(parentFD)
		return -1, -1, unix.Stat_t{}, fmt.Errorf("admin token parent is unsafe")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(AdminTokenPath), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = unix.Close(parentFD)
		return -1, -1, unix.Stat_t{}, err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Size != tokenBytes {
		_ = unix.Close(fd)
		_ = unix.Close(parentFD)
		return -1, -1, unix.Stat_t{}, fmt.Errorf("admin token source is unsafe")
	}
	return parentFD, fd, stat, nil
}

func readAdminToken(parentFD int) ([]byte, error) {
	fd, err := unix.Openat(parentFD, filepath.Base(AdminTokenPath), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Size != tokenBytes {
		return nil, fmt.Errorf("admin token source is unsafe")
	}
	return readFD(fd)
}

func readCandidate(parentFD int) ([]byte, error) {
	fd, err := unix.Openat(parentFD, candidateName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Size != tokenBytes {
		return nil, fmt.Errorf("admin token recovery candidate is unsafe")
	}
	return readFD(fd)
}

func readFD(fd int) ([]byte, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	reader := os.NewFile(uintptr(duplicate), "admin-token-read")
	if reader == nil {
		_ = unix.Close(duplicate)
		return nil, fmt.Errorf("admin token reader invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(reader.Close)
	data, err := io.ReadAll(io.LimitReader(reader, tokenBytes+1))
	if err != nil || len(data) != tokenBytes {
		return nil, fmt.Errorf("read admin token")
	}
	if _, err := hex.DecodeString(string(data)); err != nil || strings.ToLower(string(data)) != string(data) {
		clear(data)
		return nil, fmt.Errorf("admin token encoding invalid")
	}
	return data, nil
}

func writeFull(fd int, value []byte) error {
	for len(value) > 0 {
		written, err := unix.Write(fd, value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
