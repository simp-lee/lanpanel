//go:build linux

package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const Path = "/var/lib/lanpanel-management-audit/events.json"

const maximumFileBytes = 256 << 10

type FileSink struct {
	mu   sync.Mutex
	path string
}

func NewFileSink(path string) (*FileSink, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, fmt.Errorf("audit path is invalid")
	}
	return &FileSink{path: path}, nil
}

func (sink *FileSink) Append(record Record) error {
	if sink == nil {
		return fmt.Errorf("audit sink is unavailable")
	}
	if err := validate(record); err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if err := validateAuditPath(sink.path); err != nil {
		return err
	}
	directory, err := openAuditDirectory(filepath.Dir(sink.path))
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	base := filepath.Base(sink.path)
	records, err := readAuditRecords(directory, base)
	if err != nil {
		return err
	}
	records = append(records, record)
	if len(records) > MaximumRecords {
		records = records[len(records)-MaximumRecords:]
	}
	data, err := json.Marshal(records)
	if err != nil || len(data) > maximumFileBytes {
		return fmt.Errorf("audit store cannot be encoded")
	}
	return replaceAuditFile(directory, base, data)
}

func openAuditDirectory(path string) (int, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("audit parent is invalid")
	}
	components := stringsSplitPath(path)
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range components {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 && stat.Mode&0o1000 == 0 && (stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid())) {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("audit parent is unsafe")
		}
	}
	return fd, nil
}

func stringsSplitPath(path string) []string {
	return splitNonEmpty(filepath.ToSlash(path), "/")
}

func splitNonEmpty(value, separator string) []string {
	parts := []string{}
	for _, part := range strings.Split(value, separator) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func readAuditRecords(directory int, base string) ([]Record, error) {
	fd, err := unix.Openat(directory, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uint32(os.Getuid()) || before.Gid != uint32(os.Getgid()) || before.Mode&0o777 != 0o600 || before.Size <= 0 || before.Size > maximumFileBytes {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("audit file is unsafe")
	}
	file := os.NewFile(uintptr(fd), base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("audit file descriptor is invalid")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumFileBytes+1))
	var after unix.Stat_t
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || int64(len(data)) != before.Size || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		clear(data)
		return nil, fmt.Errorf("audit file changed while reading")
	}
	defer clear(data)
	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("audit store is malformed")
	}
	if len(records) > MaximumRecords {
		return nil, fmt.Errorf("audit store exceeds record bound")
	}
	for _, value := range records {
		if err := validate(value); err != nil {
			return nil, fmt.Errorf("audit store record is invalid")
		}
	}
	return records, nil
}

func replaceAuditFile(directory int, base string, data []byte) error {
	var random [8]byte
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		name := ".audit-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(directory, name, 0)
			return fmt.Errorf("audit temporary descriptor is invalid")
		}
		writeErr := error(nil)
		if _, writeErr = file.Write(data); writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			_ = unix.Unlinkat(directory, name, 0)
			return errors.Join(writeErr, closeErr)
		}
		if err := unix.Renameat(directory, name, directory, base); err != nil {
			_ = unix.Unlinkat(directory, name, 0)
			return err
		}
		return unix.Fsync(directory)
	}
	return fmt.Errorf("audit temporary name allocation failed")
}

func validateAuditPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." {
		return fmt.Errorf("audit path is invalid")
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
			return fmt.Errorf("audit file is unsafe")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func validate(record Record) error {
	if record.Operation == "" || record.Target == "" || record.Actor == "" || record.At.IsZero() || record.Result == "" || len(record.Paths) > 8192 || len(record.ErrorCode) > 64 {
		return fmt.Errorf("audit record is invalid")
	}
	return nil
}
