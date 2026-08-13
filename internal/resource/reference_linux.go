//go:build linux

package resource

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumEnvironmentBytes = 64 << 10

type ReferenceEvidence struct {
	ExecutableDigest         string
	WorkingDirectoryIdentity string
	EnvironmentFingerprint   string
	WritePathIdentities      []string
}

func ValidateServiceReferences(service domain.ManagedService, processUID uint32, knownSecretDigests map[string]struct{}) (ReferenceEvidence, error) {
	if processUID == 0 {
		return ReferenceEvidence{}, fmt.Errorf("managed process identity must be non-root")
	}
	if err := ValidateArguments(service.Arguments, knownSecretDigests); err != nil {
		return ReferenceEvidence{}, err
	}
	executable, err := openExternal(service.Executable, false)
	if err != nil {
		return ReferenceEvidence{}, fmt.Errorf("service executable: %w", err)
	}
	defer executable.Close()
	var executableStat unix.Stat_t
	if unix.Fstat(int(executable.Fd()), &executableStat) != nil || executableStat.Mode&unix.S_IFMT != unix.S_IFREG || executableStat.Uid != 0 || executableStat.Mode&0o022 != 0 || executableStat.Mode&0o6000 != 0 || executableStat.Mode&0o111 == 0 || executableStat.Nlink != 1 {
		return ReferenceEvidence{}, fmt.Errorf("service executable type, owner, mode, links, or executable bit is unsafe")
	}
	var capability [1]byte
	if size, xerr := unix.Fgetxattr(int(executable.Fd()), "security.capability", capability[:]); xerr == nil && size > 0 || xerr != nil && !errors.Is(xerr, unix.ENODATA) && !errors.Is(xerr, unix.EOPNOTSUPP) {
		return ReferenceEvidence{}, fmt.Errorf("service executable has file capability or unverifiable xattrs")
	}
	executableDigest, err := digestFD(executable, 512<<20)
	if err != nil {
		return ReferenceEvidence{}, err
	}
	working, err := openExternal(service.WorkingDirectory, true)
	if err != nil {
		return ReferenceEvidence{}, fmt.Errorf("service working directory: %w", err)
	}
	defer working.Close()
	var workingStat unix.Stat_t
	if unix.Fstat(int(working.Fd()), &workingStat) != nil || workingStat.Mode&unix.S_IFMT != unix.S_IFDIR || workingStat.Uid != 0 || workingStat.Mode&0o022 != 0 {
		return ReferenceEvidence{}, fmt.Errorf("service working directory is unsafe")
	}
	evidence := ReferenceEvidence{ExecutableDigest: executableDigest, WorkingDirectoryIdentity: statIdentity(service.WorkingDirectory, workingStat), WritePathIdentities: []string{}}
	for _, path := range service.WritePaths {
		file, openErr := openExternal(path, true)
		if openErr != nil {
			return ReferenceEvidence{}, fmt.Errorf("service write path: %w", openErr)
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(int(file.Fd()), &stat)
		_ = file.Close()
		if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 && stat.Uid != processUID || stat.Mode&0o002 != 0 {
			return ReferenceEvidence{}, fmt.Errorf("service write path type, owner, or mode is unsafe")
		}
		if !pathBelow(service.WorkingDirectory, path) {
			return ReferenceEvidence{}, fmt.Errorf("service write path escapes working directory")
		}
		evidence.WritePathIdentities = append(evidence.WritePathIdentities, statIdentity(path, stat))
	}
	slices.Sort(evidence.WritePathIdentities)
	if service.EnvironmentFile != "" {
		fingerprint, envErr := validateEnvironmentFile(service.EnvironmentFile)
		if envErr != nil {
			return ReferenceEvidence{}, envErr
		}
		evidence.EnvironmentFingerprint = fingerprint
	}
	return evidence, nil
}

func openExternal(path string, directory bool) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, fmt.Errorf("external path is not clean and absolute")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for index, component := range components {
		last := index == len(components)-1
		flags := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_DIRECTORY
		if last {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
			if directory {
				flags |= unix.O_DIRECTORY
			}
		}
		next, openErr := unix.Openat(fd, component, flags, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("inspect external path")
		}
		if !last && (stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0) {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("external path parent is linked, non-root-owned, or writable")
		}
	}
	return os.NewFile(uintptr(fd), filepath.Base(path)), nil
}

func ReadEnvironmentFile(path string) ([]string, error) {
	file, err := openExternal(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximumEnvironmentBytes {
		return nil, fmt.Errorf("environment file is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumEnvironmentBytes+1))
	if err != nil || int64(len(data)) != stat.Size {
		clear(data)
		return nil, fmt.Errorf("environment file changed")
	}
	defer clear(data)
	values := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	seen := map[string]bool{}
	for scanner.Scan() {
		lineBytes := scanner.Bytes()
		line := string(lineBytes)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, found := strings.Cut(line, "=")
		if !found || !validEnvironmentName(name) || seen[name] || name == "LANPANEL_HTTP_SOCKET" || strings.HasPrefix(name, "LISTEN_") || strings.ContainsAny(line, "\x00\r") {
			return nil, fmt.Errorf("environment file syntax or reserved endpoint variable is invalid")
		}
		seen[name] = true
		values = append(values, line)
		clear(lineBytes)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func validateEnvironmentFile(path string) (string, error) {
	file, err := openExternal(path, false)
	if err != nil {
		return "", fmt.Errorf("environment file: %w", err)
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximumEnvironmentBytes {
		return "", fmt.Errorf("environment file type, owner, mode, link, or size is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumEnvironmentBytes+1))
	if err != nil || int64(len(data)) != stat.Size {
		clear(data)
		return "", fmt.Errorf("environment file changed or exceeded its bound")
	}
	defer clear(data)
	if _, err := ReadEnvironmentFile(path); err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validEnvironmentName(value string) bool {
	if value == "" || value[0] >= '0' && value[0] <= '9' {
		return false
	}
	for _, character := range value {
		if character != '_' && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func digestFD(file *os.File, maximum int64) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || count > maximum {
		return "", fmt.Errorf("external executable is unreadable or exceeds fixed bound")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func statIdentity(path string, stat unix.Stat_t) string {
	data := fmt.Sprintf("%s\x00%d\x00%d\x00%d\x00%d\x00%d", path, stat.Dev, stat.Ino, stat.Uid, stat.Gid, stat.Mode)
	digest := sha256.Sum256([]byte(data))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func pathBelow(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
