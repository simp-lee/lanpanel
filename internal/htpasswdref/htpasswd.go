package htpasswdref

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const FixedCost = 12

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

type Identity struct {
	Path        string   `json:"path"`
	Fingerprint string   `json:"fingerprint"`
	Usernames   []string `json:"usernames"`
	Bytes       int64    `json:"bytes"`
	Mode        uint32   `json:"mode"`
}

func ValidateRecord(username, record string) bool {
	return ValidUsername(username) && validBcrypt(record)
}
func ValidUsername(value string) bool { return usernamePattern.MatchString(value) }
func Validate(path string, nginxGID uint32) (Identity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || nginxGID == 0 {
		return Identity{}, fmt.Errorf("htpasswd reference identity invalid")
	}
	if err := validateParents(path, nginxGID); err != nil {
		return Identity{}, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Identity{}, fmt.Errorf("htpasswd source missing or unsafe")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return Identity{}, fmt.Errorf("htpasswd descriptor invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Size <= 0 || stat.Size > 64<<10 || stat.Uid != 0 || stat.Gid != nginxGID || (stat.Mode&0o7777 != 0o640 && stat.Mode&0o7777 != 0o440) || stat.Nlink != 1 {
		return Identity{}, fmt.Errorf("htpasswd source ownership or mode invalid")
	}
	size := stat.Size
	hash := sha256.New()
	reader := bufio.NewReader(io.TeeReader(io.LimitReader(file, 64<<10+1), hash))
	seen := map[string]bool{}
	names := []string{}
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 256 {
			return Identity{}, fmt.Errorf("htpasswd line oversized")
		}
		if len(line) > 0 {
			if !strings.HasSuffix(line, "\n") {
				return Identity{}, fmt.Errorf("htpasswd final newline missing")
			}
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")
			username, encoded, found := strings.Cut(line, ":")
			if !found || !ValidUsername(username) || seen[username] || !validBcrypt(encoded) {
				return Identity{}, fmt.Errorf("htpasswd record invalid")
			}
			seen[username] = true
			names = append(names, username)
			if len(names) > 1024 {
				return Identity{}, fmt.Errorf("htpasswd record inventory oversized")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Identity{}, readErr
		}
	}
	if len(names) == 0 {
		return Identity{}, fmt.Errorf("htpasswd source empty")
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	var current syscall.Stat_t
	if err != nil || syscall.Fstat(fd, &current) != nil || offset != size || current.Dev != stat.Dev || current.Ino != stat.Ino || current.Size != stat.Size || current.Mtim != stat.Mtim {
		return Identity{}, fmt.Errorf("htpasswd source changed while reading")
	}
	return Identity{Path: path, Fingerprint: "sha256:" + hex.EncodeToString(hash.Sum(nil)), Usernames: names, Bytes: size, Mode: uint32(stat.Mode & 0o7777)}, nil
}

func validBcrypt(value string) bool {
	if len(value) != 60 || !strings.HasPrefix(value, "$2y$") {
		return false
	}
	cost, err := strconv.Atoi(value[4:6])
	if err != nil || cost != FixedCost || value[6] != '$' {
		return false
	}
	for _, character := range value[7:] {
		if !strings.ContainsRune("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", character) {
			return false
		}
	}
	return true
}

func validateParents(path string, nginxGID uint32) error {
	current := filepath.Dir(path)
	for {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("htpasswd parent unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o001 == 0 && (stat.Gid != nginxGID || info.Mode().Perm()&0o010 == 0) {
			return fmt.Errorf("htpasswd parent ownership or traversal unsafe")
		}
		if current == "/" {
			return nil
		}
		next := filepath.Dir(current)
		if next == current {
			return fmt.Errorf("htpasswd parent traversal invalid")
		}
		current = next
	}
}
