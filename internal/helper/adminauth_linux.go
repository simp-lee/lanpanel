//go:build linux

package helper

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const fixedAdminTokenPath = "/var/lib/lanpanel/installation/admin-token"

func verifyAdminToken(value []byte) (string, error) {
	source, fingerprint, err := readAdminToken()
	if err != nil {
		return "", err
	}
	defer clear(source)
	if subtle.ConstantTimeCompare(source, value) != 1 {
		return "", fmt.Errorf("admin token is invalid")
	}
	return fingerprint, nil
}

func readAdminToken() ([]byte, string, error) {
	parent := filepath.Dir(fixedAdminTokenPath)
	if err := validateRootParentChain(parent, 0, 0o711); err != nil {
		return nil, "", fmt.Errorf("admin token parent is unsafe")
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if unix.Fstat(parentFD, &parentStat) != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Gid != 0 || parentStat.Mode&0o777 != 0o711 {
		return nil, "", fmt.Errorf("admin token parent identity is unsafe")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(fixedAdminTokenPath), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "admin-token")
	if file == nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("admin token descriptor is invalid")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Size != 64 {
		return nil, "", fmt.Errorf("admin token source identity is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65))
	var final unix.Stat_t
	if err != nil || len(data) != 64 || unix.Fstat(fd, &final) != nil || final.Dev != stat.Dev || final.Ino != stat.Ino || final.Size != stat.Size || final.Mtim != stat.Mtim || final.Ctim != stat.Ctim {
		clear(data)
		return nil, "", fmt.Errorf("admin token source read failed")
	}
	if _, err := hex.DecodeString(string(data)); err != nil || strings.ToLower(string(data)) != string(data) {
		clear(data)
		return nil, "", fmt.Errorf("admin token source encoding is invalid")
	}
	digest := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(digest[:]), nil
}
