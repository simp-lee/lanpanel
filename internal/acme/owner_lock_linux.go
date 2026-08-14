//go:build linux

package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type OwnerLocks struct {
	files   []*os.File
	Owners  []string
	Binding string
}

func AcquireOwnerLocks(ctx context.Context, root string, provider DNSProvider, zone string, owners []string, binding string) (*OwnerLocks, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || len(owners) == 0 || binding == "" {
		return nil, fmt.Errorf("DNS owner lock authority invalid")
	}
	owners = append([]string(nil), owners...)
	slices.Sort(owners)
	owners = slices.Compact(owners)
	aggregate := sha256.Sum256([]byte(string(provider) + "\x00" + zone + "\x00" + strings.Join(owners, "\x00")))
	if binding != "sha256:"+hex.EncodeToString(aggregate[:]) {
		return nil, fmt.Errorf("DNS owner lock binding mismatched")
	}
	result := &OwnerLocks{Owners: owners, Binding: binding}
	for _, owner := range owners {
		if owner != zone && !strings.HasSuffix(owner, "."+zone) {
			result.Close()
			return nil, fmt.Errorf("DNS owner outside zone")
		}
		sum := sha256.Sum256([]byte(string(provider) + "\x00" + zone + "\x00" + owner))
		path := filepath.Join(root, "dns-owner-"+hex.EncodeToString(sum[:])+".lock")
		fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			result.Close()
			return nil, err
		}
		file := os.NewFile(uintptr(fd), path)
		if file == nil {
			unix.Close(fd)
			result.Close()
			return nil, fmt.Errorf("DNS owner lock descriptor invalid")
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
			file.Close()
			result.Close()
			return nil, fmt.Errorf("DNS owner lock file unsafe")
		}
		for {
			if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
				break
			}
			if !errors.Is(err, syscall.EWOULDBLOCK) {
				file.Close()
				result.Close()
				return nil, err
			}
			select {
			case <-ctx.Done():
				file.Close()
				result.Close()
				return nil, ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
		result.files = append(result.files, file)
	}
	return result, nil
}
func (locks *OwnerLocks) Close() error {
	if locks == nil {
		return nil
	}
	var result error
	for index := len(locks.files) - 1; index >= 0; index-- {
		result = errors.Join(result, syscall.Flock(int(locks.files[index].Fd()), syscall.LOCK_UN), locks.files[index].Close())
	}
	locks.files = nil
	return result
}
