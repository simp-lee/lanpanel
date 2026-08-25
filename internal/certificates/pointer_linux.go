//go:build linux

package certificates

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	FixedRoot        = "/var/lib/lanpanel/certificates"
	FixedBundlesRoot = FixedRoot + "/bundles"
	FixedActiveRoot  = FixedRoot + "/active"
)

type Pointer struct {
	CertificateID           string
	CandidateGeneration     uint64
	ExpectedPriorGeneration uint64
}
type PointerResult struct {
	PriorTarget     string
	CandidateTarget string
	Durable         bool
}

func RemoveInactiveBundle(certificateIdentity string, generation uint64, uid, gid uint32) error {
	path, err := BundlePath(certificateIdentity, generation)
	if err != nil || uid == 0 || gid == 0 {
		return fmt.Errorf("inactive certificate cleanup identity invalid")
	}
	active, err := ObservePointer(certificateIdentity)
	if err != nil {
		return err
	}
	if active == path {
		return fmt.Errorf("active certificate bundle cannot be removed")
	}
	remaining := 16
	var remove func(string) error
	remove = func(current string) error {
		remaining--
		if remaining < 0 {
			return fmt.Errorf("certificate cleanup inventory unbounded")
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("certificate cleanup path unsafe")
		}
		stat, ok := info.Sys().(*unix.Stat_t)
		if !ok || stat.Uid != uid || stat.Gid != gid {
			return fmt.Errorf("certificate cleanup owner changed")
		}
		if info.IsDir() {
			entries, err := os.ReadDir(current)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := remove(filepath.Join(current, entry.Name())); err != nil {
					return err
				}
			}
		}
		return os.Remove(current)
	}
	if err := remove(path); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(parent.Close)
	return parent.Sync()
}

func BundlePath(certificateIdentity string, generation uint64) (string, error) {
	if !certificateID(certificateIdentity) || generation == 0 {
		return "", fmt.Errorf("certificate bundle identity invalid")
	}
	return filepath.Join(FixedBundlesRoot, bundleName(certificateIdentity, generation)), nil
}

func ActivePointerPath(certificateIdentity string) (string, error) {
	if !certificateID(certificateIdentity) {
		return "", fmt.Errorf("certificate identity invalid")
	}
	return filepath.Join(FixedActiveRoot, certificateIdentity+".current"), nil
}

func ActiveCertificatePath(certificateIdentity string) (string, error) {
	pointer, err := ActivePointerPath(certificateIdentity)
	if err != nil {
		return "", err
	}
	return filepath.Join(pointer, "certificate.pem"), nil
}

func ActivePrivateKeyPath(certificateIdentity string) (string, error) {
	pointer, err := ActivePointerPath(certificateIdentity)
	if err != nil {
		return "", err
	}
	return filepath.Join(pointer, "private-key.pem"), nil
}

func ActivatePointer(ctx context.Context, pointer Pointer) (PointerResult, error) {
	if err := ctx.Err(); err != nil {
		return PointerResult{}, err
	}
	path, candidate, prior, err := pointerPaths(pointer)
	if err != nil {
		return PointerResult{}, err
	}
	parent := filepath.Dir(path)
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return PointerResult{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	observed, err := readPointer(fd, filepath.Base(path))
	if errors.Is(err, os.ErrNotExist) {
		observed = ""
	} else if err != nil {
		return PointerResult{}, err
	}
	if observed != prior {
		return PointerResult{}, fmt.Errorf("certificate prior pointer changed")
	}
	if err := verifyBundleTarget(candidate); err != nil {
		return PointerResult{}, err
	}
	temporary := "." + filepath.Base(path) + ".lanpanel-pointer"
	_ = unix.Unlinkat(fd, temporary, 0)
	if err := unix.Symlinkat(candidate, fd, temporary); err != nil {
		return PointerResult{}, err
	}
	if err := unix.Renameat(fd, temporary, fd, filepath.Base(path)); err != nil {
		_ = unix.Unlinkat(fd, temporary, 0)
		return PointerResult{}, err
	}
	result := PointerResult{PriorTarget: prior, CandidateTarget: candidate}
	if err := unix.Fsync(fd); err != nil {
		return result, fmt.Errorf("certificate pointer changed but durability is unknown: %w", err)
	}
	current, err := readPointer(fd, filepath.Base(path))
	if err != nil || current != candidate {
		return result, fmt.Errorf("certificate pointer verification failed")
	}
	result.Durable = true
	return result, nil
}

func RestorePointer(ctx context.Context, pointer Pointer, expectedCandidate string) error {
	path, candidate, prior, err := pointerPaths(pointer)
	if err != nil {
		return err
	}
	if candidate != expectedCandidate {
		return fmt.Errorf("candidate certificate pointer mismatch")
	}
	current, err := readLink(path)
	if err != nil || current != candidate {
		return fmt.Errorf("candidate certificate pointer changed")
	}
	if prior == "" {
		parent := filepath.Dir(path)
		fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		if err := unix.Unlinkat(fd, filepath.Base(path), 0); err != nil {
			return err
		}
		return unix.Fsync(fd)
	}
	if err := verifyBundleTarget(prior); err != nil {
		return err
	}
	reverse := Pointer{CertificateID: pointer.CertificateID, CandidateGeneration: pointer.ExpectedPriorGeneration, ExpectedPriorGeneration: pointer.CandidateGeneration}
	_, err = ActivatePointer(ctx, reverse)
	return err
}

func pointerPaths(pointer Pointer) (string, string, string, error) {
	if !certificateID(pointer.CertificateID) || pointer.CandidateGeneration == 0 || pointer.CandidateGeneration == pointer.ExpectedPriorGeneration {
		return "", "", "", fmt.Errorf("certificate pointer authority invalid")
	}
	path, err := ActivePointerPath(pointer.CertificateID)
	if err != nil {
		return "", "", "", err
	}
	candidate, err := BundlePath(pointer.CertificateID, pointer.CandidateGeneration)
	if err != nil {
		return "", "", "", err
	}
	prior := ""
	if pointer.ExpectedPriorGeneration != 0 {
		prior, err = BundlePath(pointer.CertificateID, pointer.ExpectedPriorGeneration)
		if err != nil {
			return "", "", "", err
		}
	}
	return path, candidate, prior, nil
}

func verifyBundleTarget(path string) error {
	if !strings.HasPrefix(path, FixedBundlesRoot+string(filepath.Separator)) || filepath.Clean(path) != path || filepath.Dir(path) != FixedBundlesRoot {
		return fmt.Errorf("certificate target outside fixed root")
	}
	name := filepath.Base(path)
	separator := strings.LastIndex(name, "-")
	if separator <= 0 {
		return fmt.Errorf("certificate target identity invalid")
	}
	certificateIdentity := name[:separator]
	generationText := name[separator+1:]
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil || name != bundleName(certificateIdentity, generation) {
		return fmt.Errorf("certificate target generation invalid")
	}
	stage, err := identity.CertificateStageIdentityFor(certificateIdentity)
	if err != nil {
		return err
	}
	if _, err := ObserveIdentity(FixedBundlesRoot, certificateIdentity, generation, filetxn.Owner{UID: stage.UID, GID: stage.GID}); err != nil {
		return fmt.Errorf("certificate target bundle invalid: %w", err)
	}
	return nil
}
func bundleName(id string, generation uint64) string { return fmt.Sprintf("%s-%020d", id, generation) }
func certificateID(value string) bool {
	if len(value) != 37 || value[:5] != "cert_" {
		return false
	}
	for _, r := range value[5:] {
		if r < '0' || r > '9' && r < 'a' || r > 'f' {
			return false
		}
	}
	return true
}

func ObservePointer(certificateIdentity string) (string, error) {
	path, err := ActivePointerPath(certificateIdentity)
	if err != nil {
		return "", err
	}
	value, err := readLink(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return value, err
}

func readLink(path string) (string, error) {
	parent := filepath.Dir(path)
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	return readPointer(fd, filepath.Base(path))
}

func readPointer(parentFD int, name string) (string, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFLNK {
		return "", fmt.Errorf("certificate pointer is not symlink")
	}
	buffer := make([]byte, 4097)
	n, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil || n <= 0 || n > 4096 {
		return "", fmt.Errorf("certificate pointer invalid")
	}
	value := string(buffer[:n])
	if !cleanAbsolute(value) || !strings.HasPrefix(value, FixedBundlesRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("certificate target invalid")
	}
	return value, nil
}
