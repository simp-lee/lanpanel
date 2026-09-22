//go:build linux

package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/acmeaccount"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type Stage struct {
	CertificateID string
	Root          string
	UID           uint32
	GID           uint32
}

func PrepareStage(ctx context.Context, certificateID string, binding Binding, uid, gid uint32) (Stage, error) {
	root := filepath.Join("/var/lib/lanpanel/certificates/chroot", certificateID)
	webroot := filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID)
	cleanup := func() error {
		return errors.Join(RemoveStage(certificateID, uid, gid), RemoveWebroot(certificateID, uid, gid))
	}
	mountSources := []string{"/usr/lib/lanpanel/dependencies/lego", "/etc/ssl/certs/ca-certificates.crt", "/etc/resolv.conf", "/etc/hosts"}
	return prepareStage(ctx, certificateID, binding, uid, gid, root, webroot, mountSources, cleanup)
}

func prepareStage(ctx context.Context, certificateID string, binding Binding, uid, gid uint32, root, webroot string, mountSources []string, cleanup func() error) (stage Stage, resultErr error) {
	if ctx.Err() != nil {
		return Stage{}, ctx.Err()
	}
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 || cleanup == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) != certificateID || !filepath.IsAbs(webroot) || filepath.Clean(webroot) != webroot || filepath.Base(webroot) != certificateID || root == webroot {
		return Stage{}, fmt.Errorf("ACME stage identity invalid")
	}
	if err := ValidateBinding(binding); err != nil {
		return Stage{}, err
	}
	for _, path := range []string{root, webroot} {
		if _, err := os.Lstat(path); err == nil {
			return Stage{}, fmt.Errorf("ACME stage residue exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return Stage{}, err
		}
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return Stage{}, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, cleanup())
			stage = Stage{}
		}
	}()
	if err := ensureStageDirectory(root, 0, 0); err != nil {
		return Stage{}, err
	}
	for _, directory := range []string{filepath.Join(root, "work"), filepath.Join(root, "var"), filepath.Join(root, "var", "lib"), filepath.Join(root, "var", "lib", "lanpanel"), filepath.Join(root, "var", "lib", "lanpanel", "certificates"), filepath.Join(root, "var", "lib", "lanpanel", "certificates", "webroot"), filepath.Join(root, "var", "lib", "lanpanel", "certificates", "webroot", certificateID)} {
		if err := ensureStageDirectory(directory, 0, 0); err != nil {
			return Stage{}, err
		}
	}
	for _, directory := range []string{filepath.Join(root, "usr"), filepath.Join(root, "usr", "lib"), filepath.Join(root, "usr", "lib", "lanpanel"), filepath.Join(root, "usr", "lib", "lanpanel", "dependencies"), filepath.Join(root, "etc"), filepath.Join(root, "etc", "ssl"), filepath.Join(root, "etc", "ssl", "certs")} {
		if err := ensureStageDirectory(directory, 0, 0); err != nil {
			return Stage{}, err
		}
	}
	for _, path := range []string{root, filepath.Join(root, "usr"), filepath.Join(root, "usr", "lib"), filepath.Join(root, "usr", "lib", "lanpanel"), filepath.Join(root, "usr", "lib", "lanpanel", "dependencies"), filepath.Join(root, "etc"), filepath.Join(root, "etc", "ssl"), filepath.Join(root, "etc", "ssl", "certs"), filepath.Join(root, "var"), filepath.Join(root, "var", "lib"), filepath.Join(root, "var", "lib", "lanpanel"), filepath.Join(root, "var", "lib", "lanpanel", "certificates"), filepath.Join(root, "var", "lib", "lanpanel", "certificates", "webroot")} {
		if err := os.Chmod(path, 0o711); err != nil {
			return Stage{}, err
		}
	}
	if err := ensureStageDirectory(webroot, uid, gid); err != nil {
		return Stage{}, err
	}
	if err := os.Chmod(webroot, 0o711); err != nil {
		return Stage{}, err
	}
	if err := os.Chown(filepath.Join(root, "work"), int(uid), int(gid)); err != nil {
		return Stage{}, err
	}
	if err := os.Chmod(filepath.Join(root, "work"), 0o700); err != nil {
		return Stage{}, err
	}
	stage = Stage{CertificateID: certificateID, Root: root, UID: uid, GID: gid}
	if err := stage.installAccountKey(binding); err != nil {
		return Stage{}, err
	}
	for _, credential := range binding.CredentialFiles {
		if err := stage.copyCredential(credential, uid, gid); err != nil {
			return Stage{}, err
		}
	}
	for _, source := range mountSources {
		if err := stage.prepareMountTarget(source); err != nil {
			return Stage{}, err
		}
	}
	return stage, nil
}

func RemoveStage(certificateID string, uid, gid uint32) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 {
		return fmt.Errorf("ACME cleanup identity invalid")
	}
	root := filepath.Join("/var/lib/lanpanel/certificates/chroot", certificateID)
	return removeOwnedTree(root, uid, gid, 4096)
}

func VerifyWebrootEmpty(certificateID string, uid, gid uint32) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 {
		return fmt.Errorf("ACME webroot identity invalid")
	}
	return verifyWebrootEmptyAt(filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID), uid, gid)
}

func verifyWebrootEmptyAt(root string, uid, gid uint32) (resultErr error) {
	rootFD, err := openDirectoryPathNoFollow(root)
	if err != nil {
		return fmt.Errorf("ACME webroot missing or unsafe: %w", err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	if err := validateACMEWebrootFD(rootFD, uid, gid); err != nil {
		return err
	}
	rootSeal, err := sealDirectory(rootFD)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, restoreDirectorySeal(rootFD, rootSeal)) }()
	entries, err := readDirectoryFD(rootFD)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if len(entries) != 1 || entries[0].Name() != ".well-known" {
		return fmt.Errorf("ACME webroot inventory unexpected")
	}
	wellKnownFD, err := openDirectoryAtNoFollow(rootFD, ".well-known")
	if err != nil {
		return fmt.Errorf("ACME challenge directory unsafe: %w", err)
	}
	defer func() { _ = unix.Close(wellKnownFD) }()
	if err := validateHTTP01ChallengeDirectoryFD(wellKnownFD, uid, gid); err != nil {
		return err
	}
	wellKnownSeal, err := sealDirectory(wellKnownFD)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, restoreDirectorySeal(wellKnownFD, wellKnownSeal))
		}
	}()
	entries, err = readDirectoryFD(wellKnownFD)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != "acme-challenge" {
		return fmt.Errorf("ACME webroot inventory unexpected")
	}
	challengeFD, err := openDirectoryAtNoFollow(wellKnownFD, "acme-challenge")
	if err != nil {
		return fmt.Errorf("ACME challenge directory unsafe: %w", err)
	}
	defer func() { _ = unix.Close(challengeFD) }()
	if err := validateHTTP01ChallengeDirectoryFD(challengeFD, uid, gid); err != nil {
		return err
	}
	challengeSeal, err := sealDirectory(challengeFD)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, restoreDirectorySeal(challengeFD, challengeSeal))
		}
	}()
	tokens, err := readDirectoryFD(challengeFD)
	if err != nil {
		return err
	}
	if len(tokens) != 0 {
		return fmt.Errorf("ACME challenge token cleanup unproved")
	}
	if err := unix.Unlinkat(wellKnownFD, "acme-challenge", unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := unix.Unlinkat(rootFD, ".well-known", unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := restoreDirectorySeal(rootFD, rootSeal); err != nil {
		return err
	}
	return unix.Fsync(rootFD)
}

func RemoveWebroot(certificateID string, uid, gid uint32) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 {
		return fmt.Errorf("ACME webroot cleanup identity invalid")
	}
	root := filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID)
	return removeOwnedTree(root, uid, gid, 1024)
}

func removeOwnedTree(root string, uid, gid uint32, remaining int) error {
	parentFD, err := openDirectoryPathNoFollow(filepath.Dir(root))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ACME cleanup root invalid: %w", err)
	}
	defer func() { _ = unix.Close(parentFD) }()

	rootFD, err := openDirectoryAtNoFollow(parentFD, filepath.Base(root))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ACME cleanup root invalid: %w", err)
	}
	removeErr := removeOwnedDirectoryAt(parentFD, filepath.Base(root), rootFD, uid, gid, &remaining)
	closeErr := unix.Close(rootFD)
	if removeErr != nil {
		return errors.Join(removeErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	return unix.Fsync(parentFD)
}

func removeOwnedDirectoryAt(parentFD int, name string, directoryFD int, uid, gid uint32, remaining *int) (resultErr error) {
	if *remaining <= 0 {
		return fmt.Errorf("ACME cleanup inventory unbounded")
	}
	*remaining--
	seal, err := sealDirectory(directoryFD)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, restoreDirectorySeal(directoryFD, seal))
		}
	}()
	entries, err := readDirectoryFD(directoryFD)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		childFD, err := unix.Openat(directoryFD, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(childFD, &stat)
		memberValid := statErr == nil && (stat.Uid == 0 || stat.Uid == uid) && (stat.Gid == 0 || stat.Gid == gid) && stat.Mode&0o022 == 0
		memberType := stat.Mode & unix.S_IFMT
		if !memberValid {
			_ = unix.Close(childFD)
			return fmt.Errorf("ACME cleanup member identity invalid")
		}
		if memberType == unix.S_IFDIR {
			childErr := removeOwnedDirectoryAt(directoryFD, entry.Name(), childFD, uid, gid, remaining)
			closeErr := unix.Close(childFD)
			if childErr != nil {
				return errors.Join(childErr, closeErr)
			}
			if closeErr != nil {
				return closeErr
			}
			continue
		}
		if memberType != unix.S_IFREG {
			_ = unix.Close(childFD)
			return fmt.Errorf("ACME cleanup member type invalid")
		}
		if err := unix.Close(childFD); err != nil {
			return err
		}
		if err := unix.Unlinkat(directoryFD, entry.Name(), 0); err != nil {
			return err
		}
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return err
	}
	if parentFD >= 0 {
		if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	return nil
}

func openDirectoryPathNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("directory path invalid")
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(current)
		if openErr != nil {
			return -1, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return -1, closeErr
		}
		current = next
	}
	return current, nil
}

func openDirectoryAtNoFollow(parentFD int, name string) (int, error) {
	return unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

type directorySeal struct {
	uid, gid uint32
	mode     uint32
	changed  bool
}

func sealDirectory(directoryFD int) (directorySeal, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(directoryFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return directorySeal{}, fmt.Errorf("ACME cleanup directory identity invalid")
	}
	seal := directorySeal{uid: stat.Uid, gid: stat.Gid, mode: stat.Mode & 0o7777}
	if os.Geteuid() != 0 {
		return seal, nil
	}
	if stat.Uid != 0 || stat.Gid != 0 {
		if err := unix.Fchown(directoryFD, 0, 0); err != nil {
			return directorySeal{}, err
		}
		seal.changed = true
	}
	if err := unix.Fchmod(directoryFD, seal.mode&^0o222); err != nil {
		return directorySeal{}, errors.Join(err, restoreDirectorySeal(directoryFD, seal))
	}
	return seal, nil
}

func restoreDirectorySeal(directoryFD int, seal directorySeal) error {
	var result error
	if seal.changed {
		result = errors.Join(result, unix.Fchown(directoryFD, int(seal.uid), int(seal.gid)))
	}
	return errors.Join(result, unix.Fchmod(directoryFD, seal.mode))
}

func readDirectoryFD(directoryFD int) ([]os.DirEntry, error) {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(duplicate)
	directory := os.NewFile(uintptr(duplicate), "acme-directory")
	if directory == nil {
		_ = unix.Close(duplicate)
		return nil, fmt.Errorf("ACME directory descriptor unavailable")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	return entries, errors.Join(readErr, closeErr)
}

func (stage Stage) Close() error {
	if !certificateIDPattern(stage.CertificateID) || stage.Root != "/var/lib/lanpanel/certificates/chroot/"+stage.CertificateID {
		return fmt.Errorf("ACME stage identity invalid")
	}
	return nil
}

func ensureStageDirectory(path string, uid, gid uint32) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
		return fmt.Errorf("ACME stage directory unsafe")
	}
	if err := os.Chown(path, int(uid), int(gid)); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func LegoAccountKeyPath(binding Binding) (string, error) {
	if err := ValidateBinding(binding); err != nil {
		return "", err
	}
	parsed, err := url.Parse(binding.DirectoryURL)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("ACME account server invalid")
	}
	server := strings.NewReplacer(":", "_", "/", string(filepath.Separator)).Replace(parsed.Host)
	if server == "" || strings.Contains(server, "..") {
		return "", fmt.Errorf("ACME account server invalid")
	}
	return filepath.Join("/work/accounts", server, binding.AccountEmail, "keys", binding.AccountEmail+".key"), nil
}

func (stage Stage) installAccountKey(binding Binding) error {
	target, err := LegoAccountKeyPath(binding)
	if err != nil {
		return err
	}
	relative := strings.TrimPrefix(filepath.Dir(target), "/")
	current := stage.Root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := ensureStageDirectory(current, stage.UID, stage.GID); err != nil {
			return err
		}
	}
	return stage.copyProtectedTo(binding.AccountKeyPath, target, stage.UID, stage.GID, binding.AccountKeyFingerprint)
}

func (stage Stage) copyCredential(credential CredentialFile, uid, gid uint32) error {
	return stage.copyProtectedToVerified(credential.Path, credential.Path, uid, gid, func(data []byte) error {
		sum := sha256.Sum256(data)
		fingerprint := "sha256:" + hex.EncodeToString(sum[:])
		if fingerprint != credential.Fingerprint {
			return fmt.Errorf("ACME credential changed before staging")
		}
		return nil
	})
}

func (stage Stage) copyProtectedTo(source, targetPath string, uid, gid uint32, accountKeyFingerprint string) error {
	return stage.copyProtectedToVerified(source, targetPath, uid, gid, func(data []byte) error {
		fingerprint, err := acmeaccount.Fingerprint(data)
		if err != nil || fingerprint != accountKeyFingerprint {
			return fmt.Errorf("ACME account key changed before staging")
		}
		return nil
	})
}

func (stage Stage) copyProtectedToVerified(source, targetPath string, uid, gid uint32, verify func([]byte) error) error {
	input, err := openProtected(source)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(input.Close)
	data, readErr := io.ReadAll(io.LimitReader(input, 64<<10+1))
	if readErr != nil || len(data) == 0 || len(data) > 64<<10 {
		return fmt.Errorf("ACME protected input invalid")
	}
	if err := verify(data); err != nil {
		return err
	}
	target := filepath.Join(stage.Root, strings.TrimPrefix(targetPath, "/"))
	if err := os.MkdirAll(filepath.Dir(target), 0o711); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	writeErr := writeFull(output, data)
	ownerErr := output.Chown(int(uid), int(gid))
	modeErr := output.Chmod(0o400)
	syncErr := output.Sync()
	closeErr := output.Close()
	return errors.Join(writeErr, ownerErr, modeErr, syncErr, closeErr)
}

func writeFull(output *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := output.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (stage Stage) prepareMountTarget(source string) error {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return fmt.Errorf("ACME mount source invalid")
	}
	target := filepath.Join(stage.Root, strings.TrimPrefix(source, "/"))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	stat, err := os.Stat(source)
	if err != nil || !stat.Mode().IsRegular() {
		return fmt.Errorf("ACME mount source type invalid")
	}
	fd, err := unix.Open(target, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if fd >= 0 {
		return unix.Close(fd)
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ACME mount target invalid")
	}
	return nil
}

func certificateIDPattern(value string) bool {
	if len(value) != 37 || !strings.HasPrefix(value, "cert_") {
		return false
	}
	for _, r := range value[5:] {
		if r < '0' || r > '9' && r < 'a' || r > 'f' {
			return false
		}
	}
	return true
}
