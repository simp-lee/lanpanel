//go:build linux

package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type Stage struct {
	CertificateID string
	Root          string
	UID           uint32
	GID           uint32
}

func PrepareStage(ctx context.Context, certificateID string, binding Binding, uid, gid uint32) (Stage, error) {
	if ctx.Err() != nil {
		return Stage{}, ctx.Err()
	}
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 {
		return Stage{}, fmt.Errorf("ACME stage identity invalid")
	}
	if err := ValidateBinding(binding); err != nil {
		return Stage{}, err
	}
	root := filepath.Join("/var/lib/lanpanel/certificates/chroot", certificateID)
	webroot := filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID)
	for _, path := range []string{root, webroot} {
		if _, err := os.Lstat(path); err == nil {
			return Stage{}, fmt.Errorf("ACME stage residue exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return Stage{}, err
		}
	}
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
	stage := Stage{CertificateID: certificateID, Root: root, UID: uid, GID: gid}
	if err := stage.installAccountKey(binding); err != nil {
		_ = stage.Close()
		return Stage{}, err
	}
	for _, source := range credentialPaths(binding) {
		if err := stage.copyProtected(source, uid, gid); err != nil {
			_ = stage.Close()
			return Stage{}, err
		}
	}
	for _, source := range []string{"/usr/lib/lanpanel/dependencies/lego", "/etc/ssl/certs/ca-certificates.crt", "/etc/resolv.conf", "/etc/hosts"} {
		if err := stage.prepareMountTarget(source); err != nil {
			_ = stage.Close()
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
	root := filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ACME webroot missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("ACME webroot owner changed")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if len(entries) != 1 || entries[0].Name() != ".well-known" || !entries[0].IsDir() {
		return fmt.Errorf("ACME webroot inventory unexpected")
	}
	wellKnown := filepath.Join(root, ".well-known")
	challenge := filepath.Join(wellKnown, "acme-challenge")
	for _, path := range []string{wellKnown, challenge} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ACME challenge directory unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uid || stat.Gid != gid || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("ACME challenge directory owner changed")
		}
	}
	tokens, err := os.ReadDir(challenge)
	if err != nil {
		return err
	}
	if len(tokens) != 0 {
		return fmt.Errorf("ACME challenge token cleanup unproved")
	}
	if err := os.Remove(challenge); err != nil {
		return err
	}
	if err := os.Remove(wellKnown); err != nil {
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func RemoveWebroot(certificateID string, uid, gid uint32) error {
	if !certificateIDPattern(certificateID) || uid == 0 || gid == 0 {
		return fmt.Errorf("ACME webroot cleanup identity invalid")
	}
	root := filepath.Join("/var/lib/lanpanel/certificates/webroot", certificateID)
	return removeOwnedTree(root, uid, gid, 1024)
}
func removeOwnedTree(root string, uid, gid uint32, remaining int) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ACME cleanup root invalid")
	}
	var walk func(string) error
	walk = func(path string) error {
		if remaining <= 0 {
			return fmt.Errorf("ACME cleanup inventory unbounded")
		}
		remaining--
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			childPath := filepath.Join(path, entry.Name())
			info, err := os.Lstat(childPath)
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || (stat.Uid != 0 && stat.Uid != uid) || (stat.Gid != 0 && stat.Gid != gid) || info.Mode().Perm()&0o022 != 0 || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("ACME cleanup member identity invalid")
			}
			if info.IsDir() {
				if err := walk(childPath); err != nil {
					return err
				}
			} else if !info.Mode().IsRegular() {
				return fmt.Errorf("ACME cleanup member type invalid")
			}
			if err := os.Remove(childPath); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return err
	}
	if err := os.Remove(root); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(root))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
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
	return stage.copyProtectedTo(binding.AccountKeyPath, target, stage.UID, stage.GID, true)
}
func (stage Stage) copyProtected(source string, uid, gid uint32) error {
	return stage.copyProtectedTo(source, source, uid, gid, false)
}
func (stage Stage) copyProtectedTo(source, targetPath string, uid, gid uint32, accountKey bool) error {
	input, err := openProtected(source)
	if err != nil {
		return err
	}
	defer input.Close()
	target := filepath.Join(stage.Root, strings.TrimPrefix(targetPath, "/"))
	if err := os.MkdirAll(filepath.Dir(target), 0o711); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(input, 64<<10+1))
	if readErr != nil || len(data) == 0 || len(data) > 64<<10 {
		output.Close()
		return fmt.Errorf("ACME protected input invalid")
	}
	if accountKey {
		block, rest := pem.Decode(data)
		valid := false
		if block != nil && len(strings.TrimSpace(string(rest))) == 0 {
			if block.Type == "RSA PRIVATE KEY" {
				_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				valid = err == nil
			} else if block.Type == "EC PRIVATE KEY" {
				_, err = x509.ParseECPrivateKey(block.Bytes)
				valid = err == nil
			}
		}
		if !valid {
			output.Close()
			return fmt.Errorf("ACME account key format invalid")
		}
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
func credentialPaths(binding Binding) []string {
	result := make([]string, len(binding.CredentialFiles))
	for index, file := range binding.CredentialFiles {
		result[index] = file.Path
	}
	slices.Sort(result)
	return result
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
