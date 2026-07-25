// Package browserauth manages LanPanel-owned htpasswd files for browser apps.
package browserauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

const (
	DefaultDir        = "/etc/lanpanel/browser-auth"
	defaultHtpasswd   = "/usr/bin/htpasswd"
	Marker            = "# LanPanel-managed browser-auth"
	MinimumBcryptCost = 12
	managedDirMode    = 0o710
)

var bcryptHashPattern = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
var managedRoot = DefaultDir
var htpasswdPath = defaultHtpasswd
var unsafeSkipManagedChownForTest bool

// UnsafeSetManagedRootForTest redirects managed browser-auth operations for
// browser E2E/test servers. Production code must keep DefaultDir.
func UnsafeSetManagedRootForTest(root string) (func(), error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("browser auth test managed root must be an absolute path")
	}
	previous := managedRoot
	managedRoot = root
	return func() { managedRoot = previous }, nil
}

// UnsafeDisableManagedChownForTest lets non-root browser E2E test servers
// exercise create/rotate without changing file ownership. Production code must
// keep ownership enforcement enabled.
func UnsafeDisableManagedChownForTest() func() {
	previous := unsafeSkipManagedChownForTest
	unsafeSkipManagedChownForTest = true
	return func() { unsafeSkipManagedChownForTest = previous }
}

type Credential struct {
	ID                  string `json:"id" yaml:"id"`
	Username            string `json:"username" yaml:"username"`
	HtpasswdPath        string `json:"htpasswd_path" yaml:"htpasswd_path"`
	Password            string `json:"-" yaml:"-"`
	PasswordFingerprint string `json:"password_fingerprint" yaml:"password_fingerprint"`
}

type FilePolicy struct {
	ExpectedUID   uint32
	RequireMarker bool
}

func CreateManaged(dir string, id string, username string, password string) (Credential, error) {
	return createManaged(dir, id, username, password, false)
}

func createManaged(dir string, id string, username string, password string, replaceExisting bool) (Credential, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = DefaultDir
	}
	id = strings.TrimSpace(id)
	username = strings.TrimSpace(username)
	if id == "" {
		return Credential{}, fmt.Errorf("credential id is required")
	}
	if !validCredentialID(id) {
		return Credential{}, fmt.Errorf("credential id must start with a lowercase letter, contain only lowercase letters, digits, and hyphens, and must not end with a hyphen")
	}
	dir, err := normalizeManagedDir(dir)
	if err != nil {
		return Credential{}, err
	}
	if username == "" {
		return Credential{}, fmt.Errorf("browser auth username is required")
	}
	if !validUsername(username) {
		return Credential{}, fmt.Errorf("browser auth username must contain only ASCII letters, digits, dot, underscore, and hyphen, and must not start with hyphen")
	}
	if password == "" {
		generated, err := RandomPassword()
		if err != nil {
			return Credential{}, err
		}
		password = generated
	}
	if err := validatePassword(password); err != nil {
		return Credential{}, err
	}
	hashLine, err := HashPassword(username, password)
	if err != nil {
		return Credential{}, err
	}
	content := []byte(Marker + "\n" + hashLine + "\n")
	if err := ValidateManagedContent(content); err != nil {
		return Credential{}, err
	}
	nginxUID, nginxGID, err := nginxRuntimeIdentity()
	if err != nil {
		return Credential{}, err
	}
	dir, err = prepareManagedDir(dir, currentUID(), int(nginxGID))
	if err != nil {
		return Credential{}, err
	}
	path := filepath.Join(dir, id+".htpasswd")
	if err := validateRuntimeSearchPath(path, nginxUID, nginxGID); err != nil {
		return Credential{}, err
	}
	if err := writeManagedFile(path, content, currentUID(), int(nginxGID), replaceExisting); err != nil {
		return Credential{}, err
	}
	if err := validateRuntimeReadableFile(path, nginxUID, nginxGID); err != nil {
		if !replaceExisting {
			_ = os.Remove(path)
		}
		return Credential{}, err
	}
	return Credential{
		ID:                  id,
		Username:            username,
		HtpasswdPath:        path,
		Password:            password,
		PasswordFingerprint: Fingerprint(password),
	}, nil
}

func writeManagedFile(path string, content []byte, uid uint32, gid int, replaceExisting bool) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+strings.TrimSuffix(filepath.Base(path), ".htpasswd")+".*.tmp")
	if err != nil {
		return fmt.Errorf("create browser auth temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod browser auth temp file: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write browser auth temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync browser auth temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close browser auth temp file: %w", err)
	}
	if err := chownManagedPath(tmpPath, uid, gid); err != nil {
		return fmt.Errorf("set browser auth temp file owner/group: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return fmt.Errorf("set browser auth temp file mode: %w", err)
	}
	if err := ValidateFile(tmpPath, FilePolicy{ExpectedUID: uid, RequireMarker: true}); err != nil {
		return err
	}
	if replaceExisting {
		if err := os.Rename(tmpPath, path); err != nil {
			return fmt.Errorf("install browser auth file: %w", err)
		}
		cleanup = false
		return nil
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("browser auth credential %s already exists; use rotate to replace it", path)
		}
		return fmt.Errorf("install browser auth file: %w", err)
	}
	return nil
}

func RotateManaged(path string, username string, password string) (Credential, error) {
	id, err := managedCredentialIDFromPath(path)
	if err != nil {
		return Credential{}, err
	}
	if err := ValidateFile(path, FilePolicy{ExpectedUID: currentUID(), RequireMarker: true}); err != nil {
		return Credential{}, err
	}
	return createManaged(filepath.Dir(path), id, username, password, true)
}

func DeleteManaged(path string, referencedPaths []string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if _, err := managedCredentialIDFromPath(path); err != nil {
		return err
	}
	for _, referenced := range referencedPaths {
		if filepath.Clean(strings.TrimSpace(referenced)) == path {
			return fmt.Errorf("browser auth credential %s is still referenced by an active or staged browser app", path)
		}
	}
	if err := ValidateFile(path, FilePolicy{ExpectedUID: currentUID(), RequireMarker: true}); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete browser auth credential: %w", err)
	}
	return nil
}

func ValidateFile(path string, policy FilePolicy) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("browser auth htpasswd path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("browser auth htpasswd file unavailable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("browser auth htpasswd file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("browser auth htpasswd file must be a regular file")
	}
	if info.Size() == 0 {
		return fmt.Errorf("browser auth htpasswd file must not be empty")
	}
	if info.Mode().Perm()&0o027 != 0 {
		return fmt.Errorf("browser auth htpasswd file must not be group-writable or accessible by others")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("browser auth htpasswd owner could not be inspected")
	}
	if stat.Uid != policy.ExpectedUID {
		return fmt.Errorf("browser auth htpasswd file owner uid %d does not match expected uid %d", stat.Uid, policy.ExpectedUID)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read browser auth htpasswd file: %w", err)
	}
	if policy.RequireMarker {
		if err := ValidateManagedContent(data); err != nil {
			return err
		}
	} else if !containsCredentialLine(data) {
		return fmt.Errorf("browser auth htpasswd file must contain at least one user:hash credential line")
	}
	if err := validateParents(path, policy.ExpectedUID); err != nil {
		return err
	}
	return nil
}

func ValidateManagedContent(data []byte) error {
	if !bytes.HasPrefix(data, []byte(Marker+"\n")) {
		return fmt.Errorf("managed browser auth htpasswd file is missing LanPanel marker")
	}
	count := 0
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if count > 1 {
			return fmt.Errorf("managed browser auth htpasswd file must contain exactly one credential line")
		}
		if err := validateStrongBcryptCredentialLine(line); err != nil {
			return err
		}
	}
	if count == 0 {
		return fmt.Errorf("browser auth htpasswd file must contain at least one user:hash credential line")
	}
	return nil
}

func HashPassword(username string, password string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("browser auth username is required")
	}
	if !validUsername(username) {
		return "", fmt.Errorf("browser auth username must contain only ASCII letters, digits, dot, underscore, and hyphen, and must not start with hyphen")
	}
	if err := validatePassword(password); err != nil {
		return "", err
	}
	binaryPath, err := htpasswdCommandPath()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(binaryPath, "-nB", "-C", strconv.Itoa(MinimumBcryptCost), "-i", username)
	cmd.Stdin = strings.NewReader(password + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		detail := redactSecretFromText(strings.TrimSpace(stderr.String()), password)
		if detail == "" {
			return "", fmt.Errorf("generate browser auth bcrypt hash with htpasswd failed: %w", err)
		}
		return "", fmt.Errorf("generate browser auth bcrypt hash with htpasswd failed: %s", detail)
	}
	line := strings.TrimSpace(string(output))
	if !strings.HasPrefix(line, username+":") || !strings.Contains(line, ":$2") {
		return "", fmt.Errorf("htpasswd did not return a bcrypt credential line")
	}
	if err := validateStrongBcryptCredentialLine(line); err != nil {
		return "", err
	}
	return line, nil
}

func RandomPassword() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate browser auth password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func htpasswdCommandPath() (string, error) {
	path := strings.TrimSpace(htpasswdPath)
	if path == "" {
		return "", fmt.Errorf("htpasswd path is required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("htpasswd path must be a clean absolute path")
	}
	return path, nil
}

func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func RedactSecret(secret string) string {
	if strings.TrimSpace(secret) == "" {
		return ""
	}
	return "[redacted " + Fingerprint(secret) + "]"
}

func redactSecretFromText(text string, secret string) string {
	if strings.TrimSpace(secret) == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, RedactSecret(secret))
}

func containsCredentialLine(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, hash, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(user) == "" || strings.TrimSpace(hash) == "" {
			return false
		}
		if strings.ContainsAny(user, " \t\r\n") || strings.ContainsAny(hash, " \t\r\n") {
			return false
		}
		return true
	}
	return false
}

func containsStrongBcryptCredentialLine(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return validateStrongBcryptCredentialLine(line) == nil
	}
	return false
}

func validateStrongBcryptCredentialLine(line string) error {
	user, hash, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(user) == "" || strings.TrimSpace(hash) == "" {
		return fmt.Errorf("browser auth htpasswd file must contain at least one user:hash credential line")
	}
	if strings.ContainsAny(user, " \t\r\n") || strings.ContainsAny(hash, " \t\r\n") {
		return fmt.Errorf("browser auth htpasswd file must contain at least one user:hash credential line")
	}
	if !bcryptHashPattern.MatchString(hash) {
		return fmt.Errorf("managed browser auth htpasswd file must contain a valid bcrypt credential line")
	}
	cost, err := strconv.Atoi(hash[4:6])
	if err != nil || cost < MinimumBcryptCost {
		return fmt.Errorf("managed browser auth htpasswd file must contain a bcrypt credential line with cost at least %d", MinimumBcryptCost)
	}
	return nil
}

func normalizeManagedDir(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = managedRoot
	}
	dir = filepath.Clean(dir)
	root := filepath.Clean(managedRoot)
	if dir != root {
		return "", fmt.Errorf("browser auth managed directory must be %s", root)
	}
	return dir, nil
}

func managedCredentialIDFromPath(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	root := filepath.Clean(managedRoot)
	if filepath.Dir(path) != root {
		return "", fmt.Errorf("managed browser auth credential path must be a direct child of %s", root)
	}
	if filepath.Ext(path) != ".htpasswd" {
		return "", fmt.Errorf("managed browser auth credential path must end with .htpasswd")
	}
	id := strings.TrimSuffix(filepath.Base(path), ".htpasswd")
	if !validCredentialID(id) {
		return "", fmt.Errorf("managed browser auth credential file name must be <credential_id>.htpasswd")
	}
	return id, nil
}

func prepareManagedDir(dir string, expectedUID uint32, nginxGID int) (string, error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "." || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("browser auth dir must be an absolute path")
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(dir, string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("browser auth dir must be clean and absolute")
		}
		current = filepath.Join(current, part)
		final := i == len(parts)-1
		info, err := os.Lstat(current)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("inspect browser auth directory %s: %w", current, err)
			}
			if err := os.Mkdir(current, managedDirMode); err != nil {
				return "", fmt.Errorf("create browser auth directory %s: %w", current, err)
			}
			if err := chownManagedPath(current, expectedUID, nginxGID); err != nil {
				return "", fmt.Errorf("set browser auth directory %s owner/group: %w", current, err)
			}
			if err := os.Chmod(current, managedDirMode); err != nil {
				return "", fmt.Errorf("set browser auth directory %s mode: %w", current, err)
			}
			continue
		}
		if err := validateDirectoryForManagedCreate(current, info, expectedUID); err != nil {
			return "", err
		}
		if final {
			if err := chownManagedPath(current, expectedUID, nginxGID); err != nil {
				return "", fmt.Errorf("set browser auth dir owner/group: %w", err)
			}
			if err := os.Chmod(current, managedDirMode); err != nil {
				return "", fmt.Errorf("set browser auth dir mode: %w", err)
			}
		}
	}
	if err := validateParents(filepath.Join(dir, "placeholder"), expectedUID); err != nil {
		return "", err
	}
	return dir, nil
}

func chownManagedPath(path string, uid uint32, gid int) error {
	if unsafeSkipManagedChownForTest {
		return nil
	}
	return os.Chown(path, int(uid), gid)
}

func validateDirectoryForManagedCreate(path string, info os.FileInfo, expectedUID uint32) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("browser auth directory %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("browser auth path %s must be a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("browser auth directory %s must not be writable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("browser auth directory %s owner could not be inspected", path)
	}
	if stat.Uid != expectedUID && stat.Uid != 0 {
		return fmt.Errorf("browser auth directory %s owner uid %d does not match expected uid %d", path, stat.Uid, expectedUID)
	}
	return nil
}

func validateParents(path string, expectedUID uint32) error {
	dir := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("inspect browser auth parent directory %s: %w", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("browser auth parent directory %s must not be a symlink", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("browser auth parent path %s must be a directory", dir)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("browser auth parent directory %s must not be writable by group or others", dir)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("browser auth parent directory %s owner could not be inspected", dir)
		}
		if stat.Uid != expectedUID && stat.Uid != 0 {
			return fmt.Errorf("browser auth parent directory %s owner uid %d does not match expected uid %d", dir, stat.Uid, expectedUID)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func validateRuntimeReadableFile(path string, runtimeUID uint32, runtimeGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect browser auth htpasswd file runtime readability: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("browser auth htpasswd file owner could not be inspected for runtime readability")
	}
	if !modeAllowsRuntime(info.Mode().Perm(), stat, runtimeUID, runtimeGID, 0o400, 0o040, 0o004) {
		return fmt.Errorf("browser auth htpasswd file %s must be readable by nginx runtime user www-data", path)
	}
	return validateRuntimeSearchPath(path, runtimeUID, runtimeGID)
}

func validateRuntimeSearchPath(path string, runtimeUID uint32, runtimeGID uint32) error {
	dir := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("inspect browser auth parent directory %s runtime readability: %w", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("browser auth parent directory %s must not be a symlink", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("browser auth parent path %s must be a directory", dir)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("browser auth parent directory %s owner could not be inspected for runtime readability", dir)
		}
		if !modeAllowsRuntime(info.Mode().Perm(), stat, runtimeUID, runtimeGID, 0o100, 0o010, 0o001) {
			return fmt.Errorf("browser auth parent directory %s must be searchable by nginx runtime user www-data", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func modeAllowsRuntime(mode os.FileMode, stat *syscall.Stat_t, runtimeUID uint32, runtimeGID uint32, ownerBit os.FileMode, groupBit os.FileMode, otherBit os.FileMode) bool {
	switch {
	case stat.Uid == runtimeUID:
		return mode&ownerBit != 0
	case stat.Gid == runtimeGID:
		return mode&groupBit != 0
	default:
		return mode&otherBit != 0
	}
}

func validCredentialID(id string) bool {
	if id == "" || len(id) > 64 || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return false
	}
	if id[0] < 'a' || id[0] > 'z' || id[len(id)-1] == '-' {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

func validUsername(username string) bool {
	if username == "" || len(username) > 64 {
		return false
	}
	if username[0] == '-' {
		return false
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func validatePassword(password string) error {
	if len(password) < 16 {
		return fmt.Errorf("browser auth password must be at least 16 characters")
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return fmt.Errorf("browser auth password must not contain control characters")
		}
	}
	return nil
}

func nginxRuntimeIdentity() (uint32, uint32, error) {
	if unsafeSkipManagedChownForTest {
		return uint32(os.Geteuid()), uint32(os.Getegid()), nil
	}
	runtimeUser, err := user.Lookup("www-data")
	if err != nil {
		return 0, 0, fmt.Errorf("lookup nginx runtime user www-data: %w", err)
	}
	uid, err := strconv.Atoi(runtimeUser.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse nginx runtime user uid %q: %w", runtimeUser.Uid, err)
	}
	group, err := user.LookupGroup("www-data")
	if err != nil {
		return 0, 0, fmt.Errorf("lookup nginx runtime group www-data: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse nginx runtime group gid %q: %w", group.Gid, err)
	}
	return uint32(uid), uint32(gid), nil
}

func currentUID() uint32 {
	return uint32(os.Geteuid())
}
