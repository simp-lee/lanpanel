package edgeone

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	EnvSecretIDFile     = "TENCENTCLOUD_SECRET_ID_FILE"
	EnvSecretKeyFile    = "TENCENTCLOUD_SECRET_KEY_FILE"
	EnvSessionTokenFile = "TENCENTCLOUD_SESSION_TOKEN_FILE"
)

var allowedCredentialEnvKeys = map[string]struct{}{
	EnvSecretIDFile:     {},
	EnvSecretKeyFile:    {},
	EnvSessionTokenFile: {},
}

type Credentials struct {
	SecretID     string
	SecretKey    string
	SessionToken string
}

type FileSystem interface {
	Lstat(path string) (fs.FileInfo, error)
	ReadFile(path string) ([]byte, error)
}

type OSFileSystem struct{}

func (OSFileSystem) Lstat(path string) (fs.FileInfo, error) {
	return os.Lstat(path)
}

func (OSFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func LoadCredentialsFromEnvFile(fileSystem FileSystem, envFile string) (Credentials, error) {
	envFile = strings.TrimSpace(envFile)
	if envFile == "" {
		return Credentials{}, fmt.Errorf("edgeone env_file is required")
	}
	if !filepath.IsAbs(envFile) || filepath.Clean(envFile) != envFile {
		return Credentials{}, fmt.Errorf("edgeone env_file must be a clean absolute path")
	}
	if fileSystem == nil {
		fileSystem = OSFileSystem{}
	}
	if err := validateRootOnlyFile(fileSystem, "edgeone env_file", envFile); err != nil {
		return Credentials{}, err
	}
	data, err := fileSystem.ReadFile(envFile)
	if err != nil {
		return Credentials{}, fmt.Errorf("read edgeone env_file %s: %w", envFile, err)
	}
	env, err := parseCredentialEnvFile(string(data))
	if err != nil {
		return Credentials{}, fmt.Errorf("parse edgeone env_file %s: %w", envFile, err)
	}
	secretID, err := readSecretReference(fileSystem, EnvSecretIDFile, env[EnvSecretIDFile])
	if err != nil {
		return Credentials{}, err
	}
	secretKey, err := readSecretReference(fileSystem, EnvSecretKeyFile, env[EnvSecretKeyFile])
	if err != nil {
		return Credentials{}, err
	}
	sessionToken := ""
	if path := strings.TrimSpace(env[EnvSessionTokenFile]); path != "" {
		sessionToken, err = readSecretReference(fileSystem, EnvSessionTokenFile, path)
		if err != nil {
			return Credentials{}, err
		}
	}
	return Credentials{SecretID: secretID, SecretKey: secretKey, SessionToken: sessionToken}, nil
}

func parseCredentialEnvFile(content string) (map[string]string, error) {
	env := map[string]string{}
	for lineNumber, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			return nil, fmt.Errorf("line %d uses unsupported export syntax", lineNumber+1)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d is not KEY=value", lineNumber+1)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || strings.ContainsAny(key, " \t\r\n") {
			return nil, fmt.Errorf("line %d has an invalid key", lineNumber+1)
		}
		if _, ok := allowedCredentialEnvKeys[key]; !ok {
			return nil, fmt.Errorf("%s is not supported for EdgeOne realip credentials; use %s and %s", key, EnvSecretIDFile, EnvSecretKeyFile)
		}
		if _, exists := env[key]; exists {
			return nil, fmt.Errorf("%s is duplicated in EdgeOne realip credentials", key)
		}
		if value == "" {
			return nil, fmt.Errorf("%s must not be empty", key)
		}
		if strings.ContainsAny(value, "\"'\\") || strings.ContainsAny(value, "\r\n\t ") {
			return nil, fmt.Errorf("%s must be an absolute path without quotes, escapes, or whitespace", key)
		}
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return nil, fmt.Errorf("%s must be a clean absolute path", key)
		}
		env[key] = value
	}
	if env[EnvSecretIDFile] == "" {
		return nil, fmt.Errorf("%s is required", EnvSecretIDFile)
	}
	if env[EnvSecretKeyFile] == "" {
		return nil, fmt.Errorf("%s is required", EnvSecretKeyFile)
	}
	return env, nil
}

func readSecretReference(fileSystem FileSystem, key string, path string) (string, error) {
	if err := validateRootOnlyFile(fileSystem, key, path); err != nil {
		return "", err
	}
	data, err := fileSystem.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s referenced file %s: %w", key, path, err)
	}
	value, err := secretFileToken(data)
	if err != nil {
		return "", fmt.Errorf("%s referenced file %s %w", key, path, err)
	}
	if value == "" {
		return "", fmt.Errorf("%s referenced file %s is empty", key, path)
	}
	return value, nil
}

func secretFileToken(data []byte) (string, error) {
	value := string(data)
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
	}
	if value == "" {
		return "", nil
	}
	if containsWhitespaceOrControl(value) {
		return "", fmt.Errorf("must contain exactly one token without whitespace or control characters")
	}
	return value, nil
}

func containsWhitespaceOrControl(value string) bool {
	for _, r := range value {
		if r <= 0x1f || r == 0x7f || strings.ContainsRune(" \t\n\r", r) {
			return true
		}
	}
	return false
}

func validateRootOnlyFile(fileSystem FileSystem, label string, path string) error {
	info, err := fileSystem.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s %s unavailable: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s must not be a symlink", label, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s must be a regular file", label, path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("%s %s must not be empty", label, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s %s must be root-only, for example mode 0600", label, path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("%s %s owner could not be inspected", label, path)
	}
	if uid != 0 {
		return fmt.Errorf("%s %s must be owned by root", label, path)
	}
	if err := validateRootOwnedParents(fileSystem, label, path); err != nil {
		return err
	}
	return nil
}

func validateRootOwnedParents(fileSystem FileSystem, label string, path string) error {
	dir := filepath.Dir(path)
	immediateParent := dir
	for {
		info, err := fileSystem.Lstat(dir)
		if err != nil {
			return fmt.Errorf("%s parent directory %s unavailable: %w", label, dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s parent directory %s must not be a symlink", label, dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s parent path %s must be a directory", label, dir)
		}
		if info.Mode().Perm()&0o022 != 0 && (dir == immediateParent || info.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("%s parent directory %s must not be writable by group or others", label, dir)
		}
		uid, ok := fileOwnerUID(info)
		if !ok {
			return fmt.Errorf("%s parent directory %s owner could not be inspected", label, dir)
		}
		if uid != 0 {
			return fmt.Errorf("%s parent directory %s must be owned by root", label, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func fileOwnerUID(info fs.FileInfo) (uint64, bool) {
	return fileSysUintField(info, "Uid", "UID")
}

func fileSysUintField(info fs.FileInfo, fieldNames ...string) (uint64, bool) {
	sys := reflect.ValueOf(info.Sys())
	if !sys.IsValid() {
		return 0, false
	}
	if sys.Kind() == reflect.Pointer {
		if sys.IsNil() {
			return 0, false
		}
		sys = sys.Elem()
	}
	if sys.Kind() != reflect.Struct {
		return 0, false
	}
	var field reflect.Value
	for _, fieldName := range fieldNames {
		field = sys.FieldByName(fieldName)
		if field.IsValid() {
			break
		}
	}
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value := field.Int()
		if value < 0 {
			return 0, false
		}
		return uint64(value), true
	default:
		return 0, false
	}
}
