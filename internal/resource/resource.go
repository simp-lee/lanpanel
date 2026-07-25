// Package resource provides stable local instance and resource identifiers.
package resource

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
)

const instanceIDFileName = "instance_id"
const resourceIDDomain = "lanpanel.resource.v1"

var ErrInstanceNotFound = errors.New("instance_id is not initialized")

type Instance struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"instance_id"`
}

type Store struct {
	dir string
}

func NewStore(dir string) Store {
	return Store{dir: dir}
}

func (store Store) LoadInstance() (Instance, error) {
	if store.dir == "" {
		return Instance{}, fmt.Errorf("resource state dir is required")
	}
	if err := checkStatePathParents(store.dir); err != nil {
		return Instance{}, err
	}
	if _, err := os.Lstat(store.dir); err != nil {
		if os.IsNotExist(err) {
			return Instance{}, ErrInstanceNotFound
		}
		return Instance{}, fmt.Errorf("inspect resource state dir %s: %w", store.dir, err)
	}
	if err := checkStateDir(store.dir); err != nil {
		return Instance{}, err
	}
	path := filepath.Join(store.dir, instanceIDFileName)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Instance{}, ErrInstanceNotFound
		}
		return Instance{}, fmt.Errorf("inspect instance_id: %w", err)
	}
	if err := checkInstanceIDFile(path, info); err != nil {
		return Instance{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Instance{}, fmt.Errorf("read instance_id: %w", err)
	}
	return instanceFromData(path, data)
}

func (store Store) LoadOrCreateInstance() (Instance, error) {
	if store.dir == "" {
		return Instance{}, fmt.Errorf("resource state dir is required")
	}
	if err := checkStatePathParents(store.dir); err != nil {
		return Instance{}, err
	}
	if err := os.MkdirAll(store.dir, 0o700); err != nil {
		return Instance{}, fmt.Errorf("create resource state dir: %w", err)
	}
	if err := checkStateDir(store.dir); err != nil {
		return Instance{}, err
	}
	path := filepath.Join(store.dir, instanceIDFileName)
	info, err := os.Lstat(path)
	if err == nil {
		if err := checkInstanceIDFile(path, info); err != nil {
			return Instance{}, err
		}
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return instanceFromData(path, data)
	}
	if !os.IsNotExist(err) {
		return Instance{}, fmt.Errorf("read instance_id: %w", err)
	}
	id, err := newInstanceID()
	if err != nil {
		return Instance{}, err
	}
	recordData, err := marshalInstance(Instance{SchemaVersion: domain.InstanceSchemaVersion, ID: id})
	if err != nil {
		return Instance{}, err
	}
	if err := writeNewFile(path, recordData, 0o600); err != nil {
		if os.IsExist(err) {
			info, statErr := os.Lstat(path)
			if statErr != nil {
				return Instance{}, fmt.Errorf("inspect concurrently created instance_id: %w", statErr)
			}
			if checkErr := checkInstanceIDFile(path, info); checkErr != nil {
				return Instance{}, checkErr
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return Instance{}, fmt.Errorf("read concurrently created instance_id: %w", readErr)
			}
			return instanceFromData(path, data)
		}
		return Instance{}, fmt.Errorf("write instance_id: %w", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return Instance{}, fmt.Errorf("inspect instance_id: %w", err)
	}
	if err := checkInstanceIDFile(path, info); err != nil {
		return Instance{}, err
	}
	return Instance{SchemaVersion: domain.InstanceSchemaVersion, ID: id}, nil
}

func ResourceID(instanceID string, resourceType domain.ResourceType, canonicalName string) (string, error) {
	if !validInstanceID(instanceID) {
		return "", fmt.Errorf("valid instance_id is required")
	}
	if !validResourceType(resourceType) {
		return "", fmt.Errorf("resource type %q is not supported", resourceType)
	}
	if !validCanonicalName(canonicalName) {
		return "", fmt.Errorf("canonical resource name is required")
	}
	input := strings.Join([]string{resourceIDDomain, instanceID, string(resourceType), canonicalName}, "\x00")
	sum := sha256.Sum256([]byte(input))
	return "res_" + hex.EncodeToString(sum[:16]), nil
}

func instanceFromData(path string, data []byte) (Instance, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var instance Instance
	if err := decoder.Decode(&instance); err != nil {
		return Instance{}, fmt.Errorf("parse instance_id record %s: %w", path, err)
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return Instance{}, fmt.Errorf("parse instance_id record %s: multiple JSON values are not supported", path)
	}
	if instance.SchemaVersion != domain.InstanceSchemaVersion {
		return Instance{}, fmt.Errorf("unsupported instance_id schema_version %q in %s", instance.SchemaVersion, path)
	}
	if !validInstanceID(instance.ID) {
		return Instance{}, fmt.Errorf("invalid instance_id in %s", path)
	}
	return instance, nil
}

func marshalInstance(instance Instance) ([]byte, error) {
	if instance.SchemaVersion != domain.InstanceSchemaVersion {
		return nil, fmt.Errorf("unsupported instance schema_version %q", instance.SchemaVersion)
	}
	if !validInstanceID(instance.ID) {
		return nil, fmt.Errorf("valid instance_id is required")
	}
	data, err := json.Marshal(instance)
	if err != nil {
		return nil, fmt.Errorf("marshal instance_id record: %w", err)
	}
	return append(data, '\n'), nil
}

func newInstanceID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate instance_id: %w", err)
	}
	return "ins_" + hex.EncodeToString(bytes[:]), nil
}

func validInstanceID(id string) bool {
	if id != strings.TrimSpace(id) || id != strings.ToLower(id) {
		return false
	}
	if len(id) != len("ins_")+32 || !strings.HasPrefix(id, "ins_") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, "ins_"))
	return err == nil
}

func validResourceType(resourceType domain.ResourceType) bool {
	if string(resourceType) != strings.TrimSpace(string(resourceType)) {
		return false
	}
	switch resourceType {
	case domain.ResourceTypeHTTPApp,
		domain.ResourceTypeWebSocketApp:
		return true
	default:
		return false
	}
}

func validCanonicalName(name string) bool {
	if name == "" || name != strings.TrimSpace(name) || name != strings.ToLower(name) {
		return false
	}
	for _, r := range name {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return false
		}
	}
	return true
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	var lastErr error
	for i := 0; i < 8; i++ {
		tmp, err := tempPath(dir, filepath.Base(path))
		if err != nil {
			return err
		}
		if err := writeTempFile(tmp, data, mode); err != nil {
			lastErr = err
			continue
		}
		if err := os.Link(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Remove(tmp); err != nil {
			return fmt.Errorf("remove temporary instance_id file: %w", err)
		}
		if err := syncDir(dir); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("create temporary instance_id file: %w", lastErr)
}

func tempPath(dir, base string) (string, error) {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate temporary instance_id name: %w", err)
	}
	return filepath.Join(dir, "."+base+".tmp."+hex.EncodeToString(bytes[:])), nil
}

func writeTempFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	n, err := file.Write(data)
	if err != nil {
		_ = file.Close()
		return err
	}
	if n != len(data) {
		_ = file.Close()
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open resource state dir for sync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync resource state dir: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close resource state dir: %w", err)
	}
	return nil
}

func checkStatePathParents(path string) error {
	trimmed := strings.TrimSpace(path)
	clean := filepath.Clean(trimmed)
	if clean == "." || path != trimmed || clean != trimmed {
		return fmt.Errorf("resource state dir must be a clean path")
	}
	parent := filepath.Dir(clean)
	if parent == "." {
		return checkStatePathComponent(".")
	}
	current := ""
	parts := strings.Split(parent, string(filepath.Separator))
	if filepath.IsAbs(clean) {
		current = string(filepath.Separator)
		parts = strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator))
	} else if err := checkStatePathComponent("."); err != nil {
		return err
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("inspect resource state path component %s: %w", current, err)
		}
		if err := checkStatePathComponentInfo(current, info); err != nil {
			return err
		}
	}
	return nil
}

func checkStatePathComponent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect resource state path component %s: %w", path, err)
	}
	return checkStatePathComponentInfo(path, info)
}

func checkStatePathComponentInfo(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("resource state path component %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("resource state path component %s must be a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("resource state path component %s must not be writable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("resource state path component %s owner could not be inspected", path)
	}
	if stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
		return fmt.Errorf("resource state path component %s owner uid %d does not match effective uid %d or root", path, stat.Uid, os.Geteuid())
	}
	return nil
}

func checkStateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect resource state dir %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("resource state dir %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("resource state path %s must be a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("resource state dir %s must not be writable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("resource state dir %s owner could not be inspected", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("resource state dir %s owner uid %d does not match effective uid %d", path, stat.Uid, os.Geteuid())
	}
	return nil
}

func checkInstanceIDFile(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("instance_id %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("instance_id %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("instance_id %s must not be readable, writable, or executable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("instance_id %s owner could not be inspected", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("instance_id %s owner uid %d does not match effective uid %d", path, stat.Uid, os.Geteuid())
	}
	return nil
}
