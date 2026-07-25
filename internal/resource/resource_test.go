package resource

import (
	"encoding/json"
	"errors"
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func secureResourceTempDir(t *testing.T) string {
	t.Helper()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	dir, err := os.MkdirTemp(home, ".lanpanel-resource-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	return dir
}

func TestLoadOrCreateInstancePersistsStableID(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	store := NewStore(dir)
	first, err := store.LoadOrCreateInstance()
	if err != nil {
		t.Fatalf("LoadOrCreateInstance() error = %v", err)
	}
	second, err := store.LoadOrCreateInstance()
	if err != nil {
		t.Fatalf("LoadOrCreateInstance() second error = %v", err)
	}
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("instance IDs = %q, %q; want stable non-empty ID", first.ID, second.ID)
	}
	if first.SchemaVersion != domain.InstanceSchemaVersion || second.SchemaVersion != domain.InstanceSchemaVersion {
		t.Fatalf("schema versions = %q, %q; want %q", first.SchemaVersion, second.SchemaVersion, domain.InstanceSchemaVersion)
	}
	data, err := os.ReadFile(filepath.Join(dir, instanceIDFileName))
	if err != nil {
		t.Fatalf("ReadFile(instance_id) error = %v", err)
	}
	var stored Instance
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("Unmarshal(instance_id) error = %v; data = %q", err, data)
	}
	if stored.SchemaVersion != domain.InstanceSchemaVersion || stored.ID != first.ID {
		t.Fatalf("stored instance = %#v, want schema %q and id %q", stored, domain.InstanceSchemaVersion, first.ID)
	}
}

func TestLoadInstanceDoesNotCreateState(t *testing.T) {
	t.Parallel()

	parent := secureResourceTempDir(t)
	dir := filepath.Join(parent, "resources")
	if _, err := NewStore(dir).LoadInstance(); !errors.Is(err, ErrInstanceNotFound) {
		t.Fatalf("LoadInstance() error = %v, want ErrInstanceNotFound", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("resource dir stat error = %v, want no directory created", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if _, err := NewStore(dir).LoadInstance(); !errors.Is(err, ErrInstanceNotFound) {
		t.Fatalf("LoadInstance() empty dir error = %v, want ErrInstanceNotFound", err)
	}
	if _, err := os.Stat(filepath.Join(dir, instanceIDFileName)); !os.IsNotExist(err) {
		t.Fatalf("instance_id stat error = %v, want no file created", err)
	}
}

func TestResourceIDIsStableAndInstanceScoped(t *testing.T) {
	t.Parallel()

	first, err := ResourceID("ins_00112233445566778899aabbccddeeff", domain.ResourceTypeHTTPApp, "api")
	if err != nil {
		t.Fatalf("ResourceID() error = %v", err)
	}
	again, err := ResourceID("ins_00112233445566778899aabbccddeeff", domain.ResourceTypeHTTPApp, "api")
	if err != nil {
		t.Fatalf("ResourceID() again error = %v", err)
	}
	other, err := ResourceID("ins_ffeeddccbbaa99887766554433221100", domain.ResourceTypeHTTPApp, "api")
	if err != nil {
		t.Fatalf("ResourceID() other error = %v", err)
	}
	if first != again {
		t.Fatalf("ResourceID stable = %q, %q", first, again)
	}
	if first != "res_2bb76e0e928f57cde54234e1782b0705" {
		t.Fatalf("ResourceID test vector = %q", first)
	}
	if first == other {
		t.Fatalf("ResourceID must differ across instances")
	}
}

func TestResourceIDRejectsNonCanonicalInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		instanceID    string
		resourceType  domain.ResourceType
		canonicalName string
	}{
		{
			name:          "uppercase instance id",
			instanceID:    "ins_00112233445566778899AABBCCDDEEFF",
			resourceType:  domain.ResourceTypeHTTPApp,
			canonicalName: "api",
		},
		{
			name:          "unsupported resource type",
			instanceID:    "ins_00112233445566778899aabbccddeeff",
			resourceType:  domain.ResourceType("app"),
			canonicalName: "api",
		},
		{
			name:          "p1 private endpoint resource type",
			instanceID:    "ins_00112233445566778899aabbccddeeff",
			resourceType:  domain.ResourceTypePrivateEndpoint,
			canonicalName: "db",
		},
		{
			name:          "p1 private host resource type",
			instanceID:    "ins_00112233445566778899aabbccddeeff",
			resourceType:  domain.ResourceTypePrivateHost,
			canonicalName: "host",
		},
		{
			name:          "p1 private network service resource type",
			instanceID:    "ins_00112233445566778899aabbccddeeff",
			resourceType:  domain.ResourceTypePrivateNetworkService,
			canonicalName: "ssh",
		},
		{
			name:          "nul canonical name",
			instanceID:    "ins_00112233445566778899aabbccddeeff",
			resourceType:  domain.ResourceTypeHTTPApp,
			canonicalName: "api\x00public",
		},
		{
			name:          "uppercase canonical name",
			instanceID:    "ins_00112233445566778899aabbccddeeff",
			resourceType:  domain.ResourceTypeHTTPApp,
			canonicalName: "API",
		},
		{
			name:          "spaced canonical name",
			instanceID:    "ins_00112233445566778899aabbccddeeff",
			resourceType:  domain.ResourceTypeHTTPApp,
			canonicalName: "api v1",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ResourceID(tt.instanceID, tt.resourceType, tt.canonicalName); err == nil {
				t.Fatal("ResourceID() error = nil, want non-canonical input failure")
			}
		})
	}
}

func TestLoadOrCreateInstanceHandlesConcurrentFirstUse(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	store := NewStore(dir)
	const callers = 8
	instances := make([]Instance, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			instances[i], errs[i] = store.LoadOrCreateInstance()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("LoadOrCreateInstance() caller %d error = %v", i, err)
		}
	}
	for i := 1; i < callers; i++ {
		if instances[i].ID != instances[0].ID {
			t.Fatalf("instances[%d].ID = %q, want %q", i, instances[i].ID, instances[0].ID)
		}
	}
}

func TestLoadOrCreateInstanceRejectsInvalidStoredID(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	data, err := marshalInstance(Instance{SchemaVersion: domain.InstanceSchemaVersion, ID: "ins_00112233445566778899aabbccddeeff"})
	if err != nil {
		t.Fatalf("marshalInstance() error = %v", err)
	}
	data = []byte(strings.Replace(string(data), "ins_00112233445566778899aabbccddeeff", "bad", 1))
	if err := os.WriteFile(filepath.Join(dir, instanceIDFileName), data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := NewStore(dir).LoadOrCreateInstance(); err == nil {
		t.Fatal("LoadOrCreateInstance() error = nil, want invalid stored ID failure")
	}
}

func TestLoadOrCreateInstanceRejectsLegacyRawInstanceID(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, instanceIDFileName), []byte("ins_00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := NewStore(dir).LoadOrCreateInstance(); err == nil || !strings.Contains(err.Error(), "parse instance_id record") {
		t.Fatalf("LoadOrCreateInstance() error = %v, want legacy raw instance_id refusal", err)
	}
}

func TestLoadOrCreateInstanceRejectsUnsupportedInstanceSchema(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	data := []byte(`{"schema_version":"lanpanel.instance.v2","instance_id":"ins_00112233445566778899aabbccddeeff"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, instanceIDFileName), data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := NewStore(dir).LoadOrCreateInstance(); err == nil || !strings.Contains(err.Error(), "unsupported instance_id schema_version") {
		t.Fatalf("LoadOrCreateInstance() error = %v, want unsupported schema refusal", err)
	}
}

func TestLoadOrCreateInstanceRejectsUnsafeStateDir(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(dir, 0o722); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := NewStore(dir).LoadOrCreateInstance(); err == nil {
		t.Fatal("LoadOrCreateInstance() error = nil, want unsafe dir failure")
	}
}

func TestStoreRejectsSymlinkStatePathParent(t *testing.T) {
	t.Parallel()

	dir := secureResourceTempDir(t)
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := NewStore(filepath.Join(link, "created")).LoadOrCreateInstance(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("LoadOrCreateInstance() error = %v, want symlink parent refusal", err)
	}
	if _, err := NewStore(filepath.Join(link, "missing")).LoadInstance(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("LoadInstance() missing path error = %v, want symlink parent refusal", err)
	}

	existing := filepath.Join(target, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatalf("Mkdir(existing) error = %v", err)
	}
	if _, err := NewStore(filepath.Join(link, "existing")).LoadInstance(); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("LoadInstance() error = %v, want symlink parent refusal", err)
	}
}

func TestStoreRejectsWritableStatePathParent(t *testing.T) {
	t.Parallel()

	dir := secureResourceTempDir(t)
	writable := filepath.Join(dir, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatalf("Mkdir(writable) error = %v", err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatalf("Chmod(writable) error = %v", err)
	}
	if _, err := NewStore(filepath.Join(writable, "created")).LoadOrCreateInstance(); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("LoadOrCreateInstance() error = %v, want writable parent refusal", err)
	}

	existing := filepath.Join(writable, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatalf("Mkdir(existing) error = %v", err)
	}
	if _, err := NewStore(existing).LoadInstance(); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("LoadInstance() error = %v, want writable parent refusal", err)
	}
}

func TestStoreRejectsRelativePathFromWritableWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Chdir(dir)

	if _, err := NewStore("resources").LoadOrCreateInstance(); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("LoadOrCreateInstance() error = %v, want writable cwd refusal", err)
	}
	if _, err := NewStore("resources").LoadInstance(); err == nil || !strings.Contains(err.Error(), "must not be writable by group or others") {
		t.Fatalf("LoadInstance() error = %v, want writable cwd refusal", err)
	}
}

func TestStoreRejectsWhitespacePaddedPath(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	if _, err := NewStore(dir + " ").LoadOrCreateInstance(); err == nil || !strings.Contains(err.Error(), "clean path") {
		t.Fatalf("LoadOrCreateInstance() error = %v, want clean path refusal", err)
	}
	if _, err := NewStore(" " + dir).LoadInstance(); err == nil || !strings.Contains(err.Error(), "clean path") {
		t.Fatalf("LoadInstance() error = %v, want clean path refusal", err)
	}
}

func TestLoadOrCreateInstanceRejectsSymlinkInstanceID(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("ins_00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, instanceIDFileName)); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := NewStore(dir).LoadOrCreateInstance(); err == nil {
		t.Fatal("LoadOrCreateInstance() error = nil, want symlink instance_id failure")
	}
}

func TestLoadOrCreateInstanceRejectsUnsafeInstanceIDMode(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(secureResourceTempDir(t), "resources")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	path := filepath.Join(dir, instanceIDFileName)
	if err := os.WriteFile(path, []byte("ins_00112233445566778899aabbccddeeff\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := NewStore(dir).LoadOrCreateInstance(); err == nil {
		t.Fatal("LoadOrCreateInstance() error = nil, want unsafe instance_id mode failure")
	}
}

func TestWriteNewFileDoesNotOverwriteExistingFinalFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, instanceIDFileName)
	original := []byte("ins_00112233445566778899aabbccddeeff\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := writeNewFile(path, []byte("ins_ffeeddccbbaa99887766554433221100\n"), 0o600); !os.IsExist(err) {
		t.Fatalf("writeNewFile() error = %v, want exists", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("final instance_id = %q, want original %q", got, original)
	}
	assertNoInstanceIDTemps(t, dir)
}

func TestWriteNewFileCleansTempOnPublishFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, instanceIDFileName)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := writeNewFile(path, []byte("ins_00112233445566778899aabbccddeeff\n"), 0o600); err == nil {
		t.Fatal("writeNewFile() error = nil, want publish failure")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("publish failure replaced final path with mode %s", info.Mode())
	}
	assertNoInstanceIDTemps(t, dir)
}

func assertNoInstanceIDTemps(t *testing.T, dir string) {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(dir, "."+instanceIDFileName+".tmp.*"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary instance_id files remain: %v", matches)
	}
}
