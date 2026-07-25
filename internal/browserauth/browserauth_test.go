package browserauth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const validManagedContent = Marker + "\nadmin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"

func TestHashPasswordUsesBcryptWhenHtpasswdAvailable(t *testing.T) {
	if _, err := os.Stat(defaultHtpasswd); err != nil {
		t.Skip(defaultHtpasswd + " is not installed")
	}
	line, err := HashPassword("admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(line, "admin:$2") {
		t.Fatalf("hash line = %q, want bcrypt htpasswd line", line)
	}
	if !strings.Contains(line, "$12$") {
		t.Fatalf("hash line = %q, want bcrypt cost 12", line)
	}
	if strings.Contains(line, "correct horse") {
		t.Fatalf("hash line leaked plaintext password")
	}
}

func TestGeneratedBcryptHtpasswdWorksWithNginxAuthBasic(t *testing.T) {
	nginxPath, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx is not installed")
	}
	if _, err := os.Stat(defaultHtpasswd); err != nil {
		t.Skip(defaultHtpasswd + " is not installed")
	}
	password := "correct horse battery staple"
	hashLine, err := HashPassword("admin", password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	dir := t.TempDir()
	htpasswdPath := filepath.Join(dir, "browser.htpasswd")
	if err := os.WriteFile(htpasswdPath, []byte(Marker+"\n"+hashLine+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(htpasswd) error = %v", err)
	}
	port := freeLocalPort(t)
	confPath := filepath.Join(dir, "nginx.conf")
	conf := fmt.Sprintf(`
pid %s;
error_log %s notice;
events { worker_connections 64; }
http {
    server {
        listen 127.0.0.1:%d;
        location / {
            auth_basic "LanPanel Browser";
            auth_basic_user_file %s;
            return 204;
        }
    }
}
`, filepath.Join(dir, "nginx.pid"), filepath.Join(dir, "nginx.error.log"), port, htpasswdPath)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("WriteFile(nginx.conf) error = %v", err)
	}
	startNginx(t, nginxPath, dir, confPath, port)
	if got := authFixtureStatus(t, port, "", ""); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", got)
	}
	if got := authFixtureStatus(t, port, "admin", "wrong-password"); got != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", got)
	}
	if got := authFixtureStatus(t, port, "admin", password); got != http.StatusNoContent {
		t.Fatalf("correct password status = %d, want 204", got)
	}
}

func TestCreateManagedRejectsWeakHtpasswdOutputBeforeInstall(t *testing.T) {
	dir := secureTempDir(t)
	setManagedRoot(t, dir)
	restoreChown := UnsafeDisableManagedChownForTest()
	t.Cleanup(restoreChown)
	withFakeHtpasswd(t, "admin:$2y$05$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n", 0)

	_, err := CreateManaged(dir, "admin", "admin", "correct horse battery staple")
	if err == nil || !strings.Contains(err.Error(), "cost at least 12") {
		t.Fatalf("CreateManaged() error = %v, want weak bcrypt cost failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "admin.htpasswd")); !os.IsNotExist(statErr) {
		t.Fatalf("target file exists after failed create: %v", statErr)
	}
}

func TestCreateManagedDoesNotOverwriteExistingUnmarkedCredential(t *testing.T) {
	dir := secureTempDir(t)
	setManagedRoot(t, dir)
	restoreChown := UnsafeDisableManagedChownForTest()
	t.Cleanup(restoreChown)
	withFakeHtpasswd(t, "admin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n", 0)
	path := filepath.Join(dir, "admin.htpasswd")
	original := []byte("admin:external-hash\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("WriteFile(existing htpasswd) error = %v", err)
	}

	_, err := CreateManaged(dir, "admin", "admin", "correct horse battery staple")
	if err == nil || !strings.Contains(err.Error(), "already exists; use rotate") {
		t.Fatalf("CreateManaged() error = %v, want existing credential failure", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(existing htpasswd) error = %v", err)
	}
	if string(current) != string(original) {
		t.Fatalf("CreateManaged replaced existing credential\ncurrent=%q\noriginal=%q", current, original)
	}
}

func TestCreateManagedDoesNotOverwriteExistingManagedCredential(t *testing.T) {
	dir := secureTempDir(t)
	setManagedRoot(t, dir)
	restoreChown := UnsafeDisableManagedChownForTest()
	t.Cleanup(restoreChown)
	withFakeHtpasswd(t, "admin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n", 0)
	path := filepath.Join(dir, "admin.htpasswd")
	if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
		t.Fatalf("WriteFile(existing htpasswd) error = %v", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(existing htpasswd) error = %v", err)
	}

	_, err = CreateManaged(dir, "admin", "admin", "correct horse battery staple")
	if err == nil || !strings.Contains(err.Error(), "already exists; use rotate") {
		t.Fatalf("CreateManaged() error = %v, want existing credential failure", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(existing htpasswd) error = %v", err)
	}
	if string(current) != string(original) {
		t.Fatalf("CreateManaged replaced existing credential\ncurrent=%q\noriginal=%q", current, original)
	}
}

func TestRotateManagedReplacesExistingManagedCredential(t *testing.T) {
	dir := secureTempDir(t)
	setManagedRoot(t, dir)
	restoreChown := UnsafeDisableManagedChownForTest()
	t.Cleanup(restoreChown)
	path := filepath.Join(dir, "admin.htpasswd")
	if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
		t.Fatalf("WriteFile(existing htpasswd) error = %v", err)
	}
	rotatedLine := "admin:$2y$12$1234567890123456789012ABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	withFakeHtpasswd(t, rotatedLine, 0)

	credential, err := RotateManaged(path, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("RotateManaged() error = %v", err)
	}
	if credential.HtpasswdPath != path {
		t.Fatalf("RotateManaged() path = %q, want %q", credential.HtpasswdPath, path)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(rotated htpasswd) error = %v", err)
	}
	want := Marker + "\n" + rotatedLine
	if string(current) != want {
		t.Fatalf("RotateManaged() content = %q, want %q", current, want)
	}
}

func TestCreateManagedSetsMinimalDirectoryPermissions(t *testing.T) {
	parent := secureTempDir(t)
	dir := filepath.Join(parent, "browser-auth")
	setManagedRoot(t, dir)
	restoreChown := UnsafeDisableManagedChownForTest()
	t.Cleanup(restoreChown)
	withFakeHtpasswd(t, "admin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n", 0)

	credential, err := CreateManaged(dir, "admin", "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateManaged() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(managed dir) error = %v", err)
	}
	if got := info.Mode().Perm(); got != managedDirMode {
		t.Fatalf("managed dir mode = %04o, want %04o", got, managedDirMode)
	}
	fileInfo, err := os.Stat(credential.HtpasswdPath)
	if err != nil {
		t.Fatalf("Stat(htpasswd) error = %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o640 {
		t.Fatalf("managed htpasswd mode = %04o, want 0640", got)
	}
}

func TestHashPasswordRedactsPasswordFromHtpasswdFailure(t *testing.T) {
	secret := "correct horse battery staple"
	withFakeHtpasswdOutput(t, "", "tool echoed "+secret+"\n", 42)

	_, err := HashPassword("admin", secret)
	if err == nil {
		t.Fatal("HashPassword() error = nil, want htpasswd failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("HashPassword() error leaked password: %v", err)
	}
	if !strings.Contains(err.Error(), Fingerprint(secret)) {
		t.Fatalf("HashPassword() error = %v, want redacted fingerprint", err)
	}
}

func TestRotateManagedRejectsWeakHtpasswdOutputWithoutReplacingExistingFile(t *testing.T) {
	dir := secureTempDir(t)
	setManagedRoot(t, dir)
	path := filepath.Join(dir, "admin.htpasswd")
	if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	withFakeHtpasswd(t, "admin:$2y$05$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n", 0)

	_, err = RotateManaged(path, "admin", "correct horse battery staple")
	if err == nil || !strings.Contains(err.Error(), "cost at least 12") {
		t.Fatalf("RotateManaged() error = %v, want weak bcrypt cost failure", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() after rotate error = %v", err)
	}
	if string(current) != string(original) {
		t.Fatalf("RotateManaged replaced existing credential after failed hash\ncurrent=%q\noriginal=%q", current, original)
	}
}

func TestHashPasswordRejectsLeadingHyphenUsername(t *testing.T) {
	t.Parallel()

	if _, err := HashPassword("-admin", "correct horse battery staple"); err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("HashPassword() error = %v, want username validation failure", err)
	}
}

func TestHashPasswordDoesNotUsePATH(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "htpasswd")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf 'admin:$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\\n'\n"), 0o700); err != nil {
		t.Fatalf("WriteFile(fake htpasswd) error = %v", err)
	}
	t.Setenv("PATH", dir)
	previous := htpasswdPath
	htpasswdPath = filepath.Join(dir, "missing-htpasswd")
	t.Cleanup(func() { htpasswdPath = previous })

	_, err := HashPassword("admin", "correct horse battery staple")
	if err == nil || strings.Contains(err.Error(), fake) {
		t.Fatalf("HashPassword() error = %v, want explicit htpasswd path failure without PATH lookup", err)
	}
}

func TestCredentialJSONDoesNotExposePassword(t *testing.T) {
	data, err := json.Marshal(Credential{
		ID:                  "admin",
		Username:            "admin",
		HtpasswdPath:        "/etc/lanpanel/browser-auth/admin.htpasswd",
		Password:            "correct horse battery staple",
		PasswordFingerprint: "sha256:1234",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(data), "correct horse") || strings.Contains(string(data), "Password") {
		t.Fatalf("credential JSON leaked password: %s", data)
	}
}

func TestValidateFileAndDeleteManaged(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	dir, err := os.MkdirTemp(home, ".browserauth-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	setManagedRoot(t, dir)
	path := filepath.Join(dir, "admin.htpasswd")
	if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	policy := FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true}
	if err := ValidateFile(path, policy); err != nil {
		t.Fatalf("ValidateFile() error = %v", err)
	}
	if err := DeleteManaged(path, []string{path}); err == nil {
		t.Fatal("DeleteManaged() error = nil, want referenced credential failure")
	}
	if err := DeleteManaged(path, nil); err != nil {
		t.Fatalf("DeleteManaged() unreferenced error = %v", err)
	}
}

func TestValidateFileRejectsManagedMissingMarker(t *testing.T) {
	dir := secureTempDir(t)
	path := filepath.Join(dir, "admin.htpasswd")
	content := strings.TrimPrefix(validManagedContent, Marker+"\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := ValidateFile(path, FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true})
	if err == nil || !strings.Contains(err.Error(), "missing LanPanel marker") {
		t.Fatalf("ValidateFile() error = %v, want missing marker failure", err)
	}
}

func TestValidateFileRejectsManagedWeakBcryptCost(t *testing.T) {
	dir := secureTempDir(t)
	path := filepath.Join(dir, "weak.htpasswd")
	content := Marker + "\nadmin:$2y$05$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := ValidateFile(path, FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true})
	if err == nil || !strings.Contains(err.Error(), "cost at least 12") {
		t.Fatalf("ValidateFile() error = %v, want weak cost failure", err)
	}
}

func TestValidateFileRejectsManagedExtraCredentialLine(t *testing.T) {
	dir := secureTempDir(t)
	path := filepath.Join(dir, "extra.htpasswd")
	content := validManagedContent + "backup:plain-hash\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := ValidateFile(path, FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true})
	if err == nil || !strings.Contains(err.Error(), "exactly one credential line") {
		t.Fatalf("ValidateFile() error = %v, want extra credential failure", err)
	}
}

func TestValidateFileRejectsUnsafeFilesAndParents(t *testing.T) {
	t.Parallel()

	policy := FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true}

	t.Run("symlink file", func(t *testing.T) {
		t.Parallel()
		dir := secureTempDir(t)
		target := filepath.Join(dir, "target.htpasswd")
		if err := os.WriteFile(target, []byte(validManagedContent), 0o600); err != nil {
			t.Fatalf("WriteFile(target) error = %v", err)
		}
		link := filepath.Join(dir, "admin.htpasswd")
		if err := os.Symlink(filepath.Base(target), link); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
		if err := ValidateFile(link, policy); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
			t.Fatalf("ValidateFile() error = %v, want symlink file refusal", err)
		}
	})

	t.Run("symlink parent", func(t *testing.T) {
		t.Parallel()
		dir := secureTempDir(t)
		targetDir := filepath.Join(dir, "target")
		if err := os.Mkdir(targetDir, 0o700); err != nil {
			t.Fatalf("Mkdir(target) error = %v", err)
		}
		path := filepath.Join(targetDir, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		linkDir := filepath.Join(dir, "link")
		if err := os.Symlink(filepath.Base(targetDir), linkDir); err != nil {
			t.Fatalf("Symlink(parent) error = %v", err)
		}
		if err := ValidateFile(filepath.Join(linkDir, "admin.htpasswd"), policy); err == nil || !strings.Contains(err.Error(), "parent directory") || !strings.Contains(err.Error(), "must not be a symlink") {
			t.Fatalf("ValidateFile() error = %v, want symlink parent refusal", err)
		}
	})

	t.Run("group writable file", func(t *testing.T) {
		t.Parallel()
		dir := secureTempDir(t)
		path := filepath.Join(dir, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o620); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		if err := ValidateFile(path, policy); err == nil || !strings.Contains(err.Error(), "group-writable") {
			t.Fatalf("ValidateFile() error = %v, want group-writable file refusal", err)
		}
	})

	t.Run("world readable file", func(t *testing.T) {
		t.Parallel()
		dir := secureTempDir(t)
		path := filepath.Join(dir, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o604); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		if err := ValidateFile(path, policy); err == nil || !strings.Contains(err.Error(), "accessible by others") {
			t.Fatalf("ValidateFile() error = %v, want world-readable file refusal", err)
		}
	})

	t.Run("group writable parent", func(t *testing.T) {
		t.Parallel()
		dir := secureTempDir(t)
		parent := filepath.Join(dir, "unsafe")
		if err := os.Mkdir(parent, 0o777); err != nil {
			t.Fatalf("Mkdir(parent) error = %v", err)
		}
		path := filepath.Join(parent, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		if err := ValidateFile(path, policy); err == nil || !strings.Contains(err.Error(), "parent directory") || !strings.Contains(err.Error(), "writable by group or others") {
			t.Fatalf("ValidateFile() error = %v, want writable parent refusal", err)
		}
	})

	t.Run("wrong owner", func(t *testing.T) {
		t.Parallel()
		dir := secureTempDir(t)
		path := filepath.Join(dir, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		policy := FilePolicy{ExpectedUID: uint32(os.Geteuid()) + 1, RequireMarker: true}
		if err := ValidateFile(path, policy); err == nil || !strings.Contains(err.Error(), "owner uid") {
			t.Fatalf("ValidateFile() error = %v, want owner mismatch refusal", err)
		}
	})
}

func TestValidateFileExternalPolicyAllowsUnmarkedCredentialLine(t *testing.T) {
	t.Parallel()

	dir := secureTempDir(t)
	path := filepath.Join(dir, "external.htpasswd")
	if err := os.WriteFile(path, []byte("admin:external-hash\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(path) error = %v", err)
	}
	externalPolicy := FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: false}
	if err := ValidateFile(path, externalPolicy); err != nil {
		t.Fatalf("ValidateFile(external) error = %v", err)
	}
	managedPolicy := FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true}
	if err := ValidateFile(path, managedPolicy); err == nil || !strings.Contains(err.Error(), "missing LanPanel marker") {
		t.Fatalf("ValidateFile(managed) error = %v, want marker refusal", err)
	}
}

func TestRuntimeReadabilityRequiresSearchableParentsAndReadableFile(t *testing.T) {
	t.Parallel()

	runtimeUID := uint32(os.Geteuid()) + 1
	runtimeGID := uint32(os.Getegid())

	t.Run("searchable group path passes", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		makeRuntimeSearchableAncestors(t, dir)
		parent := filepath.Join(dir, "lanpanel")
		managed := filepath.Join(parent, "browser-auth")
		if err := os.Mkdir(parent, 0o710); err != nil {
			t.Fatalf("Mkdir(parent) error = %v", err)
		}
		if err := os.Mkdir(managed, 0o710); err != nil {
			t.Fatalf("Mkdir(managed) error = %v", err)
		}
		path := filepath.Join(managed, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o640); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		if err := validateRuntimeReadableFile(path, runtimeUID, runtimeGID); err != nil {
			t.Fatalf("validateRuntimeReadableFile() error = %v", err)
		}
	})

	t.Run("hidden parent fails", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		makeRuntimeSearchableAncestors(t, dir)
		parent := filepath.Join(dir, "lanpanel")
		managed := filepath.Join(parent, "browser-auth")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatalf("Mkdir(parent) error = %v", err)
		}
		if err := os.Mkdir(managed, 0o710); err != nil {
			t.Fatalf("Mkdir(managed) error = %v", err)
		}
		path := filepath.Join(managed, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o640); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		err := validateRuntimeReadableFile(path, runtimeUID, runtimeGID)
		if err == nil || !strings.Contains(err.Error(), "must be searchable by nginx runtime user") {
			t.Fatalf("validateRuntimeReadableFile() error = %v, want searchable parent failure", err)
		}
	})

	t.Run("group-unreadable file fails", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		makeRuntimeSearchableAncestors(t, dir)
		path := filepath.Join(dir, "admin.htpasswd")
		if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
			t.Fatalf("WriteFile(path) error = %v", err)
		}
		err := validateRuntimeReadableFile(path, runtimeUID, runtimeGID)
		if err == nil || !strings.Contains(err.Error(), "must be readable by nginx runtime user") {
			t.Fatalf("validateRuntimeReadableFile() error = %v, want file readability failure", err)
		}
	})
}

func TestCreateManagedRejectsUnsafeCredentialIDBeforeHashing(t *testing.T) {
	_, err := CreateManaged("/tmp/browserauth", "../escape", "admin", "correct horse battery staple")
	if err == nil || !strings.Contains(err.Error(), "credential id") {
		t.Fatalf("CreateManaged() error = %v, want credential id failure", err)
	}
}

func TestManagedOperationsRejectOutsideManagedRoot(t *testing.T) {
	dir := secureTempDir(t)
	path := filepath.Join(dir, "admin.htpasswd")
	if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := CreateManaged(dir, "admin", "admin", "correct horse battery staple"); err == nil || !strings.Contains(err.Error(), "managed directory") {
		t.Fatalf("CreateManaged() error = %v, want managed root failure", err)
	}
	if _, err := RotateManaged(path, "admin", "correct horse battery staple"); err == nil || !strings.Contains(err.Error(), "direct child") {
		t.Fatalf("RotateManaged() error = %v, want managed root failure", err)
	}
	if err := DeleteManaged(path, nil); err == nil || !strings.Contains(err.Error(), "direct child") {
		t.Fatalf("DeleteManaged() error = %v, want managed root failure", err)
	}
}

func TestManagedOperationsRejectNonHtpasswdPath(t *testing.T) {
	dir := secureTempDir(t)
	setManagedRoot(t, dir)
	path := filepath.Join(dir, "admin.backup")
	if err := os.WriteFile(path, []byte(validManagedContent), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := RotateManaged(path, "admin", "correct horse battery staple"); err == nil || !strings.Contains(err.Error(), "end with .htpasswd") {
		t.Fatalf("RotateManaged() error = %v, want suffix failure", err)
	}
	if err := DeleteManaged(path, nil); err == nil || !strings.Contains(err.Error(), "end with .htpasswd") {
		t.Fatalf("DeleteManaged() error = %v, want suffix failure", err)
	}
}

func TestValidateFileRejectsManagedUnsupportedBcryptPrefix(t *testing.T) {
	dir := secureTempDir(t)
	path := filepath.Join(dir, "bad-prefix.htpasswd")
	content := Marker + "\nadmin:$2x$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12345\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := ValidateFile(path, FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true})
	if err == nil || !strings.Contains(err.Error(), "valid bcrypt") {
		t.Fatalf("ValidateFile() error = %v, want invalid bcrypt failure", err)
	}
}

func TestValidateFileRejectsManagedTruncatedBcryptHash(t *testing.T) {
	dir := secureTempDir(t)
	path := filepath.Join(dir, "short.htpasswd")
	content := Marker + "\nadmin:$2y$12$short\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := ValidateFile(path, FilePolicy{ExpectedUID: uint32(os.Geteuid()), RequireMarker: true})
	if err == nil || !strings.Contains(err.Error(), "valid bcrypt") {
		t.Fatalf("ValidateFile() error = %v, want invalid bcrypt failure", err)
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	dir, err := os.MkdirTemp(home, ".browserauth-test-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func setManagedRoot(t *testing.T, root string) {
	t.Helper()
	previous := managedRoot
	managedRoot = root
	t.Cleanup(func() { managedRoot = previous })
}

func makeRuntimeSearchableAncestors(t *testing.T, path string) {
	t.Helper()
	stop := filepath.Clean(os.TempDir())
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		if dir == stop || dir == filepath.Dir(dir) {
			return
		}
		if err := os.Chmod(dir, 0o710); err != nil {
			t.Fatalf("Chmod(%s) error = %v", dir, err)
		}
	}
}

func withFakeHtpasswd(t *testing.T, output string, exitCode int) {
	t.Helper()
	withFakeHtpasswdOutput(t, output, "", exitCode)
}

func withFakeHtpasswdOutput(t *testing.T, stdout string, stderr string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat >/dev/null\nprintf '%s' " + shellQuote(stdout) + "\nprintf '%s' " + shellQuote(stderr) + " >&2\nexit " + strconv.Itoa(exitCode) + "\n"
	path := filepath.Join(dir, "htpasswd")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile(fake htpasswd) error = %v", err)
	}
	previous := htpasswdPath
	htpasswdPath = path
	t.Cleanup(func() { htpasswdPath = previous })
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func startNginx(t *testing.T, nginxPath string, prefix string, confPath string, port int) {
	t.Helper()
	output, err := exec.Command(nginxPath, "-p", prefix, "-c", confPath).CombinedOutput()
	if err != nil {
		t.Fatalf("start nginx fixture: %v\n%s", err, string(output))
	}
	t.Cleanup(func() {
		_ = exec.Command(nginxPath, "-p", prefix, "-c", confPath, "-s", "quit").Run()
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nginx fixture did not open port %d: %v", port, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func authFixtureStatus(t *testing.T, port int, username string, password string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if username != "" || password != "" {
		request.SetBasicAuth(username, password)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("auth fixture request error = %v", err)
	}
	defer response.Body.Close()
	return response.StatusCode
}
