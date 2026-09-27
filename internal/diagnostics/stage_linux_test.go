//go:build linux

package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordCertificateStageIsRedactedAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lanpanel", "stages.jsonl")
	job := "job_" + strings.Repeat("a", 64)
	if err := recordCertificateStage(path, job, "nginx_test", "failed"); err != nil {
		t.Fatal(err)
	}
	data, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"stage":"nginx_test"`) || strings.Contains(string(data), "secret") {
		t.Fatalf("unexpected diagnostic=%q", data)
	}
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("diagnostic directory mode=%v", directory.Mode())
	}
	file, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if file.Mode().Perm() != 0o600 {
		t.Fatalf("diagnostic file mode=%v", file.Mode())
	}
	if err := recordCertificateStage(path, job, "provider-output", "failed"); err == nil {
		t.Fatal("accepted unbounded stage")
	}
}

func TestRecordCertificateStageRejectsUnsafeDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "lanpanel")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "stages.jsonl")
	job := "job_" + strings.Repeat("b", 64)
	if err := recordCertificateStage(path, job, "nginx_test", "failed"); err == nil {
		t.Fatal("accepted unsafe diagnostic directory")
	}
	if err := os.Chmod(directory, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := recordCertificateStage(path, job, "nginx_test", "failed"); err != nil {
		t.Fatalf("rejected installer diagnostic directory: %v", err)
	}
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
