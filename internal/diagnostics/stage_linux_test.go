//go:build linux

package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordCertificateStageIsRedactedAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stages.jsonl")
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
	if err := recordCertificateStage(path, job, "provider-output", "failed"); err == nil {
		t.Fatal("accepted unbounded stage")
	}
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
