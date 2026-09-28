//go:build linux

package diagnostics

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"
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

func TestCertificateErrorMetadataClassifiesRateLimitAndRetryAfter(t *testing.T) {
	cause := &xacme.Error{ProblemType: "urn:ietf:params:acme:error:rateLimited", Header: http.Header{"Retry-After": []string{"120"}}}
	class, retryAfter := certificateErrorMetadata(cause)
	if class != "rate_limited" || retryAfter != 120 {
		t.Fatalf("metadata=%q,%d", class, retryAfter)
	}
	if class, retryAfter := certificateErrorMetadata(&xacme.OrderError{Problem: cause}); class != "rate_limited" || retryAfter != 120 {
		t.Fatalf("order rate-limit metadata=%q,%d", class, retryAfter)
	}
	if class, retryAfter := certificateErrorMetadata(context.DeadlineExceeded); class != "deadline" || retryAfter != 0 {
		t.Fatalf("deadline metadata=%q,%d", class, retryAfter)
	}
	if class, retryAfter := certificateErrorMetadata(context.Canceled); class != "canceled" || retryAfter != 0 {
		t.Fatalf("canceled metadata=%q,%d", class, retryAfter)
	}
}

func TestRecordCertificateStageErrorPersistsOnlyBoundedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lanpanel", "stages.jsonl")
	job := "job_" + strings.Repeat("c", 64)
	cause := &xacme.Error{ProblemType: "urn:ietf:params:acme:error:rateLimited", Header: http.Header{"Retry-After": []string{"1"}}}
	if err := recordCertificateStageError(path, job, "acme", "failed", cause); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value CertificateStage
	if err := json.Unmarshal(data[:len(data)-1], &value); err != nil {
		t.Fatal(err)
	}
	if value.ErrorClass != "rate_limited" || value.RetryAfterSeconds != 1 || strings.Contains(string(data), "rateLimited") {
		t.Fatalf("unexpected bounded diagnostic=%q", data)
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
