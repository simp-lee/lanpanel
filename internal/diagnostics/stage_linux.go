//go:build linux

package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	"golang.org/x/sys/unix"
)

const CertificateStageLog = "/var/log/lanpanel/certificate-stages.jsonl"

var certificateJobID = regexp.MustCompile(`^job_[0-9a-f]{64}$`)

type CertificateStage struct {
	At                time.Time `json:"at"`
	JobID             string    `json:"job_id"`
	Stage             string    `json:"stage"`
	Outcome           string    `json:"outcome"`
	ErrorClass        string    `json:"error_class,omitempty"`
	RetryAfterSeconds int64     `json:"retry_after_seconds,omitempty"`
}

// RecordCertificateStage retains only fixed stage names and outcomes, never
// provider output, account material, challenge tokens or request bodies.
func RecordCertificateStage(jobID, stage, outcome string) error {
	return recordCertificateStage(CertificateStageLog, jobID, stage, outcome)
}

// RecordCertificateStageError adds a bounded error classification and ACME
// Retry-After duration without persisting provider output or request data.
func RecordCertificateStageError(jobID, stage, outcome string, cause error) error {
	return recordCertificateStageError(CertificateStageLog, jobID, stage, outcome, cause)
}

func recordCertificateStage(path, jobID, stage, outcome string) error {
	return recordCertificateStageError(path, jobID, stage, outcome, nil)
}

func recordCertificateStageError(path, jobID, stage, outcome string, cause error) error {
	if !certificateJobID.MatchString(jobID) || !validCertificateStage(stage, outcome) {
		return fmt.Errorf("certificate stage diagnostic identity invalid")
	}
	errorClass, retryAfter := certificateErrorMetadata(cause)
	data, err := json.Marshal(CertificateStage{At: time.Now().UTC(), JobID: jobID, Stage: stage, Outcome: outcome, ErrorClass: errorClass, RetryAfterSeconds: retryAfter})
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.Mkdir(directory, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	var directoryStat unix.Stat_t
	if err := unix.Lstat(directory, &directoryStat); err != nil || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Gid != uint32(os.Getegid()) {
		return fmt.Errorf("certificate stage diagnostic directory is unsafe")
	}
	mode := directoryStat.Mode & 0o7777
	if mode != 0o700 && mode != 0o711 {
		return fmt.Errorf("certificate stage diagnostic directory is unsafe")
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	var fileStat unix.Stat_t
	if err := unix.Fstat(fd, &fileStat); err != nil || fileStat.Mode&unix.S_IFMT != unix.S_IFREG || fileStat.Nlink != 1 || fileStat.Uid != uint32(os.Geteuid()) || fileStat.Gid != uint32(os.Getegid()) || fileStat.Mode&0o7777 != 0o600 {
		_ = unix.Close(fd)
		return fmt.Errorf("certificate stage diagnostic file is unsafe")
	}
	file := os.NewFile(uintptr(fd), path)
	_, writeErr := file.Write(append(data, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func certificateErrorMetadata(cause error) (string, int64) {
	if cause == nil {
		return "", 0
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return "deadline", 0
	}
	if errors.Is(cause, context.Canceled) {
		return "canceled", 0
	}
	var apiErr *xacme.Error
	if errors.As(cause, &apiErr) {
		if retryAfter, limited := xacme.RateLimit(apiErr); limited {
			seconds := int64(0)
			if retryAfter > 0 {
				seconds = int64((retryAfter + time.Second - 1) / time.Second)
			}
			return "rate_limited", seconds
		}
		switch strings.ToLower(apiErr.ProblemType) {
		case "urn:ietf:params:acme:error:unauthorized", "urn:ietf:params:acme:error:connection", "urn:ietf:params:acme:error:dns", "urn:ietf:params:acme:error:tls":
			return "authorization_failed", 0
		case "urn:ietf:params:acme:error:badnonce", "urn:ietf:params:acme:error:serverinternal":
			return "provider_retryable", 0
		default:
			return "acme_failed", 0
		}
	}
	var authorizationErr *xacme.AuthorizationError
	if errors.As(cause, &authorizationErr) {
		return "authorization_failed", 0
	}
	var orderErr *xacme.OrderError
	if errors.As(cause, &orderErr) {
		return "order_failed", 0
	}
	return "internal_failed", 0
}

func validCertificateStage(stage, outcome string) bool {
	switch outcome {
	case "started", "succeeded", "failed", "deadline", "interrupted":
	default:
		return false
	}
	switch stage {
	case "challenge", "acme", "child_terminal", "issued_material", "certificate_staging", "publication_handoff", "nginx_graph", "nginx_dump", "nginx_test", "nginx_reload", "nginx_listeners", "upstream_probe", "abort", "job_terminal":
		return true
	}
	return false
}
