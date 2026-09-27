//go:build linux

package diagnostics

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
)

const CertificateStageLog = "/var/log/lanpanel/certificate-stages.jsonl"

var certificateJobID = regexp.MustCompile(`^job_[0-9a-f]{64}$`)

type CertificateStage struct {
	At      time.Time `json:"at"`
	JobID   string    `json:"job_id"`
	Stage   string    `json:"stage"`
	Outcome string    `json:"outcome"`
}

// RecordCertificateStage retains only fixed stage names and outcomes, never
// provider output, account material, challenge tokens or request bodies.
func RecordCertificateStage(jobID, stage, outcome string) error {
	return recordCertificateStage(CertificateStageLog, jobID, stage, outcome)
}

func recordCertificateStage(path, jobID, stage, outcome string) error {
	if !certificateJobID.MatchString(jobID) || !validCertificateStage(stage, outcome) {
		return fmt.Errorf("certificate stage diagnostic identity invalid")
	}
	data, err := json.Marshal(CertificateStage{At: time.Now().UTC(), JobID: jobID, Stage: stage, Outcome: outcome})
	if err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
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
