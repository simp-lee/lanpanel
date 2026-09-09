package qualification

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

// BuildSummary accepts only the exact Prepared authority and a cleanup report
// that independently passes the final cleanup verifier.
func BuildSummary(prepared Prepared, report release.LiveCleanupReport, completedAt time.Time) ([]byte, error) {
	reportBytes, err := release.MarshalCanonical(report)
	if err != nil {
		return nil, err
	}
	attestationBytes, _, err := readProtectedFile(prepared.Input.Artifacts.ExecutorAttestation, 4<<20, true)
	if err != nil {
		return nil, err
	}
	verified, attestation, err := release.VerifyLiveCleanup(prepared.PlanBytes, reportBytes, attestationBytes, prepared.InstallManifestDigest, prepared.InputDigest)
	if err != nil || !reflect.DeepEqual(verified, report) {
		return nil, fmt.Errorf("qualification summary requires verified final readiness: %w", err)
	}
	if !completedAt.Equal(completedAt.UTC().Truncate(time.Second)) || completedAt.Before(report.UpdatedAt) {
		return nil, fmt.Errorf("qualification summary completion time is invalid")
	}
	providers := []release.ProviderLiveTest{}
	for _, name := range []string{"cloudflare", "digitalocean", "gcloud", "route53", "tencentcloud"} {
		status := "not_live_tested"
		if name == prepared.Input.DNS.Provider {
			status = "live_tested"
		}
		providers = append(providers, release.ProviderLiveTest{Provider: name, Status: status})
	}
	installIdentity := prepared.Install.Identity()
	summary := release.QualificationSummary{SchemaVersion: release.QualificationSummarySchemaVersion, RunID: prepared.Input.RunID, CandidateDigest: installIdentity.CandidateDigest, SourceTreeDigest: prepared.SourceDigest, TargetProfileDigest: installIdentity.ProfileDigest, JourneySucceeded: true, TailnetLiveStatus: attestation.TailnetLiveStatus, ProviderLiveTests: append([]release.ProviderLiveTest(nil), providers...), CompletedAt: completedAt}
	encoded, err := release.MarshalCanonical(summary)
	if err != nil {
		return nil, err
	}
	if _, err := release.DecodeQualificationSummary(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func WriteQualificationSummary(path string, data []byte) error {
	if err := WriteSummary(path, data); err != nil {
		return err
	}
	return sealProtectedFile(path)
}

func sealProtectedFile(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("protected artifact descriptor is invalid")
	}
	chmodErr := file.Chmod(0o400)
	closeErr := file.Close()
	return errors.Join(chmodErr, closeErr)
}

func WriteSummary(path string, data []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(data) == 0 {
		return fmt.Errorf("qualification summary path or bytes are invalid")
	}
	if existing, _, err := readProtectedFile(path, 4<<20, false); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("existing qualification summary differs")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	parent, name := filepath.Dir(path), filepath.Base(path)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	var parentStat unix.Stat_t
	if unix.Fstat(parentFD, &parentStat) != nil || parentStat.Uid != uint32(os.Geteuid()) || parentStat.Mode&0o077 != 0 {
		return fmt.Errorf("qualification summary parent is unsafe")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(nonce[:])
	output, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(output), temporary)
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	writeErr := error(nil)
	if _, writeErr = file.Write(data); writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	if err := unix.Renameat2(parentFD, temporary, parentFD, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	cleanup = false
	return unix.Fsync(parentFD)
}
