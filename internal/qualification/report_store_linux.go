//go:build linux

package qualification

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type ProtectedReportStore struct{ Path string }

func (store ProtectedReportStore) Read() (release.LiveCleanupReport, bool, error) {
	data, _, err := readProtectedFile(store.Path, 4<<20, false)
	if os.IsNotExist(err) {
		return release.LiveCleanupReport{}, false, nil
	}
	if err != nil {
		return release.LiveCleanupReport{}, false, err
	}
	value, err := release.DecodeLiveCleanupReport(data)
	return value, err == nil, err
}

func (store ProtectedReportStore) Write(report release.LiveCleanupReport) error {
	encoded, err := release.MarshalCanonical(report)
	if err != nil {
		return err
	}
	if _, err := release.DecodeLiveCleanupReport(encoded); err != nil {
		return err
	}
	if existing, _, readErr := readProtectedFile(store.Path, 4<<20, false); readErr == nil {
		prior, decodeErr := release.DecodeLiveCleanupReport(existing)
		if decodeErr != nil {
			return decodeErr
		}
		if err := validateReportAdvance(prior, report); err != nil {
			return err
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	parentPath, name := filepath.Dir(store.Path), filepath.Base(store.Path)
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	var parent syscall.Stat_t
	if err := syscall.Fstat(parentFD, &parent); err != nil {
		return err
	}
	if uint32(parent.Mode)&syscall.S_IFMT != syscall.S_IFDIR || parent.Uid != uint32(os.Geteuid()) || uint32(parent.Mode)&0o077 != 0 {
		return fmt.Errorf("cleanup report parent authority is unsafe")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, name); err != nil {
		return err
	}
	cleanup = false
	return unix.Fsync(parentFD)
}

func validateReportAdvance(prior, next release.LiveCleanupReport) error {
	if prior.RunID != next.RunID || prior.SideEffectPlanDigest != next.SideEffectPlanDigest || prior.QualificationInstallManifestDigest != next.QualificationInstallManifestDigest || prior.ProtectedInputDigest != next.ProtectedInputDigest || prior.ExecutionFailed && !next.ExecutionFailed || prior.JourneySucceeded && !next.JourneySucceeded || next.UpdatedAt.Before(prior.UpdatedAt) || len(next.Steps) < len(prior.Steps) || len(next.Items) < len(prior.Items) {
		return fmt.Errorf("cleanup report authority regressed")
	}
	if next.JourneySucceeded && (next.ExecutionFailed || !release.ValidDigest(next.ExecutorAttestationDigest)) {
		return fmt.Errorf("cleanup report success attestation is incomplete")
	}
	steps := make(map[string]release.JourneyStepResult, len(next.Steps))
	for _, step := range next.Steps {
		steps[step.MutationID] = step
		if (step.Outcome == release.StepFailed || step.Outcome == release.StepUnknown) && !next.ExecutionFailed {
			return fmt.Errorf("cleanup report hides a failed execution")
		}
	}
	for _, step := range prior.Steps {
		nextStep, present := steps[step.MutationID]
		if !present {
			return fmt.Errorf("cleanup report removed a step")
		}
		valid := nextStep == step
		if step.Outcome == release.StepSubmitted {
			valid = valid || nextStep.MutationID == step.MutationID && nextStep.AttemptID == step.AttemptID && (nextStep.Outcome == release.StepPassed || nextStep.Outcome == release.StepFailed || nextStep.Outcome == release.StepUnknown)
		}
		if !valid {
			return fmt.Errorf("cleanup report step transition is invalid")
		}
	}
	byID := make(map[string]release.CleanupItem, len(next.Items))
	for _, item := range next.Items {
		byID[item.MutationID] = item
	}
	for _, item := range prior.Items {
		nextItem, present := byID[item.MutationID]
		if !present {
			return fmt.Errorf("cleanup report removed an item")
		}
		valid := nextItem == item
		switch item.Result {
		case release.CleanupSubmitted:
			valid = valid || nextItem.MutationID == item.MutationID && nextItem.Result == release.CleanupExecuted && nextItem.ObservedIdentity != ""
		case release.CleanupExecuted:
			valid = valid || nextItem.MutationID == item.MutationID && nextItem.ObservedIdentity == item.ObservedIdentity && (nextItem.Result == release.CleanupCleaned || nextItem.Result == release.CleanupRetained)
		}
		if !valid {
			return fmt.Errorf("cleanup report item transition is invalid")
		}
	}
	return nil
}
