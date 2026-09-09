//go:build linux

package qualification

import (
	"context"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunnerCompletesWithProtectedReportAndAttestationStores(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := testJourneyPlan(t, "run-protected-store")
	planBytes, _ := release.MarshalCanonical(plan)
	manifestDigest, inputDigest := release.DigestBytes([]byte("manifest")), release.DigestBytes([]byte("input"))
	now := plan.CreatedAt.Add(time.Minute)
	executor := &fakeExecutor{}
	runner := Runner{RunID: plan.RunID, Plan: plan, PlanDigest: release.DigestBytes(planBytes), InstallManifestDigest: manifestDigest, ProtectedInputDigest: inputDigest, Executor: executor, Reports: ProtectedReportStore{Path: filepath.Join(root, "cleanup.json")}, Attestor: fakeAttestor{release.DigestBytes(planBytes), manifestDigest, inputDigest, now}, Attestations: ProtectedAttestationStore{Path: filepath.Join(root, "attestation.json")}, Now: func() time.Time { return now }, NewAttemptID: sequenceAttempts(), ExecutionTimeout: time.Minute, CleanupTimeout: time.Minute}
	report, err := runner.Run(context.Background())
	if err != nil || !report.JourneySucceeded {
		t.Fatalf("protected runner failed: report=%+v err=%v", report, err)
	}
	if info, err := os.Lstat(filepath.Join(root, "attestation.json")); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("attestation was not made immutable: info=%v err=%v", info, err)
	}
}

func TestProtectedReportStoreIsMonotonic(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cleanup.json")
	store := ProtectedReportStore{Path: path}
	now := time.Unix(1_700_000_000, 0).UTC()
	firstEvidence := fakeStepEvidence("one")
	first := release.LiveCleanupReport{SchemaVersion: release.LiveCleanupReportSchemaVersion, RunID: "run-one", SideEffectPlanDigest: release.DigestBytes([]byte("plan")), QualificationInstallManifestDigest: release.DigestBytes([]byte("manifest")), ProtectedInputDigest: release.DigestBytes([]byte("input")), UpdatedAt: now, Steps: []release.JourneyStepResult{{MutationID: "one", AttemptID: "attempt-one", Outcome: release.StepPassed, Evidence: firstEvidence, EvidenceDigest: release.DigestBytes(firstEvidence)}}, Items: []release.CleanupItem{{MutationID: "one", ObservedIdentity: "object/one", Result: release.CleanupCleaned}}}
	if err := store.Write(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.UpdatedAt = now.Add(time.Second)
	secondEvidence := fakeStepEvidence("two")
	second.Steps = append(append([]release.JourneyStepResult(nil), first.Steps...), release.JourneyStepResult{MutationID: "two", AttemptID: "attempt-two", Outcome: release.StepPassed, Evidence: secondEvidence, EvidenceDigest: release.DigestBytes(secondEvidence)})
	second.Items = append(append([]release.CleanupItem(nil), first.Items...), release.CleanupItem{MutationID: "two", ObservedIdentity: "object/two", Result: release.CleanupRetained})
	if err := store.Write(second); err != nil {
		t.Fatal(err)
	}
	regressed := second
	regressed.UpdatedAt = now.Add(2 * time.Second)
	regressed.Steps = regressed.Steps[1:]
	regressed.Items = regressed.Items[1:]
	if err := store.Write(regressed); err == nil {
		t.Fatal("cleanup report regression was accepted")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("cleanup report mode changed: %v %v", info, err)
	}
}
