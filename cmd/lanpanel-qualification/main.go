package main

import (
	"context"
	"fmt"
	"lanpanel/internal/qualification"
	"lanpanel/internal/release"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type result struct {
	RunID                      string `json:"run_id"`
	CandidateDigest            string `json:"candidate_digest"`
	SourceDigest               string `json:"source_digest"`
	TargetProfileDigest        string `json:"target_profile_digest,omitempty"`
	PlanDigest                 string `json:"plan_digest"`
	InstallManifestDigest      string `json:"install_manifest_digest,omitempty"`
	ProtectedInput             string `json:"protected_input,omitempty"`
	CleanupVerified            bool   `json:"cleanup_verified"`
	QualificationSummaryDigest string `json:"qualification_summary_digest,omitempty"`
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "generate" && os.Args[1] != "preflight" && os.Args[1] != "run" && os.Args[1] != "final" && os.Args[1] != "release" {
		fmt.Fprintln(os.Stderr, "usage: lanpanel-qualification generate|preflight|run|final|release /absolute/protected-input.json")
		os.Exit(2)
	}
	if os.Args[1] == "generate" {
		generated, err := qualification.Generate(os.Args[2], time.Now)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		encoded, err := release.MarshalCanonical(result{RunID: generated.RunID, CandidateDigest: generated.CandidateDigest, SourceDigest: generated.SourceTreeDigest, TargetProfileDigest: generated.TargetProfileDigest, PlanDigest: generated.SideEffectPlanDigest, InstallManifestDigest: generated.InstallManifestDigest, ProtectedInput: generated.ProtectedInput})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "release" {
		finalized, err := qualification.FinalizeRelease(os.Args[2], time.Now)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		encoded, err := release.MarshalCanonical(finalized)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "run" {
		prepared, report, err := runLiveWithSignals(os.Args[2], qualification.RunLive)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		encoded, err := release.MarshalCanonical(result{RunID: prepared.Input.RunID, CandidateDigest: prepared.Install.Identity().CandidateDigest, SourceDigest: prepared.SourceDigest, PlanDigest: prepared.PlanDigest, InstallManifestDigest: prepared.InstallManifestDigest, CleanupVerified: report.JourneySucceeded})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	prepared, cleanupVerified, summaryDigest, err := run(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, err := release.MarshalCanonical(result{RunID: prepared.Input.RunID, CandidateDigest: prepared.Install.Identity().CandidateDigest, SourceDigest: prepared.SourceDigest, PlanDigest: prepared.PlanDigest, CleanupVerified: cleanupVerified, QualificationSummaryDigest: summaryDigest})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type liveRun func(context.Context, string) (qualification.Prepared, release.LiveCleanupReport, error)

func runLiveWithSignals(inputPath string, execute liveRun) (qualification.Prepared, release.LiveCleanupReport, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return execute(ctx, inputPath)
}

func run(mode, inputPath string) (qualification.Prepared, bool, string, error) {
	if mode == "final" {
		prepared, report, err := qualification.VerifyFinalReadiness(inputPath)
		if err != nil {
			return prepared, false, "", err
		}
		summary, err := qualification.BuildSummary(prepared, report, report.UpdatedAt)
		if err != nil {
			return prepared, false, "", err
		}
		if err := qualification.WriteQualificationSummary(prepared.Input.Artifacts.QualificationSummary, summary); err != nil {
			return prepared, false, "", err
		}
		return prepared, true, release.DigestBytes(summary), nil
	}
	prepared, err := qualification.Prepare(inputPath)
	if err != nil {
		return prepared, false, "", err
	}
	if err := qualification.VerifyRemotePreflight(context.Background(), prepared); err != nil {
		return prepared, false, "", err
	}
	return prepared, false, "", nil
}
