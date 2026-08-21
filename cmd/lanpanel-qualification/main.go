package main

import (
	"fmt"
	"lanpanel/internal/qualification"
	"lanpanel/internal/release"
	"os"
)

type result struct {
	RunID                      string `json:"run_id"`
	CandidateDigest            string `json:"candidate_digest"`
	SourceDigest               string `json:"source_digest"`
	PlanDigest                 string `json:"plan_digest"`
	CleanupVerified            bool   `json:"cleanup_verified"`
	QualificationSummaryDigest string `json:"qualification_summary_digest,omitempty"`
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "preflight" && os.Args[1] != "final" {
		fmt.Fprintln(os.Stderr, "usage: lanpanel-qualification preflight|final /absolute/protected-input.json")
		os.Exit(2)
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
		if err := qualification.WriteSummary(prepared.Input.Artifacts.QualificationSummary, summary); err != nil {
			return prepared, false, "", err
		}
		return prepared, true, release.DigestBytes(summary), nil
	}
	prepared, err := qualification.Prepare(inputPath)
	return prepared, false, "", err
}
