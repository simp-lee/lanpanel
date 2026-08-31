//go:build linux

package application

import (
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/operations"
	"lanpanel/internal/safety"
	"testing"
	"time"
)

func TestPreparedHeadscaleDeployWithoutControlJournalIsFailureTerminalizable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	installation := headscaleDeployInstallation()
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: deployTestDigest("account"), Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}, AccountEmail: "admin@example.test", TermsAccepted: true}
	request, result := headscaleDeployPreflight(t, now)
	authority, err := buildHeadscaleDeployAuthority(installation, binding, "cert_00000000000000000000000000000001", "ui/session/generation/1", request, result, safety.EmptyState(), now)
	if err != nil {
		t.Fatal(err)
	}
	candidate := authority.Rendered.Candidate
	applied, err := control.AppliedIdentity(candidate)
	if err != nil {
		t.Fatal(err)
	}
	jobID := "job_0000000000000000000000000000000000000000000000000000000000000000"
	planID := "plan_0000000000000000000000000000000000000000000000000000000000000000"
	installation.Headscale.DeployIntent = &domain.HeadscaleDeployIntent{Generation: applied.Generation, PlanID: planID, JobID: jobID, Phase: domain.HeadscaleDeployPrepared, PreflightDigest: result.RequestDigest, CertificateBinding: candidate.CertificateBinding, Candidate: applied}
	installation.Headscale.LastOperation = domain.OperationHeadscaleControlDeploy
	installation.Headscale.LastJobID = jobID
	intent := operations.Reservation{JobID: jobID, PlanID: planID, Operation: operations.HeadscaleDeploy, Target: "headscale/" + installation.Headscale.ID, Phase: operations.PhaseLocalIntent, HeadscaleDeploy: &operations.HeadscaleDeployBinding{Candidate: candidate, PreflightRequest: request, PreflightResult: result}}

	for _, failurePoint := range []string{"account_validation", "runtime_creation", "candidate_host_creation", "control_prepare_before_journal", "startup_restart"} {
		t.Run(failurePoint, func(t *testing.T) {
			required, err := classifyJournalLessPreparedHeadscaleDeploy(installation, intent)
			if err != nil || !required {
				t.Fatalf("required=%t err=%v", required, err)
			}
		})
	}
}
