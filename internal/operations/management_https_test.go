package operations

import (
	"lanpanel/internal/safety"
	"testing"
	"time"
)

func TestManagementHTTPSRecoveryAuthorityStates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	binding := SafetyBinding{ResourceID: "management_https", PlanID: "cert_issue", IntentGeneration: 2, CandidateDigest: testDigest("config"), CandidateBundle: testDigest("binding"), CertificateIdentity: "cert_issue"}
	state := safety.EmptyState()
	if err := authorize(AutomaticReconciliation, state, binding, true, now); err != nil {
		t.Fatalf("pending issuance authority rejected: %v", err)
	}
	state.ManagementHTTPS.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 1, Fingerprint: testDigest("old-certificate"), Binding: testDigest("old-binding"), NotAfter: now.Add(-time.Minute), LastTrustedWall: now.Add(-time.Hour)}
	state.ManagementHTTPS.CertificateExpiry = &safety.DeadlineMarker{Generation: 2, Deadline: now.Add(-time.Minute), Binding: state.ManagementHTTPS.ActiveCertificate.Binding}
	state.ManagementHTTPS.EntryDigest = ""
	if err := authorize(AutomaticReconciliation, state, binding, true, now); err != nil {
		t.Fatalf("expired replacement recovery authority rejected: %v", err)
	}
	state.ManagementHTTPS.CertificateExpiry = nil
	state.ManagementHTTPS.EntryDigest = testDigest("entry")
	state.ManagementHTTPS.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 2, Fingerprint: testDigest("candidate"), Binding: binding.CandidateBundle, NotAfter: now.Add(time.Hour), LastTrustedWall: now.Add(-time.Minute)}
	if err := authorize(AutomaticReconciliation, state, binding, true, now); err != nil {
		t.Fatalf("completed candidate recovery authority rejected: %v", err)
	}
	state.ManagementHTTPS.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 2, Fingerprint: testDigest("candidate"), Binding: binding.CandidateBundle, NotAfter: now.Add(time.Hour), LastTrustedWall: now.Add(-time.Minute)}
	if err := authorize(CertificateRenew, state, SafetyBinding{ResourceID: "management_https", PlanID: "renew", IntentGeneration: 3, CandidateBundle: binding.CandidateBundle}, true, now); err != nil {
		t.Fatalf("independent renewal authority rejected: %v", err)
	}
}

func TestManagementHTTPSIssueAuthoritySurvivesChallengeAndCompletion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	binding := SafetyBinding{ResourceID: "management_https", PlanID: "cert_issue", IntentGeneration: 2, CandidateDigest: testDigest("config"), CandidateBundle: testDigest("binding"), CertificateIdentity: "cert_issue"}
	state := safety.EmptyState()
	if err := authorize(AutomaticReconciliation, state, binding, true, now); err != nil {
		t.Fatalf("initial issuance authority rejected: %v", err)
	}
	state.ManagementHTTPS.ChallengePending = &safety.ChallengePending{PlanID: binding.PlanID, Generation: binding.IntentGeneration, ConfigDigest: binding.CandidateDigest, SANIdentity: testDigest("san"), ACMEBinding: binding.CandidateBundle, CertificateIdentity: binding.CertificateIdentity}
	if err := authorize(AutomaticReconciliation, state, binding, true, now); err != nil {
		t.Fatalf("owned challenge authority rejected: %v", err)
	}
	state.ManagementHTTPS.ChallengePending = nil
	state.ManagementHTTPS.EntryDigest = testDigest("entry")
	state.ManagementHTTPS.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 1, Fingerprint: testDigest("certificate"), Binding: binding.CandidateBundle, NotAfter: now.Add(time.Hour), LastTrustedWall: now.Add(-time.Minute)}
	if err := authorize(AutomaticReconciliation, state, binding, true, now); err != nil {
		t.Fatalf("completed issuance authority rejected: %v", err)
	}
}
