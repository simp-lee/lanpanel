package renewal

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/safety"
	"testing"
	"time"
)

const resourceID = "res_00000000000000000000000000000001"

func publication(now, notAfter time.Time) domain.PublicationRecord {
	return domain.PublicationRecord{State: domain.PublicationPublished, LastAppliedBundle: &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{Certificate: domain.CertificateBundleIdentity{Generation: 1, Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BindingIdentity: "binding", NotAfter: notAfter.Format(time.RFC3339), LastTrustedWall: now.Add(-time.Minute).Format(time.RFC3339)}}}}
}
func safeState(record domain.PublicationRecord) safety.State {
	certificate := record.LastAppliedBundle.DomainHTTPS.Certificate
	notAfter, _ := time.Parse(time.RFC3339, certificate.NotAfter)
	wall, _ := time.Parse(time.RFC3339, certificate.LastTrustedWall)
	return safety.State{GlobalClose: safety.GlobalClose{Phase: safety.GlobalCloseNone}, Resources: []safety.ResourceSafety{{ResourceID: resourceID, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, ActiveCertificate: &safety.ActiveCertificateAuthority{Generation: certificate.Generation, Fingerprint: certificate.Fingerprint, Binding: certificate.BindingIdentity, NotAfter: notAfter, LastTrustedWall: wall}}}}
}
func TestRenewalDecisionUsesAppliedCertificateAndSafety(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	record := publication(now, now.Add(20*24*time.Hour))
	state := safeState(record)
	decision, err := Evaluate(Input{Now: now, RenewBefore: 30 * 24 * time.Hour, Publication: record, Safety: state, ResourceID: resourceID})
	if err != nil || decision != DecisionRenew {
		t.Fatalf("decision=%s err=%v", decision, err)
	}
	state.Resources[0].StickyUnpublished = &safety.GenerationMarker{Generation: 1}
	decision, _ = Evaluate(Input{Now: now, RenewBefore: 30 * 24 * time.Hour, Publication: publication(now, now.Add(20*24*time.Hour)), Safety: state, ResourceID: resourceID})
	if decision != DecisionIdle {
		t.Fatalf("marker did not block renewal: %s", decision)
	}
}
func TestRenewalContractsExpiredOrRegressedClock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	regressed := publication(now, now.Add(time.Hour))
	regressed.LastAppliedBundle.DomainHTTPS.Certificate.LastTrustedWall = now.Add(time.Minute).Format(time.RFC3339)
	expired := publication(now, now.Add(-time.Second))
	stateWithChallenge := safeState(expired)
	stateWithChallenge.Resources[0].ChallengePending = &safety.ChallengePending{}
	decision, err := Evaluate(Input{Now: now, RenewBefore: time.Hour, Publication: expired, Safety: stateWithChallenge, ResourceID: resourceID})
	if err != nil || decision != DecisionContract {
		t.Fatalf("challenge suppressed expiry: decision=%s err=%v", decision, err)
	}
	for _, publication := range []domain.PublicationRecord{regressed, publication(now, now.Add(-time.Second))} {
		decision, err := Evaluate(Input{Now: now, RenewBefore: time.Hour, Publication: publication, Safety: safeState(publication), ResourceID: resourceID})
		if err != nil || decision != DecisionContract {
			t.Fatalf("decision=%s err=%v", decision, err)
		}
	}
}
