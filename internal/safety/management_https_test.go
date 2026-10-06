package safety

import (
	"testing"
	"time"
)

func TestManagementHTTPSSafetyTransitionRequiresCertificateActivationAuthority(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	current := EmptyState()
	current.ManagementHTTPS = ManagementHTTPSSafety{
		GenerationSequence: 1,
		EntryDigest:        digest("entry-1"),
		ActiveCertificate: &ActiveCertificateAuthority{
			Generation:      1,
			Fingerprint:     digest("certificate-1"),
			Binding:         digest("binding"),
			NotAfter:        now.Add(time.Hour),
			LastTrustedWall: now.Add(-time.Minute),
		},
	}
	unauthorized := current
	unauthorized.ManagementHTTPS.EntryDigest = digest("entry-two")
	if err := validateTransition(RoleChallenge, current, unauthorized, TransitionProof{}); err == nil {
		t.Fatal("unauthorized management HTTPS entry writer accepted")
	}
	if err := validateTransition(RolePublish, current, unauthorized, TransitionProof{}); err == nil {
		t.Fatal("management HTTPS publish role changed entry authority")
	}

	pending := &ChallengePending{Generation: 2, PlanID: "cert_one", Method: "dns-01", ConfigDigest: digest("config"), SANIdentity: digest("san"), ACMEBinding: digest("binding"), CertificateIdentity: "cert_one", Webroot: "/var/lib/lanpanel/certificates/dns-only"}
	activated := current
	activated.Revision = current.Revision + 1
	activated.ManagementHTTPS.GenerationSequence = 2
	activated.ManagementHTTPS.EntryDigest = digest("entry-two")
	activated.ManagementHTTPS.ActiveCertificate = &ActiveCertificateAuthority{Generation: 2, Fingerprint: digest("certificate-two"), Binding: digest("binding"), NotAfter: now.Add(2 * time.Hour), LastTrustedWall: now.Add(-time.Minute)}
	activated.ManagementHTTPS.ChallengePending = pending
	if err := validateTransition(RoleCertificateActivation, current, activated, TransitionProof{}); err == nil {
		t.Fatal("management HTTPS activation without challenge clearance accepted")
	}
	activated.ManagementHTTPS.ChallengePending = nil
	if err := validateTransition(RoleCertificateActivation, current, activated, TransitionProof{}); err == nil {
		t.Fatal("management HTTPS activation without prior challenge authority accepted")
	}

	current.ManagementHTTPS.ChallengePending = pending
	current.ManagementHTTPS.GenerationSequence = 2
	activated = current
	activated.Revision = current.Revision + 1
	activated.ManagementHTTPS.GenerationSequence = 2
	activated.ManagementHTTPS.EntryDigest = digest("entry-two")
	activated.ManagementHTTPS.ActiveCertificate = &ActiveCertificateAuthority{Generation: 2, Fingerprint: digest("certificate-two"), Binding: digest("binding"), NotAfter: now.Add(2 * time.Hour), LastTrustedWall: now.Add(-time.Minute)}
	retainedChallenge := activated
	retainedChallenge.ManagementHTTPS.ChallengePending = pending
	if err := validateTransition(RoleCertificateActivation, current, retainedChallenge, TransitionProof{}); err == nil {
		t.Fatal("management HTTPS activation retained challenge authority")
	}
	activated.ManagementHTTPS.ChallengePending = nil
	if err := validateTransition(RoleCertificateActivation, current, activated, TransitionProof{}); err != nil {
		t.Fatalf("exact management HTTPS activation rejected: %v", err)
	}
}

func TestManagementHTTPSInitialActivationUsesIndependentBundleGeneration(t *testing.T) {
	current := EmptyState()
	current.ManagementHTTPS.GenerationSequence = 4
	current.ManagementHTTPS.ChallengePending = &ChallengePending{Generation: 4, PlanID: "cert_one", Method: "dns-01", ConfigDigest: digest("config"), SANIdentity: digest("san"), ACMEBinding: digest("binding"), CertificateIdentity: "cert_one", Webroot: "/var/lib/lanpanel/certificates/dns-only"}
	activated := current
	activated.Revision++
	activated.ManagementHTTPS.ActiveCertificate = &ActiveCertificateAuthority{Generation: 1, Fingerprint: digest("certificate"), Binding: digest("binding"), NotAfter: time.Unix(1_700_000_000, 0).UTC().Add(time.Hour), LastTrustedWall: time.Unix(1_700_000_000, 0).UTC()}
	activated.ManagementHTTPS.EntryDigest = digest("entry")
	activated.ManagementHTTPS.ChallengePending = nil
	if err := validateTransition(RoleCertificateActivation, current, activated, TransitionProof{}); err != nil {
		t.Fatalf("initial activation with independent bundle generation rejected: %v", err)
	}
}

func TestManagementHTTPSExpiryContractionRetainsCertificateAuthority(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	current := EmptyState()
	current.ManagementHTTPS = ManagementHTTPSSafety{
		GenerationSequence: 2,
		EntryDigest:        digest("entry-1"),
		ActiveCertificate:  &ActiveCertificateAuthority{Generation: 1, Fingerprint: digest("certificate-1"), Binding: digest("binding"), NotAfter: now.Add(-time.Minute), LastTrustedWall: now.Add(-time.Hour)},
		CertificateExpiry:  &DeadlineMarker{Generation: 2, Deadline: now.Add(-time.Minute), Binding: digest("binding")},
	}
	closed := current
	closed.Revision++
	closed.ManagementHTTPS.EntryDigest = ""
	if err := validateTransition(RoleContraction, current, closed, TransitionProof{}); err != nil {
		t.Fatalf("expiry contraction rejected: %v", err)
	}
}
