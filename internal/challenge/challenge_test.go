package challenge

import (
	"lanpanel/internal/acme"
	"lanpanel/internal/safety"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func snapshots() []safety.MarkerSnapshot {
	return []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotPresent, Generation: 1}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}
}

func TestHTTPChallengeRendersOnlyExactTokenRoute(t *testing.T) {
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: testDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}}
	prepared, err := Prepare(Request{ResourceID: "res_00000000000000000000000000000001", PlanID: "plan-one", Generation: 2, ConfigDigest: testDigest, Domains: []string{"app.example.test"}, Binding: binding, CertificateIdentity: "cert-one", Webroot: "/var/lib/lanpanel/certificates/webroot/cert-one", BaseMarkers: snapshots()})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Entry == nil || prepared.Safety.TokenPath != "/.well-known/acme-challenge" || prepared.Safety.Method != "http-01" {
		t.Fatalf("prepared=%#v", prepared)
	}
}

func TestDNSChallengeCreatesOwnerLockWithoutNginxRoute(t *testing.T) {
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: testDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeDNS01, Provider: acme.DNSProviderCloudflare, ProfilePath: "/root/cloudflare.env", ProfileFingerprint: testDigest, CredentialFiles: []acme.CredentialFile{{Key: "CF_DNS_API_TOKEN_FILE", Path: "/root/token", Fingerprint: testDigest}}, Zone: "example.test"}
	prepared, err := Prepare(Request{ResourceID: "res_00000000000000000000000000000001", PlanID: "plan-one", Generation: 2, ConfigDigest: testDigest, Domains: []string{"app.example.test"}, Binding: binding, CertificateIdentity: "cert-one", BaseMarkers: snapshots()})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Entry != nil || len(prepared.Owners) != 1 || prepared.Owners[0] != "_acme-challenge.app.example.test" || prepared.Safety.OwnerLock == "" {
		t.Fatalf("prepared=%#v", prepared)
	}
}
