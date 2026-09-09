package challenge

import (
	"lanpanel/internal/acme"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func snapshots() []safety.MarkerSnapshot {
	return []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotPresent, Generation: 1}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}
}

func TestHTTPChallengeRendersOnlyExactTokenRoute(t *testing.T) {
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: testDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}}
	base, err := Prepare(Request{ResourceID: "res_00000000000000000000000000000001", PlanID: "plan-one", Generation: 2, ConfigDigest: testDigest, Domains: []string{"app.example.test"}, Binding: binding, CertificateIdentity: "cert-one", Webroot: "/var/lib/lanpanel/certificates/webroot/cert-one", BaseMarkers: snapshots()})
	if err != nil {
		t.Fatal(err)
	}
	if base.Entry != nil || base.Safety.Token != "" || base.Safety.TokenPath != "" || base.Safety.Method != "http-01" {
		t.Fatalf("tokenless base=%#v", base)
	}
	token := "abcdefghijklmnopqrstuv"
	prepared, err := PresentHTTPForResource("res_00000000000000000000000000000001", base, "app.example.test", token, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := nginx.RenderEntry(*prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rendered)
	if prepared.Safety.Token != token || prepared.Safety.TokenPath != "/.well-known/acme-challenge/"+token || prepared.Entry.Challenge.Generation != prepared.Safety.Generation || !strings.Contains(text, "HTTP-01 generation 2; key authorization "+testDigest) || !strings.Contains(text, "location = "+prepared.Safety.TokenPath) || strings.Contains(text, "location ~") || strings.Contains(text, "$1") {
		t.Fatalf("exact challenge route missing: %s", text)
	}
	if _, err := PresentHTTPForResource("res_00000000000000000000000000000001", base, "other.example.test", token, testDigest); err == nil {
		t.Fatal("token was associated with a Host outside the SAN inventory")
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
