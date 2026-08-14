//go:build linux

package certificates

import "testing"

func TestCertificatePointerRejectsUnfixedOrRegressingIdentity(t *testing.T) {
	for _, value := range []Pointer{{CertificateID: "bad", CandidateGeneration: 2, ExpectedPriorGeneration: 1}, {CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 1, ExpectedPriorGeneration: 1}, {CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 0}} {
		if _, _, _, err := pointerPaths(value); err == nil {
			t.Fatalf("accepted %#v", value)
		}
	}
}
func TestCertificatePointerPathsStayInFixedRoots(t *testing.T) {
	value := Pointer{CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, ExpectedPriorGeneration: 1}
	path, candidate, prior, err := pointerPaths(value)
	if err != nil {
		t.Fatal(err)
	}
	if path != FixedActiveRoot+"/cert_00000000000000000000000000000000.current" || candidate != FixedBundlesRoot+"/cert_00000000000000000000000000000000-00000000000000000002" || prior != FixedBundlesRoot+"/cert_00000000000000000000000000000000-00000000000000000001" {
		t.Fatalf("paths=%q %q %q", path, candidate, prior)
	}
}
