//go:build linux

package application

import (
	"errors"
	"lanpanel/internal/certificates"
	"testing"
)

func TestHeadscaleRollbackAcceptsDeletedCandidateOnlyAfterContraction(t *testing.T) {
	expected := certificates.BundleIdentity{Fingerprint: deployTestDigest("fingerprint"), SANIdentity: deployTestDigest("san"), ChainIdentity: deployTestDigest("chain"), IssuerIdentity: deployTestDigest("issuer"), BindingIdentity: deployTestDigest("binding"), DirectoryIdentity: deployTestDigest("directory")}
	incomplete := errors.New("certificate inventory incomplete")
	verified := 0
	verify := func() error { verified++; return nil }
	candidate, present, err := headscaleRollbackCandidate(certificates.Identity{}, incomplete, expected, true, verify)
	if err != nil || present || candidate.ID != "" || verified != 1 {
		t.Fatalf("verified deletion prefix was not accepted as cleanup-only: candidate=%+v present=%t verified=%d err=%v", candidate, present, verified, err)
	}
	if _, _, err := headscaleRollbackCandidate(certificates.Identity{}, incomplete, expected, false, verify); !errors.Is(err, incomplete) || verified != 1 {
		t.Fatal("incomplete candidate bypassed pending activation authority")
	}
	changed := errors.New("remaining certificate changed")
	if _, _, err := headscaleRollbackCandidate(certificates.Identity{}, incomplete, expected, true, func() error { return changed }); !errors.Is(err, changed) {
		t.Fatal("changed deletion suffix accepted")
	}
}
