//go:build linux

package certificates

import (
	"context"
	"errors"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

func TestObserveIdentityAndPointerRejectModifiedBundleMaterial(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires root-owned fixed certificate roots")
	}
	if _, err := os.Lstat(FixedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Skip("requires an isolated root with no existing /var/lib/lanpanel/certificates")
	}
	if err := os.MkdirAll(FixedBundlesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for generation := uint64(1); generation <= 6; generation++ {
			path, _ := BundlePath("cert_00000000000000000000000000000001", generation)
			if err := os.RemoveAll(path); err != nil {
				t.Errorf("remove isolated certificate bundle: %v", err)
			}
		}
		_ = os.Remove(FixedBundlesRoot)
		_ = os.Remove(FixedRoot)
	}()
	now := time.Now().UTC().Truncate(time.Second)
	chain, key := issuedFixture(t, now, []string{"control.example.test"})
	material := validateFixtureMaterial(t, chain, key, []string{"control.example.test"}, now)
	otherChain, otherKey := issuedFixture(t, now, []string{"control.example.test"})
	certificateID := "cert_00000000000000000000000000000001"
	stage, err := identity.CertificateStageIdentityFor(certificateID)
	if err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: stage.UID, GID: stage.GID}
	tests := []struct {
		name   string
		mutate func(Identity)
	}{
		{name: "certificate", mutate: func(value Identity) {
			if err := os.WriteFile(value.CertificatePath, otherChain, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "certificate-key-pair", mutate: func(value Identity) {
			if err := os.WriteFile(value.CertificatePath, otherChain, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(value.PrivateKeyPath, otherKey, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "private-key", mutate: func(value Identity) {
			if err := os.WriteFile(value.PrivateKeyPath, otherKey, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "SAN", mutate: func(value Identity) {
			rewriteBundleIdentity(t, filepath.Join(filepath.Dir(value.CertificatePath), "identity.json"), func(stored *Identity) {
				stored.Domains = []string{"other.example.test"}
				stored.SANIdentity = sum([]byte(strings.Join(stored.Domains, "\x00")))
			})
		}},
		{name: "chain", mutate: func(value Identity) {
			rewriteBundleIdentity(t, filepath.Join(filepath.Dir(value.CertificatePath), "identity.json"), func(stored *Identity) { stored.ChainIdentity = sum([]byte("other-chain")) })
		}},
		{name: "fingerprint", mutate: func(value Identity) {
			rewriteBundleIdentity(t, filepath.Join(filepath.Dir(value.CertificatePath), "identity.json"), func(stored *Identity) { stored.Fingerprint = sum([]byte("other-fingerprint")) })
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generation := uint64(index + 1)
			value, err := StageIssued(context.Background(), FixedBundlesRoot, certificateID, generation, sum([]byte("binding")), material, owner, now)
			if err != nil {
				t.Fatal(err)
			}
			target, err := BundlePath(certificateID, generation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ObserveIdentity(FixedBundlesRoot, certificateID, generation, owner); err != nil {
				t.Fatalf("valid ObserveIdentity failed: %v", err)
			}
			if err := verifyBundleTarget(target); err != nil {
				t.Fatalf("valid pointer target failed: %v", err)
			}
			test.mutate(value)
			if _, err := ObserveIdentity(FixedBundlesRoot, certificateID, generation, owner); err == nil {
				t.Fatal("ObserveIdentity accepted modified bundle")
			}
			if err := verifyBundleTarget(target); err == nil {
				t.Fatal("pointer validation accepted modified bundle")
			}
		})
	}
}
