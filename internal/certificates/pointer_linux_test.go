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

func pointerTestIdentity(value string) BundleIdentity {
	return BundleIdentity{Fingerprint: sum([]byte("fingerprint-" + value)), SANIdentity: sum([]byte("san-" + value)), ChainIdentity: sum([]byte("chain-" + value)), IssuerIdentity: sum([]byte("issuer-" + value)), BindingIdentity: sum([]byte("binding-" + value)), DirectoryIdentity: sum([]byte("directory-" + value))}
}

func TestCertificatePointerRejectsUnfixedOrRegressingIdentity(t *testing.T) {
	candidate, prior := pointerTestIdentity("candidate"), pointerTestIdentity("prior")
	for _, value := range []Pointer{{CertificateID: "bad", CandidateGeneration: 2, CandidateIdentity: candidate, ExpectedPriorGeneration: 1, ExpectedPriorIdentity: prior}, {CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 1, CandidateIdentity: candidate, ExpectedPriorGeneration: 1, ExpectedPriorIdentity: prior}, {CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 0, CandidateIdentity: candidate}, {CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, ExpectedPriorGeneration: 1, ExpectedPriorIdentity: prior}, {CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, CandidateIdentity: candidate, ExpectedPriorGeneration: 1}} {
		if _, _, _, err := pointerPaths(value); err == nil {
			t.Fatalf("accepted %#v", value)
		}
	}
}

func TestCertificatePointerPathsStayInFixedRoots(t *testing.T) {
	value := Pointer{CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, CandidateIdentity: pointerTestIdentity("candidate"), ExpectedPriorGeneration: 1, ExpectedPriorIdentity: pointerTestIdentity("prior")}
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
			expected := BundleIdentityFor(value)
			if err := verifyBundleTarget(target, expected); err != nil {
				t.Fatalf("valid pointer target failed: %v", err)
			}
			test.mutate(value)
			if _, err := ObserveIdentity(FixedBundlesRoot, certificateID, generation, owner); err == nil {
				t.Fatal("ObserveIdentity accepted modified bundle")
			}
			if err := verifyBundleTarget(target, expected); err == nil {
				t.Fatal("pointer validation accepted modified bundle")
			}
		})
	}
}

func TestCertificatePointerBindsCandidateAndRestoresExactPriorIdentity(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires root-owned fixed certificate roots")
	}
	if _, err := os.Lstat(FixedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Skip("requires an isolated root with no existing /var/lib/lanpanel/certificates")
	}
	if err := os.MkdirAll(FixedBundlesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(FixedActiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	certificateID := "cert_00000000000000000000000000000002"
	activePath, _ := ActivePointerPath(certificateID)
	priorPath, _ := BundlePath(certificateID, 1)
	candidatePath, _ := BundlePath(certificateID, 2)
	defer func() {
		_ = os.Remove(activePath)
		_ = os.RemoveAll(candidatePath)
		_ = os.RemoveAll(priorPath)
		_ = os.Remove(FixedActiveRoot)
		_ = os.Remove(FixedBundlesRoot)
		_ = os.Remove(FixedRoot)
	}()
	stage, err := identity.CertificateStageIdentityFor(certificateID)
	if err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: stage.UID, GID: stage.GID}
	now := time.Now().UTC().Truncate(time.Second)
	priorChain, priorKey := issuedFixture(t, now, []string{"control.example.test"})
	priorMaterial := validateFixtureMaterial(t, priorChain, priorKey, []string{"control.example.test"}, now)
	prior, err := StageIssued(context.Background(), FixedBundlesRoot, certificateID, 1, sum([]byte("binding")), priorMaterial, owner, now)
	if err != nil {
		t.Fatal(err)
	}
	expectedChain, expectedKey := issuedFixture(t, now, []string{"control.example.test"})
	expectedMaterial := validateFixtureMaterial(t, expectedChain, expectedKey, []string{"control.example.test"}, now)
	expectedCandidate, err := StageIssued(context.Background(), FixedBundlesRoot, certificateID, 2, sum([]byte("binding")), expectedMaterial, owner, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(candidatePath); err != nil {
		t.Fatal(err)
	}
	otherCandidate, err := StageIssued(context.Background(), FixedBundlesRoot, certificateID, 2, sum([]byte("binding")), expectedMaterial, owner, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	priorPointer := Pointer{CertificateID: certificateID, CandidateGeneration: 1, CandidateIdentity: BundleIdentityFor(prior)}
	if result, err := ActivatePointer(context.Background(), priorPointer); err != nil || !result.Durable {
		t.Fatalf("activate prior: result=%+v err=%v", result, err)
	}
	mismatched := Pointer{CertificateID: certificateID, CandidateGeneration: 2, CandidateIdentity: BundleIdentityFor(expectedCandidate), ExpectedPriorGeneration: 1, ExpectedPriorIdentity: BundleIdentityFor(prior)}
	if result, err := ActivatePointer(context.Background(), mismatched); err == nil || result.CandidateTarget != "" {
		t.Fatalf("self-consistent replacement candidate activated: result=%+v err=%v", result, err)
	}
	if observed, err := ObservePointer(certificateID); err != nil || observed != priorPath {
		t.Fatalf("failed activation changed pointer: observed=%q err=%v", observed, err)
	}
	valid := Pointer{CertificateID: certificateID, CandidateGeneration: 2, CandidateIdentity: BundleIdentityFor(otherCandidate), ExpectedPriorGeneration: 1, ExpectedPriorIdentity: BundleIdentityFor(prior)}
	if result, err := ActivatePointer(context.Background(), valid); err != nil || !result.Durable || result.CandidateTarget != candidatePath {
		t.Fatalf("activate exact candidate: result=%+v err=%v", result, err)
	}
	if err := os.RemoveAll(priorPath); err != nil {
		t.Fatal(err)
	}
	if _, err := StageIssued(context.Background(), FixedBundlesRoot, certificateID, 1, sum([]byte("binding")), priorMaterial, owner, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := RestorePointer(context.Background(), valid, candidatePath); err == nil {
		t.Fatal("self-consistent replacement prior was restored")
	}
	if observed, err := ObservePointer(certificateID); err != nil || observed != candidatePath {
		t.Fatalf("failed restoration changed pointer: observed=%q err=%v", observed, err)
	}
	if err := os.RemoveAll(priorPath); err != nil {
		t.Fatal(err)
	}
	restoredPrior, err := StageIssued(context.Background(), FixedBundlesRoot, certificateID, 1, sum([]byte("binding")), priorMaterial, owner, now)
	if err != nil || BundleIdentityFor(restoredPrior) != BundleIdentityFor(prior) {
		t.Fatalf("restage exact prior: identity=%+v err=%v", restoredPrior, err)
	}
	if err := RestorePointer(context.Background(), valid, candidatePath); err != nil {
		t.Fatalf("restore exact prior: %v", err)
	}
	if observed, err := ObservePointer(certificateID); err != nil || observed != priorPath {
		t.Fatalf("restored pointer=%q err=%v", observed, err)
	}
	if err := RestorePointer(context.Background(), priorPointer, priorPath); err == nil {
		t.Fatal("prior-less restoration authority was accepted")
	}
	if err := RemovePointer(context.Background(), priorPointer, priorPath); err != nil {
		t.Fatalf("remove exact initial candidate: %v", err)
	}
	if observed, err := ObservePointer(certificateID); err != nil || observed != "" {
		t.Fatalf("removed pointer=%q err=%v", observed, err)
	}
}
