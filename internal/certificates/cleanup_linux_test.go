//go:build linux

package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateCleanupResumesEachDeletionPrefix(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	chain, key := issuedFixture(t, now, []string{"control.example.test"})
	material := validateFixtureMaterial(t, chain, key, []string{"control.example.test"}, now)
	for _, stop := range []string{"private-key.pem", "certificate.pem", "identity.json"} {
		t.Run(stop, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "bundle")
			if err := os.Mkdir(base, 0o700); err != nil {
				t.Fatal(err)
			}
			stored := materialIdentity(base, "cert_00000000000000000000000000000001", 1, material, now)
			raw, _ := json.Marshal(stored)
			for name, data := range map[string][]byte{"private-key.pem": material.PrivateKeyPEM(), "certificate.pem": material.CertificatePEM(), "identity.json": raw} {
				if err := os.WriteFile(filepath.Join(base, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			interrupted := errors.New("interrupted unlink")
			if err := removeVerifiedBundle(base, func(name string) error {
				if name == stop {
					return interrupted
				}
				return nil
			}); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			members := cleanupTestMembers(t, base)
			if err := verifyCleanupMembers(base, stored.ID, 1, BundleIdentityFor(stored), members); err != nil {
				t.Fatalf("valid deletion prefix rejected: %v", err)
			}
			if certificate, present := members["certificate.pem"]; present {
				members["certificate.pem"] = []byte("changed")
				if err := verifyCleanupMembers(base, stored.ID, 1, BundleIdentityFor(stored), members); err == nil {
					t.Fatal("changed remaining certificate accepted")
				}
				members["certificate.pem"] = certificate
			}
			if len(members) != 0 {
				delete(members, "identity.json")
				if len(members) != 0 && verifyCleanupMembers(base, stored.ID, 1, BundleIdentityFor(stored), members) == nil {
					t.Fatal("remaining material without identity accepted")
				}
			}
			if err := removeVerifiedBundle(base, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(base); !os.IsNotExist(err) {
				t.Fatalf("bundle remains: %v", err)
			}
		})
	}
}

func cleanupTestMembers(t *testing.T, base string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	members := map[string][]byte{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(base, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		members[entry.Name()] = data
	}
	return members
}

func TestInactiveCertificateCleanupResumesWithExactStageOwnership(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires isolated root-owned fixed certificate roots")
	}
	if _, err := os.Lstat(FixedRoot); !os.IsNotExist(err) {
		t.Skip("requires absent fixed certificate root")
	}
	if err := os.MkdirAll(FixedBundlesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(FixedActiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(FixedRoot) }()
	id := "cert_00000000000000000000000000000003"
	stage, err := identity.CertificateStageIdentityFor(id)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	chain, key := issuedFixture(t, now, []string{"control.example.test"})
	material := validateFixtureMaterial(t, chain, key, []string{"control.example.test"}, now)
	for index, stop := range []string{"private-key.pem", "certificate.pem", "identity.json"} {
		generation := uint64(index + 1)
		stored, err := StageIssued(context.Background(), FixedBundlesRoot, id, generation, sum([]byte("binding")), material, filetxn.Owner{UID: stage.UID, GID: stage.GID}, now)
		if err != nil {
			t.Fatal(err)
		}
		expected := BundleIdentityFor(stored)
		pointer := Pointer{CertificateID: id, CandidateGeneration: generation, CandidateIdentity: expected}
		active, err := ActivatePointer(context.Background(), pointer)
		if err != nil {
			t.Fatal(err)
		}
		if err := RemoveInactiveBundle(id, generation, expected, stage.UID, stage.GID); err == nil {
			t.Fatal("active bundle was deleted")
		}
		if err := RemovePointer(context.Background(), pointer, active.CandidateTarget); err != nil {
			t.Fatal(err)
		}
		if err := VerifyBundleCleanupIdentity(id, generation, expected); err != nil {
			t.Fatal(err)
		}
		interrupted := errors.New("interrupted unlink")
		if err := removeVerifiedBundle(active.CandidateTarget, func(name string) error {
			if name == stop {
				return interrupted
			}
			return nil
		}); !errors.Is(err, interrupted) {
			t.Fatal(err)
		}
		if err := VerifyBundleCleanupIdentity(id, generation, expected); err != nil {
			t.Fatal(err)
		}
		if err := VerifyBundleIdentity(id, generation, expected); err == nil {
			t.Fatal("partially deleted bundle accepted for activation")
		}
		if err := RemoveInactiveBundle(id, generation, expected, stage.UID, stage.GID); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(active.CandidateTarget); !os.IsNotExist(err) {
			t.Fatalf("bundle remains: %v", err)
		}
	}
}
