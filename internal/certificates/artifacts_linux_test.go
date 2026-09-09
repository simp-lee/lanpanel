//go:build linux

package certificates

import (
	"context"
	"errors"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResourceCertificateInventoryCleanup(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires isolated root-owned fixed certificate roots")
	}
	if _, err := os.Lstat(FixedRoot); !os.IsNotExist(err) {
		t.Skip("requires absent fixed certificate root")
	}
	for _, prefix := range []string{"complete", "pointer", "private-key.pem", "certificate.pem", "identity.json", "bundle", "foreign_generation", "changed_material", "failed_generation_retry", "staging_complete", "staging_certificate_only", "staging_partial", "temporary_pointer", "dangling_temporary_pointer", "foreign_temporary_pointer"} {
		t.Run(prefix, func(t *testing.T) {
			if err := os.MkdirAll(FixedBundlesRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(FixedActiveRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.RemoveAll(FixedRoot) }()
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			chain, key := issuedFixture(t, now, []string{"app.example.test"})
			material := validateFixtureMaterial(t, chain, key, []string{"app.example.test"}, now)
			stageBundle := func(id string, generation uint64) Artifact {
				stage, err := identity.CertificateStageIdentityFor(id)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := StageIssued(ctx, FixedBundlesRoot, id, generation, sum([]byte("binding")), material, filetxn.Owner{UID: stage.UID, GID: stage.GID}, now)
				if err != nil {
					t.Fatal(err)
				}
				return Artifact{CertificateID: id, Generation: generation, Bundle: BundleIdentityFor(stored)}
			}
			id := "cert_00000000000000000000000000000001"
			old := stageBundle(id, 1)
			current := stageBundle(id, 2)
			foreign := stageBundle("cert_00000000000000000000000000000002", 1)
			inventory := AddArtifact([]Artifact{old}, current)
			pointer := Pointer{CertificateID: id, CandidateGeneration: 2, CandidateIdentity: current.Bundle}
			active, err := ActivatePointer(ctx, pointer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ActivatePointer(ctx, Pointer{CertificateID: foreign.CertificateID, CandidateGeneration: 1, CandidateIdentity: foreign.Bundle}); err != nil {
				t.Fatal(err)
			}
			switch prefix {
			case "temporary_pointer", "dangling_temporary_pointer", "foreign_temporary_pointer":
				target := active.CandidateTarget
				if prefix == "foreign_temporary_pointer" {
					target, _ = BundlePath(foreign.CertificateID, foreign.Generation)
				}
				if prefix == "dangling_temporary_pointer" {
					target, _ = BundlePath(old.CertificateID, old.Generation)
					stage, _ := identity.CertificateStageIdentityFor(id)
					if err := RemoveInactiveBundle(id, old.Generation, old.Bundle, stage.UID, stage.GID); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, temporaryArtifactPointerPath(id)); err != nil {
					t.Fatal(err)
				}
			case "staging_complete", "staging_certificate_only", "staging_partial":
				if err := RemovePointer(ctx, pointer, active.CandidateTarget); err != nil {
					t.Fatal(err)
				}
				staging := filepath.Join(FixedBundlesRoot, "."+filepath.Base(active.CandidateTarget)+".lanpanel-staging")
				if err := os.Rename(active.CandidateTarget, staging); err != nil {
					t.Fatal(err)
				}
				if prefix != "staging_complete" {
					for _, name := range []string{"private-key.pem", "identity.json"} {
						if err := os.Remove(filepath.Join(staging, name)); err != nil {
							t.Fatal(err)
						}
					}
				}
				if prefix == "staging_partial" {
					if err := os.WriteFile(filepath.Join(staging, "certificate.pem"), []byte("truncated"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "foreign_generation":
				stageBundle(id, 3)
			case "changed_material":
				if err := os.WriteFile(filepath.Join(active.CandidateTarget, "private-key.pem"), []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "failed_generation_retry":
				failed := current
				failed.Bundle.Fingerprint = sum([]byte("previous failed material"))
				inventory = AddArtifact(inventory, failed)
			case "pointer", "private-key.pem", "certificate.pem", "identity.json", "bundle":
				if err := RemovePointer(ctx, pointer, active.CandidateTarget); err != nil {
					t.Fatal(err)
				}
				if prefix != "pointer" {
					stop := errors.New("crash during bundle deletion")
					err := removeVerifiedBundle(active.CandidateTarget, func(name string) error {
						if name == prefix {
							return stop
						}
						return nil
					})
					if prefix == "bundle" && err != nil || prefix != "bundle" && !errors.Is(err, stop) {
						t.Fatal(err)
					}
				}
			}
			_, err = CleanupArtifacts(ctx, inventory)
			switch prefix {
			case "staging_partial":
				if err == nil {
					t.Fatal("incomplete staging was silently accepted as deleted")
				}
			case "foreign_generation", "changed_material", "foreign_temporary_pointer":
				if err == nil {
					t.Fatal("deleted unrecognized certificate inventory")
				}
				if observed, err := ObservePointer(id); err != nil || observed != active.CandidateTarget {
					t.Fatalf("failure removed pointer: %s %v", observed, err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if _, err := CleanupArtifacts(ctx, inventory); err != nil {
					t.Fatalf("exact resume failed: %v", err)
				}
				for _, artifact := range []Artifact{old, current} {
					path, _ := BundlePath(id, artifact.Generation)
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatalf("managed bundle remains: %v", err)
					}
					staging := filepath.Join(FixedBundlesRoot, "."+filepath.Base(path)+".lanpanel-staging")
					if _, err := os.Lstat(staging); !os.IsNotExist(err) {
						t.Fatalf("managed staging remains: %v", err)
					}
				}
				if _, err := os.Lstat(temporaryArtifactPointerPath(id)); !os.IsNotExist(err) {
					t.Fatalf("temporary pointer remains: %v", err)
				}
				if observed, err := ObservePointer(id); err != nil || observed != "" {
					t.Fatalf("managed pointer remains: %s %v", observed, err)
				}
			}
			if err := VerifyBundleIdentity(foreign.CertificateID, foreign.Generation, foreign.Bundle); err != nil {
				t.Fatalf("unrelated certificate was touched: %v", err)
			}
			if observed, err := ObservePointer(foreign.CertificateID); err != nil || observed == "" {
				t.Fatalf("unrelated pointer was touched: %v", err)
			}
		})
	}
}
