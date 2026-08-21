//go:build linux

package qualification

import (
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProtectedReportStoreIsMonotonic(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cleanup.json")
	store := ProtectedReportStore{Path: path}
	now := time.Unix(1_700_000_000, 0).UTC()
	first := release.LiveCleanupReport{SchemaVersion: release.LiveCleanupReportSchemaVersion, RunID: "run-one", SideEffectPlanDigest: release.DigestBytes([]byte("plan")), QualificationInstallManifestDigest: release.DigestBytes([]byte("manifest")), ProtectedInputDigest: release.DigestBytes([]byte("input")), UpdatedAt: now, Items: []release.CleanupItem{{MutationID: "one", ObservedIdentity: "object/one", Result: release.CleanupCleaned}}}
	if err := store.Write(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.UpdatedAt = now.Add(time.Second)
	second.Items = append(append([]release.CleanupItem(nil), first.Items...), release.CleanupItem{MutationID: "two", ObservedIdentity: "object/two", Result: release.CleanupRetained})
	if err := store.Write(second); err != nil {
		t.Fatal(err)
	}
	regressed := second
	regressed.UpdatedAt = now.Add(2 * time.Second)
	regressed.Items = regressed.Items[1:]
	if err := store.Write(regressed); err == nil {
		t.Fatal("cleanup report regression was accepted")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("cleanup report mode changed: %v %v", info, err)
	}
}
