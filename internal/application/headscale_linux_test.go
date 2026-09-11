//go:build linux

package application

import (
	"encoding/json"
	"lanpanel/internal/identity"
	"lanpanel/internal/release"
	"strings"
	"testing"
	"time"
)

func TestCommittedBootstrapWireKeepsStructCanonicalOrderAndOriginalDigest(t *testing.T) {
	bundle := installationBundleWire{SchemaVersion: "lanpanel.installation.bundle.v2", AttemptID: "bst_" + strings.Repeat("a", 64), InstallationID: "ins_00000000000000000000000000000001", GenerationID: "gen_00000000000000000000000000000001", SafetyGeneration: 1, Fingerprint: "0123456789abcdef", Management: identity.ManagementAuthority{Address: "127.1.2.3", Port: 50000}, PreflightDigest: "sha256:" + strings.Repeat("b", 64), ACMEAccountKeyFingerprint: "sha256:" + strings.Repeat("d", 64)}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(bundleBytes), `{"schema_version":"lanpanel.installation.bundle.v2","attempt_id":`) {
		t.Fatalf("wire field order changed: %s", bundleBytes)
	}
	var decoded installationBundleWire
	if err := decodeProtectedCanonical(bundleBytes, &decoded); err != nil {
		t.Fatal(err)
	}
	commit := bootstrapCommitWire{SchemaVersion: "lanpanel.bootstrap.commit.v1", AttemptID: bundle.AttemptID, InstallationID: bundle.InstallationID, GenerationID: bundle.GenerationID, JournalSequence: 2, BundleDigest: release.DigestBytes(bundleBytes), ArtifactDigest: strings.Repeat("c", 64), CommittedAt: time.Unix(1_700_000_000, 0).UTC()}
	commitBytes, err := json.Marshal(commit)
	if err != nil {
		t.Fatal(err)
	}
	var decodedCommit bootstrapCommitWire
	if err := decodeProtectedCanonical(commitBytes, &decodedCommit); err != nil || decodedCommit.BundleDigest != release.DigestBytes(bundleBytes) {
		t.Fatalf("commit wire did not bind original bundle bytes: %v", err)
	}
}
