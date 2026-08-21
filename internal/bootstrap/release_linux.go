//go:build linux

package bootstrap

import (
	"fmt"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/identity"
	"lanpanel/internal/release"
	"path/filepath"
)

// ReadCommittedReleaseIdentity returns optional-runtime authority only after the
// protected installation bundle and final bootstrap commit agree.
func ReadCommittedReleaseIdentity() (release.InstallIdentity, error) {
	return readCommittedReleaseIdentity(FixedPaths())
}

func readCommittedReleaseIdentity(paths Paths) (release.InstallIdentity, error) {
	commitBytes, err := readCommittedArtifact(paths.CommitPath, MaximumJournalBytes, 0o644)
	if err != nil {
		return release.InstallIdentity{}, err
	}
	var commit Commit
	if decodeCanonical(commitBytes, &commit) != nil || commit.SchemaVersion != CommitSchemaVersion || !identity.ValidateAttemptID(commit.AttemptID) || !identity.ValidateInstallationID(commit.InstallationID) || !identity.ValidateGenerationID(commit.GenerationID) || commit.JournalSequence == 0 || len(commit.BundleDigest) != 64 || len(commit.ArtifactDigest) != 64 || commit.CommittedAt.IsZero() {
		return release.InstallIdentity{}, fmt.Errorf("bootstrap commit authority is invalid")
	}
	bundleBytes, err := readCommittedArtifact(filepath.Join(paths.InstallationRoot, "bundle.json"), MaximumJournalBytes, 0o600)
	if err != nil {
		return release.InstallIdentity{}, err
	}
	var bundle Bundle
	if decodeCanonical(bundleBytes, &bundle) != nil || validateBundle(bundle) != nil || bundle.AttemptID != commit.AttemptID || bundle.InstallationID != commit.InstallationID || bundle.GenerationID != commit.GenerationID || commit.BundleDigest != release.DigestBytes(bundleBytes) || release.ValidateInstallIdentity(bundle.Release) != nil {
		return release.InstallIdentity{}, fmt.Errorf("installation release authority does not match bootstrap commit")
	}
	accountKey, keyErr := readCommittedArtifact(paths.ACMEAccountKey, acmeaccount.MaximumKeyBytes, 0o600)
	accountFingerprint, fingerprintErr := acmeaccount.Fingerprint(accountKey)
	if keyErr != nil || fingerprintErr != nil || accountFingerprint != bundle.ACMEAccountKeyFingerprint {
		return release.InstallIdentity{}, fmt.Errorf("managed ACME account key does not match release authority")
	}
	return bundle.Release, nil
}
