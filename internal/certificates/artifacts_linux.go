//go:build linux

package certificates

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// CleanupArtifacts removes only resource-owned, exact staged identities. The
// caller must hold its deleting operation/exposure authority and prove ingress
// closed. Inventory is retained through every deletion prefix by that owner.
func CleanupArtifacts(ctx context.Context, artifacts []Artifact) ([]string, error) {
	if err := ValidateArtifacts(artifacts); err != nil {
		return nil, err
	}
	if len(artifacts) == 0 {
		return nil, nil
	}
	groups := map[string][]Artifact{}
	ids := []string{}
	for _, artifact := range artifacts {
		path, _ := BundlePath(artifact.CertificateID, artifact.Generation)
		groups[path] = append(groups[path], artifact)
		staging := filepath.Join(FixedBundlesRoot, "."+filepath.Base(path)+".lanpanel-staging")
		groups[staging] = append(groups[staging], artifact)
		ids = append(ids, artifact.CertificateID)
	}
	ids = slices.Compact(ids)
	entries, err := os.ReadDir(FixedBundlesRoot)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		for _, id := range ids {
			if strings.HasPrefix(strings.TrimPrefix(entry.Name(), "."), id+"-") && len(groups[filepath.Join(FixedBundlesRoot, entry.Name())]) == 0 {
				return nil, fmt.Errorf("certificate has a bundle outside deleting inventory")
			}
		}
	}
	// Verify every remaining bundle before removing any pointer. Multiple exact
	// identities for one generation are possible after a failed staging retry;
	// only material actually authorized by that resource may be removed.
	selected := map[string]Artifact{}
	for path, candidates := range groups {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		var verifyErr error
		for _, artifact := range candidates {
			verifyErr = verifyArtifactCleanupPath(path, artifact)
			if verifyErr == nil {
				selected[path] = artifact
				break
			}
		}
		if verifyErr != nil {
			return nil, verifyErr
		}
	}
	pointers := map[string]string{}
	temporaryPointers := map[string]string{}
	for _, id := range ids {
		observed, err := ObservePointer(id)
		if err != nil {
			return nil, err
		}
		if observed != "" {
			artifact, present := selected[observed]
			expected, _ := BundlePath(artifact.CertificateID, artifact.Generation)
			if !present || artifact.CertificateID != id || observed != expected {
				return nil, fmt.Errorf("certificate pointer is outside deleting inventory")
			}
			if err := VerifyBundleIdentity(id, artifact.Generation, artifact.Bundle); err != nil {
				return nil, err
			}
		}
		pointers[id] = observed
		temporary, err := readLink(temporaryArtifactPointerPath(id))
		if errors.Is(err, os.ErrNotExist) {
			temporary = ""
		} else if err != nil {
			return nil, err
		}
		if temporary != "" {
			candidates := groups[temporary]
			if len(candidates) == 0 || candidates[0].CertificateID != id {
				return nil, fmt.Errorf("temporary certificate pointer is outside deleting inventory")
			}
			expected, _ := BundlePath(id, candidates[0].Generation)
			if temporary != expected {
				return nil, fmt.Errorf("temporary certificate pointer targets uncommitted staging")
			}
		}
		temporaryPointers[id] = temporary
	}
	removed := []string{}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if err := removeTemporaryArtifactPointer(id, temporaryPointers[id]); err != nil {
			return removed, err
		}
		removed = append(removed, temporaryArtifactPointerPath(id))
		if target := pointers[id]; target != "" {
			artifact := selected[target]
			if err := RemovePointer(ctx, Pointer{CertificateID: id, CandidateGeneration: artifact.Generation, CandidateIdentity: artifact.Bundle}, target); err != nil {
				return removed, err
			}
		}
		// Absence may be the prefix left by an interrupted unlink/fsync.
		if err := syncCertificateDirectory(FixedActiveRoot); err != nil {
			return removed, err
		}
		path, _ := ActivePointerPath(id)
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("certificate pointer absence unverified: %w", err)
		}
		removed = append(removed, path)
	}
	paths := make([]string, 0, len(groups))
	for path := range groups {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		artifact, present := selected[path]
		if present {
			stage, err := identity.CertificateStageIdentityFor(artifact.CertificateID)
			if err != nil {
				return removed, err
			}
			if strings.HasPrefix(filepath.Base(path), ".") {
				if err := verifyArtifactCleanupPath(path, artifact); err != nil {
					return removed, err
				}
				if err := removeVerifiedBundle(path, nil); err != nil {
					return removed, err
				}
			} else if err := RemoveInactiveBundle(artifact.CertificateID, artifact.Generation, artifact.Bundle, stage.UID, stage.GID); err != nil {
				return removed, err
			}
		}
		if err := syncCertificateDirectory(FixedBundlesRoot); err != nil {
			return removed, err
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("certificate bundle absence unverified: %w", err)
		}
		removed = append(removed, path)
	}
	return removed, nil
}

func temporaryArtifactPointerPath(id string) string {
	return filepath.Join(FixedActiveRoot, "."+id+".current.lanpanel-pointer")
}

func removeTemporaryArtifactPointer(id, expected string) error {
	fd, err := unix.Open(FixedActiveRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	name := filepath.Base(temporaryArtifactPointerPath(id))
	observed, err := readPointer(fd, name)
	if errors.Is(err, os.ErrNotExist) {
		observed = ""
	} else if err != nil {
		return err
	}
	if observed != expected {
		return fmt.Errorf("temporary certificate pointer changed before cleanup")
	}
	if observed != "" {
		if err := unix.Unlinkat(fd, name, 0); err != nil {
			return err
		}
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("temporary certificate pointer absence unverified: %w", err)
	}
	return nil
}

func verifyArtifactCleanupPath(path string, artifact Artifact) error {
	final, err := BundlePath(artifact.CertificateID, artifact.Generation)
	if err != nil {
		return err
	}
	if path == final {
		return VerifyBundleCleanupIdentity(artifact.CertificateID, artifact.Generation, artifact.Bundle)
	}
	if path != filepath.Join(FixedBundlesRoot, "."+filepath.Base(final)+".lanpanel-staging") {
		return fmt.Errorf("certificate staging identity differs")
	}
	stage, err := identity.CertificateStageIdentityFor(artifact.CertificateID)
	if err != nil {
		return err
	}
	members, err := readCertificateBundleMembers(FixedBundlesRoot, filepath.Base(path), filetxn.Owner{UID: stage.UID, GID: stage.GID}, true)
	if err != nil {
		return err
	}
	// CommitNewDirectory writes certificate, identity, then key. A complete
	// certificate-only prefix is verifiable from the pre-staging authority.
	if len(members) == 1 && members["certificate.pem"] != nil {
		material, err := inspectCertificateMaterial(members["certificate.pem"])
		if err != nil {
			return err
		}
		expected := artifact.Bundle
		if material.fingerprint != expected.Fingerprint || material.chainIdentity != expected.ChainIdentity || material.issuerIdentity != expected.IssuerIdentity || sum([]byte(strings.Join(material.domains, "\x00"))) != expected.SANIdentity {
			return fmt.Errorf("staged certificate material differs")
		}
		return nil
	}
	return verifyCleanupMembers(final, artifact.CertificateID, artifact.Generation, artifact.Bundle, members)
}

func syncCertificateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
