//go:build linux

package certificates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
)

// VerifyBundleCleanupIdentity accepts only the suffix left by key-first
// deletion. The existing identity.json is retained until last, so no extra
// journal is needed: every remaining file can still be checked against the
// caller's exact bundle authority. An empty owned directory has no material
// left to authorize. This must never be used for activation or serving.
func VerifyBundleCleanupIdentity(id string, generation uint64, expected BundleIdentity) error {
	path, err := BundlePath(id, generation)
	if err != nil || ValidateBundleIdentity(expected) != nil {
		return fmt.Errorf("certificate cleanup authority invalid")
	}
	stage, err := identity.CertificateStageIdentityFor(id)
	if err != nil {
		return err
	}
	members, err := readCertificateBundleMembers(FixedBundlesRoot, filepath.Base(path), filetxn.Owner{UID: stage.UID, GID: stage.GID}, true)
	if err != nil {
		return err
	}
	return verifyCleanupMembers(path, id, generation, expected, members)
}

func verifyCleanupMembers(path, id string, generation uint64, expected BundleIdentity, members map[string][]byte) error {
	if len(members) == 0 {
		return nil
	}
	var stored Identity
	decoder := json.NewDecoder(bytes.NewReader(members["identity.json"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil || decoder.Decode(&struct{}{}) != io.EOF || ValidateIdentity(stored) != nil || stored.ID != id || stored.Generation != generation || BundleIdentityFor(stored) != expected || stored.CertificatePath != filepath.Join(path, "certificate.pem") || stored.PrivateKeyPath != filepath.Join(path, "private-key.pem") {
		return fmt.Errorf("remaining certificate cleanup identity differs")
	}
	certificate, hasCertificate := members["certificate.pem"]
	key, hasKey := members["private-key.pem"]
	if hasKey {
		if !hasCertificate {
			return fmt.Errorf("certificate cleanup order changed: key without certificate")
		}
		return verifyBundleMaterial(path, stored, certificate, key)
	}
	if hasCertificate {
		material, err := inspectCertificateMaterial(certificate)
		if err != nil {
			return err
		}
		return verifyCertificateIdentity(stored, material)
	}
	return nil
}

func removeVerifiedBundle(path string, afterRemove func(string) error) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	for _, name := range []string{"private-key.pem", "certificate.pem", "identity.json"} {
		if err := os.Remove(filepath.Join(path, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		// Make each prefix durable before deleting its remaining verifier.
		if err := directory.Sync(); err != nil {
			return err
		}
		if afterRemove != nil {
			if err := afterRemove(name); err != nil {
				return err
			}
		}
	}
	return os.Remove(path)
}
