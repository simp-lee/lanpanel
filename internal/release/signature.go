package release

import (
	"crypto/ed25519"
	"fmt"
)

// SignCanonicalManifest returns the fixed raw Ed25519 detached signature used
// by the release artifact. Release tooling must sign the exact bytes that are
// shipped as release.json; re-marshalling after signing is not permitted.
func SignCanonicalManifest(manifestBytes []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if _, err := DecodeReleaseManifest(manifestBytes); err != nil {
		return nil, fmt.Errorf("manifest to sign is invalid: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("release signing key has an invalid size")
	}
	return append([]byte(nil), ed25519.Sign(privateKey, manifestBytes)...), nil
}

func VerifyCanonicalManifestSignature(manifestBytes, signatureBytes []byte) error {
	if len(signatureBytes) != ReleaseSignatureBytes || !ed25519.Verify(trustedReleasePublicKey, manifestBytes, signatureBytes) {
		return fmt.Errorf("release manifest signature is invalid")
	}
	return nil
}
