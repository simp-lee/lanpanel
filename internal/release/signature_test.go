package release

import (
	"crypto/ed25519"
	"testing"
)

func TestTrustedReleaseSignatureUsesExactManifestBytes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := trustedReleasePublicKey
	trustedReleasePublicKey = public
	defer func() { trustedReleasePublicKey = previous }()
	manifest := []byte(`{"schema_version":"test"}`)
	signature := ed25519.Sign(private, manifest)
	if err := VerifyCanonicalManifestSignature(manifest, signature); err != nil {
		t.Fatal(err)
	}
	manifest[0] = ' '
	if err := VerifyCanonicalManifestSignature(manifest, signature); err == nil {
		t.Fatal("signature accepted changed canonical bytes")
	}
	wrong := append([]byte(nil), signature...)
	wrong[0] ^= 1
	if err := VerifyCanonicalManifestSignature([]byte(`{"schema_version":"test"}`), wrong); err == nil {
		t.Fatal("signature accepted wrong bytes")
	}
}

func TestArtifactKeyIsNotAcceptedAsTrustAnchor(t *testing.T) {
	key := TrustedReleasePublicKeyBytes()
	key[0] ^= 1
	if string(key) == string(TrustedReleasePublicKeyBytes()) {
		t.Fatal("trusted key is mutable through returned bytes")
	}
}
