package certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"lanpanel/internal/filetxn"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestObserveIdentityRejectsUnsafeMembersBeforeReading(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("certificate bundle parent contract is root-owned")
	}
	now := time.Now().UTC().Truncate(time.Second)
	chain, key := issuedFixture(t, now, []string{"control.example.test"})
	parsed, err := parseCertificateChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed[len(parsed)-1])
	material, err := ValidateIssuedWithRoots(chain, key, []string{"control.example.test"}, now, "https://acme.example.test/directory", roots)
	if err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{"symlink", func(path string) error { return os.Symlink("/dev/zero", path) }},
		{"fifo", func(path string) error { return unix.Mkfifo(path, 0o600) }},
		{"oversized", func(path string) error {
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			defer func(ignore func() error) { _ = ignore() }(file.Close)
			return file.Truncate((1 << 20) + 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			id := "cert_00000000000000000000000000000001"
			identity, err := StageIssued(context.Background(), parent, id, 1, sum([]byte("binding")), material, owner, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ObserveIdentity(parent, id, 1, owner); err != nil {
				t.Fatalf("observe staged identity: %v", err)
			}
			if err := os.Remove(identity.PrivateKeyPath); err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(filepath.Join(filepath.Dir(identity.PrivateKeyPath), "private-key.pem")); err != nil {
				t.Fatal(err)
			}
			if _, err := ObserveIdentity(parent, id, 1, owner); err == nil {
				t.Fatal("unsafe certificate bundle member was accepted")
			}
		})
	}
}

func TestBootstrapCertificateIsShortLivedExactSANPKCS8(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	material, err := GenerateBootstrap([]string{"b.example.test", "a.example.test"}, now, bytes.NewReader(bytes.Repeat([]byte{9}, 512)))
	if err != nil {
		t.Fatal(err)
	}
	if !material.NotAfter().Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("notAfter=%s", material.NotAfter())
	}
	if _, err := ValidateIssued(material.CertificatePEM(), material.PrivateKeyPEM(), []string{"a.example.test", "b.example.test"}, now, "https://acme.example.test/directory"); err == nil {
		t.Fatal("bootstrap accepted as issued")
	}
}

func TestIssuedCertificateAcceptsLegoECKeyAndCanonicalizesPKCS8(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	chain, key := issuedFixture(t, now, []string{"app.example.test"})
	certificates, _ := parseCertificateChain(chain)
	roots := x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])
	block, _ := pem.Decode(key)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("fixture key is not ECDSA")
	}
	legacyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	legacy := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: legacyDER})
	material, err := ValidateIssuedWithRoots(chain, legacy, []string{"app.example.test"}, now, "https://acme.example.test/directory", roots)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := pem.Decode(material.PrivateKeyPEM())
	if canonical == nil || canonical.Type != "PRIVATE KEY" {
		t.Fatal("issued key was not canonical PKCS8")
	}
}

func TestIssuedCertificateRequiresExactSANKeyAndChain(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	chain, key := issuedFixture(t, now, []string{"a.example.test", "b.example.test"})
	parsed, _ := parseCertificateChain(chain)
	roots := x509.NewCertPool()
	roots.AddCert(parsed[len(parsed)-1])
	material, err := ValidateIssuedWithRoots(chain, key, []string{"b.example.test", "a.example.test"}, now, "https://acme.example.test/directory", roots)
	if err != nil {
		t.Fatal(err)
	}
	if material.Fingerprint() == "" || !material.NotAfter().After(now) {
		t.Fatalf("material incomplete")
	}
	if _, err := ValidateIssuedWithRoots(chain, key, []string{"a.example.test", "b.example.test"}, now, "https://acme.example.test/directory", x509.NewCertPool()); err == nil {
		t.Fatal("untrusted chain accepted")
	}
	blocks, _ := parseCertificateChain(chain)
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blocks[0].Raw})
	issuer := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blocks[1].Raw})
	joined, err := JoinLegoChain(leaf, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateIssuedWithRoots(joined, key, []string{"a.example.test", "b.example.test"}, now, "https://acme.example.test/directory", roots); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateIssuedWithRoots(chain, key, []string{"a.example.test"}, now, "https://acme.example.test/directory", roots); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	if _, err := ValidateIssuedWithRoots(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), []string{"a.example.test", "b.example.test"}, now, "https://acme.example.test/directory", roots); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func issuedFixture(t *testing.T, now time.Time, domains []string) ([]byte, []byte) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: new(big.Int).Lsh(big.NewInt(1), 80), Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
