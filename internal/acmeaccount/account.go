// Package acmeaccount owns the one installation-managed ACME account key.
package acmeaccount

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	ManagedKeyPath      = "/var/lib/lanpanel/installation/acme-account.key"
	ManagedContactPath  = "/var/lib/lanpanel/installation/acme-account.contact"
	MaximumKeyBytes     = 4096
	MaximumContactBytes = 254
)

func ValidContact(value string) bool {
	if len(value) < 3 || len(value) > 254 || strings.Count(value, "@") != 1 || strings.ContainsAny(value, "\x00\r\n /=") {
		return false
	}
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(local) == 0 || len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for index := 0; index < len(local); index++ {
		if !validLocalContactByte(local[index]) {
			return false
		}
	}
	if len(domain) == 0 || len(domain) > 253 || domain != strings.ToLower(domain) || !strings.Contains(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			if !validDomainContactByte(label[index]) {
				return false
			}
		}
	}
	return true
}

func validLocalContactByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune(".!#$%&'*+-?^_`{|}~", rune(value))
}

func validDomainContactByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-'
}

func ReadContact() (string, error) {
	data, err := os.ReadFile(ManagedContactPath)
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data) > MaximumContactBytes || strings.TrimSpace(string(data)) != string(data) || !ValidContact(string(data)) {
		return "", fmt.Errorf("managed ACME contact is missing or invalid")
	}
	return string(data), nil
}

func WriteContact(value string) error {
	if !ValidContact(value) {
		return fmt.Errorf("managed ACME contact is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(ManagedContactPath), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(ManagedContactPath), ".contact-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, value); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, ManagedContactPath)
}

func Generate(reader io.Reader) ([]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), reader)
	if err != nil {
		return nil, fmt.Errorf("generate managed ACME account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode managed ACME account key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := Validate(data); err != nil {
		return nil, err
	}
	return data, nil
}

func Validate(data []byte) error {
	if len(data) == 0 || len(data) > MaximumKeyBytes {
		return fmt.Errorf("managed ACME account key size is invalid")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return fmt.Errorf("managed ACME account key PEM is invalid")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() {
		return fmt.Errorf("managed ACME account key is not P-256")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("re-encode managed ACME account key: %w", err)
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("managed ACME account key is not canonical")
	}
	return nil
}

func Fingerprint(data []byte) (string, error) {
	if err := Validate(data); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
