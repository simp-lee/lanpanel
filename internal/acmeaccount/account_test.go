package acmeaccount

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"
)

func TestManagedAccountContactIsCanonical(t *testing.T) {
	for _, value := range []string{"admin@example.com", "release+acme@example.co.uk"} {
		if !ValidContact(value) {
			t.Fatalf("valid contact rejected: %q", value)
		}
	}
	for _, value := range []string{"@ab", "ab@", "ab@example", "ab@Example.com", ".ab@example.com", "ab..cd@example.com", "ab@-example.com", "ab@example..com", "display name <ab@example.com>"} {
		if ValidContact(value) {
			t.Fatalf("invalid contact accepted: %q", value)
		}
	}
}

func TestGenerateProducesCanonicalP256Key(t *testing.T) {
	data, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := Fingerprint(data)
	if err != nil || !strings.HasPrefix(fingerprint, "sha256:") || len(fingerprint) != 71 {
		t.Fatalf("fingerprint=%q err=%v", fingerprint, err)
	}
}

func TestValidateRejectsNonCanonicalAndWrongPEM(t *testing.T) {
	data, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		append(append([]byte(nil), data...), '\n'),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("foreign")}),
		bytes.Repeat([]byte("x"), MaximumKeyBytes+1),
	} {
		if err := Validate(value); err == nil {
			t.Fatal("unsafe ACME account key was accepted")
		}
	}
}
