package secrets

import (
	"bytes"
	"errors"
	"testing"
)

func TestValueFingerprintDoesNotConsumePlaintext(t *testing.T) {
	value, _ := New([]byte("sentinel-secret"))
	first, err := value.Fingerprint()
	if err != nil || first == "" {
		t.Fatal(err)
	}
	second, err := value.Fingerprint()
	if err != nil || second != first {
		t.Fatal("fingerprint changed")
	}
	if err := value.Use(func(actual []byte) error {
		if string(actual) != "sentinel-secret" {
			t.Fatal("secret changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := value.Fingerprint(); err == nil {
		t.Fatal("destroyed secret remained fingerprintable")
	}
}

func TestValueIsConsumableOnceAndDestroyed(t *testing.T) {
	sentinel := []byte("sentinel-secret")
	value, _ := New(sentinel)
	if err := value.Use(func(actual []byte) error {
		if !bytes.Equal(actual, sentinel) {
			t.Fatal("secret changed")
		}
		return errors.New("consumer failed")
	}); err == nil {
		t.Fatal("consumer failure lost")
	}
	if err := value.Use(func([]byte) error { return nil }); err == nil {
		t.Fatal("secret replayed")
	}
}
