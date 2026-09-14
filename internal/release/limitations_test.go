package release

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func readREADME(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	return data
}

func TestREADMEIsValidKnownLimitationsAsset(t *testing.T) {
	if err := ValidateKnownLimitations(readREADME(t)); err != nil {
		t.Fatalf("README.md is not a valid known limitations asset: %v", err)
	}
}

func TestValidateKnownLimitationsRejectsMissingRequiredStatement(t *testing.T) {
	data := readREADME(t)
	data = bytes.Replace(data, []byte("Key revoke does not expire a registered device."), nil, 1)
	if err := ValidateKnownLimitations(data); err == nil {
		t.Fatal("ValidateKnownLimitations accepted README.md without a required statement")
	}
}
