package identity

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestInstallationMaterialUsesBoundedIndependentRandomValues(t *testing.T) {
	material, err := Generate(bytes.NewReader(make([]byte, attemptRandomBytes+installationBytes+generationBytes+5+AdminTokenRandomBytes)))
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	if !ValidateAttemptID(material.AttemptID) || !ValidateInstallationID(material.InstallationID) || !ValidateGenerationID(material.GenerationID) {
		t.Fatalf("invalid generated identities: %#v", material)
	}
	if material.Authority.Address != "127.0.0.0" || material.Authority.Port != managementPortBase {
		t.Fatalf("authority=%#v", material.Authority)
	}
	token := material.TakeAdminToken()
	if len(token) != AdminTokenRandomBytes*2 || strings.Trim(tokenString(token), "0") != "" {
		t.Fatal("admin token encoding is not exact")
	}
	clear(token)
	if material.TakeAdminToken() != nil {
		t.Fatal("admin token was returned twice")
	}
}

func TestRandomFailureNeverFallsBack(t *testing.T) {
	for size := 0; size < attemptRandomBytes+installationBytes+generationBytes+5+AdminTokenRandomBytes; size++ {
		if _, err := Generate(bytes.NewReader(make([]byte, size))); err == nil {
			t.Fatalf("short random stream of %d bytes succeeded", size)
		}
	}
	if _, err := GenerateAdminToken(errorReader{}); err == nil {
		t.Fatal("admin token generation failure used a fallback")
	}
}

func TestManagementAuthorityHasExactRandomSpace(t *testing.T) {
	authority, err := GenerateManagementAuthority(bytes.NewReader([]byte{1, 2, 3, 0xff, 0xff}))
	if err != nil {
		t.Fatal(err)
	}
	if authority.Address != "127.1.2.3" || authority.Port != 65535 {
		t.Fatalf("authority=%#v", authority)
	}
	for _, invalid := range []ManagementAuthority{{Address: "0.0.0.0", Port: 50000}, {Address: "127.0.0.1", Port: 1024}, {Address: "localhost", Port: 50000}} {
		if ValidateManagementAuthority(invalid) == nil {
			t.Fatalf("invalid authority accepted: %#v", invalid)
		}
	}
}

func tokenString(value []byte) string { return string(value) }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

var _ io.Reader = errorReader{}
