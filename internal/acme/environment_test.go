package acme

import (
	"bytes"
	"testing"
)

func TestEnvironmentFrameIsClosedAndRejectsDuplicates(t *testing.T) {
	frame, err := EncodeEnvironmentFrame([]string{"LANG=C", "LC_ALL=C", "CF_DNS_API_TOKEN_FILE=/protected/token"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvironmentFrame(bytes.NewReader(frame))
	if err != nil || len(decoded) != 3 {
		t.Fatalf("decoded=%v err=%v", decoded, err)
	}
	if _, err := DecodeEnvironmentFrame(bytes.NewReader([]byte(EnvironmentFrameSchema + "\x00LANG=C\x00LANG=C\x00"))); err == nil {
		t.Fatal("duplicate environment key accepted")
	}
}
