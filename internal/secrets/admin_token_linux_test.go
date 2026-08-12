//go:build linux

package secrets

import (
	"bytes"
	"errors"
	"testing"
)

func TestAdminTokenEntropyFailurePrecedesSourceMutation(t *testing.T) {
	_, err := GenerateAdminToken(AdminTokenOptions{Random: bytes.NewReader(nil)})
	if err == nil {
		t.Fatal("entropy failure accepted")
	}
}
func TestAdminTokenGenerationFaultIsFailure(t *testing.T) {
	_, err := GenerateAdminToken(AdminTokenOptions{Random: bytes.NewReader(make([]byte, 32)), Fault: func(phase string) error {
		if phase == "generated" {
			return errors.New("fault")
		}
		return nil
	}})
	if err == nil {
		t.Fatal("generation fault accepted")
	}
}
