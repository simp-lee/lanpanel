//go:build linux

package application

import (
	"lanpanel/internal/operations"
	"testing"
)

func TestRegistrationReservedRestartIsRejected(t *testing.T) {
	for _, test := range []struct {
		operation operations.Type
		code      string
	}{
		{operation: operations.StaticRootRegister, code: "static_root_registration_interrupted"},
		{operation: operations.ExternalHTPasswdRegister, code: "external_htpasswd_registration_interrupted"},
	} {
		intent := operations.Reservation{Operation: test.operation, Phase: operations.PhaseReserved}
		if stage := classifyRegistrationRecovery(intent); stage != registrationRecoveryReject {
			t.Fatalf("operation %q stage=%v", test.operation, stage)
		}
		if code := basicReservationRejectionCode(test.operation); code != test.code {
			t.Fatalf("operation %q rejection code=%q", test.operation, code)
		}
	}
}

func TestRegistrationRecoverySkipsRejectedAndTerminalRecords(t *testing.T) {
	for _, phase := range []operations.Phase{operations.PhaseRejected, operations.PhaseTerminal} {
		intent := operations.Reservation{Operation: operations.StaticRootRegister, Phase: phase}
		if stage := classifyRegistrationRecovery(intent); stage != registrationRecoverySkip {
			t.Fatalf("phase %q stage=%v", phase, stage)
		}
	}
}
