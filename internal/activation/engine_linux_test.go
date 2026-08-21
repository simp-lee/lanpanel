//go:build linux

package activation

import (
	"context"
	"errors"
	"lanpanel/internal/certificates"
	"testing"
)

func TestCertificatePointerHandoffAcceptsExactCandidate(t *testing.T) {
	pointer := certificates.Pointer{CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, ExpectedPriorGeneration: 1}
	restored := false
	result, err := activateCandidatePointer(context.Background(), pointer, "/candidate", func(context.Context, certificates.Pointer) (certificates.PointerResult, error) {
		return certificates.PointerResult{CandidateTarget: "/candidate", Durable: true}, nil
	}, func(context.Context, certificates.Pointer, string) error { restored = true; return nil })
	if err != nil || result.CandidateTarget != "/candidate" || restored {
		t.Fatalf("handoff=%#v restored=%t err=%v", result, restored, err)
	}
}

func TestCertificatePointerHandoffPropagatesActivationFaultWithoutRestore(t *testing.T) {
	fault := errors.New("activate fault")
	restored := false
	_, err := activateCandidatePointer(context.Background(), certificates.Pointer{}, "/candidate", func(context.Context, certificates.Pointer) (certificates.PointerResult, error) {
		return certificates.PointerResult{}, fault
	}, func(context.Context, certificates.Pointer, string) error { restored = true; return nil })
	if !errors.Is(err, fault) || restored {
		t.Fatalf("err=%v restored=%t", err, restored)
	}
}

func TestCertificatePointerPostRenameFaultRestoresPriorPointer(t *testing.T) {
	fault := errors.New("fsync fault")
	restored := false
	_, err := activateCandidatePointer(context.Background(), certificates.Pointer{}, "/candidate", func(context.Context, certificates.Pointer) (certificates.PointerResult, error) {
		return certificates.PointerResult{CandidateTarget: "/candidate"}, fault
	}, func(context.Context, certificates.Pointer, string) error { restored = true; return nil })
	var failure *Failure
	if !errors.As(err, &failure) || !failure.PriorRestored || !restored || !errors.Is(err, fault) {
		t.Fatalf("err=%v restored=%t", err, restored)
	}
}

func TestCertificatePointerPostRenameRestoreFailureIsReported(t *testing.T) {
	fault := errors.New("verify fault")
	restoreFault := errors.New("restore fault")
	_, err := activateCandidatePointer(context.Background(), certificates.Pointer{}, "/candidate", func(context.Context, certificates.Pointer) (certificates.PointerResult, error) {
		return certificates.PointerResult{CandidateTarget: "/candidate"}, fault
	}, func(context.Context, certificates.Pointer, string) error { return restoreFault })
	var failure *Failure
	if !errors.As(err, &failure) || failure.PriorRestored || !errors.Is(err, fault) || !errors.Is(err, restoreFault) {
		t.Fatalf("err=%v", err)
	}
}

func TestCertificatePointerTargetMismatchRestoresBeforeFailure(t *testing.T) {
	pointer := certificates.Pointer{CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, ExpectedPriorGeneration: 1}
	restoredTarget := ""
	_, err := activateCandidatePointer(context.Background(), pointer, "/expected", func(context.Context, certificates.Pointer) (certificates.PointerResult, error) {
		return certificates.PointerResult{CandidateTarget: "/observed", Durable: true}, nil
	}, func(_ context.Context, got certificates.Pointer, target string) error {
		if got != pointer {
			t.Fatal("pointer authority changed")
		}
		restoredTarget = target
		return nil
	})
	if err == nil || restoredTarget != "/observed" {
		t.Fatalf("err=%v restored=%q", err, restoredTarget)
	}
}
