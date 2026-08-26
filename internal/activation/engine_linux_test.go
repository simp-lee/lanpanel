//go:build linux

package activation

import (
	"context"
	"errors"
	"lanpanel/internal/certificates"
	"lanpanel/internal/nginx"
	"testing"
)

func TestTemporaryRuntimeEntryRequiresExactGenerationAndIdentity(t *testing.T) {
	candidate := nginx.Entry{Kind: nginx.EntryTemporary, ResourceID: "res_one", Relative: "temporary/res_one.conf", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Listeners: []string{"tcp:0.0.0.0:18080"}, Generation: 2, Temporary: &nginx.TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/run/app.sock", ReadinessPath: "/ready"}}
	prior := candidate
	prior.Generation = 1
	if exactTemporaryEntryPresent([]nginx.Entry{prior}, candidate) {
		t.Fatal("prior temporary generation satisfied current runtime authority")
	}
	wrongIdentity := candidate
	wrongIdentity.Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if exactTemporaryEntryPresent([]nginx.Entry{wrongIdentity}, candidate) {
		t.Fatal("same-generation wrong temporary identity satisfied runtime authority")
	}
	if !exactTemporaryEntryPresent([]nginx.Entry{candidate}, candidate) {
		t.Fatal("exact temporary runtime entry was rejected")
	}
}

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
