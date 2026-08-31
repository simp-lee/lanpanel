//go:build linux

package activation

import (
	"context"
	"errors"
	"lanpanel/internal/certificates"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/publication"
	"strings"
	"testing"
)

func TestPriorRuntimeVerificationCanonicalizesIPv6Listeners(t *testing.T) {
	master := closure.ProcessIdentity{PID: 10}
	manifest := nginx.Manifest{GenerationID: "gen_ipv6", Entries: []nginx.Entry{{Listeners: []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}}}}
	snapshot := closure.RuntimeSnapshot{Master: &master, Generation: manifest.GenerationID, Listeners: []closure.ListenerIdentity{{Protocol: "tcp", Address: "0.0.0.0", Port: 80}, {Protocol: "tcp", Address: "0.0.0.0", Port: 443}, {Protocol: "tcp", Address: "::", Port: 80}, {Protocol: "tcp", Address: "::", Port: 443}}}
	if err := verifyPriorSnapshot(snapshot, manifest); err != nil {
		t.Fatalf("IPv6 runtime listener identity was not canonicalized: %v", err)
	}
}

func TestTemporaryRuntimeEntryRequiresExactGenerationAndIdentity(t *testing.T) {
	candidate := nginx.Entry{Kind: nginx.EntryTemporary, ResourceID: "res_one", Relative: "temporary/res_one.conf", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Listeners: []string{"tcp:0.0.0.0:18080"}, Generation: 2, Temporary: &nginx.TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/run/app.sock", ReadinessPath: "/ready"}}
	prior := candidate
	prior.Generation = 1
	if exactEntryPresent([]nginx.Entry{prior}, candidate) {
		t.Fatal("prior temporary generation satisfied current runtime authority")
	}
	wrongIdentity := candidate
	wrongIdentity.Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if exactEntryPresent([]nginx.Entry{wrongIdentity}, candidate) {
		t.Fatal("same-generation wrong temporary identity satisfied runtime authority")
	}
	if !exactEntryPresent([]nginx.Entry{candidate}, candidate) {
		t.Fatal("exact temporary runtime entry was rejected")
	}
}

func TestActivationInstallFaultsRecoverWithPriorManifestAuthority(t *testing.T) {
	for _, test := range []struct {
		name  string
		paths []string
	}{
		{name: "entry install", paths: nil},
		{name: "manifest install", paths: []string{"/entry.conf"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fault := errors.New(test.name + " fault")
			prior := nginx.Manifest{GenerationID: "prior_generation"}
			active := prior
			_, _, err := installActivationEntry(&active, func() (nginx.Manifest, []string, error) {
				return nginx.Manifest{}, test.paths, fault
			})
			if !errors.Is(err, fault) {
				t.Fatalf("install error=%v", err)
			}
			var restoreErr error
			if active.GenerationID != prior.GenerationID {
				restoreErr = errors.New("prior runtime manifest authority changed")
			}
			failure := activationRecoveryFailure(err, restoreErr)
			if !failure.PriorRestored || !errors.Is(failure, fault) {
				t.Fatalf("recovery failure=%#v active=%#v", failure, active)
			}
		})
	}
}

func TestDomainRuntimeRejectsSameDigestFromPriorGeneration(t *testing.T) {
	paths, owner, _, _ := challengeTransactionFixture(t)
	prior := nginx.Entry{
		Kind:       nginx.EntryApp,
		ResourceID: "res_challenge",
		Relative:   nginx.AppsDirectory + "/res_challenge.conf",
		Digest:     "sha256:" + strings.Repeat("0", 64),
		Domains:    []string{"app.example.test"},
		Generation: 1,
		Domain: &nginx.DomainSite{
			Hosts:              []string{"app.example.test"},
			CertificatePointer: "/var/lib/lanpanel/certificates/active/cert_domain",
			RejectionAuditPath: "/var/log/lanpanel/nginx-rejections.log",
			AuthMode:           "public",
			UpstreamNetwork:    "unix",
			UpstreamAddress:    "/run/lanpanel/res_domain.sock",
		},
	}
	var err error
	prior.Digest, err = nginx.DigestEntry(prior)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := nginx.InstallEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	candidate := prior
	candidate.Generation = 2
	candidateDigest, err := nginx.DigestEntry(candidate)
	if err != nil || candidateDigest != prior.Digest {
		t.Fatalf("same rendering digest=%q err=%v", candidateDigest, err)
	}
	host := Host{Paths: paths, Owner: owner}
	_, err = host.VerifyDomain(context.Background(), publication.Candidate{ResourceID: candidate.ResourceID, Entry: candidate}, domain.AppTarget{})
	if err == nil || !strings.Contains(err.Error(), "manifest candidate missing") {
		t.Fatalf("prior generation satisfied domain verification: %v", err)
	}
}

func testPointerBundleIdentity(value string) certificates.BundleIdentity {
	digest := "sha256:" + strings.Repeat(value, 64)
	return certificates.BundleIdentity{Fingerprint: digest, SANIdentity: digest, ChainIdentity: digest, IssuerIdentity: digest, BindingIdentity: digest, DirectoryIdentity: digest}
}

func TestCertificatePointerHandoffAcceptsExactCandidate(t *testing.T) {
	pointer := certificates.Pointer{CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, CandidateIdentity: testPointerBundleIdentity("a"), ExpectedPriorGeneration: 1, ExpectedPriorIdentity: testPointerBundleIdentity("b")}
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
	pointer := certificates.Pointer{CertificateID: "cert_00000000000000000000000000000000", CandidateGeneration: 2, CandidateIdentity: testPointerBundleIdentity("a"), ExpectedPriorGeneration: 1, ExpectedPriorIdentity: testPointerBundleIdentity("b")}
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
