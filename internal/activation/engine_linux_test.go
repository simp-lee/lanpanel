//go:build linux

package activation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"lanpanel/internal/certificates"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/publication"
	"lanpanel/internal/safety"
	"reflect"
	"strings"
	"testing"
	"time"
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

func normalActivationReloadFixture(t *testing.T) (nginx.Paths, filetxn.Owner, publication.Candidate, nginx.ActivationSnapshot, *ReloadAuthoritySnapshot, ReloadAuthority) {
	t.Helper()
	paths, owner, _, initial := challengeTransactionFixture(t)
	if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, initial); err != nil {
		t.Fatal(err)
	}
	resourceID := "res_normal_activation"
	priorEntry := nginx.Entry{Kind: nginx.EntryTemporary, ResourceID: resourceID, Relative: nginx.TemporaryDirectory + "/" + resourceID + ".conf", Digest: challengeTestDigest, Listeners: []string{"tcp:0.0.0.0:18080"}, Generation: 1, Temporary: &nginx.TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/run/lanpanel/prior.sock", ReadinessPath: "/ready"}}
	manifest, _, err := nginx.InstallEntry(context.Background(), paths, owner, priorEntry)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Entries {
		if entry.ResourceID == resourceID {
			priorEntry = entry
		}
	}
	candidateEntry := priorEntry
	candidateEntry.Generation = 2
	candidateEntry.Temporary = &nginx.TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/run/lanpanel/candidate.sock", ReadinessPath: "/ready"}
	candidateEntry.Digest, err = nginx.DigestEntry(candidateEntry)
	if err != nil {
		t.Fatal(err)
	}
	bundle := func(id string, entry nginx.Entry) domain.PublicationBundle {
		return domain.PublicationBundle{ID: id, Generation: entry.Generation, ConfigDigest: "sha256:" + strings.Repeat(string(id[0]), 64), Kind: domain.PublicationTemporaryHTTP, EndpointIdentity: challengeTestDigest, SiteIdentity: entry.Digest, ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 18080}}, TemporaryHTTP: &domain.TemporaryHTTPBundleIdentity{PublicIPv4: entry.Temporary.PublicIPv4, Port: entry.Temporary.Port, HostAuthority: entry.Temporary.HostAuthority, ListenerIdentity: challengeTestDigest}}
	}
	priorBundle := bundle("a-prior", priorEntry)
	candidateBundle := bundle("b-candidate", candidateEntry)
	candidateRaw, err := json.Marshal(candidateBundle)
	if err != nil {
		t.Fatal(err)
	}
	candidateSum := sha256.Sum256(candidateRaw)
	candidateBundleDigest := "sha256:" + hex.EncodeToString(candidateSum[:])
	intent := domain.ActivationIntent{ID: "activation-normal", JobID: "job-normal", PlanID: "plan-normal", Generation: 2, Candidate: candidateBundle, PriorState: domain.PublicationPublished, Prior: &priorBundle}
	installation := domain.Installation{InstallationID: "ins_challenge", Resources: []domain.AppResource{{ID: resourceID, Publication: domain.AppPublication{Kind: domain.PublicationTemporaryHTTP, TemporaryHTTP: &domain.TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 18080}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationActivating, ActivationIntent: &intent}}}}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: resourceID, GenerationSequence: 2, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: challengeTestDigest, Reactivating: &safety.Reactivating{Generation: 2, PriorGeneration: 1, PlanID: intent.PlanID, CandidateDigest: candidateBundle.ConfigDigest, CandidateBundle: candidateBundleDigest, BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}, TemporaryHTTP: true}}}
	if err := safety.Validate(state); err != nil {
		t.Fatal(err)
	}
	snapshot := &ReloadAuthoritySnapshot{Safety: state, Installation: installation, Ownership: map[string]string{resourceID: challengeTestDigest}}
	authority := challengeReloadAuthorityFromSnapshot(snapshot, func() time.Time { return time.Now().UTC() })
	disk, err := nginx.SnapshotActivation(paths, owner, candidateEntry)
	if err != nil {
		t.Fatal(err)
	}
	candidate := publication.Candidate{ResourceID: resourceID, Generation: 2, Bundle: candidateBundle, BundleDigest: candidateBundleDigest, Entry: candidateEntry, PriorBundle: &priorBundle}
	return paths, owner, candidate, disk, snapshot, authority
}

func TestNormalActivationPriorReloadAllowsSafetyGenerationGap(t *testing.T) {
	_, _, _, priorDisk, authoritySnapshot, authority := normalActivationReloadFixture(t)
	intent := authoritySnapshot.Installation.Resources[0].PublicationRecord.ActivationIntent
	intent.Generation = 3
	intent.Candidate.Generation = 3
	candidateRaw, err := json.Marshal(intent.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidateSum := sha256.Sum256(candidateRaw)
	resource := &authoritySnapshot.Safety.Resources[0]
	resource.GenerationSequence = 3
	resource.Reactivating.Generation = 3
	resource.Reactivating.PriorGeneration = 2
	resource.Reactivating.CandidateBundle = "sha256:" + hex.EncodeToString(candidateSum[:])
	if err := safety.Validate(authoritySnapshot.Safety); err != nil {
		t.Fatal(err)
	}
	if err := authority.Guard(priorDisk.Manifest); err != nil {
		t.Fatalf("exact prior publication was rejected after a failed-generation gap: %v", err)
	}
}

func TestNormalActivationRejectsChangedSafetyBeforeDiskMutation(t *testing.T) {
	paths, owner, candidate, priorDisk, authoritySnapshot, authority := normalActivationReloadFixture(t)
	authoritySnapshot.Safety.Resources[0].Reactivating.PlanID = "plan-changed-before-install"
	if _, _, err := prepareApplicationExpansion(paths, owner, candidate.Entry, authority); err == nil {
		t.Fatal("changed pre-install safety authorized candidate graph")
	}
	audited, err := nginx.Audit(paths, owner)
	if err != nil || !reflect.DeepEqual(audited, priorDisk.Manifest) {
		t.Fatalf("pre-install rejection changed disk graph: %#v err=%v", audited, err)
	}
}

func TestNormalActivationRereadsSafetyAfterInstallBeforeSignal(t *testing.T) {
	paths, owner, candidate, _, authoritySnapshot, authority := normalActivationReloadFixture(t)
	prospective, err := nginx.ProspectiveManifest(mustAuditActivationGraph(t, paths, owner), candidate.Entry)
	if err != nil || guardReload(prospective, authority) != nil {
		t.Fatalf("initial prospective authority rejected: %v", err)
	}
	manifest, _, err := nginx.InstallEntry(context.Background(), paths, owner, candidate.Entry)
	if err != nil {
		t.Fatal(err)
	}
	authoritySnapshot.Safety.Resources[0].Reactivating.PlanID = "plan-changed-after-install"
	signals := 0
	err = signalAuthorizedReload(paths, owner, manifest, authority, func() error {
		signals++
		return nil
	})
	if err == nil || signals != 0 {
		t.Fatalf("changed safety signaled reload: signals=%d err=%v", signals, err)
	}
}

func TestNormalActivationRollbackStopsWhenPriorGraphLosesAuthority(t *testing.T) {
	paths, owner, candidate, priorDisk, authoritySnapshot, authority := normalActivationReloadFixture(t)
	if err := authority.Guard(priorDisk.Manifest); err != nil {
		t.Fatalf("exact activation prior lacked initial rollback authority: %v", err)
	}
	if _, _, err := nginx.InstallEntry(context.Background(), paths, owner, candidate.Entry); err != nil {
		t.Fatal(err)
	}
	if _, err := nginx.RestoreActivation(context.Background(), paths, owner, candidate.Entry, priorDisk); err != nil {
		t.Fatal(err)
	}
	authoritySnapshot.Safety.Resources[0].Reactivating.PlanID = "plan-changed-before-rollback"
	reloads, stops := 0, 0
	err := reloadAuthorizedOrStop(func() error {
		return guardAuditedReload(paths, owner, priorDisk.Manifest, authority)
	}, func() error {
		reloads++
		return nil
	}, func() error {
		stops++
		return nil
	})
	if err == nil || reloads != 0 || stops != 1 {
		t.Fatalf("unauthorized rollback reloads=%d stops=%d err=%v", reloads, stops, err)
	}
}

func TestNormalActivationRollbackStopsWhenReloadSignalFails(t *testing.T) {
	reloadFailure := errors.New("reload signal failed")
	reloads, stops := 0, 0
	err := reloadAuthorizedOrStop(func() error { return nil }, func() error {
		reloads++
		return reloadFailure
	}, func() error {
		stops++
		return nil
	})
	if !errors.Is(err, reloadFailure) || reloads != 1 || stops != 1 {
		t.Fatalf("failed rollback reloads=%d stops=%d err=%v", reloads, stops, err)
	}
}

func mustAuditActivationGraph(t *testing.T, paths nginx.Paths, owner filetxn.Owner) nginx.Manifest {
	t.Helper()
	manifest, err := nginx.Audit(paths, owner)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
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
