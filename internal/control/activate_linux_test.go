//go:build linux

package control

import (
	"context"
	"errors"
	"lanpanel/internal/challenge"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestChallengeControlEntryComparisonUsesCanonicalEncoding(t *testing.T) {
	rendered := testRendered(t)
	certificate := testCertificateIdentity(IssueRequest{JobID: "job_control", PlanID: "plan_control", IntentGeneration: 1, CertificateID: rendered.Candidate.CertificateID, BindingDigest: rendered.Candidate.CertificateBinding, Domain: rendered.Candidate.ControlDomain})
	bundle, err := BuildActivation("ins_00000000000000000000000000000001", rendered.Candidate, certificate)
	if err != nil {
		t.Fatal(err)
	}
	audited := bundle.Entry
	domainCopy := *audited.Domain
	domainCopy.Static = nil
	audited.Domain = &domainCopy
	if !sameNginxEntry(audited, bundle.Entry) {
		t.Fatal("canonical audited control entry differs only by an omitted empty route set")
	}
}

func TestActivationAuthorityFailurePrecedesPhysicalWork(t *testing.T) {
	rendered := testRendered(t)
	certificate := testCertificateIdentity(IssueRequest{JobID: "job_control", PlanID: "plan_control", IntentGeneration: 1, CertificateID: rendered.Candidate.CertificateID, BindingDigest: rendered.Candidate.CertificateBinding, Domain: rendered.Candidate.ControlDomain})
	bundle, err := BuildActivation("ins_00000000000000000000000000000001", rendered.Candidate, certificate)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	marker := filepath.Join(root, "unchanged")
	if err := os.WriteFile(marker, []byte("authority-bound"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := (&ActivationHost{}).Activate(context.Background(), bundle, ActivationAuthority{})
	if err == nil || !strings.Contains(err.Error(), "headscale activation runtime authority invalid") {
		t.Fatalf("invalid authority did not fail before host access: result=%+v err=%v", result, err)
	}
	data, readErr := os.ReadFile(marker)
	if readErr != nil || string(data) != "authority-bound" {
		t.Fatalf("authority failure changed physical state: %q %v", data, readErr)
	}
	entries, readDirErr := os.ReadDir(root)
	if readDirErr != nil || len(entries) != 1 {
		t.Fatalf("authority failure created physical output: entries=%v err=%v", entries, readDirErr)
	}
}

func TestHeadscaleChallengeRemovalProspectiveBaseIsGuarded(t *testing.T) {
	rendered := testRendered(t)
	identity := testCertificateIdentity(IssueRequest{JobID: "job_control", PlanID: "plan_control", IntentGeneration: 1, CertificateID: rendered.Candidate.CertificateID, BindingDigest: rendered.Candidate.CertificateBinding, Domain: rendered.Candidate.ControlDomain})
	bundle, err := BuildActivation("ins_00000000000000000000000000000001", rendered.Candidate, identity)
	if err != nil {
		t.Fatal(err)
	}
	pending := safety.ChallengePending{Generation: bundle.Entry.Generation + 1, PlanID: "plan_renew", Method: "http-01", ConfigDigest: testDigest("config"), SANIdentity: testDigest("san"), ACMEBinding: testDigest("binding"), CertificateIdentity: identity.ID, Host: rendered.Candidate.ControlDomain, Hosts: []string{rendered.Candidate.ControlDomain}, TokenPath: "/.well-known/acme-challenge", Webroot: "/var/lib/lanpanel/certificates/webroot/" + identity.ID, BootstrapIdentity: testDigest("bootstrap"), BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}}
	prepared, err := challenge.PreparedHTTP("headscale", pending)
	if err != nil {
		t.Fatal(err)
	}
	challengeEntry, err := headscaleChallengeEntry(bundle, prepared)
	if err != nil {
		t.Fatal(err)
	}
	manifest := nginx.Manifest{SchemaVersion: nginx.ManifestSchema, InstallationID: bundle.InstallationID, GenerationID: "gen_control", DefaultCertFingerprint: testDigest("default"), MainDigest: testDigest("main"), SanitizerDigest: testDigest("sanitizer"), Entries: []nginx.Entry{challengeEntry}}
	prospective, err := prospectiveCertificateChallengeRemoval(nginx.ActivationSnapshot{Manifest: manifest, EntryPresent: true, Entry: challengeEntry}, bundle, challengeEntry)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := AppliedIdentity(bundle.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	installation := domain.Installation{Headscale: &domain.HeadscaleDomain{Enabled: true, Applied: &applied, Certificate: &domain.CertificateBundleIdentity{Generation: identity.Generation, Fingerprint: identity.Fingerprint, BindingIdentity: identity.BindingIdentity}}}
	state := safety.EmptyState()
	state.Headscale.GenerationSequence = pending.Generation
	state.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: identity.Generation, Fingerprint: identity.Fingerprint, Binding: identity.BindingIdentity, NotAfter: identity.NotAfter, LastTrustedWall: identity.LastTrustedWall}
	state.Headscale.ControlEntryDigest = bundle.Entry.Digest
	state.Headscale.ChallengePending = &pending
	input := nginx.GuardInput{Action: nginx.GuardReload, Manifest: prospective, Safety: state, Installation: &installation, Ownership: map[string]string{}, Now: identity.LastTrustedWall}
	if decision := nginx.Guard(input); !decision.Allowed {
		t.Fatalf("valid Headscale challenge removal base rejected: %+v", decision)
	}
	input.Now = identity.NotAfter
	if decision := nginx.Guard(input); decision.Allowed {
		t.Fatal("expired Headscale base control entry was restored by challenge removal")
	}
	input.Now = identity.LastTrustedWall
	input.Safety.Headscale.ControlEntryDigest = testDigest("foreign-control")
	if decision := nginx.Guard(input); decision.Allowed {
		t.Fatal("changed Headscale base control entry was restored by challenge removal")
	}
}

func TestActivationRollbackReloadDependsOnEntryRemovalAndNginxTest(t *testing.T) {
	removeFailure := errors.New("remove failed")
	testFailure := errors.New("test failed")
	for _, test := range []struct {
		name       string
		removeErr  error
		testErr    error
		wantCalls  []string
		wantErrors []error
	}{
		{name: "success", wantCalls: []string{"stop", "remove", "test", "reload", "restore"}},
		{name: "remove failure", removeErr: removeFailure, wantCalls: []string{"stop", "remove", "test", "restore"}, wantErrors: []error{removeFailure}},
		{name: "test failure", testErr: testFailure, wantCalls: []string{"stop", "remove", "test", "restore"}, wantErrors: []error{testFailure}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			record := func(name string, result error) func() error {
				return func() error {
					calls = append(calls, name)
					return result
				}
			}
			err := runActivationRollback(true, true, activationRollbackActions{
				stopSockets:    record("stop", nil),
				removeEntry:    record("remove", test.removeErr),
				testNginx:      record("test", test.testErr),
				reloadNginx:    record("reload", nil),
				restorePointer: record("restore", nil),
			})
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("rollback calls=%v want=%v", calls, test.wantCalls)
			}
			if len(test.wantErrors) == 0 && err != nil {
				t.Fatalf("successful rollback failed: %v", err)
			}
			for _, wanted := range test.wantErrors {
				if !errors.Is(err, wanted) {
					t.Fatalf("rollback error %v does not contain %v", err, wanted)
				}
			}
		})
	}
}
