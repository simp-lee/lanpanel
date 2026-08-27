package control

import (
	"encoding/json"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"strings"
	"testing"
	"time"
)

func TestActivationBundleBindsControlIngressAndPublicSTUNRelay(t *testing.T) {
	rendered := testRendered(t)
	identity := testCertificateIdentity(IssueRequest{JobID: "job_control", PlanID: "plan_control", IntentGeneration: 1, CertificateID: rendered.Candidate.CertificateID, BindingDigest: rendered.Candidate.CertificateBinding, Domain: rendered.Candidate.ControlDomain})
	bundle, err := BuildActivation("ins_00000000000000000000000000000001", rendered.Candidate, identity)
	if err != nil {
		t.Fatal(err)
	}
	config, err := nginxRender(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"listen 443 ssl", "proxy_pass http://unix:" + rendered.Candidate.Paths.ControlSocket + ":", "proxy_set_header Proxy-Authorization \"\"", "proxy_set_header Cookie \"\"", "if ($ssl_server_name"} {
		if !strings.Contains(config, fragment) {
			t.Fatalf("control rendering missing %q", fragment)
		}
	}
	if !strings.Contains(string(bundle.STUNSocket), "ListenDatagram=0.0.0.0:3478") || !strings.Contains(string(bundle.ControlRelay), "JoinsNamespaceOf=lanpanel-headscale.service") || !strings.Contains(string(bundle.STUNRelay), "headscale-stun-relay") {
		t.Fatal("activation relay topology changed")
	}
	state := safety.EmptyState()
	state.Headscale.GenerationSequence = 1
	state.Headscale.Reactivating = &safety.HeadscaleReactivating{Generation: 1, PriorGeneration: 0, PlanID: "plan_control", ControlGeneration: bundle.Entry.Generation, CertificateGeneration: identity.Generation, CertificateFingerprint: identity.Fingerprint, CandidateDigest: bundle.Candidate.ConfigDigest, CandidateBundle: bundle.Digest, ActivationDigest: bundle.Digest, ControlEntryDigest: bundle.Entry.Digest, BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}, CertificateUntil: identity.NotAfter, CertificateLastTrustedWall: identity.LastTrustedWall}
	manifest := nginx.Manifest{SchemaVersion: nginx.ManifestSchema, InstallationID: "ins_control", GenerationID: "gen_control", DefaultCertFingerprint: testDigest("default"), MainDigest: testDigest("main"), SanitizerDigest: testDigest("sanitizer"), Entries: []nginx.Entry{bundle.Entry}}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: state, Now: identity.LastTrustedWall}); !decision.Allowed {
		t.Fatalf("exact Headscale reactivation graph rejected: %+v", decision)
	}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: state, Now: identity.NotAfter}); decision.Allowed {
		t.Fatal("expired Headscale reactivation graph allowed")
	}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: state, Now: identity.LastTrustedWall.Add(-time.Second)}); decision.Allowed {
		t.Fatal("regressed-clock Headscale reactivation graph allowed")
	}
	challengeEntry := bundle.Entry
	challengeEntry.Challenge = &nginx.ChallengeSite{Hosts: []string{bundle.Candidate.ControlDomain}, Webroot: "/var/lib/lanpanel/certificates/webroot/" + bundle.Certificate.ID}
	challengeEntry.Digest = controlZeroDigest()
	challengeDigest, digestErr := nginx.DigestEntry(challengeEntry)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	challengeEntry.Digest = challengeDigest
	challengeConfig, renderErr := nginx.RenderEntry(challengeEntry)
	if renderErr != nil || !strings.Contains(string(challengeConfig), "/.well-known/acme-challenge/") {
		t.Fatalf("Headscale challenge route missing: %v", renderErr)
	}
	state.Headscale.Reactivating = nil
	state.Headscale.ControlEntryDigest = bundle.Entry.Digest
	state.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: identity.Generation, Fingerprint: identity.Fingerprint, Binding: identity.BindingIdentity, NotAfter: identity.NotAfter, LastTrustedWall: identity.LastTrustedWall}
	applied, _ := AppliedIdentity(bundle.Candidate)
	installation := domain.Installation{Headscale: &domain.HeadscaleDomain{Enabled: true, Applied: &applied, Certificate: &domain.CertificateBundleIdentity{Generation: identity.Generation, Fingerprint: identity.Fingerprint, BindingIdentity: identity.BindingIdentity}}}
	state.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseEmergency, Generation: 4}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardStart, Manifest: manifest, Safety: state, Installation: &installation, Now: identity.LastTrustedWall.Add(time.Minute)}); !decision.Allowed {
		t.Fatalf("committed Headscale control did not survive App close: %+v", decision)
	}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardStart, Manifest: manifest, Safety: state, Installation: &installation, Now: identity.NotAfter}); decision.Allowed {
		t.Fatal("expired committed Headscale control start allowed")
	}
	changed := bundle
	changed.STUNSocket = append([]byte(nil), bundle.STUNSocket...)
	changed.STUNSocket[0] ^= 1
	if ValidateActivation(changed) == nil {
		t.Fatal("changed activation bytes accepted")
	}
}

func TestExpiredHeadscaleHTTPChallengeIsChallengeOnlyAndSnapshotBound(t *testing.T) {
	now := time.Now().UTC()
	base := []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotPresent, Generation: 1}}
	entry := nginx.Entry{Kind: nginx.EntryChallenge, ResourceID: "headscale", Relative: nginx.ChallengesDirectory + "/headscale.conf", Digest: controlZeroDigest(), Domains: []string{"control.example.test"}, Listeners: []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}, Generation: 2, Challenge: &nginx.ChallengeSite{Hosts: []string{"control.example.test"}, Webroot: "/var/lib/lanpanel/certificates/webroot/cert_00000000000000000000000000000001"}}
	digestValue, err := nginx.DigestEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Digest = digestValue
	state := safety.EmptyState()
	state.Headscale.GenerationSequence = 2
	state.Headscale.ControlEntryDigest = testDigest("control")
	state.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: 1, Fingerprint: testDigest("prior"), Binding: "binding", LastTrustedWall: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}
	state.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: 1, Deadline: now.Add(-time.Hour), Binding: "binding"}
	state.Headscale.ChallengePending = &safety.ChallengePending{Generation: 2, PlanID: "plan_reissue", Method: "http-01", ConfigDigest: testDigest("config"), SANIdentity: testDigest("san"), ACMEBinding: testDigest("acme"), CertificateIdentity: "cert_00000000000000000000000000000001", Host: "control.example.test", Hosts: []string{"control.example.test"}, TokenPath: "/.well-known/acme-challenge", Webroot: entry.Challenge.Webroot, BootstrapIdentity: testDigest("bootstrap"), BaseMarkers: base}
	manifest := nginx.Manifest{SchemaVersion: nginx.ManifestSchema, InstallationID: "ins_control", GenerationID: "gen_challenge", DefaultCertFingerprint: testDigest("default"), MainDigest: testDigest("main"), SanitizerDigest: testDigest("sanitizer"), Entries: []nginx.Entry{entry}}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: state, Now: now}); !decision.Allowed {
		t.Fatalf("exact expired Headscale challenge rejected: %+v", decision)
	}
	state.Headscale.CertificateExpiry.Generation = 2
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: state, Now: now}); decision.Allowed {
		t.Fatal("stale expired Headscale challenge snapshot accepted")
	}
}

func TestReactivationBundleBindsPriorControlAndChangedCertificateAuthority(t *testing.T) {
	rendered := testRendered(t)
	first := testCertificateIdentity(IssueRequest{JobID: "job_first", PlanID: "plan_first", IntentGeneration: 1, CertificateID: rendered.Candidate.CertificateID, BindingDigest: rendered.Candidate.CertificateBinding, Domain: rendered.Candidate.ControlDomain})
	second := first
	second.Generation = 2
	second.BindingIdentity = testDigest("changed-binding")
	second.Fingerprint = testDigest("changed-certificate")
	second.CertificatePath = "/var/lib/lanpanel/certificates/headscale-2/certificate.pem"
	second.PrivateKeyPath = "/var/lib/lanpanel/certificates/headscale-2/private-key.pem"
	second.DirectoryIdentity = ""
	raw, _ := json.Marshal(second)
	second.DirectoryIdentity = testDigest(string(raw))
	prior, err := AppliedIdentity(rendered.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildReactivation("ins_00000000000000000000000000000001", rendered.Candidate, second, first, prior)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Prior == nil || bundle.PriorCertificate == nil || bundle.PriorCertificate.DirectoryIdentity != first.DirectoryIdentity || bundle.Certificate.BindingIdentity == first.BindingIdentity || bundle.Digest == "" {
		t.Fatal("Headscale reactivation did not bind prior and changed certificate authority")
	}
	changed := prior
	changed.ControlIdentity = testDigest("other")
	if _, err := BuildReactivation(bundle.InstallationID, rendered.Candidate, second, first, changed); err == nil {
		t.Fatal("mismatched prior Headscale control accepted")
	}
}

func nginxRender(bundle ActivationBundle) (string, error) {
	data, err := nginx.RenderEntry(bundle.Entry)
	return string(data), err
}
