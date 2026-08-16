package control

import (
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"strings"
	"testing"
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
	state.Headscale.Reactivating = &safety.HeadscaleReactivating{Generation: 1, PriorGeneration: 0, PlanID: "plan_control", ControlGeneration: bundle.Entry.Generation, CertificateGeneration: identity.Generation, CertificateFingerprint: identity.Fingerprint, CandidateDigest: bundle.Candidate.ConfigDigest, CandidateBundle: bundle.Digest, ActivationDigest: bundle.Digest, ControlEntryDigest: bundle.Entry.Digest, BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}, {Kind: safety.MarkerEdgeOneExpiry, State: safety.SnapshotAbsent}}, CertificateUntil: identity.NotAfter}
	manifest := nginx.Manifest{SchemaVersion: nginx.ManifestSchema, InstallationID: "ins_control", GenerationID: "gen_control", DefaultCertFingerprint: testDigest("default"), MainDigest: testDigest("main"), SanitizerDigest: testDigest("sanitizer"), Entries: []nginx.Entry{bundle.Entry}}
	if decision := nginx.Guard(nginx.GuardInput{Action: nginx.GuardReload, Manifest: manifest, Safety: state, Now: identity.LastTrustedWall}); !decision.Allowed {
		t.Fatalf("exact Headscale reactivation graph rejected: %+v", decision)
	}
	changed := bundle
	changed.STUNSocket = append([]byte(nil), bundle.STUNSocket...)
	changed.STUNSocket[0] ^= 1
	if ValidateActivation(changed) == nil {
		t.Fatal("changed activation bytes accepted")
	}
}
func nginxRender(bundle ActivationBundle) (string, error) {
	data, err := nginx.RenderEntry(bundle.Entry)
	return string(data), err
}
