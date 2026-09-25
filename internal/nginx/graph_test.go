package nginx

import (
	"bytes"
	"context"
	"errors"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUnixUpstreamRejectsInjectionAndTailnetSource(t *testing.T) {
	base := TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/run/lanpanel/app.sock", ReadinessPath: "/ready"}
	for _, mutate := range []func(*TemporarySite){
		func(value *TemporarySite) { value.UpstreamAddress = "/run/lanpanel/app.sock; include /tmp/x;" },
		func(value *TemporarySite) { value.Tailnet = true },
		func(value *TemporarySite) { value.UpstreamSource = "127.0.0.1" },
	} {
		candidate := base
		mutate(&candidate)
		if validTemporarySite(candidate, "tcp:0.0.0.0:18080") {
			t.Fatalf("unsafe Unix upstream accepted: %#v", candidate)
		}
	}
}

func TestConfigIdentitySurvivesPartialTeardown(t *testing.T) {
	paths, _ := installTestGraph(t)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	manifest, err := Audit(paths, owner)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Entries = nil
	data, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeMode(t, paths.ManifestPath(), data, 0o600)
	if err := os.Remove(paths.CertificatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.PrivateKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(paths.StateRoot); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{AppsDirectory, ChallengesDirectory, ControlDirectory, TemporaryDirectory} {
		if err := os.RemoveAll(filepath.Join(paths.ConfigRoot, directory)); err != nil {
			t.Fatal(err)
		}
	}
	verified, err := VerifyConfigIdentity(paths, owner)
	if err != nil || verified.InstallationID != manifest.InstallationID || len(verified.Entries) != 0 {
		t.Fatalf("partial teardown config identity=%#v err=%v", verified, err)
	}
}

func TestClosedGraphRejectsForeignFilesAndContractsWithoutRestore(t *testing.T) {
	paths, manifest := installTestGraph(t)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if audited, err := Audit(paths, owner); err != nil || len(audited.Entries) != 1 {
		t.Fatalf("Audit()=%#v,%v", audited, err)
	}
	foreign := filepath.Join(paths.ConfigRoot, "foreign.conf")
	if err := os.WriteFile(foreign, []byte("server {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Audit(paths, owner); err == nil {
		t.Fatal("foreign root include was accepted")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	contracted, removed, err := Contract(context.Background(), paths, owner, []string{"app-one"})
	if err != nil || len(contracted.Entries) != 0 || len(removed) != 2 || !slices.Contains(removed, paths.ManifestPath()) {
		t.Fatalf("Contract()=%#v,%v,%v", contracted, removed, err)
	}
	if _, err := os.Lstat(filepath.Join(paths.ConfigRoot, manifest.Entries[0].Relative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("contracted include remains: %v", err)
	}
	if _, err := Audit(paths, owner); err != nil {
		t.Fatalf("contracted graph is invalid: %v", err)
	}
}

func TestTemporaryEntryClearsCredentialsAndRequiresExactAuthority(t *testing.T) {
	entry := Entry{Kind: EntryTemporary, ResourceID: "res_00000000000000000000000000000001", Relative: "temporary-enabled/res_00000000000000000000000000000001.conf", Digest: "sha256:" + strings.Repeat("a", 64), Listeners: []string{"tcp:0.0.0.0:18080"}, Generation: 2, Temporary: &TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/var/lib/lanpanel/resources/res_00000000000000000000000000000001/frontend/http.sock", ReadinessPath: "/ready"}}
	data, err := RenderEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Forwarded", "X-Forwarded-Port", "X-Client-IP", "CF-Connecting-IP", "EO-Connecting-IP"} {
		if !strings.Contains(text, "proxy_set_header "+header+" \"\";") {
			t.Fatalf("temporary sanitizer omits %s", header)
		}
	}
	for _, expected := range []string{"server_name 8.8.8.8;", "if ($http_host != 8.8.8.8:18080)", "if ($server_protocol != HTTP/1.1)", "proxy_set_header X-Real-IP $remote_addr;", "proxy_set_header X-Forwarded-Proto http;"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("temporary route omits %q", expected)
		}
	}
}

func TestAuditRejectsManifestBoundEntryWithHiddenDirective(t *testing.T) {
	paths, manifest := installTestGraph(t)
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	path := filepath.Join(paths.ConfigRoot, manifest.Entries[0].Relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("server { listen 9443; proxy_pass http://127.0.0.1; }\n")...)
	manifest.Entries[0].Digest = digest(data)
	manifestBytes, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeMode(t, path, data, 0o600)
	writeMode(t, paths.ManifestPath(), manifestBytes, 0o600)
	if _, err := Audit(paths, owner); err == nil {
		t.Fatal("manifest-digested hidden Nginx directive was accepted")
	}
}

func TestDefaultCertificateAndHeaderBoundaryAreInstallationSpecific(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	first, err := GenerateDefaultCertificate("ins_one", bytes.NewReader(bytes.Repeat([]byte{7}, 256)), now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDefaultCertificate(first.CertificatePEM, first.PrivateKeyPEM)
	if err != nil || parsed.Fingerprint != first.Fingerprint || !strings.HasSuffix(parsed.DNSName, ".lanpanel.invalid") {
		t.Fatalf("certificate=%#v error=%v", parsed, err)
	}
	want, _ := ExpectedDefaultDNSName("ins_one")
	other, _ := ExpectedDefaultDNSName("ins_two")
	if parsed.DNSName != want || want == other {
		t.Fatal("default rejection identity was not installation-bound")
	}
	sanitizer := HeaderSanitizer()
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP", "X-Client-IP", "X-Cluster-Client-IP", "X-Original-Forwarded-For", "CF-Connecting-IP", "True-Client-IP", "EO-Connecting-IP", "EO-Client-IP"} {
		if !strings.Contains(sanitizer, "proxy_set_header "+header+" \"\";") {
			t.Fatalf("sanitizer omitted %s", header)
		}
	}
	guard, err := DomainSNIGuard([]string{"alias.example.test", "app.example.test"})
	if err != nil || !strings.Contains(guard, "$ssl_server_name") || !strings.Contains(guard, "return 421") {
		t.Fatalf("SNI guard=%q,%v", guard, err)
	}
	if _, err := DomainSNIGuard([]string{"*.example.test"}); err == nil {
		t.Fatal("wildcard SNI authority was accepted")
	}
}

func TestStartupReloadGuardNeverCrossesContraction(t *testing.T) {
	_, manifest := installTestGraph(t)
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "app-one", State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner")}}
	installation := &domain.Installation{InstallationID: manifest.InstallationID, Resources: []domain.AppResource{{ID: "app-one", PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished, LastAppliedDigest: &manifest.Entries[0].Digest, LastAppliedBundle: &domain.PublicationBundle{ConfigDigest: manifest.Entries[0].Digest, Kind: domain.PublicationDomainHTTPS, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test"}}}}}}}
	ownership := map[string]string{"app-one": testDigest("owner")}
	decision := Guard(GuardInput{Action: GuardStart, Manifest: manifest, Safety: state, Installation: installation, Ownership: ownership, Now: time.Now().UTC()})
	if decision.Allowed {
		t.Fatalf("pre-S13 App graph was allowed: %#v", decision)
	}
	manifest.Entries = nil
	decision = Guard(GuardInput{Action: GuardStart, Manifest: manifest, Safety: state, Installation: installation, Ownership: ownership, Now: time.Now().UTC()})
	if !decision.Allowed {
		t.Fatalf("closed baseline rejected: %#v", decision)
	}
	state.Resources[0].GenerationSequence = 1
	state.Resources[0].StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 1, Reason: "closed"}
	manifest.Entries = []Entry{{Kind: EntryApp, ResourceID: "app-one", Relative: "apps-enabled/app-one.conf", Digest: testDigest("site"), Domains: []string{"app.example.test"}, Generation: 1}}
	if decision = Guard(GuardInput{Action: GuardReload, Manifest: manifest, Safety: state, Installation: installation, Ownership: ownership, Now: time.Now().UTC()}); decision.Allowed {
		t.Fatalf("sticky App graph allowed: %#v", decision)
	}
	state.StopFenceSequence = 1
	state.StopFence = nil
	state.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseClosing, Generation: 1}
	if decision = Guard(GuardInput{Action: GuardStart, Manifest: manifest, Safety: state, Installation: installation, Ownership: ownership, Now: time.Now().UTC()}); decision.Allowed {
		t.Fatalf("global close crossed: %#v", decision)
	}
}

func TestReloadGuardRequiresExactHTTP01HostTokenWebrootAndGeneration(t *testing.T) {
	_, manifest := installTestGraph(t)
	resourceID := "app-one"
	ownerDigest := testDigest("owner")
	pending := safety.ChallengePending{
		Generation:             2,
		PlanID:                 "plan-one",
		Method:                 "http-01",
		ConfigDigest:           testDigest("config"),
		SANIdentity:            testDigest("san"),
		ACMEBinding:            testDigest("acme"),
		CertificateIdentity:    "cert_00000000000000000000000000000001",
		Host:                   "app.example.test",
		Hosts:                  []string{"app.example.test", "www.example.test"},
		Token:                  "abcdefghijklmnopqrstuv",
		TokenPath:              "/.well-known/acme-challenge/abcdefghijklmnopqrstuv",
		KeyAuthorizationDigest: testDigest("key-authorization"),
		Webroot:                "/var/lib/lanpanel/certificates/webroot/cert_00000000000000000000000000000001",
		BootstrapIdentity:      testDigest("bootstrap"),
		BaseMarkers:            []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}},
	}
	entry := Entry{Kind: EntryChallenge, ResourceID: resourceID, Relative: ChallengesDirectory + "/" + resourceID + ".conf", Digest: testDigest("entry"), Domains: []string{pending.Host}, Listeners: []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}, Generation: pending.Generation, Challenge: &ChallengeSite{Generation: pending.Generation, Host: pending.Host, Token: pending.Token, TokenPath: pending.TokenPath, KeyAuthorizationDigest: pending.KeyAuthorizationDigest, Webroot: pending.Webroot}}
	manifest.Entries = []Entry{entry}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: resourceID, GenerationSequence: 2, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: ownerDigest, ChallengePending: &pending}}
	installation := &domain.Installation{InstallationID: manifest.InstallationID, Resources: []domain.AppResource{{ID: resourceID}}}
	input := GuardInput{Action: GuardReload, Manifest: manifest, Safety: state, Installation: installation, Ownership: map[string]string{resourceID: ownerDigest}, Now: time.Now().UTC()}
	if decision := Guard(input); !decision.Allowed {
		t.Fatalf("exact HTTP-01 authority rejected: %#v", decision)
	}

	crossHost := *entry.Challenge
	crossHost.Host = "www.example.test"
	input.Manifest.Entries[0].Challenge = &crossHost
	input.Manifest.Entries[0].Domains = []string{"www.example.test"}
	if decision := Guard(input); decision.Allowed {
		t.Fatal("cross-Host HTTP-01 route was allowed")
	}
	input.Manifest.Entries[0] = entry
	input.Manifest.Entries[0].Challenge = &ChallengeSite{Generation: pending.Generation, Host: pending.Host, Token: "differentabcdefghijkl", TokenPath: "/.well-known/acme-challenge/differentabcdefghijkl", KeyAuthorizationDigest: pending.KeyAuthorizationDigest, Webroot: pending.Webroot}
	if decision := Guard(input); decision.Allowed {
		t.Fatal("cross-token HTTP-01 route was allowed")
	}
	input.Manifest.Entries[0] = entry
	input.Manifest.Entries[0].Challenge = &ChallengeSite{Generation: pending.Generation, Host: pending.Host, Token: pending.Token, TokenPath: pending.TokenPath, KeyAuthorizationDigest: pending.KeyAuthorizationDigest, Webroot: "/var/lib/lanpanel/certificates/webroot/cert_00000000000000000000000000000002"}
	if decision := Guard(input); decision.Allowed {
		t.Fatal("cross-webroot HTTP-01 route was allowed")
	}
	input.Manifest.Entries[0] = entry
	input.Manifest.Entries[0].Generation++
	if decision := Guard(input); decision.Allowed {
		t.Fatal("cross-generation HTTP-01 route was allowed")
	}
}

func TestStartupReloadGuardAllowsOnlyExactDurableDomainAuthority(t *testing.T) {
	_, manifest := installTestGraph(t)
	now := time.Now().UTC().Truncate(time.Second)
	resourceID := "app-one"
	ownershipDigest := testDigest("owner")
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert-one", BindingIdentity: "binding-one", Generation: 3, Fingerprint: testDigest("certificate"), SANIdentity: testDigest("san"), ChainIdentity: testDigest("chain"), IssuerIdentity: testDigest("issuer"), NotAfter: now.Add(time.Hour).Format(time.RFC3339), LastTrustedWall: now.Add(-time.Minute).Format(time.RFC3339)}
	bundle := domain.PublicationBundle{ID: "bundle-one", Generation: 2, ConfigDigest: testDigest("config"), Kind: domain.PublicationDomainHTTPS, EndpointIdentity: testDigest("endpoint"), SiteIdentity: testDigest("site"), ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 80}, {Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test"}, Certificate: certificate, Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, Static: domain.StaticBundleIdentity{Routes: []domain.StaticRouteBundleIdentity{}, RouteIdentities: []string{}}, GoAccess: domain.GoAccessBundleIdentity{Enabled: false}}}
	entry := Entry{Kind: EntryApp, ResourceID: resourceID, Relative: AppsDirectory + "/app-one.conf", Digest: bundle.SiteIdentity, Domains: []string{"app.example.test"}, Listeners: []string{"tcp:0.0.0.0:443", "tcp:0.0.0.0:80", "tcp:[::]:443", "tcp:[::]:80"}, Generation: bundle.Generation, Domain: &DomainSite{Hosts: []string{"app.example.test"}, CertificatePointer: certificate.PointerIdentity, RejectionAuditPath: "/var/log/lanpanel/nginx-rejections.log", AuthMode: "public", UpstreamNetwork: "unix", UpstreamAddress: "/run/lanpanel/app-one.sock"}}
	manifest.Entries = []Entry{entry}
	app := domain.AppResource{ID: resourceID, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessPublic}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished, UnpublishedGeneration: 1, LastAppliedDigest: &bundle.ConfigDigest, LastAppliedBundle: &bundle}}
	installation := &domain.Installation{InstallationID: manifest.InstallationID, Resources: []domain.AppResource{app}}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: resourceID, GenerationSequence: 2, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: ownershipDigest, ActiveCertificate: &safety.ActiveCertificateAuthority{Generation: certificate.Generation, Fingerprint: certificate.Fingerprint, Binding: certificate.BindingIdentity, LastTrustedWall: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}}}
	input := GuardInput{Action: GuardStart, Manifest: manifest, Safety: state, Installation: installation, Ownership: map[string]string{resourceID: ownershipDigest}, Now: now}
	if decision := Guard(input); !decision.Allowed {
		t.Fatalf("exact committed domain App rejected: %#v", decision)
	}
	input.Manifest.InstallationID = "ins_other"
	if decision := Guard(input); decision.Allowed || !strings.Contains(decision.Reason, "installation identity") {
		t.Fatalf("cross-installation disk graph was not diagnosed: %#v", decision)
	}
	input.Manifest.InstallationID = installation.InstallationID
	orphanID := "orphan-one"
	orphanDigest := testDigest("orphan")
	input.Safety.Resources = append(input.Safety.Resources, safety.ResourceSafety{ResourceID: orphanID, State: safety.ResourceActive, Ownership: safety.OwnershipOrphan, OwnershipDigest: orphanDigest})
	input.Ownership[orphanID] = orphanDigest
	if decision := Guard(input); decision.Allowed || !strings.Contains(decision.Reason, "clean-host rebuild") {
		t.Fatalf("one-sided ownership orphan did not block the complete graph: %#v", decision)
	}
	input.Safety.Resources = input.Safety.Resources[:1]
	delete(input.Ownership, orphanID)
	input.Ownership[resourceID] = testDigest("foreign")
	if decision := Guard(input); decision.Allowed {
		t.Fatal("ownership-mismatched domain App was allowed")
	}
	input.Ownership[resourceID] = ownershipDigest
	input.Safety.Resources[0].StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 2, Reason: "closed"}
	if decision := Guard(input); decision.Allowed {
		t.Fatal("sticky-unpublished domain App was reopened")
	}
	input.Safety.Resources[0].StickyUnpublished = nil
	input.Safety.Resources[0].CertificateExpiry = &safety.DeadlineMarker{Generation: 2, Deadline: now, Binding: certificate.BindingIdentity}
	if decision := Guard(input); decision.Allowed {
		t.Fatal("certificate-expired domain App was reopened")
	}
}

func TestReloadGuardAllowsExactActivatingDomainAndRejectsStalePlan(t *testing.T) {
	_, manifest := installTestGraph(t)
	now := time.Now().UTC().Truncate(time.Second)
	resourceID := "app-one"
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert-one", BindingIdentity: "binding-one", Generation: 1, Fingerprint: testDigest("certificate"), SANIdentity: testDigest("san"), ChainIdentity: testDigest("chain"), IssuerIdentity: testDigest("issuer"), NotAfter: now.Add(time.Hour).Format(time.RFC3339), LastTrustedWall: now.Add(-time.Minute).Format(time.RFC3339)}
	bundle := domain.PublicationBundle{ID: "candidate", Generation: 2, ConfigDigest: testDigest("config"), Kind: domain.PublicationDomainHTTPS, EndpointIdentity: testDigest("endpoint"), SiteIdentity: testDigest("site"), ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 80}, {Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test"}, Certificate: certificate, Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, Static: domain.StaticBundleIdentity{Routes: []domain.StaticRouteBundleIdentity{}, RouteIdentities: []string{}}, GoAccess: domain.GoAccessBundleIdentity{Enabled: false}}}
	entry := Entry{Kind: EntryApp, ResourceID: resourceID, Relative: AppsDirectory + "/app-one.conf", Digest: bundle.SiteIdentity, Domains: []string{"app.example.test"}, Listeners: []string{"tcp:0.0.0.0:443", "tcp:0.0.0.0:80", "tcp:[::]:443", "tcp:[::]:80"}, Generation: 2, Domain: &DomainSite{Hosts: []string{"app.example.test"}, CertificatePointer: certificate.PointerIdentity, RejectionAuditPath: "/var/log/lanpanel/nginx-rejections.log", AuthMode: "public", UpstreamNetwork: "unix", UpstreamAddress: "/run/lanpanel/app-one.sock"}}
	manifest.Entries = []Entry{entry}
	intent := domain.ActivationIntent{ID: "activation", JobID: "job-one", PlanID: "plan-one", Generation: 2, Candidate: bundle, PriorState: domain.PublicationUnpublished}
	app := domain.AppResource{ID: resourceID, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessPublic}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationActivating, UnpublishedGeneration: 1, ActivationIntent: &intent}}
	candidateDigest, _ := publicationBundleDigest(bundle)
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: resourceID, GenerationSequence: 2, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: testDigest("owner"), StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 1, Reason: "initial"}, Reactivating: &safety.Reactivating{Generation: 2, PriorGeneration: 1, PlanID: intent.PlanID, CandidateDigest: bundle.ConfigDigest, CandidateBundle: candidateDigest, BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotPresent, Generation: 1}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}, CertificateUntil: now.Add(time.Hour)}}}
	input := GuardInput{Action: GuardReload, Manifest: manifest, Safety: state, Installation: &domain.Installation{InstallationID: manifest.InstallationID, Resources: []domain.AppResource{app}}, Ownership: map[string]string{resourceID: testDigest("owner")}, Now: now}
	if decision := Guard(input); !decision.Allowed {
		t.Fatalf("exact activating domain candidate rejected: %#v", decision)
	}
	input.Safety.Resources[0].Reactivating.PlanID = "stale-plan"
	if decision := Guard(input); decision.Allowed {
		t.Fatal("stale activating Plan authority was allowed")
	}
}

func TestBasicStaticRoutesRenderAnonymousAndAuthenticatedBoundaries(t *testing.T) {
	entry := Entry{
		Kind:       EntryApp,
		ResourceID: "res_static",
		Relative:   AppsDirectory + "/res_static.conf",
		Digest:     "sha256:" + strings.Repeat("a", 64),
		Domains:    []string{"static.example.test"},
		Generation: 1,
		Domain: &DomainSite{
			Hosts:              []string{"static.example.test"},
			CertificatePointer: "/var/lib/lanpanel/certificates/active/cert_static",
			RejectionAuditPath: "/var/log/lanpanel/nginx-rejections.log",
			AuthMode:           "basic",
			HTPasswdPath:       "/var/lib/lanpanel/credentials/static.htpasswd",
			UpstreamNetwork:    "unix",
			UpstreamAddress:    "/run/lanpanel/res_static.sock",
			Static: []StaticRoute{
				{URLPath: "/anonymous.txt", RelativePath: "anonymous.txt", SourcePath: "/srv/static/anonymous.txt", Anonymous: true, Identity: testDigest("anonymous")},
				{URLPath: "/protected.txt", RelativePath: "protected.txt", SourcePath: "/srv/static/protected.txt", Identity: testDigest("protected")},
			},
		},
	}
	data, err := RenderEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	location := func(path string) string {
		marker := "  location = " + path + " {\n"
		start := strings.Index(text, marker)
		if start < 0 {
			t.Fatalf("location %q was not rendered", path)
		}
		remainder := text[start+len(marker):]
		end := strings.Index(remainder, "\n  }\n")
		if end < 0 {
			t.Fatalf("location %q rendering was not bounded", path)
		}
		return remainder[:end]
	}
	anonymous := location("/anonymous.txt")
	protected := location("/protected.txt")
	if strings.Contains(anonymous, "auth_basic") || strings.Contains(anonymous, "auth_basic_user_file") {
		t.Fatalf("anonymous static route rendered Basic authentication:\n%s", anonymous)
	}
	for _, directive := range []string{"auth_basic \"Restricted\";", "auth_basic_user_file \"/var/lib/lanpanel/credentials/static.htpasswd\";"} {
		if !strings.Contains(protected, directive) {
			t.Fatalf("authenticated static route omitted %q:\n%s", directive, protected)
		}
	}
}

func installTestGraph(t *testing.T) (Paths, Manifest) {
	t.Helper()
	root := t.TempDir()
	paths := Paths{ConfigRoot: filepath.Join(root, "config"), StateRoot: filepath.Join(root, "state"), AuditPath: filepath.Join(root, "audit"), CertificatePath: filepath.Join(root, "default.crt"), PrivateKeyPath: filepath.Join(root, "default.key"), PIDPath: filepath.Join(root, "nginx.pid")}
	for _, directory := range []string{paths.ConfigRoot, paths.StateRoot, paths.StagingPath(), filepath.Join(paths.ConfigRoot, AppsDirectory), filepath.Join(paths.ConfigRoot, ChallengesDirectory), filepath.Join(paths.ConfigRoot, ControlDirectory), filepath.Join(paths.ConfigRoot, TemporaryDirectory)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := GenerateDefaultCertificate("ins_one", bytes.NewReader(bytes.Repeat([]byte{9}, 256)), time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	writeMode(t, paths.CertificatePath, certificate.CertificatePEM, 0o644)
	writeMode(t, paths.PrivateKeyPath, certificate.PrivateKeyPEM, 0o600)
	writeMode(t, paths.AuditPath, []byte(AuditMarker), 0o600)
	baseline, err := RenderBaseline(paths, "ins_one", "gen_one", certificate.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range baseline.Files {
		writeMode(t, path, data, 0o600)
	}
	relative := filepath.ToSlash(filepath.Join(AppsDirectory, "app-one.conf"))
	manifest := baseline.Manifest
	entry := Entry{Kind: EntryApp, ResourceID: "app-one", Relative: relative, Digest: testDigest("pending"), Domains: []string{"app.example.test"}, Listeners: []string{"tcp:0.0.0.0:443"}, Generation: 1}
	site, err := RenderClosedEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Digest = digest(site)
	site, err = RenderClosedEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	// Digest is intentionally outside the rendered identity to avoid a
	// self-referential file; it binds the final exact bytes in the manifest.
	entry.Digest = digest(site)
	writeMode(t, filepath.Join(paths.ConfigRoot, relative), site, 0o600)
	manifest.Entries = []Entry{entry}
	manifestBytes, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeMode(t, paths.ManifestPath(), manifestBytes, 0o600)
	return paths, manifest
}

func writeMode(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func testDigest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}
