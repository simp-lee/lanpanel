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
	"strings"
	"testing"
	"time"
)

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
	if err != nil || len(contracted.Entries) != 0 || len(removed) != 1 {
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
	installation := &domain.Installation{Resources: []domain.AppResource{{ID: "app-one", PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished, LastAppliedDigest: &manifest.Entries[0].Digest, LastAppliedBundle: &domain.PublicationBundle{ConfigDigest: manifest.Entries[0].Digest, Kind: domain.PublicationDomainHTTPS, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test"}}}}}}}
	decision := Guard(GuardInput{Action: GuardStart, Manifest: manifest, Safety: state, Installation: installation, Now: time.Now().UTC()})
	if decision.Allowed {
		t.Fatalf("pre-S13 App graph was allowed: %#v", decision)
	}
	manifest.Entries = nil
	decision = Guard(GuardInput{Action: GuardStart, Manifest: manifest, Safety: state, Installation: installation, Now: time.Now().UTC()})
	if !decision.Allowed {
		t.Fatalf("closed baseline rejected: %#v", decision)
	}
	state.Resources[0].GenerationSequence = 1
	state.Resources[0].StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 1, Reason: "closed"}
	manifest.Entries = []Entry{{Kind: EntryApp, ResourceID: "app-one", Relative: "apps-enabled/app-one.conf", Digest: testDigest("site"), Domains: []string{"app.example.test"}, Generation: 1}}
	if decision = Guard(GuardInput{Action: GuardReload, Manifest: manifest, Safety: state, Installation: installation, Now: time.Now().UTC()}); decision.Allowed {
		t.Fatalf("sticky App graph allowed: %#v", decision)
	}
	state.StopFenceSequence = 1
	state.StopFence = nil
	state.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseClosing, Generation: 1}
	if decision = Guard(GuardInput{Action: GuardStart, Manifest: manifest, Safety: state, Installation: installation, Now: time.Now().UTC()}); decision.Allowed {
		t.Fatalf("global close crossed: %#v", decision)
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
