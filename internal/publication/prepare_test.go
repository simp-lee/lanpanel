package publication

import (
	"lanpanel/internal/domain"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func temporaryResource() domain.AppResource {
	return domain.AppResource{ID: "res_00000000000000000000000000000001", Name: "temporary", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: testDigest, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}}, Publication: domain.AppPublication{Kind: domain.PublicationTemporaryHTTP, TemporaryHTTP: &domain.TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 18080}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}, ManagedProcess: &domain.ManagedProcess{ID: "proc_00000000000000000000000000000001", Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{Generation: 1, ConfigDigest: testDigest, PolicyDigest: testDigest, FrontendEndpoint: "/var/lib/lanpanel/resources/res_00000000000000000000000000000001/frontend/http.sock", FrontendUID: 33, FrontendGID: 33, FrontendMode: 0o660}}}
}
func TestPrepareTemporaryBindsExactPublicSurface(t *testing.T) {
	candidate, err := PrepareTemporary(temporaryResource(), 2)
	if err != nil {
		t.Fatal(err)
	}
	text := string(candidate.EntryBytes)
	for _, expected := range []string{"listen 0.0.0.0:18080 default_server", "server_name 8.8.8.8", "if ($http_host != 8.8.8.8:18080)", "if ($server_protocol != HTTP/1.1)", "proxy_set_header Authorization \"\"", "proxy_set_header X-Real-IP $remote_addr", "X-LanPanel-Plaintext-Warning"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("rendered candidate omits %q", expected)
		}
	}
	if candidate.PublicURL != "http://8.8.8.8:18080/" || candidate.Bundle.Generation != 2 || candidate.Bundle.TemporaryHTTP.HostAuthority != "8.8.8.8:18080" {
		t.Fatalf("candidate identity mismatch: %#v", candidate)
	}
}
func TestPrepareTemporaryRejectsRetainedGoAccessAuthority(t *testing.T) {
	resource := temporaryResource()
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{RetiredGeneration: 2, RetiredStateGeneration: 2, RetiredServiceIdentity: testDigest, RetiredUnitIdentities: []string{testDigest, testDigest, testDigest, testDigest, testDigest}}}}
	if _, err := PrepareTemporary(resource, 2); err == nil || !strings.Contains(err.Error(), "retained GoAccess authority") {
		t.Fatalf("temporary publication discarded retained GoAccess: %v", err)
	}
}

func TestPrepareTemporaryRejectsWebSocketAndNonpublicAddress(t *testing.T) {
	resource := temporaryResource()
	resource.Target.WebSocket = domain.WebSocketReadiness{Enabled: true, Path: "/ws"}
	if _, err := PrepareTemporary(resource, 2); err == nil {
		t.Fatal("WebSocket temporary publication accepted")
	}
	resource = temporaryResource()
	resource.Publication.TemporaryHTTP.PublicIPv4 = "192.0.2.1"
	if _, err := PrepareTemporary(resource, 2); err == nil {
		t.Fatal("documentation IPv4 accepted")
	}
}
func TestBundleDigestRejectsDifferentListener(t *testing.T) {
	candidate, err := PrepareTemporary(temporaryResource(), 2)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Bundle.Listeners[0].Port++
	if err := RequireBundleDigest(candidate.Bundle, candidate.BundleDigest); err == nil {
		t.Fatal("changed listener retained candidate digest")
	}
}
