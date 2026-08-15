package publication

import (
	"crypto/sha256"
	"encoding/hex"
	"lanpanel/internal/domain"
	goaccessruntime "lanpanel/internal/goaccess"
	"lanpanel/internal/nginx"
	"lanpanel/internal/ownership"
	"slices"
	"strings"
	"testing"
)

func TestDomainCandidateRejectsNginxDirectiveURL(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: digest, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessPublic, StaticRootID: "static_00000000000000000000000000000000"}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: digest, PolicyDigest: digest, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000.current", BindingIdentity: digest, Generation: 1, Fingerprint: digest, SANIdentity: digest, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: digest, IssuerIdentity: digest, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	for _, path := range []string{"/bad;include", "/bad value", "/bad$variable", "/bad{block"} {
		_, err := PrepareDomain(resource, 2, certificate, "", "", "", "", []nginx.StaticRoute{{URLPath: path, RelativePath: "file", SourcePath: "/srv/static/file", Identity: digest}}, nil)
		if err == nil {
			t.Fatalf("unsafe location %q accepted", path)
		}
	}
}

func TestApplicationManagedDomainForwardsOnlyAuthorizationAndWebSocket(t *testing.T) {
	value := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: value, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, WebSocket: domain.WebSocketReadiness{Enabled: true, Path: "/ws"}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessApplicationManaged}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: value, PolicyDigest: value, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000/current", BindingIdentity: value, Generation: 1, Fingerprint: value, SANIdentity: value, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: value, IssuerIdentity: value, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	candidate, err := PrepareDomain(resource, 2, certificate, "", "", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(candidate.EntryBytes)
	for _, required := range []string{"proxy_set_header Authorization $http_authorization", "proxy_set_header Upgrade $http_upgrade", "proxy_set_header X-Authenticated-User \"\"", "proxy_set_header Forwarded \"\""} {
		if !strings.Contains(text, required) {
			t.Fatalf("application-managed render missing %q", required)
		}
	}
}

func TestGoAccessCandidateUsesIndependentBasicAndCredentialCleanWebSocket(t *testing.T) {
	value := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: value, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessPublic, GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", CIDRs: []string{"8.8.8.8/32"}, DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: value, PolicyDigest: value, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000/current", BindingIdentity: value, Generation: 1, Fingerprint: value, SANIdentity: value, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: value, IssuerIdentity: value, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	goaccessCandidate, err := goaccessruntime.Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareDomain(resource, 2, certificate, "", "", "/srv/goaccess.htpasswd", value, nil, &goaccessCandidate)
	if err != nil {
		t.Fatal(err)
	}
	text := string(candidate.EntryBytes)
	for _, required := range []string{"location = /__lanpanel/goaccess/", "location = /__lanpanel/goaccess-ws", "auth_basic_user_file \"/srv/goaccess.htpasswd\"", "allow 8.8.8.8/32", "proxy_pass_request_headers off", "default_type text/html", "if ($host != \"app.example.test\") { return 308 https://app.example.test$request_uri; }", "proxy_set_header Sec-WebSocket-Key $http_sec_websocket_key", "proxy_set_header Authorization \"\"", "proxy_set_header Cookie \"\"", "proxy_set_header X-Authenticated-User \"\"", "proxy_pass http://unix:/run/lanpanel-goaccess/"} {
		if !strings.Contains(text, required) {
			t.Fatalf("GoAccess render missing %q", required)
		}
	}
	if !candidate.Bundle.DomainHTTPS.GoAccess.Enabled || len(candidate.Bundle.CredentialIDs) != 1 {
		t.Fatal("GoAccess bundle authority missing")
	}
	if !slices.Contains(candidate.Bundle.ManagedPaths, goaccessCandidate.Paths.ServiceEnablement) {
		t.Fatalf("GoAccess enablement mutation missing: %v", candidate.Bundle.ManagedPaths)
	}
	if slices.Contains(candidate.Bundle.ManagedPaths, "/etc/passwd") || slices.ContainsFunc(candidate.OwnershipPaths, func(path ownership.OwnedPath) bool { return path.Path == "/etc/passwd" }) {
		t.Fatal("shared account database was assigned to resource ownership")
	}
	if candidate.Bundle.DomainHTTPS.GoAccess.DatabasePath == candidate.Bundle.DomainHTTPS.GoAccess.ReportPath {
		t.Fatal("GoAccess state identities collapsed")
	}
}

func TestGoAccessReenableReusesRetainedStateWhileRetiringOldUnits(t *testing.T) {
	value := "sha256:" + strings.Repeat("a", 64)
	units := []string{value, value, value, value, value}
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: value, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessPublic, GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}, PublicationRecord: domain.PublicationRecord{LastAppliedBundle: &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{RetiredGeneration: 2, RetiredStateGeneration: 2, RetiredServiceIdentity: value, RetiredUnitIdentities: units}}}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: value, PolicyDigest: value, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	runtimeCandidate, err := goaccessruntime.Render("ins_00000000000000000000000000000001", resource, 33, 3)
	if err != nil {
		t.Fatal(err)
	}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000/current", BindingIdentity: value, Generation: 1, Fingerprint: value, SANIdentity: value, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: value, IssuerIdentity: value, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	candidate, err := PrepareDomain(resource, 3, certificate, "", "", "/srv/goaccess.htpasswd", value, nil, &runtimeCandidate)
	if err != nil {
		t.Fatal(err)
	}
	identity := candidate.Bundle.DomainHTTPS.GoAccess
	if identity.RetiredGeneration != 2 || identity.RetiredServiceIdentity != value || identity.Generation != 3 || identity.StateGeneration != 2 || identity.RemovesRetiredState() || identity.DatabasePath != "/var/lib/lanpanel/goaccess/"+resource.ID+"/generations/2/database" {
		t.Fatalf("retained-state identity=%+v", identity)
	}
}

func TestDomainCandidateBindsTLSAuthStaticAndWebSocket(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: digest, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, WebSocket: domain.WebSocketReadiness{Enabled: true, Path: "/ws"}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessBasic, CredentialID: "cred_00000000000000000000000000000001", CIDRs: []string{"8.8.8.8/32"}, StaticRootID: "static_00000000000000000000000000000000"}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: digest, PolicyDigest: digest, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000/current", BindingIdentity: digest, Generation: 1, Fingerprint: digest, SANIdentity: digest, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: digest, IssuerIdentity: digest, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	candidate, err := PrepareDomain(resource, 2, certificate, "/var/lib/lanpanel/credentials/basic/app.htpasswd", digest, "", "", []nginx.StaticRoute{{URLPath: "/robots.txt", RelativePath: "robots.txt", SourcePath: "/srv/static/robots.txt", Identity: digest}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(candidate.EntryBytes)
	for _, required := range []string{"listen 443 ssl http2", "ssl_protocols TLSv1.2 TLSv1.3", "auth_basic_user_file", "allow 8.8.8.8/32", "location = /robots.txt", "proxy_set_header Upgrade $http_upgrade", "access_log \"/var/log/lanpanel/nginx-rejections.log\" lanpanel_rejection", "if ($http_host !~*", "if ($ssl_server_name !~*", "proxy_set_header X-Authenticated-User \"\"", "proxy_set_header Authorization \"\""} {
		if !strings.Contains(text, required) {
			t.Fatalf("render missing %q", required)
		}
	}
	referenceSum := sha256.Sum256([]byte(resource.Publication.DomainHTTPS.CredentialID + "\x00/var/lib/lanpanel/credentials/basic/app.htpasswd"))
	expectedReference := "sha256:" + hex.EncodeToString(referenceSum[:])
	if candidate.Bundle.DomainHTTPS.Auth.ReferenceIdentity != expectedReference {
		t.Fatal("credential content fingerprint was not bound")
	}
	if candidate.CertificatePointer == nil || len(candidate.OwnershipListeners) != 0 {
		t.Fatalf("candidate authority incomplete")
	}
}
