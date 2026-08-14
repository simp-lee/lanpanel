package publication

import (
	"crypto/sha256"
	"encoding/hex"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"strings"
	"testing"
)

func TestDomainCandidateRejectsNginxDirectiveURL(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: digest, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessPublic, StaticRootID: "static_00000000000000000000000000000000"}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: digest, PolicyDigest: digest, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000.current", BindingIdentity: digest, Generation: 1, Fingerprint: digest, SANIdentity: digest, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: digest, IssuerIdentity: digest, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	for _, path := range []string{"/bad;include", "/bad value", "/bad$variable", "/bad{block"} {
		_, err := PrepareDomain(resource, 2, certificate, "", "", []nginx.StaticRoute{{URLPath: path, RelativePath: "file", SourcePath: "/srv/static/file", Identity: digest}})
		if err == nil {
			t.Fatalf("unsafe location %q accepted", path)
		}
	}
}

func TestApplicationManagedDomainForwardsOnlyAuthorizationAndWebSocket(t *testing.T) {
	value := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: value, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, WebSocket: domain.WebSocketReadiness{Enabled: true, Path: "/ws"}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessApplicationManaged}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: value, PolicyDigest: value, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000/current", BindingIdentity: value, Generation: 1, Fingerprint: value, SANIdentity: value, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: value, IssuerIdentity: value, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	candidate, err := PrepareDomain(resource, 2, certificate, "", "", nil)
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

func TestDomainCandidateBindsTLSAuthStaticAndWebSocket(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleActive, CurrentConfigDigest: digest, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, WebSocket: domain.WebSocketReadiness{Enabled: true, Path: "/ws"}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessBasic, CredentialID: "cred_00000000000000000000000000000001", CIDRs: []string{"8.8.8.8/32"}, StaticRootID: "static_00000000000000000000000000000000"}}, ManagedProcess: &domain.ManagedProcess{Requested: domain.ProcessRequestedRunning, Applied: &domain.ProcessBundle{ConfigDigest: digest, PolicyDigest: digest, FrontendEndpoint: "/run/lanpanel/apps/app.sock"}}}
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert_00000000000000000000000000000000/current", BindingIdentity: digest, Generation: 1, Fingerprint: digest, SANIdentity: digest, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", ChainIdentity: digest, IssuerIdentity: digest, Authority: &domain.CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000000"}}
	candidate, err := PrepareDomain(resource, 2, certificate, "/var/lib/lanpanel/credentials/basic/app.htpasswd", digest, []nginx.StaticRoute{{URLPath: "/robots.txt", RelativePath: "robots.txt", SourcePath: "/srv/static/robots.txt", Identity: digest}})
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
