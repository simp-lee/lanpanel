package reservations

import (
	"errors"
	"lanpanel/internal/domain"
	"reflect"
	"strings"
	"testing"
)

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestConflictRegistry(t *testing.T) {
	t.Run("magicdns_namespace_overlap_is_rejected", func(t *testing.T) {
		installation := validInstallation()
		installation.Resources[0].Publication.DomainHTTPS.CanonicalDomain = "node.tail.example.net"
		if _, err := BuildClaims(installation); err == nil || !errors.As(err, new(ConflictError)) {
			t.Fatalf("BuildClaims(overlapping MagicDNS) error = %v", err)
		}
		installation = validInstallation()
		installation.Headscale.ControlDomain = "control.tail.example.net"
		if _, err := BuildClaims(installation); err == nil || !errors.As(err, new(ConflictError)) {
			t.Fatalf("BuildClaims(control domain inside own MagicDNS namespace) error = %v", err)
		}
	})

	t.Run("exact_domain_collision_is_rejected", func(t *testing.T) {
		installation := validInstallation()
		installation.Resources[0].Publication.DomainHTTPS.Aliases = []string{installation.Headscale.ControlDomain}
		if _, err := BuildClaims(installation); err == nil || !errors.As(err, new(ConflictError)) {
			t.Fatalf("BuildClaims(control alias collision) error = %v", err)
		}
	})

	t.Run("resource_name_collision_is_rejected", func(t *testing.T) {
		assertConflict(t,
			Claim{Kind: KindResourceName, Value: "application", Owner: "resource:a"},
			Claim{Kind: KindResourceName, Value: "application", Owner: "resource:b"},
		)
	})

	t.Run("listener_collision_is_rejected", func(t *testing.T) {
		assertConflict(t,
			Claim{Kind: KindListener, Value: "tcp:23456", Owner: "management"},
			Claim{Kind: KindListener, Value: "tcp:23456", Owner: "resource:b"},
		)
	})

	t.Run("local_tcp_listener_collision_is_rejected", func(t *testing.T) {
		installation := validInstallation()
		installation.Resources[0].Target.LocalHTTP = &domain.LocalHTTPTarget{
			EndpointKind: domain.LocalEndpointTCPSocketActivation,
			TCPAddress:   "127.0.0.9",
			TCPPort:      installation.Management.Port,
		}
		if _, err := BuildClaims(installation); err == nil || !errors.As(err, new(ConflictError)) {
			t.Fatalf("BuildClaims(local TCP listener collision) error = %v", err)
		}
	})

	t.Run("credential_collision_is_rejected", func(t *testing.T) {
		assertConflict(t,
			Claim{Kind: KindCredentialUse, Value: "cred_00000000000000000000000000000001", Owner: "resource:a"},
			Claim{Kind: KindCredentialUse, Value: "cred_00000000000000000000000000000001", Owner: "resource:b"},
		)
		installation := validInstallation()
		second := installation.Resources[0]
		second.ID = "res_00000000000000000000000000000002"
		second.Name = "Second Application"
		second.Target.LocalHTTP = &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}
		second.Publication.DomainHTTPS = &domain.DomainHTTPSPublication{
			CanonicalDomain: "second.example.com",
			AccessMode:      domain.AppAccessPublic,
		}
		second.ManagedProcess = &domain.ManagedProcess{
			ID:        "proc_00000000000000000000000000000002",
			Requested: domain.ProcessRequestedStopped,
			Service:   domain.ManagedService{Executable: "/usr/local/bin/second-app", WorkingDirectory: "/srv/second-app", WritePaths: []string{"/var/lib/second-app"}},
		}
		second.ManagedPaths = []string{"/var/lib/lanpanel/resources/second"}
		installation.Resources = append(installation.Resources, second)
		if _, err := BuildClaims(installation); err == nil || !errors.As(err, new(ConflictError)) {
			t.Fatalf("BuildClaims(shared resource credential) error = %v", err)
		}
	})

	t.Run("pending_applied_identity_remains_reserved", func(t *testing.T) {
		installation := validInstallation()
		installation.Credentials = append(installation.Credentials, domain.Credential{
			ID: "cred_00000000000000000000000000000002", ManagedPath: "/var/lib/lanpanel/credentials/old",
		})
		resource := &installation.Resources[0]
		resource.Publication = domain.AppPublication{
			Kind:          domain.PublicationTemporaryHTTP,
			TemporaryHTTP: &domain.TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 18080},
		}
		resource.PublicationRecord.LastAppliedDigest = stringPointer(digest)
		resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{
			Generation: 1,
			ID:         "old-bundle", ConfigDigest: digest, Kind: domain.PublicationDomainHTTPS,
			EndpointIdentity: "old-endpoint", SiteIdentity: "old-site",
			ManagedPaths:  []string{"/var/lib/lanpanel/resources/old-runtime"},
			CredentialIDs: []string{"cred_00000000000000000000000000000002"},
			Listeners:     []domain.BundleListenerIdentity{{Network: "tcp", Port: 19002}},
			DomainHTTPS: &domain.DomainHTTPSBundleIdentity{
				ExactDomains: []string{"old.example.com"},
				Certificate:  domain.CertificateBundleIdentity{PointerIdentity: "old-pointer", BindingIdentity: "old-certificate"},
				Auth:         domain.AuthBundleIdentity{Mode: domain.AppAccessPublic},
				Static:       domain.StaticBundleIdentity{RouteIdentities: []string{}},
				GoAccess:     domain.GoAccessBundleIdentity{Enabled: false},
				EdgeOne:      domain.EdgeOneBundleIdentity{Enabled: false},
			},
		}
		claims, err := BuildClaims(installation)
		if err != nil {
			t.Fatalf("BuildClaims(pending config) error = %v", err)
		}
		for _, expected := range []Claim{
			{Kind: KindExactDomain, Value: "old.example.com"},
			{Kind: KindListener, Value: "tcp:80"},
			{Kind: KindListener, Value: "tcp:19002"},
			{Kind: KindCredentialUse, Value: "cred_00000000000000000000000000000002"},
			{Kind: KindManagedPath, Value: "/var/lib/lanpanel/resources/old-runtime"},
		} {
			if !hasClaim(claims, expected.Kind, expected.Value) {
				t.Fatalf("BuildClaims() omitted still-applied claim %#v from %#v", expected, claims)
			}
		}
	})

	t.Run("managed_path_overlap_is_rejected", func(t *testing.T) {
		assertConflict(t,
			Claim{Kind: KindManagedPath, Value: "/var/lib/lanpanel/a", Owner: "resource:a"},
			Claim{Kind: KindManagedPath, Value: "/var/lib/lanpanel/a/child", Owner: "resource:b"},
		)
	})

	t.Run("failed_replacement_is_atomic", func(t *testing.T) {
		registry := NewRegistry()
		transaction := registry.Begin()
		original := Claim{Kind: KindExactDomain, Value: "one.example.com", Owner: "resource:one"}
		if err := transaction.ReplaceOwner(original.Owner, []Claim{original}); err != nil {
			t.Fatal(err)
		}
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
		beforeGeneration, beforeClaims := registry.Snapshot()
		failed := registry.Begin()
		if err := failed.ReplaceOwner(original.Owner, []Claim{
			{Kind: KindExactDomain, Value: "replacement.example.com", Owner: original.Owner},
			{Kind: KindExactDomain, Value: "partial.example.com", Owner: "wrong-owner"},
		}); err == nil {
			t.Fatal("ReplaceOwner(wrong owner after valid prefix) error = nil")
		}
		if err := failed.Commit(); err == nil || !strings.Contains(err.Error(), "not open") {
			t.Fatalf("Commit() after rejected replacement error = %v", err)
		}
		afterGeneration, afterClaims := registry.Snapshot()
		if afterGeneration != beforeGeneration || !reflect.DeepEqual(beforeClaims, afterClaims) {
			t.Fatalf("registry changed after failed replacement: before=(%d,%#v) after=(%d,%#v)", beforeGeneration, beforeClaims, afterGeneration, afterClaims)
		}
	})

	t.Run("stale_transaction_is_rejected", func(t *testing.T) {
		registry := NewRegistry()
		first := registry.Begin()
		second := registry.Begin()
		if err := first.ReplaceOwner("resource:first", []Claim{{Kind: KindResourceName, Value: "first", Owner: "resource:first"}}); err != nil {
			t.Fatal(err)
		}
		if err := first.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := second.ReplaceOwner("resource:second", []Claim{{Kind: KindResourceName, Value: "second", Owner: "resource:second"}}); err != nil {
			t.Fatal(err)
		}
		if err := second.Commit(); err == nil || !strings.Contains(err.Error(), "stale") {
			t.Fatalf("second.Commit() error = %v", err)
		}
	})

	t.Run("stable_owner_is_not_derived_from_name_or_filename", func(t *testing.T) {
		installation := validInstallation()
		claimsBefore, err := BuildClaims(installation)
		if err != nil {
			t.Fatal(err)
		}
		installation.Resources[0].Name = "Renamed Application"
		claimsAfter, err := BuildClaims(installation)
		if err != nil {
			t.Fatal(err)
		}
		ownerBefore := resourceOwner(claimsBefore)
		ownerAfter := resourceOwner(claimsAfter)
		if ownerBefore == "" || ownerBefore != ownerAfter || !strings.Contains(ownerBefore, installation.Resources[0].ID) {
			t.Fatalf("resource owners before=%q after=%q", ownerBefore, ownerAfter)
		}
	})
}

func hasClaim(claims []Claim, kind Kind, value string) bool {
	for _, claim := range claims {
		if claim.Kind == kind && claim.Value == value {
			return true
		}
	}
	return false
}

func stringPointer(value string) *string { return &value }

func assertConflict(t *testing.T, original, conflicting Claim) {
	t.Helper()
	registry := NewRegistry()
	transaction := registry.Begin()
	if err := transaction.ReplaceOwner(original.Owner, []Claim{original}); err != nil {
		t.Fatal(err)
	}
	if err := transaction.ReplaceOwner(conflicting.Owner, []Claim{conflicting}); err == nil || !errors.As(err, new(ConflictError)) {
		t.Fatalf("ReplaceOwner(%#v) error = %v", conflicting, err)
	}
}

func resourceOwner(claims []Claim) string {
	for _, claim := range claims {
		if claim.Kind == KindResourceName {
			return claim.Owner
		}
	}
	return ""
}

func validInstallation() domain.Installation {
	return domain.Installation{
		SchemaVersion:  domain.InstallationSchemaVersion,
		InstallationID: "ins_00000000000000000000000000000001",
		Management: domain.ManagementAuthority{
			Address:      "127.23.45.67",
			Port:         23456,
			ManagedPaths: []string{"/var/lib/lanpanel/ui"},
		},
		Headscale: &domain.HeadscaleDomain{
			ID:                "hds_00000000000000000000000000000001",
			ControlDomain:     "control.example.com",
			MagicDNSNamespace: "tail.example.net",
			ManagedPaths:      []string{"/var/lib/lanpanel/headscale"},
		},
		Connector: &domain.TailnetConnector{
			ID:           "con_00000000000000000000000000000001",
			LoginServer:  "https://control.example.com",
			ManagedPaths: []string{"/var/lib/lanpanel/connector"},
		},
		Credentials: []domain.Credential{{
			ID:          "cred_00000000000000000000000000000001",
			ManagedPath: "/var/lib/lanpanel/credentials/app-basic",
		}},
		ManagedPaths: []string{"/var/lib/lanpanel/state"},
		Resources: []domain.AppResource{{
			ID:                  "res_00000000000000000000000000000001",
			Name:                "Application",
			Lifecycle:           domain.LifecycleActive,
			CurrentConfigDigest: digest,
			Target: domain.AppTarget{
				Kind:                domain.AppTargetLocalHTTP,
				ReadinessPath:       "/ready",
				AllowedHTTPStatuses: []uint16{200},
				WebSocket:           domain.WebSocketReadiness{Enabled: false},
				LocalHTTP:           &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation},
			},
			Publication: domain.AppPublication{
				Kind: domain.PublicationDomainHTTPS,
				DomainHTTPS: &domain.DomainHTTPSPublication{
					CanonicalDomain: "app.example.com",
					Aliases:         []string{"alias.example.com"},
					AccessMode:      domain.AppAccessPublic,
				},
			},
			PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1},
			ManagedProcess: &domain.ManagedProcess{
				ID:        "proc_00000000000000000000000000000001",
				Requested: domain.ProcessRequestedStopped,
				Service:   domain.ManagedService{Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{"/var/lib/app"}},
			},
			CredentialIDs: []string{"cred_00000000000000000000000000000001"},
			ManagedPaths:  []string{"/var/lib/lanpanel/resources/application"},
		}},
	}
}
