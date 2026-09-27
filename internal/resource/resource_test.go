package resource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"lanpanel/internal/domain"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshResourceHasStableUnpublishedStoppedIdentity(t *testing.T) {
	spec := LocalSpec{Name: "Example", EndpointKind: domain.LocalEndpointRelayUnix, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200, 204}, Service: domain.ManagedService{Executable: "/usr/local/bin/example", WorkingDirectory: "/srv/example", WritePaths: []string{"/srv/example/data"}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "example.test", AccessMode: domain.AppAccessPublic}}}
	first, err := NewLocal(spec, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Name = "Renamed"
	firstPaths, _ := DerivePaths(first.ID)
	secondPaths, _ := DerivePaths(second.ID)
	if first.ID != "res_"+strings.Repeat("01", 16) || first.ManagedProcess.ID != "proc_"+strings.Repeat("01", 16) || first.PublicationRecord.State != domain.PublicationUnpublished || first.PublicationRecord.UnpublishedGeneration != 1 || first.ManagedProcess.Requested != domain.ProcessRequestedStopped || first.ManagedProcess.Applied != nil || firstPaths != secondPaths {
		t.Fatalf("resource=%#v paths=%#v", first, firstPaths)
	}
	backendDir := filepath.Dir(firstPaths.BackendSocket)
	foundBackendDir := false
	for _, path := range first.ManagedPaths {
		if path == backendDir {
			foundBackendDir = true
			break
		}
	}
	if !foundBackendDir {
		t.Fatalf("resource managed paths omit backend directory: %v", first.ManagedPaths)
	}
}

func TestNewLocalManagedBasicDeclaresCredentialForAtomicCreate(t *testing.T) {
	spec := LocalSpec{Name: "Basic", EndpointKind: domain.LocalEndpointRelayUnix, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, Service: domain.ManagedService{Executable: "/usr/local/bin/example", WorkingDirectory: "/srv/example", WritePaths: []string{"/srv/example/data"}}, ManagedBasicUsername: "alice", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "basic.example.test", AccessMode: domain.AppAccessBasic}}}
	value, err := NewLocal(spec, bytes.NewReader(bytes.Repeat([]byte{3}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	if value.Publication.DomainHTTPS == nil || value.Publication.DomainHTTPS.CredentialID == "" || len(value.CredentialIDs) != 1 || value.CredentialIDs[0] != value.Publication.DomainHTTPS.CredentialID {
		t.Fatalf("resource=%#v", value)
	}
	credential := domain.Credential{ID: value.Publication.DomainHTTPS.CredentialID, Kind: "managed_basic", OwnerResourceID: value.ID, Username: "alice", ManagedPath: "/etc/lanpanel-public/basic/" + value.Publication.DomainHTTPS.CredentialID + ".htpasswd", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 49152}}
	if err := ValidateCreateWithCredential(installation, value, credential); err != nil {
		t.Fatal(err)
	}
}

func TestTailnetResourceHasNoLocalProcessAndRequiresConnectorBinding(t *testing.T) {
	spec := TailnetSpec{TargetKind: domain.AppTargetTailnetHTTP, Name: "Peer App", PeerIP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "peer.example.test", AccessMode: domain.AppAccessPublic}}}
	value, err := NewTailnet(spec, bytes.NewReader(bytes.Repeat([]byte{3}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if value.ManagedProcess != nil || value.Target.TailnetHTTP == nil || len(value.ManagedPaths) != 0 {
		t.Fatalf("tailnet resource=%#v", value)
	}
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 49152}, Connector: &domain.TailnetConnector{ID: "con_00000000000000000000000000000001", ControlURL: "https://control.example.test", ManagedPaths: domain.ConnectorManagedPaths()}}
	if err := ValidateCreate(installation, value); err != nil {
		t.Fatal(err)
	}
	installation.Connector = nil
	if err := ValidateCreate(installation, value); err == nil {
		t.Fatal("tailnet resource accepted without connector binding")
	} else {
		var prerequisite domain.PrerequisiteError
		if !errors.As(err, &prerequisite) || prerequisite.Code != domain.PrerequisiteConnectorRequired {
			t.Fatalf("create prerequisite error=%v", err)
		}
	}
	if _, err := PrepareUpdate(installation, value); err == nil {
		t.Fatal("tailnet update accepted without connector binding")
	} else {
		var prerequisite domain.PrerequisiteError
		if !errors.As(err, &prerequisite) || prerequisite.Code != domain.PrerequisiteConnectorRequired {
			t.Fatalf("update prerequisite error=%v", err)
		}
	}
}

func TestPrepareUpdatePreservesPriorSnapshot(t *testing.T) {
	spec := LocalSpec{Name: "Prior", EndpointKind: domain.LocalEndpointRelayUnix, ReadinessPath: "/ready", Service: domain.ManagedService{Executable: "/usr/local/bin/example", WorkingDirectory: "/srv/example", WritePaths: []string{"/srv/example/data"}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "example.test", AccessMode: domain.AppAccessPublic}}}
	prior, err := NewLocal(spec, bytes.NewReader(bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 49152}, Resources: []domain.AppResource{prior}}
	candidate := prior
	process := *prior.ManagedProcess
	candidate.ManagedProcess = &process
	candidate.Name = "Candidate"
	if _, err := PrepareUpdate(installation, candidate); err == nil {
		t.Fatal("resource update accepted immutable name change")
	}
	candidate.Name = prior.Name
	updated, err := PrepareUpdate(installation, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if installation.Resources[0].Name != "Prior" || updated.Name != prior.Name {
		t.Fatalf("prior=%q updated=%q", installation.Resources[0].Name, updated.Name)
	}

	candidate.ManagedProcess = nil
	if _, err := PrepareUpdate(installation, candidate); err == nil {
		t.Fatal("Local update candidate without managed process accepted")
	}
}

func TestPrepareUpdateRejectsInvalidStaticRelativePaths(t *testing.T) {
	const rootID = "static_00000000000000000000000000000001"
	cases := []struct {
		name         string
		relativePath string
		valid        bool
	}{
		{name: "backslash", relativePath: `assets\app.js`},
		{name: "newline", relativePath: "assets/\napp.js"},
		{name: "nul", relativePath: "assets/\x00app.js"},
		{name: "del", relativePath: "assets/\x7fapp.js"},
		{name: "absolute", relativePath: "/etc/passwd"},
		{name: "parent_escape", relativePath: "../secret"},
		{name: "legal_nested", relativePath: "assets/app.js", valid: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			spec := LocalSpec{Name: "Prior", EndpointKind: domain.LocalEndpointRelayUnix, ReadinessPath: "/ready", Service: domain.ManagedService{Executable: "/usr/local/bin/example", WorkingDirectory: "/srv/example", WritePaths: []string{"/srv/example/data"}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "example.test", AccessMode: domain.AppAccessPublic}}}
			prior, err := NewLocal(spec, bytes.NewReader(bytes.Repeat([]byte{2}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 49152}, StaticRoots: []domain.StaticContentRoot{{ID: rootID, OwnerResourceID: prior.ID, Path: "/srv/example-static", Fingerprint: shaDigest("static-root"), Device: 1}}, Resources: []domain.AppResource{prior}}
			candidate := prior
			publication := *candidate.Publication.DomainHTTPS
			publication.StaticRootID = rootID
			publication.StaticMappings = []domain.StaticMapping{{URLPath: "/assets/app.js", RelativePath: testCase.relativePath}}
			candidate.Publication.DomainHTTPS = &publication

			updated, err := PrepareUpdate(installation, candidate)
			if testCase.valid && err != nil {
				t.Fatalf("PrepareUpdate(relative path %q) error = %v", testCase.relativePath, err)
			}
			if !testCase.valid && err == nil {
				t.Fatalf("PrepareUpdate(relative path %q) accepted invalid path", testCase.relativePath)
			}
			if testCase.valid && updated.Publication.DomainHTTPS.StaticMappings[0].RelativePath != testCase.relativePath {
				t.Fatalf("PrepareUpdate changed relative path to %q", updated.Publication.DomainHTTPS.StaticMappings[0].RelativePath)
			}
		})
	}
}

func TestPrepareTailnetUpdatePreservesAbsentProcess(t *testing.T) {
	prior, err := NewTailnet(TailnetSpec{TargetKind: domain.AppTargetTailnetHTTP, Name: "Peer App", PeerIP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080, ReadinessPath: "/ready", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "peer.example.test", AccessMode: domain.AppAccessPublic}}}, bytes.NewReader(bytes.Repeat([]byte{4}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 49152}, Connector: &domain.TailnetConnector{ID: "con_00000000000000000000000000000001", ControlURL: "https://control.example.test", ManagedPaths: domain.ConnectorManagedPaths()}, Resources: []domain.AppResource{prior}}
	candidate := prior
	candidate.Target.TailnetHTTP = &domain.TailnetHTTPTarget{IP: "100.64.0.3", SourceIP: "100.64.0.1", Port: 8081}
	updated, err := PrepareUpdate(installation, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ManagedProcess != nil || updated.Target.Kind != domain.AppTargetTailnetHTTP {
		t.Fatalf("updated Tailnet resource=%#v", updated)
	}
	candidate.ManagedProcess = &domain.ManagedProcess{ID: "proc_00000000000000000000000000000001", Requested: domain.ProcessRequestedStopped}
	if _, err := PrepareUpdate(installation, candidate); err == nil {
		t.Fatal("Tailnet update candidate carrying managed process accepted")
	}
	candidate = prior
	candidate.Target = domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointRelayUnix}}
	candidate.ManagedProcess = &domain.ManagedProcess{ID: "proc_00000000000000000000000000000001", Requested: domain.ProcessRequestedStopped, Service: domain.ManagedService{Executable: "/usr/local/bin/example", WorkingDirectory: "/srv/example"}}
	if _, err := PrepareUpdate(installation, candidate); err == nil {
		t.Fatal("Tailnet update switched target kind")
	}
}

func TestArgumentsRejectExpansionAndKnownSecret(t *testing.T) {
	if ValidateArguments([]string{"${SECRET}"}, nil) == nil {
		t.Fatal("expansion accepted")
	}
	known := map[string]struct{}{shaDigest("secret"): {}}
	if ValidateArguments([]string{"secret"}, known) == nil {
		t.Fatal("known secret accepted")
	}
}

func shaDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
