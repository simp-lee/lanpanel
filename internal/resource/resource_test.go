package resource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"lanpanel/internal/domain"
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
	updated, err := PrepareUpdate(installation, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if installation.Resources[0].Name != "Prior" || updated.Name != "Candidate" {
		t.Fatalf("prior=%q updated=%q", installation.Resources[0].Name, updated.Name)
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
