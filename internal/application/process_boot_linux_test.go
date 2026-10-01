//go:build linux

package application

import (
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	managedprocess "lanpanel/internal/process"
	managedresource "lanpanel/internal/resource"
	"strings"
	"testing"
)

func TestValidateBootProcessAuthorityRejectsMismatchedAppliedAuthority(t *testing.T) {
	resourceID := "res_00000000000000000000000000000001"
	configDigest := "sha256:" + strings.Repeat("a", 64)
	policyDigest := "sha256:" + strings.Repeat("b", 64)
	service := domain.ManagedService{Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app"}
	item := domain.AppResource{ID: resourceID, CurrentConfigDigest: configDigest, Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointUnixSocketActivation}}, ManagedProcess: &domain.ManagedProcess{Service: service}}
	paths, err := managedresource.DerivePaths(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	applied := domain.ProcessBundle{ConfigDigest: configDigest, PolicyDigest: policyDigest, Cgroup: "/system.slice/lanpanel-app.service", FrontendEndpoint: paths.FrontendSocket, ApplicationUID: 1200, ApplicationGID: 1201}
	authority := managedprocess.ExecAuthority{ResourceID: resourceID, UID: applied.ApplicationUID, GID: applied.ApplicationGID, Service: domain.ManagedService{Executable: service.Executable, Arguments: []string{}, WorkingDirectory: service.WorkingDirectory, WritePaths: []string{}}, Endpoint: paths.FrontendSocket, Policy: confinement.UnitPolicy{ResourceID: resourceID, Digest: policyDigest, Cgroup: applied.Cgroup}, Evidence: managedresource.ReferenceEvidence{WritePathIdentities: []string{}}}
	if err := validateBootProcessAuthority(item, authority, applied); err != nil {
		t.Fatalf("valid boot authority rejected: %v", err)
	}
	applied.PolicyDigest = "sha256:" + strings.Repeat("c", 64)
	if err := validateBootProcessAuthority(item, authority, applied); err == nil {
		t.Fatal("mismatched applied policy authority accepted")
	}
}
