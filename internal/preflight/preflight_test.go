package preflight

import (
	"strings"
	"testing"
	"time"

	"lanpanel/internal/plans"
)

func TestExpansionPreflightUsesExactScopeAndResponsibilities(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := expansionRequest(ExpansionHeadscale)
	observed := passingExpansionObservations(request, now)
	result, err := EvaluateExpansion(request, observed)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("result=%#v", result)
	}
	for _, code := range []string{"responsibility/cloud_firewall", "responsibility/public_dns"} {
		finding, ok := findingByCode(result.Findings, code)
		if !ok || finding.Disposition != FindingResponsibility {
			t.Fatalf("responsibility %q missing from %#v", code, result.Findings)
		}
	}
	listener, ok := findingByCode(result.Findings, "listeners")
	if !ok || !strings.Contains(listener.Identity, "03478") || !strings.Contains(listener.Identity, "00080") || !strings.Contains(listener.Identity, "00443") {
		t.Fatalf("Headscale listener authority=%#v", listener)
	}
	evidence, err := result.PlanEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireExpansionPlanEvidence([]ExpansionScope{ExpansionHeadscale}, request.Target, []plans.Evidence{evidence}, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapRequiresManagementAndClosedNginxListeners(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := expansionRequest(ExpansionBootstrap)
	request.Target = "installation"
	request.Domains = nil
	request.BootstrapListeners = []ListenerRequirement{{Protocol: "tcp", Address: "127.23.45.67", Port: 52345, Purpose: "management"}}
	observed := passingExpansionObservations(request, now)
	result, err := EvaluateExpansion(request, observed)
	if err != nil || !result.Allowed {
		t.Fatalf("bootstrap result=%#v error=%v", result, err)
	}
	listener, ok := findingByCode(result.Findings, "listeners")
	if !ok || !strings.Contains(listener.Identity, "127.23.45.67") || !strings.Contains(listener.Identity, "00080") || !strings.Contains(listener.Identity, "00443") {
		t.Fatalf("bootstrap listener authority=%#v", listener)
	}
	observed.Listeners = []ListenerObservation{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, SocketInode: 91}}
	result, err = EvaluateExpansion(request, observed)
	if err != nil || result.Allowed {
		t.Fatalf("bootstrap accepted occupied Nginx listener: %#v error=%v", result, err)
	}
}

func TestNonBootstrapScopesRejectExtraListenerRequirements(t *testing.T) {
	request := expansionRequest(ExpansionTemporaryHTTP)
	request.Domains = nil
	request.PublicAddresses = []string{"8.8.8.8"}
	request.TemporaryPort = 23456
	request.BootstrapListeners = []ListenerRequirement{{Protocol: "tcp", Address: "0.0.0.0", Port: 9999, Purpose: "unrelated"}}
	if _, err := EvaluateExpansion(request, passingExpansionObservations(request, time.Unix(1_700_000_000, 0).UTC())); err == nil {
		t.Fatal("temporary HTTP accepted unrelated listener prerequisite")
	}
}

func TestExpansionScopesCheckOnlyTheirExactPublicListeners(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	temporary := expansionRequest(ExpansionTemporaryHTTP)
	temporary.TemporaryPort = 23456
	temporary.Domains = nil
	temporary.PublicAddresses = []string{"8.8.8.8"}
	observed := passingExpansionObservations(temporary, now)
	observed.Listeners = []ListenerObservation{{Protocol: "tcp", Address: "0.0.0.0", Port: 80, SocketInode: 10}, {Protocol: "udp", Address: "0.0.0.0", Port: 3478, SocketInode: 11}}
	result, err := EvaluateExpansion(temporary, observed)
	if err != nil || !result.Allowed {
		t.Fatalf("temporary result=%#v err=%v", result, err)
	}

	domain := expansionRequest(ExpansionDomainHTTPS)
	observed = passingExpansionObservations(domain, now)
	observed.Listeners = []ListenerObservation{{Protocol: "tcp", Address: "0.0.0.0", Port: 3478, SocketInode: 12}}
	result, err = EvaluateExpansion(domain, observed)
	if err != nil || !result.Allowed {
		t.Fatalf("domain result=%#v err=%v", result, err)
	}
}

func TestExpansionPreflightRejectsConflictsClockPackageAndPathDrift(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := expansionRequest(ExpansionDomainHTTPS)
	tests := []struct {
		name string
		edit func(*ExpansionObservations)
		code string
	}{
		{"foreign listener", func(value *ExpansionObservations) {
			value.Listeners = []ListenerObservation{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, SocketInode: 10}}
		}, "listeners"},
		{"clock regression", func(value *ExpansionObservations) { value.Clock.Now = request.LastTrustedWall.Add(-time.Second) }, "trusted_clock"},
		{"dpkg not ready", func(value *ExpansionObservations) {
			value.Packages.Ready = false
			value.Packages.Reason = "half_configured"
		}, "package_state"},
		{"unsafe path", func(value *ExpansionObservations) { value.Paths[0].ParentsSafe = false }, "managed_paths"},
		{"disk short", func(value *ExpansionObservations) {
			value.Disks[0].AvailableBytes = request.Disks[0].MinimumAvailableBytes - 1
		}, "disk"},
		{"disk read only", func(value *ExpansionObservations) { value.Disks[0].ReadOnly = true }, "disk"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observed := passingExpansionObservations(request, now)
			test.edit(&observed)
			result, err := EvaluateExpansion(request, observed)
			if err != nil {
				t.Fatal(err)
			}
			finding, ok := findingByCode(result.Findings, test.code)
			if result.Allowed || !ok || finding.Disposition != FindingBlocked {
				t.Fatalf("result=%#v finding=%#v", result, finding)
			}
		})
	}
}

func TestExpansionPreflightAcceptsOnlyExactOwnedListenerIdentity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := expansionRequest(ExpansionDomainHTTPS)
	request.OwnedListeners = []OwnedListenerAuthority{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, SocketInode: 19, IdentityDigest: OwnedListenerDigest("tcp", "0.0.0.0", 443, 19)}}
	observed := passingExpansionObservations(request, now)
	observed.Listeners = []ListenerObservation{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, SocketInode: 19}}
	result, err := EvaluateExpansion(request, observed)
	if err != nil || !result.Allowed {
		t.Fatalf("owned listener result=%#v err=%v", result, err)
	}
	observed.Listeners[0].SocketInode++
	result, err = EvaluateExpansion(request, observed)
	if err != nil || result.Allowed {
		t.Fatalf("reused listener identity result=%#v err=%v", result, err)
	}
}

func TestContractionPreflightIgnoresUnrelatedExpansionFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	owned := []OwnedIngressAuthority{{ResourceID: "res_00000000000000000000000000000001", RuntimeIdentity: "sha256:" + strings.Repeat("1", 64), OwnershipDigest: "sha256:" + strings.Repeat("2", 64)}}
	request := ContractionRequest{Kind: ContractionUnpublish, Target: "resource/res_00000000000000000000000000000001", Generation: 7, OwnershipInventoryDigest: "sha256:" + strings.Repeat("3", 64), ClosureAuthorityDigest: "sha256:" + strings.Repeat("4", 64), OwnedIngress: owned}
	observed := ContractionObservations{ExecutorUID: 0, InventoryComplete: true, OwnershipInventoryDigest: request.OwnershipInventoryDigest, ClosureAuthorityDigest: request.ClosureAuthorityDigest, OwnedIngress: owned, ObservedAt: now, Diagnostics: []Diagnostic{
		{Code: "dns_failed", Summary: "DNS is unavailable", Identity: "app.example.test"},
		{Code: "clock_unsynchronized", Summary: "clock is unsynchronized", Identity: "kernel"},
		{Code: "package_broken", Summary: "dpkg is not ready", Identity: "dpkg"},
		{Code: "provider_failed", Summary: "provider is unavailable", Identity: "provider"},
	}}
	result, err := EvaluateContraction(request, observed)
	if err != nil || !result.Allowed {
		t.Fatalf("contraction result=%#v err=%v", result, err)
	}
	for _, finding := range result.Findings {
		if strings.HasPrefix(finding.Code, "diagnostic/") && finding.Disposition != FindingDiagnostic {
			t.Fatalf("diagnostic blocked contraction: %#v", finding)
		}
	}
	evidence, err := result.PlanEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireContractionPlanEvidence([]ContractionKind{ContractionUnpublish}, request.Target, []plans.Evidence{evidence}, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestContractionPreflightBlocksOnlyPrivilegeAndClosureAuthority(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	owned := []OwnedIngressAuthority{{ResourceID: "res_00000000000000000000000000000001", RuntimeIdentity: "sha256:" + strings.Repeat("1", 64), OwnershipDigest: "sha256:" + strings.Repeat("2", 64)}}
	request := ContractionRequest{Kind: ContractionCloseAll, Target: "installation", Generation: 8, OwnershipInventoryDigest: "sha256:" + strings.Repeat("3", 64), ClosureAuthorityDigest: "sha256:" + strings.Repeat("4", 64), OwnedIngress: owned}
	observed := ContractionObservations{ExecutorUID: 1000, InventoryComplete: false, OwnershipInventoryDigest: request.OwnershipInventoryDigest, ClosureAuthorityDigest: "sha256:" + strings.Repeat("5", 64), OwnedIngress: owned, ObservedAt: now}
	result, err := EvaluateContraction(request, observed)
	if err != nil || result.Allowed {
		t.Fatalf("contraction result=%#v err=%v", result, err)
	}
	for _, code := range []string{"closure_authority", "owned_ingress", "root_executor"} {
		finding, ok := findingByCode(result.Findings, code)
		if !ok || finding.Disposition != FindingBlocked {
			t.Fatalf("missing blocker %q: %#v", code, result.Findings)
		}
	}
}

func TestExpansionResultBindsExactTypedRequest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := expansionRequest(ExpansionDomainHTTPS)
	result, err := EvaluateExpansion(request, passingExpansionObservations(request, now))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ExpansionRequestDigest(request)
	if err != nil || result.RequestDigest != digest {
		t.Fatalf("request digest=%q want=%q err=%v", result.RequestDigest, digest, err)
	}
	changed := request
	changed.Domains = []string{"other.example.test"}
	changedDigest, _ := ExpansionRequestDigest(changed)
	if changedDigest == result.RequestDigest {
		t.Fatal("domain change preserved preflight request authority")
	}
	if err := RequireExpansionResultForRequest(result, changed, now); err == nil {
		t.Fatal("result authorized changed domain request")
	}
	changed = request
	changed.Disks = []DiskRequirement{{Path: request.Disks[0].Path, MinimumAvailableBytes: request.Disks[0].MinimumAvailableBytes + 1}}
	changedDigest, _ = ExpansionRequestDigest(changed)
	if changedDigest == result.RequestDigest {
		t.Fatal("disk threshold change preserved preflight request authority")
	}
}

func TestQualificationCandidateUsesManifestHostProfileCaseBinding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := expansionRequest(ExpansionHeadscale)
	request.Profile.Authority = ProfileAuthority{Kind: QualificationCandidate, Digest: "sha256:" + strings.Repeat("a", 64), CandidateDigest: "sha256:" + strings.Repeat("b", 64), ManifestDigest: "sha256:" + strings.Repeat("c", 64), HostFingerprint: "host/fingerprint", CaseID: "headscale-install"}
	result, err := EvaluateExpansion(request, passingExpansionObservations(request, now))
	if err != nil || !result.Allowed {
		t.Fatalf("candidate result=%#v err=%v", result, err)
	}
	request.Profile.Authority.CaseID = ""
	if _, err := EvaluateExpansion(request, passingExpansionObservations(request, now)); err == nil {
		t.Fatal("candidate without case binding was accepted")
	}
}

func TestFallbackStopDoesNotDependOnCompleteSelectiveInventory(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := ContractionRequest{Kind: ContractionEmergency, Target: "installation", Generation: 1, OwnershipInventoryDigest: "sha256:" + strings.Repeat("1", 64), ClosureAuthorityDigest: "sha256:" + strings.Repeat("2", 64), FallbackStop: true}
	observed := ContractionObservations{ExecutorUID: 0, InventoryComplete: false, OwnershipInventoryDigest: "sha256:" + strings.Repeat("3", 64), ClosureAuthorityDigest: request.ClosureAuthorityDigest, ObservedAt: now, Diagnostics: []Diagnostic{{Code: "invalid code", Summary: "ignored malformed diagnostic", Identity: "fixture"}}}
	result, err := EvaluateContraction(request, observed)
	if err != nil || !result.Allowed {
		t.Fatalf("fallback result=%#v err=%v", result, err)
	}
}

func TestCrossFamilyWildcardIsConservativelyConflicting(t *testing.T) {
	if !socketAddressesOverlap("::", "0.0.0.0") {
		t.Fatal("IPv6 wildcard was treated as disjoint without IPV6_V6ONLY proof")
	}
}

func TestPreflightAuthorityRejectsStaleWrongScopeOrTarget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := expansionRequest(ExpansionDomainHTTPS)
	result, err := EvaluateExpansion(request, passingExpansionObservations(request, now))
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireExpansionResult(result, []ExpansionScope{ExpansionTemporaryHTTP}, request.Target, request.Generation, now); err == nil {
		t.Fatal("wrong expansion scope was accepted")
	}
	if err := RequireExpansionResult(result, []ExpansionScope{ExpansionDomainHTTPS}, "resource/other", request.Generation, now); err == nil {
		t.Fatal("wrong expansion target was accepted")
	}
	if err := RequireExpansionResult(result, []ExpansionScope{ExpansionDomainHTTPS}, request.Target, request.Generation, result.ValidUntil.Add(time.Nanosecond)); err == nil {
		t.Fatal("stale expansion result was accepted")
	}
}

func expansionRequest(scope ExpansionScope) ExpansionRequest {
	return ExpansionRequest{
		Scope: scope, Target: "resource/res_00000000000000000000000000000001", Generation: 7,
		Profile: ExpectedProfile{ID: "debian", VersionID: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: "sha256:" + strings.Repeat("9", 64), Authority: ProfileAuthority{Kind: FinalSupportedProfile, Digest: "sha256:" + strings.Repeat("a", 64), LiveQualified: true}},
		Domains: []string{"app.example.test"}, ManagedPaths: []ManagedPathRequirement{{Path: "/var/lib/lanpanel/apps/app-one", Kind: ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o700, MaximumMode: 0o700}}, Disks: []DiskRequirement{{Path: "/var/lib/lanpanel", MinimumAvailableBytes: 1024}}, LastTrustedWall: time.Unix(1_699_999_000, 0).UTC(),
	}
}

func passingExpansionObservations(request ExpansionRequest, now time.Time) ExpansionObservations {
	dns := make([]DNSObservation, len(request.Domains))
	for index, domain := range request.Domains {
		dns[index] = DNSObservation{Domain: domain, Addresses: []string{"8.8.8.8"}}
	}
	paths := make([]PathObservation, len(request.ManagedPaths))
	for index, path := range request.ManagedPaths {
		paths[index] = PathObservation{Path: path.Path, Exists: true, Kind: path.Kind, UID: path.OwnerUID, GID: path.OwnerGID, Mode: path.MaximumMode, Device: 1, Inode: uint64(index + 1), ParentsSafe: true}
	}
	disks := make([]DiskObservation, len(request.Disks))
	for index, disk := range request.Disks {
		disks[index] = DiskObservation{Path: disk.Path, Device: uint64(index + 1), AvailableBytes: disk.MinimumAvailableBytes}
	}
	return ExpansionObservations{OperatingSystem: "linux", Architecture: "amd64", Platform: PlatformInfo{ID: request.Profile.ID, VersionID: request.Profile.VersionID}, Clock: ClockObservation{Now: now, Synchronized: true, Source: "kernel"}, ExecutorUID: 0, Systemd: ComponentObservation{Available: true, Identity: "systemd/1"}, APT: ComponentObservation{Available: true, Identity: "apt/1"}, DPKG: ComponentObservation{Available: true, Identity: "dpkg/1"}, Packages: PackageObservation{Ready: true, Identity: "sha256:" + strings.Repeat("b", 64), SystemdVersion: request.Profile.SystemdVersion, NginxVersion: request.Profile.NginxVersion, PackageSnapshotDigest: request.Profile.PackageSnapshotDigest}, DNS: dns, ListenerInventoryComplete: true, Paths: paths, Disks: disks}
}

func findingByCode(values []Finding, code string) (Finding, bool) {
	for _, value := range values {
		if value.Code == code {
			return value, true
		}
	}
	return Finding{}, false
}
