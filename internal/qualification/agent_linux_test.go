//go:build linux

package qualification

import (
	"lanpanel/internal/certificates"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentResponseRequiresReviewableObservedPackageTuple(t *testing.T) {
	tuple := []release.PackageTuple{{Name: "nginx", Version: "1.26.0-1", Architecture: "amd64"}}
	response := AgentResponse{SchemaVersion: AgentResponseSchemaVersion, RunID: "run-one", Action: AgentFinalInventory, Succeeded: true, Evidence: release.DigestBytes([]byte("inventory")), ObservedPackageTuple: tuple}
	data, err := release.MarshalCanonical(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAgentResponse(data, response.RunID, response.Action); err != nil {
		t.Fatalf("exact observed package tuple was rejected: %v", err)
	}
	response.ObservedPackageTuple = nil
	data, _ = release.MarshalCanonical(response)
	if _, err := DecodeAgentResponse(data, response.RunID, response.Action); err == nil {
		t.Fatal("successful terminal inventory omitted observed package tuple")
	}
	response.ObservedPackageTuple = []release.PackageTuple{{Name: "zlib", Version: "1.0", Architecture: "amd64"}, {Name: "nginx", Version: "1.26.0-1", Architecture: "amd64"}}
	data, _ = release.MarshalCanonical(response)
	if _, err := DecodeAgentResponse(data, response.RunID, response.Action); err == nil {
		t.Fatal("noncanonical observed package tuple was accepted")
	}
}

func TestCertificateInventoryEvidencePreservesExactCleanupAuthority(t *testing.T) {
	deleted := testQualificationCertificateArtifact("cert_00000000000000000000000000000001", "deleted")
	retained := testQualificationCertificateArtifact("cert_00000000000000000000000000000002", "retained")
	state := liveState{CertificateCleanup: []qualificationCertificateArtifact{deleted}, CertificateCleanupComplete: true, RetainedCertificate: &retained}
	raw, err := certificateInventoryEvidence(state)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := decodeQualificationCertificateInventoryEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Deleted) != 1 || observed.Deleted[0] != deleted || observed.Retained != retained {
		t.Fatal("certificate cleanup evidence lost an exact identity")
	}
	observed.Deleted = append(observed.Deleted, deleted)
	if err := validateQualificationCertificateInventoryEvidence(observed); err == nil {
		t.Fatal("duplicate certificate cleanup identity was accepted")
	}
	observed.Deleted = []qualificationCertificateArtifact{retained}
	if err := validateQualificationCertificateInventoryEvidence(observed); err == nil {
		t.Fatal("retained certificate was accepted in deletion inventory")
	}
}

func TestFinalLiveStateRequiresCompletedCertificateCleanup(t *testing.T) {
	digest := release.DigestBytes([]byte("input"))
	artifact := testQualificationCertificateArtifact("cert_00000000000000000000000000000001", "deleted")
	state := liveState{SchemaVersion: liveStateSchemaVersion, RunID: "run-one", ProtectedInputDigest: digest, DNSCreateIntents: []dnsCreateIntent{}, CloudflareRecords: []cloudflareRecord{}, CertificateCleanup: []qualificationCertificateArtifact{artifact}, CompletedSteps: []string{}, FinalCleanupComplete: true}
	if err := validateLiveState(state, state.RunID, digest); err == nil {
		t.Fatal("final cleanup state accepted a recorded certificate without completed deletion")
	}
}

func testQualificationCertificateArtifact(id, seed string) qualificationCertificateArtifact {
	digest := func(suffix string) string { return "sha256:" + release.DigestBytes([]byte(seed+"/"+suffix)) }
	return qualificationCertificateArtifact{CertificateID: id, Generation: 1, Bundle: certificates.BundleIdentity{Fingerprint: digest("fingerprint"), SANIdentity: digest("san"), ChainIdentity: digest("chain"), IssuerIdentity: digest("issuer"), BindingIdentity: digest("binding"), DirectoryIdentity: digest("directory")}}
}

func TestSecretSentinelDetectsManagedResidue(t *testing.T) {
	root := t.TempDir()
	secret := []byte("qualification-sentinel-secret")
	path := filepath.Join(root, "managed.json")
	if err := os.WriteFile(path, []byte(`{"status":"clean"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSecretSentinelRoots([][]byte{secret}, []string{root}); err != nil {
		t.Fatalf("clean inventory rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"secret":"`+string(secret)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSecretSentinelRoots([][]byte{secret}, []string{root}); err == nil || !strings.Contains(err.Error(), "secret residue") {
		t.Fatalf("secret residue was not detected: %v", err)
	}
}
