//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordingSecurityExecutor struct {
	commands []securityCommand
	outputs  []securityCommandOutput
}

func (executor *recordingSecurityExecutor) Run(_ context.Context, command securityCommand) (securityCommandOutput, error) {
	executor.commands = append(executor.commands, command)
	output := executor.outputs[0]
	executor.outputs = executor.outputs[1:]
	return output, nil
}

func TestReleaseSecurityScannerVersionChecksKeepGovulncheckOnFixedFeed(t *testing.T) {
	executor := &recordingSecurityExecutor{outputs: []securityCommandOutput{
		{Stdout: []byte("Scanner: govulncheck@v" + PinnedGovulncheckVersion + "\n")},
		{Stdout: []byte("osv-scanner version: " + PinnedOSVScannerVersion + "\n")},
	}}
	input := SecurityScanInput{Govulncheck: FixedScanner{Path: "/tools/govulncheck"}, OSVScanner: FixedScanner{Path: "/tools/osv-scanner"}}
	if err := verifyScannerVersions(executor, []string{"PATH="}, "/work", input, "file:///feeds/go-fixed"); err != nil {
		t.Fatal(err)
	}
	if len(executor.commands) != 2 || !reflect.DeepEqual(executor.commands[0].Arguments, []string{"-db=file:///feeds/go-fixed", "-version"}) || !reflect.DeepEqual(executor.commands[1].Arguments, []string{"--version"}) {
		t.Fatalf("scanner version checks are not bound to the fixed feed and versions: %#v", executor.commands)
	}
}

func TestReleaseSecurityScannersUseExactOfflineArtifactArguments(t *testing.T) {
	executor := &recordingSecurityExecutor{outputs: []securityCommandOutput{{ExitCode: 1}}}
	_, err := executeOSVScan(executor, "/tools/osv-scanner", "/feeds/osv-fixed", "/artifacts/lanpanel.spdx.json", "/work/empty.toml", []string{"PATH="}, "/work")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"scan", "source", "--sbom=/artifacts/lanpanel.spdx.json", "--config=/work/empty.toml", "--format=json", "--offline", "--offline-vulnerabilities", "--no-resolve", "--all-packages", "--local-db-path=/feeds/osv-fixed", "--verbosity=error"}
	if len(executor.commands) != 1 || executor.commands[0].Path != "/tools/osv-scanner" || !reflect.DeepEqual(executor.commands[0].Arguments, want) || !reflect.DeepEqual(executor.commands[0].Environment, []string{"PATH="}) {
		t.Fatalf("OSV invocation did not bind exact SBOM/feed/offline flags: %#v", executor.commands)
	}
}

func TestGovulncheckOutputRequiresBinaryModeAndProducesReachableFindings(t *testing.T) {
	database := "file:///feeds/go-vulndb"
	stream := strings.Join([]string{
		`{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.4","db":"` + database + `","scan_level":"symbol","scan_mode":"binary"}}`,
		`{"SBOM":{"go_version":"go1.26.6","modules":[{"path":"lanpanel","version":"(devel)"}]}}`,
		`{"finding":{"osv":"GO-2026-0001","trace":[{"module":"golang.org/x/net","package":"golang.org/x/net/http2","function":"ServeConn"}]}}`,
	}, "\n")
	findings, err := decodeGovulncheckOutput([]byte(stream), database)
	if err != nil || len(findings) != 1 || findings[0].Component != "golang.org/x/net" || !findings[0].InShippedClosure || !findings[0].RuntimeReachable || findings[0].Resolution != release.ResolutionUnresolved {
		t.Fatalf("binary scan output was not converted exactly: %#v error=%v", findings, err)
	}
	if _, err := decodeGovulncheckOutput([]byte(strings.Replace(stream, `"scan_mode":"binary"`, `"scan_mode":"source"`, 1)), database); err == nil {
		t.Fatal("source-mode output was accepted as an exact candidate scan")
	}
}

func TestGovulncheckReachabilityRequiresFunctionTrace(t *testing.T) {
	database := "file:///feeds/go-vulndb"
	header := `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.4","db":"` + database + `","scan_level":"symbol","scan_mode":"binary"}}` + "\n" +
		`{"SBOM":{"go_version":"go1.26.6","modules":[{"path":"stdlib","version":"v1.26.6"}]}}` + "\n"
	for _, test := range []struct {
		name, trace string
		reachable   bool
	}{
		{"module", `{"module":"stdlib"}`, false},
		{"package", `{"module":"stdlib","package":"fmt"}`, false},
		{"function", `{"module":"stdlib","package":"fmt","function":"Sprintf"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := header + `{"finding":{"osv":"GO-2026-0001","trace":[` + test.trace + `]}}`
			findings, err := decodeGovulncheckOutput([]byte(stream), database)
			if err != nil || len(findings) != 1 || findings[0].RuntimeReachable != test.reachable || !findings[0].InShippedClosure || findings[0].Severity != release.SeverityHigh || findings[0].Resolution != release.ResolutionUnresolved {
				t.Fatalf("wrong finding disposition: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestOSVOutputMustCoverExactSBOMAndDistroClosure(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "lanpanel.spdx.json")
	expected := map[string]osvPackageIdentity{}
	for _, value := range []osvPackageIdentity{{Name: "golang.org/x/net", Version: "v0.58.0", Ecosystem: "Go"}, {Name: "nginx", Version: "1.26.0-1", Ecosystem: "Debian"}} {
		expected[value.key()] = value
	}
	data := []byte(`{"results":[{"source":{"path":"` + sbomPath + `","type":"sbom"},"packages":[` +
		`{"package":{"name":"golang.org/x/net","version":"v0.58.0","ecosystem":"Go"},"vulnerabilities":[]},` +
		`{"package":{"name":"nginx","version":"1.26.0-1","ecosystem":"Debian"},"vulnerabilities":[{"id":"DSA-0001"}],"groups":[{"ids":["DSA-0001"],"max_severity":"9.1"}]}` +
		`]}]}`)
	findings, err := decodeOSVOutput(data, sbomPath, expected, "Debian")
	if err != nil || len(findings) != 1 || findings[0].ID != "DSA-0001" || findings[0].Severity != release.SeverityCritical || !findings[0].RuntimeReachable {
		t.Fatalf("distro closure result=%#v error=%v", findings, err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	results := decoded["results"].([]any)
	result := results[0].(map[string]any)
	result["packages"] = result["packages"].([]any)[:1]
	missing, _ := json.Marshal(decoded)
	if _, err := decodeOSVOutput(missing, sbomPath, expected, "Debian"); err == nil {
		t.Fatal("OSV output omitting the distro package closure was accepted")
	}
	result["packages"] = []any{}
	zeroCoverage, _ := json.Marshal(decoded)
	if _, err := decodeOSVOutput(zeroCoverage, sbomPath, expected, "Debian"); err == nil {
		t.Fatal("OSV output with zero package coverage was accepted")
	}
}

func TestSecurityDatabaseCapturesMustBeCurrentAtScan(t *testing.T) {
	scannedAt := time.Unix(1_700_000_000, 0).UTC()
	fresh := FixedVulnerabilityDatabase{CapturedAt: scannedAt.Add(-maximumSecurityAuthorityAge)}
	input := SecurityScanInput{GoDatabase: fresh, SBOMDatabase: fresh, DistroDatabase: fresh}
	if err := validateSecurityDatabaseFreshness(input, scannedAt); err != nil {
		t.Fatalf("boundary-age fixed feeds were rejected: %v", err)
	}
	input.DistroDatabase.CapturedAt = scannedAt.Add(-maximumSecurityAuthorityAge - time.Second)
	if err := validateSecurityDatabaseFreshness(input, scannedAt); err == nil {
		t.Fatal("stale distro vulnerability feed was accepted")
	}
	input.DistroDatabase.CapturedAt = scannedAt.Add(time.Second)
	if err := validateSecurityDatabaseFreshness(input, scannedAt); err == nil {
		t.Fatal("future-dated distro vulnerability feed was accepted")
	}
}

func TestFixedVulnerabilityDatabaseDigestBindsCompleteRelativeClosure(t *testing.T) {
	makeDatabase := func(root string) {
		t.Helper()
		t.Cleanup(func() {
			_ = os.Chmod(root, 0o700)
			_ = os.Chmod(filepath.Join(root, "Go"), 0o700)
			_ = os.Chmod(filepath.Join(root, "Go", "all.zip"), 0o600)
		})
		if err := os.MkdirAll(filepath.Join(root, "Go"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "Go", "all.zip"), []byte("fixed-feed"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, "Go", "all.zip"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, "Go"), 0o500); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	left := filepath.Join(t.TempDir(), "database")
	right := filepath.Join(t.TempDir(), "database")
	makeDatabase(left)
	makeDatabase(right)
	leftDigest, err := FixedVulnerabilityDatabaseDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := FixedVulnerabilityDatabaseDigest(right)
	if err != nil || leftDigest != rightDigest || !release.ValidDigest(leftDigest) {
		t.Fatalf("fixed database digest is path-dependent or invalid: left=%s right=%s error=%v", leftDigest, rightDigest, err)
	}
}

func TestSecurityFindingMergeRetainsSameAdvisoryForEachComponent(t *testing.T) {
	input := []release.SecurityFinding{
		{ID: "OSV-1", Component: "module-b", Severity: release.SeverityMedium, InShippedClosure: true, Resolution: release.ResolutionUnresolved},
		{ID: "OSV-1", Component: "module-a", Severity: release.SeverityHigh, InShippedClosure: true, Resolution: release.ResolutionUnresolved},
		{ID: "OSV-1", Component: "module-b", Severity: release.SeverityCritical, RuntimeReachable: true, Resolution: release.ResolutionUnresolved},
	}
	got := mergeSecurityFindings(input)
	if len(got) != 2 || got[0].Component != "module-a" || got[1].Component != "module-b" || got[1].Severity != release.SeverityCritical || !got[1].InShippedClosure || !got[1].RuntimeReachable {
		t.Fatalf("finding merge lost exact component or strongest disposition: %#v", got)
	}
}
