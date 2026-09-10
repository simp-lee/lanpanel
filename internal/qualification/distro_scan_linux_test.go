//go:build linux

package qualification

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"lanpanel/internal/packages"
	"lanpanel/internal/release"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeTestOSVArchive(t *testing.T, root, ecosystem string, records map[string]string) {
	t.Helper()
	path := filepath.Join(root, "osv-scanner", ecosystem, "all.zip")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range records {
		member, err := writer.Create(name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositorySnapshotsBindEveryExactRepository(t *testing.T) {
	valid := RepositorySnapshotFiles{Repositories: []RepositorySnapshot{
		{ID: "ubuntu-base", Keyring: "/protected/base.gpg", InRelease: "/protected/base.inrelease", Indexes: []RepositoryIndexFile{{ReleasePath: "main/binary-amd64/Packages", Path: "/protected/base.packages"}}},
		{ID: "ubuntu-security", Keyring: "/protected/security.gpg", InRelease: "/protected/security.inrelease", Indexes: []RepositoryIndexFile{{ReleasePath: "main/binary-amd64/Packages", Path: "/protected/security.packages"}}},
	}}
	if err := validateRepositorySnapshotFiles(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RepositorySnapshotFiles){
		func(value *RepositorySnapshotFiles) { value.Repositories[1].ID = value.Repositories[0].ID },
		func(value *RepositorySnapshotFiles) {
			value.Repositories[1], value.Repositories[0] = value.Repositories[0], value.Repositories[1]
		},
		func(value *RepositorySnapshotFiles) { value.Repositories[0].Indexes[0].ReleasePath = "../bad" },
	} {
		changed := valid
		changed.Repositories = append([]RepositorySnapshot(nil), valid.Repositories...)
		changed.Repositories[0].Indexes = append([]RepositoryIndexFile(nil), valid.Repositories[0].Indexes...)
		changed.Repositories[1].Indexes = append([]RepositoryIndexFile(nil), valid.Repositories[1].Indexes...)
		mutate(&changed)
		if err := validateRepositorySnapshotFiles(changed); err == nil {
			t.Fatal("invalid multi-repository snapshot authority was accepted")
		}
	}
}

func TestDistroFeedSelectsAffectedEntriesForExactRelease(t *testing.T) {
	data := []byte(`{"id":"OSV-mixed","modified":"2025-01-01T00:00:00Z","affected":[{"package":{"name":"apache2","ecosystem":"Debian:12"},"versions":["2.4.62-1"]},{"package":{"name":"apache2","ecosystem":"Debian:13"},"versions":["2.4.61-1"]}]}`)
	filtered, err := filterDistroAdvisory(data, "Debian", "13")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(filtered, []byte("Debian:12")) || bytes.Contains(filtered, []byte("2.4.62-1")) || !bytes.Contains(filtered, []byte("2.4.61-1")) {
		t.Fatalf("wrong affected ranges retained: %s", filtered)
	}
	if value, err := filterDistroAdvisory(data, "Debian", "11"); err != nil || value != nil {
		t.Fatalf("unrelated release retained: %s %v", value, err)
	}
	for _, ecosystem := range []string{"Debian", "Debian:12:13", "Debian:stable", "Ubuntu:Pro"} {
		data := []byte(`{"id":"OSV-ambiguous","affected":[{"package":{"name":"apache2","ecosystem":"` + ecosystem + `"}}]}`)
		family := "Debian"
		if ecosystem == "Ubuntu:Pro" {
			family = "Ubuntu"
		}
		if _, err := filterDistroAdvisory(data, family, "13"); err == nil {
			t.Fatalf("ambiguous release accepted: %s", ecosystem)
		}
	}
}

func TestNativeOSVScansMappedSourceIdentitiesAndExactRelease(t *testing.T) {
	scanner, err := exec.LookPath("osv-scanner")
	if err != nil {
		t.Skip("pinned native OSV Scanner is unavailable")
	}
	version, err := exec.Command(scanner, "--version").Output()
	if err != nil || !containsExactLine(version, "osv-scanner version: "+PinnedOSVScannerVersion) {
		t.Fatalf("native test requires pinned OSV Scanner %s: %v %s", PinnedOSVScannerVersion, err, version)
	}
	for _, test := range []struct{ family, version, scoped, other string }{
		{"debian", "13", "Debian:13", "Debian:12"},
		{"ubuntu", "22.04", "Ubuntu:Pro:22.04:LTS", "Ubuntu:24.04:LTS"},
	} {
		t.Run(test.family, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			ecosystem := distroEcosystem(test.family)
			profile := release.OSProfile{Family: test.family, Release: test.version}
			feed := filepath.Join(root, "fixed-feed")
			writeTestOSVArchive(t, feed, ecosystem, map[string]string{
				"source-match":  `{"id":"OSV-source-match","modified":"2025-01-01T00:00:00Z","affected":[{"package":{"name":"apache2","ecosystem":"` + test.scoped + `"},"versions":["2.4.62-1"]}]}`,
				"mixed-release": `{"id":"OSV-mixed-release","modified":"2025-01-01T00:00:00Z","affected":[{"package":{"name":"apache2","ecosystem":"` + test.other + `"},"versions":["2.4.62-1"]},{"package":{"name":"other-source","ecosystem":"` + test.scoped + `"},"versions":["2.4.62-1"]}]}`,
			})
			writeTestOSVArchive(t, feed, "Go", map[string]string{"go": `{"id":"GO-fixture","modified":"2025-01-01T00:00:00Z","affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},"versions":["v0.0.0"]}]}`})
			ref := func(purl string) []release.SPDXExternalRef {
				return []release.SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: purl}}
			}
			document := release.SPDXDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "fixture", DocumentNamespace: "https://lanpanel.invalid/fixture", CreationInfo: release.SPDXCreation{Created: "2025-01-01T00:00:00Z", Creators: []string{"Tool: fixture"}}, Packages: []release.SPDXPackage{
				{Name: "apache2-utils", SPDXID: "SPDXRef-binary1", VersionInfo: "2.4.62-1+b1", DownloadLocation: "NOASSERTION", ExternalRefs: ref("pkg:deb/" + test.family + "/apache2-utils@2.4.62-1+b1")},
				{Name: "apache2-bin", SPDXID: "SPDXRef-binary2", VersionInfo: "2.4.62-1+b1", DownloadLocation: "NOASSERTION", ExternalRefs: ref("pkg:deb/" + test.family + "/apache2-bin@2.4.62-1+b1")},
				{Name: "golang.org/x/net", SPDXID: "SPDXRef-go", VersionInfo: "v0.58.0", DownloadLocation: "NOASSERTION", ExternalRefs: ref("pkg:golang/golang.org/x/net@v0.58.0")},
			}}
			original, err := release.MarshalCanonical(document)
			if err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), original...)
			mappings := []packages.SourcePackageMapping{}
			for _, name := range []string{"apache2-utils", "apache2-bin"} {
				mappings = append(mappings, packages.SourcePackageMapping{Binary: packages.Package{Name: name, Version: "2.4.62-1+b1", Architecture: "amd64"}, SourceName: "apache2", SourceVersion: "2.4.62-1"})
			}
			mappedPath := filepath.Join(root, "mapped.spdx.json")
			if err := writeSourceMappedSBOM(original, mappings, test.family, mappedPath); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, original) {
				t.Fatal("public SBOM bytes changed")
			}
			if err := writeSourceMappedSBOM(original, mappings[:1], test.family, filepath.Join(root, "missing.spdx.json")); err == nil {
				t.Fatal("incomplete source mapping accepted")
			}
			config := filepath.Join(root, "osv-scanner.toml")
			if err := os.WriteFile(config, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, full := range []bool{true, false} {
				path, cache := mappedPath, filepath.Join(root, "full-cache")
				if !full {
					path, cache = filepath.Join(root, "distro.spdx.json"), filepath.Join(root, "distro-cache")
					if _, err := writeDistroClosureSBOM(mappedPath, path, ecosystem); err != nil {
						t.Fatal(err)
					}
				}
				if err := writeReleaseScopedOSVCache(feed, cache, profile, full); err != nil {
					t.Fatal(err)
				}
				expected, err := expectedOSVPackageInventory(path)
				if err != nil {
					t.Fatal(err)
				}
				want := 1
				if full {
					want++
				}
				if len(expected) != want {
					t.Fatalf("shared source was not deduplicated: %+v", expected)
				}
				output, err := executeOSVScan(systemSecurityCommandExecutor{}, scanner, cache, path, config, []string{"HOME=" + root, "XDG_CACHE_HOME=" + root, "GOTELEMETRY=off", "PATH=", "LANG=C"}, root)
				if err != nil {
					t.Fatalf("native scan failed: %v", err)
				}
				findings, err := decodeOSVOutput(output.Stdout, path, expected, "")
				if err != nil || len(findings) != 1 || findings[0].ID != "OSV-source-match" || findings[0].Component != "apache2" || !findings[0].RuntimeReachable || findings[0].Severity != release.SeverityHigh {
					t.Fatalf("incorrect source/release coverage: %+v %v\n%s", findings, err, output.Stdout)
				}
			}
			var unchanged release.SPDXDocument
			if err := json.Unmarshal(original, &unchanged); err != nil || unchanged.Packages[0].Name != "apache2-utils" {
				t.Fatal("public binary identity was replaced")
			}
		})
	}
}
