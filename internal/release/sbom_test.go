package release

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestValidateSPDXRejectsUnrelatedCandidate(t *testing.T) {
	data, _ := MarshalCanonical(SPDXDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "test", DocumentNamespace: "https://lanpanel.invalid/test", CreationInfo: SPDXCreation{Created: time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339), Creators: []string{"Tool: test"}}, Packages: []SPDXPackage{{Name: "lanpanel", SPDXID: "SPDXRef-Package-lanpanel", VersionInfo: "v1", DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Checksums: []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: strings.Repeat("a", 64)}}}}, Relationships: []SPDXRelationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package-lanpanel"}}})
	if ValidateSPDX(data, strings.Repeat("b", 64)) == nil {
		t.Fatal("unrelated SBOM candidate accepted")
	}
}

func TestReleaseSPDXRequiresExactPackageAndRelationshipSets(t *testing.T) {
	data, candidate, candidateDigest, dependency, profile := releaseSBOMValidationFixture(t)
	if err := ValidateReleaseSPDX(data, candidate, candidateDigest, "v1.0.0", dependency, profile); err != nil {
		t.Fatalf("generated release SBOM failed exact validation: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*SPDXDocument)
	}{
		{
			name: "extra_package",
			mutate: func(document *SPDXDocument) {
				document.Packages = append(document.Packages, spdxPackage("forged", spdxID("forged"), "v1.0.0", "NOASSERTION"))
				sort.Slice(document.Packages, func(i, j int) bool { return document.Packages[i].SPDXID < document.Packages[j].SPDXID })
				describeSPDXPackages(document)
			},
		},
		{
			name: "extra_relationship",
			mutate: func(document *SPDXDocument) {
				document.Relationships = append(document.Relationships, SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: spdxID("forged")})
			},
		},
		{
			name: "duplicate_relationship",
			mutate: func(document *SPDXDocument) {
				document.Relationships[1].RelatedSPDXElement = document.Relationships[0].RelatedSPDXElement
			},
		},
		{
			name: "missing_package",
			mutate: func(document *SPDXDocument) {
				missingID := spdxID("os-" + profile.Packages[0].Name + "-" + profile.Packages[0].Architecture)
				for index, pkg := range document.Packages {
					if pkg.SPDXID == missingID {
						document.Packages = append(document.Packages[:index], document.Packages[index+1:]...)
						break
					}
				}
				describeSPDXPackages(document)
			},
		},
		{
			name: "missing_relationship",
			mutate: func(document *SPDXDocument) {
				document.Relationships = document.Relationships[:len(document.Relationships)-1]
			},
		},
		{
			name: "duplicate_package_id",
			mutate: func(document *SPDXDocument) {
				document.Packages = append(document.Packages, document.Packages[0])
				sort.Slice(document.Packages, func(i, j int) bool { return document.Packages[i].SPDXID < document.Packages[j].SPDXID })
				describeSPDXPackages(document)
			},
		},
		{
			name: "changed_package_field",
			mutate: func(document *SPDXDocument) {
				id := spdxID("os-" + profile.Packages[0].Name + "-" + profile.Packages[0].Architecture)
				for index := range document.Packages {
					if document.Packages[index].SPDXID == id {
						document.Packages[index].Name = "forged"
						break
					}
				}
			},
		},
		{
			name: "changed_native_checksum",
			mutate: func(document *SPDXDocument) {
				id := spdxID("native-headscale")
				for index := range document.Packages {
					if document.Packages[index].SPDXID == id {
						document.Packages[index].Checksums[0].ChecksumValue = strings.Repeat("0", 64)
						break
					}
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateSPDX(t, data, test.mutate)
			if ValidateReleaseSPDX(mutated, candidate, candidateDigest, "v1.0.0", dependency, profile) == nil {
				t.Fatal("non-exact release SBOM was accepted")
			}
		})
	}
}

func TestReleaseSPDXResolvesGoModuleReplacement(t *testing.T) {
	binaryPath := replacementCandidateFixture(t)
	candidate, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	profile := testProfile()
	_, dependency, _, _ := dependencyAuthorityFixture(t, profile)
	data, err := GenerateReleaseSPDX(binaryPath, dependency, profile, "v1.0.0", time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReleaseSPDX(data, candidate, DigestBytes(candidate), "v1.0.0", dependency, profile); err != nil {
		t.Fatalf("release SBOM rejected resolved Go module replacement: %v", err)
	}
	var document SPDXDocument
	if err := DecodeCanonical(data, &document); err != nil {
		t.Fatal(err)
	}
	foundReplacement := false
	for _, pkg := range document.Packages {
		if pkg.Name == "example.test/original" {
			t.Fatal("release SBOM retained replaced Go module identity")
		}
		if pkg.Name == "./replacement" && pkg.SPDXID == spdxID("./replacement") && pkg.VersionInfo == "(devel)" {
			foundReplacement = true
		}
	}
	if !foundReplacement {
		t.Fatal("release SBOM omitted resolved Go module replacement")
	}
}

func TestGenerateSPDXBindsExactGoBinaryAndModules(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := GenerateSPDX(path, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var document SPDXDocument
	if json.Unmarshal(raw, &document) != nil || document.SPDXVersion != "SPDX-2.3" || len(document.Packages) == 0 {
		t.Fatalf("SBOM=%s", raw)
	}
	found := false
	for _, pkg := range document.Packages {
		if pkg.Name == "lanpanel" && len(pkg.Checksums) == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("SBOM omits exact LanPanel binary checksum")
	}
}

func replacementCandidateFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	replacement := filepath.Join(root, "replacement")
	if err := os.MkdirAll(replacement, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(root, "go.mod"):                "module candidate.test/main\n\ngo 1.23\n\nrequire example.test/original v0.0.0\n\nreplace example.test/original => ./replacement\n",
		filepath.Join(root, "main.go"):               "package main\n\nimport replacement \"example.test/original\"\n\nfunc main() { replacement.Use() }\n",
		filepath.Join(replacement, "go.mod"):         "module example.test/replacement\n\ngo 1.23\n",
		filepath.Join(replacement, "replacement.go"): "package replacement\n\nfunc Use() {}\n",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	binaryPath := filepath.Join(root, "candidate")
	command := exec.Command("go", "build", "-o", binaryPath, ".")
	command.Dir = root
	command.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build replacement candidate: %v\n%s", err, output)
	}
	return binaryPath
}

func releaseSBOMValidationFixture(t *testing.T) ([]byte, []byte, string, QualificationDependencyAuthority, OSProfile) {
	t.Helper()
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	profile := testProfile()
	_, dependency, _, _ := dependencyAuthorityFixture(t, profile)
	data, err := GenerateReleaseSPDX(binaryPath, dependency, profile, "v1.0.0", time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return data, candidate, DigestBytes(candidate), dependency, profile
}

func mutateSPDX(t *testing.T, data []byte, mutate func(*SPDXDocument)) []byte {
	t.Helper()
	var document SPDXDocument
	if err := DecodeCanonical(data, &document); err != nil {
		t.Fatal(err)
	}
	mutate(&document)
	mutated, err := MarshalCanonical(document)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}

func describeSPDXPackages(document *SPDXDocument) {
	document.Relationships = make([]SPDXRelationship, len(document.Packages))
	for index, pkg := range document.Packages {
		document.Relationships[index] = SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkg.SPDXID}
	}
}
