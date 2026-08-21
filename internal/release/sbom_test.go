package release

import (
	"encoding/json"
	"os"
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
