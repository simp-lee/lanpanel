package release

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreation       `json:"creationInfo"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}
type SPDXCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}
type SPDXPackage struct {
	Name             string         `json:"name"`
	SPDXID           string         `json:"SPDXID"`
	VersionInfo      string         `json:"versionInfo"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	LicenseConcluded string         `json:"licenseConcluded"`
	LicenseDeclared  string         `json:"licenseDeclared"`
	CopyrightText    string         `json:"copyrightText"`
	Checksums        []SPDXChecksum `json:"checksums,omitempty"`
}
type (
	SPDXRelationship struct {
		SPDXElementID      string `json:"spdxElementId"`
		RelationshipType   string `json:"relationshipType"`
		RelatedSPDXElement string `json:"relatedSpdxElement"`
	}
	SPDXChecksum struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	}
)

func ValidateSPDX(data []byte, candidateDigest string) error {
	if !ValidDigest(candidateDigest) {
		return fmt.Errorf("SBOM candidate digest is invalid")
	}
	var document SPDXDocument
	if err := DecodeCanonical(data, &document); err != nil {
		return err
	}
	if document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" || document.SPDXID != "SPDXRef-DOCUMENT" || document.Name == "" || document.DocumentNamespace == "" || len(document.CreationInfo.Creators) == 0 || len(document.Packages) == 0 || len(document.Relationships) != len(document.Packages) {
		return fmt.Errorf("SBOM document authority is invalid")
	}
	created, err := time.Parse(time.RFC3339, document.CreationInfo.Created)
	if err != nil || !sameUTCSecond(created) {
		return fmt.Errorf("SBOM creation time is invalid")
	}
	previous := ""
	bound := false
	for _, pkg := range document.Packages {
		if pkg.Name == "" || pkg.SPDXID == "" || pkg.VersionInfo == "" || pkg.DownloadLocation == "" || pkg.LicenseConcluded == "" || pkg.LicenseDeclared == "" || pkg.CopyrightText == "" || previous != "" && previous >= pkg.SPDXID {
			return fmt.Errorf("SBOM package inventory is invalid")
		}
		if pkg.Name == "lanpanel" && pkg.SPDXID == "SPDXRef-Package-lanpanel" {
			if bound {
				return fmt.Errorf("SBOM duplicates candidate package")
			}
			for _, checksum := range pkg.Checksums {
				if checksum.Algorithm == "SHA256" && checksum.ChecksumValue == candidateDigest {
					bound = true
				}
			}
		}
		previous = pkg.SPDXID
	}
	if !bound {
		return fmt.Errorf("SBOM does not bind candidate binary")
	}
	for index, relationship := range document.Relationships {
		if relationship.SPDXElementID != "SPDXRef-DOCUMENT" || relationship.RelationshipType != "DESCRIBES" || relationship.RelatedSPDXElement != document.Packages[index].SPDXID {
			return fmt.Errorf("SBOM relationship inventory is invalid")
		}
	}
	return nil
}

func GenerateSPDX(binaryPath string, created time.Time) ([]byte, error) {
	if binaryPath == "" || !sameUTCSecond(created) {
		return nil, fmt.Errorf("SBOM binary path or creation time invalid")
	}
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return nil, err
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(binary)
	binaryDigest := hex.EncodeToString(sum[:])
	mainVersion := info.Main.Version
	if mainVersion == "" {
		mainVersion = "(devel)"
	}
	packages := []SPDXPackage{{Name: "lanpanel", SPDXID: "SPDXRef-Package-lanpanel", VersionInfo: mainVersion, DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Checksums: []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: binaryDigest}}}}
	for _, module := range info.Deps {
		name, version := module.Path, module.Version
		if module.Replace != nil {
			name, version = module.Replace.Path, module.Replace.Version
		}
		if version == "" {
			version = "(devel)"
		}
		id := strings.NewReplacer("/", "-", ".", "-", "_", "-", "@", "-").Replace(name)
		packages = append(packages, SPDXPackage{Name: name, SPDXID: "SPDXRef-Package-" + id, VersionInfo: version, DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"})
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].SPDXID < packages[j].SPDXID })
	relationships := make([]SPDXRelationship, len(packages))
	for index, pkg := range packages {
		relationships[index] = SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkg.SPDXID}
	}
	document := SPDXDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "lanpanel-" + binaryDigest[:16], DocumentNamespace: "https://lanpanel.invalid/spdx/" + binaryDigest, CreationInfo: SPDXCreation{Created: created.Format(time.RFC3339), Creators: []string{"Tool: lanpanel-release-tooling"}}, Packages: packages, Relationships: relationships}
	return json.Marshal(document)
}
