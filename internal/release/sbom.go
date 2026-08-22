package release

import (
	"bytes"
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

func GenerateReleaseSPDX(binaryPath string, dependency QualificationDependencyAuthority, profile OSProfile, releaseTag string, created time.Time) ([]byte, error) {
	base, err := GenerateSPDX(binaryPath, created)
	if err != nil {
		return nil, err
	}
	var document SPDXDocument
	if err := DecodeCanonical(base, &document); err != nil {
		return nil, err
	}
	if !releaseTagPattern.MatchString(releaseTag) {
		return nil, fmt.Errorf("release SBOM tag is invalid")
	}
	for index := range document.Packages {
		if document.Packages[index].SPDXID == "SPDXRef-Package-lanpanel" {
			document.Packages[index].VersionInfo = releaseTag
		}
	}
	if validateHeadscaleAuthority(dependency.Headscale) != nil || validateClientArtifactAuthority(dependency.Tailscale, "tailscale", "/usr/lib/lanpanel/dependencies/tailscale") != nil || validateOSProfile(profile) != nil {
		return nil, fmt.Errorf("release SBOM dependency or OS profile is invalid")
	}
	native := []SPDXPackage{
		spdxNativePackage("headscale", dependency.Headscale.Version, dependency.Headscale.ArtifactIdentity, dependency.Headscale.Archive.Digest),
		spdxNativePackage("lego", dependency.LegoVersion, dependency.LegoArtifactIdentity, dependency.LegoArchive.Digest),
		spdxNativePackage("tailscale-client", dependency.Tailscale.Version, dependency.Tailscale.ArtifactIdentity, dependency.Tailscale.Archive.Digest),
	}
	for _, tuple := range profile.Packages {
		id := spdxID("os-" + tuple.Name + "-" + tuple.Architecture)
		native = append(native, SPDXPackage{Name: tuple.Name, SPDXID: id, VersionInfo: tuple.Version, DownloadLocation: profile.RepositorySource, FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"})
	}
	document.Packages = append(document.Packages, native...)
	sort.Slice(document.Packages, func(i, j int) bool { return document.Packages[i].SPDXID < document.Packages[j].SPDXID })
	for index := 1; index < len(document.Packages); index++ {
		if document.Packages[index-1].SPDXID == document.Packages[index].SPDXID {
			return nil, fmt.Errorf("release SBOM package identity collides")
		}
	}
	document.Relationships = make([]SPDXRelationship, len(document.Packages))
	for index, pkg := range document.Packages {
		document.Relationships[index] = SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkg.SPDXID}
	}
	return json.Marshal(document)
}

func ValidateReleaseSPDX(data, candidate []byte, candidateDigest, releaseTag string, dependency QualificationDependencyAuthority, profile OSProfile) error {
	if DigestBytes(candidate) != candidateDigest {
		return fmt.Errorf("release SBOM candidate bytes differ")
	}
	if err := ValidateSPDX(data, candidateDigest); err != nil {
		return err
	}
	var document SPDXDocument
	if err := DecodeCanonical(data, &document); err != nil {
		return err
	}
	byID := make(map[string]SPDXPackage, len(document.Packages))
	for _, pkg := range document.Packages {
		byID[pkg.SPDXID] = pkg
	}
	lanpanelPackage, present := byID["SPDXRef-Package-lanpanel"]
	if !present || lanpanelPackage.VersionInfo != releaseTag || !releaseTagPattern.MatchString(releaseTag) {
		return fmt.Errorf("release SBOM LanPanel package version differs from release tag")
	}
	build, err := buildinfo.Read(bytes.NewReader(candidate))
	if err != nil {
		return fmt.Errorf("read exact candidate Go module closure: %w", err)
	}
	for _, module := range build.Deps {
		name, version := module.Path, module.Version
		if module.Replace != nil {
			name, version = module.Replace.Path, module.Replace.Version
		}
		if version == "" {
			version = "(devel)"
		}
		observed, present := byID[spdxID(name)]
		if !present || observed.Name != name || observed.VersionInfo != version {
			return fmt.Errorf("release SBOM omits exact Go module %q", name)
		}
	}
	expected := []SPDXPackage{
		spdxNativePackage("headscale", dependency.Headscale.Version, dependency.Headscale.ArtifactIdentity, dependency.Headscale.Archive.Digest),
		spdxNativePackage("lego", dependency.LegoVersion, dependency.LegoArtifactIdentity, dependency.LegoArchive.Digest),
		spdxNativePackage("tailscale-client", dependency.Tailscale.Version, dependency.Tailscale.ArtifactIdentity, dependency.Tailscale.Archive.Digest),
	}
	for _, pkg := range expected {
		observed, present := byID[pkg.SPDXID]
		if !present || observed.Name != pkg.Name || observed.VersionInfo != pkg.VersionInfo || observed.DownloadLocation != pkg.DownloadLocation || len(observed.Checksums) != 1 || observed.Checksums[0] != pkg.Checksums[0] {
			return fmt.Errorf("release SBOM omits exact native dependency %q", pkg.Name)
		}
	}
	for _, tuple := range profile.Packages {
		observed, present := byID[spdxID("os-"+tuple.Name+"-"+tuple.Architecture)]
		if !present || observed.Name != tuple.Name || observed.VersionInfo != tuple.Version || observed.DownloadLocation != profile.RepositorySource {
			return fmt.Errorf("release SBOM omits exact OS package %q", tuple.Name)
		}
	}
	return nil
}

func spdxNativePackage(name, version, location, digest string) SPDXPackage {
	return SPDXPackage{Name: name, SPDXID: spdxID("native-" + name), VersionInfo: version, DownloadLocation: location, FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Checksums: []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: digest}}}
}

func spdxID(value string) string {
	return "SPDXRef-Package-" + strings.NewReplacer("/", "-", ".", "-", "_", "-", "@", "-", "+", "-", ":", "-").Replace(value)
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
		packages = append(packages, SPDXPackage{Name: name, SPDXID: spdxID(name), VersionInfo: version, DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"})
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].SPDXID < packages[j].SPDXID })
	relationships := make([]SPDXRelationship, len(packages))
	for index, pkg := range packages {
		relationships[index] = SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkg.SPDXID}
	}
	document := SPDXDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "lanpanel-" + binaryDigest[:16], DocumentNamespace: "https://lanpanel.invalid/spdx/" + binaryDigest, CreationInfo: SPDXCreation{Created: created.Format(time.RFC3339), Creators: []string{"Tool: lanpanel-release-tooling"}}, Packages: packages, Relationships: relationships}
	return json.Marshal(document)
}
