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
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Checksums        []SPDXChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
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
	SPDXExternalRef struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
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
		candidatePackage := pkg.Name == "lanpanel" && pkg.SPDXID == "SPDXRef-Package-lanpanel"
		if candidatePackage {
			if bound || len(pkg.ExternalRefs) != 0 {
				return fmt.Errorf("SBOM duplicates candidate package or gives it an external package identity")
			}
			for _, checksum := range pkg.Checksums {
				if checksum.Algorithm == "SHA256" && checksum.ChecksumValue == candidateDigest {
					bound = true
				}
			}
		} else if len(pkg.ExternalRefs) != 1 || !validSPDXPURL(pkg.ExternalRefs[0]) {
			return fmt.Errorf("SBOM component lacks one scanner-compatible package URL")
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
		native = append(native, spdxOSPackage(tuple, profile.Family, profileRepositorySource(profile, tuple)))
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
	expected, err := expectedReleaseSPDXPackages(candidate, candidateDigest, releaseTag, dependency, profile)
	if err != nil {
		return err
	}
	if len(document.Packages) != len(expected) {
		return fmt.Errorf("release SBOM package inventory differs from the exact expected set")
	}
	observedIDs := make(map[string]struct{}, len(document.Packages))
	for _, observed := range document.Packages {
		if _, duplicate := observedIDs[observed.SPDXID]; duplicate {
			return fmt.Errorf("release SBOM package ID %q is duplicated", observed.SPDXID)
		}
		observedIDs[observed.SPDXID] = struct{}{}
		expectedPackage, present := expected[observed.SPDXID]
		if !present {
			return fmt.Errorf("release SBOM contains unexpected package %q", observed.SPDXID)
		}
		if !spdxPackagesEqual(observed, expectedPackage) {
			return fmt.Errorf("release SBOM package %q differs from exact candidate evidence", observed.SPDXID)
		}
	}
	for id := range expected {
		if _, present := observedIDs[id]; !present {
			return fmt.Errorf("release SBOM omits expected package %q", id)
		}
	}

	if len(document.Relationships) != len(expected) {
		return fmt.Errorf("release SBOM relationship inventory differs from the exact expected set")
	}
	described := make(map[string]struct{}, len(document.Relationships))
	for _, relationship := range document.Relationships {
		if relationship.SPDXElementID != "SPDXRef-DOCUMENT" || relationship.RelationshipType != "DESCRIBES" {
			return fmt.Errorf("release SBOM contains an unexpected relationship")
		}
		if _, present := expected[relationship.RelatedSPDXElement]; !present {
			return fmt.Errorf("release SBOM describes unexpected package %q", relationship.RelatedSPDXElement)
		}
		if _, duplicate := described[relationship.RelatedSPDXElement]; duplicate {
			return fmt.Errorf("release SBOM duplicates relationship for package %q", relationship.RelatedSPDXElement)
		}
		described[relationship.RelatedSPDXElement] = struct{}{}
	}
	for id := range expected {
		if _, present := described[id]; !present {
			return fmt.Errorf("release SBOM omits DOCUMENT DESCRIBES relationship for package %q", id)
		}
	}
	return nil
}

func expectedReleaseSPDXPackages(candidate []byte, candidateDigest, releaseTag string, dependency QualificationDependencyAuthority, profile OSProfile) (map[string]SPDXPackage, error) {
	if !releaseTagPattern.MatchString(releaseTag) {
		return nil, fmt.Errorf("release SBOM tag is invalid")
	}
	build, err := buildinfo.Read(bytes.NewReader(candidate))
	if err != nil {
		return nil, fmt.Errorf("read exact candidate Go module closure: %w", err)
	}
	packages := []SPDXPackage{spdxCandidatePackage(releaseTag, candidateDigest)}
	for _, module := range build.Deps {
		name, version := module.Path, module.Version
		if module.Replace != nil {
			name, version = module.Replace.Path, module.Replace.Version
		}
		if version == "" {
			version = "(devel)"
		}
		packages = append(packages, spdxGoPackage(name, version))
	}
	packages = append(packages,
		spdxNativePackage("headscale", dependency.Headscale.Version, dependency.Headscale.ArtifactIdentity, dependency.Headscale.Archive.Digest),
		spdxNativePackage("lego", dependency.LegoVersion, dependency.LegoArtifactIdentity, dependency.LegoArchive.Digest),
		spdxNativePackage("tailscale-client", dependency.Tailscale.Version, dependency.Tailscale.ArtifactIdentity, dependency.Tailscale.Archive.Digest),
	)
	for _, tuple := range profile.Packages {
		packages = append(packages, spdxOSPackage(tuple, profile.Family, profileRepositorySource(profile, tuple)))
	}
	expected := make(map[string]SPDXPackage, len(packages))
	for _, pkg := range packages {
		if _, duplicate := expected[pkg.SPDXID]; duplicate {
			return nil, fmt.Errorf("release SBOM expected package ID %q collides", pkg.SPDXID)
		}
		expected[pkg.SPDXID] = pkg
	}
	return expected, nil
}

func spdxPackagesEqual(left, right SPDXPackage) bool {
	if left.Name != right.Name || left.SPDXID != right.SPDXID || left.VersionInfo != right.VersionInfo || left.DownloadLocation != right.DownloadLocation || left.FilesAnalyzed != right.FilesAnalyzed || left.LicenseConcluded != right.LicenseConcluded || left.LicenseDeclared != right.LicenseDeclared || left.CopyrightText != right.CopyrightText || len(left.Checksums) != len(right.Checksums) || len(left.ExternalRefs) != len(right.ExternalRefs) {
		return false
	}
	for index := range left.Checksums {
		if left.Checksums[index] != right.Checksums[index] {
			return false
		}
	}
	for index := range left.ExternalRefs {
		if left.ExternalRefs[index] != right.ExternalRefs[index] {
			return false
		}
	}
	return true
}

func spdxPackage(name, id, version, location string) SPDXPackage {
	return SPDXPackage{Name: name, SPDXID: id, VersionInfo: version, DownloadLocation: location, FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"}
}

func spdxCandidatePackage(version, digest string) SPDXPackage {
	pkg := spdxPackage("lanpanel", "SPDXRef-Package-lanpanel", version, "NOASSERTION")
	pkg.Checksums = []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: digest}}
	return pkg
}

func spdxGoPackage(name, version string) SPDXPackage {
	pkg := spdxPackage(name, spdxID(name), version, "NOASSERTION")
	pkg.ExternalRefs = []SPDXExternalRef{spdxPURL("pkg:golang/" + name + "@" + version)}
	return pkg
}

func spdxNativePackage(name, version, location, digest string) SPDXPackage {
	pkg := spdxPackage(name, spdxID("native-"+name), version, location)
	pkg.Checksums = []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: digest}}
	module := map[string]string{"headscale": "github.com/juanfont/headscale", "lego": "github.com/go-acme/lego/v4", "tailscale-client": "tailscale.com"}[name]
	pkg.ExternalRefs = []SPDXExternalRef{spdxPURL("pkg:golang/" + module + "@v" + strings.TrimPrefix(version, "v"))}
	return pkg
}

func profileRepositorySource(profile OSProfile, tuple PackageTuple) string {
	for _, repository := range profile.Repositories {
		if tuple.RepositoryID == repository.ID {
			return repository.URI
		}
	}
	if len(profile.Repositories) == 1 {
		return profile.Repositories[0].URI
	}
	return ""
}

func spdxOSPackage(tuple PackageTuple, family, repositorySource string) SPDXPackage {
	pkg := spdxPackage(tuple.Name, spdxID("os-"+tuple.Name+"-"+tuple.Architecture), tuple.Version, repositorySource)
	pkg.ExternalRefs = []SPDXExternalRef{spdxPURL("pkg:deb/" + family + "/" + tuple.Name + "@" + tuple.Version)}
	return pkg
}

func spdxPURL(locator string) SPDXExternalRef {
	return SPDXExternalRef{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: locator}
}

func validSPDXPURL(reference SPDXExternalRef) bool {
	if reference.ReferenceCategory != "PACKAGE-MANAGER" || reference.ReferenceType != "purl" || strings.ContainsAny(reference.ReferenceLocator, "\x00\r\n\t ") {
		return false
	}
	value := strings.TrimPrefix(reference.ReferenceLocator, "pkg:golang/")
	if value == reference.ReferenceLocator {
		value = strings.TrimPrefix(reference.ReferenceLocator, "pkg:deb/debian/")
		if value == reference.ReferenceLocator {
			value = strings.TrimPrefix(reference.ReferenceLocator, "pkg:deb/ubuntu/")
		}
	}
	separator := strings.LastIndexByte(value, '@')
	return value != reference.ReferenceLocator && separator > 0 && separator < len(value)-1
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
	packages := []SPDXPackage{spdxCandidatePackage(mainVersion, binaryDigest)}
	for _, module := range info.Deps {
		name, version := module.Path, module.Version
		if module.Replace != nil {
			name, version = module.Replace.Path, module.Replace.Version
		}
		if version == "" {
			version = "(devel)"
		}
		packages = append(packages, spdxGoPackage(name, version))
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].SPDXID < packages[j].SPDXID })
	relationships := make([]SPDXRelationship, len(packages))
	for index, pkg := range packages {
		relationships[index] = SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkg.SPDXID}
	}
	document := SPDXDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "lanpanel-" + binaryDigest[:16], DocumentNamespace: "https://lanpanel.invalid/spdx/" + binaryDigest, CreationInfo: SPDXCreation{Created: created.Format(time.RFC3339), Creators: []string{"Tool: lanpanel-release-tooling"}}, Packages: packages, Relationships: relationships}
	return json.Marshal(document)
}
