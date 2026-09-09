//go:build linux

package qualification

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/packages"
	"lanpanel/internal/release"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type RepositorySnapshotFiles struct {
	Keyring   string                `json:"keyring"`
	InRelease string                `json:"in_release"`
	Indexes   []RepositoryIndexFile `json:"indexes"`
}

type RepositoryIndexFile struct {
	ReleasePath string `json:"release_path"`
	Path        string `json:"path"`
}

func validateRepositorySnapshotFiles(snapshot RepositorySnapshotFiles) error {
	if !absoluteCleanPath(snapshot.Keyring) || !absoluteCleanPath(snapshot.InRelease) || len(snapshot.Indexes) == 0 || len(snapshot.Indexes) > 64 {
		return fmt.Errorf("protected repository snapshot locators are invalid")
	}
	for _, index := range snapshot.Indexes {
		if !absoluteCleanPath(index.Path) || !release.ValidRelativePath(index.ReleasePath) {
			return fmt.Errorf("protected Packages index locator is invalid")
		}
	}
	return nil
}

func loadRepositorySourceMapping(snapshot RepositorySnapshotFiles, template packages.Plan) ([]packages.SourcePackageMapping, error) {
	if err := validateRepositorySnapshotFiles(snapshot); err != nil {
		return nil, err
	}
	if len(template.Repositories) != 1 {
		return nil, fmt.Errorf("source mapping requires the exact qualified repository")
	}
	keyring, _, err := readProtectedFile(snapshot.Keyring, 4<<20, true)
	if err != nil {
		return nil, err
	}
	inRelease, _, err := readProtectedFile(snapshot.InRelease, 4<<20, true)
	if err != nil {
		return nil, err
	}
	indexes := make([]packages.RepositoryPackageIndex, 0, len(snapshot.Indexes))
	for _, index := range snapshot.Indexes {
		data, _, err := readProtectedFile(index.Path, 128<<20, true)
		if err != nil {
			return nil, err
		}
		indexes = append(indexes, packages.RepositoryPackageIndex{ReleasePath: index.ReleasePath, Data: data})
	}
	return packages.ResolveRepositoryPackageSources(template.Repositories[0], keyring, inRelease, indexes, template.Packages)
}

// Only the private scanner input is mapped. The qualified public SBOM and its
// binary checksums remain byte-for-byte unchanged in the release bundle.
func writeSourceMappedSBOM(original []byte, mappings []packages.SourcePackageMapping, family, path string) error {
	var document release.SPDXDocument
	if err := release.DecodeCanonical(original, &document); err != nil {
		return err
	}
	ecosystem := distroEcosystem(family)
	byBinary := map[string]packages.SourcePackageMapping{}
	for _, mapping := range mappings {
		key := mapping.Binary.Name + "\x00" + mapping.Binary.Version
		if _, duplicate := byBinary[key]; duplicate {
			return fmt.Errorf("binary source mapping duplicated")
		}
		byBinary[key] = mapping
	}
	mapped := make([]release.SPDXPackage, 0, len(document.Packages))
	seenBinary, seenSource := map[string]bool{}, map[string]bool{}
	for _, pkg := range document.Packages {
		if len(pkg.ExternalRefs) != 1 {
			mapped = append(mapped, pkg)
			continue
		}
		identity, err := osvIdentityFromPURL(pkg.ExternalRefs[0].ReferenceLocator)
		if err != nil {
			return err
		}
		if identity.Ecosystem != ecosystem {
			mapped = append(mapped, pkg)
			continue
		}
		key := identity.Name + "\x00" + identity.Version
		mapping, present := byBinary[key]
		if !present || seenBinary[key] {
			return fmt.Errorf("SBOM binary does not resolve to one signed source mapping")
		}
		seenBinary[key] = true
		source := osvPackageIdentity{Name: mapping.SourceName, Version: mapping.SourceVersion, Ecosystem: ecosystem}
		if seenSource[source.key()] {
			continue
		}
		seenSource[source.key()] = true
		pkg.Name, pkg.VersionInfo = source.Name, source.Version
		pkg.SPDXID = "SPDXRef-Source-" + release.DigestBytes([]byte(source.key()))
		pkg.Checksums = nil // Binary artifact hashes are not source-package hashes.
		pkg.ExternalRefs[0].ReferenceLocator = "pkg:deb/" + family + "/" + url.PathEscape(source.Name) + "@" + url.PathEscape(source.Version)
		mapped = append(mapped, pkg)
	}
	if len(seenBinary) != len(byBinary) || len(seenBinary) == 0 {
		return fmt.Errorf("signed source mapping does not cover the exact SBOM binary closure")
	}
	document.Name += "-source-mapped"
	document.DocumentNamespace += "/source-mapped"
	slices.SortFunc(mapped, func(a, b release.SPDXPackage) int { return strings.Compare(a.SPDXID, b.SPDXID) })
	document.Packages = mapped
	document.Relationships = make([]release.SPDXRelationship, len(mapped))
	for index, pkg := range mapped {
		document.Relationships[index] = release.SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkg.SPDXID}
	}
	encoded, err := release.MarshalCanonical(document)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o400)
}

func distroEcosystem(family string) string {
	if family == "ubuntu" {
		return "Ubuntu"
	}
	return "Debian"
}

// Pinned OSV Scanner ignores PURL distro qualifiers. Filter the fixed cache's
// affected entries, not whole advisories, so another release's ranges cannot
// match a source package in the selected profile. Original feed digests remain
// the authority and are checked again after scanning.
func writeReleaseScopedOSVCache(inputRoot, outputRoot string, profile release.OSProfile, includeGo bool) error {
	ecosystem := distroEcosystem(profile.Family)
	input, err := zip.OpenReader(filepath.Join(inputRoot, "osv-scanner", ecosystem, "all.zip"))
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	directory := filepath.Join(outputRoot, "osv-scanner", ecosystem)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(filepath.Join(directory, "all.zip"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()
	writer := zip.NewWriter(output)
	defer func() { _ = writer.Close() }()
	files := append([]*zip.File(nil), input.File...)
	slices.SortFunc(files, func(a, b *zip.File) int { return strings.Compare(a.Name, b.Name) })
	selected, previous := 0, ""
	for _, file := range files {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}
		if file.Name == previous || file.UncompressedSize64 > 16<<20 {
			return fmt.Errorf("fixed distro advisory archive member invalid")
		}
		previous = file.Name
		member, err := file.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(member, 16<<20+1))
		closeErr := member.Close()
		if readErr != nil || closeErr != nil || len(data) > 16<<20 {
			return fmt.Errorf("cannot read bounded distro advisory %s", file.Name)
		}
		filtered, err := filterDistroAdvisory(data, ecosystem, profile.Release)
		if err != nil {
			return err
		}
		if filtered == nil {
			continue
		}
		selected++
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: file.Name, Method: zip.Deflate})
		if err != nil {
			return err
		}
		if _, err := entry.Write(filtered); err != nil {
			return err
		}
	}
	if selected == 0 {
		return fmt.Errorf("fixed distro feed contains no evidence for %s:%s", ecosystem, profile.Release)
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if includeGo {
		data, err := os.ReadFile(filepath.Join(inputRoot, "osv-scanner", "Go", "all.zip"))
		if err != nil {
			return err
		}
		directory := filepath.Join(outputRoot, "osv-scanner", "Go")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(directory, "all.zip"), data, 0o400)
	}
	return nil
}

func filterDistroAdvisory(data []byte, ecosystem, targetRelease string) ([]byte, error) {
	var advisory map[string]json.RawMessage
	if err := json.Unmarshal(data, &advisory); err != nil {
		return nil, err
	}
	var affected []json.RawMessage
	if raw, present := advisory["affected"]; present {
		if err := json.Unmarshal(raw, &affected); err != nil {
			return nil, err
		}
	}
	selected := []json.RawMessage{}
	for _, raw := range affected {
		var entry struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, err
		}
		parts := strings.Split(entry.Package.Ecosystem, ":")
		if parts[0] != ecosystem {
			continue
		}
		version := ""
		labels := map[string]bool{}
		for _, part := range parts[1:] {
			if ecosystem == "Ubuntu" && (part == "Pro" || part == "LTS") && !labels[part] {
				labels[part] = true
				continue
			}
			if version != "" || part == "" || strings.IndexFunc(part, func(c rune) bool { return c != '.' && (c < '0' || c > '9') }) >= 0 {
				return nil, fmt.Errorf("ambiguous distro advisory release %q", entry.Package.Ecosystem)
			}
			version = part
		}
		if version == "" {
			return nil, fmt.Errorf("distro advisory omits its release scope")
		}
		if version == targetRelease {
			selected = append(selected, raw)
		}
	}
	if len(selected) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(selected)
	if err != nil {
		return nil, err
	}
	advisory["affected"] = encoded
	return json.Marshal(advisory)
}
