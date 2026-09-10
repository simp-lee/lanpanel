//go:build linux

package packages

import (
	"bufio"
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// RepositoryPackageIndex contains the uncompressed bytes named by InRelease.
// Locating/decompressing the protected snapshot is the harness's responsibility.
type RepositoryPackageIndex struct {
	ReleasePath string
	Data        []byte
}

type SourcePackageMapping struct {
	Binary        Package
	SourceName    string
	SourceVersion string
}

// ResolveRepositoryPackageSources reuses the installation's repository trust
// authority. A caller-supplied source name is never advisory-matching authority.
func ResolveRepositoryPackageSources(repository Repository, keyring, inRelease []byte, indexes []RepositoryPackageIndex, closure []Package) ([]SourcePackageMapping, error) {
	if len(closure) > 0 && len(indexes) == 0 || digestBytes(keyring) != repository.KeyringDigest || digestBytes(inRelease) != repository.MetadataDigest {
		return nil, fmt.Errorf("source mapping repository snapshot differs from package authority")
	}
	plaintext, err := verifyInRelease(inRelease, keyring)
	if err != nil {
		return nil, err
	}
	if !releaseFieldEqualsTokens(plaintext, "Suite", []string{repository.Suite}) || !releaseFieldEqualsTokens(plaintext, "Components", repository.Components) || !releaseFieldContainsToken(plaintext, "Architectures", "amd64") {
		return nil, fmt.Errorf("source mapping signed suite, components, or architecture differs")
	}
	cutoff, err := repositoryCutoffDigest(plaintext)
	if err != nil || cutoff != repository.CutoffDigest {
		return nil, fmt.Errorf("source mapping repository cutoff differs")
	}
	files, err := releaseSHA256Files(plaintext)
	if err != nil {
		return nil, err
	}
	byTuple := map[string]Package{}
	for _, pkg := range closure {
		key := pkg.Name + "\x00" + pkg.Version + "\x00" + pkg.Architecture
		if _, duplicate := byTuple[key]; duplicate {
			return nil, fmt.Errorf("source mapping binary tuple duplicated")
		}
		byTuple[key] = pkg
	}
	mapped := map[string]SourcePackageMapping{}
	seenIndexes := map[string]bool{}
	for _, index := range indexes {
		parts := strings.Split(index.ReleasePath, "/")
		if len(parts) != 3 || !slices.Contains(repository.Components, parts[0]) || parts[1] != "binary-amd64" && parts[1] != "binary-all" || parts[2] != "Packages" || seenIndexes[index.ReleasePath] {
			return nil, fmt.Errorf("source mapping index is not an exact authorized Packages path")
		}
		seenIndexes[index.ReleasePath] = true
		file, present := files[index.ReleasePath]
		if !present || len(index.Data) > maximumRepositoryMetadataFileBytes || int64(len(index.Data)) != file.Bytes || digestBytes(index.Data) != file.Digest {
			return nil, fmt.Errorf("source mapping index differs from signed InRelease")
		}
		if err := mapPackageSourceStanzas(index.Data, byTuple, mapped); err != nil {
			return nil, err
		}
	}
	result := make([]SourcePackageMapping, 0, len(closure))
	for _, pkg := range closure {
		value, present := mapped[pkg.Name+"\x00"+pkg.Version+"\x00"+pkg.Architecture]
		if !present {
			return nil, fmt.Errorf("source mapping omits exact binary %s=%s/%s", pkg.Name, pkg.Version, pkg.Architecture)
		}
		result = append(result, value)
	}
	return result, nil
}

func mapPackageSourceStanzas(data []byte, expected map[string]Package, mapped map[string]SourcePackageMapping) error {
	fields := map[string]string{}
	commit := func() error {
		key := fields["Package"] + "\x00" + fields["Version"] + "\x00" + fields["Architecture"]
		pkg, present := expected[key]
		if !present {
			return nil
		}
		size, err := strconv.ParseInt(fields["Size"], 10, 64)
		if err != nil || size != pkg.ArtifactBytes || fields["SHA256"] != pkg.ArtifactDigest {
			return nil
		}
		sourceName, sourceVersion := pkg.Name, pkg.Version
		if source, present := fields["Source"]; present {
			parts := strings.Fields(source)
			if len(parts) < 1 || len(parts) > 2 || !packageNamePattern.MatchString(parts[0]) {
				return fmt.Errorf("invalid signed Source field for %s", pkg.Name)
			}
			sourceName = parts[0]
			if len(parts) == 2 {
				if !strings.HasPrefix(parts[1], "(") || !strings.HasSuffix(parts[1], ")") {
					return fmt.Errorf("invalid signed source version for %s", pkg.Name)
				}
				sourceVersion = parts[1][1 : len(parts[1])-1]
				if !versionPattern.MatchString(sourceVersion) {
					return fmt.Errorf("invalid signed source version for %s", pkg.Name)
				}
			}
		}
		if previous, present := mapped[key]; present && (previous.SourceName != sourceName || previous.SourceVersion != sourceVersion) {
			return fmt.Errorf("conflicting signed source mapping for %s", pkg.Name)
		}
		mapped[key] = SourcePackageMapping{Binary: pkg, SourceName: sourceName, SourceVersion: sourceVersion}
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lastField := ""
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := commit(); err != nil {
				return err
			}
			fields, lastField = map[string]string{}, ""
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if _, identityField := fields[lastField]; identityField {
				return fmt.Errorf("folded package identity field")
			}
			continue
		}
		name, value, valid := strings.Cut(line, ":")
		if !valid {
			return fmt.Errorf("malformed signed Packages stanza")
		}
		lastField = name
		switch name {
		case "Package", "Version", "Architecture", "SHA256", "Size", "Source":
			if _, duplicate := fields[name]; duplicate {
				return fmt.Errorf("duplicate signed package identity field %s", name)
			}
			fields[name] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return commit()
}
