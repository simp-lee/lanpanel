//go:build linux

package packages

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

func TestSignedRepositoryMetadataAllowsEmptyIndexOnlyForEmptyClosure(t *testing.T) {
	files, err := releaseSHA256Files([]byte("Suite: stable\nComponents: main\nArchitectures: amd64\nSHA256:\n"))
	if err != nil || len(files) != 0 {
		t.Fatalf("empty signed index = %#v, %v", files, err)
	}
	if _, err := releaseSHA256Files([]byte("Suite: stable\nComponents: main\nArchitectures: amd64\n")); err == nil {
		t.Fatal("missing SHA256 field was accepted")
	}
}

func TestSignedRepositorySourceMappingBindsExactBinaryClosure(t *testing.T) {
	signer, err := openpgp.NewEntity("Source fixture", "", "fixture@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	var keyring bytes.Buffer
	if err := signer.Serialize(&keyring); err != nil {
		t.Fatal(err)
	}
	closure := []Package{
		{Name: "apache2-utils", Version: "2.4.62-1+b1", Architecture: "amd64", ArtifactDigest: strings.Repeat("a", 64), ArtifactBytes: 41},
		{Name: "data-package", Version: "1.0-1", Architecture: "all", ArtifactDigest: strings.Repeat("b", 64), ArtifactBytes: 42},
		{Name: "libc6", Version: "2.41-1", Architecture: "amd64", ArtifactDigest: strings.Repeat("c", 64), ArtifactBytes: 43},
	}
	var index strings.Builder
	for i, pkg := range closure {
		fmt.Fprintf(&index, "Package: %s\nVersion: %s\nArchitecture: %s\nSHA256: %s\nSize: %d\n", pkg.Name, pkg.Version, pkg.Architecture, pkg.ArtifactDigest, pkg.ArtifactBytes)
		switch i {
		case 0:
			index.WriteString("Source: apache2 (2.4.62-1)\n")
		case 2:
			index.WriteString("Source: glibc\n")
		}
		index.WriteString("Description: fixture\n continued description\n\n")
	}
	resolve := func(data string, mutate func(*Repository, []byte, []byte, []RepositoryPackageIndex, []Package)) ([]SourcePackageMapping, error) {
		t.Helper()
		plain := []byte(fmt.Sprintf("Suite: stable\nDate: Mon, 01 Sep 2025 00:00:00 UTC\nArchitectures: amd64 all\nComponents: main\nSHA256:\n %s %d main/binary-amd64/Packages\n", digestBytes([]byte(data)), len(data)))
		var signed bytes.Buffer
		writer, err := clearsign.Encode(&signed, signer.PrivateKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		cutoff, err := repositoryCutoffDigest(plain)
		if err != nil {
			t.Fatal(err)
		}
		repository := Repository{Suite: "stable", Components: []string{"main"}, KeyringDigest: digestBytes(keyring.Bytes()), MetadataDigest: digestBytes(signed.Bytes()), CutoffDigest: cutoff}
		keys, inRelease := append([]byte(nil), keyring.Bytes()...), append([]byte(nil), signed.Bytes()...)
		indexes := []RepositoryPackageIndex{{ReleasePath: "main/binary-amd64/Packages", Data: []byte(data)}}
		packages := append([]Package(nil), closure...)
		if mutate != nil {
			mutate(&repository, keys, inRelease, indexes, packages)
		}
		return ResolveRepositoryPackageSources(repository, keys, inRelease, indexes, packages)
	}
	mapped, err := resolve(index.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range [][2]string{{"apache2", "2.4.62-1"}, {"data-package", "1.0-1"}, {"glibc", "2.41-1"}} {
		if mapped[i].SourceName != want[0] || mapped[i].SourceVersion != want[1] || mapped[i].Binary.ArtifactDigest != closure[i].ArtifactDigest {
			t.Fatalf("incorrect signed mapping: %+v", mapped[i])
		}
	}
	for name, mutate := range map[string]func(*Repository, []byte, []byte, []RepositoryPackageIndex, []Package){
		"keyring": func(_ *Repository, keys, _ []byte, _ []RepositoryPackageIndex, _ []Package) { keys[0] ^= 1 },
		"release": func(_ *Repository, _, signed []byte, _ []RepositoryPackageIndex, _ []Package) {
			signed[len(signed)/2] ^= 1
		},
		"signature despite changed digest": func(repo *Repository, _, signed []byte, _ []RepositoryPackageIndex, _ []Package) {
			signed[bytes.Index(signed, []byte("Architectures"))] = 'Z'
			repo.MetadataDigest = digestBytes(signed)
		},
		"signed suite": func(repo *Repository, _, signed []byte, _ []RepositoryPackageIndex, _ []Package) {
			index := bytes.Index(signed, []byte("Suite: stable"))
			signed[index+len("Suite: ")] = 'x'
			repo.MetadataDigest = digestBytes(signed)
		},
		"index": func(_ *Repository, _, _ []byte, indexes []RepositoryPackageIndex, _ []Package) {
			indexes[0].Data[0] ^= 1
		},
		"index path": func(_ *Repository, _, _ []byte, indexes []RepositoryPackageIndex, _ []Package) {
			indexes[0].ReleasePath = "other/binary-amd64/Packages"
		},
		"artifact digest": func(_ *Repository, _, _ []byte, _ []RepositoryPackageIndex, packages []Package) {
			packages[0].ArtifactDigest = strings.Repeat("d", 64)
		},
		"artifact size": func(_ *Repository, _, _ []byte, _ []RepositoryPackageIndex, packages []Package) {
			packages[0].ArtifactBytes++
		},
		"binary version": func(_ *Repository, _, _ []byte, _ []RepositoryPackageIndex, packages []Package) {
			packages[0].Version = "2.4.62-2"
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolve(index.String(), mutate); err == nil {
				t.Fatal("changed repository/binary authority accepted")
			}
		})
	}
	for _, source := range []string{"Source: apache2 nope", "Source: apache2 (2.4.62-1)\nSource: other", "Source: apache2 ("} {
		if _, err := resolve(strings.Replace(index.String(), "Source: apache2 (2.4.62-1)", source, 1), nil); err == nil {
			t.Fatalf("invalid signed source accepted: %s", source)
		}
	}
}
