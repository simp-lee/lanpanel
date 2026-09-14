// Command lanpanel-release builds and verifies a public Preview artifact.
package main

import (
	"flag"
	"fmt"
	"io"
	"lanpanel/internal/packages"
	"lanpanel/internal/release"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type inputAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  uint64 `json:"bytes"`
}
type dependencySource struct {
	URL    string     `json:"url"`
	Format string     `json:"format"`
	Asset  inputAsset `json:"asset"`
}
type dependencyInput struct {
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	MetadataSource string           `json:"metadata_source"`
	MetadataDigest string           `json:"metadata_digest"`
	PublishedAt    time.Time        `json:"published_at"`
	Source         dependencySource `json:"source"`
	Archive        inputAsset       `json:"archive"`
	Executable     inputAsset       `json:"executable"`
	Member         string           `json:"member"`
}
type dependencyInputs struct {
	SchemaVersion string            `json:"schema_version"`
	Dependencies  []dependencyInput `json:"dependencies"`
}

func main() {
	var source, inputsPath, manifestPath, dependencyPath, packagePath, baselinePath, profileInputDir, signingKeyPath, output, tag, verifyDir string
	flag.StringVar(&source, "source", ".", "clean source tree")
	flag.StringVar(&inputsPath, "dependency-inputs", "", "resolved dependency-inputs.json")
	flag.StringVar(&manifestPath, "manifest-template", "", "canonical release manifest template")
	flag.StringVar(&dependencyPath, "dependency-template", "", "canonical dependency manifest template")
	flag.StringVar(&packagePath, "package-template", "", "canonical package template")
	flag.StringVar(&baselinePath, "dependency-baseline", "", "canonical dependency baseline")
	flag.StringVar(&profileInputDir, "profile-input-dir", "", "directory containing package-template.<profile-id>.json and dependency-baseline.<profile-id>.json")
	flag.StringVar(&signingKeyPath, "signing-key", "", "Ed25519 private key used to sign the final manifest")
	flag.StringVar(&output, "output", "", "new artifact directory")
	flag.StringVar(&tag, "tag", "", "release tag")
	flag.StringVar(&verifyDir, "verify-dir", "", "verify an assembled release directory")
	flag.Parse()
	var err error
	if verifyDir != "" {
		err = verifyDirectory(verifyDir)
	} else {
		err = build(source, inputsPath, manifestPath, dependencyPath, packagePath, baselinePath, profileInputDir, signingKeyPath, output, tag)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(source, inputsPath, manifestPath, dependencyPath, packagePath, baselinePath, profileInputDir, signingKeyPath, output, tag string) error {
	if source == "" || inputsPath == "" || manifestPath == "" || signingKeyPath == "" || output == "" || tag == "" || profileInputDir == "" && (packagePath == "" || baselinePath == "") {
		return fmt.Errorf("source, dependency-inputs, manifest-template, output, tag, and either profile-input-dir or package-template/dependency-baseline are required")
	}
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("output directory already exists: %s", output)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := ensureCleanTag(source, tag); err != nil {
		return err
	}
	inputs, err := readCanonical(inputsPath, &dependencyInputs{})
	if err != nil {
		return fmt.Errorf("dependency inputs: %w", err)
	}
	resolved := inputs.(dependencyInputs)
	if resolved.SchemaVersion != "lanpanel.dependency-inputs.v1" || len(resolved.Dependencies) != 3 {
		return fmt.Errorf("dependency inputs are incomplete")
	}
	manifestValue, err := readCanonical(manifestPath, &release.ReleaseManifest{})
	if err != nil {
		return fmt.Errorf("release manifest template: %w", err)
	}
	manifest := manifestValue.(release.ReleaseManifest)
	manifest.ReleaseTag = tag
	dependency := release.DependencyAuthority{SchemaVersion: "lanpanel.dependency-authority.v1"}
	if dependencyPath != "" {
		dependencyValue, err := readCanonical(dependencyPath, &release.DependencyAuthority{})
		if err != nil {
			return fmt.Errorf("dependency manifest template: %w", err)
		}
		dependency = dependencyValue.(release.DependencyAuthority)
	}
	if err := validateDependencies(resolved); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return fmt.Errorf("create release output parent: %w", err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(output), ".lanpanel-release.")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			fmt.Fprintf(os.Stderr, "remove temporary release directory: %v\n", err)
		}
	}()
	if err := os.Chmod(tmp, 0o700); err != nil {
		return err
	}
	if err := buildBinary(source, filepath.Join(tmp, "lanpanel")); err != nil {
		return err
	}
	sourceArchive, _, err := release.GenerateSourceArchive(source, tag)
	if err != nil {
		return fmt.Errorf("source archive: %w", err)
	}
	if err := writeFile(filepath.Join(tmp, "lanpanel-"+tag+".tar.gz"), sourceArchive, 0o644); err != nil {
		return err
	}
	for _, path := range []string{manifest.License.Path, manifest.KnownLimitations.Path} {
		if err := copyRegular(filepath.Join(source, filepath.FromSlash(path)), filepath.Join(tmp, filepath.FromSlash(path)), 0o644); err != nil {
			return err
		}
	}
	for index := range manifest.SupportedProfiles {
		profile := &manifest.SupportedProfiles[index]
		if profile.Profile.ID == "" {
			return fmt.Errorf("release profile id is missing")
		}
		if profile.PackageTemplate.Path == "" {
			profile.PackageTemplate.Path = "package-template-" + profile.Profile.ID + ".json"
		}
		if profile.DependencyManifest.Path == "" {
			profile.DependencyManifest.Path = "dependency-manifest-" + profile.Profile.ID + ".json"
		}
		if profile.DependencyBaseline.Path == "" {
			profile.DependencyBaseline.Path = "dependency-baseline-" + profile.Profile.ID + ".json"
		}
		packageSource, baselineSource := packagePath, baselinePath
		if profileInputDir != "" {
			packageSource = filepath.Join(profileInputDir, "package-template-"+profile.Profile.ID+".json")
			baselineSource = filepath.Join(profileInputDir, "dependency-baseline-"+profile.Profile.ID+".json")
		}
		packageDestination := filepath.Join(tmp, filepath.FromSlash(profile.PackageTemplate.Path))
		if err := copyRegular(packageSource, packageDestination, 0o644); err != nil {
			return err
		}
		packageBytes, err := os.ReadFile(packageDestination)
		if err != nil {
			return fmt.Errorf("read package template: %w", err)
		}
		var packageTemplate packages.Plan
		if err := release.DecodeCanonical(packageBytes, &packageTemplate); err != nil || releasePackageTemplateMatches(packageTemplate, profile.Profile) == false {
			return fmt.Errorf("package template does not match profile %s", profile.Profile.ID)
		}
		if err := copyRegular(baselineSource, filepath.Join(tmp, filepath.FromSlash(profile.DependencyBaseline.Path)), 0o644); err != nil {
			return err
		}
	}
	for _, dep := range resolved.Dependencies {
		for _, asset := range []inputAsset{dep.Archive, dep.Executable} {
			if err := copyVerified(filepath.Join(filepath.Dir(inputsPath), filepath.FromSlash(asset.Path)), filepath.Join(tmp, filepath.FromSlash(asset.Path)), asset, 0o644); err != nil {
				return err
			}
		}
	}

	lego, tailscale, headscale := resolved.Dependencies[0], resolved.Dependencies[1], resolved.Dependencies[2]
	if lego.Name != "lego" || tailscale.Name != "tailscale" || headscale.Name != "headscale" {
		return fmt.Errorf("dependency inputs must be ordered lego, tailscale, headscale")
	}
	manifest.Headscale = hydrateHeadscale(manifest.Headscale, headscale)
	dependency.Headscale = manifest.Headscale
	dependency.LegoVersion, dependency.LegoArtifactIdentity, dependency.LegoArchive, dependency.Lego = lego.Version, lego.Source.URL, identity(lego.Archive), identity(lego.Executable)
	dependency.LegoMembers = []release.ArchiveMemberAuthority{{Path: lego.Member, Asset: identity(lego.Executable), Destination: "/usr/lib/lanpanel/dependencies/lego", Mode: 0o755}}
	if len(dependency.Tailscale.Members) == 0 {
		dependency.Tailscale = defaultTailscaleAuthority(tailscale.Source.URL)
	}
	if len(dependency.Tailscale.Members) != 1 {
		return fmt.Errorf("dependency template must declare exactly the tailscale executable member")
	}
	dependency.Tailscale = hydrateClient(dependency.Tailscale, tailscale)
	dependency.Tailscale.Version = tailscale.Version
	dependency.Tailscale.ArtifactIdentity = tailscale.Source.URL
	dependency.Tailscale.Archive = identity(tailscale.Archive)
	dependency.Tailscale.Members[0].Path = "tailscale"
	dependency.Tailscale.Members[0].Asset = identity(tailscale.Executable)
	dependency.Tailscale.Members[0].Destination = "/usr/lib/lanpanel/dependencies/tailscale"
	dependency.Tailscale.Members[0].Mode = 0o755
	for i := range manifest.SupportedProfiles {
		profile := &manifest.SupportedProfiles[i]
		dependencyForProfile := dependency
		dependencyForProfile.ProfileID = profile.Profile.ID
		dependencyForProfile.DependencyBaseline = fileIdentity(tmp, profile.DependencyBaseline.Path)
		dependencyBytes, err := release.MarshalCanonical(dependencyForProfile)
		if err != nil {
			return fmt.Errorf("dependency manifest: %w", err)
		}
		if err := writeFile(filepath.Join(tmp, filepath.FromSlash(profile.DependencyManifest.Path)), dependencyBytes, 0o644); err != nil {
			return err
		}
	}
	manifest.Binary = fileIdentity(tmp, "lanpanel")
	manifest.SourceArchive = fileIdentity(tmp, "lanpanel-"+tag+".tar.gz")
	manifest.License = fileIdentity(tmp, manifest.License.Path)
	manifest.KnownLimitations = fileIdentity(tmp, manifest.KnownLimitations.Path)
	for i := range manifest.SupportedProfiles {
		manifest.SupportedProfiles[i].PackageTemplate = fileIdentity(tmp, manifest.SupportedProfiles[i].PackageTemplate.Path)
		manifest.SupportedProfiles[i].DependencyManifest = fileIdentity(tmp, manifest.SupportedProfiles[i].DependencyManifest.Path)
		manifest.SupportedProfiles[i].DependencyBaseline = fileIdentity(tmp, manifest.SupportedProfiles[i].DependencyBaseline.Path)
	}
	manifest.Headscale.Archive = fileIdentity(tmp, headscale.Archive.Path)
	for i := range manifest.Headscale.Members {
		manifest.Headscale.Members[i].Asset = fileIdentity(tmp, manifest.Headscale.Members[i].Asset.Path)
	}
	for i := range manifest.AdditionalAssets {
		manifest.AdditionalAssets[i] = fileIdentity(tmp, manifest.AdditionalAssets[i].Path)
	}
	entries := make([]release.ChecksumEntry, 0)
	paths, err := release.InstallAssetPaths(manifest)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if path == "release.json" || path == manifest.Checksums.Path || path == release.ReleaseSignaturePath {
			continue
		}
		entries = append(entries, release.ChecksumEntry{Path: path, Digest: fileIdentity(tmp, path).Digest})
	}
	checksumBytes, err := release.EncodeChecksums(entries)
	if err != nil {
		return fmt.Errorf("checksums: %w", err)
	}
	manifest.Checksums = release.AssetIdentity{Path: "SHA256SUMS", Digest: release.DigestBytes(checksumBytes), Bytes: uint64(len(checksumBytes))}
	manifestBytes, err := release.MarshalCanonical(manifest)
	if err != nil {
		return fmt.Errorf("release manifest: %w", err)
	}
	signingKey, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return fmt.Errorf("release signing key: %w", err)
	}
	signatureBytes, err := release.SignCanonicalManifest(manifestBytes, signingKey)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(tmp, release.ReleaseSignaturePath), signatureBytes, 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(tmp, "SHA256SUMS"), checksumBytes, 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(tmp, "release.json"), manifestBytes, 0o644); err != nil {
		return err
	}
	assets := make(map[string][]byte)
	for _, path := range paths {
		if path == "release.json" || path == "SHA256SUMS" || path == release.ReleaseSignaturePath {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tmp, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		assets[path] = data
	}
	for _, profile := range manifest.SupportedProfiles {
		if _, err := release.VerifyPublicInstallAuthority(release.DigestBytes(manifestBytes), manifestBytes, signatureBytes, checksumBytes, assets, release.PublicInstallObservation{HostFingerprint: "release-builder", ObservedAt: time.Now().UTC(), OSID: profile.Profile.Family, OSVersionID: profile.Profile.Release, Architecture: profile.Profile.Architecture}); err != nil {
			return fmt.Errorf("release verification for %s: %w", profile.Profile.ID, err)
		}
	}
	return os.Rename(tmp, output)
}

func verifyDirectory(root string) error {
	manifestBytes, err := os.ReadFile(filepath.Join(root, "release.json"))
	if err != nil {
		return fmt.Errorf("release manifest: %w", err)
	}
	checksumBytes, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		return fmt.Errorf("release checksums: %w", err)
	}
	signatureBytes, err := os.ReadFile(filepath.Join(root, release.ReleaseSignaturePath))
	if err != nil {
		return fmt.Errorf("release signature: %w", err)
	}
	var manifest release.ReleaseManifest
	if err := release.DecodeCanonical(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("release manifest: %w", err)
	}
	paths, err := release.InstallAssetPaths(manifest)
	if err != nil {
		return err
	}
	expected := make(map[string]bool, len(paths))
	for _, path := range paths {
		expected[path] = true
	}
	assets := make(map[string][]byte)
	actual := make(map[string]bool)
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !info.Mode().IsRegular() {
			if info.IsDir() {
				return nil
			}
			return fmt.Errorf("release artifact contains a non-regular file: %s", rel)
		}
		if !expected[rel] {
			return fmt.Errorf("release artifact contains undeclared asset: %s", rel)
		}
		actual[rel] = true
		if rel != "release.json" && rel != manifest.Checksums.Path && rel != release.ReleaseSignaturePath {
			assets[rel], err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, path := range paths {
		if !actual[path] {
			return fmt.Errorf("release artifact is missing asset: %s", path)
		}
	}
	for _, profile := range manifest.SupportedProfiles {
		if _, err := release.VerifyPublicInstallAuthority(release.DigestBytes(manifestBytes), manifestBytes, signatureBytes, checksumBytes, assets, release.PublicInstallObservation{HostFingerprint: "release-builder", ObservedAt: time.Now().UTC(), OSID: profile.Profile.Family, OSVersionID: profile.Profile.Release, Architecture: profile.Profile.Architecture}); err != nil {
			return fmt.Errorf("release verification for %s: %w", profile.Profile.ID, err)
		}
	}
	return nil
}

func readCanonical(path string, value any) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := release.DecodeCanonical(data, value); err != nil {
		return nil, err
	}
	switch value := value.(type) {
	case *dependencyInputs:
		return *value, nil
	case *release.ReleaseManifest:
		return *value, nil
	case *release.DependencyAuthority:
		return *value, nil
	default:
		return nil, fmt.Errorf("unsupported template")
	}
}

func releasePackageTemplateMatches(template packages.Plan, profile release.OSProfile) bool {
	if err := packages.ValidatePublicReleasePlan(template); err != nil || len(template.Packages) != len(profile.Packages) {
		return false
	}
	for index, packageProfile := range profile.Packages {
		packageValue := template.Packages[index]
		if packageValue.Name != packageProfile.Name || packageValue.Version != packageProfile.Version || packageValue.VersionMinimum != packageProfile.VersionMinimum || packageValue.VersionMaximum != packageProfile.VersionMaximum || packageValue.Architecture != packageProfile.Architecture {
			return false
		}
	}
	return true
}

func validateDependencies(inputs dependencyInputs) error {
	seen := map[string]bool{}
	for _, dep := range inputs.Dependencies {
		if seen[dep.Name] || dep.Name == "" || dep.Version == "" || dep.MetadataSource == "" || !release.ValidDigest(dep.MetadataDigest) || dep.PublishedAt.IsZero() || dep.Source.URL == "" || dep.Member == "" || !release.ValidDigest(dep.Archive.SHA256) || !release.ValidDigest(dep.Executable.SHA256) || dep.Archive.Bytes == 0 || dep.Executable.Bytes == 0 {
			return fmt.Errorf("dependency input %q is invalid", dep.Name)
		}
		seen[dep.Name] = true
	}
	return nil
}

func hydrateHeadscale(value release.HeadscaleArtifactAuthority, input dependencyInput) release.HeadscaleArtifactAuthority {
	value.Version = input.Version
	value.ArtifactIdentity = input.Source.URL
	value.Archive = identity(input.Archive)
	if len(value.Members) == 0 {
		value.Members = []release.ArchiveMemberAuthority{{Path: input.Member, Destination: value.InstallPath, Mode: 0o755}}
	}
	for i := range value.Members {
		value.Members[i].Path = input.Member
		value.Members[i].Asset = identity(input.Executable)
	}
	value.ExecutableAsset = input.Member
	return value
}

func defaultTailscaleAuthority(artifactURL string) release.ClientArtifactAuthority {
	authority := release.ClientArtifactAuthority{ArchiveFormat: "tar_gzip", MaximumExtractedBytes: 1 << 30, ExecutableAsset: "tailscale", InstallPath: "/usr/lib/lanpanel/dependencies/tailscale", Members: []release.ArchiveMemberAuthority{{Path: "tailscale", Destination: "/usr/lib/lanpanel/dependencies/tailscale", Mode: 0o755}}}
	if parsed, err := url.Parse(artifactURL); err == nil && parsed.Host != "" {
		authority.RedirectAuthorities = []string{parsed.Host}
	}
	return authority
}

func hydrateClient(value release.ClientArtifactAuthority, input dependencyInput) release.ClientArtifactAuthority {
	value.Version = input.Version
	value.ArtifactIdentity = input.Source.URL
	value.Archive = identity(input.Archive)
	return value
}

func identity(asset inputAsset) release.AssetIdentity {
	return release.AssetIdentity{Path: asset.Path, Digest: asset.SHA256, Bytes: asset.Bytes}
}

func fileIdentity(root, path string) release.AssetIdentity {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return release.AssetIdentity{}
	}
	return release.AssetIdentity{Path: path, Digest: release.DigestBytes(data), Bytes: uint64(len(data))}
}

func copyRegular(src, dst string, mode os.FileMode) error {
	info, err := os.Lstat(src)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("release asset is not a regular file: %s", src)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	return writeFile(dst, data, mode)
}

func copyVerified(src, dst string, expected inputAsset, mode os.FileMode) error {
	info, err := os.Lstat(src)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("release asset is not a regular file: %s", src)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if uint64(len(data)) != expected.Bytes || release.DigestBytes(data) != expected.SHA256 {
		return fmt.Errorf("dependency asset %s differs from its lock", expected.Path)
	}
	return writeFile(dst, data, mode)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

func ensureCleanTag(source, tag string) error {
	for _, args := range [][]string{{"diff", "--quiet"}, {"diff", "--cached", "--quiet"}} {
		command := exec.Command("git", args...)
		command.Dir = source
		if err := command.Run(); err != nil {
			return fmt.Errorf("source worktree is not clean: git %s", strings.Join(args, " "))
		}
	}
	command := exec.Command("git", "status", "--porcelain", "--untracked-files=all")
	command.Dir = source
	if output, err := command.Output(); err != nil {
		return fmt.Errorf("inspect source worktree: %w", err)
	} else if len(output) != 0 {
		return fmt.Errorf("source worktree contains uncommitted or untracked files")
	}
	command = exec.Command("git", "describe", "--exact-match", "--tags", "HEAD")
	command.Dir = source
	output, err := command.Output()
	if err != nil || strings.TrimSpace(string(output)) != tag {
		return fmt.Errorf("source HEAD is not the requested exact tag %s", tag)
	}
	return nil
}

func buildBinary(source, output string) error {
	command := exec.Command("go", "build", "-trimpath", "-o", output, "./cmd/lanpanel")
	command.Dir = source
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	command.Stdout, command.Stderr = io.Discard, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("build lanpanel: %w", err)
	}
	return os.Chmod(output, 0o755)
}
