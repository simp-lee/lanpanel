// Command lanpanel-profile-capture records OS and package version
// requirements from a qualified Debian or Ubuntu amd64 host. It never
// mutates the host or binds a particular APT mirror.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"lanpanel/internal/dependencies"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"lanpanel/internal/sources"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

type stringList []string

func (v *stringList) String() string { return strings.Join(*v, ",") }
func (v *stringList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("empty package name")
	}
	*v = append(*v, value)
	return nil
}

type dependencyInput struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	MetadataSource string    `json:"metadata_source"`
	MetadataDigest string    `json:"metadata_digest"`
	PublishedAt    time.Time `json:"published_at"`
	Source         struct {
		URL   string `json:"url"`
		Asset struct {
			SHA256 string `json:"sha256"`
		} `json:"asset"`
	} `json:"source"`
}

type dependencyInputs struct {
	SchemaVersion string            `json:"schema_version"`
	Dependencies  []dependencyInput `json:"dependencies"`
}

type aptRecord struct {
	Version      string
	Architecture string
	Filename     string
	Size         int64
	Digest       string
}

func main() {
	var output, profileID, dependencyPath string
	var packageNames stringList
	flag.StringVar(&output, "output", "", "output directory")
	flag.StringVar(&profileID, "profile-id", "", "profile ID, for example debian-amd64")
	flag.StringVar(&dependencyPath, "dependency-inputs", "", "resolved dependency-inputs.json")
	flag.Var(&packageNames, "package", "package to include; may be repeated")
	flag.Parse()
	if len(packageNames) == 0 {
		packageNames = stringList{"goaccess", "nginx"}
	}
	if err := capture(output, profileID, dependencyPath, packageNames); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func capture(output, profileID, dependencyPath string, packageNames []string) error {
	if output == "" || profileID == "" || dependencyPath == "" {
		return fmt.Errorf("output, profile-id, and dependency-inputs are required")
	}
	platform, err := readPlatform()
	if err != nil {
		return err
	}
	if runtime.GOARCH != "amd64" || !release.IsSupportedPreviewTarget(release.OSProfile{Family: platform.ID, Release: platform.VersionID, Architecture: runtime.GOARCH}) {
		return fmt.Errorf("host %s/%s/%s is not a supported Debian or Ubuntu amd64 platform", platform.ID, platform.VersionID, runtime.GOARCH)
	}
	if profileID != platform.ID+"-"+runtime.GOARCH {
		return fmt.Errorf("profile-id %q must identify the host family and architecture", profileID)
	}
	observation, err := preflight.ObserveBootstrapReadiness(context.Background())
	if err != nil {
		return fmt.Errorf("observe package prerequisites: %w", err)
	}
	if !observation.Ready {
		return fmt.Errorf("APT/dpkg is not ready before capture")
	}
	packageValues := make([]packages.Package, 0, len(packageNames))
	profilePackages := make([]release.PackageTuple, 0, len(packageNames))
	seen := map[string]bool{}
	sort.Strings(packageNames)
	if !slices.Contains(packageNames, "nginx") {
		return fmt.Errorf("package set omits required nginx")
	}
	for _, name := range packageNames {
		if seen[name] {
			return fmt.Errorf("duplicate package %q", name)
		}
		seen[name] = true
		record, err := aptPackage(name)
		if err != nil {
			return err
		}
		packageValues = append(packageValues, packagePlanValue(name, record))
		minimum := packageMinimum(name)
		profilePackages = append(profilePackages, release.PackageTuple{Name: name, Version: record.Version, VersionMinimum: minimum, Architecture: record.Architecture})
	}
	profile := release.OSProfile{ID: profileID, Family: platform.ID, Release: platform.VersionID, Architecture: runtime.GOARCH, Packages: profilePackages, ManagedConfinement: confinementProfile()}
	profileDigest, err := release.ProfileDigest(profile)
	if err != nil {
		return fmt.Errorf("OS profile: %w", err)
	}
	plan := packages.Plan{TransactionID: "pkg_" + strings.Repeat("0", 64), JobID: "job_" + strings.Repeat("0", 64), IntentGeneration: 1, Deadline: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), OSProfileDigest: profileDigest, Mode: packages.DistroRepository, Packages: packageValues, FirstNginxInstall: true, LockWait: 30 * time.Second, ConnectTimeout: 15 * time.Second, ReadTimeout: 30 * time.Second, TotalTimeout: 2 * time.Minute, NoAutostartPolicyDigest: strings.Repeat("0", 64), PreflightDigest: "sha256:" + strings.Repeat("0", 64), PreflightRequestDigest: "sha256:" + strings.Repeat("0", 64), Authority: packages.Authority{Kind: packages.PreviewProfile, ReleaseAuthorityDigest: strings.Repeat("0", 64), BinaryDigest: strings.Repeat("0", 64), HostFingerprint: "profile-capture", TargetOSProfileDigest: profileDigest}}
	if err := packages.ValidatePublicReleasePlan(plan); err != nil {
		return fmt.Errorf("package template: %w", err)
	}
	profileBytes, err := release.MarshalCanonical(profile)
	if err != nil {
		return err
	}
	planBytes, err := release.MarshalCanonical(plan)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "os-profile.json"), profileBytes, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "package-template-"+profileID+".json"), planBytes, 0o644); err != nil {
		return err
	}
	baseline, err := buildBaseline(dependencyPath)
	if err != nil {
		return err
	}
	baselineBytes, err := dependencies.EncodeBaseline(baseline)
	if err != nil {
		return fmt.Errorf("dependency baseline: %w", err)
	}
	if err := os.WriteFile(filepath.Join(output, "dependency-baseline-"+profileID+".json"), baselineBytes, 0o644); err != nil {
		return err
	}
	fmt.Printf("captured %s: profile=%s package-template=%s dependency-baseline=%s\n", profileID, profileDigest, filepath.Join(output, "package-template-"+profileID+".json"), filepath.Join(output, "dependency-baseline-"+profileID+".json"))
	return nil
}

func buildBaseline(dependencyPath string) (dependencies.Baseline, error) {
	data, err := os.ReadFile(dependencyPath)
	if err != nil {
		return dependencies.Baseline{}, fmt.Errorf("dependency inputs: %w", err)
	}
	var inputs dependencyInputs
	if err := release.DecodeCanonical(data, &inputs); err != nil {
		return dependencies.Baseline{}, fmt.Errorf("dependency inputs are not canonical: %w", err)
	}
	cutoff := time.Now().UTC().Truncate(time.Second)
	selections := make([]dependencies.Selection, 0, 3)
	for _, name := range []string{"headscale", "lego", "tailscale"} {
		var dep dependencyInput
		for _, candidate := range inputs.Dependencies {
			if candidate.Name == name {
				dep = candidate
				break
			}
		}
		if dep.Name == "" || dep.MetadataSource == "" || dep.MetadataDigest == "" || dep.PublishedAt.IsZero() || dep.PublishedAt.After(cutoff) {
			return dependencies.Baseline{}, fmt.Errorf("dependency lock lacks usable publication metadata for %s", name)
		}
		component := name
		if name == "tailscale" {
			component = "tailscale-client"
		}
		selections = append(selections, dependencies.Selection{Component: component, SourceKind: dependencies.SourceCanonicalArtifact, SelectedVersion: dep.Version, LatestStableVersion: dep.Version, LatestStablePublishedAt: dep.PublishedAt.UTC(), MetadataSource: dep.MetadataSource, MetadataSnapshotDigest: dep.MetadataDigest, OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: dep.Source.URL, ArtifactDigest: dep.Source.Asset.SHA256})
	}
	sort.Slice(selections, func(left, right int) bool { return selections[left].Component < selections[right].Component })
	return dependencies.Baseline{SchemaVersion: dependencies.SchemaVersion, Cutoff: cutoff, Selections: selections}, nil
}

func readPlatform() (struct{ ID, VersionID, Architecture string }, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return struct{ ID, VersionID, Architecture string }{}, err
	}
	platform := preflight.ParseOSRelease(string(data))
	return struct{ ID, VersionID, Architecture string }{platform.ID, platform.VersionID, runtime.GOARCH}, nil
}

func aptPackage(name string) (aptRecord, error) {
	policy, err := commandOutput("apt-cache", "policy", name)
	if err != nil {
		return aptRecord{}, fmt.Errorf("apt policy %s: %w", name, err)
	}
	candidate := ""
	for _, line := range strings.Split(policy, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Candidate:") {
			candidate = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Candidate:"))
		}
	}
	if candidate == "" || candidate == "(none)" {
		return aptRecord{}, fmt.Errorf("apt has no candidate for %s", name)
	}
	show, err := commandOutput("apt-cache", "show", name)
	if err != nil {
		return aptRecord{}, err
	}
	for _, stanza := range strings.Split(show, "\n\n") {
		fields := map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(stanza))
		for scanner.Scan() {
			key, value, ok := strings.Cut(scanner.Text(), ":")
			if ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		if fields["Version"] != candidate {
			continue
		}
		architecture := fields["Architecture"]
		if architecture == "" {
			return aptRecord{}, fmt.Errorf("apt architecture for %s is missing", name)
		}
		return aptRecord{Version: candidate, Architecture: architecture}, nil
	}
	return aptRecord{}, fmt.Errorf("apt metadata has no exact candidate record for %s=%s", name, candidate)
}

func packageMinimum(name string) string {
	switch name {
	case "nginx":
		return "1.18.0"
	case "goaccess":
		return "1.8.0"
	default:
		return "0"
	}
}

func packagePlanValue(name string, record aptRecord) packages.Package {
	units, listeners := []string{}, []string{}
	switch name {
	case "nginx":
		units, listeners = []string{"nginx.service"}, []string{"tcp/80", "tcp/443"}
	}
	return packages.Package{Name: name, Version: record.Version, VersionMinimum: packageMinimum(name), Architecture: record.Architecture, MaximumInstalledFileBytes: 4 << 30, AffectedUnits: units, PossibleListeners: listeners, Source: sources.Source{Kind: sources.OfficialDistro, Artifact: sources.Artifact{Name: name, Version: record.Version, OperatingOS: "linux", Architecture: record.Architecture}}}
}

func confinementProfile() release.ConfinementProfile {
	profile := release.ConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "any", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_baseline_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8", "169.254.169.254/32", "::1/128"}}
	data, _ := json.Marshal(struct {
		SchemaVersion         string   `json:"schema_version"`
		KernelRelease         string   `json:"kernel_release"`
		CgroupMode            string   `json:"cgroup_mode"`
		BindListenPolicy      string   `json:"bind_listen_policy"`
		ConnectPolicy         string   `json:"connect_policy"`
		FilesystemPolicy      string   `json:"filesystem_policy"`
		ProtectedDestinations []string `json:"protected_destinations"`
	}{profile.SchemaVersion, profile.KernelRelease, profile.CgroupMode, profile.BindListenPolicy, profile.ConnectPolicy, profile.FilesystemPolicy, profile.ProtectedDestinations})
	profile.PolicyDigest = release.DigestBytes(data)
	return profile
}

func commandOutput(name string, args ...string) (string, error) {
	command := exec.Command(name, args...)
	data, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return string(data), nil
}
