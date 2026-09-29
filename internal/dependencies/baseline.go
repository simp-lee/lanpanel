// Package dependencies defines the frozen third-party Dependency Baseline.
package dependencies

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "lanpanel.dependency-baseline.v2"

type SourceKind string

const (
	SourceCanonicalArtifact SourceKind = "canonical_artifact"
	SourceDistroRepository  SourceKind = "distro_repository"
)

type Selection struct {
	Component               string     `json:"component"`
	SourceKind              SourceKind `json:"source_kind"`
	SelectedVersion         string     `json:"selected_version"`
	LatestStableVersion     string     `json:"latest_stable_version"`
	LatestStablePublishedAt time.Time  `json:"latest_stable_published_at"`
	MetadataSource          string     `json:"metadata_source"`
	MetadataSnapshotDigest  string     `json:"metadata_snapshot_digest"`
	OSProfileDigest         string     `json:"os_profile_digest,omitempty"`
	OperatingSystem         string     `json:"operating_system,omitempty"`
	Architecture            string     `json:"architecture,omitempty"`
	ArtifactIdentity        string     `json:"artifact_identity"`
	ArtifactDigest          string     `json:"artifact_digest"`
}

type Baseline struct {
	SchemaVersion string      `json:"schema_version"`
	Cutoff        time.Time   `json:"cutoff_utc"`
	Selections    []Selection `json:"selections"`
}

type PublishedRelease struct {
	Version          string
	PublishedAt      time.Time
	Draft            bool
	Prerelease       bool
	OperatingSystem  string
	Architecture     string
	ArtifactIdentity string
	ArtifactDigest   string
}

type DistroPackageCandidate struct {
	Version             string
	ArtifactIdentity    string
	ArtifactDigest      string
	RepositoryCandidate bool
}

var (
	componentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionPattern   = regexp.MustCompile(`^(?:v)?[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	packagePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*=[0-9A-Za-z][0-9A-Za-z.+:~_-]*@[a-z0-9][a-z0-9._/-]*$`)
)

var requiredSelections = map[string]SourceKind{
	"goaccess":         SourceCanonicalArtifact,
	"headscale":        SourceCanonicalArtifact,
	"lego":             SourceCanonicalArtifact,
	"tailscale-client": SourceCanonicalArtifact,
}

func DecodeBaseline(data []byte) (Baseline, error) {
	var baseline Baseline
	if err := decodeCanonical(data, &baseline); err != nil {
		return Baseline{}, err
	}
	if err := ValidateBaseline(baseline); err != nil {
		return Baseline{}, err
	}
	return baseline, nil
}

func EncodeBaseline(baseline Baseline) ([]byte, error) {
	if err := ValidateBaseline(baseline); err != nil {
		return nil, err
	}
	return json.Marshal(baseline)
}

func BaselineDigest(baseline Baseline) (string, error) {
	data, err := EncodeBaseline(baseline)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

func ValidateBaseline(baseline Baseline) error {
	if baseline.SchemaVersion != SchemaVersion || !exactUTCSecond(baseline.Cutoff) {
		return fmt.Errorf("dependency baseline schema or cutoff is invalid")
	}
	seen := map[string]SourceKind{}
	previous := ""
	for _, selection := range baseline.Selections {
		if err := validateSelection(selection, baseline.Cutoff); err != nil {
			return err
		}
		if previous != "" && strings.Compare(previous, selection.Component) >= 0 {
			return fmt.Errorf("dependency selections are duplicated or unsorted")
		}
		seen[selection.Component] = selection.SourceKind
		previous = selection.Component
	}
	for component, sourceKind := range requiredSelections {
		if seen[component] != sourceKind {
			return fmt.Errorf("dependency baseline omits required %s selection %q", sourceKind, component)
		}
	}
	return nil
}

// SelectLatestStable chooses the most recently published non-draft,
// non-prerelease candidate at or before the frozen cutoff.
func SelectLatestStable(component, metadataSource, metadataSnapshotDigest string, cutoff time.Time, candidates []PublishedRelease) (Selection, error) {
	if !componentPattern.MatchString(component) || !canonicalHTTPSURL(metadataSource) || !validDigest(metadataSnapshotDigest) || !exactUTCSecond(cutoff) {
		return Selection{}, fmt.Errorf("dependency selection authority is invalid")
	}
	eligible := make([]PublishedRelease, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Draft || candidate.Prerelease || candidate.PublishedAt.After(cutoff) {
			continue
		}
		if err := validatePublishedRelease(candidate, SourceCanonicalArtifact); err != nil {
			return Selection{}, err
		}
		eligible = append(eligible, candidate)
	}
	if len(eligible) == 0 {
		return Selection{}, fmt.Errorf("dependency has no stable release at the baseline cutoff")
	}
	slices.SortFunc(eligible, func(left, right PublishedRelease) int {
		if order := right.PublishedAt.Compare(left.PublishedAt); order != 0 {
			return order
		}
		return strings.Compare(right.Version, left.Version)
	})
	selected := eligible[0]
	for _, candidate := range eligible[1:] {
		if !candidate.PublishedAt.Equal(selected.PublishedAt) {
			break
		}
		if candidate.Version != selected.Version || candidate.ArtifactIdentity != selected.ArtifactIdentity || candidate.ArtifactDigest != selected.ArtifactDigest {
			return Selection{}, fmt.Errorf("upstream latest-stable ordering is ambiguous at the cutoff")
		}
	}
	return Selection{
		Component: component, SourceKind: SourceCanonicalArtifact, SelectedVersion: selected.Version, LatestStableVersion: selected.Version,
		LatestStablePublishedAt: selected.PublishedAt, MetadataSource: metadataSource, MetadataSnapshotDigest: metadataSnapshotDigest,
		OperatingSystem: selected.OperatingSystem, Architecture: selected.Architecture, ArtifactIdentity: selected.ArtifactIdentity, ArtifactDigest: selected.ArtifactDigest,
	}, nil
}

// SelectDistroPackage accepts only the single candidate resolved by apt for the
// exact qualified OS/repository snapshot; publication timestamps are not used
// as Debian package-version authority.
func SelectDistroPackage(component, metadataSource, metadataSnapshotDigest, osProfileDigest string, cutoff time.Time, candidates []DistroPackageCandidate) (Selection, error) {
	if !componentPattern.MatchString(component) || !canonicalHTTPSURL(metadataSource) || !validDigest(metadataSnapshotDigest) || !validDigest(osProfileDigest) || !exactUTCSecond(cutoff) {
		return Selection{}, fmt.Errorf("distribution package selection authority is invalid")
	}
	var selected *DistroPackageCandidate
	for index := range candidates {
		candidate := &candidates[index]
		packageName, packageVersion, ok := parsePackageIdentity(candidate.ArtifactIdentity)
		if !versionPattern.MatchString(candidate.Version) || floating(candidate.Version) || !ok || packageName != component || packageVersion != candidate.Version || floating(candidate.ArtifactIdentity) || !validDigest(candidate.ArtifactDigest) {
			return Selection{}, fmt.Errorf("distribution package candidate is invalid, mismatched, or floating")
		}
		if candidate.RepositoryCandidate {
			if selected != nil {
				return Selection{}, fmt.Errorf("qualified repository resolved multiple package candidates")
			}
			selected = candidate
		}
	}
	if selected == nil {
		return Selection{}, fmt.Errorf("qualified repository did not resolve an exact package candidate")
	}
	return Selection{Component: component, SourceKind: SourceDistroRepository, SelectedVersion: selected.Version, LatestStableVersion: selected.Version, LatestStablePublishedAt: cutoff, MetadataSource: metadataSource, MetadataSnapshotDigest: metadataSnapshotDigest, OSProfileDigest: osProfileDigest, ArtifactIdentity: selected.ArtifactIdentity, ArtifactDigest: selected.ArtifactDigest}, nil
}

func validateSelection(selection Selection, cutoff time.Time) error {
	if !componentPattern.MatchString(selection.Component) || !validSourceKind(selection.SourceKind) || !versionPattern.MatchString(selection.SelectedVersion) || selection.SelectedVersion != selection.LatestStableVersion || floating(selection.SelectedVersion) || !exactUTCSecond(selection.LatestStablePublishedAt) || selection.LatestStablePublishedAt.After(cutoff) || !canonicalHTTPSURL(selection.MetadataSource) || !validDigest(selection.MetadataSnapshotDigest) || !validDigest(selection.ArtifactDigest) {
		return fmt.Errorf("dependency selection %q is not exact latest-stable authority", selection.Component)
	}
	switch selection.SourceKind {
	case SourceCanonicalArtifact:
		if selection.OSProfileDigest != "" || selection.OperatingSystem != "linux" || selection.Architecture != "amd64" || !canonicalHTTPSURL(selection.ArtifactIdentity) || floating(selection.ArtifactIdentity) {
			return fmt.Errorf("canonical dependency artifact identity is invalid or floating")
		}
	case SourceDistroRepository:
		packageName, packageVersion, ok := parsePackageIdentity(selection.ArtifactIdentity)
		if selection.OperatingSystem != "" || selection.Architecture != "" || !validDigest(selection.OSProfileDigest) || !ok || packageName != selection.Component || packageVersion != selection.SelectedVersion || floating(selection.ArtifactIdentity) {
			return fmt.Errorf("distribution package identity, version, or qualified OS profile is invalid")
		}
	}
	return nil
}

func validatePublishedRelease(candidate PublishedRelease, sourceKind SourceKind) error {
	if !versionPattern.MatchString(candidate.Version) || floating(candidate.Version) || !exactUTCSecond(candidate.PublishedAt) || !validDigest(candidate.ArtifactDigest) {
		return fmt.Errorf("published dependency release identity is invalid")
	}
	if sourceKind == SourceCanonicalArtifact && (candidate.OperatingSystem != "linux" || candidate.Architecture != "amd64" || !canonicalHTTPSURL(candidate.ArtifactIdentity) || floating(candidate.ArtifactIdentity)) {
		return fmt.Errorf("published canonical artifact is not pinned")
	}
	if sourceKind == SourceDistroRepository && (candidate.OperatingSystem != "" || candidate.Architecture != "" || !packagePattern.MatchString(candidate.ArtifactIdentity) || floating(candidate.ArtifactIdentity)) {
		return fmt.Errorf("published distribution package is not pinned")
	}
	return nil
}

func validSourceKind(kind SourceKind) bool {
	return kind == SourceCanonicalArtifact || kind == SourceDistroRepository
}

func canonicalHTTPSURL(value string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n\t") || floating(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Host != strings.ToLower(parsed.Host) || parsed.RawPath != "" || strings.Contains(parsed.EscapedPath(), "%") || parsed.Path == "" || path.Clean(parsed.Path) != parsed.Path {
		return false
	}
	hostname, port := parsed.Hostname(), parsed.Port()
	if hostname == "" || strings.HasSuffix(hostname, ".") || strings.HasSuffix(parsed.Host, ":") || strings.Contains(hostname, "%") || port == "443" {
		return false
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number <= 0 || number > 65535 || strconv.Itoa(number) != port {
			return false
		}
	}
	if address, err := netip.ParseAddr(hostname); err == nil {
		if address.String() != hostname {
			return false
		}
	} else if strings.Contains(hostname, ":") || onlyDigitsAndDots(hostname) {
		return false
	}
	return parsed.String() == value
}

func ValidateForOSProfile(baseline Baseline, osProfileDigest, nginxVersion string) error {
	if err := ValidateBaseline(baseline); err != nil {
		return fmt.Errorf("dependency baseline is invalid")
	}
	// Distro packages are selected from the host's authenticated APT
	// configuration. The baseline binds only the fixed canonical third-party
	// assets; retain this signature for callers that also validate an OS
	// profile, but no longer compare an nginx snapshot here.
	_ = osProfileDigest
	_ = nginxVersion
	return nil
}

func parsePackageIdentity(identity string) (string, string, bool) {
	packageName, remainder, found := strings.Cut(identity, "=")
	version, repository, foundRepository := strings.Cut(remainder, "@")
	return packageName, version, found && foundRepository && repository != "" && packagePattern.MatchString(identity)
}

func onlyDigitsAndDots(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return true
}

func floating(value string) bool {
	if pinnedTailscaleStableArtifact(value) {
		return false
	}
	lower := strings.ToLower(value)
	if parsed, err := url.Parse(lower); err == nil && parsed.Scheme != "" {
		lower = parsed.Path
	}
	for _, component := range strings.FieldsFunc(lower, func(character rune) bool {
		return (character < 'a' || character > 'z') && (character < '0' || character > '9')
	}) {
		if component == "latest" || component == "stable" {
			return true
		}
	}
	return strings.Contains(lower, "${") || strings.Contains(lower, "{{")
}

func decodeCanonical(data []byte, destination any) error {
	if destination == nil || len(data) == 0 || len(data) > 8<<20 || !utf8.Valid(data) {
		return fmt.Errorf("dependency baseline canonical JSON size or encoding is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode dependency baseline: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("dependency baseline has trailing JSON")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, data) {
		return fmt.Errorf("dependency baseline JSON is duplicate-bearing or noncanonical")
	}
	return nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func pinnedTailscaleStableArtifact(value string) bool {
	parsed, err := url.Parse(strings.ToLower(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host != "pkgs.tailscale.com" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" || path.Dir(parsed.Path) != "/stable" {
		return false
	}
	name := path.Base(parsed.Path)
	if !strings.HasPrefix(name, "tailscale_") || !strings.HasSuffix(name, "_amd64.tgz") {
		return false
	}
	version := strings.TrimSuffix(strings.TrimPrefix(name, "tailscale_"), "_amd64.tgz")
	return versionPattern.MatchString(version)
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func exactUTCSecond(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}
