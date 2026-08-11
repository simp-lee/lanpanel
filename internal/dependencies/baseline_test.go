package dependencies

import (
	"slices"
	"testing"
	"time"
)

func TestDependencyBaselinePinsExactLatestStableSelections(t *testing.T) {
	cutoff := time.Unix(1_700_000_000, 0).UTC()
	selection, err := SelectLatestStable("headscale", "https://api.example.test/releases", digest("metadata-snapshot"), cutoff, []PublishedRelease{
		{Version: "0.26.0-rc1", PublishedAt: cutoff.Add(-time.Hour), Prerelease: true, OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/headscale-0.26.0-rc1", ArtifactDigest: digest("rc")},
		{Version: "0.25.1", PublishedAt: cutoff.Add(-2 * time.Hour), OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/headscale-0.25.1", ArtifactDigest: digest("new")},
		{Version: "0.25.0", PublishedAt: cutoff.Add(-24 * time.Hour), OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/headscale-0.25.0", ArtifactDigest: digest("old")},
		{Version: "0.26.0", PublishedAt: cutoff.Add(time.Hour), OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/headscale-0.26.0", ArtifactDigest: digest("future")},
	})
	if err != nil || selection.SelectedVersion != "0.25.1" || selection.SelectedVersion != selection.LatestStableVersion {
		t.Fatalf("latest stable selection=%#v error=%v", selection, err)
	}

	baseline := testBaseline(cutoff)
	for index := range baseline.Selections {
		if baseline.Selections[index].Component == "headscale" {
			baseline.Selections[index] = selection
		}
	}
	slices.SortFunc(baseline.Selections, func(left, right Selection) int {
		if left.Component < right.Component {
			return -1
		}
		if left.Component > right.Component {
			return 1
		}
		return 0
	})
	encoded, err := EncodeBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBaseline(encoded)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := BaselineDigest(baseline)
	second, _ := BaselineDigest(decoded)
	if first != second || !validDigest(first) {
		t.Fatalf("baseline digest mismatch %q %q", first, second)
	}
}

func TestDependencyBaselineRejectsDowngradeFloatingAndMissingClosure(t *testing.T) {
	baseline := testBaseline(time.Unix(1_700_000_000, 0).UTC())
	baseline.Selections[0].LatestStableVersion = "99.0.0"
	if err := ValidateBaseline(baseline); err == nil {
		t.Fatal("silent dependency downgrade was accepted")
	}
	baseline = testBaseline(time.Unix(1_700_000_000, 0).UTC())
	baseline.Selections[2].ArtifactIdentity = "https://downloads.example.test/releases/latest"
	if err := ValidateBaseline(baseline); err == nil {
		t.Fatal("floating latest artifact was accepted")
	}
	baseline = testBaseline(time.Unix(1_700_000_000, 0).UTC())
	baseline.Selections[1].ArtifactIdentity = "nginx=1.22.1-9@debian/bookworm-security"
	if err := ValidateBaseline(baseline); err == nil {
		t.Fatal("dependency component accepted another package artifact identity")
	}
	baseline = testBaseline(time.Unix(1_700_000_000, 0).UTC())
	if err := ValidateForOSProfile(baseline, digest("debian-12-profile"), "9.99.0"); err == nil {
		t.Fatal("Dependency Baseline Nginx version differed from the qualified profile")
	}
	baseline.Selections = baseline.Selections[1:]
	if err := ValidateBaseline(baseline); err == nil {
		t.Fatal("incomplete required dependency closure was accepted")
	}
}

func TestDependencyBaselineRejectsDraftOnlyOrUnpinnedSelection(t *testing.T) {
	cutoff := time.Unix(1_700_000_000, 0).UTC()
	if _, err := SelectLatestStable("lego", "https://api.example.test/releases", digest("metadata-snapshot"), cutoff, []PublishedRelease{{Version: "1.0.0", PublishedAt: cutoff.Add(-time.Hour), Draft: true, OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/lego-1.0.0", ArtifactDigest: digest("artifact")}}); err == nil {
		t.Fatal("draft-only upstream metadata produced a stable selection")
	}
	if _, err := SelectLatestStable("lego", "https://api.example.test/releases", digest("metadata-snapshot"), cutoff, []PublishedRelease{{Version: "1.0.0", PublishedAt: cutoff.Add(-time.Hour), OperatingSystem: "linux", Architecture: "arm64", ArtifactIdentity: "https://downloads.example.test/lego-1.0.0", ArtifactDigest: digest("artifact")}}); err == nil {
		t.Fatal("non-amd64 canonical artifact produced a baseline selection")
	}
	if _, err := SelectLatestStable("lego", "https://api.example.test/releases", digest("metadata-snapshot"), cutoff, []PublishedRelease{{Version: "1.0.0", PublishedAt: cutoff.Add(-time.Hour), OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/lego-latest.tar.gz", ArtifactDigest: digest("artifact")}}); err == nil {
		t.Fatal("floating latest filename produced a selection")
	}
	for _, alias := range []string{"https://api.example.test:443/releases", "https://api.example.test:/releases", "https://api.example.test/%72eleases", "https://api.example.test/releases?", "https://api.example.test./releases", "https://127.0.0.01/releases"} {
		if _, err := SelectLatestStable("lego", alias, digest("metadata-snapshot"), cutoff, []PublishedRelease{{Version: "1.0.0", PublishedAt: cutoff.Add(-time.Hour), OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/lego-1.0.0", ArtifactDigest: digest("artifact")}}); err == nil {
			t.Fatalf("noncanonical metadata URL alias %q was accepted", alias)
		}
	}
	if _, err := SelectLatestStable("lego", "https://api.example.test/releases", digest("metadata-snapshot"), cutoff, []PublishedRelease{{Version: "1.0.0", PublishedAt: cutoff.Add(-time.Hour), OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/lego-1.0.0", ArtifactDigest: digest("one")}, {Version: "1.0.1", PublishedAt: cutoff.Add(-time.Hour), OperatingSystem: "linux", Architecture: "amd64", ArtifactIdentity: "https://downloads.example.test/lego-1.0.1", ArtifactDigest: digest("two")}}); err == nil {
		t.Fatal("ambiguous upstream release ordering was accepted")
	}
}

func TestDistroSelectionUsesExactQualifiedRepositoryCandidate(t *testing.T) {
	cutoff := time.Unix(1_700_000_000, 0).UTC()
	selected, err := SelectDistroPackage("nginx", "https://snapshot.example.test/debian", digest("repo-snapshot"), digest("os-profile"), cutoff, []DistroPackageCandidate{{Version: "1.22.1-8", ArtifactIdentity: "nginx=1.22.1-8@debian/bookworm", ArtifactDigest: digest("old")}, {Version: "1.22.1-9", ArtifactIdentity: "nginx=1.22.1-9@debian/bookworm-security", ArtifactDigest: digest("candidate"), RepositoryCandidate: true}})
	if err != nil || selected.SelectedVersion != "1.22.1-9" || selected.OSProfileDigest != digest("os-profile") {
		t.Fatalf("distro selection=%#v error=%v", selected, err)
	}
	if _, err := SelectDistroPackage("nginx", "https://snapshot.example.test/debian", digest("repo-snapshot"), digest("os-profile"), cutoff, []DistroPackageCandidate{{Version: "1.22.1-8", ArtifactIdentity: "nginx=1.22.1-8@debian/bookworm", ArtifactDigest: digest("old"), RepositoryCandidate: true}, {Version: "1.22.1-9", ArtifactIdentity: "nginx=1.22.1-9@debian/bookworm-security", ArtifactDigest: digest("new"), RepositoryCandidate: true}}); err == nil {
		t.Fatal("multiple apt repository candidates were accepted")
	}
}

func testBaseline(cutoff time.Time) Baseline {
	published := cutoff.Add(-time.Hour)
	return Baseline{SchemaVersion: SchemaVersion, Cutoff: cutoff, Selections: []Selection{
		selection("apache2-utils", SourceDistroRepository, "2.4.62-1", "apache2-utils=2.4.62-1@debian/bookworm-security", published),
		selection("goaccess", SourceDistroRepository, "1.7-1", "goaccess=1.7-1@debian/bookworm", published),
		selection("headscale", SourceCanonicalArtifact, "0.25.1", "https://downloads.example.test/headscale-0.25.1", published),
		selection("lego", SourceCanonicalArtifact, "4.25.2", "https://downloads.example.test/lego-4.25.2", published),
		selection("nginx", SourceDistroRepository, "1.22.1-9", "nginx=1.22.1-9@debian/bookworm-security", published),
		selection("tailscale-client", SourceCanonicalArtifact, "1.82.0", "https://downloads.example.test/tailscale-1.82.0", published),
	}}
}

func selection(component string, sourceKind SourceKind, version, identity string, published time.Time) Selection {
	selected := Selection{Component: component, SourceKind: sourceKind, SelectedVersion: version, LatestStableVersion: version, LatestStablePublishedAt: published, MetadataSource: "https://metadata.example.test/releases", MetadataSnapshotDigest: digest("metadata-" + component), ArtifactIdentity: identity, ArtifactDigest: digest(component)}
	if sourceKind == SourceDistroRepository {
		selected.OSProfileDigest = digest("debian-12-profile")
	} else {
		selected.OperatingSystem = "linux"
		selected.Architecture = "amd64"
	}
	return selected
}

func digest(seed string) string {
	return digestBytes([]byte(seed))
}
