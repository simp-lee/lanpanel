package release

import "time"

const DependencyInputsSchemaVersion = "lanpanel.dependency-inputs.v2"

// DependencyInputAsset is an asset identity in the resolved dependency lock.
type DependencyInputAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  uint64 `json:"bytes"`
}

// DependencyInputSource identifies the upstream artifact before materialization.
type DependencyInputSource struct {
	URL    string               `json:"url"`
	Format string               `json:"format"`
	Asset  DependencyInputAsset `json:"asset"`
}

// DependencyInput is the complete v2 dependency lock entry shared by release
// building and profile capture. GoAccess is represented by an executable-only
// entry; its Archive identity is intentionally empty because the release
// carries the release-builder-produced binary.
type DependencyInput struct {
	Name           string                `json:"name"`
	Version        string                `json:"version"`
	MetadataSource string                `json:"metadata_source"`
	MetadataDigest string                `json:"metadata_digest"`
	PublishedAt    time.Time             `json:"published_at"`
	Source         DependencyInputSource `json:"source"`
	Archive        DependencyInputAsset  `json:"archive"`
	Executable     DependencyInputAsset  `json:"executable"`
	Member         string                `json:"member"`
}

// DependencyInputs is the canonical resolved dependency lock.
type DependencyInputs struct {
	SchemaVersion string            `json:"schema_version"`
	Dependencies  []DependencyInput `json:"dependencies"`
}
