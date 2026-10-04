// Package packages defines exact qualified apt/dpkg transaction authority.
package packages

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/debianversion"
	"lanpanel/internal/sources"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Mode string

const (
	DistroRepository Mode = "distro_repository"
	StagedDebs       Mode = "staged_debs"
	OfflineDebs      Mode = "offline_debs"
)

type AuthorityKind string

const (
	PreviewProfile AuthorityKind = "preview"
)

type Authority struct {
	Kind                           AuthorityKind `json:"kind"`
	ReleaseAuthorityDigest         string        `json:"release_authority_digest"`
	BinaryDigest                   string        `json:"binary_digest"`
	HostFingerprint                string        `json:"host_fingerprint"`
	TargetCapabilityContractDigest string        `json:"target_capability_contract_digest,omitempty"`
	// TargetOSProfileDigest is retained for journal replay compatibility.
	TargetOSProfileDigest string `json:"target_os_profile_digest,omitempty"`
}

type Package struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	VersionMinimum string `json:"version_minimum,omitempty"`
	VersionMaximum string `json:"version_maximum,omitempty"`
	Architecture   string `json:"architecture"`
	// RepositoryID optionally selects one repository within an explicit plan.
	RepositoryID string `json:"repository_id"`
	// RepositoryFilename is used only when an explicit repository plan supplies it.
	RepositoryFilename        string         `json:"repository_filename"`
	ArtifactDigest            string         `json:"artifact_digest"`
	ArtifactBytes             int64          `json:"artifact_bytes"`
	MaximumInstalledFileBytes int64          `json:"maximum_installed_file_bytes"`
	StagedIdentity            string         `json:"staged_identity,omitempty"`
	AffectedUnits             []string       `json:"affected_units"`
	PossibleListeners         []string       `json:"possible_listeners"`
	Source                    sources.Source `json:"source"`
}

type Repository struct {
	ID            string   `json:"id"`
	URI           string   `json:"uri"`
	Suite         string   `json:"suite"`
	Components    []string `json:"components"`
	KeyringPath   string   `json:"keyring_path"`
	KeyringDigest string   `json:"keyring_digest"`
	// MetadataDigest and CutoffDigest are diagnostic evidence only; they are not
	// release or installation authority.
	MetadataDigest string `json:"metadata_digest,omitempty"`
	CutoffDigest   string `json:"cutoff_digest,omitempty"`
}

type Plan struct {
	TransactionID            string    `json:"transaction_id"`
	JobID                    string    `json:"job_id"`
	IntentGeneration         uint64    `json:"intent_generation"`
	Deadline                 time.Time `json:"deadline"`
	CapabilityContractDigest string    `json:"capability_contract_digest,omitempty"`
	// OSProfileDigest is retained for journal replay compatibility.
	OSProfileDigest string `json:"os_profile_digest,omitempty"`
	Mode            Mode   `json:"mode"`
	// Public release plans never persist a proxy; a non-nil in-memory value is
	// rejected by ValidatePublicReleasePlan and strict decoders reject legacy JSON.
	Proxy        *sources.Proxy `json:"-"`
	Packages     []Package      `json:"packages"`
	Repositories []Repository   `json:"repositories"`
	// FirstNginxInstall is true only for a fresh LanPanel-owned Nginx
	// transaction. Internal transactions for an already committed LanPanel
	// installation set it false.
	// ExternalNginx records an explicit choice to reuse a compatible
	// pre-existing host Nginx package instead of mutating it. It is a mode
	// choice, not an OS-version exception: the installer removes Nginx from
	// the signed package closure and validates the host package by capability
	// range instead.
	FirstNginxInstall       bool          `json:"first_nginx_install"`
	ExternalNginx           bool          `json:"external_nginx,omitempty"`
	LockWait                time.Duration `json:"lock_wait"`
	ConnectTimeout          time.Duration `json:"connect_timeout"`
	ReadTimeout             time.Duration `json:"read_timeout"`
	TotalTimeout            time.Duration `json:"total_timeout"`
	NoNetwork               bool          `json:"no_network"`
	NoAutostartPolicyDigest string        `json:"no_autostart_policy_digest"`
	PreflightDigest         string        `json:"preflight_digest"`
	PreflightRequestDigest  string        `json:"preflight_request_digest"`
	Authority               Authority     `json:"authority"`
}

type ConfigKind string

const (
	APTConfig  ConfigKind = "apt_config"
	APTSource  ConfigKind = "apt_source"
	APTKeyring ConfigKind = "apt_keyring"
	DPKGConfig ConfigKind = "dpkg_config"
)

type ObservedConfig struct {
	Path        string
	Kind        ConfigKind
	UID         uint32
	GID         uint32
	Mode        uint32
	Regular     bool
	Linked      bool
	ParentsSafe bool
	Bytes       []byte
}

type RepositoryPackageBinding struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	Digest       string `json:"digest"`
}

type ObservedRepository struct {
	ID             string
	URI            string
	Suite          string
	Components     []string
	KeyringPath    string
	KeyringDigest  string
	MetadataDigest string
	CutoffDigest   string
	Enabled        bool
	// PackageBindings are derived only from the verified, signed Packages
	// indexes. They are evidence for the local postcondition, not plan input.
	PackageBindings []RepositoryPackageBinding `json:"package_bindings"`
}

type DPKGState struct {
	HalfConfigured  []string
	Unpacked        []string
	TriggersPending []string
	Broken          []string
}

type UnitState struct {
	Name   string
	Active bool
	Masked bool
}

type Listener struct {
	Protocol string
	Port     uint16
	Owner    string
}

type InstalledPackage struct {
	Name         string
	Version      string
	Architecture string
}

type RuntimeSnapshot struct {
	Installed      []Package
	SystemPackages []InstalledPackage
	Units          []UnitState
	Listeners      []Listener
}

type FileIdentity struct {
	Path        string
	UID         uint32
	GID         uint32
	Mode        uint32
	Regular     bool
	Linked      bool
	ParentsSafe bool
	Digest      string
}

type Postcondition struct {
	Repositories   []ObservedRepository
	Installed      []Package
	SystemPackages []InstalledPackage
	Units          []UnitState
	Listeners      []Listener
	RetainedMasks  []string
}

var (
	transactionPattern = regexp.MustCompile(`^pkg_[0-9a-f]{64}$`)
	jobPattern         = regexp.MustCompile(`^job_[0-9a-f]{64}$`)
	packageNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
	versionPattern     = regexp.MustCompile(`^[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	unitPattern        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,127}\.(?:service|socket|timer)$`)
	listenerPattern    = regexp.MustCompile(`^(?:tcp|udp)/[0-9]{1,5}$`)
	refPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	componentPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,63}$`)
	suitePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9+./_-]{0,127}$`)
)

// ValidateRepositories validates a complete, canonical repository authority set.
func ValidateRepositories(repositories []Repository) error {
	if len(repositories) == 0 {
		return fmt.Errorf("package repository authority set is empty")
	}
	return validateRepositories(repositories)
}

// ValidatePublicReleasePlan narrows the generic transaction validator to the
// user-configured APT source exposed by the public release contract.
func ValidatePublicReleasePlan(plan Plan) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if plan.ExternalNginx {
		return fmt.Errorf("public release package template cannot select external Nginx")
	}
	if plan.Mode != DistroRepository || plan.Proxy != nil || len(plan.Repositories) != 0 {
		return fmt.Errorf("public release package plan must use the host's authenticated APT sources")
	}
	for _, pkg := range plan.Packages {
		if pkg.Source.Kind != sources.OfficialDistro || pkg.Source.URL != "" || pkg.Source.OfflinePath != "" || len(pkg.Source.OfficialAuthorities) != 0 || pkg.RepositoryID != "" || pkg.RepositoryFilename != "" || pkg.VersionMinimum == "" && pkg.VersionMaximum == "" {
			return fmt.Errorf("public release package source is not a ranged host APT source")
		}
	}
	return nil
}

func ValidatePlan(plan Plan) error {
	contractDigest := plan.CapabilityContractDigest
	if contractDigest == "" {
		contractDigest = plan.OSProfileDigest
	}
	if !transactionPattern.MatchString(plan.TransactionID) || !jobPattern.MatchString(plan.JobID) || plan.IntentGeneration == 0 || plan.Deadline.IsZero() || !digestPattern.MatchString(contractDigest) || plan.LockWait <= 0 || plan.LockWait > 5*time.Minute || plan.LockWait%time.Second != 0 || plan.ConnectTimeout <= 0 || plan.ConnectTimeout > 5*time.Minute || plan.ConnectTimeout%time.Second != 0 || plan.ReadTimeout <= 0 || plan.ReadTimeout > 5*time.Minute || plan.ReadTimeout%time.Second != 0 || plan.TotalTimeout <= plan.LockWait || plan.TotalTimeout < plan.ConnectTimeout || plan.TotalTimeout < plan.ReadTimeout || plan.TotalTimeout > 30*time.Minute || len(plan.Packages) == 0 && (!plan.ExternalNginx || plan.Mode != DistroRepository) || len(plan.Packages) > 256 {
		return fmt.Errorf("package transaction identity, bounds, or OS profile are invalid")
	}
	if !digestPattern.MatchString(plan.NoAutostartPolicyDigest) || !strings.HasPrefix(plan.PreflightDigest, "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(plan.PreflightDigest, "sha256:")) || !strings.HasPrefix(plan.PreflightRequestDigest, "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(plan.PreflightRequestDigest, "sha256:")) {
		return fmt.Errorf("package no-autostart or shared preflight identity is invalid")
	}
	if err := sources.ValidateProxy(plan.Proxy); err != nil {
		return err
	}
	switch plan.Mode {
	case DistroRepository:
		if plan.NoNetwork {
			return fmt.Errorf("distro transaction cannot be offline")
		}
	case StagedDebs:
		if !plan.NoNetwork || len(plan.Repositories) != 0 || plan.Proxy != nil {
			return fmt.Errorf("staged deb transaction is not in the required no-network package phase")
		}
	case OfflineDebs:
		if !plan.NoNetwork || len(plan.Repositories) != 0 || plan.Proxy != nil {
			return fmt.Errorf("offline deb transaction is not in an explicit no-network profile")
		}
	default:
		return fmt.Errorf("package transaction mode is unknown")
	}
	if len(plan.Repositories) != 0 {
		if err := validateRepositories(plan.Repositories); err != nil {
			return err
		}
	}
	previous := ""
	repositoryIDs := make(map[string]bool, len(plan.Repositories))
	if plan.Mode == DistroRepository && len(plan.Repositories) == 0 {
		for _, pkg := range plan.Packages {
			if pkg.VersionMinimum == "" && pkg.VersionMaximum == "" {
				return fmt.Errorf("user APT package plan requires a version range")
			}
		}
	}
	for _, repository := range plan.Repositories {
		repositoryIDs[repository.ID] = true
	}
	hasNginx := false
	for _, pkg := range plan.Packages {
		if !packageNamePattern.MatchString(pkg.Name) || !versionPattern.MatchString(pkg.Version) || moving(pkg.Version) || pkg.VersionMinimum != "" && (!versionPattern.MatchString(pkg.VersionMinimum) || moving(pkg.VersionMinimum)) || pkg.VersionMaximum != "" && (!versionPattern.MatchString(pkg.VersionMaximum) || moving(pkg.VersionMaximum) || debianversion.Compare(pkg.VersionMinimum, pkg.VersionMaximum) >= 0) || pkg.Architecture != "amd64" && pkg.Architecture != "all" || pkg.RepositoryID != "" && (!refPattern.MatchString(pkg.RepositoryID) || !repositoryIDs[pkg.RepositoryID]) || plan.Mode == DistroRepository && len(plan.Repositories) != 0 && (pkg.RepositoryID == "" || pkg.RepositoryFilename == "") || plan.Mode != DistroRepository && pkg.RepositoryFilename != "" || pkg.RepositoryFilename != "" && !validRepositoryFilename(pkg.RepositoryFilename) || (plan.Mode != DistroRepository || len(plan.Repositories) != 0) && (!digestPattern.MatchString(pkg.ArtifactDigest) || pkg.ArtifactBytes <= 0 || pkg.ArtifactBytes > 4<<30) || pkg.MaximumInstalledFileBytes <= 0 || pkg.MaximumInstalledFileBytes > 4<<30 || previous != "" && strings.Compare(previous, pkg.Name) >= 0 {
			return fmt.Errorf("package closure is invalid, duplicated, floating, or unsorted")
		}
		if (plan.Mode == StagedDebs || plan.Mode == OfflineDebs) && pkg.StagedIdentity != "sha256:"+pkg.ArtifactDigest || plan.Mode == DistroRepository && pkg.StagedIdentity != "" {
			return fmt.Errorf("package staged identity does not match transaction mode")
		}
		if err := sources.Validate(pkg.Source); err != nil || pkg.Source.Artifact.Name != pkg.Name || pkg.Source.Artifact.Version != pkg.Version || pkg.Source.Artifact.OperatingOS != "linux" || pkg.Source.Artifact.Architecture != pkg.Architecture || (plan.Mode != DistroRepository || len(plan.Repositories) != 0) && pkg.Source.Artifact.Digest != pkg.ArtifactDigest || plan.Mode == DistroRepository && pkg.Source.Kind != sources.OfficialDistro || plan.Mode == StagedDebs && pkg.Source.Kind != sources.OfficialCanonical && pkg.Source.Kind != sources.Mirror || plan.Mode == OfflineDebs && pkg.Source.Kind != sources.Offline {
			return fmt.Errorf("package source does not match its exact artifact and transaction mode")
		}
		if err := validateSortedUnits(pkg.AffectedUnits); err != nil || validateListeners(pkg.PossibleListeners) != nil {
			return fmt.Errorf("package unit/listener closure is invalid")
		}
		if pkg.Name == "nginx" {
			hasNginx = true
		}
		previous = pkg.Name
	}
	if plan.ExternalNginx && plan.Mode != DistroRepository {
		return fmt.Errorf("external Nginx reuse requires a host APT plan")
	}
	if plan.ExternalNginx && plan.FirstNginxInstall {
		return fmt.Errorf("external Nginx mode cannot be a first-install transaction")
	}
	if plan.ExternalNginx && hasNginx {
		return fmt.Errorf("external Nginx package closure must omit nginx")
	}
	if plan.FirstNginxInstall && !hasNginx {
		return fmt.Errorf("first Nginx package closure omits nginx")
	}
	authorityContractDigest := plan.Authority.TargetCapabilityContractDigest
	if authorityContractDigest == "" {
		authorityContractDigest = plan.Authority.TargetOSProfileDigest
	}
	if plan.Authority.Kind != PreviewProfile || !digestPattern.MatchString(plan.Authority.ReleaseAuthorityDigest) || !digestPattern.MatchString(plan.Authority.BinaryDigest) || !refPattern.MatchString(plan.Authority.HostFingerprint) || authorityContractDigest != contractDigest {
		return fmt.Errorf("package authority does not match the install identity")
	}
	return nil
}

// ValidateAPTConfigurationBasic checks functional APT/dpkg prerequisites
// without requiring the host's pre-existing mirror or repository metadata to
// match a release transaction plan.
func ValidateAPTConfigurationBasic(files []ObservedConfig, repositories []ObservedRepository) error {
	if _, err := validateAPTConfigurationFiles(files); err != nil {
		return err
	}
	if len(repositories) > 16 {
		return fmt.Errorf("APT repository configuration is unbounded")
	}
	for _, repository := range repositories {
		if !repository.Enabled || repository.URI == "" || repository.Suite == "" {
			return fmt.Errorf("APT repository configuration is incomplete")
		}
	}
	return nil
}

func ValidateAPTConfiguration(files []ObservedConfig, repositories []ObservedRepository, expected []Repository) error {
	if len(expected) == 0 {
		return ValidateAPTConfigurationBasic(files, repositories)
	}
	observedKeyrings, err := validateAPTConfigurationFiles(files)
	if err != nil {
		return err
	}
	if err := validateRepositoryObservations(repositories, expected); err != nil {
		return err
	}
	for index := range repositories {
		want := expected[index]
		if observedKeyrings[want.KeyringPath] != want.KeyringDigest {
			return fmt.Errorf("active repository keyring bytes differ from the package Plan")
		}
	}
	return nil
}

func validateAPTConfigurationFiles(files []ObservedConfig) (map[string]string, error) {
	if len(files) == 0 || len(files) > 1024 {
		return nil, fmt.Errorf("APT/dpkg configuration inventory is empty or unbounded")
	}
	previous := ""
	observedKeyrings := map[string]string{}
	for _, file := range files {
		if !validConfigPath(file.Kind, file.Path) || file.UID != 0 || file.GID != 0 || file.Mode&0o022 != 0 || !file.Regular || file.Linked || !file.ParentsSafe || len(file.Bytes) > 1<<20 || previous != "" && strings.Compare(previous, file.Path) >= 0 {
			return nil, fmt.Errorf("APT/dpkg configuration path, owner, type, mode, parent, or order is unsafe")
		}
		if file.Kind == APTKeyring {
			digest := sha256.Sum256(file.Bytes)
			observedKeyrings[file.Path] = hex.EncodeToString(digest[:])
		} else if forbiddenAPTConfiguration(file.Bytes) {
			return nil, fmt.Errorf("APT/dpkg configuration contains an unsafe executable override or unauthenticated option")
		}
		previous = file.Path
	}
	return observedKeyrings, nil
}

func validateRepositoryObservations(observed []ObservedRepository, expected []Repository) error {
	if len(observed) != len(expected) {
		return fmt.Errorf("active repository closure differs from the package Plan")
	}
	for index, repository := range observed {
		want := expected[index]
		if !repository.Enabled || repository.ID != want.ID || repository.URI != want.URI || repository.Suite != want.Suite || !slices.Equal(repository.Components, want.Components) || repository.KeyringPath != want.KeyringPath || repository.KeyringDigest != want.KeyringDigest {
			return fmt.Errorf("active repository, keyring, metadata, or cutoff identity differs from the package Plan")
		}
	}
	return nil
}

func ValidateDPKGReady(state DPKGState) error {
	if len(state.HalfConfigured) != 0 || len(state.Unpacked) != 0 || len(state.TriggersPending) != 0 || len(state.Broken) != 0 {
		return fmt.Errorf("dpkg has unresolved half-configured, unpacked, trigger, or broken state")
	}
	return nil
}

func ValidatePostcondition(plan Plan, before RuntimeSnapshot, observed Postcondition, createdMasks []string) error {
	if err := ValidatePlan(plan); err != nil {
		return fmt.Errorf("package postcondition plan authority is invalid")
	}
	if len(plan.Repositories) != 0 {
		if err := validateRepositoryObservations(observed.Repositories, plan.Repositories); err != nil {
			return fmt.Errorf("package postcondition repository authority is invalid: %w", err)
		}
	}
	if err := validateInstalledRepositoryBindings(plan, observed.Repositories, observed.Installed); err != nil {
		return fmt.Errorf("package postcondition package repository authority is invalid: %w", err)
	}
	if !reflectPackages(observed.Installed, plan.Packages) {
		return fmt.Errorf("package postcondition has unexpected package closure")
	}
	if err := validateRuntime(before); err != nil || errRuntime(observed.Units, observed.Listeners) != nil {
		return fmt.Errorf("package runtime observation is invalid or unsafe")
	}
	if len(observed.Units) != len(before.Units) {
		return fmt.Errorf("package transaction changed the observed unit inventory")
	}
	for index, unit := range observed.Units {
		prior := before.Units[index]
		if unit.Name != prior.Name || unit.Active != prior.Active {
			return fmt.Errorf("package transaction activated, stopped, added, or removed a unit")
		}
		if slices.Contains(createdMasks, unit.Name) {
			if !unit.Masked || prior.Masked {
				return fmt.Errorf("transaction-created package mask is missing or was preexisting")
			}
		} else if slices.Contains(affectedUnits(plan.Packages), unit.Name) {
			if !unit.Masked || !prior.Masked {
				return fmt.Errorf("preexisting package mask was not retained")
			}
		} else if unit.Masked != prior.Masked {
			return fmt.Errorf("package transaction changed an unrelated unit mask")
		}
	}
	if err := validateSystemPackageDelta(before.SystemPackages, observed.SystemPackages, plan.Packages); err != nil {
		return err
	}
	if !slices.Equal(observed.Listeners, before.Listeners) {
		return fmt.Errorf("package transaction created, removed, or rebound a listener")
	}
	expectedMasks := affectedUnits(plan.Packages)
	if !slices.Equal(observed.RetainedMasks, expectedMasks) {
		return fmt.Errorf("package transaction did not retain its exact safety masks through verification")
	}
	return nil
}

func validateInstalledRepositoryBindings(plan Plan, repositories []ObservedRepository, installed []Package) error {
	if plan.Mode != DistroRepository || len(plan.Repositories) == 0 {
		return nil
	}
	for _, pkg := range installed {
		if _, err := repositoryPackageBinding(pkg, repositories); err != nil {
			return err
		}
	}
	return nil
}

func repositoryPackageBinding(pkg Package, repositories []ObservedRepository) (RepositoryPackageBinding, error) {
	repositoryID := pkg.RepositoryID
	if repositoryID == "" && len(repositories) == 1 {
		repositoryID = repositories[0].ID
	}
	matches := []RepositoryPackageBinding{}
	for _, repository := range repositories {
		if repository.ID != repositoryID {
			continue
		}
		for _, binding := range repository.PackageBindings {
			if !packageBindingIdentityValid(binding) {
				continue
			}
			if binding.Name == pkg.Name && binding.Version == pkg.Version && binding.Architecture == pkg.Architecture && binding.Size == pkg.ArtifactBytes && binding.Digest == pkg.ArtifactDigest && (pkg.RepositoryFilename == "" || binding.Filename == pkg.RepositoryFilename) {
				matches = append(matches, binding)
			}
		}
	}
	if len(matches) != 1 {
		return RepositoryPackageBinding{}, fmt.Errorf("package %s=%s/%s has %d signed repository bindings", pkg.Name, pkg.Version, pkg.Architecture, len(matches))
	}
	return matches[0], nil
}

func packageBindingIdentityValid(binding RepositoryPackageBinding) bool {
	return packageNamePattern.MatchString(binding.Name) && versionPattern.MatchString(binding.Version) && !moving(binding.Version) && (binding.Architecture == "amd64" || binding.Architecture == "all") && validRepositoryFilename(binding.Filename) && binding.Size > 0 && binding.Size <= 4<<30 && digestPattern.MatchString(binding.Digest)
}

func validateObservedRepositoryAuthorities(repositories []ObservedRepository, keyrings map[string][]byte) error {
	if len(repositories) == 0 || len(repositories) > 16 {
		return fmt.Errorf("APT repository configuration is empty or unbounded")
	}
	seenLocation := map[string]bool{}
	trustedKeyrings := 0
	for path, keyring := range keyrings {
		if (path == "/etc/apt/trusted.gpg" || strings.HasPrefix(path, "/etc/apt/trusted.gpg.d/")) && len(keyring) != 0 {
			trustedKeyrings++
		}
	}
	for _, repository := range repositories {
		parsed, err := url.Parse(repository.URI)
		location := repository.URI + "\x00" + repository.Suite
		keyringApproved := repository.KeyringPath == "" && trustedKeyrings != 0 || cleanRootFile(repository.KeyringPath) && (strings.HasPrefix(repository.KeyringPath, "/etc/apt/") || strings.HasPrefix(repository.KeyringPath, "/usr/share/keyrings/")) && len(keyrings[repository.KeyringPath]) != 0
		if !repository.Enabled || err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path == "" || parsed.RawPath != "" || parsed.String() != repository.URI || !suitePattern.MatchString(repository.Suite) || len(repository.Components) == 0 || len(repository.Components) > 32 || !keyringApproved || seenLocation[location] {
			return fmt.Errorf("APT repository authority is invalid, duplicated, or missing its approved keyring")
		}
		seenLocation[location] = true
		seenComponents := map[string]bool{}
		for _, component := range repository.Components {
			if !componentPattern.MatchString(component) || seenComponents[component] {
				return fmt.Errorf("APT repository components are invalid or duplicated")
			}
			seenComponents[component] = true
		}
	}
	return nil
}

func validateRepositories(repositories []Repository) error {
	if len(repositories) > 16 {
		return fmt.Errorf("package repository authority set is unbounded")
	}
	previous := ""
	seenLocation := map[string]bool{}
	for _, repository := range repositories {
		parsed, err := url.Parse(repository.URI)
		location := repository.URI + "\x00" + repository.Suite
		if !refPattern.MatchString(repository.ID) || err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path == "" || parsed.RawPath != "" || parsed.String() != repository.URI || !suitePattern.MatchString(repository.Suite) || len(repository.Components) == 0 || len(repository.Components) > 32 || !cleanRootFile(repository.KeyringPath) || !strings.HasPrefix(repository.KeyringPath, "/etc/apt/") && !strings.HasPrefix(repository.KeyringPath, "/usr/share/keyrings/") || !digestPattern.MatchString(repository.KeyringDigest) || previous != "" && strings.Compare(previous, repository.ID) >= 0 || seenLocation[location] {
			return fmt.Errorf("package repository authority is invalid, duplicated, or unsorted")
		}
		seenComponents := map[string]bool{}
		for _, component := range repository.Components {
			if !componentPattern.MatchString(component) || seenComponents[component] {
				return fmt.Errorf("package repository components are invalid or duplicated")
			}
			seenComponents[component] = true
		}
		seenLocation[location] = true
		previous = repository.ID
	}
	return nil
}

func validRepositoryFilename(value string) bool {
	if value == "" || len(value) > 1024 || !strings.HasSuffix(value, ".deb") || strings.ContainsAny(value, "\x00\r\n\\") || strings.HasPrefix(value, "/") {
		return false
	}
	clean := path.Clean(value)
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func validConfigPath(kind ConfigKind, value string) bool {
	if !cleanRootFile(value) {
		return false
	}
	switch kind {
	case APTConfig:
		return value == "/etc/apt/apt.conf" || strings.HasPrefix(value, "/etc/apt/apt.conf.d/") || value == "/etc/apt/auth.conf" || strings.HasPrefix(value, "/etc/apt/auth.conf.d/") || value == "/etc/apt/preferences" || strings.HasPrefix(value, "/etc/apt/preferences.d/")
	case APTSource:
		return value == "/etc/apt/sources.list" || strings.HasPrefix(value, "/etc/apt/sources.list.d/")
	case APTKeyring:
		return value == "/etc/apt/trusted.gpg" || strings.HasPrefix(value, "/etc/apt/trusted.gpg.d/") || strings.HasPrefix(value, "/etc/apt/keyrings/") || strings.HasPrefix(value, "/usr/share/keyrings/")
	case DPKGConfig:
		return value == "/etc/dpkg/dpkg.cfg" || strings.HasPrefix(value, "/etc/dpkg/dpkg.cfg.d/")
	default:
		return false
	}
}

func forbiddenAPTMetadataRefreshConfiguration(data []byte) bool {
	lower := strings.ToLower(string(data))
	for _, directive := range []string{"#include", "#clear", "#if", "rootdir", "proxy-auto-detect"} {
		if strings.Contains(lower, directive) {
			return true
		}
	}
	words := aptConfigurationWords(data)
	for index, word := range words {
		if word != "dir" {
			continue
		}
		if index+2 >= len(words) {
			return true
		}
		// These are the only standard Dir namespaces that do not affect
		// repository metadata: Debian's CD mount path and apt-listchanges'
		// own configuration paths. Dir::Etc/State/Cache redirects remain
		// blocked because the refresh and auditor use fixed paths.
		switch words[index+1] {
		case "media":
			if words[index+2] != "mountpath" {
				return true
			}
		case "etc":
			if words[index+2] != "apt-listchanges-main" && words[index+2] != "apt-listchanges-parts" {
				return true
			}
		default:
			return true
		}
	}
	for index := 0; index+2 < len(words); index++ {
		if words[index] == "apt" && words[index+1] == "update" && strings.Contains(words[index+2], "invoke") {
			return true
		}
	}
	return false
}

func aptConfigurationWords(data []byte) []string {
	lower := strings.ToLower(string(data))
	words := []string{}
	var token strings.Builder
	flush := func() {
		if token.Len() != 0 {
			words = append(words, token.String())
			token.Reset()
		}
	}
	for _, character := range lower {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			token.WriteRune(character)
		} else {
			flush()
		}
	}
	flush()
	return words
}

func forbiddenAPTConfiguration(data []byte) bool {
	lower := strings.ToLower(string(data))
	if strings.ContainsAny(lower, "\x00\r") {
		return true
	}
	if strings.Contains(lower, "admindir") || strings.Contains(lower, "instdir") || strings.Contains(lower, "check-valid-until") && strings.Contains(lower, "false") || strings.Contains(lower, "apt::update::pre-invoke") || strings.Contains(lower, "apt::update::post-invoke") {
		return true
	}
	words := aptConfigurationWords(data)
	for _, word := range words {
		if word == "proxy-auto-detect" || word == "allowunauthenticated" || word == "allowinsecurerepositories" || word == "allow-downgrades" || word == "force-yes" || word == "force-confnew" || word == "admindir" || word == "instdir" {
			return true
		}
	}
	for index := 0; index+1 < len(words); index++ {
		if words[index] == "dir" && words[index+1] == "bin" {
			return true
		}
	}
	return false
}

func validateSortedUnits(units []string) error {
	previous := ""
	for _, unit := range units {
		if !unitPattern.MatchString(unit) || previous != "" && strings.Compare(previous, unit) >= 0 {
			return fmt.Errorf("unit closure is invalid")
		}
		previous = unit
	}
	return nil
}

func validateListeners(listeners []string) error {
	previous := ""
	for _, listener := range listeners {
		_, portText, _ := strings.Cut(listener, "/")
		port, parseErr := strconv.Atoi(portText)
		if !listenerPattern.MatchString(listener) || parseErr != nil || port <= 0 || port > 65535 || previous != "" && strings.Compare(previous, listener) >= 0 {
			return fmt.Errorf("listener closure is invalid")
		}
		previous = listener
	}
	return nil
}

func validateRuntime(snapshot RuntimeSnapshot) error {
	if err := validateInstalledPackages(snapshot.SystemPackages); err != nil {
		return err
	}
	return errRuntime(snapshot.Units, snapshot.Listeners)
}

func validateInstalledPackages(packages []InstalledPackage) error {
	previous := ""
	for _, pkg := range packages {
		if !packageNamePattern.MatchString(pkg.Name) || !versionPattern.MatchString(pkg.Version) || pkg.Architecture == "" || len(pkg.Architecture) > 32 || previous != "" && strings.Compare(previous, pkg.Name) >= 0 {
			return fmt.Errorf("installed package inventory is invalid, duplicated, or unsorted")
		}
		previous = pkg.Name
	}
	return nil
}

// PackageVersionMatches reports whether an observed Debian version satisfies
// the public package requirement. A package without bounds retains exact
// version semantics for staged and existing transaction callers.
func PackageVersionMatches(pkg Package, observed string) bool {
	if pkg.VersionMinimum != "" || pkg.VersionMaximum != "" {
		return debianversion.Satisfies(observed, pkg.VersionMinimum, pkg.VersionMaximum)
	}
	return observed == pkg.Version
}

func validateSystemPackageDelta(before, after []InstalledPackage, planned []Package) error {
	if err := validateInstalledPackages(before); err != nil {
		return err
	}
	if err := validateInstalledPackages(after); err != nil {
		return err
	}
	prior := map[string]InstalledPackage{}
	current := map[string]InstalledPackage{}
	for _, pkg := range before {
		prior[pkg.Name] = pkg
	}
	for _, pkg := range after {
		current[pkg.Name] = pkg
	}
	plannedNames := map[string]Package{}
	for _, pkg := range planned {
		plannedNames[pkg.Name] = pkg
		observed, exists := current[pkg.Name]
		if !exists || !PackageVersionMatches(pkg, observed.Version) || observed.Architecture != pkg.Architecture {
			return fmt.Errorf("planned package postcondition differs from dpkg inventory")
		}
	}
	flexible := false
	for _, pkg := range planned {
		flexible = flexible || pkg.VersionMinimum != "" || pkg.VersionMaximum != ""
	}
	if flexible {
		// Native APT may add transitive dependencies, but it must not mutate
		// unrelated packages that were already installed.
		for name, old := range prior {
			if _, planned := plannedNames[name]; planned {
				continue
			}
			if current[name] != old {
				return fmt.Errorf("package transaction changed an unexpected installed package")
			}
		}
		return nil
	}
	for name, old := range prior {
		if _, planned := plannedNames[name]; planned {
			continue
		}
		if current[name] != old {
			return fmt.Errorf("package transaction changed an unexpected installed package")
		}
	}
	for name := range current {
		if _, existed := prior[name]; !existed {
			if _, planned := plannedNames[name]; !planned {
				return fmt.Errorf("package transaction installed an unexpected package")
			}
		}
	}
	return nil
}

func errRuntime(units []UnitState, listeners []Listener) error {
	previous := ""
	for _, unit := range units {
		if !unitPattern.MatchString(unit.Name) || previous != "" && strings.Compare(previous, unit.Name) >= 0 {
			return fmt.Errorf("runtime unit inventory is invalid")
		}
		previous = unit.Name
	}
	previous = ""
	for _, listener := range listeners {
		identity := listener.Protocol + "/" + strconv.Itoa(int(listener.Port)) + "/" + listener.Owner
		if (listener.Protocol != "tcp" && listener.Protocol != "udp") || listener.Port == 0 || !refPattern.MatchString(listener.Owner) || previous != "" && strings.Compare(previous, identity) >= 0 {
			return fmt.Errorf("runtime listener inventory is invalid")
		}
		previous = identity
	}
	return nil
}

func hasPackage(packages []Package, name string) bool {
	for _, pkg := range packages {
		if pkg.Name == name {
			return true
		}
	}
	return false
}

func affectedUnits(packages []Package) []string {
	units := []string{}
	for _, pkg := range packages {
		units = append(units, pkg.AffectedUnits...)
	}
	slices.Sort(units)
	return slices.Compact(units)
}

func cleanRootFile(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsAny(value, "\x00\r\n")
}

func moving(value string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return (character < 'a' || character > 'z') && (character < '0' || character > '9')
	}) {
		if token == "latest" || token == "stable" {
			return true
		}
	}
	return false
}
