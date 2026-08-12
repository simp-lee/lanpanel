// Package packages defines exact qualified apt/dpkg transaction authority.
package packages

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"lanpanel/internal/sources"
)

type Mode string

const (
	DistroRepository Mode = "distro_repository"
	StagedDebs       Mode = "staged_debs"
	OfflineDebs      Mode = "offline_debs"
)

type AuthorityKind string

const (
	FinalSupportedProfile  AuthorityKind = "final_supported_profile"
	QualificationCandidate AuthorityKind = "qualification_candidate"
)

type QualificationAuthority struct {
	Kind                  AuthorityKind `json:"kind"`
	EnvelopeDigest        string        `json:"envelope_digest"`
	BinaryDigest          string        `json:"binary_digest"`
	RunID                 string        `json:"run_id,omitempty"`
	ManifestDigest        string        `json:"manifest_digest,omitempty"`
	HostFingerprint       string        `json:"host_fingerprint"`
	CaseID                string        `json:"case_id,omitempty"`
	Operation             string        `json:"operation"`
	TargetOSProfileDigest string        `json:"target_os_profile_digest"`
	FrozenClosureDigest   string        `json:"frozen_closure_digest"`
}

type Package struct {
	Name                      string         `json:"name"`
	Version                   string         `json:"version"`
	Architecture              string         `json:"architecture"`
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
}

type Plan struct {
	TransactionID           string                 `json:"transaction_id"`
	JobID                   string                 `json:"job_id"`
	IntentGeneration        uint64                 `json:"intent_generation"`
	Deadline                time.Time              `json:"deadline"`
	OSProfileDigest         string                 `json:"os_profile_digest"`
	Mode                    Mode                   `json:"mode"`
	Proxy                   *sources.Proxy         `json:"proxy,omitempty"`
	Packages                []Package              `json:"packages"`
	Repositories            []Repository           `json:"repositories"`
	FirstNginxInstall       bool                   `json:"first_nginx_install"`
	LockWait                time.Duration          `json:"lock_wait"`
	ConnectTimeout          time.Duration          `json:"connect_timeout"`
	ReadTimeout             time.Duration          `json:"read_timeout"`
	TotalTimeout            time.Duration          `json:"total_timeout"`
	NoNetwork               bool                   `json:"no_network"`
	NoAutostartPolicyDigest string                 `json:"no_autostart_policy_digest"`
	Authority               QualificationAuthority `json:"authority"`
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

type ObservedRepository struct {
	ID            string
	URI           string
	Suite         string
	Components    []string
	KeyringPath   string
	KeyringDigest string
	Enabled       bool
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
	Installed      []Package
	SystemPackages []InstalledPackage
	Units          []UnitState
	Listeners      []Listener
	RetainedMasks  []string
	HTPasswd       *FileIdentity
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

func ValidatePlan(plan Plan) error {
	if !transactionPattern.MatchString(plan.TransactionID) || !jobPattern.MatchString(plan.JobID) || plan.IntentGeneration == 0 || plan.Deadline.IsZero() || !digestPattern.MatchString(plan.OSProfileDigest) || plan.LockWait <= 0 || plan.LockWait > 5*time.Minute || plan.LockWait%time.Second != 0 || plan.ConnectTimeout <= 0 || plan.ConnectTimeout > 5*time.Minute || plan.ConnectTimeout%time.Second != 0 || plan.ReadTimeout <= 0 || plan.ReadTimeout > 5*time.Minute || plan.ReadTimeout%time.Second != 0 || plan.TotalTimeout <= plan.LockWait || plan.TotalTimeout < plan.ConnectTimeout || plan.TotalTimeout < plan.ReadTimeout || plan.TotalTimeout > 30*time.Minute || len(plan.Packages) == 0 || len(plan.Packages) > 256 {
		return fmt.Errorf("package transaction identity, bounds, or OS profile are invalid")
	}
	if !digestPattern.MatchString(plan.NoAutostartPolicyDigest) {
		return fmt.Errorf("package no-autostart policy identity is invalid")
	}
	if err := sources.ValidateProxy(plan.Proxy); err != nil {
		return err
	}
	switch plan.Mode {
	case DistroRepository:
		if plan.NoNetwork || len(plan.Repositories) == 0 {
			return fmt.Errorf("distro transaction lacks exact network repository authority")
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
	if err := validateRepositories(plan.Repositories); err != nil {
		return err
	}
	previous := ""
	hasNginx, hasApacheUtils := false, false
	for _, pkg := range plan.Packages {
		if !packageNamePattern.MatchString(pkg.Name) || !versionPattern.MatchString(pkg.Version) || moving(pkg.Version) || pkg.Architecture != "amd64" && pkg.Architecture != "all" || !digestPattern.MatchString(pkg.ArtifactDigest) || pkg.ArtifactBytes <= 0 || pkg.ArtifactBytes > 4<<30 || pkg.MaximumInstalledFileBytes <= 0 || pkg.MaximumInstalledFileBytes > 4<<30 || previous != "" && strings.Compare(previous, pkg.Name) >= 0 {
			return fmt.Errorf("package closure is invalid, duplicated, floating, or unsorted")
		}
		if (plan.Mode == StagedDebs || plan.Mode == OfflineDebs) && pkg.StagedIdentity != "sha256:"+pkg.ArtifactDigest || plan.Mode == DistroRepository && pkg.StagedIdentity != "" {
			return fmt.Errorf("package staged identity does not match transaction mode")
		}
		if err := sources.Validate(pkg.Source); err != nil || pkg.Source.Artifact.Name != pkg.Name || pkg.Source.Artifact.Version != pkg.Version || pkg.Source.Artifact.OperatingOS != "linux" || pkg.Source.Artifact.Architecture != pkg.Architecture || pkg.Source.Artifact.Digest != pkg.ArtifactDigest || plan.Mode == DistroRepository && pkg.Source.Kind != sources.OfficialDistro || plan.Mode == StagedDebs && pkg.Source.Kind != sources.OfficialCanonical && pkg.Source.Kind != sources.Mirror || plan.Mode == OfflineDebs && pkg.Source.Kind != sources.Offline {
			return fmt.Errorf("package source does not match its exact artifact and transaction mode")
		}
		if err := validateSortedUnits(pkg.AffectedUnits); err != nil || validateListeners(pkg.PossibleListeners) != nil {
			return fmt.Errorf("package unit/listener closure is invalid")
		}
		if pkg.Name == "apache2-utils" {
			hasApacheUtils = true
			if len(pkg.AffectedUnits) != 0 || len(pkg.PossibleListeners) != 0 {
				return fmt.Errorf("apache2-utils transaction would activate an Apache unit or listener")
			}
		} else if strings.HasPrefix(pkg.Name, "apache2") {
			return fmt.Errorf("package closure contains an Apache HTTP Server package")
		}
		if pkg.Name == "nginx" {
			hasNginx = true
		}
		previous = pkg.Name
	}
	if plan.FirstNginxInstall && (!hasNginx || !hasApacheUtils) {
		return fmt.Errorf("first Nginx package closure omits nginx or apache2-utils")
	}
	closureDigest, err := ClosureDigest(plan.Packages)
	if err != nil || closureDigest != plan.Authority.FrozenClosureDigest || plan.Authority.TargetOSProfileDigest != plan.OSProfileDigest || plan.Authority.Operation != "package_transaction" || !digestPattern.MatchString(plan.Authority.EnvelopeDigest) || !digestPattern.MatchString(plan.Authority.BinaryDigest) || !refPattern.MatchString(plan.Authority.HostFingerprint) {
		return fmt.Errorf("package qualification authority does not bind the exact closure and host profile")
	}
	switch plan.Authority.Kind {
	case FinalSupportedProfile:
		if plan.Authority.RunID != "" || plan.Authority.ManifestDigest != "" || plan.Authority.CaseID != "" {
			return fmt.Errorf("final supported package authority carries candidate-only fields")
		}
	case QualificationCandidate:
		if !refPattern.MatchString(plan.Authority.RunID) || !digestPattern.MatchString(plan.Authority.ManifestDigest) || !refPattern.MatchString(plan.Authority.CaseID) {
			return fmt.Errorf("qualification candidate package authority is incomplete")
		}
	default:
		return fmt.Errorf("package qualification authority kind is unknown")
	}
	return nil
}

func ClosureDigest(packages []Package) (string, error) {
	data, err := json.Marshal(packages)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func ValidateAPTConfiguration(files []ObservedConfig, repositories []ObservedRepository, expected []Repository) error {
	if len(files) == 0 || len(files) > 1024 {
		return fmt.Errorf("APT/dpkg configuration inventory is empty or unbounded")
	}
	previous := ""
	observedKeyrings := map[string]string{}
	for _, file := range files {
		if !validConfigPath(file.Kind, file.Path) || file.UID != 0 || file.GID != 0 || file.Mode&0o022 != 0 || !file.Regular || file.Linked || !file.ParentsSafe || len(file.Bytes) > 1<<20 || previous != "" && strings.Compare(previous, file.Path) >= 0 {
			return fmt.Errorf("APT/dpkg configuration path, owner, type, mode, parent, or order is unsafe")
		}
		if file.Kind == APTKeyring {
			digest := sha256.Sum256(file.Bytes)
			observedKeyrings[file.Path] = hex.EncodeToString(digest[:])
		} else if forbiddenAPTConfiguration(file.Bytes) {
			return fmt.Errorf("APT/dpkg configuration contains a hook, executable override, ambient proxy, or dangerous option")
		}
		previous = file.Path
	}
	if len(repositories) != len(expected) {
		return fmt.Errorf("active repository closure differs from the package Plan")
	}
	for index, repository := range repositories {
		want := expected[index]
		if !repository.Enabled || repository.ID != want.ID || repository.URI != want.URI || repository.Suite != want.Suite || !slices.Equal(repository.Components, want.Components) || repository.KeyringPath != want.KeyringPath || repository.KeyringDigest != want.KeyringDigest || observedKeyrings[want.KeyringPath] != want.KeyringDigest {
			return fmt.Errorf("active repository or keyring identity differs from the package Plan")
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
	if err := ValidatePlan(plan); err != nil || !reflectPackages(observed.Installed, plan.Packages) {
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
	if hasPackage(plan.Packages, "apache2-utils") {
		if observed.HTPasswd == nil || observed.HTPasswd.Path != "/usr/bin/htpasswd" || observed.HTPasswd.UID != 0 || observed.HTPasswd.GID != 0 || observed.HTPasswd.Mode&0o022 != 0 || !observed.HTPasswd.Regular || observed.HTPasswd.Linked || !observed.HTPasswd.ParentsSafe || !digestPattern.MatchString(observed.HTPasswd.Digest) {
			return fmt.Errorf("apache2-utils did not produce a safe exact htpasswd executable")
		}
	} else if observed.HTPasswd != nil {
		return fmt.Errorf("package postcondition contains unexpected htpasswd authority")
	}
	return nil
}

func validateRepositories(repositories []Repository) error {
	previous := ""
	for _, repository := range repositories {
		parsed, err := url.Parse(repository.URI)
		if !refPattern.MatchString(repository.ID) || err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path == "" || parsed.RawPath != "" || parsed.String() != repository.URI || !suitePattern.MatchString(repository.Suite) || len(repository.Components) == 0 || len(repository.Components) > 32 || !cleanRootFile(repository.KeyringPath) || !strings.HasPrefix(repository.KeyringPath, "/etc/apt/") || !digestPattern.MatchString(repository.KeyringDigest) || previous != "" && strings.Compare(previous, repository.ID) >= 0 {
			return fmt.Errorf("package repository authority is invalid, duplicated, or unsorted")
		}
		componentPrevious := ""
		for _, component := range repository.Components {
			if !componentPattern.MatchString(component) || componentPrevious != "" && strings.Compare(componentPrevious, component) >= 0 {
				return fmt.Errorf("package repository components are invalid, duplicated, or unsorted")
			}
			componentPrevious = component
		}
		previous = repository.ID
	}
	return nil
}

func validConfigPath(kind ConfigKind, value string) bool {
	if !cleanRootFile(value) {
		return false
	}
	switch kind {
	case APTConfig:
		return value == "/etc/apt/apt.conf" || strings.HasPrefix(value, "/etc/apt/apt.conf.d/")
	case APTSource:
		return value == "/etc/apt/sources.list" || strings.HasPrefix(value, "/etc/apt/sources.list.d/")
	case APTKeyring:
		return value == "/etc/apt/trusted.gpg" || strings.HasPrefix(value, "/etc/apt/trusted.gpg.d/") || strings.HasPrefix(value, "/etc/apt/keyrings/")
	case DPKGConfig:
		return value == "/etc/dpkg/dpkg.cfg" || strings.HasPrefix(value, "/etc/dpkg/dpkg.cfg.d/")
	default:
		return false
	}
}

func forbiddenAPTConfiguration(data []byte) bool {
	lower := strings.ToLower(string(data))
	if strings.ContainsAny(lower, "\x00\r") {
		return true
	}
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
	for index, word := range words {
		if word == "pre-invoke" || word == "post-invoke" || word == "pre-install-pkgs" || word == "proxy-auto-detect" || word == "allowunauthenticated" || word == "allowinsecurerepositories" || word == "allow-downgrades" || word == "force-yes" || word == "force-confnew" {
			return true
		}
		if index > 0 && (words[index-1] == "http" || words[index-1] == "https" || words[index-1] == "ftp") && word == "proxy" {
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
		if !exists || observed.Version != pkg.Version || observed.Architecture != pkg.Architecture {
			return fmt.Errorf("planned package postcondition differs from dpkg inventory")
		}
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
