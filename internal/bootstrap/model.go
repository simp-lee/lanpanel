//go:build linux

// Package bootstrap implements the one closed clean-install root phase.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/identity"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	JournalSchemaVersion             = "lanpanel.bootstrap.journal.v3"
	BundleSchemaVersion              = "lanpanel.installation.bundle.v2"
	CommitSchemaVersion              = "lanpanel.bootstrap.commit.v1"
	MaximumJournalBytes              = 4 << 20
	maximumPublicInstallerInputBytes = 1 << 20
)

type Phase string

const (
	PhasePrepared          Phase = "prepared"
	PhaseNginxMasked       Phase = "nginx_masked"
	PhasePackagesCommitted Phase = "packages_committed"
	PhaseBundleCommitted   Phase = "bundle_committed"
	PhaseAccountsSubmitted Phase = "accounts_submitted"
	PhaseAccountsVerified  Phase = "accounts_verified"
	PhaseStoresInitialized Phase = "stores_initialized"
	PhaseAssetsInstalled   Phase = "assets_installed"
	PhaseCommitted         Phase = "committed"
	PhaseActivated         Phase = "activated"
)

type Paths struct {
	Journal          string `json:"journal"`
	StartupAuthority string `json:"startup_authority"`
	CommitPath       string `json:"commit_path"`
	PersistentRoot   string `json:"persistent_root"`
	InstallationRoot string `json:"installation_root"`
	ACMEAccountKey   string `json:"acme_account_key"`
	StateRoot        string `json:"state_root"`
	SafetyRoot       string `json:"safety_root"`
	OwnershipRoot    string `json:"ownership_root"`
	LockRoot         string `json:"lock_root"`
	PackageRoot      string `json:"package_root"`
	RuntimeRoot      string `json:"runtime_root"`
	SystemdRoot      string `json:"systemd_root"`
	SysusersPath     string `json:"sysusers_path"`
	BinaryPath       string `json:"binary_path"`
}

func FixedPaths() Paths {
	return Paths{
		Journal: "/var/lib/lanpanel.bootstrap-journal", StartupAuthority: "/etc/lanpanel/startup-authority.json", CommitPath: "/var/lib/lanpanel/bootstrap-commit.json", PersistentRoot: "/var/lib/lanpanel", InstallationRoot: "/var/lib/lanpanel/installation", ACMEAccountKey: acmeaccount.ManagedKeyPath,
		StateRoot: "/var/lib/lanpanel/state", SafetyRoot: "/var/lib/lanpanel/safety", OwnershipRoot: "/var/lib/lanpanel/ownership",
		LockRoot: "/var/lib/lanpanel/locks", PackageRoot: "/var/lib/lanpanel/packages", RuntimeRoot: "/run/lanpanel",
		SystemdRoot: "/etc/systemd/system", SysusersPath: "/etc/lanpanel-sysusers.conf", BinaryPath: "/usr/lib/lanpanel/lanpanel",
	}
}

type Journal struct {
	SchemaVersion          string                       `json:"schema_version"`
	AttemptID              string                       `json:"attempt_id"`
	InstallationID         string                       `json:"installation_id"`
	GenerationID           string                       `json:"generation_id"`
	SafetyGeneration       uint64                       `json:"safety_generation"`
	Phase                  Phase                        `json:"phase"`
	Sequence               uint64                       `json:"sequence"`
	Release                release.InstallIdentity      `json:"release"`
	Authority              identity.ManagementAuthority `json:"management_authority"`
	PreflightRequest       preflight.ExpansionRequest   `json:"preflight_request"`
	PreflightDigest        string                       `json:"preflight_digest"`
	ACMEAccountContact     string                       `json:"acme_account_contact"`
	PackageTransactionID   string                       `json:"package_transaction_id"`
	PackagePlanDigest      string                       `json:"package_plan_digest"`
	PackageInputPlanDigest string                       `json:"package_input_plan_digest"`
	PackagePlan            packages.Plan                `json:"package_plan"`
	PackagePreflight       preflight.Result             `json:"package_preflight"`
	PackageJournalDigest   string                       `json:"package_journal_digest,omitempty"`
	Accounts               identity.AccountSet          `json:"accounts"`
	Paths                  Paths                        `json:"paths"`
	ArtifactDigests        map[string]string            `json:"artifact_digests"`
	PlannedPaths           []string                     `json:"planned_paths"`
	TokenDeliveryAttempted bool                         `json:"token_delivery_attempted"`
	FinalCommitDigest      string                       `json:"final_commit_digest,omitempty"`
	InstallerInput         []byte                       `json:"installer_input,omitempty"`
}

type Bundle struct {
	SchemaVersion             string                       `json:"schema_version"`
	AttemptID                 string                       `json:"attempt_id"`
	InstallationID            string                       `json:"installation_id"`
	GenerationID              string                       `json:"generation_id"`
	SafetyGeneration          uint64                       `json:"safety_generation"`
	Fingerprint               string                       `json:"fingerprint"`
	Management                identity.ManagementAuthority `json:"management_authority"`
	Release                   release.InstallIdentity      `json:"release"`
	PreflightDigest           string                       `json:"preflight_digest"`
	ACMEAccountContact        string                       `json:"acme_account_contact"`
	ACMEAccountKeyFingerprint string                       `json:"acme_account_key_fingerprint"`
}

type Commit struct {
	SchemaVersion   string    `json:"schema_version"`
	AttemptID       string    `json:"attempt_id"`
	InstallationID  string    `json:"installation_id"`
	GenerationID    string    `json:"generation_id"`
	JournalSequence uint64    `json:"journal_sequence"`
	BundleDigest    string    `json:"bundle_digest"`
	ArtifactDigest  string    `json:"artifact_inventory_digest"`
	CommittedAt     time.Time `json:"committed_at"`
}

func FixedManagedPathRequirements(paths Paths) []preflight.ManagedPathRequirement {
	values := []preflight.ManagedPathRequirement{
		{Path: filepath.Dir(paths.BinaryPath), Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o755, MaximumMode: 0o755, AllowAbsent: true},
		{Path: paths.PersistentRoot, Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o711, MaximumMode: 0o711, AllowAbsent: true},
		{Path: paths.RuntimeRoot, Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o710, MaximumMode: 0o710, AllowAbsent: true},
		{Path: filepath.Dir(paths.StartupAuthority), Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o710, MaximumMode: 0o710, AllowAbsent: true},
		{Path: paths.SystemdRoot, Kind: preflight.ManagedPathDirectory, OwnerUID: 0, OwnerGID: 0, RequiredMode: 0o755, MaximumMode: 0o755, AllowAbsent: false},
	}
	slices.SortFunc(values, func(left, right preflight.ManagedPathRequirement) int { return strings.Compare(left.Path, right.Path) })
	return values
}

func FixedDiskRequirements(paths Paths) []preflight.DiskRequirement {
	values := []preflight.DiskRequirement{{Path: paths.PersistentRoot, MinimumAvailableBytes: 512 << 20}, {Path: paths.SystemdRoot, MinimumAvailableBytes: 16 << 20}}
	slices.SortFunc(values, func(left, right preflight.DiskRequirement) int { return strings.Compare(left.Path, right.Path) })
	return values
}

type PreflightEvaluator func(context.Context, identity.ManagementAuthority, uint64) (preflight.ExpansionRequest, preflight.Result, error)

type PackageTransaction func(context.Context, packages.Plan, preflight.Result) (packages.Journal, error)

type Request struct {
	ReleaseAuthority *release.InstallAuthority
	// Material is supplied only by the public installer authority builder so
	// its package Plan can bind the same installation generation used by Install.
	Material *identity.Material
	// InstallerInput is persisted in the preinstall journal for public resume;
	// transient authority material is intentionally not copied into the journal.
	InstallerInput     []byte
	Preflight          PreflightEvaluator
	PackagePlan        packages.Plan
	PackagePreflight   preflight.Result
	PackageTransaction PackageTransaction
	SourceBinary       []byte
	ACMEAccountContact string
	LegoBytes          []byte
	TailscaleBytes     []byte
	Random             io.Reader
	Now                func() time.Time
	Paths              Paths
	Output             io.Writer
	TTY                TTY
}

type TTY interface {
	Attached() bool
	WriteToken([]byte) error
}

func validateJournal(value Journal) error {
	if value.SchemaVersion != JournalSchemaVersion || len(value.InstallerInput) > maximumPublicInstallerInputBytes || value.Paths.CommitPath == "" || value.Paths.StartupAuthority == "" || value.Paths.ACMEAccountKey != filepath.Join(value.Paths.InstallationRoot, "acme-account.key") || len(value.PlannedPaths) == 0 || !identity.ValidateAttemptID(value.AttemptID) || !identity.ValidateInstallationID(value.InstallationID) || !identity.ValidateGenerationID(value.GenerationID) || value.SafetyGeneration == 0 || !validPhase(value.Phase) || value.Sequence == 0 || release.ValidateInstallIdentity(value.Release) != nil || identity.ValidateManagementAuthority(value.Authority) != nil || value.PreflightRequest.Target != "installation" || value.PreflightRequest.Scope != preflight.ExpansionBootstrap || value.PreflightDigest == "" || !acmeaccount.ValidContact(value.ACMEAccountContact) || value.PackageTransactionID == "" || !release.ValidDigest(value.PackagePlanDigest) || value.Accounts.HelperClientGroup == "" || value.Paths.PersistentRoot == "" || len(value.ArtifactDigests) == 0 {
		return fmt.Errorf("bootstrap journal is incomplete or invalid")
	}
	beforePackages := value.Phase == PhasePrepared || value.Phase == PhaseNginxMasked
	if !beforePackages && !release.ValidDigest(value.PackageJournalDigest) || beforePackages && value.PackageJournalDigest != "" {
		return fmt.Errorf("bootstrap package transaction binding is invalid")
	}
	if (value.Phase == PhaseCommitted || value.Phase == PhaseActivated) && !release.ValidDigest(value.FinalCommitDigest) || value.Phase != PhaseCommitted && value.Phase != PhaseActivated && value.FinalCommitDigest != "" {
		return fmt.Errorf("bootstrap final commit binding is invalid")
	}
	requestDigest, err := preflight.ExpansionRequestDigest(value.PreflightRequest)
	if err != nil || requestDigest != value.PreflightDigest {
		return fmt.Errorf("bootstrap journal preflight authority mismatched")
	}
	for index, path := range value.PlannedPaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || index > 0 && value.PlannedPaths[index-1] >= path {
			return fmt.Errorf("bootstrap planned path inventory is invalid")
		}
	}
	previous := ""
	for path, digest := range value.ArtifactDigests {
		if path == "" || !release.ValidDigest(digest) || path == previous {
			return fmt.Errorf("bootstrap artifact inventory is invalid")
		}
		previous = path
	}
	return nil
}

func validateBundle(value Bundle) error {
	if value.SchemaVersion != BundleSchemaVersion || !identity.ValidateAttemptID(value.AttemptID) || !identity.ValidateInstallationID(value.InstallationID) || !identity.ValidateGenerationID(value.GenerationID) || value.SafetyGeneration == 0 || len(value.Fingerprint) != 16 || identity.ValidateManagementAuthority(value.Management) != nil || release.ValidateInstallIdentity(value.Release) != nil || value.PreflightDigest == "" || !acmeaccount.ValidContact(value.ACMEAccountContact) || !strings.HasPrefix(value.ACMEAccountKeyFingerprint, "sha256:") || !release.ValidDigest(strings.TrimPrefix(value.ACMEAccountKeyFingerprint, "sha256:")) {
		return fmt.Errorf("installation bundle is invalid")
	}
	fingerprint, _ := identity.Fingerprint(value.InstallationID)
	if value.Fingerprint != fingerprint {
		return fmt.Errorf("installation fingerprint mismatched")
	}
	return nil
}

func validPhase(value Phase) bool {
	switch value {
	case PhasePrepared, PhaseNginxMasked, PhasePackagesCommitted, PhaseBundleCommitted, PhaseAccountsSubmitted, PhaseAccountsVerified, PhaseStoresInitialized, PhaseAssetsInstalled, PhaseCommitted, PhaseActivated:
		return true
	}
	return false
}

func encodeCanonical(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > MaximumJournalBytes {
		return nil, fmt.Errorf("encode bounded canonical bootstrap authority")
	}
	return data, nil
}

func decodeCanonical(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("bootstrap authority has trailing data")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, data) {
		return fmt.Errorf("bootstrap authority is noncanonical")
	}
	return nil
}

func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func authorityInUse(authority identity.ManagementAuthority) error {
	listener, err := net.Listen("tcp4", net.JoinHostPort(authority.Address, fmt.Sprintf("%d", authority.Port)))
	if err != nil {
		return fmt.Errorf("management authority conflicts with an existing listener")
	}
	return listener.Close()
}

func ManagementAuthorityAvailable(authority identity.ManagementAuthority) error {
	return authorityInUse(authority)
}

func canonicalPaths(values []string) []string {
	copyValues := append([]string(nil), values...)
	slices.Sort(copyValues)
	return copyValues
}

var _ = os.ErrNotExist
