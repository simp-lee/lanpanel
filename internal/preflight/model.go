package preflight

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/plans"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = "lanpanel.preflight.v1"
	MaximumAge    = time.Minute
)

const (
	MaximumDomains           = 256
	MaximumPublicAddresses   = 16
	MaximumListenerAuthority = 1024
	MaximumManagedPaths      = 512
	MaximumDisks             = 64
	MaximumOwnedIngress      = 512
	MaximumDiagnostics       = 64
	MaximumFindings          = 1024
)

const (
	ExpansionEvidencePrefix   = "preflight_expansion/"
	ContractionEvidencePrefix = "preflight_contraction/"
)

type ExpansionScope string

const (
	ExpansionBootstrap     ExpansionScope = "bootstrap"
	ExpansionDomainHTTPS   ExpansionScope = "domain_https"
	ExpansionTemporaryHTTP ExpansionScope = "temporary_ip_http"
	ExpansionHeadscale     ExpansionScope = "headscale"
)

type ContractionKind string

const (
	ContractionUnpublish ContractionKind = "unpublish"
	ContractionCloseAll  ContractionKind = "close_all"
	ContractionEmergency ContractionKind = "emergency_close_all"
	ContractionExpiry    ContractionKind = "expiry"
	ContractionStartup   ContractionKind = "startup_contraction"
)

type ProfileAuthorityKind string

const (
	FinalSupportedProfile ProfileAuthorityKind = "final_supported_profile"
	QualificationTarget   ProfileAuthorityKind = "qualification_target_profile"
)

type ProfileAuthority struct {
	Kind                  ProfileAuthorityKind `json:"kind"`
	Digest                string               `json:"digest"`
	LiveQualified         bool                 `json:"live_qualified"`
	CandidateDigest       string               `json:"candidate_digest,omitempty"`
	InstallManifestDigest string               `json:"install_manifest_digest,omitempty"`
	SideEffectPlanDigest  string               `json:"side_effect_plan_digest,omitempty"`
	HostFingerprint       string               `json:"host_fingerprint,omitempty"`
	RunID                 string               `json:"run_id,omitempty"`
}

type ExpectedProfile struct {
	ID                    string                    `json:"id"`
	VersionID             string                    `json:"version_id"`
	Architecture          string                    `json:"architecture"`
	SystemdVersion        string                    `json:"systemd_version"`
	NginxVersion          string                    `json:"nginx_version"`
	PackageSnapshotDigest string                    `json:"package_snapshot_digest"`
	ManagedConfinement    ManagedConfinementProfile `json:"managed_confinement"`
	Authority             ProfileAuthority          `json:"authority"`
}

type ManagedConfinementProfile struct {
	SchemaVersion         string   `json:"schema_version"`
	KernelRelease         string   `json:"kernel_release"`
	CgroupMode            string   `json:"cgroup_mode"`
	BindListenPolicy      string   `json:"bind_listen_policy"`
	ConnectPolicy         string   `json:"connect_policy"`
	FilesystemPolicy      string   `json:"filesystem_policy"`
	ProtectedDestinations []string `json:"protected_destinations"`
	QualificationDigest   string   `json:"qualification_digest"`
}

type ListenerRequirement struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Purpose  string `json:"purpose"`
}

type OwnedListenerAuthority struct {
	Protocol       string `json:"protocol"`
	Address        string `json:"address"`
	Port           uint16 `json:"port"`
	SocketInode    uint64 `json:"socket_inode"`
	IdentityDigest string `json:"identity_digest"`
}

type ManagedPathKind string

const (
	ManagedPathDirectory ManagedPathKind = "directory"
	ManagedPathRegular   ManagedPathKind = "regular"
)

type ManagedPathRequirement struct {
	Path         string          `json:"path"`
	Kind         ManagedPathKind `json:"kind"`
	OwnerUID     uint32          `json:"owner_uid"`
	OwnerGID     uint32          `json:"owner_gid"`
	RequiredMode uint32          `json:"required_mode"`
	MaximumMode  uint32          `json:"maximum_mode"`
	AllowAbsent  bool            `json:"allow_absent"`
}

type DiskRequirement struct {
	Path                  string `json:"path"`
	MinimumAvailableBytes uint64 `json:"minimum_available_bytes"`
}

type ExpansionRequest struct {
	Scope              ExpansionScope           `json:"scope"`
	Target             string                   `json:"target"`
	Generation         uint64                   `json:"generation"`
	Profile            ExpectedProfile          `json:"profile"`
	Domains            []string                 `json:"domains"`
	PublicAddresses    []string                 `json:"public_addresses"`
	TemporaryPort      uint16                   `json:"temporary_port,omitempty"`
	BootstrapListeners []ListenerRequirement    `json:"bootstrap_listeners"`
	OwnedListeners     []OwnedListenerAuthority `json:"owned_listeners"`
	ManagedPaths       []ManagedPathRequirement `json:"managed_paths"`
	Disks              []DiskRequirement        `json:"disks"`
	LastTrustedWall    time.Time                `json:"last_trusted_wall"`
}

type ClockObservation struct {
	Now          time.Time `json:"now"`
	Synchronized bool      `json:"synchronized"`
	Source       string    `json:"source"`
}

type ComponentObservation struct {
	Available bool   `json:"available"`
	Identity  string `json:"identity"`
}

type PackageObservation struct {
	Ready                 bool   `json:"ready"`
	Identity              string `json:"identity"`
	SystemdVersion        string `json:"systemd_version"`
	NginxVersion          string `json:"nginx_version"`
	PackageSnapshotDigest string `json:"package_snapshot_digest"`
	Reason                string `json:"reason,omitempty"`
}

type DNSObservation struct {
	Domain    string   `json:"domain"`
	Addresses []string `json:"addresses"`
	Failure   string   `json:"failure,omitempty"`
}

type ListenerObservation struct {
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        uint16 `json:"port"`
	SocketInode uint64 `json:"socket_inode"`
}

type PathObservation struct {
	Path        string          `json:"path"`
	Exists      bool            `json:"exists"`
	Kind        ManagedPathKind `json:"kind,omitempty"`
	UID         uint32          `json:"uid,omitempty"`
	GID         uint32          `json:"gid,omitempty"`
	Mode        uint32          `json:"mode,omitempty"`
	Device      uint64          `json:"device,omitempty"`
	Inode       uint64          `json:"inode,omitempty"`
	ParentsSafe bool            `json:"parents_safe"`
	Failure     string          `json:"failure,omitempty"`
}

type DiskObservation struct {
	Path           string `json:"path"`
	Device         uint64 `json:"device"`
	AvailableBytes uint64 `json:"available_bytes"`
	ReadOnly       bool   `json:"read_only"`
	Failure        string `json:"failure,omitempty"`
}

type ExpansionObservations struct {
	OperatingSystem           string                `json:"operating_system"`
	Architecture              string                `json:"architecture"`
	KernelRelease             string                `json:"kernel_release"`
	CgroupMode                string                `json:"cgroup_mode"`
	Platform                  PlatformInfo          `json:"platform"`
	Clock                     ClockObservation      `json:"clock"`
	ExecutorUID               uint32                `json:"executor_uid"`
	Systemd                   ComponentObservation  `json:"systemd"`
	APT                       ComponentObservation  `json:"apt"`
	DPKG                      ComponentObservation  `json:"dpkg"`
	Packages                  PackageObservation    `json:"packages"`
	DNS                       []DNSObservation      `json:"dns"`
	Listeners                 []ListenerObservation `json:"listeners"`
	ListenerInventoryComplete bool                  `json:"listener_inventory_complete"`
	Paths                     []PathObservation     `json:"paths"`
	Disks                     []DiskObservation     `json:"disks"`
}

type FindingDisposition string

const (
	FindingPassed         FindingDisposition = "passed"
	FindingBlocked        FindingDisposition = "blocked"
	FindingResponsibility FindingDisposition = "responsibility"
	FindingDiagnostic     FindingDisposition = "diagnostic"
)

type Finding struct {
	Code        string             `json:"code"`
	Disposition FindingDisposition `json:"disposition"`
	Summary     string             `json:"summary"`
	Identity    string             `json:"identity"`
}

type Result struct {
	SchemaVersion string    `json:"schema_version"`
	Scope         string    `json:"scope"`
	Target        string    `json:"target"`
	Generation    uint64    `json:"generation"`
	RequestDigest string    `json:"request_digest"`
	Allowed       bool      `json:"allowed"`
	ObservedAt    time.Time `json:"observed_at"`
	ValidUntil    time.Time `json:"valid_until"`
	Findings      []Finding `json:"findings"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Summary  string `json:"summary"`
	Identity string `json:"identity"`
}

type OwnedIngressAuthority struct {
	ResourceID      string `json:"resource_id"`
	RuntimeIdentity string `json:"runtime_identity"`
	OwnershipDigest string `json:"ownership_digest"`
}

type ContractionRequest struct {
	Kind                     ContractionKind         `json:"kind"`
	Target                   string                  `json:"target"`
	Generation               uint64                  `json:"generation"`
	OwnershipInventoryDigest string                  `json:"ownership_inventory_digest"`
	ClosureAuthorityDigest   string                  `json:"closure_authority_digest"`
	OwnedIngress             []OwnedIngressAuthority `json:"owned_ingress"`
	FallbackStop             bool                    `json:"fallback_stop"`
}

type ContractionObservations struct {
	ExecutorUID              uint32                  `json:"executor_uid"`
	InventoryComplete        bool                    `json:"inventory_complete"`
	OwnershipInventoryDigest string                  `json:"ownership_inventory_digest"`
	ClosureAuthorityDigest   string                  `json:"closure_authority_digest"`
	OwnedIngress             []OwnedIngressAuthority `json:"owned_ingress"`
	ObservedAt               time.Time               `json:"observed_at"`
	Diagnostics              []Diagnostic            `json:"diagnostics"`
}

var (
	digestPattern  = regexp.MustCompile(`^(?:sha256:)?[0-9a-f]{64}$`)
	refPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	versionPattern = regexp.MustCompile(`^(?:v)?[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	domainPattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

func ExpansionRequestDigest(request ExpansionRequest) (string, error) {
	if err := validateExpansionRequest(request); err != nil {
		return "", err
	}
	return canonicalDigest(request)
}

func ContractionRequestDigest(request ContractionRequest) (string, error) {
	if err := validateContractionRequest(request); err != nil {
		return "", err
	}
	return canonicalDigest(request)
}

func canonicalDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (result Result) Digest() (string, error) {
	if err := validateResult(result); err != nil {
		return "", err
	}
	return canonicalDigest(result)
}

func (result Result) AuthorityDigest() (string, error) {
	if err := validateResult(result); err != nil {
		return "", err
	}
	authority := struct {
		SchemaVersion string    `json:"schema_version"`
		Scope         string    `json:"scope"`
		Target        string    `json:"target"`
		Generation    uint64    `json:"generation"`
		RequestDigest string    `json:"request_digest"`
		Allowed       bool      `json:"allowed"`
		Findings      []Finding `json:"findings"`
	}{result.SchemaVersion, result.Scope, result.Target, result.Generation, result.RequestDigest, result.Allowed, result.Findings}
	encoded, err := json.Marshal(authority)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (result Result) PlanEvidence() (plans.Evidence, error) {
	if !result.Allowed {
		return plans.Evidence{}, fmt.Errorf("blocked preflight cannot become Plan authority")
	}
	digest, err := result.AuthorityDigest()
	if err != nil {
		return plans.Evidence{}, err
	}
	prefix := ExpansionEvidencePrefix
	if isContractionScope(result.Scope) {
		prefix = ContractionEvidencePrefix
	}
	return plans.Evidence{Kind: prefix + result.Scope, Identity: result.Target, Generation: result.Generation, Digest: digest, ObservedAt: result.ObservedAt}, nil
}

func ValidateFreshResult(result Result, now time.Time) error {
	if err := validateResult(result); err != nil {
		return err
	}
	if !result.Allowed {
		return fmt.Errorf("preflight is blocked")
	}
	if now.Before(result.ObservedAt) || now.After(result.ValidUntil) {
		return fmt.Errorf("preflight result is stale")
	}
	return nil
}

func RequireExpansionResultForRequest(result Result, request ExpansionRequest, now time.Time) error {
	digest, err := ExpansionRequestDigest(request)
	if err != nil {
		return err
	}
	if result.RequestDigest != digest {
		return fmt.Errorf("expansion preflight request authority changed")
	}
	return RequireExpansionResult(result, []ExpansionScope{request.Scope}, request.Target, request.Generation, now)
}

func RequireContractionResultForRequest(result Result, request ContractionRequest, now time.Time) error {
	digest, err := ContractionRequestDigest(request)
	if err != nil {
		return err
	}
	if result.RequestDigest != digest {
		return fmt.Errorf("contraction preflight request authority changed")
	}
	return RequireContractionResult(result, []ContractionKind{request.Kind}, request.Target, request.Generation, now)
}

func RequireExpansionResult(result Result, scopes []ExpansionScope, target string, generation uint64, now time.Time) error {
	if err := ValidateFreshResult(result, now); err != nil {
		return err
	}
	if result.Target != target || result.Generation != generation {
		return fmt.Errorf("expansion preflight target or generation changed")
	}
	for _, scope := range scopes {
		if result.Scope == string(scope) && validExpansionScope(scope) {
			return nil
		}
	}
	return fmt.Errorf("expansion preflight scope is not authorized")
}

func RequireContractionResult(result Result, kinds []ContractionKind, target string, generation uint64, now time.Time) error {
	if err := ValidateFreshResult(result, now); err != nil {
		return err
	}
	if result.Target != target || result.Generation != generation {
		return fmt.Errorf("contraction preflight target or generation changed")
	}
	for _, kind := range kinds {
		if result.Scope == string(kind) && validContractionKind(kind) {
			return nil
		}
	}
	return fmt.Errorf("contraction preflight kind is not authorized")
}

func RequireExpansionPlanEvidence(scopes []ExpansionScope, target string, evidence []plans.Evidence, now time.Time) error {
	allowed := map[string]bool{}
	for _, scope := range scopes {
		if !validExpansionScope(scope) {
			return fmt.Errorf("expansion evidence scope is invalid")
		}
		allowed[ExpansionEvidencePrefix+string(scope)] = true
	}
	return requirePlanEvidence(allowed, target, evidence, now)
}

func RequireContractionPlanEvidence(kinds []ContractionKind, target string, evidence []plans.Evidence, now time.Time) error {
	allowed := map[string]bool{}
	for _, kind := range kinds {
		if !validContractionKind(kind) {
			return fmt.Errorf("contraction evidence kind is invalid")
		}
		allowed[ContractionEvidencePrefix+string(kind)] = true
	}
	return requirePlanEvidence(allowed, target, evidence, now)
}

func requirePlanEvidence(allowed map[string]bool, target string, evidence []plans.Evidence, now time.Time) error {
	matches := 0
	for _, item := range evidence {
		isPreflight := strings.HasPrefix(item.Kind, ExpansionEvidencePrefix) || strings.HasPrefix(item.Kind, ContractionEvidencePrefix)
		if !isPreflight {
			continue
		}
		if !allowed[item.Kind] || item.Identity != target || item.Generation == 0 || !validDigest(item.Digest) || item.ObservedAt.After(now) || now.Sub(item.ObservedAt) > MaximumAge {
			return fmt.Errorf("preflight Plan evidence is stale, wrong-scope, or target-mismatched")
		}
		matches++
	}
	if matches != 1 {
		return fmt.Errorf("exactly one fresh typed preflight authority is required")
	}
	return nil
}

func validateResult(result Result) error {
	if result.SchemaVersion != SchemaVersion || !refPattern.MatchString(result.Scope) || !validTarget(result.Target) || result.Generation == 0 || !strings.HasPrefix(result.RequestDigest, "sha256:") || !validDigest(result.RequestDigest) || result.ObservedAt.IsZero() || !result.ValidUntil.Equal(result.ObservedAt.Add(MaximumAge)) {
		return fmt.Errorf("preflight result identity or lifetime is invalid")
	}
	if len(result.Findings) == 0 || len(result.Findings) > MaximumFindings {
		return fmt.Errorf("preflight finding inventory is empty or unbounded")
	}
	blocked := false
	previous := ""
	for _, finding := range result.Findings {
		if !refPattern.MatchString(finding.Code) || finding.Code <= previous || !validSummary(finding.Summary) || !validIdentity(finding.Identity) {
			return fmt.Errorf("preflight findings are noncanonical or invalid")
		}
		switch finding.Disposition {
		case FindingPassed, FindingResponsibility, FindingDiagnostic:
		case FindingBlocked:
			blocked = true
		default:
			return fmt.Errorf("preflight finding disposition is invalid")
		}
		previous = finding.Code
	}
	if result.Allowed == blocked {
		return fmt.Errorf("preflight result does not match blocking findings")
	}
	return nil
}

func canonicalFindings(findings []Finding) ([]Finding, error) {
	result := append([]Finding(nil), findings...)
	sort.Slice(result, func(i, j int) bool { return result[i].Code < result[j].Code })
	for index := range result {
		if index > 0 && result[index-1].Code == result[index].Code {
			return nil, fmt.Errorf("preflight finding code %q is duplicated", result[index].Code)
		}
	}
	return result, nil
}

func newResult(scope, target string, generation uint64, requestDigest string, observedAt time.Time, findings []Finding) (Result, error) {
	findings, err := canonicalFindings(findings)
	if err != nil {
		return Result{}, err
	}
	allowed := true
	for _, finding := range findings {
		if finding.Disposition == FindingBlocked {
			allowed = false
			break
		}
	}
	result := Result{SchemaVersion: SchemaVersion, Scope: scope, Target: target, Generation: generation, RequestDigest: requestDigest, Allowed: allowed, ObservedAt: observedAt.UTC(), ValidUntil: observedAt.UTC().Add(MaximumAge), Findings: findings}
	return result, validateResult(result)
}

func validExpansionScope(scope ExpansionScope) bool {
	return scope == ExpansionBootstrap || scope == ExpansionDomainHTTPS || scope == ExpansionTemporaryHTTP || scope == ExpansionHeadscale
}

func validContractionKind(kind ContractionKind) bool {
	return kind == ContractionUnpublish || kind == ContractionCloseAll || kind == ContractionEmergency || kind == ContractionExpiry || kind == ContractionStartup
}

func isContractionScope(scope string) bool { return validContractionKind(ContractionKind(scope)) }

func validTarget(value string) bool { return refPattern.MatchString(value) }
func validDigest(value string) bool { return digestPattern.MatchString(value) }
func validSummary(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n")
}

func validIdentity(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 1024 && !strings.ContainsAny(value, "\x00\r\n")
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsAny(value, "\x00\r\n")
}

func canonicalDomain(value string) bool {
	return domainPattern.MatchString(value) && len(value) <= 253 && !strings.Contains(value, "*")
}

func canonicalIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.String() == value
}

func canonicalStringSet(values []string, valid func(string) bool) bool {
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}
