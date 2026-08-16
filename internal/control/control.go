// Package control owns the non-applied Headscale service and control candidate.
package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/release"
	"regexp"
	"slices"
	"strings"
)

const (
	CandidateSchema = "lanpanel.headscale.control-candidate.v1"
	ConfigContract  = "headscale-trusted-mesh-v1"
	ControlBackend  = "127.0.0.1:8080"
	AdminBackend    = "127.0.0.1:50443"
	MetricsBackend  = "127.0.0.1:9090"
	STUNBackend     = "0.0.0.0:3478"
)

var certificatePattern = regexp.MustCompile(`^cert_[0-9a-f]{32}$`)

type Paths struct {
	ConfigRoot     string `json:"config_root"`
	Config         string `json:"config"`
	Policy         string `json:"policy"`
	Unit           string `json:"unit"`
	RuntimeRoot    string `json:"runtime_root"`
	JournalRoot    string `json:"journal_root"`
	Database       string `json:"database"`
	NoiseKey       string `json:"noise_key"`
	DERPKey        string `json:"derp_key"`
	Journal        string `json:"journal"`
	JournalStaging string `json:"journal_staging"`
	ControlSocket  string `json:"control_socket"`
	AdminSocket    string `json:"admin_socket"`
	MetricsSocket  string `json:"metrics_socket"`
	Executable     string `json:"executable"`
}

func FixedPaths() Paths {
	return Paths{
		ConfigRoot:     "/etc/lanpanel-headscale",
		Config:         "/etc/lanpanel-headscale/config.json",
		Policy:         "/etc/lanpanel-headscale/policy.json",
		Unit:           "/etc/systemd/system/lanpanel-headscale.service",
		RuntimeRoot:    "/var/lib/lanpanel/headscale-runtime",
		JournalRoot:    "/var/lib/lanpanel/headscale-control",
		Database:       "/var/lib/lanpanel/headscale-runtime/db.sqlite",
		NoiseKey:       "/var/lib/lanpanel/headscale-runtime/noise-private.key",
		DERPKey:        "/var/lib/lanpanel/headscale-runtime/derp-private.key",
		Journal:        "/var/lib/lanpanel/headscale-control/deploy.json",
		JournalStaging: "/var/lib/lanpanel/headscale-control/.lanpanel-deploy-filetxn",
		ControlSocket:  "/run/lanpanel/headscale/control.sock",
		AdminSocket:    "/run/lanpanel/headscale/admin.sock",
		MetricsSocket:  "/run/lanpanel/headscale/metrics.sock",
		Executable:     "/usr/lib/lanpanel/dependencies/headscale",
	}
}

type Candidate struct {
	SchemaVersion      string                           `json:"schema_version"`
	HeadscaleID        string                           `json:"headscale_id"`
	DatabaseUUID       string                           `json:"database_uuid"`
	DatabaseGeneration uint64                           `json:"database_generation"`
	Generation         uint64                           `json:"generation"`
	ControlDomain      string                           `json:"control_domain"`
	MagicDNSNamespace  string                           `json:"magicdns_namespace"`
	Artifact           domain.HeadscaleArtifactIdentity `json:"artifact"`
	ConfigDigest       string                           `json:"config_digest"`
	PolicyDigest       string                           `json:"policy_digest"`
	UnitDigest         string                           `json:"unit_digest"`
	ServiceIdentity    string                           `json:"service_identity"`
	ControlIdentity    string                           `json:"control_identity"`
	CertificateID      string                           `json:"certificate_id"`
	CertificateBinding string                           `json:"certificate_binding"`
	Paths              Paths                            `json:"paths"`
	ControlBackend     string                           `json:"control_backend"`
	AdminBackend       string                           `json:"admin_backend"`
	MetricsBackend     string                           `json:"metrics_backend"`
	STUNBackend        string                           `json:"stun_backend"`
	PublicSTUN         bool                             `json:"public_stun"`
}

type Rendered struct {
	Candidate Candidate
	Config    []byte
	Policy    []byte
	Unit      []byte
}

type BuildRequest struct {
	InstallationID string
	Headscale      domain.HeadscaleDomain
	Binding        acme.Binding
	CertificateID  string
}

type headscaleConfig struct {
	ServerURL            string         `json:"server_url"`
	ListenAddr           string         `json:"listen_addr"`
	MetricsListenAddr    string         `json:"metrics_listen_addr"`
	GRPCListenAddr       string         `json:"grpc_listen_addr"`
	GRPCAllowInsecure    bool           `json:"grpc_allow_insecure"`
	UnixSocket           string         `json:"unix_socket"`
	UnixSocketPermission string         `json:"unix_socket_permission"`
	Noise                noiseConfig    `json:"noise"`
	Prefixes             prefixesConfig `json:"prefixes"`
	Database             databaseConfig `json:"database"`
	DNS                  dnsConfig      `json:"dns"`
	DERP                 derpConfig     `json:"derp"`
	Policy               policyConfig   `json:"policy"`
	Log                  logConfig      `json:"log"`
}
type noiseConfig struct {
	PrivateKeyPath string `json:"private_key_path"`
}
type prefixesConfig struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}
type databaseConfig struct {
	Type   string       `json:"type"`
	SQLite sqliteConfig `json:"sqlite"`
}
type sqliteConfig struct {
	Path          string `json:"path"`
	WriteAheadLog bool   `json:"write_ahead_log"`
}
type dnsConfig struct {
	MagicDNS      bool     `json:"magic_dns"`
	BaseDomain    string   `json:"base_domain"`
	SearchDomains []string `json:"search_domains"`
}
type derpConfig struct {
	Server            derpServer `json:"server"`
	URLs              []string   `json:"urls"`
	Paths             []string   `json:"paths"`
	AutoUpdateEnabled bool       `json:"auto_update_enabled"`
}
type derpServer struct {
	Enabled        bool   `json:"enabled"`
	RegionID       int    `json:"region_id"`
	RegionCode     string `json:"region_code"`
	RegionName     string `json:"region_name"`
	STUNListenAddr string `json:"stun_listen_addr"`
	PrivateKeyPath string `json:"private_key_path"`
}
type policyConfig struct {
	Mode string `json:"mode"`
	Path string `json:"path"`
}
type logConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}
type trustedPolicy struct {
	ACLs []policyACL `json:"acls"`
}
type policyACL struct {
	Action       string   `json:"action"`
	Sources      []string `json:"src"`
	Destinations []string `json:"dst"`
}

func Build(request BuildRequest) (Rendered, error) {
	value := request.Headscale
	if request.InstallationID == "" || domain.ValidateHeadscale(value) != nil || value.Policy != "trusted_mesh" || value.Database.Phase != domain.HeadscaleIdentityCommitted || value.Database.SQLitePath != FixedPaths().Database || value.DeployIntent != nil || value.Applied != nil || value.Enabled || value.Artifact.ConfigContract != ConfigContract || !certificatePattern.MatchString(request.CertificateID) {
		return Rendered{}, fmt.Errorf("Headscale control candidate requires exact uncommitted identity authority")
	}
	if err := acme.ValidateBinding(request.Binding); err != nil {
		return Rendered{}, fmt.Errorf("Headscale certificate binding: %w", err)
	}
	bindingDigest, err := acme.BindingDigest(request.Binding)
	if err != nil {
		return Rendered{}, err
	}
	accounts, err := identity.HeadscaleAccounts(request.InstallationID, value.ID)
	if err != nil || len(accounts.Specs) != 1 {
		return Rendered{}, fmt.Errorf("Headscale service account authority unavailable")
	}
	paths := FixedPaths()
	configValue := headscaleConfig{
		ServerURL:            "https://" + value.ControlDomain,
		ListenAddr:           ControlBackend,
		MetricsListenAddr:    MetricsBackend,
		GRPCListenAddr:       AdminBackend,
		GRPCAllowInsecure:    true,
		UnixSocket:           paths.AdminSocket,
		UnixSocketPermission: "0700",
		Noise:                noiseConfig{PrivateKeyPath: paths.NoiseKey},
		Prefixes:             prefixesConfig{V4: "100.64.0.0/10", V6: "fd7a:115c:a1e0::/48"},
		Database:             databaseConfig{Type: "sqlite", SQLite: sqliteConfig{Path: paths.Database, WriteAheadLog: true}},
		DNS:                  dnsConfig{MagicDNS: true, BaseDomain: value.MagicDNSNamespace, SearchDomains: []string{}},
		DERP:                 derpConfig{Server: derpServer{Enabled: true, RegionID: 999, RegionCode: "lanpanel", RegionName: "LanPanel Embedded DERP", STUNListenAddr: STUNBackend, PrivateKeyPath: paths.DERPKey}, URLs: []string{}, Paths: []string{}, AutoUpdateEnabled: false},
		Policy:               policyConfig{Mode: "file", Path: paths.Policy},
		Log:                  logConfig{Level: "info", Format: "json"},
	}
	config, err := json.Marshal(configValue)
	if err != nil {
		return Rendered{}, err
	}
	policy, err := json.Marshal(trustedPolicy{ACLs: []policyACL{{Action: "accept", Sources: []string{"*"}, Destinations: []string{"*:*"}}}})
	if err != nil {
		return Rendered{}, err
	}
	unit := renderUnit(accounts.Specs[0].User, accounts.Specs[0].Group, paths, value.ControlDomain)
	candidate := Candidate{
		SchemaVersion: CandidateSchema, HeadscaleID: value.ID, DatabaseUUID: value.Database.UUID, DatabaseGeneration: value.Database.Generation, Generation: 1,
		ControlDomain: value.ControlDomain, MagicDNSNamespace: value.MagicDNSNamespace, Artifact: value.Artifact,
		ConfigDigest: digest(config), PolicyDigest: digest(policy), UnitDigest: digest(unit), CertificateID: request.CertificateID, CertificateBinding: bindingDigest,
		Paths: paths, ControlBackend: ControlBackend, AdminBackend: AdminBackend, MetricsBackend: MetricsBackend, STUNBackend: STUNBackend, PublicSTUN: false,
	}
	candidate.ServiceIdentity = digest(joinIdentity(candidate.Artifact.ExecutableDigest, candidate.ConfigDigest, candidate.PolicyDigest, candidate.UnitDigest, candidate.DatabaseUUID, candidate.ControlBackend, candidate.AdminBackend, candidate.MetricsBackend, candidate.STUNBackend))
	candidate.ControlIdentity = digest(joinIdentity(candidate.HeadscaleID, candidate.ControlDomain, paths.ControlSocket, candidate.CertificateID, candidate.CertificateBinding, candidate.ServiceIdentity))
	if err := Validate(candidate); err != nil {
		return Rendered{}, err
	}
	return Rendered{Candidate: candidate, Config: config, Policy: policy, Unit: unit}, nil
}

func Validate(value Candidate) error {
	if value.SchemaVersion != CandidateSchema || value.HeadscaleID == "" || value.DatabaseUUID == "" || value.DatabaseGeneration == 0 || value.Generation == 0 || value.ControlDomain == "" || value.MagicDNSNamespace == "" || value.Artifact.ConfigContract != ConfigContract || !digestValue(value.ConfigDigest) || !digestValue(value.PolicyDigest) || !digestValue(value.UnitDigest) || !digestValue(value.ServiceIdentity) || !digestValue(value.ControlIdentity) || !certificatePattern.MatchString(value.CertificateID) || !digestValue(value.CertificateBinding) || value.Paths != FixedPaths() || value.ControlBackend != ControlBackend || value.AdminBackend != AdminBackend || value.MetricsBackend != MetricsBackend || value.STUNBackend != STUNBackend || value.PublicSTUN {
		return fmt.Errorf("Headscale control candidate is invalid")
	}
	return nil
}

func AppliedIdentity(value Candidate) (domain.HeadscaleAppliedIdentity, error) {
	if err := Validate(value); err != nil {
		return domain.HeadscaleAppliedIdentity{}, err
	}
	return domain.HeadscaleAppliedIdentity{Generation: value.Generation, ConfigDigest: value.ConfigDigest, ArtifactDigest: value.Artifact.ExecutableDigest, ServiceIdentity: value.ServiceIdentity, ControlIdentity: value.ControlIdentity, CertificateID: value.CertificateID}, nil
}

func Digest(value Candidate) (string, error) {
	if err := Validate(value); err != nil {
		return "", err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digest(data), nil
}

func VerifyRendered(value Rendered) error {
	if err := Validate(value.Candidate); err != nil {
		return err
	}
	if digest(value.Config) != value.Candidate.ConfigDigest || digest(value.Policy) != value.Candidate.PolicyDigest || digest(value.Unit) != value.Candidate.UnitDigest || !json.Valid(value.Config) || !json.Valid(value.Policy) {
		return fmt.Errorf("Headscale rendered candidate differs from authority")
	}
	var config headscaleConfig
	var policy trustedPolicy
	if json.Unmarshal(value.Config, &config) != nil || json.Unmarshal(value.Policy, &policy) != nil || config.ListenAddr != ControlBackend || config.GRPCListenAddr != AdminBackend || config.UnixSocket != value.Candidate.Paths.AdminSocket || config.UnixSocketPermission != "0700" || config.MetricsListenAddr != MetricsBackend || config.DERP.Server.STUNListenAddr != STUNBackend || len(config.DERP.URLs) != 0 || config.DERP.AutoUpdateEnabled || len(policy.ACLs) != 1 || policy.ACLs[0].Action != "accept" || !slices.Equal(policy.ACLs[0].Sources, []string{"*"}) || !slices.Equal(policy.ACLs[0].Destinations, []string{"*:*"}) {
		return fmt.Errorf("Headscale rendered contract changed")
	}
	return nil
}

func renderUnit(user, group string, paths Paths, controlDomain string) []byte {
	lines := []string{
		"[Unit]", "Description=LanPanel isolated Headscale candidate", "After=network-online.target", "Wants=network-online.target", "", "[Service]", "Type=simple", "User=" + user, "Group=" + group,
		"ExecStart=" + paths.Executable + " serve --config " + paths.Config, "ExecStartPost=/usr/lib/lanpanel/lanpanel headscale-private-probe", "Environment=LANPANEL_HEADSCALE_CANDIDATE=private-v1", "Environment=LANPANEL_HEADSCALE_CONTROL_DOMAIN=" + controlDomain, "Restart=on-failure", "RestartSec=2s", "KillMode=control-group", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateNetwork=yes", "PrivateTmp=yes", "PrivateDevices=yes", "RuntimeDirectory=lanpanel/headscale", "RuntimeDirectoryMode=0700", "ProtectSystem=strict", "ProtectHome=yes", "ProtectProc=invisible", "ProcSubset=pid", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "SystemCallArchitectures=native", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "ReadWritePaths=" + paths.RuntimeRoot + " /run/lanpanel/headscale", "UMask=0077", "", "[Install]", "WantedBy=multi-user.target", "",
	}
	return []byte(strings.Join(lines, "\n"))
}

func joinIdentity(values ...string) []byte { return []byte(strings.Join(values, "\x00")) }
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func digestValue(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func ValidateRelease(authority release.InstallIdentity, candidate Candidate) error {
	if err := release.ValidateInstallIdentity(authority); err != nil || candidate.Artifact.Version != authority.Headscale.Version || candidate.Artifact.ConfigContract != authority.Headscale.ConfigContract || candidate.Artifact.ConfigContractDigest != "sha256:"+authority.Headscale.ConfigContractDigest || candidate.Paths.Executable != authority.Headscale.InstallPath {
		return fmt.Errorf("Headscale candidate differs from release authority")
	}
	return nil
}
