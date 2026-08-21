package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"reflect"
	"slices"
	"strings"
	"time"
)

const ActivationSchema = "lanpanel.headscale.control-activation.v1"

type ActivationPaths struct {
	ControlRuntime    string `json:"control_runtime"`
	ControlSocketUnit string `json:"control_socket_unit"`
	ControlRelayUnit  string `json:"control_relay_unit"`
	STUNSocketUnit    string `json:"stun_socket_unit"`
	STUNRelayUnit     string `json:"stun_relay_unit"`
}

func FixedActivationPaths() ActivationPaths {
	return ActivationPaths{"/run/lanpanel-headscale-control", "/etc/systemd/system/lanpanel-headscale-control.socket", "/etc/systemd/system/lanpanel-headscale-control-relay.service", "/etc/systemd/system/lanpanel-headscale-stun.socket", "/etc/systemd/system/lanpanel-headscale-stun-relay.service"}
}

type ActivationBundle struct {
	SchemaVersion  string                           `json:"schema_version"`
	InstallationID string                           `json:"installation_id"`
	Candidate      Candidate                        `json:"candidate"`
	Certificate    certificates.Identity            `json:"certificate"`
	Prior          *domain.HeadscaleAppliedIdentity `json:"prior,omitempty"`
	Paths          ActivationPaths                  `json:"paths"`
	ServiceUser    string                           `json:"service_user"`
	ServiceGroup   string                           `json:"service_group"`
	ControlSocket  []byte                           `json:"control_socket"`
	ControlRelay   []byte                           `json:"control_relay"`
	STUNSocket     []byte                           `json:"stun_socket"`
	STUNRelay      []byte                           `json:"stun_relay"`
	Entry          nginx.Entry                      `json:"entry"`
	Digest         string                           `json:"digest"`
}

type ActivationAuthority struct {
	Safety       safety.State        `json:"safety"`
	Installation domain.Installation `json:"installation"`
	Ownership    map[string]string   `json:"ownership"`
	ObservedAt   time.Time           `json:"observed_at"`
}

func ValidateActivationAuthority(bundle ActivationBundle, authority ActivationAuthority) error {
	if ValidateActivation(bundle) != nil || safety.Validate(authority.Safety) != nil || domain.ValidateInstallation(authority.Installation) != nil || authority.ObservedAt.IsZero() || authority.ObservedAt.Before(bundle.Certificate.LastTrustedWall) || authority.ObservedAt.Before(bundle.Certificate.NotBefore) || !authority.ObservedAt.Before(bundle.Certificate.NotAfter) || authority.Installation.InstallationID != bundle.InstallationID || authority.Installation.Headscale == nil || authority.Installation.Headscale.DeployIntent == nil {
		return fmt.Errorf("headscale activation runtime authority invalid")
	}
	intent := authority.Installation.Headscale.DeployIntent
	active := authority.Safety.Headscale.Reactivating
	if intent.Phase != domain.HeadscaleDeployActivating || intent.ActivationDigest != bundle.Digest || intent.CertificateFingerprint != bundle.Certificate.Fingerprint || !reflect.DeepEqual(intent.Prior, bundle.Prior) || !reflect.DeepEqual(intent.Candidate, AppliedFromActivation(bundle)) || active == nil || active.ActivationDigest != bundle.Digest || active.ControlEntryDigest != bundle.Entry.Digest || active.CertificateFingerprint != bundle.Certificate.Fingerprint || active.ControlGeneration != bundle.Entry.Generation {
		return fmt.Errorf("headscale activation runtime binding changed")
	}
	return nil
}

func BuildActivation(installationID string, candidate Candidate, certificate certificates.Identity) (ActivationBundle, error) {
	bundle, err := renderActivation(installationID, candidate, certificate)
	if err != nil {
		return ActivationBundle{}, err
	}
	return bundle, ValidateActivation(bundle)
}

func BuildReactivation(installationID string, candidate Candidate, certificate certificates.Identity, prior domain.HeadscaleAppliedIdentity) (ActivationBundle, error) {
	applied, appliedErr := AppliedIdentity(candidate)
	if appliedErr != nil || !reflect.DeepEqual(applied, prior) {
		return ActivationBundle{}, fmt.Errorf("headscale reactivation prior invalid")
	}
	bundle, err := renderActivation(installationID, candidate, certificate)
	if err != nil {
		return ActivationBundle{}, err
	}
	bundle.Prior = &prior
	digest, err := ActivationDigest(bundle)
	if err != nil {
		return ActivationBundle{}, err
	}
	bundle.Digest = digest
	return bundle, ValidateActivation(bundle)
}

func renderActivation(installationID string, candidate Candidate, certificate certificates.Identity) (ActivationBundle, error) {
	if installationID == "" || Validate(candidate) != nil || certificates.ValidateIdentity(certificate) != nil || certificate.ID != candidate.CertificateID || certificate.Generation == 0 || !slices.Equal(certificate.Domains, []string{candidate.ControlDomain}) {
		return ActivationBundle{}, fmt.Errorf("headscale control activation authority is invalid")
	}
	accounts, err := identity.HeadscaleAccounts(installationID, candidate.HeadscaleID)
	if err != nil || len(accounts.Specs) != 1 {
		return ActivationBundle{}, fmt.Errorf("headscale relay account unavailable")
	}
	user, group := accounts.Specs[0].User, accounts.Specs[0].Group
	paths := FixedActivationPaths()
	controlSocket := []byte("[Unit]\nDescription=LanPanel Headscale protected control socket\nPartOf=lanpanel-headscale.service\n\n[Socket]\nListenStream=" + candidate.Paths.ControlSocket + "\nSocketMode=0600\nSocketUser=www-data\nSocketGroup=www-data\nService=lanpanel-headscale-control-relay.service\nFileDescriptorName=headscale-control\nRemoveOnStop=yes\n\n[Install]\nWantedBy=multi-user.target\n")
	controlRelay := []byte("[Unit]\nDescription=LanPanel Headscale control namespace relay\nRequires=lanpanel-headscale.service lanpanel-headscale-control.socket\nAfter=lanpanel-headscale.service\nJoinsNamespaceOf=lanpanel-headscale.service\n\n[Service]\nType=simple\nUser=" + user + "\nGroup=" + group + "\nExecStart=/usr/lib/lanpanel/lanpanel headscale-control-relay\nSockets=lanpanel-headscale-control.socket\nEnvironment=LANPANEL_HEADSCALE_RELAY=control-v1\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nProtectProc=invisible\nProcSubset=pid\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nRestrictSUIDSGID=yes\nRestrictAddressFamilies=AF_UNIX AF_INET\nKillMode=control-group\nRestart=no\nUMask=0077\n")
	stunSocket := []byte("[Unit]\nDescription=LanPanel Headscale public STUN socket\nPartOf=lanpanel-headscale.service\n\n[Socket]\nListenDatagram=0.0.0.0:3478\nSocketMode=0600\nSocketUser=" + user + "\nSocketGroup=" + group + "\nService=lanpanel-headscale-stun-relay.service\nFileDescriptorName=headscale-stun\nRemoveOnStop=yes\nReusePort=no\nFreeBind=no\n\n[Install]\nWantedBy=multi-user.target\n")
	stunRelay := []byte("[Unit]\nDescription=LanPanel Headscale STUN namespace relay\nRequires=lanpanel-headscale.service lanpanel-headscale-stun.socket\nAfter=lanpanel-headscale.service\nJoinsNamespaceOf=lanpanel-headscale.service\n\n[Service]\nType=simple\nUser=" + user + "\nGroup=" + group + "\nExecStart=/usr/lib/lanpanel/lanpanel headscale-stun-relay\nSockets=lanpanel-headscale-stun.socket\nEnvironment=LANPANEL_HEADSCALE_RELAY=stun-v1\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nProtectProc=invisible\nProcSubset=pid\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nRestrictSUIDSGID=yes\nRestrictAddressFamilies=AF_INET\nKillMode=control-group\nRestart=no\nUMask=0077\n")
	pointer, err := certificates.ActivePointerPath(certificate.ID)
	if err != nil {
		return ActivationBundle{}, err
	}
	entry := nginx.Entry{Kind: nginx.EntryControl, Relative: nginx.ControlDirectory + "/headscale.conf", Digest: controlZeroDigest(), Domains: []string{candidate.ControlDomain}, Listeners: []string{"tcp:0.0.0.0:443", "tcp:0.0.0.0:80", "tcp:[::]:443", "tcp:[::]:80"}, Generation: candidate.Generation, Domain: &nginx.DomainSite{Hosts: []string{candidate.ControlDomain}, CertificatePointer: pointer, RejectionAuditPath: nginx.FixedPaths().AuditPath, AuthMode: "application_managed", UpstreamNetwork: "unix", UpstreamAddress: candidate.Paths.ControlSocket, WebSocket: true, Static: []nginx.StaticRoute{}}}
	entryDigest, err := nginx.DigestEntry(entry)
	if err != nil {
		return ActivationBundle{}, err
	}
	entry.Digest = entryDigest
	bundle := ActivationBundle{SchemaVersion: ActivationSchema, InstallationID: installationID, Candidate: candidate, Certificate: certificate, Paths: paths, ServiceUser: user, ServiceGroup: group, ControlSocket: controlSocket, ControlRelay: controlRelay, STUNSocket: stunSocket, STUNRelay: stunRelay, Entry: entry}
	digest, err := ActivationDigest(bundle)
	if err != nil {
		return ActivationBundle{}, err
	}
	bundle.Digest = digest
	return bundle, nil
}

func ValidateActivation(bundle ActivationBundle) error {
	if bundle.SchemaVersion != ActivationSchema || bundle.InstallationID == "" {
		return fmt.Errorf("headscale activation bundle is invalid")
	}
	expected, err := renderActivation(bundle.InstallationID, bundle.Candidate, bundle.Certificate)
	if err == nil && bundle.Prior != nil {
		prior := *bundle.Prior
		expected.Prior = &prior
		expected.Digest = ""
		expected.Digest, err = ActivationDigest(expected)
	}
	if err != nil || !reflect.DeepEqual(expected, bundle) {
		return fmt.Errorf("headscale activation bundle changed")
	}
	return nil
}

func ActivationDigest(bundle ActivationBundle) (string, error) {
	bundle.Digest = ""
	raw, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func controlZeroDigest() string { return "sha256:" + strings.Repeat("0", 64) }
func AppliedFromActivation(bundle ActivationBundle) domain.HeadscaleAppliedIdentity {
	return domain.HeadscaleAppliedIdentity{Generation: bundle.Candidate.Generation, ConfigDigest: bundle.Candidate.ConfigDigest, ArtifactDigest: bundle.Candidate.Artifact.ExecutableDigest, ServiceIdentity: bundle.Candidate.ServiceIdentity, ControlIdentity: bundle.Candidate.ControlIdentity, CertificateID: bundle.Certificate.ID}
}
