//go:build linux

// Package process owns fixed per-resource managed-process units and lifecycle evidence.
package process

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/resource"
	"path/filepath"
	"strconv"
	"strings"
)

type UnitSet struct {
	Paths          resource.Paths
	Application    []byte
	Socket         []byte
	BackendSocket  []byte
	Relay          []byte
	Policy         []byte
	Sysusers       []byte
	ExecAuthority  []byte
	Bundle         domain.ProcessBundle
	Confinement    confinement.UnitPolicy
	ApplicationUID uint32
	ApplicationGID uint32
	RelayUID       uint32
	RelayGID       uint32
}

func (units UnitSet) BundlePolicy() confinement.UnitPolicy { return units.Confinement }

func Render(installationID string, app domain.AppResource, accounts identity.ResourceAccountSet, policyProfile confinement.Profile, evidence resource.ReferenceEvidence, frontendGID uint32) (UnitSet, error) {
	if installationID == "" || accounts.InstallationID != installationID || app.Target.Kind != domain.AppTargetLocalHTTP || app.Target.LocalHTTP == nil || app.ManagedProcess == nil || app.ManagedProcess.Requested != domain.ProcessRequestedStopped && app.ManagedProcess.Requested != domain.ProcessRequestedRunning {
		return UnitSet{}, fmt.Errorf("managed-process unit authority is invalid")
	}
	paths, err := resource.DerivePaths(app.ID)
	if err != nil {
		return UnitSet{}, err
	}
	relay := app.Target.LocalHTTP.EndpointKind == domain.LocalEndpointRelayUnix
	if err := validateAccounts(accounts, app.ID, relay); err != nil {
		return UnitSet{}, err
	}
	applicationIdentity := accounts.Identities[0]
	frontendForPolicy := paths.FrontendSocket
	if app.Target.LocalHTTP.EndpointKind == domain.LocalEndpointTCPSocketActivation {
		frontendForPolicy = ""
	}
	policy, err := confinement.Render(policyProfile, app.ID, app.ManagedProcess.Service.WorkingDirectory, app.ManagedProcess.Service.EnvironmentFile, frontendForPolicy, relayBackend(relay, paths.BackendSocket), app.ManagedProcess.Service.WritePaths)
	if err != nil {
		return UnitSet{}, err
	}
	var service strings.Builder
	requiredSocket := paths.SocketUnit
	unitRequires := "Requires=" + requiredSocket + "\n"
	if relay {
		unitRequires = ""
	}
	service.WriteString("[Unit]\nDescription=LanPanel managed application " + app.ID + "\nRequires=lanpanel-process-guard.service\nAfter=network.target lanpanel-process-guard.service\n" + unitRequires + "\n[Service]\nType=simple\n")
	service.WriteString("User=root\nGroup=root\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP\n")
	service.WriteString("ExecStart=/usr/lib/lanpanel/lanpanel managed-executor\nWorkingDirectory=" + escapeSystemd(app.ManagedProcess.Service.WorkingDirectory) + "\n")
	service.WriteString("Environment=LANPANEL_EXEC_AUTHORITY=" + escapeSystemd(AuthorityPath(app.ID)) + "\n")
	service.WriteString("Slice=" + paths.PolicyUnit + "\nKillMode=control-group\nRestart=on-failure\nRestartPreventExitStatus=0\n")
	if app.ManagedProcess.Requested == domain.ProcessRequestedStopped {
		service.WriteString("RefuseManualStart=yes\n")
	}
	for _, directive := range policy.Directives {
		service.WriteString(directive + "\n")
	}
	socket, err := renderSocket(app, paths, applicationIdentity, frontendGID)
	if err != nil {
		return UnitSet{}, err
	}
	var relayBytes, backendSocket []byte
	var relayUID, relayGID uint32
	if app.Target.LocalHTTP.EndpointKind == domain.LocalEndpointUnixSocketActivation || app.Target.LocalHTTP.EndpointKind == domain.LocalEndpointTCPSocketActivation {
		service.WriteString("Sockets=" + paths.SocketUnit + "\nEnvironment=LANPANEL_HTTP_SOCKET=/proc/self/fd/3\n")
	}
	service.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	if relay {
		relayIdentity := accounts.Identities[1]
		relayUID, relayGID = relayIdentity.UID, relayIdentity.GID
		relayBytes = []byte("[Unit]\nDescription=LanPanel fixed relay " + app.ID + "\nRequires=" + paths.SocketUnit + "\nAfter=" + paths.SocketUnit + " " + paths.ServiceUnit + "\n\n[Service]\nType=simple\nExecStart=/usr/lib/lanpanel/lanpanel relay\nUser=" + fmt.Sprint(relayIdentity.UID) + "\nGroup=" + fmt.Sprint(relayIdentity.GID) + "\nSockets=" + paths.SocketUnit + "\nEnvironment=LANPANEL_RESOURCE_ID=" + app.ID + "\nEnvironment=LANPANEL_RELAY_BACKEND=/backend/http.sock\nUMask=0007\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictSUIDSGID=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictAddressFamilies=AF_UNIX\nTemporaryFileSystem=/run:ro\nBindReadOnlyPaths=" + filepath.Dir(paths.BackendSocket) + ":/backend\nInaccessiblePaths=/proc\nRestart=on-failure\n")
	}
	policyBytes := []byte("[Unit]\nDescription=LanPanel confinement slice " + app.ID + "\nBefore=" + paths.ServiceUnit + "\n\n[Slice]\n")
	for _, destination := range policyProfile.ProtectedDestinations {
		policyBytes = append(policyBytes, []byte("IPAddressDeny="+destination+"\n")...)
	}
	sysusers, err := identity.RenderResourceSysusers(accounts)
	if err != nil {
		return UnitSet{}, err
	}
	execAuthority, err := json.Marshal(ExecAuthority{SchemaVersion: managedExecSchema, ResourceID: app.ID, UID: applicationIdentity.UID, GID: applicationIdentity.GID, Service: app.ManagedProcess.Service, Endpoint: processEndpoint(app.Target.LocalHTTP.EndpointKind, paths), Policy: policy, Evidence: evidence})
	if err != nil {
		return UnitSet{}, err
	}
	endpointUnits := []string{paths.SocketUnit}
	bundle := domain.ProcessBundle{Generation: max(uint64(1), appliedGeneration(app.ManagedProcess)), ConfigDigest: app.CurrentConfigDigest, UnitDigest: digest([]byte(service.String())), SocketUnitDigest: digest(append(append([]byte(nil), socket...), backendSocket...)), PolicyDigest: policy.Digest, AccountDigest: digest(sysusers), ExecutableDigest: evidence.ExecutableDigest, WorkingDirectoryIdentity: evidence.WorkingDirectoryIdentity, WritePathIdentities: append([]string(nil), evidence.WritePathIdentities...), EnvironmentFingerprint: evidence.EnvironmentFingerprint, Cgroup: policy.Cgroup, FrontendEndpoint: paths.FrontendSocket, EndpointSocketUnits: endpointUnits, RelayRequired: relay, ApplicationUID: applicationIdentity.UID, ApplicationGID: applicationIdentity.GID, FrontendGID: frontendGID, FrontendMode: 0o660, RelayUID: relayUID, RelayGID: relayGID, ManagedPaths: paths.ManagedPaths()}
	if relay {
		bundle.BackendEndpoint = paths.BackendSocket
	}
	if app.Target.LocalHTTP.EndpointKind == domain.LocalEndpointTCPSocketActivation {
		bundle.FrontendGID, bundle.FrontendMode = 0, 0
		bundle.TCPAddress = app.Target.LocalHTTP.TCPAddress
		bundle.TCPPort = app.Target.LocalHTTP.TCPPort
	}
	return UnitSet{Paths: paths, Application: []byte(service.String()), Socket: socket, BackendSocket: backendSocket, Relay: relayBytes, Policy: policyBytes, Sysusers: sysusers, ExecAuthority: execAuthority, Bundle: bundle, Confinement: policy, ApplicationUID: applicationIdentity.UID, ApplicationGID: applicationIdentity.GID, RelayUID: relayUID, RelayGID: relayGID}, nil
}

func renderSocket(app domain.AppResource, paths resource.Paths, account identity.AccountIdentity, frontendGID uint32) ([]byte, error) {
	local := app.Target.LocalHTTP
	var listen, mode string
	switch local.EndpointKind {
	case domain.LocalEndpointUnixSocketActivation, domain.LocalEndpointRelayUnix:
		if frontendGID == 0 {
			return nil, fmt.Errorf("Nginx frontend group identity is missing")
		}
		listen, mode = "ListenStream="+paths.FrontendSocket, "SocketMode=0660\nSocketUser=root\nSocketGroup="+fmt.Sprint(frontendGID)
	case domain.LocalEndpointTCPSocketActivation:
		listen, mode = "ListenStream="+local.TCPAddress+":"+fmt.Sprint(local.TCPPort), "BindIPv6Only=both\nFreeBind=no"
	default:
		return nil, fmt.Errorf("local endpoint realization is unsupported")
	}
	service := paths.ServiceUnit
	if local.EndpointKind == domain.LocalEndpointRelayUnix {
		service = paths.RelayUnit
	}
	return []byte("[Unit]\nDescription=LanPanel PID1-owned endpoint " + app.ID + "\nBefore=" + service + "\n\n[Socket]\n" + listen + "\n" + mode + "\nService=" + service + "\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n"), nil
}

func validateAccounts(accounts identity.ResourceAccountSet, resourceID string, relay bool) error {
	want := 1
	if relay {
		want = 2
	}
	if accounts.ResourceID != resourceID || len(accounts.Identities) != want || accounts.Identities[0].UID == 0 || accounts.Identities[0].GID == 0 || relay && (accounts.Identities[1].UID == 0 || accounts.Identities[1].GID == 0 || accounts.Identities[0].UID == accounts.Identities[1].UID) {
		return fmt.Errorf("managed-process numeric account authority is incomplete")
	}
	return nil
}
func appliedGeneration(process *domain.ManagedProcess) uint64 {
	if process.Applied == nil {
		return 1
	}
	return process.Applied.Generation + 1
}
func processEndpoint(kind domain.LocalEndpointKind, paths resource.Paths) string {
	if kind == domain.LocalEndpointRelayUnix {
		return paths.BackendSocket
	}
	return paths.FrontendSocket
}
func relayBackend(relay bool, value string) string {
	if relay {
		return value
	}
	return ""
}
func escapeSystemd(value string) string { return strconv.Quote(value) }
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
