//go:build linux

// Package goaccess owns the fixed per-resource analytics service authority.
package goaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"path/filepath"
	"strconv"
	"strings"
)

const Backend = "127.0.0.1:7890"

type Paths struct{ ResourceRoot, StateRoot, Database, Report, AccessLog, Endpoint, ServiceUnit, ServiceEnablement, RelayUnit, RelayEnablement, SocketUnit, SocketEnablement, Sysusers, RetentionUnit, RetentionTimer, RetentionEnablement, RetentionLock string }
type Candidate struct {
	InstallationID                                                     string
	ResourceID                                                         string
	Generation                                                         uint64
	Paths                                                              Paths
	Service, Relay, Socket, Sysusers, RetentionService, RetentionTimer []byte
	ServiceIdentity                                                    string
	UID, GID, RelayUID, RelayGID, NginxGID                             uint32
	WebSocketPath                                                      string
	User, Group, RelayUser, RelayGroup                                 string
	Accounts                                                           identity.ResourceAccountSet
	RetainShared                                                       bool
	RetainState                                                        bool
	ReuseApplied                                                       bool
	StateGeneration                                                    uint64
	RetainedServiceGeneration                                          uint64
	RetainedServiceIdentity                                            string
	RetainedUnitIdentities                                             []string
	UnitIdentities                                                     []string
}

func DerivePaths(resourceID string, generation uint64) (Paths, error) {
	if !validResourceID(resourceID) || generation == 0 {
		return Paths{}, fmt.Errorf("GoAccess resource identity invalid")
	}
	unitID := resourceID + "-" + fmt.Sprint(generation)
	resourceRoot := "/var/lib/lanpanel/goaccess/" + resourceID
	state := resourceRoot + "/generations/" + fmt.Sprint(generation)
	return Paths{ResourceRoot: resourceRoot, StateRoot: state, Database: state + "/database", Report: state + "/report/index.html", AccessLog: "/var/log/lanpanel/goaccess/" + resourceID + "/access.log", Endpoint: "/run/lanpanel-goaccess/" + unitID + ".sock", ServiceUnit: "/etc/systemd/system/lanpanel-goaccess-" + unitID + ".service", ServiceEnablement: "/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-" + unitID + ".service", RelayUnit: "/etc/systemd/system/lanpanel-goaccess-relay-" + unitID + ".service", RelayEnablement: "/etc/systemd/system/multi-user.target.wants/lanpanel-goaccess-relay-" + unitID + ".service", SocketUnit: "/etc/systemd/system/lanpanel-goaccess-" + unitID + ".socket", SocketEnablement: "/etc/systemd/system/sockets.target.wants/lanpanel-goaccess-" + unitID + ".socket", Sysusers: "/etc/sysusers.d/lanpanel-goaccess-" + resourceID + ".conf", RetentionUnit: "/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".service", RetentionTimer: "/etc/systemd/system/lanpanel-goaccess-retention-" + unitID + ".timer", RetentionEnablement: "/etc/systemd/system/timers.target.wants/lanpanel-goaccess-retention-" + unitID + ".timer", RetentionLock: "/var/log/lanpanel/goaccess/" + resourceID + "/.retention.lock"}, nil
}

type accountAuthority struct {
	accounts                           identity.ResourceAccountSet
	uid, gid, relayUID, relayGID       uint32
	user, group, relayUser, relayGroup string
	sysusers                           []byte
}

func deriveAccountAuthority(installationID, resourceID string) (accountAuthority, error) {
	accounts, err := identity.GoAccessAccounts(installationID, resourceID)
	if err != nil {
		return accountAuthority{}, err
	}
	uid, gid, relayUID, relayGID := numeric(installationID, resourceID)
	accounts.Identities = []identity.AccountIdentity{{Role: accounts.Application.Role, User: accounts.Application.User, UID: uid, Group: accounts.Application.Group, GID: gid}, {Role: accounts.Relay.Role, User: accounts.Relay.User, UID: relayUID, Group: accounts.Relay.Group, GID: relayGID}}
	user, group, relayUser, relayGroup := accounts.Application.User, accounts.Application.Group, accounts.Relay.User, accounts.Relay.Group
	sysusers := []byte("g " + group + " " + fmt.Sprint(gid) + " -\nu " + user + " " + fmt.Sprint(uid) + ":" + fmt.Sprint(gid) + " " + strconv.Quote(accounts.Application.Comment) + " /nonexistent /usr/sbin/nologin\ng " + relayGroup + " " + fmt.Sprint(relayGID) + " -\nu " + relayUser + " " + fmt.Sprint(relayUID) + ":" + fmt.Sprint(relayGID) + " " + strconv.Quote(accounts.Relay.Comment) + " /nonexistent /usr/sbin/nologin\n")
	return accountAuthority{accounts: accounts, uid: uid, gid: gid, relayUID: relayUID, relayGID: relayGID, user: user, group: group, relayUser: relayUser, relayGroup: relayGroup, sysusers: sysusers}, nil
}
func ObserveCandidate(installationID, resourceID string, nginxGID uint32, applied domain.GoAccessBundleIdentity) (Candidate, error) {
	if !applied.Enabled || applied.Generation == 0 || applied.StateGeneration == 0 || applied.ServiceIdentity == "" || len(applied.UnitIdentities) != 5 || applied.WebSocketPath == "" {
		return Candidate{}, fmt.Errorf("applied GoAccess observation authority incomplete")
	}
	paths, err := deriveRuntimePaths(resourceID, applied.Generation, applied.StateGeneration)
	if err != nil {
		return Candidate{}, err
	}
	authority, err := deriveAccountAuthority(installationID, resourceID)
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{InstallationID: installationID, ResourceID: resourceID, Generation: applied.Generation, RetainShared: true, RetainState: true, ReuseApplied: true, StateGeneration: applied.StateGeneration, Paths: paths, UID: authority.uid, GID: authority.gid, RelayUID: authority.relayUID, RelayGID: authority.relayGID, NginxGID: nginxGID, ServiceIdentity: applied.ServiceIdentity, WebSocketPath: applied.WebSocketPath, User: authority.user, Group: authority.group, RelayUser: authority.relayUser, RelayGroup: authority.relayGroup, Accounts: authority.accounts, Sysusers: authority.sysusers, UnitIdentities: append([]string(nil), applied.UnitIdentities...)}, nil
}

func deriveRuntimePaths(resourceID string, generation, stateGeneration uint64) (Paths, error) {
	paths, err := DerivePaths(resourceID, generation)
	if err != nil {
		return Paths{}, err
	}
	state, err := DerivePaths(resourceID, stateGeneration)
	if err != nil {
		return Paths{}, err
	}
	paths.StateRoot, paths.Database, paths.Report = state.StateRoot, state.Database, state.Report
	return paths, nil
}
func Render(installationID string, resource domain.AppResource, nginxGID uint32, generation uint64) (Candidate, error) {
	publication := resource.Publication.DomainHTTPS
	if publication == nil || !publication.GoAccess.Enabled || nginxGID == 0 || !validInstallationID(installationID) {
		return Candidate{}, fmt.Errorf("GoAccess publication authority incomplete")
	}
	stateGeneration := generation
	retainedServiceGeneration := uint64(0)
	retainedServiceIdentity := ""
	retainedUnitIdentities := []string{}
	retainShared, retainState := false, false
	if prior := resource.PublicationRecord.LastAppliedBundle; prior != nil && prior.DomainHTTPS != nil {
		applied := prior.DomainHTTPS.GoAccess
		retainShared = applied.Enabled || applied.RetiredGeneration != 0
		if applied.Enabled && resource.PublicationRecord.State == domain.PublicationPublished {
			if applied.CanonicalHost != publication.CanonicalDomain || applied.WebSocketPath != publication.GoAccess.WebSocketPath {
				return Candidate{}, fmt.Errorf("active GoAccess service identity change requires an explicit disable publication first")
			}
			return ObserveCandidate(installationID, resource.ID, nginxGID, applied)
		}
		if applied.Enabled {
			stateGeneration = applied.StateGeneration
			retainedServiceGeneration = applied.Generation
			retainedServiceIdentity = applied.ServiceIdentity
			retainedUnitIdentities = append([]string(nil), applied.UnitIdentities...)
			retainState = true
		} else if applied.RetiredGeneration != 0 {
			if applied.RetiredStateGeneration == 0 || applied.RetiredStateGeneration > applied.RetiredGeneration {
				return Candidate{}, fmt.Errorf("retained GoAccess state generation invalid")
			}
			stateGeneration = applied.RetiredStateGeneration
			retainedServiceGeneration = applied.RetiredGeneration
			retainedServiceIdentity = applied.RetiredServiceIdentity
			retainedUnitIdentities = append([]string(nil), applied.RetiredUnitIdentities...)
			retainState = true
		}
	}
	paths, err := deriveRuntimePaths(resource.ID, generation, stateGeneration)
	if err != nil {
		return Candidate{}, err
	}
	authority, accountErr := deriveAccountAuthority(installationID, resource.ID)
	if accountErr != nil {
		return Candidate{}, accountErr
	}
	uid, gid, relayUID, relayGID := authority.uid, authority.gid, authority.relayUID, authority.relayGID
	accounts := authority.accounts
	user, group, relayUser, relayGroup := authority.user, authority.group, authority.relayUser, authority.relayGroup
	serviceName := filepath.Base(paths.ServiceUnit)
	socketName := filepath.Base(paths.SocketUnit)
	service := []byte("[Unit]\nDescription=LanPanel isolated GoAccess " + resource.ID + "\nAfter=network.target\n\n[Service]\nType=simple\nUser=" + fmt.Sprint(uid) + "\nGroup=" + fmt.Sprint(gid) + "\nEnvironment=LANPANEL_INSTALLATION_ID=" + installationID + "\nEnvironment=LANPANEL_RESOURCE_ID=" + resource.ID + "\nEnvironment=LANPANEL_GOACCESS_GENERATION=" + fmt.Sprint(generation) + "\nExecStartPre=+/usr/lib/lanpanel/lanpanel goaccess-account-guard\nExecStart=/usr/bin/goaccess --no-global-config " + quote(paths.AccessLog) + " --log-format=COMBINED --real-time-html --ws-url=wss://" + publication.CanonicalDomain + publication.GoAccess.WebSocketPath + " --addr=127.0.0.1 --port=7890 --output=" + quote(paths.Report) + " --persist --restore --db-path=" + quote(paths.Database) + " --keep-last=30\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictSUIDSGID=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths=" + quote(paths.StateRoot) + "\nRestrictAddressFamilies=AF_INET\nSystemCallArchitectures=native\nUMask=0027\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n")
	relay := []byte("[Unit]\nDescription=LanPanel isolated GoAccess relay " + resource.ID + "\nRequires=" + serviceName + " " + socketName + "\nAfter=" + serviceName + " " + socketName + "\nJoinsNamespaceOf=" + serviceName + "\n\n[Service]\nType=simple\nUser=" + fmt.Sprint(relayUID) + "\nGroup=" + fmt.Sprint(relayGID) + "\nExecStartPre=+/usr/lib/lanpanel/lanpanel goaccess-account-guard\nExecStart=/usr/lib/lanpanel/lanpanel goaccess-relay\nSockets=" + socketName + "\nEnvironment=LANPANEL_INSTALLATION_ID=" + installationID + "\nEnvironment=LANPANEL_RESOURCE_ID=" + resource.ID + "\nEnvironment=LANPANEL_GOACCESS_GENERATION=" + fmt.Sprint(generation) + "\nEnvironment=LANPANEL_GOACCESS_BACKEND=" + Backend + "\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictSUIDSGID=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictAddressFamilies=AF_INET\nUMask=0077\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n")
	socket := []byte("[Unit]\nDescription=LanPanel protected GoAccess endpoint " + resource.ID + "\nBefore=" + filepath.Base(paths.RelayUnit) + "\n\n[Socket]\nUser=root\nGroup=" + fmt.Sprint(nginxGID) + "\nListenStream=" + paths.Endpoint + "\nSocketMode=0660\nSocketUser=root\nSocketGroup=" + fmt.Sprint(nginxGID) + "\nService=" + filepath.Base(paths.RelayUnit) + "\nFileDescriptorName=goaccess\nRemoveOnStop=yes\nRuntimeDirectory=lanpanel-goaccess\nRuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=yes\n\n[Install]\nWantedBy=sockets.target\n")
	sysusers := authority.sysusers
	retentionService := []byte("[Unit]\nDescription=LanPanel bounded GoAccess retention " + resource.ID + "\n\n[Service]\nType=oneshot\nExecStart=/usr/lib/lanpanel/lanpanel goaccess-retention\nEnvironment=LANPANEL_INSTALLATION_ID=" + installationID + "\nEnvironment=LANPANEL_RESOURCE_ID=" + resource.ID + "\nEnvironment=LANPANEL_GOACCESS_GENERATION=" + fmt.Sprint(generation) + "\nUser=" + fmt.Sprint(uid) + "\nGroup=" + fmt.Sprint(gid) + "\nExecStartPre=+/usr/lib/lanpanel/lanpanel goaccess-account-guard\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictSUIDSGID=yes\nPrivateNetwork=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_UNIX\nTimeoutStartSec=30s\nUMask=0077\nReadWritePaths=" + quote(filepath.Dir(paths.AccessLog)) + " " + quote(paths.RetentionLock) + "\n")
	retentionTimer := []byte("[Unit]\nDescription=LanPanel bounded GoAccess retention timer " + resource.ID + "\n\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=1min\nUnit=" + filepath.Base(paths.RetentionUnit) + "\n\n[Install]\nWantedBy=timers.target\n")
	identity := managedServiceIdentity(service, relay, socket, sysusers, retentionService, retentionTimer)
	unitIdentities := []string{digest(service), digest(relay), digest(socket), digest(retentionService), digest(retentionTimer)}
	return Candidate{InstallationID: installationID, ResourceID: resource.ID, Generation: generation, RetainShared: retainShared, RetainState: retainState, StateGeneration: stateGeneration, RetainedServiceGeneration: retainedServiceGeneration, RetainedServiceIdentity: retainedServiceIdentity, RetainedUnitIdentities: retainedUnitIdentities, Paths: paths, Service: service, Relay: relay, Socket: socket, Sysusers: sysusers, RetentionService: retentionService, RetentionTimer: retentionTimer, ServiceIdentity: identity, UID: uid, GID: gid, RelayUID: relayUID, RelayGID: relayGID, NginxGID: nginxGID, WebSocketPath: publication.GoAccess.WebSocketPath, User: user, Group: group, RelayUser: relayUser, RelayGroup: relayGroup, Accounts: accounts, UnitIdentities: unitIdentities}, nil
}
func numeric(installationID, resourceID string) (uint32, uint32, uint32, uint32) {
	sum := sha256.Sum256([]byte(installationID + "\x00" + resourceID))
	raw := sum[:6]
	value := func(base uint32, index int) uint32 {
		return base + (uint32(raw[index]) << 16) + (uint32(raw[index+1]) << 8) + uint32(raw[index+2])
	}
	uid := value(40_000_000, 0)
	relay := value(60_000_000, 3)
	return uid, uid, relay, relay
}
func validInstallationID(value string) bool {
	if len(value) != 36 || !strings.HasPrefix(value, "ins_") {
		return false
	}
	_, err := hex.DecodeString(value[4:])
	return err == nil
}
func validResourceID(value string) bool {
	if len(value) != 36 || !strings.HasPrefix(value, "res_") {
		return false
	}
	_, err := hex.DecodeString(value[4:])
	return err == nil
}
func quote(value string) string { return strconv.Quote(value) }
func managedServiceIdentity(values ...[]byte) string {
	authority := []byte{}
	for _, value := range values {
		authority = append(authority, fmt.Sprintf("%d:", len(value))...)
		authority = append(authority, value...)
	}
	return digest(authority)
}
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
