//go:build linux

package process

import (
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/resource"
	"strings"
	"testing"
)

func TestManagedUnitsUseRootGuardAndPID1Endpoint(t *testing.T) {
	app := domain.AppResource{ID: "res_00000000000000000000000000000001", CurrentConfigDigest: "sha256:" + strings.Repeat("a", 64), Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointRelayUnix}}, ManagedProcess: &domain.ManagedProcess{ID: "proc_00000000000000000000000000000001", Requested: domain.ProcessRequestedStopped, Service: domain.ManagedService{Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{"/srv/app/data"}}}}
	accounts, _ := identity.ResourceAccounts("ins_00000000000000000000000000000001", app.ID, true)
	accounts.Identities = []identity.AccountIdentity{{Role: accounts.Application.Role, User: accounts.Application.User, UID: 1200, Group: accounts.Application.Group, GID: 1200}, {Role: accounts.Relay.Role, User: accounts.Relay.User, UID: 1201, Group: accounts.Relay.Group, GID: 1201}}
	profile := confinement.Profile{SchemaVersion: confinement.SchemaVersion, KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_baseline_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8"}, PolicyDigest: "sha256:" + strings.Repeat("b", 64)}
	units, err := Render("ins_00000000000000000000000000000001", app, accounts, profile, resource.ReferenceEvidence{}, 33, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Render("ins_00000000000000000000000000000001", app, accounts, profile, resource.ReferenceEvidence{}, 33, nil); err == nil {
		t.Fatal("Render accepted a missing secret inventory")
	}
	service := string(units.Application)
	socket := string(units.Socket)
	backendDir := strings.TrimSuffix(units.Paths.BackendSocket, "/http.sock")
	relay := string(units.Relay)
	if !strings.Contains(service, "ExecStart=/usr/lib/lanpanel/lanpanel managed-executor") || !strings.Contains(service, "User=root") || !strings.Contains(service, "RefuseManualStart=yes") || !strings.Contains(service, "LANPANEL_EXEC_AUTHORITY=") || strings.Contains(service, app.ManagedProcess.Service.Executable) || !strings.Contains(socket, "RemoveOnStop=yes") || !strings.Contains(relay, "RestrictAddressFamilies=AF_UNIX") || !strings.Contains(relay, "BindReadOnlyPaths="+backendDir+":/backend") || strings.Contains(relay, "BindReadOnlyPaths="+units.Paths.BackendSocket) {
		t.Fatalf("service=%s\nsocket=%s\nrelay=%s", service, socket, units.Relay)
	}
}
