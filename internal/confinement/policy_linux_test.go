//go:build linux

package confinement

import "testing"

func TestManagedCgroupIdentityAcceptsOnlyDerivedServices(t *testing.T) {
	id := "0123456789abcdef0123"
	for _, value := range []string{"/lanpanel.slice/lanpanel-app.slice/lanpanel-app-" + id + ".slice/lanpanel-app-" + id + ".service", "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-" + id + ".slice/lanpanel-app-" + id + ".service/worker-1", "/system.slice/lanpanel-relay-" + id + ".service"} {
		if !validManagedCgroup(value) {
			t.Fatalf("valid cgroup rejected: %s", value)
		}
	}
	for _, value := range []string{"/system.slice/ssh.service", "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-" + id + ".slice/lanpanel-app-aaaaaaaaaaaaaaaaaaaa.service", "/system.slice/lanpanel-relay-" + id + ".service/../ssh.service"} {
		if validManagedCgroup(value) {
			t.Fatalf("foreign cgroup accepted: %s", value)
		}
	}
}

func TestManagedPolicyCoversDescendantsAndProtectedDestinations(t *testing.T) {
	profile := Profile{SchemaVersion: SchemaVersion, KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8", "169.254.169.254/32", "::1/128"}, QualificationDigest: digestForTest()}
	policy, err := Render(profile, "res_00000000000000000000000000000001", "/srv/app", "", "/run/app.sock", "", []string{"/srv/app/data"})
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"SocketBindDeny=any": false, "IPAddressDeny=127.0.0.0/8": false, "IPAddressDeny=169.254.169.254/32": false, "NoNewPrivileges=yes": false}
	for _, value := range policy.Directives {
		if _, ok := required[value]; ok {
			required[value] = true
		}
	}
	for value, present := range required {
		if !present {
			t.Fatalf("policy omitted %q: %v", value, policy.Directives)
		}
	}
}

func digestForTest() string {
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
