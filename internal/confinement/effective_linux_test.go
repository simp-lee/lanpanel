//go:build linux

package confinement

import "testing"

func TestEffectivePropertiesCanonicalizeSystemdLists(t *testing.T) {
	policy := UnitPolicy{ResourceID: "res_00000000000000000000000000000001", Cgroup: "/lanpanel.slice/x", BindListenPolicy: "systemd_bind_baseline_v1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Directives: []string{"AmbientCapabilities=", "IPAddressDeny=127.0.0.0/8", "IPAddressDeny=::1/128", "RestrictAddressFamilies=AF_UNIX AF_INET"}}
	effective := map[string][]string{"AmbientCapabilities": {""}, "IPAddressDeny": {"127.0.0.0/8 ::1/128"}, "RestrictAddressFamilies": {"AF_INET AF_UNIX"}}
	if err := VerifyEffective(policy, effective); err != nil {
		t.Fatal(err)
	}
}

func TestEffectivePropertiesCanonicalizeSystemdBindPaths(t *testing.T) {
	path := "/var/lib/lanpanel/resources/res_00000000000000000000000000000001/exec-authority.json"
	policy := UnitPolicy{ResourceID: "res_00000000000000000000000000000001", Cgroup: "/lanpanel.slice/x", BindListenPolicy: "systemd_bind_baseline_v1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Directives: []string{"BindReadOnlyPaths=" + path}}
	effective := map[string][]string{"BindReadOnlyPaths": {path + ":" + path + ":rbind"}}
	if err := VerifyEffective(policy, effective); err != nil {
		t.Fatal(err)
	}
}
