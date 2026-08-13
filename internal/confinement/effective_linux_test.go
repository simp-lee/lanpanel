//go:build linux

package confinement

import "testing"

func TestEffectivePropertiesCanonicalizeSystemdLists(t *testing.T) {
	policy := UnitPolicy{ResourceID: "res_00000000000000000000000000000001", Cgroup: "/lanpanel.slice/x", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Directives: []string{"AmbientCapabilities=", "IPAddressDeny=127.0.0.0/8", "IPAddressDeny=::1/128", "RestrictAddressFamilies=AF_UNIX AF_INET"}}
	effective := map[string][]string{"AmbientCapabilities": {""}, "IPAddressDeny": {"127.0.0.0/8 ::1/128"}, "RestrictAddressFamilies": {"AF_INET AF_UNIX"}}
	if err := VerifyEffective(policy, effective); err != nil {
		t.Fatal(err)
	}
}
