//go:build linux

package control

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeadscaleSocketBootTransactionHasNoOrderingCycle(t *testing.T) {
	analyzer, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("native systemd dependency verifier is unavailable")
	}
	rendered := testRendered(t)
	certificate := testCertificateIdentity(IssueRequest{JobID: "job_control", PlanID: "plan_control", IntentGeneration: 1, CertificateID: rendered.Candidate.CertificateID, BindingDigest: rendered.Candidate.CertificateBinding, Domain: rendered.Candidate.ControlDomain})
	bundle, err := BuildActivation("ins_00000000000000000000000000000001", rendered.Candidate, certificate)
	if err != nil {
		t.Fatal(err)
	}
	for _, defaults := range []bool{false, true} {
		name := "late_sockets"
		if defaults {
			name = "default_socket_ordering_reproduces_cycle"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			write := func(path string, data []byte, mode os.FileMode) {
				t.Helper()
				path = filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			// A minimal boot transaction with systemd's normal target ordering.
			// The analyzer itself adds the implicit service/socket dependencies.
			units := map[string]string{
				"sysinit.target":                           "[Unit]\nDefaultDependencies=no\n",
				"shutdown.target":                          "[Unit]\nDefaultDependencies=no\n",
				"sockets.target":                           "[Unit]\nDefaultDependencies=no\n",
				"basic.target":                             "[Unit]\nRequires=sysinit.target\nWants=sockets.target\nAfter=sysinit.target sockets.target\n",
				"multi-user.target":                        "[Unit]\nRequires=basic.target\nAfter=basic.target\nWants=lanpanel-headscale.service lanpanel-headscale-control.socket lanpanel-headscale-stun.socket\n",
				"network-online.target":                    "[Unit]\nDescription=Network readiness fixture\n",
				"lanpanel-recovery.service":                "[Service]\nType=oneshot\nExecStart=/usr/lib/lanpanel/lanpanel\nRemainAfterExit=yes\n",
				"lanpanel-headscale.service":               string(rendered.Unit),
				"lanpanel-headscale-control.socket":        string(bundle.ControlSocket),
				"lanpanel-headscale-stun.socket":           string(bundle.STUNSocket),
				"lanpanel-headscale-control-relay.service": string(bundle.ControlRelay),
				"lanpanel-headscale-stun-relay.service":    string(bundle.STUNRelay),
			}
			for name, unit := range units {
				if defaults && strings.HasSuffix(name, ".socket") {
					unit = strings.Replace(unit, "DefaultDependencies=no\n", "", 1)
				}
				write("etc/systemd/system/"+name, []byte(unit), 0o644)
			}
			for _, path := range []string{"/usr/lib/lanpanel/lanpanel", rendered.Candidate.Paths.Executable} {
				write(path, []byte("#!/bin/true\n"), 0o755)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, analyzer, "--root="+root, "--man=no", "--generators=no", "verify", "multi-user.target")
			output, err := command.CombinedOutput()
			cycle := strings.Contains(strings.ToLower(string(output)), "ordering cycle")
			if defaults {
				if !cycle {
					t.Fatalf("default socket ordering did not reproduce the boot cycle: err=%v\n%s", err, output)
				}
			} else if err != nil || cycle {
				t.Fatalf("Headscale boot transaction is invalid: %v\n%s", err, output)
			}
		})
	}
}
