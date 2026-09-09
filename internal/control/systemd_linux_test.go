//go:build linux

package control

import (
	"encoding/binary"
	"fmt"
	"lanpanel/internal/identity"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestHeadscaleEffectiveUnitObservationIsClosed(t *testing.T) {
	values := map[string]string{"Id": "lanpanel-headscale.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "UnitFileState": "disabled", "MainPID": "123", "ControlGroup": "/system.slice/lanpanel-headscale.service", "User": "headscale", "Group": "headscale", "SupplementaryGroups": "", "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictSUIDSGID": "yes", "PrivateNetwork": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes", "RuntimeDirectory": "lanpanel/headscale", "RuntimeDirectoryMode": "0700", "ProtectSystem": "strict", "ProtectHome": "yes", "ProtectProc": "invisible", "ProcSubset": "pid", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "yes", "SystemCallArchitectures": "native", "RestrictAddressFamilies": "AF_INET6 AF_UNIX AF_INET", "ReadWritePaths": "/run/lanpanel/headscale /var/lib/lanpanel/headscale-runtime", "UMask": "0077", "KillMode": "control-group", "ExecStart": "{ path=/usr/lib/lanpanel/dependencies/headscale ; argv[]=/usr/lib/lanpanel/dependencies/headscale serve --config /etc/lanpanel-headscale/config.json ; ignore_errors=no ; }", "ExecStartPost": "{ path=/usr/lib/lanpanel/lanpanel ; argv[]=/usr/lib/lanpanel/lanpanel headscale-private-probe ; ignore_errors=no ; }", "FragmentPath": "/etc/systemd/system/lanpanel-headscale.service", "DropInPaths": ""}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var lines []string
	for _, key := range keys {
		lines = append(lines, key+"="+values[key])
	}
	raw := []byte(strings.Join(lines, "\n") + "\n")
	parsed, err := parseHeadscaleUnitProperties(raw)
	if err != nil || len(parsed) != len(values) {
		t.Fatalf("closed unit parse: %v, %+v", err, parsed)
	}
	if !sameWords(parsed["RestrictAddressFamilies"], "AF_UNIX AF_INET AF_INET6") {
		t.Fatal("address-family set comparison changed")
	}
	if _, err := parseHeadscaleUnitProperties(append(raw, []byte("Unexpected=value\n")...)); err == nil {
		t.Fatal("unexpected effective property accepted")
	}
	if _, err := parseHeadscaleUnitProperties(append(raw, []byte("User=other\n")...)); err == nil {
		t.Fatal("duplicate effective property accepted")
	}
	parsed["ActiveState"], parsed["SubState"], parsed["MainPID"], parsed["ControlGroup"] = "inactive", "dead", "0", ""
	rendered := testRendered(t)
	account := identity.AccountIdentity{User: "headscale", Group: "headscale"}
	if err := validateHeadscaleServiceProperties(parsed, rendered, account, headscaleServiceInactive, "disabled"); err != nil {
		t.Fatalf("private staging unit state rejected: %v", err)
	}
	if err := validateHeadscaleServiceProperties(parsed, rendered, account, headscaleServiceInactive, "enabled"); err == nil {
		t.Fatal("disabled private staging unit accepted as committed boot activation")
	}
	parsed["UnitFileState"] = "enabled"
	if err := validateHeadscaleServiceProperties(parsed, rendered, account, headscaleServiceInactive, "enabled"); err != nil {
		t.Fatalf("committed boot unit state rejected: %v", err)
	}
}

func TestHostListenersOnCandidatePortsDoNotBlockIsolatedCandidate(t *testing.T) {
	procRoot := headscaleProcFixture(t, 42, false, map[string][]string{
		"tcp": {
			procNetworkRow("0100007F:1F90", "00000000:0000", "0A", 111),
			procNetworkRow("0100007F:2382", "00000000:0000", "0A", 333),
		},
	})
	if err := requireHostCandidateListenersAbsentAt(procRoot, 42); err != nil {
		t.Fatalf("unrelated host 8080/9090 listeners blocked private candidate: %v", err)
	}
}

func TestCandidateHostNetworkNamespaceEscapeIsRejected(t *testing.T) {
	for _, test := range []struct {
		name  string
		table string
		row   string
	}{
		{name: "TCP", table: "tcp", row: procNetworkRow("0100007F:1F90", "00000000:0000", "0A", 222)},
		{name: "UDP", table: "udp", row: procNetworkRow("00000000:0D96", "00000000:0000", "07", 222)},
	} {
		t.Run(test.name, func(t *testing.T) {
			procRoot := headscaleProcFixture(t, 42, true, map[string][]string{test.table: {test.row}})
			if err := requireHostCandidateListenersAbsentAt(procRoot, 42); err == nil {
				t.Fatal("candidate host-network namespace escape was accepted")
			}
		})
	}
}

func headscaleProcFixture(t *testing.T, pid int, sameNamespace bool, rows map[string][]string) string {
	t.Helper()
	root := t.TempDir()
	hostNamespace := filepath.Join(root, "host-netns")
	candidateNamespace := filepath.Join(root, "candidate-netns")
	if err := os.WriteFile(hostNamespace, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sameNamespace {
		candidateNamespace = hostNamespace
	} else if err := os.WriteFile(candidateNamespace, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for process, namespace := range map[int]string{1: hostNamespace, pid: candidateNamespace} {
		nsRoot := filepath.Join(root, fmt.Sprintf("%d/ns", process))
		if err := os.MkdirAll(nsRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(namespace, filepath.Join(nsRoot, "net")); err != nil {
			t.Fatal(err)
		}
	}
	netRoot := filepath.Join(root, "1/net")
	if err := os.MkdirAll(netRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data := header + strings.Join(rows[table], "\n")
		if len(rows[table]) != 0 {
			data += "\n"
		}
		if err := os.WriteFile(filepath.Join(netRoot, table), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func procNetworkRow(local, remote, state string, inode uint64) string {
	return fmt.Sprintf("0: %s %s %s 00000000:00000000 00:00000000 00000000 0 0 %d", local, remote, state, inode)
}

func TestProtectedHeadscaleDatabaseRequiresSQLiteEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	page := make([]byte, 512)
	copy(page, []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(page[16:18], 512)
	page[18], page[19], page[20], page[21], page[22], page[23] = 1, 1, 0, 64, 32, 32
	binary.BigEndian.PutUint32(page[44:48], 4)
	binary.BigEndian.PutUint32(page[56:60], 1)
	if err := os.WriteFile(path, page, 0o600); err != nil {
		t.Fatal(err)
	}
	account := identity.AccountIdentity{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if digest, present, err := protectedRuntimeFile(path, account, true); err != nil || !present || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("SQLite envelope rejected: %q %v %v", digest, present, err)
	}
	page[21] = 0
	if err := os.WriteFile(path, page, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := protectedRuntimeFile(path, account, true); err == nil {
		t.Fatal("malformed SQLite envelope accepted")
	}
}
