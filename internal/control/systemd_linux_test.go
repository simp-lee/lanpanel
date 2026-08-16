//go:build linux

package control

import (
	"encoding/binary"
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
