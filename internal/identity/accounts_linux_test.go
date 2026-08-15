//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoAccessAccountsBindInstallationAndResource(t *testing.T) {
	first, err := GoAccessAccounts("ins_00000000000000000000000000000001", "res_00000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	second, err := GoAccessAccounts("ins_00000000000000000000000000000002", "res_00000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if first.Application.User == second.Application.User || first.Relay == nil || first.Application.User == first.Relay.User || !strings.Contains(first.Application.Comment, first.InstallationID) {
		t.Fatal("GoAccess account origin is not exact")
	}
}

func TestInstallationAccountsAreCollisionSafeAndExact(t *testing.T) {
	set, err := InstallationAccounts("ins_00000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderSysusers(set)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), "sudo") || strings.Contains(string(rendered), " /bin/") || !strings.Contains(string(rendered), NoLoginShell) {
		t.Fatalf("unsafe sysusers content: %s", rendered)
	}

	root := t.TempDir()
	passwd, group, shadow := filepath.Join(root, "passwd"), filepath.Join(root, "group"), filepath.Join(root, "shadow")
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(passwd, "root:x:0:0:root:/root:/bin/sh\n")
	write(group, "root:x:0:\n")
	write(shadow, "root:*:1:0:99999:7:::\n")
	present, identities, err := InspectAccountFiles(set, passwd, group, shadow)
	if err != nil || present || len(identities) != 0 {
		t.Fatalf("fresh accounts=%v,%v,%v", present, identities, err)
	}

	var passwdData, groupData, shadowData strings.Builder
	passwdData.WriteString("root:x:0:0:root:/root:/bin/sh\n")
	groupData.WriteString("root:x:0:\n")
	shadowData.WriteString("root:*:1:0:99999:7:::\n")
	groupData.WriteString(set.HelperClientGroup + ":x:3000:\n")
	createdGroups := map[string]int{set.HelperClientGroup: 3000}
	for index, spec := range set.Specs {
		uid := 3100 + index
		gid, exists := createdGroups[spec.Group]
		if !exists {
			gid = 3200 + index
			createdGroups[spec.Group] = gid
			groupData.WriteString(spec.Group + ":x:" + itoa(gid) + ":\n")
		}
		passwdData.WriteString(spec.User + ":x:" + itoa(uid) + ":" + itoa(gid) + ":" + spec.Comment + ":" + spec.Home + ":" + spec.Shell + "\n")
		shadowData.WriteString(spec.User + ":!:1:0:99999:7:::\n")
	}
	write(passwd, passwdData.String())
	write(group, groupData.String())
	write(shadow, shadowData.String())
	present, identities, err = InspectAccountFiles(set, passwd, group, shadow)
	if err != nil || !present || len(identities) != len(set.Specs) {
		t.Fatalf("installed accounts=%v,%v,%v", present, identities, err)
	}

	write(group, groupData.String()+"wheel:x:4000:"+set.Specs[0].User+"\n")
	if _, _, err := InspectAccountFiles(set, passwd, group, shadow); err == nil {
		t.Fatal("supplementary privilege was accepted")
	}
}

func TestPartialExactInstallationAccountCanResumeSubmittedSysusers(t *testing.T) {
	set, _ := InstallationAccounts("ins_00000000000000000000000000000001")
	root := t.TempDir()
	passwd, group, shadow := filepath.Join(root, "passwd"), filepath.Join(root, "group"), filepath.Join(root, "shadow")
	_ = os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o600)
	_ = os.WriteFile(group, []byte("root:x:0:\n"+set.HelperClientGroup+":x:3000:\n"), 0o600)
	_ = os.WriteFile(shadow, []byte("root:*:1:0:99999:7:::\n"), 0o600)
	complete, identities, err := inspectAccountFiles(set, passwd, group, shadow, true)
	if err != nil || complete || len(identities) != 0 {
		t.Fatalf("partial=%v,%v,%v", complete, identities, err)
	}
}

func TestPartialOrWrongInstallationAccountIsRejected(t *testing.T) {
	set, _ := InstallationAccounts("ins_00000000000000000000000000000001")
	root := t.TempDir()
	passwd, group, shadow := filepath.Join(root, "passwd"), filepath.Join(root, "group"), filepath.Join(root, "shadow")
	_ = os.WriteFile(passwd, []byte(set.Specs[0].User+":x:3100:3200:wrong:/home/wrong:/bin/sh\n"), 0o600)
	_ = os.WriteFile(group, []byte(set.Specs[0].Group+":x:3200:\n"), 0o600)
	_ = os.WriteFile(shadow, []byte(set.Specs[0].User+":!:1:0:99999:7:::\n"), 0o600)
	if _, _, err := InspectAccountFiles(set, passwd, group, shadow); err == nil {
		t.Fatal("hostile partial account was adopted")
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
