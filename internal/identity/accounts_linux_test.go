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
	if strings.Contains(string(rendered), "sudo") || strings.Contains(string(rendered), " /bin/") || !strings.Contains(string(rendered), NoLoginShell) || strings.Contains(string(rendered), "headscale") {
		t.Fatalf("unsafe or premature sysusers content: %s", rendered)
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

func TestHeadscaleAccountIsSeparateAndBoundToInitializedDomain(t *testing.T) {
	installation := "ins_00000000000000000000000000000001"
	set, err := HeadscaleAccounts(installation, "hds_00000000000000000000000000000001")
	if err != nil || len(set.Specs) != 1 || set.Specs[0].Role != RoleHeadscale || !strings.Contains(set.Specs[0].Comment, installation) {
		t.Fatalf("HeadscaleAccounts() = %#v, %v", set, err)
	}
	if _, err := HeadscaleAccounts(installation, "res_00000000000000000000000000000001"); err == nil {
		t.Fatal("non-Headscale identity was accepted")
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

func TestInstallationAccountPasswordPlaceholdersAreExact(t *testing.T) {
	set, err := InstallationAccounts("ins_00000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	data := installationAccountDatabase(set)
	privateGroup := set.Specs[3].Group
	tests := []struct {
		name, database, account, password string
	}{
		{name: "empty passwd", database: "passwd", account: set.Specs[0].User, password: ""},
		{name: "passwd hash", database: "passwd", account: set.Specs[0].User, password: "$6$direct-hash"},
		{name: "wrong passwd placeholder with locked shadow", database: "passwd", account: set.Specs[0].User, password: "!"},
		{name: "empty helper group password", database: "group", account: set.HelperClientGroup, password: ""},
		{name: "helper group password hash", database: "group", account: set.HelperClientGroup, password: "$6$direct-hash"},
		{name: "wrong private group placeholder", database: "group", account: privateGroup, password: "!"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := data
			switch test.database {
			case "passwd":
				changed.passwd = replaceAccountPassword(t, changed.passwd, test.account, test.password)
			case "group":
				changed.group = replaceAccountPassword(t, changed.group, test.account, test.password)
			default:
				t.Fatalf("unknown database %q", test.database)
			}
			passwd, group, shadow := writeAccountDatabase(t, changed)
			if _, _, err := InspectAccountFiles(set, passwd, group, shadow); err == nil {
				t.Fatal("non-sysusers password placeholder was accepted")
			}
			if _, _, err := inspectAccountFiles(set, passwd, group, shadow, true); err == nil {
				t.Fatal("partial account inspection accepted a non-sysusers password placeholder")
			}
		})
	}
}

func TestResourceAccountPasswordPlaceholdersAreExact(t *testing.T) {
	installationID := "ins_00000000000000000000000000000001"
	resourceID := "res_00000000000000000000000000000001"
	resourceSet, err := ResourceAccounts(installationID, resourceID, true)
	if err != nil {
		t.Fatal(err)
	}
	goAccessSet, err := GoAccessAccounts(installationID, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]ResourceAccountSet{"resource": resourceSet, "goaccess": goAccessSet} {
		t.Run(name, func(t *testing.T) {
			data := resourceAccountDatabase(set)
			specs := []AccountSpec{set.Application, *set.Relay}
			for _, spec := range specs {
				t.Run(spec.User, func(t *testing.T) {
					tests := []struct {
						name, database, password string
					}{
						{name: "empty passwd", database: "passwd", password: ""},
						{name: "passwd hash", database: "passwd", password: "$6$direct-hash"},
						{name: "wrong passwd placeholder", database: "passwd", password: "!"},
						{name: "empty group password", database: "group", password: ""},
						{name: "group password hash", database: "group", password: "$6$direct-hash"},
					}
					for _, test := range tests {
						t.Run(test.name, func(t *testing.T) {
							changed := data
							switch test.database {
							case "passwd":
								changed.passwd = replaceAccountPassword(t, changed.passwd, spec.User, test.password)
							case "group":
								changed.group = replaceAccountPassword(t, changed.group, spec.Group, test.password)
							}
							passwd, group, shadow := writeAccountDatabase(t, changed)
							if _, _, err := InspectResourceAccountFiles(set, passwd, group, shadow); err == nil {
								t.Fatal("non-sysusers resource password placeholder was accepted")
							}
						})
					}
				})
			}
		})
	}
}

func TestResourceAccountDeletionRequiresExactPasswordPlaceholders(t *testing.T) {
	set, err := ResourceAccounts("ins_00000000000000000000000000000001", "res_00000000000000000000000000000001", true)
	if err != nil {
		t.Fatal(err)
	}
	data := resourceAccountDatabase(set)
	passwd, group, shadow := writeAccountDatabase(t, data)
	present, identities, err := InspectResourceAccountFiles(set, passwd, group, shadow)
	if err != nil || !present || len(identities) != 2 {
		t.Fatalf("resource account fixture is invalid: present=%v identities=%v err=%v", present, identities, err)
	}
	set.Identities = identities
	tests := []struct {
		name, database, password string
	}{
		{name: "locked shadow does not excuse wrong passwd", database: "passwd", password: "!"},
		{name: "empty passwd", database: "passwd", password: ""},
		{name: "passwd hash", database: "passwd", password: "$6$direct-hash"},
		{name: "empty group password", database: "group", password: ""},
		{name: "group password hash", database: "group", password: "$6$direct-hash"},
	}
	for _, spec := range []AccountSpec{set.Application, *set.Relay} {
		t.Run(spec.User, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					changed := data
					if test.database == "passwd" {
						changed.passwd = replaceAccountPassword(t, changed.passwd, spec.User, test.password)
					} else {
						changed.group = replaceAccountPassword(t, changed.group, spec.Group, test.password)
					}
					passwd, group, shadow := writeAccountDatabase(t, changed)
					if _, err := InspectResourceAccountDeletionFiles(set, passwd, group, shadow); err == nil {
						t.Fatal("resource deletion accepted a non-sysusers password placeholder")
					}
				})
			}
		})
	}
}

func TestHeadscaleAccountPasswordPlaceholdersAreExact(t *testing.T) {
	set, err := HeadscaleAccounts("ins_00000000000000000000000000000001", "hds_00000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	data := installationAccountDatabase(set)
	tests := []struct {
		name, database, account, password string
	}{
		{name: "passwd hash", database: "passwd", account: set.Specs[0].User, password: "$6$direct-hash"},
		{name: "private group empty", database: "group", account: set.Specs[0].Group, password: ""},
		{name: "helper group wrong", database: "group", account: set.HelperClientGroup, password: "!"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := data
			if test.database == "passwd" {
				changed.passwd = replaceAccountPassword(t, changed.passwd, test.account, test.password)
			} else {
				changed.group = replaceAccountPassword(t, changed.group, test.account, test.password)
			}
			passwd, group, shadow := writeAccountDatabase(t, changed)
			if _, _, err := InspectAccountFiles(set, passwd, group, shadow); err == nil {
				t.Fatal("non-sysusers Headscale password placeholder was accepted")
			}
		})
	}
}

func TestForeignAccountPasswordFieldsRemainOutsideManagedContract(t *testing.T) {
	set, err := ResourceAccounts("ins_00000000000000000000000000000001", "res_00000000000000000000000000000001", true)
	if err != nil {
		t.Fatal(err)
	}
	data := resourceAccountDatabase(set)
	data.passwd += "foreign:$6$foreign:9000:9000:Foreign:/home/foreign:/bin/sh\n"
	data.group += "foreign::9000:\n"
	passwd, group, shadow := writeAccountDatabase(t, data)
	present, identities, err := InspectResourceAccountFiles(set, passwd, group, shadow)
	if err != nil || !present || len(identities) != 2 {
		t.Fatalf("foreign password fields changed managed inspection: present=%v identities=%v err=%v", present, identities, err)
	}
}

type accountDatabase struct {
	passwd string
	group  string
	shadow string
}

func installationAccountDatabase(set AccountSet) accountDatabase {
	var passwd, group, shadow strings.Builder
	passwd.WriteString("root:x:0:0:root:/root:/bin/sh\n")
	group.WriteString("root:x:0:\n")
	shadow.WriteString("root:*:1:0:99999:7:::\n")
	group.WriteString(set.HelperClientGroup + ":x:3000:\n")
	createdGroups := map[string]int{set.HelperClientGroup: 3000}
	for index, spec := range set.Specs {
		gid, exists := createdGroups[spec.Group]
		if !exists {
			gid = 3200 + index
			createdGroups[spec.Group] = gid
			group.WriteString(spec.Group + ":x:" + itoa(gid) + ":\n")
		}
		passwd.WriteString(spec.User + ":x:" + itoa(3100+index) + ":" + itoa(gid) + ":" + spec.Comment + ":" + spec.Home + ":" + spec.Shell + "\n")
		shadow.WriteString(spec.User + ":!:1:0:99999:7:::\n")
	}
	return accountDatabase{passwd: passwd.String(), group: group.String(), shadow: shadow.String()}
}

func resourceAccountDatabase(set ResourceAccountSet) accountDatabase {
	var passwd, group, shadow strings.Builder
	passwd.WriteString("root:x:0:0:root:/root:/bin/sh\n")
	group.WriteString("root:x:0:\n")
	shadow.WriteString("root:*:1:0:99999:7:::\n")
	specs := []AccountSpec{set.Application}
	if set.Relay != nil {
		specs = append(specs, *set.Relay)
	}
	for index, spec := range specs {
		uid, gid := 4100+index, 4200+index
		passwd.WriteString(spec.User + ":x:" + itoa(uid) + ":" + itoa(gid) + ":" + spec.Comment + ":" + spec.Home + ":" + spec.Shell + "\n")
		group.WriteString(spec.Group + ":x:" + itoa(gid) + ":\n")
		shadow.WriteString(spec.User + ":!:1:0:99999:7:::\n")
	}
	return accountDatabase{passwd: passwd.String(), group: group.String(), shadow: shadow.String()}
}

func writeAccountDatabase(t *testing.T, data accountDatabase) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	passwd, group, shadow := filepath.Join(root, "passwd"), filepath.Join(root, "group"), filepath.Join(root, "shadow")
	for path, content := range map[string]string{passwd: data.passwd, group: data.group, shadow: data.shadow} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return passwd, group, shadow
}

func replaceAccountPassword(t *testing.T, database, account, password string) string {
	t.Helper()
	old := account + ":x:"
	if strings.Count(database, old) != 1 {
		t.Fatalf("account %q does not have one x password field", account)
	}
	return strings.Replace(database, old, account+":"+password+":", 1)
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
