//go:build linux

package child

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInvocationCgroupNamesAreTyped(t *testing.T) {
	for _, name := range []string{"lanpanel-lego-cert_" + strings.Repeat("a", 32), "lanpanel-package-pkg_" + strings.Repeat("b", 64)} {
		if !validInvocationCgroupName(name) {
			t.Fatalf("valid invocation cgroup rejected: %s", name)
		}
	}
	for _, name := range []string{"lanpanel-package-pkg_" + strings.Repeat("b", 63), "lanpanel-lego-cert_" + strings.Repeat("z", 32), "lanpanel-other-" + strings.Repeat("a", 32)} {
		if validInvocationCgroupName(name) {
			t.Fatalf("invalid invocation cgroup accepted: %s", name)
		}
	}
}

func TestExternalProfilesAreFixedAndIncompleteProfilesStayUnavailable(t *testing.T) {
	want := []ProfileID{ProfileAPTDownload, ProfileAPTOfflineTransaction, ProfileAPTSimulate, ProfileAPTTransaction, ProfileDPKGTransaction, ProfileGoAccessAccounts, ProfileGoAccessProbe, ProfileGoAccessRetain, ProfileGoAccessShow, ProfileGoAccessStart, ProfileGoAccessStop, ProfileHeadscaleAccounts, ProfileHeadscaleActivateShow, ProfileHeadscaleActivateStart, ProfileHeadscaleActivateStop, ProfileHeadscaleAdmin, ProfileHeadscaleBootDisable, ProfileHeadscaleBootEnable, ProfileHeadscaleBootPersist, ProfileHeadscaleBootReconcile, ProfileHeadscaleFallbackStop, ProfileHeadscalePrivateProbe, ProfileHeadscaleShow, ProfileHeadscaleStart, ProfileHeadscaleStop, ProfileLego, ProfileNginxDump, ProfileExistingNginxTest, ProfileNginxQuitSignal, ProfileNginxReloadSignal, ProfileNginxReopenSignal, ProfileNginxStart, ProfileNginxTest, ProfileResourceAccounts, ProfileResourceDaemonReload, ProfileResourceShow, ProfileResourceStart, ProfileResourceStop, ProfileSystemctl, ProfileSystemctlBootstrap, ProfileExistingNginxStop, ProfileSystemctlNginxReload, ProfileSystemctlNginxStart, ProfileSystemctlNginxStop, ProfileSystemdSysusers, ProfileTailscaleAdmin}
	if got := FixedProfileIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fixed profiles=%v want=%v", got, want)
	}
	nginx, err := ResolveProfile(ProfileNginxTest, Identities{})
	if err != nil || !nginx.Complete || nginx.Executable != "/usr/sbin/nginx" || !reflect.DeepEqual(nginx.Arguments, []string{"-t", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/"}) || !nginx.RootTCB || nginx.Network != NetworkUnixOnly {
		t.Fatalf("Nginx profile=%#v error=%v", nginx, err)
	}
	start, err := ResolveProfile(ProfileNginxStart, Identities{})
	if err != nil || !start.PersistentDaemon || start.Timeout != 0 || !reflect.DeepEqual(start.Arguments, []string{"-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/", "-g", "daemon off;"}) {
		t.Fatalf("persistent Nginx profile=%#v error=%v", start, err)
	}
	reopen, err := ResolveProfile(ProfileNginxReopenSignal, Identities{})
	if err != nil || !reopen.Complete || !reflect.DeepEqual(reopen.Arguments, []string{"-s", "reopen", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/", "-e", "stderr"}) || !reflect.DeepEqual(reopen.AllowedCapabilities, []int{0, 1, 5, 6, 7}) || slices.Contains(reopen.AllowedCapabilities, 10) {
		t.Fatalf("Nginx reopen profile=%#v error=%v", reopen, err)
	}
	stop, err := ResolveProfile(ProfileSystemctlNginxStop, Identities{})
	if err != nil || !stop.Complete || !reflect.DeepEqual(stop.Arguments, []string{"stop", "lanpanel-nginx.service"}) || !reflect.DeepEqual(stop.AllowedAddressFamilies, []int{1}) {
		t.Fatalf("Nginx stop profile=%#v error=%v", stop, err)
	}
	existingStop, err := ResolveProfile(ProfileExistingNginxStop, Identities{})
	if err != nil || !existingStop.Complete || !reflect.DeepEqual(existingStop.Arguments, []string{"stop", "nginx.service"}) || !reflect.DeepEqual(existingStop.AllowedAddressFamilies, []int{1}) {
		t.Fatalf("existing Nginx stop profile=%#v error=%v", existingStop, err)
	}
	existingTest, err := ResolveProfile(ProfileExistingNginxTest, Identities{})
	if err != nil || !existingTest.Complete || !reflect.DeepEqual(existingTest.Arguments, []string{"-t"}) || existingTest.Network != NetworkUnixOnly {
		t.Fatalf("existing Nginx test profile=%#v error=%v", existingTest, err)
	}
	headscaleInvocation := Invocation{Headscale: &HeadscaleInvocation{HeadscaleID: "hds_00000000000000000000000000000001"}}
	for profileID, wantArguments := range map[ProfileID][]string{
		ProfileHeadscaleStart:         {"start", "lanpanel-headscale.service"},
		ProfileHeadscaleStop:          {"stop", "lanpanel-headscale.service"},
		ProfileHeadscaleBootEnable:    {"enable", "--now", "lanpanel-headscale.service", "lanpanel-headscale-control.socket", "lanpanel-headscale-stun.socket"},
		ProfileHeadscaleBootReconcile: {"enable", "--now", "--no-block", "lanpanel-headscale.service", "lanpanel-headscale-control.socket", "lanpanel-headscale-stun.socket"},
		ProfileHeadscaleBootPersist:   {"enable", "lanpanel-headscale.service", "lanpanel-headscale-control.socket", "lanpanel-headscale-stun.socket"},
		ProfileHeadscaleBootDisable:   {"disable", "--now", "lanpanel-headscale-stun.socket", "lanpanel-headscale-control.socket", "lanpanel-headscale.service"},
	} {
		profile, err := ResolveInvocation(profileID, Identities{}, headscaleInvocation)
		if err != nil || !profile.Complete || !profile.RootTCB || !reflect.DeepEqual(profile.Arguments, wantArguments) {
			t.Fatalf("Headscale profile %s=%#v error=%v", profileID, profile, err)
		}
	}
	show, err := ResolveInvocation(ProfileHeadscaleShow, Identities{}, headscaleInvocation)
	if err != nil || !show.Complete || len(show.Arguments) != 4 || show.Arguments[3] != "lanpanel-headscale.service" {
		t.Fatalf("Headscale show profile=%#v error=%v", show, err)
	}
	if _, err := ResolveProfile(ProfileID("shell"), Identities{}); err == nil {
		t.Fatal("unknown arbitrary executable profile was accepted")
	}
}

func TestTailscaleLoginUsesOnlyFileAuthKeyAndExactControlURL(t *testing.T) {
	identities := Identities{TailscaleOperator: Identity{UID: 3200, GID: 3200}}
	invocation := Invocation{Tailscale: &TailscaleInvocation{Action: TailscaleLogin, ControlURL: "https://control.example.test", AuthKeyPath: "/var/lib/lanpanel/connector/auth/job_0000000000000000000000000000000000000000000000000000000000000001.key", ExecutableDigest: strings.Repeat("a", 64)}}
	profile, err := ResolveInvocation(ProfileTailscaleAdmin, identities, invocation)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"up", "--login-server=https://control.example.test", "--auth-key=file:/var/lib/lanpanel/connector/auth/job_0000000000000000000000000000000000000000000000000000000000000001.key"}
	if !reflect.DeepEqual(profile.Arguments, want) || strings.Contains(strings.Join(profile.Arguments, " "), "tskey-auth-") {
		t.Fatalf("Tailscale login profile=%#v", profile)
	}
	invocation.Tailscale.AuthKeyPath = "/root/key"
	if _, err := ResolveInvocation(ProfileTailscaleAdmin, identities, invocation); err == nil {
		t.Fatal("caller-selected Tailscale auth path accepted")
	}
}

func TestHeadscaleAdminProfilesUseOnlyTypedImmutableLifecycleArguments(t *testing.T) {
	identities := Identities{Headscale: Identity{UID: 3100, GID: 3100}}
	headscaleID := "hds_00000000000000000000000000000001"
	profile, err := ResolveInvocation(ProfileHeadscaleAdmin, identities, Invocation{Headscale: &HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: HeadscalePreauthCreate, Identifier: "17", ExpirationSeconds: 3600}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--config", "/etc/lanpanel-headscale/config.yaml", "--output", "json-line", "preauthkeys", "create", "--user", "17", "--expiration", "3600s"}
	if !reflect.DeepEqual(profile.Arguments, want) || profile.UID != 3100 || profile.Network != NetworkUnixOnly || !profile.Complete {
		t.Fatalf("Headscale admin profile=%#v", profile)
	}
	for _, hostile := range []HeadscaleInvocation{{HeadscaleID: headscaleID, AdminAction: HeadscalePreauthCreate, Identifier: "17", ExpirationSeconds: 86401}, {HeadscaleID: headscaleID, AdminAction: HeadscalePreauthRevoke, Identifier: "key-secret"}, {HeadscaleID: headscaleID, AdminAction: "delete_user", Identifier: "1"}} {
		if _, err := ResolveInvocation(ProfileHeadscaleAdmin, identities, Invocation{Headscale: &hostile}); err == nil {
			t.Fatalf("hostile Headscale admin invocation accepted: %#v", hostile)
		}
	}
}

func TestHeadscaleAccountInvocationUsesOnlyFixedAuthorityPath(t *testing.T) {
	id := "hds_00000000000000000000000000000001"
	profile, err := ResolveInvocation(ProfileHeadscaleAccounts, Identities{}, Invocation{Headscale: &HeadscaleInvocation{HeadscaleID: id}})
	if err != nil || !profile.Complete || !reflect.DeepEqual(profile.Arguments, []string{"/etc/sysusers.d/lanpanel-headscale.conf"}) {
		t.Fatalf("Headscale account profile=%#v error=%v", profile, err)
	}
	if _, err := ResolveInvocation(ProfileHeadscaleAccounts, Identities{}, Invocation{Headscale: &HeadscaleInvocation{HeadscaleID: "res_00000000000000000000000000000001"}}); err == nil {
		t.Fatal("arbitrary Headscale account identity was accepted")
	}
}

func TestResourceInvocationsDeriveOnlyStableUnits(t *testing.T) {
	resourceID := "res_00000000000000000000000000000001"
	for id, want := range map[ProfileID][]string{
		ProfileResourceAccounts:     {"/etc/lanpanel/sysusers/" + resourceID + ".conf"},
		ProfileResourceDaemonReload: {"daemon-reload"},
		ProfileResourceStart:        {"enable", "--now", "lanpanel-app-00000000000000000000.socket", "lanpanel-app-00000000000000000000.service"},
		ProfileResourceStop:         {"disable", "--now", "lanpanel-app-00000000000000000000.socket", "lanpanel-app-00000000000000000000.service"},
	} {
		profile, err := ResolveInvocation(id, Identities{}, Invocation{Resource: &ResourceInvocation{ResourceID: resourceID}})
		if err != nil || !profile.Complete || !reflect.DeepEqual(profile.Arguments, want) {
			t.Fatalf("%s profile=%#v error=%v", id, profile, err)
		}
	}
	for _, id := range []ProfileID{ProfileResourceStart, ProfileResourceStop} {
		relay, err := ResolveInvocation(id, Identities{}, Invocation{Resource: &ResourceInvocation{ResourceID: resourceID, Relay: true}})
		if err != nil || !reflect.DeepEqual(relay.Arguments, map[ProfileID][]string{ProfileResourceStart: {"enable", "--now", "lanpanel-app-00000000000000000000.service", "lanpanel-app-00000000000000000000.socket", "lanpanel-relay-00000000000000000000.service"}, ProfileResourceStop: {"disable", "--now", "lanpanel-app-00000000000000000000.socket", "lanpanel-app-00000000000000000000.service", "lanpanel-relay-00000000000000000000.service"}}[id]) {
			t.Fatalf("relay profile=%#v error=%v", relay, err)
		}
	}
	if _, err := ResolveInvocation(ProfileResourceStart, Identities{}, Invocation{Resource: &ResourceInvocation{ResourceID: "../../ssh"}}); err == nil {
		t.Fatal("caller-selected unit escaped stable resource identity")
	}
}

func TestNginxProfilesFitFixedUnitCapabilityBoundary(t *testing.T) {
	unitCapabilities := []int{0, 1, 5, 6, 7, 8, 10}
	for _, id := range []ProfileID{ProfileNginxStart, ProfileNginxTest, ProfileNginxDump, ProfileNginxReloadSignal, ProfileNginxReopenSignal, ProfileNginxQuitSignal} {
		profile, err := ResolveProfile(id, Identities{})
		if err != nil {
			t.Fatal(err)
		}
		for _, capability := range profile.AllowedCapabilities {
			if !slices.Contains(unitCapabilities, capability) {
				t.Fatalf("%s capability %d exceeds unit boundary", id, capability)
			}
		}
	}
}

func TestPackageInvocationsDeriveOnlyExactAPTArguments(t *testing.T) {
	invocation := Invocation{Package: &PackageInvocation{TransactionID: "pkg_" + strings.Repeat("a", 64), LockWaitSeconds: 30, Packages: []PackageArgument{
		{Name: "goaccess", Version: "1.9.3-1", Digest: strings.Repeat("b", 64), Bytes: 1024, MaximumInstalledFileBytes: 8 << 20},
		{Name: "nginx", Version: "1.22.1-9", Digest: strings.Repeat("c", 64), Bytes: 2048, MaximumInstalledFileBytes: 16 << 20},
	}}}
	distro, err := ResolveInvocation(ProfileAPTTransaction, Identities{}, invocation)
	if err != nil || !distro.Complete || distro.Network != NetworkHostQualified || !slices.Contains(distro.Arguments, "nginx=1.22.1-9") {
		t.Fatalf("distro profile=%#v error=%v", distro, err)
	}
	offlineInvocation := invocation
	offlinePackage := *invocation.Package
	offlineInvocation.Package = &offlinePackage
	offlineInvocation.Package.Staged = true
	offline, err := ResolveInvocation(ProfileAPTOfflineTransaction, Identities{}, offlineInvocation)
	wantPath := "/var/lib/lanpanel/packages/staging/" + invocation.Package.TransactionID + "/" + strings.Repeat("c", 64) + ".deb"
	if err != nil || !offline.Complete || offline.Network != NetworkNoSockets || !slices.Contains(offline.Arguments, "--no-download") || !slices.Contains(offline.Arguments, wantPath) {
		t.Fatalf("offline profile=%#v error=%v", offline, err)
	}
	bad := invocation
	copyPackage := *invocation.Package
	bad.Package = &copyPackage
	bad.Package.Packages = append([]PackageArgument(nil), invocation.Package.Packages...)
	bad.Package.Packages[0].Name = "--option"
	if _, err := ResolveInvocation(ProfileAPTTransaction, Identities{}, bad); err == nil {
		t.Fatal("package flag injection was accepted")
	}
}

func TestFixedProfilesContainNoForbiddenUtilityExecutable(t *testing.T) {
	forbidden := map[string]bool{"curl": true, "wget": true, "sha256sum": true, "tar": true, "unzip": true, "openssl": true, "install": true, "cp": true, "mv": true, "rm": true, "ln": true, "chmod": true, "chown": true}
	for _, id := range FixedProfileIDs() {
		profile, err := ResolveProfile(id, Identities{})
		if err != nil {
			t.Fatal(err)
		}
		if forbidden[filepath.Base(profile.Executable)] {
			t.Fatalf("forbidden utility executable in %s: %s", id, profile.Executable)
		}
	}
}

func TestLauncherHasNoNonRootOrIncompleteFallback(t *testing.T) {
	if _, err := NewLauncher("/usr/bin/other", Identities{}); err == nil {
		t.Fatal("caller-selected bootstrap executable was accepted")
	}
	launcher, err := NewLauncher(FixedLanPanelExecutable, Identities{})
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := launcher.Run(context.Background(), ProfileNginxTest, nil); err == nil {
			t.Fatal("non-root caller launched a privileged child")
		}
	}
	if _, err := launcher.Run(context.Background(), ProfileNginxStart, nil); err == nil {
		t.Fatal("persistent daemon crossed the bounded one-shot launcher")
	}
	if err := ExecuteBootstrap([]string{"/bin/sh"}); err == nil {
		t.Fatal("child bootstrap accepted argv-selected executable")
	}
}

func TestExecutableValidationRejectsLinksAndWritablePaths(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "tool")
	if err := os.WriteFile(file, []byte("tool"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyRootExecutable(file); err == nil {
		t.Fatal("writable external executable was accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyRootExecutable(link); err == nil {
		t.Fatal("symlink executable was accepted")
	}
}

func TestChildProcessGroupIsTerminatedBeforeLeaderReap(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestProcessGroupMember$")
	command.Env = append(os.Environ(), "LANPANEL_PROCESS_GROUP_TEST=leader")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := waitForProcessExit(command.Process.Pid); err != nil {
		t.Fatal(err)
	}
	live, err := processGroupHasLiveMember(command.Process.Pid, command.Process.Pid)
	if err != nil || !live {
		t.Fatalf("descendant before termination=%v,%v", live, err)
	}
	if err := terminateProcessGroupBeforeReap(command.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("reap exited group leader: %v", err)
	}
}

func TestProcessGroupMember(t *testing.T) {
	switch os.Getenv("LANPANEL_PROCESS_GROUP_TEST") {
	case "":
		return
	case "leader":
		command := exec.Command(os.Args[0], "-test.run=^TestProcessGroupMember$")
		command.Env = append(os.Environ(), "LANPANEL_PROCESS_GROUP_TEST=member")
		if err := command.Start(); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "member":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		os.Exit(3)
	}
}

func TestProcessGroupStatParsingIsExact(t *testing.T) {
	group, state, err := parseProcStat([]byte("123 (worker name) S 1 456 456 0 -1"))
	if err != nil || group != 456 || state != "S" {
		t.Fatalf("process stat=%d,%q,%v", group, state, err)
	}
	for _, malformed := range [][]byte{
		[]byte("123 worker S 1 456"),
		[]byte("123 (worker) S 1 invalid"),
	} {
		if _, _, err := parseProcStat(malformed); err == nil {
			t.Fatalf("malformed process stat was accepted: %q", malformed)
		}
	}
}

func TestAPTSimulationReturnsOnlyCanonicalExactChanges(t *testing.T) {
	changes, err := parseAPTSimulation([]byte("Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"))
	if err != nil || len(changes) != 0 {
		t.Fatalf("no-op changes=%#v error=%v", changes, err)
	}
	changes, err = parseAPTSimulation([]byte("Reading package lists...\nInst nginx (1.22.1-9 Debian [amd64])\nInst goaccess (1.9.3-1 Debian [amd64])\nConf nginx (1.22.1-9 Debian [amd64])\n"))
	if err != nil || len(changes) != 2 || changes[0].Name != "goaccess" || changes[1].Version != "1.22.1-9" {
		t.Fatalf("changes=%#v error=%v", changes, err)
	}
	if _, err := parseAPTSimulation([]byte("Remv nginx [1.22.1]\n")); err == nil {
		t.Fatal("APT simulation removal was accepted")
	}
}

func TestGoAccessProfilesDeriveOnlyFixedPerResourceUnits(t *testing.T) {
	inv := Invocation{Resource: &ResourceInvocation{ResourceID: "res_00000000000000000000000000000001", Generation: 2}}
	start, err := ResolveInvocation(ProfileGoAccessStart, Identities{}, inv)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(start.Arguments, " ")
	for _, required := range []string{"lanpanel-goaccess-res_00000000000000000000000000000001-2.service", "lanpanel-goaccess-res_00000000000000000000000000000001-2.socket", "lanpanel-goaccess-relay-res_00000000000000000000000000000001-2.service", "lanpanel-goaccess-retention-res_00000000000000000000000000000001-2.timer"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("start profile missing %q", required)
		}
	}
	retain, err := ResolveInvocation(ProfileGoAccessRetain, Identities{}, inv)
	if err != nil || retain.Timeout != 90*time.Second || !reflect.DeepEqual(retain.Arguments, []string{"start", "lanpanel-goaccess-retention-res_00000000000000000000000000000001-2.service"}) {
		t.Fatalf("retention profile=%v error=%v", retain.Arguments, err)
	}
	if _, err = ResolveInvocation(ProfileGoAccessStart, Identities{}, Invocation{}); err == nil {
		t.Fatal("untyped GoAccess invocation accepted")
	}
	subset := inv
	subset.Resource = &ResourceInvocation{ResourceID: inv.Resource.ResourceID, Generation: 2, UnitMask: 5}
	stop, err := ResolveInvocation(ProfileGoAccessStop, Identities{}, subset)
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(stop.Arguments, " ")
	if !strings.Contains(joined, ".socket") || !strings.Contains(joined, ".service") || strings.Contains(joined, "relay") {
		t.Fatalf("subset stop args=%v", stop.Arguments)
	}
	timerOnly := inv
	timerOnly.Resource = &ResourceInvocation{ResourceID: inv.Resource.ResourceID, Generation: 2, UnitMask: 16}
	timerStop, err := ResolveInvocation(ProfileGoAccessStop, Identities{}, timerOnly)
	wantTimerStop := []string{"disable", "--now", "lanpanel-goaccess-retention-res_00000000000000000000000000000001-2.timer"}
	if err != nil || !reflect.DeepEqual(timerStop.Arguments, wantTimerStop) {
		t.Fatalf("exact timer quiesce profile=%v error=%v", timerStop.Arguments, err)
	}
	show, err := ResolveInvocation(ProfileGoAccessShow, Identities{}, inv)
	if err != nil || !slices.Contains(show.Arguments, "--property=Job") {
		t.Fatalf("GoAccess quiesce inventory lacks pending-job evidence: %v error=%v", show.Arguments, err)
	}
}

func TestOutputIsBoundedAndOnlyDigestsEscape(t *testing.T) {
	writer := newDigestWriter(4)
	if _, err := writer.Write([]byte("sentinel-secret")); !errors.Is(err, errOutputLimit) {
		t.Fatalf("output limit error=%v", err)
	}
	if !writer.CutOff() || !strings.HasPrefix(writer.Digest(), "sha256:") || strings.Contains(writer.Digest(), "sentinel") {
		t.Fatalf("bounded digest writer leaked or missed cutoff: %q", writer.Digest())
	}
	if _, err := ParseExitCode(" 1"); err == nil {
		t.Fatal("noncanonical child exit code was accepted")
	}
}
