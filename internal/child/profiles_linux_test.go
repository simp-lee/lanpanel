//go:build linux

package child

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExternalProfilesAreFixedAndIncompleteProfilesStayUnavailable(t *testing.T) {
	want := []ProfileID{ProfileAPTTransaction, ProfileDPKGTransaction, ProfileGoAccessProbe, ProfileHeadscaleAdmin, ProfileHTPasswd, ProfileLego, ProfileNginxTest, ProfileSystemctl, ProfileSystemdSysusers, ProfileTailscaleAdmin}
	if got := FixedProfileIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fixed profiles=%v want=%v", got, want)
	}
	nginx, err := ResolveProfile(ProfileNginxTest, Identities{})
	if err != nil || !nginx.Complete || nginx.Executable != "/usr/sbin/nginx" || !reflect.DeepEqual(nginx.Arguments, []string{"-t", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/"}) || !nginx.RootTCB || nginx.Network != NetworkNone {
		t.Fatalf("Nginx profile=%#v error=%v", nginx, err)
	}
	htpasswd, err := ResolveProfile(ProfileHTPasswd, Identities{EphemeralHTPasswd: Identity{UID: 1200, GID: 1200}})
	if err != nil || htpasswd.Complete {
		t.Fatalf("incomplete htpasswd profile=%#v error=%v", htpasswd, err)
	}
	if _, err := ResolveProfile(ProfileID("shell"), Identities{}); err == nil {
		t.Fatal("unknown arbitrary executable profile was accepted")
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
