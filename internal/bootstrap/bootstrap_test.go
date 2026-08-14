//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"lanpanel/internal/identity"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBPFGuardDirectoryRequiresExactBPFFSMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root runtime-guard test")
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), " /sys/fs/bpf ") {
		t.Skip("test runner has no bpffs")
	}
	if err := ensureBPFGuardDirectory(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedBootstrapPreflightRequirementsAreCanonical(t *testing.T) {
	paths := FixedPaths()
	managed := FixedManagedPathRequirements(paths)
	for index := 1; index < len(managed); index++ {
		if managed[index-1].Path >= managed[index].Path {
			t.Fatal("fixed managed paths are not canonical")
		}
	}
	disks := FixedDiskRequirements(paths)
	for index := 1; index < len(disks); index++ {
		if disks[index-1].Path >= disks[index].Path {
			t.Fatal("fixed disk requirements are not canonical")
		}
	}
}

func TestBootstrapRejectsBeforeFirstSideEffect(t *testing.T) {
	root := t.TempDir()
	paths := testPaths(root)
	request := Request{Paths: paths, SourceBinaryPath: filepath.Join(root, "candidate"), Random: errorReader{}, Preflight: func(context.Context, identity.ManagementAuthority, uint64) (preflight.ExpansionRequest, preflight.Result, error) {
		t.Fatal("preflight called without release authority")
		return preflight.ExpansionRequest{}, preflight.Result{}, nil
	}}
	if err := install(context.Background(), request, false); err == nil {
		t.Fatal("missing release authority accepted")
	}
	if _, err := os.Lstat(paths.Journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal side effect exists: %v", err)
	}
}

func TestBootstrapJournalSlotsPreserveExactAttempt(t *testing.T) {
	root := t.TempDir()
	if err := os.Chown(root, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, "bootstrap-journal")
	journal := testJournal(root)
	store, err := createJournal(journalPath, uint32(os.Geteuid()), uint32(os.Getegid()), journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.Sequence = 2
	journal.Phase = PhaseBundleCommitted
	journal.ArtifactDigests["bundle"] = strings.Repeat("b", 64)
	if err := store.update(journal); err != nil {
		t.Fatal(err)
	}
	_ = store.close()
	opened, loaded, err := openJournal(journalPath, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	if loaded.AttemptID != journal.AttemptID || loaded.InstallationID != journal.InstallationID || loaded.Sequence != 2 || loaded.Phase != PhaseBundleCommitted {
		t.Fatalf("loaded=%#v", loaded)
	}
}

func TestManagementAuthorityConflictFailsClosed(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.71.72.73:52345")
	if err != nil {
		t.Skip(err)
	}
	defer listener.Close()
	if ManagementAuthorityAvailable(identity.ManagementAuthority{Address: "127.71.72.73", Port: 52345}) == nil {
		t.Fatal("hostile Management binding was accepted")
	}
}

func TestSystemdAssetsReserveExactAuthorityAndKeepRolesIndependent(t *testing.T) {
	journal := testJournal(t.TempDir())
	journal.Accounts.Identities = []identity.AccountIdentity{{Role: identity.RoleUI, UID: 1101, GID: 1201}, {Role: identity.RoleTimer, UID: 1102, GID: 1201}, {Role: identity.RoleRecovery, UID: 1103, GID: 1201}}
	artifacts, err := renderArtifacts(journal)
	if err != nil {
		t.Fatal(err)
	}
	helperUnit := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-helper.service")])
	for _, required := range []string{"Type=notify", "NotifyAccess=main"} {
		if !strings.Contains(helperUnit, required) {
			t.Fatalf("helper unit omitted %q: %s", required, helperUnit)
		}
	}
	socket := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-management.socket")])
	if !strings.Contains(socket, "ListenStream=127.41.42.43:52345") || !strings.Contains(socket, "FileDescriptorName=lanpanel-management-"+journal.GenerationID) || !strings.Contains(socket, "RemoveOnStop=no") {
		t.Fatalf("socket=%s", socket)
	}
	recoveryUnit := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-recovery.service")])
	for _, required := range []string{"Type=oneshot", "Before=lanpanel-nginx.service", "Requires=lanpanel-helper.service", "RestrictAddressFamilies=AF_UNIX", "RemainAfterExit=yes"} {
		if !strings.Contains(recoveryUnit, required) {
			t.Fatalf("recovery unit omitted %q: %s", required, recoveryUnit)
		}
	}
	nginxUnit := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-nginx.service")])
	for _, required := range []string{"Type=simple", "Requires=lanpanel-helper.service lanpanel-recovery.service", "After=network.target lanpanel-helper.service lanpanel-recovery.service", "ExecStart=" + journal.Paths.BinaryPath + " startup-guard", "ExecReload=" + journal.Paths.BinaryPath + " reload-guard", "ExecStop=" + journal.Paths.BinaryPath + " reload-guard stop", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE"} {
		if !strings.Contains(nginxUnit, required) {
			t.Fatalf("Nginx unit omitted %q: %s", required, nginxUnit)
		}
	}
	for _, forbidden := range []string{"Type=forking", "CAP_SYS_ADMIN", "CAP_NET_ADMIN"} {
		if strings.Contains(nginxUnit, forbidden) {
			t.Fatalf("Nginx unit contains %q: %s", forbidden, nginxUnit)
		}
	}
	ui := string(artifacts[filepath.Join(journal.Paths.SystemdRoot, "lanpanel-ui.service")])
	for _, forbidden := range []string{"PartOf=", "BindsTo=", "lanpanel-timer.service", "nginx", "headscale"} {
		if strings.Contains(ui, forbidden) {
			t.Fatalf("UI couples independent role through %q", forbidden)
		}
	}
}

func TestVendorNginxMaskIsExactAndPersistent(t *testing.T) {
	root := t.TempDir()
	if err := installVendorNginxMask(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nginx.service")
	if err := verifyVendorNginxMask(path); err != nil {
		t.Fatal(err)
	}
	if err := installVendorNginxMask(root); err != nil {
		t.Fatalf("exact mask retry failed: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installVendorNginxMask(root); err == nil {
		t.Fatal("foreign vendor unit was replaced by a mask")
	}
}

func TestTokenDeliveryMarksAttemptBeforeOutputAndNeverRedirectsSecret(t *testing.T) {
	root := t.TempDir()
	if err := os.Chown(root, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := testJournal(root)
	store, err := createJournal(journal.Paths.Journal, uint32(os.Geteuid()), uint32(os.Getegid()), journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.Sequence = 2
	journal.Phase = PhaseActivated
	journal.FinalCommitDigest = strings.Repeat("f", 64)
	if err := store.update(journal); err != nil {
		t.Fatal(err)
	}
	defer store.close()
	var output bytes.Buffer
	token := []byte("sentinel-admin-token")
	if err := deliverToken(store, &journal, Request{Output: &output}, token); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), string(token)) || !strings.Contains(output.String(), ProtectedAdminTokenPath) {
		t.Fatalf("redirected output=%q", output.String())
	}
	if !journal.TokenDeliveryAttempted {
		t.Fatal("delivery attempt was not durable")
	}
	output.Reset()
	if err := deliverToken(store, &journal, Request{Output: &output}, token); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatal("token delivery was replayed")
	}
}

func testJournal(root string) Journal {
	profile := release.OSProfile{ID: "debian-13", Family: "debian", Release: "13", Architecture: "amd64", SystemdVersion: "257.1", NginxVersion: "1.26.0", PackageSnapshotDigest: strings.Repeat("1", 64), ManagedConfinement: release.ConfinementProfile{SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "6.12.1", CgroupMode: "unified_v2", BindListenPolicy: "systemd_bind_deny_bpf_lsm_listen_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1", ProtectedDestinations: []string{"127.0.0.0/8", "169.254.169.254/32", "::1/128"}, QualificationDigest: strings.Repeat("8", 64)}}
	profileDigest, _ := release.ProfileDigest(profile)
	paths := testPaths(root)
	request := preflight.ExpansionRequest{Scope: preflight.ExpansionBootstrap, Target: "installation", Generation: 1, Profile: preflight.ExpectedProfile{ID: "debian", VersionID: "13", Architecture: "amd64", SystemdVersion: profile.SystemdVersion, NginxVersion: profile.NginxVersion, PackageSnapshotDigest: "sha256:" + profile.PackageSnapshotDigest, ManagedConfinement: preflight.ManagedConfinementProfile{SchemaVersion: profile.ManagedConfinement.SchemaVersion, KernelRelease: profile.ManagedConfinement.KernelRelease, CgroupMode: profile.ManagedConfinement.CgroupMode, BindListenPolicy: profile.ManagedConfinement.BindListenPolicy, ConnectPolicy: profile.ManagedConfinement.ConnectPolicy, FilesystemPolicy: profile.ManagedConfinement.FilesystemPolicy, ProtectedDestinations: append([]string(nil), profile.ManagedConfinement.ProtectedDestinations...), QualificationDigest: "sha256:" + profile.ManagedConfinement.QualificationDigest}, Authority: preflight.ProfileAuthority{Kind: preflight.FinalSupportedProfile, Digest: "sha256:" + profileDigest, LiveQualified: true}}, BootstrapListeners: []preflight.ListenerRequirement{{Protocol: "tcp", Address: "127.41.42.43", Port: 52345, Purpose: "management"}}, Disks: []preflight.DiskRequirement{{Path: root, MinimumAvailableBytes: 1}}, LastTrustedWall: time.Unix(1700000000, 0).UTC()}
	requestDigest, _ := preflight.ExpansionRequestDigest(request)
	accounts, _ := identity.InstallationAccounts("ins_00000000000000000000000000000001")
	return Journal{SchemaVersion: JournalSchemaVersion, AttemptID: "bst_" + strings.Repeat("a", 64), InstallationID: "ins_00000000000000000000000000000001", GenerationID: "gen_00000000000000000000000000000001", SafetyGeneration: 1, Phase: PhasePrepared, Sequence: 1, Release: release.InstallIdentity{Kind: release.EnvelopeFinal, ReleaseTag: "v1.0.0", EnvelopeDigest: strings.Repeat("2", 64), ManifestDigest: strings.Repeat("3", 64), Binary: release.AssetIdentity{Path: "lanpanel", Digest: strings.Repeat("4", 64), Bytes: 1}, SourceTreeDigest: strings.Repeat("5", 64), Lego: release.AssetIdentity{Path: "lego", Digest: strings.Repeat("8", 64), Bytes: 1}, Profile: profile, ProfileDigest: profileDigest, CapabilityDigest: strings.Repeat("6", 64), CandidateDigest: strings.Repeat("7", 64), HostFingerprint: "host-one", Operation: "bootstrap_install", AuthorityCreatedAt: time.Unix(1700000000, 0).UTC()}, Authority: identity.ManagementAuthority{Address: "127.41.42.43", Port: 52345}, PreflightRequest: request, PreflightDigest: requestDigest, Accounts: accounts, Paths: paths, ArtifactDigests: map[string]string{"release_binary": strings.Repeat("4", 64)}, PlannedPaths: canonicalPaths([]string{paths.Journal, paths.CommitPath, paths.PersistentRoot})}
}

func testPaths(root string) Paths {
	return Paths{Journal: filepath.Join(root, "bootstrap-journal"), StartupAuthority: filepath.Join(root, "startup-authority.json"), CommitPath: filepath.Join(root, "bootstrap-commit.json"), PersistentRoot: root, InstallationRoot: filepath.Join(root, "installation"), StateRoot: filepath.Join(root, "state"), SafetyRoot: filepath.Join(root, "safety"), OwnershipRoot: filepath.Join(root, "ownership"), LockRoot: filepath.Join(root, "locks"), PackageRoot: filepath.Join(root, "packages"), RuntimeRoot: filepath.Join(root, "run"), SystemdRoot: filepath.Join(root, "systemd"), SysusersPath: filepath.Join(root, "etc", "sysusers.conf"), BinaryPath: filepath.Join(root, "usr", "lanpanel")}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

var _ io.Reader = errorReader{}
