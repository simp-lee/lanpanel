//go:build linux

package goaccess

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/child"
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRenderUsesPrivateNetworkAndProtectedRelay(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	candidate, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	service, relay, socket, retentionTimer := string(candidate.Service), string(candidate.Relay), string(candidate.Socket), string(candidate.RetentionTimer)
	for _, required := range []string{"PrivateNetwork=yes", "--no-global-config", "--keep-last=30", "--addr=127.0.0.1", "--port=7890", "ExecStartPre=+/usr/lib/lanpanel/lanpanel goaccess-account-guard", "Environment=LANPANEL_INSTALLATION_ID=", "WantedBy=multi-user.target"} {
		if !strings.Contains(service, required) {
			t.Fatalf("service missing %q", required)
		}
	}
	for _, required := range []string{"JoinsNamespaceOf=lanpanel-goaccess-", "ExecStart=/usr/lib/lanpanel/lanpanel goaccess-relay", "RestrictAddressFamilies=AF_INET", "WantedBy=multi-user.target"} {
		if !strings.Contains(relay, required) {
			t.Fatalf("relay missing %q", required)
		}
	}
	if strings.Contains(retentionTimer, "Persistent=") {
		t.Fatal("retention timer created untracked persistent systemd state")
	}
	if candidate.Paths.RetentionUnit == "" || candidate.Paths.RetentionTimer == "" || !strings.Contains(string(candidate.RetentionService), candidate.Paths.RetentionLock) || !strings.Contains(string(candidate.RetentionService), "TimeoutStartSec=30s") || !strings.Contains(string(candidate.RetentionService), "LANPANEL_INSTALLATION_ID=ins_00000000000000000000000000000001") || !strings.Contains(socket, "ListenStream=/run/lanpanel-goaccess/") || candidate.ServiceIdentity != digest && len(candidate.ServiceIdentity) != 71 {
		t.Fatal("protected endpoint identity missing")
	}
}
func TestServiceIdentityIsLengthDelimited(t *testing.T) {
	if managedServiceIdentity([]byte("a"), []byte("bc")) == managedServiceIdentity([]byte("ab"), []byte("c")) {
		t.Fatal("service identity lost file boundaries")
	}
}

func TestObserveCandidateReconstructsAccountAuthority(t *testing.T) {
	applied := domain.GoAccessBundleIdentity{Enabled: true, Generation: 2, StateGeneration: 1, ServiceIdentity: digest([]byte("service")), UnitIdentities: []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}, WebSocketPath: "/__lanpanel/goaccess-ws"}
	candidate, err := ObserveCandidate("ins_00000000000000000000000000000001", "res_00000000000000000000000000000001", 33, applied)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.User == "" || candidate.RelayUser == "" || len(candidate.Sysusers) == 0 || candidate.Accounts.Application.User != candidate.User || candidate.Paths.StateRoot != "/var/lib/lanpanel/goaccess/res_00000000000000000000000000000001/generations/1" || !candidate.ReuseApplied {
		t.Fatal("observed candidate omitted account or retained-state authority")
	}
}

func TestAccountAuthorityIsInstallationBound(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	first, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render("ins_00000000000000000000000000000002", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.User == second.User || first.UID == second.UID || first.ServiceIdentity == second.ServiceIdentity {
		t.Fatal("GoAccess account authority was not installation-bound")
	}
}

func TestCandidateCleanupRetainsSharedStateOnlyForAppliedGoAccess(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	candidate, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.RetainShared {
		t.Fatal("first enable retained candidate artifacts")
	}
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{RetiredGeneration: 1, RetiredStateGeneration: 1, RetiredServiceIdentity: digest([]byte("prior"))}}}
	candidate, err = Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil || !candidate.RetainShared || !candidate.RetainState || candidate.StateGeneration != 1 || candidate.Paths.StateRoot == "/var/lib/lanpanel/goaccess/res_00000000000000000000000000000001/generations/2" {
		t.Fatalf("applied retained state lost: %+v %v", candidate, err)
	}
}

func TestActiveRepublishReusesExactServiceAndRequiresDisableForServiceIdentityChange(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	first, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	resource.PublicationRecord.State = domain.PublicationPublished
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: first.Generation, StateGeneration: first.StateGeneration, CanonicalHost: resource.Publication.DomainHTTPS.CanonicalDomain, ServiceIdentity: first.ServiceIdentity, UnitIdentities: append([]string(nil), first.UnitIdentities...), WebSocketPath: first.WebSocketPath}}}
	reused, err := Render("ins_00000000000000000000000000000001", resource, 33, 3)
	if err != nil || !reused.ReuseApplied || reused.Generation != 2 || reused.StateGeneration != 2 || reused.ServiceIdentity != first.ServiceIdentity {
		t.Fatalf("active service was not reused exactly: %+v %v", reused, err)
	}
	resource.Publication.DomainHTTPS.GoAccess.WebSocketPath = "/changed"
	if _, err = Render("ins_00000000000000000000000000000001", resource, 33, 3); err == nil {
		t.Fatal("active service identity changed without disable")
	}
}

func TestUnpublishedRepublishStagesNewUnitsAgainstRetainedState(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", GoAccess: domain.GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}}}}
	first, err := Render("ins_00000000000000000000000000000001", resource, 33, 2)
	if err != nil {
		t.Fatal(err)
	}
	resource.PublicationRecord.State = domain.PublicationUnpublished
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{DomainHTTPS: &domain.DomainHTTPSBundleIdentity{GoAccess: domain.GoAccessBundleIdentity{Enabled: true, Generation: 2, StateGeneration: 2, CanonicalHost: "app.example.test", ServiceIdentity: first.ServiceIdentity, UnitIdentities: append([]string(nil), first.UnitIdentities...), WebSocketPath: "/__lanpanel/goaccess-ws"}}}
	candidate, err := Render("ins_00000000000000000000000000000001", resource, 33, 3)
	if err != nil || candidate.ReuseApplied || !candidate.RetainState || candidate.Generation != 3 || candidate.StateGeneration != 2 || candidate.Paths.StateRoot != first.Paths.StateRoot || candidate.Paths.Endpoint == first.Paths.Endpoint {
		t.Fatalf("unpublished republish candidate=%+v err=%v", candidate, err)
	}
}

func TestCandidateGenerationsHaveIsolatedStateAndEndpoints(t *testing.T) {
	first, err := DerivePaths("res_00000000000000000000000000000001", 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DerivePaths("res_00000000000000000000000000000001", 3)
	if err != nil {
		t.Fatal(err)
	}
	if first.StateRoot == second.StateRoot || first.Database == second.Database || first.Report == second.Report || first.Endpoint == second.Endpoint || first.AccessLog != second.AccessLog {
		t.Fatalf("generation paths not isolated: first=%+v second=%+v", first, second)
	}
}

func TestRetentionBoundsCanonicalLogAndRecoversExactTemp(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "access.log")
	lock := filepath.Join(directory, "retention.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(maximumAccessLogBytes + 4096); err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("latest"), maximumAccessLogBytes+4090); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".1.lanpanel", []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = rotateAccessLog(path, lock, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(path)
	if err != nil || current.Size() != 0 {
		t.Fatalf("current log not truncated: info=%v err=%v", current, err)
	}
	snapshot, err := os.Stat(path + ".1")
	if err != nil || snapshot.Size() != maximumAccessLogBytes {
		t.Fatalf("snapshot not bounded: info=%v err=%v", snapshot, err)
	}
	tail, err := os.ReadFile(path + ".1")
	if err != nil || !strings.HasSuffix(string(tail), "latest") {
		t.Fatalf("snapshot did not retain latest bytes: %v", err)
	}
}

func TestRetentionRejectsSymlinkSnapshot(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "access.log")
	if err := os.WriteFile(path, make([]byte, maximumAccessLogBytes+1), 0o640); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(directory, "outside")
	if err := os.WriteFile(outside, []byte("foreign"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path+".1"); err != nil {
		t.Fatal(err)
	}
	err := rotateAccessLog(path, filepath.Join(directory, "lock"), uint32(os.Getuid()), uint32(os.Getgid()))
	if err == nil {
		t.Fatal("symlink snapshot accepted")
	}
	value, _ := os.ReadFile(outside)
	if string(value) != "foreign" {
		t.Fatal("foreign snapshot target changed")
	}
}

type fakeLauncher struct {
	results   map[child.ProfileID]child.Result
	sequences map[child.ProfileID][]child.Result
	calls     []child.ProfileID
}

func (f *fakeLauncher) RunInvocation(_ context.Context, id child.ProfileID, _ child.Invocation, _ []byte) (child.Result, error) {
	f.calls = append(f.calls, id)
	if sequence := f.sequences[id]; len(sequence) != 0 {
		f.sequences[id] = sequence[1:]
		return sequence[0], nil
	}
	return f.results[id], nil
}
func stoppedUnits(active string) []byte {
	unitID := "res_00000000000000000000000000000001-7"
	names := []string{"lanpanel-goaccess-" + unitID + ".service", "lanpanel-goaccess-relay-" + unitID + ".service", "lanpanel-goaccess-" + unitID + ".socket", "lanpanel-goaccess-retention-" + unitID + ".timer", "lanpanel-goaccess-retention-" + unitID + ".service"}
	blocks := make([]string, len(names))
	for index, name := range names {
		state, pid := "inactive", "0"
		if strings.Contains(name, active) && active != "" {
			state, pid = "active", "42"
		}
		unitFileState := "disabled"
		if strings.HasSuffix(name, ".service") && strings.Contains(name, "goaccess-retention-") {
			unitFileState = "static"
		}
		blocks[index] = fmt.Sprintf("Id=%s\nLoadState=loaded\nActiveState=%s\nMainPID=%s\nUnitFileState=%s", name, state, pid, unitFileState)
	}
	return []byte(strings.Join(blocks, "\n\n"))
}
func TestCandidateStagingRecoveryRemovesOnlyExactOwnedPrefix(t *testing.T) {
	directory := t.TempDir()
	staging := filepath.Join(directory, ".unit.service.lanpanel")
	expected := []byte("complete candidate unit")
	if err := os.WriteFile(staging, expected[:8], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupExactStaging(staging, expected, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact staging residue remains: %v", err)
	}
	if err := os.WriteFile(staging, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupExactStaging(staging, expected, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("foreign staging residue removed")
	}
	if value, err := os.ReadFile(staging); err != nil || string(value) != "foreign" {
		t.Fatalf("foreign staging changed: %q %v", value, err)
	}
}

func TestRetainedCleanupRequiresExactUnitAndStateGenerationsBeforeObservation(t *testing.T) {
	item := RetainedGeneration{Generation: 2, StateGeneration: 3, ServiceIdentity: digest([]byte("service")), UnitIdentities: []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}}
	err := (Host{}).CleanupRetained(context.Background(), "ins_00000000000000000000000000000001", "res_00000000000000000000000000000001", []RetainedGeneration{item})
	if err == nil || !strings.Contains(err.Error(), "generation inventory invalid") {
		t.Fatalf("invalid retained state generation error=%v", err)
	}
}

func TestRetainedTreeCleanupNeverFollowsForeignSymlink(t *testing.T) {
	parent := t.TempDir()
	owned := filepath.Join(parent, "owned")
	if err := os.Mkdir(owned, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.WriteFile(outside, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(owned, "link")); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedTree(context.Background(), owned, uint32(os.Getuid()), uint32(os.Getgid()), 0o750); err == nil {
		t.Fatal("foreign symlink accepted")
	}
	value, err := os.ReadFile(outside)
	if err != nil || string(value) != "foreign" {
		t.Fatalf("foreign source changed: %q %v", value, err)
	}
	if err := os.Remove(filepath.Join(owned, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(owned); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, owned); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedTree(context.Background(), owned, uint32(os.Getuid()), uint32(os.Getgid()), 0o750); err == nil {
		t.Fatal("symlink retained root accepted")
	}
}

func TestAccountLockAcquisitionIsBoundedAndContextAware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pwd.lock")
	first, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := unix.Flock(int(first.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := acquireBoundedFlock(context.Background(), int(second.Fd()), 40*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended account lock error=%v", err)
	}
	if err := unix.Flock(int(first.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := acquireBoundedFlock(context.Background(), int(second.Fd()), 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(second.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedAccountAuthorityCannotBeRecreated(t *testing.T) {
	candidate := Candidate{Paths: Paths{Sysusers: filepath.Join(t.TempDir(), "missing.conf")}}
	if err := verifyAccountAuthority(candidate, true, true); err == nil || !strings.Contains(err.Error(), "retained account origin marker missing") {
		t.Fatalf("missing retained account authority accepted: %v", err)
	}
}

func TestCleanupRejectsCancellationAndUnavailableHostBeforeMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (Host{}).cleanupAccounts(ctx, Candidate{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled account cleanup error=%v", err)
	}
	if err := (Host{}).CleanupCandidate(context.Background(), Candidate{}); err == nil || !strings.Contains(err.Error(), "host unavailable") {
		t.Fatalf("unavailable candidate cleanup error=%v", err)
	}
}

func TestRetainedStateStagingFreshlyStopsExactPriorGeneration(t *testing.T) {
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessStop: {ExitCode: 0}, child.ProfileGoAccessShow: {ExitCode: 0, Stdout: stoppedUnits("")}}}
	host := Host{launcher: launcher}
	candidate := Candidate{ResourceID: "res_00000000000000000000000000000001", Generation: 8, RetainedServiceGeneration: 7, RetainedServiceIdentity: digest([]byte("service")), RetainedUnitIdentities: []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}}
	if err := host.ensureRetainedStateStopped(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow, child.ProfileGoAccessRetain, child.ProfileGoAccessStop, child.ProfileGoAccessShow}) {
		t.Fatalf("retained-state stop calls=%v", launcher.calls)
	}
}

func TestStopRequiresEveryUnitAndEndpointClosed(t *testing.T) {
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessStop: {ExitCode: 0}, child.ProfileGoAccessShow: {ExitCode: 0, Stdout: stoppedUnits("")}}}
	host := Host{launcher: launcher}
	if err := host.Stop(context.Background(), "res_00000000000000000000000000000001", 7); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessRetain, child.ProfileGoAccessStop, child.ProfileGoAccessShow}) {
		t.Fatalf("final retention/stop order=%v", launcher.calls)
	}
	launcher.results[child.ProfileGoAccessShow] = child.Result{ExitCode: 0, Stdout: stoppedUnits("relay")}
	if err := host.Stop(context.Background(), "res_00000000000000000000000000000001", 7); err == nil {
		t.Fatal("active relay accepted as stopped")
	}
}

func TestEnsureStoppedContractsDespiteFinalRetentionFailure(t *testing.T) {
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessRetain: {ExitCode: 1}, child.ProfileGoAccessStop: {ExitCode: 0}, child.ProfileGoAccessShow: {ExitCode: 0, Stdout: stoppedUnits("")}}}
	host := Host{launcher: launcher}
	if err := host.EnsureStopped(context.Background(), "res_00000000000000000000000000000001", 7); err == nil || !strings.Contains(err.Error(), "final GoAccess retention failed") {
		t.Fatalf("retention failure was hidden: %v", err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow, child.ProfileGoAccessRetain, child.ProfileGoAccessStop, child.ProfileGoAccessShow}) {
		t.Fatalf("emergency retention/stop calls=%v", launcher.calls)
	}
}

func TestRetireAcceptsExactAlreadyRemovedGeneration(t *testing.T) {
	removed := strings.ReplaceAll(string(stoppedUnits("")), "LoadState=loaded", "LoadState=not-found")
	removed = strings.ReplaceAll(removed, "UnitFileState=disabled", "UnitFileState=")
	removed = strings.ReplaceAll(removed, "UnitFileState=static", "UnitFileState=")
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileGoAccessShow: {ExitCode: 0, Stdout: []byte(removed)}}}
	host := Host{launcher: launcher}
	identities := []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}
	if err := host.Retire(context.Background(), "res_00000000000000000000000000000001", 7, digest([]byte("service")), identities); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow}) {
		t.Fatalf("already-retired generation was restarted: %v", launcher.calls)
	}
}

func TestRetireReloadsCrashRemovedUnitFilesBeforeCompletion(t *testing.T) {
	removed := strings.ReplaceAll(string(stoppedUnits("")), "LoadState=loaded", "LoadState=not-found")
	removed = strings.ReplaceAll(removed, "UnitFileState=disabled", "UnitFileState=")
	removed = strings.ReplaceAll(removed, "UnitFileState=static", "UnitFileState=")
	launcher := &fakeLauncher{results: map[child.ProfileID]child.Result{child.ProfileSystemctl: {ExitCode: 0}}, sequences: map[child.ProfileID][]child.Result{child.ProfileGoAccessShow: {{ExitCode: 0, Stdout: stoppedUnits("")}, {ExitCode: 0, Stdout: []byte(removed)}}}}
	host := Host{launcher: launcher}
	identities := []string{digest([]byte("1")), digest([]byte("2")), digest([]byte("3")), digest([]byte("4")), digest([]byte("5"))}
	if err := host.Retire(context.Background(), "res_00000000000000000000000000000001", 7, digest([]byte("service")), identities); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launcher.calls, []child.ProfileID{child.ProfileGoAccessShow, child.ProfileSystemctl, child.ProfileGoAccessShow}) {
		t.Fatalf("crash removal recovery calls=%v", launcher.calls)
	}
}

func TestPartialStopAcceptsOnlyExcludedNotFoundUnits(t *testing.T) {
	resourceID := "res_00000000000000000000000000000001"
	output := string(stoppedUnits(""))
	relayID := "lanpanel-goaccess-relay-" + resourceID + "-7.service"
	output = strings.Replace(output, "Id="+relayID+"\nLoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled", "Id="+relayID+"\nLoadState=not-found\nActiveState=inactive\nMainPID=0\nUnitFileState=", 1)
	if err := verifyStoppedUnitOutput([]byte(output), resourceID, 7, 29); err != nil {
		t.Fatal(err)
	}
	if err := verifyStoppedUnitOutput([]byte(output), resourceID, 7, 31); err == nil {
		t.Fatal("required not-found relay accepted")
	}
}

func TestRemovedUnitsRequireNotFoundEvidence(t *testing.T) {
	output := strings.ReplaceAll(string(stoppedUnits("")), "LoadState=loaded", "LoadState=not-found")
	output = strings.ReplaceAll(output, "UnitFileState=disabled", "UnitFileState=")
	output = strings.ReplaceAll(output, "UnitFileState=static", "UnitFileState=")
	if err := verifyRemovedUnitOutput([]byte(output)); err != nil {
		t.Fatal(err)
	}
	if err := verifyRemovedUnitOutput(stoppedUnits("")); err == nil {
		t.Fatal("loaded stopped units accepted as removed")
	}
}

func TestRetentionRuntimeAcceptsOnlyBoundedExpectedOneshotPhases(t *testing.T) {
	for _, properties := range []map[string]string{{"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}, {"ActiveState": "activating", "SubState": "start", "MainPID": "42"}} {
		if !validRetentionRuntime(properties) {
			t.Fatalf("expected retention phase rejected: %#v", properties)
		}
	}
	for _, properties := range []map[string]string{{"ActiveState": "active", "SubState": "running", "MainPID": "42"}, {"ActiveState": "activating", "SubState": "start-pre", "MainPID": "0"}, {"ActiveState": "activating", "SubState": "start", "MainPID": "0"}, {"ActiveState": "activating", "SubState": "start-post", "MainPID": "0"}, {"ActiveState": "failed", "SubState": "failed", "MainPID": "0"}} {
		if validRetentionRuntime(properties) {
			t.Fatalf("unexpected retention phase accepted: %#v", properties)
		}
	}
}

func TestEffectiveUnitParserRequiresDistinctClosedInventory(t *testing.T) {
	blocks := []string{}
	for _, name := range []string{"service", "relay", "socket", "timer", "retention"} {
		blocks = append(blocks, fmt.Sprintf("Id=%s\nActiveState=active", name))
	}
	units, err := parseEffectiveUnits(strings.Join(blocks, "\n\n"))
	if err != nil || len(units) != 5 {
		t.Fatalf("units=%v err=%v", units, err)
	}
	if _, err = parseEffectiveUnits(strings.Join(append(blocks, blocks[0]), "\n\n")); err == nil {
		t.Fatal("duplicate effective unit accepted")
	}
}

func TestDisabledGoAccessCreatesNoCandidate(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{}}}
	if _, err := Render("ins_00000000000000000000000000000001", resource, 33, 2); err == nil {
		t.Fatal("disabled GoAccess rendered files")
	}
}
