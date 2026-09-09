//go:build linux

package activation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/challenge"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const challengeTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func challengeTransactionFixture(t *testing.T) (nginx.Paths, filetxn.Owner, challenge.Prepared, nginx.Entry) {
	t.Helper()
	root := t.TempDir()
	paths := nginx.Paths{ConfigRoot: filepath.Join(root, "config"), StateRoot: filepath.Join(root, "state"), AuditPath: filepath.Join(root, "audit"), CertificatePath: filepath.Join(root, "default.crt"), PrivateKeyPath: filepath.Join(root, "default.key"), PIDPath: filepath.Join(root, "nginx.pid")}
	for _, directory := range []string{paths.ConfigRoot, paths.StateRoot, paths.StagingPath(), filepath.Join(paths.ConfigRoot, nginx.AppsDirectory), filepath.Join(paths.ConfigRoot, nginx.ChallengesDirectory), filepath.Join(paths.ConfigRoot, nginx.ControlDirectory), filepath.Join(paths.ConfigRoot, nginx.TemporaryDirectory)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := nginx.GenerateDefaultCertificate("ins_challenge", bytes.NewReader(bytes.Repeat([]byte{9}, 256)), time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	writeChallengeTestFile(t, paths.CertificatePath, certificate.CertificatePEM, 0o644)
	writeChallengeTestFile(t, paths.PrivateKeyPath, certificate.PrivateKeyPEM, 0o600)
	writeChallengeTestFile(t, paths.AuditPath, []byte(nginx.AuditMarker), 0o600)
	baseline, err := nginx.RenderBaseline(paths, "ins_challenge", "gen_challenge", certificate.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range baseline.Files {
		writeChallengeTestFile(t, path, data, 0o600)
	}

	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: challengeTestDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}}
	base, err := challenge.Prepare(challenge.Request{ResourceID: "res_challenge", PlanID: "plan_challenge", Generation: 2, ConfigDigest: challengeTestDigest, Domains: []string{"app.example.test"}, Binding: binding, CertificateIdentity: "cert_challenge", Webroot: "/var/lib/lanpanel/certificates/webroot/cert_challenge", BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := challenge.PresentHTTPForResource("res_challenge", base, "app.example.test", "abcdefghijklmnopqrstuv", challengeTestDigest)
	if err != nil {
		t.Fatal(err)
	}
	prior := *prepared.Entry
	prior.Generation = 1
	prior.Challenge = &nginx.ChallengeSite{Generation: 1, Host: "app.example.test", Token: "priorabcdefghijklmnopq", TokenPath: "/.well-known/acme-challenge/priorabcdefghijklmnopq", KeyAuthorizationDigest: challengeTestDigest, Webroot: "/var/lib/lanpanel/certificates/webroot/cert_challenge"}
	prior.Digest = "sha256:" + strings.Repeat("0", 64)
	prior.Digest, err = nginx.DigestEntry(prior)
	if err != nil {
		t.Fatal(err)
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if _, _, err := nginx.InstallEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	return paths, owner, prepared, prior
}

func writeChallengeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertChallengeSnapshotRestored(t *testing.T, paths nginx.Paths, owner filetxn.Owner, candidate nginx.Entry, snapshot nginx.ActivationSnapshot) {
	t.Helper()
	manifest, err := nginx.Audit(paths, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest, snapshot.Manifest) {
		t.Fatalf("restored manifest differs from snapshot: got=%#v want=%#v", manifest, snapshot.Manifest)
	}
	manifestBytes, err := os.ReadFile(paths.ManifestPath())
	if err != nil || !bytes.Equal(manifestBytes, snapshot.ManifestBytes) {
		t.Fatalf("manifest bytes were not restored exactly: %v", err)
	}
	entryPath := filepath.Join(paths.ConfigRoot, filepath.FromSlash(candidate.Relative))
	if !snapshot.EntryPresent {
		if _, err := os.Lstat(entryPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("entry absent from snapshot remains after restoration: %v", err)
		}
		return
	}
	entryBytes, err := os.ReadFile(entryPath)
	if err != nil || !bytes.Equal(entryBytes, snapshot.EntryBytes) {
		t.Fatalf("entry bytes were not restored exactly: %v", err)
	}
}

func challengeReloadAuthorityFromSnapshot(snapshot *ReloadAuthoritySnapshot, now func() time.Time) ChallengeReloadAuthority {
	authority, err := NewReloadAuthority(func() (ReloadAuthoritySnapshot, error) {
		current := *snapshot
		current.ObservedAt = now()
		return current, nil
	})
	if err != nil {
		panic(err)
	}
	return authority
}

func TestReloadAuthorityChecksRuntimeIdentityAtGuard(t *testing.T) {
	runtimeErr := errors.New("package profile drift")
	authority, err := NewReloadAuthorityWithRuntimeCheck(func() (ReloadAuthoritySnapshot, error) {
		return ReloadAuthoritySnapshot{ObservedAt: time.Now().UTC()}, nil
	}, func() error {
		return runtimeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Guard(nginx.Manifest{}); !errors.Is(err, runtimeErr) {
		t.Fatalf("runtime identity error was not enforced: %v", err)
	}
}

func challengeReloadTestSnapshot(prepared challenge.Prepared) ReloadAuthoritySnapshot {
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: prepared.Entry.ResourceID, GenerationSequence: prepared.Safety.Generation, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: challengeTestDigest, ChallengePending: &prepared.Safety}}
	return ReloadAuthoritySnapshot{Safety: state, Installation: domain.Installation{InstallationID: "ins_challenge", Resources: []domain.AppResource{{ID: prepared.Entry.ResourceID}}}, Ownership: map[string]string{prepared.Entry.ResourceID: challengeTestDigest}}
}

func challengeReloadTestAuthority(prepared challenge.Prepared) ChallengeReloadAuthority {
	snapshot := challengeReloadTestSnapshot(prepared)
	return challengeReloadAuthorityFromSnapshot(&snapshot, func() time.Time { return time.Now().UTC() })
}

func challengePreparedForEntry(prepared challenge.Prepared, entry nginx.Entry) challenge.Prepared {
	prepared.Entry = &entry
	prepared.Safety.Generation = entry.Generation
	prepared.Safety.Host = entry.Challenge.Host
	prepared.Safety.Hosts = []string{entry.Challenge.Host}
	prepared.Safety.Token = entry.Challenge.Token
	prepared.Safety.TokenPath = entry.Challenge.TokenPath
	prepared.Safety.KeyAuthorizationDigest = entry.Challenge.KeyAuthorizationDigest
	prepared.Safety.Webroot = entry.Challenge.Webroot
	return prepared
}

func TestChallengeExpansionGuardRejectsBeforeDiskMutation(t *testing.T) {
	paths, owner, prepared, _ := challengeTransactionFixture(t)
	before, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	state := safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: prepared.Entry.ResourceID, GenerationSequence: prepared.Safety.Generation, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: challengeTestDigest, ChallengePending: &prepared.Safety}}
	authoritySnapshot := &ReloadAuthoritySnapshot{Safety: state, Installation: domain.Installation{InstallationID: "ins_challenge"}, Ownership: map[string]string{prepared.Entry.ResourceID: "sha256:" + strings.Repeat("b", 64)}}
	authority := challengeReloadAuthorityFromSnapshot(authoritySnapshot, func() time.Time { return time.Now().UTC() })
	if _, _, err := PrepareChallengeExpansion(paths, owner, *prepared.Entry, authority); err == nil {
		t.Fatal("ownership-mismatched challenge expansion was allowed")
	}
	assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, before)
}

func TestAbsentChallengeDiskGraphStillRequiresRuntimeContraction(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	workersRemain := errors.New("challenge workers survived rollback reload")
	attempts := 0
	runtime := ChallengeGraphRuntime{
		Activate: func(_ context.Context, _ nginx.Manifest, authorize func() error) error {
			attempts++
			if err := authorize(); err != nil {
				return err
			}
			return workersRemain
		},
		Observe: func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) {
			return nil, workersRemain
		},
		Restore: func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error {
			return workersRemain
		},
	}
	remove := func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(ctx, paths, owner, *prepared.Entry)
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, snapshot.Manifest, challengeReloadTestAuthority(prepared), remove, runtime)
	var failure *Failure
	if !errors.As(err, &failure) || failure.PriorRestored || attempts != 1 {
		t.Fatalf("disk absence was accepted without runtime closure: attempts=%d err=%v", attempts, err)
	}
	assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, snapshot)
	workersRemain = nil
	if _, err := CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, snapshot.Manifest, challengeReloadTestAuthority(prepared), remove, runtime); err != nil || attempts != 2 {
		t.Fatalf("verified runtime contraction did not converge: attempts=%d err=%v", attempts, err)
	}
}

func TestChallengeInstallFaultsRestoreExactPriorGraph(t *testing.T) {
	testFault := errors.New("nginx test fault")
	reloadFault := errors.New("nginx reload fault")
	waitFault := errors.New("worker drain fault")
	for _, test := range []struct {
		name  string
		stage string
		fault error
	}{
		{name: "nginx test", stage: "test", fault: testFault},
		{name: "reload", stage: "reload", fault: reloadFault},
		{name: "worker drain", stage: "wait", fault: waitFault},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, owner, prepared, prior := challengeTransactionFixture(t)
			if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, prior); err != nil {
				t.Fatal(err)
			}
			snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
			if err != nil {
				t.Fatal(err)
			}
			prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
			if err != nil {
				t.Fatal(err)
			}
			var calls []string
			runtime := ChallengeGraphRuntime{
				Activate: func(_ context.Context, _ nginx.Manifest, authorize func() error) error {
					calls = append(calls, "test")
					if test.stage == "test" {
						return test.fault
					}
					if err := authorize(); err != nil {
						return err
					}
					calls = append(calls, "reload")
					if test.stage == "reload" {
						return test.fault
					}
					calls = append(calls, "wait")
					return test.fault
				},
				Observe: func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) {
					calls = append(calls, "observe")
					return []closure.ProcessIdentity{}, nil
				},
				Restore: func(_ context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity, authorize func() error) error {
					if err := authorize(); err != nil {
						return err
					}
					calls = append(calls, "restore-runtime")
					if !reflect.DeepEqual(manifest, snapshot.Manifest) {
						t.Fatal("runtime restoration did not receive prior manifest")
					}
					return nil
				},
			}
			_, err = CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, challengeReloadTestAuthority(prepared), func(ctx context.Context) (nginx.Manifest, []string, error) {
				return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
			}, runtime)
			var failure *Failure
			if !errors.As(err, &failure) || !failure.PriorRestored || !errors.Is(err, test.fault) {
				t.Fatalf("transaction error=%v", err)
			}
			if calls[len(calls)-1] != "restore-runtime" {
				t.Fatalf("runtime was not verified after graph restoration: %v", calls)
			}
			assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, snapshot)
		})
	}
}

func TestChallengeInstallReloadFaultRemovesNewEntry(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	if _, _, err := nginx.RemoveEntry(context.Background(), paths, owner, prior); err != nil {
		t.Fatal(err)
	}
	snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil || snapshot.EntryPresent {
		t.Fatalf("new challenge snapshot=%#v err=%v", snapshot, err)
	}
	prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	reloadFault := errors.New("new challenge reload fault")
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest, func() error) error { return reloadFault },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore: func(_ context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity, authorize func() error) error {
			if err := authorize(); err != nil {
				return err
			}
			if !reflect.DeepEqual(manifest, snapshot.Manifest) {
				t.Fatal("new challenge rollback runtime did not receive prior manifest")
			}
			return nil
		},
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, challengeReloadTestAuthority(prepared), func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
	}, runtime)
	var failure *Failure
	if !errors.As(err, &failure) || !failure.PriorRestored || !errors.Is(err, reloadFault) {
		t.Fatalf("new challenge transaction error=%v", err)
	}
	manifest, auditErr := nginx.Audit(paths, owner)
	if auditErr != nil || !reflect.DeepEqual(manifest, snapshot.Manifest) {
		t.Fatalf("new challenge prior manifest was not restored: %#v %v", manifest, auditErr)
	}
	if _, statErr := os.Lstat(filepath.Join(paths.ConfigRoot, filepath.FromSlash(prepared.Entry.Relative))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed new challenge entry remains: %v", statErr)
	}
}

func TestChallengeRemovalTestAndReloadFaultsRecreateExactPriorEntry(t *testing.T) {
	for _, stage := range []string{"nginx test", "nginx reload"} {
		t.Run(stage, func(t *testing.T) {
			paths, owner, prepared, prior := challengeTransactionFixture(t)
			expected := challengePreparedForEntry(prepared, prior)
			snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
			if err != nil {
				t.Fatal(err)
			}
			prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
			if err != nil {
				t.Fatal(err)
			}
			activationFault := fmt.Errorf("removal %s fault", stage)
			runtime := ChallengeGraphRuntime{
				Activate: func(context.Context, nginx.Manifest, func() error) error { return activationFault },
				Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
				Restore: func(_ context.Context, manifest nginx.Manifest, _ []closure.ProcessIdentity, authorize func() error) error {
					if err := authorize(); err != nil {
						return err
					}
					if !reflect.DeepEqual(manifest, snapshot.Manifest) {
						t.Fatal("removal rollback runtime did not receive prior manifest")
					}
					return nil
				},
			}
			_, err = CommitChallengeGraph(context.Background(), paths, owner, *expected.Entry, snapshot, prospective, challengeReloadTestAuthority(expected), func(ctx context.Context) (nginx.Manifest, []string, error) {
				return nginx.RemoveEntry(ctx, paths, owner, *expected.Entry)
			}, runtime)
			var failure *Failure
			if !errors.As(err, &failure) || !failure.PriorRestored || !errors.Is(err, activationFault) {
				t.Fatalf("removal transaction error=%v", err)
			}
			assertChallengeSnapshotRestored(t, paths, owner, *prepared.Entry, snapshot)
		})
	}
}

func TestStoppedChallengeRemovalCommitsAndVerifiesStoppedRuntime(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	observations := 0
	runtime := StoppedChallengeGraphRuntime(func(_ context.Context, manifest nginx.Manifest) (closure.RuntimeSnapshot, error) {
		observations++
		return closure.RuntimeSnapshot{ObservedAt: time.Now().UTC(), Workers: []closure.ProcessIdentity{}, Listeners: []closure.ListenerIdentity{}, Complete: true, Generation: manifest.GenerationID}, nil
	})
	expected := challengePreparedForEntry(prepared, prior)
	result, err := CommitChallengeGraph(context.Background(), paths, owner, prior, snapshot, prospective, challengeReloadTestAuthority(expected), func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(ctx, paths, owner, prior)
	}, runtime)
	if err != nil || observations != 1 || !reflect.DeepEqual(result.Manifest, prospective) {
		t.Fatalf("stopped removal result=%#v observations=%d err=%v", result, observations, err)
	}
	manifest, err := nginx.Audit(paths, owner)
	if err != nil || !reflect.DeepEqual(manifest, prospective) {
		t.Fatalf("stopped removal graph=%#v err=%v", manifest, err)
	}
}

func TestChallengeRemovalGuardRejectsStopFenceBeforeMutationOrReload(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	expected := challengePreparedForEntry(prepared, prior)
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	state := safety.EmptyState()
	state.GlobalClose = safety.GlobalClose{Phase: safety.GlobalCloseClosing, Generation: 1}
	state.StopFenceSequence = 1
	state.StopFence = &safety.StopFence{
		Kind: safety.StopFenceContraction, OriginOperation: "operation", Scope: safety.FenceScope{Kind: "installation"}, FenceGeneration: 1,
		CreatedAt: time.Unix(100, 0).UTC(), SafetyGenerations: []safety.MarkerGeneration{{Kind: "global_close", Generation: 1}},
		OwnedGraphDigest: challengeTestDigest, InventoryDigest: challengeTestDigest, Observation: safety.StopObservation{ObservedAt: time.Unix(101, 0).UTC()}, AccessMayRemain: true,
		Contraction: &safety.ContractionFence{Authorities: []safety.MarkerGeneration{{Kind: "global_close", Generation: 1}}, OwnershipDigest: challengeTestDigest, OperationRef: "intent/job_challenge"},
	}
	if err := safety.Validate(state); err != nil {
		t.Fatal(err)
	}
	changed, reloaded := false, false
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest, func() error) error { reloaded = true; return nil },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore:  func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error { return nil },
	}
	authoritySnapshot := &ReloadAuthoritySnapshot{Safety: state, Installation: domain.Installation{InstallationID: "ins_challenge"}, Ownership: map[string]string{}}
	authority := challengeReloadAuthorityFromSnapshot(authoritySnapshot, func() time.Time { return time.Now().UTC() })
	_, err = CommitChallengeGraph(context.Background(), paths, owner, prior, snapshot, prospective, authority, func(ctx context.Context) (nginx.Manifest, []string, error) {
		changed = true
		return nginx.RemoveEntry(ctx, paths, owner, *expected.Entry)
	}, runtime)
	if err == nil || changed || reloaded {
		t.Fatalf("stop-fenced removal changed=%t reloaded=%t err=%v", changed, reloaded, err)
	}
	assertChallengeSnapshotRestored(t, paths, owner, prior, snapshot)
}

func TestChallengeRemovalGuardRejectsChangedOwnershipBeforeMutationOrReload(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	expected := challengePreparedForEntry(prepared, prior)
	binding := acme.Binding{DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: challengeTestDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: acme.ChallengeHTTP01, CredentialFiles: []acme.CredentialFile{}}
	retainedBase, err := challenge.Prepare(challenge.Request{ResourceID: "res_retained", PlanID: "plan_retained", Generation: 1, ConfigDigest: challengeTestDigest, Domains: []string{"retained.example.test"}, Binding: binding, CertificateIdentity: "cert_retained", Webroot: "/var/lib/lanpanel/certificates/webroot/cert_retained", BaseMarkers: []safety.MarkerSnapshot{{Kind: safety.MarkerStickyUnpublished, State: safety.SnapshotAbsent}, {Kind: safety.MarkerContraction, State: safety.SnapshotAbsent}, {Kind: safety.MarkerCertificateExpiry, State: safety.SnapshotAbsent}}})
	if err != nil {
		t.Fatal(err)
	}
	retained, err := challenge.PresentHTTPForResource("res_retained", retainedBase, "retained.example.test", "retainedabcdefghijklmn", challengeTestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := nginx.InstallEntry(context.Background(), paths, owner, *retained.Entry); err != nil {
		t.Fatal(err)
	}
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	authoritySnapshot := challengeReloadTestSnapshot(expected)
	authoritySnapshot.Safety.Resources = append(authoritySnapshot.Safety.Resources, safety.ResourceSafety{ResourceID: retained.Entry.ResourceID, GenerationSequence: retained.Safety.Generation, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: challengeTestDigest, ChallengePending: &retained.Safety})
	authoritySnapshot.Ownership[retained.Entry.ResourceID] = "sha256:" + strings.Repeat("b", 64)
	authority := challengeReloadAuthorityFromSnapshot(&authoritySnapshot, func() time.Time { return time.Now().UTC() })
	changed, reloaded := false, false
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest, func() error) error { reloaded = true; return nil },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore:  func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error { return nil },
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, prior, snapshot, prospective, authority, func(ctx context.Context) (nginx.Manifest, []string, error) {
		changed = true
		return nginx.RemoveEntry(ctx, paths, owner, prior)
	}, runtime)
	if err == nil || changed || reloaded {
		t.Fatalf("ownership-mismatched removal changed=%t reloaded=%t err=%v", changed, reloaded, err)
	}
	assertChallengeSnapshotRestored(t, paths, owner, prior, snapshot)
}

func TestChallengeRemovalGuardRejectsExpiredRetainedAppBeforeMutationOrReload(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	expected := challengePreparedForEntry(prepared, prior)
	now := time.Now().UTC().Truncate(time.Second)
	certificate := domain.CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/cert-retained", BindingIdentity: "binding-retained", Generation: 1, Fingerprint: challengeTestDigest, SANIdentity: challengeTestDigest, ChainIdentity: challengeTestDigest, IssuerIdentity: challengeTestDigest, NotAfter: now.Add(-time.Minute).Format(time.RFC3339), LastTrustedWall: now.Add(-time.Hour).Format(time.RFC3339)}
	entry := nginx.Entry{Kind: nginx.EntryApp, ResourceID: "res_retained", Relative: nginx.AppsDirectory + "/res_retained.conf", Digest: challengeTestDigest, Domains: []string{"retained.example.test"}, Listeners: []string{"tcp:0.0.0.0:443", "tcp:0.0.0.0:80", "tcp:[::]:443", "tcp:[::]:80"}, Generation: 1, Domain: &nginx.DomainSite{Hosts: []string{"retained.example.test"}, CertificatePointer: certificate.PointerIdentity, RejectionAuditPath: "/var/log/lanpanel/nginx-rejections.log", AuthMode: "public", UpstreamNetwork: "unix", UpstreamAddress: "/run/lanpanel/res_retained.sock"}}
	manifest, _, err := nginx.InstallEntry(context.Background(), paths, owner, entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range manifest.Entries {
		if current.Kind == nginx.EntryApp && current.ResourceID == entry.ResourceID {
			entry = current
		}
	}
	bundle := domain.PublicationBundle{ID: "bundle-retained", Generation: entry.Generation, ConfigDigest: challengeTestDigest, Kind: domain.PublicationDomainHTTPS, EndpointIdentity: challengeTestDigest, SiteIdentity: entry.Digest, ManagedPaths: []string{}, CredentialIDs: []string{}, Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 80}, {Network: "tcp", Port: 443}}, DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: append([]string(nil), entry.Domains...), Certificate: certificate, Auth: domain.AuthBundleIdentity{Mode: domain.AppAccessPublic}, Static: domain.StaticBundleIdentity{Routes: []domain.StaticRouteBundleIdentity{}, RouteIdentities: []string{}}, GoAccess: domain.GoAccessBundleIdentity{Enabled: false}}}
	app := domain.AppResource{ID: entry.ResourceID, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: entry.Domains[0], AccessMode: domain.AppAccessPublic}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished, LastAppliedBundle: &bundle}}
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	authoritySnapshot := challengeReloadTestSnapshot(expected)
	authoritySnapshot.Installation.Resources = []domain.AppResource{app}
	authoritySnapshot.Safety.Resources = append(authoritySnapshot.Safety.Resources, safety.ResourceSafety{ResourceID: entry.ResourceID, GenerationSequence: entry.Generation, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: challengeTestDigest, ActiveCertificate: &safety.ActiveCertificateAuthority{Generation: certificate.Generation, Fingerprint: certificate.Fingerprint, Binding: certificate.BindingIdentity, LastTrustedWall: now.Add(-time.Hour), NotAfter: now.Add(-time.Minute)}})
	authoritySnapshot.Ownership[entry.ResourceID] = challengeTestDigest
	authority := challengeReloadAuthorityFromSnapshot(&authoritySnapshot, func() time.Time { return now })
	changed, reloaded := false, false
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest, func() error) error { reloaded = true; return nil },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore:  func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error { return nil },
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, prior, snapshot, prospective, authority, func(ctx context.Context) (nginx.Manifest, []string, error) {
		changed = true
		return nginx.RemoveEntry(ctx, paths, owner, prior)
	}, runtime)
	if err == nil || changed || reloaded {
		t.Fatalf("expired-retained-App removal changed=%t reloaded=%t err=%v", changed, reloaded, err)
	}
	assertChallengeSnapshotRestored(t, paths, owner, prior, snapshot)
}

func TestChallengeRemovalAllowedAuthorityCommitsAndReloads(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	expected := challengePreparedForEntry(prepared, prior)
	snapshot, err := nginx.SnapshotActivation(paths, owner, prior)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveRemoval(snapshot.Manifest, prior)
	if err != nil {
		t.Fatal(err)
	}
	reloads := 0
	runtime := ChallengeGraphRuntime{
		Activate: func(_ context.Context, manifest nginx.Manifest, authorize func() error) error {
			if err := authorize(); err != nil {
				return err
			}
			reloads++
			if !reflect.DeepEqual(manifest, prospective) {
				t.Fatal("removal reload did not receive guarded prospective manifest")
			}
			return nil
		},
		Observe: func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) {
			t.Fatal("successful removal observed rollback")
			return nil, nil
		},
		Restore: func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error {
			t.Fatal("successful removal rolled back")
			return nil
		},
	}
	result, err := CommitChallengeGraph(context.Background(), paths, owner, prior, snapshot, prospective, challengeReloadTestAuthority(expected), func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.RemoveEntry(ctx, paths, owner, prior)
	}, runtime)
	if err != nil || reloads != 1 || !reflect.DeepEqual(result.Manifest, prospective) {
		t.Fatalf("allowed removal result=%#v reloads=%d err=%v", result, reloads, err)
	}
}

func TestChallengeRollbackReloadRequiresAuthorityForRestoredGraph(t *testing.T) {
	paths, owner, prepared, prior := challengeTransactionFixture(t)
	snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	activateErr := errors.New("reload failed")
	restoredRuntime := false
	runtime := ChallengeGraphRuntime{
		Activate: func(context.Context, nginx.Manifest, func() error) error { return activateErr },
		Observe:  func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) { return nil, nil },
		Restore: func(_ context.Context, _ nginx.Manifest, _ []closure.ProcessIdentity, authorize func() error) error {
			if err := authorize(); err != nil {
				return err
			}
			restoredRuntime = true
			return nil
		},
	}
	_, err = CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, challengeReloadTestAuthority(prepared), func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
	}, runtime)
	var failure *Failure
	if !errors.As(err, &failure) || failure.PriorRestored || !errors.Is(err, activateErr) || restoredRuntime {
		t.Fatalf("unauthorized rollback failure=%#v runtimeRestored=%t err=%v", failure, restoredRuntime, err)
	}
	assertChallengeSnapshotRestored(t, paths, owner, prior, snapshot)
}

func TestChallengeGraphTransactionSuccessKeepsProspectiveGraph(t *testing.T) {
	paths, owner, prepared, _ := challengeTransactionFixture(t)
	snapshot, err := nginx.SnapshotActivation(paths, owner, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	prospective, err := nginx.ProspectiveManifest(snapshot.Manifest, *prepared.Entry)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	runtime := ChallengeGraphRuntime{
		Activate: func(_ context.Context, _ nginx.Manifest, authorize func() error) error {
			calls = append(calls, "test")
			if err := authorize(); err != nil {
				return err
			}
			calls = append(calls, "reload", "wait")
			return nil
		},
		Observe: func(context.Context, nginx.Manifest) ([]closure.ProcessIdentity, error) {
			t.Fatal("successful transaction attempted rollback observation")
			return nil, nil
		},
		Restore: func(context.Context, nginx.Manifest, []closure.ProcessIdentity, func() error) error {
			t.Fatal("successful transaction attempted rollback")
			return nil
		},
	}
	result, err := CommitChallengeGraph(context.Background(), paths, owner, *prepared.Entry, snapshot, prospective, challengeReloadTestAuthority(prepared), func(ctx context.Context) (nginx.Manifest, []string, error) {
		return nginx.InstallEntry(ctx, paths, owner, *prepared.Entry)
	}, runtime)
	if err != nil || !reflect.DeepEqual(result.Manifest, prospective) || !reflect.DeepEqual(calls, []string{"test", "reload", "wait"}) {
		t.Fatalf("successful transaction result=%#v calls=%v err=%v", result, calls, err)
	}
	manifest, err := nginx.Audit(paths, owner)
	if err != nil || !reflect.DeepEqual(manifest, prospective) {
		t.Fatalf("prospective graph was not retained: %#v %v", manifest, err)
	}
}
