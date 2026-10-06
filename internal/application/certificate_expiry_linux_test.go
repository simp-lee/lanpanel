//go:build linux

package application

import (
	"bytes"
	"context"
	"errors"
	"lanpanel/internal/control"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type certificateExpiryTestSafety struct {
	state     safety.State
	authority locks.Authority
}

func TestIndependentCertificateExpiryContractionStopsForConcurrentAuthority(t *testing.T) {
	state := safety.EmptyState()
	if independentCertificateContractionRequiresStop(state) {
		t.Fatal("unrelated certificate expiry stop fence was requested")
	}
	state.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: 1, Deadline: time.Unix(1_700_000_000, 0).UTC(), Binding: "binding"}
	if !independentCertificateContractionRequiresStop(state) {
		t.Fatal("Headscale expiry did not request a stop fence")
	}
	state = safety.EmptyState()
	state.Resources = []safety.ResourceSafety{{ResourceID: "res_expired", CertificateExpiry: &safety.DeadlineMarker{Generation: 1, Deadline: time.Unix(1_700_000_000, 0).UTC(), Binding: "binding"}}}
	if !independentCertificateContractionRequiresStop(state) {
		t.Fatal("App expiry did not request a stop fence")
	}
}

func (store certificateExpiryTestSafety) Read() (safety.State, error) { return store.state, nil }
func (store certificateExpiryTestSafety) LockAuthority() locks.Authority {
	return store.authority
}

func TestContractExpiredCertificateSetupFailuresRejectReservedIntent(t *testing.T) {
	for _, point := range []string{"open_mutation_set", "acquire_exposure", "preflight", "begin_planless"} {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
			lockRoot := t.TempDir()
			if err := os.Chmod(lockRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			manager, err := locks.Open(locks.Config{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = manager.Close() }()
			admission, err := manager.Acquire(ctx, locks.MutationAdmission)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = admission.Release() }()
			stateRoot := t.TempDir()
			if err := os.Chmod(stateRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			staging := filepath.Join(stateRoot, "staging")
			if err := os.Mkdir(staging, 0o700); err != nil {
				t.Fatal(err)
			}
			normal, err := persist.Open(persist.Config{RootPath: stateRoot, StagingPath: staging, StatePath: filepath.Join(stateRoot, "normal.json"), Owner: owner, LockAuthority: manager.Authority()})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = normal.Close() }()
			if _, err := normal.Initialize(ctx, admission); err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_700_000_000, 0).UTC()
			deadline := now.Add(-time.Minute)
			resourceID := "res_00000000000000000000000000000001"
			binding := applicationTestDigest("certificate-binding")
			state := safety.EmptyState()
			state.Resources = []safety.ResourceSafety{{ResourceID: resourceID, GenerationSequence: 3, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: applicationTestDigest("ownership"), ActiveCertificate: &safety.ActiveCertificateAuthority{Generation: 1, Fingerprint: applicationTestDigest("certificate"), Binding: binding, NotAfter: deadline, LastTrustedWall: deadline.Add(-time.Hour)}}}
			registry, err := operationRegistry()
			if err != nil {
				t.Fatal(err)
			}
			admitter, err := operations.NewAdmitter(normal, certificateExpiryTestSafety{state: state, authority: manager.Authority()}, operations.Options{Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 64)), Bindings: planBinding{}, Confirmation: confirmation{}, Registry: registry})
			if err != nil {
				t.Fatal(err)
			}
			record, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.CertificateExpiry, Target: "resource/" + resourceID, ActorIdentity: "timer/certificate-expiry", Source: operations.AdmissionTimer, SafetyBinding: operations.SafetyBinding{ResourceID: resourceID, ExpiryGeneration: 4, Deadline: deadline, CandidateBundle: binding}, ExpectedRevision: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err := admission.Release(); err != nil {
				t.Fatal(err)
			}
			service := &FixedService{normal: normal, manager: manager}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			cleanup := &certificateContractionCleanup{reservedJobID: record.ID, rejectReserved: func(jobID string) error {
				return rejectReservedCertificateExpiry(canceled, service, admitter, jobID, "certificate_setup_failed")
			}}
			if point != "open_mutation_set" {
				mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: lockRoot, Owner: owner.UID, Group: owner.GID, Mode: 0o700, Authority: manager.Authority()})
				if err != nil {
					t.Fatal(err)
				}
				cleanup.mutationSet = mutationSet
				if point == "preflight" || point == "begin_planless" {
					mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+resourceID, manager)
					if err != nil {
						t.Fatal(err)
					}
					cleanup.mutation = mutation
					cleanup.exposure = exposure
				}
			}
			if err := cleanup.Close(); err != nil {
				t.Fatalf("%s cleanup: %v", point, err)
			}
			if err := cleanup.Close(); err != nil {
				t.Fatalf("%s cleanup was not idempotent: %v", point, err)
			}
			intent, err := admitter.OperationIntent(record.ID)
			if err != nil || intent.Phase != operations.PhaseRejected {
				t.Fatalf("%s left intent phase=%s err=%v", point, intent.Phase, err)
			}
			jobStore, err := jobs.NewStore(normal, jobs.Options{})
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := jobStore.Read(record.ID)
			if err != nil || terminal.Status != jobs.StatusTerminal || terminal.Result != jobs.ResultFailed {
				t.Fatalf("%s job=%#v err=%v", point, terminal, err)
			}
			exposure, err := manager.Acquire(ctx, locks.Exposure)
			if err != nil {
				t.Fatalf("%s left lock-order state: %v", point, err)
			}
			if err := exposure.Release(); err != nil {
				t.Fatal(err)
			}
			admission, err = manager.Acquire(ctx, locks.MutationAdmission)
			if err != nil {
				t.Fatalf("%s blocked later mutation admission: %v", point, err)
			}
			if err := admission.Release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCertificateExpiryLocalIntentResumesPersistedGeneration(t *testing.T) {
	const resourceID = "res_00000000000000000000000000000001"
	closureDigest := applicationTestDigest("closure")
	intent := operations.Reservation{JobID: "job_existing", Operation: operations.CertificateExpiry, Phase: operations.PhaseLocalIntent, ContractionDigest: closureDigest, SafetyBinding: operations.SafetyBinding{ExpiryGeneration: 8}}
	installation := domain.Installation{Resources: []domain.AppResource{{ID: resourceID, PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 9, ContractionIntent: &domain.ContractionIntent{JobID: intent.JobID, Operation: string(operations.CertificateExpiry), Generation: 9, ClosureAuthorityDigest: closureDigest}}}}}
	for _, marker := range []string{"closing", "closed"} {
		t.Run(marker, func(t *testing.T) {
			resource := safety.ResourceSafety{ResourceID: resourceID, GenerationSequence: 9}
			if marker == "closing" {
				resource.Closing = &safety.GenerationMarker{Kind: safety.MarkerClosing, Generation: 9, Reason: "contraction"}
			} else {
				resource.StickyUnpublished = &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 9, Reason: "closed"}
			}
			generations, err := certificateExpiryContractionGenerations(installation, safety.State{Resources: []safety.ResourceSafety{resource}}, resourceID, intent)
			if err != nil || generations[resourceID] != 9 {
				t.Fatalf("generations=%v err=%v", generations, err)
			}
		})
	}
}

func TestCertificateExpiryDigestlessLocalIntentUsesIndependentClosedGeneration(t *testing.T) {
	const resourceID = "res_00000000000000000000000000000001"
	intent := operations.Reservation{JobID: "job_existing", Operation: operations.CertificateExpiry, Phase: operations.PhaseLocalIntent, SafetyBinding: operations.SafetyBinding{ExpiryGeneration: 8}}
	installation := domain.Installation{Resources: []domain.AppResource{{ID: resourceID, PublicationRecord: domain.PublicationRecord{State: domain.PublicationPublished}}}}
	resource := safety.ResourceSafety{ResourceID: resourceID, GenerationSequence: 9, StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 9, Reason: "closed"}}
	state := safety.State{Resources: []safety.ResourceSafety{resource}}
	generations, err := certificateExpiryContractionGenerations(installation, state, resourceID, intent)
	if err != nil || generations[resourceID] != 9 || !certificateExpirySafetyClosed(state, resourceID, 9) {
		t.Fatalf("generations=%v closed=%t err=%v", generations, certificateExpirySafetyClosed(state, resourceID, 9), err)
	}
}

func TestIndependentHeadscaleExpiryRejectsStaleExpiredJournal(t *testing.T) {
	installation, journal := headscaleExpiryTestAuthority(t)
	journal.Phase = control.PhaseExpired
	state := safety.EmptyState()
	state.Headscale.GenerationSequence = 3
	state.Headscale.ControlEntryDigest = applicationTestDigest("different-control-entry")
	state.Headscale.ActiveCertificate = &safety.ActiveCertificateAuthority{Generation: journal.Certificate.Generation, Fingerprint: journal.Certificate.Fingerprint, Binding: journal.Certificate.BindingIdentity, NotAfter: journal.Certificate.NotAfter, LastTrustedWall: journal.Certificate.LastTrustedWall.Add(time.Minute)}
	state.Headscale.CertificateExpiry = &safety.DeadlineMarker{Generation: 3, Deadline: journal.Certificate.NotAfter, Binding: journal.Certificate.BindingIdentity}
	if !headscaleExpiryJournalMatchesNormal(installation, journal) {
		t.Fatal("exact Headscale journal did not match normal authority")
	}
	if independentHeadscaleExpiryJournalMatches(state, journal) {
		t.Fatal("journal with a stale control graph matched independent safety authority")
	}
	journal.Certificate = nil
	if independentHeadscaleExpiryJournalMatches(state, journal) {
		t.Fatal("missing stale Headscale journal certificate matched safety authority")
	}
}

func TestIndependentCertificateExpiryEarlyReturnsReleaseExposure(t *testing.T) {
	for _, point := range []string{"safety_commit", "control_journal", "fallback_stop", "fence_write"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			owner, group := uint32(os.Geteuid()), uint32(os.Getegid())
			manager, err := locks.Open(locks.Config{RootPath: root, Owner: owner, Group: group, Mode: 0o700})
			if err != nil {
				t.Fatal(err)
			}
			exposure, err := manager.Acquire(context.Background(), locks.Exposure)
			if err != nil {
				t.Fatal(err)
			}
			closeFault := errors.New("service close fault")
			cleanup := &certificateExpiryCleanup{exposure: exposure, closeService: func() error {
				return errors.Join(manager.Close(), closeFault)
			}}
			pointFault := errors.New(point + " fault")
			returned := errors.Join(pointFault, cleanup.Close())
			if !errors.Is(returned, pointFault) || !errors.Is(returned, closeFault) {
				t.Fatalf("cleanup errors were not returned: %v", returned)
			}
			if err := cleanup.Close(); err != nil {
				t.Fatalf("cleanup was not idempotent: %v", err)
			}

			reopened, err := locks.Open(locks.Config{RootPath: root, Owner: owner, Group: group, Mode: 0o700})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			nextExposure, err := reopened.Acquire(context.Background(), locks.Exposure)
			if err != nil {
				t.Fatalf("exposure remained held after %s failure: %v", point, err)
			}
			if err := nextExposure.Release(); err != nil {
				t.Fatal(err)
			}
			admission, err := reopened.Acquire(context.Background(), locks.MutationAdmission)
			if err != nil {
				t.Fatalf("mutation admission saw leaked exposure after %s failure: %v", point, err)
			}
			if err := admission.Release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
