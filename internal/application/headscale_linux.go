//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/acmeaccount"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
	"lanpanel/internal/reservations"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type HeadscaleExecution struct {
	Service      *FixedService
	Admitter     *operations.Admitter
	MutationSet  *operations.MutationSet
	Mutation     *operations.MutationLease
	Exposure     *locks.Lease
	JobID        string
	Revision     uint64
	Installation domain.Installation
	Candidate    domain.HeadscaleDomain
	Snapshot     []byte
	Release      release.InstallIdentity
	Preflight    preflight.ExpansionRequest
	RemoteWait   bool
	Resuming     bool
}

func InitializeHeadscale(ctx context.Context, actor Actor, payload HeadscaleInitializePayload) (result jobs.Record, headscaleID, authorityDigest string, err error) {
	if payload.Confirmation != "initialize" {
		return jobs.Record{}, "", "", fmt.Errorf("headscale initialization confirmation is invalid")
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	// Headscale is initialized only from the asset committed by the release
	// transaction. No source, mirror, offline path, or proxy is accepted.
	execution, err := beginHeadscaleInitialize(ctx, actor, payload, installed)
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	defer func() {
		if execution != nil {
			err = errors.Join(err, execution.Close())
			if err != nil {
				result = jobs.Record{ID: execution.JobID}
				err = MutationJobError{JobID: execution.JobID, Err: err}
			}
		}
	}()
	paths := managedheadscale.FixedPaths()
	if err := managedheadscale.CommitInitializationJournal(ctx, paths, installed, execution.Candidate, execution.Snapshot, execution.JobID); err != nil {
		return jobs.Record{}, "", "", execution.fail(ctx, "no_effect", "headscale_journal_failed", err)
	}
	if err := managedheadscale.ValidateInitializationEvidence(execution.Installation.InstallationID, execution.Candidate, installed, execution.Snapshot, paths, filetxn.Owner{UID: 0, GID: 0}, !execution.Resuming); err != nil {
		if execution.Resuming {
			return jobs.Record{ID: execution.JobID}, "", "", fmt.Errorf("%w: %v", managedheadscale.ErrForeignEvidence, err)
		}
		removeErr := managedheadscale.RemoveInitializationJournal(paths, installed, execution.Candidate, execution.Snapshot, execution.JobID)
		if removeErr != nil {
			return jobs.Record{}, "", "", errors.Join(err, removeErr)
		}
		terminalErr := execution.fail(ctx, "no_effect", "foreign_database_evidence", err)
		return jobs.Record{ID: execution.JobID}, "", "", terminalErr
	}
	if !execution.Resuming {
		if err := managedheadscale.MarkInitializationFreshValidated(ctx, paths, installed, execution.Candidate, execution.Snapshot, execution.JobID); err != nil {
			return jobs.Record{}, "", "", err
		}
		execution.Resuming = true
	}
	if err := managedheadscale.EnsureLayout(paths, filetxn.Owner{UID: 0, GID: 0}); err != nil {
		return jobs.Record{}, "", "", err
	}
	if err := managedheadscale.EnsureIdentityLayout(paths, filetxn.Owner{UID: 0, GID: 0}); err != nil {
		return jobs.Record{}, "", "", err
	}
	intent, err := execution.Admitter.OperationIntent(execution.JobID)
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	if !execution.RemoteWait {
		intent, err = execution.Admitter.EnterRemoteWait(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID)
		execution.Mutation, execution.Exposure = nil, nil
		if err != nil {
			return jobs.Record{}, "", "", err
		}
		execution.Revision++
		execution.RemoteWait = true
	}
	archive, err := managedheadscale.ReadInstalledArchive(paths, installed, filetxn.Owner{UID: 0, GID: 0})
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	document, err := execution.Service.Normal().Read()
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	_, mutation, exposure, err := execution.Admitter.Reenter(ctx, execution.MutationSet, execution.Service.Manager(), document.Revision, intent.JobID)
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	execution.Mutation, execution.Exposure = mutation, exposure
	execution.Revision = document.Revision + 1
	freshPreflight, _, err := evaluateHeadscalePreflight(ctx, installed, execution.Candidate.ControlDomain, execution.Candidate.Database.Generation)
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	if !sameHeadscalePreflightPolicy(freshPreflight, execution.Preflight) {
		return jobs.Record{}, "", "", fmt.Errorf("fresh Headscale preflight policy authority changed")
	}
	if err := managedheadscale.ValidateInitializationEvidence(execution.Installation.InstallationID, execution.Candidate, installed, execution.Snapshot, paths, filetxn.Owner{UID: 0, GID: 0}, false); err != nil {
		return jobs.Record{ID: execution.JobID}, "", "", fmt.Errorf("%w: %v", managedheadscale.ErrForeignEvidence, err)
	}
	if _, err := managedheadscale.EnsureAccount(ctx, execution.Installation.InstallationID, execution.Candidate.ID); err != nil {
		return jobs.Record{}, "", "", err
	}
	if err := managedheadscale.Install(ctx, managedheadscale.InstallRequest{Paths: paths, Owner: filetxn.Owner{UID: 0, GID: 0}, Release: installed, Candidate: execution.Candidate, SnapshotBytes: execution.Snapshot, ArchiveBytes: archive}); err != nil {
		if errors.Is(err, managedheadscale.ErrForeignEvidence) {
			return jobs.Record{ID: execution.JobID}, "", "", err
		}
		return jobs.Record{}, "", "", err
	}
	committedCandidate := execution.Candidate
	committedCandidate.LastOperation = domain.OperationHeadscaleInitialize
	committedCandidate.LastJobID = execution.JobID
	if err := execution.Admitter.CommitHeadscaleInitialize(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.HeadscaleInitializeCommit{Headscale: committedCandidate}); err != nil {
		return jobs.Record{}, "", "", err
	}
	execution.Revision++
	if err := managedheadscale.RemoveInitializationJournal(paths, installed, execution.Candidate, execution.Snapshot, execution.JobID); err != nil {
		return jobs.Record{}, "", "", err
	}
	job, err := execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "complete", []string{paths.Executable, paths.IdentityParent}, []jobs.Postcondition{{Kind: "headscale_identity_committed", Status: jobs.PostconditionVerified, Identity: execution.Candidate.Database.IdentityBundleDigest}, {Kind: "headscale_service_absent", Status: jobs.PostconditionVerified, Identity: execution.Candidate.ID}}, "")
	if err != nil {
		return jobs.Record{}, "", "", err
	}
	headscaleID = execution.Candidate.ID
	return job, headscaleID, execution.Candidate.DesiredDigest, nil
}

type bootstrapCommitWire struct {
	SchemaVersion            string    `json:"schema_version"`
	AttemptID                string    `json:"attempt_id"`
	InstallationID           string    `json:"installation_id"`
	GenerationID             string    `json:"generation_id"`
	JournalSequence          uint64    `json:"journal_sequence"`
	BundleDigest             string    `json:"bundle_digest"`
	ArtifactDigest           string    `json:"artifact_inventory_digest"`
	OwnershipInventoryDigest string    `json:"ownership_inventory_digest"`
	CommittedAt              time.Time `json:"committed_at"`
}

type installationBundleWire struct {
	SchemaVersion             string                       `json:"schema_version"`
	AttemptID                 string                       `json:"attempt_id"`
	InstallationID            string                       `json:"installation_id"`
	GenerationID              string                       `json:"generation_id"`
	SafetyGeneration          uint64                       `json:"safety_generation"`
	Fingerprint               string                       `json:"fingerprint"`
	Management                identity.ManagementAuthority `json:"management_authority"`
	Release                   release.InstallIdentity      `json:"release"`
	PreflightDigest           string                       `json:"preflight_digest"`
	ACMEAccountKeyFingerprint string                       `json:"acme_account_key_fingerprint"`
}

func sameHeadscalePreflightPolicy(left, right preflight.ExpansionRequest) bool {
	left.OwnedListeners = nil
	right.OwnedListeners = nil
	return reflect.DeepEqual(left, right)
}

func readCommittedInstallationAuthority() (installationBundleWire, error) {
	commitBytes, err := readProtectedBytes("/var/lib/lanpanel/bootstrap-commit.json", 0o644)
	var commit bootstrapCommitWire
	if err != nil || decodeProtectedCanonical(commitBytes, &commit) != nil || commit.SchemaVersion != "lanpanel.bootstrap.commit.v1" || !identity.ValidateAttemptID(commit.AttemptID) || !identity.ValidateInstallationID(commit.InstallationID) || !identity.ValidateGenerationID(commit.GenerationID) || commit.JournalSequence == 0 || !release.ValidDigest(commit.BundleDigest) || !release.ValidDigest(commit.ArtifactDigest) || !release.ValidDigest(commit.OwnershipInventoryDigest) || commit.CommittedAt.IsZero() {
		return installationBundleWire{}, fmt.Errorf("bootstrap commit authority is unavailable")
	}
	bundleBytes, err := readProtectedBytes("/var/lib/lanpanel/installation/bundle.json", 0o600)
	var bundle installationBundleWire
	if err != nil || decodeProtectedCanonical(bundleBytes, &bundle) != nil || bundle.SchemaVersion != "lanpanel.installation.bundle.v2" || bundle.AttemptID != commit.AttemptID || bundle.InstallationID != commit.InstallationID || bundle.GenerationID != commit.GenerationID || bundle.SafetyGeneration == 0 || commit.BundleDigest != release.DigestBytes(bundleBytes) || identity.ValidateManagementAuthority(bundle.Management) != nil || release.ValidateInstallIdentity(bundle.Release) != nil || bundle.PreflightDigest == "" {
		return installationBundleWire{}, fmt.Errorf("installation bundle does not match bootstrap commit")
	}
	accountKey, keyErr := readProtectedBytes(acmeaccount.ManagedKeyPath, 0o600)
	accountFingerprint, fingerprintErr := acmeaccount.Fingerprint(accountKey)
	if keyErr != nil || fingerprintErr != nil || accountFingerprint != bundle.ACMEAccountKeyFingerprint {
		return installationBundleWire{}, fmt.Errorf("managed ACME account key does not match installation bundle")
	}
	fingerprint, err := identity.Fingerprint(bundle.InstallationID)
	if err != nil || bundle.Fingerprint != fingerprint {
		return installationBundleWire{}, fmt.Errorf("installation bundle fingerprint changed")
	}
	return bundle, nil
}

func readCommittedReleaseIdentity() (release.InstallIdentity, error) {
	bundle, err := readCommittedInstallationAuthority()
	return bundle.Release, err
}

func readManagedACMEAccountAuthority() (string, string, error) {
	bundle, err := readCommittedInstallationAuthority()
	if err != nil {
		return "", "", err
	}
	contact, err := acmeaccount.ReadContact()
	if err != nil {
		return "", "", fmt.Errorf("ACME contact is not configured in the authenticated Management UI: %w", err)
	}
	return contact, bundle.ACMEAccountKeyFingerprint, nil
}

func decodeProtectedCanonical(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("protected authority JSON has trailing data")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !slices.Equal(canonical, data) {
		return fmt.Errorf("protected authority JSON is noncanonical")
	}
	return nil
}

func readProtectedBytes(path string, mode uint32) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("protected authority descriptor unavailable")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o7777 != mode || stat.Size <= 0 || stat.Size > 4<<20 {
		return nil, fmt.Errorf("protected authority file metadata is unsafe")
	}
	data := make([]byte, stat.Size)
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || stat.Dev != after.Dev || stat.Ino != after.Ino || stat.Size != after.Size || stat.Mtim != after.Mtim {
		return nil, fmt.Errorf("protected authority file changed during read")
	}
	return data, nil
}

func beginHeadscaleInitialize(ctx context.Context, actor Actor, payload HeadscaleInitializePayload, installed release.InstallIdentity) (*HeadscaleExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*HeadscaleExecution, error) { _ = service.Close(); return nil, cause }
	document, err := service.Normal().Read()
	if err != nil {
		return fail(err)
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fail(fmt.Errorf("installation authority is missing"))
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil || installation.Headscale != nil {
		return fail(errors.Join(err, fmt.Errorf("headscale trust domain is already configured")))
	}
	journal, snapshot, err := managedheadscale.LoadInitializationJournal(managedheadscale.FixedPaths(), installed)
	var candidate domain.HeadscaleDomain
	if err != nil {
		return fail(err)
	}
	if journal != nil {
		candidate = journal.Candidate
		if candidate.ControlDomain != payload.ControlDomain || candidate.MagicDNSNamespace != payload.MagicDNSNamespace {
			return fail(fmt.Errorf("an exact Headscale initialization is already pending"))
		}
	} else {
		candidate, _, snapshot, err = managedheadscale.NewCandidate(managedheadscale.CandidateRequest{InstallationID: installation.InstallationID, ControlDomain: payload.ControlDomain, MagicDNSNamespace: payload.MagicDNSNamespace, Release: installed})
		if err != nil {
			return fail(err)
		}
	}
	preflightRequest, preflightResult, err := evaluateHeadscalePreflight(ctx, installed, candidate.ControlDomain, candidate.Database.Generation)
	if err != nil {
		return fail(err)
	}
	next := installation
	next.Headscale = &candidate
	if err := domain.ValidateInstallation(next); err != nil {
		return fail(err)
	}
	if _, err := reservations.BuildClaims(next); err != nil {
		return fail(err)
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return fail(err)
	}
	if journal != nil {
		record, err := jobs.LoadEntries(document.Entries, journal.JobID)
		if err != nil || record.Status != jobs.StatusRunning {
			return fail(fmt.Errorf("pending Headscale initialization job authority is unavailable"))
		}
		intent, err := admitter.OperationIntent(journal.JobID)
		if err != nil || intent.Operation != operations.HeadscaleInitialize || intent.Target != string(plans.TargetInstallation) || intent.SafetyBinding.CandidateDigest != candidate.DesiredDigest || intent.SafetyBinding.CandidateBundle != candidate.Artifact.ArchiveDigest || intent.HeadscaleBinding == nil || intent.HeadscaleBinding.Candidate.ID != candidate.ID || !slices.Equal(intent.HeadscaleBinding.Snapshot, snapshot) || !sameHeadscalePreflightPolicy(intent.HeadscaleBinding.PreflightRequest, preflightRequest) {
			return fail(fmt.Errorf("pending Headscale initialization intent changed"))
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
		if err != nil {
			return fail(err)
		}
		execution := &HeadscaleExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, JobID: journal.JobID, Revision: document.Revision, Installation: installation, Candidate: candidate, Snapshot: snapshot, Release: installed, Preflight: preflightRequest, Resuming: journal.FreshValidated}
		switch intent.Phase {
		case operations.PhaseRemoteWait:
			execution.RemoteWait = true
			return execution, nil
		case operations.PhaseLocalIntent, operations.PhaseReentered:
			mutation, exposure, err := mutationSet.AcquireExposure(ctx, string(plans.TargetInstallation), service.Manager())
			if err != nil {
				_ = mutationSet.Close()
				return fail(err)
			}
			if _, err := admitter.EnterRemoteWait(ctx, mutation, exposure, document.Revision, journal.JobID); err != nil {
				_ = mutationSet.Close()
				return fail(err)
			}
			execution.Revision++
			execution.RemoteWait = true
			return execution, nil
		default:
			_ = mutationSet.Close()
			return fail(fmt.Errorf("pending Headscale initialization phase is not resumable"))
		}
	}
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	admission, err := service.Manager().Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.HeadscaleInitialize, Target: string(plans.TargetInstallation), ActorIdentity: authority, Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{CandidateDigest: candidate.DesiredDigest, CandidateBundle: candidate.Artifact.ArchiveDigest}, HeadscaleBinding: &operations.HeadscaleInitializationBinding{Candidate: candidate, Snapshot: append(json.RawMessage(nil), snapshot...), PreflightRequest: preflightRequest, PreflightResult: preflightResult}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, string(plans.TargetInstallation), service.Manager())
	if err != nil {
		_ = mutationSet.Close()
		return fail(err)
	}
	fresh, err := service.Normal().Read()
	if err != nil || fresh.Revision != document.Revision+1 {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(fmt.Errorf("headscale initialization authority changed"))
	}
	intent, err := admitter.BeginUI(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		_ = operations.ReleaseExposure(mutation, exposure)
		_ = mutationSet.Close()
		return fail(err)
	}
	return &HeadscaleExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: intent.IntentGeneration, Installation: installation, Candidate: candidate, Snapshot: snapshot, Release: installed, Preflight: preflightRequest}, nil
}

func (execution *HeadscaleExecution) fail(ctx context.Context, branch, code string, cause error) error {
	if execution == nil || execution.Mutation == nil || execution.Exposure == nil {
		return cause
	}
	_, terminalErr := execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, branch, nil, []jobs.Postcondition{{Kind: "headscale_not_initialized", Status: jobs.PostconditionKnown, Identity: execution.Candidate.ID}}, code)
	return errors.Join(cause, terminalErr)
}

func (execution *HeadscaleExecution) Close() error {
	if execution == nil {
		return nil
	}
	var err error
	if execution.Mutation != nil || execution.Exposure != nil {
		err = operations.ReleaseExposure(execution.Mutation, execution.Exposure)
		execution.Mutation, execution.Exposure = nil, nil
	}
	if execution.MutationSet != nil {
		err = errors.Join(err, execution.MutationSet.Close())
	}
	if execution.Service != nil {
		err = errors.Join(err, execution.Service.Close())
	}
	return err
}
