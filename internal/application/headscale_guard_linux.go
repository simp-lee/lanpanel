//go:build linux

package application

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"os"
	"reflect"
)

func (s *FixedService) PendingHeadscaleRecovery() error {
	if s == nil || s.normal == nil {
		return fmt.Errorf("normal authority is unavailable")
	}
	document, err := s.normal.Read()
	if err != nil {
		return err
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fmt.Errorf("normal installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return err
	}
	paths := managedheadscale.FixedPaths()
	if installation.Headscale == nil {
		if _, err := os.Lstat(paths.Journal); os.IsNotExist(err) {
			_, _, pending, pendingErr := operations.FindRunningHeadscaleInitialization(document)
			if pendingErr != nil {
				return pendingErr
			}
			if pending {
				return fmt.Errorf("exact Headscale initialization requires journal recovery")
			}
			return nil
		} else if err != nil {
			return err
		}
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return err
	}
	journal, _, err := managedheadscale.LoadInitializationJournal(paths, installed)
	if err != nil {
		return err
	}
	if installation.Headscale == nil {
		if journal != nil {
			return fmt.Errorf("exact Headscale initialization requires resumption")
		}
		return nil
	}
	if journal != nil && journal.Candidate.ID != installation.Headscale.ID {
		return fmt.Errorf("headscale initialization journal conflicts with committed identity")
	}
	return managedheadscale.ValidateCommittedInitialization(installation.InstallationID, *installation.Headscale, installed, paths, filetxn.Owner{UID: 0, GID: 0})
}

// ReconcileHeadscaleInitialization resumes the exact journaled initialization
// or terminalizes a host-complete commit. It never creates a new identity.
func ReconcileHeadscaleInitialization(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	document, err := service.Normal().Read()
	if err != nil {
		_ = service.Close()
		return err
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		_ = service.Close()
		return fmt.Errorf("normal installation authority is missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		_ = service.Close()
		return err
	}
	paths := managedheadscale.FixedPaths()
	journalPresent := false
	if _, statErr := os.Lstat(paths.Journal); statErr == nil {
		journalPresent = true
	} else if !os.IsNotExist(statErr) {
		_ = service.Close()
		return statErr
	}
	pending, _, pendingFound, err := operations.FindRunningHeadscaleInitialization(document)
	if err != nil {
		_ = service.Close()
		return err
	}
	if installation.Headscale == nil && !journalPresent && !pendingFound {
		return service.Close()
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		_ = service.Close()
		return err
	}
	journal, _, err := managedheadscale.LoadInitializationJournal(paths, installed)
	if err != nil {
		_ = service.Close()
		return err
	}
	if installation.Headscale == nil {
		if !pendingFound || pending.HeadscaleBinding == nil {
			_ = service.Close()
			return fmt.Errorf("headscale initialization journal has no running intent")
		}
		if pending.Phase == operations.PhaseReserved {
			admitter, admitterErr := service.resourceAdmitter()
			admission, lockErr := service.Manager().Acquire(ctx, locks.MutationAdmission)
			if admitterErr != nil || lockErr != nil {
				_ = service.Close()
				return errors.Join(admitterErr, lockErr)
			}
			rejectErr := admitter.RejectReservation(ctx, admission, document.Revision, pending.JobID, "executor_died")
			releaseErr := admission.Release()
			return errors.Join(rejectErr, releaseErr, service.Close())
		}
		binding := pending.HeadscaleBinding
		if journal == nil {
			if err := managedheadscale.CommitInitializationJournal(ctx, paths, installed, binding.Candidate, binding.Snapshot, pending.JobID, binding.Source, binding.ProxyURL); err != nil {
				_ = service.Close()
				return err
			}
		} else if journal.JobID != pending.JobID || journal.Candidate.ID != binding.Candidate.ID || !reflect.DeepEqual(journal.Source, binding.Source) || journal.ProxyURL != binding.ProxyURL {
			_ = service.Close()
			return fmt.Errorf("headscale initialization journal differs from running intent")
		}
		_ = service.Close()
		return fmt.Errorf("exact Headscale initialization awaits explicit UI resumption")
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	candidate := *installation.Headscale
	if err := managedheadscale.ValidateCommittedInitialization(installation.InstallationID, candidate, installed, paths, filetxn.Owner{UID: 0, GID: 0}); err != nil {
		return err
	}
	if journal != nil && (journal.Candidate.ID != candidate.ID || journal.JobID != candidate.LastJobID) {
		return fmt.Errorf("committed Headscale journal binding changed")
	}
	record, err := jobs.LoadEntries(document.Entries, candidate.LastJobID)
	if errors.Is(err, jobs.ErrMissing) && journal == nil {
		return nil
	}
	if err != nil {
		return err
	}
	if record.Status == jobs.StatusTerminal {
		if journal != nil {
			return fmt.Errorf("terminal Headscale job retained a journal")
		}
		return nil
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return err
	}
	intent, err := admitter.OperationIntent(candidate.LastJobID)
	if err != nil || intent.Phase != operations.PhaseReentered || intent.Operation != operations.HeadscaleInitialize {
		return fmt.Errorf("committed Headscale operation is not terminalizable")
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, string(plans.TargetInstallation), service.Manager())
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	if journal != nil {
		if err := managedheadscale.RemoveInitializationJournal(paths, installed, journal.Candidate, journal.Snapshot, journal.JobID, journal.Source, journal.ProxyURL); err != nil {
			return err
		}
	}
	_, terminalErr := admitter.Complete(ctx, mutation, exposure, document.Revision, candidate.LastJobID, "complete", []string{paths.Executable, paths.IdentityParent}, []jobs.Postcondition{{Kind: "headscale_identity_committed", Status: jobs.PostconditionVerified, Identity: candidate.Database.IdentityBundleDigest}, {Kind: "headscale_service_absent", Status: jobs.PostconditionVerified, Identity: candidate.ID}}, "")
	return terminalErr
}
