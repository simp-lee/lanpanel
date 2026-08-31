//go:build linux

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/basic"
	"lanpanel/internal/domain"
	"lanpanel/internal/htpasswdref"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/persist"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func ReconcileManagedBasic(ctx context.Context, childClosure string) error {
	if len(childClosure) != 71 || !strings.HasPrefix(childClosure, "sha256:") {
		return fmt.Errorf("managed Basic child closure invalid")
	}
	directory := filepath.Dir(basicJournalPath("cred_00000000000000000000000000000000"))
	paths, err := managedBasicJournalInventory(directory, 0, 0)
	if errors.Is(err, os.ErrNotExist) {
		return reconcileJournalLessManagedBasic(ctx, childClosure)
	}
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := reconcileManagedBasicJournal(ctx, path); err != nil {
			return err
		}
	}
	return reconcileJournalLessManagedBasic(ctx, childClosure)
}

func managedBasicJournalInventory(directory string, uid, gid uint32) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		if entry.Name() == ".filetxn" {
			info, statErr := os.Lstat(path)
			if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
				return nil, fmt.Errorf("managed Basic journal staging identity invalid")
			}
			var stat unix.Stat_t
			if unix.Lstat(path, &stat) != nil || stat.Uid != uid || stat.Gid != gid {
				return nil, fmt.Errorf("managed Basic journal staging owner invalid")
			}
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil, fmt.Errorf("managed Basic recovery inventory invalid")
		}
		result = append(result, path)
	}
	return result, nil
}

type managedBasicRecoveryStage uint8

const (
	managedBasicRecoverySkip managedBasicRecoveryStage = iota
	managedBasicRecoveryReject
	managedBasicRecoveryLocal
	managedBasicRecoveryInvalid
)

func classifyManagedBasicRecovery(intent operations.Reservation) managedBasicRecoveryStage {
	if intent.Operation != operations.ManagedBasicCreate && intent.Operation != operations.ManagedBasicRotate && intent.Operation != operations.ManagedBasicDelete {
		return managedBasicRecoverySkip
	}
	switch intent.Phase {
	case operations.PhaseReserved:
		return managedBasicRecoveryReject
	case operations.PhaseLocalIntent:
		return managedBasicRecoveryLocal
	case operations.PhaseRejected, operations.PhaseTerminal:
		return managedBasicRecoverySkip
	default:
		return managedBasicRecoveryInvalid
	}
}

func rejectReservedBasicOperation(ctx context.Context, service *FixedService, admitter *operations.Admitter, jobID, code string) (returnErr error) {
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, admission.Release()) }()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	raw, present := document.Entries["intents/"+jobID]
	var intent operations.Reservation
	if !present || json.Unmarshal(raw, &intent) != nil || intent.JobID != jobID {
		return fmt.Errorf("reserved Basic operation authority changed")
	}
	switch intent.Phase {
	case operations.PhaseRejected, operations.PhaseTerminal:
		return nil
	case operations.PhaseReserved:
		return admitter.RejectReservation(ctx, admission, document.Revision, jobID, code)
	default:
		return fmt.Errorf("reserved Basic operation is no longer rejectable")
	}
}

func reconcileJournalLessManagedBasic(ctx context.Context, childClosure string) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) != nil {
			continue
		}
		switch classifyManagedBasicRecovery(intent) {
		case managedBasicRecoverySkip:
			continue
		case managedBasicRecoveryReject:
			if err := rejectReservedBasicOperation(ctx, service, admitter, intent.JobID, "managed_basic_interrupted"); err != nil {
				return err
			}
			document, err = service.normal.Read()
			if err != nil {
				return err
			}
			continue
		case managedBasicRecoveryInvalid:
			return fmt.Errorf("managed Basic recovery phase changed")
		}
		credentialID := strings.TrimPrefix(intent.Target, "credential/")
		if intent.Operation == operations.ManagedBasicCreate {
			credentialID = ""
		}
		if credentialID != "" {
			if _, err := os.Lstat(basicJournalPath(credentialID)); err == nil {
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else {
			entries, _ := os.ReadDir(filepath.Dir(basicJournalPath("cred_00000000000000000000000000000000")))
			found := false
			for _, entry := range entries {
				journal, readErr := readBasicJournal(filepath.Join(filepath.Dir(basicJournalPath("cred_00000000000000000000000000000000")), entry.Name()))
				if readErr == nil && journal.JobID == intent.JobID {
					found = true
				}
			}
			if found {
				continue
			}
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		fresh, err := service.normal.Read()
		if err == nil {
			childRecord, present, childErr := managedBasicChild(fresh, intent.JobID)
			if childErr != nil {
				err = childErr
			} else if present && childRecord.State != operations.ChildTerminal {
				err = admitter.TerminalizeManagedBasicChildClosure(ctx, mutation, exposure, fresh.Revision, intent.JobID, childRecord.ID, childClosure)
				if err == nil {
					fresh, err = service.normal.Read()
				}
			}
		}
		if err == nil {
			condition := jobs.Postcondition{Kind: "managed_basic_not_started", Status: jobs.PostconditionKnown, Identity: intent.JobID}
			_, err = admitter.TerminalizeManagedBasicInterrupted(ctx, mutation, exposure, fresh.Revision, intent.JobID, nil, condition)
		}
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err != nil {
			return err
		}
		if releaseErr != nil || closeErr != nil {
			return fmt.Errorf("managed Basic recovery lock release failed")
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
	}
	return nil
}

func reconcileManagedBasicJournal(ctx context.Context, path string) error {
	journal, err := readBasicJournal(path)
	if err != nil {
		return err
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	intent, err := admitter.OperationIntent(journal.JobID)
	if err != nil {
		return err
	}
	expectedOperation := operations.ManagedBasicRotate
	target := "credential/" + journal.CredentialID
	switch journal.Operation {
	case "create":
		expectedOperation = operations.ManagedBasicCreate
		target = "resource/" + journal.ResourceID
	case "delete":
		expectedOperation = operations.ManagedBasicDelete
	}
	if intent.Operation != expectedOperation || intent.Target != target || journal.Operation != "create" && intent.SafetyBinding.PriorFingerprint != journal.PriorFingerprint || journal.Operation == "create" && intent.SafetyBinding.PriorFingerprint != "" {
		return fmt.Errorf("managed Basic recovery intent changed")
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(mutationSet.Close)
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, target, service.manager)
	if err != nil {
		return err
	}
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	record, err := jobs.LoadEntries(document.Entries, journal.JobID)
	if err != nil {
		return err
	}
	childRecord, presentChild, err := managedBasicChild(document, journal.JobID)
	if err != nil {
		return err
	}
	if journal.Operation != "delete" && (!presentChild || childRecord.State != operations.ChildTerminal || childRecord.Outcome != operations.ChildSucceeded || childRecord.ResultDigest != journal.CandidateFingerprint) {
		return fmt.Errorf("managed Basic journal child result changed")
	}
	if journal.Operation == "delete" && presentChild {
		return fmt.Errorf("managed Basic delete carried child")
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return err
	}
	credential, present := findBasicCredential(installation, journal.CredentialID)
	if record.Status == jobs.StatusTerminal && managedBasicPriorChangedCompletion(record) {
		return removeBasicJournal(path)
	}
	if record.Status != jobs.StatusTerminal && (intent.Phase != operations.PhaseLocalIntent || record.Status != jobs.StatusRunning) {
		return fmt.Errorf("managed Basic recovery phase changed")
	}
	if record.Status == jobs.StatusRunning && managedBasicCredentialChanged(journal, present, credential) {
		_, err := admitter.Complete(ctx, mutation, exposure, document.Revision, journal.JobID, "no_effect", nil, []jobs.Postcondition{{Kind: "managed_basic_prior_changed", Status: jobs.PostconditionVerified, Identity: journal.PriorFingerprint}}, "plan_consumption_rejected")
		if err != nil {
			return err
		}
		return removeBasicJournal(path)
	}
	gid, err := nginxGroupGID()
	if err != nil {
		return err
	}
	observedFingerprint := ""
	if _, statErr := os.Lstat(journal.Path); statErr == nil {
		observed, validateErr := htpasswdref.Validate(journal.Path, gid)
		if validateErr != nil {
			return validateErr
		}
		if observed.Mode != 0o640 {
			return fmt.Errorf("managed Basic file mode changed")
		}
		observedFingerprint = observed.Fingerprint
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if record.Status == jobs.StatusTerminal {
		if journal.Operation == "delete" {
			if present || observedFingerprint != "" {
				return fmt.Errorf("terminal managed Basic delete residue changed")
			}
		} else if !present || credential.Fingerprint != journal.CandidateFingerprint || observedFingerprint != journal.CandidateFingerprint {
			return fmt.Errorf("terminal managed Basic authority changed")
		}
		return removeBasicJournal(path)
	}
	revision := document.Revision
	condition := jobs.Postcondition{Kind: "managed_basic_interrupted", Status: jobs.PostconditionKnown, Identity: journal.CredentialID}
	decision, err := decideManagedBasicRecovery(journal, present, credential, observedFingerprint)
	if err != nil {
		return err
	}
	prior := managedBasicJournalCredential(journal, journal.PriorFingerprint)
	if decision.NoEffect {
		_, err := admitter.Complete(ctx, mutation, exposure, revision, journal.JobID, "no_effect", nil, []jobs.Postcondition{{Kind: "managed_basic_prior_changed", Status: jobs.PostconditionVerified, Identity: journal.PriorFingerprint}}, "plan_consumption_rejected")
		if err != nil {
			return err
		}
		return removeBasicJournal(path)
	}
	if decision.CommitFingerprint {
		if err = admitter.CommitManagedBasicFingerprint(ctx, mutation, exposure, revision, journal.JobID, prior, journal.CandidateFingerprint); err != nil {
			return err
		}
		revision++
	}
	if decision.CommitDelete {
		if err = admitter.CommitManagedBasicDelete(ctx, mutation, exposure, revision, journal.JobID, prior); err != nil {
			return err
		}
		revision++
	}
	modified := []string{}
	if decision.DeleteFile {
		if err = basic.Delete(ctx, journal.CredentialID, gid); err != nil {
			return err
		}
	}
	if decision.FileModified {
		modified = []string{journal.Path}
	}
	if decision.LostDelivery {
		_, err := admitter.CompleteWithSecret(ctx, mutation, exposure, revision, journal.JobID, "executor_died", modified, []jobs.Postcondition{condition}, "managed_basic_interrupted", &jobs.SecretResult{Kind: "managed_basic", ObjectID: journal.CredentialID, Fingerprint: journal.CandidateFingerprint, DeliveryAttempted: true, Remedy: "rotate_again"})
		if err != nil {
			return err
		}
	} else if _, err := admitter.TerminalizeManagedBasicInterrupted(ctx, mutation, exposure, revision, journal.JobID, modified, condition); err != nil {
		return err
	}
	return removeBasicJournal(path)
}

type managedBasicRecoveryDecision struct {
	CommitFingerprint bool
	CommitDelete      bool
	DeleteFile        bool
	FileModified      bool
	LostDelivery      bool
	NoEffect          bool
}

func managedBasicJournalCredential(journal BasicJournal, fingerprint string) domain.Credential {
	return domain.Credential{ID: journal.CredentialID, Kind: "managed_basic", OwnerResourceID: journal.ResourceID, Username: journal.Username, ManagedPath: journal.Path, Fingerprint: fingerprint}
}

func managedBasicCredentialChanged(journal BasicJournal, present bool, credential domain.Credential) bool {
	switch journal.Operation {
	case "rotate":
		prior := managedBasicJournalCredential(journal, journal.PriorFingerprint)
		candidate := managedBasicJournalCredential(journal, journal.CandidateFingerprint)
		return !present || credential != prior && credential != candidate
	case "delete":
		return present && credential != managedBasicJournalCredential(journal, journal.PriorFingerprint)
	default:
		return false
	}
}

func managedBasicPriorChangedCompletion(record jobs.Record) bool {
	if record.Result != jobs.ResultFailed || record.ErrorCode != "plan_consumption_rejected" {
		return false
	}
	for _, condition := range record.Postconditions {
		if condition.Kind == "managed_basic_prior_changed" && condition.Status == jobs.PostconditionVerified {
			return true
		}
	}
	return false
}

func decideManagedBasicRecovery(journal BasicJournal, present bool, credential domain.Credential, observed string) (managedBasicRecoveryDecision, error) {
	var result managedBasicRecoveryDecision
	switch journal.Operation {
	case "create":
		if present && credential.Fingerprint != journal.CandidateFingerprint {
			return result, fmt.Errorf("managed Basic create state changed")
		}
		if observed != "" && observed != journal.CandidateFingerprint {
			return result, fmt.Errorf("managed Basic create file identity changed")
		}
		if present {
			if observed != journal.CandidateFingerprint {
				return result, fmt.Errorf("committed managed Basic create file missing")
			}
			result.FileModified = true
			result.LostDelivery = true
		} else if observed == journal.CandidateFingerprint {
			result.DeleteFile = true
			result.FileModified = true
		}
	case "rotate":
		prior := managedBasicJournalCredential(journal, journal.PriorFingerprint)
		candidate := managedBasicJournalCredential(journal, journal.CandidateFingerprint)
		if !present || credential != prior && credential != candidate {
			result.NoEffect = true
			return result, nil
		}
		if observed == journal.CandidateFingerprint {
			if credential == prior {
				result.CommitFingerprint = true
			}
			result.FileModified = true
			result.LostDelivery = true
		} else if observed != journal.PriorFingerprint || credential != prior {
			return result, fmt.Errorf("managed Basic rotate identity ambiguous")
		}
	case "delete":
		prior := managedBasicJournalCredential(journal, journal.PriorFingerprint)
		if present && credential != prior || observed != "" && observed != journal.PriorFingerprint {
			result.NoEffect = true
			return result, nil
		}
		result.CommitDelete = present
		result.DeleteFile = observed != ""
		result.FileModified = result.DeleteFile
	default:
		return result, fmt.Errorf("managed Basic recovery operation invalid")
	}
	return result, nil
}

func managedBasicChild(document persist.Document, jobID string) (operations.ChildRecord, bool, error) {
	var result operations.ChildRecord
	found := false
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "children/") {
			continue
		}
		var child operations.ChildRecord
		if json.Unmarshal(raw, &child) != nil {
			return result, false, fmt.Errorf("managed Basic child malformed")
		}
		if child.JobID != jobID {
			continue
		}
		if found {
			return result, false, fmt.Errorf("managed Basic child inventory ambiguous")
		}
		result = child
		found = true
	}
	return result, found, nil
}

func findBasicCredential(installation domain.Installation, id string) (domain.Credential, bool) {
	for _, credential := range installation.Credentials {
		if credential.ID == id {
			return credential, true
		}
	}
	return domain.Credential{}, false
}
