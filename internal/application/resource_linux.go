//go:build linux

package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"lanpanel/internal/resource"
	"lanpanel/internal/safety"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type ResourceUpdateJournal struct {
	SchemaVersion string             `json:"schema_version"`
	JobID         string             `json:"job_id"`
	ResourceID    string             `json:"resource_id"`
	Prior         domain.AppResource `json:"prior"`
	Candidate     domain.AppResource `json:"candidate"`
}

const resourceUpdateJournalSchema = "lanpanel.resource.update.v1"

func resourceUpdateJournalPath(resourceID string) string {
	return fixedRoot + "/safety/resource-update/" + resourceID + ".json"
}
func writeResourceUpdateJournal(ctx context.Context, value ResourceUpdateJournal) error {
	if value.SchemaVersion != resourceUpdateJournalSchema || value.JobID == "" || value.ResourceID == "" || value.Prior.ID != value.ResourceID || value.Candidate.ID != value.ResourceID {
		return fmt.Errorf("resource update journal invalid")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeBoundedJournal(ctx, resourceUpdateJournalPath(value.ResourceID), raw)
}
func readResourceUpdateJournal(path string) (ResourceUpdateJournal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ResourceUpdateJournal{}, err
	}
	if len(data) == 0 || len(data) > maximumCreateJournalBytes {
		return ResourceUpdateJournal{}, fmt.Errorf("resource update journal size invalid")
	}
	var value ResourceUpdateJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ResourceUpdateJournal{}, fmt.Errorf("resource update journal malformed")
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(canonical, data) || value.SchemaVersion != resourceUpdateJournalSchema || value.JobID == "" || value.ResourceID == "" || value.Prior.ID != value.ResourceID || value.Candidate.ID != value.ResourceID {
		return ResourceUpdateJournal{}, fmt.Errorf("resource update journal noncanonical")
	}
	return value, nil
}
func writeBoundedJournal(ctx context.Context, path string, raw []byte) error {
	if err := ensureDurableJournalDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	owner := filetxn.Owner{UID: 0, GID: 0}
	staging := filepath.Join(filepath.Dir(path), ".filetxn")
	if err := ensureDurableJournalDirectory(staging); err != nil {
		return err
	}
	store, err := filetxn.Open(filetxn.Config{RootPath: "/", Root: filetxn.Metadata{Owner: owner, Mode: 0o755}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}}, filetxn.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	disposition := filetxn.CreateOnly
	if _, statErr := os.Lstat(path); statErr == nil {
		disposition = filetxn.ReplaceOnly
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	_, err = store.Put(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o755}, Existing: &metadata, New: metadata, MaxBytes: int64(len(raw))}, raw, disposition)
	return err
}

func ensureDurableJournalDirectory(path string) error {
	created := false
	if err := os.Mkdir(path, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("journal directory identity is unsafe")
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if created {
		parent, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			return errors.Join(syncErr, closeErr, openErr)
		}
		syncErr = errors.Join(syncErr, parent.Sync())
		closeErr = errors.Join(closeErr, parent.Close())
	}
	return errors.Join(syncErr, closeErr)
}

func removeJournal(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type ResourceCreateJournal struct {
	SchemaVersion   string             `json:"schema_version"`
	JobID           string             `json:"job_id"`
	ResourceID      string             `json:"resource_id"`
	Resource        domain.AppResource `json:"resource"`
	Phase           string             `json:"phase"`
	OwnershipDigest string             `json:"ownership_digest,omitempty"`
}

const maximumCreateJournalBytes = 64 << 10

func resourceCreateJournalPath(resourceID string) string {
	return fixedRoot + "/safety/resource-create/" + resourceID + ".json"
}
func readCreateJournal(path string) (ResourceCreateJournal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ResourceCreateJournal{}, err
	}
	if len(data) == 0 || len(data) > maximumCreateJournalBytes {
		return ResourceCreateJournal{}, fmt.Errorf("resource create journal size invalid")
	}
	var value ResourceCreateJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ResourceCreateJournal{}, fmt.Errorf("resource create journal malformed")
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(canonical, data) || value.SchemaVersion != "lanpanel.resource.create.v1" || value.JobID == "" || value.ResourceID == "" || value.Resource.ID != value.ResourceID {
		return ResourceCreateJournal{}, fmt.Errorf("resource create journal noncanonical")
	}
	if value.Phase != "prepared" && value.Phase != "ownership_committed" && value.Phase != "safety_committed" {
		return ResourceCreateJournal{}, fmt.Errorf("resource create journal phase is unsupported")
	}
	if value.Phase == "prepared" && value.OwnershipDigest != "" || value.Phase != "prepared" && !validCreateDigest(value.OwnershipDigest) {
		return ResourceCreateJournal{}, fmt.Errorf("resource create journal ownership binding is invalid")
	}
	return value, nil
}

func writeCreateJournal(ctx context.Context, journal ResourceCreateJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeBoundedJournal(ctx, resourceCreateJournalPath(journal.ResourceID), raw)
}
func ReconcileResourceUpdates(ctx context.Context) error {
	if err := reconcileJournalLessResourceUpdates(ctx); err != nil {
		return err
	}
	paths, err := filepath.Glob(fixedRoot + "/safety/resource-update/*.json")
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := reconcileResourceUpdate(ctx, path); err != nil {
			return err
		}
	}
	return nil
}
func reconcileJournalLessResourceUpdates(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	document, err := service.normal.Read()
	if err != nil {
		service.Close()
		return err
	}
	intents, err := operations.PendingResourceUpdates(document)
	service.Close()
	if err != nil {
		return err
	}
	for _, intent := range intents {
		if _, err := os.Lstat(resourceUpdateJournalPath(intent.SafetyBinding.ResourceID)); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		service, err := OpenFixed()
		if err != nil {
			return err
		}
		document, err := service.normal.Read()
		if err != nil {
			service.Close()
			return err
		}
		fresh, err := operations.FindResourceUpdateAuthority(document, intent.JobID, intent.SafetyBinding.ResourceID)
		if err != nil {
			service.Close()
			return err
		}
		admitter, err := service.resourceAdmitter()
		if err != nil {
			service.Close()
			return err
		}
		if fresh.Phase == operations.PhaseReserved {
			admission, lockErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if lockErr != nil {
				service.Close()
				return lockErr
			}
			err = admitter.RejectReservation(ctx, admission, document.Revision, fresh.JobID, "resource_update_not_started")
			releaseErr := admission.Release()
			service.Close()
			if err != nil || releaseErr != nil {
				return errors.Join(err, releaseErr)
			}
			continue
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			service.Close()
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+fresh.SafetyBinding.ResourceID, service.manager)
		if err != nil {
			mutationSet.Close()
			service.Close()
			return err
		}
		document, err = service.normal.Read()
		if err == nil {
			fresh, err = operations.FindResourceUpdateAuthority(document, fresh.JobID, fresh.SafetyBinding.ResourceID)
		}
		if err == nil && fresh.Phase != operations.PhaseLocalIntent {
			err = fmt.Errorf("journal-less resource update phase changed")
		}
		if err == nil && (!validCreateDigest(fresh.SafetyBinding.CandidateDigest) || !validCreateDigest(fresh.SafetyBinding.CandidateBundle)) {
			err = fmt.Errorf("journal-less resource update digest binding invalid")
		}
		branch, condition := "", ""
		if err == nil {
			installation, decodeErr := installationFromDocument(document)
			err = decodeErr
			if err == nil {
				current := findNormalResource(installation, fresh.SafetyBinding.ResourceID)
				if current == nil {
					err = fmt.Errorf("journal-less resource update target missing")
				} else if current.CurrentConfigDigest == fresh.SafetyBinding.CandidateDigest {
					branch = "complete"
					condition = "resource_config_saved"
				} else if current.CurrentConfigDigest == fresh.SafetyBinding.CandidateBundle {
					branch = "no_effect"
					condition = "resource_update_not_committed"
				} else {
					err = fmt.Errorf("journal-less resource update current digest matches neither prior nor candidate")
				}
			}
		}
		if err == nil {
			status := jobs.PostconditionVerified
			identity := fresh.SafetyBinding.ResourceID
			if branch == "complete" {
				identity = fresh.SafetyBinding.CandidateDigest
			}
			_, err = admitter.Complete(ctx, mutation, exposure, document.Revision, fresh.JobID, branch, nil, []jobs.Postcondition{{Kind: condition, Status: status, Identity: identity}}, "")
		}
		err = errors.Join(err, operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close())
		if err != nil {
			return err
		}
	}
	return nil
}
func reconcileResourceUpdate(ctx context.Context, path string) (result error) {
	journal, err := readResourceUpdateJournal(path)
	if err != nil {
		return err
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		service.Close()
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+journal.ResourceID, service.manager)
	if err != nil {
		mutationSet.Close()
		service.Close()
		return err
	}
	remove := false
	defer func() {
		cleanup := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close())
		result = errors.Join(result, cleanup)
		if result == nil && remove {
			result = removeJournal(path)
		}
	}()
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	intent, err := operations.FindResourceUpdateAuthority(document, journal.JobID, journal.ResourceID)
	if err != nil {
		return err
	}
	if intent.SafetyBinding.CandidateDigest != journal.Candidate.CurrentConfigDigest || intent.SafetyBinding.CandidateBundle != journal.Prior.CurrentConfigDigest {
		return fmt.Errorf("resource update journal digest binding differs from intent")
	}
	job, err := jobs.LoadEntries(document.Entries, journal.JobID)
	if err != nil {
		return err
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		return err
	}
	current := findNormalResource(installation, journal.ResourceID)
	if current == nil {
		return fmt.Errorf("resource update recovery target missing")
	}
	if intent.Phase == operations.PhaseTerminal {
		if !exactSuccessfulResourceUpdate(job, current, journal) {
			return fmt.Errorf("terminal resource update differs from journal")
		}
		remove = true
		return nil
	}
	if intent.Phase != operations.PhaseLocalIntent || job.Status != jobs.StatusRunning {
		return fmt.Errorf("resource update recovery phase is inconsistent")
	}
	if reflect.DeepEqual(*current, journal.Prior) {
		admitter, err := service.resourceAdmitter()
		if err != nil {
			return err
		}
		if err := admitter.CommitResourceUpdate(ctx, mutation, exposure, document.Revision, journal.JobID, journal.Candidate); err != nil {
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
		installation, err = installationFromDocument(document)
		if err != nil {
			return err
		}
		current = findNormalResource(installation, journal.ResourceID)
	}
	if current == nil || !reflect.DeepEqual(*current, journal.Candidate) {
		return fmt.Errorf("resource update current authority matches neither prior nor candidate")
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return err
	}
	if _, err := admitter.Complete(ctx, mutation, exposure, document.Revision, journal.JobID, "complete", nil, []jobs.Postcondition{{Kind: "resource_config_saved", Status: jobs.PostconditionVerified, Identity: journal.Candidate.CurrentConfigDigest}}, ""); err != nil {
		return err
	}
	remove = true
	return nil
}
func exactSuccessfulResourceUpdate(job jobs.Record, current *domain.AppResource, journal ResourceUpdateJournal) bool {
	if job.Status != jobs.StatusTerminal || job.Result != jobs.ResultSucceeded || current == nil || len(job.Postconditions) != 1 || job.Postconditions[0] != (jobs.Postcondition{Kind: "resource_config_saved", Status: jobs.PostconditionVerified, Identity: journal.Candidate.CurrentConfigDigest}) {
		return false
	}
	expected := journal.Candidate
	expected.PublicationRecord.LastOperation = domain.OperationResourceUpdate
	expected.PublicationRecord.LastOperationResult = domain.OperationSucceeded
	expected.PublicationRecord.LastJobID = journal.JobID
	return reflect.DeepEqual(*current, expected)
}

func ReconcileResourceCreates(ctx context.Context) error {
	if err := reconcileJournalLessResourceCreates(ctx); err != nil {
		return err
	}
	paths, err := filepath.Glob(fixedRoot + "/safety/resource-create/*.json")
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := reconcileResourceCreate(ctx, path); err != nil {
			return err
		}
	}
	return nil
}

func reconcileJournalLessResourceCreates(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	document, err := service.normal.Read()
	if err != nil {
		service.Close()
		return err
	}
	intents, err := operations.PendingResourceCreates(document)
	if err != nil {
		service.Close()
		return err
	}
	service.Close()
	for _, intent := range intents {
		if _, err := os.Lstat(resourceCreateJournalPath(intent.SafetyBinding.ResourceID)); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		service, err := OpenFixed()
		if err != nil {
			return err
		}
		document, err := service.normal.Read()
		if err != nil {
			service.Close()
			return err
		}
		var fresh operations.Reservation
		if intent.Phase != operations.PhaseReserved {
			fresh, err = operations.FindResourceCreateAuthority(document, intent.JobID, intent.SafetyBinding.ResourceID)
		}
		if intent.Phase == operations.PhaseReserved {
			admission, lockErr := service.manager.Acquire(ctx, locks.MutationAdmission)
			if lockErr != nil {
				service.Close()
				return lockErr
			}
			admitter, admitErr := service.resourceAdmitter()
			if admitErr == nil {
				admitErr = admitter.RejectReservation(ctx, admission, document.Revision, intent.JobID, "resource_create_not_started")
			}
			releaseErr := admission.Release()
			service.Close()
			if admitErr != nil || releaseErr != nil {
				return errors.Join(admitErr, releaseErr)
			}
			continue
		}
		if err != nil || fresh.Phase != operations.PhaseLocalIntent {
			service.Close()
			if err != nil {
				return err
			}
			return fmt.Errorf("journal-less resource create authority changed")
		}
		installation, err := installationFromDocument(document)
		if err != nil {
			service.Close()
			return err
		}
		state, err := service.safety.Read()
		if err != nil {
			service.Close()
			return err
		}
		_, ownedErr := service.ownership.Read(intent.SafetyBinding.ResourceID)
		if findNormalResource(installation, intent.SafetyBinding.ResourceID) != nil || findSafetyResource(state, intent.SafetyBinding.ResourceID) != nil || ownedErr == nil {
			service.Close()
			return fmt.Errorf("journal-less resource create %s has residual authority", intent.SafetyBinding.ResourceID)
		}
		if !errors.Is(ownedErr, os.ErrNotExist) {
			service.Close()
			return ownedErr
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			service.Close()
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, "installation", service.manager)
		if err != nil {
			mutationSet.Close()
			service.Close()
			return err
		}
		admitter, err := service.resourceAdmitter()
		if err == nil {
			_, err = admitter.Complete(ctx, mutation, exposure, document.Revision, intent.JobID, "no_effect", nil, []jobs.Postcondition{{Kind: "resource_create_not_committed", Status: jobs.PostconditionVerified, Identity: intent.SafetyBinding.ResourceID}}, "")
		}
		err = errors.Join(err, operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

func reconcileResourceCreate(ctx context.Context, path string) (result error) {
	removeJournal := false
	journal, err := readCreateJournal(path)
	if err != nil {
		return err
	}
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		_ = service.Close()
		return err
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "installation", service.manager)
	if err != nil {
		_ = mutationSet.Close()
		_ = service.Close()
		return err
	}
	defer func() {
		cleanupErr := errors.Join(operations.ReleaseExposure(mutation, exposure), mutationSet.Close(), service.Close())
		result = errors.Join(result, cleanupErr)
		if result == nil && removeJournal {
			result = removeCreateJournal(path)
		}
	}()

	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	intent, err := operations.FindResourceCreateAuthority(document, journal.JobID, journal.ResourceID)
	if err != nil {
		return err
	}
	job, err := jobs.LoadEntries(document.Entries, journal.JobID)
	if err != nil {
		return err
	}
	if intent.Phase == operations.PhaseLocalIntent && job.Status != jobs.StatusRunning || intent.Phase == operations.PhaseTerminal && job.Status != jobs.StatusTerminal {
		return fmt.Errorf("resource create journal job phase is inconsistent")
	}
	state, err := service.safety.ReadForRecovery(exposure)
	if err != nil {
		return err
	}
	installation, err := installationFromDocument(document)
	if err != nil {
		return err
	}
	normalResource := findNormalResource(installation, journal.ResourceID)
	safetyResource := findSafetyResource(state, journal.ResourceID)
	owned, ownedErr := service.ownership.Read(journal.ResourceID)
	ownedPresent := ownedErr == nil
	if ownedErr != nil && !errors.Is(ownedErr, os.ErrNotExist) {
		return fmt.Errorf("read resource create ownership authority: %w", ownedErr)
	}

	if !ownedPresent {
		if journal.Phase != "prepared" || safetyResource != nil || normalResource != nil {
			return fmt.Errorf("resource create journal %s has contradictory residual authority", journal.ResourceID)
		}
		if intent.Phase == operations.PhaseTerminal {
			if !exactNoEffectResourceCreate(job, journal) {
				return fmt.Errorf("resource create no-effect result is inconsistent")
			}
			removeJournal = true
			return nil
		}
		admitter, err := service.resourceAdmitter()
		if err != nil {
			return err
		}
		if _, err := admitter.Complete(ctx, mutation, exposure, document.Revision, journal.JobID, "no_effect", nil, []jobs.Postcondition{{Kind: "resource_create_not_committed", Status: jobs.PostconditionVerified, Identity: journal.ResourceID}}, ""); err != nil {
			return fmt.Errorf("resource create exact no-effect recovery failed: %w", err)
		}
		removeJournal = true
		return nil
	}

	if intent.Phase != operations.PhaseLocalIntent && normalResource == nil {
		return fmt.Errorf("terminal resource create is missing normal authority")
	}
	if !exactCreateOwnership(owned, journal.Resource) {
		return fmt.Errorf("resource create ownership authority differs from journal")
	}
	switch journal.Phase {
	case "prepared":
		if safetyResource != nil || normalResource != nil {
			return fmt.Errorf("prepared resource create has later committed authority")
		}
		journal.Phase = "ownership_committed"
		journal.OwnershipDigest = owned.Checksum
		if err := writeCreateJournal(ctx, journal); err != nil {
			return err
		}
	case "ownership_committed", "safety_committed":
		if journal.OwnershipDigest != owned.Checksum {
			return fmt.Errorf("resource create ownership digest changed")
		}
	}

	if safetyResource == nil {
		if journal.Phase != "ownership_committed" || normalResource != nil {
			return fmt.Errorf("resource create safety authority is missing out of phase")
		}
		next := state
		next.Revision++
		next.Resources = append(append([]safety.ResourceSafety(nil), state.Resources...), initialResourceSafety(journal.ResourceID, owned.Checksum))
		if _, err := service.safety.Commit(ctx, exposure, safety.RoleResourceCreate, state.Revision, next, safety.TransitionProof{}); err != nil {
			return err
		}
		state = next
		safetyResource = findSafetyResource(state, journal.ResourceID)
	} else if !reflect.DeepEqual(*safetyResource, initialResourceSafety(journal.ResourceID, owned.Checksum)) {
		return fmt.Errorf("resource create safety authority differs from journal")
	}
	if journal.Phase == "ownership_committed" {
		if normalResource != nil {
			return fmt.Errorf("resource create normal authority committed before safety journal")
		}
		journal.Phase = "safety_committed"
		if err := writeCreateJournal(ctx, journal); err != nil {
			return err
		}
	}

	if normalResource == nil {
		if intent.Phase != operations.PhaseLocalIntent || job.Status != jobs.StatusRunning {
			return fmt.Errorf("resource create cannot roll normal authority forward")
		}
		admitter, err := service.resourceAdmitter()
		if err != nil {
			return err
		}
		if err := admitter.CommitResourceCreate(ctx, mutation, exposure, document.Revision, journal.JobID, operations.ResourceCreateCommit{Resource: journal.Resource}); err != nil {
			return err
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
		installation, err = installationFromDocument(document)
		if err != nil {
			return err
		}
		normalResource = findNormalResource(installation, journal.ResourceID)
	}
	if intent.Phase == operations.PhaseTerminal {
		if !exactSuccessfulResourceCreate(job, normalResource, journal) {
			return fmt.Errorf("terminal resource create authority differs from journal")
		}
		removeJournal = true
		return nil
	}
	if normalResource == nil || !reflect.DeepEqual(*normalResource, journal.Resource) {
		return fmt.Errorf("running resource create normal authority differs from journal")
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return err
	}
	if _, err := admitter.Complete(ctx, mutation, exposure, document.Revision, journal.JobID, "complete", nil, []jobs.Postcondition{{Kind: "resource_persisted_unpublished_stopped", Status: jobs.PostconditionVerified, Identity: journal.Resource.CurrentConfigDigest}}, ""); err != nil {
		return err
	}
	removeJournal = true
	return nil
}

func validCreateDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func installationFromDocument(document persist.Document) (domain.Installation, error) {
	raw, present := document.Entries["installations/current"]
	if !present {
		return domain.Installation{}, fmt.Errorf("installation authority is missing")
	}
	return domain.DecodeInstallation(raw)
}

func findNormalResource(installation domain.Installation, resourceID string) *domain.AppResource {
	for index := range installation.Resources {
		if installation.Resources[index].ID == resourceID {
			return &installation.Resources[index]
		}
	}
	return nil
}

func findSafetyResource(state safety.State, resourceID string) *safety.ResourceSafety {
	for index := range state.Resources {
		if state.Resources[index].ResourceID == resourceID {
			return &state.Resources[index]
		}
	}
	return nil
}

func initialResourceSafety(resourceID, ownershipDigest string) safety.ResourceSafety {
	return safety.ResourceSafety{ResourceID: resourceID, GenerationSequence: 1, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: ownershipDigest, StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 1, Reason: "initial"}}
}

func exactCreateOwnership(owned ownership.Record, created domain.AppResource) bool {
	paths, err := resource.DerivePaths(created.ID)
	if err != nil || owned.SchemaVersion != ownership.SchemaVersion || owned.Revision != 1 || owned.ResourceID != created.ID || owned.State != ownership.Owned || len(owned.Listeners) != 0 || len(owned.Paths) != 1 {
		return false
	}
	path := owned.Paths[0]
	return path.Kind == ownership.PathService && path.Path == paths.ResourceRoot && path.IdentityDigest == ownership.PathIdentity(created.ID, ownership.PathService, paths.ResourceRoot)
}

func exactNoEffectResourceCreate(job jobs.Record, journal ResourceCreateJournal) bool {
	return job.Status == jobs.StatusTerminal && job.Result == jobs.ResultFailed && len(job.Postconditions) == 1 && job.Postconditions[0] == (jobs.Postcondition{Kind: "resource_create_not_committed", Status: jobs.PostconditionVerified, Identity: journal.ResourceID})
}

func exactSuccessfulResourceCreate(job jobs.Record, normal *domain.AppResource, journal ResourceCreateJournal) bool {
	if job.Status != jobs.StatusTerminal || job.Result != jobs.ResultSucceeded || normal == nil || len(job.Postconditions) != 1 || job.Postconditions[0] != (jobs.Postcondition{Kind: "resource_persisted_unpublished_stopped", Status: jobs.PostconditionVerified, Identity: journal.Resource.CurrentConfigDigest}) {
		return false
	}
	expected := journal.Resource
	expected.PublicationRecord.LastOperation = domain.OperationResourceCreate
	expected.PublicationRecord.LastOperationResult = domain.OperationSucceeded
	expected.PublicationRecord.LastJobID = journal.JobID
	return reflect.DeepEqual(*normal, expected)
}

func removeCreateJournal(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type ResourceExecution struct {
	Service     *FixedService
	Admitter    *operations.Admitter
	MutationSet *operations.MutationSet
	Mutation    *operations.MutationLease
	Exposure    *locks.Lease
	JobID       string
	Revision    uint64
	Resource    domain.AppResource
	Prior       *domain.AppResource
}

func (s *FixedService) resourceAdmitter() (*operations.Admitter, error) {
	table, err := operations.NewBranchTable([]operations.ResultBranch{{Name: "complete", Result: jobs.ResultSucceeded, Postcondition: jobs.PostconditionVerified}, {Name: "no_effect", Result: jobs.ResultFailed, Postcondition: jobs.PostconditionVerified}, {Name: "known_residual", Result: jobs.ResultPartial, Postcondition: jobs.PostconditionKnown}, {Name: "executor_died", Result: jobs.ResultInterrupted, Postcondition: jobs.PostconditionKnown}, {Name: "source_unknown", Result: jobs.ResultUnknown, Postcondition: jobs.PostconditionUnobserved}})
	if err != nil {
		return nil, err
	}
	registry, err := operations.NewRegistry([]operations.Registration{{Operation: operations.ResourceCreate, Owner: "application.resource", Results: table}, {Operation: operations.ResourceUpdate, Owner: "application.resource", Results: table}, {Operation: operations.ProcessStart, Owner: "application.process", Results: table}, {Operation: operations.ProcessStop, Owner: "application.process", Results: table}})
	if err != nil {
		return nil, err
	}
	return operations.NewAdmitter(s.normal, s.safety, operations.Options{Bindings: directBinding{}, Confirmation: directConfirmation{}, Registry: registry})
}

type directBinding struct{}

func (directBinding) CurrentBinding(operation operations.Type, target string, _ time.Time) (plans.Binding, error) {
	return plans.Binding{Operation: string(operation), Target: plans.Target{Kind: plans.TargetKind(strings.Split(target, "/")[0])}}, nil
}

type directConfirmation struct{}

func (directConfirmation) VerifyConfirmation(plans.Plan, string, string, time.Time) (string, error) {
	return "", fmt.Errorf("direct UI action has no Plan")
}

func BeginResourceCreate(ctx context.Context, actor Actor, candidate domain.AppResource) (*ResourceExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*ResourceExecution, error) { _ = service.Close(); return nil, cause }
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	document, err := service.Normal().Read()
	if err != nil {
		return fail(err)
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fail(fmt.Errorf("installation authority is missing"))
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return fail(err)
	}
	if err := resource.ValidateCreate(installation, candidate); err != nil {
		return fail(err)
	}
	if _, err := service.SafetyState(); err != nil {
		return fail(err)
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return fail(err)
	}
	admission, err := service.Manager().Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ResourceCreate, Target: "installation", ActorIdentity: authority, Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{ResourceID: candidate.ID}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "installation", service.Manager())
	if err != nil {
		mutationSet.Close()
		return fail(err)
	}
	fresh, err := service.Normal().Read()
	if err != nil || fresh.Revision != document.Revision+1 {
		operations.ReleaseExposure(mutation, exposure)
		mutationSet.Close()
		return fail(fmt.Errorf("resource creation authority changed"))
	}
	intent, err := admitter.BeginUI(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		operations.ReleaseExposure(mutation, exposure)
		mutationSet.Close()
		return fail(err)
	}
	return &ResourceExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: intent.IntentGeneration, Resource: candidate}, nil
}

func BeginResourceUpdate(ctx context.Context, actor Actor, candidate domain.AppResource, knownSecretDigests map[string]struct{}) (*ResourceExecution, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*ResourceExecution, error) { _ = service.Close(); return nil, cause }
	authority, err := actorAuthority(actor)
	if err != nil {
		return fail(err)
	}
	document, err := service.Normal().Read()
	if err != nil {
		return fail(err)
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return fail(fmt.Errorf("installation authority is missing"))
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return fail(err)
	}
	var prior *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == candidate.ID {
			prior = &installation.Resources[index]
			break
		}
	}
	if prior != nil && prior.ManagedProcess != nil && prior.ManagedProcess.Requested == domain.ProcessRequestedRunning {
		return fail(fmt.Errorf("stop managed process before resource update"))
	}
	candidate, err = resource.PrepareUpdate(installation, candidate)
	if err != nil {
		return fail(err)
	}
	if prior.ManagedProcess.Applied != nil {
		relay := candidate.Target.LocalHTTP != nil && candidate.Target.LocalHTTP.EndpointKind == domain.LocalEndpointRelayUnix
		accounts, accountErr := identity.ResourceAccounts(installation.InstallationID, candidate.ID, relay)
		if accountErr != nil {
			return fail(accountErr)
		}
		present, identities, inspectErr := identity.InspectResourceAccountFiles(accounts, "/etc/passwd", "/etc/group", "/etc/shadow")
		if inspectErr != nil || !present || len(identities) == 0 {
			return fail(errors.Join(inspectErr, fmt.Errorf("explicit stopped reapply requires exact existing resource identity")))
		}
		evidence, evidenceErr := resource.ValidateServiceReferences(candidate.ManagedProcess.Service, identities[0].UID, knownSecretDigests)
		if evidenceErr != nil {
			return fail(evidenceErr)
		}
		candidate.ManagedProcess.ReferenceBinding = referenceBinding(evidence)
		candidate.CurrentConfigDigest = ""
		digest, digestErr := resource.ConfigDigest(candidate)
		if digestErr != nil {
			return fail(digestErr)
		}
		candidate.CurrentConfigDigest = digest
		next := installation
		next.Resources = append([]domain.AppResource(nil), installation.Resources...)
		for index := range next.Resources {
			if next.Resources[index].ID == candidate.ID {
				next.Resources[index] = candidate
			}
		}
		if validateErr := domain.ValidateInstallation(next); validateErr != nil {
			return fail(validateErr)
		}
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return fail(err)
	}
	admission, err := service.Manager().Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return fail(err)
	}
	job, err := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ResourceUpdate, Target: "resource/" + candidate.ID, ActorIdentity: authority, Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{ResourceID: candidate.ID, CandidateDigest: candidate.CurrentConfigDigest, CandidateBundle: prior.CurrentConfigDigest}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if err != nil || releaseErr != nil {
		return fail(errors.Join(err, releaseErr))
	}
	mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.Manager().Authority()})
	if err != nil {
		return fail(err)
	}
	mutation, exposure, err := mutationSet.AcquireExposure(ctx, "resource/"+candidate.ID, service.Manager())
	if err != nil {
		mutationSet.Close()
		return fail(err)
	}
	fresh, err := service.Normal().Read()
	if err != nil || fresh.Revision != document.Revision+1 {
		operations.ReleaseExposure(mutation, exposure)
		mutationSet.Close()
		return fail(fmt.Errorf("resource update authority changed"))
	}
	intent, err := admitter.BeginUI(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1})
	if err != nil {
		operations.ReleaseExposure(mutation, exposure)
		mutationSet.Close()
		return fail(err)
	}
	priorCopy := *prior
	return &ResourceExecution{Service: service, Admitter: admitter, MutationSet: mutationSet, Mutation: mutation, Exposure: exposure, JobID: job.ID, Revision: intent.IntentGeneration, Resource: candidate, Prior: &priorCopy}, nil
}

func referenceBinding(evidence resource.ReferenceEvidence) *domain.ProcessReferenceBinding {
	return &domain.ProcessReferenceBinding{ExecutableDigest: evidence.ExecutableDigest, WorkingDirectoryIdentity: evidence.WorkingDirectoryIdentity, EnvironmentFingerprint: evidence.EnvironmentFingerprint, WritePathIdentities: append([]string(nil), evidence.WritePathIdentities...)}
}

func (execution *ResourceExecution) CommitUpdate(ctx context.Context) (jobs.Record, error) {
	if execution == nil || execution.Prior == nil {
		return jobs.Record{}, fmt.Errorf("resource update execution is inactive")
	}
	if err := execution.Admitter.ValidateActive(ctx, execution.Mutation, execution.Exposure, execution.JobID); err != nil {
		return jobs.Record{}, err
	}
	journal := ResourceUpdateJournal{SchemaVersion: resourceUpdateJournalSchema, JobID: execution.JobID, ResourceID: execution.Resource.ID, Prior: *execution.Prior, Candidate: execution.Resource}
	if err := writeResourceUpdateJournal(ctx, journal); err != nil {
		_, terminalErr := execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "no_effect", nil, []jobs.Postcondition{{Kind: "resource_update_not_committed", Status: jobs.PostconditionVerified, Identity: execution.Resource.ID}}, "")
		closeErr := execution.Close()
		return jobs.Record{}, errors.Join(err, terminalErr, closeErr)
	}
	if err := execution.Admitter.CommitResourceUpdate(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, execution.Resource); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	job, err := execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "complete", nil, []jobs.Postcondition{{Kind: "resource_config_saved", Status: jobs.PostconditionVerified, Identity: execution.Resource.CurrentConfigDigest}}, "")
	closeErr := execution.Close()
	if err == nil && closeErr == nil {
		err = removeJournal(resourceUpdateJournalPath(execution.Resource.ID))
	}
	return job, errors.Join(err, closeErr)
}

func (execution *ResourceExecution) CommitCreate(ctx context.Context) (jobs.Record, error) {
	if execution == nil || execution.Resource.ID == "" {
		return jobs.Record{}, fmt.Errorf("resource creation execution is inactive")
	}
	if err := execution.Admitter.ValidateActive(ctx, execution.Mutation, execution.Exposure, execution.JobID); err != nil {
		return jobs.Record{}, err
	}
	journal := ResourceCreateJournal{SchemaVersion: "lanpanel.resource.create.v1", JobID: execution.JobID, ResourceID: execution.Resource.ID, Resource: execution.Resource, Phase: "prepared"}
	if err := writeCreateJournal(ctx, journal); err != nil {
		return jobs.Record{}, err
	}
	paths, err := resource.DerivePaths(execution.Resource.ID)
	if err != nil {
		return jobs.Record{}, err
	}
	record := ownership.Record{Revision: 1, ResourceID: execution.Resource.ID, State: ownership.Owned, Paths: []ownership.OwnedPath{{Kind: ownership.PathService, Path: paths.ResourceRoot, IdentityDigest: ownership.PathIdentity(execution.Resource.ID, ownership.PathService, paths.ResourceRoot)}}}
	if _, err := execution.Service.ownership.Write(ctx, execution.Exposure, ownership.ActivationWriter, 0, record); err != nil {
		return jobs.Record{}, err
	}
	persisted, err := execution.Service.ownership.Read(execution.Resource.ID)
	if err != nil {
		return jobs.Record{}, err
	}
	journal.Phase = "ownership_committed"
	journal.OwnershipDigest = persisted.Checksum
	if err := writeCreateJournal(ctx, journal); err != nil {
		return jobs.Record{}, err
	}
	state, err := execution.Service.safety.ReadForRecovery(execution.Exposure)
	if err != nil {
		return jobs.Record{}, err
	}
	next := state
	next.Revision++
	next.Resources = append(append([]safety.ResourceSafety(nil), state.Resources...), safety.ResourceSafety{ResourceID: execution.Resource.ID, GenerationSequence: 1, State: safety.ResourceActive, Ownership: safety.OwnershipOwned, OwnershipDigest: persisted.Checksum, StickyUnpublished: &safety.GenerationMarker{Kind: safety.MarkerStickyUnpublished, Generation: 1, Reason: "initial"}})
	if _, err := execution.Service.safety.Commit(ctx, execution.Exposure, safety.RoleResourceCreate, state.Revision, next, safety.TransitionProof{}); err != nil {
		return jobs.Record{}, err
	}
	journal.Phase = "safety_committed"
	if err := writeCreateJournal(ctx, journal); err != nil {
		return jobs.Record{}, err
	}
	if err := execution.Admitter.CommitResourceCreate(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, operations.ResourceCreateCommit{Resource: execution.Resource}); err != nil {
		return jobs.Record{}, err
	}
	execution.Revision++
	job, err := execution.Admitter.Complete(ctx, execution.Mutation, execution.Exposure, execution.Revision, execution.JobID, "complete", nil, []jobs.Postcondition{{Kind: "resource_persisted_unpublished_stopped", Status: jobs.PostconditionVerified, Identity: execution.Resource.CurrentConfigDigest}}, "")
	closeErr := execution.Close()
	if err == nil && closeErr == nil {
		err = removeCreateJournal(resourceCreateJournalPath(execution.Resource.ID))
	}
	return job, errors.Join(err, closeErr)
}
func (execution *ResourceExecution) Close() error {
	if execution == nil {
		return nil
	}
	err := operations.ReleaseExposure(execution.Mutation, execution.Exposure)
	if execution.MutationSet != nil {
		err = errors.Join(err, execution.MutationSet.Close())
	}
	if execution.Service != nil {
		err = errors.Join(err, execution.Service.Close())
	}
	execution.Mutation = nil
	execution.Exposure = nil
	return err
}

func DigestPayload(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
