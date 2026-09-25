package operations

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"lanpanel/internal/plans"
	"slices"
	"time"
)

func validateClosedRecoveryGenerations(document persist.Document, generations map[string]uint64) error {
	installation, err := loadInstallationEntries(document.Entries)
	if err != nil {
		return err
	}
	if len(generations) != len(installation.Resources) {
		return fmt.Errorf("closed recovery generation inventory does not exactly cover installation Apps")
	}
	expected := make(map[string]struct{}, len(installation.Resources))
	for _, resource := range installation.Resources {
		if !validIdentityRef(resource.ID) {
			return fmt.Errorf("closed recovery installation App identity is invalid")
		}
		if _, duplicate := expected[resource.ID]; duplicate {
			return fmt.Errorf("closed recovery installation App identity is duplicated")
		}
		expected[resource.ID] = struct{}{}
	}
	for id, generation := range generations {
		if !validIdentityRef(id) || generation == 0 {
			return fmt.Errorf("closed recovery generation is invalid")
		}
		if _, present := expected[id]; !present {
			return fmt.Errorf("closed recovery generation has an extra App identity")
		}
	}
	return nil
}

// RecoverClosedInstallation durably projects already-proven closed runtime
// into normal state. It is resumable at each normal transaction and grants no
// authority to start a process or reopen ingress.
func RecoverClosedInstallation(ctx context.Context, normal *persist.Store, exposure *locks.Lease, generations map[string]uint64, modifiedPaths []string, closureDigest, safetyDigest string, now time.Time, random io.Reader) error {
	if normal == nil || exposure == nil || exposure.Authority() != normal.LockAuthority() || !exposure.Holds(locks.Exposure) || len(generations) > maximumJournalResources || !exactDigest(closureDigest) || !exactDigest(safetyDigest) || now.IsZero() {
		return fmt.Errorf("closed recovery authority is incomplete")
	}
	if random == nil {
		random = rand.Reader
	}
	document, err := normal.Read()
	if err != nil {
		return err
	}
	if err := validateClosedRecoveryGenerations(document, generations); err != nil {
		return err
	}
	if changed, err := terminalizeInterruptedContractions(ctx, normal, exposure, document, nil, closureDigest, now); err != nil {
		return err
	} else if changed {
		document, err = normal.Read()
		if err != nil {
			return err
		}
	}
	intent, found, err := pendingClosedRecovery(document, closureDigest, safetyDigest)
	if err != nil {
		return err
	}
	if !found {
		record, err := jobs.NewReserved(jobs.Spec{Operation: string(StartupContraction), Target: "installation", ActorIdentity: "startup-recovery"}, now, random)
		if err != nil {
			return err
		}
		reserved := Reservation{SchemaVersion: "lanpanel.operation.reservation.v1", JobID: record.ID, AdmissionSource: AdmissionStartup, Operation: StartupContraction, Target: "installation", Phase: PhaseReserved, SafetyDigest: safetyDigest, SafetyBinding: SafetyBinding{}, CreatedAt: now}
		_, _, err = normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
			if err := jobs.Put(transaction, record); err != nil {
				return err
			}
			raw, err := persist.EncodeEntry(reserved)
			if err != nil {
				return err
			}
			return transaction.Create(reservationKey(record.ID), raw)
		})
		if err != nil {
			return err
		}
		document, err = normal.Read()
		if err != nil {
			return err
		}
		_, _, err = normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
			freshRecord, err := jobs.Load(transaction, record.ID)
			if err != nil {
				return err
			}
			freshRecord, err = jobs.Start(freshRecord)
			if err != nil {
				return err
			}
			if err := jobs.Replace(transaction, freshRecord); err != nil {
				return err
			}
			fresh, err := loadReservation(transaction, record.ID)
			if err != nil || fresh.Phase != PhaseReserved {
				return fmt.Errorf("closed recovery reservation changed: %w", err)
			}
			fresh.Phase = PhaseLocalIntent
			fresh.IntentGeneration = document.Revision + 1
			fresh.Consumption = &ConsumptionSnapshot{Source: AdmissionStartup, ConfirmationDigest: closureDigest, ConfirmedAt: now, SafetyDigest: safetyDigest}
			raw, err := persist.EncodeEntry(fresh)
			if err != nil {
				return err
			}
			return transaction.Replace(reservationKey(record.ID), raw)
		})
		if err != nil {
			return err
		}
		document, err = normal.Read()
		if err != nil {
			return err
		}
		intent, _, err = pendingClosedRecovery(document, closureDigest, safetyDigest)
		if err != nil {
			return err
		}
	}
	if intent.Phase == PhaseReserved {
		_, _, err = normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
			record, err := jobs.Load(transaction, intent.JobID)
			if err != nil {
				return err
			}
			record, err = jobs.Start(record)
			if err != nil {
				return err
			}
			if err := jobs.Replace(transaction, record); err != nil {
				return err
			}
			fresh, err := loadReservation(transaction, intent.JobID)
			if err != nil || fresh.Phase != PhaseReserved {
				return fmt.Errorf("closed recovery reservation changed: %w", err)
			}
			fresh.Phase = PhaseLocalIntent
			fresh.IntentGeneration = document.Revision + 1
			fresh.Consumption = &ConsumptionSnapshot{Source: AdmissionStartup, ConfirmationDigest: closureDigest, ConfirmedAt: now, SafetyDigest: safetyDigest}
			raw, err := persist.EncodeEntry(fresh)
			if err != nil {
				return err
			}
			return transaction.Replace(reservationKey(fresh.JobID), raw)
		})
		if err != nil {
			return err
		}
		document, err = normal.Read()
		if err != nil {
			return err
		}
		intent, _, err = pendingClosedRecovery(document, closureDigest, safetyDigest)
		if err != nil {
			return err
		}
	}
	if intent.Phase == PhaseLocalIntent && intent.ContractionDigest == "" {
		_, _, err = normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
			fresh, err := loadReservation(transaction, intent.JobID)
			if err != nil {
				return err
			}
			if fresh.Phase != PhaseLocalIntent || fresh.ContractionDigest != "" {
				return fmt.Errorf("closed recovery intent changed")
			}
			installation, err := loadInstallation(transaction)
			if err != nil {
				return err
			}
			remaining := make(map[string]uint64, len(generations))
			for id, generation := range generations {
				if !validIdentityRef(id) || generation == 0 {
					return fmt.Errorf("closed recovery generation is invalid")
				}
				remaining[id] = generation
			}
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				generation, ok := remaining[resource.ID]
				if !ok {
					continue
				}
				if generation < resource.PublicationRecord.UnpublishedGeneration {
					return fmt.Errorf("closed recovery generation regressed")
				}
				if generation == resource.PublicationRecord.UnpublishedGeneration {
					if resource.PublicationRecord.State != domain.PublicationUnpublished {
						return fmt.Errorf("equal closed recovery generation is not unpublished")
					}
					existing := resource.PublicationRecord.ContractionIntent
					if existing != nil && (existing.JobID != fresh.JobID || existing.Operation != string(fresh.Operation) || existing.Generation != generation || existing.ClosureAuthorityDigest != closureDigest) {
						return fmt.Errorf("equal closed recovery generation has conflicting contraction authority")
					}
					if existing == nil {
						resource.PublicationRecord.ContractionIntent = &domain.ContractionIntent{JobID: fresh.JobID, Operation: string(fresh.Operation), Generation: generation, ClosureAuthorityDigest: closureDigest}
					}
					resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: now.UTC().Format(time.RFC3339), Reason: "access_closed"}
					delete(remaining, resource.ID)
					continue
				}
				prior := resource.PublicationRecord.LastAppliedBundle
				var candidate *domain.PublicationBundle
				if resource.PublicationRecord.ActivationIntent != nil {
					value := resource.PublicationRecord.ActivationIntent.Candidate
					candidate = &value
					if resource.PublicationRecord.ActivationIntent.Prior != nil {
						prior = resource.PublicationRecord.ActivationIntent.Prior
					}
				}
				resource.PublicationRecord.State = domain.PublicationUnpublished
				resource.PublicationRecord.UnpublishedGeneration = generation
				resource.PublicationRecord.ActivationIntent = nil
				resource.PublicationRecord.RuntimeObservation = &domain.RuntimeObservation{Status: domain.RuntimeDegraded, ObservedAt: now.UTC().Format(time.RFC3339), Reason: "access_closed"}
				resource.PublicationRecord.ContractionIntent = &domain.ContractionIntent{JobID: fresh.JobID, Operation: string(fresh.Operation), Generation: generation, ClosureAuthorityDigest: closureDigest, Prior: cloneBundle(prior), Candidate: cloneBundle(candidate)}
				delete(remaining, resource.ID)
			}
			if len(remaining) != 0 {
				return fmt.Errorf("closed recovery App identity is missing")
			}
			rawInstallation, err := persist.EncodeEntry(installation)
			if err != nil {
				return err
			}
			if err := transaction.Replace("installations/current", rawInstallation); err != nil {
				return err
			}
			fresh.ContractionDigest = closureDigest
			rawIntent, err := persist.EncodeEntry(fresh)
			if err != nil {
				return err
			}
			return transaction.Replace(reservationKey(fresh.JobID), rawIntent)
		})
		if err != nil {
			return err
		}
		document, err = normal.Read()
		if err != nil {
			return err
		}
		intent, _, err = pendingClosedRecovery(document, closureDigest, safetyDigest)
		if err != nil {
			return err
		}
	}
	if intent.Phase == PhaseLocalIntent && intent.ContractionDigest == closureDigest {
		_, _, err = normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
			fresh, err := loadReservation(transaction, intent.JobID)
			if err != nil {
				return err
			}
			if fresh.Phase != PhaseLocalIntent || fresh.ContractionDigest != closureDigest {
				return fmt.Errorf("closed recovery terminal authority changed")
			}
			installation, err := loadInstallation(transaction)
			if err != nil {
				return err
			}
			affected := 0
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				contraction := resource.PublicationRecord.ContractionIntent
				if contraction == nil || contraction.JobID != fresh.JobID {
					continue
				}
				resource.PublicationRecord.ContractionIntent = nil
				resource.PublicationRecord.LastOperation = domain.OperationUnpublish
				resource.PublicationRecord.LastOperationResult = domain.OperationSucceeded
				resource.PublicationRecord.LastJobID = fresh.JobID
				affected++
			}
			if affected != len(generations) {
				return fmt.Errorf("closed recovery terminal App inventory changed")
			}
			rawInstallation, err := persist.EncodeEntry(installation)
			if err != nil {
				return err
			}
			if err := transaction.Replace("installations/current", rawInstallation); err != nil {
				return err
			}
			record, err := jobs.Load(transaction, fresh.JobID)
			if err != nil {
				return err
			}
			record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, ModifiedPaths: append([]string(nil), modifiedPaths...), Postconditions: []jobs.Postcondition{{Kind: "access_closed", Status: jobs.PostconditionVerified, Identity: closureDigest}}}, now)
			if err != nil {
				return err
			}
			if err := jobs.Replace(transaction, record); err != nil {
				return err
			}
			fresh.Phase = PhaseTerminal
			rawIntent, err := persist.EncodeEntry(fresh)
			if err != nil {
				return err
			}
			return transaction.Replace(reservationKey(fresh.JobID), rawIntent)
		})
		return err
	}
	if intent.Phase == PhaseTerminal {
		record, err := jobs.LoadEntries(document.Entries, intent.JobID)
		if err != nil {
			return err
		}
		expectedPaths := append([]string(nil), modifiedPaths...)
		slices.Sort(expectedPaths)
		expectedPaths = slices.Compact(expectedPaths)
		if len(expectedPaths) == 0 {
			expectedPaths = append([]string(nil), record.ModifiedPaths...)
		}
		if record.Status != jobs.StatusTerminal || record.Result != jobs.ResultSucceeded || len(record.Postconditions) != 1 || record.Postconditions[0].Kind != "access_closed" || record.Postconditions[0].Status != jobs.PostconditionVerified || record.Postconditions[0].Identity != closureDigest || !slices.Equal(record.ModifiedPaths, expectedPaths) {
			return fmt.Errorf("closed recovery terminal evidence changed")
		}
		return nil
	}
	return fmt.Errorf("closed recovery is in an unsupported phase")
}

// ErrContractionReceiptUnbound means a full startup contraction must own the receipt.
var ErrContractionReceiptUnbound = errors.New("contraction receipt has no exact normal job binding")

func TerminalizeContractionReceipt(ctx context.Context, normal *persist.Store, exposure *locks.Lease, resourceIDs, modifiedPaths []string, closureDigest string, now time.Time) error {
	if normal == nil || exposure == nil || exposure.Authority() != normal.LockAuthority() || !exposure.Holds(locks.Exposure) || len(resourceIDs) == 0 || len(resourceIDs) > maximumJournalResources || !slices.IsSorted(resourceIDs) || !exactDigest(closureDigest) || now.IsZero() {
		return fmt.Errorf("contraction receipt terminal authority is incomplete")
	}
	document, err := normal.Read()
	if err != nil {
		return err
	}
	installation, err := loadInstallationEntries(document.Entries)
	if err != nil {
		return err
	}
	remaining := make(map[string]bool, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		if !validIdentityRef(resourceID) || remaining[resourceID] {
			return fmt.Errorf("contraction receipt resource scope is invalid")
		}
		remaining[resourceID] = true
	}
	jobID := ""
	for _, resource := range installation.Resources {
		if !remaining[resource.ID] {
			continue
		}
		candidateJobID := ""
		if resource.PublicationRecord.ContractionIntent != nil {
			candidateJobID = resource.PublicationRecord.ContractionIntent.JobID
		} else if resource.PublicationRecord.ActivationIntent != nil {
			candidateJobID = resource.PublicationRecord.ActivationIntent.JobID
		}
		if candidateJobID == "" {
			return ErrContractionReceiptUnbound
		}
		if jobID != "" && jobID != candidateJobID {
			return fmt.Errorf("contraction receipt binds multiple normal jobs")
		}
		jobID = candidateJobID
		delete(remaining, resource.ID)
	}
	if len(remaining) != 0 || jobID == "" {
		return ErrContractionReceiptUnbound
	}
	intent, err := loadReservationEntries(document.Entries, jobID)
	if err != nil {
		return err
	}
	switch intent.Operation {
	case CloseAll:
		if intent.Target != "installation" {
			return fmt.Errorf("close-all receipt target changed")
		}
	case Unpublish, CertificateExpiry, Publish:
		if len(resourceIDs) != 1 || intent.Target != "resource/"+resourceIDs[0] {
			return fmt.Errorf("selective contraction receipt target changed")
		}
	default:
		return fmt.Errorf("contraction receipt operation is unsupported")
	}
	expectedPaths := append([]string(nil), modifiedPaths...)
	slices.Sort(expectedPaths)
	expectedPaths = slices.Compact(expectedPaths)
	if intent.Phase == PhaseTerminal {
		record, err := jobs.LoadEntries(document.Entries, jobID)
		if err != nil || record.Status != jobs.StatusTerminal || !slices.Equal(record.ModifiedPaths, expectedPaths) {
			return errors.Join(err, fmt.Errorf("terminal contraction receipt job evidence changed"))
		}
		return nil
	}
	changed, err := terminalizeInterruptedContractions(ctx, normal, exposure, document, map[string][]string{jobID: expectedPaths}, closureDigest, now)
	if err != nil || !changed {
		return errors.Join(err, fmt.Errorf("contraction receipt did not terminalize its exact job"))
	}
	return nil
}

func terminalizeInterruptedContractions(ctx context.Context, normal *persist.Store, exposure *locks.Lease, document persist.Document, modifiedByJob map[string][]string, closureDigest string, now time.Time) (bool, error) {
	pending := map[string]Reservation{}
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, key[len("intents/"):])
		if err != nil {
			return false, err
		}
		if (intent.Operation == Unpublish || intent.Operation == CloseAll || intent.Operation == Publish || intent.Operation == CertificateExpiry) && intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
			if modifiedByJob != nil {
				if _, selected := modifiedByJob[intent.JobID]; !selected {
					continue
				}
			}
			pending[intent.JobID] = intent
		}
	}
	if len(pending) == 0 {
		return false, nil
	}
	_, _, err := normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
		if err := pruneTerminalGraphs(transaction, maximumTerminalOperationGraphs-len(pending)); err != nil {
			return err
		}
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		for jobID, intent := range pending {
			if intent.Phase == PhaseReserved {
				record, err := jobs.Load(transaction, jobID)
				if err != nil {
					return fmt.Errorf("reserved interrupted contraction job changed: %w", err)
				}
				if record.Status != jobs.StatusReserved {
					return fmt.Errorf("reserved interrupted contraction job changed")
				}
				record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultFailed, Postconditions: []jobs.Postcondition{{Kind: "mutation_not_started", Status: jobs.PostconditionVerified, Identity: jobID}}, ErrorCode: "contraction_authority_failed"}, now)
				if err != nil {
					return err
				}
				if err := jobs.Replace(transaction, record); err != nil {
					return err
				}
				if intent.AdmissionSource == AdmissionPlan {
					if _, err := plans.Reject(transaction, intent.PlanID, jobID, now); err != nil {
						return err
					}
				}
				intent.Phase = PhaseRejected
				raw, err := persist.EncodeEntry(intent)
				if err != nil {
					return err
				}
				if err := transaction.Replace(reservationKey(jobID), raw); err != nil {
					return err
				}
				continue
			}
			retirements := map[int][]domain.GoAccessRetirementIdentity{}
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				if contraction := resource.PublicationRecord.ContractionIntent; contraction != nil && contraction.JobID == jobID && len(contraction.GoAccessRetirements) != 0 {
					retirements[index] = append([]domain.GoAccessRetirementIdentity(nil), contraction.GoAccessRetirements...)
				}
				if activation := resource.PublicationRecord.ActivationIntent; intent.Operation == Publish && activation != nil && activation.JobID == jobID {
					values, retirementErr := goAccessRetirements(activation.Prior, &activation.Candidate)
					if retirementErr != nil {
						return retirementErr
					}
					if len(values) != 0 {
						retirements[index] = values
					}
				}
			}
			result, errorCode, conditionKind := jobs.ResultInterrupted, "activation_contracted", "contraction_interrupted"
			if len(retirements) != 0 {
				result, errorCode, conditionKind = jobs.ResultPartial, "goaccess_stop_failed", "goaccess_retirement_pending"
			}
			record, err := jobs.Load(transaction, jobID)
			if err != nil {
				return err
			}
			if record.Status == jobs.StatusReserved {
				record, err = jobs.Start(record)
				if err != nil {
					return err
				}
			} else if record.Status != jobs.StatusRunning {
				return fmt.Errorf("interrupted contraction job state changed")
			}
			record, err = jobs.Finish(record, jobs.Completion{Result: result, ModifiedPaths: append([]string(nil), modifiedByJob[jobID]...), Postconditions: []jobs.Postcondition{{Kind: conditionKind, Status: jobs.PostconditionKnown, Identity: closureDigest}}, ErrorCode: errorCode}, now)
			if err != nil {
				return err
			}
			if err := jobs.Replace(transaction, record); err != nil {
				return err
			}
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				if values := retirements[index]; len(values) != 0 {
					digest, digestErr := GoAccessRetirementInventoryDigest(values)
					if digestErr != nil {
						return digestErr
					}
					resource.PublicationRecord.PendingGoAccessRetirements = values
					resource.PublicationRecord.GoAccessRetirementSourceJobID = jobID
					resource.PublicationRecord.GoAccessRetirementSourceJournalID = ""
					resource.PublicationRecord.GoAccessRetirementAuthorityDigest = digest
				}
				if intent.Operation == Publish && resource.ID == intent.SafetyBinding.ResourceID {
					if resource.PublicationRecord.ActivationIntent == nil || resource.PublicationRecord.ActivationIntent.JobID != jobID {
						continue
					}
					resource.PublicationRecord.ActivationIntent = nil
					resource.PublicationRecord.State = domain.PublicationUnpublished
					resource.PublicationRecord.LastOperation = domain.OperationPublish
					resource.PublicationRecord.LastOperationResult = domain.OperationResult(result)
					resource.PublicationRecord.LastJobID = jobID
					continue
				}
				contraction := resource.PublicationRecord.ContractionIntent
				if contraction == nil || contraction.JobID != jobID {
					continue
				}
				resource.PublicationRecord.ContractionIntent = nil
				resource.PublicationRecord.LastOperation = contractionOperationCode(intent.Operation)
				resource.PublicationRecord.LastOperationResult = domain.OperationResult(result)
				resource.PublicationRecord.LastJobID = jobID
			}
			for _, key := range transaction.Keys("journals") {
				rawJournal, _ := transaction.Get(key)
				var journal JournalRecord
				if err := decodeStrict(rawJournal, &journal); err != nil {
					return err
				}
				if journal.JobID == jobID && journal.Kind == JournalAppActivation {
					journal.Phase = JournalTerminal
					rawJournal, err = persist.EncodeEntry(journal)
					if err != nil {
						return err
					}
					if err := transaction.Replace(key, rawJournal); err != nil {
						return err
					}
				}
			}
			intent.Phase = PhaseTerminal
			raw, err := persist.EncodeEntry(intent)
			if err != nil {
				return err
			}
			if err := transaction.Replace(reservationKey(jobID), raw); err != nil {
				return err
			}
		}
		raw, err := persist.EncodeEntry(installation)
		if err != nil {
			return err
		}
		return transaction.Replace("installations/current", raw)
	})
	return err == nil, err
}

func pendingClosedRecovery(document persist.Document, closureDigest, safetyDigest string) (Reservation, bool, error) {
	var result Reservation
	found := false
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, key[len("intents/"):])
		if err != nil {
			return Reservation{}, false, err
		}
		if intent.Operation != StartupContraction || intent.Target != "installation" || intent.Phase == PhaseRejected {
			continue
		}
		if intent.Phase == PhaseTerminal {
			if intent.SafetyDigest != safetyDigest || intent.ContractionDigest != closureDigest || intent.Consumption == nil || intent.Consumption.ConfirmationDigest != closureDigest || intent.Consumption.SafetyDigest != safetyDigest {
				continue
			}
		} else if intent.SafetyDigest != safetyDigest || intent.Consumption != nil && (intent.Consumption.ConfirmationDigest != closureDigest || intent.Consumption.SafetyDigest != safetyDigest) {
			return Reservation{}, false, fmt.Errorf("active startup closed-recovery authority changed")
		}
		if found {
			return Reservation{}, false, fmt.Errorf("multiple startup closed-recovery intents")
		}
		result, found = intent, true
	}
	return result, found, nil
}
