package operations

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/persist"
	"time"
)

// RecoverClosedInstallation durably projects already-proven closed runtime
// into normal state. It is resumable at each normal transaction and grants no
// authority to start a process or reopen ingress.
func RecoverClosedInstallation(ctx context.Context, normal *persist.Store, exposure *locks.Lease, generations map[string]uint64, closureDigest, safetyDigest string, now time.Time, random io.Reader) error {
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
	if changed, err := terminalizeInterruptedContractions(ctx, normal, exposure, document, closureDigest, now); err != nil {
		return err
	} else if changed {
		document, err = normal.Read()
		if err != nil {
			return err
		}
	}
	intent, found, err := pendingClosedRecovery(document)
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
		intent, _, err = pendingClosedRecovery(document)
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
		intent, _, err = pendingClosedRecovery(document)
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
		intent, _, err = pendingClosedRecovery(document)
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
			record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultSucceeded, Postconditions: []jobs.Postcondition{{Kind: "access_closed", Status: jobs.PostconditionVerified, Identity: closureDigest}}}, now)
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
		return nil
	}
	return fmt.Errorf("closed recovery is in an unsupported phase")
}

func terminalizeInterruptedContractions(ctx context.Context, normal *persist.Store, exposure *locks.Lease, document persist.Document, closureDigest string, now time.Time) (bool, error) {
	pending := map[string]Reservation{}
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, key[len("intents/"):])
		if err != nil {
			return false, err
		}
		if (intent.Operation == Unpublish || intent.Operation == CloseAll) && intent.Phase != PhaseTerminal && intent.Phase != PhaseRejected {
			pending[intent.JobID] = intent
		}
	}
	if len(pending) == 0 {
		return false, nil
	}
	_, _, err := normal.Update(ctx, exposure, document.Revision, func(transaction *persist.Transaction) error {
		installation, err := loadInstallation(transaction)
		if err != nil {
			return err
		}
		for jobID, intent := range pending {
			record, err := jobs.Load(transaction, jobID)
			if err != nil {
				return err
			}
			if record.Status == jobs.StatusRunning {
				record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "contraction_interrupted", Status: jobs.PostconditionKnown, Identity: closureDigest}}, ErrorCode: "activation_contracted"}, now)
				if err != nil {
					return err
				}
				if err := jobs.Replace(transaction, record); err != nil {
					return err
				}
			} else if record.Status != jobs.StatusReserved {
				return fmt.Errorf("interrupted contraction job state changed")
			} else {
				record, err = jobs.Start(record)
				if err != nil {
					return err
				}
				record, err = jobs.Finish(record, jobs.Completion{Result: jobs.ResultInterrupted, Postconditions: []jobs.Postcondition{{Kind: "contraction_interrupted", Status: jobs.PostconditionKnown, Identity: closureDigest}}, ErrorCode: "activation_contracted"}, now)
				if err != nil {
					return err
				}
				if err := jobs.Replace(transaction, record); err != nil {
					return err
				}
			}
			for index := range installation.Resources {
				resource := &installation.Resources[index]
				contraction := resource.PublicationRecord.ContractionIntent
				if contraction == nil || contraction.JobID != jobID {
					continue
				}
				resource.PublicationRecord.ContractionIntent = nil
				resource.PublicationRecord.LastOperation = contractionOperationCode(intent.Operation)
				resource.PublicationRecord.LastOperationResult = domain.OperationInterrupted
				resource.PublicationRecord.LastJobID = jobID
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

func pendingClosedRecovery(document persist.Document) (Reservation, bool, error) {
	var result Reservation
	found := false
	for _, key := range persist.EntryKeys(document, "intents") {
		intent, err := loadReservationEntries(document.Entries, key[len("intents/"):])
		if err != nil {
			return Reservation{}, false, err
		}
		if intent.Operation != StartupContraction || intent.Target != "installation" || intent.Phase == PhaseRejected || intent.Phase == PhaseTerminal {
			continue
		}
		if found {
			return Reservation{}, false, fmt.Errorf("multiple startup closed-recovery intents")
		}
		result, found = intent, true
	}
	return result, found, nil
}
