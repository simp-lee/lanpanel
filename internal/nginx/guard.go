package nginx

import (
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/safety"
	"time"
)

type GuardAction string

const (
	GuardStart  GuardAction = "start"
	GuardReload GuardAction = "reload"
)

type GuardInput struct {
	Action           GuardAction
	Manifest         Manifest
	Safety           safety.State
	Installation     *domain.Installation
	Now              time.Time
	RuntimeTarget    string
	AllowMaintenance bool
}

type GuardDecision struct {
	Allowed bool
	Reason  string
}

// Guard evaluates only durable safety and the already audited disk manifest.
// It never normalizes, clears, or invents state.
func Guard(input GuardInput) GuardDecision {
	if input.Action != GuardStart && input.Action != GuardReload || input.Now.IsZero() || ValidateManifest(input.Manifest) != nil {
		return GuardDecision{Reason: "guard authority is invalid"}
	}
	if err := safety.Validate(input.Safety); err != nil {
		return GuardDecision{Reason: "independent safety authority is invalid"}
	}
	if input.Safety.StopFence != nil {
		return GuardDecision{Reason: "stop fence blocks Nginx start and reload"}
	}
	if input.Safety.UpgradePending != nil || input.Safety.BackupQuiescence != nil || input.Safety.BackupTransition != nil && input.Safety.BackupTransition.Phase != safety.BackupTransitionImported {
		return GuardDecision{Reason: "upgrade or backup fence blocks Nginx"}
	}
	if input.Safety.DependencyTransitionPending != nil {
		if hasAppEntries(input.Manifest) || input.RuntimeTarget == "" || input.RuntimeTarget != input.Safety.DependencyTransitionPending.TargetEnvelope {
			return GuardDecision{Reason: "dependency transition accepts only its exact no-App runtime"}
		}
	}
	if input.Safety.MaintenancePending != nil {
		if !input.AllowMaintenance || hasAppEntries(input.Manifest) || input.RuntimeTarget == "" || input.RuntimeTarget != input.Safety.MaintenancePending.TargetEnvelope {
			return GuardDecision{Reason: "maintenance accepts only its exact no-App runtime"}
		}
	}
	for _, entry := range input.Manifest.Entries {
		if entry.Kind == EntryControl {
			return GuardDecision{Reason: "control ingress authority is unavailable"}
		}
		resource := findSafetyResource(input.Safety, entry.ResourceID)
		if resource == nil {
			return GuardDecision{Reason: fmt.Sprintf("disk graph resource %q lacks safety authority", entry.ResourceID)}
		}
		if input.Safety.GlobalClose.Phase != safety.GlobalCloseNone || resource.Closing != nil || resource.State == safety.ResourceDeleting || resource.Ownership == safety.OwnershipOrphan {
			return GuardDecision{Reason: "higher-priority contraction blocks App graph"}
		}
		switch entry.Kind {
		case EntryChallenge:
			return GuardDecision{Reason: "challenge ingress renderer is unavailable"}
		case EntryApp:
			return GuardDecision{Reason: "domain App ingress prerequisite is unavailable"}
		case EntryTemporary:
			if input.Installation == nil {
				return GuardDecision{Reason: "normal publication authority is unavailable"}
			}
			var app *domain.AppResource
			for index := range input.Installation.Resources {
				if input.Installation.Resources[index].ID == entry.ResourceID {
					app = &input.Installation.Resources[index]
					break
				}
			}
			published := app != nil && app.PublicationRecord.State == domain.PublicationPublished && app.PublicationRecord.LastAppliedBundle != nil && app.PublicationRecord.LastAppliedBundle.Generation == entry.Generation && app.PublicationRecord.LastAppliedBundle.SiteIdentity == entry.Digest && resource.StickyUnpublished == nil && resource.Contraction == nil && resource.CertificateExpiry == nil && resource.EdgeOne.Expiry == nil && resource.Reactivating == nil
			activating := app != nil && app.PublicationRecord.State == domain.PublicationActivating && app.PublicationRecord.ActivationIntent != nil && app.PublicationRecord.ActivationIntent.Candidate.Generation == entry.Generation && app.PublicationRecord.ActivationIntent.Candidate.SiteIdentity == entry.Digest && resource.Reactivating != nil && resource.Reactivating.Generation == entry.Generation && resource.Reactivating.CandidateBundle != ""
			if !published && !activating {
				return GuardDecision{Reason: "temporary App graph lacks exact published or activating authority"}
			}
		default:
			return GuardDecision{Reason: "disk graph kind is unsupported"}
		}
	}
	return GuardDecision{Allowed: true, Reason: "exact durable safety and disk graph match"}
}

func hasAppEntries(manifest Manifest) bool {
	for _, entry := range manifest.Entries {
		if entry.Kind != EntryControl {
			return true
		}
	}
	return false
}

func findSafetyResource(state safety.State, id string) *safety.ResourceSafety {
	for index := range state.Resources {
		if state.Resources[index].ResourceID == id {
			return &state.Resources[index]
		}
	}
	return nil
}
