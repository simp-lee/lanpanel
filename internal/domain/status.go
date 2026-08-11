package domain

type PublicationDisplayState string

const (
	DisplayActivatingMayBeLive PublicationDisplayState = "activating_may_be_live"
	DisplayPublishedHealthy    PublicationDisplayState = "published_healthy"
	DisplayPublishedDegraded   PublicationDisplayState = "published_degraded"
	DisplayPublishedUnknown    PublicationDisplayState = "published_unknown"
	DisplayClosingMayBeLive    PublicationDisplayState = "closing_may_be_live"
	DisplayUnpublishedClosed   PublicationDisplayState = "unpublished_closed"
)

type ClosureEvidence struct {
	ResourceID            string `json:"resource_id"`
	UnpublishedGeneration uint64 `json:"unpublished_generation"`
}

type PublicationStatusInput struct {
	ContractionPending bool
	ClosureEvidence    *ClosureEvidence
}

type PublicationStatusView struct {
	State                 PublicationDisplayState `json:"state"`
	PendingChanges        bool                    `json:"pending_changes"`
	RecentOperationFailed bool                    `json:"recent_operation_failed"`
}

func DerivePublicationStatus(resource AppResource, input PublicationStatusInput) PublicationStatusView {
	record := resource.PublicationRecord
	pending := record.LastAppliedDigest == nil || *record.LastAppliedDigest != resource.CurrentConfigDigest
	view := PublicationStatusView{
		PendingChanges:        pending,
		RecentOperationFailed: record.LastOperationResult != "" && record.LastOperationResult != OperationSucceeded,
	}
	if input.ContractionPending {
		view.State = DisplayClosingMayBeLive
		return view
	}
	switch record.State {
	case PublicationActivating:
		view.State = DisplayActivatingMayBeLive
	case PublicationPublished:
		if record.RuntimeObservation == nil || record.RuntimeObservation.Status == RuntimeUnknown {
			view.State = DisplayPublishedUnknown
		} else if record.RuntimeObservation.Status == RuntimeDegraded {
			view.State = DisplayPublishedDegraded
		} else {
			view.State = DisplayPublishedHealthy
		}
	case PublicationUnpublished:
		closureMatches := input.ClosureEvidence != nil &&
			input.ClosureEvidence.ResourceID == resource.ID &&
			input.ClosureEvidence.UnpublishedGeneration == record.UnpublishedGeneration
		if record.LastAppliedBundle != nil && !closureMatches {
			view.State = DisplayClosingMayBeLive
		} else {
			view.State = DisplayUnpublishedClosed
		}
	default:
		view.State = DisplayPublishedUnknown
	}
	return view
}
