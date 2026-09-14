//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/domain"
	"sort"
	"time"
)

// ReadResourceStatus returns the fixed, non-secret status projection for one
// resource. Runtime probes are intentionally owned by the status coordinator;
// this base projection never starts a process, logs in a connector, or
// publishes an entry.
func ReadResourceStatus(ctx context.Context, resourceID string) (domain.ResourceStatusResult, error) {
	if ctx == nil || resourceID == "" {
		return domain.ResourceStatusResult{}, fmt.Errorf("resource status request is invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return domain.ResourceStatusResult{}, err
	}
	defer func() { _ = service.Close() }()
	document, err := service.Normal().Read()
	if err != nil {
		return domain.ResourceStatusResult{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return domain.ResourceStatusResult{}, err
	}
	var resource *domain.AppResource
	for index := range installation.Resources {
		if installation.Resources[index].ID == resourceID {
			resource = &installation.Resources[index]
			break
		}
	}
	if resource == nil {
		return domain.ResourceStatusResult{}, fmt.Errorf("resource %q does not exist", resourceID)
	}
	return ProjectResourceStatus(*resource, time.Now().UTC())
}

// ReadResourceStatusCatalog returns typed status entries without reading an
// arbitrary JSON read-model payload. It is deliberately observational only.
func ReadResourceStatusCatalog(ctx context.Context) (domain.ResourceStatusCatalog, error) {
	if ctx == nil {
		return domain.ResourceStatusCatalog{}, fmt.Errorf("resource status catalog context is unavailable")
	}
	service, err := OpenFixed()
	if err != nil {
		return domain.ResourceStatusCatalog{}, err
	}
	defer func() { _ = service.Close() }()
	document, err := service.Normal().Read()
	if err != nil {
		return domain.ResourceStatusCatalog{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return domain.ResourceStatusCatalog{}, err
	}
	observedAt := time.Now().UTC()
	catalog := domain.ResourceStatusCatalog{InstallationID: installation.InstallationID, ObservedAt: observedAt}
	for _, resource := range installation.Resources {
		status, statusErr := ProjectResourceStatus(resource, observedAt)
		if statusErr != nil {
			return domain.ResourceStatusCatalog{}, statusErr
		}
		catalog.Resources = append(catalog.Resources, status)
	}
	sort.Slice(catalog.Resources, func(i, j int) bool { return catalog.Resources[i].ResourceID < catalog.Resources[j].ResourceID })
	if err := domain.ValidateResourceStatusCatalog(catalog); err != nil {
		return domain.ResourceStatusCatalog{}, err
	}
	return catalog, nil
}

// ProjectResourceStatus maps durable authority to a conservative fixed
// status. More specific runtime evidence can replace the evidence fields, but
// callers must preserve the authority digest and provide closure evidence before
// claiming a closed overall state.
func ProjectResourceStatus(resource domain.AppResource, observedAt time.Time) (domain.ResourceStatusResult, error) {
	if observedAt.IsZero() {
		return domain.ResourceStatusResult{}, fmt.Errorf("resource status observation time is invalid")
	}
	result := domain.ResourceStatusResult{
		ResourceID:          resource.ID,
		Name:                resource.Name,
		TargetKind:          resource.Target.Kind,
		OverallStatus:       domain.ResourceStatusUnknown,
		ConfigurationStatus: domain.ConfigurationComplete,
		PublicationStatus:   projectPublicationStatus(resource.PublicationRecord.State),
		FailureCategory:     domain.FailureEvidenceMissing,
		LastOperation:       resource.PublicationRecord.LastOperation,
		AffectedObject:      "resource/" + resource.ID,
		NextStep:            "refresh status and follow the available resource action",
		JobID:               resource.PublicationRecord.LastJobID,
		ConfigDigest:        resource.CurrentConfigDigest,
		ObservedAt:          observedAt.UTC(),
	}
	result.AuthorityDigest = domain.ResourceStatusAuthorityDigest(result.ResourceID, result.ConfigDigest)
	if resource.ManagedProcess != nil {
		result.ProcessStatus = projectProcessStatus(*resource.ManagedProcess)
		if result.LastOperation == "" {
			result.LastOperation = resource.ManagedProcess.LastOperation
		}
		if result.JobID == "" {
			result.JobID = resource.ManagedProcess.LastJobID
		}
	} else {
		result.ProcessStatus = domain.ProcessNotApplicable
	}
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		result.ConnectorStatus = domain.EvidenceUnverified
		result.RouteStatus = domain.EvidenceUnverified
		result.TargetStatus = domain.EvidenceUnknown
		result.ConnectorObservation = &domain.ConnectorObservation{Validity: domain.ConnectorObservationMissing}
		if resource.Target.TailnetHTTP == nil {
			result.ConfigurationStatus = domain.ConfigurationInvalid
			result.FailureCategory = domain.FailureConfiguration
			result.OverallStatus = domain.ResourceStatusUnknown
		} else {
			result.TargetPeerIP = resource.Target.TailnetHTTP.IP
			result.TargetSourceIP = resource.Target.TailnetHTTP.SourceIP
			result.TargetPort = resource.Target.TailnetHTTP.Port
			result.RouteEvidence = &domain.RouteEvidence{PeerIP: resource.Target.TailnetHTTP.IP, SourceIP: resource.Target.TailnetHTTP.SourceIP, Port: resource.Target.TailnetHTTP.Port, Validity: domain.EvidenceUnverified, Failure: domain.FailureEvidenceMissing}
		}
		result.TargetObservation = &domain.TargetObservation{WebSocketRequired: resource.Target.WebSocket.Enabled, Validity: domain.EvidenceUnknown, ObservedAt: observedAt.UTC(), Failure: domain.FailureEvidenceMissing}
		result.NextStep = "verify the connector, route, and fixed remote target before publishing"
	} else {
		result.ConnectorStatus = domain.EvidenceNotApplicable
		result.RouteStatus = domain.EvidenceNotApplicable
		result.TargetStatus = domain.EvidenceUnknown
		result.TargetObservation = &domain.TargetObservation{WebSocketRequired: resource.Target.WebSocket.Enabled, Validity: domain.EvidenceUnknown, ObservedAt: observedAt.UTC(), Failure: domain.FailureEvidenceMissing}
	}
	if err := domain.ValidateResourceStatusResult(result); err != nil {
		return domain.ResourceStatusResult{}, err
	}
	return result, nil
}

func projectPublicationStatus(value domain.PublicationState) domain.ResourcePublicationStatus {
	switch value {
	case domain.PublicationPublished:
		return domain.PublicationStatusPublished
	case domain.PublicationUnpublished:
		return domain.PublicationStatusUnpublished
	case domain.PublicationActivating:
		return domain.PublicationStatusActivating
	default:
		return domain.PublicationStatusUnknown
	}
}

func projectProcessStatus(value domain.ManagedProcess) domain.ResourceProcessStatus {
	switch value.Requested {
	case domain.ProcessRequestedRunning:
		if value.LastOperation == domain.OperationProcessStart && value.LastOperationResult == "" {
			return domain.ProcessStarting
		}
		return domain.ProcessRequestedRun
	case domain.ProcessRequestedStopped:
		if value.LastOperation == domain.OperationProcessStop && value.LastOperationResult == "" {
			return domain.ProcessStopping
		}
		return domain.ProcessRequestedStop
	default:
		return domain.ProcessUnknown
	}
}
