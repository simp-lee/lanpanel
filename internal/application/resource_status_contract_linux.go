//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/persist"
	"net/netip"
	"sort"
	"time"
)

type ResourceStatusEvidence struct {
	ConnectorBindingStatus domain.ConnectorBindingStatus
	NginxHealthy           bool
	NginxGeneration        string
	ManifestContains       bool
	NginxFailure           domain.ResourceFailureCategory
	NginxFenced            bool
	ProcessStatus          domain.ResourceProcessStatus
	ProcessFailure         domain.ResourceFailureCategory
	ConnectorObservation   *domain.ConnectorObservation
	ConnectorFailure       domain.ResourceFailureCategory
	RouteEvidence          *domain.RouteEvidence
	RouteFailure           domain.ResourceFailureCategory
	TargetObservation      *domain.TargetObservation
	TargetFailure          domain.ResourceFailureCategory
	PublicationFailure     domain.ResourceFailureCategory
	SourceChecked          bool
	SourceHealthy          bool
	SourceFailure          domain.ResourceFailureCategory
	CertificateChecked     bool
	CertificateHealthy     bool
	CertificateFailure     domain.ResourceFailureCategory
	JobPending             bool
	JobID                  string
	JobResult              domain.OperationResult
	JobErrorCode           domain.JobErrorCode
	LastOperation          domain.OperationCode
}

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
	probeStartedAt := time.Now().UTC()
	manifest, nginxHealthy, nginxFailure, nginxFenced := observeNginxStatusForResource(ctx, service, installation)
	evidence := observeTypedResourceEvidence(ctx, *resource, probeStartedAt, manifest, nginxHealthy, nil)
	evidence.ConnectorBindingStatus = connectorBindingStatus(installation, *resource)
	evidence.JobPending, evidence.JobID, evidence.LastOperation, evidence.JobResult, evidence.JobErrorCode = observeResourceJob(document, *resource)
	evidence.NginxFailure = nginxFailure
	evidence.NginxFenced = nginxFenced
	result, err := ProjectObservedResourceStatus(*resource, time.Now().UTC(), evidence)
	if err != nil {
		return domain.ResourceStatusResult{}, err
	}
	result.Dependencies = resourceDependencyStatuses(installation, *resource)
	if err := domain.ValidateResourceStatusResult(result); err != nil {
		return domain.ResourceStatusResult{}, err
	}
	return result, nil
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
	probeStartedAt := time.Now().UTC()
	manifest, nginxHealthy, nginxFailure, nginxFenced := observeNginxStatusForResource(ctx, service, installation)
	connectorCache := &typedConnectorCache{}
	catalog := domain.ResourceStatusCatalog{InstallationID: installation.InstallationID, Resources: []domain.ResourceStatusResult{}}
	for _, resource := range installation.Resources {
		evidence := observeTypedResourceEvidence(ctx, resource, probeStartedAt, manifest, nginxHealthy, connectorCache)
		evidence.ConnectorBindingStatus = connectorBindingStatus(installation, resource)
		evidence.JobPending, evidence.JobID, evidence.LastOperation, evidence.JobResult, evidence.JobErrorCode = observeResourceJob(document, resource)
		evidence.NginxFailure = nginxFailure
		evidence.NginxFenced = nginxFenced
		status, statusErr := ProjectObservedResourceStatus(resource, time.Now().UTC(), evidence)
		if statusErr != nil {
			return domain.ResourceStatusCatalog{}, statusErr
		}
		status.Dependencies = resourceDependencyStatuses(installation, resource)
		if err := domain.ValidateResourceStatusResult(status); err != nil {
			return domain.ResourceStatusCatalog{}, err
		}
		catalog.Resources = append(catalog.Resources, status)
	}
	sort.Slice(catalog.Resources, func(i, j int) bool { return catalog.Resources[i].ResourceID < catalog.Resources[j].ResourceID })
	catalog.ObservedAt = time.Now().UTC()
	if err := domain.ValidateResourceStatusCatalog(catalog); err != nil {
		return domain.ResourceStatusCatalog{}, err
	}
	return catalog, nil
}

func connectorBindingStatus(installation domain.Installation, resource domain.AppResource) domain.ConnectorBindingStatus {
	if resource.Target.Kind != domain.AppTargetTailnetHTTP {
		return domain.ConnectorBindingNotApplicable
	}
	if installation.Connector == nil {
		return domain.ConnectorBindingMissing
	}
	return domain.ConnectorBindingBound
}

func resourceDependencyStatuses(installation domain.Installation, resource domain.AppResource) []domain.ResourceDependencyStatus {
	boundCredentials := map[string]bool{}
	for _, id := range resource.CredentialIDs {
		boundCredentials[id] = true
	}
	if publication := resource.Publication.DomainHTTPS; publication != nil {
		boundCredentials[publication.CredentialID] = true
		boundCredentials[publication.GoAccess.CredentialID] = true
	}
	dependencies := make([]domain.ResourceDependencyStatus, 0)
	for _, credential := range installation.Credentials {
		if credential.OwnerResourceID != resource.ID || credential.Kind != "managed_basic" && credential.Kind != "external_htpasswd" {
			continue
		}
		state := domain.DependencyAvailable
		if boundCredentials[credential.ID] {
			state = domain.DependencyBound
		}
		kind := domain.DependencyExternalHTPasswd
		if credential.Kind == "managed_basic" {
			kind = domain.DependencyManagedBasic
		}
		dependencies = append(dependencies, domain.ResourceDependencyStatus{ID: credential.ID, Kind: kind, State: state, OwnerResourceID: resource.ID, Fingerprint: credential.Fingerprint})
	}
	for _, root := range installation.StaticRoots {
		if root.OwnerResourceID != resource.ID {
			continue
		}
		state := domain.DependencyAvailable
		if resource.Publication.DomainHTTPS != nil && resource.Publication.DomainHTTPS.StaticRootID == root.ID {
			state = domain.DependencyBound
		}
		dependencies = append(dependencies, domain.ResourceDependencyStatus{ID: root.ID, Kind: domain.DependencyStaticRoot, State: state, OwnerResourceID: resource.ID, Fingerprint: root.Fingerprint})
	}
	sort.Slice(dependencies, func(i, j int) bool {
		left := string(dependencies[i].Kind) + "\x00" + dependencies[i].ID
		right := string(dependencies[j].Kind) + "\x00" + dependencies[j].ID
		return left < right
	})
	return dependencies
}

// ProjectResourceStatus maps durable authority to a conservative fixed
// status. More specific runtime evidence can replace the evidence fields, but
// callers must preserve the authority digest and provide closure evidence before
// claiming a closed overall state.
func ProjectResourceStatus(resource domain.AppResource, observedAt time.Time) (domain.ResourceStatusResult, error) {
	return projectResourceStatus(resource, observedAt, true)
}

func projectResourceStatus(resource domain.AppResource, observedAt time.Time, validate bool) (domain.ResourceStatusResult, error) {
	if observedAt.IsZero() {
		return domain.ResourceStatusResult{}, fmt.Errorf("resource status observation time is invalid")
	}
	result := domain.ResourceStatusResult{
		ResourceID:             resource.ID,
		Name:                   resource.Name,
		TargetKind:             resource.Target.Kind,
		OverallStatus:          domain.ResourceStatusUnknown,
		ConfigurationStatus:    domain.ConfigurationComplete,
		PublicationStatus:      projectPublicationStatus(resource.PublicationRecord),
		ConnectorBindingStatus: domain.ConnectorBindingUnknown,
		FailureCategory:        domain.FailureEvidenceMissing,
		LastOperation:          resource.PublicationRecord.LastOperation,
		AffectedObject:         "resource/" + resource.ID,
		NextStep:               "refresh status and follow the available resource action",
		JobID:                  resource.PublicationRecord.LastJobID,
		JobPending:             resource.PublicationRecord.LastJobID != "" && resource.PublicationRecord.LastOperationResult == "",
		JobResult:              resource.PublicationRecord.LastOperationResult,
		ConfigDigest:           resource.CurrentConfigDigest,
		Configuration:          domain.ResourceStatusConfigurationFor(resource),
		ObservedAt:             observedAt.UTC(),
	}
	result.AuthorityDigest = domain.ResourceStatusAuthorityDigest(result.ResourceID, result.ConfigDigest)
	if resource.Target.Kind == domain.AppTargetLocalHTTP && resource.ManagedProcess != nil {
		result.ProcessRequestedStatus = projectProcessRequestedStatus(*resource.ManagedProcess)
		result.ProcessObservedStatus = domain.ProcessUnknown
		result.ProcessStatus = projectProcessStatus(*resource.ManagedProcess)
		if result.LastOperation == "" {
			result.LastOperation = resource.ManagedProcess.LastOperation
		}
		if result.JobID == "" || resource.ManagedProcess.LastJobID != "" && resource.ManagedProcess.LastOperationResult == "" {
			result.JobID = resource.ManagedProcess.LastJobID
			result.JobResult = resource.ManagedProcess.LastOperationResult
		}
		if resource.ManagedProcess.LastJobID != "" && resource.ManagedProcess.LastOperationResult == "" {
			result.JobPending = true
		}
	} else {
		result.ProcessRequestedStatus = domain.ProcessNotApplicable
		result.ProcessObservedStatus = domain.ProcessNotApplicable
		result.ProcessStatus = domain.ProcessNotApplicable
		if resource.Target.Kind == domain.AppTargetTailnetHTTP && resource.ManagedProcess != nil {
			result.ConfigurationStatus = domain.ConfigurationInvalid
			result.FailureCategory = domain.FailureConfiguration
		}
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
			result.TargetPeerIP = canonicalStatusIP(resource.Target.TailnetHTTP.IP)
			result.TargetSourceIP = canonicalStatusIP(resource.Target.TailnetHTTP.SourceIP)
			result.TargetPort = resource.Target.TailnetHTTP.Port
			result.RouteEvidence = &domain.RouteEvidence{PeerIP: result.TargetPeerIP, SourceIP: result.TargetSourceIP, Port: result.TargetPort, Validity: domain.EvidenceUnverified, Failure: domain.FailureEvidenceMissing}
		}
		result.TargetObservation = &domain.TargetObservation{WebSocketRequired: resource.Target.WebSocket.Enabled, Validity: domain.EvidenceUnknown, ObservedAt: observedAt.UTC(), Failure: domain.FailureEvidenceMissing}
		result.NextStep = "verify the connector, route, and fixed remote target before publishing"
	} else {
		result.ConnectorBindingStatus = domain.ConnectorBindingNotApplicable
		result.ConnectorStatus = domain.EvidenceNotApplicable
		result.RouteStatus = domain.EvidenceNotApplicable
		result.TargetStatus = domain.EvidenceUnknown
		result.TargetObservation = &domain.TargetObservation{WebSocketRequired: resource.Target.WebSocket.Enabled, Validity: domain.EvidenceUnknown, ObservedAt: observedAt.UTC(), Failure: domain.FailureEvidenceMissing}
	}
	if result.PublicationStatus == domain.PublicationStatusPublished && resource.PublicationRecord.LastAppliedBundle != nil && (resource.PublicationRecord.LastAppliedDigest == nil || *resource.PublicationRecord.LastAppliedDigest != resource.PublicationRecord.LastAppliedBundle.ConfigDigest || resource.CurrentConfigDigest != resource.PublicationRecord.LastAppliedBundle.ConfigDigest) {
		result.ConfigurationStatus = domain.ConfigurationUnknown
		result.FailureCategory = domain.FailureAuthorityConflict
		result.NextStep = "republish the current configuration after a fresh preflight"
	}
	result.AllowedActions = projectResourceActions(resource, result)
	if validate {
		if err := domain.ValidateResourceStatusResult(result); err != nil {
			return domain.ResourceStatusResult{}, err
		}
	}
	return result, nil
}

// ProjectObservedResourceStatus combines the durable resource authority with
// independently collected evidence. It never interprets a missing probe as a
// successful observation.
func ProjectObservedResourceStatus(resource domain.AppResource, observedAt time.Time, evidence ResourceStatusEvidence) (domain.ResourceStatusResult, error) {
	result, err := projectResourceStatus(resource, observedAt, false)
	if err != nil {
		return domain.ResourceStatusResult{}, err
	}
	if evidence.ConnectorBindingStatus != "" {
		result.ConnectorBindingStatus = evidence.ConnectorBindingStatus
	}
	if evidence.JobID != "" {
		result.JobID = evidence.JobID
		result.JobPending = evidence.JobPending
		result.JobResult = evidence.JobResult
		result.JobErrorCode = evidence.JobErrorCode
	}
	if evidence.LastOperation != "" {
		result.LastOperation = evidence.LastOperation
	}
	if evidence.JobPending {
		result.JobPending = true
		result.NextStep = "wait for the current Job to finish, then refresh status"
	}
	if evidence.ProcessStatus != "" {
		result.ProcessObservedStatus = evidence.ProcessStatus
		result.ProcessStatus = evidence.ProcessStatus
	} else if resource.Target.Kind == domain.AppTargetLocalHTTP && result.ProcessRequestedStatus != domain.ProcessNotApplicable {
		result.ProcessObservedStatus = domain.ProcessUnknown
		if hasStatusFailure(evidence.ProcessFailure) {
			result.ProcessStatus = domain.ProcessUnknown
			result.FailureCategory = evidence.ProcessFailure
		}
	}
	if hasStatusFailure(evidence.NginxFailure) {
		result.FailureCategory = evidence.NginxFailure
	}
	if evidence.NginxFenced {
		result.PublicationStatus = domain.PublicationStatusFenced
		result.FailureCategory = domain.FailurePublication
	}
	if resource.Target.Kind == domain.AppTargetTailnetHTTP {
		projectTailnetEvidence(&result, evidence)
	} else {
		projectLocalEvidence(&result, resource, evidence)
	}
	if evidence.NginxFenced {
		result.PublicationStatus = domain.PublicationStatusFenced
		result.FailureCategory = domain.FailurePublication
	} else if hasStatusFailure(evidence.NginxFailure) {
		result.FailureCategory = evidence.NginxFailure
	}
	runtimeObserved := resource.Target.Kind == domain.AppTargetTailnetHTTP && result.ProcessStatus == domain.ProcessNotApplicable || resource.Target.Kind == domain.AppTargetLocalHTTP && (result.ProcessStatus == domain.ProcessRunning || result.ProcessStatus == domain.ProcessStopped)
	if result.FailureCategory == domain.FailureEvidenceMissing && evidence.NginxHealthy && evidence.ManifestContains && result.TargetStatus == domain.EvidenceFresh && publicationEvidenceHealthy(result, evidence) {
		result.FailureCategory = domain.FailureNone
	}
	if !result.JobPending && result.PublicationStatus == domain.PublicationStatusUnpublished && runtimeObserved && evidence.NginxHealthy && !hasStatusFailure(evidence.NginxFailure) && !evidence.NginxFenced && !evidence.ManifestContains {
		result.ClosureVerified = true
		result.ClosureDigest = digestLifecycle(struct {
			ResourceID      string
			ConfigDigest    string
			NginxGeneration string
		}{resource.ID, resource.CurrentConfigDigest, evidence.NginxGeneration})
		result.ClosureObservedAt = result.ObservedAt
		result.NextStep = "start or publish explicitly when the resource is ready"
	}
	result.OverallStatus = projectOverallStatus(resource, result, evidence)
	if !result.JobPending {
		result.NextStep = projectStatusNextStep(result)
	}
	if result.OverallStatus == domain.ResourceStatusDegraded && (result.FailureCategory == domain.FailureEvidenceMissing || result.FailureCategory == domain.FailureNone) {
		result.FailureCategory = domain.FailureEvidenceMismatch
	}
	if result.OverallStatus == domain.ResourceStatusHealthy || result.OverallStatus == domain.ResourceStatusClosed {
		result.FailureCategory = domain.FailureNone
	} else if result.OverallStatus == domain.ResourceStatusUnknown && result.FailureCategory == domain.FailureNone {
		if result.JobPending {
			result.FailureCategory = domain.FailureOperation
		} else {
			result.FailureCategory = domain.FailureEvidenceMissing
		}
	}
	result.AllowedActions = projectResourceActions(resource, result)
	if err := domain.ValidateResourceStatusResult(result); err != nil {
		return domain.ResourceStatusResult{}, err
	}
	return result, nil
}

func canonicalStatusIP(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	return address.String()
}

func observeResourceJob(document persist.Document, resource domain.AppResource) (bool, string, domain.OperationCode, domain.OperationResult, domain.JobErrorCode) {
	ids := make([]string, 0, 2)
	if resource.PublicationRecord.LastJobID != "" {
		ids = append(ids, resource.PublicationRecord.LastJobID)
	}
	if resource.Target.Kind == domain.AppTargetLocalHTTP && resource.ManagedProcess != nil && resource.ManagedProcess.LastJobID != "" && (len(ids) == 0 || ids[0] != resource.ManagedProcess.LastJobID) {
		ids = append(ids, resource.ManagedProcess.LastJobID)
	}
	var latest jobs.Record
	for _, id := range ids {
		record, err := jobs.LoadEntries(document.Entries, id)
		if err != nil || latest.ID != "" && !record.StartedAt.After(latest.StartedAt) {
			continue
		}
		latest = record
	}
	if latest.ID == "" {
		return false, "", "", "", ""
	}
	pending := latest.Status == jobs.StatusReserved || latest.Status == jobs.StatusRunning
	if pending {
		return true, latest.ID, domain.OperationCode(latest.Operation), "", ""
	}
	return false, latest.ID, domain.OperationCode(latest.Operation), domain.OperationResult(latest.Result), domain.JobErrorCode(latest.ErrorCode)
}

func hasStatusFailure(value domain.ResourceFailureCategory) bool {
	return value != "" && value != domain.FailureNone
}

func projectLocalEvidence(result *domain.ResourceStatusResult, resource domain.AppResource, evidence ResourceStatusEvidence) {
	if evidence.TargetObservation != nil {
		result.TargetObservation = evidence.TargetObservation
		result.TargetStatus = evidence.TargetObservation.Validity
	} else if hasStatusFailure(evidence.TargetFailure) {
		result.TargetStatus = domain.EvidenceUnreachable
		result.TargetObservation = &domain.TargetObservation{WebSocketRequired: resource.Target.WebSocket.Enabled, Validity: domain.EvidenceUnreachable, ObservedAt: result.ObservedAt, Failure: evidence.TargetFailure}
	}
	if evidence.SourceChecked {
		if evidence.SourceHealthy && result.FailureCategory == domain.FailureEvidenceMissing {
			result.FailureCategory = domain.FailureNone
		} else if !evidence.SourceHealthy && hasStatusFailure(evidence.SourceFailure) {
			result.FailureCategory = evidence.SourceFailure
		}
	}
	if evidence.CertificateChecked && !evidence.CertificateHealthy && hasStatusFailure(evidence.CertificateFailure) {
		result.FailureCategory = evidence.CertificateFailure
	}
	if hasStatusFailure(evidence.PublicationFailure) {
		result.FailureCategory = evidence.PublicationFailure
	}
	if hasStatusFailure(evidence.ProcessFailure) {
		result.FailureCategory = evidence.ProcessFailure
	}
	if hasStatusFailure(evidence.TargetFailure) {
		result.FailureCategory = evidence.TargetFailure
	}
	if evidence.TargetObservation != nil && hasStatusFailure(evidence.TargetObservation.Failure) {
		result.FailureCategory = evidence.TargetObservation.Failure
	}
}

func projectTailnetEvidence(result *domain.ResourceStatusResult, evidence ResourceStatusEvidence) {
	if evidence.ConnectorObservation != nil {
		result.ConnectorObservation = evidence.ConnectorObservation
		switch evidence.ConnectorObservation.Validity {
		case domain.ConnectorObservationFresh:
			result.ConnectorStatus = domain.EvidenceFresh
		case domain.ConnectorObservationExpired:
			result.ConnectorStatus = domain.EvidenceExpired
		default:
			result.ConnectorStatus = domain.EvidenceUnknown
		}
	} else if evidence.ConnectorFailure == domain.FailureConnectorDown {
		result.ConnectorStatus = domain.EvidenceUnreachable
		result.ConnectorObservation = &domain.ConnectorObservation{Validity: domain.ConnectorObservationMissing}
	} else if hasStatusFailure(evidence.ConnectorFailure) {
		result.ConnectorStatus = domain.EvidenceUnknown
		result.ConnectorObservation = &domain.ConnectorObservation{Validity: domain.ConnectorObservationMissing}
	}
	if evidence.RouteEvidence != nil {
		result.RouteEvidence = evidence.RouteEvidence
		result.RouteStatus = evidence.RouteEvidence.Validity
	} else if hasStatusFailure(evidence.RouteFailure) {
		result.RouteStatus = domain.EvidenceUnknown
		validity := domain.EvidenceUnknown
		var connectorIdentity, routeIdentity string
		if (evidence.RouteFailure == domain.FailureRouteDown || evidence.RouteFailure == domain.FailurePeerOffline) && result.ConnectorStatus == domain.EvidenceFresh && result.ConnectorObservation != nil {
			connectorIdentity = domain.TailnetConnectorIdentity(result.ConnectorObservation.ControlURL, result.ConnectorObservation.ClientVersion, result.ConnectorObservation.ClientIdentityDigest, result.ConnectorObservation.LocalIdentityDigest)
			routeIdentity = domain.TailnetRouteIdentity(connectorIdentity, result.TargetPeerIP, result.TargetSourceIP, result.TargetPort)
			validity = domain.EvidenceUnreachable
			result.RouteStatus = validity
		}
		var peerOnline *bool
		if evidence.RouteFailure == domain.FailurePeerOffline {
			offline := false
			peerOnline = &offline
		}
		result.RouteEvidence = &domain.RouteEvidence{PeerIP: result.TargetPeerIP, SourceIP: result.TargetSourceIP, Port: result.TargetPort, PeerOnline: peerOnline, ConnectorIdentityDigest: connectorIdentity, RouteIdentity: routeIdentity, Validity: validity, ObservedAt: func() time.Time {
			if validity == domain.EvidenceUnreachable {
				return result.ObservedAt
			}
			return time.Time{}
		}(), ValidUntil: func() time.Time {
			if validity == domain.EvidenceUnreachable {
				return result.ObservedAt
			}
			return time.Time{}
		}(), Failure: evidence.RouteFailure}
	}
	if evidence.TargetObservation != nil {
		result.TargetObservation = evidence.TargetObservation
		result.TargetStatus = evidence.TargetObservation.Validity
	} else if hasStatusFailure(evidence.TargetFailure) {
		result.TargetStatus = domain.EvidenceUnreachable
		result.TargetObservation = &domain.TargetObservation{Validity: domain.EvidenceUnreachable, ObservedAt: result.ObservedAt, Failure: evidence.TargetFailure}
	}
	result.FailureCategory = selectTailnetFailure(evidence, *result)
}

func selectTailnetFailure(evidence ResourceStatusEvidence, result domain.ResourceStatusResult) domain.ResourceFailureCategory {
	routeFailure := evidence.RouteFailure
	if result.RouteEvidence != nil && hasStatusFailure(result.RouteEvidence.Failure) {
		routeFailure = result.RouteEvidence.Failure
	}
	targetFailure := evidence.TargetFailure
	if result.TargetObservation != nil && hasStatusFailure(result.TargetObservation.Failure) {
		targetFailure = result.TargetObservation.Failure
	}
	for _, failure := range []domain.ResourceFailureCategory{evidence.ConnectorFailure, routeFailure, targetFailure} {
		if failure == domain.FailureConnectorDown || failure == domain.FailureRouteDown || failure == domain.FailurePeerOffline || failure == domain.FailureTargetDown {
			return failure
		}
	}
	for _, failure := range []domain.ResourceFailureCategory{evidence.NginxFailure, evidence.ConnectorFailure, routeFailure, targetFailure, evidence.SourceFailure, evidence.CertificateFailure, evidence.PublicationFailure} {
		if hasStatusFailure(failure) {
			return failure
		}
	}
	return result.FailureCategory
}

func projectOverallStatus(resource domain.AppResource, result domain.ResourceStatusResult, evidence ResourceStatusEvidence) domain.ResourceStatusOverall {
	if result.JobPending {
		return domain.ResourceStatusUnknown
	}
	if result.PublicationStatus != domain.PublicationStatusPublished {
		if result.ClosureVerified {
			return domain.ResourceStatusClosed
		}
		return domain.ResourceStatusUnknown
	}
	if resource.Target.Kind == domain.AppTargetTailnetHTTP && tailnetNetworkUnreachable(result, evidence) {
		return domain.ResourceStatusUnreachable
	}
	processHealthy := result.TargetKind == domain.AppTargetTailnetHTTP && result.ProcessStatus == domain.ProcessNotApplicable || result.TargetKind == domain.AppTargetLocalHTTP && result.ProcessStatus == domain.ProcessRunning
	if result.ConfigurationStatus == domain.ConfigurationComplete && result.FailureCategory == domain.FailureNone && evidence.NginxHealthy && evidence.ManifestContains && processHealthy && result.TargetStatus == domain.EvidenceFresh && publicationEvidenceHealthy(result, evidence) {
		return domain.ResourceStatusHealthy
	}
	if evidence.NginxFailure == domain.FailureEvidenceMismatch || evidence.ConnectorFailure == domain.FailureEvidenceMismatch || evidence.RouteFailure == domain.FailureEvidenceMismatch || evidence.TargetFailure == domain.FailureEvidenceMismatch || result.RouteEvidence != nil && result.RouteEvidence.Failure == domain.FailureEvidenceMismatch || result.TargetObservation != nil && result.TargetObservation.Failure == domain.FailureEvidenceMismatch || result.FailureCategory == domain.FailureAuthorityMissing || result.FailureCategory == domain.FailureAuthorityConflict || result.FailureCategory == domain.FailureEvidenceMissing || result.FailureCategory == domain.FailureEvidenceExpired || result.FailureCategory == domain.FailurePublication || result.FailureCategory == domain.FailureOperation {
		return domain.ResourceStatusUnknown
	}
	if result.ConfigurationStatus == domain.ConfigurationUnknown || result.ConfigurationStatus == domain.ConfigurationInvalid || result.PublicationStatus == domain.PublicationStatusUnknown || result.PublicationStatus == domain.PublicationStatusActivating || result.PublicationStatus == domain.PublicationStatusContracting || result.ProcessStatus == domain.ProcessUnknown || result.ProcessStatus == domain.ProcessStarting || result.ProcessStatus == domain.ProcessStopping || result.TargetStatus == domain.EvidenceUnknown || result.TargetStatus == domain.EvidenceExpired || resource.Target.Kind == domain.AppTargetTailnetHTTP && (result.ConnectorStatus == domain.EvidenceUnknown || result.ConnectorStatus == domain.EvidenceExpired || result.RouteStatus == domain.EvidenceUnknown || result.RouteStatus == domain.EvidenceExpired) {
		return domain.ResourceStatusUnknown
	}
	return domain.ResourceStatusDegraded
}

func projectStatusNextStep(result domain.ResourceStatusResult) string {
	switch result.OverallStatus {
	case domain.ResourceStatusClosed:
		return "resource is closed; start or publish explicitly when ready"
	case domain.ResourceStatusHealthy:
		return "no action is required; refresh status to recheck evidence"
	case domain.ResourceStatusDegraded:
		return "review the failure category and remediate before republishing"
	case domain.ResourceStatusUnreachable:
		return "restore fixed connector, route, or target reachability, then refresh status"
	default:
		return "refresh status and resolve missing, stale, or conflicting evidence"
	}
}

func tailnetNetworkUnreachable(result domain.ResourceStatusResult, evidence ResourceStatusEvidence) bool {
	if result.ConnectorStatus == domain.EvidenceUnreachable && evidence.ConnectorFailure == domain.FailureConnectorDown {
		return true
	}
	if result.RouteStatus == domain.EvidenceUnreachable {
		failure := evidence.RouteFailure
		if result.RouteEvidence != nil {
			failure = result.RouteEvidence.Failure
		}
		if failure == domain.FailureRouteDown || failure == domain.FailurePeerOffline {
			return true
		}
	}
	if result.TargetStatus == domain.EvidenceUnreachable {
		failure := evidence.TargetFailure
		if result.TargetObservation != nil {
			failure = result.TargetObservation.Failure
		}
		return failure == domain.FailureTargetDown
	}
	return false
}

func publicationEvidenceHealthy(result domain.ResourceStatusResult, evidence ResourceStatusEvidence) bool {
	if result.TargetKind == domain.AppTargetTailnetHTTP && (result.ConnectorStatus != domain.EvidenceFresh || result.RouteStatus != domain.EvidenceFresh) {
		return false
	}
	if hasStatusFailure(evidence.PublicationFailure) || evidence.SourceChecked && !evidence.SourceHealthy || evidence.CertificateChecked && !evidence.CertificateHealthy {
		return false
	}
	return true
}

func projectResourceActions(resource domain.AppResource, status domain.ResourceStatusResult) []domain.ResourceAction {
	if status.JobPending || status.OverallStatus == domain.ResourceStatusUnknown {
		return []domain.ResourceAction{domain.ResourceActionRefresh}
	}
	if status.PublicationStatus == domain.PublicationStatusUnknown || status.PublicationStatus == domain.PublicationStatusActivating || status.PublicationStatus == domain.PublicationStatusContracting || status.PublicationStatus == domain.PublicationStatusFenced {
		return []domain.ResourceAction{domain.ResourceActionRefresh}
	}
	actions := []domain.ResourceAction{domain.ResourceActionRefresh}
	if status.PublicationStatus != domain.PublicationStatusActivating && status.PublicationStatus != domain.PublicationStatusContracting && status.PublicationStatus != domain.PublicationStatusFenced {
		actions = append(actions, domain.ResourceActionEdit)
	}
	if resource.Target.Kind == domain.AppTargetLocalHTTP && resource.ManagedProcess != nil && status.PublicationStatus == domain.PublicationStatusUnpublished {
		switch status.ProcessRequestedStatus {
		case domain.ProcessRequestedRun:
			if status.ProcessObservedStatus == domain.ProcessRunning {
				actions = append(actions, domain.ResourceActionStop)
			}
		case domain.ProcessRequestedStop:
			if status.ProcessObservedStatus == domain.ProcessStopped {
				actions = append(actions, domain.ResourceActionStart)
			}
		}
	}
	if status.PublicationStatus == domain.PublicationStatusPublished {
		actions = append(actions, domain.ResourceActionUnpublish)
		if status.OverallStatus == domain.ResourceStatusHealthy || status.OverallStatus == domain.ResourceStatusDegraded {
			actions = append(actions, domain.ResourceActionRepublish)
		}
	} else if status.OverallStatus == domain.ResourceStatusClosed && status.PublicationStatus == domain.PublicationStatusUnpublished && (resource.Target.Kind == domain.AppTargetLocalHTTP && status.ProcessStatus == domain.ProcessRunning && status.TargetStatus == domain.EvidenceFresh || resource.Target.Kind == domain.AppTargetTailnetHTTP && status.ConnectorStatus == domain.EvidenceFresh && status.RouteStatus == domain.EvidenceFresh && status.TargetStatus == domain.EvidenceFresh) {
		actions = append(actions, domain.ResourceActionPublish)
	}
	processClosed := status.TargetKind == domain.AppTargetTailnetHTTP && status.ProcessStatus == domain.ProcessNotApplicable || status.TargetKind == domain.AppTargetLocalHTTP && status.ProcessStatus == domain.ProcessStopped
	if status.ClosureVerified && status.PublicationStatus == domain.PublicationStatusUnpublished && processClosed {
		actions = append(actions, domain.ResourceActionDelete)
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i] < actions[j] })
	return actions
}

func projectPublicationStatus(value domain.PublicationRecord) domain.ResourcePublicationStatus {
	if value.ActivationIntent != nil {
		return domain.PublicationStatusActivating
	}
	if value.ContractionIntent != nil {
		return domain.PublicationStatusContracting
	}
	switch value.State {
	case domain.PublicationPublished:
		return domain.PublicationStatusPublished
	case domain.PublicationUnpublished:
		return domain.PublicationStatusUnpublished
	default:
		return domain.PublicationStatusUnknown
	}
}

func projectProcessRequestedStatus(value domain.ManagedProcess) domain.ResourceProcessStatus {
	switch value.Requested {
	case domain.ProcessRequestedRunning:
		return domain.ProcessRequestedRun
	case domain.ProcessRequestedStopped:
		return domain.ProcessRequestedStop
	default:
		return domain.ProcessUnknown
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
