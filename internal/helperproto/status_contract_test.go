package helperproto

import (
	"lanpanel/internal/domain"
	"testing"
	"time"
)

func TestTypedStatusResponseBindsCanonicalResultDigest(t *testing.T) {
	now := time.Now().UTC()
	status := domain.ResourceStatusResult{ResourceID: "res_00000000000000000000000000000001", Name: "app", TargetKind: domain.AppTargetLocalHTTP, OverallStatus: domain.ResourceStatusClosed, ConfigurationStatus: domain.ConfigurationComplete, ProcessStatus: domain.ProcessRequestedStop, PublicationStatus: domain.PublicationStatusUnpublished, ConnectorStatus: domain.EvidenceNotApplicable, RouteStatus: domain.EvidenceNotApplicable, TargetStatus: domain.EvidenceUnknown, FailureCategory: domain.FailureNone, ClosureVerified: true, ClosureDigest: digest("closure"), ClosureObservedAt: now, AffectedObject: "resource/res_00000000000000000000000000000001", NextStep: "publish explicitly", ConfigDigest: digest("config"), ObservedAt: now, TargetObservation: &domain.TargetObservation{Validity: domain.EvidenceUnknown, ObservedAt: now, Failure: domain.FailureEvidenceMissing}}
	status.AuthorityDigest = domain.ResourceStatusAuthorityDigest(status.ResourceID, status.ConfigDigest)
	resultDigest, err := domain.ResourceStatusDigest(status)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{SchemaVersion: SchemaVersion, RequestID: "status-result", Code: ResponseSucceeded, ResultDigest: resultDigest, Status: (*ResourceStatusResult)(&status)}
	if err := ValidateResponse(OperationDomainStatus, response); err != nil {
		t.Fatal(err)
	}
	response.ResultDigest = digest("different")
	if err := ValidateResponse(OperationDomainStatus, response); err == nil {
		t.Fatal("status response accepted a digest for another result")
	}
}
