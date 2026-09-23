package domain

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func boolPointer(value bool) *bool { return &value }

func TestResourceCreateRequestSupportsManagedBasicCreation(t *testing.T) {
	request := ResourceCreateRequest{TargetKind: AppTargetLocalHTTP, Local: &LocalResourceCreateRequest{
		Name: "Basic app", EndpointKind: LocalEndpointRelayUnix, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200},
		Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{"/srv/app/data"}, ManagedBasicUsername: "alice",
		Publication: AppPublication{Kind: PublicationDomainHTTPS, DomainHTTPS: &DomainHTTPSPublication{CanonicalDomain: "basic.example.test", AccessMode: AppAccessBasic}},
	}}
	if err := ValidateResourceCreateRequest(request); err != nil {
		t.Fatal(err)
	}
	request.Local.ManagedBasicUsername = ""
	if err := ValidateResourceCreateRequest(request); err == nil {
		t.Fatal("basic creation without a managed username was accepted")
	}
	request.Local.ManagedBasicUsername = "alice"
	request.Local.Publication.DomainHTTPS.AccessMode = AppAccessPublic
	if err := ValidateResourceCreateRequest(request); err == nil {
		t.Fatal("managed Basic username on public publication was accepted")
	}
}

func TestResourceCreateRequestIsClosedAndDoesNotCarryAuthority(t *testing.T) {
	request := ResourceCreateRequest{TargetKind: AppTargetLocalHTTP, Local: &LocalResourceCreateRequest{
		Name: "Local app", EndpointKind: LocalEndpointRelayUnix, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200},
		Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{"/srv/app/data"},
		Publication: AppPublication{Kind: PublicationDomainHTTPS, DomainHTTPS: &DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: AppAccessPublic}},
	}}
	if err := ValidateResourceCreateRequest(request); err != nil {
		t.Fatal(err)
	}
	mutated := request
	mutated.Local = new(LocalResourceCreateRequest)
	*mutated.Local = *request.Local
	mutated.Local.EndpointKind = LocalEndpointUnixSocketActivation
	mutated.Local.TCPPort = 8080
	if err := ValidateResourceCreateRequest(mutated); err == nil {
		t.Fatal("unix endpoint accepted TCP authority")
	}
	if err := ValidateResourceUpdateRequest(ResourceUpdateRequest{TargetKind: AppTargetLocalHTTP, Local: &LocalResourceUpdateRequest{Name: "Local app", EndpointKind: LocalEndpointRelayUnix, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{"/srv/app/data"}, Publication: request.Local.Publication}}); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("current_config_digest")) || bytes.Contains(encoded, []byte("managed_process")) {
		t.Fatalf("request contains internal authority: %s", encoded)
	}
}

func TestResourceStatusCanonicalDecodeRejectsUnknownDuplicateAndInvalidCombination(t *testing.T) {
	observed := time.Now().UTC()
	value := ResourceStatusResult{ResourceID: "res_00000000000000000000000000000001", Name: "Local app", TargetKind: AppTargetLocalHTTP, OverallStatus: ResourceStatusClosed, ConfigurationStatus: ConfigurationComplete, ProcessRequestedStatus: ProcessRequestedStop, ProcessObservedStatus: ProcessStopped, ProcessStatus: ProcessStopped, PublicationStatus: PublicationStatusUnpublished, ConnectorBindingStatus: ConnectorBindingNotApplicable, ConnectorStatus: EvidenceNotApplicable, RouteStatus: EvidenceNotApplicable, TargetStatus: EvidenceUnknown, FailureCategory: FailureNone, AllowedActions: []ResourceAction{ResourceActionRefresh}, ClosureVerified: true, ClosureDigest: testDigest, ClosureObservedAt: observed, AffectedObject: "resource/res_00000000000000000000000000000001", NextStep: "publish explicitly", ConfigDigest: testDigest, ObservedAt: observed, TargetObservation: &TargetObservation{Validity: EvidenceUnknown, ObservedAt: observed, Failure: FailureEvidenceMissing}}
	value.Dependencies = []ResourceDependencyStatus{{ID: "cred_00000000000000000000000000000001", Kind: DependencyManagedBasic, State: DependencyAvailable, OwnerResourceID: value.ResourceID, Fingerprint: testDigest}}
	value.AuthorityDigest = ResourceStatusAuthorityDigest(value.ResourceID, value.ConfigDigest)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResourceStatusResult(data)
	if err != nil || decoded.ResourceID != value.ResourceID {
		t.Fatalf("canonical status decode=%#v,%v", decoded, err)
	}
	unknown := append(append([]byte(nil), data[:len(data)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := DecodeResourceStatusResult(unknown); err == nil {
		t.Fatal("unknown status field accepted")
	}
	duplicate := append(append([]byte(nil), data[:len(data)-1]...), []byte(`,"overall_status":"closed"}`)...)
	if _, err := DecodeResourceStatusResult(duplicate); err == nil {
		t.Fatal("duplicate status field accepted")
	}
	invalidDependency := value
	invalidDependency.Dependencies = []ResourceDependencyStatus{{ID: "cred_00000000000000000000000000000001", Kind: DependencyManagedBasic, State: DependencyAvailable, OwnerResourceID: "res_00000000000000000000000000000002", Fingerprint: testDigest}}
	if err := ValidateResourceStatusResult(invalidDependency); err == nil {
		t.Fatal("dependency from another resource was accepted")
	}
	invalid := value
	invalid.OverallStatus = ResourceStatusUnreachable
	if err := ValidateResourceStatusResult(invalid); err == nil {
		t.Fatal("closed resource was relabeled unreachable")
	}
	invalidJob := value
	invalidJob.JobID = "job_not-a-job"
	invalidJob.JobResult = OperationSucceeded
	if err := ValidateResourceStatusResult(invalidJob); err == nil {
		t.Fatal("noncanonical job identity was accepted")
	}
	invalidJob = value
	invalidJob.JobID = "job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	invalidJob.JobResult = OperationFailed
	invalidJob.JobErrorCode = "arbitrary_error"
	if err := ValidateResourceStatusResult(invalidJob); err == nil {
		t.Fatal("unknown job error code was accepted")
	}
	incompleteJob := value
	incompleteJob.JobID = invalidJob.JobID
	if err := ValidateResourceStatusResult(incompleteJob); err == nil {
		t.Fatal("job identity without pending or terminal evidence was accepted")
	}
	missingError := value
	missingError.JobID = invalidJob.JobID
	missingError.JobResult = OperationFailed
	if err := ValidateResourceStatusResult(missingError); err == nil {
		t.Fatal("failed job without an error code was accepted")
	}
	invalidPending := value
	invalidPending.JobID = invalidJob.JobID
	invalidPending.JobPending = true
	invalidPending.JobResult = OperationSucceeded
	if err := ValidateResourceStatusResult(invalidPending); err == nil {
		t.Fatal("pending status carried a terminal job result")
	}
}

func TestTailnetEvidenceStagesBindRouteAndRemainIndependent(t *testing.T) {
	observed := time.Now().UTC()
	connectorIdentity := TailnetConnectorIdentity("https://control.example.test", "1.0", testDigest, testDigest)
	routeIdentity := TailnetRouteIdentity(connectorIdentity, "100.64.0.2", "100.64.0.1", 8080)
	value := ResourceStatusResult{ResourceID: "res_00000000000000000000000000000002", Name: "Remote app", TargetKind: AppTargetTailnetHTTP, TargetPeerIP: "100.64.0.2", TargetSourceIP: "100.64.0.1", TargetPort: 8080, OverallStatus: ResourceStatusUnknown, ConfigurationStatus: ConfigurationComplete, ProcessRequestedStatus: ProcessNotApplicable, ProcessObservedStatus: ProcessNotApplicable, ProcessStatus: ProcessNotApplicable, PublicationStatus: PublicationStatusUnpublished, ConnectorBindingStatus: ConnectorBindingBound, ConnectorStatus: EvidenceFresh, RouteStatus: EvidenceFresh, TargetStatus: EvidenceFresh, FailureCategory: FailureEvidenceMissing, AllowedActions: []ResourceAction{ResourceActionRefresh}, AffectedObject: "resource/res_00000000000000000000000000000002", NextStep: "publish explicitly", ConfigDigest: testDigest, ObservedAt: observed, ConnectorObservation: &ConnectorObservation{ControlURL: "https://control.example.test", ClientVersion: "1.0", ClientIdentityDigest: testDigest, LocalIdentityDigest: testDigest, Validity: ConnectorObservationFresh, ObservedAt: observed, ValidUntil: observed.Add(time.Minute)}, RouteEvidence: &RouteEvidence{PeerIP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080, ConnectorIdentityDigest: connectorIdentity, RouteIdentity: routeIdentity, PeerOnline: boolPointer(true), Validity: EvidenceFresh, ObservedAt: observed, ValidUntil: observed.Add(time.Minute), Failure: FailureNone}, TargetObservation: &TargetObservation{RouteIdentity: routeIdentity, PortConnected: true, HTTPReady: true, HTTPStatus: 200, Validity: EvidenceFresh, ObservedAt: observed, Failure: FailureNone}}
	value.AuthorityDigest = ResourceStatusAuthorityDigest(value.ResourceID, value.ConfigDigest)
	if err := ValidateResourceStatusResult(value); err != nil {
		t.Fatal(err)
	}
	value.TargetObservation.RouteIdentity = "sha256:" + strings.Repeat("b", 64)
	if err := ValidateResourceStatusResult(value); err == nil {
		t.Fatal("target evidence was accepted for another route")
	}
}
