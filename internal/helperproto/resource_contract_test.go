package helperproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"lanpanel/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestResourceMutationUsesTypedOneOfAndRejectsRawResourceJSON(t *testing.T) {
	create := domain.ResourceCreateRequest{TargetKind: domain.AppTargetLocalHTTP, Local: &domain.LocalResourceCreateRequest{Name: "app", EndpointKind: domain.LocalEndpointRelayUnix, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, Executable: "/usr/local/bin/app", WorkingDirectory: "/srv/app", WritePaths: []string{"/srv/app/data"}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "app.example.test", AccessMode: domain.AppAccessPublic}}}}
	request := Request{SchemaVersion: SchemaVersion, RequestID: "resource-create", Operation: OperationResourceMutation, Target: "installation", IntentGeneration: 1, Deadline: time.Now().UTC().Add(time.Minute), Resource: &ResourcePayload{Operation: "resource_create", ActorIdentity: "session", ActorGeneration: 1, Confirmation: "submit", Create: &create}}
	request.InputDigest, _ = ApplicationInputDigest(request)
	if err := ValidateRequest(request, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	request.Resource.Resource = json.RawMessage(`{"id":"res_00000000000000000000000000000001"}`)
	request.InputDigest, _ = ApplicationInputDigest(request)
	if err := ValidateRequest(request, time.Now().UTC()); err == nil {
		t.Fatal("raw resource JSON was accepted alongside typed mutation")
	}
	request.Resource.Resource = nil
	request.Resource.Create = nil
	request.InputDigest, _ = ApplicationInputDigest(request)
	if err := ValidateRequest(request, time.Now().UTC()); err == nil {
		t.Fatal("resource mutation without typed one-of was accepted")
	}
}

func TestResourceMutationResponseCarriesCommittedJobIdentityAndResult(t *testing.T) {
	jobID := "job_" + strings.Repeat("a", 64)
	response := Response{SchemaVersion: SchemaVersion, RequestID: "resource-result", Code: ResponseSucceeded, ResultDigest: "sha256:" + strings.Repeat("a", 64), Resource: &ResourceResult{ResourceID: "res_00000000000000000000000000000001", JobID: jobID, JobResult: "succeeded"}}
	if err := ValidateResponse(OperationResourceMutation, response); err != nil {
		t.Fatal(err)
	}
	response.Resource.JobID = ""
	if ValidateResponse(OperationResourceMutation, response) == nil {
		t.Fatal("resource mutation response without committed Job identity was accepted")
	}
	response.Resource.JobID = jobID
	response.Resource.JobResult = "failed"
	if ValidateResponse(OperationResourceMutation, response) == nil {
		t.Fatal("resource mutation response without successful terminal result was accepted")
	}
}

func TestNestedResourceMutationUnknownAndDuplicateFieldsAreRejected(t *testing.T) {
	now := time.Now().UTC()
	create := domain.ResourceCreateRequest{TargetKind: domain.AppTargetTailnetHTTP, Tailnet: &domain.TailnetResourceCreateRequest{Name: "remote", PeerIP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{200}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: "remote.example.test", AccessMode: domain.AppAccessPublic}}}}
	request := Request{SchemaVersion: SchemaVersion, RequestID: "resource-wire", Operation: OperationResourceMutation, Target: "installation", IntentGeneration: 1, Deadline: now.Add(time.Minute), Resource: &ResourcePayload{Operation: "resource_create", ActorIdentity: "session", ActorGeneration: 1, Confirmation: "submit", Create: &create}}
	request.InputDigest, _ = ApplicationInputDigest(request)
	var wire bytes.Buffer
	if err := WriteRequest(&wire, request, nil); err != nil {
		t.Fatal(err)
	}
	payload := wire.Bytes()
	payload = append([]byte(nil), payload...)
	// The request frame contains canonical JSON; adding an unknown nested field
	// must be rejected before the typed helper handler can run.
	needle := []byte(`"target_kind":"tailnet_http"`)
	index := bytes.Index(payload, needle)
	if index < 0 {
		t.Fatal("typed target kind was not encoded")
	}
	insert := index + len(needle)
	payload = append(payload[:insert], append([]byte(`,"unknown":true`), payload[insert:]...)...)
	if _, _, err := ReadRequest(bytes.NewReader(payload)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("nested unknown field error=%v", err)
	}
	if strings.Contains(wire.String(), "managed_process") {
		t.Fatal("typed mutation wire contains process authority")
	}
}
