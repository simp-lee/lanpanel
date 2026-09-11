package helperproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTypedProtocolRejectsQueueingAndGenericSecrets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := Request{SchemaVersion: SchemaVersion, RequestID: "request-one", Operation: OperationAdminTokenVerify, Target: "installation", IntentGeneration: 4, Deadline: now.Add(time.Minute), InputDigest: digest("input")}
	var wire bytes.Buffer
	secret := []byte("sentinel-secret")
	if err := WriteRequest(&wire, request, secret); err != nil {
		t.Fatal(err)
	}
	got, framedSecret, err := ReadRequest(&wire)
	if err != nil || got != request || framedSecret == nil {
		t.Fatalf("ReadRequest()=%#v,%#v,%v", got, framedSecret, err)
	}
	seen := ""
	if err := framedSecret.Use(func(value []byte) error {
		seen = string(value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != string(secret) || framedSecret.Present() {
		t.Fatal("secret was not delivered once and destroyed")
	}
	if err := WriteRequest(&bytes.Buffer{}, Request{Operation: OperationManagementProfile}, secret); err == nil {
		t.Fatal("generic non-secret request accepted a secret frame")
	}

	var queued bytes.Buffer
	first := request
	if err := WriteRequest(&queued, first, secret); err != nil {
		t.Fatal(err)
	}
	// Replace the required secret frame kind with request. The decoder must not
	// accept a queued generic request in its place.
	value := queued.Bytes()
	firstFrameLength := frameHeaderBytes + int(binary.BigEndian.Uint32(value[8:12]))
	value[firstFrameLength+4] = byte(frameRequest)
	if _, _, err := ReadRequest(&queued); !errors.Is(err, ErrProtocol) {
		t.Fatalf("queued request error=%v", err)
	}
}

func TestManagedBasicAndStaticRequestsAreClosed(t *testing.T) {
	now := time.Now().UTC()
	cases := []Request{{SchemaVersion: SchemaVersion, RequestID: "basic-create", Operation: OperationManagedBasicGenerate, Target: "resource/res_00000000000000000000000000000001", IntentGeneration: 1, Deadline: now.Add(time.Minute), Action: &ActionPayload{Operation: "managed_basic_create", TargetKind: "resource", TargetID: "res_00000000000000000000000000000001", ActorIdentity: "session-one", ActorGeneration: 1, Confirmation: "generate", Username: "admin.user"}}, {SchemaVersion: SchemaVersion, RequestID: "static-register", Operation: OperationStaticRootRegister, Target: "resource/res_00000000000000000000000000000001", IntentGeneration: 1, Deadline: now.Add(time.Minute), Action: &ActionPayload{Operation: "static_root_register", TargetKind: "resource", TargetID: "res_00000000000000000000000000000001", ActorIdentity: "session-one", ActorGeneration: 1, Confirmation: "register", StaticRoot: "/srv/application/static"}}}
	for index := range cases {
		digestValue, err := ApplicationInputDigest(cases[index])
		if err != nil {
			t.Fatal(err)
		}
		cases[index].InputDigest = digestValue
		if err := ValidateRequest(cases[index], now); err != nil {
			t.Fatalf("valid request rejected: %v", err)
		}
	}
	unsafe := cases[1]
	unsafe.Action.StaticRoot = "/srv/static\ninclude"
	unsafe.InputDigest, _ = ApplicationInputDigest(unsafe)
	if ValidateRequest(unsafe, now) == nil {
		t.Fatal("unsafe static path accepted")
	}

	rotate := Request{SchemaVersion: SchemaVersion, RequestID: "basic-rotate", Operation: OperationManagedBasicGenerate, Target: "credential/cred_00000000000000000000000000000001", IntentGeneration: 1, Deadline: now.Add(time.Minute), Action: &ActionPayload{Operation: "managed_basic_rotate", TargetKind: "credential", TargetID: "cred_00000000000000000000000000000001", ActorIdentity: "session-one", ActorGeneration: 1, PlanID: "plan_" + strings.Repeat("a", 64), Confirmation: "rotate"}}
	rotate.InputDigest, _ = ApplicationInputDigest(rotate)
	if err := ValidateRequest(rotate, now); err != nil {
		t.Fatalf("valid planned rotate rejected: %v", err)
	}
	rotate.Action.PlanID = ""
	rotate.Action.Confirmation = "generate"
	rotate.InputDigest, _ = ApplicationInputDigest(rotate)
	if ValidateRequest(rotate, now) == nil {
		t.Fatal("planless rotate accepted")
	}

	planResponse := Response{SchemaVersion: SchemaVersion, RequestID: "rotate-plan", Code: ResponseSucceeded, ResultDigest: digest("rotate-plan-result"), Action: &ActionResult{Operation: "managed_basic_rotate", TargetKind: "credential", TargetID: "cred_00000000000000000000000000000001", PlanID: "plan_" + strings.Repeat("b", 64), Confirmation: digest("rotate-nonce"), ExposureSummary: "rotates_managed_basic_credential", Prerequisites: "credential_fingerprint_unchanged", ExpiresAt: now.Add(time.Minute)}}
	if err := ValidateResponse(OperationApplicationPlan, planResponse); err != nil {
		t.Fatalf("planned rotate response rejected: %v", err)
	}
	var wire bytes.Buffer
	if err := WriteResponse(&wire, OperationApplicationPlan, planResponse, nil); err != nil {
		t.Fatal(err)
	}
	decoded, output, err := ReadResponse(&wire, OperationApplicationPlan)
	if err != nil || output != nil || !reflect.DeepEqual(decoded, planResponse) {
		t.Fatalf("planned rotate response round trip=%#v,%#v,%v", decoded, output, err)
	}
}

func TestHeadscaleInitializationRequestAndResponseAreClosed(t *testing.T) {
	now := time.Now().UTC()
	payload := []byte(`{"control_domain":"control.example.test","magicdns_namespace":"mesh.example.test","confirmation":"initialize"}`)
	request := Request{SchemaVersion: SchemaVersion, RequestID: "headscale-initialize", Operation: OperationHeadscaleInitialize, Target: "installation", IntentGeneration: 1, Deadline: now.Add(time.Minute), Resource: &ResourcePayload{Operation: "headscale_initialize", ActorIdentity: "session-one", ActorGeneration: 1, Confirmation: "initialize", Resource: payload}}
	request.InputDigest, _ = ApplicationInputDigest(request)
	if err := ValidateRequest(request, now); err != nil {
		t.Fatal(err)
	}
	response := Response{SchemaVersion: SchemaVersion, RequestID: request.RequestID, Code: ResponseSucceeded, ResultDigest: digest("headscale"), Action: &ActionResult{JobID: "job_00000000000000000000000000000001", Operation: "headscale_initialize", TargetKind: "installation", TargetID: "hds_00000000000000000000000000000001"}}
	if err := ValidateResponse(OperationHeadscaleInitialize, response); err != nil {
		t.Fatal(err)
	}
	failure := Response{SchemaVersion: SchemaVersion, RequestID: request.RequestID, Code: ResponseRejected, ErrorCode: "foreign_database_evidence", ErrorJobID: "job_00000000000000000000000000000001"}
	if err := ValidateResponse(OperationHeadscaleInitialize, failure); err != nil {
		t.Fatal(err)
	}
	failure.ErrorJobID = ""
	if ValidateResponse(OperationHeadscaleInitialize, failure) == nil {
		t.Fatal("foreign-evidence failure omitted its job identity")
	}
	request.Resource.Operation = "publish"
	request.InputDigest, _ = ApplicationInputDigest(request)
	if ValidateRequest(request, now) == nil {
		t.Fatal("non-initialize Headscale request accepted")
	}
	response.Action.TargetID = "res_00000000000000000000000000000001"
	if ValidateResponse(OperationHeadscaleInitialize, response) == nil {
		t.Fatal("non-Headscale result identity accepted")
	}
}

func TestHeadscaleDeployAndReissueTerminalResponses(t *testing.T) {
	cases := []struct {
		name      string
		operation Operation
		action    string
	}{
		{name: "deploy", operation: OperationHeadscaleDeploy, action: "headscale_control_deploy"},
		{name: "reissue", operation: OperationHeadscaleReissue, action: "headscale_certificate_reissue"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := Response{SchemaVersion: SchemaVersion, RequestID: "headscale-" + test.name, Code: ResponseSucceeded, ResultDigest: digest(test.name), Action: &ActionResult{JobID: "job_00000000000000000000000000000001", JobResult: "succeeded", Operation: test.action, TargetKind: "headscale", TargetID: "headscale"}}
			var wire bytes.Buffer
			if err := WriteResponse(&wire, test.operation, response, nil); err != nil {
				t.Fatalf("terminal response rejected: %v", err)
			}
			decoded, output, err := ReadResponse(&wire, test.operation)
			if err != nil || output != nil || !reflect.DeepEqual(decoded, response) {
				t.Fatalf("terminal response round trip=%#v,%#v,%v", decoded, output, err)
			}

			invalid := response
			invalid.Action = new(ActionResult)
			*invalid.Action = *response.Action
			invalid.Action.JobResult = "partial"
			if ValidateResponse(test.operation, invalid) == nil {
				t.Fatal("non-success terminal job result accepted")
			}
			invalid.Action.JobResult = ""
			if ValidateResponse(test.operation, invalid) == nil {
				t.Fatal("terminal response without job result accepted")
			}
			invalid.Action.JobID = ""
			invalid.Action.PlanID = "plan-one"
			invalid.Action.JobResult = "succeeded"
			invalid.Action.ExposureSummary = "deploys Headscale control"
			invalid.Action.Prerequisites = "fresh authority"
			invalid.Action.ExpiresAt = time.Now().UTC().Add(time.Minute)
			if ValidateResponse(test.operation, invalid) == nil {
				t.Fatal("Plan response carrying a terminal job result accepted")
			}
		})
	}
}

func TestDomainStatusRequestAndResponseAreTyped(t *testing.T) {
	now := time.Now().UTC()
	request := Request{SchemaVersion: SchemaVersion, RequestID: "domain-status", Operation: OperationDomainStatus, Target: "resource/res_00000000000000000000000000000001", IntentGeneration: 1, Deadline: now.Add(time.Minute), Action: &ActionPayload{Operation: "status", TargetKind: "resource", TargetID: "res_00000000000000000000000000000001", ActorIdentity: "session-one", ActorGeneration: 1}}
	request.InputDigest, _ = ApplicationInputDigest(request)
	if err := ValidateRequest(request, now); err != nil {
		t.Fatal(err)
	}
	response := Response{SchemaVersion: SchemaVersion, RequestID: request.RequestID, Code: ResponseSucceeded, ResultDigest: digest("status"), Resource: &ResourceResult{ResourceID: request.Action.TargetID, Status: "degraded", AccessMayRemain: true, ObservedAt: now, Reason: "external htpasswd changed", AllowedActions: []string{"unpublish", "close_all"}}}
	if err := ValidateResponse(OperationDomainStatus, response); err != nil {
		t.Fatal(err)
	}
	response.Resource.Status = "healthy"
	response.Resource.AllowedActions = nil
	response.Resource.AccessMayRemain = false
	response.Resource.CredentialID = "cred_00000000000000000000000000000001"
	response.Resource.CredentialChanged = true
	response.Resource.CredentialFingerprint = digest("changed")
	response.Resource.GoAccessCredentialID = "cred_00000000000000000000000000000002"
	response.Resource.GoAccessCredentialChanged = true
	response.Resource.GoAccessCredentialFingerprint = digest("goaccess-changed")
	response.Resource.Reason = "App and GoAccess external htpasswd fingerprints changed but remain valid"
	if err := ValidateResponse(OperationDomainStatus, response); err != nil {
		t.Fatalf("valid changed external status rejected: %v", err)
	}
	response.Resource.Status = "source_verified_runtime_unknown"
	response.Resource.Reason = "source identities exact; runtime health is not proved by source verification"
	if err := ValidateResponse(OperationDomainStatus, response); err != nil {
		t.Fatalf("conservative runtime-unknown status rejected: %v", err)
	}
	response.Resource.Status = "healthy"
	response.Resource.Reason = ""
	if ValidateResponse(OperationDomainStatus, response) == nil {
		t.Fatal("status without remediation reason accepted")
	}
	response.Resource = &ResourceResult{ResourceID: request.Action.TargetID, Status: "degraded", AccessMayRemain: true, ObservedAt: now, Reason: "GoAccess retirement pending", AllowedActions: []string{"unpublish", "close_all"}, GoAccessRetirementJobID: "job-retirement", GoAccessRetirementGenerations: []uint64{2, 4}}
	if err := ValidateResponse(OperationDomainStatus, response); err != nil {
		t.Fatalf("pending GoAccess retirement status rejected: %v", err)
	}
	response.Resource.GoAccessRetirementGenerations = []uint64{4, 2}
	if ValidateResponse(OperationDomainStatus, response) == nil {
		t.Fatal("unsorted GoAccess retirement generations accepted")
	}
}

func TestPublicationRequestAllowsBoundedIssuanceDeadline(t *testing.T) {
	now := time.Now().UTC()
	request := Request{SchemaVersion: SchemaVersion, RequestID: "publish", Operation: OperationPublicationActivate, Target: "resource/res_00000000000000000000000000000001", IntentGeneration: 1, Deadline: now.Add(10 * time.Minute), Resource: &ResourcePayload{Operation: "publish", ActorIdentity: "session-one", ActorGeneration: 1, PlanID: "plan-one", Confirmation: "publish"}}
	request.InputDigest, _ = ApplicationInputDigest(request)
	if err := ValidateRequest(request, now); err != nil {
		t.Fatal(err)
	}
	response := Response{SchemaVersion: SchemaVersion, RequestID: request.RequestID, Code: ResponseSucceeded, ResultDigest: digest("publication"), Action: &ActionResult{JobID: "job-publication", JobResult: "partial", PublicURL: "https://app.example.test/"}}
	if err := ValidateResponse(OperationPublicationActivate, response); err != nil {
		t.Fatalf("partial publication result rejected: %v", err)
	}
	response.Action.JobResult = "unknown"
	if ValidateResponse(OperationPublicationActivate, response) == nil {
		t.Fatal("unknown publication job result accepted")
	}
	request.Deadline = now.Add(12 * time.Minute)
	request.InputDigest, _ = ApplicationInputDigest(request)
	if ValidateRequest(request, now) == nil {
		t.Fatal("unbounded publication deadline accepted")
	}
}

func TestOneTimeOutputSecretIsOutsideGenericResponse(t *testing.T) {
	secret, err := NewOutputSecret([]byte("generated-password"))
	if err != nil {
		t.Fatal(err)
	}
	response := Response{SchemaVersion: SchemaVersion, RequestID: "request-one", Code: ResponseSucceeded, ResultDigest: digest("result"), Action: &ActionResult{JobID: "job_00000000000000000000000000000001", Operation: "managed_basic_rotate", TargetKind: "credential", TargetID: "cred_00000000000000000000000000000001"}}
	var wire bytes.Buffer
	if err := WriteResponse(&wire, OperationManagedBasicGenerate, response, secret); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), wire.Bytes()...)
	genericLength := frameHeaderBytes + int(binary.BigEndian.Uint32(encoded[8:12]))
	if bytes.Contains(encoded[:genericLength], []byte("generated-password")) {
		t.Fatal("output secret entered generic response JSON")
	}
	got, output, err := ReadResponse(bytes.NewReader(encoded), OperationManagedBasicGenerate)
	if err != nil || !reflect.DeepEqual(got, response) || output == nil {
		t.Fatalf("ReadResponse()=%#v,%#v,%v", got, output, err)
	}
	seen := ""
	if err := output.Use(func(value []byte) error { seen = string(value); return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != "generated-password" || output.Present() {
		t.Fatal("one-time output secret was not consumed and destroyed")
	}

	rejected := Response{SchemaVersion: SchemaVersion, RequestID: "request-two", Code: ResponseRejected, ErrorCode: "authority_rejected"}
	wire.Reset()
	if err := WriteResponse(&wire, OperationManagedBasicGenerate, rejected, nil); err != nil {
		t.Fatalf("write rejected secret-output response: %v", err)
	}
	got, output, err = ReadResponse(&wire, OperationManagedBasicGenerate)
	if err != nil || got != rejected || output != nil {
		t.Fatalf("rejected secret-output response=%#v,%#v,%v", got, output, err)
	}
}

func TestApplicationResponseShapeIsOperationBound(t *testing.T) {
	plan := Response{SchemaVersion: SchemaVersion, RequestID: "request-plan", Code: ResponseSucceeded, ResultDigest: digest("result"), Action: &ActionResult{PlanID: "plan-one", Confirmation: digest("confirmation"), Operation: "admin_token_rotate", TargetKind: "installation", ExposureSummary: "admin_token_rotation", Prerequisites: "authenticated_confirmation", ExpiresAt: time.Now().Add(time.Minute)}}
	if err := ValidateResponse(OperationApplicationPlan, plan); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(OperationAdminTokenRotate, plan); err == nil {
		t.Fatal("Plan response entered rotation operation")
	}
	rotation := Response{SchemaVersion: SchemaVersion, RequestID: "request-rotate", Code: ResponseSucceeded, ResultDigest: digest("result"), Action: &ActionResult{JobID: "job-one"}}
	if err := ValidateResponse(OperationAdminTokenRotate, rotation); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(OperationManagementProfile, rotation); err == nil {
		t.Fatal("action result entered unrelated operation")
	}
}

func TestTruncatedFrameClearsAllocatedPayload(t *testing.T) {
	payload := []byte("sentinel-secret")
	var complete bytes.Buffer
	if err := writeFrame(&complete, frameSecret, payload, maxSecretBytes); err != nil {
		t.Fatal(err)
	}
	reader := &capturingTruncatedReader{header: append([]byte(nil), complete.Bytes()[:frameHeaderBytes]...), fragment: payload[:8]}
	if _, err := readFrame(reader, frameSecret, maxSecretBytes); !errors.Is(err, ErrProtocol) {
		t.Fatalf("truncated secret frame error=%v", err)
	}
	if len(reader.destination) != len(payload) {
		t.Fatalf("captured payload bytes=%d want %d", len(reader.destination), len(payload))
	}
	for _, value := range reader.destination {
		if value != 0 {
			t.Fatal("truncated protocol payload was not cleared")
		}
	}
}

func TestProtocolRequiresCanonicalBoundedTypedJSON(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := Request{SchemaVersion: SchemaVersion, RequestID: "request-one", Operation: OperationManagementProfile, Target: "installation", IntentGeneration: 2, Deadline: now.Add(time.Minute), InputDigest: digest("input")}
	var wire bytes.Buffer
	if err := WriteRequest(&wire, request, nil); err != nil {
		t.Fatal(err)
	}
	got, secret, err := ReadRequest(&wire)
	if err != nil || got != request || secret != nil {
		t.Fatalf("ReadRequest()=%#v,%#v,%v", got, secret, err)
	}
	if err := ValidateRequest(got, now); err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"schema_version":"lanpanel.helper.request.v1","request_id":"one","request_id":"two","operation":"management_profile_status","target":"installation","intent_generation":2,"deadline":"2030-01-01T00:00:00Z","input_digest":"` + digest("input") + `"}`)
	wire.Reset()
	if err := writeFrame(&wire, frameRequest, payload, maxRequestBytes); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRequest(&wire); !errors.Is(err, ErrProtocol) {
		t.Fatalf("duplicate-field error=%v", err)
	}

	oversize := make([]byte, frameHeaderBytes)
	copy(oversize, frameMagic[:])
	oversize[4] = byte(frameRequest)
	binary.BigEndian.PutUint32(oversize[8:12], maxRequestBytes+1)
	if _, _, err := ReadRequest(bytes.NewReader(oversize)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversize frame error=%v", err)
	}
}

func TestApplicationPayloadIsOperationBound(t *testing.T) {
	now := time.Now()
	request := Request{SchemaVersion: SchemaVersion, RequestID: "request-action", Operation: OperationApplicationPlan, Target: "installation", IntentGeneration: 1, Deadline: now.Add(time.Minute)}
	request.Action = &ActionPayload{Operation: "admin_token_rotate", TargetKind: "installation", ActorIdentity: "session", ActorGeneration: 1}
	request.InputDigest, _ = ApplicationInputDigest(request)
	if err := ValidateRequest(request, now); err != nil {
		t.Fatal(err)
	}
	request.Action.ActorGeneration++
	if err := ValidateRequest(request, now); err == nil {
		t.Fatal("application payload changed without invalidating its digest")
	}
	request.Action.ActorGeneration--
	request.Operation = OperationManagementProfile
	if err := ValidateRequest(request, now); err == nil {
		t.Fatal("application payload entered unrelated operation")
	}
}

func TestFinalCallerOperationMatrixIsClosed(t *testing.T) {
	expected := []Operation{
		"application_plan", "admin_token_verify", "admin_token_source_status", "management_profile_status",
		"admin_token_rotate", "admin_token_rotate_reconcile", "certificate_renew", "managed_basic_generate",
		"managed_basic_delete", "static_root_register", "external_htpasswd_register", "domain_status",
		"contraction_close", "startup_contraction", "headscale_initialize", "headscale_deploy",
		"headscale_reissue", "headscale_read", "headscale_mutation", "preauth_key_plan", "preauth_key_create", "connector_mutation", "connector_read", "connector_login_plan", "connector_login", "product_read", "resource_delete", "resource_mutation", "process_lifecycle", "publication_activate",
	}
	if len(policies) != len(expected) {
		t.Fatalf("final helper operations=%d, want %d", len(policies), len(expected))
	}
	for _, operation := range expected {
		if _, known := PolicyFor(operation); !known {
			t.Fatalf("P1 helper operation %q missing", operation)
		}
	}
	for _, removed := range []Operation{"package_transaction", "credential_adopt", "edgeone_refresh", "tailscale_auth_import", "tailscale_auth_adopt", "tailscale_admin", "nginx_test", "systemd_transition", "managed_file_commit"} {
		if _, known := PolicyFor(removed); known || Authorized(CallerUI, removed) || Authorized(CallerTimer, removed) || Authorized(CallerRecovery, removed) {
			t.Fatalf("removed helper operation %q remains reachable", removed)
		}
	}
	if Authorized(CallerTimer, OperationApplicationPlan) || Authorized(Caller("foreign"), OperationContractionClose) || !Authorized(CallerTimer, OperationCertificateRenew) || !Authorized(CallerRecovery, OperationStartupContraction) {
		t.Fatal("caller crossed the fixed final helper operation matrix")
	}
	request := Request{SchemaVersion: SchemaVersion, RequestID: "request-one", Operation: OperationManagementProfile, Target: strings.Repeat("x", 257), IntentGeneration: 1, Deadline: time.Now().Add(time.Minute), InputDigest: digest("input")}
	if err := ValidateRequest(request, time.Now()); err == nil {
		t.Fatal("unbounded helper target was accepted")
	}
	request.Target = "installation"
	request.Deadline = time.Now().Add(2 * time.Minute)
	if err := ValidateRequest(request, time.Now()); err == nil {
		t.Fatal("helper request exceeded its release-fixed operation deadline")
	}
	request.Deadline = time.Now().Add(time.Minute)
	request.Operation = "systemd_transition"
	request.Target = "service/ssh.service"
	if err := ValidateRequest(request, time.Now()); err == nil {
		t.Fatal("caller-selected systemd unit entered helper schema")
	}
	request.Operation = OperationAdminTokenRotate
	request.Target = "installation"
	request.Action = &ActionPayload{Operation: "admin_token_rotate", TargetKind: "installation", ActorIdentity: "session", ActorGeneration: 1, PlanID: "plan-one", Confirmation: "rotate"}
	request.InputDigest, _ = ApplicationInputDigest(request)
	policy, known := PolicyFor(request.Operation)
	if !known || !policy.SecretOutput || !Authorized(CallerUI, request.Operation) || Authorized(CallerTimer, request.Operation) || Authorized(CallerRecovery, request.Operation) {
		t.Fatal("admin token one-time secret policy is invalid")
	}
	if err := ValidateRequest(request, time.Now()); err != nil {
		t.Fatalf("admin token rotation request is invalid: %v", err)
	}
}

type capturingTruncatedReader struct {
	header      []byte
	fragment    []byte
	destination []byte
	readHeader  bool
}

func (reader *capturingTruncatedReader) Read(destination []byte) (int, error) {
	if !reader.readHeader {
		reader.readHeader = true
		return copy(destination, reader.header), nil
	}
	if reader.destination == nil {
		reader.destination = destination
		return copy(destination, reader.fragment), io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}

func digest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}
