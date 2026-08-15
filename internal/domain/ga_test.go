package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestTemporaryPublicationRejectsReservedIPv4(t *testing.T) {
	for _, address := range []string{"0.0.0.1", "192.88.99.1", "192.0.2.1", "240.0.0.1"} {
		if err := ValidateTemporaryPublicIPv4(address); err == nil {
			t.Fatalf("reserved address %s accepted", address)
		}
	}
	if err := ValidateTemporaryPublicIPv4("8.8.8.8"); err != nil {
		t.Fatalf("public address rejected: %v", err)
	}
}

func TestInstallationSchema(t *testing.T) {
	t.Run("optional_headscale_allows_local_app", func(t *testing.T) {
		installation := validGAInstallation()
		installation.Headscale = nil
		installation.Connector = nil
		data, err := json.Marshal(installation)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeInstallation(data)
		if err != nil {
			t.Fatalf("DecodeInstallation() error = %v", err)
		}
		if decoded.Headscale != nil || decoded.Connector != nil || len(decoded.Resources) != 1 {
			t.Fatalf("decoded installation = %#v", decoded)
		}
		if err := PublicationPrerequisites(decoded, decoded.Resources[0].ID); err != nil {
			t.Fatalf("local publication prerequisites error = %v", err)
		}
	})

	t.Run("concrete_prerequisite_codes", func(t *testing.T) {
		installation := validGAInstallation()
		installation.Headscale = nil
		installation.Connector = nil
		if err := RequireHeadscale(installation); !errors.As(err, new(PrerequisiteError)) || err.Error() != "headscale_not_configured" {
			t.Fatalf("RequireHeadscale() error = %v", err)
		}
		if err := RequireConnector(installation); !errors.As(err, new(PrerequisiteError)) || err.Error() != "connector_required" {
			t.Fatalf("RequireConnector() error = %v", err)
		}
		for _, code := range []string{"headscale_not_configured", "connector_required", "os_profile_live_unqualified", "dependency_transition_required"} {
			if _, err := ParsePrerequisiteCode(code); err != nil {
				t.Fatalf("ParsePrerequisiteCode(%q) error = %v", code, err)
			}
		}
		for _, rejected := range []string{"mode_incompatible", "license_required", "quota_exceeded", ""} {
			if _, err := ParsePrerequisiteCode(rejected); err == nil {
				t.Fatalf("ParsePrerequisiteCode(%q) error = nil", rejected)
			}
		}
	})

	t.Run("single_schema_round_trip_is_canonical", func(t *testing.T) {
		installation := validGAInstallation()
		data, err := json.Marshal(installation)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeInstallation(data)
		if err != nil {
			t.Fatalf("DecodeInstallation() error = %v", err)
		}
		if !reflect.DeepEqual(decoded, installation) {
			t.Fatalf("round trip changed installation:\n got %#v\nwant %#v", decoded, installation)
		}
	})

	t.Run("single_optional_component_fields", func(t *testing.T) {
		installation := validGAInstallation()
		data, err := json.Marshal(installation)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeInstallation(data); err != nil {
			t.Fatalf("DecodeInstallation() error = %v", err)
		}
		duplicateHeadscale := strings.Replace(string(data), `"headscale":`, `"headscale":null,"headscale":`, 1)
		if _, err := DecodeInstallation([]byte(duplicateHeadscale)); err == nil || !strings.Contains(err.Error(), "duplicate field") {
			t.Fatalf("DecodeInstallation(duplicate headscale) error = %v", err)
		}
	})

	t.Run("strict_decoder_rejects_unknown_and_alpha_fields", func(t *testing.T) {
		installation := validGAInstallation()
		data, err := json.Marshal(installation)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{`"mode":"integrated"`, `"api_version":"lanpanel.io/v1alpha1"`, `"placeholder":true`} {
			mutated := strings.TrimSuffix(string(data), "}") + "," + field + "}"
			if _, err := DecodeInstallation([]byte(mutated)); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("DecodeInstallation(%s) error = %v", field, err)
			}
		}
		mutated := strings.Replace(string(data), `"kind":"local_http"`, `"kind":"listen"`, 1)
		if _, err := DecodeInstallation([]byte(mutated)); err == nil || !strings.Contains(err.Error(), "target kind") {
			t.Fatalf("DecodeInstallation(alpha target) error = %v", err)
		}
		caseAlias := strings.Replace(string(data), `"schema_version"`, `"SCHEMA_VERSION"`, 1)
		if _, err := DecodeInstallation([]byte(caseAlias)); err == nil || !strings.Contains(err.Error(), "non-canonical field") {
			t.Fatalf("DecodeInstallation(case alias) error = %v", err)
		}
	})

	t.Run("commercial_gate_fields_are_impossible", func(t *testing.T) {
		installation := validGAInstallation()
		data, err := json.Marshal(installation)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{`"edition":"enterprise"`, `"license":"required"`, `"quota":1`, `"call_home":true`} {
			mutated := strings.TrimSuffix(string(data), "}") + "," + field + "}"
			if _, err := DecodeInstallation([]byte(mutated)); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("DecodeInstallation(%s) error = %v", field, err)
			}
		}
	})

	t.Run("target_union_is_closed", func(t *testing.T) {
		installation := validGAInstallation()
		resource := &installation.Resources[0]
		resource.Target.TailnetHTTP = &TailnetHTTPTarget{IP: "100.64.0.2", Port: 8080}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "must contain only local_http") {
			t.Fatalf("ValidateInstallation(mixed target) error = %v", err)
		}
		installation = validGAInstallation()
		resource = &installation.Resources[0]
		resource.Target.Kind = "hostname_http"
		resource.Target.LocalHTTP = nil
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "target kind") {
			t.Fatalf("ValidateInstallation(unsupported target) error = %v", err)
		}
	})

	t.Run("target_readiness_and_websocket_are_typed", func(t *testing.T) {
		installation := validGAInstallation()
		resource := &installation.Resources[0]
		resource.Target.ReadinessPath = ""
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "readiness_path") {
			t.Fatalf("ValidateInstallation(missing readiness) error = %v", err)
		}
		installation = validGAInstallation()
		resource = &installation.Resources[0]
		resource.Target.WebSocket = WebSocketReadiness{Enabled: false, Path: "/ws"}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "requires enabled=true") {
			t.Fatalf("ValidateInstallation(disabled websocket path) error = %v", err)
		}
		installation = validGAInstallation()
		installation.Resources[0].Target.WebSocket = WebSocketReadiness{Enabled: true, Path: "/ws-ready"}
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(enabled websocket) error = %v", err)
		}
		for _, invalidPath := range []string{"/a/../ready", "/a//ready", `/a\ready`, "/ready%2fnext", "/bad\x00path"} {
			installation = validGAInstallation()
			installation.Resources[0].Target.ReadinessPath = invalidPath
			if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "normalized absolute HTTP path") {
				t.Fatalf("ValidateInstallation(readiness path %q) error = %v", invalidPath, err)
			}
		}
	})

	t.Run("local_endpoint_realizations_are_closed", func(t *testing.T) {
		for _, local := range []LocalHTTPTarget{
			{EndpointKind: LocalEndpointUnixSocketActivation},
			{EndpointKind: LocalEndpointRelayUnix},
			{EndpointKind: LocalEndpointTCPSocketActivation, TCPAddress: "127.0.0.9", TCPPort: 19001},
		} {
			installation := validGAInstallation()
			installation.Resources[0].Target.LocalHTTP = &local
			if err := ValidateInstallation(installation); err != nil {
				t.Fatalf("ValidateInstallation(%s) error = %v", local.EndpointKind, err)
			}
		}
		installation := validGAInstallation()
		installation.Resources[0].Target.LocalHTTP = &LocalHTTPTarget{EndpointKind: LocalEndpointRelayUnix, TCPAddress: "127.0.0.9", TCPPort: 19001}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "must not include TCP authority") {
			t.Fatalf("ValidateInstallation(relay with TCP) error = %v", err)
		}
	})

	t.Run("managed_process_state_includes_runtime_observation", func(t *testing.T) {
		installation := validGAInstallation()
		installation.Resources[0].ManagedProcess.RuntimeObservation = &RuntimeObservation{
			Status: RuntimeHealthy, ObservedAt: "2026-08-10T00:00:00Z",
		}
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(process observation) error = %v", err)
		}
		installation.Resources[0].ManagedProcess.RuntimeObservation.Status = "started"
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "runtime_observation") {
			t.Fatalf("ValidateInstallation(invalid process observation) error = %v", err)
		}
	})

	t.Run("publication_union_is_closed", func(t *testing.T) {
		installation := validGAInstallation()
		resource := &installation.Resources[0]
		resource.Publication.TemporaryHTTP = &TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 8080}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "must contain only domain_https") {
			t.Fatalf("ValidateInstallation(mixed publication) error = %v", err)
		}
		installation = validGAInstallation()
		resource = &installation.Resources[0]
		resource.Publication.DomainHTTPS.CanonicalDomain = "*.example.com"
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "wildcard") {
			t.Fatalf("ValidateInstallation(wildcard) error = %v", err)
		}
	})

	t.Run("publication_state_preserves_applied_identity", func(t *testing.T) {
		installation := validGAInstallation()
		record := &installation.Resources[0].PublicationRecord
		record.LastAppliedDigest = pointer(testDigest)
		record.LastAppliedBundle = pointerBundle(domainBundle("bundle-old", testDigest))
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(unpublished retained bundle) error = %v", err)
		}
		record.State = PublicationPublished
		record.LastAppliedBundle = nil
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "both be present") {
			t.Fatalf("ValidateInstallation(one-sided applied state) error = %v", err)
		}
	})

	t.Run("publication_type_changes_require_unpublished_state", func(t *testing.T) {
		installation := validGAInstallation()
		resource := &installation.Resources[0]
		resource.Publication = AppPublication{
			Kind:          PublicationTemporaryHTTP,
			TemporaryHTTP: &TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 8080},
		}
		resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
		resource.PublicationRecord.LastAppliedBundle = pointerBundle(domainBundle("old-domain", testDigest))
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(unpublished type change) error = %v", err)
		}

		resource.PublicationRecord.State = PublicationPublished
		resource.PublicationRecord.LastAppliedBundle = pointerBundle(temporaryBundle("temporary", testDigest, "8.8.8.8", 8080))
		resource.Publication.TemporaryHTTP.Port = 8081
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "cannot change before unpublish") {
			t.Fatalf("ValidateInstallation(published temporary edit) error = %v", err)
		}
		resource.Publication = validGAInstallation().Resources[0].Publication
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "kind cannot change") {
			t.Fatalf("ValidateInstallation(published type change) error = %v", err)
		}
	})

	t.Run("publication_bundle_is_kind_complete", func(t *testing.T) {
		installation := validGAInstallation()
		record := &installation.Resources[0].PublicationRecord
		record.LastAppliedDigest = pointer(testDigest)
		incomplete := domainBundle("bundle-incomplete", testDigest)
		incomplete.DomainHTTPS.Certificate.BindingIdentity = ""
		record.LastAppliedBundle = pointerBundle(incomplete)
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "certificate pointer") {
			t.Fatalf("ValidateInstallation(incomplete domain bundle) error = %v", err)
		}

		installation = validGAInstallation()
		resource := &installation.Resources[0]
		resource.Publication = AppPublication{
			Kind:          PublicationTemporaryHTTP,
			TemporaryHTTP: &TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 8080},
		}
		resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
		resource.PublicationRecord.LastAppliedBundle = &PublicationBundle{
			Generation:       1,
			ID:               "temporary-bundle",
			ConfigDigest:     testDigest,
			Kind:             PublicationTemporaryHTTP,
			EndpointIdentity: "temporary-endpoint",
			SiteIdentity:     "temporary-site",
			TemporaryHTTP: &TemporaryHTTPBundleIdentity{
				PublicIPv4:       "8.8.8.8",
				Port:             8080,
				HostAuthority:    "wrong.example:8080",
				ListenerIdentity: "listener-8080",
			},
		}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "host_authority") {
			t.Fatalf("ValidateInstallation(incomplete temporary bundle) error = %v", err)
		}

		installation = validGAInstallation()
		resource = &installation.Resources[0]
		edgeBundle := domainBundle("edge-bundle", testDigest)
		edgeBundle.DomainHTTPS.EdgeOne = EdgeOneBundleIdentity{Enabled: true, PublishBinding: "edge-binding", InitialACLGeneration: 7}
		resource.PublicationRecord.State = PublicationPublished
		resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
		resource.PublicationRecord.LastAppliedBundle = pointerBundle(edgeBundle)
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "requires effective_security") {
			t.Fatalf("ValidateInstallation(EdgeOne without effective security) error = %v", err)
		}
		resource.PublicationRecord.EffectiveSecurity = &EffectiveSecurityIdentity{
			Generation: 7, ACLVersion: "acl-v7", CIDRs: []string{"1.1.1.0/24"}, EffectiveDeadline: "2026-08-17T00:00:00Z",
		}
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(complete EdgeOne identity) error = %v", err)
		}
	})

	t.Run("activation_prior_matches_applied_identity", func(t *testing.T) {
		installation := validGAInstallation()
		resource := &installation.Resources[0]
		applied := domainBundle("bundle-applied", testDigest)
		resource.PublicationRecord.State = PublicationActivating
		resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
		resource.PublicationRecord.LastAppliedBundle = pointerBundle(applied)
		resource.PublicationRecord.ActivationIntent = &ActivationIntent{
			ID: "activation-one", JobID: "job-one", PlanID: "plan-one", Generation: 1,
			Candidate:  domainBundle("bundle-candidate", testDigest),
			PriorState: PublicationPublished,
			Prior:      pointerBundle(domainBundle("bundle-other", testDigest)),
		}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "must match last_applied_bundle") {
			t.Fatalf("ValidateInstallation(mismatched prior) error = %v", err)
		}
		resource.PublicationRecord.ActivationIntent.Prior = pointerBundle(applied)
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(matching prior) error = %v", err)
		}
	})

	t.Run("new_resource_is_sticky_unpublished_without_applied_identity", func(t *testing.T) {
		resource := validGAInstallation().Resources[0]
		record := resource.PublicationRecord
		if record.State != PublicationUnpublished || record.UnpublishedGeneration == 0 || record.LastAppliedDigest != nil || record.LastAppliedBundle != nil || record.ActivationIntent != nil {
			t.Fatalf("new resource publication record = %#v", record)
		}
	})

	t.Run("current_and_applied_digests_stay_distinct", func(t *testing.T) {
		installation := validGAInstallation()
		resource := &installation.Resources[0]
		resource.PublicationRecord.State = PublicationPublished
		resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
		resource.PublicationRecord.LastAppliedBundle = pointerBundle(domainBundle("bundle-old", testDigest))
		resource.PublicationRecord.RuntimeObservation = &RuntimeObservation{Status: RuntimeHealthy, ObservedAt: "2026-08-10T00:00:00Z"}
		resource.CurrentConfigDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(pending config) error = %v", err)
		}
		view := DerivePublicationStatus(*resource, PublicationStatusInput{})
		if view.State != DisplayPublishedHealthy || !view.PendingChanges || *resource.PublicationRecord.LastAppliedDigest == resource.CurrentConfigDigest {
			t.Fatalf("pending config view=%#v record=%#v", view, resource.PublicationRecord)
		}
	})

	t.Run("stable_id_is_explicit", func(t *testing.T) {
		installation := validGAInstallation()
		originalID := installation.Resources[0].ID
		installation.Resources[0].Name = "Renamed Application"
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(rename) error = %v", err)
		}
		if installation.Resources[0].ID != originalID {
			t.Fatalf("resource ID changed from %q to %q", originalID, installation.Resources[0].ID)
		}
	})

	t.Run("status_distinguishes_pending_and_closure", func(t *testing.T) {
		resource := validGAInstallation().Resources[0]
		view := DerivePublicationStatus(resource, PublicationStatusInput{})
		if view.State != DisplayUnpublishedClosed || !view.PendingChanges {
			t.Fatalf("new resource status = %#v", view)
		}
		resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
		resource.PublicationRecord.LastAppliedBundle = pointerBundle(domainBundle("bundle-old", testDigest))
		view = DerivePublicationStatus(resource, PublicationStatusInput{})
		if view.State != DisplayClosingMayBeLive {
			t.Fatalf("unverified contraction status = %#v", view)
		}
		view = DerivePublicationStatus(resource, PublicationStatusInput{ClosureEvidence: &ClosureEvidence{
			ResourceID: resource.ID, UnpublishedGeneration: resource.PublicationRecord.UnpublishedGeneration - 1,
		}})
		if view.State != DisplayClosingMayBeLive {
			t.Fatalf("stale contraction evidence status = %#v", view)
		}
		view = DerivePublicationStatus(resource, PublicationStatusInput{ClosureEvidence: &ClosureEvidence{
			ResourceID: resource.ID, UnpublishedGeneration: resource.PublicationRecord.UnpublishedGeneration,
		}})
		if view.State != DisplayUnpublishedClosed {
			t.Fatalf("verified contraction status = %#v", view)
		}
	})

	t.Run("activating_status_is_may_be_live", func(t *testing.T) {
		installation := validGAInstallation()
		resource := &installation.Resources[0]
		resource.PublicationRecord.State = PublicationActivating
		resource.PublicationRecord.ActivationIntent = &ActivationIntent{
			ID: "activation-first", JobID: "job-one", PlanID: "plan-one", Generation: 1,
			Candidate:  domainBundle("bundle-candidate", testDigest),
			PriorState: PublicationUnpublished,
		}
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(activating) error = %v", err)
		}
		if view := DerivePublicationStatus(*resource, PublicationStatusInput{}); view.State != DisplayActivatingMayBeLive {
			t.Fatalf("activating status = %#v", view)
		}
	})

	t.Run("published_healthy_status_is_distinct", func(t *testing.T) {
		resource := publishedResource(RuntimeHealthy)
		if view := DerivePublicationStatus(resource, PublicationStatusInput{}); view.State != DisplayPublishedHealthy {
			t.Fatalf("published healthy status = %#v", view)
		}
	})

	t.Run("published_degraded_status_is_distinct", func(t *testing.T) {
		resource := publishedResource(RuntimeDegraded)
		if view := DerivePublicationStatus(resource, PublicationStatusInput{}); view.State != DisplayPublishedDegraded {
			t.Fatalf("published degraded status = %#v", view)
		}
	})

	t.Run("published_unknown_status_is_distinct", func(t *testing.T) {
		resource := publishedResource(RuntimeUnknown)
		if view := DerivePublicationStatus(resource, PublicationStatusInput{}); view.State != DisplayPublishedUnknown {
			t.Fatalf("published unknown status = %#v", view)
		}
	})

	t.Run("recent_operation_failure_is_additive", func(t *testing.T) {
		for _, result := range []OperationResult{OperationFailed, OperationPartial, OperationInterrupted, OperationUnknown} {
			resource := validGAInstallation().Resources[0]
			resource.PublicationRecord.LastOperation = OperationPublish
			resource.PublicationRecord.LastOperationResult = result
			view := DerivePublicationStatus(resource, PublicationStatusInput{})
			if view.State != DisplayUnpublishedClosed || !view.RecentOperationFailed {
				t.Fatalf("recent operation %s status = %#v", result, view)
			}
		}
	})

	t.Run("action_vocabulary_is_closed", func(t *testing.T) {
		for _, operation := range []string{
			"instance_config_create", "instance_config_update", "validate", "plan", "deploy", "status", "diagnostics", "configuration_export",
			"admin_token_rotate", "headscale_certificate_reissue", "dependency_upload", "dependency_import", "maintenance",
			"backup_enter", "backup_preparing_abort", "backup_exit", "restore_evidence_import", "restore_cutover",
			"connector_verify", "connector_auth_key_import", "connector_auth_key_adopt", "connector_auth_key_discard", "connector_login", "connector_disconnect", "connector_rebind",
			"resource_create", "resource_update", "resource_delete", "publish", "unpublish", "close_all", "process_start", "process_stop", "unpublish_and_stop",
			"headscale_user_create", "headscale_user_list", "preauth_key_create", "preauth_key_list", "preauth_key_revoke", "device_list", "device_expire",
			"managed_basic_create", "managed_basic_rotate", "managed_basic_delete", "edgeone_diagnostics", "edgeone_refresh", "job_list", "job_detail", "session_logout",
		} {
			if _, err := ParseOperationCode(operation); err != nil {
				t.Fatalf("ParseOperationCode(%q) error = %v", operation, err)
			}
		}
		for _, operation := range []string{"repair", "fix_host", "shell", "mode_incompatible", "license_check", "", " publish"} {
			if _, err := ParseOperationCode(operation); err == nil {
				t.Fatalf("ParseOperationCode(%q) error = nil", operation)
			}
		}
	})

	t.Run("operation_targets_are_closed", func(t *testing.T) {
		valid := []struct {
			operation OperationCode
			target    OperationTarget
		}{
			{OperationDeploy, OperationTarget{Kind: OperationTargetInstallation}},
			{OperationPlan, OperationTarget{Kind: OperationTargetResource, ID: "res_00000000000000000000000000000001"}},
			{OperationPublish, OperationTarget{Kind: OperationTargetResource, ID: "res_00000000000000000000000000000001"}},
			{OperationManagedBasicRotate, OperationTarget{Kind: OperationTargetCredential, ID: "cred_00000000000000000000000000000001"}},
			{OperationPreauthKeyCreate, OperationTarget{Kind: OperationTargetHeadscaleUser, ID: "user-17"}},
			{OperationPreauthKeyRevoke, OperationTarget{Kind: OperationTargetPreauthKey, ID: "key-23"}},
			{OperationDeviceExpire, OperationTarget{Kind: OperationTargetDevice, ID: "node-42"}},
			{OperationJobDetail, OperationTarget{Kind: OperationTargetJob, ID: "job-99"}},
		}
		for _, item := range valid {
			if err := ValidateOperationTarget(item.operation, item.target); err != nil {
				t.Fatalf("ValidateOperationTarget(%s, %#v) error = %v", item.operation, item.target, err)
			}
		}
		for _, invalid := range []struct {
			operation OperationCode
			target    OperationTarget
		}{
			{OperationPublish, OperationTarget{Kind: OperationTargetInstallation}},
			{OperationCloseAll, OperationTarget{Kind: OperationTargetResource, ID: "res_00000000000000000000000000000001"}},
			{OperationResourceDelete, OperationTarget{Kind: OperationTargetResource, ID: "resource-by-filename"}},
			{OperationJobDetail, OperationTarget{Kind: OperationTargetJob, ID: ""}},
		} {
			if err := ValidateOperationTarget(invalid.operation, invalid.target); err == nil {
				t.Fatalf("ValidateOperationTarget(%s, %#v) error = nil", invalid.operation, invalid.target)
			}
		}
	})

	t.Run("result_vocabulary_is_closed", func(t *testing.T) {
		for _, result := range []string{"succeeded", "failed", "partial", "interrupted", "unknown"} {
			if _, err := ParseOperationResult(result); err != nil {
				t.Fatalf("ParseOperationResult(%q) error = %v", result, err)
			}
		}
		for _, result := range []string{"ok", "deferred", "skipped", ""} {
			if _, err := ParseOperationResult(result); err == nil {
				t.Fatalf("ParseOperationResult(%q) error = nil", result)
			}
		}
	})
}

func TestGoAccessRequiresIndependentOwnedExternalCredential(t *testing.T) {
	installation := validGAInstallation()
	resource := &installation.Resources[0]
	resource.Publication.DomainHTTPS.GoAccess = GoAccessPublication{Enabled: true, CredentialID: "cred_00000000000000000000000000000001", DashboardPath: "/__lanpanel/goaccess/", WebSocketPath: "/__lanpanel/goaccess-ws"}
	if ValidateInstallation(installation) == nil {
		t.Fatal("Managed Basic accepted for GoAccess")
	}
	resource.Publication.DomainHTTPS.AccessMode = AppAccessBasic
	resource.Publication.DomainHTTPS.CredentialID = installation.Credentials[0].ID
	external := Credential{ID: "cred_00000000000000000000000000000002", Kind: "external_htpasswd", OwnerResourceID: resource.ID, ExternalPath: "/srv/goaccess.htpasswd", Fingerprint: testDigest}
	installation.Credentials = append(installation.Credentials, external)
	resource.CredentialIDs = append(resource.CredentialIDs, external.ID)
	resource.Publication.DomainHTTPS.GoAccess.CredentialID = external.ID
	installation.Credentials[len(installation.Credentials)-1].ExternalPath = installation.Credentials[0].ManagedPath
	if ValidateInstallation(installation) == nil {
		t.Fatal("Managed Basic effective path reused for GoAccess")
	}
	installation.Credentials[len(installation.Credentials)-1].ExternalPath = "/srv/goaccess.htpasswd"
	if err := ValidateInstallation(installation); err != nil {
		t.Fatal(err)
	}
	resource.Publication.DomainHTTPS.GoAccess.WebSocketPath = resource.Target.ReadinessPath
	if ValidateInstallation(installation) == nil {
		t.Fatal("GoAccess route overlapping target readiness accepted")
	}
	resource.Publication.DomainHTTPS.GoAccess.WebSocketPath = "/__lanpanel/goaccess-ws"
	resource.Publication.DomainHTTPS.GoAccess.DashboardPath = "/reserved/"
	resource.Target.ReadinessPath = "/reserved/live"
	if ValidateInstallation(installation) == nil {
		t.Fatal("GoAccess dashboard prefix shadowing target readiness accepted")
	}
}
func TestInstallationRejectsResourcesBeyondRecoveryCapacity(t *testing.T) {
	installation := validGAInstallation()
	for len(installation.Resources) <= MaximumResources {
		installation.Resources = append(installation.Resources, installation.Resources[0])
	}
	if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "resource limit") {
		t.Fatalf("oversized resource inventory accepted: %v", err)
	}
}

func TestDisabledGoAccessCarriesNoLatentAuthority(t *testing.T) {
	installation := validGAInstallation()
	installation.Resources[0].Publication.DomainHTTPS.GoAccess.DashboardPath = "/__lanpanel/goaccess/"
	if ValidateInstallation(installation) == nil {
		t.Fatal("disabled GoAccess authority accepted")
	}
}

func validGAInstallation() Installation {
	return Installation{
		SchemaVersion:  InstallationSchemaVersion,
		InstallationID: "ins_00000000000000000000000000000001",
		Management: ManagementAuthority{
			Address:      "127.23.45.67",
			Port:         23456,
			ManagedPaths: []string{"/var/lib/lanpanel/ui"},
		},
		Headscale: &HeadscaleDomain{
			ID:                "hds_00000000000000000000000000000001",
			ControlDomain:     "control.example.com",
			MagicDNSNamespace: "tail.example.net",
			ManagedPaths:      []string{"/var/lib/lanpanel/headscale"},
		},
		Connector: &TailnetConnector{
			ID:           "con_00000000000000000000000000000001",
			LoginServer:  "https://control.example.com",
			ManagedPaths: []string{"/var/lib/lanpanel/connector"},
		},
		Credentials:  []Credential{{ID: "cred_00000000000000000000000000000001", Kind: "managed_basic", OwnerResourceID: "res_00000000000000000000000000000001", Username: "admin", ManagedPath: "/etc/lanpanel-public/basic/cred_00000000000000000000000000000001.htpasswd", Fingerprint: testDigest}},
		ManagedPaths: []string{"/var/lib/lanpanel/state"},
		Resources: []AppResource{{
			ID:                  "res_00000000000000000000000000000001",
			Name:                "Example Application",
			Lifecycle:           LifecycleActive,
			CurrentConfigDigest: testDigest,
			Target: AppTarget{
				Kind:                AppTargetLocalHTTP,
				ReadinessPath:       "/ready",
				AllowedHTTPStatuses: []uint16{200, 204},
				WebSocket:           WebSocketReadiness{Enabled: false},
				LocalHTTP:           &LocalHTTPTarget{EndpointKind: LocalEndpointUnixSocketActivation},
			},
			Publication: AppPublication{
				Kind: PublicationDomainHTTPS,
				DomainHTTPS: &DomainHTTPSPublication{
					CanonicalDomain: "app.example.com",
					Aliases:         []string{"alias.example.com"},
					AccessMode:      AppAccessPublic,
				},
			},
			PublicationRecord: PublicationRecord{
				State:                 PublicationUnpublished,
				UnpublishedGeneration: 1,
			},
			ManagedProcess: &ManagedProcess{
				ID:        "proc_00000000000000000000000000000001",
				Requested: ProcessRequestedStopped,
				Service:   ManagedService{Executable: "/usr/local/bin/example-app", WorkingDirectory: "/srv/example-app", WritePaths: []string{"/var/lib/example-app"}},
			},
			CredentialIDs: []string{"cred_00000000000000000000000000000001"},
			ManagedPaths:  []string{"/var/lib/lanpanel/resources/example"},
		}},
	}
}

func publishedResource(health RuntimeHealth) AppResource {
	resource := validGAInstallation().Resources[0]
	resource.PublicationRecord.State = PublicationPublished
	resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
	resource.PublicationRecord.LastAppliedBundle = pointerBundle(domainBundle("bundle-published", testDigest))
	resource.PublicationRecord.RuntimeObservation = &RuntimeObservation{
		Status: health, ObservedAt: "2026-08-10T00:00:00Z",
	}
	return resource
}

func temporaryBundle(id, configDigest, publicIPv4 string, port uint16) PublicationBundle {
	return PublicationBundle{
		ID:               id,
		Generation:       1,
		ConfigDigest:     configDigest,
		Kind:             PublicationTemporaryHTTP,
		EndpointIdentity: "endpoint-" + id,
		SiteIdentity:     "site-" + id,
		Listeners:        []BundleListenerIdentity{{Network: "tcp", Port: port}},
		TemporaryHTTP: &TemporaryHTTPBundleIdentity{
			PublicIPv4: publicIPv4, Port: port, HostAuthority: fmt.Sprintf("%s:%d", publicIPv4, port), ListenerIdentity: "listener-" + id,
		},
	}
}

func domainBundle(id, configDigest string) PublicationBundle {
	return PublicationBundle{
		ID:               id,
		Generation:       1,
		ConfigDigest:     configDigest,
		Kind:             PublicationDomainHTTPS,
		EndpointIdentity: "endpoint-" + id,
		SiteIdentity:     "site-" + id,
		DomainHTTPS: &DomainHTTPSBundleIdentity{
			ExactDomains: []string{"app.example.com", "alias.example.com"},
			Certificate:  completeCertificate("certificate-pointer", "certificate-binding"),
			Auth:         AuthBundleIdentity{Mode: AppAccessPublic},
			Static:       StaticBundleIdentity{RouteIdentities: []string{}},
			GoAccess:     GoAccessBundleIdentity{Enabled: false},
			EdgeOne:      EdgeOneBundleIdentity{Enabled: false},
		},
	}
}

func TestDisabledGoAccessBundleRetainsExactRetirementAuthority(t *testing.T) {
	bundle := domainBundle("pub_1_00000000000000000000000000000001", testDigest)
	bundle.DomainHTTPS.GoAccess = GoAccessBundleIdentity{RetiredGeneration: 1, RetiredStateGeneration: 1, RetiredServiceIdentity: testDigest, RetiredUnitIdentities: []string{testDigest, testDigest, testDigest, testDigest, testDigest}}
	if err := validateBundle(bundle, PublicationDomainHTTPS); err != nil {
		t.Fatalf("retirement authority rejected: %v", err)
	}
	bundle.DomainHTTPS.GoAccess.RetiredServiceIdentity = ""
	if err := validateBundle(bundle, PublicationDomainHTTPS); err == nil {
		t.Fatal("generation-only retirement authority accepted")
	}
}

func completeCertificate(pointer, binding string) CertificateBundleIdentity {
	return CertificateBundleIdentity{PointerIdentity: pointer, BindingIdentity: binding, Generation: 1, Fingerprint: testDigest, SANIdentity: testDigest, ChainIdentity: testDigest, IssuerIdentity: testDigest, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z"}
}
func pointer(value string) *string { return &value }

func pointerBundle(value PublicationBundle) *PublicationBundle { return &value }
