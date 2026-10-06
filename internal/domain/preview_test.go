package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/acmeaccount"
	"reflect"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestManagementHTTPSConfigValidation(t *testing.T) {
	installation := validPreviewInstallation()
	installation.ManagementHTTPS = &ManagementHTTPSConfig{
		Domain: "panel.example.test",
		Certificate: CertificateRequest{
			ChallengeMethod: "http-01",
			DirectoryURL:    "https://acme.example.test/directory",
			TermsAccepted:   true,
		},
		Phase:      ManagementHTTPSPending,
		Generation: 1,
	}
	if err := ValidateInstallation(installation); err != nil {
		t.Fatalf("pending management HTTPS config rejected: %v", err)
	}

	base := *installation.ManagementHTTPS
	for name, mutate := range map[string]func(*ManagementHTTPSConfig){
		"invalid_domain":             func(value *ManagementHTTPSConfig) { value.Domain = "*.example.test" },
		"active_without_certificate": func(value *ManagementHTTPSConfig) { value.Phase = ManagementHTTPSActive },
		"invalid_failure_code":       func(value *ManagementHTTPSConfig) { value.LastFailureCode = "unsafe failure" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			installation.ManagementHTTPS = &candidate
			if err := ValidateInstallation(installation); err == nil {
				t.Fatal("invalid management HTTPS config accepted")
			}
		})
	}
}

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
		installation := validPreviewInstallation()
		installation.Headscale = nil
		data, err := json.Marshal(installation)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeInstallation(data)
		if err != nil {
			t.Fatalf("DecodeInstallation() error = %v", err)
		}
		if decoded.Headscale != nil || len(decoded.Resources) != 1 {
			t.Fatalf("decoded installation = %#v", decoded)
		}
		if err := PublicationPrerequisites(decoded, decoded.Resources[0].ID); err != nil {
			t.Fatalf("local publication prerequisites error = %v", err)
		}
	})

	t.Run("concrete_prerequisite_codes", func(t *testing.T) {
		installation := validPreviewInstallation()
		installation.Headscale = nil
		if err := RequireHeadscale(installation); !errors.As(err, new(PrerequisiteError)) || err.Error() != "headscale_not_configured" {
			t.Fatalf("RequireHeadscale() error = %v", err)
		}
		for _, code := range []string{"headscale_not_configured", "package_identity_drift"} {
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
		installation := validPreviewInstallation()
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
		installation := validPreviewInstallation()
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
		installation := validPreviewInstallation()
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

	t.Run("preview_contract_fields_are_impossible", func(t *testing.T) {
		installation := validPreviewInstallation()
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
		installation := validPreviewInstallation()
		resource := &installation.Resources[0]
		resource.Target.LocalHTTP = nil
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "must contain local_http") {
			t.Fatalf("ValidateInstallation(incomplete target) error = %v", err)
		}
		installation = validPreviewInstallation()
		resource = &installation.Resources[0]
		resource.Target.Kind = "hostname_http"
		resource.Target.LocalHTTP = nil
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "target kind") {
			t.Fatalf("ValidateInstallation(unsupported target) error = %v", err)
		}
	})

	t.Run("target_readiness_and_websocket_are_typed", func(t *testing.T) {
		installation := validPreviewInstallation()
		resource := &installation.Resources[0]
		resource.Target.ReadinessPath = ""
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "readiness_path") {
			t.Fatalf("ValidateInstallation(missing readiness) error = %v", err)
		}
		installation = validPreviewInstallation()
		resource = &installation.Resources[0]
		resource.Target.WebSocket = WebSocketReadiness{Enabled: false, Path: "/ws"}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "requires enabled=true") {
			t.Fatalf("ValidateInstallation(disabled websocket path) error = %v", err)
		}
		installation = validPreviewInstallation()
		installation.Resources[0].Target.WebSocket = WebSocketReadiness{Enabled: true, Path: "/ws-ready"}
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(enabled websocket) error = %v", err)
		}
		for _, invalidPath := range []string{"/a/../ready", "/a//ready", `/a\ready`, "/ready%2fnext", "/bad\x00path"} {
			installation = validPreviewInstallation()
			installation.Resources[0].Target.ReadinessPath = invalidPath
			if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "normalized absolute HTTP path") {
				t.Fatalf("ValidateInstallation(readiness path %q) error = %v", invalidPath, err)
			}
		}
	})

	t.Run("target_readiness_statuses_are_closed", func(t *testing.T) {
		for _, statuses := range [][]uint16{{200}, {401}, {403}, {200, 204, 399, 401, 403}} {
			installation := validPreviewInstallation()
			installation.Resources[0].Target.AllowedHTTPStatuses = statuses
			if err := ValidateInstallation(installation); err != nil {
				t.Fatalf("ValidateInstallation(statuses %v) error = %v", statuses, err)
			}
		}
		for _, statuses := range [][]uint16{{199}, {400}, {402}, {404}, {500}, {200, 200}, {403, 401}} {
			installation := validPreviewInstallation()
			installation.Resources[0].Target.AllowedHTTPStatuses = statuses
			if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "allowed_http_statuses") {
				t.Fatalf("ValidateInstallation(statuses %v) error = %v", statuses, err)
			}
		}
	})

	t.Run("local_endpoint_realizations_are_closed", func(t *testing.T) {
		for _, local := range []LocalHTTPTarget{
			{EndpointKind: LocalEndpointUnixSocketActivation},
			{EndpointKind: LocalEndpointRelayUnix},
			{EndpointKind: LocalEndpointTCPSocketActivation, TCPAddress: "127.0.0.9", TCPPort: 19001},
		} {
			installation := validPreviewInstallation()
			installation.Resources[0].Target.LocalHTTP = &local
			if err := ValidateInstallation(installation); err != nil {
				t.Fatalf("ValidateInstallation(%s) error = %v", local.EndpointKind, err)
			}
		}
		installation := validPreviewInstallation()
		installation.Resources[0].Target.LocalHTTP = &LocalHTTPTarget{EndpointKind: LocalEndpointRelayUnix, TCPAddress: "127.0.0.9", TCPPort: 19001}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "must not include TCP authority") {
			t.Fatalf("ValidateInstallation(relay with TCP) error = %v", err)
		}
	})

	t.Run("managed_process_state_includes_runtime_observation", func(t *testing.T) {
		installation := validPreviewInstallation()
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
		installation := validPreviewInstallation()
		resource := &installation.Resources[0]
		resource.Publication.TemporaryHTTP = &TemporaryIPPublication{PublicIPv4: "8.8.8.8", Port: 8080}
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "must contain only domain_https") {
			t.Fatalf("ValidateInstallation(mixed publication) error = %v", err)
		}
		installation = validPreviewInstallation()
		resource = &installation.Resources[0]
		resource.Publication.DomainHTTPS.CanonicalDomain = "*.example.com"
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "wildcard") {
			t.Fatalf("ValidateInstallation(wildcard) error = %v", err)
		}
	})

	t.Run("publication_state_preserves_applied_identity", func(t *testing.T) {
		installation := validPreviewInstallation()
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
		installation := validPreviewInstallation()
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
		resource.Publication = validPreviewInstallation().Resources[0].Publication
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "kind cannot change") {
			t.Fatalf("ValidateInstallation(published type change) error = %v", err)
		}
	})

	t.Run("publication_bundle_is_kind_complete", func(t *testing.T) {
		installation := validPreviewInstallation()
		record := &installation.Resources[0].PublicationRecord
		record.LastAppliedDigest = pointer(testDigest)
		incomplete := domainBundle("bundle-incomplete", testDigest)
		incomplete.DomainHTTPS.Certificate.BindingIdentity = ""
		record.LastAppliedBundle = pointerBundle(incomplete)
		if err := ValidateInstallation(installation); err == nil || !strings.Contains(err.Error(), "certificate complete identity") {
			t.Fatalf("ValidateInstallation(incomplete domain bundle) error = %v", err)
		}

		installation = validPreviewInstallation()
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
	})

	t.Run("activation_prior_matches_applied_identity", func(t *testing.T) {
		installation := validPreviewInstallation()
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
		resource := validPreviewInstallation().Resources[0]
		record := resource.PublicationRecord
		if record.State != PublicationUnpublished || record.UnpublishedGeneration == 0 || record.LastAppliedDigest != nil || record.LastAppliedBundle != nil || record.ActivationIntent != nil {
			t.Fatalf("new resource publication record = %#v", record)
		}
	})

	t.Run("current_and_applied_digests_stay_distinct", func(t *testing.T) {
		installation := validPreviewInstallation()
		resource := &installation.Resources[0]
		resource.PublicationRecord.State = PublicationPublished
		resource.PublicationRecord.LastAppliedDigest = pointer(testDigest)
		resource.PublicationRecord.LastAppliedBundle = pointerBundle(domainBundle("bundle-old", testDigest))
		resource.PublicationRecord.RuntimeObservation = &RuntimeObservation{Status: RuntimeHealthy, ObservedAt: "2026-08-10T00:00:00Z"}
		resource.CurrentConfigDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(pending config) error = %v", err)
		}
		if *resource.PublicationRecord.LastAppliedDigest == resource.CurrentConfigDigest {
			t.Fatalf("applied digest unexpectedly matches current digest: %#v", resource.PublicationRecord)
		}
	})

	t.Run("stable_id_is_explicit", func(t *testing.T) {
		installation := validPreviewInstallation()
		originalID := installation.Resources[0].ID
		installation.Resources[0].Name = "Renamed Application"
		if err := ValidateInstallation(installation); err != nil {
			t.Fatalf("ValidateInstallation(rename) error = %v", err)
		}
		if installation.Resources[0].ID != originalID {
			t.Fatalf("resource ID changed from %q to %q", originalID, installation.Resources[0].ID)
		}
	})

	t.Run("activating_from_unpublished_is_valid", func(t *testing.T) {
		installation := validPreviewInstallation()
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
	})

	t.Run("action_vocabulary_is_closed", func(t *testing.T) {
		for _, operation := range []string{
			"plan", "status", "admin_token_rotate", "headscale_initialize", "headscale_control_deploy", "headscale_certificate_reissue", "headscale_user_create", "headscale_user_list", "preauth_key_create", "preauth_key_list", "preauth_key_revoke", "device_list", "device_expire", "connector_binding_set", "connector_verify", "connector_login", "resource_delete", "diagnostics", "configuration_export", "job_list", "job_detail",
			"resource_create", "resource_update", "publish", "unpublish", "close_all", "process_start", "process_stop",
			"managed_basic_create", "managed_basic_rotate", "managed_basic_delete", "static_root_register", "external_htpasswd_register",
		} {
			if _, err := ParseOperationCode(operation); err != nil {
				t.Fatalf("ParseOperationCode(%q) error = %v", operation, err)
			}
		}
		for _, operation := range []string{"deploy", "session_logout", "edgeone_refresh", "maintenance", "backup_enter", "repair", "fix_host", "shell", "mode_incompatible", "license_check", "", " publish"} {
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
			{OperationHeadscaleInitialize, OperationTarget{Kind: OperationTargetInstallation}},
			{OperationPlan, OperationTarget{Kind: OperationTargetResource, ID: "res_00000000000000000000000000000001"}},
			{OperationPublish, OperationTarget{Kind: OperationTargetResource, ID: "res_00000000000000000000000000000001"}},
			{OperationManagedBasicRotate, OperationTarget{Kind: OperationTargetCredential, ID: "cred_00000000000000000000000000000001"}},
			{OperationPreauthKeyCreate, OperationTarget{Kind: OperationTargetHeadscaleUser, ID: "17"}},
			{OperationPreauthKeyRevoke, OperationTarget{Kind: OperationTargetPreauthKey, ID: "23"}},
			{OperationDeviceExpire, OperationTarget{Kind: OperationTargetDevice, ID: "42"}},
			{OperationConnectorVerify, OperationTarget{Kind: OperationTargetConnector}},
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
			{OperationResourceUpdate, OperationTarget{Kind: OperationTargetResource, ID: "resource-by-filename"}},
			{OperationManagedBasicDelete, OperationTarget{Kind: OperationTargetCredential, ID: ""}},
			{OperationPreauthKeyRevoke, OperationTarget{Kind: OperationTargetPreauthKey, ID: "key-secret"}},
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
	installation := validPreviewInstallation()
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

func TestInstallationAllowsMoreThan256Resources(t *testing.T) {
	installation := validPreviewInstallation()
	base := installation.Resources[0]
	for index := 2; index <= 257; index++ {
		resource := base
		resource.ID = fmt.Sprintf("res_%032x", index)
		resource.Name = fmt.Sprintf("Application %d", index)
		resource.CredentialIDs = nil
		publication := *base.Publication.DomainHTTPS
		publication.CanonicalDomain = fmt.Sprintf("app-%d.example.com", index)
		publication.Aliases = []string{fmt.Sprintf("alias-%d.example.com", index)}
		resource.Publication.DomainHTTPS = &publication
		process := *base.ManagedProcess
		process.ID = fmt.Sprintf("proc_%032x", index)
		resource.ManagedProcess = &process
		installation.Resources = append(installation.Resources, resource)
	}
	if err := ValidateInstallation(installation); err != nil {
		t.Fatalf("installation with 257 resources rejected: %v", err)
	}
}

func TestDecodeInstallationRejectsConflictingHeadscaleDomains(t *testing.T) {
	for name, mutate := range map[string]func(*HeadscaleDomain){
		"equal": func(headscale *HeadscaleDomain) {
			headscale.MagicDNSNamespace = headscale.ControlDomain
		},
		"control_within_magicdns": func(headscale *HeadscaleDomain) {
			headscale.ControlDomain = "control." + headscale.MagicDNSNamespace
		},
		"magicdns_within_control": func(headscale *HeadscaleDomain) {
			headscale.MagicDNSNamespace = "mesh." + headscale.ControlDomain
		},
	} {
		t.Run(name, func(t *testing.T) {
			installation := validPreviewInstallation()
			mutate(installation.Headscale)
			data, err := json.Marshal(installation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeInstallation(data); err == nil || !strings.Contains(err.Error(), "domains conflict") {
				t.Fatalf("DecodeInstallation(conflicting Headscale domains) error = %v", err)
			}
		})
	}
}

func TestDecodeInstallationRejectsNoncanonicalStaticRootIDs(t *testing.T) {
	for name, id := range map[string]string{
		"non_hex":    "static_0000000000000000000000000000000g",
		"uppercase":  "static_0000000000000000000000000000000A",
		"whitespace": "static_0000000000000000000000000000000 ",
		"control":    "static_0000000000000000000000000000000\x00",
	} {
		t.Run(name, func(t *testing.T) {
			installation := validPreviewInstallation()
			installation.StaticRoots = []StaticContentRoot{{ID: id, OwnerResourceID: installation.Resources[0].ID, Path: "/srv/example-static", Fingerprint: testDigest, Device: 1}}
			data, err := json.Marshal(installation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeInstallation(data); err == nil || !strings.Contains(err.Error(), "static_roots[0] identity invalid") {
				t.Fatalf("DecodeInstallation(static ID %q) error = %v", id, err)
			}
		})
	}
}

func TestDecodeInstallationUsesRuntimeStaticRelativePathGrammar(t *testing.T) {
	const rootID = "static_00000000000000000000000000000001"
	cases := []struct {
		name         string
		relativePath string
		valid        bool
	}{
		{name: "backslash", relativePath: `assets\app.js`},
		{name: "newline", relativePath: "assets/\napp.js"},
		{name: "nul", relativePath: "assets/\x00app.js"},
		{name: "del", relativePath: "assets/\x7fapp.js"},
		{name: "absolute", relativePath: "/etc/passwd"},
		{name: "parent_escape", relativePath: "../secret"},
		{name: "legal_nested", relativePath: "assets/app.js", valid: true},
	}
	layers := []struct {
		name      string
		configure func(*Installation, string)
	}{
		{
			name: "configured_mapping",
			configure: func(installation *Installation, relativePath string) {
				publication := installation.Resources[0].Publication.DomainHTTPS
				publication.StaticRootID = rootID
				publication.StaticMappings = []StaticMapping{{URLPath: "/assets/app.js", RelativePath: relativePath}}
			},
		},
		{
			name: "applied_route",
			configure: func(installation *Installation, relativePath string) {
				bundle := domainBundle("bundle-static-route", testDigest)
				bundle.DomainHTTPS.Static = StaticBundleIdentity{
					RootID: rootID,
					Routes: []StaticRouteBundleIdentity{{
						URLPath:      "/assets/app.js",
						RelativePath: relativePath,
						SourcePath:   "/srv/example-static/assets/app.js",
						Fingerprint:  testDigest,
					}},
					RouteIdentities: []string{testDigest},
				}
				record := &installation.Resources[0].PublicationRecord
				record.LastAppliedDigest = pointer(testDigest)
				record.LastAppliedBundle = &bundle
			},
		},
	}

	for _, layer := range layers {
		t.Run(layer.name, func(t *testing.T) {
			for _, testCase := range cases {
				t.Run(testCase.name, func(t *testing.T) {
					installation := validPreviewInstallation()
					installation.StaticRoots = []StaticContentRoot{{ID: rootID, OwnerResourceID: installation.Resources[0].ID, Path: "/srv/example-static", Fingerprint: testDigest, Device: 1}}
					layer.configure(&installation, testCase.relativePath)
					data, err := json.Marshal(installation)
					if err != nil {
						t.Fatal(err)
					}
					_, err = DecodeInstallation(data)
					if testCase.valid && err != nil {
						t.Fatalf("DecodeInstallation(relative path %q) error = %v", testCase.relativePath, err)
					}
					if !testCase.valid && err == nil {
						t.Fatalf("DecodeInstallation(relative path %q) accepted invalid path", testCase.relativePath)
					}
				})
			}
		})
	}
}

func TestCertificateSANIdentityMatchesStageIssuedSingleDomainVector(t *testing.T) {
	const expected = "sha256:fafc5334b24801d62c56fc90e7850b20e426994cd2b578dcb532a602b9d28c91"
	if got := certificateSANIdentity([]string{"control.example.com"}); got != expected {
		t.Fatalf("single-domain SAN identity = %q, want StageIssued vector %q", got, expected)
	}
}

func TestDomainCertificateSANIdentityMatchesStageIssuedMultiDomainVector(t *testing.T) {
	const expected = "sha256:2d4da7ea966cbf76da0fb0c0f1ded13a4b3765addd7c53f499c4cca12fcf822b"
	if got := certificateSANIdentity([]string{"alias.example.com", "app.example.com"}); got != expected {
		t.Fatalf("multi-domain SAN identity = %q, want StageIssued vector %q", got, expected)
	}
	bundle := domainBundle("bundle-stage-issued-san", testDigest)
	bundle.DomainHTTPS.Certificate.SANIdentity = expected
	if err := validateBundle(bundle, PublicationDomainHTTPS); err != nil {
		t.Fatalf("unsorted exact_domains with StageIssued SAN vector rejected: %v", err)
	}
}

func TestHeadscaleCertificateSANBindsControlDomain(t *testing.T) {
	value := enabledTestHeadscaleDomain()
	if err := ValidateHeadscale(*value); err != nil {
		t.Fatalf("valid Headscale certificate rejected: %v", err)
	}
	value.Certificate.SANIdentity = testDigest
	if err := ValidateHeadscale(*value); err == nil || !strings.Contains(err.Error(), "SAN identity") {
		t.Fatalf("Headscale certificate with wrong SAN digest error = %v", err)
	}
}

func TestHeadscaleCertificateDNSZoneCoversControlDomain(t *testing.T) {
	value := enabledTestHeadscaleDomain()
	authority := &CertificateAuthorityIdentity{CertificateID: value.Applied.CertificateID, DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: testDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: string(acme.ChallengeDNS01), Provider: string(acme.DNSProviderCloudflare), ProfilePath: "/etc/lanpanel/acme/cloudflare.env", ProfileFingerprint: testDigest, CredentialFiles: []CertificateCredentialIdentity{{Key: "CF_DNS_API_TOKEN_FILE", Path: "/etc/lanpanel/acme/cloudflare.token", Fingerprint: testDigest}}, Zone: "example.com"}
	certificate := completeCertificateWithAuthority(authority, []string{value.ControlDomain})
	value.Certificate = &certificate
	if err := ValidateHeadscale(*value); err != nil {
		t.Fatalf("Headscale DNS-01 zone covering control domain rejected: %v", err)
	}
	outsideAuthority := *authority
	outsideAuthority.Zone = "other.example"
	outsideCertificate := completeCertificateWithAuthority(&outsideAuthority, []string{value.ControlDomain})
	value.Certificate = &outsideCertificate
	if err := ValidateHeadscale(*value); err == nil || !strings.Contains(err.Error(), "zone does not cover") {
		t.Fatalf("Headscale DNS-01 zone outside control domain error = %v", err)
	}
}

func TestHeadscaleAppliedRejectsNoncanonicalCertificateIDs(t *testing.T) {
	valid := HeadscaleAppliedIdentity{Generation: 1, ConfigDigest: testDigest, ArtifactDigest: testDigest, ServiceIdentity: testDigest, ControlIdentity: testDigest, CertificateID: "cert_00000000000000000000000000000001"}
	if err := ValidateHeadscaleApplied(valid); err != nil {
		t.Fatalf("valid applied Headscale identity rejected: %v", err)
	}
	for _, certificateID := range []string{
		"cert_0000000000000000000000000000000g",
		"cert_0000000000000000000000000000000A",
		"cert_0000000000000000000000000000000 ",
		"cert_0000000000000000000000000000000\x00",
	} {
		candidate := valid
		candidate.CertificateID = certificateID
		if err := ValidateHeadscaleApplied(candidate); err == nil {
			t.Fatalf("noncanonical certificate ID %q accepted", certificateID)
		}
	}
}

func TestHeadscaleIdentityCannotBeRenamedAdoptedOrDisabled(t *testing.T) {
	prior := *testHeadscaleDomain()
	for name, mutate := range map[string]func(*HeadscaleDomain){
		"control domain": func(value *HeadscaleDomain) { value.ControlDomain = "other.example.com" },
		"database UUID":  func(value *HeadscaleDomain) { value.Database.UUID = "hdb_00000000000000000000000000000002" },
		"SQLite path":    func(value *HeadscaleDomain) { value.Database.SQLitePath = "/var/lib/lanpanel/headscale/other.sqlite" },
		"artifact":       func(value *HeadscaleDomain) { value.Artifact.Version = "0.25.2" },
	} {
		candidate := prior
		mutate(&candidate)
		if err := ValidateHeadscaleTransition(prior, candidate); err == nil {
			t.Fatalf("%s mutation accepted", name)
		}
	}
	initialized := prior
	initialized.Database.Phase = HeadscaleInitialized
	initialized.Database.InitializedDigest = testDigest
	candidate := initialized
	candidate.Database.Phase = HeadscaleIdentityCommitted
	candidate.Database.InitializedDigest = ""
	if err := ValidateHeadscaleTransition(initialized, candidate); err == nil {
		t.Fatal("initialized database was returned to pre-initialized phase")
	}
}

func TestHeadscaleDeployIntentIsExactAndNonApplied(t *testing.T) {
	value := *testHeadscaleDomain()
	value.DeployIntent = &HeadscaleDeployIntent{Generation: 1, PlanID: "plan_control", JobID: "job_control", Phase: HeadscaleDeployPrepared, PreflightDigest: testDigest, CertificateBinding: testDigest, Candidate: HeadscaleAppliedIdentity{Generation: 1, ConfigDigest: testDigest, ArtifactDigest: testDigest, ServiceIdentity: testDigest, ControlIdentity: testDigest, CertificateID: "cert_00000000000000000000000000000001"}}
	value.LastOperation = OperationHeadscaleControlDeploy
	value.LastJobID = "job_control"
	if err := ValidateHeadscale(value); err != nil {
		t.Fatal(err)
	}
	if value.Enabled || value.Applied != nil {
		t.Fatal("prepared Headscale deploy became applied")
	}
	changed := value
	intent := *changed.DeployIntent
	intent.PlanID = ""
	changed.DeployIntent = &intent
	if err := ValidateHeadscale(changed); err == nil {
		t.Fatal("Headscale deploy without Plan authority accepted")
	}
	changed = value
	intent = *changed.DeployIntent
	intent.Candidate.ControlIdentity = ""
	changed.DeployIntent = &intent
	if err := ValidateHeadscale(changed); err == nil {
		t.Fatal("Headscale deploy with incomplete control identity accepted")
	}
	activated := value
	activatedIntent := *activated.DeployIntent
	activatedIntent.Phase = HeadscaleDeployActivated
	activatedIntent.CertificateFingerprint = testDigest
	activatedIntent.ActivationDigest = testDigest
	activatedIntent.RuntimeDigest = testDigest
	activated.DeployIntent = &activatedIntent
	applied := activatedIntent.Candidate
	activated.Applied = &applied
	activated.Enabled = true
	if err := ValidateHeadscale(activated); err != nil {
		t.Fatalf("activated Headscale authority invalid: %v", err)
	}
	activatedIntent.RuntimeDigest = ""
	activated.DeployIntent = &activatedIntent
	if err := ValidateHeadscale(activated); err == nil {
		t.Fatal("activated Headscale without runtime proof accepted")
	}
}

func TestDisabledGoAccessCarriesNoLatentAuthority(t *testing.T) {
	installation := validPreviewInstallation()
	installation.Resources[0].Publication.DomainHTTPS.GoAccess.DashboardPath = "/__lanpanel/goaccess/"
	if ValidateInstallation(installation) == nil {
		t.Fatal("disabled GoAccess authority accepted")
	}
}

func TestCompleteInstallationCanonicalRoundTrip(t *testing.T) {
	installation := validPreviewInstallation()
	installation.Headscale = enabledTestHeadscaleDomain()
	bundle := domainBundle("bundle-complete", testDigest)
	installation.Resources[0].PublicationRecord.State = PublicationPublished
	installation.Resources[0].PublicationRecord.LastAppliedDigest = pointer(testDigest)
	installation.Resources[0].PublicationRecord.LastAppliedBundle = &bundle
	data, err := json.Marshal(installation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInstallation(data)
	if err != nil {
		t.Fatalf("DecodeInstallation(complete installation) error = %v", err)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, data) || !reflect.DeepEqual(decoded, installation) {
		t.Fatal("complete installation did not canonical round-trip")
	}
}

func validPreviewInstallation() Installation {
	return Installation{
		SchemaVersion:  InstallationSchemaVersion,
		InstallationID: "ins_00000000000000000000000000000001",
		Management: ManagementAuthority{
			Address:      "127.23.45.67",
			Port:         23456,
			ManagedPaths: []string{"/var/lib/lanpanel/ui"},
		},
		Headscale:    testHeadscaleDomain(),
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

func testHeadscaleDomain() *HeadscaleDomain {
	return &HeadscaleDomain{ID: "hds_00000000000000000000000000000001", ControlDomain: "control.example.com", MagicDNSNamespace: "tail.example.net", Policy: "trusted_mesh", Artifact: HeadscaleArtifactIdentity{BaselineDigest: testDigest, Version: "0.25.1", ArchiveDigest: testDigest, ExecutableDigest: testDigest, ConfigContract: "headscale-trusted-mesh-v1", ConfigContractDigest: testDigest}, Database: HeadscaleDatabaseIdentity{UUID: "hdb_00000000000000000000000000000001", SQLitePath: "/var/lib/lanpanel/headscale-runtime/db.sqlite", IdentityBundleDigest: testDigest, Generation: 1, Phase: HeadscaleIdentityCommitted}, DesiredDigest: testDigest, ManagedPaths: HeadscaleManagedPaths()}
}

func enabledTestHeadscaleDomain() *HeadscaleDomain {
	value := *testHeadscaleDomain()
	certificateID := "cert_00000000000000000000000000000001"
	applied := HeadscaleAppliedIdentity{Generation: 1, ConfigDigest: testDigest, ArtifactDigest: testDigest, ServiceIdentity: testDigest, ControlIdentity: testDigest, CertificateID: certificateID}
	certificate := completeCertificate(certificateID, []string{value.ControlDomain})
	value.Applied = &applied
	value.Certificate = &certificate
	value.Enabled = true
	return &value
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
			Certificate:  completeCertificate("cert_00000000000000000000000000000002", []string{"alias.example.com", "app.example.com"}),
			Auth:         AuthBundleIdentity{Mode: AppAccessPublic},
			Static:       StaticBundleIdentity{RouteIdentities: []string{}},
			GoAccess:     GoAccessBundleIdentity{Enabled: false},
		},
	}
}

func TestDomainHTTPSBundleRequiresCompleteCertificateAuthority(t *testing.T) {
	valid := domainBundle("bundle-certificate-authority", testDigest)
	if err := validateBundle(valid, PublicationDomainHTTPS); err != nil {
		t.Fatalf("complete HTTP-01 certificate authority rejected: %v", err)
	}
	for name, mutate := range map[string]func(*CertificateBundleIdentity){
		"nil_authority": func(certificate *CertificateBundleIdentity) {
			certificate.Authority = nil
		},
		"incomplete_authority": func(certificate *CertificateBundleIdentity) {
			certificate.Authority.AccountEmail = ""
		},
		"invalid_certificate_id": func(certificate *CertificateBundleIdentity) {
			certificate.Authority.CertificateID = "cert_0000000000000000000000000000000G"
			certificate.PointerIdentity = "/var/lib/lanpanel/certificates/active/" + certificate.Authority.CertificateID + ".current"
		},
		"wrong_active_pointer": func(certificate *CertificateBundleIdentity) {
			certificate.PointerIdentity = "/var/lib/lanpanel/certificates/active/other.current"
		},
		"wrong_san_identity": func(certificate *CertificateBundleIdentity) {
			certificate.SANIdentity = testDigest
		},
		"http_with_dns_field": func(certificate *CertificateBundleIdentity) {
			certificate.Authority.ProfileFingerprint = testDigest
		},
	} {
		t.Run(name, func(t *testing.T) {
			bundle := domainBundle("bundle-"+name, testDigest)
			mutate(&bundle.DomainHTTPS.Certificate)
			if err := validateBundle(bundle, PublicationDomainHTTPS); err == nil {
				t.Fatalf("invalid certificate authority accepted: %#v", bundle.DomainHTTPS.Certificate)
			}
		})
	}

	dnsAuthority := &CertificateAuthorityIdentity{CertificateID: "cert_00000000000000000000000000000003", DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: testDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: string(acme.ChallengeDNS01), Provider: string(acme.DNSProviderCloudflare), ProfilePath: "/etc/lanpanel/acme/cloudflare.env", ProfileFingerprint: testDigest, CredentialFiles: []CertificateCredentialIdentity{{Key: "CF_DNS_API_TOKEN_FILE", Path: "/etc/lanpanel/acme/cloudflare.token", Fingerprint: testDigest}}, Zone: "example.com"}
	dnsBundle := domainBundle("bundle-dns-authority", testDigest)
	dnsBundle.DomainHTTPS.Certificate = completeCertificateWithAuthority(dnsAuthority, []string{"alias.example.com", "app.example.com"})
	if err := validateBundle(dnsBundle, PublicationDomainHTTPS); err != nil {
		t.Fatalf("complete DNS-01 certificate authority rejected: %v", err)
	}
	outsideAuthority := *dnsAuthority
	outsideAuthority.Zone = "other.example"
	outsideBundle := domainBundle("bundle-dns-outside-zone", testDigest)
	outsideBundle.DomainHTTPS.Certificate = completeCertificateWithAuthority(&outsideAuthority, []string{"alias.example.com", "app.example.com"})
	if err := validateBundle(outsideBundle, PublicationDomainHTTPS); err == nil || !strings.Contains(err.Error(), "zone does not cover") {
		t.Fatalf("DNS-01 authority outside exact domains error = %v", err)
	}
	dnsBundle.DomainHTTPS.Certificate.Authority.CredentialFiles = nil
	if err := validateBundle(dnsBundle, PublicationDomainHTTPS); err == nil {
		t.Fatal("DNS-01 authority without required credential files accepted")
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

func completeCertificate(certificateID string, domains []string) CertificateBundleIdentity {
	authority := &CertificateAuthorityIdentity{CertificateID: certificateID, DirectoryURL: "https://acme.example.test/directory", AccountKeyPath: acmeaccount.ManagedKeyPath, AccountKeyFingerprint: testDigest, AccountEmail: "admin@example.test", TermsAccepted: true, Method: string(acme.ChallengeHTTP01), CredentialFiles: []CertificateCredentialIdentity{}}
	return completeCertificateWithAuthority(authority, domains)
}

func completeCertificateWithAuthority(authority *CertificateAuthorityIdentity, domains []string) CertificateBundleIdentity {
	binding, err := validateCertificateAuthority(*authority)
	if err != nil {
		panic(err)
	}
	bindingIdentity, err := acme.BindingDigest(binding)
	if err != nil {
		panic(err)
	}
	return CertificateBundleIdentity{PointerIdentity: "/var/lib/lanpanel/certificates/active/" + authority.CertificateID + ".current", BindingIdentity: bindingIdentity, Generation: 1, Fingerprint: testDigest, SANIdentity: certificateSANIdentity(domains), ChainIdentity: testDigest, IssuerIdentity: testDigest, DirectoryIdentity: testDigest, NotAfter: "2030-01-01T00:00:00Z", LastTrustedWall: "2029-01-01T00:00:00Z", Authority: authority}
}
func pointer(value string) *string { return &value }

func pointerBundle(value PublicationBundle) *PublicationBundle { return &value }
