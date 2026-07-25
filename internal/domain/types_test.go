package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseDiagnosticStatus(t *testing.T) {
	t.Parallel()

	got, err := ParseDiagnosticStatus("manual")
	if err != nil {
		t.Fatalf("ParseDiagnosticStatus(manual) error = %v", err)
	}
	if got != DiagnosticStatusManual {
		t.Fatalf("ParseDiagnosticStatus(manual) = %q", got)
	}
	if _, err := ParseDiagnosticStatus("future"); err == nil {
		t.Fatal("ParseDiagnosticStatus(future) error = nil, want unsupported status failure")
	}
	if _, err := ParseDiagnosticStatus(" manual "); err == nil {
		t.Fatal("ParseDiagnosticStatus(whitespace) error = nil, want exact enum failure")
	}
}

func TestNotApplicableActivationRef(t *testing.T) {
	t.Parallel()

	ref := NotApplicableActivationRef()
	if ref.Kind != ActivationRefNotApplicable || ref.Path != "" {
		t.Fatalf("NotApplicableActivationRef() = %#v", ref)
	}
}

func TestValidateManualConfirmationRecords(t *testing.T) {
	t.Parallel()

	record := ManualConfirmation{
		ConfirmationID: "evt_20260620T120000Z_00112233",
		Reason:         "origin_firewall_confirmed",
		Actor:          Actor{Source: ActorSourceUI, EffectiveUID: 1000, EffectiveUser: "uid:1000"},
		ConfirmedAt:    time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
	if err := ValidateManualConfirmationRecords([]string{"origin-protection-manual"}, []ManualConfirmation{record}); err != nil {
		t.Fatalf("ValidateManualConfirmationRecords() error = %v", err)
	}
	if err := ValidateManualConfirmationRecords([]string{"origin-protection-manual"}, nil); err == nil || !strings.Contains(err.Error(), "missing reason") {
		t.Fatalf("ValidateManualConfirmationRecords(missing) error = %v, want missing reason", err)
	}
	record.Actor.Source = ""
	if err := ValidateManualConfirmationRecords([]string{"origin-protection-manual"}, []ManualConfirmation{record}); err == nil || !strings.Contains(err.Error(), "actor source") {
		t.Fatalf("ValidateManualConfirmationRecords(no actor) error = %v, want actor source", err)
	}
	if _, err := ManualConfirmationReason("unknown-token"); err == nil {
		t.Fatal("ManualConfirmationReason(unknown-token) error = nil, want unsupported token")
	}
}

func TestDiagnosticItemCarriesDecisionMetadata(t *testing.T) {
	t.Parallel()

	item := DiagnosticItem{
		ID:               "origin-protection",
		Status:           DiagnosticStatusUnknown,
		Scope:            DiagnosticScopeResource,
		ResourceID:       "res_example",
		Severity:         DiagnosticSeverityCritical,
		Summary:          "origin protection cannot be verified",
		EvidenceSource:   DiagnosticEvidenceRuntimeProbe,
		ResponsibleParty: DiagnosticResponsibleLocalAdmin,
		BlocksActivation: true,
		Redaction:        RedactionNone,
		RedactionStatus:  RedactionStatusNoSensitiveData,
	}
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"diagnostic_id":"origin-protection"`, `"scope":"resource"`, `"evidence_source":"runtime_probe"`, `"responsible_party":"local_admin"`, `"blocking_activation":true`, `"redaction_status":"no_sensitive_data"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("DiagnosticItem JSON = %s, want %s", data, want)
		}
	}
}

func TestDiagnosticRefCarriesDecisionMetadata(t *testing.T) {
	t.Parallel()

	ref := DiagnosticRef{
		ID:               "host-health:dns",
		Status:           DiagnosticStatusManual,
		Scope:            DiagnosticScopeInstance,
		Severity:         DiagnosticSeverityMedium,
		EvidenceSource:   DiagnosticEvidenceManual,
		ResponsibleParty: DiagnosticResponsibleLocalAdmin,
		Redaction:        RedactionFingerprint,
		RedactionStatus:  RedactionStatusRedacted,
	}
	data, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"diagnostic_id":"host-health:dns"`, `"scope":"instance"`, `"severity":"medium"`, `"evidence_source":"manual_confirmation"`, `"redaction":"fingerprint"`, `"redaction_status":"redacted"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("DiagnosticRef JSON = %s, want %s", data, want)
		}
	}
}

func TestDiagnosticRedactionStatusSerializesExplicitly(t *testing.T) {
	t.Parallel()

	refData, err := json.Marshal(DiagnosticRef{ID: "runtime", Status: DiagnosticStatusPass})
	if err != nil {
		t.Fatalf("Marshal(DiagnosticRef) error = %v", err)
	}
	if !strings.Contains(string(refData), `"redaction_status":""`) {
		t.Fatalf("DiagnosticRef JSON = %s, want explicit empty redaction_status", refData)
	}

	itemData, err := json.Marshal(DiagnosticItem{ID: "runtime", Title: "Runtime", Status: DiagnosticStatusPass, Summary: "runtime check"})
	if err != nil {
		t.Fatalf("Marshal(DiagnosticItem) error = %v", err)
	}
	if !strings.Contains(string(itemData), `"redaction_status":""`) {
		t.Fatalf("DiagnosticItem JSON = %s, want explicit empty redaction_status", itemData)
	}
}

func TestDiagnosticScopesCoverP0Surfaces(t *testing.T) {
	t.Parallel()

	scopes := []domainScopeCarrier{
		{Scope: DiagnosticScopeInstance},
		{Scope: DiagnosticScopeResource},
		{Scope: DiagnosticScopeService},
		{Scope: DiagnosticScopeCertificate},
		{Scope: DiagnosticScopeRealIP},
		{Scope: DiagnosticScopeHeadscale},
		{Scope: DiagnosticScopeGoAccess},
		{Scope: DiagnosticScopeExport},
	}
	data, err := json.Marshal(scopes)
	if err != nil {
		t.Fatalf("Marshal(scopes) error = %v", err)
	}
	for _, want := range []string{`"instance"`, `"resource"`, `"service"`, `"certificate"`, `"realip"`, `"headscale"`, `"goaccess"`, `"export"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("Diagnostic scopes JSON = %s, want %s", data, want)
		}
	}
	for _, forbidden := range []string{`"host"`, `"job"`} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("Diagnostic scopes JSON = %s, must not contain unsupported scope %s", data, forbidden)
		}
	}
}

type domainScopeCarrier struct {
	Scope DiagnosticScope `json:"scope"`
}

func TestJobRecordCarriesActorAndRedactionContract(t *testing.T) {
	t.Parallel()

	startedAt := NewOptionalTime(time.Date(2026, 6, 20, 12, 0, 1, 0, time.UTC))
	completedAt := NewOptionalTime(time.Date(2026, 6, 20, 12, 0, 2, 0, time.UTC))
	record := JobRecord{
		SchemaVersion: JobRecordSchemaVersion,
		ID:            "job_20260620T120000Z_00112233",
		Kind:          JobKindDeploy,
		Status:        JobStatusSucceeded,
		Actor: Actor{
			Source:                  ActorSourceUI,
			EffectiveUID:            0,
			EffectiveUser:           "uid:0",
			ProcessID:               1234,
			SessionIDFingerprint:    "sha256:session",
			RequestSource:           "127.0.0.1:12345",
			StartupTokenFingerprint: "sha256:token",
		},
		CreatedAt:       time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		StartedAt:       startedAt,
		CompletedAt:     completedAt,
		CheckpointRef:   NotApplicableActivationRef(),
		RedactionStatus: RedactionStatusNoSensitiveData,
		ContainsSecret:  false,
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"job_id":"job_20260620T120000Z_00112233"`, `"source":"ui"`, `"effective_uid":0`, `"session_id_fingerprint":"sha256:session"`, `"startup_token_fingerprint":"sha256:token"`, `"redaction_status":"no_sensitive_data"`, `"contains_secret":false`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("JobRecord JSON = %s, want %s", data, want)
		}
	}
}

func TestJobRecordQueuedTimesUseNotApplicable(t *testing.T) {
	t.Parallel()

	record := JobRecord{
		SchemaVersion: JobRecordSchemaVersion,
		ID:            "job_20260620T120000Z_00112233",
		Kind:          JobKindDeploy,
		Status:        JobStatusQueued,
		Actor: Actor{
			Source:        ActorSourceCLI,
			EffectiveUID:  1000,
			EffectiveUser: "uid:1000",
		},
		CreatedAt:       time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		CheckpointRef:   NotApplicableActivationRef(),
		RedactionStatus: RedactionStatusNoSensitiveData,
		ContainsSecret:  false,
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"started_at":"not_applicable"`, `"completed_at":"not_applicable"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("JobRecord JSON = %s, want %s", data, want)
		}
	}
	if strings.Contains(string(data), "0001-01-01") {
		t.Fatalf("JobRecord JSON leaked zero timestamp: %s", data)
	}
}

func TestExposurePlanCarriesP0SchemaFields(t *testing.T) {
	t.Parallel()

	plan := ExposurePlan{
		SchemaVersion: ExposurePlanSchemaVersion,
		PlanID:        "plan_20260620T120000.000000000Z_00112233",
		CreatedAt:     time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		Actor: Actor{
			Source:        ActorSourceCLI,
			EffectiveUID:  1000,
			EffectiveUser: "uid:1000",
		},
		Operation:        ExposurePlanOperationDeploy,
		ResourcesChanged: []string{"res_example"},
		ModifiedPaths:    []string{"/etc/nginx/sites-available/example.conf"},
		BeforeDigest:     "none",
		AfterDigest:      "sha256:abc123",
		Decision: ExposurePlanDecisionSummary{
			Status:                ExposurePlanDecisionManual,
			Blockers:              []string{"origin-protection"},
			RequiredConfirmations: []string{"origin-protection-manual"},
		},
		ActivationPreview: ExposureActivationPreview{
			ReloadServices:        []string{"nginx.service"},
			CertificatesChanged:   []string{"example.com"},
			PublicExposureChanged: true,
		},
		Resource: Resource{
			ID:            "res_example",
			Type:          ResourceTypeHTTPApp,
			Name:          "Example API",
			CanonicalName: "example",
			OwnerScope:    ResourceOwnerScopeLocalInstance,
			ConfigRef:     ResourceConfigRef{Path: "/etc/example.yaml", Digest: "sha256:abc123"},
			State:         ResourceStatePlanned,
			CreatedAt:     "unknown",
			UpdatedAt:     "unknown",
		},
		Access:           AccessSurface{AccessMode: AccessModePublic, RiskLabel: AccessRiskPublicInternet},
		OriginProtection: OriginProtectionConfiguredManual,
	}
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{
		`"schema_version":"lanpanel.exposure_plan.v1"`,
		`"plan_id":"plan_20260620T120000.000000000Z_00112233"`,
		`"operation":"deploy"`,
		`"resources_changed":["res_example"]`,
		`"before_digest":"none"`,
		`"after_digest":"sha256:abc123"`,
		`"decision":{"status":"manual","blockers":["origin-protection"],"required_confirmations":["origin-protection-manual"]}`,
		`"activation_preview":{"reload_services":["nginx.service"],"certificates_changed":["example.com"],"public_exposure_changed":true}`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("ExposurePlan JSON = %s, want %s", data, want)
		}
	}
}

func TestResourceJSONUsesSchemaFieldNames(t *testing.T) {
	t.Parallel()

	resource := Resource{
		ID:            "res_example",
		Type:          ResourceTypeHTTPApp,
		Name:          "API",
		CanonicalName: "api",
		OwnerScope:    ResourceOwnerScopeLocalInstance,
		ConfigRef:     ResourceConfigRef{Path: "/etc/api.yaml", Digest: "sha256:abc123"},
		State:         ResourceStateActive,
		CreatedAt:     "unknown",
		UpdatedAt:     "unknown",
	}
	data, err := json.Marshal(resource)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"resource_id":"res_example"`, `"resource_type":"http_app"`, `"name":"API"`, `"owner_scope":"local_instance"`, `"config_ref":{"path":"/etc/api.yaml","digest":"sha256:abc123"}`, `"state":"active"`, `"created_at":"unknown"`, `"updated_at":"unknown"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("Resource JSON = %s, want %s", data, want)
		}
	}
	for _, stale := range []string{`"id":"res_example"`, `"type":"http_app"`} {
		if strings.Contains(string(data), stale) {
			t.Fatalf("Resource JSON = %s, did not expect stale field %s", data, stale)
		}
	}
}

func TestResourceTargetJSONUsesExplicitKindAndNotApplicableFields(t *testing.T) {
	t.Parallel()

	target := ResourceTarget{
		TargetKind: ResourceTargetKindListen,
		Listen: ListenResourceTarget{
			Address:     "127.0.0.1",
			Port:        3000,
			ServiceName: "api.service",
		},
		NotApplicableFields: []string{"upstream", "private_resource"},
	}
	data, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"target_kind":"listen"`, `"listen":{"address":"127.0.0.1","port":3000,"service_name":"api.service"}`, `"not_applicable_fields":["upstream","private_resource"]`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("ResourceTarget JSON = %s, want %s", data, want)
		}
	}
	if strings.Contains(string(data), `"mode"`) || strings.Contains(string(data), `"address":"127.0.0.1:3000"`) {
		t.Fatalf("ResourceTarget JSON = %s, did not expect legacy raw target fields", data)
	}
}

func TestAccessSurfaceJSONUsesStructuredEntry(t *testing.T) {
	t.Parallel()

	access := AccessSurface{
		AccessMode: AccessModeBrowser,
		PublicEntry: PublicEntry{
			Status:    PublicEntryEnabled,
			Domains:   []string{"api.example.com"},
			TLS:       "enabled",
			NginxSite: "enabled",
		},
		PrivateEntry: PrivateEntry{Status: PrivateEntryNotApplicable},
		RiskLabel:    AccessRiskBrowserAuthRequired,
	}
	data, err := json.Marshal(access)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"access_mode":"browser"`, `"public_entry":{"status":"enabled","domains":["api.example.com"],"tls":"enabled","nginx_site":"enabled"}`, `"private_entry":{"status":"not_applicable"}`, `"risk_label":"browser_auth_required"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("AccessSurface JSON = %s, want %s", data, want)
		}
	}
	if strings.Contains(string(data), `"private_entry":{}`) {
		t.Fatalf("AccessSurface JSON = %s, did not expect ambiguous empty private_entry", data)
	}
}

func TestAccessSurfacePrivateClientMarksPublicEntryNotApplicable(t *testing.T) {
	t.Parallel()

	access := AccessSurface{
		AccessMode: AccessModePrivateClient,
		PublicEntry: PublicEntry{
			Status:              PublicEntryNotApplicable,
			TLS:                 "not_applicable",
			NginxSite:           "not_applicable",
			NotApplicableFields: []string{"domains", "tls", "nginx_site"},
		},
		PrivateEntry: PrivateEntry{Status: PrivateEntryEnabled},
		RiskLabel:    AccessRiskPrivateOnly,
	}
	data, err := json.Marshal(access)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"access_mode":"private_client"`, `"public_entry":{"status":"not_applicable","domains":null,"tls":"not_applicable","nginx_site":"not_applicable","not_applicable_fields":["domains","tls","nginx_site"]}`, `"private_entry":{"status":"enabled"}`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("AccessSurface JSON = %s, want %s", data, want)
		}
	}
}

func TestOptionalTimeRejectsWhitespaceSentinel(t *testing.T) {
	t.Parallel()

	var value OptionalTime
	if err := json.Unmarshal([]byte(`" not_applicable "`), &value); err == nil {
		t.Fatal("Unmarshal(whitespace sentinel) error = nil, want exact sentinel failure")
	}
}
