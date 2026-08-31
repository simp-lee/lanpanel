//go:build linux

package qualification

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"lanpanel/internal/application"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/release"
	"lanpanel/internal/resource"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type contractionResult struct {
	Outcome           string `json:"outcome"`
	AccessClosed      bool   `json:"access_closed"`
	SharedIngressDown bool   `json:"shared_ingress_down"`
	AccessMayRemain   bool   `json:"access_may_remain"`
}

type TailnetPeerAuthority struct {
	SchemaVersion string `json:"schema_version"`
	PeerIP        string `json:"peer_ip"`
	SourceIP      string `json:"source_ip"`
	Port          uint16 `json:"port"`
}

func (executor *LiveExecutor) ensureManagement(ctx context.Context) error {
	if executor.management != nil {
		return nil
	}
	if executor.target == nil {
		return fmt.Errorf("management target is unavailable")
	}
	client, err := OpenManagementClient(ctx, executor.target)
	if err != nil {
		return err
	}
	executor.management = client
	return nil
}

func (executor *LiveExecutor) executeStep(ctx context.Context, step string) (MutationObservation, error) {
	var evidence []byte
	var err error
	switch step {
	case "ui_startup_session_restart":
		evidence, err = executor.stepUISession(ctx)
	case "local_http_websocket":
		evidence, err = executor.stepLocalApp(ctx)
	case "temporary_public_http":
		evidence, err = executor.stepTemporaryHTTP(ctx)
	case "domain_https_controls":
		evidence, err = executor.stepDomainHTTPS(ctx)
	case "app_http01":
		evidence, err = executor.stepAppHTTP01(ctx)
	case "headscale_initialize_http01":
		evidence, err = executor.stepHeadscale(ctx)
	case "headscale_entities":
		evidence, err = executor.stepHeadscaleEntities(ctx)
	case "connector_assisted_login":
		evidence, err = executor.stepConnector(ctx)
	case "tailnet_http_websocket":
		evidence, err = executor.stepTailnet(ctx)
	case "dns01":
		evidence, err = executor.stepDNS01(ctx)
	case "delete_diagnostics_export_close_reboot":
		evidence, err = executor.stepManagementCleanupReboot(ctx)
	case "final_cleanup_inventory":
		evidence, err = executor.stepFinalInventory(ctx)
	default:
		err = fmt.Errorf("trusted live executor step is unknown")
	}
	identity := "step/" + step + "/" + executor.prepared.Input.RunID
	if len(evidence) == 0 {
		evidence = []byte("failed/" + step)
	}
	if err == nil {
		executor.state.CompletedSteps = append(executor.state.CompletedSteps, step)
		slices.Sort(executor.state.CompletedSteps)
		executor.state.CompletedSteps = slices.Compact(executor.state.CompletedSteps)
		if stateErr := executor.states.Write(executor.state); stateErr != nil {
			err = stateErr
		}
	}
	return MutationObservation{Identity: identity, Evidence: evidence}, err
}

func (executor *LiveExecutor) stepUISession(ctx context.Context) ([]byte, error) {
	if err := executor.ensureManagement(ctx); err != nil {
		return nil, err
	}
	before, err := executor.target.readRemoteRegular("/var/lib/lanpanel/installation/admin-token", 4096)
	if err != nil {
		return nil, err
	}
	beforeDigest := release.DigestBytes(before)
	clearBytes(before)
	if err := executor.management.VerifyWebSocket(ctx); err != nil {
		return nil, err
	}
	candidatePath := remoteStagingRoot(executor.prepared.Input.RunID) + "/lanpanel"
	response, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentRestartUI, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes)})
	if err != nil || !response.Succeeded {
		return nil, errors.Join(err, fmt.Errorf("UI restart failed: %s", response.ErrorCode))
	}
	executor.management.Close()
	executor.management = nil
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if err := executor.ensureManagement(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("management UI did not return after restart")
		}
		time.Sleep(2 * time.Second)
	}
	after, err := executor.target.readRemoteRegular("/var/lib/lanpanel/installation/admin-token", 4096)
	if err != nil || release.DigestBytes(after) != beforeDigest {
		clearBytes(after)
		return nil, fmt.Errorf("admin token changed across UI restart: %w", err)
	}
	clearBytes(after)
	return evidence("ui-session", map[string]string{"token_digest": beforeDigest, "restart": response.Evidence, "websocket": "passed"})
}

func (executor *LiveExecutor) stepLocalApp(ctx context.Context) ([]byte, error) {
	if err := executor.ensureManagement(ctx); err != nil {
		return nil, err
	}
	spec := resource.LocalSpec{TargetKind: domain.AppTargetLocalHTTP, Name: "qualification-local-" + executor.prepared.Input.RunID[4:16], EndpointKind: domain.LocalEndpointUnixSocketActivation, ReadinessPath: "/ready", WebSocket: domain.WebSocketReadiness{Enabled: true, Path: "/ws"}, AllowedHTTPStatuses: []uint16{204}, Service: domain.ManagedService{Executable: "/usr/lib/lanpanel/lanpanel", Arguments: []string{"qualification-fixture"}, WorkingDirectory: "/usr/lib/lanpanel", WritePaths: []string{}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: executor.journey.AppDomain, Aliases: []string{executor.journey.AppAlias}, AccessMode: domain.AppAccessPublic, Certificate: &domain.CertificateRequest{ChallengeMethod: "http-01", DirectoryURL: executor.prepared.Input.ACME.DirectoryURL, TermsAccepted: true}, GoAccess: domain.GoAccessPublication{}}}, CredentialIDs: []string{}}
	var created helperproto.ResourceResult
	if _, err := executor.management.Post(ctx, "/api/actions/resource_create", spec, &created); err != nil || created.ResourceID == "" {
		return nil, fmt.Errorf("create local qualification resource: %w", err)
	}
	executor.state.ResourceID = created.ResourceID
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	var started helperproto.ActionResult
	if _, err := executor.management.Post(ctx, "/api/actions/process_start?resource_id="+url.QueryEscape(created.ResourceID), nil, &started); err != nil || started.JobID == "" {
		return nil, fmt.Errorf("start local qualification fixture: %w", err)
	}
	return evidence("local-http-websocket", map[string]string{"resource_id": created.ResourceID, "start_job": started.JobID})
}

func (executor *LiveExecutor) stepTemporaryHTTP(ctx context.Context) ([]byte, error) {
	spec := resource.LocalSpec{TargetKind: domain.AppTargetLocalHTTP, Name: "qualification-temporary-" + executor.prepared.Input.RunID[4:16], EndpointKind: domain.LocalEndpointUnixSocketActivation, ReadinessPath: "/ready", WebSocket: domain.WebSocketReadiness{}, AllowedHTTPStatuses: []uint16{204}, Service: domain.ManagedService{Executable: "/usr/lib/lanpanel/lanpanel", Arguments: []string{"qualification-fixture"}, WorkingDirectory: "/usr/lib/lanpanel", WritePaths: []string{}}, Publication: domain.AppPublication{Kind: domain.PublicationTemporaryHTTP, TemporaryHTTP: &domain.TemporaryIPPublication{PublicIPv4: executor.journey.PublicIPv4, Port: executor.journey.TemporaryHTTPPort}}, CredentialIDs: []string{}}
	var created helperproto.ResourceResult
	if _, err := executor.management.Post(ctx, "/api/actions/resource_create", spec, &created); err != nil || created.ResourceID == "" {
		return nil, fmt.Errorf("create temporary qualification resource: %w", err)
	}
	executor.state.TemporaryResourceID = created.ResourceID
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	if _, err := executor.management.Post(ctx, "/api/actions/process_start?resource_id="+url.QueryEscape(created.ResourceID), nil, &helperproto.ActionResult{}); err != nil {
		return nil, err
	}
	var published application.PublicationResult
	if err := executor.planConfirmation(ctx, "publish", created.ResourceID, "publish", &published); err != nil {
		return nil, err
	}
	probe, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "http", ConnectIPv4: executor.journey.PublicIPv4, Port: executor.journey.TemporaryHTTPPort, Host: executor.journey.PublicIPv4, Path: "/echo", Authorization: "Bearer qualification-sentinel", ExpectedStatus: 200, ExpectedAuthorization: ""})
	if err != nil {
		return nil, err
	}
	if err := executor.planConfirmation(ctx, "unpublish", created.ResourceID, "unpublish", &contractionResult{}); err != nil {
		return nil, err
	}
	if _, err := executor.management.Post(ctx, "/api/actions/process_stop?resource_id="+url.QueryEscape(created.ResourceID), nil, &helperproto.ActionResult{}); err != nil {
		return nil, err
	}
	if err := executor.planConfirmation(ctx, "resource_delete", created.ResourceID, "delete", &application.ResourceDeleteResult{}); err != nil {
		return nil, err
	}
	executor.state.TemporaryResourceID = ""
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	return evidence("temporary-public-http", map[string]string{"publication": published.PublicURL, "probe": release.DigestBytes(probe)})
}

func (executor *LiveExecutor) stepDomainHTTPS(ctx context.Context) ([]byte, error) {
	resourceID, err := executor.requireResource()
	if err != nil {
		return nil, err
	}
	for _, name := range []string{executor.journey.AppDomain, executor.journey.AppAlias} {
		_, err := executor.createARecord(ctx, name)
		if err != nil {
			return nil, err
		}
	}
	if err := waitAuthoritativeDNS(ctx, executor.journey.AuthoritativeZone, []string{executor.journey.AppDomain, executor.journey.AppAlias}, executor.journey.PublicIPv4); err != nil {
		return nil, err
	}
	externalPassword, err := randomSecret(24)
	if err != nil {
		return nil, err
	}
	executor.externalPassword = externalPassword
	candidatePath := remoteStagingRoot(executor.prepared.Input.RunID) + "/lanpanel"
	setup, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentSetupFixture, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes), Secret: externalPassword})
	if err != nil || !setup.Succeeded {
		return nil, errors.Join(err, fmt.Errorf("qualification fixture setup failed: %s", setup.ErrorCode))
	}
	executor.state.FixtureCreated = true
	paths, _ := FixedQualificationFixturePaths(executor.prepared.Input.RunID)
	var basic application.ManagedBasicActionResult
	if _, err := executor.management.Post(ctx, "/api/actions/managed_basic_create?resource_id="+url.QueryEscape(resourceID), application.ManagedBasicPayload{Username: "ga-user", Confirmation: "generate"}, &basic); err != nil || basic.CredentialID == "" || len(basic.Password) == 0 {
		return nil, fmt.Errorf("create Managed Basic qualification credential: %w", err)
	}
	executor.basicPassword = append([]byte(nil), basic.Password...)
	executor.state.BasicCredentialID = basic.CredentialID
	var staticResult helperproto.ActionResult
	if _, err := executor.management.Post(ctx, "/api/actions/static_root_register?resource_id="+url.QueryEscape(resourceID), application.StaticRootPayload{Path: paths.StaticRoot, Confirmation: "register"}, &staticResult); err != nil || staticResult.TargetID == "" {
		return nil, fmt.Errorf("register qualification static root: %w", err)
	}
	executor.state.StaticRootID = staticResult.TargetID
	var externalResult helperproto.ActionResult
	if _, err := executor.management.Post(ctx, "/api/actions/external_htpasswd_register?resource_id="+url.QueryEscape(resourceID), application.StaticRootPayload{Path: paths.HTPasswd, Confirmation: "register"}, &externalResult); err != nil || externalResult.TargetID == "" {
		return nil, fmt.Errorf("register qualification external htpasswd: %w", err)
	}
	executor.state.ExternalCredentialID = externalResult.TargetID
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	publication := executor.domainPublication(domain.AppAccessPublic, "", nil, executor.journey.AppDomain, []string{executor.journey.AppAlias}, domain.CertificateRequest{ChallengeMethod: "http-01", DirectoryURL: executor.prepared.Input.ACME.DirectoryURL, TermsAccepted: true})
	publication.StaticRootID = staticResult.TargetID
	publication.StaticMappings = []domain.StaticMapping{{URLPath: "/static.txt", RelativePath: "live.txt", Anonymous: true}}
	if err := executor.updateDomain(ctx, resourceID, publication); err != nil {
		return nil, err
	}
	if err := executor.planConfirmation(ctx, "publish", resourceID, "publish", &application.PublicationResult{}); err != nil {
		return nil, err
	}
	publicEvidence, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/echo", Authorization: "Bearer public-sentinel", ExpectedStatus: 200, ExpectedAuthorization: ""})
	if err != nil {
		return nil, err
	}
	aliasEvidence, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppAlias, Path: "/echo", ExpectedStatus: 200, ExpectedAuthorization: ""})
	if err != nil {
		return nil, err
	}
	websocketEvidence, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/ws", ExpectedStatus: 101, WebSocket: true})
	if err != nil {
		return nil, err
	}
	staticEvidence, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/static.txt", ExpectedStatus: 200, ExpectedBodyDigest: release.DigestBytes([]byte("lanpanel-live-static\n"))})
	if err != nil {
		return nil, err
	}
	publication.AccessMode = domain.AppAccessApplicationManaged
	if err := executor.updateDomain(ctx, resourceID, publication); err != nil {
		return nil, err
	}
	if _, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/echo", Authorization: "Bearer pending-sentinel", ExpectedStatus: 200, ExpectedAuthorization: ""}); err != nil {
		return nil, fmt.Errorf("pending config affected applied publication: %w", err)
	}
	if err := executor.planConfirmation(ctx, "publish", resourceID, "publish", &application.PublicationResult{}); err != nil {
		return nil, err
	}
	if _, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/echo", Authorization: "Bearer applied-sentinel", ExpectedStatus: 200, ExpectedAuthorization: "Bearer applied-sentinel"}); err != nil {
		return nil, err
	}
	publication.AccessMode = domain.AppAccessBasic
	publication.CredentialID = basic.CredentialID
	publication.CIDRs = []string{executor.vantage.ExpectedSourceIPv4 + "/32"}
	publication.GoAccess = domain.GoAccessPublication{Enabled: true, CredentialID: externalResult.TargetID, CIDRs: []string{executor.vantage.ExpectedSourceIPv4 + "/32"}, DashboardPath: "/analytics/", WebSocketPath: "/analytics-ws"}
	if err := executor.updateDomain(ctx, resourceID, publication); err != nil {
		return nil, err
	}
	if err := executor.planConfirmation(ctx, "publish", resourceID, "publish", &application.PublicationResult{}); err != nil {
		return nil, err
	}
	basicEvidence, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/echo", BasicUsername: "ga-user", BasicPassword: string(executor.basicPassword), ExpectedStatus: 200, ExpectedAuthorization: ""})
	if err != nil {
		return nil, err
	}
	goaccessEvidence, err := retryPublicProbe(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/analytics/", BasicUsername: "ga-dashboard", BasicPassword: string(executor.externalPassword), ExpectedStatus: 200}, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	publication.AccessMode = domain.AppAccessPublic
	publication.CredentialID = ""
	publication.CIDRs = nil
	publication.GoAccess = domain.GoAccessPublication{}
	if err := executor.updateDomain(ctx, resourceID, publication); err != nil {
		return nil, err
	}
	if err := executor.planConfirmation(ctx, "publish", resourceID, "publish", &application.PublicationResult{}); err != nil {
		return nil, err
	}
	credentialQuery := "?credential_id=" + url.QueryEscape(basic.CredentialID)
	credentialPlan, err := executor.management.Plan(ctx, "/api/actions/managed_basic_delete", credentialQuery, struct{}{})
	if err != nil {
		return nil, err
	}
	if _, err := executor.management.Post(ctx, "/api/actions/managed_basic_delete"+credentialQuery, application.ManagedBasicPayload{PlanID: credentialPlan, Confirmation: "delete"}, &application.ManagedBasicActionResult{}); err != nil {
		return nil, err
	}
	executor.state.BasicCredentialID = ""
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	return evidence("domain-https-controls", map[string]string{"public": release.DigestBytes(publicEvidence), "alias": release.DigestBytes(aliasEvidence), "websocket": release.DigestBytes(websocketEvidence), "static": release.DigestBytes(staticEvidence), "basic": release.DigestBytes(basicEvidence), "goaccess": release.DigestBytes(goaccessEvidence), "fixture": setup.Evidence})
}

func (executor *LiveExecutor) stepAppHTTP01(ctx context.Context) ([]byte, error) {
	probe, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.AppDomain, Path: "/echo", BasicUsername: "ga-user", BasicPassword: string(executor.basicPassword), ExpectedStatus: 200, ExpectedAuthorization: ""})
	if err != nil {
		return nil, err
	}
	return evidence("app-http01", map[string]string{"served_certificate_and_cleanup": release.DigestBytes(probe)})
}

func (executor *LiveExecutor) stepHeadscale(ctx context.Context) ([]byte, error) {
	record, err := executor.createARecord(ctx, executor.journey.HeadscaleDomain)
	if err != nil {
		return nil, err
	}
	if err := waitAuthoritativeDNS(ctx, executor.journey.AuthoritativeZone, []string{executor.journey.HeadscaleDomain}, executor.journey.PublicIPv4); err != nil {
		return nil, err
	}
	var initialized helperproto.ActionResult
	payload := application.HeadscaleInitializePayload{ControlDomain: executor.journey.HeadscaleDomain, MagicDNSNamespace: executor.journey.MagicDNSNamespace, SourceKind: "official_canonical_artifact", Confirmation: "initialize"}
	if _, err := executor.management.Post(ctx, "/api/actions/headscale_initialize", payload, &initialized); err != nil {
		return nil, err
	}
	certificate := application.HeadscaleCertificateConfig{ChallengeMethod: "http-01", DirectoryURL: executor.prepared.Input.ACME.DirectoryURL, TermsAccepted: true}
	planPayload := application.HeadscaleDeployPayload{Certificate: certificate}
	planID, err := executor.management.Plan(ctx, "/api/actions/headscale_control_deploy", "", planPayload)
	if err != nil {
		return nil, err
	}
	var deployed helperproto.ActionResult
	if _, err := executor.management.Post(ctx, "/api/actions/headscale_control_deploy", application.HeadscaleDeployPayload{PlanID: planID, Confirmation: "deploy", Certificate: certificate}, &deployed); err != nil {
		return nil, err
	}
	probe, err := retryPublicProbe(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.HeadscaleDomain, Path: "/health", ExpectedStatus: 200}, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	derp, err := ProbeDERP(ctx, executor.journey.PublicIPv4, executor.journey.HeadscaleDomain)
	if err != nil {
		return nil, err
	}
	stun, err := ProbeSTUN(ctx, executor.vantage, executor.journey.PublicIPv4)
	if err != nil {
		return nil, err
	}
	return evidence("headscale-http01", map[string]string{"initialize_job": initialized.JobID, "deploy_job": deployed.JobID, "control_https": release.DigestBytes(probe), "derp": release.DigestBytes(derp), "stun": release.DigestBytes(stun), "dns_record": record.ID})
}

func (executor *LiveExecutor) stepHeadscaleEntities(ctx context.Context) ([]byte, error) {
	var created application.HeadscaleUserResult
	if _, err := executor.management.Post(ctx, "/api/actions/headscale_user_create", application.HeadscaleUserPayload{Name: "qualification"}, &created); err != nil || created.User.ID == 0 {
		return nil, fmt.Errorf("create qualification Headscale user: %w", err)
	}
	executor.state.HeadscaleUserID = strconv.FormatUint(created.User.ID, 10)
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	query := "?user_id=" + url.QueryEscape(executor.state.HeadscaleUserID)
	planBody := application.HeadscaleLifecyclePayload{ExpirationSeconds: 3600}
	planID, err := executor.management.Plan(ctx, "/api/actions/preauth_key_create", query, planBody)
	if err != nil {
		return nil, err
	}
	var key application.HeadscaleKeyResult
	if _, err := executor.management.Post(ctx, "/api/actions/preauth_key_create"+query, application.HeadscaleLifecyclePayload{PlanID: planID, Confirmation: "create", ExpirationSeconds: 3600}, &key); err != nil || key.Key.ID == 0 || len(key.Secret) == 0 {
		return nil, fmt.Errorf("create qualification Headscale preauth key: %w", err)
	}
	executor.preauthKey = append([]byte(nil), key.Secret...)
	executor.state.PreauthKeyID = strconv.FormatUint(key.Key.ID, 10)
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	var users application.HeadscaleUsersResult
	var keys application.HeadscaleKeysResult
	var devices application.HeadscaleDevicesResult
	if _, err := executor.management.Post(ctx, "/api/actions/headscale_user_list", struct{}{}, &users); err != nil {
		return nil, err
	}
	if _, err := executor.management.Post(ctx, "/api/actions/preauth_key_list", struct{}{}, &keys); err != nil {
		return nil, err
	}
	if _, err := executor.management.Post(ctx, "/api/actions/device_list", struct{}{}, &devices); err != nil {
		return nil, err
	}
	return evidence("headscale-entities", map[string]string{"user_id": executor.state.HeadscaleUserID, "key_id": executor.state.PreauthKeyID, "device_count_before_connector": strconv.Itoa(len(devices.Devices))})
}

func (executor *LiveExecutor) stepConnector(ctx context.Context) ([]byte, error) {
	if len(executor.preauthKey) == 0 {
		return nil, fmt.Errorf("one-time connector key is unavailable")
	}
	if _, err := executor.management.Post(ctx, "/api/actions/connector_verify", struct{}{}, &helperproto.ConnectorResult{}); err == nil {
		return nil, fmt.Errorf("connector unexpectedly verified before binding/login")
	}
	controlURL := "https://" + executor.journey.HeadscaleDomain
	var binding application.ConnectorMutationResult
	if _, err := executor.management.Post(ctx, "/api/actions/connector_binding_set", application.ConnectorBindingPayload{ControlURL: controlURL}, &binding); err != nil || binding.JobID == "" {
		return nil, errors.Join(err, fmt.Errorf("connector binding did not return a job identity"))
	}
	executor.state.ConnectorBound = true
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	planID, err := executor.management.Plan(ctx, "/api/actions/connector_login", "", application.ConnectorLoginActionPayload{})
	if err != nil {
		return nil, err
	}
	var loggedIn application.ConnectorMutationResult
	if _, err := executor.management.Post(ctx, "/api/actions/connector_login", application.ConnectorLoginActionPayload{PlanID: planID, Confirmation: "login", AuthKey: executor.preauthKey}, &loggedIn); err != nil || loggedIn.JobID == "" {
		return nil, err
	}
	var verified application.ConnectorVerifyResult
	if _, err := executor.management.Post(ctx, "/api/actions/connector_verify", struct{}{}, &verified); err != nil || verified.Observation.ControlURL != controlURL || len(verified.Observation.LocalIPs) == 0 {
		return nil, fmt.Errorf("connector post-login verification failed: %w", err)
	}
	var devices application.HeadscaleDevicesResult
	if _, err := executor.management.Post(ctx, "/api/actions/device_list", struct{}{}, &devices); err != nil || len(devices.Devices) == 0 {
		return nil, fmt.Errorf("connector device was not visible in Headscale: %w", err)
	}
	device := devices.Devices[len(devices.Devices)-1]
	executor.state.ConnectorDeviceID = strconv.FormatUint(device.ID, 10)
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	if len(device.IPAddresses) == 0 {
		return nil, fmt.Errorf("connector device has no MagicDNS address")
	}
	magicName := strings.ToLower(strings.TrimSuffix(device.Name, ".") + "." + executor.journey.MagicDNSNamespace)
	candidatePath := remoteStagingRoot(executor.prepared.Input.RunID) + "/lanpanel"
	magic, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentMagicDNSProbe, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes), ProbeName: magicName, ExpectedIP: device.IPAddresses[0]})
	if err != nil || !magic.Succeeded {
		return nil, errors.Join(err, fmt.Errorf("MagicDNS probe failed: %s", magic.ErrorCode))
	}
	return evidence("connector-assisted-login", map[string]string{"control_url": verified.Observation.ControlURL, "local_ip": verified.Observation.LocalIPs[0].String(), "device_id": executor.state.ConnectorDeviceID, "magicdns": magic.Evidence})
}

func (executor *LiveExecutor) stepTailnet(ctx context.Context) ([]byte, error) {
	if !executor.journey.TailnetLiveEnabled {
		return evidence("tailnet-not-live-tested", map[string]string{"status": "not_live_tested"})
	}
	peer, peerDigest, err := loadTailnetPeer(executor.prepared.Input.TailnetPeerRef)
	if err != nil || peerDigest != executor.prepared.TailnetPeerDigest {
		return nil, errors.Join(err, fmt.Errorf("tailnet peer authority changed"))
	}
	_, err = executor.createARecord(ctx, executor.journey.TailnetDomain)
	if err != nil {
		return nil, err
	}
	spec := resource.TailnetSpec{TargetKind: domain.AppTargetTailnetHTTP, Name: "qualification-tailnet-" + executor.prepared.Input.RunID[4:16], PeerIP: peer.PeerIP, SourceIP: peer.SourceIP, Port: peer.Port, ReadinessPath: "/ready", WebSocket: domain.WebSocketReadiness{Enabled: true, Path: "/ws"}, AllowedHTTPStatuses: []uint16{204}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS, DomainHTTPS: &domain.DomainHTTPSPublication{CanonicalDomain: executor.journey.TailnetDomain, AccessMode: domain.AppAccessPublic, Certificate: &domain.CertificateRequest{ChallengeMethod: "http-01", DirectoryURL: executor.prepared.Input.ACME.DirectoryURL, TermsAccepted: true}}}, CredentialIDs: []string{}}
	var created helperproto.ResourceResult
	if _, err := executor.management.Post(ctx, "/api/actions/resource_create", spec, &created); err != nil || created.ResourceID == "" {
		return nil, fmt.Errorf("create tailnet qualification resource: %w", err)
	}
	executor.state.TailnetResourceID = created.ResourceID
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	if err := waitAuthoritativeDNS(ctx, executor.journey.AuthoritativeZone, []string{executor.journey.TailnetDomain}, executor.journey.PublicIPv4); err != nil {
		return nil, err
	}
	if err := executor.planConfirmation(ctx, "publish", created.ResourceID, "publish", &application.PublicationResult{}); err != nil {
		return nil, err
	}
	httpEvidence, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.TailnetDomain, Path: "/ready", ExpectedStatus: 204})
	if err != nil {
		return nil, err
	}
	websocketEvidence, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.TailnetDomain, Path: "/ws", ExpectedStatus: 101, WebSocket: true})
	if err != nil {
		return nil, err
	}
	return evidence("tailnet-live", map[string]string{"http": release.DigestBytes(httpEvidence), "websocket": release.DigestBytes(websocketEvidence), "resource_id": created.ResourceID})
}

func (executor *LiveExecutor) stepDNS01(ctx context.Context) ([]byte, error) {
	resourceID, err := executor.requireResource()
	if err != nil {
		return nil, err
	}
	candidatePath := remoteStagingRoot(executor.prepared.Input.RunID) + "/lanpanel"
	setup, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentSetupDNSProfile, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes), Provider: "cloudflare", Secret: append([]byte(nil), executor.cloudflare.token...)})
	if err != nil || !setup.Succeeded {
		return nil, errors.Join(err, fmt.Errorf("DNS profile setup failed: %s", setup.ErrorCode))
	}
	executor.state.DNSProfileCreated = true
	_, err = executor.createARecord(ctx, executor.journey.DNS01Domain)
	if err != nil {
		return nil, err
	}
	if err := waitAuthoritativeDNS(ctx, executor.journey.AuthoritativeZone, []string{executor.journey.DNS01Domain}, executor.journey.PublicIPv4); err != nil {
		return nil, err
	}
	if err := executor.cloudflare.RequireNoTXT(ctx, "_acme-challenge."+executor.journey.DNS01Domain); err != nil {
		return nil, err
	}
	paths, _ := FixedQualificationFixturePaths(executor.prepared.Input.RunID)
	publication := executor.domainPublication(domain.AppAccessPublic, "", nil, executor.journey.DNS01Domain, nil, domain.CertificateRequest{ChallengeMethod: "dns-01", DirectoryURL: executor.prepared.Input.ACME.DirectoryURL, TermsAccepted: true, DNSProvider: "cloudflare", ProviderProfilePath: paths.DNSProfile, AuthoritativeZone: executor.journey.AuthoritativeZone})
	if err := executor.updateDomain(ctx, resourceID, publication); err != nil {
		return nil, err
	}
	if err := executor.planConfirmation(ctx, "publish", resourceID, "publish", &application.PublicationResult{}); err != nil {
		return nil, err
	}
	if err := executor.cloudflare.RequireNoTXT(ctx, "_acme-challenge."+executor.journey.DNS01Domain); err != nil {
		return nil, err
	}
	if err := waitAuthoritativeNoTXT(ctx, executor.journey.AuthoritativeZone, "_acme-challenge."+executor.journey.DNS01Domain); err != nil {
		return nil, err
	}
	probe, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.DNS01Domain, Path: "/echo", ExpectedStatus: 200, ExpectedAuthorization: ""})
	if err != nil {
		return nil, err
	}
	return evidence("dns01", map[string]string{"provider": "cloudflare", "https": release.DigestBytes(probe), "txt_cleanup": "verified", "profile": setup.Evidence})
}

func (executor *LiveExecutor) stepManagementCleanupReboot(ctx context.Context) ([]byte, error) {
	planID, err := executor.management.Plan(ctx, "/api/actions/close_all", "", struct{}{})
	if err != nil {
		return nil, err
	}
	var contraction contractionResult
	if _, err := executor.management.Post(ctx, "/api/actions/close_all", application.ConfirmationPayload{PlanID: planID, Confirmation: "close"}, &contraction); err != nil || contraction.Outcome == "" || !contraction.AccessClosed || contraction.AccessMayRemain {
		return nil, errors.Join(err, fmt.Errorf("close-all did not prove exact access closure"))
	}
	executor.state.CloseAllCommitted = true
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	closedBefore, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "http", ConnectIPv4: executor.journey.PublicIPv4, Port: 80, Host: executor.journey.DNS01Domain, Path: "/closed-check", ExpectedStatus: 421})
	if err != nil {
		return nil, fmt.Errorf("close-all did not reject App ingress: %w", err)
	}
	tokenBefore, err := executor.target.readRemoteRegular("/var/lib/lanpanel/installation/admin-token", 4096)
	if err != nil {
		return nil, err
	}
	tokenDigest := release.DigestBytes(tokenBefore)
	clearBytes(tokenBefore)
	bootBefore, err := executor.target.readRemoteVirtual("/proc/sys/kernel/random/boot_id", 4096)
	if err != nil {
		return nil, err
	}
	candidatePath := remoteStagingRoot(executor.prepared.Input.RunID) + "/lanpanel"
	rebootResponse, rebootErr := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentReboot, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes)})
	if executor.management != nil {
		executor.management.Close()
		executor.management = nil
	}
	_ = executor.target.Close()
	executor.target = nil
	if rebootErr == nil && !rebootResponse.Succeeded {
		return nil, fmt.Errorf("reboot agent rejected submission: %s", rebootResponse.ErrorCode)
	}
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		target, err := OpenSSH(ctx, executor.prepared.Input.SSH)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		fingerprint, _, observeErr := target.ObserveQualificationHost(ctx, executor.prepared.Install.Identity().Profile)
		bootAfter, bootErr := target.readRemoteVirtual("/proc/sys/kernel/random/boot_id", 4096)
		if observeErr == nil && bootErr == nil && fingerprint == executor.prepared.Input.SSH.MachineFingerprint && strings.TrimSpace(string(bootAfter)) != strings.TrimSpace(string(bootBefore)) {
			executor.target = target
			break
		}
		_ = target.Close()
		time.Sleep(5 * time.Second)
	}
	if executor.target == nil {
		return nil, fmt.Errorf("target did not complete an observed reboot")
	}
	tokenAfter, err := executor.target.readRemoteRegular("/var/lib/lanpanel/installation/admin-token", 4096)
	if err != nil || release.DigestBytes(tokenAfter) != tokenDigest {
		clearBytes(tokenAfter)
		return nil, errors.Join(err, fmt.Errorf("admin token changed across reboot"))
	}
	clearBytes(tokenAfter)
	if err := executor.ensureManagement(ctx); err != nil {
		return nil, err
	}
	closedAfter, err := ProbePublic(ctx, executor.vantage, PublicProbe{Scheme: "http", ConnectIPv4: executor.journey.PublicIPv4, Port: 80, Host: executor.journey.DNS01Domain, Path: "/closed-check", ExpectedStatus: 421})
	if err != nil {
		return nil, fmt.Errorf("sticky closure did not survive reboot: %w", err)
	}
	if _, err := retryPublicProbe(ctx, executor.vantage, PublicProbe{Scheme: "https", ConnectIPv4: executor.journey.PublicIPv4, Port: 443, Host: executor.journey.HeadscaleDomain, Path: "/health", ExpectedStatus: 200}, 2*time.Minute); err != nil {
		return nil, fmt.Errorf("headscale control did not survive reboot: %w", err)
	}
	var connectorAfterReboot application.ConnectorVerifyResult
	if _, err := executor.management.Post(ctx, "/api/actions/connector_verify", struct{}{}, &connectorAfterReboot); err != nil || connectorAfterReboot.Observation.ControlURL != "https://"+executor.journey.HeadscaleDomain || len(connectorAfterReboot.Observation.LocalIPs) == 0 {
		return nil, errors.Join(err, fmt.Errorf("connector did not survive reboot"))
	}
	if executor.state.ConnectorDeviceID != "" {
		query := "?device_id=" + url.QueryEscape(executor.state.ConnectorDeviceID)
		planID, err := executor.management.Plan(ctx, "/api/actions/device_expire", query, application.HeadscaleLifecyclePayload{})
		if err != nil {
			return nil, err
		}
		if _, err := executor.management.Post(ctx, "/api/actions/device_expire"+query, application.HeadscaleLifecyclePayload{PlanID: planID, Confirmation: "expire"}, &application.HeadscaleDeviceResult{}); err != nil {
			return nil, err
		}
	}
	if err := executor.cleanupLiveEffects(ctx); err != nil {
		return nil, err
	}
	var diagnostics application.DiagnosticsResult
	var exported application.ConfigurationExport
	var jobs application.JobsResult
	if _, err := executor.management.Post(ctx, "/api/actions/diagnostics", struct{}{}, &diagnostics); err != nil || diagnostics.ObservedAt.IsZero() {
		return nil, errors.Join(err, fmt.Errorf("diagnostics observation is incomplete"))
	}
	if _, err := executor.management.Post(ctx, "/api/actions/configuration_export", struct{}{}, &exported); err != nil || exported.SchemaVersion != "lanpanel.configuration-export.v1" || len(exported.Installation.Resources) != 0 || len(exported.Installation.StaticRoots) != 0 || len(exported.Installation.Credentials) != 0 {
		return nil, errors.Join(err, fmt.Errorf("configuration export retains qualification resources"))
	}
	if _, err := executor.management.Post(ctx, "/api/actions/job_list", struct{}{}, &jobs); err != nil || len(jobs.Jobs) == 0 {
		return nil, errors.Join(err, fmt.Errorf("job inventory is incomplete"))
	}
	return evidence("management-cleanup-reboot", map[string]string{"close_before": release.DigestBytes(closedBefore), "close_after": release.DigestBytes(closedAfter), "token_digest": tokenDigest, "diagnostics": "read", "configuration_export": "read", "jobs": "read", "reboot": "verified"})
}

func (executor *LiveExecutor) stepFinalInventory(ctx context.Context) ([]byte, error) {
	if len(executor.state.DNSCreateIntents) != 0 || len(executor.state.CloudflareRecords) != 1 || executor.state.CloudflareRecords[0].Name != executor.journey.HeadscaleDomain {
		return nil, fmt.Errorf("final DNS state inventory contains uncommitted or unexpected objects")
	}
	nonRetained := []string{executor.journey.AppDomain, executor.journey.AppAlias, executor.journey.DNS01Domain}
	if executor.journey.TailnetLiveEnabled {
		nonRetained = append(nonRetained, executor.journey.TailnetDomain)
	}
	for _, name := range nonRetained {
		for _, kind := range []string{"A", "AAAA", "CNAME"} {
			if records, err := executor.cloudflare.List(ctx, name, kind); err != nil || len(records) != 0 {
				return nil, fmt.Errorf("final provider DNS residue remains for %s %s: %w", kind, name, err)
			}
		}
		if err := waitAuthoritativeAbsent(ctx, executor.journey.AuthoritativeZone, name); err != nil {
			return nil, err
		}
	}
	if err := exactAuthoritativeA(ctx, executor.journey.AuthoritativeZone, []string{executor.journey.HeadscaleDomain}, executor.journey.PublicIPv4); err != nil {
		return nil, err
	}
	for _, kind := range []string{"AAAA", "CNAME"} {
		if records, err := executor.cloudflare.List(ctx, executor.journey.HeadscaleDomain, kind); err != nil || len(records) != 0 {
			return nil, fmt.Errorf("retained Headscale DNS contains extra %s records: %w", kind, err)
		}
	}
	for _, domainName := range []string{executor.journey.AppDomain, executor.journey.DNS01Domain} {
		owner := "_acme-challenge." + domainName
		if err := executor.cloudflare.RequireNoTXT(ctx, owner); err != nil {
			return nil, err
		}
		if err := waitAuthoritativeNoTXT(ctx, executor.journey.AuthoritativeZone, owner); err != nil {
			return nil, err
		}
	}
	candidatePath := remoteStagingRoot(executor.prepared.Input.RunID) + "/lanpanel"
	final, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentFinalInventory, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes)})
	if err != nil || !final.Succeeded {
		return nil, errors.Join(err, fmt.Errorf("final host inventory failed: %s", final.ErrorCode))
	}
	if err := executor.ensureManagement(ctx); err != nil {
		return nil, err
	}
	records, err := executor.cloudflare.List(ctx, executor.journey.HeadscaleDomain, "A")
	if err != nil || len(records) != 1 || records[0].Content != executor.journey.PublicIPv4 || records[0].Proxied {
		return nil, fmt.Errorf("retained Headscale DNS identity differs: %w", err)
	}
	var diagnostics application.DiagnosticsResult
	if _, err := executor.management.Post(ctx, "/api/actions/diagnostics", struct{}{}, &diagnostics); err != nil || diagnostics.ObservedAt.IsZero() {
		return nil, errors.Join(err, fmt.Errorf("final diagnostics observation is incomplete"))
	}
	executor.state.FinalCleanupComplete = true
	if err := executor.states.Write(executor.state); err != nil {
		return nil, err
	}
	return evidence("final-inventory", map[string]string{"host": final.Evidence, "provider_txt": "empty", "cleanup": "complete"})
}

func (executor *LiveExecutor) createARecord(ctx context.Context, name string) (cloudflareRecord, error) {
	for _, kind := range []string{"A", "AAAA", "CNAME"} {
		records, err := executor.cloudflare.List(ctx, name, kind)
		if err != nil || len(records) != 0 {
			return cloudflareRecord{}, fmt.Errorf("DNS create prior state is not empty for %s: %w", name, err)
		}
	}
	intent := dnsCreateIntent{Name: name, Address: executor.journey.PublicIPv4}
	executor.state.DNSCreateIntents = append(executor.state.DNSCreateIntents, intent)
	if err := executor.states.Write(executor.state); err != nil {
		return cloudflareRecord{}, err
	}
	record, createErr := executor.cloudflare.CreateA(ctx, name, executor.journey.PublicIPv4)
	if createErr != nil {
		records, listErr := executor.cloudflare.List(ctx, name, "A")
		if listErr != nil {
			return cloudflareRecord{}, errors.Join(createErr, listErr)
		}
		matches := []cloudflareRecord{}
		for _, candidate := range records {
			if candidate.Content == executor.journey.PublicIPv4 && !candidate.Proxied {
				matches = append(matches, candidate)
			}
		}
		if len(matches) != 1 {
			return cloudflareRecord{}, errors.Join(createErr, fmt.Errorf("uncertain DNS create cannot be reconciled exactly"))
		}
		record = matches[0]
	}
	executor.state.CloudflareRecords = append(executor.state.CloudflareRecords, record)
	executor.state.DNSCreateIntents = slices.DeleteFunc(executor.state.DNSCreateIntents, func(value dnsCreateIntent) bool { return value.Name == name })
	if err := executor.states.Write(executor.state); err != nil {
		return cloudflareRecord{}, err
	}
	return record, nil
}

func (executor *LiveExecutor) cleanupLiveEffects(ctx context.Context) error {
	if err := executor.ensureManagement(ctx); err != nil {
		return err
	}
	var cleanupErr error
	for _, resourceID := range []string{executor.state.TemporaryResourceID, executor.state.TailnetResourceID, executor.state.ResourceID} {
		if resourceID == "" || executor.state.ResourceDeleted && resourceID == executor.state.ResourceID {
			continue
		}
		_ = executor.planConfirmation(ctx, "unpublish", resourceID, "unpublish", &contractionResult{})
		if resourceID == executor.state.ResourceID || resourceID == executor.state.TemporaryResourceID {
			_, _ = executor.management.Post(ctx, "/api/actions/process_stop?resource_id="+url.QueryEscape(resourceID), nil, &helperproto.ActionResult{})
		}
		if resourceID == executor.state.ResourceID && executor.state.BasicCredentialID != "" {
			credentialQuery := "?credential_id=" + url.QueryEscape(executor.state.BasicCredentialID)
			credentialPlan, err := executor.management.Plan(ctx, "/api/actions/managed_basic_delete", credentialQuery, struct{}{})
			if err == nil {
				_, err = executor.management.Post(ctx, "/api/actions/managed_basic_delete"+credentialQuery, application.ManagedBasicPayload{PlanID: credentialPlan, Confirmation: "delete"}, &application.ManagedBasicActionResult{})
			}
			if err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("cleanup managed Basic credential: %w", err))
				continue
			}
			executor.state.BasicCredentialID = ""
			if err := executor.states.Write(executor.state); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
				continue
			}
		}
		if err := executor.planConfirmation(ctx, "resource_delete", resourceID, "delete", &application.ResourceDeleteResult{}); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		switch resourceID {
		case executor.state.ResourceID:
			executor.state.ResourceDeleted = true
		case executor.state.TemporaryResourceID:
			executor.state.TemporaryResourceID = ""
		case executor.state.TailnetResourceID:
			executor.state.TailnetResourceID = ""
		}
		if err := executor.states.Write(executor.state); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if !executor.state.CloseAllCommitted {
		planID, err := executor.management.Plan(ctx, "/api/actions/close_all", "", struct{}{})
		var contraction contractionResult
		if err == nil {
			_, err = executor.management.Post(ctx, "/api/actions/close_all", application.ConfirmationPayload{PlanID: planID, Confirmation: "close"}, &contraction)
		}
		if err != nil || contraction.Outcome == "" || !contraction.AccessClosed || contraction.AccessMayRemain {
			cleanupErr = errors.Join(cleanupErr, err, fmt.Errorf("cleanup close-all did not prove access closure"))
		} else {
			executor.state.CloseAllCommitted = true
			if err := executor.states.Write(executor.state); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
	}
	for _, intent := range append([]dnsCreateIntent(nil), executor.state.DNSCreateIntents...) {
		records, err := executor.cloudflare.List(ctx, intent.Name, "A")
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		matches := []cloudflareRecord{}
		for _, record := range records {
			if record.Content == intent.Address && !record.Proxied {
				matches = append(matches, record)
			}
		}
		if len(matches) > 1 {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("pending DNS create has ambiguous record inventory"))
			continue
		}
		if len(matches) == 1 {
			executor.state.CloudflareRecords = append(executor.state.CloudflareRecords, matches[0])
		}
		executor.state.DNSCreateIntents = slices.DeleteFunc(executor.state.DNSCreateIntents, func(value dnsCreateIntent) bool { return value.Name == intent.Name })
		if err := executor.states.Write(executor.state); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	for _, record := range append([]cloudflareRecord(nil), executor.state.CloudflareRecords...) {
		if record.Name == executor.journey.HeadscaleDomain {
			continue
		}
		if err := executor.cloudflare.DeleteExact(ctx, record); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		executor.state.CloudflareRecords = slices.DeleteFunc(executor.state.CloudflareRecords, func(value cloudflareRecord) bool { return value.ID == record.ID })
		if err := executor.states.Write(executor.state); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	candidatePath := remoteStagingRoot(executor.prepared.Input.RunID) + "/lanpanel"
	cleanup, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentCleanupFixture, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes)})
	if err != nil || !cleanup.Succeeded {
		cleanupErr = errors.Join(cleanupErr, err, fmt.Errorf("fixture cleanup failed: %s", cleanup.ErrorCode))
	}
	secrets := [][]byte{}
	for _, secret := range [][]byte{executor.basicPassword, executor.externalPassword, executor.preauthKey, executor.cloudflare.token} {
		if len(secret) != 0 {
			secrets = append(secrets, append([]byte(nil), secret...))
		}
	}
	if len(secrets) != 0 {
		sentinel, err := executor.target.RunAgent(ctx, candidatePath, AgentRequest{SchemaVersion: AgentRequestSchemaVersion, RunID: executor.prepared.Input.RunID, Action: AgentSecretSentinel, CandidateDigest: release.DigestBytes(executor.prepared.CandidateBytes), Secrets: secrets})
		for _, secret := range secrets {
			clearBytes(secret)
		}
		if err != nil || !sentinel.Succeeded {
			cleanupErr = errors.Join(cleanupErr, err, fmt.Errorf("secret sentinel failed: %s", sentinel.ErrorCode))
		}
	}
	executor.state.FixtureCreated = false
	executor.state.DNSProfileCreated = false
	if err := executor.states.Write(executor.state); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	return cleanupErr
}

func (executor *LiveExecutor) updateDomain(ctx context.Context, resourceID string, publication domain.DomainHTTPSPublication) error {
	update := application.DomainPublicationUpdate{SchemaVersion: application.DomainPublicationUpdateSchema, ResourceID: resourceID, Publication: publication}
	var result helperproto.ResourceResult
	_, err := executor.management.Post(ctx, "/api/actions/resource_update?resource_id="+url.QueryEscape(resourceID), update, &result)
	return err
}

func (executor *LiveExecutor) domainPublication(access domain.AppAccessMode, credential string, cidrs []string, canonical string, aliases []string, certificate domain.CertificateRequest) domain.DomainHTTPSPublication {
	return domain.DomainHTTPSPublication{CanonicalDomain: canonical, Aliases: append([]string(nil), aliases...), AccessMode: access, CredentialID: credential, CIDRs: append([]string(nil), cidrs...), Certificate: &certificate, GoAccess: domain.GoAccessPublication{}}
}

func (executor *LiveExecutor) planConfirmation(ctx context.Context, operation, targetID, confirmation string, result any) error {
	query := ""
	if targetID != "" {
		query = "?resource_id=" + url.QueryEscape(targetID)
	}
	path := "/api/actions/" + operation
	planID, err := executor.management.Plan(ctx, path, query, struct{}{})
	if err != nil {
		return err
	}
	_, err = executor.management.Post(ctx, path+query, application.ConfirmationPayload{PlanID: planID, Confirmation: confirmation}, result)
	if err != nil {
		return err
	}
	switch value := result.(type) {
	case *application.PublicationResult:
		if value.JobResult != "succeeded" || value.JobID == "" {
			return fmt.Errorf("publication did not reach an exact succeeded terminal result")
		}
	case *contractionResult:
		if value.Outcome == "" || !value.AccessClosed || value.AccessMayRemain {
			return fmt.Errorf("contraction did not prove exact access closure")
		}
	case *application.ResourceDeleteResult:
		if value.JobID == "" {
			return fmt.Errorf("resource deletion lacks a terminal job identity")
		}
	}
	return nil
}

func (executor *LiveExecutor) requireResource() (string, error) {
	if executor.state.ResourceID == "" || executor.state.ResourceDeleted {
		return "", fmt.Errorf("qualification local resource identity is unavailable")
	}
	return executor.state.ResourceID, nil
}

func loadTailnetPeer(reference string) (TailnetPeerAuthority, string, error) {
	if !strings.HasPrefix(reference, "file:") {
		return TailnetPeerAuthority{}, "", fmt.Errorf("tailnet live case requires a protected file reference")
	}
	data, _, err := readProtectedFile(strings.TrimPrefix(reference, "file:"), 1<<20, true)
	if err != nil {
		return TailnetPeerAuthority{}, "", err
	}
	var value TailnetPeerAuthority
	if err := release.DecodeCanonical(data, &value); err != nil {
		return TailnetPeerAuthority{}, "", err
	}
	peer := net.ParseIP(value.PeerIP)
	source := net.ParseIP(value.SourceIP)
	if value.SchemaVersion != "lanpanel.qualification.tailnet-peer.v1" || peer == nil || source == nil || peer.To4() == nil || source.To4() == nil || peer.String() != value.PeerIP || source.String() != value.SourceIP || value.PeerIP == value.SourceIP || value.Port == 0 {
		return TailnetPeerAuthority{}, "", fmt.Errorf("tailnet peer authority is invalid")
	}
	return value, release.DigestBytes(data), nil
}

func evidence(kind string, values map[string]string) ([]byte, error) {
	return release.MarshalCanonical(struct {
		SchemaVersion string            `json:"schema_version"`
		Kind          string            `json:"kind"`
		Values        map[string]string `json:"values"`
	}{"lanpanel.qualification.step-evidence.v1", kind, values})
}

func waitAuthoritativeDNS(ctx context.Context, zone string, names []string, expected string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if err := exactAuthoritativeA(ctx, zone, names, expected); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("authoritative DNS did not converge to one exact qualification A record")
		}
		time.Sleep(5 * time.Second)
	}
}

func exactAuthoritativeA(ctx context.Context, zone string, names []string, expected string) error {
	servers, err := net.DefaultResolver.LookupNS(ctx, zone)
	if err != nil || len(servers) == 0 || len(servers) > 16 {
		return fmt.Errorf("authoritative nameserver inventory is unavailable: %w", err)
	}
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	for _, server := range servers {
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, strings.TrimSuffix(server.Host, "."))
		if err != nil || len(addresses) == 0 || len(addresses) > 16 {
			return fmt.Errorf("authoritative nameserver address is unavailable: %w", err)
		}
		for _, address := range addresses {
			destination := net.JoinHostPort(address.IP.String(), "53")
			for _, name := range names {
				for _, queryType := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
					message := new(dns.Msg)
					message.SetQuestion(dns.Fqdn(name), queryType)
					message.RecursionDesired = false
					response, _, err := client.ExchangeContext(ctx, message, destination)
					if err != nil || response == nil || !response.Authoritative || response.Rcode != dns.RcodeSuccess {
						return fmt.Errorf("direct authoritative DNS query failed: %w", err)
					}
					if queryType == dns.TypeA {
						if len(response.Answer) != 1 {
							return fmt.Errorf("authoritative A RRset is not exact")
						}
						record, ok := response.Answer[0].(*dns.A)
						if !ok || record.A.String() != expected {
							return fmt.Errorf("authoritative A RRset differs")
						}
					} else if len(response.Answer) != 0 {
						return fmt.Errorf("authoritative DNS contains forbidden AAAA or CNAME")
					}
				}
			}
		}
	}
	return nil
}

func waitAuthoritativeAbsent(ctx context.Context, zone, name string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		servers, err := net.DefaultResolver.LookupNS(ctx, zone)
		clean := err == nil && len(servers) > 0 && len(servers) <= 16
		for _, server := range servers {
			addresses, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, strings.TrimSuffix(server.Host, "."))
			if lookupErr != nil || len(addresses) == 0 || len(addresses) > 16 {
				clean = false
				break
			}
			for _, address := range addresses {
				for _, queryType := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
					message := new(dns.Msg)
					message.SetQuestion(dns.Fqdn(name), queryType)
					message.RecursionDesired = false
					response, _, queryErr := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).ExchangeContext(ctx, message, net.JoinHostPort(address.IP.String(), "53"))
					if queryErr != nil || response == nil || !response.Authoritative || response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError || len(response.Answer) != 0 {
						clean = false
						break
					}
				}
			}
		}
		if clean {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("authoritative A/AAAA/CNAME cleanup did not converge")
		}
		time.Sleep(5 * time.Second)
	}
}

func waitAuthoritativeNoTXT(ctx context.Context, zone, owner string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		servers, err := net.DefaultResolver.LookupNS(ctx, zone)
		clean := err == nil && len(servers) > 0 && len(servers) <= 16
		for _, server := range servers {
			addresses, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, strings.TrimSuffix(server.Host, "."))
			if lookupErr != nil || len(addresses) == 0 || len(addresses) > 16 {
				clean = false
				break
			}
			for _, address := range addresses {
				message := new(dns.Msg)
				message.SetQuestion(dns.Fqdn(owner), dns.TypeTXT)
				message.RecursionDesired = false
				response, _, queryErr := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).ExchangeContext(ctx, message, net.JoinHostPort(address.IP.String(), "53"))
				if queryErr != nil || response == nil || !response.Authoritative || response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError || len(response.Answer) != 0 {
					clean = false
					break
				}
			}
		}
		if clean {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("authoritative TXT cleanup did not converge")
		}
		time.Sleep(5 * time.Second)
	}
}

func retryPublicProbe(ctx context.Context, vantage VantageAuthority, probe PublicProbe, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		value, err := ProbePublic(ctx, vantage, probe)
		if err == nil {
			return value, nil
		}
		last = err
		if time.Now().After(deadline) {
			return nil, last
		}
		time.Sleep(3 * time.Second)
	}
}

func randomSecret(bytesCount int) ([]byte, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%x", value)), nil
}
