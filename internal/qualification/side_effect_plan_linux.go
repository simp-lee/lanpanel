//go:build linux

package qualification

import (
	"fmt"
	"lanpanel/internal/release"
	"slices"
	"strings"
	"time"
)

type sideEffectAuthority struct {
	Scope           string
	PriorState      string
	PlannedMutation string
	Selector        string
	CleanupPolicy   string
}

// buildSideEffectPlan freezes the complete, reviewable authority used by the
// live executor. Runtime-assigned object IDs are named as result references;
// each reference is resolved against a unique, freshly observed selector
// before a later mutation is submitted.
func buildSideEffectPlan(runID string, input GenerationInput, tailnetPeer TailnetPeerAuthority, vantage VantageAuthority, candidateDigest, profileDigest, journeyDigest string, createdAt time.Time) release.LiveSideEffectPlan {
	authorities := sideEffectAuthorities(runID, input, tailnetPeer, vantage, candidateDigest, profileDigest, journeyDigest, input.CleanInstallInventoryDigest)
	mutations := make([]release.PlannedMutation, 0, len(orderedJourney))
	for _, step := range orderedJourney {
		authority := authorities[step]
		mutations = append(mutations, release.PlannedMutation{
			ID:                    step,
			Scope:                 authority.Scope,
			ScopeDigest:           release.DigestBytes([]byte(authority.Scope)),
			PriorState:            authority.PriorState,
			PriorStateDigest:      release.DigestBytes([]byte(authority.PriorState)),
			PlannedMutation:       authority.PlannedMutation,
			PlannedMutationDigest: release.DigestBytes([]byte(authority.PlannedMutation)),
			Selector:              authority.Selector,
			SelectorDigest:        release.DigestBytes([]byte(authority.Selector)),
			CleanupPolicy:         authority.CleanupPolicy,
		})
	}
	slices.SortFunc(mutations, func(left, right release.PlannedMutation) int { return strings.Compare(left.ID, right.ID) })
	return release.LiveSideEffectPlan{SchemaVersion: release.LiveSideEffectPlanSchemaVersion, RunID: runID, AuthorizedHostFingerprint: input.SSH.MachineFingerprint, CreatedAt: createdAt, Mutations: mutations}
}

func sideEffectAuthorities(runID string, input GenerationInput, tailnetPeer TailnetPeerAuthority, vantage VantageAuthority, candidateDigest, profileDigest, journeyDigest, cleanInventoryDigest string) map[string]sideEffectAuthority {
	host := input.SSH.MachineFingerprint
	journey := input.Journey
	localName := "qualification-local-" + runID[4:16]
	temporaryName := "qualification-temporary-" + runID[4:16]
	tailnetName := "qualification-tailnet-" + runID[4:16]
	fixtureRoot := "/srv/lanpanel-qualification/" + runID
	fixtureConfig := "/etc/lanpanel-qualification/" + runID
	commonScope := "run=" + runID + ";host=" + host + ";journey_digest=" + journeyDigest
	localResult := "result:local_http_websocket.resource_id"
	userResult := "result:headscale_entities.user_id"
	keyResult := "result:headscale_entities.preauth_key_id"
	deviceResult := "result:connector_assisted_login.device_id"
	nonRetainedDomains := []string{journey.AppDomain, journey.AppAlias, journey.DNS01Domain}
	tailnetCleanupSelector := "tailnet_resource=none"
	if journey.TailnetLiveEnabled {
		nonRetainedDomains = append(nonRetainedDomains, journey.TailnetDomain)
		tailnetCleanupSelector = "tailnet_resource=result:tailnet_http_websocket.resource_id"
	}

	values := map[string]sideEffectAuthority{
		"clean_install": {
			Scope:           commonScope + ";providers=ssh,target-package-manager,target-filesystem,target-systemd,target-nginx;objects=qualification-staging,installation",
			PriorState:      release.QualificationCleanInstallPriorState(host, cleanInventoryDigest, runID),
			PlannedMutation: "candidate_digest=" + candidateDigest + ";profile_digest=" + profileDigest + ";effects=stage-candidate-and-dependency-assets[delete_exact],execute-bound-package-transaction[retain_authorized],write-installation-bundle-and-acme-account[retain_authorized],install-candidate-and-fixed-units[retain_authorized],activate-management-ui[retain_authorized]",
			Selector:        "host_fingerprint=" + host + ";staging_root=/var/lib/lanpanel-qualification/" + runID + ";installation_root=/var/lib/lanpanel;candidate_digest=" + candidateDigest,
			CleanupPolicy:   "retain_authorized",
		},
		"ui_startup_session_restart": {
			Scope:           commonScope + ";providers=lanpanel-management,target-systemd;objects=management-session,lanpanel-ui.service",
			PriorState:      priorState("ui_startup_session_restart", "bootstrap_commit=present", "management_session=authenticated", "admin_token=present"),
			PlannedMutation: "effects=verify-management-websocket[none],restart-lanpanel-ui.service[none],reauthenticate-management-session[none],verify-admin-token-digest-unchanged[none]",
			Selector:        "service=lanpanel-ui.service;management=installation-specific-loopback;installation=run:" + runID,
			CleanupPolicy:   "delete_exact",
		},
		"local_http_websocket": {
			Scope:           commonScope + ";providers=lanpanel-management,target-systemd,target-filesystem;objects=resource,managed-process,unix-socket",
			PriorState:      priorState("local_http_websocket", "configuration.resources=0", "configuration.credentials=0", "configuration.static_roots=0", "resource[name="+localName+"]=absent"),
			PlannedMutation: "effects=create-local-http-resource[name=" + localName + ",endpoint=unix-socket-activation,readiness=/ready,status=204,websocket=/ws,pending_publication=domain_https:" + journey.AppDomain + ",alias=" + journey.AppAlias + ",access=public,certificate=http-01:" + input.ACME.DirectoryURL + "][delete_exact],start-managed-qualification-fixture[delete_exact]",
			Selector:        "resource_name=" + localName + ";resource_target=local_http;pending_domains=" + journey.AppDomain + "," + journey.AppAlias + ";acme_directory=" + input.ACME.DirectoryURL + ";result_reference=" + localResult,
			CleanupPolicy:   "delete_exact",
		},
		"temporary_public_http": {
			Scope:           commonScope + ";providers=lanpanel-management,target-systemd,target-nginx,external-vantage;objects=temporary-resource,managed-process,public-listener",
			PriorState:      priorState("temporary_public_http", "configuration.resources=1", "local_resource[name="+localName+"]=present", "resource[name="+temporaryName+"]=absent", fmt.Sprintf("listener[%s:%d].conflicts=0", journey.PublicIPv4, journey.TemporaryHTTPPort)),
			PlannedMutation: fmt.Sprintf("effects=create-temporary-http-resource[name=%s,endpoint=unix-socket-activation][delete_exact],start-fixture[delete_exact],publish-listener[%s:%d][delete_exact],probe-http-and-header-sanitization[none],unpublish-listener[delete_exact],stop-fixture[delete_exact],delete-resource[delete_exact]", temporaryName, journey.PublicIPv4, journey.TemporaryHTTPPort),
			Selector:        fmt.Sprintf("resource_name=%s;public_listener=%s:%d;connect_ip=%s", temporaryName, journey.PublicIPv4, journey.TemporaryHTTPPort, journey.PublicIPv4),
			CleanupPolicy:   "delete_exact",
		},
		"domain_https_controls": {
			Scope:           commonScope + ";providers=lanpanel-management,target-filesystem,target-systemd,target-nginx,cloudflare-zone:" + input.DNS.BaseDomain + ",acme-directory:" + input.ACME.DirectoryURL + ",external-vantage;objects=app-dns,fixture,basic-credential,static-root,external-htpasswd,publication,certificate,goaccess",
			PriorState:      priorState("domain_https_controls", "configuration.resources=1", "configuration.credentials=0", "configuration.static_roots=0", "local_resource[name="+localName+"]=present", "fixture_base=/srv/lanpanel-qualification:absent", "fixture_config_base=/etc/lanpanel-qualification:absent", "dns["+journey.AppDomain+",A|AAAA|CNAME].records=0", "dns["+journey.AppAlias+",A|AAAA|CNAME].records=0"),
			PlannedMutation: "effects=create-cloudflare-A[" + journey.AppDomain + "=" + journey.PublicIPv4 + "][delete_exact],create-cloudflare-A[" + journey.AppAlias + "=" + journey.PublicIPv4 + "][delete_exact],create-fixture-files[delete_exact],create-managed-basic[username=ga-user][delete_exact],register-static-root[path=" + fixtureRoot + "/static,mapping=/static.txt:live.txt:anonymous][delete_exact],register-external-htpasswd[path=" + fixtureConfig + "/dashboard.htpasswd][delete_exact],issue-http01-certificate[" + journey.AppDomain + "," + journey.AppAlias + "][delete_exact],publish-public-and-websocket[delete_exact],publish-application-managed[delete_exact],publish-basic-cidr-goaccess[cidr=" + vantage.ExpectedSourceIPv4 + "/32,dashboard=/analytics/,websocket=/analytics-ws][delete_exact],restore-public-publication[delete_exact],delete-managed-basic[delete_exact]",
			Selector:        "resource=" + localResult + ";domains=" + journey.AppDomain + "," + journey.AppAlias + ";dns_provider=cloudflare;zone=" + input.DNS.BaseDomain + ";vantage_cidr=" + vantage.ExpectedSourceIPv4 + "/32;fixture_root=" + fixtureRoot + ";fixture_config=" + fixtureConfig + ";static_root_result=result:domain_https_controls.static_root_id;external_credential_result=result:domain_https_controls.external_credential_id",
			CleanupPolicy:   "delete_exact",
		},
		"app_http01": {
			Scope:           commonScope + ";providers=lanpanel-management,target-nginx,external-vantage;objects=app-http01-certificate,app-ingress",
			PriorState:      priorState("app_http01", "configuration.resources=1", "configuration.credentials=1", "configuration.static_roots=1", "resource[name="+localName+"]=published", "certificate["+journey.AppDomain+"]=present", "app_ingress=open"),
			PlannedMutation: "effects=probe-public-trusted-http01-certificate[none],close-all-app-ingress[delete_exact]",
			Selector:        "resource=" + localResult + ";certificate_domain=" + journey.AppDomain + ";connect_ip=" + journey.PublicIPv4,
			CleanupPolicy:   "delete_exact",
		},
		"headscale_initialize_http01": {
			Scope:           commonScope + ";providers=lanpanel-management,target-filesystem,target-systemd,target-nginx,cloudflare-zone:" + input.DNS.BaseDomain + ",acme-directory:" + input.ACME.DirectoryURL + ",external-vantage;objects=headscale-identity,database,control,certificate,dns,derp,stun",
			PriorState:      priorState("headscale_initialize_http01", "headscale=absent", "headscale_user_result=absent", "dns["+journey.HeadscaleDomain+",A|AAAA|CNAME].records=0"),
			PlannedMutation: "effects=create-cloudflare-A[" + journey.HeadscaleDomain + "=" + journey.PublicIPv4 + "][retain_authorized],initialize-headscale[control=" + journey.HeadscaleDomain + ",magicdns=" + journey.MagicDNSNamespace + "][retain_authorized],issue-http01-certificate[" + journey.HeadscaleDomain + "][retain_authorized],deploy-control-derp-stun[retain_authorized],probe-control-derp-stun[none]",
			Selector:        "headscale=installation-singleton;control_domain=" + journey.HeadscaleDomain + ";magicdns_namespace=" + journey.MagicDNSNamespace + ";dns_provider=cloudflare;zone=" + input.DNS.BaseDomain,
			CleanupPolicy:   "retain_authorized",
		},
		"headscale_entities": {
			Scope:           commonScope + ";providers=lanpanel-management,headscale-admin;objects=headscale-user,preauth-key",
			PriorState:      priorState("headscale_entities", "headscale=initialized", "headscale.users=0", "headscale.preauth_keys=0", "headscale.devices=0", "user[name=qualification]=absent"),
			PlannedMutation: "effects=create-headscale-user[name=qualification][retain_authorized],create-single-use-preauth-key[user=" + userResult + ",expiration_seconds=3600][revoke_exact],list-and-verify-created-entities[none]",
			Selector:        "headscale=installation-singleton;user_name=qualification;user_result_reference=" + userResult + ";key_result_reference=" + keyResult,
			CleanupPolicy:   "retain_authorized",
		},
		"connector_assisted_login": {
			Scope:           commonScope + ";providers=lanpanel-management,headscale-admin,target-systemd,target-filesystem;objects=connector-binding,connector-session,headscale-device,preauth-key",
			PriorState:      priorState("connector_assisted_login", "headscale.users=1", "headscale.preauth_keys=1", "headscale.devices=0", "connector=absent", "user="+userResult+":present", "preauth_key="+keyResult+":active"),
			PlannedMutation: "effects=set-connector-binding[https://" + journey.HeadscaleDomain + "][retain_authorized],submit-connector-login[key=" + keyResult + "][retain_authorized],create-headscale-device[user=" + userResult + "][expire_exact],verify-connector-and-magicdns[none]",
			Selector:        "connector=installation-singleton;control_url=https://" + journey.HeadscaleDomain + ";user=" + userResult + ";preauth_key=" + keyResult + ";device_result_reference=" + deviceResult,
			CleanupPolicy:   "retain_authorized",
		},
		"tailnet_http_websocket": {
			Scope:           commonScope + ";providers=lanpanel-management,target-nginx,cloudflare-zone:" + input.DNS.BaseDomain + ",acme-directory:" + input.ACME.DirectoryURL + ",external-vantage;objects=tailnet-resource,tailnet-dns,tailnet-certificate",
			PriorState:      tailnetPriorState(journey, localName, tailnetName),
			PlannedMutation: tailnetMutation(journey, tailnetPeer, tailnetName),
			Selector:        tailnetSelector(journey, tailnetPeer, tailnetName),
			CleanupPolicy:   "delete_exact",
		},
		"dns01": {
			Scope:           commonScope + ";providers=lanpanel-management,target-filesystem,target-nginx,cloudflare-zone:" + input.DNS.BaseDomain + ",acme-directory:" + input.ACME.DirectoryURL + ",external-vantage;objects=dns-provider-profile,dns-A,dns01-TXT,certificate,publication",
			PriorState:      priorState("dns01", fmt.Sprintf("configuration.resources=%d", 1+boolInt(journey.TailnetLiveEnabled)), "dns_profile=absent", "dns["+journey.DNS01Domain+",A|AAAA|CNAME].records=0", "dns[_acme-challenge."+journey.DNS01Domain+",TXT].records=0", "resource[name="+localName+"]=present"),
			PlannedMutation: "effects=create-protected-cloudflare-profile[delete_exact],create-cloudflare-A[" + journey.DNS01Domain + "=" + journey.PublicIPv4 + "][delete_exact],create-and-clean-acme-TXT[_acme-challenge." + journey.DNS01Domain + "][delete_exact],issue-dns01-certificate[" + journey.DNS01Domain + "][delete_exact],publish-and-probe-https[delete_exact]",
			Selector:        "resource=" + localResult + ";certificate_domain=" + journey.DNS01Domain + ";txt_owner=_acme-challenge." + journey.DNS01Domain + ";dns_provider=cloudflare;zone=" + input.DNS.BaseDomain + ";provider_profile=/etc/lanpanel-qualification/" + runID + "/cloudflare.env;credential_file=/etc/lanpanel-qualification/" + runID + "/cloudflare.token",
			CleanupPolicy:   "delete_exact",
		},
		"delete_diagnostics_export_close_reboot": {
			Scope:           commonScope + ";providers=lanpanel-management,target-systemd,target-filesystem,target-nginx,cloudflare-zone:" + input.DNS.BaseDomain + ",headscale-admin,external-vantage;objects=all-app-ingress,connector-device,preauth-key,run-resources,run-dns,fixtures,host",
			PriorState:      priorState("delete_diagnostics_export_close_reboot", fmt.Sprintf("configuration.resources=%d", 1+boolInt(journey.TailnetLiveEnabled)), "resource="+localResult+":present", "app_ingress=published", "headscale.users=1", "headscale.preauth_keys=1", "headscale.devices=1", "connector_device="+deviceResult+":present", "preauth_key="+keyResult+":present", "fixture=present", "dns_profile=present", fmt.Sprintf("run_owned_A_records=%d", 4+boolInt(journey.TailnetLiveEnabled)), "run_owned_AAAA_CNAME_records=0", "pending_dns_create_intents=0", "final_cleanup_complete=false"),
			PlannedMutation: "effects=close-all-app-ingress[delete_exact],reboot-target-and-verify-boot-id-change[none],verify-admin-token-unchanged[none],expire-headscale-device[" + deviceResult + "][retain-inactive],revoke-preauth-key[" + keyResult + "][retain-inactive],unpublish-and-delete-run-resources[delete_exact],delete-tracked-nonretained-certificate-pointers-and-bundles[delete_exact],delete-non-headscale-cloudflare-records[delete_exact],delete-fixture-and-dns-profile[delete_exact],scan-secret-sentinels[none],read-diagnostics-configuration-jobs[none]",
			Selector:        "installation=run:" + runID + ";resource=" + localResult + ";" + tailnetCleanupSelector + ";device=" + deviceResult + ";preauth_key=" + keyResult + ";nonretained_dns=" + strings.Join(nonRetainedDomains, ",") + ";retained_dns=" + journey.HeadscaleDomain + ";fixture_root=/srv/lanpanel-qualification/" + runID + ";fixture_config=/etc/lanpanel-qualification/" + runID,
			CleanupPolicy:   "delete_exact",
		},
		"final_cleanup_inventory": {
			Scope:           commonScope + ";providers=ssh,lanpanel-management,target-filesystem,target-systemd,target-nginx,cloudflare-zone:" + input.DNS.BaseDomain + ",authoritative-dns;objects=cleanup-inventory,retained-installation,retained-headscale,retained-headscale-dns",
			PriorState:      priorState("final_cleanup_inventory", "configuration.resources=0", "configuration.credentials=0", "configuration.static_roots=0", "nonretained_certificate_pointers_and_bundles=absent", "retained_headscale_certificate_pointer_and_bundle=present", "run_owned_nonretained_A_records=0", "retained_headscale_A_records=1", "retained_headscale_AAAA_CNAME_records=0", "resource_deleted=true", "temporary_resource=absent", "tailnet_resource=absent", "fixture=absent", "dns_profile=absent", "headscale.users=1", "headscale.preauth_keys=1", "headscale.devices=1", "headscale_user_result=present", "preauth_key_result=inactive", "connector_device_result=expired", "connector_binding=present", "pending_dns_create_intents=0", "final_cleanup_complete=false"),
			PlannedMutation: "effects=verify-nonretained-certificate-pointers-and-bundles-absent[none],verify-exact-retained-headscale-certificate-pointer-and-bundle[retain_authorized],verify-nonretained-provider-and-authoritative-dns-absent[none],verify-acme-TXT-absent[none],verify-exact-headscale-A[retain_authorized],verify-retained-headscale-and-connector-results[retain_authorized],run-final-host-inventory[none],read-final-diagnostics[none],commit-final-cleanup-state[retain_authorized]",
			Selector:        "host_fingerprint=" + host + ";installation=run:" + runID + ";retained_headscale_domain=" + journey.HeadscaleDomain + ";retained_headscale_address=" + journey.PublicIPv4 + ";zone=" + input.DNS.BaseDomain,
			CleanupPolicy:   "retain_authorized",
		},
	}
	return values
}

func priorState(step string, facts ...string) string {
	return "step=" + step + ";fresh_observation=" + strings.Join(facts, ",")
}

func tailnetPriorState(journey JourneySpec, localName, tailnetName string) string {
	if !journey.TailnetLiveEnabled {
		return priorState("tailnet_http_websocket", "live_test=disabled", "configuration.resources=1", "tailnet_resource=absent")
	}
	return priorState("tailnet_http_websocket", "live_test=enabled", "configuration.resources=1", "local_resource[name="+localName+"]=present", "resource[name="+tailnetName+"]=absent", "dns["+journey.TailnetDomain+",A|AAAA|CNAME].records=0")
}

func tailnetMutation(journey JourneySpec, peer TailnetPeerAuthority, name string) string {
	if !journey.TailnetLiveEnabled {
		return "effects=record-tailnet-not-live-tested[none]"
	}
	return fmt.Sprintf("effects=create-cloudflare-A[%s=%s][delete_exact],create-tailnet-resource[name=%s,source=%s,peer=%s:%d,readiness=/ready,websocket=/ws][delete_exact],issue-http01-certificate[%s][delete_exact],publish-and-probe-https-websocket[delete_exact]", journey.TailnetDomain, journey.PublicIPv4, name, peer.SourceIP, peer.PeerIP, peer.Port, journey.TailnetDomain)
}

func tailnetSelector(journey JourneySpec, peer TailnetPeerAuthority, name string) string {
	if !journey.TailnetLiveEnabled {
		return "tailnet_authority=none;status=not_live_tested"
	}
	return fmt.Sprintf("resource_name=%s;source_ip=%s;peer=%s:%d;domain=%s;connect_ip=%s", name, peer.SourceIP, peer.PeerIP, peer.Port, journey.TailnetDomain, journey.PublicIPv4)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
