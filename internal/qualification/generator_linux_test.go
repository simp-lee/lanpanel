//go:build linux

package qualification

import (
	"lanpanel/internal/release"
	"strings"
	"testing"
	"time"
)

func TestJourneySpecAndGeneratedPlanBindHumanReadableExactScope(t *testing.T) {
	journey := JourneySpec{SchemaVersion: JourneySpecSchemaVersion, PublicIPv4: "8.8.8.8", TemporaryHTTPPort: 49180, AppDomain: "app.ga.example.com", AppAlias: "alias.ga.example.com", HeadscaleDomain: "control.ga.example.com", MagicDNSNamespace: "tail.ga.example.com", DNS01Domain: "dns.ga.example.com", AuthoritativeZone: "example.com"}
	if err := validateJourneySpec(journey, "example.com"); err != nil {
		t.Fatal(err)
	}
	input := GenerationInput{CleanInstallInventoryDigest: strings.Repeat("a", 64), SSH: SSHAuthority{MachineFingerprint: "host_0123456789abcdef0123456789abcdef"}, ACME: ACMEAuthority{DirectoryURL: "https://acme.example/directory"}, DNS: DNSAuthority{Provider: "cloudflare", BaseDomain: "example.com"}, Journey: journey}
	plan := buildSideEffectPlan("run_"+strings.Repeat("b", 64), input, TailnetPeerAuthority{}, VantageAuthority{ExpectedSourceIPv4: "203.0.113.1"}, strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), time.Unix(1_700_000_000, 0).UTC())
	encoded, err := release.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := release.DecodeLiveSideEffectPlan(encoded)
	if err != nil || len(decoded.Mutations) != len(OrderedJourney()) {
		t.Fatalf("generated plan invalid: count=%d err=%v", len(decoded.Mutations), err)
	}
	expected := map[string][]string{
		"clean_install":                          {"bootstrap_inventory_digest=" + strings.Repeat("a", 64), "staging_base=/var/lib/lanpanel-qualification:absent", "execute-bound-package-transaction", "candidate_digest=" + strings.Repeat("c", 64)},
		"ui_startup_session_restart":             {"bootstrap_commit=present", "restart-lanpanel-ui.service", "service=lanpanel-ui.service"},
		"local_http_websocket":                   {"configuration.resources=0", "create-local-http-resource", "result:local_http_websocket.resource_id"},
		"temporary_public_http":                  {"listener[8.8.8.8:49180].conflicts=0", "publish-listener[8.8.8.8:49180]", "delete-resource"},
		"domain_https_controls":                  {"dns[app.ga.example.com,A|AAAA|CNAME].records=0", "create-cloudflare-A[app.ga.example.com=8.8.8.8]", "issue-http01-certificate", "vantage_cidr=203.0.113.1/32", "dashboard=/analytics/", "dns_provider=cloudflare"},
		"app_http01":                             {"certificate[app.ga.example.com]=present", "probe-public-trusted-http01-certificate", "close-all-app-ingress"},
		"headscale_initialize_http01":            {"headscale=absent", "initialize-headscale[control=control.ga.example.com", "retain_authorized"},
		"headscale_entities":                     {"headscale.users=0", "create-headscale-user[name=qualification]", "result:headscale_entities.user_id"},
		"connector_assisted_login":               {"connector=absent", "set-connector-binding[https://control.ga.example.com]", "result:connector_assisted_login.device_id"},
		"tailnet_http_websocket":                 {"live_test=disabled", "record-tailnet-not-live-tested", "status=not_live_tested"},
		"dns01":                                  {"dns[_acme-challenge.dns.ga.example.com,TXT].records=0", "create-and-clean-acme-TXT", "dns_provider=cloudflare"},
		"delete_diagnostics_export_close_reboot": {"run_owned_A_records=4", "expire-headscale-device", "delete-non-headscale-cloudflare-records"},
		"final_cleanup_inventory":                {"run_owned_nonretained_A_records=0", "verify-exact-headscale-A", "retained_headscale_domain=control.ga.example.com"},
	}
	for _, mutation := range decoded.Mutations {
		combined := mutation.Scope + "\n" + mutation.PriorState + "\n" + mutation.PlannedMutation + "\n" + mutation.Selector
		if mutation.Scope == "" || mutation.PriorState == "" || mutation.PlannedMutation == "" || mutation.Selector == "" {
			t.Fatal("generated side-effect plan hid human-readable authority behind digests")
		}
		if strings.Contains(combined, "fresh-prior/") || strings.Contains(mutation.PlannedMutation, "execute=") {
			t.Fatalf("mutation %q retained placeholder authority: %s", mutation.ID, combined)
		}
		for _, fragment := range expected[mutation.ID] {
			if !strings.Contains(combined, fragment) {
				t.Fatalf("mutation %q omits concrete authority %q", mutation.ID, fragment)
			}
		}
	}
}

func TestGeneratedTailnetPlanBindsExactPeerAndProviderMutation(t *testing.T) {
	journey := JourneySpec{SchemaVersion: JourneySpecSchemaVersion, PublicIPv4: "8.8.8.8", TemporaryHTTPPort: 49180, AppDomain: "app.ga.example.com", AppAlias: "alias.ga.example.com", HeadscaleDomain: "control.ga.example.com", MagicDNSNamespace: "tail.ga.example.com", DNS01Domain: "dns.ga.example.com", AuthoritativeZone: "example.com", TailnetDomain: "peer.ga.example.com", TailnetLiveEnabled: true}
	input := GenerationInput{CleanInstallInventoryDigest: strings.Repeat("a", 64), SSH: SSHAuthority{MachineFingerprint: "host_0123456789abcdef0123456789abcdef"}, ACME: ACMEAuthority{DirectoryURL: "https://acme.example/directory"}, DNS: DNSAuthority{Provider: "cloudflare", BaseDomain: "example.com"}, Journey: journey}
	peer := TailnetPeerAuthority{SourceIP: "100.64.0.1", PeerIP: "100.64.0.2", Port: 8080}
	plan := buildSideEffectPlan("run_"+strings.Repeat("b", 64), input, peer, VantageAuthority{ExpectedSourceIPv4: "203.0.113.1"}, strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), time.Unix(1_700_000_000, 0).UTC())
	for _, mutation := range plan.Mutations {
		if mutation.ID != "tailnet_http_websocket" {
			continue
		}
		combined := mutation.PriorState + "\n" + mutation.PlannedMutation + "\n" + mutation.Selector
		for _, expected := range []string{"dns[peer.ga.example.com,A|AAAA|CNAME].records=0", "source=100.64.0.1", "peer=100.64.0.2:8080", "create-cloudflare-A[peer.ga.example.com=8.8.8.8]"} {
			if !strings.Contains(combined, expected) {
				t.Fatalf("tailnet authority omits %q: %s", expected, combined)
			}
		}
		return
	}
	t.Fatal("tailnet mutation is missing")
}

func TestJourneySpecRejectsDNSOrTailnetScopeEscape(t *testing.T) {
	value := JourneySpec{SchemaVersion: JourneySpecSchemaVersion, PublicIPv4: "8.8.8.8", TemporaryHTTPPort: 49180, AppDomain: "app.ga.example.com", AppAlias: "alias.ga.example.com", HeadscaleDomain: "control.ga.example.com", MagicDNSNamespace: "tail.ga.example.com", DNS01Domain: "dns.ga.example.com", AuthoritativeZone: "example.com", TailnetLiveEnabled: true, TailnetDomain: "outside.invalid"}
	if validateJourneySpec(value, "example.com") == nil {
		t.Fatal("tailnet domain escaped authorized DNS base")
	}
	value.TailnetLiveEnabled = false
	value.TailnetDomain = ""
	value.DNS01Domain = "dns.other.invalid"
	if validateJourneySpec(value, "example.com") == nil {
		t.Fatal("DNS-01 domain escaped authorized DNS base")
	}
}
