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
	input := GenerationInput{CleanInstallInventoryDigest: strings.Repeat("a", 64), SSH: SSHAuthority{MachineFingerprint: "host_0123456789abcdef0123456789abcdef"}, DNS: DNSAuthority{Provider: "cloudflare", BaseDomain: "example.com"}, Journey: journey}
	plan := buildSideEffectPlan("run_"+strings.Repeat("b", 64), input, TailnetPeerAuthority{}, strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), time.Unix(1_700_000_000, 0).UTC())
	encoded, err := release.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := release.DecodeLiveSideEffectPlan(encoded)
	if err != nil || len(decoded.Mutations) != len(OrderedJourney()) {
		t.Fatalf("generated plan invalid: count=%d err=%v", len(decoded.Mutations), err)
	}
	for _, mutation := range decoded.Mutations {
		if mutation.Scope == "" || mutation.PriorState == "" || mutation.PlannedMutation == "" || mutation.Selector == "" {
			t.Fatal("generated side-effect plan hid human-readable authority behind digests")
		}
	}
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
