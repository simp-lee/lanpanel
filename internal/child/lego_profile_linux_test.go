//go:build linux

package child

import (
	"slices"
	"strings"
	"testing"
)

func legoTestEnvironment(provider string) []string {
	values := map[string][]string{"cloudflare": {"CF_DNS_API_TOKEN_FILE=/secret"}, "route53": {"AWS_EC2_METADATA_DISABLED=true", "AWS_HOSTED_ZONE_ID=zone", "AWS_PROFILE=lanpanel", "AWS_REGION=us-east-1", "AWS_SHARED_CREDENTIALS_FILE=/secret"}, "digitalocean": {"DO_AUTH_TOKEN_FILE=/secret"}, "gcloud": {"GCE_PROJECT=project", "GCE_SERVICE_ACCOUNT_FILE=/secret"}, "tencentcloud": {"TENCENTCLOUD_SECRET_ID_FILE=/id", "TENCENTCLOUD_SECRET_KEY_FILE=/key"}}[provider]
	return append([]string{"LANG=C", "LC_ALL=C"}, values...)
}

func TestLegoRendersEveryBuiltInDNSProviderWithoutFallback(t *testing.T) {
	id := "cert_00000000000000000000000000000000"
	identities := Identities{CertificateStage: Identity{UID: 1200, GID: 1200, Chroot: "/var/lib/lanpanel/certificates/chroot/" + id}}
	for _, provider := range []string{"cloudflare", "route53", "digitalocean", "gcloud", "tencentcloud"} {
		t.Run(provider, func(t *testing.T) {
			invocation := Invocation{Lego: &LegoInvocation{CertificateID: id, DirectoryURL: "https://acme.example.test/directory", AccountEmail: "admin@example.test", Method: "dns-01", Provider: provider, Domains: []string{"app.example.test"}, DataPath: "/work", UID: 1200, GID: 1200, Chroot: identities.CertificateStage.Chroot, ExecutableDigest: strings.Repeat("a", 64), Environment: legoTestEnvironment(provider)}}
			profile, err := ResolveInvocation(ProfileLego, identities, invocation)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(profile.AllowedAddressFamilies, []int{2, 10}) {
				t.Fatalf("lego address families=%v", profile.AllowedAddressFamilies)
			}
			filter, filterErr := addressFamilyFilter(profile.AllowedAddressFamilies)
			if filterErr != nil || len(filter) != 7 {
				t.Fatalf("lego address-family filter=%v err=%v", filter, filterErr)
			}
			for index, argument := range profile.Arguments {
				if argument == "--dns" && (index+1 >= len(profile.Arguments) || profile.Arguments[index+1] != provider) {
					t.Fatalf("provider argv=%v", profile.Arguments)
				}
				if argument == "--no-bundle" && (index == 0 || profile.Arguments[index-1] != "run") {
					t.Fatalf("run subcommand flag order=%v", profile.Arguments)
				}
			}
		})
	}
}

func TestLegoInvocationIsPinnedPerCertificateAndRejectsProviderFallback(t *testing.T) {
	id := "cert_00000000000000000000000000000000"
	identities := Identities{CertificateStage: Identity{UID: 1200, GID: 1200, Chroot: "/var/lib/lanpanel/certificates/chroot/" + id}}
	invocation := Invocation{Lego: &LegoInvocation{CertificateID: id, DirectoryURL: "https://acme.example.test/directory", AccountEmail: "admin@example.test", Method: "dns-01", Provider: "cloudflare", Domains: []string{"app.example.test"}, DataPath: "/work", UID: 1200, GID: 1200, Chroot: identities.CertificateStage.Chroot, ExecutableDigest: strings.Repeat("a", 64), Environment: legoTestEnvironment("cloudflare")}}
	profile, err := ResolveInvocation(ProfileLego, identities, invocation)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Executable != "/usr/lib/lanpanel/dependencies/lego" || !slices.Contains(profile.Arguments, "cloudflare") || !slices.Contains(profile.Arguments, "--accept-tos") || profile.Umask != 0o022 || profile.UID != 1200 || profile.Chroot != identities.CertificateStage.Chroot {
		t.Fatalf("profile=%#v", profile)
	}
	invocation.Lego.Provider = "route53,cloudflare"
	if _, err := ResolveInvocation(ProfileLego, identities, invocation); err == nil {
		t.Fatal("provider fallback accepted")
	}
	for _, argument := range profile.Arguments {
		if strings.Contains(argument, "secret") {
			t.Fatal("secret entered argv")
		}
	}
}
