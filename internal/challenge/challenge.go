package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type Request struct {
	ResourceID          string
	PlanID              string
	Generation          uint64
	ConfigDigest        string
	Domains             []string
	Binding             acme.Binding
	CertificateIdentity string
	Webroot             string
	BaseMarkers         []safety.MarkerSnapshot
}
type Prepared struct {
	Safety safety.ChallengePending
	Entry  *nginx.Entry
	Owners []string
}

var http01TokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,256}$`)

func Prepare(request Request) (Prepared, error) {
	if request.ResourceID == "" || request.PlanID == "" || request.Generation == 0 || !digest(request.ConfigDigest) || request.CertificateIdentity == "" || len(request.Domains) == 0 {
		return Prepared{}, fmt.Errorf("challenge request incomplete")
	}
	bindingDigest, err := acme.BindingDigest(request.Binding)
	if err != nil {
		return Prepared{}, err
	}
	domains := append([]string(nil), request.Domains...)
	slices.Sort(domains)
	if !slices.Equal(domains, request.Domains) {
		return Prepared{}, fmt.Errorf("challenge SAN inventory is noncanonical")
	}
	pending := safety.ChallengePending{Generation: request.Generation, PlanID: request.PlanID, Method: string(request.Binding.Method), ConfigDigest: request.ConfigDigest, SANIdentity: sum([]byte(strings.Join(domains, "\x00"))), ACMEBinding: bindingDigest, CertificateIdentity: request.CertificateIdentity, BaseMarkers: append([]safety.MarkerSnapshot(nil), request.BaseMarkers...), Hosts: domains}
	switch request.Binding.Method {
	case acme.ChallengeHTTP01:
		expectedWebroot := filepath.Join("/var/lib/lanpanel/certificates/webroot", request.CertificateIdentity)
		if request.Webroot != expectedWebroot {
			return Prepared{}, fmt.Errorf("HTTP-01 route identity invalid")
		}
		// The CA chooses each HTTP-01 token after the order starts. Persist this
		// tokenless operation identity now; PresentHTTP derives the only graph
		// entry that may be loaded once an exact Host/token is available.
		pending.Host = domains[0]
		pending.Webroot = request.Webroot
		pending.BootstrapIdentity = sum([]byte("bootstrap:not-required"))
		return Prepared{Safety: pending}, nil
	case acme.ChallengeDNS01:
		if !acme.DNS01ZoneCoversDomains(request.Binding.Zone, domains) {
			return Prepared{}, fmt.Errorf("DNS challenge owner outside authoritative zone")
		}
		owners := make([]string, len(domains))
		for index, domain := range domains {
			owners[index] = "_acme-challenge." + domain
		}
		pending.Host = domains[0]
		pending.TokenPath = "/dns-01"
		pending.Webroot = "/var/lib/lanpanel/certificates/dns-only"
		pending.BootstrapIdentity = sum([]byte("dns-only\x00" + request.CertificateIdentity))
		pending.OwnerLock = sum([]byte(string(request.Binding.Provider) + "\x00" + request.Binding.Zone + "\x00" + strings.Join(owners, "\x00")))
		pending.Provider = string(request.Binding.Provider)
		pending.Zone = request.Binding.Zone
		pending.Owners = append([]string(nil), owners...)
		return Prepared{Safety: pending, Owners: owners}, nil
	default:
		return Prepared{}, fmt.Errorf("unsupported challenge method")
	}
}

func ClearHTTP(active Prepared) (Prepared, error) {
	if active.Entry == nil || active.Safety.Method != "http-01" || active.Safety.Token == "" || active.Safety.TokenPath != "/.well-known/acme-challenge/"+active.Safety.Token || active.Safety.KeyAuthorizationDigest == "" || len(active.Safety.Hosts) == 0 {
		return Prepared{}, fmt.Errorf("HTTP challenge active presentation identity invalid")
	}
	pending := active.Safety
	pending.Host = pending.Hosts[0]
	pending.Token = ""
	pending.TokenPath = ""
	pending.KeyAuthorizationDigest = ""
	return Prepared{Safety: pending}, nil
}

func PreparedHTTP(resourceID string, pending safety.ChallengePending) (Prepared, error) {
	if pending.Method != "http-01" || resourceID == "" || !slices.Contains(pending.Hosts, pending.Host) || !http01TokenPattern.MatchString(pending.Token) || pending.TokenPath != "/.well-known/acme-challenge/"+pending.Token || !digest(pending.KeyAuthorizationDigest) {
		return Prepared{}, fmt.Errorf("HTTP challenge recovery identity invalid")
	}
	entry := nginx.Entry{Kind: nginx.EntryChallenge, ResourceID: resourceID, Relative: filepath.ToSlash(filepath.Join(nginx.ChallengesDirectory, resourceID+".conf")), Digest: "sha256:" + strings.Repeat("0", 64), Domains: []string{pending.Host}, Listeners: []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}, Generation: pending.Generation, Challenge: &nginx.ChallengeSite{Generation: pending.Generation, Host: pending.Host, Token: pending.Token, TokenPath: pending.TokenPath, KeyAuthorizationDigest: pending.KeyAuthorizationDigest, Webroot: pending.Webroot}}
	digest, err := nginx.DigestEntry(entry)
	if err != nil {
		return Prepared{}, err
	}
	entry.Digest = digest
	return Prepared{Safety: pending, Entry: &entry}, nil
}

func PresentHTTPForResource(resourceID string, base Prepared, host, token, keyAuthorizationDigest string) (Prepared, error) {
	if resourceID == "" {
		return Prepared{}, fmt.Errorf("HTTP challenge resource identity invalid")
	}
	pending := base.Safety
	if pending.Method != "http-01" || base.Entry != nil || pending.Token != "" || pending.TokenPath != "" || pending.KeyAuthorizationDigest != "" || !slices.Contains(pending.Hosts, host) || !http01TokenPattern.MatchString(token) || !digest(keyAuthorizationDigest) {
		return Prepared{}, fmt.Errorf("HTTP challenge presentation identity invalid")
	}
	pending.Host = host
	pending.Token = token
	pending.TokenPath = "/.well-known/acme-challenge/" + token
	pending.KeyAuthorizationDigest = keyAuthorizationDigest
	return PreparedHTTP(resourceID, pending)
}

func Matches(pending safety.ChallengePending, prepared Prepared) bool {
	return pending.Generation == prepared.Safety.Generation && pending.PlanID == prepared.Safety.PlanID && pending.Method == prepared.Safety.Method && pending.ConfigDigest == prepared.Safety.ConfigDigest && pending.SANIdentity == prepared.Safety.SANIdentity && pending.ACMEBinding == prepared.Safety.ACMEBinding && pending.CertificateIdentity == prepared.Safety.CertificateIdentity && pending.OwnerLock == prepared.Safety.OwnerLock && pending.Provider == prepared.Safety.Provider && pending.Zone == prepared.Safety.Zone && slices.Equal(pending.Owners, prepared.Safety.Owners) && pending.Host == prepared.Safety.Host && slices.Equal(pending.Hosts, prepared.Safety.Hosts) && pending.Token == prepared.Safety.Token && pending.TokenPath == prepared.Safety.TokenPath && pending.KeyAuthorizationDigest == prepared.Safety.KeyAuthorizationDigest && pending.Webroot == prepared.Safety.Webroot && pending.BootstrapIdentity == prepared.Safety.BootstrapIdentity && slices.Equal(pending.BaseMarkers, prepared.Safety.BaseMarkers)
}

func sum(data []byte) string {
	value := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(value[:])
}
func digest(value string) bool { return len(value) == 71 && strings.HasPrefix(value, "sha256:") }
