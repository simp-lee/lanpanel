package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/nginx"
	"lanpanel/internal/safety"
	"path/filepath"
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
		if !strings.HasPrefix(request.Webroot, "/var/lib/lanpanel/certificates/webroot/") || filepath.Clean(request.Webroot) != request.Webroot {
			return Prepared{}, fmt.Errorf("HTTP-01 route identity invalid")
		}
		pending.Host = domains[0]
		pending.TokenPath = "/.well-known/acme-challenge"
		pending.Webroot = request.Webroot
		pending.BootstrapIdentity = sum([]byte("bootstrap:not-required"))
		entry := nginx.Entry{Kind: nginx.EntryChallenge, ResourceID: request.ResourceID, Relative: filepath.ToSlash(filepath.Join(nginx.ChallengesDirectory, request.ResourceID+".conf")), Digest: "sha256:" + strings.Repeat("0", 64), Domains: domains, Listeners: []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}, Generation: request.Generation, Challenge: &nginx.ChallengeSite{Hosts: domains, Webroot: request.Webroot}}
		data, err := nginx.RenderEntry(entry)
		if err != nil {
			return Prepared{}, err
		}
		entry.Digest = sum(data)
		return Prepared{Safety: pending, Entry: &entry}, nil
	case acme.ChallengeDNS01:
		owners := make([]string, len(domains))
		for index, domain := range domains {
			owner := "_acme-challenge." + domain
			if owner != request.Binding.Zone && !strings.HasSuffix(owner, "."+request.Binding.Zone) {
				return Prepared{}, fmt.Errorf("DNS challenge owner outside authoritative zone")
			}
			owners[index] = owner
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
func PreparedHTTP(resourceID string, pending safety.ChallengePending) (Prepared, error) {
	if pending.Method != "http-01" || resourceID == "" {
		return Prepared{}, fmt.Errorf("HTTP challenge recovery identity invalid")
	}
	entry := nginx.Entry{Kind: nginx.EntryChallenge, ResourceID: resourceID, Relative: filepath.ToSlash(filepath.Join(nginx.ChallengesDirectory, resourceID+".conf")), Digest: "sha256:" + strings.Repeat("0", 64), Domains: append([]string(nil), pending.Hosts...), Listeners: []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}, Generation: pending.Generation, Challenge: &nginx.ChallengeSite{Hosts: append([]string(nil), pending.Hosts...), Webroot: pending.Webroot}}
	digest, err := nginx.DigestEntry(entry)
	if err != nil {
		return Prepared{}, err
	}
	entry.Digest = digest
	return Prepared{Safety: pending, Entry: &entry}, nil
}
func Matches(pending safety.ChallengePending, prepared Prepared) bool {
	return pending.Generation == prepared.Safety.Generation && pending.PlanID == prepared.Safety.PlanID && pending.Method == prepared.Safety.Method && pending.ConfigDigest == prepared.Safety.ConfigDigest && pending.SANIdentity == prepared.Safety.SANIdentity && pending.ACMEBinding == prepared.Safety.ACMEBinding && pending.CertificateIdentity == prepared.Safety.CertificateIdentity && pending.OwnerLock == prepared.Safety.OwnerLock && pending.Provider == prepared.Safety.Provider && pending.Zone == prepared.Safety.Zone && slices.Equal(pending.Owners, prepared.Safety.Owners) && pending.Host == prepared.Safety.Host && slices.Equal(pending.Hosts, prepared.Safety.Hosts) && pending.TokenPath == prepared.Safety.TokenPath && pending.Webroot == prepared.Safety.Webroot && pending.BootstrapIdentity == prepared.Safety.BootstrapIdentity && slices.Equal(pending.BaseMarkers, prepared.Safety.BaseMarkers)
}
func sum(data []byte) string {
	value := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(value[:])
}
func digest(value string) bool { return len(value) == 71 && strings.HasPrefix(value, "sha256:") }
