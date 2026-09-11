// Package sources validates the closed dependency source and proxy vocabulary.
package sources

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Kind string

const (
	OfficialCanonical Kind = "official/canonical_artifact"
	OfficialDistro    Kind = "official/distro_repository"
	Mirror            Kind = "mirror"
	Offline           Kind = "offline"
)

type Artifact struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	OperatingOS  string `json:"operating_os"`
	Architecture string `json:"architecture"`
	Digest       string `json:"digest"`
}

type Source struct {
	Kind Kind `json:"kind"`
	// Acquisition locations are runtime-only and are not part of the
	// persisted release/package contract.
	URL                 string   `json:"-"`
	OfflinePath         string   `json:"-"`
	OfficialAuthorities []string `json:"-"`
	Artifact            Artifact `json:"artifact"`
}

type Proxy struct {
	URL string `json:"url"`
}

var (
	namePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionPattern = regexp.MustCompile(`^(?:v)?[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func Validate(source Source) error {
	if !namePattern.MatchString(source.Artifact.Name) || !versionPattern.MatchString(source.Artifact.Version) || moving(source.Artifact.Version) || source.Artifact.OperatingOS != "linux" || source.Artifact.Architecture != "amd64" && source.Artifact.Architecture != "all" || !digestPattern.MatchString(source.Artifact.Digest) {
		return fmt.Errorf("source artifact identity is invalid or floating")
	}
	switch source.Kind {
	case OfficialCanonical:
		parsed, err := parseNetworkURL(source.URL)
		if err != nil || parsed.Scheme != "https" || source.OfflinePath != "" || len(source.OfficialAuthorities) == 0 {
			return fmt.Errorf("official canonical source is invalid")
		}
		previous := ""
		for _, authority := range source.OfficialAuthorities {
			if !canonicalAuthority(authority) || previous != "" && strings.Compare(previous, authority) >= 0 {
				return fmt.Errorf("official redirect authorities are invalid, duplicated, or unsorted")
			}
			previous = authority
		}
		if !slices.Contains(source.OfficialAuthorities, parsed.Host) {
			return fmt.Errorf("initial official authority is not pinned")
		}
	case OfficialDistro:
		if source.URL != "" || source.OfflinePath != "" || len(source.OfficialAuthorities) != 0 {
			return fmt.Errorf("distro repository source cannot carry artifact URL authority")
		}
	case Mirror:
		if _, err := parseNetworkURL(source.URL); err != nil || source.OfflinePath != "" || len(source.OfficialAuthorities) != 0 {
			return fmt.Errorf("mirror source is invalid")
		}
	case Offline:
		if source.URL != "" || len(source.OfficialAuthorities) != 0 || !cleanAbsolute(source.OfflinePath) {
			return fmt.Errorf("offline source path is invalid")
		}
	default:
		return fmt.Errorf("source kind is unknown")
	}
	return nil
}

func ValidateProxy(proxy *Proxy) error {
	if proxy == nil {
		return nil
	}
	_, err := ParseProxyURL(proxy.URL)
	return err
}

func ParseProxyURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Host != strings.ToLower(parsed.Host) || !canonicalAuthority(parsed.Host) || defaultPort(parsed) || parsed.String() != value {
		return nil, fmt.Errorf("download proxy is not a canonical unauthenticated authority URL")
	}
	return parsed, nil
}

// ValidateRedirect enforces the release-fixed official authority set or the
// mirror same-authority, same-or-stronger scheme rule. Signed query is accepted
// only on an official redirect response and is never returned as identity.
func ValidateRedirect(source Source, fromURL, targetURL string, redirectCount, maximumRedirects int) error {
	if err := Validate(source); err != nil || redirectCount <= 0 || maximumRedirects <= 0 || redirectCount > maximumRedirects {
		return fmt.Errorf("redirect count or source authority is invalid")
	}
	from, err := parseRedirectURL(fromURL, source.Kind == OfficialCanonical)
	if err != nil {
		return err
	}
	target, err := parseRedirectURL(targetURL, source.Kind == OfficialCanonical)
	if err != nil {
		return err
	}
	switch source.Kind {
	case OfficialCanonical:
		if target.Scheme != "https" || !slices.Contains(source.OfficialAuthorities, target.Host) {
			return fmt.Errorf("official redirect escaped pinned HTTPS authorities")
		}
	case Mirror:
		if target.Host != from.Host || from.Scheme == "https" && target.Scheme != "https" {
			return fmt.Errorf("mirror redirect changed authority or downgraded scheme")
		}
	default:
		return fmt.Errorf("source kind does not permit artifact redirects")
	}
	return nil
}

func ParseURL(value string) (*url.URL, error) { return parseNetworkURL(value) }

func parseNetworkURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" || strings.Contains(parsed.EscapedPath(), "%") || parsed.Path == "" || filepath.ToSlash(filepath.Clean(parsed.Path)) != parsed.Path || parsed.Host != strings.ToLower(parsed.Host) {
		return nil, fmt.Errorf("network source URL is not canonical hierarchical HTTP(S)")
	}
	if !canonicalAuthority(parsed.Host) || defaultPort(parsed) {
		return nil, fmt.Errorf("network source authority is noncanonical")
	}
	return parsed, nil
}

func parseRedirectURL(value string, allowQuery bool) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" || parsed.ForceQuery || parsed.RawPath != "" || strings.Contains(parsed.EscapedPath(), "%") || parsed.Path == "" || filepath.ToSlash(filepath.Clean(parsed.Path)) != parsed.Path || parsed.Host != strings.ToLower(parsed.Host) || !canonicalAuthority(parsed.Host) || defaultPort(parsed) || len(parsed.RawQuery) > 4096 || !allowQuery && parsed.RawQuery != "" {
		return nil, fmt.Errorf("redirect URL is noncanonical or unauthorized")
	}
	return parsed, nil
}

func canonicalAuthority(authority string) bool {
	parsed, err := url.Parse("https://" + authority + "/x")
	if err != nil || parsed.Host != authority || parsed.Hostname() == "" || strings.HasSuffix(parsed.Hostname(), ".") || strings.HasSuffix(authority, ":") || strings.Contains(parsed.Hostname(), "%") {
		return false
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number <= 0 || number > 65535 || strconv.Itoa(number) != port {
			return false
		}
	}
	host := parsed.Hostname()
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String() == host
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func defaultPort(parsed *url.URL) bool {
	return parsed.Scheme == "https" && parsed.Port() == "443" || parsed.Scheme == "http" && parsed.Port() == "80"
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func moving(value string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return (character < 'a' || character > 'z') && (character < '0' || character > '9')
	}) {
		if token == "latest" || token == "stable" {
			return true
		}
	}
	return false
}
