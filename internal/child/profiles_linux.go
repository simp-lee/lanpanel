//go:build linux

// Package child owns the release-fixed external executable profiles. Callers
// select a profile ID; they cannot supply an executable, argv, UID, capability,
// environment key, filesystem policy, or network policy.
package child

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

type ProfileID string

const (
	ProfileSystemdSysusers ProfileID = "systemd_sysusers"
	ProfileAPTTransaction  ProfileID = "apt_transaction"
	ProfileDPKGTransaction ProfileID = "dpkg_transaction"
	ProfileSystemctl       ProfileID = "systemctl"
	ProfileNginxTest       ProfileID = "nginx_test"
	ProfileHeadscaleAdmin  ProfileID = "headscale_admin"
	ProfileGoAccessProbe   ProfileID = "goaccess_probe"
	ProfileLego            ProfileID = "lego"
	ProfileHTPasswd        ProfileID = "htpasswd"
	ProfileTailscaleAdmin  ProfileID = "tailscale_admin"
)

type IdentityKind string

const (
	IdentityRoot              IdentityKind = "root_tcb"
	IdentityHeadscale         IdentityKind = "headscale"
	IdentityGoAccess          IdentityKind = "goaccess"
	IdentityCertificateStage  IdentityKind = "certificate_staging"
	IdentityEphemeralHTPasswd IdentityKind = "ephemeral_htpasswd"
	IdentityTailscaleOperator IdentityKind = "tailscale_operator"
)

type NetworkPolicy string

const (
	NetworkHostQualified NetworkPolicy = "host_qualified"
	NetworkNone          NetworkPolicy = "none"
	NetworkProviderOnly  NetworkPolicy = "provider_only"
	NetworkLocalAPIOnly  NetworkPolicy = "local_api_only"
)

type Identity struct {
	UID    uint32
	GID    uint32
	Chroot string
}

type Identities struct {
	Headscale         Identity
	GoAccess          Identity
	CertificateStage  Identity
	EphemeralHTPasswd Identity
	TailscaleOperator Identity
}

type Profile struct {
	ID                  ProfileID
	Executable          string
	Arguments           []string
	Environment         []string
	IdentityKind        IdentityKind
	UID                 uint32
	GID                 uint32
	Chroot              string
	Network             NetworkPolicy
	AllowedCapabilities []int
	Timeout             time.Duration
	MaximumInputBytes   int
	MaximumOutputBytes  int
	RootTCB             bool
	Complete            bool
}

var catalog = map[ProfileID]Profile{
	ProfileSystemdSysusers: {ID: ProfileSystemdSysusers, Executable: "/usr/bin/systemd-sysusers", Arguments: []string{"/etc/lanpanel/sysusers.conf"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedCapabilities: []int{0, 1, 2, 3, 4, 5, 6, 7}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileNginxTest:       {ID: ProfileNginxTest, Executable: "/usr/sbin/nginx", Arguments: []string{"-t", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedCapabilities: []int{0, 1, 6, 7, 10, 12}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	// The remaining profiles are deliberately unavailable until their owning
	// component supplies its release-fixed argv, identity, chroot, and network
	// qualification. There is no root or generic-exec fallback.
	ProfileAPTTransaction:  {ID: ProfileAPTTransaction, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkHostQualified, RootTCB: true},
	ProfileDPKGTransaction: {ID: ProfileDPKGTransaction, Executable: "/usr/bin/dpkg", IdentityKind: IdentityRoot, Network: NetworkNone, RootTCB: true},
	ProfileSystemctl:       {ID: ProfileSystemctl, Executable: "/usr/bin/systemctl", IdentityKind: IdentityRoot, Network: NetworkNone, RootTCB: true},
	ProfileHeadscaleAdmin:  {ID: ProfileHeadscaleAdmin, Executable: "/usr/bin/headscale", IdentityKind: IdentityHeadscale, Network: NetworkNone},
	ProfileGoAccessProbe:   {ID: ProfileGoAccessProbe, Executable: "/usr/bin/goaccess", IdentityKind: IdentityGoAccess, Network: NetworkNone},
	ProfileLego:            {ID: ProfileLego, Executable: "/usr/local/lib/lanpanel/bin/lego", IdentityKind: IdentityCertificateStage, Network: NetworkProviderOnly},
	ProfileHTPasswd:        {ID: ProfileHTPasswd, Executable: "/usr/bin/htpasswd", IdentityKind: IdentityEphemeralHTPasswd, Network: NetworkNone},
	ProfileTailscaleAdmin:  {ID: ProfileTailscaleAdmin, Executable: "/usr/bin/tailscale", IdentityKind: IdentityTailscaleOperator, Network: NetworkLocalAPIOnly},
}

func FixedProfileIDs() []ProfileID {
	ids := make([]ProfileID, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func ResolveProfile(id ProfileID, identities Identities) (Profile, error) {
	profile, known := catalog[id]
	if !known {
		return Profile{}, fmt.Errorf("external child profile is unknown")
	}
	identity := Identity{}
	switch profile.IdentityKind {
	case IdentityRoot:
		profile.UID, profile.GID = 0, 0
	case IdentityHeadscale:
		identity = identities.Headscale
	case IdentityGoAccess:
		identity = identities.GoAccess
	case IdentityCertificateStage:
		identity = identities.CertificateStage
	case IdentityEphemeralHTPasswd:
		identity = identities.EphemeralHTPasswd
	case IdentityTailscaleOperator:
		identity = identities.TailscaleOperator
	default:
		return Profile{}, fmt.Errorf("external child identity profile is unknown")
	}
	if profile.IdentityKind != IdentityRoot {
		profile.UID, profile.GID, profile.Chroot = identity.UID, identity.GID, identity.Chroot
		profile.Complete = profile.Complete && identity.UID != 0 && identity.GID != 0 && identity.Chroot != ""
	}
	profile.Arguments = append([]string(nil), profile.Arguments...)
	profile.Environment = append([]string(nil), profile.Environment...)
	profile.AllowedCapabilities = append([]int(nil), profile.AllowedCapabilities...)
	if err := validateProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func validateProfile(profile Profile) error {
	if profile.ID == "" || profile.Executable == "" || !strings.HasPrefix(profile.Executable, "/") || profile.Timeout < 0 || profile.Timeout > 30*time.Minute || profile.MaximumInputBytes < 0 || profile.MaximumInputBytes > 64<<10 || profile.MaximumOutputBytes < 0 || profile.MaximumOutputBytes > 1<<20 {
		return fmt.Errorf("external child profile shape is invalid")
	}
	for _, argument := range profile.Arguments {
		if argument == "" || len(argument) > 512 || strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("external child fixed argv is invalid")
		}
	}
	for _, value := range profile.Environment {
		if len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") || !strings.Contains(value, "=") {
			return fmt.Errorf("external child clean environment is invalid")
		}
	}
	if !profile.RootTCB && profile.Complete && (profile.UID == 0 || profile.GID == 0 || profile.Chroot == "" || len(profile.AllowedCapabilities) != 0) {
		return fmt.Errorf("unprivileged child profile lacks exact confinement")
	}
	return nil
}
