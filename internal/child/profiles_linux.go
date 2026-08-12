//go:build linux

// Package child owns the release-fixed external executable profiles. Callers
// select a profile ID; they cannot supply an executable, argv, UID, capability,
// environment key, filesystem policy, or network policy.
package child

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type ProfileID string

const (
	ProfileSystemdSysusers       ProfileID = "systemd_sysusers"
	ProfileAPTDownload           ProfileID = "apt_download"
	ProfileAPTSimulate           ProfileID = "apt_simulate"
	ProfileAPTTransaction        ProfileID = "apt_transaction"
	ProfileAPTOfflineTransaction ProfileID = "apt_offline_transaction"
	ProfileDPKGTransaction       ProfileID = "dpkg_transaction"
	ProfileSystemctl             ProfileID = "systemctl"
	ProfileSystemctlBootstrap    ProfileID = "systemctl_bootstrap"
	ProfileSystemctlNginxStart   ProfileID = "systemctl_nginx_start"
	ProfileSystemctlNginxReload  ProfileID = "systemctl_nginx_reload"
	ProfileSystemctlNginxStop    ProfileID = "systemctl_nginx_stop"
	ProfileNginxStart            ProfileID = "nginx_start"
	ProfileNginxTest             ProfileID = "nginx_test"
	ProfileNginxDump             ProfileID = "nginx_dump"
	ProfileNginxReloadSignal     ProfileID = "nginx_reload_signal"
	ProfileNginxQuitSignal       ProfileID = "nginx_quit_signal"
	ProfileHeadscaleAdmin        ProfileID = "headscale_admin"
	ProfileGoAccessProbe         ProfileID = "goaccess_probe"
	ProfileLego                  ProfileID = "lego"
	ProfileHTPasswd              ProfileID = "htpasswd"
	ProfileTailscaleAdmin        ProfileID = "tailscale_admin"
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
	NetworkUnixOnly      NetworkPolicy = "host_unix_only"
	NetworkNone          NetworkPolicy = "none"
	NetworkNoSockets     NetworkPolicy = "none_no_sockets"
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

type PackageChange struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PackageArgument struct {
	Name                      string `json:"name"`
	Version                   string `json:"version"`
	Digest                    string `json:"digest"`
	Bytes                     int64  `json:"bytes"`
	MaximumInstalledFileBytes int64  `json:"maximum_installed_file_bytes"`
}

type Invocation struct {
	Package *PackageInvocation `json:"package,omitempty"`
}

type PackageInvocation struct {
	TransactionID   string            `json:"transaction_id"`
	LockWaitSeconds uint32            `json:"lock_wait_seconds"`
	Staged          bool              `json:"staged"`
	Packages        []PackageArgument `json:"packages"`
}

type Profile struct {
	ID                     ProfileID
	Executable             string
	Arguments              []string
	Environment            []string
	IdentityKind           IdentityKind
	UID                    uint32
	GID                    uint32
	Chroot                 string
	Network                NetworkPolicy
	AllowedAddressFamilies []int
	AllowedCapabilities    []int
	Timeout                time.Duration
	MaximumInputBytes      int
	MaximumOutputBytes     int
	MaximumFileBytes       uint64
	RootTCB                bool
	PersistentDaemon       bool
	Complete               bool
}

var catalog = map[ProfileID]Profile{
	ProfileSystemdSysusers:   {ID: ProfileSystemdSysusers, Executable: "/usr/bin/systemd-sysusers", Arguments: []string{"/etc/lanpanel-sysusers.conf"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedCapabilities: []int{0, 1, 2, 3, 4, 5, 6, 7}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileNginxStart:        {ID: ProfileNginxStart, Executable: "/usr/sbin/nginx", Arguments: []string{"-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/", "-g", "daemon off;"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkHostQualified, AllowedCapabilities: []int{0, 1, 5, 6, 7, 10}, RootTCB: true, PersistentDaemon: true, Complete: true},
	ProfileNginxTest:         {ID: ProfileNginxTest, Executable: "/usr/sbin/nginx", Arguments: []string{"-t", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, AllowedCapabilities: []int{0, 1, 6, 7, 10}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileNginxDump:         {ID: ProfileNginxDump, Executable: "/usr/sbin/nginx", Arguments: []string{"-T", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, AllowedCapabilities: []int{0, 1, 6, 7, 10}, Timeout: 30 * time.Second, MaximumOutputBytes: 1 << 20, RootTCB: true, Complete: true},
	ProfileNginxReloadSignal: {ID: ProfileNginxReloadSignal, Executable: "/usr/sbin/nginx", Arguments: []string{"-s", "reload", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, AllowedCapabilities: []int{0, 1, 5, 6, 7, 10}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileNginxQuitSignal:   {ID: ProfileNginxQuitSignal, Executable: "/usr/sbin/nginx", Arguments: []string{"-s", "quit", "-c", "/etc/lanpanel/nginx/nginx.conf", "-p", "/var/lib/lanpanel/nginx/"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, AllowedCapabilities: []int{0, 1, 5, 6, 7, 10}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	// The remaining profiles are deliberately unavailable until their owning
	// component supplies its release-fixed argv, identity, chroot, and network
	// qualification. There is no root or generic-exec fallback.
	ProfileAPTDownload:           {ID: ProfileAPTDownload, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkHostQualified, RootTCB: true},
	ProfileAPTSimulate:           {ID: ProfileAPTSimulate, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkNone, RootTCB: true},
	ProfileAPTTransaction:        {ID: ProfileAPTTransaction, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkHostQualified, RootTCB: true},
	ProfileAPTOfflineTransaction: {ID: ProfileAPTOfflineTransaction, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkNoSockets, RootTCB: true},
	ProfileDPKGTransaction:       {ID: ProfileDPKGTransaction, Executable: "/usr/bin/dpkg", Arguments: []string{"--audit"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedCapabilities: packageCapabilities(), Timeout: 2 * time.Minute, MaximumOutputBytes: 256 << 10, RootTCB: true, Complete: true},
	ProfileSystemctl:             {ID: ProfileSystemctl, Executable: "/usr/bin/systemctl", Arguments: []string{"daemon-reload"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlBootstrap:    {ID: ProfileSystemctlBootstrap, Executable: "/usr/bin/systemctl", Arguments: []string{"enable", "--now", "lanpanel-runtime.service", "lanpanel-management.socket", "lanpanel-helper.service", "lanpanel-ui.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlNginxStart:   {ID: ProfileSystemctlNginxStart, Executable: "/usr/bin/systemctl", Arguments: []string{"start", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlNginxReload:  {ID: ProfileSystemctlNginxReload, Executable: "/usr/bin/systemctl", Arguments: []string{"reload", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlNginxStop:    {ID: ProfileSystemctlNginxStop, Executable: "/usr/bin/systemctl", Arguments: []string{"stop", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileHeadscaleAdmin:        {ID: ProfileHeadscaleAdmin, Executable: "/usr/bin/headscale", IdentityKind: IdentityHeadscale, Network: NetworkNone},
	ProfileGoAccessProbe:         {ID: ProfileGoAccessProbe, Executable: "/usr/bin/goaccess", IdentityKind: IdentityGoAccess, Network: NetworkNone},
	ProfileLego:                  {ID: ProfileLego, Executable: "/usr/local/lib/lanpanel/bin/lego", IdentityKind: IdentityCertificateStage, Network: NetworkProviderOnly},
	ProfileHTPasswd:              {ID: ProfileHTPasswd, Executable: "/usr/bin/htpasswd", IdentityKind: IdentityEphemeralHTPasswd, Network: NetworkNone},
	ProfileTailscaleAdmin:        {ID: ProfileTailscaleAdmin, Executable: "/usr/bin/tailscale", IdentityKind: IdentityTailscaleOperator, Network: NetworkLocalAPIOnly},
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
	if profile.Network == NetworkNone && len(profile.AllowedAddressFamilies) == 0 {
		profile.AllowedAddressFamilies = []int{1}
	} else {
		profile.AllowedAddressFamilies = append([]int(nil), profile.AllowedAddressFamilies...)
	}
	profile.AllowedCapabilities = append([]int(nil), profile.AllowedCapabilities...)
	if err := validateProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

var (
	packageTransactionPattern = regexp.MustCompile(`^pkg_[0-9a-f]{64}$`)
	packageNamePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
	packageVersionPattern     = regexp.MustCompile(`^[0-9][0-9A-Za-z.+:~_-]{0,127}$`)
	packageDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func ResolveInvocation(id ProfileID, identities Identities, invocation Invocation) (Profile, error) {
	profile, err := ResolveProfile(id, identities)
	if err != nil {
		return Profile{}, err
	}
	if id != ProfileAPTDownload && id != ProfileAPTSimulate && id != ProfileAPTTransaction && id != ProfileAPTOfflineTransaction {
		if invocation.Package != nil {
			return Profile{}, fmt.Errorf("external child profile rejects package invocation")
		}
		return profile, nil
	}
	if invocation.Package == nil || !packageTransactionPattern.MatchString(invocation.Package.TransactionID) || invocation.Package.LockWaitSeconds == 0 || invocation.Package.LockWaitSeconds > 300 || len(invocation.Package.Packages) == 0 || len(invocation.Package.Packages) > 256 || (id == ProfileAPTDownload || id == ProfileAPTTransaction) && invocation.Package.Staged || id == ProfileAPTOfflineTransaction && !invocation.Package.Staged {
		return Profile{}, fmt.Errorf("package child invocation authority is invalid")
	}
	arguments := []string{
		"-c", "/var/lib/lanpanel/packages/transactions/" + invocation.Package.TransactionID + "/apt.conf",
		"-o", "APT::Get::Assume-Yes=true",
		"-o", "APT::Install-Recommends=false",
		"-o", "APT::Install-Suggests=false",
		"-o", "APT::Get::AllowUnauthenticated=false",
		"-o", "Acquire::AllowInsecureRepositories=false",
		"-o", "Dpkg::Use-Pty=0",
		"-o", "DPkg::Options::=--force-confold",
		"-o", "DPkg::Lock::Timeout=" + strconv.FormatUint(uint64(invocation.Package.LockWaitSeconds), 10),
		"--no-remove",
	}
	if id == ProfileAPTDownload {
		arguments = append(arguments, "--download-only")
	} else if id == ProfileAPTSimulate {
		arguments = append(arguments, "--simulate", "--no-download")
	} else if id == ProfileAPTOfflineTransaction {
		arguments = append(arguments, "--no-download")
	}
	arguments = append(arguments, "install")
	previous := ""
	maximumFileBytes := int64(64 << 20)
	for _, pkg := range invocation.Package.Packages {
		if !packageNamePattern.MatchString(pkg.Name) || !packageVersionPattern.MatchString(pkg.Version) || !packageDigestPattern.MatchString(pkg.Digest) || pkg.Bytes <= 0 || pkg.Bytes > 4<<30 || pkg.MaximumInstalledFileBytes <= 0 || pkg.MaximumInstalledFileBytes > 4<<30 || previous != "" && strings.Compare(previous, pkg.Name) >= 0 {
			return Profile{}, fmt.Errorf("package child closure is invalid, duplicated, or unsorted")
		}
		if id == ProfileAPTOfflineTransaction || id == ProfileAPTSimulate && invocation.Package.Staged {
			arguments = append(arguments, "/var/lib/lanpanel/packages/staging/"+invocation.Package.TransactionID+"/"+pkg.Digest+".deb")
		} else {
			arguments = append(arguments, pkg.Name+"="+pkg.Version)
		}
		maximumFileBytes = max(maximumFileBytes, pkg.Bytes, pkg.MaximumInstalledFileBytes)
		previous = pkg.Name
	}
	profile.Arguments = arguments
	profile.Environment = []string{"APT_LISTCHANGES_FRONTEND=none", "DEBIAN_FRONTEND=noninteractive", "LANG=C", "LC_ALL=C"}
	if id != ProfileAPTSimulate {
		profile.AllowedCapabilities = packageCapabilities()
	}
	profile.Timeout = 30 * time.Minute
	profile.MaximumOutputBytes = 1 << 20
	profile.MaximumFileBytes = uint64(maximumFileBytes)
	profile.Complete = true
	if err := validateProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func packageCapabilities() []int {
	return []int{0, 1, 3, 4, 5, 6, 7, 8, 9, 18, 27, 29, 31}
}

func validateProfile(profile Profile) error {
	if profile.ID == "" || profile.Executable == "" || !strings.HasPrefix(profile.Executable, "/") || profile.Timeout < 0 || profile.Timeout > 30*time.Minute || profile.MaximumInputBytes < 0 || profile.MaximumInputBytes > 64<<10 || profile.MaximumOutputBytes < 0 || profile.MaximumOutputBytes > 1<<20 || profile.MaximumFileBytes > 4<<30 || profile.PersistentDaemon && (profile.ID != ProfileNginxStart || !profile.RootTCB || profile.Timeout != 0 || profile.MaximumFileBytes != 0) {
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
	if profile.Network == NetworkNoSockets {
		if len(profile.AllowedAddressFamilies) != 0 {
			return fmt.Errorf("no-socket child cannot allow an address family")
		}
	} else if profile.Network == NetworkNone || profile.Network == NetworkUnixOnly {
		if !slices.IsSorted(profile.AllowedAddressFamilies) || len(profile.AllowedAddressFamilies) == 0 {
			return fmt.Errorf("no-network child lacks an exact address-family policy")
		}
		for _, family := range profile.AllowedAddressFamilies {
			if family != 1 {
				return fmt.Errorf("no-network child address family is outside the AF_UNIX closure")
			}
		}
	}
	if !profile.RootTCB && profile.Complete && (profile.UID == 0 || profile.GID == 0 || profile.Chroot == "" || len(profile.AllowedCapabilities) != 0) {
		return fmt.Errorf("unprivileged child profile lacks exact confinement")
	}
	return nil
}
