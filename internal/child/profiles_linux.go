//go:build linux

// Package child owns the release-fixed external executable profiles. Callers
// select a profile ID; they cannot supply an executable, argv, UID, capability,
// environment key, filesystem policy, or network policy.
package child

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type ProfileID string

const (
	ProfileSystemdSysusers        ProfileID = "systemd_sysusers"
	ProfileAPTDownload            ProfileID = "apt_download"
	ProfileAPTSimulate            ProfileID = "apt_simulate"
	ProfileAPTTransaction         ProfileID = "apt_transaction"
	ProfileAPTOfflineTransaction  ProfileID = "apt_offline_transaction"
	ProfileDPKGTransaction        ProfileID = "dpkg_transaction"
	ProfileSystemctl              ProfileID = "systemctl"
	ProfileSystemctlBootstrap     ProfileID = "systemctl_bootstrap"
	ProfileSystemctlNginxStart    ProfileID = "systemctl_nginx_start"
	ProfileSystemctlNginxReload   ProfileID = "systemctl_nginx_reload"
	ProfileSystemctlNginxStop     ProfileID = "systemctl_nginx_stop"
	ProfileQualificationUIRestart ProfileID = "qualification_ui_restart"
	ProfileQualificationReboot    ProfileID = "qualification_reboot"
	ProfileQualificationServices  ProfileID = "qualification_services"
	ProfileNginxStart             ProfileID = "nginx_start"
	ProfileNginxTest              ProfileID = "nginx_test"
	ProfileNginxDump              ProfileID = "nginx_dump"
	ProfileNginxReloadSignal      ProfileID = "nginx_reload_signal"
	ProfileNginxQuitSignal        ProfileID = "nginx_quit_signal"
	ProfileHeadscaleAccounts      ProfileID = "headscale_accounts"
	ProfileHeadscaleStart         ProfileID = "headscale_start"
	ProfileHeadscaleStop          ProfileID = "headscale_stop"
	ProfileHeadscaleShow          ProfileID = "headscale_show"
	ProfileHeadscaleActivateStart ProfileID = "headscale_activate_start"
	ProfileHeadscaleActivateStop  ProfileID = "headscale_activate_stop"
	ProfileHeadscaleActivateShow  ProfileID = "headscale_activate_show"
	ProfileHeadscaleFallbackStop  ProfileID = "headscale_fallback_stop"
	ProfileHeadscaleAdmin         ProfileID = "headscale_admin"
	ProfileGoAccessProbe          ProfileID = "goaccess_probe"
	ProfileGoAccessAccounts       ProfileID = "goaccess_accounts"
	ProfileGoAccessStart          ProfileID = "goaccess_start"
	ProfileGoAccessRetain         ProfileID = "goaccess_retain"
	ProfileGoAccessStop           ProfileID = "goaccess_stop"
	ProfileGoAccessShow           ProfileID = "goaccess_show"
	ProfileLego                   ProfileID = "lego"
	ProfileHTPasswd               ProfileID = "htpasswd"
	ProfileTailscaleAdmin         ProfileID = "tailscale_admin"
	ProfileResourceAccounts       ProfileID = "resource_accounts"
	ProfileResourceDaemonReload   ProfileID = "resource_daemon_reload"
	ProfileResourceStart          ProfileID = "resource_start"
	ProfileResourceStop           ProfileID = "resource_stop"
	ProfileResourceShow           ProfileID = "resource_show"
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
	Package   *PackageInvocation   `json:"package,omitempty"`
	Resource  *ResourceInvocation  `json:"resource,omitempty"`
	Headscale *HeadscaleInvocation `json:"headscale,omitempty"`
	Lego      *LegoInvocation      `json:"lego,omitempty"`
	HTPasswd  *HTPasswdInvocation  `json:"htpasswd,omitempty"`
	Tailscale *TailscaleInvocation `json:"tailscale,omitempty"`
}
type HeadscaleAdminAction string

const (
	HeadscaleUserCreate    HeadscaleAdminAction = "user_create"
	HeadscaleUserList      HeadscaleAdminAction = "user_list"
	HeadscalePreauthCreate HeadscaleAdminAction = "preauth_create"
	HeadscalePreauthList   HeadscaleAdminAction = "preauth_list"
	HeadscalePreauthRevoke HeadscaleAdminAction = "preauth_revoke"
	HeadscaleDeviceList    HeadscaleAdminAction = "device_list"
	HeadscaleDeviceExpire  HeadscaleAdminAction = "device_expire"
)

type HeadscaleInvocation struct {
	HeadscaleID       string               `json:"headscale_id"`
	AdminAction       HeadscaleAdminAction `json:"admin_action,omitempty"`
	Name              string               `json:"name,omitempty"`
	Identifier        string               `json:"identifier,omitempty"`
	ExpirationSeconds uint32               `json:"expiration_seconds,omitempty"`
}
type HTPasswdInvocation struct {
	Username string `json:"username"`
	Cost     uint32 `json:"cost"`
}
type LegoInvocation struct {
	CertificateID    string   `json:"certificate_id"`
	DirectoryURL     string   `json:"directory_url"`
	AccountEmail     string   `json:"account_email"`
	Method           string   `json:"method"`
	Provider         string   `json:"provider,omitempty"`
	Domains          []string `json:"domains"`
	Webroot          string   `json:"webroot,omitempty"`
	DataPath         string   `json:"data_path"`
	UID              uint32   `json:"uid"`
	GID              uint32   `json:"gid"`
	Chroot           string   `json:"chroot"`
	ExecutableDigest string   `json:"executable_digest"`
	Environment      []string `json:"environment"`
}

type ResourceInvocation struct {
	ResourceID string `json:"resource_id"`
	Relay      bool   `json:"relay,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	UnitMask   uint8  `json:"unit_mask,omitempty"`
}

type TailscaleAction string

const (
	TailscaleVersion TailscaleAction = "version"
	TailscaleStatus  TailscaleAction = "status"
	TailscalePrefs   TailscaleAction = "prefs"
	TailscaleLogin   TailscaleAction = "login"
)

type TailscaleInvocation struct {
	Action           TailscaleAction `json:"action"`
	ControlURL       string          `json:"control_url,omitempty"`
	AuthKeyPath      string          `json:"auth_key_path,omitempty"`
	ExecutableDigest string          `json:"executable_digest"`
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
	ExecutableDigest       string
	Umask                  uint32
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
	ProfileAPTDownload:            {ID: ProfileAPTDownload, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkHostQualified, RootTCB: true},
	ProfileAPTSimulate:            {ID: ProfileAPTSimulate, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkNone, RootTCB: true},
	ProfileAPTTransaction:         {ID: ProfileAPTTransaction, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkHostQualified, RootTCB: true},
	ProfileAPTOfflineTransaction:  {ID: ProfileAPTOfflineTransaction, Executable: "/usr/bin/apt-get", IdentityKind: IdentityRoot, Network: NetworkNoSockets, RootTCB: true},
	ProfileDPKGTransaction:        {ID: ProfileDPKGTransaction, Executable: "/usr/bin/dpkg", Arguments: []string{"--audit"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedCapabilities: packageCapabilities(), Timeout: 2 * time.Minute, MaximumOutputBytes: 256 << 10, RootTCB: true, Complete: true},
	ProfileSystemctl:              {ID: ProfileSystemctl, Executable: "/usr/bin/systemctl", Arguments: []string{"daemon-reload"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlBootstrap:     {ID: ProfileSystemctlBootstrap, Executable: "/usr/bin/systemctl", Arguments: []string{"enable", "--now", "lanpanel-runtime.service", "lanpanel-management.socket", "lanpanel-helper.service", "lanpanel-ui.service", "lanpanel-timer.timer", "lanpanel-recovery.service", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlNginxStart:    {ID: ProfileSystemctlNginxStart, Executable: "/usr/bin/systemctl", Arguments: []string{"start", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlNginxReload:   {ID: ProfileSystemctlNginxReload, Executable: "/usr/bin/systemctl", Arguments: []string{"reload", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileSystemctlNginxStop:     {ID: ProfileSystemctlNginxStop, Executable: "/usr/bin/systemctl", Arguments: []string{"stop", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileQualificationUIRestart: {ID: ProfileQualificationUIRestart, Executable: "/usr/bin/systemctl", Arguments: []string{"restart", "lanpanel-ui.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileQualificationReboot:    {ID: ProfileQualificationReboot, Executable: "/usr/bin/systemctl", Arguments: []string{"reboot"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileQualificationServices:  {ID: ProfileQualificationServices, Executable: "/usr/bin/systemctl", Arguments: []string{"show", "--property=ActiveState", "--value", "lanpanel-helper.service", "lanpanel-ui.service", "lanpanel-nginx.service", "lanpanel-headscale.service", "tailscaled.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileHeadscaleAccounts:      {ID: ProfileHeadscaleAccounts, Executable: "/usr/bin/systemd-sysusers", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedAddressFamilies: []int{1}, AllowedCapabilities: []int{0, 1, 2, 3, 4, 5, 6, 7}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileHeadscaleStart:         {ID: ProfileHeadscaleStart, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileHeadscaleStop:          {ID: ProfileHeadscaleStop, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileHeadscaleShow:          {ID: ProfileHeadscaleShow, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileHeadscaleActivateStart: {ID: ProfileHeadscaleActivateStart, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileHeadscaleActivateStop:  {ID: ProfileHeadscaleActivateStop, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileHeadscaleFallbackStop:  {ID: ProfileHeadscaleFallbackStop, Executable: "/usr/bin/systemctl", Arguments: []string{"mask", "--runtime", "--now", "lanpanel-headscale-control.socket", "lanpanel-headscale-control-relay.service", "lanpanel-headscale-stun.socket", "lanpanel-headscale-stun-relay.service", "lanpanel-headscale.service", "lanpanel-nginx.service"}, Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true, Complete: true},
	ProfileHeadscaleActivateShow:  {ID: ProfileHeadscaleActivateShow, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 128 << 10, RootTCB: true},
	ProfileHeadscaleAdmin:         {ID: ProfileHeadscaleAdmin, Executable: "/usr/lib/lanpanel/dependencies/headscale", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityHeadscale, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 1 << 20},
	ProfileGoAccessProbe:          {ID: ProfileGoAccessProbe, Executable: "/usr/bin/goaccess", IdentityKind: IdentityGoAccess, Network: NetworkNone},
	ProfileGoAccessAccounts:       {ID: ProfileGoAccessAccounts, Executable: "/usr/bin/systemd-sysusers", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedAddressFamilies: []int{1}, AllowedCapabilities: []int{0, 1, 2, 3, 4, 5, 6, 7}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileGoAccessStart:          {ID: ProfileGoAccessStart, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileGoAccessRetain:         {ID: ProfileGoAccessRetain, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileGoAccessStop:           {ID: ProfileGoAccessStop, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileGoAccessShow:           {ID: ProfileGoAccessShow, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileLego:                   {ID: ProfileLego, Executable: "/usr/lib/lanpanel/dependencies/lego", IdentityKind: IdentityCertificateStage, Network: NetworkHostQualified, AllowedAddressFamilies: []int{2, 10}, Timeout: 10 * time.Minute, MaximumInputBytes: 32 << 10, MaximumOutputBytes: 64 << 10, MaximumFileBytes: 16 << 20, Umask: 0o022, Complete: true},
	ProfileHTPasswd:               {ID: ProfileHTPasswd, Executable: "/usr/bin/htpasswd", IdentityKind: IdentityEphemeralHTPasswd, Network: NetworkNoSockets, Timeout: 5 * time.Second, MaximumInputBytes: 72, MaximumOutputBytes: 4 << 10, Complete: true},
	ProfileTailscaleAdmin:         {ID: ProfileTailscaleAdmin, Executable: "/usr/lib/lanpanel/dependencies/tailscale", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityTailscaleOperator, Network: NetworkLocalAPIOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 1 << 20},
	ProfileResourceAccounts:       {ID: ProfileResourceAccounts, Executable: "/usr/bin/systemd-sysusers", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkNone, AllowedAddressFamilies: []int{1}, AllowedCapabilities: []int{0, 1, 2, 3, 4, 5, 6, 7}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileResourceDaemonReload:   {ID: ProfileResourceDaemonReload, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileResourceStart:          {ID: ProfileResourceStart, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileResourceStop:           {ID: ProfileResourceStop, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: time.Minute, MaximumOutputBytes: 64 << 10, RootTCB: true},
	ProfileResourceShow:           {ID: ProfileResourceShow, Executable: "/usr/bin/systemctl", Environment: []string{"LANG=C", "LC_ALL=C"}, IdentityKind: IdentityRoot, Network: NetworkUnixOnly, AllowedAddressFamilies: []int{1}, Timeout: 30 * time.Second, MaximumOutputBytes: 64 << 10, RootTCB: true},
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
		profile.Complete = profile.Complete && identity.UID != 0 && identity.GID != 0 && (profile.ID == ProfileHTPasswd || identity.Chroot != "")
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
	headscaleProfile := id == ProfileHeadscaleAccounts || id == ProfileHeadscaleStart || id == ProfileHeadscaleStop || id == ProfileHeadscaleShow || id == ProfileHeadscaleActivateStart || id == ProfileHeadscaleActivateStop || id == ProfileHeadscaleActivateShow || id == ProfileHeadscaleAdmin
	if headscaleProfile {
		if invocation.Headscale == nil || !regexp.MustCompile(`^hds_[0-9a-f]{32}$`).MatchString(invocation.Headscale.HeadscaleID) || invocation.Package != nil || invocation.Resource != nil || invocation.Lego != nil || invocation.HTPasswd != nil || invocation.Tailscale != nil {
			return Profile{}, fmt.Errorf("headscale child invocation authority is invalid")
		}
		if id != ProfileHeadscaleAdmin && (invocation.Headscale.AdminAction != "" || invocation.Headscale.Name != "" || invocation.Headscale.Identifier != "" || invocation.Headscale.ExpirationSeconds != 0) {
			return Profile{}, fmt.Errorf("non-admin Headscale invocation carried lifecycle authority")
		}
		switch id {
		case ProfileHeadscaleAccounts:
			profile.Arguments = []string{"/etc/sysusers.d/lanpanel-headscale.conf"}
		case ProfileHeadscaleStart:
			profile.Arguments = []string{"start", "lanpanel-headscale.service"}
		case ProfileHeadscaleStop:
			profile.Arguments = []string{"stop", "lanpanel-headscale.service"}
		case ProfileHeadscaleShow:
			profile.Arguments = []string{"show", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlGroup,User,Group,SupplementaryGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,RestrictSUIDSGID,PrivateNetwork,PrivateTmp,PrivateDevices,RuntimeDirectory,RuntimeDirectoryMode,ProtectSystem,ProtectHome", "--property=ProtectProc,ProcSubset,ProtectKernelTunables,ProtectKernelModules,ProtectControlGroups,LockPersonality,MemoryDenyWriteExecute,SystemCallArchitectures,RestrictAddressFamilies,ReadWritePaths,UMask,KillMode,ExecStart,ExecStartPost,FragmentPath,DropInPaths", "lanpanel-headscale.service"}
		case ProfileHeadscaleActivateStart:
			profile.Arguments = []string{"start", "lanpanel-headscale-control.socket", "lanpanel-headscale-stun.socket"}
		case ProfileHeadscaleActivateStop:
			profile.Arguments = []string{"stop", "lanpanel-headscale-stun.socket", "lanpanel-headscale-stun-relay.service", "lanpanel-headscale-control.socket", "lanpanel-headscale-control-relay.service"}
		case ProfileHeadscaleActivateShow:
			profile.Arguments = []string{"show", "--property=Id,LoadState,ActiveState,SubState,User,Group,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,PrivateNetwork,JoinsNamespaceOf,RestrictAddressFamilies,ProtectSystem,ProtectHome,ProtectProc,ProcSubset,ProtectKernelTunables,ProtectKernelModules,ProtectControlGroups,LockPersonality,MemoryDenyWriteExecute,SystemCallArchitectures,RestrictSUIDSGID,KillMode,Restart,ExecStart,Sockets,Listen,SocketMode,SocketUser,SocketGroup,RemoveOnStop,FreeBind,ReusePort,FragmentPath,DropInPaths", "lanpanel-headscale-control.socket", "lanpanel-headscale-control-relay.service", "lanpanel-headscale-stun.socket", "lanpanel-headscale-stun-relay.service"}
		case ProfileHeadscaleAdmin:
			profile.Arguments, err = headscaleAdminArguments(*invocation.Headscale)
			if err != nil {
				return Profile{}, err
			}
		}
		profile.Complete = true
		return profile, validateProfile(profile)
	}
	resourceProfile := id == ProfileResourceAccounts || id == ProfileResourceDaemonReload || id == ProfileResourceStart || id == ProfileResourceStop || id == ProfileResourceShow || id == ProfileGoAccessAccounts || id == ProfileGoAccessStart || id == ProfileGoAccessRetain || id == ProfileGoAccessStop || id == ProfileGoAccessShow
	if resourceProfile {
		if invocation.Package != nil || invocation.Lego != nil || invocation.HTPasswd != nil || invocation.Tailscale != nil || invocation.Resource == nil || !validResourceIdentity(invocation.Resource.ResourceID) {
			return Profile{}, fmt.Errorf("resource child invocation authority is invalid")
		}
		short := strings.TrimPrefix(invocation.Resource.ResourceID, "res_")[:20]
		goaccessUnit := invocation.Resource.ResourceID + "-" + strconv.FormatUint(invocation.Resource.Generation, 10)
		goaccessProfile := id == ProfileGoAccessAccounts || id == ProfileGoAccessStart || id == ProfileGoAccessRetain || id == ProfileGoAccessStop || id == ProfileGoAccessShow
		if goaccessProfile != (invocation.Resource.Generation > 0) {
			return Profile{}, fmt.Errorf("resource child generation authority invalid")
		}
		switch id {
		case ProfileResourceAccounts:
			profile.Arguments = []string{"/etc/lanpanel/sysusers/" + invocation.Resource.ResourceID + ".conf"}
		case ProfileGoAccessAccounts:
			profile.Arguments = []string{"/etc/sysusers.d/lanpanel-goaccess-" + invocation.Resource.ResourceID + ".conf"}
		case ProfileGoAccessStart:
			profile.Arguments = []string{"enable", "--now", "lanpanel-goaccess-" + goaccessUnit + ".service", "lanpanel-goaccess-" + goaccessUnit + ".socket", "lanpanel-goaccess-relay-" + goaccessUnit + ".service", "lanpanel-goaccess-retention-" + goaccessUnit + ".timer"}
		case ProfileGoAccessRetain:
			profile.Arguments = []string{"start", "lanpanel-goaccess-retention-" + goaccessUnit + ".service"}
		case ProfileGoAccessStop:
			mask := invocation.Resource.UnitMask
			if mask == 0 {
				mask = 31
			}
			if mask&^uint8(31) != 0 {
				return Profile{}, fmt.Errorf("GoAccess stop unit mask invalid")
			}
			profile.Arguments = []string{"disable", "--now"}
			for _, item := range []struct {
				bit  uint8
				name string
			}{{4, "lanpanel-goaccess-" + goaccessUnit + ".socket"}, {2, "lanpanel-goaccess-relay-" + goaccessUnit + ".service"}, {1, "lanpanel-goaccess-" + goaccessUnit + ".service"}, {16, "lanpanel-goaccess-retention-" + goaccessUnit + ".timer"}, {8, "lanpanel-goaccess-retention-" + goaccessUnit + ".service"}} {
				if mask&item.bit != 0 {
					profile.Arguments = append(profile.Arguments, item.name)
				}
			}
		case ProfileGoAccessShow:
			profile.Arguments = []string{"show", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlGroup,User,Group,SupplementaryGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,RestrictSUIDSGID,PrivateNetwork,PrivateTmp,PrivateDevices,ProtectSystem,ProtectHome,ProtectProc,ProcSubset,JoinsNamespaceOf,RestrictAddressFamilies,ReadWritePaths,UMask,KillMode,ExecStart,Environment,Sockets,Service,Unit,FragmentPath,DropInPaths,Listen,SocketMode,SocketUser,SocketGroup,RuntimeDirectory,RuntimeDirectoryMode,RuntimeDirectoryPreserve,TimeoutStartUSec", "lanpanel-goaccess-" + goaccessUnit + ".service", "lanpanel-goaccess-relay-" + goaccessUnit + ".service", "lanpanel-goaccess-" + goaccessUnit + ".socket", "lanpanel-goaccess-retention-" + goaccessUnit + ".timer", "lanpanel-goaccess-retention-" + goaccessUnit + ".service"}
		case ProfileResourceDaemonReload:
			profile.Arguments = []string{"daemon-reload"}
		case ProfileResourceStart:
			profile.Arguments = []string{"enable", "--now", "lanpanel-app-" + short + ".socket", "lanpanel-app-" + short + ".service"}
			if invocation.Resource.Relay {
				profile.Arguments = []string{"enable", "--now", "lanpanel-app-" + short + ".service", "lanpanel-app-" + short + ".socket", "lanpanel-relay-" + short + ".service"}
			}
		case ProfileResourceStop:
			profile.Arguments = []string{"disable", "--now", "lanpanel-app-" + short + ".socket", "lanpanel-app-" + short + ".service"}
			if invocation.Resource.Relay {
				profile.Arguments = []string{"disable", "--now", "lanpanel-app-" + short + ".socket", "lanpanel-app-" + short + ".service", "lanpanel-relay-" + short + ".service"}
			}
		case ProfileResourceShow:
			unit := "lanpanel-app-" + short + ".service"
			if invocation.Resource.Relay {
				unit = "lanpanel-relay-" + short + ".service"
			}
			profile.Arguments = []string{"show", "--property=ActiveState,SubState,MainPID,ControlGroup,User,Group,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,RestrictSUIDSGID,SocketBindDeny,SocketBindAllow,IPAddressDeny,ProtectSystem,ProtectHome,ProtectProc,ProcSubset,PrivateTmp,PrivateDevices,LockPersonality,RestrictRealtime,RestrictAddressFamilies,ReadWritePaths,ReadOnlyPaths,BindPaths,BindReadOnlyPaths,TemporaryFileSystem,InaccessiblePaths,UMask", unit}
		}
		profile.Complete = true
		if err := validateProfile(profile); err != nil {
			return Profile{}, err
		}
		return profile, nil
	}
	if id == ProfileLego {
		return resolveLegoInvocation(profile, invocation)
	}
	if id == ProfileHTPasswd {
		return resolveHTPasswdInvocation(profile, invocation)
	}
	if id == ProfileTailscaleAdmin {
		return resolveTailscaleInvocation(profile, invocation)
	}
	if id != ProfileAPTDownload && id != ProfileAPTSimulate && id != ProfileAPTTransaction && id != ProfileAPTOfflineTransaction {
		if invocation.Package != nil || invocation.Resource != nil || invocation.Headscale != nil || invocation.Lego != nil || invocation.HTPasswd != nil || invocation.Tailscale != nil {
			return Profile{}, fmt.Errorf("external child profile rejects typed invocation")
		}
		return profile, nil
	}
	if invocation.Resource != nil || invocation.Headscale != nil || invocation.Lego != nil || invocation.HTPasswd != nil || invocation.Tailscale != nil {
		return Profile{}, fmt.Errorf("package child rejects resource or Headscale invocation")
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
	switch id {
	case ProfileAPTDownload:
		arguments = append(arguments, "--download-only")
	case ProfileAPTSimulate:
		arguments = append(arguments, "--simulate", "--no-download")
	case ProfileAPTOfflineTransaction:
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

func resolveTailscaleInvocation(profile Profile, invocation Invocation) (Profile, error) {
	if invocation.Package != nil || invocation.Resource != nil || invocation.Headscale != nil || invocation.Lego != nil || invocation.HTPasswd != nil || invocation.Tailscale == nil {
		return Profile{}, fmt.Errorf("tailscale invocation authority invalid")
	}
	value := invocation.Tailscale
	if !packageDigestPattern.MatchString(value.ExecutableDigest) {
		return Profile{}, fmt.Errorf("tailscale executable identity is invalid")
	}
	profile.ExecutableDigest = value.ExecutableDigest
	empty := value.ControlURL == "" && value.AuthKeyPath == ""
	switch value.Action {
	case TailscaleVersion:
		if !empty {
			return Profile{}, fmt.Errorf("tailscale version invocation carries mutation authority")
		}
		profile.Arguments = []string{"version", "--json"}
	case TailscaleStatus:
		if !empty {
			return Profile{}, fmt.Errorf("tailscale status invocation carries mutation authority")
		}
		profile.Arguments = []string{"status", "--json"}
	case TailscalePrefs:
		if !empty {
			return Profile{}, fmt.Errorf("tailscale prefs invocation carries mutation authority")
		}
		profile.Arguments = []string{"debug", "prefs"}
	case TailscaleLogin:
		parsed, err := url.Parse(value.ControlURL)
		base := filepath.Base(value.AuthKeyPath)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value.ControlURL || filepath.Dir(value.AuthKeyPath) != "/var/lib/lanpanel/connector/auth" || !regexp.MustCompile(`^job_[0-9a-f]{64}\.key$`).MatchString(base) {
			return Profile{}, fmt.Errorf("tailscale login authority is invalid")
		}
		profile.Arguments = []string{"up", "--login-server=" + value.ControlURL, "--auth-key=file:" + value.AuthKeyPath}
	default:
		return Profile{}, fmt.Errorf("tailscale action is unsupported")
	}
	profile.Complete = true
	return profile, validateProfile(profile)
}

func resolveHTPasswdInvocation(profile Profile, invocation Invocation) (Profile, error) {
	if invocation.Package != nil || invocation.Resource != nil || invocation.Headscale != nil || invocation.Lego != nil || invocation.Tailscale != nil || invocation.HTPasswd == nil {
		return Profile{}, fmt.Errorf("htpasswd invocation authority invalid")
	}
	value := invocation.HTPasswd
	if value.Cost != 12 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`).MatchString(value.Username) {
		return Profile{}, fmt.Errorf("htpasswd username or cost invalid")
	}
	profile.Arguments = []string{"-n", "-i", "-B", "-C", "12", value.Username}
	profile.Environment = []string{"LANG=C", "LC_ALL=C"}
	if err := validateProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func resolveLegoInvocation(profile Profile, invocation Invocation) (Profile, error) {
	if invocation.Package != nil || invocation.Resource != nil || invocation.Headscale != nil || invocation.HTPasswd != nil || invocation.Tailscale != nil || invocation.Lego == nil {
		return Profile{}, fmt.Errorf("lego child invocation authority invalid")
	}
	value := invocation.Lego
	if !regexp.MustCompile(`^cert_[0-9a-f]{32}$`).MatchString(value.CertificateID) || value.Method != "http-01" && value.Method != "dns-01" || len(value.Domains) == 0 || len(value.Domains) > 32 || !strings.HasPrefix(value.DirectoryURL, "https://") || value.DataPath != "/work" || !validACMEEmail(value.AccountEmail) || value.UID == 0 || value.GID == 0 || value.Chroot != "/var/lib/lanpanel/certificates/chroot/"+value.CertificateID || !packageDigestPattern.MatchString(value.ExecutableDigest) {
		return Profile{}, fmt.Errorf("lego invocation identity invalid")
	}
	if err := validateLegoEnvironment(value.Provider, value.Method, value.Environment); err != nil {
		return Profile{}, err
	}
	arguments := []string{"--server", value.DirectoryURL, "--email", value.AccountEmail, "--path", value.DataPath, "--accept-tos", "--pem"}
	if value.Method == "http-01" {
		if value.Webroot != "/var/lib/lanpanel/certificates/webroot/"+value.CertificateID || value.Provider != "" {
			return Profile{}, fmt.Errorf("lego HTTP-01 authority invalid")
		}
		arguments = append(arguments, "--http", "--http.webroot", value.Webroot)
	} else {
		matched, err := regexp.MatchString(`^(cloudflare|route53|digitalocean|gcloud|tencentcloud)$`, value.Provider)
		if err != nil || !matched || value.Webroot != "" {
			return Profile{}, fmt.Errorf("lego DNS-01 authority invalid")
		}
		arguments = append(arguments, "--dns", value.Provider)
	}
	previous := ""
	for _, domain := range value.Domains {
		if domain == "" || strings.ToLower(domain) != domain || strings.ContainsAny(domain, "\x00\r\n /") || previous != "" && previous >= domain {
			return Profile{}, fmt.Errorf("lego domain authority invalid")
		}
		arguments = append(arguments, "--domains", domain)
		previous = domain
	}
	arguments = append(arguments, "run", "--no-bundle")
	profile.Arguments = arguments
	profile.Environment = []string{"LANG=C", "LC_ALL=C"}
	profile.UID = value.UID
	profile.GID = value.GID
	profile.Chroot = value.Chroot
	profile.ExecutableDigest = value.ExecutableDigest
	profile.Complete = true
	if err := validateProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func validateLegoEnvironment(provider, method string, environment []string) error {
	if len(environment) < 2 || environment[0] != "LANG=C" || environment[1] != "LC_ALL=C" {
		return fmt.Errorf("lego environment identity invalid")
	}
	allowed := map[string]bool{}
	required := map[string]bool{}
	if method == "http-01" {
		if len(environment) != 2 {
			return fmt.Errorf("lego HTTP environment invalid")
		}
		return nil
	}
	schemas := map[string]struct{ required, optional []string }{"cloudflare": {[]string{"CF_DNS_API_TOKEN_FILE"}, nil}, "route53": {[]string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_REGION", "AWS_HOSTED_ZONE_ID", "AWS_PROFILE", "AWS_EC2_METADATA_DISABLED"}, nil}, "digitalocean": {[]string{"DO_AUTH_TOKEN_FILE"}, nil}, "gcloud": {[]string{"GCE_SERVICE_ACCOUNT_FILE", "GCE_PROJECT"}, nil}, "tencentcloud": {[]string{"TENCENTCLOUD_SECRET_ID_FILE", "TENCENTCLOUD_SECRET_KEY_FILE"}, []string{"TENCENTCLOUD_SESSION_TOKEN_FILE", "TENCENTCLOUD_REGION"}}}
	schema, ok := schemas[provider]
	if !ok {
		return fmt.Errorf("lego provider environment invalid")
	}
	for _, key := range schema.required {
		allowed[key] = true
		required[key] = true
	}
	for _, key := range schema.optional {
		allowed[key] = true
	}
	previous := ""
	for _, entry := range environment[2:] {
		key, value, found := strings.Cut(entry, "=")
		if !found || !allowed[key] || previous != "" && previous >= key || value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("lego environment closure invalid")
		}
		if key == "AWS_EC2_METADATA_DISABLED" && value != "true" {
			return fmt.Errorf("lego metadata fallback is not disabled")
		}
		if strings.HasSuffix(key, "_FILE") {
			if !filepath.IsAbs(value) || filepath.Clean(value) != value {
				return fmt.Errorf("lego credential path invalid")
			}
		} else if strings.ContainsAny(value, " =") {
			return fmt.Errorf("lego non-secret environment invalid")
		}
		delete(required, key)
		previous = key
	}
	if len(required) != 0 {
		return fmt.Errorf("lego environment incomplete")
	}
	return nil
}

func validACMEEmail(value string) bool {
	return len(value) >= 3 && len(value) <= 254 && strings.Count(value, "@") == 1 && !strings.ContainsAny(value, "\x00\r\n /=")
}

func headscaleAdminArguments(invocation HeadscaleInvocation) ([]string, error) {
	namePattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	identifierPattern := regexp.MustCompile(`^[0-9]{1,20}$`)
	base := []string{"--config", "/etc/lanpanel-headscale/config.yaml", "--output", "json-line"}
	empty := invocation.Name == "" && invocation.Identifier == "" && invocation.ExpirationSeconds == 0
	switch invocation.AdminAction {
	case HeadscaleUserCreate:
		if !namePattern.MatchString(invocation.Name) || invocation.Identifier != "" || invocation.ExpirationSeconds != 0 {
			return nil, fmt.Errorf("headscale user-create invocation is invalid")
		}
		return append(base, "users", "create", invocation.Name), nil
	case HeadscaleUserList:
		if !empty {
			return nil, fmt.Errorf("headscale user-list invocation is invalid")
		}
		return append(base, "users", "list"), nil
	case HeadscalePreauthCreate:
		if invocation.Name != "" || !identifierPattern.MatchString(invocation.Identifier) || invocation.ExpirationSeconds == 0 || invocation.ExpirationSeconds > 24*60*60 {
			return nil, fmt.Errorf("headscale preauth-create invocation is invalid")
		}
		return append(base, "preauthkeys", "create", "--user", invocation.Identifier, "--expiration", strconv.FormatUint(uint64(invocation.ExpirationSeconds), 10)+"s"), nil
	case HeadscalePreauthList:
		if !empty {
			return nil, fmt.Errorf("headscale preauth-list invocation is invalid")
		}
		return append(base, "preauthkeys", "list"), nil
	case HeadscalePreauthRevoke:
		if invocation.Name != "" || !identifierPattern.MatchString(invocation.Identifier) || invocation.ExpirationSeconds != 0 {
			return nil, fmt.Errorf("headscale preauth-revoke invocation is invalid")
		}
		return append(base, "preauthkeys", "expire", "--id", invocation.Identifier), nil
	case HeadscaleDeviceList:
		if !empty {
			return nil, fmt.Errorf("headscale device-list invocation is invalid")
		}
		return append(base, "nodes", "list"), nil
	case HeadscaleDeviceExpire:
		if invocation.Name != "" || !identifierPattern.MatchString(invocation.Identifier) || invocation.ExpirationSeconds != 0 {
			return nil, fmt.Errorf("headscale device-expire invocation is invalid")
		}
		return append(base, "nodes", "expire", "--identifier", invocation.Identifier), nil
	default:
		return nil, fmt.Errorf("headscale admin action is unsupported")
	}
}

func validResourceIdentity(value string) bool {
	if len(value) != 36 || !strings.HasPrefix(value, "res_") {
		return false
	}
	for _, character := range value[4:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func packageCapabilities() []int {
	return []int{0, 1, 3, 4, 5, 6, 7, 8, 9, 18, 27, 29, 31}
}

func validateProfile(profile Profile) error {
	if profile.ID == "" || profile.Executable == "" || !strings.HasPrefix(profile.Executable, "/") || profile.Timeout < 0 || profile.Timeout > 30*time.Minute || profile.MaximumInputBytes < 0 || profile.MaximumInputBytes > 64<<10 || profile.MaximumOutputBytes < 0 || profile.MaximumOutputBytes > 1<<20 || profile.MaximumFileBytes > 4<<30 || profile.Umask > 0o077 || profile.PersistentDaemon && (profile.ID != ProfileNginxStart || !profile.RootTCB || profile.Timeout != 0 || profile.MaximumFileBytes != 0) {
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
	switch profile.Network {
	case NetworkNoSockets:
		if len(profile.AllowedAddressFamilies) != 0 {
			return fmt.Errorf("no-socket child cannot allow an address family")
		}
	case NetworkNone, NetworkUnixOnly:
		if !slices.IsSorted(profile.AllowedAddressFamilies) || len(profile.AllowedAddressFamilies) == 0 {
			return fmt.Errorf("no-network child lacks an exact address-family policy")
		}
		for _, family := range profile.AllowedAddressFamilies {
			if family != 1 {
				return fmt.Errorf("no-network child address family is outside the AF_UNIX closure")
			}
		}
	}
	if !profile.RootTCB && profile.Complete && (profile.UID == 0 || profile.GID == 0 || (profile.ID != ProfileHTPasswd && profile.ID != ProfileHeadscaleAdmin && profile.ID != ProfileTailscaleAdmin && profile.Chroot == "") || len(profile.AllowedCapabilities) != 0) {
		return fmt.Errorf("unprivileged child profile lacks exact confinement")
	}
	return nil
}
