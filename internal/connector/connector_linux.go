//go:build linux

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const EvidenceTTL = 60 * time.Second

type Runner interface {
	Run(context.Context, child.TailscaleInvocation) ([]byte, error)
}

type FixedRunner struct {
	launcher *child.Launcher
	digest   string
}

func NewFixedRunner(uid, gid uint32, executableDigest string) (*FixedRunner, error) {
	if uid == 0 || gid == 0 || len(executableDigest) != 64 {
		return nil, fmt.Errorf("tailscale operator identity is invalid")
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{TailscaleOperator: child.Identity{UID: uid, GID: gid}})
	if err != nil {
		return nil, err
	}
	return &FixedRunner{launcher: launcher, digest: executableDigest}, nil
}

func (runner *FixedRunner) Run(ctx context.Context, invocation child.TailscaleInvocation) ([]byte, error) {
	if runner == nil || runner.launcher == nil {
		return nil, fmt.Errorf("tailscale runner is unavailable")
	}
	invocation.ExecutableDigest = runner.digest
	result, err := runner.launcher.RunInvocation(ctx, child.ProfileTailscaleAdmin, child.Invocation{Tailscale: &invocation}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff || invocation.Action != child.TailscaleLogin && len(result.Stdout) == 0 {
		clear(result.Stdout)
		return nil, errors.Join(err, fmt.Errorf("tailscale child failed"))
	}
	return result.Stdout, nil
}

type Peer struct {
	IP     netip.Addr `json:"ip"`
	Online bool       `json:"online"`
}

type Observation struct {
	ClientVersion string       `json:"client_version"`
	ControlURL    string       `json:"control_url"`
	LocalIPs      []netip.Addr `json:"local_ips"`
	Peers         []Peer       `json:"peers"`
	ObservedAt    time.Time    `json:"observed_at"`
	ValidUntil    time.Time    `json:"valid_until"`
}

type RouteObserver interface {
	InterfaceFor(netip.Addr, netip.Addr) (string, error)
}

func Verify(ctx context.Context, runner Runner, route RouteObserver, expectedVersion, expectedControlURL string, now time.Time) (Observation, error) {
	if runner == nil || route == nil || expectedVersion == "" || !canonicalControlURL(expectedControlURL) || now.IsZero() {
		return Observation{}, fmt.Errorf("connector verification authority is incomplete")
	}
	versionRaw, err := runner.Run(ctx, child.TailscaleInvocation{Action: child.TailscaleVersion})
	if err != nil {
		return Observation{}, err
	}
	defer clear(versionRaw)
	var version map[string]json.RawMessage
	if decodeJSON(versionRaw, &version) != nil {
		return Observation{}, fmt.Errorf("tailscale version JSON invalid")
	}
	var observedVersion string
	if json.Unmarshal(version["short"], &observedVersion) != nil || observedVersion != expectedVersion {
		return Observation{}, fmt.Errorf("tailscale client version drift")
	}
	prefsRaw, err := runner.Run(ctx, child.TailscaleInvocation{Action: child.TailscalePrefs})
	if err != nil {
		return Observation{}, err
	}
	defer clear(prefsRaw)
	var prefs map[string]json.RawMessage
	if decodeJSON(prefsRaw, &prefs) != nil {
		return Observation{}, fmt.Errorf("tailscale prefs JSON invalid")
	}
	var controlURL string
	if json.Unmarshal(prefs["ControlURL"], &controlURL) != nil || controlURL != expectedControlURL {
		return Observation{}, fmt.Errorf("connector ControlURL mismatch; administrator must resolve outside LanPanel")
	}
	statusRaw, err := runner.Run(ctx, child.TailscaleInvocation{Action: child.TailscaleStatus})
	if err != nil {
		return Observation{}, err
	}
	defer clear(statusRaw)
	var status map[string]json.RawMessage
	if decodeJSON(statusRaw, &status) != nil {
		return Observation{}, fmt.Errorf("tailscale status JSON invalid")
	}
	var backend string
	if json.Unmarshal(status["BackendState"], &backend) != nil || backend != "Running" {
		return Observation{}, fmt.Errorf("tailscaled is not active and logged in")
	}
	var health []string
	if raw, present := status["Health"]; present && string(raw) != "null" && json.Unmarshal(raw, &health) != nil {
		return Observation{}, fmt.Errorf("tailscale health JSON invalid")
	}
	if len(health) != 0 {
		return Observation{}, fmt.Errorf("tailscale health reports degraded state")
	}
	var localText []string
	if json.Unmarshal(status["TailscaleIPs"], &localText) != nil || len(localText) == 0 {
		return Observation{}, fmt.Errorf("connector has no local tailnet IP")
	}
	local := make([]netip.Addr, 0, len(localText))
	localSet := map[netip.Addr]bool{}
	for _, text := range localText {
		address, err := netip.ParseAddr(text)
		if err != nil || address.IsUnspecified() || address.IsLoopback() {
			return Observation{}, fmt.Errorf("connector local tailnet IP invalid")
		}
		local, localSet[address] = append(local, address), true
	}
	var peerMap map[string]json.RawMessage
	if raw, present := status["Peer"]; present && string(raw) != "null" {
		if json.Unmarshal(raw, &peerMap) != nil {
			return Observation{}, fmt.Errorf("tailscale peer JSON invalid")
		}
	}
	peers := []Peer{}
	seen := map[netip.Addr]bool{}
	for _, raw := range peerMap {
		var value map[string]json.RawMessage
		if json.Unmarshal(raw, &value) != nil {
			return Observation{}, fmt.Errorf("tailscale peer entry invalid")
		}
		var ips []string
		var online bool
		if json.Unmarshal(value["TailscaleIPs"], &ips) != nil || json.Unmarshal(value["Online"], &online) != nil {
			return Observation{}, fmt.Errorf("tailscale peer route evidence incomplete")
		}
		for _, text := range ips {
			address, err := netip.ParseAddr(text)
			if err != nil || localSet[address] || seen[address] {
				return Observation{}, fmt.Errorf("tailscale peer IP inventory invalid")
			}
			var source netip.Addr
			for _, candidate := range local {
				if candidate.BitLen() == address.BitLen() {
					source = candidate
					break
				}
			}
			if !source.IsValid() {
				return Observation{}, fmt.Errorf("peer route has no same-family local source")
			}
			iface, err := route.InterfaceFor(source, address)
			if err != nil || iface != "tailscale0" {
				return Observation{}, fmt.Errorf("peer route is not through tailscale0")
			}
			seen[address] = true
			peers = append(peers, Peer{IP: address, Online: online})
		}
	}
	return Observation{ClientVersion: observedVersion, ControlURL: controlURL, LocalIPs: local, Peers: peers, ObservedAt: now.UTC(), ValidUntil: now.UTC().Add(EvidenceTTL)}, nil
}

func VerifyPeer(observation Observation, address netip.Addr, now time.Time) error {
	if now.IsZero() || observation.ObservedAt.IsZero() || now.Before(observation.ObservedAt) || now.After(observation.ValidUntil) || observation.ValidUntil.Sub(observation.ObservedAt) > EvidenceTTL {
		return fmt.Errorf("connector evidence is stale")
	}
	for _, local := range observation.LocalIPs {
		if local == address {
			return fmt.Errorf("tailnet target cannot be this connector")
		}
	}
	for _, peer := range observation.Peers {
		if peer.IP == address {
			if !peer.Online {
				return fmt.Errorf("tailnet peer is offline")
			}
			return nil
		}
	}
	return fmt.Errorf("tailnet peer IP is not in fresh connector evidence")
}

func PreflightLogin(ctx context.Context, runner Runner, expectedControlURL string) error {
	if runner == nil || !canonicalControlURL(expectedControlURL) {
		return fmt.Errorf("connector login preflight authority is incomplete")
	}
	prefsRaw, err := runner.Run(ctx, child.TailscaleInvocation{Action: child.TailscalePrefs})
	if err != nil {
		return err
	}
	defer clear(prefsRaw)
	var prefs map[string]json.RawMessage
	if decodeJSON(prefsRaw, &prefs) != nil {
		return fmt.Errorf("tailscale prefs JSON invalid")
	}
	var currentURL string
	if json.Unmarshal(prefs["ControlURL"], &currentURL) != nil {
		return fmt.Errorf("tailscale ControlURL is unavailable")
	}
	statusRaw, err := runner.Run(ctx, child.TailscaleInvocation{Action: child.TailscaleStatus})
	if err != nil {
		return err
	}
	defer clear(statusRaw)
	var status map[string]json.RawMessage
	if decodeJSON(statusRaw, &status) != nil {
		return fmt.Errorf("tailscale status JSON invalid")
	}
	var backend string
	if json.Unmarshal(status["BackendState"], &backend) != nil {
		return fmt.Errorf("tailscale backend state is unavailable")
	}
	if backend == "Running" {
		return fmt.Errorf("connector is already logged in; adoption or rebinding is unsupported")
	}
	if backend != "NeedsLogin" && backend != "NoState" && backend != "Stopped" {
		return fmt.Errorf("connector pre-login state is unknown")
	}
	if currentURL != "" && currentURL != "https://controlplane.tailscale.com" && currentURL != expectedControlURL {
		return fmt.Errorf("connector pre-login ControlURL is foreign")
	}
	return nil
}

func Login(ctx context.Context, runner Runner, controlURL, authKeyPath string) error {
	if runner == nil || !canonicalControlURL(controlURL) || authKeyPath == "" {
		return fmt.Errorf("connector login authority is incomplete")
	}
	raw, err := runner.Run(ctx, child.TailscaleInvocation{Action: child.TailscaleLogin, ControlURL: controlURL, AuthKeyPath: authKeyPath})
	clear(raw)
	return err
}

func canonicalControlURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Opaque == "" && parsed.String() == value
}

func decodeJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func RedactedSummary(observation Observation) string {
	return fmt.Sprintf("version=%s control=%s local_ips=%d peers=%d valid_until=%s", observation.ClientVersion, observation.ControlURL, len(observation.LocalIPs), len(observation.Peers), observation.ValidUntil.UTC().Format(time.RFC3339))
}

func ControlURLHost(value string) string {
	parsed, _ := url.Parse(value)
	return strings.ToLower(parsed.Hostname())
}
