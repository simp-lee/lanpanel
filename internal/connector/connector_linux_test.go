//go:build linux

package connector

import (
	"context"
	"lanpanel/internal/child"
	"net/netip"
	"testing"
	"time"
)

type fixtureRunner struct {
	values map[child.TailscaleAction][]byte
}

func (runner fixtureRunner) Run(_ context.Context, invocation child.TailscaleInvocation) ([]byte, error) {
	return append([]byte(nil), runner.values[invocation.Action]...), nil
}

type fixtureRoute struct{ name string }

func (route fixtureRoute) InterfaceFor(netip.Addr, netip.Addr) (string, error) {
	return route.name, nil
}

func TestVerifyBindsVersionControlURLLoginAndTailnetRoute(t *testing.T) {
	now := time.Now().UTC()
	runner := fixtureRunner{values: map[child.TailscaleAction][]byte{
		child.TailscaleVersion: []byte(`{"short":"1.82.0"}`),
		child.TailscalePrefs:   []byte(`{"ControlURL":"https://control.example.test"}`),
		child.TailscaleStatus:  []byte(`{"BackendState":"Running","TailscaleIPs":["100.64.0.1"],"Health":[],"Peer":{"nodekey:peer":{"TailscaleIPs":["100.64.0.2"],"Online":true}}}`),
	}}
	observation, err := Verify(context.Background(), runner, fixtureRoute{"tailscale0"}, "1.82.0", "https://control.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPeer(observation, netip.MustParseAddr("100.64.0.2"), now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPeer(observation, netip.MustParseAddr("100.64.0.2"), now.Add(61*time.Second)); err == nil {
		t.Fatal("stale connector evidence accepted")
	}
	if _, err := Verify(context.Background(), runner, fixtureRoute{"eth0"}, "1.82.0", "https://control.example.test", now); err == nil {
		t.Fatal("LAN/default route accepted as tailnet")
	}
	if _, err := Verify(context.Background(), runner, fixtureRoute{"tailscale0"}, "1.82.0", "https://other.example.test", now); err == nil {
		t.Fatal("ControlURL mismatch accepted")
	}
}
