//go:build linux

package application

import (
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/helperproto"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestClientConnectorObservationPreservesOfflinePeer(t *testing.T) {
	validUntil := time.Now().UTC().Add(managedconnector.EvidenceTTL)
	observation, err := clientConnectorObservation(helperproto.ConnectorResult{
		ClientVersion: "1.82.0",
		ControlURL:    "https://control.example.test",
		LocalIPs:      []string{"100.64.0.2"},
		Peers:         []helperproto.ConnectorPeerRecord{{IP: "100.64.0.3", Online: false}},
		ValidUntil:    validUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Peers) != 1 || observation.Peers[0].IP != netip.MustParseAddr("100.64.0.3") || observation.Peers[0].Online {
		t.Fatalf("offline peer changed during client conversion: %#v", observation.Peers)
	}
	if err := managedconnector.VerifyPeer(observation, observation.Peers[0].IP, observation.ObservedAt); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("offline peer verification error=%v", err)
	}
}
