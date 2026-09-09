//go:build linux

package helper

import (
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/helperproto"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestHelperConnectorObservationPreservesOfflinePeer(t *testing.T) {
	validUntil := time.Now().UTC().Add(managedconnector.EvidenceTTL)
	observation := managedconnector.Observation{
		ClientVersion: "1.82.0",
		ControlURL:    "https://control.example.test",
		LocalIPs:      []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::2"), netip.MustParseAddr("100.64.0.2")},
		Peers: []managedconnector.Peer{
			{IP: netip.MustParseAddr("100.64.0.4"), Online: false},
			{IP: netip.MustParseAddr("100.64.0.3"), Online: true},
		},
		ValidUntil: validUntil,
	}

	got := helperConnectorObservation(observation)
	want := helperproto.ConnectorResult{
		Operation:     "connector_verify",
		ClientVersion: observation.ClientVersion,
		ControlURL:    observation.ControlURL,
		LocalIPs:      []string{"100.64.0.2", "fd7a:115c:a1e0::2"},
		Peers: []helperproto.ConnectorPeerRecord{
			{IP: "100.64.0.3", Online: true},
			{IP: "100.64.0.4", Online: false},
		},
		ValidUntil: validUntil,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("helperConnectorObservation()=%#v, want %#v", got, want)
	}
}
