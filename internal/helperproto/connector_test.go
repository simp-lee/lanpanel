package helperproto

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestConnectorOfflinePeerResponseRoundTrip(t *testing.T) {
	response := Response{
		SchemaVersion: SchemaVersion,
		RequestID:     "connector-offline-round-trip",
		Code:          ResponseSucceeded,
		ResultDigest:  digest("connector-offline-round-trip"),
		Connector: &ConnectorResult{
			Operation:     "connector_verify",
			ClientVersion: "1.82.0",
			ControlURL:    "https://control.example.test",
			LocalIPs:      []string{"100.64.0.2"},
			Peers:         []ConnectorPeerRecord{{IP: "100.64.0.3", Online: false}},
			ValidUntil:    time.Now().UTC().Add(time.Minute),
		},
	}
	var wire bytes.Buffer
	if err := WriteResponse(&wire, OperationConnectorRead, response, nil); err != nil {
		t.Fatal(err)
	}
	decoded, secret, err := ReadResponse(&wire, OperationConnectorRead)
	if err != nil || secret != nil || !reflect.DeepEqual(decoded, response) {
		t.Fatalf("connector response round trip=%#v,%#v,%v", decoded, secret, err)
	}
	if decoded.Connector.Peers[0].Online {
		t.Fatal("offline connector peer changed to online")
	}
}
