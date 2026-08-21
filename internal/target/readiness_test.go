package target

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type dialTransport struct{ address, identity string }

func (value dialTransport) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", value.address)
}
func (value dialTransport) Identity() string { return value.identity }

func TestSharedReadinessSkipsDisabledWebSocketAndRejectsRedirect(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path == "/ready" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writer.Header().Set("Location", "/ready")
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	request := validProbeRequest(address)
	evidence, err := Probe(context.Background(), request, dialTransport{address, request.EndpointIdentity + "/tcp/" + address})
	if err != nil || evidence.HTTPStatus != 204 || evidence.WebSocketStatus != 0 || requests != 1 {
		t.Fatalf("evidence=%#v requests=%d error=%v", evidence, requests, err)
	}
	request.Target.ReadinessPath = "/redirect"
	request.Target.AllowedHTTPStatuses = []uint16{200}
	if _, err := Probe(context.Background(), request, dialTransport{address, request.EndpointIdentity + "/tcp/" + address}); err == nil {
		t.Fatal("redirect became readiness success")
	}
}

func TestTailnetReadinessUsesExactVerifiedTransportIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	request := ProbeRequest{ResourceID: "res_00000000000000000000000000000001", ConfigDigest: digest("config"), EndpointIdentity: digest("route"), Target: domain.AppTarget{Kind: domain.AppTargetTailnetHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{204}, TailnetHTTP: &domain.TailnetHTTPTarget{IP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080}}, AccessMode: domain.AppAccessPublic, Host: "app.example.test"}
	identity := request.EndpointIdentity + "/tailnet/100.64.0.2:8080"
	if _, err := Probe(context.Background(), request, dialTransport{address, identity}); err != nil {
		t.Fatal(err)
	}
	if _, err := Probe(context.Background(), request, dialTransport{address, request.EndpointIdentity + "/tailnet/100.64.0.3:8080"}); err == nil {
		t.Fatal("mismatched tailnet transport identity accepted")
	}
}

func TestReadinessIdentityIsStableAcrossFreshObservationTimes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	request := validProbeRequest(address)
	first, err := Probe(context.Background(), request, dialTransport{address, request.EndpointIdentity + "/tcp/" + address})
	if err != nil {
		t.Fatal(err)
	}
	request.Now = func() time.Time { return time.Unix(1700000060, 0).UTC() }
	second, err := Probe(context.Background(), request, dialTransport{address, request.EndpointIdentity + "/tcp/" + address})
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.ObservedAt.Equal(second.ObservedAt) {
		t.Fatalf("readiness identity changed across observation times: %#v %#v", first, second)
	}
}

func TestSharedReadinessValidatesWebSocketAndApplicationBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func(ignore func() error) { _ = ignore() }(listener.Close)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for count := 0; count < 2; count++ {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			request, _ := http.ReadRequest(bufioReader(connection))
			if request.URL.Path == "/ready" {
				_, _ = io.WriteString(connection, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
			} else {
				accept := websocketAccept(request.Header.Get("Sec-WebSocket-Key"))
				_, _ = fmt.Fprintf(connection, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
			}
			_ = connection.Close()
		}
	}()
	request := validProbeRequest(listener.Addr().String())
	request.Target.WebSocket = domain.WebSocketReadiness{Enabled: true, Path: "/ws"}
	evidence, err := Probe(context.Background(), request, dialTransport{listener.Addr().String(), request.EndpointIdentity + "/tcp/" + listener.Addr().String()})
	if err != nil || evidence.WebSocketStatus != 101 {
		t.Fatalf("evidence=%#v error=%v", evidence, err)
	}
	<-done

	boundary := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusUnauthorized) }))
	defer boundary.Close()
	request = validProbeRequest(strings.TrimPrefix(boundary.URL, "http://"))
	request.AccessMode = domain.AppAccessApplicationManaged
	request.Target.WebSocket = domain.WebSocketReadiness{Enabled: true, Path: "/ws"}
	request.Target.AllowedHTTPStatuses = []uint16{200}
	transport := dialTransport{strings.TrimPrefix(boundary.URL, "http://"), request.EndpointIdentity + "/tcp/" + strings.TrimPrefix(boundary.URL, "http://")}
	if _, err := Probe(context.Background(), request, transport); err != nil {
		t.Fatalf("application-managed 401 boundary rejected: %v", err)
	}
	request.ApplicationManagedWebSocketProof = &ControlledWebSocketProof{ResourceID: request.ResourceID, ConfigDigest: request.ConfigDigest, EndpointIdentity: request.EndpointIdentity, AuthenticatedStatus: 200, Digest: digest("invalid")}
	if _, err := Probe(context.Background(), request, transport); err == nil {
		t.Fatal("mismatched optional WebSocket proof accepted")
	}
}

func validProbeRequest(authority string) ProbeRequest {
	host, portText, _ := net.SplitHostPort(authority)
	var port uint16
	_, _ = fmt.Sscan(portText, &port)
	return ProbeRequest{ResourceID: "res_00000000000000000000000000000001", ConfigDigest: digest("config"), EndpointIdentity: digest("endpoint"), Target: domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: "/ready", AllowedHTTPStatuses: []uint16{204}, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: domain.LocalEndpointTCPSocketActivation, TCPAddress: host, TCPPort: port}}, AccessMode: domain.AppAccessPublic, Host: "readiness.lanpanel.invalid", Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}
}

func digest(seed string) string {
	return "sha256:" + strings.Repeat(string("abcdef0123456789"[len(seed)%16]), 64)
}
func bufioReader(reader io.Reader) *bufio.Reader { return bufio.NewReader(reader) }
