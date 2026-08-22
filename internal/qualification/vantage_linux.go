//go:build linux

package qualification

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"lanpanel/internal/release"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const VantageAuthoritySchemaVersion = "lanpanel.qualification.direct-vantage.v1"

type VantageAuthority struct {
	SchemaVersion      string `json:"schema_version"`
	ExpectedSourceIPv4 string `json:"expected_source_ipv4"`
}

type PublicProbe struct {
	Scheme                string
	ConnectIPv4           string
	Port                  uint16
	Host                  string
	Path                  string
	Authorization         string
	BasicUsername         string
	BasicPassword         string
	ExpectedStatus        int
	ExpectedBodyDigest    string
	ExpectedAuthorization string
	WebSocket             bool
}

type PublicEvidence struct {
	SchemaVersion    string `json:"schema_version"`
	URL              string `json:"url"`
	Status           int    `json:"status"`
	BodyDigest       string `json:"body_digest"`
	ObservedSourceIP string `json:"observed_source_ip,omitempty"`
	TLSVersion       uint16 `json:"tls_version,omitempty"`
	WebSocket        bool   `json:"websocket"`
}

func LoadVantageAuthority(reference string) (VantageAuthority, string, error) {
	if !strings.HasPrefix(reference, "file:") {
		return VantageAuthority{}, "", fmt.Errorf("direct external vantage requires an explicit protected file reference")
	}
	data, _, err := readProtectedFile(strings.TrimPrefix(reference, "file:"), 1<<20, true)
	if err != nil {
		return VantageAuthority{}, "", err
	}
	var value VantageAuthority
	if err := release.DecodeCanonical(data, &value); err != nil {
		return VantageAuthority{}, "", err
	}
	address, err := netip.ParseAddr(value.ExpectedSourceIPv4)
	if value.SchemaVersion != VantageAuthoritySchemaVersion || err != nil || !address.Is4() || address.String() != value.ExpectedSourceIPv4 || !publicIPv4(address) {
		return VantageAuthority{}, "", fmt.Errorf("direct external vantage authority is invalid")
	}
	return value, release.DigestBytes(data), nil
}

func ProbePublic(ctx context.Context, vantage VantageAuthority, probe PublicProbe) ([]byte, error) {
	address, err := netip.ParseAddr(probe.ConnectIPv4)
	hostAddress, hostErr := netip.ParseAddr(probe.Host)
	validHost := canonicalDomain(probe.Host) || hostErr == nil && hostAddress.Is4() && hostAddress.String() == probe.Host
	if err != nil || !address.Is4() || address.String() != probe.ConnectIPv4 || !publicIPv4(address) || probe.Port == 0 || !validHost || probe.Scheme == "https" && !canonicalDomain(probe.Host) || probe.Path == "" || !strings.HasPrefix(probe.Path, "/") || strings.ContainsAny(probe.Path, "\x00\r\n") || probe.Scheme != "http" && probe.Scheme != "https" || probe.ExpectedStatus < 100 || probe.ExpectedStatus > 599 {
		return nil, fmt.Errorf("public probe authority is invalid")
	}
	connectAddress := net.JoinHostPort(probe.ConnectIPv4, strconv.Itoa(int(probe.Port)))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: probe.Scheme == "https", DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
		if requested != net.JoinHostPort(probe.Host, strconv.Itoa(int(probe.Port))) {
			return nil, fmt.Errorf("public probe destination escaped exact authority")
		}
		return (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}).DialContext(ctx, "tcp4", connectAddress)
	}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: probe.Host}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	probeURL := probe.Scheme + "://" + net.JoinHostPort(probe.Host, strconv.Itoa(int(probe.Port))) + probe.Path
	if probe.Scheme == "https" && probe.Port == 443 {
		probeURL = probe.Scheme + "://" + probe.Host + probe.Path
	}
	if probe.WebSocket {
		return probePublicWebSocket(ctx, client, probeURL)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, err
	}
	request.Host = probe.Host
	if probe.Scheme == "http" && probe.Port != 80 {
		request.Host = net.JoinHostPort(probe.Host, strconv.Itoa(int(probe.Port)))
	}
	request.Header.Set("Authorization", probe.Authorization)
	if probe.BasicUsername != "" {
		request.SetBasicAuth(probe.BasicUsername, probe.BasicPassword)
	}
	for key, value := range map[string]string{"Forwarded": "for=203.0.113.1", "X-Forwarded-For": "203.0.113.2", "X-Forwarded-Host": "attacker.invalid", "X-Forwarded-Proto": "gopher", "X-Real-IP": "203.0.113.3", "CF-Connecting-IP": "203.0.113.4", "True-Client-IP": "203.0.113.5"} {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	body, err := readHTTPResponse(response, 4<<20)
	if err != nil || response.StatusCode != probe.ExpectedStatus || probe.ExpectedBodyDigest != "" && release.DigestBytes(body) != probe.ExpectedBodyDigest {
		return nil, fmt.Errorf("public probe status or body differs: status=%d digest=%s: %w", response.StatusCode, release.DigestBytes(body), err)
	}
	evidence := PublicEvidence{SchemaVersion: "lanpanel.qualification.public-evidence.v1", URL: probe.Scheme + "://" + probe.Host + probe.Path, Status: response.StatusCode, BodyDigest: release.DigestBytes(body)}
	if response.TLS != nil {
		evidence.TLSVersion = response.TLS.Version
	}
	if probe.Path == "/echo" {
		var echo struct {
			Authorization   string `json:"authorization"`
			Forwarded       string `json:"forwarded"`
			XForwardedFor   string `json:"x_forwarded_for"`
			XForwardedHost  string `json:"x_forwarded_host"`
			XForwardedProto string `json:"x_forwarded_proto"`
			XRealIP         string `json:"x_real_ip"`
			CFConnectingIP  string `json:"cf_connecting_ip"`
			TrueClientIP    string `json:"true_client_ip"`
		}
		if err := json.Unmarshal(body, &echo); err != nil || echo.Authorization != probe.ExpectedAuthorization || echo.Forwarded != "" || echo.CFConnectingIP != "" || echo.TrueClientIP != "" || echo.XRealIP != vantage.ExpectedSourceIPv4 || echo.XForwardedFor != vantage.ExpectedSourceIPv4 || echo.XForwardedHost != probe.Host || echo.XForwardedProto != probe.Scheme {
			return nil, fmt.Errorf("public probe header sanitization or external source identity differs: %w", err)
		}
		evidence.ObservedSourceIP = echo.XRealIP
	}
	return release.MarshalCanonical(evidence)
}

func ProbeSTUN(ctx context.Context, target string) ([]byte, error) {
	address, err := netip.ParseAddr(target)
	if err != nil || !address.Is4() || address.String() != target || !publicIPv4(address) {
		return nil, fmt.Errorf("STUN target authority is invalid")
	}
	connection, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}).DialContext(ctx, "udp4", net.JoinHostPort(target, "3478"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = connection.Close() }()
	var transaction [12]byte
	if _, err := rand.Read(transaction[:]); err != nil {
		return nil, err
	}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], 0x2112a442)
	copy(request[8:], transaction[:])
	if _, err := connection.Write(request); err != nil {
		return nil, err
	}
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 2048)
	count, err := connection.Read(response)
	if err != nil || count < 20 || binary.BigEndian.Uint16(response[:2]) != 0x0101 || binary.BigEndian.Uint32(response[4:8]) != 0x2112a442 || !bytes.Equal(response[8:20], transaction[:]) {
		return nil, fmt.Errorf("public STUN binding response is invalid: %w", err)
	}
	return release.MarshalCanonical(PublicEvidence{SchemaVersion: "lanpanel.qualification.public-evidence.v1", URL: "stun:" + target + ":3478", Status: 200, BodyDigest: release.DigestBytes(response[:count])})
}

func ProbeDERP(ctx context.Context, targetIP, host string) ([]byte, error) {
	address, err := netip.ParseAddr(targetIP)
	if err != nil || !address.Is4() || address.String() != targetIP || !publicIPv4(address) || !canonicalDomain(host) {
		return nil, fmt.Errorf("DERP probe authority is invalid")
	}
	tlsDialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
	connection, err := tlsDialer.DialContext(ctx, "tcp4", net.JoinHostPort(targetIP, "443"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = connection.Close() }()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/derp", nil)
	request.Host = host
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "DERP")
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), "DERP") {
		return nil, fmt.Errorf("public DERP upgrade endpoint did not switch protocols")
	}
	return release.MarshalCanonical(PublicEvidence{SchemaVersion: "lanpanel.qualification.public-evidence.v1", URL: "https://" + host + "/derp", Status: response.StatusCode, BodyDigest: release.DigestBytes([]byte(response.Header.Get("Upgrade"))), TLSVersion: connection.(*tls.Conn).ConnectionState().Version})
}

func probePublicWebSocket(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	} else {
		parsed.Scheme = "ws"
	}
	connection, response, err := websocket.Dial(ctx, parsed.String(), &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "complete") }()
	message := []byte("lanpanel-qualified-websocket")
	if err := connection.Write(ctx, websocket.MessageText, message); err != nil {
		return nil, err
	}
	kind, responseBytes, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageText || string(responseBytes) != string(message) {
		return nil, fmt.Errorf("public WebSocket echo differs: %w", err)
	}
	return release.MarshalCanonical(PublicEvidence{SchemaVersion: "lanpanel.qualification.public-evidence.v1", URL: parsed.String(), Status: http.StatusSwitchingProtocols, BodyDigest: release.DigestBytes(responseBytes), WebSocket: true})
}
