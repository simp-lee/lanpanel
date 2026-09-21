// Package target implements the shared exact-target HTTP and WebSocket readiness state machine.
package target

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ConnectTimeout = 2 * time.Second
	ReadTimeout    = 3 * time.Second
	TotalTimeout   = 5 * time.Second
	MaximumBody    = 4096
)

type Transport interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Identity() string
}

type Evidence struct {
	ResourceID        string
	ConfigDigest      string
	EndpointIdentity  string
	TransportIdentity string
	HTTPStatus        int
	WebSocketStatus   int
	ObservedAt        time.Time
	Digest            string
}

type ProbeRequest struct {
	ResourceID, ConfigDigest, EndpointIdentity string
	Target                                     domain.AppTarget
	AccessMode                                 domain.AppAccessMode
	ApplicationManagedWebSocketProof           *ControlledWebSocketProof
	Host                                       string
	Now                                        func() time.Time
}
type ControlledWebSocketProof struct {
	ResourceID, ConfigDigest, EndpointIdentity string
	AuthenticatedStatus                        int
	Digest                                     string
}

func (proof *ControlledWebSocketProof) valid(request ProbeRequest) bool {
	return proof != nil && proof.ResourceID == request.ResourceID && proof.ConfigDigest == request.ConfigDigest && proof.EndpointIdentity == request.EndpointIdentity && proof.AuthenticatedStatus == http.StatusSwitchingProtocols && validDigest(proof.Digest)
}

func Probe(ctx context.Context, request ProbeRequest, transport Transport) (Evidence, error) {
	if transport == nil || request.ResourceID == "" || !validDigest(request.ConfigDigest) || !validDigest(request.EndpointIdentity) || transport.Identity() == "" {
		return Evidence{}, fmt.Errorf("target readiness authority is incomplete")
	}
	if request.Target.Kind != domain.AppTargetLocalHTTP && request.Target.Kind != domain.AppTargetTailnetHTTP || request.Target.Kind == domain.AppTargetLocalHTTP && request.Target.LocalHTTP == nil || request.Target.Kind == domain.AppTargetTailnetHTTP && request.Target.TailnetHTTP == nil {
		return Evidence{}, fmt.Errorf("target readiness kind is unsupported")
	}
	if expected := targetTransportIdentity(request.Target); expected == "" || transport.Identity() != request.EndpointIdentity+"/"+expected {
		return Evidence{}, fmt.Errorf("target readiness transport does not match configured endpoint")
	}
	now := time.Now().UTC()
	if request.Now != nil {
		now = request.Now().UTC()
	}
	if now.IsZero() {
		return Evidence{}, fmt.Errorf("target readiness observation time is invalid")
	}
	evidence := Evidence{ResourceID: request.ResourceID, ConfigDigest: request.ConfigDigest, EndpointIdentity: request.EndpointIdentity, TransportIdentity: transport.Identity(), ObservedAt: now}
	probeCtx, cancel := context.WithTimeout(ctx, TotalTimeout)
	defer cancel()
	var err error
	evidence.HTTPStatus, err = probeHTTP(probeCtx, request, transport)
	if err != nil {
		return withEvidenceDigest(evidence), err
	}
	if request.Target.WebSocket.Enabled {
		evidence.WebSocketStatus, err = probeWebSocket(probeCtx, request, transport)
		if err != nil {
			return withEvidenceDigest(evidence), err
		}
	}
	return withEvidenceDigest(evidence), nil
}

func withEvidenceDigest(evidence Evidence) Evidence {
	identity := strings.Join([]string{evidence.ResourceID, evidence.ConfigDigest, evidence.EndpointIdentity, evidence.TransportIdentity, fmt.Sprint(evidence.HTTPStatus), fmt.Sprint(evidence.WebSocketStatus)}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	evidence.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return evidence
}

func probeHTTP(ctx context.Context, request ProbeRequest, transport Transport) (int, error) {
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: transport.DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: ReadTimeout}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	urlValue := &url.URL{Scheme: "http", Host: request.Host, Path: request.Target.ReadinessPath}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, urlValue.String(), nil)
	if err != nil {
		return 0, err
	}
	httpRequest.Host = request.Host
	httpRequest.Header.Set("Connection", "close")
	response, err := client.Do(httpRequest)
	if err != nil {
		return 0, err
	}
	defer func(ignore func() error) { _ = ignore() }(response.Body.Close)
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaximumBody))
	if !allowedHTTPStatus(response.StatusCode, request.Target.AllowedHTTPStatuses) {
		return response.StatusCode, fmt.Errorf("target HTTP readiness returned disallowed status %d", response.StatusCode)
	}
	return response.StatusCode, nil
}

func probeWebSocket(ctx context.Context, request ProbeRequest, transport Transport) (int, error) {
	connection, err := transport.DialContext(ctx, "tcp", request.Host)
	if err != nil {
		return 0, err
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	deadline := time.Now().Add(ReadTimeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return 0, err
	}
	rawKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
		return 0, err
	}
	key := base64.StdEncoding.EncodeToString(rawKey)
	clear(rawKey)
	requestText := "GET " + request.Target.WebSocket.Path + " HTTP/1.1\r\nHost: " + request.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n"
	if _, err := io.WriteString(connection, requestText); err != nil {
		return 0, err
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(connection, 16<<10)), &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, err
	}
	defer func(ignore func() error) { _ = ignore() }(response.Body.Close)
	if response.StatusCode == http.StatusSwitchingProtocols {
		if !headerToken(response.Header.Values("Connection"), "upgrade") || !headerToken(response.Header.Values("Upgrade"), "websocket") || response.Header.Get("Sec-WebSocket-Accept") != websocketAccept(key) {
			return response.StatusCode, fmt.Errorf("target WebSocket upgrade identity is invalid")
		}
		return response.StatusCode, nil
	}
	if request.AccessMode == domain.AppAccessApplicationManaged && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
		if request.ApplicationManagedWebSocketProof != nil && !request.ApplicationManagedWebSocketProof.valid(request) {
			return response.StatusCode, fmt.Errorf("application-managed WebSocket proof changed")
		}
		return response.StatusCode, nil
	}
	return response.StatusCode, fmt.Errorf("target WebSocket readiness returned disallowed status %d", response.StatusCode)
}

func allowedHTTPStatus(status int, configured []uint16) bool {
	for _, allowed := range configured {
		if status == int(allowed) {
			return true
		}
	}
	return false
}

func websocketAccept(key string) string {
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func headerToken(values []string, token string) bool {
	found := false
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				found = true
			}
		}
	}
	return found
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func targetTransportIdentity(target domain.AppTarget) string {
	if target.Kind == domain.AppTargetTailnetHTTP && target.TailnetHTTP != nil {
		address, addressErr := netip.ParseAddr(target.TailnetHTTP.IP)
		source, sourceErr := netip.ParseAddr(target.TailnetHTTP.SourceIP)
		if addressErr != nil || sourceErr != nil {
			return ""
		}
		return "tailnet/" + source.String() + "/" + net.JoinHostPort(address.String(), fmt.Sprint(target.TailnetHTTP.Port))
	}
	local := target.LocalHTTP
	if local == nil {
		return ""
	}
	switch local.EndpointKind {
	case domain.LocalEndpointUnixSocketActivation, domain.LocalEndpointRelayUnix:
		return "unix"
	case domain.LocalEndpointTCPSocketActivation:
		return "tcp/" + net.JoinHostPort(local.TCPAddress, fmt.Sprint(local.TCPPort))
	default:
		return ""
	}
}

// TCPTransport is allowed only for an exact loopback socket-activation target.
type TCPTransport struct {
	Address  string
	identity string
}

func NewTCPTransport(address string, port uint16, identity string) (TCPTransport, error) {
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.IsLoopback() || parsed.IsUnspecified() || port == 0 || identity == "" {
		return TCPTransport{}, fmt.Errorf("TCP readiness endpoint is not exact loopback authority")
	}
	authority := net.JoinHostPort(address, fmt.Sprint(port))
	return TCPTransport{Address: authority, identity: identity + "/tcp/" + authority}, nil
}

func (transport TCPTransport) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: ConnectTimeout}).DialContext(ctx, "tcp", transport.Address)
}
func (transport TCPTransport) Identity() string { return transport.identity }

type TailnetTransport struct {
	Address  string
	SourceIP string
	identity string
}

func NewTailnetTransport(address, sourceIP string, port uint16, identity string) (TailnetTransport, error) {
	parsed, err := netip.ParseAddr(address)
	source, sourceErr := netip.ParseAddr(sourceIP)
	if err != nil || sourceErr != nil || parsed.IsLoopback() || parsed.IsUnspecified() || !parsed.IsGlobalUnicast() || !source.IsGlobalUnicast() || source.IsLoopback() || source.BitLen() != parsed.BitLen() || port == 0 || identity == "" {
		return TailnetTransport{}, fmt.Errorf("tailnet readiness endpoint authority invalid")
	}
	authority := net.JoinHostPort(parsed.String(), fmt.Sprint(port))
	return TailnetTransport{Address: authority, SourceIP: source.String(), identity: identity + "/tailnet/" + source.String() + "/" + authority}, nil
}

func (transport TailnetTransport) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: ConnectTimeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(transport.SourceIP)}, Control: func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "tailscale0")
		}); err != nil {
			return err
		}
		return controlErr
	}}
	return dialer.DialContext(ctx, "tcp", transport.Address)
}
func (transport TailnetTransport) Identity() string { return transport.identity }
