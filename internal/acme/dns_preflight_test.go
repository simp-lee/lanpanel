package acme

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeDNS struct {
	observations map[string]DNSObservation
	failure      string
}

func (value fakeDNS) AuthoritativeServers(context.Context, string) ([]string, error) {
	return []string{"ns2.example.test", "ns1.example.test"}, nil
}

func (value fakeDNS) Observe(_ context.Context, server, owner string) (DNSObservation, error) {
	if value.failure == server {
		return DNSObservation{}, fmt.Errorf("failed")
	}
	result := value.observations[server]
	result.Server = server
	result.Owner = owner
	return result, nil
}

func TestDNSPreflightRequiresEveryAuthoritativeServerEmpty(t *testing.T) {
	observer := fakeDNS{observations: map[string]DNSObservation{"ns1.example.test": {Authoritative: true}, "ns2.example.test": {Authoritative: true}}}
	result, err := PreflightDNS01(context.Background(), observer, "example.test", []string{"_acme-challenge.app.example.test"})
	if err != nil || len(result.Servers) != 2 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	observer.observations["ns2.example.test"] = DNSObservation{Authoritative: true, TXT: []string{"foreign"}}
	if _, err := PreflightDNS01(context.Background(), observer, "example.test", []string{"_acme-challenge.app.example.test"}); err == nil {
		t.Fatal("preexisting TXT accepted")
	}
	observer.observations["ns2.example.test"] = DNSObservation{Authoritative: true, CNAME: "other.example.test"}
	if _, err := PreflightDNS01(context.Background(), observer, "example.test", []string{"_acme-challenge.app.example.test"}); err == nil {
		t.Fatal("delegation accepted")
	}
}

func TestDNSOwnerLockRejectsMismatchedDurableBinding(t *testing.T) {
	if _, err := AcquireOwnerLocks(context.Background(), t.TempDir(), DNSProviderCloudflare, "example.test", []string{"_acme-challenge.app.example.test"}, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("mismatched owner-lock binding accepted")
	}
}

func TestDNSPreflightRejectsInconsistentAuthority(t *testing.T) {
	observer := fakeDNS{observations: map[string]DNSObservation{"ns1.example.test": {Authoritative: true}, "ns2.example.test": {Authoritative: false}}}
	if _, err := PreflightDNS01(context.Background(), observer, "example.test", []string{"_acme-challenge.app.example.test"}); err == nil {
		t.Fatal("non-authoritative response accepted")
	}
}

func TestDNSPreflightFallsBackFromUDPTruncationToTCP(t *testing.T) {
	server := startTruncatedDNSServer(t, func(_ int, query *dns.Msg, connection net.Conn) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Authoritative = true
		writeTCPDNSResponse(connection, response)
	})
	observer := addressDNSObserver{address: server.address}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := PreflightDNS01(ctx, observer, "example.test", []string{"_acme-challenge.app.example.test"})
	if err != nil {
		t.Fatalf("preflight through TCP fallback: %v", err)
	}
	if len(result.Servers) != 1 || result.Servers[0] != "ns.local.test" {
		t.Fatalf("unexpected preflight result: %#v", result)
	}
	udpIDs, tcpIDs := server.queryIDs()
	if len(udpIDs) != 3 || len(tcpIDs) != 3 {
		t.Fatalf("query counts UDP=%v TCP=%v", udpIDs, tcpIDs)
	}
	for index := range udpIDs {
		if udpIDs[index] != tcpIDs[index] {
			t.Fatalf("query %d changed ID from UDP %d to TCP %d", index, udpIDs[index], tcpIDs[index])
		}
	}
}

func TestRawDNSQueryRejectsInvalidTCPFallback(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		handle  func(*dns.Msg, net.Conn)
	}{
		{name: "wrong-id", handle: func(query *dns.Msg, connection net.Conn) {
			response := authoritativeDNSReply(query)
			response.Id++
			writeTCPDNSResponse(connection, response)
		}},
		{name: "wrong-question", handle: func(query *dns.Msg, connection net.Conn) {
			response := authoritativeDNSReply(query)
			response.Question[0].Name = "other.example.test."
			writeTCPDNSResponse(connection, response)
		}},
		{name: "not-response", handle: func(query *dns.Msg, connection net.Conn) {
			response := authoritativeDNSReply(query)
			response.Response = false
			writeTCPDNSResponse(connection, response)
		}},
		{name: "not-authoritative", handle: func(query *dns.Msg, connection net.Conn) {
			response := authoritativeDNSReply(query)
			response.Authoritative = false
			writeTCPDNSResponse(connection, response)
		}},
		{name: "bad-rcode", handle: func(query *dns.Msg, connection net.Conn) {
			response := authoritativeDNSReply(query)
			response.Rcode = dns.RcodeRefused
			writeTCPDNSResponse(connection, response)
		}},
		{name: "oversized", handle: func(_ *dns.Msg, connection net.Conn) {
			var prefix [2]byte
			binary.BigEndian.PutUint16(prefix[:], maximumDNSMessageSize+1)
			_, _ = connection.Write(prefix[:])
		}},
		{name: "short-frame", handle: func(query *dns.Msg, connection net.Conn) {
			response, _ := authoritativeDNSReply(query).Pack()
			var prefix [2]byte
			binary.BigEndian.PutUint16(prefix[:], uint16(len(response)+8))
			_, _ = connection.Write(append(prefix[:], response...))
		}},
		{name: "trailing-wire", handle: func(query *dns.Msg, connection net.Conn) {
			response, _ := authoritativeDNSReply(query).Pack()
			writeTCPDNSWire(connection, append(response, 0))
		}},
		{name: "tc-again", handle: func(query *dns.Msg, connection net.Conn) {
			response := authoritativeDNSReply(query)
			response.Truncated = true
			writeTCPDNSResponse(connection, response)
		}},
		{name: "timeout", timeout: 100 * time.Millisecond, handle: func(_ *dns.Msg, connection net.Conn) {
			_, _ = io.Copy(io.Discard, connection)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := startTruncatedDNSServer(t, func(_ int, query *dns.Msg, connection net.Conn) { test.handle(query, connection) })
			timeout := test.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if _, err := rawDNSQueryAddress(ctx, "ns.local.test", server.address, "_acme-challenge.app.example.test", dns.TypeTXT); err == nil {
				t.Fatal("invalid TCP DNS response accepted")
			}
		})
	}
}

func TestRawDNSQueryPreservesRootAliasTarget(t *testing.T) {
	server := startTruncatedDNSServer(t, func(_ int, query *dns.Msg, connection net.Conn) {
		response := authoritativeDNSReply(query)
		response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "."}}
		writeTCPDNSResponse(connection, response)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation, err := rawDNSQueryAddress(ctx, "ns.local.test", server.address, "_acme-challenge.app.example.test", dns.TypeCNAME)
	if err != nil {
		t.Fatal(err)
	}
	if observation.CNAME != "." {
		t.Fatalf("root CNAME target treated as absent: %#v", observation)
	}
}

func TestRawDNSQueryRejectsUnexpectedUDPSource(t *testing.T) {
	primary, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = primary.Close() }()
	foreign, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maximumDNSMessageSize)
		n, source, readErr := primary.ReadFrom(buffer)
		if readErr != nil {
			return
		}
		query := new(dns.Msg)
		if query.Unpack(buffer[:n]) != nil {
			return
		}
		response := authoritativeDNSReply(query)
		wire, packErr := response.Pack()
		if packErr == nil {
			_, _ = foreign.WriteTo(wire, source)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := rawDNSQueryAddress(ctx, "ns.local.test", primary.LocalAddr().String(), "_acme-challenge.app.example.test", dns.TypeTXT); err == nil {
		t.Fatal("DNS response from unexpected UDP source accepted")
	}
	_ = primary.Close()
	<-done
}

type addressDNSObserver struct{ address string }

func (addressDNSObserver) AuthoritativeServers(context.Context, string) ([]string, error) {
	return []string{"ns.local.test"}, nil
}

func (observer addressDNSObserver) Observe(ctx context.Context, server, owner string) (DNSObservation, error) {
	var result DNSObservation
	for index, kind := range []uint16{dns.TypeTXT, dns.TypeCNAME, dns.TypeDNAME} {
		answer, err := rawDNSQueryAddress(ctx, server, observer.address, owner, kind)
		if err != nil {
			return DNSObservation{}, err
		}
		if index == 0 {
			result = answer
			continue
		}
		if answer.Authoritative != result.Authoritative || answer.RCode != result.RCode {
			return DNSObservation{}, fmt.Errorf("DNS response authority inconsistent")
		}
		result.CNAME += answer.CNAME
		result.DNAME += answer.DNAME
	}
	return result, nil
}

type truncatedDNSServer struct {
	address string
	udp     net.PacketConn
	tcp     net.Listener
	mu      sync.Mutex
	udpIDs  []uint16
	tcpIDs  []uint16
	wg      sync.WaitGroup
}

func startTruncatedDNSServer(t *testing.T, tcpHandler func(int, *dns.Msg, net.Conn)) *truncatedDNSServer {
	t.Helper()
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpListener, err := net.ListenPacket("udp4", tcpListener.Addr().String())
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	server := &truncatedDNSServer{address: tcpListener.Addr().String(), udp: udpListener, tcp: tcpListener}
	server.wg.Add(2)
	go func() {
		defer server.wg.Done()
		buffer := make([]byte, maximumDNSMessageSize+1)
		for {
			n, source, readErr := udpListener.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			query := new(dns.Msg)
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			server.mu.Lock()
			server.udpIDs = append(server.udpIDs, query.Id)
			server.mu.Unlock()
			response := authoritativeDNSReply(query)
			response.Truncated = true
			wire, packErr := response.Pack()
			if packErr == nil {
				_, _ = udpListener.WriteTo(wire, source)
			}
		}
	}()
	go func() {
		defer server.wg.Done()
		index := 0
		for {
			connection, acceptErr := tcpListener.Accept()
			if acceptErr != nil {
				return
			}
			server.wg.Add(1)
			go func(current int, connection net.Conn) {
				defer server.wg.Done()
				defer func() { _ = connection.Close() }()
				query, readErr := readTCPDNSQuery(connection)
				if readErr != nil {
					return
				}
				server.mu.Lock()
				server.tcpIDs = append(server.tcpIDs, query.Id)
				server.mu.Unlock()
				tcpHandler(current, query, connection)
			}(index, connection)
			index++
		}
	}()
	t.Cleanup(func() {
		_ = server.udp.Close()
		_ = server.tcp.Close()
		server.wg.Wait()
	})
	return server
}

func (server *truncatedDNSServer) queryIDs() ([]uint16, []uint16) {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]uint16(nil), server.udpIDs...), append([]uint16(nil), server.tcpIDs...)
}

func authoritativeDNSReply(query *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	return response
}

func readTCPDNSQuery(connection net.Conn) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length < 12 || length > maximumDNSMessageSize {
		return nil, fmt.Errorf("query size invalid")
	}
	wire := make([]byte, length)
	if _, err := io.ReadFull(connection, wire); err != nil {
		return nil, err
	}
	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil {
		return nil, err
	}
	return query, nil
}

func writeTCPDNSResponse(connection net.Conn, response *dns.Msg) {
	wire, err := response.Pack()
	if err != nil {
		return
	}
	writeTCPDNSWire(connection, wire)
}

func writeTCPDNSWire(connection net.Conn, wire []byte) {
	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed, uint16(len(wire)))
	copy(framed[2:], wire)
	_, _ = connection.Write(framed)
}
