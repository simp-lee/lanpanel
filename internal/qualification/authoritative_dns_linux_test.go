//go:build linux

package qualification

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLookupAuthoritativeIPv4(t *testing.T) {
	for _, test := range []struct {
		name      string
		ipv4Count int
		ipv6      bool
		rcode     int
		wantError bool
	}{
		{name: "dual_stack_preserves_every_ipv4_endpoint", ipv4Count: 2, ipv6: true},
		{name: "maximum_ipv4_inventory", ipv4Count: 16, ipv6: true},
		{name: "ipv6_only_does_not_substitute_for_ipv4", ipv6: true, wantError: true},
		{name: "empty_inventory", wantError: true},
		{name: "unbounded_ipv4_inventory", ipv4Count: 17, wantError: true},
		{name: "resolution_failure", rcode: dns.RcodeServerFailure, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var want []netip.Addr
			for index := range test.ipv4Count {
				want = append(want, netip.AddrFrom4([4]byte{127, 0, 0, byte(index + 1)}))
			}
			resolver := qualificationDNSResolver(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
				response := new(dns.Msg)
				response.SetReply(request)
				response.RecursionAvailable = true
				response.Rcode = test.rcode
				question := request.Question[0]
				if response.Rcode == dns.RcodeSuccess {
					header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
					switch question.Qtype {
					case dns.TypeA:
						for _, address := range want {
							response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IP(address.AsSlice())})
						}
					case dns.TypeAAAA:
						if test.ipv6 {
							response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::53")})
						}
					}
				}
				if err := writer.WriteMsg(response); err != nil {
					t.Errorf("write DNS response: %v", err)
				}
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			got, err := lookupAuthoritativeIPv4(ctx, resolver, "ns.example.test.")
			if test.wantError {
				if err == nil || len(got) != 0 {
					t.Fatalf("lookup = %v, %v; want failure without endpoints", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			slices.SortFunc(got, func(a, b netip.Addr) int { return a.Compare(b) })
			if !slices.Equal(got, want) {
				t.Fatalf("IPv4 endpoints = %v, want every endpoint %v", got, want)
			}
		})
	}
}

func qualificationDNSResolver(t *testing.T, handler dns.Handler) *net.Resolver {
	t.Helper()
	connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	finished := make(chan error, 1)
	server := &dns.Server{PacketConn: connection, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { finished <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-finished:
		_ = connection.Close()
		t.Fatalf("start DNS fixture: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil {
			t.Errorf("stop DNS fixture: %v", err)
		}
		if err := <-finished; err != nil {
			t.Errorf("serve DNS fixture: %v", err)
		}
	})
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", connection.LocalAddr().String())
	}}
}
