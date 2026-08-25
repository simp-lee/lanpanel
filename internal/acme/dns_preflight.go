package acme

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSObservation struct {
	Server        string
	Owner         string
	TXT           []string
	CNAME         string
	DNAME         string
	Authoritative bool
	RCode         uint8
}
type DNSObserver interface {
	AuthoritativeServers(context.Context, string) ([]string, error)
	Observe(context.Context, string, string) (DNSObservation, error)
}
type DNSPreflight struct {
	Zone    string
	Owners  []string
	Servers []string
	Digest  string
}

func PreflightDNS01(ctx context.Context, observer DNSObserver, zone string, owners []string) (DNSPreflight, error) {
	if observer == nil || zone == "" || len(owners) == 0 {
		return DNSPreflight{}, fmt.Errorf("DNS-01 owner authority invalid")
	}
	owners = append([]string(nil), owners...)
	slices.Sort(owners)
	owners = slices.Compact(owners)
	for _, owner := range owners {
		if owner != zone && !strings.HasSuffix(owner, "."+zone) {
			return DNSPreflight{}, fmt.Errorf("DNS-01 owner outside authoritative zone")
		}
	}
	servers, err := observer.AuthoritativeServers(ctx, zone)
	if err != nil || len(servers) == 0 || len(servers) > 16 {
		return DNSPreflight{}, fmt.Errorf("authoritative DNS server inventory unavailable")
	}
	slices.Sort(servers)
	servers = slices.Compact(servers)
	for _, owner := range owners {
		var reference *DNSObservation
		for _, server := range servers {
			observation, err := observer.Observe(ctx, server, owner)
			if err != nil || observation.Server != server || observation.Owner != owner || !observation.Authoritative || observation.RCode != 0 && observation.RCode != 3 || len(observation.TXT) != 0 || observation.CNAME != "" || observation.DNAME != "" {
				return DNSPreflight{}, fmt.Errorf("DNS-01 owner is delegated, occupied, or inconsistent")
			}
			slices.Sort(observation.TXT)
			if reference != nil && (reference.RCode != observation.RCode || !slices.Equal(reference.TXT, observation.TXT)) {
				return DNSPreflight{}, fmt.Errorf("DNS-01 authoritative answers are inconsistent")
			}
			copy := observation
			reference = &copy
		}
	}
	identity := zone + "\x00" + strings.Join(owners, "\x00") + "\x00" + strings.Join(servers, "\x00")
	return DNSPreflight{Zone: zone, Owners: owners, Servers: servers, Digest: digestValue(identity)}, nil
}

func VerifyDNS01Cleanup(ctx context.Context, observer DNSObserver, preflight DNSPreflight) error {
	current, err := PreflightDNS01(ctx, observer, preflight.Zone, preflight.Owners)
	if err != nil {
		return err
	}
	if !slices.Equal(current.Servers, preflight.Servers) {
		return fmt.Errorf("authoritative DNS server inventory changed")
	}
	return nil
}

type NetDNSObserver struct{}

func (NetDNSObserver) AuthoritativeServers(ctx context.Context, zone string) ([]string, error) {
	records, err := net.DefaultResolver.LookupNS(ctx, zone)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, strings.TrimSuffix(strings.ToLower(record.Host), "."))
	}
	return result, nil
}

func (NetDNSObserver) Observe(ctx context.Context, server, owner string) (DNSObservation, error) {
	answers := []DNSObservation{}
	for _, kind := range []uint16{16, 5, 39} {
		answer, err := rawDNSQuery(ctx, server, owner, kind)
		if err != nil {
			return DNSObservation{}, err
		}
		answers = append(answers, answer)
	}
	result := answers[0]
	for _, answer := range answers[1:] {
		if answer.Authoritative != result.Authoritative || answer.RCode != result.RCode {
			return DNSObservation{}, fmt.Errorf("DNS response authority inconsistent")
		}
		result.CNAME += answer.CNAME
		result.DNAME += answer.DNAME
	}
	return result, nil
}

const (
	dnsQueryTimeout       = 5 * time.Second
	maximumDNSMessageSize = 4096
)

func rawDNSQuery(ctx context.Context, server, owner string, kind uint16) (DNSObservation, error) {
	return rawDNSQueryAddress(ctx, server, net.JoinHostPort(server, "53"), owner, kind)
}

func rawDNSQueryAddress(ctx context.Context, server, address, owner string, kind uint16) (DNSObservation, error) {
	if server == "" || address == "" || owner == "" {
		return DNSObservation{}, fmt.Errorf("DNS query authority invalid")
	}
	questionName := dns.Fqdn(strings.ToLower(strings.TrimSuffix(owner, ".")))
	if _, valid := dns.IsDomainName(questionName); !valid {
		return DNSObservation{}, fmt.Errorf("DNS name invalid")
	}
	query := new(dns.Msg)
	query.SetQuestion(questionName, kind)
	query.Id = dns.Id()
	query.RecursionDesired = false
	wireQuery, err := query.Pack()
	if err != nil {
		return DNSObservation{}, fmt.Errorf("pack DNS query: %w", err)
	}
	deadline := time.Now().Add(dnsQueryTimeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := ctx.Err(); err != nil {
		return DNSObservation{}, err
	}
	udpResponse, remoteAddress, err := exchangeDNSMessage(ctx, "udp", address, wireQuery, deadline)
	if err != nil {
		return DNSObservation{}, err
	}
	udpMessage, udpObservation, err := validateDNSResponse(udpResponse, query, server, owner)
	if err != nil {
		return DNSObservation{}, err
	}
	if !udpMessage.Truncated {
		return udpObservation, nil
	}
	tcpResponse, _, err := exchangeDNSMessage(ctx, "tcp", remoteAddress, wireQuery, deadline)
	if err != nil {
		return DNSObservation{}, err
	}
	tcpMessage, tcpObservation, err := validateDNSResponse(tcpResponse, query, server, owner)
	if err != nil {
		return DNSObservation{}, err
	}
	if tcpMessage.Truncated {
		return DNSObservation{}, fmt.Errorf("DNS TCP response truncated")
	}
	return tcpObservation, nil
}

func exchangeDNSMessage(ctx context.Context, network, address string, query []byte, deadline time.Time) ([]byte, string, error) {
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, "", err
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stopCancellation()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, "", err
	}
	if network == "tcp" {
		if len(query) > int(^uint16(0)) {
			return nil, "", fmt.Errorf("DNS query oversized")
		}
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		copy(framed[2:], query)
		if err := writeDNSMessage(connection, framed); err != nil {
			return nil, "", dnsContextError(ctx, err)
		}
		var prefix [2]byte
		if _, err := io.ReadFull(connection, prefix[:]); err != nil {
			return nil, "", dnsContextError(ctx, err)
		}
		length := int(binary.BigEndian.Uint16(prefix[:]))
		if length < 12 || length > maximumDNSMessageSize {
			return nil, "", fmt.Errorf("DNS TCP response size invalid")
		}
		response := make([]byte, length)
		if _, err := io.ReadFull(connection, response); err != nil {
			return nil, "", dnsContextError(ctx, err)
		}
		return response, connection.RemoteAddr().String(), nil
	}
	if err := writeDNSMessage(connection, query); err != nil {
		return nil, "", dnsContextError(ctx, err)
	}
	response := make([]byte, maximumDNSMessageSize+1)
	n, err := connection.Read(response)
	if err != nil {
		return nil, "", dnsContextError(ctx, err)
	}
	if n > maximumDNSMessageSize {
		return nil, "", fmt.Errorf("DNS UDP response size invalid")
	}
	return response[:n], connection.RemoteAddr().String(), nil
}

func writeDNSMessage(connection net.Conn, value []byte) error {
	for len(value) != 0 {
		n, err := connection.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}

func dnsContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func validateDNSResponse(value []byte, query *dns.Msg, server, owner string) (*dns.Msg, DNSObservation, error) {
	if len(value) < 12 || len(value) > maximumDNSMessageSize {
		return nil, DNSObservation{}, fmt.Errorf("DNS response size invalid")
	}
	if err := requireCompleteDNSWire(value); err != nil {
		return nil, DNSObservation{}, err
	}
	message := new(dns.Msg)
	if err := message.Unpack(value); err != nil {
		return nil, DNSObservation{}, fmt.Errorf("DNS response invalid: %w", err)
	}
	if message.Id != query.Id || !message.Response || message.Opcode != query.Opcode || len(query.Question) != 1 || len(message.Question) != 1 || !sameDNSQuestion(message.Question[0], query.Question[0]) {
		return nil, DNSObservation{}, fmt.Errorf("DNS response identity invalid")
	}
	if !message.Authoritative || message.Rcode != dns.RcodeSuccess && message.Rcode != dns.RcodeNameError {
		return nil, DNSObservation{}, fmt.Errorf("DNS response authority or rcode invalid")
	}
	result := DNSObservation{Server: server, Owner: owner, Authoritative: true, RCode: uint8(message.Rcode)}
	for _, answer := range message.Answer {
		if answer.Header().Class != dns.ClassINET {
			return nil, DNSObservation{}, fmt.Errorf("DNS answer class invalid")
		}
		switch record := answer.(type) {
		case *dns.TXT:
			result.TXT = append(result.TXT, record.Txt...)
		case *dns.CNAME:
			result.CNAME = dnsTarget(record.Target)
		case *dns.DNAME:
			result.DNAME = dnsTarget(record.Target)
		}
	}
	return message, result, nil
}

func requireCompleteDNSWire(value []byte) error {
	offset := 12
	questions := int(binary.BigEndian.Uint16(value[4:6]))
	for range questions {
		_, next, err := dns.UnpackDomainName(value, offset)
		if err != nil || next+4 > len(value) {
			return fmt.Errorf("DNS question wire invalid")
		}
		offset = next + 4
	}
	records := int(binary.BigEndian.Uint16(value[6:8])) + int(binary.BigEndian.Uint16(value[8:10])) + int(binary.BigEndian.Uint16(value[10:12]))
	for range records {
		_, next, err := dns.UnpackRR(value, offset)
		if err != nil || next <= offset {
			return fmt.Errorf("DNS record wire invalid")
		}
		offset = next
	}
	if offset != len(value) {
		return fmt.Errorf("DNS response contains trailing wire data")
	}
	return nil
}

func dnsTarget(value string) string {
	value = strings.ToLower(value)
	if value == "." {
		return value
	}
	return strings.TrimSuffix(value, ".")
}

func sameDNSQuestion(left, right dns.Question) bool {
	return strings.EqualFold(left.Name, right.Name) && left.Qtype == right.Qtype && left.Qclass == right.Qclass
}

func digestValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
