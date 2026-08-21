package acme

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"time"
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

func rawDNSQuery(ctx context.Context, server, owner string, kind uint16) (DNSObservation, error) {
	name, err := dnsName(owner)
	if err != nil {
		return DNSObservation{}, err
	}
	id := uint16(rand.Uint32())
	query := make([]byte, 12, 12+len(name)+4)
	binary.BigEndian.PutUint16(query, id)
	binary.BigEndian.PutUint16(query[4:], 1)
	query = append(query, name...)
	query = append(query, byte(kind>>8), byte(kind), 0, 1)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return DNSObservation{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(connection.Close)
	deadline := time.Now().Add(5 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write(query); err != nil {
		return DNSObservation{}, err
	}
	buffer := make([]byte, 4096)
	n, err := connection.Read(buffer)
	if err != nil {
		return DNSObservation{}, err
	}
	message := buffer[:n]
	if len(message) < 12 || binary.BigEndian.Uint16(message) != id || message[2]&0x80 == 0 || message[2]&0x02 != 0 {
		return DNSObservation{}, fmt.Errorf("DNS response invalid or truncated")
	}
	result := DNSObservation{Server: server, Owner: owner, Authoritative: message[2]&0x04 != 0, RCode: message[3] & 0x0f}
	questions := int(binary.BigEndian.Uint16(message[4:]))
	answers := int(binary.BigEndian.Uint16(message[6:]))
	offset := 12
	for range questions {
		offset, err = skipDNSName(message, offset)
		if err != nil || offset+4 > len(message) {
			return DNSObservation{}, fmt.Errorf("DNS question invalid")
		}
		offset += 4
	}
	for range answers {
		offset, err = skipDNSName(message, offset)
		if err != nil || offset+10 > len(message) {
			return DNSObservation{}, fmt.Errorf("DNS answer invalid")
		}
		recordType := binary.BigEndian.Uint16(message[offset:])
		length := int(binary.BigEndian.Uint16(message[offset+8:]))
		offset += 10
		if offset+length > len(message) {
			return DNSObservation{}, fmt.Errorf("DNS answer truncated")
		}
		data := message[offset : offset+length]
		switch recordType {
		case 16:
			values, err := decodeTXT(data)
			if err != nil {
				return DNSObservation{}, err
			}
			result.TXT = append(result.TXT, values...)
		case 5:
			name, err := decodeDNSName(message, offset)
			if err != nil {
				return DNSObservation{}, err
			}
			result.CNAME = name
		case 39:
			name, err := decodeDNSName(message, offset)
			if err != nil {
				return DNSObservation{}, err
			}
			result.DNAME = name
		}
		offset += length
	}
	return result, nil
}

func dnsName(value string) ([]byte, error) {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	parts := strings.Split(value, ".")
	result := []byte{}
	for _, part := range parts {
		if part == "" || len(part) > 63 {
			return nil, fmt.Errorf("DNS name invalid")
		}
		result = append(result, byte(len(part)))
		result = append(result, part...)
	}
	return append(result, 0), nil
}

func skipDNSName(message []byte, offset int) (int, error) {
	for steps := 0; steps < 128; steps++ {
		if offset >= len(message) {
			return 0, fmt.Errorf("DNS name truncated")
		}
		length := int(message[offset])
		offset++
		if length&0xc0 == 0xc0 {
			if offset >= len(message) {
				return 0, fmt.Errorf("DNS pointer truncated")
			}
			return offset + 1, nil
		}
		if length == 0 {
			return offset, nil
		}
		if length > 63 || offset+length > len(message) {
			return 0, fmt.Errorf("DNS label invalid")
		}
		offset += length
	}
	return 0, fmt.Errorf("DNS name unbounded")
}

func decodeDNSName(message []byte, offset int) (string, error) {
	labels := []string{}
	visited := map[int]bool{}
	for steps := 0; steps < 128; steps++ {
		if offset >= len(message) || visited[offset] {
			return "", fmt.Errorf("DNS name invalid")
		}
		visited[offset] = true
		length := int(message[offset])
		offset++
		if length&0xc0 == 0xc0 {
			if offset >= len(message) {
				return "", fmt.Errorf("DNS pointer truncated")
			}
			offset = (length&0x3f)<<8 | int(message[offset])
			continue
		}
		if length == 0 {
			return strings.Join(labels, "."), nil
		}
		if length > 63 || offset+length > len(message) {
			return "", fmt.Errorf("DNS label invalid")
		}
		labels = append(labels, strings.ToLower(string(message[offset:offset+length])))
		offset += length
	}
	return "", fmt.Errorf("DNS name unbounded")
}

func decodeTXT(data []byte) ([]string, error) {
	result := []string{}
	for len(data) != 0 {
		length := int(data[0])
		data = data[1:]
		if length > len(data) {
			return nil, fmt.Errorf("DNS TXT invalid")
		}
		result = append(result, string(data[:length]))
		data = data[length:]
	}
	return result, nil
}

func digestValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
