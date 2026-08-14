package acme

import (
	"context"
	"fmt"
	"strings"
	"testing"
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
