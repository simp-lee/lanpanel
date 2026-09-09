//go:build linux

package application

import (
	"context"
	"errors"
	"lanpanel/internal/closure"
	"lanpanel/internal/domain"
	"lanpanel/internal/nginx"
	"lanpanel/internal/operations"
	"lanpanel/internal/ownership"
	"lanpanel/internal/safety"
	"net"
	"syscall"
	"testing"
	"time"
)

type deleteRuntimeObserver func(context.Context) (closure.RuntimeSnapshot, error)

func (observe deleteRuntimeObserver) Observe(ctx context.Context) (closure.RuntimeSnapshot, error) {
	return observe(ctx)
}

func TestDeleteRequiresFreshIngressEvidence(t *testing.T) {
	resource := recoveryTailnetResource()
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{Kind: domain.PublicationTemporaryHTTP, SiteIdentity: recoveryDigest("site"), Listeners: []domain.BundleListenerIdentity{{Network: "tcp", Port: 18080}}}
	binding := operations.ResourceDeleteBinding{InstallationID: "ins_00000000000000000000000000000001", Resource: resource, Ownership: ownership.Record{ResourceID: resource.ID, Checksum: recoveryDigest("ownership")}}
	for _, scenario := range []string{"stopped", "serving_other_resource", "app_entry", "challenge_entry", "wrong_installation", "observation_error", "incomplete", "stale", "listener_remains", "dial_timeout", "dial_accepts"} {
		t.Run(scenario, func(t *testing.T) {
			manifest := nginx.Manifest{InstallationID: binding.InstallationID, GenerationID: "generation", DefaultCertFingerprint: recoveryDigest("default")}
			if scenario == "app_entry" {
				manifest.Entries = []nginx.Entry{{Kind: nginx.EntryApp, ResourceID: resource.ID}}
			}
			if scenario == "challenge_entry" {
				manifest.Entries = []nginx.Entry{{Kind: nginx.EntryChallenge, ResourceID: resource.ID}}
			}
			if scenario == "wrong_installation" {
				manifest.InstallationID = "foreign"
			}
			proof, err := verifyResourceDeleteIngress(context.Background(), binding, safety.State{}, manifest, func(inventory closure.Inventory) (closure.RuntimeObserver, func(context.Context, closure.Inventory) (string, error), error) {
				observe := deleteRuntimeObserver(func(context.Context) (closure.RuntimeSnapshot, error) {
					value := closure.RuntimeSnapshot{Complete: true, ObservedAt: time.Now().UTC(), Generation: manifest.GenerationID}
					if scenario == "observation_error" {
						return value, errors.New("unreadable proc")
					}
					if scenario == "incomplete" {
						value.Complete = false
					}
					if scenario == "stale" {
						value.ObservedAt = value.ObservedAt.Add(-time.Minute)
					}
					if scenario == "listener_remains" || scenario == "serving_other_resource" {
						value.Master = &closure.ProcessIdentity{PID: 1}
						value.Workers = []closure.ProcessIdentity{{PID: 2}}
						value.Listeners = []closure.ListenerIdentity{{Protocol: "tcp", Address: "0.0.0.0", Port: 80}, {Protocol: "tcp", Address: "0.0.0.0", Port: 443}, {Protocol: "tcp", Address: "::", Port: 80}, {Protocol: "tcp", Address: "::", Port: 443}}
						if scenario == "listener_remains" {
							value.Listeners = append(value.Listeners, closure.ListenerIdentity{Protocol: "tcp", Address: "0.0.0.0", Port: 18080})
						}
					}
					return value, nil
				})
				probe := closure.NegativeProbe{TLSAddress: "127.0.0.1:443", DefaultCertFingerprint: manifest.DefaultCertFingerprint, AuditPath: "/unused", Dialer: func(_ context.Context, network, address string) (net.Conn, error) {
					if network != "tcp4" || address != "127.0.0.1:18080" {
						t.Fatalf("wrong closure target: %s %s", network, address)
					}
					if scenario == "dial_timeout" {
						return nil, context.DeadlineExceeded
					}
					if scenario == "dial_accepts" {
						client, server := net.Pipe()
						_ = server.Close()
						return client, nil
					}
					return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: syscall.ECONNREFUSED}
				}}
				return observe, probe.Run, nil
			})
			wantSuccess := scenario == "stopped" || scenario == "serving_other_resource"
			if (err == nil) != wantSuccess || wantSuccess && proof == "" {
				t.Fatalf("proof=%s err=%v", proof, err)
			}
		})
	}
}

func TestRunningDomainDeletionRequiresRejectionProof(t *testing.T) {
	resource := recoveryTailnetResource()
	resource.PublicationRecord.LastAppliedBundle = &domain.PublicationBundle{Kind: domain.PublicationDomainHTTPS, SiteIdentity: recoveryDigest("site"), DomainHTTPS: &domain.DomainHTTPSBundleIdentity{ExactDomains: []string{"app.example.test"}}}
	binding := operations.ResourceDeleteBinding{InstallationID: "ins_00000000000000000000000000000001", Resource: resource, Ownership: ownership.Record{ResourceID: resource.ID, Checksum: recoveryDigest("ownership")}}
	manifest := nginx.Manifest{InstallationID: binding.InstallationID, GenerationID: "generation"}
	for _, reject := range []bool{false, true} {
		calls := 0
		_, err := verifyResourceDeleteIngress(context.Background(), binding, safety.State{}, manifest, func(inventory closure.Inventory) (closure.RuntimeObserver, func(context.Context, closure.Inventory) (string, error), error) {
			observe := deleteRuntimeObserver(func(context.Context) (closure.RuntimeSnapshot, error) {
				return closure.RuntimeSnapshot{Complete: true, ObservedAt: time.Now().UTC(), Generation: manifest.GenerationID, Master: &closure.ProcessIdentity{PID: 1}, Workers: []closure.ProcessIdentity{{PID: 2}}, Listeners: []closure.ListenerIdentity{{Protocol: "tcp", Address: "0.0.0.0", Port: 80}, {Protocol: "tcp", Address: "0.0.0.0", Port: 443}, {Protocol: "tcp", Address: "::", Port: 80}, {Protocol: "tcp", Address: "::", Port: 443}}}, nil
			})
			return observe, func(_ context.Context, inventory closure.Inventory) (string, error) {
				calls++
				found := false
				for _, value := range inventory.Identities {
					found = found || value.Kind == closure.IdentityDomain && value.Value == "app.example.test"
				}
				if !found {
					t.Fatal("dropped prior domain before rejection probe")
				}
				if reject {
					return "", errors.New("rejection audit lacks correlation")
				}
				return recoveryDigest("fresh-negative-probe"), nil
			}, nil
		})
		if calls != 1 || (err != nil) != reject {
			t.Fatalf("probe calls=%d err=%v", calls, err)
		}
	}
}
