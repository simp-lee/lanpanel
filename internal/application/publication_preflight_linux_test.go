//go:build linux

package application

import (
	"context"
	"errors"
	"lanpanel/internal/closure"
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/domain"
	"lanpanel/internal/ownership"
	managedprocess "lanpanel/internal/process"
	"lanpanel/internal/target"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPublicationProbeBindsOnlyConfirmedProcessRuntimeViolations(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", ManagedProcess: &domain.ManagedProcess{Applied: &domain.ProcessBundle{PolicyDigest: deployTestDigest("policy"), Cgroup: "/expected", RelayRequired: true}}}
	ordinary := context.DeadlineExceeded
	if got := bindProcessRuntimeViolation(resource, ordinary); got != ordinary || IsProcessRuntimeViolation(got) {
		t.Fatalf("ordinary observation error became a contraction trigger: %v", got)
	}
	confirmed := managedprocess.NewRuntimeViolation(managedprocess.RuntimeViolationExtraListener, context.Canceled)
	bound := bindProcessRuntimeViolation(resource, confirmed)
	if !IsProcessRuntimeViolation(bound) {
		t.Fatalf("confirmed extra listener did not carry process contraction authority: %v", bound)
	}
	var violation *processRuntimeViolation
	if !errors.As(bound, &violation) || violation.ResourceID != resource.ID || violation.PolicyDigest != resource.ManagedProcess.Applied.PolicyDigest || violation.Cgroup != resource.ManagedProcess.Applied.Cgroup || !violation.RelayRequired || violation.Kind != managedprocess.RuntimeViolationExtraListener {
		t.Fatalf("process contraction authority is incomplete: %#v", violation)
	}
}

func TestTemporaryPreflightUsesOnlyExactOwnedNginxRuntimeListener(t *testing.T) {
	const (
		resourceID = "res_00000000000000000000000000000001"
		port       = uint16(18080)
	)
	record := &ownership.Record{
		ResourceID: resourceID,
		State:      ownership.Owned,
		Listeners: []ownership.OwnedListener{{
			Protocol:       "tcp",
			Address:        "0.0.0.0",
			Port:           port,
			IdentityDigest: ownership.ListenerIdentity(resourceID, "tcp", "0.0.0.0", port),
		}},
	}
	if !ownsTemporaryListener(record, resourceID, port) {
		t.Fatal("exact same-resource ownership was not recognized")
	}
	other := *record
	other.ResourceID = "res_00000000000000000000000000000002"
	if ownsTemporaryListener(&other, resourceID, port) {
		t.Fatal("another resource's listener was treated as owned")
	}

	master := closure.ProcessIdentity{PID: 10}
	runtime := closure.RuntimeSnapshot{
		ObservedAt: time.Now().UTC(),
		Master:     &master,
		Workers:    []closure.ProcessIdentity{{PID: 11, ParentPID: master.PID}},
		Listeners:  []closure.ListenerIdentity{{Protocol: "tcp", Address: "0.0.0.0", Port: port, Inode: 91}},
		Complete:   true,
		Generation: "generation-one",
	}
	authority, err := temporaryListenerAuthorityFromRuntime(runtime, port)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Protocol != "tcp" || authority.Address != "0.0.0.0" || authority.Port != port || authority.SocketInode != 91 {
		t.Fatalf("wrong temporary listener authority: %#v", authority)
	}

	for name, mutate := range map[string]func(*closure.RuntimeSnapshot){
		"loopback address": func(value *closure.RuntimeSnapshot) { value.Listeners[0].Address = "127.0.0.1" },
		"different port":   func(value *closure.RuntimeSnapshot) { value.Listeners[0].Port++ },
		"missing inode":    func(value *closure.RuntimeSnapshot) { value.Listeners[0].Inode = 0 },
		"no worker":        func(value *closure.RuntimeSnapshot) { value.Workers = nil },
		"no generation":    func(value *closure.RuntimeSnapshot) { value.Generation = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := runtime
			candidate.Listeners = append([]closure.ListenerIdentity(nil), runtime.Listeners...)
			candidate.Workers = append([]closure.ProcessIdentity(nil), runtime.Workers...)
			mutate(&candidate)
			if _, err := temporaryListenerAuthorityFromRuntime(candidate, port); err == nil {
				t.Fatal("non-exact or unverified listener became owned authority")
			}
		})
	}
}

func TestTailnetEndpointIdentityIsStableAcrossFreshVerification(t *testing.T) {
	observedAt := time.Unix(1700000000, 0).UTC()
	observation := managedconnector.Observation{
		ClientVersion: "1.80.3",
		ControlURL:    "https://control.example.test",
		ObservedAt:    observedAt,
		ValidUntil:    observedAt.Add(managedconnector.EvidenceTTL),
	}
	source := netip.MustParseAddr("100.64.0.1")
	peer := netip.MustParseAddr("100.64.0.2")
	identity := tailnetEndpointIdentity(observation, source, peer, 8080)

	refreshed := observation
	refreshed.ObservedAt = observedAt.Add(30 * time.Second)
	refreshed.ValidUntil = refreshed.ObservedAt.Add(managedconnector.EvidenceTTL)
	if got := tailnetEndpointIdentity(refreshed, source, peer, 8080); got != identity {
		t.Fatalf("fresh verification lifetime changed endpoint identity: got %q want %q", got, identity)
	}

	changedConnector := observation
	changedConnector.ControlURL = "https://other-control.example.test"
	for name, got := range map[string]string{
		"connector": tailnetEndpointIdentity(changedConnector, source, peer, 8080),
		"source":    tailnetEndpointIdentity(observation, netip.MustParseAddr("100.64.0.3"), peer, 8080),
		"peer":      tailnetEndpointIdentity(observation, source, netip.MustParseAddr("100.64.0.4"), 8080),
		"port":      tailnetEndpointIdentity(observation, source, peer, 8081),
	} {
		if got == identity {
			t.Fatalf("changed %s retained endpoint identity", name)
		}
	}
}

func TestManagedProcessEndpointIdentityIsAcceptedByReadiness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/protected-ready" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	address := strings.TrimPrefix(server.URL, "http://")
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := deployTestDigest("managed-policy")
	runtimeDigest := deployTestDigest("managed-runtime")
	endpointIdentity := managedProcessEndpointIdentity(policyDigest, runtimeDigest)
	transport, err := target.NewTCPTransport(host, uint16(port), endpointIdentity)
	if err != nil {
		t.Fatal(err)
	}
	configuredTarget := domain.AppTarget{
		Kind:                domain.AppTargetLocalHTTP,
		ReadinessPath:       "/protected-ready",
		AllowedHTTPStatuses: []uint16{http.StatusNoContent},
		LocalHTTP: &domain.LocalHTTPTarget{
			EndpointKind: domain.LocalEndpointTCPSocketActivation,
			TCPAddress:   host,
			TCPPort:      uint16(port),
		},
	}
	evidence, err := target.Probe(context.Background(), target.ProbeRequest{
		ResourceID:       "res_00000000000000000000000000000001",
		ConfigDigest:     deployTestDigest("config"),
		EndpointIdentity: endpointIdentity,
		Target:           configuredTarget,
		AccessMode:       domain.AppAccessPublic,
		Host:             "protected.lanpanel.invalid",
	}, transport)
	if err != nil {
		t.Fatalf("canonical managed-process authority rejected: %v", err)
	}
	if evidence.EndpointIdentity != endpointIdentity {
		t.Fatalf("protected readiness endpoint was not verified: %#v", evidence)
	}
	if endpointIdentity == managedProcessEndpointIdentity(deployTestDigest("changed-policy"), runtimeDigest) || endpointIdentity == managedProcessEndpointIdentity(policyDigest, deployTestDigest("changed-runtime")) {
		t.Fatal("managed-process endpoint identity did not bind both authorities")
	}
}
