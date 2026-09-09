//go:build linux

package qualification

import (
	"lanpanel/internal/domain"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/resource"
	"net/netip"
	"testing"
	"time"
)

func TestCreatedHeadscaleEntitiesMustAppearByExactIDAndUserBinding(t *testing.T) {
	user := managedheadscale.User{ID: 41, Name: "qualification"}
	key := managedheadscale.PreauthKey{ID: 73, UserID: user.ID}
	if err := confirmCreatedHeadscaleEntities([]managedheadscale.User{{ID: user.ID, Name: user.Name}}, []managedheadscale.PreauthKey{{ID: key.ID, UserID: user.ID}}, user, key); err != nil {
		t.Fatal(err)
	}
	if err := confirmCreatedHeadscaleEntities([]managedheadscale.User{{ID: user.ID + 1, Name: user.Name}}, []managedheadscale.PreauthKey{{ID: key.ID, UserID: user.ID}}, user, key); err == nil {
		t.Fatal("user list success was accepted without the created user ID")
	}
	if err := confirmCreatedHeadscaleEntities([]managedheadscale.User{{ID: user.ID, Name: user.Name}}, []managedheadscale.PreauthKey{{ID: key.ID, UserID: user.ID + 1}}, user, key); err == nil {
		t.Fatal("preauth key list accepted a different user binding")
	}
}

func TestSelectConnectorDeviceIgnoresOrderAndRequiresUniqueNewUserIPMatch(t *testing.T) {
	locals := []netip.Addr{netip.MustParseAddr("100.64.0.10"), netip.MustParseAddr("fd7a:115c:a1e0::10")}
	before := []managedheadscale.Device{{ID: 10, UserID: 9, Name: "existing", IPAddresses: []string{"100.64.0.1"}}}
	selected := managedheadscale.Device{ID: 21, UserID: 41, Name: "connector", IPAddresses: []string{locals[1].String(), locals[0].String()}}
	after := []managedheadscale.Device{
		selected,
		{ID: 10, UserID: 9, Name: "existing", IPAddresses: []string{"100.64.0.1"}},
		{ID: 99, UserID: 9, Name: "unrelated-new", IPAddresses: []string{"100.64.0.99"}},
	}
	device, err := selectConnectorDevice(before, after, 41, locals)
	if err != nil || device.ID != selected.ID {
		t.Fatalf("device order affected exact connector selection: device=%+v err=%v", device, err)
	}
	if err := requireExactDeviceInventoryDelta(before, after, selected.ID); err == nil {
		t.Fatal("connector inventory accepted an unrelated additional device")
	}
	if err := requireExactDeviceInventoryDelta(before, []managedheadscale.Device{selected, before[0]}, selected.ID); err != nil {
		t.Fatalf("one exact connector device delta was rejected: %v", err)
	}

	after = append(after, managedheadscale.Device{ID: 22, UserID: 41, Name: "duplicate-match", IPAddresses: []string{locals[0].String(), locals[1].String()}})
	if _, err := selectConnectorDevice(before, after, 41, locals); err == nil {
		t.Fatal("multiple new devices matching the connector were accepted")
	}
	if _, err := selectConnectorDevice(before, []managedheadscale.Device{{ID: 21, UserID: 42, Name: "wrong-user", IPAddresses: []string{locals[0].String(), locals[1].String()}}}, 41, locals); err == nil {
		t.Fatal("connector device with a different user was accepted")
	}
}

func TestConnectorPriorRequiresFreshlyActivePreauthKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	executor := &LiveExecutor{state: liveState{HeadscaleUserID: "41", PreauthKeyID: "73"}}
	users := []managedheadscale.User{{ID: 41, Name: "qualification"}}
	key := managedheadscale.PreauthKey{ID: 73, UserID: 41, CreatedAt: now.Add(-2 * time.Hour), Expiration: now.Add(-time.Hour)}
	if _, _, err := executor.requireExactHeadscaleResults(users, []managedheadscale.PreauthKey{key}, true, now); err == nil {
		t.Fatal("expired preauth key was reported active")
	}
	key.Expiration = now.Add(time.Hour)
	if _, _, err := executor.requireExactHeadscaleResults(users, []managedheadscale.PreauthKey{key}, true, now); err != nil {
		t.Fatalf("fresh active preauth key was rejected: %v", err)
	}
}

func TestPendingResourceRecoveryRequiresExactRequestedSpecification(t *testing.T) {
	spec := resource.LocalSpec{TargetKind: domain.AppTargetLocalHTTP, Name: "qualification-local", EndpointKind: domain.LocalEndpointUnixSocketActivation, ReadinessPath: "/ready", WebSocket: domain.WebSocketReadiness{Enabled: true, Path: "/ws"}, AllowedHTTPStatuses: []uint16{204}, Service: domain.ManagedService{Executable: "/usr/lib/lanpanel/lanpanel", Arguments: []string{"qualification-fixture"}, WorkingDirectory: "/usr/lib/lanpanel", WritePaths: []string{}}, Publication: domain.AppPublication{Kind: domain.PublicationDomainHTTPS}, CredentialIDs: []string{}}
	specDigest, err := resourceSpecDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	candidate := domain.AppResource{ID: "res_new", Name: spec.Name, Target: domain.AppTarget{Kind: spec.TargetKind, ReadinessPath: spec.ReadinessPath, AllowedHTTPStatuses: spec.AllowedHTTPStatuses, WebSocket: spec.WebSocket, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: spec.EndpointKind}}, Publication: spec.Publication, ManagedProcess: &domain.ManagedProcess{Service: spec.Service}}
	id, found, err := resourceCandidate(domain.Installation{Resources: []domain.AppResource{candidate}}, &resourceCreateIntent{Slot: "local", Name: spec.Name, TargetKind: string(spec.TargetKind), SpecDigest: specDigest})
	if err != nil || !found || id != candidate.ID {
		t.Fatalf("exact resource specification was not recovered: id=%q found=%t err=%v", id, found, err)
	}
	candidate.Publication.Kind = domain.PublicationTemporaryHTTP
	if _, found, err := resourceCandidate(domain.Installation{Resources: []domain.AppResource{candidate}}, &resourceCreateIntent{Slot: "local", Name: spec.Name, TargetKind: string(spec.TargetKind), SpecDigest: specDigest}); err != nil || found {
		t.Fatalf("resource with a different publication specification was accepted: found=%t err=%v", found, err)
	}
}

func TestPendingRegistrationRecoveryUsesExactPriorInventoryDelta(t *testing.T) {
	installation := domain.Installation{Credentials: []domain.Credential{{ID: "cred_prior", Kind: "managed_basic", OwnerResourceID: "res_one", Username: "ga-user"}, {ID: "cred_new", Kind: "managed_basic", OwnerResourceID: "res_one", Username: "ga-user"}}, StaticRoots: []domain.StaticContentRoot{{ID: "static_new", OwnerResourceID: "res_one", Path: "/srv/static"}}}
	id, found, err := registrationCandidate(installation, &registrationIntent{Kind: "managed_basic", ResourceID: "res_one", Selector: "ga-user", PriorIDs: []string{"cred_prior"}})
	if err != nil || !found || id != "cred_new" {
		t.Fatalf("managed Basic delta was not recovered exactly: id=%q found=%t err=%v", id, found, err)
	}
	id, found, err = registrationCandidate(installation, &registrationIntent{Kind: "static_root", ResourceID: "res_one", Selector: "/srv/static", PriorIDs: []string{}})
	if err != nil || !found || id != "static_new" {
		t.Fatalf("static root delta was not recovered exactly: id=%q found=%t err=%v", id, found, err)
	}
	installation.Credentials = append(installation.Credentials, domain.Credential{ID: "cred_ambiguous", Kind: "managed_basic", OwnerResourceID: "res_one", Username: "ga-user"})
	if _, _, err := registrationCandidate(installation, &registrationIntent{Kind: "managed_basic", ResourceID: "res_one", Selector: "ga-user", PriorIDs: []string{"cred_prior"}}); err == nil {
		t.Fatal("ambiguous new Managed Basic identities were accepted")
	}
}

func TestPendingHeadscaleRecoveryRequiresUniqueNewExactEntity(t *testing.T) {
	userID, found, err := headscaleUserCandidate([]managedheadscale.User{{ID: 10, Name: "existing"}, {ID: 41, Name: "qualification"}}, &headscaleUserCreateIntent{Name: "qualification", PriorIDs: []uint64{10}})
	if err != nil || !found || userID != 41 {
		t.Fatalf("Headscale user delta was not recovered exactly: id=%d found=%t err=%v", userID, found, err)
	}
	if _, _, err := headscaleUserCandidate([]managedheadscale.User{{ID: 41, Name: "qualification"}}, &headscaleUserCreateIntent{Name: "qualification", PriorIDs: []uint64{10}}); err == nil {
		t.Fatal("missing prior Headscale user identity was accepted")
	}
	createdAt := time.Now().UTC()
	keyID, found, err := preauthKeyCandidate([]managedheadscale.PreauthKey{{ID: 11, UserID: 41}, {ID: 73, UserID: 41, CreatedAt: createdAt, Expiration: createdAt.Add(time.Hour)}}, &preauthKeyCreateIntent{UserID: 41, ExpirationSeconds: 3600, CreatedAt: createdAt, Deadline: createdAt.Add(10 * time.Minute), PriorIDs: []uint64{11}})
	if err != nil || !found || keyID != 73 {
		t.Fatalf("preauth key delta was not recovered exactly: id=%d found=%t err=%v", keyID, found, err)
	}
	future := createdAt.Add(11 * time.Minute)
	if _, found, err := preauthKeyCandidate([]managedheadscale.PreauthKey{{ID: 11, UserID: 41}, {ID: 75, UserID: 41, CreatedAt: future, Expiration: future.Add(time.Hour)}}, &preauthKeyCreateIntent{UserID: 41, ExpirationSeconds: 3600, CreatedAt: createdAt, Deadline: createdAt.Add(10 * time.Minute), PriorIDs: []uint64{11}}); err != nil || found {
		t.Fatalf("future unrelated preauth key was accepted: found=%t err=%v", found, err)
	}
	if _, _, err := preauthKeyCandidate([]managedheadscale.PreauthKey{{ID: 73, UserID: 41, CreatedAt: createdAt, Expiration: createdAt.Add(time.Hour)}, {ID: 74, UserID: 41, CreatedAt: createdAt, Expiration: createdAt.Add(time.Hour)}}, &preauthKeyCreateIntent{UserID: 41, ExpirationSeconds: 3600, CreatedAt: createdAt, Deadline: createdAt.Add(10 * time.Minute), PriorIDs: []uint64{11}}); err == nil {
		t.Fatal("ambiguous new preauth key identities were accepted")
	}
	connectorCreatedAt := time.Now().UTC()
	deviceID, found, err := connectorDeviceCandidate([]managedheadscale.Device{{ID: 21, UserID: 41, CreatedAt: connectorCreatedAt, IPAddresses: []string{"100.64.0.10", "fd7a:115c:a1e0::10"}}}, &connectorDeviceIntent{UserID: 41, ControlURL: "https://control.example.test", CreatedAt: connectorCreatedAt, Deadline: connectorCreatedAt.Add(10 * time.Minute), PriorIDs: []uint64{}}, []netip.Addr{netip.MustParseAddr("100.64.0.10"), netip.MustParseAddr("fd7a:115c:a1e0::10")})
	if err != nil || !found || deviceID != 21 {
		t.Fatalf("connector device delta was not recovered exactly: id=%d found=%t err=%v", deviceID, found, err)
	}
}

func TestRevokedPreauthKeyRequiresFreshInactiveListProof(t *testing.T) {
	now := time.Now().UTC()
	key := managedheadscale.PreauthKey{ID: 73, UserID: 41, Expiration: now.Add(time.Hour)}
	if err := confirmRevokedPreauthKey([]managedheadscale.PreauthKey{key}, key.ID, now); err == nil {
		t.Fatal("active key was accepted as revoked")
	}
	key.Used = true
	if err := confirmRevokedPreauthKey([]managedheadscale.PreauthKey{key}, key.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := confirmRevokedPreauthKey(nil, key.ID, now); err == nil {
		t.Fatal("missing key was accepted as exact revocation proof")
	}
}

func TestExpiredConnectorDeviceRequiresFreshListProof(t *testing.T) {
	now := time.Now().UTC()
	active := managedheadscale.Device{ID: 21, UserID: 41, Expiry: time.Time{}}
	if err := confirmExpiredConnectorDevice([]managedheadscale.Device{active}, active.ID, active.UserID, now); err == nil {
		t.Fatal("expire action success was trusted without a changed device list")
	}
	active.Expiry = now.Add(time.Minute)
	if err := confirmExpiredConnectorDevice([]managedheadscale.Device{active}, active.ID, active.UserID, now); err == nil {
		t.Fatal("future device expiry was accepted as effective")
	}
	active.Expiry = now.Add(-time.Second)
	if err := confirmExpiredConnectorDevice([]managedheadscale.Device{active}, active.ID, active.UserID, now); err != nil {
		t.Fatal(err)
	}
	if err := confirmExpiredConnectorDevice(nil, active.ID, active.UserID, now); err == nil {
		t.Fatal("disappeared device was accepted as proof that the exact ID expired")
	}
}
