//go:build linux

package qualification

import (
	managedheadscale "lanpanel/internal/headscale"
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

	after = append(after, managedheadscale.Device{ID: 22, UserID: 41, Name: "duplicate-match", IPAddresses: []string{locals[0].String(), locals[1].String()}})
	if _, err := selectConnectorDevice(before, after, 41, locals); err == nil {
		t.Fatal("multiple new devices matching the connector were accepted")
	}
	if _, err := selectConnectorDevice(before, []managedheadscale.Device{{ID: 21, UserID: 42, Name: "wrong-user", IPAddresses: []string{locals[0].String(), locals[1].String()}}}, 41, locals); err == nil {
		t.Fatal("connector device with a different user was accepted")
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
