//go:build linux

package headscale

import (
	"context"
	"fmt"
	"lanpanel/internal/child"
	"testing"
	"time"
)

type adminFixtureRunner struct {
	outputs map[child.HeadscaleAdminAction][][]byte
	seen    []child.HeadscaleInvocation
}

func (runner *adminFixtureRunner) Run(_ context.Context, invocation child.HeadscaleInvocation) ([]byte, error) {
	runner.seen = append(runner.seen, invocation)
	values := runner.outputs[invocation.AdminAction]
	if len(values) == 0 {
		return nil, fmt.Errorf("missing fixture for %s", invocation.AdminAction)
	}
	runner.outputs[invocation.AdminAction] = values[1:]
	return append([]byte(nil), values[0]...), nil
}

func TestHeadscaleLifecycleParsesRedactedListsAndOneTimeCreate(t *testing.T) {
	future := time.Now().UTC().Add(time.Hour).Unix()
	created := future - int64(time.Hour/time.Second)
	runner := &adminFixtureRunner{outputs: map[child.HeadscaleAdminAction][][]byte{
		child.HeadscaleUserList:      {[]byte(`[ {"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}} ]`)},
		child.HeadscaleDeviceList:    {[]byte(`[ {"id":3,"ip_addresses":["100.64.0.2"],"name":"laptop","user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"created_at":{"seconds":1700000001,"nanos":0},"online":true} ]`)},
		child.HeadscalePreauthList:   {[]byte(fmt.Sprintf(`[ {"user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"id":7,"key":"hskey-auth-prefix-***","reusable":false,"ephemeral":false,"used":false,"expiration":{"seconds":%d,"nanos":0},"created_at":{"seconds":%d,"nanos":0},"acl_tags":[]} ]`, future, created))},
		child.HeadscalePreauthCreate: {[]byte(fmt.Sprintf(`{"user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"id":8,"key":"hskey-auth-prefix-secret","reusable":false,"ephemeral":false,"used":false,"expiration":{"seconds":%d,"nanos":0},"created_at":{"seconds":%d,"nanos":0},"acl_tags":[]}`, future, created))},
	}}
	users, err := ListUsers(context.Background(), runner, "hds_00000000000000000000000000000001")
	if err != nil || len(users) != 1 || users[0].DeviceCount != 1 || users[0].ActiveKeyCount != 1 {
		t.Fatalf("users=%#v err=%v", users, err)
	}
	key, secret, err := CreatePreauthKey(context.Background(), runner, "hds_00000000000000000000000000000001", 1, time.Hour)
	if err != nil || key.ID != 8 || string(secret) != "hskey-auth-prefix-secret" {
		t.Fatalf("key=%#v secret=%q err=%v", key, secret, err)
	}
	clear(secret)
	last := runner.seen[len(runner.seen)-1]
	if last.ExpirationSeconds != 3600 || last.Identifier != "1" {
		t.Fatalf("typed create invocation=%#v", last)
	}
}

func TestCreatePreauthKeyRejectsWrongExpiration(t *testing.T) {
	created := time.Now().UTC().Unix()
	runner := &adminFixtureRunner{outputs: map[child.HeadscaleAdminAction][][]byte{
		child.HeadscalePreauthCreate: {[]byte(fmt.Sprintf(`{"user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"id":8,"key":"hskey-auth-prefix-secret","reusable":false,"ephemeral":false,"used":false,"expiration":{"seconds":%d,"nanos":0},"created_at":{"seconds":%d,"nanos":0},"acl_tags":[]}`, created+7200, created))},
	}}
	if _, _, err := CreatePreauthKey(context.Background(), runner, "hds_00000000000000000000000000000001", 1, time.Hour); err == nil {
		t.Fatal("preauth key exceeding requested expiration accepted")
	}
}

func TestHeadscaleLifecycleRejectsSecretBearingListAndUnknownFields(t *testing.T) {
	runner := &adminFixtureRunner{outputs: map[child.HeadscaleAdminAction][][]byte{
		child.HeadscalePreauthList: {[]byte(`[ {"user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"id":7,"key":"hskey-auth-prefix-plaintext-secret","reusable":false,"ephemeral":false,"used":false,"expiration":{"seconds":2000000000,"nanos":0},"created_at":{"seconds":1700000002,"nanos":0},"acl_tags":[]} ]`)},
	}}
	if _, err := ListPreauthKeys(context.Background(), runner, "hds_00000000000000000000000000000001"); err == nil {
		t.Fatal("secret-bearing preauth list was accepted")
	}
	runner.outputs[child.HeadscaleUserCreate] = [][]byte{[]byte(`{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0},"future_field":true}`)}
	if _, err := CreateUser(context.Background(), runner, "hds_00000000000000000000000000000001", "alice"); err == nil {
		t.Fatal("unknown upstream user field was accepted")
	}
}
