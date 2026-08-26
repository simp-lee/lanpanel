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
		child.HeadscaleUserList:    {[]byte(`[ {"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}} ]`)},
		child.HeadscaleDeviceList:  {[]byte(`[ {"id":3,"ip_addresses":["100.64.0.2"],"name":"laptop","user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"created_at":{"seconds":1700000001,"nanos":0},"online":true} ]`)},
		child.HeadscalePreauthList: {[]byte(fmt.Sprintf(`[ {"user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"id":7,"key":"hskey-auth-prefix-***","reusable":false,"ephemeral":false,"used":false,"expiration":{"seconds":%d,"nanos":0},"created_at":{"seconds":%d,"nanos":0},"acl_tags":[]} ]`, future, created))},
	}}
	users, err := ListUsers(context.Background(), runner, "hds_00000000000000000000000000000001")
	if err != nil || len(users) != 1 || users[0].DeviceCount != 1 || users[0].ActiveKeyCount != 1 {
		t.Fatalf("users=%#v err=%v", users, err)
	}
	createRunner := &timedPreauthRunner{lifetime: time.Hour}
	key, secret, err := CreatePreauthKey(context.Background(), createRunner, "hds_00000000000000000000000000000001", 1, time.Hour)
	if err != nil || key.ID != 8 || string(secret) != "hskey-auth-prefix-secret" {
		t.Fatalf("key=%#v secret=%q err=%v", key, secret, err)
	}
	clear(secret)
	last := createRunner.seen
	if last.ExpirationSeconds != 3600 || last.Identifier != "1" {
		t.Fatalf("typed create invocation=%#v", last)
	}
}

func TestCreatePreauthKeyRequiresFreshCurrentExactLifetime(t *testing.T) {
	for _, test := range []struct {
		name          string
		createdOffset time.Duration
		lifetime      time.Duration
		wantAccepted  bool
	}{
		{name: "accurate lifetime", lifetime: time.Hour, wantAccepted: true},
		{name: "stale creation", createdOffset: -2 * time.Minute, lifetime: time.Hour},
		{name: "expired", createdOffset: -2 * time.Hour, lifetime: time.Hour},
		{name: "too short", lifetime: 30 * time.Minute},
		{name: "future creation", createdOffset: time.Minute, lifetime: time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &timedPreauthRunner{createdOffset: test.createdOffset, lifetime: test.lifetime}
			key, secret, err := CreatePreauthKey(context.Background(), runner, "hds_00000000000000000000000000000001", 1, time.Hour)
			defer clear(secret)
			if test.wantAccepted {
				if err != nil || key.Expiration.Sub(key.CreatedAt) != time.Hour || len(secret) == 0 {
					t.Fatalf("accurate fresh key rejected: key=%+v err=%v", key, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid key timing accepted: key=%+v", key)
			}
		})
	}
}

type timedPreauthRunner struct {
	createdOffset time.Duration
	lifetime      time.Duration
	seen          child.HeadscaleInvocation
}

func (runner *timedPreauthRunner) Run(_ context.Context, invocation child.HeadscaleInvocation) ([]byte, error) {
	runner.seen = invocation
	if invocation.AdminAction != child.HeadscalePreauthCreate {
		return nil, fmt.Errorf("unexpected action %s", invocation.AdminAction)
	}
	created := time.Now().UTC().Add(runner.createdOffset)
	expiration := created.Add(runner.lifetime)
	return []byte(fmt.Sprintf(`{"user":{"id":1,"name":"alice","created_at":{"seconds":1700000000,"nanos":0}},"id":8,"key":"hskey-auth-prefix-secret","reusable":false,"ephemeral":false,"used":false,"expiration":{"seconds":%d,"nanos":%d},"created_at":{"seconds":%d,"nanos":%d},"acl_tags":[]}`,
		expiration.Unix(), expiration.Nanosecond(), created.Unix(), created.Nanosecond())), nil
}

func TestCreatedPreauthTimeBoundaries(t *testing.T) {
	startedAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	finishedAt := startedAt.Add(10 * time.Millisecond)
	validatedAt := finishedAt.Add(10 * time.Millisecond)
	for _, test := range []struct {
		name       string
		createdAt  time.Time
		expiration time.Time
		wantErr    bool
	}{
		{name: "exact", createdAt: startedAt, expiration: startedAt.Add(time.Hour)},
		{name: "subsecond serialization loss", createdAt: startedAt, expiration: startedAt.Add(time.Hour - 999*time.Millisecond)},
		{name: "full second too short", createdAt: startedAt, expiration: startedAt.Add(time.Hour - time.Second), wantErr: true},
		{name: "overlong", createdAt: startedAt, expiration: startedAt.Add(time.Hour + time.Nanosecond), wantErr: true},
		{name: "exact freshness window stale", createdAt: startedAt.Add(-time.Second), expiration: startedAt.Add(time.Hour - time.Second), wantErr: true},
		{name: "stale", createdAt: startedAt.Add(-time.Second - time.Nanosecond), expiration: startedAt.Add(time.Hour), wantErr: true},
		{name: "future created", createdAt: finishedAt.Add(time.Nanosecond), expiration: finishedAt.Add(time.Hour), wantErr: true},
		{name: "expired", createdAt: startedAt, expiration: validatedAt, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCreatedPreauthTimes(PreauthKey{CreatedAt: test.createdAt, Expiration: test.expiration}, time.Hour, startedAt, finishedAt, validatedAt)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateCreatedPreauthTimes() error=%v wantErr=%v", err, test.wantErr)
			}
		})
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
