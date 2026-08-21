//go:build linux

package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"lanpanel/internal/release"
	"strconv"
	"strings"
	"time"
)

const LifecycleVersion = release.SupportedHeadscaleVersion

type AdminRunner interface {
	Run(context.Context, child.HeadscaleInvocation) ([]byte, error)
}

type FixedAdminRunner struct {
	launcher    *child.Launcher
	headscaleID string
}

func NewFixedAdminRunner(installationID, headscaleID string) (*FixedAdminRunner, error) {
	account, err := ValidateAccount(installationID, headscaleID)
	if err != nil {
		return nil, err
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{Headscale: child.Identity{UID: account.UID, GID: account.GID}})
	if err != nil {
		return nil, err
	}
	return &FixedAdminRunner{launcher: launcher, headscaleID: headscaleID}, nil
}

func (runner *FixedAdminRunner) Run(ctx context.Context, invocation child.HeadscaleInvocation) ([]byte, error) {
	if runner == nil || runner.launcher == nil || invocation.HeadscaleID != runner.headscaleID {
		return nil, fmt.Errorf("headscale admin runner authority changed")
	}
	result, err := runner.launcher.RunInvocation(ctx, child.ProfileHeadscaleAdmin, child.Invocation{Headscale: &invocation}, nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff || len(result.Stdout) == 0 {
		clear(result.Stdout)
		return nil, errors.Join(err, fmt.Errorf("headscale admin child failed"))
	}
	return result.Stdout, nil
}

type Timestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

func (value Timestamp) Time() (time.Time, error) {
	if value.Seconds <= 0 || value.Nanos < 0 || value.Nanos >= 1_000_000_000 {
		return time.Time{}, fmt.Errorf("headscale timestamp is invalid")
	}
	return time.Unix(value.Seconds, int64(value.Nanos)).UTC(), nil
}

type User struct {
	ID             uint64    `json:"id"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"created_at"`
	DeviceCount    int       `json:"device_count"`
	ActiveKeyCount int       `json:"active_key_count"`
}

type PreauthKey struct {
	ID         uint64    `json:"id"`
	UserID     uint64    `json:"user_id"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"created_at"`
}

type Device struct {
	ID          uint64    `json:"id"`
	Name        string    `json:"name"`
	UserID      uint64    `json:"user_id"`
	IPAddresses []string  `json:"ip_addresses"`
	Online      bool      `json:"online"`
	Expiry      time.Time `json:"expiry,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
}

type userWire struct {
	ID            uint64    `json:"id"`
	Name          string    `json:"name"`
	CreatedAt     Timestamp `json:"created_at"`
	DisplayName   string    `json:"display_name,omitempty"`
	Email         string    `json:"email,omitempty"`
	ProviderID    string    `json:"provider_id,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	ProfilePicURL string    `json:"profile_pic_url,omitempty"`
}

type preauthWire struct {
	User       userWire  `json:"user"`
	ID         uint64    `json:"id"`
	Key        string    `json:"key"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration Timestamp `json:"expiration"`
	CreatedAt  Timestamp `json:"created_at"`
	ACLTags    []string  `json:"acl_tags"`
}

type nodeWire struct {
	ID              uint64       `json:"id"`
	MachineKey      string       `json:"machine_key,omitempty"`
	NodeKey         string       `json:"node_key,omitempty"`
	DiscoKey        string       `json:"disco_key,omitempty"`
	IPAddresses     []string     `json:"ip_addresses"`
	Name            string       `json:"name"`
	User            userWire     `json:"user"`
	LastSeen        *Timestamp   `json:"last_seen,omitempty"`
	Expiry          *Timestamp   `json:"expiry,omitempty"`
	PreAuthKey      *preauthWire `json:"pre_auth_key,omitempty"`
	CreatedAt       Timestamp    `json:"created_at"`
	RegisterMethod  int32        `json:"register_method,omitempty"`
	GivenName       string       `json:"given_name,omitempty"`
	Online          bool         `json:"online,omitempty"`
	ApprovedRoutes  []string     `json:"approved_routes,omitempty"`
	AvailableRoutes []string     `json:"available_routes,omitempty"`
	SubnetRoutes    []string     `json:"subnet_routes,omitempty"`
	Tags            []string     `json:"tags,omitempty"`
}

func CreateUser(ctx context.Context, runner AdminRunner, headscaleID, name string) (User, error) {
	raw, err := runner.Run(ctx, child.HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: child.HeadscaleUserCreate, Name: name})
	if err != nil {
		return User{}, err
	}
	defer clear(raw)
	var wire userWire
	if err := decodeStrict(raw, &wire); err != nil {
		return User{}, err
	}
	return normalizeUser(wire)
}

func ListUsers(ctx context.Context, runner AdminRunner, headscaleID string) ([]User, error) {
	usersRaw, err := runner.Run(ctx, child.HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: child.HeadscaleUserList})
	if err != nil {
		return nil, err
	}
	defer clear(usersRaw)
	var userValues []userWire
	if err := decodeStrict(usersRaw, &userValues); err != nil {
		return nil, err
	}
	nodes, err := ListDevices(ctx, runner, headscaleID)
	if err != nil {
		return nil, err
	}
	keys, err := ListPreauthKeys(ctx, runner, headscaleID)
	if err != nil {
		return nil, err
	}
	countsNodes, countsKeys := map[uint64]int{}, map[uint64]int{}
	for _, node := range nodes {
		countsNodes[node.UserID]++
	}
	for _, key := range keys {
		if !key.Used && key.Expiration.After(time.Now().UTC()) {
			countsKeys[key.UserID]++
		}
	}
	result := make([]User, 0, len(userValues))
	prior := uint64(0)
	for _, value := range userValues {
		user, err := normalizeUser(value)
		if err != nil || prior != 0 && prior >= user.ID {
			return nil, fmt.Errorf("headscale user inventory is invalid or unsorted")
		}
		user.DeviceCount, user.ActiveKeyCount = countsNodes[user.ID], countsKeys[user.ID]
		result = append(result, user)
		prior = user.ID
	}
	return result, nil
}

func CreatePreauthKey(ctx context.Context, runner AdminRunner, headscaleID string, userID uint64, expiration time.Duration) (PreauthKey, []byte, error) {
	if userID == 0 || expiration <= 0 || expiration > 24*time.Hour || expiration%time.Second != 0 {
		return PreauthKey{}, nil, fmt.Errorf("preauth key request is invalid")
	}
	raw, err := runner.Run(ctx, child.HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: child.HeadscalePreauthCreate, Identifier: strconv.FormatUint(userID, 10), ExpirationSeconds: uint32(expiration / time.Second)})
	if err != nil {
		return PreauthKey{}, nil, err
	}
	defer clear(raw)
	var wire preauthWire
	if err := decodeStrict(raw, &wire); err != nil {
		return PreauthKey{}, nil, err
	}
	key, err := normalizePreauth(wire, false)
	if err != nil || wire.User.ID != userID || wire.Reusable || wire.Ephemeral || len(wire.ACLTags) != 0 || wire.Used {
		return PreauthKey{}, nil, fmt.Errorf("created preauth key contract changed")
	}
	secret := []byte(wire.Key)
	wire.Key = ""
	return key, secret, nil
}

func ListPreauthKeys(ctx context.Context, runner AdminRunner, headscaleID string) ([]PreauthKey, error) {
	raw, err := runner.Run(ctx, child.HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: child.HeadscalePreauthList})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var values []preauthWire
	if err := decodeStrict(raw, &values); err != nil {
		return nil, err
	}
	result := make([]PreauthKey, 0, len(values))
	prior := uint64(0)
	for _, value := range values {
		key, err := normalizePreauth(value, true)
		if err != nil || prior != 0 && prior >= key.ID {
			return nil, fmt.Errorf("headscale preauth key inventory is invalid, secret-bearing, or unsorted")
		}
		result = append(result, key)
		prior = key.ID
	}
	return result, nil
}

func RevokePreauthKey(ctx context.Context, runner AdminRunner, headscaleID string, id uint64) (PreauthKey, error) {
	if id == 0 {
		return PreauthKey{}, fmt.Errorf("preauth key ID is invalid")
	}
	raw, err := runner.Run(ctx, child.HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: child.HeadscalePreauthRevoke, Identifier: strconv.FormatUint(id, 10)})
	if err != nil {
		return PreauthKey{}, err
	}
	clear(raw)
	values, err := ListPreauthKeys(ctx, runner, headscaleID)
	if err != nil {
		return PreauthKey{}, err
	}
	for _, value := range values {
		if value.ID == id {
			if value.Expiration.After(time.Now().UTC()) && !value.Used {
				return PreauthKey{}, fmt.Errorf("preauth key revoke postcondition is not fresh")
			}
			return value, nil
		}
	}
	return PreauthKey{}, fmt.Errorf("preauth key revoke ID disappeared")
}

func ListDevices(ctx context.Context, runner AdminRunner, headscaleID string) ([]Device, error) {
	raw, err := runner.Run(ctx, child.HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: child.HeadscaleDeviceList})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var values []nodeWire
	if err := decodeStrict(raw, &values); err != nil {
		return nil, err
	}
	result := make([]Device, 0, len(values))
	prior := uint64(0)
	for _, value := range values {
		created, err := value.CreatedAt.Time()
		if err != nil || value.ID == 0 || value.User.ID == 0 || value.Name == "" || strings.TrimSpace(value.Name) != value.Name || prior != 0 && prior >= value.ID {
			return nil, fmt.Errorf("headscale device inventory is invalid or unsorted")
		}
		device := Device{ID: value.ID, Name: value.Name, UserID: value.User.ID, IPAddresses: append([]string(nil), value.IPAddresses...), Online: value.Online, CreatedAt: created}
		if value.Expiry != nil {
			device.Expiry, err = value.Expiry.Time()
			if err != nil {
				return nil, err
			}
		}
		result = append(result, device)
		prior = value.ID
	}
	return result, nil
}

func ExpireDevice(ctx context.Context, runner AdminRunner, headscaleID string, id uint64) (Device, error) {
	if id == 0 {
		return Device{}, fmt.Errorf("device ID is invalid")
	}
	raw, err := runner.Run(ctx, child.HeadscaleInvocation{HeadscaleID: headscaleID, AdminAction: child.HeadscaleDeviceExpire, Identifier: strconv.FormatUint(id, 10)})
	if err != nil {
		return Device{}, err
	}
	clear(raw)
	values, err := ListDevices(ctx, runner, headscaleID)
	if err != nil {
		return Device{}, err
	}
	now := time.Now().UTC()
	for _, value := range values {
		if value.ID == id {
			if value.Expiry.IsZero() || value.Expiry.After(now) {
				return Device{}, fmt.Errorf("device expiry postcondition is not fresh")
			}
			return value, nil
		}
	}
	return Device{}, fmt.Errorf("device expiry ID disappeared")
}

func normalizeUser(value userWire) (User, error) {
	created, err := value.CreatedAt.Time()
	if err != nil || value.ID == 0 || value.Name == "" || strings.TrimSpace(value.Name) != value.Name {
		return User{}, fmt.Errorf("headscale user identity is invalid")
	}
	return User{ID: value.ID, Name: value.Name, CreatedAt: created}, nil
}

func normalizePreauth(value preauthWire, listed bool) (PreauthKey, error) {
	expiration, expirationErr := value.Expiration.Time()
	created, createdErr := value.CreatedAt.Time()
	masked := strings.HasSuffix(value.Key, "-***") && len(value.Key) < 160 && !strings.ContainsAny(value.Key, " \t\r\n")
	full := strings.HasPrefix(value.Key, "hskey-auth-") && !masked && len(value.Key) < 256 && !strings.ContainsAny(value.Key, " \t\r\n")
	if expirationErr != nil || createdErr != nil || value.ID == 0 || value.User.ID == 0 || listed && !masked || !listed && !full {
		return PreauthKey{}, fmt.Errorf("headscale preauth key identity or redaction is invalid")
	}
	return PreauthKey{ID: value.ID, UserID: value.User.ID, Reusable: value.Reusable, Ephemeral: value.Ephemeral, Used: value.Used, Expiration: expiration, CreatedAt: created}, nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode Headscale JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("headscale JSON has trailing output")
	}
	return nil
}
