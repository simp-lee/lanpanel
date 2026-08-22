//go:build linux

package qualification

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/release"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const liveStateSchemaVersion = "lanpanel.qualification.live-state.v2"

type dnsCreateIntent struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type liveState struct {
	SchemaVersion        string             `json:"schema_version"`
	RunID                string             `json:"run_id"`
	ProtectedInputDigest string             `json:"protected_input_digest"`
	ResourceID           string             `json:"resource_id,omitempty"`
	TemporaryResourceID  string             `json:"temporary_resource_id,omitempty"`
	TailnetResourceID    string             `json:"tailnet_resource_id,omitempty"`
	BasicCredentialID    string             `json:"basic_credential_id,omitempty"`
	StaticRootID         string             `json:"static_root_id,omitempty"`
	ExternalCredentialID string             `json:"external_credential_id,omitempty"`
	HeadscaleUserID      string             `json:"headscale_user_id,omitempty"`
	PreauthKeyID         string             `json:"preauth_key_id,omitempty"`
	ConnectorDeviceID    string             `json:"connector_device_id,omitempty"`
	ConnectorBound       bool               `json:"connector_bound"`
	DNSCreateIntents     []dnsCreateIntent  `json:"dns_create_intents"`
	CloudflareRecords    []cloudflareRecord `json:"cloudflare_records"`
	FixtureCreated       bool               `json:"fixture_created"`
	DNSProfileCreated    bool               `json:"dns_profile_created"`
	ResourceDeleted      bool               `json:"resource_deleted"`
	CloseAllCommitted    bool               `json:"close_all_committed"`
	CompletedSteps       []string           `json:"completed_steps"`
	FinalCleanupComplete bool               `json:"final_cleanup_complete"`
}

type liveStateStore struct{ path string }

func (store liveStateStore) Read(runID, inputDigest string) (liveState, bool, error) {
	data, _, err := readProtectedFile(store.path, 4<<20, false)
	if os.IsNotExist(err) {
		return liveState{SchemaVersion: liveStateSchemaVersion, RunID: runID, ProtectedInputDigest: inputDigest, DNSCreateIntents: []dnsCreateIntent{}, CloudflareRecords: []cloudflareRecord{}, CompletedSteps: []string{}}, false, nil
	}
	if err != nil {
		return liveState{}, false, err
	}
	var state liveState
	if err := release.DecodeCanonical(data, &state); err != nil {
		return liveState{}, false, err
	}
	if err := validateLiveState(state, runID, inputDigest); err != nil {
		return liveState{}, false, err
	}
	return state, true, nil
}

func (store liveStateStore) Write(state liveState) error {
	if err := validateLiveState(state, state.RunID, state.ProtectedInputDigest); err != nil {
		return err
	}
	data, err := release.MarshalCanonical(state)
	if err != nil {
		return err
	}
	parentPath, name := filepath.Dir(store.path), filepath.Base(store.path)
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	var parent unix.Stat_t
	if unix.Fstat(parentFD, &parent) != nil || parent.Uid != uint32(os.Geteuid()) || parent.Mode&0o077 != 0 {
		return fmt.Errorf("live executor state parent is unsafe")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, name); err != nil {
		return err
	}
	cleanup = false
	return unix.Fsync(parentFD)
}

func validateLiveState(state liveState, runID, inputDigest string) error {
	if state.SchemaVersion != liveStateSchemaVersion || state.RunID != runID || state.ProtectedInputDigest != inputDigest || !release.ValidDigest(inputDigest) || len(state.DNSCreateIntents) > 16 || len(state.CloudflareRecords) > 16 {
		return fmt.Errorf("live executor state authority is invalid")
	}
	for _, value := range []string{state.ResourceID, state.TemporaryResourceID, state.TailnetResourceID, state.BasicCredentialID, state.StaticRootID, state.ExternalCredentialID, state.HeadscaleUserID, state.PreauthKeyID, state.ConnectorDeviceID} {
		if value != "" && (len(value) > 256 || value != filepath.Base(value)) {
			return fmt.Errorf("live executor state identity is invalid")
		}
	}
	previousStep := ""
	for _, step := range state.CompletedSteps {
		if !containsString(orderedJourney, step) || previousStep != "" && previousStep >= step {
			return fmt.Errorf("live executor completed-step state is invalid")
		}
		previousStep = step
	}
	intentNames := map[string]bool{}
	for _, intent := range state.DNSCreateIntents {
		if !canonicalDomain(intent.Name) || intent.Address == "" || intentNames[intent.Name] {
			return fmt.Errorf("live executor DNS intent state is invalid")
		}
		intentNames[intent.Name] = true
	}
	seen := map[string]bool{}
	for _, record := range state.CloudflareRecords {
		if record.ID == "" || !canonicalDomain(record.Name) || record.Type != "A" || record.Content == "" || seen[record.ID] {
			return fmt.Errorf("live executor Cloudflare state is invalid")
		}
		seen[record.ID] = true
	}
	return nil
}
