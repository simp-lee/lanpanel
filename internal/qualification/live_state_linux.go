//go:build linux

package qualification

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/release"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const liveStateSchemaVersion = "lanpanel.qualification.live-state.v4"

type dnsCreateIntent struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type registrationIntent struct {
	Kind       string   `json:"kind"`
	ResourceID string   `json:"resource_id"`
	Selector   string   `json:"selector"`
	PriorIDs   []string `json:"prior_ids"`
}

type resourceCreateIntent struct {
	Slot       string   `json:"slot"`
	Name       string   `json:"name"`
	TargetKind string   `json:"target_kind"`
	SpecDigest string   `json:"spec_digest"`
	PriorIDs   []string `json:"prior_ids"`
}

type headscaleUserCreateIntent struct {
	Name     string   `json:"name"`
	PriorIDs []uint64 `json:"prior_ids"`
}

type preauthKeyCreateIntent struct {
	UserID            uint64    `json:"user_id"`
	ExpirationSeconds uint32    `json:"expiration_seconds"`
	CreatedAt         time.Time `json:"created_at"`
	Deadline          time.Time `json:"deadline"`
	PriorIDs          []uint64  `json:"prior_ids"`
}

type connectorDeviceIntent struct {
	UserID     uint64    `json:"user_id"`
	ControlURL string    `json:"control_url"`
	CreatedAt  time.Time `json:"created_at"`
	Deadline   time.Time `json:"deadline"`
	PriorIDs   []uint64  `json:"prior_ids"`
}

type qualificationCertificateArtifact struct {
	CertificateID string                      `json:"certificate_id"`
	Generation    uint64                      `json:"generation"`
	Bundle        certificates.BundleIdentity `json:"bundle"`
}

type qualificationCertificateInventoryEvidence struct {
	SchemaVersion string                             `json:"schema_version"`
	Deleted       []qualificationCertificateArtifact `json:"deleted"`
	Retained      qualificationCertificateArtifact   `json:"retained"`
}

const qualificationCertificateInventoryEvidenceSchema = "lanpanel.qualification.certificate-inventory.v1"

type liveState struct {
	SchemaVersion              string                             `json:"schema_version"`
	RunID                      string                             `json:"run_id"`
	ProtectedInputDigest       string                             `json:"protected_input_digest"`
	ResourceID                 string                             `json:"resource_id,omitempty"`
	TemporaryResourceID        string                             `json:"temporary_resource_id,omitempty"`
	TailnetResourceID          string                             `json:"tailnet_resource_id,omitempty"`
	BasicCredentialID          string                             `json:"basic_credential_id,omitempty"`
	StaticRootID               string                             `json:"static_root_id,omitempty"`
	ExternalCredentialID       string                             `json:"external_credential_id,omitempty"`
	HeadscaleUserID            string                             `json:"headscale_user_id,omitempty"`
	PreauthKeyID               string                             `json:"preauth_key_id,omitempty"`
	ConnectorDeviceID          string                             `json:"connector_device_id,omitempty"`
	ConnectorBound             bool                               `json:"connector_bound"`
	DNSCreateIntents           []dnsCreateIntent                  `json:"dns_create_intents"`
	CloudflareRecords          []cloudflareRecord                 `json:"cloudflare_records"`
	CertificateCleanup         []qualificationCertificateArtifact `json:"certificate_cleanup"`
	CertificateCleanupComplete bool                               `json:"certificate_cleanup_complete"`
	RetainedCertificate        *qualificationCertificateArtifact  `json:"retained_certificate,omitempty"`
	FixtureCreated             bool                               `json:"fixture_created"`
	DNSProfileCreated          bool                               `json:"dns_profile_created"`
	ResourceDeleted            bool                               `json:"resource_deleted"`
	CloseAllCommitted          bool                               `json:"close_all_committed"`
	CompletedSteps             []string                           `json:"completed_steps"`
	FinalCleanupComplete       bool                               `json:"final_cleanup_complete"`
	PendingRegistration        *registrationIntent                `json:"pending_registration,omitempty"`
	PendingResourceCreate      *resourceCreateIntent              `json:"pending_resource_create,omitempty"`
	PendingHeadscaleUserCreate *headscaleUserCreateIntent         `json:"pending_headscale_user_create,omitempty"`
	PendingPreauthKeyCreate    *preauthKeyCreateIntent            `json:"pending_preauth_key_create,omitempty"`
	PendingConnectorDevice     *connectorDeviceIntent             `json:"pending_connector_device,omitempty"`
}

type liveStateStore struct{ path string }

func (store liveStateStore) Read(runID, inputDigest string) (liveState, bool, error) {
	data, _, err := readProtectedFile(store.path, 4<<20, false)
	if os.IsNotExist(err) {
		return liveState{SchemaVersion: liveStateSchemaVersion, RunID: runID, ProtectedInputDigest: inputDigest, DNSCreateIntents: []dnsCreateIntent{}, CloudflareRecords: []cloudflareRecord{}, CertificateCleanup: []qualificationCertificateArtifact{}, CompletedSteps: []string{}}, false, nil
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
	if state.SchemaVersion != liveStateSchemaVersion || state.RunID != runID || state.ProtectedInputDigest != inputDigest || !release.ValidDigest(inputDigest) || len(state.DNSCreateIntents) > 16 || len(state.CloudflareRecords) > 16 || len(state.CertificateCleanup) > 32 {
		return fmt.Errorf("live executor state authority is invalid")
	}
	if err := validateQualificationCertificateArtifacts(state.CertificateCleanup, false); err != nil {
		return err
	}
	if state.RetainedCertificate != nil {
		if err := validateQualificationCertificateArtifacts([]qualificationCertificateArtifact{*state.RetainedCertificate}, false); err != nil {
			return err
		}
		for _, artifact := range state.CertificateCleanup {
			if artifact.CertificateID == state.RetainedCertificate.CertificateID {
				return fmt.Errorf("retained certificate is scheduled for cleanup")
			}
		}
	}
	if state.CertificateCleanupComplete && len(state.CertificateCleanup) == 0 || state.FinalCleanupComplete && len(state.CertificateCleanup) != 0 && !state.CertificateCleanupComplete {
		return fmt.Errorf("live executor certificate cleanup state is incomplete")
	}
	for _, value := range []string{state.ResourceID, state.TemporaryResourceID, state.TailnetResourceID, state.BasicCredentialID, state.StaticRootID, state.ExternalCredentialID, state.HeadscaleUserID, state.PreauthKeyID, state.ConnectorDeviceID} {
		if value != "" && (len(value) > 256 || value != filepath.Base(value)) {
			return fmt.Errorf("live executor state identity is invalid")
		}
	}
	if err := validateRegistrationIntent(state.PendingRegistration); err != nil {
		return err
	}
	if err := validateResourceCreateIntent(state.PendingResourceCreate); err != nil {
		return err
	}
	if err := validateHeadscaleUserIntent(state.PendingHeadscaleUserCreate); err != nil {
		return err
	}
	if err := validatePreauthKeyIntent(state.PendingPreauthKeyCreate); err != nil {
		return err
	}
	if err := validateConnectorDeviceIntent(state.PendingConnectorDevice); err != nil {
		return err
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

func validateQualificationCertificateArtifacts(values []qualificationCertificateArtifact, requireOne bool) error {
	if len(values) > 32 || requireOne && len(values) != 1 {
		return fmt.Errorf("qualification certificate inventory is invalid")
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		bundlePath, bundleErr := certificates.BundlePath(value.CertificateID, value.Generation)
		pointerPath, pointerErr := certificates.ActivePointerPath(value.CertificateID)
		key := fmt.Sprintf("%s/%d", value.CertificateID, value.Generation)
		if bundleErr != nil || pointerErr != nil || bundlePath == "" || pointerPath == "" || certificates.ValidateBundleIdentity(value.Bundle) != nil || seen[key] {
			return fmt.Errorf("qualification certificate identity is invalid")
		}
		seen[key] = true
	}
	return nil
}

func certificateInventoryEvidence(state liveState) ([]byte, error) {
	if !state.CertificateCleanupComplete || len(state.CertificateCleanup) == 0 || state.RetainedCertificate == nil {
		return nil, fmt.Errorf("qualification certificate evidence state is incomplete")
	}
	value := qualificationCertificateInventoryEvidence{SchemaVersion: qualificationCertificateInventoryEvidenceSchema, Deleted: append([]qualificationCertificateArtifact(nil), state.CertificateCleanup...), Retained: *state.RetainedCertificate}
	if err := validateQualificationCertificateInventoryEvidence(value); err != nil {
		return nil, err
	}
	return release.MarshalCanonical(value)
}

func decodeQualificationCertificateInventoryEvidence(data []byte) (qualificationCertificateInventoryEvidence, error) {
	var value qualificationCertificateInventoryEvidence
	if err := release.DecodeCanonical(data, &value); err != nil {
		return qualificationCertificateInventoryEvidence{}, err
	}
	if err := validateQualificationCertificateInventoryEvidence(value); err != nil {
		return qualificationCertificateInventoryEvidence{}, err
	}
	return value, nil
}

func validateQualificationCertificateInventoryEvidence(value qualificationCertificateInventoryEvidence) error {
	if value.SchemaVersion != qualificationCertificateInventoryEvidenceSchema || len(value.Deleted) == 0 || validateQualificationCertificateArtifacts(value.Deleted, false) != nil || validateQualificationCertificateArtifacts([]qualificationCertificateArtifact{value.Retained}, true) != nil {
		return fmt.Errorf("qualification certificate evidence is invalid")
	}
	for _, deleted := range value.Deleted {
		if deleted.CertificateID == value.Retained.CertificateID {
			return fmt.Errorf("qualification retained certificate is in deleted inventory")
		}
	}
	return nil
}

func validateRegistrationIntent(intent *registrationIntent) error {
	if intent == nil {
		return nil
	}
	if (intent.Kind != "managed_basic" && intent.Kind != "static_root" && intent.Kind != "external_htpasswd") || intent.ResourceID == "" || intent.ResourceID != filepath.Base(intent.ResourceID) || intent.Selector == "" || len(intent.Selector) > 4096 || strings.ContainsRune(intent.Selector, '\x00') || len(intent.PriorIDs) > 1024 {
		return fmt.Errorf("live executor registration intent is invalid")
	}
	return validateStringIDs(intent.PriorIDs)
}

func validateResourceCreateIntent(intent *resourceCreateIntent) error {
	if intent == nil {
		return nil
	}
	if (intent.Slot != "local" && intent.Slot != "temporary" && intent.Slot != "tailnet") || intent.Name == "" || len(intent.Name) > 256 || strings.ContainsAny(intent.Name, "\x00\r\n") || intent.TargetKind == "" || len(intent.TargetKind) > 256 || strings.ContainsAny(intent.TargetKind, "\x00\r\n") || !release.ValidDigest(intent.SpecDigest) || len(intent.PriorIDs) > 1024 {
		return fmt.Errorf("live executor resource creation intent is invalid")
	}
	wantKind := "local_http"
	if intent.Slot == "tailnet" {
		wantKind = "tailnet_http"
	}
	if intent.TargetKind != wantKind {
		return fmt.Errorf("live executor resource creation target kind is invalid")
	}
	return validateStringIDs(intent.PriorIDs)
}

func validateHeadscaleUserIntent(intent *headscaleUserCreateIntent) error {
	if intent == nil {
		return nil
	}
	if intent.Name == "" || len(intent.Name) > 256 || strings.ContainsRune(intent.Name, '\x00') || len(intent.PriorIDs) > 1024 {
		return fmt.Errorf("live executor Headscale user intent is invalid")
	}
	return validateUintIDs(intent.PriorIDs)
}

func validatePreauthKeyIntent(intent *preauthKeyCreateIntent) error {
	if intent == nil {
		return nil
	}
	if intent.UserID == 0 || intent.ExpirationSeconds == 0 || intent.ExpirationSeconds > 24*60*60 || intent.CreatedAt.IsZero() || intent.Deadline.IsZero() || !intent.Deadline.After(intent.CreatedAt) || intent.Deadline.Sub(intent.CreatedAt) > 10*time.Minute || len(intent.PriorIDs) > 1024 {
		return fmt.Errorf("live executor preauth key intent is invalid")
	}
	return validateUintIDs(intent.PriorIDs)
}

func validateConnectorDeviceIntent(intent *connectorDeviceIntent) error {
	if intent == nil {
		return nil
	}
	if intent.UserID == 0 || intent.ControlURL == "" || len(intent.ControlURL) > 512 || strings.ContainsAny(intent.ControlURL, "\x00\r\n") || intent.CreatedAt.IsZero() || intent.Deadline.IsZero() || !intent.Deadline.After(intent.CreatedAt) || intent.Deadline.Sub(intent.CreatedAt) > 10*time.Minute || len(intent.PriorIDs) > 1024 {
		return fmt.Errorf("live executor connector device intent is invalid")
	}
	return validateUintIDs(intent.PriorIDs)
}

func validateStringIDs(values []string) error {
	previous := ""
	for _, value := range values {
		if value == "" || len(value) > 256 || value != filepath.Base(value) || previous != "" && previous >= value {
			return fmt.Errorf("live executor string identity inventory is invalid")
		}
		previous = value
	}
	return nil
}

func validateUintIDs(values []uint64) error {
	previous := uint64(0)
	for _, value := range values {
		if value == 0 || previous >= value {
			return fmt.Errorf("live executor numeric identity inventory is invalid")
		}
		previous = value
	}
	return nil
}
