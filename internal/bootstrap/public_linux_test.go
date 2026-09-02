//go:build linux

package bootstrap

import (
	"encoding/json"
	"lanpanel/internal/preflight"
	"reflect"
	"strings"
	"testing"
)

func TestPublicInstallerArgsAreClosedAndExplicit(t *testing.T) {
	digest := strings.Repeat("a", 64)
	bundle, contact, selectedDigest, err := parsePublicInstallerArgs([]string{"--bundle-dir", "/srv/lanpanel-release", "--release-digest", digest, "--acme-account-contact", "admin@example.com"})
	if err != nil || bundle != "/srv/lanpanel-release" || contact != "admin@example.com" || selectedDigest != digest {
		t.Fatalf("valid public installer arguments rejected: %q %q %q %v", bundle, contact, selectedDigest, err)
	}
	for _, args := range [][]string{
		{"--bundle-dir", "release", "--release-digest", digest, "--acme-account-contact", "admin@example.com"},
		{"--bundle-dir", "/srv/release", "--release-digest", "not-a-digest", "--acme-account-contact", "admin@example.com"},
		{"--bundle-dir", "/srv/release", "--release-digest", digest, "--acme-account-contact", "not-an-email"},
		{"--bundle-dir", "/srv/release", "--unknown", "value", "--release-digest", digest, "--acme-account-contact", "admin@example.com"},
		{"--bundle-dir", "/srv/release", "--bundle-dir", "/srv/other", "--release-digest", digest, "--acme-account-contact", "admin@example.com"},
		{"--bundle-dir", "/srv/release", "--release-digest", "", "--release-digest", digest, "--acme-account-contact", "admin@example.com"},
	} {
		if _, _, _, err := parsePublicInstallerArgs(args); err == nil {
			t.Fatalf("unsafe public installer arguments accepted: %#v", args)
		}
	}
}

func TestPublicInstallerResumeChecksTerminalPhaseBeforeInput(t *testing.T) {
	if err := validatePublicInstallerResume(PhaseActivated, nil); err == nil || !strings.Contains(err.Error(), "already activated") {
		t.Fatalf("activated resume was not recognized before input validation: %v", err)
	}
	if err := validatePublicInstallerResume(PhasePrepared, nil); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("nonterminal resume without input was not rejected: %v", err)
	}
}

func TestPublicInstallerInputRebindsPackageAuthority(t *testing.T) {
	original := installerInput{SchemaVersion: installerInputSchema, Kind: "public_release", ACMEAccountContact: "admin@example.com", AssetPaths: map[string]string{"lanpanel": "/srv/lanpanel"}}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	result := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: 7}
	plan := original.PackagePlan
	bound, err := rebindPublicInstallerInput(data, plan, result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded installerInput
	if err := json.Unmarshal(bound, &decoded); err != nil || !reflect.DeepEqual(decoded.PackagePlan, plan) || !reflect.DeepEqual(decoded.PackagePreflight, result) {
		t.Fatalf("rebound public authority changed unexpectedly: %#v", decoded)
	}
}

func TestPublicInstallerBindsTheRunningExecutable(t *testing.T) {
	binary, err := readCurrentExecutable(64 << 20)
	if err != nil || len(binary) == 0 {
		t.Fatalf("current executable was not readable: %v", err)
	}
	if _, err := readCurrentExecutable(uint64(len(binary) - 1)); err == nil {
		t.Fatal("current executable over the selected release size was accepted")
	}
}
