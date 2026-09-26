//go:build linux

package bootstrap

import (
	"encoding/json"
	"io"
	"lanpanel/internal/preflight"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestArtifactDirectoryRejectsUnexpectedAssets(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "release.json"), []byte("manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateArtifactDirectory(root, []string{"release.json"}); err == nil {
		t.Fatal("unexpected artifact asset was accepted")
	}
}

func TestFreshInstallRejectsForeignNginx(t *testing.T) {
	if err := validateFreshNginxPackageOwnership(preflight.InstalledPackageTuple{Name: "nginx", Version: "1.22.1-9", Architecture: "amd64"}); err == nil || !strings.Contains(err.Error(), "already installed outside LanPanel") {
		t.Fatalf("foreign Nginx was not rejected clearly: %v", err)
	}
}

func TestPublicInstallerHasNoUserSuppliedAuthorityArguments(t *testing.T) {
	if err := runPublicInstaller([]string{"--bundle-dir", "/srv/release"}, io.Discard); err == nil {
		t.Fatal("legacy public installer arguments were accepted")
	}
}

func TestPublicInstallerResumeAllowsCommittedSameReleaseReplay(t *testing.T) {
	if err := validatePublicInstallerResume(PhaseActivated, nil); err != nil {
		t.Fatalf("activated same-release replay was rejected: %v", err)
	}
	if err := validatePublicInstallerResume(PhasePrepared, nil); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("nonterminal resume without input was not rejected: %v", err)
	}
}

func TestPublicInstallerInputRebindsPackageAuthority(t *testing.T) {
	original := installerInput{SchemaVersion: installerInputSchema, Kind: "public_release", AssetPaths: map[string]string{"lanpanel": "/srv/lanpanel"}}
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
