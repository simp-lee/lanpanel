//go:build linux

package bootstrap

import (
	"encoding/json"
	"io"
	"lanpanel/internal/packages"
	"lanpanel/internal/preflight"
	"lanpanel/internal/release"
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

func TestExistingNginxOwnedListenersOnlyCoversIngressPorts(t *testing.T) {
	got := existingNginxOwnedListeners([]preflight.ListenerObservation{{Protocol: "tcp", Address: "0.0.0.0", Port: 80, SocketInode: 11}, {Protocol: "tcp", Address: "::", Port: 443, SocketInode: 12}, {Protocol: "udp", Address: "0.0.0.0", Port: 3478, SocketInode: 13}})
	if len(got) != 2 || got[0].Port != 80 || got[1].Port != 443 || got[0].IdentityDigest != preflight.OwnedListenerDigest("tcp", "0.0.0.0", 80, 11) || got[1].IdentityDigest != preflight.OwnedListenerDigest("tcp", "::", 443, 12) {
		t.Fatalf("owned listeners=%#v", got)
	}
}

func TestExistingNginxVersionUsesCapabilityRange(t *testing.T) {
	authority := release.InstallIdentity{Profile: release.OSProfile{Nginx: release.NginxCapabilityContract{MinimumVersion: "1.18.0", MaximumVersion: "2.0.0"}}}
	for _, test := range []struct {
		version string
		wantErr bool
	}{
		{version: "1.24.0-2ubuntu7.18"},
		{version: "2.0.0", wantErr: true},
		{version: "1.17.9", wantErr: true},
	} {
		err := validateExistingNginxVersion(authority, preflight.InstalledPackageTuple{Name: "nginx", Version: test.version, Architecture: "amd64"})
		if (err != nil) != test.wantErr {
			t.Fatalf("version %s error=%v wantErr=%t", test.version, err, test.wantErr)
		}
	}
}

func TestPublicPackagePlanRequiresHostAPTMode(t *testing.T) {
	for _, mode := range []packages.Mode{packages.StagedDebs, packages.OfflineDebs} {
		if err := validatePublicPackagePlan(packages.Plan{Mode: mode}); err == nil {
			t.Fatalf("public package mode %q was accepted", mode)
		}
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
