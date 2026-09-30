package release

import (
	"strings"
	"testing"
)

func testCapabilityContract(arch string) OSProfile {
	return OSProfile{
		ID:             PreviewCapabilityContractID,
		Architecture:   arch,
		ServiceManager: "systemd",
		PackageManager: "apt-dpkg",
		Nginx:          NginxCapabilityContract{Package: "nginx", MinimumVersion: "1.18.0", Service: "nginx.service"},
		Confinement:    ConfinementCapabilityContract{UnifiedCgroupV2: true, CgroupKill: true, SystemdDelegate: true},
		Packages:       []PackageTuple{{Name: "nginx", Version: "1.26.0", VersionMinimum: "1.18.0", Architecture: "amd64"}},
		ManagedConfinement: ConfinementProfile{
			SchemaVersion: "lanpanel.managed.confinement.v1", KernelRelease: "any", CgroupMode: "unified_v2",
			BindListenPolicy: "systemd_bind_baseline_v1", ConnectPolicy: "systemd_cgroup_ip_deny_v1", FilesystemPolicy: "systemd_mount_namespace_v1",
			ProtectedDestinations: []string{"127.0.0.0/8"}, PolicyDigest: strings.Repeat("0", 64),
		},
	}
}

func TestValidateSupportedPreviewFamiliesAcceptsGenericCapabilityContract(t *testing.T) {
	profile := SupportedOSProfile{Profile: testCapabilityContract("amd64")}
	if err := validateSupportedPreviewFamilies([]SupportedOSProfile{profile}); err != nil {
		t.Fatalf("generic capability contract rejected: %v", err)
	}
}

func TestIsSupportedPreviewTargetRequiresCapabilityContract(t *testing.T) {
	if !IsSupportedPreviewTarget(testCapabilityContract("amd64")) {
		t.Fatal("complete capability contract was rejected")
	}
	if IsSupportedPreviewTarget(OSProfile{Family: "debian", Release: "12", Architecture: "amd64"}) {
		t.Fatal("legacy OS profile was accepted")
	}
	if IsSupportedPreviewTarget(testCapabilityContract("arm64")) {
		t.Fatal("non-amd64 capability contract was accepted")
	}
}
