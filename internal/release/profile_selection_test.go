package release

import "testing"

func TestSelectSupportedProfileMatchesFamilyAcrossReleases(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: "debian-amd64", Family: "debian", Release: "12", Architecture: "amd64"}},
		{Profile: OSProfile{ID: "ubuntu-amd64", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
	}}
	for _, version := range []string{"12", "13", "14"} {
		selected, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "debian", OSVersionID: version, Architecture: "amd64"})
		if err != nil || selected.Profile.ID != "debian-amd64" {
			t.Fatalf("debian %s family profile = %#v, err = %v", version, selected.Profile, err)
		}
	}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "fedora", OSVersionID: "40", Architecture: "amd64"}); err == nil {
		t.Fatal("unsupported distribution family was accepted")
	}
}

func TestSelectSupportedProfileMatchesGenericCapabilityContract(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{{Profile: OSProfile{ID: PreviewCapabilityContractID, Architecture: "amd64", ServiceManager: "systemd", PackageManager: "apt-dpkg", Nginx: NginxCapabilityContract{Package: "nginx", MinimumVersion: "1.18.0", Service: "nginx.service"}, Packages: []PackageTuple{{Name: "nginx", Version: "1.26.0", VersionMinimum: "1.18.0", Architecture: "amd64"}}}}}}
	for _, platform := range []string{"debian", "ubuntu", "fedora", "alpine"} {
		selected, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: platform, OSVersionID: "future", Architecture: "amd64"})
		if err != nil || selected.Profile.ID != PreviewCapabilityContractID {
			t.Fatalf("generic contract for %s = %#v, err = %v", platform, selected.Profile, err)
		}
	}
}

func TestSelectSupportedProfileRejectsDuplicateFamilyProfiles(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: "ubuntu-a", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
		{Profile: OSProfile{ID: "ubuntu-b", Family: "ubuntu", Release: "26.04", Architecture: "amd64"}},
	}}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "ubuntu", OSVersionID: "26.04", Architecture: "amd64"}); err == nil {
		t.Fatal("duplicate family profiles were accepted")
	}
}
