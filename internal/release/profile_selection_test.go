package release

import "testing"

func TestSelectSupportedProfileMatchesExactRelease(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: "debian-12-amd64", Family: "debian", Release: "12", Architecture: "amd64"}},
		{Profile: OSProfile{ID: "debian-13-amd64", Family: "debian", Release: "13", Architecture: "amd64"}},
		{Profile: OSProfile{ID: "ubuntu-24.04-amd64", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
	}}
	selected, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "debian", OSVersionID: "13", Architecture: "amd64"})
	if err != nil || selected.Profile.ID != "debian-13-amd64" {
		t.Fatalf("exact release profile = %#v, err = %v", selected.Profile, err)
	}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "ubuntu", OSVersionID: "22.04", Architecture: "amd64"}); err == nil {
		t.Fatal("unsupported exact release was accepted")
	}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "fedora", OSVersionID: "40", Architecture: "amd64"}); err == nil {
		t.Fatal("unsupported distribution family was accepted")
	}
}

func TestSelectSupportedProfileRejectsDuplicateExactReleaseProfiles(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: "ubuntu-a", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
		{Profile: OSProfile{ID: "ubuntu-b", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
	}}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "ubuntu", OSVersionID: "24.04", Architecture: "amd64"}); err == nil {
		t.Fatal("duplicate exact release profiles were accepted")
	}
}
