package release

import "testing"

func TestSelectSupportedProfileMatchesFamilyAndFallsBackForFutureRelease(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: "debian-13", Family: "debian", Release: "13", Architecture: "amd64"}},
		{Profile: OSProfile{ID: "ubuntu-24.04", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
	}}
	selected, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "ubuntu", OSVersionID: "30.04", Architecture: "amd64"})
	if err != nil || selected.Profile.ID != "ubuntu-24.04" {
		t.Fatalf("future family profile = %#v, err = %v", selected.Profile, err)
	}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "fedora", OSVersionID: "40", Architecture: "amd64"}); err == nil {
		t.Fatal("unsupported distribution family was accepted")
	}
}

func TestSelectSupportedProfileRejectsDuplicateExactFamilyProfiles(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: "ubuntu-a", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
		{Profile: OSProfile{ID: "ubuntu-b", Family: "ubuntu", Release: "24.04", Architecture: "amd64"}},
	}}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "ubuntu", OSVersionID: "24.04", Architecture: "amd64"}); err == nil {
		t.Fatal("duplicate exact family profiles were accepted")
	}
}
