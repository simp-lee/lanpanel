package release

import "testing"

func TestSelectSupportedProfileUsesOnlyArchitectureAndCapabilityContract(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: PreviewCapabilityContractID, Architecture: "amd64"}},
	}}
	for _, platform := range []string{"debian", "ubuntu", "fedora", "alpine"} {
		selected, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: platform, OSVersionID: "future", Architecture: "amd64"})
		if err != nil || selected.Profile.ID != PreviewCapabilityContractID {
			t.Fatalf("generic contract for %s = %#v, err = %v", platform, selected.Profile, err)
		}
	}
}

func TestSelectSupportedProfileRejectsDuplicateCapabilityContracts(t *testing.T) {
	manifest := ReleaseManifest{SupportedProfiles: []SupportedOSProfile{
		{Profile: OSProfile{ID: PreviewCapabilityContractID, Architecture: "amd64"}},
		{Profile: OSProfile{ID: PreviewCapabilityContractID, Architecture: "amd64"}},
	}}
	if _, err := selectSupportedProfile(manifest, PublicInstallObservation{OSID: "ubuntu", OSVersionID: "26.04", Architecture: "amd64"}); err == nil {
		t.Fatal("duplicate capability contracts were accepted")
	}
}
