package release

import "testing"

func TestValidateSupportedPreviewFamiliesRequiresExactFourTargets(t *testing.T) {
	profile := func(family, release string) SupportedOSProfile {
		return SupportedOSProfile{Profile: OSProfile{Family: family, Release: release, Architecture: PreviewTargetArchitecture}}
	}
	if err := validateSupportedPreviewFamilies([]SupportedOSProfile{profile(PreviewUbuntuFamily, "24.04")}); err == nil {
		t.Fatal("partial release profile set was accepted")
	}
	complete := []SupportedOSProfile{
		profile(PreviewDebianFamily, "12"), profile(PreviewDebianFamily, "13"),
		profile(PreviewUbuntuFamily, "22.04"), profile(PreviewUbuntuFamily, "24.04"),
	}
	if err := validateSupportedPreviewFamilies(complete); err != nil {
		t.Fatalf("complete four-target profile set rejected: %v", err)
	}
}

func TestIsSupportedPreviewTarget(t *testing.T) {
	cases := []struct {
		name      string
		family    string
		release   string
		arch      string
		supported bool
	}{
		{name: "debian 12 amd64", family: PreviewDebianFamily, release: "12", arch: PreviewTargetArchitecture, supported: true},
		{name: "debian 13 amd64", family: PreviewDebianFamily, release: "13", arch: PreviewTargetArchitecture, supported: true},
		{name: "ubuntu 22.04 amd64", family: PreviewUbuntuFamily, release: "22.04", arch: PreviewTargetArchitecture, supported: true},
		{name: "ubuntu 24.04 amd64", family: PreviewUbuntuFamily, release: "24.04", arch: PreviewTargetArchitecture, supported: true},
		{name: "debian future amd64", family: PreviewDebianFamily, release: "99", arch: PreviewTargetArchitecture, supported: false},
		{name: "ubuntu future amd64", family: PreviewUbuntuFamily, release: "30.04", arch: PreviewTargetArchitecture, supported: false},
		{name: "arm64", family: PreviewDebianFamily, release: "13", arch: "arm64"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			profile := OSProfile{Family: test.family, Release: test.release, Architecture: test.arch}
			if actual := IsSupportedPreviewTarget(profile); actual != test.supported {
				t.Fatalf("IsSupportedPreviewTarget() = %v, want %v", actual, test.supported)
			}
		})
	}
}
