package release

import "testing"

func TestIsSupportedPreviewTarget(t *testing.T) {
	cases := []struct {
		name      string
		family    string
		release   string
		arch      string
		supported bool
	}{
		{name: "debian current amd64", family: PreviewDebianFamily, release: "13", arch: PreviewTargetArchitecture, supported: true},
		{name: "debian future amd64", family: PreviewDebianFamily, release: "99", arch: PreviewTargetArchitecture, supported: true},
		{name: "ubuntu current amd64", family: PreviewUbuntuFamily, release: "24.04", arch: PreviewTargetArchitecture, supported: true},
		{name: "ubuntu future amd64", family: PreviewUbuntuFamily, release: "30.04", arch: PreviewTargetArchitecture, supported: true},
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
