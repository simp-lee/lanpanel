package release

import "testing"

func TestValidateSupportedPreviewFamiliesAcceptsGenericCapabilityContract(t *testing.T) {
	profile := SupportedOSProfile{Profile: OSProfile{ID: PreviewCapabilityContractID, Architecture: PreviewTargetArchitecture, ServiceManager: "systemd", PackageManager: "apt-dpkg", Nginx: NginxCapabilityContract{Package: "nginx", MinimumVersion: "1.18.0", Service: "nginx.service"}, Packages: []PackageTuple{{Name: "nginx", Version: "1.26.0", VersionMinimum: "1.18.0", Architecture: "amd64"}}}}
	if err := validateSupportedPreviewFamilies([]SupportedOSProfile{profile}); err != nil {
		t.Fatalf("generic capability contract rejected: %v", err)
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
		{name: "debian future amd64", family: PreviewDebianFamily, release: "99", arch: PreviewTargetArchitecture, supported: true},
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
