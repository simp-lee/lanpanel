package preflight

import (
	"strings"
	"testing"
)

func TestCheckPackageSourceModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        PackageSourceState
		status       Status
		wantFindings []string
	}{
		{
			name: "direct missing reachability confirmation",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:    "direct",
				Version: "0.29.1",
			}),
			status: StatusFail,
		},
		{
			name: "direct missing integrity evidence",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:                "direct",
				Version:             "0.29.1",
				ReachabilityChecked: true,
				Reachable:           true,
			}),
			status: StatusFail,
		},
		{
			name: "direct verified",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:                "direct",
				Version:             "0.29.1",
				ExpectedSHA256:      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				ReachabilityChecked: true,
				Reachable:           true,
				IntegrityChecked:    true,
				ActualSHA256:        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			}),
			status: StatusPass,
			wantFindings: []string{
				"Pinned lego archive source mode: direct.",
				"Pinned lego archive URL: https://github.com/go-acme/lego/releases/download/v5.2.2/lego_v5.2.2_linux_amd64.tar.gz.",
			},
		},
		{
			name: "mirror checksum mismatch",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:                "mirror",
				Version:             "0.29.1",
				URL:                 "https://mirror.example.com/headscale.deb",
				ExpectedSHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ReachabilityChecked: true,
				Reachable:           true,
				IntegrityChecked:    true,
				ActualSHA256:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			}),
			status: StatusFail,
		},
		{
			name: "mirror reachability not confirmed",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:           "mirror",
				Version:        "0.29.1",
				URL:            "https://mirror.example.com/headscale.deb",
				ExpectedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}),
			status: StatusFail,
		},
		{
			name: "mirror integrity not confirmed",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:                "mirror",
				Version:             "0.29.1",
				URL:                 "https://mirror.example.com/headscale.deb",
				ExpectedSHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ReachabilityChecked: true,
				Reachable:           true,
			}),
			status: StatusFail,
		},
		{
			name: "offline package missing",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:             "offline",
				Version:          "0.29.1",
				FilePath:         "/tmp/headscale.deb",
				ExpectedSHA256:   "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				FileExists:       false,
				IntegrityChecked: true,
			}),
			status: StatusFail,
		},
		{
			name: "offline integrity not confirmed",
			input: withVerifiedLegoSource(PackageSourceState{
				Mode:           "offline",
				Version:        "0.29.1",
				FilePath:       "/tmp/headscale.deb",
				ExpectedSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				FileExists:     true,
			}),
			status: StatusFail,
		},
		{
			name: "lego reachability not confirmed",
			input: PackageSourceState{
				Mode:                "direct",
				Version:             "0.29.1",
				ExpectedSHA256:      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				ReachabilityChecked: true,
				Reachable:           true,
				IntegrityChecked:    true,
				ActualSHA256:        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				LegoVersion:         "v5.2.2",
				LegoURL:             "https://github.com/go-acme/lego/releases/download/v5.2.2/lego_v5.2.2_linux_amd64.tar.gz",
				LegoExpectedSHA256:  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			},
			status: StatusFail,
		},
		{
			name: "offline lego archive verified",
			input: PackageSourceState{
				Mode:                 "direct",
				Version:              "0.29.1",
				ExpectedSHA256:       "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				ReachabilityChecked:  true,
				Reachable:            true,
				IntegrityChecked:     true,
				ActualSHA256:         "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				LegoMode:             "offline",
				LegoVersion:          "v5.2.2",
				LegoFilePath:         "/srv/packages/lego_v5.2.2_linux_amd64.tar.gz",
				LegoFileExists:       true,
				LegoExpectedSHA256:   "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
				LegoIntegrityChecked: true,
				LegoActualSHA256:     "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			},
			status: StatusPass,
			wantFindings: []string{
				"Pinned lego archive source mode: offline.",
				"Offline lego archive path: /srv/packages/lego_v5.2.2_linux_amd64.tar.gz.",
			},
		},
		{
			name: "offline lego archive missing",
			input: PackageSourceState{
				Mode:                "direct",
				Version:             "0.29.1",
				ExpectedSHA256:      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				ReachabilityChecked: true,
				Reachable:           true,
				IntegrityChecked:    true,
				ActualSHA256:        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				LegoMode:            "offline",
				LegoVersion:         "v5.2.2",
				LegoFilePath:        "/srv/packages/lego_v5.2.2_linux_amd64.tar.gz",
				LegoExpectedSHA256:  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			},
			status: StatusFail,
		},
		{
			name: "offline lego archive checksum mismatch",
			input: PackageSourceState{
				Mode:                 "direct",
				Version:              "0.29.1",
				ExpectedSHA256:       "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				ReachabilityChecked:  true,
				Reachable:            true,
				IntegrityChecked:     true,
				ActualSHA256:         "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				LegoMode:             "offline",
				LegoVersion:          "v5.2.2",
				LegoFilePath:         "/srv/packages/lego_v5.2.2_linux_amd64.tar.gz",
				LegoFileExists:       true,
				LegoExpectedSHA256:   "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
				LegoIntegrityChecked: true,
				LegoActualSHA256:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			},
			status: StatusFail,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := CheckPackageSource(tt.input)
			if result.Status != tt.status {
				t.Fatalf("CheckPackageSource() status = %q, want %q", result.Status, tt.status)
			}
			if result.Summary == "" {
				t.Fatal("CheckPackageSource() summary = empty, want actionable summary")
			}
			for _, wantFinding := range tt.wantFindings {
				if !strings.Contains(strings.Join(result.Findings, "\n"), wantFinding) {
					t.Fatalf("CheckPackageSource() findings = %#v, want finding %q", result.Findings, wantFinding)
				}
			}
		})
	}
}

func withVerifiedLegoSource(state PackageSourceState) PackageSourceState {
	state.LegoMode = "direct"
	state.LegoVersion = "v5.2.2"
	state.LegoURL = "https://github.com/go-acme/lego/releases/download/v5.2.2/lego_v5.2.2_linux_amd64.tar.gz"
	state.LegoExpectedSHA256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	state.LegoReachabilityChecked = true
	state.LegoReachable = true
	state.LegoIntegrityChecked = true
	state.LegoActualSHA256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	return state
}
