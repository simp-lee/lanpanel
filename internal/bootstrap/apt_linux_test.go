//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"io"
	"lanpanel/internal/packages"
	"strings"
	"testing"
)

func TestShouldPrepareAPTMetadataSkipsCompletedReplay(t *testing.T) {
	activated := PhaseActivated
	packagesCommitted := PhasePackagesCommitted
	for _, test := range []struct {
		name     string
		strict   bool
		prepared bool
		mode     packages.Mode
		count    int
		phase    *Phase
		want     bool
	}{
		{name: "fresh", strict: true, count: 1, want: true},
		{name: "prepared input", strict: true, prepared: true, count: 1},
		{name: "no packages", strict: true},
		{name: "activated replay", strict: true, count: 1, phase: &activated},
		{name: "packages committed replay", strict: true, count: 1, phase: &packagesCommitted},
		{name: "non-strict fixture", count: 1},
		{name: "staged packages", mode: packages.StagedDebs, strict: true, count: 1},
		{name: "offline packages", mode: packages.OfflineDebs, strict: true, count: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := test.mode
			if mode == "" {
				mode = packages.DistroRepository
			}
			got := shouldPrepareAPTMetadata(test.strict, FixedPaths(), mode, test.prepared, test.count, test.phase)
			if got != test.want {
				t.Fatalf("shouldPrepareAPTMetadata()=%t want %t", got, test.want)
			}
		})
	}
}

func TestRefreshAPTMetadataWithReportsUpdaterDiagnostics(t *testing.T) {
	called := false
	err := refreshAPTMetadataWithOutput(context.Background(), func(_ context.Context, _, stderr io.Writer) error {
		called = true
		_, _ = io.WriteString(stderr, "mirror unavailable\n")
		return errors.New("apt-get exited unsuccessfully")
	}, io.Discard, io.Discard)
	if !called {
		t.Fatal("APT updater was not called")
	}
	if err == nil || !strings.Contains(err.Error(), "mirror unavailable") || !strings.Contains(err.Error(), "check the system clock") {
		t.Fatalf("APT updater error lacked actionable diagnostics: %v", err)
	}
}

func TestRefreshAPTMetadataWithBoundsUpdaterDiagnostics(t *testing.T) {
	err := refreshAPTMetadataWithOutput(context.Background(), func(_ context.Context, _, stderr io.Writer) error {
		_, _ = io.WriteString(stderr, strings.Repeat("x", maximumAPTRefreshOutput+1))
		return errors.New("apt-get exited unsuccessfully")
	}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "[APT output truncated]") {
		t.Fatalf("APT updater output was not bounded: %v", err)
	}
}
