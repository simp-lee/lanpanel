//go:build linux

package application

import (
	"lanpanel/internal/nginx"
	"slices"
	"sort"
	"testing"
)

func TestExpectedNginxRuntimeListenersIncludesBaselineAndCanonicalizesIPv6(t *testing.T) {
	manifest := nginx.Manifest{Entries: []nginx.Entry{{Listeners: []string{"tcp:0.0.0.0:18080", "tcp:[::]:80"}}}}
	got := expectedNginxRuntimeListeners(manifest)
	want := []string{"tcp:0.0.0.0:80", "tcp:0.0.0.0:443", "tcp::::80", "tcp::::443", "tcp:0.0.0.0:18080"}
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("runtime listeners=%v, want %v", got, want)
	}
}
