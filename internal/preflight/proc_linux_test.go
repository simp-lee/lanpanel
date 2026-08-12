//go:build linux

package preflight

import "testing"

func TestRealProcListenerTablesAreReadableWithPseudoFileSemantics(t *testing.T) {
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		data, err := readBoundedProcFile(path, 32<<20)
		if err != nil {
			t.Fatalf("readBoundedProcFile(%q): %v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("readBoundedProcFile(%q) returned no header", path)
		}
	}
}
