//go:build linux

package process

import (
	"context"
	"lanpanel/internal/domain"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestStoppedTCPInventoryRejectsExactListener(t *testing.T) {
	data := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0900007F:4A39 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42\n")
	present, err := procTCPListenerPresent(data, netip.MustParseAddr("127.0.0.9"), 19001)
	if err != nil || !present {
		t.Fatalf("present=%t err=%v", present, err)
	}
	present, err = procTCPListenerPresent(data, netip.MustParseAddr("127.0.0.10"), 19001)
	if err != nil || present {
		t.Fatalf("foreign present=%t err=%v", present, err)
	}
}

func TestStoppedObservationRejectsOwnedEndpointResidue(t *testing.T) {
	root := t.TempDir()
	cgroup := "/lanpanel.slice/lanpanel-app.slice/lanpanel-app-00000000000000000000.slice/lanpanel-app-00000000000000000000.service"
	bundle := domain.ProcessBundle{Cgroup: cgroup, FrontendEndpoint: filepath.Join(root, "frontend.sock"), EndpointSocketUnits: []string{"lanpanel-app-00000000000000000000.socket"}}
	if err := os.MkdirAll(filepath.Join(root, cgroup), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, cgroup, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, cgroup, "cgroup.events"), []byte("populated 0\nfrozen 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle.FrontendEndpoint, []byte("residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ObserveStopped(context.Background(), root, bundle); err == nil {
		t.Fatal("endpoint residue accepted")
	}
	if err := os.Remove(bundle.FrontendEndpoint); err != nil {
		t.Fatal(err)
	}
	observation, err := ObserveStopped(context.Background(), root, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStopped(observation); err != nil {
		t.Fatal(err)
	}
}
