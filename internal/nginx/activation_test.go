package nginx

import (
	"context"
	"lanpanel/internal/filetxn"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestActivationSnapshotRestoresExactPriorGraph(t *testing.T) {
	paths, prior := installTestGraph(t)
	owner := testOwner()
	resourceID := "res_restore"
	relative := filepath.ToSlash(filepath.Join(TemporaryDirectory, resourceID+".conf"))
	priorEntry := Entry{Kind: EntryTemporary, ResourceID: resourceID, Relative: relative, Digest: "sha256:" + repeatHex('a'), Listeners: []string{"tcp:0.0.0.0:18080"}, Generation: 1, Temporary: &TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/tmp/prior.sock", ReadinessPath: "/ready"}}
	manifest, _, err := InstallEntry(context.Background(), paths, owner, priorEntry)
	if err != nil {
		t.Fatal(err)
	}
	prior = manifest
	candidate := priorEntry
	candidate.Generation = 2
	candidate.Temporary = &TemporarySite{PublicIPv4: "8.8.8.8", Port: 18080, HostAuthority: "8.8.8.8:18080", UpstreamNetwork: "unix", UpstreamAddress: "/tmp/candidate.sock", ReadinessPath: "/ready"}
	snapshot, err := SnapshotActivation(paths, owner, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := InstallEntry(context.Background(), paths, owner, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreActivation(context.Background(), paths, owner, candidate, snapshot); err != nil {
		t.Fatal(err)
	}
	restored, err := Audit(paths, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Entries) != len(prior.Entries) || restored.Entries[len(restored.Entries)-1].Generation != 1 {
		t.Fatalf("prior graph not restored: %#v", restored.Entries)
	}
	data, err := os.ReadFile(filepath.Join(paths.ConfigRoot, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(snapshot.EntryBytes) {
		t.Fatal("prior entry bytes changed")
	}
}

func testOwner() filetxn.Owner {
	current, _ := user.Current()
	uid, _ := strconv.ParseUint(current.Uid, 10, 32)
	gid, _ := strconv.ParseUint(current.Gid, 10, 32)
	return filetxn.Owner{UID: uint32(uid), GID: uint32(gid)}
}

func repeatHex(value byte) string {
	data := make([]byte, 64)
	for i := range data {
		data[i] = value
	}
	return string(data)
}
