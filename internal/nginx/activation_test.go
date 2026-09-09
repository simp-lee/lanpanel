package nginx

import (
	"context"
	"lanpanel/internal/filetxn"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func TestChallengeSnapshotCoexistsWithPublishedResourceEntry(t *testing.T) {
	paths, prior := installTestGraph(t)
	owner := testOwner()
	entry := Entry{Kind: EntryChallenge, ResourceID: "app-one", Relative: ChallengesDirectory + "/app-one.conf", Digest: "sha256:" + repeatHex('0'), Domains: []string{"app.example.test"}, Listeners: []string{"tcp:0.0.0.0:80", "tcp:[::]:80"}, Generation: 2, Challenge: &ChallengeSite{Generation: 2, Host: "app.example.test", Token: "abcdefghijklmnopqrstuv", TokenPath: "/.well-known/acme-challenge/abcdefghijklmnopqrstuv", KeyAuthorizationDigest: "sha256:" + repeatHex('b'), Webroot: "/var/lib/lanpanel/certificates/webroot/cert_app_one"}}
	digestValue, err := DigestEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Digest = digestValue
	snapshot, err := SnapshotActivation(paths, owner, entry)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.EntryPresent {
		t.Fatal("published App entry was mistaken for its separate challenge entry")
	}
	prospective, err := ProspectiveManifest(prior, entry)
	if err != nil {
		t.Fatal(err)
	}
	installed, _, err := InstallEntry(context.Background(), paths, owner, entry)
	if err != nil || !reflect.DeepEqual(installed, prospective) || len(installed.Entries) != len(prior.Entries)+1 {
		t.Fatalf("coexisting challenge install=%#v err=%v", installed, err)
	}
	removalSnapshot, err := SnapshotActivation(paths, owner, entry)
	if err != nil || !removalSnapshot.EntryPresent {
		t.Fatalf("installed challenge snapshot=%#v err=%v", removalSnapshot, err)
	}
	if _, _, err := RemoveEntry(context.Background(), paths, owner, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreActivation(context.Background(), paths, owner, entry, removalSnapshot); err != nil {
		t.Fatal(err)
	}
	restored, err := Audit(paths, owner)
	if err != nil || !reflect.DeepEqual(restored, installed) {
		t.Fatalf("coexisting challenge removal rollback=%#v err=%v", restored, err)
	}
}

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
	prospective, err := ProspectiveManifest(prior, candidate)
	if err != nil {
		t.Fatal(err)
	}
	installed, _, err := InstallEntry(context.Background(), paths, owner, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prospective, installed) {
		t.Fatal("prospective Nginx manifest differs from installed graph")
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
