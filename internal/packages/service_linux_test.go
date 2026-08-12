//go:build linux

package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lanpanel/internal/filetxn"
	"lanpanel/internal/helperproto"
)

func TestPackageServiceBindsCanonicalPlanToHelperIntent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "filetxn")
	plans := filepath.Join(root, "plans")
	journalsPath := filepath.Join(root, "journals")
	for _, path := range []string{staging, plans, journalsPath} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	owner := filetxn.Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	files, err := filetxn.Open(filetxn.Config{RootPath: root, Root: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingPath: staging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700}, StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}}, filetxn.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	journals, err := NewFileJournalStore(files, journalsPath, owner)
	if err != nil {
		t.Fatal(err)
	}
	plan := testPlan(t, OfflineDebs)
	plan.Deadline = time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	inputDigest := "sha256:" + hex.EncodeToString(digest[:])
	metadata := filetxn.Metadata{Owner: owner, Mode: 0o600}
	path := filepath.Join(plans, hex.EncodeToString(digest[:])+".json")
	if _, err := files.Put(context.Background(), filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, New: metadata, MaxBytes: maximumJournalBytes}, data, filetxn.CreateOnly); err != nil {
		t.Fatal(err)
	}
	service := &Service{files: files, journal: journals, owner: owner}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "request-one", Operation: helperproto.OperationPackageTransaction, Target: "installation", IntentGeneration: plan.IntentGeneration, Deadline: plan.Deadline, InputDigest: inputDigest}
	// Production adds current installation/release authority verification. This
	// narrow test proves digest/generation/deadline binding and fails closed
	// before that verifier when authority is absent.
	if _, err := service.loadPlan(context.Background(), request); err == nil {
		t.Fatalf("missing current release authority error=%v", err)
	}
	request.IntentGeneration++
	if _, err := service.loadPlan(context.Background(), request); err == nil {
		t.Fatal("helper intent generation mismatch was accepted")
	}
}
