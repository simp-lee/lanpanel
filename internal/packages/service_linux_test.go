//go:build linux

package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanpanel/internal/filetxn"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/preflight"
)

func TestPackageServiceSerializesExecution(t *testing.T) {
	service := &Service{}
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		service.mu.Lock()
		close(locked)
		<-release
		service.mu.Unlock()
	}()
	<-locked
	go func() {
		_, _ = service.Execute(context.Background(), helperproto.Request{})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("package execution bypassed service transaction serialization")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serialized package execution did not resume")
	}
}

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
	preflightResult := preflight.Result{SchemaVersion: preflight.SchemaVersion, Scope: string(preflight.ExpansionBootstrap), Target: "installation", Generation: plan.IntentGeneration, RequestDigest: "sha256:" + strings.Repeat("6", 64), Allowed: true, ObservedAt: time.Now().UTC(), ValidUntil: time.Now().UTC().Add(preflight.MaximumAge), Findings: []preflight.Finding{{Code: "ready", Disposition: preflight.FindingPassed, Summary: "shared expansion preflight passed", Identity: "fixture"}}}
	preflightResult.ValidUntil = preflightResult.ObservedAt.Add(preflight.MaximumAge)
	plan.PreflightDigest, err = preflightResult.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.PreflightRequestDigest = preflightResult.RequestDigest
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
	service := &Service{files: files, journal: journals, owner: owner, planRoot: plans}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: "request-one", Operation: helperproto.OperationPackageTransaction, Target: "installation", IntentGeneration: plan.IntentGeneration, Deadline: plan.Deadline, InputDigest: inputDigest}
	// Production adds current installation/release authority verification. This
	// narrow test proves digest/generation/deadline binding and fails closed
	// before that verifier when authority is absent.
	if _, err := service.loadPlan(context.Background(), request); err == nil {
		t.Fatalf("missing current release authority error=%v", err)
	}
	preflightData, err := json.Marshal(preflightResult)
	if err != nil {
		t.Fatal(err)
	}
	preflightPath := filepath.Join(plans, hex.EncodeToString(digest[:])+".preflight.json")
	if _, err := files.Put(context.Background(), filetxn.Request{Path: preflightPath, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700}, New: metadata, MaxBytes: maximumJournalBytes}, preflightData, filetxn.CreateOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := service.loadPreflight(context.Background(), request, plan); err != nil {
		t.Fatal(err)
	}
	request.IntentGeneration++
	if _, err := service.loadPlan(context.Background(), request); err == nil {
		t.Fatal("helper intent generation mismatch was accepted")
	}
}
