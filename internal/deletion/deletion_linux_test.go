//go:build linux

package deletion

import (
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveDurablyDeletesOnlyThroughSafeParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "managed")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeDurably(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("durable removal left path: %v", err)
	}
}

func TestTailnetDeleteHasNoLocalInventoryAndExternalSourcesAreNeverAccepted(t *testing.T) {
	resource := domain.AppResource{ID: "res_00000000000000000000000000000001", Lifecycle: domain.LifecycleDeleting, Target: domain.AppTarget{Kind: domain.AppTargetTailnetHTTP, TailnetHTTP: &domain.TailnetHTTPTarget{IP: "100.64.0.2", SourceIP: "100.64.0.1", Port: 8080}}, PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 2}, ManagedPaths: []string{}}
	removed, err := Cleanup(resource, nil)
	if err != nil || len(removed) != 0 {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	resource.ManagedPaths = []string{"/srv/external-app"}
	if _, err := Cleanup(resource, nil); err == nil {
		t.Fatal("tailnet delete accepted external inventory")
	}
}
