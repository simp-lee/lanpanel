package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceArchiveMustMatchCleanTrackedTree(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "--quiet")
	runGit(t, root, "add", "main.go")
	runGit(t, root, "-c", "user.name=LanPanel Test", "-c", "user.email=test@lanpanel.invalid", "commit", "--quiet", "-m", "fixture")
	archive := sourceArchiveFixture(t)
	digest, err := VerifySourceArchiveAgainstCleanTree(root, archive)
	if err != nil || !ValidDigest(digest) {
		t.Fatalf("clean archive was not bound to tracked tree: digest=%q err=%v", digest, err)
	}
	runGit(t, root, "update-index", "--split-index")
	if _, err := VerifySourceArchiveAgainstCleanTree(root, archive); err == nil {
		t.Fatal("split Git index was accepted")
	}
	runGit(t, root, "update-index", "--no-split-index")
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySourceArchiveAgainstCleanTree(root, archive); err == nil {
		t.Fatal("tracked source drift was accepted")
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
