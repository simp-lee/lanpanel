//go:build linux

package filetxn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanPrivateStagingRequiresExactInertArtifacts(t *testing.T) {
	owner := Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	name := ".lanpanel-txn.0123456789abcdef.0123456789abcdef01234567"

	t.Run("removes_exact_artifact", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(root, "staging")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("staged"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CleanPrivateStaging(directory, owner, 64<<10); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("staging artifact remains: %v", err)
		}
	})

	for _, test := range []struct {
		name  string
		entry string
		make  func(string) error
	}{
		{name: "unknown_name", entry: "unknown", make: func(path string) error { return os.WriteFile(path, nil, 0o600) }},
		{name: "symbolic_link", entry: name, make: func(path string) error { return os.Symlink("missing", path) }},
		{name: "wrong_mode", entry: name, make: func(path string) error { return os.WriteFile(path, nil, 0o640) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(root, "staging")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, test.entry)
			if err := test.make(path); err != nil {
				t.Fatal(err)
			}
			if err := CleanPrivateStaging(directory, owner, 64<<10); err == nil {
				t.Fatal("unsafe staging artifact was accepted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("unsafe staging artifact was removed: %v", err)
			}
		})
	}
}
