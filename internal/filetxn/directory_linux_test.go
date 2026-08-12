//go:build linux

package filetxn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryBundleCommitsAllMembersAtOneNamespaceBoundary(t *testing.T) {
	parent := t.TempDir()
	owner := Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	request := DirectoryRequest{ParentPath: parent, Parent: Metadata{Owner: owner, Mode: 0o700}, TargetName: "installation", Directory: Metadata{Owner: owner, Mode: 0o700}, Members: []DirectoryMember{
		{Name: "admin-token", Data: []byte("secret"), Owner: owner, Mode: 0o600, Maximum: 64},
		{Name: "bundle.json", Data: []byte("{}"), Owner: owner, Mode: 0o600, Maximum: 64},
	}}
	identity, err := CommitNewDirectory(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyDirectory(request)
	if err != nil || verified != identity {
		t.Fatalf("verify=%#v err=%v want=%#v", verified, err, identity)
	}
	if _, err := CommitNewDirectory(context.Background(), request); err == nil {
		t.Fatal("committed bundle was replaced")
	}
}

func TestDirectoryBundleRejectsForeignAndLinkedMembers(t *testing.T) {
	parent := t.TempDir()
	owner := Owner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	_ = os.Chmod(parent, 0o700)
	request := DirectoryRequest{ParentPath: parent, Parent: Metadata{Owner: owner, Mode: 0o700}, TargetName: "installation", Directory: Metadata{Owner: owner, Mode: 0o700}, Members: []DirectoryMember{{Name: "bundle.json", Data: []byte("{}"), Owner: owner, Mode: 0o600, Maximum: 64}}}
	if _, err := CommitNewDirectory(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "installation", "foreign"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(request); err == nil {
		t.Fatal("foreign member accepted")
	}
	_ = os.Remove(filepath.Join(parent, "installation", "foreign"))
	if err := os.Link(filepath.Join(parent, "installation", "bundle.json"), filepath.Join(parent, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(request); err == nil {
		t.Fatal("hard-linked bundle member accepted")
	}
}
