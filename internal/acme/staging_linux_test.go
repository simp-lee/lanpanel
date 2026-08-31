//go:build linux

package acme

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegoAccountKeyPathUsesPinnedServerAndEmail(t *testing.T) {
	binding := Binding{DirectoryURL: "https://acme.example.test:8443/directory", AccountKeyPath: "/root/account.key", AccountKeyFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AccountEmail: "admin@example.test", TermsAccepted: true, Method: ChallengeHTTP01, CredentialFiles: []CredentialFile{}}
	path, err := LegoAccountKeyPath(binding)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/work/accounts/acme.example.test_8443/admin@example.test/keys/admin@example.test.key" {
		t.Fatalf("account key path=%q", path)
	}
	binding.TermsAccepted = false
	if _, err := LegoAccountKeyPath(binding); err == nil {
		t.Fatal("unapproved Terms binding accepted")
	}
}

func TestPrepareStageMidwayFaultLeavesNoResidueAndCanRetry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership transitions are unavailable")
	}
	base := t.TempDir()
	chrootBase := filepath.Join(base, "chroot")
	webrootBase := filepath.Join(base, "webroot")
	for _, directory := range []string{chrootBase, webrootBase} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	certificateID := "cert_00000000000000000000000000000000"
	root := filepath.Join(chrootBase, certificateID)
	webroot := filepath.Join(webrootBase, certificateID)
	uid, gid := uint32(2200000), uint32(2200000)
	binding := Binding{
		DirectoryURL:          "https://acme.example.test/directory",
		AccountKeyPath:        filepath.Join(base, "missing-account.key"),
		AccountKeyFingerprint: "sha256:" + strings.Repeat("a", 64),
		AccountEmail:          "admin@example.test",
		TermsAccepted:         true,
		Method:                ChallengeHTTP01,
		CredentialFiles:       []CredentialFile{},
	}
	cleanup := func() error {
		return errors.Join(removeOwnedTree(root, uid, gid, 4096), removeOwnedTree(webroot, uid, gid, 1024))
	}
	for attempt := 1; attempt <= 2; attempt++ {
		stage, err := prepareStage(context.Background(), certificateID, binding, uid, gid, root, webroot, nil, cleanup)
		if err == nil || stage != (Stage{}) {
			t.Fatalf("attempt %d stage=%#v err=%v", attempt, stage, err)
		}
		if strings.Contains(err.Error(), "residue exists") {
			t.Fatalf("attempt %d was blocked by prior residue: %v", attempt, err)
		}
		for _, path := range []string{root, webroot} {
			if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("attempt %d left residue %q: %v", attempt, path, statErr)
			}
		}
	}
}
