//go:build linux

package acme

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"lanpanel/internal/acmeaccount"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestPrepareStageRejectsCredentialChangedAfterBindingAndCleansResidue(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected source identity requires root test")
	}
	base := protectedTestDir(t)
	chrootBase := filepath.Join(base, "chroot")
	webrootBase := filepath.Join(base, "webroot")
	for _, directory := range []string{chrootBase, webrootBase} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	accountKey, err := acmeaccount.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accountPath := filepath.Join(base, "account.key")
	if err := os.WriteFile(accountPath, accountKey, 0o600); err != nil {
		t.Fatal(err)
	}
	accountFingerprint, err := acmeaccount.Fingerprint(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	credential := make([]byte, 32)
	if _, err := rand.Read(credential); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(base, "dns-credential")
	if err := os.WriteFile(credentialPath, credential, 0o600); err != nil {
		t.Fatal(err)
	}
	credentialSum := sha256.Sum256(credential)
	credentialFingerprint := "sha256:" + hex.EncodeToString(credentialSum[:])
	credential[0] ^= 0xff
	if err := os.WriteFile(credentialPath, credential, 0o600); err != nil {
		t.Fatal(err)
	}

	certificateID := "cert_00000000000000000000000000000000"
	root := filepath.Join(chrootBase, certificateID)
	webroot := filepath.Join(webrootBase, certificateID)
	uid, gid := uint32(2200000), uint32(2200000)
	binding := Binding{
		DirectoryURL:          "https://acme.example.test/directory",
		AccountKeyPath:        accountPath,
		AccountKeyFingerprint: accountFingerprint,
		AccountEmail:          "admin@example.test",
		TermsAccepted:         true,
		Method:                ChallengeDNS01,
		Provider:              DNSProviderCloudflare,
		ProfilePath:           filepath.Join(base, "dns.env"),
		ProfileFingerprint:    "sha256:" + strings.Repeat("a", 64),
		CredentialFiles:       []CredentialFile{{Key: "CF_DNS_API_TOKEN_FILE", Path: credentialPath, Fingerprint: credentialFingerprint}},
		Zone:                  "example.test",
	}
	cleanup := func() error {
		return errors.Join(removeOwnedTree(root, uid, gid, 4096), removeOwnedTree(webroot, uid, gid, 1024))
	}
	stage, err := prepareStage(context.Background(), certificateID, binding, uid, gid, root, webroot, nil, cleanup)
	if err == nil || stage != (Stage{}) || !strings.Contains(err.Error(), "credential changed before staging") {
		t.Fatalf("changed credential stage=%#v err=%v", stage, err)
	}
	for _, path := range []string{root, webroot} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("changed credential left stage residue %q: %v", path, statErr)
		}
	}
}

func TestVerifyWebrootEmptyRemovesManagedHierarchyAndRestoresRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership transitions are unavailable")
	}
	base := protectedTestDir(t)
	root := filepath.Join(base, "cert_00000000000000000000000000000000")
	uid, gid := uint32(2200000), uint32(2200000)
	if err := os.MkdirAll(filepath.Join(root, ".well-known", "acme-challenge"), 0o711); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{root, filepath.Join(root, ".well-known"), filepath.Join(root, ".well-known", "acme-challenge")} {
		if err := os.Chown(directory, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyWebrootEmptyAt(root, uid, gid); err != nil {
		t.Fatalf("managed empty webroot was not removed: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid || info.Mode().Perm() != 0o711 {
		t.Fatalf("webroot identity was not restored: info=%#v stat=%#v", info, stat)
	}
	if _, err := os.Lstat(filepath.Join(root, ".well-known")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed challenge hierarchy remains: %v", err)
	}
}

func TestRemoveOwnedTreeFailureRestoresSealedRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership transitions are unavailable")
	}
	base := protectedTestDir(t)
	root := filepath.Join(base, "cert_00000000000000000000000000000000")
	uid, gid := uint32(2200000), uint32(2200000)
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(root, "foreign")
	if err := os.WriteFile(member, []byte("foreign"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(member, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedTree(root, uid, gid, 16); err == nil {
		t.Fatal("unsafe cleanup inventory was accepted")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid || info.Mode().Perm() != 0o711 {
		t.Fatalf("failed cleanup did not restore root identity: info=%#v stat=%#v", info, stat)
	}
	if err := os.Chmod(member, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedTree(root, uid, gid, 16); err != nil {
		t.Fatalf("restored cleanup could not retry: %v", err)
	}
}

func TestPrepareStageMidwayFaultLeavesNoResidueAndCanRetry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership transitions are unavailable")
	}
	base := protectedTestDir(t)
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
		if !errors.Is(err, os.ErrNotExist) || stage != (Stage{}) {
			t.Fatalf("attempt %d: expected missing account key fault, stage=%#v err=%v", attempt, stage, err)
		}
		for _, path := range []string{root, webroot} {
			if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("attempt %d left residue %q: %v", attempt, path, statErr)
			}
		}
	}
}
