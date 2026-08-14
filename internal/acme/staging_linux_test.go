//go:build linux

package acme

import "testing"

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
