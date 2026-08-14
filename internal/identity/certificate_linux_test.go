//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCertificateStageIdentitiesAreStableDistinctAndRejectHostAliases(t *testing.T) {
	first, err := CertificateStageIdentityFor("cert_00000100000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	same, _ := CertificateStageIdentityFor(first.CertificateID)
	second, _ := CertificateStageIdentityFor("cert_00000200000000000000000000000000")
	if first != same || first.UID == second.UID || first.UID == 0 || first.GID == 0 {
		t.Fatal("certificate stage identities are not stable and distinct")
	}
	root := t.TempDir()
	passwd := filepath.Join(root, "passwd")
	group := filepath.Join(root, "group")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte("root:x:0:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificateStageIdentityAvailable(first, passwd, group); err != nil {
		t.Fatal(err)
	}
	uid := strconv.FormatUint(uint64(first.UID), 10)
	if err := os.WriteFile(passwd, []byte("alias:x:"+uid+":"+uid+":alias:/nonexistent:/usr/sbin/nologin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificateStageIdentityAvailable(first, passwd, group); err == nil {
		t.Fatal("persistent numeric alias accepted")
	}
}
