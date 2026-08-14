package htpasswdref

import "testing"

func TestManagedBcryptRecordContract(t *testing.T) {
	valid := "$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
	if len(valid) != 60 {
		t.Fatalf("fixture length=%d", len(valid))
	}
	if !validBcrypt(valid) {
		t.Fatal("fixed-cost bcrypt rejected")
	}
	for _, value := range []string{"$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234", "$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234", "plain"} {
		if validBcrypt(value) {
			t.Fatalf("accepted %q", value)
		}
	}
	if !ValidUsername("admin.user@example") || ValidUsername("bad:name") {
		t.Fatal("username grammar mismatch")
	}
}
