package preflight

import "testing"

func TestParseOSReleasePreservesExactProfileFields(t *testing.T) {
	info := ParseOSRelease(`
ID='debian'
ID_LIKE="debian"
VERSION_ID="13"
PRETTY_NAME="Debian GNU/Linux 13 \"trixie\""
IGNORED_FIELD=not-authority
`)

	if info.ID != "debian" || info.IDLike != "debian" || info.VersionID != "13" || info.PrettyName != `Debian GNU/Linux 13 "trixie"` {
		t.Fatalf("ParseOSRelease() = %#v", info)
	}
}

func TestParseOSReleaseDoesNotClassifySupport(t *testing.T) {
	info := ParseOSRelease("ID=linuxmint\nID_LIKE=ubuntu\\ debian\nVERSION_ID=22\n")
	if info.ID != "linuxmint" || info.IDLike != "ubuntu debian" || info.VersionID != "22" {
		t.Fatalf("ParseOSRelease() = %#v", info)
	}
}
