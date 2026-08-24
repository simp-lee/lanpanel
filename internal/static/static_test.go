package staticcontent

import "testing"

func TestRegisterRejectsNoncanonicalStaticRootIDs(t *testing.T) {
	for _, id := range []string{
		"static_0000000000000000000000000000000g",
		"static_0000000000000000000000000000000A",
		"static_0000000000000000000000000000000 ",
		"static_0000000000000000000000000000000\x00",
	} {
		if _, err := Register(id, t.TempDir(), nil); err == nil || err.Error() != "static root identity invalid" {
			t.Fatalf("Register(%q) error = %v, want static ID rejection", id, err)
		}
	}
}

func TestStaticMappingGrammarIsClosed(t *testing.T) {
	cases := []struct {
		path      string
		directory bool
		ok        bool
	}{{"/robots.txt", false, true}, {"/assets/", true, true}, {"/assets", true, false}, {"/assets/../secret", false, false}, {"//assets", false, false}}
	for _, value := range cases {
		if got := validURLPath(value.path, value.directory); got != value.ok {
			t.Fatalf("path %q directory=%v got=%v", value.path, value.directory, got)
		}
	}
	for _, value := range []string{"index.html", "assets/app.js"} {
		if !cleanRelative(value) {
			t.Fatalf("relative %q rejected", value)
		}
	}
	for _, value := range []string{"../secret", "/absolute", "a\\b"} {
		if cleanRelative(value) {
			t.Fatalf("relative %q accepted", value)
		}
	}
}
